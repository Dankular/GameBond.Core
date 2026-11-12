package bond

import (
	"container/list"
	"errors"
	"math"
)

// The reference limits (kept for NewBudget so the behaviour vectors still hold) are
// 4096 tracked packets and a 1 MiB window. A live path uses the larger limits, which
// must cover rate x RTT at the configured ceiling (300 Mbps at 100 ms is 3.75 MB):
// otherwise the window, not the link, limits throughput.
const (
	maxPending  = 4096
	maxWindow   = 1 << 20
	livePending = 16384
	liveWindow  = 8 << 20
)

type budgetPending struct {
	sequence uint64
	size     int
	at       float64
	copy     bool // a redundancy copy: tracked for its acknowledgement, not counted in flight
	// key names the flow packet this frame carries, so a loss seen in the selective
	// acknowledgement can be answered with that packet's payload.
	key   MissingPacket
	keyed bool
	// lost: the peer's selective acknowledgement showed later frames arriving without
	// this one. It stays tracked until the cumulative acknowledgement retires it.
	lost bool
}

// growthLossCeiling is the loss ratio above which a path stops growing. Random loss
// of a few percent (a LEO link) is not congestion: real congestion is caught by the
// corroborated test, so growth only pauses once loss is clearly heavy.
const growthLossCeiling = .05

// assertiveDelayFloor is the queueing delay (seconds over the baseline) an assertive
// path tolerates before it counts as a standing queue. A loaded LEO link sits at
// 20-40 ms by itself, so 10 ms made every busy second look like congestion.
const assertiveDelayFloor = .040

// BaseRTTWindow is the seconds per bucket of the decaying delay baseline.
const BaseRTTWindow = 10.0

// Budget preserves the Python PathBudget's units and authenticated-feedback
// growth gates. All times are caller-supplied monotonic seconds; it never waits.
type Budget struct {
	initial, maximum, rate, minimum, next, inflight float64
	srtt, rawSRTT, minRTT, rtoBackoff               float64
	// Jitter-aware delay baseline (see BaseRTTWindow): rttVar is a mean deviation,
	// baseCur/basePrev are the minima of the current and previous window.
	rttVar, baseCur, basePrev, baseStarted                                              float64
	hasBaseCur, hasBasePrev, hasBaseStarted                                             bool
	hasMin, hasSent, hasAck                                                             bool
	lastSent, lastAck                                                                   uint64
	lastAckAt                                                                           float64 // time of the last accepted acknowledgement
	ackGap                                                                              float64 // smoothed seconds between accepted acknowledgements (0: none yet)
	lastSentAt                                                                          float64
	pending                                                                             map[uint64]*list.Element
	order                                                                               list.List
	deliveryCounter, sentBytes, sentPackets, ackedPackets, expiredPackets, expiredBytes uint64
	invalidACKs, untracked, rttSamples, backoffs, increases, timeoutBackoffs            uint64
	priorityBytes, priorityPackets, controlBytes, controlPackets, debtSaturations       uint64
	observed, lastBackoff                                                               float64
	epochStarted                                                                        float64
	hasEpoch                                                                            bool
	lossSeen                                                                            bool
	lossEWMA                                                                            float64
	lossEWSet                                                                           bool
	epochSent, epochDelivered, epochBulkWire, epochUnpacedWire, epochRetired            float64
	pressureAt                                                                          float64
	hasPressure, pressureActive                                                         bool
	epochPressure, epochPacingWait, waitUntil, pressureRatio, lossRatio, lossAt         float64
	growthAppLimited, appLimited, startup                                               bool
	growthUtilization, growthAllowance, pacingWaitRatio, deliveryRate                   float64
	congestionEpochs, delaySamples, startupIncreases                                    uint64
	delayBackoffs                                                                       uint64
	delayControl                                                                        bool
	// delayAssertive also cuts the rate on a modest standing queue while the
	// path carries real traffic (>= half the rate). Plain delay control waits for
	// 25 ms of queue and a saturated rate, which a TCP-limited download never
	// reaches, so bulk sat in the bottleneck buffer and delayed game packets.
	delayAssertive bool
	startupExit    string
	// pendingCap and windowCap are the tracked-packet and in-flight limits.
	pendingCap int
	windowCap  float64
	// Selective-acknowledgement loss counters (see Sack).
	sackLost, sackReports, tailLost uint64
}

// UseLiveLimits gives the budget the larger production window and tracking limits.
func (b *Budget) UseLiveLimits() { b.pendingCap, b.windowCap = livePending, liveWindow }

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func NewBudget(initial, maximum float64) (*Budget, error) {
	if !finite(initial) || !finite(maximum) || initial <= 0 || initial > maximum {
		return nil, errors.New("invalid path rates")
	}
	return &Budget{initial: initial, maximum: maximum, rate: initial * 125000, minimum: math.Min(initial, .05) * 125000,
		srtt: .25, rawSRTT: .25, rtoBackoff: 1, pending: make(map[uint64]*list.Element), lastBackoff: math.Inf(-1), pendingCap: maxPending, windowCap: maxWindow,
		growthAppLimited: true, appLimited: true, startup: true}, nil
}
func validTime(now float64) bool   { return finite(now) && now >= 0 }
func validSize(size int) bool      { return size >= 1 && size <= 65535 }
func (b *Budget) Timeout() float64 { return math.Min(2, math.Max(.25, 4*b.rawSRTT)*b.rtoBackoff) }

// AckStalled reports a path that is sending but hearing nothing back: the oldest
// unacknowledged packet is older than limit seconds and no acknowledgement has
// been accepted for that long. It is a passive loss-of-path signal that needs no
// probe, and fires in tens of milliseconds on a busy path.
func (b *Budget) AckStalled(now, limit float64) bool {
	front := b.order.Front()
	if front == nil || !b.hasAck {
		return false
	}
	return now-front.Value.(budgetPending).at > limit && now-b.lastAckAt > limit
}

func (b *Budget) Window() int {
	return int(math.Max(6000, math.Min(b.windowCap, b.rate*math.Max(.02, b.rawSRTT)*2)))
}
func (b *Budget) RateMbps() float64 { return b.rate / 125000 }
func (b *Budget) pressure(now float64, active *bool) {
	if b.hasPressure && b.hasEpoch && b.pressureActive {
		b.epochPressure += math.Max(0, now-b.pressureAt)
	}
	if !b.hasPressure {
		b.pressureAt = now
		b.hasPressure = true
	} else {
		b.pressureAt = math.Max(now, b.pressureAt)
	}
	if active != nil {
		b.pressureActive = *active
	}
}
func (b *Budget) ReadyAt(size int, now float64) (float64, error) {
	if !validSize(size) || !validTime(now) {
		return 0, ErrFrame
	}
	b.observed = math.Max(b.observed, now)
	b.expire(now, true)
	active := len(b.pending) >= b.pendingCap || b.inflight+float64(size) > math.Max(float64(size), float64(b.Window()))
	b.pressure(now, &active)
	if !active {
		return math.Max(now, b.next), nil
	}
	oldest := b.order.Front().Value.(budgetPending)
	return math.Max(now, oldest.at+b.Timeout()), nil
}
func (b *Budget) TransitSeconds(size int, probeRTT float64) float64 {
	rtt := b.srtt
	if finite(probeRTT) && probeRTT > 0 {
		if b.rttSamples > 0 {
			rtt = math.Max(rtt, probeRTT)
		} else {
			rtt = probeRTT
		}
	}
	return float64(size+28)/b.rate + rtt/2
}
func (b *Budget) RecordWait(start, end float64) error {
	if !validTime(start) || !validTime(end) || end < start {
		return ErrFrame
	}
	if b.hasEpoch {
		b.epochPacingWait += math.Max(0, end-math.Max(start, math.Max(b.epochStarted, b.waitUntil)))
	}
	b.waitUntil = math.Max(b.waitUntil, end)
	return nil
}
func (b *Budget) UnpacedSent(size int, now float64, control bool) error {
	if !validSize(size) || !validTime(now) || now < b.observed {
		return ErrFrame
	}
	b.observed = now
	wire := float64(size + 28)
	if !b.hasEpoch {
		b.hasEpoch = true
		b.epochStarted = now
	}
	b.epochUnpacedWire += wire
	if control {
		b.controlBytes += uint64(size + 28)
		b.controlPackets++
	} else {
		b.priorityBytes += uint64(size + 28)
		b.priorityPackets++
	}
	proposed := math.Max(now, b.next) + wire/b.rate
	bounded := math.Min(proposed, now+.1)
	if bounded < proposed {
		b.debtSaturations++
	}
	b.next = math.Max(b.next, bounded)
	return nil
}
func (b *Budget) Sent(sequence uint64, size int, now float64) (bool, error) {
	if !validSize(size) || !validTime(now) || (b.hasSent && now < b.lastSentAt) {
		return false, ErrFrame
	}
	if b.hasSent && sequence <= b.lastSent {
		return false, nil
	}
	b.expire(now, true)
	b.hasSent = true
	b.lastSentAt = now
	b.lastSent = sequence
	b.sentBytes += uint64(size)
	b.sentPackets++
	if !b.hasEpoch {
		b.hasEpoch = true
		b.epochStarted = now
	}
	b.epochSent += float64(size)
	b.epochBulkWire += float64(size + 28)
	b.observed = math.Max(b.observed, now)
	b.next = math.Max(now-.002, b.next) + float64(size+28)/b.rate
	if len(b.pending) >= b.pendingCap {
		b.untracked++
		return false, nil
	}
	b.pending[sequence] = b.order.PushBack(budgetPending{sequence: sequence, size: size, at: now})
	b.inflight += float64(size)
	return true, nil
}

// SentCopy records a redundancy copy. The receiver acknowledges the copy's sequence
// like any other frame, so it must be tracked (an unknown sequence makes the path's
// feedback get refused), but it is not window data: it neither fills the send window
// nor waits behind it. The link still carries it, so it is charged as unpaced wire
// and advances the pacing clock.
func (b *Budget) SentCopy(sequence uint64, size int, now float64) (bool, error) {
	if !validSize(size) || !validTime(now) || (b.hasSent && now < b.lastSentAt) {
		return false, ErrFrame
	}
	if b.hasSent && sequence <= b.lastSent {
		return false, nil
	}
	b.expire(now, true)
	b.hasSent = true
	b.lastSentAt = now
	b.lastSent = sequence
	b.sentBytes += uint64(size)
	b.sentPackets++
	if err := b.UnpacedSent(size, now, false); err != nil {
		return false, err
	}
	if len(b.pending) >= b.pendingCap {
		b.untracked++
		return false, nil
	}
	b.pending[sequence] = b.order.PushBack(budgetPending{sequence: sequence, size: size, at: now, copy: true})
	return true, nil
}

// Tag records which flow packet the tracked frame with this sequence carries.
func (b *Budget) Tag(sequence uint64, key MissingPacket) {
	if e := b.pending[sequence]; e != nil {
		p := e.Value.(budgetPending)
		p.key, p.keyed = key, true
		e.Value = p
	}
}

// sackThreshold is how many later frames on the same path must arrive before an
// earlier one that did not is called lost. One path delivers in order, so a small
// threshold is enough to ride out a swap while still reacting within a few packets.
const sackThreshold = 3

// Sack applies the peer's selective acknowledgement: bits is a bitmap over the 8*len(bits)
// frame sequences starting at base, set where the peer received that frame on this path.
// A tracked frame inside the window that is clear, with at least sackThreshold later
// tracked frames of this path received, is lost. It returns the flow packets those
// frames carried (each frame is reported once). It must run before Acknowledge, which
// retires the entries.
func (b *Budget) Sack(base uint64, bits []byte) []MissingPacket {
	end := base + uint64(len(bits))*8
	type seen struct {
		e   *list.Element
		got bool
	}
	var window []seen
	for e := b.order.Front(); e != nil; e = e.Next() {
		p := e.Value.(budgetPending)
		if p.sequence < base {
			continue
		}
		if p.sequence >= end {
			break
		}
		i := p.sequence - base
		window = append(window, seen{e, bits[i/8]&(1<<(i%8)) != 0})
	}
	b.sackReports++
	var lost []MissingPacket
	later := 0
	for i := len(window) - 1; i >= 0; i-- {
		if window[i].got {
			later++
			continue
		}
		p := window[i].e.Value.(budgetPending)
		if p.lost || later < sackThreshold {
			continue
		}
		p.lost = true
		window[i].e.Value = p
		b.sackLost++
		if p.keyed {
			lost = append(lost, p.key)
		}
	}
	return lost
}

// tailProbeLimit bounds how many silent frames one call can declare lost.
const tailProbeLimit = 64

// TailLost names the flow packets of frames that no acknowledgement has covered for
// longer than a round trip plus a small feedback allowance. A later frame arriving would have
// retired them (the cumulative acknowledgement covers everything below it), so the
// frames at the front of the queue that are still pending are the tail of a burst, or
// everything on a path that has stopped answering: the selective acknowledgement cannot
// see them because nothing was sent after them. Each frame is reported once.
func (b *Budget) TailLost(now float64) []MissingPacket {
	// One round trip, two deviations of it, and one and a half measured gaps between
	// acknowledgements: the peer only reports every 20-100 ms, so a frame is not overdue
	// until a report that could have covered it is itself late. Until the gap is known
	// the slowest cadence (100 ms) is assumed. No fixed floor.
	gap := b.ackGap
	if gap == 0 {
		gap = .1
	}
	limit := b.rawSRTT + 2*b.rttVar + 1.5*gap
	var lost []MissingPacket
	for e := b.order.Front(); e != nil && len(lost) < tailProbeLimit; e = e.Next() {
		p := e.Value.(budgetPending)
		if now-p.at < limit {
			break
		}
		if p.lost {
			continue
		}
		p.lost = true
		e.Value = p
		b.tailLost++
		if p.keyed {
			lost = append(lost, p.key)
		}
	}
	return lost
}

func (b *Budget) Acknowledge(sequence, delivered uint64, now float64, delayUS uint32) bool {
	element := b.pending[sequence]
	if !validTime(now) || delayUS > 1000000 || element == nil || (b.hasAck && sequence <= b.lastAck) || delivered <= b.deliveryCounter || delivered > b.sentBytes {
		b.invalidACKs++
		return false
	}
	p := element.Value.(budgetPending)
	if delivered-b.deliveryCounter < uint64(p.size) || now < p.at {
		b.invalidACKs++
		return false
	}
	b.expire(now, false)
	if b.pending[sequence] == nil {
		b.invalidACKs++
		b.measure(now)
		return false
	}
	rawSample := math.Max(.000001, now-p.at)
	sample := math.Max(.000001, rawSample-math.Min(rawSample, float64(delayUS)/1e6))
	if b.rttSamples == 0 {
		b.rttVar = 0
		b.rawSRTT = rawSample
		b.srtt = sample
	} else {
		b.rttVar = b.rttVar*.75 + math.Abs(sample-b.srtt)*.25
		b.rawSRTT = b.rawSRTT*.875 + rawSample*.125
		b.srtt = b.srtt*.875 + sample*.125
	}
	if !b.hasMin || sample < b.minRTT {
		b.minRTT = sample
		b.hasMin = true
	}
	if !b.hasBaseStarted || now-b.baseStarted >= BaseRTTWindow {
		b.basePrev, b.hasBasePrev = b.baseCur, b.hasBaseCur
		b.hasBaseCur, b.baseStarted, b.hasBaseStarted = false, now, true
	}
	if !b.hasBaseCur || sample < b.baseCur {
		b.baseCur, b.hasBaseCur = sample, true
	}
	b.rttSamples++
	b.rtoBackoff = math.Max(1, b.rtoBackoff/2)
	for b.order.Len() > 0 {
		entry := b.order.Front()
		p := entry.Value.(budgetPending)
		if p.sequence > sequence {
			break
		}
		delete(b.pending, p.sequence)
		b.order.Remove(entry)
		if !p.copy {
			b.inflight -= float64(p.size)
		}
		b.ackedPackets++
		b.epochRetired += float64(p.size)
	}
	active := false
	b.pressure(now, &active)
	delta := delivered - b.deliveryCounter
	b.deliveryCounter = delivered
	if b.hasAck {
		gap := math.Min(.12, math.Max(0, now-b.lastAckAt))
		if b.ackGap == 0 {
			b.ackGap = gap
		} else {
			b.ackGap += .25 * (gap - b.ackGap)
		}
	}
	b.lastAck = sequence
	b.hasAck = true
	b.lastAckAt = now
	b.epochDelivered += float64(delta)
	elapsed := 0.
	if b.hasEpoch {
		elapsed = now - b.epochStarted
	}
	utilization := 0.
	if elapsed > 0 {
		utilization = b.epochSent / (b.rate * elapsed)
	}
	b.appLimited = utilization < .8
	base := b.baseCur
	if b.hasBasePrev && (!b.hasBaseCur || b.basePrev < base) {
		base = b.basePrev
	}
	delayFloor, delayVar, busy := .025, 4.0, !b.appLimited
	if b.delayAssertive {
		delayFloor, delayVar, busy = assertiveDelayFloor, 2.5, utilization >= .5
	}
	if busy && math.Max(0, b.srtt-base) > math.Max(delayFloor, math.Max(base*.5, delayVar*b.rttVar)) {
		if b.delaySamples < 3 {
			b.delaySamples++
		}
	} else {
		b.delaySamples = 0
	}
	b.measure(now)
	return true
}
func (b *Budget) resetEpoch(now float64) {
	b.epochStarted = now
	b.epochSent = 0
	b.epochDelivered = 0
	b.epochBulkWire = 0
	b.epochUnpacedWire = 0
	b.epochRetired = 0
	b.epochPressure = 0
	b.epochPacingWait = 0
}
func (b *Budget) reduce(now float64) {
	if now-b.lastBackoff < math.Max(.1, b.srtt) {
		return
	}
	b.rate = math.Max(b.minimum, b.rate*.8)
	b.lastBackoff = now
	b.backoffs++
	b.resetEpoch(now)
	b.delaySamples = 0
}

// reduceForDelay answers a standing queue that loss never signals: the
// bottleneck buffer is full and delaying everything behind it. The rate drops
// by a tenth so the queue drains, at most once
// per two round trips, and never below the floor. It only runs when the path is
// really being used (not app-limited), so sparse traffic is left alone.
func (b *Budget) reduceForDelay(now float64) {
	if now-b.lastBackoff < math.Max(.25, 2*b.srtt) {
		return
	}
	// A fixed 10% cut, not "just under what was delivered": delivery is measured under
	// the very throttling being applied (and on TCP it is capped by earlier drops), so
	// following it down is a ratchet that pins the rate near whatever was last achieved.
	b.rate = math.Max(b.minimum, b.rate*.9)
	b.lastBackoff = now
	b.delayBackoffs++
	b.startup = false
	if b.startupExit == "" {
		b.startupExit = "delay"
	}
	b.resetEpoch(now)
	b.delaySamples = 0
}
func (b *Budget) measure(now float64) {
	if !b.hasEpoch {
		return
	}
	elapsed := now - b.epochStarted
	if elapsed < math.Max(.25, 2*b.rawSRTT) {
		return
	}
	deliveredRate := b.epochDelivered / elapsed
	if b.deliveryRate == 0 {
		b.deliveryRate = deliveredRate
	} else {
		b.deliveryRate = .75*b.deliveryRate + .25*deliveredRate
	}
	utilization := b.epochSent / (b.rate * elapsed)
	pressure := math.Min(1, b.epochPressure/elapsed)
	b.pressureRatio = pressure
	b.lossRatio = 0
	if b.epochRetired > 0 {
		b.lossRatio = math.Max(0, (b.epochRetired-b.epochDelivered)/b.epochRetired)
		b.lossAt, b.lossSeen = now, true
		if b.epochRetired >= 4000 {
			if b.lossEWSet {
				b.lossEWMA = .6*b.lossEWMA + .4*b.lossRatio
			} else {
				b.lossEWMA, b.lossEWSet = b.lossRatio, true
			}
		}
	}
	b.appLimited = utilization < .8 && pressure < .5
	remaining := math.Max(0, b.rate*elapsed-b.epochUnpacedWire)
	fraction := 0.
	if b.epochBulkWire > 0 {
		fraction = b.epochSent / b.epochBulkWire
	}
	allowance := remaining * fraction
	b.growthAllowance = allowance
	b.growthUtilization = 0
	if allowance > 0 {
		b.growthUtilization = b.epochSent / allowance
	}
	b.pacingWaitRatio = math.Min(1, b.epochPacingWait/elapsed)
	b.growthAppLimited = b.growthUtilization < .8 && pressure < .5 && b.pacingWaitRatio < .1
	corroborated := !b.appLimited && pressure >= .25 && b.epochRetired >= 6000 && b.lossRatio >= .10 && deliveredRate < b.rate*.85
	if corroborated {
		b.congestionEpochs++
	} else {
		b.congestionEpochs = 0
	}
	if b.startup && corroborated {
		b.startup = false
		b.startupExit = "loss"
	}
	if b.congestionEpochs >= 2 {
		b.reduce(now)
		b.congestionEpochs = 0
	} else if b.delayControl && b.delaySamples >= 3 && (!b.appLimited || (b.delayAssertive && utilization >= .5)) {
		b.reduceForDelay(now)
	}
	// A path that mostly carries redundancy copies charges them as unpaced wire, which
	// leaves no allowance for window data, so the usual gate never opens and the path
	// stays at its starting rate while the copies fill it. If the wire is full and nearly
	// all of it is being delivered, the path can take more.
	wire := b.epochBulkWire + b.epochUnpacedWire
	copyFull := wire >= b.rate*elapsed*.8 && b.epochDelivered >= wire*.65
	grow := (!b.growthAppLimited && allowance > 0 && b.epochDelivered >= allowance*.65) || copyFull
	if grow && b.delaySamples == 0 && !corroborated && b.lossRatio < growthLossCeiling && pressure < .25 && b.epochDelivered >= 6000 && b.epochRetired >= 6000 && now-b.lastBackoff >= math.Max(.25, b.rawSRTT) {
		increment := 12500.
		if b.startup {
			increment = math.Max(12500, math.Min(b.rate*.5, 1250000))
		}
		if b.delayAssertive && !b.startup {
			// Backing off on a modest queue is only safe if the rate can come
			// back: 12.5 KB/s per epoch takes minutes to climb from a few Mbps.
			// Grow in proportion to the rate instead, capped per epoch.
			increment = math.Max(increment, math.Min(b.rate*.08, 625000))
		}
		updated := math.Min(b.maximum*125000, b.rate+increment)
		if updated > b.rate {
			b.rate = updated
			b.increases++
			if b.startup {
				b.startupIncreases++
			}
		}
	}
	b.resetEpoch(now)
}
func (b *Budget) expire(now float64, measure bool) int {
	b.observed = math.Max(b.observed, now)
	b.pressure(now, nil)
	expired := 0
	timeout := b.Timeout()
	for b.order.Len() > 0 {
		entry := b.order.Front()
		p := entry.Value.(budgetPending)
		if now < p.at+timeout {
			break
		}
		b.order.Remove(entry)
		delete(b.pending, p.sequence)
		if !p.copy {
			b.inflight -= float64(p.size)
		}
		b.expiredBytes += uint64(p.size)
		b.expiredPackets++
		expired++
	}
	if expired > 0 {
		b.rtoBackoff = math.Min(16, b.rtoBackoff*2)
		b.timeoutBackoffs++
		active := false
		b.pressure(now, &active)
	}
	if measure {
		b.measure(now)
	}
	return expired
}
func (b *Budget) Expire(now float64) (int, error) {
	if !validTime(now) {
		return 0, ErrFrame
	}
	return b.expire(now, true), nil
}
func (b *Budget) Stats() map[string]any {
	var minimum any
	if b.hasMin {
		minimum = b.minRTT * 1000
	}
	var exit any
	if b.startupExit != "" {
		exit = b.startupExit
	}
	delay := 0.
	if b.hasMin {
		delay = math.Max(0, b.srtt-b.minRTT) * 1000
	}
	return map[string]any{"rate_mbps": b.RateMbps(), "delivery_rate_mbps": b.deliveryRate / 125000, "initial_rate_mbps": b.initial, "max_rate_mbps": b.maximum,
		"next_send": b.next, "inflight_bytes": b.inflight, "wire_overhead": 28, "priority_wire_bytes": b.priorityBytes, "priority_wire_packets": b.priorityPackets, "control_wire_bytes": b.controlBytes, "control_wire_packets": b.controlPackets,
		"priority_debt_saturations": b.debtSaturations, "pacing_debt_ms": math.Max(0, b.next-b.observed) * 1000, "pacing_observed_at": b.observed, "window_bytes": b.Window(), "pending_packets": len(b.pending),
		"srtt_ms": b.srtt * 1000, "min_rtt_ms": minimum, "raw_srtt_ms": b.rawSRTT * 1000, "rtt_var_ms": b.rttVar * 1000, "queue_delay_ms": delay, "timeout_seconds": b.Timeout(), "sent_packets": b.sentPackets, "rto_backoff": b.rtoBackoff,
		"sent_bytes": b.sentBytes, "acked_packets": b.ackedPackets, "delivered_bytes": b.deliveryCounter, "expired_packets": b.expiredPackets, "expired_bytes": b.expiredBytes, "invalid_acks": b.invalidACKs, "untracked_packets": b.untracked,
		"backoffs": b.backoffs, "rate_increases": b.increases, "app_limited": b.appLimited, "startup": b.startup, "startup_increases": b.startupIncreases, "startup_exit_reason": exit, "growth_app_limited": b.growthAppLimited,
		"growth_bulk_utilization": b.growthUtilization, "growth_bulk_allowance_bytes": b.growthAllowance, "pacing_wait_ratio": b.pacingWaitRatio, "delay_samples": b.delaySamples, "delay_backoffs": b.delayBackoffs, "timeout_backoffs": b.timeoutBackoffs, "window_pressure_ratio": b.pressureRatio, "settled_loss_ratio": b.lossRatio, "congestion_epochs": b.congestionEpochs}
}
