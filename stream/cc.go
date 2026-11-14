package stream

import (
	"math"
	"time"
)

// Congestion control: a model of the path, not a reaction to loss or to delay.
//
// The controller measures the two numbers that describe a path and paces to them:
//
//   - btlBw, the bottleneck bandwidth, is the highest delivery rate seen over the last
//     ccBwRounds round trips. A delivery rate is bytes newly acknowledged over the time they
//     took, measured per packet from the moment it was sent (see rateSample), so it does not
//     depend on how acknowledgements are batched or on how many links carried the packets.
//   - rtProp, the propagation delay, is the lowest round trip seen over ccRTPropWindow.
//
// Packets are paced at gain x btlBw and in-flight data is capped at about two bandwidth-delay
// products, so a queue never builds beyond what the cap allows. This is what the two
// earlier rules could not do: a window that shrinks when the round trip rises is pinned at
// its floor by any path whose delay is not constant (two links of different length, jitter,
// a satellite hop), and a window that grows whenever nothing is lost overshoots the bottleneck
// by several times, then retransmits half of what it sent.
//
// Loss is not a signal of congestion by itself, because the transport underneath already
// duplicates over several links and random loss is common on radio links. It only matters
// when a round trip loses more than ccLossThresh of what it carried, which means a buffer
// overflowed, and then the in-flight data is bounded (inflightHi) below where it overflowed.
//
// Phases, as in BBR: Startup finds the bandwidth by doubling the rate each round trip,
// Drain empties the queue Startup built, ProbeBW cruises at the estimate and probes 25% above
// it once per cycle, and ProbeRTT briefly lowers in-flight data to re-measure rtProp.

type ccMode int

const (
	ccStartup ccMode = iota
	ccDrain
	ccProbeBW
	ccProbeRTT
)

func (m ccMode) String() string {
	return [...]string{"startup", "drain", "probe_bw", "probe_rtt"}[m]
}

const (
	ccHighGain     = 2.885 // 2/ln 2: doubles the delivery rate every round trip
	ccCwndGain     = 2.0
	ccBwRounds     = 10
	ccRTPropWindow = 20 * time.Second
	ccRecentSpan   = 1500 * time.Millisecond // two spans make the short-term RTT floor
	ccProbeRTTTime = 150 * time.Millisecond
	ccFullBwGrowth = 1.25
	ccFullBwRounds = 3
	ccLossThresh   = 0.02
	ccLossMinPkts  = 6
	ccMinPipePkts  = 4
	ccMinRate      = 20000.     // bytes/s, so a stalled estimate can always recover
	ccMaxRate      = 4000000000 // 32 Gbit/s
)

// ProbeBW phases. A flow spends nearly all its time cruising at the measured rate; once per
// cycle it probes 25% above it to find out whether the path has more room, then drains what
// the probe queued until the pipe holds no more than its bandwidth-delay product.
type pbPhase int

const (
	pbDown pbPhase = iota
	pbCruise
	pbRefill
	pbUp
)

const (
	ccProbeUpGain   = 1.25
	ccProbeGrowGain = 2.0 // while probes keep finding room, double like Startup instead of creeping
	ccProbeDownGain = 0.75
	ccCruiseMin     = 250 * time.Millisecond
	ccBwGrowth      = 1.05 // a probe that raised the estimate by this much is followed at once
)

// rateSample is what one acknowledgement says about the delivery rate.
type rateSample struct {
	valid          bool
	rate           float64 // bytes/s
	appLimited     bool    // the sender ran out of data while this was measured
	priorDelivered uint64  // delivered counter when the newest acknowledged packet was sent
	rtt            time.Duration
}

type congestion struct {
	mss  int
	mode ccMode

	// Model.
	round              int
	nextRoundDelivered uint64
	roundStart         bool
	bwRound            [ccBwRounds]int
	bwMax              [ccBwRounds]float64
	btlBw              float64
	rtProp             time.Duration
	rtPropAt           time.Time
	rtRecent           [2]time.Duration // lowest RTT in the current and previous ccRecentSpan
	rtRecentAt         time.Time

	// Startup exit.
	fullBw      float64
	fullBwCount int
	fullPipe    bool

	// Probing.
	phase    pbPhase
	cycleAt  time.Time
	cycleFor time.Duration // how long to cruise before the next probe
	cycles   int
	bwAtUp   float64
	growing  bool // the last probe raised the estimate: probe again without waiting

	// ProbeRTT.
	probeRTTUntil time.Time
	probeRTTRound bool
	probeRTTStart int

	// Outputs.
	pacingGain float64
	cwndGain   float64
	pacing     float64
	cwnd       int
	initCwnd   int

	// Loss.
	conservation   bool // first round after a loss: send no more than comes back
	conserveRound  int
	roundLost      uint64
	roundLostPkts  int
	roundDelivered uint64
	roundLostPeak  int // largest in-flight when a loss was declared this round
	inflightHi     int // upper bound on in-flight data after an overflow; 0 = none

	// Acknowledgement aggregation: bytes acknowledged beyond what the rate predicts.
	extraAt    time.Time
	extraAcked uint64
	extraBytes [2]float64
	extraRound [2]int
}

func newCongestion(mss int, initialRTT time.Duration) *congestion {
	g := &congestion{mss: mss, mode: ccStartup, pacingGain: ccHighGain, cwndGain: ccHighGain}
	g.initCwnd = 32 * mss
	g.cwnd = g.initCwnd
	g.pacing = ccHighGain * float64(g.initCwnd) / math.Max(initialRTT.Seconds(), 0.01)
	return g
}

func (g *congestion) minPipe() int { return ccMinPipePkts * g.mss }

func (g *congestion) bdp(gain float64) float64 {
	if g.btlBw <= 0 || g.rtProp <= 0 {
		return float64(g.initCwnd)
	}
	return gain * g.btlBw * g.rtProp.Seconds()
}

// extra is how far acknowledgements ran ahead of the estimated rate: it is the slack the
// window needs so that bursty or batched acknowledgements do not leave the pipe idle.
func (g *congestion) extra() float64 {
	return math.Max(g.extraBytes[0], g.extraBytes[1])
}

// onAck folds one acknowledgement into the model and recomputes the pacing rate and window.
// delivered is the connection's total, newly the bytes this acknowledgement delivered, and
// inflight the bytes still unacknowledged after it.
func (g *congestion) onAck(now time.Time, rs rateSample, delivered uint64, newly, inflight int) {
	g.roundStart = false
	if rs.valid || rs.priorDelivered > 0 {
		if rs.priorDelivered >= g.nextRoundDelivered {
			g.endRound(now, inflight)
			g.nextRoundDelivered = delivered
			g.round++
			g.roundStart = true
		}
	}
	g.roundDelivered += uint64(newly)
	// The estimate changes only when a sample is accepted. A flow that stops sending, or only
	// produces application-limited samples below the estimate, keeps what it learned: the
	// path has not changed because nobody is using it.
	if rs.valid && (rs.rate >= g.btlBw || !rs.appLimited) {
		slot := g.round % ccBwRounds
		if g.bwRound[slot] != g.round {
			g.bwRound[slot], g.bwMax[slot] = g.round, 0
		}
		g.bwMax[slot] = math.Max(g.bwMax[slot], rs.rate)
		best := 0.
		for i := range g.bwMax {
			if g.round-g.bwRound[i] < ccBwRounds {
				best = math.Max(best, g.bwMax[i])
			}
		}
		g.btlBw = best
	}
	if rs.rtt > 0 {
		g.noteRecentRTT(now, rs.rtt)
		expired := !g.rtPropAt.IsZero() && now.Sub(g.rtPropAt) > ccRTPropWindow
		if g.rtProp == 0 || rs.rtt <= g.rtProp || (expired && g.mode == ccProbeRTT) {
			g.rtProp, g.rtPropAt = rs.rtt, now
		}
		if expired && g.mode != ccProbeRTT {
			g.enterProbeRTT(now)
		}
	}
	g.noteAggregation(now, newly)
	g.checkFullPipe(rs)
	switch g.mode {
	case ccStartup:
		if g.fullPipe {
			g.mode, g.pacingGain, g.cwndGain = ccDrain, 1/ccHighGain, ccHighGain
		}
	case ccDrain:
		if float64(inflight) <= g.bdp(1) {
			g.enterProbeBW(now)
		}
	case ccProbeBW:
		g.advanceCycle(now, inflight)
	case ccProbeRTT:
		g.handleProbeRTT(now, inflight)
	}
	if g.conservation && g.roundStart && g.round > g.conserveRound {
		g.conservation = false
	}
	g.setPacing()
	g.setCwnd(newly, inflight)
}

// endRound looks at how much the round that just ended lost.
func (g *congestion) endRound(now time.Time, inflight int) {
	// A buffer has overflowed only if a round loses several packets and more than the threshold:
	// one or two lost packets in a short round are what random loss on a radio link looks like.
	total := g.roundLost + g.roundDelivered
	if g.roundLostPkts >= ccLossMinPkts && float64(g.roundLost) > ccLossThresh*float64(total) {
		g.overflow(now)
	}
	g.roundLost, g.roundDelivered, g.roundLostPeak, g.roundLostPkts = 0, 0, 0, 0
}

// overflow bounds in-flight data below the level that lost packets: a buffer filled.
func (g *congestion) overflow(now time.Time) {
	hi := int(0.85 * float64(g.roundLostPeak))
	if hi < g.minPipe() {
		hi = g.minPipe()
	}
	if g.inflightHi == 0 || hi < g.inflightHi {
		g.inflightHi = hi
	}
	g.conservation, g.conserveRound = true, g.round
	switch g.mode {
	case ccStartup:
		g.fullPipe = true
	case ccProbeBW:
		if g.phase == pbUp {
			g.setPhase(pbDown, now) // stop probing up at once
		}
	}
}

func (g *congestion) checkFullPipe(rs rateSample) {
	if g.fullPipe || !g.roundStart || rs.appLimited {
		return
	}
	if g.btlBw >= g.fullBw*ccFullBwGrowth {
		g.fullBw, g.fullBwCount = g.btlBw, 0
		return
	}
	if g.fullBwCount++; g.fullBwCount >= ccFullBwRounds {
		g.fullPipe = true
	}
}

func (g *congestion) enterProbeBW(now time.Time) {
	g.mode, g.cwndGain = ccProbeBW, ccCwndGain
	// The pipe was just drained: probe for more room soon, then settle into the cycle.
	g.setPhase(pbCruise, now)
	g.cycleFor = ccCruiseMin
}

func (g *congestion) setPhase(ph pbPhase, now time.Time) {
	g.phase, g.cycleAt = ph, now
	switch ph {
	case pbDown:
		g.pacingGain = ccProbeDownGain
	case pbUp:
		g.pacingGain = ccProbeUpGain
		if g.growing {
			g.pacingGain = ccProbeGrowGain // the last probe found room: ask for a lot more
		}
		g.bwAtUp = g.btlBw
		g.cycles++
		// A clean probe lets the bound rise again, so one overflow does not cap the flow forever.
		if g.inflightHi > 0 {
			g.inflightHi += g.inflightHi/4 + g.mss
			if float64(g.inflightHi) > g.bdp(ccCwndGain)+g.extra() {
				g.inflightHi = 0
			}
		}
	default:
		g.pacingGain = 1
	}
}

// cruiseFor is the wait between probes: several round trips, never so short that probing
// itself keeps a queue standing, varied a little so flows on one path do not probe in step.
func (g *congestion) cruiseFor() time.Duration {
	d := time.Duration(6+g.cycles*7%5) * g.rtProp
	return max(d, ccCruiseMin)
}

func (g *congestion) advanceCycle(now time.Time, inflight int) {
	if g.cycleAt.IsZero() {
		g.cycleAt = now
	}
	elapsed := now.Sub(g.cycleAt)
	rt := max(g.rtProp, time.Millisecond)
	switch g.phase {
	case pbDown:
		// Drain until nothing but the pipe itself is in flight; a bounded wait keeps a flow
		// that shares its queue with others from sitting here forever.
		if float64(inflight) <= g.bdp(1) || elapsed > 5*rt+50*time.Millisecond {
			g.setPhase(pbCruise, now)
			g.cycleFor = g.cruiseFor()
			if g.growing {
				g.cycleFor = 0
			}
		}
	case pbCruise:
		if elapsed >= g.cycleFor {
			g.setPhase(pbRefill, now)
		}
	case pbRefill:
		if elapsed >= rt {
			g.setPhase(pbUp, now)
		}
	case pbUp:
		// The probe counts only once the extra data is really in flight; it ends early on an overflow.
		full := elapsed >= rt && (g.inflightHi > 0 || float64(inflight) >= g.bdp(g.pacingGain))
		if full || elapsed >= 4*rt {
			g.growing = g.btlBw >= g.bwAtUp*ccBwGrowth // the path had room: keep going
			g.setPhase(pbDown, now)
		}
	}
}

// noteRecentRTT keeps the lowest round trip of roughly the last three seconds. When even that
// floor sits well above rtProp the base delay has changed (a route change, a new satellite),
// not a queue: waiting twenty seconds for rtProp to expire would size every window and every
// drain for a path that no longer exists.
func (g *congestion) noteRecentRTT(now time.Time, rtt time.Duration) {
	if g.rtRecentAt.IsZero() || now.Sub(g.rtRecentAt) >= ccRecentSpan {
		g.rtRecent[1], g.rtRecent[0] = g.rtRecent[0], 0
		g.rtRecentAt = now
	}
	if g.rtRecent[0] == 0 || rtt < g.rtRecent[0] {
		g.rtRecent[0] = rtt
	}
	if g.rtRecent[1] > 0 && g.rtProp > 0 && g.mode != ccProbeRTT {
		floor := min(g.rtRecent[0], g.rtRecent[1])
		if floor > g.rtProp+g.rtProp/4+5*time.Millisecond {
			g.rtProp, g.rtPropAt = floor, now
		}
	}
}

func (g *congestion) enterProbeRTT(now time.Time) {
	g.mode, g.pacingGain = ccProbeRTT, 1
	g.probeRTTUntil = time.Time{}
	g.probeRTTRound = false
	g.probeRTTStart = g.round
}

func (g *congestion) handleProbeRTT(now time.Time, inflight int) {
	target := g.probeRTTCwnd()
	if g.probeRTTUntil.IsZero() && inflight <= target {
		g.probeRTTUntil = now.Add(ccProbeRTTTime)
		g.probeRTTStart = g.round
	}
	if g.probeRTTUntil.IsZero() {
		return
	}
	if g.roundStart && g.round > g.probeRTTStart {
		g.probeRTTRound = true
	}
	if g.probeRTTRound && now.After(g.probeRTTUntil) {
		g.rtPropAt = now
		if g.fullPipe {
			g.enterProbeBW(now)
		} else {
			g.mode, g.pacingGain, g.cwndGain = ccStartup, ccHighGain, ccHighGain
		}
	}
}

// probeRTTCwnd keeps half the pipe full while the round trip is re-measured, so a flow that
// is being watched does not stall for the measurement.
func (g *congestion) probeRTTCwnd() int {
	return max(g.minPipe(), int(g.bdp(0.5)))
}

// noteAggregation tracks how much more was acknowledged in an interval than the estimated
// rate predicts, which is how acknowledgements that arrive in clumps show up.
func (g *congestion) noteAggregation(now time.Time, newly int) {
	if g.btlBw <= 0 || newly <= 0 {
		return
	}
	expected := g.btlBw * now.Sub(g.extraAt).Seconds()
	if g.extraAt.IsZero() || float64(g.extraAcked) <= expected {
		g.extraAcked, g.extraAt = 0, now
	}
	g.extraAcked += uint64(newly)
	extra := math.Min(float64(g.extraAcked)-g.btlBw*now.Sub(g.extraAt).Seconds(), g.bdp(ccCwndGain))
	slot := (g.round / 5) % 2
	if g.extraRound[slot] != g.round/5 {
		g.extraRound[slot], g.extraBytes[slot] = g.round/5, 0
	}
	if extra > g.extraBytes[slot] {
		g.extraBytes[slot] = extra
	}
}

func (g *congestion) setPacing() {
	rate := g.pacingGain * g.btlBw
	if g.btlBw <= 0 {
		return
	}
	// Until the pipe is known to be full the rate may only rise.
	if !g.fullPipe && rate < g.pacing {
		return
	}
	g.pacing = math.Min(math.Max(rate, ccMinRate), ccMaxRate)
}

func (g *congestion) setCwnd(newly, inflight int) {
	target := int(g.bdp(g.cwndGain) + g.extra())
	if target < g.minPipe() {
		target = g.minPipe()
	}
	switch {
	case g.mode == ccProbeRTT:
		g.cwnd = min(g.cwnd, g.probeRTTCwnd())
		g.cwnd = max(g.minPipe(), min(g.cwnd, g.probeRTTCwnd()))
		return
	case g.conservation:
		// Packet conservation: while losses are being repaired, send no more than comes back.
		g.cwnd = max(inflight+newly, g.minPipe())
		g.cwnd = min(g.cwnd, max(target, g.initCwnd))
	case !g.fullPipe:
		// The model is still being found: open the window as fast as data is acknowledged, but
		// never beyond what the bandwidth measured so far could use. Without that bound a deep
		// buffer is filled with seconds of data before the plateau is noticed.
		if g.cwnd < target {
			g.cwnd = min(g.cwnd+newly, max(target, g.initCwnd))
		}
	default:
		g.cwnd = min(g.cwnd+newly, target)
	}
	if g.cwnd < g.minPipe() {
		g.cwnd = g.minPipe()
	}
	if g.inflightHi > 0 && g.cwnd > g.inflightHi {
		g.cwnd = max(g.inflightHi, g.minPipe())
	}
}

// onLoss notes bytes declared lost. A loss by itself changes nothing: repairs are paced like
// any other data. Only a round that loses more than ccLossThresh bounds the window (endRound).
func (g *congestion) onLoss(lost, inflight int) {
	g.roundLost += uint64(lost)
	g.roundLostPkts++
	if inflight+lost > g.roundLostPeak {
		g.roundLostPeak = inflight + lost
	}
}

// ccPersistentTimeouts is how many timeouts in a row mean the path has gone, not hiccuped.
const ccPersistentTimeouts = 3

// onTimeout is a whole flight going unanswered. The first timeouts are probes: a handover or a
// delay spike is far more common than a dead path, and what was measured is still the best
// description of it, so nothing is forgotten. After ccPersistentTimeouts in a row the path is
// treated as new: the model is discarded and relearned from the packets that get through.
func (g *congestion) onTimeout(consecutive int) {
	if consecutive < ccPersistentTimeouts {
		return
	}
	restart := ccHighGain * float64(g.initCwnd) / math.Max(g.rtProp.Seconds(), 0.05)
	g.btlBw, g.fullBw, g.fullBwCount, g.fullPipe = 0, 0, 0, false
	g.bwMax = [ccBwRounds]float64{}
	g.rtProp, g.rtPropAt = 0, time.Time{}
	g.rtRecent = [2]time.Duration{}
	g.mode, g.pacingGain, g.cwndGain = ccStartup, ccHighGain, ccHighGain
	g.inflightHi, g.growing = 0, false
	g.conservation = false
	g.cwnd = g.initCwnd
	g.pacing = math.Min(math.Max(restart, ccMinRate), ccMaxRate)
}

func (g *congestion) window() int { return g.cwnd }

func (g *congestion) pacingRate() float64 {
	if g.pacing < ccMinRate {
		return ccMinRate
	}
	return g.pacing
}
