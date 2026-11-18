package bond

import (
	"container/list"
	"encoding/binary"
	"math"
	"sort"
	"time"
)

type repairEntry struct {
	key      MissingPacket
	payload  []byte
	at       time.Time
	attempts int
	order    *list.Element
	origin   *receivePath // path that last carried this packet (failover replay)
	// sent counts the frames put on the wire for this packet (original, copies,
	// resends) and lost how many of them the peer's selective acknowledgement showed
	// were dropped. When every one is lost the packet is gone unless we send it again.
	sent, lost int
	// carried lists every path a frame of this packet went out on (original,
	// copies, resends, replays), so a failover replay can see that a healthy
	// path already holds a copy.
	carried []*receivePath
}

func (e *repairEntry) carry(p *receivePath) {
	for _, q := range e.carried {
		if q == p {
			return
		}
	}
	e.carried = append(e.carried, p)
}

type askedRepair struct {
	key      MissingPacket
	at       time.Time
	attempts int
	order    *list.Element
	// exhausted marks a hole that used every attempt and is still missing.
	exhausted bool
	// resolved is set when the packet arrived after this ask, so it is judged once.
	resolved bool
}

// askScaleMax bounds how far spurious asks can widen the wait before the next one.
const askScaleMax = 3.

// noteArrival judges an ask the moment its packet turns up. An answer to an ask needs at least the fastest
// path's round trip, so a packet landing sooner than that was only late, and asking was wasted bandwidth
// and a duplicate for the application. The wait before asking grows with the share of asks that were
// spurious (as RACK's reordering window grows on DSACK) and shrinks back as they stop.
func (s *Sender) noteArrival(key MissingPacket, now time.Time) {
	a := s.asked[key]
	if a == nil || a.resolved {
		return
	}
	a.resolved = true
	least := math.Inf(1)
	for _, p := range s.r.paths {
		if p.ready && p.hasRTT {
			least = math.Min(least, p.rtt)
		}
	}
	if math.IsInf(least, 1) {
		return
	}
	sample := 0.
	if now.Sub(a.at).Seconds() < .9*least {
		s.stats.RepairSpurious++
		sample = 1
	} else {
		s.stats.RepairAnswered++
	}
	s.spuriousRate += .02 * (sample - s.spuriousRate)
	s.askScale = math.Min(askScaleMax, 1+4*math.Min(.5, s.spuriousRate))
	s.stats.RepairAskScale = s.askScale
}

// A 100 Mbps bulk flow is about 10,000 packets a second, so the old 2048-entry
// cache covered only 200 ms and four repairs per 10 ms could not keep up with
// a burst of loss: holes then waited out the reorder deadline and were skipped,
// which TCP reads as loss.
const (
	repairCacheMax = 131072 // ~170 MB at full-size packets; hardware is not the limit
	repairBatch    = 16
	// A hole is asked for up to repairAttempts times. Each ask goes out on every
	// ready path, and the answering copy prefers a path other than the one that last
	// carried the packet, so one lossy link cannot swallow both the request and the
	// answer.
	repairAttempts   = 8
	repairOriginBias = 0.015 // seconds added to the path that last carried the packet
	// Bounded ARQ: a resend happens only when SACK (or the tail probe) shows a frame was lost
	// or the peer asks, at most repairAttempts times, and repairs as a whole are limited to a
	// rate and burst so a loss storm cannot turn into a repair storm. There is no age timer.
	repairRate  = 30000. // resent packets per second
	repairBurst = 4096.
)

func repairable(packet []byte) bool {
	p, err := ParseIPv4(packet)
	return err == nil && p.Protocol == 6 && !p.Fragmented
}
func (s *Sender) cacheRepair(key MissingPacket, payload []byte, now time.Time, origin *receivePath) {
	if len(payload) > 2048 || !(s.failover || repairable(payload)) {
		s.noteNotCached(key, now)
		return
	}
	entry := &repairEntry{key: key, payload: append([]byte(nil), payload...), at: now, origin: origin, sent: 1, carried: []*receivePath{origin}}
	entry.order = s.repairOrder.PushBack(entry)
	s.repairs[key] = entry
	for len(s.repairs) > repairCacheMax {
		old := s.repairOrder.Front().Value.(*repairEntry)
		s.retire(old, now)
		delete(s.repairs, old.key)
		s.repairOrder.Remove(old.order)
	}
}

// Maintenance requests only short-lived TCP holes and sends at most four
// cached repairs per call. Repairs use fresh AEAD nonces but retain flow IDs
// and sequence numbers, so first arrival wins without injecting duplicates.
func (s *Sender) Maintenance(now time.Time, writer DatagramWriter) error {
	s.syncPeer()
	if !s.labMode {
		s.observeAggregateCongestion(now)
	}
	for s.repairOrder.Len() > 0 {
		old := s.repairOrder.Front().Value.(*repairEntry)
		if now.Sub(old.at) < s.repairLife() {
			break
		}
		s.retire(old, now)
		delete(s.repairs, old.key)
		s.repairOrder.Remove(old.order)
	}
	s.pruneTombstones(now)
	for s.askedOrder.Len() > 0 {
		old := s.askedOrder.Front().Value.(*askedRepair)
		if now.Sub(old.at) < 5*time.Second && len(s.asked) <= 16384 {
			break
		}
		delete(s.asked, old.key)
		s.askedOrder.Remove(old.order)
	}
	if s.labMode {
		return nil
	}
	s.tailProbe(now)
	s.flushParity(now, writer)
	s.sendDeferred(now, writer)
	if s.failover {
		if err := s.failoverStep(now, writer); err != nil {
			return err
		}
	}
	paths := s.eligible(now, true)
	if len(paths) == 0 {
		return nil
	}
	best := paths[0]
	minimum, maximum, jitter := math.Inf(1), 0., 0.
	for _, p := range paths {
		score, bestScore := 1., 1.
		if p.hasRTT {
			score = p.rtt
		}
		if best.hasRTT {
			bestScore = best.rtt
		}
		if score < bestScore {
			best = p
		}
		minimum = math.Min(minimum, p.rtt)
		maximum = math.Max(maximum, p.rtt)
		jitter = math.Max(jitter, p.jitter)
	}
	if s.nextRepairRequest.IsZero() || !now.Before(s.nextRepairRequest) {
		delay := time.Duration(math.Max(.012, (maximum-minimum)/2+jitter) * math.Max(1, s.askScale) * float64(time.Second))
		// UDP holes are asked for too: a lost video or QUIC packet is worth a resend, and the
		// peer answers late ones with an RepairNA, so asking costs one small frame.
		missing := s.r.reorder.Missing(now, delay, repairBatch, nil)
		if len(missing) > 0 {
			s.nextRepairRequest = now.Add(5 * time.Millisecond)
		}
		// Space asks so a copy can arrive before the next one goes out.
		gap := time.Duration(math.Min(.08, math.Max(.03, maximum*.75)) * float64(time.Second))
		for _, key := range missing {
			asked := s.asked[key]
			if asked != nil && asked.attempts >= repairAttempts {
				if !asked.exhausted {
					asked.exhausted = true
					s.stats.RepairExhausted++
				}
				continue
			}
			if asked != nil && now.Sub(asked.at) < gap {
				continue
			}
			body := make([]byte, 16)
			binary.BigEndian.PutUint64(body, key.Flow)
			binary.BigEndian.PutUint64(body[8:], key.Number)
			sent := false
			for _, p := range paths {
				frame, err := s.r.codec.Encode(Repair, body)
				if err != nil {
					return err
				}
				if s.written(Datagram{Endpoint: p.endpoint, Frame: frame, Local: p.local}, p, now, writer) {
					sent = true
				}
			}
			if sent {
				if asked == nil {
					asked = &askedRepair{key: key}
					asked.order = s.askedOrder.PushBack(asked)
					s.asked[key] = asked
				} else {
					s.askedOrder.MoveToBack(asked.order)
				}
				asked.at = now
				asked.resolved = false
				asked.attempts++
				s.stats.RepairRequests++
			}
		}
	}
	timestamp := s.r.seconds(now)
	for i := 0; i < repairBatch && s.requestOrder.Len() > 0; i++ {
		e := s.requestOrder.Front()
		key := e.Value.(MissingPacket)
		cached := s.repairs[key]
		if cached == nil || cached.attempts >= repairAttempts {
			delete(s.repairRequests, key)
			s.requestOrder.Remove(e)
			continue
		}
		if !s.takeRepairToken(now) {
			s.stats.RepairThrottled++
			break
		}
		refund := func() { s.repairTokens++ }
		size := len(cached.payload) + Overhead + 24
		type repairCandidate struct {
			p     *receivePath
			score float64
		}
		var candidates []repairCandidate
		for _, p := range s.fitPaths(paths, size) {
			ready, err := p.budget.ReadyAt(size, timestamp)
			if err != nil {
				return err
			}
			// Repairs are small and recover data the peer is already waiting for, so they
			// go out at once instead of queueing behind the path's bulk pacing; the wait
			// only decides which path is cheapest.
			ready = math.Max(ready, p.pacer.ReadyAt(size+28, timestamp))
			if !s.recoveryAllow(p, size+28, now) {
				continue // recovery is held to a share of each link
			}
			probe := 0.
			if p.hasRTT {
				probe = p.rtt
			}
			score := ready + p.budget.TransitSeconds(size, probe)
			if p == cached.origin {
				score += repairOriginBias
			}
			candidates = append(candidates, repairCandidate{p, score})
		}
		if len(candidates) == 0 {
			refund()
			s.stats.RepairThrottled++
			break
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].score < candidates[j].score })
		priorOrigin := cached.origin // the path that carried (and lost) this packet last
		target := candidates[0].p
		body := make([]byte, 24+len(cached.payload))
		binary.BigEndian.PutUint64(body, key.Flow)
		binary.BigEndian.PutUint64(body[8:], key.Number)
		binary.BigEndian.PutUint64(body[16:], target.txEpoch)
		copy(body[24:], cached.payload)
		frame, err := s.r.codec.Encode(Striped, body)
		if err != nil {
			return err
		}
		if !s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local, TrafficClass: outerTrafficClassForPath(cached.payload, target)}, target, now, writer) {
			break
		}
		sequence := binary.BigEndian.Uint64(frame[37:])
		target.budget.Sent(sequence, len(frame), timestamp)
		target.budget.Tag(sequence, key)
		cached.sent++
		cached.attempts++
		cached.origin = target
		cached.carry(target)
		s.recoverySpent(target, size+28, now)
		delete(s.repairRequests, key)
		s.requestOrder.Remove(e)
		s.stats.RepairCopies++
		s.stats.Copies++
		// A repair answers a packet that was already unlucky once: copy it onto a second path
		// too, the same redundancy every first-send packet gets (protection.go), so the repair
		// itself is not a single point of failure if that one chosen line blips right as it
		// goes out. The second path must not be the one that just lost the packet (priorOrigin):
		// duplicating onto the path already proven bad for this packet buys nothing. The copy
		// spends its own repair-rate token, so a quiet link cannot double the wire cost of every
		// repair, and a failed copy is not fatal: the primary already answered the request.
		var second *receivePath
		for _, c := range candidates[1:] {
			if c.p != priorOrigin {
				second = c.p
				break
			}
		}
		if second != nil && s.takeRepairToken(now) {
			body2 := make([]byte, 24+len(cached.payload))
			binary.BigEndian.PutUint64(body2, key.Flow)
			binary.BigEndian.PutUint64(body2[8:], key.Number)
			binary.BigEndian.PutUint64(body2[16:], second.txEpoch)
			copy(body2[24:], cached.payload)
			if frame2, err := s.r.codec.Encode(Striped, body2); err != nil {
				return err
			} else if s.written(Datagram{Endpoint: second.endpoint, Frame: frame2, Local: second.local, TrafficClass: outerTrafficClassForPath(cached.payload, second)}, second, now, writer) {
				sequence2 := binary.BigEndian.Uint64(frame2[37:])
				second.budget.Sent(sequence2, len(frame2), timestamp)
				second.budget.Tag(sequence2, key)
				cached.sent++
				cached.origin = second
				cached.carry(second)
				s.recoverySpent(second, size+28, now)
				s.stats.RepairCopies++
				s.stats.Copies++
			} else {
				s.repairTokens++ // the copy never left; refund its token
			}
		}
	}
	return nil
}

// repairLife is how long a sent packet stays cached; failover needs it to
// outlive the suspicion delay.
func (s *Sender) repairLife() time.Duration {
	life := 5 * time.Second
	if s.failover {
		life = 8 * time.Second
	}
	// A repair must outlive the slowest path's round trip with room for several asks (SRT and RIST size the
	// buffer from RTT the same way); on a long-delay path a fixed few seconds would expire entries mid-ask.
	slow := 0.
	for _, p := range s.r.paths {
		if p.ready && p.hasRTT {
			slow = math.Max(slow, p.rtt)
		}
	}
	if need := time.Duration(repairAttempts * 2 * slow * float64(time.Second)); need > life {
		life = need
	}
	return life
}
