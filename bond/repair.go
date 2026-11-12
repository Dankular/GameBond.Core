package bond

import (
	"container/list"
	"encoding/binary"
	"math"
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
}
type askedRepair struct {
	key      MissingPacket
	at       time.Time
	attempts int
	order    *list.Element
	// exhausted marks a hole that used every attempt and is still missing.
	exhausted bool
}

// A 100 Mbps bulk flow is about 10,000 packets a second, so the old 2048-entry
// cache covered only 200 ms and four repairs per 10 ms could not keep up with
// a burst of loss: holes then waited out the reorder deadline and were skipped,
// which TCP reads as loss.
const (
	repairCacheMax = 16384
	repairBatch    = 16
	// A hole is asked for up to repairAttempts times. Each ask goes out on every
	// ready path, and the answering copy prefers a path other than the one that last
	// carried the packet, so one lossy link cannot swallow both the request and the
	// answer.
	repairAttempts   = 4
	repairOriginBias = 0.015 // seconds added to the path that last carried the packet
	// Bounded ARQ: a resend happens only when SACK (or the tail probe) shows a frame was lost
	// or the peer asks, at most repairAttempts times, and repairs as a whole are limited to a
	// rate and burst so a loss storm cannot turn into a repair storm. There is no age timer.
	repairRate  = 3000. // resent packets per second
	repairBurst = 512.
)

func repairable(packet []byte) bool {
	p, err := ParseIPv4(packet)
	return err == nil && p.Protocol == 6 && !p.Fragmented
}
func (s *Sender) cacheRepair(key MissingPacket, payload []byte, now time.Time, origin *receivePath) {
	if len(payload) > 2048 || !(s.failover || repairable(payload)) {
		return
	}
	entry := &repairEntry{key: key, payload: append([]byte(nil), payload...), at: now, origin: origin, sent: 1}
	entry.order = s.repairOrder.PushBack(entry)
	s.repairs[key] = entry
	for len(s.repairs) > repairCacheMax {
		old := s.repairOrder.Front().Value.(*repairEntry)
		delete(s.repairs, old.key)
		s.repairOrder.Remove(old.order)
	}
}

// Maintenance requests only short-lived TCP holes and sends at most four
// cached repairs per call. Repairs use fresh AEAD nonces but retain flow IDs
// and sequence numbers, so first arrival wins without injecting duplicates.
func (s *Sender) Maintenance(now time.Time, writer DatagramWriter) error {
	s.syncPeer()
	for s.repairOrder.Len() > 0 {
		old := s.repairOrder.Front().Value.(*repairEntry)
		if now.Sub(old.at) < s.repairLife() {
			break
		}
		delete(s.repairs, old.key)
		s.repairOrder.Remove(old.order)
	}
	for s.askedOrder.Len() > 0 {
		old := s.askedOrder.Front().Value.(*askedRepair)
		if now.Sub(old.at) < time.Second && len(s.asked) <= 2048 {
			break
		}
		delete(s.asked, old.key)
		s.askedOrder.Remove(old.order)
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
		delay := time.Duration(math.Max(.012, (maximum-minimum)/2+jitter) * float64(time.Second))
		missing := s.r.reorder.Missing(now, delay, repairBatch, repairable)
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
		size := len(cached.payload) + Overhead + 24
		var target *receivePath
		bestScore := math.Inf(1)
		for _, p := range s.fitPaths(paths, size) {
			ready, err := p.budget.ReadyAt(size, timestamp)
			if err != nil {
				return err
			}
			// Repairs are small and recover data the peer is already waiting for, so they
			// go out at once instead of queueing behind the path's bulk pacing; the wait
			// only decides which path is cheapest.
			ready = math.Max(ready, p.pacer.ReadyAt(size+28, timestamp))
			probe := 0.
			if p.hasRTT {
				probe = p.rtt
			}
			score := ready + p.budget.TransitSeconds(size, probe)
			if p == cached.origin {
				score += repairOriginBias
			}
			if score < bestScore {
				bestScore = score
				target = p
			}
		}
		if target == nil {
			break
		}
		body := make([]byte, 24+len(cached.payload))
		binary.BigEndian.PutUint64(body, key.Flow)
		binary.BigEndian.PutUint64(body[8:], key.Number)
		binary.BigEndian.PutUint64(body[16:], target.txEpoch)
		copy(body[24:], cached.payload)
		frame, err := s.r.codec.Encode(Striped, body)
		if err != nil {
			return err
		}
		if s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
			sequence := binary.BigEndian.Uint64(frame[37:])
			target.budget.Sent(sequence, len(frame), timestamp)
			target.budget.Tag(sequence, key)
			cached.sent++
			cached.attempts++
			cached.origin = target
			delete(s.repairRequests, key)
			s.requestOrder.Remove(e)
			s.stats.RepairCopies++
			s.stats.Copies++
		} else {
			break
		}
	}
	return nil
}

// repairLife is how long a sent packet stays cached; failover needs it to
// outlive the suspicion delay.
func (s *Sender) repairLife() time.Duration {
	if s.failover {
		return 3 * time.Second
	}
	return time.Second
}
