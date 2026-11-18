package bond

import (
	"encoding/binary"
	"time"
)

// Selective acknowledgement. The cumulative feedback (highest sequence, delivered
// bytes) says how much arrived but not which frames did not, so a loss was only
// noticed by timeout or by the peer waiting out a reorder hole. The feedback also
// carries a bitmap of the last sackBits frame sequences received on the path; the
// sender calls a tracked frame lost once later frames of that path arrived without it
// and answers at once on the other path.

const (
	sackBits         = 512
	sackWords        = sackBits / 64
	feedbackSackSize = 28 + 8 + sackBits/8 // epoch, sequence, bytes, hold, base, bitmap
)

// A loss that slides out of the bitmap before the sender hears of it (a feedback gap longer than the
// window: a link that went quiet for a second, or a burst faster than the report cadence) would
// otherwise be retired by the cumulative acknowledgement unmarked. RFC 2018 and RFC 8888 report
// ranges for this reason: the window bounds the detail, not how far back a gap can be named. The
// receiver keeps the evicted gaps as ranges and repeats them in the next sackMissReports reports.
const (
	sackMissMax     = 16      // ranges carried in one report
	sackMissSpan    = 1 << 16 // a longer jump is a restart, not a loss to name
	sackMissReports = 40      // reports a range rides on before it is dropped
	sackMissSize    = 12      // wire bytes per range: start (8) and count (4)
)

type missRange struct {
	start uint64
	n     uint32
	born  uint64
}

// sackWindow is a sliding bitmap ending at the highest sequence seen on a path.
type sackWindow struct {
	high    uint64
	seen    bool
	bits    [sackWords]uint64
	missed  []missRange
	reports uint64
	first   uint64 // the first sequence seen: nothing below it was ever expected
}

func windowBase(high uint64) uint64 {
	if high >= sackBits-1 {
		return high - (sackBits - 1)
	}
	return 0
}

func (w *sackWindow) has(seq uint64) bool { return w.bits[(seq%sackBits)/64]&(1<<(seq%64)) != 0 }

// miss records one or more consecutive missing sequences.
func (w *sackWindow) miss(start uint64, n uint64) {
	if n == 0 || n > sackMissSpan {
		return
	}
	if l := len(w.missed); l > 0 && w.missed[l-1].start+uint64(w.missed[l-1].n) == start && uint64(w.missed[l-1].n)+n <= sackMissSpan {
		w.missed[l-1].n += uint32(n)
		w.missed[l-1].born = w.reports
		return
	}
	if len(w.missed) >= sackMissMax {
		w.missed = w.missed[1:]
	}
	w.missed = append(w.missed, missRange{start: start, n: uint32(n), born: w.reports})
}

// unmiss removes a sequence that turned up after it was named missing.
func (w *sackWindow) unmiss(seq uint64) {
	for i, m := range w.missed {
		if seq < m.start || seq >= m.start+uint64(m.n) {
			continue
		}
		before, after := seq-m.start, m.start+uint64(m.n)-seq-1
		rest := append([]missRange(nil), w.missed[i+1:]...)
		w.missed = w.missed[:i]
		if before > 0 {
			w.missed = append(w.missed, missRange{start: m.start, n: uint32(before), born: m.born})
		}
		if after > 0 {
			w.missed = append(w.missed, missRange{start: seq + 1, n: uint32(after), born: m.born})
		}
		w.missed = append(w.missed, rest...)
		return
	}
}

// evict names the gaps in the part of the window about to scroll out when the highest sequence
// moves from w.high to seq, including the numbers between the old high and the new window.
func (w *sackWindow) evict(seq uint64) {
	oldBase, newBase := windowBase(w.high), windowBase(seq)
	run, runStart := uint64(0), uint64(0)
	for s := max(oldBase, w.first); s < newBase && s <= w.high; s++ {
		if w.has(s) {
			if run > 0 {
				w.miss(runStart, run)
				run = 0
			}
			continue
		}
		if run == 0 {
			runStart = s
		}
		run++
	}
	if run > 0 {
		w.miss(runStart, run)
	}
	if newBase > w.high+1 {
		w.miss(w.high+1, newBase-w.high-1)
	}
}

// Missed returns the evicted gaps still worth repeating and ages the rest out. It runs once per
// report, so a range rides on a fixed number of reports whatever the cadence.
func (w *sackWindow) Missed() []missRange {
	w.reports++
	kept := w.missed[:0]
	for _, m := range w.missed {
		if w.reports-m.born <= sackMissReports {
			kept = append(kept, m)
		}
	}
	w.missed = kept
	return append([]missRange(nil), kept...)
}

// encodeMissed appends the optional trailer to a feedback payload: a count, then the ranges.
func encodeMissed(payload []byte, ranges []missRange) []byte {
	if len(ranges) == 0 {
		return payload
	}
	payload = append(payload, byte(len(ranges)))
	for _, m := range ranges {
		payload = binary.BigEndian.AppendUint64(payload, m.start)
		payload = binary.BigEndian.AppendUint32(payload, m.n)
	}
	return payload
}

// decodeMissed reads the trailer; ok is false when the length does not match the count.
func decodeMissed(tail []byte) ([]missRange, bool) {
	if len(tail) == 0 {
		return nil, true
	}
	n := int(tail[0])
	if n < 1 || n > sackMissMax || len(tail) != 1+n*sackMissSize {
		return nil, false
	}
	out := make([]missRange, n)
	for i := range out {
		b := tail[1+i*sackMissSize:]
		out[i] = missRange{start: binary.BigEndian.Uint64(b), n: binary.BigEndian.Uint32(b[8:])}
	}
	return out, true
}

func (w *sackWindow) clear(seq uint64) { w.bits[(seq%sackBits)/64] &^= 1 << (seq % 64) }

// Note records the receipt of one frame sequence.
func (w *sackWindow) Note(seq uint64) {
	if !w.seen {
		w.seen, w.high, w.first = true, seq, seq
	} else if seq > w.high {
		w.evict(seq)
		if seq-w.high >= sackBits {
			w.bits = [sackWords]uint64{}
		} else {
			for s := w.high + 1; s <= seq; s++ {
				w.clear(s)
			}
		}
		w.high = seq
	} else if w.high-seq >= sackBits {
		w.unmiss(seq) // older than the window: it was named missing, and it came after all
		return
	}
	w.bits[(seq%sackBits)/64] |= 1 << (seq % 64)
}

// Report returns the first sequence covered and the bitmap over sackBits sequences.
func (w *sackWindow) Report() (uint64, []byte) {
	out := make([]byte, sackBits/8)
	if !w.seen {
		return 0, out
	}
	base := uint64(0)
	if w.high >= sackBits-1 {
		base = w.high - (sackBits - 1)
	}
	for i := uint64(0); i < sackBits; i++ {
		s := base + i
		if s > w.high {
			break
		}
		if w.bits[(s%sackBits)/64]&(1<<(s%64)) != 0 {
			out[i/8] |= 1 << (i % 8)
		}
	}
	return base, out
}

// acknowledge applies one feedback frame: the selective part first (the cumulative
// part retires the entries it needs), then the cumulative acknowledgement.
func (r *Receiver) acknowledge(p *receivePath, payload []byte, out *ReceiveResult, sequence, delivered uint64, now float64) bool {
	var lost []MissingPacket
	if len(payload) >= feedbackSackSize {
		var outcomes []SackObservation
		lost, outcomes = p.budget.SackWithObservations(binary.BigEndian.Uint64(payload[28:]), payload[36:feedbackSackSize])
		if p.mtu != nil {
			for _, outcome := range outcomes {
				p.mtu.ObserveDataOutcome(outcome, now)
			}
		}
		if ranges, ok := decodeMissed(payload[feedbackSackSize:]); ok && len(ranges) > 0 {
			lost = append(lost, p.budget.SackMissed(ranges)...)
		}
	}
	// Reported once: Sack marks the entries, so keep the result even if the
	// cumulative part is refused.
	out.Lost = append(out.Lost, lost...)
	return p.budget.Acknowledge(sequence, delivered, now, binary.BigEndian.Uint32(payload[24:]))
}

// sackLoss handles one flow packet whose frame the peer's selective acknowledgement
// showed was dropped on a path. If every frame sent for it is now lost it goes out
// again at once (Maintenance picks the best path, biased away from the one that
// lost it); if a sibling copy is still unaccounted for, it waits for that frame's own
// report instead of sending a third.
func (s *Sender) sackLoss(key MissingPacket, now time.Time) {
	s.stats.SackLost++
	s.addLossHeat(now)
	cached := s.repairs[key]
	if cached == nil {
		// No payload to resend. The tombstone still knows how many copies went out,
		// so a loss with a sibling copy unaccounted for is covered, not unrecovered.
		if t := s.tombs[key]; t != nil {
			t.lost++
			if t.lost < t.sent {
				s.stats.SackHeld++
				return
			}
			s.stats.SackUnrecoverable++
			if t.uncached {
				s.stats.SackNotRepairable++
			} else {
				s.stats.SackExpired++
			}
			return
		}
		s.stats.SackUnrecoverable++
		s.stats.SackExpired++ // too old even for a tombstone
		return
	}
	if cached.attempts >= repairAttempts {
		s.stats.SackUnrecoverable++
		s.stats.SackExhausted++
		return
	}
	cached.lost++
	if cached.lost < cached.sent {
		s.stats.SackHeld++
		return
	}
	s.queueRepair(key, cached.payload)
	s.stats.SackResent++
}

// tailProbe treats frames nobody has acknowledged for more than a round trip as lost
// and sends their packets again on the best path (see Budget.TailLost). It is what
// protects the last packets of a burst, and everything in flight on a path that went
// quiet.
func (s *Sender) tailProbe(now time.Time) {
	ts := s.r.seconds(now)
	for _, p := range s.r.paths {
		if !p.ready || !p.hasFeedback {
			continue
		}
		for _, key := range p.budget.TailLost(ts) {
			s.stats.TailProbed++
			s.sackLoss(key, now)
		}
	}
}
