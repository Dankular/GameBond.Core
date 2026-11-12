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

// sackWindow is a sliding bitmap ending at the highest sequence seen on a path.
type sackWindow struct {
	high uint64
	seen bool
	bits [sackWords]uint64
}

func (w *sackWindow) clear(seq uint64) { w.bits[(seq%sackBits)/64] &^= 1 << (seq % 64) }

// Note records the receipt of one frame sequence.
func (w *sackWindow) Note(seq uint64) {
	if !w.seen {
		w.seen, w.high = true, seq
	} else if seq > w.high {
		if seq-w.high >= sackBits {
			w.bits = [sackWords]uint64{}
		} else {
			for s := w.high + 1; s <= seq; s++ {
				w.clear(s)
			}
		}
		w.high = seq
	} else if w.high-seq >= sackBits {
		return // older than the window
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
	if len(payload) == feedbackSackSize {
		lost = p.budget.Sack(binary.BigEndian.Uint64(payload[28:]), payload[36:])
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
	if cached == nil || cached.attempts >= repairAttempts {
		s.stats.SackUnrecoverable++
		return
	}
	cached.lost++
	if cached.lost < cached.sent {
		s.stats.SackHeld++
		return
	}
	if s.repairRequests[key] == nil {
		s.repairRequests[key] = s.requestOrder.PushBack(key)
	}
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
