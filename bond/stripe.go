package bond

import (
	"math"
	"time"
)

// Heavy-flow striping. Duplicating every packet makes the bonded link no faster than its
// slower path, which is right for a game or a call but caps a video download at one link's
// speed. A flow that keeps sending above the threshold is striped across the paths instead
// (each packet once, the fair split picks the path); lost packets are still asked for from
// the repair cache, and the flow goes back to duplication when it slows down.

const stripeWindow = 500 * time.Millisecond

// SetStripeAbove sets the sustained rate (Mbit/s) above which a bulk flow is striped
// rather than duplicated; 0 keeps every flow duplicated.
func (s *Sender) SetStripeAbove(mbps float64) { s.stripeMbps = mbps }

func (s *Sender) noteFlowRate(f *sendFlow, bytes int, now time.Time) {
	if s.stripeMbps <= 0 {
		f.striped, f.stripeOn = false, false
		return
	}
	if f.rateAt.IsZero() || now.Sub(f.rateAt) > 4*stripeWindow {
		f.rateAt, f.rateBytes = now, 0
	}
	f.rateBytes += bytes + Overhead
	if dt := now.Sub(f.rateAt); dt >= stripeWindow {
		mbps := float64(f.rateBytes) * 8 / dt.Seconds() / 1e6
		switch {
		case mbps >= s.stripeMbps:
			f.striped = true
		case mbps < s.stripeMbps/2:
			f.striped = false
		}
		f.rateAt, f.rateBytes = now, 0
	}
	f.stripeOn = f.striped && s.stripeCalm(now)
}

// StripedFlows counts the flows currently striped.
func (s *Sender) StripedFlows() int {
	n := 0
	for _, f := range s.flows {
		if f.stripeOn {
			n++
		}
	}
	return n
}

// Striping gives up first-arrival redundancy, so it is only allowed while every path is
// calm, and it ends at once, for every flow, the moment any path shows a spike. The hold
// keeps a flapping link from toggling the mode.
const (
	stripeHold       = 10 * time.Second
	stripeCalmLoss   = .003
	stripeCalmJitter = .020
	stripeRecheck    = 2 * time.Millisecond
)

func (s *Sender) stripeCalm(now time.Time) bool {
	if now.Before(s.calmUntil) {
		return false
	}
	if now.Sub(s.calmChecked) < stripeRecheck && !s.calmChecked.IsZero() {
		return s.calm
	}
	s.calmChecked = now
	paths := s.eligible(now, true)
	calm := len(paths) >= 2
	ts := s.r.seconds(now)
	for _, p := range paths {
		if s.atRisk(p, now) || s.pathSuspect(p, now) || s.hinted(p.local, now) || p.steerOn ||
			s.lossEstimate(p, ts) >= stripeCalmLoss || p.jitter > stripeCalmJitter || p.bfdDown() ||
			(p.budget.hasMin && p.budget.rawSRTT-p.budget.minRTT > math.Max(.060, 3*p.budget.minRTT)) {
			calm = false
			s.calmUntil = now.Add(stripeHold)
			break
		}
	}
	s.calm = calm
	return calm
}
