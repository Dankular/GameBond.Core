package bond

import "math"

// ECMP-style flow pinning with fast reroute.
//
// With pinning on, each bulk flow sticks to one path so its packets arrive in order
// instead of being striped across paths with different delays. New flows pin to the
// path that is least loaded (the fair-queue winner), which spreads flows across
// paths in proportion to capacity. Each pinned flow also keeps a precomputed backup
// (the best other usable path). When the pin stops being usable (BFD Down, suspect,
// loss-steered, hinted) the flow flips to its backup on the very next packet and
// stays there, so it does not bounce back when the old path recovers. A flow stripes
// again only when its pin cannot send for longer than pinSpillWait (bigger than one
// path can carry).

const pinSpillWait = 0.020 // seconds the pinned path may be busy before the flow spills

// pinChoose picks the path for a flow from the usable set (paths) and those ready to
// send now (available, best first). It returns nil when the flow should wait for its
// pinned path, with the time that path becomes ready.
func (s *Sender) pinChoose(f *sendFlow, paths, available []*receivePath, ready map[*receivePath]float64, ts float64) (*receivePath, float64) {
	usable := func(p *receivePath) bool {
		for _, q := range paths {
			if q == p {
				return true
			}
		}
		return false
	}
	if f.pin != nil && !usable(f.pin) {
		// Fast reroute: flip to the precomputed backup, or the best path if that is gone too.
		next := f.backup
		if next == nil || !usable(next) {
			next = nil
			if len(available) > 0 {
				next = available[0]
			} else if len(paths) > 0 {
				next = paths[0]
			}
		}
		if next != nil {
			f.pin, f.backup = next, nil
			s.stats.FastReroutes++
		}
	}
	if f.pin == nil && len(available) > 0 {
		f.pin = available[0]
		s.stats.FlowsPinned++
	}
	if f.pin == nil {
		return nil, 0
	}
	if f.backup == nil || f.backup == f.pin || !usable(f.backup) {
		f.backup = nil
		best := math.Inf(1)
		for _, p := range paths {
			if p != f.pin && p.budget.TransitSeconds(1200, 0) < best {
				f.backup, best = p, p.budget.TransitSeconds(1200, 0)
			}
		}
	}
	at := ready[f.pin]
	if at <= ts+.000001 {
		return f.pin, 0
	}
	if at-ts > pinSpillWait && len(available) > 0 {
		s.stats.PinSpills++
		return available[0], 0
	}
	return nil, at
}

// SetFlowPinning turns on flow pinning with fast reroute. Off by default.
func (s *Sender) SetFlowPinning(on bool) { s.pinning = on }
