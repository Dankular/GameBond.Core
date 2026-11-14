package bond

import "time"

// Recovery (resends after loss, replays after a failover) must not become the
// thing that hurts the traffic it protects. It is held to a share of each link,
// with a burst of a few milliseconds, so a repair pass cannot fill a slow uplink's
// buffer and delay game packets queued behind it. Game traffic (anything that is
// not a TCP segment) is recovered first, because TCP resends for itself.
const (
	recoveryShare        = 0.20  // fraction of a link's rate recovery may use
	recoveryBurstSeconds = 0.005 // burst depth, in seconds of the link's rate
	recoveryBurstFloor   = 6000. // bytes: never smaller than a few packets
	replayMaxAge         = 1500 * time.Millisecond
	recoveryWindow       = 10 * time.Millisecond
)

func recoveryBurst(p *receivePath) float64 {
	b := p.budget.rate * recoveryBurstSeconds
	if b < recoveryBurstFloor {
		b = recoveryBurstFloor
	}
	return b
}

// recoveryAllow reports whether path p may carry bytes of recovery traffic now.
func (s *Sender) recoveryAllow(p *receivePath, bytes int, now time.Time) bool {
	burst := recoveryBurst(p)
	if p.recoveryAt.IsZero() {
		p.recoveryTokens, p.recoveryAt = burst, now
	}
	if dt := now.Sub(p.recoveryAt).Seconds(); dt > 0 {
		p.recoveryTokens += dt * p.budget.rate * recoveryShare
		if p.recoveryTokens > burst {
			p.recoveryTokens = burst
		}
		p.recoveryAt = now
	}
	return p.recoveryTokens >= float64(bytes)
}

// recoverySpent charges a recovery frame to p and tracks the densest 10 ms window.
func (s *Sender) recoverySpent(p *receivePath, bytes int, now time.Time) {
	p.recoveryTokens -= float64(bytes)
	if s.recWinStart.IsZero() || now.Sub(s.recWinStart) >= recoveryWindow {
		s.recWinStart, s.recWinCount = now, 0
	}
	s.recWinCount++
	if s.recWinCount > s.stats.RecoveryPeak10ms {
		s.stats.RecoveryPeak10ms = s.recWinCount
	}
}

// queueRepair puts a key on the repair queue, game traffic ahead of TCP.
func (s *Sender) queueRepair(key MissingPacket, payload []byte) {
	if s.repairRequests[key] != nil {
		return
	}
	if repairable(payload) {
		s.repairRequests[key] = s.requestOrder.PushBack(key)
	} else {
		s.repairRequests[key] = s.requestOrder.PushFront(key)
	}
}
