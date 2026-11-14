package bond

import "time"

// Recovery (resends after loss, replays after a failover) must neither starve the
// flow it repairs nor become the burst that delays game packets queued behind it.
// The limit is therefore adaptive:
//
//   - It applies only while latency-sensitive traffic (a game or other non-TCP
//     packet) went out within recoveryGameWindow. With nothing like that to
//     protect, recovery is unlimited, so a download is repaired at full speed.
//   - While it applies, a path may spend a share of its rate on recovery, a share
//     that grows with the path's measured loss (more loss, more repair needed).
//   - A repair never waits longer than recoveryMaxDelay: once held that long, the
//     limit opens for recoveryEscape and the debt is carried, so sustained need is
//     served and only short spikes are smoothed.
const (
	recoveryShareMin     = 0.20  // fraction of a link's rate, with no loss
	recoveryShareMax     = 0.60  // ceiling as loss rises
	recoveryBurstSeconds = 0.005 // burst depth, in seconds of the link's rate
	recoveryBurstFloor   = 6000. // bytes: never smaller than a few packets
	recoveryMaxDelay     = 12 * time.Millisecond
	recoveryEscape       = 50 * time.Millisecond
	recoveryGameWindow   = 300 * time.Millisecond
	replayMaxAge         = 1500 * time.Millisecond // game packets only; TCP replays always go
	recoveryWindow       = 10 * time.Millisecond
)

func recoveryBurst(p *receivePath) float64 {
	b := p.budget.rate * recoveryBurstSeconds
	if b < recoveryBurstFloor {
		b = recoveryBurstFloor
	}
	return b
}

// recoveryShare is the fraction of the path's rate recovery may use: the base
// share plus three times the smoothed loss, up to the ceiling.
func (s *Sender) recoveryShare(p *receivePath, now time.Time) float64 {
	share := recoveryShareMin + 3*s.lossEstimate(p, s.r.seconds(now))
	if share > recoveryShareMax {
		share = recoveryShareMax
	}
	return share
}

// noteGame records that latency-sensitive traffic is flowing.
func (s *Sender) noteGame(now time.Time) { s.lastGame = now }

func (s *Sender) gameActive(now time.Time) bool {
	return !s.lastGame.IsZero() && now.Sub(s.lastGame) < recoveryGameWindow
}

// recoveryAllow reports whether path p may carry bytes of recovery traffic now.
func (s *Sender) recoveryAllow(p *receivePath, bytes int, now time.Time) bool {
	if !s.gameActive(now) {
		s.recHeldSince = time.Time{}
		return true
	}
	if now.Before(s.recEscapeUntil) {
		return true
	}
	burst := recoveryBurst(p)
	if p.recoveryAt.IsZero() {
		p.recoveryTokens, p.recoveryAt = burst, now
	}
	if dt := now.Sub(p.recoveryAt).Seconds(); dt > 0 {
		p.recoveryTokens += dt * p.budget.rate * s.recoveryShare(p, now)
		if p.recoveryTokens > burst {
			p.recoveryTokens = burst
		}
		p.recoveryAt = now
	}
	if p.recoveryTokens >= float64(bytes) {
		return true
	}
	if s.recHeldSince.IsZero() {
		s.recHeldSince = now
		return false
	}
	if now.Sub(s.recHeldSince) >= recoveryMaxDelay {
		s.recEscapeUntil = now.Add(recoveryEscape)
		s.stats.RecoveryEscapes++
		return true
	}
	return false
}

// recoverySpent charges a recovery frame to p and tracks the densest 10 ms window.
func (s *Sender) recoverySpent(p *receivePath, bytes int, now time.Time) {
	p.recoveryTokens -= float64(bytes)
	if floor := -2 * recoveryBurst(p); p.recoveryTokens < floor {
		p.recoveryTokens = floor // the debt of an escape is paid back, but bounded
	}
	s.recHeldSince = time.Time{}
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
