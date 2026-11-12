package bond

import "time"

// takeRepairToken spends one unit of the repair rate budget.
func (s *Sender) takeRepairToken(now time.Time) bool {
	if s.repairTokensAt.IsZero() {
		s.repairTokens, s.repairTokensAt = repairBurst, now
	}
	if dt := now.Sub(s.repairTokensAt).Seconds(); dt > 0 {
		s.repairTokens += dt * repairRate
		if s.repairTokens > repairBurst {
			s.repairTokens = repairBurst
		}
		s.repairTokensAt = now
	}
	if s.repairTokens < 1 {
		return false
	}
	s.repairTokens--
	return true
}
