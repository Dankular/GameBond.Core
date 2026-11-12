package bond

import "fmt"

// Alarm is a transport health problem worth surfacing: it does not change
// behaviour, it makes a silent failure (such as feedback being rejected, which
// starves the rate controller while loss and RTT still look fine) visible.
type Alarm struct {
	Kind   string `json:"kind"`
	Link   int    `json:"link"` // 1-based link number, 0 for the whole transport
	Detail string `json:"detail"`
}

// Health turns successive snapshots into alarms. Call Observe once per status
// tick (about a second apart).
type Health struct {
	started            bool
	received, rejected uint64
	timeoutStreak      map[int]int
	rejectedStreak     int
}

const (
	healthRejectRatio   = .2 // share of feedback frames refused that raises an alarm
	healthRejectMinimum = 20 // refused frames per tick below which the ratio is noise
	healthTimeoutRatio  = .5 // share of a link's packets expiring unacknowledged
	healthStreak        = 3  // consecutive ticks before an alarm is raised
)

// Observe takes the cumulative feedback counters and each link's feedback-timeout
// ratio (index order) and returns the alarms active now.
func (h *Health) Observe(received, rejected uint64, timeouts []float64) []Alarm {
	var alarms []Alarm
	if h.started {
		dRec, dRej := delta64(received, h.received), delta64(rejected, h.rejected)
		if dRej >= healthRejectMinimum && float64(dRej) >= healthRejectRatio*float64(dRec+dRej) {
			h.rejectedStreak++
		} else {
			h.rejectedStreak = 0
		}
		if h.rejectedStreak >= healthStreak {
			alarms = append(alarms, Alarm{"feedback_rejected", 0, fmt.Sprintf("%d of %d feedback frames refused in the last second: the rate controller is not getting acknowledgements", dRej, dRec+dRej)})
		}
	}
	h.started, h.received, h.rejected = true, received, rejected
	if h.timeoutStreak == nil {
		h.timeoutStreak = map[int]int{}
	}
	for i, ratio := range timeouts {
		if ratio >= healthTimeoutRatio {
			h.timeoutStreak[i]++
		} else {
			h.timeoutStreak[i] = 0
		}
		if h.timeoutStreak[i] >= healthStreak {
			alarms = append(alarms, Alarm{"feedback_timeout", i + 1, fmt.Sprintf("%.0f%% of packets on this link expire unacknowledged", ratio*100)})
		}
	}
	return alarms
}

func delta64(now, before uint64) uint64 {
	if now < before {
		return 0
	}
	return now - before
}
