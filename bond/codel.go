package bond

import (
	"encoding/binary"
	"math"
	"time"
)

// CoDel on the bulk queue. The fair queue already isolates flows (DRR); CoDel keeps
// each flow's own standing queue short. When a flow's packets have waited longer than
// codelTarget for a whole codelInterval, the head packet is ECN-marked (CE) if the flow
// negotiated ECN, otherwise dropped, and the rate of marks/drops rises with the
// square root of the count until the delay falls. Queue time includes time spent held
// back by pacing or the congestion window, which is exactly the standing queue that
// builds on the slow uplink. The target and interval are sized for a LEO path (round
// trips of 50-150 ms with jitter): a 12 ms / 120 ms setting treated every burst held
// behind the rate limit as a standing queue and dropped it, so TCP collapsed.

const (
	codelTarget   = 50 * time.Millisecond
	codelInterval = 300 * time.Millisecond
)

type codelFlow struct {
	firstAbove time.Time
	dropNext   time.Time
	count      int
	dropping   bool
	seen       time.Time
}

type codelState struct {
	flows map[string]*codelFlow
}

// verdict is what to do with the head packet of a flow.
type verdict int

const (
	codelKeep verdict = iota
	codelMark
	codelDrop
)

func (c *codelState) judge(flow string, sojourn time.Duration, ecn bool, now time.Time) verdict {
	if c.flows == nil {
		c.flows = make(map[string]*codelFlow)
	}
	if len(c.flows) > 4096 {
		for k, f := range c.flows {
			if now.Sub(f.seen) > 10*time.Second {
				delete(c.flows, k)
			}
		}
	}
	f := c.flows[flow]
	if f == nil {
		f = &codelFlow{}
		c.flows[flow] = f
	}
	f.seen = now
	if sojourn < codelTarget {
		f.firstAbove, f.dropping = time.Time{}, false
		return codelKeep
	}
	if f.firstAbove.IsZero() {
		f.firstAbove = now.Add(codelInterval)
		return codelKeep
	}
	act := func() verdict {
		if ecn {
			return codelMark
		}
		return codelDrop
	}
	if f.dropping {
		if now.Before(f.dropNext) {
			return codelKeep
		}
		f.count++
		f.dropNext = f.dropNext.Add(time.Duration(float64(codelInterval) / math.Sqrt(float64(f.count))))
		return act()
	}
	if now.Before(f.firstAbove) {
		return codelKeep
	}
	f.dropping = true
	if f.count > 2 {
		f.count -= 2 // resume near the previous rate if we were recently dropping
	} else {
		f.count = 1
	}
	f.dropNext = now.Add(time.Duration(float64(codelInterval) / math.Sqrt(float64(f.count))))
	return act()
}

// ecnCapable reports an IPv4 packet whose ECN field is ECT(0), ECT(1) or already CE.
func ecnCapable(packet []byte) bool {
	return len(packet) >= 20 && packet[0]>>4 == 4 && packet[1]&3 != 0
}

// markCE sets Congestion Experienced on an ECN-capable IPv4 packet in place and fixes
// the header checksum.
func markCE(packet []byte) bool {
	if !ecnCapable(packet) {
		return false
	}
	if packet[1]&3 == 3 {
		return true
	}
	header := int(packet[0]&15) * 4
	if header < 20 || header > len(packet) {
		return false
	}
	packet[1] |= 3
	packet[10], packet[11] = 0, 0
	sum := uint32(0)
	for i := 0; i < header; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:], ^uint16(sum))
	return true
}

// EnableCoDel turns on per-flow CoDel with ECN marking on the bulk queue. Off by default.
func (q *TransmitQueue) EnableCoDel(on bool) { q.codel = on }
