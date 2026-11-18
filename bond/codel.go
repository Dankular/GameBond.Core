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
// back by pacing or the congestion window. The 5 ms target and 100 ms interval are
// RFC 8289's normal Internet defaults; non-starvation prevents drops when less than
// one maximum packet would remain queued.

const (
	codelTarget   = 5 * time.Millisecond
	codelInterval = 100 * time.Millisecond
)

type codelFlow struct {
	firstAbove time.Time
	dropNext   time.Time
	count      int
	lastCount  int
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

func (c *codelState) judge(flow string, sojourn time.Duration, backlog, maxPacket int, ecn bool, now time.Time) verdict {
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
	// RFC 8289's non-starvation rule suppresses dropping when it would leave
	// less than one maximum packet queued. Apply it per flow because this CoDel
	// instance sits behind the per-flow DRR queues.
	if sojourn < codelTarget || backlog <= maxPacket {
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
	// RFC 8289 Section 5.5 uses the previous drop episode's count as a
	// starting point when the queue rises above TARGET again soon after it
	// left dropping mode. This avoids restarting the control loop too slowly
	// when the previous episode had already found an effective drop rate.
	delta := f.count - f.lastCount
	f.count = 1
	if delta > 1 && now.Sub(f.dropNext) < 16*codelInterval {
		f.count = delta
	}
	f.dropNext = now.Add(time.Duration(float64(codelInterval) / math.Sqrt(float64(f.count))))
	f.lastCount = f.count
	return act()
}

// ecnCapable reports an IPv4 or IPv6 packet whose ECN field is ECT(0), ECT(1) or CE.
func ecnCapable(packet []byte) bool {
	trafficClass, ok := innerTrafficClass(packet)
	if !ok || trafficClass&3 == 0 {
		return false
	}
	if packet[0]>>4 == 4 {
		header := int(packet[0]&15) * 4
		return header >= 20 && header <= len(packet)
	}
	return packet[0]>>4 == 6
}

// markCE sets Congestion Experienced on an ECN-capable IPv4 or IPv6 packet in
// place, repairing the IPv4 header checksum when required.
func markCE(packet []byte) bool {
	if !ecnCapable(packet) {
		return false
	}
	trafficClass, _ := innerTrafficClass(packet)
	if trafficClass&3 == 3 {
		return true
	}
	switch packet[0] >> 4 {
	case 4:
		header := int(packet[0]&15) * 4
		if header < 20 || header > len(packet) {
			return false
		}
		packet[1] = packet[1]&0xfc | 3
		packet[10], packet[11] = 0, 0
		sum := uint32(0)
		for i := 0; i < header; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i:]))
		}
		for sum>>16 != 0 {
			sum = sum&0xFFFF + sum>>16
		}
		binary.BigEndian.PutUint16(packet[10:], ^uint16(sum))
	case 6:
		trafficClass = (packet[0]&0x0f)<<4 | packet[1]>>4
		trafficClass = trafficClass&0xfc | 3
		packet[0] = packet[0]&0xf0 | trafficClass>>4
		packet[1] = trafficClass<<4 | packet[1]&0x0f
	default:
		return false
	}
	return true
}

// EnableCoDel turns on per-flow CoDel with ECN marking on the bulk queue. Off by default.
func (q *TransmitQueue) EnableCoDel(on bool) { q.codel = on }
