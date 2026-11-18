package bond

import (
	"container/heap"
	"math"
	"testing"
)

type capacitySample struct {
	sent, received, lost uint64
	delaySum             float64
	delays               int
	rateMbps             float64
}

// RFC 8867 Section 5.1 uses a 2 Mbps reference bottleneck with capacity ratios
// 1.0, 2.5, 0.6, and 1.0 starting at 0, 40, 60, and 80 seconds. This deterministic
// single-flow model exercises GameBond's production Budget against that capacity
// timeline and logs 200 ms sending/goodput/delay/loss samples per RFC 8868.
func TestRFC8867VariableCapacitySingleFlow(t *testing.T) {
	const (
		packetSize = 1200
		seconds    = 100
		oneWay     = .050
		queueLimit = .300
	)
	b, err := NewBudget(10, 100)
	if err != nil {
		t.Fatal(err)
	}
	b.UseLiveLimits()
	b.delayControl, b.delayAssertive = true, true
	var acks simAcks
	var sequence, delivered, sent uint64
	sentAt := make(map[uint64]float64)
	var linkFree float64
	const tick = .001
	samples := make([]capacitySample, seconds*5)
	capacityAt := func(now float64) float64 {
		switch {
		case now >= 80:
			return 2.0
		case now >= 60:
			return 1.2
		case now >= 40:
			return 5.0
		default:
			return 2.0
		}
	}
	for ms := 0; ms < seconds*1000; ms++ {
		now := float64(ms) * tick
		for len(acks) > 0 && acks[0].at <= now {
			a := heap.Pop(&acks).(simAck)
			b.Acknowledge(a.seq, a.delivered, a.at, 0)
			at, ok := sentAt[a.seq]
			idx := int(a.at * 5)
			if ok && idx >= 0 && idx < len(samples) {
				samples[idx].received += packetSize
				samples[idx].delaySum += a.at - at - oneWay
				samples[idx].delays++
			}
		}
		b.Expire(now)
		samples[ms/200].rateMbps = b.RateMbps()
		for n := 0; n < 100; n++ {
			ready, err := b.ReadyAt(packetSize, now)
			if err != nil || ready > now+1e-6 {
				break
			}
			sequence++
			sentAt[sequence] = now
			if _, err := b.Sent(sequence, packetSize, now); err != nil {
				t.Fatal(err)
			}
			sent++
			idx := ms / 200
			samples[idx].sent += packetSize
			start := max(now, linkFree)
			capacityBytes := capacityAt(start) * 125000
			if start-now > queueLimit {
				samples[idx].lost += packetSize
				continue
			}
			linkFree = start + float64(packetSize+28)/capacityBytes
			delivered += packetSize
			arrived := linkFree + oneWay
			heap.Push(&acks, simAck{at: arrived + oneWay, seq: sequence, delivered: delivered})
		}
	}

	// Report each RFC 8867 capacity epoch using the final 10 s, excluding the
	// transient immediately after a capacity change. Loss is reported against
	// offered packets; delay is the media packet's one-way sojourn to the receiver.
	for _, epoch := range []struct {
		name       string
		start, end int
		capacity   float64
	}{
		{name: "1x initial", start: 20, end: 39, capacity: 2},
		{name: "2.5x", start: 45, end: 59, capacity: 5},
		{name: "0.6x", start: 65, end: 79, capacity: 1.2},
		{name: "1x restored", start: 85, end: 99, capacity: 2},
	} {
		var tx, rx, loss uint64
		var delaySum, rateSum float64
		var delayN int
		for i := epoch.start * 5; i < epoch.end*5; i++ {
			s := samples[i]
			tx += s.sent
			rx += s.received
			loss += s.lost
			delaySum += s.delaySum
			delayN += s.delays
			rateSum += s.rateMbps
		}
		duration := float64(epoch.end-epoch.start)
		goodput := float64(rx) * 8 / duration / 1e6
		lossRate := float64(loss) / math.Max(1, float64(tx))
		meanDelay := delaySum / math.Max(1, float64(delayN)) * 1000
		t.Logf("RFC8867 %s capacity=%.1f Mbps send=%.2f Mbps goodput=%.2f Mbps loss=%.2f%% mean one-way delay=%.1f ms mean budget=%.2f Mbps",
			epoch.name, epoch.capacity, float64(tx)*8/duration/1e6, goodput, lossRate*100, meanDelay, rateSum/float64((epoch.end-epoch.start)*5))
		if goodput > epoch.capacity*1.10 {
			t.Errorf("%s goodput %.2f Mbps exceeds bottleneck %.2f Mbps", epoch.name, goodput, epoch.capacity)
		}
	}
	if sent == 0 {
		t.Fatal("no packets were sent")
	}
	t.Logf("RFC8867 controller: backoffs=%d delay_backoffs=%d timeout_backoffs=%d increases=%d", b.backoffs, b.delayBackoffs, b.timeoutBackoffs, b.increases)
}
