package bond

import (
	"container/heap"
	"math"
	"testing"
	"time"
)

type sharedBottleneckFlow struct {
	budget             *Budget
	acks               simAcks
	sequence           uint64
	delivered, sampled uint64
	oneWay             float64
}

// simulateSharedUDPFlows puts independent GameBond path budgets on one FIFO
// bottleneck. It checks aggregate UDP fairness without relying on host timing.
func simulateSharedUDPFlows(t *testing.T, flowCount int, capacityMbps float64, seconds int, mixedRTT, assertiveDelay bool) []float64 {
	oneWayDelays := make([]time.Duration, flowCount)
	for i := range oneWayDelays {
		oneWayDelays[i] = 25 * time.Millisecond
		if mixedRTT {
			oneWayDelays[i] = 10*time.Millisecond + time.Duration(i%2)*40*time.Millisecond
		}
	}
	return simulateSharedUDPFlowsWithDelays(t, oneWayDelays, capacityMbps, seconds, assertiveDelay)
}

func simulateSharedUDPFlowsWithDelays(t *testing.T, oneWayDelays []time.Duration, capacityMbps float64, seconds int, assertiveDelay bool) []float64 {
	t.Helper()
	const packetSize = 1200
	const queueLimit = .100
	flowCount := len(oneWayDelays)
	flows := make([]sharedBottleneckFlow, flowCount)
	for i := range flows {
		b, err := NewBudget(10, 100)
		if err != nil {
			t.Fatal(err)
		}
		b.UseLiveLimits()
		if assertiveDelay {
			b.delayControl, b.delayAssertive = true, true
		}
		flows[i].budget = b
		flows[i].oneWay = oneWayDelays[i].Seconds()
	}
	capacityBytes := capacityMbps * 125000
	var linkFree float64
	const rampSeconds = 10
	for ms := 0; ms < seconds*1000; ms++ {
		now := float64(ms) / 1000
		for i := range flows {
			f := &flows[i]
			for len(f.acks) > 0 && f.acks[0].at <= now {
				a := heap.Pop(&f.acks).(simAck)
				f.budget.Acknowledge(a.seq, a.delivered, a.at, 0)
			}
			f.budget.Expire(now)
		}
		// Rotate the first sender to avoid granting one flow a permanent enqueue
		// advantage when the simulated bottleneck is nearly full.
		for offset := 0; offset < flowCount; offset++ {
			i := (ms + offset) % flowCount
			f := &flows[i]
			for n := 0; n < 100; n++ {
				ready, err := f.budget.ReadyAt(packetSize, now)
				if err != nil || ready > now+1e-6 {
					break
				}
				f.sequence++
				f.budget.Sent(f.sequence, packetSize, now)
				start := max(now, linkFree)
				if start-now > queueLimit {
					continue // drop-tail loss: the sender learns by timeout/feedback
				}
				linkFree = start + float64(packetSize+28)/capacityBytes
				f.delivered += packetSize
				if ms >= rampSeconds*1000 {
					f.sampled += packetSize
				}
				heap.Push(&f.acks, simAck{at: linkFree + 2*f.oneWay, seq: f.sequence, delivered: f.delivered})
			}
		}
	}
	goodput := make([]float64, flowCount)
	for i := range flows {
		goodput[i] = float64(flows[i].sampled) * 8 / float64(seconds-rampSeconds) / 1e6
		t.Logf("flow %d RTT=%dms goodput=%.2fMbps rate=%.2fMbps backoffs=%d delay_backoffs=%d loss=%.3f", i,
			int(2*flows[i].oneWay*1000), goodput[i], flows[i].budget.RateMbps(), flows[i].budget.backoffs,
			flows[i].budget.delayBackoffs, flows[i].budget.lossRatio)
	}
	return goodput
}

func TestRFC8867RTTFairnessAcrossFivePaths(t *testing.T) {
	// RFC 8867 Section 5.5 tests five media flows with distinct propagation
	// delays. These one-way delays produce 20, 40, 100, 200, and 300 ms RTTs.
	delays := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 150 * time.Millisecond}
	goodput := simulateSharedUDPFlowsWithDelays(t, delays, 40, 50, true)
	var total, sumSquares, minRate, maxRate float64
	for i, rate := range goodput {
		total += rate
		sumSquares += rate * rate
		if i == 0 || rate < minRate {
			minRate = rate
		}
		if rate > maxRate {
			maxRate = rate
		}
	}
	jain := total * total / (float64(len(goodput)) * sumSquares)
	if total < 30 || total > 40.8 {
		t.Fatalf("RFC 8867 RTT-fairness aggregate %.1f Mbps outside expected capacity range: rates=%v", total, goodput)
	}
	if jain < .70 {
		t.Fatalf("RFC 8867 RTT fairness collapsed (Jain %.3f): rates=%v", jain, goodput)
	}
	t.Logf("RFC 8867 RTT fairness (20/40/100/200/300 ms): rates=%v aggregate=%.1f Mbps Jain=%.3f max/min=%.2f",
		goodput, total, jain, maxRate/math.Max(minRate, 1e-9))
}

func TestRFC8869SixteenFlowsShareWiFiAirtime(t *testing.T) {
	// RFC 8869 Section 3.2 models sixteen media flows sharing a Wi-Fi bottleneck,
	// with roughly 20 Mbps application throughput at the stated 802.11n PHY rate.
	// This deterministic shared-airtime abstraction isolates the production Budget;
	// it is not a substitute for the RFC's recommended Wi-Fi simulator/testbed.
	delays := make([]time.Duration, 16)
	for i := range delays {
		delays[i] = 25 * time.Millisecond
	}
	goodput := simulateSharedUDPFlowsWithDelays(t, delays, 20, 50, true)
	var total, sumSquares, minRate, maxRate float64
	for i, rate := range goodput {
		total += rate
		sumSquares += rate * rate
		if i == 0 || rate < minRate {
			minRate = rate
		}
		if rate > maxRate {
			maxRate = rate
		}
	}
	jain := total * total / (float64(len(goodput)) * sumSquares)
	if total > 20.8 {
		t.Fatalf("RFC 8869 shared-airtime goodput %.2f Mbps exceeded 20 Mbps bottleneck", total)
	}
	if total < 14 {
		t.Fatalf("RFC 8869 shared-airtime underused bottleneck: %.2f Mbps rates=%v", total, goodput)
	}
	if jain < .70 {
		t.Fatalf("RFC 8869 16-flow sharing unfair (Jain %.3f): rates=%v", jain, goodput)
	}
	t.Logf("RFC 8869-inspired 16-flow wireless abstraction: aggregate=%.2f Mbps Jain=%.3f max/min=%.2f", total, jain, maxRate/math.Max(minRate, 1e-9))
}

func TestRFC8869MediaAdaptsToOnOffCBRCrossTraffic(t *testing.T) {
	// RFC 8869 Section 3.2.3 uses competing on/off CBR traffic to test whether
	// real-time flows adapt when shared Wi-Fi capacity changes. This models one
	// 8 Mbps cross-traffic source on a 20 Mbps FIFO; it is not 802.11 simulation.
	const (
		mediaFlows = 4
		capacity   = 20.0
		packetSize = 1200
		oneWay     = 25 * time.Millisecond
		queueLimit = .300
	)
	flows := make([]sharedBottleneckFlow, mediaFlows)
	for i := range flows {
		budget, err := NewBudget(10, 100)
		if err != nil {
			t.Fatal(err)
		}
		budget.UseLiveLimits()
		budget.delayControl, budget.delayAssertive = true, true
		flows[i].budget = budget
		flows[i].oneWay = oneWay.Seconds()
	}
	capacityBytes := capacity * 125000
	var linkFree, crossTrafficBytes float64
	var delivered [3]uint64 // 10-20s, 25-35s, and 45-55s windows
	var offered [3]uint64
	var queueDelaySum [3]float64
	var queueDelayCount [3]uint64
	var acks simAcks
	var sequence uint64
	ackFlow := make(map[uint64]int)
	sentAt := make(map[uint64]float64)
	windowAt := func(at float64) int {
		switch {
		case at >= 10 && at < 20:
			return 0
		case at >= 25 && at < 35:
			return 1
		case at >= 45 && at < 55:
			return 2
		default:
			return -1
		}
	}
	for ms := 0; ms < 60000; ms++ {
		now := float64(ms) / 1000
		for len(acks) > 0 && acks[0].at <= now {
			a := heap.Pop(&acks).(simAck)
			flowIndex := ackFlow[a.seq]
			delete(ackFlow, a.seq)
			flows[flowIndex].budget.Acknowledge(a.seq, a.delivered, a.at, 0)
			if window := windowAt(sentAt[a.seq]); window >= 0 {
				delivered[window] += packetSize
				queueDelaySum[window] += a.at - sentAt[a.seq] - 2*flows[flowIndex].oneWay
				queueDelayCount[window]++
			}
		}
		for i := range flows {
			flows[i].budget.Expire(now)
		}
		for offset := 0; offset < mediaFlows; offset++ {
			i := (ms + offset) % mediaFlows
			f := &flows[i]
			for n := 0; n < 100; n++ {
				ready, err := f.budget.ReadyAt(packetSize, now)
				if err != nil || ready > now+1e-6 {
					break
				}
				sequence++
				f.sequence = sequence
				if _, err := f.budget.Sent(sequence, packetSize, now); err != nil {
					t.Fatal(err)
				}
				if window := windowAt(now); window >= 0 {
					offered[window] += packetSize
				}
				sentAt[sequence] = now
				start := max(now, linkFree)
				if start-now > queueLimit {
					continue
				}
				linkFree = start + float64(packetSize+28)/capacityBytes
				f.delivered += packetSize
				ackFlow[sequence] = i
				heap.Push(&acks, simAck{at: linkFree + 2*f.oneWay, seq: sequence, delivered: f.delivered})
			}
		}
		if ms >= 20000 && ms < 40000 {
			crossTrafficBytes += 8 * 125.0 // 8 Mbps produces 1,000 bytes per millisecond
			for crossTrafficBytes >= packetSize {
				crossTrafficBytes -= packetSize
				start := max(now, linkFree)
				if start-now <= queueLimit {
					linkFree = start + float64(packetSize+28)/capacityBytes
				}
			}
		}
	}
	rate := func(bytes uint64) float64 { return float64(bytes) * 8 / 10 / 1e6 }
	before, during, after := rate(delivered[0]), rate(delivered[1]), rate(delivered[2])
	lossRate := func(i int) float64 { return 1 - float64(delivered[i])/math.Max(1, float64(offered[i])) }
	meanQueueDelayMS := func(i int) float64 { return queueDelaySum[i] * 1000 / math.Max(1, float64(queueDelayCount[i])) }
	t.Logf("RFC 8869-inspired on/off CBR: media goodput before=%.2f during=%.2f after=%.2f Mbps; loss=%.2f/%.2f/%.2f%%; mean queue delay=%.1f/%.1f/%.1f ms (8 Mbps CBR active at 20-40s)",
		before, during, after, 100*lossRate(0), 100*lossRate(1), 100*lossRate(2), meanQueueDelayMS(0), meanQueueDelayMS(1), meanQueueDelayMS(2))
	if before < 14 || before > 20.8 {
		t.Fatalf("unexpected pre-cross-traffic media goodput %.2f Mbps", before)
	}
	if during >= before*.90 {
		t.Fatalf("media flows did not yield capacity to arriving cross traffic: before=%.2f during=%.2f", before, during)
	}
	if after <= during*1.10 {
		t.Fatalf("media flows did not recover after cross traffic departed: during=%.2f after=%.2f", during, after)
	}
}

func TestIndependentUDPFlowsShareBottleneckFairly(t *testing.T) {
	const capacity = 40.
	for _, count := range []int{2, 4, 8} {
		goodput := simulateSharedUDPFlows(t, count, capacity, 50, false, true)
		var total, sumSquares float64
		for _, rate := range goodput {
			total += rate
			sumSquares += rate * rate
		}
		jain := total * total / (float64(len(goodput)) * sumSquares)
		if total < capacity*.8 {
			t.Errorf("%d flows aggregate goodput %.1f Mbit/s underused %.0f Mbit/s bottleneck: flows=%v", count, total, capacity, goodput)
		}
		if jain < .90 {
			t.Errorf("%d independent UDP flows were unfair (Jain %.3f): %v", count, jain, goodput)
		}
		t.Logf("%d shared UDP flows: rates=%v aggregate=%.1f Mbit/s Jain=%.3f", count, goodput, total, jain)
	}
}

func TestMixedRTTUDPFlowsStayWithinSharedCapacity(t *testing.T) {
	const capacity = 40.
	goodput := simulateSharedUDPFlows(t, 4, capacity, 50, true, true)
	var total, sumSquares float64
	for _, rate := range goodput {
		total += rate
		sumSquares += rate * rate
	}
	jain := total * total / (float64(len(goodput)) * sumSquares)
	if total > capacity*1.02 {
		t.Fatalf("mixed-RTT aggregate goodput %.1f exceeded %.0f Mbit/s bottleneck", total, capacity)
	}
	if total < capacity*.75 {
		t.Fatalf("mixed-RTT flows underused bottleneck: aggregate=%.1f rates=%v", total, goodput)
	}
	if jain < .70 {
		t.Fatalf("assertive delay control regressed mixed-RTT fairness: Jain=%.3f rates=%v", jain, goodput)
	}
	t.Logf("mixed RTT 20/100 ms: rates=%v aggregate=%.1f Mbit/s Jain=%.3f", goodput, total, jain)
}

func TestMixedRTTUDPFlowsWithDefaultController(t *testing.T) {
	goodput := simulateSharedUDPFlows(t, 4, 40, 50, true, false)
	var total, sumSquares float64
	for _, rate := range goodput {
		total += rate
		sumSquares += rate * rate
	}
	jain := total * total / (float64(len(goodput)) * sumSquares)
	if total < 30 || total > 40.8 || jain < .9 {
		t.Fatalf("default mixed-RTT sharing regressed: total=%.1f Jain=%.3f rates=%v", total, jain, goodput)
	}
	t.Logf("default mixed RTT 20/100 ms: rates=%v aggregate=%.1f Mbit/s Jain=%.3f", goodput, total, jain)
}
