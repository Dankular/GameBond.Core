package bond

import (
	"container/heap"
	"testing"
)

// simAck is an acknowledgement in flight back to the sender.
type simAck struct {
	at        float64
	seq       uint64
	delivered uint64
}
type simAcks []simAck

func (h simAcks) Len() int           { return len(h) }
func (h simAcks) Less(i, j int) bool { return h[i].at < h[j].at }
func (h simAcks) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *simAcks) Push(x any)        { *h = append(*h, x.(simAck)) }
func (h *simAcks) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// simulateLink drives one budget flat out against a bottleneck of capMbps with a
// 100 ms drop-tail queue and oneWay seconds of delay each direction. It returns
// the controller's rate (Mbps) sampled every second and the goodput of the last
// ten seconds.
func simulateLink(t *testing.T, b *Budget, capMbps, oneWay float64, seconds int) (rates []float64, goodputMbps, dropPct, queueMS float64) {
	t.Helper()
	const size = 1400
	capBytes := capMbps * 125000
	var linkFree float64
	var seq, delivered, lastDelivered uint64
	var acks simAcks
	var lateBytes, sentLate, droppedLate uint64
	var queueSum float64
	for ms := 0; ms < seconds*1000; ms++ {
		now := float64(ms) / 1000
		for len(acks) > 0 && acks[0].at <= now {
			a := heap.Pop(&acks).(simAck)
			b.Acknowledge(a.seq, a.delivered, a.at, 0)
		}
		b.Expire(now)
		for n := 0; n < 400; n++ {
			ready, err := b.ReadyAt(size, now)
			if err != nil || ready > now+1e-6 {
				break
			}
			seq++
			b.Sent(seq, size, now)
			start := max(now, linkFree)
			late := ms >= (seconds-10)*1000
			if late {
				sentLate++
			}
			if start-now > .1 {
				if late {
					droppedLate++
				}
				continue // tail drop: no acknowledgement will come
			}
			if late {
				queueSum += start - now
			}
			linkFree = start + size/capBytes
			delivered += size
			if ms >= (seconds-10)*1000 {
				lateBytes += size
			}
			heap.Push(&acks, simAck{linkFree + 2*oneWay, seq, delivered})
		}
		if ms%1000 == 999 {
			rates = append(rates, b.RateMbps())
		}
		lastDelivered = delivered
	}
	_ = lastDelivered
	return rates, float64(lateBytes) / 10 / 125000, 100 * float64(droppedLate) / float64(max(1, sentLate)), 1000 * queueSum / float64(max(1, sentLate-droppedLate))
}

func TestBudgetStalledDetectionIsPassiveAndFast(t *testing.T) {
	b, _ := NewBudget(10, 100)
	b.Sent(1, 1000, 0)
	b.Acknowledge(1, 1000, 0.05, 0)
	b.Sent(2, 1000, 0.06)
	if b.AckStalled(0.08, 0.06) {
		t.Fatal("stalled after only 20 ms of waiting")
	}
	if !b.AckStalled(0.14, 0.06) {
		t.Fatal("not stalled after 80 ms with nothing acknowledged")
	}
	b.Acknowledge(2, 2000, 0.15, 0)
	if b.AckStalled(0.16, 0.06) {
		t.Fatal("still stalled after an acknowledgement")
	}
}

func TestBudgetConvergesOnAThrottledLink(t *testing.T) {
	for _, assertive := range []bool{false, true} {
		for _, c := range []float64{20, 60} {
			b, err := NewBudget(10, 300)
			if err != nil {
				t.Fatal(err)
			}
			b.delayControl, b.delayAssertive = true, assertive
			rates, goodput, drops, queue := simulateLink(t, b, c, .025, 40)
			t.Logf("assertive=%v cap %.0f Mbps: rate %.0f goodput %.1f drops %.1f%% queue %.0f ms", assertive, c, rates[len(rates)-1], goodput, drops, queue)
			if last := rates[len(rates)-1]; last > 1.6*c || last < .5*c {
				t.Errorf("assertive=%v cap %.0f Mbps: controller rate %.1f did not settle near the link", assertive, c, last)
			}
			if goodput < .7*c {
				t.Errorf("assertive=%v cap %.0f Mbps: goodput %.1f under 70%% of the link", assertive, c, goodput)
			}
			if drops > 5 {
				t.Errorf("assertive=%v cap %.0f Mbps: %.1f%% of packets dropped at the bottleneck", assertive, c, drops)
			}
		}
	}
}

// A redundancy copy is tracked for its acknowledgement but never fills the send
// window: bulk must not queue behind the copies of itself.
func TestCopiesAreAcknowledgedButDoNotFillTheWindow(t *testing.T) {
	b, _ := NewBudget(10, 100)
	window := b.Window()
	var seq uint64
	for sent := 0; sent <= 3*window; sent += 1400 {
		seq++
		b.SentCopy(seq, 1400, 0)
	}
	// Copies still cost wire time (the pacing clock), but bulk is never held for the
	// timeout waiting for the window to drain.
	if ready, _ := b.ReadyAt(1400, 0); ready >= b.Timeout()-1e-9 || ready > .1+1e-9 {
		t.Fatalf("bulk held behind its own copies until %.3f", ready)
	}
	if b.inflight != 0 {
		t.Fatalf("copies counted in flight: %.0f", b.inflight)
	}
	if !b.Acknowledge(seq, b.sentBytes, 0.05, 0) {
		t.Fatal("acknowledgement of a copy was refused")
	}
	if b.inflight != 0 {
		t.Fatalf("inflight went negative or non-zero after retiring copies: %.0f", b.inflight)
	}
}

// A live path's window covers rate x RTT at the 300 Mbps ceiling.
func TestLiveBudgetWindowCoversTheRateCeiling(t *testing.T) {
	b, _ := NewBudget(10, 300)
	b.UseLiveLimits()
	b.rate = 300 * 125000
	b.rawSRTT = .06
	if w := b.Window(); w < 4_000_000 {
		t.Fatalf("window %d cannot carry 300 Mbps at 60 ms", w)
	}
	ref, _ := NewBudget(10, 300)
	ref.rate, ref.rawSRTT = 300*125000, .06
	if ref.Window() != 1<<20 {
		t.Fatalf("reference window changed: %d", ref.Window())
	}
}
