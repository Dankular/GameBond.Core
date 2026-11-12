package bond

import (
	"container/heap"
	"math/rand"
	"testing"
)

// simulateNoisy drives a budget flat out against a bottleneck of capMbps whose
// return path has jitter (uniform 0..jitter seconds on top of the delay) and random
// loss, like a LEO link. It returns the rate (Mbps) sampled every second and the
// goodput of the last ten seconds.
func simulateNoisy(b *Budget, capMbps, oneWay, jitter, loss float64, seconds int) (rates []float64, goodputMbps float64) {
	const size = 1400
	rng := rand.New(rand.NewSource(7))
	capBytes := capMbps * 125000
	var linkFree float64
	var seq, delivered, lateBytes uint64
	var acks simAcks
	for ms := 0; ms < seconds*1000; ms++ {
		now := float64(ms) / 1000
		for len(acks) > 0 && acks[0].at <= now {
			a := heap.Pop(&acks).(simAck)
			b.Acknowledge(a.seq, a.delivered, a.at, 0)
		}
		b.Expire(now)
		for n := 0; n < 2000; n++ {
			ready, err := b.ReadyAt(size, now)
			if err != nil || ready > now+1e-6 {
				break
			}
			seq++
			b.Sent(seq, size, now)
			start := max(now, linkFree)
			if start-now > .1 {
				continue
			}
			linkFree = start + size/capBytes
			if rng.Float64() < loss {
				continue
			}
			delivered += size
			if ms >= (seconds-10)*1000 {
				lateBytes += size
			}
			heap.Push(&acks, simAck{linkFree + 2*oneWay + rng.Float64()*jitter, seq, delivered})
		}
		if ms%1000 == 999 {
			rates = append(rates, b.RateMbps())
		}
	}
	return rates, float64(lateBytes) / 10 / 125000
}

// A path with Starlink-like jitter and a little random loss must still ramp to the
// link, not sit near its starting rate.
func TestBudgetRampsOnAJitteryLossyLink(t *testing.T) {
	for _, c := range []struct{ capMbps, jitter, loss float64 }{{200, .03, 0}, {200, .03, .02}, {200, .08, .02}} {
		b, _ := NewBudget(10, 300)
		b.UseLiveLimits()
		b.delayControl, b.delayAssertive = true, true
		rates, goodput := simulateNoisy(b, c.capMbps, .025, c.jitter, c.loss, 40)
		t.Logf("cap %.0f jitter %.0f ms loss %.0f%%: rate %.0f goodput %.1f (backoffs %d delay %d increases %d)",
			c.capMbps, c.jitter*1000, c.loss*100, rates[len(rates)-1], goodput, b.backoffs, b.delayBackoffs, b.increases)
		if goodput < .5*c.capMbps {
			t.Errorf("cap %.0f jitter %.0f ms loss %.0f%%: goodput %.1f under half the link", c.capMbps, c.jitter*1000, c.loss*100, goodput)
		}
	}
}
