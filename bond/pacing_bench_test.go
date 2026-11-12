package bond

import (
	"sort"
	"strings"
	"testing"
	"time"
)

// pumpProfile feeds a standing backlog through the queue at a path rate of rateMbps and
// steps simulated time by step, recording how many datagrams each Pump releases. The
// largest release is the burst the wire sees; the wakeup interval sets how big it gets.
func pumpProfile(tb testing.TB, rateMbps float64, step time.Duration, steps int) (perPump []int, bytesPerSecMbps float64) {
	tb.Helper()
	f, s, a := senderFixture(&testing.T{}, 2)
	_ = a
	for _, p := range s.r.paths {
		p.budget.UseLiveLimits()
		p.budget.rate = rateMbps * 125000
		p.budget.startup = false
	}
	q, err := NewTransmitQueue(s, 4096, 8<<20)
	if err != nil {
		tb.Fatal(err)
	}
	now := f.now
	var sentBytes int
	for i := 0; i < steps; i++ {
		for q.Stats().QueuedPackets < 2000 { // standing backlog
			payload := tcpPacket(strings.Repeat("x", 1200))
			if !q.Enqueue(QueuedPacket{Payload: payload, Flow: "bulk", Expires: now.Add(time.Second)}) {
				break
			}
		}
		for _, p := range s.r.paths {
			p.last = now
		}
		n := 0
		q.Pump(now, func(d Datagram) error { n++; sentBytes += len(d.Frame); return nil })
		perPump = append(perPump, n)
		now = now.Add(step)
	}
	return perPump, float64(sentBytes) * 8 / (float64(steps) * step.Seconds()) / 1e6
}

func TestPacingBurstSizeByWakeupInterval(t *testing.T) {
	for _, step := range []time.Duration{200 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 15600 * time.Microsecond} {
		per, mbps := pumpProfile(t, 100, step, 2000)
		sorted := append([]int(nil), per...)
		sort.Ints(sorted)
		p99, max := sorted[len(sorted)*99/100], sorted[len(sorted)-1]
		t.Logf("wakeup every %-7v: achieved %6.1f Mbps (2 paths x 100), packets/pump p99 %3d max %3d (= %.1f KB, %.2f ms at 100 Mbps)",
			step, mbps, p99, max, float64(max)*1200/1000, float64(max)*1200*8/100e6*1000)
	}
}

func BenchmarkTransmitPump(b *testing.B) {
	f, s, _ := senderFixture(&testing.T{}, 2)
	for _, p := range s.r.paths {
		p.budget.UseLiveLimits()
		p.budget.rate = 300 * 125000
		p.budget.startup = false
	}
	q, _ := NewTransmitQueue(s, 4096, 8<<20)
	now := f.now
	payload := tcpPacket(strings.Repeat("x", 1200))
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range s.r.paths {
			p.last = now
		}
		q.Enqueue(QueuedPacket{Payload: payload, Flow: "bulk", Expires: now.Add(time.Second)})
		q.Pump(now, func(Datagram) error { return nil })
		now = now.Add(40 * time.Microsecond)
	}
}
