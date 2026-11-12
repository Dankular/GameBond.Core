package bond

import "testing"

// A saturated path whose round trip balloons with no loss (a bloated buffer):
// without delay control the rate never moves; with it the rate backs off.
func runBloat(t *testing.T, control bool) *Budget {
	t.Helper()
	b, err := NewBudget(10, 10)
	if err != nil {
		t.Fatal(err)
	}
	b.delayControl = control
	type inflight struct {
		seq   uint64
		ackAt float64
		size  int
	}
	var queue []inflight
	var seq, delivered uint64
	const size = 1400
	now := 0.0
	for now < 8 {
		gap := float64(size+28) / b.rate // send exactly at the budgeted rate
		now += gap
		seq++
		if ok, _ := b.Sent(seq, size, now); ok {
			rtt := .020
			if now > 2 {
				rtt = .020 + .080 // standing queue appears at 2 s, nothing is lost
			}
			queue = append(queue, inflight{seq, now + rtt, size})
		}
		for len(queue) > 0 && queue[0].ackAt <= now {
			p := queue[0]
			queue = queue[1:]
			delivered += uint64(p.size)
			b.Acknowledge(p.seq, delivered, p.ackAt, 0)
		}
	}
	return b
}

func TestDelayControlDrainsStandingQueue(t *testing.T) {
	without := runBloat(t, false)
	with := runBloat(t, true)
	if without.rate < 1250000*.95 {
		t.Fatalf("control run lost its rate (%.0f B/s); the signal must come from delay control", without.rate)
	}
	if with.delayBackoffs == 0 {
		t.Fatalf("no delay backoff on a standing 80 ms queue: stats %v", with.Stats())
	}
	if with.rate > without.rate*.8 {
		t.Fatalf("rate %.0f not meaningfully below the uncontrolled %.0f", with.rate, without.rate)
	}
	if with.rate < with.minimum {
		t.Fatalf("rate fell below the floor: %.0f < %.0f", with.rate, with.minimum)
	}
}

func TestDelayControlIgnoresSparseTraffic(t *testing.T) {
	b, _ := NewBudget(10, 10)
	b.delayControl = true
	var delivered uint64
	now := 0.0
	for seq := uint64(1); seq <= 400; seq++ { // 100 kB/s on a 1.25 MB/s path, with 100 ms of delay
		now += .014
		b.Sent(seq, 1400, now)
		delivered += 1400
		b.Acknowledge(seq, delivered, now+.1, 0)
	}
	if b.delayBackoffs != 0 {
		t.Fatalf("sparse (app-limited) traffic was throttled: %d backoffs", b.delayBackoffs)
	}
}

// After a standing queue clears, an assertive path must get its rate back in
// seconds, not minutes; otherwise every backoff permanently starves the link.
func TestAssertiveDelayControlRecovers(t *testing.T) {
	b, err := NewBudget(10, 100)
	if err != nil {
		t.Fatal(err)
	}
	b.delayControl, b.delayAssertive = true, true
	b.rate, b.startup = 80*125000, false
	type inflight struct {
		seq   uint64
		ackAt float64
		size  int
	}
	var queue []inflight
	var seq, delivered uint64
	const size = 1400
	now, low := 0.0, b.rate
	for now < 20 {
		now += float64(size+28) / b.rate
		seq++
		if ok, _ := b.Sent(seq, size, now); ok {
			rtt := .030
			if now > 2 && now < 5 {
				rtt = .030 + .060 // a 60 ms standing queue for three seconds
			}
			queue = append(queue, inflight{seq, now + rtt, size})
		}
		for len(queue) > 0 && queue[0].ackAt <= now {
			p := queue[0]
			queue = queue[1:]
			delivered += uint64(p.size)
			b.Acknowledge(p.seq, delivered, p.ackAt, 0)
		}
		if now > 5 && b.rate < low {
			low = b.rate
		}
	}
	if b.delayBackoffs == 0 {
		t.Fatal("no backoff during the queue")
	}
	if b.rate < 60*125000 {
		t.Fatalf("rate only recovered to %.1f Mbps within 15 s of the queue clearing", b.rate/125000)
	}
}
