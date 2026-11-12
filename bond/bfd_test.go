package bond

import (
	"testing"
	"time"
)

func TestBFDDetectsOneWayFailureAndHoldsDown(t *testing.T) {
	r := &Receiver{}
	p := &receivePath{}
	t0 := time.Unix(1000, 0)
	frame := func(hears byte) []byte { return []byte{hears, bfdMultiplier, 100, 0, 0, 0, 0, 0} }

	r.bfdReceived(p, frame(1), t0)
	if !p.bfd.up || p.bfdDown() {
		t.Fatal("first healthy exchange must come up without hold-down")
	}
	// Peer stops hearing us: down at once, though frames still arrive.
	r.bfdReceived(p, frame(0), t0.Add(100*time.Millisecond))
	if !p.bfdDown() {
		t.Fatal("peer-reported one-way loss not detected")
	}
	// Peer hears us again: the first failure's hold-down keeps it down for bfdHoldMin.
	for i := 2; i < 4; i++ {
		r.bfdReceived(p, frame(1), t0.Add(time.Duration(i)*100*time.Millisecond))
	}
	if !p.bfdDown() {
		t.Fatal("path returned before hold-down")
	}
	for i := 4; i < 25; i++ {
		r.bfdReceived(p, frame(1), t0.Add(time.Duration(i)*100*time.Millisecond))
	}
	if p.bfdDown() {
		t.Fatal("path did not return after hold-down")
	}
	// Silence beyond the detect time: down.
	r.bfdEvaluate(p, t0.Add(2500*time.Millisecond+400*time.Millisecond))
	if !p.bfdDown() {
		t.Fatal("silence not detected within detect time")
	}
}

func TestBFDStatusReportsFlapsAndCause(t *testing.T) {
	r := &Receiver{}
	p := &receivePath{}
	t0 := time.Unix(1000, 0)
	if p.bfdStatus(t0)["state"] != "off" {
		t.Fatal("unmanaged path should report off")
	}
	r.bfdReceived(p, []byte{1, bfdMultiplier, 100, 0, 0, 0, 0, 0}, t0)
	st := p.bfdStatus(t0)
	if st["state"] != "up" || st["downs"].(uint64) != 0 {
		t.Fatalf("%v", st)
	}
	r.bfdEvaluate(p, t0.Add(time.Second)) // silent for 1 s: beyond 500 ms detect time
	st = p.bfdStatus(t0.Add(time.Second))
	if st["state"] != "down" || st["downs"].(uint64) != 1 || st["last_cause"] != "silence" || st["detect_ms"].(int) != 500 {
		t.Fatalf("%v", st)
	}
}

// Repeated failures within the flap window lengthen the hold-down, up to the cap.
func TestBFDHoldDownGrowsWithRepeatedFlaps(t *testing.T) {
	b := &bfdState{}
	want := []time.Duration{bfdHoldMin, 2 * bfdHoldMin, 4 * bfdHoldMin, 8 * bfdHoldMin, 16 * bfdHoldMin, bfdHoldMax, bfdHoldMax}
	for i, w := range want {
		b.flaps = i + 1
		if got := b.hold(); got != w {
			t.Fatalf("after %d failures hold %v, want %v", i+1, got, w)
		}
	}
	r := &Receiver{}
	p := &receivePath{}
	t0 := time.Unix(1000, 0)
	frame := func(hears byte) []byte { return []byte{hears, bfdMultiplier, 100, 0, 0, 0, 0, 0} }
	r.bfdReceived(p, frame(1), t0)
	for i := 1; i <= 3; i++ {
		now := t0.Add(time.Duration(i) * 5 * time.Second)
		r.bfdReceived(p, frame(0), now)        // fails
		r.bfdReceived(p, frame(1), now.Add(1)) // starts to recover
		r.bfdReceived(p, frame(1), now.Add(10*time.Second))
	}
	if p.bfd.flaps != 3 {
		t.Fatalf("flaps %d, want 3 within the window", p.bfd.flaps)
	}
	p.bfd.lastDown = t0
	r.bfdReceived(p, frame(0), t0.Add(2*bfdFlapWindow))
	if p.bfd.flaps != 1 {
		t.Fatalf("flaps %d after a quiet window, want 1", p.bfd.flaps)
	}
}
