package bond

import (
	"bytes"
	"testing"
	"time"
)

// A flow above the threshold is sent once, on alternating paths; a slow flow stays duplicated.
func TestHeavyFlowIsStripedAndSlowFlowDuplicated(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	s.lossTiered = false // the live always-duplicate mode
	s.SetStripeAbove(1)
	used := map[string]int{}
	writer := func(d Datagram) error {
		if p, err := f.c.Decode(d.Frame); err == nil && p.Header.Kind == Striped {
			used[d.Endpoint.String()]++
		}
		return nil
	}
	payload := bytes.Repeat([]byte{7}, 1000)
	send := func(key string, n int, gap time.Duration, from time.Time) time.Time {
		at := from
		for i := 0; i < n; i++ {
			for _, p := range s.r.paths {
				p.last = at // a live link: probes keep arriving
			}
			for tries := 0; tries < 2000; tries++ {
				for _, p := range s.r.paths {
					p.last = at
				}
				if ok, _, err := s.Bulk(payload, key, at, writer); err != nil {
					t.Fatal(err)
				} else if ok {
					break
				}
				at = at.Add(time.Millisecond)
			}
			at = at.Add(gap)
		}
		return at
	}
	slowEnd := send("slow", 20, 20*time.Millisecond, f.now)
	if s.Stats().BulkDuplicates < 15 {
		t.Fatalf("slow flow not duplicated: %d", s.Stats().BulkDuplicates)
	}
	// ~16 Mbit/s: one 1000-byte packet every 500 microseconds.
	end := send("heavy", 3000, 500*time.Microsecond, slowEnd)
	_ = end
	if s.StripedFlows() != 1 || s.Stats().HeavyStriped == 0 {
		t.Fatalf("heavy flow not striped: %+v", s.Stats())
	}
	if s.Stats().ParitySent == 0 {
		t.Fatalf("striped flow has no parity protection: %+v", s.Stats())
	}
	if len(used) != 2 {
		t.Fatalf("striping used %d path(s)", len(used))
	}
}

// A spike on either path drops every heavy flow back to duplication at once.
func TestStripingStopsWhenAPathSpikes(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	s.SetStripeAbove(1)
	writer := func(Datagram) error { return nil }
	payload := bytes.Repeat([]byte{7}, 1000)
	at := f.now
	send := func(n int) {
		for i := 0; i < n; i++ {
			for _, p := range s.r.paths {
				p.last = at
			}
			for tries := 0; tries < 2000; tries++ {
				for _, p := range s.r.paths {
					p.last = at
				}
				if ok, _, _ := s.Bulk(payload, "heavy", at, writer); ok {
					break
				}
				at = at.Add(time.Millisecond)
			}
			at = at.Add(500 * time.Microsecond)
		}
	}
	send(3000)
	if s.StripedFlows() != 1 {
		t.Fatal("not striped while calm")
	}
	p0 := s.r.paths[pk(a[0])]
	p0.jitter = .05 // 50 ms of jitter
	dups := s.Stats().BulkDuplicates
	send(50)
	if s.StripedFlows() != 0 || s.Stats().BulkDuplicates-dups < 40 {
		t.Fatalf("still striping after a spike: %d dups", s.Stats().BulkDuplicates-dups)
	}
}
