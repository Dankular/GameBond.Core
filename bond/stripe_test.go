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
			for tries := 0; tries < 2000; tries++ {
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
