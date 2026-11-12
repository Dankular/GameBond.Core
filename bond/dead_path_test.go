package bond

import (
	"testing"
	"time"
)

func markBFDDown(p *receivePath) { p.bfd.seen, p.bfd.up, p.bfd.failed = true, false, true }

// A line BFD has declared down stops receiving data; its traffic and copies move to the
// line that is up instead of being sent into a dead link for seconds.
func TestDeadPathGetsNoDataUntilEveryPathIsDown(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	var to []string
	write := func(d Datagram) error { to = append(to, d.Endpoint.String()); return nil }
	markBFDDown(f.r.paths[pk(a[0])])
	n, err := s.Urgent(udpOfSize(60), false, f.now, write)
	if err != nil || n != 1 || to[0] != a[1].String() {
		t.Fatalf("sent %d to %v (%v), want only the live path", n, to, err)
	}
	// Everything down: send anyway rather than go silent.
	markBFDDown(f.r.paths[pk(a[1])])
	to = nil
	if n, _ := s.Urgent(udpOfSize(60), false, f.now, write); n != 2 {
		t.Fatalf("all paths down: sent %d, want 2", n)
	}
}

// The merge state stays bounded however many replicated packets arrive.
func TestCopyLedgerStaysBoundedUnderFlood(t *testing.T) {
	l, _ := NewCopyLedger[PathKey](4096)
	keys := []PathKey{{}, {}}
	for i := 0; i < 200000; i++ {
		l.First(uint64(i), keys[0], keys, float64(i)/1000)
	}
	if len(l.pending) > 4096 {
		t.Fatalf("ledger holds %d entries", len(l.pending))
	}
}

func TestExpectedCopyPathsAreCachedBetweenRefreshes(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	_ = s
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	if got := len(f.r.expectedCopyPaths(f.now)); got != 2 {
		t.Fatalf("expected 2 paths, got %d", got)
	}
	markBFDDown(f.r.paths[pk(a[0])])
	if got := len(f.r.expectedCopyPaths(f.now.Add(time.Millisecond))); got != 2 {
		t.Fatalf("cache refreshed too early: %d", got)
	}
	if got := len(f.r.expectedCopyPaths(f.now.Add(expectedRefresh + time.Millisecond))); got != 1 {
		t.Fatalf("cache not refreshed: %d", got)
	}
}
