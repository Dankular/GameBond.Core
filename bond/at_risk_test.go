package bond

import (
	"testing"
	"time"
)

// A path that goes quiet is covered by a copy on the healthy path at once, long
// before the loss estimate or the suspect timer reacts.
func TestQuietPathIsDuplicatedOntoTheHealthyOne(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	quiet, healthy := f.r.paths[pk(a[0])], f.r.paths[pk(a[1])]
	quiet.last = f.now.Add(-400 * time.Millisecond) // silent, but well inside the 3 s eligibility window
	healthy.last = f.now
	if !s.atRisk(quiet, f.now) || s.atRisk(healthy, f.now) {
		t.Fatal("risk classification wrong")
	}
	toHealthy, toQuiet := 0, 0
	writer := func(d Datagram) error {
		if d.Endpoint == healthy.endpoint {
			toHealthy++
		} else {
			toQuiet++
		}
		return nil
	}
	sent := 0
	for i := 0; i < 400 && sent < 20; i++ {
		now := f.now.Add(time.Duration(i) * time.Millisecond)
		healthy.last = now
		if ok, _, err := s.Bulk(tcpPacket("payload"), "flow", now, writer); err != nil {
			t.Fatal(err)
		} else if ok {
			sent++
		}
	}
	if s.Stats().BulkDuplicates == 0 {
		t.Fatalf("nothing duplicated while a path was quiet: %+v", s.Stats())
	}
	if toHealthy < sent {
		t.Fatalf("healthy path carried %d frames for %d packets: every packet needs a copy there", toHealthy, sent)
	}
	_ = toQuiet
}

func TestHealthyPathsAreNotDuplicated(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	writer := func(Datagram) error { return nil }
	for i := 0; i < 20; i++ {
		now := f.now.Add(time.Duration(i) * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now
		}
		s.Bulk(tcpPacket("payload"), "flow", now, writer)
	}
	if s.Stats().BulkDuplicates != 0 {
		t.Fatal("duplicated on healthy paths")
	}
}
