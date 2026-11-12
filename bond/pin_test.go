package bond

import "testing"

func TestFlowPinningSticksAndFastReroutes(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.SetFlowPinning(true)
	s.EnableFailover(true)
	hits := map[string]int{}
	i := 0
	send := func(n int) {
		for k := 0; k < n; k++ {
			i++
			_, _, err := s.Bulk(steerPacket(), "pinned", f.now.Add(timeStep(i)), func(d Datagram) error { hits[d.Endpoint.String()]++; return nil })
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	send(30)
	if (hits[a[0].String()] == 0) == (hits[a[1].String()] == 0) {
		t.Fatalf("flow not pinned to exactly one path: %v", hits)
	}
	if s.Stats().FlowsPinned != 1 {
		t.Fatalf("pinned %d", s.Stats().FlowsPinned)
	}
	var pinned, other string
	if hits[a[0].String()] > 0 {
		pinned, other = a[0].String(), a[1].String()
	} else {
		pinned, other = a[1].String(), a[0].String()
	}
	// BFD marks the pinned path Down: the next packet goes to the backup.
	for _, p := range f.r.paths {
		if p.endpoint.String() == pinned {
			p.bfd = bfdState{seen: true, failed: true}
		}
	}
	before := hits[other]
	send(10)
	if hits[other] <= before || s.Stats().FastReroutes != 1 {
		t.Fatalf("no fast reroute: %v %+v", hits, s.Stats())
	}
}
