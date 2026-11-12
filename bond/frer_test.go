package bond

import (
	"testing"
	"time"
)

// A UDP packet behind a hole is delivered at once (PRP/HSR first-arrival); the missing one,
// if it turns up later, is still delivered and nothing is delivered twice.
func TestUDPFirstArrivalIsNotHeldBehindAHole(t *testing.T) {
	r := reorderForTest(t, DefaultReorderConfig())
	now := time.Now()
	r.Push(1, 0, udpPacket(1, 2, 0), now)
	if got := r.Push(1, 2, udpPacket(1, 2, 2), now); len(got) != 1 {
		t.Fatalf("UDP held behind a hole: %d delivered", len(got))
	}
	if got := r.Push(1, 1, udpPacket(1, 2, 1), now); len(got) != 1 {
		t.Fatalf("late original not delivered: %d", len(got))
	}
	if got := r.Push(1, 2, udpPacket(1, 2, 2), now); len(got) != 0 {
		t.Fatal("duplicate delivered")
	}
}

func TestTCPStillWaitsForTheHole(t *testing.T) {
	r := reorderForTest(t, DefaultReorderConfig())
	now := time.Now()
	r.Push(1, 0, tcpPacket("a"), now)
	if got := r.Push(1, 2, tcpPacket("c"), now); len(got) != 0 {
		t.Fatal("TCP delivered ahead of a hole")
	}
}

// A second copy that arrives far later than the old 8192-packet window is still recognised
// as a duplicate rather than dropped as too old.
func TestEliminationWindowOutlastsOldWidth(t *testing.T) {
	var w ReplayWindow
	w.Accept(1)
	for s := uint64(2); s < 60000; s++ {
		w.Accept(s)
	}
	if v := w.Check(5); v != ReplayDuplicate {
		t.Fatalf("copy 60k sequences later: %v", v)
	}
	if v := w.Check(60000 - 1 - 20000); v != ReplayDuplicate {
		t.Fatalf("got %v", v)
	}
}

func TestPathAccountingCountsWinnersAndSkew(t *testing.T) {
	r := &Receiver{}
	a, b := &receivePath{}, &receivePath{}
	t0 := time.Now()
	for n := uint64(0); n < 300; n++ {
		r.accountArrival(a, 1, n, false, t0)
		r.accountArrival(b, 1, n, true, t0.Add(12*time.Millisecond))
	}
	if a.firstWins != 300 || b.lateCopies != 300 || b.firstWins != 0 {
		t.Fatalf("a=%+v b=%+v", a.firstWins, b.lateCopies)
	}
	if b.skewMS < 11 || b.skewMS > 13 || r.skewSamples < 200 || r.skewPeakMS < 11.9 {
		t.Fatalf("skew %.2f samples %d peak %.2f", b.skewMS, r.skewSamples, r.skewPeakMS)
	}
}

func TestSupervisionAnnouncesPathStatesAndAges(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	for i := 0; i < 24; i++ { // 6 s: at least two announcements
		p.step()
	}
	for k, path := range p.server.paths {
		if path.peerSupAt.IsZero() || len(path.peerSup) != 2 {
			t.Fatalf("server heard no complete supervision on %v: %+v", k, path.peerSup)
		}
		for _, e := range path.peerSup {
			if !e.Ready() || !e.Healthy() {
				t.Fatalf("peer reports a live path down: %+v", e)
			}
		}
		if state := path.supervisionState(p.now); state["aged"].(bool) {
			t.Fatalf("fresh supervision reported aged: %v", state)
		}
		if state := path.supervisionState(p.now.Add(supervisionAging + time.Second)); !state["aged"].(bool) {
			t.Fatalf("silent peer not aged out at 2.5x: %v", state)
		}
	}
	if validSupervision([]byte{1, 2, 0}) || !validSupervision(p.client.supervisionPayload(p.now)) {
		t.Fatal("payload validation")
	}
}
