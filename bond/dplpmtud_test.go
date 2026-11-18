package bond

import "testing"

func TestDPLPMTUDDetectsSizeCorrelatedBlackHole(t *testing.T) {
	p, err := NewDPLPMTUD(1400, 548)
	if err != nil {
		t.Fatal(err)
	}
	p.confirmed, p.state = 1200, DPLPMTUDSearching
	for i := 0; i < 3; i++ {
		if p.ObserveDataOutcome(SackObservation{FrameSize: 1000, Delivered: true}, float64(i)) {
			t.Fatal("ordinary smaller-frame success declared a black hole")
		}
	}
	for i := 0; i < 5; i++ {
		p.ObserveDataOutcome(SackObservation{FrameSize: 1150}, float64(i+3)) // Below the old 1200-byte confirmation, above the current path MTU.
	}
	if p.PathMTU() != 1000 || p.State() != DPLPMTUDSearchComplete {
		t.Fatalf("size-correlated losses did not revert to largest delivered size: %+v", p.Stats())
	}
	if probes := p.Due(605, 0.1, func() uint64 { return 9 }); len(probes) != 0 {
		t.Fatalf("black-hole re-probe ignored PMTU raise timer: %+v", probes)
	}
}

func TestDPLPMTUDBaseSearchAndRaiseTimer(t *testing.T) {
	p, err := NewDPLPMTUD(1300, 548)
	if err != nil {
		t.Fatal(err)
	}
	nonce := uint64(0)
	next := func() uint64 { nonce++; return nonce }

	probe := p.Due(0, 0.2, next)
	if len(probe) != 1 || probe[0].Size != 1200 || p.State() != DPLPMTUDBase {
		t.Fatalf("BASE probe = %+v state=%s", probe, p.State())
	}
	if p.Acknowledge(probe[0].Nonce, probe[0].Size-1, 0.1) {
		t.Fatal("accepted acknowledgement with wrong probe size")
	}
	if !p.Acknowledge(probe[0].Nonce, probe[0].Size, 0.1) || p.State() != DPLPMTUDSearching {
		t.Fatalf("base probe did not enter SEARCHING: %+v", p.Stats())
	}
	if got := p.Due(0.2, 0.2, next); len(got) != 0 {
		t.Fatalf("probed before one RTT gap: %+v", got)
	}
	probe = p.Due(1.1, 0.2, next)
	if len(probe) != 1 || probe[0].Size != 1232 {
		t.Fatalf("first SEARCHING probe = %+v, want one 1232-byte probe", probe)
	}
	if p.Acknowledge(probe[0].Nonce, probe[0].Size, 1.0) {
		t.Fatal("accepted MTU acknowledgement predating the probe")
	}
	if !p.Acknowledge(probe[0].Nonce, probe[0].Size, 1.2) || p.PathMTU() != 1232 {
		t.Fatalf("successful probe did not advance PLPMTU: %+v", p.Stats())
	}

	// Acknowledge each selected size until the configured ceiling completes search.
	completedAt := 0.0
	for now := 2.2; p.State() != DPLPMTUDSearchComplete && now < 20; now += 1 {
		probe = p.Due(now, 0.2, next)
		if len(probe) != 1 {
			continue
		}
		if !p.Acknowledge(probe[0].Nonce, probe[0].Size, now+0.1) {
			t.Fatalf("probe acknowledgement rejected: %+v", probe[0])
		}
		if p.State() == DPLPMTUDSearchComplete {
			completedAt = now + 0.1
		}
	}
	if p.State() != DPLPMTUDSearchComplete || p.PathMTU() != 1300 {
		t.Fatalf("ceiling did not enter SEARCH_COMPLETE: %+v", p.Stats())
	}
	if got := p.Due(completedAt+599, 0.2, next); len(got) != 0 {
		t.Fatalf("PMTU_RAISE_TIMER fired before 600 seconds: %+v", got)
	}
	if got := p.Due(completedAt+600, 0.2, next); len(got) != 0 || p.State() != DPLPMTUDSearchComplete {
		t.Fatalf("completed maximum search should remain settled: probes=%+v state=%s", got, p.State())
	}
}

func TestDPLPMTUDSearchFailureSettlesAndRetriesLater(t *testing.T) {
	p, err := NewDPLPMTUD(1400, 548)
	if err != nil {
		t.Fatal(err)
	}
	nonce := uint64(0)
	next := func() uint64 { nonce++; return nonce }
	probe := p.Due(0, 0, next)
	p.Acknowledge(probe[0].Nonce, probe[0].Size, 0.1)
	probe = p.Due(1, 0, next)
	if len(probe) != 1 || probe[0].Size != 1232 {
		t.Fatalf("initial search probe = %+v", probe)
	}
	for _, now := range []float64{17, 34, 51} {
		probe = p.Due(now, 0, next)
		if now < 51 && len(probe) != 1 {
			t.Fatalf("retry %g = %+v", now, probe)
		}
	}
	if p.State() != DPLPMTUDSearchComplete || p.PathMTU() != 1200 {
		t.Fatalf("failed larger probes changed the confirmed size or state: %+v", p.Stats())
	}
	if got := p.Due(650, 0, next); len(got) != 0 {
		t.Fatalf("search restarted before PMTU_RAISE_TIMER: %+v", got)
	}
	probe = p.Due(651, 0, next)
	if len(probe) != 1 || probe[0].Size != 1232 || p.State() != DPLPMTUDSearching {
		t.Fatalf("raise timer did not restart search at next size: probes=%+v state=%s", probe, p.State())
	}
}

func TestDPLPMTUDBaseFailureEntersError(t *testing.T) {
	p, err := NewDPLPMTUD(1200, 548)
	if err != nil {
		t.Fatal(err)
	}
	nonce := uint64(0)
	next := func() uint64 { nonce++; return nonce }
	for _, now := range []float64{0, 16, 32, 48} {
		probes := p.Due(now, 0, next)
		if len(probes) != 1 {
			t.Fatalf("base retry at %g = %+v", now, probes)
		}
		if now == 48 && probes[0].Size != 548 {
			t.Fatalf("BASE failure did not fall back to MIN_PLPMTU: %+v", probes)
		}
	}
	if p.State() != DPLPMTUDError || p.PathMTU() != 548 {
		t.Fatalf("base failure did not retain conservative size and enter ERROR: %+v", p.Stats())
	}
	for _, now := range []float64{64, 80, 96} {
		probes := p.Due(now, 0, next)
		if now < 96 && (len(probes) != 1 || probes[0].Size != 548) {
			t.Fatalf("MIN_PLPMTU retry at %g = %+v", now, probes)
		}
	}
	if p.State() != DPLPMTUDisabled || p.PathMTU() != 0 {
		t.Fatalf("failed MIN_PLPMTU validation did not disable the path: %+v", p.Stats())
	}
	if got := p.Due(700, 0, next); len(got) != 0 {
		t.Fatalf("disabled path continued probing: %+v", got)
	}
}

func TestDPLPMTUDPathChangeRestartsBase(t *testing.T) {
	p, err := NewDPLPMTUD(1400, 548)
	if err != nil {
		t.Fatal(err)
	}
	nonce := uint64(0)
	next := func() uint64 { nonce++; return nonce }
	probe := p.Due(0, 0, next)
	if !p.Acknowledge(probe[0].Nonce, probe[0].Size, 0.1) {
		t.Fatal("base probe ack rejected")
	}
	probe = p.Due(1, 0, next)
	if !p.Acknowledge(probe[0].Nonce, probe[0].Size, 1.1) {
		t.Fatal("search probe ack rejected")
	}
	p.PathChanged()
	if p.State() != DPLPMTUDBase || p.PathMTU() != 548 || p.Stats().Capable {
		t.Fatalf("path change retained stale search state: %+v", p.Stats())
	}
	probe = p.Due(2, 0, next)
	if len(probe) != 1 || probe[0].Size != 1200 {
		t.Fatalf("path change did not immediately probe BASE: %+v", probe)
	}
}
