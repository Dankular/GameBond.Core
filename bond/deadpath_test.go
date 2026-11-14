package bond

import "testing"

// A packet is sent on two links, the copy on link A is lost, and link B (carrying
// the other copy) dies. B will never report its frame, so the packet must be
// resent when B is declared suspect instead of waiting for B forever.
func TestPacketIsResentWhenItsOnlySurvivingCopyIsOnADeadLink(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	pa, pb := f.r.paths[pk(a[0])], f.r.paths[pk(a[1])]
	key := MissingPacket{Flow: 5, Number: 1}
	s.cacheRepair(key, tcpPacket("x"), f.now, pa)
	s.repairs[key].carry(pb)
	s.repairs[key].sent = 2
	// The frame on B is pending and unreported.
	if _, err := pb.budget.Sent(900, 1200, 0); err != nil {
		t.Fatal(err)
	}
	pb.budget.Tag(900, key)
	// The copy on A was reported lost by the selective acknowledgement.
	s.sackLoss(key, f.now)
	if st := s.Stats(); st.SackHeld != 1 || st.SackResent != 0 {
		t.Fatalf("first copy lost, second unaccounted: %+v", st)
	}
	// B dies: its frames are declared lost, and now every copy is gone.
	for _, k := range pb.budget.LostPending() {
		s.stats.DeadPathLost++
		s.sackLoss(k, f.now)
	}
	if st := s.Stats(); st.SackResent != 1 || st.DeadPathLost != 1 || len(s.repairRequests) != 1 {
		t.Fatalf("not resent after the other link died: %+v", st)
	}
	if got := pb.budget.LostPending(); len(got) != 0 {
		t.Fatalf("same frame declared lost twice: %v", got)
	}
}
