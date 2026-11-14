package bond

import "testing"

// A lost frame is classified by why it cannot be resent, and a failover replay is
// skipped when a healthy path already carries a copy.
func TestUnrecoverableLossSaysWhy(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	// Never cached (a UDP packet): not repairable by design.
	udp := MissingPacket{Flow: 7, Number: 1}
	s.cacheRepair(udp, []byte("not tcp"), f.now, f.r.paths[pk(a[0])])
	s.sackLoss(udp, f.now)
	// Cached once, then gone from the cache: expired.
	gone := MissingPacket{Flow: 8, Number: 1}
	s.cacheRepair(gone, tcpPacket("x"), f.now, f.r.paths[pk(a[0])])
	delete(s.repairs, gone)
	s.sackLoss(gone, f.now)
	// Cached and every attempt used.
	spent := MissingPacket{Flow: 9, Number: 1}
	s.cacheRepair(spent, tcpPacket("y"), f.now, f.r.paths[pk(a[0])])
	s.repairs[spent].attempts = repairAttempts
	s.sackLoss(spent, f.now)
	st := s.Stats()
	if st.SackUnrecoverable != 3 || st.SackNotRepairable != 1 || st.SackExpired != 1 || st.SackExhausted != 1 {
		t.Fatalf("reasons: %+v", st)
	}
}

func TestReplaySkippedWhenAHealthyPathHoldsACopy(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p0, p1 := f.r.paths[pk(a[0])], f.r.paths[pk(a[1])]
	paired := MissingPacket{Flow: 1, Number: 1}
	alone := MissingPacket{Flow: 1, Number: 2}
	s.cacheRepair(paired, tcpPacket("a"), f.now, p0)
	s.repairs[paired].carry(p1) // the duplicate went out on the other link
	s.cacheRepair(alone, tcpPacket("b"), f.now, p0)
	p0.last = f.now
	s.queueReplays(p0, f.now)
	if len(s.replayQueue) != 1 || s.replayQueue[0].key != alone || s.Stats().ReplaySkipped != 1 {
		t.Fatalf("queue %v stats %+v", s.replayQueue, s.Stats())
	}
}
