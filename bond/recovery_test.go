package bond

import (
	"testing"
	"time"
)

func TestRecoveryIsUnlimitedWhenNoGameTrafficFlows(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	p.budget.rate = 1_000_000
	for i := 0; i < 500; i++ { // a download being repaired
		if !s.recoveryAllow(p, 1400, f.now) {
			t.Fatalf("held back repair %d with no game traffic to protect", i)
		}
		s.recoverySpent(p, 1400, f.now)
	}
}

func TestRecoveryIsSmoothedWhileAGameRunsButNeverHeldLong(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	p.budget.rate = 1_000_000
	s.noteGame(f.now)
	sent := 0
	for s.recoveryAllow(p, 1400, f.now) {
		s.recoverySpent(p, 1400, f.now)
		sent++
		if sent > 100 {
			t.Fatal("no limit while a game runs")
		}
	}
	if sent < 3 || sent > 5 {
		t.Fatalf("burst of %d packets, want about 4", sent)
	}
	// Held, but only for recoveryMaxDelay: then it opens (and stays open briefly).
	at := f.now.Add(recoveryMaxDelay + time.Millisecond)
	s.noteGame(at)
	// A packet larger than the refill so far (13 ms buys about 2.6 KB) is held, then let through.
	if !s.recoveryAllow(p, 5000, at) || s.Stats().RecoveryEscapes != 1 {
		t.Fatalf("a repair was held past %v: %+v", recoveryMaxDelay, s.Stats())
	}
	for i := 0; i < 50; i++ {
		if !s.recoveryAllow(p, 1400, at.Add(10*time.Millisecond)) {
			t.Fatal("limit closed during the escape")
		}
		s.recoverySpent(p, 1400, at.Add(10*time.Millisecond))
	}
}

func TestRecoveryShareGrowsWithLoss(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	if got := s.recoveryShare(p, f.now); got != recoveryShareMin {
		t.Fatalf("share %v with no loss, want %v", got, recoveryShareMin)
	}
	p.budget.lossSeen, p.budget.lossAt, p.budget.lossEWMA = true, s.r.seconds(f.now), 0.05
	if got := s.recoveryShare(p, f.now); got <= recoveryShareMin || got > recoveryShareMax {
		t.Fatalf("share %v at 5%% loss", got)
	}
}

func TestGameRepairsGoAheadOfTCP(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	tcp := MissingPacket{Flow: 1, Number: 1}
	udp := MissingPacket{Flow: 2, Number: 1}
	s.failover = true // lets non-TCP payloads into the repair cache
	s.cacheRepair(tcp, tcpPacket("t"), f.now, p)
	s.cacheRepair(udp, []byte("game"), f.now, p)
	s.queueRepair(tcp, s.repairs[tcp].payload)
	s.queueRepair(udp, s.repairs[udp].payload)
	if first := s.requestOrder.Front().Value.(MissingPacket); first != udp {
		t.Fatalf("first repair %v, want the game packet", first)
	}
}

func TestOnlyStaleGameReplaysAreDropped(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	s.failover = true
	game := MissingPacket{Flow: 1, Number: 1}
	bulk := MissingPacket{Flow: 1, Number: 2}
	s.cacheRepair(game, []byte("game"), f.now, p)
	s.cacheRepair(bulk, tcpPacket("old"), f.now, p)
	s.replayQueue = append(s.replayQueue, replayItem{game})
	s.replayBulk = append(s.replayBulk, replayItem{bulk})
	late := f.now.Add(replayMaxAge + time.Second)
	_ = s.failoverStep(late, func(Datagram) error { return nil })
	if len(s.replayQueue) != 0 {
		t.Fatalf("stale game replay kept: %v", s.replayQueue)
	}
	if st := s.Stats(); st.FailoverReplayDropped == 0 {
		t.Fatalf("nothing dropped: %+v", st)
	}
}
