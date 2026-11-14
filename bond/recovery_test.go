package bond

import (
	"testing"
	"time"
)

func TestRecoveryIsHeldToAShareOfTheLink(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	p.budget.rate = 1_000_000 // 1 MB/s link: burst is the 6000 byte floor
	sent := 0
	for s.recoveryAllow(p, 1400, f.now) {
		s.recoverySpent(p, 1400, f.now)
		sent++
		if sent > 100 {
			t.Fatal("no limit")
		}
	}
	if sent < 3 || sent > 5 {
		t.Fatalf("burst of %d packets, want about 4 (6000 bytes)", sent)
	}
	if s.Stats().RecoveryPeak10ms != uint64(sent) {
		t.Fatalf("peak %d, want %d", s.Stats().RecoveryPeak10ms, sent)
	}
	// 20% of 1 MB/s is 200 KB/s: 10 ms buys 2000 bytes, one more packet.
	later := f.now.Add(10 * time.Millisecond)
	if !s.recoveryAllow(p, 1400, later) {
		t.Fatal("no refill after 10 ms")
	}
	s.recoverySpent(p, 1400, later)
	if s.recoveryAllow(p, 1400, later) {
		t.Fatal("refill is faster than the share")
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

func TestStaleReplaysAreDropped(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p := f.r.paths[pk(a[0])]
	key := MissingPacket{Flow: 1, Number: 1}
	s.cacheRepair(key, tcpPacket("old"), f.now, p)
	s.replayBulk = append(s.replayBulk, replayItem{key})
	if err := s.failoverStep(f.now.Add(replayMaxAge+time.Second), func(Datagram) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(s.replayBulk) != 0 || s.Stats().FailoverReplayDropped == 0 || s.Stats().FailoverReplayed != 0 {
		t.Fatalf("queue %v stats %+v", s.replayBulk, s.Stats())
	}
}
