package bond

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestCoDelUsesRFC8289TargetAndInterval(t *testing.T) {
	var c codelState
	t0 := time.Unix(500, 0)
	if got := c.judge("short", 4*time.Millisecond, 3000, 1500, false, t0); got != codelKeep {
		t.Fatalf("acted below the 5 ms target: %v", got)
	}
	if got := c.judge("standing", 6*time.Millisecond, 3000, 1500, false, t0); got != codelKeep {
		t.Fatalf("acted before the 100 ms interval: %v", got)
	}
	if got := c.judge("standing", 6*time.Millisecond, 3000, 1500, false, t0.Add(codelInterval-time.Nanosecond)); got != codelKeep {
		t.Fatalf("acted before persistent delay lasted one interval: %v", got)
	}
	if got := c.judge("standing", 6*time.Millisecond, 3000, 1500, false, t0.Add(codelInterval)); got != codelDrop {
		t.Fatalf("did not act after the RFC interval: %v", got)
	}
}

func TestCoDelReentryUsesRFC8289PreviousDropCountWhenRecent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dropAge   time.Duration
		wantCount int
	}{
		{name: "recent episode", dropAge: 15 * codelInterval, wantCount: 3},
		{name: "stale episode", dropAge: 16 * codelInterval, wantCount: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c codelState
			t0 := time.Unix(700, 0)
			c.flows = map[string]*codelFlow{
				"f": {firstAbove: t0.Add(-time.Nanosecond), dropNext: t0.Add(-tc.dropAge), count: 8, lastCount: 5},
			}
			if got := c.judge("f", 6*time.Millisecond, 3000, 1500, false, t0); got != codelDrop {
				t.Fatalf("re-entry did not trigger its initial action: %v", got)
			}
			if got := c.flows["f"].count; got != tc.wantCount {
				t.Fatalf("re-entry count = %d, want %d", got, tc.wantCount)
			}
		})
	}
}

func TestCoDelLeavesShortQueuesAloneAndActsOnStandingDelay(t *testing.T) {
	var c codelState
	t0 := time.Unix(1000, 0)
	for i := 0; i < 50; i++ {
		if c.judge("f", 2*time.Millisecond, 3000, 1500, false, t0.Add(time.Duration(i)*10*time.Millisecond)) != codelKeep {
			t.Fatal("acted on a short queue")
		}
	}
	var drops, marks int
	for i := 0; i < 200; i++ { // 2 s of 120 ms standing delay
		switch c.judge("g", 120*time.Millisecond, 3000, 1500, i%2 == 0, t0.Add(time.Duration(i)*10*time.Millisecond)) {
		case codelDrop:
			drops++
		case codelMark:
			marks++
		}
	}
	if drops+marks < 3 {
		t.Fatalf("standing queue not controlled: drops %d marks %d", drops, marks)
	}
	if c.judge("g", time.Millisecond, 3000, 1500, false, t0.Add(2*time.Second)) != codelKeep {
		t.Fatal("kept acting after the queue drained")
	}
}

func TestCoDelDoesNotStarveFlowBelowOneMaxPacket(t *testing.T) {
	var c codelState
	t0 := time.Unix(2000, 0)
	for i := 0; i < 100; i++ {
		if got := c.judge("sparse", 500*time.Millisecond, 1500, 1500, false, t0.Add(time.Duration(i)*10*time.Millisecond)); got != codelKeep {
			t.Fatalf("acted with only one maximum packet queued: %v", got)
		}
	}
	// Once there is more than one maximum packet of backlog, persistent
	// sojourn above the target must enter the control loop.
	var acted bool
	for i := 0; i < 100; i++ {
		if got := c.judge("bulk", 500*time.Millisecond, 3000, 1500, false, t0.Add(time.Duration(i)*10*time.Millisecond)); got != codelKeep {
			acted = true
			break
		}
	}
	if !acted {
		t.Fatal("did not act on persistent delay with more than one maximum packet queued")
	}
}

func TestTransmitQueueCoDelMarksAndDropsAtDequeue(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    byte
		ecn        byte
		wantMarked uint64
		wantDrop   uint64
		wantFirst  byte
		markOffset int
	}{
		{name: "IPv4 ECT", version: 4, ecn: 2, wantMarked: 1, wantFirst: 0, markOffset: 20},
		{name: "IPv4 Not-ECT", version: 4, ecn: 0, wantDrop: 1, wantFirst: 1, markOffset: 20},
		{name: "IPv6 ECT", version: 6, ecn: 1, wantMarked: 1, wantFirst: 0, markOffset: 40},
		{name: "IPv6 Not-ECT", version: 6, ecn: 0, wantDrop: 1, wantFirst: 1, markOffset: 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, sender, _ := senderFixture(t, 1)
			q, err := NewTransmitQueue(sender, 8, 8192)
			if err != nil {
				t.Fatal(err)
			}
			q.EnableCoDel(true)
			for i := byte(0); i < 3; i++ {
				p := make([]byte, 600)
				header := 20
				if tc.version == 4 {
					p[0], p[1], p[9] = 0x45, 0xa8|tc.ecn, 17
					binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
				} else {
					trafficClass := byte(42<<2) | tc.ecn
					p[0], p[1], p[6], p[7] = 0x60|trafficClass>>4, trafficClass<<4, 17, 64
					binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
					header = 40
				}
				binary.BigEndian.PutUint16(p[header+4:header+6], uint16(len(p)-header))
				p[tc.markOffset] = i
				if !q.EnqueueAt(QueuedPacket{Payload: p, Flow: "bulk-flow", Expires: f.now.Add(time.Second)}, f.now.Add(-200*time.Millisecond)) {
					t.Fatal("queue admission failed")
				}
			}
			bucket := q.bulk.bucket("bulk-flow")
			key := fqCoDelKey(bucket)
			q.codelState.flows = map[string]*codelFlow{key: {firstAbove: f.now.Add(-time.Second)}}

			var firstData []byte
			_, err = q.Pump(f.now, func(d Datagram) error {
				decoded, decodeErr := f.c.Decode(d.Frame)
				if decodeErr != nil {
					return decodeErr
				}
				if decoded.Header.Kind == Striped && len(decoded.Payload) >= 24 && firstData == nil {
					firstData = decoded.Payload[24:]
				} else if decoded.Header.Kind == Data && firstData == nil {
					firstData = decoded.Payload
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if q.Stats().CoDelMarked != tc.wantMarked || q.Stats().CoDelDropped != tc.wantDrop {
				t.Fatalf("CoDel stats = %+v", q.Stats())
			}
			if firstData == nil || firstData[tc.markOffset] != tc.wantFirst {
				t.Fatalf("first delivered packet sequence = %v, want %d; queue=%+v sender=%+v", firstData, tc.wantFirst, q.Stats(), sender.Stats())
			}
			if tc.wantMarked != 0 && testPacketECN(firstData) != 3 {
				t.Fatalf("first delivered packet ECN = %d, want CE", testPacketECN(firstData))
			}
		})
	}
}

func TestTransmitQueueMixedFlowCoDelDoesNotHideSparseFlow(t *testing.T) {
	f, sender, addresses := senderFixture(t, 1)
	budget, err := NewBudget(100, 100)
	if err != nil {
		t.Fatal(err)
	}
	f.r.paths[pk(addresses[0])].budget = budget
	q, err := NewTransmitQueue(sender, 256, 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	q.EnableCoDel(true)
	base := f.now
	makePacket := func(marker byte, size int) []byte {
		p := make([]byte, size)
		p[0], p[1], p[9] = 0x45, marker<<2, 17
		binary.BigEndian.PutUint16(p[2:4], uint16(size))
		return p
	}
	for i := 0; i < 120; i++ {
		if !q.EnqueueAt(QueuedPacket{Payload: makePacket(1, 1200), Flow: "backlogged", Expires: base.Add(time.Second)}, base) {
			t.Fatal("bulk admission failed")
		}
	}
	seen := make([]byte, 0, 128)
	writer := func(d Datagram) error {
		decoded, err := f.c.Decode(d.Frame)
		if err != nil {
			return err
		}
		payload := decoded.Payload
		if decoded.Header.Kind == Striped {
			payload = payload[24:]
		}
		if decoded.Header.Kind == Striped || decoded.Header.Kind == Data || decoded.Header.Kind == DataCopy {
			seen = append(seen, payload[1]>>2)
		}
		return nil
	}
	if _, err := q.Pump(base.Add(200*time.Millisecond), writer); err != nil {
		t.Fatal(err)
	}
	// The sparse flow arrives just before the CoDel interval expires. Its short
	// sojourn should let it use the fair queue while persistent bulk delay is
	// controlled independently.
	queueIndexAtSparseArrival := len(seen)
	for i := 0; i < 4; i++ {
		if !q.EnqueueAt(QueuedPacket{Payload: makePacket(2, 200), Flow: "sparse", Expires: base.Add(time.Second)}, base.Add(290*time.Millisecond)) {
			t.Fatal("sparse admission failed")
		}
	}
	for step := 0; step < 20 && q.Stats().QueuedPackets > 0; step++ {
		now := base.Add(time.Duration(300+step*10) * time.Millisecond)
		if _, err := q.Pump(now, writer); err != nil {
			t.Fatal(err)
		}
	}
	firstSparse := -1
	backlogged, sparse := 0, 0
	for i, marker := range seen {
		if marker == 1 {
			backlogged++
		}
		if marker == 2 {
			sparse++
			if firstSparse < 0 {
				firstSparse = i
			}
		}
	}
	if firstSparse < queueIndexAtSparseArrival || firstSparse-queueIndexAtSparseArrival > 16 {
		t.Fatalf("sparse flow waited behind bulk backlog: index at admission=%d, first index=%d, sent=%v", queueIndexAtSparseArrival, firstSparse, seen)
	}
	if sparse != 4 {
		t.Fatalf("sparse packets delivered=%d, want 4; queue=%+v", sparse, q.Stats())
	}
	if q.Stats().CoDelDropped == 0 || backlogged == 0 {
		t.Fatalf("mixed-flow run missed persistent bulk queue control: sent bulk=%d stats=%+v", backlogged, q.Stats())
	}
}

func TestMarkCESetsCEAndKeepsChecksumValid(t *testing.T) {
	p := make([]byte, 40)
	p[0], p[1], p[8], p[9] = 0x45, 0x02, 64, 6 // ECT(0)
	p[3] = 40
	if !markCE(p) || p[1]&3 != 3 {
		t.Fatal("not marked")
	}
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	if sum != 0xFFFF {
		t.Fatalf("bad checksum %x", sum)
	}
	p[1] = 0
	if markCE(p) {
		t.Fatal("marked a non-ECN packet")
	}
	ipv6 := ecnIPv6Packet(1)
	flowLabel := [3]byte{ipv6[1] & 0x0f, ipv6[2], ipv6[3]}
	if !markCE(ipv6) {
		t.Fatal("IPv6 ECT packet was not marked CE")
	}
	trafficClass, ok := innerTrafficClass(ipv6)
	if !ok || trafficClass&3 != 3 || trafficClass>>2 != 42 {
		t.Fatal("IPv6 ECT packet was not marked CE with its DSCP preserved")
	}
	if [3]byte{ipv6[1] & 0x0f, ipv6[2], ipv6[3]} != flowLabel {
		t.Fatal("IPv6 flow label changed while marking CE")
	}
	malformed := ecnIPv4Packet(2)
	malformed[0] = 0x44 // Invalid IPv4 IHL must not take the mark path.
	if ecnCapable(malformed) || markCE(malformed) {
		t.Fatal("malformed IPv4 header reported as ECN-capable")
	}
}
