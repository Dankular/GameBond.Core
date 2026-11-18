package bond

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func tcpPacket(payload string) []byte {
	p := make([]byte, 40+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[9] = 6
	copy(p[12:16], []byte{10, 77, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:], 1234)
	binary.BigEndian.PutUint16(p[22:], 443)
	p[32] = 0x50
	p[33] = 0x10
	copy(p[40:], payload)
	return p
}
func TestRepairRetainsFlowSequenceUsesFreshNonceAndStopsAfterFour(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	var frames []Datagram
	writer := func(d Datagram) error { frames = append(frames, d); return nil }
	payload := tcpPacket("application data")
	sent, _, err := s.Bulk(payload, "tcp-flow", f.now, writer)
	if !sent || err != nil {
		t.Fatal(err)
	}
	original, _ := f.c.Decode(frames[0].Frame)
	request := append([]byte(nil), original.Payload[:16]...)
	for i := 0; i < repairAttempts+1; i++ {
		f.now = f.now.Add(20 * time.Millisecond)
		out := f.receive(t, Repair, request, a[0])
		s.Controls(out, f.now, writer)
		if err := s.Maintenance(f.now, writer); err != nil {
			t.Fatal(err)
		}
	}
	// the third request is past the attempt limit: it is answered with REPAIR_NA
	if len(frames) != repairAttempts+2 || s.Stats().RepairUnavailableSent != 1 || s.Stats().RepairCopies != repairAttempts || s.Stats().Copies != repairAttempts+1 || s.Stats().PayloadPackets != 1 {
		t.Fatal("repair attempts or payload accounting differ", s.Stats(), len(frames))
	}
	na, err := f.c.Decode(frames[repairAttempts+1].Frame)
	if err != nil || na.Header.Kind != RepairNA || !bytes.Equal(na.Payload, request) || frames[repairAttempts+1].Endpoint != a[0] {
		t.Fatal("expected REPAIR_NA for the exhausted request", err)
	}
	for _, d := range frames[1 : repairAttempts+1] {
		packet, err := f.c.Decode(d.Frame)
		if err != nil || packet.Header.Sequence <= original.Header.Sequence || !bytes.Equal(packet.Payload[:16], original.Payload[:16]) || !bytes.Equal(packet.Payload[24:], payload) {
			t.Fatal("repair reused nonce or changed inner packet", err)
		}
	}
	s.Maintenance(f.now.Add(s.repairLife()+time.Second), writer)
	if len(s.repairs) != 0 {
		t.Fatal("repair cache did not expire")
	}
}

// A repair answer is itself redundancy-worthy: with a third path ready besides the one that
// lost the packet, the cached payload goes out on two different paths, neither of them the
// one already proven bad for this packet, so the repair is not a single point of failure the
// way a single-path answer would be if that one chosen line blipped right as it went out.
func TestRepairAnswerIsCopiedOntoASecondPathAvoidingTheOneThatLostIt(t *testing.T) {
	f, s, a := senderFixture(t, 3)
	var frames []Datagram
	writer := func(d Datagram) error { frames = append(frames, d); return nil }
	payload := tcpPacket("application data")
	if sent, _, err := s.Bulk(payload, "tcp-flow", f.now, writer); !sent || err != nil {
		t.Fatal(err)
	}
	original, _ := f.c.Decode(frames[0].Frame)
	originEndpoint := frames[0].Endpoint
	request := append([]byte(nil), original.Payload[:16]...)
	frames = nil
	f.now = f.now.Add(20 * time.Millisecond)
	out := f.receive(t, Repair, request, a[0])
	s.Controls(out, f.now, writer)
	if err := s.Maintenance(f.now, writer); err != nil {
		t.Fatal(err)
	}
	seen := map[netip.AddrPort]int{}
	for _, d := range frames {
		packet, err := f.c.Decode(d.Frame)
		if err != nil || packet.Header.Kind != Striped {
			continue
		}
		if !bytes.Equal(packet.Payload[:16], original.Payload[:16]) || !bytes.Equal(packet.Payload[24:], payload) {
			t.Fatal("repair copy changed inner packet or key")
		}
		seen[d.Endpoint]++
	}
	if len(seen) != 2 {
		t.Fatalf("repair answered on %d path(s), want both: %v", len(seen), seen)
	}
	if seen[originEndpoint] > 0 {
		t.Fatalf("repair duplicated onto the path that lost it (%v): %v", originEndpoint, seen)
	}
	if s.Stats().RepairCopies != 2 {
		t.Fatalf("RepairCopies = %d, want 2", s.Stats().RepairCopies)
	}
}

func TestReceiveHolesRequestBoundedTCPRepairsWithoutBlockingUrgent(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	f.r.reorder.config.Timeout = 1500 * time.Millisecond
	f.receive(t, Striped, stripe(77, 1, 1, tcpPacket("later")), a[0])
	var requests []Packet
	writer := func(d Datagram) error {
		packet, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, packet)
		return nil
	}
	// Past the attempt limit, spaced beyond the ask gap, so the bound is what stops the asking.
	for i := 0; i <= repairAttempts+2; i++ {
		if err := s.Maintenance(f.now.Add(time.Duration(16+i*90)*time.Millisecond), writer); err != nil {
			t.Fatal(err)
		}
	}
	if len(requests) != repairAttempts {
		t.Fatal("missing TCP range not bounded to the repair attempt limit", len(requests))
	}
	for _, p := range requests {
		if p.Header.Kind != Repair || binary.BigEndian.Uint64(p.Payload) != 77 || binary.BigEndian.Uint64(p.Payload[8:]) != 0 {
			t.Fatal("wrong repair hole")
		}
	}
	out := f.receive(t, Data, []byte("urgent"), a[0])
	if len(out.Deliver) != 1 {
		t.Fatal("repair hole blocked urgent DATA")
	}
	// A lost UDP packet is asked for as well (see TestLostUDPPacketIsAskedForLikeTCP).
	f.receive(t, Striped, stripe(88, 1, 1, udpPacket(5000, 6000, 2)), a[0])
	s.Maintenance(f.now.Add(time.Duration(16+(repairAttempts+3)*90)*time.Millisecond), writer)
	if len(requests) != repairAttempts+1 {
		t.Fatalf("UDP hole not asked for: %d requests", len(requests))
	}
}
func TestTransmitQueueAdmitsUrgentDuringBulkPressureAndOwnsBuffers(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 2, 2800)
	expires := f.now.Add(200 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if !q.Enqueue(QueuedPacket{Payload: []byte("bulk"), Flow: "b", Expires: expires}) {
			t.Fatal("bulk admission failed")
		}
	}
	ack := tcpPacket("")
	if !q.Enqueue(QueuedPacket{Payload: ack, Flow: "a", Expires: expires}) {
		t.Fatal("TCP ACK was not admitted over full bulk")
	}
	ack[20] ^= 1
	for i := 0; i < maxPending; i++ {
		s.r.paths[pk(a[0])].budget.Sent(uint64(i), 1400, 0)
	}
	var delivered [][]byte
	writer := func(d Datagram) error {
		packet, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Header.Kind == Data {
			delivered = append(delivered, packet.Payload)
		}
		return nil
	}
	q.Pump(f.now, writer)
	if len(delivered) != 1 || !bytes.Equal(delivered[0], tcpPacket("")) || q.Stats().EvictedBulk != 1 || q.Stats().QueuedPackets != 1 {
		t.Fatal("bulk pressure blocked ACK or queue borrowed memory", q.Stats())
	}
	q.Pump(expires, writer)
	if q.Stats().Expired != 1 || q.Stats().ExpiredBulk != 1 || q.Stats().ExpiredPriority != 0 || q.Stats().QueuedPackets != 0 || q.Stats().QueuedBytes != 0 {
		t.Fatal("expired bulk retained", q.Stats())
	}
}

func TestTransmitQueueBatchesAdmissionEvictionFromLargestFlow(t *testing.T) {
	f, s, _ := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 4, 8192)
	expires := f.now.Add(time.Second)
	for i := 0; i < 4; i++ {
		if !q.Enqueue(QueuedPacket{Payload: make([]byte, 100), Flow: "hog", Expires: expires}) {
			t.Fatal("hog admission failed")
		}
	}
	if !q.Enqueue(QueuedPacket{Payload: make([]byte, 100), Flow: "mouse", Expires: expires}) {
		t.Fatal("bulk admission should evict a batch from the largest flow")
	}
	stats := q.Stats()
	if stats.EvictedBulk != 2 || stats.QueuedPackets != 3 || stats.QueuedBytes != 300 || stats.Rejected != 0 {
		t.Fatalf("largest-flow batch eviction stats: %+v", stats)
	}
}

func TestMalformedTCPAndFragmentsCannotBypassBulk(t *testing.T) {
	valid := tcpPacket("")
	if !IsTCPControl(valid) {
		t.Fatal("valid ACK not recognized")
	}
	withData := tcpPacket("data")
	if IsTCPControl(withData) {
		t.Fatal("TCP application bytes promoted to control")
	}
	fragment := append([]byte(nil), valid...)
	fragment[6] = 0x20
	invalidLength := append([]byte(nil), valid...)
	invalidLength[3]--
	invalidTCPHeader := append([]byte(nil), valid...)
	invalidTCPHeader[32] = 0x10
	for _, p := range [][]byte{fragment, invalidLength, invalidTCPHeader, valid[:30]} {
		if IsTCPControl(p) {
			t.Fatal("malformed/fragmented packet bypassed bulk")
		}
	}
}
func TestPeerRestartDiscardsOldQueuedPlaintextAndRepairState(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 4, 4096)
	if !q.Enqueue(QueuedPacket{Payload: tcpPacket("old session"), Flow: "old", Expires: f.now.Add(time.Second)}) {
		t.Fatal("admission failed")
	}
	client, _ := NewCodec(f.c.key[:], f.c.Session[:], "client")
	f.c = client
	f.connect(t, a[0])
	if !q.Enqueue(QueuedPacket{Payload: tcpPacket("new session"), Flow: "new", Expires: f.now.Add(time.Second)}) {
		t.Fatal("new admission failed")
	}
	var payloads [][]byte
	q.Pump(f.now, func(d Datagram) error {
		p, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, p.Payload[24:])
		return nil
	})
	if len(payloads) != 1 || !bytes.Equal(payloads[0], tcpPacket("new session")) || q.Stats().PeerResetDropped != 1 {
		t.Fatal("old session crossed peer restart", q.Stats())
	}
}

func TestUnknownRepairIsAnsweredOnceWithNAOnItsPath(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	var frames []Datagram
	writer := func(d Datagram) error { frames = append(frames, d); return nil }
	request := make([]byte, 16)
	binary.BigEndian.PutUint64(request, 7)
	binary.BigEndian.PutUint64(request[8:], 99)
	out := f.receive(t, Repair, request, a[0])
	s.Controls(out, f.now, writer)
	if len(frames) != 1 || s.Stats().RepairUnavailableSent != 1 {
		t.Fatalf("frames=%d %+v", len(frames), s.Stats())
	}
	na, err := f.c.Decode(frames[0].Frame)
	if err != nil || na.Header.Kind != RepairNA || !bytes.Equal(na.Payload, request) {
		t.Fatal(err, na)
	}
	// a request that is still queued for repair must not also be answered NA
	payload := tcpPacket("x")
	f.now = f.now.Add(50 * time.Millisecond)
	if sent, _, err := s.Bulk(payload, "flow", f.now, writer); !sent || err != nil {
		t.Fatal(err)
	}
	original, _ := f.c.Decode(frames[1].Frame)
	known := append([]byte(nil), original.Payload[:16]...)
	n := len(frames)
	s.Controls(f.receive(t, Repair, known, a[0]), f.now, writer)
	s.Controls(f.receive(t, Repair, known, a[0]), f.now, writer) // already queued: silent
	if len(frames) != n || s.Stats().RepairUnavailableSent != 1 {
		t.Fatalf("queued repair was answered NA: frames %d->%d %+v", n, len(frames), s.Stats())
	}
	// queued, then the cached copy goes stale: still queued, so still no NA
	f.now = f.now.Add(1100 * time.Millisecond)
	s.Controls(f.receive(t, Repair, known, a[0]), f.now, writer)
	if len(frames) != n || s.Stats().RepairUnavailableSent != 1 {
		t.Fatalf("stale-but-queued request answered NA: %+v", s.Stats())
	}
}

func TestRepairRequestGoesOutOnEveryReadyPath(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	f.r.reorder.config.Timeout = 200 * time.Millisecond
	f.receive(t, Striped, stripe(77, 1, 1, tcpPacket("later")), a[0])
	targets := map[string]int{}
	writer := func(d Datagram) error {
		if p, err := f.c.Decode(d.Frame); err == nil && p.Header.Kind == Repair {
			targets[d.Endpoint.String()]++
		}
		return nil
	}
	if err := s.Maintenance(f.now.Add(20*time.Millisecond), writer); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("repair request used %d path(s), want both: %v", len(targets), targets)
	}
	if s.Stats().RepairRequests != 1 {
		t.Fatalf("one hole counted as %d requests", s.Stats().RepairRequests)
	}
}

func TestLostUDPPacketIsAskedForLikeTCP(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	f.r.reorder.config.Timeout = 200 * time.Millisecond
	f.receive(t, Striped, stripe(78, 1, 1, udpPacket(5000, 6000, 1)), a[0])
	asked := 0
	writer := func(d Datagram) error {
		if p, err := f.c.Decode(d.Frame); err == nil && p.Header.Kind == Repair {
			asked++
		}
		return nil
	}
	if err := s.Maintenance(f.now.Add(20*time.Millisecond), writer); err != nil {
		t.Fatal(err)
	}
	if asked == 0 || s.Stats().RepairRequests != 1 {
		t.Fatalf("lost UDP packet not asked for: %d frames, %+v", asked, s.Stats())
	}
}
