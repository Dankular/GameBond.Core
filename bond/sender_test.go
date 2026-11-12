package bond

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"
)

func senderFixture(t *testing.T, paths int) (receiverFixture, *Sender, []netip.AddrPort) {
	t.Helper()
	f := newReceiverFixture(t)
	sender, err := NewSender(f.r, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	sender.lossTiered = true // older tests count the loss-driven tiers; the always-duplicate tests set it false
	var addresses []netip.AddrPort
	for i := 0; i < paths; i++ {
		a := netip.AddrPortFrom(f.endpoint.Addr(), uint16(1234+i))
		f.connect(t, a)
		addresses = append(addresses, a)
		f.r.paths[pk(a)].hasRTT = true
		f.r.paths[pk(a)].rtt = .02
	}
	return f, sender, addresses
}
func policyPayload(revision uint64, role byte, blocked bool, upload, download float64) []byte {
	data := make([]byte, 26)
	binary.BigEndian.PutUint64(data, revision)
	data[8] = role
	if blocked {
		data[9] = 1
	}
	binary.BigEndian.PutUint64(data[10:], math.Float64bits(upload))
	binary.BigEndian.PutUint64(data[18:], math.Float64bits(download))
	return data
}
func TestSenderWeightedSingleFlowAndAuthenticatedFeedback(t *testing.T) {
	f, s, addresses := senderFixture(t, 2)
	f.r.paths[pk(addresses[0])].budget, _ = NewBudget(10, 10)
	f.r.paths[pk(addresses[1])].budget, _ = NewBudget(20, 20)
	var packets []Datagram
	counts := map[netip.AddrPort]int{}
	delivered := map[netip.AddrPort]uint64{}
	now := f.now
	for number := 0; number < 600; {
		s.ResumeBulk(now)
		sent, due, err := s.Bulk(bytes.Repeat([]byte{42}, 1000), "one-flow", now, func(d Datagram) error { packets = append(packets, d); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if !sent {
			now = due.Add(time.Microsecond)
			continue
		}
		d := packets[len(packets)-1]
		packet, err := f.c.Decode(d.Frame)
		if err != nil || packet.Header.Kind != Striped || binary.BigEndian.Uint64(packet.Payload[8:]) != uint64(number) {
			t.Fatal("flow sequencing failed", err)
		}
		counts[d.Endpoint]++
		delivered[d.Endpoint] += uint64(len(d.Frame))
		p := f.r.paths[pk(d.Endpoint)]
		feedback := make([]byte, 28)
		binary.BigEndian.PutUint64(feedback, p.txEpoch)
		binary.BigEndian.PutUint64(feedback[8:], packet.Header.Sequence)
		binary.BigEndian.PutUint64(feedback[16:], delivered[d.Endpoint])
		f.now = now
		f.receive(t, Feedback, feedback, d.Endpoint)
		number++
		now = now.Add(10 * time.Microsecond)
	}
	if counts[addresses[0]] < 150 || counts[addresses[1]] < 350 {
		t.Fatal("one flow did not exercise weighted paths", counts)
	}
	for _, p := range f.r.paths {
		if p.budget.deliveryCounter == 0 || p.budget.invalidACKs != 0 {
			t.Fatal("feedback did not credit correct path")
		}
	}
	if s.Stats().StripedPackets != 600 {
		t.Fatal(s.Stats())
	}
}
func TestSenderFailedWritesDoNotAdvanceFlowOrCreditBudget(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	calls := 0
	var successes []Datagram
	sent, _, err := s.Bulk([]byte("payload"), "flow", f.now, func(d Datagram) error {
		calls++
		if calls == 1 {
			return errors.New("socket unavailable")
		}
		successes = append(successes, d)
		return nil
	})
	if !sent || err != nil || calls != 2 {
		t.Fatal("no immediate fallback", err, calls)
	}
	packet, _ := f.c.Decode(successes[0].Frame)
	if binary.BigEndian.Uint64(packet.Payload[8:]) != 0 || s.flows["flow"].number != 1 || s.Stats().SocketErrors != 1 {
		t.Fatal("failed write consumed flow sequence or payload accounting")
	}
	sentBytes := uint64(0)
	for _, p := range f.r.paths {
		sentBytes += p.budget.sentBytes
	}
	if sentBytes != uint64(len(successes[0].Frame)) {
		t.Fatal("failed write credited delivery budget")
	}
}
func TestLinkRolesFailClosedForUnconfirmedAndFailOverToBackup(t *testing.T) {
	f, s, a := senderFixture(t, 3)
	f.receive(t, LinkPolicy, policyPayload(1, Primary, false, 0, 0), a[0])
	if paths := s.eligible(f.now, true); len(paths) != 1 || paths[0].endpoint != a[0] {
		t.Fatal("unconfirmed policy path eligible")
	}
	f.receive(t, LinkPolicy, policyPayload(1, Secondary, false, 0, 0), a[1])
	f.receive(t, LinkPolicy, policyPayload(1, Backup, false, 0, 0), a[2])
	if len(s.eligible(f.now, true)) != 2 || len(s.eligible(f.now, false)) != 1 {
		t.Fatal("primary/secondary role semantics differ")
	}
	f.receive(t, LinkPolicy, policyPayload(2, Never, true, 0, 0), a[0])
	if paths := s.eligible(f.now, true); len(paths) != 1 || paths[0].endpoint != a[1] {
		t.Fatal("secondary fallback failed")
	}
	f.receive(t, LinkPolicy, policyPayload(2, Secondary, true, 0, 0), a[1])
	if paths := s.eligible(f.now, true); len(paths) != 1 || paths[0].endpoint != a[2] {
		t.Fatal("backup not selected after other links disabled")
	}
	// Same revision cannot silently alter the effective policy.
	f.receive(t, LinkPolicy, policyPayload(2, Primary, false, 0, 0), a[0])
	if f.r.paths[pk(a[0])].policy.Role != Never {
		t.Fatal("same revision overwrote policy")
	}
	f.receive(t, LinkPolicy, policyPayload(1, Primary, false, 0, 0), a[0])
	if f.r.paths[pk(a[0])].policy.Role != Never {
		t.Fatal("old revision overwrote policy")
	}
}
func TestConfiguredWireCapChargesControlUrgentAndEveryCopy(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	now := f.now
	tx := map[netip.AddrPort]int{}
	writer := func(d Datagram) error { tx[d.Endpoint] += len(d.Frame) + 28; return nil }
	for _, endpoint := range a {
		out := f.receive(t, LinkPolicy, policyPayload(1, Primary, false, 0, 1), endpoint)
		s.Controls(out, now, writer)
	}
	for tick := 0; tick < 1000; tick++ {
		now = f.now.Add(time.Duration(tick) * time.Millisecond)
		// Both replicated traffic and timer control share the configured cap.
		if _, err := s.Urgent(bytes.Repeat([]byte{3}, 1000), true, now, writer); err != nil {
			t.Fatal(err)
		}
		frame, _ := f.r.codec.Encode(Pong, probe(1))
		s.Controls(ReceiveResult{Send: []Datagram{{Endpoint: a[0], Frame: frame}, {Endpoint: a[1], Frame: frame}}}, now, writer)
	}
	for _, endpoint := range a {
		if tx[endpoint] > 127800 || tx[endpoint] < 120000 {
			t.Fatal("wire cap not enforced per copy", tx)
		}
		if f.r.paths[pk(endpoint)].wireTX != uint64(tx[endpoint]) {
			t.Fatal("all-wire meter disagrees with successful writes")
		}
	}
	if s.Stats().WireLimited == 0 {
		t.Fatal("cap never constrained traffic")
	}
}
func TestUrgentTCPAcknowledgementBypassesBulkWindow(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	p := f.r.paths[pk(a[0])]
	for i := 0; i < maxPending; i++ {
		p.budget.Sent(uint64(i), 1400, 0)
	}
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:], 40)
	packet[32] = 0x50
	packet[33] = 0x10
	var emitted Datagram
	sent, _, err := s.Bulk(packet, "ack", f.now, func(d Datagram) error { emitted = d; return nil })
	if !sent || err != nil || emitted.Frame[36] != Data || s.Stats().TCPControlPackets != 1 {
		t.Fatal("ACK blocked behind bulk window", err)
	}
	if p.budget.priorityPackets != 1 || p.budget.sentPackets != maxPending {
		t.Fatal("ACK consumed bulk tracking")
	}
}
func TestPolicyDecoderAndWirePacerValidation(t *testing.T) {
	for _, data := range [][]byte{nil, policyPayload(1, 4, false, 0, 1), policyPayload(1, Primary, false, math.NaN(), 1), policyPayload(1, Primary, false, 0, 10001)} {
		if _, _, err := decodePolicy(data); err == nil {
			t.Fatal("invalid link policy accepted")
		}
	}
	var p WirePacer
	p.SetRate(1, 0)
	p.Sent(2800, 0)
	before := p.ReadyAt(1000, 0)
	p.SetRate(.5, 0)
	if p.ReadyAt(1000, 0) < before {
		t.Fatal("rate change discarded queued wire debt")
	}
}
func TestBlockedAndNeverPathsCannotInjectData(t *testing.T) {
	f, _, a := senderFixture(t, 1)
	for revision, policy := range []PathPolicy{{Primary, true, 0, 0}, {Never, false, 0, 0}} {
		f.receive(t, LinkPolicy, policyPayload(uint64(revision+1), policy.Role, policy.Blocked, 0, 0), a[0])
		if out := f.receive(t, Data, []byte("forbidden"), a[0]); len(out.Deliver) != 0 {
			t.Fatal("disabled path injected priority DATA")
		}
		if out := f.receive(t, Striped, stripe(99, 0, 1, []byte("forbidden")), a[0]); len(out.Deliver) != 0 {
			t.Fatal("disabled path injected bulk")
		}
	}
	if f.r.Stats().PolicyDrops != 4 {
		t.Fatal("policy drops not exposed")
	}
	f.receive(t, LinkPolicy, policyPayload(3, Primary, false, 0, 0), a[0])
	if out := f.receive(t, Data, []byte("allowed"), a[0]); len(out.Deliver) != 1 {
		t.Fatal("path did not recover after unblocking")
	}
}

// bulkEndpoints sends n bulk packets (TCP data on distinct flows) and counts which
// endpoint carried each.
func bulkEndpoints(t *testing.T, f receiverFixture, s *Sender, a []netip.AddrPort, n int) map[netip.AddrPort]int {
	t.Helper()
	used := map[netip.AddrPort]int{}
	for i := 0; i < n; i++ {
		now := f.now.Add(time.Duration(i) * 5 * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now
		}
		if _, _, err := s.Bulk(tcpPacket("data"), fmt.Sprint("flow", i), now, func(d Datagram) error {
			used[d.Endpoint]++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return used
}

func TestBulkPrefersTheClearlyFasterPath(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	slow, fast := f.r.paths[pk(a[0])], f.r.paths[pk(a[1])]
	slow.rtt, slow.hasRTT = .120, true
	fast.rtt, fast.hasRTT = .030, true
	f.r.reorder.config.Timeout = time.Second // the old margin filter would let both through
	used := bulkEndpoints(t, f, s, a, 20)
	if used[a[0]] != 0 || used[a[1]] == 0 {
		t.Fatalf("slow path carried bulk while the fast one was free: %v", used)
	}
}

func TestBulkStillSharesNearEqualPaths(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	for i, k := range a {
		p := f.r.paths[pk(k)]
		p.rtt, p.hasRTT = .050+float64(i)*.003, true
	}
	used := bulkEndpoints(t, f, s, a, 40)
	if used[a[0]] == 0 || used[a[1]] == 0 {
		t.Fatalf("near-equal paths did not share: %v", used)
	}
}

// The reorder timeout follows the measured RTT difference between the paths: a
// small one keeps game latency low, a large one waits for the slow path.
func TestReorderTimeoutTracksTheRTTGapBetweenPaths(t *testing.T) {
	f, _, a := senderFixture(t, 2)
	set := func(r0, r1 float64) (time.Duration, time.Duration) {
		for i, rtt := range []float64{r0, r1} {
			p := f.r.paths[pk(a[i])]
			p.rtt, p.hasRTT, p.ready = rtt, true, true
		}
		f.r.updateReorderBudget()
		return f.r.reorder.config.Timeout, f.r.reorder.config.UDPTimeout
	}
	closeTCP, closeUDP := set(.050, .053)
	farTCP, farUDP := set(.050, .200)
	if farTCP <= closeTCP || farUDP <= closeUDP {
		t.Fatalf("timeouts did not widen with the gap: tcp %v->%v udp %v->%v", closeTCP, farTCP, closeUDP, farUDP)
	}
	if closeUDP > closeTCP {
		t.Fatalf("UDP waits longer than TCP: %v > %v", closeUDP, closeTCP)
	}
}
