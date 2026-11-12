package bond

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

type receiverFixture struct {
	r        *Receiver
	c        *Codec
	now      time.Time
	endpoint netip.AddrPort
}

func newReceiverFixture(t *testing.T) receiverFixture {
	t.Helper()
	key := bytes.Repeat([]byte{4}, 32)
	session := bytes.Repeat([]byte{5}, 16)
	c, _ := NewCodec(key, session, "client")
	server, _ := NewCodec(key, session, "server")
	r, _ := NewReceiver(server, 1400)
	return receiverFixture{r, c, time.Now(), netip.MustParseAddrPort("127.0.0.1:1234")}
}
func (f receiverFixture) receive(t *testing.T, kind byte, payload []byte, endpoint netip.AddrPort) ReceiveResult {
	t.Helper()
	frame, err := f.c.Encode(kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.r.Receive(frame, endpoint, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func (f receiverFixture) connect(t *testing.T, endpoint netip.AddrPort) {
	t.Helper()
	hello := f.receive(t, Hello, bytes.Repeat([]byte{9}, 16), endpoint)
	if len(hello.Send) != 1 {
		t.Fatal("missing challenge")
	}
	challenge, err := f.c.Decode(hello.Send[0].Frame)
	if err != nil || challenge.Header.Kind != Challenge {
		t.Fatal("bad challenge", err)
	}
	ready := f.receive(t, Reset, challenge.Payload, endpoint)
	if len(ready.Send) != 1 {
		t.Fatal("missing ready")
	}
	packet, err := f.c.Decode(ready.Send[0].Frame)
	if err != nil || packet.Header.Kind != Ready {
		t.Fatal("bad ready", err)
	}
}
func stripe(flow, sequence, epoch uint64, payload []byte) []byte {
	p := make([]byte, 24+len(payload))
	binary.BigEndian.PutUint64(p, flow)
	binary.BigEndian.PutUint64(p[8:], sequence)
	binary.BigEndian.PutUint64(p[16:], epoch)
	copy(p[24:], payload)
	return p
}
func probe(epoch uint64) []byte {
	p := bytes.Repeat([]byte{7}, 24)
	binary.BigEndian.PutUint64(p, epoch)
	return p
}
func TestReceiverTwoPathsFeedbackAndNoDuplicateHealthCredit(t *testing.T) {
	f := newReceiverFixture(t)
	other := netip.MustParseAddrPort("127.0.0.1:1235")
	f.connect(t, f.endpoint)
	f.connect(t, other)
	if f.r.ReadyPaths(f.now) != 2 {
		t.Fatal("parallel handshake lost a path")
	}
	f.receive(t, Probe, probe(1), f.endpoint)
	f.receive(t, Probe, probe(2), other)
	out := f.receive(t, Striped, stripe(1, 1, 2, []byte("b")), other)
	if len(out.Deliver) != 0 {
		t.Fatal("early reordered packet")
	}
	out = f.receive(t, Striped, stripe(1, 0, 1, []byte("a")), f.endpoint)
	if len(out.Deliver) != 2 || string(out.Deliver[0])+string(out.Deliver[1]) != "ab" {
		t.Fatal("multipath flow reassembly failed")
	}
	feedback, err := f.r.Tick(f.now.Add(21 * time.Millisecond))
	if err != nil || len(feedback.Send) != 2 {
		t.Fatal("feedback missing", err)
	}
	for _, d := range feedback.Send {
		p, err := f.c.Decode(d.Frame)
		if err != nil || p.Header.Kind != Feedback || binary.BigEndian.Uint64(p.Payload[16:]) != uint64(Overhead+25) {
			t.Fatal("wrong cumulative path feedback", err)
		}
		f.r.Sent(d, nil)
	}
	frame, _ := f.c.Encode(Data, []byte("urgent"))
	first, _ := f.r.Receive(frame, f.endpoint, f.now)
	second, _ := f.r.Receive(frame, other, f.now.Add(2*time.Second))
	if len(first.Deliver) != 1 || len(second.Deliver) != 0 || f.r.Stats().Duplicates != 1 {
		t.Fatal("duplicate payload escaped")
	}
	if f.r.ReadyPaths(f.now.Add(3100*time.Millisecond)) != 0 {
		t.Fatal("duplicate kept a path healthy")
	}
	if f.r.Stats().WireTX == 0 {
		t.Fatal("successful writes not metered")
	}
}
func TestReceiverNATMigrationRequiresKnownEpochAndNewSequence(t *testing.T) {
	f := newReceiverFixture(t)
	f.connect(t, f.endpoint)
	f.receive(t, Probe, probe(1), f.endpoint)
	old, _ := f.c.Encode(Probe, probe(1))
	f.receive(t, Probe, probe(1), f.endpoint)
	changed := netip.MustParseAddrPort("127.0.0.1:4567")
	f.receive(t, Probe, probe(999), changed)
	if f.r.Stats().PathMigrations != 0 {
		t.Fatal("unknown epoch moved path")
	}
	f.r.Receive(old, changed, f.now)
	if f.r.Stats().PathMigrations != 0 {
		t.Fatal("old sequence moved path")
	}
	f.receive(t, Probe, probe(1), changed)
	if f.r.Stats().PathMigrations != 1 || f.r.paths[pk(f.endpoint)] != nil || f.r.paths[pk(changed)] == nil {
		t.Fatal("fresh authenticated NAT migration failed")
	}
}
func TestReceiverTamperPreHandshakeAndRestartIsolation(t *testing.T) {
	f := newReceiverFixture(t)
	f.receive(t, Data, []byte("before"), f.endpoint)
	if f.r.Stats().PayloadPackets != 0 {
		t.Fatal("pre-handshake data accepted")
	}
	f.connect(t, f.endpoint)
	old, _ := f.c.Encode(Data, []byte("old"))
	tampered := append([]byte(nil), old...)
	tampered[len(tampered)-1] ^= 1
	f.r.Receive(tampered, f.endpoint, f.now)
	if f.r.Stats().AuthenticationErrors != 1 {
		t.Fatal("tamper not rejected")
	}
	if out, _ := f.r.Receive(old, f.endpoint, f.now); len(out.Deliver) != 1 {
		t.Fatal("tamper advanced replay state")
	}
	f.receive(t, Striped, stripe(1, 1, 1, []byte("old buffered")), f.endpoint)
	newClient, _ := NewCodec(f.c.key[:], f.c.Session[:], "client")
	f.c = newClient
	f.connect(t, f.endpoint)
	if out, _ := f.r.Receive(old, f.endpoint, f.now); len(out.Deliver) != 0 {
		t.Fatal("old domain accepted after restart")
	}
	if out, _ := f.r.Tick(f.now.Add(time.Second)); len(out.Deliver) != 0 {
		t.Fatal("old reordered data leaked into new session")
	}
	if f.r.ReorderStats().BufferedPackets != 0 {
		t.Fatal("restart did not reset reorder state")
	}
}
