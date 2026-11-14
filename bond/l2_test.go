package bond

import (
	"testing"
	"time"
)

func mac(b byte) [6]byte { return [6]byte{0x02, 0, 0, 0, 0, b} }

func eth(dst, src [6]byte, etherType uint16, body []byte) []byte {
	f := append([]byte{}, dst[:]...)
	f = append(f, src[:]...)
	f = append(f, byte(etherType>>8), byte(etherType))
	return append(f, body...)
}

var bcast = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	f := eth(mac(1), mac(2), etherARP, make([]byte, 28))
	p := WrapFrame(f)
	if !IsL2(p) || p[0] == 0x45 {
		t.Fatalf("payload not marked as L2")
	}
	got, ok := UnwrapFrame(p)
	if !ok || string(got) != string(f) {
		t.Fatalf("round trip mismatch")
	}
	if _, ok := UnwrapFrame([]byte{0x45, 0, 0}); ok {
		t.Fatalf("IPv4 payload taken for L2")
	}
}

func TestParseFrameKinds(t *testing.T) {
	arp, err := ParseFrame(eth(bcast, mac(2), etherARP, make([]byte, 28)))
	if err != nil || !arp.Control || !arp.Broadcast || !arp.Multicast {
		t.Fatalf("ARP: %+v %v", arp, err)
	}
	tagged := eth(mac(1), mac(2), etherVLAN, []byte{0x00, 0x2a, 0x08, 0x06})
	tagged = append(tagged, make([]byte, 28)...)
	v, err := ParseFrame(tagged)
	if err != nil || v.VLAN != 42 || v.EtherType != etherARP {
		t.Fatalf("VLAN: %+v %v", v, err)
	}
	if _, err := ParseFrame([]byte{1, 2, 3}); err == nil {
		t.Fatalf("short frame accepted")
	}
	stp, _ := ParseFrame(eth([6]byte{0x01, 0x80, 0xc2, 0, 0, 0}, mac(2), 0x0026, make([]byte, 20)))
	if !stp.Control {
		t.Fatalf("bridge-group frame not control")
	}
}

func TestSessionL2OffRefusesFrames(t *testing.T) {
	s := l2Session(t, false)
	_, ok := s.classify(WrapFrame(eth(mac(1), mac(2), etherARP, make([]byte, 28))), false, time.Now())
	if ok || s.stats.L2Refused != 1 {
		t.Fatalf("frame not refused: ok=%v stats=%+v", ok, s.stats)
	}
}

func TestSessionL2ClassifiesAndCountsOversize(t *testing.T) {
	s := l2Session(t, true)
	now := time.Now()
	c, ok := s.classify(WrapFrame(eth(bcast, mac(2), etherARP, make([]byte, 28))), false, now)
	if !ok || c.Tag != l2ControlTag || s.stats.L2Control != 1 {
		t.Fatalf("ARP not priority: %+v ok=%v", c, ok)
	}
	c, ok = s.classify(WrapFrame(eth(mac(1), mac(2), 0x88b5, make([]byte, 100))), false, now)
	if !ok || c.Reason != "l2_other" {
		t.Fatalf("other frame: %+v ok=%v", c, ok)
	}
	_, ok = s.classify(WrapFrame(eth(mac(1), mac(2), 0x88b5, make([]byte, 1600))), false, now)
	if ok || s.stats.L2Oversize != 1 {
		t.Fatalf("oversize not counted")
	}
}

func l2Session(t *testing.T, on bool) *Session {
	t.Helper()
	f := newReceiverFixture(t)
	options := DefaultSessionOptions()
	options.L2 = on
	s, err := NewSession(f.c.key[:], f.c.Session[:], options)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestSwitch(cfg L2SwitchConfig) *L2Switch {
	if cfg.Ports == nil {
		cfg.Ports = []L2PortConfig{{ID: 1, Name: "tunnel"}, {ID: 2, Name: "lan"}, {ID: 3, Name: "lan2"}}
	}
	return NewL2Switch(cfg)
}

func TestSwitchLearnsAndForwards(t *testing.T) {
	s := newTestSwitch(L2SwitchConfig{})
	now := time.Now()
	v := s.Forward(2, eth(mac(9), mac(2), 0x88b5, nil), now) // unknown destination floods
	if !v.Flooded || len(v.Out) != 2 || v.Out[0] != 1 || v.Out[1] != 3 {
		t.Fatalf("flood: %+v", v)
	}
	v = s.Forward(1, eth(mac(2), mac(9), 0x88b5, nil), now) // reply is known unicast to port 2
	if v.Flooded || len(v.Out) != 1 || v.Out[0] != 2 {
		t.Fatalf("unicast: %+v", v)
	}
	v = s.Forward(2, eth(mac(2), mac(7), 0x88b5, nil), now) // destination behind ingress port
	if v.Drop != L2DropFiltered {
		t.Fatalf("same-port: %+v", v)
	}
}

func TestSwitchMACLimit(t *testing.T) {
	s := newTestSwitch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2, MACLimit: 2}}})
	now := time.Now()
	for i := byte(1); i <= 2; i++ {
		if v := s.Forward(2, eth(mac(100), mac(i), 0x88b5, nil), now); v.Drop != L2Forward {
			t.Fatalf("mac %d: %+v", i, v)
		}
	}
	if v := s.Forward(2, eth(mac(100), mac(3), 0x88b5, nil), now); v.Drop != L2DropMACLimit {
		t.Fatalf("third MAC allowed: %+v", v)
	}
	if got := s.Sweep(now.Add(time.Hour)); got != 2 {
		t.Fatalf("sweep aged %d", got)
	}
	if v := s.Forward(2, eth(mac(100), mac(3), 0x88b5, nil), now.Add(time.Hour)); v.Drop != L2Forward {
		t.Fatalf("cap not released after aging: %+v", v)
	}
}

func TestSwitchLoopGuardHoldsOffendingPort(t *testing.T) {
	s := newTestSwitch(L2SwitchConfig{MoveLimit: 3, MoveWindow: 10 * time.Second, LoopHold: 30 * time.Second})
	now := time.Now()
	s.Forward(2, eth(mac(50), mac(7), 0x88b5, nil), now)
	var held bool
	for i := 0; i < 8; i++ {
		now = now.Add(100 * time.Millisecond)
		in := PortID(1 + i%2) // the same MAC keeps appearing on ports 1 and 2
		if s.Forward(in, eth(mac(50), mac(7), 0x88b5, nil), now).Drop == L2DropBlocked {
			held = true
		}
	}
	if !held || s.Stats().LoopHolds == 0 {
		t.Fatalf("loop not detected: %+v", s.Stats())
	}
	if v := s.Forward(1, eth(mac(50), mac(8), 0x88b5, nil), now.Add(time.Second)); v.Drop != L2DropBlocked {
		// whichever port was held must stay held for the hold time
		if v2 := s.Forward(2, eth(mac(50), mac(8), 0x88b5, nil), now.Add(time.Second)); v2.Drop != L2DropBlocked {
			t.Fatalf("no port held: %+v %+v", v, v2)
		}
	}
	if v := s.Forward(1, eth(mac(50), mac(8), 0x88b5, nil), now.Add(time.Minute)); v.Drop == L2DropBlocked {
		t.Fatalf("hold never released")
	}
}

func TestSwitchStormControl(t *testing.T) {
	s := newTestSwitch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2, BroadcastPPS: 10, UnknownUnicastPPS: 5}}})
	now := time.Now()
	pass, drop := 0, 0
	for i := 0; i < 100; i++ {
		if s.Forward(2, eth(bcast, mac(2), etherARP, make([]byte, 28)), now).Drop == L2DropStorm {
			drop++
		} else {
			pass++
		}
	}
	if pass != 10 || drop != 90 {
		t.Fatalf("broadcast bucket: pass=%d drop=%d", pass, drop)
	}
	// Tokens refill with time.
	if s.Forward(2, eth(bcast, mac(2), etherARP, make([]byte, 28)), now.Add(time.Second)).Drop == L2DropStorm {
		t.Fatalf("bucket never refilled")
	}
	// Known unicast is not limited by the unknown-unicast bucket.
	s.Forward(1, eth(mac(2), mac(9), 0x88b5, nil), now)
	for i := 0; i < 50; i++ {
		if s.Forward(1, eth(mac(2), mac(9), 0x88b5, nil), now).Drop != L2Forward {
			t.Fatalf("known unicast dropped")
		}
	}
}

func TestSwitchIsolation(t *testing.T) {
	s := newTestSwitch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2, Isolated: true}, {ID: 3, Isolated: true}}})
	now := time.Now()
	s.Forward(3, eth(bcast, mac(3), etherARP, make([]byte, 28)), now)
	v := s.Forward(2, eth(mac(3), mac(2), 0x88b5, nil), now)
	if v.Drop != L2DropIsolated {
		t.Fatalf("isolated ports talked: %+v", v)
	}
	v = s.Forward(2, eth(bcast, mac(2), etherARP, make([]byte, 28)), now)
	if len(v.Out) != 1 || v.Out[0] != 1 {
		t.Fatalf("broadcast must reach only the uplink: %+v", v)
	}
}

func TestSwitchRejectsGroupSourceAndMalformed(t *testing.T) {
	s := newTestSwitch(L2SwitchConfig{})
	if v := s.Forward(2, eth(mac(1), bcast, 0x88b5, nil), time.Now()); v.Drop != L2DropMalform {
		t.Fatalf("group source accepted")
	}
	if v := s.Forward(2, []byte{1, 2}, time.Now()); v.Drop != L2DropMalform {
		t.Fatalf("short frame accepted")
	}
	if v := s.Forward(9, eth(mac(1), mac(2), 0x88b5, nil), time.Now()); v.Drop != L2DropNoPort {
		t.Fatalf("unknown port accepted")
	}
}
