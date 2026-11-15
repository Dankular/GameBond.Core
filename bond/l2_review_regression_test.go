package bond

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestMalformedIGMPDoesNotSuppressIPv4Classification(t *testing.T) {
	ip := make([]byte, 28)
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{239, 1, 2, 3})
	ip[20] = 0x22 // IGMPv3 report claiming one truncated group record.
	ip[27] = 1
	info, err := ParseFrame(eth(ipv4MulticastMAC([4]byte{239, 1, 2, 3}), mac(1), etherIPv4, ip))
	if err != nil || info.IP == nil || info.IPv4SourceIP.String() != "10.0.0.1" || info.MulticastIPLen != 4 || !info.Control || !info.MulticastRecordsMalformed {
		t.Fatalf("malformed IGMP damaged valid IPv4 classification: info=%+v err=%v", info, err)
	}
}

func TestOrdinarySwitchTransparentlyForwardsEAPOL(t *testing.T) {
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2}, {ID: 3, Monitor: true}}})
	frame := eth([6]byte{1, 0x80, 0xc2, 0, 0, 3}, mac(1), etherEAPOL, []byte{2, 1, 0, 0})
	v := s.Forward(1, frame, time.Unix(100, 0))
	if v.Drop != L2Forward || !hasPort(v.Out, 2) {
		t.Fatalf("ordinary EAPOL did not bridge transparently: %+v", v)
	}
}

func TestMVRRetagsTrunkReceiverToReceiverVLAN(t *testing.T) {
	group := [4]byte{239, 3, 3, 3}
	config := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	s := NewL2Switch(L2SwitchConfig{MVR: &config, Ports: []L2PortConfig{
		{ID: 1, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{100}}, MulticastRouter: true},
		{ID: 2, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10}}},
		{ID: 3, VLAN: L2VLANPolicy{AccessVLAN: 10}},
	}})
	now := time.Unix(100, 0)
	s.Forward(3, igmpReportFrame(mac(3), group, 0x16), now)
	frame := insertVLANTag(ipv4MulticastFrame(mac(1), group), 100, FrameInfo{})
	v := s.Forward(1, frame, now.Add(time.Second))
	if v.Drop != L2Forward || !hasPort(v.Out, 2) {
		t.Fatalf("MVR trunk receiver missing: %+v", v)
	}
	out, err := ParseFrame(v.FrameFor(2, frame))
	if err != nil || out.VLAN != 10 || out.VLANDepth != 1 {
		t.Fatalf("MVR trunk carried source VLAN: info=%+v err=%v frame=%x", out, err, v.FrameFor(2, frame))
	}
}

func TestNewL2SwitchCheckedRejectsInvalidRSTPTimers(t *testing.T) {
	_, err := NewL2SwitchChecked(L2SwitchConfig{RSTPEnabled: true, RSTPHelloTime: 300 * time.Second, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	if err == nil {
		t.Fatal("invalid RSTP timer was accepted")
	}
}

func TestNewL2SwitchCheckedSupportsBrokerPortsAttachedAfterConstruction(t *testing.T) {
	mvr := &L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	if _, err := NewL2SwitchChecked(L2SwitchConfig{DynamicPorts: true, MVR: mvr}); err != nil {
		t.Fatalf("dynamic-port broker rejected valid MVR settings before attachments: %v", err)
	}
	if err := (L2SwitchConfig{MVR: mvr}).Validate(); err == nil {
		t.Fatal("static switch validation accepted MVR without source/receiver ports")
	}
}

func TestRemovePortAtUsesSimulationClock(t *testing.T) {
	start := time.Unix(100, 0)
	s := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}, {ID: 2, RSTPParticipant: true}}})
	s.Forward(1, eth(bcast, mac(1), 0x88b5, nil), start)
	if !s.RemovePortAt(1, start.Add(time.Second)) {
		t.Fatal("simulated port removal failed")
	}
	if role, _ := s.RSTPPortState(2); role != RSTPRoleDesignated {
		t.Fatalf("remaining simulated port has unexpected role %v", role)
	}
}

func TestKnownUnicastIsolationDropCounterMatchesVerdict(t *testing.T) {
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1, Isolated: true}, {ID: 2, Isolated: true}}})
	now := time.Unix(100, 0)
	s.Forward(2, eth(bcast, mac(2), 0x88b5, nil), now)
	v := s.Forward(1, eth(mac(2), mac(1), 0x88b5, nil), now)
	if v.Drop != L2DropIsolated {
		t.Fatalf("expected isolation verdict, got %+v", v)
	}
	stats := s.Stats()
	if stats.DropIsolated != 2 || stats.DropOther != 0 {
		t.Fatalf("drop counters disagree with isolation verdict: %+v", stats)
	}
}

func TestIPv6SourceGuardChecksNeighborAdvertisementTargetThroughExtensionHeader(t *testing.T) {
	guardedMAC, rogueMAC := mac(41), mac(42)
	target := netip.MustParseAddr("2001:db8::41")
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 10}},
	}})
	if err := s.SetPortSourceBindings(1, []L2SourceBinding{{VLAN: 10, IP: target, MAC: guardedMAC}}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if v := s.Forward(1, ipv6NeighborAdvertisement(guardedMAC, target), now); v.Drop != L2Forward {
		t.Fatalf("authorized NA target rejected: %+v", v)
	}
	if v := s.Forward(1, ipv6NeighborAdvertisement(rogueMAC, target), now); v.Drop != L2DropSourceGuard {
		t.Fatalf("forged NA target accepted through extension header: %+v", v)
	}
}

func TestStaticSourceBindingsSurviveDHCPBindingRefresh(t *testing.T) {
	staticIP, dhcpIP := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
	staticMAC, dhcpMAC := mac(51), mac(52)
	s, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{{
		ID: 1, IPv4SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10},
		StaticSourceBindings: []L2SourceBinding{{VLAN: 10, IP: staticIP, MAC: staticMAC}},
	}, {ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 10}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPortSourceBindings(1, []L2SourceBinding{{VLAN: 10, IP: dhcpIP, MAC: dhcpMAC}}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if v := s.Forward(1, sourceGuardIPv4(staticMAC, [4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 1}, 1234, 80), now); v.Drop != L2Forward {
		t.Fatalf("static binding disappeared during lease refresh: %+v", v)
	}
	if v := s.Forward(1, sourceGuardIPv4(dhcpMAC, [4]byte{192, 0, 2, 11}, [4]byte{192, 0, 2, 1}, 1234, 80), now); v.Drop != L2Forward {
		t.Fatalf("DHCP binding was not added alongside static binding: %+v", v)
	}
}

func ipv6NeighborAdvertisement(sourceMAC [6]byte, target netip.Addr) []byte {
	const (
		etherIPv6HopByHop = 0
		icmpv6NA          = 136
	)
	packet := make([]byte, 40+8+24+8)
	packet[0], packet[6], packet[7] = 0x60, etherIPv6HopByHop, 255
	binary.BigEndian.PutUint16(packet[4:6], 40)
	copy(packet[8:24], netip.MustParseAddr("fe80::1").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("ff02::1").AsSlice())
	packet[40], packet[41] = 58, 0
	packet[48] = icmpv6NA
	copy(packet[56:72], target.AsSlice())
	packet[72], packet[73] = 2, 1 // Target Link-Layer Address option.
	copy(packet[74:80], sourceMAC[:])
	packet[50], packet[51] = 0, 0
	binary.BigEndian.PutUint16(packet[50:52], ipv6ICMPChecksum(packet[8:24], packet[24:40], packet[48:]))
	return eth([6]byte{0x33, 0x33, 0, 0, 0, 1}, sourceMAC, etherIPv6, packet)
}
