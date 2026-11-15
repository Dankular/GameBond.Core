package bond

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
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

func qinqFrame(dst, src [6]byte, service, customer uint16, etherType uint16, body []byte) []byte {
	f := append([]byte{}, dst[:]...)
	f = append(f, src[:]...)
	f = append(f, 0x88, 0xa8, byte(service>>8), byte(service), 0x81, 0x00, byte(customer>>8), byte(customer))
	f = append(f, byte(etherType>>8), byte(etherType))
	return append(f, body...)
}

func TestQinQCompositeVLANLearningFloodingAndEgressRewrite(t *testing.T) {
	now := time.Now()
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, VLAN: L2VLANPolicy{ServiceVLAN: 10, CustomerVLAN: 20}},
		{ID: 2, VLAN: L2VLANPolicy{ServiceVLAN: 10, AllowedCustomerVLANs: []uint16{20, 30}}},
		{ID: 3, VLAN: L2VLANPolicy{ServiceVLAN: 10, CustomerVLAN: 30}},
		{ID: 4, VLAN: L2VLANPolicy{ServiceVLAN: 11, CustomerVLAN: 20}},
		{ID: 5, VLAN: L2VLANPolicy{ServiceVLAN: 11, AllowedCustomerVLANs: []uint16{20}}},
	}})
	clientA, clientB := mac(71), mac(72)
	v := s.Forward(1, eth(bcast, clientA, 0x88b5, []byte{1}), now)
	if v.Drop != L2Forward || len(v.Out) != 1 || !hasPort(v.Out, 2) || hasPort(v.Out, 3) || hasPort(v.Out, 4) || hasPort(v.Out, 5) {
		t.Fatalf("customer VLAN leaked across composite domains: %+v", v)
	}
	tagged := v.OutFrames[2]
	info, err := ParseFrame(tagged)
	if err != nil || info.VLANDepth != 2 || info.VLAN != 10 || info.InnerVLAN != 20 || binary.BigEndian.Uint16(tagged[12:14]) != etherVLANService {
		t.Fatalf("Q-in-Q trunk egress tags = %+v, err=%v, frame=%x", info, err, tagged)
	}
	// An independently learned MAC on S-VLAN 11/C-VLAN 20 stays isolated even
	// though the customer VID is identical.
	s.Forward(4, eth(mac(1), clientB, 0x88b5, nil), now)
	v = s.Forward(2, qinqFrame(bcast, mac(73), 10, 20, 0x88b5, nil), now)
	if !hasPort(v.Out, 1) || hasPort(v.Out, 3) || hasPort(v.Out, 4) || hasPort(v.Out, 5) {
		t.Fatalf("stacked-tag ingress was not scoped to S10/C20: %+v", v)
	}
	if got := v.OutFrames[1]; len(got) < 14 || binary.BigEndian.Uint16(got[12:14]) != 0x88b5 {
		t.Fatalf("Q-in-Q customer access egress did not strip both tags: %x", got)
	}
	// Known unicast learned from the access side returns through the Q-in-Q
	// trunk with the same composite identity.
	v = s.Forward(2, qinqFrame(clientA, mac(74), 10, 20, 0x88b5, nil), now)
	if len(v.Out) != 1 || v.Out[0] != 1 || len(v.OutFrames[1]) < 14 || binary.BigEndian.Uint16(v.OutFrames[1][12:14]) != 0x88b5 {
		t.Fatalf("known unicast Q-in-Q egress rewrite failed: %+v", v)
	}
}

func TestQinQPolicyRejectsMalformedAndStackedIngressOnOrdinaryTrunk(t *testing.T) {
	if err := (L2VLANPolicy{ServiceVLAN: 10}).Validate(); err == nil {
		t.Fatal("Q-in-Q trunk without customer policy was accepted")
	}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10}}}}})
	if v := s.Forward(1, qinqFrame(bcast, mac(75), 10, 20, 0x88b5, nil), time.Now()); v.Drop != L2DropVLAN {
		t.Fatalf("ordinary trunk accepted stacked tags: %+v", v)
	}
	qinq := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1, VLAN: L2VLANPolicy{ServiceVLAN: 10, AllowedCustomerVLANs: []uint16{20}}}}})
	wrongTPID := qinqFrame(bcast, mac(76), 10, 20, 0x88b5, nil)
	wrongTPID[12], wrongTPID[13] = 0x81, 0x00
	if v := qinq.Forward(1, wrongTPID, time.Now()); v.Drop != L2DropVLAN {
		t.Fatalf("Q-in-Q trunk accepted a non-service outer TPID: %+v", v)
	}
}

func TestVLANPolicyEgressTagOverhead(t *testing.T) {
	for _, test := range []struct {
		name   string
		policy L2VLANPolicy
		want   int
	}{
		{name: "access", policy: L2VLANPolicy{AccessVLAN: 10}, want: 0},
		{name: "single tag trunk", policy: L2VLANPolicy{AllowedVLANs: []uint16{10}}, want: 4},
		{name: "qinq customer access", policy: L2VLANPolicy{ServiceVLAN: 100, CustomerVLAN: 10}, want: 0},
		{name: "qinq service trunk", policy: L2VLANPolicy{ServiceVLAN: 100, AllowedCustomerVLANs: []uint16{10}}, want: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.policy.EgressTagOverhead(); got != test.want {
				t.Fatalf("EgressTagOverhead()=%d, want %d", got, test.want)
			}
		})
	}
}

func TestQinQMulticastMembershipUsesCompositeVLAN(t *testing.T) {
	now := time.Now()
	trunk := L2VLANPolicy{ServiceVLAN: 10, AllowedCustomerVLANs: []uint16{20, 30}}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, VLAN: L2VLANPolicy{ServiceVLAN: 10, CustomerVLAN: 20}},
		{ID: 2, VLAN: L2VLANPolicy{ServiceVLAN: 10, CustomerVLAN: 30}},
		{ID: 3, VLAN: trunk, MulticastRouter: true},
	}})
	query := qinqFrame(mac(1), mac(3), 10, 20, etherIPv4, igmpQueryBody())
	s.Forward(3, query, now)
	group := [4]byte{239, 1, 1, 1}
	s.Forward(1, igmpReportFrame(mac(81), group, 0x16), now)
	s.Forward(2, igmpReportFrame(mac(82), group, 0x16), now)
	data := ipv4MulticastFrame(mac(83), group)
	v := s.Forward(3, qinqFrame(mac(1), mac(84), 10, 20, etherIPv4, data[14:]), now.Add(time.Second))
	if len(v.Out) != 1 || v.Out[0] != 1 {
		t.Fatalf("multicast crossed customer VLAN boundary or missed member: %+v", v)
	}
}

func igmpQueryBody() []byte {
	ip := make([]byte, 20+8)
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15] = 10, 1
	ip[16], ip[17], ip[18], ip[19] = 224, 0, 0, 1
	ip[20] = 0x11
	ip[25] = 1
	return ip
}

func sourceGuardARP(sourceMAC, ethernetMAC [6]byte, senderIP, targetIP [4]byte) []byte {
	body := make([]byte, 28)
	binary.BigEndian.PutUint16(body[0:2], 1)
	binary.BigEndian.PutUint16(body[2:4], etherIPv4)
	body[4], body[5] = 6, 4
	binary.BigEndian.PutUint16(body[6:8], 1)
	copy(body[8:14], sourceMAC[:])
	copy(body[14:18], senderIP[:])
	copy(body[24:28], targetIP[:])
	return eth(bcast, ethernetMAC, etherARP, body)
}

func sourceGuardIPv4(sourceMAC [6]byte, source, destination [4]byte, sourcePort, destinationPort uint16) []byte {
	ip := make([]byte, 28)
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	binary.BigEndian.PutUint16(ip[20:22], sourcePort)
	binary.BigEndian.PutUint16(ip[22:24], destinationPort)
	binary.BigEndian.PutUint16(ip[24:26], 8)
	return eth(bcast, sourceMAC, etherIPv4, ip)
}

func TestIPv4SourceGuardValidatesDHCPBindingAndARPIdentity(t *testing.T) {
	clientMAC, attackerMAC := mac(21), mac(22)
	clientIP := netip.MustParseAddr("10.0.0.21")
	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1, IPv4SourceGuard: true}, {ID: 2}}})
	if err := switcher.SetPortSourceBindings(1, []L2SourceBinding{{IP: clientIP, MAC: clientMAC}}); err != nil {
		t.Fatal(err)
	}
	src := [4]byte{10, 0, 0, 21}
	dst := [4]byte{10, 0, 0, 1}
	now := time.Now()
	if verdict := switcher.Forward(1, sourceGuardIPv4(clientMAC, src, dst, 1234, 80), now); verdict.Drop != L2Forward {
		t.Fatalf("bound IPv4 source rejected: %+v", verdict)
	}
	if verdict := switcher.Forward(1, sourceGuardIPv4(attackerMAC, src, dst, 1234, 80), now); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("spoofed IPv4 source accepted: %+v", verdict)
	}
	if verdict := switcher.Forward(1, sourceGuardARP(clientMAC, attackerMAC, src, dst), now); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("ARP Ethernet/SHA mismatch accepted: %+v", verdict)
	}
	if verdict := switcher.Forward(1, sourceGuardARP(clientMAC, clientMAC, src, dst), now); verdict.Drop != L2Forward {
		t.Fatalf("bound ARP sender rejected: %+v", verdict)
	}
	zero := [4]byte{}
	broadcast := [4]byte{255, 255, 255, 255}
	if verdict := switcher.Forward(1, sourceGuardIPv4(attackerMAC, zero, broadcast, 68, 67), now); verdict.Drop != L2Forward {
		t.Fatalf("DHCP discover before lease rejected: %+v", verdict)
	}
	if err := switcher.SetPortSourceBindings(1, nil); err != nil {
		t.Fatal(err)
	}
	if verdict := switcher.Forward(1, sourceGuardIPv4(clientMAC, src, dst, 1234, 80), now); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("traffic remained authorized after lease removal: %+v", verdict)
	}
	if got := switcher.Stats().DropSourceGuard; got != 3 {
		t.Fatalf("source guard drop count = %d, want 3", got)
	}
}

func TestControlPlanePolicerLimitsOnlyControlTrafficToGatewayEgress(t *testing.T) {
	now := time.Now()
	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "session-a"},
		{ID: 2, Name: "gateway", ControlPlane: true, ControlPlanePPS: 1},
		{ID: 3, Name: "session-b"},
	}})
	ar := eth(bcast, mac(31), etherARP, make([]byte, 28))
	first := switcher.Forward(1, ar, now)
	if !hasPort(first.Out, 2) || len(first.Policed) != 0 {
		t.Fatalf("first control frame was not delivered: %+v", first)
	}
	second := switcher.Forward(1, ar, now.Add(time.Millisecond))
	if !hasPort(second.Out, 3) || hasPort(second.Out, 2) || len(second.Policed) != 1 || second.Policed[0] != 2 || second.Drop != L2Forward {
		t.Fatalf("policing gateway egress also blocked peer delivery: %+v", second)
	}
	data := eth(bcast, mac(31), 0x88b5, nil)
	if verdict := switcher.Forward(1, data, now.Add(2*time.Millisecond)); !hasPort(verdict.Out, 2) || len(verdict.Policed) != 0 {
		t.Fatalf("ordinary data traffic was affected by CoPP: %+v", verdict)
	}
	if got := switcher.Stats().DropCoPP; got != 1 {
		t.Fatalf("CoPP drop count = %d, want 1", got)
	}
}

func TestControlPlanePolicerUsesIndependentProtocolBuckets(t *testing.T) {
	now := time.Now()
	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "session-a"},
		{ID: 2, Name: "gateway", ControlPlane: true, ControlPlaneRates: L2ControlPlaneRates{ARP: 1, DHCPv4: 1, BurstSeconds: 1}},
		{ID: 3, Name: "session-b"},
	}})
	arp := eth(bcast, mac(35), etherARP, make([]byte, 28))
	dhcp := sourceGuardIPv4(mac(35), [4]byte{169, 254, 0, 1}, [4]byte{255, 255, 255, 255}, 68, 67)
	arpInfo, err := ParseFrame(arp)
	if err != nil || arpInfo.ControlClass != L2ControlARP {
		t.Fatalf("ARP control class = %v, err=%v", arpInfo.ControlClass, err)
	}
	dhcpInfo, err := ParseFrame(dhcp)
	if err != nil || dhcpInfo.ControlClass != L2ControlDHCPv4 {
		t.Fatalf("DHCPv4 control class = %v, err=%v", dhcpInfo.ControlClass, err)
	}
	if verdict := switcher.Forward(1, arp, now); !hasPort(verdict.Out, 2) {
		t.Fatalf("first ARP did not reach gateway: %+v", verdict)
	}
	if verdict := switcher.Forward(1, arp, now.Add(time.Millisecond)); hasPort(verdict.Out, 2) || !hasPort(verdict.Out, 3) || !hasPort(verdict.Policed, 2) {
		t.Fatalf("exhausted ARP bucket blocked peer forwarding or failed to police gateway: %+v", verdict)
	}
	if verdict := switcher.Forward(1, dhcp, now.Add(2*time.Millisecond)); !hasPort(verdict.Out, 2) || len(verdict.Policed) != 0 {
		t.Fatalf("ARP exhaustion incorrectly starved independent DHCP bucket: %+v", verdict)
	}
	if got := switcher.Stats().DropCoPP; got != 1 {
		t.Fatalf("protocol-class CoPP drops = %d, want 1", got)
	}
}

func TestControlPlaneRatesValidateRangesAndEgressRole(t *testing.T) {
	for name, port := range map[string]L2PortConfig{
		"rates require control-plane port": {ID: 1, ControlPlaneRates: L2ControlPlaneRates{ARP: 10}},
		"reject NaN":                       {ID: 1, ControlPlane: true, ControlPlaneRates: L2ControlPlaneRates{DHCPv4: math.NaN()}},
		"reject infinite rate":             {ID: 1, ControlPlane: true, ControlPlaneRates: L2ControlPlaneRates{NeighborDiscovery: math.Inf(1)}},
		"reject burst without class":       {ID: 1, ControlPlane: true, ControlPlaneRates: L2ControlPlaneRates{BurstSeconds: 2}},
		"reject short burst":               {ID: 1, ControlPlane: true, ControlPlaneRates: L2ControlPlaneRates{ARP: 10, BurstSeconds: 0.5}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{port}})
			if err == nil {
				t.Fatal("invalid control-plane rates were accepted")
			}
		})
	}
}

func TestControlClassificationIncludesDHCPv6(t *testing.T) {
	ip := make([]byte, 48)
	ip[0], ip[6] = 0x60, 17
	binary.BigEndian.PutUint16(ip[4:6], 8)
	binary.BigEndian.PutUint16(ip[40:42], 546)
	binary.BigEndian.PutUint16(ip[42:44], 547)
	binary.BigEndian.PutUint16(ip[44:46], 8)
	info, err := ParseFrame(eth(bcast, mac(32), etherIPv6, ip))
	if err != nil || !info.Control || info.ControlClass != L2ControlDHCPv6 {
		t.Fatalf("DHCPv6 was not classified as DHCPv6 control traffic: %+v, %v", info, err)
	}
	binary.BigEndian.PutUint16(ip[40:42], 547)
	binary.BigEndian.PutUint16(ip[42:44], 546)
	info, err = ParseFrame(eth(bcast, mac(32), etherIPv6, ip))
	if err != nil || !info.Control || info.ControlClass != L2ControlDHCPv6 {
		t.Fatalf("DHCPv6 server reply was not classified as DHCPv6 control traffic: %+v, %v", info, err)
	}
}

func TestControlClassificationCoversLinkControlAndMulticastProtocols(t *testing.T) {
	for _, item := range []struct {
		name  string
		frame []byte
		class L2ControlClass
	}{
		{"LLDP", eth([6]byte{1, 0x80, 0xc2, 0, 0, 0x0e}, mac(33), etherLLDP, nil), L2ControlLLDP},
		{"EAPOL", eth(bcast, mac(33), etherEAPOL, nil), L2ControlEAPOL},
		{"IGMP", igmpQueryFrame(mac(33)), L2ControlMulticast},
		{"MLD", ipv6MLDQueryFrame(mac(33)), L2ControlMulticast},
		{"mDNS", sourceGuardIPv4(mac(33), [4]byte{169, 254, 1, 1}, [4]byte{224, 0, 0, 251}, 5353, 5353), L2ControlMDNS},
	} {
		t.Run(item.name, func(t *testing.T) {
			info, err := ParseFrame(item.frame)
			if err != nil || !info.Control || info.ControlClass != item.class {
				t.Fatalf("control classification = %v/%v, want %v: %+v", info.Control, info.ControlClass, item.class, err)
			}
		})
	}
}

func TestMalformedIPv4ControlTrafficStillUsesItsCoPPClass(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[9] = 2 // IGMP, despite the intentionally invalid IPv4 total length.
	binary.BigEndian.PutUint16(packet[2:4], 60)
	igmp := eth(bcast, mac(36), etherIPv4, packet)
	info, err := ParseFrame(igmp)
	if err != nil || !info.Control || info.ControlClass != L2ControlMulticast {
		t.Fatalf("malformed IGMP escaped control classification: control=%v class=%v err=%v", info.Control, info.ControlClass, err)
	}
	dhcpPacket := make([]byte, 24)
	dhcpPacket[0], dhcpPacket[9] = 0x45, 17
	binary.BigEndian.PutUint16(dhcpPacket[2:4], 60) // Invalid total length, but enough bytes to identify UDP ports.
	binary.BigEndian.PutUint16(dhcpPacket[20:22], 68)
	binary.BigEndian.PutUint16(dhcpPacket[22:24], 67)
	dhcp := eth(bcast, mac(37), etherIPv4, dhcpPacket)
	info, err = ParseFrame(dhcp)
	if err != nil || !info.Control || info.ControlClass != L2ControlDHCPv4 {
		t.Fatalf("malformed DHCPv4 escaped control classification: control=%v class=%v err=%v", info.Control, info.ControlClass, err)
	}

	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "session-a"},
		{ID: 2, Name: "gateway", ControlPlane: true, ControlPlaneRates: L2ControlPlaneRates{Multicast: 1, DHCPv4: 1, BurstSeconds: 1}},
		{ID: 3, Name: "session-b"},
	}})
	now := time.Now()
	if verdict := switcher.Forward(1, igmp, now); !hasPort(verdict.Out, 2) {
		t.Fatalf("first IGMP frame did not reach gateway: %+v", verdict)
	}
	verdict := switcher.Forward(1, igmp, now.Add(time.Millisecond))
	if hasPort(verdict.Out, 2) || !hasPort(verdict.Out, 3) || !hasPort(verdict.Policed, 2) {
		t.Fatalf("malformed IGMP bypassed CoPP or blocked peer forwarding: %+v", verdict)
	}
	if verdict := switcher.Forward(1, dhcp, now.Add(2*time.Millisecond)); !hasPort(verdict.Out, 2) {
		t.Fatalf("first DHCPv4 frame did not reach gateway: %+v", verdict)
	}
	verdict = switcher.Forward(1, dhcp, now.Add(3*time.Millisecond))
	if hasPort(verdict.Out, 2) || !hasPort(verdict.Out, 3) || !hasPort(verdict.Policed, 2) {
		t.Fatalf("malformed DHCPv4 bypassed CoPP or blocked peer forwarding: %+v", verdict)
	}
}

func TestIPv6SourceGuardUsesVLANScopedDHCPv6Bindings(t *testing.T) {
	guardedMAC, otherMAC := mac(41), mac(42)
	clientIP := netip.MustParseAddr("2001:db8:1::41")
	now := time.Now()
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1, IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}}, {ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 10}}}})
	if err := s.SetPortSourceBindings(1, []L2SourceBinding{{VLAN: 10, IP: clientIP, MAC: guardedMAC}}); err != nil {
		t.Fatal(err)
	}
	if v := s.Forward(1, ipv6SourceFrame(guardedMAC, clientIP), now); v.Drop != L2Forward {
		t.Fatalf("bound IPv6 source was blocked: %+v", v)
	}
	if v := s.Forward(1, ipv6SourceFrame(otherMAC, clientIP), now); v.Drop != L2DropSourceGuard {
		t.Fatalf("IPv6 source spoofed across MAC was accepted: %+v", v)
	}
	if v := s.Forward(1, ipv6SourceFrame(guardedMAC, netip.MustParseAddr("2001:db8:1::42")), now); v.Drop != L2DropSourceGuard {
		t.Fatalf("unbound IPv6 source was accepted: %+v", v)
	}
	if v := s.Forward(1, ipv6NeighborSolicitationFrame(guardedMAC, netip.MustParseAddr("fe80::41")), now); v.Drop != L2Forward {
		t.Fatalf("link-local IPv6 control identity was blocked: %+v", v)
	}
	if v := s.Forward(1, ipv6SourceFrame(guardedMAC, netip.MustParseAddr("fe80::41")), now); v.Drop != L2DropSourceGuard {
		t.Fatalf("unbound link-local application source was accepted: %+v", v)
	}
	if v := s.Forward(1, dhcpv6SolicitFrame(guardedMAC), now); v.Drop != L2Forward {
		t.Fatalf("initial DHCPv6 solicit from unspecified address was blocked: %+v", v)
	}
	if v := s.Forward(1, ipv6NeighborSolicitationFrame(guardedMAC, netip.IPv6Unspecified()), now); v.Drop != L2Forward {
		t.Fatalf("IPv6 duplicate-address detection was blocked: %+v", v)
	}
	malformedSolicit := dhcpv6SolicitFrame(guardedMAC)
	binary.BigEndian.PutUint16(malformedSolicit[14+44:14+46], 0)
	if v := s.Forward(1, malformedSolicit, now); v.Drop != L2DropSourceGuard {
		t.Fatalf("malformed DHCPv6 packet bypassed source guard: %+v", v)
	}
	if v := s.Forward(1, ipv6SourceFrame(guardedMAC, clientIP), now.Add(time.Second)); v.Drop != L2Forward {
		t.Fatalf("valid binding changed unexpectedly: %+v", v)
	}
	if got := s.Stats().DropSourceGuard; got != 4 {
		t.Fatalf("source guard drops = %d, want 4", got)
	}
}

func TestIPv6NeighborDiscoveryParserValidatesDADWireFields(t *testing.T) {
	sourceMAC := mac(61)
	frame := ipv6NeighborSolicitationFrame(sourceMAC, netip.IPv6Unspecified())
	info, err := ParseFrame(frame)
	if err != nil || !info.IPv6NDValid || info.IPv6NDType != 135 || !info.IPv6NDValidated || !info.IPv6NDChecksumValid || !info.IPv6NDCodeValid || !info.IPv6NDReservedValid || !info.IPv6NDHopLimitValid || !info.IPv6NDDestinationValid || !info.IPv6NDOptionsValid || !info.IPv6DADNeighborSolicit || info.IPv6NDSourceLinkLayerSet {
		t.Fatalf("valid DAD NS not fully validated: %+v err=%v", info, err)
	}

	badChecksum := append([]byte(nil), frame...)
	badChecksum[14+40+2] ^= 0x01
	if got, _ := ParseFrame(badChecksum); got.IPv6NDChecksumValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("bad-checksum DAD accepted: %+v", got)
	}
	badHop := append([]byte(nil), frame...)
	badHop[14+7] = 64
	if got, _ := ParseFrame(badHop); got.IPv6NDHopLimitValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("bad-hop-limit DAD accepted: %+v", got)
	}
	badCode := append([]byte(nil), frame...)
	badCode[14+40+1] = 1
	setIPv6ICMPChecksum(badCode)
	if got, _ := ParseFrame(badCode); got.IPv6NDCodeValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("nonzero ND code accepted: %+v", got)
	}
	badReserved := append([]byte(nil), frame...)
	badReserved[14+40+4] = 1
	setIPv6ICMPChecksum(badReserved)
	if got, _ := ParseFrame(badReserved); got.IPv6NDReservedValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("nonzero NS reserved field accepted: %+v", got)
	}
	badDestination := append([]byte(nil), frame...)
	copy(badDestination[14+24:14+40], netip.MustParseAddr("ff02::1").AsSlice())
	wrongMulticastMAC := ipv6MulticastMAC(netip.MustParseAddr("ff02::1"))
	copy(badDestination[:6], wrongMulticastMAC[:])
	setIPv6ICMPChecksum(badDestination)
	if got, _ := ParseFrame(badDestination); got.IPv6NDDestinationValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("DAD with wrong IPv6 destination accepted: %+v", got)
	}
	badEthernetDestination := append([]byte(nil), frame...)
	badEthernetDestination[0] ^= 1
	if got, _ := ParseFrame(badEthernetDestination); got.IPv6NDDestinationValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("DAD with mismatched Ethernet destination accepted: %+v", got)
	}

	withSLLAO := append(append([]byte(nil), frame...), make([]byte, 8)...)
	withSLLAO[14+4], withSLLAO[14+5] = 0, 32
	withSLLAO[14+40+24], withSLLAO[14+40+25] = 1, 1
	copy(withSLLAO[14+40+26:14+40+32], sourceMAC[:])
	setIPv6ICMPChecksum(withSLLAO)
	if got, _ := ParseFrame(withSLLAO); !got.IPv6NDOptionsValid || !got.IPv6NDSourceLinkLayerSet || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("DAD with forbidden SLLAO was not distinguished: %+v", got)
	}
	badOption := append(append([]byte(nil), frame...), make([]byte, 8)...)
	badOption[14+4], badOption[14+5] = 0, 32
	badOption[14+40+24], badOption[14+40+25] = 1, 0
	setIPv6ICMPChecksum(badOption)
	if got, _ := ParseFrame(badOption); got.IPv6NDOptionsValid || got.IPv6NDValidated || got.IPv6DADNeighborSolicit {
		t.Fatalf("zero-length ND option accepted: %+v", got)
	}
}

func TestIPv6NeighborDiscoveryParserExposesValidatedNALinkLayerOption(t *testing.T) {
	sourceMAC := mac(62)
	target := netip.MustParseAddr("2001:db8::62")
	destination := netip.MustParseAddr("ff02::1")
	ip := make([]byte, 40+32)
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:6], 32)
	ip[40] = 136
	copy(ip[8:24], target.AsSlice())
	copy(ip[24:40], destination.AsSlice())
	copy(ip[48:64], target.AsSlice())
	ip[64], ip[65] = 2, 1
	copy(ip[66:72], sourceMAC[:])
	frame := eth(ipv6MulticastMAC(destination), sourceMAC, etherIPv6, ip)
	setIPv6ICMPChecksum(frame)
	info, err := ParseFrame(frame)
	if err != nil || !info.IPv6NDValid || !info.IPv6NDValidated || info.ControlClass != L2ControlNeighborDiscovery || !info.IPv6NDChecksumValid || !info.IPv6NDCodeValid || !info.IPv6NDReservedValid || !info.IPv6NDHopLimitValid || !info.IPv6NDDestinationValid || !info.IPv6NDOptionsValid || !info.IPv6NDTargetLinkLayerSet || !info.IPv6NDLinkLayerMatchesEth {
		t.Fatalf("valid NA did not expose validated TLLAO: %+v err=%v", info, err)
	}
	frame[14+40+26] ^= 1 // Ethernet source is no longer the advertised target link-layer address.
	setIPv6ICMPChecksum(frame)
	if got, _ := ParseFrame(frame); !got.IPv6NDTargetLinkLayerSet || got.IPv6NDLinkLayerMatchesEth || got.IPv6NDValidated {
		t.Fatalf("mismatched NA TLLAO not exposed: %+v", got)
	}
}

func TestRouterAdvertisementParserValidatesPrefixLifetimes(t *testing.T) {
	frame := ipv6RouterAdvertisementFrame(mac(62), netip.MustParsePrefix("2001:db8::/64"), 30, 10)
	info, err := ParseFrame(frame)
	if err != nil || !info.RouterAdvertisement || !info.RouterAdvertisementValid || info.ControlClass != L2ControlRouterAdvertisement || len(info.IPv6PrefixAdvertisements) != 1 {
		t.Fatalf("valid RA PIO was not parsed: %+v err=%v", info, err)
	}
	advertisement := info.IPv6PrefixAdvertisements[0]
	if advertisement.Prefix != netip.MustParsePrefix("2001:db8::/64") || advertisement.ValidLifetime != 30 || advertisement.PreferredLifetime != 10 || !advertisement.Autonomous {
		t.Fatalf("RA PIO values differ: %+v", advertisement)
	}
	badChecksum := append([]byte(nil), frame...)
	badChecksum[14+40+2] ^= 1
	if got, _ := ParseFrame(badChecksum); got.RouterAdvertisementValid || len(got.IPv6PrefixAdvertisements) != 0 {
		t.Fatalf("RA with invalid checksum was trusted: %+v", got)
	}
	badPreferred := append([]byte(nil), frame...)
	binary.BigEndian.PutUint32(badPreferred[14+40+16+8:14+40+16+12], 31)
	setIPv6ICMPChecksum(badPreferred)
	if got, _ := ParseFrame(badPreferred); got.RouterAdvertisementValid || len(got.IPv6PrefixAdvertisements) != 0 {
		t.Fatalf("RA with preferred lifetime above valid lifetime was trusted: %+v", got)
	}
}

func TestSAVILearnsValidatedDADAndExpiresAfterIdleLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	target := netip.MustParseAddr("2001:db8::41")
	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{
		ID: 1, Name: "guarded", IPv6SourceGuard: true,
		VLAN:               L2VLANPolicy{AccessVLAN: 10},
		IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/64")}},
	}, {ID: 2, Name: "peer", VLAN: L2VLANPolicy{AccessVLAN: 10}}, {ID: 3, Name: "router", VLAN: L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true}}})
	ra := ipv6RouterAdvertisementFrame(mac(68), netip.MustParsePrefix("2001:db8::/64"), 3, 1)
	if verdict := switcher.Forward(3, ra, now); verdict.Drop != L2Forward {
		t.Fatalf("trusted RA was rejected: %+v", verdict)
	}
	station := mac(63)
	if verdict := switcher.Forward(1, ipv6NeighborSolicitationFrame(station, netip.IPv6Unspecified()), now); verdict.Drop != L2Forward {
		t.Fatalf("validated DAD was rejected: %+v", verdict)
	}
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), now.Add(saviDADWindow-time.Millisecond)); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("SLAAC source passed before DAD window elapsed: %+v", verdict)
	}
	switcher.Sweep(now.Add(saviDADWindow))
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), now.Add(2*saviDADWindow)); verdict.Drop != L2Forward {
		t.Fatalf("SLAAC source was not learned after conflict-free DAD: %+v", verdict)
	}
	// Activity cannot extend a claim past the trusted PIO valid lifetime.
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), now.Add(2500*time.Millisecond)); verdict.Drop != L2Forward {
		t.Fatalf("active SAVI claim expired before the PIO lifetime: %+v", verdict)
	}
	expiredAt := now.Add(3 * time.Second)
	switcher.Sweep(expiredAt)
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), expiredAt); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("idle SAVI claim survived its lifetime: %+v", verdict)
	}
}

func TestSAVIPreferredLifetimeDeprecatesWithoutRevokingBinding(t *testing.T) {
	now := time.Unix(1_800_050_000, 0)
	station, target := mac(74), netip.MustParseAddr("2001:db8::41")
	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "guarded", IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}, IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
		{ID: 2, Name: "router", VLAN: L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true},
	}})
	if verdict := switcher.Forward(2, ipv6RouterAdvertisementFrame(mac(75), netip.MustParsePrefix("2001:db8::/64"), 30, 1), now); verdict.Drop != L2Forward {
		t.Fatalf("trusted RA was rejected: %+v", verdict)
	}
	if verdict := switcher.Forward(1, ipv6NeighborSolicitationFrame(station, netip.IPv6Unspecified()), now); verdict.Drop != L2Forward {
		t.Fatalf("validated DAD was rejected: %+v", verdict)
	}
	switcher.Sweep(now.Add(saviDADWindow))
	deprecatedAt := now.Add(2 * time.Second)
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), deprecatedAt); verdict.Drop != L2Forward {
		t.Fatalf("deprecated SLAAC address was revoked at preferred lifetime: %+v", verdict)
	}
	validUntil := now.Add(30 * time.Second)
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), validUntil.Add(-time.Millisecond)); verdict.Drop != L2Forward {
		t.Fatalf("deprecated SLAAC address was revoked before valid lifetime: %+v", verdict)
	}
	switcher.Sweep(validUntil)
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), validUntil); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("SLAAC source remained authorized after valid lifetime: %+v", verdict)
	}
}

func TestSAVIConflictingDADQuarantinesTargetAndDetachClearsClaim(t *testing.T) {
	now := time.Unix(1_800_100_000, 0)
	ports := []L2PortConfig{
		{ID: 1, Name: "first", IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}, IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
		{ID: 2, Name: "second", IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}, IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
		{ID: 3, Name: "peer", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 4, Name: "router", VLAN: L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true},
	}
	switcher := NewL2Switch(L2SwitchConfig{Ports: ports})
	if verdict := switcher.Forward(4, ipv6RouterAdvertisementFrame(mac(69), netip.MustParsePrefix("2001:db8::/64"), 30, 10), now); verdict.Drop != L2Forward {
		t.Fatalf("trusted RA was rejected: %+v", verdict)
	}
	firstMAC, secondMAC := mac(64), mac(65)
	if verdict := switcher.Forward(1, ipv6NeighborSolicitationFrame(firstMAC, netip.IPv6Unspecified()), now); verdict.Drop != L2Forward {
		t.Fatalf("first DAD claim was rejected: %+v", verdict)
	}
	if verdict := switcher.Forward(2, ipv6NeighborSolicitationFrame(secondMAC, netip.IPv6Unspecified()), now.Add(saviDADWindow/2)); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("conflicting DAD claim was accepted: %+v", verdict)
	}
	if verdict := switcher.Forward(1, ipv6NeighborSolicitationFrame(firstMAC, netip.IPv6Unspecified()), now.Add(saviDADWindow)); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("claim escaped conflict quarantine: %+v", verdict)
	}
	if !switcher.RemovePortAt(1, now.Add(2*saviDADWindow)) {
		t.Fatal("failed to detach original claimant")
	}
	if verdict := switcher.Forward(2, ipv6NeighborSolicitationFrame(secondMAC, netip.IPv6Unspecified()), now.Add(3*saviDADWindow)); verdict.Drop != L2Forward {
		t.Fatalf("new port could not claim address after detach: %+v", verdict)
	}
}

func TestSAVIRouterAdvertisementWithdrawalRevokesClaimImmediately(t *testing.T) {
	now := time.Unix(1_800_150_000, 0)
	target, station := netip.MustParseAddr("2001:db8::41"), mac(70)
	switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "guarded", IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}, IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
		{ID: 2, Name: "peer", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 3, Name: "router", VLAN: L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true},
	}})
	if verdict := switcher.Forward(3, ipv6RouterAdvertisementFrame(mac(71), netip.MustParsePrefix("2001:db8::/64"), 30, 10), now); verdict.Drop != L2Forward {
		t.Fatalf("trusted RA was rejected: %+v", verdict)
	}
	if verdict := switcher.Forward(1, ipv6NeighborSolicitationFrame(station, netip.IPv6Unspecified()), now); verdict.Drop != L2Forward {
		t.Fatalf("validated DAD was rejected: %+v", verdict)
	}
	switcher.Sweep(now.Add(saviDADWindow))
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), now.Add(2*saviDADWindow)); verdict.Drop != L2Forward {
		t.Fatalf("learned source was not authorized: %+v", verdict)
	}
	withdrawal := ipv6RouterAdvertisementFrame(mac(71), netip.MustParsePrefix("2001:db8::/64"), 0, 0)
	if verdict := switcher.Forward(3, withdrawal, now.Add(3*saviDADWindow)); verdict.Drop != L2Forward {
		t.Fatalf("RA withdrawal was rejected: %+v", verdict)
	}
	if verdict := switcher.Forward(1, ipv6SourceFrame(station, target), now.Add(4*saviDADWindow)); verdict.Drop != L2DropSourceGuard {
		t.Fatalf("withdrawn SLAAC source remained authorized: %+v", verdict)
	}
}

func TestSAVIDoesNotOverrideDHCPOrStaticBindings(t *testing.T) {
	now := time.Unix(1_800_200_000, 0)
	target, ownerMAC, otherMAC := netip.MustParseAddr("2001:db8::41"), mac(66), mac(67)
	for _, static := range []bool{false, true} {
		port := L2PortConfig{ID: 1, Name: "guarded", IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}, IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/64")}}}
		if static {
			port.StaticSourceBindings = []L2SourceBinding{{VLAN: 10, IP: target, MAC: ownerMAC}}
		}
		peer := L2PortConfig{ID: 2, Name: "peer", VLAN: L2VLANPolicy{AccessVLAN: 10}}
		switcher := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{port, peer}})
		if !static {
			if err := switcher.SetPortSourceBindings(1, []L2SourceBinding{{VLAN: 10, IP: target, MAC: ownerMAC}}); err != nil {
				t.Fatalf("install DHCP binding: %v", err)
			}
		}
		if verdict := switcher.Forward(1, ipv6NeighborSolicitationFrame(otherMAC, netip.IPv6Unspecified()), now); verdict.Drop != L2DropSourceGuard {
			t.Fatalf("SAVI replaced existing static=%v binding: %+v", static, verdict)
		}
		if verdict := switcher.Forward(1, ipv6SourceFrame(ownerMAC, target), now); verdict.Drop != L2Forward {
			t.Fatalf("SAVI conflict damaged existing static=%v binding: %+v", static, verdict)
		}
	}
}

func TestSAVIPrefixConfigurationRequiresGuardAndAdmittedCanonical64(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/64")
	valid := L2PortConfig{ID: 1, Name: "guarded", IPv6SourceGuard: true, VLAN: L2VLANPolicy{AccessVLAN: 10}, IPv6SourcePrefixes: []L2SourcePrefix{{VLAN: 10, Prefix: prefix}}}
	if _, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{valid}}); err != nil {
		t.Fatalf("valid SAVI prefix config rejected: %v", err)
	}
	withoutGuard := valid
	withoutGuard.IPv6SourceGuard = false
	if _, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{withoutGuard}}); err == nil {
		t.Fatal("SAVI prefix accepted without IPv6 source guard")
	}
	unadmitted := valid
	unadmitted.VLAN = L2VLANPolicy{AccessVLAN: 20}
	if _, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{unadmitted}}); err == nil {
		t.Fatal("SAVI prefix accepted on an unadmitted VLAN")
	}
	non64 := valid
	non64.IPv6SourcePrefixes = []L2SourcePrefix{{VLAN: 10, Prefix: netip.MustParsePrefix("2001:db8::/80")}}
	if _, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{non64}}); err == nil {
		t.Fatal("non-/64 SLAAC prefix accepted")
	}
}

func ipv6SourceFrame(sourceMAC [6]byte, source netip.Addr) []byte {
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 59, 64
	copy(ip[8:24], source.AsSlice())
	return eth(mac(50), sourceMAC, etherIPv6, ip)
}

func dhcpv6SolicitFrame(sourceMAC [6]byte) []byte {
	ip := make([]byte, 48)
	ip[0], ip[6], ip[7] = 0x60, 17, 1
	binary.BigEndian.PutUint16(ip[4:6], 8)
	binary.BigEndian.PutUint16(ip[40:42], 546)
	binary.BigEndian.PutUint16(ip[42:44], 547)
	binary.BigEndian.PutUint16(ip[44:46], 8)
	return eth(mac(50), sourceMAC, etherIPv6, ip)
}

func ipv6NeighborSolicitationFrame(sourceMAC [6]byte, source netip.Addr) []byte {
	target := netip.MustParseAddr("2001:db8::41")
	optionLen := 0
	if !source.IsUnspecified() {
		optionLen = 8
	}
	ip := make([]byte, 40+24+optionLen)
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(ip)-40))
	ip[40] = 135
	copy(ip[8:24], source.AsSlice())
	solicited := solicitedNodeAddress(target).As16()
	copy(ip[24:40], solicited[:])
	copy(ip[48:64], target.AsSlice())
	if optionLen > 0 {
		ip[64], ip[65] = 1, 1
		copy(ip[66:72], sourceMAC[:])
	}
	destinationMAC := ipv6MulticastMAC(netip.AddrFrom16(solicited))
	frame := eth(destinationMAC, sourceMAC, etherIPv6, ip)
	setIPv6ICMPChecksum(frame)
	return frame
}

func ipv6RouterAdvertisementFrame(sourceMAC [6]byte, prefix netip.Prefix, validLifetime, preferredLifetime uint32) []byte {
	ip := make([]byte, 40+16+32)
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:6], 48)
	copy(ip[8:24], netip.MustParseAddr("fe80::1").AsSlice())
	copy(ip[24:40], netip.MustParseAddr("ff02::1").AsSlice())
	ra := ip[40:]
	ra[0], ra[4], ra[16], ra[17], ra[18], ra[19] = 134, 64, 3, 4, byte(prefix.Bits()), 0xc0
	binary.BigEndian.PutUint16(ra[6:8], 1800)
	binary.BigEndian.PutUint32(ra[20:24], validLifetime)
	binary.BigEndian.PutUint32(ra[24:28], preferredLifetime)
	copy(ra[32:48], prefix.Masked().Addr().AsSlice())
	frame := eth([6]byte{0x33, 0x33, 0, 0, 0, 1}, sourceMAC, etherIPv6, ip)
	setIPv6ICMPChecksum(frame)
	return frame
}

func setIPv6ICMPChecksum(frame []byte) {
	ip := frame[14:]
	ip[42], ip[43] = 0, 0
	checksum := ipv6ICMPChecksum(ip[8:24], ip[24:40], ip[40:])
	binary.BigEndian.PutUint16(ip[42:44], checksum)
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

func TestRouterAdvertisementDetectionWalksExtensionsAndFailsClosed(t *testing.T) {
	for name, frame := range map[string][]byte{
		"direct":          routerAdvertisementFrame(false, false, false),
		"hop-by-hop":      routerAdvertisementFrame(true, false, false),
		"fragmented":      routerAdvertisementFrame(false, true, false),
		"malformed-chain": routerAdvertisementFrame(true, false, true),
	} {
		info, err := ParseFrame(frame)
		if err != nil {
			t.Fatalf("%s: ParseFrame: %v", name, err)
		}
		switch name {
		case "direct", "hop-by-hop":
			if !info.RouterAdvertisement || info.IPv6GuardUnsafe {
				t.Errorf("%s was not identified as an RA: %+v", name, info)
			}
		default:
			if info.RouterAdvertisement || !info.IPv6GuardUnsafe {
				t.Errorf("%s did not fail closed: %+v", name, info)
			}
		}
	}
}

func TestRAGuardBlocksOnlyOnConfiguredIngressPorts(t *testing.T) {
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "untrusted", RAGuard: true},
		{ID: 2, Name: "trusted-router"},
	}})
	now := time.Now()
	if verdict := s.Forward(1, routerAdvertisementFrame(true, false, false), now); verdict.Drop != L2DropRAGuard {
		t.Fatalf("guarded ingress forwarded rogue RA: %+v", verdict)
	}
	ordinary := make([]byte, 40)
	ordinary[0], ordinary[6] = 0x60, 59
	if verdict := s.Forward(1, eth(mac(2), mac(1), etherIPv6, ordinary), now); verdict.Drop != L2Forward {
		t.Fatalf("guard blocked ordinary IPv6 traffic: %+v", verdict)
	}
	if verdict := s.Forward(2, routerAdvertisementFrame(false, false, false), now); verdict.Drop != L2Forward {
		t.Fatalf("trusted router ingress RA was blocked: %+v", verdict)
	}
	if got := s.Stats().DropRAGuard; got != 1 {
		t.Fatalf("RA guard drop counter = %d, want 1", got)
	}
}

func routerAdvertisementFrame(extension, fragment, malformed bool) []byte {
	var payload []byte
	next := byte(58)
	if extension {
		ext := []byte{58, 0, 1, 0, 0, 0, 0, 0}
		if malformed {
			ext[1] = 10
		}
		payload = append(payload, ext...)
		next = 0
	}
	if fragment {
		payload = append(payload, []byte{58, 0, 0, 0, 0, 0, 0, 0}...)
		next = 44
	}
	icmp := make([]byte, 16)
	icmp[0] = 134
	payload = append(payload, icmp...)
	ip := make([]byte, 40+len(payload))
	ip[0], ip[6], ip[7] = 0x60, next, 255
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
	ip[8], ip[9] = 0xfe, 0x80
	ip[24], ip[25], ip[39] = 0xff, 0x02, 1
	copy(ip[40:], payload)
	return eth([6]byte{0x33, 0x33, 0, 0, 0, 1}, mac(1), etherIPv6, ip)
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

func TestMACAuthorizationAllowsOnlyEAPOLUntilAuthorized(t *testing.T) {
	client, gateway := mac(61), mac(62)
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "access", MACAuth: true, VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 2, Name: "authenticator", EAPOLAuthenticator: true, EAPOLAuthenticatorFor: "access", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 3, Name: "peer", VLAN: L2VLANPolicy{AccessVLAN: 10}},
	}})
	now := time.Now()
	eapolRequest := eth([6]byte{1, 0x80, 0xc2, 0, 0, 3}, client, etherEAPOL, []byte{2, 1, 0, 0})
	if v := s.Forward(1, eapolRequest, now); v.Drop != L2Forward || !hasPort(v.Out, 2) || hasPort(v.Out, 3) {
		t.Fatalf("unauthorized EAPOL escaped only to authenticator port: %+v", v)
	}
	if v := s.Forward(1, eth(bcast, client, etherARP, make([]byte, 28)), now); v.Drop != L2DropUnauthorized {
		t.Fatalf("unauthorized ARP was not gated: %+v", v)
	}
	if err := s.SetPortMACAuthorized(1, client, true); err != nil {
		t.Fatal(err)
	}
	if v := s.Forward(1, eth(bcast, client, etherARP, make([]byte, 28)), now); v.Drop != L2Forward || !hasPort(v.Out, 2) || !hasPort(v.Out, 3) {
		t.Fatalf("authorized client traffic was blocked: %+v", v)
	}
	response := eth(client, gateway, etherEAPOL, []byte{2, 0, 0, 0})
	if v := s.Forward(2, response, now); v.Drop != L2Forward || len(v.Out) != 1 || v.Out[0] != 1 {
		t.Fatalf("authenticator response did not return only to client: %+v", v)
	}
	if err := s.SetPortMACAuthorized(1, client, false); err != nil {
		t.Fatal(err)
	}
	if v := s.Forward(1, eth(mac(62), client, 0x88b5, nil), now); v.Drop != L2DropUnauthorized {
		t.Fatalf("revoked client traffic was not blocked: %+v", v)
	}
	if _, exists := s.fdb[fdbKey{vlan: vlanID{outer: 10}, mac: client}]; exists {
		t.Fatal("revocation left stale source MAC forwarding state")
	}
	if got := s.Stats().DropUnauthorized; got != 2 {
		t.Fatalf("unauthorized drop counter = %d, want 2", got)
	}
}

func TestMACAuthorizationEAPOLRoutesOnlyToPairedAuthenticator(t *testing.T) {
	clientA, clientB, authMACA, authMACB := mac(71), mac(72), mac(73), mac(74)
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "session-a", MACAuth: true, VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 2, Name: "session-b", MACAuth: true, VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 3, Name: "auth-a", EAPOLAuthenticator: true, EAPOLAuthenticatorFor: "session-a", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 4, Name: "auth-b", EAPOLAuthenticator: true, EAPOLAuthenticatorFor: "session-b", VLAN: L2VLANPolicy{AccessVLAN: 10}},
	}})
	now := time.Now()
	requestA := eth([6]byte{1, 0x80, 0xc2, 0, 0, 3}, clientA, etherEAPOL, []byte{2, 1, 0, 0})
	if v := s.Forward(1, requestA, now); v.Drop != L2Forward || len(v.Out) != 1 || v.Out[0] != 3 {
		t.Fatalf("session A EAPOL reached wrong authenticator TAP: %+v", v)
	}
	requestB := eth([6]byte{1, 0x80, 0xc2, 0, 0, 3}, clientB, etherEAPOL, []byte{2, 1, 0, 0})
	if v := s.Forward(2, requestB, now); v.Drop != L2Forward || len(v.Out) != 1 || v.Out[0] != 4 {
		t.Fatalf("session B EAPOL reached wrong authenticator TAP: %+v", v)
	}
	responseA := eth(clientA, authMACA, etherEAPOL, []byte{2, 0, 0, 0})
	if v := s.Forward(3, responseA, now); v.Drop != L2Forward || len(v.Out) != 1 || v.Out[0] != 1 {
		t.Fatalf("authenticator A response reached wrong session: %+v", v)
	}
	responseB := eth(clientB, authMACB, etherEAPOL, []byte{2, 0, 0, 0})
	if v := s.Forward(4, responseB, now); v.Drop != L2Forward || len(v.Out) != 1 || v.Out[0] != 2 {
		t.Fatalf("authenticator B response reached wrong session: %+v", v)
	}
}

func TestPrivateVLANRolesLimitBroadcastAndUnicastDomains(t *testing.T) {
	access := L2VLANPolicy{AccessVLAN: 10}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "promiscuous", PrivateVLAN: 100, PrivateVLANRole: L2PVLANPromiscuous, VLAN: access},
		{ID: 2, Name: "isolated-a", PrivateVLAN: 100, PrivateVLANRole: L2PVLANIsolated, VLAN: access},
		{ID: 3, Name: "isolated-b", PrivateVLAN: 100, PrivateVLANRole: L2PVLANIsolated, VLAN: access},
		{ID: 4, Name: "community-a", PrivateVLAN: 100, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 7, VLAN: access},
		{ID: 5, Name: "community-b", PrivateVLAN: 100, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 7, VLAN: access},
		{ID: 6, Name: "community-other", PrivateVLAN: 100, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 8, VLAN: access},
	}})
	now := time.Now()
	if v := s.Forward(2, eth(bcast, mac(72), etherARP, make([]byte, 28)), now); !samePorts(v.Out, []PortID{1}) {
		t.Fatalf("isolated-port broadcast must reach only the promiscuous port: %+v", v)
	}
	if v := s.Forward(4, eth(bcast, mac(74), etherARP, make([]byte, 28)), now); !samePorts(v.Out, []PortID{1, 5}) {
		t.Fatalf("community broadcast should reach promiscuous and same community only: %+v", v)
	}
	// Learn the community peer, then verify known unicast follows the same role matrix.
	s.Forward(5, eth(bcast, mac(75), etherARP, make([]byte, 28)), now)
	if v := s.Forward(4, eth(mac(75), mac(74), 0x88b5, nil), now); len(v.Out) != 1 || v.Out[0] != 5 {
		t.Fatalf("same-community unicast was not allowed: %+v", v)
	}
	if err := s.AddPort(L2PortConfig{ID: 7, PrivateVLAN: 100, PrivateVLANRole: L2PVLANCommunity, VLAN: access}); err == nil {
		t.Fatal("community port without a community ID was accepted")
	}
}

func TestPrivateVLANPrimarySecondaryMappingAndTagTranslation(t *testing.T) {
	s, err := NewL2SwitchChecked(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, Name: "primary-gateway", PrivateVLAN: 7, PrivateVLANRole: L2PVLANPromiscuous, PVLANPrimaryVLAN: 100, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{100}}},
		{ID: 2, Name: "isolated-a", PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{101}}},
		{ID: 3, Name: "isolated-b", PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{101}}},
		{ID: 4, Name: "community-a", PrivateVLAN: 7, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 1, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 102, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{102}}},
		{ID: 5, Name: "community-b", PrivateVLAN: 7, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 1, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 102, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{102}}},
		{ID: 6, Name: "community-other", PrivateVLAN: 7, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 2, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 103, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{103}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	validPorts := []L2PortConfig{
		{ID: 1, PrivateVLAN: 7, PrivateVLANRole: L2PVLANPromiscuous, PVLANPrimaryVLAN: 100, VLAN: L2VLANPolicy{AccessVLAN: 100}},
		{ID: 2, PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101, VLAN: L2VLANPolicy{AccessVLAN: 101}},
	}
	for name, ports := range map[string][]L2PortConfig{
		"missing promiscuous port": {validPorts[1]},
		"ordinary port bypass":     {validPorts[0], validPorts[1], {ID: 3, VLAN: L2VLANPolicy{AccessVLAN: 101}}},
		"role admits extra VLAN":   {validPorts[0], {ID: 2, PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{100, 101}}}},
	} {
		if _, err := NewL2SwitchChecked(L2SwitchConfig{Ports: ports}); err == nil {
			t.Errorf("unsafe PVLAN configuration %q was accepted", name)
		}
	}
	now := time.Now()

	isolatedBroadcast := insertVLANTag(eth(bcast, mac(82), etherARP, make([]byte, 28)), 101, FrameInfo{})
	verdict := s.Forward(2, isolatedBroadcast, now)
	if verdict.Drop != L2Forward || !samePorts(verdict.Out, []PortID{1}) {
		t.Fatalf("isolated secondary VLAN broadcast escaped its primary gateway: %+v", verdict)
	}
	if got, err := ParseFrame(verdict.FrameFor(1, isolatedBroadcast)); err != nil || got.VLAN != 100 {
		t.Fatalf("isolated-to-primary egress tag = %+v err=%v, want VLAN 100", got, err)
	}

	primaryBroadcast := insertVLANTag(eth(bcast, mac(81), etherARP, make([]byte, 28)), 100, FrameInfo{})
	verdict = s.Forward(1, primaryBroadcast, now.Add(time.Second))
	if verdict.Drop != L2Forward || !samePorts(verdict.Out, []PortID{2, 3, 4, 5, 6}) {
		t.Fatalf("primary-to-secondary flood = %+v", verdict)
	}
	for port, want := range map[PortID]uint16{2: 101, 3: 101, 4: 102, 5: 102, 6: 103} {
		got, err := ParseFrame(verdict.FrameFor(port, primaryBroadcast))
		if err != nil || got.VLAN != want {
			t.Errorf("primary egress to port %d = VLAN %d err=%v, want secondary VLAN %d", port, got.VLAN, err, want)
		}
	}

	communityBroadcast := insertVLANTag(eth(bcast, mac(84), etherARP, make([]byte, 28)), 102, FrameInfo{})
	verdict = s.Forward(4, communityBroadcast, now.Add(2*time.Second))
	if verdict.Drop != L2Forward || !samePorts(verdict.Out, []PortID{1, 5}) {
		t.Fatalf("community secondary VLAN broadcast crossed role/community boundaries: %+v", verdict)
	}
}

func samePorts(got, want []PortID) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func ipv4MulticastMAC(group [4]byte) [6]byte {
	return [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
}

func igmpReportFrame(source [6]byte, group [4]byte, typ byte) []byte {
	ip := make([]byte, 28)
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], []byte{10, 0, 0, source[5]})
	copy(ip[16:20], group[:])
	ip[20] = typ
	copy(ip[24:28], group[:])
	return eth(ipv4MulticastMAC(group), source, etherIPv4, ip)
}

func ipv4MulticastFrame(source [6]byte, group [4]byte) []byte {
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 1, 1
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], []byte{10, 0, 0, source[5]})
	copy(ip[16:20], group[:])
	return eth(ipv4MulticastMAC(group), source, etherIPv4, ip)
}

func hasPort(ports []PortID, want PortID) bool {
	for _, port := range ports {
		if port == want {
			return true
		}
	}
	return false
}

func TestMulticastMembershipDoesNotExpireWithoutQuerier(t *testing.T) {
	group := [4]byte{239, 1, 2, 3}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4, MulticastRouter: true},
	}})
	start := time.Unix(1000, 0)
	s.Forward(2, igmpReportFrame(mac(2), group, 0x16), start)
	s.Forward(3, igmpReportFrame(mac(3), group, 0x16), start.Add(200*time.Second))
	s.Sweep(start.Add(261 * time.Second))

	// Port 2's report is older than the former 260-second timeout, while port
	// 3's report is newer. Without a querier both memberships stay effective.
	v := s.Forward(1, ipv4MulticastFrame(mac(1), group), start.Add(261*time.Second))
	if v.Drop != L2Forward || !hasPort(v.Out, 2) || !hasPort(v.Out, 3) {
		t.Fatalf("listeners lost multicast after timer gap: %+v", v)
	}
	if !hasPort(v.Out, 4) {
		t.Fatalf("multicast router port missed snooped traffic: %+v", v)
	}

	// A leave from one reporter cannot safely prune a shared port without a
	// querier and last-member query, so retain the conservative membership.
	s.Forward(2, igmpReportFrame(mac(2), group, 0x17), start.Add(262*time.Second))
	v = s.Forward(1, ipv4MulticastFrame(mac(1), group), start.Add(263*time.Second))
	if !hasPort(v.Out, 2) {
		t.Fatalf("IGMP leave suppressed another listener on shared port: %+v", v)
	}
}

func igmpQueryFrame(source [6]byte) []byte {
	group := [4]byte{224, 0, 0, 1}
	ip := make([]byte, 28)
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15] = 10, source[5]
	copy(ip[16:20], group[:])
	ip[20] = 0x11 // IGMP Membership Query
	return eth(ipv4MulticastMAC(group), source, etherIPv4, ip)
}

func igmpV3RecordFrame(source [6]byte, group [4]byte, recordType byte, sources [][4]byte) []byte {
	groupRecord := make([]byte, 8+4*len(sources))
	groupRecord[0] = recordType
	binary.BigEndian.PutUint16(groupRecord[2:4], uint16(len(sources)))
	copy(groupRecord[4:8], group[:])
	for i, address := range sources {
		copy(groupRecord[8+i*4:12+i*4], address[:])
	}
	igmp := make([]byte, 8+len(groupRecord))
	igmp[0] = 0x22
	binary.BigEndian.PutUint16(igmp[6:8], 1)
	copy(igmp[8:], groupRecord)
	ip := make([]byte, 20+len(igmp))
	ip[0], ip[8], ip[9] = 0x45, 1, 2
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[12], ip[15], ip[16], ip[17], ip[18], ip[19] = 10, source[5], 224, 0, 0, 22
	copy(ip[20:], igmp)
	return eth(ipv4MulticastMAC([4]byte{224, 0, 0, 22}), source, etherIPv4, ip)
}

func ipv6MLDv2RecordFrame(sourceMAC [6]byte, group [16]byte, recordType byte, sources [][16]byte, declaredSources uint16) []byte {
	record := make([]byte, 20+16*len(sources))
	record[0] = recordType
	binary.BigEndian.PutUint16(record[2:4], declaredSources)
	copy(record[4:20], group[:])
	for i, address := range sources {
		copy(record[20+i*16:36+i*16], address[:])
	}
	icmp := make([]byte, 8+len(record))
	icmp[0] = 143
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	copy(icmp[8:], record)
	hop := []byte{58, 0, 5, 2, 0, 0, 1, 0}
	ip := make([]byte, 40+len(hop)+len(icmp))
	ip[0], ip[6], ip[7] = 0x60, 0, 1
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(hop)+len(icmp)))
	ip[8], ip[9] = 0xfe, 2               // fe80::2
	ip[24], ip[25], ip[39] = 0xff, 2, 22 // ff02::16
	copy(ip[40:], hop)
	copy(ip[48:], icmp)
	return eth([6]byte{0x33, 0x33, 0, 0, 0, 0x16}, sourceMAC, etherIPv6, ip)
}

func ipv6MulticastDataFrame(sourceMAC [6]byte, source, group [16]byte) []byte {
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 59, 1
	copy(ip[8:24], source[:])
	copy(ip[24:40], group[:])
	destination := [6]byte{0x33, 0x33, group[12], group[13], group[14], group[15]}
	return eth(destination, sourceMAC, etherIPv6, ip)
}

func ipv6MLDQueryFrame(sourceMAC [6]byte) []byte {
	icmp := make([]byte, 24)
	icmp[0] = 130
	hop := []byte{58, 0, 5, 2, 0, 0, 1, 0}
	ip := make([]byte, 40+len(hop)+len(icmp))
	ip[0], ip[6], ip[7] = 0x60, 0, 1
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(hop)+len(icmp)))
	ip[8], ip[9] = 0xfe, 1              // fe80::1
	ip[24], ip[25], ip[39] = 0xff, 2, 1 // ff02::1
	copy(ip[40:], hop)
	copy(ip[48:], icmp)
	return eth([6]byte{0x33, 0x33, 0, 0, 0, 1}, sourceMAC, etherIPv6, ip)
}

func ipv6MLDv1DoneFrame(sourceMAC [6]byte, group [16]byte) []byte {
	icmp := make([]byte, 24)
	icmp[0] = 132
	copy(icmp[8:24], group[:])
	hop := []byte{58, 0, 5, 2, 0, 0, 1, 0}
	ip := make([]byte, 40+len(hop)+len(icmp))
	ip[0], ip[6], ip[7] = 0x60, 0, 1
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(hop)+len(icmp)))
	ip[8], ip[9] = 0xfe, 2
	ip[24], ip[25], ip[39] = 0xff, 2, 2
	copy(ip[40:], hop)
	copy(ip[48:], icmp)
	return eth([6]byte{0x33, 0x33, 0, 0, 0, 2}, sourceMAC, etherIPv6, ip)
}

func TestIGMPv3SourceFilterTransitions(t *testing.T) {
	group := [4]byte{239, 30, 40, 50}
	sourceA, sourceB, sourceC := [4]byte{10, 1, 0, 1}, [4]byte{10, 1, 0, 2}, [4]byte{10, 1, 0, 3}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4, MulticastRouter: true}}})
	now := time.Unix(6000, 0)
	s.Forward(4, igmpQueryFrame(mac(4)), now)
	s.Forward(2, igmpV3RecordFrame(mac(2), group, 1, [][4]byte{sourceA}), now)
	s.Forward(3, igmpV3RecordFrame(mac(3), group, 2, [][4]byte{sourceB}), now)
	forward := func(source [4]byte) []PortID {
		frame := ipv4MulticastFrame(mac(1), group)
		copy(frame[26:30], source[:])
		verdict := s.Forward(1, frame, now.Add(time.Second))
		if verdict.Drop != L2Forward {
			t.Fatalf("multicast source %v was dropped: %+v", source, verdict)
		}
		return verdict.Out
	}
	if got := forward(sourceA); !hasPort(got, 2) || !hasPort(got, 3) {
		t.Fatalf("INCLUDE(A) and EXCLUDE(B) rejected source A: %v", got)
	}
	if got := forward(sourceB); hasPort(got, 2) || hasPort(got, 3) {
		t.Fatalf("INCLUDE(A) and EXCLUDE(B) admitted source B: %v", got)
	}
	if got := forward(sourceC); hasPort(got, 2) || !hasPort(got, 3) {
		t.Fatalf("source C did not follow per-port filters: %v", got)
	}
	s.Forward(2, igmpV3RecordFrame(mac(2), group, 5, [][4]byte{sourceB}), now.Add(2*time.Second)) // ALLOW B
	if got := forward(sourceB); !hasPort(got, 2) || hasPort(got, 3) {
		t.Fatalf("ALLOW_NEW_SOURCES did not update both filters: %v", got)
	}
	s.Forward(2, igmpV3RecordFrame(mac(2), group, 6, [][4]byte{sourceA}), now.Add(3*time.Second)) // BLOCK A
	if got := forward(sourceA); hasPort(got, 2) || !hasPort(got, 3) {
		t.Fatalf("BLOCK_OLD_SOURCES did not update INCLUDE filter: %v", got)
	}
	s.Forward(2, igmpV3RecordFrame(mac(2), group, 6, [][4]byte{sourceB}), now.Add(4*time.Second)) // INCLUDE list becomes empty
	s.Forward(3, igmpV3RecordFrame(mac(3), group, 5, [][4]byte{sourceB}), now.Add(5*time.Second)) // ALLOW removes EXCLUDE block
	if got := forward(sourceB); hasPort(got, 2) || !hasPort(got, 3) {
		t.Fatalf("ALLOW_NEW_SOURCES did not update EXCLUDE filter: %v", got)
	}
	s.Forward(3, igmpV3RecordFrame(mac(3), group, 6, [][4]byte{sourceC}), now.Add(6*time.Second)) // BLOCK adds EXCLUDE block
	if got := forward(sourceC); hasPort(got, 3) {
		t.Fatalf("BLOCK_OLD_SOURCES did not update EXCLUDE filter: %v", got)
	}
}

func TestMLDv2SourceFilterAndMalformedRecords(t *testing.T) {
	group := [16]byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	sourceA := [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	sourceB := [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4, MulticastRouter: true}}})
	now := time.Unix(7000, 0)
	s.Forward(4, ipv6MLDQueryFrame(mac(4)), now)
	valid := ipv6MLDv2RecordFrame(mac(2), group, 1, [][16]byte{sourceA}, 1)
	info, err := ParseFrame(valid)
	if err != nil || info.MulticastRecordsMalformed || len(info.MulticastRecords) != 1 {
		t.Fatalf("valid MLDv2 record failed to parse: info=%+v err=%v", info, err)
	}
	s.Forward(2, valid, now)
	s.Forward(3, ipv6MLDv2RecordFrame(mac(3), group, 2, [][16]byte{sourceB}, 1), now)
	dataA := ipv6MulticastDataFrame(mac(1), sourceA, group)
	dataB := ipv6MulticastDataFrame(mac(1), sourceB, group)
	if got := s.Forward(1, dataA, now.Add(time.Second)); !hasPort(got.Out, 2) || !hasPort(got.Out, 3) {
		t.Fatalf("MLDv2 filters rejected source A: %+v", got)
	}
	if got := s.Forward(1, dataB, now.Add(time.Second)); hasPort(got.Out, 2) || hasPort(got.Out, 3) {
		t.Fatalf("MLDv2 filters admitted source B: %+v", got)
	}
	malformed := ipv6MLDv2RecordFrame(mac(2), group, 1, [][16]byte{sourceA}, 2)
	info, err = ParseFrame(malformed)
	if err != nil || !info.MulticastRecordsMalformed {
		t.Fatalf("truncated MLDv2 source list was not marked malformed: info=%+v err=%v", info, err)
	}
	// Malformed reports must not partially replace the last valid filter.
	s.Forward(2, malformed, now.Add(2*time.Second))
	if got := s.Forward(1, dataA, now.Add(3*time.Second)); !hasPort(got.Out, 2) {
		t.Fatalf("malformed report changed existing MLD membership: %+v", got)
	}
}

func TestMalformedIGMPv3SourceRecordDoesNotLearnPartialMembership(t *testing.T) {
	group := [4]byte{239, 30, 40, 60}
	source := [4]byte{10, 1, 0, 1}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2}, {ID: 3}}})
	now := time.Unix(8000, 0)
	frame := igmpV3RecordFrame(mac(2), group, 1, [][4]byte{source})
	// Declare a second source while keeping the wire packet short.
	frame[14+20+8+2], frame[14+20+8+3] = 0, 2
	info, err := ParseFrame(frame)
	if err != nil || !info.MulticastRecordsMalformed {
		t.Fatalf("truncated IGMPv3 source list was not marked malformed: info=%+v err=%v", info, err)
	}
	s.Forward(2, frame, now)
	if got := s.Stats().MulticastMembers; got != 0 {
		t.Fatalf("malformed IGMPv3 report partially learned %d members", got)
	}
}

func TestQuerierEnablesExpiryAndFallsBackToFloodWhenItDisappears(t *testing.T) {
	group := [4]byte{239, 20, 30, 40}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4, MulticastRouter: true},
	}})
	start := time.Unix(5000, 0)
	if got, err := ParseFrame(igmpQueryFrame(mac(4))); err != nil || !got.IGMPQuery {
		t.Fatalf("IGMP query was not identified: info=%+v err=%v", got, err)
	}
	s.Forward(4, igmpQueryFrame(mac(4)), start)
	s.Forward(2, igmpReportFrame(mac(2), group, 0x16), start.Add(time.Second))
	s.Forward(4, igmpQueryFrame(mac(4)), start.Add(200*time.Second))
	s.Forward(3, igmpReportFrame(mac(3), group, 0x16), start.Add(200*time.Second))
	// The membership from port 2 ages while port 3's later report is still fresh.
	s.Sweep(start.Add(262 * time.Second))
	if got := s.Stats().MulticastMembers; got != 1 {
		t.Fatalf("expected only the later reporter to remain, got %d", got)
	}
	v := s.Forward(1, ipv4MulticastFrame(mac(1), group), start.Add(262*time.Second))
	if v.Drop != L2Forward || hasPort(v.Out, 2) || !hasPort(v.Out, 3) || !hasPort(v.Out, 4) {
		t.Fatalf("active querier did not apply membership expiry/router-port forwarding: %+v", v)
	}
	// Once query traffic has stopped for a full membership interval, stale
	// snooping state is no longer authoritative: flood to avoid silent loss.
	v = s.Forward(1, ipv4MulticastFrame(mac(1), group), start.Add(461*time.Second))
	if v.Drop != L2Forward || !v.Flooded || !hasPort(v.Out, 2) || !hasPort(v.Out, 3) {
		t.Fatalf("expired querier did not restore safe flooding: %+v", v)
	}
}

func TestDueMulticastQueriesAreValidPerVLANAndInterval(t *testing.T) {
	macQuerier := [6]byte{0x02, 0x47, 0x42, 0, 0, 1}
	ipv4Source := [4]byte{10, 78, 0, 1}
	ipv6Source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0, 1}
	s := NewL2Switch(L2SwitchConfig{MulticastQueryInterval: 125 * time.Second, Ports: []L2PortConfig{
		{ID: 1, VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 20}},
		{ID: 4, MulticastRouter: true, MulticastQuerier: true, QuerierMAC: macQuerier, QuerierIPv4: ipv4Source, QuerierIPv6: ipv6Source,
			VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10, 20}, NativeVLAN: 10}},
	}})
	now := time.Unix(9000, 0)
	queries := s.DueMulticastQueries(now)
	if len(queries) != 4 {
		t.Fatalf("expected two protocols for both VLANs, got %d", len(queries))
	}
	seen := map[uint16]map[uint8]bool{}
	for _, query := range queries {
		info, err := ParseFrame(query.Frame)
		if err != nil || query.IngressPort != 4 || !info.Control {
			t.Fatalf("generated query failed to parse: info=%+v err=%v", info, err)
		}
		vlan := info.VLAN
		if info.VLANDepth == 0 {
			vlan = 10 // this querier port emits its native VLAN untagged
		}
		if info.VLAN == 20 && info.VLANDepth != 1 || info.VLAN == 0 && info.VLANDepth != 0 {
			t.Fatalf("unexpected query VLAN encoding: %+v", info)
		}
		if seen[vlan] == nil {
			seen[vlan] = map[uint8]bool{}
		}
		ipOffset := EthHeaderLen + int(info.VLANDepth)*vlanTagLen
		if info.IGMPQuery {
			ip := query.Frame[ipOffset:]
			if internetChecksum(ip[:24]) != 0 || internetChecksum(ip[24:]) != 0 || ip[8] != 1 || ip[16] != 224 || ip[19] != 1 {
				t.Fatalf("generated IGMP query has invalid checksums/header: %x", ip)
			}
			seen[vlan][4] = true
		} else if info.MLDQuery {
			ip := query.Frame[ipOffset:]
			icmp := ip[48:]
			pseudo := make([]byte, 40+len(icmp))
			copy(pseudo[:16], ip[8:24])
			copy(pseudo[16:32], ip[24:40])
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
			pseudo[39] = 58
			copy(pseudo[40:], icmp)
			if internetChecksum(pseudo) != 0 || ip[7] != 1 || ip[24] != 0xff || ip[39] != 1 {
				t.Fatalf("generated MLD query has invalid checksum/header: %x", ip)
			}
			seen[vlan][16] = true
		} else {
			t.Fatalf("generated frame is not a general query: %+v", info)
		}
		verdict := s.Forward(query.IngressPort, query.Frame, now)
		want := PortID(1)
		if vlan == 20 {
			want = 2
		}
		if verdict.Drop != L2Forward || !hasPort(verdict.Out, want) {
			t.Fatalf("generated query did not traverse the switch on VLAN %d: %+v", vlan, verdict)
		}
	}
	for _, vlan := range []uint16{10, 20} {
		if !seen[vlan][4] || !seen[vlan][16] {
			t.Fatalf("missing query family for VLAN %d: %v", vlan, seen[vlan])
		}
	}
	if got := s.DueMulticastQueries(now.Add(124 * time.Second)); len(got) != 0 {
		t.Fatalf("queries fired before configured interval: %d", len(got))
	}
	if got := s.DueMulticastQueries(now.Add(125 * time.Second)); len(got) != 4 {
		t.Fatalf("queries did not repeat at configured interval: %d", len(got))
	}
}

func TestIGMPLeaveUsesLastMemberQueriesBeforePruning(t *testing.T) {
	group := [4]byte{239, 10, 20, 30}
	querierMAC := [6]byte{0x02, 0x47, 0x42, 0, 0, 4}
	querierIP := [4]byte{10, 0, 0, 4}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1}, {ID: 2},
		{ID: 4, MulticastRouter: true, MulticastQuerier: true, QuerierMAC: querierMAC, QuerierIPv4: querierIP},
	}})
	now := time.Unix(12000, 0)
	for _, query := range s.DueMulticastQueries(now) {
		if info, _ := ParseFrame(query.Frame); info.IGMPQuery {
			s.Forward(query.IngressPort, query.Frame, now)
		}
	}
	s.Forward(2, igmpV3RecordFrame(mac(2), group, 1, [][4]byte{{10, 0, 0, 2}}), now.Add(time.Millisecond))
	leave := igmpReportFrame(mac(2), group, 0x17)
	s.Forward(2, leave, now.Add(2*time.Millisecond))
	if got := s.Stats().MulticastMembers; got != 1 {
		t.Fatalf("leave pruned membership before queries: members=%d", got)
	}
	for i := 0; i < 2; i++ {
		at := now.Add(3*time.Millisecond + time.Duration(i)*time.Second)
		queries := s.DueMulticastQueries(at)
		if len(queries) != 1 {
			t.Fatalf("query round %d emitted %d queries: %+v", i+1, len(queries), queries)
		}
		info, err := ParseFrame(queries[0].Frame)
		if err != nil || !info.IGMPQuery || queries[0].Frame[14+16] != group[0] || queries[0].Frame[14+19] != group[3] {
			t.Fatalf("invalid group-specific query: info=%+v err=%v frame=%x", info, err, queries[0].Frame)
		}
		if err := validateIGMPQueryChecksums(queries[0].Frame, 14); err != nil {
			t.Fatal(err)
		}
		verdict := s.Forward(queries[0].IngressPort, queries[0].Frame, at)
		if verdict.Drop != L2Forward || !hasPort(verdict.Out, 2) {
			t.Fatalf("last-member query missed listener: %+v", verdict)
		}
	}
	if got := s.Stats().MulticastMembers; got != 1 {
		t.Fatalf("listener pruned before final response window: members=%d", got)
	}
	s.DueMulticastQueries(now.Add(2*time.Second + 3*time.Millisecond))
	if got := s.Stats().MulticastMembers; got != 0 {
		t.Fatalf("silent listener was not pruned after response window: members=%d", got)
	}
}

func TestMLDLeaveUsesLastMemberQueriesBeforePruning(t *testing.T) {
	group := [16]byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34}
	querierMAC := [6]byte{0x02, 0x47, 0x42, 0, 0, 4}
	querierIP := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0, 4}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1}, {ID: 2},
		{ID: 4, MulticastRouter: true, MulticastQuerier: true, QuerierMAC: querierMAC, QuerierIPv6: querierIP},
	}})
	now := time.Unix(13000, 0)
	for _, query := range s.DueMulticastQueries(now) {
		if info, _ := ParseFrame(query.Frame); info.MLDQuery {
			s.Forward(query.IngressPort, query.Frame, now)
		}
	}
	includeSource := [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	s.Forward(2, ipv6MLDv2RecordFrame(mac(2), group, 1, [][16]byte{includeSource}, 1), now.Add(time.Millisecond))
	s.Forward(2, ipv6MLDv1DoneFrame(mac(2), group), now.Add(2*time.Millisecond))
	for i := 0; i < 2; i++ {
		at := now.Add(3*time.Millisecond + time.Duration(i)*time.Second)
		queries := s.DueMulticastQueries(at)
		if len(queries) != 1 {
			t.Fatalf("MLD query round %d emitted %d queries", i+1, len(queries))
		}
		info, err := ParseFrame(queries[0].Frame)
		if err != nil || !info.MLDQuery || !bytes.Equal(queries[0].Frame[14+48+8:14+48+24], group[:]) {
			t.Fatalf("invalid MLD group-specific query: info=%+v err=%v", info, err)
		}
		ip := queries[0].Frame[14:]
		icmp := ip[48:]
		pseudo := make([]byte, 40+len(icmp))
		copy(pseudo[:16], ip[8:24])
		copy(pseudo[16:32], ip[24:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
		pseudo[39] = 58
		copy(pseudo[40:], icmp)
		if internetChecksum(pseudo) != 0 {
			t.Fatal("MLD group-specific query has an invalid ICMPv6 checksum")
		}
		verdict := s.Forward(queries[0].IngressPort, queries[0].Frame, at)
		if verdict.Drop != L2Forward || !hasPort(verdict.Out, 2) {
			t.Fatalf("last-member MLD query missed listener: %+v", verdict)
		}
	}
	if got := s.Stats().MulticastMembers; got != 1 {
		t.Fatalf("MLD listener pruned before final response window: members=%d", got)
	}
	s.DueMulticastQueries(now.Add(2*time.Second + 3*time.Millisecond))
	if got := s.Stats().MulticastMembers; got != 0 {
		t.Fatalf("silent MLD listener was not pruned after response window: members=%d", got)
	}
}

func TestIGMPv2ReportDuringLastMemberWindowCancelsPruning(t *testing.T) {
	group := [4]byte{239, 10, 20, 31}
	querierMAC := [6]byte{0x02, 0x47, 0x42, 0, 0, 4}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 2}, {ID: 4, MulticastRouter: true, MulticastQuerier: true, QuerierMAC: querierMAC, QuerierIPv4: [4]byte{10, 0, 0, 4}},
	}})
	now := time.Unix(14000, 0)
	for _, query := range s.DueMulticastQueries(now) {
		if info, _ := ParseFrame(query.Frame); info.IGMPQuery {
			s.Forward(query.IngressPort, query.Frame, now)
		}
	}
	s.Forward(2, igmpReportFrame(mac(2), group, 0x16), now.Add(time.Millisecond))
	s.Forward(2, igmpReportFrame(mac(2), group, 0x17), now.Add(2*time.Millisecond))
	if queries := s.DueMulticastQueries(now.Add(3 * time.Millisecond)); len(queries) != 1 {
		t.Fatalf("expected initial group-specific query, got %d", len(queries))
	}
	// A report from another host on the shared port is evidence that the
	// aggregate port still has listeners; IGMPv2 suppression refreshes it.
	s.Forward(2, igmpReportFrame(mac(22), group, 0x16), now.Add(4*time.Millisecond))
	if queries := s.DueMulticastQueries(now.Add(2 * time.Second)); len(queries) != 0 {
		t.Fatalf("last-member queries continued after a listener report: %d", len(queries))
	}
	if got := s.Stats().MulticastMembers; got != 2 {
		t.Fatalf("shared-port listener membership was pruned: %d", got)
	}
}

func validateIGMPQueryChecksums(frame []byte, offset int) error {
	ip := frame[offset:]
	if len(ip) < 36 || internetChecksum(ip[:24]) != 0 || internetChecksum(ip[24:]) != 0 {
		return fmt.Errorf("invalid IGMP query checksums")
	}
	return nil
}

func TestLinkLocalMulticastFloodsDespiteMembership(t *testing.T) {
	mdns := [4]byte{224, 0, 0, 251}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}}})
	now := time.Unix(2000, 0)
	s.Forward(2, igmpReportFrame(mac(2), mdns, 0x16), now)
	v := s.Forward(1, ipv4MulticastFrame(mac(1), mdns), now.Add(500*time.Second))
	for _, port := range []PortID{2, 3, 4} {
		if !hasPort(v.Out, port) {
			t.Fatalf("mDNS did not flood to port %d: %+v", port, v)
		}
	}
}

func TestRemovePortPrunesMulticastMembership(t *testing.T) {
	group := [4]byte{239, 9, 8, 7}
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{{ID: 1}, {ID: 2}, {ID: 3}}})
	now := time.Unix(3000, 0)
	s.Forward(2, igmpReportFrame(mac(2), group, 0x16), now)
	if got := s.Stats().MulticastMembers; got != 1 {
		t.Fatalf("member count before detach: %d", got)
	}
	if !s.RemovePort(2) {
		t.Fatal("listener port was not removed")
	}
	if got := s.Stats().MulticastMembers; got != 0 {
		t.Fatalf("removed membership leaked: %d", got)
	}
	v := s.Forward(1, ipv4MulticastFrame(mac(1), group), now.Add(time.Second))
	if hasPort(v.Out, 2) || !hasPort(v.Out, 3) {
		t.Fatalf("detached port remained in multicast forwarding: %+v", v)
	}
}

func TestSwitchVLANAccessAndTrunkIsolation(t *testing.T) {
	s := NewL2Switch(L2SwitchConfig{Ports: []L2PortConfig{
		{ID: 1, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10, 20}, NativeVLAN: 20}},
		{ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 3, VLAN: L2VLANPolicy{AccessVLAN: 20}},
		{ID: 4, VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10, 20}, NativeVLAN: 20}},
	}})
	now := time.Unix(4000, 0)
	frame := eth(bcast, mac(1), etherVLAN, []byte{0x00, 0x0a, 0x08, 0x00})
	frame = append(frame, make([]byte, 20)...)
	v := s.Forward(1, frame, now)
	if v.Drop != L2Forward || hasPort(v.Out, 3) || !hasPort(v.Out, 2) || !hasPort(v.Out, 4) {
		t.Fatalf("VLAN 10 broadcast crossed VLAN membership: %+v", v)
	}
	if got := v.FrameFor(2, frame); len(got) != len(frame)-4 || binary.BigEndian.Uint16(got[12:14]) != etherIPv4 {
		t.Fatalf("access VLAN frame was not untagged: %x", got)
	}
	if got := v.FrameFor(4, frame); len(got) != len(frame) || binary.BigEndian.Uint16(got[14:16])&0x0fff != 10 {
		t.Fatalf("trunk VLAN tag was not preserved: %x", got)
	}

	// Native VLAN traffic leaves an untagged trunk, while a VLAN 10 access frame
	// receives an inserted tag on a non-native trunk.
	native := eth(bcast, mac(1), etherARP, make([]byte, 28))
	v = s.Forward(1, native, now.Add(time.Second))
	if !hasPort(v.Out, 4) || binary.BigEndian.Uint16(v.FrameFor(4, native)[12:14]) != etherARP {
		t.Fatalf("native VLAN egress was tagged: %+v", v)
	}
	if bad := s.Forward(2, frame, now.Add(2*time.Second)); bad.Drop != L2DropVLAN {
		t.Fatalf("tagged VLAN 10 frame entered access VLAN: %+v", bad)
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

// A session with L2 on must carry the largest bridged frame whatever its L3 MTU is. The limit used to follow
// the L3 MTU alone (1280 by default), so every frame over 1303 bytes was refused with nothing logged.
func TestL2SessionLimitAdmitsFullFrames(t *testing.T) {
	s := l2Session(t, true)
	need := WrapFrameSize(DefaultL2FrameMTU) + Overhead + 24
	if s.Receiver.mtu < need {
		t.Fatalf("datagram limit %d cannot carry a %d-byte frame (needs %d)", s.Receiver.mtu, DefaultL2FrameMTU, need)
	}
	off := l2Session(t, false)
	if off.Receiver.mtu >= need {
		t.Fatalf("L2 off should keep the L3 limit, got %d", off.Receiver.mtu)
	}
}

// A refused oversize datagram is counted, with the size that was refused and the limit that refused it.
func TestOversizeRefusalIsCounted(t *testing.T) {
	s := l2Session(t, false)
	snd := s.Sender
	big := make([]byte, s.Receiver.mtu)
	if _, err := snd.Urgent(big, false, time.Now(), func(Datagram) error { return nil }); err != ErrFrame {
		t.Fatalf("want ErrFrame, got %v", err)
	}
	st := snd.stats
	if st.RefusedOversize != 1 || st.RefusedOversizeLargest != uint64(len(big)+Overhead) || st.DatagramLimit != uint64(s.Receiver.mtu) {
		t.Fatalf("refusal not recorded: %+v", st)
	}
}

func WrapFrameSize(n int) int { return n + 1 }
