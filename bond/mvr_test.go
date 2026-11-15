package bond

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mvrTestSwitch(t *testing.T) *L2Switch {
	t.Helper()
	config := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	ports := []L2PortConfig{
		{ID: 1, Name: "mvr-source", VLAN: L2VLANPolicy{AccessVLAN: 100}, MulticastRouter: true},
		{ID: 2, Name: "receiver-querier", VLAN: L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true},
		{ID: 3, Name: "listener-a", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 4, Name: "listener-b", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 5, Name: "other-vlan", VLAN: L2VLANPolicy{AccessVLAN: 20}},
	}
	if err := (L2SwitchConfig{MVR: &config, Ports: ports}).Validate(); err != nil {
		t.Fatal(err)
	}
	return NewL2Switch(L2SwitchConfig{MVR: &config, Ports: ports})
}

func TestMVRForwardsJoinedGroupsAcrossVLANAndRetainsIsolation(t *testing.T) {
	s := mvrTestSwitch(t)
	now := time.Unix(100, 0)
	group := [4]byte{239, 3, 3, 3}
	s.Forward(2, igmpQueryFrame(mac(2)), now)
	s.Forward(3, igmpReportFrame(mac(3), group, 0x16), now.Add(time.Second))
	frame := ipv4MulticastFrame(mac(1), group)
	verdict := s.Forward(1, frame, now.Add(2*time.Second))
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{3}) {
		t.Fatalf("MVR member forwarding = %+v, want only receiver port 3", verdict)
	}
	if got := verdict.FrameFor(3, frame); len(got) != len(frame) {
		t.Fatalf("MVR access egress changed frame length: %d != %d", len(got), len(frame))
	}
	info, err := ParseFrame(verdict.FrameFor(3, frame))
	if err != nil || info.VLAN != 0 {
		t.Fatalf("MVR access egress should be untagged: info=%+v err=%v", info, err)
	}
}

func TestMVRRelaysReceiverReportsToMulticastVLANRouter(t *testing.T) {
	s := mvrTestSwitch(t)
	now := time.Unix(100, 0)
	group := [4]byte{239, 3, 3, 3}
	verdict := s.Forward(3, igmpReportFrame(mac(3), group, 0x16), now)
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{1}) {
		t.Fatalf("MVR listener report did not reach multicast router: %+v", verdict)
	}
	info, err := ParseFrame(verdict.FrameFor(1, igmpReportFrame(mac(3), group, 0x16)))
	if err != nil || info.VLAN != 0 {
		t.Fatalf("MVR report egress was not access encoded: info=%+v err=%v", info, err)
	}
}

func TestMVRWithoutQuerierFallsBackOnlyWithinReceiverVLAN(t *testing.T) {
	s := mvrTestSwitch(t)
	now := time.Unix(100, 0)
	group := [4]byte{239, 3, 3, 3}
	frame := ipv4MulticastFrame(mac(1), group)
	verdict := s.Forward(1, frame, now)
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{2, 3, 4}) {
		t.Fatalf("MVR fallback escaped receiver VLAN or dropped: %+v", verdict)
	}
}

func TestMVRForwardsOneGroupToMultipleIsolatedReceiverVLANs(t *testing.T) {
	group := [4]byte{239, 3, 3, 3}
	config := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLANs: []uint16{10, 20}}}}
	ports := []L2PortConfig{
		{ID: 1, Name: "mvr-source", VLAN: L2VLANPolicy{AccessVLAN: 100}, MulticastRouter: true},
		{ID: 2, Name: "vlan-10-querier", VLAN: L2VLANPolicy{AccessVLAN: 10}, MulticastRouter: true},
		{ID: 3, Name: "vlan-10-listener", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 4, Name: "vlan-10-nonmember", VLAN: L2VLANPolicy{AccessVLAN: 10}},
		{ID: 5, Name: "vlan-20-querier", VLAN: L2VLANPolicy{AccessVLAN: 20}, MulticastRouter: true},
		{ID: 6, Name: "vlan-20-listener", VLAN: L2VLANPolicy{AccessVLAN: 20}},
		{ID: 7, Name: "other-vlan", VLAN: L2VLANPolicy{AccessVLAN: 30}},
	}
	if err := (L2SwitchConfig{MVR: &config, Ports: ports}).Validate(); err != nil {
		t.Fatalf("valid multi-receiver mapping rejected: %v", err)
	}
	s := NewL2Switch(L2SwitchConfig{MVR: &config, Ports: ports})
	now := time.Unix(100, 0)
	s.Forward(2, igmpQueryFrame(mac(2)), now)
	s.Forward(5, igmpQueryFrame(mac(5)), now)
	s.Forward(3, igmpReportFrame(mac(3), group, 0x16), now.Add(time.Second))
	s.Forward(6, igmpReportFrame(mac(6), group, 0x16), now.Add(time.Second))

	frame := ipv4MulticastFrame(mac(1), group)
	verdict := s.Forward(1, frame, now.Add(2*time.Second))
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{3, 6}) {
		t.Fatalf("multi-VLAN MVR delivery = %+v, want listeners on VLANs 10 and 20 only", verdict)
	}
	for _, id := range verdict.Out {
		info, err := ParseFrame(verdict.FrameFor(id, frame))
		if err != nil || info.VLAN != 0 {
			t.Fatalf("access VLAN %d received a tagged or malformed MVR frame: info=%+v err=%v", id, info, err)
		}
	}
}

func TestMVRRejectsTrunkThatWouldNeedTwoEgressTagsForOneGroup(t *testing.T) {
	config := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLANs: []uint16{10, 20}}}}
	s := NewL2Switch(L2SwitchConfig{DynamicPorts: true, MVR: &config, Ports: []L2PortConfig{{ID: 1, VLAN: L2VLANPolicy{AccessVLAN: 100}, MulticastRouter: true}}})
	err := s.AddPort(L2PortConfig{ID: 2, Name: "multi-vlan-trunk", VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10, 20}}})
	if err == nil || !strings.Contains(err.Error(), "multiple mapped receiver VLANs") {
		t.Fatalf("ambiguous MVR trunk accepted: %v", err)
	}
}

func TestMVRRetagsPerReceiverVLANAndRespectsPrivateVLAN(t *testing.T) {
	group := [4]byte{239, 3, 3, 3}
	config := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	s := NewL2Switch(L2SwitchConfig{MVR: &config, Ports: []L2PortConfig{
		{ID: 1, VLAN: L2VLANPolicy{AccessVLAN: 100}, MulticastRouter: true, PrivateVLAN: 7, PrivateVLANRole: L2PVLANPromiscuous},
		{ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 10}, PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, MulticastRouter: true},
		{ID: 3, VLAN: L2VLANPolicy{AccessVLAN: 10}, PrivateVLAN: 7, PrivateVLANRole: L2PVLANCommunity, PVLANCommunity: 1},
	}})
	now := time.Unix(100, 0)
	s.Forward(2, igmpQueryFrame(mac(2)), now)
	s.Forward(2, igmpReportFrame(mac(2), group, 0x16), now.Add(time.Second))
	frame := ipv4MulticastFrame(mac(1), group)
	verdict := s.Forward(1, frame, now.Add(2*time.Second))
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{2}) {
		t.Fatalf("MVR violated PVLAN membership: %+v", verdict)
	}
	if len(verdict.FrameFor(2, frame)) != len(frame) {
		t.Fatalf("access receiver should get untagged frame: %#v", verdict.OutFrames)
	}
}

func TestMVRRewritesTaggedSourceVLANForReceiverTrunk(t *testing.T) {
	group := [4]byte{239, 3, 3, 3}
	config := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	s := NewL2Switch(L2SwitchConfig{MVR: &config, Ports: []L2PortConfig{
		{ID: 1, Name: "source-trunk", VLAN: L2VLANPolicy{AllowedVLANs: []uint16{100}}, MulticastRouter: true},
		{ID: 2, Name: "receiver-trunk", VLAN: L2VLANPolicy{AllowedVLANs: []uint16{10, 20}, NativeVLAN: 20}, MulticastRouter: true},
		{ID: 3, Name: "receiver", VLAN: L2VLANPolicy{AccessVLAN: 10}},
	}})
	now := time.Unix(100, 0)
	query := insertVLANTag(igmpQueryFrame(mac(2)), 10, FrameInfo{})
	s.Forward(2, query, now)
	s.learnGroups4(2, vlanID{outer: 10}, mac(2), [][4]byte{group}, now.Add(500*time.Millisecond))
	s.Forward(3, igmpReportFrame(mac(3), group, 0x16), now.Add(time.Second))

	sourceFrame := insertVLANTag(ipv4MulticastFrame(mac(1), group), 100, FrameInfo{})
	verdict := s.Forward(1, sourceFrame, now.Add(2*time.Second))
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{2, 3}) {
		t.Fatalf("MVR trunk forwarding = %+v, want trunk and access listeners", verdict)
	}
	trunkFrame := verdict.FrameFor(2, sourceFrame)
	if len(trunkFrame) != len(sourceFrame) {
		t.Fatalf("MVR receiver trunk frame size = %d, want %d", len(trunkFrame), len(sourceFrame))
	}
	if got := binary.BigEndian.Uint16(trunkFrame[14:16]) & 0x0fff; got != 10 {
		t.Fatalf("MVR receiver trunk retained wrong VLAN tag %d, want receiver VLAN 10: %x", got, trunkFrame[:18])
	}
	if got := binary.BigEndian.Uint16(sourceFrame[14:16]) & 0x0fff; got != 100 {
		t.Fatalf("MVR forwarding mutated original source frame VLAN: %d", got)
	}
}

func TestMVRUsesPVLANSecondaryMembershipAndEgressVLAN(t *testing.T) {
	group := [4]byte{239, 3, 3, 3}
	mvr := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 101}}}
	s := NewL2Switch(L2SwitchConfig{MVR: &mvr, Ports: []L2PortConfig{
		{ID: 1, Name: "primary-gateway", VLAN: L2VLANPolicy{AccessVLAN: 100}, MulticastRouter: true, PrivateVLAN: 7, PrivateVLANRole: L2PVLANPromiscuous, PVLANPrimaryVLAN: 100},
		{ID: 2, Name: "receiver-querier", VLAN: L2VLANPolicy{AccessVLAN: 101}, MulticastRouter: true, PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101},
		{ID: 3, Name: "receiver-trunk", VLAN: L2VLANPolicy{AllowedVLANs: []uint16{101}}, PrivateVLAN: 7, PrivateVLANRole: L2PVLANIsolated, PVLANPrimaryVLAN: 100, PVLANSecondaryVLAN: 101},
	}})
	now := time.Unix(100, 0)
	s.Forward(2, igmpQueryFrame(mac(2)), now)
	report := insertVLANTag(igmpReportFrame(mac(3), group, 0x16), 101, FrameInfo{})
	if verdict := s.Forward(3, report, now.Add(time.Second)); verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{1}) {
		t.Fatalf("PVLAN secondary report did not reach primary MVR router: %+v", verdict)
	}

	frame := ipv4MulticastFrame(mac(1), group)
	verdict := s.Forward(1, frame, now.Add(2*time.Second))
	if verdict.Drop != L2Forward || !reflect.DeepEqual(verdict.Out, []PortID{3}) {
		t.Fatalf("MVR did not use PVLAN secondary membership: %+v", verdict)
	}
	egress := verdict.FrameFor(3, frame)
	if got := binary.BigEndian.Uint16(egress[14:16]) & 0x0fff; got != 101 {
		t.Fatalf("MVR PVLAN trunk egress tag = %d, want receiver secondary VLAN 101: %x", got, egress[:18])
	}
}

func TestMVRConfigValidationRejectsUnsafeOrIncompleteMappings(t *testing.T) {
	validPort := []L2PortConfig{{ID: 1, VLAN: L2VLANPolicy{AccessVLAN: 100}, MulticastRouter: true}, {ID: 2, VLAN: L2VLANPolicy{AccessVLAN: 10}}}
	valid := L2MVRConfig{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}}}
	if err := (L2SwitchConfig{MVR: &valid, Ports: validPort}).Validate(); err != nil {
		t.Fatalf("valid MVR rejected: %v", err)
	}
	for _, config := range []L2MVRConfig{
		{MulticastVLAN: 0, Groups: valid.Groups},
		{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("224.0.0.251"), ReceiverVLAN: 10}}},
		{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 100}}},
		{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10}, {Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 20}}},
		{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLAN: 10, ReceiverVLANs: []uint16{20}}}},
		{MulticastVLAN: 100, Groups: []L2MVRGroup{{Group: netip.MustParseAddr("239.3.3.3"), ReceiverVLANs: []uint16{10, 10}}}},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid MVR config accepted: %+v", config)
		}
	}
	noSource := []L2PortConfig{{ID: 1, VLAN: L2VLANPolicy{AccessVLAN: 100}}, validPort[1]}
	if err := (L2SwitchConfig{MVR: &valid, Ports: noSource}).Validate(); err == nil {
		t.Fatal("MVR accepted without a multicast-router source port")
	}
}
