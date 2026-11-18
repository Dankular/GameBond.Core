package bond

import (
	"encoding/binary"
	"testing"
)

func ecnIPv4Packet(ecn byte) []byte {
	p := make([]byte, 28)
	p[0], p[1], p[9] = 0x45, 0xa8|ecn, 17 // Preserve DSCP 42.
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[24:26], 8)
	binary.BigEndian.PutUint16(p[10:12], 0x1234)
	return p
}

func ecnIPv6Packet(ecn byte) []byte {
	p := make([]byte, 48)
	trafficClass := byte(42<<2) | ecn
	p[0], p[1], p[4], p[6], p[7] = 0x60|trafficClass>>4, trafficClass<<4, 0, 17, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
	binary.BigEndian.PutUint16(p[44:46], 8)
	return p
}

func testPacketECN(packet []byte) byte {
	trafficClass, _ := innerTrafficClass(packet)
	return trafficClass & 3
}

func TestReceiveViaECNPropagatesAndCountsRFC6040(t *testing.T) {
	p := newClientServerPair(t)
	if err := p.server.SetECN(0, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	packet := ecnIPv4Packet(2) // ECT(0)
	frame, err := p.client.codec.Encode(Data, packet)
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.server.ReceiveViaECN(0, frame, p.src[0], p.now, true, 3)
	if err != nil || len(result.Deliver) != 1 {
		t.Fatalf("outer CE failed to deliver ECT packet: delivered=%d err=%v", len(result.Deliver), err)
	}
	if result.Deliver[0][1]&3 != 3 || checksum(result.Deliver[0][:20]) != 0 {
		t.Fatal("outer CE was not propagated with a valid inner IPv4 checksum")
	}

	packet = ecnIPv6Packet(1) // IPv6 ECT(1).
	frame, err = p.client.codec.Encode(Data, packet)
	if err != nil {
		t.Fatal(err)
	}
	result, err = p.server.ReceiveViaECN(0, frame, p.src[0], p.now, true, 3)
	if err != nil || len(result.Deliver) != 1 || testPacketECN(result.Deliver[0]) != 3 {
		t.Fatalf("outer CE was not propagated into inner IPv6: delivered=%d packet=%x err=%v", len(result.Deliver), result.Deliver, err)
	}
	stats := p.server.Stats()
	if stats.OuterECNCE != 2 || stats.InnerECNPropagated != 2 {
		t.Fatalf("RFC 6040 counters = %+v", stats)
	}

	packet = ecnIPv4Packet(0) // Not-ECT + outer CE is dropped by RFC 6040.
	frame, err = p.client.codec.Encode(Data, packet)
	if err != nil {
		t.Fatal(err)
	}
	result, err = p.server.ReceiveViaECN(0, frame, p.src[0], p.now, true, 3)
	if err != nil || len(result.Deliver) != 0 || p.server.Stats().InnerECNDropped != 1 {
		t.Fatalf("Not-ECT/CE handling: delivered=%d stats=%+v err=%v", len(result.Deliver), p.server.Stats(), err)
	}
}

func TestECNCapabilityNegotiatesPerPathBeforeMarking(t *testing.T) {
	p := newClientServerPair(t)
	if err := p.client.SetECN(0, true); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetECN(0, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		p.step()
		cp := p.client.paths[PathKey{0, p.srv}]
		sp := p.server.paths[PathKey{0, p.src[0]}]
		if cp != nil && sp != nil && cp.ecnPeer && sp.ecnPeer {
			break
		}
	}
	cp := p.client.paths[PathKey{0, p.srv}]
	sp := p.server.paths[PathKey{0, p.src[0]}]
	if cp == nil || sp == nil || !cp.ecnPeer || !sp.ecnPeer {
		t.Fatalf("capability exchange incomplete: client=%+v server=%+v", cp, sp)
	}
	otherClient := p.client.paths[PathKey{1, p.srv}]
	otherServer := p.server.paths[PathKey{0, p.src[1]}]
	if otherClient == nil || otherServer == nil || otherClient.ecnPeer || otherServer.ecnPeer {
		t.Fatalf("capability leaked across independent paths: client=%+v server=%+v", otherClient, otherServer)
	}
	payload := ecnIPv4Packet(2)
	if got := outerTrafficClassForPath(payload, cp); got != payload[1] {
		t.Fatalf("negotiated peer did not receive copied ECN: %#02x", got)
	}
	cp.ecnPeer = false
	if got := outerTrafficClassForPath(payload, cp); got != payload[1]&0xfc {
		t.Fatalf("unconfirmed peer received ECT marking: %#02x", got)
	}
}

func TestECNRemainsDisabledForPeersWithoutCapability(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12; i++ {
		p.step()
	}
	cp := p.client.paths[PathKey{0, p.srv}]
	sp := p.server.paths[PathKey{0, p.src[0]}]
	if cp == nil || sp == nil || cp.ecnPeer || sp.ecnPeer {
		t.Fatalf("unadvertised ECN capability was assumed: client=%+v server=%+v", cp, sp)
	}
	payload := ecnIPv4Packet(2)
	if got := outerTrafficClassForPath(payload, cp); got != payload[1]&0xfc {
		t.Fatalf("unnegotiated peer received ECT marking: %#02x", got)
	}
}

func TestPropagateTunnelECNRFC6040Table(t *testing.T) {
	want := [4][4]int{
		{0, 0, 0, -1},
		{1, 1, 1, 3}, // ECT(1)
		{2, 1, 2, 3}, // ECT(0)
		{3, 3, 3, 3}, // CE
	}
	for _, tc := range []struct {
		name string
		make func(byte) []byte
	}{
		{"IPv4", ecnIPv4Packet},
		{"IPv6", ecnIPv6Packet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for inner := byte(0); inner < 4; inner++ {
				for outer := byte(0); outer < 4; outer++ {
					got, err := PropagateTunnelECN(tc.make(inner), outer)
					if want[inner][outer] < 0 {
						if err == nil || got != nil {
							t.Fatalf("inner=%d outer=%d: expected drop, got packet=%v err=%v", inner, outer, got, err)
						}
						continue
					}
					trafficClass, ok := innerTrafficClass(got)
					if err != nil || !ok || testPacketECN(got) != byte(want[inner][outer]) || trafficClass>>2 != 42 {
						t.Fatalf("inner=%d outer=%d: got packet=%v err=%v, want ECN=%d with DSCP 42", inner, outer, got, err, want[inner][outer])
					}
					if tc.name == "IPv4" && testPacketECN(got) != inner && checksum(got[:20]) != 0 {
						t.Fatalf("inner=%d outer=%d: changed IPv4 header has invalid checksum", inner, outer)
					}
				}
			}
		})
	}
}

func TestPropagateTunnelECNRejectsMalformedValues(t *testing.T) {
	for _, tc := range []struct {
		packet []byte
		outer  byte
	}{{ecnIPv4Packet(0), 4}, {[]byte{0x45}, 0}, {ecnIPv4Packet(0)[:19], 0}, {ecnIPv6Packet(0)[:39], 0}, {append(ecnIPv6Packet(0), 1), 0}} {
		if _, err := PropagateTunnelECN(tc.packet, tc.outer); err == nil {
			t.Fatalf("accepted malformed packet/outer ECN: %#v", tc)
		}
	}
}

func TestOuterTrafficClassPreservesDSCPAndECN(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(byte) []byte
	}{
		{"IPv4", ecnIPv4Packet},
		{"IPv6", ecnIPv6Packet},
	} {
		packet := tc.make(2)
		if tc.name == "IPv4" {
			packet[1] = (46 << 2) | 2 // EF DSCP with ECT(0).
		} else {
			trafficClass := byte(46<<2) | 2
			packet[0] = packet[0]&0xf0 | trafficClass>>4
			packet[1] = trafficClass<<4 | packet[1]&0x0f
		}
		if got := outerTrafficClassForPayload(packet); got != 46<<2|2 {
			t.Errorf("%s outer traffic class = %#02x, want EF/ECT(0) %#02x", tc.name, got, 46<<2|2)
		}
	}
	if got := outerTrafficClassForPayload([]byte{0x45}); got != 0 {
		t.Fatalf("malformed/non-IPv4 payload traffic class = %#02x, want best effort", got)
	}
	packet := ecnIPv4Packet(0)
	for _, dscp := range []byte{1, 48, 56} { // unused DSCP passes through; CS6/CS7 are reset to DF.
		packet[1] = dscp<<2 | 1
		want := byte(1)
		if dscp == 1 {
			want = dscp<<2 | 1
		}
		if got := outerTrafficClassForPayload(packet); got != want {
			t.Errorf("DSCP %d produced outer DS field %#02x, want %#02x", dscp, got, want)
		}
	}
}

func checksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
