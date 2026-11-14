package bond

import (
	"encoding/binary"
	"errors"
	"time"
)

// Layer 2 carriage. An Ethernet frame travels as an ordinary Data payload behind one marker
// byte, so sequencing, duplication, SACK repair, FEC and reordering apply to it exactly as they
// do to an IP packet. The marker is 0xE2: the high nibble 0xE can never begin an IPv4 (4) or
// IPv6 (6) packet, so an L2 payload is never mistaken for IP and, when L2 carriage is off, it
// fails the IPv4 parse and is counted as malformed like any other junk.
const (
	L2Marker       byte = 0xE2
	EthHeaderLen        = 14
	vlanTagLen          = 4
	etherIPv4           = 0x0800
	etherARP            = 0x0806
	etherVLAN           = 0x8100
	etherIPv6           = 0x86DD
	etherEAPOL          = 0x888E
	etherLLDP           = 0x88CC
	etherSlowProto      = 0x8809
	l2ControlTag   byte = 46 // priority copies on every path, like game traffic
)

var ErrL2Frame = errors.New("invalid Ethernet frame")

// IsL2 reports whether a Data payload carries an Ethernet frame.
func IsL2(payload []byte) bool { return len(payload) > EthHeaderLen && payload[0] == L2Marker }

// WrapFrame returns the payload that carries frame.
func WrapFrame(frame []byte) []byte {
	out := make([]byte, 1+len(frame))
	out[0] = L2Marker
	copy(out[1:], frame)
	return out
}

// UnwrapFrame returns the Ethernet frame inside an L2 payload.
func UnwrapFrame(payload []byte) ([]byte, bool) {
	if !IsL2(payload) {
		return nil, false
	}
	return payload[1:], true
}

// FrameInfo is what the switch core and the classifier need to know about a frame.
type FrameInfo struct {
	Dst, Src  [6]byte
	EtherType uint16 // after any 802.1Q tag
	VLAN      uint16 // 0 when untagged; tags are carried through unmodified
	Multicast bool   // group bit set, including broadcast
	Broadcast bool
	Control   bool // ARP, ND, DHCP, IGMP, EAPOL, LLDP, BPDU/slow protocols: latency sensitive and tiny
	IP        *IPv4Info
}

// ParseFrame reads the Ethernet header, one optional 802.1Q tag, and the IPv4 header when the
// frame carries one.
func ParseFrame(frame []byte) (FrameInfo, error) {
	var f FrameInfo
	if len(frame) < EthHeaderLen {
		return f, ErrL2Frame
	}
	copy(f.Dst[:], frame[0:6])
	copy(f.Src[:], frame[6:12])
	f.EtherType = binary.BigEndian.Uint16(frame[12:14])
	body := frame[EthHeaderLen:]
	if f.EtherType == etherVLAN {
		if len(frame) < EthHeaderLen+vlanTagLen {
			return f, ErrL2Frame
		}
		f.VLAN = binary.BigEndian.Uint16(frame[14:16]) & 0x0fff
		f.EtherType = binary.BigEndian.Uint16(frame[16:18])
		body = frame[EthHeaderLen+vlanTagLen:]
	}
	f.Multicast = f.Dst[0]&1 == 1
	f.Broadcast = f.Dst == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	switch f.EtherType {
	case etherARP, etherEAPOL, etherLLDP, etherSlowProto:
		f.Control = true
	case etherIPv4:
		if p, err := ParseIPv4(body); err == nil {
			f.IP = &p
			f.Control = p.Protocol == 2 || (p.Protocol == 17 && p.HasPorts && isDHCP(p.SourcePort, p.DestinationPort))
		}
	case etherIPv6:
		// Neighbour discovery (ICMPv6 types 133-137) with no extension headers.
		f.Control = len(body) >= 41 && body[6] == 58 && body[40] >= 133 && body[40] <= 137
	}
	if f.Dst[0] == 0x01 && f.Dst[1] == 0x80 && f.Dst[2] == 0xc2 { // spanning tree and other bridge-group protocols
		f.Control = true
	}
	return f, nil
}

func isDHCP(a, b uint16) bool { return (a == 67 || a == 68) && (b == 67 || b == 68) }

// classifyFrame gives an Ethernet frame its queue policy: control frames are priority copies,
// an IPv4 frame is classified by its packet exactly as it would be without L2 carriage, and
// everything else is bulk keyed by its MAC pair so it still keeps its order.
func (s *Session) classifyFrame(payload []byte, now time.Time) (Classification, bool) {
	frame, _ := UnwrapFrame(payload)
	if len(frame) > s.options.L2MTU() {
		s.stats.L2Oversize++
		return Classification{}, false
	}
	info, err := ParseFrame(frame)
	if err != nil {
		s.stats.Malformed++
		return Classification{}, false
	}
	s.stats.L2Frames++
	if info.Control {
		s.stats.L2Control++
		return Classification{Info: IPv4Info{Flow: "l2:ctl", DSCP: l2ControlTag}, Tag: l2ControlTag, Policy: s.classifier.policyFor(l2ControlTag), Reason: "l2_control"}, true
	}
	if info.IP != nil {
		c := s.classifier.Classify(*info.IP, now)
		return c, true
	}
	flow := "l2:" + macPair(info.Src, info.Dst)
	return Classification{Info: IPv4Info{Flow: flow}, Tag: 0, Policy: s.classifier.policyFor(0), Reason: "l2_other"}, true
}

func macPair(a, b [6]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 25)
	for i, m := range [][6]byte{a, b} {
		if i == 1 {
			out = append(out, '>')
		}
		for _, v := range m {
			out = append(out, hex[v>>4], hex[v&15])
		}
	}
	return string(out)
}

// DefaultL2FrameMTU is the largest Ethernet frame carried by default: 1500 wire bytes minus
// IP/UDP (28) and the transport's 61 bytes leaves 1411; a 6-byte PRP trailer and 1492-byte
// (PPPoE) uplinks bring the bridged domain to an L3 MTU of 1380 plus the 14-byte header.
const DefaultL2FrameMTU = 1394

// L2MTU is the largest Ethernet frame this session carries.
func (o SessionOptions) L2MTU() int {
	if o.L2FrameMTU > 0 {
		return o.L2FrameMTU
	}
	return DefaultL2FrameMTU
}
