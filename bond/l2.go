package bond

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Layer 2 carriage. An Ethernet frame travels as an ordinary Data payload behind one marker
// byte, so sequencing, duplication, SACK repair, FEC and reordering apply to it exactly as they
// do to an IP packet. The marker is 0xE2: the high nibble 0xE can never begin an IPv4 (4) or
// IPv6 (6) packet, so an L2 payload is never mistaken for IP and, when L2 carriage is off, it
// fails the IPv4 parse and is counted as malformed like any other junk.
const (
	L2Marker         byte = 0xE2
	EthHeaderLen          = 14
	vlanTagLen            = 4
	etherIPv4             = 0x0800
	etherARP              = 0x0806
	etherVLAN             = 0x8100
	etherIPv6             = 0x86DD
	etherEAPOL            = 0x888E
	etherLLDP             = 0x88CC
	etherSlowProto        = 0x8809
	etherVLANService      = 0x88A8
	etherVLAN9100         = 0x9100
	l2ControlTag     byte = 46 // priority copies on every path, like game traffic
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
	Dst, Src                  [6]byte
	EtherType                 uint16 // after any 802.1Q tag
	VLAN                      uint16 // 0 when untagged; tags are carried through unmodified
	InnerVLAN                 uint16 // second 802.1Q customer VLAN in an explicit Q-in-Q frame
	VLANDepth                 uint8  // number of outer 802.1Q/802.1ad tags
	OuterVLANType             uint16 // TPID of the outer tag, when tagged
	InnerVLANType             uint16 // TPID of the inner tag, when stacked
	Multicast                 bool   // group bit set, including broadcast
	Broadcast                 bool
	BPDU                      bool // IEEE 802.1D/RSTP BPDU using the reserved bridge group address
	Control                   bool // ARP, ND, DHCP, IGMP, EAPOL, LLDP, BPDU/slow protocols: latency sensitive and tiny
	ControlClass              L2ControlClass
	IP                        *IPv4Info
	IGMPType                  byte
	IGMPQuery                 bool
	IGMPGroup                 [4]byte
	IGMPJoins                 [][4]byte
	IGMPLeaves                [][4]byte
	MulticastRecords          []MulticastRecord
	MulticastRecordsMalformed bool
	MLDJoins                  [][16]byte
	MLDLeaves                 [][16]byte
	MLDQuery                  bool
	RouterAdvertisement       bool
	RouterAdvertisementValid  bool
	IPv6PrefixAdvertisements  []IPv6PrefixAdvertisement
	IPv6GuardUnsafe           bool // malformed, fragmented, or opaque IPv6 extension chain
	ARPValid                  bool
	ARPOp                     uint16
	ARPSenderIP               netip.Addr
	ARPSenderMAC              [6]byte
	IPv4SourceIP              netip.Addr
	IPv6SourceIP              netip.Addr
	IPv6SourceValid           bool
	IPv6NDType                byte
	IPv6NDTargetIP            netip.Addr
	IPv6NDValid               bool
	IPv6NDValidated           bool // checksum, hop-limit, destination and ND-option checks passed
	IPv6NDChecksumValid       bool
	IPv6NDCodeValid           bool
	IPv6NDReservedValid       bool
	IPv6NDHopLimitValid       bool
	IPv6NDDestinationValid    bool
	IPv6NDOptionsValid        bool
	IPv6NDSourceLinkLayer     [6]byte
	IPv6NDSourceLinkLayerSet  bool
	IPv6NDTargetLinkLayer     [6]byte
	IPv6NDTargetLinkLayerSet  bool
	IPv6NDLinkLayerMatchesEth bool
	DHCPv6Client              bool
	IPv6DADNeighborSolicit    bool
	MulticastIP               [16]byte
	MulticastIPLen            uint8
	MulticastSource           [16]byte
	MulticastSourceLen        uint8
}

// L2ControlClass groups control frames for independent control-plane policing.
type L2ControlClass uint8

const (
	L2ControlOther L2ControlClass = iota
	L2ControlARP
	L2ControlDHCPv4
	L2ControlDHCPv6
	L2ControlNeighborDiscovery
	L2ControlRouterAdvertisement
	L2ControlMulticast
	L2ControlMDNS
	L2ControlLLDP
	L2ControlEAPOL
	l2ControlClassCount
)

// IPv6PrefixAdvertisement is one validated autonomous Prefix Information option.
type IPv6PrefixAdvertisement struct {
	Prefix            netip.Prefix
	ValidLifetime     uint32 // seconds from this advertisement; 0xffffffff is infinity
	PreferredLifetime uint32 // seconds from this advertisement
	Autonomous        bool
}

// MulticastRecord is one IGMPv3 Group Record or MLDv2 Multicast Address
// Record. Group and Sources use 16-byte storage; IPv4 addresses occupy the
// first four bytes. RecordType follows RFC 3376/RFC 3810 values 1..6.
type MulticastRecord struct {
	Family     uint8
	RecordType uint8
	Group      [16]byte
	Sources    [][16]byte
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
	offset := EthHeaderLen
	for tags := 0; isVLANTag(f.EtherType); tags++ {
		if tags == 2 || len(frame) < offset+vlanTagLen {
			return f, ErrL2Frame
		}
		tagType := f.EtherType
		vid := binary.BigEndian.Uint16(frame[offset:offset+2]) & 0x0fff
		f.VLANDepth++
		if tags == 0 {
			f.VLAN = vid
			f.OuterVLANType = tagType
		} else {
			f.InnerVLAN = vid
			f.InnerVLANType = tagType
		}
		f.EtherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += vlanTagLen
	}
	body := frame[offset:]
	f.Multicast = f.Dst[0]&1 == 1
	f.Broadcast = f.Dst == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	switch f.EtherType {
	case etherARP, etherEAPOL, etherLLDP, etherSlowProto:
		f.Control = true
		switch f.EtherType {
		case etherARP:
			f.ControlClass = L2ControlARP
		case etherEAPOL:
			f.ControlClass = L2ControlEAPOL
		case etherLLDP:
			f.ControlClass = L2ControlLLDP
		}
		if f.EtherType == etherARP && len(body) >= 28 && binary.BigEndian.Uint16(body[0:2]) == 1 && binary.BigEndian.Uint16(body[2:4]) == etherIPv4 && body[4] == 6 && body[5] == 4 {
			op := binary.BigEndian.Uint16(body[6:8])
			if op == 1 || op == 2 {
				f.ARPOp = op
				copy(f.ARPSenderMAC[:], body[8:14])
				var senderIP [4]byte
				copy(senderIP[:], body[14:18])
				f.ARPSenderIP = netip.AddrFrom4(senderIP)
				f.ARPValid = f.ARPSenderMAC == f.Src
			}
		}
	case etherIPv4:
		// Mark control-looking packets before validating the complete IPv4
		// datagram so malformed IGMP or UDP control traffic cannot evade CoPP.
		if len(body) >= 20 && body[0]>>4 == 4 {
			switch body[9] {
			case 2:
				f.Control, f.ControlClass = true, L2ControlMulticast
			case 17:
				ihl := int(body[0]&0x0f) * 4
				if ihl >= 20 && len(body) >= ihl+4 {
					sourcePort := binary.BigEndian.Uint16(body[ihl : ihl+2])
					destinationPort := binary.BigEndian.Uint16(body[ihl+2 : ihl+4])
					switch {
					case isDHCP(sourcePort, destinationPort):
						f.Control, f.ControlClass = true, L2ControlDHCPv4
					case isMDNS(sourcePort, destinationPort):
						f.Control, f.ControlClass = true, L2ControlMDNS
					}
				}
			}
		}
		if len(body) >= 28 && body[9] == 2 {
			ihl := int(body[0]&0x0f) * 4
			if ihl >= 20 && len(body) >= ihl+8 {
				totalLen := int(binary.BigEndian.Uint16(body[2:4]))
				if totalLen < ihl+8 || totalLen > len(body) {
					f.MulticastRecordsMalformed = true
				} else {
					igmp := body[ihl:totalLen]
					if igmp[0] == 0x11 && len(igmp) >= 8 { // IGMPv1/v2/v3 Membership Query.
						f.IGMPQuery = true
					}
					switch igmp[0] {
					case 0x16, 0x17:
						f.IGMPType = igmp[0]
						copy(f.IGMPGroup[:], igmp[4:8])
						if igmp[0] == 0x16 {
							f.IGMPJoins = append(f.IGMPJoins, f.IGMPGroup)
						} else {
							f.IGMPLeaves = append(f.IGMPLeaves, f.IGMPGroup)
						}
					case 0x22: // IGMPv3 Membership Report with zero or more group records.
						f.IGMPType = igmp[0]
						parseIGMPv3Records(igmp, &f)
					}
				}
			}
		}
		if p, err := ParseIPv4(body); err == nil {
			f.IP = &p
			f.IPv4SourceIP = netip.AddrFrom4(p.Source)
			if p.Destination[0] >= 224 && p.Destination[0] <= 239 {
				copy(f.MulticastIP[:4], p.Destination[:])
				f.MulticastIPLen = 4
				copy(f.MulticastSource[:4], p.Source[:])
				f.MulticastSourceLen = 4
			}
			if p.Protocol == 2 {
				f.Control = true
				f.ControlClass = L2ControlMulticast
			} else if p.Protocol == 17 && p.HasPorts {
				switch {
				case isDHCP(p.SourcePort, p.DestinationPort):
					f.Control = true
					f.ControlClass = L2ControlDHCPv4
				case isMDNS(p.SourcePort, p.DestinationPort):
					f.Control = true
					f.ControlClass = L2ControlMDNS
				}
			}
		}
	case etherIPv6:
		if len(body) >= 40 && body[0]>>4 == 6 {
			payloadLen := int(binary.BigEndian.Uint16(body[4:6]))
			if payloadLen <= len(body)-40 {
				f.IPv6SourceIP = netip.AddrFrom16([16]byte(body[8:24]))
				f.IPv6SourceValid = true
			}
		}
		f.RouterAdvertisement, f.IPv6GuardUnsafe = detectRouterAdvertisement(body)
		f.RouterAdvertisementValid, f.IPv6PrefixAdvertisements = parseIPv6RouterAdvertisement(body, f.Dst, f.Src)
		f.Control = f.Control || f.RouterAdvertisement
		if f.RouterAdvertisement {
			f.ControlClass = L2ControlRouterAdvertisement
		}
		nd := parseIPv6NeighborDiscovery(body, f.IPv6GuardUnsafe, f.Dst, f.Src)
		f.IPv6NDType, f.IPv6NDTargetIP, f.IPv6NDValid, f.IPv6GuardUnsafe = nd.typ, nd.target, nd.valid, nd.unsafe
		f.IPv6NDChecksumValid = nd.checksumValid
		f.IPv6NDCodeValid = nd.codeValid
		f.IPv6NDReservedValid = nd.reservedValid
		f.IPv6NDHopLimitValid = nd.hopLimitValid
		f.IPv6NDDestinationValid = nd.destinationValid
		f.IPv6NDOptionsValid = nd.optionsValid
		f.IPv6NDValidated = nd.validated
		f.IPv6NDSourceLinkLayer, f.IPv6NDSourceLinkLayerSet = nd.sourceLinkLayer, nd.sourceLinkLayerSet
		f.IPv6NDTargetLinkLayer, f.IPv6NDTargetLinkLayerSet = nd.targetLinkLayer, nd.targetLinkLayerSet
		f.IPv6NDLinkLayerMatchesEth = nd.linkLayerMatchesEth
		f.IPv6DADNeighborSolicit = nd.dadValid
		f.Control = f.Control || f.IPv6NDValid
		if f.IPv6NDValid && !f.RouterAdvertisement {
			f.ControlClass = L2ControlNeighborDiscovery
		}
		if len(body) >= 40 && body[24] == 0xff {
			copy(f.MulticastIP[:], body[24:40])
			f.MulticastIPLen = 16
			copy(f.MulticastSource[:], body[8:24])
			f.MulticastSourceLen = 16
		}
		// Neighbor Discovery control types with no extension headers. Enforce each
		// message's fixed minimum size before a source-guarded port permits it.
		if len(body) >= 40 && body[6] == 58 {
			payloadLen := int(binary.BigEndian.Uint16(body[4:6]))
			if payloadLen <= len(body)-40 && payloadLen > 0 {
				icmpLen := payloadLen
				if icmpLen <= len(body)-40 {
					switch body[40] {
					case 133, 134:
						f.Control = icmpLen >= 8
						if body[40] == 134 {
							f.Control = icmpLen >= 16
						}
					case 135, 136:
						f.Control = icmpLen >= 24
					case 137:
						f.Control = icmpLen >= 40
					}
				}
			}
		}
		// mDNS uses UDP/5353 on both IPv4 and IPv6. IPv6 base-header packets are
		// recognized here; extension-header parsing remains the responsibility of the endpoint.
		if len(body) >= 48 && body[6] == 17 {
			sourcePort, destinationPort := binary.BigEndian.Uint16(body[40:42]), binary.BigEndian.Uint16(body[42:44])
			udpLen := int(binary.BigEndian.Uint16(body[44:46]))
			payloadLen := int(binary.BigEndian.Uint16(body[4:6]))
			validUDP := udpLen >= 8 && udpLen <= payloadLen && udpLen <= len(body)-40
			if validUDP {
				if isMDNS(sourcePort, destinationPort) {
					f.Control = true
					f.ControlClass = L2ControlMDNS
				} else if (sourcePort == 546 && destinationPort == 547) || (sourcePort == 547 && destinationPort == 546) {
					f.Control = true
					f.ControlClass = L2ControlDHCPv6
				}
				f.DHCPv6Client = sourcePort == 546 && destinationPort == 547
			}
		}
		parseMLD(body, &f)
		if f.MLDQuery || len(f.MLDJoins) > 0 || len(f.MLDLeaves) > 0 {
			f.ControlClass = L2ControlMulticast
		}
	}
	if f.Dst[0] == 0x01 && f.Dst[1] == 0x80 && f.Dst[2] == 0xc2 { // spanning tree and other bridge-group protocols
		f.Control = true
	}
	if f.Dst == [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00} && len(body) >= 3 && body[0] == 0x42 && body[1] == 0x42 && body[2] == 0x03 {
		f.BPDU = true
	}
	return f, nil
}

type ipv6NDDetails struct {
	typ                 byte
	target              netip.Addr
	valid               bool
	unsafe              bool
	checksumValid       bool
	codeValid           bool
	reservedValid       bool
	hopLimitValid       bool
	destinationValid    bool
	optionsValid        bool
	sourceLinkLayer     [6]byte
	sourceLinkLayerSet  bool
	targetLinkLayer     [6]byte
	targetLinkLayerSet  bool
	linkLayerMatchesEth bool
	dadValid            bool
	validated           bool
	baseHeaderOnly      bool
}

// parseIPv6NeighborDiscovery finds NS/NA targets through a bounded extension
// chain and exposes the wire checks required by the switch's guarded SAVI
// learner. Parsing never creates or changes address bindings.
func parseIPv6NeighborDiscovery(ip []byte, unsafe bool, ethernetDestination, ethernetSource [6]byte) ipv6NDDetails {
	bad := ipv6NDDetails{unsafe: true}
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return bad
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if payloadLen > len(ip)-40 {
		return bad
	}
	end, offset, next := 40+payloadLen, 40, ip[6]
	baseHeaderOnly := next == 58
	for depth := 0; depth < 8; depth++ {
		switch next {
		case 58:
			if offset >= end {
				return bad
			}
			typ := ip[offset]
			if typ != 135 && typ != 136 {
				return ipv6NDDetails{unsafe: unsafe}
			}
			if offset+24 > end {
				return ipv6NDDetails{typ: typ, unsafe: true}
			}
			var rawTarget [16]byte
			copy(rawTarget[:], ip[offset+8:offset+24])
			target := netip.AddrFrom16(rawTarget)
			if target.IsUnspecified() || target.IsMulticast() {
				return ipv6NDDetails{typ: typ, target: target, unsafe: true}
			}
			source := netip.AddrFrom16([16]byte(ip[8:24]))
			destination := netip.AddrFrom16([16]byte(ip[24:40]))
			icmp := ip[offset:end]
			reservedValid := false
			if typ == 135 {
				reservedValid = icmp[1] == 0 && icmp[4] == 0 && icmp[5] == 0 && icmp[6] == 0 && icmp[7] == 0
			} else {
				reservedValid = icmp[1] == 0 && icmp[4]&0x1f == 0 && icmp[5] == 0 && icmp[6] == 0 && icmp[7] == 0
			}
			details := ipv6NDDetails{
				typ: typ, target: target, valid: true, unsafe: unsafe,
				checksumValid: ipv6ICMPChecksum(ip[8:24], ip[24:40], icmp) == 0,
				codeValid:     icmp[1] == 0, reservedValid: reservedValid,
				hopLimitValid: ip[7] == 255,
				optionsValid:  true, baseHeaderOnly: baseHeaderOnly,
			}
			details.destinationValid = validNeighborDiscoveryDestination(typ, target, destination, ethernetDestination, ip[offset+4]&0x40 != 0)
			for optionOffset := offset + 24; optionOffset < end; {
				if end-optionOffset < 2 {
					details.optionsValid = false
					break
				}
				optionType, optionUnits := icmp[optionOffset-offset], int(icmp[optionOffset-offset+1])
				optionLen := optionUnits * 8
				if optionUnits == 0 || optionLen > end-optionOffset {
					details.optionsValid = false
					break
				}
				option := ip[optionOffset : optionOffset+optionLen]
				switch optionType {
				case 1: // Source Link-Layer Address.
					if typ != 135 || details.sourceLinkLayerSet || optionLen != 8 {
						details.optionsValid = false
					} else {
						copy(details.sourceLinkLayer[:], option[2:8])
						details.sourceLinkLayerSet = true
						if !validNDLinkLayer(details.sourceLinkLayer) {
							details.optionsValid = false
						}
					}
				case 2: // Target Link-Layer Address.
					if typ != 136 || details.targetLinkLayerSet || optionLen != 8 {
						details.optionsValid = false
					} else {
						copy(details.targetLinkLayer[:], option[2:8])
						details.targetLinkLayerSet = true
						if !validNDLinkLayer(details.targetLinkLayer) {
							details.optionsValid = false
						}
					}
				}
				optionOffset += optionLen
			}
			details.linkLayerMatchesEth = typ == 135 && details.sourceLinkLayerSet && details.sourceLinkLayer == ethernetSource ||
				typ == 136 && details.targetLinkLayerSet && details.targetLinkLayer == ethernetSource
			// DAD must use an unspecified IPv6 source, the target's solicited-node
			// multicast destination, a valid Ethernet mapping, and no SLLAO.
			details.dadValid = typ == 135 && baseHeaderOnly && source.IsUnspecified() &&
				details.checksumValid && details.codeValid && details.reservedValid && details.hopLimitValid && details.destinationValid && details.optionsValid && !details.sourceLinkLayerSet
			if typ == 135 && source.IsUnspecified() {
				details.dadValid = details.dadValid && ethernetSource != [6]byte{} && ethernetSource[0]&1 == 0
			}
			details.validated = details.valid && validNDLinkLayer(ethernetSource) && details.checksumValid && details.codeValid && details.reservedValid && details.hopLimitValid && details.destinationValid && details.optionsValid &&
				(typ != 135 || !source.IsUnspecified() || details.dadValid) && (typ != 136 || details.linkLayerMatchesEth)
			if typ == 135 && details.sourceLinkLayerSet && details.sourceLinkLayer != ethernetSource {
				details.validated = false
			}
			return details
		case 0, 43, 60, 135, 139, 140:
			if offset+2 > end {
				return bad
			}
			length := (int(ip[offset+1]) + 1) * 8
			if length < 8 || offset+length > end {
				return bad
			}
			next, offset = ip[offset], offset+length
		case 51:
			if offset+2 > end {
				return bad
			}
			length := (int(ip[offset+1]) + 2) * 4
			if length < 8 || offset+length > end {
				return bad
			}
			next, offset = ip[offset], offset+length
		case 44, 50:
			return bad
		default:
			return ipv6NDDetails{unsafe: unsafe}
		}
	}
	return bad
}

func validNDLinkLayer(mac [6]byte) bool {
	return mac != [6]byte{} && mac[0]&1 == 0
}

func validNeighborDiscoveryDestination(typ byte, target, destination netip.Addr, ethernetDestination [6]byte, solicited bool) bool {
	if !destination.Is6() || destination.IsUnspecified() {
		return false
	}
	if typ == 135 {
		if destination.IsMulticast() {
			expected := solicitedNodeAddress(target)
			return destination == expected && ethernetDestination == ipv6MulticastMAC(expected)
		}
		return destination == target
	}
	if solicited && destination.IsMulticast() {
		return false
	}
	if destination.IsMulticast() {
		allNodes := netip.MustParseAddr("ff02::1")
		return destination == allNodes && ethernetDestination == ipv6MulticastMAC(allNodes)
	}
	return true
}

func solicitedNodeAddress(target netip.Addr) netip.Addr {
	var raw [16]byte
	copy(raw[:], netip.MustParseAddr("ff02::1:ff00:0").AsSlice())
	t := target.As16()
	raw[13], raw[14], raw[15] = t[13], t[14], t[15]
	return netip.AddrFrom16(raw)
}

func ipv6MulticastMAC(address netip.Addr) [6]byte {
	var mac [6]byte
	if address.Is6() && address.IsMulticast() {
		raw := address.As16()
		mac = [6]byte{0x33, 0x33, raw[12], raw[13], raw[14], raw[15]}
	}
	return mac
}

func ipv6ICMPChecksum(source, destination, payload []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	add(source)
	add(destination)
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[:4], uint32(len(payload)))
	pseudo[7] = 58
	add(pseudo[:])
	add(payload)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseIPv6RouterAdvertisement validates the RA envelope and extracts autonomous
// /64 Prefix Information options. RA parsing is independent from RA Guard: even
// an invalid advertisement remains recognizable so an untrusted access port
// can be blocked by the guard.
func parseIPv6RouterAdvertisement(ip []byte, ethernetDestination, ethernetSource [6]byte) (bool, []IPv6PrefixAdvertisement) {
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return false, nil
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if payloadLen > len(ip)-40 {
		return false, nil
	}
	end, offset, next := 40+payloadLen, 40, ip[6]
	for depth := 0; depth < 8; depth++ {
		switch next {
		case 58:
			if offset+16 > end || ip[offset] != 134 || ip[offset+1] != 0 || ip[7] != 255 || !validNDLinkLayer(ethernetSource) {
				return false, nil
			}
			source := netip.AddrFrom16([16]byte(ip[8:24]))
			destination := netip.AddrFrom16([16]byte(ip[24:40]))
			if !source.IsLinkLocalUnicast() || !validRouterAdvertisementDestination(destination, ethernetDestination) {
				return false, nil
			}
			icmp := ip[offset:end]
			if ipv6ICMPChecksum(ip[8:24], ip[24:40], icmp) != 0 {
				return false, nil
			}
			var advertisements []IPv6PrefixAdvertisement
			seen := make(map[netip.Prefix]IPv6PrefixAdvertisement)
			for optionOffset := offset + 16; optionOffset < end; {
				if end-optionOffset < 2 {
					return false, nil
				}
				optionType, units := ip[optionOffset], int(ip[optionOffset+1])
				optionLen := units * 8
				if units == 0 || optionLen > end-optionOffset {
					return false, nil
				}
				option := ip[optionOffset : optionOffset+optionLen]
				switch optionType {
				case 1: // Source Link-Layer Address.
					if optionLen != 8 || !bytes.Equal(option[2:8], ethernetSource[:]) {
						return false, nil
					}
				case 3: // Prefix Information.
					if optionLen != 32 {
						return false, nil
					}
					prefixBits := int(option[2])
					if option[3]&0x3f != 0 || binary.BigEndian.Uint32(option[12:16]) != 0 {
						return false, nil
					}
					validLifetime := binary.BigEndian.Uint32(option[4:8])
					preferredLifetime := binary.BigEndian.Uint32(option[8:12])
					if preferredLifetime > validLifetime {
						return false, nil
					}
					if prefixBits == 64 {
						var raw [16]byte
						copy(raw[:], option[16:32])
						prefix := netip.PrefixFrom(netip.AddrFrom16(raw), prefixBits).Masked()
						if prefix.Addr().As16() != raw || prefix.Addr().IsMulticast() || prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsUnspecified() {
							return false, nil
						}
						advertisement := IPv6PrefixAdvertisement{Prefix: prefix, ValidLifetime: validLifetime, PreferredLifetime: preferredLifetime, Autonomous: option[3]&0x40 != 0}
						if previous, duplicate := seen[prefix]; duplicate && previous != advertisement {
							return false, nil
						}
						seen[prefix] = advertisement
					}
				}
				optionOffset += optionLen
			}
			for _, advertisement := range seen {
				advertisements = append(advertisements, advertisement)
			}
			return true, advertisements
		case 0, 43, 60, 135, 139, 140:
			if offset+2 > end {
				return false, nil
			}
			length := (int(ip[offset+1]) + 1) * 8
			if length < 8 || offset+length > end {
				return false, nil
			}
			next, offset = ip[offset], offset+length
		case 51:
			if offset+2 > end {
				return false, nil
			}
			length := (int(ip[offset+1]) + 2) * 4
			if length < 8 || offset+length > end {
				return false, nil
			}
			next, offset = ip[offset], offset+length
		case 44, 50:
			return false, nil
		default:
			return false, nil
		}
	}
	return false, nil
}

func validRouterAdvertisementDestination(destination netip.Addr, ethernetDestination [6]byte) bool {
	if destination == netip.MustParseAddr("ff02::1") {
		return ethernetDestination == [6]byte{0x33, 0x33, 0, 0, 0, 1}
	}
	return destination.Is6() && !destination.IsMulticast() && !destination.IsUnspecified() && validNDLinkLayer(ethernetDestination) && ethernetDestination[0]&1 == 0
}

// detectRouterAdvertisement walks the bounded IPv6 extension chain so an
// access-port RA guard cannot be bypassed by placing ICMPv6 behind extension
// headers. IPv6 fragments and ESP are reported unsafe because the RA type
// cannot be inspected reliably; Neighbor Discovery must not be fragmented.
func detectRouterAdvertisement(ip []byte) (advertisement, unsafe bool) {
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return false, true
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if payloadLen > len(ip)-40 {
		return false, true
	}
	end := 40 + payloadLen
	next := ip[6]
	offset := 40
	for depth := 0; depth < 8; depth++ {
		switch next {
		case 58: // ICMPv6
			if offset >= end {
				return false, true
			}
			return ip[offset] == 134, false
		case 0, 43, 60, 135, 139, 140: // Hop-by-Hop, Routing, Destination, Mobility, HIP, Shim6
			if offset+2 > end {
				return false, true
			}
			length := (int(ip[offset+1]) + 1) * 8
			if length < 8 || offset+length > end {
				return false, true
			}
			next, offset = ip[offset], offset+length
		case 51: // Authentication Header
			if offset+2 > end {
				return false, true
			}
			length := (int(ip[offset+1]) + 2) * 4
			if length < 8 || offset+length > end {
				return false, true
			}
			next, offset = ip[offset], offset+length
		case 44, 50: // Fragment or ESP: fail closed on guarded ports.
			return false, true
		default:
			return false, false
		}
	}
	return false, true
}

func parseMLD(ip []byte, f *FrameInfo) {
	if len(ip) < 48 || ip[6] != 0 { // MLD uses an IPv6 Hop-by-Hop header with Router Alert.
		return
	}
	extLen := (int(ip[41]) + 1) * 8
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if extLen < 8 || payloadLen < extLen+8 || payloadLen > len(ip)-40 || len(ip) < 40+extLen+8 || ip[40] != 58 {
		return
	}
	ipEnd := 40 + payloadLen
	icmp := ip[40+extLen : ipEnd]
	switch icmp[0] {
	case 130: // MLDv1/v2 Multicast Listener Query.
		if len(icmp) >= 24 {
			f.MLDQuery = true
		}
	case 131, 132: // MLDv1 report/done
		if len(icmp) < 24 {
			return
		}
		var group [16]byte
		copy(group[:], icmp[8:24])
		if group[0] != 0xff {
			return
		}
		if icmp[0] == 131 {
			f.MLDJoins = append(f.MLDJoins, group)
		} else {
			f.MLDLeaves = append(f.MLDLeaves, group)
		}
	case 143: // MLDv2 report
		parseMLDv2Records(icmp, f)
	}
	if icmp[0] == 130 || icmp[0] == 131 || icmp[0] == 132 || icmp[0] == 143 {
		f.Control = true
	}
}

func parseMLDv2Records(icmp []byte, f *FrameInfo) {
	if len(icmp) < 8 {
		f.MulticastRecordsMalformed = true
		return
	}
	count, offset := int(binary.BigEndian.Uint16(icmp[6:8])), 8
	for i := 0; i < count; i++ {
		if len(icmp)-offset < 20 {
			f.MulticastRecordsMalformed = true
			return
		}
		record := icmp[offset:]
		typ, auxWords := record[0], int(record[1])
		sources := int(binary.BigEndian.Uint16(record[2:4]))
		size := 20 + sources*16 + auxWords*4
		if size > len(icmp)-offset {
			f.MulticastRecordsMalformed = true
			return
		}
		if typ < 1 || typ > 6 {
			offset += size
			continue // RFC 3810: ignore unknown record types and process the rest.
		}
		var group [16]byte
		copy(group[:], record[4:20])
		if group[0] != 0xff || group[1]&0x0f == 0 {
			f.MulticastRecordsMalformed = true
			return
		}
		decoded := MulticastRecord{Family: 16, RecordType: typ, Group: group}
		for sourceOffset := 20; sourceOffset < 20+sources*16; sourceOffset += 16 {
			var source [16]byte
			copy(source[:], record[sourceOffset:sourceOffset+16])
			if source == [16]byte{} || source[0] == 0xff {
				f.MulticastRecordsMalformed = true
				return
			}
			decoded.Sources = append(decoded.Sources, source)
		}
		f.MulticastRecords = append(f.MulticastRecords, decoded)
		if (typ == 1 || typ == 3) && sources == 0 {
			f.MLDLeaves = append(f.MLDLeaves, group)
		} else if typ >= 1 && typ <= 6 {
			f.MLDJoins = append(f.MLDJoins, group)
		}
		offset += size
	}
	if offset != len(icmp) {
		f.MulticastRecordsMalformed = true
	}
}

func parseIGMPv3Records(igmp []byte, f *FrameInfo) {
	if len(igmp) < 8 {
		f.MulticastRecordsMalformed = true
		return
	}
	count := int(binary.BigEndian.Uint16(igmp[6:8]))
	offset := 8
	for i := 0; i < count; i++ {
		if len(igmp)-offset < 8 {
			f.MulticastRecordsMalformed = true
			return
		}
		record := igmp[offset:]
		typ, auxWords := record[0], int(record[1])
		sources := int(binary.BigEndian.Uint16(record[2:4]))
		size := 8 + sources*4 + auxWords*4
		if size > len(igmp)-offset {
			f.MulticastRecordsMalformed = true
			return
		}
		if typ < 1 || typ > 6 {
			offset += size
			continue // RFC 3376: ignore unknown record types and process the rest.
		}
		var group [4]byte
		copy(group[:], record[4:8])
		if group[0] < 224 || group[0] > 239 {
			f.MulticastRecordsMalformed = true
			return
		}
		decoded := MulticastRecord{Family: 4, RecordType: typ}
		copy(decoded.Group[:4], group[:])
		for sourceOffset := 8; sourceOffset < 8+sources*4; sourceOffset += 4 {
			var source [16]byte
			copy(source[:4], record[sourceOffset:sourceOffset+4])
			if source[0] == 0 || source[0] >= 224 {
				f.MulticastRecordsMalformed = true
				return
			}
			decoded.Sources = append(decoded.Sources, source)
		}
		f.MulticastRecords = append(f.MulticastRecords, decoded)
		if typ == 1 || typ == 3 {
			if sources == 0 {
				f.IGMPLeaves = append(f.IGMPLeaves, group)
			} else {
				f.IGMPJoins = append(f.IGMPJoins, group)
			}
		} else if typ >= 2 && typ <= 6 {
			f.IGMPJoins = append(f.IGMPJoins, group)
		}
		offset += size
	}
	if offset != len(igmp) {
		f.MulticastRecordsMalformed = true
	}
}

func isVLANTag(etherType uint16) bool {
	return etherType == etherVLAN || etherType == etherVLANService || etherType == etherVLAN9100
}

func isDHCP(a, b uint16) bool { return (a == 67 || a == 68) && (b == 67 || b == 68) }
func isMDNS(a, b uint16) bool { return a == 5353 || b == 5353 }

// ClassifyFrame gives an Ethernet frame its queue policy: control frames are priority copies,
// an IPv4 frame is classified by its packet exactly as it would be without L2 carriage, and
// everything else is bulk keyed by its MAC pair so it still keeps its order. It is shared by the
// session (server) and the client's own queue so both ends treat a frame the same way.
func (c *Classifier) ClassifyFrame(frame []byte, now time.Time) (Classification, FrameInfo, error) {
	info, err := ParseFrame(frame)
	if err != nil {
		return Classification{}, info, err
	}
	if info.Control {
		return Classification{Info: IPv4Info{Flow: "l2:ctl", DSCP: l2ControlTag}, Tag: l2ControlTag, Policy: c.policyFor(l2ControlTag), Reason: "l2_control"}, info, nil
	}
	if info.IP != nil {
		return c.Classify(*info.IP, now), info, nil
	}
	flow := "l2:" + macPair(info.Src, info.Dst)
	return Classification{Info: IPv4Info{Flow: flow}, Tag: 0, Policy: c.policyFor(0), Reason: "l2_other"}, info, nil
}

func (s *Session) classifyFrame(payload []byte, now time.Time) (Classification, bool) {
	frame, _ := UnwrapFrame(payload)
	if len(frame) > s.options.L2MTU() {
		s.stats.L2Oversize++
		return Classification{}, false
	}
	c, info, err := s.classifier.ClassifyFrame(frame, now)
	if err != nil {
		s.stats.Malformed++
		return Classification{}, false
	}
	s.stats.L2Frames++
	if info.Control {
		s.stats.L2Control++
	}
	return c, true
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
