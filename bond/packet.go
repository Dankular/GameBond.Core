package bond

import "encoding/binary"

// PropagateTunnelECN applies RFC 6040 decapsulation rules to an inner IPv4 or
// IPv6 packet. outerECN is the ECN field from the outer IP header (0..3). The
// returned packet is a copy when its ECN field changes. A Not-ECT inner packet
// arriving with CE on the outer header must be dropped; this function returns
// ErrFrame for that invalid combination. DSCP bits are preserved.
func PropagateTunnelECN(inner []byte, outerECN byte) ([]byte, error) {
	if outerECN > 3 || len(inner) == 0 {
		return nil, ErrFrame
	}
	version := inner[0] >> 4
	var innerECN byte
	switch version {
	case 4:
		if len(inner) < 20 {
			return nil, ErrFrame
		}
		header := int(inner[0]&15) * 4
		if header < 20 || header > len(inner) || int(binary.BigEndian.Uint16(inner[2:])) != len(inner) {
			return nil, ErrFrame
		}
		innerECN = inner[1] & 3
	case 6:
		if len(inner) < 40 || int(binary.BigEndian.Uint16(inner[4:6])) != len(inner)-40 {
			return nil, ErrFrame
		}
		innerECN = (inner[1] >> 4) & 3
	default:
		return nil, ErrFrame
	}
	if innerECN == 0 && outerECN == 3 {
		return nil, ErrFrame
	}
	outECN := innerECN
	if innerECN == 0 {
		outECN = 0
	} else if ecnSeverity(outerECN) > ecnSeverity(innerECN) {
		outECN = outerECN
	}
	if outECN == innerECN {
		return inner, nil
	}
	out := append([]byte(nil), inner...)
	if version == 4 {
		header := int(out[0]&15) * 4
		out[1] = out[1]&0xfc | outECN
		out[10], out[11] = 0, 0
		sum := uint32(0)
		for i := 0; i < header; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(out[i:]))
		}
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(out[10:], ^uint16(sum))
	} else {
		trafficClass := ((out[0] & 0x0f) << 4) | (out[1] >> 4)
		trafficClass = trafficClass&0xfc | outECN
		out[0] = out[0]&0xf0 | trafficClass>>4
		out[1] = trafficClass<<4 | out[1]&0x0f
	}
	return out, nil
}

func ecnSeverity(ecn byte) byte {
	switch ecn { // RFC 6040: CE > ECT(1) > ECT(0) > Not-ECT.
	case 3:
		return 3
	case 1:
		return 2
	case 2:
		return 1
	default:
		return 0
	}
}

// outerTrafficClassForPayload preserves ECN and applies the RFC 8325 safe
// DSCP policy to the outer tunnel header. The inner packet is unchanged.
func outerTrafficClassForPayload(packet []byte) byte {
	trafficClass, ok := innerTrafficClass(packet)
	if !ok {
		return 0
	}
	dscp := WiFiSafeDSCP(trafficClass >> 2)
	return dscp<<2 | trafficClass&3
}

func innerTrafficClass(packet []byte) (byte, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return 0, false
		}
		return packet[1], true
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6])) != len(packet)-40 {
			return 0, false
		}
		return (packet[0]&0x0f)<<4 | packet[1]>>4, true
	default:
		return 0, false
	}
}

// outerTrafficClassForPath copies ECN only after the remote peer advertises
// RFC 6040 decapsulation support. DSCP remains available independently.
func outerTrafficClassForPath(packet []byte, p *receivePath) byte {
	trafficClass := outerTrafficClassForPayload(packet)
	if p == nil || !p.ecnPeer {
		trafficClass &= 0xfc
	}
	return trafficClass
}

type IPv4Info struct {
	Source, Destination           [4]byte
	Protocol, DSCP                byte
	Fragmented                    bool
	HeaderLength, TransportOffset int
	Length                        int // total IPv4 packet length
	Flow                          string // normalized bidirectional key used by policy/quality tracking
	QueueFlow                     string // directional binary IP tuple used by RFC 8290 flow hashing
	TCPControl                    bool
	SourcePort, DestinationPort   uint16
	HasPorts                      bool
	FragmentKey, PolicyFlow       string
	FallbackFlow                  string // address/protocol flow key when transport ports are unavailable
	FragmentOffset                int
}

func IsTCPControl(packet []byte) bool {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}
	offset := int(packet[0]&15) * 4
	if offset < 20 || offset+20 > len(packet) {
		return false
	}
	flags := packet[offset+13]
	if flags&7 == 0 && (flags&16 == 0 || offset+int(packet[offset+12]>>4)*4 != len(packet)) {
		return false
	}
	p, err := ParseIPv4(packet)
	return err == nil && p.TCPControl
}

// ParseIPv4 validates structural bounds without guessing an application from
// timing, size, or generic QUIC ports. Checksums remain the IP stack's job.
func ParseIPv4(packet []byte) (IPv4Info, error) {
	var p IPv4Info
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return p, ErrFrame
	}
	header := int(packet[0]&15) * 4
	if header < 20 || header > len(packet) || int(binary.BigEndian.Uint16(packet[2:])) != len(packet) {
		return p, ErrFrame
	}
	p.Protocol = packet[9]
	p.DSCP = packet[1] >> 2
	p.HeaderLength = header
	p.Length = len(packet)
	p.TransportOffset = header
	copy(p.Source[:], packet[12:16])
	copy(p.Destination[:], packet[16:20])
	p.FallbackFlow = tupleFlow(p.Protocol, p.Source, 0, p.Destination, 0)
	fragment := binary.BigEndian.Uint16(packet[6:])
	p.Fragmented = fragment&0x3fff != 0
	if p.Fragmented {
		length := len(packet) - header
		if length == 0 || (fragment&0x2000 != 0 && length%8 != 0) || int(fragment&0x1fff)*8+length > 65515 {
			return p, ErrFrame
		}
		key := make([]byte, 11)
		copy(key, p.Source[:])
		copy(key[4:], p.Destination[:])
		key[8] = p.Protocol
		copy(key[9:], packet[4:6])
		p.FragmentKey = string(key)
		// All IPv4 fragments for one datagram share a queue key. Noninitial
		// fragments do not carry transport ports, so hashing each by its
		// apparent fallback tuple would split/reorder the datagram.
		p.QueueFlow = p.FragmentKey
		p.FragmentOffset = int(fragment&0x1fff) * 8
		if p.FragmentOffset == 0 && p.Protocol == 17 {
			if header+8 > len(packet) {
				return p, ErrFrame
			}
			length := int(binary.BigEndian.Uint16(packet[header+4:]))
			if length <= len(packet)-header || length > 65535-header {
				return p, ErrFrame
			}
			p.SourcePort = binary.BigEndian.Uint16(packet[header:])
			p.DestinationPort = binary.BigEndian.Uint16(packet[header+2:])
			p.HasPorts = true
			p.PolicyFlow = normalizedFlow(p.Protocol, p.Source, p.Destination, p.SourcePort, p.DestinationPort)
		}
		return p, nil
	}
	if p.Protocol == 6 {
		if header+20 > len(packet) {
			return p, ErrFrame
		}
		tcpHeader := int(packet[header+12]>>4) * 4
		if tcpHeader < 20 || header+tcpHeader > len(packet) {
			return p, ErrFrame
		}
		flags := packet[header+13]
		p.TCPControl = flags&7 != 0 || (flags&16 != 0 && header+tcpHeader == len(packet))
	} else if p.Protocol == 17 {
		if header+8 > len(packet) || int(binary.BigEndian.Uint16(packet[header+4:])) != len(packet)-header {
			return p, ErrFrame
		}
	} else {
		p.QueueFlow = p.FallbackFlow
		return p, nil
	}
	p.HasPorts = true
	p.SourcePort = binary.BigEndian.Uint16(packet[header:])
	p.DestinationPort = binary.BigEndian.Uint16(packet[header+2:])
	p.Flow = normalizedFlow(p.Protocol, p.Source, p.Destination, p.SourcePort, p.DestinationPort)
	p.QueueFlow = tupleFlow(p.Protocol, p.Source, p.SourcePort, p.Destination, p.DestinationPort)
	p.PolicyFlow = p.Flow
	return p, nil
}

// tupleFlow encodes the RFC 8290 5-tuple as a fixed-width, directional byte
// string: protocol, source address/port, destination address/port. A protocol
// with no transport ports uses zero ports, a stable address/protocol subset.
func tupleFlow(protocol byte, source [4]byte, sport uint16, destination [4]byte, dport uint16) string {
	key := make([]byte, 13)
	key[0] = protocol
	copy(key[1:5], source[:])
	binary.BigEndian.PutUint16(key[5:7], sport)
	copy(key[7:11], destination[:])
	binary.BigEndian.PutUint16(key[11:13], dport)
	return string(key)
}

func normalizedFlow(protocol byte, source, destination [4]byte, sport, dport uint16) string {
	var a, b [6]byte
	copy(a[:4], source[:])
	binary.BigEndian.PutUint16(a[4:], sport)
	copy(b[:4], destination[:])
	binary.BigEndian.PutUint16(b[4:], dport)
	// Normalize endpoints so inbound app markings also classify return traffic.
	if string(a[:]) > string(b[:]) {
		a, b = b, a
	}
	key := make([]byte, 13)
	key[0] = protocol
	copy(key[1:7], a[:])
	copy(key[7:], b[:])
	return string(key)
}

// MarkGameUDP sets DSCP 46 on a UDP packet whose source or destination port is
// in ports, preserving ECN and recomputing the IPv4 header checksum. It mirrors
// userspace.mark_game_udp, including reading ports from any fragment. A packet
// that does not qualify is returned unchanged.
func MarkGameUDP(packet []byte, ports map[uint16]bool) ([]byte, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		return packet, nil
	}
	header := int(packet[0]&15) * 4
	if header < 20 || header > len(packet) {
		return nil, ErrFrame
	}
	if ports != nil {
		if len(packet) < header+8 {
			return packet, nil
		}
		if !ports[binary.BigEndian.Uint16(packet[header:])] && !ports[binary.BigEndian.Uint16(packet[header+2:])] {
			return packet, nil
		}
	}
	out := append([]byte(nil), packet...)
	out[1] = 46<<2 | out[1]&3
	out[10], out[11] = 0, 0
	sum := uint32(0)
	for i := 0; i+1 < header; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(out[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	binary.BigEndian.PutUint16(out[10:], ^uint16(sum))
	return out, nil
}
