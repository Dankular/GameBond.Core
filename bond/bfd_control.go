package bond

import "encoding/binary"

// BFD v1 control packet fields from RFC 5880 Section 4.1. Authentication is
// carried as an opaque RFC-defined section; callers remain responsible for
// validating it against the configured session authentication.
type BFDState uint8

const (
	BFDAdminDown BFDState = iota
	BFDDown
	BFDInit
	BFDUp
)

type BFDControlPacket struct {
	Version                   uint8
	Diagnostic                uint8
	State                     BFDState
	Poll, Final               bool
	ControlPlaneIndependent   bool
	Demand                    bool
	DetectMultiplier          uint8
	MyDiscriminator           uint32
	YourDiscriminator         uint32
	DesiredMinTXInterval      uint32
	RequiredMinRXInterval     uint32
	RequiredMinEchoRXInterval uint32
	AuthenticationSection     []byte
}

const bfdControlHeaderLength = 24

func validBFDControlAuthSection(auth []byte) bool {
	if len(auth) < 2 || int(auth[1]) != len(auth) {
		return false
	}
	switch auth[0] {
	case 1: // Simple Password: type, length, key ID, and 1-16 password bytes.
		return len(auth) >= 4 && len(auth) <= 19
	case 2, 3: // Keyed/Meticulous Keyed MD5.
		return len(auth) == 24
	case 4, 5: // Keyed/Meticulous Keyed SHA1.
		return len(auth) == 28
	default: // Reserved or unassigned authentication type.
		return false
	}
}

// EncodeBFDControl encodes an asynchronous BFD Control packet. BFD
// Authentication is optional in RFC 5880; when present, its encoded section
// is included verbatim after the fixed 24-byte header.
func EncodeBFDControl(p BFDControlPacket) ([]byte, error) {
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Version != 1 || p.Diagnostic > 31 || p.State > BFDUp || p.DetectMultiplier == 0 || p.MyDiscriminator == 0 || p.DesiredMinTXInterval == 0 {
		return nil, ErrFrame
	}
	if p.YourDiscriminator == 0 && p.State != BFDDown && p.State != BFDAdminDown {
		return nil, ErrFrame
	}
	if len(p.AuthenticationSection) > 0 {
		if len(p.AuthenticationSection) > 255 || !validBFDControlAuthSection(p.AuthenticationSection) {
			return nil, ErrFrame
		}
	}
	length := bfdControlHeaderLength + len(p.AuthenticationSection)
	if length > 255 {
		return nil, ErrFrame
	}
	packet := make([]byte, length)
	packet[0] = p.Version<<5 | p.Diagnostic&0x1f
	packet[1] = uint8(p.State) << 6
	if p.Poll {
		packet[1] |= 1 << 5
	}
	if p.Final {
		packet[1] |= 1 << 4
	}
	if p.ControlPlaneIndependent {
		packet[1] |= 1 << 3
	}
	if len(p.AuthenticationSection) > 0 {
		packet[1] |= 1 << 2
	}
	if p.Demand {
		packet[1] |= 1 << 1
	}
	packet[2], packet[3] = p.DetectMultiplier, uint8(length)
	binary.BigEndian.PutUint32(packet[4:8], p.MyDiscriminator)
	binary.BigEndian.PutUint32(packet[8:12], p.YourDiscriminator)
	binary.BigEndian.PutUint32(packet[12:16], p.DesiredMinTXInterval)
	binary.BigEndian.PutUint32(packet[16:20], p.RequiredMinRXInterval)
	binary.BigEndian.PutUint32(packet[20:24], p.RequiredMinEchoRXInterval)
	copy(packet[bfdControlHeaderLength:], p.AuthenticationSection)
	return packet, nil
}

// DecodeBFDControl parses one BFD v1 Control packet. It returns the number of
// bytes consumed so an encapsulation may carry padding after the declared BFD
// Length. Authentication bytes are exposed but never treated as authenticated.
func DecodeBFDControl(payload []byte) (BFDControlPacket, int, error) {
	if len(payload) < bfdControlHeaderLength {
		return BFDControlPacket{}, 0, ErrFrame
	}
	p := BFDControlPacket{
		Version:                   payload[0] >> 5,
		Diagnostic:                payload[0] & 0x1f,
		State:                     BFDState(payload[1] >> 6),
		Poll:                      payload[1]&(1<<5) != 0,
		Final:                     payload[1]&(1<<4) != 0,
		ControlPlaneIndependent:   payload[1]&(1<<3) != 0,
		Demand:                    payload[1]&(1<<1) != 0,
		DetectMultiplier:          payload[2],
		MyDiscriminator:           binary.BigEndian.Uint32(payload[4:8]),
		YourDiscriminator:         binary.BigEndian.Uint32(payload[8:12]),
		DesiredMinTXInterval:      binary.BigEndian.Uint32(payload[12:16]),
		RequiredMinRXInterval:     binary.BigEndian.Uint32(payload[16:20]),
		RequiredMinEchoRXInterval: binary.BigEndian.Uint32(payload[20:24]),
	}
	length := int(payload[3])
	authPresent := payload[1]&(1<<2) != 0
	minimum := bfdControlHeaderLength
	if authPresent {
		minimum += 2
	}
	if p.Version != 1 || p.State > BFDUp || p.DetectMultiplier == 0 || p.MyDiscriminator == 0 || p.DesiredMinTXInterval == 0 || payload[1]&1 != 0 || length < minimum || length > len(payload) {
		return BFDControlPacket{}, 0, ErrFrame
	}
	if p.YourDiscriminator == 0 && p.State != BFDDown && p.State != BFDAdminDown {
		return BFDControlPacket{}, 0, ErrFrame
	}
	if authPresent {
		auth := payload[bfdControlHeaderLength:length]
		if !validBFDControlAuthSection(auth) {
			return BFDControlPacket{}, 0, ErrFrame
		}
		p.AuthenticationSection = append([]byte(nil), auth...)
	}
	return p, length, nil
}
