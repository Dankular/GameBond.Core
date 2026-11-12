// Package bond implements the existing GB03 authenticated multipath protocol.
package bond

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	HeaderSize         = 45
	Overhead           = 61
	Data          byte = 1
	Probe         byte = 2
	Pong          byte = 3
	Striped       byte = 4
	Feedback      byte = 5
	Hello         byte = 6
	Challenge     byte = 7
	Reset         byte = 8
	Ready         byte = 9
	Repair        byte = 10
	LinkPolicy    byte = 11
	LinkPolicyAck byte = 12
	DataCopy      byte = 13
	MTUProbeKind  byte = 14
	MTUAck        byte = 15
	RepairNA      byte = 16
	CopyReport    byte = 17
	Parity        byte = 18
	BFD           byte = 19
	ParityRS      byte = 20
	VersionReq    byte = 21 // client -> server: payload is the client build id
	VersionInfo   byte = 22 // server -> client: payload is the server build id
	Supervision   byte = 23 // either way: this side's view of its own paths (IEC 62439-3 supervision)
)

var (
	ErrFrame          = errors.New("invalid GB03 frame")
	ErrAuthentication = errors.New("GB03 authentication failed")
	ErrNonceExhausted = errors.New("GB03 nonce domain exhausted")
)

type Header struct {
	Session  [16]byte
	Prefix   [16]byte
	Kind     byte
	Sequence uint64
}
type Packet struct {
	Header  Header
	Payload []byte
}
type rxKey struct {
	prefix [16]byte
	cipher cipher.AEAD
}

type Codec struct {
	key       [32]byte
	Session   [16]byte
	Prefix    [16]byte
	role      string
	tx        cipher.AEAD
	sequence  atomic.Uint64
	rxMutex   sync.Mutex
	rx        []rxKey
}

func NewCodec(key, session []byte, role string) (*Codec, error) {
	var prefix [16]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, err
	}
	return newCodec(key, session, role, prefix)
}

func newCodec(key, session []byte, role string, prefix [16]byte) (*Codec, error) {
	if len(key) != 32 || len(session) != 16 || (role != "client" && role != "server") {
		return nil, ErrFrame
	}
	c := &Codec{Prefix: prefix, role: role}
	copy(c.key[:], key)
	copy(c.Session[:], session)
	var err error
	c.tx, err = c.derive(prefix, role)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Codec) derive(prefix [16]byte, role string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, c.key[:], c.Session[:], "gamebond-v1/"+role+"/"+string(prefix[:]), 32)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

func (c *Codec) Encode(kind byte, payload []byte) ([]byte, error) {
	if kind < Data || kind > Supervision || len(payload)+Overhead > 65507 {
		return nil, ErrFrame
	}
	var sequence uint64
	for {
		sequence = c.sequence.Load()
		if sequence == math.MaxUint64 {
			return nil, ErrNonceExhausted
		}
		if c.sequence.CompareAndSwap(sequence, sequence+1) {
			break
		}
	}
	// Capacity for the sealed frame up front: Seal appends to the header, and a short
	// slice would reallocate and copy the whole frame once per packet.
	header := make([]byte, HeaderSize, HeaderSize+len(payload)+c.tx.Overhead())
	copy(header, []byte("GB03"))
	copy(header[4:20], c.Session[:])
	copy(header[20:36], c.Prefix[:])
	header[36] = kind
	binary.BigEndian.PutUint64(header[37:], sequence)
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return c.tx.Seal(header, nonce[:], payload, header), nil
}

func (c *Codec) Decode(frame []byte) (Packet, error) {
	var result Packet
	if len(frame) < Overhead || len(frame) > 65507 || string(frame[:4]) != "GB03" ||
		subtle.ConstantTimeCompare(frame[4:20], c.Session[:]) != 1 || frame[36] < Data || frame[36] > Supervision {
		return result, ErrFrame
	}
	copy(result.Header.Session[:], frame[4:20])
	copy(result.Header.Prefix[:], frame[20:36])
	result.Header.Kind = frame[36]
	result.Header.Sequence = binary.BigEndian.Uint64(frame[37:45])
	c.rxMutex.Lock()
	defer c.rxMutex.Unlock()
	var receiver cipher.AEAD
	for _, cached := range c.rx {
		if cached.prefix == result.Header.Prefix {
			receiver = cached.cipher
			break
		}
	}
	cached := receiver != nil
	if receiver == nil {
		role := "client"
		if c.role == "client" {
			role = "server"
		}
		var err error
		receiver, err = c.derive(result.Header.Prefix, role)
		if err != nil {
			return Packet{}, err
		}
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], result.Header.Sequence)
	plaintext, err := receiver.Open(nil, nonce[:], frame[HeaderSize:], frame[:HeaderSize])
	if err != nil {
		return Packet{}, ErrAuthentication
	}
	// Only authenticated domains enter this bounded cache.
	if !cached {
		if len(c.rx) >= 8 {
			copy(c.rx, c.rx[1:])
			c.rx = c.rx[:7]
		}
		c.rx = append(c.rx, rxKey{result.Header.Prefix, receiver})
	}
	result.Payload = plaintext
	return result, nil
}
