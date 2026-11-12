package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func hello(prefix byte, nonce byte) Packet {
	var header Header
	header.Kind = Hello
	header.Prefix[0] = prefix
	return Packet{Header: header, Payload: bytes.Repeat([]byte{nonce}, 16)}
}

func reset(packet Packet, challenge HandshakeReply) Packet {
	packet.Header.Kind = Reset
	packet.Payload = append([]byte(nil), challenge.Payload...)
	return packet
}

func TestHandshakeRequiresFreshProofAndPreservesParallelPathChallenges(t *testing.T) {
	h := NewServerHandshake()
	now := time.Now()
	a, b := netip.MustParseAddrPort("127.0.0.1:1000"), netip.MustParseAddrPort("127.0.0.1:1001")
	first, second := hello(1, 2), hello(1, 3)
	ca, ok, err := h.Handle(first, a, now)
	if err != nil || !ok || ca.Kind != Challenge {
		t.Fatal("no first challenge")
	}
	cb, _, _ := h.Handle(second, b, now)
	wrong := reset(first, cb)
	if _, ok, _ := h.Handle(wrong, a, now); ok {
		t.Fatal("accepted another path's proof")
	}
	ra, ok, _ := h.Handle(reset(first, ca), a, now)
	if !ok || !ra.AdoptPeer || !ra.FreshProof || ra.Kind != Ready {
		t.Fatal("fresh proof not adopted")
	}
	rb, ok, _ := h.Handle(reset(second, cb), b, now)
	if !ok || rb.AdoptPeer || !rb.FreshProof {
		t.Fatal("parallel same-domain challenge discarded")
	}
	repeat, ok, _ := h.Handle(reset(first, ca), a, now.Add(time.Millisecond))
	if !ok || repeat.FreshProof || repeat.AdoptPeer {
		t.Fatal("lost READY retry semantics differ")
	}
	if _, ok, _ := h.Handle(reset(first, ca), a, now.Add(3*time.Second)); ok {
		t.Fatal("expired reset replay accepted")
	}
}

func TestOldRecordedResetCannotRollPeerBackAfterRestart(t *testing.T) {
	h := NewServerHandshake()
	now := time.Now()
	endpoint := netip.MustParseAddrPort("127.0.0.1:1000")
	old := hello(1, 2)
	challenge, _, _ := h.Handle(old, endpoint, now)
	oldReset := reset(old, challenge)
	h.Handle(oldReset, endpoint, now)
	current := hello(2, 3)
	challenge, _, _ = h.Handle(current, endpoint, now)
	reply, ok, _ := h.Handle(reset(current, challenge), endpoint, now)
	if !ok || !reply.AdoptPeer {
		t.Fatal("new peer not adopted")
	}
	if _, ok, _ := h.Handle(oldReset, endpoint, now); ok {
		t.Fatal("recorded old peer reset rolled domain back")
	}
}

func TestChallengeAndConfirmationStateRemainBounded(t *testing.T) {
	h := NewServerHandshake()
	now := time.Now()
	for i := 0; i < 100; i++ {
		h.Handle(hello(1, byte(i)), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+i)), now)
	}
	if len(h.pending) != 8 {
		t.Fatal("challenge cache is not bounded")
	}
	h.Handle(hello(1, 1), netip.MustParseAddrPort("127.0.0.1:2000"), now.Add(3*time.Second))
	if len(h.pending) != 1 {
		t.Fatal("expired challenges retained")
	}
}
