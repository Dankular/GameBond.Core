package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

var (
	testClientPrefix = [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	testServerPrefix = [16]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	testEndpoint     = netip.MustParseAddrPort("203.0.113.9:40000")
)

func fromClient(kind byte, payload []byte) Packet {
	return Packet{Header: Header{Prefix: testClientPrefix, Kind: kind}, Payload: payload}
}
func fromServer(kind byte, payload []byte) Packet {
	return Packet{Header: Header{Prefix: testServerPrefix, Kind: kind}, Payload: payload}
}

// handshakeToChallenge runs HELLO -> CHALLENGE and returns the RESET the client sent.
func handshakeToChallenge(t *testing.T, c *ClientHandshake, s *ServerHandshake, now time.Time) []byte {
	t.Helper()
	kind, hello, restarted, err := c.Poll(false, now)
	if err != nil || kind != Hello || !restarted || len(hello) != 16 {
		t.Fatalf("Poll = %d %d %v %v", kind, len(hello), restarted, err)
	}
	challenge, ok, err := s.Handle(fromClient(Hello, hello), testEndpoint, now)
	if err != nil || !ok || challenge.Kind != Challenge {
		t.Fatalf("server HELLO = %+v %v %v", challenge, ok, err)
	}
	reply, ready, _, ok := c.Handle(fromServer(Challenge, challenge.Payload), now)
	if !ok || ready || reply == nil || reply.Kind != Reset {
		t.Fatalf("client CHALLENGE = %+v %v %v", reply, ready, ok)
	}
	return reply.Payload
}

func TestClientHandshakeAgainstServer(t *testing.T) {
	now := time.Unix(1000, 0)
	var c ClientHandshake
	s := NewServerHandshake()
	reset := handshakeToChallenge(t, &c, s, now)

	ready, ok, err := s.Handle(fromClient(Reset, reset), testEndpoint, now)
	if err != nil || !ok || ready.Kind != Ready || !ready.FreshProof || !ready.AdoptPeer {
		t.Fatalf("server RESET = %+v %v %v", ready, ok, err)
	}
	_, done, peer, ok := c.Handle(fromServer(Ready, ready.Payload), now)
	if !ok || !done || peer != testServerPrefix {
		t.Fatalf("client READY = done %v ok %v peer %x", done, ok, peer)
	}
	if c.Pending() {
		t.Fatal("handshake still pending after READY")
	}
	// A READY replayed after completion must not be accepted again.
	if _, done, _, ok = c.Handle(fromServer(Ready, ready.Payload), now); ok || done {
		t.Fatal("replayed READY accepted")
	}
}

func TestClientHandshakeRetransmitsResetUntilReady(t *testing.T) {
	now := time.Unix(1000, 0)
	var c ClientHandshake
	s := NewServerHandshake()
	reset := handshakeToChallenge(t, &c, s, now)
	kind, payload, restarted, err := c.Poll(false, now.Add(500*time.Millisecond))
	if err != nil || kind != Reset || restarted || !bytes.Equal(payload, reset) {
		t.Fatalf("retransmit = %d restarted %v err %v", kind, restarted, err)
	}
}

func TestClientHandshakeRejectsForgeries(t *testing.T) {
	now := time.Unix(1000, 0)
	var c ClientHandshake
	s := NewServerHandshake()
	_, hello, _, _ := c.Poll(false, now)
	challenge, _, _ := s.Handle(fromClient(Hello, hello), testEndpoint, now)

	tamper := append([]byte(nil), challenge.Payload...)
	tamper[20] ^= 1 // client nonce echo no longer matches
	if _, _, _, ok := c.Handle(fromServer(Challenge, tamper), now); ok {
		t.Fatal("CHALLENGE with wrong client nonce accepted")
	}
	if _, _, _, ok := c.Handle(fromServer(Challenge, challenge.Payload[:31]), now); ok {
		t.Fatal("short CHALLENGE accepted")
	}
	// READY before any accepted CHALLENGE.
	if _, done, _, ok := c.Handle(fromServer(Ready, append(append([]byte(nil), hello...), make([]byte, 16)...)), now); ok || done {
		t.Fatal("READY accepted before CHALLENGE")
	}
	// Good CHALLENGE, then a READY under a different prefix than issued it.
	reply, _, _, ok := c.Handle(fromServer(Challenge, challenge.Payload), now)
	if !ok {
		t.Fatal("valid CHALLENGE rejected")
	}
	readyReply, _, _ := s.Handle(fromClient(Reset, reply.Payload), testEndpoint, now)
	other := Packet{Header: Header{Prefix: [16]byte{9}, Kind: Ready}, Payload: readyReply.Payload}
	if _, done, _, ok := c.Handle(other, now); ok || done {
		t.Fatal("READY from a different prefix accepted")
	}
	// Wrong nonce material under the right prefix.
	bad := append([]byte(nil), readyReply.Payload...)
	bad[0] ^= 1
	if _, done, _, ok := c.Handle(fromServer(Ready, bad), now); ok || done {
		t.Fatal("READY with wrong nonces accepted")
	}
	// The genuine one still completes: rejections must not have changed state.
	if _, done, _, ok := c.Handle(fromServer(Ready, readyReply.Payload), now); !ok || !done {
		t.Fatal("genuine READY rejected after forgeries")
	}
}

func TestClientHandshakeExpiryAndRestart(t *testing.T) {
	now := time.Unix(1000, 0)
	var c ClientHandshake
	s := NewServerHandshake()
	_, hello, _, _ := c.Poll(false, now)
	challenge, _, _ := s.Handle(fromClient(Hello, hello), testEndpoint, now)
	late := now.Add(handshakeLifetime)
	if _, _, _, ok := c.Handle(fromServer(Challenge, challenge.Payload), late); ok {
		t.Fatal("CHALLENGE accepted after the attempt expired")
	}
	// An expired attempt restarts with a new nonce, so the old challenge is dead.
	_, again, restarted, _ := c.Poll(false, late)
	if !restarted || bytes.Equal(hello, again) {
		t.Fatal("expired attempt did not restart with a fresh nonce")
	}
	if _, _, _, ok := c.Handle(fromServer(Challenge, challenge.Payload), late); ok {
		t.Fatal("stale CHALLENGE accepted after restart")
	}
	// A ready path that went silent restarts the exchange and drops readiness.
	_, third, restarted, _ := c.Poll(true, late.Add(time.Second))
	if !restarted || bytes.Equal(again, third) {
		t.Fatal("silent ready path did not restart")
	}
}
