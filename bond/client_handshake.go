package bond

import (
	"crypto/rand"
	"crypto/subtle"
	"time"
)

// ClientHandshake is the per-path client half of the GB03 HELLO / CHALLENGE /
// RESET / READY exchange. It ports the client branches of gamebond/transport.py
// (Node.maintenance and Node._handshake) and is the counterpart of
// ServerHandshake. It owns nothing but the nonces of one path; the caller owns
// path readiness, peer adoption and replay state, exactly as the Python Node does.
//
// Like ServerHandshake it must only be fed packets already authenticated by
// Codec.Decode. HELLO and CHALLENGE never pin a peer prefix; only a READY that
// proves both nonces does.
type ClientHandshake struct {
	hello           [16]byte
	hasHello        bool
	started         time.Time
	server          [16]byte
	hasServer       bool
	challengePrefix [16]byte
}

// Pending reports whether a handshake attempt is in flight.
func (h *ClientHandshake) Pending() bool { return h.hasHello }

// Poll returns the control datagram a client path should send on this tick.
// Call it only when the path is not ready or has been silent for the path
// timeout (the Python condition `not path.ready or now - path.last_rx >=
// path_timeout`). ready is the path's current readiness. restarted is true when
// a fresh attempt began, in which case the caller must mark the path not ready.
// The result is HELLO until a CHALLENGE has been accepted, then RESET.
func (h *ClientHandshake) Poll(ready bool, now time.Time) (kind byte, payload []byte, restarted bool, err error) {
	if ready || !h.hasHello || now.Sub(h.started) >= handshakeLifetime {
		if _, err = rand.Read(h.hello[:]); err != nil {
			return 0, nil, false, err
		}
		h.hasHello, h.started = true, now
		h.hasServer = false
		h.challengePrefix = [16]byte{}
		restarted = true
	}
	if !h.hasServer {
		return Hello, append([]byte(nil), h.hello[:]...), restarted, nil
	}
	return Reset, append(append([]byte(nil), h.server[:]...), h.hello[:]...), restarted, nil
}

// ClientReply is a control datagram to send in answer to a handshake packet.
type ClientReply struct {
	Kind    byte
	Payload []byte
}

// Handle consumes an authenticated CHALLENGE or READY. reply is non-nil when a
// RESET must be sent. ready is true exactly once per attempt, when READY proves
// the server echoed both nonces under the prefix that issued the challenge; peer
// is that prefix and the caller must adopt it. ok is false for anything
// unexpected, stale or forged, and changes no state.
func (h *ClientHandshake) Handle(packet Packet, now time.Time) (reply *ClientReply, ready bool, peer [16]byte, ok bool) {
	kind, payload := packet.Header.Kind, packet.Payload
	if (kind != Challenge && kind != Ready) || len(payload) != 32 ||
		!h.hasHello || now.Sub(h.started) >= handshakeLifetime {
		return nil, false, peer, false
	}
	if kind == Challenge {
		if subtle.ConstantTimeCompare(payload[16:], h.hello[:]) != 1 {
			return nil, false, peer, false
		}
		copy(h.server[:], payload[:16])
		h.hasServer = true
		h.challengePrefix = packet.Header.Prefix
		return &ClientReply{Kind: Reset, Payload: append([]byte(nil), payload...)}, false, peer, true
	}
	expected := append(append([]byte(nil), h.hello[:]...), h.server[:]...)
	if !h.hasServer || h.challengePrefix != packet.Header.Prefix ||
		subtle.ConstantTimeCompare(payload, expected) != 1 {
		return nil, false, peer, false
	}
	peer = packet.Header.Prefix
	*h = ClientHandshake{}
	return nil, true, peer, true
}

// Restart begins a handshake attempt with a caller-chosen HELLO nonce (UDP
// recovery: path.hello_nonce=recovery nonce, hello_started=now, server cleared).
func (h *ClientHandshake) Restart(nonce [16]byte, now time.Time) {
	h.hello, h.hasHello, h.started = nonce, true, now
	h.hasServer = false
	h.challengePrefix = [16]byte{}
}
