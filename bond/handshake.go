package bond

import (
	"crypto/rand"
	"crypto/subtle"
	"net/netip"
	"time"
)

const handshakeLifetime = 2 * time.Second

type challengeKey struct {
	endpoint netip.AddrPort
	prefix   [16]byte
}
type challengeProof struct {
	client, server [16]byte
	expires        time.Time
}
type confirmation struct {
	proof   [32]byte
	expires time.Time
}

// ServerHandshake consumes only packets already authenticated by Codec.Decode.
// Recorded old challenges cannot replace the live peer's encryption domain.
type ServerHandshake struct {
	peer      [16]byte
	hasPeer   bool
	pending   map[challengeKey]challengeProof
	confirmed map[netip.AddrPort]confirmation
}

type HandshakeReply struct {
	Kind       byte
	Payload    []byte
	AdoptPeer  bool
	FreshProof bool
	Peer       [16]byte
}

func NewServerHandshake() *ServerHandshake {
	return &ServerHandshake{pending: make(map[challengeKey]challengeProof), confirmed: make(map[netip.AddrPort]confirmation)}
}

func (h *ServerHandshake) Handle(packet Packet, endpoint netip.AddrPort, now time.Time) (HandshakeReply, bool, error) {
	var reply HandshakeReply
	for key, proof := range h.pending {
		if !proof.expires.After(now) {
			delete(h.pending, key)
		}
	}
	for key, proof := range h.confirmed {
		if !proof.expires.After(now) {
			delete(h.confirmed, key)
		}
	}
	key := challengeKey{endpoint, packet.Header.Prefix}
	if packet.Header.Kind == Hello && len(packet.Payload) == 16 {
		var client [16]byte
		copy(client[:], packet.Payload)
		proof, ok := h.pending[key]
		if !ok || proof.client != client {
			if len(h.pending) >= 8 {
				var oldest challengeKey
				var expiry time.Time
				for candidate, value := range h.pending {
					if expiry.IsZero() || value.expires.Before(expiry) {
						oldest, expiry = candidate, value.expires
					}
				}
				delete(h.pending, oldest)
			}
			proof = challengeProof{client: client, expires: now.Add(handshakeLifetime)}
			if _, err := rand.Read(proof.server[:]); err != nil {
				return reply, false, err
			}
			h.pending[key] = proof
		}
		reply.Kind = Challenge
		reply.Payload = append(append([]byte(nil), proof.server[:]...), proof.client[:]...)
		return reply, true, nil
	}
	if packet.Header.Kind != Reset || len(packet.Payload) != 32 {
		return reply, false, nil
	}
	proof, exists := h.pending[key]
	expected := append(append([]byte(nil), proof.server[:]...), proof.client[:]...)
	fresh := exists && proof.expires.After(now) && subtle.ConstantTimeCompare(packet.Payload, expected) == 1
	if fresh {
		delete(h.pending, key)
		reply.AdoptPeer = !h.hasPeer || h.peer != packet.Header.Prefix
		if reply.AdoptPeer {
			h.peer = packet.Header.Prefix
			h.hasPeer = true
			clear(h.confirmed)
			for candidate := range h.pending {
				if candidate.prefix != h.peer {
					delete(h.pending, candidate)
				}
			}
		}
		if len(h.confirmed) >= 8 {
			var oldest netip.AddrPort
			var expiry time.Time
			for candidate, value := range h.confirmed {
				if expiry.IsZero() || value.expires.Before(expiry) {
					oldest, expiry = candidate, value.expires
				}
			}
			delete(h.confirmed, oldest)
		}
		var confirmationProof [32]byte
		copy(confirmationProof[:], packet.Payload)
		h.confirmed[endpoint] = confirmation{confirmationProof, now.Add(handshakeLifetime)}
	} else {
		cached, ok := h.confirmed[endpoint]
		if !h.hasPeer || packet.Header.Prefix != h.peer || !ok || !cached.expires.After(now) || subtle.ConstantTimeCompare(packet.Payload, cached.proof[:]) != 1 {
			return reply, false, nil
		}
	}
	reply.Kind = Ready
	reply.Payload = append(append([]byte(nil), packet.Payload[16:]...), packet.Payload[:16]...)
	reply.Peer = h.peer
	reply.FreshProof = fresh
	return reply, true, nil
}
