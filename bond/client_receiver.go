package bond

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"time"
)

// This file is the client half of Receiver. A client Receiver is built from a
// "client" Codec, is given its uplinks up front with AddClientPath (one local
// socket per uplink, all talking to one server endpoint), and learns nothing
// from the network: a datagram from an unconfigured (socket, endpoint) is
// dropped before any state changes, exactly as in the Python client.

var errNotClient = errors.New("operation requires a client receiver")

// freshPath builds a path with a new random transmit epoch and an initial
// budget, without registering it.
func (r *Receiver) freshPath(local int, endpoint netip.AddrPort, now time.Time) (*receivePath, error) {
	var epoch [8]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, err
	}
	p := &receivePath{local: local, endpoint: endpoint, txEpoch: binary.BigEndian.Uint64(epoch[:]), last: now}
	p.budget, _ = NewBudget(r.initialRate, r.maxRate)
	p.budget.UseLiveLimits()
	p.budget.delayControl = r.delayControl
	p.budget.delayAssertive = r.delayAssertive
	if r.mtuDiscovery {
		p.mtu, _ = NewMTUProber(r.mtu, min(548, r.mtu))
	}
	return p, nil
}

// AddClientPath registers an uplink: local is the caller's socket index and
// remote the server's address. Call it before traffic starts; the path stays
// not ready until its handshake completes.
func (r *Receiver) AddClientPath(local int, remote netip.AddrPort, now time.Time) error {
	if r.role != "client" {
		return errNotClient
	}
	if local < 0 || !remote.IsValid() || !remote.Addr().Is4() {
		return ErrFrame
	}
	if r.paths[PathKey{local, remote}] != nil {
		return ErrFrame
	}
	_, err := r.newPath(local, remote, now)
	return err
}

// clientPoll sends the next HELLO or RESET for a path that is not ready or has
// gone silent. A restarted attempt marks the path not ready.
func (r *Receiver) clientPoll(p *receivePath, now time.Time, out *ReceiveResult) error {
	kind, payload, restarted, err := p.hello.Poll(p.ready, now)
	if err != nil {
		return err
	}
	if restarted {
		if p.ready {
			p.ready = false
			r.noteLine(p, now, OutageLinkLost, "handshake_restart", 0)
		}
		p.ready = false
	}
	return r.write(kind, payload, p.local, p.endpoint, out)
}

// clientHandshake consumes an authenticated CHALLENGE or READY on a configured
// path. Only a READY proving both nonces under the challenging prefix adopts
// the peer and makes the path ready.
func (r *Receiver) clientHandshake(p *receivePath, packet Packet, now time.Time) (ReceiveResult, error) {
	var out ReceiveResult
	reply, ready, peer, ok := p.hello.Handle(packet, now)
	if !ok {
		r.stats.HandshakeRejected++
		return out, nil
	}
	if reply != nil {
		return out, r.write(reply.Kind, reply.Payload, p.local, p.endpoint, &out)
	}
	if ready {
		if err := r.adoptClientPeer(peer, packet.Header.Sequence, now); err != nil {
			return out, err
		}
		wasReady := p.ready
		p.ready = true
		p.last = now
		if !wasReady {
			r.noteLine(p, now, OutageLinkReady, "", 0)
		}
		if p.policy != nil {
			return out, r.sendPolicy(p, now, &out)
		}
	}
	return out, nil
}

// adoptClientPeer mirrors Node._adopt_peer for a client. A new peer prefix
// resets replay, reorder and the probe table, and returns every configured
// path to a fresh state while keeping each path's in-flight handshake so
// parallel attempts on the other uplinks are not thrown away.
func (r *Receiver) adoptClientPeer(peer [16]byte, sequence uint64, now time.Time) error {
	if r.handshake.hasPeer && r.handshake.peer == peer {
		return nil
	}
	if r.handshake.hasPeer {
		r.stats.PeerRestarts++
	}
	r.handshake.peer, r.handshake.hasPeer = peer, true
	clear(r.probes)
	r.replay = ReplayWindow{}
	r.dataHigh, r.dataHighAt = 0, time.Time{}
	r.floor = sequence + 1
	r.reorder, _ = NewReorder(DefaultReorderConfig())
	r.fecReset()
	r.copies = newCopyLedger()
	r.reorder.config.Timeout = r.reorderBase
	for _, p := range r.paths {
		fresh, err := r.freshPath(p.local, p.endpoint, now)
		if err != nil {
			return err
		}
		fresh.hello = p.hello
		fresh.copySeen, fresh.copyMissed, fresh.copyLate = p.copySeen, p.copyMissed, p.copyLate
		fresh.copyLagMS, fresh.hasCopyLag = p.copyLagMS, p.hasCopyLag
		fresh.copyReported, fresh.lastCopyReport = p.copyReported, p.lastCopyReport
		if p.policy != nil { // keep the configured policy; it must be confirmed again
			fresh.policy, fresh.policyRevision = p.policy, p.policyRevision
			fresh.pacer = p.pacer
		}
		*p = *fresh // in place: callers and the sender keep valid path pointers
	}
	return nil
}

// SetClientLinkPolicies installs one policy per uplink (indexed by local socket)
// and bumps the revision. Paths re-send their policy until the server acks it,
// and carry no payload until then. Mirrors Node.set_link_states.
func (r *Receiver) SetClientLinkPolicies(policies []PathPolicy, now time.Time) error {
	if r.role != "client" {
		return errNotClient
	}
	for _, p := range policies {
		if p.Role > Never || !finite(p.UploadMbps) || !finite(p.DownloadMbps) || p.UploadMbps < 0 || p.DownloadMbps < 0 || p.UploadMbps > 10000 || p.DownloadMbps > 10000 {
			return ErrFrame
		}
	}
	for _, p := range r.paths {
		if p.local >= len(policies) {
			return ErrFrame
		}
	}
	r.policyRevisionClient++
	r.policyEnabled = true
	timestamp := r.seconds(now)
	for _, p := range r.paths {
		policy := policies[p.local]
		p.policy, p.policyRevision = &policy, r.policyRevisionClient
		p.policyConfirmed, p.policySent = false, time.Time{}
		p.pacer.SetRate(policy.UploadMbps, timestamp)
	}
	return nil
}

func (r *Receiver) sendPolicy(p *receivePath, now time.Time, out *ReceiveResult) error {
	payload := make([]byte, 26)
	binary.BigEndian.PutUint64(payload, p.policyRevision)
	payload[8] = p.policy.Role
	if p.policy.Blocked {
		payload[9] = 1
	}
	binary.BigEndian.PutUint64(payload[10:], math.Float64bits(p.policy.UploadMbps))
	binary.BigEndian.PutUint64(payload[18:], math.Float64bits(p.policy.DownloadMbps))
	p.policySent = now
	return r.write(LinkPolicy, payload, p.local, p.endpoint, out)
}

// RebindClientPath restarts one uplink after its socket was replaced (adapter
// or address change): the path gets fresh budget, MTU and handshake state and
// must handshake again, in-flight probes and a pending UDP recovery are
// dropped, wire usage counters carry over, and an installed link policy is
// re-applied unconfirmed. A parked path (adapter unavailable) is not polled. The peer session and other paths are untouched.
func (r *Receiver) RebindClientPath(local int, now time.Time, parked bool) error {
	if r.role != "client" {
		return errNotClient
	}
	var old *receivePath
	for _, p := range r.paths {
		if p.local == local {
			old = p
			break
		}
	}
	if old == nil {
		return ErrFrame
	}
	fresh, err := r.freshPath(local, old.endpoint, now)
	if err != nil {
		return err
	}
	fresh.wireRX, fresh.wireTX = old.wireRX, old.wireTX
	fresh.parked = parked
	if old.policy != nil {
		policy := *old.policy
		fresh.policy, fresh.policyRevision = &policy, r.policyRevisionClient
		fresh.pacer.SetRate(policy.UploadMbps, r.seconds(now))
	}
	for token, probe := range r.probes {
		if probe.path == old {
			delete(r.probes, token)
		}
	}
	delete(r.recovery, local)
	r.paths[old.key()] = fresh
	return nil
}
