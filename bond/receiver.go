package bond

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"math"
	"net/netip"
	"strings"
	"time"
)

// PathKey identifies a path by local socket index and remote endpoint. A server
// has a single bound socket (Local 0); a client binds one socket per uplink, so
// several paths share one remote endpoint and the index tells them apart.
type PathKey struct {
	Local  int
	Remote netip.AddrPort
}

type Datagram struct {
	Endpoint netip.AddrPort
	Frame    []byte
	// Local is the index of the socket to send from (0 for a server).
	Local int
	// DirectUDP asks the caller to send over UDP even if the path has fallen
	// back to a stream carrier (recovery probes).
	DirectUDP bool
}
type ReceiveResult struct {
	Send    []Datagram
	Deliver [][]byte
	Repairs []MissingPacket
	// RepairPaths[i] is the path Repairs[i] arrived on (REPAIR_NA goes back there).
	RepairPaths []PathKey
	// Unavailable lists repairs the peer answered with REPAIR_NA.
	Unavailable []MissingPacket
	// Lost lists flow packets the peer's selective acknowledgement shows were
	// dropped on a path: later frames of that path arrived, these did not.
	Lost []MissingPacket
	// Authenticated is true when the datagram proved a live peer on a ready path
	// (the point where Python calls sock.note_authenticated()).
	Authenticated bool
	// ReturnToUDP is true when a UDP CHALLENGE answered a recovery HELLO: the
	// stream carrier should be dropped and UDP used again.
	ReturnToUDP bool
}
type ReceiverStats struct {
	Authenticated, AuthenticationErrors, Malformed, Duplicates, FloorDrops, HandshakeRejected uint64
	PayloadPackets, PayloadBytes, WireRX, WireTX, SendErrors                                  uint64
	ReplayTooOld, ReplayTooFar                                                                uint64
	PeerRestarts, PathMigrations                                                              uint64
	// Data frames (replicated game traffic) are delivered at first arrival, so a
	// frame with a lower sequence than one already delivered arrives out of order.
	DataReordered, DataReorderedOver5ms, DataReorderedOver20ms uint64
	DataReorderMaxMS                                           float64
	FeedbackReceived, FeedbackRejected, FeedbackDuplicates     uint64
	PolicyDrops                                                uint64
	FECParity, FECRecovered, FECRecoveredRS                    uint64
	ReorderScale                                               float64
	BFDSent, BFDReceived, BFDUp, BFDDown                       uint64
}
type receivePath struct {
	copySeen, copyMissed, copyLate   uint64
	copyLagMS                        float64
	firstWins, lateCopies            uint64
	skewMS, skewMaxMS                float64
	hasCopyLag                       bool
	copyReported                     [3]uint64
	lastCopyReport                   time.Time
	hello                            ClientHandshake
	local                            int
	endpoint                         netip.AddrPort
	ready                            bool
	last                             time.Time
	lastSequence                     uint64
	txEpoch, rxEpoch                 uint64
	hasEpoch                         bool
	stripeBytes, stripeHighest       uint64
	sack                             sackWindow
	stripeAt                         time.Time
	feedbackDue                      bool
	lastFeedback                     time.Time
	wireRX, wireTX                   uint64
	budget                           *Budget
	pacer                            WirePacer
	policy                           *PathPolicy
	policyRevision                   uint64
	policyConfirmed                  bool
	policySent                       time.Time
	bulkFinish                       float64
	bulkFiltered                     bool
	steerOn                          bool
	steerUntil                       float64
	rtt, jitter                      float64
	hasRTT                           bool
	probeSent, probeAcked, probeLost uint64
	acceptedSequence, acceptedBytes  uint64
	hasFeedback                      bool
	mtu                              *MTUProber
	mtuAcks, mtuSkips                uint64
	suspect                          bool
	bfd                              bfdState
	peerCopy                         [3]uint64
	lastSupervision, peerSupAt       time.Time
	peerSup                          []supervisedPath
	// parked: the adapter is gone; never polled, never ready.
	parked bool
}
type pendingProbe struct {
	at   time.Time
	path *receivePath
}

// Receiver implements the GB03 server's authenticated receive half. It does not
// implement transmit congestion control, link quotas, or TUN routing; callers
// must not use it as a production edge server on its own.
type Receiver struct {
	role                 string
	version              string    // this side's build id (commit)
	peerVersion          string    // the other side's build id, once it has said
	peerState            string    // the server's announced state ("updating"), client side
	stateFn              func() string // server side: current state to announce
	lastState            string
	versionAsked         time.Time // last VersionReq sent (client)
	codec                *Codec
	handshake            *ServerHandshake
	replay               ReplayWindow
	firsts               [1 << 16]firstArrival
	skewSamples          uint64
	skewPeakMS           float64
	dataHigh             uint64
	dataHighAt           time.Time
	floor                uint64
	paths                map[PathKey]*receivePath
	outages              *OutageJournal
	recovery             map[int]recoveryState
	copies               *CopyLedger[PathKey]
	reorder              *Reorder
	mtu                  int
	stats                ReceiverStats
	origin               time.Time
	initialRate, maxRate float64
	policyEnabled        bool
	probeInterval        time.Duration
	lastProbe            time.Time
	probes               map[[24]byte]pendingProbe
	reorderBase          time.Duration
	expected             []PathKey // see expectedCopyPaths
	expectedAt           time.Time
	mtuDiscovery         bool
	delayControl         bool
	delayAssertive       bool
	policyRevisionClient uint64
	repairUnavailable    uint64
	fec                  *fecState
	reorderScale         float64   // >= 1: widens the wait while TCP packets keep arriving after it
	tuneAt               time.Time // last scale review
	tuneLate, tuneDeliv  uint64
}

func NewReceiver(codec *Codec, mtu int) (*Receiver, error) {
	if codec == nil || (codec.role != "server" && codec.role != "client") || mtu < Overhead+24 || mtu > 65507 {
		return nil, ErrFrame
	}
	r, _ := NewReorder(DefaultReorderConfig())
	return &Receiver{role: codec.role, codec: codec, handshake: NewServerHandshake(), paths: make(map[PathKey]*receivePath), reorder: r, mtu: mtu, initialRate: 1, maxRate: 100, probes: make(map[[24]byte]pendingProbe), reorderBase: 30 * time.Millisecond, copies: newCopyLedger(), outages: newOutageJournal()}, nil
}
func (r *Receiver) SetReorderTimeout(timeout time.Duration) error {
	if len(r.paths) > 0 || timeout < time.Millisecond || timeout > 200*time.Millisecond {
		return ErrFrame
	}
	r.reorderBase = timeout
	r.reorder.config.Timeout = timeout
	return nil
}

// SetPathMTUDiscovery enables per-path outbound MTU probing (kinds 14/15).
// It must be set before any path exists.
func (r *Receiver) SetPathMTUDiscovery(on bool) error {
	if len(r.paths) > 0 {
		return ErrFrame
	}
	r.mtuDiscovery = on
	return nil
}
func (r *Receiver) seconds(now time.Time) float64 {
	if r.origin.IsZero() {
		r.origin = now
	}
	return math.Max(0, now.Sub(r.origin).Seconds())
}
func (r *Receiver) Stats() ReceiverStats       { return r.stats }
func (r *Receiver) ReorderStats() ReorderStats { return r.reorder.Stats() }
func (r *Receiver) ReadyPaths(now time.Time) int {
	n := 0
	for _, p := range r.paths {
		if p.ready && now.Sub(p.last) < 3*time.Second {
			n++
		}
	}
	return n
}
func (p *receivePath) key() PathKey { return PathKey{p.local, p.endpoint} }
func (r *Receiver) write(kind byte, payload []byte, local int, endpoint netip.AddrPort, out *ReceiveResult) error {
	frame, err := r.codec.Encode(kind, payload)
	if err != nil {
		return err
	}
	out.Send = append(out.Send, Datagram{Endpoint: endpoint, Frame: frame, Local: local})
	return nil
}

// Sent records only actual successful socket writes, including control and
// duplicate datagrams. Queuing a reply is not evidence it reached the socket.
func (r *Receiver) Sent(d Datagram, err error) {
	if err != nil {
		r.stats.SendErrors++
		return
	}
	n := uint64(len(d.Frame) + 28)
	r.stats.WireTX += n
	if p := r.paths[PathKey{d.Local, d.Endpoint}]; p != nil {
		p.wireTX += n
	}
}
func (r *Receiver) newPath(local int, endpoint netip.AddrPort, now time.Time) (*receivePath, error) {
	p, err := r.freshPath(local, endpoint, now)
	if err != nil {
		return nil, err
	}
	if len(r.paths) >= 8 {
		var oldest *receivePath
		for _, p := range r.paths {
			if oldest == nil || p.last.Before(oldest.last) {
				oldest = p
			}
		}
		delete(r.paths, oldest.key())
	}
	r.paths[p.key()] = p
	return p, nil
}

// Receive processes a datagram that arrived on the server's only socket.
func (r *Receiver) Receive(frame []byte, endpoint netip.AddrPort, now time.Time) (ReceiveResult, error) {
	return r.ReceiveOn(0, frame, endpoint, now)
}

// ReceiveOn processes a datagram that arrived on local socket index local.
func (r *Receiver) ReceiveOn(local int, frame []byte, endpoint netip.AddrPort, now time.Time) (ReceiveResult, error) {
	return r.ReceiveVia(local, frame, endpoint, now, true)
}

// ReceiveVia is ReceiveOn that also says whether the datagram arrived over
// UDP (true) or a stream carrier (false); only a UDP CHALLENGE can complete a
// UDP recovery.
func (r *Receiver) ReceiveVia(local int, frame []byte, endpoint netip.AddrPort, now time.Time, viaUDP bool) (ReceiveResult, error) {
	var out ReceiveResult
	key := PathKey{local, endpoint}
	timestamp := r.seconds(now)
	if len(frame) > r.mtu || !endpoint.IsValid() {
		r.stats.Malformed++
		return out, nil
	}
	packet, err := r.codec.Decode(frame)
	if err != nil {
		if err == ErrAuthentication {
			r.stats.AuthenticationErrors++
		} else {
			r.stats.Malformed++
		}
		return out, nil
	}
	h := packet.Header
	payload := packet.Payload
	if r.role == "client" && r.paths[key] == nil {
		r.stats.Malformed++ // configured peer only, as in the Python client
		return out, nil
	}
	r.stats.Authenticated++
	r.stats.WireRX += uint64(len(frame) + 28)
	p := r.paths[key]
	if p != nil {
		p.wireRX += uint64(len(frame) + 28)
	}
	if h.Kind >= Hello && h.Kind <= Ready {
		if r.role == "client" {
			returned := false
			if h.Kind == Challenge && viaUDP && len(payload) == 32 {
				if rec, ok := r.recovery[local]; ok && now.Sub(rec.at) < handshakeLifetime &&
					subtle.ConstantTimeCompare(payload[16:], rec.nonce[:]) == 1 {
					p.hello.Restart(rec.nonce, now)
					delete(r.recovery, local)
					returned = true
				}
			}
			res, err := r.clientHandshake(p, packet, now)
			res.ReturnToUDP = returned
			res.Authenticated = p.ready
			return res, err
		}
		if h.Kind == Reset && h.Sequence == math.MaxUint64 {
			r.stats.HandshakeRejected++
			return out, nil
		}
		reply, ok, err := r.handshake.Handle(packet, endpoint, now)
		if err != nil {
			return out, err
		}
		if !ok {
			r.stats.HandshakeRejected++
			return out, nil
		}
		if reply.AdoptPeer {
			if len(r.paths) > 0 {
				r.stats.PeerRestarts++
			}
			clear(r.paths)
			clear(r.probes)
			r.policyEnabled = false
			r.replay = ReplayWindow{}
			r.dataHigh, r.dataHighAt = 0, time.Time{}
			r.floor = h.Sequence + 1
			r.reorder, _ = NewReorder(DefaultReorderConfig())
			r.fecReset()
			r.copies = newCopyLedger()
			r.reorder.config.Timeout = r.reorderBase
			p = nil
		}
		if reply.Kind == Ready && reply.FreshProof {
			p = r.paths[key]
			if p == nil {
				p, err = r.newPath(local, endpoint, now)
				if err != nil {
					return out, err
				}
			}
			p.ready = true
			p.last = now
			if h.Sequence > p.lastSequence {
				p.lastSequence = h.Sequence
			}
		}
		err = r.write(reply.Kind, reply.Payload, local, endpoint, &out)
		return out, err
	}
	if !r.handshake.hasPeer || h.Prefix != r.handshake.peer {
		r.stats.HandshakeRejected++
		return out, nil
	}
	var epoch uint64
	hasEpoch := false
	if h.Kind == Probe && len(payload) == 24 {
		epoch = binary.BigEndian.Uint64(payload)
		hasEpoch = true
	}
	if h.Kind == Striped && len(payload) >= 24 {
		epoch = binary.BigEndian.Uint64(payload[16:])
		hasEpoch = true
	}
	var migrated *receivePath
	if hasEpoch && r.role == "server" {
		for _, candidate := range r.paths {
			if candidate.ready && candidate.hasEpoch && candidate.rxEpoch == epoch && candidate.key() != key {
				migrated = candidate
				break
			}
		}
	}
	if (p == nil && migrated == nil) || (p != nil && !p.ready) {
		r.stats.HandshakeRejected++
		return out, nil
	}
	if h.Sequence < r.floor {
		r.stats.FloorDrops++
		return out, nil
	}
	verdict := r.replay.Check(h.Sequence)
	if verdict != ReplayNew {
		switch verdict {
		case ReplayTooOld:
			r.stats.ReplayTooOld++
		case ReplayTooFar:
			r.stats.ReplayTooFar++
		}
		r.stats.Duplicates++
		if h.Kind == DataCopy && p != nil && verdict == ReplayDuplicate {
			r.noteCopy(p, key, h.Sequence, timestamp)
		}
		return out, nil
	}
	r.replay.Accept(h.Sequence)
	valid := true
	switch h.Kind {
	case Probe, Pong:
		valid = len(payload) == 24
	case Striped:
		valid = len(payload) >= 24
	case Feedback:
		valid = (len(payload) == 28 || len(payload) == feedbackSackSize) && binary.BigEndian.Uint32(payload[24:]) <= 1000000
	case Repair:
		valid = len(payload) == 16
	case LinkPolicy:
		valid = len(payload) == 26
	case LinkPolicyAck:
		valid = r.role == "client" && len(payload) == 32
	case MTUProbeKind:
		valid = len(payload) >= 12
	case MTUAck:
		valid = len(payload) == 12
	case RepairNA:
		valid = len(payload) == 16
	case CopyReport:
		valid = len(payload) == 24
	case Supervision:
		valid = validSupervision(payload)
	case VersionReq, VersionInfo:
		valid = len(payload) <= 64
	case Parity:
		valid = len(payload) >= parityHeader+2
	case ParityRS:
		valid = len(payload) >= rsHeader+2
	case BFD:
		valid = len(payload) == bfdPayload
	}
	if !valid {
		r.stats.Malformed++
		return out, nil
	}
	if migrated != nil {
		if h.Sequence <= migrated.lastSequence {
			r.stats.HandshakeRejected++
			return out, nil
		}
		delete(r.paths, migrated.key())
		migrated.local, migrated.endpoint = local, endpoint
		r.paths[key] = migrated
		p = migrated
		p.wireRX += uint64(len(frame) + 28)
		r.stats.PathMigrations++
	}
	if (h.Kind == Data || h.Kind == Striped || h.Kind == Parity || h.Kind == ParityRS) && p.policy != nil && (p.policy.Blocked || p.policy.Role == Never) {
		r.stats.PolicyDrops++
		return out, nil
	}
	p.last = now
	out.Authenticated = true
	if h.Sequence > p.lastSequence {
		p.lastSequence = h.Sequence
	}
	if !p.hasEpoch && hasEpoch {
		p.rxEpoch = epoch
		p.hasEpoch = true
	}
	switch h.Kind {
	case BFD:
		r.bfdReceived(p, payload, now)
	case Probe:
		err = r.write(Pong, payload, local, endpoint, &out)
	case Pong:
		var token [24]byte
		copy(token[:], payload)
		if probe, ok := r.probes[token]; ok && probe.path == p {
			delete(r.probes, token)
			p.probeAcked++
			sample := math.Max(.000001, now.Sub(probe.at).Seconds())
			if !p.hasRTT {
				p.rtt = sample
				p.jitter = sample / 2
				p.hasRTT = true
			} else {
				p.jitter = .75*p.jitter + .25*math.Abs(sample-p.rtt)
				p.rtt = .8*p.rtt + .2*sample
			}
			r.updateReorderBudget()
		}
	case Feedback:
		epoch, sequence, delivered := binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:]), binary.BigEndian.Uint64(payload[16:])
		if epoch == p.txEpoch && p.hasFeedback && sequence == p.acceptedSequence && delivered == p.acceptedBytes {
			r.stats.FeedbackDuplicates++
		} else if epoch == p.txEpoch && r.acknowledge(p, payload, &out, sequence, delivered, timestamp) {
			p.hasFeedback = true
			p.acceptedSequence = sequence
			p.acceptedBytes = delivered
			r.stats.FeedbackReceived++
		} else {
			r.stats.FeedbackRejected++
		}
	case LinkPolicy:
		if r.role != "server" {
			r.stats.Malformed++
			break
		}
		revision, policy, decodeErr := decodePolicy(payload)
		if decodeErr != nil || (revision == p.policyRevision && p.policy != nil && policy != *p.policy) {
			r.stats.Malformed++
			break
		}
		if p.policy == nil || revision >= p.policyRevision {
			p.policy = &policy
			p.policyRevision = revision
			r.policyEnabled = true
			p.pacer.SetRate(policy.DownloadMbps, timestamp)
		}
		ack := make([]byte, 32)
		binary.BigEndian.PutUint64(ack, p.policyRevision)
		binary.BigEndian.PutUint64(ack[8:], p.txEpoch)
		binary.BigEndian.PutUint64(ack[16:], p.wireTX+Overhead+32+28)
		binary.BigEndian.PutUint64(ack[24:], p.wireRX)
		err = r.write(LinkPolicyAck, ack, local, endpoint, &out)
	case VersionReq:
		if r.role != "server" {
			r.stats.Malformed++
			break
		}
		r.peerVersion = string(payload)
		err = r.write(VersionInfo, r.versionInfo(), local, endpoint, &out)
	case VersionInfo:
		if r.role != "client" {
			r.stats.Malformed++
			break
		}
		r.peerVersion, r.peerState, _ = strings.Cut(string(payload), "|")
	case LinkPolicyAck:
		// Only a client with a policy of its own can be acknowledged.
		revision, epoch := binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:])
		if p.policy == nil {
			r.stats.Malformed++
			break
		}
		if revision != p.policyRevision || (p.hasEpoch && p.rxEpoch != epoch) {
			break
		}
		p.rxEpoch, p.hasEpoch = epoch, true
		p.policyConfirmed = true
	case Repair:
		out.Repairs = append(out.Repairs, MissingPacket{binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:])})
		out.RepairPaths = append(out.RepairPaths, PathKey{local, endpoint})
	case Striped:
		if !p.hasEpoch || (p.rxEpoch != epoch && h.Sequence > p.stripeHighest) {
			p.rxEpoch = epoch
			p.hasEpoch = true
			p.stripeBytes = 0
			p.stripeAt = time.Time{}
		}
		if p.rxEpoch == epoch {
			p.stripeBytes += uint64(len(frame))
			if p.stripeAt.IsZero() || h.Sequence > p.stripeHighest {
				p.stripeHighest = h.Sequence
				p.stripeAt = now
			}
			p.feedbackDue = true
		}
		r.stats.PayloadPackets++
		r.stats.PayloadBytes += uint64(len(payload) - 24)
		flow, number := binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:])
		duplicates := r.reorder.stats.Duplicates
		out.Deliver = r.reorder.Push(flow, number, payload[24:], now)
		r.accountArrival(p, flow, number, r.reorder.stats.Duplicates != duplicates, now)
		for _, hit := range r.fecData(flow, number, payload[24:], now) {
			out.Deliver = append(out.Deliver, r.reorder.Push(hit.flow, hit.number, hit.payload, now)...)
		}
	case Parity:
		r.stats.FECParity++
		if hit := r.fecParity(payload, now); hit.payload != nil {
			out.Deliver = append(out.Deliver, r.reorder.Push(hit.flow, hit.number, hit.payload, now)...)
		}
	case ParityRS:
		r.stats.FECParity++
		for _, hit := range r.fecParityRS(payload, now) {
			out.Deliver = append(out.Deliver, r.reorder.Push(hit.flow, hit.number, hit.payload, now)...)
		}
	case MTUProbeKind:
		// Answer with the size actually received, as the Python peer does.
		reply := make([]byte, 12)
		copy(reply, payload[:8])
		binary.BigEndian.PutUint32(reply[8:], uint32(len(frame)))
		err = r.write(MTUAck, reply, local, endpoint, &out)
	case MTUAck:
		if p.mtu != nil && p.mtu.Acknowledge(binary.BigEndian.Uint64(payload), int(binary.BigEndian.Uint32(payload[8:]))) {
			p.mtuAcks++
		}
	case RepairNA:
		r.repairUnavailable++
		out.Unavailable = append(out.Unavailable, MissingPacket{binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:])})
	case Supervision:
		p.peerSup, p.peerSupAt = parseSupervision(payload), now
	case CopyReport:
		p.peerCopy = [3]uint64{binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:]), binary.BigEndian.Uint64(payload[16:])}
	case Data, DataCopy:
		if h.Kind == DataCopy {
			r.copies.First(h.Sequence, p.key(), r.expectedCopyPaths(now), timestamp)
		}
		r.stats.PayloadPackets++
		r.stats.PayloadBytes += uint64(len(payload))
		if h.Sequence < r.dataHigh && r.dataHighAt.After(time.Time{}) {
			r.stats.DataReordered++
			late := float64(now.Sub(r.dataHighAt)) / float64(time.Millisecond)
			if late > r.stats.DataReorderMaxMS {
				r.stats.DataReorderMaxMS = late
			}
			if late > 5 {
				r.stats.DataReorderedOver5ms++
			}
			if late > 20 {
				r.stats.DataReorderedOver20ms++
			}
		} else {
			r.dataHigh, r.dataHighAt = h.Sequence, now
		}
		out.Deliver = append(out.Deliver, payload)
	}
	return out, err
}
func (r *Receiver) Tick(now time.Time) (ReceiveResult, error) {
	r.tuneReorder(now)
	out := ReceiveResult{Deliver: r.reorder.Poll(now)}
	if err := r.resolveCopies(now, &out); err != nil {
		return out, err
	}
	if err := r.announceState(now, &out); err != nil {
		return out, err
	}
	for _, p := range r.paths {
		if p.policy != nil && (p.policy.Blocked || p.policy.Role == Never) {
			continue
		}
		if !p.ready || p.stripeAt.IsZero() || now.Sub(p.last) >= 3*time.Second {
			continue
		}
		interval := 100 * time.Millisecond
		if p.feedbackDue {
			interval = 20 * time.Millisecond
		}
		if !p.lastFeedback.IsZero() && now.Sub(p.lastFeedback) < interval {
			continue
		}
		payload := make([]byte, 28)
		binary.BigEndian.PutUint64(payload, p.rxEpoch)
		binary.BigEndian.PutUint64(payload[8:], p.stripeHighest)
		binary.BigEndian.PutUint64(payload[16:], p.stripeBytes)
		hold := now.Sub(p.stripeAt) / time.Microsecond
		if hold < 0 {
			hold = 0
		}
		if hold > 1000000 {
			hold = 1000000
		}
		binary.BigEndian.PutUint32(payload[24:], uint32(hold))
		if err := r.write(Feedback, payload, p.local, p.endpoint, &out); err != nil {
			return out, err
		}
		p.feedbackDue = false
		p.lastFeedback = now
	}
	if r.probeInterval > 0 {
		for _, p := range r.paths {
			if p.parked || !p.ready || now.Sub(p.last) >= 3*time.Second || (p.policy != nil && (p.policy.Blocked || p.policy.Role == Never)) {
				continue
			}
			if err := r.bfdSend(p, now, &out); err != nil {
				return out, err
			}
		}
	}
	if r.probeInterval > 0 && (r.lastProbe.IsZero() || now.Sub(r.lastProbe) >= r.probeInterval) {
		r.lastProbe = now
		for token, probe := range r.probes {
			if now.Sub(probe.at) >= 3*time.Second {
				probe.path.probeLost++
				delete(r.probes, token)
			}
		}
		for _, p := range r.paths {
			if p.parked {
				continue
			}
			if r.role == "client" && (!p.ready || now.Sub(p.last) >= 3*time.Second) {
				if err := r.clientPoll(p, now, &out); err != nil {
					return out, err
				}
				continue
			}
			if r.role == "client" && p.policy != nil && p.ready {
				disabled := p.policy.Blocked || p.policy.Role == Never
				if !p.policyConfirmed || (!disabled && now.Sub(p.policySent) >= time.Second) {
					if err := r.sendPolicy(p, now, &out); err != nil {
						return out, err
					}
				}
			}
			if r.role == "client" && p.ready && now.Sub(p.last) < 3*time.Second {
				every := 5 * time.Second // a restarted server shows its new build within seconds
				if r.peerVersion == "" {
					every = 2 * time.Second // not known yet (or the server predates this frame)
				}
				if now.Sub(r.versionAsked) >= every {
					r.versionAsked = now
					if err := r.write(VersionReq, []byte(r.version), p.local, p.endpoint, &out); err != nil {
						return out, err
					}
				}
			}
			if !p.ready || now.Sub(p.last) >= 3*time.Second || (p.policy != nil && (p.policy.Blocked || p.policy.Role == Never)) {
				continue
			}
			var token [24]byte
			binary.BigEndian.PutUint64(token[:], p.txEpoch)
			if _, err := rand.Read(token[8:]); err != nil {
				return out, err
			}
			if len(r.probes) >= 256 {
				break
			}
			r.probes[token] = pendingProbe{now, p}
			if err := r.write(Probe, token[:], p.local, p.endpoint, &out); err != nil {
				return out, err
			}
			if p.mtu != nil {
				for _, probe := range p.mtu.Due(r.seconds(now), randomNonce) {
					body := make([]byte, probe.Size-Overhead)
					binary.BigEndian.PutUint64(body, probe.Nonce)
					binary.BigEndian.PutUint32(body[8:], uint32(probe.Size))
					if err := r.write(MTUProbeKind, body, p.local, p.endpoint, &out); err != nil {
						return out, err
					}
				}
			}
		}
	}
	return out, nil
}
func randomNonce() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}
// firstArrival remembers when a packet was first delivered, so the later copy on another
// path can be timed against it (the PRP/802.1CB per-LAN accounting).
type firstArrival struct {
	key uint64
	at  time.Time
}

// accountArrival records which path delivered a packet first and, for the redundant copy,
// how long after the winner it arrived: the skew between the paths.
func (r *Receiver) accountArrival(p *receivePath, flow, number uint64, duplicate bool, now time.Time) {
	key := (flow*0x9E3779B97F4A7C15 ^ number) * 0x9E3779B97F4A7C15
	if key == 0 {
		key = 1
	}
	slot := &r.firsts[key>>48]
	if !duplicate {
		p.firstWins++
		*slot = firstArrival{key, now}
		return
	}
	p.lateCopies++
	if slot.key != key {
		return
	}
	ms := float64(now.Sub(slot.at)) / float64(time.Millisecond)
	if ms < 0 {
		return
	}
	if p.skewMS == 0 {
		p.skewMS = ms
	} else {
		p.skewMS = .9*p.skewMS + .1*ms
	}
	p.skewMaxMS = math.Max(p.skewMaxMS*.999, ms)
	r.skewSamples++
	r.skewPeakMS = math.Max(r.skewPeakMS*.999, ms)
}

// reorderCeiling bounds how long (seconds, before scaling) one hole may hold back a flow.
// With every packet duplicated on a second path, the copy lands within the path skew, so
// a hole older than this is a real loss and waiting longer only builds a burst behind it.
const reorderCeiling = .1

func (r *Receiver) updateReorderBudget() {
	count := 0
	minimum, maximum, jitter := math.Inf(1), 0., 0.
	for _, p := range r.paths {
		if p.ready && p.hasRTT {
			count++
			minimum = math.Min(minimum, p.rtt)
			maximum = math.Max(maximum, p.rtt)
			jitter = math.Max(jitter, p.jitter)
		}
	}
	timeout := r.reorderBase.Seconds()
	scale := math.Max(1, r.reorderScale)
	if count >= 2 {
		timeout = math.Min(reorderCeiling*scale, scale*math.Max(timeout, math.Max((maximum-minimum)/2, maximum/2)+4*jitter+timeout))
	}
	// The copy lands within the measured skew of the first: waiting much longer for a hole
	// to fill only adds latency. Applies once enough duplicates have been timed.
	if r.skewSamples >= 200 {
		timeout = math.Min(timeout, math.Max(r.reorderBase.Seconds(), 2*r.skewPeakMS/1000+4*jitter))
	}
	r.reorder.config.Timeout = time.Duration(timeout * float64(time.Second))
	udp := timeout
	if count >= 2 {
		udp = math.Min(timeout, math.Max(r.reorderBase.Seconds(), (maximum-minimum)/2+2*jitter))
	}
	r.reorder.config.UDPTimeout = time.Duration(udp * float64(time.Second))
}

type recoveryState struct {
	nonce [16]byte
	at    time.Time
}

// StartRecovery builds a HELLO with a fresh nonce for the client path on local
// socket local; the caller sends it over UDP (DirectUDP). A UDP CHALLENGE that
// echoes the nonce within the handshake lifetime sets ReturnToUDP and restarts
// the path handshake with that nonce (Node._udp_recovery).
func (r *Receiver) StartRecovery(local int, now time.Time) (Datagram, error) {
	if r.role != "client" {
		return Datagram{}, errNotClient
	}
	var path *receivePath
	for _, p := range r.paths {
		if p.local == local {
			path = p
			break
		}
	}
	if path == nil || path.parked {
		return Datagram{}, ErrFrame
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Datagram{}, err
	}
	if r.recovery == nil {
		r.recovery = map[int]recoveryState{}
	}
	r.recovery[local] = recoveryState{nonce, now}
	frame, err := r.codec.Encode(Hello, nonce[:])
	if err != nil {
		return Datagram{}, err
	}
	return Datagram{Endpoint: path.endpoint, Frame: frame, Local: local, DirectUDP: true}, nil
}

func newCopyLedger() *CopyLedger[PathKey] {
	l, _ := NewCopyLedger[PathKey](4096)
	return l
}

const copyReportInterval = 500 * time.Millisecond

// expectedCopyPaths lists the paths a replicated packet should arrive on. It is rebuilt at
// most every expectedRefresh rather than for every packet: a game flow sends thousands of
// copies a second and the set of ready paths changes far more slowly.
const expectedRefresh = 20 * time.Millisecond

func (r *Receiver) expectedCopyPaths(now time.Time) []PathKey {
	if r.expectedAt.IsZero() || now.Sub(r.expectedAt) >= expectedRefresh || now.Before(r.expectedAt) {
		r.expected = r.expected[:0]
		for _, e := range (&Sender{r: r}).eligible(now, true) {
			r.expected = append(r.expected, e.key())
		}
		r.expectedAt = now
	}
	return r.expected
}

// noteCopy is Node._note_copy: a further copy of a replicated packet arrived.
func (r *Receiver) noteCopy(p *receivePath, key PathKey, sequence uint64, now float64) {
	kind, lag, ok := r.copies.Duplicate(sequence, key, now)
	if !ok {
		return
	}
	ms := lag * 1000
	if !p.hasCopyLag {
		p.copyLagMS, p.hasCopyLag = ms, true
	} else {
		p.copyLagMS = .8*p.copyLagMS + .2*ms
	}
	if kind == DuplicateLate {
		if p.copyMissed > 0 {
			p.copyMissed--
		}
		p.copyLate++
	}
}

// copyResolveDelay is Node._copy_resolve_delay.
func (r *Receiver) copyResolveDelay() float64 {
	var n int
	var lo, hi, jitter float64
	for _, p := range r.paths {
		if !p.ready || !p.hasRTT {
			continue
		}
		ms := p.rtt * 1000
		if n == 0 || ms < lo {
			lo = ms
		}
		if n == 0 || ms > hi {
			hi = ms
		}
		jitter = math.Max(jitter, p.jitter*1000)
		n++
	}
	if n < 2 {
		return .05
	}
	spread := (hi - lo) / 2000
	return math.Min(.25, math.Max(.05, spread+4*(jitter/1000)+.02))
}

// resolveCopies scores replicated copies and reports the cumulative counters
// to the peer (Node.maintenance, after the reorder poll).
func (r *Receiver) resolveCopies(now time.Time, out *ReceiveResult) error {
	if r.copies.HasPending() {
		for _, o := range r.copies.Resolve(r.seconds(now), r.copyResolveDelay()) {
			if t := r.paths[o.Identity]; t != nil {
				if o.Outcome == CopySeen {
					t.copySeen++
				} else {
					t.copyMissed++
				}
			}
		}
	}
	for _, p := range r.paths {
		counters := [3]uint64{p.copySeen, p.copyMissed, p.copyLate}
		if counters == p.copyReported || !p.ready || now.Sub(p.last) >= 3*time.Second || now.Sub(p.lastCopyReport) < copyReportInterval {
			continue
		}
		payload := make([]byte, 24)
		for i, v := range counters {
			binary.BigEndian.PutUint64(payload[8*i:], v)
		}
		if err := r.write(CopyReport, payload, p.local, p.endpoint, out); err != nil {
			return err
		}
		p.copyReported, p.lastCopyReport = counters, now
	}
	return r.supervise(now, out)
}

// tuneReorder reviews the reorder wait every few seconds. TCP packets that keep
// arriving after the receiver gave up mean the wait is shorter than the real delay
// spread, so it widens (up to 1.6x); when they stop it relaxes back. UDP is
// excluded on purpose: its wait is deliberately short and late packets are delivered.
func (r *Receiver) tuneReorder(now time.Time) {
	const (
		period    = 5 * time.Second
		maxScale  = 1.6
		raiseRate = 0.003
		lowerRate = 0.0005
	)
	if r.reorderScale == 0 {
		r.reorderScale = 1
	}
	if r.tuneAt.IsZero() {
		r.tuneAt = now
		return
	}
	if now.Sub(r.tuneAt) < period {
		return
	}
	st := r.reorder.Stats()
	dLate, dDeliv := st.LateTCP-r.tuneLate, st.Delivered-r.tuneDeliv
	r.tuneAt, r.tuneLate, r.tuneDeliv = now, st.LateTCP, st.Delivered
	if dDeliv < 2000 {
		return
	}
	rate := float64(dLate) / float64(dDeliv)
	switch {
	case rate > raiseRate:
		r.reorderScale = math.Min(maxScale, r.reorderScale*1.15)
	case rate < lowerRate:
		r.reorderScale = math.Max(1, r.reorderScale*0.95)
	}
	r.stats.ReorderScale = r.reorderScale
	r.updateReorderBudget()
}
