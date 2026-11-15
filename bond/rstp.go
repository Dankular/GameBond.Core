package bond

// Single-instance Rapid Spanning Tree (IEEE 802.1w) state for L2Switch.
// This implementation handles single-instance RSTP BPDUs and the 802.1D
// version-0 configuration/TCN compatibility formats. MSTP remains unsupported.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	rstpProtocolID          = 0
	rstpVersion             = 2
	rstpBPDUType            = 2
	rstpBPDUBodyLength      = 36
	stpVersion              = 0
	stpConfigBPDUType       = 0
	stpTCNBPDUType          = 0x80
	stpConfigLength         = 35
	stpTCNLength            = 4
	rstpMigrateTime         = 3 * time.Second
	rstpLLCLength           = 3
	rstpFlagTC         byte = 0x01
	stpFlagTCA         byte = 0x80
	rstpFlagProposal   byte = 0x02
	rstpRoleAlternate  byte = 0x04
	rstpRoleRoot       byte = 0x08
	rstpRoleDesignated byte = 0x0c
	rstpFlagLearning   byte = 0x10
	rstpFlagForwarding byte = 0x20
	rstpFlagAgreement  byte = 0x40
)

type RSTPBridgeID struct {
	Priority uint16
	MAC      [6]byte
}

func (id RSTPBridgeID) String() string {
	return fmt.Sprintf("%04x.%02x:%02x:%02x:%02x:%02x:%02x", id.Priority, id.MAC[0], id.MAC[1], id.MAC[2], id.MAC[3], id.MAC[4], id.MAC[5])
}

type RSTPPortRole uint8

const (
	RSTPRoleDisabled RSTPPortRole = iota
	RSTPRoleRoot
	RSTPRoleDesignated
	RSTPRoleAlternate
	RSTPRoleBackup
)

func (r RSTPPortRole) String() string {
	switch r {
	case RSTPRoleRoot:
		return "root"
	case RSTPRoleDesignated:
		return "designated"
	case RSTPRoleAlternate:
		return "alternate"
	case RSTPRoleBackup:
		return "backup"
	default:
		return "disabled"
	}
}

type RSTPPortState uint8

const (
	RSTPStateDisabled RSTPPortState = iota
	RSTPStateDiscarding
	RSTPStateLearning
	RSTPStateForwarding
)

func (s RSTPPortState) String() string {
	switch s {
	case RSTPStateDiscarding:
		return "discarding"
	case RSTPStateLearning:
		return "learning"
	case RSTPStateForwarding:
		return "forwarding"
	default:
		return "disabled"
	}
}

type rstpConfig struct {
	bridgeID RSTPBridgeID
	hello    time.Duration
	maxAge   time.Duration
	forward  time.Duration
}

type rstpVector struct {
	root   RSTPBridgeID
	cost   uint32
	bridge RSTPBridgeID
	port   uint16
}

type rstpBPDU struct {
	flags      byte
	root       RSTPBridgeID
	rootCost   uint32
	bridge     RSTPBridgeID
	port       uint16
	messageAge time.Duration
	maxAge     time.Duration
	hello      time.Duration
	forward    time.Duration
	legacy     bool
	tcn        bool
	tca        bool
}

type rstpPort struct {
	id               PortID
	pathCost         uint32
	edgeConfigured   bool
	edgeOperational  bool
	shared           bool
	role             RSTPPortRole
	state            RSTPPortState
	peer             *rstpBPDU
	peerAt           time.Time
	lastSent         time.Time
	changed          time.Time
	proposal         bool
	agreement        bool
	legacy           bool
	legacyPeer       bool
	tcaPending       bool
	migrationStarted bool
	migrationTimer   bool
	migrationSensing bool
	migrationUntil   time.Time
}

type rstpBridge struct {
	cfg            rstpConfig
	ports          map[PortID]*rstpPort
	rootID         RSTPBridgeID
	rootCost       uint32
	rootPort       PortID
	rootMessageAge time.Duration
	lastTC         time.Time
	haveLastTC     bool
	tcUntil        time.Time
	pendingTCFlush bool
	legacyTCN      bool
	legacyTCNSent  time.Time
	nextAdvance    time.Time
}

type L2RSTPPortStatus struct {
	PortID     PortID
	Role       string
	State      string
	PathCost   uint32
	Edge       bool
	PeerBridge string
}

type L2RSTPStatus struct {
	Enabled      bool
	BridgeID     string
	RootID       string
	RootPathCost uint32
	RootPort     PortID
	Ports        []L2RSTPPortStatus
}

func newRSTPBridge(priority uint16, mac [6]byte, hello, maxAge, forward time.Duration) *rstpBridge {
	if mac == [6]byte{} {
		_, _ = rand.Read(mac[:])
		mac[0] = (mac[0] | 0x02) & 0xfe
	}
	if hello <= 0 {
		hello = 2 * time.Second
	}
	if maxAge <= 0 {
		maxAge = 20 * time.Second
	}
	if forward <= 0 {
		forward = 15 * time.Second
	}
	id := RSTPBridgeID{Priority: priority, MAC: mac}
	return &rstpBridge{cfg: rstpConfig{bridgeID: id, hello: hello, maxAge: maxAge, forward: forward}, ports: make(map[PortID]*rstpPort), rootID: id}
}

func (b *rstpBridge) addPort(cfg L2PortConfig) error {
	if cfg.ID <= 0 || cfg.ID > 4095 {
		return errors.New("rstp: port ID must be in 1..4095")
	}
	if _, exists := b.ports[cfg.ID]; exists {
		return errors.New("rstp: duplicate port ID")
	}
	cost := cfg.RSTPPathCost
	if cost == 0 {
		cost = 20000
	}
	state, role := RSTPStateDiscarding, RSTPRoleDesignated
	if cfg.RSTPEdge {
		state = RSTPStateForwarding
	}
	b.ports[cfg.ID] = &rstpPort{id: cfg.ID, pathCost: cost, edgeConfigured: cfg.RSTPEdge, edgeOperational: cfg.RSTPEdge, shared: cfg.RSTPSharedLink, role: role, state: state}
	b.nextAdvance = time.Time{}
	return nil
}

func (b *rstpBridge) removePort(id PortID, now time.Time) {
	delete(b.ports, id)
	b.nextAdvance = time.Time{}
	b.recompute(now)
}

func (b *rstpBridge) portState(id PortID) RSTPPortState {
	if p := b.ports[id]; p != nil {
		return p.state
	}
	return RSTPStateDisabled
}

func (b *rstpBridge) portStatus(id PortID) (RSTPPortRole, RSTPPortState) {
	if p := b.ports[id]; p != nil {
		return p.role, p.state
	}
	return RSTPRoleDisabled, RSTPStateDisabled
}

func (b *rstpBridge) status() L2RSTPStatus {
	status := L2RSTPStatus{Enabled: true, BridgeID: b.cfg.bridgeID.String(), RootID: b.rootID.String(), RootPathCost: b.rootCost, RootPort: b.rootPort}
	for id, p := range b.ports {
		peer := ""
		if p.peer != nil {
			peer = p.peer.bridge.String()
		}
		status.Ports = append(status.Ports, L2RSTPPortStatus{PortID: id, Role: p.role.String(), State: p.state.String(), PathCost: p.pathCost, Edge: p.edgeOperational, PeerBridge: peer})
	}
	slices.SortFunc(status.Ports, func(a, c L2RSTPPortStatus) int { return int(a.PortID - c.PortID) })
	return status
}

func (b *rstpBridge) receive(port PortID, frame []byte, now time.Time) error {
	b.nextAdvance = time.Time{}
	p := b.ports[port]
	if p == nil {
		return errors.New("rstp: BPDU received on an unknown port")
	}
	b.startPortMigration(p, now)
	b.advancePortMigration(p, now)
	bpdu, err := parseRSTPBPDU(frame)
	if err != nil {
		return err
	}
	if bpdu.bridge == b.cfg.bridgeID || bpdu.root == b.cfg.bridgeID {
		if bpdu.tcn {
			return errors.New("rstp: TCN received with no bridge vector")
		}
		return errors.New("rstp: received BPDU contains this bridge ID")
	}
	if bpdu.legacy {
		p.legacyPeer = true
		// During the initial SEND_NEW window, old information is parsed but
		// cannot change the port's transmit format. In sensing mode, the next
		// old BPDU selects legacy output and starts a fresh migration lock.
		if !p.legacy && p.migrationSensing && !p.migrationTimer {
			b.selectLegacyMode(p, now)
		}
	} else if p.legacy && p.migrationSensing && !p.migrationTimer {
		// Once the migration lock expires, the next rapid BPDU switches this
		// port back to RSTP and starts a fresh lock interval.
		p.legacy = false
		p.legacyPeer = false
		p.migrationSensing = false
		p.migrationTimer = true
		p.migrationUntil = now.Add(rstpMigrateTime)
	} else if !p.legacy {
		p.legacyPeer = false
	}
	if bpdu.legacy && p.legacy {
		p.legacyPeer = true
	}
	if !bpdu.legacy && p.legacy {
		p.legacyPeer = true
	}
	p.edgeOperational = false
	if bpdu.tcn {
		// IEEE 802.1D TCNs carry no priority vector. A designated receiver
		// acknowledges the sender and relays the notification toward its root.
		if p.role == RSTPRoleDesignated {
			p.tcaPending = true
			b.markTopologyChange(now, b.cfg.maxAge+b.cfg.forward)
			if b.rootPort != 0 {
				b.legacyTCN = true
			}
		}
		return nil
	}
	p.peer, p.peerAt = bpdu, now
	b.recompute(now)
	if p.role == RSTPRoleRoot && !p.shared && !p.legacyPeer && bpdu.flags&rstpFlagProposal != 0 && bpdu.flags&0x0c == rstpRoleDesignated {
		// Synchronize every other non-edge path before rapidly agreeing on the
		// newly selected root port. This prevents transient forwarding loops.
		for id, other := range b.ports {
			if id == port || other.edgeOperational {
				continue
			}
			if other.state == RSTPStateForwarding || other.state == RSTPStateLearning {
				other.state, other.changed = RSTPStateDiscarding, now
			}
		}
		p.state, p.changed, p.agreement = RSTPStateForwarding, now, true
	}
	if p.role == RSTPRoleDesignated && bpdu.flags&rstpFlagAgreement != 0 && !p.shared && !p.legacyPeer {
		p.state, p.changed = RSTPStateForwarding, now
	}
	if bpdu.flags&rstpFlagTC != 0 {
		window := 2 * b.cfg.hello
		if bpdu.legacy {
			window = bpdu.maxAge + bpdu.forward
		}
		b.markTopologyChange(now, window)
	}
	if bpdu.legacy && bpdu.tca && port == b.rootPort {
		b.legacyTCN = false
	}
	return nil
}

func (b *rstpBridge) selectLegacyMode(p *rstpPort, now time.Time) {
	if p.legacy {
		return
	}
	p.migrationStarted = true
	p.legacy = true
	p.legacyPeer = true
	p.migrationSensing = false
	p.migrationTimer = true
	p.migrationUntil = now.Add(rstpMigrateTime)
}

func (b *rstpBridge) startPortMigration(p *rstpPort, now time.Time) {
	if p.migrationStarted {
		return
	}
	p.migrationStarted = true
	p.migrationTimer = true
	p.migrationUntil = now.Add(rstpMigrateTime)
}

func (b *rstpBridge) advancePortMigration(p *rstpPort, now time.Time) {
	if p.migrationTimer && !now.Before(p.migrationUntil) {
		p.migrationTimer = false
		p.migrationSensing = true
	}
}

func (b *rstpBridge) markTopologyChange(now time.Time, window time.Duration) {
	if window <= 0 {
		window = 2 * b.cfg.hello
	}
	// Refresh propagation on every notification, but dampen FDB flushes to
	// one per hello interval.
	b.tcUntil = now.Add(window)
	if !b.haveLastTC || now.Sub(b.lastTC) >= b.cfg.hello {
		b.lastTC = now
		b.haveLastTC = true
		b.pendingTCFlush = true
	}
}

func (b *rstpBridge) takeTCFlush() bool {
	flush := b.pendingTCFlush
	b.pendingTCFlush = false
	return flush
}

func (b *rstpBridge) advance(now time.Time) {
	if !b.nextAdvance.IsZero() && now.Before(b.nextAdvance) {
		return
	}
	// Port addition and BPDU receipt invalidate nextAdvance, so migration
	// initialization and all bridge-wide scans can stay behind this fast path.
	for _, p := range b.ports {
		b.startPortMigration(p, now)
	}
	for _, p := range b.ports {
		b.advancePortMigration(p, now)
		if p.changed.IsZero() {
			p.changed = now
		}
		if p.peer != nil && now.Sub(p.peerAt) >= rstpPeerLifetime(p.peer) {
			p.peer = nil
			p.legacyPeer = false
			p.proposal = false
			p.agreement = false
		}
	}
	b.recompute(now)
	for _, p := range b.ports {
		if (!p.shared && !p.legacyPeer) || (p.role != RSTPRoleDesignated && p.role != RSTPRoleRoot) {
			continue
		}
		forwardDelay := b.cfg.forward
		if p.legacyPeer && p.peer != nil && p.peer.forward > 0 {
			forwardDelay = p.peer.forward
		}
		if p.state == RSTPStateDiscarding && now.Sub(p.changed) >= forwardDelay {
			p.state, p.changed = RSTPStateLearning, now
		} else if p.state == RSTPStateLearning && now.Sub(p.changed) >= forwardDelay {
			p.state, p.changed = RSTPStateForwarding, now
		}
	}
	// Recompute only when a peer expires or a shared-link state transition is
	// due. Forward() may run once per packet, so avoid a bridge-wide scan there.
	b.nextAdvance = now.Add(24 * time.Hour)
	for _, p := range b.ports {
		if p.migrationTimer && p.migrationUntil.Before(b.nextAdvance) {
			b.nextAdvance = p.migrationUntil
		}
		if p.peer != nil {
			deadline := p.peerAt.Add(rstpPeerLifetime(p.peer))
			if deadline.Before(b.nextAdvance) {
				b.nextAdvance = deadline
			}
		}
		if (p.shared || p.legacy) && (p.role == RSTPRoleDesignated || p.role == RSTPRoleRoot) && p.state != RSTPStateForwarding {
			forwardDelay := b.cfg.forward
			if p.legacy && p.peer != nil && p.peer.forward > 0 {
				forwardDelay = p.peer.forward
			}
			deadline := p.changed.Add(forwardDelay)
			if p.state == RSTPStateLearning {
				deadline = p.changed.Add(forwardDelay)
			}
			if deadline.Before(b.nextAdvance) {
				b.nextAdvance = deadline
			}
			if p.state == RSTPStateDiscarding {
				deadline = p.changed.Add(forwardDelay)
				if deadline.Before(b.nextAdvance) {
					b.nextAdvance = deadline
				}
			}
		}
	}
}

func (b *rstpBridge) recompute(now time.Time) {
	b.rootID, b.rootCost, b.rootPort, b.rootMessageAge = b.cfg.bridgeID, 0, 0, 0
	var best *rstpVector
	var bestPort PortID
	for id, p := range b.ports {
		if p.peer == nil || now.Sub(p.peerAt) >= rstpPeerLifetime(p.peer) {
			continue
		}
		candidate := rstpVector{root: p.peer.root, cost: p.peer.rootCost + p.pathCost, bridge: p.peer.bridge, port: p.peer.port}
		if compareBridgeID(candidate.root, b.cfg.bridgeID) >= 0 {
			continue
		}
		if best == nil || compareRSTPVector(candidate, *best) < 0 || (compareRSTPVector(candidate, *best) == 0 && id < bestPort) {
			copy := candidate
			best, bestPort = &copy, id
		}
	}
	if best != nil {
		b.rootID, b.rootCost, b.rootPort = best.root, best.cost, bestPort
		if p := b.ports[bestPort]; p != nil && p.peer != nil {
			b.rootMessageAge = p.peer.messageAge + time.Second
		}
	}
	for id, p := range b.ports {
		oldRole, oldState := p.role, p.state
		if p.edgeOperational {
			p.role, p.state = RSTPRoleDesignated, RSTPStateForwarding
		} else if id == b.rootPort {
			p.role = RSTPRoleRoot
			if p.agreement {
				p.state = RSTPStateForwarding
			} else if p.state == RSTPStateForwarding && oldRole == RSTPRoleRoot {
				// Retain a forwarding root port while its current information is valid.
			} else if !((p.shared || p.legacyPeer) && p.state == RSTPStateLearning) {
				p.state = RSTPStateDiscarding
			}
		} else if p.peer == nil || compareRSTPVector(localRSTPVector(b, id), rstpVector{root: p.peer.root, cost: p.peer.rootCost, bridge: p.peer.bridge, port: p.peer.port}) < 0 {
			p.role = RSTPRoleDesignated
			if p.state == RSTPStateForwarding && oldRole == RSTPRoleDesignated {
				// Keep established designated forwarding until a topology change.
			} else if p.state != RSTPStateForwarding && !((p.shared || p.legacyPeer) && p.state == RSTPStateLearning) {
				p.state = RSTPStateDiscarding
			}
		} else if p.peer.bridge == b.cfg.bridgeID {
			p.role, p.state = RSTPRoleBackup, RSTPStateDiscarding
		} else {
			p.role, p.state = RSTPRoleAlternate, RSTPStateDiscarding
		}
		if p.role != oldRole || p.state != oldState {
			p.changed = now
		}
		if p.role == RSTPRoleDesignated && p.state != RSTPStateForwarding && !p.shared {
			p.proposal = true
		}
	}
}

func (b *rstpBridge) dueBPDUs(now time.Time) map[PortID][]byte {
	b.advance(now)
	out := make(map[PortID][]byte)
	for id, p := range b.ports {
		if b.legacyTCN && id == b.rootPort && (b.legacyTCNSent.IsZero() || now.Sub(b.legacyTCNSent) >= b.cfg.hello) {
			out[id] = b.buildLegacyTCN(id)
			b.legacyTCNSent = now
			continue
		}
		if p.legacy {
			sendPeriodic := p.role == RSTPRoleDesignated && (p.lastSent.IsZero() || now.Sub(p.lastSent) >= b.cfg.hello)
			if !sendPeriodic && !p.tcaPending {
				continue
			}
			flags := byte(0)
			if p.role == RSTPRoleDesignated && now.Before(b.tcUntil) {
				flags |= rstpFlagTC
			}
			if p.tcaPending {
				flags |= stpFlagTCA
				p.tcaPending = false
			}
			out[id] = b.buildLegacyConfig(id, flags)
			p.lastSent = now
			continue
		}
		sendAgreement := p.agreement
		sendPeriodic := p.role == RSTPRoleDesignated && (p.lastSent.IsZero() || now.Sub(p.lastSent) >= b.cfg.hello)
		if !sendAgreement && !sendPeriodic {
			continue
		}
		flags := byte(0)
		if p.state == RSTPStateLearning || p.state == RSTPStateForwarding {
			flags |= rstpFlagLearning
		}
		if p.state == RSTPStateForwarding {
			flags |= rstpFlagForwarding
		}
		switch p.role {
		case RSTPRoleRoot:
			flags |= rstpRoleRoot
		case RSTPRoleAlternate, RSTPRoleBackup:
			flags |= rstpRoleAlternate
		default:
			flags |= rstpRoleDesignated
		}
		if p.proposal && p.role == RSTPRoleDesignated && !p.shared {
			flags |= rstpFlagProposal
			p.proposal = false
		}
		if sendAgreement {
			flags |= rstpFlagAgreement
			p.agreement = false
		}
		if p.role == RSTPRoleDesignated && now.Before(b.tcUntil) {
			flags |= rstpFlagTC
		}
		out[id] = b.buildBPDU(id, flags)
		p.lastSent = now
	}
	return out
}

func (b *rstpBridge) buildBPDU(id PortID, flags byte) []byte {
	frame := make([]byte, 14+rstpLLCLength+rstpBPDUBodyLength)
	copy(frame[:6], []byte{0x01, 0x80, 0xc2, 0, 0, 0})
	copy(frame[6:12], b.cfg.bridgeID.MAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(rstpLLCLength+rstpBPDUBodyLength))
	frame[14], frame[15], frame[16] = 0x42, 0x42, 0x03
	body := frame[17:]
	binary.BigEndian.PutUint16(body[0:2], rstpProtocolID)
	body[2], body[3], body[4] = rstpVersion, rstpBPDUType, flags
	encodeRSTPBridgeID(body[5:13], b.rootID)
	binary.BigEndian.PutUint32(body[13:17], b.rootCost)
	encodeRSTPBridgeID(body[17:25], b.cfg.bridgeID)
	binary.BigEndian.PutUint16(body[25:27], uint16(0x8000|(int(id)&0x0fff)))
	putRSTPTimer(body[27:29], b.rootMessageAge)
	maxAge, hello, forward := b.rootTimers()
	putRSTPTimer(body[29:31], maxAge)
	putRSTPTimer(body[31:33], hello)
	putRSTPTimer(body[33:35], forward)
	body[35] = 0 // RSTP version-1 length; zero denotes no MST extension.
	return padBPDUFrame(frame)
}

func (b *rstpBridge) buildLegacyConfig(id PortID, flags byte) []byte {
	frame := make([]byte, EthHeaderLen+rstpLLCLength+stpConfigLength)
	copy(frame[:6], []byte{0x01, 0x80, 0xc2, 0, 0, 0})
	copy(frame[6:12], b.cfg.bridgeID.MAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(rstpLLCLength+stpConfigLength))
	frame[14], frame[15], frame[16] = 0x42, 0x42, 0x03
	body := frame[17:]
	binary.BigEndian.PutUint16(body[0:2], rstpProtocolID)
	body[2], body[3], body[4] = stpVersion, stpConfigBPDUType, flags
	encodeRSTPBridgeID(body[5:13], b.rootID)
	binary.BigEndian.PutUint32(body[13:17], b.rootCost)
	encodeRSTPBridgeID(body[17:25], b.cfg.bridgeID)
	binary.BigEndian.PutUint16(body[25:27], uint16(0x8000|(int(id)&0x0fff)))
	putRSTPTimer(body[27:29], b.rootMessageAge)
	maxAge, hello, forward := b.rootTimers()
	putRSTPTimer(body[29:31], maxAge)
	putRSTPTimer(body[31:33], hello)
	putRSTPTimer(body[33:35], forward)
	return padBPDUFrame(frame)
}

func (b *rstpBridge) rootTimers() (maxAge, hello, forward time.Duration) {
	maxAge, hello, forward = b.cfg.maxAge, b.cfg.hello, b.cfg.forward
	if p := b.ports[b.rootPort]; p != nil && p.peer != nil {
		if p.peer.maxAge > 0 {
			maxAge = p.peer.maxAge
		}
		if p.peer.hello > 0 {
			hello = p.peer.hello
		}
		if p.peer.forward > 0 {
			forward = p.peer.forward
		}
	}
	return
}

func validRSTPTimers(messageAge, maxAge, hello, forward time.Duration) bool {
	return hello >= time.Second && hello <= 10*time.Second &&
		maxAge >= 6*time.Second && maxAge <= 40*time.Second &&
		forward >= 4*time.Second && forward <= 30*time.Second &&
		maxAge >= 2*(hello+time.Second) && maxAge <= 2*(forward-time.Second) &&
		messageAge >= 0 && messageAge < maxAge
}

func rstpPeerLifetime(peer *rstpBPDU) time.Duration {
	if peer == nil {
		return 0
	}
	return peer.maxAge - peer.messageAge
}

func (b *rstpBridge) buildLegacyTCN(id PortID) []byte {
	frame := make([]byte, EthHeaderLen+rstpLLCLength+stpTCNLength)
	copy(frame[:6], []byte{0x01, 0x80, 0xc2, 0, 0, 0})
	copy(frame[6:12], b.cfg.bridgeID.MAC[:])
	binary.BigEndian.PutUint16(frame[12:14], uint16(rstpLLCLength+stpTCNLength))
	frame[14], frame[15], frame[16] = 0x42, 0x42, 0x03
	body := frame[17:]
	binary.BigEndian.PutUint16(body[0:2], rstpProtocolID)
	body[2], body[3] = stpVersion, stpTCNBPDUType
	_ = id // The classic TCN format has no port identifier.
	return padBPDUFrame(frame)
}

// Ethernet MAC frames are at least 64 octets including the four-octet FCS;
// callers provide/receive frames without FCS, so control frames are padded to
// 60 octets before direct tunnel/TAP transmission.
func padBPDUFrame(frame []byte) []byte {
	if len(frame) >= 60 {
		return frame
	}
	return append(frame, make([]byte, 60-len(frame))...)
}

func parseRSTPBPDU(frame []byte) (*rstpBPDU, error) {
	info, err := ParseFrame(frame)
	if err != nil || !info.BPDU || info.VLANDepth != 0 || info.Src[0]&1 != 0 {
		return nil, errors.New("rstp: malformed or tagged BPDU")
	}
	offset := EthHeaderLen + rstpLLCLength
	if len(frame) < offset+4 {
		return nil, errors.New("rstp: truncated BPDU header")
	}
	body := frame[offset:]
	if binary.BigEndian.Uint16(body[0:2]) != rstpProtocolID {
		return nil, errors.New("rstp: invalid protocol identifier")
	}
	length := binary.BigEndian.Uint16(frame[12:14])
	if body[2] == stpVersion {
		if body[3] == stpTCNBPDUType {
			if length != rstpLLCLength+stpTCNLength || len(body) < stpTCNLength {
				return nil, errors.New("rstp: invalid TCN BPDU length")
			}
			return &rstpBPDU{legacy: true, tcn: true}, nil
		}
		if body[3] != stpConfigBPDUType || length != rstpLLCLength+stpConfigLength || len(body) < stpConfigLength {
			return nil, errors.New("rstp: unsupported legacy BPDU type or length")
		}
		if body[4] & ^byte(rstpFlagTC|stpFlagTCA) != 0 {
			return nil, errors.New("rstp: reserved legacy BPDU flags are set")
		}
		maxAge, hello, forward, messageAge := getRSTPTimer(body[29:31]), getRSTPTimer(body[31:33]), getRSTPTimer(body[33:35]), getRSTPTimer(body[27:29])
		portID := binary.BigEndian.Uint16(body[25:27])
		if !validRSTPTimers(messageAge, maxAge, hello, forward) || portID == 0 {
			return nil, errors.New("rstp: invalid legacy BPDU timer or port ID")
		}
		return &rstpBPDU{flags: body[4], root: decodeRSTPBridgeID(body[5:13]), rootCost: binary.BigEndian.Uint32(body[13:17]), bridge: decodeRSTPBridgeID(body[17:25]), port: portID, messageAge: messageAge, maxAge: maxAge, hello: hello, forward: forward, legacy: true, tca: body[4]&stpFlagTCA != 0}, nil
	}
	if len(body) < rstpBPDUBodyLength || length != rstpLLCLength+rstpBPDUBodyLength || body[2] != rstpVersion || body[3] != rstpBPDUType || body[35] != 0 {
		return nil, errors.New("rstp: unsupported BPDU version, type, length, or MST extension")
	}
	maxAge := getRSTPTimer(body[29:31])
	hello := getRSTPTimer(body[31:33])
	forward := getRSTPTimer(body[33:35])
	messageAge := getRSTPTimer(body[27:29])
	if !validRSTPTimers(messageAge, maxAge, hello, forward) || binary.BigEndian.Uint16(body[25:27]) == 0 {
		return nil, errors.New("rstp: invalid BPDU timer or port ID")
	}
	return &rstpBPDU{flags: body[4], root: decodeRSTPBridgeID(body[5:13]), rootCost: binary.BigEndian.Uint32(body[13:17]), bridge: decodeRSTPBridgeID(body[17:25]), port: binary.BigEndian.Uint16(body[25:27]), messageAge: messageAge, maxAge: maxAge, hello: hello, forward: forward}, nil
}

func compareRSTPVector(a, b rstpVector) int {
	if c := compareBridgeID(a.root, b.root); c != 0 {
		return c
	}
	if a.cost < b.cost {
		return -1
	}
	if a.cost > b.cost {
		return 1
	}
	if c := compareBridgeID(a.bridge, b.bridge); c != 0 {
		return c
	}
	if a.port < b.port {
		return -1
	}
	if a.port > b.port {
		return 1
	}
	return 0
}

func localRSTPVector(b *rstpBridge, id PortID) rstpVector {
	return rstpVector{root: b.rootID, cost: b.rootCost, bridge: b.cfg.bridgeID, port: uint16(0x8000 | (int(id) & 0x0fff))}
}

func compareBridgeID(a, b RSTPBridgeID) int {
	if a.Priority < b.Priority {
		return -1
	}
	if a.Priority > b.Priority {
		return 1
	}
	for i := range a.MAC {
		if a.MAC[i] < b.MAC[i] {
			return -1
		}
		if a.MAC[i] > b.MAC[i] {
			return 1
		}
	}
	return 0
}

func decodeRSTPBridgeID(src []byte) RSTPBridgeID {
	return RSTPBridgeID{Priority: binary.BigEndian.Uint16(src[:2]), MAC: [6]byte{src[2], src[3], src[4], src[5], src[6], src[7]}}
}

func encodeRSTPBridgeID(dst []byte, id RSTPBridgeID) {
	binary.BigEndian.PutUint16(dst[:2], id.Priority)
	copy(dst[2:8], id.MAC[:])
}

func putRSTPTimer(dst []byte, d time.Duration) {
	ticks := uint16(d * 256 / time.Second)
	binary.BigEndian.PutUint16(dst, ticks)
}

func getRSTPTimer(src []byte) time.Duration {
	return time.Duration(binary.BigEndian.Uint16(src)) * time.Second / 256
}
