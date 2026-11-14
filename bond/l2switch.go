package bond

import (
	"sync"
	"time"
)

// L2Switch is the forwarding brain of the bridged tunnel port: it learns which port each source
// MAC lives behind, decides where a frame goes, and protects the bridged domain at the tunnel
// edge: a cap on MACs per port, loop detection, and storm control. It does no I/O; the edges
// ask it for a verdict per frame and act on it. All methods are safe for concurrent use.
type L2Switch struct {
	mu    sync.Mutex
	cfg   L2SwitchConfig
	ports map[PortID]*l2Port
	fdb   map[[6]byte]*fdbEntry
	stats L2SwitchStats
}

// PortID names a switch port; the edges assign them (for example 1 = the tunnel, 2 = a LAN device).
type PortID int

// L2SwitchConfig holds the switch-wide settings; zero values pick safe defaults.
type L2SwitchConfig struct {
	AgeTime       time.Duration // idle time before a learned MAC is forgotten (default 300 s)
	MoveWindow    time.Duration // window in which repeated MAC moves signal a loop (default 10 s)
	MoveLimit     int           // moves inside MoveWindow that trigger loop protection (default 5)
	LoopHold      time.Duration // how long a looping port stays blocked (default 30 s)
	MaxFDB        int           // table size bound (default 4096)
	Ports         []L2PortConfig
	StormBurstSec float64 // bucket depth in seconds of the configured rate (default 1)
}

// L2PortConfig is one port's policy.
type L2PortConfig struct {
	ID       PortID
	Name     string
	MACLimit int  // learned MACs allowed on the port (0 = unlimited)
	Isolated bool // isolated ports exchange frames only with non-isolated ports
	// Storm limits in frames per second; 0 = unlimited. Unknown unicast is a unicast whose
	// destination is not in the table, so it must be flooded.
	UnknownUnicastPPS, MulticastPPS, BroadcastPPS float64
}

type l2Port struct {
	cfg       L2PortConfig
	macs      int
	blockedTo time.Time
	moves     []time.Time
	uucast    bucket
	mcast     bucket
	bcast     bucket
}

type fdbEntry struct {
	port PortID
	seen time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) allow(rate, depth float64, now time.Time) bool {
	if rate <= 0 {
		return true
	}
	if b.at.IsZero() {
		b.tokens, b.at = rate*depth, now
	}
	b.tokens = min(rate*depth, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// L2Drop says why a frame was not forwarded.
type L2Drop string

const (
	L2Forward      L2Drop = ""
	L2DropMalform  L2Drop = "malformed"
	L2DropBlocked  L2Drop = "port_blocked"   // loop protection holds the ingress port
	L2DropMACLimit L2Drop = "mac_limit"      // new source MAC beyond the port's cap
	L2DropStorm    L2Drop = "storm_control"  // unknown-unicast, multicast or broadcast over its rate
	L2DropNoPort   L2Drop = "unknown_port"   // ingress port is not configured
	L2DropFiltered L2Drop = "same_port"      // destination is behind the ingress port; the segment already carried it
	L2DropIsolated L2Drop = "port_isolation" // both ports isolated
)

// L2Verdict is the forwarding decision for one frame.
type L2Verdict struct {
	Drop L2Drop
	Out  []PortID // egress ports, never including the ingress port
	// Flooded is true when the frame goes to several ports because its destination is
	// broadcast, multicast, or an unlearned unicast.
	Flooded bool
}

// L2SwitchStats are counters for the panel.
type L2SwitchStats struct {
	Forwarded, Flooded, Learned, Moves, Aged                      uint64
	DropBlocked, DropMACLimit, DropStorm, DropIsolated, DropOther uint64
	LoopHolds                                                     uint64
	FDBSize                                                       int
}

func NewL2Switch(cfg L2SwitchConfig) *L2Switch {
	if cfg.AgeTime <= 0 {
		cfg.AgeTime = 300 * time.Second
	}
	if cfg.MoveWindow <= 0 {
		cfg.MoveWindow = 10 * time.Second
	}
	if cfg.MoveLimit <= 0 {
		cfg.MoveLimit = 5
	}
	if cfg.LoopHold <= 0 {
		cfg.LoopHold = 30 * time.Second
	}
	if cfg.MaxFDB <= 0 {
		cfg.MaxFDB = 4096
	}
	if cfg.StormBurstSec <= 0 {
		cfg.StormBurstSec = 1
	}
	s := &L2Switch{cfg: cfg, ports: map[PortID]*l2Port{}, fdb: map[[6]byte]*fdbEntry{}}
	for _, p := range cfg.Ports {
		s.ports[p.ID] = &l2Port{cfg: p}
	}
	return s
}

// Stats snapshots the counters.
func (s *L2Switch) Stats() L2SwitchStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.FDBSize = len(s.fdb)
	return st
}

// Forward learns the frame's source and decides where it goes.
func (s *L2Switch) Forward(in PortID, frame []byte, now time.Time) L2Verdict {
	info, err := ParseFrame(frame)
	if err != nil {
		s.mu.Lock()
		s.stats.DropOther++
		s.mu.Unlock()
		return L2Verdict{Drop: L2DropMalform}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	port := s.ports[in]
	if port == nil {
		s.stats.DropOther++
		return L2Verdict{Drop: L2DropNoPort}
	}
	if now.Before(port.blockedTo) {
		s.stats.DropBlocked++
		return L2Verdict{Drop: L2DropBlocked}
	}
	if info.Src[0]&1 == 1 { // a group address is never a source
		s.stats.DropOther++
		return L2Verdict{Drop: L2DropMalform}
	}
	if drop := s.learn(port, in, info.Src, now); drop != L2Forward {
		return L2Verdict{Drop: drop}
	}
	depth := s.cfg.StormBurstSec
	dst, known := s.fdb[info.Dst]
	switch {
	case info.Broadcast:
		if !port.bcast.allow(port.cfg.BroadcastPPS, depth, now) {
			s.stats.DropStorm++
			return L2Verdict{Drop: L2DropStorm}
		}
	case info.Multicast:
		if !port.mcast.allow(port.cfg.MulticastPPS, depth, now) {
			s.stats.DropStorm++
			return L2Verdict{Drop: L2DropStorm}
		}
	case !known || now.Sub(dst.seen) > s.cfg.AgeTime:
		if !port.uucast.allow(port.cfg.UnknownUnicastPPS, depth, now) {
			s.stats.DropStorm++
			return L2Verdict{Drop: L2DropStorm}
		}
		known = false
	}
	if known && !info.Multicast {
		if dst.port == in {
			return L2Verdict{Drop: L2DropFiltered}
		}
		out := s.ports[dst.port]
		if out == nil || (port.cfg.Isolated && out.cfg.Isolated) {
			s.stats.DropIsolated++
			return L2Verdict{Drop: L2DropIsolated}
		}
		s.stats.Forwarded++
		return L2Verdict{Out: []PortID{dst.port}}
	}
	var outs []PortID
	for id, p := range s.ports {
		if id == in || (port.cfg.Isolated && p.cfg.Isolated) || now.Before(p.blockedTo) {
			continue
		}
		outs = append(outs, id)
	}
	sortPorts(outs)
	if len(outs) == 0 {
		s.stats.DropIsolated++
		return L2Verdict{Drop: L2DropIsolated}
	}
	s.stats.Flooded++
	return L2Verdict{Out: outs, Flooded: true}
}

func sortPorts(p []PortID) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j] < p[j-1]; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

// learn records src behind port. A MAC that keeps hopping between ports means a loop: the port
// that keeps claiming it is held down for LoopHold instead of letting the loop saturate the bond.
func (s *L2Switch) learn(port *l2Port, in PortID, src [6]byte, now time.Time) L2Drop {
	e := s.fdb[src]
	if e != nil && now.Sub(e.seen) > s.cfg.AgeTime {
		s.ageOut(src, e)
		e = nil
	}
	if e == nil {
		if port.cfg.MACLimit > 0 && port.macs >= port.cfg.MACLimit {
			s.stats.DropMACLimit++
			return L2DropMACLimit
		}
		if len(s.fdb) >= s.cfg.MaxFDB {
			s.evictOldest(now)
		}
		s.fdb[src] = &fdbEntry{port: in, seen: now}
		port.macs++
		s.stats.Learned++
		return L2Forward
	}
	if e.port != in {
		s.stats.Moves++
		keep := port.moves[:0]
		for _, t := range port.moves {
			if now.Sub(t) <= s.cfg.MoveWindow {
				keep = append(keep, t)
			}
		}
		port.moves = append(keep, now)
		if len(port.moves) >= s.cfg.MoveLimit {
			port.blockedTo = now.Add(s.cfg.LoopHold)
			port.moves = nil
			s.stats.LoopHolds++
			s.stats.DropBlocked++
			return L2DropBlocked
		}
		if old := s.ports[e.port]; old != nil && old.macs > 0 {
			old.macs--
		}
		if port.cfg.MACLimit > 0 && port.macs >= port.cfg.MACLimit {
			s.stats.DropMACLimit++
			return L2DropMACLimit
		}
		e.port = in
		port.macs++
	}
	e.seen = now
	return L2Forward
}

func (s *L2Switch) ageOut(mac [6]byte, e *fdbEntry) {
	if p := s.ports[e.port]; p != nil && p.macs > 0 {
		p.macs--
	}
	delete(s.fdb, mac)
	s.stats.Aged++
}

func (s *L2Switch) evictOldest(now time.Time) {
	var oldest [6]byte
	var at time.Time
	first := true
	for mac, e := range s.fdb {
		if first || e.seen.Before(at) {
			oldest, at, first = mac, e.seen, false
		}
	}
	if !first {
		s.ageOut(oldest, s.fdb[oldest])
	}
}

// Sweep forgets idle MACs; the edges call it now and then so a quiet port's table does not hold
// its MAC cap forever.
func (s *L2Switch) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for mac, e := range s.fdb {
		if now.Sub(e.seen) > s.cfg.AgeTime {
			s.ageOut(mac, e)
			n++
		}
	}
	return n
}
