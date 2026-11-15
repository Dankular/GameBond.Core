package bond

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// L2Switch is the forwarding brain of the bridged tunnel port: it learns which port each source
// MAC lives behind, decides where a frame goes, and protects the bridged domain at the tunnel
// edge: a cap on MACs per port, loop detection, and storm control. It does no I/O; the edges
// ask it for a verdict per frame and act on it. All methods are safe for concurrent use.
type L2Switch struct {
	mu                sync.Mutex
	cfg               L2SwitchConfig
	ports             map[PortID]*l2Port
	fdb               map[fdbKey]*fdbEntry
	groups            map[mcastKey]map[PortID]map[[6]byte]time.Time
	sourceFilters     map[mcastKey]map[PortID]map[[6]byte]mcastSourceFilter
	lastMemberQueries map[mcastMemberKey]lastMemberQuery
	querierUntil      map[vlanID]time.Time
	saviClaims        map[sourceBindingKey]saviClaim
	saviPrefixes      map[saviPrefixKey]saviPrefixLifetime
	queryDue          map[mcastQuerierKey]time.Time
	queryInterval     time.Duration
	multicastMembers  int
	multicastSources  int
	stats             L2SwitchStats
	mirrors           []L2Mirror
	mvrGroups         map[mvrGroupKey]L2MVRGroup
	mvrMulticastVLAN  uint16
	rstp              *rstpBridge
	lastObserved      time.Time
}

// PortID names a switch port; the edges assign them (for example 1 = the tunnel, 2 = a LAN device).
type PortID int

// L2SwitchConfig holds the switch-wide settings; zero values pick safe defaults.
type L2SwitchConfig struct {
	DynamicPorts            bool // broker attaches ports after construction; caller validates the complete membership set
	RSTPEnabled             bool
	BridgePriority          uint16
	BridgePrioritySet       bool // permits priority 0; otherwise zero selects the 32768 default
	BridgeMAC               [6]byte
	RSTPHelloTime           time.Duration
	RSTPMaxAge              time.Duration
	RSTPForwardDelay        time.Duration
	MVR                     *L2MVRConfig
	AgeTime                 time.Duration // idle time before a learned MAC is forgotten (default 300 s)
	MoveWindow              time.Duration // window in which repeated MAC moves signal a loop (default 10 s)
	MoveLimit               int           // moves inside MoveWindow that trigger loop protection (default 5)
	LoopHold                time.Duration // how long a looping port stays blocked (default 30 s)
	MaxFDB                  int           // table size bound (default 4096)
	Ports                   []L2PortConfig
	Mirrors                 []L2Mirror
	StormBurstSec           float64       // bucket depth in seconds of the configured rate (default 1)
	MulticastQueryInterval  time.Duration // IGMP/MLD general-query interval (default 125 s)
	LastMemberQueryInterval time.Duration // interval between group-specific leave queries (default 1 s)
	LastMemberQueryCount    int           // group-specific queries before pruning a silent listener (default 2)
}

// L2PortConfig is one port's policy.
type L2PortConfig struct {
	ID                    PortID
	Name                  string
	MACLimit              int  // learned MACs allowed on the port (0 = unlimited)
	Isolated              bool // isolated ports exchange frames only with non-isolated ports
	Monitor               bool // output-only port used as a software capture destination
	BPDUGuard             bool // permanently disables the port after an STP/RSTP BPDU arrives
	RSTPParticipant       bool // include this port in the single spanning tree
	RSTPEdge              bool // configured edge port; forwards immediately until a BPDU is received
	RSTPSharedLink        bool // do not use rapid proposal/agreement transitions on this shared segment
	RSTPPathCost          uint32
	RAGuard               bool              // drops IPv6 Router Advertisements and uninspectable fragment/ESP chains
	IPv4SourceGuard       bool              // validates IPv4 sources and ARP sender tuples against DHCP bindings
	IPv6SourceGuard       bool              // validates global IPv6 sources against DHCPv6/static bindings and guarded SAVI claims
	StaticSourceBindings  []L2SourceBinding // administrator-provisioned bindings retained across DHCP lease refreshes
	IPv6SourcePrefixes    []L2SourcePrefix  // prefixes eligible for SLAAC DAD learning on this port's admitted VLANs
	MACAuth               bool              // unknown source MACs may send only EAPOL until explicitly authorized
	EAPOLAuthenticator    bool              // trusted port that terminates EAPOL for MACAuth ports
	EAPOLAuthenticatorFor string            // when set, only the named session port exchanges EAPOL with this port
	PrivateVLAN           uint16
	PrivateVLANRole       L2PrivateVLANRole
	PVLANCommunity        uint16
	PVLANPrimaryVLAN      uint16 // primary VLAN for this PVLAN port; zero keeps legacy same-VLAN role filtering
	PVLANSecondaryVLAN    uint16 // isolated/community secondary VLAN; zero on promiscuous ports
	ControlPlane          bool
	ControlPlanePPS       float64
	ControlPlaneRates     L2ControlPlaneRates
	// MobilityGroup identifies attachments that share one logical L2 endpoint. A source MAC
	// moving between ports in the same group updates the FDB without triggering loop protection.
	// This is the local FDB primitive needed by a multi-attachment edge; it does not synchronize
	// entries with another switch or arbitrate an MC-LAG peer.
	MobilityGroup    string
	VLAN             L2VLANPolicy
	MulticastRouter  bool // always receive multicast for VLANs admitted by this port
	MulticastQuerier bool // generate general queries for VLANs admitted by this router port
	QuerierMAC       [6]byte
	QuerierIPv4      [4]byte
	QuerierIPv6      [16]byte // link-local source address for MLD queries
	// Storm limits in frames per second; 0 = unlimited. Unknown unicast is a unicast whose
	// destination is not in the table, so it must be flooded.
	UnknownUnicastPPS, MulticastPPS, BroadcastPPS float64
}

// L2ControlPlaneRates bounds each control protocol independently. A zero rate
// leaves that class governed only by the optional aggregate ControlPlanePPS.
// BurstSeconds defaults to the switch storm burst when zero.
type L2ControlPlaneRates struct {
	ARP                 float64 `json:"arp_pps,omitempty"`
	DHCPv4              float64 `json:"dhcpv4_pps,omitempty"`
	DHCPv6              float64 `json:"dhcpv6_pps,omitempty"`
	NeighborDiscovery   float64 `json:"neighbor_discovery_pps,omitempty"`
	RouterAdvertisement float64 `json:"router_advertisement_pps,omitempty"`
	Multicast           float64 `json:"multicast_control_pps,omitempty"`
	MDNS                float64 `json:"mdns_pps,omitempty"`
	LLDP                float64 `json:"lldp_pps,omitempty"`
	EAPOL               float64 `json:"eapol_pps,omitempty"`
	Other               float64 `json:"other_pps,omitempty"`
	BurstSeconds        float64 `json:"burst_seconds,omitempty"`
}

func (r L2ControlPlaneRates) pps(class L2ControlClass) float64 {
	switch class {
	case L2ControlARP:
		return r.ARP
	case L2ControlDHCPv4:
		return r.DHCPv4
	case L2ControlDHCPv6:
		return r.DHCPv6
	case L2ControlNeighborDiscovery:
		return r.NeighborDiscovery
	case L2ControlRouterAdvertisement:
		return r.RouterAdvertisement
	case L2ControlMulticast:
		return r.Multicast
	case L2ControlMDNS:
		return r.MDNS
	case L2ControlLLDP:
		return r.LLDP
	case L2ControlEAPOL:
		return r.EAPOL
	default:
		return r.Other
	}
}

func (r L2ControlPlaneRates) values() []float64 {
	return []float64{r.ARP, r.DHCPv4, r.DHCPv6, r.NeighborDiscovery, r.RouterAdvertisement, r.Multicast, r.MDNS, r.LLDP, r.EAPOL, r.Other}
}

func (r L2ControlPlaneRates) enabled() bool {
	for _, rate := range r.values() {
		if rate > 0 {
			return true
		}
	}
	return false
}

// Validate checks rate/burst bounds and the port role that consumes the rates.
func (r L2ControlPlaneRates) Validate(controlPlane bool) error {
	for _, rate := range r.values() {
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || rate > 1_000_000 || rate > 0 && rate < 1 {
			return errors.New("per-class PPS must be 0 or 1..1000000")
		}
	}
	if r.enabled() && !controlPlane {
		return errors.New("per-class PPS requires a control-plane egress port")
	}
	burst := r.BurstSeconds
	if math.IsNaN(burst) || math.IsInf(burst, 0) || burst < 0 || burst > 60 || burst > 0 && burst < 1 {
		return errors.New("burst_seconds must be 0 or 1..60")
	}
	if burst > 0 && !r.enabled() {
		return errors.New("burst_seconds requires a per-class rate")
	}
	return nil
}

// L2PrivateVLANRole defines how a port communicates inside a private VLAN group.
type L2PrivateVLANRole uint8

const (
	L2PVLANNone L2PrivateVLANRole = iota
	L2PVLANPromiscuous
	L2PVLANIsolated
	L2PVLANCommunity
)

// L2VLANPolicy defines an access VLAN, a single-tag trunk, or an explicit
// Q-in-Q service/customer mapping. With all fields zero the port keeps legacy
// transparent behavior and accepts untagged or single-tag traffic.
type L2VLANPolicy struct {
	AccessVLAN           uint16   `json:"access_vlan,omitempty"`
	AllowedVLANs         []uint16 `json:"allowed_vlans,omitempty"`
	NativeVLAN           uint16   `json:"native_vlan,omitempty"`
	ServiceVLAN          uint16   `json:"service_vlan,omitempty"`
	CustomerVLAN         uint16   `json:"customer_vlan,omitempty"`
	AllowedCustomerVLANs []uint16 `json:"allowed_customer_vlans,omitempty"`
}

// EgressTagOverhead returns the maximum bytes this VLAN policy can add to an
// untagged customer frame. Access policies strip tags; a single-tag trunk adds
// four bytes and a Q-in-Q service trunk adds an S-tag plus C-tag (eight bytes).
func (v L2VLANPolicy) EgressTagOverhead() int {
	if v.ServiceVLAN != 0 {
		if v.CustomerVLAN != 0 {
			return 0
		}
		return 8
	}
	if len(v.AllowedVLANs) > 0 {
		return 4
	}
	return 0
}

// Validate checks VLAN IDs and mutually exclusive access/trunk settings.
func (v L2VLANPolicy) Validate() error {
	if v.AccessVLAN > 4094 || v.NativeVLAN > 4094 || v.ServiceVLAN > 4094 || v.CustomerVLAN > 4094 {
		return errors.New("l2 switch: VLAN IDs must be 1..4094")
	}
	if v.ServiceVLAN != 0 {
		if v.AccessVLAN != 0 || v.NativeVLAN != 0 || len(v.AllowedVLANs) != 0 {
			return errors.New("l2 switch: Q-in-Q service VLAN cannot combine with single-tag VLAN policy")
		}
		if v.CustomerVLAN != 0 && len(v.AllowedCustomerVLANs) != 0 {
			return errors.New("l2 switch: Q-in-Q customer access VLAN cannot combine with customer trunk VLANs")
		}
		if v.CustomerVLAN == 0 && len(v.AllowedCustomerVLANs) == 0 {
			return errors.New("l2 switch: Q-in-Q service trunk needs a customer VLAN allow-list")
		}
		seenCustomer := make(map[uint16]struct{}, len(v.AllowedCustomerVLANs))
		for _, customer := range v.AllowedCustomerVLANs {
			if customer == 0 || customer > 4094 {
				return errors.New("l2 switch: Q-in-Q customer VLAN IDs must be 1..4094")
			}
			if _, exists := seenCustomer[customer]; exists {
				return fmt.Errorf("l2 switch: duplicate Q-in-Q customer VLAN %d", customer)
			}
			seenCustomer[customer] = struct{}{}
		}
		return nil
	}
	if v.CustomerVLAN != 0 || len(v.AllowedCustomerVLANs) != 0 {
		return errors.New("l2 switch: Q-in-Q customer VLAN policy requires a service VLAN")
	}
	if v.AccessVLAN != 0 && (len(v.AllowedVLANs) > 0 || v.NativeVLAN != 0) {
		return errors.New("l2 switch: access VLAN cannot be combined with trunk VLANs")
	}
	seen := make(map[uint16]struct{}, len(v.AllowedVLANs))
	for _, vlan := range v.AllowedVLANs {
		if vlan == 0 || vlan > 4094 {
			return errors.New("l2 switch: allowed trunk VLAN IDs must be 1..4094")
		}
		if _, exists := seen[vlan]; exists {
			return fmt.Errorf("l2 switch: duplicate allowed VLAN %d", vlan)
		}
		seen[vlan] = struct{}{}
	}
	if v.NativeVLAN != 0 {
		if len(v.AllowedVLANs) == 0 {
			return errors.New("l2 switch: native VLAN requires a trunk allow-list")
		}
		if _, exists := seen[v.NativeVLAN]; !exists {
			return errors.New("l2 switch: native VLAN must be in the trunk allow-list")
		}
	}
	return nil
}

// L2Mirror copies frames entering or leaving Source to an output-only Monitor port.
// Mirror copies are reported separately from forwarding outputs so they never affect
// learning, flooding, isolation, or storm-control decisions.
type L2Mirror struct {
	Source, Monitor PortID
	Ingress, Egress bool
}

// L2SourceBinding authorizes one IPv4 or IPv6 address and Ethernet source on one guarded port.
type L2SourceBinding struct {
	VLAN      uint16 // legacy single-tag VLAN ID
	OuterVLAN uint16 // Q-in-Q service VLAN; zero for a single-tag binding
	InnerVLAN uint16 // Q-in-Q customer VLAN; zero for a single-tag binding
	IP        netip.Addr
	MAC       [6]byte
}

// L2SourcePrefix scopes SLAAC source learning to one VLAN or Q-in-Q domain.
type L2SourcePrefix struct {
	VLAN      uint16
	OuterVLAN uint16
	InnerVLAN uint16
	Prefix    netip.Prefix
}

type sourceBindingKey struct {
	vlan vlanID
	ip   netip.Addr
}

type saviClaim struct {
	port            PortID
	mac             [6]byte
	observed        time.Time
	confirmed       bool
	expires         time.Time
	conflictedUntil time.Time
}

type saviPrefixKey struct {
	vlan   vlanID
	prefix netip.Prefix
}

type saviPrefixLifetime struct {
	validUntil     time.Time
	preferredUntil time.Time
}

type l2Port struct {
	cfg            L2PortConfig
	invalidVLAN    bool
	macs           int
	blockedTo      time.Time
	bpduGuarded    bool
	moves          []time.Time
	uucast         bucket
	mcast          bucket
	bcast          bucket
	sourceBindings map[sourceBindingKey][6]byte
	staticBindings map[sourceBindingKey][6]byte
	controlPlane   bucket
	controlClasses [l2ControlClassCount]bucket
	authorizedMACs map[[6]byte]struct{}
}

type fdbEntry struct {
	port PortID
	seen time.Time
}

type vlanID struct {
	outer uint16
	inner uint16
}

// fdbKey keeps identical MAC addresses in separate 802.1Q or Q-in-Q domains.
type fdbKey struct {
	vlan vlanID
	mac  [6]byte
}

type mcastKey struct {
	vlan   vlanID
	family uint8
	group  [16]byte
}

type mcastSourceFilter struct {
	exclude bool
	sources map[[16]byte]struct{}
}

type mcastQuerierKey struct {
	port   PortID
	vlan   vlanID
	family uint8
}

type mcastMemberKey struct {
	group mcastKey
	port  PortID
}

type lastMemberQuery struct {
	next       time.Time
	completeAt time.Time
	remaining  int
}

// L2GeneratedFrame is a locally generated control frame that must enter the
// switch on IngressPort so ordinary VLAN, isolation, and mirror policy applies.
type L2GeneratedFrame struct {
	IngressPort PortID
	Frame       []byte
}

const maxMulticastGroups = 4096
const maxMulticastMembers = 65536
const maxMulticastSources = 65536
const multicastMembershipLifetime = 260 * time.Second
const defaultMulticastQueryInterval = 125 * time.Second
const defaultLastMemberQueryInterval = time.Second
const maxLastMemberQueryCount = 10

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
	L2Forward          L2Drop = ""
	L2DropMalform      L2Drop = "malformed"
	L2DropBlocked      L2Drop = "port_blocked"    // loop protection holds the ingress port
	L2DropMACLimit     L2Drop = "mac_limit"       // new source MAC beyond the port's cap
	L2DropStorm        L2Drop = "storm_control"   // unknown-unicast, multicast or broadcast over its rate
	L2DropNoPort       L2Drop = "unknown_port"    // ingress port is not configured
	L2DropFiltered     L2Drop = "same_port"       // destination is behind the ingress port; the segment already carried it
	L2DropIsolated     L2Drop = "port_isolation"  // both ports isolated
	L2DropBPDUGuard    L2Drop = "bpdu_guard"      // port has been disabled by BPDU guard
	L2DropRSTP         L2Drop = "rstp_discarding" // RSTP port is not in forwarding state
	L2DropVLAN         L2Drop = "vlan_filtered"   // ingress or egress port is not a member of the VLAN
	L2DropRAGuard      L2Drop = "ra_guard"        // Router Advertisement received on a guarded port
	L2DropSourceGuard  L2Drop = "ip_source_guard" // IPv4/ARP source does not match a DHCP binding
	L2DropCoPP         L2Drop = "control_plane_policed"
	L2DropUnauthorized L2Drop = "unauthorized_mac"
)

// L2Verdict is the forwarding decision for one frame.
type L2Verdict struct {
	Drop   L2Drop
	Out    []PortID // egress ports, never including the ingress port
	Mirror []PortID // monitor destinations that receive a copy of this frame
	// OutFrames contains per-port rewrites where VLAN tags differ from the input.
	// Callers should use FrameFor for every Out and Mirror destination.
	OutFrames    map[PortID][]byte
	MirrorFrames map[PortID][]byte
	// Flooded is true when the frame goes to several ports because its destination is
	// broadcast, multicast, or an unlearned unicast.
	Flooded bool
	Policed []PortID
}

// FrameFor returns the egress representation for a port, or the original frame
// when that port does not require VLAN tag insertion/removal.
func (v L2Verdict) FrameFor(port PortID, original []byte) []byte {
	if frame := v.OutFrames[port]; frame != nil {
		return frame
	}
	if frame := v.MirrorFrames[port]; frame != nil {
		return frame
	}
	return original
}

// L2SwitchStats are counters for the panel.
type L2SwitchStats struct {
	Forwarded, Flooded, Learned, Moves, Aged                                                      uint64
	DropBlocked, DropMACLimit, DropStorm, DropIsolated, DropOther                                 uint64
	DropBPDUGuard, DropVLAN, DropRAGuard, DropSourceGuard, DropCoPP, DropUnauthorized, BPDUGuards uint64
	DropRSTP                                                                                      uint64
	LoopHolds                                                                                     uint64
	FDBSize, MulticastGroups, MulticastMembers                                                    int
}

func NewL2Switch(cfg L2SwitchConfig) *L2Switch {
	s, err := NewL2SwitchChecked(cfg)
	if err != nil {
		panic(err)
	}
	return s
}

// NewL2SwitchChecked validates the complete static configuration before constructing a switch.
func NewL2SwitchChecked(cfg L2SwitchConfig) (*L2Switch, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
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
	if cfg.MulticastQueryInterval <= 0 || cfg.MulticastQueryInterval > multicastMembershipLifetime/2 {
		cfg.MulticastQueryInterval = defaultMulticastQueryInterval
	}
	if cfg.LastMemberQueryInterval <= 0 || cfg.LastMemberQueryInterval > 10*time.Second {
		cfg.LastMemberQueryInterval = defaultLastMemberQueryInterval
	}
	if cfg.LastMemberQueryCount <= 0 || cfg.LastMemberQueryCount > maxLastMemberQueryCount {
		cfg.LastMemberQueryCount = 2
	}
	s := &L2Switch{cfg: cfg, ports: map[PortID]*l2Port{}, fdb: map[fdbKey]*fdbEntry{}, groups: map[mcastKey]map[PortID]map[[6]byte]time.Time{}, sourceFilters: map[mcastKey]map[PortID]map[[6]byte]mcastSourceFilter{}, lastMemberQueries: map[mcastMemberKey]lastMemberQuery{}, querierUntil: map[vlanID]time.Time{}, saviClaims: map[sourceBindingKey]saviClaim{}, saviPrefixes: map[saviPrefixKey]saviPrefixLifetime{}, queryDue: map[mcastQuerierKey]time.Time{}, queryInterval: cfg.MulticastQueryInterval}
	if cfg.RSTPEnabled {
		priority := cfg.BridgePriority
		if priority == 0 && !cfg.BridgePrioritySet {
			priority = 32768
		}
		s.rstp = newRSTPBridge(priority, cfg.BridgeMAC, cfg.RSTPHelloTime, cfg.RSTPMaxAge, cfg.RSTPForwardDelay)
	}
	for _, p := range cfg.Ports {
		staticBindings := make(map[sourceBindingKey][6]byte, len(p.StaticSourceBindings))
		for _, binding := range p.StaticSourceBindings {
			vlan, _ := sourceBindingVLAN(binding)
			staticBindings[sourceBindingKey{vlan: vlan, ip: binding.IP}] = binding.MAC
		}
		s.ports[p.ID] = &l2Port{cfg: p, staticBindings: staticBindings, sourceBindings: cloneSourceBindings(staticBindings), invalidVLAN: p.VLAN.Validate() != nil || !validMulticastQuerier(p) || validatePVLAN(p) != nil || validateIPv6SourcePrefixes(p) != nil}
		if s.rstp != nil && p.RSTPParticipant && !p.Monitor && !p.BPDUGuard {
			_ = s.rstp.addPort(p)
		}
	}
	for _, m := range cfg.Mirrors {
		if m.Source == m.Monitor || (!m.Ingress && !m.Egress) {
			continue
		}
		source, monitor := s.ports[m.Source], s.ports[m.Monitor]
		if source == nil || monitor == nil || !monitor.cfg.Monitor {
			continue
		}
		s.mirrors = append(s.mirrors, m)
	}
	if cfg.MVR != nil && cfg.MVR.Validate() == nil {
		s.mvrMulticastVLAN = cfg.MVR.MulticastVLAN
		s.mvrGroups = make(map[mvrGroupKey]L2MVRGroup, len(cfg.MVR.Groups))
		for _, group := range cfg.MVR.Groups {
			group.ReceiverVLANs = slices.Clone(group.ReceiverVLANs)
			s.mvrGroups[mvrKey(group.Group)] = group
		}
	}
	return s, nil
}

// AddPort attaches a switch port at runtime. A port ID is stable for the lifetime of its
// connection and cannot be reused while already present.
func (s *L2Switch) AddPort(cfg L2PortConfig) error {
	if cfg.ID == 0 {
		return errors.New("l2 switch: port ID must be nonzero")
	}
	if err := cfg.VLAN.Validate(); err != nil {
		return err
	}
	if !validMulticastQuerier(cfg) {
		return errors.New("l2 switch: invalid multicast querier configuration")
	}
	if err := validatePVLAN(cfg); err != nil {
		return err
	}
	staticBindings, err := validateStaticSourceBindings(cfg)
	if err != nil {
		return err
	}
	if err := validateIPv6SourcePrefixes(cfg); err != nil {
		return err
	}
	if math.IsNaN(cfg.ControlPlanePPS) || math.IsInf(cfg.ControlPlanePPS, 0) || cfg.ControlPlanePPS < 0 || cfg.ControlPlanePPS > 1_000_000 || (cfg.ControlPlanePPS > 0 && cfg.ControlPlanePPS < 1) {
		return errors.New("l2 switch: control-plane PPS must be 0 or 1..1000000")
	}
	if cfg.ControlPlanePPS > 0 && !cfg.ControlPlane {
		return errors.New("l2 switch: control-plane PPS requires a control-plane egress port")
	}
	if err := cfg.ControlPlaneRates.Validate(cfg.ControlPlane); err != nil {
		return fmt.Errorf("l2 switch: %w", err)
	}
	if cfg.EAPOLAuthenticator && cfg.EAPOLAuthenticatorFor == "" || !cfg.EAPOLAuthenticator && cfg.EAPOLAuthenticatorFor != "" {
		return errors.New("l2 switch: EAPOL authenticator ports require exactly one paired session name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.ports[cfg.ID]; exists {
		return errors.New("l2 switch: port ID already exists")
	}
	for _, current := range s.ports {
		if !pvlanMappingsCompatible(current.cfg, cfg) {
			return errors.New("l2 switch: private VLAN ports in one group must share the same primary VLAN mapping")
		}
		if cfg.EAPOLAuthenticator && current.cfg.EAPOLAuthenticator && current.cfg.EAPOLAuthenticatorFor == cfg.EAPOLAuthenticatorFor {
			return errors.New("l2 switch: a session can have only one EAPOL authenticator port")
		}
	}
	if len(s.mvrGroups) > 0 {
		groups := make([]L2MVRGroup, 0, len(s.mvrGroups))
		for _, group := range s.mvrGroups {
			groups = append(groups, group)
		}
		if err := validateMVRReceiverPort(cfg, groups); err != nil {
			return err
		}
	}
	if cfg.BPDUGuard && cfg.RSTPParticipant && s.rstp != nil {
		return errors.New("l2 switch: BPDU guard and RSTP cannot be enabled on the same port")
	}
	if s.rstp != nil && cfg.RSTPParticipant && !cfg.Monitor {
		if err := s.rstp.addPort(cfg); err != nil {
			return err
		}
	}
	s.ports[cfg.ID] = &l2Port{cfg: cfg, staticBindings: staticBindings, sourceBindings: cloneSourceBindings(staticBindings)}
	return nil
}

func validatePVLAN(cfg L2PortConfig) error {
	if cfg.PVLANPrimaryVLAN == 0 {
		if cfg.PVLANSecondaryVLAN != 0 {
			return errors.New("l2 switch: private VLAN secondary VLAN requires a primary VLAN")
		}
	} else {
		if cfg.PrivateVLAN == 0 || cfg.PVLANPrimaryVLAN > 4094 || cfg.VLAN.ServiceVLAN != 0 {
			return errors.New("l2 switch: primary/secondary VLAN mapping requires a private VLAN group and single-tag VLAN policy")
		}
		switch cfg.PrivateVLANRole {
		case L2PVLANPromiscuous:
			if cfg.PVLANSecondaryVLAN != 0 || !policyAdmitsOnlyVLAN(cfg.VLAN, cfg.PVLANPrimaryVLAN) {
				return errors.New("l2 switch: promiscuous PVLAN port must admit only the primary VLAN and cannot set a secondary VLAN")
			}
		case L2PVLANIsolated, L2PVLANCommunity:
			if cfg.PVLANSecondaryVLAN == 0 || cfg.PVLANSecondaryVLAN > 4094 || cfg.PVLANSecondaryVLAN == cfg.PVLANPrimaryVLAN || !policyAdmitsOnlyVLAN(cfg.VLAN, cfg.PVLANSecondaryVLAN) {
				return errors.New("l2 switch: isolated/community PVLAN port must admit only a distinct secondary VLAN")
			}
		default:
			return errors.New("l2 switch: primary/secondary VLAN mapping requires a promiscuous, isolated, or community role")
		}
	}
	if cfg.PrivateVLAN == 0 {
		if cfg.PrivateVLANRole != L2PVLANNone || cfg.PVLANCommunity != 0 {
			return errors.New("l2 switch: private VLAN role/community requires a private VLAN ID")
		}
		return nil
	}
	if cfg.PrivateVLAN > 4094 || cfg.Isolated {
		return errors.New("l2 switch: private VLAN ID must be 1..4094 and cannot combine with legacy isolated mode")
	}
	switch cfg.PrivateVLANRole {
	case L2PVLANPromiscuous, L2PVLANIsolated:
		if cfg.PVLANCommunity != 0 {
			return errors.New("l2 switch: only community private VLAN ports may set a community ID")
		}
	case L2PVLANCommunity:
		if cfg.PVLANCommunity == 0 || cfg.PVLANCommunity > 4094 {
			return errors.New("l2 switch: community private VLAN ports need a community ID in 1..4094")
		}
	default:
		return errors.New("l2 switch: private VLAN ID requires a promiscuous, isolated, or community role")
	}
	return nil
}

func policyAdmitsOnlyVLAN(policy L2VLANPolicy, vlan uint16) bool {
	if policy.AccessVLAN != 0 {
		return policy.AccessVLAN == vlan
	}
	return policy.ServiceVLAN == 0 && len(policy.AllowedVLANs) == 1 && policy.AllowedVLANs[0] == vlan && (policy.NativeVLAN == 0 || policy.NativeVLAN == vlan)
}

func pvlanMappingsCompatible(a, b L2PortConfig) bool {
	if a.PVLANSecondaryVLAN != 0 && a.PVLANSecondaryVLAN == b.PVLANSecondaryVLAN && a.PVLANPrimaryVLAN != b.PVLANPrimaryVLAN {
		return false
	}
	if a.PrivateVLAN == 0 || a.PrivateVLAN != b.PrivateVLAN {
		return true
	}
	if a.PVLANPrimaryVLAN != b.PVLANPrimaryVLAN {
		return false
	}
	return a.PVLANSecondaryVLAN == 0 || b.PVLANSecondaryVLAN == 0 || a.PVLANSecondaryVLAN != b.PVLANSecondaryVLAN ||
		a.PrivateVLANRole == b.PrivateVLANRole && a.PVLANCommunity == b.PVLANCommunity
}

func pvlanForwardingVLAN(port *l2Port, vlan vlanID) (vlanID, bool) {
	if port == nil || port.cfg.PVLANPrimaryVLAN == 0 {
		return vlan, true
	}
	if vlan.inner != 0 {
		return vlanID{}, false
	}
	if port.cfg.PrivateVLANRole == L2PVLANPromiscuous && vlan.outer == port.cfg.PVLANPrimaryVLAN ||
		(port.cfg.PrivateVLANRole == L2PVLANIsolated || port.cfg.PrivateVLANRole == L2PVLANCommunity) && vlan.outer == port.cfg.PVLANSecondaryVLAN {
		return vlanID{outer: port.cfg.PVLANPrimaryVLAN}, true
	}
	return vlanID{}, false
}

func pvlanEgressVLAN(cfg L2PortConfig, vlan vlanID) vlanID {
	if cfg.PVLANPrimaryVLAN == 0 || vlan.inner != 0 || vlan.outer != cfg.PVLANPrimaryVLAN {
		return vlan
	}
	if cfg.PrivateVLANRole == L2PVLANPromiscuous {
		return vlanID{outer: cfg.PVLANPrimaryVLAN}
	}
	if cfg.PrivateVLANRole == L2PVLANIsolated || cfg.PrivateVLANRole == L2PVLANCommunity {
		return vlanID{outer: cfg.PVLANSecondaryVLAN}
	}
	return vlan
}

// SetPortMACAuthorized controls whether a source MAC may send data on a MACAuth port.
// EAPOL remains available before authorization. Revocation flushes learned forwarding
// and multicast state for that source so stale state cannot bypass a later re-authentication.
func (s *L2Switch) SetPortMACAuthorized(id PortID, mac [6]byte, authorized bool) error {
	if mac == [6]byte{} || mac[0]&1 != 0 {
		return errors.New("l2 switch: authorization requires a unicast source MAC")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	port := s.ports[id]
	if port == nil {
		return errors.New("l2 switch: authorization port does not exist")
	}
	if !port.cfg.MACAuth {
		return errors.New("l2 switch: MAC authorization is not enabled on port")
	}
	if authorized {
		if port.authorizedMACs == nil {
			port.authorizedMACs = make(map[[6]byte]struct{})
		}
		port.authorizedMACs[mac] = struct{}{}
		return nil
	}
	delete(port.authorizedMACs, mac)
	s.removePortMAC(id, mac)
	return nil
}

func (s *L2Switch) removePortMAC(id PortID, mac [6]byte) {
	for key, entry := range s.fdb {
		if entry.port == id && key.mac == mac {
			delete(s.fdb, key)
			s.stats.Aged++
		}
	}
	for key, ports := range s.groups {
		if reporters := ports[id]; reporters != nil {
			if _, exists := reporters[mac]; exists {
				delete(reporters, mac)
				s.multicastMembers--
			}
			if len(reporters) == 0 {
				delete(ports, id)
			}
		}
		if len(ports) == 0 {
			delete(s.groups, key)
		}
		delete(s.lastMemberQueries, mcastMemberKey{group: key, port: id})
	}
	for key, ports := range s.sourceFilters {
		if reporters := ports[id]; reporters != nil {
			if filter, exists := reporters[mac]; exists {
				s.multicastSources -= len(filter.sources)
				delete(reporters, mac)
			}
			if len(reporters) == 0 {
				delete(ports, id)
			}
		}
		if len(ports) == 0 {
			delete(s.sourceFilters, key)
		}
	}
}

// SetPortSourceBindings atomically replaces the learned DHCP binding set for a
// source-guarded port. Callers should only publish leases with authenticated
// ingress identity and remove them when the lease expires or the port detaches.
func (s *L2Switch) SetPortSourceBindings(id PortID, bindings []L2SourceBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	port := s.ports[id]
	if port == nil {
		return errors.New("l2 switch: source binding port does not exist")
	}
	if !port.cfg.IPv4SourceGuard && !port.cfg.IPv6SourceGuard {
		return errors.New("l2 switch: source guard is not enabled on port")
	}
	replacement := cloneSourceBindings(port.staticBindings)
	if replacement == nil {
		replacement = make(map[sourceBindingKey][6]byte, len(bindings))
	}
	for _, binding := range bindings {
		key, err := sourceBindingKeyForPort(port.cfg, binding)
		if err != nil {
			return err
		}
		if current, exists := replacement[key]; exists && current != binding.MAC {
			return fmt.Errorf("l2 switch: conflicting source binding for %s", binding.IP)
		}
		replacement[key] = binding.MAC
	}
	for key, claim := range s.saviClaims {
		if mac, exists := replacement[key]; exists && (claim.port != id || mac != claim.mac) {
			delete(s.saviClaims, key)
		}
	}
	port.sourceBindings = replacement
	return nil
}

func validateStaticSourceBindings(cfg L2PortConfig) (map[sourceBindingKey][6]byte, error) {
	if len(cfg.StaticSourceBindings) != 0 && !cfg.IPv4SourceGuard && !cfg.IPv6SourceGuard {
		return nil, errors.New("l2 switch: static source bindings require IPv4 or IPv6 source guard")
	}
	bindings := make(map[sourceBindingKey][6]byte, len(cfg.StaticSourceBindings))
	for _, binding := range cfg.StaticSourceBindings {
		key, err := sourceBindingKeyForPort(cfg, binding)
		if err != nil {
			return nil, err
		}
		if binding.IP.Is4() && !cfg.IPv4SourceGuard || binding.IP.Is6() && !cfg.IPv6SourceGuard {
			return nil, errors.New("l2 switch: static source binding address family requires its source guard to be enabled")
		}
		if current, exists := bindings[key]; exists && current != binding.MAC {
			return nil, fmt.Errorf("l2 switch: conflicting static source binding for %s", binding.IP)
		}
		bindings[key] = binding.MAC
	}
	return bindings, nil
}

func validateIPv6SourcePrefixes(cfg L2PortConfig) error {
	if len(cfg.IPv6SourcePrefixes) != 0 && !cfg.IPv6SourceGuard {
		return errors.New("l2 switch: SLAAC source prefixes require IPv6 source guard")
	}
	seen := make(map[vlanID]bool, len(cfg.IPv6SourcePrefixes))
	for _, item := range cfg.IPv6SourcePrefixes {
		vlan, ok := sourcePrefixVLAN(item)
		if !ok || !item.Prefix.IsValid() || !item.Prefix.Addr().Is6() || item.Prefix.Addr().Is4In6() || item.Prefix.Bits() != 64 || item.Prefix != item.Prefix.Masked() {
			return errors.New("l2 switch: SLAAC source prefix must be a canonical IPv6 /64 and VLAN")
		}
		binding := L2SourceBinding{VLAN: vlan.outer, OuterVLAN: vlan.outer, InnerVLAN: vlan.inner, IP: item.Prefix.Addr(), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
		if vlan.inner != 0 {
			binding.VLAN = 0
		} else {
			binding.OuterVLAN = 0
		}
		if _, err := sourceBindingKeyForPort(cfg, binding); err != nil {
			return errors.New("l2 switch: SLAAC source prefix VLAN is not admitted by the port")
		}
		if seen[vlan] {
			return errors.New("l2 switch: duplicate SLAAC source prefix VLAN")
		}
		seen[vlan] = true
	}
	return nil
}

func sourcePrefixVLAN(prefix L2SourcePrefix) (vlanID, bool) {
	if prefix.OuterVLAN != 0 || prefix.InnerVLAN != 0 {
		if prefix.VLAN != 0 || prefix.OuterVLAN == 0 || prefix.OuterVLAN > 4094 || prefix.InnerVLAN == 0 || prefix.InnerVLAN > 4094 {
			return vlanID{}, false
		}
		return vlanID{outer: prefix.OuterVLAN, inner: prefix.InnerVLAN}, true
	}
	if prefix.VLAN > 4094 {
		return vlanID{}, false
	}
	return vlanID{outer: prefix.VLAN}, true
}

func sourceBindingKeyForPort(cfg L2PortConfig, binding L2SourceBinding) (sourceBindingKey, error) {
	vlan, validVLAN := sourceBindingVLAN(binding)
	if !validVLAN || !binding.IP.IsValid() || binding.IP.Is4In6() || (!binding.IP.Is4() && !binding.IP.Is6()) || binding.IP.IsUnspecified() || binding.IP.IsMulticast() || binding.MAC == [6]byte{} || binding.MAC[0]&1 != 0 {
		return sourceBindingKey{}, errors.New("l2 switch: source binding must contain a valid VLAN, unicast IP address, and unicast MAC")
	}
	if cfg.VLAN.ServiceVLAN != 0 {
		if vlan.outer != cfg.VLAN.ServiceVLAN || cfg.VLAN.CustomerVLAN != 0 && vlan.inner != cfg.VLAN.CustomerVLAN || cfg.VLAN.CustomerVLAN == 0 && !slices.Contains(cfg.VLAN.AllowedCustomerVLANs, vlan.inner) {
			return sourceBindingKey{}, errors.New("l2 switch: source binding VLAN is not admitted by the port")
		}
	} else if vlan.inner != 0 || !policyAdmitsVLAN(cfg.VLAN, vlan.outer) {
		defaultVLAN := cfg.VLAN.AccessVLAN == 0 && cfg.VLAN.NativeVLAN == 0 && cfg.VLAN.ServiceVLAN == 0 && cfg.VLAN.CustomerVLAN == 0 && len(cfg.VLAN.AllowedVLANs) == 0 && len(cfg.VLAN.AllowedCustomerVLANs) == 0
		if vlan != (vlanID{}) || !defaultVLAN {
			return sourceBindingKey{}, errors.New("l2 switch: source binding VLAN is not admitted by the port")
		}
	}
	return sourceBindingKey{vlan: vlan, ip: binding.IP}, nil
}

func cloneSourceBindings(bindings map[sourceBindingKey][6]byte) map[sourceBindingKey][6]byte {
	if bindings == nil {
		return nil
	}
	copy := make(map[sourceBindingKey][6]byte, len(bindings))
	for key, mac := range bindings {
		copy[key] = mac
	}
	return copy
}

func sourceBindingVLAN(binding L2SourceBinding) (vlanID, bool) {
	if binding.OuterVLAN != 0 || binding.InnerVLAN != 0 {
		if binding.VLAN != 0 || binding.OuterVLAN == 0 || binding.InnerVLAN == 0 || binding.OuterVLAN > 4094 || binding.InnerVLAN > 4094 {
			return vlanID{}, false
		}
		return vlanID{outer: binding.OuterVLAN, inner: binding.InnerVLAN}, true
	}
	if binding.VLAN > 4094 {
		return vlanID{}, false
	}
	return vlanID{outer: binding.VLAN}, true
}

const (
	saviDADWindow = time.Second
	maxSAVIClaims = 8192
)

func (s *L2Switch) sourceGuardAllows(id PortID, port *l2Port, info FrameInfo, now time.Time) bool {
	switch info.EtherType {
	case etherARP:
		if !port.cfg.IPv4SourceGuard {
			return true
		}
		if !info.ARPValid {
			return false
		}
		if info.ARPSenderIP.IsUnspecified() {
			return info.ARPOp == 1 // RFC 5227 address probe; it makes no sender-IP claim.
		}
		return port.sourceBindings[sourceBindingKey{vlan: frameVLAN(info), ip: info.ARPSenderIP}] == info.ARPSenderMAC
	case etherIPv4:
		if !port.cfg.IPv4SourceGuard {
			return true
		}
		if info.IP == nil {
			return false
		}
		if info.IPv4SourceIP.IsUnspecified() {
			return info.IP.Protocol == 17 && info.IP.HasPorts && info.IP.SourcePort == 68 && info.IP.DestinationPort == 67
		}
		return port.sourceBindings[sourceBindingKey{vlan: frameVLAN(info), ip: info.IPv4SourceIP}] == info.Src
	case etherIPv6:
		if !port.cfg.IPv6SourceGuard {
			return true
		}
		if !info.IPv6SourceValid || info.IPv6SourceIP.IsMulticast() || info.IPv6GuardUnsafe {
			return false
		}
		if info.IPv6DADNeighborSolicit {
			return s.observeSAVIDAD(id, port, info, now)
		}
		if info.IPv6NDType == 135 || info.IPv6NDType == 136 {
			if !info.IPv6NDValid || !info.IPv6NDValidated || !s.observeSAVIConflict(id, info, now) {
				return false
			}
		}
		if info.IPv6NDType == 136 && (!info.IPv6NDValid || port.sourceBindings[sourceBindingKey{vlan: frameVLAN(info), ip: info.IPv6NDTargetIP}] != info.Src) {
			if !s.saviBindingMatches(id, frameVLAN(info), info.IPv6NDTargetIP, info.Src, now) {
				return false
			}
		}
		if info.IPv6SourceIP.IsUnspecified() {
			return info.DHCPv6Client
		}
		if info.IPv6SourceIP.IsLinkLocalUnicast() {
			return info.Control || info.RouterAdvertisement
		}
		key := sourceBindingKey{vlan: frameVLAN(info), ip: info.IPv6SourceIP}
		if mac, exists := port.sourceBindings[key]; exists {
			return mac == info.Src
		}
		return s.saviBindingMatches(id, key.vlan, key.ip, info.Src, now)
	default:
		return true
	}
}

func (s *L2Switch) observeSAVIDAD(id PortID, port *l2Port, info FrameInfo, now time.Time) bool {
	if !info.IPv6NDValid || !info.IPv6NDValidated || info.IPv6NDType != 135 || !info.IPv6SourceIP.IsUnspecified() {
		return false
	}
	if !portHasSAVIPrefix(port, frameVLAN(info), info.IPv6NDTargetIP) {
		return true // DAD remains available when SLAAC learning is not configured.
	}
	key := sourceBindingKey{vlan: frameVLAN(info), ip: info.IPv6NDTargetIP}
	if owner, mac, exists := s.sourceBindingOwner(key); exists {
		return owner == id && mac == info.Src
	}
	validUntil, active := s.saviPrefixLifetime(frameVLAN(info), info.IPv6NDTargetIP, now)
	if !active {
		return true // Do not learn from DAD until a trusted router advertises this prefix.
	}
	claim, exists := s.saviClaims[key]
	if exists && claim.confirmed && !now.Before(claim.expires) {
		delete(s.saviClaims, key)
		exists = false
	}
	if exists && !claim.conflictedUntil.IsZero() {
		if now.Before(claim.conflictedUntil) {
			return false
		}
		delete(s.saviClaims, key)
		exists = false
	}
	if !exists {
		if len(s.saviClaims) >= maxSAVIClaims {
			return false
		}
		s.saviClaims[key] = saviClaim{port: id, mac: info.Src, observed: now, expires: validUntil}
		return true
	}
	if claim.port != id || claim.mac != info.Src {
		if !claim.confirmed {
			claim.conflictedUntil = now.Add(saviDADWindow)
			s.saviClaims[key] = claim
		}
		return false
	}
	return true
}

func (s *L2Switch) observeSAVIConflict(id PortID, info FrameInfo, now time.Time) bool {
	if !info.IPv6NDValidated || !info.IPv6NDTargetIP.IsValid() {
		return false
	}
	key := sourceBindingKey{vlan: frameVLAN(info), ip: info.IPv6NDTargetIP}
	claim, exists := s.saviClaims[key]
	if exists && claim.confirmed && !now.Before(claim.expires) {
		delete(s.saviClaims, key)
		exists = false
	}
	if !exists || claim.port == id && claim.mac == info.Src {
		return true
	}
	if !claim.confirmed && now.Sub(claim.observed) > saviDADWindow {
		validUntil, active := s.saviPrefixLifetime(key.vlan, key.ip, now)
		if !active {
			delete(s.saviClaims, key)
			return false
		}
		claim.confirmed = true
		claim.expires = validUntil
		s.saviClaims[key] = claim
		return false
	}
	if !claim.confirmed {
		claim.conflictedUntil = now.Add(saviDADWindow)
		s.saviClaims[key] = claim
	}
	return false
}

func (s *L2Switch) saviBindingMatches(id PortID, vlan vlanID, ip netip.Addr, mac [6]byte, now time.Time) bool {
	key := sourceBindingKey{vlan: vlan, ip: ip}
	if owner, ownerMAC, exists := s.sourceBindingOwner(key); exists {
		return owner == id && ownerMAC == mac
	}
	claim, exists := s.saviClaims[key]
	if !exists || claim.port != id || claim.mac != mac {
		return false
	}
	validUntil, active := s.saviPrefixLifetime(vlan, ip, now)
	if !active || !now.Before(claim.expires) {
		delete(s.saviClaims, key)
		return false
	}
	if !claim.confirmed {
		if now.Sub(claim.observed) < saviDADWindow {
			return false
		}
		claim.confirmed = true
	}
	claim.expires = validUntil
	s.saviClaims[key] = claim
	return true
}

func (s *L2Switch) saviPrefixConfigured(vlan vlanID, prefix netip.Prefix) bool {
	for _, port := range s.ports {
		if !port.cfg.IPv6SourceGuard {
			continue
		}
		for _, configured := range port.cfg.IPv6SourcePrefixes {
			configuredVLAN, ok := sourcePrefixVLAN(configured)
			if ok && configuredVLAN == vlan && configured.Prefix == prefix {
				return true
			}
		}
	}
	return false
}

func (s *L2Switch) saviPrefixLifetime(vlan vlanID, ip netip.Addr, now time.Time) (time.Time, bool) {
	for key, lifetime := range s.saviPrefixes {
		if key.vlan == vlan && key.prefix.Contains(ip) && now.Before(lifetime.validUntil) {
			return lifetime.validUntil, true
		}
	}
	return time.Time{}, false
}

func (s *L2Switch) updateSAVIPrefixLifetimes(vlan vlanID, advertisements []IPv6PrefixAdvertisement, now time.Time) {
	for _, advertisement := range advertisements {
		if !s.saviPrefixConfigured(vlan, advertisement.Prefix) {
			continue
		}
		key := saviPrefixKey{vlan: vlan, prefix: advertisement.Prefix}
		if !advertisement.Autonomous || advertisement.ValidLifetime == 0 {
			delete(s.saviPrefixes, key)
			for claimKey := range s.saviClaims {
				if claimKey.vlan == vlan && advertisement.Prefix.Contains(claimKey.ip) {
					delete(s.saviClaims, claimKey)
				}
			}
			continue
		}
		validUntil := now.Add(time.Duration(advertisement.ValidLifetime) * time.Second)
		preferredUntil := now.Add(time.Duration(advertisement.PreferredLifetime) * time.Second)
		s.saviPrefixes[key] = saviPrefixLifetime{validUntil: validUntil, preferredUntil: preferredUntil}
		for claimKey, claim := range s.saviClaims {
			if claimKey.vlan == vlan && advertisement.Prefix.Contains(claimKey.ip) {
				claim.expires = validUntil
				s.saviClaims[claimKey] = claim
			}
		}
	}
}

func (s *L2Switch) sourceBindingOwner(key sourceBindingKey) (PortID, [6]byte, bool) {
	for id, port := range s.ports {
		if mac, exists := port.sourceBindings[key]; exists {
			return id, mac, true
		}
	}
	return 0, [6]byte{}, false
}

func portHasSAVIPrefix(port *l2Port, vlan vlanID, ip netip.Addr) bool {
	for _, item := range port.cfg.IPv6SourcePrefixes {
		prefixVLAN, ok := sourcePrefixVLAN(item)
		if ok && prefixVLAN == vlan && item.Prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func frameVLAN(info FrameInfo) vlanID {
	return vlanID{outer: info.VLAN, inner: info.InnerVLAN}
}

func validMulticastQuerier(cfg L2PortConfig) bool {
	if !cfg.MulticastQuerier {
		return true
	}
	if !cfg.MulticastRouter || cfg.Monitor || cfg.QuerierMAC == [6]byte{} || cfg.QuerierMAC[0]&1 != 0 {
		return false
	}
	ipv4 := cfg.QuerierIPv4
	ipv4Set := ipv4 != [4]byte{}
	if ipv4Set && (ipv4[0] == 0 || ipv4[0] >= 224) {
		return false
	}
	ipv6 := cfg.QuerierIPv6
	ipv6Set := ipv6 != [16]byte{}
	if ipv6Set && (ipv6[0] != 0xfe || ipv6[1]&0xc0 != 0x80) {
		return false
	}
	return ipv4Set || ipv6Set
}

// DueMulticastQueries returns standard IGMPv3/MLDv2 general queries for
// configured querier ports. The caller must pass each frame back through
// Forward on its IngressPort so normal switch policy selects egress ports.
// The first call emits immediately; later queries follow MulticastQueryInterval.
func (s *L2Switch) DueMulticastQueries(now time.Time) []L2GeneratedFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastObserved = now
	ids := make([]PortID, 0, len(s.ports))
	for id := range s.ports {
		ids = append(ids, id)
	}
	sortPorts(ids)
	var generated []L2GeneratedFrame
	for _, id := range ids {
		port := s.ports[id]
		if port == nil || !port.cfg.MulticastQuerier || !port.cfg.MulticastRouter || port.cfg.Monitor || port.invalidVLAN || port.bpduGuarded || now.Before(port.blockedTo) {
			continue
		}
		for _, vlan := range querierVLANs(port.cfg.VLAN) {
			if port.cfg.QuerierIPv4 != [4]byte{} {
				key := mcastQuerierKey{port: id, vlan: vlan, family: 4}
				if due := s.queryDue[key]; due.IsZero() || !now.Before(due) {
					frame := tagGeneratedQuery(buildIGMPv3GeneralQuery(port.cfg.QuerierMAC, port.cfg.QuerierIPv4), vlan, port.cfg.VLAN)
					generated = append(generated, L2GeneratedFrame{IngressPort: id, Frame: frame})
					s.queryDue[key] = now.Add(s.queryInterval)
				}
			}
			if port.cfg.QuerierIPv6 != [16]byte{} {
				key := mcastQuerierKey{port: id, vlan: vlan, family: 16}
				if due := s.queryDue[key]; due.IsZero() || !now.Before(due) {
					frame := tagGeneratedQuery(buildMLDv2GeneralQuery(port.cfg.QuerierMAC, port.cfg.QuerierIPv6), vlan, port.cfg.VLAN)
					generated = append(generated, L2GeneratedFrame{IngressPort: id, Frame: frame})
					s.queryDue[key] = now.Add(s.queryInterval)
				}
			}
		}
	}
	memberKeys := make([]mcastMemberKey, 0, len(s.lastMemberQueries))
	for key := range s.lastMemberQueries {
		memberKeys = append(memberKeys, key)
	}
	slices.SortFunc(memberKeys, func(a, b mcastMemberKey) int {
		if a.group.vlan != b.group.vlan {
			if a.group.vlan.outer != b.group.vlan.outer {
				return int(a.group.vlan.outer) - int(b.group.vlan.outer)
			}
			return int(a.group.vlan.inner) - int(b.group.vlan.inner)
		}
		if a.group.family != b.group.family {
			return int(a.group.family) - int(b.group.family)
		}
		if cmp := bytes.Compare(a.group.group[:], b.group.group[:]); cmp != 0 {
			return cmp
		}
		return int(a.port - b.port)
	})
	for _, key := range memberKeys {
		state, exists := s.lastMemberQueries[key]
		if !exists || now.Before(state.next) {
			continue
		}
		if state.remaining > 0 {
			queryPort := s.multicastQuerierPort(key.group.vlan, key.group.family)
			if queryPort == nil {
				delete(s.lastMemberQueries, key)
				continue
			}
			var frame []byte
			if key.group.family == 4 {
				var group [4]byte
				copy(group[:], key.group.group[:4])
				frame = buildIGMPv3GroupQuery(queryPort.cfg.QuerierMAC, queryPort.cfg.QuerierIPv4, group)
			} else {
				frame = buildMLDv2GroupQuery(queryPort.cfg.QuerierMAC, queryPort.cfg.QuerierIPv6, key.group.group)
			}
			frame = tagGeneratedQuery(frame, key.group.vlan, queryPort.cfg.VLAN)
			generated = append(generated, L2GeneratedFrame{IngressPort: queryPort.cfg.ID, Frame: frame})
			state.remaining--
			state.next = now.Add(s.cfg.LastMemberQueryInterval)
			if state.remaining == 0 {
				state.completeAt = state.next
			}
			s.lastMemberQueries[key] = state
			continue
		}
		if !state.completeAt.IsZero() && !now.Before(state.completeAt) {
			for reporter := range s.groups[key.group][key.port] {
				s.removeMulticastReporter(key.group, key.port, reporter)
			}
			delete(s.lastMemberQueries, key)
		}
	}
	return generated
}

func (s *L2Switch) multicastQuerierPort(vlan vlanID, family uint8) *l2Port {
	ids := make([]PortID, 0, len(s.ports))
	for id := range s.ports {
		ids = append(ids, id)
	}
	sortPorts(ids)
	for _, id := range ids {
		port := s.ports[id]
		if !port.cfg.MulticastQuerier || !port.cfg.MulticastRouter || port.invalidVLAN || port.bpduGuarded || port.cfg.Monitor {
			continue
		}
		if family == 4 && port.cfg.QuerierIPv4 == [4]byte{} || family == 16 && port.cfg.QuerierIPv6 == [16]byte{} {
			continue
		}
		for _, allowed := range querierVLANs(port.cfg.VLAN) {
			if allowed == vlan {
				return port
			}
		}
	}
	return nil
}

func (s *L2Switch) scheduleLastMemberQuery(key mcastKey, port PortID, now time.Time) {
	if !s.querierActive(key.vlan, now) || len(s.groups[key][port]) == 0 || s.multicastQuerierPort(key.vlan, key.family) == nil {
		return
	}
	s.lastMemberQueries[mcastMemberKey{group: key, port: port}] = lastMemberQuery{
		next: now, remaining: s.cfg.LastMemberQueryCount,
	}
}

func querierVLANs(policy L2VLANPolicy) []vlanID {
	if policy.ServiceVLAN != 0 {
		if policy.CustomerVLAN != 0 {
			return []vlanID{{outer: policy.ServiceVLAN, inner: policy.CustomerVLAN}}
		}
		vlans := make([]vlanID, 0, len(policy.AllowedCustomerVLANs))
		for _, customer := range policy.AllowedCustomerVLANs {
			vlans = append(vlans, vlanID{outer: policy.ServiceVLAN, inner: customer})
		}
		return vlans
	}
	if policy.AccessVLAN != 0 {
		return []vlanID{{outer: policy.AccessVLAN}}
	}
	if len(policy.AllowedVLANs) > 0 {
		vlans := slices.Clone(policy.AllowedVLANs)
		slices.Sort(vlans)
		out := make([]vlanID, len(vlans))
		for i, vlan := range vlans {
			out[i] = vlanID{outer: vlan}
		}
		return out
	}
	return []vlanID{{}}
}

func tagGeneratedQuery(frame []byte, vlan vlanID, policy L2VLANPolicy) []byte {
	if policy.ServiceVLAN != 0 {
		if policy.CustomerVLAN != 0 || vlan.outer != policy.ServiceVLAN || !slices.Contains(policy.AllowedCustomerVLANs, vlan.inner) {
			return frame
		}
		return encodeQinQFrame(frame, vlan, FrameInfo{}, policy)
	}
	if vlan.outer == 0 || policy.AccessVLAN != 0 || len(policy.AllowedVLANs) == 0 || vlan.outer == policy.NativeVLAN {
		return frame
	}
	return insertVLANTag(frame, vlan.outer, FrameInfo{})
}

func buildIGMPv3GeneralQuery(mac [6]byte, source [4]byte) []byte {
	frame := make([]byte, 14+24+12)
	copy(frame[:6], []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01})
	copy(frame[6:12], mac[:])
	binary.BigEndian.PutUint16(frame[12:14], etherIPv4)
	ip := frame[14:]
	ip[0], ip[8], ip[9] = 0x46, 1, 2 // IPv4, TTL 1, IGMP.
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[20], ip[21], ip[22], ip[23] = 0x94, 4, 0, 0 // Router Alert option.
	copy(ip[12:16], source[:])
	ip[16], ip[19] = 224, 1 // 224.0.0.1 all systems.
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:24]))
	igmp := ip[24:]
	igmp[0], igmp[1] = 0x11, 100 // IGMPv3 query, 10-second max response.
	igmp[8], igmp[9] = 2, 125    // QRV=2, QQIC=125 seconds.
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))
	return frame
}

func buildIGMPv3GroupQuery(mac [6]byte, source, group [4]byte) []byte {
	frame := buildIGMPv3GeneralQuery(mac, source)
	frame[0], frame[1], frame[2], frame[3] = 0x01, 0x00, 0x5e, group[1]&0x7f
	frame[4], frame[5] = group[2], group[3]
	ip := frame[14:]
	copy(ip[16:20], group[:])
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:24]))
	igmp := ip[24:]
	igmp[1] = 10 // 1-second maximum response time.
	copy(igmp[4:8], group[:])
	igmp[2], igmp[3] = 0, 0
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))
	return frame
}

func buildMLDv2GeneralQuery(mac [6]byte, source [16]byte) []byte {
	frame := make([]byte, 14+40+8+28)
	copy(frame[:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], mac[:])
	binary.BigEndian.PutUint16(frame[12:14], etherIPv6)
	ip := frame[14:]
	ip[0], ip[6], ip[7] = 0x60, 0, 1 // IPv6, Hop-by-Hop options, hop limit 1.
	binary.BigEndian.PutUint16(ip[4:6], 8+28)
	copy(ip[8:24], source[:])
	ip[24], ip[25], ip[39] = 0xff, 0x02, 1 // ff02::1 all nodes.
	hop := ip[40:48]
	copy(hop, []byte{58, 0, 5, 2, 0, 0, 1, 0}) // Router Alert option and PadN.
	icmp := ip[48:]
	icmp[0] = 130
	binary.BigEndian.PutUint16(icmp[4:6], 10000) // 10-second max response delay.
	icmp[24], icmp[25] = 2, 125                  // QRV=2, QQIC=125 seconds.
	pseudo := make([]byte, 40+len(icmp))
	copy(pseudo[:16], ip[8:24])
	copy(pseudo[16:32], ip[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = 58
	copy(pseudo[40:], icmp)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(pseudo))
	return frame
}

func buildMLDv2GroupQuery(mac [6]byte, source, group [16]byte) []byte {
	frame := buildMLDv2GeneralQuery(mac, source)
	copy(frame[:2], []byte{0x33, 0x33})
	copy(frame[2:6], group[12:16])
	ip := frame[14:]
	copy(ip[24:40], group[:])
	icmp := ip[48:]
	binary.BigEndian.PutUint16(icmp[4:6], 1000) // 1-second maximum response delay.
	copy(icmp[8:24], group[:])
	icmp[2], icmp[3] = 0, 0
	pseudo := make([]byte, 40+len(icmp))
	copy(pseudo[:16], ip[8:24])
	copy(pseudo[16:32], ip[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = 58
	copy(pseudo[40:], icmp)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(pseudo))
	return frame
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// AddMirror attaches a mirror rule to existing source and monitor ports.
// Monitor ports remain output-only and mirror copies never enter forwarding.
func (s *L2Switch) AddMirror(mirror L2Mirror) error {
	if mirror.Source == mirror.Monitor || (!mirror.Ingress && !mirror.Egress) {
		return errors.New("l2 switch: invalid mirror rule")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	source, monitor := s.ports[mirror.Source], s.ports[mirror.Monitor]
	if source == nil || monitor == nil || !monitor.cfg.Monitor {
		return errors.New("l2 switch: mirror source or monitor port is unavailable")
	}
	for _, existing := range s.mirrors {
		if existing == mirror {
			return errors.New("l2 switch: mirror rule already exists")
		}
	}
	s.mirrors = append(s.mirrors, mirror)
	return nil
}

// RemovePort detaches a port and removes every learned MAC and multicast membership
// associated with it so a later peer cannot inherit stale forwarding state.
func (s *L2Switch) RemovePort(id PortID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removePortAtLocked(id, s.lastObserved)
}

// RemovePortAt detaches a port using the caller's simulation/runtime clock.
func (s *L2Switch) RemovePortAt(id PortID, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removePortAtLocked(id, now)
}

func (s *L2Switch) removePortAtLocked(id PortID, now time.Time) bool {
	if _, exists := s.ports[id]; !exists {
		return false
	}
	delete(s.ports, id)
	for key, claim := range s.saviClaims {
		if claim.port == id {
			delete(s.saviClaims, key)
		}
	}
	if s.rstp != nil {
		s.rstp.removePort(id, now)
	}
	mirrors := s.mirrors[:0]
	for _, mirror := range s.mirrors {
		if mirror.Source != id && mirror.Monitor != id {
			mirrors = append(mirrors, mirror)
		}
	}
	s.mirrors = mirrors
	for key, entry := range s.fdb {
		if entry.port == id {
			delete(s.fdb, key)
			s.stats.Aged++
		}
	}
	for key, ports := range s.groups {
		if members := ports[id]; members != nil {
			s.multicastMembers -= len(members)
			delete(ports, id)
		}
		if len(ports) == 0 {
			delete(s.groups, key)
		}
	}
	for key, ports := range s.sourceFilters {
		for _, filter := range ports[id] {
			s.multicastSources -= len(filter.sources)
		}
		delete(ports, id)
		if len(ports) == 0 {
			delete(s.sourceFilters, key)
		}
	}
	for key := range s.queryDue {
		if key.port == id {
			delete(s.queryDue, key)
		}
	}
	for key := range s.lastMemberQueries {
		if key.port == id {
			delete(s.lastMemberQueries, key)
		}
	}
	return true
}

// Stats snapshots the counters.
func (s *L2Switch) Stats() L2SwitchStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.FDBSize = len(s.fdb)
	st.MulticastGroups = len(s.groups)
	st.MulticastMembers = s.multicastMembers
	return st
}

// FDBEntry describes a single learned MAC address binding.
type FDBEntry struct {
	MAC  [6]byte
	Port PortID
	VLAN uint16
	Age  time.Duration
}

// FDBEntries returns a snapshot of every currently learned MAC address
// binding. Callers that only care about a single port (e.g. a bridge
// exposing its LAN-facing side) should filter on Port themselves.
func (s *L2Switch) FDBEntries() []FDBEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FDBEntry, 0, len(s.fdb))
	for key, e := range s.fdb {
		if e == nil {
			continue
		}
		out = append(out, FDBEntry{MAC: key.mac, Port: e.port, VLAN: key.vlan.outer, Age: s.lastObserved.Sub(e.seen)})
	}
	return out
}

// DueRSTPBPDUs returns protocol frames that should be transmitted directly on
// each participating port. They are control frames and must not pass through
// Forward, which intentionally consumes incoming BPDUs.
func (s *L2Switch) DueRSTPBPDUs(now time.Time) map[PortID][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rstp == nil {
		return nil
	}
	s.lastObserved = now
	s.rstp.advance(now)
	return s.rstp.dueBPDUs(now)
}

// RSTPStatus returns the bridge ID, current root, and per-port role/state.
func (s *L2Switch) RSTPStatus() L2RSTPStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rstp == nil {
		return L2RSTPStatus{}
	}
	return s.rstp.status()
}

// RSTPPortState returns the current role and state for a port, or disabled
// when RSTP is off or the port does not participate.
func (s *L2Switch) RSTPPortState(id PortID) (RSTPPortRole, RSTPPortState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rstp == nil {
		return RSTPRoleDisabled, RSTPStateDisabled
	}
	return s.rstp.portStatus(id)
}

// Forward learns the frame's source and decides where it goes.
func (s *L2Switch) Forward(in PortID, frame []byte, now time.Time) L2Verdict {
	info, err := ParseFrame(frame)
	if err != nil {
		s.mu.Lock()
		s.stats.DropOther++
		var mirrors []PortID
		if port := s.ports[in]; port != nil && !port.cfg.Monitor {
			mirrors = s.ingressMirrors(in)
		}
		s.mu.Unlock()
		return L2Verdict{Drop: L2DropMalform, Mirror: mirrors, MirrorFrames: mirrorFrameMap(mirrors, frame)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastObserved = now
	port := s.ports[in]
	if port == nil {
		s.stats.DropOther++
		return L2Verdict{Drop: L2DropNoPort}
	}
	if port.cfg.Monitor {
		s.stats.DropOther++
		return L2Verdict{Drop: L2DropNoPort}
	}
	if port.bpduGuarded {
		s.stats.DropBPDUGuard++
		return s.droppedWithIngressMirror(in, L2DropBPDUGuard, frame)
	}
	if info.BPDU {
		if port.cfg.BPDUGuard {
			port.bpduGuarded = true
			s.removePortFDB(in)
			s.stats.BPDUGuards++
			s.stats.DropBPDUGuard++
			return s.droppedWithIngressMirror(in, L2DropBPDUGuard, frame)
		}
		if s.rstp != nil && port.cfg.RSTPParticipant {
			if info.VLANDepth != 0 {
				s.stats.DropOther++
				return s.droppedWithIngressMirror(in, L2DropMalform, frame)
			}
			if err := s.rstp.receive(in, frame, now); err != nil {
				s.stats.DropOther++
				return s.droppedWithIngressMirror(in, L2DropMalform, frame)
			}
			if s.rstp.takeTCFlush() {
				s.flushRSTPFDBExcept(in)
			}
			return L2Verdict{Mirror: s.ingressMirrors(in), MirrorFrames: mirrorFrameMap(s.ingressMirrors(in), frame)}
		}
		// Bridge-reserved protocol frames are never ordinary user traffic. A
		// nonparticipating service/router port consumes them unless guard applies.
		return L2Verdict{Mirror: s.ingressMirrors(in), MirrorFrames: mirrorFrameMap(s.ingressMirrors(in), frame)}
	}
	if s.rstp != nil {
		s.rstp.advance(now)
		if port.cfg.RSTPParticipant && s.rstp.portState(in) != RSTPStateForwarding {
			s.stats.DropRSTP++
			return s.droppedWithIngressMirror(in, L2DropRSTP, frame)
		}
	}
	if port.invalidVLAN {
		s.stats.DropVLAN++
		return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
	}
	vlan, accepted := ingressVLAN(port.cfg.VLAN, info)
	if !accepted {
		s.stats.DropVLAN++
		return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
	}
	info.VLAN, info.InnerVLAN = vlan.outer, vlan.inner
	forwardVLAN, accepted := pvlanForwardingVLAN(port, vlan)
	if !accepted {
		s.stats.DropVLAN++
		return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
	}
	if port.cfg.MACAuth && info.EtherType != etherEAPOL {
		if _, authorized := port.authorizedMACs[info.Src]; !authorized {
			s.stats.DropUnauthorized++
			return s.droppedWithIngressMirror(in, L2DropUnauthorized, frame)
		}
	}
	if port.cfg.RAGuard && (info.RouterAdvertisement || info.IPv6GuardUnsafe) {
		s.stats.DropRAGuard++
		return s.droppedWithIngressMirror(in, L2DropRAGuard, frame)
	}
	if port.cfg.MulticastRouter && info.RouterAdvertisementValid {
		s.updateSAVIPrefixLifetimes(vlan, info.IPv6PrefixAdvertisements, now)
	}
	if info.EtherType == etherIPv6 && !port.cfg.IPv6SourceGuard && (info.IPv6NDType == 135 || info.IPv6NDType == 136) {
		// Unprotected ports do not learn addresses, but their validated ND traffic
		// still participates in duplicate-address detection for a tentative claim.
		s.observeSAVIConflict(in, info, now)
	}
	if !s.sourceGuardAllows(in, port, info, now) {
		s.stats.DropSourceGuard++
		return s.droppedWithIngressMirror(in, L2DropSourceGuard, frame)
	}
	// Only a configured multicast-router port can establish a querier. A query
	// observed on the segment enables bounded snooping leases; without a recent
	// query, multicast falls back to flooding so stale state cannot blackhole it.
	if port.cfg.MulticastRouter && (info.IGMPQuery || info.MLDQuery) {
		s.querierUntil[forwardVLAN] = now.Add(multicastMembershipLifetime)
	}
	if now.Before(port.blockedTo) {
		s.stats.DropBlocked++
		return s.droppedWithIngressMirror(in, L2DropBlocked, frame)
	}
	if info.Src[0]&1 == 1 { // a group address is never a source
		s.stats.DropOther++
		return s.droppedWithIngressMirror(in, L2DropMalform, frame)
	}
	if info.EtherType == etherEAPOL {
		if drop := s.learn(port, in, forwardVLAN, info.Src, now); drop != L2Forward {
			return s.droppedWithIngressMirror(in, drop, frame)
		}
		var outs []PortID
		if port.cfg.MACAuth {
			for id, candidate := range s.ports {
				if candidate.cfg.EAPOLAuthenticator && candidate.cfg.EAPOLAuthenticatorFor == port.cfg.Name {
					outs = append(outs, id)
				}
			}
		} else if port.cfg.EAPOLAuthenticator {
			if destination := s.fdb[fdbKey{vlan: forwardVLAN, mac: info.Dst}]; destination != nil {
				if target := s.ports[destination.port]; target != nil && target.cfg.MACAuth && port.cfg.EAPOLAuthenticatorFor == target.cfg.Name {
					outs = append(outs, destination.port)
				}
			}
		} else {
			// Keep EAPOL transparent on ordinary bridges while keeping the
			// dedicated authenticator/session ports paired-only.
			for _, candidateID := range s.eligibleFloodPorts(in, port, now) {
				candidate := s.ports[candidateID]
				if candidate != nil && !candidate.cfg.MACAuth && !candidate.cfg.EAPOLAuthenticator {
					outs = append(outs, candidateID)
				}
			}
		}
		sortPorts(outs)
		allowed, rewrites, vlanRejected, policed := s.egressFrames(outs, frame, info, forwardVLAN, now)
		if len(allowed) == 0 {
			if len(policed) > 0 {
				return s.droppedWithIngressMirror(in, L2DropCoPP, frame)
			}
			if vlanRejected {
				s.stats.DropVLAN++
				return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
			}
			return s.droppedWithIngressMirror(in, L2DropFiltered, frame)
		}
		s.stats.Forwarded++
		verdict := s.withMirrors(in, allowed, frame, rewrites)
		verdict.Policed = policed
		return verdict
	}
	if drop := s.learn(port, in, forwardVLAN, info.Src, now); drop != L2Forward {
		return s.droppedWithIngressMirror(in, drop, frame)
	}
	if !info.MulticastRecordsMalformed {
		if len(info.MulticastRecords) > 0 {
			s.learnMulticastRecords(in, forwardVLAN, info.Src, info.MulticastRecords, now)
		} else {
			s.learnGroups4(in, forwardVLAN, info.Src, info.IGMPJoins, now)
			s.learnGroups6(in, forwardVLAN, info.Src, info.MLDJoins, now)
		}
	}
	for _, group := range info.IGMPLeaves {
		var address [16]byte
		copy(address[:4], group[:])
		s.scheduleLastMemberQuery(mcastKey{vlan: forwardVLAN, family: 4, group: address}, in, now)
	}
	for _, group := range info.MLDLeaves {
		s.scheduleLastMemberQuery(mcastKey{vlan: forwardVLAN, family: 16, group: group}, in, now)
	}
	depth := s.cfg.StormBurstSec
	dst, known := s.fdb[fdbKey{vlan: forwardVLAN, mac: info.Dst}]
	switch {
	case info.Broadcast:
		if !port.bcast.allow(port.cfg.BroadcastPPS, depth, now) {
			s.stats.DropStorm++
			return s.droppedWithIngressMirror(in, L2DropStorm, frame)
		}
	case info.Multicast:
		if !port.mcast.allow(port.cfg.MulticastPPS, depth, now) {
			s.stats.DropStorm++
			return s.droppedWithIngressMirror(in, L2DropStorm, frame)
		}
		if handled, verdict := s.forwardMVRReport(in, port, frame, info, now, vlan); handled {
			return verdict
		}
		if handled, verdict := s.forwardMVR(in, port, frame, info, now, vlan); handled {
			return verdict
		}
		if info.IGMPType == 0x16 { // IGMPv2 report destination is the reported group itself.
			outs := s.multicastRouterPorts(in, port, now)
			if len(outs) == 0 {
				outs = s.eligibleFloodPorts(in, port, now)
			}
			allowed, rewrites, vlanRejected, policed := s.egressFrames(outs, frame, info, forwardVLAN, now)
			if len(allowed) == 0 {
				if len(policed) > 0 {
					return s.droppedWithIngressMirror(in, L2DropCoPP, frame)
				}
				if vlanRejected {
					s.stats.DropVLAN++
					return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
				}
				return s.droppedWithIngressMirror(in, L2DropFiltered, frame)
			}
			s.stats.Forwarded++
			verdict := s.withMirrors(in, allowed, frame, rewrites)
			verdict.Policed = policed
			return verdict
		}
		// Link-local multicast, including mDNS (224.0.0.251 / ff02::fb),
		// must be bridged to all eligible ports. Host membership reports and
		// querier timers must not make these link-scoped control frames disappear.
		if info.MulticastIPLen != 0 && !isLinkLocalMulticast(info.MulticastIP, info.MulticastIPLen) {
			key := mcastKey{vlan: forwardVLAN, family: info.MulticastIPLen, group: info.MulticastIP}
			members := s.groups[key]
			if !s.querierActive(forwardVLAN, now) {
				members = nil // no current querier: flood instead of trusting stale snooping state
			}
			for id, reporters := range members {
				for mac, until := range reporters {
					if !until.IsZero() && now.After(until) {
						s.removeMulticastReporter(key, id, mac)
					}
				}
				reporters = members[id]
				if s.ports[id] == nil {
					for mac := range reporters {
						s.removeMulticastReporter(key, id, mac)
					}
				} else if len(reporters) == 0 {
					delete(members, id)
				}
			}
			if len(members) == 0 {
				delete(s.groups, key)
				members = nil
			}
			if len(members) > 0 {
				outs := make([]PortID, 0, len(members)+len(s.ports))
				seen := make(map[PortID]struct{}, len(members)+len(s.ports))
				for id, reporters := range members {
					if len(reporters) == 0 || id == in {
						continue
					}
					controlQuery := info.IGMPQuery || info.MLDQuery
					if out := s.ports[id]; out != nil && !now.Before(out.blockedTo) && portsCanExchange(port, out) && (controlQuery || s.multicastSourceAllowed(key, id, info.MulticastSource)) {
						outs = append(outs, id)
						seen[id] = struct{}{}
					}
				}
				// Router ports receive snooped multicast even without a host
				// membership report on that port.
				for _, id := range s.multicastRouterPorts(in, port, now) {
					if _, exists := seen[id]; !exists {
						outs = append(outs, id)
					}
				}
				sortPorts(outs)
				allowed, rewrites, vlanRejected, policed := s.egressFrames(outs, frame, info, forwardVLAN, now)
				if len(allowed) == 0 {
					if len(policed) > 0 {
						return s.droppedWithIngressMirror(in, L2DropCoPP, frame)
					}
					if vlanRejected {
						s.stats.DropVLAN++
						return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
					}
					return s.droppedWithIngressMirror(in, L2DropFiltered, frame)
				}
				s.stats.Forwarded++
				verdict := s.withMirrors(in, allowed, frame, rewrites)
				verdict.Policed = policed
				return verdict
			}
		}
	case !known || now.Sub(dst.seen) > s.cfg.AgeTime:
		if !port.uucast.allow(port.cfg.UnknownUnicastPPS, depth, now) {
			s.stats.DropStorm++
			return s.droppedWithIngressMirror(in, L2DropStorm, frame)
		}
		known = false
	}
	if known && !info.Multicast {
		if dst.port == in {
			return s.droppedWithIngressMirror(in, L2DropFiltered, frame)
		}
		out := s.ports[dst.port]
		if out == nil || !portsCanExchange(port, out) {
			s.stats.DropIsolated++
			return s.droppedWithIngressMirror(in, L2DropIsolated, frame)
		}
		allowed, rewrites, vlanRejected, policed := s.egressFrames([]PortID{dst.port}, frame, info, forwardVLAN, now)
		if len(allowed) == 0 {
			if len(policed) > 0 {
				return s.droppedWithIngressMirror(in, L2DropCoPP, frame)
			}
			if vlanRejected {
				s.stats.DropVLAN++
				return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
			}
			s.stats.DropIsolated++
			return s.droppedWithIngressMirror(in, L2DropIsolated, frame)
		}
		s.stats.Forwarded++
		verdict := s.withMirrors(in, allowed, frame, rewrites)
		verdict.Policed = policed
		return verdict
	}
	outs := s.eligibleFloodPorts(in, port, now)
	allowed, rewrites, vlanRejected, policed := s.egressFrames(outs, frame, info, forwardVLAN, now)
	if len(allowed) == 0 {
		if len(policed) > 0 {
			return s.droppedWithIngressMirror(in, L2DropCoPP, frame)
		}
		if vlanRejected {
			s.stats.DropVLAN++
			return s.droppedWithIngressMirror(in, L2DropVLAN, frame)
		}
		s.stats.DropIsolated++
		return s.droppedWithIngressMirror(in, L2DropIsolated, frame)
	}
	s.stats.Flooded++
	v := s.withMirrors(in, allowed, frame, rewrites)
	v.Policed = policed
	v.Flooded = true
	return v
}

func isLinkLocalMulticast(group [16]byte, family uint8) bool {
	switch family {
	case 4:
		return group[0] == 224 && group[1] == 0 && group[2] == 0
	case 16:
		scope := group[1] & 0x0f
		return group[0] == 0xff && (scope == 1 || scope == 2)
	default:
		return false
	}
}

func (s *L2Switch) multicastRouterPorts(in PortID, ingress *l2Port, now time.Time) []PortID {
	var outs []PortID
	for id, port := range s.ports {
		if id == in || !port.cfg.MulticastRouter || port.cfg.Monitor || now.Before(port.blockedTo) || !portsCanExchange(ingress, port) {
			continue
		}
		outs = append(outs, id)
	}
	sortPorts(outs)
	return outs
}

func (s *L2Switch) eligibleFloodPorts(in PortID, ingress *l2Port, now time.Time) []PortID {
	var outs []PortID
	for id, port := range s.ports {
		if id == in || port.cfg.Monitor || !portsCanExchange(ingress, port) || now.Before(port.blockedTo) {
			continue
		}
		outs = append(outs, id)
	}
	sortPorts(outs)
	return outs
}

func portsCanExchange(a, b *l2Port) bool {
	if a == nil || b == nil {
		return false
	}
	groupA, groupB := a.cfg.PrivateVLAN, b.cfg.PrivateVLAN
	if groupA == 0 && groupB == 0 {
		return !(a.cfg.Isolated && b.cfg.Isolated)
	}
	if groupA == 0 || groupA != groupB {
		return false
	}
	if a.cfg.PVLANPrimaryVLAN != b.cfg.PVLANPrimaryVLAN {
		return false
	}
	if a.cfg.PrivateVLANRole == L2PVLANPromiscuous || b.cfg.PrivateVLANRole == L2PVLANPromiscuous {
		return true
	}
	if a.cfg.PrivateVLANRole == L2PVLANIsolated || b.cfg.PrivateVLANRole == L2PVLANIsolated {
		return false
	}
	return a.cfg.PrivateVLANRole == L2PVLANCommunity && b.cfg.PrivateVLANRole == L2PVLANCommunity && a.cfg.PVLANCommunity == b.cfg.PVLANCommunity
}

func (s *L2Switch) withMirrors(in PortID, out []PortID, frame []byte, outFrames map[PortID][]byte) L2Verdict {
	copies := s.ingressMirrors(in)
	frames := mirrorFrameMap(copies, frame)
	seen := make(map[PortID]struct{}, len(copies)+len(s.mirrors))
	for _, port := range copies {
		seen[port] = struct{}{}
	}
	for _, mirror := range s.mirrors {
		if mirror.Egress && containsPort(out, mirror.Source) {
			if _, exists := seen[mirror.Monitor]; !exists {
				seen[mirror.Monitor] = struct{}{}
				copy := frame
				if rewritten := outFrames[mirror.Source]; rewritten != nil {
					copy = rewritten
				}
				if frames == nil {
					frames = make(map[PortID][]byte)
				}
				frames[mirror.Monitor] = copy
				copies = append(copies, mirror.Monitor)
			}
		}
	}
	sortPorts(copies)
	return L2Verdict{Out: out, Mirror: copies, OutFrames: outFrames, MirrorFrames: frames}
}

func mirrorFrameMap(ports []PortID, frame []byte) map[PortID][]byte {
	if len(ports) == 0 {
		return nil
	}
	frames := make(map[PortID][]byte, len(ports))
	for _, port := range ports {
		frames[port] = frame
	}
	return frames
}

func (s *L2Switch) droppedWithIngressMirror(in PortID, reason L2Drop, frame []byte) L2Verdict {
	ports := s.ingressMirrors(in)
	return L2Verdict{Drop: reason, Mirror: ports, MirrorFrames: mirrorFrameMap(ports, frame)}
}

func (s *L2Switch) ingressMirrors(in PortID) []PortID {
	seen := make(map[PortID]struct{}, len(s.mirrors))
	var copies []PortID
	for _, mirror := range s.mirrors {
		if mirror.Source == in && mirror.Ingress {
			if _, exists := seen[mirror.Monitor]; !exists {
				seen[mirror.Monitor] = struct{}{}
				copies = append(copies, mirror.Monitor)
			}
		}
	}
	sortPorts(copies)
	return copies
}

func containsPort(ports []PortID, target PortID) bool {
	for _, port := range ports {
		if port == target {
			return true
		}
	}
	return false
}

func ingressVLAN(policy L2VLANPolicy, info FrameInfo) (vlanID, bool) {
	if policy.ServiceVLAN != 0 {
		if policy.CustomerVLAN != 0 {
			if info.VLANDepth > 1 || (info.VLANDepth == 1 && info.VLAN != 0) {
				return vlanID{}, false
			}
			return vlanID{outer: policy.ServiceVLAN, inner: policy.CustomerVLAN}, true
		}
		if info.VLANDepth != 2 || info.OuterVLANType != etherVLANService || info.InnerVLANType != etherVLAN || info.VLAN != policy.ServiceVLAN || !slices.Contains(policy.AllowedCustomerVLANs, info.InnerVLAN) {
			return vlanID{}, false
		}
		return vlanID{outer: policy.ServiceVLAN, inner: info.InnerVLAN}, true
	}
	if info.VLANDepth > 1 {
		return vlanID{}, false
	}
	if policy.AccessVLAN != 0 {
		// Untagged and priority-tagged frames belong to the access VLAN. Other
		// tagged frames cannot cross an access port.
		if info.VLANDepth > 1 || (info.VLANDepth == 1 && info.VLAN != 0) {
			return vlanID{}, false
		}
		return vlanID{outer: policy.AccessVLAN}, true
	}
	if len(policy.AllowedVLANs) > 0 {
		if info.VLANDepth == 0 || info.VLAN == 0 {
			return vlanID{outer: policy.NativeVLAN}, policy.NativeVLAN != 0
		}
		return vlanID{outer: info.VLAN}, slices.Contains(policy.AllowedVLANs, info.VLAN)
	}
	return vlanID{outer: info.VLAN}, true
}

func (s *L2Switch) egressFrames(ports []PortID, frame []byte, info FrameInfo, vlan vlanID, now time.Time) ([]PortID, map[PortID][]byte, bool, []PortID) {
	allowed := make([]PortID, 0, len(ports))
	var rewrites map[PortID][]byte
	vlanRejected := false
	var policed []PortID
	for _, id := range ports {
		port := s.ports[id]
		if port == nil || port.cfg.Monitor || port.invalidVLAN {
			continue
		}
		egressVLAN := pvlanEgressVLAN(port.cfg, vlan)
		out, ok := encodeVLANForPort(frame, info, egressVLAN, port.cfg.VLAN)
		if !ok {
			vlanRejected = true
			continue
		}
		if info.Control && port.cfg.ControlPlane {
			class := info.ControlClass
			if class >= l2ControlClassCount {
				class = L2ControlOther
			}
			classBurst := port.cfg.ControlPlaneRates.BurstSeconds
			if classBurst == 0 {
				classBurst = s.cfg.StormBurstSec
			}
			classAllowed := port.controlClasses[class].allow(port.cfg.ControlPlaneRates.pps(class), classBurst, now)
			aggregateAllowed := classAllowed && port.controlPlane.allow(port.cfg.ControlPlanePPS, s.cfg.StormBurstSec, now)
			if !classAllowed || !aggregateAllowed {
				s.stats.DropCoPP++
				policed = append(policed, id)
				continue
			}
		}
		allowed = append(allowed, id)
		if !bytes.Equal(out, frame) {
			if rewrites == nil {
				rewrites = make(map[PortID][]byte)
			}
			rewrites[id] = out
		}
	}
	return allowed, rewrites, vlanRejected, policed
}

func encodeVLANForPort(frame []byte, info FrameInfo, vlan vlanID, policy L2VLANPolicy) ([]byte, bool) {
	if policy.ServiceVLAN != 0 {
		if vlan.outer != policy.ServiceVLAN {
			return nil, false
		}
		if policy.CustomerVLAN != 0 {
			if vlan.inner != policy.CustomerVLAN {
				return nil, false
			}
			return stripVLANTags(frame), true
		}
		if !slices.Contains(policy.AllowedCustomerVLANs, vlan.inner) {
			return nil, false
		}
		return encodeQinQFrame(frame, vlan, info, policy), true
	}
	if vlan.inner != 0 {
		return nil, false
	}
	if policy.AccessVLAN != 0 {
		if vlan.outer != policy.AccessVLAN {
			return nil, false
		}
		return stripVLANTags(frame), true
	}
	if len(policy.AllowedVLANs) > 0 {
		if !slices.Contains(policy.AllowedVLANs, vlan.outer) {
			return nil, false
		}
		if vlan.outer == policy.NativeVLAN && policy.NativeVLAN != 0 {
			return stripVLANTags(frame), true
		}
		if info.VLANDepth > 0 && info.VLAN != 0 {
			if info.VLAN == vlan.outer {
				return frame, true
			}
			return rewriteOuterVLANTag(frame, vlan.outer), true
		}
		return insertVLANTag(frame, vlan.outer, info), true
	}
	return frame, true
}

func rewriteOuterVLANTag(frame []byte, vlan uint16) []byte {
	if len(frame) < 18 || !isVLANTag(binary.BigEndian.Uint16(frame[12:14])) {
		return insertVLANTag(frame, vlan, FrameInfo{})
	}
	out := append([]byte(nil), frame...)
	tci := binary.BigEndian.Uint16(out[14:16])
	binary.BigEndian.PutUint16(out[14:16], tci&0xf000|(vlan&0x0fff))
	return out
}

func stripVLANTags(frame []byte) []byte {
	if len(frame) < 14 {
		return frame
	}
	typeOffset, bodyOffset := 12, 14
	etherType := binary.BigEndian.Uint16(frame[typeOffset : typeOffset+2])
	for tags := 0; tags < 2 && isVLANTag(etherType); tags++ {
		if len(frame) < bodyOffset+4 {
			return frame
		}
		typeOffset = bodyOffset + 2
		bodyOffset += 4
		etherType = binary.BigEndian.Uint16(frame[typeOffset : typeOffset+2])
	}
	if typeOffset == 12 {
		return frame
	}
	out := make([]byte, 0, len(frame)-(typeOffset-12))
	out = append(out, frame[:12]...)
	out = append(out, frame[typeOffset:]...)
	return out
}

func insertVLANTag(frame []byte, vlan uint16, info FrameInfo) []byte {
	if len(frame) < 14 {
		return frame
	}
	tci := vlan & 0x0fff
	if info.VLANDepth > 0 && len(frame) >= 16 {
		tci |= binary.BigEndian.Uint16(frame[14:16]) & 0xf000
	}
	out := make([]byte, 0, len(frame)+4)
	out = append(out, frame[:12]...)
	out = append(out, 0x81, 0x00, byte(tci>>8), byte(tci))
	out = append(out, frame[12:]...)
	return out
}

// encodeQinQFrame rewrites any existing tags into an S-tag/C-tag pair while
// preserving PCP/DEI bits from corresponding tags when available.
func encodeQinQFrame(frame []byte, vlan vlanID, info FrameInfo, policy L2VLANPolicy) []byte {
	if len(frame) < 14 || vlan.outer == 0 || vlan.inner == 0 {
		return frame
	}
	var outerTCI, innerTCI uint16
	if info.VLANDepth > 0 && len(frame) >= 16 {
		outerTCI = binary.BigEndian.Uint16(frame[14:16]) & 0xf000
	}
	if info.VLANDepth > 1 && len(frame) >= 20 {
		innerTCI = binary.BigEndian.Uint16(frame[18:20]) & 0xf000
	}
	base := stripVLANTags(frame)
	if len(base) < 14 {
		return frame
	}
	out := make([]byte, 0, len(base)+8)
	out = append(out, base[:12]...)
	out = append(out, 0x88, 0xa8, byte((outerTCI|vlan.outer&0x0fff)>>8), byte(outerTCI|vlan.outer&0x0fff))
	out = append(out, 0x81, 0x00, byte((innerTCI|vlan.inner&0x0fff)>>8), byte(innerTCI|vlan.inner&0x0fff))
	out = append(out, base[12:]...)
	return out
}

// ClearBPDUGuard re-enables a port disabled by BPDU guard. Learned addresses are flushed
// so traffic is relearned after the loop has been removed.
func (s *L2Switch) ClearBPDUGuard(id PortID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	port := s.ports[id]
	if port == nil || !port.bpduGuarded {
		return false
	}
	port.bpduGuarded = false
	s.removePortFDB(id)
	return true
}

func (s *L2Switch) removePortFDB(id PortID) {
	for key, entry := range s.fdb {
		if entry.port == id {
			delete(s.fdb, key)
			if port := s.ports[id]; port != nil && port.macs > 0 {
				port.macs--
			}
			s.stats.Aged++
		}
	}
}

// flushRSTPFDBExcept ages dynamic addresses learned behind participating RSTP
// ports, except entries learned on the port carrying the TC BPDU. Unrelated
// service/router ports remain outside the spanning-tree topology and retain
// their learned entries.
func (s *L2Switch) flushRSTPFDBExcept(ingress PortID) {
	for key, entry := range s.fdb {
		if entry.port == ingress {
			continue
		}
		port := s.ports[entry.port]
		if port == nil || !port.cfg.RSTPParticipant {
			continue
		}
		delete(s.fdb, key)
		if port.macs > 0 {
			port.macs--
		}
		s.stats.Aged++
	}
}

func (s *L2Switch) querierActive(vlan vlanID, now time.Time) bool {
	return now.Before(s.querierUntil[vlan])
}

func (s *L2Switch) learnGroups4(port PortID, vlan vlanID, reporter [6]byte, joins [][4]byte, now time.Time) {
	for _, group := range joins {
		if group[0] < 224 || group[0] > 239 {
			continue
		}
		var address [16]byte
		copy(address[:4], group[:])
		key := mcastKey{vlan: vlan, family: 4, group: address}
		delete(s.lastMemberQueries, mcastMemberKey{group: key, port: port})
		ports := s.groups[key]
		if ports == nil {
			if len(s.groups) >= maxMulticastGroups {
				continue
			}
			ports = make(map[PortID]map[[6]byte]time.Time)
			s.groups[key] = ports
		}
		members := ports[port]
		if members == nil {
			members = make(map[[6]byte]time.Time)
			ports[port] = members
		}
		until := time.Time{}
		if s.querierActive(vlan, now) {
			until = now.Add(multicastMembershipLifetime)
			// IGMP report suppression means a single host's report represents
			// listeners on the whole port; refresh the port's reporters together.
			for mac := range members {
				members[mac] = until
			}
		}
		if _, exists := members[reporter]; !exists {
			if s.multicastMembers >= maxMulticastMembers {
				continue
			}
			s.multicastMembers++
		}
		members[reporter] = until
		s.setSourceFilter(key, port, reporter, mcastSourceFilter{exclude: true, sources: map[[16]byte]struct{}{}})
	}
}

func (s *L2Switch) learnGroups6(port PortID, vlan vlanID, reporter [6]byte, joins [][16]byte, now time.Time) {
	for _, group := range joins {
		if group[0] != 0xff {
			continue
		}
		key := mcastKey{vlan: vlan, family: 16, group: group}
		delete(s.lastMemberQueries, mcastMemberKey{group: key, port: port})
		ports := s.groups[key]
		if ports == nil {
			if len(s.groups) >= maxMulticastGroups {
				continue
			}
			ports = make(map[PortID]map[[6]byte]time.Time)
			s.groups[key] = ports
		}
		members := ports[port]
		if members == nil {
			members = make(map[[6]byte]time.Time)
			ports[port] = members
		}
		until := time.Time{}
		if s.querierActive(vlan, now) {
			until = now.Add(multicastMembershipLifetime)
			for mac := range members {
				members[mac] = until
			}
		}
		if _, exists := members[reporter]; !exists {
			if s.multicastMembers >= maxMulticastMembers {
				continue
			}
			s.multicastMembers++
		}
		members[reporter] = until
		s.setSourceFilter(key, port, reporter, mcastSourceFilter{exclude: true, sources: map[[16]byte]struct{}{}})
	}
}

func (s *L2Switch) setSourceFilter(key mcastKey, port PortID, reporter [6]byte, filter mcastSourceFilter) bool {
	ports := s.sourceFilters[key]
	var oldCount int
	if reporters := ports[port]; reporters != nil {
		oldCount = len(reporters[reporter].sources)
	}
	if s.multicastSources-oldCount+len(filter.sources) > maxMulticastSources {
		return false
	}
	if ports == nil {
		ports = make(map[PortID]map[[6]byte]mcastSourceFilter)
		s.sourceFilters[key] = ports
	}
	reporters := ports[port]
	if reporters == nil {
		reporters = make(map[[6]byte]mcastSourceFilter)
		ports[port] = reporters
	}
	reporters[reporter] = filter
	s.multicastSources += len(filter.sources) - oldCount
	return true
}

func (s *L2Switch) learnMulticastRecords(port PortID, vlan vlanID, reporter [6]byte, records []MulticastRecord, now time.Time) {
	for _, record := range records {
		if record.Family != 4 && record.Family != 16 {
			continue
		}
		key := mcastKey{vlan: vlan, family: record.Family, group: record.Group}
		if key.family == 4 && (key.group[0] < 224 || key.group[0] > 239) || key.family == 16 && key.group[0] != 0xff {
			continue
		}
		var current mcastSourceFilter
		if reporters := s.sourceFilters[key][port]; reporters != nil {
			current = reporters[reporter]
		}
		if current.sources == nil {
			current.sources = make(map[[16]byte]struct{})
		}
		oldSourceCount := len(current.sources)
		current = cloneSourceFilter(current)
		switch record.RecordType {
		case 1, 3: // MODE_IS_INCLUDE / CHANGE_TO_INCLUDE_MODE
			current = sourceFilter(false, record.Sources)
		case 2, 4: // MODE_IS_EXCLUDE / CHANGE_TO_EXCLUDE_MODE
			current = sourceFilter(true, record.Sources)
		case 5, 6: // ALLOW_NEW_SOURCES / BLOCK_OLD_SOURCES
			for _, source := range record.Sources {
				if current.exclude {
					if record.RecordType == 5 {
						delete(current.sources, source)
					} else {
						current.sources[source] = struct{}{}
					}
				} else if record.RecordType == 5 {
					current.sources[source] = struct{}{}
				} else {
					delete(current.sources, source)
				}
			}
		default:
			continue
		}
		if !current.exclude && len(current.sources) == 0 {
			_, hasMembership := s.groups[key][port][reporter]
			if s.querierActive(vlan, now) && hasMembership {
				// Stop forwarding sources immediately, but retain port membership
				// through the local last-member response window or normal lease expiry.
				s.setSourceFilter(key, port, reporter, current)
				s.scheduleLastMemberQuery(key, port, now)
			} else if hasMembership {
				s.removeMulticastReporter(key, port, reporter)
			}
			continue
		}
		delete(s.lastMemberQueries, mcastMemberKey{group: key, port: port})
		members := s.groups[key]
		portMembers := members[port]
		_, alreadyMember := portMembers[reporter]
		if !alreadyMember && s.multicastMembers >= maxMulticastMembers {
			continue
		}
		if s.multicastSources-oldSourceCount+len(current.sources) > maxMulticastSources {
			continue
		}
		if members == nil {
			if len(s.groups) >= maxMulticastGroups {
				continue
			}
			members = make(map[PortID]map[[6]byte]time.Time)
			s.groups[key] = members
		}
		reporters := members[port]
		if reporters == nil {
			reporters = make(map[[6]byte]time.Time)
			members[port] = reporters
		}
		until := time.Time{}
		if s.querierActive(vlan, now) {
			until = now.Add(multicastMembershipLifetime)
			for mac := range reporters {
				reporters[mac] = until
			}
		}
		if _, exists := reporters[reporter]; !exists {
			s.multicastMembers++
		}
		reporters[reporter] = until
		s.setSourceFilter(key, port, reporter, current)
	}
}

func sourceFilter(exclude bool, sources [][16]byte) mcastSourceFilter {
	filter := mcastSourceFilter{exclude: exclude, sources: make(map[[16]byte]struct{}, len(sources))}
	for _, source := range sources {
		filter.sources[source] = struct{}{}
	}
	return filter
}

func cloneSourceFilter(filter mcastSourceFilter) mcastSourceFilter {
	clone := mcastSourceFilter{exclude: filter.exclude, sources: make(map[[16]byte]struct{}, len(filter.sources))}
	for source := range filter.sources {
		clone.sources[source] = struct{}{}
	}
	return clone
}

func (s *L2Switch) removeMulticastReporter(key mcastKey, port PortID, reporter [6]byte) {
	if members := s.groups[key][port]; members != nil {
		if _, exists := members[reporter]; exists {
			delete(members, reporter)
			s.multicastMembers--
		}
		if len(members) == 0 {
			delete(s.groups[key], port)
		}
		if len(s.groups[key]) == 0 {
			delete(s.groups, key)
		}
	}
	if reporters := s.sourceFilters[key][port]; reporters != nil {
		if filter, exists := reporters[reporter]; exists {
			s.multicastSources -= len(filter.sources)
		}
		delete(reporters, reporter)
		if len(reporters) == 0 {
			delete(s.sourceFilters[key], port)
		}
		if len(s.sourceFilters[key]) == 0 {
			delete(s.sourceFilters, key)
		}
	}
}

func (s *L2Switch) multicastSourceAllowed(key mcastKey, port PortID, source [16]byte) bool {
	filters := s.sourceFilters[key][port]
	if len(filters) == 0 {
		return true // legacy ASM membership
	}
	for _, filter := range filters {
		_, listed := filter.sources[source]
		if filter.exclude && !listed || !filter.exclude && listed {
			return true
		}
	}
	return false
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
func (s *L2Switch) learn(port *l2Port, in PortID, vlan vlanID, src [6]byte, now time.Time) L2Drop {
	key := fdbKey{vlan: vlan, mac: src}
	e := s.fdb[key]
	if e != nil && now.Sub(e.seen) > s.cfg.AgeTime {
		s.ageOut(key, e)
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
		s.fdb[key] = &fdbEntry{port: in, seen: now}
		port.macs++
		s.stats.Learned++
		return L2Forward
	}
	if e.port != in {
		oldPort := s.ports[e.port]
		sharedMobility := oldPort != nil && oldPort.cfg.MobilityGroup != "" && oldPort.cfg.MobilityGroup == port.cfg.MobilityGroup
		if sharedMobility {
			// The attachment is changing, but the logical endpoint is stable. Refresh FDB
			// ownership and the per-port MAC count without treating this as a loop.
			if port.cfg.MACLimit > 0 && port.macs >= port.cfg.MACLimit {
				s.stats.DropMACLimit++
				return L2DropMACLimit
			}
			if oldPort.macs > 0 {
				oldPort.macs--
			}
			port.macs++
			e.port = in
			e.seen = now
			s.stats.Moves++
			return L2Forward
		}
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

func (s *L2Switch) ageOut(key fdbKey, e *fdbEntry) {
	if p := s.ports[e.port]; p != nil && p.macs > 0 {
		p.macs--
	}
	delete(s.fdb, key)
	s.stats.Aged++
}

func (s *L2Switch) evictOldest(now time.Time) {
	var oldest fdbKey
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
	s.lastObserved = now
	n := 0
	for mac, e := range s.fdb {
		if now.Sub(e.seen) > s.cfg.AgeTime {
			s.ageOut(mac, e)
			n++
		}
	}
	for key, claim := range s.saviClaims {
		if !claim.conflictedUntil.IsZero() {
			if now.Before(claim.conflictedUntil) {
				continue
			}
			delete(s.saviClaims, key)
			continue
		}
		if s.ports[claim.port] == nil || !now.Before(claim.expires) {
			delete(s.saviClaims, key)
			continue
		}
		if !claim.confirmed && now.Sub(claim.observed) >= saviDADWindow {
			if _, active := s.saviPrefixLifetime(key.vlan, key.ip, now); !active {
				delete(s.saviClaims, key)
				continue
			}
			claim.confirmed = true
			s.saviClaims[key] = claim
		}
	}
	for key, ports := range s.groups {
		for port, reporters := range ports {
			for mac, until := range reporters {
				if !until.IsZero() && now.After(until) {
					s.removeMulticastReporter(key, port, mac)
				}
			}
			reporters = ports[port]
			if s.ports[port] == nil {
				for mac := range reporters {
					s.removeMulticastReporter(key, port, mac)
				}
			} else if len(reporters) == 0 {
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(s.groups, key)
			delete(s.sourceFilters, key)
		}
	}
	return n
}
