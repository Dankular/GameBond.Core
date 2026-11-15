package bond

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"
)

// L2MVRConfig maps configured multicast groups arriving on MulticastVLAN into
// one or more receiver VLANs. Listener membership continues to be learned from
// IGMP/MLD reports in each receiver VLAN. Multicast sources must arrive on a
// MulticastRouter port. Link-local groups are intentionally excluded.
type L2MVRConfig struct {
	MulticastVLAN uint16       `json:"multicast_vlan"`
	Groups        []L2MVRGroup `json:"groups"`
}

// L2MVRGroup assigns one multicast IP group to one or more receiver VLANs.
// ReceiverVLAN is retained for existing configurations; new configurations
// should use ReceiverVLANs. A trunk port may carry at most one receiver VLAN
// for a given group because one Ethernet egress cannot carry two VLAN tags.
type L2MVRGroup struct {
	Group         netip.Addr `json:"group"`
	ReceiverVLAN  uint16     `json:"receiver_vlan,omitempty"`
	ReceiverVLANs []uint16   `json:"receiver_vlans,omitempty"`
}

func (g L2MVRGroup) receiverVLANs() []uint16 {
	if len(g.ReceiverVLANs) > 0 {
		return g.ReceiverVLANs
	}
	if g.ReceiverVLAN != 0 {
		return []uint16{g.ReceiverVLAN}
	}
	return nil
}

// ReceiverVLANIDs returns an independent list of the group's receiver VLANs.
// It normalizes the legacy single receiver_vlan field for consumers.
func (g L2MVRGroup) ReceiverVLANIDs() []uint16 {
	return slices.Clone(g.receiverVLANs())
}

type mvrGroupKey struct {
	family uint8
	group  [16]byte
}

// Validate checks the MVR multicast VLAN and group-to-receiver mappings.
func (c L2MVRConfig) Validate() error {
	if c.MulticastVLAN == 0 || c.MulticastVLAN > 4094 {
		return errors.New("l2 switch: MVR multicast VLAN must be in 1..4094")
	}
	if len(c.Groups) == 0 || len(c.Groups) > 4096 {
		return errors.New("l2 switch: MVR requires 1..4096 configured multicast groups")
	}
	seen := make(map[mvrGroupKey]struct{}, len(c.Groups))
	for _, entry := range c.Groups {
		if !entry.Group.IsValid() || !entry.Group.IsMulticast() || entry.Group.Is4In6() || isLinkLocalGroup(entry.Group) {
			return fmt.Errorf("l2 switch: MVR group %q must be a non-link-local multicast address", entry.Group)
		}
		if entry.ReceiverVLAN != 0 && len(entry.ReceiverVLANs) > 0 {
			return fmt.Errorf("l2 switch: MVR group %s cannot set both receiver_vlan and receiver_vlans", entry.Group)
		}
		receiverVLANs := entry.receiverVLANs()
		if len(receiverVLANs) == 0 || len(receiverVLANs) > 32 {
			return fmt.Errorf("l2 switch: MVR group %s must map to 1..32 receiver VLANs", entry.Group)
		}
		seenVLANs := make(map[uint16]struct{}, len(receiverVLANs))
		for _, vlan := range receiverVLANs {
			if vlan == 0 || vlan > 4094 || vlan == c.MulticastVLAN {
				return errors.New("l2 switch: MVR receiver VLAN must be 1..4094 and differ from multicast VLAN")
			}
			if _, exists := seenVLANs[vlan]; exists {
				return fmt.Errorf("l2 switch: MVR group %s has duplicate receiver VLAN %d", entry.Group, vlan)
			}
			seenVLANs[vlan] = struct{}{}
		}
		key := mvrKey(entry.Group)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("l2 switch: duplicate MVR group %s", entry.Group)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Validate checks that the MVR source VLAN has a configured multicast-router
// port and every receiver VLAN has at least one egress member.
func (c L2SwitchConfig) Validate() error {
	if err := ValidatePVLANPorts(c.Ports); err != nil {
		return err
	}
	for _, port := range c.Ports {
		if math.IsNaN(port.ControlPlanePPS) || math.IsInf(port.ControlPlanePPS, 0) || port.ControlPlanePPS < 0 || port.ControlPlanePPS > 1_000_000 || port.ControlPlanePPS > 0 && port.ControlPlanePPS < 1 {
			return fmt.Errorf("port %d: control-plane PPS must be 0 or 1..1000000", port.ID)
		}
		if port.ControlPlanePPS > 0 && !port.ControlPlane {
			return fmt.Errorf("port %d: control-plane PPS requires a control-plane egress port", port.ID)
		}
		if err := port.ControlPlaneRates.Validate(port.ControlPlane); err != nil {
			return fmt.Errorf("port %d: %w", port.ID, err)
		}
		if _, err := validateStaticSourceBindings(port); err != nil {
			return fmt.Errorf("port %d: %w", port.ID, err)
		}
		if err := validateIPv6SourcePrefixes(port); err != nil {
			return fmt.Errorf("port %d: %w", port.ID, err)
		}
	}
	if !c.RSTPEnabled {
		for _, port := range c.Ports {
			if port.RSTPParticipant || port.RSTPEdge || port.RSTPSharedLink || port.RSTPPathCost != 0 {
				return errors.New("l2 switch: RSTP port settings require RSTP to be enabled")
			}
		}
	}
	if c.RSTPEnabled {
		if c.BridgePriority != 0 && (c.BridgePriority > 61440 || c.BridgePriority%4096 != 0) {
			return errors.New("l2 switch: RSTP bridge priority must be 0 or a multiple of 4096 through 61440")
		}
		hello, maxAge, forward := c.RSTPHelloTime, c.RSTPMaxAge, c.RSTPForwardDelay
		if hello == 0 {
			hello = 2 * time.Second
		}
		if maxAge == 0 {
			maxAge = 20 * time.Second
		}
		if forward == 0 {
			forward = 15 * time.Second
		}
		if !validRSTPTimers(0, maxAge, hello, forward) {
			return errors.New("l2 switch: invalid RSTP hello/max-age/forward-delay timer combination")
		}
		seenPorts := make(map[PortID]bool)
		for _, port := range c.Ports {
			if !port.RSTPParticipant {
				continue
			}
			if port.ID <= 0 || port.ID > 4095 || seenPorts[port.ID] {
				return errors.New("l2 switch: RSTP participant port IDs must be unique and in 1..4095")
			}
			seenPorts[port.ID] = true
			if port.BPDUGuard {
				return errors.New("l2 switch: BPDU guard and RSTP cannot be enabled on the same port")
			}
			if port.RSTPPathCost > 200000000 {
				return errors.New("l2 switch: RSTP path cost exceeds 200000000")
			}
		}
	}
	if c.MVR == nil {
		return nil
	}
	if err := c.MVR.Validate(); err != nil {
		return err
	}
	for _, port := range c.Ports {
		if err := validateMVRReceiverPort(port, c.MVR.Groups); err != nil {
			return fmt.Errorf("port %d: %w", port.ID, err)
		}
	}
	if c.DynamicPorts {
		return nil // the broker validates the complete port set before serving sessions
	}
	source, receivers := false, make(map[uint16]bool)
	for _, group := range c.MVR.Groups {
		for _, vlan := range group.receiverVLANs() {
			receivers[vlan] = false
		}
	}
	for _, port := range c.Ports {
		if port.MulticastRouter && policyAdmitsVLAN(port.VLAN, c.MVR.MulticastVLAN) {
			source = true
		}
		for vlan := range receivers {
			if policyAdmitsVLAN(port.VLAN, vlan) {
				receivers[vlan] = true
			}
		}
	}
	if !source {
		return errors.New("l2 switch: MVR multicast VLAN needs a multicast-router source port")
	}
	for vlan, present := range receivers {
		if !present {
			return fmt.Errorf("l2 switch: MVR receiver VLAN %d has no member port", vlan)
		}
	}
	return nil
}

// ValidatePVLANPorts checks primary/secondary VLAN associations across a
// complete set of static ports. Callers that attach ports dynamically should
// validate their configured session and service-port set before starting.
func ValidatePVLANPorts(ports []L2PortConfig) error {
	return validatePVLANMappings(ports)
}

func validatePVLANMappings(ports []L2PortConfig) error {
	type mapping struct {
		primary     uint16
		promiscuous bool
		secondary   map[uint16]struct {
			role      L2PrivateVLANRole
			community uint16
		}
	}
	mappings := make(map[uint16]*mapping)
	secondaryPrimary := make(map[uint16]uint16)
	for _, port := range ports {
		if port.PVLANPrimaryVLAN == 0 {
			continue
		}
		if err := validatePVLAN(port); err != nil {
			return fmt.Errorf("port %d: %w", port.ID, err)
		}
		m := mappings[port.PrivateVLAN]
		if m == nil {
			m = &mapping{primary: port.PVLANPrimaryVLAN, secondary: make(map[uint16]struct {
				role      L2PrivateVLANRole
				community uint16
			})}
			mappings[port.PrivateVLAN] = m
		} else if m.primary != port.PVLANPrimaryVLAN {
			return fmt.Errorf("l2 switch: private VLAN group %d has conflicting primary VLANs", port.PrivateVLAN)
		}
		if port.PrivateVLANRole == L2PVLANPromiscuous {
			m.promiscuous = true
			continue
		}
		if primary, exists := secondaryPrimary[port.PVLANSecondaryVLAN]; exists && primary != port.PVLANPrimaryVLAN {
			return fmt.Errorf("l2 switch: private VLAN secondary %d maps to more than one primary VLAN", port.PVLANSecondaryVLAN)
		}
		secondaryPrimary[port.PVLANSecondaryVLAN] = port.PVLANPrimaryVLAN
		secondary := struct {
			role      L2PrivateVLANRole
			community uint16
		}{port.PrivateVLANRole, port.PVLANCommunity}
		if previous, exists := m.secondary[port.PVLANSecondaryVLAN]; exists && previous != secondary {
			return fmt.Errorf("l2 switch: private VLAN secondary %d has conflicting roles or community IDs", port.PVLANSecondaryVLAN)
		}
		m.secondary[port.PVLANSecondaryVLAN] = secondary
	}
	if len(mappings) == 0 {
		return nil
	}
	for _, port := range ports {
		if port.PVLANPrimaryVLAN != 0 || port.PrivateVLANRole != L2PVLANNone {
			continue
		}
		for groupID, m := range mappings {
			if policyAdmitsVLAN(port.VLAN, m.primary) {
				return fmt.Errorf("port %d admits private VLAN primary %d without a PVLAN role in group %d", port.ID, m.primary, groupID)
			}
			for secondary := range m.secondary {
				if policyAdmitsVLAN(port.VLAN, secondary) {
					return fmt.Errorf("port %d admits private VLAN secondary %d without a PVLAN role in group %d", port.ID, secondary, groupID)
				}
			}
		}
	}
	for groupID, m := range mappings {
		if !m.promiscuous {
			return fmt.Errorf("l2 switch: private VLAN group %d needs a promiscuous primary-VLAN port", groupID)
		}
	}
	return nil
}

func policyAdmitsVLAN(policy L2VLANPolicy, vlan uint16) bool {
	if policy.ServiceVLAN != 0 {
		return false
	}
	if policy.AccessVLAN != 0 {
		return policy.AccessVLAN == vlan
	}
	if len(policy.AllowedVLANs) != 0 {
		return slices.Contains(policy.AllowedVLANs, vlan)
	}
	return false
}

func mvrKey(group netip.Addr) mvrGroupKey {
	if group.Is4() {
		v := group.As4()
		var address [16]byte
		copy(address[:4], v[:])
		return mvrGroupKey{family: 4, group: address}
	}
	return mvrGroupKey{family: 16, group: group.As16()}
}

func isLinkLocalGroup(group netip.Addr) bool {
	var address [16]byte
	if group.Is4() {
		v := group.As4()
		copy(address[:4], v[:])
		return isLinkLocalMulticast(address, 4)
	}
	if group.Is6() {
		address = group.As16()
		return isLinkLocalMulticast(address, 16)
	}
	return false
}

func (s *L2Switch) forwardMVR(in PortID, ingress *l2Port, frame []byte, info FrameInfo, now time.Time, sourceVLAN vlanID) (bool, L2Verdict) {
	if s.mvrGroups == nil || sourceVLAN.inner != 0 || sourceVLAN.outer != s.mvrMulticastVLAN || !ingress.cfg.MulticastRouter || info.MulticastIPLen == 0 {
		return false, L2Verdict{}
	}
	entry, configured := s.mvrGroups[mvrGroupKey{family: info.MulticastIPLen, group: info.MulticastIP}]
	if !configured {
		return false, L2Verdict{}
	}
	var allowed []PortID
	rewrites := make(map[PortID][]byte)
	seenOut := make(map[PortID]struct{})
	var policed []PortID
	vlanRejected := false
	for _, receiver := range entry.receiverVLANs() {
		receiverVLAN := vlanID{outer: receiver}
		membershipVLAN := receiverVLAN
		for _, candidate := range s.ports {
			if candidate.cfg.PVLANSecondaryVLAN == receiver {
				membershipVLAN = vlanID{outer: candidate.cfg.PVLANPrimaryVLAN}
				break
			}
		}
		key := mcastKey{vlan: membershipVLAN, family: info.MulticastIPLen, group: info.MulticastIP}
		members := s.groups[key]
		querier := s.querierActive(membershipVLAN, now)
		if !querier {
			members = nil
		}
		if members != nil {
			for id, reporters := range members {
				for mac, until := range reporters {
					if !until.IsZero() && !now.Before(until) {
						s.removeMulticastReporter(key, id, mac)
					}
				}
				if s.ports[id] == nil {
					for mac := range members[id] {
						s.removeMulticastReporter(key, id, mac)
					}
				}
			}
			members = s.groups[key]
		}
		var outs []PortID
		fallback := !querier || len(members) == 0
		if !fallback {
			for id, reporters := range members {
				if id != in && len(reporters) > 0 {
					if port := s.ports[id]; port != nil && portCanReceiveMVRVLAN(port.cfg, receiver) && !now.Before(port.blockedTo) && portsCanExchange(ingress, port) && s.multicastSourceAllowed(key, id, info.MulticastSource) {
						outs = append(outs, id)
					}
				}
			}
		}
		// Without a current querier or membership, fail open only within this
		// configured receiver VLAN. Egress filtering prevents cross-VLAN leakage.
		if fallback {
			for id, port := range s.ports {
				if id != in && !port.cfg.Monitor && !now.Before(port.blockedTo) && portsCanExchange(ingress, port) && portCanReceiveMVRVLAN(port.cfg, receiver) {
					outs = append(outs, id)
				}
			}
		}
		sortPorts(outs)
		vlanAllowed, vlanRewrites, rejected, rateLimited := s.egressFrames(outs, frame, info, receiverVLAN, now)
		vlanRejected = vlanRejected || rejected
		policed = append(policed, rateLimited...)
		for _, id := range vlanAllowed {
			if _, duplicate := seenOut[id]; duplicate {
				continue
			}
			seenOut[id] = struct{}{}
			allowed = append(allowed, id)
			if rewritten := vlanRewrites[id]; len(rewritten) > 0 {
				rewrites[id] = rewritten
			}
		}
	}
	if len(allowed) == 0 {
		if len(policed) > 0 {
			return true, s.droppedWithIngressMirror(in, L2DropCoPP, frame)
		}
		if vlanRejected {
			s.stats.DropVLAN++
			return true, s.droppedWithIngressMirror(in, L2DropVLAN, frame)
		}
		return true, s.droppedWithIngressMirror(in, L2DropFiltered, frame)
	}
	sortPorts(allowed)
	s.stats.Forwarded++
	verdict := s.withMirrors(in, allowed, frame, rewrites)
	verdict.Policed = policed
	return true, verdict
}

func portCanReceiveMVRVLAN(cfg L2PortConfig, receiverVLAN uint16) bool {
	if cfg.PVLANPrimaryVLAN != 0 {
		return cfg.PVLANPrimaryVLAN == receiverVLAN && cfg.PrivateVLANRole == L2PVLANPromiscuous || cfg.PVLANSecondaryVLAN == receiverVLAN
	}
	return policyAdmitsVLAN(cfg.VLAN, receiverVLAN)
}

func validateMVRReceiverPort(port L2PortConfig, groups []L2MVRGroup) error {
	for _, group := range groups {
		admitted := 0
		for _, vlan := range group.receiverVLANs() {
			if portCanReceiveMVRVLAN(port, vlan) {
				admitted++
			}
		}
		if admitted > 1 {
			return fmt.Errorf("MVR trunk or PVLAN port cannot receive group %s on multiple mapped receiver VLANs", group.Group)
		}
	}
	return nil
}

func (s *L2Switch) forwardMVRReport(in PortID, ingress *l2Port, frame []byte, info FrameInfo, now time.Time, receiverVLAN vlanID) (bool, L2Verdict) {
	if s.mvrGroups == nil || receiverVLAN.inner != 0 {
		return false, L2Verdict{}
	}
	matches := func(family uint8, group [16]byte) bool {
		entry, ok := s.mvrGroups[mvrGroupKey{family: family, group: group}]
		return ok && slices.Contains(entry.receiverVLANs(), receiverVLAN.outer)
	}
	registered := false
	for _, group := range info.IGMPJoins {
		var address [16]byte
		copy(address[:4], group[:])
		registered = registered || matches(4, address)
	}
	for _, group := range info.IGMPLeaves {
		var address [16]byte
		copy(address[:4], group[:])
		registered = registered || matches(4, address)
	}
	for _, group := range info.MLDJoins {
		registered = registered || matches(16, group)
	}
	for _, group := range info.MLDLeaves {
		registered = registered || matches(16, group)
	}
	for _, record := range info.MulticastRecords {
		registered = registered || matches(record.Family, record.Group)
	}
	if !registered {
		return false, L2Verdict{}
	}
	var routers []PortID
	for id, port := range s.ports {
		if id != in && port.cfg.MulticastRouter && !port.cfg.Monitor && !now.Before(port.blockedTo) && portsCanExchange(ingress, port) && policyAdmitsVLAN(port.cfg.VLAN, s.mvrMulticastVLAN) {
			routers = append(routers, id)
		}
	}
	sortPorts(routers)
	if len(routers) == 0 {
		return false, L2Verdict{}
	}
	multicastVLAN := vlanID{outer: s.mvrMulticastVLAN}
	allowed, rewrites, rejected, policed := s.egressFrames(routers, frame, info, multicastVLAN, now)
	if len(allowed) == 0 {
		if len(policed) > 0 {
			return true, s.droppedWithIngressMirror(in, L2DropCoPP, frame)
		}
		if rejected {
			s.stats.DropVLAN++
			return true, s.droppedWithIngressMirror(in, L2DropVLAN, frame)
		}
		return true, s.droppedWithIngressMirror(in, L2DropFiltered, frame)
	}
	s.stats.Forwarded++
	verdict := s.withMirrors(in, allowed, frame, rewrites)
	verdict.Policed = policed
	return true, verdict
}
