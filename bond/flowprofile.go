package bond

import (
	"container/list"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
)

// profileTags is adaptive_qos.PROFILE_TAGS.
var profileTags = map[string]byte{"bulk": 0, "stream": 18, "call": 26, "game": 46}

// FlowProfileCap and FlowProfileTTL are userspace.py's 4096-entry cache and
// its 120 s idle expiry.
const (
	FlowProfileCap = 4096
	FlowProfileTTL = 120 * time.Second
)

// FlowKey is the key IPv4Info.Flow holds for the same 5-tuple.
func FlowKey(protocol byte, src [4]byte, sport uint16, dst [4]byte, dport uint16) string {
	return normalizedFlow(protocol, src, dst, sport, dport)
}

// MarkDSCP is adaptive_qos.mark_dscp: set the DSCP, keep ECN, fix the header
// checksum. IPv4 only.
func MarkDSCP(packet []byte, tag byte) ([]byte, error) {
	if len(packet) < 1 || packet[0]>>4 != 4 {
		return nil, ErrFrame
	}
	if len(packet) < 2 {
		return nil, ErrFrame
	}
	if packet[1]>>2 == tag {
		return packet, nil
	}
	header := int(packet[0]&15) * 4
	if header < 20 || header > len(packet) {
		return nil, ErrFrame
	}
	out := append([]byte(nil), packet...)
	out[1] = tag<<2 | out[1]&3
	out[10], out[11] = 0, 0
	sum := uint32(0)
	for i := 0; i < header; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(out[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	binary.BigEndian.PutUint16(out[10:], ^uint16(sum))
	return out, nil
}

// ProfileTag returns the DSCP tag of a flow profile name.
func ProfileTag(profile string) (byte, bool) { t, ok := profileTags[profile]; return t, ok }

type profileEntry struct {
	key      string
	profile  string
	lastSeen time.Time
	order    *list.Element
}

// FlowProfiles is userspace.py's flow_profiles: application-chosen profiles
// per flow, fed by the netstack's app_flow_profile records.
type FlowProfiles struct {
	mu      sync.Mutex
	entries map[string]*profileEntry
	order   list.List
}

// Observe is observe_flow_profile. clientIP is config client_tunnel_ip. It
// reports whether the record was accepted.
func (f *FlowProfiles) Observe(record map[string]any, clientIP string, now time.Time) bool {
	profile, _ := record["profile"].(string)
	protocol, _ := record["protocol"].(string)
	switch profile {
	case "automatic", "bulk", "game", "call", "stream":
	default:
		return false
	}
	if protocol != "tcp" && protocol != "udp" {
		return false
	}
	src, sport, ok1 := splitEndpoint(record["source"])
	dst, dport, ok2 := splitEndpoint(record["destination"])
	if !ok1 || !ok2 || src.String() != clientIP {
		return false
	}
	proto := byte(6)
	if protocol == "udp" {
		proto = 17
	}
	var key string
	if src.Is4() && dst.Is4() {
		key = FlowKey(proto, src.As4(), sport, dst.As4(), dport)
	} else {
		// Python also stores mixed-family flows (they occupy cache slots but
		// no IPv4 packet can match them); keep them under an unmatchable key.
		key = "ÿ" + string([]byte{proto}) + src.String() + "|" + dst.String() + string(rune(sport)) + string(rune(dport))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entries == nil {
		f.entries = map[string]*profileEntry{}
	}
	e := f.entries[key]
	if e == nil {
		e = &profileEntry{key: key}
		e.order = f.order.PushBack(e)
		f.entries[key] = e
	} else {
		f.order.MoveToBack(e.order)
	}
	e.profile, e.lastSeen = profile, now
	for len(f.entries) > FlowProfileCap {
		old := f.order.Front().Value.(*profileEntry)
		delete(f.entries, old.key)
		f.order.Remove(old.order)
	}
	return true
}

// Lookup returns the flow's profile ("" when none or idle for over 120 s) and
// refreshes its last-seen time.
func (f *FlowProfiles) Lookup(flow string, now time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.entries[flow]
	if e == nil {
		return ""
	}
	if now.Sub(e.lastSeen) > FlowProfileTTL {
		delete(f.entries, flow)
		f.order.Remove(e.order)
		return ""
	}
	e.lastSeen = now
	return e.profile
}

func splitEndpoint(v any) (netip.Addr, uint16, bool) {
	s, ok := v.(string)
	if !ok {
		return netip.Addr{}, 0, false
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	addr, err := netip.ParseAddr(s[:i])
	if err != nil {
		return netip.Addr{}, 0, false
	}
	port, perr := parsePort(s[i+1:])
	if perr || port < 1 {
		return netip.Addr{}, 0, false
	}
	return addr, uint16(port), true
}

// parsePort accepts what int() accepts for a decimal port 1..65535 (ASCII
// digits, optional surrounding space and sign); the bool is true on failure.
func parsePort(s string) (int, bool) {
	s = strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) })
	s = strings.TrimPrefix(s, "+")
	if s == "" || strings.Contains(s, "__") || s[0] == '_' || s[len(s)-1] == '_' {
		return 0, true
	}
	n := 0
	for _, c := range strings.ReplaceAll(s, "_", "") {
		d, ok := decimalValue(c)
		if !ok {
			return 0, true
		}
		n = n*10 + d
		if n > 65535 {
			return 0, true
		}
	}
	return n, false
}

// ForProfile is AdaptiveQoS.classify with a profile: "automatic" or "" keeps
// the DSCP-derived class, otherwise the profile's tag and policy replace it.
// With QoS disabled the classification is returned unchanged.
func (c *Classifier) ForProfile(base Classification, profile string) Classification {
	if !c.qos.Enabled {
		return base
	}
	if profile == "automatic" {
		profile = ""
	}
	if profile == "" {
		for name, tag := range profileTags {
			if tag != 0 && tag == base.Tag {
				profile = name
			}
		}
	}
	tag, ok := profileTags[profile]
	if profile == "" || !ok {
		return base
	}
	// AdaptiveQoS.policies, not the operator's `queues` overrides: bulk is
	// always the default policy.
	policy := DefaultQueuePolicy()
	if tag != 0 {
		policy = c.policyFor(tag)
	}
	return Classification{base.Info, tag, policy, "app_profile_" + profile}
}

// QoSEnabled reports whether adaptive QoS is on.
func (c *Classifier) QoSEnabled() bool { return c.qos.Enabled }

// decimalValue is unicodedata.decimal for the Nd category: digit runs are
// contiguous blocks of ten starting at zero.
func decimalValue(r rune) (int, bool) {
	if !unicode.Is(unicode.Nd, r) {
		return 0, false
	}
	start := r
	for unicode.Is(unicode.Nd, start-1) {
		start--
	}
	return int(r-start) % 10, true
}
