package bond

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
)

const gatewayProvisioningWireVersion = 1
const gatewayProvisioningMaxPayload = 1024
const gatewayProvisioningMaxExtension = 7 + gatewayProvisioningMaxPayload

var gatewayProvisioningMagic = [4]byte{'G', 'B', 'P', 'C'}

// GatewayMode is the topology-assigned role of an exit for one segment.
type GatewayMode string

const (
	GatewayDisabled    GatewayMode = "disabled"
	GatewayPrimary     GatewayMode = "primary"
	GatewayPassthrough GatewayMode = "passthrough"
)

// GatewayLinkProvisioning is the point-to-point gVisor link configuration
// delivered to the client after the authenticated GB03 handshake completes.
type GatewayLinkProvisioning struct {
	ClientAddress string `json:"client_address"`
	ExitAddress   string `json:"exit_address"`
	MTU           uint16 `json:"mtu"`
}

// GatewayProvisioning describes one exit's topology assignment. DHCP lease
// records are intentionally absent: the primary gateway remains their sole
// authority and clients receive only the gateway's link configuration.
type GatewayProvisioning struct {
	Revision        uint64                  `json:"revision"`
	TopologyID      string                  `json:"topology_id"`
	SegmentID       string                  `json:"segment_id"`
	ExitID          string                  `json:"exit_id"`
	Mode            GatewayMode             `json:"mode"`
	Link            GatewayLinkProvisioning `json:"link"`
	GatewayAddress  string                  `json:"gateway_address,omitempty"`
	DHCPAuthorityID string                  `json:"dhcp_authority_id,omitempty"`
	// Routes are operator-assigned IPv4 prefixes routed through this exit.
	Routes []string `json:"routes,omitempty"`
	// ClientHosts are fixed addresses the client's own gVisor stack serves by DHCP for devices
	// bridged from its adapter. The exit keeps each address reserved and does not answer for the
	// MAC. Primary and passthrough exits both carry the same list, so the client serves the same
	// hosts whichever exit it is connected to. Older clients reject the field, so an exit sends it
	// only when configured.
	ClientHosts []GatewayClientHost `json:"client_hosts,omitempty"`
	// ClientDNS are the resolvers the client hands out with ClientHosts (at most 3 IPv4).
	ClientDNS []string `json:"client_dns,omitempty"`
}

// MaxGatewayClientHosts bounds ClientHosts so the extension stays inside its payload limit.
const MaxGatewayClientHosts = 8

// GatewayClientHost is one fixed DHCP reservation the client serves.
type GatewayClientHost struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
}

// Validate checks the fields required to safely establish an exit link. A
// primary must name the unique DHCP authority; passthrough and disabled exits
// may not claim DHCP ownership.
func (p GatewayProvisioning) Validate() error {
	if p.Revision == 0 || !validProvisioningID(p.TopologyID) || !validProvisioningID(p.SegmentID) || !validProvisioningID(p.ExitID) {
		return errors.New("gateway provisioning requires revision and topology, segment, and exit IDs")
	}
	switch p.Mode {
	case GatewayDisabled:
		if p.DHCPAuthorityID != "" {
			return errors.New("disabled gateway cannot name a DHCP authority")
		}
	case GatewayPrimary:
		if !validProvisioningID(p.DHCPAuthorityID) || p.DHCPAuthorityID != p.ExitID {
			return errors.New("primary gateway must be the named DHCP authority")
		}
	case GatewayPassthrough:
		if !validProvisioningID(p.DHCPAuthorityID) || p.DHCPAuthorityID == p.ExitID {
			return errors.New("passthrough gateway must name another exit as DHCP authority")
		}
	default:
		return errors.New("gateway mode must be disabled, primary, or passthrough")
	}
	if p.Mode != GatewayDisabled {
		client, err := netip.ParsePrefix(p.Link.ClientAddress)
		if err != nil || !client.Addr().Is4() {
			return errors.New("gateway link client_address must be an IPv4 prefix")
		}
		exit, err := netip.ParseAddr(p.Link.ExitAddress)
		if err != nil || !exit.Is4() || !client.Contains(exit) || exit == client.Addr() {
			return errors.New("gateway link exit_address must be a distinct IPv4 address in the client subnet")
		}
		if p.Link.MTU < 576 || p.Link.MTU > 9000 {
			return errors.New("gateway link mtu must be in 576..9000")
		}
		if p.GatewayAddress != "" {
			gateway, err := netip.ParseAddr(p.GatewayAddress)
			if err != nil || !gateway.Is4() {
				return errors.New("gateway_address must be IPv4")
			}
		}
	}
	if err := p.validateClientHosts(); err != nil {
		return err
	}
	if len(p.Routes) > 32 {
		return errors.New("gateway provisioning supports at most 32 routes")
	}
	seenRoutes := make(map[netip.Prefix]struct{}, len(p.Routes))
	for _, route := range p.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return errors.New("gateway routes must be canonical, non-default IPv4 prefixes")
		}
		if _, exists := seenRoutes[prefix]; exists {
			return errors.New("gateway routes must not contain duplicates")
		}
		seenRoutes[prefix] = struct{}{}
	}
	return nil
}

func (p GatewayProvisioning) validateClientHosts() error {
	if len(p.ClientHosts) == 0 {
		if len(p.ClientDNS) != 0 {
			return errors.New("client DNS requires client DHCP hosts")
		}
		return nil
	}
	if len(p.ClientDNS) > 3 {
		return errors.New("gateway provisioning supports at most 3 client DNS servers")
	}
	for _, d := range p.ClientDNS {
		if a, err := netip.ParseAddr(d); err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
			return errors.New("client DNS servers must be unicast IPv4 addresses")
		}
	}
	if p.Mode == GatewayDisabled {
		return errors.New("a disabled gateway cannot delegate DHCP hosts to the client")
	}
	if len(p.ClientHosts) > MaxGatewayClientHosts {
		return errors.New("gateway provisioning supports at most 8 client DHCP hosts")
	}
	client, _ := netip.ParsePrefix(p.Link.ClientAddress)
	exit, _ := netip.ParseAddr(p.Link.ExitAddress)
	subnet := client.Masked()
	broadcast := subnet.Addr().As4()
	for i := range broadcast {
		bits := client.Bits() - i*8
		switch {
		case bits >= 8:
		case bits <= 0:
			broadcast[i] = 0xff
		default:
			broadcast[i] |= 0xff >> bits
		}
	}
	seenMAC, seenIP := map[string]bool{}, map[netip.Addr]bool{}
	for _, h := range p.ClientHosts {
		mac, err := net.ParseMAC(h.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != h.MAC {
			return errors.New("client DHCP host mac must be a canonical lower-case unicast Ethernet address")
		}
		ip, err := netip.ParseAddr(h.IP)
		if err != nil || !ip.Is4() || !subnet.Contains(ip) || ip == subnet.Addr() || ip.As4() == broadcast || ip == exit || ip == client.Addr() {
			return errors.New("client DHCP host ip must be a usable IPv4 host address in the client subnet")
		}
		if len(h.Name) > 32 {
			return errors.New("client DHCP host name is too long")
		}
		for _, c := range h.Name {
			if c < 0x21 || c > 0x7e {
				return errors.New("client DHCP host name must be printable ASCII without spaces")
			}
		}
		if seenMAC[h.MAC] || seenIP[ip] {
			return errors.New("client DHCP hosts must not repeat a mac or ip")
		}
		seenMAC[h.MAC], seenIP[ip] = true, true
	}
	return nil
}

func validProvisioningID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func encodeGatewayProvisioning(p *GatewayProvisioning) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(p)
	if err != nil || len(body) == 0 || len(body) > gatewayProvisioningMaxPayload {
		return nil, errors.New("gateway provisioning payload is invalid or too large")
	}
	out := make([]byte, 7+len(body))
	copy(out[:4], gatewayProvisioningMagic[:])
	out[4] = gatewayProvisioningWireVersion
	binary.BigEndian.PutUint16(out[5:7], uint16(len(body)))
	copy(out[7:], body)
	return out, nil
}

func decodeGatewayProvisioning(payload []byte) (*GatewayProvisioning, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if len(payload) < 7 || !bytes.Equal(payload[:4], gatewayProvisioningMagic[:]) || payload[4] != gatewayProvisioningWireVersion {
		return nil, errors.New("unsupported gateway provisioning extension")
	}
	n := int(binary.BigEndian.Uint16(payload[5:7]))
	if n == 0 || n > gatewayProvisioningMaxPayload || len(payload) != 7+n {
		return nil, errors.New("invalid gateway provisioning extension length")
	}
	var p GatewayProvisioning
	dec := json.NewDecoder(bytes.NewReader(payload[7:]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, errors.New("invalid gateway provisioning payload")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("invalid trailing gateway provisioning data")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func cloneGatewayProvisioning(p *GatewayProvisioning) *GatewayProvisioning {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Routes = append([]string(nil), p.Routes...)
	copy.ClientHosts = append([]GatewayClientHost(nil), p.ClientHosts...)
	copy.ClientDNS = append([]string(nil), p.ClientDNS...)
	return &copy
}
