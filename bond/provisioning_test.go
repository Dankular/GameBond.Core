package bond

import "testing"

func primaryProvisioning(hosts ...GatewayClientHost) GatewayProvisioning {
	return GatewayProvisioning{Revision: 1, TopologyID: "t", SegmentID: "s", ExitID: "e", Mode: GatewayPrimary, DHCPAuthorityID: "e",
		Link:        GatewayLinkProvisioning{ClientAddress: "10.77.0.2/24", ExitAddress: "10.77.0.1", MTU: 1400},
		ClientHosts: hosts}
}

func TestClientHostsRoundTripThroughTheWire(t *testing.T) {
	p := primaryProvisioning(GatewayClientHost{MAC: "02:11:22:33:44:55", IP: "10.77.0.50", Name: "ps5"})
	wire, err := encodeGatewayProvisioning(&p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeGatewayProvisioning(wire)
	if err != nil || len(got.ClientHosts) != 1 || got.ClientHosts[0] != p.ClientHosts[0] {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	if clone := cloneGatewayProvisioning(got); &clone.ClientHosts[0] == &got.ClientHosts[0] {
		t.Fatal("clone shares the client host slice")
	}
}

func TestClientHostsRejectUnusableEntries(t *testing.T) {
	ok := GatewayClientHost{MAC: "02:11:22:33:44:55", IP: "10.77.0.50", Name: "ps5"}
	bad := map[string][]GatewayClientHost{
		"upper-case mac":  {{MAC: "02:11:22:33:44:AA", IP: "10.77.0.50"}},
		"multicast mac":   {{MAC: "01:11:22:33:44:55", IP: "10.77.0.50"}},
		"outside subnet":  {{MAC: "02:11:22:33:44:55", IP: "10.78.0.50"}},
		"exit address":    {{MAC: "02:11:22:33:44:55", IP: "10.77.0.1"}},
		"client address":  {{MAC: "02:11:22:33:44:55", IP: "10.77.0.2"}},
		"network address": {{MAC: "02:11:22:33:44:55", IP: "10.77.0.0"}},
		"broadcast":       {{MAC: "02:11:22:33:44:55", IP: "10.77.0.255"}},
		"ipv6":            {{MAC: "02:11:22:33:44:55", IP: "fd00::5"}},
		"duplicate mac":   {ok, {MAC: ok.MAC, IP: "10.77.0.51"}},
		"duplicate ip":    {ok, {MAC: "02:11:22:33:44:66", IP: ok.IP}},
		"name with space": {{MAC: ok.MAC, IP: ok.IP, Name: "my ps5"}},
	}
	for name, hosts := range bad {
		if err := primaryProvisioning(hosts...).Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := primaryProvisioning(ok).Validate(); err != nil {
		t.Fatalf("valid host rejected: %v", err)
	}
	many := make([]GatewayClientHost, MaxGatewayClientHosts+1)
	for i := range many {
		many[i] = GatewayClientHost{MAC: "02:11:22:33:44:" + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16]), IP: "10.77.0." + string(rune('0'+10+i))}
	}
	if err := primaryProvisioning(many...).Validate(); err == nil {
		t.Error("more than the maximum was accepted")
	}
}

func TestPassthroughCarriesTheSameClientHostsButDisabledDoesNot(t *testing.T) {
	p := primaryProvisioning(GatewayClientHost{MAC: "02:11:22:33:44:55", IP: "10.77.0.50"})
	p.Mode, p.DHCPAuthorityID = GatewayPassthrough, "other"
	if err := p.Validate(); err != nil {
		t.Fatalf("a passthrough exit must carry the delegation so the client serves it on any exit: %v", err)
	}
	p.Mode, p.DHCPAuthorityID = GatewayDisabled, ""
	if p.Validate() == nil {
		t.Fatal("a disabled gateway must not delegate DHCP hosts")
	}
}

func TestClientDNSValidation(t *testing.T) {
	p := primaryProvisioning(GatewayClientHost{MAC: "02:11:22:33:44:55", IP: "10.77.0.50"})
	p.ClientDNS = []string{"1.1.1.1", "9.9.9.9"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"::1"}, {"0.0.0.0"}, {"224.0.0.1"}, {"x"}, {"1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"}} {
		p.ClientDNS = bad
		if p.Validate() == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	p.ClientHosts, p.ClientDNS = nil, []string{"1.1.1.1"}
	if p.Validate() == nil {
		t.Error("DNS without hosts accepted")
	}
}
