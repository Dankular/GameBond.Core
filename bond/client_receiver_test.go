package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// clientServerPair wires a client Receiver (two uplinks) to a server Receiver
// through an in-memory network. Each client socket has its own source address,
// as two physical adapters would.
type clientServerPair struct {
	t      *testing.T
	client *Receiver
	server *Receiver
	now    time.Time
	srv    netip.AddrPort
	src    [2]netip.AddrPort
	drop   [2]bool // blackhole uplink i in both directions
	limit  [2]int  // when non-zero, uplink i silently drops frames larger than this
}

func newClientServerPair(t *testing.T) *clientServerPair {
	t.Helper()
	key, session := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16)
	cc, _ := NewCodec(key, session, "client")
	sc, _ := NewCodec(key, session, "server")
	cr, err := NewReceiver(cc, 1400)
	if err != nil {
		t.Fatal(err)
	}
	sr, _ := NewReceiver(sc, 1400)
	cr.probeInterval, sr.probeInterval = 250*time.Millisecond, 250*time.Millisecond
	p := &clientServerPair{t: t, client: cr, server: sr, now: time.Unix(5000, 0),
		srv: netip.MustParseAddrPort("203.0.113.1:4433"),
		src: [2]netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:5000"), netip.MustParseAddrPort("198.51.100.2:5000")}}
	for i := range p.src {
		if err := cr.AddClientPath(i, p.srv, p.now); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// deliver pushes datagrams to the opposite side until the exchange settles.
func (p *clientServerPair) deliver(fromClient bool, out ReceiveResult) {
	type item struct {
		fromClient bool
		d          Datagram
	}
	queue := make([]item, 0, len(out.Send))
	for _, d := range out.Send {
		queue = append(queue, item{fromClient, d})
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		var res ReceiveResult
		var err error
		if it.fromClient {
			if p.drop[it.d.Local] || (p.limit[it.d.Local] > 0 && len(it.d.Frame) > p.limit[it.d.Local]) {
				continue
			}
			res, err = p.server.ReceiveOn(0, it.d.Frame, p.src[it.d.Local], p.now)
			for _, r := range res.Send {
				queue = append(queue, item{false, r})
			}
		} else {
			local := -1
			for i, s := range p.src {
				if s == it.d.Endpoint {
					local = i
				}
			}
			if local < 0 || p.drop[local] || (p.limit[local] > 0 && len(it.d.Frame) > p.limit[local]) {
				continue
			}
			res, err = p.client.ReceiveOn(local, it.d.Frame, p.srv, p.now)
			for _, r := range res.Send {
				queue = append(queue, item{true, r})
			}
		}
		if err != nil {
			p.t.Fatal(err)
		}
	}
}

func (p *clientServerPair) step() {
	p.now = p.now.Add(250 * time.Millisecond)
	co, err := p.client.Tick(p.now)
	if err != nil {
		p.t.Fatal(err)
	}
	p.deliver(true, co)
	so, err := p.server.Tick(p.now)
	if err != nil {
		p.t.Fatal(err)
	}
	p.deliver(false, so)
}

func (p *clientServerPair) readyClientPaths() int {
	n := 0
	for _, path := range p.client.paths {
		if path.ready {
			n++
		}
	}
	return n
}

func TestClientReceiverHandshakesEveryUplinkAgainstServer(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	if p.readyClientPaths() != 2 {
		t.Fatalf("client paths ready = %d, want 2", p.readyClientPaths())
	}
	if !p.client.handshake.hasPeer || p.client.handshake.peer != p.server.codec.Prefix {
		t.Fatal("client did not adopt the server prefix")
	}
	if p.server.ReadyPaths(p.now) != 2 {
		t.Fatalf("server ready paths = %d, want 2 (one per client uplink)", p.server.ReadyPaths(p.now))
	}
	// Probes then flow both ways and produce an RTT sample per uplink.
	for i := 0; i < 6; i++ {
		p.step()
	}
	for key, path := range p.client.paths {
		if !path.hasRTT || path.probeAcked == 0 {
			t.Fatalf("uplink %d has no RTT sample (acked %d)", key.Local, path.probeAcked)
		}
	}
}

func TestClientReceiverRecoversAnUplinkAfterBlackhole(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	p.drop[1] = true
	for i := 0; i < 20; i++ { // silent for > 3 s: uplink 1 must drop out and re-handshake
		p.step()
	}
	if p.client.paths[PathKey{1, p.srv}].ready {
		t.Fatal("blackholed uplink still ready")
	}
	if !p.client.paths[PathKey{0, p.srv}].ready {
		t.Fatal("healthy uplink lost readiness")
	}
	p.drop[1] = false
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	if p.readyClientPaths() != 2 {
		t.Fatal("uplink did not recover after the blackhole ended")
	}
}

func TestClientReceiverIgnoresUnconfiguredSources(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 8 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	frame, _ := p.server.codec.Encode(Probe, probe(1))
	before := p.client.Stats().Malformed
	out, err := p.client.ReceiveOn(0, frame, netip.MustParseAddrPort("192.0.2.77:4433"), p.now)
	if err != nil || len(out.Send) != 0 || p.client.Stats().Malformed != before+1 {
		t.Fatalf("unconfigured source not dropped: %+v malformed %d err %v", out, p.client.Stats().Malformed, err)
	}
}

func TestServerReceiverStillRejectsAddClientPath(t *testing.T) {
	f := newReceiverFixture(t)
	if err := f.r.AddClientPath(0, f.endpoint, f.now); err == nil {
		t.Fatal("server receiver accepted a client path")
	}
}

func TestMTUDiscoveryFindsPerUplinkLimitAndSenderFitsPaths(t *testing.T) {
	p := newClientServerPair(t)
	p.limit[1] = 1250 // second uplink: largest ladder size that fits is 1232
	if err := p.client.SetPathMTUDiscovery(true); err == nil {
		t.Fatal("discovery must be configured before paths exist")
	}
	p = newClientServerPair(t)
	p.client.paths = map[PathKey]*receivePath{} // configure before paths, as production does
	p.client.SetPathMTUDiscovery(true)
	p.server.SetPathMTUDiscovery(true)
	p.limit[1] = 1250
	for i := range p.src {
		if err := p.client.AddClientPath(i, p.srv, p.now); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 120; i++ {
		p.step()
	}
	want := map[int]int{0: 1400, 1: 1232}
	for local, mtu := range want {
		path := p.client.paths[PathKey{local, p.srv}]
		if path == nil || path.mtu == nil {
			t.Fatalf("uplink %d has no prober", local)
		}
		if got := path.mtu.PathMTU(); got != mtu {
			t.Fatalf("uplink %d path MTU = %d, want %d (stats %+v)", local, got, mtu, path.mtu.Stats())
		}
		if path.mtuAcks == 0 {
			t.Fatalf("uplink %d never counted an MTU ack", local)
		}
	}
	sender, err := NewSender(p.client, 1, 100)
	_ = sender
	if err == nil {
		t.Fatal("sender must refuse a receiver that already has paths")
	}
	s := &Sender{r: p.client}
	all := s.eligible(p.now, true)
	if len(all) != 2 {
		t.Fatalf("eligible = %d", len(all))
	}
	if fit := s.fitPaths(all, 1300); len(fit) != 1 || fit[0].local != 0 {
		t.Fatalf("a 1300-byte datagram must use only the full-size uplink, got %d paths", len(fit))
	}
	if fit := s.fitPaths(all, 1200); len(fit) != 2 {
		t.Fatalf("a 1200-byte datagram fits both uplinks, got %d", len(fit))
	}
	p.client.paths[PathKey{0, p.srv}].mtu = &MTUProber{ceiling: 1000, strikes: map[int]int{}, outstanding: map[mtuProbeKey]float64{}}
	if fit := s.fitPaths(all, 1500); len(fit) != 2 || s.stats.MTUNoFit != 1 {
		t.Fatalf("when nothing fits every path must stay usable, got %d (no_fit=%d)", len(fit), s.stats.MTUNoFit)
	}
}

func TestClientLinkPolicyIsSentConfirmedAndGatesPayload(t *testing.T) {
	p := newClientServerPair(t)
	if err := p.client.SetClientLinkPolicies([]PathPolicy{{Role: Primary, UploadMbps: 50, DownloadMbps: 50}, {Role: Never}}, p.now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.SetClientLinkPolicies([]PathPolicy{{Role: Primary}}, p.now); err == nil {
		t.Fatal("policy list shorter than the uplink count accepted")
	}
	s := &Sender{r: p.client}
	for i := 0; i < 12; i++ {
		p.step()
	}
	c0, c1 := p.client.paths[PathKey{0, p.srv}], p.client.paths[PathKey{1, p.srv}]
	if !c0.policyConfirmed || !c1.policyConfirmed {
		t.Fatalf("policies not confirmed: %v %v", c0.policyConfirmed, c1.policyConfirmed)
	}
	if got := s.eligible(p.now, true); len(got) != 1 || got[0].local != 0 {
		t.Fatalf("only the primary uplink may carry payload, got %d paths", len(got))
	}
	var server1 *receivePath
	for _, sp := range p.server.paths {
		if sp.policy != nil && sp.policy.Role == Never {
			server1 = sp
		}
	}
	if server1 == nil {
		t.Fatal("server never learned the never-role policy")
	}
	// A new revision is unconfirmed until the server answers it, and the
	// unconfirmed path may not carry payload in the meantime.
	if err := p.client.SetClientLinkPolicies([]PathPolicy{{Role: Primary, UploadMbps: 50}, {Role: Secondary, UploadMbps: 50}}, p.now); err != nil {
		t.Fatal(err)
	}
	if got := s.eligible(p.now, true); len(got) != 0 {
		t.Fatalf("unconfirmed revision still eligible: %d", len(got))
	}
	for i := 0; i < 12; i++ {
		p.step()
	}
	if got := s.eligible(p.now, true); len(got) != 2 {
		t.Fatalf("after confirmation want primary+secondary, got %d", len(got))
	}
	// Policy frames are server-bound only.
	if _, err := NewReceiver(mustCodec(t, "server"), 1400); err != nil {
		t.Fatal(err)
	}
}

func mustCodec(t *testing.T, role string) *Codec {
	t.Helper()
	c, err := NewCodec(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16), role)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
