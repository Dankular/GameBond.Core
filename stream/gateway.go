package stream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

var errEOF = io.EOF

// Gateway accepts streams from an Endpoint, dials the requested TCP target
// and relays bytes both ways.
type Gateway struct {
	Ep      *Endpoint
	Dial    func(network, address string, timeout time.Duration) (net.Conn, error)
	Allowed func(address string) bool // nil allows everything
}

// Serve runs until the endpoint closes.
func (g *Gateway) Serve() error {
	dial := g.Dial
	if dial == nil {
		dial = func(n, a string, d time.Duration) (net.Conn, error) { return net.DialTimeout(n, a, d) }
	}
	for {
		s, err := g.Ep.Accept()
		if err != nil {
			return err
		}
		go g.handle(s, dial)
	}
}

func (g *Gateway) handle(s *Stream, dial func(string, string, time.Duration) (net.Conn, error)) {
	defer s.Close()
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	var l [1]byte
	if _, err := io.ReadFull(s, l[:]); err != nil || l[0] == 0 {
		s.abort()
		return
	}
	target := make([]byte, l[0])
	if _, err := io.ReadFull(s, target); err != nil {
		s.abort()
		return
	}
	s.SetReadDeadline(time.Time{})
	addr := string(target)
	if g.Allowed != nil && !g.Allowed(addr) {
		s.Write([]byte{1})
		return
	}
	up, err := dial("tcp4", addr, 8*time.Second)
	if err != nil {
		s.Write([]byte{1})
		return
	}
	defer up.Close()
	if _, err := s.Write([]byte{0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	finished := make(chan struct{})
	defer close(finished)
	go func() { // a failed or reaped stream must not leave the upstream socket blocked
		select {
		case <-s.Dead():
			up.Close()
		case <-finished:
		}
	}()
	go func() {
		t := time.NewTicker(logInterval())
		defer t.Stop()
		for {
			select {
			case <-t.C:
			case <-s.Dead():
				return
			case <-finished:
				return
			}
			st, cwnd, rtt := s.Stats()
			if st.PacketsSent == 0 && st.BytesAcked == 0 {
				continue
			}
			fmt.Printf("{\"status\":\"stream\",\"cwnd\":%d,\"srtt_ms\":%d,\"retx\":%d,\"spurious\":%d,\"acked\":%d}\n", cwnd, rtt.Milliseconds(), st.Retransmits, st.SpuriousRetx, st.BytesAcked)
			if s.closedNow() {
				return
			}
		}
	}()
	go func() { // stream -> upstream
		io.Copy(up, s)
		if tc, ok := up.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() { // upstream -> stream
		io.Copy(s, up)
		s.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
	if st, cwnd, rtt := s.Stats(); st.BytesAcked > 1<<20 {
		fmt.Printf("{\"status\":\"stream_done\",\"cwnd\":%d,\"srtt_ms\":%d,\"sent\":%d,\"retx\":%d,\"spurious\":%d,\"timeouts\":%d,\"acked\":%d}\n", cwnd, rtt.Milliseconds(), st.PacketsSent, st.Retransmits, st.SpuriousRetx, st.Timeouts, st.BytesAcked)
	}
}

// logInterval is how often an active stream reports its counters. It defaults to 10 s, because
// every active stream writes a line and the container's log rotation is small;
// GAMEBOND_STREAM_LOG_INTERVAL (a Go duration such as 2s or 1m) overrides it.
func logInterval() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("GAMEBOND_STREAM_LOG_INTERVAL")); err == nil && d >= time.Second {
		return d
	}
	return 10 * time.Second
}

// ErrBlockedDestination is returned by SafeDial for an address a tunnel client
// may not reach.
var ErrBlockedDestination = errors.New("stream: destination not allowed")

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// AllowedDestination reports whether a tunnel client may connect to ip: only
// globally routable unicast IPv4. Loopback, private, link-local, CGNAT, multicast
// and reserved ranges are refused, so a client cannot reach the admin portal, the
// container bridge, the host or the tunnel network through the gateway.
func AllowedDestination(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// SafeDial dials like net.DialTimeout but checks the address actually being
// connected to, after name resolution, so a hostname that resolves to a blocked
// address is refused as well. Set GAMEBOND_STREAM_ALLOW_PRIVATE=1 to disable.
func SafeDial(network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if os.Getenv("GAMEBOND_STREAM_ALLOW_PRIVATE") != "1" {
		d.Control = func(_, addr string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil || !AllowedDestination(ap.Addr()) {
				return ErrBlockedDestination
			}
			return nil
		}
	}
	return d.Dial(network, address)
}
