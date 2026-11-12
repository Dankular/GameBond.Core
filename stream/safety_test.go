package stream

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A data packet the receiver discards (outside its advertised window) must not
// be acknowledged: an ACK makes the sender forget the bytes and the stream
// stalls forever.
func TestDiscardedDataIsNotAcknowledged(t *testing.T) {
	a := New(Config{})
	b := New(Config{RecvWindow: 4000})
	if _, err := a.Write(make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	var out [][]byte
	for i := 0; i < 200 && len(out) < 16; i++ {
		a.Poll(now, &out)
		now = now.Add(time.Millisecond)
	}
	if len(out) < 8 {
		t.Fatalf("expected a burst of packets, got %d", len(out))
	}
	// Withhold the first packet so everything else is out of order.
	for _, p := range out[1:] {
		if err := b.OnPacket(p, now); err != nil {
			t.Fatal(err)
		}
	}
	if b.Stats.DroppedData == 0 {
		t.Fatal("test needs some packets to fall outside the window")
	}
	acked := uint64(0)
	for _, r := range b.rcvPNs {
		acked += r.hi - r.lo + 1
	}
	if want := uint64(len(out)-1) - b.Stats.DroppedData; acked != want {
		t.Fatalf("acknowledged %d packet numbers, but only %d were stored (%d dropped)", acked, want, b.Stats.DroppedData)
	}
}

func TestDuplicateAndLongerOutOfOrderCopies(t *testing.T) {
	b := New(Config{})
	now := time.Unix(1000, 0)
	if !b.onData(1000, make([]byte, 100), false, now) {
		t.Fatal("first copy rejected")
	}
	if !b.onData(1000, make([]byte, 100), false, now) {
		t.Fatal("duplicate must be acknowledged: the bytes are held")
	}
	if !b.onData(1000, make([]byte, 300), false, now) || b.oooBytes != 300 {
		t.Fatalf("longer copy of the same start must replace the shorter one (oooBytes=%d)", b.oooBytes)
	}
	if !b.onData(0, make([]byte, 1000), false, now) || b.rcvNxt != 1300 {
		t.Fatalf("gap fill should deliver through the held data, rcvNxt=%d", b.rcvNxt)
	}
}

// An idle stream that is reaped must release the upstream connection and its
// goroutines instead of blocking forever.
func TestIdleReapClosesUpstream(t *testing.T) {
	old := idleTimeout
	idleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })
	closed := make(chan struct{})
	addr := tcpServer(t, func(c net.Conn) {
		buf := make([]byte, 16)
		for {
			if _, err := c.Read(buf); err != nil {
				close(closed)
				return
			}
		}
	})
	cli := gatewayPair(t, 0)
	c, err := cli.Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not closed after the stream went idle")
	}
}

func TestReapedStreamWakesAllWaiters(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })
	addr := tcpServer(t, func(c net.Conn) { time.Sleep(10 * time.Second) })
	cli := gatewayPair(t, 0)
	c, err := cli.Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	go func() { _, err := c.Read(make([]byte, 1)); errs <- err }()
	go func() { // blocks once the send buffer is full
		buf := make([]byte, 1<<20)
		for {
			if _, err := c.Write(buf); err != nil {
				errs <- err
				return
			}
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err == nil {
				t.Fatal("expected an error")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a blocked reader or writer was never woken")
		}
	}
}

func TestAllowedDestination(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "195.154.119.136": true,
		"127.0.0.1": false, "10.77.0.1": false, "10.0.0.5": false, "172.17.0.1": false, "172.32.0.1": true,
		"192.168.1.1": false, "169.254.169.254": false, "100.64.1.1": false, "0.0.0.0": false,
		"224.0.0.1": false, "255.255.255.255": false, "::1": false, "2001:4860:4860::8888": false,
		"::ffff:127.0.0.1": false, "::ffff:8.8.8.8": true,
	} {
		if got := AllowedDestination(netip.MustParseAddr(ip)); got != want {
			t.Errorf("AllowedDestination(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestSafeDialRefusesLoopback(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) { c.Close() })
	t.Setenv("GAMEBOND_STREAM_ALLOW_PRIVATE", "")
	if _, err := SafeDial("tcp4", addr, time.Second); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("loopback dial: got %v, want ErrBlockedDestination", err)
	}
	t.Setenv("GAMEBOND_STREAM_ALLOW_PRIVATE", "1")
	c, err := SafeDial("tcp4", addr, time.Second)
	if err != nil {
		t.Fatalf("override should allow loopback: %v", err)
	}
	c.Close()
}
