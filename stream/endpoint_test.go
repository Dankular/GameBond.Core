package stream

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

// lossy wraps a PacketConn, dropping and delaying outbound datagrams.
type lossy struct {
	net.PacketConn
	loss  float64
	delay func() time.Duration
	rng   *rand.Rand
}

func (l *lossy) WriteTo(p []byte, a net.Addr) (int, error) {
	if l.rng.Float64() < l.loss {
		return len(p), nil
	}
	q := append([]byte(nil), p...)
	d := l.delay()
	time.AfterFunc(d, func() { l.PacketConn.WriteTo(q, a) })
	return len(p), nil
}

func gatewayPair(t *testing.T, loss float64) *Endpoint {
	sc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(c net.PacketConn, seed int64) PacketConn {
		r := rand.New(rand.NewSource(seed))
		return &lossy{c, loss, func() time.Duration {
			if r.Intn(2) == 0 {
				return 10 * time.Millisecond
			}
			return 25*time.Millisecond + time.Duration(r.Intn(5))*time.Millisecond
		}, r}
	}
	srv := NewEndpoint(mk(sc, 1), nil, Config{ReorderHint: func() time.Duration { return 20 * time.Millisecond }})
	go (&Gateway{Ep: srv}).Serve()
	cli := NewEndpoint(mk(cc, 2), sc.LocalAddr(), Config{ReorderHint: func() time.Duration { return 20 * time.Millisecond }})
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return cli
}

func tcpServer(t *testing.T, handle func(net.Conn)) string {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return l.Addr().String()
}

func runDownload(t *testing.T, loss float64, size int) time.Duration {
	data := make([]byte, size)
	rand.New(rand.NewSource(3)).Read(data)
	addr := tcpServer(t, func(c net.Conn) { c.Write(data); c.Close() })
	cli := gatewayPair(t, loss)
	start := time.Now()
	c, err := cli.Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v after %d bytes", err, len(got))
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatalf("mismatch: %d of %d", len(got), len(data))
	}
	return time.Since(start)
}

func TestEndpointDownload(t *testing.T) {
	t.Logf("clean 8MB in %v", runDownload(t, 0, 8<<20))
}

func TestEndpointDownloadLossy(t *testing.T) {
	t.Logf("2%% loss 4MB in %v", runDownload(t, 0.02, 4<<20))
}

func TestEndpointEchoAndRefuse(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) { io.Copy(c, c); c.Close() })
	cli := gatewayPair(t, 0)
	c, err := cli.Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("hello "), 5000)
	go func() { c.Write(msg); c.(*Stream).CloseWrite() }()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v %d", err, len(got))
	}
	if _, err := cli.Dial("127.0.0.1:1", 3*time.Second); err == nil {
		t.Fatal("expected refusal")
	}
}
