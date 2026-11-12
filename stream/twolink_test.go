package stream

import (
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// A model of the bonded wire: every datagram goes out on both links (full duplication),
// each link has a rate, a drop-tail buffer and jitter, so the slower link's queue builds
// and its delay shows up in the round trip. Used to study single-stream throughput.
type model struct {
	rate   float64       // bytes/second
	base   time.Duration // one-way propagation
	jitter time.Duration
	maxQ   time.Duration // buffer, as queueing delay
	loss   float64       // random loss
	spike  func(now time.Time) time.Duration // extra delay (Starlink handovers)
	mu     sync.Mutex
	free   time.Time
}

func (m *model) arrival(size int, now time.Time, r *rand.Rand) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.free.Before(now) {
		m.free = now
	}
	q := m.free.Sub(now)
	if q > m.maxQ || (m.loss > 0 && r.Float64() < m.loss) {
		return 0, false
	}
	m.free = m.free.Add(time.Duration(float64(size) / m.rate * float64(time.Second)))
	d := m.free.Sub(now) + m.base
	if m.spike != nil {
		d += m.spike(now)
	}
	if m.jitter > 0 {
		d += time.Duration(r.Int63n(int64(m.jitter)))
	}
	return d, true
}

type bonded struct {
	net.PacketConn
	links []*model
	r     *rand.Rand
	mu    sync.Mutex
	seen  map[string]struct{} // first-arrival: the second copy is dropped
}

func (b *bonded) WriteTo(p []byte, a net.Addr) (int, error) {
	now := time.Now()
	for _, l := range b.links {
		b.mu.Lock()
		d, ok := l.arrival(len(p)+28, now, b.r)
		b.mu.Unlock()
		if !ok {
			continue
		}
		q := append([]byte(nil), p...)
		time.AfterFunc(d, func() { b.deliver(q, a) })
	}
	return len(p), nil
}

// deliver writes the datagram to the peer once: a duplicate of one already delivered is dropped.
func (b *bonded) deliver(q []byte, a net.Addr) {
	key := string(q)
	b.mu.Lock()
	if _, dup := b.seen[key]; dup {
		b.mu.Unlock()
		return
	}
	if len(b.seen) > 20000 {
		b.seen = map[string]struct{}{}
	}
	b.seen[key] = struct{}{}
	b.mu.Unlock()
	b.PacketConn.WriteTo(q, a)
}

// twoLinkDownload runs a single stream download over two modelled links and returns Mbit/s.
func twoLinkDownload(t *testing.T, seconds int, a, b model, cfg Config) float64 {
	t.Helper()
	size := 400 << 20
	data := make([]byte, 1<<20)
	rand.New(rand.NewSource(3)).Read(data)
	addr := tcpServer(t, func(c net.Conn) {
		for sent := 0; sent < size; sent += len(data) {
			if _, err := c.Write(data); err != nil {
				break
			}
		}
		c.Close()
	})
	sc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	cc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	mk := func(c net.PacketConn, seed int64) PacketConn {
		la, lb := a, b
		return &bonded{PacketConn: c, links: []*model{&la, &lb}, r: rand.New(rand.NewSource(seed)), seen: map[string]struct{}{}}
	}
	hint := func() time.Duration { return 20 * time.Millisecond }
	scfg, ccfg := cfg, cfg
	scfg.ReorderHint, ccfg.ReorderHint = hint, hint
	srv := NewEndpoint(mk(sc, 1), nil, scfg)
	go (&Gateway{Ep: srv}).Serve()
	cli := NewEndpoint(mk(cc, 2), sc.LocalAddr(), ccfg)
	t.Cleanup(func() { cli.Close(); srv.Close() })
	c, err := cli.Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	buf := make([]byte, 64<<10)
	end := time.Now().Add(time.Duration(seconds) * time.Second)
	mid := time.Now().Add(2 * time.Second) // skip the ramp
	var midBytes int64
	for time.Now().Before(end) {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(buf)
		total += int64(n)
		if midBytes == 0 && time.Now().After(mid) {
			midBytes = total
		}
		if err != nil && err != io.EOF {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	span := time.Until(end)
	_ = span
	secs := float64(seconds) - 2
	return float64(total-midBytes) * 8 / secs / 1e6
}

func TestTwoLinkSingleStream(t *testing.T) {
	// Starlink-like: 30 Mbit/s, 20 ms one way, deep buffer. Hotspot-like: 25 Mbit/s, 27 ms, shallow buffer.
	starlink := model{rate: 30e6 / 8, base: 20 * time.Millisecond, jitter: 8 * time.Millisecond, maxQ: 250 * time.Millisecond}
	hotspot := model{rate: 25e6 / 8, base: 27 * time.Millisecond, jitter: 4 * time.Millisecond, maxQ: 60 * time.Millisecond}
	t.Logf("single stream, full duplication: %.1f Mbit/s (links 30 and 25)", twoLinkDownload(t, 12, starlink, hotspot, Config{}))
}

// Starlink-like conditions: a handover every ~15 s adds a delay burst, jitter is heavy, 1% loss.
func TestTwoLinkSingleStreamRough(t *testing.T) {
	t0 := time.Now()
	starlink := model{rate: 30e6 / 8, base: 20 * time.Millisecond, jitter: 30 * time.Millisecond, maxQ: 250 * time.Millisecond, loss: .01,
		spike: func(now time.Time) time.Duration {
			if ph := now.Sub(t0) % (5 * time.Second); ph < 300*time.Millisecond {
				return 80 * time.Millisecond
			}
			return 0
		}}
	hotspot := model{rate: 25e6 / 8, base: 27 * time.Millisecond, jitter: 8 * time.Millisecond, maxQ: 60 * time.Millisecond, loss: .005}
	t.Logf("rough: single stream, full duplication: %.1f Mbit/s", twoLinkDownload(t, 12, starlink, hotspot, Config{}))
}
