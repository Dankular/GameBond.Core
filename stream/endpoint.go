package stream

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// PacketConn is the datagram socket an Endpoint runs on (net.PacketConn
// satisfies it; so does gonet.UDPConn).
type PacketConn interface {
	ReadFrom(p []byte) (int, net.Addr, error)
	WriteTo(p []byte, a net.Addr) (int, error)
	Close() error
}

const (
	tick       = time.Millisecond
	recentTTL  = 30 * time.Second
	maxStreams = 192
)

// idleTimeout is how long a stream may receive nothing before it is reaped.
var idleTimeout = 2 * time.Minute

type key struct {
	id   uint32
	addr string
}

// Endpoint multiplexes many streams over one datagram socket. A client uses
// Dial; a server calls Accept.
type Endpoint struct {
	pc     PacketConn
	peer   net.Addr // fixed peer for a client; nil on a server
	cfg    Config
	mu     sync.Mutex
	conns  map[key]*Stream
	recent map[key]time.Time
	nextID uint32
	accept chan *Stream
	closed chan struct{}
	once   sync.Once
}

// NewEndpoint starts the read and timer loops. peer is non-nil for a client.
func NewEndpoint(pc PacketConn, peer net.Addr, cfg Config) *Endpoint {
	e := &Endpoint{pc: pc, peer: peer, cfg: cfg, conns: map[key]*Stream{}, recent: map[key]time.Time{}, closed: make(chan struct{})}
	if peer == nil {
		e.accept = make(chan *Stream, 64)
	}
	go e.readLoop()
	go e.timerLoop()
	return e
}

// Close stops the endpoint and resets every stream.
func (e *Endpoint) Close() error {
	e.once.Do(func() {
		close(e.closed)
		e.pc.Close()
		e.mu.Lock()
		for _, s := range e.conns {
			s.fail(ErrClosed)
		}
		e.mu.Unlock()
	})
	return nil
}

func (e *Endpoint) newStream(k key, addr net.Addr) *Stream {
	cfg := e.cfg
	s := &Stream{ep: e, k: k, addr: addr, notify: make(chan struct{}, 1), dead: make(chan struct{})}
	s.c = New(cfg)
	e.conns[k] = s
	return s
}

// Dial opens a stream to the gateway and asks it to connect to target
// ("host:port"). It returns once the gateway has connected.
func (e *Endpoint) Dial(target string, timeout time.Duration) (net.Conn, error) {
	if e.peer == nil {
		return nil, errors.New("stream: Dial on a server endpoint")
	}
	if len(target) == 0 || len(target) > 255 {
		return nil, errors.New("stream: bad target")
	}
	e.mu.Lock()
	select {
	case <-e.closed:
		e.mu.Unlock()
		return nil, ErrClosed
	default:
	}
	e.nextID++
	s := e.newStream(key{e.nextID, e.peer.String()}, e.peer)
	e.mu.Unlock()
	hdr := append([]byte{byte(len(target))}, target...)
	if _, err := s.Write(hdr); err != nil {
		s.Close()
		return nil, err
	}
	s.SetReadDeadline(time.Now().Add(timeout))
	var status [1]byte
	n, err := s.Read(status[:])
	s.SetReadDeadline(time.Time{})
	if err != nil || n != 1 || status[0] != 0 {
		s.abort()
		if err == nil {
			err = ErrRefused
		}
		return nil, err
	}
	return s, nil
}

// Accept returns the next stream a client opened (server side).
func (e *Endpoint) Accept() (*Stream, error) {
	select {
	case s := <-e.accept:
		return s, nil
	case <-e.closed:
		return nil, ErrClosed
	}
}

func (e *Endpoint) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := e.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-e.closed:
				return
			default:
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			e.Close()
			return
		}
		if n < 4+9 {
			continue
		}
		id := binary.BigEndian.Uint32(buf[:4])
		k := key{id, addr.String()}
		now := time.Now()
		e.mu.Lock()
		s := e.conns[k]
		if s == nil {
			if e.accept == nil || buf[4]&flagData == 0 || e.recent[k].After(now) {
				e.mu.Unlock()
				continue
			}
			if len(e.conns) >= maxStreams {
				e.mu.Unlock()
				continue
			}
			s = e.newStream(k, addr)
			select {
			case e.accept <- s:
			default:
				delete(e.conns, k)
				e.mu.Unlock()
				continue
			}
		}
		s.c.OnPacket(buf[4:n], now)
		s.afterEvent(now)
		e.mu.Unlock()
	}
}

func (e *Endpoint) timerLoop() {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-e.closed:
			return
		case now := <-t.C:
			e.mu.Lock()
			for k, s := range e.conns {
				s.afterEvent(now)
				if s.reapable(now) {
					s.fail(ErrClosed) // wake anything still blocked on a stream that is being forgotten
					delete(e.conns, k)
					e.recent[k] = now.Add(recentTTL)
				}
			}
			for k, until := range e.recent {
				if now.After(until) {
					delete(e.recent, k)
				}
			}
			e.mu.Unlock()
		}
	}
}

// Stream is one connection; it implements net.Conn.
type Stream struct {
	ep     *Endpoint
	k      key
	addr   net.Addr
	c      *Conn // guarded by ep.mu
	notify chan struct{}
	dead   chan struct{} // closed once the stream has failed or been reaped; wakes every waiter
	deadMu sync.Once
	rd, wd time.Time // guarded by ep.mu
	gone   time.Time
}

// Dead is closed when the stream has failed, been reset, or been reaped.
func (s *Stream) Dead() <-chan struct{} { return s.dead }

func (s *Stream) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// afterEvent polls the state machine, sends what it wants to send and wakes
// blocked callers. ep.mu is held.
func (s *Stream) afterEvent(now time.Time) {
	var out [][]byte
	s.c.Poll(now, &out)
	for _, p := range out {
		pkt := make([]byte, 4+len(p))
		binary.BigEndian.PutUint32(pkt, s.k.id)
		copy(pkt[4:], p)
		s.ep.pc.WriteTo(pkt, s.addr)
	}
	s.wake()
}

func (s *Stream) reapable(now time.Time) bool {
	if s.c.Done() && s.gone.IsZero() {
		s.gone = now.Add(2 * time.Second) // linger to re-acknowledge a retransmitted FIN
	}
	if !s.gone.IsZero() && now.After(s.gone) {
		return true
	}
	return now.Sub(s.c.lastRecv) > idleTimeout && !s.c.lastRecv.IsZero()
}

func (s *Stream) fail(err error) {
	if s.c.closedErr == nil {
		s.c.closedErr = err
	}
	s.deadMu.Do(func() { close(s.dead) })
	s.wake()
}

func (s *Stream) abort() {
	s.ep.mu.Lock()
	s.c.Reset()
	s.afterEvent(time.Now())
	s.ep.mu.Unlock()
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "stream: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (s *Stream) wait(deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-s.notify:
		case <-s.dead:
		}
		return nil
	}
	d := time.Until(deadline)
	if d <= 0 {
		return timeoutErr{}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.notify:
		return nil
	case <-s.dead:
		return nil
	case <-t.C:
		return timeoutErr{}
	}
}

// Read implements net.Conn.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.ep.mu.Lock()
		if n := s.c.Read(p); n > 0 {
			s.afterEvent(time.Now())
			s.ep.mu.Unlock()
			return n, nil
		}
		if s.c.Finished() {
			s.ep.mu.Unlock()
			return 0, errEOF
		}
		if err := s.c.Err(); err != nil {
			s.ep.mu.Unlock()
			return 0, err
		}
		dl := s.rd
		s.ep.mu.Unlock()
		if err := s.wait(dl); err != nil {
			return 0, err
		}
	}
}

// Write implements net.Conn; it blocks while the send buffer is full.
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		s.ep.mu.Lock()
		n, err := s.c.Write(p)
		if err != nil {
			s.ep.mu.Unlock()
			return total, err
		}
		if n > 0 {
			s.afterEvent(time.Now())
		}
		dl := s.wd
		s.ep.mu.Unlock()
		total += n
		p = p[n:]
		if len(p) > 0 {
			if err := s.wait(dl); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// CloseWrite sends FIN after buffered data.
func (s *Stream) CloseWrite() error {
	s.ep.mu.Lock()
	s.c.CloseWrite()
	s.afterEvent(time.Now())
	s.ep.mu.Unlock()
	return nil
}

// Close half-closes the write side; the stream is reaped once both FINs are
// acknowledged. A stream that was never read to EOF is reset.
func (s *Stream) Close() error {
	s.ep.mu.Lock()
	s.c.CloseWrite()
	if !s.c.Finished() && s.c.Readable() > 0 {
		s.c.Reset()
	}
	s.afterEvent(time.Now())
	s.ep.mu.Unlock()
	return nil
}

func (s *Stream) LocalAddr() net.Addr  { return s.addr }
func (s *Stream) RemoteAddr() net.Addr { return s.addr }
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.ep.mu.Lock()
	s.rd = t
	s.ep.mu.Unlock()
	s.wake()
	return nil
}
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.ep.mu.Lock()
	s.wd = t
	s.ep.mu.Unlock()
	s.wake()
	return nil
}

// Stats snapshots the connection counters and congestion window.
func (s *Stream) Stats() (Stats, int, time.Duration) {
	s.ep.mu.Lock()
	defer s.ep.mu.Unlock()
	st := s.c.Stats
	st.InFlight = s.c.InFlight()
	return st, s.c.Cwnd(), s.c.SRTT()
}

func (s *Stream) closedNow() bool {
	s.ep.mu.Lock()
	defer s.ep.mu.Unlock()
	return s.c.Done()
}
