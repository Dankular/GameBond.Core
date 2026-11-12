// Package stream is a reliable, ordered byte stream built for a bonded
// multi-path datagram transport. It is a pure state machine: callers feed it
// packets and a clock, and drain packets to send, so it can be simulated and
// tested without sockets or goroutines.
//
// Differences from TCP that matter here:
//   - Every packet has its own number, even a retransmission, so an ACK is never
//     ambiguous about which copy arrived.
//   - Loss is declared by a time threshold that is at least the transport's
//     reorder window (the gap between the slowest and fastest link), never by
//     a duplicate-ACK count, so packets that merely took the slower link are not
//     retransmitted and do not collapse a window.
//   - Congestion control is not here: the transport's per-link budgets pace
//     sends (Poll only emits what Allow permits), so the stream is one
//     connection over all links.
package stream

import (
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"time"
)

const (
	flagData = 1 << iota
	flagAck
	flagFin
	flagRst

	// HeaderOverhead is the most bytes a packet adds to its payload.
	HeaderOverhead = 1 + 8 + 8 + 2 + 23 + 4 + 8*maxAckRanges
	maxAckRanges   = 200
	dataAckRanges  = 16
	bareAckRanges  = 100
	maxOOOBytes    = 4 << 20
)

// Errors reported by Conn.
var (
	ErrClosed  = errors.New("stream: closed")
	ErrReset   = errors.New("stream: reset by peer")
	ErrFrame   = errors.New("stream: malformed packet")
	ErrRefused = errors.New("stream: gateway refused the destination")
)

// Config tunes a connection. Zero values take the defaults below.
type Config struct {
	MSS          int           // payload bytes per packet (default 1000)
	SendBuffer   int           // bytes Write may queue (default 4 MiB)
	RecvWindow   int           // bytes the peer may have unread or out of order (default 4 MiB)
	MinReorder   time.Duration // floor for the loss time threshold (default 5 ms)
	Allow        func(size int, now time.Time) bool
	ReorderHint  func() time.Duration // transport's slow-link minus fast-link delay plus jitter
	InitialRTT   time.Duration        // default 100 ms
	AckDelay     time.Duration        // max time to hold an ACK (default 2 ms)
	MaxRetxTries int                  // consecutive timeouts before reset (default 12)
}

func (c *Config) defaults() {
	if c.MSS == 0 {
		c.MSS = 1000
	}
	if c.SendBuffer == 0 {
		c.SendBuffer = 4 << 20
	}
	if c.RecvWindow == 0 {
		c.RecvWindow = 4 << 20
	}
	if c.MinReorder == 0 {
		c.MinReorder = 5 * time.Millisecond
	}
	if c.InitialRTT == 0 {
		c.InitialRTT = 100 * time.Millisecond
	}
	if c.AckDelay == 0 {
		c.AckDelay = 2 * time.Millisecond
	}
	if c.MaxRetxTries == 0 {
		c.MaxRetxTries = 12
	}
}

type sentPacket struct {
	pn       uint64
	off, end uint64 // stream range carried; off == end for a bare FIN
	fin      bool
	at       time.Time
	lost     bool
}

type chunk struct {
	off, end uint64
	fin      bool
}

type span struct{ lo, hi uint64 } // inclusive

// Conn is one stream. It is not safe for concurrent use; a mux serializes it.
type Conn struct {
	cfg Config

	// Send side. sndBuf holds stream bytes from sndBase (everything below is
	// acknowledged and gone).
	sndBuf         []byte
	sndBase        uint64
	sndNxt         uint64 // next never-sent offset
	finQueued      bool
	finSent        bool
	finAcked       bool
	finOff         uint64
	nextPN         uint64
	inflight       map[uint64]*sentPacket
	order          []uint64 // packet numbers in send order
	retx           []chunk
	acked          []span // acknowledged stream ranges above sndBase (sorted, disjoint)
	peerWindow     uint64
	largestAck     uint64
	hasAck         bool
	lastAckSent    time.Time
	timeouts       int
	cwnd, ssthresh int
	paceNext       time.Time
	recoveryPN     uint64

	// RTT
	srtt, rttvar, minRTT time.Duration
	minNext              time.Duration
	minAt                time.Time
	hasRTT               bool

	// Receive side.
	rcvNxt    uint64
	ooo       []span
	oooData   map[uint64][]byte
	oooBytes  int
	readBuf   []byte
	finRecv   bool
	finAt     uint64
	rcvPNs    []span // received packet number ranges, sorted
	ackDue    time.Time
	ackPend   int
	needAck   bool
	rstOut    bool
	rstIn     bool
	closedErr error
	lastRecv  time.Time

	Stats Stats
}

// Stats counts what the connection did.
type Stats struct {
	PacketsSent, PacketsRecv, Retransmits, SpuriousRetx uint64
	BytesAcked, BytesDelivered                          uint64
	Timeouts                                            uint64
	DropWindow, DropOOO                                 uint64
	DroppedData                                         uint64 // data packets discarded without being stored (not acknowledged)
}

// New returns a connection.
func New(cfg Config) *Conn {
	cfg.defaults()
	return &Conn{cwnd: 32 * cfg.MSS, ssthresh: 1 << 30, cfg: cfg, inflight: make(map[uint64]*sentPacket), oooData: make(map[uint64][]byte), peerWindow: uint64(cfg.RecvWindow), srtt: cfg.InitialRTT, rttvar: cfg.InitialRTT / 2}
}

// Write queues bytes and reports how many were accepted (the send buffer can
// be full). It never blocks.
func (c *Conn) Write(p []byte) (int, error) {
	if c.closedErr != nil {
		return 0, c.closedErr
	}
	if c.finQueued {
		return 0, ErrClosed
	}
	room := c.cfg.SendBuffer - len(c.sndBuf)
	if room <= 0 {
		return 0, nil
	}
	if len(p) > room {
		p = p[:room]
	}
	c.sndBuf = append(c.sndBuf, p...)
	return len(p), nil
}

// WriteSpace is how many more bytes Write would accept now.
func (c *Conn) WriteSpace() int { return c.cfg.SendBuffer - len(c.sndBuf) }

// CloseWrite queues a FIN after the buffered bytes.
func (c *Conn) CloseWrite() {
	if !c.finQueued {
		c.finQueued = true
		c.finOff = c.sndBase + uint64(len(c.sndBuf))
	}
}

// Reset aborts both directions.
func (c *Conn) Reset() {
	if c.closedErr == nil {
		c.closedErr = ErrClosed
	}
	c.rstOut, c.needAck = true, true
}

// Read copies delivered bytes. io.EOF-style end is reported by Finished.
func (c *Conn) Read(p []byte) int {
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if n > 0 && len(c.readBuf) == 0 {
		c.readBuf = nil
	}
	if n > 0 {
		c.needAck = true // the window opened
	}
	return n
}

// Readable is how many bytes Read can return now.
func (c *Conn) Readable() int { return len(c.readBuf) }

// Finished reports that the peer's FIN arrived and everything before it was read.
func (c *Conn) Finished() bool { return c.finRecv && c.rcvNxt == c.finAt && len(c.readBuf) == 0 }

// Err is the terminal error, if any.
func (c *Conn) Err() error {
	if c.rstIn {
		return ErrReset
	}
	return c.closedErr
}

// Done reports that nothing more will be sent or delivered: both FINs are
// acknowledged, or the connection was reset.
func (c *Conn) Done() bool {
	if c.rstIn || c.closedErr != nil {
		return true
	}
	return c.finQueued && c.finAcked && c.Finished()
}

func (c *Conn) recvWindow() uint64 {
	used := len(c.readBuf) + c.oooBytes
	if used >= c.cfg.RecvWindow {
		return 0
	}
	return uint64(c.cfg.RecvWindow - used)
}

func (c *Conn) reorderWindow() time.Duration {
	w := c.srtt/8 + 4*c.rttvar
	if c.cfg.ReorderHint != nil {
		if h := c.cfg.ReorderHint(); h > w {
			w = h
		}
	}
	if w < c.cfg.MinReorder {
		w = c.cfg.MinReorder
	}
	return w
}

// rto is the whole-flight timeout, after which unacknowledged data is resent
// regardless of acks.
func (c *Conn) rto() time.Duration {
	d := c.srtt + 4*c.rttvar + 2*c.reorderWindow()
	if d < 300*time.Millisecond {
		d = 300 * time.Millisecond
	}
	d <<= uint(min(c.timeouts, 6))
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

// SRTT is the smoothed round trip.
func (c *Conn) SRTT() time.Duration { return c.srtt }

// InFlight is the bytes sent and not yet acknowledged or declared lost.
func (c *Conn) InFlight() int {
	n := 0
	for _, p := range c.inflight {
		if !p.lost {
			n += int(p.end - p.off)
		}
	}
	return n
}

// ---------------------------------------------------------------- receive

// OnPacket processes one received packet.
func (c *Conn) OnPacket(b []byte, now time.Time) error {
	if len(b) < 9 {
		return ErrFrame
	}
	flags := b[0]
	pn := binary.BigEndian.Uint64(b[1:9])
	b = b[9:]
	c.lastRecv = now
	c.Stats.PacketsRecv++
	if flags&flagRst != 0 {
		c.rstIn = true
		return nil
	}
	if flags&flagAck != 0 {
		var err error
		if b, err = c.onAck(b, now); err != nil {
			return err
		}
	}
	dataPacket := false
	if flags&flagData != 0 {
		if len(b) < 10 {
			return ErrFrame
		}
		off := binary.BigEndian.Uint64(b)
		n := int(binary.BigEndian.Uint16(b[8:]))
		if len(b) < 10+n {
			return ErrFrame
		}
		dataPacket = c.onData(off, b[10:10+n], flags&flagFin != 0, now)
		if !dataPacket {
			c.Stats.DroppedData++
		}
	}
	if dataPacket {
		c.notePN(pn)
		c.ackPend++
		if c.ackDue.IsZero() {
			c.ackDue = now.Add(c.cfg.AckDelay)
		}
	}
	return nil
}

func (c *Conn) notePN(pn uint64) {
	i := sort.Search(len(c.rcvPNs), func(i int) bool { return c.rcvPNs[i].hi+1 >= pn })
	switch {
	case i < len(c.rcvPNs) && c.rcvPNs[i].lo <= pn && pn <= c.rcvPNs[i].hi:
		return
	case i < len(c.rcvPNs) && c.rcvPNs[i].hi+1 == pn:
		c.rcvPNs[i].hi = pn
		if i+1 < len(c.rcvPNs) && c.rcvPNs[i+1].lo == pn+1 {
			c.rcvPNs[i].hi = c.rcvPNs[i+1].hi
			c.rcvPNs = append(c.rcvPNs[:i+1], c.rcvPNs[i+2:]...)
		}
	case i < len(c.rcvPNs) && c.rcvPNs[i].lo == pn+1:
		c.rcvPNs[i].lo = pn
	default:
		c.rcvPNs = append(c.rcvPNs, span{})
		copy(c.rcvPNs[i+1:], c.rcvPNs[i:])
		c.rcvPNs[i] = span{pn, pn}
	}
	if len(c.rcvPNs) > 400 { // forget the oldest ranges; the peer has long since moved on
		c.rcvPNs = c.rcvPNs[len(c.rcvPNs)-400:]
	}
}

// onData stores one data packet. It reports whether the bytes are now held (or
// were already held): only then may the packet number be acknowledged, because
// an ACK for data that was discarded makes the sender drop it from its
// retransmission state and the stream stalls.
func (c *Conn) onData(off uint64, p []byte, fin bool, now time.Time) bool {
	end := off + uint64(len(p))
	if len(p) > 0 && end > c.rcvNxt && off > c.rcvNxt && end > c.rcvNxt+c.recvWindow()+uint64(len(c.readBuf)) {
		c.Stats.DropWindow++
		return false // outside the window we advertised
	}
	if fin {
		c.finRecv, c.finAt = true, end
	}
	if len(p) == 0 || end <= c.rcvNxt {
		return true // a bare FIN, or a retransmission of data we already have
	}
	if off < c.rcvNxt {
		p = p[c.rcvNxt-off:]
		off = c.rcvNxt
	}
	if off == c.rcvNxt {
		c.readBuf = append(c.readBuf, p...)
		c.Stats.BytesDelivered += uint64(len(p))
		c.rcvNxt = end
		c.drainOOO()
		return true
	}
	if old, ok := c.oooData[off]; ok {
		if len(old) >= len(p) {
			return true // already held
		}
		if c.oooBytes+len(p)-len(old) > maxOOOBytes {
			c.Stats.DropOOO++
			return false
		}
		c.oooBytes += len(p) - len(old) // a longer copy of the same start replaces the shorter one
		c.oooData[off] = append([]byte(nil), p...)
		return true
	}
	if c.oooBytes+len(p) > maxOOOBytes {
		c.Stats.DropOOO++
		return false
	}
	c.oooData[off] = append([]byte(nil), p...)
	c.oooBytes += len(p)
	i := sort.Search(len(c.ooo), func(i int) bool { return c.ooo[i].lo >= off })
	c.ooo = append(c.ooo, span{})
	copy(c.ooo[i+1:], c.ooo[i:])
	c.ooo[i] = span{off, off} // lo is the key into oooData; hi is unused
	return true
}

func (c *Conn) drainOOO() {
	for len(c.ooo) > 0 {
		key := c.ooo[0].lo
		p := c.oooData[key]
		end := key + uint64(len(p))
		if key > c.rcvNxt {
			return
		}
		delete(c.oooData, key)
		c.oooBytes -= len(p)
		c.ooo = c.ooo[1:]
		if end <= c.rcvNxt {
			continue
		}
		p = p[c.rcvNxt-key:]
		c.readBuf = append(c.readBuf, p...)
		c.Stats.BytesDelivered += uint64(len(p))
		c.rcvNxt = end
	}
}

// ---------------------------------------------------------------- ack in

func (c *Conn) onAck(b []byte, now time.Time) ([]byte, error) {
	if len(b) < 8+4+2+8+1+4 {
		return nil, ErrFrame
	}
	rcvNxt := binary.BigEndian.Uint64(b)
	window := binary.BigEndian.Uint32(b[8:])
	delay := time.Duration(binary.BigEndian.Uint16(b[12:])) * 100 * time.Microsecond
	largest := binary.BigEndian.Uint64(b[14:])
	n := int(b[22])
	b = b[23:]
	if n > maxAckRanges || len(b) < 8*n+4 {
		return nil, ErrFrame
	}
	var ranges []span
	hi := largest
	first := uint64(binary.BigEndian.Uint32(b))
	if first > hi {
		return nil, ErrFrame
	}
	ranges = append(ranges, span{hi - first, hi})
	b = b[4:]
	lo := hi - first
	for i := 0; i < n; i++ {
		gap := uint64(binary.BigEndian.Uint32(b))
		ln := uint64(binary.BigEndian.Uint32(b[4:]))
		b = b[8:]
		if lo < gap+2 || lo-gap-2 < ln {
			return nil, ErrFrame
		}
		hi = lo - gap - 2
		lo = hi - ln
		ranges = append(ranges, span{lo, hi})
	}
	c.peerWindow = uint64(window)
	newly := false
	var sample time.Duration
	var got []*sentPacket
	for _, r := range ranges {
		for pn := r.lo; pn <= r.hi; pn++ {
			p := c.inflight[pn]
			if p == nil {
				if pn == r.lo && r.hi-r.lo > 1<<16 {
					break
				}
				continue
			}
			delete(c.inflight, pn)
			got = append(got, p)
			newly = true
			if pn == largest || !c.hasAck || pn > c.largestAck {
				if s := now.Sub(p.at) - delay; s > 0 {
					sample = s
				}
			}
		}
	}
	if sample > 0 {
		c.rttSample(sample)
	}
	// Account for the acknowledged packets before the cumulative ack drops them.
	for _, p := range got {
		if p.lost {
			c.Stats.SpuriousRetx++
		}
		c.grow(int(p.end - p.off))
		c.markAcked(p.off, p.end)
		if p.fin {
			c.finAcked = true
		}
	}
	if rcvNxt > c.sndBase {
		c.advanceBase(rcvNxt)
	}
	if !c.hasAck || largest > c.largestAck {
		c.largestAck, c.hasAck = largest, true
	}
	if newly {
		c.timeouts = 0
	}
	c.detectLoss(now)
	return b, nil
}

func (c *Conn) grow(acked int) {
	// A standing queue in the transport (RTT well above the floor, beyond what
	// the slower link explains) means the window is past the path's capacity:
	// shrink it gently rather than wait for the queue to overflow into loss.
	// Only a sustained, large inflation counts (twice the recent floor): a fast
	// link's jitter and the other path's ordinary delay must not pin the window.
	if c.hasRTT && c.srtt > 2*c.minRTT+c.reorderWindow()+30*time.Millisecond {
		c.cwnd = max(c.cwnd-acked/16, 32*c.cfg.MSS)
		c.ssthresh = min(c.ssthresh, c.cwnd)
		return
	}
	if c.cwnd < c.ssthresh {
		c.cwnd += acked
		return
	}
	c.cwnd += acked / 4 // probe 25% per round trip
}

// Cwnd is the congestion window in bytes.
func (c *Conn) Cwnd() int { return c.cwnd }

func (c *Conn) rttSample(s time.Duration) {
	if !c.hasRTT {
		c.srtt, c.rttvar, c.minRTT, c.hasRTT = s, s/2, s, true
		return
	}
	// minRTT is the floor over roughly the last 10-20 s, so a route change that
	// raises the base delay is not mistaken for a standing queue forever.
	if s < c.minRTT {
		c.minRTT = s
	}
	if c.minAt.IsZero() {
		c.minAt = time.Now()
	} else if time.Since(c.minAt) > 10*time.Second {
		c.minRTT, c.minAt = max(c.minNext, s), time.Now()
		c.minNext = s
	} else if c.minNext == 0 || s < c.minNext {
		c.minNext = s
	}
	d := c.srtt - s
	if d < 0 {
		d = -d
	}
	c.rttvar = (3*c.rttvar + d) / 4
	c.srtt = (7*c.srtt + s) / 8
}

func (c *Conn) advanceBase(to uint64) {
	if to > c.sndBase+uint64(len(c.sndBuf)) {
		to = c.sndBase + uint64(len(c.sndBuf))
	}
	n := to - c.sndBase
	c.Stats.BytesAcked += n
	c.sndBuf = c.sndBuf[n:]
	if len(c.sndBuf) == 0 {
		c.sndBuf = nil
	}
	c.sndBase = to
	if c.sndNxt < to {
		c.sndNxt = to
	}
	// Drop retransmission work and acked spans that are now below the base.
	kept := c.retx[:0]
	for _, ch := range c.retx {
		if ch.end > to || ch.fin {
			if ch.off < to {
				ch.off = to
			}
			kept = append(kept, ch)
		}
	}
	c.retx = kept
	j := 0
	for _, s := range c.acked {
		if s.hi+1 > to {
			if s.lo < to {
				s.lo = to
			}
			c.acked[j] = s
			j++
		}
	}
	c.acked = c.acked[:j]
	for pn, p := range c.inflight {
		if p.end <= to && !p.fin {
			delete(c.inflight, pn)
		}
	}
}

// markAcked records that stream range [off,end) reached the peer. Spans use
// [lo,hi) semantics internally via hi = end-1... kept as half-open here.
func (c *Conn) markAcked(off, end uint64) {
	if end <= off || end <= c.sndBase {
		return
	}
	if off < c.sndBase {
		off = c.sndBase
	}
	s := span{off, end}
	c.acked = append(c.acked, s)
	sort.Slice(c.acked, func(i, j int) bool { return c.acked[i].lo < c.acked[j].lo })
	merged := c.acked[:1]
	for _, x := range c.acked[1:] {
		last := &merged[len(merged)-1]
		if x.lo <= last.hi {
			if x.hi > last.hi {
				last.hi = x.hi
			}
		} else {
			merged = append(merged, x)
		}
	}
	c.acked = merged
	if c.acked[0].lo == c.sndBase {
		c.advanceBase(c.acked[0].hi)
	}
	// Anything queued for retransmission that is now covered is dropped in Poll.
}

func (c *Conn) isAcked(off, end uint64) bool {
	if end <= c.sndBase {
		return true
	}
	for _, s := range c.acked {
		if s.lo <= off && end <= s.hi {
			return true
		}
	}
	return false
}

// detectLoss declares in-flight packets lost when a later packet was acked
// and enough time has passed that a slow link could not explain it.
func (c *Conn) detectLoss(now time.Time) {
	if !c.hasAck {
		return
	}
	window := c.reorderWindow()
	for _, pn := range c.order {
		p := c.inflight[pn]
		if p == nil || p.lost {
			continue
		}
		if pn < c.largestAck && now.Sub(p.at) > c.srtt+window {
			c.markLost(p)
		}
	}
	c.gcOrder()
}

func (c *Conn) markLost(p *sentPacket) {
	p.lost = true
	if p.pn >= c.recoveryPN { // one reduction per round trip of losses
		c.cwnd = max(c.cwnd*85/100, 4*c.cfg.MSS)
		c.ssthresh = c.cwnd
		c.recoveryPN = c.nextPN
	}
	if !c.isAcked(p.off, p.end) || p.fin && !c.finAcked {
		c.retx = append(c.retx, chunk{p.off, p.end, p.fin})
	}
}

func (c *Conn) gcOrder() {
	i := 0
	for i < len(c.order) && c.inflight[c.order[i]] == nil {
		i++
	}
	c.order = c.order[i:]
}

// ---------------------------------------------------------------- send

// Poll appends the packets to send now and returns when it next needs to run.
// allow gates each packet on the transport's pacing; a refused packet stays
// queued and Poll returns a short wake-up.
func (c *Conn) Poll(now time.Time, out *[][]byte) time.Time {
	var wake time.Time
	soon := func(t time.Time) {
		if wake.IsZero() || t.Before(wake) {
			wake = t
		}
	}
	if c.rstOut {
		*out = append(*out, c.encode(flagRst, 0, 0, nil, false, now))
		c.rstOut, c.closedErr = false, ErrClosed
		return wake
	}
	// Whole-flight timeout.
	if len(c.inflight) > 0 {
		var oldest time.Time
		for _, pn := range c.order {
			if p := c.inflight[pn]; p != nil && !p.lost {
				oldest = p.at
				break
			}
		}
		if !oldest.IsZero() {
			if now.Sub(oldest) >= c.rto() {
				c.timeouts++
				if c.nextPN > c.recoveryPN { // one reduction per window, not one per timeout
					c.ssthresh = max(c.cwnd*7/10, 8*c.cfg.MSS)
					c.cwnd, c.recoveryPN = c.ssthresh, c.nextPN
				}
				c.Stats.Timeouts++
				marked := 0
				for _, pn := range c.order { // probe with the oldest few, not the whole flight
					if p := c.inflight[pn]; p != nil && !p.lost {
						c.markLost(p)
						if marked++; marked >= 4 {
							break
						}
					}
				}
				if c.timeouts > c.cfg.MaxRetxTries {
					c.closedErr = errors.New("stream: peer unreachable")
					return wake
				}
			} else {
				soon(oldest.Add(c.rto()))
			}
		}
	}
	allow := c.cfg.Allow
	flight := c.InFlight()
	// Pace at 1.25 x cwnd per smoothed RTT so a window is never dumped into the
	// transport as one burst (which overflows its queues and looks like loss).
	base := c.srtt
	if c.hasRTT && base > 2*c.minRTT {
		base = 2 * c.minRTT
	}
	rate := 1.25 * float64(c.cwnd) / math.Max(base.Seconds(), 0.005) // bytes/s
	if c.paceNext.Before(now.Add(-4 * time.Millisecond)) {
		c.paceNext = now.Add(-4 * time.Millisecond)
	}
	paced := func(size int) bool {
		if c.paceNext.After(now) {
			soon(c.paceNext)
			return false
		}
		c.paceNext = c.paceNext.Add(time.Duration(float64(size) / rate * float64(time.Second)))
		return true
	}
	emit := func(pkt []byte) bool {
		if !paced(len(pkt)) {
			return false
		}
		if allow != nil && !allow(len(pkt), now) {
			soon(now.Add(time.Millisecond))
			return false
		}
		*out = append(*out, pkt)
		c.Stats.PacketsSent++
		return true
	}
	// Retransmissions first.
	for len(c.retx) > 0 {
		ch := c.retx[0]
		if ch.fin || ch.end > ch.off {
			if ch.end > ch.off && c.isAcked(ch.off, ch.end) {
				c.retx = c.retx[1:]
				continue
			}
		}
		if ch.off < c.sndBase {
			ch.off = c.sndBase
		}
		take := ch
		if int(take.end-take.off) > c.cfg.MSS {
			take.end = take.off + uint64(c.cfg.MSS)
			take.fin = false
		}
		if flight >= c.cwnd {
			soon(now.Add(time.Millisecond))
			break
		}
		pkt, p := c.dataPacket(take, now)
		if !emit(pkt) {
			c.unsend(p)
			break
		}
		flight += int(take.end - take.off)
		c.Stats.Retransmits++
		if take.end == ch.end {
			c.retx = c.retx[1:]
		} else {
			c.retx[0].off = take.end
		}
	}
	// New data, bounded by the peer's window.
	for {
		avail := c.sndBase + uint64(len(c.sndBuf)) - c.sndNxt
		limit := c.sndBase + c.peerWindow
		if c.sndNxt >= limit {
			avail = 0
		} else if avail > limit-c.sndNxt {
			avail = limit - c.sndNxt
		}
		fin := c.finQueued && !c.finSent && c.sndNxt+avail == c.finOff
		if avail == 0 && !fin {
			break
		}
		n := avail
		if n > uint64(c.cfg.MSS) {
			n = uint64(c.cfg.MSS)
			fin = false
		}
		if flight >= c.cwnd {
			soon(now.Add(time.Millisecond))
			break
		}
		ch := chunk{c.sndNxt, c.sndNxt + n, fin}
		pkt, p := c.dataPacket(ch, now)
		if !emit(pkt) {
			c.unsend(p)
			break
		}
		c.sndNxt = ch.end
		flight += int(n)
		if fin {
			c.finSent = true
		}
	}
	// A bare ACK when one is due and nothing carried it.
	if c.needAck || (c.ackPend > 0 && (c.ackPend >= 2 || !now.Before(c.ackDue))) {
		pkt := c.encode(0, 0, 0, nil, false, now)
		if allow == nil || allow(len(pkt), now) {
			*out = append(*out, pkt)
			c.Stats.PacketsSent++
		} else {
			soon(now.Add(time.Millisecond))
		}
		c.ackPend, c.needAck, c.ackDue = 0, false, time.Time{}
	} else if c.ackPend > 0 {
		soon(c.ackDue)
	}
	return wake
}

func (c *Conn) unsend(p *sentPacket) {
	delete(c.inflight, p.pn)
	c.order = c.order[:len(c.order)-1]
	c.nextPN--
}

func (c *Conn) dataPacket(ch chunk, now time.Time) ([]byte, *sentPacket) {
	var payload []byte
	if ch.end > ch.off {
		payload = c.sndBuf[ch.off-c.sndBase : ch.end-c.sndBase]
	}
	pn := c.nextPN
	c.nextPN++
	p := &sentPacket{pn: pn, off: ch.off, end: ch.end, fin: ch.fin, at: now}
	c.inflight[pn] = p
	c.order = append(c.order, pn)
	flags := byte(flagData)
	if ch.fin {
		flags |= flagFin
	}
	pkt := c.encode(flags, pn, ch.off, payload, true, now)
	return pkt, p
}

// encode builds a packet. Every packet carries an ACK when we have anything
// to acknowledge, so ACKs ride data in both directions.
func (c *Conn) encode(flags byte, pn, off uint64, payload []byte, hasPN bool, now time.Time) []byte {
	if !hasPN {
		pn = c.nextPN
		c.nextPN++
	}
	withAck := len(c.rcvPNs) > 0 || c.rcvNxt > 0 || c.recvWindow() != uint64(c.cfg.RecvWindow)
	if flags&flagRst != 0 {
		withAck = false
	}
	if withAck {
		flags |= flagAck
	}
	b := make([]byte, 0, 64+len(payload))
	b = append(b, flags)
	b = binary.BigEndian.AppendUint64(b, pn)
	if withAck {
		rng := dataAckRanges
		if flags&flagData == 0 {
			rng = bareAckRanges
		}
		b = c.appendAck(b, now, rng)
		c.ackPend, c.needAck, c.ackDue = 0, false, time.Time{}
	}
	if flags&flagData != 0 {
		b = binary.BigEndian.AppendUint64(b, off)
		b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
		b = append(b, payload...)
	}
	return b
}

// appendAck writes [rcvNxt u64][window u32][delay u16][largest u64][n u8]
// [firstLen u32] then n x [gap u32][len u32], newest range first.
func (c *Conn) appendAck(b []byte, now time.Time, maxRanges int) []byte {
	b = binary.BigEndian.AppendUint64(b, c.rcvNxt)
	w := c.recvWindow()
	if w > math.MaxUint32 {
		w = math.MaxUint32
	}
	b = binary.BigEndian.AppendUint32(b, uint32(w))
	delay := now.Sub(c.lastRecv) / (100 * time.Microsecond)
	if c.lastRecv.IsZero() || delay < 0 {
		delay = 0
	}
	if delay > math.MaxUint16 {
		delay = math.MaxUint16
	}
	b = binary.BigEndian.AppendUint16(b, uint16(delay))
	if len(c.rcvPNs) == 0 {
		b = binary.BigEndian.AppendUint64(b, 0)
		b = append(b, 0)
		return binary.BigEndian.AppendUint32(b, 0)
	}
	top := c.rcvPNs[len(c.rcvPNs)-1]
	b = binary.BigEndian.AppendUint64(b, top.hi)
	n := len(c.rcvPNs) - 1
	if n > maxRanges {
		n = maxRanges
	}
	b = append(b, byte(n))
	b = binary.BigEndian.AppendUint32(b, uint32(top.hi-top.lo))
	prevLo := top.lo
	for i := 0; i < n; i++ {
		r := c.rcvPNs[len(c.rcvPNs)-2-i]
		b = binary.BigEndian.AppendUint32(b, uint32(prevLo-r.hi-2))
		b = binary.BigEndian.AppendUint32(b, uint32(r.hi-r.lo))
		prevLo = r.lo
	}
	return b
}
