package bond

import (
	"encoding/binary"
	"math"
	"time"
)

type protection int

const (
	protectNone protection = iota
	protectParity
	protectDuplicate
)

// lossEstimate is the path's smoothed delivery loss, or 0 when it has not been
// measured within lossStale seconds.
func (s *Sender) lossEstimate(p *receivePath, ts float64) float64 {
	if !p.budget.lossSeen || ts-p.budget.lossAt > lossStale {
		return 0
	}
	return p.budget.lossEWMA
}

// protectionLevel decides how a packet is protected. With two or more ready paths every
// packet is duplicated on a second path from the first packet on, with no loss or delay
// condition to wait for: whichever copy arrives first wins. lossTiered (tests only) restores
// the older loss-driven parity/duplication tiers.
func (s *Sender) protectionLevel(paths []*receivePath, now time.Time) protection {
	if len(paths) < 2 {
		return protectNone
	}
	if !s.lossTiered {
		return protectDuplicate
	}
	ts := s.r.seconds(now)
	worst := 0.
	for _, p := range paths {
		worst = math.Max(worst, s.lossEstimate(p, ts))
		if s.hinted(p.local, now) || s.atRisk(p, now) {
			return protectDuplicate
		}
	}
	switch {
	case worst >= dupRatio:
		return protectDuplicate
	case worst >= fecRatio:
		return protectParity
	}
	return protectNone
}

// bulkProtect runs after a bulk packet was sent on used: it duplicates the packet
// on a second ready path or folds it into the flow's parity group.
func (s *Sender) bulkProtect(f *sendFlow, number uint64, payload []byte, used *receivePath, now time.Time, writer DatagramWriter) {
	paths := s.eligible(now, true)
	level := s.protectionLevel(paths, now)
	// A copy that cannot be placed falls back to a parity group, so the packet is still
	// recoverable from one loss.
	tcpMode := len(paths) > 1 && !s.lossTiered
	if level != protectParity && !(tcpMode && level == protectDuplicate) {
		f.fecMask = 0
	}
	switch level {
	case protectDuplicate:
		if !s.duplicate(f, number, payload, used, paths, now, writer) && tcpMode {
			s.accumulateParity(f, number, payload, used, paths, now, writer)
		}
	case protectParity:
		s.accumulateParity(f, number, payload, used, paths, now, writer)
	}
}

// other returns the ready path (other than used) with the shortest transit time.
// ungated skips the path's window and pacing gate: a redundancy copy must not have
// to win a place in line against the traffic it protects. The copy is still
// charged to the path's wire accounting by the caller.
func (s *Sender) other(used *receivePath, paths []*receivePath, size int, now time.Time, ungated bool) *receivePath {
	ts := s.r.seconds(now)
	var best *receivePath
	bestScore := math.Inf(1)
	for _, p := range s.fitPaths(paths, size) {
		if p == used || s.atRisk(p, now) {
			continue
		}
		if !ungated {
			ready, err := p.budget.ReadyAt(size, ts)
			if err != nil || math.Max(ready, p.pacer.ReadyAt(size+28, ts)) > ts+.000001 {
				continue
			}
		}
		probe := 0.
		if p.hasRTT {
			probe = p.rtt
		}
		if score := p.budget.TransitSeconds(size, probe); score < bestScore {
			best, bestScore = p, score
		}
	}
	return best
}

func (s *Sender) duplicate(f *sendFlow, number uint64, payload []byte, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) bool {
	size := len(payload) + Overhead + 24
	ungated := !s.lossTiered // a copy must not queue behind the traffic it protects
	target := s.other(used, paths, size, now, ungated)
	if target == nil {
		s.stats.BulkDupSkipped++
		return false
	}
	body := make([]byte, 24+len(payload))
	binary.BigEndian.PutUint64(body, f.id)
	binary.BigEndian.PutUint64(body[8:], number)
	binary.BigEndian.PutUint64(body[16:], target.txEpoch)
	copy(body[24:], payload)
	frame, err := s.r.codec.Encode(Striped, body)
	if err != nil {
		return false
	}
	if s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
		// Always tracked: the receiver acknowledges this frame's sequence, and an
		// untracked sequence makes that path's feedback get rejected (everything
		// then times out and the feedback-timeout ratio reads 100%).
		sequence := binary.BigEndian.Uint64(frame[37:])
		target.budget.SentCopy(sequence, len(frame), s.r.seconds(now))
		key := MissingPacket{f.id, number}
		target.budget.Tag(sequence, key)
		if cached := s.repairs[key]; cached != nil {
			cached.sent++
		}
		s.stats.Copies++
		s.stats.BulkDuplicates++
		return true
	}
	s.stats.BulkDupSkipped++
	return false
}

// parityFlushAfter is how long a partly filled parity group may wait for its next
// packet before its parity goes out anyway. It covers the tail of a burst, which
// would otherwise sit unprotected until the flow sent again.
const parityFlushAfter = 3 * time.Millisecond

// flushParity sends the parity of groups whose flow has gone quiet.
func (s *Sender) flushParity(now time.Time, writer DatagramWriter) {
	if len(s.parityOpen) == 0 {
		return
	}
	paths := s.eligible(now, true)
	for f := range s.parityOpen {
		if now.Sub(f.last) < parityFlushAfter {
			continue
		}
		if len(paths) == 0 || f.fecPath == nil {
			f.fecMask, f.fecXor = 0, f.fecXor[:0]
			delete(s.parityOpen, f)
			continue
		}
		s.emitParity(f, f.fecPath, paths, now, writer)
	}
}

// smallUDP is a UDP datagram small enough to be game or voice traffic: cheap to
// copy and the first to suffer when a link drops it.
func smallUDP(packet []byte) bool {
	p, err := ParseIPv4(packet)
	return err == nil && p.Protocol == 17 && !p.Fragmented && len(packet) <= 400
}

// accumulateParity folds the packet into the flow's current group and emits the
// parity frame when the group is complete or the flow moved to the next group.
func (s *Sender) accumulateParity(f *sendFlow, number uint64, payload []byte, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	base := number - number%fecK
	if f.fecMask != 0 && f.fecBase != base {
		s.emitParity(f, used, paths, now, writer)
	}
	if f.fecMask == 0 {
		f.fecBase, f.fecXor = base, f.fecXor[:0]
		f.rsReset()
	}
	if need := 2 + len(payload); need > len(f.fecXor) {
		f.fecXor = append(f.fecXor, make([]byte, need-len(f.fecXor))...)
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	f.fecXor[0] ^= l[0]
	f.fecXor[1] ^= l[1]
	for i, b := range payload {
		f.fecXor[2+i] ^= b
	}
	f.rsAccumulate(int(number-base), payload)
	f.fecMask |= 1 << (number - base)
	f.fecPath = used
	if s.parityOpen == nil {
		s.parityOpen = make(map[*sendFlow]struct{})
	}
	s.parityOpen[f] = struct{}{}
	if number%fecK == fecK-1 {
		s.emitParity(f, used, paths, now, writer)
	}
}

func (s *Sender) emitParity(f *sendFlow, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	if f.fecMask == 0 {
		return
	}
	if rows := s.parityRows(now); rows > 1 {
		s.emitParityRS(f, rows, used, paths, now, writer)
		f.fecMask, f.fecXor = 0, f.fecXor[:0]
		delete(s.parityOpen, f)
		return
	}
	body := make([]byte, parityHeader+len(f.fecXor))
	binary.BigEndian.PutUint64(body, f.id)
	binary.BigEndian.PutUint64(body[8:], f.fecBase)
	body[16] = f.fecMask
	copy(body[parityHeader:], f.fecXor)
	f.fecMask, f.fecXor = 0, f.fecXor[:0]
	delete(s.parityOpen, f)
	size := len(body) + Overhead
	// Parity travels on a different path than the data when one is ready, so a
	// single-path loss burst cannot take both.
	target := s.other(used, paths, size, now, !s.lossTiered)
	if target == nil {
		target = used
	}
	frame, err := s.r.codec.Encode(Parity, body)
	if err != nil {
		return
	}
	if s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
		s.stats.Copies++
		s.stats.ParitySent++
	}
}

// lossSteered applies the steering hysteresis to one path.
func (s *Sender) lossSteered(p *receivePath, ts float64) bool {
	est := s.lossEstimate(p, ts)
	if p.steerOn {
		if ts >= p.steerUntil && est < lossSteerExit {
			p.steerOn = false
		}
	} else if est >= lossSteerRatio {
		p.steerOn, p.steerUntil = true, ts+lossSteerHold
		s.stats.LossSteered++
	}
	return p.steerOn
}
