package bond

import (
	"encoding/binary"
	"math"
	"math/bits"
	"time"
)

// Reed-Solomon parity. A group of fecK consecutive packets of a bulk flow can carry up
// to fecMaxRows parity rows, each row a different linear combination over GF(256) of
// the members (a Cauchy matrix, so any n rows recover any n missing members). One row
// is the cheap 12.5% protection the XOR PARITY frame already gave; more rows are added
// while loss is being seen, so a burst that takes two or three packets of a group is
// repaired without a round trip. Rows after the first are sent a few milliseconds
// later (time diversity): one fade that swallows a whole instant does not take every
// row with it.

const (
	fecMaxRows    = 3
	rsHeader      = 18 // flow(8) base(8) mask(1) row(1)
	parityStagger = 6 * time.Millisecond
	deferredMax   = 256
)

var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) byte { return gfExp[255-int(gfLog[a])] }

// rsCoeff is the weight of group member i in parity row r. The members are the points
// 0..fecK-1 and the rows the points 16.., so x+y is never zero and the matrix is Cauchy.
func rsCoeff(row, member int) byte { return gfInv(byte(16+row) ^ byte(member)) }

// gfAddScaled sets dst ^= c*src.
func gfAddScaled(dst, src []byte, c byte) {
	if c == 0 {
		return
	}
	if c == 1 {
		for i, b := range src {
			dst[i] ^= b
		}
		return
	}
	lc := int(gfLog[c])
	for i, b := range src {
		if b != 0 {
			dst[i] ^= gfExp[int(gfLog[b])+lc]
		}
	}
}

// rsAccumulate folds member idx (length prefix plus payload) into every parity row.
func (f *sendFlow) rsAccumulate(idx int, payload []byte) {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	need := 2 + len(payload)
	for r := 0; r < fecMaxRows; r++ {
		if need > len(f.fecRS[r]) {
			f.fecRS[r] = append(f.fecRS[r], make([]byte, need-len(f.fecRS[r]))...)
		}
		c := rsCoeff(r, idx)
		gfAddScaled(f.fecRS[r][:2], l[:], c)
		gfAddScaled(f.fecRS[r][2:], payload, c)
	}
}

func (f *sendFlow) rsReset() {
	for r := range f.fecRS {
		f.fecRS[r] = f.fecRS[r][:0]
	}
}

// parityRows is how many parity rows the next group gets: the configured minimum, plus
// one while frames are being lost and another during a heavy burst.
func (s *Sender) parityRows(now time.Time) int {
	lo, hi := s.parityMin, s.parityMax
	if lo < 1 {
		lo = 1
	}
	if hi == 0 {
		hi = fecMaxRows
	}
	if hi < lo {
		hi = lo
	}
	if hi > fecMaxRows {
		hi = fecMaxRows
	}
	heat := s.lossHeatAt(now)
	rows := lo
	if heat >= 2 {
		rows++
	}
	if heat >= 12 {
		rows++
	}
	if rows > hi {
		rows = hi
	}
	return rows
}

// SetParityRows bounds the adaptive number of parity rows per group of fecK packets:
// 1 row is a 12.5% overhead, 2 is 25%, 3 is 37.5%. Zero max means the built-in limit.
func (s *Sender) SetParityRows(min, max int) {
	s.parityMin, s.parityMax = min, max
}

// lossHeatAt is an exponentially decaying count of frames recently seen lost.
func (s *Sender) lossHeatAt(now time.Time) float64 {
	if s.heatAt.IsZero() {
		return 0
	}
	return s.heat * math.Exp(-now.Sub(s.heatAt).Seconds()/2)
}

func (s *Sender) addLossHeat(now time.Time) {
	s.heat = s.lossHeatAt(now) + 1
	s.heatAt = now
}

type deferredFrame struct {
	at   time.Time
	kind byte
	body []byte
	used *receivePath
}

// sendDeferred writes the staggered parity rows that have come due.
func (s *Sender) sendDeferred(now time.Time, writer DatagramWriter) {
	if len(s.deferred) == 0 {
		return
	}
	kept := s.deferred[:0]
	for _, d := range s.deferred {
		if now.Before(d.at) {
			kept = append(kept, d)
			continue
		}
		paths := s.eligible(now, true)
		if len(paths) == 0 {
			continue
		}
		s.writeParity(d.kind, d.body, d.used, paths, now, writer)
	}
	s.deferred = kept
}

// writeParity sends one parity frame on the best path other than used (or used itself
// when nothing else is ready).
func (s *Sender) writeParity(kind byte, body []byte, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	size := len(body) + Overhead
	target := s.other(used, paths, size, now, !s.lossTiered)
	if target == nil {
		target = used
	}
	if target == nil {
		return
	}
	frame, err := s.r.codec.Encode(kind, body)
	if err != nil {
		return
	}
	if s.written(Datagram{Endpoint: target.endpoint, Frame: frame, Local: target.local}, target, now, writer) {
		s.stats.Copies++
		s.stats.ParitySent++
		if kind == ParityRS {
			s.stats.ParityRSSent++
		}
	}
}

// emitParityRS sends rows parity rows for the finished group.
func (s *Sender) emitParityRS(f *sendFlow, rows int, used *receivePath, paths []*receivePath, now time.Time, writer DatagramWriter) {
	for r := 0; r < rows; r++ {
		body := make([]byte, rsHeader+len(f.fecRS[r]))
		binary.BigEndian.PutUint64(body, f.id)
		binary.BigEndian.PutUint64(body[8:], f.fecBase)
		body[16] = f.fecMask
		body[17] = byte(r)
		copy(body[rsHeader:], f.fecRS[r])
		if r == 0 {
			s.writeParity(ParityRS, body, used, paths, now, writer)
			continue
		}
		if len(s.deferred) < deferredMax {
			s.deferred = append(s.deferred, deferredFrame{at: now.Add(time.Duration(r) * parityStagger), kind: ParityRS, body: body, used: used})
		}
	}
}

// --- receiving ---

// rsRows are the Reed-Solomon parity rows a receiver holds for one group.
type rsRows struct {
	mask    uint8 // rows held
	members uint8 // the group's membership as the sender saw it (the same on every row)
	rows    [fecMaxRows][]byte
}

func (r *Receiver) fecParityRS(body []byte, now time.Time) []fecHit {
	if len(body) < rsHeader+2 {
		r.stats.Malformed++
		return nil
	}
	flow, base, mask, row := binary.BigEndian.Uint64(body), binary.BigEndian.Uint64(body[8:]), body[16], int(body[17])
	if base%fecK != 0 || mask == 0 || row >= fecMaxRows {
		r.stats.Malformed++
		return nil
	}
	if r.fec == nil {
		r.fec = &fecState{groups: make(map[fecKey]*fecGroup)}
	}
	r.fec.lastParity = now
	g := r.fecGroup(fecKey{flow, base})
	if g.rs.mask&(1<<row) != 0 {
		return nil
	}
	g.rs.mask |= 1 << row
	g.rs.members = mask
	g.rs.rows[row] = append([]byte(nil), body[rsHeader:]...)
	return r.fecTryRS(g)
}

// fecTryRS rebuilds every missing member it can: n missing members need n rows.
func (r *Receiver) fecTryRS(g *fecGroup) []fecHit {
	if g.rs.mask == 0 {
		return nil
	}
	members := g.rs.members
	missing := members &^ g.have
	if missing == 0 {
		r.fecDrop(g)
		return nil
	}
	n := bits.OnesCount8(missing)
	if n > bits.OnesCount8(g.rs.mask) {
		return nil
	}
	var rowIdx []int
	for i := 0; i < fecMaxRows && len(rowIdx) < n; i++ {
		if g.rs.mask&(1<<i) != 0 {
			rowIdx = append(rowIdx, i)
		}
	}
	length := len(g.rs.rows[rowIdx[0]])
	for _, i := range rowIdx {
		if len(g.rs.rows[i]) != length {
			r.stats.Malformed++
			return nil
		}
	}
	// Subtract the known members from each chosen row.
	known := make([][]byte, n)
	for a, ri := range rowIdx {
		known[a] = append([]byte(nil), g.rs.rows[ri]...)
		for m := 0; m < fecK; m++ {
			if members&(1<<m) == 0 || missing&(1<<m) != 0 {
				continue
			}
			d := g.data[m]
			if d == nil || len(d)+2 > length {
				return nil // member longer than the parity block: not part of this group
			}
			var l [2]byte
			binary.BigEndian.PutUint16(l[:], uint16(len(d)))
			c := rsCoeff(ri, m)
			gfAddScaled(known[a][:2], l[:], c)
			gfAddScaled(known[a][2:], d, c)
		}
	}
	var cols []int
	for m := 0; m < fecK; m++ {
		if missing&(1<<m) != 0 {
			cols = append(cols, m)
		}
	}
	// Gauss-Jordan over GF(256): A x = known, one unknown block per missing member.
	a := make([][]byte, n)
	for i := range a {
		a[i] = make([]byte, n)
		for j := range cols {
			a[i][j] = rsCoeff(rowIdx[i], cols[j])
		}
	}
	for c := 0; c < n; c++ {
		p := -1
		for i := c; i < n; i++ {
			if a[i][c] != 0 {
				p = i
				break
			}
		}
		if p < 0 {
			return nil // cannot happen for a Cauchy matrix; never guess
		}
		a[c], a[p] = a[p], a[c]
		known[c], known[p] = known[p], known[c]
		inv := gfInv(a[c][c])
		for j := range a[c] {
			a[c][j] = gfMul(a[c][j], inv)
		}
		scaled := make([]byte, length)
		gfAddScaled(scaled, known[c], inv)
		known[c] = scaled
		for i := 0; i < n; i++ {
			if i == c || a[i][c] == 0 {
				continue
			}
			f := a[i][c]
			for j := range a[i] {
				a[i][j] ^= gfMul(f, a[c][j])
			}
			gfAddScaled(known[i], known[c], f)
		}
	}
	var hits []fecHit
	for j, m := range cols {
		block := known[j]
		size := int(binary.BigEndian.Uint16(block))
		if size == 0 || 2+size > len(block) {
			r.stats.Malformed++
			continue
		}
		g.have |= 1 << m
		r.stats.FECRecovered++
		r.stats.FECRecoveredRS++
		hits = append(hits, fecHit{g.key.flow, g.key.base + uint64(m), append([]byte(nil), block[2:2+size]...)})
	}
	if g.have&members == members {
		r.fecDrop(g)
	}
	return hits
}
