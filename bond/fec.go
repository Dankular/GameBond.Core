package bond

import (
	"container/list"
	"encoding/binary"
	"math/bits"
	"time"
)

// Forward error correction and adaptive duplication for striped bulk flows.
//
// Every fecK consecutive packets of a bulk flow (numbers n with the same n/fecK)
// form a group. While a path shows loss the sender adds one PARITY frame per group:
// the XOR of each member's 2-byte length plus payload. The receiver rebuilds a single
// missing member from the parity and the others, so a lone loss is repaired without
// a round trip. Heavier loss is answered by duplicating each packet on a second path
// (see bulkProtect). Both are first-arrival-wins through the reorder window.
const (
	fecK         = 8
	fecGroupsMax = 1024
	fecLife      = 10 * time.Second // receivers keep data for FEC this long after the last parity
	parityHeader = 17               // flow(8) base(8) mask(1)

	// Protection tiers by smoothed per-path loss.
	fecRatio = 0.003 // parity from here
	dupRatio = 0.015 // duplicate from here
	// lossStale is how long a loss estimate stays usable without a new measurement.
	lossStale = 3.0
)

// fecHit is a rebuilt packet: payload is nil when nothing was recovered.
type fecHit struct {
	flow, number uint64
	payload      []byte
}
type fecKey struct{ flow, base uint64 }
type fecGroup struct {
	key        fecKey
	have       uint8
	data       [fecK][]byte
	hasParity  bool
	parityMask uint8
	parity     []byte
	order      *list.Element
	rs         rsRows
}
type fecState struct {
	groups     map[fecKey]*fecGroup
	order      list.List
	lastParity time.Time
}

func (r *Receiver) fecReset() { r.fec = nil }

func (r *Receiver) fecEnabled(now time.Time) bool {
	return r.fec != nil && now.Sub(r.fec.lastParity) < fecLife
}

func (r *Receiver) fecGroup(k fecKey) *fecGroup {
	if r.fec == nil {
		r.fec = &fecState{groups: make(map[fecKey]*fecGroup)}
	}
	g := r.fec.groups[k]
	if g == nil {
		g = &fecGroup{key: k}
		g.order = r.fec.order.PushBack(g)
		r.fec.groups[k] = g
		for len(r.fec.groups) > fecGroupsMax {
			old := r.fec.order.Front().Value.(*fecGroup)
			r.fec.order.Remove(old.order)
			delete(r.fec.groups, old.key)
		}
	}
	return g
}

// fecData records a received striped payload (only while parity is arriving) and
// returns a payload rebuilt from it, if that completes a group.
func (r *Receiver) fecData(flow, number uint64, payload []byte, now time.Time) []fecHit {
	if !r.fecEnabled(now) {
		return nil
	}
	idx := number % fecK
	g := r.fecGroup(fecKey{flow, number - idx})
	if g.have&(1<<idx) != 0 {
		return nil
	}
	g.have |= 1 << idx
	g.data[idx] = append([]byte(nil), payload...)
	var hits []fecHit
	if hit := r.fecTry(g); hit.payload != nil {
		hits = append(hits, hit)
	}
	return append(hits, r.fecTryRS(g)...)
}

func (r *Receiver) fecParity(body []byte, now time.Time) fecHit {
	if len(body) < parityHeader+2 {
		r.stats.Malformed++
		return fecHit{}
	}
	flow, base, mask := binary.BigEndian.Uint64(body), binary.BigEndian.Uint64(body[8:]), body[16]
	if base%fecK != 0 || mask == 0 {
		r.stats.Malformed++
		return fecHit{}
	}
	if r.fec == nil {
		r.fec = &fecState{groups: make(map[fecKey]*fecGroup)}
	}
	r.fec.lastParity = now
	g := r.fecGroup(fecKey{flow, base})
	if g.hasParity {
		return fecHit{}
	}
	g.hasParity, g.parityMask = true, mask
	g.parity = append([]byte(nil), body[parityHeader:]...)
	return r.fecTry(g)
}

func (r *Receiver) fecTry(g *fecGroup) fecHit {
	if !g.hasParity {
		return fecHit{}
	}
	missing := g.parityMask &^ g.have
	if missing == 0 {
		r.fecDrop(g)
		return fecHit{}
	}
	if bits.OnesCount8(missing) != 1 {
		return fecHit{}
	}
	idx := uint(bits.TrailingZeros8(missing))
	block := append([]byte(nil), g.parity...)
	for i := uint(0); i < fecK; i++ {
		if g.parityMask&(1<<i) == 0 || i == idx {
			continue
		}
		d := g.data[i]
		if d == nil || len(d)+2 > len(block) {
			return fecHit{} // member longer than the parity block: cannot be part of this group
		}
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(d)))
		block[0] ^= l[0]
		block[1] ^= l[1]
		for j, b := range d {
			block[2+j] ^= b
		}
	}
	n := int(binary.BigEndian.Uint16(block))
	if n == 0 || 2+n > len(block) {
		r.stats.Malformed++
		r.fecDrop(g)
		return fecHit{}
	}
	g.have |= 1 << idx
	number := g.key.base + uint64(idx)
	rebuilt := append([]byte(nil), block[2:2+n]...)
	r.stats.FECRecovered++
	flow := g.key.flow
	if g.have&g.parityMask == g.parityMask {
		r.fecDrop(g)
	}
	return fecHit{flow, number, rebuilt}
}

func (r *Receiver) fecDrop(g *fecGroup) {
	if r.fec == nil {
		return
	}
	r.fec.order.Remove(g.order)
	delete(r.fec.groups, g.key)
}
