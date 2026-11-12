package bond

import (
	"encoding/binary"
	"sort"
	"time"
)

// Supervision follows IEC 62439-3 (PRP/HSR) and IEEE 802.1CB: each side periodically tells
// the other what it believes about each of its own paths, and ages out a peer that goes
// quiet at 2.5x the interval. BFD detects a dead path in 300 ms; supervision adds what
// BFD cannot: the peer's own opinion, which exposes asymmetric failures (a path that
// looks healthy here while the peer already counts it down).
const (
	supervisionInterval = 2 * time.Second
	supervisionAging    = supervisionInterval * 5 / 2
	supervisionVersion  = 1
	supervisedSize      = 12

	// A burst that takes one announcement leaves the peer's view stale for a further whole
	// interval. When the peer's own announcement is overdue by a quarter interval we retry every
	// supervisionRetry instead of waiting, and a change in what we believe about our paths is
	// announced at once (at most one frame per supervisionMinGap per path).
	supervisionOverdue = supervisionInterval * 5 / 4
	supervisionRetry   = 250 * time.Millisecond
	supervisionMinGap  = 100 * time.Millisecond
)

const (
	supReady byte = 1 << iota
	supHealthy
	supSuspect
)

// supervisedPath is one path as its owner sees it.
type supervisedPath struct {
	Local      uint8
	Flags      byte
	RTTTenthMS uint16
	SkewTenth  uint16
	FirstWins  uint32
}

func (s supervisedPath) Ready() bool   { return s.Flags&supReady != 0 }
func (s supervisedPath) Healthy() bool { return s.Flags&supHealthy != 0 }
func (s supervisedPath) Suspect() bool { return s.Flags&supSuspect != 0 }

func validSupervision(payload []byte) bool {
	return len(payload) >= 2 && payload[0] == supervisionVersion && len(payload) == 2+int(payload[1])*supervisedSize
}

func parseSupervision(payload []byte) []supervisedPath {
	out := make([]supervisedPath, payload[1])
	for i := range out {
		e := payload[2+i*supervisedSize:]
		out[i] = supervisedPath{e[0], e[1], binary.BigEndian.Uint16(e[2:]), binary.BigEndian.Uint16(e[4:]), binary.BigEndian.Uint32(e[6:])}
	}
	return out
}

func tenths(ms float64) uint16 {
	switch {
	case ms <= 0:
		return 0
	case ms >= 6553:
		return 65535
	}
	return uint16(ms * 10)
}

// supervisionEntries is this side's view of each of its own paths.
func (r *Receiver) supervisionEntries(now time.Time) []supervisedPath {
	var entries []supervisedPath
	for _, p := range r.paths {
		if p.parked || len(entries) >= 16 {
			continue
		}
		var flags byte
		if p.ready {
			flags |= supReady
			if now.Sub(p.last) < 3*time.Second {
				flags |= supHealthy
			}
		}
		if p.suspect {
			flags |= supSuspect
		}
		entries = append(entries, supervisedPath{uint8(p.local), flags, tenths(p.rtt * 1000), tenths(p.skewMS), uint32(p.firstWins)})
	}
	// r.paths is a map: a stable order keeps the frame, and its signature, deterministic.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Local < entries[j].Local })
	return entries
}

// supervisionSignature identifies what the entries say about path state, ignoring the
// measurements that change on every frame (RTT, skew, win counts).
func supervisionSignature(entries []supervisedPath) uint64 {
	h := uint64(14695981039346656037)
	for _, e := range entries {
		h = (h ^ uint64(e.Local)) * 1099511628211
		h = (h ^ uint64(e.Flags)) * 1099511628211
	}
	return h
}

func encodeSupervision(entries []supervisedPath) []byte {
	payload := make([]byte, 2+len(entries)*supervisedSize)
	payload[0], payload[1] = supervisionVersion, byte(len(entries))
	for i, e := range entries {
		b := payload[2+i*supervisedSize:]
		b[0], b[1] = e.Local, e.Flags
		binary.BigEndian.PutUint16(b[2:], e.RTTTenthMS)
		binary.BigEndian.PutUint16(b[4:], e.SkewTenth)
		binary.BigEndian.PutUint32(b[6:], e.FirstWins)
	}
	return payload
}

func (r *Receiver) supervisionPayload(now time.Time) []byte {
	return encodeSupervision(r.supervisionEntries(now))
}

// supervise sends the announcement over every live path, so the peer learns both what we
// think and, from which copies arrive, whether each path really carries it.
//
// The regular cadence is anchored to the previous deadline, so a late tick does not stretch it.
// Two things send earlier: a change in path state, and a peer announcement that is overdue (the
// burst that ate it may have eaten ours too). Both are rate limited per path.
func (r *Receiver) supervise(now time.Time, out *ReceiveResult) error {
	var payload []byte
	var sig uint64
	for _, p := range r.paths {
		if !p.ready || p.parked || now.Sub(p.last) >= 3*time.Second {
			continue
		}
		if p.supNext.IsZero() || p.lastSupervision.IsZero() {
			// first announcement one interval after the path comes up
			p.lastSupervision, p.supNext = now, now.Add(supervisionInterval)
			continue
		}
		if payload == nil {
			entries := r.supervisionEntries(now)
			payload, sig = encodeSupervision(entries), supervisionSignature(entries)
		}
		since := now.Sub(p.lastSupervision)
		scheduled := !now.Before(p.supNext)
		changed := sig != p.supSig && since >= supervisionMinGap
		overdue := !p.peerSupAt.IsZero() && now.Sub(p.peerSupAt) > supervisionOverdue && since >= supervisionRetry
		if !scheduled && !changed && !overdue {
			continue
		}
		if err := r.write(Supervision, payload, p.local, p.endpoint, out); err != nil {
			return err
		}
		p.lastSupervision, p.supSig = now, sig
		if scheduled {
			p.supNext = p.supNext.Add(supervisionInterval)
			if !p.supNext.After(now) { // more than an interval late: re-anchor rather than burst
				p.supNext = now.Add(supervisionInterval)
			}
		} else if min := now.Add(supervisionInterval / 2); p.supNext.Before(min) {
			p.supNext = min
		}
	}
	return nil
}

// supervisionState summarises what the peer said on this path: how stale it is, and
// whether the peer's view of the same path disagrees with ours.
func (p *receivePath) supervisionState(now time.Time) map[string]any {
	state := map[string]any{"heard": !p.peerSupAt.IsZero()}
	if p.peerSupAt.IsZero() {
		return state
	}
	age := now.Sub(p.peerSupAt)
	state["age_ms"] = float64(age) / float64(time.Millisecond)
	state["aged"] = age > supervisionAging
	state["peer_paths"] = len(p.peerSup)
	var down, suspect int
	for _, e := range p.peerSup {
		if !e.Ready() || !e.Healthy() {
			down++
		}
		if e.Suspect() {
			suspect++
		}
	}
	state["peer_paths_down"], state["peer_paths_suspect"] = down, suspect
	return state
}
