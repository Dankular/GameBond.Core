package bond

import (
	"container/list"
	"errors"
	"math"
	"slices"
)

// Port of gamebond/path_quality.py: bounded, clock-free state machines for
// data-plane path evidence. Every timestamp is supplied by the caller and access
// must be serialized. path-quality-vectors.json.gz, generated from the Python
// classes by tools/generate_native_path_quality_vectors.py, pins the behaviour.

// MTULadder lists outer UDP payload sizes (the complete datagram body).
var MTULadder = [...]int{1472, 1400, 1344, 1280, 1232, 1200, 1100, 1000, 800, 600, 548}

const (
	MTURoundSeconds   = 1.0  // spacing between search rounds
	MTUStrikes        = 3    // unanswered rounds before a size counts as failed
	MTURecheckSeconds = 60.0 // settled/blocked paths re-run the search this often
)

// CopyOutcome is the verdict for one expected path of a resolved packet.
type CopyOutcome string

const (
	CopySeen   CopyOutcome = "seen"
	CopyMissed CopyOutcome = "missed"
)

// CopyResolution pairs a path identity with its outcome.
type CopyResolution[K comparable] struct {
	Identity K
	Outcome  CopyOutcome
}

// DuplicateKind says how a further copy was classified.
type DuplicateKind string

const (
	DuplicatePending DuplicateKind = "pending"
	DuplicateLate    DuplicateKind = "late"
)

type ledgerPending[K comparable] struct {
	sequence uint64
	firstAt  float64
	expected []K
	arrived  map[K]float64
}
type ledgerResolved[K comparable] struct {
	sequence uint64
	firstAt  float64
	missed   map[K]struct{}
}

// CopyLedger is a first-arrival ledger for replicated packets, keyed by
// transport sequence. First records which paths were expected to carry a copy,
// Duplicate notes further copies, and Resolve decides, once a packet is older
// than the resolve delay, which expected paths delivered it and which did not.
//
// Like the Python OrderedDict it replaces, re-recording an existing sequence
// updates it in place without changing its eviction order.
type CopyLedger[K comparable] struct {
	capacity     int
	pending      map[uint64]*list.Element
	pendingOrder list.List
	resolved     map[uint64]*list.Element
	resolvedList list.List
}

func NewCopyLedger[K comparable](capacity int) (*CopyLedger[K], error) {
	if capacity < 1 {
		return nil, errors.New("capacity must be a positive integer")
	}
	return &CopyLedger[K]{capacity: capacity, pending: make(map[uint64]*list.Element), resolved: make(map[uint64]*list.Element)}, nil
}

func (l *CopyLedger[K]) HasPending() bool { return len(l.pending) != 0 }

func (l *CopyLedger[K]) First(sequence uint64, identity K, expected []K, now float64) {
	entry := &ledgerPending[K]{sequence: sequence, firstAt: now, expected: slices.Clone(expected), arrived: map[K]float64{identity: now}}
	if e, ok := l.pending[sequence]; ok {
		e.Value = entry
	} else {
		l.pending[sequence] = l.pendingOrder.PushBack(entry)
	}
	for len(l.pending) > l.capacity {
		front := l.pendingOrder.Front()
		delete(l.pending, front.Value.(*ledgerPending[K]).sequence)
		l.pendingOrder.Remove(front)
	}
}

// Duplicate classifies a further copy. ok is false for an unknown packet or an
// identity already recorded. DuplicateLate means the path had already been
// counted missed; the caller reverses that count and treats lag as jitter.
func (l *CopyLedger[K]) Duplicate(sequence uint64, identity K, now float64) (kind DuplicateKind, lag float64, ok bool) {
	if e, found := l.pending[sequence]; found {
		entry := e.Value.(*ledgerPending[K])
		if _, seen := entry.arrived[identity]; seen {
			return "", 0, false
		}
		entry.arrived[identity] = now
		return DuplicatePending, math.Max(0, now-entry.firstAt), true
	}
	if e, found := l.resolved[sequence]; found {
		entry := e.Value.(*ledgerResolved[K])
		if _, missed := entry.missed[identity]; missed {
			delete(entry.missed, identity)
			return DuplicateLate, math.Max(0, now-entry.firstAt), true
		}
	}
	return "", 0, false
}

// Resolve returns an outcome per expected path for every packet older than
// delay. Packets with fewer than two expected paths carry no comparison and
// produce no outcome.
func (l *CopyLedger[K]) Resolve(now, delay float64) []CopyResolution[K] {
	var outcomes []CopyResolution[K]
	for l.pendingOrder.Len() > 0 {
		front := l.pendingOrder.Front()
		entry := front.Value.(*ledgerPending[K])
		if now-entry.firstAt < delay {
			break
		}
		l.pendingOrder.Remove(front)
		delete(l.pending, entry.sequence)
		if len(entry.expected) < 2 {
			continue
		}
		missed := make(map[K]struct{})
		for _, identity := range entry.expected {
			if _, ok := entry.arrived[identity]; ok {
				outcomes = append(outcomes, CopyResolution[K]{identity, CopySeen})
			} else {
				outcomes = append(outcomes, CopyResolution[K]{identity, CopyMissed})
				missed[identity] = struct{}{}
			}
		}
		if len(missed) > 0 {
			record := &ledgerResolved[K]{sequence: entry.sequence, firstAt: entry.firstAt, missed: missed}
			if e, ok := l.resolved[entry.sequence]; ok {
				e.Value = record
			} else {
				l.resolved[entry.sequence] = l.resolvedList.PushBack(record)
			}
			for len(l.resolved) > l.capacity {
				oldest := l.resolvedList.Front()
				delete(l.resolved, oldest.Value.(*ledgerResolved[K]).sequence)
				l.resolvedList.Remove(oldest)
			}
		}
	}
	return outcomes
}

func (l *CopyLedger[K]) Stats() (pending, resolved int) { return len(l.pending), len(l.resolved) }

type mtuProbeKey struct {
	nonce uint64
	size  int
}

// MTUProbe is one probe to transmit: a datagram claiming Size bytes.
type MTUProbe struct {
	Nonce uint64
	Size  int
}

// MTUStats mirrors MtuProber.stats().
type MTUStats struct {
	PathMTU     int
	Ceiling     int
	Confirmed   int // valid only when Capable
	Capable     bool
	Rounds      int
	Acks        int
	FailedSizes []int
}

// MTUProber runs one path's outbound MTU search.
//
// Until the peer answers any probe, PathMTU stays at the ceiling: a peer that
// predates the probe message would otherwise look like a path that drops every
// large packet. After the first answer it is the largest answered size. Every
// ladder size above it is probed once per round; a size unanswered for
// MTUStrikes rounds is failed until the next recheck.
type MTUProber struct {
	sizes       []int
	ceiling     int
	confirmed   int
	capable     bool
	strikes     map[int]int
	outstanding map[mtuProbeKey]float64
	roundAt     float64
	hasRound    bool
	recheckAt   float64
	hasRecheck  bool
	rounds      int
	acks        int
}

func NewMTUProber(ceiling, floor int) (*MTUProber, error) {
	if floor <= 0 || floor > ceiling {
		return nil, errors.New("invalid MTU bounds")
	}
	set := map[int]struct{}{ceiling: {}}
	for _, s := range MTULadder {
		if s >= floor && s <= ceiling {
			set[s] = struct{}{}
		}
	}
	sizes := make([]int, 0, len(set))
	for s := range set {
		sizes = append(sizes, s)
	}
	slices.SortFunc(sizes, func(a, b int) int { return b - a })
	return &MTUProber{sizes: sizes, ceiling: ceiling, strikes: make(map[int]int), outstanding: make(map[mtuProbeKey]float64)}, nil
}

func (p *MTUProber) Capable() bool { return p.capable }

func (p *MTUProber) PathMTU() int {
	if p.capable {
		return p.confirmed
	}
	return p.ceiling
}

func (p *MTUProber) failed(size int) bool { return p.strikes[size] >= MTUStrikes }

func (p *MTUProber) openSizes() []int {
	above := 0
	if p.capable {
		above = p.confirmed
	}
	var open []int
	for _, s := range p.sizes {
		if s > above && !p.failed(s) {
			open = append(open, s)
		}
	}
	return open
}

// Due returns the probes to transmit now (possibly none). newNonce is called
// once per probe, in descending size order.
func (p *MTUProber) Due(now float64, newNonce func() uint64) []MTUProbe {
	// A round that went unanswered strikes every size it covered.
	for key, sent := range p.outstanding {
		if now-sent >= MTURoundSeconds*1.5 {
			delete(p.outstanding, key)
			p.strikes[key.size]++
		}
	}
	open := p.openSizes()
	if len(open) == 0 {
		if !p.hasRecheck {
			p.recheckAt, p.hasRecheck = now+MTURecheckSeconds, true
		} else if now >= p.recheckAt {
			clear(p.strikes)
			p.hasRecheck = false
			open = p.openSizes()
		}
		if len(open) == 0 {
			return nil
		}
	}
	if p.hasRound && now-p.roundAt < MTURoundSeconds {
		return nil
	}
	p.roundAt, p.hasRound = now, true
	p.rounds++
	sends := make([]MTUProbe, 0, len(open))
	for _, size := range open {
		nonce := newNonce()
		p.outstanding[mtuProbeKey{nonce, size}] = now
		sends = append(sends, MTUProbe{nonce, size})
	}
	return sends
}

// Acknowledge records an answer and reports whether it matched an outstanding probe.
func (p *MTUProber) Acknowledge(nonce uint64, size int) bool {
	key := mtuProbeKey{nonce, size}
	if _, ok := p.outstanding[key]; !ok {
		return false
	}
	delete(p.outstanding, key)
	p.acks++
	if !p.capable || size > p.confirmed {
		p.confirmed, p.capable = size, true
	}
	for other := range p.strikes {
		if other <= size {
			delete(p.strikes, other)
		}
	}
	// Probes for smaller sizes in this round no longer add information.
	for k := range p.outstanding {
		if k.size <= size {
			delete(p.outstanding, k)
		}
	}
	return true
}

func (p *MTUProber) Stats() MTUStats {
	var failed []int
	for _, s := range p.sizes {
		if p.failed(s) {
			failed = append(failed, s)
		}
	}
	slices.Sort(failed)
	return MTUStats{PathMTU: p.PathMTU(), Ceiling: p.ceiling, Confirmed: p.confirmed, Capable: p.capable, Rounds: p.rounds, Acks: p.acks, FailedSizes: failed}
}
