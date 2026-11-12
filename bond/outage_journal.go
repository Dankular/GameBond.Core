package bond

import (
	"sort"
	"sync"
	"time"
)

// Outage journal: a timestamped record of every moment a line stopped or resumed
// carrying traffic, with the cause, and of every moment no line was carrying at all.
// The status sampler only looks every few seconds; this records the exact transition.
//
// It is built to survive an unbounded event count:
//   - Memory is fixed: a small ring of recent events, running totals, and one counter per
//     minute for the last day. Nothing grows with the number of events.
//   - Recording is O(1) and never blocks the packet loop: the durable log (outage_log.go)
//     is fed through a non-blocking queue and drops, counting the drops, rather than wait.
//   - The status snapshot is rebuilt only when something changed, not on every poll, and
//     carries only the newest events; full history is on disk.

const (
	outageJournalSize = 256 // recent events kept in memory
	outageSnapshotLen = 40  // newest events placed in each status snapshot
	outageMinutes     = 1440
	outageSlots       = 8
)

// Outage event kinds.
const (
	OutageLinkDown      = "link_down"      // BFD declared the line down
	OutageLinkUp        = "link_up"        // BFD accepted the line again (after hold-down)
	OutageLinkLost      = "link_lost"      // handshake restarted: line not ready
	OutageLinkReady     = "link_ready"     // handshake complete: line ready
	OutageNoLinks       = "no_links"       // no line is carrying traffic
	OutageLinksRestored = "links_restored" // a line is carrying traffic again

	// Driver and adapter health (Slot is -1; Source names the component).
	OutageComponentDown  = "component_down"  // a driver, adapter or capture process failed
	OutageComponentUp    = "component_up"    // it recovered
	OutageComponentError = "component_error" // its error or discard counters grew
)

var outageKinds = []string{OutageLinkDown, OutageLinkUp, OutageLinkLost, OutageLinkReady, OutageNoLinks, OutageLinksRestored,
	OutageComponentDown, OutageComponentUp, OutageComponentError}

func kindID(k string) uint8 {
	for i, n := range outageKinds {
		if n == k {
			return uint8(i)
		}
	}
	return 255
}

// Causes are stored as one byte in the durable log.
var outageCauses = []string{"", "silence", "peer_not_hearing_us", "handshake_restart"}

func causeID(c string) uint8 {
	for i, n := range outageCauses {
		if n == c {
			return uint8(i)
		}
	}
	return 255
}

// OutageEvent is one journal entry. AtMS is Unix milliseconds.
type OutageEvent struct {
	Seq    uint64  `json:"seq"`
	AtMS   int64   `json:"at_ms"`
	Slot   int     `json:"slot"`
	Source string  `json:"source,omitempty"` // component events: "driver:packet_filter", "nic:Ethernet", ...
	Note   string  `json:"note,omitempty"`   // component events: short reason or counter growth
	Kind   string  `json:"kind"`
	Cause  string  `json:"cause,omitempty"`
	DownMS float64 `json:"down_ms,omitempty"` // how long the line (or all lines) had been out
}

type minuteBucket struct {
	minute  int64
	downs   uint32
	noLinks uint32
}

// OutageJournal is safe for concurrent use.
type OutageJournal struct {
	mu     sync.Mutex
	events []OutageEvent
	next   int
	full   bool
	seq    uint64

	noLinksSince time.Time // zero while some line carries

	// totals since the client started
	byKind       [16]uint64
	comps        map[string]*compState
	slotDowns    [outageSlots]uint64
	slotDownMS   [outageSlots]float64
	noLinksCount uint64
	noLinksMaxMS float64
	minutes      [outageMinutes]minuteBucket

	version  uint64
	cacheVer uint64
	cache    OutageSummary
	log      *outageLog
}

func newOutageJournal() *OutageJournal {
	return &OutageJournal{events: make([]OutageEvent, outageJournalSize), version: 1, comps: map[string]*compState{}}
}

// add stores one event. The caller holds j.mu.
func (j *OutageJournal) add(e OutageEvent) {
	j.seq++
	e.Seq = j.seq
	j.events[j.next] = e
	j.next++
	if j.next == len(j.events) {
		j.next, j.full = 0, true
	}
	if k := kindID(e.Kind); int(k) < len(j.byKind) {
		j.byKind[k]++
	}
	if e.Kind == OutageLinkDown && e.Slot >= 0 && e.Slot < outageSlots {
		j.slotDowns[e.Slot]++
	}
	if e.Kind == OutageLinkUp && e.Slot >= 0 && e.Slot < outageSlots {
		j.slotDownMS[e.Slot] += e.DownMS
	}
	if e.Kind == OutageLinkDown || e.Kind == OutageNoLinks {
		min := e.AtMS / 60000
		b := &j.minutes[min%outageMinutes]
		if b.minute != min {
			*b = minuteBucket{minute: min}
		}
		if e.Kind == OutageLinkDown {
			b.downs++
		} else {
			b.noLinks++
		}
	}
	j.version++
	if j.log != nil {
		j.log.enqueue(e) // never blocks
	}
}

// Record adds one event.
func (j *OutageJournal) Record(now time.Time, slot int, kind, cause string, down time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.add(OutageEvent{AtMS: now.UnixMilli(), Slot: slot, Kind: kind, Cause: cause, DownMS: float64(down) / float64(time.Millisecond)})
}

// Carrying is called after any transition with whether at least one line can carry
// traffic; it records the start and end of full outages.
func (j *OutageJournal) Carrying(now time.Time, slot int, any bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch {
	case !any && j.noLinksSince.IsZero():
		j.noLinksSince = now
		j.noLinksCount++
		j.add(OutageEvent{AtMS: now.UnixMilli(), Slot: slot, Kind: OutageNoLinks})
	case any && !j.noLinksSince.IsZero():
		d := now.Sub(j.noLinksSince)
		ms := float64(d) / float64(time.Millisecond)
		if ms > j.noLinksMaxMS {
			j.noLinksMaxMS = ms
		}
		j.noLinksSince = time.Time{}
		j.add(OutageEvent{AtMS: now.UnixMilli(), Slot: slot, Kind: OutageLinksRestored, DownMS: ms})
	}
}

// maxComponents bounds the component table; further sources are folded into "other".
const maxComponents = 64

type compState struct {
	ok      bool
	since   time.Time
	fails   uint64
	errors  uint64
	note    string
	lastErr int64 // Unix ms of the last error event
}

// ComponentInfo is the current state of one driver, adapter or capture process.
type ComponentInfo struct {
	Source  string `json:"source"`
	OK      bool   `json:"ok"`
	SinceMS int64  `json:"since_ms"`
	Fails   uint64 `json:"fails"`
	Errors  uint64 `json:"errors"`
	Note    string `json:"note,omitempty"`
}

func (j *OutageJournal) compLocked(now time.Time, source string) (*compState, string) {
	if c := j.comps[source]; c != nil {
		return c, source
	}
	if len(j.comps) >= maxComponents {
		source = "other"
		if c := j.comps[source]; c != nil {
			return c, source
		}
	}
	c := &compState{ok: true, since: now}
	j.comps[source] = c
	return c, source
}

// Component records the state of a driver, adapter or process. Only changes are journalled,
// so polling it every second costs nothing when nothing changes. A source first seen failing
// is journalled at once; one first seen healthy is just remembered.
func (j *OutageJournal) Component(now time.Time, source string, ok bool, note string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	c, source := j.compLocked(now, source)
	if c.ok == ok {
		if c.note != note && !ok {
			c.note = note
			j.version++ // the reason changed while still failing
		}
		return
	}
	prev := c.since
	c.ok, c.since, c.note = ok, now, note
	if ok {
		j.add(OutageEvent{AtMS: now.UnixMilli(), Slot: -1, Source: source, Kind: OutageComponentUp, Note: note, DownMS: float64(now.Sub(prev)) / float64(time.Millisecond)})
		return
	}
	c.fails++
	j.add(OutageEvent{AtMS: now.UnixMilli(), Slot: -1, Source: source, Kind: OutageComponentDown, Note: note})
}

// ComponentError records growth of a component's error counters. The caller polls, so this
// is at most one event per source per poll.
func (j *OutageJournal) ComponentError(now time.Time, source, note string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	c, source := j.compLocked(now, source)
	c.errors++
	c.lastErr = now.UnixMilli()
	j.add(OutageEvent{AtMS: now.UnixMilli(), Slot: -1, Source: source, Kind: OutageComponentError, Note: note})
}

// Events returns the recent ring, oldest first.
func (j *OutageJournal) Events() []OutageEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.ringLocked()
}

func (j *OutageJournal) ringLocked() []OutageEvent {
	if !j.full {
		return append([]OutageEvent(nil), j.events[:j.next]...)
	}
	return append(append([]OutageEvent(nil), j.events[j.next:]...), j.events[:j.next]...)
}

// OutageSummary is the compact view for the status document.
type OutageSummary struct {
	Events         []OutageEvent   `json:"events"` // newest events only, oldest first
	TotalEvents    uint64          `json:"total_events"`
	LinkDowns      uint64          `json:"link_downs"`
	SlotDowns      []uint64        `json:"slot_downs"`
	SlotDownMS     []float64       `json:"slot_down_ms"`
	NoLinksCount   uint64          `json:"no_links_count"`
	NoLinksMaxMS   float64         `json:"no_links_max_ms"`
	NoLinksNow     bool            `json:"no_links_now"`
	DownsLastHour  uint64          `json:"downs_last_hour"`
	DownsLastDay   uint64          `json:"downs_last_day"`
	Log            OutageLogInfo   `json:"log"`
	Components     []ComponentInfo `json:"components"`
	ComponentFails uint64          `json:"component_fails"`
}

// Summary returns the snapshot, rebuilding it only if an event arrived since the last call.
func (j *OutageJournal) Summary() OutageSummary {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cacheVer == j.version {
		s := j.cache
		if j.log != nil {
			s.Log = j.log.info() // counters move without events
		}
		return s
	}
	ring := j.ringLocked()
	if len(ring) > outageSnapshotLen {
		ring = ring[len(ring)-outageSnapshotLen:]
	}
	nowMin := time.Now().UnixMilli() / 60000
	var hour, day uint64
	for i := range j.minutes {
		b := j.minutes[i]
		if b.minute == 0 || nowMin-b.minute >= outageMinutes {
			continue
		}
		day += uint64(b.downs)
		if nowMin-b.minute < 60 {
			hour += uint64(b.downs)
		}
	}
	s := OutageSummary{Events: ring, TotalEvents: j.seq, LinkDowns: j.byKind[kindID(OutageLinkDown)],
		SlotDowns: append([]uint64(nil), j.slotDowns[:]...), SlotDownMS: append([]float64(nil), j.slotDownMS[:]...),
		NoLinksCount: j.noLinksCount, NoLinksMaxMS: j.noLinksMaxMS, NoLinksNow: !j.noLinksSince.IsZero(),
		DownsLastHour: hour, DownsLastDay: day, Components: make([]ComponentInfo, 0, len(j.comps))}
	for name, c := range j.comps {
		s.Components = append(s.Components, ComponentInfo{Source: name, OK: c.ok, SinceMS: c.since.UnixMilli(), Fails: c.fails, Errors: c.errors, Note: c.note})
		s.ComponentFails += c.fails
	}
	sort.Slice(s.Components, func(a, b int) bool { return s.Components[a].Source < s.Components[b].Source })
	j.cache, j.cacheVer = s, j.version
	if j.log != nil {
		s.Log = j.log.info()
	}
	return s
}

// anyCarrying reports whether any line is ready and not BFD-down.
func (r *Receiver) anyCarrying() bool {
	for _, p := range r.paths {
		if p.ready && !p.parked && !p.bfdDown() {
			return true
		}
	}
	return false
}

// noteLine records a line transition and re-evaluates whether any line still carries.
func (r *Receiver) noteLine(p *receivePath, now time.Time, kind, cause string, down time.Duration) {
	if r.outages == nil {
		return
	}
	r.outages.Record(now, p.local, kind, cause, down)
	r.outages.Carrying(now, p.local, r.anyCarrying())
}

// Outages returns the journal summary.
func (r *Receiver) Outages() OutageSummary {
	if r.outages == nil {
		return OutageSummary{}
	}
	return r.outages.Summary()
}

// NoteComponent records a driver, adapter or process state change (see OutageJournal.Component).
func (r *Receiver) NoteComponent(source string, ok bool, note string) {
	if r.outages != nil {
		r.outages.Component(time.Now(), source, ok, note)
	}
}

// NoteComponentError records growth of a component's error counters.
func (r *Receiver) NoteComponentError(source, note string) {
	if r.outages != nil {
		r.outages.ComponentError(time.Now(), source, note)
	}
}

// OpenOutageLog starts the durable log in dir: fixed-size records in rotating segment
// files, capped in total size. It returns at once; writing happens in the background.
func (r *Receiver) OpenOutageLog(dir string) error {
	if r.outages == nil {
		return nil
	}
	l, err := openOutageLog(dir, outageSegmentBytes, outageMaxSegments)
	if err != nil {
		return err
	}
	r.outages.mu.Lock()
	r.outages.log = l
	r.outages.version++
	r.outages.mu.Unlock()
	return nil
}

// CloseOutageLog flushes and stops the durable log.
func (r *Receiver) CloseOutageLog() {
	if r.outages == nil {
		return
	}
	r.outages.mu.Lock()
	l := r.outages.log
	r.outages.log = nil
	r.outages.mu.Unlock()
	if l != nil {
		l.close()
	}
}
