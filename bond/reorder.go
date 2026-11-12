package bond

import (
	"container/heap"
	"container/list"
	"errors"
	"math"
	"time"
)

type sequenceHeap []uint64

func (h sequenceHeap) Len() int           { return len(h) }
func (h sequenceHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h sequenceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sequenceHeap) Push(v any)        { *h = append(*h, v.(uint64)) }
func (h *sequenceHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }

type heldPacket struct {
	payload []byte
	at      time.Time
}
// holeRange is a run of numbers skipped on first arrival: not held, but still asked for
// from the peer's repair cache if neither copy turns up.
type holeRange struct {
	from, to uint64
	at       time.Time
	probe    []byte
}

const (
	maxHoles    = 64
	maxHoleSpan = 4096
	holeLife    = 2 * time.Second
)

type orderedFlow struct {
	holes        []holeRange
	id, expected uint64
	exhausted    bool
	seen         ReplayWindow
	last         time.Time
	deadline     time.Time
	pending      map[uint64]heldPacket
	numbers      sequenceHeap
	lru          *list.Element
}
type ReorderConfig struct {
	MaxFlows, MaxPackets, MaxBytes int
	Timeout, Idle                  time.Duration
	AllowLate                      bool
	// UDPTimeout, when positive and shorter than Timeout, is how long a hole in a UDP flow
	// holds back later packets. UDP cannot be repaired, so waiting the full TCP budget only
	// stalls the flow; a straggler is still delivered late (AllowLate).
	UDPTimeout time.Duration
	// FirstArrivalUDP delivers a UDP packet the moment its first copy arrives, as PRP and HSR
	// do, instead of holding it behind a hole. The skipped numbers are still accepted if they
	// show up later (AllowLate).
	FirstArrivalUDP bool
	// FirstArrivalTCP does the same for TCP. A hole in a bonded flow is almost always the
	// slower path's copy still in flight, so holding the flow behind it only adds that path's
	// delay (and its jitter) to every segment; TCP tolerates the brief reordering, and the
	// skipped segment is still delivered when it lands.
	FirstArrivalTCP bool
}

func DefaultReorderConfig() ReorderConfig {
	return ReorderConfig{1024, 2048, 4 * 1024 * 1024, 30 * time.Millisecond, 120 * time.Second, true, 0, true, true}
}

type ReorderStats struct {
	Delivered, Duplicates, Late, Gaps, Skipped, DeadlineFlushes, CapacityFlushes uint64
	// Protocol split (IPv4 protocol of the packet after the hole) for diagnosing loss.
	SkippedTCP, SkippedUDP, LateTCP, LateUDP uint64
	// Lost is Skipped minus the skipped packets that arrived afterwards: packets that
	// never came. Computed in Stats.
	Lost, LostTCP, LostUDP uint64
	// How long a hole waits before it is declared lost, as currently adapted to the
	// paths' RTT difference (milliseconds).
	TimeoutMS, UDPTimeoutMS                                       float64
	EvictedFlows, ExpiredFlows, DroppedPackets, DroppedBytes      uint64
	BufferedPackets, BufferedBytes, Flows, PeakPackets, PeakBytes int
}

// Reorder owns independent flow sequences. The server actor serializes calls.
// Only buffered payloads are copied; delivered payloads retain caller ownership.
type Reorder struct {
	config  ReorderConfig
	flows   map[uint64]*orderedFlow
	lru     list.List
	nextDue time.Time
	stats   ReorderStats
}

func NewReorder(config ReorderConfig) (*Reorder, error) {
	if config.MaxFlows < 1 || config.MaxPackets < 1 || config.MaxBytes < 1 || config.Timeout < 0 || config.Idle <= 0 {
		return nil, errors.New("invalid reorder bounds")
	}
	return &Reorder{config: config, flows: make(map[uint64]*orderedFlow)}, nil
}
func (r *Reorder) Stats() ReorderStats {
	result := r.stats
	result.Flows = len(r.flows)
	result.TimeoutMS = r.config.Timeout.Seconds() * 1000
	result.UDPTimeoutMS = r.config.UDPTimeout.Seconds() * 1000
	sub := func(a, b uint64) uint64 {
		if b >= a {
			return 0
		}
		return a - b
	}
	result.LostTCP, result.LostUDP = sub(result.SkippedTCP, result.LateTCP), sub(result.SkippedUDP, result.LateUDP)
	result.Lost = sub(result.Skipped, result.Late)
	return result
}
func (r *Reorder) remove(f *orderedFlow, expired bool) {
	for _, p := range f.pending {
		r.stats.BufferedBytes -= len(p.payload)
		r.stats.DroppedBytes += uint64(len(p.payload))
	}
	r.stats.BufferedPackets -= len(f.pending)
	r.stats.DroppedPackets += uint64(len(f.pending))
	if expired {
		r.stats.ExpiredFlows++
	} else {
		r.stats.EvictedFlows++
	}
	delete(r.flows, f.id)
	r.lru.Remove(f.lru)
}
func (r *Reorder) expire(now time.Time) {
	for r.lru.Len() > 0 {
		f := r.lru.Front().Value.(*orderedFlow)
		if now.Sub(f.last) < r.config.Idle {
			break
		}
		r.remove(f, true)
	}
}
func (r *Reorder) deadline(f *orderedFlow) {
	f.deadline = time.Time{}
	for _, p := range f.pending {
		timeout := r.config.Timeout
		if u := r.config.UDPTimeout; u > 0 && u < timeout && ipProto(p.payload) == 17 {
			timeout = u
		}
		due := p.at.Add(timeout)
		if f.deadline.IsZero() || due.Before(f.deadline) {
			f.deadline = due
		}
	}
	if !f.deadline.IsZero() && (r.nextDue.IsZero() || f.deadline.Before(r.nextDue)) {
		r.nextDue = f.deadline
	}
}
func (r *Reorder) advance(f *orderedFlow, number uint64) {
	if number == math.MaxUint64 {
		f.exhausted = true
	} else {
		f.expected = number + 1
	}
}
func (r *Reorder) drain(f *orderedFlow, out *[][]byte) {
	for !f.exhausted && len(f.numbers) > 0 && f.numbers[0] == f.expected {
		number := heap.Pop(&f.numbers).(uint64)
		p := f.pending[number]
		delete(f.pending, number)
		r.stats.BufferedPackets--
		r.stats.BufferedBytes -= len(p.payload)
		r.stats.Delivered++
		*out = append(*out, p.payload)
		r.advance(f, number)
	}
	r.deadline(f)
}
func ipProto(p []byte) byte {
	if len(p) >= 20 && p[0]>>4 == 4 {
		return p[9]
	}
	return 0
}
func (r *Reorder) gap(f *orderedFlow, number uint64, after []byte) {
	if number <= f.expected {
		return
	}
	r.stats.Gaps++
	gap := number - f.expected
	switch ipProto(after) {
	case 6:
		r.stats.SkippedTCP += gap
	case 17:
		r.stats.SkippedUDP += gap
	}
	if math.MaxUint64-r.stats.Skipped < gap {
		r.stats.Skipped = math.MaxUint64
	} else {
		r.stats.Skipped += gap
	}
}
func (r *Reorder) flush(f *orderedFlow, out *[][]byte, capacity bool) {
	r.gap(f, f.numbers[0], f.pending[f.numbers[0]].payload)
	f.expected = f.numbers[0]
	if capacity {
		r.stats.CapacityFlushes++
	} else {
		r.stats.DeadlineFlushes++
	}
	r.drain(f, out)
}
func (r *Reorder) due(now time.Time, out *[][]byte) {
	if r.nextDue.IsZero() || now.Before(r.nextDue) {
		return
	}
	r.nextDue = time.Time{}
	for _, f := range r.flows {
		for !f.deadline.IsZero() && !now.Before(f.deadline) {
			r.flush(f, out, false)
		}
		if !f.deadline.IsZero() && (r.nextDue.IsZero() || f.deadline.Before(r.nextDue)) {
			r.nextDue = f.deadline
		}
	}
}
func (r *Reorder) Push(id, number uint64, payload []byte, now time.Time) [][]byte {
	r.expire(now)
	f := r.flows[id]
	if f == nil {
		if len(r.flows) >= r.config.MaxFlows {
			r.remove(r.lru.Front().Value.(*orderedFlow), false)
		}
		f = &orderedFlow{id: id, pending: make(map[uint64]heldPacket), seen: ReplayWindow{width: flowReplayWidth}}
		f.lru = r.lru.PushBack(f)
		r.flows[id] = f
	}
	f.last = now
	r.lru.MoveToBack(f.lru)
	var out [][]byte
	if !f.seen.Accept(number) {
		r.stats.Duplicates++
		r.due(now, &out)
		return out
	}
	if f.exhausted || number < f.expected {
		if r.config.AllowLate {
			out = append(out, payload)
			r.stats.Delivered++
			r.stats.Late++
			switch ipProto(payload) {
			case 6:
				r.stats.LateTCP++
			case 17:
				r.stats.LateUDP++
			}
		} else {
			r.stats.Duplicates++
		}
	} else if number == f.expected {
		out = append(out, payload)
		r.stats.Delivered++
		r.advance(f, number)
		r.drain(f, &out)
	} else if r.config.Timeout == 0 || len(payload) > r.config.MaxBytes || (r.config.FirstArrivalUDP && ipProto(payload) == 17) || (r.config.FirstArrivalTCP && ipProto(payload) == 6) {
		for len(f.numbers) > 0 && f.numbers[0] < number {
			r.flush(f, &out, true)
		}
		if number > f.expected && number-f.expected <= maxHoleSpan && ipProto(payload) == 6 {
			if len(f.holes) >= maxHoles {
				f.holes = f.holes[1:]
			}
			f.holes = append(f.holes, holeRange{f.expected, number, now, append([]byte(nil), payload...)})
		}
		r.gap(f, number, payload)
		r.advance(f, number)
		out = append(out, payload)
		r.stats.Delivered++
		r.drain(f, &out)
	} else {
		for r.stats.BufferedPackets >= r.config.MaxPackets || r.stats.BufferedBytes+len(payload) > r.config.MaxBytes {
			var oldest *orderedFlow
			for e := r.lru.Front(); e != nil; e = e.Next() {
				candidate := e.Value.(*orderedFlow)
				if !candidate.deadline.IsZero() && (oldest == nil || candidate.deadline.Before(oldest.deadline)) {
					oldest = candidate
				}
			}
			if oldest == f && number < f.numbers[0] {
				r.gap(f, number, payload)
				r.advance(f, number)
				out = append(out, payload)
				r.stats.Delivered++
				r.stats.CapacityFlushes++
				r.drain(f, &out)
				r.due(now, &out)
				return out
			}
			r.flush(oldest, &out, true)
		}
		if number == f.expected {
			out = append(out, payload)
			r.stats.Delivered++
			r.advance(f, number)
			r.drain(f, &out)
		} else {
			f.pending[number] = heldPacket{append([]byte(nil), payload...), now}
			heap.Push(&f.numbers, number)
			r.stats.BufferedPackets++
			r.stats.BufferedBytes += len(payload)
			if r.stats.BufferedPackets > r.stats.PeakPackets {
				r.stats.PeakPackets = r.stats.BufferedPackets
			}
			if r.stats.BufferedBytes > r.stats.PeakBytes {
				r.stats.PeakBytes = r.stats.BufferedBytes
			}
			r.deadline(f)
		}
	}
	r.due(now, &out)
	return out
}
func (r *Reorder) Poll(now time.Time) [][]byte {
	r.expire(now)
	var out [][]byte
	r.due(now, &out)
	return out
}

type MissingPacket struct{ Flow, Number uint64 }

func (r *Reorder) Missing(now time.Time, delay time.Duration, limit int, predicate func([]byte) bool) []MissingPacket {
	var out []MissingPacket
	if limit <= 0 {
		return out
	}
	for e := r.lru.Front(); e != nil && len(out) < limit; e = e.Next() {
		f := e.Value.(*orderedFlow)
		kept := f.holes[:0]
		for _, h := range f.holes {
			if now.Sub(h.at) > holeLife {
				continue
			}
			kept = append(kept, h)
			if now.Before(h.at.Add(delay)) || (predicate != nil && !predicate(h.probe)) {
				continue
			}
			for n := h.from; n < h.to && len(out) < limit; n++ {
				if f.seen.Check(n) == ReplayNew {
					out = append(out, MissingPacket{f.id, n})
				}
			}
		}
		f.holes = kept
		if len(f.numbers) == 0 || now.Before(f.deadline.Add(delay-r.config.Timeout)) || (predicate != nil && !predicate(f.pending[f.numbers[0]].payload)) {
			continue
		}
		for n := f.expected; n < f.numbers[0] && len(out) < limit; n++ {
			out = append(out, MissingPacket{f.id, n})
		}
	}
	return out
}
