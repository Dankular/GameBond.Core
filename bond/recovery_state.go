package bond

import (
	"container/heap"
	"errors"
	"sort"
	"time"
)

const recoveryStateVersion = 1

// ErrRecoveryState reports an invalid or incompatible recovery-state snapshot.
var ErrRecoveryState = errors.New("invalid GameBond recovery state")

// ReplayWindowState is a portable copy of a bounded packet duplicate window.
type ReplayWindowState struct {
	Initialized bool
	Highest     uint64
	Width       uint64
	Bits        []uint64
}

// SnapshotState copies a replay window. Callers must quiesce its owner while
// capturing or restoring state.
func (w *ReplayWindow) SnapshotState() ReplayWindowState {
	state := ReplayWindowState{Initialized: w.initialized, Highest: w.highest, Width: w.width}
	state.Bits = append([]uint64(nil), w.bits...)
	return state
}

// RestoreState validates and installs a replay window snapshot.
func (w *ReplayWindow) RestoreState(state ReplayWindowState) error {
	size := state.Width
	if size == 0 {
		size = replayWidth
	}
	if size < 64 || size > replayWidth || size%64 != 0 {
		return ErrRecoveryState
	}
	if state.Initialized {
		if uint64(len(state.Bits)) != size/64 {
			return ErrRecoveryState
		}
	} else if state.Highest != 0 || len(state.Bits) != 0 {
		return ErrRecoveryState
	}
	w.initialized = state.Initialized
	w.highest = state.Highest
	w.width = state.Width
	w.bits = append(w.bits[:0], state.Bits...)
	return nil
}

// ReorderPendingState is one held packet in an ordered flow.
type ReorderPendingState struct {
	Number  uint64
	Payload []byte
	At      time.Time
}

// ReorderHoleState records a skipped sequence range that may still be repaired.
type ReorderHoleState struct {
	From, To uint64
	At       time.Time
	Probe    []byte
}

// ReorderFlowState is the transferable state for one inner packet flow.
type ReorderFlowState struct {
	ID        uint64
	Expected  uint64
	Exhausted bool
	Seen      ReplayWindowState
	Last      time.Time
	Deadline  time.Time
	Pending   []ReorderPendingState
	Holes     []ReorderHoleState
}

// ReorderState is a portable snapshot of a Reorder receiver, including held
// L2 frames and the flow-level duplicate windows. The owner must be quiesced
// while this state is captured or restored.
type ReorderState struct {
	Version uint8
	Config  ReorderConfig
	Stats   ReorderStats
	Flows   []ReorderFlowState
}

// SnapshotState returns a deep copy in deterministic flow and packet order.
func (r *Reorder) SnapshotState() ReorderState {
	state := ReorderState{Version: recoveryStateVersion, Config: r.config, Stats: r.stats}
	state.Flows = make([]ReorderFlowState, 0, len(r.flows))
	for e := r.lru.Front(); e != nil; e = e.Next() {
		f := e.Value.(*orderedFlow)
		flow := ReorderFlowState{
			ID: f.id, Expected: f.expected, Exhausted: f.exhausted,
			Seen: f.seen.SnapshotState(), Last: f.last, Deadline: f.deadline,
			Holes: make([]ReorderHoleState, len(f.holes)),
		}
		for i, h := range f.holes {
			flow.Holes[i] = ReorderHoleState{From: h.from, To: h.to, At: h.at, Probe: append([]byte(nil), h.probe...)}
		}
		flow.Pending = make([]ReorderPendingState, 0, len(f.pending))
		for number, packet := range f.pending {
			flow.Pending = append(flow.Pending, ReorderPendingState{Number: number, Payload: append([]byte(nil), packet.payload...), At: packet.at})
		}
		sort.Slice(flow.Pending, func(i, j int) bool { return flow.Pending[i].Number < flow.Pending[j].Number })
		state.Flows = append(state.Flows, flow)
	}
	return state
}

// SnapshotRecoveryState returns the receiver's flow reorder state. The caller
// must quiesce the receiver while the snapshot is captured.
func (r *Receiver) SnapshotRecoveryState() ReorderState {
	if r == nil || r.reorder == nil {
		return ReorderState{}
	}
	return r.reorder.SnapshotState()
}

// RestoreRecoveryState replaces the receiver's flow reorder state while
// retaining the destination's path, handshake, and outer-frame replay state.
func (r *Receiver) RestoreRecoveryState(state ReorderState) error {
	if r == nil || r.reorder == nil || !compatibleReorderConfig(state.Config, r.reorder.config) {
		return ErrRecoveryState
	}
	reorder, err := NewReorder(state.Config)
	if err != nil {
		return ErrRecoveryState
	}
	if err := reorder.RestoreState(state); err != nil {
		return err
	}
	r.reorder = reorder
	return nil
}

// RestoreState validates a snapshot and replaces this reorder receiver's
// state. The destination's configuration must match the snapshot.
func (r *Reorder) RestoreState(state ReorderState) error {
	if r == nil || state.Version != recoveryStateVersion || state.Config != r.config || len(state.Flows) > r.config.MaxFlows {
		return ErrRecoveryState
	}
	flows := make(map[uint64]*orderedFlow, len(state.Flows))
	var packets, payloadBytes int
	for _, saved := range state.Flows {
		if _, exists := flows[saved.ID]; exists || len(saved.Holes) > maxHoles ||
			len(saved.Pending) > r.config.MaxPackets-packets {
			return ErrRecoveryState
		}
		flow := &orderedFlow{
			id: saved.ID, expected: saved.Expected, exhausted: saved.Exhausted,
			last: saved.Last, deadline: saved.Deadline,
			pending: make(map[uint64]heldPacket, len(saved.Pending)),
			holes:   make([]holeRange, len(saved.Holes)),
		}
		if err := flow.seen.RestoreState(saved.Seen); err != nil || saved.Seen.Width != flowReplayWidth {
			return ErrRecoveryState
		}
		for i, h := range saved.Holes {
			if h.From > h.To || h.To-h.From > maxHoleSpan || len(h.Probe) > 2048 {
				return ErrRecoveryState
			}
			flow.holes[i] = holeRange{from: h.From, to: h.To, at: h.At, probe: append([]byte(nil), h.Probe...)}
		}
		for _, packet := range saved.Pending {
			if _, exists := flow.pending[packet.Number]; exists || len(packet.Payload) > r.config.MaxBytes-payloadBytes {
				return ErrRecoveryState
			}
			flow.pending[packet.Number] = heldPacket{payload: append([]byte(nil), packet.Payload...), at: packet.At}
			flow.numbers = append(flow.numbers, packet.Number)
			packets++
			payloadBytes += len(packet.Payload)
		}
		heap.Init(&flow.numbers)
		flows[saved.ID] = flow
	}
	if packets > r.config.MaxPackets || payloadBytes > r.config.MaxBytes ||
		state.Stats.BufferedPackets != packets || state.Stats.BufferedBytes != payloadBytes {
		return ErrRecoveryState
	}

	// SnapshotState stores flows oldest-first in LRU order. Recreate that order
	// and recalculate the next timer from the saved deadlines.
	r.flows = flows
	r.lru.Init()
	r.nextDue = time.Time{}
	r.stats = state.Stats
	for _, saved := range state.Flows {
		flow := flows[saved.ID]
		flow.lru = r.lru.PushBack(flow)
		if !flow.deadline.IsZero() && (r.nextDue.IsZero() || flow.deadline.Before(r.nextDue)) {
			r.nextDue = flow.deadline
		}
	}
	r.stats.Flows = len(flows)
	r.stats.BufferedPackets = packets
	r.stats.BufferedBytes = payloadBytes
	return nil
}
