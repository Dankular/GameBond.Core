package bond

import (
	"container/list"
	"time"
)

const senderStateVersion = 2

// SendFlowState preserves a flow's GameBond packet numbering across a
// failover. Path-specific pacing, pins and partial parity groups are rebuilt
// from the promoted exit's live paths.
type SendFlowState struct {
	Key       string
	ID        uint64
	Number    uint64
	Exhausted bool
	Last      time.Time
}

// RepairEntryState is a cached inner packet that can be replayed after
// promotion. Network-path references are intentionally omitted.
type RepairEntryState struct {
	Key      MissingPacket
	Payload  []byte
	At       time.Time
	Attempts int
	Sent     int
	Lost     int
}

// SenderState is the portable packet-number and retransmission state for one
// sender. Capture and restore only while the sender actor is quiesced.
type SenderState struct {
	Version uint8
	Full    bool
	Flows   []SendFlowState
	Repairs []RepairEntryState
	Removed []MissingPacket
	Stats   SenderStats
}

// SnapshotState returns the current flow-number state and all unretired repair
// payloads, ordered oldest-first for deterministic transfer.
func (s *Sender) SnapshotState() SenderState {
	state := SenderState{Version: senderStateVersion, Full: true, Stats: s.stats}
	state.Flows = make([]SendFlowState, 0, len(s.flows))
	for e := s.lru.Front(); e != nil; e = e.Next() {
		flow := e.Value.(*sendFlow)
		state.Flows = append(state.Flows, SendFlowState{Key: flow.key, ID: flow.id, Number: flow.number, Exhausted: flow.exhausted, Last: flow.last})
	}
	state.Repairs = make([]RepairEntryState, 0, len(s.repairs))
	for e := s.repairOrder.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*repairEntry)
		state.Repairs = append(state.Repairs, RepairEntryState{
			Key: entry.key, Payload: append([]byte(nil), entry.payload...), At: entry.at,
			Attempts: entry.attempts, Sent: entry.sent, Lost: entry.lost,
		})
	}
	return state
}

// RestoreState installs flow and repair state on a newly handshaken sender.
// It binds the state to the destination's current peer and queues the cached
// payloads for bounded replay on the destination's live paths.
func (s *Sender) RestoreState(state SenderState) error {
	return s.restoreState(state, true)
}

// RestoreReplicatedState installs a shadow copy without sending its cached
// packets to the client while this sender remains a standby.
func (s *Sender) RestoreReplicatedState(state SenderState) error {
	return s.restoreState(state, false)
}

func (s *Sender) restoreState(state SenderState, queueReplay bool) error {
	if s == nil || s.r == nil || state.Version != senderStateVersion || !state.Full || len(state.Removed) != 0 || len(state.Flows) > 8192 || len(state.Repairs) > repairCacheMax ||
		!s.r.handshake.hasPeer {
		return ErrRecoveryState
	}
	flows := make(map[string]*sendFlow, len(state.Flows))
	flowOrder := make([]*sendFlow, 0, len(state.Flows))
	for _, saved := range state.Flows {
		if saved.Key == "" {
			return ErrRecoveryState
		}
		if _, exists := flows[saved.Key]; exists {
			return ErrRecoveryState
		}
		flow := &sendFlow{key: saved.Key, id: saved.ID, number: saved.Number, exhausted: saved.Exhausted, last: saved.Last}
		flows[saved.Key] = flow
		flowOrder = append(flowOrder, flow)
	}
	repairs := make(map[MissingPacket]*repairEntry, len(state.Repairs))
	repairOrder := make([]*repairEntry, 0, len(state.Repairs))
	var replayGame, replayBulk []replayItem
	for _, saved := range state.Repairs {
		if len(saved.Payload) == 0 || len(saved.Payload) > 2048 || saved.Attempts < 0 || saved.Sent < 0 || saved.Lost < 0 {
			return ErrRecoveryState
		}
		if _, exists := repairs[saved.Key]; exists {
			return ErrRecoveryState
		}
		entry := &repairEntry{
			key: saved.Key, payload: append([]byte(nil), saved.Payload...), at: saved.At,
			attempts: saved.Attempts, sent: saved.Sent, lost: saved.Lost,
		}
		repairs[saved.Key] = entry
		repairOrder = append(repairOrder, entry)
		if queueReplay {
			if repairable(entry.payload) {
				replayBulk = append(replayBulk, replayItem{saved.Key})
			} else {
				replayGame = append(replayGame, replayItem{saved.Key})
			}
		}
	}

	// Publish only after the complete snapshot has passed validation.
	s.flows = flows
	s.lru.Init()
	for _, flow := range flowOrder {
		flow.lru = s.lru.PushBack(flow)
	}
	s.repairs = repairs
	s.repairOrder.Init()
	for _, entry := range repairOrder {
		entry.order = s.repairOrder.PushBack(entry)
	}
	s.replayQueue, s.replayBulk = replayGame, replayBulk
	s.stats = state.Stats
	s.peer, s.hasPeer = s.r.handshake.peer, true
	s.parityOpen = nil
	s.deferred = nil
	s.repairRequests = make(map[MissingPacket]*list.Element)
	s.requestOrder.Init()
	s.asked = make(map[MissingPacket]*askedRepair)
	s.askedOrder.Init()
	s.tombs = nil
	s.tombOrder = nil
	s.waiters = nil
	s.waitStart = time.Time{}
	return nil
}

// ApplyReplicatedStateDelta replaces flow numbering and applies repair-cache
// changes to a shadow sender. The caller must serialize access with packet I/O.
func (s *Sender) ApplyReplicatedStateDelta(state SenderState) error {
	if s == nil || s.r == nil || !s.r.handshake.hasPeer || state.Version != senderStateVersion || state.Full ||
		len(state.Flows) > 8192 || len(state.Repairs) > repairCacheMax || len(state.Removed) > repairCacheMax {
		return ErrRecoveryState
	}
	flows := make(map[string]*sendFlow, len(state.Flows))
	flowOrder := make([]*sendFlow, 0, len(state.Flows))
	for _, saved := range state.Flows {
		if saved.Key == "" {
			return ErrRecoveryState
		}
		if _, exists := flows[saved.Key]; exists {
			return ErrRecoveryState
		}
		flow := &sendFlow{key: saved.Key, id: saved.ID, number: saved.Number, exhausted: saved.Exhausted, last: saved.Last}
		flows[saved.Key] = flow
		flowOrder = append(flowOrder, flow)
	}
	upserts := make(map[MissingPacket]RepairEntryState, len(state.Repairs))
	for _, saved := range state.Repairs {
		if len(saved.Payload) == 0 || len(saved.Payload) > 2048 || saved.Attempts < 0 || saved.Sent < 0 || saved.Lost < 0 {
			return ErrRecoveryState
		}
		if _, exists := upserts[saved.Key]; exists {
			return ErrRecoveryState
		}
		upserts[saved.Key] = saved
	}
	removed := make(map[MissingPacket]struct{}, len(state.Removed))
	for _, key := range state.Removed {
		if _, exists := removed[key]; exists {
			return ErrRecoveryState
		}
		if _, alsoUpdated := upserts[key]; alsoUpdated {
			return ErrRecoveryState
		}
		if s.repairs[key] == nil {
			return ErrRecoveryState
		}
		removed[key] = struct{}{}
	}
	futureRepairs := len(s.repairs) - len(removed)
	for key := range upserts {
		if s.repairs[key] == nil {
			futureRepairs++
		}
	}
	if futureRepairs > repairCacheMax {
		return ErrRecoveryState
	}

	for key := range removed {
		entry := s.repairs[key]
		delete(s.repairs, key)
		s.repairOrder.Remove(entry.order)
	}
	for _, saved := range state.Repairs {
		if entry := s.repairs[saved.Key]; entry != nil {
			entry.payload = append(entry.payload[:0], saved.Payload...)
			entry.at, entry.attempts, entry.sent, entry.lost = saved.At, saved.Attempts, saved.Sent, saved.Lost
			continue
		}
		entry := &repairEntry{key: saved.Key, payload: append([]byte(nil), saved.Payload...), at: saved.At,
			attempts: saved.Attempts, sent: saved.Sent, lost: saved.Lost}
		entry.order = s.repairOrder.PushBack(entry)
		s.repairs[saved.Key] = entry
	}
	s.flows = flows
	s.lru.Init()
	for _, flow := range flowOrder {
		flow.lru = s.lru.PushBack(flow)
	}
	s.stats = state.Stats
	return nil
}

// QueueCachedRepairs schedules the mirrored repair cache for bounded replay
// after a replicated standby becomes active.
func (s *Sender) QueueCachedRepairs() {
	if s == nil {
		return
	}
	s.replayQueue = s.replayQueue[:0]
	s.replayBulk = s.replayBulk[:0]
	for e := s.repairOrder.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*repairEntry)
		if repairable(entry.payload) {
			s.replayBulk = append(s.replayBulk, replayItem{entry.key})
		} else {
			s.replayQueue = append(s.replayQueue, replayItem{entry.key})
		}
	}
}
