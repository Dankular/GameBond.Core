package bond

import (
	"crypto/sha256"
	"time"
)

const sessionStateVersion = 1

// SessionFailoverState is the packet numbering and recovery state copied from
// an active GameBond session to a warmed standby. It does not contain keys or
// path-specific measurements. The destination must already have completed a
// handshake with this same client session.
type SessionFailoverState struct {
	Version        uint8
	Session        [16]byte
	KeyFingerprint [32]byte
	ClientIP       string
	DeviceIPs      []string
	MTU            int
	L2             bool
	L2FrameMTU     int
	CapturedAt     time.Time
	Revision       uint64
	Sender         SenderState
	Reorder        ReorderState
	Stats          SessionStats
}

// SnapshotFailoverState returns a deep copy of the active session's sender
// repair cache and receiver reorder state. The session actor must be quiesced
// for the duration of the call.
func (s *Session) SnapshotFailoverState(now time.Time, revision uint64) (SessionFailoverState, error) {
	if s == nil || s.Receiver == nil || s.Receiver.codec == nil || s.Sender == nil || s.Receiver.reorder == nil {
		return SessionFailoverState{}, ErrRecoveryState
	}
	if revision == 0 {
		return SessionFailoverState{}, ErrRecoveryState
	}
	state := SessionFailoverState{
		Version:        sessionStateVersion,
		Session:        s.Receiver.codec.Session,
		KeyFingerprint: sha256.Sum256(s.Receiver.codec.key[:]),
		ClientIP:       s.options.ClientIP.String(),
		MTU:            s.options.MTU,
		L2:             s.options.L2,
		L2FrameMTU:     s.options.L2FrameMTU,
		CapturedAt:     now,
		Revision:       revision,
		Sender:         s.Sender.SnapshotState(),
		Reorder:        s.Receiver.reorder.SnapshotState(),
		Stats:          s.stats,
	}
	state.DeviceIPs = make([]string, len(s.options.DeviceIPs))
	for i, ip := range s.options.DeviceIPs {
		state.DeviceIPs[i] = ip.String()
	}
	return state, nil
}

// RestoreFailoverState installs compatible packet recovery state on a warmed
// standby session. Crypto sequence/replay state and the standby's own paths are
// retained; its completed handshake provides the peer identity for the restored
// sender state.
func (s *Session) RestoreFailoverState(state SessionFailoverState) error {
	if s == nil || s.Receiver == nil || s.Receiver.codec == nil || s.Sender == nil ||
		state.Version != sessionStateVersion || state.Session != s.Receiver.codec.Session ||
		state.KeyFingerprint != sha256.Sum256(s.Receiver.codec.key[:]) ||
		state.ClientIP != s.options.ClientIP.String() || state.MTU != s.options.MTU ||
		state.L2 != s.options.L2 || state.L2FrameMTU != s.options.L2FrameMTU ||
		len(state.DeviceIPs) != len(s.options.DeviceIPs) || state.Revision == 0 ||
		state.CapturedAt.IsZero() ||
		!s.Receiver.handshake.hasPeer {
		return ErrRecoveryState
	}
	for i, ip := range s.options.DeviceIPs {
		if state.DeviceIPs[i] != ip.String() {
			return ErrRecoveryState
		}
	}
	if s.Receiver.reorder == nil || !compatibleReorderConfig(state.Reorder.Config, s.Receiver.reorder.config) {
		return ErrRecoveryState
	}
	state = state.forLocalClock(time.Now())
	reorder, err := NewReorder(state.Reorder.Config)
	if err != nil {
		return ErrRecoveryState
	}
	if err := reorder.RestoreState(state.Reorder); err != nil {
		return err
	}
	if err := s.Sender.RestoreReplicatedState(state.Sender); err != nil {
		return err
	}
	s.Receiver.reorder = reorder
	s.peer, s.hasPeer = s.Receiver.handshake.peer, true
	s.stats = state.Stats
	return nil
}

// forLocalClock preserves each timer's age while replacing the source host's
// wall-clock basis with the destination's current clock.
func (state SessionFailoverState) forLocalClock(now time.Time) SessionFailoverState {
	shift := func(value time.Time) time.Time {
		if value.IsZero() {
			return time.Time{}
		}
		return now.Add(value.Sub(state.CapturedAt))
	}
	state.Sender.Flows = append([]SendFlowState(nil), state.Sender.Flows...)
	for i := range state.Sender.Flows {
		state.Sender.Flows[i].Last = shift(state.Sender.Flows[i].Last)
	}
	state.Sender.Repairs = append([]RepairEntryState(nil), state.Sender.Repairs...)
	for i := range state.Sender.Repairs {
		state.Sender.Repairs[i].At = shift(state.Sender.Repairs[i].At)
	}
	state.Reorder.Flows = append([]ReorderFlowState(nil), state.Reorder.Flows...)
	for i := range state.Reorder.Flows {
		flow := &state.Reorder.Flows[i]
		flow.Last, flow.Deadline = shift(flow.Last), shift(flow.Deadline)
		flow.Pending = append([]ReorderPendingState(nil), flow.Pending...)
		for j := range flow.Pending {
			flow.Pending[j].At = shift(flow.Pending[j].At)
		}
		flow.Holes = append([]ReorderHoleState(nil), flow.Holes...)
		for j := range flow.Holes {
			flow.Holes[j].At = shift(flow.Holes[j].At)
		}
	}
	return state
}

// PacketStats returns the actor-owned packet counters without building the
// full diagnostic snapshot.
func (s *Session) PacketStats() SessionStats {
	if s == nil {
		return SessionStats{}
	}
	return s.stats
}

// ActivateFailoverState starts cached packet replay after this session, which
// has been receiving state as a standby, receives real client traffic.
func (s *Session) ActivateFailoverState() {
	if s != nil && s.Sender != nil {
		s.Sender.QueueCachedRepairs()
	}
}

// compatibleReorderConfig permits adaptive hole timers to differ between the
// active and warmed standby while requiring the memory bounds and delivery
// semantics to remain identical.
func compatibleReorderConfig(source, destination ReorderConfig) bool {
	return source.MaxFlows == destination.MaxFlows &&
		source.MaxPackets == destination.MaxPackets &&
		source.MaxBytes == destination.MaxBytes &&
		source.Idle == destination.Idle &&
		source.AllowLate == destination.AllowLate &&
		source.FirstArrivalTCP == destination.FirstArrivalTCP &&
		source.FirstArrivalUDP == destination.FirstArrivalUDP &&
		source.Timeout >= 0 && source.Timeout <= 250*time.Millisecond &&
		source.UDPTimeout >= 0 && source.UDPTimeout <= 250*time.Millisecond
}
