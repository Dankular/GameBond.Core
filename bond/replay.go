package bond

// replayWidth is the elimination (history) window in sequence numbers. 802.1CB calls this
// the history length and IEC 62439-3 sizes the equivalent memory in time (400 ms). The
// sequence is shared by every path and every copy, so at 1 Gbps with each packet duplicated
// the sequence advances about 180k per second; 1<<17 keeps over 700 ms, well past the
// 400 ms PRP forget time, and a late second copy is still recognised instead of dropped.
const replayWidth = 1 << 17

// flowReplayWidth is the per-flow packet-number window used by Reorder.
const flowReplayWidth = 8192

// maxForwardJump bounds how far one packet may move the window. The sequence is one
// global counter shared by every path, so a jump of this size is a peer restart (which
// goes through the handshake and resets the window) or a fault, never normal loss. Taking
// it would mark every in-flight packet as too old.
const maxForwardJump = 1 << 24

// ReplayVerdict is the outcome of checking one sequence number.
type ReplayVerdict int

const (
	ReplayNew       ReplayVerdict = iota // not seen before and inside the window
	ReplayDuplicate                      // already accepted
	ReplayTooOld                         // behind the window, so it cannot be checked
	ReplayTooFar                         // ahead of the window by more than maxForwardJump
)

// ReplayWindow accepts unique out-of-order packets within the GB03 window. It is a ring
// indexed by sequence modulo the width, so advancing costs O(distance) bit clears
// (amortised O(1) per packet) rather than shifting the whole bitmap.
// Its owner serializes access together with the peer's authenticated state.
type ReplayWindow struct {
	highest     uint64
	initialized bool
	width       uint64 // zero means replayWidth
	bits        []uint64
}

func (w *ReplayWindow) size() uint64 {
	if w.width == 0 {
		return replayWidth
	}
	return w.width
}

func (w *ReplayWindow) ring() {
	if w.bits == nil {
		w.bits = make([]uint64, w.size()/64)
	}
}

func (w *ReplayWindow) get(sequence uint64) bool {
	pos := sequence % w.size()
	return w.bits[pos/64]&(uint64(1)<<(pos%64)) != 0
}

func (w *ReplayWindow) set(sequence uint64, on bool) {
	pos := sequence % w.size()
	if on {
		w.bits[pos/64] |= uint64(1) << (pos % 64)
	} else {
		w.bits[pos/64] &^= uint64(1) << (pos % 64)
	}
}

// Check classifies a sequence number without changing the window.
func (w *ReplayWindow) Check(sequence uint64) ReplayVerdict {
	if !w.initialized || sequence > w.highest {
		if w.initialized && sequence-w.highest > maxForwardJump {
			return ReplayTooFar
		}
		return ReplayNew
	}
	if w.highest-sequence >= w.size() {
		return ReplayTooOld
	}
	if w.get(sequence) {
		return ReplayDuplicate
	}
	return ReplayNew
}

// Accept records the sequence number and reports whether it was new. Packets that are
// duplicates, behind the window or absurdly far ahead are refused without any change.
func (w *ReplayWindow) Accept(sequence uint64) bool {
	if w.Check(sequence) != ReplayNew {
		return false
	}
	w.ring()
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.set(sequence, true)
		return true
	}
	if sequence > w.highest {
		if sequence-w.highest >= w.size() {
			clear(w.bits)
		} else {
			for s := w.highest + 1; s <= sequence; s++ {
				w.set(s, false)
			}
		}
		w.highest = sequence
	}
	w.set(sequence, true)
	return true
}
