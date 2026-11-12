package bond

const replayWidth = 8192

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

// ReplayWindow accepts unique out-of-order packets within the GB03 window.
// Its owner serializes access together with the peer's authenticated state.
type ReplayWindow struct {
	highest     uint64
	initialized bool
	bits        [replayWidth / 64]uint64
}

// Check classifies a sequence number without changing the window.
func (w *ReplayWindow) Check(sequence uint64) ReplayVerdict {
	if !w.initialized || sequence > w.highest {
		if w.initialized && sequence-w.highest > maxForwardJump {
			return ReplayTooFar
		}
		return ReplayNew
	}
	age := w.highest - sequence
	if age >= replayWidth {
		return ReplayTooOld
	}
	if w.bits[age/64]&(uint64(1)<<(age%64)) != 0 {
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
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.bits[0] = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= replayWidth {
			w.bits = [replayWidth / 64]uint64{}
		} else {
			words, bits := int(shift/64), uint(shift%64)
			for i := len(w.bits) - 1; i >= 0; i-- {
				var value uint64
				j := i - words
				if j >= 0 {
					value = w.bits[j] << bits
					if bits > 0 && j > 0 {
						value |= w.bits[j-1] >> (64 - bits)
					}
				}
				w.bits[i] = value
			}
		}
		w.highest = sequence
		w.bits[0] |= 1
		return true
	}
	age := w.highest - sequence
	if age >= replayWidth {
		return false
	}
	word, bit := int(age/64), uint(age%64)
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}
