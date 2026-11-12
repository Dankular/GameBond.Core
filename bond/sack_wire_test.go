package bond

import (
	"encoding/binary"
	"testing"
	"time"
)

// The receiver's feedback must carry the bitmap of frames it received on the path, or
// the sender never learns which frame was lost and falls back to its slow tail timer.
func TestReceiverFeedbackCarriesTheSackBitmap(t *testing.T) {
	f := newReceiverFixture(t)
	f.connect(t, f.endpoint)
	f.receive(t, Probe, probe(1), f.endpoint)
	var seqs []uint64
	for i := 0; i < 8; i++ {
		payload := stripe(1, uint64(i), 1, []byte{byte(i)})
		frame, err := f.c.Encode(Striped, payload)
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, binary.BigEndian.Uint64(frame[37:]))
		if i == 3 {
			continue // this frame never reaches the receiver
		}
		if _, err := f.r.Receive(frame, f.endpoint, f.now); err != nil {
			t.Fatal(err)
		}
	}
	out, err := f.r.Tick(f.now.Add(21 * time.Millisecond))
	if err != nil || len(out.Send) != 1 {
		t.Fatalf("feedback frames %d, err %v", len(out.Send), err)
	}
	var got []byte
	for _, d := range out.Send {
		if p, err := f.c.Decode(d.Frame); err == nil && p.Header.Kind == Feedback {
			got = p.Payload
		}
	}
	if len(got) != feedbackSackSize {
		t.Fatalf("feedback payload is %d bytes, want %d (with the bitmap)", len(got), feedbackSackSize)
	}
	base := binary.BigEndian.Uint64(got[28:])
	bits := got[36:]
	has := func(seq uint64) bool {
		if seq < base {
			return false
		}
		i := seq - base
		return bits[i/8]&(1<<(i%8)) != 0
	}
	for i, seq := range seqs {
		if want := i != 3; has(seq) != want {
			t.Fatalf("sequence %d (frame %d): bitmap says %v, want %v", seq, i, has(seq), want)
		}
	}
}
