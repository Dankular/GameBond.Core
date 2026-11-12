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

// A frame that arrives ahead of a missing one must be reported at once, inside the same Receive,
// not at the next feedback timer: the sender cannot begin repairing until it hears.
func TestGapIsReportedImmediately(t *testing.T) {
	f := newReceiverFixture(t)
	f.connect(t, f.endpoint)
	f.receive(t, Probe, probe(1), f.endpoint)
	feedbacks := func(out ReceiveResult) (n int) {
		for _, d := range out.Send {
			if p, err := f.c.Decode(d.Frame); err == nil && p.Header.Kind == Feedback {
				n++
			}
		}
		return n
	}
	drop := map[int]bool{3: true, 10: true, 13: true}
	send := func(i int) ReceiveResult {
		frame, err := f.c.Encode(Striped, stripe(1, uint64(i), 1, []byte{byte(i)}))
		if err != nil {
			t.Fatal(err)
		}
		if drop[i] {
			return ReceiveResult{} // encoded, then lost on the wire
		}
		out, err := f.r.Receive(frame, f.endpoint, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for i := 0; i < 3; i++ {
		send(i)
	}
	// The regular timer has just run, so without the gap rule nothing would go out for 20 ms.
	if _, err := f.r.Tick(f.now); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(11 * time.Millisecond) // past the gap rate limit, still inside the 20 ms timer
	send(3)
	if n := feedbacks(send(4)); n != 1 {
		t.Fatalf("%d feedback frames on the frame that revealed the gap, want 1", n)
	}
	// In-order frames behind it reveal nothing new and must not each cost a feedback frame.
	for i := 5; i < 9; i++ {
		if n := feedbacks(send(i)); n != 0 {
			t.Fatalf("frame %d sent %d feedback frames with no new gap", i, n)
		}
	}
	// A second gap inside the rate-limit window waits for the timer; one after it is reported at once.
	send(9)
	send(10)
	if n := feedbacks(send(11)); n != 0 {
		t.Fatalf("gap inside the %v rate limit sent %d feedback frames", gapFeedbackGap, n)
	}
	f.now = f.now.Add(gapFeedbackGap + time.Millisecond)
	send(12)
	send(13)
	if n := feedbacks(send(14)); n != 1 {
		t.Fatalf("gap after the rate limit sent %d feedback frames, want 1", n)
	}
	if got := f.r.stats.GapFeedback; got != 2 {
		t.Fatalf("GapFeedback = %d, want 2", got)
	}
}
