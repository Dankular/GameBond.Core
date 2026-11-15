package bond

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestWindowNamesLossThatScrolledOut(t *testing.T) {
	var w sackWindow
	for s := uint64(1000); s < 1100; s++ {
		if s == 1010 || s == 1011 || s == 1050 {
			continue
		}
		w.Note(s)
	}
	if got := w.Missed(); len(got) != 0 {
		t.Fatalf("nothing has left the window yet, got %v", got)
	}
	// Jump far enough that the old window and the numbers between are all gone.
	for s := uint64(3000); s < 3010; s++ {
		w.Note(s)
	}
	got := w.Missed()
	has := func(seq uint64) bool {
		for _, m := range got {
			if seq >= m.start && seq-m.start < uint64(m.n) {
				return true
			}
		}
		return false
	}
	for _, seq := range []uint64{1010, 1011, 1050, 1100, 2000, 3000 - sackBits + 1 - 1} {
		if !has(seq) {
			t.Fatalf("sequence %d was lost and left the window, but is not named: %v", seq, got)
		}
	}
	if has(1012) || has(1049) {
		t.Fatalf("received sequences must not be named: %v", got)
	}
	// One that turns up later is withdrawn.
	w.Note(1050)
	for _, m := range w.Missed() {
		if 1050 >= m.start && 1050-m.start < uint64(m.n) {
			t.Fatalf("1050 arrived and is still named: %v", m)
		}
	}
	// Ranges age out after a fixed number of reports.
	for i := 0; i < sackMissReports+2; i++ {
		w.Missed()
	}
	if got := w.Missed(); len(got) != 0 {
		t.Fatalf("ranges must expire, still %v", got)
	}
}

func TestMissedTrailerRoundTripsAndRejectsDamage(t *testing.T) {
	in := []missRange{{start: 7, n: 3}, {start: 1 << 40, n: 65000}}
	payload := encodeMissed(make([]byte, feedbackSackSize), in)
	out, ok := decodeMissed(payload[feedbackSackSize:])
	if !ok || len(out) != 2 || out[0].start != 7 || out[1].n != 65000 {
		t.Fatalf("round trip: %v %v", out, ok)
	}
	if _, ok := decodeMissed(payload[feedbackSackSize : len(payload)-1]); ok {
		t.Fatal("a truncated trailer was accepted")
	}
	if got, ok := decodeMissed(nil); !ok || got != nil {
		t.Fatal("no trailer is the old format and must be accepted")
	}
	if _, ok := decodeMissed([]byte{0}); ok {
		t.Fatal("a zero count with a trailer was accepted")
	}
}

func TestSackMissedMarksOnlyNamedFrames(t *testing.T) {
	b, err := NewBudget(1000, 100000)
	if err != nil {
		t.Fatal(err)
	}
	for s := uint64(1); s <= 6; s++ {
		b.Sent(s, 1000, float64(s)/100)
		b.Tag(s, MissingPacket{1, s * 10})
	}
	lost := b.SackMissed([]missRange{{start: 2, n: 2}, {start: 6, n: 1}})
	if len(lost) != 3 || lost[0] != (MissingPacket{1, 20}) || lost[1] != (MissingPacket{1, 30}) || lost[2] != (MissingPacket{1, 60}) {
		t.Fatalf("lost %v", lost)
	}
	if again := b.SackMissed([]missRange{{start: 2, n: 2}}); len(again) != 0 {
		t.Fatalf("reported twice: %v", again)
	}
}

// A frame lost long before the bitmap's window moved on is still found through the ranges, and the
// bitmap alone cannot find it.
func TestLossBeyondTheBitmapIsRepairedThroughRanges(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	frames := sendCaptured(t, f, s, a, 40)
	var onA []wireFrame
	for _, fr := range frames {
		if fr.to == a[0] {
			onA = append(onA, fr)
		}
	}
	if len(onA) < 10 {
		t.Fatalf("only %d frames on path 0", len(onA))
	}
	victim := onA[5]
	build := func(withRanges bool) []byte {
		var w sackWindow
		var high, bytes uint64
		for _, fr := range onA {
			if fr.sequence == victim.sequence {
				continue
			}
			w.Note(fr.sequence)
			bytes += uint64(fr.size)
			if fr.sequence > high {
				high = fr.sequence
			}
		}
		// The peer went on to receive a long run of later frames (a feedback gap longer than the window),
		// so the victim has scrolled out of the bitmap it reports now.
		for k := uint64(1); k <= sackBits+20; k++ {
			w.Note(high + k)
		}
		payload := make([]byte, feedbackSackSize)
		binary.BigEndian.PutUint64(payload, f.r.paths[pk(a[0])].txEpoch)
		binary.BigEndian.PutUint64(payload[8:], high)
		binary.BigEndian.PutUint64(payload[16:], bytes)
		base, bits := w.Report()
		binary.BigEndian.PutUint64(payload[28:], base)
		copy(payload[36:], bits)
		if withRanges {
			payload = encodeMissed(payload, w.Missed())
		}
		return payload
	}
	f.now = f.now.Add(200 * time.Millisecond)
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	res := f.receive(t, Feedback, build(true), a[0])
	found := false
	for _, k := range res.Lost {
		found = found || k == victim.key
	}
	if !found {
		t.Fatalf("victim %v not reported lost through ranges: %v", victim.key, res.Lost)
	}
	// Without the ranges the bitmap alone cannot name it.
	res = f.receive(t, Feedback, build(false), a[0])
	for _, k := range res.Lost {
		if k == victim.key {
			t.Fatalf("the bitmap alone named %v; the test is not exercising the range path", k)
		}
	}
}

func TestSpuriousAskIsRecognisedAndWidensTheWait(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	for _, p := range f.r.paths {
		p.hasRTT, p.rtt = true, .040
	}
	now := f.now
	key := MissingPacket{9, 1}
	ask := &askedRepair{key: key, at: now}
	s.asked[key] = ask
	// Landed 5 ms after the ask: faster than any answer could be, so the original was only late.
	s.noteArrival(key, now.Add(5*time.Millisecond))
	if st := s.Stats(); st.RepairSpurious != 1 || st.RepairAnswered != 0 {
		t.Fatalf("stats %+v", st)
	}
	// Judged once.
	s.noteArrival(key, now.Add(6*time.Millisecond))
	if st := s.Stats(); st.RepairSpurious != 1 {
		t.Fatalf("judged twice: %+v", st)
	}
	// A late arrival counts as answered and does not widen.
	key2 := MissingPacket{9, 2}
	s.asked[key2] = &askedRepair{key: key2, at: now}
	s.noteArrival(key2, now.Add(70*time.Millisecond))
	if st := s.Stats(); st.RepairAnswered != 1 {
		t.Fatalf("stats %+v", st)
	}
	for i := 0; i < 200; i++ {
		k := MissingPacket{10, uint64(i)}
		s.asked[k] = &askedRepair{key: k, at: now}
		s.noteArrival(k, now.Add(time.Millisecond))
	}
	if st := s.Stats(); st.RepairAskScale < 2.5 || st.RepairAskScale > askScaleMax {
		t.Fatalf("ask scale %v after a run of spurious asks, want it near the cap", st.RepairAskScale)
	}
	_ = a
}
