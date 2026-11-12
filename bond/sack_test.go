package bond

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func bit(bits []byte, i uint64) bool { return bits[i/8]&(1<<(i%8)) != 0 }

func TestSackWindowReportsExactlyTheFramesReceived(t *testing.T) {
	var w sackWindow
	for s := uint64(100); s <= 140; s++ {
		if s == 105 || s == 106 || s == 120 {
			continue
		}
		w.Note(s)
	}
	base, bits := w.Report()
	if base != 0 {
		t.Fatalf("base %d, want 0 while the window is not yet full", base)
	}
	for s := uint64(0); s <= 140; s++ {
		want := s >= 100 && s != 105 && s != 106 && s != 120
		if bit(bits, s-base) != want {
			t.Fatalf("sequence %d reported %v, want %v", s, !want, want)
		}
	}
	// Slide far past the old frames: they leave the window and stale bits do not return.
	for s := uint64(2000); s < 2100; s++ {
		if s != 2050 {
			w.Note(s)
		}
	}
	base, bits = w.Report()
	if base != 2099-(sackBits-1) {
		t.Fatalf("base %d", base)
	}
	for s := base; s <= 2099; s++ {
		want := s >= 2000 && s != 2050
		if bit(bits, s-base) != want {
			t.Fatalf("after sliding, sequence %d reported %v, want %v", s, !want, want)
		}
	}
	w.Note(1000) // older than the window: ignored
	_, again := w.Report()
	for i := range bits {
		if bits[i] != again[i] {
			t.Fatal("a frame older than the window changed the report")
		}
	}
}

func TestBudgetSackNamesLostFramesOnceAfterThreeLaterArrivals(t *testing.T) {
	b, _ := NewBudget(10, 100)
	for s := uint64(1); s <= 8; s++ {
		b.Sent(s, 1000, float64(s)/100)
		b.Tag(s, MissingPacket{Flow: 7, Number: s * 10})
	}
	bits := make([]byte, 8)
	for _, s := range []uint64{1, 2, 4, 5, 6, 8} { // 3 and 7 are missing
		bits[s/8] |= 1 << (s % 8)
	}
	lost := b.Sack(0, bits)
	// 3 has four later arrivals (4,5,6,8); 7 has only one, so it is not yet called lost.
	if len(lost) != 1 || lost[0] != (MissingPacket{7, 30}) {
		t.Fatalf("lost %v, want only flow 7 number 30", lost)
	}
	if again := b.Sack(0, bits); len(again) != 0 {
		t.Fatalf("the same loss was reported twice: %v", again)
	}
	// Three more arrivals later and 7 is lost too.
	b.Sent(9, 1000, .09)
	b.Sent(10, 1000, .10)
	b.Sent(11, 1000, .11)
	bits = make([]byte, 8)
	for _, s := range []uint64{1, 2, 4, 5, 6, 8, 9, 10, 11} {
		bits[s/8] |= 1 << (s % 8)
	}
	if lost := b.Sack(0, bits); len(lost) != 1 || lost[0] != (MissingPacket{7, 70}) {
		t.Fatalf("lost %v, want flow 7 number 70", lost)
	}
}

// capture sends n TCP packets through the sender and returns every striped frame with
// the path it used.
type wireFrame struct {
	to       netip.AddrPort
	sequence uint64
	size     int
	key      MissingPacket
}

func sendCaptured(t *testing.T, f receiverFixture, s *Sender, a []netip.AddrPort, n int) []wireFrame {
	t.Helper()
	var frames []wireFrame
	writer := func(d Datagram) error {
		pkt, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		if pkt.Header.Kind == Striped {
			frames = append(frames, wireFrame{d.Endpoint, pkt.Header.Sequence, len(d.Frame),
				MissingPacket{binary.BigEndian.Uint64(pkt.Payload), binary.BigEndian.Uint64(pkt.Payload[8:])}})
		}
		return nil
	}
	for i := 0; i < n; i++ {
		now := f.now.Add(time.Duration(i) * 10 * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now
		}
		if _, _, err := s.Bulk(tcpPacket(string(make([]byte, 800))), "flow", now, writer); err != nil {
			t.Fatal(err)
		}
	}
	return frames
}

// feedbackFor builds the peer's feedback for one path, acknowledging every frame it
// carried except the ones in drop.
func feedbackFor(f receiverFixture, a netip.AddrPort, frames []wireFrame, drop map[uint64]bool) []byte {
	var w sackWindow
	var high, bytes uint64
	for _, fr := range frames {
		if fr.to != a || drop[fr.sequence] {
			continue
		}
		w.Note(fr.sequence)
		bytes += uint64(fr.size)
		if fr.sequence > high {
			high = fr.sequence
		}
	}
	payload := make([]byte, feedbackSackSize)
	binary.BigEndian.PutUint64(payload, f.r.paths[pk(a)].txEpoch)
	binary.BigEndian.PutUint64(payload[8:], high)
	binary.BigEndian.PutUint64(payload[16:], bytes)
	base, bits := w.Report()
	binary.BigEndian.PutUint64(payload[28:], base)
	copy(payload[36:], bits)
	return payload
}

func TestLostFrameIsResentAtOnceOnTheOtherPath(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	frames := sendCaptured(t, f, s, a, 16)
	var onA []wireFrame
	for _, fr := range frames {
		if fr.to == a[0] {
			onA = append(onA, fr)
		}
	}
	if len(onA) < 6 {
		t.Fatalf("only %d frames on path 0", len(onA))
	}
	victim := onA[1]
	f.now = f.now.Add(200 * time.Millisecond)
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	res := f.receive(t, Feedback, feedbackFor(f, a[0], frames, map[uint64]bool{victim.sequence: true}), a[0])
	if len(res.Lost) != 1 || res.Lost[0] != victim.key {
		t.Fatalf("lost %v, want %v", res.Lost, victim.key)
	}
	s.Controls(res, f.now, func(Datagram) error { return nil })
	if st := s.Stats(); st.SackLost != 1 || st.SackResent != 1 || st.SackUnrecoverable != 0 {
		t.Fatalf("stats %+v", st)
	}
	var resent []wireFrame
	writer := func(d Datagram) error {
		if pkt, err := f.c.Decode(d.Frame); err == nil && pkt.Header.Kind == Striped {
			resent = append(resent, wireFrame{d.Endpoint, pkt.Header.Sequence, len(d.Frame),
				MissingPacket{binary.BigEndian.Uint64(pkt.Payload), binary.BigEndian.Uint64(pkt.Payload[8:])}})
		}
		return nil
	}
	if err := s.Maintenance(f.now, writer); err != nil {
		t.Fatal(err)
	}
	if len(resent) != 1 || resent[0].key != victim.key {
		t.Fatalf("resent %v, want one copy of %v", resent, victim.key)
	}
	if resent[0].to != a[1] {
		t.Fatalf("resent on the path that lost it (%v)", resent[0].to)
	}
}

// With a sibling copy still unaccounted for, the loss of one copy must not trigger a
// third send; only when every copy is lost does the packet go out again.
func TestLossOfOneCopyWaitsForTheSibling(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	key := MissingPacket{Flow: 1, Number: 1}
	s.cacheRepair(key, tcpPacket("x"), f.now, f.r.paths[pk(a[0])])
	s.repairs[key].sent = 2 // original + one copy
	s.sackLoss(key, f.now)
	if st := s.Stats(); st.SackHeld != 1 || st.SackResent != 0 || len(s.repairRequests) != 0 {
		t.Fatalf("first copy lost: %+v", st)
	}
	s.sackLoss(key, f.now)
	if st := s.Stats(); st.SackResent != 1 || len(s.repairRequests) != 1 {
		t.Fatalf("both copies lost: %+v", st)
	}
	// A packet that was never cached (UDP) is counted, not resent.
	s.sackLoss(MissingPacket{Flow: 9, Number: 9}, f.now)
	if s.Stats().SackUnrecoverable != 1 {
		t.Fatal("uncached loss not counted")
	}
}

// The last packets of a burst have nothing after them for the selective
// acknowledgement to compare with; silence for longer than a round trip stands in.
func TestTailOfABurstIsResentWhenNothingAcknowledgesIt(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	frames := sendCaptured(t, f, s, a, 6)
	if len(frames) == 0 {
		t.Fatal("nothing sent")
	}
	for _, k := range a {
		f.r.paths[pk(k)].hasFeedback = true
	}
	s.tailProbe(f.now.Add(2 * time.Millisecond))
	if s.Stats().TailProbed != 0 {
		t.Fatalf("resent %d frames that were not yet overdue", s.Stats().TailProbed)
	}
	late := f.now.Add(700 * time.Millisecond)
	for _, k := range a {
		f.r.paths[pk(k)].last = late
	}
	s.tailProbe(late)
	if st := s.Stats(); st.TailProbed != uint64(len(frames)) || st.SackResent != uint64(len(frames)) {
		t.Fatalf("frames %d, stats %+v", len(frames), st)
	}
	s.tailProbe(late.Add(time.Millisecond))
	if s.Stats().TailProbed != uint64(len(frames)) {
		t.Fatal("the same silent frames were probed twice")
	}
}
