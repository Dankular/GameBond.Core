package bond

import (
	"encoding/binary"
	"testing"
	"time"
)

// Production runs with always-duplicate (lossTiered off) and failover on. A UDP packet
// whose original and copy are both lost on the wire must be sent again: the peer cannot
// ask for UDP holes, so the sender's selective acknowledgement is the only repair.
func TestUDPPacketLostOnBothPathsIsResent(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	s.failover = true
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
	for i := 0; i < 24; i++ {
		now := f.now.Add(time.Duration(i) * 10 * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now
		}
		if _, _, err := s.Bulk(udpOfSize(800), "udpflow", now, writer); err != nil {
			t.Fatal(err)
		}
	}
	var victim MissingPacket
	drop := map[uint64]bool{}
	n := 0
	for _, fr := range frames {
		if fr.to == a[0] {
			n++
			if n == 3 {
				victim = fr.key
			}
		}
	}
	for _, fr := range frames {
		if fr.key == victim {
			drop[fr.sequence] = true
		}
	}
	if len(drop) != 2 {
		t.Fatalf("victim %v has %d frames on the wire, want an original and a copy", victim, len(drop))
	}
	f.now = f.now.Add(400 * time.Millisecond)
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	for _, k := range a {
		res := f.receive(t, Feedback, feedbackFor(f, k, frames, drop), k)
		s.Controls(res, f.now, func(Datagram) error { return nil })
	}
	st := s.Stats()
	if st.SackResent != 1 {
		t.Fatalf("both frames of %v lost but resend not queued: %+v", victim, st)
	}
	var resent []MissingPacket
	if err := s.Maintenance(f.now, func(d Datagram) error {
		if pkt, err := f.c.Decode(d.Frame); err == nil && pkt.Header.Kind == Striped {
			resent = append(resent, MissingPacket{binary.BigEndian.Uint64(pkt.Payload), binary.BigEndian.Uint64(pkt.Payload[8:])})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(resent) != 1 || resent[0] != victim {
		t.Fatalf("resent %v, want %v", resent, victim)
	}
}
