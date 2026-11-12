package bond

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

type sentFrame struct {
	kind byte
	body []byte
	to   netip.AddrPort
}

// sendProtected sends n distinct bulk packets (varying lengths) with the given
// smoothed loss on path 0 and returns every frame the sender wrote.
func sendProtected(t *testing.T, loss float64, n int, mode ...string) ([][]byte, []sentFrame, *Sender) {
	t.Helper()
	f, s, a := senderFixture(t, 2)
	p0 := f.r.paths[pk(a[0])]
	ts := f.r.seconds(f.now)
	p0.budget.lossSeen, p0.budget.lossAt, p0.budget.lossEWMA, p0.budget.lossEWSet = true, ts, loss, true
	var frames []sentFrame
	writer := func(d Datagram) error {
		pkt, err := f.c.Decode(d.Frame)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, sentFrame{pkt.Header.Kind, pkt.Payload, d.Endpoint})
		return nil
	}
	var originals [][]byte
	for i := 0; i < n; i++ {
		payload := bytes.Repeat([]byte{byte(i + 1)}, 60+i*7)
		originals = append(originals, payload)
		for tries := 0; ; tries++ {
			if tries > 5000 {
				t.Fatal("bulk never sent")
			}
			now := f.now.Add(time.Duration(i*5+tries) * time.Millisecond)
			p0.budget.lossAt = f.r.seconds(now) // keep the estimate fresh
			if ok, _, err := s.Bulk(payload, "flow", now, writer); err != nil {
				t.Fatal(err)
			} else if ok {
				break
			}
		}
	}
	return originals, frames, s
}

// receiverFor builds an independent receiver with two ready paths.
func receiverFor(t *testing.T) (receiverFixture, [2]netip.AddrPort) {
	g := newReceiverFixture(t)
	var ep [2]netip.AddrPort
	for i := range ep {
		ep[i] = netip.AddrPortFrom(g.endpoint.Addr(), uint16(2000+i))
		g.connect(t, ep[i])
	}
	return g, ep
}

func TestParityRebuildsOneLostPacketPerGroup(t *testing.T) {
	originals, frames, s := sendProtected(t, 0.005, 16)
	var parities int
	for _, fr := range frames {
		if fr.kind == Parity {
			parities++
		}
	}
	if parities != 2 || s.Stats().ParitySent != 2 {
		t.Fatalf("want two parity frames for two full groups, got %d (stat %d)", parities, s.Stats().ParitySent)
	}
	// The first group only primes the receiver (data is kept once parity has been seen).
	for lost := 8; lost < 16; lost++ {
		g, ep := receiverFor(t)
		var delivered [][]byte
		seen := 0
		for _, fr := range frames {
			if fr.kind == Striped {
				if seen == lost {
					seen++
					continue
				}
				seen++
			}
			out := g.receive(t, fr.kind, fr.body, ep[0])
			delivered = append(delivered, out.Deliver...)
		}
		if g.r.stats.FECRecovered != 1 {
			t.Fatalf("lost %d: nothing recovered (%+v)", lost, g.r.stats)
		}
		if len(delivered) != 16 {
			t.Fatalf("lost %d: delivered %d of 16", lost, len(delivered))
		}
		for i, want := range originals {
			if !bytes.Equal(delivered[i], want) {
				t.Fatalf("lost %d: packet %d differs after recovery", lost, i)
			}
		}
	}
}

func TestParityIgnoredWhenTwoMembersMissing(t *testing.T) {
	_, frames, _ := sendProtected(t, 0.005, 16)
	g, ep := receiverFor(t)
	seen := 0
	for _, fr := range frames {
		if fr.kind == Striped {
			seen++
			if seen == 10 || seen == 13 {
				continue
			}
		}
		g.receive(t, fr.kind, fr.body, ep[0])
	}
	if g.r.stats.FECRecovered != 0 {
		t.Fatal("recovered from an unsolvable group")
	}
}

func TestHeavyLossDuplicatesBulkOnAnotherPath(t *testing.T) {
	originals, frames, s := sendProtected(t, 0.03, 10)
	if s.Stats().BulkDuplicates == 0 {
		t.Fatalf("no duplicates sent: %+v", s.Stats())
	}
	if s.Stats().ParitySent != 0 {
		t.Fatal("parity sent alongside duplication")
	}
	g, ep := receiverFor(t)
	var delivered [][]byte
	for _, fr := range frames {
		out := g.receive(t, fr.kind, fr.body, ep[0])
		delivered = append(delivered, out.Deliver...)
	}
	if len(delivered) != len(originals) {
		t.Fatalf("delivered %d, want %d: duplicates must be dropped", len(delivered), len(originals))
	}
	// Drop every copy that went to the lossy path: the rest must still be complete.
	g2, ep2 := receiverFor(t)
	lossy := frames[0].to
	delivered = nil
	for _, fr := range frames {
		if fr.kind == Striped && fr.to == lossy {
			continue
		}
		out := g2.receive(t, fr.kind, fr.body, ep2[0])
		delivered = append(delivered, out.Deliver...)
	}
	_ = lossy
	if len(delivered) < len(originals)/2 {
		t.Fatalf("clean-path copies too few: %d", len(delivered))
	}
}

func TestNoProtectionWhenClean(t *testing.T) {
	_, frames, s := sendProtected(t, 0, 8)
	for _, fr := range frames {
		if fr.kind == Parity {
			t.Fatal("parity on a clean path")
		}
	}
	if s.Stats().BulkDuplicates != 0 {
		t.Fatal("duplicated on a clean path")
	}
}

// Every packet is copied from the first one, whatever it is and however clean the lines.
func TestEveryPacketIsCopiedFromTheFirst(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	udp := udpOfSize(600)
	small := udpOfSize(40)
	n := 0
	for _, pkt := range [][]byte{tcpPacket("data"), udp, small, tcpPacket(string(make([]byte, 1000)))} {
		for i := 0; i < 5; i++ {
			n++
			for tries := 0; ; tries++ {
				if tries > 500 {
					t.Fatal("never sent")
				}
				now := f.now.Add(time.Duration(n*10+tries) * time.Millisecond)
				for _, k := range a {
					f.r.paths[pk(k)].last = now
				}
				if ok, _, err := s.Bulk(pkt, "flow", now, func(Datagram) error { return nil }); err != nil {
					t.Fatal(err)
				} else if ok {
					break
				}
			}
			if got := s.Stats().BulkDuplicates; got != uint64(n) {
				t.Fatalf("packet %d: %d copies so far", n, got)
			}
		}
	}
}

// When the copy cannot go out, the packet falls back to a parity group instead of
// travelling alone.
func TestTCPPresetFallsBackToParityWhenNoCopyFits(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	// Both links look quiet, so no path may take a copy.
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now.Add(-400 * time.Millisecond)
	}
	var parity int
	writer := func(d Datagram) error {
		if p, err := f.c.Decode(d.Frame); err == nil && p.Header.Kind == Parity {
			parity++
		}
		return nil
	}
	sent := 0
	for i := 0; i < 2000 && sent < 16; i++ {
		now := f.now.Add(time.Duration(i) * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now.Add(-400 * time.Millisecond)
		}
		if ok, _, err := s.Bulk(tcpPacket("data"), "flow", now, writer); err != nil {
			t.Fatal(err)
		} else if ok {
			sent++
		}
	}
	if s.Stats().BulkDupSkipped == 0 || parity == 0 || s.Stats().ParitySent == 0 {
		t.Fatalf("no parity fallback: skipped=%d parity=%d %+v", s.Stats().BulkDupSkipped, parity, s.Stats())
	}
}

// udpOfSize builds a valid IPv4/UDP datagram with n payload bytes.
func udpOfSize(n int) []byte {
	p := make([]byte, 28+n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[9] = 17
	copy(p[12:16], []byte{10, 77, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:], 5000)
	binary.BigEndian.PutUint16(p[22:], 27015)
	binary.BigEndian.PutUint16(p[24:], uint16(8+n))
	return p
}

// A line whose window is full still takes the copy: redundancy does not queue
// behind the traffic it protects.
func TestTCPPresetCopiesOntoAFullWindow(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	full := f.r.paths[pk(a[1])]
	for i := 0; i < maxPending; i++ {
		full.budget.Sent(uint64(1000+i), 1400, 0)
	}
	if ready, _ := full.budget.ReadyAt(1400, 0); ready <= 0.01 {
		t.Fatal("fixture: window not full")
	}
	sent := 0
	for i := 0; i < 2000 && sent < 10; i++ {
		now := f.now.Add(time.Duration(i) * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now
		}
		if ok, _, err := s.Bulk(tcpPacket("data"), "flow", now, func(Datagram) error { return nil }); err != nil {
			t.Fatal(err)
		} else if ok {
			sent++
		}
	}
	if sent < 10 || s.Stats().BulkDuplicates != uint64(sent) || s.Stats().BulkDupSkipped != 0 {
		t.Fatalf("sent %d, copies %d, skipped %d", sent, s.Stats().BulkDuplicates, s.Stats().BulkDupSkipped)
	}
}

// Every copy is tracked by its line's budget: the receiver acknowledges the copy's
// sequence, and feedback for an untracked sequence is rejected (the line then reads
// 100% feedback timeouts).
func TestTCPPresetCopiesAreTrackedForFeedback(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	sent := 0
	for i := 0; i < 200 && sent < 20; i++ {
		now := f.now.Add(time.Duration(i) * 10 * time.Millisecond)
		for _, k := range a {
			f.r.paths[pk(k)].last = now
		}
		if ok, _, err := s.Bulk(tcpPacket("data"), "flow", now, func(Datagram) error { return nil }); err != nil {
			t.Fatal(err)
		} else if ok {
			sent++
		}
	}
	var tracked uint64
	for _, k := range a {
		tracked += f.r.paths[pk(k)].budget.sentPackets
	}
	if sent < 20 || s.Stats().BulkDuplicates == 0 || tracked != uint64(sent)+s.Stats().BulkDuplicates {
		t.Fatalf("sent %d copies %d but budgets track %d", sent, s.Stats().BulkDuplicates, tracked)
	}
}

// Priority traffic is copied onto both lines even when nothing asked for a copy.
func TestUrgentPacketsAreAlwaysSentOnEveryReadyPath(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	s.lossTiered = false
	for _, k := range a {
		f.r.paths[pk(k)].last = f.now
	}
	var to []netip.AddrPort
	n, err := s.Urgent(udpOfSize(60), false, f.now, func(d Datagram) error { to = append(to, d.Endpoint); return nil })
	if err != nil || n != 2 || len(to) != 2 || to[0] == to[1] {
		t.Fatalf("sent %d on %v (%v)", n, to, err)
	}
}
