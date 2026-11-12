package bond

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestGaloisFieldBasics(t *testing.T) {
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("%d has no inverse", a)
		}
		if gfMul(byte(a), 1) != byte(a) || gfMul(byte(a), 0) != 0 {
			t.Fatal("identity")
		}
	}
	// Distributive law spot check.
	for a := 1; a < 256; a += 7 {
		for b := 1; b < 256; b += 11 {
			for c := 1; c < 256; c += 13 {
				if gfMul(byte(a), byte(b)^byte(c)) != gfMul(byte(a), byte(b))^gfMul(byte(a), byte(c)) {
					t.Fatal("not distributive")
				}
			}
		}
	}
}

// rsGroup builds one group of eight payloads of different lengths and its parity rows.
func rsGroup() (payloads [][]byte, rows [][]byte) {
	f := &sendFlow{id: 77, fecBase: 16, fecMask: 0xff}
	for i := 0; i < fecK; i++ {
		p := bytes.Repeat([]byte{byte(0x30 + i), byte(i * 17)}, 20+i*13)
		payloads = append(payloads, p)
		f.rsAccumulate(i, p)
	}
	for r := 0; r < fecMaxRows; r++ {
		body := make([]byte, rsHeader+len(f.fecRS[r]))
		binary.BigEndian.PutUint64(body, f.id)
		binary.BigEndian.PutUint64(body[8:], f.fecBase)
		body[16] = f.fecMask
		body[17] = byte(r)
		copy(body[rsHeader:], f.fecRS[r])
		rows = append(rows, body)
	}
	return
}

// Any n missing members are rebuilt from any n parity rows.
func TestReedSolomonRebuildsAnyMissingSetUpToTheRowCount(t *testing.T) {
	payloads, rows := rsGroup()
	cases := 0
	for missing := 1; missing < 256; missing++ {
		n := 0
		for b := 0; b < fecK; b++ {
			if missing&(1<<b) != 0 {
				n++
			}
		}
		if n > fecMaxRows {
			continue
		}
		// Use the last n rows so the row-0-only shortcut cannot hide a bad matrix.
		for _, use := range [][]int{rangeFrom(fecMaxRows-n, fecMaxRows), rangeFrom(0, n)} {
			g, _ := receiverFor(t)
			now := time.Now()
			var got = map[uint64][]byte{}
			for _, r := range use {
				for _, hit := range g.r.fecParityRS(rows[r], now) {
					got[hit.number] = hit.payload
				}
			}
			for i := 0; i < fecK; i++ {
				if missing&(1<<i) != 0 {
					continue
				}
				for _, hit := range g.r.fecData(77, 16+uint64(i), payloads[i], now) {
					got[hit.number] = hit.payload
				}
			}
			if len(got) != n {
				t.Fatalf("missing %08b rows %v: rebuilt %d of %d", missing, use, len(got), n)
			}
			for i := 0; i < fecK; i++ {
				if missing&(1<<i) != 0 && !bytes.Equal(got[16+uint64(i)], payloads[i]) {
					t.Fatalf("missing %08b rows %v: member %d rebuilt wrongly", missing, use, i)
				}
			}
			cases++
		}
	}
	if cases < 150 {
		t.Fatalf("only %d cases ran", cases)
	}
}

func rangeFrom(a, b int) []int {
	var out []int
	for i := a; i < b; i++ {
		out = append(out, i)
	}
	return out
}

func TestReedSolomonNeverGuessesWithTooFewRows(t *testing.T) {
	payloads, rows := rsGroup()
	g, _ := receiverFor(t)
	now := time.Now()
	for r := 0; r < 2; r++ {
		g.r.fecParityRS(rows[r], now)
	}
	var hits int
	for i := 3; i < fecK; i++ { // members 0, 1, 2 are missing: three unknowns, two rows
		hits += len(g.r.fecData(77, 16+uint64(i), payloads[i], now))
	}
	if hits != 0 || g.r.stats.FECRecovered != 0 {
		t.Fatalf("rebuilt %d members from too few rows", hits)
	}
	// The third row arrives and all three come back.
	if got := len(g.r.fecParityRS(rows[2], now)); got != 3 {
		t.Fatalf("third row rebuilt %d, want 3", got)
	}
}

// Loss makes the sender add rows, and the extra rows go out later than the first.
func TestSenderAddsParityRowsWhileLossIsSeen(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p0 := f.r.paths[pk(a[0])]
	ts := f.r.seconds(f.now)
	p0.budget.lossSeen, p0.budget.lossAt, p0.budget.lossEWMA, p0.budget.lossEWSet = true, ts, .01, true
	if rows := s.parityRows(f.now); rows != 1 {
		t.Fatalf("clean path got %d rows", rows)
	}
	for i := 0; i < 3; i++ {
		s.addLossHeat(f.now)
	}
	if rows := s.parityRows(f.now); rows != 2 {
		t.Fatalf("lossy path got %d rows, want 2", rows)
	}
	for i := 0; i < 12; i++ {
		s.addLossHeat(f.now)
	}
	if rows := s.parityRows(f.now); rows != 3 {
		t.Fatalf("burst got %d rows, want 3", rows)
	}
	if rows := s.parityRows(f.now.Add(30 * time.Second)); rows != 1 {
		t.Fatalf("heat did not decay: %d rows", rows)
	}
	s.SetParityRows(1, 2)
	if rows := s.parityRows(f.now); rows != 2 {
		t.Fatalf("cap ignored: %d rows", rows)
	}
	s.SetParityRows(2, 0)
	if rows := s.parityRows(f.now.Add(30 * time.Second)); rows != 2 {
		t.Fatalf("floor ignored: %d rows", rows)
	}
}

// End to end: the sender protects a flow with two rows, two members of one group are
// lost on the wire, and the receiver still delivers everything in order.
func TestTwoLostPacketsInOneGroupAreRepairedWithoutARoundTrip(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	p0 := f.r.paths[pk(a[0])]
	p0.budget.lossSeen, p0.budget.lossEWMA, p0.budget.lossEWSet = true, .005, true // parity, not duplication
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
	now := f.now
	for i := 0; i < 24; i++ {
		payload := bytes.Repeat([]byte{byte(i + 1)}, 60+i*7)
		originals = append(originals, payload)
		for tries := 0; ; tries++ {
			if tries > 5000 {
				t.Fatal("bulk never sent")
			}
			now = f.now.Add(time.Duration(i*5+tries) * time.Millisecond)
			p0.budget.lossAt = f.r.seconds(now)
			p0.last, f.r.paths[pk(a[1])].last = now, now
			s.addLossHeat(now)
			if ok, _, err := s.Bulk(payload, "flow", now, writer); err != nil {
				t.Fatal(err)
			} else if ok {
				break
			}
		}
	}
	for i := 0; i < 20; i++ { // let the staggered rows come due
		now = now.Add(parityStagger)
		p0.last, f.r.paths[pk(a[1])].last = now, now
		if err := s.Maintenance(now, writer); err != nil {
			t.Fatal(err)
		}
	}
	rs := 0
	for _, fr := range frames {
		if fr.kind == ParityRS {
			rs++
		}
	}
	if rs < 4 || s.Stats().ParityRSSent == 0 {
		t.Fatalf("only %d Reed-Solomon rows sent", rs)
	}
	g, ep := receiverFor(t)
	var delivered [][]byte
	seen := 0
	for _, fr := range frames {
		if fr.kind == Striped {
			seen++
			if seen == 10 || seen == 12 { // two members of the second group
				continue
			}
		}
		delivered = append(delivered, g.receive(t, fr.kind, fr.body, ep[0]).Deliver...)
	}
	if g.r.stats.FECRecoveredRS < 2 {
		t.Fatalf("rebuilt %d members, want 2 (%+v)", g.r.stats.FECRecoveredRS, g.r.stats)
	}
	if len(delivered) < 24 {
		t.Fatalf("delivered %d of 24", len(delivered))
	}
	for i, want := range originals {
		if !bytes.Equal(delivered[i], want) {
			t.Fatalf("packet %d differs", i)
		}
	}
}
