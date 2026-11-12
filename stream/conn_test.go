package stream

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
	"time"
)

type inflightPkt struct {
	at time.Time
	b  []byte
	to int
}

// simulate runs a<->b through two paths with different delay, jitter and loss.
func simulate(t *testing.T, size int, loss float64, delays [2]time.Duration, jitter time.Duration) (*Conn, *Conn, time.Duration) {
	rng := rand.New(rand.NewSource(7))
	reorder := delays[1] - delays[0]
	if reorder < 0 {
		reorder = -reorder
	}
	hint := func() time.Duration { return reorder + jitter }
	a := New(Config{ReorderHint: hint})
	b := New(Config{ReorderHint: hint})
	cs := [2]*Conn{a, b}
	data := make([]byte, size)
	rng.Read(data)
	now := time.Unix(1000, 0)
	start := now
	var net []inflightPkt
	sent, got := 0, []byte(nil)
	a.CloseWrite()
	a.finQueued = false // re-armed below once all bytes are queued
	closed := false
	buf := make([]byte, 64<<10)
	for step := 0; step < 2_000_000; step++ {
		if sent < len(data) {
			n, _ := a.Write(data[sent:])
			sent += n
		}
		if sent == len(data) && !closed {
			a.CloseWrite()
			closed = true
		}
		for i, c := range cs {
			var out [][]byte
			c.Poll(now, &out)
			for _, p := range out {
				if rng.Float64() < loss {
					continue
				}
				path := rng.Intn(2)
				d := delays[path] + time.Duration(rng.Int63n(int64(jitter)+1))
				net = append(net, inflightPkt{now.Add(d), p, 1 - i})
			}
		}
		sort.SliceStable(net, func(i, j int) bool { return net[i].at.Before(net[j].at) })
		now = now.Add(500 * time.Microsecond)
		for len(net) > 0 && !net[0].at.After(now) {
			p := net[0]
			net = net[1:]
			if err := cs[p.to].OnPacket(p.b, now); err != nil {
				t.Fatal(err)
			}
		}
		for {
			n := b.Read(buf)
			if n == 0 {
				break
			}
			got = append(got, buf[:n]...)
		}
		if b.Finished() && a.finAcked {
			break
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data mismatch: got %d of %d bytes (a: %+v)", len(got), len(data), a.Stats)
	}
	return a, b, now.Sub(start)
}

func TestTransferClean(t *testing.T) {
	a, _, d := simulate(t, 2<<20, 0, [2]time.Duration{20 * time.Millisecond, 45 * time.Millisecond}, 5*time.Millisecond)
	t.Logf("clean: %v %+v", d, a.Stats)
	if a.Stats.SpuriousRetx > 20 {
		t.Fatalf("too many spurious retransmits on a lossless reordering path: %d", a.Stats.SpuriousRetx)
	}
}

func TestTransferLossy(t *testing.T) {
	a, _, d := simulate(t, 2<<20, 0.03, [2]time.Duration{20 * time.Millisecond, 45 * time.Millisecond}, 5*time.Millisecond)
	t.Logf("lossy: %v %+v", d, a.Stats)
	if a.Stats.Retransmits == 0 {
		t.Fatal("expected retransmits")
	}
}

func TestEmptyFin(t *testing.T) {
	simulate(t, 0, 0, [2]time.Duration{10 * time.Millisecond, 10 * time.Millisecond}, time.Millisecond)
}
