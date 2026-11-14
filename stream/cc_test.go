package stream

import (
	"testing"
	"time"
)

func ccAt(ms int) time.Time { return time.Unix(2000, 0).Add(time.Duration(ms) * time.Millisecond) }

// feed delivers n acknowledgements, each carrying one packet, at the given rate.
func feed(g *congestion, start *int, n int, rate float64, rtt time.Duration, inflight int, delivered *uint64) {
	for i := 0; i < n; i++ {
		*start += 10
		*delivered += uint64(g.mss)
		g.onAck(ccAt(*start), rateSample{valid: true, rate: rate, priorDelivered: *delivered - uint64(10*g.mss), rtt: rtt}, *delivered, g.mss, inflight)
	}
}

func TestBandwidthIsTheRecentMaximum(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 50, 1_000_000, 50*time.Millisecond, 50000, &d)
	feed(g, &at, 50, 500_000, 50*time.Millisecond, 50000, &d)
	if g.btlBw != 1_000_000 {
		t.Fatalf("bandwidth %v forgot a recent peak", g.btlBw)
	}
	// Once the peak is older than ccBwRounds rounds, the estimate follows the path down.
	for i := 0; i < 40; i++ {
		feed(g, &at, 20, 500_000, 50*time.Millisecond, 50000, &d)
	}
	if g.btlBw > 600_000 {
		t.Fatalf("bandwidth %v still remembers a peak from long ago", g.btlBw)
	}
}

func TestAppLimitedSamplesNeverLowerTheEstimate(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 50, 2_000_000, 50*time.Millisecond, 50000, &d)
	for i := 0; i < 200; i++ {
		at += 10
		d += 1000
		g.onAck(ccAt(at), rateSample{valid: true, rate: 10_000, appLimited: true, priorDelivered: d - 10000, rtt: 50 * time.Millisecond}, d, 1000, 5000)
	}
	if g.btlBw < 2_000_000 {
		t.Fatalf("an idle application pulled the estimate to %v", g.btlBw)
	}
}

func TestIsolatedLossDoesNotBoundTheWindow(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 200, 1_000_000, 50*time.Millisecond, 50000, &d)
	for i := 0; i < 30; i++ { // a lost packet or two in every round: random loss on a radio link
		g.onLoss(1000, 50000)
		g.onLoss(1000, 50000)
		feed(g, &at, 20, 1_000_000, 50*time.Millisecond, 50000, &d)
	}
	if g.inflightHi != 0 {
		t.Fatalf("random loss bounded the window at %d", g.inflightHi)
	}
	if g.conservation {
		t.Fatal("random loss put the connection into packet conservation")
	}
}

func TestOverflowBoundsTheWindowBelowWhereItLost(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 200, 1_000_000, 50*time.Millisecond, 50000, &d)
	g.fullPipe = true
	g.enterProbeBW(ccAt(at))
	for i := 0; i < 12; i++ {
		g.onLoss(1000, 90000) // a buffer overflowed: a dozen packets in one round
	}
	feed(g, &at, 11, 1_000_000, 50*time.Millisecond, 60000, &d)
	if g.inflightHi == 0 || g.inflightHi > 90000 {
		t.Fatalf("window bound %d after an overflow at 90000", g.inflightHi)
	}
	if g.window() > g.inflightHi {
		t.Fatalf("window %d above its bound %d", g.window(), g.inflightHi)
	}
}

func TestRepeatedTimeoutsRelearnThePath(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 100, 1_000_000, 50*time.Millisecond, 50000, &d)
	g.onTimeout(1)
	if g.btlBw == 0 {
		t.Fatal("a single timeout threw the model away")
	}
	g.onTimeout(3)
	if g.btlBw != 0 || g.mode != ccStartup || g.window() != g.initCwnd {
		t.Fatalf("model kept after repeated timeouts: bw %v mode %v cwnd %d", g.btlBw, g.mode, g.window())
	}
	if g.pacingRate() < ccMinRate {
		t.Fatal("pacing rate fell to zero: the flow could never restart")
	}
}

func TestProbeDownDrainsBeforeCruising(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 200, 1_000_000, 50*time.Millisecond, 50000, &d)
	g.fullPipe = true
	g.enterProbeBW(ccAt(at))
	g.setPhase(pbDown, ccAt(at))
	bdp := int(g.bdp(1))
	// A queue three times the pipe is in flight: the phase must not end after one round trip.
	for i := 0; i < 8; i++ {
		feed(g, &at, 1, 1_000_000, 50*time.Millisecond, 3*bdp, &d)
	}
	if g.phase != pbDown {
		t.Fatalf("left the drain phase with %d in flight against a pipe of %d", 3*bdp, bdp)
	}
	feed(g, &at, 1, 1_000_000, 50*time.Millisecond, bdp-1, &d)
	if g.phase != pbCruise {
		t.Fatalf("still draining with the pipe empty: phase %v", g.phase)
	}
}

func TestWindowNeverGrowsPastTheModelInCruise(t *testing.T) {
	g := newCongestion(1000, 100*time.Millisecond)
	var d uint64
	at := 0
	feed(g, &at, 300, 1_000_000, 50*time.Millisecond, 50000, &d)
	g.fullPipe = true
	g.enterProbeBW(ccAt(at))
	feed(g, &at, 2000, 1_000_000, 50*time.Millisecond, 50000, &d)
	limit := int(g.bdp(ccCwndGain)+g.extra()) + g.mss
	if g.window() > limit {
		t.Fatalf("window %d runs away from the model (%d)", g.window(), limit)
	}
}
