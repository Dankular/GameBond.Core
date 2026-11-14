package bond

import (
	"testing"
	"time"
)

func supervisionPair(t *testing.T) *clientServerPair {
	t.Helper()
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	// Let the first announcements settle so the tests start from a steady state.
	for i := 0; i < 40; i++ {
		p.step()
	}
	return p
}

// A burst that eats every supervision frame in both directions must not leave the peer's view stale
// for a further whole interval once the burst ends: the side that stopped hearing the peer retries
// quickly instead of waiting for its next scheduled announcement.
func TestSupervisionRecoversQuicklyAfterABurst(t *testing.T) {
	p := supervisionPair(t)
	burstEnd := p.now.Add(3 * time.Second)
	p.lose = func(fromClient bool, local int, kind byte) bool { return kind == Supervision && p.now.Before(burstEnd) }
	for p.now.Before(burstEnd) {
		p.step()
	}
	fresh := func() bool {
		for _, path := range p.server.paths {
			if !path.peerSupAt.After(burstEnd) {
				return false
			}
		}
		return true
	}
	var waited time.Duration
	for waited = 0; waited < 4*time.Second && !fresh(); waited += 250 * time.Millisecond {
		p.step()
	}
	t.Logf("peer view refreshed %v after the burst ended", waited)
	if waited > 750*time.Millisecond {
		t.Fatalf("peer view still stale %v after the burst ended, want at most 750ms", waited)
	}
}

// A change in what this side believes about its paths is announced at once, not at the next tick of
// the two second cadence.
func TestSupervisionAnnouncesAStateChangeAtOnce(t *testing.T) {
	p := supervisionPair(t)
	for i := 0; i < 3; i++ { // move off the announcement boundary so the change lands mid-interval
		p.step()
	}
	for _, path := range p.client.paths {
		path.suspect = true
		break
	}
	for i := 0; i < 3; i++ { // 750 ms
		p.step()
	}
	for _, path := range p.server.paths {
		suspect := 0
		for _, e := range path.peerSup {
			if e.Suspect() {
				suspect++
			}
		}
		if suspect == 0 {
			t.Fatalf("server did not learn of the suspect path within 750 ms: %+v", path.peerSup)
		}
	}
}

// Late ticks (a busy loop) must not stretch the cadence: announcements are scheduled from the
// previous deadline, not from when the late tick happened to run.
func TestSupervisionCadenceDoesNotDriftUnderLateTicks(t *testing.T) {
	p := supervisionPair(t)
	sent := 0
	p.lose = func(fromClient bool, local int, kind byte) bool {
		if fromClient && local == 0 && kind == Supervision {
			sent++
		}
		return false
	}
	start := p.now
	for p.now.Sub(start) < 120*time.Second {
		p.now = p.now.Add(700 * time.Millisecond)
		co, err := p.client.Tick(p.now)
		if err != nil {
			t.Fatal(err)
		}
		p.deliver(true, co)
		so, err := p.server.Tick(p.now)
		if err != nil {
			t.Fatal(err)
		}
		p.deliver(false, so)
	}
	t.Logf("%d announcements in 120 s", sent)
	// 120 s at 2 s is 60 announcements; allow one for the granularity of the ticks.
	if sent < 59 {
		t.Fatalf("%d announcements in 120 s, want at least 59: the cadence drifts", sent)
	}
}

// A peer that never sends supervision (an older build) must not make us announce faster than the
// normal cadence.
func TestSupervisionDoesNotRetryAgainstASilentOldPeer(t *testing.T) {
	p := supervisionPair(t)
	for _, path := range p.client.paths {
		path.peerSupAt = time.Time{}
	}
	sent := 0
	p.lose = func(fromClient bool, local int, kind byte) bool {
		if fromClient && local == 0 && kind == Supervision {
			sent++
		}
		return kind == Supervision && !fromClient // the server's frames never arrive
	}
	for i := 0; i < 80; i++ { // 20 s
		p.step()
		for _, path := range p.client.paths {
			path.peerSupAt = time.Time{}
		}
	}
	if sent > 12 {
		t.Fatalf("%d announcements in 20 s against a silent peer, want about 10", sent)
	}
}

// A line that loses or delays its BFD frames while data, probes and feedback still arrive is
// lossy, not dead. It must stay up (and keep carrying copies) rather than be declared down for
// "peer_not_hearing_us" every time a burst eats five BFD frames in a row.
func TestBFDFrameLossDoesNotDownALineThatStillDelivers(t *testing.T) {
	p := supervisionPair(t)
	downs := func() (n uint64) {
		for _, side := range []*Receiver{p.client, p.server} {
			for _, path := range side.paths {
				n += path.bfd.downs
			}
		}
		return n
	}
	before := downs()
	p.lose = func(fromClient bool, local int, kind byte) bool { return kind == BFD && local == 0 }
	for i := 0; i < 24; i++ { // 6 s with every BFD frame on link 0 lost, both directions
		p.step()
	}
	if got := downs() - before; got != 0 {
		t.Fatalf("%d BFD downs although probes and feedback kept arriving", got)
	}
}

// A line that really stops delivering is still detected within the BFD detect time.
func TestBFDStillDetectsADeadLine(t *testing.T) {
	p := supervisionPair(t)
	p.drop[0] = true
	var down bool
	for i := 0; i < 4 && !down; i++ { // up to 1 s
		p.step()
		for _, path := range p.server.paths {
			if path.local == 0 && path.bfdDown() {
				down = true
			}
		}
	}
	if !down {
		t.Fatal("a dead line was not declared down within 1 s")
	}
}

// stepBy advances the pair by d and ticks both sides, like a loop that wakes more often than the
// default 250 ms test step.
func (p *clientServerPair) stepBy(d time.Duration) {
	p.now = p.now.Add(d)
	co, err := p.client.Tick(p.now)
	if err != nil {
		p.t.Fatal(err)
	}
	p.deliver(true, co)
	so, err := p.server.Tick(p.now)
	if err != nil {
		p.t.Fatal(err)
	}
	p.deliver(false, so)
}

// A line that stops delivering is declared down within the calm-line detect time plus one BFD
// interval on the far side, measured with a loop that ticks every 5 ms.
func TestBFDDetectsADeadLineInUnder250ms(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	for i := 0; i < 400; i++ { // 2 s of steady state at 5 ms
		p.stepBy(5 * time.Millisecond)
	}
	p.drop[0] = true
	start := p.now
	var took time.Duration
	for took = 0; took < time.Second; took = p.now.Sub(start) {
		p.stepBy(5 * time.Millisecond)
		down := 0
		for _, side := range []*Receiver{p.client, p.server} {
			for _, path := range side.paths {
				if path.local == 0 && path.bfdDown() {
					down++
				}
			}
		}
		if down == 2 { // both ends have declared it
			break
		}
	}
	t.Logf("both ends declared the dead line down after %v", took)
	if took > 250*time.Millisecond {
		t.Fatalf("dead line took %v to detect on both ends, want at most 250ms", took)
	}
}

// The detect time follows the line: after a line shows a 120 ms stall that was not a failure, a
// 170 ms silence is within what that line does, while a calm line is declared down at once.
func TestBFDDetectTimeWidensToTheLinesOwnJitter(t *testing.T) {
	run := func(stall time.Duration) *receivePath {
		r := &Receiver{}
		path := &receivePath{}
		t0 := time.Unix(1000, 0)
		frame := []byte{1, bfdMultiplier, 50, 0, 0, 0, 0, 0}
		now := t0
		for i := 0; i < 40; i++ { // steady frames every 50 ms
			path.touch(now)
			r.bfdReceived(path, frame, now)
			now = now.Add(50 * time.Millisecond)
		}
		now = now.Add(stall - 50*time.Millisecond)
		path.touch(now)
		r.bfdReceived(path, frame, now)
		r.bfdEvaluate(path, now.Add(170*time.Millisecond))
		return path
	}
	if calm := run(50 * time.Millisecond); !calm.bfdDown() {
		t.Fatal("a calm line silent for 170 ms must be down")
	}
	if jittery := run(120 * time.Millisecond); jittery.bfdDown() {
		t.Fatalf("a line that stalls for 120 ms was declared down after 170 ms (limit %v)", jittery.bfdLimit(time.Unix(1000, 0).Add(10*time.Second)))
	}
}

// A remembered stall fades, so a line that was jittery once is not given a long detect time forever.
func TestBFDDetectTimeFadesBackToTheFloor(t *testing.T) {
	path := &receivePath{}
	t0 := time.Unix(1000, 0)
	path.touch(t0)
	path.touch(t0.Add(400 * time.Millisecond)) // a 400 ms stall
	if got := path.bfdLimit(t0.Add(400 * time.Millisecond)); got < 500*time.Millisecond-time.Millisecond {
		t.Fatalf("limit right after a 400 ms stall is %v, want the 500 ms cap", got)
	}
	if got := path.bfdLimit(t0.Add(60 * time.Second)); got != bfdDetectMin {
		t.Fatalf("limit a minute later is %v, want the %v floor", got, bfdDetectMin)
	}
}
