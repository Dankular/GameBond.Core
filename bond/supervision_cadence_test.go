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
