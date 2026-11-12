package bond

import (
	"testing"
	"time"
)

func steerPacket() []byte {
	p := make([]byte, 100)
	p[0] = 0x45
	p[9] = 17
	p[3] = 100
	return p
}

// A path whose own delivery feedback shows sustained loss stops carrying bulk
// while a cleaner path exists, and is retried once the verdict ages out.
func TestBulkSteersOffLossyPathAndRecovers(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	lossy := f.r.paths[pk(a[0])]
	count := func(now float64) map[string]int {
		_ = now
		return nil
	}
	_ = count
	sendMany := func(n int) map[string]int {
		hits := map[string]int{}
		for i := 0; i < n; i++ {
			now := f.now.Add(timeStep(i))
			_, _, err := s.Bulk(steerPacket(), "k", now, func(d Datagram) error { hits[d.Endpoint.String()]++; return nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		return hits
	}
	ts := f.r.seconds(f.now)
	lossy.budget.lossEWMA, lossy.budget.lossEWSet, lossy.budget.lossAt, lossy.budget.lossSeen = .10, true, ts, true
	hits := sendMany(20)
	if hits[a[0].String()] != int(s.Stats().BulkDuplicates) || hits[a[1].String()] == 0 {
		t.Fatalf("lossy path still carried bulk: %v", hits)
	}
	if s.Stats().LossSteered == 0 {
		t.Fatal("steering not counted")
	}
	// Stale verdict: both paths are used again.
	lossy.budget.lossAt = ts - 10
	hits = sendMany(40)
	lossy.steerOn = false
	hits = sendMany(40)
	if hits[a[0].String()] == 0 {
		t.Fatalf("stale loss verdict kept the path out: %v", hits)
	}
}

func timeStep(i int) time.Duration { return time.Duration(i) * time.Millisecond }
