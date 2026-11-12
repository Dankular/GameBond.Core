package hwmon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type scripted struct {
	mu    sync.Mutex
	out   []byte
	err   error
	calls int
	gate  chan struct{}
}

func (s *scripted) run(ctx context.Context, script string) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	out, err, gate := s.out, s.err, s.gate
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return out, err
}

func waitIdle(t *testing.T, g *GPUSampler) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		if r := g.Sample(); r["sampling"] == false {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("sampler stayed busy")
	return nil
}

func TestGPUSamplerParsingAndThrottle(t *testing.T) {
	now := 100.0
	var cm sync.Mutex
	clock := func() float64 { cm.Lock(); defer cm.Unlock(); return now }
	set := func(v float64) { cm.Lock(); now = v; cm.Unlock() }
	run := &scripted{out: []byte("\xef\xbb\xbf" + `{"percent":37.5,"dedicated_used_bytes":1024,"engine_count":3,"errors":["x"]}`)}
	g := NewGPUSampler(5, run.run, clock, func() float64 { return 7 })
	first := g.Sample()
	if first["status"] != "not_sampled" || first["sampling"] != true {
		t.Fatalf("first call: %v", first)
	}
	got := waitIdle(t, g)
	if got["status"] != "available" || got["percent"] != 37.5 || got["dedicated_used_bytes"] != int64(1024) ||
		got["engine_count"] != 1*3 || got["available"] != true || got["metric"] != "busiest_engine_percent" {
		t.Fatalf("%v", got)
	}
	// within the interval: no new query
	set(103)
	g.Sample()
	if run.calls != 1 {
		t.Fatalf("calls=%d", run.calls)
	}
	// interval passed: a new query starts
	set(105)
	g.Sample()
	waitIdle(t, g)
	if run.calls != 2 {
		t.Fatalf("calls=%d", run.calls)
	}
	// stale after max(15, 3*interval) without a refresh
	run.mu.Lock()
	run.err = errors.New("boom")
	run.mu.Unlock()
	set(105 + 14)
	if r := g.Sample(); r["status"] == "stale" {
		t.Fatal("stale too early")
	}
	waitIdle(t, g) // refresh failed -> unavailable
	r := g.Sample()
	if r["status"] != "unavailable" || r["available"] != false || r["errors"].([]string)[0] != "boom" {
		t.Fatalf("%v", r)
	}
}

func TestGPUSamplerValidation(t *testing.T) {
	cases := map[string]string{
		`{"percent":101}`:               "unavailable",
		`{"percent":-1}`:                "unavailable",
		`{"percent":true}`:              "unavailable",
		`{"percent":"5"}`:               "unavailable",
		`{"dedicated_used_bytes":5.0}`:  "unavailable",
		`{"dedicated_used_bytes":-1}`:   "unavailable",
		`{"dedicated_used_bytes":true}`: "unavailable",
		`[]`:                            "unavailable",
		`nope`:                          "unavailable",
		`{"percent":null,"dedicated_used_bytes":null}`: "unavailable",
		`{"percent":0}`: "available",
		`{"percent":100,"dedicated_used_bytes":0}`: "available",
		`{"dedicated_used_bytes":9}`:               "available",
	}
	for text, want := range cases {
		run := &scripted{out: []byte(text)}
		g := NewGPUSampler(5, run.run, func() float64 { return 1 }, nil)
		g.Sample()
		if got := waitIdle(t, g)["status"]; got != want {
			t.Errorf("%s: %v, want %s", text, got, want)
		}
	}
	// a failing runner and exit status
	run := &scripted{err: errors.New("Windows GPU counters are unavailable")}
	g := NewGPUSampler(5, run.run, func() float64 { return 1 }, nil)
	g.Sample()
	if r := waitIdle(t, g); r["status"] != "unavailable" || r["errors"].([]string)[0] != "Windows GPU counters are unavailable" {
		t.Fatalf("%v", r)
	}
}

func TestGPUSamplerShutdownCancelsQuery(t *testing.T) {
	run := &scripted{gate: make(chan struct{}), out: []byte(`{"percent":1}`)}
	g := NewGPUSampler(5, run.run, func() float64 { return 1 }, nil)
	g.Sample()
	done := make(chan struct{})
	go func() { g.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not cancel the running query")
	}
	before := run.calls
	g.Sample()
	time.Sleep(50 * time.Millisecond)
	if run.calls != before {
		t.Fatal("query started after shutdown")
	}
}

func TestGPUSamplerAsProvider(t *testing.T) {
	var _ GPUProvider = NewGPUSampler(5, nil, nil, nil)
}
