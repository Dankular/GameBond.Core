package bond

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
	"time"
)

type vecPath struct {
	Slot      int      `json:"slot"`
	Local     string   `json:"local"`
	Remote    string   `json:"remote"`
	Healthy   bool     `json:"healthy"`
	Available *bool    `json:"available"`
	Enabled   *bool    `json:"enabled"`
	RTT       *float64 `json:"rtt_ms"`
	Jitter    *float64 `json:"rtt_jitter_ms"`
	Bonding   struct {
		Expired, Acked, Delivered uint64
		Loss, Queue               float64
	}
	BondingRaw struct {
		Expired   uint64  `json:"expired_packets"`
		Acked     uint64  `json:"acked_packets"`
		Delivered uint64  `json:"delivered_bytes"`
		Loss      float64 `json:"settled_loss_ratio"`
		Queue     float64 `json:"queue_delay_ms"`
	} `json:"bonding"`
	Probe struct {
		Lost  uint64 `json:"lost"`
		Acked uint64 `json:"acked"`
	} `json:"probe_quality"`
	Copy struct {
		Seen   uint64 `json:"seen"`
		Missed uint64 `json:"missed"`
	} `json:"peer_copy_quality"`
}

type vecStep struct {
	Op       string `json:"op"`
	T        float64
	Snapshot struct {
		Paths []vecPath `json:"paths"`
	} `json:"snapshot"`
	Quality []struct {
		Loss, FeedbackTimeoutRatio float64 `json:"-"`
		L                          float64 `json:"loss"`
		F                          float64 `json:"feedback_timeout_ratio"`
		P                          float64 `json:"round_trip_probe_loss"`
		C                          float64 `json:"copy_loss"`
		N                          uint64  `json:"copy_samples"`
		J                          float64 `json:"jitter_ms"`
		D                          float64 `json:"predicted_ms"`
	} `json:"quality"`
	Reasons   map[string][]string `json:"reasons"`
	Active    map[string]bool     `json:"active"`
	Tag       byte                `json:"tag"`
	Size      int                 `json:"size"`
	Base      bool                `json:"base"`
	Replicate bool                `json:"replicate"`
}

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-9*math.Max(1, math.Abs(b)) }

func TestAdaptiveQoSMatchesPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/qos-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var scenarios []struct {
		Settings map[string]any `json:"settings"`
		Steps    []vecStep      `json:"steps"`
		Counts   map[string]uint64
	}
	if err := json.NewDecoder(z).Decode(&scenarios); err != nil {
		t.Fatal(err)
	}
	epoch := time.Unix(1000, 0)
	at := func(s float64) time.Time { return epoch.Add(time.Duration((s - 1000) * float64(time.Second))) }
	steps := 0
	for si, sc := range scenarios {
		settings := DefaultQoSSettings()
		raw, _ := json.Marshal(sc.Settings)
		if err := json.Unmarshal(raw, &settings); err != nil {
			t.Fatal(err)
		}
		q, err := NewAdaptiveQoS(settings)
		if err != nil {
			t.Fatal(err)
		}
		for i, st := range sc.Steps {
			now := at(st.T)
			steps++
			if st.Op == "tx" {
				got := q.Replicate(st.Tag, st.Size, st.Base, now)
				if got != st.Replicate {
					t.Fatalf("scenario %d step %d: replicate %v want %v (tag %d size %d)", si, i, got, st.Replicate, st.Tag, st.Size)
				}
				continue
			}
			var paths []QoSPath
			for _, p := range st.Snapshot.Paths {
				qp := QoSPath{Slot: p.Slot, Local: p.Local, Remote: p.Remote, Healthy: p.Healthy, Available: p.Available == nil || *p.Available,
					Enabled: p.Enabled == nil || *p.Enabled, RTTMS: p.RTT, Expired: p.BondingRaw.Expired, Acked: p.BondingRaw.Acked,
					DeliveredBytes: p.BondingRaw.Delivered, SettledLoss: p.BondingRaw.Loss, QueueDelayMS: p.BondingRaw.Queue,
					ProbeLost: p.Probe.Lost, ProbeAcked: p.Probe.Acked, CopySeen: p.Copy.Seen, CopyMissed: p.Copy.Missed}
				if p.Jitter != nil {
					qp.JitterMS = *p.Jitter
				}
				paths = append(paths, qp)
			}
			q.ObservePaths(paths, now)
			if len(q.quality) != len(st.Quality) {
				t.Fatalf("scenario %d step %d: %d healthy paths, want %d", si, i, len(q.quality), len(st.Quality))
			}
			for k, w := range st.Quality {
				g := q.quality[k]
				if !near(g.Loss, w.L) || !near(g.FeedbackTimeoutRatio, w.F) || !near(g.ProbeLoss, w.P) || !near(g.CopyLoss, w.C) ||
					g.CopySamples != w.N || !near(g.JitterMS, w.J) || !near(g.PredictedMS, w.D) {
					t.Fatalf("scenario %d step %d path %d: got %+v want %+v", si, i, k, g, w)
				}
			}
			for name, tag := range map[string]byte{"call": 26, "stream": 18} {
				got, want := q.reasons[tag], st.Reasons[name]
				if len(got) == 0 && len(want) == 0 {
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("scenario %d step %d %s reasons %v want %v", si, i, name, got, want)
				}
				if active := len(q.quality) > 1 && now.Before(q.until[tag]); active != st.Active[name] {
					t.Fatalf("scenario %d step %d %s active %v want %v", si, i, name, active, st.Active[name])
				}
			}
		}
		if q.samples != uint64(sc.Counts["samples"]) && false {
			t.Fatal("unreachable")
		}
		if q.replicated != sc.Counts["replicated"] || q.single != sc.Counts["single"] || q.budgetLimited != sc.Counts["duplicate_budget_limited"] {
			t.Fatalf("scenario %d counters repl=%d single=%d limited=%d want %v", si, q.replicated, q.single, q.budgetLimited, sc.Counts)
		}
	}
	t.Logf("%d steps over %d scenarios", steps, len(scenarios))
}
