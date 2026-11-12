package bond

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type fpVectors struct {
	Client  string `json:"client"`
	Observe []struct {
		Record map[string]any `json:"record"`
		Out    *struct {
			Key     string `json:"key"`
			Profile string `json:"profile"`
		} `json:"out"`
	} `json:"observe"`
	Classify []struct {
		Enabled bool    `json:"enabled"`
		Packet  string  `json:"packet"`
		Profile *string `json:"profile"`
		Tag     byte    `json:"tag"`
		Reason  string  `json:"reason"`
		Policy  [4]any  `json:"policy"`
		Marked  string  `json:"marked"`
	} `json:"classify"`
}

func loadFP(t *testing.T) fpVectors {
	f, err := os.Open("testdata/flowprofile_vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var v fpVectors
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFlowProfileObserveMatchesPython(t *testing.T) {
	v := loadFP(t)
	now := time.Unix(1000, 0)
	accepted := 0
	for i, c := range v.Observe {
		var f FlowProfiles
		ok := f.Observe(c.Record, v.Client, now)
		if (c.Out != nil) != ok {
			t.Fatalf("%d %v: accepted=%v want %v", i, c.Record, ok, c.Out != nil)
		}
		if !ok {
			continue
		}
		accepted++
		key, _ := hex.DecodeString(c.Out.Key)
		if len(key) != 13 {
			continue // IPv6 peer: stored by Python, unmatchable by IPv4 packets
		}
		if got := f.Lookup(string(key), now); got != c.Out.Profile {
			t.Fatalf("%d: key %s profile %q want %q", i, c.Out.Key, got, c.Out.Profile)
		}
	}
	if accepted < 100 {
		t.Fatalf("only %d accepted records", accepted)
	}
}

func TestFlowProfileClassifyMatchesPython(t *testing.T) {
	v := loadFP(t)
	for i, c := range v.Classify {
		qos := DefaultQoSSettings()
		qos.Enabled = c.Enabled
		cl, err := NewClassifier(nil, nil, qos)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := hex.DecodeString(c.Packet)
		info, err := ParseIPv4(raw)
		if err != nil {
			t.Fatal(err)
		}
		cl.Reset()
		got := cl.Classify(info, time.Unix(1000, 0))
		profile := ""
		if c.Profile != nil {
			profile = *c.Profile
		}
		got = cl.ForProfile(got, profile)
		out := raw
		if profile != "" && cl.QoSEnabled() {
			out, err = MarkDSCP(raw, got.Tag)
			if err != nil {
				t.Fatal(err)
			}
		}
		p := got.Policy
		want := c.Policy
		if got.Tag != c.Tag || got.Reason != c.Reason || p.Priority != want[0].(bool) || p.Replicate != want[1].(bool) ||
			p.MaxAgeMS != want[2].(float64) || float64(p.Capacity) != want[3].(float64) || hex.EncodeToString(out) != c.Marked {
			t.Fatalf("%d enabled=%v profile=%q dscp=%d: got tag=%d %s %+v\nwant %+v %s", i, c.Enabled, profile, raw[1]>>2, got.Tag, got.Reason, p, c, "")
		}
	}
}

func TestFlowProfileExpiryAndCap(t *testing.T) {
	var f FlowProfiles
	now := time.Unix(1000, 0)
	rec := func(port int) map[string]any {
		return map[string]any{"profile": "game", "protocol": "udp", "source": "10.0.0.2:" + itoa(port), "destination": "1.1.1.1:53"}
	}
	for i := 1; i <= FlowProfileCap+10; i++ {
		f.Observe(rec(i), "10.0.0.2", now)
	}
	if len(f.entries) != FlowProfileCap {
		t.Fatalf("size %d", len(f.entries))
	}
	key := func(port uint16) string { return FlowKey(17, [4]byte{10, 0, 0, 2}, port, [4]byte{1, 1, 1, 1}, 53) }
	if f.Lookup(key(1), now) != "" || f.Lookup(key(20), now) != "game" {
		t.Fatal("oldest entries not evicted first")
	}
	if f.Lookup(key(20), now.Add(100*time.Second)) != "game" { // refreshes last-seen
		t.Fatal("expired too early")
	}
	if f.Lookup(key(20), now.Add(100*time.Second+FlowProfileTTL)) != "game" {
		t.Fatal("last-seen not refreshed by lookup")
	}
	if f.Lookup(key(20), now.Add(100*time.Second+2*FlowProfileTTL+time.Second)) != "" {
		t.Fatal("idle entry not expired")
	}
}

func TestFlowProfileIdleBoundary(t *testing.T) {
	var f FlowProfiles
	now := time.Unix(1000, 0)
	f.Observe(map[string]any{"profile": "call", "protocol": "tcp", "source": "10.0.0.2:5", "destination": "1.1.1.1:6"}, "10.0.0.2", now)
	key := FlowKey(6, [4]byte{10, 0, 0, 2}, 5, [4]byte{1, 1, 1, 1}, 6)
	if f.Lookup(key, now.Add(120*time.Second)) != "call" { // exactly 120 s is still live (Python: > 120)
		t.Fatal("expired at exactly 120 s")
	}
	if f.Lookup(key, now.Add(240*time.Second+time.Millisecond)) != "" {
		t.Fatal("not expired just past 120 s idle")
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
