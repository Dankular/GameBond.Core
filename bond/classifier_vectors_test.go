package bond

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type classifierVectors struct {
	Policies map[string]struct {
		Priority, Replicate bool
		MaxAgeMS            float64 `json:"max_age_ms"`
		Capacity            int
	}
	GamePorts []uint16 `json:"game_ports"`
	Rows      []struct {
		Step   int
		Now    float64
		Packet string
		Result *struct {
			Tag                 byte
			Reason              string
			Priority, Replicate bool
			MaxAgeMS            float64 `json:"max_age_ms"`
			Capacity            int
		}
		Error  *string
		Marked *string
	}
}

// TestClassifierMatchesPythonVectors replays tools/generate_native_classifier_vectors.py:
// classification (tag, reason, queue policy) and game-UDP marking must match
// Python byte for byte, including the learned flow and fragment caches.
func TestClassifierMatchesPythonVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/classifier-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var v classifierVectors
	if err = json.NewDecoder(zr).Decode(&v); err != nil {
		t.Fatal(err)
	}
	policies := map[byte]QueuePolicy{}
	for k, p := range v.Policies {
		var tag int
		for _, c := range k {
			tag = tag*10 + int(c-'0')
		}
		policies[byte(tag)] = QueuePolicy{Priority: p.Priority, Replicate: p.Replicate, MaxAgeMS: p.MaxAgeMS, Capacity: p.Capacity}
	}
	settings := DefaultQoSSettings()
	settings.Enabled = false
	c, err := NewClassifier(policies, v.GamePorts, settings)
	if err != nil {
		t.Fatal(err)
	}
	ports := map[uint16]bool{}
	for _, p := range v.GamePorts {
		ports[p] = true
	}
	base := time.Unix(0, 0)
	classified, marked := 0, 0
	for i, row := range v.Rows {
		packet, _ := hex.DecodeString(row.Packet)
		now := base.Add(time.Duration(row.Now * float64(time.Second)))
		info, perr := ParseIPv4(packet)
		if (perr != nil) != (row.Error != nil) {
			t.Fatalf("row %d: parse error mismatch: go %v python %v", i, perr, row.Error)
		}
		if perr == nil && row.Result != nil {
			got := c.Classify(info, now)
			w := row.Result
			if got.Tag != w.Tag || got.Reason != w.Reason || got.Policy.Priority != w.Priority || got.Policy.Replicate != w.Replicate ||
				got.Policy.MaxAgeMS != w.MaxAgeMS || got.Policy.Capacity != w.Capacity {
				t.Fatalf("row %d: go %+v python %+v", i, got, *w)
			}
			classified++
		}
		out, merr := MarkGameUDP(packet, ports)
		if (merr != nil) != (row.Marked == nil) {
			t.Fatalf("row %d: mark error mismatch: go %v python marked %v", i, merr, row.Marked)
		}
		if merr == nil {
			if hex.EncodeToString(out) != *row.Marked {
				t.Fatalf("row %d: marked packet differs\n go %x\n py %s", i, out, *row.Marked)
			}
			if !bytes.Equal(out, packet) {
				marked++
			}
		}
	}
	t.Logf("%d rows: %d classified, %d marked", len(v.Rows), classified, marked)
	if classified < 300 || marked < 100 {
		t.Fatal("vectors too thin")
	}
}
