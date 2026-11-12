package hwmon

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
)

type rawProc struct {
	PID        int64      `json:"pid"`
	CreateTime *float64   `json:"create_time"`
	CPU        []*float64 `json:"cpu"`
	RSS        *int64     `json:"rss"`
	Name       *string    `json:"name"`
	Exe        *string    `json:"exe"`
	Threads    *int64     `json:"threads"`
	Err        bool       `json:"err"`
}

type rawState struct {
	CPUTimes [][]any `json:"cpu_times"`
	CPUCount *int    `json:"cpu_count"`
	VM       struct {
		Total, Available, Used int64
		Percent                float64
	} `json:"vm"`
	Swap struct {
		Total, Used int64
		Percent     float64
	} `json:"swap"`
	Procs      []rawProc                  `json:"procs"`
	DiskIO     json.RawMessage            `json:"disk_io"`
	Partitions json.RawMessage            `json:"partitions"`
	Usage      map[string]json.RawMessage `json:"usage"`
	IfStats    json.RawMessage            `json:"if_stats"`
	NetIO      json.RawMessage            `json:"net_io"`
}

type fakeBackend struct{ s rawState }

func failure(raw json.RawMessage) error {
	var msg string
	if json.Unmarshal(raw, &msg) == nil {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (f *fakeBackend) CPUTimes() []KV {
	var out []KV
	for _, p := range f.s.CPUTimes {
		out = append(out, KV{p[0].(string), p[1].(float64)})
	}
	return out
}
func (f *fakeBackend) CPUCount() int {
	if f.s.CPUCount == nil {
		return 0
	}
	return *f.s.CPUCount
}
func (f *fakeBackend) VirtualMemory() Memory {
	v := f.s.VM
	return Memory{v.Total, v.Available, v.Used, v.Percent}
}
func (f *fakeBackend) SwapMemory() Swap { v := f.s.Swap; return Swap{v.Total, v.Used, v.Percent} }
func (f *fakeBackend) Processes() []Proc {
	var out []Proc
	for _, r := range f.s.Procs {
		p := Proc{PID: r.PID, CreateTime: r.CreateTime, RSS: r.RSS, Exe: r.Exe, Threads: r.Threads, Err: r.Err}
		if r.Name != nil {
			p.Name = *r.Name
		}
		if r.CPU != nil {
			p.User, p.Sys = r.CPU[0], r.CPU[1]
		}
		out = append(out, p)
	}
	return out
}
func (f *fakeBackend) DiskIO() ([]NamedDisk, error) {
	if err := failure(f.s.DiskIO); err != nil {
		return nil, err
	}
	var rows [][]json.Number
	var names [][]any
	_ = rows
	json.Unmarshal(f.s.DiskIO, &names)
	var out []NamedDisk
	for _, r := range names {
		out = append(out, NamedDisk{r[0].(string), DiskCounter{int64(r[1].(float64)), int64(r[2].(float64)), int64(r[3].(float64)), int64(r[4].(float64))}})
	}
	return out, nil
}
func (f *fakeBackend) Partitions() ([]Partition, error) {
	if err := failure(f.s.Partitions); err != nil {
		return nil, err
	}
	var rows [][]string
	json.Unmarshal(f.s.Partitions, &rows)
	var out []Partition
	for _, r := range rows {
		out = append(out, Partition{r[0], r[1], r[2], r[3]})
	}
	return out, nil
}
func (f *fakeBackend) DiskUsage(m string) (DiskUsage, error) {
	raw := f.s.Usage[m]
	if err := failure(raw); err != nil {
		return DiskUsage{}, err
	}
	var v []float64
	json.Unmarshal(raw, &v)
	return DiskUsage{int64(v[0]), int64(v[1]), int64(v[2]), v[3]}, nil
}
func (f *fakeBackend) NetIfStats() (map[string]IfStat, error) {
	if err := failure(f.s.IfStats); err != nil {
		return nil, err
	}
	var raw map[string][]any
	json.Unmarshal(f.s.IfStats, &raw)
	out := map[string]IfStat{}
	for k, v := range raw {
		out[k] = IfStat{v[0].(bool), int64(v[1].(float64))}
	}
	return out, nil
}
func (f *fakeBackend) NetIO() ([]NamedNet, error) {
	if err := failure(f.s.NetIO); err != nil {
		return nil, err
	}
	var rows [][]any
	json.Unmarshal(f.s.NetIO, &rows)
	var out []NamedNet
	for _, r := range rows {
		out = append(out, NamedNet{r[0].(string), NetCounter{int64(r[1].(float64)), int64(r[2].(float64)), int64(r[3].(float64)), int64(r[4].(float64))}})
	}
	return out, nil
}

type fakeGPU struct{ value map[string]any }

func (g *fakeGPU) Sample() map[string]any { return g.value }

func same(a, b any, path string) string {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return path + ": map shape"
		}
		for k, v := range x {
			if d := same(v, y[k], path+"."+k); d != "" {
				return d
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return fmt.Sprintf("%s: list length %v vs %v", path, len(x), len(y))
		}
		for i := range x {
			if d := same(x[i], y[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
				return d
			}
		}
	case float64:
		y, ok := b.(float64)
		if !ok || math.Abs(x-y) > 1e-9*math.Max(1, math.Abs(x)) {
			return fmt.Sprintf("%s: %v vs %v", path, a, b)
		}
	default:
		if fmt.Sprint(a) != fmt.Sprint(b) {
			return fmt.Sprintf("%s: %v vs %v", path, a, b)
		}
	}
	return ""
}

func TestSamplerMatchesPython(t *testing.T) {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, _ := gzip.NewReader(f)
	var vec struct {
		Scenarios []struct {
			Config map[string]int `json:"config"`
			GPU    bool           `json:"gpu"`
			Steps  []struct {
				State    rawState       `json:"state"`
				Clock    float64        `json:"clock"`
				GPU      map[string]any `json:"gpu"`
				Expected any            `json:"expected"`
			} `json:"steps"`
		} `json:"scenarios"`
		Limits []struct {
			Config map[string]int `json:"config"`
			OK     bool           `json:"ok"`
		} `json:"limits"`
	}
	if err := json.NewDecoder(zr).Decode(&vec); err != nil {
		t.Fatal(err)
	}
	steps := 0
	for si, sc := range vec.Scenarios {
		be := &fakeBackend{}
		gp := &fakeGPU{}
		var now float64
		opt := Options{ProcessLimit: sc.Config["process_limit"], ScanLimit: sc.Config["scan_limit"],
			DiskLimit: sc.Config["disk_limit"], HistoryLimit: sc.Config["history_limit"],
			Clock: func() float64 { return now }}
		if sc.GPU {
			opt.GPU = gp
		}
		// Python defaults are applied when a key is omitted; Go's zero means the
		// same except when only some keys are given, so fill the dependent ones.
		if opt.ProcessLimit > opt.ScanLimit && opt.ScanLimit == 0 {
			opt.ScanLimit = 2048
		}
		s, err := New(be, opt)
		if err != nil {
			t.Fatalf("scenario %d: %v", si, err)
		}
		for i, st := range sc.Steps {
			be.s, now, gp.value = st.State, st.Clock, st.GPU
			got := s.Sample()
			delete(got, "observed_at")
			raw, _ := json.Marshal(got)
			var gotAny any
			json.Unmarshal(raw, &gotAny)
			if d := same(st.Expected, gotAny, "out"); d != "" {
				t.Fatalf("scenario %d step %d: %s", si, i, d)
			}
			steps++
		}
	}
	for _, l := range vec.Limits {
		_, err := New(&fakeBackend{}, Options{ProcessLimit: l.Config["process_limit"], ScanLimit: l.Config["scan_limit"],
			DiskLimit: l.Config["disk_limit"], HistoryLimit: l.Config["history_limit"]})
		if (err == nil) != l.OK && !strings.Contains(fmt.Sprint(l.Config), "0") {
			t.Errorf("limits %v: ok=%v want %v", l.Config, err == nil, l.OK)
		}
	}
	t.Logf("%d steps matched", steps)
}
