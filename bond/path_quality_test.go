package bond

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
)

type qualityOp struct {
	Method string
	Args   []json.RawMessage
	Result json.RawMessage
}
type qualityTrace struct {
	Kind, Name     string
	Capacity       int
	Ceiling, Floor int
	Operations     []qualityOp
}

func decodeArg[T any](t *testing.T, op qualityOp, i int) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(op.Args[i], &v); err != nil {
		t.Fatalf("%s arg %d: %v", op.Method, i, err)
	}
	return v
}

func loadQualityVectors(t *testing.T) []qualityTrace {
	t.Helper()
	data, err := os.ReadFile("testdata/path-quality-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var traces []qualityTrace
	if err = json.NewDecoder(reader).Decode(&traces); err != nil {
		t.Fatal(err)
	}
	return traces
}

func sameFloat(a, b float64) bool { return math.Abs(a-b) <= math.Max(1e-12, math.Abs(a)*1e-12) }

func TestCopyLedgerMatchesPythonVectors(t *testing.T) {
	var ran, ops int
	for _, trace := range loadQualityVectors(t) {
		if trace.Kind != "copy_ledger" {
			continue
		}
		ran++
		t.Run(trace.Name, func(t *testing.T) {
			ledger, err := NewCopyLedger[string](trace.Capacity)
			if err != nil {
				t.Fatal(err)
			}
			for i, op := range trace.Operations {
				ops++
				switch op.Method {
				case "first":
					expected := decodeArg[[]string](t, op, 2)
					ledger.First(decodeArg[uint64](t, op, 0), decodeArg[string](t, op, 1), expected, decodeArg[float64](t, op, 3))
				case "duplicate":
					kind, lag, ok := ledger.Duplicate(decodeArg[uint64](t, op, 0), decodeArg[string](t, op, 1), decodeArg[float64](t, op, 2))
					var want []json.RawMessage
					json.Unmarshal(op.Result, &want)
					if want == nil {
						if ok {
							t.Fatalf("op %d: Python returned None, Go returned %s %v", i, kind, lag)
						}
						continue
					}
					var wantKind string
					var wantLag float64
					json.Unmarshal(want[0], &wantKind)
					json.Unmarshal(want[1], &wantLag)
					if !ok || string(kind) != wantKind || !sameFloat(lag, wantLag) {
						t.Fatalf("op %d: want %s %v got %s %v ok=%v", i, wantKind, wantLag, kind, lag, ok)
					}
				case "resolve":
					got := ledger.Resolve(decodeArg[float64](t, op, 0), decodeArg[float64](t, op, 1))
					var want [][2]string
					json.Unmarshal(op.Result, &want)
					if len(got) != len(want) {
						t.Fatalf("op %d: want %d outcomes got %d", i, len(want), len(got))
					}
					for j := range want {
						if got[j].Identity != want[j][0] || string(got[j].Outcome) != want[j][1] {
							t.Fatalf("op %d outcome %d: want %v got %v", i, j, want[j], got[j])
						}
					}
				case "stats":
					pending, resolved := ledger.Stats()
					var want map[string]int
					json.Unmarshal(op.Result, &want)
					if want["pending"] != pending || want["resolved"] != resolved {
						t.Fatalf("op %d: want %v got pending=%d resolved=%d", i, want, pending, resolved)
					}
				default:
					t.Fatalf("unknown method %q", op.Method)
				}
			}
		})
	}
	if ran == 0 || ops < 1000 {
		t.Fatalf("vectors not exercised: %d traces, %d operations", ran, ops)
	}
}

func TestMTUProberMatchesPythonVectors(t *testing.T) {
	var ran, ops int
	for _, trace := range loadQualityVectors(t) {
		if trace.Kind != "mtu_prober" {
			continue
		}
		ran++
		t.Run(trace.Name, func(t *testing.T) {
			prober, err := NewMTUProber(trace.Ceiling, trace.Floor)
			if err != nil {
				t.Fatal(err)
			}
			var nonce uint64
			next := func() uint64 { nonce++; return nonce }
			for i, op := range trace.Operations {
				ops++
				switch op.Method {
				case "due":
					got := prober.Due(decodeArg[float64](t, op, 0), next)
					var want [][2]uint64
					json.Unmarshal(op.Result, &want)
					if len(got) != len(want) {
						t.Fatalf("op %d: want %d probes got %d", i, len(want), len(got))
					}
					for j := range want {
						if got[j].Nonce != want[j][0] || uint64(got[j].Size) != want[j][1] {
							t.Fatalf("op %d probe %d: want %v got %v", i, j, want[j], got[j])
						}
					}
				case "acknowledge":
					var want bool
					json.Unmarshal(op.Result, &want)
					if got := prober.Acknowledge(decodeArg[uint64](t, op, 0), decodeArg[int](t, op, 1)); got != want {
						t.Fatalf("op %d: acknowledge want %v got %v", i, want, got)
					}
				case "stats":
					var want struct {
						PathMTU     int  `json:"path_mtu"`
						Ceiling     int  `json:"ceiling"`
						Confirmed   *int `json:"confirmed"`
						Capable     bool `json:"capable"`
						Rounds      int
						Acks        int
						FailedSizes []int `json:"failed_sizes"`
					}
					if err := json.Unmarshal(op.Result, &want); err != nil {
						t.Fatal(err)
					}
					got := prober.Stats()
					if got.PathMTU != want.PathMTU || got.Ceiling != want.Ceiling || got.Capable != want.Capable ||
						got.Rounds != want.Rounds || got.Acks != want.Acks ||
						(want.Confirmed != nil) != got.Capable || (want.Confirmed != nil && *want.Confirmed != got.Confirmed) ||
						!(len(got.FailedSizes) == 0 && len(want.FailedSizes) == 0 || reflect.DeepEqual(got.FailedSizes, want.FailedSizes)) {
						t.Fatalf("op %d: want %+v got %+v", i, want, got)
					}
				default:
					t.Fatalf("unknown method %q", op.Method)
				}
			}
		})
	}
	if ran == 0 || ops < 1000 {
		t.Fatalf("vectors not exercised: %d traces, %d operations", ran, ops)
	}
}

func TestPathQualityConstructorsRejectInvalidBounds(t *testing.T) {
	if _, err := NewCopyLedger[string](0); err == nil {
		t.Fatal("zero capacity accepted")
	}
	for _, bounds := range [][2]int{{1400, 0}, {1400, 1500}, {1400, -1}} {
		if _, err := NewMTUProber(bounds[0], bounds[1]); err == nil {
			t.Fatalf("bounds %v accepted", bounds)
		}
	}
}
