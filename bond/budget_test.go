package bond

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"testing"
)

type vectorOperation struct {
	Method string
	Args   []json.RawMessage
	Result json.RawMessage
	Stats  map[string]any
}
type budgetVector struct {
	Name             string
	Initial, Maximum float64
	Operations       []vectorOperation
}

func numberArg(op vectorOperation, index int) float64 {
	var v float64
	if err := json.Unmarshal(op.Args[index], &v); err != nil {
		panic(err)
	}
	return v
}
func sequenceArg(op vectorOperation, index int) uint64 {
	var v uint64
	if err := json.Unmarshal(op.Args[index], &v); err != nil {
		panic(err)
	}
	return v
}
func equalValue(t *testing.T, label string, want, got any) {
	t.Helper()
	if w, ok := want.(float64); ok {
		g, ok := got.(float64)
		if !ok || math.Abs(g-w) > math.Max(1e-7, math.Abs(w)*1e-10) {
			t.Fatalf("%s: want %v got %v", label, w, got)
		}
		return
	}
	if want != got {
		t.Fatalf("%s: want %v got %v", label, want, got)
	}
}
func normalized(v any) any {
	data, _ := json.Marshal(v)
	var out any
	json.Unmarshal(data, &out)
	return out
}
func TestBudgetMatchesPythonBehaviorVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/budget-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	var traces []budgetVector
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = json.NewDecoder(reader).Decode(&traces); err != nil {
		t.Fatal(err)
	}
	for _, trace := range traces {
		t.Run(trace.Name, func(t *testing.T) {
			b, err := NewBudget(trace.Initial, trace.Maximum)
			if err != nil {
				t.Fatal(err)
			}
			for i, op := range trace.Operations {
				var got any
				var err error
				switch op.Method {
				case "ready_at":
					got, err = b.ReadyAt(int(numberArg(op, 0)), numberArg(op, 1))
				case "sent":
					got, err = b.Sent(sequenceArg(op, 0), int(numberArg(op, 1)), numberArg(op, 2))
				case "acknowledge":
					got = b.Acknowledge(sequenceArg(op, 0), sequenceArg(op, 1), numberArg(op, 2), uint32(numberArg(op, 3)))
				case "expire":
					got, err = b.Expire(numberArg(op, 0))
				case "record_pacing_wait":
					err = b.RecordWait(numberArg(op, 0), numberArg(op, 1))
				case "priority_sent", "control_sent":
					err = b.UnpacedSent(int(numberArg(op, 0)), numberArg(op, 1), op.Method == "control_sent")
					got = math.Max(0, b.next-numberArg(op, 1))
				default:
					t.Fatal("unknown operation", op.Method)
				}
				if err != nil {
					t.Fatalf("operation %d %s: %v", i, op.Method, err)
				}
				var want any
				json.Unmarshal(op.Result, &want)
				equalValue(t, op.Method, want, normalized(got))
				if op.Stats != nil {
					stats := normalized(b.Stats()).(map[string]any)
					if len(stats) != len(op.Stats) {
						t.Fatalf("snapshot fields differ at %d", i)
					}
					for key, want := range op.Stats {
						equalValue(t, key, want, stats[key])
					}
				}
			}
		})
	}
}
func TestBudgetRejectsInvalidInputsAndBoundsUnpacedDebt(t *testing.T) {
	for _, rates := range [][2]float64{{0, 1}, {2, 1}, {math.NaN(), 1}, {1, math.Inf(1)}} {
		if _, err := NewBudget(rates[0], rates[1]); err == nil {
			t.Fatal("invalid rate accepted")
		}
	}
	b, _ := NewBudget(1, 10)
	if _, err := b.ReadyAt(0, 0); err == nil {
		t.Fatal("zero packet accepted")
	}
	if _, err := b.ReadyAt(100, -1); err == nil {
		t.Fatal("negative timestamp accepted")
	}
	if err := b.RecordWait(2, 1); err == nil {
		t.Fatal("reversed wait accepted")
	}
	for i := 0; i < 100; i++ {
		if err := b.UnpacedSent(1400, 1, false); err != nil {
			t.Fatal(err)
		}
	}
	if b.next > 1.100000001 || b.debtSaturations == 0 {
		t.Fatal("priority debt unbounded")
	}
	if err := b.UnpacedSent(100, .5, true); err == nil {
		t.Fatal("reversed priority timestamp accepted")
	}
	if ok, _ := b.Sent(math.MaxUint64, 100, 1); !ok {
		t.Fatal("uint64 sequence rejected")
	}
	if ok, _ := b.Sent(math.MaxUint64, 100, 1); ok {
		t.Fatal("sequence reused")
	}
	if b.Acknowledge(math.MaxUint64, 100, 1.01, 1000001) {
		t.Fatal("unbounded feedback hold accepted")
	}
}
