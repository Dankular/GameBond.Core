package bond

import (
	"bytes"
	"math"
	"testing"
	"time"
)

func reorderForTest(t *testing.T, c ReorderConfig) *Reorder {
	t.Helper()
	r, e := NewReorder(c)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestIndependentOrderingAndImmediateLateFirstArrival(t *testing.T) {
	r := reorderForTest(t, DefaultReorderConfig())
	now := time.Now()
	if got := r.Push(1, 1, []byte("b"), now); len(got) != 0 {
		t.Fatal("gap delivered early")
	}
	if got := r.Push(2, 0, []byte("other"), now); len(got) != 1 {
		t.Fatal("unrelated flow blocked")
	}
	got := r.Push(1, 0, []byte("a"), now)
	if len(got) != 2 || string(got[0])+string(got[1]) != "ab" {
		t.Fatal("ordering differs")
	}
	r.Push(1, 3, []byte("d"), now)
	got = r.Poll(now.Add(31 * time.Millisecond))
	if len(got) != 1 || string(got[0]) != "d" {
		t.Fatal("deadline did not release")
	}
	got = r.Push(1, 2, []byte("c"), now.Add(32*time.Millisecond))
	if len(got) != 1 {
		t.Fatal("manufactured loss of a late first arrival")
	}
	if got = r.Push(1, 2, []byte("c"), now.Add(33*time.Millisecond)); len(got) != 0 {
		t.Fatal("repair duplicate delivered twice")
	}
	if r.Stats().Late != 1 || r.Stats().Skipped != 1 {
		t.Fatal(r.Stats())
	}
}
func TestGapDeadlineCannotBeExtendedAndRepairRequestsAreBounded(t *testing.T) {
	r := reorderForTest(t, DefaultReorderConfig())
	now := time.Now()
	r.Push(1, 1000000000000, []byte("x"), now)
	r.Push(1, 1000000000001, []byte("y"), now.Add(25*time.Millisecond))
	if len(r.Missing(now.Add(20*time.Millisecond), 15*time.Millisecond, 4, nil)) != 4 {
		t.Fatal("missing range unbounded or absent")
	}
	got := r.Poll(now.Add(30 * time.Millisecond))
	if len(got) != 2 {
		t.Fatal("later arrival extended the first gap deadline")
	}
}
func TestReorderCapacityOwnershipAndExpiration(t *testing.T) {
	c := DefaultReorderConfig()
	c.MaxFlows = 2
	c.MaxPackets = 2
	c.MaxBytes = 4
	r := reorderForTest(t, c)
	now := time.Now()
	p := []byte("ab")
	r.Push(1, 2, p, now)
	p[0] = 'z'
	r.Push(2, 2, []byte("cd"), now.Add(time.Millisecond))
	got := r.Push(1, 1, []byte("q"), now.Add(2*time.Millisecond))
	if len(got) != 2 || string(got[0]) != "q" || string(got[1]) != "ab" {
		t.Fatal("capacity skipped predecessor or borrowed buffered memory", got)
	}
	r.Push(3, 1, []byte("ef"), now)
	s := r.Stats()
	if s.Flows != 2 || s.EvictedFlows != 1 || s.BufferedBytes > 4 || s.BufferedPackets > 2 {
		t.Fatal(s)
	}
	r.Poll(now.Add(121 * time.Second))
	s = r.Stats()
	if s.Flows != 0 || s.BufferedPackets != 0 || s.BufferedBytes != 0 || s.DroppedPackets != 2 {
		t.Fatal(s)
	}
}
func TestSequenceMaxDoesNotWrapOrIterateMissingRange(t *testing.T) {
	c := DefaultReorderConfig()
	c.Timeout = 0
	r := reorderForTest(t, c)
	now := time.Now()
	if len(r.Push(1, math.MaxUint64, []byte("end"), now)) != 1 {
		t.Fatal("max sequence not released")
	}
	if len(r.Push(1, math.MaxUint64, []byte("end"), now)) != 0 {
		t.Fatal("max duplicate delivered")
	}
	if len(r.Push(1, math.MaxUint64-1, []byte("late"), now)) != 1 {
		t.Fatal("late arrival suppressed")
	}
	if r.Stats().Skipped != math.MaxUint64 {
		t.Fatal("gap accounting overflow")
	}
}
func BenchmarkOrderedReceive(b *testing.B) {
	r, _ := NewReorder(DefaultReorderConfig())
	payload := bytes.Repeat([]byte{1}, 1200)
	now := time.Now()
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Push(1, uint64(i), payload, now)
	}
}
