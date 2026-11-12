package bond

import (
	"testing"
	"time"
)

func TestRepairTokensRefillAndCap(t *testing.T) {
	s := &Sender{}
	now := time.Now()
	n := 0
	for s.takeRepairToken(now) {
		n++
	}
	if n != int(repairBurst) {
		t.Fatalf("burst %d", n)
	}
	later := now.Add(100 * time.Millisecond)
	n = 0
	for s.takeRepairToken(later) {
		n++
	}
	if n < 295 || n > 305 {
		t.Fatalf("refill gave %d, want about 300", n)
	}
	n = 0
	for s.takeRepairToken(later.Add(time.Hour)) {
		n++
	}
	if n != int(repairBurst) {
		t.Fatalf("cap %d", n)
	}
}
