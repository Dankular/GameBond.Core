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
	if want := int(repairRate * 0.1); n < want*98/100 || n > want*102/100 {
		t.Fatalf("refill gave %d, want about %d", n, want)
	}
	n = 0
	for s.takeRepairToken(later.Add(time.Hour)) {
		n++
	}
	if n != int(repairBurst) {
		t.Fatalf("cap %d", n)
	}
}
