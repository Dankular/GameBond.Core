package bond

import (
	"testing"
	"time"
)

// A line that stalls every so often is remembered for minutes, so its next stall is tolerated and counted,
// not declared down; a gap this long on a path already down is not a stall.
func TestStallIsCountedAndRemembered(t *testing.T) {
	p := &receivePath{}
	p.bfd.seen, p.bfd.up = true, true
	t0 := time.Unix(1000, 0)
	p.touch(t0)
	if !p.touch(t0.Add(250 * time.Millisecond)) {
		t.Fatal("a 250 ms quiet spell on an up path was not reported as a stall")
	}
	if p.touch(t0.Add(300 * time.Millisecond)) {
		t.Fatal("a 50 ms gap is normal, not a stall")
	}
	if limit := p.bfdLimit(t0.Add(90 * time.Second)); limit <= bfdDetectMin {
		t.Fatalf("90 s later the detect time is %v: the line's stall was forgotten", limit)
	}
	p.bfd.up = false
	p.touch(t0.Add(10 * time.Second))
	if p.touch(t0.Add(10*time.Second + 300*time.Millisecond)) {
		t.Fatal("a path already declared down must not also count a stall")
	}
}
