package bond

import (
	"testing"
	"time"
)

func TestPathHintLapses(t *testing.T) {
	s := &Sender{}
	now := time.Now()
	s.SetPathHint(1, true, now.Add(time.Second), "packet_loss")
	if !s.hinted(1, now) || s.hinted(0, now) {
		t.Fatal("hint not applied to the right slot")
	}
	if got := s.HintedPaths(now); len(got) != 1 || got[0] != 1 {
		t.Fatalf("%v", got)
	}
	if s.hinted(1, now.Add(2*time.Second)) {
		t.Fatal("hint outlived its ttl")
	}
	s.SetPathHint(1, false, time.Time{}, "")
	if s.hinted(1, now) {
		t.Fatal("hint not cleared")
	}
}
