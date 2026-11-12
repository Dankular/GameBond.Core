package bond

import "testing"

func TestHealthRaisesFeedbackRejectedAfterASustainedRun(t *testing.T) {
	var h Health
	rec, rej := uint64(1000), uint64(0)
	h.Observe(rec, rej, []float64{0, 0})
	for i := 1; i <= 3; i++ {
		rec, rej = rec+10, rej+300 // the regression: copies acknowledged but refused
		alarms := h.Observe(rec, rej, []float64{0, 0})
		if (i < 3) != (len(alarms) == 0) {
			t.Fatalf("tick %d: alarms %v", i, alarms)
		}
		if i == 3 && alarms[0].Kind != "feedback_rejected" {
			t.Fatalf("wrong alarm %v", alarms)
		}
	}
	rec = rec + 500
	if got := h.Observe(rec, rej, []float64{0, 0}); len(got) != 0 {
		t.Fatalf("alarm did not clear: %v", got)
	}
}

func TestHealthIgnoresAFewRefusedFramesAndRaisesLinkTimeouts(t *testing.T) {
	var h Health
	h.Observe(0, 0, nil)
	for i := 1; i <= 5; i++ {
		if a := h.Observe(uint64(i*500), uint64(i*3), []float64{0, 0}); len(a) != 0 {
			t.Fatalf("normal noise raised %v", a)
		}
	}
	var last []Alarm
	for i := 0; i < 3; i++ {
		last = h.Observe(5000, 15, []float64{0, 1})
	}
	if len(last) != 1 || last[0].Kind != "feedback_timeout" || last[0].Link != 2 {
		t.Fatalf("link 2 timeout alarm missing: %v", last)
	}
}
