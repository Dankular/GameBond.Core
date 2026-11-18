package bond

import "testing"

func TestDiffservToWiFiUPRFC8325Figure1(t *testing.T) {
	for dscp := byte(0); dscp < 64; dscp++ {
		want := byte(0) // Unused / default codepoint: best effort.
		switch {
		case dscp == 8:
			want = 1
		case dscp == 24 || dscp == 32 || dscp == 26 || dscp == 28 || dscp == 30 || dscp == 34 || dscp == 36 || dscp == 38:
			want = 4
		case dscp == 40:
			want = 5
		case dscp == 46 || dscp == 44:
			want = 6
		case dscp == 18 || dscp == 20 || dscp == 22:
			want = 3
		}
		if got := DiffservToWiFiUP(dscp); got != want {
			t.Errorf("DSCP %d: UP %d, want %d", dscp, got, want)
		}
	}
	if got := DiffservToWiFiUP(64); got != 0 {
		t.Fatalf("out-of-range DSCP mapped to UP %d", got)
	}
}

func TestWiFiSafeDSCPPreservesUpstreamMarkingsExceptCS6CS7(t *testing.T) {
	for dscp := byte(0); dscp < 64; dscp++ {
		got := WiFiSafeDSCP(dscp)
		want := dscp
		if dscp == 48 || dscp == 56 { // RFC 8325: CS6/CS7 are not sourced by wireless clients.
			want = 0
		}
		if got != want {
			t.Errorf("DSCP %d changed to %d, want %d", dscp, got, want)
		}
	}
}
