//go:build windows

package hwmon

import (
	"testing"
	"time"
)

// Real read-only Get-Counter query; the status depends on the machine's drivers.
func TestGPUSamplerRealPowerShell(t *testing.T) {
	g := NewGPUSampler(5, nil, nil, nil)
	defer g.Shutdown()
	g.Sample()
	var r map[string]any
	for i := 0; i < 300; i++ {
		if r = g.Sample(); r["sampling"] == false {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r["sampling"] != false || r["status"] == "not_sampled" {
		t.Fatalf("query did not finish: %v", r)
	}
	t.Logf("status=%v percent=%v mem=%v errors=%v", r["status"], r["percent"], r["dedicated_used_bytes"], r["errors"])
}
