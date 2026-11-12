//go:build windows

package hwmon

import (
	"net"
	"os"
	"testing"
	"time"
)

// Read-only smoke test against this machine: values must be plausible, and the
// test's own process must be found with times, memory and executable.
func TestWindowsBackendSmoke(t *testing.T) {
	s, err := New(WindowsBackend{}, Options{ScanLimit: 8192, ProcessLimit: 8192})
	if err != nil {
		t.Fatal(err)
	}
	s.Sample()
	end := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(end) { // burn some CPU so a rate exists
	}
	time.Sleep(200 * time.Millisecond)
	out := s.Sample()
	if errs := out["errors"].([]string); len(errs) != 0 {
		t.Errorf("errors %v", errs)
	}
	if out["cpu"].(map[string]any)["logical_processors"].(int) < 1 {
		t.Error("no processors")
	}
	if cpu, ok := out["cpu"].(map[string]any)["percent"].(float64); !ok || cpu < 0 || cpu > 100 {
		t.Errorf("cpu percent %v", out["cpu"])
	}
	mem := out["memory"].(map[string]any)
	if mem["total_bytes"].(int64) <= 0 || mem["available_bytes"].(int64) > mem["total_bytes"].(int64) {
		t.Errorf("memory %v", mem)
	}
	found := false
	for _, p := range out["processes"].([]map[string]any) {
		if p["pid"].(int64) == int64(os.Getpid()) {
			found = true
			if p["resident_bytes"] == nil || p["executable"] == nil || p["cpu_percent"] == nil {
				t.Errorf("own process incomplete: %v", p)
			}
		}
	}
	if !found {
		t.Error("own process missing")
	}
	if len(out["disks"].([]map[string]any)) == 0 {
		t.Error("no disks")
	}
	if len(out["adapters"].([]map[string]any)) == 0 {
		t.Error("no adapters")
	}
	t.Logf("cpu=%v mem%%=%v swap=%v disks=%d diskio=%d adapters=%d procs=%d coverage=%v",
		out["cpu"], mem["percent"], out["swap"], len(out["disks"].([]map[string]any)), len(out["disk_io"].(map[string]any)),
		len(out["adapters"].([]map[string]any)), len(out["processes"].([]map[string]any)), out["process_coverage"])
}

func TestWindowsNetworkCountersHaveNamesAndBytes(t *testing.T) {
	rows, err := (WindowsBackend{}).NetIO()
	if err != nil {
		t.Fatal(err)
	}
	positive := false
	for _, row := range rows {
		if row.Name == "" {
			t.Fatal("Windows counter row was returned before GetIfEntry2Ex filled it")
		}
		if row.BytesRecv > 0 || row.BytesSent > 0 {
			positive = true
		}
	}
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		row, err := ifRow(i.Index)
		if err == nil && row.InterfaceIndex != uint32(i.Index) {
			t.Fatal("wrong returned interface index")
		}
	}
	if !positive {
		t.Fatal("all adapters reported zero cumulative byte counters")
	}
}
