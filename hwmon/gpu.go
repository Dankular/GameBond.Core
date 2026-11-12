package hwmon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// GPUScript is gpu_monitor.GPU_SCRIPT, unchanged: read-only Get-Counter queries.
const GPUScript = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$issues=@();$usage=$null;$memory=$null;$count=0
try {
 $samples=@((Get-Counter '\GPU Engine(*)\Utilization Percentage' -MaxSamples 1 -ErrorAction Stop).CounterSamples |
  Where-Object {$_.Status -eq 0} | Select-Object -First 8192)
 $engines=@($samples | Group-Object {$_.InstanceName -replace '^pid_\d+_',''} |
  ForEach-Object {($_.Group | Measure-Object CookedValue -Sum).Sum})
 if($engines.Count){$usage=[math]::Min(100,[math]::Max(0,($engines | Measure-Object -Maximum).Maximum));$count=$engines.Count}
} catch {$issues+= $_.Exception.Message}
try {
 $samples=@((Get-Counter '\GPU Adapter Memory(*)\Dedicated Usage' -MaxSamples 1 -ErrorAction Stop).CounterSamples |
  Where-Object {$_.Status -eq 0 -and $_.InstanceName -ne '_total'} | Select-Object -First 64)
 if($samples.Count){$memory=[long]($samples | Measure-Object CookedValue -Sum).Sum}
} catch {$issues+=$_.Exception.Message}
ConvertTo-Json -InputObject ([pscustomobject]@{percent=$usage;dedicated_used_bytes=$memory;engine_count=$count;errors=$issues}) -Depth 4 -Compress
`

// Runner executes the script and returns stdout (exit code != 0 is an error).
type Runner func(ctx context.Context, script string) ([]byte, error)

// PowerShellRunner runs the script with powershell.exe, hidden, 12 s limit.
func PowerShellRunner(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	hideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("Windows GPU counter query timed out")
		}
		return nil, errors.New("Windows GPU counters are unavailable")
	}
	return out.Bytes(), nil
}

// GPUSampler is WindowsGPUSampler: a cached sample refreshed off the caller's
// thread at most every Interval seconds.
type GPUSampler struct {
	interval float64
	run      Runner
	clock    func() float64
	wall     func() float64

	mu          sync.Mutex
	lastStarted *float64
	busy        bool
	latest      map[string]any
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func NewGPUSampler(interval float64, run Runner, clock, wall func() float64) *GPUSampler {
	if interval == 0 {
		interval = 5
	}
	if run == nil {
		run = PowerShellRunner
	}
	if clock == nil {
		start := time.Now()
		clock = func() float64 { return time.Since(start).Seconds() + 1 }
	}
	if wall == nil {
		wall = func() float64 { return float64(time.Now().UnixNano()) / 1e9 }
	}
	g := &GPUSampler{interval: interval, run: run, clock: clock, wall: wall,
		latest: map[string]any{"percent": nil, "dedicated_used_bytes": nil, "dedicated_total_bytes": nil,
			"available": false, "status": "not_sampled", "errors": []string{}}}
	g.ctx, g.cancel = context.WithCancel(context.Background())
	return g
}

// Sample implements GPUProvider.
func (g *GPUSampler) Sample() map[string]any {
	now := g.clock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.busy && g.ctx.Err() == nil && (g.lastStarted == nil || now-*g.lastStarted >= g.interval) {
		g.busy = true
		g.lastStarted = &now
		g.wg.Add(1)
		go g.collect()
	}
	out := make(map[string]any, len(g.latest)+1)
	for k, v := range g.latest {
		out[k] = v
	}
	if errs, ok := out["errors"].([]string); ok {
		out["errors"] = append([]string(nil), errs...)
	}
	out["sampling"] = g.busy
	if seen, ok := out["observed_monotonic"].(float64); ok && now-seen > math.Max(15, g.interval*3) {
		out["percent"], out["dedicated_used_bytes"], out["available"], out["status"] = nil, nil, false, "stale"
	}
	return out
}

func (g *GPUSampler) collect() {
	defer g.wg.Done()
	result := g.query()
	g.mu.Lock()
	g.latest, g.busy = result, false
	g.mu.Unlock()
}

func failed(err error, clock func() float64) map[string]any {
	return map[string]any{"percent": nil, "dedicated_used_bytes": nil, "dedicated_total_bytes": nil,
		"available": false, "status": "unavailable", "errors": []string{err.Error()}, "observed_monotonic": clock()}
}

func (g *GPUSampler) query() map[string]any {
	output, err := g.run(g.ctx, GPUScript)
	if err != nil {
		return failed(err, g.clock)
	}
	output = bytes.TrimPrefix(output, []byte("\xef\xbb\xbf"))
	var rec map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(output))
	dec.UseNumber()
	if err := dec.Decode(&rec); err != nil || rec == nil {
		return failed(errors.New("invalid GPU counter output"), g.clock)
	}
	var percent, memory any
	if raw, ok := rec["percent"]; ok && string(raw) != "null" {
		var n json.Number
		if raw[0] == '"' || json.Unmarshal(raw, &n) != nil {
			return failed(errors.New("Invalid GPU utilization counter"), g.clock)
		}
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil || f < 0 || f > 100 {
			return failed(errors.New("Invalid GPU utilization counter"), g.clock)
		}
		percent = f
	}
	if raw, ok := rec["dedicated_used_bytes"]; ok && string(raw) != "null" {
		var n json.Number
		v, err := int64(0), error(nil)
		if raw[0] == '"' {
			err = errors.New("string")
		} else if err = json.Unmarshal(raw, &n); err == nil {
			v, err = strconv.ParseInt(string(n), 10, 64) // a float is not an int, as in Python
		}
		if err != nil || v < 0 {
			return failed(errors.New("Invalid GPU memory counter"), g.clock)
		}
		memory = v
	}
	engines := 0
	if raw, ok := rec["engine_count"]; ok {
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			if v, err := strconv.Atoi(string(n)); err == nil {
				engines = v
			}
		}
	}
	errs := []string{}
	if raw, ok := rec["errors"]; ok {
		var list []string
		if json.Unmarshal(raw, &list) == nil {
			errs = list
		}
	}
	available := percent != nil || memory != nil
	status := "unavailable"
	if available {
		status = "available"
	}
	return map[string]any{"percent": percent, "dedicated_used_bytes": memory, "dedicated_total_bytes": nil,
		"engine_count": engines, "available": available, "status": status, "metric": "busiest_engine_percent",
		"errors": errs, "observed_at": g.wall(), "observed_monotonic": g.clock(),
		"limitations": []string{"GPU usage is the busiest engine across adapters.",
			"Dedicated memory is usage, not adapter capacity. Counter names are English and can be unavailable on localized systems."}}
}

// Shutdown cancels a running query and stops new ones.
func (g *GPUSampler) Shutdown() {
	g.cancel()
	g.wg.Wait()
}
