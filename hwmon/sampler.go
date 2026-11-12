// Package hwmon is hardware_monitor.py: bounded, read-only resource snapshots
// with their own rate baselines. The platform sources sit behind Backend so
// the sampling logic can be replayed against the Python implementation.
package hwmon

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// KV is one named CPU time (psutil's namedtuple field order is preserved
// because the sums are order dependent).
type KV struct {
	Key   string
	Value float64
}

type Memory struct {
	Total, Available, Used int64
	Percent                float64
}

type Swap struct {
	Total, Used int64
	Percent     float64
}

// Proc is one process_iter row. Nil pointers are psutil's None (access
// denied attributes); Err mirrors a psutil.Error raised while reading it.
type Proc struct {
	PID        int64
	CreateTime *float64
	User, Sys  *float64 // cpu_times; both nil when unavailable
	RSS        *int64
	Name       string
	Exe        *string
	Threads    *int64
	Err        bool
}

type DiskCounter struct{ ReadBytes, WriteBytes, ReadCount, WriteCount int64 }

type Partition struct{ Device, Mountpoint, FSType, Opts string }

type DiskUsage struct {
	Total, Used, Free int64
	Percent           float64
}

type IfStat struct {
	Up    bool
	Speed int64
}

type NetCounter struct{ BytesRecv, BytesSent, PacketsRecv, PacketsSent int64 }

// NamedDisk / NamedNet carry map entries; the sampler sorts them by name.
type NamedDisk struct {
	Name string
	DiskCounter
}
type NamedNet struct {
	Name string
	NetCounter
}

// Backend is the psutil surface the sampler uses. Methods returning an error
// stand for psutil.Error / OSError.
type Backend interface {
	CPUTimes() []KV
	CPUCount() int
	VirtualMemory() Memory
	SwapMemory() Swap
	Processes() []Proc
	DiskIO() ([]NamedDisk, error)
	Partitions() ([]Partition, error)
	DiskUsage(mountpoint string) (DiskUsage, error)
	NetIfStats() (map[string]IfStat, error)
	NetIO() ([]NamedNet, error)
}

// GPUProvider returns the gpu dict (percent may be nil, int or float64).
type GPUProvider interface{ Sample() map[string]any }

type Options struct {
	ProcessLimit, ScanLimit, DiskLimit, HistoryLimit int            // zero = default
	Clock                                            func() float64 // monotonic seconds
	Wall                                             func() float64 // unix seconds
	GPU                                              GPUProvider
}

type Sampler struct {
	be                                 Backend
	clock, wall                        func() float64
	processLimit, scanLimit, diskLimit int
	historyLimit                       int
	mu                                 sync.Mutex
	prevTime                           *float64
	prevCPU                            *[2]float64
	prevProcs                          map[procKey]float64
	prevDisks                          map[string]map[string]int64
	prevNet                            map[string]map[string]int64
	history                            []map[string]any
	gpu                                GPUProvider
}

type procKey struct {
	pid  int64
	born float64
}

func def(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

// New validates the limits like HardwareSampler.__init__.
func New(be Backend, o Options) (*Sampler, error) {
	s := &Sampler{be: be, clock: o.Clock, wall: o.Wall, gpu: o.GPU,
		processLimit: def(o.ProcessLimit, 100), scanLimit: def(o.ScanLimit, 2048),
		diskLimit: def(o.DiskLimit, 16), historyLimit: def(o.HistoryLimit, 360)}
	if !(1 <= s.processLimit && s.processLimit <= s.scanLimit && s.scanLimit <= 8192) {
		return nil, errors.New("Invalid process sample limits")
	}
	if !(1 <= s.diskLimit && s.diskLimit <= 64) || !(1 <= s.historyLimit && s.historyLimit <= 3600) {
		return nil, errors.New("Invalid resource history limits")
	}
	if s.clock == nil {
		start := time.Now()
		s.clock = func() float64 { return time.Since(start).Seconds() + 1 }
	}
	if s.wall == nil {
		s.wall = func() float64 { return float64(time.Now().UnixNano()) / 1e9 }
	}
	return s, nil
}

func delta(cur map[string]int64, prev map[string]int64, elapsed *float64) any {
	if prev == nil || elapsed == nil || *elapsed <= 0 {
		return nil
	}
	for k, v := range cur {
		if p, ok := prev[k]; ok && v < p {
			return nil
		}
	}
	out := map[string]any{}
	for k, v := range cur {
		p, ok := prev[k]
		if !ok {
			p = v
		}
		out[k] = float64(v-p) / *elapsed
	}
	return out
}

func rate(row any, key string) (float64, bool) {
	m, ok := row.(map[string]any)
	if !ok {
		return 0, false
	}
	return m[key].(float64), true
}

func numberOrNil(v any) any {
	switch x := v.(type) {
	case float64, int, int64:
		return x
	}
	return nil
}

// Sample is HardwareSampler.sample.
func (s *Sampler) Sample() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	var elapsed *float64
	if s.prevTime != nil {
		e := now - *s.prevTime
		elapsed = &e
	}
	errs := []string{}
	if be, ok := s.be.(interface{ BeginSample() }); ok {
		be.BeginSample()
	}

	times := s.be.CPUTimes()
	total, idleV := 0.0, 0.0
	for _, kv := range times {
		if kv.Key != "guest" && kv.Key != "guest_nice" {
			total += kv.Value
		}
		if kv.Key == "idle" || kv.Key == "iowait" {
			idleV += kv.Value
		}
	}
	var cpu any
	if s.prevCPU != nil {
		td, id := total-s.prevCPU[0], idleV-s.prevCPU[1]
		if td > 0 && 0 <= id && id <= td {
			cpu = 100 * (td - id) / td
		}
	}
	s.prevCPU = &[2]float64{total, idleV}
	logical := s.be.CPUCount()
	if logical == 0 {
		logical = 1
	}
	mem := s.be.VirtualMemory()
	swap := s.be.SwapMemory()

	var procs []map[string]any
	next := map[procKey]float64{}
	examined, inaccessible := 0, 0
	var processes []Proc
	if be, ok := s.be.(interface{ LimitedProcesses(int) []Proc }); ok {
		processes = be.LimitedProcesses(s.scanLimit)
	} else {
		processes = s.be.Processes()
	}
	for _, p := range processes {
		if examined >= s.scanLimit {
			break
		}
		examined++
		if p.Err || p.CreateTime == nil || p.User == nil || p.Sys == nil {
			inaccessible++
			continue
		}
		key := procKey{p.PID, *p.CreateTime}
		pt := *p.User + *p.Sys
		var usage any
		if old, ok := s.prevProcs[key]; ok && elapsed != nil && *elapsed > 0 && pt >= old {
			u := 100 * (pt - old) / *elapsed / float64(logical)
			if u > 100 {
				u = 100
			}
			usage = u
		}
		next[key] = pt
		var rss, exe, threads any
		if p.RSS != nil {
			rss = *p.RSS
		}
		if p.Exe != nil {
			exe = *p.Exe
		}
		if p.Threads != nil {
			threads = *p.Threads
		}
		procs = append(procs, map[string]any{"pid": p.PID, "create_time": *p.CreateTime, "name": p.Name,
			"executable": exe, "cpu_percent": usage, "resident_bytes": rss, "threads": threads})
	}
	s.prevProcs = next
	key := func(r map[string]any) (float64, float64) {
		c, _ := r["cpu_percent"].(float64)
		var b float64
		if v, ok := r["resident_bytes"].(int64); ok {
			b = float64(v)
		}
		return c, b
	}
	sort.SliceStable(procs, func(i, j int) bool {
		ci, bi := key(procs[i])
		cj, bj := key(procs[j])
		if ci != cj {
			return ci > cj
		}
		return bi > bj
	})

	diskIO := map[string]any{}
	nextDisks := map[string]map[string]int64{}
	diskNames := []string{}
	if list, err := s.be.DiskIO(); err != nil {
		errs = append(errs, "Disk counters: "+err.Error())
	} else {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		if len(list) > s.diskLimit {
			list = list[:s.diskLimit]
		}
		for _, d := range list {
			cur := map[string]int64{"read_bytes": d.ReadBytes, "write_bytes": d.WriteBytes,
				"read_operations": d.ReadCount, "write_operations": d.WriteCount}
			rates := delta(cur, s.prevDisks[d.Name], elapsed)
			nextDisks[d.Name] = cur
			diskIO[d.Name] = map[string]any{"totals": cur, "rates": rates}
			diskNames = append(diskNames, d.Name)
		}
	}
	s.prevDisks = nextDisks

	disks := []map[string]any{}
	if parts, err := s.be.Partitions(); err != nil {
		errs = append(errs, "Disk inventory: "+err.Error())
	} else {
		if len(parts) > s.diskLimit {
			parts = parts[:s.diskLimit]
		}
		for _, p := range parts {
			if strings.Contains(p.Opts, "remote") || strings.HasPrefix(p.Mountpoint, `\\`) {
				continue
			}
			u, err := s.be.DiskUsage(p.Mountpoint)
			if err != nil {
				disks = append(disks, map[string]any{"device": p.Device, "mountpoint": p.Mountpoint, "error": err.Error()})
				continue
			}
			disks = append(disks, map[string]any{"device": p.Device, "mountpoint": p.Mountpoint, "filesystem": p.FSType,
				"total_bytes": u.Total, "used_bytes": u.Used, "free_bytes": u.Free, "percent": u.Percent})
		}
	}

	network := []map[string]any{}
	nextNet := map[string]map[string]int64{}
	if stats, err := s.be.NetIfStats(); err != nil {
		errs = append(errs, "Adapter counters: "+err.Error())
	} else if list, err := s.be.NetIO(); err != nil {
		errs = append(errs, "Adapter counters: "+err.Error())
	} else {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		if len(list) > 128 {
			list = list[:128]
		}
		for _, n := range list {
			cur := map[string]int64{"received_bytes": n.BytesRecv, "sent_bytes": n.BytesSent,
				"received_packets": n.PacketsRecv, "sent_packets": n.PacketsSent}
			rates := delta(cur, s.prevNet[n.Name], elapsed)
			nextNet[n.Name] = cur
			st, ok := stats[n.Name]
			var speed any
			if ok {
				speed = st.Speed
			}
			network = append(network, map[string]any{"name": n.Name, "up": ok && st.Up, "speed_mbps": speed,
				"totals": cur, "rates": rates})
		}
	}
	s.prevNet = nextNet
	s.prevTime = &now

	var gpu map[string]any
	if s.gpu != nil {
		gpu = s.gpu.Sample()
	} else {
		gpu = map[string]any{"percent": nil, "dedicated_used_bytes": nil, "available": false, "status": "unsupported"}
	}
	var diskRead, diskWrite any
	haveRates := false
	for _, n := range diskNames {
		if diskIO[n].(map[string]any)["rates"] != nil {
			haveRates = true
		}
	}
	if haveRates {
		r, w := 0.0, 0.0
		for _, n := range diskNames {
			row := diskIO[n].(map[string]any)["rates"]
			if v, ok := rate(row, "read_bytes"); ok {
				r += v
			}
			if v, ok := rate(row, "write_bytes"); ok {
				w += v
			}
		}
		diskRead, diskWrite = r, w
	}
	memory := map[string]any{"total_bytes": mem.Total, "available_bytes": mem.Available, "used_bytes": mem.Used, "percent": mem.Percent}
	swapMemory := map[string]any{"total_bytes": swap.Total, "used_bytes": swap.Used, "percent": swap.Percent}
	if be, ok := s.be.(interface{ Failures() map[string]string }); ok {
		failures := be.Failures()
		keys := make([]string, 0, len(failures))
		for key := range failures {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			errs = append(errs, key+": "+failures[key])
			switch key {
			case "cpu":
				cpu = nil
				s.prevCPU = nil
				for _, p := range procs {
					p["cpu_percent"] = nil
				}
			case "memory":
				for field := range memory {
					memory[field] = nil
				}
			case "swap":
				for field := range swapMemory {
					swapMemory[field] = nil
				}
			}
		}
	}
	hist := map[string]any{"monotonic_time": now, "cpu_percent": cpu, "memory_percent": memory["percent"],
		"memory_used_bytes": memory["used_bytes"], "disk_read_bytes_s": diskRead, "disk_write_bytes_s": diskWrite,
		"gpu_percent": numberOrNil(gpu["percent"])}
	s.history = append(s.history, hist)
	if len(s.history) > s.historyLimit {
		s.history = s.history[len(s.history)-s.historyLimit:]
	}

	allProcs := len(procs)
	returned := len(procs)
	if returned > s.processLimit {
		returned = s.processLimit
	}
	if len(procs) > s.processLimit {
		procs = procs[:s.processLimit]
	}
	if procs == nil {
		procs = []map[string]any{}
	}
	var interval any
	if elapsed != nil {
		interval = *elapsed
	}
	hcopy := append([]map[string]any(nil), s.history...)
	return map[string]any{
		"observed_at": s.wall(), "interval_seconds": interval,
		"cpu":    map[string]any{"percent": cpu, "logical_processors": logical, "normalization": "total_machine_capacity"},
		"memory": memory,
		"swap":   swapMemory,
		"disks":  disks, "disk_io": diskIO, "gpu": gpu, "adapters": network, "processes": procs,
		"process_coverage": map[string]any{"examined": examined, "returned": returned,
			"omitted": max(0, allProcs-s.processLimit), "inaccessible": inaccessible,
			"scan_limit": s.scanLimit, "scan_limit_reached": examined >= s.scanLimit},
		"history": hcopy, "errors": errs,
		"limitations": []string{"Process CPU percentages are normalized to total logical CPU capacity.",
			"First CPU/I/O samples and reset counters have unavailable rates.",
			"GPU data is unavailable when Windows counters are missing, restricted or unsupported."},
	}
}
