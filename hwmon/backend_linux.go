//go:build linux

package hwmon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/common"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// LinuxBackend reads OS-visible procfs/sysfs counters. Context can select
// alternate procfs/sysfs roots through gopsutil common.EnvMap (fixture tests).
type LinuxBackend struct {
	Context       context.Context
	mu            sync.Mutex
	failures      map[string]string
	sampleContext context.Context
	cancel        context.CancelFunc
}

func (b *LinuxBackend) BeginSample() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	parent := b.Context
	if parent == nil {
		parent = context.Background()
	}
	b.sampleContext, b.cancel = context.WithTimeout(parent, 3*time.Second)
	b.failures = map[string]string{}
}

func (b *LinuxBackend) ctx() context.Context {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sampleContext != nil {
		return b.sampleContext
	}
	if b.Context != nil {
		return b.Context
	}
	return context.Background()
}

func (b *LinuxBackend) failed(section string, err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures == nil {
		b.failures = map[string]string{}
	}
	b.failures[section] = err.Error()
}

func (b *LinuxBackend) Failures() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]string{}
	for key, value := range b.failures {
		out[key] = value
	}
	return out
}

func (b *LinuxBackend) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *LinuxBackend) CPUTimes() []KV {
	rows, err := cpu.TimesWithContext(b.ctx(), false)
	if err != nil {
		b.failed("cpu", err)
		return nil
	}
	if len(rows) == 0 {
		b.failed("cpu", fmt.Errorf("CPU counters unavailable"))
		return nil
	}
	v := rows[0]
	return []KV{{"user", v.User}, {"nice", v.Nice}, {"system", v.System}, {"idle", v.Idle}, {"iowait", v.Iowait}, {"irq", v.Irq}, {"softirq", v.Softirq}, {"steal", v.Steal}, {"guest", v.Guest}, {"guest_nice", v.GuestNice}}
}

func (b *LinuxBackend) CPUCount() int {
	n, err := cpu.CountsWithContext(b.ctx(), true)
	if err != nil || n < 1 {
		b.failed("cpu", fmt.Errorf("logical CPU count unavailable"))
		return runtime.NumCPU()
	}
	return n
}

func percent(value float64) float64 {v,_:=strconv.ParseFloat(strconv.FormatFloat(value,'f',1,64),64);return v}

func (b *LinuxBackend) VirtualMemory() Memory {
	v, err := mem.VirtualMemoryWithContext(b.ctx())
	if err != nil {
		b.failed("memory", err)
		return Memory{}
	}
	if v.Total == 0 {
		b.failed("memory", fmt.Errorf("memory total unavailable"))
		return Memory{}
	}
	available := v.Available
	if available > v.Total {
		available = min(v.Free, v.Total)
	}
	used := v.Total - available
	// psutil >=7.2.2 uses total - available and rounds percentages to one digit.
	return Memory{Total: int64(v.Total), Available: int64(available), Used: int64(used), Percent: percent(float64(used) * 100 / float64(v.Total))}
}

func (b *LinuxBackend) SwapMemory() Swap {
	v, err := mem.SwapMemoryWithContext(b.ctx())
	if err != nil {
		b.failed("swap", err)
		return Swap{}
	}
	return Swap{Total: int64(v.Total), Used: int64(v.Used), Percent: percent(v.UsedPercent)}
}

func (b *LinuxBackend) Processes() []Proc { return b.LimitedProcesses(8192) }

func (b *LinuxBackend) LimitedProcesses(limit int) []Proc {
	ctx := b.ctx()
	ids, err := process.PidsWithContext(ctx)
	if err != nil {
		b.failed("processes", err)
		return nil
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	limit = min(max(limit, 1), 8192)
	ids = ids[:min(limit, len(ids))]
	out := make([]Proc, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			b.failed("processes", err)
			break
		}
		row := Proc{PID: int64(id)}
		p, err := process.NewProcessWithContext(ctx, id)
		if err != nil {
			row.Err = true
			out = append(out, row)
			continue
		}
		born, err := p.CreateTimeWithContext(ctx)
		if err != nil {
			row.Err = true
			out = append(out, row)
			continue
		}
		at := float64(born) / 1000
		row.CreateTime = &at
		times, err := p.TimesWithContext(ctx)
		if err != nil {
			row.Err = true
			out = append(out, row)
			continue
		}
		row.User, row.Sys = &times.User, &times.System
		row.Name, _ = p.NameWithContext(ctx)
		if v, err := p.MemoryInfoWithContext(ctx); err == nil {
			rss := int64(v.RSS)
			row.RSS = &rss
		}
		if v, err := p.ExeWithContext(ctx); err == nil {
			row.Exe = &v
		}
		if v, err := p.NumThreadsWithContext(ctx); err == nil {
			threads := int64(v)
			row.Threads = &threads
		}
		out = append(out, row)
	}
	return out
}

func (b *LinuxBackend) DiskIO() ([]NamedDisk, error) {
	rows, err := disk.IOCountersWithContext(b.ctx())
	if err != nil {
		return nil, err
	}
	out := make([]NamedDisk, 0, len(rows))
	for name, v := range rows {
		out = append(out, NamedDisk{Name: name, DiskCounter: DiskCounter{int64(v.ReadBytes), int64(v.WriteBytes), int64(v.ReadCount), int64(v.WriteCount)}})
	}
	return out, nil
}

func remoteFS(kind, device string) bool {
	switch strings.ToLower(kind) {
	case "nfs", "nfs4", "cifs", "smb", "smbfs", "fuse.sshfs", "sshfs", "9p", "ceph", "glusterfs", "afs":
		return true
	}
	return strings.HasPrefix(device, "//") || strings.Contains(device, ":/")
}

func (b *LinuxBackend) Partitions() ([]Partition, error) {
	rows, err := disk.PartitionsWithContext(b.ctx(), false)
	if err != nil {
		return nil, err
	}
	out := make([]Partition, 0, len(rows))
	for _, v := range rows {
		opts := strings.Join(v.Opts, ",")
		if remoteFS(v.Fstype, v.Device) {
			opts += ",remote"
		}
		out = append(out, Partition{Device: v.Device, Mountpoint: v.Mountpoint, FSType: v.Fstype, Opts: opts})
	}
	return out, nil
}

func (b *LinuxBackend) DiskUsage(mountpoint string) (DiskUsage, error) {
	v, err := disk.UsageWithContext(b.ctx(), mountpoint)
	if err != nil {
		return DiskUsage{}, err
	}
	return DiskUsage{Total: int64(v.Total), Used: int64(v.Used), Free: int64(v.Free), Percent: percent(v.UsedPercent)}, nil
}

func (b *LinuxBackend) sysRoot() string {
	if env, ok := b.ctx().Value(common.EnvKey).(common.EnvMap); ok && env[common.HostSysEnvKey] != "" {
		return env[common.HostSysEnvKey]
	}
	if path := os.Getenv("HOST_SYS"); path != "" {
		return path
	}
	return "/sys"
}

func (b *LinuxBackend) NetIfStats() (map[string]IfStat, error) {
	rows, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[string]IfStat{}
	for _, v := range rows {
		var speed int64
		if raw, err := os.ReadFile(filepath.Join(b.sysRoot(), "class/net", v.Name, "speed")); err == nil {
			speed, _ = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
			speed = max(0, speed)
		}
		out[v.Name] = IfStat{Up:v.Flags&net.FlagUp!=0 && v.Flags&net.FlagRunning!=0, Speed: speed}
	}
	return out, nil
}

func (b *LinuxBackend) NetIO() ([]NamedNet, error) {
	rows, err := psnet.IOCountersWithContext(b.ctx(), true)
	if err != nil {
		return nil, err
	}
	out := make([]NamedNet, 0, len(rows))
	for _, v := range rows {
		out = append(out, NamedNet{Name: v.Name, NetCounter: NetCounter{int64(v.BytesRecv), int64(v.BytesSent), int64(v.PacketsRecv), int64(v.PacketsSent)}})
	}
	return out, nil
}
