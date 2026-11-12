//go:build windows

package hwmon

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsBackend reads the same Windows sources psutil uses, read-only.
type WindowsBackend struct{}

var (
	kernel32   = windows.NewLazySystemDLL("kernel32.dll")
	psapi      = windows.NewLazySystemDLL("psapi.dll")
	pGetTimes  = kernel32.NewProc("GetSystemTimes")
	pGlobalMem = kernel32.NewProc("GlobalMemoryStatusEx")
	pProcMem   = psapi.NewProc("GetProcessMemoryInfo")
)

func ft(f windows.Filetime) float64 {
	return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) / 1e7
}

func (WindowsBackend) CPUTimes() []KV {
	var idle, kernel, user windows.Filetime
	r, _, _ := pGetTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return nil
	}
	// psutil: user = user, system = kernel - idle (kernel time includes idle).
	return []KV{{"user", ft(user)}, {"system", ft(kernel) - ft(idle)}, {"idle", ft(idle)}}
}

func (WindowsBackend) CPUCount() int {
	return int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS))
}

type memoryStatusEx struct {
	Length, Load                         uint32
	TotalPhys, AvailPhys                 uint64
	TotalPageFile, AvailPageFile         uint64
	TotalVirtual, AvailVirtual, AvailExt uint64
}

func memStatus() (memoryStatusEx, bool) {
	m := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r, _, _ := pGlobalMem.Call(uintptr(unsafe.Pointer(&m)))
	return m, r != 0
}

func (WindowsBackend) VirtualMemory() Memory {
	m, ok := memStatus()
	if !ok {
		return Memory{}
	}
	return Memory{Total: int64(m.TotalPhys), Available: int64(m.AvailPhys), Used: int64(m.TotalPhys - m.AvailPhys), Percent: float64(m.Load)}
}

// SwapMemory is the page file only: commit limit minus physical memory.
func (WindowsBackend) SwapMemory() Swap {
	m, ok := memStatus()
	if !ok || m.TotalPageFile <= m.TotalPhys {
		return Swap{}
	}
	total := m.TotalPageFile - m.TotalPhys
	free := uint64(0)
	if m.AvailPageFile > m.AvailPhys {
		free = m.AvailPageFile - m.AvailPhys
	}
	if free > total {
		free = total
	}
	used := total - free
	return Swap{Total: int64(total), Used: int64(used), Percent: math.Round(float64(used)/float64(total)*1000) / 10}
}

func (WindowsBackend) Processes() []Proc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var out []Proc
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := Proc{PID: int64(e.ProcessID), Name: windows.UTF16ToString(e.ExeFile[:])}
		threads := int64(e.Threads)
		p.Threads = &threads
		fillProc(&p, e.ProcessID)
		out = append(out, p)
	}
	return out
}

func fillProc(p *Proc, pid uint32) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return // protected or exited: counted as inaccessible
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return
	}
	birth := float64(created.Nanoseconds()) / 1e9
	u, k := ft(user), ft(kernel)
	p.CreateTime, p.User, p.Sys = &birth, &u, &k
	var counters struct {
		Cb, PageFaults                                           uint32
		PeakWorkingSet, WorkingSet, QuotaPeakPaged, QuotaPaged   uintptr
		QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile uintptr
	}
	counters.Cb = uint32(unsafe.Sizeof(counters))
	if r, _, _ := pProcMem.Call(uintptr(h), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Cb)); r != 0 {
		rss := int64(counters.WorkingSet)
		p.RSS = &rss
	}
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		exe := windows.UTF16ToString(buf[:n])
		p.Exe = &exe
	}
}

type diskPerformance struct {
	BytesRead, BytesWritten, ReadTime, WriteTime, IdleTime int64
	ReadCount, WriteCount, QueueDepth, SplitCount          uint32
	QueryTime, StorageDeviceNumber                         int64
	StorageManagerName                                     [8]uint16
	_                                                      [8]byte
}

const ioctlDiskPerformance = 0x70020

func (WindowsBackend) DiskIO() ([]NamedDisk, error) {
	var out []NamedDisk
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("PhysicalDrive%d", i)
		path, _ := windows.UTF16PtrFromString(`\\.\` + name)
		h, err := windows.CreateFile(path, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			continue
		}
		var perf diskPerformance
		var n uint32
		err = windows.DeviceIoControl(h, ioctlDiskPerformance, nil, 0, (*byte)(unsafe.Pointer(&perf)), uint32(unsafe.Sizeof(perf)), &n, nil)
		windows.CloseHandle(h)
		if err != nil {
			continue
		}
		out = append(out, NamedDisk{name, DiskCounter{perf.BytesRead, perf.BytesWritten, int64(perf.ReadCount), int64(perf.WriteCount)}})
	}
	return out, nil
}

func (WindowsBackend) Partitions() ([]Partition, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	old := windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS)
	defer windows.SetErrorMode(old)
	var out []Partition
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+i)
		rootp, _ := windows.UTF16PtrFromString(root)
		kind := ""
		switch windows.GetDriveType(rootp) {
		case windows.DRIVE_FIXED:
			kind = "fixed"
		case windows.DRIVE_REMOVABLE:
			kind = "removable"
		case windows.DRIVE_CDROM:
			kind = "cdrom"
		case windows.DRIVE_REMOTE:
			out = append(out, Partition{root, root, "", "rw,remote"}) // never touched: could block
			continue
		default:
			continue
		}
		var fs [64]uint16
		var flags uint32
		if windows.GetVolumeInformation(rootp, nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs))) != nil {
			continue // no media
		}
		opts := "rw"
		if flags&0x00080000 != 0 { // FILE_READ_ONLY_VOLUME
			opts = "ro"
		}
		out = append(out, Partition{root, root, windows.UTF16ToString(fs[:]), opts + "," + kind})
	}
	return out, nil
}

func (WindowsBackend) DiskUsage(mount string) (DiskUsage, error) {
	p, err := windows.UTF16PtrFromString(mount)
	if err != nil {
		return DiskUsage{}, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return DiskUsage{}, err
	}
	if total == 0 {
		return DiskUsage{}, errors.New("volume reports zero size")
	}
	used := total - free
	return DiskUsage{int64(total), int64(used), int64(free), math.Round(float64(used)/float64(total)*1000) / 10}, nil
}

func ifRow(index int) (windows.MibIfRow2, error) {
	row := windows.MibIfRow2{InterfaceIndex: uint32(index)}
	err := windows.GetIfEntry2Ex(0, &row)
	return row, err
}

func (WindowsBackend) NetIfStats() (map[string]IfStat, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[string]IfStat{}
	for _, i := range ifs {
		row, err := ifRow(i.Index)
		if err != nil {
			continue
		}
		out[windows.UTF16ToString(row.Alias[:])] = IfStat{Up: row.OperStatus == 1, Speed: int64(row.ReceiveLinkSpeed / 1_000_000)}
	}
	return out, nil
}

func (WindowsBackend) NetIO() ([]NamedNet, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []NamedNet
	for _, i := range ifs {
		row, err := ifRow(i.Index)
		if err != nil {
			continue
		}
		out = append(out, NamedNet{windows.UTF16ToString(row.Alias[:]), NetCounter{
			int64(row.InOctets), int64(row.OutOctets),
			int64(row.InUcastPkts + row.InNUcastPkts), int64(row.OutUcastPkts + row.OutNUcastPkts)}})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

var _ = syscall.Errno(0)
var _ Backend = WindowsBackend{}
