package bond

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Durable outage log. One fixed 24-byte record per event, appended to segment files that
// rotate at outageSegmentBytes; the oldest segment is deleted once there are more than
// outageMaxSegments, so disk use is capped (about 128 MiB, roughly 5.6 million events)
// however long the client runs. A background goroutine writes; the packet loop only does a
// non-blocking channel send, and an event that finds the queue full is dropped and counted.
//
// Record layout, little endian:
//
//	0  seq     uint64
//	8  at_ms   int64
//	16 down_us uint32 (saturating)
//	20 slot    uint8
//	21 kind    uint8  index into outageKinds
//	22 cause   uint8  index into outageCauses, 255 unknown
//	23 reserved
//	24 source  [16]byte  zero padded, truncated; component events
//	40 note    [16]byte  zero padded, truncated; component events
const (
	outageRecordSize   = 56
	outageSegmentBytes = 8 << 20
	outageMaxSegments  = 16
	outageQueue        = 4096
	outageFlushEvery   = time.Second
	outageSegmentPre   = "ojrnl-"
	outageSegmentExt   = ".bin"
)

// OutageLogInfo reports the durable log's health.
type OutageLogInfo struct {
	Enabled  bool   `json:"enabled"`
	Written  uint64 `json:"written"`
	Dropped  uint64 `json:"dropped"`
	Errors   uint64 `json:"errors"`
	Segments int64  `json:"segments"`
}

type outageLog struct {
	dir        string
	segBytes   int64
	maxSeg     int
	ch         chan OutageEvent
	done       chan struct{}
	written    atomic.Uint64
	dropped    atomic.Uint64
	errors     atomic.Uint64
	segments   atomic.Int64
	f          *os.File
	w          *bufio.Writer
	size       int64
	lastSegMS  int64
	closedFlag atomic.Bool
}

func openOutageLog(dir string, segBytes int64, maxSeg int) (*outageLog, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	l := &outageLog{dir: dir, segBytes: segBytes, maxSeg: maxSeg, ch: make(chan OutageEvent, outageQueue), done: make(chan struct{})}
	l.segments.Store(int64(len(l.listSegments())))
	go l.run()
	return l, nil
}

// enqueue never blocks.
func (l *outageLog) enqueue(e OutageEvent) {
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

func (l *outageLog) info() OutageLogInfo {
	return OutageLogInfo{Enabled: true, Written: l.written.Load(), Dropped: l.dropped.Load(), Errors: l.errors.Load(), Segments: l.segments.Load()}
}

func (l *outageLog) close() {
	if l.closedFlag.Swap(true) {
		return
	}
	close(l.ch)
	<-l.done
}

func (l *outageLog) run() {
	defer close(l.done)
	tick := time.NewTicker(outageFlushEvery)
	defer tick.Stop()
	defer l.closeFile()
	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				return
			}
			l.write(e)
		case <-tick.C:
			if l.w != nil && l.w.Flush() != nil {
				l.errors.Add(1)
			}
		}
	}
}

func (l *outageLog) closeFile() {
	if l.w != nil {
		l.w.Flush()
	}
	if l.f != nil {
		l.f.Close()
	}
	l.f, l.w = nil, nil
}

func (l *outageLog) write(e OutageEvent) {
	if l.f == nil || l.size+outageRecordSize > l.segBytes {
		if !l.rotate(e.AtMS) {
			l.errors.Add(1)
			return
		}
	}
	var rec [outageRecordSize]byte
	binary.LittleEndian.PutUint64(rec[0:], e.Seq)
	binary.LittleEndian.PutUint64(rec[8:], uint64(e.AtMS))
	us := e.DownMS * 1000
	if us < 0 || math.IsNaN(us) {
		us = 0
	}
	if us > math.MaxUint32 {
		us = math.MaxUint32
	}
	binary.LittleEndian.PutUint32(rec[16:], uint32(us))
	rec[20] = uint8(int8(e.Slot))
	rec[21] = kindID(e.Kind)
	rec[22] = causeID(e.Cause)
	copy(rec[24:40], e.Source)
	copy(rec[40:56], e.Note)
	if _, err := l.w.Write(rec[:]); err != nil {
		l.errors.Add(1)
		return
	}
	l.size += outageRecordSize
	l.written.Add(1)
}

func (l *outageLog) listSegments() []string {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, outageSegmentPre) && strings.HasSuffix(n, outageSegmentExt) {
			out = append(out, n)
		}
	}
	sort.Strings(out) // names carry a zero-padded timestamp, so lexical order is time order
	return out
}

// rotate closes the current segment, opens a new one, and deletes the oldest beyond the cap.
func (l *outageLog) rotate(atMS int64) bool {
	l.closeFile()
	if atMS <= l.lastSegMS {
		atMS = l.lastSegMS + 1 // names stay unique and ordered
	}
	l.lastSegMS = atMS
	name := fmt.Sprintf("%s%016d%s", outageSegmentPre, atMS, outageSegmentExt)
	f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return false
	}
	l.f, l.w, l.size = f, bufio.NewWriterSize(f, 64<<10), 0
	segs := l.listSegments()
	for len(segs) > l.maxSeg {
		os.Remove(filepath.Join(l.dir, segs[0]))
		segs = segs[1:]
	}
	l.segments.Store(int64(len(segs)))
	return true
}

// ReadOutageLog returns up to limit of the newest events in dir that satisfy keep (nil keeps
// all), oldest first. It reads segments newest first and stops once it has enough, so the
// cost depends on the answer size, not on how much history is on disk.
func ReadOutageLog(dir string, limit int, keep func(OutageEvent) bool) ([]OutageEvent, error) {
	if limit <= 0 {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var segs []string
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, outageSegmentPre) && strings.HasSuffix(n, outageSegmentExt) {
			segs = append(segs, n)
		}
	}
	sort.Strings(segs)
	var out []OutageEvent // newest first while collecting
	for i := len(segs) - 1; i >= 0 && len(out) < limit; i-- {
		evs, err := readSegment(filepath.Join(dir, segs[i]))
		if err != nil {
			return nil, err
		}
		for j := len(evs) - 1; j >= 0 && len(out) < limit; j-- {
			if keep == nil || keep(evs[j]) {
				out = append(out, evs[j])
			}
		}
	}
	for a, b := 0, len(out)-1; a < b; a, b = a+1, b-1 {
		out[a], out[b] = out[b], out[a]
	}
	return out, nil
}

func readSegment(path string) ([]OutageEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	var out []OutageEvent
	var rec [outageRecordSize]byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, nil // a torn final record from a crash is ignored
			}
			return out, err
		}
		e := OutageEvent{Seq: binary.LittleEndian.Uint64(rec[0:]), AtMS: int64(binary.LittleEndian.Uint64(rec[8:])),
			DownMS: float64(binary.LittleEndian.Uint32(rec[16:])) / 1000, Slot: int(int8(rec[20]))}
		e.Source, e.Note = cstr(rec[24:40]), cstr(rec[40:56])
		if int(rec[21]) < len(outageKinds) {
			e.Kind = outageKinds[rec[21]]
		} else {
			e.Kind = "unknown"
		}
		if int(rec[22]) < len(outageCauses) {
			e.Cause = outageCauses[rec[22]]
		}
		out = append(out, e)
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
