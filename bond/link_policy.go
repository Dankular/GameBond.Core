package bond

import (
	"encoding/binary"
	"math"
)

const (
	Primary byte = iota
	Secondary
	Backup
	Never
)

type PathPolicy struct {
	Role                     byte
	Blocked                  bool
	UploadMbps, DownloadMbps float64
}

func decodePolicy(payload []byte) (uint64, PathPolicy, error) {
	if len(payload) != 26 || payload[8] > Never || payload[9] > 1 {
		return 0, PathPolicy{}, ErrFrame
	}
	p := PathPolicy{payload[8], payload[9] == 1, math.Float64frombits(binary.BigEndian.Uint64(payload[10:])), math.Float64frombits(binary.BigEndian.Uint64(payload[18:]))}
	if !finite(p.UploadMbps) || !finite(p.DownloadMbps) || p.UploadMbps < 0 || p.DownloadMbps < 0 || p.UploadMbps > 10000 || p.DownloadMbps > 10000 {
		return 0, PathPolicy{}, ErrFrame
	}
	return binary.BigEndian.Uint64(payload), p, nil
}

// WirePacer charges all successful IPv4 UDP bytes, including control, copies
// and repairs. It is separate from the measured bulk congestion budget.
type WirePacer struct{ rate, finish float64 }

func (p *WirePacer) SetRate(mbps, now float64) error {
	if !finite(mbps) || mbps < 0 || mbps > 10000 || !validTime(now) {
		return ErrFrame
	}
	debt := math.Max(0, p.finish-now) * p.rate
	p.rate = mbps * 125000
	p.finish = now
	if p.rate > 0 {
		p.finish += debt / p.rate
	}
	return nil
}
func (p *WirePacer) ReadyAt(size int, now float64) float64 {
	if p.rate == 0 {
		return now
	}
	return math.Max(now, p.finish+(float64(size)-math.Max(2800, float64(size)))/p.rate)
}
func (p *WirePacer) Sent(size int, now float64) {
	if p.rate > 0 {
		p.finish = math.Max(now, p.finish) + float64(size)/p.rate
	}
}
