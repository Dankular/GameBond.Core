package bond

import (
	"container/list"
	"errors"
	"time"
)

var ErrWouldBlock = errors.New("packet device temporarily unavailable")
var ErrPacketRejected = errors.New("packet device rejected datagram")

type InjectionStats struct {
	Admitted, Written, WrittenBytes, Expired, Rejected, EvictedBulk, WriteRejected, PeerResetDropped uint64
	QueuedPackets, QueuedBytes, PeakPackets                                                          int
}
type InjectionQueue struct {
	priority, bulk      list.List
	capacity, byteLimit int
	classes             [64]int
	stats               InjectionStats
}

func NewInjectionQueue(capacity, byteLimit int) (*InjectionQueue, error) {
	if capacity < 1 || byteLimit < 1400 {
		return nil, ErrFrame
	}
	return &InjectionQueue{capacity: capacity, byteLimit: byteLimit}, nil
}
func (q *InjectionQueue) Stats() InjectionStats { return q.stats }
func (q *InjectionQueue) Reset() {
	q.stats.PeerResetDropped += uint64(q.stats.QueuedPackets)
	q.priority.Init()
	q.bulk.Init()
	q.classes = [64]int{}
	q.stats.QueuedPackets = 0
	q.stats.QueuedBytes = 0
}
func (q *InjectionQueue) remove(queue *list.List) QueuedPacket {
	e := queue.Front()
	p := e.Value.(QueuedPacket)
	queue.Remove(e)
	q.classes[p.Tag]--
	q.stats.QueuedPackets--
	q.stats.QueuedBytes -= len(p.Payload)
	return p
}
func (q *InjectionQueue) Enqueue(p QueuedPacket) bool {
	if IsTCPControl(p.Payload) {
		p.Priority = true
		p.ClassCapacity = 0
	}
	if p.Tag > 63 || len(p.Payload) > q.byteLimit || p.Expires.IsZero() || (p.ClassCapacity > 0 && q.classes[p.Tag] >= p.ClassCapacity) {
		q.stats.Rejected++
		return false
	}
	if IsTCPControl(p.Payload) {
		p.Priority = true
	}
	for q.stats.QueuedPackets >= q.capacity || q.stats.QueuedBytes+len(p.Payload) > q.byteLimit {
		if !p.Priority || q.bulk.Len() == 0 {
			q.stats.Rejected++
			return false
		}
		q.remove(&q.bulk)
		q.stats.EvictedBulk++
	}
	p.Payload = append([]byte(nil), p.Payload...)
	if p.Priority {
		q.priority.PushBack(p)
	} else {
		q.bulk.PushBack(p)
	}
	q.classes[p.Tag]++
	q.stats.Admitted++
	q.stats.QueuedPackets++
	q.stats.QueuedBytes += len(p.Payload)
	if q.stats.QueuedPackets > q.stats.PeakPackets {
		q.stats.PeakPackets = q.stats.QueuedPackets
	}
	return true
}
func (q *InjectionQueue) Drain(now time.Time, write func([]byte) error) error {
	for _, queue := range []*list.List{&q.priority, &q.bulk} {
		for i := 0; i < 64 && queue.Len() > 0; i++ {
			p := queue.Front().Value.(QueuedPacket)
			if !now.Before(p.Expires) {
				q.remove(queue)
				q.stats.Expired++
				continue
			}
			err := write(p.Payload)
			if errors.Is(err, ErrWouldBlock) {
				return nil
			}
			if err != nil && !errors.Is(err, ErrPacketRejected) {
				return err
			}
			q.remove(queue)
			if err != nil {
				q.stats.WriteRejected++
			} else {
				q.stats.Written++
				q.stats.WrittenBytes += uint64(len(p.Payload))
			}
		}
	}
	return nil
}
