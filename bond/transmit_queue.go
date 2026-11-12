package bond

import (
	"container/list"
	"time"
)

type QueuedPacket struct {
	Payload             []byte
	Flow                string
	Priority, Replicate bool
	Expires             time.Time
	Tag                 byte
	ClassCapacity       int
	queuedAt            time.Time // set on admission; measures queue residency
	held                bool      // a send was attempted and deferred by pacing or the window
}
type TransmitQueueStats struct {
	Admitted, Completed, Expired, Rejected, EvictedBulk uint64
	PeerResetDropped                                    uint64
	CoDelDropped, CoDelMarked                           uint64
	// ExpiredPriority and ExpiredBulk split Expired by queue: packets that outlived
	// their class's max age before they could be sent.
	ExpiredPriority, ExpiredBulk uint64
	// PriorityWaitMaxMS and the over-counters report how long urgent packets
	// sat in the queue before being written (0 means released immediately).
	ExpiredInWait, PrioritySent, PriorityWaitOver1ms, PriorityWaitOver5ms uint64
	PriorityWaitMaxMS                                                     float64
	QueuedPackets, QueuedBytes, PeakPackets                               int
}

// TransmitQueue keeps urgent and bulk admission separate and bounds memory.
// Pump never waits for a pacing slot, so the actor can service UDP/TUN events.
type TransmitQueue struct {
	sender              *Sender
	priority            list.List
	bulk                fairQueue
	capacity, byteLimit int
	stats               TransmitQueueStats
	peer                [16]byte
	hasPeer             bool
	classes             [64]int
	qos                 *AdaptiveQoS
	codel               bool
	codelState          codelState
}

func NewTransmitQueue(sender *Sender, capacity, byteLimit int) (*TransmitQueue, error) {
	if sender == nil || capacity < 1 || byteLimit < sender.r.mtu {
		return nil, ErrFrame
	}
	return &TransmitQueue{sender: sender, capacity: capacity, byteLimit: byteLimit}, nil
}
func (q *TransmitQueue) Stats() TransmitQueueStats { return q.stats }
func (q *TransmitQueue) SetQoS(qos *AdaptiveQoS)   { q.qos = qos }
func (q *TransmitQueue) syncPeer() {
	q.sender.syncPeer()
	if q.sender.hasPeer && (!q.hasPeer || q.peer != q.sender.peer) {
		q.stats.PeerResetDropped += uint64(q.priority.Len() + q.bulk.Len())
		q.priority.Init()
		q.bulk.Reset()
		q.stats.QueuedPackets = 0
		q.stats.QueuedBytes = 0
		q.classes = [64]int{}
		q.peer = q.sender.peer
		q.hasPeer = true
	}
}
func (q *TransmitQueue) release(p QueuedPacket) {
	q.stats.QueuedPackets--
	q.stats.QueuedBytes -= len(p.Payload)
	q.classes[p.Tag]--
}
func (q *TransmitQueue) remove(queue *list.List) QueuedPacket {
	e := queue.Front()
	p := e.Value.(QueuedPacket)
	queue.Remove(e)
	q.release(p)
	return p
}
func (q *TransmitQueue) popBulk() QueuedPacket {
	p := q.bulk.Pop()
	q.release(p)
	return p
}
// bulkClassFloor is the minimum per-class packet limit for bulk traffic.
const bulkClassFloor = 2048

func (q *TransmitQueue) Enqueue(packet QueuedPacket) bool {
	q.syncPeer()
	if IsTCPControl(packet.Payload) {
		packet.Priority = true
		packet.ClassCapacity = 0
	}
	if packet.Tag > 63 || packet.ClassCapacity < 0 || packet.Expires.IsZero() || len(packet.Flow) > 512 || len(packet.Payload)+Overhead+24 > q.sender.r.mtu || len(packet.Payload) > q.byteLimit {
		q.stats.Rejected++
		return false
	}
	// Bulk traffic gets a deeper class limit than the 256-packet policy default: a TCP
	// burst arriving at line rate faster than the paced uplink drains would otherwise be
	// rejected, which makes the sender collapse. Delay is still bounded by CoDel and MaxAge.
	if limit := packet.ClassCapacity; limit > 0 && !packet.Priority && !packet.Replicate && limit < bulkClassFloor {
		packet.ClassCapacity = bulkClassFloor
	}
	if packet.ClassCapacity > 0 && q.classes[packet.Tag] >= packet.ClassCapacity {
		q.stats.Rejected++
		return false
	}
	if packet.Replicate || IsTCPControl(packet.Payload) {
		packet.Priority = true
	}
	for q.stats.QueuedPackets >= q.capacity || q.stats.QueuedBytes+len(packet.Payload) > q.byteLimit {
		if !packet.Priority || q.bulk.Len() == 0 {
			q.stats.Rejected++
			return false
		}
		p, _ := q.bulk.EvictLargest()
		q.release(p)
		q.stats.EvictedBulk++
	}
	packet.Payload = append([]byte(nil), packet.Payload...)
	packet.queuedAt = time.Now()
	if packet.Priority {
		q.priority.PushBack(packet)
	} else {
		q.bulk.Push(packet)
	}
	q.stats.Admitted++
	q.stats.QueuedPackets++
	q.stats.QueuedBytes += len(packet.Payload)
	q.classes[packet.Tag]++
	if q.stats.QueuedPackets > q.stats.PeakPackets {
		q.stats.PeakPackets = q.stats.QueuedPackets
	}
	return true
}

// Pump services bounded batches from both queues. Its return is the next bulk
// wakeup; Receive/Tick and newly admitted urgent traffic may wake it earlier.
func (q *TransmitQueue) Pump(now time.Time, writer DatagramWriter) (time.Time, error) {
	q.syncPeer()
	if q.qos != nil {
		q.qos.Observe(q.sender, now)
	}
	due := now.Add(5 * time.Millisecond)
	for i := 0; i < 64 && q.priority.Len() > 0; i++ {
		p := q.priority.Front().Value.(QueuedPacket)
		if !now.Before(p.Expires) {
			q.remove(&q.priority)
			q.stats.Expired++
			q.stats.ExpiredPriority++
			continue
		}
		replicate := p.Replicate
		if q.qos != nil {
			replicate = q.qos.Replicate(p.Tag, len(p.Payload), replicate, now)
		}
		sent, err := q.sender.Urgent(p.Payload, replicate, now, writer)
		if err != nil {
			return due, err
		}
		if sent == 0 {
			due = now.Add(time.Millisecond)
			break
		}
		q.remove(&q.priority)
		q.stats.Completed++
		q.stats.PrioritySent++
		if !p.queuedAt.IsZero() {
			ms := float64(time.Since(p.queuedAt)) / float64(time.Millisecond)
			if ms > q.stats.PriorityWaitMaxMS {
				q.stats.PriorityWaitMaxMS = ms
			}
			if ms > 1 {
				q.stats.PriorityWaitOver1ms++
			}
			if ms > 5 {
				q.stats.PriorityWaitOver5ms++
			}
		}
	}
	if q.bulk.Len() > 0 {
		q.sender.ResumeBulk(now)
	}
	for i := 0; i < 64 && q.bulk.Len() > 0; i++ {
		p, _ := q.bulk.Peek()
		if !now.Before(p.Expires) {
			q.popBulk()
			q.stats.Expired++
			q.stats.ExpiredBulk++
			if p.held {
				q.stats.ExpiredInWait++ // aged out while pacing or the window held it back
			}
			continue
		}
		if q.codel && !p.queuedAt.IsZero() {
			switch q.codelState.judge(p.Flow, time.Since(p.queuedAt), ecnCapable(p.Payload), time.Now()) {
			case codelDrop:
				q.popBulk()
				q.stats.CoDelDropped++
				continue
			case codelMark:
				if markCE(p.Payload) {
					q.stats.CoDelMarked++
				}
			}
		}
		sent, next, err := q.sender.Bulk(p.Payload, p.Flow, now, writer)
		if err != nil {
			return due, err
		}
		if !sent {
			q.bulk.MarkHeld()
			if next.Before(due) {
				due = next
			}
			if p.Expires.Before(due) {
				due = p.Expires
			}
			break
		}
		q.popBulk()
		q.stats.Completed++
	}
	if q.priority.Len() > 0 || q.bulk.Len() > 0 { // Do not sleep through another ready batch.
		if q.bulk.Len() > 0 && q.sender.waitStart.IsZero() {
			due = now
		}
	} else {
		q.sender.waitStart = time.Time{}
		q.sender.waiters = nil
	}
	return due, nil
}
