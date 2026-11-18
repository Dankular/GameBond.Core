package bond

import (
	"container/list"
	"hash/maphash"
)

// fairQuantum is the byte credit each bulk flow earns per DRR round. One
// full-size packet fits in a round, so sparse flows are serviced promptly.
const fairQuantum = 1500
const fqCoDelBuckets = 1024

type fqFlow struct {
	index   uint16
	pkts    list.List
	bytes   int
	deficit int
	active  *list.List
	elem    *list.Element
}

// fairQueue is a byte-based two-tier DRR scheduler. Newly active flows get a
// turn before backlogged flows; queues that persist move to the old list. This
// is the scheduling behavior specified by RFC 8290 Section 4. Flow keys are
// mapped through Linux-compatible Jenkins hashing with a per-queue random salt
// into its fixed bucket table.
type fairQueue struct {
	flows    map[uint16]*fqFlow
	new      list.List
	old      list.List
	cur      *fqFlow // queue chosen by Peek; stays chosen until Pop
	n        int
	bytes    int
	seed     uint32
	seeded   bool
	hashFlow func(string) uint64 // deterministic injection for collision tests
}

func (f *fairQueue) Len() int { return f.n }

// Bytes reports total bytes across all active flow buckets. CoDel's
// non-starvation check uses shared output occupancy for a multi-queue setup.
func (f *fairQueue) Bytes() int { return f.bytes }

func (f *fairQueue) flowBytes(key string) int {
	return f.bucketBytes(f.bucket(key))
}

func (f *fairQueue) bucketBytes(bucket uint16) int {
	if fl := f.flows[bucket]; fl != nil {
		return fl.bytes
	}
	return 0
}

func (f *fairQueue) bucket(key string) uint16 {
	var sum uint32
	if f.hashFlow != nil {
		sum = uint32(f.hashFlow(key))
	} else {
		if !f.seeded {
			// RFC 8290 requires an unpredictable salt. Derive the 32-bit
			// jhash salt from Go's randomized maphash seed, while keeping the
			// packet-key hash itself identical to Linux jhash.
			f.seed = uint32(maphash.String(maphash.MakeSeed(), "GameBond FQ-CoDel salt"))
			f.seeded = true
		}
		sum = linuxJenkinsHash([]byte(key), f.seed)
	}
	return uint16(sum % uint32(fqCoDelBuckets))
}

func fqCoDelKey(bucket uint16) string { return string([]byte{byte(bucket >> 8), byte(bucket)}) }

func (f *fairQueue) Reset() {
	f.flows = nil
	f.new.Init()
	f.old.Init()
	f.cur = nil
	f.n, f.bytes = 0, 0
	f.seed, f.seeded = 0, false
}

func (f *fairQueue) Push(p QueuedPacket) {
	if f.flows == nil {
		f.flows = make(map[uint16]*fqFlow)
	}
	bucket := f.bucket(p.Flow)
	p.fqBucket = bucket
	fl := f.flows[bucket]
	if fl == nil {
		fl = &fqFlow{index: bucket, deficit: fairQuantum}
		fl.active = &f.new
		fl.elem = f.new.PushBack(fl)
		f.flows[bucket] = fl
	}
	fl.pkts.PushBack(p)
	fl.bytes += len(p.Payload)
	f.n++
	f.bytes += len(p.Payload)
}

// Peek returns the next packet without removing it. Repeated calls return the
// same packet until Pop. An empty new queue is moved to the old list before it
// can be reused, which prevents a sparse flow from starving continuously
// backlogged flows by repeatedly becoming new.
func (f *fairQueue) Peek() (QueuedPacket, bool) {
	if f.n == 0 {
		for f.new.Len() > 0 {
			f.moveToOld(f.new.Front().Value.(*fqFlow))
		}
		for f.old.Len() > 0 {
			f.deactivate(f.old.Front().Value.(*fqFlow))
		}
		f.cur = nil
		return QueuedPacket{}, false
	}
	if f.cur != nil && f.cur.pkts.Len() > 0 {
		return f.cur.pkts.Front().Value.(QueuedPacket), true
	}
	f.cur = nil
	for attempts := 0; attempts < 4*(len(f.flows)+1); attempts++ {
		active := &f.new
		if active.Len() == 0 {
			active = &f.old
		}
		if active.Len() == 0 {
			break
		}
		fl := active.Front().Value.(*fqFlow)
		if fl.pkts.Len() == 0 {
			if active == &f.new {
				f.moveToOld(fl)
			} else {
				f.deactivate(fl)
			}
			continue
		}
		head := fl.pkts.Front().Value.(QueuedPacket)
		if fl.deficit < len(head.Payload) {
			fl.deficit += fairQuantum
			f.rotate(fl)
			continue
		}
		f.cur = fl
		return head, true
	}
	return QueuedPacket{}, false
}

// Pop removes the packet Peek returned and charges its bytes against that
// flow's deficit. A queue keeps its turn while it has credit, then joins the
// tail of the old list with a fresh quantum.
func (f *fairQueue) Pop() QueuedPacket {
	if _, ok := f.Peek(); !ok {
		return QueuedPacket{}
	}
	fl := f.cur
	p := f.take(fl)
	fl.deficit -= len(p.Payload)
	f.cur = nil
	if fl.pkts.Len() == 0 {
		if fl.active == &f.new {
			f.moveToOld(fl)
		} else {
			f.deactivate(fl)
		}
	} else if fl.deficit < len(fl.pkts.Front().Value.(QueuedPacket).Payload) {
		fl.deficit += fairQuantum
		f.rotate(fl)
	} else {
		f.cur = fl
	}
	return p
}

// EvictLargest drops the oldest packet from the flow holding the most bytes.
func (f *fairQueue) EvictLargest() (QueuedPacket, bool) {
	dropped := f.EvictLargestBurst(1)
	if len(dropped) == 0 {
		return QueuedPacket{}, false
	}
	return dropped[0], true
}

// EvictLargestBurst drops half the packets (up to maxPackets) from the
// largest active bucket, amortizing overload handling as RFC 8290 describes.
func (f *fairQueue) EvictLargestBurst(maxPackets int) []QueuedPacket {
	if maxPackets < 1 {
		return nil
	}
	var big *fqFlow
	for _, active := range []*list.List{&f.new, &f.old} {
		for e := active.Front(); e != nil; e = e.Next() {
			fl := e.Value.(*fqFlow)
			if fl.pkts.Len() > 0 && (big == nil || fl.bytes > big.bytes) {
				big = fl
			}
		}
	}
	if big == nil {
		return nil
	}
	count := big.pkts.Len() / 2
	if count < 1 {
		count = 1
	}
	if count > maxPackets {
		count = maxPackets
	}
	if big == f.cur {
		f.cur = nil
	}
	dropped := make([]QueuedPacket, 0, count)
	for i := 0; i < count; i++ {
		dropped = append(dropped, f.take(big))
	}
	if big.pkts.Len() == 0 {
		if big.active == &f.new {
			f.moveToOld(big)
		} else {
			f.deactivate(big)
		}
	}
	return dropped
}

func (f *fairQueue) take(fl *fqFlow) QueuedPacket {
	e := fl.pkts.Front()
	p := e.Value.(QueuedPacket)
	fl.pkts.Remove(e)
	fl.bytes -= len(p.Payload)
	f.n--
	f.bytes -= len(p.Payload)
	return p
}

func (f *fairQueue) moveToOld(fl *fqFlow) {
	if fl.active == &f.old {
		return
	}
	fl.active.Remove(fl.elem)
	fl.active = &f.old
	fl.elem = f.old.PushBack(fl)
	fl.deficit = fairQuantum
}

func (f *fairQueue) rotate(fl *fqFlow) {
	if fl.active == &f.new {
		f.moveToOld(fl)
		return
	}
	fl.active.MoveToBack(fl.elem)
}

func (f *fairQueue) deactivate(fl *fqFlow) {
	fl.active.Remove(fl.elem)
	fl.active, fl.elem, fl.deficit = nil, nil, 0
	delete(f.flows, fl.index)
}

// MarkHeld records that the packet Peek returned was deferred, so a later
// expiry can be told apart from one that never reached the head of the queue.
func (f *fairQueue) MarkHeld() {
	if f.cur == nil || f.cur.pkts.Len() == 0 {
		return
	}
	e := f.cur.pkts.Front()
	p := e.Value.(QueuedPacket)
	p.held = true
	e.Value = p
}
