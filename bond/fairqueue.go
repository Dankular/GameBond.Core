package bond

import "container/list"

// fairQuantum is the byte credit a bulk flow earns per round. One full-size
// packet fits in a round, so a sparse flow is served as soon as it has data.
const fairQuantum = 1500

type fqFlow struct {
	key     string
	pkts    list.List
	bytes   int
	deficit int
	ringPos int // index in fairQueue.ring, -1 when idle
}

// fairQueue holds bulk packets per flow and serves them by byte deficit
// (deficit round robin). A saturating download cannot queue ahead of a sparse
// flow, and each flow stays first-in first-out. Callers serialise access.
type fairQueue struct {
	flows map[string]*fqFlow
	ring  []*fqFlow
	idx   int
	cur   *fqFlow // flow chosen by Peek; stays chosen until Pop
	n     int
}

func (f *fairQueue) Len() int { return f.n }

func (f *fairQueue) Reset() {
	f.flows, f.ring, f.idx, f.cur, f.n = nil, nil, 0, nil, 0
}

func (f *fairQueue) Push(p QueuedPacket) {
	if f.flows == nil {
		f.flows = make(map[string]*fqFlow)
	}
	fl := f.flows[p.Flow]
	if fl == nil {
		fl = &fqFlow{key: p.Flow, ringPos: -1}
		f.flows[p.Flow] = fl
	}
	fl.pkts.PushBack(p)
	fl.bytes += len(p.Payload)
	if fl.ringPos < 0 {
		fl.deficit = fairQuantum // a newly active flow is served in the next round
		fl.ringPos = len(f.ring)
		f.ring = append(f.ring, fl)
	}
	f.n++
}

// Peek returns the packet to serve next without removing it. Repeated calls
// return the same packet until Pop.
func (f *fairQueue) Peek() (QueuedPacket, bool) {
	if f.n == 0 {
		return QueuedPacket{}, false
	}
	if f.cur != nil && f.cur.pkts.Len() > 0 {
		return f.cur.pkts.Front().Value.(QueuedPacket), true
	}
	f.cur = nil
	for i := 0; i < 2*len(f.ring)+10; i++ {
		if f.idx >= len(f.ring) {
			f.idx = 0
		}
		fl := f.ring[f.idx]
		head := fl.pkts.Front().Value.(QueuedPacket)
		if fl.deficit >= len(head.Payload) {
			f.cur = fl
			return head, true
		}
		fl.deficit += fairQuantum
		f.idx++
	}
	// Unreachable for sane sizes (a packet is at most one MTU); serve in order.
	f.cur = f.ring[0]
	return f.cur.pkts.Front().Value.(QueuedPacket), true
}

// Pop removes the packet Peek returned.
func (f *fairQueue) Pop() QueuedPacket {
	if _, ok := f.Peek(); !ok {
		return QueuedPacket{}
	}
	fl := f.cur
	p := f.take(fl)
	fl.deficit -= len(p.Payload)
	if fl.pkts.Len() == 0 {
		f.deactivate(fl)
		f.cur = nil
		return p
	}
	if next := fl.pkts.Front().Value.(QueuedPacket); fl.deficit < len(next.Payload) {
		f.cur = nil // credit spent: next flow's turn
		f.idx = fl.ringPos + 1
	}
	return p
}

// EvictLargest drops the oldest packet of the flow holding the most bytes, so
// overload falls on the flow causing it.
func (f *fairQueue) EvictLargest() (QueuedPacket, bool) {
	var big *fqFlow
	for _, fl := range f.ring {
		if big == nil || fl.bytes > big.bytes {
			big = fl
		}
	}
	if big == nil {
		return QueuedPacket{}, false
	}
	p := f.take(big)
	if big.pkts.Len() == 0 {
		f.deactivate(big)
	}
	f.cur = nil
	return p, true
}

func (f *fairQueue) take(fl *fqFlow) QueuedPacket {
	e := fl.pkts.Front()
	p := e.Value.(QueuedPacket)
	fl.pkts.Remove(e)
	fl.bytes -= len(p.Payload)
	f.n--
	return p
}

func (f *fairQueue) deactivate(fl *fqFlow) {
	pos := fl.ringPos
	f.ring = append(f.ring[:pos], f.ring[pos+1:]...)
	for i := pos; i < len(f.ring); i++ {
		f.ring[i].ringPos = i
	}
	fl.ringPos, fl.deficit = -1, 0
	delete(f.flows, fl.key)
	if f.idx > pos {
		f.idx--
	}
	if f.idx >= len(f.ring) {
		f.idx = 0
	}
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
