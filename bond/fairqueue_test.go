package bond

import (
	"fmt"
	"testing"
	"time"
)

func fqPkt(flow string, n int, seq int) QueuedPacket {
	b := make([]byte, n)
	b[0] = byte(seq)
	return QueuedPacket{Payload: b, Flow: flow, Expires: time.Now().Add(time.Hour)}
}

func deterministicFairQueue() fairQueue {
	return fairQueue{hashFlow: func(flow string) uint64 {
		var h uint64
		for i := 0; i < len(flow); i++ {
			h = h*31 + uint64(flow[i])
		}
		return h
	}}
}

func TestFairQueueSparseFlowNotStuckBehindBacklog(t *testing.T) {
	q := deterministicFairQueue()
	for i := 0; i < 200; i++ {
		q.Push(fqPkt("download", 1400, i))
	}
	q.Push(fqPkt("voice", 120, 0))
	for served := 0; served < 6; served++ {
		p, _ := q.Peek()
		q.Pop()
		if p.Flow == "voice" {
			return
		}
	}
	t.Fatal("sparse flow waited behind more than five full-size packets of a 200-packet backlog")
}

func TestFairQueueKeepsOrderWithinFlow(t *testing.T) {
	q := deterministicFairQueue()
	for i := 0; i < 50; i++ {
		q.Push(fqPkt("a", 900, i))
		q.Push(fqPkt("b", 300, i))
	}
	next := map[string]int{}
	for q.Len() > 0 {
		p, _ := q.Peek()
		q.Pop()
		if int(p.Payload[0]) != next[p.Flow] {
			t.Fatalf("flow %s out of order: got %d want %d", p.Flow, p.Payload[0], next[p.Flow])
		}
		next[p.Flow]++
	}
	if next["a"] != 50 || next["b"] != 50 {
		t.Fatalf("lost packets: %v", next)
	}
}

func TestFairQueueByteFairness(t *testing.T) {
	q := deterministicFairQueue()
	for i := 0; i < 400; i++ {
		q.Push(fqPkt("big", 1400, 0))
		q.Push(fqPkt("small", 140, 0))
	}
	bytes := map[string]int{}
	for i := 0; i < 400; i++ { // both flows stay backlogged throughout
		p, _ := q.Peek()
		q.Pop()
		bytes[p.Flow] += len(p.Payload)
	}
	ratio := float64(bytes["big"]) / float64(bytes["small"])
	if ratio < 0.8 || ratio > 1.25 {
		t.Fatalf("byte shares not equal: %v ratio %.2f", bytes, ratio)
	}
}

func TestFairQueueTracksAggregateBytesAcrossBuckets(t *testing.T) {
	q := deterministicFairQueue()
	q.Push(fqPkt("sparse", 600, 0))
	q.Push(fqPkt("bulk", 1400, 0))
	if got := q.Bytes(); got != 2000 {
		t.Fatalf("aggregate bytes after enqueue = %d, want 2000", got)
	}
	if got := q.bucketBytes(q.bucket("sparse")); got != 600 {
		t.Fatalf("sparse bucket bytes = %d, want 600", got)
	}
	q.Pop()
	if got := q.Bytes(); got != 1400 {
		t.Fatalf("aggregate bytes after dequeue = %d, want 1400", got)
	}
	if dropped := q.EvictLargestBurst(64); len(dropped) != 1 {
		t.Fatalf("evicted %d packets, want 1", len(dropped))
	}
	if got := q.Bytes(); got != 0 {
		t.Fatalf("aggregate bytes after eviction = %d, want 0", got)
	}
}

func TestFairQueuePeekStableUntilPop(t *testing.T) {
	q := deterministicFairQueue()
	q.Push(fqPkt("a", 1000, 1))
	q.Push(fqPkt("b", 1000, 2))
	first, _ := q.Peek()
	for i := 0; i < 5; i++ {
		again, _ := q.Peek()
		if again.Flow != first.Flow {
			t.Fatal("Peek changed its answer before Pop")
		}
	}
}

func TestFairQueueEvictsFromLargestFlow(t *testing.T) {
	q := deterministicFairQueue()
	for i := 0; i < 30; i++ {
		q.Push(fqPkt("hog", 1400, i))
	}
	q.Push(fqPkt("mouse", 100, 0))
	p, ok := q.EvictLargest()
	if !ok || p.Flow != "hog" || p.Payload[0] != 0 {
		t.Fatalf("evicted %+v", p.Flow)
	}
	if q.Len() != 30 {
		t.Fatalf("len %d", q.Len())
	}
	for q.Len() > 0 {
		q.Pop()
	}
	if _, ok := q.Peek(); ok || len(q.flows) != 0 || q.new.Len() != 0 || q.old.Len() != 0 {
		t.Fatal("queue not empty after draining")
	}
}

func TestFairQueueBatchEvictsHalfOfLargestBucket(t *testing.T) {
	q := deterministicFairQueue()
	for i := 0; i < 8; i++ {
		q.Push(fqPkt("hog", 1400, i))
	}
	for i := 0; i < 2; i++ {
		q.Push(fqPkt("mouse", 100, i))
	}
	dropped := q.EvictLargestBurst(64)
	if len(dropped) != 4 {
		t.Fatalf("evicted %d packets, want half of largest bucket (4)", len(dropped))
	}
	for i, p := range dropped {
		if p.Flow != "hog" || int(p.Payload[0]) != i {
			t.Fatalf("drop %d was flow=%q sequence=%d", i, p.Flow, p.Payload[0])
		}
	}
	if q.Len() != 6 || q.flowBytes("hog") != 4*1400 || q.flowBytes("mouse") != 200 {
		t.Fatalf("batch eviction accounting wrong: packets=%d hog=%d mouse=%d", q.Len(), q.flowBytes("hog"), q.flowBytes("mouse"))
	}
}

func TestFairQueuePrioritizesNewFlowsAndPreventsNewFlowStarvation(t *testing.T) {
	q := deterministicFairQueue()
	for i := 0; i < 20; i++ {
		q.Push(fqPkt("backlogged", 1400, i))
	}
	if p, _ := q.Peek(); p.Flow != "backlogged" {
		t.Fatalf("first active flow = %q", p.Flow)
	}
	q.Pop() // Exhausts this flow's initial quantum and moves it to the old list.
	if q.new.Len() != 0 || q.old.Len() != 1 {
		t.Fatalf("backlogged flow state: new=%d old=%d", q.new.Len(), q.old.Len())
	}
	q.Push(fqPkt("sparse", 100, 0))
	if p, _ := q.Peek(); p.Flow != "sparse" {
		t.Fatalf("new flow did not get first service: %q", p.Flow)
	}
	q.Pop() // Empty new queue joins the tail of old rather than disappearing.
	q.Push(fqPkt("sparse", 100, 1))
	if p, _ := q.Peek(); p.Flow != "backlogged" {
		t.Fatalf("reappearing sparse flow starved the old queue: %q", p.Flow)
	}
}

func TestFairQueueChurn(t *testing.T) {
	q := deterministicFairQueue()
	total := 0
	for round := 0; round < 200; round++ {
		for f := 0; f < 7; f++ {
			q.Push(fqPkt(fmt.Sprintf("f%d", (round+f)%11), 200+f*150, round))
			total++
		}
		for i := 0; i < 5 && q.Len() > 0; i++ {
			if _, ok := q.Peek(); !ok {
				t.Fatal("Peek failed with packets queued")
			}
			q.Pop()
			total--
		}
	}
	for q.Len() > 0 {
		q.Pop()
		total--
	}
	if total != 0 {
		t.Fatalf("accounting off by %d", total)
	}
}

func TestFairQueueBoundsHashedFlowsAndSharesCollisions(t *testing.T) {
	q := fairQueue{hashFlow: func(string) uint64 { return 7 }}
	q.Push(fqPkt("flow-a", 120, 1))
	q.Push(fqPkt("flow-b", 120, 2))
	if len(q.flows) != 1 || q.new.Len() != 1 {
		t.Fatalf("collision did not share one bounded queue: buckets=%d active=%d", len(q.flows), q.new.Len())
	}
	for _, want := range []string{"flow-a", "flow-b"} {
		p, ok := q.Peek()
		if !ok || p.Flow != want {
			t.Fatalf("hashed bucket order got %q want %q", p.Flow, want)
		}
		q.Pop()
	}
	if _, ok := q.Peek(); ok {
		t.Fatal("collision bucket remained after draining")
	}
	if q.Len() != 0 || len(q.flows) != 0 {
		t.Fatalf("queue did not retire collision bucket: packets=%d buckets=%d", q.Len(), len(q.flows))
	}
}

func TestFairQueueUsesBoundedSaltedBucketTable(t *testing.T) {
	var q fairQueue
	for i := 0; i < 2048; i++ {
		q.Push(fqPkt(fmt.Sprintf("flow-%d", i), 1, i))
	}
	if !q.seeded {
		t.Fatal("production queue did not initialize its randomized hash seed")
	}
	if got := len(q.flows); got > fqCoDelBuckets {
		t.Fatalf("active queues %d exceeded fixed bucket count %d", got, fqCoDelBuckets)
	}
}
