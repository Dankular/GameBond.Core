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

func TestFairQueueSparseFlowNotStuckBehindBacklog(t *testing.T) {
	var q fairQueue
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
	var q fairQueue
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
	var q fairQueue
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

func TestFairQueuePeekStableUntilPop(t *testing.T) {
	var q fairQueue
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
	var q fairQueue
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
	if _, ok := q.Peek(); ok || len(q.flows) != 0 || len(q.ring) != 0 {
		t.Fatal("queue not empty after draining")
	}
}

func TestFairQueueChurn(t *testing.T) {
	var q fairQueue
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
