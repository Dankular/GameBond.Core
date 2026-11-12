package bond

import (
	"testing"
	"time"
)

// A saturating download must not queue ahead of a sparse flow, and expiry of a
// held packet is counted separately.
func TestTransmitQueueServesSparseFlowAheadOfBacklog(t *testing.T) {
	f, s, _ := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 512, 4<<20)
	expires := f.now.Add(time.Second)
	for i := 0; i < 120; i++ {
		p := make([]byte, 1000)
		p[0] = 'D'
		if !q.Enqueue(QueuedPacket{Payload: p, Flow: "download", Expires: expires}) {
			t.Fatal("download packet not admitted")
		}
	}
	if !q.Enqueue(QueuedPacket{Payload: append([]byte{'S'}, make([]byte, 99)...), Flow: "sparse", Expires: expires}) {
		t.Fatal("sparse packet not admitted")
	}
	var sent []QueuedPacket
	for i := 0; i < 10 && q.bulk.Len() > 0; i++ {
		p, _ := q.bulk.Peek()
		sent = append(sent, p)
		q.popBulk()
	}
	found := -1
	for i, p := range sent {
		if p.Flow == "sparse" {
			found = i
		}
	}
	if found < 0 || found > 3 {
		t.Fatalf("sparse flow served at position %d of the first 10", found)
	}
	if q.Stats().QueuedPackets != 111 {
		t.Fatalf("queue accounting off: %+v", q.Stats())
	}
}

func TestTransmitQueueCountsExpiryOfHeldPackets(t *testing.T) {
	f, s, a := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 8, 1<<20)
	expires := f.now.Add(100 * time.Millisecond)
	q.Enqueue(QueuedPacket{Payload: []byte("held"), Flow: "x", Expires: expires})
	for i := 0; i < maxPending; i++ { // window full: the send is deferred, not dropped
		s.r.paths[pk(a[0])].budget.Sent(uint64(i), 1400, 0)
	}
	q.Pump(f.now, func(Datagram) error { return nil })
	if q.Stats().QueuedPackets != 1 || q.Stats().Expired != 0 {
		t.Fatalf("held packet was dropped early: %+v", q.Stats())
	}
	q.Pump(expires, func(Datagram) error { return nil })
	st := q.Stats()
	if st.Expired != 1 || st.ExpiredInWait != 1 || st.QueuedPackets != 0 {
		t.Fatalf("expiry not counted as held: %+v", st)
	}
}
