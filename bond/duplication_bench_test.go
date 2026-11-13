package bond

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"sort"
	"testing"
	"time"
)

// Duplication benchmark. The real client Sender and server Receiver run on a virtual clock (no sockets, no OS timers)
// with an impaired wire between them: each uplink has its own loss, one-way delay and jitter, in both directions.
// It measures what duplicating packets over several links buys and what it costs:
//
//	delivery   unique packets that reached the server's output / packets the sender accepted
//	latency    time from send to the server delivering the packet (p50, p99, max)
//	overhead   bytes put on the wire (all frames, controls included) / payload bytes accepted
//
// Run it with:  GB_BENCH=1 go test -run TestDuplicationBenchmark -v ./bond
// Without GB_BENCH it is skipped, because it simulates a few minutes of traffic per scenario.
//
// "tiered" is the older loss-driven mode (parity then duplication as loss rises) kept in the sender for tests;
// the default is to duplicate every packet from the first packet on whenever two or more links are ready.

type simLink struct {
	loss   float64       // probability a datagram is dropped, each direction
	delay  time.Duration // one-way base delay
	jitter time.Duration // added uniformly in [0, jitter]
}

type simEvent struct {
	at       time.Time
	toServer bool
	d        Datagram
	order    uint64
}
type simQueue []simEvent

func (q simQueue) Len() int { return len(q) }
func (q simQueue) Less(i, j int) bool {
	if q[i].at.Equal(q[j].at) {
		return q[i].order < q[j].order
	}
	return q[i].at.Before(q[j].at)
}
func (q simQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)   { *q = append(*q, x.(simEvent)) }
func (q *simQueue) Pop() any {
	old := *q
	e := old[len(old)-1]
	*q = old[:len(old)-1]
	return e
}

type dupResult struct {
	sent, delivered int
	p50, p99, max   time.Duration
	copiesPerPacket float64
	wireOverPayload float64
}

type dupScenario struct {
	name   string
	links  []simLink
	game   bool // true: priority class (copied on every ready link); false: bulk
	tiered bool
}

const (
	dupWarm    = 8 * time.Second
	dupMeasure = 20 * time.Second
	dupDrain   = 2 * time.Second
	dupStep    = 200 * time.Microsecond
)

// simPacket builds a well-formed IPv4/UDP datagram of the given total size carrying seq, so the receiver classifies it
// and the benchmark can identify it on delivery.
func simPacket(size int, seq uint32, dscp byte) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[1] = dscp << 2
	binary.BigEndian.PutUint16(p[2:], uint16(size))
	p[8], p[9] = 64, 17
	copy(p[12:20], []byte{10, 77, 0, 2, 1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], 27015)
	binary.BigEndian.PutUint16(p[24:], uint16(size-20))
	binary.BigEndian.PutUint32(p[28:], seq)
	return p
}

func runDuplication(t testing.TB, sc dupScenario, seed int64) dupResult {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	n := len(sc.links)
	key, session := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16)
	cc, _ := NewCodec(key, session, "client")
	sc2, _ := NewCodec(key, session, "server")
	cr, err := NewReceiver(cc, 1400)
	if err != nil {
		t.Fatal(err)
	}
	sr, _ := NewReceiver(sc2, 1400)
	cr.probeInterval, sr.probeInterval = 250*time.Millisecond, 250*time.Millisecond
	sender, err := NewSender(cr, 25, 100)
	if err != nil {
		t.Fatal(err)
	}
	sender.lossTiered = sc.tiered
	now := time.Unix(9000, 0)
	server := netip.MustParseAddrPort("203.0.113.1:4433")
	src := make([]netip.AddrPort, n)
	for i := range src {
		src[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 5000)
		if err := cr.AddClientPath(i, server, now); err != nil {
			t.Fatal(err)
		}
	}

	var q simQueue
	var order uint64
	impaired := false
	links := sc.links
	var wireBytes uint64
	counting := false
	schedule := func(toServer bool, d Datagram, local int) {
		if counting && toServer {
			wireBytes += uint64(len(d.Frame))
		}
		l := simLink{}
		if impaired {
			l = links[local]
		}
		if l.loss > 0 && rng.Float64() < l.loss {
			return
		}
		delay := l.delay
		if l.jitter > 0 {
			delay += time.Duration(rng.Int63n(int64(l.jitter)))
		}
		order++
		heap.Push(&q, simEvent{at: now.Add(delay), toServer: toServer, d: d, order: order})
	}
	toServerWriter := func(d Datagram) error { schedule(true, d, d.Local); return nil }
	sendBack := func(res ReceiveResult) {
		for _, d := range res.Send {
			for i, s := range src {
				if s == d.Endpoint {
					schedule(false, d, i)
				}
			}
		}
	}

	sentAt := map[uint32]time.Time{}
	got := map[uint32]time.Duration{}
	record := func(res ReceiveResult, at time.Time) {
		for _, p := range res.Deliver {
			if len(p) < 32 {
				continue
			}
			seq := binary.BigEndian.Uint32(p[28:])
			if st, ok := sentAt[seq]; ok {
				if _, dup := got[seq]; !dup {
					got[seq] = at.Sub(st)
				}
			}
		}
	}
	process := func() {
		for q.Len() > 0 && !q[0].at.After(now) {
			e := heap.Pop(&q).(simEvent)
			if e.toServer {
				res, err := sr.ReceiveOn(0, e.d.Frame, src[e.d.Local], e.at)
				if err != nil {
					t.Fatal(err)
				}
				record(res, e.at)
				sendBack(res)
			} else {
				for i, s := range src {
					if s == e.d.Endpoint {
						res, err := cr.ReceiveOn(i, e.d.Frame, server, e.at)
						if err != nil {
							t.Fatal(err)
						}
						sender.Controls(res, e.at, toServerWriter)
						for _, d := range res.Send {
							schedule(true, d, d.Local)
						}
					}
				}
			}
		}
	}
	tickAt := now
	tick := func() {
		co, _ := cr.Tick(now)
		for _, d := range co.Send {
			schedule(true, d, d.Local)
		}
		so, _ := sr.Tick(now)
		record(so, now)
		sendBack(so)
	}

	// Warm up on a clean wire until every link is ready, then switch the impairment on.
	end := now.Add(dupWarm)
	for now.Before(end) {
		now = now.Add(dupStep)
		process()
		if !now.Before(tickAt) {
			tick()
			tickAt = now.Add(2 * time.Millisecond)
		}
	}
	if cr.ReadyPaths(now) != n {
		t.Fatalf("%s: only %d of %d links ready after warm-up", sc.name, cr.ReadyPaths(now), n)
	}
	impaired = true
	before := sender.Stats()

	var interval time.Duration
	var size int
	var dscp byte
	if sc.game {
		interval, size, dscp = 20*time.Millisecond, 100, 46 // 50 packets a second
	} else {
		interval, size, dscp = 800*time.Microsecond, 1000, 0 // about 10 Mbit/s offered
	}
	start := now
	counting = true
	nextSend := now
	var seq uint32
	accepted := 0
	var payloadBytes uint64
	stop := start.Add(dupMeasure)
	for now.Before(stop.Add(dupDrain)) {
		now = now.Add(dupStep)
		process()
		if !now.Before(tickAt) {
			tick()
			tickAt = now.Add(2 * time.Millisecond)
		}
		if now.Before(stop) && !now.Before(nextSend) {
			seq++
			pkt := simPacket(size, seq, dscp)
			ok := false
			if sc.game {
				c, err := sender.Urgent(pkt, true, now, toServerWriter)
				if err != nil {
					t.Fatal(err)
				}
				ok = c > 0
			} else {
				var err error
				ok, _, err = sender.Bulk(pkt, "bench", now, toServerWriter)
				if err != nil {
					t.Fatal(err)
				}
			}
			if ok {
				sentAt[seq] = now
				accepted++
				payloadBytes += uint64(size)
			}
			nextSend = nextSend.Add(interval)
			if nextSend.Before(now) {
				nextSend = now
			}
		}
	}
	after := sender.Stats()
	res := dupResult{sent: accepted, delivered: len(got)}
	lat := make([]time.Duration, 0, len(got))
	for _, d := range got {
		lat = append(lat, d)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if len(lat) > 0 {
		res.p50, res.p99, res.max = lat[len(lat)/2], lat[len(lat)*99/100], lat[len(lat)-1]
	}
	if pk := after.PayloadPackets - before.PayloadPackets; pk > 0 {
		res.copiesPerPacket = float64(after.Copies-before.Copies) / float64(pk)
	}
	if payloadBytes > 0 {
		res.wireOverPayload = float64(wireBytes) / float64(payloadBytes)
	}
	return res
}

// runSeeds repeats a scenario with different seeds and pools the counts, so a difference of a few tenths of a percent
// is not just sampling noise. Latency percentiles are the median of p50 and the worst of p99 and max.
func runSeeds(t testing.TB, sc dupScenario, seeds int) dupResult {
	var total dupResult
	var p50s []time.Duration
	for s := 1; s <= seeds; s++ {
		r := runDuplication(t, sc, int64(s))
		total.sent += r.sent
		total.delivered += r.delivered
		total.copiesPerPacket += r.copiesPerPacket / float64(seeds)
		total.wireOverPayload += r.wireOverPayload / float64(seeds)
		p50s = append(p50s, r.p50)
		if r.p99 > total.p99 {
			total.p99 = r.p99
		}
		if r.max > total.max {
			total.max = r.max
		}
	}
	sort.Slice(p50s, func(i, j int) bool { return p50s[i] < p50s[j] })
	total.p50 = p50s[len(p50s)/2]
	return total
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f", float64(d)/float64(time.Millisecond)) }

func TestDuplicationBenchmark(t *testing.T) {
	if os.Getenv("GB_BENCH") == "" {
		t.Skip("set GB_BENCH=1 to run the duplication benchmark")
	}
	clean := simLink{delay: 20 * time.Millisecond, jitter: 2 * time.Millisecond}
	lossy := func(p float64) simLink { l := clean; l.loss = p; return l }
	same := func(n int, l simLink) []simLink {
		out := make([]simLink, n)
		for i := range out {
			out[i] = l
		}
		return out
	}
	var scenarios []dupScenario
	for _, class := range []bool{true, false} {
		for _, p := range []float64{0, 0.01, 0.05, 0.10, 0.20} {
			for _, n := range []int{1, 2, 3} {
				scenarios = append(scenarios, dupScenario{name: fmt.Sprintf("%d link(s), %.0f%% loss each", n, p*100), links: same(n, lossy(p)), game: class})
			}
		}
		slow := clean
		slow.delay, slow.jitter = 80*time.Millisecond, 20*time.Millisecond
		scenarios = append(scenarios,
			dupScenario{name: "2 links: one 30% loss, one clean", links: []simLink{lossy(0.30), clean}, game: class},
			dupScenario{name: "2 links: one blackholed, one clean", links: []simLink{lossy(1), clean}, game: class},
			dupScenario{name: "2 links: 20 ms and 80 ms (+20 jitter)", links: []simLink{clean, slow}, game: class},
			dupScenario{name: "2 links: 0% loss, tiered mode", links: same(2, lossy(0)), game: class, tiered: true},
			dupScenario{name: "2 links: 1% loss each, tiered mode", links: same(2, lossy(0.01)), game: class, tiered: true},
			dupScenario{name: "2 links: 5% loss each, tiered mode", links: same(2, lossy(0.05)), game: class, tiered: true},
			dupScenario{name: "2 links: 10% loss each, tiered mode", links: same(2, lossy(0.10)), game: class, tiered: true},
			dupScenario{name: "3 links: 10% loss each, tiered mode", links: same(3, lossy(0.10)), game: class, tiered: true},
		)
	}
	fmt.Printf("\nDuplication benchmark: %v measured per scenario, 5 seeds pooled, virtual clock\n", dupMeasure)
	for _, game := range []bool{true, false} {
		if game {
			fmt.Println("\nGAME class: 100 B at 50 packets/s, DSCP 46, copied on every ready link")
		} else {
			fmt.Println("\nBULK class: 1000 B at about 10 Mbit/s offered")
		}
		fmt.Printf("%-40s %8s %9s %8s %8s %8s %7s %9s\n", "scenario", "sent", "delivered", "p50 ms", "p99 ms", "max ms", "copies", "wire/data")
		for _, sc := range scenarios {
			if sc.game != game {
				continue
			}
			r := runSeeds(t, sc, 5)
			fmt.Printf("%-40s %8d %8.2f%% %8s %8s %8s %7.2f %9.2f\n", sc.name, r.sent, 100*float64(r.delivered)/math.Max(1, float64(r.sent)), ms(r.p50), ms(r.p99), ms(r.max), r.copiesPerPacket, r.wireOverPayload)
		}
	}
}

// A cheap guard that runs with the normal tests: two links at 10% loss each must deliver far more than one link does,
// and the copy count must show that packets were duplicated.
func TestDuplicationBeatsASingleLossyLink(t *testing.T) {
	lossy := simLink{loss: 0.10, delay: 20 * time.Millisecond, jitter: 2 * time.Millisecond}
	one := runDuplication(t, dupScenario{name: "one", links: []simLink{lossy}, game: true}, 7)
	two := runDuplication(t, dupScenario{name: "two", links: []simLink{lossy, lossy}, game: true}, 7)
	rate := func(r dupResult) float64 { return float64(r.delivered) / float64(r.sent) }
	if rate(one) > 0.95 || rate(one) < 0.80 {
		t.Fatalf("one link at 10%% loss should deliver about 90%%, got %.1f%%", 100*rate(one))
	}
	if rate(two) < 0.97 {
		t.Fatalf("two duplicated links at 10%% loss should deliver about 99%%, got %.1f%%", 100*rate(two))
	}
	if two.copiesPerPacket < 1.9 {
		t.Fatalf("expected two copies per packet, got %.2f", two.copiesPerPacket)
	}
}
