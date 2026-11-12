package bond

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"
)

// virtualThroughput drives the real client Sender against the real server
// Receiver on a virtual clock: no sockets, no OS timers, no goroutines, an ideal
// zero-delay lossless wire. Any ceiling it reports belongs to the Go protocol
// logic itself, separately from what the network or host scheduler add. It
// returns payload Mbit/s over the virtual duration and the sender counters.
// virtualViaQueue drives the sender through TransmitQueue.Pump, as the real
// clients do, instead of calling Bulk directly.
var virtualViaQueue bool

func virtualThroughput(t testing.TB, uplinks int, policyMbps, rateMbps, seconds float64) (float64, SenderStats, bool) {
	t.Helper()
	key, session := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16)
	cc, _ := NewCodec(key, session, "client")
	sc, _ := NewCodec(key, session, "server")
	cr, _ := NewReceiver(cc, 1400)
	sr, _ := NewReceiver(sc, 1400)
	cr.probeInterval, sr.probeInterval = 250*time.Millisecond, 250*time.Millisecond
	sender, err := NewSender(cr, rateMbps/4, rateMbps)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := NewSender(sr, rateMbps/4, rateMbps)
	_ = srv
	now := time.Unix(9000, 0)
	server := netip.MustParseAddrPort("203.0.113.1:4433")
	src := make([]netip.AddrPort, uplinks)
	for i := range src {
		src[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 5000)
		if err := cr.AddClientPath(i, server, now); err != nil {
			t.Fatal(err)
		}
	}
	var toServer, toClient []Datagram
	flush := func() {
		for len(toServer)+len(toClient) > 0 {
			for len(toServer) > 0 {
				d := toServer[0]
				toServer = toServer[1:]
				res, err := sr.ReceiveOn(0, d.Frame, src[d.Local], now)
				if err != nil {
					t.Fatal(err)
				}
				toClient = append(toClient, res.Send...)
			}
			for len(toClient) > 0 {
				d := toClient[0]
				toClient = toClient[1:]
				for i, s := range src {
					if s == d.Endpoint {
						res, err := cr.ReceiveOn(i, d.Frame, server, now)
						if err != nil {
							t.Fatal(err)
						}
						sender.Controls(res, now, func(w Datagram) error { toServer = append(toServer, w); return nil })
						toServer = append(toServer, res.Send...)
					}
				}
			}
		}
	}
	tick := func() {
		co, _ := cr.Tick(now)
		toServer = append(toServer, co.Send...)
		so, _ := sr.Tick(now)
		toClient = append(toClient, so.Send...)
		flush()
	}
	for i := 0; i < 20 && cr.ReadyPaths(now) < uplinks; i++ {
		now = now.Add(250 * time.Millisecond)
		tick()
	}
	if cr.ReadyPaths(now) != uplinks {
		t.Fatalf("only %d of %d uplinks ready", cr.ReadyPaths(now), uplinks)
	}
	if policyMbps > 0 {
		policies := make([]PathPolicy, uplinks)
		for i := range policies {
			policies[i] = PathPolicy{Role: Primary, UploadMbps: policyMbps, DownloadMbps: policyMbps}
		}
		if err := cr.SetClientLinkPolicies(policies, now); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			now = now.Add(250 * time.Millisecond)
			tick()
		}
	}
	writer := func(d Datagram) error { toServer = append(toServer, d); return nil }
	queue, _ := NewTransmitQueue(sender, 40000, 64<<20)
	payload := make([]byte, 1000)
	start, sent := now, 0
	nextTick := now
	for now.Sub(start) < time.Duration(seconds*float64(time.Second)) {
		if !now.Before(nextTick) {
			tick()
			nextTick = now.Add(2 * time.Millisecond)
		}
		var ok bool
		var next time.Time
		var err error
		if virtualViaQueue {
			before := queue.Stats().Completed
			for queue.Stats().QueuedPackets < 256 {
				queue.Enqueue(QueuedPacket{Payload: payload, Flow: "virtual", Expires: now.Add(time.Hour)})
			}
			next, err = queue.Pump(now, writer)
			sent += int(queue.Stats().Completed - before)
			ok = false // Pump batches; always advance to its wakeup
		} else {
			ok, next, err = sender.Bulk(payload, "virtual", now, writer)
		}
		if err != nil {
			t.Fatal(err)
		}
		flush()
		if ok {
			sent++
			continue
		}
		if next.After(nextTick) {
			next = nextTick
		}
		if !next.After(now) {
			next = now.Add(10 * time.Microsecond)
		}
		now = next
	}
	return float64(sent) * 8000 / seconds / 1e6, sender.Stats(), true
}

func TestVirtualThroughputReport(t *testing.T) {
	if os.Getenv("GB_VIRTUAL") == "" {
		t.Skip("set GB_VIRTUAL=1 to print the virtual-clock throughput table")
	}
	for _, c := range []struct {
		uplinks      int
		policy, rate float64
	}{{1, 0, 4000}, {2, 0, 4000}, {2, 25, 4000}, {2, 50, 4000}, {2, 200, 4000}, {2, 1000, 4000}} {
		mbit, st, _ := virtualThroughput(t, c.uplinks, c.policy, c.rate, 5)
		fmt.Printf("uplinks=%d policy=%v rate=%v -> %.1f Mbit/s payload (wire-limited %d)\n", c.uplinks, c.policy, c.rate, mbit, st.WireLimited)
	}
}

// The protocol logic must honour a link policy at close to line rate on an
// ideal wire. Real-socket runs that fall below this are losing time in the I/O
// loop or the network, not in the bond code.
func TestVirtualThroughputHonoursPolicyAndHasNoHiddenCeiling(t *testing.T) {
	policy, _, _ := virtualThroughput(t, 2, 50, 4000, 2)
	// Every packet is copied onto the second line, so two lines carry one line's worth of
	// payload: redundancy is bought with bandwidth, by design.
	if policy < 40 || policy > 50 {
		t.Fatalf("2 uplinks x 50 Mbit/s policy gave %.1f Mbit/s payload, want about 45 (all packets duplicated)", policy)
	}
	free, _, _ := virtualThroughput(t, 2, 0, 4000, 2)
	if free < 300 {
		t.Fatalf("unpaced logic ceiling %.1f Mbit/s is suspiciously low", free)
	}
}

func TestVirtualThroughputThroughPump(t *testing.T) {
	virtualViaQueue = true
	defer func() { virtualViaQueue = false }()
	for _, policy := range []float64{50, 200} {
		mbit, st, _ := virtualThroughput(t, 2, policy, 4000, 5)
		t.Logf("via Pump: policy=%v -> %.1f Mbit/s (wire-limited %d)", policy, mbit, st.WireLimited)
	}
}
