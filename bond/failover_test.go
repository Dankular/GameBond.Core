package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// A blackholed uplink must become suspect, stop carrying bulk, and have the
// packets it was holding replayed on the surviving uplink.
func TestFailoverReplaysBlackholedUplink(t *testing.T) {
	key, session := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16)
	cc, _ := NewCodec(key, session, "client")
	sc, _ := NewCodec(key, session, "server")
	cr, _ := NewReceiver(cc, 1400)
	sr, _ := NewReceiver(sc, 1400)
	cr.probeInterval, sr.probeInterval = 250*time.Millisecond, 250*time.Millisecond
	sender, err := NewSender(cr, 50, 100)
	if err != nil {
		t.Fatal(err)
	}
	sender.EnableFailover(true)
	now := time.Unix(7000, 0)
	srv := netip.MustParseAddrPort("203.0.113.1:4433")
	src := [2]netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:5000"), netip.MustParseAddrPort("198.51.100.2:5000")}
	for i := range src {
		if err := cr.AddClientPath(i, srv, now); err != nil {
			t.Fatal(err)
		}
	}
	var drop [2]bool
	var toServer, toClient []Datagram
	var wire [2]int
	flush := func() {
		for len(toServer)+len(toClient) > 0 {
			for len(toServer) > 0 {
				d := toServer[0]
				toServer = toServer[1:]
				if drop[d.Local] {
					continue
				}
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
					if s == d.Endpoint && !drop[i] {
						res, err := cr.ReceiveOn(i, d.Frame, srv, now)
						if err != nil {
							t.Fatal(err)
						}
						toServer = append(toServer, res.Send...)
					}
				}
			}
		}
	}
	write := func(d Datagram) error { wire[d.Local]++; toServer = append(toServer, d); return nil }
	step := func() {
		now = now.Add(50 * time.Millisecond)
		co, _ := cr.Tick(now)
		toServer = append(toServer, co.Send...)
		so, _ := sr.Tick(now)
		for _, d := range so.Send {
			for i, s := range src {
				if s == d.Endpoint && !drop[i] {
					res, _ := cr.ReceiveOn(i, d.Frame, srv, now)
					toServer = append(toServer, res.Send...)
				}
			}
		}
		flush()
		if err := sender.Maintenance(now, write); err != nil {
			t.Fatal(err)
		}
		flush()
	}
	for i := 0; i < 60 && cr.ReadyPaths(now) < 2; i++ {
		step()
	}
	for i := 0; i < 30; i++ { // let RTT samples accumulate
		step()
	}
	payload := bytes.Repeat([]byte{7}, 400)
	send := func(n int) {
		for i := 0; i < n; i++ {
			if _, _, err := sender.Bulk(payload, "f", now, write); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Millisecond)
		}
		flush()
	}
	send(20)
	if sender.stats.FailoverSuspected != 0 {
		t.Fatal("healthy paths flagged suspect")
	}
	drop[1] = true
	send(20) // half of these go into the black hole
	for i := 0; i < 40; i++ {
		step()
	}
	if sender.stats.FailoverSuspected != 1 {
		t.Fatalf("want one suspicion, stats %+v", sender.stats)
	}
	if sender.stats.FailoverReplayed == 0 {
		t.Fatalf("nothing replayed, stats %+v", sender.stats)
	}
	if !cr.paths[PathKey{1, srv}].suspect {
		t.Fatal("blackholed path not marked suspect")
	}
	before := wire[1]
	send(30)
	// First copies keep off the suspect path; redundancy copies may still go there, one
	// per packet at most, because a copy into a dead line costs only bandwidth while
	// withholding it leaves the live line as the only copy.
	if got := wire[1] - before; got > 30 {
		t.Fatalf("suspect path carried %d frames for 30 packets: more than one copy each", got)
	}
	drop[1] = false
	for i := 0; i < 80; i++ {
		step()
	}
	if sender.stats.FailoverRecovered == 0 || cr.paths[PathKey{1, srv}].suspect {
		t.Fatalf("path never recovered, stats %+v", sender.stats)
	}
}
