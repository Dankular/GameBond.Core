package bond

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// Replicated copies are scored by the receiver and the score is reported back
// to the sender, which feeds it to AdaptiveQoS as the only data-path loss
// evidence (Node._note_copy / COPY_REPORT).
func TestReplicatedCopiesAreScoredAndReported(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	for i := 0; i < 8; i++ {
		p.step()
	}
	send := func(payload string, onPath ...int) {
		frame, err := p.client.codec.Encode(DataCopy, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range onPath {
			res, err := p.server.ReceiveOn(0, frame, p.src[i], p.now)
			if err != nil {
				t.Fatal(err)
			}
			p.deliver(false, res)
		}
	}
	for i := 0; i < 10; i++ {
		send("both", 0, 1)
	}
	for i := 0; i < 6; i++ {
		send("only-path-0", 0) // path 1 never delivers its copy
	}
	for i := 0; i < 8; i++ {
		p.step()
	}
	var seen, missed [2]uint64
	for k, path := range p.server.paths {
		for i := range p.src {
			if k.Remote == p.src[i] {
				seen[i], missed[i] = path.copySeen, path.copyMissed
			}
		}
	}
	if seen[0] != 16 || missed[0] != 0 || seen[1] != 10 || missed[1] != 6 {
		t.Fatalf("server scores seen=%v missed=%v", seen, missed)
	}
	// The client learned its copies' fate through COPY_REPORT.
	var reported [2][3]uint64
	for k, path := range p.client.paths {
		reported[k.Local] = path.peerCopy
	}
	if reported[0] != [3]uint64{16, 0, 0} || reported[1] != [3]uint64{10, 6, 0} {
		t.Fatalf("client reports %v", reported)
	}
}

// A copy that arrives after its path was counted missed is late, not missed.
func TestLateCopyReversesMissedCount(t *testing.T) {
	p := newClientServerPair(t)
	for i := 0; i < 12 && p.readyClientPaths() < 2; i++ {
		p.step()
	}
	for i := 0; i < 8; i++ {
		p.step()
	}
	frame, _ := p.client.codec.Encode(DataCopy, []byte("x"))
	res, _ := p.server.ReceiveOn(0, frame, p.src[0], p.now)
	p.deliver(false, res)
	for i := 0; i < 4; i++ {
		p.step() // resolves: path 1 missed
	}
	res, _ = p.server.ReceiveOn(0, frame, p.src[1], p.now)
	p.deliver(false, res)
	for k, path := range p.server.paths {
		if k.Remote == p.src[1] && (path.copyMissed != 0 || path.copyLate != 1 || !path.hasCopyLag) {
			t.Fatalf("path 1: missed=%d late=%d", path.copyMissed, path.copyLate)
		}
	}
}

// With loss tracking a replicated priority send is DATA_COPY on every path and
// the server scores it; without it the same send is plain DATA, unscored.
func TestSenderLossTrackingUsesDataCopy(t *testing.T) {
	for _, tracking := range []bool{false, true} {
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
		sender.EnableLossTracking(tracking)
		now := time.Unix(8000, 0)
		srv := netip.MustParseAddrPort("203.0.113.1:4433")
		src := [2]netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:5000"), netip.MustParseAddrPort("198.51.100.2:5000")}
		for i := range src {
			if err := cr.AddClientPath(i, srv, now); err != nil {
				t.Fatal(err)
			}
		}
		var toServer []Datagram
		flush := func() {
			for len(toServer) > 0 {
				d := toServer[0]
				toServer = toServer[1:]
				res, _ := sr.ReceiveOn(0, d.Frame, src[d.Local], now)
				for _, r := range res.Send {
					for i, s := range src {
						if s == r.Endpoint {
							back, _ := cr.ReceiveOn(i, r.Frame, srv, now)
							toServer = append(toServer, back.Send...)
						}
					}
				}
			}
		}
		step := func() {
			now = now.Add(50 * time.Millisecond)
			co, _ := cr.Tick(now)
			toServer = append(toServer, co.Send...)
			so, _ := sr.Tick(now)
			for _, r := range so.Send {
				for i, s := range src {
					if s == r.Endpoint {
						back, _ := cr.ReceiveOn(i, r.Frame, srv, now)
						toServer = append(toServer, back.Send...)
					}
				}
			}
			flush()
		}
		for i := 0; i < 60 && cr.ReadyPaths(now) < 2; i++ {
			step()
		}
		for i := 0; i < 10; i++ {
			step()
		}
		var sent []Datagram
		write := func(d Datagram) error { sent = append(sent, d); toServer = append(toServer, d); return nil }
		for i := 0; i < 5; i++ {
			if n, err := sender.Urgent([]byte("game"), true, now, write); err != nil || n != 2 {
				t.Fatalf("urgent sent %d err %v", n, err)
			}
			flush()
		}
		for i := 0; i < 8; i++ {
			step()
		}
		kinds := map[byte]int{}
		for _, d := range sent {
			pkt, err := sc.Decode(d.Frame)
			if err != nil {
				t.Fatal(err)
			}
			kinds[pkt.Header.Kind]++
		}
		var seen uint64
		for _, path := range sr.paths {
			seen += path.copySeen
		}
		want := byte(Data)
		if tracking {
			want = DataCopy
		}
		if kinds[want] != 10 || len(kinds) != 1 {
			t.Fatalf("tracking=%v frame kinds %v", tracking, kinds)
		}
		if tracking && seen != 10 || !tracking && seen != 0 {
			t.Fatalf("tracking=%v server scored %d copies", tracking, seen)
		}
	}
}
