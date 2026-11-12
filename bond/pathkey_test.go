package bond

import (
	"bytes"
	"net/netip"
	"testing"
)

// pk is the key of a server path, which always uses local socket 0.
func pk(e netip.AddrPort) PathKey { return PathKey{Remote: e} }

// A client has one socket per uplink, so the same remote endpoint is reached on
// several local sockets. They must be distinct paths and replies must go back
// out of the socket that received the request.
func TestPathsSharingARemoteEndpointStayDistinctPerLocalSocket(t *testing.T) {
	f := newReceiverFixture(t)
	handshake := func(local int) ReceiveResult {
		hello, err := f.c.Encode(Hello, bytes.Repeat([]byte{byte(9 + local)}, 16))
		if err != nil {
			t.Fatal(err)
		}
		out, err := f.r.ReceiveOn(local, hello, f.endpoint, f.now)
		if err != nil || len(out.Send) != 1 || out.Send[0].Local != local {
			t.Fatalf("local %d: challenge = %+v err %v", local, out.Send, err)
		}
		challenge, err := f.c.Decode(out.Send[0].Frame)
		if err != nil {
			t.Fatal(err)
		}
		reset, _ := f.c.Encode(Reset, challenge.Payload)
		out, err = f.r.ReceiveOn(local, reset, f.endpoint, f.now)
		if err != nil || len(out.Send) != 1 || out.Send[0].Local != local {
			t.Fatalf("local %d: ready = %+v err %v", local, out.Send, err)
		}
		return out
	}
	handshake(0)
	handshake(1)
	if len(f.r.paths) != 2 {
		t.Fatalf("paths = %d, want 2 distinct paths for one remote endpoint", len(f.r.paths))
	}
	for local := 0; local < 2; local++ {
		p := f.r.paths[PathKey{local, f.endpoint}]
		if p == nil || !p.ready || p.local != local {
			t.Fatalf("path for local %d = %+v", local, p)
		}
	}
	// A probe on socket 1 is answered from socket 1 and touches only that path.
	frame, _ := f.c.Encode(Probe, probe(1))
	out, err := f.r.ReceiveOn(1, frame, f.endpoint, f.now)
	if err != nil || len(out.Send) != 1 || out.Send[0].Local != 1 {
		t.Fatalf("pong = %+v err %v", out.Send, err)
	}
}
