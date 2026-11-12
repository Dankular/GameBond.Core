package bond

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/rand"
	"sync"
	"testing"
)

func testCodec(t *testing.T, role string) *Codec {
	t.Helper()
	key := make([]byte, 32)
	session := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range session {
		session[i] = byte(i)
	}
	var prefix [16]byte
	for i := range prefix {
		prefix[i] = byte(i + 16)
	}
	c, err := newCodec(key, session, role, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMatchesExistingPythonCipherVector(t *testing.T) {
	client, server := testCodec(t, "client"), testCodec(t, "server")
	client.sequence.Store(17)
	frame, err := client.Encode(Data, []byte("cross-language-vector"))
	if err != nil {
		t.Fatal(err)
	}
	const expected = "47423033000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01000000000000001133c66e946a909a695657836736b9a234cbfd7b7869f485744dc17ee4f15028bbfe7f554986"
	if hex.EncodeToString(frame) != expected {
		t.Fatal("wire format differs from Python")
	}
	packet, err := server.Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.Sequence != 17 || packet.Header.Kind != Data || !bytes.Equal(packet.Payload, []byte("cross-language-vector")) {
		t.Fatal("decode mismatch")
	}
}

func TestHeaderCiphertextAndTagTamperingAreRejected(t *testing.T) {
	client, server := testCodec(t, "client"), testCodec(t, "server")
	frame, _ := client.Encode(Data, []byte("payload"))
	for index := range frame {
		altered := append([]byte(nil), frame...)
		altered[index] ^= 1
		if _, err := server.Decode(altered); err == nil {
			t.Fatalf("accepted altered byte %d", index)
		}
	}
	if len(server.rx) != 0 {
		t.Fatal("unauthenticated domains populated receiver cache")
	}
}

func TestConcurrentSendNeverReusesNoncesAndStopsAtExhaustion(t *testing.T) {
	client, server := testCodec(t, "client"), testCodec(t, "server")
	frames := make(chan []byte, 2000)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				frame, err := client.Encode(Data, []byte("x"))
				if err != nil {
					panic(err)
				}
				frames <- frame
			}
		}()
	}
	workers.Wait()
	close(frames)
	seen := make(map[uint64]bool)
	for frame := range frames {
		packet, err := server.Decode(frame)
		if err != nil {
			t.Fatal(err)
		}
		if seen[packet.Header.Sequence] {
			t.Fatal("nonce reused")
		}
		seen[packet.Header.Sequence] = true
	}
	client.sequence.Store(math.MaxUint64)
	if _, err := client.Encode(Data, nil); err != ErrNonceExhausted {
		t.Fatal("nonce exhaustion did not fail closed")
	}
}

func TestReplayWindowRetainsLateFirstArrivalsAndRejectsKnownCopies(t *testing.T) {
	var w ReplayWindow
	if !w.Accept(0) || !w.Accept(65) || !w.Accept(64) || w.Accept(0) || w.Accept(65) {
		t.Fatal("replay bitmap shift mismatch")
	}
	if !w.Accept(8191) || !w.Accept(1) || w.Accept(1) {
		t.Fatal("late first arrival rejected or duplicate accepted")
	}
	if !w.Accept(20000) || w.Accept(8191) || !w.Accept(19999) {
		t.Fatal("bounded replay window mismatch")
	}
}

func BenchmarkCodecSeal(b *testing.B) {
	key := make([]byte, 32)
	session := make([]byte, 16)
	client, _ := NewCodec(key, session, "server")
	payload := make([]byte, 1304)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Encode(Striped, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func TestReplayWindowEdgesAndForwardJumpLimit(t *testing.T) {
	var w ReplayWindow
	w.Accept(100000)
	if w.Check(100000) != ReplayDuplicate {
		t.Fatal("highest not a duplicate")
	}
	if w.Check(100000-replayWidth+1) != ReplayNew || w.Check(100000-replayWidth) != ReplayTooOld {
		t.Fatal("window edge")
	}
	if w.Check(100000+maxForwardJump) != ReplayNew || w.Check(100000+maxForwardJump+1) != ReplayTooFar {
		t.Fatal("forward limit")
	}
	if w.Accept(100000+maxForwardJump+1) || w.Check(100000) != ReplayDuplicate {
		t.Fatal("a refused jump changed the window")
	}
	if w.Check(100001) != ReplayNew {
		t.Fatal("window moved after refused jump")
	}
}

// The bitmap must agree with a plain map model for any mix of in-order, late and
// repeated sequence numbers, including shifts across 64-bit word boundaries.
func TestReplayWindowMatchesModel(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var w ReplayWindow
	seen := map[uint64]bool{}
	var high uint64
	started := false
	for i := 0; i < 300000; i++ {
		var seq uint64
		switch rng.Intn(4) {
		case 0:
			seq = high + uint64(rng.Intn(200))
		case 1:
			seq = high + uint64(rng.Intn(3*replayWidth))
		default:
			back := uint64(rng.Intn(replayWidth + 100))
			if back > high {
				back = high
			}
			seq = high - back
		}
		want := !seen[seq]
		if started && seq < high && high-seq >= replayWidth {
			want = false
		}
		if got := w.Accept(seq); got != want {
			t.Fatalf("step %d seq %d high %d: got %v want %v", i, seq, high, got, want)
		}
		if want {
			seen[seq] = true
			if !started || seq > high {
				high = seq
			}
			started = true
		}
	}
}
