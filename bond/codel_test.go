package bond

import (
	"testing"
	"time"
)

func TestCoDelLeavesShortQueuesAloneAndActsOnStandingDelay(t *testing.T) {
	var c codelState
	t0 := time.Unix(1000, 0)
	for i := 0; i < 50; i++ {
		if c.judge("f", 2*time.Millisecond, false, t0.Add(time.Duration(i)*10*time.Millisecond)) != codelKeep {
			t.Fatal("acted on a short queue")
		}
	}
	var drops, marks int
	for i := 0; i < 200; i++ { // 2 s of 120 ms standing delay
		switch c.judge("g", 120*time.Millisecond, i%2 == 0, t0.Add(time.Duration(i)*10*time.Millisecond)) {
		case codelDrop:
			drops++
		case codelMark:
			marks++
		}
	}
	if drops+marks < 3 {
		t.Fatalf("standing queue not controlled: drops %d marks %d", drops, marks)
	}
	if c.judge("g", time.Millisecond, false, t0.Add(2*time.Second)) != codelKeep {
		t.Fatal("kept acting after the queue drained")
	}
}

func TestMarkCESetsCEAndKeepsChecksumValid(t *testing.T) {
	p := make([]byte, 40)
	p[0], p[1], p[8], p[9] = 0x45, 0x02, 64, 6 // ECT(0)
	p[3] = 40
	if !markCE(p) || p[1]&3 != 3 {
		t.Fatal("not marked")
	}
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	if sum != 0xFFFF {
		t.Fatalf("bad checksum %x", sum)
	}
	p[1] = 0
	if markCE(p) {
		t.Fatal("marked a non-ECN packet")
	}
}
