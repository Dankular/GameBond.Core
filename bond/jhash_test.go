package bond

import (
	"encoding/binary"
	"testing"
)

func TestLinuxJenkinsHashMatchesReferenceVectors(t *testing.T) {
	if got := linuxJenkinsHash(nil, 0); got != 0xdeadbeef {
		t.Fatalf("empty key hash = %#08x, want %#08x", got, uint32(0xdeadbeef))
	}
	key := make([]byte, 12)
	for i, word := range []uint32{123, 234, 345} {
		binary.LittleEndian.PutUint32(key[i*4:], word)
	}
	if got := linuxJenkinsHash(key, 456); got != 2698615579 {
		t.Fatalf("Linux jhash vector = %d, want 2698615579", got)
	}
}
