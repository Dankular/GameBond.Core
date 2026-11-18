package bond

import (
	"encoding/binary"
	"math/bits"
)

// linuxJenkinsHash is the Linux jhash() byte-key variant of Bob Jenkins'
// lookup3 hash, used by FQ-CoDel for packet flow classification. The byte
// order and mix/final operations match include/linux/jhash.h.
func linuxJenkinsHash(key []byte, seed uint32) uint32 {
	a, b, c := uint32(0xdeadbeef)+uint32(len(key))+seed, uint32(0xdeadbeef)+uint32(len(key))+seed, uint32(0xdeadbeef)+uint32(len(key))+seed
	for len(key) > 12 {
		a += binary.LittleEndian.Uint32(key[0:4])
		b += binary.LittleEndian.Uint32(key[4:8])
		c += binary.LittleEndian.Uint32(key[8:12])
		a, b, c = jhashMix(a, b, c)
		key = key[12:]
	}
	switch len(key) {
	case 12:
		c += uint32(key[11]) << 24
		fallthrough
	case 11:
		c += uint32(key[10]) << 16
		fallthrough
	case 10:
		c += uint32(key[9]) << 8
		fallthrough
	case 9:
		c += uint32(key[8])
		fallthrough
	case 8:
		b += uint32(key[7]) << 24
		fallthrough
	case 7:
		b += uint32(key[6]) << 16
		fallthrough
	case 6:
		b += uint32(key[5]) << 8
		fallthrough
	case 5:
		b += uint32(key[4])
		fallthrough
	case 4:
		a += uint32(key[3]) << 24
		fallthrough
	case 3:
		a += uint32(key[2]) << 16
		fallthrough
	case 2:
		a += uint32(key[1]) << 8
		fallthrough
	case 1:
		a += uint32(key[0])
		a, b, c = jhashFinal(a, b, c)
	}
	return c
}

func jhashMix(a, b, c uint32) (uint32, uint32, uint32) {
	a -= c
	a ^= bits.RotateLeft32(c, 4)
	c += b
	b -= a
	b ^= bits.RotateLeft32(a, 6)
	a += c
	c -= b
	c ^= bits.RotateLeft32(b, 8)
	b += a
	a -= c
	a ^= bits.RotateLeft32(c, 16)
	c += b
	b -= a
	b ^= bits.RotateLeft32(a, 19)
	a += c
	c -= b
	c ^= bits.RotateLeft32(b, 4)
	b += a
	return a, b, c
}

func jhashFinal(a, b, c uint32) (uint32, uint32, uint32) {
	c ^= b
	c -= bits.RotateLeft32(b, 14)
	a ^= c
	a -= bits.RotateLeft32(c, 11)
	b ^= a
	b -= bits.RotateLeft32(a, 25)
	c ^= b
	c -= bits.RotateLeft32(b, 16)
	a ^= c
	a -= bits.RotateLeft32(c, 4)
	b ^= a
	b -= bits.RotateLeft32(a, 14)
	c ^= b
	c -= bits.RotateLeft32(b, 24)
	return a, b, c
}
