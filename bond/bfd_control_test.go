package bond

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBFDControlRFC5880DownPacketVector(t *testing.T) {
	packet, err := EncodeBFDControl(BFDControlPacket{
		Version: 1, Diagnostic: 1, State: BFDDown, Poll: true,
		DetectMultiplier: 3, MyDiscriminator: 0x01020304,
		DesiredMinTXInterval: 1_000_000, RequiredMinRXInterval: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("216003180102030400000000000f4240000186a000000000")
	if !bytes.Equal(packet, want) {
		t.Fatalf("BFD wire packet = %x, want %x", packet, want)
	}
	decoded, consumed, err := DecodeBFDControl(append(append([]byte(nil), packet...), 0, 0))
	if err != nil || consumed != len(packet) {
		t.Fatalf("decode with encapsulation padding: consumed=%d err=%v", consumed, err)
	}
	if decoded.Version != 1 || decoded.State != BFDDown || !decoded.Poll || decoded.DetectMultiplier != 3 || decoded.MyDiscriminator != 0x01020304 || decoded.DesiredMinTXInterval != 1_000_000 || decoded.RequiredMinRXInterval != 100_000 {
		t.Fatalf("decoded fields differ from RFC packet: %+v", decoded)
	}
}

func TestBFDControlAuthenticationSectionIsFramedButNotTrusted(t *testing.T) {
	p := BFDControlPacket{
		State: BFDInit, DetectMultiplier: 3, MyDiscriminator: 1, YourDiscriminator: 2,
		DesiredMinTXInterval: 1_000_000, AuthenticationSection: []byte{1, 4, 7, 'x'},
	}
	packet, err := EncodeBFDControl(p)
	if err != nil {
		t.Fatal(err)
	}
	if packet[1]&(1<<2) == 0 || packet[3] != 28 {
		t.Fatalf("authentication flag or packet length wrong: %x", packet[:4])
	}
	got, consumed, err := DecodeBFDControl(packet)
	if err != nil || consumed != len(packet) || !bytes.Equal(got.AuthenticationSection, p.AuthenticationSection) {
		t.Fatalf("authentication section not preserved: %+v consumed=%d err=%v", got, consumed, err)
	}
	// Parsing only preserves bytes. A BFD session must still authenticate them
	// before treating the control packet as valid.
}

func TestBFDControlRejectsRFC5880MalformedFields(t *testing.T) {
	valid, err := EncodeBFDControl(BFDControlPacket{State: BFDDown, DetectMultiplier: 3, MyDiscriminator: 1, DesiredMinTXInterval: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(p []byte) { p[0] = 0x40 }},
		{"multipoint", func(p []byte) { p[1] |= 1 }},
		{"zero detect multiplier", func(p []byte) { p[2] = 0 }},
		{"zero my discriminator", func(p []byte) { p[4], p[5], p[6], p[7] = 0, 0, 0, 0 }},
		{"declared length too short", func(p []byte) { p[3] = 23 }},
		{"declared length beyond payload", func(p []byte) { p[3] = 25 }},
		{"unknown your discriminator with init", func(p []byte) { p[1] = byte(BFDInit) << 6 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := append([]byte(nil), valid...)
			tc.mutate(packet)
			if _, _, err := DecodeBFDControl(packet); err == nil {
				t.Fatal("malformed BFD Control packet accepted")
			}
		})
	}
	if _, err := EncodeBFDControl(BFDControlPacket{State: BFDUp, DetectMultiplier: 3, MyDiscriminator: 1, DesiredMinTXInterval: 1_000_000}); err == nil {
		t.Fatal("encoded Up with unknown remote discriminator")
	}
	if _, err := EncodeBFDControl(BFDControlPacket{State: BFDDown, DetectMultiplier: 3, MyDiscriminator: 1}); err == nil {
		t.Fatal("encoded reserved zero Desired Min TX Interval")
	}
	if _, err := EncodeBFDControl(BFDControlPacket{State: BFDDown, DetectMultiplier: 3, MyDiscriminator: 1, DesiredMinTXInterval: 1_000_000, AuthenticationSection: []byte{1, 5, 7, 'x'}}); err == nil {
		t.Fatal("encoded Authentication Length inconsistent with section size")
	}
}
