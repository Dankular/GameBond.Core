package bond

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func udpPacket(source, destination uint16, tag byte) []byte {
	p := make([]byte, 36)
	p[0] = 0x45
	p[1] = tag << 2
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:], 36)
	copy(p[12:20], []byte{10, 77, 0, 2, 1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:], source)
	binary.BigEndian.PutUint16(p[22:], destination)
	binary.BigEndian.PutUint16(p[24:], 16)
	return p
}
func reverseUDP(p []byte) []byte {
	b := append([]byte(nil), p...)
	copy(b[12:16], p[16:20])
	copy(b[16:20], p[12:16])
	copy(b[20:22], p[22:24])
	copy(b[22:24], p[20:22])
	return b
}
func TestClassifierLearnsBidirectionalProfilesAndDoesNotGuessQUIC(t *testing.T) {
	c, _ := NewClassifier(nil, []uint16{3075}, DefaultQoSSettings())
	now := time.Now()
	for _, tag := range []byte{18, 26, 46} {
		now = now.Add(122 * time.Second)
		packet := udpPacket(1234+uint16(tag), 443, tag)
		p, _ := ParseIPv4(packet)
		classification := c.Classify(p, now)
		if !classification.Policy.Priority || classification.Tag != tag {
			t.Fatal("explicit profile lost")
		}
		reverse := reverseUDP(packet)
		reverse[1] = 0
		p, _ = ParseIPv4(reverse)
		classification = c.Classify(p, now)
		if classification.Tag != tag || classification.Reason != "flow_cache" {
			t.Fatal("return profile was not learned")
		}
		classification = c.Classify(p, now.Add(121*time.Second))
		if classification.Tag != 0 {
			t.Fatal("expired profile persisted")
		}
	}
	now = now.Add(122 * time.Second)
	packet := udpPacket(8000, 443, 0)
	p, _ := ParseIPv4(packet)
	if result := c.Classify(p, now.Add(122*time.Second)); result.Policy.Priority {
		t.Fatal("ordinary QUIC guessed interactive")
	}
	packet = udpPacket(8000, 3075, 0)
	p, _ = ParseIPv4(packet)
	if result := c.Classify(p, now.Add(123*time.Second)); result.Tag != 46 || !result.Policy.Replicate {
		t.Fatal("explicit game port not honored")
	}
}
func TestFragmentPolicyAssociationIsBoundedAndOrphansStayBulk(t *testing.T) {
	c, _ := NewClassifier(nil, []uint16{3075}, DefaultQoSSettings())
	now := time.Now()
	first := udpPacket(1234, 3075, 0)
	first[6] = 0x20
	binary.BigEndian.PutUint16(first[24:], 32)
	p, err := ParseIPv4(first)
	if err != nil || p.Flow != "" || p.PolicyFlow == "" {
		t.Fatal("first fragment transport parsing wrong", err)
	}
	if c.Classify(p, now).Tag != 46 {
		t.Fatal("first fragment game policy lost")
	}
	later := append([]byte(nil), first...)
	later[6] = 0
	later[7] = 2
	p, err = ParseIPv4(later)
	if err != nil {
		t.Fatal(err)
	}
	if result := c.Classify(p, now.Add(time.Second)); result.Tag != 46 || result.Reason != "fragment_cache" {
		t.Fatal("later fragment association lost")
	}
	if result := c.Classify(p, now.Add(3*time.Second)); result.Tag != 0 {
		t.Fatal("later fragments extended TTL")
	}
}
func TestAdaptiveRedundancyRequiresFreshQualityAndHasRecoveryHold(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	q, _ := NewAdaptiveQoS(DefaultQoSSettings())
	q.Observe(s, f.now)
	if q.Replicate(26, 200, false, f.now) {
		t.Fatal("healthy call duplicated without risk")
	}
	for _, endpoint := range a {
		p := f.r.paths[pk(endpoint)]
		p.budget.lossRatio = .2
		p.budget.deliveryCounter += 1000
	}
	q.Observe(s, f.now.Add(500*time.Millisecond))
	if !q.Replicate(26, 200, false, f.now.Add(500*time.Millisecond)) {
		t.Fatal("fresh measured loss did not activate redundancy")
	}
	for _, endpoint := range a {
		f.r.paths[pk(endpoint)].last = f.now.Add(4 * time.Second)
	}
	q.Observe(s, f.now.Add(time.Second))
	if !q.Replicate(18, 200, false, f.now.Add(time.Second)) {
		t.Fatal("recovery hold lost")
	}
	q.Observe(s, f.now.Add(4*time.Second))
	if q.Replicate(26, 200, false, f.now.Add(4*time.Second)) {
		t.Fatal("stale settled loss prolonged redundancy forever")
	}
}
func TestDuplicateBudgetIsBoundedAndDisabledQoSPreservesExplicitPolicy(t *testing.T) {
	f, s, a := senderFixture(t, 2)
	q, _ := NewAdaptiveQoS(DefaultQoSSettings())
	for _, endpoint := range a {
		p := f.r.paths[pk(endpoint)]
		p.jitter = .02
	}
	q.Observe(s, f.now)
	if !q.Replicate(26, 1200, false, f.now) || !q.Replicate(26, 1200, false, f.now) || q.Replicate(26, 1200, false, f.now) {
		t.Fatal("duplicate burst budget not bounded")
	}
	if !q.Replicate(46, 1200, true, f.now) {
		t.Fatal("explicit gameplay policy changed")
	}
	settings := DefaultQoSSettings()
	settings.Enabled = false
	q, _ = NewAdaptiveQoS(settings)
	if q.Replicate(26, 1200, false, f.now) || !q.Replicate(46, 1200, true, f.now) {
		t.Fatal("disabled QoS overrode explicit policy")
	}
	settings.DuplicateMbps = math.NaN()
	if _, err := NewAdaptiveQoS(settings); err == nil {
		t.Fatal("invalid settings accepted")
	}
}
func TestTransmitQueueProfileCapacityIsIndependent(t *testing.T) {
	f, s, _ := senderFixture(t, 1)
	q, _ := NewTransmitQueue(s, 10, 14000)
	for i := 0; i < 2; i++ {
		if !q.Enqueue(QueuedPacket{Payload: []byte("call"), Tag: 26, ClassCapacity: 2, Priority: true, Expires: f.now.Add(time.Second)}) {
			t.Fatal("call admission failed")
		}
	}
	if q.Enqueue(QueuedPacket{Payload: []byte("call"), Tag: 26, ClassCapacity: 2, Priority: true, Expires: f.now.Add(time.Second)}) {
		t.Fatal("class capacity ignored")
	}
	if !q.Enqueue(QueuedPacket{Payload: []byte("bulk"), Tag: 0, ClassCapacity: 2, Expires: f.now.Add(time.Second)}) {
		t.Fatal("call capacity blocked bulk class")
	}
	q.Pump(f.now, func(Datagram) error { return nil })
	q.Pump(f.now.Add(5*time.Millisecond), func(Datagram) error { return nil })
	if q.classes[26] != 0 || q.classes[0] != 0 {
		t.Fatal("class capacity did not retire")
	}
}
