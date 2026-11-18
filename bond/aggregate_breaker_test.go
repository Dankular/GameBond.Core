package bond

import (
	"testing"
	"time"
)

func driveAggregateCongestion(f receiverFixture, s *Sender, from time.Time, seconds int) {
	for second := 1; second <= seconds; second++ {
		now := from.Add(time.Duration(second) * time.Second)
		for _, p := range f.r.paths {
			p.budget.lossSeen = true
			p.budget.lossAt = f.r.seconds(now)
			p.budget.congestionEpochs = 2
			p.budget.sentBytes += 20000
			p.budget.deliveryCounter += 18000
		}
		s.observeAggregateCongestion(now)
	}
}

func TestAggregateCongestionBreakerTripsReducesAndRecovers(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	setCongested := func(now time.Time, epochs uint64) {
		for _, p := range f.r.paths {
			p.budget.lossSeen = true
			p.budget.lossAt = f.r.seconds(now)
			p.budget.congestionEpochs = epochs
		}
	}
	setCongested(f.now, 2)
	s.observeAggregateCongestion(f.now)
	if s.aggregateBreaker.phase != aggregateBreakerClosed {
		t.Fatal("breaker tripped before the slow-trip interval")
	}
	tripAt := f.now.Add(aggregateMeterWindow + aggregateBreakerTripDelay)
	driveAggregateCongestion(f, s, f.now, int((aggregateMeterWindow+aggregateBreakerTripDelay)/time.Second))
	if s.aggregateBreaker.phase != aggregateBreakerOpen || s.Stats().CongestionBreakerTrips != 1 {
		t.Fatalf("persistent aggregate congestion did not trip: phase=%v stats=%+v", s.aggregateBreaker.phase, s.Stats())
	}
	var paths []*receivePath
	for _, p := range f.r.paths {
		paths = append(paths, p)
	}
	if got := s.protectionLevel(paths, tripAt); got != protectNone {
		t.Fatalf("open breaker still allows redundancy: protection=%v", got)
	}

	probeAt := s.aggregateBreaker.openUntil
	setCongested(probeAt, 0)
	s.observeAggregateCongestion(probeAt)
	if s.aggregateBreaker.phase != aggregateBreakerHalfOpen {
		t.Fatalf("breaker did not enter half-open: %v", s.aggregateBreaker.phase)
	}
	if got := s.protectionLevel(paths, probeAt); got != protectParity {
		t.Fatalf("half-open phase did not use reduced parity protection: %v", got)
	}

	closeAt := probeAt.Add(aggregateBreakerProbeTime)
	setCongested(closeAt, 0)
	s.observeAggregateCongestion(closeAt)
	if s.aggregateBreaker.phase != aggregateBreakerClosed {
		t.Fatalf("breaker did not close after a clean probe: %v", s.aggregateBreaker.phase)
	}
}

func TestAggregateCongestionBreakerIgnoresStaleOrUncorroboratedFeedback(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	for _, p := range f.r.paths {
		p.budget.lossSeen = true
		p.budget.lossAt = f.r.seconds(f.now.Add(-2 * lossStale * time.Second))
		p.budget.congestionEpochs = 10
	}
	s.observeAggregateCongestion(f.now)
	s.observeAggregateCongestion(f.now.Add(aggregateBreakerTripDelay))
	if s.aggregateBreaker.phase != aggregateBreakerClosed || s.Stats().CongestionBreakerTrips != 0 {
		t.Fatalf("stale path feedback tripped the aggregate breaker: %+v", s.Stats())
	}

	for _, p := range f.r.paths {
		p.budget.lossAt = f.r.seconds(f.now.Add(aggregateBreakerTripDelay))
		p.budget.congestionEpochs = 1 // one isolated congestion epoch is not persistent evidence
	}
	s.observeAggregateCongestion(f.now.Add(aggregateBreakerTripDelay))
	s.observeAggregateCongestion(f.now.Add(2 * aggregateBreakerTripDelay))
	if s.aggregateBreaker.phase != aggregateBreakerClosed || s.Stats().CongestionBreakerTrips != 0 {
		t.Fatalf("single congestion epochs tripped the breaker: %+v", s.Stats())
	}
}

func TestAggregateCongestionBreakerRequiresAggregateLoss(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	s.observeAggregateCongestion(f.now)
	for second := 1; second <= int((aggregateMeterWindow+aggregateBreakerTripDelay)/time.Second); second++ {
		now := f.now.Add(time.Duration(second) * time.Second)
		for _, p := range f.r.paths {
			p.budget.lossSeen = true
			p.budget.lossAt = f.r.seconds(now)
			p.budget.congestionEpochs = 2
			p.budget.sentBytes += 20000
			p.budget.deliveryCounter += 20000
		}
		s.observeAggregateCongestion(now)
	}
	if s.aggregateBreaker.phase != aggregateBreakerClosed || s.Stats().CongestionBreakerTrips != 0 || s.Stats().AggregateWindowLossRatio != 0 {
		t.Fatalf("breaker tripped without aggregate loss evidence: %+v", s.Stats())
	}
}

func TestAggregateCongestionBreakerExtendsAfterFailedProbe(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	setCongested := func(now time.Time) {
		for _, p := range f.r.paths {
			p.budget.lossSeen = true
			p.budget.lossAt = f.r.seconds(now)
			p.budget.congestionEpochs = 2
		}
	}
	setCongested(f.now)
	s.observeAggregateCongestion(f.now)
	driveAggregateCongestion(f, s, f.now, int((aggregateMeterWindow+aggregateBreakerTripDelay)/time.Second))
	firstOpen := s.aggregateBreaker.openDuration
	probeAt := s.aggregateBreaker.openUntil
	setCongested(probeAt)
	s.observeAggregateCongestion(probeAt)
	if s.aggregateBreaker.phase != aggregateBreakerHalfOpen {
		t.Fatal("did not grant a half-open probe interval")
	}
	driveAggregateCongestion(f, s, probeAt, int(aggregateBreakerProbeTime/time.Second))
	if s.aggregateBreaker.phase != aggregateBreakerOpen || s.aggregateBreaker.openDuration != 2*firstOpen || s.Stats().CongestionBreakerTrips != 2 {
		t.Fatalf("failed probe did not extend backoff: phase=%v duration=%v stats=%+v", s.aggregateBreaker.phase, s.aggregateBreaker.openDuration, s.Stats())
	}
}

func TestAggregateCongestionBreakerReducesActualWireCopies(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	s.aggregateBreaker.phase = aggregateBreakerOpen
	s.aggregateBreaker.openUntil = f.now.Add(time.Minute)
	urgentWrites := 0
	if _, err := s.Urgent([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17}, true, f.now, func(Datagram) error {
		urgentWrites++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if urgentWrites != 1 {
		t.Fatalf("open breaker wrote %d urgent copies, want one", urgentWrites)
	}

	s.lossTiered = false
	bulkWrites := 0
	ok, _, err := s.Bulk([]byte("bonded bulk payload"), "breaker-flow", f.now, func(Datagram) error {
		bulkWrites++
		return nil
	})
	if err != nil || !ok {
		t.Fatalf("bulk send failed during breaker open: sent=%v err=%v", ok, err)
	}
	if bulkWrites != 1 {
		t.Fatalf("open breaker wrote %d bulk copies, want one", bulkWrites)
	}
}

func TestAggregateCongestionMeterCountsCopiesAndAcknowledgedBytes(t *testing.T) {
	f, s, _ := senderFixture(t, 2)
	s.sampleAggregateTraffic(f.now)
	paths := make([]*receivePath, 0, len(f.r.paths))
	for _, p := range f.r.paths {
		paths = append(paths, p)
	}
	paths[0].budget.sentBytes = 1200
	paths[0].budget.deliveryCounter = 900
	paths[0].budget.expiredBytes = 60
	paths[1].budget.sentBytes = 800 // includes a duplicated copy on this path
	paths[1].budget.deliveryCounter = 600
	s.sampleAggregateTraffic(f.now.Add(time.Second))
	stats := s.Stats()
	if stats.AggregateSentBytesPerSecond != 2000 || stats.AggregateDeliveredBytesPerSecond != 1500 || stats.AggregateExpiredByteRatio != .03 {
		t.Fatalf("aggregate wire accounting omitted copies or feedback: %+v", stats)
	}
}
