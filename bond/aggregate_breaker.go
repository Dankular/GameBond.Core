package bond

import (
	"math"
	"time"
)

// RFC 8084 does not prescribe fixed thresholds. These conservative values make
// this a slow safety backstop; the per-path Budget remains the primary controller.
const (
	aggregateBreakerTripDelay = 10 * time.Second
	aggregateBreakerOpenTime  = 30 * time.Second
	aggregateBreakerProbeTime = 5 * time.Second
	aggregateMeterWindow      = 5 * time.Second
	aggregateMeterMinBytes    = 100 * 1024
	aggregateMeterLossRatio   = .10
)

type aggregateBreakerPhase uint8

const (
	aggregateBreakerClosed aggregateBreakerPhase = iota
	aggregateBreakerOpen
	aggregateBreakerHalfOpen
)

type aggregateCongestionBreaker struct {
	phase         aggregateBreakerPhase
	congestedAt   time.Time
	openUntil     time.Time
	probeUntil    time.Time
	openDuration  time.Duration
	lastSampleAt  time.Time
	lastCounters  map[*Budget]aggregateBudgetCounters
	samples       []aggregateTrafficSample
	windowSent    uint64
	windowAcked   uint64
	windowExpired uint64
	windowLoss    float64
	windowReady   bool
}

type aggregateBudgetCounters struct {
	sent, delivered, expired uint64
}

type aggregateTrafficSample struct {
	start, end               time.Time
	sent, delivered, expired uint64
}

func (b *aggregateCongestionBreaker) state() string {
	switch b.phase {
	case aggregateBreakerOpen:
		return "open"
	case aggregateBreakerHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

// observe uses only recent, independently measured path congestion epochs.
// A sample is trusted only when most ready paths have fresh feedback, avoiding
// a stale or idle path turning into an aggregate congestion signal.
func (s *Sender) observeAggregateCongestion(now time.Time) {
	b := &s.aggregateBreaker
	s.sampleAggregateTraffic(now)
	ready, fresh, congested := 0, 0, 0
	ts := s.r.seconds(now)
	for _, p := range s.r.paths {
		if !p.ready {
			continue
		}
		ready++
		budget := p.budget
		if !budget.lossSeen || ts-budget.lossAt > lossStale {
			continue
		}
		fresh++
		if budget.congestionEpochs >= 2 {
			congested++
		}
	}
	credible := ready > 0 && fresh*2 > ready
	severe := credible && congested*2 >= fresh && b.windowReady && b.windowLoss >= aggregateMeterLossRatio
	if !severe {
		b.congestedAt = time.Time{}
	} else if b.congestedAt.IsZero() {
		b.congestedAt = now
	}

	switch b.phase {
	case aggregateBreakerOpen:
		if now.Before(b.openUntil) {
			s.stats.CongestionBreakerState = b.state()
			return
		}
		b.phase = aggregateBreakerHalfOpen
		b.probeUntil = now.Add(aggregateBreakerProbeTime)
	case aggregateBreakerHalfOpen:
		if !now.Before(b.probeUntil) {
			if severe {
				s.tripAggregateBreaker(now)
			} else {
				b.phase = aggregateBreakerClosed
				b.openDuration = 0
			}
		}
	case aggregateBreakerClosed:
		if severe && now.Sub(b.congestedAt) >= aggregateBreakerTripDelay {
			s.tripAggregateBreaker(now)
		}
	}
	s.stats.CongestionBreakerState = b.state()
}

// sampleAggregateTraffic meters actual bonded wire payload, including copies,
// alongside bytes acknowledged by the peer. It is independent of the breaker
// trigger's per-path congestion epochs and is exposed for operations/validation.
func (s *Sender) sampleAggregateTraffic(now time.Time) {
	b := &s.aggregateBreaker
	if b.lastSampleAt.IsZero() {
		b.lastSampleAt = now
		b.lastCounters = make(map[*Budget]aggregateBudgetCounters, len(s.r.paths))
		for _, p := range s.r.paths {
			b.lastCounters[p.budget] = aggregateBudgetCounters{p.budget.sentBytes, p.budget.deliveryCounter, p.budget.expiredBytes}
		}
		return
	}
	elapsed := now.Sub(b.lastSampleAt).Seconds()
	if elapsed < 1 {
		return
	}
	if elapsed > 2*aggregateMeterWindow.Seconds() {
		b.samples = nil
		b.windowReady = false
		b.windowSent, b.windowAcked, b.windowExpired, b.windowLoss = 0, 0, 0, 0
		s.stats.AggregateWindowSentBytes = 0
		s.stats.AggregateWindowLossRatio = 0
		b.lastSampleAt = now
		for _, p := range s.r.paths {
			b.lastCounters[p.budget] = aggregateBudgetCounters{p.budget.sentBytes, p.budget.deliveryCounter, p.budget.expiredBytes}
		}
		return
	}
	active := make(map[*Budget]struct{}, len(s.r.paths))
	var sent, delivered, expired uint64
	for _, p := range s.r.paths {
		budget := p.budget
		active[budget] = struct{}{}
		current := aggregateBudgetCounters{budget.sentBytes, budget.deliveryCounter, budget.expiredBytes}
		previous, exists := b.lastCounters[budget]
		if exists {
			sent += deltaCounter(current.sent, previous.sent)
			delivered += deltaCounter(current.delivered, previous.delivered)
			expired += deltaCounter(current.expired, previous.expired)
		} else {
			sent += current.sent
			delivered += current.delivered
			expired += current.expired
		}
		b.lastCounters[budget] = current
	}
	for budget := range b.lastCounters {
		if _, ok := active[budget]; !ok {
			delete(b.lastCounters, budget)
		}
	}
	s.stats.AggregateSentBytesPerSecond = float64(sent) / elapsed
	s.stats.AggregateDeliveredBytesPerSecond = float64(delivered) / elapsed
	s.stats.AggregateExpiredByteRatio = 0
	if sent > 0 {
		s.stats.AggregateExpiredByteRatio = float64(expired) / float64(sent)
	}
	b.samples = append(b.samples, aggregateTrafficSample{start: b.lastSampleAt, end: now, sent: sent, delivered: delivered, expired: expired})
	b.lastSampleAt = now
	cutoff := now.Add(-aggregateMeterWindow)
	kept := b.samples[:0]
	b.windowSent, b.windowAcked, b.windowExpired = 0, 0, 0
	for _, sample := range b.samples {
		if !sample.end.After(cutoff) {
			continue
		}
		kept = append(kept, sample)
		b.windowSent += sample.sent
		b.windowAcked += sample.delivered
		b.windowExpired += sample.expired
	}
	b.samples = kept
	b.windowReady = len(kept) > 0 && now.Sub(kept[0].start) >= aggregateMeterWindow
	b.windowLoss = 0
	if b.windowSent > 0 {
		unacknowledged := math.Max(0, float64(b.windowSent)-float64(b.windowAcked)) / float64(b.windowSent)
		expired := float64(b.windowExpired) / float64(b.windowSent)
		b.windowLoss = math.Max(unacknowledged, expired)
	}
	s.stats.AggregateWindowSentBytes = b.windowSent
	s.stats.AggregateWindowLossRatio = b.windowLoss
	b.lastSampleAt = now
}

func deltaCounter(current, previous uint64) uint64 {
	if current < previous { // counter reset/replaced; re-baseline without underflow
		return current
	}
	return current - previous
}

func (s *Sender) tripAggregateBreaker(now time.Time) {
	b := &s.aggregateBreaker
	b.phase = aggregateBreakerOpen
	if b.openDuration == 0 {
		b.openDuration = aggregateBreakerOpenTime
	} else {
		b.openDuration *= 2
		if b.openDuration > 5*time.Minute {
			b.openDuration = 5 * time.Minute
		}
	}
	b.openUntil = now.Add(b.openDuration)
	s.stats.CongestionBreakerTrips++
}

func (s *Sender) aggregateReductionActive(now time.Time) bool {
	s.observeAggregateCongestion(now)
	return s.aggregateBreaker.phase != aggregateBreakerClosed
}
