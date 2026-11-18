package bond

import (
	"errors"
	"slices"
)

// DPLPMTUDState is the per-path state from RFC 8899 Section 5.2.
type DPLPMTUDState string

const (
	DPLPMTUDBase           DPLPMTUDState = "base"
	DPLPMTUDSearching      DPLPMTUDState = "searching"
	DPLPMTUDSearchComplete DPLPMTUDState = "search_complete"
	DPLPMTUDError          DPLPMTUDState = "error"
	DPLPMTUDisabled        DPLPMTUDState = "disabled"
)

const (
	dplBasePLPMTU      = 1200 // RFC 8899 recommended IPv4 baseline at this UDP packetization layer
	dplProbeTimeout    = 16.0 // RFC 8899: SHOULD be greater than 15 seconds.
	dplMaxProbes       = 3
	dplRaiseTimer      = 600.0 // RFC 8899 PMTU_RAISE_TIMER.
	dplMinimumProbeGap = 1.0   // Never probe faster than one RTT; RTT raises this.
)

// DPLPMTUD is a per-path RFC 8899 search over GB03's authenticated MTU probe
// exchange. Sizes are complete UDP payloads at the GameBond packetization
// layer; the configured ceiling remains the local UDP payload limit.
// All methods are called from the owning packet-loop goroutine.
type DPLPMTUD struct {
	minimum, base, maximum, confirmed int
	sizes                             []int
	state                             DPLPMTUDState
	probeSize                         int
	probeNonce                        uint64
	probeSentAt                       float64
	hasOutstanding                    bool
	probeCount                        int
	lastProbeAt                       float64
	hasLastProbe                      bool
	nextRaiseAt                       float64
	hasRaise                          bool
	rounds, acks                      int
	failedSizes                       []int
	dataOutcomes                      []SackObservation
}

// ObserveDataOutcome consumes authenticated selective feedback for ordinary
// data frames. A black hole is declared only when repeated larger-frame losses
// coexist with successful smaller frames in a majority-loss sample window.
func (p *DPLPMTUD) ObserveDataOutcome(o SackObservation, now float64) bool {
	if o.FrameSize <= 0 || !validTime(now) {
		return false
	}
	p.dataOutcomes = append(p.dataOutcomes, o)
	if len(p.dataOutcomes) > 50 {
		p.dataOutcomes = p.dataOutcomes[len(p.dataOutcomes)-50:]
	}
	if p.confirmed <= p.minimum || len(p.dataOutcomes) < 6 {
		return false
	}
	maxLost := 0
	for _, sample := range p.dataOutcomes {
		if !sample.Delivered && sample.FrameSize > maxLost {
			maxLost = sample.FrameSize
		}
	}
	if maxLost == 0 {
		return false
	}
	safeSize, smallDelivered := 0, 0
	for _, sample := range p.dataOutcomes {
		if sample.Delivered && sample.FrameSize < maxLost {
			smallDelivered++
			if sample.FrameSize > safeSize {
				safeSize = sample.FrameSize
			}
		}
	}
	largeLost := 0
	for _, sample := range p.dataOutcomes {
		if !sample.Delivered && sample.FrameSize > safeSize {
			largeLost++
		}
	}
	if largeLost < 3 || smallDelivered < 3 || safeSize < p.minimum || largeLost*2 <= len(p.dataOutcomes) {
		return false
	}
	// The size boundary comes from authenticated data outcomes: retain the largest
	// smaller packet actually delivered and stop using larger sizes while probing
	// is deferred. A path may have changed since its earlier probe succeeded.
	p.confirmed = safeSize
	p.state = DPLPMTUDSearchComplete
	p.probeCount = 0
	p.hasOutstanding = false
	p.hasRaise = true
	p.nextRaiseAt = now + dplRaiseTimer
	p.dataOutcomes = nil
	return true
}

func NewDPLPMTUD(maximum, minimum int) (*DPLPMTUD, error) {
	if minimum <= 0 || maximum < minimum {
		return nil, errors.New("invalid DPLPMTUD bounds")
	}
	base := min(dplBasePLPMTU, maximum)
	if base < minimum {
		base = minimum
	}
	set := map[int]struct{}{maximum: {}, minimum: {}, base: {}}
	for _, size := range MTULadder {
		if size >= minimum && size <= maximum {
			set[size] = struct{}{}
		}
	}
	sizes := make([]int, 0, len(set))
	for size := range set {
		sizes = append(sizes, size)
	}
	slices.Sort(sizes)
	return &DPLPMTUD{minimum: minimum, base: base, maximum: maximum, sizes: sizes, state: DPLPMTUDBase, probeSize: base}, nil
}

func (p *DPLPMTUD) State() DPLPMTUDState { return p.state }

// PathChanged abandons probes and restarts from BASE when the transport
// confirms a new/re-established path. Probe acknowledgements from the prior
// path must not influence the new path's packetization size.
func (p *DPLPMTUD) PathChanged() {
	p.confirmed = 0
	p.state = DPLPMTUDBase
	p.probeSize = p.base
	p.probeCount = 0
	p.hasOutstanding = false
	p.hasLastProbe = false
	p.hasRaise = false
	p.failedSizes = nil
	p.dataOutcomes = nil
}

// PathMTU returns the largest acknowledged UDP payload size, or the
// conservative BASE_PLPMTU while the base probe is being confirmed.
func (p *DPLPMTUD) PathMTU() int {
	if p.state == DPLPMTUDisabled {
		return 0
	}
	if p.confirmed > 0 {
		return p.confirmed
	}
	return p.minimum
}

// nextSearchSize selects the next larger common size, probing one size at a
// time. The maximum is always included even when it is not in MTULadder.
func (p *DPLPMTUD) nextSearchSize() int {
	for _, size := range p.sizes {
		if size > p.PathMTU() {
			return size
		}
	}
	return 0
}

func (p *DPLPMTUD) enterSearchComplete(now float64) {
	p.state = DPLPMTUDSearchComplete
	p.hasOutstanding = false
	p.hasRaise = true
	p.nextRaiseAt = now + dplRaiseTimer
}

func (p *DPLPMTUD) failedProbe(now float64) {
	p.probeCount++
	p.hasOutstanding = false
	if p.probeCount < dplMaxProbes {
		return
	}
	switch p.state {
	case DPLPMTUDBase:
		p.state = DPLPMTUDError
		p.probeSize = p.minimum
		p.probeCount = 0
		p.hasRaise = false // immediately try MIN_PLPMTU as the resilient fallback
	case DPLPMTUDSearching:
		p.failedSizes = append(p.failedSizes, p.probeSize)
		p.enterSearchComplete(now)
	case DPLPMTUDError:
		p.state = DPLPMTUDisabled // MIN_PLPMTU could not be validated
		p.probeSize = 0
		p.probeCount = 0
		p.hasRaise = false
	}
}

// Due emits no more than one outstanding probe and spaces successful probes
// by at least one RTT (or the RFC minimum interval when RTT is unknown).
func (p *DPLPMTUD) Due(now, rtt float64, newNonce func() uint64) []MTUProbe {
	if p.state == DPLPMTUDisabled {
		return nil
	}
	if p.hasOutstanding {
		if now-p.probeSentAt < max(dplProbeTimeout, rtt*3) {
			return nil
		}
		p.failedProbe(now)
		if p.hasOutstanding || p.probeCount == 0 && p.state == DPLPMTUDSearchComplete {
			return nil
		}
	}
	if p.hasLastProbe && now-p.lastProbeAt < max(dplMinimumProbeGap, rtt) {
		return nil
	}
	switch p.state {
	case DPLPMTUDBase, DPLPMTUDError:
		if p.state == DPLPMTUDError && p.hasRaise && now < p.nextRaiseAt {
			return nil
		}
		if p.probeSize == 0 {
			p.probeSize = p.base
		}
	case DPLPMTUDSearching:
		p.probeSize = p.nextSearchSize()
		if p.probeSize == 0 {
			p.enterSearchComplete(now)
			return nil
		}
	case DPLPMTUDSearchComplete:
		if !p.hasRaise || now < p.nextRaiseAt {
			return nil
		}
		p.state = DPLPMTUDSearching
		p.probeCount = 0
		p.probeSize = p.nextSearchSize()
		if p.probeSize == 0 {
			p.enterSearchComplete(now)
			return nil
		}
	}
	nonce := newNonce()
	p.probeNonce, p.probeSentAt = nonce, now
	p.hasOutstanding = true
	p.hasLastProbe, p.lastProbeAt = true, now
	p.rounds++
	return []MTUProbe{{Nonce: nonce, Size: p.probeSize}}
}

// Acknowledge accepts only the exact outstanding probe identity and size.
func (p *DPLPMTUD) Acknowledge(nonce uint64, size int, now float64) bool {
	if !p.hasOutstanding || nonce != p.probeNonce || size != p.probeSize || !validTime(now) || now < p.probeSentAt {
		return false
	}
	p.hasOutstanding = false
	p.probeCount = 0
	p.acks++
	p.confirmed = size
	switch p.state {
	case DPLPMTUDBase, DPLPMTUDError:
		p.state = DPLPMTUDSearching
	case DPLPMTUDSearching:
		if size >= p.maximum {
			p.enterSearchComplete(now)
		}
	}
	return true
}

func (p *DPLPMTUD) Stats() MTUStats {
	failed := append([]int(nil), p.failedSizes...)
	slices.Sort(failed)
	return MTUStats{
		PathMTU: p.PathMTU(), Ceiling: p.maximum, Confirmed: p.confirmed,
		Capable: p.confirmed > 0, Rounds: p.rounds, Acks: p.acks,
		FailedSizes: failed, State: p.state, ProbeCount: p.probeCount,
		ProbeSize: p.probeSize,
	}
}
