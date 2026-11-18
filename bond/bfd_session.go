package bond

import (
	"math"
	"time"
)

const bfdMinimumDownTX = time.Second

type BFDSessionConfig struct {
	LocalDiscriminator uint32
	DesiredMinTX       time.Duration
	RequiredMinRX      time.Duration
	DetectMultiplier   uint8
}

type BFDReceiveResult struct {
	StateChanged bool
	ReplyFinal   bool
	PollFinished bool
}

// StandardBFDSession implements RFC 5880 asynchronous Control state and timer
// negotiation. It deliberately has no socket or path lookup: the encapsulation
// must demultiplex a packet to this session before calling Receive.
type StandardBFDSession struct {
	localDiscriminator uint32
	remoteDiscriminator uint32
	state               BFDState
	diagnostic          uint8
	detectMultiplier    uint8
	desiredMinTX        time.Duration
	requiredMinRX       time.Duration
	remoteDetectMult    uint8
	remoteDesiredTX     time.Duration
	remoteRequiredRX    time.Duration
	lastReceived        time.Time
	pollPending         bool
	pollOldDesiredTX    time.Duration
	pollOldRequiredRX   time.Duration
}

func NewStandardBFDSession(config BFDSessionConfig) (*StandardBFDSession, error) {
	if config.LocalDiscriminator == 0 || config.DetectMultiplier == 0 || !validBFDInterval(config.DesiredMinTX) || !validBFDReceiveInterval(config.RequiredMinRX) {
		return nil, ErrFrame
	}
	return &StandardBFDSession{
		localDiscriminator: config.LocalDiscriminator,
		state:              BFDDown,
		detectMultiplier:   config.DetectMultiplier,
		desiredMinTX:       config.DesiredMinTX,
		requiredMinRX:      config.RequiredMinRX,
		remoteRequiredRX:   time.Microsecond, // RFC 5880 initializes RemoteMinRxInterval to 1.
	}, nil
}

func validBFDInterval(interval time.Duration) bool {
	return interval > 0 && interval%time.Microsecond == 0 && interval/time.Microsecond <= time.Duration(math.MaxUint32)
}

func validBFDReceiveInterval(interval time.Duration) bool {
	return interval >= 0 && interval%time.Microsecond == 0 && interval/time.Microsecond <= time.Duration(math.MaxUint32)
}

func (s *StandardBFDSession) State() BFDState { return s.state }

func (s *StandardBFDSession) RemoteDiscriminator() uint32 { return s.remoteDiscriminator }

func (s *StandardBFDSession) Diagnostic() uint8 { return s.diagnostic }

func (s *StandardBFDSession) localDesiredTX() time.Duration {
	if s.state != BFDUp && s.desiredMinTX < bfdMinimumDownTX {
		return bfdMinimumDownTX
	}
	return s.desiredMinTX
}

// TransmitInterval is the negotiated periodic Control interval before jitter.
// A zero remote Required Min RX interval means the peer requested no periodic
// packets, as specified by RFC 5880 Section 6.8.7.
func (s *StandardBFDSession) TransmitInterval() time.Duration {
	if s.remoteRequiredRX == 0 {
		return 0
	}
	desiredTX := s.localDesiredTX()
	if s.state == BFDUp && s.pollPending && s.pollOldDesiredTX > desiredTX {
		desiredTX = s.pollOldDesiredTX
	}
	return max(desiredTX, s.remoteRequiredRX)
}

// JitteredTransmitInterval applies the RFC 5880 per-packet 0–25% interval
// reduction. randomUnit must be a uniform sample in [0,1]. Detect Mult=1 uses
// the narrower 75–90% range required to avoid premature detection.
func (s *StandardBFDSession) JitteredTransmitInterval(randomUnit float64) time.Duration {
	interval := s.TransmitInterval()
	if interval == 0 {
		return 0
	}
	if randomUnit < 0 {
		randomUnit = 0
	} else if randomUnit > 1 {
		randomUnit = 1
	}
	minimum := .75
	maximum := 1.0
	if s.detectMultiplier == 1 {
		maximum = .90
	}
	factor := minimum + randomUnit*(maximum-minimum)
	return time.Duration(float64(interval) * factor)
}

// DetectionTime is computed from the last accepted peer packet's parameters:
// Remote Detect Mult multiplied by max(local Required Min RX, remote Desired
// Min TX), for asynchronous mode.
func (s *StandardBFDSession) DetectionTime() time.Duration {
	if s.remoteDetectMult == 0 || s.remoteDesiredTX == 0 {
		return 0
	}
	requiredRX := s.requiredMinRX
	if s.state == BFDUp && s.pollPending && s.pollOldRequiredRX > requiredRX {
		requiredRX = s.pollOldRequiredRX
	}
	return time.Duration(s.remoteDetectMult) * max(requiredRX, s.remoteDesiredTX)
}

// ControlPacket builds the current control state. A final response suppresses
// Poll, matching the RFC requirement that a Poll reply has P clear and F set.
func (s *StandardBFDSession) ControlPacket(final bool) (BFDControlPacket, error) {
	desiredTX := s.localDesiredTX()
	if !validBFDInterval(desiredTX) {
		return BFDControlPacket{}, ErrFrame
	}
	return BFDControlPacket{
		Version:              1,
		Diagnostic:           s.diagnostic,
		State:                s.state,
		Poll:                 s.pollPending && !final,
		Final:                final,
		DetectMultiplier:     s.detectMultiplier,
		MyDiscriminator:      s.localDiscriminator,
		YourDiscriminator:    s.remoteDiscriminator,
		DesiredMinTXInterval:  uint32(desiredTX / time.Microsecond),
		RequiredMinRXInterval: uint32(s.requiredMinRX / time.Microsecond),
	}, nil
}

// UpdateTimers changes local timer parameters. Changes to Desired Min TX or
// Required Min RX start a Poll sequence; Detect Mult changes are advertised
// immediately and do not require Poll.
func (s *StandardBFDSession) UpdateTimers(desiredTX, requiredRX time.Duration, detectMultiplier uint8) error {
	if !validBFDInterval(desiredTX) || !validBFDReceiveInterval(requiredRX) || detectMultiplier == 0 {
		return ErrFrame
	}
	timerChanged := s.desiredMinTX != desiredTX || s.requiredMinRX != requiredRX
	if timerChanged && s.pollPending {
		return ErrFrame // do not overlap ambiguous Poll sequences (RFC 5880 Section 6.5)
	}
	if timerChanged && s.state == BFDUp {
		s.pollOldDesiredTX = s.desiredMinTX
		s.pollOldRequiredRX = s.requiredMinRX
	}
	s.desiredMinTX, s.requiredMinRX = desiredTX, requiredRX
	s.detectMultiplier = detectMultiplier
	if timerChanged {
		s.pollPending = true
	}
	return nil
}

// Receive processes a previously demultiplexed, unauthenticated BFD Control
// packet. Authentication bytes are rejected because this session has no auth
// verifier; a caller must verify them before using an authenticated session.
func (s *StandardBFDSession) Receive(now time.Time, payload []byte) (BFDReceiveResult, error) {
	packet, _, err := DecodeBFDControl(payload)
	if err != nil || len(packet.AuthenticationSection) != 0 {
		return BFDReceiveResult{}, ErrFrame
	}
	if packet.YourDiscriminator != 0 && packet.YourDiscriminator != s.localDiscriminator {
		return BFDReceiveResult{}, ErrFrame
	}
	if packet.YourDiscriminator == 0 && packet.State != BFDDown && packet.State != BFDAdminDown {
		return BFDReceiveResult{}, ErrFrame
	}

	result := BFDReceiveResult{}
	previous := s.state
	previousDesiredTX := s.localDesiredTX()
	s.remoteDiscriminator = packet.MyDiscriminator
	s.remoteDetectMult = packet.DetectMultiplier
	s.remoteDesiredTX = time.Duration(packet.DesiredMinTXInterval) * time.Microsecond
	s.remoteRequiredRX = time.Duration(packet.RequiredMinRXInterval) * time.Microsecond
	s.lastReceived = now

	if packet.State == BFDAdminDown {
		if s.state != BFDDown {
			s.state = BFDDown
			s.diagnostic = 3 // Neighbor signaled session down.
		}
	} else {
		switch s.state {
		case BFDDown:
			if packet.State == BFDDown {
				s.state = BFDInit
			} else if packet.State == BFDInit {
				s.state = BFDUp
			}
		case BFDInit:
			if packet.State == BFDInit || packet.State == BFDUp {
				s.state = BFDUp
			}
		case BFDUp:
			if packet.State == BFDDown {
				s.state = BFDDown
				s.diagnostic = 3 // Neighbor signaled session down.
			}
		}
	}
	if s.state != previous {
		result.StateChanged = true
		if s.state == BFDUp && previousDesiredTX != s.localDesiredTX() {
			// Leaving Down/Init changes Desired Min TX from the mandatory slow
			// rate to the configured rate; communicate that with Poll/Final.
			s.pollOldDesiredTX = previousDesiredTX
			s.pollOldRequiredRX = s.requiredMinRX
			s.pollPending = true
		}
	}
	if packet.Final && s.pollPending {
		s.pollPending = false
		s.pollOldDesiredTX = 0
		s.pollOldRequiredRX = 0
		result.PollFinished = true
	}
	result.ReplyFinal = packet.Poll
	return result, nil
}

// Tick applies asynchronous detection-time expiry. A session cannot time out
// before it has accepted a peer control packet or while it is Down/AdminDown.
func (s *StandardBFDSession) Tick(now time.Time) bool {
	if s.state != BFDInit && s.state != BFDUp || s.lastReceived.IsZero() {
		return false
	}
	if timeout := s.DetectionTime(); timeout > 0 && now.Sub(s.lastReceived) >= timeout {
		s.state = BFDDown
		s.diagnostic = 1 // Control Detection Time Expired.
		s.pollPending = false
		return true
	}
	return false
}
