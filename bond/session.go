package bond

import (
	"net/netip"
	"time"
)

type SessionOptions struct {
	// Version is the build id (git commit) reported to the client.
	Version string
	// State, when set, is polled for a word announced to clients ("updating").
	State   func() string
	MTU      int
	ClientIP netip.Addr
	// DeviceIPs are extra tunnel addresses (consoles behind a client LAN adapter)
	// accepted as sources and destinations besides ClientIP.
	// PriorityHostMax bounds game-priority device UDP (config priority_host_max_packet; 0 = tunnel MTU).
	PriorityHostMax          int
	DeviceIPs                []netip.Addr
	InitialRate, MaximumRate float64
	ReorderTimeout           time.Duration
	Policies                 map[byte]QueuePolicy
	GamePorts                []uint16
	QoS                      QoSSettings
	Redundant                bool
	// Optional behaviours, all off by default like the Python server.
	LossTracking, PathMTUDiscovery, FailoverReplay bool
	FlowPinning, CoDel                             bool
	StripeAbove                                    float64
	ParityRowsMin, ParityRowsMax                   int
	DelayControl, DelayAssertive                   bool
}

func DefaultSessionOptions() SessionOptions {
	return SessionOptions{MTU: 1280, ClientIP: netip.MustParseAddr("10.77.0.2"), InitialRate: 1, MaximumRate: 100, ReorderTimeout: 30 * time.Millisecond, QoS: DefaultQoSSettings()}
}

type SessionStats struct{ Malformed, IPv6Unsupported, MTUDrops, WrongSource, WrongDestination, OutboundPackets, OutboundBytes, InboundPackets, InboundBytes uint64 }
type Session struct {
	Receiver   *Receiver
	Sender     *Sender
	Transmit   *TransmitQueue
	Inject     *InjectionQueue
	classifier *Classifier
	qos        *AdaptiveQoS
	options    SessionOptions
	stats      SessionStats
	peer       [16]byte
	hasPeer    bool
}

func NewSession(key, session []byte, options SessionOptions) (*Session, error) {
	if options.MTU < 576 || options.MTU > 9000 || !options.ClientIP.Is4() {
		return nil, ErrFrame
	}
	codec, err := NewCodec(key, session, "server")
	if err != nil {
		return nil, err
	}
	r, err := NewReceiver(codec, options.MTU+Overhead+24)
	if err != nil {
		return nil, err
	}
	r.SetVersion(options.Version)
	r.SetStateFunc(options.State)
	if err = r.SetReorderTimeout(options.ReorderTimeout); err != nil {
		return nil, err
	}
	if err = r.SetPathMTUDiscovery(options.PathMTUDiscovery); err != nil {
		return nil, err
	}
	sender, err := NewSender(r, options.InitialRate, options.MaximumRate)
	if err != nil {
		return nil, err
	}
	sender.EnableFailover(options.FailoverReplay)
	sender.SetFlowPinning(options.FlowPinning)
	sender.SetStripeAbove(options.StripeAbove)
	sender.SetParityRows(options.ParityRowsMin, options.ParityRowsMax)
	sender.EnableLossTracking(options.LossTracking)
	sender.EnableDelayControl(options.DelayControl)
	sender.SetDelayAssertive(options.DelayAssertive)
	classifier, err := NewClassifier(options.Policies, options.GamePorts, options.QoS)
	if err != nil {
		return nil, err
	}
	classifier.SetPriorityHosts(options.DeviceIPs)
	classifier.SetPriorityHostMax(options.PriorityHostMax)
	qos, err := NewAdaptiveQoS(options.QoS)
	if err != nil {
		return nil, err
	}
	transmit, _ := NewTransmitQueue(sender, 4096, 8*1024*1024)
	transmit.EnableCoDel(options.CoDel)
	transmit.SetQoS(qos)
	inject, _ := NewInjectionQueue(1024, 4*1024*1024)
	return &Session{Receiver: r, Sender: sender, Transmit: transmit, Inject: inject, classifier: classifier, qos: qos, options: options}, nil
}
func (s *Session) syncPeer() {
	if s.Receiver.handshake.hasPeer && (!s.hasPeer || s.peer != s.Receiver.handshake.peer) {
		s.peer = s.Receiver.handshake.peer
		s.hasPeer = true
		s.Transmit.syncPeer()
		s.Inject.Reset()
		s.classifier.Reset()
		s.qos.previous = make(map[qosKey]qualityCounters)
		s.qos.quality = nil
		s.qos.last = time.Time{}
		clear(s.qos.until)
		clear(s.qos.reasons)
	}
}
func (s *Session) classify(packet []byte, incoming bool, now time.Time) (Classification, bool) {
	if len(packet) > s.options.MTU {
		s.stats.MTUDrops++
		return Classification{}, false
	}
	if len(packet) > 0 && packet[0]>>4 == 6 {
		s.stats.IPv6Unsupported++
		return Classification{}, false
	}
	p, err := ParseIPv4(packet)
	if err != nil {
		s.stats.Malformed++
		return Classification{}, false
	}
	if incoming && !s.ownsTunnelIP(p.Source) {
		s.stats.WrongSource++
		return Classification{}, false
	}
	if !incoming && !s.ownsTunnelIP(p.Destination) {
		s.stats.WrongDestination++
		return Classification{}, false
	}
	return s.classifier.Classify(p, now), true
}
func (s *Session) ownsTunnelIP(a [4]byte) bool {
	if a == s.options.ClientIP.As4() {
		return true
	}
	for _, d := range s.options.DeviceIPs {
		if d.As4() == a {
			return true
		}
	}
	return false
}
func queued(packet []byte, c Classification, now time.Time) QueuedPacket {
	return QueuedPacket{Payload: packet, Flow: c.Info.Flow, Priority: c.Policy.Priority, Replicate: c.Policy.Replicate, Expires: now.Add(time.Duration(c.Policy.MaxAgeMS * float64(time.Millisecond))), Tag: c.Tag, ClassCapacity: c.Policy.Capacity}
}
func (s *Session) process(result ReceiveResult, now time.Time, writer DatagramWriter) {
	s.syncPeer()
	s.Sender.Controls(result, now, writer)
	for _, packet := range result.Deliver {
		if c, ok := s.classify(packet, true, now); ok {
			s.stats.InboundPackets++
			s.stats.InboundBytes += uint64(len(packet))
			s.Inject.Enqueue(queued(packet, c, now))
		}
	}
}
func (s *Session) UDP(frame []byte, endpoint netip.AddrPort, now time.Time, writer DatagramWriter) error {
	result, err := s.Receiver.Receive(frame, endpoint, now)
	if err != nil {
		return err
	}
	s.process(result, now, writer)
	return nil
}
func (s *Session) TUN(packet []byte, now time.Time) bool {
	s.syncPeer()
	c, ok := s.classify(packet, false, now)
	if !ok {
		return false
	}
	s.stats.OutboundPackets++
	s.stats.OutboundBytes += uint64(len(packet))
	p := queued(packet, c, now)
	if s.options.Redundant {
		p.Replicate = true
	}
	return s.Transmit.Enqueue(p)
}
func (s *Session) Pump(now time.Time, writer DatagramWriter, inject func([]byte) error) (time.Time, error) {
	result, err := s.Receiver.Tick(now)
	if err != nil {
		return now, err
	}
	s.process(result, now, writer)
	if err = s.Sender.Maintenance(now, writer); err != nil {
		return now, err
	}
	due, err := s.Transmit.Pump(now, writer)
	if err != nil {
		return due, err
	}
	if err = s.Inject.Drain(now, inject); err != nil {
		return due, err
	}
	return due, nil
}
func (s *Session) Stats(now time.Time) map[string]any {
	return map[string]any{"backend": "native_go", "packets": s.stats, "transport": map[string]any{"receive": s.Receiver.Stats(), "send": s.Sender.Stats(), "paths": s.Sender.Paths(now), "reorder": s.Receiver.ReorderStats()}, "queues": map[string]any{"transmit": s.Transmit.Stats(), "inject": s.Inject.Stats()}, "qos": s.qos.Stats(now), "profile_cache_entries": len(s.classifier.flows), "fragment_cache_entries": len(s.classifier.fragments)}
}
