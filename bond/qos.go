package bond

import (
	"container/list"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

type QoSSettings struct {
	Enabled           bool    `json:"enabled"`
	LossThreshold     float64 `json:"loss_threshold"`
	JitterThresholdMS float64 `json:"jitter_threshold_ms"`
	RecoverySeconds   float64 `json:"recovery_seconds"`
	CallDeadlineMS    float64 `json:"call_deadline_ms"`
	StreamDeadlineMS  float64 `json:"stream_deadline_ms"`
	GameDeadlineMS    float64 `json:"game_deadline_ms"`
	DuplicateMbps     float64 `json:"duplicate_mbps"`
}

func DefaultQoSSettings() QoSSettings { return QoSSettings{true, .02, 8, 3, 60, 120, 20, 4} }
func (q QoSSettings) Validate() error {
	for _, v := range []float64{q.LossThreshold, q.JitterThresholdMS, q.RecoverySeconds, q.CallDeadlineMS, q.StreamDeadlineMS, q.GameDeadlineMS, q.DuplicateMbps} {
		if !finite(v) || v <= 0 {
			return ErrFrame
		}
	}
	if q.LossThreshold > 1 || q.RecoverySeconds > 60 || q.DuplicateMbps > 1000 {
		return ErrFrame
	}
	for _, v := range []float64{q.CallDeadlineMS, q.StreamDeadlineMS, q.GameDeadlineMS} {
		if v < 1 || v > 2000 {
			return ErrFrame
		}
	}
	return nil
}

type QueuePolicy struct {
	Priority        bool    `json:"priority"`
	Replicate       bool    `json:"replicate"`
	MaxAgeMS        float64 `json:"max_age_ms"`
	Capacity        int     `json:"capacity"`
	Retransmissions int     `json:"retransmissions"`
}

func DefaultQueuePolicy() QueuePolicy { return QueuePolicy{false, false, 100, 256, 0} }
func (p QueuePolicy) Validate() error {
	if !finite(p.MaxAgeMS) || p.MaxAgeMS <= 0 || p.Capacity < 1 || p.Capacity > 65536 || p.Retransmissions != 0 {
		return ErrFrame
	}
	return nil
}

type Classification struct {
	Info   IPv4Info
	Tag    byte
	Policy QueuePolicy
	Reason string
}
type learnedPolicy struct {
	key     string
	tag     byte
	expires time.Time
	order   *list.Element
}
type Classifier struct {
	policies                 map[byte]QueuePolicy
	ports                    map[uint16]bool
	qos                      QoSSettings
	flows, fragments         map[string]*learnedPolicy
	priorityHosts            map[[4]byte]bool
	hostMax                  int // largest device UDP packet that is game-priority
	flowOrder, fragmentOrder list.List
}

// SetPriorityHosts makes the UDP traffic of the given hosts (a console behind a
// LAN adapter) game-priority: such a device uses many unpredictable game and
// voice ports, so port lists cannot identify it. DNS and QUIC/HTTPS UDP stay
// ordinary. The classifier is used from one goroutine; call before traffic.
// SetPriorityHostMax overrides PriorityHostMaxPacket (0 keeps the default).
func (c *Classifier) SetPriorityHostMax(n int) { c.hostMax = n }

func (c *Classifier) hostLimit() int {
	if c.hostMax > 0 {
		return c.hostMax
	}
	return PriorityHostMaxPacket
}

func (c *Classifier) SetPriorityHosts(hosts []netip.Addr) {
	c.priorityHosts = make(map[[4]byte]bool, len(hosts))
	for _, h := range hosts {
		if h.Is4() {
			c.priorityHosts[h.As4()] = true
		}
	}
}

// PriorityHostMaxPacket bounds the device packets treated as latency-critical
// game traffic. Hit, damage and kill-cam events are larger than position
// updates, so the bound is the tunnel MTU: every UDP packet of the device
// (except DNS and QUIC/HTTPS) is game-priority.
const PriorityHostMaxPacket = 1280

func (c *Classifier) hostUDP(info IPv4Info) bool {
	if len(c.priorityHosts) == 0 || info.Protocol != 17 || !info.HasPorts {
		return false
	}
	for _, p := range [2]uint16{info.SourcePort, info.DestinationPort} {
		if p == 53 || p == 443 {
			return false
		}
	}
	return c.priorityHosts[info.Source] || c.priorityHosts[info.Destination]
}

func (c *Classifier) priorityHost(info IPv4Info) bool {
	return info.Length <= c.hostLimit() && c.hostUDP(info)
}

func NewClassifier(policies map[byte]QueuePolicy, ports []uint16, settings QoSSettings) (*Classifier, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	c := &Classifier{policies: make(map[byte]QueuePolicy), ports: make(map[uint16]bool), qos: settings, flows: make(map[string]*learnedPolicy), fragments: make(map[string]*learnedPolicy)}
	for tag, p := range policies {
		if tag > 63 || p.Validate() != nil {
			return nil, ErrFrame
		}
		c.policies[tag] = p
	}
	for _, port := range ports {
		if port == 0 {
			return nil, ErrFrame
		}
		c.ports[port] = true
	}
	if settings.Enabled {
		for tag, p := range map[byte]QueuePolicy{18: {true, false, settings.StreamDeadlineMS, 256, 0}, 26: {true, false, settings.CallDeadlineMS, 128, 0}, 46: {true, true, settings.GameDeadlineMS, 128, 0}} {
			if _, ok := c.policies[tag]; !ok {
				c.policies[tag] = p
			}
		}
	}
	return c, nil
}
func (c *Classifier) Reset() {
	clear(c.flows)
	clear(c.fragments)
	c.flowOrder.Init()
	c.fragmentOrder.Init()
}
func (c *Classifier) policy(tag byte) QueuePolicy {
	if p, ok := c.policies[tag]; ok {
		return p
	}
	return DefaultQueuePolicy()
}
func expireLearned(cache map[string]*learnedPolicy, order *list.List, now time.Time) {
	for order.Len() > 0 {
		entry := order.Front().Value.(*learnedPolicy)
		if now.Before(entry.expires) {
			break
		}
		delete(cache, entry.key)
		order.Remove(entry.order)
	}
}
func learn(cache map[string]*learnedPolicy, order *list.List, key string, tag byte, expires time.Time, limit int) {
	entry := cache[key]
	if entry == nil {
		entry = &learnedPolicy{key: key}
		entry.order = order.PushBack(entry)
		cache[key] = entry
	} else {
		order.MoveToBack(entry.order)
	}
	entry.tag = tag
	entry.expires = expires
	if len(cache) > limit {
		old := order.Front().Value.(*learnedPolicy)
		delete(cache, old.key)
		order.Remove(old.order)
	}
}
func (c *Classifier) policyFor(tag byte) QueuePolicy {
	policy := c.policy(tag)
	if c.qos.Enabled {
		switch tag {
		case 18:
			policy = QueuePolicy{true, false, c.qos.StreamDeadlineMS, 256, 0}
		case 26:
			policy = QueuePolicy{true, false, c.qos.CallDeadlineMS, 128, 0}
		case 46:
			policy = QueuePolicy{true, true, c.qos.GameDeadlineMS, 128, 0}
		}
	}
	return policy
}
func (c *Classifier) Classify(info IPv4Info, now time.Time) Classification {
	tag, reason := info.DSCP, "dscp"
	if info.FragmentKey != "" && info.FragmentOffset == 0 {
		reason = "fragment_first"
	}
	if info.Protocol == 17 && info.HasPorts && (c.ports[info.SourcePort] || c.ports[info.DestinationPort]) || c.priorityHost(info) {
		tag = 46
		reason = "game_port"
	}
	if info.PolicyFlow != "" {
		expireLearned(c.flows, &c.flowOrder, now)
		if cached := c.flows[info.PolicyFlow]; cached != nil {
			_, configured := c.policies[tag]
			if tag == 0 || (!configured && c.policy(cached.tag).Priority) {
				tag = cached.tag
				if reason != "game_port" {
					reason = "flow_cache"
				}
			}
		}
		learn(c.flows, &c.flowOrder, info.PolicyFlow, tag, now.Add(120*time.Second), 4096)
	}
	if info.FragmentKey != "" {
		expireLearned(c.fragments, &c.fragmentOrder, now)
		if info.FragmentOffset == 0 {
			learn(c.fragments, &c.fragmentOrder, info.FragmentKey, tag, now.Add(2*time.Second), 1024)
		} else if cached := c.fragments[info.FragmentKey]; cached != nil {
			_, configured := c.policies[tag]
			if tag == 0 || (!configured && c.policy(cached.tag).Priority) {
				tag = cached.tag
				reason = "fragment_cache"
			}
		} else if tag == 0 {
			reason = "fragment_orphan" // never guess the policy of an unassociated fragment
		}
	}
	if tag == 46 && reason != "game_port" && info.Length > c.hostLimit() && c.hostUDP(info) {
		tag, reason = 0, "device_bulk_udp" // even when the flow cache would promote it
	}
	policy := c.policyFor(tag)
	return Classification{info, tag, policy, reason}
}

type PathQuality struct {
	Endpoint                                                     string
	Loss, FeedbackTimeoutRatio, ProbeLoss, JitterMS, PredictedMS float64
	CopyLoss                                                     float64
	CopySamples                                                  uint64
}

// QoSPath is one path's counters and timings, the Go form of an entry in the
// Python transport snapshot AdaptiveQoS.observe consumes.
type QoSPath struct {
	Slot                                  int
	Local, Remote                         string
	Available, Enabled, Healthy           bool
	RTTMS                                 *float64
	JitterMS, QueueDelayMS, SettledLoss   float64
	Expired, Acked, ProbeLost, ProbeAcked uint64
	DeliveredBytes                        uint64
	CopySeen, CopyMissed                  uint64
}

// MinCopySamples is the fewest replica comparisons treated as a rate.
const MinCopySamples = 8

type qosKey struct {
	slot          int
	local, remote string
}
type qualityCounters struct{ expired, acked, probeLost, probeAcked, delivered, copySeen, copyMissed uint64 }
type AdaptiveQoS struct {
	settings                                   QoSSettings
	previous                                   map[qosKey]qualityCounters
	last                                       time.Time
	quality                                    []PathQuality
	until                                      map[byte]time.Time
	reasons                                    map[byte][]string
	tokens                                     float64
	tokenAt                                    time.Time
	samples, single, replicated, budgetLimited uint64
}

func NewAdaptiveQoS(settings QoSSettings) (*AdaptiveQoS, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &AdaptiveQoS{settings: settings, previous: make(map[qosKey]qualityCounters), until: make(map[byte]time.Time), reasons: make(map[byte][]string), tokens: 2800}, nil
}
func delta(now, before uint64) float64 {
	if now < before {
		return 0
	}
	return float64(now - before)
}

// Observe samples the sender's paths at most every 500 ms.
func (q *AdaptiveQoS) Observe(sender *Sender, now time.Time) {
	if !q.last.IsZero() && now.Sub(q.last) < 500*time.Millisecond {
		return
	}
	q.last = now
	eligible := make(map[*receivePath]bool)
	for _, p := range sender.eligible(now, true) {
		eligible[p] = true
	}
	var paths []QoSPath
	for k, p := range sender.r.paths {
		b := p.budget
		qp := QoSPath{Slot: k.Local, Local: strconv.Itoa(k.Local), Remote: p.endpoint.String(), Available: true, Enabled: true, Healthy: eligible[p],
			JitterMS: p.jitter * 1000, Expired: b.expiredPackets, Acked: b.ackedPackets, ProbeLost: p.probeLost, ProbeAcked: p.probeAcked,
			DeliveredBytes: b.deliveryCounter, SettledLoss: b.lossRatio, CopySeen: p.peerCopy[0], CopyMissed: p.peerCopy[1]}
		if p.hasRTT {
			rtt := p.rtt * 1000
			qp.RTTMS = &rtt
		}
		if b.hasMin {
			qp.QueueDelayMS = math.Max(0, b.srtt-b.minRTT) * 1000
		}
		paths = append(paths, qp)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Slot != paths[j].Slot {
			return paths[i].Slot < paths[j].Slot
		}
		return paths[i].Remote < paths[j].Remote
	})
	q.ObservePaths(paths, now)
	if hinted := sender.HintedPaths(now); len(hinted) > 0 && len(q.quality) > 1 {
		for _, tag := range []byte{18, 26} {
			q.until[tag] = now.Add(time.Duration(q.settings.RecoverySeconds * float64(time.Second)))
			q.reasons[tag] = append(q.reasons[tag], "path_hint")
		}
	}
}

// ObservePaths is AdaptiveQoS.observe: one quality sample from a snapshot.
func (q *AdaptiveQoS) ObservePaths(paths []QoSPath, now time.Time) {
	q.samples++
	q.quality = nil
	previous := make(map[qosKey]qualityCounters)
	if len(paths) > 64 {
		paths = paths[:64]
	}
	for _, p := range paths {
		key := qosKey{p.Slot, p.Local, p.Remote}
		totals := qualityCounters{p.Expired, p.Acked, p.ProbeLost, p.ProbeAcked, p.DeliveredBytes, p.CopySeen, p.CopyMissed}
		old, ok := q.previous[key]
		if !ok {
			old = totals
		}
		previous[key] = totals
		expired, acked := delta(totals.expired, old.expired), delta(totals.acked, old.acked)
		lost, probeAcked := delta(totals.probeLost, old.probeLost), delta(totals.probeAcked, old.probeAcked)
		txLoss := 0.
		if totals.delivered > old.delivered {
			txLoss = math.Max(0, math.Min(1, p.SettledLoss))
		}
		probeLoss := lost / math.Max(1, lost+probeAcked)
		seen, missed := delta(totals.copySeen, old.copySeen), delta(totals.copyMissed, old.copyMissed)
		copyLoss := 0.
		if seen+missed >= MinCopySamples {
			copyLoss = missed / (seen + missed)
		}
		if !(p.Available && p.Enabled && p.Healthy) {
			continue
		}
		predicted := 1000.
		if p.RTTMS != nil {
			predicted = *p.RTTMS / 2
		}
		predicted += 2*p.JitterMS + math.Max(0, p.QueueDelayMS)
		q.quality = append(q.quality, PathQuality{Endpoint: p.Remote, Loss: math.Max(txLoss, math.Max(probeLoss, copyLoss)), FeedbackTimeoutRatio: expired / math.Max(1, expired+acked),
			ProbeLoss: probeLoss, JitterMS: p.JitterMS, PredictedMS: predicted, CopyLoss: copyLoss, CopySamples: uint64(seen + missed)})
	}
	q.previous = previous
	for tag, deadline := range map[byte]float64{26: q.settings.CallDeadlineMS, 18: q.settings.StreamDeadlineMS} {
		var reasons []string
		if len(q.quality) > 1 {
			best := q.quality[0]
			for _, p := range q.quality[1:] {
				if p.PredictedMS < best.PredictedMS {
					best = p
				}
			}
			if best.Loss >= q.settings.LossThreshold {
				reasons = append(reasons, "measured_loss")
			}
			if best.CopyLoss >= q.settings.LossThreshold {
				reasons = append(reasons, "copy_loss")
			}
			if best.FeedbackTimeoutRatio >= q.settings.LossThreshold {
				reasons = append(reasons, "feedback_timeout")
			}
			if best.JitterMS >= q.settings.JitterThresholdMS {
				reasons = append(reasons, "jitter")
			}
			if best.PredictedMS >= deadline*.75 {
				reasons = append(reasons, "deadline_risk")
			}
		}
		if len(reasons) > 0 {
			q.until[tag] = now.Add(time.Duration(q.settings.RecoverySeconds * float64(time.Second)))
		} else if now.Before(q.until[tag]) {
			reasons = []string{"recovery_hold"}
		}
		q.reasons[tag] = reasons
	}
}
func (q *AdaptiveQoS) Replicate(tag byte, size int, base bool, now time.Time) bool {
	if !q.settings.Enabled {
		return base
	}
	replicate := base
	if tag == 18 || tag == 26 {
		replicate = len(q.quality) > 1 && now.Before(q.until[tag])
		if replicate {
			if q.tokenAt.IsZero() {
				q.tokenAt = now
			}
			q.tokens = math.Min(2800, q.tokens+math.Max(0, now.Sub(q.tokenAt).Seconds())*q.settings.DuplicateMbps*125000)
			q.tokenAt = now
			extra := float64((size + 128) * (len(q.quality) - 1))
			if q.tokens >= extra {
				q.tokens -= extra
			} else {
				replicate = false
				q.budgetLimited++
			}
		}
	}
	if replicate {
		q.replicated++
	} else {
		q.single++
	}
	return replicate
}
func (q *AdaptiveQoS) Stats(now time.Time) map[string]any {
	redundancy := make(map[byte]any)
	for _, tag := range []byte{18, 26} {
		redundancy[tag] = map[string]any{"active": len(q.quality) > 1 && now.Before(q.until[tag]), "reasons": q.reasons[tag], "hold_remaining_ms": math.Max(0, q.until[tag].Sub(now).Seconds()*1000)}
	}
	return map[string]any{"enabled": q.settings.Enabled, "quality_samples": q.samples, "healthy_paths": len(q.quality), "path_quality": q.quality, "redundancy": redundancy, "single": q.single, "replicated": q.replicated, "duplicate_budget_limited": q.budgetLimited}
}
