package bond

import "time"

// Bidirectional forwarding detection. Every ready path exchanges a small BFD frame
// each bfdInterval. A path is Up only while this end hears the peer within
// bfdMultiplier intervals AND the peer reports hearing us, so a one-way failure is
// detected by both ends in about 300 ms instead of waiting for the probe timeout.
// After any failure the path must stay healthy for its hold-down (see bfdHold) before it carries bulk
// again, which damps flapping. Peers that never send BFD keep the older silence timer.

const (
	bfdInterval   = 100 * time.Millisecond
	bfdMultiplier = 5
	// Hold-down after a failure: short the first time, doubling for each further failure
	// within bfdFlapWindow, so a flapping line is kept out longer but one blip is not. Every
	// packet is also copied onto the other line, so letting a recovering line back early
	// costs only copies, never delivery.
	bfdHoldMin    = 250 * time.Millisecond
	bfdHoldMax    = 4 * time.Second
	bfdFlapWindow = 30 * time.Second
	bfdPayload    = 8
)

type bfdState struct {
	seen      bool // the peer has sent BFD at least once
	rx        time.Time
	peerHears bool
	up        bool
	failed    bool // has been down since the session began: hold-down applies
	goodSince time.Time
	lastTx    time.Time
	// flap accounting, reported in the status
	downs, ups uint64
	flaps      int // failures within bfdFlapWindow of each other
	lastDown   time.Time
	cause      string // why the last failure was declared
}

// hold is how long the path must stay healthy before it is trusted again.
func (b *bfdState) hold() time.Duration {
	h := bfdHoldMin
	for i := 1; i < b.flaps && h < bfdHoldMax; i++ {
		h *= 2
	}
	if h > bfdHoldMax {
		h = bfdHoldMax
	}
	return h
}

func (b *bfdState) hears(now time.Time) bool {
	return b.seen && now.Sub(b.rx) < bfdMultiplier*bfdInterval
}

// bfdHears reports whether this end has heard the peer within the detect time. Any authenticated
// frame from the peer on the path counts, not only a BFD frame: a loaded or lossy line can eat five
// BFD frames in a row (or hold them in a queue behind bulk) while data, probes and feedback keep
// arriving, and declaring that line down throws away a working path. A line that really stopped
// delivers nothing at all, so it is still detected within the same time.
func (p *receivePath) bfdHears(now time.Time) bool {
	if !p.bfd.seen {
		return false
	}
	latest := p.bfd.rx
	if p.last.After(latest) {
		latest = p.last
	}
	return now.Sub(latest) < bfdMultiplier*bfdInterval
}

// bfdReceived records a BFD frame from the peer.
func (r *Receiver) bfdReceived(p *receivePath, payload []byte, now time.Time) {
	p.bfd.seen, p.bfd.rx = true, now
	p.bfd.peerHears = payload[0]&1 != 0
	r.stats.BFDReceived++
	r.bfdEvaluate(p, now)
}

// bfdEvaluate updates the path's Up/Down state from both directions.
func (r *Receiver) bfdEvaluate(p *receivePath, now time.Time) {
	b := &p.bfd
	if !b.seen {
		return
	}
	both := p.bfdHears(now) && b.peerHears
	wentDown, cameUp := false, false
	switch {
	case !both:
		if b.up {
			wentDown = true
			r.stats.BFDDown++
			b.failed = true
			b.downs++
			if now.Sub(b.lastDown) > bfdFlapWindow {
				b.flaps = 0
			}
			b.flaps++
			b.lastDown = now
			b.cause = "peer_not_hearing_us"
			if !p.bfdHears(now) {
				b.cause = "silence"
			}
		}
		b.up, b.goodSince = false, time.Time{}
	case b.up:
	default:
		if b.goodSince.IsZero() {
			b.goodSince = now
		}
		if !b.failed || now.Sub(b.goodSince) >= b.hold() {
			b.up = true
			b.ups++
			r.stats.BFDUp++
			cameUp = true
		}
	}
	if wentDown {
		r.noteLine(p, now, OutageLinkDown, b.cause, 0)
	} else if cameUp && !b.lastDown.IsZero() { // a recovery, not the first exchange
		r.noteLine(p, now, OutageLinkUp, "", now.Sub(b.lastDown))
	}
}

// bfdSend sends the path's BFD frame when one is due.
func (r *Receiver) bfdSend(p *receivePath, now time.Time, out *ReceiveResult) error {
	if now.Sub(p.bfd.lastTx) < bfdInterval {
		return nil
	}
	p.bfd.lastTx = now
	r.bfdEvaluate(p, now)
	var body [bfdPayload]byte
	if p.bfdHears(now) {
		body[0] = 1
	}
	body[1] = bfdMultiplier
	body[2] = byte(bfdInterval / time.Millisecond)
	r.stats.BFDSent++
	return r.write(BFD, body[:], p.local, p.endpoint, out)
}

// bfdDown reports a BFD-managed path that is not Up.
// A session still negotiating (never been up) is not a failure.
func (p *receivePath) bfdDown() bool { return p.bfd.seen && !p.bfd.up && p.bfd.failed }

// bfdStatus is the per-path BFD view for the status document.
func (p *receivePath) bfdStatus(now time.Time) map[string]any {
	b := &p.bfd
	state := "off"
	switch {
	case !b.seen:
	case b.up:
		state = "up"
	case b.failed:
		state = "down"
	default:
		state = "negotiating"
	}
	out := map[string]any{"state": state, "downs": b.downs, "ups": b.ups, "peer_hears_us": b.peerHears,
		"detect_ms": bfdMultiplier * int(bfdInterval/time.Millisecond)}
	if b.seen {
		out["rx_age_ms"] = float64(now.Sub(b.rx)) / float64(time.Millisecond)
	}
	if !b.lastDown.IsZero() {
		out["last_down_s_ago"] = now.Sub(b.lastDown).Seconds()
		out["last_cause"] = b.cause
	}
	return out
}
