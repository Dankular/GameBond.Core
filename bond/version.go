package bond

import (
	"strings"
	"time"
)

// SetVersion sets the build id (git commit) this side reports to its peer.
func (r *Receiver) SetVersion(v string) {
	if len(v) > 64 {
		v = v[:64]
	}
	r.version = v
}

// Versions returns this side's build id and the peer's, which is empty until the peer has
// answered (a peer built before the VersionReq/VersionInfo frames never does).
func (r *Receiver) Versions() (local, peer string) { return r.version, r.peerVersion }

// SetStateFunc (server) supplies a state word to announce to clients, such as "updating". A
// change is pushed to every ready path at once, and is also attached to each VersionInfo reply.
func (r *Receiver) SetStateFunc(f func() string) { r.stateFn = f }

// PeerState is the state the server last announced (client side); empty means nothing special.
func (r *Receiver) PeerState() string { return r.peerState }

// versionRequest adds an optional capability marker to the pre-existing
// VersionReq string, so old peers simply ignore the extension instead of
// encountering a new frame kind.
func (r *Receiver) versionRequest(p *receivePath) []byte {
	version := r.version
	if p != nil && p.ecnLocal {
		const suffix = "|ecn=1"
		if len(version)+len(suffix) > 64 {
			version = version[:64-len(suffix)]
		}
		return []byte(version + suffix)
	}
	return []byte(version)
}

func parseVersionRequest(payload []byte) (string, bool) {
	version, extension, found := strings.Cut(string(payload), "|")
	return version, found && extension == "ecn=1"
}

func (r *Receiver) versionInfo(p *receivePath) []byte {
	state := ""
	if r.stateFn != nil {
		state = r.stateFn()
	}
	if p != nil && p.ecnLocal && p.ecnPeer {
		version := r.version
		const suffixLength = len("||ecn=1")
		if len(version)+suffixLength > 64 {
			version = version[:64-suffixLength]
		}
		stateLimit := max(0, 64-len(version)-suffixLength)
		if len(state) > stateLimit {
			state = state[:stateLimit]
		}
		return []byte(version + "|" + state + "|ecn=1")
	}
	info := strings.Join([]string{r.version, state}, "|")
	if len(info) > 64 {
		info = info[:64]
	}
	return []byte(info)
}

func parseVersionInfo(payload []byte) (version, state string, ecn bool) {
	parts := strings.SplitN(string(payload), "|", 3)
	if len(parts) > 0 {
		version = parts[0]
	}
	if len(parts) > 1 {
		state = parts[1]
	}
	if len(parts) > 2 {
		ecn = parts[2] == "ecn=1"
	}
	return
}

func (r *Receiver) announceState(now time.Time, out *ReceiveResult) error {
	if r.role != "server" || r.stateFn == nil {
		return nil
	}
	st := r.stateFn()
	if st == r.lastState {
		return nil
	}
	r.lastState = st
	for _, p := range r.paths {
		if p.ready && now.Sub(p.last) < 3*time.Second {
			if p.ecnLocal && p.ecnPeer {
				r.stats.ECNCapabilitySent++
			}
			if err := r.write(VersionInfo, r.versionInfo(p), p.local, p.endpoint, out); err != nil {
				return err
			}
		}
	}
	return nil
}
