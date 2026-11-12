package bond

import "time"

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

func (r *Receiver) versionInfo() []byte {
	if r.stateFn != nil {
		if st := r.stateFn(); st != "" {
			return []byte(r.version + "|" + st)
		}
	}
	return []byte(r.version)
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
			if err := r.write(VersionInfo, r.versionInfo(), p.local, p.endpoint, out); err != nil {
				return err
			}
		}
	}
	return nil
}
