package bond

import "time"

// A repair entry carries the payload and is dropped after repairLife. Loss reports
// can arrive much later (a link that was out for 15 s reports its frames when it
// returns), and without the copy counts those reports cannot be told apart from a
// packet that is really gone. A tombstone keeps only the counts, for longer.
const (
	tombstoneMax  = 262144
	tombstoneLife = 60 * time.Second
)

type tombstone struct {
	sent, lost int
	uncached   bool // never cached (UDP or oversize): could not be resent anyway
	at         time.Time
}

type tombstoneRef struct {
	key MissingPacket
	at  time.Time
}

func (s *Sender) putTombstone(key MissingPacket, t *tombstone) {
	if s.tombs == nil {
		s.tombs = make(map[MissingPacket]*tombstone)
	}
	if len(s.tombs) >= tombstoneMax && len(s.tombOrder) > 0 {
		delete(s.tombs, s.tombOrder[0].key)
		s.tombOrder = s.tombOrder[1:]
	}
	s.tombs[key] = t
	s.tombOrder = append(s.tombOrder, tombstoneRef{key, t.at})
}

// noteNotCached records a packet that was never put in the repair cache.
func (s *Sender) noteNotCached(key MissingPacket, now time.Time) {
	s.putTombstone(key, &tombstone{sent: 1, uncached: true, at: now})
}

// retire turns a dropped repair entry into a tombstone.
func (s *Sender) retire(e *repairEntry, now time.Time) {
	s.putTombstone(e.key, &tombstone{sent: e.sent, lost: e.lost, at: now})
}

func (s *Sender) pruneTombstones(now time.Time) {
	for len(s.tombOrder) > 0 && now.Sub(s.tombOrder[0].at) >= tombstoneLife {
		if t := s.tombs[s.tombOrder[0].key]; t != nil && t.at.Equal(s.tombOrder[0].at) {
			delete(s.tombs, s.tombOrder[0].key)
		}
		s.tombOrder = s.tombOrder[1:]
	}
}
