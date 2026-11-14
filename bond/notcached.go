package bond

// notCachedMax bounds the memory of packets that were never put in the repair
// cache, kept only so a later loss report can say why it cannot be resent.
const notCachedMax = 8192

func (s *Sender) noteNotCached(key MissingPacket) {
	if s.notCached == nil {
		s.notCached = make(map[MissingPacket]struct{}, notCachedMax)
	}
	if len(s.notCachedOrder) >= notCachedMax {
		delete(s.notCached, s.notCachedOrder[0])
		s.notCachedOrder = s.notCachedOrder[1:]
	}
	s.notCached[key] = struct{}{}
	s.notCachedOrder = append(s.notCachedOrder, key)
}

func (s *Sender) wasNotCached(key MissingPacket) bool {
	_, ok := s.notCached[key]
	return ok
}
