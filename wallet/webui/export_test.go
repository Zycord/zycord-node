package webui

import "time"

// ExpireHandoff moves the handoff's deadline into the past.
//
// The deadline is the one of the handoff's four refusal reasons a test cannot
// otherwise reach: the other three — wrong, already spent, wrong server — are
// one call away, and this one is a five-minute wait. An untested refusal is a
// refusal nobody has seen happen.
func (s *Server) ExpireHandoff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handoffTill = time.Now().Add(-time.Second)
}
