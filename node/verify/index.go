package verify

import "sync/atomic"

// atomicIndex hands out the next work item. It is a named type rather than a
// bare atomic.Int64 so that the one thing worth saying about it has somewhere
// to live: take() may return an index past the end, and callers must check.
// Clamping inside would need a compare-and-swap loop to be correct, which is
// more machinery than "stop when you run out" deserves.
type atomicIndex struct {
	n atomic.Int64
}

func (a *atomicIndex) take() int { return int(a.n.Add(1) - 1) }
