//go:build !race && !zcdguard

package chain

// The shipped build: the reentrancy machinery from guard_on.go compiles away.
//
// Reentrancy detection needs the goroutine's identity, which in Go means reading
// its stack header — microseconds, which is the right price in a test binary and
// the wrong one in a node. The borrow-lifetime check is a different trade and is
// always on: see stateref.go.
//
// The honest caveat, stated here rather than in a commit message: a guarded
// build is not the shipped build. Its timing differs, so a soak should be run
// both ways — guarded, to catch rule violations, and unguarded, to exercise the
// timing a real node has.
const guardEnabled = false

// ReentrancyGuardEnabled reports whether the *reentrancy* check is compiled in.
//
// The borrow-lifetime check (rule 1) is always on, in every build, including
// this one — it costs an atomic load. Only reentrancy detection is optional,
// because only it needs the goroutine's identity and costs microseconds.
const ReentrancyGuardEnabled = false

func (c *Chain) enterRead() {}

func (c *Chain) exitRead() {}

func (c *Chain) assertNotInRead(string) {}
