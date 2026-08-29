package mempool

import (
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
)

// Test hooks. This file is `package mempool` and compiles only under `go test`,
// so the suite can reach an unexported rule without the rule being exported to
// the node.
//
// BeatsByBump exists because the eviction tests live in `package mempool_test`
// (they drive the pool through its real API) and previously carried a *copy* of
// the bump rule to recompute what a rejected floor would have decided. A copy
// silently desynchronises from the rule it mirrors, which is the one thing the
// anti-vacuity assertions must not do.
var BeatsByBump = beatsByBump

// EvictionCandidateCount is how many residents an eviction pass for this
// arrival would sort. It is the structural quantity behind the cost of a pass:
// the filters live in evictionOrder rather than in the removal loop precisely
// so that this number tracks what the arrival can take, not how big the pool
// is. See TestAnEvictionPassSortsOnlyWhatTheArrivalCanTake.
func (pool *Pool) EvictionCandidateCount(arrival *types.Certificate) int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	candidates, _, ok := pool.evictionCandidates(pool.chainPrices(), arrival)
	if !ok {
		return 0
	}
	return len(evictionOrder(candidates, arrival, pool.policy.EvictionBumpPercent))
}

// FloorLowerBound is the cheap bound as makeRoomFor sees it. Exported for the
// tests in `package mempool_test` that drive the pool through Add, because the
// bookkeeping the bound reads is fed exclusively from Add's call site and no
// internal test can reach that site with a real certificate. See
// TestFloorHintBuiltThroughAddIsTheMinimumOverEvictableTails.
//
// Takes the write lock: floorLowerBound cleans the heap and may rebuild it.
func (pool *Pool) FloorLowerBound() (u256.U256, bool) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.floorLowerBound()
}

// FloorLowerBoundFor is the arrival-aware bound makeRoomFor actually reads
// for one arrival. FloorLowerBound above is the pool-wide half of it, kept
// exported because the unevictable-chain-base tests are about that half on its own.
//
// Takes the write lock for the same reason FloorLowerBound does.
func (pool *Pool) FloorLowerBoundFor(arrival *types.Certificate) (u256.U256, bool) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.floorLowerBoundFor(arrival)
}

// ExactEvictionFloor is the authority the bound above must never exceed: the
// minimum declared SeqPriority over the residents this arrival could take.
func (pool *Pool) ExactEvictionFloor(arrival *types.Certificate) (u256.U256, bool) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	_, floor, ok := pool.evictionCandidates(pool.chainPrices(), arrival)
	return floor, ok
}

// CountSignatureChecks runs fn with the pool's V2 call counted, and returns how
// many times admission verified signatures. "the gossip path verified every
// certificate twice" and "it verified before every free refusal" are both
// claims about this number, so the suite asserts on the number rather than on a
// duration or on a reading of the source.
//
// Restores the real verifier on return. The swap is a package variable, so it
// is only safe while no test in this package runs in parallel — which is not a
// convention here but an enforced one: TestNoTestInThisPackageRunsInParallel
// parses the package's own sources and fails on any t.Parallel(). A concurrent
// test that wants a count has to take the counter itself.
func CountSignatureChecks(fn func()) int {
	n := 0
	real := checkSignatures
	checkSignatures = func(c *types.Certificate, p *params.Params) error {
		n++
		return real(c, p)
	}
	defer func() { checkSignatures = real }()
	fn()
	return n
}

// WhileVerifying runs during() from inside the pool's V2 call, on the same
// goroutine as Add, and returns how many verifications fn() paid for.
//
// It is how TestVerificationDoesNotHoldThePoolLock observes what Add is holding
// at the moment it verifies. Same package-var swap as CountSignatureChecks, and
// the same non-parallel requirement — see TestNoTestInThisPackageRunsInParallel.
func WhileVerifying(during func(), fn func()) int {
	n := 0
	real := checkSignatures
	checkSignatures = func(c *types.Certificate, p *params.Params) error {
		n++
		during()
		return real(c, p)
	}
	defer func() { checkSignatures = real }()
	fn()
	return n
}

// WhileWriteLocked runs during() with the pool's write lock held. It is the
// control for the test above: it proves the probe can actually detect a held
// lock, so observing "not held" during V2 is an observation and not a blind
// spot.
func (pool *Pool) WhileWriteLocked(during func()) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	during()
}
