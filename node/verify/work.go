package verify

import (
	"sync"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
)

// WorkWasChecked memoizes proof-of-work verdicts by block id.
//
// It belongs to this package for the reason the package doc gives: the
// predicate is consensus and lives in core/pow, and how often a node bothers to
// evaluate it is not consensus at all. Nothing here can change which headers
// are valid; it can only change how many times this node computes the same
// answer.
//
// # Why it is sound, and what it depends on
//
// A header's work verdict is a pure function of its own bytes. The digest is
// taken over the header with the nonce zeroed plus the nonce, the target is a
// header field, and — this is the load-bearing part — THE KEY COMES FROM THE
// HEIGHT (pow.KeyFor). So the block id, which commits to every header field,
// determines the verdict completely.
//
// Under upstream RandomX's own schedule, where the key is a key block's hash,
// this cache would be UNSOUND: the same header on two branches would key from
// two different blocks and could have two different verdicts, and a cache
// indexed by id would serve one branch's answer to the other. The cache is a
// direct dividend of that decision, and it stops being one if the decision is
// ever revisited (ARCHITECTURE §21).
//
// # What it is worth
//
// A block relayed hash-first is verified twice today: once as an announcement
// header, once when its body arrives. Against the BLAKE3 stand-in that was
// free. Against RandomX a verification measures about 55 ms on the machine
// core/pow/randomx records, so the duplicate is 55 ms per relayed block, per
// node, forever. Citations repeat across blocks and are the same story.
//
// It is NOT a defence against a flood of DISTINCT invalid headers, and must not
// be read as one: every unique header still costs a full evaluation, and what
// bounds that is per-peer scoring and rate limits.
type WorkWasChecked struct {
	mu   sync.Mutex
	seen map[types.Hash]error
	fifo []types.Hash
	cap  int
}

// NewWorkCache returns a cache holding at most capacity verdicts.
//
// Verdicts are evicted first-in-first-out rather than by recency. FIFO is the
// right shape here and LRU is not: the access pattern is a chain moving
// forward, so the entries worth keeping are the recent ones by arrival, and an
// LRU would let a peer that keeps re-presenting one old header pin it.
func NewWorkCache(capacity int) *WorkWasChecked {
	if capacity < 1 {
		capacity = 1
	}
	return &WorkWasChecked{seen: make(map[types.Hash]error, capacity), cap: capacity}
}

// Check answers pow.CheckWork, evaluating the work function only for a header
// this cache has not already judged.
//
// Failures are cached alongside successes. That is deliberate: a peer
// re-presenting the same invalid header is exactly the case worth making cheap,
// and the entry is bounded like any other, so remembering a refusal costs the
// same as remembering an acceptance.
func (c *WorkWasChecked) Check(e pow.Engine, h types.Header, p *params.Params) error {
	id := h.ID()

	c.mu.Lock()
	if err, ok := c.seen[id]; ok {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()

	// Evaluated OUTSIDE the lock. Holding it across a memory-hard hash would
	// serialise every verifier in the process behind one header, which is the
	// opposite of what this type is for — and with the p2p engine, the sync
	// driver and the miner sharing a node, that is a real queue rather than a
	// theoretical one. The cost of the race is that two goroutines may verify
	// the same header concurrently and store the same answer twice, which is
	// wasted work and never a wrong result.
	err := pow.CheckWork(e, h, p)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[id]; ok {
		return err // somebody else stored it while we hashed
	}
	if len(c.fifo) >= c.cap {
		delete(c.seen, c.fifo[0])
		c.fifo = c.fifo[1:]
	}
	c.seen[id] = err
	c.fifo = append(c.fifo, id)
	return err
}

// Len reports how many verdicts are held. For tests and diagnostics.
func (c *WorkWasChecked) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
