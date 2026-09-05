package stratum

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"

	"zycord/core/types"
)

// job is one template handed to one connection, kept so that a nonce arriving
// later can be judged against the bytes the miner actually searched.
//
// The block is stored WHOLE, not just the header, and that is the entire
// reason this cache exists rather than a re-assembly on submit. A block is
// certificates plus roots plus a state root sealed over a specific snapshot; a
// header alone cannot be applied, and re-assembling at submit time would
// produce a DIFFERENT block — different certificate set, different timestamp,
// different roots — whose PoWSeed the miner's nonce was never searched
// against. The share would then be rejected for arithmetic that was correct.
// Holding the candidate is the only way a solved nonce can become the block it
// solved.
type job struct {
	id string
	// block is the candidate this job's blob was derived from. It is never
	// mutated after construction: submit copies the header, stamps the nonce
	// into the copy, and builds a block value around it. Two miners submitting
	// against the same job concurrently must not race on one header.
	block *types.Block
	// extraNonce is this connection's share of the search space.
	//
	// It reaches the hashed bytes: PoWSeed covers ExtraNonce, so two
	// connections mining the same template at the same height genuinely search
	// different spaces rather than duplicating each other's work. Solo mining
	// sets it to zero.
	extraNonce uint32
	// target is the truncated 64-bit job target, kept so that a share can be
	// judged against the target the miner was GIVEN rather than against the
	// header's, which is the same number today and need not stay so if a
	// future variable-difficulty mode ever lands.
	target uint64
	// height is cached for logging and for the staleness check; it is
	// block.Header.Height and is duplicated only to keep the hot path off a
	// pointer chase.
	height uint64
	// blob is the exact bytes handed to the miner. Kept so that a submit can
	// be checked against them without recomputing a BLAKE3 pass, and so that
	// tests can assert two jobs differ.
	blob []byte
	// submitted records every nonce already seen for this job, so that a
	// retransmit is answered as a duplicate rather than verified again.
	//
	// It is bounded implicitly by the job cache's own size: a job leaves the
	// cache after jobCacheSize newer jobs, so an attacker who wanted this map
	// to grow would have to spend a real hash per entry to get past the
	// low-difficulty check first — and a share that passes that check is a
	// share worth remembering. Guarded by the owning connection's mutex; a job
	// belongs to exactly one connection and is never shared.
	submitted map[uint32]struct{}
}

// jobCacheSize is how many jobs one connection remembers.
//
// Small on purpose. The cache exists for LATE SUBMITS — a share found against
// the job that was current when the miner started hashing, arriving after a
// head change replaced it — and the window that matters is one or two jobs
// deep at a 30-second block interval. A large cache does not accept more
// honest shares; it accepts shares against templates whose parent is long
// gone, every one of which fails at Chain.Apply with ErrWrongParent after the
// node has paid a full RandomX verification for it. Eight is roughly four
// minutes of job history at the refresh interval, which is far beyond any
// honest miner's latency and still bounded.
const jobCacheSize = 8

// jobCache is a small fixed-capacity ring of a connection's recent jobs.
//
// A ring rather than a map with expiry: the eviction rule wanted here is
// "keep the last N", which a ring expresses without a clock. Tying job
// lifetime to wall time would make the cache's behaviour depend on the one
// thing this package tries hardest not to depend on, and would mean a node
// whose clock stepped backwards kept jobs forever.
//
// Not safe for concurrent use; the owning connection serialises access.
type jobCache struct {
	ring [jobCacheSize]*job
	next int
}

func (c *jobCache) put(j *job) {
	c.ring[c.next] = j
	c.next = (c.next + 1) % jobCacheSize
}

// get finds a job by id. Linear over eight entries, which is faster than a map
// at this size and allocates nothing.
func (c *jobCache) get(id string) *job {
	for _, j := range c.ring {
		if j != nil && j.id == id {
			return j
		}
	}
	return nil
}

// newest returns the most recently inserted job, or nil.
func (c *jobCache) newest() *job {
	prev := (c.next - 1 + jobCacheSize) % jobCacheSize
	return c.ring[prev]
}

// jobIDs hands out job identifiers.
//
// Random rather than a counter, and the reason is not secrecy — a job id is
// public to the miner holding it — but that ids must not collide ACROSS
// connections. Each connection keeps its own cache, but a job id also appears
// in logs and in an operator's mental model of "which miner is this", and two
// connections both calling their first job "1" makes those logs unreadable.
// Eight bytes is 2^64 of space against a population bounded by maxConns.
//
// crypto/rand rather than math/rand: not because a guessed job id would let an
// attacker do anything (submitting against someone else's job id on your own
// connection simply misses, because caches are per-connection), but because
// this package must not add a second seeded PRNG to a node whose one
// deterministic seed is a command-line flag. A reader auditing where
// randomness enters this process should find no surprises here.
type jobIDs struct{}

func (jobIDs) next() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read does not fail on any platform this node builds for;
		// if it somehow does, an id that is merely unique-per-connection is
		// still correct, because that is the only property the cache needs.
		// Falling back keeps a miner mining through an OS-level entropy fault
		// rather than dropping every connection.
		binary.LittleEndian.PutUint64(b[:], fallbackCounter.Add(1))
	}
	return hex.EncodeToString(b[:])
}

// fallbackCounter backs the entropy-failure path above. It is package-global
// because the failure is process-wide, and monotonic so that even in that
// state two connections cannot be handed the same id.
var fallbackCounter atomic.Uint64

// sessionIDs hands out per-connection session identifiers, which XMRig echoes
// on every submit. Same construction, different purpose, and deliberately not
// the same value as any job id: a session id that collided with a job id would
// make a mis-parsed submit look plausible.
type sessionIDs = jobIDs
