// Package mempool holds validated certificates waiting for a block.
//
// Admission is the V-rules — stateless, and therefore parallelisable and
// state-free — plus local policy that is explicitly *not* consensus: a deposit
// screen against the current tip, per-underwriter caps, a fee floor, a TTL
// window. Policy may differ between nodes without forking anything, which is
// exactly why it lives here and not in core/.
//
// The one thing this package must never do is let a certificate the V-rules
// reject reach a block. Everything else it does is an optimisation on behalf of
// the miner and the relay.
package mempool

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
)

// Rejection reasons that are policy rather than validity. A certificate
// rejected for one of these is not invalid — another node may hold it happily.
var (
	ErrAlreadyPooled      = errors.New("mempool: already pooled")
	ErrAlreadyCommitted   = errors.New("mempool: already committed on this chain")
	ErrExpired            = errors.New("mempool: TTL has passed")
	ErrTTLTooFar          = errors.New("mempool: TTL is beyond the consensus bound")
	ErrTTLTooNear         = errors.New("mempool: TTL leaves no room to be included")
	ErrUnderfunded        = errors.New("mempool: the deposit does not cover at the current tip")
	ErrBelowFloor         = errors.New("mempool: fee maximum is below the current base fee")
	ErrTooManyInFlight    = errors.New("mempool: the underwriter has too many certificates in flight")
	ErrFull               = errors.New("mempool: full")
	ErrBelowEvictionFloor = errors.New(
		"mempool: full, and this certificate does not outbid the cheapest resident by the required margin")
)

// Policy is the non-consensus half of admission. Defaults are conservative:
// a node that relays less than it could costs nobody anything, while a node
// that relays spam costs everybody.
type Policy struct {
	// MaxCertificates bounds the pool by certificate count.
	MaxCertificates int
	// MaxBytes bounds the pool by encoded size. Count alone does not bound
	// memory: a maximum-shape certificate (max reads, writes, sigs, moves) is
	// roughly 18x a minimal one, and nothing about MaxCertificates stops a
	// pool from being filled with the expensive shape. The two budgets
	// are independent — either one reaching its high water triggers the same
	// eviction discipline.
	MaxBytes int
	// MaxPerUnderwriter bounds how many certificates one signer may have in
	// flight, so a single funded key cannot fill the pool.
	MaxPerUnderwriter int
	// MinTTLLead is how many blocks ahead a TTL must reach to be worth pooling.
	// A certificate that can only be included in the very next block is a
	// certificate that will usually be wasted.
	MinTTLLead uint64

	// EvictionBumpPercent is how much an arrival must beat the certificate it
	// would displace, as a percentage. Displacement for one drop, repeated, is
	// itself a denial of service: it forces the evicted certificate to be
	// re-gossiped forever. A bump turns that into a geometric cost.
	EvictionBumpPercent uint64
	// EvictionHighWater is the occupancy, as a percentage of MaxCertificates,
	// at which eviction engages.
	EvictionHighWater uint64
	// EvictionLowWater is the occupancy eviction clears down to. The gap is
	// hysteresis: without it the pool sits exactly at capacity and the marginal
	// certificate thrashes on every arrival.
	EvictionLowWater uint64
}

// DefaultPolicy returns the shipped defaults.
func DefaultPolicy() Policy {
	return Policy{
		MaxCertificates:   20_000,
		MaxPerUnderwriter: 64,
		MinTTLLead:        2,

		// 32 MiB. Verified against real code (see PR description): a minimal
		// certificate is 848 B, so 20,000 of them is ~16.2 MiB — comfortably
		// under this, meaning ordinary traffic never touches the byte budget
		// and MaxCertificates keeps being the binding count constraint. The
		// largest certificate the V-rules can actually admit (32 moves, 64
		// writes, 16 sigs — the structural ceiling for a TRANSFER, since reads
		// are capped by move count rather than MaxReads) is 15,277 B, so this
		// caps worst-case resident memory at 32 MiB instead of the ~291 MiB
		// 20,000 maximum-shape certificates would otherwise cost.
		MaxBytes: 32 * 1024 * 1024,

		// Reasonable, not derived. See docs/adversarial/mempool.md §4: these are
		// node policy, nodes may differ without forking anything, and measuring
		// them is a stated purpose of the public testnet.
		EvictionBumpPercent: 10,
		EvictionHighWater:   90,
		EvictionLowWater:    85,
	}
}

// entry is a pooled certificate and the facts about it worth caching.
type entry struct {
	cert   *types.Certificate
	id     types.Hash
	seqGas uint64
	parGas uint64
	bytes  int
	// reserve is what the fold actually reserves against the deposit cell:
	// max(Deposit.Amount, FeeCeiling()). It is cached for the aggregate
	// deposit screen. Summing FeeCeiling here — as this once did — let a
	// certificate declare a small ceiling but a huge Amount, pass the screen,
	// then over-reserve at the fold and drop its siblings uncharged; the
	// screen must sum the same quantity the fold reserves. V5 guarantees
	// Amount >= FeeCeiling, so the max is Amount for every valid certificate;
	// it is written as a max to fail safe rather than to lean on that.
	reserve u256.U256
}

// Pool is a validated certificate pool.
type Pool struct {
	mu     sync.RWMutex
	params *params.Params
	policy Policy

	byID          map[types.Hash]*entry
	byUnderwriter map[types.Address]int
	// byUnderwriterReserve is the sum of entry.reserve — max(Deposit.Amount,
	// FeeCeiling) — over a deposit cell's currently pooled certificates, i.e.
	// the total the fold would reserve against the cell if every pooled
	// certificate committed. Deposit.Cell and UnderwriterID() are the same
	// identity in Era 0 (V4 requires a signature from Deposit.Cell.Addr, V5
	// requires it to be a native balance cell — so a certificate can only ever
	// name its own signer's one native balance slot), which is why this is
	// keyed exactly like byUnderwriter. Summing FeeCeiling instead of the full
	// reservation is the defect that closes, and the sum rather than the
	// per-certificate maximum is what makes the screen a screen.
	byUnderwriterReserve map[types.Address]u256.U256
	// totalBytes is the sum of entry.bytes over the pool, maintained
	// incrementally so the byte-budget check in Add is O(1) rather than a scan
	// rather than a scan.
	totalBytes int

	// floorHint is the cheap first check that keeps a refusal from costing a
	// full walk of the pool: see floorLowerBound.
	floorHint priceHeap
	// floorHintTailSeq is the highest pooled Seq per underwriter as of the last
	// time floorHint was rebuilt, kept current on admission. It is what lets
	// floorLowerBound recognise a heap top that is a chain *interior* — pooled,
	// but structurally unevictable under §2.3 — in O(1), without walking the
	// pool. See floorLowerBound.
	floorHintTailSeq map[types.Address]uint64
	// floorHintStale records that a removal happened since the last rebuild. A
	// removal is the only event that can make a previously unevictable entry
	// evictable, so it is the only event that can invalidate a pop done on
	// evictability grounds. See floorLowerBound.
	floorHintStale bool

	// Metrics, read by the observability layer (M1-G7).
	admitted uint64
	rejected uint64
	evicted  uint64
}

// StateReader is the read-only view of consensus state the pool needs.
//
// An interface rather than *state.State so that a **borrowed** reference can be
// passed in (chain.StateRef, valid only inside a Chain.Read callback) without
// the pool being able to retain a live pointer or write through it. The pool
// screens against state; it has no business mutating it, and now cannot.
//
// It lists exactly the three accessors the pool uses. Widening it is a decision
// to be made deliberately, not by adding a method call.
type StateReader interface {
	Get(types.Slot) u256.U256
	IsSpent(types.Address) bool
	Seen(types.Hash) (uint64, bool)
}

// New returns an empty pool.
func New(p *params.Params, policy Policy) *Pool {
	return &Pool{
		params:               p,
		policy:               policy,
		byID:                 make(map[types.Hash]*entry),
		byUnderwriter:        make(map[types.Address]int),
		byUnderwriterReserve: make(map[types.Address]u256.U256),
		floorHintTailSeq:     make(map[types.Address]uint64),
	}
}

// Add validates and pools a certificate.
//
// The V-rules run unconditionally. A caller that has already checked them still
// pays for them here, because the pool is the boundary between the network and
// the node, and a boundary that trusts its input is not a boundary.
//
// They do not all run *first*. Admission is ordered by cost — every byte a peer
// sends is priced before it buys work: the structural V-rules, which are
// integer comparisons over the decoded body, then every O(1) policy gate, and
// only then V2 — the Ed25519 verification, which dominates the whole predicate.
// The order used to be the opposite one, so the cheapest refusal the pool has
// (a certificate whose TTL is already past, needing no funds and replayable
// forever) was charged the dearest check in it. The boundary property survives
// the reorder untouched: nothing between the two halves mutates the pool, and
// no certificate is pooled without V2 having returned nil for it. See the
// screened type below for what enforces the order.
//
// V2 also runs with pool.mu RELEASED, and that is load-bearing rather than
// incidental. Holding the write lock across an Ed25519 pass would have handed
// an attacker with one funded deposit cell a way to stall the pool: a forged
// certificate is never pooled, so it never raises the aggregate deposit screen
// or the per-underwriter count, so the same cell screens an unbounded stream of
// distinct forgeries — each one paying for a verification that Candidates(),
// IDs(), Stats() and every RPC reader would have waited behind (§2.6 names that
// lock as the contention that matters). screen is a pure predicate, so running
// it again after the lock is retaken restores exactly the atomicity the single
// critical section had: the admission decision and the insert are still taken
// together, under one lock, against one view of the pool.
//
// LOAD-BEARING for eviction, and recorded here because the dependency is remote:
// chain pricing (§2.1) means one cheap certificate sets its whole underwriter's
// eviction rank, so it would be a griefing primitive if a third party could
// attach a certificate to somebody else's chain. It cannot, and the reason is
// this call. UnderwriterID() is Deposit.Cell.Addr; V5 (CheckDeposit) requires
// that cell to be a *user* address, and V4 (CheckAuthorization) then requires
// that address's signature. Note that V4's signature requirement is a condition
// — `if crypto.IsUserAddress(...)` — and not a whitelist: an era that ever
// admitted a non-user deposit cell would make chain pricing remotely griefable
// for the price of one certificate, where the old tail pricing was not.
func (pool *Pool) Add(c *types.Certificate, s StateReader, tipHeight uint64) error {
	// The cheap half of the V-rules: integer comparisons, ordering, limits and
	// derivation over the already-decoded body. V2 is not in here — it is at the
	// far end of this function, behind every gate that can refuse for free.
	if err := validity.CheckStructural(c, pool.params); err != nil {
		pool.countRejected()
		return fmt.Errorf("mempool: %w", err)
	}

	// The id is a hash of the body and does not cover the signatures,
	// so it is well defined before V2 has run and means the same thing after.
	id := c.ID()

	pool.mu.Lock()
	passed, err := pool.screen(c, id, s, tipHeight)
	pool.mu.Unlock()
	if err != nil {
		return err
	}

	// V2, once, last, and outside the critical section. `passed` is not data —
	// it is the ordering proof; see screened.
	if err := pool.verifySignatures(c, passed); err != nil {
		pool.countRejected()
		return fmt.Errorf("mempool: %w", err)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Re-screen. The lock was released for the verification, so both the pool
	// and the state may have moved; this is the evaluation admission is
	// actually taken on, and it is atomic with the eviction pass and the insert
	// below. Every gate is a pure predicate, so a certificate the first screen
	// passed and this one refuses is one the single-lock version would have
	// refused too, with the same error and the same single increment of
	// pool.rejected — the first screen only ever decides whether V2 is worth
	// paying for.
	passed, err = pool.screen(c, id, s, tipHeight)
	if err != nil {
		return err
	}

	reserve, underwriter := passed.reserve, passed.underwriter

	// Under pressure, price decides entry — not arrival time. A pool that
	// refused arrivals when full would be grindable: flood it with minimum
	// priority and legitimate traffic is censored at the door, exactly when the
	// fee market is supposed to be resolving the contention
	// (docs/adversarial/mempool.md §1).
	if len(pool.byID) >= pool.highWater() {
		if err := pool.makeRoomFor(c); err != nil {
			pool.rejected++
			return err
		}
	}

	// The pool also bounds bytes, not just count: a maximum-shape
	// certificate is worth roughly 18x a minimal one in resident memory, and
	// nothing about the count budget stops an attacker from choosing that
	// shape. Same room-making discipline as the count check immediately above
	// (price order, tail-safe, bump-gated) — just measured in bytes.
	//
	// The trigger counts the arrival, unlike the count trigger above, and the
	// asymmetry is deliberate. A count arrival is worth exactly one slot, so
	// testing occupancy before it can overshoot the high water by one. A byte
	// arrival is worth anything from 848 B to ~15 KB, so a pool resting one
	// byte below its byte high water would admit a maximum-shape certificate
	// with no byte check at all — and repeatedly, since each admission leaves
	// the pool below the mark again only if something else left. Measuring
	// `totalBytes + entryBytes` is what makes MaxBytes an actual bound rather
	// than a bound plus one worst-case certificate.
	entryBytes := c.SizeBytes()
	if pool.totalBytes+entryBytes > pool.byteHighWater() {
		if err := pool.makeByteRoomFor(c, entryBytes); err != nil {
			pool.rejected++
			return err
		}
	}

	pool.byID[id] = &entry{
		cert:    c,
		id:      id,
		seqGas:  c.SeqGas(pool.params),
		parGas:  c.ParGas(pool.params),
		bytes:   entryBytes,
		reserve: reserve,
	}
	pool.byUnderwriter[underwriter]++
	pool.byUnderwriterReserve[underwriter] = pool.byUnderwriterReserve[underwriter].SatAdd(reserve)
	pool.totalBytes += entryBytes
	pool.admitted++
	pool.pushFloorHint(id, c.FeeBid.SeqPriority, underwriter, c.Seq)
	return nil
}

// screened is the token every O(1) admission gate has said yes to, carrying the
// two facts those gates computed that admission needs again.
//
// It exists to make Add's cost order a data dependency rather than a
// convention. verifySignatures takes a screened, and screen is its only
// producer, so V2 cannot be moved back in front of the cheap gates without the
// move being visible at the call site. A comment saying "keep these in this
// order" is what this already had, one line above the code that did not.
type screened struct {
	underwriter types.Address
	reserve     u256.U256
}

// screen runs every admission gate that can refuse in O(1), in the order cost
// discipline prescribes: dedup, then the TTL window and the committed-set lookup,
// then the budget gates (fee floor, deposit screen, per-underwriter cap).
//
// Nothing in here mutates the pool's admission state, and every gate is a pure
// predicate of (certificate, pool, state). Two things rest on that. It is safe
// to run before V2 — a certificate with a forged signature can reach every one
// of these gates and still change nothing an honest certificate can observe,
// exactly as it did when V2 ran first; the pool's first mutation of admission
// state is the eviction pass in Add, which is downstream of verifySignatures.
// And it is safe to run TWICE, which is what lets Add release the lock across
// the verification: the second evaluation is the authoritative one and agrees
// with what a single critical section would have decided.
//
// The one thing it does write is pool.rejected, the refusal counter, and Add is
// structured so that a refused certificate increments it exactly once: a
// certificate the first screen passes and the second refuses was not counted by
// the first.
//
// Caller holds pool.mu.
func (pool *Pool) screen(c *types.Certificate, id types.Hash, s StateReader, tipHeight uint64) (screened, error) {
	if _, dup := pool.byID[id]; dup {
		return screened{}, ErrAlreadyPooled
	}

	// Consensus-shaped policy: these mirror B1 and B2 evaluated at the height
	// this certificate could first be included at, so pooling a certificate
	// that could never be included would only waste the miner's time.
	//
	// Each of the THREE CERTIFICATE BOUNDS below is written as a distance from
	// the tip, never as a sum against it, because a wrapped ceiling is not a
	// ceiling. core/fold/blockrules.go and sim/refold/refold.go carry B2 in
	// exactly this form and for exactly this reason; the claim to mirror them
	// is only true while this does too. ttl_max is bounded from below only
	// (params.Validate requires >= 2) and it was ruled deliberately that it
	// stays that way, so ttl_max = 2^64-1 -- the most permissive horizon the
	// parameter set can express -- is a value the loader accepts. In the sum
	// form next+ttl_max wrapped to next-1, every certificate B1 admitted was
	// above it, and the pool refused the whole stream with ErrTTLTooFar: a
	// silent liveness stop in the direction of censorship. No bound on ttl_max
	// can repair the sum, because the other addend is unbounded chain height;
	// only the subtraction can, and the expiry check below makes it total.
	//
	// `next` itself is the ONE sum that remains, and the claim above is scoped
	// to exclude it deliberately rather than by oversight. It is not a bound on
	// a certificate but the height the bounds are evaluated at, and it wraps to
	// 0 at tipHeight = 2^64-1. That is FAIL-OPEN, and measured rather than
	// inferred: at that height `c.TTL < next` cannot fire, so an EXPIRED
	// certificate reaches the two bounds below and passes both whenever
	// MinTTLLead-1 <= c.TTL <= ttl_max -- at the shipped devnet parameters, any
	// expired TTL in 1..32. It is admitted. (A larger expired TTL is still
	// refused, by the horizon rather than by expiry, so the witness must sit
	// inside ttl_max; TTL=500 at devnet does NOT show this.) It stays a sum
	// because its wrap is unreachable rather than merely
	// unlikely -- REACHABILITY, NOT DIRECTION, is what separates it from
	// MinTTLLead below, whose wrap needs no chain history at all. Every non-test
	// caller passes chain.View.Height read under Chain.Read, and
	// node/chain/forkchoice.go admits a successor only at parent height + 1, so
	// 2^64-1 costs 2^64 applied blocks and nothing a peer, an operator or an RPC
	// client supplies can shortcut it. Do not read this exception as licence to
	// add a fourth bound in the sum form.
	next := tipHeight + 1
	if c.TTL < next {
		pool.rejected++
		return screened{}, ErrExpired
	}
	// Total: c.TTL >= next was just established.
	if c.TTL-next > pool.params.TTLMax {
		pool.rejected++
		return screened{}, ErrTTLTooFar
	}
	// Total for the same reason, one step weaker: c.TTL >= next > tipHeight.
	// MinTTLLead is node policy rather than a chain parameter, but it is an
	// operator-set uint64 with no upper bound either, and in the sum form a
	// large one wrapped below the tip and disabled this gate entirely -- the
	// fail-open direction, which is why it is not left as the one sum here.
	//
	// This is also the only one of the three whose totality is load-bearing in
	// the dangerous direction, so these arms must keep this order. An underflow
	// at either bound above yields a huge distance and fails CLOSED -- the same
	// refusal the expiry arm itself gives. A huge distance HERE is not
	// < MinTTLLead, so it fails OPEN, and the expiry arm above is the only thing
	// standing between this subtraction and that.
	if c.TTL-tipHeight < pool.policy.MinTTLLead {
		pool.rejected++
		return screened{}, ErrTTLTooNear
	}
	if _, seen := s.Seen(id); seen {
		pool.rejected++
		return screened{}, ErrAlreadyCommitted
	}

	// B4's policy shadow: a maximum below the current base fee cannot be
	// included now, and the base fee only falls when blocks are under target.
	seqBase := s.Get(types.SeqBaseFeeSlot())
	parBase := s.Get(types.ParBaseFeeSlot())
	if c.FeeBid.SeqMax.Lt(seqBase) || c.FeeBid.ParMax.Lt(parBase) {
		pool.rejected++
		return screened{}, ErrBelowFloor
	}

	// The deposit screen. This is the only tip-dependent check a relay needs,
	// and it is what stops unfunded spam from propagating for free (§10).
	//
	// The screen is a SUM over the cell's already-pooled certificates, not a
	// per-certificate maximum. Deposit.Cell backs every certificate
	// pooled against it simultaneously — the fold has not run yet, so the pool
	// cannot know which of them will actually commit — so the balance must
	// cover the arrival's reservation *plus* everything already pooled for the
	// same cell. A per-certificate check let one funded balance back
	// MaxPerUnderwriter certificates at once, at the cost of one; this backs
	// them each in full.
	//
	// The quantity summed is the reservation the fold takes — max(Amount,
	// FeeCeiling) — not FeeCeiling alone. V5 only enforces Amount >= FeeCeiling
	// (Amount is unbounded above), while core/fold reserves the full Amount and
	// drops any sibling the cell can no longer cover *uncharged*. Summing
	// FeeCeiling let a certificate declare a small ceiling but a huge Amount,
	// pass this screen, buy a block slot, then drop for free and starve honest
	// certs under contention. A single honest high-Amount deposit is
	// unaffected: the cell it names actually holds that Amount, so the arrival
	// alone still fits — only the over-reserving *flood*, whose reservations
	// sum past the balance, is refused.
	ceiling, ok := c.FeeCeiling(pool.params)
	if !ok {
		pool.rejected++
		return screened{}, ErrUnderfunded
	}
	reserve := u256.MaxOf(c.Deposit.Amount, ceiling)
	underwriter := c.UnderwriterID()
	required := pool.byUnderwriterReserve[underwriter].SatAdd(reserve)
	if s.IsSpent(c.Deposit.Cell.Addr) || s.Get(c.Deposit.Cell).Lt(required) {
		pool.rejected++
		return screened{}, ErrUnderfunded
	}

	// MaxPerUnderwriter is not redundant with the sum above: it is not the
	// Sybil defence (that is the deposit screen; docs/adversarial/mempool.md
	// §2.5) and it is not made moot by the screen being aggregated. It caps
	// how much of the pool one identity — however well funded — can occupy, so
	// a single whale cannot own every slot even at fully-priced cost, and it
	// forces a well-funded attacker's capital to spread across many prices
	// rather than concentrate in one, which is what keeps the eviction
	// ranking meaningful. The two checks answer different questions: this one
	// bounds occupancy per identity; the one above prices that occupancy
	// honestly.
	if pool.byUnderwriter[underwriter] >= pool.policy.MaxPerUnderwriter {
		pool.rejected++
		return screened{}, ErrTooManyInFlight
	}

	return screened{underwriter: underwriter, reserve: reserve}, nil
}

// verifySignatures is V2 — the Ed25519 verification of every signature — and it
// is the only place the pool pays for it. The gossip path used to pay for
// it twice per certificate, and to pay before every free refusal.
//
// The screened argument is deliberately unused: it is the compiler-checked
// proof that the cheap gates have already run. Do not delete it to silence a
// linter; deleting it is precisely the refactor this parameter exists to stop.
func (pool *Pool) verifySignatures(c *types.Certificate, _ screened) error {
	return checkSignatures(c, pool.params)
}

// checkSignatures is validity.CheckSignatures behind one word of indirection so
// that a test can *count* how many Ed25519 verifications an admission pays for.
// "verified once" and "verified after the free refusals" are both claims about
// a number of calls, and a claim about a number of calls is only pinned by a
// test that counts them — timing them measures the machine, and reading the
// code measures nothing at all. Swapped only from export_test.go.
var checkSignatures = validity.CheckSignatures

func (pool *Pool) highWater() int {
	n := pool.policy.MaxCertificates * int(pool.policy.EvictionHighWater) / 100
	if n < 1 {
		n = 1
	}
	if n > pool.policy.MaxCertificates {
		n = pool.policy.MaxCertificates
	}
	return n
}

func (pool *Pool) lowWater() int {
	n := pool.policy.MaxCertificates * int(pool.policy.EvictionLowWater) / 100
	if n < 0 {
		n = 0
	}
	if n >= pool.highWater() {
		n = pool.highWater() - 1
	}
	return n
}

// byteHighWater and byteLowWater are the byte-budget analogues of highWater
// and lowWater, reusing the same hysteresis percentages against MaxBytes
// instead of MaxCertificates.
func (pool *Pool) byteHighWater() int {
	n := pool.policy.MaxBytes * int(pool.policy.EvictionHighWater) / 100
	if n < 1 {
		n = 1
	}
	if n > pool.policy.MaxBytes {
		n = pool.policy.MaxBytes
	}
	return n
}

func (pool *Pool) byteLowWater() int {
	n := pool.policy.MaxBytes * int(pool.policy.EvictionLowWater) / 100
	if n < 0 {
		n = 0
	}
	if n >= pool.byteHighWater() {
		n = pool.byteHighWater() - 1
	}
	return n
}

// makeByteRoomFor is the byte budget: the same eviction discipline
// makeRoomFor applies, denominated in the pool's total encoded size instead of
// its certificate count.
//
// It is a second budget rather than a second *rule*. Everything that decides
// *who* may leave is makeRoomFor's and is reused unchanged — the cheap-bound fast
// path, chainPrices, evictionCandidates (which carries §2.3's chain-safety and
// own-chain predicates), the floor read from that same candidate set, and
// evictionOrder's beatable filter. Only the stopping condition differs: this
// pass drains until the pool is under its byte low water rather than its count
// low water, because a handful of maximum-shape certificates can exhaust the
// byte budget while the count is nowhere near its own high water.
//
// The per-victim guards are re-checked here for the same reason makeRoomFor
// re-checks them: they fail closed against a wrong candidate set, not merely
// against a wrong floor.
func (pool *Pool) makeByteRoomFor(arrival *types.Certificate, arrivalBytes int) error {
	bump := pool.policy.EvictionBumpPercent

	// The cheap-bound fast path, sound here for the same reason it is sound in
	// makeRoomFor: the bound is over the same candidate set and the same
	// declarations, and the byte target changes only how many victims are
	// taken, never which ones are eligible.
	if hint, ok := pool.floorLowerBoundFor(arrival); ok && !beatsByBump(arrival.FeeBid.SeqPriority, hint, bump) {
		return ErrBelowEvictionFloor
	}

	prices := pool.chainPrices()
	candidates, floor, ok := pool.evictionCandidates(prices, arrival)
	if !ok {
		return ErrFull
	}
	if !beatsByBump(arrival.FeeBid.SeqPriority, floor, bump) {
		return ErrBelowEvictionFloor
	}

	target := pool.byteLowWater()
	victims := evictionOrder(candidates, arrival, bump)
	for _, v := range victims {
		if pool.totalBytes <= target {
			break
		}
		if !beatsByBump(arrival.FeeBid.SeqPriority, v.cert.FeeBid.SeqPriority, bump) {
			continue
		}
		if v.cert.Seq < arrival.Seq && v.cert.UnderwriterID() == arrival.UnderwriterID() {
			continue
		}
		pool.removeLocked(v.id)
		pool.evicted++
	}

	// Reachable, unlike its count-budget counterpart, and that difference is
	// the point. Clearing the floor guarantees the pass removes at least one
	// *certificate*; it guarantees nothing about how many *bytes* that
	// certificate carried. A pool full of minimal certificates cannot make
	// room for a maximum-shape arrival one 848-byte eviction at a time once
	// the candidate set runs out, so the arrival is refused rather than
	// admitted over the budget.
	if pool.totalBytes+arrivalBytes > pool.policy.MaxBytes {
		return ErrFull
	}
	return nil
}

// makeRoomFor evicts the lowest-paying evictable residents until the pool is at
// its low-water mark, provided the arrival outbids the worst of them by the
// required bump.
//
// The metric is sequential priority — already a per-gas price, so no division
// and no rounding enters the ordering. It is deliberately *not* the parallel
// tip or the total: the sequential loop is the scarce resource, and a pool
// ranked by the abundant one would evict exactly the certificates a rational
// miner most wants (R2-H2's error, one layer up).
//
// THE INVARIANT, and there is only one:
//
//	An arrival may displace a certificate only if it beats *that certificate's
//	own declared SeqPriority* by the bump margin.
//
// It is enforced where it is stated: at the point of removal, against each
// victim, one at a time. Nothing else here is load-bearing for it. Three earlier
// attempts tried instead to *infer* it from a gate computed before the pass, and
// each failed by denominating the gate in one metric and the victims in another:
//
//   - Gate = the cheapest evictable *tail's* own price, victims = the `need`
//     cheapest, removed unconditionally. The gate covered only victims[0];
//     victims 2..need could declare arbitrarily more than the arrival.
//   - Gate = the cheapest *chain* price in the pool (min over a chain's members),
//     victims = chain tails. A tail's own declaration is unbounded above its
//     chain's minimum, so one cheap-based chain let an arrival declaring 2 remove
//     residents declaring 1,000,000.
//   - Gate = the `need`-th smallest chain price. Same defect, threshold raised
//     from one such chain to `need` of them, which is ordinary fee-bumping
//     traffic rather than an attack shape.
//
// With the per-victim check in place the gate no longer has to carry the
// invariant, and it must not try to: a gate that guarantees a *full* low-water
// batch has to be quantified at the top of the cut rather than the bottom, and
// that is a censorship vector in its own right. Measured, on the shape below —
// nine 10-long chains at 100 with one honest tail declaring 1,000,000, so the
// evictable set (9) is smaller than `need` (10) and the batch gate degenerates
// to the *largest* evictable declaration:
//
//	floor = need-th smallest declared: arrivals at 200, 1_000, 5_000, 50_000
//	and 999_999 all refused; only 1_100_000 admitted. One certificate set the
//	admission price for the whole pool, at 5_500x the market rate — §1's
//	censorship attack, delivered by §2's fix.
//
// So the gate is the **cheapest removable resident's own declaration**, which is
// §2.1's headline rule, and the pass removes every resident the arrival beats,
// down to the low-water target. The batch is therefore proportional to what the
// arrival outbids instead of being all-or-nothing, and hysteresis becomes
// best-effort — which §2.3 already required of it, since a pass over few
// evictable chains cannot reach the target at any price.
//
// The batch gate was not paying for itself either, and the evidence is counts
// rather than a stopwatch — wall time on a shared machine moved by 3-8x run to
// run, more than the effect. TestEvictionPathCostIsCountedNotTimed asserts
// these; pool of 4,000 at high water, 300 arrivals, need = 200:
//
//	                  need-th smallest      cheapest candidate
//	distribution      admitted  passes      admitted  passes  sorted
//	flat                   300       2           300       2   7 000
//	tight spread           300       2           300       2   7 000
//	wide spread            111     190           300       5     492
//	geometric ladder       250      52           300       3   1 620
//	marginal ladder          0     300            49     300      49
//
// Refusing an arrival does not skip the pass: it runs the whole floor
// computation and then says no, and it leaves the pool at its high-water mark
// so the next arrival pays again. The refusing gate runs 38x and 17x as many
// passes on the two middle rows, to admit less traffic.
//
// The last row is the exception, and the one shape where the refusing gate is
// genuinely cheaper: it is not a distribution but an attacker, renting the
// pool's cheapest slot and climbing it a drop at a time so that every arrival
// clears the floor and can take exactly one certificate. Both rules run 300
// passes; a gate at the cut refuses all of them before reaching the sort, and
// this gate must admit them, because refusing them is refusing §1's arrival.
// That is paid for in evictionOrder, which filters before it sorts, so those
// 300 passes sort 49 certificates between them — see there.
//
// Chain *ordering* is unchanged and still keyed on the chain price (see
// chainPrices): which of the beatable residents leaves first is the
// floor-pinning flood's question, and ranking chains as units is the answer to
// it.
//
// Cost of the invariant, stated plainly rather than argued away: an attacker's
// chain tail declaring P is protected at P, exactly as an honest resident
// declaring P is, and the pool cannot tell the two apart because they are the
// same declaration. So an attacker that declares P on one evictable tail per
// identity — every one of them, since the floor is a minimum — raises the floor
// to P. That is the flood's upward vector at the flood's price, and it is not
// closable here: a rule that lets a cheap arrival remove a dear tail *is* the
// regression above. Closing it needs the declaration to cost something — a
// guaranteed-skip certificate is ranked at a price the fold never charges it —
// and the deposit screen to aggregate. See docs/adversarial/mempool.md §2.1.
//
// The *cost of saying no* is a separate matter, and it is what floorLowerBound
// below is for. Everything from chainPrices down is O(len(byID)) and is paid
// before the arrival's price is ever consulted, so a stream of arrivals priced
// below the market forces a full two-pass walk of the pool per certificate,
// under the write lock, for the price of one gossip message. The exact floor
// cannot be made cheaper than that — it is a minimum over a set defined by a
// per-entry predicate, so it has to visit every entry — but a *sound lower
// bound* on it can be, and an arrival that cannot clear the lower bound
// provably cannot clear the floor. That check is O(1) amortised, it runs first,
// and it is the only thing in this function that can refuse an arrival without
// walking the pool.
//
// It is a fast path, never an authority: it can only ever return the same
// ErrBelowEvictionFloor the exact path below would have returned for the same
// arrival, and clearing it decides nothing. See floorLowerBound.
func (pool *Pool) makeRoomFor(arrival *types.Certificate) error {
	bump := pool.policy.EvictionBumpPercent

	// The cheap-bound fast path. A sound lower bound on `floor` below, maintained
	// incrementally on admission instead of recomputed here, so an arrival that
	// was never going to clear the floor is refused before the pool is walked
	// at all. Failing here implies failing below; clearing it implies nothing.
	if hint, ok := pool.floorLowerBoundFor(arrival); ok && !beatsByBump(arrival.FeeBid.SeqPriority, hint, bump) {
		return ErrBelowEvictionFloor
	}

	prices := pool.chainPrices()

	// One predicate, used twice: what this arrival could conceivably take. The
	// floor is read from that set and the pass removes from it, so the gate can
	// never say yes to a price no candidate carries — which is what happens when
	// the floor is a minimum over residents the arrival is then forbidden to
	// touch, and it is why these are not two independent passes over the pool.
	candidates, floor, ok := pool.evictionCandidates(prices, arrival)
	if !ok {
		return ErrFull
	}
	if !beatsByBump(arrival.FeeBid.SeqPriority, floor, bump) {
		return ErrBelowEvictionFloor
	}

	// Clearing the floor means beating the cheapest candidate, so the pass now
	// removes at least one certificate. Occupancy therefore never rises above
	// the high-water mark, and the hard cap below is unreachable.
	target := pool.lowWater()
	victims := evictionOrder(candidates, arrival, bump)

	for _, v := range victims {
		if len(pool.byID) <= target {
			break
		}
		// The invariant and §2.3's own-chain rule, re-checked at the point of
		// removal rather than inferred from anything computed before the pass.
		// evictionCandidates and evictionOrder applied both already, so deleting
		// either of these two guards passes the whole suite — they are the only
		// lines in this file no test can falsify, which is worth stating rather
		// than hiding.
		//
		// They stay because they fail closed against a wrong *candidate set*,
		// not merely against a wrong floor, and that is demonstrable rather than
		// hopeful: invert the build-side own-chain predicate and the stranding is
		// caught here, not by TestAnArrivalNeverEvictsItsOwnChainBase. A future
		// change to how candidates are chosen cannot silently remove a
		// certificate the arrival did not outbid, or strand the arrival's own
		// chain.
		if !beatsByBump(arrival.FeeBid.SeqPriority, v.cert.FeeBid.SeqPriority, bump) {
			continue
		}
		if v.cert.Seq < arrival.Seq && v.cert.UnderwriterID() == arrival.UnderwriterID() {
			continue
		}
		pool.removeLocked(v.id)
		pool.evicted++
	}
	// Unreachable: the floor is the cheapest candidate's declaration, so an
	// arrival that cleared it beats at least one candidate and the loop above
	// removed at least one certificate. Kept so that a future change which
	// breaks that reasoning overshoots by a bounded amount instead of an
	// unbounded one. TestOccupancyNeverRisesAboveTheHighWaterMark pins the
	// property; nothing can pin this line while the property holds.
	if len(pool.byID) >= pool.policy.MaxCertificates {
		return ErrFull
	}
	return nil
}

// chain is what the pool knows about one underwriter's pooled certificates.
type chain struct {
	maxSeq uint64
	// price is the chain's sequential priority as a unit: the minimum over its
	// members. A dependent chain is only worth what its weakest link is worth,
	// because nothing above a Seq can apply until that Seq has — so a chain
	// whose base bids zero is a zero-priority occupant of the pool however much
	// its tail declares.
	price u256.U256
}

// chainPrices summarises every underwriter's pooled certificates in one pass.
//
// The chain price is an *ordering* key. §2.3's chain-safety rule makes
// only a sender's highest pooled Seq evictable, so an attacker holding Seq
// chains presents the pool with one tail per identity and may declare any price
// it likes on it. Ranking those tails by their own declaration lets the attacker
// buy protection for 63 unbid certificates with one bid; ranking them by the
// chain's cheapest member does not, because the chain is only worth what its
// weakest link is worth — nothing above a Seq can apply until that Seq has.
//
// Rejected alternative: price a chain by the *total* of its members. One
// expensive tail lifts the whole chain's total, so the ordering is bought back
// with the same certificates.
//
// What the chain price is deliberately *not* is the floor, at any cut. See
// makeRoomFor: the floor is denominated in the victims' own declarations. A
// chain price is a *lower* bound on what its tail declares, and the tail is what
// leaves, so any gate read from chain prices licenses removing certificates that
// declare more than the arrival — which is exactly the bug the two previous
// shapes of this function's caller shipped.
func (pool *Pool) chainPrices() map[types.Address]chain {
	out := make(map[types.Address]chain, len(pool.byUnderwriter))
	for _, e := range pool.byID {
		u := e.cert.UnderwriterID()
		c, seen := out[u]
		if !seen {
			out[u] = chain{maxSeq: e.cert.Seq, price: e.cert.FeeBid.SeqPriority}
			continue
		}
		if e.cert.Seq > c.maxSeq {
			c.maxSeq = e.cert.Seq
		}
		c.price = u256.MinOf(c.price, e.cert.FeeBid.SeqPriority)
		out[u] = c
	}
	return out
}

// evictable reports whether an entry may leave without stranding a chain.
//
// A certificate is evictable only if no certificate from the same underwriter
// with a higher Seq is pooled. Evicting the middle of a dependent chain would
// strand everything above it — those certificates can never apply, so the pool
// would keep offering miners work that is guaranteed to skip. Chains truncate
// from the tail, which is the same order the fold commits them in (F1). This
// rule is unchanged by the floor-pinning fix: what changed is the price the
// tail is ranked and gated at, not which certificates may go.
//
// LOAD-BEARING, and not obvious: `prices` is computed once per makeRoomFor pass
// and is deliberately *stale* for the rest of it. Because evictable() is
// `Seq == prices[u].maxSeq`, every entry an underwriter contributes to the
// victim list sits at that underwriter's highest pooled Seq *in the snapshot*,
// so removing any subset of them strands nothing — nothing in the pool sits
// above them. A multi-eviction pass therefore cannot hole a chain even though
// the map stops describing the pool after the first removal.
//
// It is a subset property, not a uniqueness one, and the distinction is worth
// the sentence: Seq is an ordering key rather than a nonce (see
// core/types/certificate.go), so one underwriter may pool several certificates
// at the same Seq — replace-by-fee does exactly that — and then contributes
// several entries here. Verified on Seq 0,1,1: both tails may be taken in one
// pass and Seq 0 survives with no hole.
//
// What a refactor must not do is recompute `prices` between evictions, or let
// the order return a member *below* another pooled member of the same chain in
// order to hit the low-water target. Either strands chains immediately and
// breaks §2.3. The pass under-delivering on lowWater() when few chains are
// evictable is not an oversight; it is the shape of the safety property.
func evictable(e *entry, prices map[types.Address]chain) bool {
	return e.cert.Seq == prices[e.cert.UnderwriterID()].maxSeq
}

// evictionCandidates is the set of residents this arrival could take, together
// with the eviction floor read from that same set.
//
// The floor is §2.1's headline rule — "a full pool admits a higher-paying
// arrival by evicting the lowest-paying resident" — in the currency residents
// actually declare:
//
//	floor = min over the candidates of SeqPriority
//
// It is the whole gate. The invariant that an arrival never removes a
// certificate it did not outbid is enforced per candidate, here and again at
// the point of removal; the floor does not carry it.
//
// Two exclusions, and both have to apply to the floor as well as to the pass,
// which is why one function returns both:
//
//   - Not removable. §2.3 makes only an underwriter's highest pooled Seq
//     evictable — a chain's cheap base cannot leave without stranding what sits
//     above it. It is therefore not a price anyone can be admitted against, and
//     this is the entire difference between this floor and the pool-wide
//     minimum.
//   - The arrival's own chain, below its own Seq. Removing it would strand the
//     arrival itself (§2.3 from the arrival's side).
//
// Reading the floor over a wider set than the pass may remove is not a
// conservative error, it is an incoherent one: a user extending their own chain
// sets the minimum with their own base and then clears a gate priced at a
// certificate they are forbidden to take. The pass would find nothing to do and
// the pool would grow past its high-water mark on an arrival that outbid
// nobody.
//
// Deliberately *not* a chain price. A chain's price is the minimum over its
// members, but the member that leaves is the tail, whose own declaration is
// unbounded above that minimum. Gating on the minimum while removing the tail is
// how an arrival declaring 2 came to evict certificates declaring 1,000,000 —
// with no attacker, just ordinary fee bumping. Chain price still decides the
// *order* (see evictionOrder); it does not decide who may be removed.
//
// Deliberately *not* a rank statistic at the low-water cut either, which is what
// the floor was before and is a censorship vector: the cut's price is the
// need-th smallest of however many residents are removable, so as chains grow
// longer and the removable set shrinks toward `need`, the floor climbs toward
// the *dearest* removable declaration — and at or below `need` removable
// residents it is exactly that. One resident declaring high then sets the
// admission price for the entire pool. See makeRoomFor for the measurement and
// docs/adversarial/mempool.md §2.1 for the argument.
func (pool *Pool) evictionCandidates(prices map[types.Address]chain, arrival *types.Certificate) ([]candidate, u256.U256, bool) {
	out := make([]candidate, 0, len(pool.byUnderwriter))
	var floor u256.U256
	for _, e := range pool.byID {
		if !evictable(e, prices) {
			continue // a higher Seq from this signer is pooled; not the tail
		}
		if e.cert.Seq < arrival.Seq && e.cert.UnderwriterID() == arrival.UnderwriterID() {
			continue // the arrival's own chain base; removing it strands the arrival
		}
		if p := e.cert.FeeBid.SeqPriority; len(out) == 0 || p.Lt(floor) {
			floor = p
		}
		out = append(out, candidate{e: e, chainPrice: prices[e.cert.UnderwriterID()].price})
	}
	if len(out) == 0 {
		return nil, u256.U256{}, false
	}
	return out, floor, true
}

// candidate is a resident an arrival may take, carrying its chain's price so the
// sort comparator does not have to look it up. A sort does O(n log n)
// comparisons against a map keyed on a 20-byte address; reading it there cost
// two hashed lookups per comparison, measured at ~13 ms of a 28 ms pass over
// 18,000 certificates.
type candidate struct {
	e          *entry
	chainPrice u256.U256
}

// evictionOrder returns the residents this arrival may take, cheapest chain
// first.
//
// Ranking by chain price rather than by the tail's own price is the other half
// of the floor-pinning answer: a pool that gated on the chain but still ordered
// by the tail would admit the honest arrival and then evict honest residents in
// preference to the flooder's expensively-tipped tails, which is the same
// censorship with an extra step. The chain that is cheapest as a unit is the
// one that leaves, and it leaves from its tail, so a long cheap chain is peeled
// off across successive evictions rather than holed.
//
// **This arrival's** candidates, not the pool's, and the difference is a
// denial-of-service surface rather than a nicety. The three filters below used
// to sit in makeRoomFor's removal loop, so the sort ran over every removable
// resident whether or not the arrival could take any of them. One identity can
// rent the pool's cheapest slot and churn it a drop at a time — each arrival
// clears the floor (its own previous certificate) and takes exactly that one
// certificate, while every other resident outbids it — which made an O(n log n)
// sort over the whole pool triggerable per certificate, under the write lock,
// for the price of one deposit cell. Filtering first makes the sort
// proportional to what the arrival can actually do: on that shape the candidate
// set is 1 rather than 18,000, and the pass costs 8.0 ms instead of 17.2 ms.
//
// What is left is the two O(n) passes over the map (chainPrices, then the
// floor) that every pass has paid all along, refused arrivals included.
// Reducing *that* is the cost of saying no, and is not attempted here.
func evictionOrder(candidates []candidate, arrival *types.Certificate, bump uint64) []*entry {
	beatable := candidates[:0]
	for _, c := range candidates {
		if !beatsByBump(arrival.FeeBid.SeqPriority, c.e.cert.FeeBid.SeqPriority, bump) {
			continue // the invariant: this arrival may not take this certificate
		}
		beatable = append(beatable, c)
	}

	// Worst-paying first, ties broken by the certificate's own priority and
	// then by id, so the order is total and a node is reproducible against its
	// own logs.
	sort.Slice(beatable, func(i, j int) bool {
		if cmp := beatable[i].chainPrice.Cmp(beatable[j].chainPrice); cmp != 0 {
			return cmp < 0
		}
		x, y := beatable[i].e.cert.FeeBid.SeqPriority, beatable[j].e.cert.FeeBid.SeqPriority
		if cmp := x.Cmp(y); cmp != 0 {
			return cmp < 0
		}
		return string(beatable[i].e.id[:]) < string(beatable[j].e.id[:])
	})

	victims := make([]*entry, len(beatable))
	for i := range beatable {
		victims[i] = beatable[i].e
	}
	return victims
}

// priceHeapItem is one admitted certificate's price, as tracked by floorHint.
type priceHeapItem struct {
	price u256.U256
	id    types.Hash
	// underwriter and seq are carried so floorLowerBound can test §2.3
	// evictability against floorHintTailSeq without touching the entry or the
	// pool.
	underwriter types.Address
	seq         uint64
}

// priceHeap is a min-heap of priceHeapItem ordered by price, maintained by
// pushPriceHeap/popPriceHeap/heapifyPriceHeap below. See (*Pool).floorLowerBound
// for what it is for.
//
// Hand-rolled rather than container/heap, in the same spirit as the max-heap
// this file already rolls for IDs() (heapify/siftDown): the shapes read
// almost the same, and one dependency-free idiom for "a slice that is a
// binary heap" is easier to audit than a stdlib one plus a hand-rolled one.
// It also carries no locking of its own — every caller already holds pool.mu.
type priceHeap []priceHeapItem

// pushPriceHeap inserts item and restores the heap invariant by sifting up.
func pushPriceHeap(h *priceHeap, item priceHeapItem) {
	*h = append(*h, item)
	i := len(*h) - 1
	for i > 0 {
		parent := (i - 1) / 2
		if !(*h)[i].price.Lt((*h)[parent].price) {
			break
		}
		(*h)[i], (*h)[parent] = (*h)[parent], (*h)[i]
		i = parent
	}
}

// popPriceHeap removes and returns the minimum-price item.
//
// Precondition: len(*h) > 0. The sole caller (floorHintTop) checks this
// itself before calling, same discipline the id heap's siftDown keeps.
func popPriceHeap(h *priceHeap) priceHeapItem {
	old := *h
	top := old[0]
	last := len(old) - 1
	old[0] = old[last]
	*h = old[:last]
	siftDownPrice(*h, 0)
	return top
}

// heapifyPriceHeap arranges h into heap order in place, bottom-up, in O(n) —
// the same construction heapify uses for the id max-heap.
func heapifyPriceHeap(h priceHeap) {
	for i := len(h)/2 - 1; i >= 0; i-- {
		siftDownPrice(h, i)
	}
}

func siftDownPrice(h priceHeap, i int) {
	for {
		smallest, l, r := i, 2*i+1, 2*i+2
		if l < len(h) && h[l].price.Lt(h[smallest].price) {
			smallest = l
		}
		if r < len(h) && h[r].price.Lt(h[smallest].price) {
			smallest = r
		}
		if smallest == i {
			return
		}
		h[i], h[smallest] = h[smallest], h[i]
		i = smallest
	}
}

// floorHintRebuildSlack bounds how far floorHint may drift from len(byID)
// before it is rebuilt from scratch. See pushFloorHint.
const floorHintRebuildSlack = 64

// pushFloorHint records a newly-admitted certificate's price and, if the heap
// has accumulated enough stale entries, rebuilds it from the pool directly.
//
// Removal never touches floorHint — see floorLowerBound for why that is
// sound — so left alone the heap would grow by one entry per admission for
// the life of the pool, most of which eventually describe certificates that
// have long since left. Rebuilding whenever the heap holds more than double
// the pool's current size (or floorHintRebuildSlack, whichever is larger, so
// a small pool is not rebuilt on every other admission) keeps it at O(n)
// always, and because a rebuild resets the count exactly to len(byID), the
// pool must absorb that many more admissions before the next one is due — the
// same amortised-constant argument that justifies lazy deletion in the first
// place, applied to the heap's size rather than to one lookup.
func (pool *Pool) pushFloorHint(id types.Hash, price u256.U256, underwriter types.Address, seq uint64) {
	// An admission can only ever *raise* an underwriter's highest pooled Seq,
	// so this stays exact between rebuilds without consulting the pool. The
	// certificate just admitted may itself be a chain interior (a lower Seq
	// arriving after a higher one); it is pushed anyway and recognised as
	// unevictable when it surfaces, which keeps this path O(1).
	//
	// Nothing here consults byUnderwriter, deliberately. The one state a
	// fallback clause could defend — an underwriter emptied by a removal and
	// then re-admitted at a *lower* Seq, leaving floorHintTailSeq stale-high —
	// is unreachable at any read: only a removal can create it, a removal sets
	// floorHintStale unconditionally, and the rebuild that flag forces
	// *replaces* the map before floorLowerBound reads it. A clause guarded on
	// `byUnderwriter[underwriter] == 1` was tried and deleted: it was
	// unfalsifiable, and its only live effect was to make the position of Add's
	// counter increment safety-critical — read before that increment it fires
	// on an underwriter's *second* certificate and drags floorHintTailSeq down
	// onto a chain interior, popping the real tail and lifting the bound above
	// the exact floor, which is censorship. No test can pin that ordering,
	// because the test helpers necessarily mirror it. Reading nothing makes the
	// hazard structurally absent instead of merely documented.
	//
	// The *position* of the one non-test call site is load-bearing in the other
	// direction, and this says why: it sits twelve lines after
	// `pool.byID[id] = &entry{...}` in Add, and it has to. The push below can
	// trigger the overgrowth rebuild, and rebuildFloorHint recomputes the heap
	// from byID alone — so a push made before the entry was in byID would be
	// discarded by that very rebuild, leaving the just-admitted price out of
	// the heap and floorLowerBound reporting a bound above the true tail
	// minimum, which admits at a floor nobody paid.
	if seq > pool.floorHintTailSeq[underwriter] {
		pool.floorHintTailSeq[underwriter] = seq
	}
	pushPriceHeap(&pool.floorHint, priceHeapItem{price: price, id: id, underwriter: underwriter, seq: seq})
	if bound := 2 * len(pool.byID); len(pool.floorHint) > bound && len(pool.floorHint) > floorHintRebuildSlack {
		pool.rebuildFloorHint()
	}
}

// rebuildFloorHint recomputes floorHint from the pool, holding only the entries
// that are structurally evictable right now — an underwriter's highest pooled
// Seq (§2.3). A pooled certificate that can never be a candidate is not a price
// anyone can be admitted against.
//
// The interior filter below is a heap-size optimisation, not a soundness
// component, and saying so here is the point of this paragraph: floorLowerBound
// re-tests evictability on every pop, so an interior admitted into the heap
// here would be caught at read time anyway. Mutation testing confirms it —
// deleting the `continue` keeps every floorHint test green, exactly as deleting
// the second clause in pushFloorHint does. It is kept because leaving interiors
// in the heap makes it grow toward len(byID) with nothing to show for it, and
// because a rebuild that already knows the tails should not hand the read path
// work it has the answer to. Do not read it as tested.
func (pool *Pool) rebuildFloorHint() {
	tails := make(map[types.Address]uint64, len(pool.byUnderwriter))
	for _, e := range pool.byID {
		u := e.cert.UnderwriterID()
		if s, seen := tails[u]; !seen || e.cert.Seq > s {
			tails[u] = e.cert.Seq
		}
	}
	fresh := make(priceHeap, 0, len(pool.byID))
	for id, e := range pool.byID {
		u := e.cert.UnderwriterID()
		if e.cert.Seq != tails[u] {
			continue // chain interior: unevictable, so it bounds nothing (untested, see above)
		}
		fresh = append(fresh, priceHeapItem{price: e.cert.FeeBid.SeqPriority, id: id, underwriter: u, seq: e.cert.Seq})
	}
	heapifyPriceHeap(fresh)
	pool.floorHint = fresh
	pool.floorHintTailSeq = tails
	pool.floorHintStale = false
}

// floorLowerBound returns a cheap, sound lower bound on makeRoomFor's exact
// eviction floor, or false if the pool holds nothing to bound it with.
//
// It is no longer what makeRoomFor reads: both room-making paths now call
// floorLowerBoundFor, which starts from this value and may raise it for the one
// arrival being judged. This is kept as the arrival-independent half, because
// everything below is the soundness argument *that* one is built on and the
// unevictable-chain-base tests pin it here. Read floorLowerBoundFor for the
// live path; read this for why either is allowed to refuse anything at all.
//
// It is deliberately *not* the floor itself. The floor (evictionCandidates) is
// the minimum declared SeqPriority over the residents *this arrival* could take
// — a set defined by a per-entry predicate (evictable, plus the arrival's own
// chain base), so answering it exactly means visiting every entry, and there is
// no cheaper exact answer to find. The cost of saying no is not about making
// that walk faster; it is about not performing it for an arrival that was never
// going to clear the floor. What this returns instead is the smallest declared
// SeqPriority among *every* currently pooled certificate, candidate or not:
//
//	floor = min(candidates) >= min(all pooled) = this
//
// because candidates are a subset of the pooled certificates and a subset's
// minimum is never below the whole set's. The value returned here can
// therefore never exceed the true floor.
//
// That subset relation is the entire soundness argument, and it is worth
// noting how little it assumes: it does not care *which* entries the two
// exclusions in evictionCandidates remove, only that they remove rather than
// add. Both exclusions are `continue`s over a loop ranging pool.byID, so the
// property survives any future change to what they filter on — a third
// exclusion, or a change to evictable's chain rule, keeps this bound sound
// without anything here needing to know about it. What would break it is an
// evictionCandidates that could *include* a price no pooled certificate
// declares (a synthesised floor, a value read off params rather than off a
// resident); that is the one refactor this comment exists to forbid.
//
// The second half is monotonicity, and it is what makes "fails the bound" mean
// "fails the floor". beatsByBump is monotonically harder to clear as its
// resident argument grows: `required = resident +| max(1, resident*bump/100)`,
// which is non-decreasing in resident — MulDiv64 is a saturating floor(u*m/d)
// and monotone in u, max(1, .) preserves that, and SatAdd is monotone in both
// arguments — so raising the price you must beat never makes beating it
// easier. Failing against a value no larger than the floor therefore proves
// failing against the floor. An arrival this
// refuses would have been refused by the exact computation, with the same
// error; this can only make that refusal cheaper, never wrong. An arrival that
// *clears* the bound learns nothing and falls through to the exact
// computation, which stays the sole authority on admission and on what may be
// evicted — nothing here ever licenses a removal.
//
// One behavioural difference, deliberate and benign: an arrival can now be
// refused with ErrBelowEvictionFloor where the exact path would have said
// ErrFull, when the pool is non-empty but holds no candidate for this arrival.
// Both are refusals of the same arrival at the same point and neither is
// distinguished by any caller (they exist to tell an operator reading logs
// *why* a pool is refusing). ErrBelowEvictionFloor is if anything the more
// accurate of the two here, since the pool is not full in the hard-cap sense —
// it is at high water and the arrival underbid it.
//
// floorHint is a lazily-cleaned min-heap (pushFloorHint pushes, nothing ever
// pops on removal), so it can hold entries for certificates that have since
// left the pool. Cleaning happens here, on demand: pop the top until one that
// is both live and evictable surfaces, or the heap is empty. Every certificate
// is pushed exactly once over its lifetime and popped here at most once, so the
// amortised cost is O(1) per certificate rather than O(n) per refused arrival,
// which is the whole trade the cheap bound asks for.
//
// The two pops are not alike, and a refactor must not merge them:
//
//   - A *dead* top is never unsound. It is a price that was in the pool and is
//     no longer, so it can only be lower than the live minimum, which is the
//     safe direction; popping it just keeps the bound tight enough to fire.
//   - An *interior* top — live, but not at its underwriter's highest pooled Seq,
//     so §2.3 forbids evicting it — is popped on a judgement that can expire.
//     Removing the certificate above it promotes it to a tail, and the popped
//     price then belongs in the bound again. Popping it with no way back would
//     let the bound rise above the exact floor and refuse arrivals the exact
//     path admits, which is censorship rather than optimisation. The way back
//     is floorHintStale: removeLocked is the only path that deletes from byID,
//     it sets the flag unconditionally, and the flag forces one rebuild here
//     before the next bound is read. Anything that pops on evictability without
//     that flag is unsound — see
//     TestFloorHintSurvivesInterleavedAdmissionAndRemoval, which fails on
//     exactly that mutation.
func (pool *Pool) floorLowerBound() (u256.U256, bool) {
	top, ok := pool.floorHintTop()
	if !ok {
		return u256.U256{}, false
	}
	return top.price, true
}

// floorHintTop cleans the heap and returns its minimum live, structurally
// evictable item — the item whose price floorLowerBound reports. Split out so
// floorLowerBoundFor can look at *which* certificate holds the bound, not only
// at its price.
//
// On a true return floorHint[0] is that item, which is what lets the caller
// read its children as a bound over everything else in the heap.
func (pool *Pool) floorHintTop() (priceHeapItem, bool) {
	// A removal is the only event that can promote a chain interior to a tail,
	// so it is the only event that can invalidate an evictability pop. Rebuild
	// once here rather than on the removal itself: eviction passes and OnBlock
	// already walk the pool, and a stream of refusals between two removals then
	// pays for one rebuild, not one per arrival.
	if pool.floorHintStale {
		pool.rebuildFloorHint()
	}
	for len(pool.floorHint) > 0 {
		top := pool.floorHint[0]
		if _, live := pool.byID[top.id]; live && top.seq == pool.floorHintTailSeq[top.underwriter] {
			return top, true
		}
		popPriceHeap(&pool.floorHint)
	}
	return priceHeapItem{}, false
}

// floorLowerBoundFor is floorLowerBound made arrival-aware, and it is the one
// makeRoomFor and makeByteRoomFor use.
//
// evictionCandidates has *two* exclusions, and only the first is a property of
// the resident alone. The hint was taught the first one — a chain interior is
// unevictable at any price, so it bounds nothing. The second is relative to the
// arrival: an arrival may not take its own chain below its own Seq, because
// that would strand the arrival itself. A single pool-wide value cannot
// represent it, so before this the hint was held at the planter's own cheap
// tail and every arrival the planter underwrote fell through to the two O(n)
// walks and was refused by the exact floor anyway. Perishable and bounded to
// the planter's own traffic, unlike the pool-wide unevictable base — but free
// to replay, because the refusal returns Score 0 and neither dedupe path
// remembers it.
//
// The bound when the heap top *is* the arrival's own excluded chain base is
// structural rather than semantic, and that is the whole reason it can stay
// size-independent. In a binary min-heap heap order makes an ancestor no dearer
// than any of its descendants, so the price at any node is a lower bound over
// that node's whole subtree. Descend from the root through the arrival's own
// excluded certificates *only*, stopping at the first non-excluded item on each
// branch; the minimum over that frontier is a sound lower bound on the exact
// floor.
//
// Soundness. evictionCandidates' floor is a minimum over candidates — pooled
// items that are neither a chain interior nor the arrival's own chain below its
// Seq. Take any such candidate at heap index j and walk the root-to-j path: it
// is excluded nodes, every one of them expanded by the descent, up to the first
// non-excluded node f — which the descent therefore reaches and folds into the
// frontier. f is an ancestor of j (or is j), so price[f] <= price[j] by heap
// order, and the frontier minimum <= price[f] <= that candidate's price. It
// holds for every candidate, so the frontier minimum <= the exact floor. Dead
// or interior items landing on the frontier only lower it further, which is the
// safe direction — the argument never asks what a frontier item *is*, exactly
// as the old single-level descend did not.
//
// Size-independence. The descent expands only nodes that are the arrival's own
// excluded chain base, and floorHintTop has already rebuilt away every dead
// entry (a removal sets floorHintStale, which forces that rebuild), so the heap
// it walks holds only live certificates. One underwriter has at most
// MaxPerUnderwriter of those, so the descent expands at most MaxPerUnderwriter
// nodes and reads at most twice that many children — a policy constant, not a
// function of len(byID). That is the size-independence guarantee the residual
// used to break: a steerable arrival whose underwriter owns floorHint[0..2] is
// now refused in bounded time under pool.mu instead of falling through the two
// O(n) walks walks. BenchmarkRejectedArrivalIsSizeIndependent's residual
// sibling pins it.
//
// The single-level special case this replaces — root excluded, bound taken as
// min(floorHint[1], floorHint[2]) — is exactly what the descent computes when
// the root's two children are both non-excluded, so nothing changes for the
// common self-underwritten arrival. Only the residual, where those
// children are *also* the arrival's own certificates, is now followed further
// down instead of bounding on one of the arrival's own prices.
func (pool *Pool) floorLowerBoundFor(arrival *types.Certificate) (u256.U256, bool) {
	top, ok := pool.floorHintTop()
	if !ok {
		return u256.U256{}, false
	}
	// evictionCandidates' second exclusion, verbatim, answered against a heap
	// item instead of against an entry: priceHeapItem carries the underwriter
	// and Seq precisely so this costs no pool lookup.
	excluded := func(it priceHeapItem) bool {
		return it.seq < arrival.Seq && it.underwriter == arrival.UnderwriterID()
	}
	if !excluded(top) {
		return top.price, true
	}

	// The root is one of the arrival's own excluded chain-base certificates.
	// Descend past every excluded node and bound the floor by the cheapest
	// non-excluded item on the frontier. The worklist only ever holds indices
	// beneath excluded nodes, so it visits O(MaxPerUnderwriter) items — see the
	// size-independence argument above.
	var bound u256.U256
	have := false
	work := []int{0} // the root, known excluded
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		if it := pool.floorHint[i]; !excluded(it) {
			// A frontier item: heap order makes its price a lower bound over its
			// whole subtree, so stop here and fold it in rather than descend.
			if !have || it.price.Lt(bound) {
				bound, have = it.price, true
			}
			continue
		}
		// Excluded: it bounds nothing this arrival can take, so look beneath it.
		if l := 2*i + 1; l < len(pool.floorHint) {
			work = append(work, l)
		}
		if r := 2*i + 2; r < len(pool.floorHint) {
			work = append(work, r)
		}
	}
	// Every item reachable from the root is the arrival's own excluded chain, so
	// there is no candidate to bound with. Reporting none is a deferral, not a
	// refusal: the caller falls through to the exact floor, the sole authority
	// either way.
	if !have {
		return u256.U256{}, false
	}
	return bound, true
}

// beatsByBump reports whether arrival exceeds resident by at least the bump.
//
// The bump is at least one drop, always. `resident * bumpPercent / 100` is
// integer division and it truncates, so at the default 10% every resident
// declaring fewer than ten drops had a bump of exactly **zero** — and `Gte`
// then let an arrival displace a resident at the *same* declared price, for
// free, as many times as it liked. §1 says a zero-priority certificate is
// perfectly valid and costs only its deposit, so the bottom of the range is
// precisely where a flood lives; measured on smallPolicy against residents
// declaring 5, twenty consecutive same-price displacements were accepted, each
// forcing a re-gossip. That is the churn §2.2 exists to price, at zero cost,
// in the range where it is cheapest to mount.
//
// The old code already knew the rule — it special-cased `resident == 0` to
// require a strict increase. That special case is this one at n = 0; applying
// it at every n both fixes the range 1..9 and subsumes the branch.
//
// Saturating arithmetic: the required price for a resident declaring near the
// 256-bit ceiling saturates at the ceiling, so nothing below it can displace
// such a resident — correct, since nothing can outbid it either. At exactly the
// ceiling the saturated requirement is the resident's own price, so an equal bid
// displaces it: the same free churn this function forbids everywhere else,
// surviving where the arithmetic has nowhere left to go. It is unreachable
// through Add — the deposit screen tests SeqGas x SeqMax + ParGas x ParMax, and
// canonical form requires SeqPriority <= SeqMax, so a cell would have to hold
// on the order of 2^256 drops — and it is recorded rather than guarded because
// a guard here would be dead code with no witness.
func beatsByBump(arrival, resident u256.U256, bumpPercent uint64) bool {
	bump := resident.MulDiv64(bumpPercent, 100)
	if bump.IsZero() {
		bump = u256.FromUint64(1)
	}
	return arrival.Gte(resident.SatAdd(bump))
}

func (pool *Pool) countRejected() {
	pool.mu.Lock()
	pool.rejected++
	pool.mu.Unlock()
}

// Candidates returns the pooled certificates in a deterministic order, for a
// builder to select from.
func (pool *Pool) Candidates() []*types.Certificate {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	entries := make([]*entry, 0, len(pool.byID))
	for _, e := range pool.byID {
		entries = append(entries, e)
	}
	// Sorted by id: the pool is a map, and a builder fed in map order would
	// produce a different block on every run from the same inputs. The id is
	// read from the cache rather than recomputed via Certificate.ID, which
	// would marshal and BLAKE3-hash every certificate inside the comparator on
	// every mining attempt — entry.id is already the map's own key, and
	// evictionOrder already reads it this way.
	sort.Slice(entries, func(i, j int) bool {
		return string(entries[i].id[:]) < string(entries[j].id[:])
	})
	out := make([]*types.Certificate, len(entries))
	for i, e := range entries {
		out[i] = e.cert
	}
	return out
}

// IDs returns up to limit pooled certificate ids in deterministic order. A
// negative limit returns them all.
//
// Separate from Candidates rather than a projection of it, because a bounded
// request should do bounded work. Candidates reads the cached id cheaply now
// now, but it still copies and sorts the *whole* pool to answer any
// request, including one asking for ten ids out of thousands — a fair price
// for a miner building one block per target interval, and not a fair price on
// a request handler (see the bounded-selection comment below).
func (pool *Pool) IDs(limit int) []types.Hash {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	if limit < 0 || limit >= len(pool.byID) {
		out := make([]types.Hash, 0, len(pool.byID))
		for id := range pool.byID {
			out = append(out, id)
		}
		sortIDs(out)
		return out
	}
	if limit == 0 {
		return nil
	}

	// Bounded work for a bounded answer. Copying and sorting the whole pool to
	// return ten ids costs the same as returning a thousand: at MaxCertificates
	// that is most of a megabyte allocated and a full sort performed under the
	// read lock, on every request, contending with the relay's Add and the
	// miner's Candidates. The byte budget prices /block and nothing else, so
	// this is the surface's second asymmetric answer and it goes unpriced.
	//
	// A max-heap of exactly `limit` entries keeps the smallest ids in one pass
	// with no allocation beyond the result.
	worst := make([]types.Hash, 0, limit)
	for id := range pool.byID {
		if len(worst) < limit {
			worst = append(worst, id)
			if len(worst) == limit {
				heapify(worst)
			}
			continue
		}
		if less(id, worst[0]) {
			worst[0] = id
			siftDown(worst, 0)
		}
	}
	sortIDs(worst)
	return worst
}

// Ordering is over the raw id bytes, which is the same order Candidates uses
// and is deterministic. It is not a ranking: a caller asking for N gets the N
// lexicographically smallest ids, so a view built from it shows a stable subset
// of the pool rather than a sample of it.
func less(a, b types.Hash) bool { return string(a[:]) < string(b[:]) }

func sortIDs(ids []types.Hash) {
	sort.Slice(ids, func(i, j int) bool { return less(ids[i], ids[j]) })
}

// heapify and siftDown maintain a max-heap, so worst[0] is the largest id kept
// and therefore the first candidate to be displaced by a smaller one.
func heapify(h []types.Hash) {
	for i := len(h)/2 - 1; i >= 0; i-- {
		siftDown(h, i)
	}
}

func siftDown(h []types.Hash, i int) {
	for {
		largest, l, r := i, 2*i+1, 2*i+2
		if l < len(h) && less(h[largest], h[l]) {
			largest = l
		}
		if r < len(h) && less(h[largest], h[r]) {
			largest = r
		}
		if largest == i {
			return
		}
		h[i], h[largest] = h[largest], h[i]
		i = largest
	}
}

// Remove drops certificates by id.
func (pool *Pool) Remove(ids ...types.Hash) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, id := range ids {
		pool.removeLocked(id)
	}
}

func (pool *Pool) removeLocked(id types.Hash) {
	e, ok := pool.byID[id]
	if !ok {
		return
	}
	delete(pool.byID, id)
	u := e.cert.UnderwriterID()
	if pool.byUnderwriter[u] <= 1 {
		delete(pool.byUnderwriter, u)
		delete(pool.byUnderwriterReserve, u)
	} else {
		pool.byUnderwriter[u]--
		pool.byUnderwriterReserve[u] = pool.byUnderwriterReserve[u].SatSub(e.reserve)
	}
	pool.totalBytes -= e.bytes
	// May have promoted a chain interior to a tail, which floorHint's
	// evictability pops assume cannot happen silently.
	pool.floorHintStale = true
}

// OnBlock updates the pool after a block commits: committed certificates leave,
// expired ones leave, and everything else is re-screened against the new state.
//
// Re-screening matters because a deposit that covered at the old tip may not
// cover at the new one — the depositor may have spent it. A pool that skipped
// this would keep handing the miner certificates that will DROP.
func (pool *Pool) OnBlock(b *types.Block, s StateReader, tipHeight uint64) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, c := range b.Certs {
		pool.removeLocked(c.ID())
	}
	pool.rescreenLocked(s, tipHeight)
}

// Rescreen brings the pool into line with a new tip without naming a block.
//
// It is what a node that caught up by *sync* needs. `OnBlock` is per block and
// the sync path has no cheap way to replay hundreds of them — but it does not
// need to. The re-screen below is a function of state, not of blocks: a
// committed certificate is dropped because `s.Seen(id)` is true, which is
// exactly B3's rule, so one pass against the new tip removes everything
// committed anywhere in the range that was synced.
//
// Without it a node that caught up by sync assembled its next block from a pool
// still holding certificates the chain it had just adopted already committed,
// and B3 makes that block invalid — so the node caught up and then could not
// mine. Gossip masked it: a gossiped block goes through OnBlock and clears the
// pool within seconds. A node whose only route home is sync has no such rescue,
// and that is the node this exists for.
func (pool *Pool) Rescreen(s StateReader, tipHeight uint64) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.rescreenLocked(s, tipHeight)
}

// §2.3, third door. The eviction pass truncates chains from the tail and
// Readmit restores them as a prefix, but this sweep answers to neither: a
// certificate that has stopped being admissible has to go wherever in a chain
// it sits, and dropping the middle of a chain strands everything above it.
//
// The four reasons are not alike, and the difference decides the rule:
//
//   - **Already committed.** The certificate was *billed*, which usually means
//     it applied, and then its successor is next in line rather than stranded:
//     truncating there would throw away the chain about to become the pool's
//     most valuable. Not benign in every case, only in the common one — see the
//     residual below.
//   - **TTL passed**, **TTL now beyond TTL_MAX** (which a height-lowering
//     reorg can do), **below the base fee**, **deposit no longer
//     covers.** The
//     certificate never applied and cannot be included as it stands. Nothing
//     above it can ever apply either — the pool would keep offering miners work
//     guaranteed to skip, which is the exact state §2.3 exists to prevent.
//
// Both stranding witnesses are ordinary traffic rather than attacks, because
// they need only a chain whose members declare different ceilings or deadlines
// — a modest bound on a routine payment, a higher one on an urgent follow-up:
//
//	base SeqMax 10 000, tail 5 000 000; the sequential base fee rises to 20 000
//	  -> base dropped, tail pooled and permanently unappliable
//	base TTL 12, tail TTL 30; rescreened at tip 15
//	  -> base dropped, tail pooled and permanently unappliable
//
// So a stranding removal truncates the underwriter's chain above it, cut at the
// lowest vacated Seq that no surviving certificate re-occupies. Both halves of
// that are load-bearing. Duplicate Seq is not stranding — Seq is an ordering key
// rather than a nonce, so a certificate still sitting at a vacated Seq keeps the
// chain above it reachable — but re-occupancy has to be tested per Seq and not
// per underwriter: a chain that loses Seq 0 and Seq 1, and has a second Seq 0
// standing, is still holed at Seq 1, and a whole-underwriter veto would leave
// everything above Seq 1 pooled and unappliable.
//
// RESIDUAL, and it is not closable here. `Seen` means billed, not applied:
// core/fold settles SkippedStale and SkippedOverflow through the same path that
// ends in markSeen, so a base that committed *and skipped* is Seen, its writes
// never happened, and its successor's declared reads will not hold. That
// successor is guaranteed to skip and stays pooled. The pool cannot tell the two
// apart — StateReader carries Get, IsSpent and Seen, and none of them says which
// outcome a certificate had — and truncating on every Seen would throw away the
// successor in the common applied case, which is the worse error. Closing this
// needs the outcome to reach the pool, which is a wider change than §2.3.
func (pool *Pool) rescreenLocked(s StateReader, tipHeight uint64) {
	seqBase := s.Get(types.SeqBaseFeeSlot())
	parBase := s.Get(types.ParBaseFeeSlot())
	next := tipHeight + 1

	doomed := make(map[types.Hash]bool)
	// Every Seq each underwriter loses for a reason that strands what sits above
	// it. All of them, not just the lowest: which one becomes the cut cannot be
	// known until the removals are done, because a surviving duplicate may
	// re-occupy some of them. Committed removals are deliberately absent.
	vacated := make(map[types.Address][]uint64)
	strands := func(e *entry) {
		u := e.cert.UnderwriterID()
		vacated[u] = append(vacated[u], e.cert.Seq)
	}
	for id, e := range pool.byID {
		if e.cert.TTL < next {
			doomed[id] = true
			strands(e)
			continue
		}
		// B2's other half. Add mirrors both bounds of the consensus TTL
		// rule; this pass mirrored only the lower one, because the tip was
		// assumed to move monotonically upward. Fork choice does not promise
		// that — it compares accumulated work and nothing else, so a shorter,
		// heavier branch legitimately LOWERS the tip and a certificate admitted
		// at the old ceiling is suddenly past the new one. With no arm for it
		// no removal reason covered that certificate, and it sat in the pool
		// with no path out. Treated as stranding for the same reason the base
		// fee arm below is: it cannot be included as it stands, so nothing
		// declaring reads on its writes can apply either, and like the base fee
		// the condition may well be transient — a re-gossiped certificate
		// returns through Add, which checks both bounds. Say the cost plainly:
		// that recovery is not self-healing from the local pool, and peers that
		// adopted the same branch dropped the certificate on the same rule, so
		// what comes back depends on a holder that did not lower its tip.
		//
		// Written as the distance, not as the sum, for the reason screen states
		// at length: next+ttl_max wraps at a large ttl_max, and the wrapped
		// ceiling would mark EVERY pooled entry doomed on a tip move -- a reorg
		// emptying the whole pool and stranding it, which is the shape of the
		// stranded certificate rather than its fix. The subtraction is total:
		// the expiry arm at the top of this same loop body has already
		// `continue`d on e.cert.TTL < next. Only comment separates the two --
		// no statement does -- so no path reaches here with e.cert.TTL < next.
		if e.cert.TTL-next > pool.params.TTLMax {
			doomed[id] = true
			strands(e)
			continue
		}
		if _, seen := s.Seen(id); seen {
			doomed[id] = true
			continue
		}
		if e.cert.FeeBid.SeqMax.Lt(seqBase) || e.cert.FeeBid.ParMax.Lt(parBase) {
			doomed[id] = true
			strands(e)
			continue
		}
	}

	// The deposit screen re-checked here must be the same SUM Add enforces,
	// or the amplification the aggregate screen closes at admission
	// comes back on the very next block: a cell that funded one certificate's
	// reservation was never re-checked against everything else it backs. A cell
	// that can no longer cover its surviving pooled certificates sheds from
	// each underwriter's tail first — the same truncation direction eviction
	// already uses (§2.3) — so this pass does not itself hole a chain.
	//
	// It still reports every shed certificate to `strands`, and that call is
	// defence in depth rather than a live requirement — worth saying plainly,
	// in the same spirit as makeRoomFor's note about its own two unfalsifiable
	// guards. The shed walks tail-first and stops the moment the balance
	// covers what is left, so it always removes a *suffix* of what survived
	// the pass above, and a suffix removal cannot hole a chain. Deleting the
	// two `strands` calls in this loop therefore passes the whole suite; no
	// test can falsify them today.
	//
	// They stay because they fail closed against a future change to the shed's
	// *order*, not merely against a wrong cut. Anything that made this loop
	// remove by price, by size, or by anything other than descending Seq would
	// silently start holing chains, and truncateStrandedLocked is the only
	// thing positioned to catch it. The cost when the shed is well-behaved is
	// nil: the cut lands at or above what was already removed, so there is
	// nothing left for it to take.
	byUnderwriter := make(map[types.Address][]*entry)
	for id, e := range pool.byID {
		if doomed[id] {
			continue
		}
		u := e.cert.UnderwriterID()
		byUnderwriter[u] = append(byUnderwriter[u], e)
	}
	for u, entries := range byUnderwriter {
		if s.IsSpent(u) {
			for _, e := range entries {
				doomed[e.id] = true
				strands(e)
			}
			continue
		}
		// Tail (highest Seq) first, ties broken by id so two nodes with the
		// same pool shed the same certificates.
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].cert.Seq != entries[j].cert.Seq {
				return entries[i].cert.Seq > entries[j].cert.Seq
			}
			return string(entries[i].id[:]) < string(entries[j].id[:])
		})
		var sum u256.U256
		for _, e := range entries {
			sum = sum.SatAdd(e.reserve)
		}
		balance := s.Get(entries[0].cert.Deposit.Cell)
		for i := 0; i < len(entries) && balance.Lt(sum); i++ {
			doomed[entries[i].id] = true
			strands(entries[i])
			sum = sum.SatSub(entries[i].reserve)
		}
	}

	// Deterministic eviction order so two nodes with identical pools evict
	// identically — not consensus, but a difference here is a difference in
	// what gets mined, and reproducing a report needs it.
	ids := make([]types.Hash, 0, len(doomed))
	for id := range doomed {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
	for _, id := range ids {
		pool.removeLocked(id)
		pool.evicted++
	}
	pool.truncateStrandedLocked(vacated)
}

// truncateStrandedLocked removes what a rescreen left unappliable: for each
// underwriter, everything above the lowest Seq it vacated for a stranding reason
// and that no surviving certificate re-occupies. Called only from
// rescreenLocked, after its removals.
//
// Re-occupancy is tested per Seq. Testing it per underwriter — "some survivor
// sits at the lowest vacated Seq, so nothing is stranded" — is wrong whenever a
// chain vacates two levels and only the lower one is re-occupied: the higher
// vacancy still holes the chain, and everything above it is left pooled and
// guaranteed to skip. Witness: Seq 0 twice (one dropped, one standing), Seq 1
// dropped, Seq 2 standing. The cut is 1, not 0, and Seq 2 goes.
func (pool *Pool) truncateStrandedLocked(vacated map[types.Address][]uint64) {
	if len(vacated) == 0 {
		return
	}
	// Which of the vacated positions a certificate still stands in, after the
	// sweep's own removals.
	occupied := make(map[types.Address]map[uint64]bool, len(vacated))
	for _, e := range pool.byID {
		u := e.cert.UnderwriterID()
		if _, watched := vacated[u]; !watched {
			continue
		}
		seqs := occupied[u]
		if seqs == nil {
			seqs = make(map[uint64]bool)
			occupied[u] = seqs
		}
		seqs[e.cert.Seq] = true
	}

	cut := make(map[types.Address]uint64, len(vacated))
	for u, seqs := range vacated {
		var lowest uint64
		found := false
		for _, seq := range seqs {
			if occupied[u][seq] {
				continue // a duplicate still carries the chain through this Seq
			}
			if !found || seq < lowest {
				lowest, found = seq, true
			}
		}
		if found {
			cut[u] = lowest
		}
	}

	var stranded []types.Hash
	for id, e := range pool.byID {
		if seq, ok := cut[e.cert.UnderwriterID()]; ok && e.cert.Seq > seq {
			stranded = append(stranded, id)
		}
	}
	sort.Slice(stranded, func(i, j int) bool { return string(stranded[i][:]) < string(stranded[j][:]) })
	for _, id := range stranded {
		pool.removeLocked(id)
		pool.evicted++
	}
}

// Readmit returns certificates from an abandoned branch to the pool. Their TTLs
// may still be live, and under the billing law they may be committed on the new
// branch — once.
//
// §2.3 through the front door. Add gates each certificate individually, and the
// pool is at or above its high-water mark during a reorg, so a readmission is a
// sequence of independent admissions any one of which may be refused or
// immediately evicted. Readmitting a chain member by member therefore holed
// chains: a refused or evicted middle left the members above it pooled and
// guaranteed to skip — the state eviction is careful never to produce, produced
// by admission instead. Nothing at admission enforces Seq contiguity, so
// it has to be enforced here, where the chain is visible as a chain.
//
// Two ways a hole appears, and both are closed below:
//
//   - a member is refused (ErrBelowEvictionFloor, the quota, anything), and a
//     later member of the same chain is admitted above the gap;
//   - a member is admitted and then evicted by a *later* member's own admission
//     pass — it is that chain's tail at that moment, and chain-unit ordering
//     makes a cheap chain the pool's first victim, so this is the common case
//     rather than the exotic one.
//
// So each underwriter's certificates are readmitted in Seq order, and the walk
// stops at the first member that does not end up pooled. What is readmitted is
// always a prefix. Members dropped this way are not lost to the network — they
// are re-gossiped like any other certificate the pool declined.
func (pool *Pool) Readmit(certs []*types.Certificate, s StateReader, tipHeight uint64) {
	byUnderwriter := make(map[types.Address][]*types.Certificate, len(certs))
	order := make([]types.Address, 0, len(certs))
	for _, c := range certs {
		u := c.UnderwriterID()
		if _, seen := byUnderwriter[u]; !seen {
			order = append(order, u)
		}
		byUnderwriter[u] = append(byUnderwriter[u], c)
	}
	// Underwriters in a fixed order, so two nodes readmitting the same branch
	// reach the same pool. The input order is the abandoned branch's, which is
	// deterministic already, but sorting costs nothing here and does not depend
	// on that remaining true.
	sort.Slice(order, func(i, j int) bool { return string(order[i][:]) < string(order[j][:]) })

	for _, u := range order {
		group := byUnderwriter[u]
		sort.Slice(group, func(i, j int) bool {
			if group[i].Seq != group[j].Seq {
				return group[i].Seq < group[j].Seq
			}
			a, b := group[i].ID(), group[j].ID()
			return string(a[:]) < string(b[:])
		})
		var prev types.Hash
		havePrev := false
		for _, c := range group {
			// The predecessor may have been evicted by an admission that happened
			// after it landed — including one of this same chain's members.
			if havePrev && !pool.Has(prev) {
				break
			}
			if err := pool.Add(c, s, tipHeight); err != nil {
				break
			}
			// And again after the fact: this member's own admission runs an
			// eviction pass, which may have taken a member of some *other* chain
			// this walk has not reached yet, or — before makeRoomFor learned to
			// refuse it — one of this chain's. Belt and braces: if the predecessor
			// is gone, so is the reason to keep what sits above it.
			if havePrev && !pool.Has(prev) {
				pool.Remove(c.ID())
				break
			}
			prev, havePrev = c.ID(), true
		}
	}
}

// Stats is the observability surface (M1-G7).
type Stats struct {
	Size         int
	Underwriters int
	Admitted     uint64
	Rejected     uint64
	Evicted      uint64
	SeqGas       uint64
	ParGas       uint64
	Bytes        int
}

// Stats returns a snapshot of the pool.
func (pool *Pool) Stats() Stats {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	st := Stats{
		Size:         len(pool.byID),
		Underwriters: len(pool.byUnderwriter),
		Admitted:     pool.admitted,
		Rejected:     pool.rejected,
		Evicted:      pool.evicted,
	}
	for _, e := range pool.byID {
		st.SeqGas += e.seqGas
		st.ParGas += e.parGas
		st.Bytes += e.bytes
	}
	return st
}

// Has reports whether an id is pooled.
func (pool *Pool) Has(id types.Hash) bool {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	_, ok := pool.byID[id]
	return ok
}

// Get returns a pooled certificate.
func (pool *Pool) Get(id types.Hash) (*types.Certificate, bool) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	e, ok := pool.byID[id]
	if !ok {
		return nil, false
	}
	return e.cert, true
}
