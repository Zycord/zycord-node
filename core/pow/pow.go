// Package pow holds the proof-of-work interface, the development engine, and
// the difficulty rule.
//
// Proof of work is used here as a *distribution mechanism with an expiry date*,
// not as permanent consensus. Proof of stake cannot fair-launch — the initial
// stake has to come from somewhere, and every classical route either
// concentrates the network or identifies its author. So the coin is mined
// first, on the laptop people already own, and the ordering role retires on a
// ramp once stake exists to replace it.
//
// The mainnet engine is RandomX, bound in at M3 through the tree's only cgo
// dependency. Until then Dev stands in: same interface, same header binding,
// trivially cheap so that tests and devnets do not spend CPU proving a point.
package pow

import (
	"errors"
	"sort"

	"zycord/core/crypto"
	"zycord/core/crypto/blake2b"
	"zycord/core/params"
	"zycord/core/ssz"
	"zycord/core/types"
	"zycord/core/u256"
)

// Engine turns a proof-of-work input into the value compared against the
// target. It is the whole substitution surface between the development engine
// and RandomX: nothing else in the tree knows which one is running.
type Engine interface {
	// Name identifies the engine in logs, in the genesis announcement, and in
	// the startup check against Params.PoWEngine — a network declares the
	// function its headers are proved against, and a node whose engine
	// disagrees must refuse to run rather than accept the wrong proof.
	Name() string
	// Hash evaluates the work function over a header's proof-of-work input,
	// keyed for the epoch the header's height belongs to.
	//
	// The key is a parameter rather than engine state on purpose. RandomX is
	// keyed, so an unkeyed Hash could not express it; but an engine that held
	// its own key would make the digest depend on the order calls arrive in,
	// which for a value shared between the miner, the gossip path and the
	// sync path is a data race wearing an interface's clothes. Callers derive
	// it with KeyFor and hand it over.
	Hash(key types.Hash, input []byte) types.Hash
}

// Dev is the development engine: one BLAKE3 pass. It is not, and never will be,
// the mainnet engine — it exists so that a devnet block costs microseconds.
type Dev struct{}

// Name identifies the engine. It is what Params.PoWEngine must say for a
// network this binary is allowed to run.
func (Dev) Name() string { return "dev-blake3" }

// Hash evaluates the development work function.
//
// It mixes the key in, which is not decoration on a stand-in engine: without
// it the key schedule would be exercised by no test that runs without cgo, and
// an unexercised path in the one place both engines share is exactly the shape
// of defect I5 and I6 catalogue. Because Dev is what devnets and the whole
// test suite run, keying it means rotation, cross-network separation and the
// boundary arithmetic are all driven by ordinary use rather than by a test
// somebody has to remember to write.
func (Dev) Hash(key types.Hash, input []byte) types.Hash {
	buf := make([]byte, 0, len(key)+len(input))
	buf = append(buf, key[:]...)
	buf = append(buf, input...)
	return crypto.Sum(crypto.TagPoW, buf)
}

// Errors returned by header checks.
var (
	ErrWorkTooLow    = errors.New("pow: commitment does not meet the target")
	ErrHashMismatch  = errors.New("pow: the header's declared RandomX digest is not the digest of its own blob")
	ErrTargetMissing = errors.New("pow: header declares a zero target")
	ErrTimeTooEarly  = errors.New("pow: header time is at or below the median of recent blocks")
)

// CheckWork reports whether a sealed header satisfies its declared target.
//
// Genesis is exempt: solving block 0 would make it unreproducible without the
// miner's nonce, and a competing genesis is a different network rather than a
// fork.
//
// It remains a TOTAL function of the header's bytes and the parameters — no
// chain, no clock, no ancestry — because the key comes from the height (see
// KeyFor). That is what lets a node price an orphan, score an announcement
// whose parent it has never seen, and cache a verdict by block id.
func CheckWork(e Engine, h types.Header, p *params.Params) error {
	return checkWorkWith(e, h, KeyFor(h.Height, p))
}

// checkWorkWith is CheckWork with the key already derived, so that a nonce
// loop pays for it once rather than once per attempt. Both entry points share
// this body deliberately: a Solve that reimplemented the comparison could
// drift from the rule it is supposed to be satisfying, and the drift would
// show up as a miner producing headers its own network rejects.
//
// **The digest is read little-endian, and that is the consensus rule.** It is
// the single most consequential line in this file, so the reason is written
// here rather than left to the u256 helper it calls.
//
// A digest is not a number anybody encoded: it is 32 opaque bytes out of the
// work function, and which end of it counts as most significant is a
// convention the rule has to *choose*. Everywhere else in this project the
// choice is already made and it is big-endian — a cell value, a target,
// accumulated work are all numbers somebody wrote down, and the wire form of
// each is 32 big-endian bytes. This one place departs from that, on purpose,
// because the digest is the one 256-bit quantity here whose producer is
// outside this tree.
//
// RandomX is a Monero-family work function, and the whole Monero-family
// ecosystem — XMRig, every pool, every proxy, every stratum dialect — reads
// its digest little-endian, comparing the *last* eight bytes as an LE `uint64`
// against a compact target. Reading it big-endian is not a harmlessly
// different convention that a translation layer could bridge: the two read
// **opposite ends** of the digest, and the ends are independent. A share a
// stock miner finds is uniform noise under the other rule, and vice versa, so
// there is no proxy that can sit between a big-endian node and the miners that
// exist. The node would be alone with its own miner, which is the failure the
// distribution mechanism in this package's doc comment cannot survive.
//
// The difficulty of the rule is unchanged by the choice — a digest is uniform,
// so the probability that either interpretation lands at or below a given
// target is the same. What changes is *which* nonces win, and therefore who
// can mine at all.
//
// One consequence is worth recording here because a later component depends on
// it. Under the LE reading, the leading bytes of a 256-bit target — the ones a
// truncation keeps — correspond to the *last* bytes of the digest, which is
// exactly the window XMRig's 64-bit job target compares. A stratum job target
// is therefore a clean truncation of the consensus target,
// `t64 = max(1, floor((target256 + 1) / 2^192))`, and every share found under
// it satisfies the full 256-bit check up to a boundary sliver of width one
// part in 2^64. Under the big-endian reading no such truncation exists, which
// is the practical statement of "no proxy can translate between them".
// docs/ARCHITECTURE.md §12 is normative and states both halves.
func checkWorkWith(e Engine, h types.Header, key types.Hash) error {
	if err := CheckCommitment(h); err != nil {
		return err
	}
	if h.Height == 0 {
		return nil
	}
	// The expensive half, and the half that makes the cheap one sound: the
	// digest the header CLAIMS must be the digest of the header's own blob.
	// Without this, PoWHash is an arbitrary 32 bytes and the commitment proves
	// only that somebody hashed a number, not that they hashed this header.
	if got := e.Hash(key, h.PoWInput()); got != h.PoWHash {
		return ErrHashMismatch
	}
	return nil
}

// Commitment is the value compared against the target: `blake2b(PoWInput ‖
// PoWHash)`, 32 bytes.
//
// **This is not a scheme this project designed, and the details are not
// negotiable.** RandomX v2's `randomx_calculate_commitment` is
// `blake2b-256(input ‖ H)` over the job blob that produced H, and stock XMRig
// computes it for every rx/2 nonce and filters its shares on it — see
// CheckCommitment for why the miner's own variable names say otherwise. The
// function, the operand order and the digest width are all upstream's. What
// this function decides is only which bytes play the role of `input`, and the
// answer is PoWInput: the same 43 bytes the work function was evaluated over,
// which is what the miner passes as `prev_job`.
func Commitment(h types.Header) types.Hash {
	in := h.PoWInput()
	buf := make([]byte, 0, len(in)+len(h.PoWHash))
	buf = append(buf, in...)
	buf = append(buf, h.PoWHash[:]...)
	return types.Hash(blake2b.Sum256(buf))
}

// CheckCommitment is the CHEAP half of the work rule: it tests the header's
// commitment against its target and evaluates no work function at all.
//
// Cost is a BLAKE3 over the header (PoWSeed) plus a BLAKE2b over 75 bytes —
// call it a microsecond, against ~55 ms for the light-mode RandomX verify
// CheckWork also pays. That ratio is the whole reason the header grew 32 bytes,
// and the paths that spend it are the ones an attacker can aim: cited headers,
// flood handling, and any light rejection where the answer is almost always
// "no".
//
// # What it proves, and what it does not
//
// It proves that whoever built this header did the work: producing a commitment
// under the target requires producing the PoWHash that goes into it, and the
// only way to produce a PoWHash that lands anywhere in particular is to run
// RandomX. So a header passing this has had the full expected number of
// evaluations spent on it.
//
// It does NOT prove that PoWHash is the digest of THIS header's blob. A header
// could carry a digest that beats the target and was computed for something
// else entirely. That is what CheckWork's second half is for, and the ordering
// is deliberate: the forgery still costs an attacker a full proof of work to
// construct, so it buys no amplification — it is refused a microsecond later
// than an honest header would be, having cost its author what an honest header
// costs. **A caller that uses only this function is choosing to defer a check,
// not to skip one**, and every such caller in the tree says so at its call
// site.
//
// # The target is compared against the COMMITMENT, and this inverts the rule
//
// Under rx/0 the target was compared against the RandomX digest. Under rx/2 it
// is compared against the commitment, and that is not a choice either: it is
// what stock XMRig does, established from its source rather than from its
// documentation, and the two disagree.
//
// `CpuWorker.cpp` at v6.26.0 computes, per nonce:
//
//	memcpy(m_commitment, m_hash, RANDOMX_HASH_SIZE);
//	randomx_calculate_commitment(prev_job, prev_job_size, m_hash, m_hash);
//
// `randomx_calculate_commitment` writes its output over `m_hash` IN PLACE,
// reading the same buffer as its input. So from that line onward `m_hash` holds
// the commitment and `m_commitment` holds the raw digest — **the two names are
// inverted relative to their contents.** The share filter twelve lines later,
//
//	const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
//	if (value < job.target())
//
// reads `m_hash`, which is the commitment. The Stratum submission inverts them
// again in the same direction: the wire field named `result` carries the
// commitment and the field named `commitment` carries the raw digest.
//
// `Tweak_V2_COMMITMENT` is set to 1 by `RandomX_ConfigurationMoneroV2`'s
// constructor and `RxAlgo::base()` returns that configuration for every rx/2
// job. There is no pool-protocol field, no command-line flag and no
// configuration that yields rx/2 with the commitment off, so this is not a mode
// to detect — it is what rx/2 means to every miner that exists.
//
// A chain that kept comparing the raw digest under rx/2 would therefore be
// evaluating a number no miner filters on. Stock XMRig would discard the nonces
// that win and submit the ones that lose, at a healthy reported hashrate with
// every share refused and no error naming the cause — the same silent,
// total failure mode docs/decisions/xmrig.md exists to prevent, arriving
// through the change meant to be invisible.
//
// # The little-endian rule is unchanged, and still applies
//
// XMRig's comparison reads eight bytes at offset 24 of the 32-byte value as a
// native little-endian uint64. That is the top limb of `le256(value)`, exactly
// as before; what moved is WHICH 32 bytes it reads. So the reading is still
// little-endian, a Stratum 64-bit job target is still the clean truncation
// `t64 = max(1, floor((TARGET + 1) / 2^192))` of the consensus target, and
// every argument in docs/decisions/xmrig.md §4 about target encodability
// survives intact. The commitment is uniform for the same reason the digest is,
// so difficulty is unaffected.
//
// Genesis is exempt for the same reason CheckWork exempts it.
func CheckCommitment(h types.Header) error {
	if h.Height == 0 {
		return nil
	}
	if h.Target.IsZero() {
		return ErrTargetMissing
	}
	if u256.FromLEBytes(Commitment(h)).Gt(h.Target) {
		return ErrWorkTooLow
	}
	return nil
}

// A Solver holds everything about a candidate block that does not change as a
// miner iterates nonces: the engine, the key its height implies, the
// proof-of-work seed, and the target.
//
// It exists because the nonce loop is the one place in this codebase where
// recomputing something cheap is expensive. Header.PoWSeed's own comment says
// what it is for — "so that a miner can hash the header once per candidate
// block instead of once per attempt" — and Solve then ignored it, calling
// PoWInput per nonce and paying a full SSZ marshal and a BLAKE3 pass every
// time. Against pow.Dev, which is one BLAKE3 pass, that doubled the cost and
// nobody noticed. Against RandomX it would be invisible for a different
// reason: a rounding error beside a memory-hard evaluation. It is hoisted here
// because it should have been hoisted from the start, not because a benchmark
// demanded it.
//
// Try and CheckWork share no code, which is a hazard, so they share a test
// instead: TestTheSolverAgreesWithCheckWork drives random nonces through both.
// A miner whose solver disagreed with the rule would produce headers its own
// network rejects.
type Solver struct {
	engine Engine
	key    types.Hash
	target u256.U256
	// input is the candidate header's own blob, as types.Header.PoWInput
	// returns it — not a copy of that layout reproduced here. Try overwrites
	// the four nonce bytes at types.PoWInputNonceOffset and nothing else, so
	// every other byte is the verifier's, byte for byte, and the encoding
	// rules have exactly one implementation for both to share.
	//
	// It is built from the same named offsets the rule uses rather than from
	// "the last four bytes", because the nonce being last is an accident of
	// this layout and not a property of it. A future reserved byte appended
	// after the nonce would leave a positional expression here silently
	// hashing the wrong bytes, and the failure would look like a miner that
	// mysteriously never finds a block its own node accepts.
	input []byte
}

// A HotKeyEngine holds a per-key resource that only a miner can justify
// building, and has to be told which key should have it.
//
// One engine needs this and it is RandomX: its ~2 GiB dataset makes hashing
// roughly an order of magnitude faster, there is only ever one of them, and it
// can hold one key's data at a time. Every other caller in the tree — the
// gossip path, the sync driver, a work cache — asks about a given key once and
// is served correctly without it. A miner asks millions of times about one
// key, which is the only thing that pays for the fill.
//
// It is an OPTIONAL interface rather than a widening of Engine. A work
// function is a total function of (key, input); which of its internal
// representations an implementation keeps warm is not a consensus fact and
// must never be one, and an engine that ignores this hint computes exactly the
// same digests, more slowly. Dev does ignore it.
type HotKeyEngine interface {
	Engine
	// MineOn asks the engine to hold this key in its fast representation. It
	// is called once per candidate block, not once per attempt, and an
	// implementation is expected to make a repeat of the current key free.
	MineOn(key types.Hash)
}

// NewSolver prepares a solver for a sealed-but-unsolved header.
//
// Constructing a Solver is the moment the tree declares "I am about to hash
// this one key several million times", so it is also where a HotKeyEngine is
// told. Doing it here rather than in node/miner covers Solve and every future
// mining path for free — and, more to the point, means no caller has to know
// that the engine has a fast path at all, which is how the
// prefetch/mining-key collision stayed invisible: the miner and the rule both
// passed the correct key, and the engine had quietly repointed the dataset
// under both of them.
func NewSolver(e Engine, h types.Header, p *params.Params) Solver {
	key := KeyFor(h.Height, p)
	if hot, ok := e.(HotKeyEngine); ok {
		hot.MineOn(key)
	}
	// The buffer is the header's own blob, built by the one function that
	// knows the layout. It used to be assembled here from PoWSeed and the
	// blob constants, which is the same bytes by a second route — and a
	// second route is exactly how a miner comes to hash something its own
	// verifier does not. The encoding rules (the seed at 0, the seven
	// reserved zeroes at 32, the little-endian nonce at 39) then had two
	// implementations, and only one of them was reachable from a test that
	// reads a header.
	//
	// Try overwrites the nonce field and nothing else, so whatever nonce the
	// header arrived with is irrelevant; what matters is that every byte
	// outside that field comes from PoWInput and therefore cannot drift from
	// what CheckWork will rebuild.
	in := h.PoWInput()
	return Solver{engine: e, key: key, target: h.Target, input: in}
}

// Try reports whether this nonce satisfies the target.
//
// It is NOT safe for concurrent use — it writes into its own input buffer — so
// a parallel miner takes one Solver per worker. That is deliberate: the
// alternative is allocating a buffer per attempt, in the loop this type exists
// to keep tight.
// It takes a uint32 because the nonce IS 32 bits (types.PoWSeal). A uint64
// parameter would have compiled unchanged when the seal narrowed and silently
// truncated, so that a miner searching past 2^32 would have re-tested nonces
// it had already rejected and reported hashrate it was not converting into
// coverage. Making the width a compile error was the point.
func (s *Solver) Try(nonce uint32) bool {
	_, ok := s.TryHash(nonce)
	return ok
}

// TryHash is Try, additionally returning the digest it computed.
//
// It exists because the winning digest is now a HEADER FIELD: a caller that
// found a nonce has to write types.Header.PoWHash, and recomputing the digest
// to obtain it would pay a second full RandomX evaluation for a value the
// solver just held. Worse than slow, it would be a second route to the same
// number — the class of duplication NewSolver's comment describes as "exactly
// how a miner comes to hash something its own verifier does not".
//
// Try remains for callers that only want the verdict, and is this function.
func (s *Solver) TryHash(nonce uint32) (types.Hash, bool) {
	copy(s.input[types.PoWInputNonceOffset:], ssz.Uint32(nonce))
	digest := s.engine.Hash(s.key, s.input)

	// The commitment, formed exactly as pow.Commitment forms it and as
	// stock XMRig's randomx_calculate_commitment forms it: BLAKE2b over the
	// blob that produced the digest, then the digest.
	//
	// It is assembled here from s.input rather than by calling Commitment(h),
	// because the solver has no header — that is the whole reason Solver
	// exists — and building one per attempt would pay a full SSZ marshal and a
	// BLAKE3 pass inside the nonce loop. The duplication is real and it is the
	// hazard TestTheSolverAgreesWithCheckWork covers, now over both halves.
	buf := make([]byte, 0, len(s.input)+len(digest))
	buf = append(buf, s.input...)
	buf = append(buf, digest[:]...)
	commitment := types.Hash(blake2b.Sum256(buf))

	// FromLEBytes, not FromBytes, and for the reason CheckCommitment gives at
	// length. A Try that read the value the other way round would find nonces
	// the rule refuses — a miner rejected by its own network — and every test
	// in the tree that mines a block would still pass, because they all mine
	// through this function.
	return digest, !u256.FromLEBytes(commitment).Gt(s.target)
}

// Clone returns an independent Solver over the same candidate, for one more
// worker.
func (s *Solver) Clone() Solver {
	in := make([]byte, len(s.input))
	copy(in, s.input)
	return Solver{engine: s.engine, key: s.key, target: s.target, input: in}
}

// Solve iterates nonces until the header meets its target, or gives up after
// limit attempts. It exists for tests and single-threaded devnets; a real miner
// parallelises, which is node/miner.
func Solve(e Engine, h *types.Header, p *params.Params, limit uint64) bool {
	if h.Height == 0 || h.Target.IsZero() {
		// Height 0 is exempt from the work rule, so there is nothing to solve
		// and every nonce would "pass"; a zero target is malformed rather than
		// impossible. CheckWork answers both, and a solver that disagreed with
		// it here would hand back a header CheckWork then refuses.
		return CheckWork(e, *h, p) == nil
	}
	s := NewSolver(e, *h, p)
	// The nonce space is 2^32 wide, so a limit above it asks for attempts
	// there is no nonce to make. Clamping rather than wrapping keeps a caller
	// that passes a large sentinel — several tests pass one — searching the
	// whole space exactly once instead of looping forever over the low nonces.
	if limit > nonceSpace {
		limit = nonceSpace
	}
	for i := uint64(0); i < limit; i++ {
		if digest, ok := s.TryHash(uint32(i)); ok {
			h.PoW.Nonce = uint32(i)
			// The digest goes into the header, because the verifier compares
			// the commitment and cannot form one without it. Written from the
			// value the solver just computed rather than re-derived: see
			// TryHash.
			h.PoWHash = digest
			return true
		}
	}
	return false
}

// nonceSpace is how many nonces exist for one (template, ExtraNonce) pair.
// Exhausting it is not a failure a solo miner can reach at any realistic
// hashrate inside a 30-second interval; a pool that could would shard by
// ExtraNonce instead (types.PoWSeal).
const nonceSpace = 1 << 32

// CheckMedianTime enforces the lower time bound: a header must be strictly
// later than the median of the last MEDIAN_TIME_BLOCKS headers.
//
// There is deliberately no upper bound here. A block dated beyond the
// future-time limit is *withheld* — queued and re-evaluated as the local clock
// advances — never rejected (R1-H2). Making validity depend on each node's
// wall clock means that at the boundary half the network accepts a block and
// half rejects it, which is a view fork an attacker can manufacture at will.
func CheckMedianTime(h types.Header, recent []types.Header, p *params.Params) error {
	if h.Height == 0 || len(recent) == 0 {
		return nil
	}
	if got := MedianTime(recent, p); h.Time <= got {
		return ErrTimeTooEarly
	}
	return nil
}

// MedianTime returns the median timestamp of the most recent headers.
func MedianTime(recent []types.Header, p *params.Params) uint64 {
	n := p.MedianTimeBlocks
	if len(recent) < n {
		n = len(recent)
	}
	window := recent[len(recent)-n:]
	times := make([]uint64, len(window))
	for i, h := range window {
		times[i] = h.Time
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times[len(times)/2]
}

// IsTooFarAhead reports whether a header should be withheld rather than judged.
// The caller supplies its own clock reading; consensus never does.
func IsTooFarAhead(h types.Header, now uint64, p *params.Params) bool {
	return h.Time > now+p.FutureTimeLimitSeconds
}

// SeedEpochFor returns the proof-of-work key epoch a header at this height
// belongs to.
//
// The schedule is the one ARCHITECTURE §12 fixes: the work function re-keys
// every RandomXKeyInterval blocks, with RandomXKeyLag blocks of slack shifting
// the boundary forward so the key a height needs was settled long before that
// height could be mined. At the mainnet values the key changes at heights
// congruent to 64 mod 2048, and epoch 0 covers everything below the first
// boundary — including genesis, which carries no proof of work at all.
//
// It is arithmetic over the height and nothing else: no clock, no chain, no
// engine, no state. Validate pins RandomXKeyLag < RandomXKeyInterval, without
// which the expression below stops shifting the boundary and starts skipping
// epochs, and the schedule would no longer re-key once per interval.
//
// The guard names the first boundary because that is what it means, but be
// precise about what it is load-bearing *for*: below the boundary the division
// already yields zero on its own, so the guard's real job is the one case the
// division cannot survive — a height below RandomXKeyLag, where the
// subtraction underflows a uint64 into a colossal epoch. Mutation-checked
// both ways: narrowing the comparison to the interval alone passes every test
// in keyschedule_test.go, because Validate has already pinned the lag below
// the interval and the two forms are then equivalent; removing it fails.
// Anyone tempted to simplify this to the minimal form should keep the
// comparison against a value at least as large as the lag.
//
// The guard is written in two steps rather than as one sum because the sum is
// the one arithmetic in this function that can itself overflow, and a guard
// that wraps stops guarding exactly where it is needed: with
// RandomXKeyInterval near the top of uint64, RandomXKeyInterval+RandomXKeyLag
// wrapped to a small value, no height compared below it, and genesis got the
// colossal epoch this guard exists to prevent. Params.Validate now refuses
// that pair outright, so the two guards hold independently — but this
// function states the property about its own arithmetic and does not borrow it
// from its caller's validator, because it is the one that cannot survive
// being wrong.
func SeedEpochFor(height uint64, p *params.Params) uint64 {
	if height < p.RandomXKeyLag || height-p.RandomXKeyLag < p.RandomXKeyInterval {
		return 0
	}
	return (height - p.RandomXKeyLag) / p.RandomXKeyInterval
}

// KeyFor returns the key the work engine is keyed from at this height.
//
// **The key is derived from the height and the chain id, never from a key
// block's hash.** That is a deliberate departure from upstream RandomX's own
// schedule and it is the one place this package parts company with it, so the
// trade is written here rather than left to be rediscovered. The full entry is
// ARCHITECTURE §21.
//
// What it buys, and it is the whole reason: CheckWork stays a **total**
// function of a header's bytes. Under a key-block hash, the key is a fact
// about a chain, so a header whose ancestry this node does not hold has no
// checkable proof of work at all — and orphan admission, announcement scoring,
// and a work cache keyed by block id all rest on being able to check one.
// So does whitepaper §3's claim that any machine can verify statelessly. It
// also removes a grinding vector upstream's schedule admits, where the miner
// *of* a key block can grind its own hash to influence the next epoch's key.
//
// What it costs: every key of every epoch is known from genesis, which breaks
// the key-unpredictability premise upstream RandomX assumes. Dataset
// precomputation is **not** the concern — it is symmetric, honest miners
// precompute the next epoch equally, and it improves liveness at a boundary
// rather than harming it. The concern is long-horizon offline specialisation:
// part of RandomX's ASIC-resistance argument is that a chip or a
// superoptimiser cannot prepare for future keys. The per-key gain is small in
// the literature, because the generated programs depend on the key *and* the
// nonce, but it is exactly the kind of assumption upstream does not guarantee,
// because upstream assumes an unpredictable key.
//
// Why that is acceptable here, and when it stops being: proof of work in this
// design is a distribution mechanism with an expiry date rather than permanent
// consensus (see this package's doc comment). **The risk grows with the length
// of the proof-of-work to proof-of-stake ramp**, so lengthening the ramp
// reopens this decision. The reversal trigger is evidence of specialised
// hardware, not a calendar review.
//
// The chain id is in the preimage so that work done on one network is worth
// nothing on another even when the two parameter sets are otherwise mirrored —
// which is exactly the configuration a public testnet is meant to run in.
func KeyFor(height uint64, p *params.Params) types.Hash {
	preimage := make([]byte, 0, 16)
	preimage = append(preimage, ssz.Uint64(p.ChainID)...)
	preimage = append(preimage, ssz.Uint64(SeedEpochFor(height, p))...)
	return crypto.Sum(crypto.TagPoWKey, preimage)
}

// NextTarget computes the difficulty target for the block after the given
// headers, using a linearly weighted moving average.
//
// LWMA rather than a Bitcoin-style retarget: a 2016-block window is a death
// trap for a young chain under hashrate tourism — a burst arrives, blocks come
// in seconds, the burst leaves, and the chain freezes for weeks at a difficulty
// nobody can meet. LWMA responds within about an hour, and the per-sample
// clamp bounds what timestamp manipulation can buy on any single block.
//
// Targets are inverse to difficulty: a larger target is easier. A solve time
// above the goal therefore raises the target — never above MaxTarget, which is
// the absolute ceiling the relative clamp cannot supply (F-PARAM-1).
//
// The relative clamp below is applied once per block, against the previous
// block's target — not once per DifficultyWindow, however the phrase reads.
// A sliding LWMA has no natural "per window" moment to anchor a second clamp
// to (there is no periodic retarget boundary the way Bitcoin's 2016-block
// rule has one), and every established LWMA-family implementation bounds
// timestamp manipulation with a per-sample solve-time clamp alone, not a
// second clamp layered on top comparing against a value N blocks back — see
// the comment on the per-sample clamp below. docs/ARCHITECTURE.md §12 is
// normative here and now says exactly this.
func NextTarget(recent []types.Header, p *params.Params) u256.U256 {
	n := int(p.DifficultyWindow)
	if len(recent) < 2 {
		return p.GenesisTarget
	}
	if len(recent) < n+1 {
		n = len(recent) - 1
	}
	window := recent[len(recent)-(n+1):]

	// Weighted sum of solve times, with recent blocks weighted most heavily.
	//
	// Each solve time is a *signed* quantity, clamped symmetrically to
	// ±maxSolve = ±(goal × DifficultyClampFactor), so that one absurd
	// timestamp cannot swing the window in either direction.
	//
	// It must be signed. There is no consensus rule that Header.Time exceeds
	// its parent's — the only lower bound is CheckMedianTime, the median of
	// the last MedianTimeBlocks headers, which a healthy chain keeps several
	// blocks behind the parent. A miner may therefore legally date its own
	// block earlier than its parent: that block's own interval goes negative,
	// and the following (honest) block's interval is inflated by exactly the
	// same amount, since it measures from the backdated timestamp forward to
	// real wall-clock time. Flooring the negative interval at zero — as this
	// rule used to — keeps the inflated positive donation but discards the
	// compensating charge, which makes backdating strictly profitable at any
	// weight and, past p ≈ goal/maxSolve of blocks manipulated, gives the
	// controller no fixed point at all: the measured average can never be
	// brought back down to the goal by any real block-production rate, so
	// the target walks monotonically toward MaxTarget (F-PARAM-3). The mirror
	// attack — dating a block into the future rather than into the past —
	// runs the same mechanism in the same direction for the same reason,
	// independently of whether the future side is externally bounded
	// the interior floor-at-zero is what breaks, not the input.
	//
	// Signing the accumulator restores the cancellation: a maximally backdated
	// block contributes -maxSolve to its own interval and the clamp on the next
	// interval still caps at +maxSolve, so the pair's net contribution is
	// bounded and independent of the manipulated share instead of growing with
	// it — a fixed point exists for every p < 1 (re-derived in
	// core/pow/pow_test.go and in the PR that introduced this comment). This is
	// also the conclusion every LWMA reference implementation surveyed reaches
	// independently: zawy12's difficulty-algorithms repository documents the
	// same zero-floor exploit by name ("if ST<0 then ST=0 ... allows unlimited
	// block production") and its real-world instance (the Graft Network 2018
	// incident, reported in the same thread), and recommends signed accumulation
	// with a symmetric clamp instead.
	goal := p.TargetBlockSeconds
	maxSolve := goal * p.DifficultyClampFactor
	var weighted int64
	var weights uint64
	for i := 1; i < len(window); i++ {
		var solve int64
		if window[i].Time >= window[i-1].Time {
			d := window[i].Time - window[i-1].Time
			if d > maxSolve {
				d = maxSolve
			}
			solve = int64(d)
		} else {
			// Subtract in the order that cannot underflow a uint64, then
			// negate — window[i].Time may be an attacker's declared value
			// anywhere in [0, 2^64-1], so this must never widen the raw
			// (unclamped) uint64 gap into an int64 before it is bounded.
			d := window[i-1].Time - window[i].Time
			if d > maxSolve {
				d = maxSolve
			}
			solve = -int64(d)
		}
		w := uint64(i)
		weighted += solve * int64(w)
		weights += w
	}
	if weights == 0 {
		return window[len(window)-1].Target
	}

	// target_next = mean_window_target * average_solve_time / goal.
	//
	// The base is the window's *average* declared target, not the last block's
	// target alone. That distinction is what makes this loop stable, and
	// the reason is a loop-gain argument, not a bookkeeping preference.
	//
	// Read NextTarget as a feedback controller whose state is log(target) and
	// whose step is log(next) = log(base) + log(avg_solve/goal). The feedback
	// is delayed: a block's solve time depends on the target that was in force
	// when it was mined, so the window's measurements describe targets from up
	// to DifficultyWindow blocks ago, and the correction they induce lands on
	// today's target.
	//
	// Normalising against `last` puts the full correction on top of the
	// previous *output of this same rule*, so corrections compound instead of
	// being shared out. Linearising that recurrence in log-space (window 90,
	// weights 1..90) puts its dominant pole at |z| ≈ 0.9993. That is inside
	// the unit circle — the loop is *stable* in the strict sense, and an
	// impulse does decay — but only barely, and "barely" is the whole problem:
	// a pole that close to 1 has a memory of roughly 1/(1-|z|) ≈ 1,500 blocks,
	// so the loop integrates solve-time noise almost without forgetting it.
	// Proof of work's solve times are exponentially distributed, which is a
	// great deal of noise, and the result is not a settling controller but a
	// random walk. Measured on this rule with the absolute ceiling lifted so
	// it cannot truncate the distribution, the spread of log2(target/genesis)
	// is several bits wide and does not converge with the seed — 3.5, 4.5 and
	// 6.4 bits on three seeds of 30,000 blocks — which is the signature of a
	// walk rather than of a distribution with a settled variance. Mainnet has
	// 12 bits of headroom between GENESIS_TARGET (2^238) and MAX_TARGET
	// (2^250), so a walk that wide crosses it, and does so within a few
	// hundred to a couple of thousand blocks: exactly what a fully honest
	// chain does, every timestamp truthful and hashrate constant, no attacker
	// present at all (core/pow/honest_chain_poisson_test.go).
	//
	// Averaging the window's targets spreads each correction over the whole
	// window instead, which moves the dominant pole to |z| ≈ 0.9785: a memory
	// of ~47 blocks rather than ~1,500. The same measurement then gives a
	// steady-state spread of 0.15 bits that is stable to two decimal places
	// across seeds — a real stationary distribution rather than a walk.
	// Disturbances decay on the timescale of the window itself, which is the
	// timescale the rule is designed around.
	//
	// Note precisely what is *not* claimed. This is still a feedback loop —
	// the window's targets are themselves prior outputs of this rule — so it
	// is a stable IIR loop and not an FIR filter, and its DC gain is not zero.
	// It must not be zero: a rule with no DC gain could never track a
	// sustained hashrate change, which is the one thing a difficulty rule
	// exists to do. It tracks a 10x hashrate step in either direction and
	// holds the mean solve time at the goal. What it no longer does is
	// amplify its own noise. This is canonical LWMA (zawy12), and damping this
	// walk is the whole reason the canonical form averages.
	//
	// mean is computed by dividing each window target by the window count and
	// summing the quotients — never by summing first and dividing after.
	// Summing first overflows u256 for realistic window sizes: DifficultyWindow
	// targets near MaxTarget sum to a value far larger than a 256-bit register
	// can hold, whereas dividing each term first keeps every partial sum in
	// range. (SatAdd guards the accumulation as defense in depth, though the
	// per-term division means it cannot actually be reached.)
	//
	// Dividing first would normally truncate away up to count-1 units, which
	// is negligible in magnitude (~10^-71 relative on a 2^248 target) but is
	// still a needless asymmetry: it would move every existing golden vector
	// by a few units and make a uniform window — every target equal — return
	// something other than that exact target, which is the one case the rule
	// most obviously ought to be exact about. So the remainders are carried:
	// each Div64 also yields its remainder, those are summed in a uint64 and
	// their own quotient folded back in. The remainder sum cannot overflow —
	// each term is < count, there are count terms, so the sum is < count^2
	// (8,190 for the mainnet window of 91) — and the result is the exact
	// floor of the true average whenever that fits, so a uniform window
	// returns its target unchanged and the pre-existing vectors keep their
	// values.
	mean := u256.Zero
	windowCount := uint64(len(window))
	var remainders uint64
	for _, h := range window {
		share, rem := h.Target.Div64(windowCount)
		mean = mean.SatAdd(share)
		remainders += rem
	}
	mean = mean.SatAdd(u256.FromUint64(remainders / windowCount))

	// A non-positive weighted sum has no sensible ratio — the measured average
	// solve time is at or below zero, i.e. the window claims to have gone
	// backwards on the whole — so it is treated the way the original
	// zero-floored rule treated an all-zero sum: lifted to the smallest
	// positive numerator, which drives next well below the mean and lets the
	// lower relative clamp below supply the actual floor.
	last := window[len(window)-1].Target
	avgDenominator := weights * goal
	var avgNumerator uint64
	if weighted <= 0 {
		avgNumerator = 1
	} else {
		avgNumerator = uint64(weighted)
	}
	next := mean.MulDiv64(avgNumerator, avgDenominator)

	// The relative clamp, applied per block against the previous block's target.
	// Before the base became the window average, this clamp's upper half was
	// provably dead code: the ratio was applied to `last` itself — the same
	// value `upper` derives from — so the ratio's own DifficultyClampFactor
	// ceiling made next ≤ upper unconditionally (R2-POW-5). That proof no longer
	// holds now that the ratio is applied to `mean`: mean and last are different
	// quantities that can diverge — a window whose earlier, about-to-age-out
	// headers declare much larger targets than the current last block pulls mean
	// above last — so a neutral-or-rising ratio applied to an inflated mean can
	// exceed last×DifficultyClampFactor even though the ratio itself never does.
	// The upper half is therefore live again, which is exactly the resolution
	// that finding predicted once normalisation stopped being a no-op against
	// its own base (TestUpperPerBlockClampIsReachable drives it). The lower half
	// was never dead: it is what turns the non-positive-sum case above, and any
	// weighted average near zero, into the actual floor on how much a single
	// block may harden.
	upper := last.MulDiv64(p.DifficultyClampFactor, 1)
	lower, _ := last.Div64(p.DifficultyClampFactor)
	if next.Gt(upper) {
		next = upper
	}
	if next.Lt(lower) {
		next = lower
	}
	// The absolute bounds, applied last and symmetrically: MaxTarget above,
	// one below. The relative clamp bounds the step and not the destination —
	// it is a ratio against a value that is itself free to move — so a
	// sustained upward push multiplies the target by the clamp factor every
	// block until 256-bit saturation delivers it to 2^256-1. There CheckWork
	// accepts every hash and BlockWork returns one for every header, so
	// accumulated work is a block count and fork choice no longer measures
	// work. The floor is the mirror image: at zero no hash can ever satisfy
	// the target and the chain stops. Neither end is recoverable after
	// genesis, so neither end is left to the relative clamp (F-PARAM-1).
	if next.Gt(p.MaxTarget) {
		next = p.MaxTarget
	}
	if next.IsZero() {
		next = u256.One
	}
	return next
}
