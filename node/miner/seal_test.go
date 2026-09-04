package miner_test

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"zycord/core/crypto/blake2b"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// The sealer went from one goroutine walking nonces to N goroutines striding
// them, which changed two things worth pinning: whichever worker wins, the
// header must satisfy the rule the network checks it against; and a search must
// be abandonable, because against a real work function the attempt budget is
// weeks of work and the tip moves every thirty seconds.

func sealHarness(t *testing.T) *miner.Miner {
	t.Helper()
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatalf("opening a chain: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	clock := p.GenesisTime
	return &miner.Miner{
		Chain:  c,
		Pool:   mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{},
		Payout: [32]byte{0x02, 1, 2, 3},
		Now: func() uint64 {
			clock += p.TargetBlockSeconds
			return clock
		},
	}
}

// TestParallelSealProducesAValidHeader guards the worst shape a miner can have:
// every block it finds rejected by every peer, nothing logged locally, and the
// symptom indistinguishable from being unlucky or unreachable.
func TestParallelSealProducesAValidHeader(t *testing.T) {
	m := sealHarness(t)
	for _, threads := range []int{1, 2, 4, 8} {
		m.Threads = threads
		b, err := m.Assemble()
		if err != nil {
			t.Fatalf("threads=%d: assemble: %v", threads, err)
		}
		if err := m.Seal(b, 1<<20); err != nil {
			t.Fatalf("threads=%d: seal: %v", threads, err)
		}
		if err := pow.CheckWork(m.Engine, b.Header, m.Chain.Params()); err != nil {
			t.Fatalf("threads=%d: the sealed header fails the rule it will be "+
				"judged by: %v", threads, err)
		}
	}
}

// TestSealAbandonsWithoutBurningTheBudget: a predicate consulted only after the
// attempt budget runs out is not a predicate. Measured by making the target
// unreachable and the budget astronomical, so returning promptly is only
// possible if the predicate was actually asked.
func TestSealAbandonsWithoutBurningTheBudget(t *testing.T) {
	m := sealHarness(t)
	m.Threads = 4
	b, err := m.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	b.Header.Target = u256.One // no nonce meets this

	var polled atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- m.SealWhile(b, 1<<62, func() bool { return polled.Add(1) > 2 })
	}()

	select {
	case err := <-done:
		if !errors.Is(err, miner.ErrNoSolution) {
			t.Fatalf("an abandoned search returned %v, want ErrNoSolution", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a search told to abandon did not return: the predicate is " +
			"reached only after the attempt budget, which makes it useless " +
			"against a work function where the budget is weeks of hashing")
	}
	if polled.Load() == 0 {
		t.Fatal("the abandon predicate was never consulted")
	}
}

// TestOneThreadIsReproducible pins the zero value's contract, and the reason is
// not obvious: F13 writes the parent id into state on EVERY block
// (types.PrevParentIDSlot, for §8.1's citations), so two chains mined from
// identical content with different nonces have different state roots from the
// next block onward. Tests that compare independently mined chains depend on
// this, and node/chain's restart-equivalence test failed the moment the default
// became parallel.
func TestOneThreadIsReproducible(t *testing.T) {
	var nonces []uint32
	for run := 0; run < 3; run++ {
		m := sealHarness(t)
		m.Threads = 1
		b, err := m.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Seal(b, 1<<20); err != nil {
			t.Fatal(err)
		}
		nonces = append(nonces, b.Header.PoW.Nonce)
	}
	for i := 1; i < len(nonces); i++ {
		if nonces[i] != nonces[0] {
			t.Fatalf("single-threaded mining is not reproducible: nonces %v", nonces)
		}
	}
}

// TestTheZeroValueIsSingleThreaded states the default in a place that fails
// when somebody changes it to GOMAXPROCS for the obvious reason.
func TestTheZeroValueIsSingleThreaded(t *testing.T) {
	a, b := sealHarness(t), sealHarness(t)
	ba, err := a.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Seal(ba, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(bb, 1<<20); err != nil {
		t.Fatal(err)
	}
	if ba.Header.PoW.Nonce != bb.Header.PoW.Nonce {
		t.Fatalf("the zero value produced different nonces (%d, %d); it must be "+
			"the reproducible one — see Miner.Threads",
			ba.Header.PoW.Nonce, bb.Header.PoW.Nonce)
	}
}

// TestMiningAcrossAKeyBoundary drives the one interaction the unit tests around
// it cannot: the miner, the fold's seed-epoch rule and the key schedule acting
// together while the epoch actually changes.
//
// Devnet re-keys every 64 blocks with an 8-block shift, so the first boundary
// is height 72 and this walks past it. Every block must declare the epoch its
// height implies (the fold refuses otherwise, which is what makes MineOne's
// success meaningful) and must still satisfy the work rule under the key that
// epoch selects.
//
// Runs with pow.Dev, so it costs milliseconds and runs in the ordinary suite.
// The same path under RandomX is exercised by the devnet acceptance run
// recorded in the commit that added it — where a serial dataset rebuild at this
// exact boundary stopped a mining node dead.
func TestMiningAcrossAKeyBoundary(t *testing.T) {
	m := sealHarness(t)
	p := m.Chain.Params()
	boundary := p.RandomXKeyInterval + p.RandomXKeyLag

	var seenEpochs []uint64
	for h := uint64(1); h <= boundary+2; h++ {
		b, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("height %d: %v", h, err)
		}
		if b.Header.Height != h {
			t.Fatalf("expected height %d, mined %d", h, b.Header.Height)
		}
		want := pow.SeedEpochFor(h, p)
		if b.Header.PoW.SeedEpoch != want {
			t.Fatalf("height %d declares epoch %d, the schedule gives %d",
				h, b.Header.PoW.SeedEpoch, want)
		}
		if err := pow.CheckWork(m.Engine, b.Header, p); err != nil {
			t.Fatalf("height %d: sealed header fails the work rule: %v", h, err)
		}
		if len(seenEpochs) == 0 || seenEpochs[len(seenEpochs)-1] != want {
			seenEpochs = append(seenEpochs, want)
		}
	}

	// Anti-vacuity: a run that never left epoch 0 proves only that the rule is
	// satisfiable by the value every unaware implementation writes.
	if len(seenEpochs) < 2 {
		t.Fatalf("mined to height %d without crossing a key boundary; epochs seen: %v",
			boundary+2, seenEpochs)
	}
}

// driftingEngine answers one hash and then changes its mind: the first
// evaluation is the honest digest of whatever it was handed, every later one is
// a fixed value that is not the digest of anything.
//
// It is a caricature, but of a real shape rather than an invented one. The
// wrong-key seal (see ErrSealDoesNotVerify in miner.go) came from a
// RandomX engine that held ONE ~2 GiB dataset, refilled it for whichever key was
// being warmed, and went on serving every key from it — so an engine which had
// just accepted a nonce would reject the very same header a moment later, with
// nobody having passed it anything different. The block that node sealed at the
// transition met the target under neither key, and it was applied, announced
// and built on regardless.
//
// **The shape had to change with the work rule and the reason is worth
// recording.** It used to return a ZERO digest first — below every target — and
// an all-ones digest afterwards. Under the commitment rule the target is
// compared against `blake2b(blob ‖ digest)`, and the commitment of a zero
// digest is a uniform value like any other, so "return zero" no longer means
// "meets any target"; the miner would simply not find a solution and the test
// would fail for a reason unrelated to drift. Delegating the FIRST answer to
// pow.Dev keeps the seal reachable — the miner searches nonces exactly as it
// would against an honest engine and finds one — while every subsequent
// evaluation returns a constant, so the re-check in SealWhile asks about the
// same header and is told something different. That is the drift, and it is now
// caught by the digest-identity half of CheckWork rather than by the target
// half, which is a strictly louder failure: ErrHashMismatch names what is
// wrong, where ErrWorkTooLow would only have said the number was too big.
type driftingEngine struct {
	target u256.U256 // the target the miner is searching against
	solved atomic.Bool
}

func (*driftingEngine) Name() string { return pow.Dev{}.Name() }

func (d *driftingEngine) Hash(key types.Hash, in []byte) types.Hash {
	if d.solved.Load() {
		// After the seal: a fixed value that is not the digest of anything, so
		// the re-check is answered differently from the search.
		var max types.Hash
		for i := range max {
			max[i] = 0xff
		}
		return max
	}
	// During the search: the honest answer, so a nonce is actually found.
	out := pow.Dev{}.Hash(key, in)

	// Flip at the moment this answer WOULD be a solution — not after a fixed
	// number of calls, which is how a count-based version of this type would
	// break the next time the miner's call pattern changed. The engine has now
	// accepted a nonce, and every question asked about that nonce from here on
	// gets a different answer. That is the drift.
	//
	// The predicate is the solver's own, recomputed from the blob because this
	// engine has no header to read: commitment = blake2b(blob ‖ digest),
	// compared little-endian.
	buf := make([]byte, 0, len(in)+32)
	buf = append(buf, in...)
	buf = append(buf, out[:]...)
	if !u256.FromLEBytes(types.Hash(blake2b.Sum256(buf))).Gt(d.target) {
		d.solved.Store(true)
	}
	return out
}

// TestAMinerChecksItsOwnBlockBeforeApplyingIt.
//
// The failure this closes is the worst-shaped one a node has: silent, local,
// and total. Nothing between SealWhile and Chain.Apply used to ask whether the
// sealed header satisfies the rule the rest of the network will judge it by —
// Chain.Apply deliberately does not check work either (see node/chain's
// fork-choice comment) — so a node whose engine and whose rule disagreed
// applied its own invalid blocks, announced them, and built on them. On the
// public testnet that ran for 1112 blocks with `roots_agree: true` in the
// explorer the whole way, and the only symptom anywhere was a stranger's node
// refusing to sync.
//
// Be precise about what this catches, because it is not everything. Try and
// CheckWork both go through Engine.Hash, so an engine that is uniformly wrong
// is uniformly wrong on both sides and passes here; that one is caught by a
// peer, and nothing local can catch it. What this catches is an engine whose
// answer for one key MOVES between the seal and the check — which is exactly
// the block the wrong-key-seal node produced while its dataset was
// mid-rebuild, the first poisoned block of the 1112.
func TestAMinerChecksItsOwnBlockBeforeApplyingIt(t *testing.T) {
	m := sealHarness(t)
	m.Engine = &driftingEngine{target: m.Chain.Params().GenesisTarget}
	m.Threads = 1

	before := m.Chain.Height()
	_, _, err := m.MineOne(1 << 20)
	if !errors.Is(err, miner.ErrSealDoesNotVerify) {
		t.Fatalf("mining with an engine that contradicts itself returned %v, want "+
			"ErrSealDoesNotVerify", err)
	}
	if after := m.Chain.Height(); after != before {
		t.Fatalf("the chain advanced from %d to %d: a block that fails the network's "+
			"own work rule was applied locally, which is how a node poisons its "+
			"chain against every peer without noticing", before, after)
	}
}

// TestTheSelfCheckPassesAnHonestSeal is the anti-vacuity half: a check that
// refused everything would also pass the test above, and would stop the miner
// dead. Driven across a key boundary so the check is exercised against more
// than one epoch's key.
func TestTheSelfCheckPassesAnHonestSeal(t *testing.T) {
	m := sealHarness(t)
	m.Threads = 2
	p := m.Chain.Params()
	for h := uint64(1); h <= p.RandomXKeyInterval+p.RandomXKeyLag+1; h++ {
		if _, _, err := m.MineOne(1 << 20); err != nil {
			t.Fatalf("height %d: an honest seal was refused: %v", h, err)
		}
	}
}

// TestAMinerRejectsItsOwnDivergentTargetBeforeApplying is the target twin of
// TestAMinerChecksItsOwnBlockBeforeApplyingIt, for the one header field the
// target re-derivation pass left behind: every ingress path re-derives the
// declared target, but a block this node produces itself reaches Chain.Apply
// through none of them.
//
// A miner that constructs a wrong target — a bad clamp, a mis-scaled window —
// would otherwise write that fabricated target verbatim into its own state root
// (F2c) and fork itself silently. The construction bug is simulated the only
// honest way it can be: assemble a real block, then move its declared target off
// the value the rule gives, and prove the pre-Apply check re-derives the target
// and refuses the block. Removing the comparison in checkDeclaredTarget makes
// this test fail — that is the mutation guard the re-derivation must survive.
func TestAMinerRejectsItsOwnDivergentTargetBeforeApplying(t *testing.T) {
	m := sealHarness(t)
	m.Threads = 1

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("assembling a block: %v", err)
	}

	// Sanity: the honestly-constructed target is accepted. Without this the test
	// could pass by rejecting everything, exactly the vacuity the seal self-check
	// pairs its two tests to rule out.
	if err := m.CheckDeclaredTarget(b); err != nil {
		t.Fatalf("the honestly-built target was refused: %v", err)
	}

	// Now the self-inflicted bug: one bit off the target the rule re-derives.
	b.Header.Target = b.Header.Target.SatAdd(u256.One)
	if err := m.CheckDeclaredTarget(b); !errors.Is(err, miner.ErrTargetDoesNotVerify) {
		t.Fatalf("a block declaring a target the difficulty rule does not give "+
			"returned %v, want ErrTargetDoesNotVerify", err)
	}
}

// The nonce space narrows to a handful of values for the tests below.
//
// Exhausting it honestly is 2^32 hash evaluations — minutes even against an
// engine that returns a constant, which is not a cost a suite running on every
// commit can carry. Narrowing the space exercises the same branch with the
// same arithmetic; what it does not prove is the production width, and
// core/types' blob tests pin that separately.
const testSpace = 64

// neverEngine answers a digest no target this chain can set will ever accept:
// 0xff in every byte is 2^256-1 read either way round, and a target is a u256,
// so nothing satisfies it. It also counts the calls, which is how the tests
// below tell a walked space from a wrapped one.
type neverEngine struct{ calls atomic.Uint64 }

func (*neverEngine) Name() string { return pow.Dev{}.Name() }

func (e *neverEngine) Hash(types.Hash, []byte) types.Hash {
	e.calls.Add(1)
	var h types.Hash
	for i := range h {
		h[i] = 0xff
	}
	return h
}

// TestExhaustingTheNonceSpaceIsReportedAsItsOwnEvent pins the distinction the
// fresh-template answer rests on: a budget that covered the whole nonce space
// and found nothing is not the same event as a budget that merely ran out.
//
// Without the distinction MineOneWhile has nothing to trigger reassembly on,
// and the only remaining options are wrapping — an unterminating re-test of
// nonces already rejected — or reporting a spent template as though retrying
// the identical bytes might work.
func TestExhaustingTheNonceSpaceIsReportedAsItsOwnEvent(t *testing.T) {
	defer miner.SetNonceSpaceForTest(testSpace)()

	m := sealHarness(t)
	m.Engine = &neverEngine{}

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("assembling: %v", err)
	}

	// A budget short of the space: no solution, but nonces remain.
	err = m.SealWhile(b, testSpace/2, nil)
	if !errors.Is(err, miner.ErrNoSolution) {
		t.Fatalf("a spent budget should report ErrNoSolution, got %v", err)
	}
	if errors.Is(err, miner.ErrNonceSpaceExhausted) {
		t.Fatal("a budget of half the space reported the whole space exhausted; " +
			"the two events are being conflated, and reassembly would fire on " +
			"every unlucky search")
	}

	// A budget covering the space. Reported as exhaustion AND still as
	// ErrNoSolution, so no existing caller stops recognising it.
	err = m.SealWhile(b, testSpace, nil)
	if !errors.Is(err, miner.ErrNonceSpaceExhausted) {
		t.Fatalf("a budget covering the whole nonce space did not report "+
			"exhaustion: %v", err)
	}
	if !errors.Is(err, miner.ErrNoSolution) {
		t.Fatalf("exhaustion stopped being an ErrNoSolution; every caller that "+
			"only needs \"no block this time\" silently changed behaviour: %v", err)
	}
}

// TestSealDoesNotWrapOntoNoncesItAlreadyRejected is the anti-wrap assertion.
//
// The issue this implements says to reassemble "rather than wrap", and wrapping
// is the failure with no symptom: a wrapped counter re-tests nonces already
// rejected, so the miner reports hashrate it is not converting into coverage
// and, against a fixed template, never terminates at all.
//
// Asserted by COUNTING engine calls rather than by observing that the call
// returned, because a wrap that happened to terminate for some other reason
// would pass a liveness check. A space of N nonces means exactly N hashes;
// more than that is a nonce tested twice.
func TestSealDoesNotWrapOntoNoncesItAlreadyRejected(t *testing.T) {
	defer miner.SetNonceSpaceForTest(testSpace)()

	m := sealHarness(t)
	e := &neverEngine{}
	m.Engine = e

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("assembling: %v", err)
	}
	// Deliberately over the space: this is the input a clamp exists for, and
	// the input a wrap would loop on.
	if err := m.SealWhile(b, testSpace*4, nil); !errors.Is(err, miner.ErrNonceSpaceExhausted) {
		t.Fatalf("expected exhaustion, got %v", err)
	}

	if got := e.calls.Load(); got != testSpace {
		t.Fatalf("a budget of %d over a space of %d made %d hash calls; more "+
			"than %d means nonces were re-tested (a wrap), fewer means the "+
			"space was reported walked when it was not",
			testSpace*4, testSpace, got, testSpace)
	}
}

// relentingEngine refuses every nonce until it has been asked a given number of
// times, then accepts everything.
//
// It is how a test places the first solution in the SECOND template: set the
// refusal count to exactly one template's worth of nonces, and a miner that
// gave up after one exhausted space fails while a miner that reassembles
// passes.
type relentingEngine struct {
	refuseFirst uint64
	calls       atomic.Uint64
}

func (*relentingEngine) Name() string { return pow.Dev{}.Name() }

func (e *relentingEngine) Hash(types.Hash, []byte) types.Hash {
	n := e.calls.Add(1)
	var h types.Hash
	if n <= e.refuseFirst {
		for i := range h {
			h[i] = 0xff
		}
	}
	return h
}

// TestExhaustionTakesAFreshTemplateRatherThanWrapping is the acceptance test
// for the policy: on exhaustion, reassemble.
//
// The engine refuses every nonce of the first template's whole space and then
// accepts, so the block that comes back can only have been sealed under a
// template assembled AFTER the first was exhausted. A miner that wrapped would
// spin inside the first template forever; a miner that reported the first
// exhaustion to its caller would return an error instead of a block.
func TestExhaustionTakesAFreshTemplateRatherThanWrapping(t *testing.T) {
	defer miner.SetNonceSpaceForTest(testSpace)()

	m := sealHarness(t)
	e := &relentingEngine{refuseFirst: testSpace}
	m.Engine = e

	b, _, err := m.MineOneWhile(testSpace, nil)
	if err != nil {
		t.Fatalf("a miner that exhausted one template's nonce space should have "+
			"reassembled and sealed under the next one, got: %v", err)
	}
	if b == nil {
		t.Fatal("no block and no error")
	}

	// Anti-vacuity: the first testSpace calls are the first template walked end
	// to end. A total at or below that means the solution came from the FIRST
	// template and reassembly was never exercised — the shape in which this
	// test would pass without the behaviour it names.
	if got := e.calls.Load(); got <= testSpace {
		t.Fatalf("the whole run cost %d hashes against a space of %d, so the "+
			"solution came from the first template and reassembly was never "+
			"reached", got, testSpace)
	}

	// Reassembly must produce a real seal, not merely an exit.
	if err := pow.CheckWork(m.Engine, b.Header, m.Chain.Params()); err != nil {
		t.Fatalf("the block sealed under the fresh template fails the work "+
			"rule: %v", err)
	}
	if b.Header.PoW.ExtraNonce != 0 {
		t.Fatalf("reassembly rolled ExtraNonce to %d; the chosen answer to "+
			"exhaustion is a fresh template, and ExtraNonce stays at zero",
			b.Header.PoW.ExtraNonce)
	}
}

// TestExhaustionIsReportedWhenReassemblyCannotHelp pins the bound on the retry
// loop.
//
// Reassembly is progress only if the template actually changed. Against an
// engine that refuses everything, no number of fresh templates produces a
// block, and the loop must terminate and say so rather than spin — the failure
// that replaces an infinite wrap with an infinite reassemble and looks
// identical from outside.
func TestExhaustionIsReportedWhenReassemblyCannotHelp(t *testing.T) {
	defer miner.SetNonceSpaceForTest(testSpace)()

	m := sealHarness(t)
	e := &neverEngine{}
	m.Engine = e

	_, _, err := m.MineOneWhile(testSpace, nil)
	if !errors.Is(err, miner.ErrNonceSpaceExhausted) {
		t.Fatalf("a miner that cannot seal under any template must report "+
			"exhaustion rather than loop, got: %v", err)
	}

	// Anti-vacuity: it must have tried more than one template, or the bound is
	// being satisfied by never retrying at all.
	if got := e.calls.Load(); got <= testSpace {
		t.Fatalf("gave up after %d hashes, one template or less, so the retry "+
			"never happened and the bound proves nothing", got)
	}
}

// TestBuiltInMiningSetsExtraNonceToZero pins the solo-miner policy of
// docs/ARCHITECTURE.md §12 as an executable claim.
//
// ExtraNonce sits INSIDE the proof-of-work seed preimage (PoWSeed zeroes Nonce
// and only Nonce), so it is not a cosmetic field: every distinct value is a
// distinct seed and therefore a disjoint nonce space. A miner that wrote a
// nonzero one would still produce valid blocks — nothing in consensus
// constrains the field — which is exactly why nothing else in the tree would
// catch the change.
func TestBuiltInMiningSetsExtraNonceToZero(t *testing.T) {
	m := sealHarness(t)

	for h := uint64(1); h <= 8; h++ {
		b, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("height %d: %v", h, err)
		}
		if b.Header.PoW.ExtraNonce != 0 {
			t.Fatalf("height %d mined with ExtraNonce %d; the built-in miner "+
				"mines at zero and shards nothing (ARCHITECTURE §12)",
				h, b.Header.PoW.ExtraNonce)
		}
	}

	// Anti-vacuity, as a measurement rather than a hope: the assertion above is
	// only meaningful if ExtraNonce is a field a seal COULD have moved. Set it
	// by hand, seal, and confirm the sealer leaves it alone — so the zero above
	// is the assembler's decision and not a field the sealer flattens
	// regardless, which would make the assertion true no matter what Assemble
	// wrote.
	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("assembling: %v", err)
	}
	b.Header.PoW.ExtraNonce = 0xDEADBEEF
	if err := m.SealWhile(b, 1<<20, nil); err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if b.Header.PoW.ExtraNonce != 0xDEADBEEF {
		t.Fatalf("the sealer rewrote ExtraNonce to %d, so the zero asserted "+
			"above would be the sealer's doing rather than the assembler's and "+
			"the assertion would prove nothing", b.Header.PoW.ExtraNonce)
	}
}

// TestAnAbandonedSearchIsNotReportedAsExhaustion covers the case where a wide
// budget and an early exit meet.
//
// The budget decides whether the space COULD have been walked; the abandon
// predicate decides whether it WAS. Conflating them tells the caller to
// reassemble and hash again on the strength of a space nobody walked — and the
// two moments a search is abandoned are a shutdown and a lost race, which are
// precisely the moments the miner has been asked to stop. The symptom would be
// a node that keeps hashing through SIGTERM.
func TestAnAbandonedSearchIsNotReportedAsExhaustion(t *testing.T) {
	defer miner.SetNonceSpaceForTest(testSpace)()

	m := sealHarness(t)
	e := &neverEngine{}
	m.Engine = e

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("assembling: %v", err)
	}

	// A budget that covers the whole space, abandoned at the first poll.
	err = m.SealWhile(b, testSpace, func() bool { return true })
	if !errors.Is(err, miner.ErrNoSolution) {
		t.Fatalf("an abandoned search should still report ErrNoSolution, got %v", err)
	}
	if errors.Is(err, miner.ErrNonceSpaceExhausted) {
		t.Fatal("a search abandoned on its first poll reported the nonce space " +
			"exhausted; the caller would reassemble and hash again on a space " +
			"nobody walked, which during a shutdown is a node that will not stop")
	}

	// Anti-vacuity: the abandon must actually have cut the search short. If
	// the workers had walked the space anyway, the assertion above would be
	// about a budget rather than about abandonment, and it would hold for the
	// wrong reason.
	if got := e.calls.Load(); got >= testSpace {
		t.Fatalf("the abandoned search still made %d of %d hash calls, so it "+
			"was not cut short and this test proves nothing about abandonment",
			got, testSpace)
	}
}
