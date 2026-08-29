package miner_test

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

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
	var nonces []uint64
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
// evaluation meets any target, every later one meets none.
//
// It is a caricature, but of a real shape rather than an invented one. The
// wrong-key seal (see ErrSealDoesNotVerify in miner.go) came from a
// RandomX engine that held ONE ~2 GiB dataset, refilled it for whichever key was
// being warmed, and went on serving every key from it — so an engine which had
// just accepted a nonce would reject the very same header a moment later, with
// nobody having passed it anything different. The block that node sealed at the
// transition met the target under neither key, and it was applied, announced
// and built on regardless.
type driftingEngine struct{ answered atomic.Bool }

func (*driftingEngine) Name() string { return pow.Dev{}.Name() }

func (d *driftingEngine) Hash(types.Hash, []byte) types.Hash {
	if !d.answered.Swap(true) {
		return types.Hash{} // zero: below every target the chain can declare
	}
	var max types.Hash
	for i := range max {
		max[i] = 0xff
	}
	return max
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
	m.Engine = &driftingEngine{}
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
