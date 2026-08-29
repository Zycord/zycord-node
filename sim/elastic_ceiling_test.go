package sim_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// Multi-epoch behaviour of whitepaper §8.1's elastic sequential ceiling.
//
// core/fold's own tests (elastic_ceiling_test.go) pin the controller's
// arithmetic for one epoch, and for two (grow, then decay). What a
// single-epoch test cannot show is what happens under sustained pressure
// over many epochs: does growth stay bounded, does decay reach and hold the
// floor, does an oscillating load avoid a runaway in either direction, and —
// the property with no unit-test shape at all — does a reorg across an
// epoch boundary restore T, the sample ring, the citation counter and the
// prev-parent/prev-target cells exactly, the way the undo log restores
// everything else.
//
// EpochLength is shrunk to 8 for every scenario here so that "many epochs"
// is affordable in a test binary; SeqGasTargetGenesis is shrunk to match, for
// the same reason core/fold's tests shrink it — a handful of certificates,
// not thousands, must be enough to bind the ceiling.

func multiEpochParams() *params.Params {
	p := *spec.Devnet()
	p.SeqGasTargetGenesis = 1000
	p.EpochLength = 8
	return &p
}

func transferCert(t *testing.T, p *params.Params, c *harness.Chain, k *wallet.Key, from, to types.Address, amount u256.U256, seq uint64) *types.Certificate {
	t.Helper()
	// The maxima track the current base fees, read fresh for every
	// certificate, rather than a fixed guess: these tests sustain full
	// blocks across many epochs on purpose, and EIP-1559's base fee has no
	// ceiling under sustained above-target demand, so any fixed cap
	// eventually falls behind it and starts failing B4 for a reason that
	// has nothing to do with what the test is actually checking. 5x plus a
	// fixed margin comfortably covers the ±12.5% a single block can move it
	// between this read and the block actually landing.
	//
	// Keep the multiplier modest, not generous: FeeCeiling is
	// seq_gas × seq_bid + par_gas × par_bid — a *price* multiplied by gas,
	// not a flat cap — so a large seqMax reserves a correspondingly large
	// deposit (temporarily, refunded within the same certificate's
	// settlement) against every one of these funded accounts' balances.
	seqBase := c.State.Get(types.SeqBaseFeeSlot())
	parBase := c.State.Get(types.ParBaseFeeSlot())
	seqMax := seqBase.MulDiv64(5, 1).SatAdd(drops(10_000))
	parMax := parBase.MulDiv64(5, 1).SatAdd(drops(10_000))
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, from, to, amount),
		Seq:     seq,
		TTL:     c.NextHeight() + 10,
		Deposit: wallet.SelfDeposit(from, from),
		FeeBid:  wallet.Bid(seqMax, drops(1_000), parMax, drops(10)),
		Signers: []*wallet.Key{k},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustApply(t *testing.T, c *harness.Chain, payout types.Address, certs ...*types.Certificate) *fold.Result {
	t.Helper()
	res := c.MustAddBlock(payout, certs...)
	for i, o := range res.Outcomes {
		if o.Outcome != fold.Applied {
			t.Fatalf("height %d certificate %d was %s, want APPLIED", c.Height(), i, o.Outcome)
		}
	}
	return res
}

func currentT(t *testing.T, c *harness.Chain) uint64 {
	t.Helper()
	v, ok := c.State.Get(types.SeqGasTargetSlot()).Uint64()
	if !ok {
		t.Fatal("T does not fit in 64 bits")
	}
	return v
}

// fillEpochFull mines every remaining block of the epoch in progress with
// three transfers each (1800 sequential gas, comfortably above the median
// this file's small T values need to clear), then one more block to land
// exactly on the boundary and run the epoch controller.
func fillEpochFull(t *testing.T, ep *params.Params, c *harness.Chain, payout types.Address, signer *wallet.Key, from, to types.Address, seq *uint64) {
	t.Helper()
	for c.NextHeight()%ep.EpochLength != 0 {
		certs := make([]*types.Certificate, 3)
		for i := range certs {
			*seq++
			certs[i] = transferCert(t, ep, c, signer, from, to, drops(1_000), *seq)
		}
		mustApply(t, c, payout, certs...)
	}
	mustApply(t, c, payout)
}

// fillEpochEmpty is fillEpochFull without the traffic: every block of the
// epoch in progress is empty, then one more lands on the boundary.
func fillEpochEmpty(t *testing.T, ep *params.Params, c *harness.Chain, payout types.Address) {
	t.Helper()
	for c.NextHeight()%ep.EpochLength != 0 {
		mustApply(t, c, payout)
	}
	mustApply(t, c, payout)
}

// alignToEpochBoundary mines forward until one block has landed exactly on
// an epoch boundary, then stops one height past it. Every scenario below
// needs it before its first fillEpochFull/fillEpochEmpty call, and the
// one-past-the-boundary landing spot matters: a boundary block's own gas
// evaluates the epoch *before* it, never the blocks added within itself, so
// fillEpochFull/fillEpochEmpty are written to fill everything up to the next
// boundary and then cross it — which only measures a clean, fully-controlled
// epoch if the chain starts one height past a boundary already. Landing
// exactly *on* the boundary instead would make each function's own
// while-loop condition false immediately, so its first call would add only
// the crossing block and fill nothing — which is the bug this comment exists
// so nobody reintroduces.
func alignToEpochBoundary(t *testing.T, ep *params.Params, c *harness.Chain, payout types.Address) {
	t.Helper()
	for c.NextHeight()%ep.EpochLength != 0 {
		mustApply(t, c, payout)
	}
	mustApply(t, c, payout) // cross the boundary; land one height past it
}

// TestElasticCeilingSustainedGrowthStaysBounded runs 20 epochs of full
// blocks and checks, at every boundary, that T only ever moved by the
// clamped step — never further, in either direction, and never below its
// starting value under sustained demand. Twenty epochs is enough to show the
// clamp holds under accumulation, not just once.
func TestElasticCeilingSustainedGrowthStaysBounded(t *testing.T) {
	ep := multiEpochParams()
	c := harness.MustNew(ep)
	miner := key(t, 1)
	payout := miner.Persistent()
	if err := c.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}
	alice, bob := key(t, 2), key(t, 3)
	minerSeq, seq := uint64(1000), uint64(0)
	fund := func() {
		minerSeq++
		mustApply(t, c, payout, transferCert(t, ep, c, miner, payout, alice.Persistent(), drops(2_000_000_000), minerSeq))
	}
	fund()
	alignToEpochBoundary(t, ep, c, payout)

	const epochs = 8
	prev := currentT(t, c)
	for e := 0; e < epochs; e++ {
		// Sustained above-target demand means the base fee keeps rising for
		// as long as this loop runs — an unavoidable consequence of the
		// property under test, not a scenario bug — and every applied
		// certificate burns real drops at that rising price. Topping up
		// from the miner every epoch, rather than funding once up front,
		// is what keeps that burn from starving the test of its own
		// traffic before growth has run its course. The miner can always
		// afford it: its own balance grows from the same blocks' emission,
		// uncapped by anything alice spends.
		fund()
		fillEpochFull(t, ep, c, payout, alice, alice.Persistent(), bob.Persistent(), &seq)
		next := currentT(t, c)
		if next < prev {
			t.Fatalf("epoch %d: T fell under sustained full blocks: %d -> %d", e, prev, next)
		}
		if want := prev + prev/ep.CeilingGrowthDivisor; next != want {
			t.Fatalf("epoch %d: T went to %d, want the clamped step %d (from %d)", e, next, want, prev)
		}
		prev = next
	}

	// Over `epochs` epochs the compounding bound is T0 * (1+1/Gamma)^epochs;
	// integer rounding can only fall short of it, never exceed it.
	bound := float64(ep.SeqGasTargetGenesis)
	for i := 0; i < epochs; i++ {
		bound *= 1 + 1/float64(ep.CeilingGrowthDivisor)
	}
	if float64(prev) > bound+1 { // +1 for floating-point slack, not integer slack
		t.Fatalf("T after %d epochs = %d, exceeds the compounding bound of %.2f", epochs, prev, bound)
	}
}

// TestElasticCeilingIdleDecaysToTheFloorAndHolds grows T across several
// epochs, then runs enough idle epochs that it must reach the genesis floor,
// and checks it never overshoots below that floor and never resumes moving
// once there — the floor is a wall, not a limit approached asymptotically
// from one side only.
func TestElasticCeilingIdleDecaysToTheFloorAndHolds(t *testing.T) {
	ep := multiEpochParams()
	ep.CeilingGrowthDivisor = 2 // aggressive on purpose, so growth clears the
	ep.CeilingDecayDivisor = 2  // floor fast and decay is observable quickly —
	// nothing this pronounced belongs in spec/params.json; see
	// core/fold's TestElasticCeilingDecaysAfterGrowth for the same choice
	// and the same reason.
	c := harness.MustNew(ep)
	miner := key(t, 1)
	payout := miner.Persistent()
	if err := c.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}
	alice, bob := key(t, 2), key(t, 3)
	seq := uint64(2000)
	mustApply(t, c, payout, transferCert(t, ep, c, miner, payout, alice.Persistent(), drops(2_000_000_000), seq))
	alignToEpochBoundary(t, ep, c, payout)

	for e := 0; e < 5; e++ {
		fillEpochFull(t, ep, c, payout, alice, alice.Persistent(), bob.Persistent(), &seq)
	}
	grown := currentT(t, c)
	if grown <= ep.SeqGasTargetGenesis {
		t.Fatalf("setup failed to grow T above the floor: %d", grown)
	}

	prev := grown
	reachedFloor := false
	for e := 0; e < 30; e++ {
		fillEpochEmpty(t, ep, c, payout)
		next := currentT(t, c)
		if next > prev {
			t.Fatalf("epoch %d: T rose under idle blocks: %d -> %d", e, prev, next)
		}
		if next < ep.SeqGasTargetGenesis {
			t.Fatalf("epoch %d: T fell below its genesis floor: %d < %d", e, next, ep.SeqGasTargetGenesis)
		}
		if reachedFloor && next != ep.SeqGasTargetGenesis {
			t.Fatalf("epoch %d: T left the floor after reaching it: %d", e, next)
		}
		if next == ep.SeqGasTargetGenesis {
			reachedFloor = true
		}
		prev = next
	}
	if !reachedFloor {
		t.Fatal("30 idle epochs were not enough to reach the floor; test setup needs more epochs or a steeper decay")
	}
}

// TestElasticCeilingOscillatingLoadStaysBounded alternates full and empty
// epochs and checks T never leaves the band its own genesis floor and the
// single-epoch growth clamp define — no runaway in either direction under a
// load shape neither the pure-growth nor the pure-decay test exercises.
func TestElasticCeilingOscillatingLoadStaysBounded(t *testing.T) {
	ep := multiEpochParams()
	c := harness.MustNew(ep)
	miner := key(t, 1)
	payout := miner.Persistent()
	if err := c.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}
	alice, bob := key(t, 2), key(t, 3)
	seq := uint64(3000)
	mustApply(t, c, payout, transferCert(t, ep, c, miner, payout, alice.Persistent(), drops(2_000_000_000), seq))
	alignToEpochBoundary(t, ep, c, payout)

	// An upper bound no honest sequence of growth steps from T0 could cross
	// in 20 rounds, however many of them happen to be growth epochs.
	ceiling := ep.SeqGasTargetGenesis
	for i := 0; i < 20; i++ {
		ceiling += ceiling / ep.CeilingGrowthDivisor
	}

	for round := 0; round < 20; round++ {
		if round%2 == 0 {
			fillEpochFull(t, ep, c, payout, alice, alice.Persistent(), bob.Persistent(), &seq)
		} else {
			fillEpochEmpty(t, ep, c, payout)
		}
		got := currentT(t, c)
		if got < ep.SeqGasTargetGenesis {
			t.Fatalf("round %d: T %d fell below the genesis floor %d", round, got, ep.SeqGasTargetGenesis)
		}
		if got > ceiling {
			t.Fatalf("round %d: T %d exceeded the 20-round growth-only bound %d — a runaway", round, got, ceiling)
		}
	}
}

// TestCitedCountAccumulatesAndResetsAcrossABoundary is the wiring check
// citation golden vectors (spec/vectors/034-cites-valid and the
// seven that follow it) cannot provide: those pin
// that a citation is accepted or rejected, one block at a time, never that
// F2c's running count (whitepaper §8.1's health signal) actually accumulates
// across a whole epoch and F2b actually resets it once evaluated. No
// certificates or funding are needed for this — headers cost nothing to
// build — which is deliberate: it isolates the citation bookkeeping from
// every fee-market complication the traffic-driven tests above had to work
// around.
func TestCitedCountAccumulatesAndResetsAcrossABoundary(t *testing.T) {
	ep := multiEpochParams()
	c := harness.MustNew(ep)
	miner := key(t, 1)
	payout := miner.Persistent()

	// A genuine sibling of height 1: a second candidate off genesis that is
	// never applied, kept only for its header. citeBlock below is the one
	// place a citation actually gets attached.
	sibling, err := c.Propose(key(t, 99).Persistent())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := c.Propose(payout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(canonical); err != nil {
		t.Fatal(err)
	}

	// Height 2 cites the height-1 sibling — the earliest a citation can
	// exist at all (fold/blockrules.go's checkCites forbids one at height
	// <= 1). One citation, attached once, is enough to prove accumulation:
	// a count that starts at zero and reads back as exactly one after this
	// block is not being silently dropped or double-counted.
	citing := citeBlock(t, ep, c, payout, []*types.Header{&sibling.Header})
	if _, err := c.Apply(citing); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.State.Get(types.CitedCountSlot()).Uint64(); got != 1 {
		t.Fatalf("cited count after one citation = %d, want 1", got)
	}

	// Fill the rest of the epoch with plain empty blocks — no more
	// citations — then cross the boundary.
	for c.NextHeight()%ep.EpochLength != 0 {
		mustApply(t, c, payout)
	}
	if got, _ := c.State.Get(types.CitedCountSlot()).Uint64(); got != 1 {
		t.Fatalf("cited count drifted before the boundary: %d, want the 1 still unevaluated", got)
	}
	mustApply(t, c, payout) // the boundary block: F2b reads the count, then zeroes it

	if got, _ := c.State.Get(types.CitedCountSlot()).Uint64(); got != 0 {
		t.Fatalf("cited count after the boundary = %d, want 0 (F2b must reset it for the next epoch)", got)
	}
}

// citeBlock builds the next block on c's tip, citing the given headers —
// harness.Chain.Propose takes no Cites parameter, so this mirrors it by
// hand for the one field it omits.
func citeBlock(t *testing.T, p *params.Params, c *harness.Chain, payout types.Address, cites []*types.Header) *types.Block {
	t.Helper()
	tip := c.Tip()
	b := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + p.TargetBlockSeconds,
			EmissionAddr: payout,
			Target:       tip.Target,
		},
		Cites: cites,
	}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	b.Header.CitesRoot = b.ComputeCitesRoot(p)
	return b
}

// TestReorgAcrossEpochBoundaryRestoresElasticCeilingState is the property no
// single-epoch or multi-epoch forward-only test can show: whitepaper §8.1
// added five new consensus cells (T, the applied-gas sample ring, the
// citation counter, and the previous parent id and target), all written by
// F2b/F2c, and every one of them must be exactly restored by the undo log a
// reorg replays — the same guarantee the fold already gives every other
// piece of state. A reorg that forgot one would fork the chain silently
// (whitepaper's own words for the equivalent gap in state prunability).
func TestReorgAcrossEpochBoundaryRestoresElasticCeilingState(t *testing.T) {
	ep := multiEpochParams()
	c := harness.MustNew(ep)
	miner := key(t, 1)
	payout := miner.Persistent()
	if err := c.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}
	alice, bob := key(t, 2), key(t, 3)
	seq := uint64(4000)
	mustApply(t, c, payout, transferCert(t, ep, c, miner, payout, alice.Persistent(), drops(2_000_000_000), seq))
	alignToEpochBoundary(t, ep, c, payout)

	// A stable reference point, captured after alignment: every §8.1 cell.
	preT := c.State.Get(types.SeqGasTargetSlot())
	preCited := c.State.Get(types.CitedCountSlot())
	prePrevParent := c.State.Get(types.PrevParentIDSlot())
	prePrevTarget := c.State.Get(types.PrevTargetSlot())
	preSamples := make([]u256.U256, ep.EpochLength)
	for i := range preSamples {
		preSamples[i] = c.State.Get(types.AppliedGasSampleSlot(uint64(i)))
	}
	preRoot := c.State.Root()

	// Cross the boundary with a full epoch, changing T and every sample.
	fillEpochFull(t, ep, c, payout, alice, alice.Persistent(), bob.Persistent(), &seq)
	if got := c.State.Get(types.SeqGasTargetSlot()); got.Eq(preT) {
		t.Fatal("test setup did not move T; the boundary crossed did nothing to undo")
	}

	// Roll every block of that epoch back, one at a time — exactly what a
	// reorg does, block by block, via the same undo log.
	rolledBack := 0
	for {
		if err := c.Rollback(); err != nil {
			t.Fatalf("rollback failed after %d blocks: %v", rolledBack, err)
		}
		rolledBack++
		if c.State.Root() == preRoot {
			break
		}
		if rolledBack > int(ep.EpochLength)+1 {
			t.Fatal("rolled back further than the epoch is long without finding the pre-boundary root")
		}
	}

	if got := c.State.Get(types.SeqGasTargetSlot()); !got.Eq(preT) {
		t.Fatalf("T not restored: got %s, want %s", got.String(), preT.String())
	}
	if got := c.State.Get(types.CitedCountSlot()); !got.Eq(preCited) {
		t.Fatalf("cited count not restored: got %s, want %s", got.String(), preCited.String())
	}
	if got := c.State.Get(types.PrevParentIDSlot()); !got.Eq(prePrevParent) {
		t.Fatalf("prev parent id not restored: got %s, want %s", got.String(), prePrevParent.String())
	}
	if got := c.State.Get(types.PrevTargetSlot()); !got.Eq(prePrevTarget) {
		t.Fatalf("prev target not restored: got %s, want %s", got.String(), prePrevTarget.String())
	}
	for i, want := range preSamples {
		if got := c.State.Get(types.AppliedGasSampleSlot(uint64(i))); !got.Eq(want) {
			t.Fatalf("applied-gas sample %d not restored: got %s, want %s", i, got.String(), want.String())
		}
	}
	if got := c.State.Root(); got != preRoot {
		t.Fatal("state root not restored even though every §8.1 cell checked above was")
	}
}
