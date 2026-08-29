package chain_test

import (
	"errors"
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/storage"
	"zycord/spec"
	"zycord/wallet"
)

func key(t *testing.T, n byte) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

// node bundles a chain, a pool and a miner over a directory.
type node struct {
	dir   string
	p     *params.Params
	chain *chain.Chain
	pool  *mempool.Pool
	miner *miner.Miner
	clock uint64
}

func openNode(t *testing.T, dir string, p *params.Params, payout types.Address) *node {
	return openNodeWith(t, dir, p, payout, storage.Options{})
}

func openNodeWith(t *testing.T, dir string, p *params.Params, payout types.Address,
	opts storage.Options) *node {
	t.Helper()
	c, err := chain.OpenWith(dir, p, opts)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{dir: dir, p: p, chain: c, pool: mempool.New(p, mempool.DefaultPolicy()), clock: p.GenesisTime}
	n.miner = &miner.Miner{
		Chain:  c,
		Pool:   n.pool,
		Engine: pow.Dev{},
		Payout: payout,
		Now: func() uint64 {
			n.clock += p.TargetBlockSeconds
			return n.clock
		},
	}
	return n
}

func (n *node) mine(t *testing.T, blocks int) {
	t.Helper()
	for i := 0; i < blocks; i++ {
		if _, _, err := n.miner.MineOne(1 << 20); err != nil {
			t.Fatalf("mining block %d: %v", n.chain.Height()+1, err)
		}
	}
}

func (n *node) close(t *testing.T) {
	t.Helper()
	if err := n.chain.Close(); err != nil {
		t.Fatal(err)
	}
}

// devnetEasy is devnet with a trivial proof-of-work target, so tests spend
// their time on the properties rather than on hashing.
func devnetEasy() *params.Params {
	// Devnet's real GENESIS_TARGET (2^248), deliberately NOT u256.Max.
	//
	// This used to override it to u256.Max to make mining free. That is 31x
	// ABOVE devnet's own MAX_TARGET (2^251) — a value params.Validate rejects
	// on a real chain — and it was invisible only because NextTarget
	// normalised against the window's LAST target and so never read an older
	// one. Now that the ratio applies to the window's AVERAGE target, a
	// genesis target that far out of range dominates the mean for a full
	// DIFFICULTY_WINDOW after any fork, pinning every branch to MAX_TARGET and
	// making two branches carry identical work — which silently destroys the
	// work difference these tests exist to observe.
	//
	// The real value is still trivial to mine: 2^256/2^248 = ~256 expected
	// attempts against the 1<<20 budget these tests give MineOne, a margin of
	// ~4000x, and it is only 8x below devnet's MAX_TARGET rather than an
	// out-of-range outlier.
	p := *spec.Devnet()
	return &p
}

// TestGenesisIsCommittedLikeAnyBlock: a fresh directory folds and persists
// genesis through the same commit path as every later block, so there is one
// path to get right rather than two.
func TestGenesisIsCommittedLikeAnyBlock(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	n := openNode(t, dir, p, key(t, 1).Persistent())
	if n.chain.Height() != 0 {
		t.Fatalf("fresh chain is at height %d", n.chain.Height())
	}
	if n.chain.StoredStateRoot() != n.chain.StateRoot() {
		t.Fatal("the stored root does not match the state genesis produced")
	}
	n.close(t)

	// Reopening must not re-fold genesis or change anything.
	again := openNode(t, dir, p, key(t, 1).Persistent())
	defer again.close(t)
	if again.chain.Tip().ID() != n.chain.Tip().ID() {
		t.Fatal("reopening changed the genesis block")
	}
}

// TestRestartEquivalence is M1-G2: a node killed and restarted every few blocks
// must be indistinguishable from one that ran continuously.
func TestRestartEquivalence(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()

	continuous := openNode(t, t.TempDir(), p, payout)
	restarted := openNode(t, t.TempDir(), p, payout)
	restartDir := restarted.dir

	const blocks = 40
	for i := 0; i < blocks; i++ {
		continuous.mine(t, 1)
		restarted.mine(t, 1)

		if i%3 == 2 {
			// Close and reopen, mid-stream.
			clock := restarted.clock
			restarted.close(t)
			restarted = openNode(t, restartDir, p, payout)
			restarted.clock = clock
		}

		if continuous.chain.Height() != restarted.chain.Height() {
			t.Fatalf("heights diverged at block %d: %d vs %d",
				i, continuous.chain.Height(), restarted.chain.Height())
		}
		if continuous.chain.StateRoot() != restarted.chain.StateRoot() {
			t.Fatalf("state roots diverged after block %d; a restart changed the state", i)
		}
		if continuous.chain.Snapshot().State.SeenCount() != restarted.chain.Snapshot().State.SeenCount() {
			t.Fatalf("seen sets diverged after block %d", i)
		}
		if !continuous.chain.Snapshot().State.Get(types.SeqBaseFeeSlot()).
			Eq(restarted.chain.Snapshot().State.Get(types.SeqBaseFeeSlot())) {
			t.Fatalf("base fees diverged after block %d", i)
		}
	}
	continuous.close(t)
	restarted.close(t)
}

// TestStartupIntegrityCatchesCorruption is M1-G3. A node must notice that its
// storage does not match its committed root *before* it mines, relays or serves
// anything on top of it.
func TestStartupIntegrityCatchesCorruption(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	n := openNode(t, dir, p, key(t, 1).Persistent())
	n.mine(t, 6)
	n.close(t)

	// Corrupt one cell value on disk, leaving everything else intact — the
	// shape a subtle persistence bug or a bad sector would take.
	corruptOneCell(t, dir)

	if _, err := chain.Open(dir, p); err == nil {
		t.Fatal("a node opened onto corrupted state and would have mined on it")
	} else if !isCorruptState(err) {
		t.Fatalf("got %v, want a corrupt-state error", err)
	}
}

// TestWrongNetworkRefusesToOpen is R3-1 at the storage boundary: a node
// restarted against a different parameter set must refuse the directory rather
// than continue onto a chain it now disagrees with.
func TestWrongNetworkRefusesToOpen(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	n := openNode(t, dir, p, key(t, 1).Persistent())
	n.mine(t, 3)
	n.close(t)

	// One parameter changed — not the chain id, something subtler.
	edited := *p
	edited.TTLMax = p.TTLMax + 1
	if _, err := chain.Open(dir, &edited); err == nil {
		t.Fatal("a node opened a chain built under different consensus parameters")
	}

	// And the original still opens.
	same, err := chain.Open(dir, p)
	if err != nil {
		t.Fatalf("the unmodified parameters no longer open the chain: %v", err)
	}
	same.Close()
}

// TestRollbackRestoresStorageAndState: a reorg must move disk and memory
// together, or a restart resurrects the abandoned branch.
func TestRollbackRestoresStorageAndState(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	n := openNode(t, dir, p, key(t, 1).Persistent())
	n.mine(t, 5)

	beforeRoot := n.chain.StateRoot()
	beforeHeight := n.chain.Height()
	beforeTip := n.chain.Tip().ID()

	n.mine(t, 1)
	if n.chain.Height() != beforeHeight+1 {
		t.Fatal("setup: the chain did not advance")
	}

	if err := n.chain.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n.chain.Height() != beforeHeight || n.chain.Tip().ID() != beforeTip {
		t.Fatal("rollback did not restore the tip")
	}
	if n.chain.StateRoot() != beforeRoot {
		t.Fatal("rollback did not restore the state")
	}
	n.close(t)

	// The rollback must have reached disk, not just memory.
	reopened, err := chain.Open(dir, p)
	if err != nil {
		t.Fatalf("reopen after rollback: %v", err)
	}
	defer reopened.Close()
	if reopened.Height() != beforeHeight {
		t.Fatalf("a restart resurrected the rolled-back block: height %d", reopened.Height())
	}
	if reopened.StateRoot() != beforeRoot {
		t.Fatal("a restart resurrected the rolled-back state")
	}
}

// TestMinedChainMatchesTheFold: the node's persisted state must equal what the
// fold produces from the same blocks in memory. This is the differential
// discipline pointed at the persistence layer.
func TestMinedChainMatchesTheFold(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	n := openNode(t, dir, p, key(t, 1).Persistent())
	n.mine(t, 12)
	persisted := n.chain.StateRoot()
	height := n.chain.Height()

	// Re-fold the same blocks from genesis into a fresh in-memory state.
	replayDir := t.TempDir()
	replay, err := chain.Open(replayDir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	for h := uint64(1); h <= height; h++ {
		b, err := n.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := replay.Apply(b); err != nil {
			t.Fatalf("replaying block %d: %v", h, err)
		}
	}
	n.close(t)

	if replay.StateRoot() != persisted {
		t.Fatal("replaying the stored blocks produced a different state than the node holds")
	}
}

// TestMinerDropsTheDrops: an unfundable certificate pays nothing and consumes
// ceiling space, so a rational builder leaves it out (§10).
func TestMinerDropsTheDrops(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	miner1 := key(t, 1)
	n := openNode(t, dir, p, miner1.Persistent())
	defer n.close(t)

	// Mine until the payout has a spendable balance.
	n.mine(t, int(p.CoinbaseMaturity)+2)

	// A certificate from an account with nothing behind it. The pool's deposit
	// screen refuses it, which is the first line of defence...
	pauper := key(t, 8)
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, pauper.Persistent(), key(t, 9).Persistent(), drops(1_000)),
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(pauper.Persistent(), pauper.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{pauper},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.pool.Add(cert, n.chain.Snapshot().State, n.chain.Height()); err == nil {
		t.Fatal("the pool admitted a certificate with no deposit behind it")
	}

	// ...and the builder's dry run is the second: even handed the certificate
	// directly, an assembled block must not carry it.
	//
	// Anti-vacuity, and it is load-bearing here: the pool refused the pauper
	// above, so `assembleWith` hands the builder an *empty* pool and Assemble
	// skips dropTheDrops entirely (it is guarded on len(b.Certs) > 0). The
	// loop below would then iterate over nothing and pass no matter what the
	// builder does — verified by disabling dropTheDrops outright, at which
	// point this half of the test still passed. So the real witness is the
	// second half: a certificate the pool *accepts* and the fold then drops.
	kept, err := assembleWith(t, n, cert)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range kept {
		if c.ID() == cert.ID() {
			t.Fatal("the builder kept a certificate that would be dropped")
		}
	}

	// A certificate that is genuinely poolable and genuinely drops at fold
	// time. Alice is funded, so her certificate passes the deposit screen; she
	// then spends the balance out from under it in a mined block, so by the
	// time the builder dry-runs it the deposit can no longer be reserved and
	// F3 returns DROPPED. Nothing about it is refusable at admission — which
	// is the whole point, and what makes this the case dropTheDrops exists for.
	alice, sink := key(t, 30), key(t, 31)
	fundAmount := drops(600_000_000)
	fundB := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), alice.Persistent(), fundAmount),
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{miner1},
	}
	fundCert, err := fundB.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.pool.Add(fundCert, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("funding alice: %v", err)
	}
	n.mine(t, 1)

	victimB := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), sink.Persistent(), drops(1_000)),
		Seq:     1,
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{alice},
	}
	victim, err := victimB.Build()
	if err != nil {
		t.Fatal(err)
	}
	// Pool it *before* the drain commits, and keep that pool. This is the real
	// race a miner faces: the deposit screen re-checks against the current
	// tip, so a certificate that will drop at fold time is refusable at
	// admission — but only once the node knows. Between pooling at height H
	// and assembling after H+1 lands, the pool still holds a certificate whose
	// deposit has since been spent, and no rescreen has run. That is the only
	// way a DROPPED certificate reaches the builder at all, and it is exactly
	// what dropTheDrops is the second line of defence for.
	victimPool := mempool.New(n.p, mempool.DefaultPolicy())
	if err := victimPool.Add(victim, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("the victim should be poolable before the drain commits: %v", err)
	}

	// Now drain alice in a committed block, so the deposit is no longer there
	// when the builder dry-runs the victim. Refund to the sink rather than to
	// alice, so nothing flows back into the cell the victim needs.
	drainB := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), sink.Persistent(), drops(1)),
		Seq:     0,
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), sink.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{alice},
	}
	drain, err := drainB.Build()
	if err != nil {
		t.Fatal(err)
	}
	// Move everything the drain's own deposit does not reserve, so alice ends
	// the block with too little to back the victim's deposit.
	movable, under := fundAmount.Sub(drain.Deposit.Amount)
	if under {
		t.Fatal("setup: alice cannot cover her own drain deposit")
	}
	drainB.Program = wallet.Tip(types.NativeAsset, alice.Persistent(), sink.Persistent(), movable)
	drain, err = drainB.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.pool.Add(drain, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("draining alice: %v", err)
	}
	n.mine(t, 1)

	// Confirm the premise rather than assuming it: folded on its own against
	// the drained state, the victim really is DROPPED.
	res, err := assembleProbe(t, n, victim)
	if err != nil {
		t.Fatalf("probing the victim: %v", err)
	}
	if len(res.Outcomes) != 1 || res.Outcomes[0].Outcome != fold.Dropped {
		t.Fatalf("victim outcome = %v, want DROPPED; the witness is not built", res.Outcomes)
	}

	// The pool from before the drain still offers it — assert that, or the
	// test degenerates into the empty-pool non-assertion above.
	var offered bool
	for _, c := range victimPool.Candidates() {
		if c.ID() == victim.ID() {
			offered = true
		}
	}
	if !offered {
		t.Fatal("the stale pool no longer offers the victim, so the builder never " +
			"sees it and this asserts nothing")
	}

	// And the builder must leave it out.
	m := &miner.Miner{Chain: n.chain, Pool: victimPool, Engine: pow.Dev{}, Payout: n.miner.Payout, Now: n.miner.Now}
	candidate, err := m.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range candidate.Certs {
		if c.ID() == victim.ID() {
			t.Fatal("the builder kept a certificate the fold drops")
		}
	}
}

// TestMinerDropsTheStaleSkips pins the unpaid-outcome gap: a certificate whose
// declared read has gone stale by the time the builder dry-runs it pays the
// miner nothing — F9 pays a tip on the Applied path only — so a rational
// builder must leave it out exactly as it already does for a DROPPED
// certificate. Unlike TestMinerDropsTheDrops, nothing here is individually
// unfundable or otherwise inadmissible: both certificates pass every V-rule and
// the pool's own screen on their own, which is the whole point — admission
// cannot tell a certificate that will skip from one that will apply, only the
// builder's own dry run can.
func TestMinerDropsTheStaleSkips(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	miner1 := key(t, 1)
	n := openNode(t, dir, p, miner1.Persistent())
	defer n.close(t)

	// Mine until the payout has a spendable balance, then fund Alice with real
	// coin — through a mined block, not a shortcut, so what follows is
	// contending for a balance that genuinely exists on chain.
	n.mine(t, int(p.CoinbaseMaturity)+2)

	alice, bob := key(t, 8), key(t, 9)
	fundAmount := drops(700_000_000)
	fundBuilder := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), alice.Persistent(), fundAmount),
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{miner1},
	}
	fund, err := fundBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.pool.Add(fund, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("funding Alice: %v", err)
	}
	n.mine(t, 1)
	if got := n.chain.Snapshot().State.Get(types.NativeBalanceSlot(alice.Persistent())); !got.Eq(fundAmount) {
		t.Fatalf("setup: Alice holds %s, want exactly %s", got.String(), fundAmount.String())
	}

	// Alice signs two sequential transfers, each for more than half her
	// balance. Both are individually well-formed and, evaluated against her
	// current balance, both are individually affordable — admission has no
	// way to know only one of them can actually land. Whichever commits first
	// spends enough that the second's declared balance read no longer holds.
	half := drops(400_000_000)
	transferAt := func(seq uint64) *types.Certificate {
		t.Helper()
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), half),
			Seq:     seq,
			TTL:     n.chain.Height() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
			Signers: []*wallet.Key{alice},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := transferAt(0)
	second := transferAt(1)

	// Anti-vacuity: both must genuinely be poolable on their own merits before
	// the builder ever sees them, or excluding "second" would prove nothing
	// about the dry run — admission would have done the work instead.
	pool := mempool.New(n.p, mempool.DefaultPolicy())
	if err := pool.Add(first, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("the first transfer should be individually admissible: %v", err)
	}
	if err := pool.Add(second, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("the second transfer should be individually admissible: %v", err)
	}

	m := &miner.Miner{Chain: n.chain, Pool: pool, Engine: pow.Dev{}, Payout: n.miner.Payout, Now: n.miner.Now}
	candidate, err := m.Assemble()
	if err != nil {
		t.Fatal(err)
	}

	var sawFirst bool
	for _, c := range candidate.Certs {
		if c.ID() == first.ID() {
			sawFirst = true
		}
		if c.ID() == second.ID() {
			t.Fatal("the builder kept a certificate that would only skip and pay it nothing")
		}
	}
	if !sawFirst {
		t.Fatal("the applying transfer was dropped too; the test proves nothing about staleness specifically")
	}

	// And committing the candidate for real must confirm the premise: the
	// certificate the builder excluded really was headed for SKIPPED_STALE, not
	// some other reason to be worried about, by running the fold over the
	// two-certificate block a builder without the dry-run drop pass would have
	// proposed.
	trial := *candidate
	trial.Certs = []*types.Certificate{first, second}
	trial.Header.CertRoot = trial.ComputeCertRoot(p)
	res, err := fold.SealOutcomes(n.chain.Snapshot().State, &trial, p)
	if err != nil {
		t.Fatalf("the two-certificate block a builder without the drop pass would have proposed does not even fold: %v", err)
	}
	if len(res.Outcomes) != 2 {
		t.Fatalf("got %d outcomes, want 2", len(res.Outcomes))
	}
	if res.Outcomes[0].ID != first.ID() || res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("first outcome = (%x, %s), want (first, APPLIED)", res.Outcomes[0].ID, res.Outcomes[0].Outcome)
	}
	if res.Outcomes[1].ID != second.ID() || res.Outcomes[1].Outcome != fold.SkippedStale {
		t.Fatalf("second outcome = (%x, %s), want (second, SKIPPED_STALE)", res.Outcomes[1].ID, res.Outcomes[1].Outcome)
	}
}

// TestMinerDropsSkipsThatOnlyOtherSkipsPaidFor is the fixpoint half of the
// same unpaid-outcome gap.
//
// A DROPPED certificate is state-neutral, so removing one cannot change any
// other certificate's outcome and a single dry-run pass is exact. A skip is
// not neutral: F5 debits Deposit.Cell by Deposit.Amount, and settle credits
// Deposit.RefundTo with Amount - SkipFee. Nothing requires RefundTo to be the
// depositor — the V-rules only require a native balance slot at a user
// address — so a skip can be a net *credit* to a third party.
//
// That makes a single pass unsound in the direction that matters. Build a
// later certificate whose GUARD_GE holds only because a skip's refund landed,
// and one pass keeps it: the dry run saw it apply, the builder removed the
// skip that paid for it, and the block ships a certificate the fold will pay
// the miner nothing for — precisely what dropTheDrops exists to prevent.
//
// The shape below is that witness. Carol's transfer moves her whole balance
// plus the refund, so it is applicable if and only if alice's skipping
// certificate ran first. Fold order is (underwriter, Seq, id), and the test
// asserts the ordering premise rather than assuming it.
func TestMinerDropsSkipsThatOnlyOtherSkipsPaidFor(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	miner1 := key(t, 1)
	n := openNode(t, dir, p, miner1.Persistent())
	defer n.close(t)

	n.mine(t, int(p.CoinbaseMaturity)+2)

	// Fold order is (underwriter, Seq, id), so the witness needs alice's
	// address to sort before carol's. Search for a pair that does rather than
	// asserting one and skipping: a t.Skip here would silently delete the only
	// test guarding the fixpoint if key derivation ever changed.
	bob := key(t, 22)
	var alice, carol *wallet.Key
	for i := byte(100); i < 160 && carol == nil; i++ {
		for j := i + 1; j < 160; j++ {
			a, c := key(t, i), key(t, j)
			aAddr, cAddr := a.Persistent(), c.Persistent()
			if string(aAddr[:]) < string(cAddr[:]) {
				alice, carol = a, c
				break
			}
		}
	}
	if carol == nil {
		t.Fatal("no key pair in the search range sorts the way this witness needs")
	}

	fund := func(to *wallet.Key, amount u256.U256) {
		t.Helper()
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), to.Persistent(), amount),
			TTL:     n.chain.Height() + 5,
			Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
			FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
			Signers: []*wallet.Key{miner1},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		if err := n.pool.Add(c, n.chain.Snapshot().State, n.chain.Height()); err != nil {
			t.Fatalf("funding: %v", err)
		}
		n.mine(t, 1)
	}
	fund(alice, drops(900_000_000))
	fund(carol, drops(100_000_000))

	state0 := n.chain.Snapshot().State
	carolBalance := state0.Get(types.NativeBalanceSlot(carol.Persistent()))
	if carolBalance.IsZero() {
		t.Fatal("setup: carol holds nothing")
	}

	// alice seq0 applies. alice seq1 declares the same debit again, so its
	// GUARD_GE goes stale once seq0 has landed — and its refund is pointed at
	// carol rather than at alice.
	half := drops(500_000_000)
	aliceCert := func(seq uint64, deposit types.Deposit) *types.Certificate {
		t.Helper()
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), half),
			Seq:     seq,
			TTL:     n.chain.Height() + 5,
			Deposit: deposit,
			FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
			Signers: []*wallet.Key{alice},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	aliceApplies := aliceCert(0, wallet.SelfDeposit(alice.Persistent(), alice.Persistent()))
	aliceSkips := aliceCert(1, wallet.SelfDeposit(alice.Persistent(), carol.Persistent()))

	// The refund carol receives if — and only if — aliceSkips runs.
	refund, under := aliceSkips.Deposit.Amount.Sub(p.SkipFee)
	if under || refund.IsZero() {
		t.Fatalf("setup: the skip refunds nothing (amount %s, skip fee %s)",
			aliceSkips.Deposit.Amount.String(), p.SkipFee.String())
	}

	// Carol moves everything she would hold *after* the refund lands and after
	// her own deposit is reserved (F5 debits the deposit before F6 evaluates
	// the read), less one drop. That is strictly more than she can cover
	// without the refund, so her certificate is applicable if and only if
	// alice's skip ran first. The deposit is not known until the certificate
	// is built, so build it once at a placeholder amount to learn the ceiling,
	// then rebuild at the real figure.
	carolAmountFor := func(deposit u256.U256) u256.U256 {
		t.Helper()
		v, over := carolBalance.Add(refund)
		if over {
			t.Fatal("setup: carol's post-refund balance overflows")
		}
		v, under := v.Sub(deposit)
		if under {
			t.Fatal("setup: carol's deposit exceeds her post-refund balance")
		}
		v, under = v.Sub(u256.FromUint64(1))
		if under {
			t.Fatal("setup: carol's target amount underflows")
		}
		return v
	}
	carolAmount := carolAmountFor(u256.Zero)
	carolBuilder := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, carol.Persistent(), bob.Persistent(), carolAmount),
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(carol.Persistent(), carol.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{carol},
	}
	carolCert, err := carolBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild at the amount that accounts for the deposit the first build
	// revealed. The deposit depends only on the fee bid and the certificate's
	// shape, neither of which the amount changes, so one iteration suffices.
	carolBuilder.Program = wallet.Tip(types.NativeAsset, carol.Persistent(), bob.Persistent(),
		carolAmountFor(carolCert.Deposit.Amount))
	carolCert, err = carolBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}
	carolAmount = carolBuilder.Program.Transfer.Moves[0].Amount

	// Anti-vacuity, and the whole premise of the test: in a fold of all three,
	// alice's second certificate skips and carol's applies *because of it*.
	probe, err := assembleProbe(t, n, aliceApplies, aliceSkips, carolCert)
	if err != nil {
		t.Fatalf("probing the three-certificate fold: %v", err)
	}
	var sawSkip, sawCarolApplied bool
	for _, o := range probe.Outcomes {
		switch o.ID {
		case aliceSkips.ID():
			sawSkip = o.Outcome == fold.SkippedStale
		case carolCert.ID():
			sawCarolApplied = o.Outcome == fold.Applied
		}
	}
	if !sawSkip {
		t.Fatal("setup: alice's second certificate did not skip; the witness is not built")
	}
	if !sawCarolApplied {
		t.Fatalf("setup: carol's certificate did not apply in the full fold, so it never "+
			"depended on the refund (balance %s, refund %s, moving %s, deposit %s)",
			carolBalance.String(), refund.String(), carolAmount.String(),
			carolCert.Deposit.Amount.String())
	}

	// The counterfactual, which is the premise the whole witness rests on:
	// carol applies *because* of the refund, not on her own merits. Without
	// the skip in the block she must not apply, or the test would pass for a
	// reason that has nothing to do with the domino.
	noSkip, err := assembleProbe(t, n, aliceApplies, carolCert)
	if err != nil {
		t.Fatalf("probing the fold without the skip: %v", err)
	}
	for _, o := range noSkip.Outcomes {
		if o.ID == carolCert.ID() && o.Outcome == fold.Applied {
			t.Fatal("setup: carol applies even without the skip's refund; " +
				"her certificate never depended on it and the witness is not built")
		}
	}

	// The builder must not ship carol's certificate. One pass removes only
	// alice's skip and keeps carol's — which then skips on chain, unpaid.
	kept, err := assembleWith(t, n, aliceApplies, aliceSkips, carolCert)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range kept {
		if c.ID() == aliceSkips.ID() {
			t.Fatal("the builder kept alice's skipping certificate")
		}
		if c.ID() == carolCert.ID() {
			t.Fatal("the builder kept a certificate that only applied because a removed skip " +
				"refunded into it: one dry-run pass is not a fixpoint")
		}
	}

	// And it must not have thrown out the one that genuinely pays.
	var sawApplied bool
	for _, c := range kept {
		if c.ID() == aliceApplies.ID() {
			sawApplied = true
		}
	}
	if !sawApplied {
		t.Fatal("the applying certificate was excluded too; the fixpoint over-removes")
	}
}

// assembleProbe folds the given certificates as a block against the current
// tip, without the builder's own filtering, so a test can assert what the
// fold would do to a candidate a builder might propose.
func assembleProbe(t *testing.T, n *node, certs ...*types.Certificate) (*fold.Result, error) {
	t.Helper()
	// Take a real candidate from the miner so the header is well-formed, then
	// substitute the certificate list under test. Only the fold's verdict on
	// those certificates is being read.
	pool := mempool.New(n.p, mempool.DefaultPolicy())
	m := &miner.Miner{Chain: n.chain, Pool: pool, Engine: pow.Dev{}, Payout: n.miner.Payout, Now: n.miner.Now}
	candidate, err := m.Assemble()
	if err != nil {
		return nil, err
	}
	candidate.Certs = certs
	candidate.Header.CertRoot = candidate.ComputeCertRoot(n.p)
	return fold.SealOutcomes(n.chain.Snapshot().State, candidate, n.p)
}

// assembleWith builds a candidate from a pool holding exactly the given
// certificates, bypassing admission so the builder's own dry run is what is
// under test.
func assembleWith(t *testing.T, n *node, certs ...*types.Certificate) ([]*types.Certificate, error) {
	t.Helper()
	pool := mempool.New(n.p, mempool.DefaultPolicy())
	for _, c := range certs {
		// Admission would refuse these; the point is what the builder does when
		// something reaches it anyway.
		_ = pool.Add(c, n.chain.Snapshot().State, n.chain.Height())
	}
	m := &miner.Miner{Chain: n.chain, Pool: pool, Engine: pow.Dev{}, Payout: n.miner.Payout, Now: n.miner.Now}
	candidate, err := m.Assemble()
	if err != nil {
		return nil, err
	}
	return candidate.Certs, nil
}

// corruptOneCell writes a *well-formed* record that changes one cell and
// nothing else.
//
// This is the corruption model that matters. A torn or checksum-failing record
// is discarded wholesale, and because the metadata rides in the same batch the
// store rolls back to a consistent earlier commit on its own — correct
// behaviour, not corruption. What no checksum can catch is a persistence bug
// that wrote the wrong value perfectly: the bytes verify, the state is wrong,
// and only recomputing the root notices.
func corruptOneCell(t *testing.T, dir string) {
	t.Helper()
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}

	var target []byte
	if err := s.ScanPrefix([]byte("c/"), func(key, _ []byte) error {
		if target == nil {
			target = append([]byte(nil), key...)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if target == nil {
		t.Fatal("no cells to corrupt")
	}

	wrong := make([]byte, 32)
	wrong[31] = 0x2a
	b := &storage.Batch{}
	b.Put(target, wrong)
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func isCorruptState(err error) bool {
	for err != nil {
		if err == chain.ErrCorruptState {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestAnOlderLayoutVersionRefusesToOpen pins the guard the certificate-id
// redefinition turned out to depend on, and which nothing was watching.
//
// The version constant is the only one of the three startup guards that can
// see a change in what stored bytes *mean* while their shape stays the same.
// That change redefined the certificate id, which is the key this store writes
// seen entries under, and altered no record layout at all:
//
//   - `metaNetwork` holds the genesis id, and the genesis id did not move,
//     because no header or block encoding changed;
//   - the startup state-root check is blind by design, because the seen set is
//     deliberately excluded from the state root (core/state.Root) — so a seen
//     set keyed under the old rule reconciles against a perfectly correct root.
//
// Reproduced before the bump: a pre-upgrade database opened cleanly, and
// `state.Seen` answered true for the old-rule key and false for the new one.
// Every pre-upgrade certificate with a live TTL was includable again on the
// upgraded node, while a node synced from genesis rejected the same block — a
// split by upgrade path rather than by content, which is the shape where both
// sides are internally consistent and neither can be shown wrong from its own
// data.
//
// The assertion is deliberately on the *stored* version rather than on a
// hand-built directory: what must be refused is a database this build wrote
// under an earlier constant, which is what an upgrading user actually has.
func TestAnOlderLayoutVersionRefusesToOpen(t *testing.T) {
	p := devnetEasy()
	dir := t.TempDir()
	n := openNode(t, dir, p, key(t, 1).Persistent())
	n.mine(t, 3)
	n.close(t)

	// It opens as written. Without this the test could pass because the
	// directory is broken for some unrelated reason.
	reopened, err := chain.Open(dir, p)
	if err != nil {
		t.Fatalf("the directory does not open as written: %v", err)
	}
	reopened.Close()

	// Now age it: rewrite the recorded layout version to the one that was
	// current before the certificate id was redefined.
	if err := chain.WriteStoreVersionForTest(dir, chain.StoreVersionForTest()-1); err != nil {
		t.Fatal(err)
	}

	if _, err := chain.Open(dir, p); err == nil {
		t.Fatal("a database written under an older layout version opened; " +
			"every pre-upgrade certificate with a live TTL is includable again")
	} else if !errors.Is(err, chain.ErrWrongVersion) {
		t.Fatalf("got %v, want ErrWrongVersion", err)
	}
}
