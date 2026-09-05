package fold_test

import (
	"math"
	"strings"
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// key returns a deterministic key. Every artifact in this repository must be
// reproducible from source, tests included.
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

// bid is the standard shape a wallet produces: maxima far above the base fees
// so the certificate survives its TTL window, and modest priorities that are
// what the miner is actually paid. The headroom is free (R2-H1).
func bid() types.FeeBid {
	return wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10))
}

// world is a funded devnet plus the bookkeeping a test needs to keep a signer's
// Seq ascending.
type world struct {
	t     *testing.T
	p     *params.Params
	chain *harness.Chain
	miner *wallet.Key
	// payout is the address every block in the test pays. Keeping it distinct
	// from the addresses under test means a maturing coinbase never lands in
	// the middle of a balance assertion.
	payout   types.Address
	minerSeq uint64
	seqs     map[types.Address]uint64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	p := spec.Devnet()
	c := harness.MustNew(p)
	miner := key(t, 1)
	w := &world{t: t, p: p, chain: c, miner: miner, payout: miner.Persistent()}
	if err := c.MineUntilFunded(w.payout); err != nil {
		t.Fatal(err)
	}
	return w
}

// transfer builds a signed single-move transfer.
func (w *world) transfer(from *wallet.Key, fromAddr, to types.Address, amount u256.U256, seq uint64) *types.Certificate {
	w.t.Helper()
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, fromAddr, to, amount),
		Seq:     seq,
		TTL:     w.chain.NextHeight() + 10,
		Deposit: wallet.SelfDeposit(fromAddr, fromAddr),
		FeeBid:  bid(),
		Signers: []*wallet.Key{from},
	}
	cert, err := b.Build()
	if err != nil {
		w.t.Fatal(err)
	}
	return cert
}

// sweep builds a whole-cell native sweep out of a one-shot address: the
// deposit reserves the fee ceiling and the move sends every drop the
// reservation does not take, so the cell is empty when the certificate
// applies. F7b refuses a burn that leaves anything behind, so a test
// that means to burn an address has to sweep it — which is what a wallet does.
//
// The ceiling is probed with a throwaway build, exactly as cmd/zcd's sweep
// path does: the amount is a fixed-width field, so the probe's encoded size —
// and therefore its ceiling — is the real certificate's.
func (w *world) sweep(from *wallet.Key, src, to, refundTo types.Address, seq uint64) *types.Certificate {
	w.t.Helper()
	build := func(amount u256.U256) (*types.Certificate, error) {
		return (&wallet.Builder{
			Params:  w.p,
			Program: wallet.Tip(types.NativeAsset, src, to, amount),
			Seq:     seq,
			TTL:     w.chain.NextHeight() + 10,
			Deposit: wallet.SelfDeposit(src, refundTo),
			FeeBid:  bid(),
			Signers: []*wallet.Key{from},
		}).Build()
	}
	probe, err := build(u256.One)
	if err != nil {
		w.t.Fatal(err)
	}
	ceiling, ok := probe.FeeCeiling(w.p)
	if !ok {
		w.t.Fatal("fee ceiling overflows")
	}
	amount := w.chain.Balance(src).SatSub(ceiling)
	if amount.IsZero() {
		w.t.Fatal("the cell does not hold more than the fee ceiling; nothing to sweep")
	}
	cert, err := build(amount)
	if err != nil {
		w.t.Fatal(err)
	}
	return cert
}

// fund mines one block that moves coins from the miner to an address.
func (w *world) fund(to types.Address, amount u256.U256) {
	w.t.Helper()
	cert := w.transfer(w.miner, w.payout, to, amount, w.minerSeq)
	w.minerSeq++
	res := w.chain.MustAddBlock(w.payout, cert)
	if res.Outcomes[0].Outcome != fold.Applied {
		w.t.Fatalf("funding transfer was %s", res.Outcomes[0].Outcome)
	}
}

// TestGenesisIsReproducible pins the property the launch announcement rests on:
// block 0 is a pure function of the parameters.
func TestGenesisIsReproducible(t *testing.T) {
	p := spec.Mainnet()
	a := harness.MustNew(p)
	b := harness.MustNew(p)
	if a.Tip().ID() != b.Tip().ID() {
		t.Fatal("two genesis builds produced different block ids")
	}
	if a.State.Root() != b.State.Root() {
		t.Fatal("two genesis builds produced different state roots")
	}
	if a.Tip().StateRoot != a.State.Root() {
		t.Fatal("the genesis header does not commit to the genesis state")
	}
	// No allocation of any kind: the only cells genesis writes are protocol
	// cells, and no address holds a coin.
	for _, slot := range a.State.SortedCells() {
		if slot.Addr[0] != crypto.AddrVersionProtocol {
			t.Fatalf("genesis allocated a cell under a non-protocol address %x", slot.Addr)
		}
	}
	if a.State.SpentCount() != 0 || a.State.SeenCount() != 0 {
		t.Fatal("genesis is not a clean slate")
	}
}

// TestMineToPlay walks the launch dynamic: the first users of the chain are
// necessarily its miners, because a deposit needs a coin and a coin needs a
// block (R1-L3).
func TestMineToPlay(t *testing.T) {
	p := spec.Devnet()
	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()

	if err := c.Mine(payout, int(p.CoinbaseMaturity)); err != nil {
		t.Fatal(err)
	}
	if !c.Balance(payout).IsZero() {
		t.Fatal("a coinbase became spendable before it matured")
	}

	// The reward of block 1 is released exactly COINBASE_MATURITY blocks later,
	// and it is the producer's share of the subsidy — not the whole subsidy,
	// because the treasury took its basis points before the ring ever saw it.
	if err := c.Mine(payout, 1); err != nil {
		t.Fatal(err)
	}
	subsidy := p.Emission(1)
	want, _ := subsidy.Sub(subsidy.MulDiv64(p.TreasuryShareBps, 10000))
	if got := c.Balance(payout); !got.Eq(want) {
		t.Fatalf("matured balance = %s, want the producer share %s", got.String(), want.String())
	}
}

// TestTreasuryIsSealedByTheProtocolAddress connects the treasury cell to the
// rules that seal it, which nothing did before.
//
// The seal is real — V7 and F13 reject every write to a 0x00 address — but it
// was reached by *where the slot sits* rather than by anything asserted about
// the slot, and an unasserted property is one a later edit can delete in
// silence. Moving TreasurySlot to an ordinary user address, where the balance
// becomes spendable by anyone who can sign for it, used to leave core/fold,
// core/validity and sim green: only the golden vectors moved, and they moved
// because the state root did, which `make vectors` would have accepted without
// comment.
//
// Two assertions, and the first is the one that catches a relocation: the cell
// must live under the protocol address, and a certificate naming it must be
// refused by the rule that refuses protocol writes.
func TestTreasuryIsSealedByTheProtocolAddress(t *testing.T) {
	slot := types.TreasurySlot()
	if slot.Addr != crypto.ProtocolAddress {
		t.Fatalf("the treasury cell sits at %x, not the protocol address — "+
			"whatever else is true, it is no longer sealed by V7 or F13", slot.Addr[:8])
	}
	if slot.Word != types.BalanceWord(types.NativeAsset) {
		t.Fatal("the treasury is no longer the protocol address's native balance; " +
			"nativeSupply in the conservation property will stop counting it")
	}

	cert := &types.Certificate{
		Writes: []types.Write{{Slot: slot, Op: types.OpDeltaAdd, Value: drops(1)}},
	}
	if err := validity.CheckProtocolExclusion(cert); err == nil {
		t.Fatal("a certificate crediting the treasury passed V7")
	}

	// And the same rule must not be a special case written for this one slot:
	// it excludes the whole protocol address, beacon and fee cells included.
	for name, other := range map[string]types.Slot{
		"beacon epoch":     types.BeaconEpochSlot(),
		"sequential base":  types.SeqBaseFeeSlot(),
		"coinbase pending": types.PendingCoinbaseAmountSlot(0),
	} {
		c := &types.Certificate{Writes: []types.Write{{Slot: other, Op: types.OpSet, Value: drops(1)}}}
		if err := validity.CheckProtocolExclusion(c); err == nil {
			t.Fatalf("a certificate writing the %s cell passed V7", name)
		}
	}
}

// TestTreasuryAccrues follows the cell the subsidy's treasury share lands in:
// it is empty at genesis and grows by exactly the share on every block. That it
// cannot be *written* is a separate property with its own test above, because a
// test whose name claims a property it does not assert is worse than no test —
// it stops anyone from writing the real one.
func TestTreasuryAccrues(t *testing.T) {
	p := spec.Devnet()
	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()

	// Genesis pays no subsidy, so it credits no treasury — the cell is absent
	// rather than present-and-zero, which is what lets `zcd genesis` report
	// no allocations of any kind.
	if !c.State.Get(types.TreasurySlot()).IsZero() {
		t.Fatal("the genesis block allocated to the treasury")
	}

	const blocks = 5
	total := u256.Zero
	for i := 0; i < blocks; i++ {
		if err := c.Mine(payout, 1); err != nil {
			t.Fatal(err)
		}
		subsidy := p.Emission(c.Height())
		share := subsidy.MulDiv64(p.TreasuryShareBps, 10000)
		total, _ = total.Add(share)
		if got := c.State.Get(types.TreasurySlot()); !got.Eq(total) {
			t.Fatalf("after %d blocks the treasury holds %s, want %s",
				i+1, got.String(), total.String())
		}
	}

	// Unlike the producer's share, the treasury's never entered the maturity
	// ring: it is already in the cell, and the ring is empty of it.
	if total.IsZero() {
		t.Fatal("the treasury never accrued; the test proves nothing")
	}
}

// TestTransferApplies is the happy path end to end.
func TestTransferApplies(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(1_000_000_000))

	before := w.chain.Balance(alice.Persistent())
	amount := drops(250_000_000)
	cert := w.transfer(alice, alice.Persistent(), bob.Persistent(), amount, 0)

	res := w.chain.MustAddBlock(w.payout, cert)
	if len(res.Outcomes) != 1 || res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("outcome = %v, want APPLIED", res.Outcomes)
	}
	if got := w.chain.Balance(bob.Persistent()); !got.Eq(amount) {
		t.Fatalf("recipient balance = %s, want %s", got.String(), amount.String())
	}

	// The sender pays the amount plus the actual fee and gets the rest of the
	// deposit back within the same fold step: liquidity is locked for exactly
	// one certificate lifetime, never longer.
	spent := before.SatSub(w.chain.Balance(alice.Persistent()))
	want := amount.SatAdd(res.Outcomes[0].Charged)
	if !spent.Eq(want) {
		t.Fatalf("sender spent %s, want %s (amount + charge)", spent.String(), want.String())
	}
}

// TestSkipIsSemanticsNotFailure: a certificate whose guard no longer holds is
// skipped and billed, and the block stays valid. Inclusion and application are
// different events.
func TestSkipIsSemanticsNotFailure(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)

	// Alice holds enough for one of the two transfers she signs, plus deposits.
	w.fund(alice.Persistent(), drops(700_000_000))

	half := drops(400_000_000)
	first := w.transfer(alice, alice.Persistent(), bob.Persistent(), half, 0)
	second := w.transfer(alice, alice.Persistent(), bob.Persistent(), half, 1)

	res := w.chain.MustAddBlock(w.payout, first, second)
	if len(res.Outcomes) != 2 {
		t.Fatalf("got %d outcomes, want 2", len(res.Outcomes))
	}
	// Seq ordering decides which is which: Alice's own certificates commit in
	// the order she signed them (R1-C2).
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("first outcome = %s, want APPLIED", res.Outcomes[0].Outcome)
	}
	if res.Outcomes[1].Outcome != fold.SkippedStale {
		t.Fatalf("second outcome = %s, want SKIPPED_STALE", res.Outcomes[1].Outcome)
	}
	if !res.Outcomes[1].Charged.Eq(w.p.SkipFee) {
		t.Fatalf("skip charged %s, want the constant skip fee %s",
			res.Outcomes[1].Charged.String(), w.p.SkipFee.String())
	}
	if got := w.chain.Balance(bob.Persistent()); !got.Eq(half) {
		t.Fatalf("recipient got %s, want exactly one transfer of %s", got.String(), half.String())
	}
}

// TestSeqOrderingSurvivesProposerShuffling is R1-C2: a proposer may present a
// signer's dependent chain in any order, and the fold must erase the choice.
func TestSeqOrderingSurvivesProposerShuffling(t *testing.T) {
	run := func(reverse bool) types.Hash {
		w := newWorld(t)
		alice, bob := key(t, 2), key(t, 3)
		w.fund(alice.Persistent(), drops(900_000_000))

		a := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(400_000_000), 0)
		b := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(400_000_000), 1)
		if reverse {
			w.chain.MustAddBlock(w.payout, b, a)
		} else {
			w.chain.MustAddBlock(w.payout, a, b)
		}
		return w.chain.State.Root()
	}

	if run(false) != run(true) {
		t.Fatal("the fold's state depends on the order the proposer chose")
	}
}

// TestDroppedIsNotBilledAndNotSeen: a deposit that is valid at admission and
// gone at commit has nothing to charge. The certificate touches no state and
// stays resubmittable.
func TestDroppedIsNotBilledAndNotSeen(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)

	// Alice is not funded at all, so her deposit cannot be reserved.
	cert := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1), 0)
	res := w.chain.MustAddBlock(w.payout, cert)

	if res.Outcomes[0].Outcome != fold.Dropped {
		t.Fatalf("outcome = %s, want DROPPED", res.Outcomes[0].Outcome)
	}
	if !res.Outcomes[0].Charged.IsZero() {
		t.Fatal("a dropped certificate was billed")
	}
	if _, seen := w.chain.State.Seen(cert.ID()); seen {
		t.Fatal("a dropped certificate was marked seen; it can never be resubmitted")
	}
}

// TestTipsCommute is the central claim of the whitepaper, exercised: a stream
// of credits into one cell produces zero conflicts and zero skips, in any order.
func TestTipsCommute(t *testing.T) {
	const tippers = 12
	streamer := key(t, 9)

	build := func(reverse bool) types.Hash {
		w := newWorld(t)
		keys := make([]*wallet.Key, tippers)
		for i := range keys {
			keys[i] = key(t, byte(20+i))
			w.fund(keys[i].Persistent(), drops(500_000_000))
		}
		// The tip certificates are built only after all funding has landed, so
		// that every one of them carries a live TTL.
		certs := make([]*types.Certificate, tippers)
		for i, k := range keys {
			certs[i] = w.transfer(k, k.Persistent(), streamer.Persistent(), drops(1_000_000), 0)
		}
		if reverse {
			for i, j := 0, len(certs)-1; i < j; i, j = i+1, j-1 {
				certs[i], certs[j] = certs[j], certs[i]
			}
		}

		res := w.chain.MustAddBlock(w.payout, certs...)
		for i, o := range res.Outcomes {
			if o.Outcome != fold.Applied {
				t.Fatalf("tip %d was %s; tips must never conflict", i, o.Outcome)
			}
		}
		if got := w.chain.Balance(streamer.Persistent()); !got.Eq(drops(tippers * 1_000_000)) {
			t.Fatalf("streamer received %s, want %d tips", got.String(), tippers)
		}
		return w.chain.State.Root()
	}

	if build(false) != build(true) {
		t.Fatal("tip order changed the state; deltas do not commute")
	}
}

// TestThirdPartyCreditCannotCauseASkip is the poisoning-immunity theorem
// (R1-N1) in one test: a credit strictly helps a >= guard, so nobody can make
// somebody else's transfer skip.
func TestThirdPartyCreditCannotCauseASkip(t *testing.T) {
	w := newWorld(t)
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)
	w.fund(alice.Persistent(), drops(900_000_000))
	w.fund(bob.Persistent(), drops(900_000_000))

	start := w.chain.Balance(alice.Persistent())

	// Alice signs against the balance she can see right now.
	pending := w.transfer(alice, alice.Persistent(), carol.Persistent(), drops(100_000_000), 0)

	// Bob pushes Alice's balance up before it commits.
	w.chain.MustAddBlock(w.payout, w.transfer(bob, bob.Persistent(), alice.Persistent(), drops(50_000_000), 0))
	if w.chain.Balance(alice.Persistent()).Eq(start) {
		t.Fatal("the credit did not land; the test proves nothing")
	}

	res := w.chain.MustAddBlock(w.payout, pending)
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("outcome = %s; a third party's credit caused a skip", res.Outcomes[0].Outcome)
	}
}

// TestABATolerance: applicability compares values, not versions. A balance that
// moved away and back is still applicable, so the fold skips strictly less
// often than version-based concurrency control would.
func TestABATolerance(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))
	w.fund(bob.Persistent(), drops(900_000_000))

	// Bob's transfer is pinned to the asset's minted cell by an EXACT read in a
	// mint; for the native coin the equivalent is a guard, so exercise the
	// property directly: move a balance away and back, then commit.
	mid := w.chain.Balance(bob.Persistent())
	w.chain.MustAddBlock(w.payout, w.transfer(bob, bob.Persistent(), alice.Persistent(), drops(10_000_000), 0))
	afterOut := w.chain.Balance(bob.Persistent())
	if afterOut.Eq(mid) {
		t.Fatal("the outbound move did not land")
	}

	pending := w.transfer(bob, bob.Persistent(), alice.Persistent(), drops(1_000_000), 1)
	w.chain.MustAddBlock(w.payout, w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0))

	res := w.chain.MustAddBlock(w.payout, pending)
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("outcome = %s; a slot that returned to a covered value skipped", res.Outcomes[0].Outcome)
	}
}

// sweepTo is sweep with an explicit payee amount: the source cell is emptied
// by sending `to` the given amount and the rest to `rest`.
func (w *world) sweepTo(from *wallet.Key, src, to, refundTo types.Address, amount u256.U256, seq uint64) *types.Certificate {
	w.t.Helper()
	build := func(a1, a2 u256.U256) (*types.Certificate, error) {
		return (&wallet.Builder{
			Params: w.p,
			Program: wallet.Transfer(
				types.Move{Asset: types.NativeAsset, Src: src, Dst: to, Amount: a1},
				types.Move{Asset: types.NativeAsset, Src: src, Dst: refundTo, Amount: a2},
			),
			Seq:     seq,
			TTL:     w.chain.NextHeight() + 10,
			Deposit: wallet.SelfDeposit(src, refundTo),
			FeeBid:  bid(),
			Signers: []*wallet.Key{from},
		}).Build()
	}
	probe, err := build(amount, u256.One)
	if err != nil {
		w.t.Fatal(err)
	}
	ceiling, ok := probe.FeeCeiling(w.p)
	if !ok {
		w.t.Fatal("ceiling overflow")
	}
	rest := w.chain.Balance(src).SatSub(ceiling).SatSub(amount)
	cert, err := build(amount, rest)
	if err != nil {
		w.t.Fatal(err)
	}
	return cert
}

// strangerSeq hands out ascending Seq values per key, so a test can commit
// several certificates from one signer without them ordering against each
// other.
func (w *world) strangerSeq(k *wallet.Key) uint64 {
	if w.seqs == nil {
		w.seqs = make(map[types.Address]uint64)
	}
	a := k.Persistent()
	n := w.seqs[a]
	w.seqs[a] = n + 1
	return n
}

// issueAsset issues an asset from a key's persistent address and returns its id.
func (w *world) issueAsset(k *wallet.Key, seq uint64) types.Address {
	w.t.Helper()
	cert, err := (&wallet.Builder{
		Params: w.p,
		Program: wallet.Issue(k.Persistent(), drops(1_000_000_000), 6,
			types.Hash{'A', 'S', 'T'}, k.PubKey()),
		Seq:     w.strangerSeq(k),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(k.Persistent(), k.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{k},
	}).Build()
	if err != nil {
		w.t.Fatal(err)
	}
	asset := types.DeriveAssetAddress(w.p.ChainID, k.Persistent(), cert.Seq)
	if res := w.chain.MustAddBlock(w.payout, cert); res.Outcomes[0].Outcome != fold.Applied {
		w.t.Fatalf("issue was %s", res.Outcomes[0].Outcome)
	}
	mint, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Mint(asset, k.Persistent(), drops(1_000_000), drops(1_000_000_000), k.PubKey()),
		Seq:     w.strangerSeq(k),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(k.Persistent(), k.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{k},
	}).Build()
	if err != nil {
		w.t.Fatal(err)
	}
	if res := w.chain.MustAddBlock(w.payout, mint); res.Outcomes[0].Outcome != fold.Applied {
		w.t.Fatalf("mint was %s", res.Outcomes[0].Outcome)
	}
	return asset
}

// assetTip is a single-move TRANSFER of a non-native asset.
func (w *world) assetTip(k *wallet.Key, from, to, asset types.Address, amount u256.U256) *types.Certificate {
	w.t.Helper()
	cert, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(asset, from, to, amount),
		Seq:     w.strangerSeq(k),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(from, from),
		FeeBid:  bid(),
		Signers: []*wallet.Key{k},
	}).Build()
	if err != nil {
		w.t.Fatal(err)
	}
	return cert
}

// TestTTLHorizonIsACeilingAtEveryAcceptedTTLMax pins what B2 is for: it is the
// ceiling on how far ahead a certificate's TTL may reach, and it must be that
// ceiling for every ttl_max params.Validate accepts — not only for the small
// ones the shipped networks carry.
//
// It did not hold. B2 was written as `c.TTL > h.Height+p.TTLMax`, and that sum
// wraps: at ttl_max = 2^64-1, the most permissive horizon expressible and one
// Validate accepts, the sum is h.Height-1, so every certificate B1 had just
// admitted was refused here. The rule stated as a ceiling was a blanket refusal
// of every certificate in every block.
//
// The sum cannot be repaired by bounding ttl_max, which is why this is fixed in
// the rule rather than in Validate: h.Height is unbounded chain state, so for
// every ttl_max above zero there is a height at which h.Height+ttl_max wraps.
// resignUnder returns a copy of c whose signatures are made over p's signing
// message instead of the one c was built with, leaving the body byte-identical.
//
// It exists for the parameter-perturbation tests. A test that folds one block
// under several parameter sets is asking about one rule at several values, and
// the signing message binds the consensus root — so the certificate
// has to be re-signed for each set or V2 answers first and the test measures
// the binding instead of the rule it names.
//
// The id is checked rather than assumed: if a future edit moved a body field
// here, the block would no longer carry the authorization the test built.
func resignUnder(t *testing.T, c *types.Certificate, p *params.Params, k *wallet.Key) *types.Certificate {
	t.Helper()
	out := *c
	out.Sigs = append([]types.Sig(nil), c.Sigs...)
	msg := out.SigningMessage(p)
	for i := range out.Sigs {
		if out.Sigs[i].PubKey != k.PubKey() {
			t.Fatalf("signature %d is not the key this helper holds; it cannot re-sign it", i)
		}
		out.Sigs[i].Sig = k.Sign(msg)
	}
	if out.ID() != c.ID() {
		t.Fatal("re-signing moved the certificate id; the body is not what it was")
	}
	if err := validity.CheckSignatures(&out, p); err != nil {
		t.Fatalf("the re-signed witness does not verify under its own parameter set: %v", err)
	}
	return &out
}

func TestTTLHorizonIsACeilingAtEveryAcceptedTTLMax(t *testing.T) {
	w := newWorld(t)
	cert := w.transfer(w.miner, w.payout, key(t, 7).Persistent(), drops(1_000), w.minerSeq)
	blk, err := w.chain.Propose(w.payout, cert)
	if err != nil {
		t.Fatal(err)
	}
	height := blk.Header.Height
	ahead := cert.TTL - height
	if ahead == 0 {
		t.Fatal("the witness certificate expires in the block that carries it; it cannot probe a horizon")
	}

	for _, c := range []struct {
		name   string
		ttlMax uint64
		want   bool // block passes the rules
	}{
		// The baseline: this block is valid under the parameters it was built
		// for. Without it a refusal below could be any rule at all, and the
		// witness could be one B2 never reaches.
		{"the shipped devnet horizon", w.p.TTLMax, true},
		{"exactly the distance ahead", ahead, true},
		{"one short of it", ahead - 1, false},
		{"the widest horizon Validate accepts", math.MaxUint64, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := *w.p
			p.TTLMax = c.ttlMax
			if err := p.Validate(); err != nil {
				t.Fatalf("ttl_max %d is not a value Validate accepts, so this row "+
					"says nothing about the rule: %v", c.ttlMax, err)
			}
			// The witness has to be signed under the row's own parameter set.
			// The signing message binds the consensus root, and ttl_max is a
			// consensus parameter, so a certificate signed under the shipped
			// ttl_max fails V2 under any other one — and V2 runs inside
			// checkCertificates, ahead of B2. Every row below the first would
			// then be a row about V2.
			//
			// Only the signature bytes are rebuilt. The body is untouched, so
			// the certificate id, the TTL and the height B2 reads are the same
			// ones the baseline block carried; the assertion under the loop
			// pins that rather than assuming it.
			rowBlk := *blk
			rowBlk.Certs = []*types.Certificate{resignUnder(t, cert, &p, w.miner)}
			rowBlk.Header.CertRoot = rowBlk.ComputeCertRoot(&p)

			err := fold.CheckBlockRules(w.chain.State.Clone(), &rowBlk, &p)
			if got := err == nil; got != c.want {
				t.Fatalf("ttl_max %d: block accepted=%v, want %v (err %v)",
					c.ttlMax, got, c.want, err)
			}
			if c.want {
				return
			}
			// A refusal has to be B2's refusal. A row that passes because some
			// other rule fired asserts nothing about the horizon.
			if !strings.Contains(err.Error(), "B2") {
				t.Fatalf("ttl_max %d was refused by something other than B2: %v", c.ttlMax, err)
			}
		})
	}

	t.Run("the widest horizon is one the old sum could not express", func(t *testing.T) {
		// Why the row above is the witness and not just a large number: it is
		// on the far side of the wrap. Asserted, because a horizon row that did
		// not wrap would pass with the defect still in place.
		if height+math.MaxUint64 >= height {
			t.Fatalf("height %d + ttl_max %d does not wrap; the row above cannot "+
				"distinguish the sum from the distance", height, uint64(math.MaxUint64))
		}
		// And the form the fix installs answers correctly there without any
		// bound on ttl_max: the distance ahead is small, and it is what the
		// rule's own error message already reported.
		if cert.TTL-height != ahead {
			t.Fatalf("the distance form disagrees with the witness: %d != %d",
				cert.TTL-height, ahead)
		}
	})
}
