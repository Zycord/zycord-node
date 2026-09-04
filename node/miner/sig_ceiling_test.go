package miner_test

import (
	"errors"
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/miner"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// The B18 selection suite.
//
// B18 is the per-block signature ceiling (`core/fold/blockrules.go`): the
// certificates of one block may declare at most `MaxSigsPerBlock(T)`
// signatures between them, counted before the fold verifies any of them. It
// is a *receiver-cost* bound — it exists because `gas_par_per_sig` cannot both
// bound verification and price the parallel market.
//
// It used to be the one block ceiling `miner.Select` did not enforce. `Select`
// enforced four of the five — B12 by `certCeiling`, B13 by the running byte
// total, B5 by `seqLimit`, B6 by `parLimit` — and never summed `len(c.Sigs)`,
// because B18 shipped after `Select` was written and the packing loop was not
// revisited (finding I8-M1).
//
// The consequence was not an invalid block: `Chain.Apply` is authoritative and
// would refuse one. It was that the refusal is *unattributable*, and that no
// other part of assembly can recover from that. B18 reports through
// `invalid()` rather than `invalidCert(i, …)` — correctly, because it is a
// genuine block-level property with no single culpable certificate — so
// `dropTheDrops`' `errors.As(err, &cre)` recovery finds no index, falls
// through to its "not attributable to any one certificate" arm, and returns
// the error. `Assemble` propagated it and `MineOneWhile` returned without
// retrying; there is no empty-block floor on that path, because the floor at
// `return nil, nil` sits *inside* the `CertRuleError` branch B18 never enters.
// One signature-dense pool and the node produced no blocks at all until the
// certificates aged out of their own TTL window.
//
// **The fix is in the builder, not in the fold.** `Select` now carries a
// running signature total against `MaxSigsPerBlock(T)`, exactly as it already
// carried running gas, byte and certificate totals; the over-dense pool is
// trimmed and a slightly smaller block is proposed. Nothing about B18 itself
// changes, and it stays unattributable on purpose: naming an index in a sum
// over every certificate would be a fiction, and it is not needed once the
// builder cannot offer such a set. The guarantee is structural — `Select`'s
// output satisfies B18, `dropTheDrops` only ever *removes* certificates from
// that output, and removing a certificate can only lower the sum, which is the
// same argument `Assemble` already makes for the other ceilings.
//
// So this suite is the regression guard for a defect that is fixed, and the
// three tests below assert, in order: `Select` respects the ceiling; the fold
// still refuses an over-dense block by name and still without an index; and a
// signature-dense pool no longer stops block production.
//
// None of this changes the reachability story recorded for the parameter
// freeze: at shipped genesis parameters B5 binds well before B18 and the stall
// could not be provoked. The witnesses below run on devnet parameters, where
// the sig ceiling is the first to bind and the defect is therefore visible at
// a pool size a test can build.

func sigDrops(n uint64) u256.U256 { return u256.FromUint64(n) }

// retireOfWidth builds one RETIRE burning n one-shot addresses, paying its
// deposit from the persistent twin of the first key. The twin is persistent,
// so no extra MARK_SPENT is derived and the certificate carries exactly n
// signatures — the densest signature-per-certificate shape Era 0 offers.
func retireOfWidth(t *testing.T, p *params.Params, run, n, ttl uint64) *types.Certificate {
	t.Helper()
	addrs := make([]types.Address, 0, n)
	keys := make([]*wallet.Key, 0, n)
	for j := uint64(0); j < n; j++ {
		k := benchKey(2_000_000 + run*128 + j)
		addrs = append(addrs, k.OneShot())
		keys = append(keys, k)
	}
	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(addrs...),
		TTL:     ttl,
		Deposit: wallet.SelfDeposit(keys[0].Persistent(), keys[0].Persistent()),
		FeeBid:  wallet.Bid(sigDrops(50_000), sigDrops(1_000), sigDrops(500), sigDrops(10)),
		Signers: keys,
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(c.Sigs)) != n {
		t.Fatalf("built a certificate with %d signatures, want %d: the fixture is not armed",
			len(c.Sigs), n)
	}
	return c
}

// signatureDensePool builds the smallest pool that clears the B18 ceiling, and
// fails the test if that pool is not strictly inside every other block ceiling
// — otherwise the witness would be measuring B12, B13, B5 or B6 instead.
func signatureDensePool(t *testing.T, p *params.Params, tgt, base uint64) []*types.Certificate {
	t.Helper()
	return signatureDensePoolAt(t, p, tgt, base, 5)
}

// signatureDensePoolAt is signatureDensePool with an explicit TTL, for the
// witness that has to mine a hundred blocks of funding first.
func signatureDensePoolAt(t *testing.T, p *params.Params, tgt, base, ttl uint64) []*types.Certificate {
	t.Helper()
	ceiling := p.MaxSigsPerBlock(tgt)
	perCert := uint64(p.MaxSigs)
	n := ceiling/perCert + 1

	pool := make([]*types.Certificate, 0, n)
	for i := uint64(0); i < n; i++ {
		pool = append(pool, retireOfWidth(t, p, base+i, perCert, ttl))
	}

	if len(pool) > p.MaxCertsPerBlock(tgt) {
		t.Fatalf("the pool of %d exceeds the certificate ceiling of %d; the witness "+
			"measures B12, not B18", len(pool), p.MaxCertsPerBlock(tgt))
	}
	var seq, par uint64
	var bytes int
	for _, c := range pool {
		seq += c.SeqGas(p)
		par += c.ParGas(p)
		bytes += c.SizeBytes()
	}
	if seq > p.SeqGasLimit(tgt) || par > p.ParGasLimit(tgt) {
		t.Fatalf("the pool exceeds a gas ceiling (seq %d/%d, par %d/%d); the witness "+
			"measures B5 or B6, not B18",
			seq, p.SeqGasLimit(tgt), par, p.ParGasLimit(tgt))
	}
	if bytes > p.BlockByteLimit(tgt) {
		t.Fatalf("the pool of %d bytes exceeds the byte ceiling of %d; the witness "+
			"measures B13, not B18", bytes, p.BlockByteLimit(tgt))
	}
	return pool
}

// TestSelectRespectsTheBlockSignatureCeiling is the defect, stated as the
// property that should hold.
func TestSelectRespectsTheBlockSignatureCeiling(t *testing.T) {
	p := spec.Devnet()
	tgt := p.SeqGasTargetGenesis
	ceiling := p.MaxSigsPerBlock(tgt)
	pool := signatureDensePool(t, p, tgt, 0)

	sel := miner.Select(pool, p, p.InitialSeqBaseFee, p.InitialParBaseFee, tgt)

	var sigs uint64
	for _, c := range sel {
		sigs += uint64(len(c.Sigs))
	}
	t.Logf("pool: %d certificates; B18 ceiling %d signatures; Select took %d certificates "+
		"carrying %d signatures", len(pool), ceiling, len(sel), sigs)

	if sigs > ceiling {
		t.Errorf("Select returned %d certificates declaring %d signatures, above the B18 "+
			"ceiling of %d: the selected set cannot be sealed into a valid block",
			len(sel), sigs, ceiling)
	}
}

// TestASelectedSetOverB18IsAnUnattributableBlockRefusal pins the fold-side
// half of the finding, which the fix deliberately leaves standing.
//
// It builds the over-dense block directly rather than through `Select`, so it
// measures the fold and not the builder, and asserts the two halves that
// together remove any recovery path *inside* assembly: the block is refused
// naming B18, and the refusal carries no certificate index. Both must stay
// true. The first is consensus. The second is why the fix had to be in
// `Select`: as long as B18 is unattributable — and it should be, since the sum
// is over every certificate and no one of them is culpable — a builder that
// can construct such a set has no way back, so it must not construct one.
func TestASelectedSetOverB18IsAnUnattributableBlockRefusal(t *testing.T) {
	p := spec.Devnet()
	tgt := p.SeqGasTargetGenesis
	pool := signatureDensePool(t, p, tgt, 1_000)

	c := harness.MustNew(p)
	payout := benchKey(9_999_999).Persistent()
	if err := c.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}

	b, err := c.Propose(payout, pool...)
	if err != nil {
		// Propose folds the block itself on some paths; a refusal here is the
		// same refusal, and what matters is which rule names it.
		if got := fold.Rule(err); got != "B18" {
			t.Fatalf("Propose failed naming %q, want B18: %v", got, err)
		}
		assertUnattributable(t, err)
		return
	}

	err = fold.CheckBlockRules(c.State, b, p)
	if err == nil {
		t.Fatal("a block declaring more signatures than B18 allows was accepted")
	}
	if got := fold.Rule(err); got != "B18" {
		t.Fatalf("block refused naming %q, want B18: the witness is not armed (%v)", got, err)
	}
	assertUnattributable(t, err)
}

// TestASignatureDensePoolDoesNotStopBlockProduction is the finding at the
// altitude an operator sees it: not "the selected set is over a ceiling" but
// "this node has stopped mining".
//
// The pool holds only certificates that are individually valid and that the
// pool itself admitted. Nothing sheds them — `Pool.OnBlock` is what would, and
// it runs only downstream of a successful `Apply`, which never happens because
// `Assemble` never returns a block. So the stall persists until the
// certificates time out of their own TTL window.
//
// Before the fix `Assemble` returned an error rather than a block, and kept
// doing so on every retry. It now trims the pool to the ceiling and proposes
// the smaller block, which is what this asserts.
func TestASignatureDensePoolDoesNotStopBlockProduction(t *testing.T) {
	m := sealHarness(t)
	p := m.Chain.Params()
	tgt := p.SeqGasTargetGenesis

	// Mine one block first, so the stall below is a change of behaviour rather
	// than a node that never worked.
	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("assembling an empty block: %v", err)
	}
	if err := m.Seal(b, 1<<20); err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if _, err := m.Chain.Apply(b); err != nil {
		t.Fatalf("applying: %v", err)
	}

	// Fund the flood's deposit cells for real, and only then build the
	// certificates — their TTLs are relative to the tip, so funding first is
	// what keeps them live when they are offered to the pool.
	//
	// The pool's aggregate deposit screen is a genuine Sybil defence
	// (mempool.md §2.5) and would otherwise refuse the whole flood. An
	// attacker who has bought coins is the premise of this witness, not the
	// thing under test, so the funding is done rather than assumed away.
	if !fundDeposits(t, m, signatureDensePool(t, p, tgt, 5_000)) {
		t.Skip("could not fund the flood's deposit cells; the stall is not armed")
	}
	pool := signatureDensePoolAt(t, p, tgt, 5_000, m.Chain.Snapshot().Height+20)

	view := m.Chain.Snapshot()
	admitted := 0
	for _, c := range pool {
		if err := m.Pool.Add(c, view.State, view.Height); err == nil {
			admitted++
		}
	}
	t.Logf("%d of %d signature-dense certificates admitted to the pool", admitted, len(pool))

	var sigs uint64
	for _, c := range m.Pool.Candidates() {
		sigs += uint64(len(c.Sigs))
	}
	if sigs <= p.MaxSigsPerBlock(tgt) {
		t.Skipf("the pool holds %d signatures, at or under the ceiling of %d: the pool's "+
			"own admission rules refused enough of the flood that the stall is not armed. "+
			"That is itself worth knowing, and it is not what this test measures.",
			sigs, p.MaxSigsPerBlock(tgt))
	}

	for attempt := 1; attempt <= 3; attempt++ {
		got, err := m.Assemble()
		if err != nil {
			t.Logf("attempt %d: Assemble failed: %v", attempt, err)
			if attempt == 3 {
				t.Fatalf("a pool of %d signatures against a B18 ceiling of %d stopped this node "+
					"producing blocks entirely, on three successive attempts, with no "+
					"smaller-block fallback: %v", sigs, p.MaxSigsPerBlock(tgt), err)
			}
			continue
		}

		// A block was produced, which is the property. The rest of the check
		// is that it is a block worth having: an assembler could satisfy this
		// test by proposing nothing at all, and an empty block under a full
		// pool is the stall wearing a different coat.
		var built uint64
		for _, c := range got.Certs {
			built += uint64(len(c.Sigs))
		}
		t.Logf("attempt %d: Assemble returned a block of %d certificates carrying %d "+
			"signatures, against a ceiling of %d",
			attempt, len(got.Certs), built, p.MaxSigsPerBlock(tgt))
		if len(got.Certs) == 0 {
			t.Fatalf("Assemble proposed an empty block from a pool of %d certificates: "+
				"production did not stop, but the pool is not being drained either",
				len(m.Pool.Candidates()))
		}
		if built > p.MaxSigsPerBlock(tgt) {
			t.Fatalf("the proposed block declares %d signatures, above the B18 ceiling "+
				"of %d", built, p.MaxSigsPerBlock(tgt))
		}
		if err := fold.CheckBlockRules(m.Chain.Snapshot().State, got, p); err != nil {
			t.Fatalf("the proposed block does not pass the block rules: %v", err)
		}
		return
	}
}

// fundDeposits mines to a key the test controls and then pays each of the
// flood's deposit cells enough to clear the pool's aggregate deposit screen.
//
// It reports false rather than failing when the funding cannot be completed,
// so that a change in the maturity schedule or the fee ceilings turns this
// witness into a skip with a reason rather than into a failure blamed on the
// defect under test.
func fundDeposits(t *testing.T, m *miner.Miner, pool []*types.Certificate) bool {
	t.Helper()
	funder := benchKey(7_777_777)
	m.Payout = funder.Persistent()

	// Mine past coinbase maturity so the funder actually holds spendable coin.
	p := m.Chain.Params()
	// Enough blocks that the funder can cover every deposit cell in the flood.
	// The emission schedule is what it is, so the count is derived from the
	// requirement rather than guessed: mine until the balance covers the sum,
	// with a hard stop so a schedule change turns this into a skip.
	need := u256.Zero
	for _, c := range pool {
		ceiling, ok := c.FeeCeiling(p)
		if !ok {
			return false
		}
		need = need.SatAdd(ceiling).SatAdd(sigDrops(50_000_000))
	}
	const maxFundingBlocks = 4000
	for i := uint64(0); i < maxFundingBlocks; i++ {
		if i >= p.CoinbaseMaturity+2 &&
			!m.Chain.Snapshot().State.Get(types.NativeBalanceSlot(funder.Persistent())).Lt(need) {
			break
		}
		b, err := m.Assemble()
		if err != nil {
			t.Logf("funding: assemble at %d: %v", i, err)
			return false
		}
		if err := m.Seal(b, 1<<20); err != nil {
			t.Logf("funding: seal at %d: %v", i, err)
			return false
		}
		if _, err := m.Chain.Apply(b); err != nil {
			t.Logf("funding: apply at %d: %v", i, err)
			return false
		}
	}

	view := m.Chain.Snapshot()
	if view.State.Get(types.NativeBalanceSlot(funder.Persistent())).IsZero() {
		t.Log("funding: the funder holds nothing after maturity")
		return false
	}

	// One multi-move TRANSFER per batch, paying every deposit cell the flood
	// declares. Each needs at least its own fee ceiling.
	moves := make([]types.Move, 0, len(pool))
	for _, c := range pool {
		ceiling, ok := c.FeeCeiling(p)
		if !ok {
			return false
		}
		moves = append(moves, types.Move{
			Asset:  types.NativeAsset,
			Src:    funder.Persistent(),
			Dst:    c.Deposit.Cell.Addr,
			Amount: ceiling.SatAdd(sigDrops(50_000_000)),
		})
	}

	seq := uint64(0)
	for len(moves) > 0 {
		n := p.MaxMovesPerTransfer
		if n > len(moves) {
			n = len(moves)
		}
		batch := moves[:n]
		moves = moves[n:]

		fc, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Transfer(batch...),
			Seq:     seq,
			TTL:     m.Chain.Snapshot().Height + 20,
			Deposit: wallet.SelfDeposit(funder.Persistent(), funder.Persistent()),
			FeeBid:  wallet.Bid(sigDrops(50_000), sigDrops(1_000), sigDrops(500), sigDrops(10)),
			Signers: []*wallet.Key{funder},
		}).Build()
		if err != nil {
			t.Logf("funding: build: %v", err)
			return false
		}
		seq++

		v := m.Chain.Snapshot()
		if err := m.Pool.Add(fc, v.State, v.Height); err != nil {
			t.Logf("funding: pool add: %v", err)
			return false
		}
		b, err := m.Assemble()
		if err != nil {
			t.Logf("funding: assemble: %v", err)
			return false
		}
		if err := m.Seal(b, 1<<20); err != nil {
			t.Logf("funding: seal: %v", err)
			return false
		}
		res, err := m.Chain.Apply(b)
		if err != nil {
			t.Logf("funding: apply: %v", err)
			return false
		}
		m.Pool.OnBlock(b, m.Chain.Snapshot().State, m.Chain.Snapshot().Height)
		for _, o := range res.Outcomes {
			if o.Outcome != fold.Applied {
				t.Logf("funding: a funding transfer was %s, not APPLIED", o.Outcome)
				return false
			}
		}
	}
	return true
}

func assertUnattributable(t *testing.T, err error) {
	t.Helper()
	var cre *fold.CertRuleError
	if errors.As(err, &cre) {
		t.Fatalf("B18 reported an attributable index %d; dropTheDrops would recover "+
			"and this would not be a stall", cre.Index)
	}
	t.Logf("B18 refusal is unattributable, as expected: %v", err)
}
