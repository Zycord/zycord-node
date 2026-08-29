package sim_test

// Rule B6 — a block's aggregate parallel gas against ParGasLimit(T) — is the
// one block-shape ceiling of the family that **cannot be reached at any shipped
// parameter set**, and TestB6CannotFireOnAnyBlockTheByteCeilingAdmits proves it
// rather than measures it: B6 asks 3.84 parallel gas per block byte at mainnet
// and 16 at testnet and devnet, and no certificate the V-rules admit supplies
// more than the derived Era-0 ceiling of 3.0352.
//
// That is why this file exists and why it is separate from
// sim/block_ceiling_boundary_test.go, where **no parameter is modified
// anywhere**. B12, B13 and B15 are reachable as shipped, so a witness there
// would be a fixture pretending to be a measurement. B6 is the other class the
// twice-written-rule census names: the boundary is unreachable at every shipped
// set, so the only honest instrument is a **legal-but-unshipped witness
// supplying the antecedent**, and the discipline that keeps such a row from
// being a statement about its own fixture is that the conclusion must survive
// **two witnesses on two different axes**.
//
// **The two axes, and why they are independent.**
//
//	par_gas_ratio            moves B6's own ceiling and nothing else. Every
//	                         other ceiling the block runs between — B13's
//	                         bytes, B12's count, B5's sequential gas — keeps
//	                         its shipped value, so a block that reaches B6
//	                         here reaches it at the shipped byte/gas ratio.
//	gas_par_per_sig          moves the measured quantity and no ceiling at
//	                         all: ParGasLimit(T) is par_gas_ratio*2T and does
//	                         not mention the gas schedule. params.Validate
//	                         constrains this coefficient in no way whatever —
//	                         not its size, not its parity, not even that it be
//	                         positive.
//
// **Neither axis is the defect this family of findings exists to name.** The
// earlier sweep's elasticBase() set the *parameter* seq_gas_target_genesis to
// 1,000 while leaving block_byte_limit_genesis at 2,500,000, moving the shipped
// ratio from 1.25 bytes per gas to 2,500 and reaching B5 and B6 only because of
// it — a fixture that has left the protocol behind. The B6 arm that did that
// was deleted by this file's change rather than left beside these two, because
// a correct arm next to a broken one, with nothing telling a reader which is
// which, is the worst of the three outcomes.
//
// **What both arms drive, and what it kills.** The separating pair on the
// compared quantity is (L, L+1) for L = ParGasLimit(T). L+1 is unreachable —
// gas_par_per_sig, gas_par_per_byte and gas_par_per_derive_unit are all even at
// every shipped set, so a block's parallel gas is even, and par_gas_ratio*2T is
// even too. The first *reachable* refusal is L+2 and the drivable pair is (L,
// L+2). Both arms below place the block on **both** halves of it:
//
//   - **parallel gas exactly L** must be FOLDED by both implementations. That
//     is the arm that kills the mutant recorded as a documented survivor —
//     sim/refold's `parGas > parCeiling` weakened to `>=`. Nothing in the tree
//     had ever put the two sides of that comparison equal, so the census of
//     over-ceiling blocks was byte-identical with and without the mutation.
//   - **parallel gas exactly L+2** must be refused as B6 by both. That kills
//     the coarser mutant — B6 deleted from sim/refold outright — and pins the
//     first refusal at the first value that can be refused rather than at some
//     value far above it.
//
// Each arm reaches L+2 by the technique available on its own axis, which is a
// third way the two are independent: the ratio arm moves the **ceiling** onto
// the block (the technique TestBothFoldsAgreeAtTheBlockByteCeiling uses for
// B13), and the per-signature arm moves the **block** onto the ceiling.

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
)

// parWitnessBid is ceilingBid with both priorities at zero, so a certificate is
// charged its base fee and nothing more.
//
// The reason is arithmetic rather than taste. Both arms below carry
// certificates whose *parallel* gas is a large fraction of ParGasLimit — that
// is what they are for — and the fee is charged on that gas, so a priority the
// other arms in this package can afford is a charge here that no matured
// coinbase covers. A certificate that cannot pay is skipped rather than
// refused, so it would not invalidate the block; it would quietly make the arm
// measure a block of skips. B4 still needs the maxima at or above the base
// fees, which these are.
func parWitnessBid() types.FeeBid {
	return wallet.Bid(u256.FromUint64(50_000), u256.Zero, u256.FromUint64(500), u256.Zero)
}

// mineEmpty commits n certificate-free blocks to the payout address, which is
// how a signer comes by a balance: there is no faucet.
func (w *folds) mineEmpty(t *testing.T, payout types.Address, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if !w.commit(t, payout) {
			t.Fatalf("both folds refused an empty block at height %d", w.chain.NextHeight())
		}
	}
}

// assertOnlyTheParallelRuleCanFire states, from the parameters and the block
// rather than from either fold's verdict, that the block is over B6's ceiling
// and under every ceiling checked before it. A fold asked whether it rejected
// would be vouching for itself.
//
// The rules that can pre-empt B6 are the ones core/fold/blockrules.go and
// sim/refold's checkBlock reach first: B12's certificate count and B13's byte
// ceiling ahead of the per-certificate loop, and B5's burst bound immediately
// above B6. B15's citation ceiling cannot fire on a block proposed without
// cites and is asserted as zero rather than assumed.
func (w *folds) assertOnlyTheParallelRuleCanFire(t *testing.T, b *types.Block, target uint64, want uint64) {
	t.Helper()
	var seqGas, parGas uint64
	for _, c := range b.Certs {
		seqGas += c.SeqGas(w.p)
		parGas += c.ParGas(w.p)
	}
	if parGas != want {
		t.Fatalf("the block declares %d parallel gas, not the %d this arm placed it at; "+
			"the separating pair is not where the derivation says it is", parGas, want)
	}
	if len(b.Cites) != 0 {
		t.Fatalf("the block carries %d citations; this arm proposes none, so B15 is not "+
			"asserted away and could fire before B6", len(b.Cites))
	}
	if ceiling := w.p.MaxCertsPerBlock(target); len(b.Certs) > ceiling {
		t.Fatalf("the block carries %d certificates against a ceiling of %d, so B12 refuses "+
			"it before B6 is reached and this arm pins the wrong rule", len(b.Certs), ceiling)
	}
	if size, limit := b.SizeBytes(), w.p.BlockByteLimit(target); size > limit {
		t.Fatalf("the block is %d bytes against a byte ceiling of %d, so B13 refuses it "+
			"before B6 is reached and this arm pins the wrong rule", size, limit)
	}
	if burst := w.p.SeqGasBurst(target); seqGas > burst {
		t.Fatalf("the block declares %d sequential gas against a 4T bound of %d, so B5 "+
			"refuses it and this arm pins the wrong rule", seqGas, burst)
	}
	// Asserted against 2T rather than 4T, for the reason the byte arm gives:
	// crossing the soft threshold makes this a burst-forfeiture block and
	// changes what the arm is about.
	if soft := w.p.SeqGasLimit(target); seqGas > soft {
		t.Fatalf("the block declares %d sequential gas against a 2T threshold of %d, so it "+
			"is a burst block and no longer a clean parallel-rule arm", seqGas, soft)
	}
	t.Logf("block: %d certificates (ceiling %d), %d bytes (ceiling %d), %d seq gas (2T %d), "+
		"%d par gas (ceiling %d)", len(b.Certs), w.p.MaxCertsPerBlock(target), b.SizeBytes(),
		w.p.BlockByteLimit(target), seqGas, w.p.SeqGasLimit(target), parGas,
		w.p.ParGasLimit(target))
}

// assertTheOddValueBetweenIsUnreachable is the parity claim, executed at the
// witness rather than stated in prose.
//
// The claim is an *unreachability* claim, which is a stronger thing to assert
// than "untested", and it rests entirely on three parameters being even while
// params.Validate constrains the parity of none of them. Checked here, at the
// two arms that would stop meaning what they say if it failed: an odd
// coefficient makes L+1 reachable, which turns the `>` -> `>=` survivor into an
// ordinary killable off-by-one and makes (L, L+2) the wrong pair to be driving.
func assertTheOddValueBetweenIsUnreachable(t *testing.T, p *params.Params, limit uint64) {
	t.Helper()
	for _, coeff := range []struct {
		name string
		v    uint64
	}{
		{"gas_par_per_sig", p.GasParPerSig},
		{"gas_par_per_byte", p.GasParPerByte},
		{"gas_par_per_derive_unit", p.GasParPerDeriveUnit},
	} {
		if coeff.v%2 != 0 {
			t.Fatalf("%s is %d, which is odd: a block's parallel gas is no longer always "+
				"even, so B6's separating value L+1 is reachable and this file drives the "+
				"wrong pair — the pair is (L, L+1) and the `>` -> `>=` mutant recorded "+
				"as a survivor becomes killable", coeff.name, coeff.v)
		}
	}
	if limit%2 != 0 {
		t.Fatalf("ParGasLimit is %d, which is odd: par_gas_ratio * 2T was the other half of "+
			"the parity argument, and L+1 is now even", limit)
	}
}

// TestBothFoldsAgreeAtTheParallelGasCeilingUnderARatioWitness drives rule B6's
// separating pair on the par_gas_ratio axis.
//
// **Derivation.** The compared quantity is a block's aggregate parallel gas,
// against ParGasLimit(T) = par_gas_ratio * 2T. The rule is stated twice, once in
// core/fold/blockrules.go and once in sim/refold's checkBlock; the bound is a
// single core/params function both folds reach, so what this arm separates is
// the comparison and not the derivation of the bound.
//
// **Why a witness at all.** Dividing B6's ceiling by B13's cancels T, so what
// B6 asks is fixed by the parameters alone: 2*par_gas_ratio*T0 per
// block_byte_limit_genesis, which is 3.84 parallel gas per block byte at
// mainnet. The densest certificate the V-rules admit supplies 3.0352
// (era0ParDensityCeiling, derived rather than searched), so B6 is inert at every
// shipped set — asserted here against the unmodified network before anything is
// moved, because an arm that needs a witness should say why in code.
//
// **The witness.** par_gas_ratio = 1, mainnet in every other respect. It is the
// axis B6 is quantified over, Validate requires only that it be positive, and it
// moves *B6's ceiling alone*: the byte, count and sequential ceilings this block
// also runs between keep the values they ship with, so the block below is one
// mainnet actually admits and the shipped byte/gas ratio is never left.
//
// **Placing the pair.** With par_gas_ratio = 1 the ceiling is 2T, so it advances
// by exactly 2 per unit of T — and T, unlike the ratio, is consensus state the
// epoch controller already moves. Seeding T = parGas/2 therefore puts the
// ceiling exactly on the block and T-1 puts it exactly two below, which is the
// pair (L, L+2). The value between them, L+1, is not a ceiling any T produces,
// which is the parity argument seen from the ceiling's side rather than the
// block's.
func TestBothFoldsAgreeAtTheParallelGasCeilingUnderARatioWitness(t *testing.T) {
	shipped := spec.Mainnet()
	// The antecedent, stated where the witness is introduced: without this the
	// arm below is a fixture nobody needed.
	assertB6IsInertByDerivation(t, shipped)

	p := *shipped
	p.ParGasRatio = 1
	if err := p.Validate(); err != nil {
		t.Fatalf("the witness is not a parameter set a network could be started with: %v", err)
	}
	assertTheOddValueBetweenIsUnreachable(t, &p, p.ParGasLimit(p.SeqGasTargetGenesis))

	w := newFolds(t, &p)
	miner := ceilingKey(t, 1)
	alice := w.fundedSigner(t, miner, 2)

	dsts := make([]types.Address, 0, p.MaxMovesPerTransfer)
	for i := 0; i < p.MaxMovesPerTransfer; i++ {
		dsts = append(dsts, ceilingKey(t, uint16(0x600+i)).Persistent())
	}
	moves := make([]types.Move, 0, len(dsts))
	for _, d := range dsts {
		moves = append(moves, types.Move{Asset: types.NativeAsset, Src: alice.Persistent(),
			Dst: d, Amount: u256.FromUint64(1)})
	}

	ttl := w.chain.NextHeight() + 5
	build := func(seq int) *types.Certificate {
		c, err := (&wallet.Builder{
			Params:  &p,
			Program: wallet.Transfer(moves...),
			Seq:     uint64(seq),
			TTL:     ttl,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  parWitnessBid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatalf("certificate %d: %v", seq, err)
		}
		return c
	}

	// Every certificate here is the same shape, so the block's parallel gas is
	// n times one certificate's and the count that lands inside T's legal
	// interval is a division rather than a search. It is checked against the
	// block that gets built, because a quantity derived from a formula nobody
	// re-measured is a quantity that silently stops being the block's.
	unit := build(0).ParGas(&p)
	if unit == 0 {
		t.Fatal("a certificate of the widest transfer shape costs no parallel gas; " +
			"nothing below can place the ceiling")
	}
	// T-1 must stay at or above seq_gas_target_genesis, T's permanent floor, so
	// the ceiling has to land strictly above its genesis value.
	floor := p.ParGasLimit(p.SeqGasTargetGenesis) + 1
	n := int((floor + unit - 1) / unit)
	certs := make([]*types.Certificate, 0, n)
	for i := 0; i < n; i++ {
		certs = append(certs, build(i))
	}

	block, err := w.chain.Propose(miner.Persistent(), certs...)
	if err != nil {
		t.Fatalf("propose %d certificates: %v", n, err)
	}
	var parGas uint64
	for _, c := range block.Certs {
		parGas += c.ParGas(&p)
	}
	if parGas != unit*uint64(n) {
		t.Fatalf("a block of %d certificates carries %d parallel gas, not the %d the linear "+
			"model predicts; the certificates are not the identical shape the count assumed",
			n, parGas, unit*uint64(n))
	}
	if parGas%2 != 0 {
		t.Fatalf("the block's parallel gas is %d, which is odd; the parity premise asserted "+
			"above did not survive the block", parGas)
	}

	hi := parGas / (2 * p.ParGasRatio)
	lo := hi - 1
	if p.ParGasLimit(hi) != parGas {
		t.Fatalf("at T=%d the parallel ceiling is %d, not the block's %d",
			hi, p.ParGasLimit(hi), parGas)
	}
	if p.ParGasLimit(lo) != parGas-2 {
		t.Fatalf("at T=%d the parallel ceiling is %d, not the block's parallel gas minus two "+
			"(%d); the ceiling does not step by two and the pair is not (L, L+2)",
			lo, p.ParGasLimit(lo), parGas-2)
	}
	// The half of the derivation that is a claim about the ceiling rather than
	// about the block: no sequential target produces L+1 either, so the value
	// between the pair is unreachable from both sides.
	for tt := lo; tt <= hi; tt++ {
		if p.ParGasLimit(tt) == parGas-1 {
			t.Fatalf("at T=%d the parallel ceiling is exactly the block's parallel gas minus "+
				"one; L+1 is reachable after all", tt)
		}
	}
	for _, tt := range []uint64{hi, lo} {
		if tt < p.SeqGasTargetGenesis || tt > p.SeqGasCapacity {
			t.Fatalf("T=%d is outside [%d, %d], the interval the epoch controller clamps the "+
				"sequential target into, so this arm would be measuring a state no network "+
				"can occupy", tt, p.SeqGasTargetGenesis, p.SeqGasCapacity)
		}
	}

	// The reachability half, at the lower of the two targets, where every other
	// ceiling is at its tightest.
	w.assertOnlyTheParallelRuleCanFire(t, block, lo, parGas)

	w.seedSeqGasTarget(lo)
	fastRule, naiveRule := w.rules(block)
	if fastRule != "B6" || naiveRule != "B6" {
		t.Fatalf("a block of %d parallel gas against a ceiling of %d — the first refusable "+
			"value, L+2 — is refused as %q by core/fold and %q by sim/refold, want B6 from both",
			parGas, p.ParGasLimit(lo), fastRule, naiveRule)
	}

	// The admitted side, and the one nothing in this tree drove before: the
	// same block with the ceiling exactly on it. This is the arm that kills
	// `parGas > parCeiling` -> `parGas >= parCeiling`.
	w.seedSeqGasTarget(hi)
	if !w.foldOn(t, w.chain.State, w.naive, block, true) {
		fr, nr := w.rules(block)
		t.Fatalf("a block of exactly %d parallel gas against a parallel ceiling of exactly %d "+
			"— the equality case — was refused (core/fold %q, sim/refold %q); the comparison "+
			"is an off-by-one", parGas, p.ParGasLimit(hi), fr, nr)
	}
	t.Logf("mainnet at par_gas_ratio=1: a block of %d parallel gas in %d certificates, folded "+
		"by both at T=%d where the ceiling is %d, refused as B6 by both at T=%d where it is %d",
		parGas, len(block.Certs), hi, p.ParGasLimit(hi), lo, p.ParGasLimit(lo))
}

// TestBothFoldsAgreeAtTheParallelGasCeilingUnderASignatureCostWitness drives the
// same separating pair on a second, independent axis: the per-unit parallel gas
// schedule, which params.Validate constrains in no way at all.
//
// **Why a second axis rather than a second value on the first.** A witness row
// carries the risk that its conclusion is a property of its fixture. Two
// witnesses are the instrument against that, and two witnesses on the *same*
// axis are the weak form of it — they share whatever the axis assumes. These
// two share nothing: the arm above moves a ceiling and leaves the gas schedule
// alone, this one moves the gas schedule and leaves every ceiling at its shipped
// value, including B6's own. If B6's comparison were wrong in either fold, no
// choice of the other axis's fixture could hide it here.
//
// **The witness.** devnet, with gas_par_per_sig alone re-priced. Nothing else
// moves: T stays at its genesis value and is never seeded, par_gas_ratio stays
// at devnet's 10, and the byte, count and sequential ceilings are the shipped
// ones. ParGasLimit(T) is therefore devnet's own 40,000,000 throughout — the
// arm above changes what the rule asks, this one changes what the block brings.
//
// **Placing the pair.** A certificate's parallel gas is gas_par_per_sig*sigs +
// gas_par_per_byte*bytes + gas_par_per_derive_unit*units, and only the first
// term moves with the witness. Two certificates of one signature each therefore
// put the block's parallel gas at 2*sig + base, where base is measured off a
// probe certificate rather than retyped from the gas schedule. Solving 2*sig +
// base = L is exact because L and base are both even — which is the parity
// premise doing load-bearing work rather than being quoted — and sig+1 then
// lands the same block on L+2 exactly, one step of the pair per unit of the
// coefficient.
func TestBothFoldsAgreeAtTheParallelGasCeilingUnderASignatureCostWitness(t *testing.T) {
	shipped := spec.Devnet()
	assertB6IsInertByDerivation(t, shipped)

	miner := ceilingKey(t, 1)
	bob := ceilingKey(t, 3)
	// The certificate shape both the probe and the arms build. Nothing in it
	// depends on chain state: wallet.Builder derives the reads and writes from
	// the program, and Seq and TTL are fixed-width fields whose *values* cannot
	// change the encoded size. So the probe below measures the same bytes the
	// arms will carry, and the arms assert that rather than trust it.
	build := func(p *params.Params, seq, ttl uint64) *types.Certificate {
		c, err := (&wallet.Builder{
			Params: p,
			Program: wallet.Tip(types.NativeAsset, miner.Persistent(), bob.Persistent(),
				u256.FromUint64(1_000)),
			Seq:     seq,
			TTL:     ttl,
			Deposit: wallet.SelfDeposit(miner.Persistent(), miner.Persistent()),
			FeeBid:  parWitnessBid(),
			Signers: []*wallet.Key{miner},
		}).Build()
		if err != nil {
			t.Fatalf("certificate at seq %d: %v", seq, err)
		}
		return c
	}

	const certs = 2
	probe := build(shipped, 0, 100)
	if len(probe.Sigs) != 1 {
		t.Fatalf("the probe certificate carries %d signatures, not the one the arithmetic "+
			"below solves for", len(probe.Sigs))
	}
	// base is what the certificate costs on the two coefficients the witness
	// leaves alone, taken by difference off the shipped schedule so that a
	// change to the encoding or to DeriveUnits moves it here instead of
	// silently invalidating the solution.
	base := probe.ParGas(shipped) - shipped.GasParPerSig*uint64(len(probe.Sigs))
	limit := shipped.ParGasLimit(shipped.SeqGasTargetGenesis)
	if limit <= certs*base {
		t.Fatalf("two certificates cost %d parallel gas before a single signature is priced, "+
			"against a ceiling of %d; there is no positive coefficient that lands the block "+
			"on the ceiling", certs*base, limit)
	}
	if (limit-certs*base)%certs != 0 {
		t.Fatalf("the ceiling minus the block's fixed cost is %d, which %d certificates do "+
			"not divide; the parity premise that makes this exact has failed",
			limit-certs*base, certs)
	}
	sig := (limit - certs*base) / certs

	for _, arm := range []struct {
		name string
		sig  uint64
		want uint64
	}{
		{"the_last_parallel_gas_the_ceiling_admits", sig, limit},
		{"the_first_parallel_gas_the_ceiling_refuses", sig + 1, limit + 2},
	} {
		t.Run(arm.name, func(t *testing.T) {
			p := *shipped
			p.GasParPerSig = arm.sig
			if err := p.Validate(); err != nil {
				t.Fatalf("the witness is not a parameter set a network could be started "+
					"with: %v", err)
			}
			if got := p.ParGasLimit(p.SeqGasTargetGenesis); got != limit {
				t.Fatalf("the witness moved the ceiling to %d from %d; this axis is supposed "+
					"to move the block and nothing else", got, limit)
			}

			w := newFolds(t, &p)
			// Mined rather than funded through a transfer: a funding certificate
			// would itself be priced at this arm's signature cost, and the point
			// of the arm is that the cost is large.
			w.mineEmpty(t, miner.Persistent(), int(p.CoinbaseMaturity)+4)
			target := w.seqGasTarget(t)
			if target != p.SeqGasTargetGenesis {
				t.Fatalf("T is %d rather than its genesis value %d; this arm moves the block "+
					"and nothing has moved T", target, p.SeqGasTargetGenesis)
			}

			ttl := w.chain.NextHeight() + 5
			cs := make([]*types.Certificate, 0, certs)
			for i := 0; i < certs; i++ {
				c := build(&p, uint64(i), ttl)
				if got := c.ParGas(&p) - arm.sig*uint64(len(c.Sigs)); got != base {
					t.Fatalf("certificate %d costs %d parallel gas outside its signatures, "+
						"not the %d the probe measured; the probe and the arm are not "+
						"building the same shape", i, got, base)
				}
				cs = append(cs, c)
			}

			block, err := w.chain.Propose(miner.Persistent(), cs...)
			if err != nil {
				t.Fatalf("propose %d certificates: %v", certs, err)
			}
			w.assertOnlyTheParallelRuleCanFire(t, block, target, arm.want)

			if arm.want > limit {
				fastRule, naiveRule := w.rules(block)
				if fastRule != "B6" || naiveRule != "B6" {
					t.Fatalf("a block of %d parallel gas against a ceiling of %d — the first "+
						"refusable value, L+2 — is refused as %q by core/fold and %q by "+
						"sim/refold, want B6 from both", arm.want, limit, fastRule, naiveRule)
				}
				t.Logf("devnet at gas_par_per_sig=%d: %d parallel gas against a ceiling of %d, "+
					"refused as B6 by both", arm.sig, arm.want, limit)
				return
			}
			if !w.foldOn(t, w.chain.State, w.naive, block, true) {
				fr, nr := w.rules(block)
				t.Fatalf("a block of exactly %d parallel gas against a parallel ceiling of "+
					"exactly %d — the equality case — was refused (core/fold %q, sim/refold "+
					"%q); the comparison is an off-by-one", arm.want, limit, fr, nr)
			}
			t.Logf("devnet at gas_par_per_sig=%d: %d parallel gas against a ceiling of %d, "+
				"folded by both", arm.sig, arm.want, limit)
		})
	}
}
