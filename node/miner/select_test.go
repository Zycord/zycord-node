package miner_test

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/miner"
	"zycord/spec"
	"zycord/wallet"
)

// transferCert builds a stateless, well-formed one-shot transfer from seed n.
// Two calls with different seeds produce certificates of identical shape — the
// same reads, writes, signatures and byte length, hence the same sequential and
// parallel gas and the same selection weight — differing only in identity. The
// fee bid is overwritten by the caller after the build, so its value here is
// immaterial.
func transferCert(t *testing.T, p *params.Params, n uint64) *types.Certificate {
	t.Helper()
	k := benchKey(n)
	src := k.OneShot()
	dst := benchKey(n + 1_000_000).Persistent()
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, src, dst, u256.FromUint64(1)),
		TTL:     240,
		Deposit: wallet.SelfDeposit(src, k.Persistent()),
		FeeBid: wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000),
			u256.FromUint64(500), u256.FromUint64(10)),
		Signers: []*wallet.Key{k},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// selectionWeight recomputes, from public inputs alone, the weight Select ranks
// by. It exists only so the overflow guard in the test below can assert the
// tie-break's overflow branch is genuinely exercised; the ordering itself is
// judged against Select's real output, never against this.
func selectionWeight(c *types.Certificate, p *params.Params, t uint64) u256.U256 {
	seqLimit := p.SeqGasLimit(t)
	parLimit := p.ParGasLimit(t)
	seqShare, _ := u256.FromUint64(c.SeqGas(p)).Mul(u256.FromUint64(parLimit))
	parShare, _ := u256.FromUint64(c.ParGas(p)).Mul(u256.FromUint64(seqLimit))
	return u256.MaxOf(seqShare, parShare)
}

// TestOverflowTieBreakRanksTheDenserCertificateFirst pins the cross-product
// overflow branch of the fee-density comparator.
//
// Select ranks by tip/weight compared as tip_a·weight_b ? tip_b·weight_a to
// stay in integers. When one side of that product exceeds 2^256, u256.Mul
// reports the overflow instead of wrapping, and the comparator must read the
// overflow as "this side is larger". A single tip near 2^256 is unreachable on
// a real chain — it takes a per-unit sequential bid of order 2^247 — so this is
// a correctness property of the operator, exercised with a hand-set fee bid
// rather than a mined one, not an attack a live pool could stage. The bug it
// guards against returned the wrong side's overflow flag, ranking the denser
// certificate last.
//
// Both certificates are the same shape, so their weights are equal; A is given
// a tip so large that A's cross product overflows while B's does not. A is the
// strictly denser certificate and must sort first. Rule 24: the assertion is on
// the order Select actually produces, not on a reconstructed comparator.
func TestOverflowTieBreakRanksTheDenserCertificateFirst(t *testing.T) {
	p := spec.Mainnet()
	target := p.SeqGasTargetGenesis

	certA := transferCert(t, p, 1)
	certB := transferCert(t, p, 2)

	// Equal shape is what makes the weights equal and the comparison a pure
	// tip contest. If a refactor ever broke that, the guard below would fail
	// loudly rather than let the test pass for the wrong reason.
	if certA.SeqGas(p) != certB.SeqGas(p) || certA.ParGas(p) != certB.ParGas(p) {
		t.Fatalf("the two certificates must share a shape: seqGas %d/%d parGas %d/%d",
			certA.SeqGas(p), certB.SeqGas(p), certA.ParGas(p), certB.ParGas(p))
	}

	// A's tip is the largest value that still settles without overflowing the
	// fee market: floor((2^256-1)/seqGas) per unit of sequential gas, clamped
	// by an equal ceiling, with no base fee to erode it. tip_A is then within
	// one gas-unit of 2^256, so tip_A·weight overflows for any weight >= 2.
	perUnit, _ := u256.Max.Div64(certA.SeqGas(p))
	certA.FeeBid = types.FeeBid{
		SeqMax:      perUnit,
		SeqPriority: perUnit,
		ParMax:      u256.Zero,
		ParPriority: u256.Zero,
	}
	// B's tip is ordinary.
	certB.FeeBid = types.FeeBid{
		SeqMax:      u256.FromUint64(1_000),
		SeqPriority: u256.FromUint64(1_000),
		ParMax:      u256.Zero,
		ParPriority: u256.Zero,
	}

	tipA := certA.MinerTip(p, u256.Zero, u256.Zero)
	tipB := certB.MinerTip(p, u256.Zero, u256.Zero)
	if tipA.IsZero() {
		t.Fatal("A's tip settled to zero; the fee market rejected the crafted bid")
	}
	if !tipA.Gt(tipB) {
		t.Fatal("A must offer the strictly higher tip for the ordering to be unambiguous")
	}

	// Guard: confirm this actually drives the comparator through its overflow
	// branch — A's cross product overflows 2^256 and B's does not. Without this
	// asymmetry the buggy and fixed comparators would agree and the test would
	// prove nothing.
	weight := selectionWeight(certA, p, target)
	if _, leftOver := tipA.Mul(weight); !leftOver {
		t.Fatalf("A's cross product did not overflow; the overflow branch is untested (weight=%s)", weight)
	}
	if _, rightOver := tipB.Mul(weight); rightOver {
		t.Fatal("B's cross product overflowed; the scenario is not the intended asymmetry")
	}

	// Pool ordered B-before-A so a correct sort must move A ahead of B; the bug
	// leaves B first.
	selected := miner.Select([]*types.Certificate{certB, certA}, p, u256.Zero, u256.Zero, target)
	if len(selected) != 2 {
		t.Fatalf("both certificates should fit and be selected; got %d", len(selected))
	}
	idA := certA.ID()
	if got := selected[0].ID(); got != idA {
		t.Fatalf("the denser certificate (overflowing cross product) must rank first; "+
			"got id %x first instead of %x", got, idA)
	}
}

func benchKey(n uint64) *wallet.Key {
	s := make([]byte, 32)
	for i := 0; i < 8; i++ {
		s[i] = byte(n >> (8 * i))
	}
	k, err := wallet.KeyFromSeed(s)
	if err != nil {
		panic(err)
	}
	return k
}

// TestSelectionFitsTheBlockItBuilds is the property the byte ceiling actually
// needs, and the one a builder summing certificate sizes does not have.
//
// `BlockByteLimit` is measured by the block rules against the *encoded block*:
// the header, the SSZ envelope, and a four-byte offset per certificate on top
// of the certificates themselves. A selector that counts only certificates
// packs a set that overshoots, and the failure is not a rejected block from
// somebody else — it is the miner's own dry run refusing its own candidate,
// after which `mineLoop` logs the error and retries the identical set forever
// while the pool it is draining stays full.
//
// At the genesis ceilings the margin was not close: 2,645 one-shot transfers
// sum to 2,499,525 bytes under a 2,500,000 ceiling and encode to 2,510,341.
// The shape below is the one WALLET.md tells receivers to hand out, so it is
// the traffic a real node would have hit first.
func TestSelectionFitsTheBlockItBuilds(t *testing.T) {
	p := spec.Mainnet()
	target := p.SeqGasTargetGenesis
	dst := benchKey(999).Persistent()
	bid := wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000),
		u256.FromUint64(500), u256.FromUint64(10))

	// Enough candidates to overflow the ceiling several times over, so the
	// selector is genuinely choosing rather than taking everything offered.
	var pool []*types.Certificate
	for i := uint64(0); i < 4_000; i++ {
		k := benchKey(1000 + i)
		src := k.OneShot()
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, src, dst, u256.FromUint64(1)),
			TTL:     240,
			Deposit: wallet.SelfDeposit(src, k.Persistent()),
			FeeBid:  bid,
			Signers: []*wallet.Key{k},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		pool = append(pool, c)
	}

	selected := miner.Select(pool, p, u256.Zero, u256.Zero, target)
	if len(selected) == 0 {
		t.Fatal("nothing was selected; the test measures nothing")
	}

	// Built with the maximum citations the selector reserved for, because that
	// is the block the assembler is entitled to produce from this selection.
	blk := &types.Block{
		Header: types.Header{Version: types.HeaderVersion, Height: 1},
		Certs:  selected,
	}
	for i := 0; i < p.MaxCitesPerBlock; i++ {
		blk.Cites = append(blk.Cites, &types.Header{Version: types.HeaderVersion})
	}
	ceiling := p.BlockByteLimit(target)
	if size := blk.SizeBytes(); size > ceiling {
		t.Fatalf("the selector built a block of %d bytes against a ceiling of %d: "+
			"%d certificates summing %d bytes, plus %d of envelope the selection did "+
			"not reserve", size, ceiling, len(selected),
			size-types.BlockOverheadBytes(len(selected), 0),
			types.BlockOverheadBytes(len(selected), 0))
	}

	// And the selection must still be worth having: a selector that reserved
	// far too much would pass the assertion above by building nearly nothing.
	if got := blk.SizeBytes(); got < ceiling*9/10 {
		t.Fatalf("the selector used only %d of %d bytes; it is leaving the block "+
			"mostly empty rather than reserving the envelope", got, ceiling)
	}
}
