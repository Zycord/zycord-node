package fold_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// retireOfWidth builds one RETIRE certificate burning n one-shot addresses,
// paying its deposit from the persistent twin of the first key — the twin is
// not one-shot, so no second MARK_SPENT is derived and V4 matches on the public
// key, which makes the certificate carry exactly n signatures.
func retireOfWidth(t *testing.T, p *params.Params, domain byte, run, n uint64) *types.Certificate {
	t.Helper()
	addrs := make([]types.Address, 0, n)
	keys := make([]*wallet.Key, 0, n)
	for j := uint64(0); j < n; j++ {
		k := budgetKey(t, domain, run*64+j)
		addrs = append(addrs, k.OneShot())
		keys = append(keys, k)
	}
	// TTL 5 rather than buildCert's 100: devnet's ttl_max is 32, and a block
	// rule refusing the TTL (B2) would answer before the ceiling under test.
	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(addrs...),
		TTL:     5,
		Deposit: wallet.SelfDeposit(keys[0].Persistent(), keys[0].Persistent()),
		FeeBid:  bid(),
		Signers: keys,
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestB18RejectsAtTheSignatureCeilingAndNotBelowIt drives B18 at the boundary
// from both sides.
//
// The ceiling is `max_sigs_per_block_genesis` scaled by `T/T₀`, and what the
// rule bounds is the RECEIVER's cost: a block's certificates may declare at
// most that many signatures between them, counted before the fold verifies
// any of them. The audit that asked for this measured one strict Ed25519
// verification at ~734 µs, so the genesis ceiling of 6,000 caps a fully
// signature-stuffed block at ~4.4 core-seconds against a 30-second interval —
// and, unlike a bound derived from the parallel gas ceiling, it does not grow
// when the byte ceilings grow.
//
// EXPECTED DIRECTION (PROTOCOL rule 22), declared before the run: a block
// declaring exactly the ceiling is ACCEPTED, and one signature more is REFUSED
// naming **B18**. The comparison is `>` and not `>=`, and driving both sides
// is the only way to say which.
func TestB18RejectsAtTheSignatureCeilingAndNotBelowIt(t *testing.T) {
	p := spec.Devnet()
	t0 := p.SeqGasTargetGenesis
	ceiling := p.MaxSigsPerBlock(t0)
	if ceiling == 0 {
		t.Fatal("the signature ceiling is zero at the genesis target; no block could carry a " +
			"certificate at all and the boundary below is not one")
	}

	// A block of `width`-signature certificates landing exactly on the
	// ceiling, so the two sides of the boundary differ by one signature rather
	// than by a whole certificate.
	const width = 4
	if ceiling%width != 0 {
		t.Fatalf("the ceiling %d is not a multiple of %d, so no block of this family lands "+
			"exactly on it and the acceptance below would be measuring slack", ceiling, width)
	}
	n := ceiling / width

	certs := make([]*types.Certificate, 0, n+1)
	var sigs uint64
	for i := uint64(0); i < n; i++ {
		c := retireOfWidth(t, p, 0x18, i, width)
		if uint64(len(c.Sigs)) != width {
			t.Fatalf("the shape carries %d signatures, not the %d this test counts on",
				len(c.Sigs), width)
		}
		certs = append(certs, c)
		sigs += uint64(len(c.Sigs))
	}
	if sigs != ceiling {
		t.Fatalf("the block declares %d signatures, not the ceiling of %d", sigs, ceiling)
	}

	// Anti-vacuity: no other ceiling may bind, or the acceptance says nothing
	// about B18 and the refusal below could be any of them.
	if got := len(certs); got > p.MaxCertsPerBlock(t0) {
		t.Fatalf("%d certificates against a count ceiling of %d: B12 answers first",
			got, p.MaxCertsPerBlock(t0))
	}
	var seqGas, parGas uint64
	for _, c := range certs {
		seqGas += c.SeqGas(p)
		parGas += c.ParGas(p)
	}
	if seqGas > p.SeqGasBurst(t0) {
		t.Fatalf("%d sequential gas against a 4T bound of %d: B5 answers first",
			seqGas, p.SeqGasBurst(t0))
	}
	if parGas > p.ParGasLimit(t0) {
		t.Fatalf("%d parallel gas against a ceiling of %d: B6 answers first",
			parGas, p.ParGasLimit(t0))
	}

	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()

	at, err := c.Propose(payout, certs...)
	if err != nil {
		t.Fatal(err)
	}
	if size := at.SizeBytes(); size > p.BlockByteLimit(t0) {
		t.Fatalf("the block is %d bytes against a byte ceiling of %d: B13 answers first",
			size, p.BlockByteLimit(t0))
	}
	if err := fold.CheckBlockRules(c.State, at, p); err != nil {
		t.Fatalf("a block declaring exactly the ceiling of %d signatures was refused by %s (%v); "+
			"the comparison is >= where it should be >, and honest traffic that fills the "+
			"ceiling exactly would be refused", ceiling, ruleOrAssertion(fold.Rule(err)), err)
	}

	// One signature more. A single-signature RETIRE is the smallest thing that
	// adds one, so the block crosses the ceiling by exactly one signature and
	// by one certificate — nothing else moves far enough to reach another
	// ceiling.
	certs = append(certs, retireOfWidth(t, p, 0x19, 0, 1))
	over, err := c.Propose(payout, certs...)
	if err != nil {
		t.Fatal(err)
	}
	err = fold.CheckBlockRules(c.State, over, p)
	if err == nil {
		t.Fatalf("a block declaring %d signatures was accepted against a ceiling of %d",
			ceiling+1, ceiling)
	}
	if got := fold.Rule(err); got != "B18" {
		t.Fatalf("the block was refused by %s, not B18 (%v)", ruleOrAssertion(got), err)
	}
}

// TestTheSignatureCeilingIsCheckedBeforeAnySignatureIsVerified is the half of
// B18 that a count comparison cannot state on its own, and it is the half the
// rule exists for.
//
// A ceiling consulted after the work it bounds bounds nothing: an
// implementation that ran `validity.Check` over every certificate and then
// counted signatures would report the same verdict on every input and would
// still have paid the full verification cost of an adversarial block. So the
// ordering is the rule, and it is stated by driving it: every certificate in
// the block below carries a signature that does not verify, and the block must
// still be refused by **B18** rather than by **V2**. A fold that verified
// first would answer V2 — correctly, and far too late.
func TestTheSignatureCeilingIsCheckedBeforeAnySignatureIsVerified(t *testing.T) {
	p := spec.Devnet()
	t0 := p.SeqGasTargetGenesis
	ceiling := p.MaxSigsPerBlock(t0)

	const width = 4
	n := ceiling/width + 1
	certs := make([]*types.Certificate, 0, n)
	for i := uint64(0); i < n; i++ {
		c := retireOfWidth(t, p, 0x1a, i, width)
		// Corrupt every signature. The certificate is otherwise untouched, so
		// its id, its gas and its size are exactly what B18 counts.
		for j := range c.Sigs {
			c.Sigs[j].Sig[0] ^= 0xff
		}
		certs = append(certs, c)
	}

	chain := harness.MustNew(p)
	b, err := chain.Propose(key(t, 1).Persistent(), certs...)
	if err != nil {
		t.Fatal(err)
	}

	// Anti-vacuity: the corruption must really be there, or a fold that
	// verified first would answer B18 too and this test would pass without
	// measuring the ordering.
	if err := fold.CheckBlockRules(chain.State, b, p); err == nil {
		t.Fatal("the block was accepted; neither the ceiling nor the signatures were checked")
	} else if got := fold.Rule(err); got != "B18" {
		t.Fatalf("the block was refused by %s, not B18 (%v): the signature ceiling is checked "+
			"after signatures are verified, so it bounds what a block may REPORT having cost "+
			"rather than what it costs", ruleOrAssertion(got), err)
	}
	// And the corruption is real: one of these certificates, on its own, is
	// refused by V2.
	if got := fold.Rule(fold.CheckBlockRules(chain.State, mustPropose(t, chain, certs[:1]), p)); got != "V2" {
		t.Fatalf("a single corrupted certificate is refused by %s, not V2; the block above was "+
			"not carrying invalid signatures and the ordering claim is unmeasured", got)
	}
}

func mustPropose(t *testing.T, c *harness.Chain, certs []*types.Certificate) *types.Block {
	t.Helper()
	b, err := c.Propose(key(t, 1).Persistent(), certs...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
