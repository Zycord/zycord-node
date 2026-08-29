package mempool_test

import (
	"errors"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/mempool"
	"zycord/wallet"
)

// Reconstruction of the floor-pinning flood, measured against the code that
// actually enforces admission rather than against what a test helper chooses to
// deposit.
//
// The flood, in one sentence: the eviction floor is the cheapest *evictable*
// certificate, §2.3 makes only an underwriter's highest pooled Seq evictable,
// so an attacker holding Seq chains presents one dear tail per identity, pins
// the floor at that tail's declared priority, and every honest arrival below it
// is refused.
//
// Attribution, because it is easy to get backwards and an earlier draft of this
// file did: what prices the pin is the aggregated deposit screen composed with
// FeeCeiling's SeqMax term, and nothing else. The builder's dry-run drop pass
// (node/miner) is a *builder* fix — it stops a miner packing certificates the
// fold will not pay it for. It is downstream of admission and cannot move the
// pool's floor, so no test here depends on it. §2.1 of
// docs/adversarial/mempool.md makes the same point at length.
//
// The report, verbatim: pool 64 certificates per identity with Seq 0..62 at
// zero priority and Seq 63 at a high priority P. §2.3's chain-safety rule makes
// only the tail evictable, so the eviction candidates are the tails, and the
// floor is pinned at P. Every honest arrival below P is refused. The issue's
// own arithmetic puts the price at one skip_fee per identity (~3.13 ZCD for 313
// identities), because the per-certificate deposit screen it was written
// against compared one certificate's own ceiling against the cell at a time and
// never summed what that cell was already backing.
//
// Two distinct questions follow, and this file keeps them apart because
// conflating them is how the previous version of this file reached a wrong
// conclusion:
//
//  1. Is the floor still pinnable by this shape? Structurally yes, and it is
//     meant to be: a cheap-base/dear-tail chain *is* the honest fee-bump
//     shape, so no floor metric can refuse one without refusing the other.
//
//  2. What does the pin *cost*, as enforced? This is the half the report is
//     actually about — it reports a flat per-identity price independent of P. Answering
//     it requires measuring the minimum funding at which the pool admits the
//     flood, NOT the funding a helper happened to hand out. A helper that
//     tops the cell up per certificate measures itself: it will report a
//     "cost" that scales even against a pool that enforces nothing, because
//     the helper, not the screen, is doing the scaling.
//
// So `enforcedChainCost` below binary-searches the real admission threshold.

// buildCert builds a certificate declaring seqPriority with SeqMax set to
// exactly seqMax, and does NOT fund anything. Funding is the measurement, so it
// is never bundled into construction. eviction_test.go's world.cert pins SeqMax
// at 1,000,000 (or at the declared priority, when that is higher) and adds a
// large unconditional buffer to keep capital cost out of scope for the ordering
// tests it serves; this file is entirely about capital cost, so this helper
// puts SeqMax — and therefore FeeCeiling — back under the test's control.
func buildCert(t *testing.T, w *world, signer *wallet.Key, seq uint64, seqPriority, seqMax uint64) *types.Certificate {
	t.Helper()
	addr := signer.Persistent()
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, addr, key(t, 9999).Persistent(), drops(1)),
		Seq:     seq,
		TTL:     20,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  wallet.Bid(drops(seqMax), drops(seqPriority), drops(0), drops(0)),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatalf("building certificate seq %d priority %d max %d: %v", seq, seqPriority, seqMax, err)
	}
	return c
}

// mustU64 unwraps a u256 -> uint64 narrowing the test knows is safe at its own
// scale (a few hundred identities times a few million drops).
func mustU64(t *testing.T, v u256.U256) uint64 {
	t.Helper()
	n, ok := v.Uint64()
	if !ok {
		t.Fatalf("value %s does not fit in uint64 at this test's scale", v)
	}
	return n
}

// freeSeqPriority returns the largest SeqPriority a certificate with
// SeqMax == SeqPriority can declare while its FeeCeiling still sits at the
// SkipFee floor — the zone in which raising the declared priority costs
// nothing beyond SkipFee, because max(SkipFee, seqGas*SeqMax) is dominated by
// SkipFee. Computed from params rather than hardcoded, so it tracks the real
// formula.
func freeSeqPriority(t *testing.T, w *world) uint64 {
	t.Helper()
	probe := buildCert(t, w, key(t, 999_999), 0, 1, 1)
	seqGas := probe.SeqGas(w.p)
	if seqGas == 0 {
		t.Fatal("setup: seqGas is zero, cannot compute a free-zone threshold")
	}
	return mustU64(t, w.p.SkipFee) / seqGas
}

// enforcedChainCost is the measurement this file exists for: the minimum
// balance on one deposit cell at which the pool will admit an entire chain.
//
// It is a binary search over the funded balance, re-running the admission
// sequence against a throwaway pool each time, so what it reports is the
// screen's own threshold and nothing else. Any helper that instead funds as it
// goes reports its own generosity.
func enforcedChainCost(t *testing.T, policy mempool.Policy, seqPriorities []uint64, seqMaxes []uint64) uint64 {
	t.Helper()

	// The chain is built and signed once and reused across every probe. The
	// certificates do not depend on the funded balance — only admission does —
	// and signing 64 of them per probe dominates the runtime otherwise,
	// especially under -race.
	w := newWorld(t, policy)
	signer := key(t, 4_242_000)
	addr := types.NativeBalanceSlot(signer.Persistent())
	certs := make([]*types.Certificate, len(seqPriorities))
	hi := uint64(0)
	for i := range seqPriorities {
		certs[i] = buildCert(t, w, signer, uint64(i), seqPriorities[i], seqMaxes[i])
		ceiling, ok := certs[i].FeeCeiling(w.p)
		if !ok {
			t.Fatal("ceiling overflow")
		}
		hi += mustU64(t, ceiling)
	}

	admits := func(balance uint64) bool {
		probe := newWorld(t, policy)
		probe.state.Set(addr, drops(balance))
		for _, c := range certs {
			if err := probe.add(c); err != nil {
				return false
			}
		}
		return true
	}

	// Upper bound: the plain sum of ceilings always suffices, since that is the
	// most any screen (per-certificate or aggregated) can demand.
	if !admits(hi) {
		t.Fatalf("setup: even the full sum of ceilings (%d drops) does not admit the chain", hi)
	}

	// Invariant: admits(hi) is true and admits(lo) is false, so the loop
	// converges on the least admitting balance. Valid because admission is
	// monotone in the funded balance — the screen is a comparison against a
	// threshold that does not itself depend on the balance.
	lo := uint64(0)
	for lo+1 < hi {
		mid := lo + (hi-lo)/2
		if admits(mid) {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

// TestFeeCeilingScalesWithDeclaredPriorityPastTheFreeZone is the pure
// arithmetic the flood's economics rest on: FeeCeiling is max(SkipFee,
// seqGas*SeqMax + parGas*ParMax), and canonical form (UnmarshalFeeBid,
// core/types/types.go) refuses SeqPriority > SeqMax, so any certificate that
// decodes on a peer's node must set SeqMax at least as high as the priority it
// declares. Below SkipFee/seqGas the SkipFee floor dominates and raising the
// declared priority is free; above it the ceiling — and so the capital the
// screen locks — scales with the declared priority, identically for whoever
// declares it.
func TestFeeCeilingScalesWithDeclaredPriorityPastTheFreeZone(t *testing.T) {
	w := newWorld(t, mempool.DefaultPolicy())
	freeP := freeSeqPriority(t, w)
	if freeP == 0 {
		t.Fatal("setup: free zone is degenerate (0), cannot exercise both sides of it")
	}

	below := buildCert(t, w, key(t, 1), 0, freeP, freeP)
	ceilingBelow, ok := below.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	if !ceilingBelow.Eq(w.p.SkipFee) {
		t.Fatalf("a tail declaring the free-zone boundary %d costs %s, want exactly SkipFee %s",
			freeP, ceilingBelow, w.p.SkipFee)
	}

	tenXP := freeP*10 + 10
	above := buildCert(t, w, key(t, 2), 0, tenXP, tenXP)
	ceilingAbove, ok := above.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	if !ceilingAbove.Gt(ceilingBelow) {
		t.Fatalf("declaring %d instead of %d did not raise the ceiling: %s vs %s",
			tenXP, freeP, ceilingAbove, ceilingBelow)
	}
	ratio := mustU64(t, ceilingAbove) / mustU64(t, ceilingBelow)
	if ratio < 5 {
		t.Fatalf("ceiling grew only %dx for a 10x rise in declared priority (%s -> %s); "+
			"the free zone appears not to have been exited", ratio, ceilingBelow, ceilingAbove)
	}
	t.Logf("free-zone boundary priority = %d (ceiling %s drops); at 10x priority (%d) ceiling is %s drops (%dx)",
		freeP, ceilingBelow, tenXP, ceilingAbove, ratio)
}

// TestPinnedChainCostsTheSumOfItsDeclarations is the flood's actual acceptance
// question, asked of the screen rather than of a helper.
//
// The shape is one identity, 64 certificates, Seq 0..62 at zero priority and
// the tail declaring P. Its claimed price is one skip_fee for the whole chain,
// independent of P. Measured here as the enforced admission threshold:
//
//   - it is the SUM of the chain's ceilings, not the maximum, so the 63 cheap
//     certificates are each paid for rather than riding on the tail's funding;
//     and
//   - that sum grows with P, so the pin is not flat-priced — because
//     canonical form refuses SeqPriority > SeqMax and FeeCeiling is computed
//     from SeqMax, so a tail cannot declare a pinning priority without
//     declaring the capital to back it.
//
// Both halves are required. Either alone leaves the flood's discount partly open.
func TestPinnedChainCostsTheSumOfItsDeclarations(t *testing.T) {
	pol := mempool.DefaultPolicy()
	w := newWorld(t, pol)
	freeP := freeSeqPriority(t, w)

	const chain = 64
	if pol.MaxPerUnderwriter != chain {
		t.Fatalf("setup: MaxPerUnderwriter is %d, want %d to match the reported chain length",
			pol.MaxPerUnderwriter, chain)
	}

	// The reported chain, at a tail 20x past the free zone.
	pinned := freeP*20 + 1000
	prios := make([]uint64, chain)
	maxes := make([]uint64, chain)
	for i := 0; i < chain; i++ {
		prios[i], maxes[i] = 0, 1
	}
	prios[chain-1], maxes[chain-1] = pinned, pinned

	enforced := enforcedChainCost(t, pol, prios, maxes)

	// What the individual ceilings are, so the enforced figure can be compared
	// against both the max (a per-certificate screen) and the sum (aggregated).
	sum, max := uint64(0), uint64(0)
	for i := 0; i < chain; i++ {
		c := buildCert(t, w, key(t, 4_242_000), uint64(i), prios[i], maxes[i])
		ceiling, ok := c.FeeCeiling(w.p)
		if !ok {
			t.Fatal("ceiling overflow")
		}
		v := mustU64(t, ceiling)
		sum += v
		if v > max {
			max = v
		}
	}
	skipFee := mustU64(t, w.p.SkipFee)

	t.Logf("chain of %d, tail declaring %d (20x the free zone %d)", chain, pinned, freeP)
	t.Logf("  claimed price (one skip_fee):              %d drops", skipFee)
	t.Logf("  largest single ceiling (per-cert screen):  %d drops", max)
	t.Logf("  sum of all ceilings (aggregated screen):   %d drops", sum)
	t.Logf("  ENFORCED admission threshold (measured):   %d drops", enforced)

	if enforced <= skipFee {
		t.Fatalf("the whole 64-chain is admitted for %d drops, at or below one skip_fee (%d): "+
			"the flat per-identity price is still available", enforced, skipFee)
	}
	// The discriminating assertion. A per-certificate screen admits the chain
	// once the cell covers the single largest ceiling; an aggregated screen
	// requires the sum. The flood's amplification is exactly the gap between them.
	if enforced <= max {
		t.Fatalf("the 64-chain is admitted for %d drops, no more than its largest single "+
			"ceiling (%d): the cheap certificates are riding on the tail's funding, i.e. "+
			"the deposit screen is still per-certificate rather than aggregated. "+
			"The aggregated requirement would be %d.", enforced, max, sum)
	}
	if enforced < sum {
		t.Fatalf("enforced threshold %d is below the sum of the chain's ceilings %d: "+
			"some certificate in the chain was admitted without its own ceiling being "+
			"covered", enforced, sum)
	}
}

// TestPinCostScalesWithTheDeclaredTail closes the other half: that the
// enforced price of the pin is not flat in P. A chain whose tail declares 20x
// the free-zone boundary must cost more to pool than the identical chain whose
// tail sits at the boundary — otherwise raising the pin is free and the
// "arbitrarily high P at a fixed price" claim survives.
//
// Scope, stated so this is not over-read: this half is delivered by FeeCeiling
// and canonical form, which the aggregated screen did not touch, so this test
// passes against a per-certificate screen too. It is not what distinguishes an
// aggregated screen — TestPinnedChainCostsTheSumOfItsDeclarations is the only
// test here that does. Both halves are needed to close the flood's discount,
// but only one of them belongs to the aggregated screen.
func TestPinCostScalesWithTheDeclaredTail(t *testing.T) {
	pol := mempool.DefaultPolicy()
	w := newWorld(t, pol)
	freeP := freeSeqPriority(t, w)

	const chain = 64
	build := func(tail uint64) ([]uint64, []uint64) {
		prios := make([]uint64, chain)
		maxes := make([]uint64, chain)
		for i := 0; i < chain; i++ {
			prios[i], maxes[i] = 0, 1
		}
		prios[chain-1], maxes[chain-1] = tail, tail
		return prios, maxes
	}

	cheapP, cheapM := build(freeP)
	dearP, dearM := build(freeP*20 + 1000)

	cheap := enforcedChainCost(t, pol, cheapP, cheapM)
	dear := enforcedChainCost(t, pol, dearP, dearM)

	t.Logf("chain with tail at the free-zone boundary (%d): %d drops enforced", freeP, cheap)
	t.Logf("chain with tail at 20x the boundary (%d):       %d drops enforced", freeP*20+1000, dear)

	if dear <= cheap {
		t.Fatalf("raising the pinned tail from %d to %d did not raise the enforced cost "+
			"(%d -> %d): the pin is flat-priced in its own declaration, which is exactly "+
			"what the report describes", freeP, freeP*20+1000, cheap, dear)
	}

	// A strict inequality alone is near-vacuous: one extra drop would satisfy
	// it while leaving the pin effectively free. What has to hold is that the
	// *increment* is the tail's own ceiling — the attacker pays for the height
	// it declared, at the same arithmetic an honest bidder declaring the same
	// priority would pay.
	tail := buildCert(t, w, key(t, 4_242_001), 0, freeP*20+1000, freeP*20+1000)
	tailCeiling, ok := tail.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	cheapTail := buildCert(t, w, key(t, 4_242_002), 0, freeP, freeP)
	cheapTailCeiling, ok := cheapTail.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	wantDelta := mustU64(t, tailCeiling) - mustU64(t, cheapTailCeiling)
	gotDelta := dear - cheap
	if gotDelta != wantDelta {
		t.Fatalf("raising the pin cost %d drops more, but the tail's own ceiling rose by "+
			"%d (%s -> %s): the enforced price of the pin does not track the declaration "+
			"that sets it", gotDelta, wantDelta, cheapTailCeiling, tailCeiling)
	}
	t.Logf("raising the pin 20x raised its enforced price by exactly the tail's own "+
		"ceiling increase: %d drops (%s -> %s)", gotDelta, cheapTailCeiling, tailCeiling)
}

// TestTheFloorIsStillPinnableAndThatIsDeliberate records the half of the flood
// that is NOT closed and is not intended to be, so a future reader does not
// mistake the cost results above for a claim that the mechanism was removed.
//
// No floor metric can refuse a cheap-base/dear-tail chain without also refusing
// the honest fee bump, which has the identical shape. What changed is the
// price, not the possibility. This test fails if the pin silently stops
// working, which would mean the honest fee bump broke too.
func TestTheFloorIsStillPinnableAndThatIsDeliberate(t *testing.T) {
	pol := mempool.DefaultPolicy()
	pol.MaxCertificates = 512
	pol.EvictionHighWater = 90
	pol.EvictionLowWater = 80
	w := newWorld(t, pol)

	const chain = 64
	highWater := pol.MaxCertificates * int(pol.EvictionHighWater) / 100
	identities := (highWater + chain - 1) / chain
	freeP := freeSeqPriority(t, w)
	pinned := freeP*20 + 1000

	pooled := 0
	for i := 0; i < identities && pooled < highWater; i++ {
		signer := key(t, 500_000+i)
		addr := signer.Persistent()
		n := chain
		if highWater-pooled < chain {
			n = highWater - pooled
		}
		// Fund honestly and generously: this test is about the mechanism, and
		// the cost of it is measured by the two tests above.
		var need u256.U256
		certs := make([]*types.Certificate, 0, n)
		for seq := 0; seq < n; seq++ {
			price, max := uint64(0), uint64(1)
			if seq == n-1 {
				price, max = pinned, pinned
			}
			c := buildCert(t, w, signer, uint64(seq), price, max)
			ceiling, ok := c.FeeCeiling(w.p)
			if !ok {
				t.Fatal("ceiling overflow")
			}
			need = need.SatAdd(ceiling)
			certs = append(certs, c)
		}
		w.state.Set(types.NativeBalanceSlot(addr), need)
		for _, c := range certs {
			if err := w.add(c); err != nil {
				t.Fatalf("identity %d: %v", i, err)
			}
			pooled++
		}
	}
	if pooled != highWater {
		t.Fatalf("setup: pooled %d certificates, want exactly the high-water mark %d", pooled, highWater)
	}

	honestPriority := freeP * 5
	if honestPriority >= pinned {
		t.Fatalf("setup: honest priority %d is not below the pinned tail %d", honestPriority, pinned)
	}
	honest := buildCert(t, w, key(t, 999_998), 0, honestPriority, honestPriority)
	ceiling, ok := honest.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	w.state.Set(types.NativeBalanceSlot(key(t, 999_998).Persistent()), ceiling)

	evictedBefore := w.pool.Stats().Evicted
	err := w.add(honest)
	if !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("an honest arrival declaring %d against a floor pinned at %d returned %v, "+
			"want ErrBelowEvictionFloor", honestPriority, pinned, err)
	}
	if w.pool.Stats().Evicted != evictedBefore {
		t.Fatalf("a refused arrival evicted %d certificates",
			w.pool.Stats().Evicted-evictedBefore)
	}
	t.Logf("floor pinned at %d by %d identities; an honest arrival at %d is refused — "+
		"the mechanism is unchanged, deliberately; only its price moved",
		pinned, identities, honestPriority)
}
