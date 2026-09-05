package chain_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/wallet"
)

// A height-lowering reorg must leave no certificate the pool cannot remove, and
// no certificate the pool still holds may stop the miner producing a block.
//
// The two halves are separate defects and this drives both from one real reorg:
//
//   - Pool.Add mirrors both bounds of the consensus TTL rule (B1 and B2), but
//     the re-screen that runs when the tip moves mirrored only B1. Fork choice
//     compares accumulated work and has no height rule, so a shorter, heavier
//     branch lowers the tip; a certificate admitted at TTL = tip+1+TTL_MAX is
//     then past B2's ceiling, and no removal reason covered it.
//   - Select never reads TTL, and dropTheDrops treated a block rule's refusal
//     as a builder bug and returned no block at all. So one such certificate
//     cost the node every block — and since Pool.OnBlock runs only downstream
//     of a successful Apply, a node that cannot build never re-screens and
//     could not clear the certificate even after the pool was fixed.
//
// The reorg is a real chain.ConsiderBranch, not a hand-set pool height: the bug
// is in the transition, and asserting against a post-state built by hand would
// be asserting the assertion.
func TestAHeightLoweringReorgStrandsNoCertificateAndStopsNoMiner(t *testing.T) {
	p := devnetEasy()
	payer := key(t, 1)
	n := openNode(t, t.TempDir(), p, payer.Persistent())
	defer n.close(t)

	// Far enough for the payout to have matured, so the deposit screen has
	// something real to pass, and clear of any epoch boundary buildBranch
	// refuses to cross.
	n.mine(t, int(p.CoinbaseMaturity)+2)
	tipBefore := n.chain.Height()

	build := func(seq, ttl uint64) *types.Certificate {
		t.Helper()
		b := &wallet.Builder{
			Params:  p,
			Seq:     seq,
			Program: wallet.Tip(types.NativeAsset, payer.Persistent(), key(t, 42).Persistent(), drops(1_000)),
			TTL:     ttl,
			Deposit: wallet.SelfDeposit(payer.Persistent(), payer.Persistent()),
			FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
			Signers: []*wallet.Key{payer},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// The new arm must be exactly as wide as B2 and no wider: a screen stricter
	// than the block rules censors certificates the network would have
	// accepted, which is the same mirror divergence, pointing the other way.
	// This one lands exactly ON the ceiling the lowered tip creates, so it is
	// still includable after the reorg and must survive the re-screen. It leads
	// in Seq so that stranding the one above it cannot strand this one too.
	survivor := build(0, tipBefore+p.TTLMax)
	// The certificate sits exactly on B2's ceiling for the current tip: the
	// highest TTL the pool will admit, and the one a lowered tip strands.
	cert := build(1, tipBefore+1+p.TTLMax)
	// And the certificate above it in the same Seq chain, whose own TTL is
	// legal. It has to go too: its declared reads are on the writes of a
	// certificate that can no longer be included, so it can never apply, and a
	// pool that kept it would keep offering the miner work guaranteed to skip —
	// which is what strands() is for and the exact thing §2.3 exists to prevent.
	successor := build(2, tipBefore+p.TTLMax)
	for _, c := range []*types.Certificate{survivor, cert, successor} {
		if err := n.pool.Add(c, n.chain.Snapshot().State, tipBefore); err != nil {
			t.Fatalf("a certificate at or under the TTL ceiling was refused at admission: %v", err)
		}
	}

	// Anti-vacuity, first half: it must be demonstrably buildable BEFORE the
	// reorg. A certificate that was never includable would prove nothing about
	// what the reorg did.
	before, err := n.miner.Assemble()
	if err != nil {
		t.Fatalf("assembling before the reorg: %v", err)
	}
	if !carries(before.Certs, cert.ID()) {
		t.Fatal("setup: the certificate is not in the block the miner builds before " +
			"the reorg, so nothing below observes the reorg's effect on it")
	}

	// A second pool holding the same certificate, which nothing will ever
	// re-screen. It stands in for any divergence between the pool's screen and
	// the block rules, and it is what keeps the miner half of this test
	// independent of the pool half: the miner must survive an entry the pool
	// failed to remove, whatever the reason.
	unscreened := mempool.New(p, mempool.DefaultPolicy())
	for _, c := range []*types.Certificate{survivor, cert} {
		if err := unscreened.Add(c, n.chain.Snapshot().State, tipBefore); err != nil {
			t.Fatal(err)
		}
	}

	// The reorg itself: a branch one block shorter than what it replaces,
	// carrying more work because its blocks are timed below the target spacing
	// — the same shape the LWMA permits with no attacker at all.
	const replaced = 5
	ancestor := ancestorAt(t, n, replaced)
	branch := buildBranch(t, n, payer.Persistent(), ancestor, int(replaced)-1, fastSolveSeconds)
	if !branch.Work().Gt(worthOf(t, n, replaced)) {
		t.Fatal("setup: the branch does not outweigh what it replaces, so no reorg happens")
	}
	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the branch: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("setup: the heavier branch was not adopted")
	}
	if got := n.chain.Height(); got != tipBefore-1 {
		t.Fatalf("height is %d after the reorg, want %d: the reorg did not lower the tip, "+
			"which is the whole transition under test", got, tipBefore-1)
	}

	// Exactly what node/p2p's applyToPool does on an adopted branch, in its
	// order: readmit what the reorg undid, then remove what the branch commits.
	n.chain.Read(func(v chain.View) {
		var readmit []*types.Certificate
		for _, blk := range reorg.Undone {
			readmit = append(readmit, blk.Certs...)
		}
		if len(readmit) > 0 {
			n.pool.Readmit(readmit, v.State, v.Height)
		}
		for _, blk := range branch.Blocks {
			n.pool.OnBlock(blk, v.State, v.Height)
		}
	})

	// Half one: the re-screen ran against the lowered tip, so a certificate the
	// block rules now refuse has left the pool. Without B2's arm in
	// rescreenLocked nothing removes it — not expiry, not Seen, not the base
	// fee, not the deposit, not eviction — and it stays for good.
	if n.pool.Has(cert.ID()) {
		t.Fatalf("the pool still holds a certificate with TTL %d after the tip fell to %d, "+
			"where the next block may carry no TTL above %d: no removal reason covers it, "+
			"so it is stranded for the life of the process",
			cert.TTL, n.chain.Height(), n.chain.Height()+1+p.TTLMax)
	}

	// And the arm removed only what B2 refuses. A certificate whose TTL is
	// exactly the lowered tip's ceiling is still includable, so removing it
	// would be the pool censoring work the network accepts — an off-by-one here
	// is invisible to every other assertion in this file.
	if !n.pool.Has(survivor.ID()) {
		t.Fatalf("the re-screen dropped Seq %d, TTL %d, which the next block at height %d "+
			"may carry (ceiling %d) and which leads the stranded Seq %d rather than "+
			"following it: the arm is wider than B2",
			survivor.Seq, survivor.TTL, n.chain.Height()+1,
			n.chain.Height()+1+p.TTLMax, cert.Seq)
	}

	// Removing it strands what sits above it. The successor's own TTL is legal,
	// so no arm in the re-screen names it; only the vacated Seq does. Without
	// strands() on the B2 arm it stays pooled and permanently unappliable, and
	// nothing else in this file can see that.
	if n.pool.Has(successor.ID()) {
		t.Fatalf("the pool still holds Seq %d after Seq %d left on B2: its reads are on "+
			"writes that can no longer happen, so it can never apply and the re-screen "+
			"did not strand it", successor.Seq, cert.Seq)
	}

	// Anti-vacuity, second half: the rejected rule — keeping only B1's arm —
	// gives a different answer in this very scenario, because the certificate
	// has not expired.
	if cert.TTL < n.chain.Height()+1 {
		t.Fatal("the certificate expired, so B1's arm alone would also have removed it " +
			"and this test does not distinguish the two rules")
	}

	// Half two: a miner whose pool still offers the refused certificate must
	// still produce a block. This is the block the halt bites on — the next one
	// after the reorg, at the height whose ceiling the certificate is past.
	stuck := &miner.Miner{
		Chain: n.chain, Pool: unscreened, Engine: pow.Dev{},
		Payout: payer.Persistent(), Now: n.miner.Now,
	}
	after, err := stuck.Assemble()
	if err != nil {
		t.Fatalf("a miner holding one certificate the block rules refuse built no block "+
			"at all: %v", err)
	}
	if carries(after.Certs, cert.ID()) {
		t.Fatal("the builder kept a certificate B2 refuses; the block it proposes is invalid")
	}
	// The exclusion is targeted: the certificate no rule named is still in the
	// block, so the builder gave up one certificate rather than its revenue.
	if !carries(after.Certs, survivor.ID()) {
		t.Fatal("the builder dropped a certificate no block rule refuses; the exclusion " +
			"cost the block its contents rather than the one certificate")
	}
	if err := stuck.Seal(after, 1<<20); err != nil {
		t.Fatalf("sealing the block built past the refused certificate: %v", err)
	}
	if _, err := n.chain.Apply(after); err != nil {
		t.Fatalf("the block the miner built past the refused certificate was rejected "+
			"by the chain: %v", err)
	}
	if got := n.chain.Height(); got != tipBefore {
		t.Fatalf("height is %d, want %d: the node did not recover the height the reorg took",
			got, tipBefore)
	}
}

func carries(certs []*types.Certificate, id types.Hash) bool {
	for _, c := range certs {
		if c.ID() == id {
			return true
		}
	}
	return false
}

// Past the rule-exclusion budget the builder must still propose a block, and
// under it the block must still carry the certificates no rule refuses.
//
// maxRuleDrops caps how many certificates dropTheDrops will exclude on a block
// rule's say-so, and the cap's whole point is that hitting it costs revenue,
// never the block. Both sides of the boundary are asserted, because
// only the pair distinguishes the fallback from the ordinary exclusion path:
// with one refusal under the cap the good certificate survives, and with one
// refusal over it the fallback gives up the certificates rather than the
// block. A test of only the over-cap side would pass with the exclusion loop
// deleted entirely.
func TestTheRuleExclusionBudgetCostsRevenueNotTheBlock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		refused  int
		wantGood bool
		// mineTo is the height the reorg lowers FROM, so the block under
		// assembly is at exactly this height. Zero takes the shortest fixture
		// that funds the deposit.
		mineTo uint64
		// replaced is how many blocks the reorg's branch replaces; it builds
		// one fewer. How large it has to be to outweigh them depends on how
		// full the difficulty window is, which depends on the height.
		replaced uint64
	}{
		{name: "at the budget the good certificate survives", refused: 4, wantGood: true},
		{name: "past the budget the block keeps only what no rule named", refused: 5, wantGood: true},
		{name: "past the budget and the confirming fold the block is empty but is still a block",
			refused: 6, wantGood: false},
		// An epoch boundary is where Assemble seals a state root, and
		// SealStateRoot runs the same block rules as SealOutcomes and can name
		// the same certificate. The exclusion path was attached to one call
		// site rather than to the error, so at one height in every EPOCH_LENGTH
		// the miner built no block at all — the halt this file exists for, at
		// the heights a stuck node cannot skip past. Devnet's epoch is 64
		// blocks.
		{name: "an epoch boundary is not an exemption", refused: 1, wantGood: true, mineTo: 64, replaced: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := devnetEasy()
			payer := key(t, 1)
			n := openNode(t, t.TempDir(), p, payer.Persistent())
			defer n.close(t)

			mineTo := tc.mineTo
			if mineTo == 0 {
				mineTo = p.CoinbaseMaturity + 2
			}
			n.mine(t, int(mineTo))
			tipBefore := n.chain.Height()
			if p.IsEpochBoundary(tipBefore) != (tc.mineTo != 0) {
				t.Fatalf("setup: the block under assembly is at height %d, boundary=%v; "+
					"this case is meant to be the other one", tipBefore, p.IsEpochBoundary(tipBefore))
			}

			build := func(seq uint64, ttl uint64) *types.Certificate {
				t.Helper()
				b := &wallet.Builder{
					Params:  p,
					Seq:     seq,
					Program: wallet.Tip(types.NativeAsset, payer.Persistent(), key(t, 42).Persistent(), drops(1_000)),
					TTL:     ttl,
					Deposit: wallet.SelfDeposit(payer.Persistent(), payer.Persistent()),
					FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
					Signers: []*wallet.Key{payer},
				}
				c, err := b.Build()
				if err != nil {
					t.Fatal(err)
				}
				return c
			}

			// A pool nothing will re-screen, standing in for any divergence
			// between the pool's screen and the block rules — the same stand-in
			// the reorg test uses, and the only way to put a refused
			// certificate in front of the builder at all now that the screen
			// mirrors both of B2's bounds.
			unscreened := mempool.New(p, mempool.DefaultPolicy())
			st := n.chain.Snapshot().State

			// Seq 0 is the one no rule refuses. It leads, so excluding the
			// certificates above it cannot make it stale.
			good := build(0, tipBefore+2)
			if err := unscreened.Add(good, st, tipBefore); err != nil {
				t.Fatal(err)
			}
			// The rest sit exactly on B2's ceiling for the tip they were
			// admitted at, so a tip one block lower puts every one of them past
			// it — one refusal each.
			for i := 0; i < tc.refused; i++ {
				c := build(uint64(1+i), tipBefore+1+p.TTLMax)
				if err := unscreened.Add(c, st, tipBefore); err != nil {
					t.Fatalf("certificate %d at the TTL ceiling was refused at admission: %v", i, err)
				}
			}

			replaced := tc.replaced
			if replaced == 0 {
				replaced = 5
			}
			ancestor := ancestorAt(t, n, replaced)
			branch := buildBranch(t, n, payer.Persistent(), ancestor, int(replaced)-1, fastSolveSeconds)
			if !branch.Work().Gt(worthOf(t, n, replaced)) {
				t.Fatal("setup: the branch does not outweigh what it replaces, so no reorg happens")
			}
			reorg, err := n.chain.ConsiderBranch(branch)
			if err != nil {
				t.Fatal(err)
			}
			if !reorg.Adopted || n.chain.Height() != tipBefore-1 {
				t.Fatalf("setup: adopted=%v height=%d, want the tip lowered to %d",
					reorg.Adopted, n.chain.Height(), tipBefore-1)
			}

			stuck := &miner.Miner{
				Chain: n.chain, Pool: unscreened, Engine: pow.Dev{},
				Payout: payer.Persistent(), Now: n.miner.Now,
			}
			blk, err := stuck.Assemble()
			if err != nil {
				t.Fatalf("a miner offered %d refused certificates built no block at all: %v",
					tc.refused, err)
			}
			for _, c := range blk.Certs {
				if c.TTL > blk.Header.Height+p.TTLMax {
					t.Fatalf("the block carries a certificate B2 refuses (TTL %d at height %d)",
						c.TTL, blk.Header.Height)
				}
			}
			if got := carries(blk.Certs, good.ID()); got != tc.wantGood {
				t.Fatalf("the good certificate is in the block: %v, want %v (block carries %d certificates)",
					got, tc.wantGood, len(blk.Certs))
			}
			// Whatever the budget did, what came out must be a block the chain
			// accepts — that is the property the fallback exists for.
			if err := stuck.Seal(blk, 1<<20); err != nil {
				t.Fatal(err)
			}
			if _, err := n.chain.Apply(blk); err != nil {
				t.Fatalf("the block built past the refused certificates was rejected: %v", err)
			}
		})
	}
}
