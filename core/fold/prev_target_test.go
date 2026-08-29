package fold_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/spec"
)

// TestTheEpochStateRootCommitsATargetTheFoldNeverChecks is the fold's own
// witness that it does not: F2c copies Header.Target into PrevTargetSlot
// verbatim, that cell enters the state root the header commits at an epoch
// boundary, and nothing in this package ever compares the field against
// pow.NextTarget.
//
// It is an existential and is stated as one (§21): there EXIST blocks whose
// declared target is not the difficulty rule's answer, which fold.ApplyBlock
// ACCEPTS, and whose committed epoch state roots differ from each other and
// from the honest one — so the commitment is a function of an unvalidated
// field. It claims no maximum and no exhaustiveness over what a fabricated
// target can do; two witnesses at opposite ends are enough for the claim, and
// a third would not strengthen it.
//
// **This test asserts the current rule, deliberately.** If it ever fails
// because ApplyBlock rejected one of these blocks, that is not a broken test:
// somebody made the fold validate the target, which is a consensus-rule change
// with the vector corpus behind it. Read the failure as the flag it is.
//
// Why the fold does not do it, since the neighbouring rule went the other way:
// checkSeedEpoch moved B0b INTO the fold because B0b is total arithmetic over
// Height and can be stated as a (pre-state, block) claim. The difficulty rule
// cannot be stated in that shape at all — it reads DifficultyWindow+1
// preceding headers, which ApplyBlock is not given — and that is exactly why
// a second, parallel (params, headers) -> next_target corpus was built for it
// instead. What keeps the fabrication unreachable is that every path by which
// a block **from another node** reaches the chain re-derives the equality:
// node/p2p Engine.OnBlock, node/sync.ValidateHeaders, and node/chain's
// validateBranchDifficultyLocked on the fork-choice path — the last of which
// was added after the fact, and its absence was a finding precisely because
// that path once did not check.
//
// The qualifier is load bearing. A block this node produces itself does not
// arrive by ingress: node/miner's Seal calls Chain.Apply directly, with a
// target pow.NextTarget *constructed* rather than one it compared. wire.md §9
// covers that with a separate normative clause on the producer, which is why
// the sentence above says "from another node" instead of "any".
func TestTheEpochStateRootCommitsATargetTheFoldNeverChecks(t *testing.T) {
	p := spec.Devnet()
	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()

	// Stop one block short of the first epoch boundary above genesis, so the
	// block under test is one that actually commits a state root in its
	// header rather than merely computing one.
	for c.NextHeight() < p.EpochLength {
		if _, _, err := c.AddBlock(payout); err != nil {
			t.Fatal(err)
		}
	}
	height := c.NextHeight()
	if !p.IsEpochBoundary(height) || height == 0 {
		t.Fatalf("height %d is not an epoch boundary above genesis, so no state root is "+
			"committed here and this test would be about a root nobody signs", height)
	}

	window := c.Headers
	if n := int(p.DifficultyWindow) + 1; len(window) > n {
		window = window[len(window)-n:]
	}
	honest := pow.NextTarget(window, p)
	if honest.IsZero() {
		t.Fatal("the difficulty rule answered zero, which it never returns; the window " +
			"handed to it is wrong and every comparison below is against nothing")
	}

	roots := make(map[types.Hash]string)
	for _, fab := range []struct {
		what   string
		target u256.U256
	}{
		{"the honest answer, as the control", honest},
		{"the hardest target representable", u256.One},
		{"the network's absolute ceiling", p.MaxTarget},
	} {
		if fab.what != "the honest answer, as the control" && fab.target.Eq(honest) {
			t.Fatalf("%q happens to equal the difficulty rule's own answer, so it is not a "+
				"fabrication and pins nothing", fab.what)
		}

		b, err := c.Propose(payout)
		if err != nil {
			t.Fatal(err)
		}
		// The ONLY field that differs between the three candidates. Everything
		// else — parent, height, time, payout, certificate and citation roots
		// — comes from the same Propose call against the same tip.
		b.Header.Target = fab.target
		root, err := fold.SealStateRoot(c.State, b, p)
		if err != nil {
			t.Fatalf("%s: sealing the state root failed: %v", fab.what, err)
		}
		b.Header.StateRoot = root

		st := c.State.Clone()
		if _, err := fold.ApplyBlock(st, b, p); err != nil {
			t.Fatalf("%s: the fold REJECTED a block declaring target %s (%v).\n"+
				"If that is deliberate, the fold now validates the difficulty rule — a "+
				"consensus-rule change, and the vector corpus moves with it.",
				fab.what, fab.target.String(), err)
		}
		if got := st.Get(types.PrevTargetSlot()); !got.Eq(fab.target) {
			t.Fatalf("%s: PrevTargetSlot holds %s, want the declared %s copied verbatim",
				fab.what, got.String(), fab.target.String())
		}
		if prior, seen := roots[root]; seen {
			t.Fatalf("%s and %s sealed the same state root %x; then the root does not "+
				"depend on the declared target and this test proves nothing",
				fab.what, prior, root[:8])
		}
		roots[root] = fab.what
	}

	if len(roots) != 3 {
		t.Fatalf("three candidate targets produced %d distinct roots", len(roots))
	}
}
