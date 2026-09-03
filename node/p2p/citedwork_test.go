package p2p_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/p2p"
	"zycord/spec"
)

// TestABlockCitingAHeaderThatNeverDidItsWorkIsRefused pins `docs/spec/wire.md`
// §9 rule 7 on the gossip path: every competing header a body cites must be
// verified for proof of work, and that is consensus rather than policy.
//
// # Why this test exists at all
//
// The rule was held by prose and by nothing executable. Measured on the
// head this test was written against: with the cited-header work loop neutered
// in BOTH `node/p2p/engine.go` and `node/sync/sync.go`, `./spec`, `./node/p2p`,
// `./node/sync`, `./node/chain` and `./sim/wiring` were all green. The corpus
// cannot see it and that half is structural — a golden vector replays
// `fold.ApplyBlock`, which holds no difficulty engine, and `core/fold`'s
// `checkCites` says why it never will. What was not structural is that no test
// saw it either.
//
// A node that skips this check counts citations backed by no work. `cited_count`
// feeds the epoch health gate, the gate decides whether the sequential target
// `T` may grow, and `T` moves every block ceiling — so the divergence is a
// chain split arrived at one epoch later than a skipped block-level work check
// would produce one.
//
// # Why the parameters are devnet's own and not devnetEasy()
//
// `devnetEasy` raises the target to `u256.Max` so that work is free, which is
// what lets every other test in this file build blocks nobody had to mine. At
// that setting `CheckWork` cannot fail for any header, so the rule under test
// is unreachable and this test would pass vacuously. Devnet's real genesis
// target is about 2^248.6, so a header solves with probability near 2^-7 and a
// nonce loop of a few hundred hashes settles either side of the rule.
//
// # The three arms, and why the third is the one that decides
//
// The forged citation and the honest one differ in ONE field, the nonce: same
// version, same height, same parent, same declared target, same payout. So the
// refusal below cannot be about citing, about the shape of the citation, or
// about any field a stricter structural rule could reach — the two headers are
// byte-identical apart from the number the work is computed over.
func TestABlockCitingAHeaderThatNeverDidItsWorkIsRefused(t *testing.T) {
	p := spec.Devnet()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 3)
	tip := victim.chain.Tip()

	// A competitor to the block below the tip: same height, same parent, same
	// declared target, a different payout address so it is a different header
	// and not a self-citation. This is what an honest proposer reports having
	// seen lose a race.
	sibling := func() types.Header {
		return types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height,
			ParentID:     tip.ParentID,
			Time:         tip.Time,
			EmissionAddr: key(t, 4).Persistent(),
			Target:       tip.Target,
			PoW:          types.PoWSeal{SeedEpoch: tip.PoW.SeedEpoch},
		}
	}

	// The forgery: the same header at a nonce that does not solve. Ground
	// rather than assumed, so the arm cannot silently become the honest case
	// if a hash, a tag or the target ever moves.
	forged := sibling()
	var found bool
	for n := uint32(0); n < 1<<16; n++ {
		forged.PoW.Nonce = n
		if pow.CheckWork(pow.Dev{}, forged, p) != nil {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("setup: no nonce in 65,536 leaves this header short of its declared " +
			"target; work is free at these parameters and the arm below is vacuous")
	}
	// Stated twice on purpose: the digest must genuinely exceed the target, so
	// that what refuses the block can only be the work.
	digest := (pow.Dev{}).Hash(pow.KeyFor(forged.Height, p), forged.PoWInput())
	// FromLEBytes, matching the rule this line is confirming: the work check
	// reads the digest little-endian (pow.checkWorkWith), so a confirmation
	// that read it big-endian would be asserting something the rule never
	// says. The two conventions read independent ends of the digest, so they
	// agree only by luck — and where the luck runs out this arm claims a
	// forgery meets its target while CheckWork has just said it does not.
	if !u256.FromLEBytes(digest).Gt(forged.Target) {
		t.Fatal("setup: the forged citation meets its declared target after all")
	}

	// The honest one, identical but for the nonce.
	honest := sibling()
	if !pow.Solve(pow.Dev{}, &honest, p, 1<<24) {
		t.Fatal("setup: could not solve the control citation at devnet's own target")
	}
	if pow.CheckWork(pow.Dev{}, honest, p) != nil {
		t.Fatal("setup: Solve returned a header CheckWork refuses")
	}
	if forged.Height != honest.Height || forged.ParentID != honest.ParentID ||
		!forged.Target.Eq(honest.Target) || forged.EmissionAddr != honest.EmissionAddr ||
		forged.Time != honest.Time || forged.Version != honest.Version {
		t.Fatal("setup: the two citations differ in more than the nonce, so the " +
			"comparison below is not about the work")
	}

	// carry builds a block at the tip's next height that cites one header. The
	// carrier's own work is solved AFTER the citation is attached, because
	// CitesRoot is a proof-of-work input: a carrier that failed its own work
	// would be refused by the block-level check and this test would pass
	// without ever reaching the rule.
	carry := func(cited types.Header, nonce uint64) *types.Block {
		t.Helper()
		b := fakeOrphan(t, p, victim.chain.Height()+1, tip.Target, nonce)
		b.Cites = []*types.Header{&cited}
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		if !pow.Solve(pow.Dev{}, &b.Header, p, 1<<24) {
			t.Fatal("setup: could not solve the carrying block")
		}
		return b
	}

	handshake(t, victim, "attacker:1")
	before := victim.engine.OrphanCount()

	v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(carry(forged, 11)))
	if v.Score >= 0 {
		t.Fatalf("a block citing a header that never did its work scored %d: the "+
			"citation cost nothing to fabricate, and cited_count moves T", v.Score)
	}
	if v.Forward {
		t.Fatal("a block carrying an unworked citation was relayed to the network")
	}
	if got := victim.engine.OrphanCount(); got != before {
		t.Fatalf("the orphan pool went from %d to %d: a body whose citation carries "+
			"no work was admitted", before, got)
	}

	// The arm that makes the refusal about the work rather than about citing.
	// Without it a node that refused every citing block would pass — and that
	// node contradicts core/fold's checkCites, which accepts them, and
	// suppresses the competing-header signal whitepaper §8.1's health gate
	// reads.
	held := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(carry(honest, 12)))
	if held.Score < 0 {
		t.Fatalf("the same block citing the same header at a solved nonce was refused "+
			"too (%v), so the case above is not measuring the work", held.Err)
	}
	if got := victim.engine.OrphanCount(); got != before+1 {
		t.Fatalf("the validly-citing block was not held (%d orphans, want %d); the "+
			"comparison above is empty", got, before+1)
	}
}
