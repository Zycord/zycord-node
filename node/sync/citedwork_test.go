package sync_test

import (
	"errors"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/sync"
)

// TestASyncedBodyCitingAHeaderThatNeverDidItsWorkIsRefused is the sibling of
// node/p2p's test of the same name, on the other ingress path.
//
// `docs/spec/wire.md` §9 rule 7 is consensus: a node that counts citations
// backed by no work derives a different `cited_count`, a different `T` one
// epoch later, and forks. The check is deliberately duplicated into this file's
// package and into node/p2p — the two call sites return different types and
// only one has a salvage step — and `PROTOCOL.md` rule 12's lesson is that a
// rule with two homes drifts toward whichever one nobody measures. Before this
// test and its sibling, neither was measured: neutering both loops left the
// whole tree green.
//
// The forged and the honest citation differ in ONE field, the nonce. Everything
// a structural rule could reach — version, height, parent, declared target,
// payout, time — is identical, so what refuses the body can only be the work.
func TestASyncedBodyCitingAHeaderThatNeverDidItsWorkIsRefused(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	// Anti-vacuity, the same one the neighbouring citation test uses: an honest
	// peer through its own cache reaches the tip, so a failure below is the
	// citation rather than the harness.
	control := newNode(t, p, key(t, 2).Persistent())
	ctl := sync.NewBodyCache()
	if _, err := sync.Run(control.chain, pow.Dev{}, ctl.Source(&peer{t: t, chain: source.chain}), 128); err != nil {
		t.Fatalf("setup: an honest sync through a cache failed: %v", err)
	}
	if control.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatal("setup: an honest sync through a cache did not reach the tip")
	}

	victim := newNode(t, p, key(t, 3).Persistent())
	cache := sync.NewBodyCache()
	liar := newUnworkedCitingPeer(t, &peer{t: t, chain: source.chain}, p)

	_, err := sync.Run(victim.chain, pow.Dev{}, cache.Source(liar), 128)
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("got %v, want the body refused at ingress as unavailable: its "+
			"citation carries no work, and cited_count moves T", err)
	}
	if liar.bodyRequests == 0 {
		t.Fatal("setup: the forged tip was never requested, so nothing was exercised")
	}

	// The half the error alone does not pin: the body must not have been
	// retained. Without the guard the citation loop passes, `Retain` runs, and
	// the forgery is served back out of local memory to every later attempt —
	// the same failure `TestAPoisonedBodyDoesNotPersistInTheCache` exists for.
	honest := &peer{t: t, chain: source.chain}
	for i := 0; i < 10; i++ {
		if _, err := sync.Run(victim.chain, pow.Dev{}, cache.Source(honest), 128); err == nil {
			break
		}
	}
	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatalf("after ten honest syncs the node is stuck at height %d of %d: a body "+
			"citing an unworked header was retained and is being served back from "+
			"local memory", victim.chain.Height(), source.chain.Height())
	}
}

// newUnworkedCitingPeer serves the source's chain with the tip's body carrying
// one citation: a competitor to the tip's own parent, well formed in every
// field the fold checks, at a nonce that does not solve.
//
// The carrier is re-solved AFTER the citation is attached, because CitesRoot is
// a proof-of-work input — a carrier that failed its own work would be refused
// by the header stage and the test would never reach the rule.
func newUnworkedCitingPeer(t *testing.T, base *peer, p *params.Params) *citingPeer {
	t.Helper()
	tip, err := base.chain.BlockAt(base.chain.Height())
	if err != nil {
		t.Fatal(err)
	}
	parent, err := base.chain.BlockAt(base.chain.Height() - 1)
	if err != nil {
		t.Fatal(err)
	}

	// A sibling of the tip's parent: same height, same parent, same declared
	// target, a different payout so it is a different header and not the
	// carrier's own parent. This is what checkCites accepts.
	cited := parent.Header
	cited.EmissionAddr = key(t, 9).Persistent()

	var found bool
	for n := uint32(0); n < 1<<16; n++ {
		cited.PoW.Nonce = n
		if pow.CheckWork(pow.Dev{}, cited, p) != nil {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("setup: no nonce in 65,536 leaves this citation short of its declared " +
			"target; work is free at these parameters and the test is vacuous")
	}
	digest := (pow.Dev{}).Hash(pow.KeyFor(cited.Height, p), cited.PoWInput())
	// FromLEBytes, matching the rule this line is confirming: the work check
	// reads the digest little-endian (pow.checkWorkWith), so a confirmation
	// that read it big-endian would be asserting something the rule never
	// says. The two conventions read independent ends of the digest, so they
	// agree only by luck — and where the luck runs out this arm claims a
	// forgery meets its target while CheckWork has just said it does not.
	if !u256.FromLEBytes(digest).Gt(cited.Target) {
		t.Fatal("setup: the forged citation meets its declared target after all")
	}
	if cited.ID() == tip.Header.ParentID {
		t.Fatal("setup: the citation is the carrier's own parent, which checkCites " +
			"refuses for a reason that has nothing to do with work")
	}

	body := &types.Block{Header: tip.Header, Certs: tip.Certs, Cites: []*types.Header{&cited}}
	body.Header.CitesRoot = body.ComputeCitesRoot(p)
	if !pow.Solve(pow.Dev{}, &body.Header, p, 1<<24) {
		t.Fatal("setup: could not re-solve the forged tip at the real target")
	}
	return &citingPeer{peer: base, forged: body.Header, body: body}
}
