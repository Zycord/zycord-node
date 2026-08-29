package p2p

import (
	"errors"
	"fmt"
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
)

// The key-epoch price the announce path carries, measured on the
// BLOCK-BODY path it was missing from.
//
// The announce path's spendKeyEpoch gate stands ahead of work.Check in
// OnBlockAnnounceFrom; OnBlock ran work.Check on the carrier header with nothing
// in front of it. A KindBlock "needs no announcement", so an unsolicited body at
// a sender-chosen foreign key epoch forced one ~0.55 s / 256 MiB cache
// initialisation on the receiver, free (a declared u256.Max target no digest can
// exceed costs the sender no work) and unbounded across minted identities. This
// file drives OnBlockFrom the way HandleFrom does — a connection address plus the
// authenticated identity the price is charged to — and measures that the same
// two bounds the announce path carries now bind the body path too.
//
// It reuses budgetHarness (keyepochbudget_internal_test.go): one engine, one
// devnet chain at genesis, a frozen clock, and an epoch counter in front of the
// work function, so the counts here are the same quantity the announce-path
// tests report and are comparable with them.

// bodyAtEpoch marshals one single-chunk block body whose carrier header is at
// the first height of the given key epoch, at the declared target given. It is
// the body-path twin of headerAtEpoch: same header, wrapped in a block with its
// (empty) certificate and citation roots computed, so UnmarshalBlock accepts it
// and the carrier reaches work.Check.
//
// The target property headerAtEpoch asserts — u256.Max PASSES CheckWork, an
// unmeetable target FAILS it — is a fact about the digest against the target and
// is independent of the roots set here, so wrapping the header does not disturb
// it.
func (h *budgetHarness) bodyAtEpoch(t *testing.T, epoch, nonce uint64, target u256.U256) []byte {
	t.Helper()
	p := h.c.Params()
	hd := h.headerAtEpoch(t, epoch, nonce, target).hd
	blk := &types.Block{Header: hd}
	blk.Header.CertRoot = blk.ComputeCertRoot(p)
	blk.Header.CitesRoot = blk.ComputeCitesRoot(p)
	return blk.MarshalSSZ()
}

// keyForEpoch is the RandomX key one epoch's first height selects, so a test can
// ask "was THIS epoch's cache built" rather than only "how many were".
func (h *budgetHarness) keyForEpoch(epoch uint64) types.Hash {
	p := h.c.Params()
	return pow.KeyFor(p.RandomXKeyLag+epoch*p.RandomXKeyInterval, p)
}

// TestABlockBodyFloodAtOneIdentitysOwnTargetBuysABoundedNumberOfKeyEpochs is the
// body-path twin of TestAnAnnouncersOwnTargetBuysABoundedNumberOfKeyEpochs.
//
// Direction, declared before the run (PROTOCOL.md rule 22): with the gate in
// place a flood of foreign-epoch bodies from one identity forces at most the
// per-identity budget of distinct key epochs, and every message past the budget
// is refused unevaluated at CostBudgeted with ErrKeyEpochBudget — so the flood
// terminates in a state this test asserts (rule 26) rather than in silence.
//
// The rival hypotheses (rule 27) and where each falls:
//   - "the gate does not bite": then distinctKeys climbs past the budget with the
//     epochs the sender chose, and the > bound arm below fails.
//   - "the gate bites too early / something else refuses first": then distinctKeys
//     is below the budget, and the < bound arm fails — the budget must be
//     REACHABLE, every credit spendable on a fresh 256 MiB build.
//
// u256.Max, so every body PASSES the work check and the refusal below is the
// budget's and not the work check's: the epochs are bounded by a price in front
// of the build, exactly what the body path lacked.
func TestABlockBodyFloodAtOneIdentitysOwnTargetBuysABoundedNumberOfKeyEpochs(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const peer = "10.71.0.1:5000"
	const identity = "one-body-flooding-identity"

	// Comfortably past the budget, so the terminating state is actually reached.
	const send = 50
	const bound = MaxUnheldKeyEpochsPerPeer

	budgeted := 0
	for n := 0; n < send; n++ {
		// One fresh foreign epoch per message, walking away from the tip's, so
		// every admitted message can be spent on a distinct never-held build and
		// the bound is tight rather than slack.
		epoch := own + 2 + uint64(n)
		v := h.e.OnBlockFrom(peer, identity, h.bodyAtEpoch(t, epoch, uint64(n), u256.Max))
		if v.Cost == CostBudgeted && errors.Is(v.Err, ErrKeyEpochBudget) {
			budgeted++
			// A budget refusal is a price, not a ban: scoring on top of it would
			// ban the honest peers a node behind the chain depends on, the
			// failure that reverted the tip-window guard (I7-H4). The announce
			// path pins this and the body path must too.
			if v.Score != 0 {
				t.Fatalf("a CostBudgeted body refusal carried Score %d; the budget "+
					"is the price and scoring on top turns it into the ban I7-H4 "+
					"reverted", v.Score)
			}
			// And the epoch it named must NOT have been built for it: the price
			// stands ahead of the build, so a refused body costs no cache.
			if h.work.sawKey(h.keyForEpoch(epoch)) {
				t.Fatalf("the key for epoch %d was built for a body the budget "+
					"refused: the price is charged after the CPU is spent, which "+
					"bounds a verdict and not a resource", epoch)
			}
		}
	}

	forced := h.work.distinctKeys()
	t.Logf("%d foreign-epoch bodies from one identity: %d distinct key epochs "+
		"built, %d refused unevaluated at CostBudgeted — bound is %d (a "+
		"per-identity budget), and at ~%.1f s per never-held epoch that is %.1f s "+
		"of CPU rather than %.1f s",
		send, forced, budgeted, bound, secondsPerNewEpoch,
		float64(forced)*secondsPerNewEpoch, float64(send)*secondsPerNewEpoch)

	if forced > bound {
		t.Fatalf("%d bodies from one identity built %d distinct key epochs, above "+
			"the budget of %d: the price on a key epoch this node is not working "+
			"in is not charged on the body path", send, forced, bound)
	}
	if forced < bound {
		t.Fatalf("%d bodies built only %d distinct key epochs against a reachable "+
			"budget of %d: something refuses these before the budget does, so this "+
			"test measures that instead and the worst case it publishes is "+
			"understated", send, forced, bound)
	}
	// The terminating state, asserted rather than awaited: every message past the
	// budget is refused unevaluated. A run in which nothing past the bound was
	// refused is a run in which the gate never fired.
	if budgeted != send-bound {
		t.Fatalf("%d of %d bodies were refused unevaluated at CostBudgeted, want "+
			"%d; every message past the budget is refused, and any other split "+
			"means the epochs above were bounded by something else",
			budgeted, send, send-bound)
	}
}

// TestABlockBodyFloodOfInvalidWorkTerminatesByBanEvenWithGoodwill is the body
// path's score conjunct: the over-budget refusal is SCORED once this identity's
// bodies have already been refused by the work check, so a minted-identity flood
// of invalid-work bodies terminates by ban rather than by an unscored amnesty.
//
// The mechanism, and why it needs its own test: OnBlockFrom marks the identity
// work-refused when the carrier fails work.Check (the same bit OnBlockAnnounceFrom
// sets), and spendKeyEpoch's own-budget refusal reads that bit. Without the mark,
// an identity that exhausts its budget while carrying goodwill would be refused
// unscored forever — the amnesty measured on the announce path, one path
// over. The goodwill start is what pushes the budget's exhaustion ahead of the
// score's own ban, so the over-budget scored branch is actually exercised: from
// a clean start the work-check score alone bans within the budget and this branch
// never runs.
//
// unmeetable target, so every body FAILS work.Check and is the charged half.
func TestABlockBodyFloodOfInvalidWorkTerminatesByBanEvenWithGoodwill(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const peer = "10.71.0.2:5000"
	const send = 60
	unmeetable := u256.FromUint64(1)

	// Enough goodwill that the budget empties before the work-check score reaches
	// the ban threshold, so the over-budget path is reached with the identity not
	// yet banned. The engine returns verdicts and never scores itself, so the
	// score is applied here the way node.go does.
	h.e.Peers.Add(peer)
	h.e.Peers.Adjust(peer, ScoreCeiling)

	// payer == peer (a string identity), so the work-refused bit, the budget and
	// the score are all keyed on the same value, and node.go's identity scoring is
	// the string-keyed Adjust/Banned here — exactly as the announce-path flood
	// test drives it.
	sent, refusedUnevaluated, scoredOverBudget, banned := 0, 0, 0, false
	for n := 0; n < send; n++ {
		if h.e.Peers.Banned(peer) {
			banned = true
			break
		}
		epoch := own + 2 + uint64(n)
		v := h.e.OnBlockFrom(peer, peer, h.bodyAtEpoch(t, epoch, uint64(n), unmeetable))
		sent++
		switch {
		case v.Cost == CostBudgeted && errors.Is(v.Err, ErrKeyEpochBudget):
			refusedUnevaluated++
		case v.Score == ScoreInvalidMessage && errors.Is(v.Err, ErrKeyEpochBudget):
			// Over budget AND scored: the conjunct this test is about.
			scoredOverBudget++
		}
		if v.Score != 0 {
			h.e.Peers.Adjust(peer, v.Score)
		}
	}
	if h.e.Peers.Banned(peer) {
		banned = true
	}

	t.Logf("invalid-work bodies from +%d goodwill: sent %d, %d refused "+
		"unevaluated, %d refused over-budget AND scored, banned=%v; %d distinct "+
		"key epochs built against a budget of %d",
		ScoreCeiling, sent, refusedUnevaluated, scoredOverBudget,
		banned, h.work.distinctKeys(), MaxUnheldKeyEpochsPerPeer)

	if !banned {
		t.Fatalf("a body flood from +%d goodwill was never banned: past the budget "+
			"an invalid-work body never reaches work.Check, so an unconditionally "+
			"unscored refusal is an amnesty and the flood stops terminating",
			ScoreCeiling)
	}
	// The over-budget scored branch must actually have run, or this test is
	// TestAUniqueInvalidHeaderFloodIsSelfLimiting wearing another name: the ban
	// would then be the work-check score's alone and the branch under test inert.
	if scoredOverBudget == 0 {
		t.Fatal("no body was refused over-budget AND scored, so the score conjunct " +
			"on the body path was never exercised — the goodwill did not push the " +
			"budget past the work-check ban, or the mark is not being set")
	}
	// The build is bounded by the budget however long the flood runs: only the
	// evaluated (within-budget) bodies build a cache; the over-budget ones do not.
	if forced := h.work.distinctKeys(); forced > MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("an invalid-work flood built %d distinct key epochs, above the "+
			"budget of %d: the price is not ahead of the build", forced, MaxUnheldKeyEpochsPerPeer)
	}
}

// TestTheNodeWideCeilingBoundsBlockBodyKeyEpochsOverIdentities is the body-path
// twin of TestTheNodeWideKeyEpochCeilingBoundsTheAggregateOverIdentities.
//
// A keypair is free, so the per-identity budget bounds the rate and never the
// total: a fresh identity for every body buys a fresh per-identity budget
// for the price of a handshake. The only thing that bounds the total number of
// never-held cache builds across identities is the node-wide ceiling, which is
// keyed on nothing a sender presents. This drives one foreign-epoch body per
// fresh identity, well past the ceiling, and requires the total distinct builds
// to be exactly the ceiling — not identities x budget.
//
// Declared direction (rule 22): builds == DefaultMaxUnheldKeyEpochsPerNode and
// refusals == send - ceiling, and the two must account for every message.
func TestTheNodeWideCeilingBoundsBlockBodyKeyEpochsOverIdentities(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const conn = "10.71.0.3:5000"
	// Four times the ceiling, a fresh identity for each, so nothing but the
	// ceiling can be doing the bounding.
	const send = 4 * DefaultMaxUnheldKeyEpochsPerNode

	refused := 0
	for n := 0; n < send; n++ {
		identity := fmt.Sprintf("fresh-body-identity-%d", n)
		epoch := own + 2 + uint64(n)
		v := h.e.OnBlockFrom(conn, identity, h.bodyAtEpoch(t, epoch, uint64(n), u256.Max))
		if v.Cost == CostBudgeted && errors.Is(v.Err, ErrKeyEpochBudget) {
			refused++
		}
	}
	forced := h.work.distinctKeys()
	t.Logf("%d foreign-epoch bodies, a fresh identity for each, clock frozen: %d "+
		"distinct key epochs built, %d refused unevaluated, against a node-wide "+
		"ceiling of %d", send, forced, refused, DefaultMaxUnheldKeyEpochsPerNode)

	if forced != DefaultMaxUnheldKeyEpochsPerNode {
		t.Fatalf("%d fresh identities built %d distinct key epochs on the body "+
			"path, want exactly the node-wide ceiling of %d. A keypair is free, so "+
			"a bound keyed on the identity bounds the rate and never the total",
			send, forced, DefaultMaxUnheldKeyEpochsPerNode)
	}
	if refused != send-DefaultMaxUnheldKeyEpochsPerNode {
		t.Fatalf("%d of %d bodies were refused unevaluated, want %d; the refusals "+
			"and the builds must account for every message, or the count above is "+
			"not the ceiling doing the work",
			refused, send, send-DefaultMaxUnheldKeyEpochsPerNode)
	}
}

// TestAnHonestNearTipBlockBodyIsNeverGatedByTheKeyEpochBudget is the liveness
// axis, and it is the one where a cost gate placed wrong would trade a security
// bug for a worse one. A node syncing at the tip receives bodies in its own
// working key epochs routinely; if the gate charged those, an honest node behind
// the chain would refuse the very bodies it needs to climb back.
//
// workingKeyEpoch exempts {tipEpoch, tipEpoch+1} ahead of both the ceiling and
// the budget, so this drains the node-wide ceiling entirely with foreign-epoch
// floods and then delivers honest bodies in the two working epochs, requiring
// that neither is gated.
//
// The rival hypothesis (rule 27): the gate bites honest traffic too. It falls on
// two observations, and the second is the positive state (rule 26) rather than an
// absence: the tipEpoch+1 body is NOT CostBudgeted, AND its epoch's cache IS
// built — it reached work.Check and was judged on its merits, which a gated body
// never would. The tipEpoch body, whose cache this node already holds from
// verifying its own tip, is required only to be un-gated.
func TestAnHonestNearTipBlockBodyIsNeverGatedByTheKeyEpochBudget(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const conn = "10.71.0.4:5000"

	// Drain the whole node-wide ceiling from minted identities at foreign epochs,
	// so anything admitted below is admitted by the working-epoch exemption and
	// not by spare ceiling.
	drained := 0
	for n := 0; n < 4*DefaultMaxUnheldKeyEpochsPerNode; n++ {
		identity := fmt.Sprintf("ceiling-drainer-%d", n)
		epoch := own + 2 + uint64(n)
		if v := h.e.OnBlockFrom(conn, identity, h.bodyAtEpoch(t, epoch, uint64(n), u256.Max)); v.Cost == CostBudgeted {
			drained++
		}
	}
	if drained == 0 {
		t.Fatal("setup: the ceiling never refused anything, so the bodies below " +
			"could be admitted by spare ceiling rather than by the working-epoch " +
			"exemption, and this test proves nothing")
	}
	// A fresh identity's own budget is also confirmed spent against the ceiling:
	// a foreign-epoch body from it is refused, so an admission below is the
	// exemption and not this identity's own credit.
	const honest = "honest-near-tip-identity"
	if v := h.e.OnBlockFrom(conn, honest, h.bodyAtEpoch(t, own+900000, 900000, u256.Max)); v.Cost != CostBudgeted {
		t.Fatalf("setup: a foreign-epoch body from the honest identity was priced "+
			"%v, want CostBudgeted — the ceiling is not drained and the exemption "+
			"below is not what admits the working-epoch bodies", v.Cost)
	}

	// tipEpoch+1: an honest peer announces into it at a boundary. Its cache is not
	// held, so a body there legitimately builds one — and it must be allowed to.
	nextKey := h.keyForEpoch(own + 1)
	if h.work.sawKey(nextKey) {
		t.Fatal("setup: the tipEpoch+1 cache was already built, so the positive " +
			"assertion below cannot tell an un-gated body from a gated one")
	}
	v := h.e.OnBlockFrom(conn, honest, h.bodyAtEpoch(t, own+1, 111, u256.Max))
	if v.Cost == CostBudgeted || errors.Is(v.Err, ErrKeyEpochBudget) {
		t.Fatalf("an honest body in this node's tipEpoch+1 was refused by the "+
			"key-epoch gate (cost=%v err=%v) after the ceiling was drained by an "+
			"attacker: the gate charges the working epochs a node at the tip "+
			"receives routinely, which trades the CPU DoS for the liveness "+
			"failure that reverted the tip-window guard", v.Cost, v.Err)
	}
	if !h.work.sawKey(nextKey) {
		t.Fatal("the tipEpoch+1 body's cache was never built: it was refused " +
			"before work.Check without carrying the budget error, so it was gated " +
			"by some other means and the exemption is not reaching it")
	}

	// tipEpoch: the cache this node already holds. It must be un-gated too — the
	// exemption is the pair, not just the boundary.
	vt := h.e.OnBlockFrom(conn, honest, h.bodyAtEpoch(t, own, 222, u256.Max))
	if vt.Cost == CostBudgeted || errors.Is(vt.Err, ErrKeyEpochBudget) {
		t.Fatalf("an honest body in this node's own tip key epoch was refused by "+
			"the key-epoch gate (cost=%v err=%v): the exemption does not cover the "+
			"epoch the node verified its own tip under", vt.Cost, vt.Err)
	}
}
