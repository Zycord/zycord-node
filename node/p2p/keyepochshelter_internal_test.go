package p2p

import (
	"errors"
	"testing"
)

// The node-wide key-epoch ceiling's amnesty has two conjuncts, and this file
// gives each of them an input that separates it.
//
//	scored  ⇔  refused  ∧  ownBudgetSpent(payer)  ∧  workRefused(payer)
//
// The middle term used to be `own` — whether the payer's OWN budget is
// what refused THIS message — and `own` is false for every payer at once while
// the shared ceiling is drained, because Engine.spendKeyEpoch reads the ceiling
// first and returns before the per-payer layer is reached. So the whole
// conjunction went inert under a drained ceiling, and the terminating class
// with it: an identity this node's own work check had already caught, holding a
// budget it had already burnt to the last credit, was answered CostBudgeted and
// unscored for as long as an attacker held the ceiling at zero.
//
// The replacement term is a question the ceiling refusal does not erase — is
// this payer's budget SPENT, rather than is it what refused this message — and
// it is read without charging anything, which is the half that keeps the
// ordering intact. TestAnAnnounceRefusalByTheSharedKeyEpochCeilingIsNeverScored
// is the other side of the same rule and stays green: a caught identity with an
// INTACT budget is still not scored for somebody else's flood, and row 3 below
// re-drives that under this file's own arrangement so the two conjuncts are
// separated in one place.

// drainOwnBudget spends one payer's whole per-identity unheld-key-epoch budget
// and returns how many announcements were admitted and the first refusal.
//
// The refusal is required rather than awaited, for the reason
// aggregateHarness.drain gives: a loop that ran out of patience rather than out
// of credits would leave the budget partly intact and every row below would be
// measuring the wrong conjunct.
//
// A key-epoch refusal is identified by its error and not by Cost or Forward,
// because this file needs the one signal that is the same on both arms of the
// split: the refusal is CostScored on the caught rows and CostBudgeted on the
// others, and an ADMITTED announcement here is not forwarded either — the
// announce path only relays a block whose body this node holds, and
// these headers name a parent it does not.
func (a *aggregateHarness) drainOwnBudget(t *testing.T, addr, payer string) (int, Verdict) {
	t.Helper()
	admitted := 0
	for n := 0; n < MaxUnheldKeyEpochsPerPeer+8; n++ {
		a.epoch++
		a.nonce++
		v := a.announceAtEpochFrom(t, addr, payer, a.epoch, a.nonce)
		if !errors.Is(v.Err, ErrKeyEpochBudget) {
			admitted++
			continue
		}
		return admitted, v
	}
	t.Fatalf("payer %q was admitted every one of %d announcements against a "+
		"budget of %d, so its own budget is not spent and every row in this "+
		"file is measuring something else",
		payer, MaxUnheldKeyEpochsPerPeer+8, MaxUnheldKeyEpochsPerPeer)
	return admitted, Verdict{}
}

// countRefusals sends n announcements from one payer against a drained ceiling
// and reports how many were refused, how many were scored, the accumulated
// score and the first error.
func (a *aggregateHarness) countRefusals(t *testing.T, addr, payer string, n int) (refusals, scored, budgeted, score int, first error) {
	t.Helper()
	for i := 0; i < n; i++ {
		a.epoch++
		a.nonce++
		v := a.announceAtEpochFrom(t, addr, payer, a.epoch, a.nonce)
		if !errors.Is(v.Err, ErrKeyEpochBudget) {
			t.Fatalf("announcement %d from %q was admitted (%v) while the node-wide "+
				"ceiling was supposed to be drained; this row measures nothing", i, payer, v.Err)
		}
		refusals++
		if v.Cost == CostBudgeted {
			budgeted++
		}
		if v.Score != 0 {
			scored++
			score += v.Score
		}
		if first == nil {
			first = v.Err
		}
	}
	return refusals, scored, budgeted, score, first
}

// TestADrainedKeyEpochCeilingStillScoresACaughtIdentityWhoseOwnBudgetIsSpent is
// the shelter, and it is the row the never-score-a-shared-ceiling-refusal fix
// took away without saying so.
//
// That fix conjoined the score with `own` so that a refusal by the SHARED ceiling —
// which anybody can drain, at no proof of work, for 55,680 bytes from 48 minted
// identities — is never charged to whoever announces next. That is right, and
// the price it charged was that `own` is false for EVERY payer while the
// ceiling is down, so the conjunction stopped firing for the guilty as well as
// for the victim. An invalid-header flood measured as self-limiting stops
// terminating for exactly as long as the ceiling is held at zero.
//
// Three rows, because no two of them separate the rule on their own:
//
//   - the caught identity whose own budget is ALREADY SPENT must be scored
//     through a drained ceiling — this is the finding, and it fails on the code
//     before the second conjunct at 0 of 30 scored;
//   - an identity whose budget is equally spent but which this node's work
//     check has NEVER refused must stay unscored, or the repair has become
//     the work-check amnesty running in reverse and every fast syncer is banned by
//     somebody else's flood;
//   - a CAUGHT identity whose own budget is INTACT must stay unscored, or the
//     new term is doing nothing and the rule has collapsed back to
//     `refused ∧ workRefused`, which is the guard that fix reverted.
//
// The first two rows separate the work-refused conjunct against a fixed budget
// state; the first and third separate the budget conjunct against a fixed
// work-refused state. The anti-vacuity checks are inside the setup rather than
// beside it: the caught payer's own budget must be drained by a refusal that is
// ALREADY scored with the ceiling intact (the work-refused conjunct live), and
// the ceiling drain must admit something before it refuses, or the two halves
// are indistinguishable.
func TestADrainedKeyEpochCeilingStillScoresACaughtIdentityWhoseOwnBudgetIsSpent(t *testing.T) {
	const (
		caughtAddr  = "10.97.0.1:5000"
		uncleanAddr = "10.97.0.2:5000"
		intactAddr  = "10.97.0.3:5000"

		caught   = "caught-identity-with-a-spent-budget"
		unclean  = "clean-identity-with-a-spent-budget"
		intactID = "caught-identity-with-an-intact-budget"
	)
	const rounds = 30

	a := newAggregateHarness(t)
	ceiling, _ := unheldKeyEpochCeiling(a.e.connSet)

	// Two identities this node's own work check has refused. Only the first will
	// be allowed to spend its own budget; the third keeps its budget intact so
	// that the two conjuncts are varied independently.
	a.e.Peers.MarkWorkRefusedKey(caught, a.e.now())
	a.e.Peers.MarkWorkRefusedKey(intactID, a.e.now())

	// Setup, and it is an anti-vacuity row: with the ceiling intact the caught
	// identity's own-budget refusal is ALREADY scored. That is the work-refused
	// conjunct, and if it were not firing here the rows below could not tell a
	// repair from a program that never scored this identity at all.
	caughtAdmitted, caughtOwn := a.drainOwnBudget(t, caughtAddr, caught)
	if caughtOwn.Score != ScoreInvalidMessage {
		t.Fatalf("with the ceiling intact, the caught identity's own-budget "+
			"refusal scored %d after %d admissions, want ScoreInvalidMessage (%d); "+
			"the work-refused conjunct is not live and this test cannot measure the shelter",
			caughtOwn.Score, caughtAdmitted, ScoreInvalidMessage)
	}

	// The same drain for an identity carrying no work-refused bit. Its refusal is
	// CostBudgeted and unscored, which is the state row 2 will re-measure once
	// the ceiling is down.
	uncleanAdmitted, uncleanOwn := a.drainOwnBudget(t, uncleanAddr, unclean)
	if uncleanOwn.Score != 0 {
		t.Fatalf("with the ceiling intact, an identity the work check has never "+
			"refused was scored %d on its own-budget refusal after %d admissions; "+
			"the amnesty is already broken before the ceiling is involved",
			uncleanOwn.Score, uncleanAdmitted)
	}

	// Somebody else drains the whole shared ceiling with a fresh identity per
	// announcement, so nothing here touches any of the three budgets above.
	drained := a.drainNodeWide(t, "flood", int(ceiling)+8)
	if drained == 0 {
		t.Fatalf("the ceiling of %d refused the very first fresh identity, so the "+
			"drain admitted nothing and every row below could be the per-identity "+
			"layer wearing the ceiling's name", ceiling)
	}

	// Row 1 — the finding.
	refusals, scored, budgeted, score, err := a.countRefusals(t, caughtAddr, caught, rounds)
	t.Logf("another %d identities drained the shared ceiling of %d; a caught "+
		"identity that had already spent all %d of its own credits was refused "+
		"%d times, %d scored, %d CostBudgeted, accumulated %d against a ban "+
		"threshold of %d", drained, ceiling, caughtAdmitted, refusals, scored,
		budgeted, score, ScoreBanThreshold)
	if scored != refusals {
		t.Errorf("%d of %d refusals of a caught identity whose OWN budget was "+
			"already spent went unscored while the shared ceiling was drained, "+
			"accumulating %d against a ban threshold of %d. The ceiling refusal "+
			"makes `own` false for everybody at once, but this identity's own "+
			"budget is spent and this node's own work check has already refused "+
			"it, so it is attributable on evidence the ceiling does not erase "+
			"on its own", refusals-scored, refusals, score, ScoreBanThreshold)
	}
	if score > ScoreBanThreshold {
		t.Errorf("a caught identity with a spent budget accumulated %d over %d "+
			"refusals against a ban threshold of %d, so the flood measured "+
			"as self-limiting still does not terminate through a drained ceiling",
			score, refusals, ScoreBanThreshold)
	}
	if !errors.Is(err, ErrKeyEpochBudget) {
		t.Errorf("the scored ceiling refusal reported %v, want ErrKeyEpochBudget", err)
	}

	// Row 2 — the work-refused conjunct. Same spent budget, no work-refused bit.
	refusals, scored, budgeted, score, err = a.countRefusals(t, uncleanAddr, unclean, rounds)
	t.Logf("an identity with an equally spent budget that the work check has "+
		"NEVER refused was refused %d times, %d scored, %d CostBudgeted, "+
		"accumulated %d", refusals, scored, budgeted, score)
	if scored != 0 {
		t.Errorf("%d of %d refusals were scored against an identity this node's "+
			"work check has never refused, accumulating %d against a ban "+
			"threshold of %d. A spent budget alone is not misbehaviour — it is "+
			"the sustained rate an honest peer that is behind reaches by "+
			"catching up — and scoring it is the guard I7-H4 reverted",
			scored, refusals, score, ScoreBanThreshold)
	}
	if budgeted != refusals {
		t.Errorf("%d of %d unscored ceiling refusals were not CostBudgeted; the "+
			"ceiling is a bounded resource and wire.md §10.2 requires the class "+
			"to name it", refusals-budgeted, refusals)
	}
	if !errors.Is(err, ErrKeyEpochBudget) {
		t.Errorf("an unscored ceiling refusal reported %v, want ErrKeyEpochBudget", err)
	}

	// Row 3 — the budget conjunct. Caught, but holding every credit it was
	// issued, because the ceiling refused it before the per-payer layer was ever
	// reached. That is the whole point of never scoring a shared-ceiling refusal,
	// and it must survive the shelter's repair.
	refusals, scored, budgeted, score, err = a.countRefusals(t, intactAddr, intactID, rounds)
	t.Logf("a caught identity that has spent NONE of its own budget was refused "+
		"%d times, %d scored, %d CostBudgeted, accumulated %d", refusals, scored,
		budgeted, score)
	if scored != 0 {
		t.Errorf("%d of %d refusals were scored against a caught identity that "+
			"has spent none of its own budget, accumulating %d against a ban "+
			"threshold of %d. The shared ceiling is keyed on nothing a sender "+
			"presents, so this peer may have sent none of the traffic that "+
			"drained it, and the new term must be a budget read and not a "+
			"restatement of the work-refused bit",
			scored, refusals, score, ScoreBanThreshold)
	}
	if budgeted != refusals {
		t.Errorf("%d of %d unscored ceiling refusals were not CostBudgeted", refusals-budgeted, refusals)
	}
	if !errors.Is(err, ErrKeyEpochBudget) {
		t.Errorf("an unscored ceiling refusal reported %v, want ErrKeyEpochBudget", err)
	}
}

// TestUnheldKeyEpochsExhaustedChargesNothing is the other half of the
// shelter's primitive, and it is the half a call-site test cannot see.
//
// The whole reason the repair is a new peer-store read rather than a second
// SpendUnheldKeyEpoch call is that the spender MUTATES: called on the ceiling
// arm it would charge a per-payer credit for a refusal the shared ceiling
// caused, which is the mutant that was killed at 26 of 30 refusals scored. A read
// that quietly charged would reintroduce exactly that, and would do it
// invisibly — the call site would still look correct, and the damage would show
// up several announcements later as a budget that drained itself.
//
// So this drives the read directly and asserts the two facts a call-site test
// cannot separate: the answer tracks the spender, and asking never changes it.
func TestUnheldKeyEpochsExhaustedChargesNothing(t *testing.T) {
	const key = "identity-being-read-rather-than-charged"
	const period, now = uint64(600), uint64(1 << 20)

	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	// An identity the store has never seen has spent nothing, and asking must not
	// plant an entry for it — a read that created entries would be an unbounded
	// map keyed on a value a sender mints for free.
	if ps.UnheldKeyEpochsExhausted(key, MaxUnheldKeyEpochsPerPeer, period, now) {
		t.Fatalf("an identity absent from the store read as exhausted")
	}
	for i := 0; i < 64; i++ {
		ps.UnheldKeyEpochsExhausted(key, MaxUnheldKeyEpochsPerPeer, period, now)
	}
	if !ps.SpendUnheldKeyEpoch(key, MaxUnheldKeyEpochsPerPeer, period, now) {
		t.Fatalf("64 reads spent the whole budget of %d: the read charges, which "+
			"is the mutation the ceiling arm must not make",
			MaxUnheldKeyEpochsPerPeer)
	}

	// Spend the rest of the budget, asking before and after every charge. The
	// read must flip exactly once, on the charge that fills the bucket, and the
	// interleaved reads must not bring that moment forward.
	flipped := -1
	for n := 1; n <= MaxUnheldKeyEpochsPerPeer; n++ {
		exhausted := ps.UnheldKeyEpochsExhausted(key, MaxUnheldKeyEpochsPerPeer, period, now)
		if exhausted && flipped < 0 {
			flipped = n
		}
		ok := ps.SpendUnheldKeyEpoch(key, MaxUnheldKeyEpochsPerPeer, period, now)
		if exhausted == ok {
			t.Fatalf("after %d credits the read said exhausted=%v and the spender "+
				"said admitted=%v; the two disagree, so the ceiling arm is reading "+
				"a different budget from the one the announce path charges",
				n, exhausted, ok)
		}
	}
	if flipped != MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("the read first said exhausted before the %d-th credit (at %d); "+
			"reads charge, or the refill arithmetic differs from the spender's",
			MaxUnheldKeyEpochsPerPeer, flipped)
	}
	if !ps.UnheldKeyEpochsExhausted(key, MaxUnheldKeyEpochsPerPeer, period, now) {
		t.Fatalf("a budget spent to the last credit did not read as exhausted")
	}

	// And it recovers on the spender's own clock rather than on a second copy of
	// the arithmetic: one credit per period, so the bucket is no longer full one
	// period on.
	if ps.UnheldKeyEpochsExhausted(key, MaxUnheldKeyEpochsPerPeer, period, now+period) {
		t.Errorf("one whole period after the drain the budget still read as " +
			"exhausted; the read does not share refilledUnheldEpochs with the " +
			"spender, so a payer would stay scoreable through a refill it has earned")
	}

	// A zero budget or a zero period is not exhausted, which is the read-side
	// complement of SpendUnheldKeyEpoch admitting on the same inputs: a
	// misconfigured store must not manufacture attributable refusals.
	if ps.UnheldKeyEpochsExhausted(key, 0, period, now) ||
		ps.UnheldKeyEpochsExhausted(key, MaxUnheldKeyEpochsPerPeer, 0, now) ||
		ps.UnheldKeyEpochsExhausted("", MaxUnheldKeyEpochsPerPeer, period, now) {
		t.Errorf("a zero budget, a zero period or an empty key read as exhausted; " +
			"the spender admits on all three and the read must not contradict it")
	}
}
