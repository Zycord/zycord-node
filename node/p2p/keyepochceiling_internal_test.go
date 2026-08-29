package p2p

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"time"
)

// The node-wide key-epoch ceiling has three terms and this file gives each of
// them an input that separates it: the SIZE of the bucket, the RATE it refills
// at, and WHOSE configuration decides both.
//
// keyepochaggregate_internal_test.go measures the size against a frozen clock,
// which is what made the other two invisible. A ceiling of the right size that
// refills at the wrong rate passes every row there — the clock never moves —
// and a ceiling sized on package defaults passes every row there too, because
// the harness runs at the defaults. Both were shipped, both are measured below.

// drainNodeWide spends the node-wide ceiling with a FRESH payer per
// announcement and reports how many were admitted before the refusal.
//
// A fresh payer every time on purpose: the per-identity layer then refuses
// nothing at all, so every refusal below belongs to the node-wide ceiling and
// no count in this file is a sum of two layers. The refusal is required rather
// than awaited, for the reason aggregateHarness.drain gives.
func (a *aggregateHarness) drainNodeWide(t *testing.T, tag string, limit int) int {
	t.Helper()
	admitted := 0
	for {
		a.epoch++
		a.nonce++
		payer := fmt.Sprintf("%s-identity-%d", tag, a.nonce)
		v := a.announceAtEpochFrom(t, "10.96.0.1:5000", payer, a.epoch, a.nonce)
		if v.Cost == CostBudgeted {
			return admitted
		}
		admitted++
		if admitted > limit {
			t.Fatalf("%s: %d announcements from fresh identities were admitted "+
				"against a limit of %d; the node-wide ceiling is not being "+
				"charged at all and every count here is measuring something else",
				tag, admitted, limit)
		}
	}
}

// step advances the harness clock by n whole key-epoch periods.
func (a *aggregateHarness) step(periods uint64) {
	a.now = a.now.Add(time.Duration(keyEpochPeriod(a.c.Params())*periods) * time.Second)
	a.e.Now = func() time.Time { return a.now }
}

// TestTheNodeWideKeyEpochCeilingRefillsAtTheConnectionSetPerPeriod is the rate
// term, and it is the one term the ceiling shipped without.
//
// The ceiling is the connection set multiplied by MaxUnheldKeyEpochsPerPeer,
// and it refilled at ONE credit per period — the rate of the layer below it,
// applied to a bucket that many times larger. Measured on that code: one
// admission after each of three successive periods, and the full 240 only after
// 240 of them. That is 1024 h on the public testnet's 512 x 30 s schedule and
// about 170 days on mainnet's 2048 x 30 s, so the ceiling was not a bound that
// recovers, it was a latch that opens once.
//
// The rate is derived rather than chosen, and the derivation is one line: a
// bucket's recovery time is its size divided by its rate, the per-payer bucket
// is MaxUnheldKeyEpochsPerPeer credits refilling at one per period, and this
// bucket is that same budget multiplied by the connection set. Refilling it at
// the connection set per period gives it the SAME recovery time as any one
// payer's, which is what "consistent with the layer below" means when it is
// said about time rather than about size.
//
// Four inputs, because the arithmetic has four cases that can each be wrong on
// their own: nothing before a period elapses, exactly the connection set at it,
// the whole ceiling after MaxUnheldKeyEpochsPerPeer of them and not before, and
// no more than the ceiling however long the node idles.
func TestTheNodeWideKeyEpochCeilingRefillsAtTheConnectionSetPerPeriod(t *testing.T) {
	a := newAggregateHarness(t)
	period := keyEpochPeriod(a.c.Params())
	ceiling, perPeriod := unheldKeyEpochCeiling(0)

	if int(ceiling) != DefaultMaxUnheldKeyEpochsPerNode {
		t.Fatalf("setup: the default ceiling is %d and the constant says %d; the "+
			"two must be the same function of the same defaults",
			ceiling, DefaultMaxUnheldKeyEpochsPerNode)
	}
	// The derivation itself, asserted rather than restated: the ratio between
	// the ceiling and its refill IS the per-payer budget, so a drained ceiling
	// and a drained payer come back in the same number of periods.
	if ceiling != perPeriod*MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("the ceiling is %d and the refill %d per period, so it recovers "+
			"in %d periods against one payer's %d. The two layers no longer "+
			"agree about time, which is the defect this test exists for",
			ceiling, perPeriod, ceiling/perPeriod, MaxUnheldKeyEpochsPerPeer)
	}

	if drained := a.drainNodeWide(t, "drain", 4*int(ceiling)); drained != int(ceiling) {
		t.Fatalf("setup: %d admitted before the node-wide refusal, want the "+
			"ceiling of %d", drained, ceiling)
	}

	// One second short of a period: still nothing. This separates a refill that
	// measures the period from one that grants credits on any elapsed time.
	a.now = a.now.Add(time.Duration(period-1) * time.Second)
	a.e.Now = func() time.Time { return a.now }
	if got := a.drainNodeWide(t, "short", int(ceiling)); got != 0 {
		t.Fatalf("%d credits arrived %d s into a %d s period; the node-wide "+
			"refill is not measuring the schedule and an attacker can spend "+
			"faster than the chain earns", got, period-1, period)
	}

	// And at the period: exactly the connection set, no more and no less. This
	// is the row that fails at one credit per period — the shipped behaviour —
	// and it is the whole finding.
	a.now = a.now.Add(time.Second)
	a.e.Now = func() time.Time { return a.now }
	if got := a.drainNodeWide(t, "one-period", int(ceiling)); got != int(perPeriod) {
		t.Fatalf("one period returned %d node-wide credits, want the connection "+
			"set of %d. At one credit per period a drained ceiling takes %d "+
			"periods to come back — measured at 1024 h on testnet parameters "+
			"and about 170 days on mainnet's — so the layer stops bounding and "+
			"starts denying", got, perPeriod, ceiling)
	}

	// The whole ceiling comes back in exactly MaxUnheldKeyEpochsPerPeer periods
	// and NOT in one fewer. Both rows, because a rate that is too fast passes
	// the row above only if it is also too fast here, and a bucket that refills
	// completely in a single period is not a bound at all.
	a.drainNodeWide(t, "resettle", int(ceiling))
	a.step(MaxUnheldKeyEpochsPerPeer - 1)
	if short := a.drainNodeWide(t, "one-short", int(ceiling)); short >= int(ceiling) {
		t.Fatalf("%d periods returned the whole ceiling of %d; the refill grants "+
			"more than the derivation says and the burst an attacker can bank "+
			"is larger than the connection set can honestly earn",
			MaxUnheldKeyEpochsPerPeer-1, ceiling)
	}
	a.drainNodeWide(t, "resettle2", int(ceiling))
	a.step(MaxUnheldKeyEpochsPerPeer)
	if got := a.drainNodeWide(t, "full", 4*int(ceiling)); got != int(ceiling) {
		t.Fatalf("%d periods returned %d node-wide credits, want the whole "+
			"ceiling of %d: a drained ceiling must recover in the same number "+
			"of periods one drained payer does",
			MaxUnheldKeyEpochsPerPeer, got, ceiling)
	}

	// However long it idles, the burst never exceeds the ceiling.
	a.drainNodeWide(t, "resettle3", int(ceiling))
	a.step(1000)
	if got := a.drainNodeWide(t, "idle", 4*int(ceiling)); got != int(ceiling) {
		t.Fatalf("after idling 1000 periods the node admitted %d, want %d: "+
			"node-wide credits accumulate without a ceiling, so an attacker "+
			"banks them and spends the lot at once", got, ceiling)
	}
}

// TestTheNodeWideKeyEpochCeilingIsNotHeldAtZeroByOneAnnouncementPerPeriod is
// what the refill rate cost in practice, stated as the arrangement rather than
// as the arithmetic.
//
// At one credit per period, one identity spending one announcement per period
// consumed the entire refill, so a ceiling drained once stayed at zero for as
// long as that identity kept sending — measured: ten periods, ten admissions to
// the pinner, and an honest newcomer holding an untouched budget of its own
// refused at the end of them. That is the node-wide layer inverting its own
// purpose. It exists to bound an aggregate no per-identity budget can, and it
// was instead denying peers whose per-identity budgets were full.
//
// The pinner is a SINGLE identity on purpose, and that is what makes this a
// finding rather than a restatement of the shared-lever concession. One
// identity is bounded by MaxUnheldKeyEpochsPerPeer credits per
// MaxUnheldKeyEpochsPerPeer periods — an average of one credit per period,
// which is exactly the old node-wide refill. A ceiling that one bounded sender
// can hold empty is not shared, it is captured.
func TestTheNodeWideKeyEpochCeilingIsNotHeldAtZeroByOneAnnouncementPerPeriod(t *testing.T) {
	a := newAggregateHarness(t)
	ceiling, _ := unheldKeyEpochCeiling(0)
	a.drainNodeWide(t, "drain", 4*int(ceiling))

	const periods = 10
	pinned := 0
	for r := 0; r < periods; r++ {
		a.step(1)
		a.epoch++
		a.nonce++
		if v := a.announceAtEpochFrom(t, "10.97.0.1:5000", "pinner", a.epoch, a.nonce); v.Cost != CostBudgeted {
			pinned++
		}
	}
	// Anti-vacuity: the pinner must actually be spending, or the row below
	// passes because nothing happened rather than because the refill outran it.
	if pinned == 0 {
		t.Fatalf("the pinner was refused all %d of its announcements, so this "+
			"test is not measuring whether one identity can hold the ceiling "+
			"down — it is measuring the per-identity budget", periods)
	}

	a.epoch++
	a.nonce++
	v := a.announceAtEpochFrom(t, "10.98.0.7:5000", "honest-newcomer", a.epoch, a.nonce)
	if v.Cost == CostBudgeted {
		t.Fatalf("after %d periods in which one identity sent one announcement "+
			"each, an honest identity with an untouched budget was refused "+
			"node-wide (%v). One sender pins the ceiling at zero indefinitely, "+
			"so the node-wide layer has stopped protecting and started denying",
			periods, v.Cost)
	}
}

// TestTheNodeWideKeyEpochCeilingFollowsTheConfiguredConnectionSet is the
// operator's half, and the reason the ceiling moved off a package constant.
//
// The ceiling is the connection set multiplied by what one payer may spend, so
// a ceiling computed from DefaultMaxInbound on a node running MaxInbound 144 is
// not that product: it was 240 against a per-payer aggregate of 800, which
// means only 48 of that node's 160 connection slots could ever have an
// out-of-epoch announcement evaluated and the 49th onward was refused before
// its own budget was consulted at all. At 256/16 it was 48 of 288. A bootstrap
// node is exactly the machine that raises MaxInbound and exactly the machine
// whose refusals cost the network most, so "the tightening direction" was not
// the safe half of the trade — it made the shared ceiling, rather than the
// per-payer budget, the binding constraint on every peer above the 48th.
//
// Driven through Node.register rather than by setting the Engine's field,
// because the WIRING is the property: register reads MaxInbound and MaxOutbound
// to decide admission and publishes those same two numbers to the Engine, so
// the ceiling cannot be sized against a set the gate does not enforce. A mutant
// that deletes the publication from register leaves the defaults in place and
// fails every row but the first.
func TestTheNodeWideKeyEpochCeilingFollowsTheConfiguredConnectionSet(t *testing.T) {
	for _, tc := range []struct{ maxIn, maxOut int }{
		{DefaultMaxInbound, DefaultMaxOutbound},
		{144, 8},
		{256, 16},
	} {
		t.Run(fmt.Sprintf("MaxInbound %d MaxOutbound %d", tc.maxIn, tc.maxOut), func(t *testing.T) {
			a := newAggregateHarness(t)
			id, err := NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			n := NewNode(id, a.e, nil, 1)
			n.MaxInbound, n.MaxOutbound = tc.maxIn, tc.maxOut
			// One admission through the real gate is what publishes the set.
			if !n.register(&Conn{Addr: "10.99.0.1:5000"}, false) {
				t.Fatal("setup: the first registration was refused")
			}

			set := tc.maxIn + 2*tc.maxOut
			want := set * MaxUnheldKeyEpochsPerPeer
			got := a.drainNodeWide(t, "configured", 4*want)
			t.Logf("MaxInbound %d, MaxOutbound %d: connection set %d, node-wide "+
				"ceiling %d, per-payer aggregate %d, identities evaluated %d",
				tc.maxIn, tc.maxOut, set, got, want, got/MaxUnheldKeyEpochsPerPeer)

			if got != want {
				t.Fatalf("a node configured at MaxInbound %d / MaxOutbound %d "+
					"admitted %d out-of-epoch announcements node-wide, want the "+
					"connection set of %d times the per-payer budget of %d = %d. "+
					"The ceiling is not reading the operator's own configuration, "+
					"so only %d of %d connection slots are ever evaluated",
					tc.maxIn, tc.maxOut, got, set, MaxUnheldKeyEpochsPerPeer, want,
					got/MaxUnheldKeyEpochsPerPeer, set)
			}
			// And the refill scales with it, or a larger node recovers slower
			// from a larger bucket than a smaller node does from a smaller one.
			if _, perPeriod := unheldKeyEpochCeiling(set); int(perPeriod) != set {
				t.Fatalf("the refill for a connection set of %d is %d per "+
					"period, want %d: the recovery time must not grow with the "+
					"operator's configuration", set, perPeriod, set)
			}
		})
	}
}

// TestTheNodeWideKeyEpochCeilingOwnsItsOwnRange gives unheldKeyEpochCeiling's
// two guards an input each.
//
// Neither is a rounding choice. A set at or below zero means nothing has
// published yet — a Node built as a struct literal, or an operator who has
// zeroed both fields — and it takes the defaults rather than a ceiling of zero,
// which is the direction SpendUnheldKeyEpoch's own zero arm takes and for the
// same reason: a node that refuses all out-of-epoch gossip is a worse failure
// than an unpayable announcement. The upper clamp is what lets the product be a
// uint32 on a 32-bit int as well as on a 64-bit one.
func TestTheNodeWideKeyEpochCeilingOwnsItsOwnRange(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  int
		want uint32
	}{
		{"nothing published takes the defaults", 0, DefaultMaxUnheldKeyEpochsPerNode},
		{"a negative set takes the defaults", -1, DefaultMaxUnheldKeyEpochsPerNode},
		{"one connection is one payer's budget", 1, MaxUnheldKeyEpochsPerPeer},
		{"the clamp bounds the product", maxUnheldConnectionSet + 1, maxUnheldConnectionSet * MaxUnheldKeyEpochsPerPeer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ceiling, perPeriod := unheldKeyEpochCeiling(tc.set)
			if ceiling != tc.want {
				t.Fatalf("unheldKeyEpochCeiling(%d) = %d, want %d", tc.set, ceiling, tc.want)
			}
			if ceiling != perPeriod*MaxUnheldKeyEpochsPerPeer {
				t.Fatalf("unheldKeyEpochCeiling(%d) returned ceiling %d and rate "+
					"%d, which do not recover in MaxUnheldKeyEpochsPerPeer "+
					"periods; the pair must stay one number",
					tc.set, ceiling, perPeriod)
			}
		})
	}

	// SetConnectionSet is the seam an operator's numbers arrive through and it
	// stores the sum raw, so the two arms above are what has to survive an
	// operator large enough to overflow the addition — whichever way it wraps.
	// The property is that the ceiling stays bounded, not which arm caught it:
	// asserting one of them would be asserting the sign of an overflow.
	e := &Engine{}
	e.SetConnectionSet(math.MaxInt, math.MaxInt)
	ceiling, perPeriod := unheldKeyEpochCeiling(e.connSet)
	if ceiling > maxUnheldConnectionSet*MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("a connection set configured at the int maximum produced a "+
			"ceiling of %d, above the clamp of %d: the product is not bounded "+
			"by this package's own arithmetic",
			ceiling, uint32(maxUnheldConnectionSet)*MaxUnheldKeyEpochsPerPeer)
	}
	if ceiling != perPeriod*MaxUnheldKeyEpochsPerPeer || ceiling == 0 {
		t.Fatalf("a connection set configured at the int maximum produced "+
			"ceiling %d and rate %d: the pair must stay one number and the "+
			"ceiling must not collapse to zero", ceiling, perPeriod)
	}
}

// TestTheUnheldEpochRefillAdvancesItsClockByPeriodsAndNotByCredits is the one
// term the rate parameter added to refilledUnheldEpochs, and it is invisible at
// the per-payer layer.
//
// The partial-refill arm banks the remainder by advancing the settle time by
// what was earned. At one credit per period "what was earned" and "what
// elapsed" are the same number of periods and no input can tell the two
// spellings apart. Above it they diverge: advancing by the CREDITS would move
// the settle time perPeriod times further than the clock actually ran, past
// `now`, and every later call would then take the backwards-clock arm and
// refill nothing at all — the same latch this rate was introduced to remove,
// reintroduced one line lower.
func TestTheUnheldEpochRefillAdvancesItsClockByPeriodsAndNotByCredits(t *testing.T) {
	const (
		period    = 100
		perPeriod = 10
		at        = 1000
	)
	// Spent 95, one period elapsed: 10 credits earned, 85 left, and the clock
	// settles at 1100 — one period on, not ten.
	spent, settled := refilledUnheldEpochs(95, at, period, at+period, perPeriod)
	if spent != 85 {
		t.Fatalf("one period at %d credits left %d spent, want 85", perPeriod, spent)
	}
	if settled != at+period {
		t.Fatalf("the settle time advanced to %d after one %d s period, want %d. "+
			"Advancing by the credits rather than by the periods puts the clock "+
			"ahead of now, and every later refill takes the backwards-clock arm "+
			"and grants nothing", settled, period, at+period)
	}
	// The consequence, driven rather than asserted about: a second period must
	// earn another perPeriod credits from the settled state above.
	spent, settled = refilledUnheldEpochs(spent, settled, period, at+2*period, perPeriod)
	if spent != 75 {
		t.Fatalf("a second period left %d spent, want 75: the refill stalled "+
			"after the first, which is the latch this rate removes", spent)
	}
	if settled != at+2*period {
		t.Fatalf("the settle time is %d after two periods, want %d", settled, at+2*period)
	}

	// A rate of zero is the latch itself and is clamped to one rather than
	// trusted from the caller. Neither production caller can pass it; the
	// arithmetic owns the property anyway, on the principle the period saturation
	// follows.
	if spent, _ := refilledUnheldEpochs(5, at, period, at+period, 0); spent != 4 {
		t.Fatalf("a refill rate of zero left %d of 5 credits spent after a full "+
			"period, want 4. A zero rate never returns a credit while the settle "+
			"clock keeps advancing, so the bucket empties permanently", spent)
	}

	// And the per-payer layer's own rate is unchanged by the parameter: one
	// credit per period, so its bucket still recovers in
	// MaxUnheldKeyEpochsPerPeer periods.
	if spent, _ := refilledUnheldEpochs(MaxUnheldKeyEpochsPerPeer, at, period, at+period, 1); spent != MaxUnheldKeyEpochsPerPeer-1 {
		t.Fatalf("one period at the per-payer rate left %d of %d credits spent, "+
			"want %d", spent, MaxUnheldKeyEpochsPerPeer, MaxUnheldKeyEpochsPerPeer-1)
	}
}

// TestAnAnnounceRefusalByTheSharedKeyEpochCeilingIsNeverScored is the announce
// path's `own` disjunct, and it is the twin of
// TestARefusalByTheSharedCeilingIsNeverScored one primitive over.
//
// The announce path had both layers — the per-identity budget and the
// node-wide ceiling — and the score conjunct, and it was missing the
// disjunct that keeps them apart. `spendKeyEpoch` returned the identical
// `epoch, false` whichever layer refused, so a caught identity whose OWN budget
// was untouched was charged `ScoreInvalidMessage` for a refusal the SHARED
// ceiling caused, and the ceiling is drainable by identities that peer never
// heard of: 48 of them x MaxUnheldKeyEpochsPerPeer announcements, at no proof
// of work at all, since this refusal stands ahead of `work.Check`.
//
// Three rows, because no two of them separate the rule on their own:
//
//   - the ceiling refusal must be `CostBudgeted` and unscored,
//   - the OWN-budget refusal from the same caught identity must still be
//     scored, or the fix is an amnesty and the work-check flood terminates
//     nowhere again,
//   - and the two must not report the same reason, because the message the
//     ceiling refusal used to carry said the identity had spent a budget it
//     had not touched.
//
// **It also pins the ORDER the two layers are read in, and that reach was
// found rather than designed — it is recorded here because a mutant declared
// to survive did not.** Swapping the two arms of `spendKeyEpoch` fails this
// test at 26 of 30 refusals scored and −520 accumulated, because
// `SpendUnheldKeyEpoch` *mutates*: read second, it is never reached by a
// ceiling refusal, and read first it spends a credit for one, so the victim's
// own budget is exhausted by the fourth announcement and every later refusal
// comes back attributable. `spendKeyEpoch`'s own comment claims exactly half
// of that — "an announcement refused by the payer's own budget does not
// consume a node-wide credit it never spent" — and the converse half, that a
// ceiling refusal consumes no per-payer credit, was prose with no instrument
// until this row. The `own` bit is what makes the ordering observable from
// outside the engine at all: before it, both orders returned the same value.
func TestAnAnnounceRefusalByTheSharedKeyEpochCeilingIsNeverScored(t *testing.T) {
	const victimAddr = "10.96.0.9:5000"
	const victim = "caught-identity-with-an-intact-budget"

	// Row 1: the shared ceiling refuses.
	a := newAggregateHarness(t)
	ceiling, _ := unheldKeyEpochCeiling(a.e.connSet)
	a.e.Peers.MarkWorkRefusedKey(victim, a.e.now())

	// Anti-vacuity, and it is a separating input rather than a setup check:
	// with the ceiling intact, this same identity carrying this same bit is
	// ADMITTED. Without this row every refusal below could be the per-identity
	// layer wearing the ceiling's name, and the test would pass against a
	// program that refused this identity for the wrong reason.
	a.epoch++
	a.nonce++
	if v := a.announceAtEpochFrom(t, victimAddr, victim, a.epoch, a.nonce); v.Cost == CostBudgeted {
		t.Fatalf("the victim was already over its own budget before the ceiling "+
			"was drained (%v); every refusal below would then belong to the "+
			"per-identity layer and this test would measure nothing", v.Err)
	}

	// Somebody else drains the whole shared ceiling. Fresh identity per
	// announcement, so nothing here touches the victim's own budget.
	drained := a.drainNodeWide(t, "flood", int(ceiling)+8)

	refusals, scored, budgeted, score := 0, 0, 0, 0
	var ceilingErr error
	for n := 0; n < 30; n++ {
		a.epoch++
		a.nonce++
		v := a.announceAtEpochFrom(t, victimAddr, victim, a.epoch, a.nonce)
		if v.Forward {
			t.Fatalf("the ceiling was drained by %d announcements and announcement "+
				"%d was still admitted; this test measures nothing", drained, n)
		}
		refusals++
		if v.Cost == CostBudgeted {
			budgeted++
		}
		if v.Score != 0 {
			scored++
			score += v.Score
		}
		if ceilingErr == nil {
			ceilingErr = v.Err
		}
	}
	t.Logf("another %d identities drained the shared ceiling of %d; a caught "+
		"identity that has spent none of its own budget was refused %d times, "+
		"%d of them CostBudgeted, %d scored, accumulated score %d against a ban "+
		"threshold of %d", drained, ceiling, refusals, budgeted, scored, score,
		ScoreBanThreshold)

	if scored != 0 {
		t.Errorf("%d of %d refusals by the SHARED ceiling were scored against an "+
			"identity that has spent none of its own budget, accumulating %d "+
			"against a ban threshold of %d. The ceiling is keyed on nothing a "+
			"sender presents, so a refusal there is not attributable and must "+
			"not be charged to whoever happens to announce next",
			scored, refusals, score, ScoreBanThreshold)
	}
	if budgeted != refusals {
		t.Errorf("%d of %d ceiling refusals were CostBudgeted; the ceiling is a "+
			"bounded resource and wire.md §10.2 requires the class to name it",
			budgeted, refusals)
	}
	if !errors.Is(ceilingErr, ErrKeyEpochBudget) {
		t.Errorf("a ceiling refusal reported %v, want ErrKeyEpochBudget", ceilingErr)
	}

	// Rows 2 and 3: the same caught identity, on a node whose ceiling is
	// intact, spending its OWN budget. This half must still be scored, or the
	// disjunct above has become an amnesty.
	b := newAggregateHarness(t)
	b.e.Peers.MarkWorkRefusedKey(victim, b.e.now())
	var ownErr error
	ownScored, ownRefusals := 0, 0
	for n := 0; n < MaxUnheldKeyEpochsPerPeer+4; n++ {
		b.epoch++
		b.nonce++
		v := b.announceAtEpochFrom(t, victimAddr, victim, b.epoch, b.nonce)
		if v.Forward {
			continue // inside its own budget, and admitted
		}
		ownRefusals++
		if v.Score == ScoreInvalidMessage {
			ownScored++
			if ownErr == nil {
				ownErr = v.Err
			}
		}
	}
	t.Logf("with the ceiling intact, the same caught identity was refused %d "+
		"times past its OWN budget of %d, %d of them scored",
		ownRefusals, MaxUnheldKeyEpochsPerPeer, ownScored)

	if ownScored == 0 {
		t.Fatalf("%d refusals past the identity's OWN budget were all unscored. "+
			"The `own` disjunct must not become an unconditional amnesty: past "+
			"the budget an announcement never reaches work.Check, so an "+
			"unscored refusal is what let a flood of unmeetable-target headers "+
			"run forever", ownRefusals)
	}
	if ceilingErr != nil && ownErr != nil && ceilingErr.Error() == ownErr.Error() {
		t.Errorf("the shared ceiling and the payer's own budget report the "+
			"identical reason %q. That message says the identity has spent a "+
			"budget it has not touched, which is the half of the defect a reader "+
			"meets first", ceilingErr)
	}
}
