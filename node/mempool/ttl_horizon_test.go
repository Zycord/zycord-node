package mempool_test

import (
	"errors"
	"math"
	"testing"

	"zycord/core/state"
	"zycord/core/types"
	"zycord/node/mempool"
	"zycord/spec"
)

// The TTL horizon is a DISTANCE from the tip, at both the sites that screen it.
//
// core/fold/blockrules.go (B2) and sim/refold/refold.go both write this bound
// as `c.TTL - h.Height > p.TTLMax` and say in as many words that a wrapped
// ceiling is not a ceiling. The mempool wrote it as the sum `next +
// params.TTLMax` in two places, while its comment claimed to mirror B1 and B2.
// params.Validate bounds ttl_max from BELOW only (`ttl_max >= 2`) and it was
// ruled deliberately that it stays that way, so ttl_max = MaxUint64 is a value
// the parameter loader accepts and the sum wraps to next-1 at it.
//
// Two sites, two opposite failures, and each needs its own separating input in
// each direction — the horizon must not collapse at a large ttl_max, and it
// must still BE a horizon at the shipped one.

// horizonWorld is newWorld with ttl_max chosen. The pool captures *params.Params
// at construction, so the value has to be set before mempool.New. spec.Devnet()
// parses a fresh copy per call, so mutating it here cannot leak into any other
// test.
func horizonWorld(t testing.TB, ttlMax uint64, policy mempool.Policy) *world {
	t.Helper()
	p := spec.Devnet()
	p.TTLMax = ttlMax
	return &world{t: t, p: p, state: state.New(), pool: mempool.New(p, policy), policy: policy}
}

// devnetTTLMax is the shipped horizon, read from the parameter set rather than
// restated, so this file cannot drift from spec/params.devnet.json.
func devnetTTLMax(t testing.TB) uint64 {
	t.Helper()
	return spec.Devnet().TTLMax
}

// TestAdmissionHorizonSurvivesTheWidestExpressibleTTLMax is site one: Add.
//
// At ttl_max = MaxUint64 every certificate B1 admits is inside the horizon by
// construction, because the widest possible distance is exactly what the
// parameter says. In the sum form next+ttl_max wrapped to next-1, so every
// such certificate compared above it and Add refused the entire stream with
// ErrTTLTooFar — a silent liveness stop indistinguishable, in the logs, from
// nobody sending anything.
func TestAdmissionHorizonSurvivesTheWidestExpressibleTTLMax(t *testing.T) {
	w := horizonWorld(t, math.MaxUint64, smallPolicy())

	const tip = 100
	// Comfortably inside MinTTLLead and far beyond the devnet horizon, so the
	// only thing that can admit it is ttl_max actually being MaxUint64.
	c := w.certWithBounds(key(t, 1), 0, 1_000_000, 10, tip+1+devnetTTLMax(t)+1_000)

	if err := w.pool.Add(c, w.state, tip); err != nil {
		t.Fatalf("at ttl_max=MaxUint64 a certificate B1 and B2 both admit must be pooled, got %v", err)
	}
	if !w.pool.Has(c.ID()) {
		t.Fatal("Add reported success but the certificate is not pooled")
	}
}

// TestAdmissionHorizonStillRefusesBeyondTheShippedTTLMax is the anti-vacuity
// half of the site-one property: the distance form must still be a ceiling.
// Deleting the check outright, or inverting its direction, passes the test
// above and fails this one.
func TestAdmissionHorizonStillRefusesBeyondTheShippedTTLMax(t *testing.T) {
	ttlMax := devnetTTLMax(t)
	w := horizonWorld(t, ttlMax, smallPolicy())

	const tip = 100
	signer := key(t, 2)

	// The last TTL inside the horizon: distance from `next` is exactly ttl_max.
	inside := w.certWithBounds(signer, 0, 1_000_000, 10, tip+1+ttlMax)
	if err := w.pool.Add(inside, w.state, tip); err != nil {
		t.Fatalf("a TTL exactly at the horizon must be admitted, got %v", err)
	}

	// One block further out. Off-by-one separated, so a `>=` for a `>` is caught.
	outside := w.certWithBounds(key(t, 3), 0, 1_000_000, 10, tip+1+ttlMax+1)
	if err := w.pool.Add(outside, w.state, tip); !errors.Is(err, mempool.ErrTTLTooFar) {
		t.Fatalf("a TTL one block beyond the horizon must be refused with ErrTTLTooFar, got %v", err)
	}
}

// TestRescreenAtTheWidestTTLMaxDoomsNothingForBeingTooFar is site two:
// rescreenLocked, reached through Rescreen when the tip moves.
//
// Fork choice compares accumulated work and nothing else, so a shorter heavier
// branch legitimately LOWERS the tip; the stranded-certificate fix gave this
// pass an upper-bound arm for that. In the sum form that arm marked EVERY
// pooled entry doomed at a large ttl_max, so a reorg emptied the pool and
// stranded everything in it — the failure that arm exists to prevent,
// reintroduced by its own arithmetic.
func TestRescreenAtTheWidestTTLMaxDoomsNothingForBeingTooFar(t *testing.T) {
	w := horizonWorld(t, math.MaxUint64, smallPolicy())

	const addTip = 100
	const lowerTip = 50 // a heavier, shorter branch

	c := w.certWithBounds(key(t, 4), 0, 1_000_000, 10, addTip+1+devnetTTLMax(t)+1_000)
	if err := w.pool.Add(c, w.state, addTip); err != nil {
		t.Fatalf("setup: %v", err)
	}

	w.pool.Rescreen(w.state, lowerTip)

	if !w.pool.Has(c.ID()) {
		t.Fatal("at ttl_max=MaxUint64 no pooled certificate is beyond the horizon, so a tip move must doom none")
	}
}

// TestRescreenStillDoomsBeyondTheShippedTTLMax is the anti-vacuity half of the
// site-two property, and it is the stranded certificate's own case: at the
// shipped horizon a certificate admitted against a high tip IS beyond the
// horizon once the tip drops, and must still be removed. Deleting the arm
// passes the test above and fails this one.
func TestRescreenStillDoomsBeyondTheShippedTTLMax(t *testing.T) {
	ttlMax := devnetTTLMax(t)
	w := horizonWorld(t, ttlMax, smallPolicy())

	const addTip = 100
	const drop = 10 // a heavier, shorter branch
	const lowerTip = addTip - drop

	// Inside the horizon at the old tip, and EXACTLY ONE BLOCK beyond it at the
	// new one — that case placed at the boundary rather than well past it.
	// Nothing about the certificate changed; the tip moved under it.
	//
	// The one-block offset is the point. With the doomed certificate sitting
	// comfortably beyond the horizon, this arm is separated only on its tight
	// side, and loosening it by one (`e.cert.TTL-next-1 > ttl_max`) survives the
	// whole file — the mirror image of the `>=` survivor this test was already
	// rewritten once to kill. Verified by mutation (D).
	c := w.certWithBounds(key(t, 5), 0, 1_000_000, 10, lowerTip+1+ttlMax+1)
	if err := w.pool.Add(c, w.state, addTip); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// A second certificate that is unexpired and inside the horizon at BOTH
	// tips, from a different underwriter, so "the pool emptied" cannot be
	// mistaken for "the doomed arm fired on the right entry". Placed EXACTLY
	// at the horizon of the lower tip rather than comfortably inside it: an
	// interior survivor leaves this arm's boundary unseparated, and a `>=` for
	// a `>` here survives the whole file. Verified by mutation.
	survivor := w.certWithBounds(key(t, 6), 0, 1_000_000, 10, lowerTip+1+ttlMax)
	if err := w.pool.Add(survivor, w.state, addTip); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// `c`'s own successor, same underwriter, one Seq above it, and itself well
	// inside the horizon at BOTH tips — so nothing about this certificate is
	// beyond any bound and the only thing that can remove it is `c` having been
	// reported to `strands`.
	//
	// This is the arm's real consequence and the reason removal alone is too
	// weak an assertion. `strands` records the vacated Seq, truncateStrandedLocked
	// cuts at the lowest vacancy no survivor re-occupies, and everything above
	// goes. Asserting only pool.Has(c) leaves that whole path unseparated: a
	// mutant that marked `c` doomed but skipped the strands(e) call passed the
	// entire file. Verified by mutation (M10).
	succ := w.certWithBounds(key(t, 5), 1, 1_000_000, 10, lowerTip+1+ttlMax)
	if err := w.pool.Add(succ, w.state, addTip); err != nil {
		t.Fatalf("setup: %v", err)
	}

	w.pool.Rescreen(w.state, lowerTip)

	if w.pool.Has(c.ID()) {
		t.Fatal("a certificate beyond the horizon at the new tip must be doomed by the rescreen")
	}
	if w.pool.Has(succ.ID()) {
		t.Fatal("dooming a certificate for being beyond the horizon must strand what sits above it: " +
			"the successor is unappliable once its predecessor's Seq is vacated, and leaving it " +
			"pooled hands the miner a certificate guaranteed to skip")
	}
	if !w.pool.Has(survivor.ID()) {
		t.Fatal("the truncation is per underwriter: an unrelated certificate inside the horizon must survive")
	}
}

// TestOnBlockAppliesTheSameTTLHorizonAsRescreen measures what the shared-arm
// argument only asserts. rescreenLocked has two callers -- Rescreen and OnBlock
// -- and the tests above drive only Rescreen, so the claim that OnBlock inherits
// the fix is an argument about a shared code path rather than a measurement.
// OnBlock is also the production path that runs on every committed block, and it
// had no test in this package at all.
//
// Both directions of the arm are separated here through OnBlock alone, so this
// stands even if the two callers ever stop sharing the arm.
func TestOnBlockAppliesTheSameTTLHorizonAsRescreen(t *testing.T) {
	t.Run("widest ttl_max dooms nothing", func(t *testing.T) {
		w := horizonWorld(t, math.MaxUint64, smallPolicy())

		const addTip = 100
		const lowerTip = 50

		c := w.certWithBounds(key(t, 10), 0, 1_000_000, 10, addTip+1+devnetTTLMax(t)+1_000)
		if err := w.pool.Add(c, w.state, addTip); err != nil {
			t.Fatalf("setup: %v", err)
		}

		w.pool.OnBlock(&types.Block{}, w.state, lowerTip)

		if !w.pool.Has(c.ID()) {
			t.Fatal("at ttl_max=MaxUint64 nothing is beyond the horizon, so OnBlock must doom none")
		}
	})

	t.Run("shipped ttl_max still dooms beyond it", func(t *testing.T) {
		ttlMax := devnetTTLMax(t)
		w := horizonWorld(t, ttlMax, smallPolicy())

		const addTip = 100
		const lowerTip = 90

		// One block beyond the new tip's horizon, so this arm is separated on
		// its loose side here too, not only on its tight side.
		c := w.certWithBounds(key(t, 11), 0, 1_000_000, 10, lowerTip+1+ttlMax+1)
		if err := w.pool.Add(c, w.state, addTip); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Exactly at the lower tip's horizon, so this arm's boundary is
		// separated on OnBlock's own path too and a `>=` for a `>` is caught
		// here and not only through Rescreen.
		survivor := w.certWithBounds(key(t, 12), 0, 1_000_000, 10, lowerTip+1+ttlMax)
		if err := w.pool.Add(survivor, w.state, addTip); err != nil {
			t.Fatalf("setup: %v", err)
		}

		w.pool.OnBlock(&types.Block{}, w.state, lowerTip)

		if w.pool.Has(c.ID()) {
			t.Fatal("a certificate beyond the horizon at the new tip must be doomed by OnBlock")
		}
		if !w.pool.Has(survivor.ID()) {
			t.Fatal("a certificate exactly at the horizon of the new tip must survive OnBlock")
		}
	})
}

// TestMinTTLLeadIsADistanceFromTheTip covers the third sum in the same guard
// block. MinTTLLead is node policy rather than a chain parameter, but it is an
// operator-set uint64 with no upper bound either, and `tipHeight+MinTTLLead`
// wrapped BELOW the tip at a large one — the fail-open direction, disabling
// the gate entirely rather than closing it. The distance form is total for the
// same reason B2's is: the expiry check above establishes c.TTL > tipHeight.
func TestMinTTLLeadIsADistanceFromTheTip(t *testing.T) {
	pol := smallPolicy()
	pol.MinTTLLead = math.MaxUint64 - 10
	w := horizonWorld(t, math.MaxUint64, pol)

	const tip = 100
	c := w.certWithBounds(key(t, 7), 0, 1_000_000, 10, tip+1+devnetTTLMax(t))

	if err := w.pool.Add(c, w.state, tip); !errors.Is(err, mempool.ErrTTLTooNear) {
		t.Fatalf("a lead far below MinTTLLead must be refused with ErrTTLTooNear, got %v", err)
	}
}

// TestMinTTLLeadStillAdmitsAtTheDefaultLead is that gate's anti-vacuity half:
// with the shipped policy the gate must not refuse an ordinary certificate.
func TestMinTTLLeadStillAdmitsAtTheDefaultLead(t *testing.T) {
	pol := smallPolicy()
	w := horizonWorld(t, devnetTTLMax(t), pol)

	const tip = 100
	// Exactly at the lead: distance from the tip is MinTTLLead.
	c := w.certWithBounds(key(t, 8), 0, 1_000_000, 10, tip+pol.MinTTLLead)
	if err := w.pool.Add(c, w.state, tip); err != nil {
		t.Fatalf("a lead exactly at MinTTLLead must be admitted, got %v", err)
	}

	// One short of it, to separate the boundary in the other direction.
	tooNear := w.certWithBounds(key(t, 9), 0, 1_000_000, 10, tip+pol.MinTTLLead-1)
	if err := w.pool.Add(tooNear, w.state, tip); !errors.Is(err, mempool.ErrTTLTooNear) {
		t.Fatalf("a lead one block short of MinTTLLead must be refused with ErrTTLTooNear, got %v", err)
	}
}
