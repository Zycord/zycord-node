package p2p

import (
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// The two prices this file converts message counts into.
//
// **They come from the benchmarks, and the numbers they replaced did not.**
// This file used to carry ~1.7 s and ~55 ms, citing `core/pow/randomx`; that
// package publishes neither. What it records is *"24.8 ms against 574.9 ms
// cold"* (`randomx.go`), and its own benchmarks on an idle machine
// (`BenchmarkInitCache`, `BenchmarkVerify`, median of three runs of 20) give
// **552.9 ms** and **15.1 ms**. The two readings agree on the expensive half to
// within 4% once the hash is subtracted — a never-held epoch is about 0.54 s,
// not 1.7 s — and disagree on the cheap half by the ratio between two
// machines' single-core speed.
//
// So the transcribed pair was wrong by about 3x in each direction, and their
// RATIO was roughly right, which is why nothing looked wrong: the quantity
// docs/decisions/testnet-measurements §2 publishes is the ratio. It is now
// sourced. A transcribed magnitude that goes stale invisibly is the class;
// this is its load-bearing instance.
const (
	// secondsPerNewEpoch is a 256 MiB allocation plus its Argon2 fill: the
	// price of a header whose height selects a key epoch this node does not
	// hold. 552.9 ms of BenchmarkInitCache minus the 15.1 ms hash that
	// benchmark also pays: 537.8 ms.
	//
	// BenchmarkInitCache builds a whole engine per iteration — New, one cold
	// hash, Close — so that subtraction leaves construction and teardown in,
	// and the cross-check is what says they do not matter: randomx.go's
	// 574.9 − 24.8 = 550.1 ms is the same quantity on another machine with no
	// engine construction in it at all, and the two agree to about 2%.
	//
	// Cache initialisation here is the REFERENCE Argon2, not upstream's SIMD
	// one: cgo has no per-file flags, so -mssse3 and -mavx2 are deliberately
	// off (see the cgo preamble in randomx_cgo.go). A binary built upstream's
	// way initialises faster, and this is the number for the binary this
	// project ships.
	secondsPerNewEpoch = 0.54

	// secondsPerHeldEpochHash is one RandomX evaluation under a key the table
	// already has: BenchmarkVerify, the same machine. This is the FASTEST of
	// the three readings the tree carries — randomx.go records 24.8 ms and
	// I7-H3's table 18 H/s, about 55 ms — so the ratio these two constants
	// imply, ~36x, is the largest of them. randomx.go's own pair gives 22x.
	// The hash is what varies across machines here; the epoch has only ever
	// been seen near 0.55 s.
	secondsPerHeldEpochHash = 0.015
)

// TestAUniqueInvalidHeaderFloodIsSelfLimiting measures the one attack the work
// cache explicitly does not stop.
//
// The cache makes a REPEATED header free. It does nothing for DISTINCT ones,
// and distinct ones are cheap to make: copy the target the rule computes — so
// the cheap NextTarget check passes — and put garbage in the nonce. Under the
// old rule every such header cost the receiver one full work evaluation before
// CheckWork refused it: 15–55 ms of RandomX across the three readings
// core/pow/randomx carries, against microseconds for the BLAKE3 stand-in. The
// question was whether per-peer scoring banned the sender before the CPU bill
// mattered, and this test answered it with a bound rather than an opinion.
//
// **The commitment rule has removed the bill entirely, and the assertion at
// the foot of this test now says so.** Garbage in the nonce changes the
// commitment, the commitment misses the declared target, and CheckWork refuses
// the header from its own bytes without asking the engine for anything. The
// count below is zero.
//
// What the test still measures is that the flood TERMINATES: the headers reach
// the work gate, are refused, are charged ScoreInvalidMessage, and the sender
// is banned inside the budget the scoring constants imply. That bound is
// derived here rather than copied, so a reader does not have to re-derive it
// from two constants in another file, and it is what keeps the zero above from
// meaning "nothing was checked".
func TestAUniqueInvalidHeaderFloodIsSelfLimiting(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	work := &countingPoW{}
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")

	const attacker = "10.66.0.1:5000"
	tip := c.Tip()
	honestTarget := pow.NextTarget(c.RecentHeaders(int(p.DifficultyWindow)+1), p)

	// Flood until the peer is banned, or until we give up and call the attack
	// unbounded.
	const giveUp = 500
	sent, banned := 0, false
	for i := 0; i < giveUp; i++ {
		h := types.Header{
			Version:  types.HeaderVersion,
			Height:   tip.Height + 1,
			ParentID: tip.ID(),
			Time:     tip.Time + p.TargetBlockSeconds,
			Target:   honestTarget, // the rule's own target: the cheap check passes
			PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(tip.Height+1, p)},
		}
		// Unique every time, and never solved.
		h.PoW.Nonce = uint32(i) | 1<<31

		ann := BlockAnnounce{Header: h, CertExemplars: nil}
		v := e.OnBlockAnnounce(attacker, ann.MarshalAnnounce())
		sent++
		if v.Score != 0 {
			peers.Adjust(attacker, v.Score)
		}
		if peers.Banned(attacker) {
			banned = true
			break
		}
	}

	evals := work.count()
	t.Logf("the peer was banned after %d unique invalid headers costing %d work "+
		"evaluations; at %.0f ms each that is %.1f s of CPU bought per peer "+
		"identity — the commitment refuses each of these before the engine is "+
		"asked, so the figure is zero rather than bounded", sent, evals,
		secondsPerHeldEpochHash*1000, float64(evals)*secondsPerHeldEpochHash)

	if !banned {
		t.Fatalf("a peer sent %d unique invalid headers without being banned; the "+
			"flood is not self-limiting and %d work evaluations is not a bound",
			sent, evals)
	}

	// The bound, stated as a fact this test will defend — and DERIVED from the
	// two constants rather than written next to them as a number.
	//
	// This assertion read `sent > 16` while the comment beside it said five,
	// and the log line above it says five: the constants imply
	// ScoreBanThreshold/ScoreInvalidMessage = 5 messages, and sixteen is three
	// times that. Softening ScoreInvalidMessage to -7 buys 15 messages —
	// triple the budget, and under 16, so the old guard passed it. (-6 buys 17
	// and would have failed by one, which is the accident that stands between
	// a slack assertion and a silent one.) The number is now computed from the
	// same two constants the prose cites, so the test cannot disagree with its
	// own comment, and a re-derivation lands here rather than on a testnet.
	//
	// A peer starts at zero and is banned at `<=` the threshold, so the budget
	// is the ceiling of the ratio — the message that crosses the line is
	// itself charged and counted.
	budget := (-ScoreBanThreshold + (-ScoreInvalidMessage) - 1) / (-ScoreInvalidMessage)
	if sent > budget {
		t.Errorf("a peer bought %d work evaluations before the ban; the scoring "+
			"constants (%d per invalid message, ban at %d) imply %d, so either "+
			"the constants moved or something stopped charging for these",
			sent, ScoreInvalidMessage, ScoreBanThreshold, budget)
	}

	// **Zero, and the attack this test was written for no longer exists.**
	//
	// This assertion used to demand a positive count, on the reasoning that a
	// header refused cheaply would mean the test was measuring the NextTarget
	// check rather than the flood it names. That reasoning was right under the
	// old rule and is wrong under this one. These headers carry the rule's own
	// target and garbage in the nonce — no work behind them at all — so their
	// commitment misses that target and pow.CheckWork answers from the header's
	// own bytes. The headers still REACH the work gate; the gate no longer
	// costs an evaluation to say no.
	//
	// So the attack in this test's doc comment above — "every such header costs
	// the receiver one full work evaluation" — has been priced out rather than
	// merely bounded. The cost per peer identity is not 5 evaluations bounded
	// by a ban; it is none, and the ban is now a second line of defence behind
	// a free refusal rather than the only one.
	//
	// The assertion is inverted rather than deleted, and the anti-vacuity it
	// carried is now carried by the `banned` check and the `sent > budget`
	// bound above: the flood was judged, charged ScoreInvalidMessage per
	// message, and terminated in a ban inside the budget the scoring constants
	// imply. "0 evaluations" therefore cannot be read as "these headers were
	// never looked at" — they were looked at, refused, and paid for.
	if evals != 0 {
		t.Fatalf("the flood cost %d work evaluations, want 0: a header whose "+
			"commitment misses its declared target is refused from its own "+
			"bytes, and an evaluation here means that cheap refusal is not "+
			"being taken and the flood is buying CPU again", evals)
	}
}

// TestAHeightVaryingFloodIsBoundedInEpochsToo measures the EXPENSIVE half of
// the flood, which the test above does not reach.
//
// TestAUniqueInvalidHeaderFloodIsSelfLimiting builds every header at
// `tip.Height+1`, so every one of them lands in the key epoch the node already
// holds: it measures the held-key case, and it is honest about being a count of
// work evaluations. But `docs/decisions/testnet-measurements.md` §2 cites that
// test TWICE as the thing that measures the flood and "fails if the bound
// moves" — while the worst case it describes in the same paragraph is a
// different one. The work key comes from `pow.KeyFor(h.Height, p)`, the
// announce path applies no height window before the work check, and an
// announcement's height is chosen by the sender. So headers at widely
// separated heights select epochs the node has never seen, at about thirty
// times the price each.
//
// That case had no test at all. A document citing a test for a property the
// test does not exercise is this project's own recurring defect — an
// instrument named for something it does not measure (I5, I7-L1) — sitting in
// the document the M3 gate leans on. This is the missing half.
//
// # The heights are aligned to epoch starts, and that is not a detail
//
// The obvious sequence — `tip.Height + 1 + i*RandomXKeyInterval` — does NOT
// give one fresh epoch per message, and an earlier draft of this test measured
// four where the attacker can have five. `SeedEpochFor` is
// `(height - RandomXKeyLag) / RandomXKeyInterval` with a clamp to 0 below the
// first boundary, so the lag SHIFTS the boundary: on devnet (interval 64, lag
// 8) heights 1 and 65 are one interval apart and both land in epoch 0 — which
// is also the epoch the node's own tip is in, so the first two messages buy a
// cache the node already holds. Stepping one interval apart is one epoch apart
// only for heights already past the shift.
//
// The attacker has no reason to make that mistake, and the document this test
// backs states a WORST case. So the heights are the first height OF each
// epoch, `RandomXKeyLag + n*RandomXKeyInterval`, walking upward from the epoch
// after the tip's: every message NAMES an epoch the node does not hold. Under
// the commitment rule none of them is built, because none of these headers gets
// past the target comparison — but the heights stay aligned so that a
// regression which restored the evaluation would force a fresh epoch per
// message and be caught, rather than being masked by heights that collide.
//
// What it defends, and the scope is the whole of it: for headers the work check
// REFUSES, the number of distinct never-held epochs one identity can force is
// bounded by the same scoring budget as the number of evaluations. If a change
// ever lets a peer force epochs with headers like these, or stops charging for
// them at all, the bound moves and this fails.
//
// **Under the commitment rule that bound has collapsed to zero, and the
// reachability arm at the foot of this test asserts zero rather than the
// budget.** These headers carry no work, so their commitment misses the target
// they declare and CheckWork refuses them from their own bytes; the engine is
// never asked for a key, so no cache is ever initialised. The worst case this
// test was written to publish — every charged message spent on a fresh 256 MiB
// initialisation — is no longer reachable at all, which is why the arm that
// demanded it be reachable had to be inverted rather than kept.
//
// The height alignment described below still matters, and is kept for that
// reason: it is what would make the count non-zero again if the cheap refusal
// ever stopped being taken, so it is the difference between this test failing
// loudly on a regression and quietly reporting zero for the wrong reason.
//
// **"For headers the work check refuses" is load-bearing and it is not a
// hedge.** Every header here carries the target the rule itself computes, so
// every one fails at the work check and every one is charged. A header that
// declares its OWN target passes that check and is scored POSITIVELY, so the
// scoring budget this test derives is a bound on its charged half and never on
// the class — reading it as a bound on "the flood" is precisely the citation
// error I7-L3 is about. That half now has a budget of its own, in front of the
// work check rather than behind it, and it is
// TestAnAnnouncersOwnTargetBuysABoundedNumberOfKeyEpochs below. The two
// budgets are the same number and that is not a coincidence: the price on an
// accepted announcement's key epoch is derived from what a REFUSED one already
// buys, which is what this test measures.
func TestAHeightVaryingFloodIsBoundedInEpochsToo(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	work := newEpochCounter()
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")

	const attacker = "10.66.0.2:5000"
	tip := c.Tip()
	honestTarget := pow.NextTarget(c.RecentHeaders(int(p.DifficultyWindow)+1), p)

	// No guard on RandomXKeyInterval == 0: params.Validate refuses any set with
	// RandomXKeyLag >= RandomXKeyInterval, and a zero interval fails that for
	// every lag including zero, so the interval is at least 1 in anything this
	// test can be handed. A Skip here would be a branch that cannot run — the
	// shape I5 spent a milestone on.
	//
	// The epoch the node already holds: it verified its own tip under this key,
	// so a header landing here costs a hash and not a cache.
	held := pow.KeyFor(tip.Height, p)
	tipEpoch := pow.SeedEpochFor(tip.Height, p)

	const giveUp = 500
	sent, banned := 0, false
	for i := 0; i < giveUp; i++ {
		// The FIRST height of epoch (tipEpoch + 1 + i). Ascending away from the
		// tip, one whole epoch per message, and never the epoch the node holds.
		height := p.RandomXKeyLag + (tipEpoch+1+uint64(i))*p.RandomXKeyInterval
		h := types.Header{
			Version: types.HeaderVersion,
			Height:  height,
			// A parent this node does not hold, and NOT the tip.
			//
			// It used to be the tip, which cost nothing while no ingress path
			// looked at the pair — and it was also a header no chain can
			// contain, since a block whose parent is the tip is at tip.Height+1
			// and these heights are whole key epochs away. The successor-height
			// rule closed that: an announcement naming this node's own tip at
			// any other height is refused ahead of the work check, so a
			// tip-parented flood now forces ZERO key epochs and every count
			// here would measure that refusal rather than the cost of a refused
			// header.
			//
			// **That is a narrowing of the attack and not a repair of this
			// test.** The quantity this test publishes is what a height-varying
			// flood of headers the WORK CHECK refuses costs, and the shape that
			// still reaches the work check is the one an attacker this far from
			// the tip would have used anyway: an unknown parent, which is what
			// keyepochbudget_internal_test.go's own header builder moved to for
			// the same reason under the tip-parent target rule. Same
			// arrangement, stated so that it still exercises the term it names.
			ParentID: types.Hash{0xab},
			Time:     tip.Time + p.TargetBlockSeconds,
			Target:   honestTarget,
			PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p)},
		}
		h.PoW.Nonce = uint32(i) | 1<<31

		ann := BlockAnnounce{Header: h, CertExemplars: nil}
		v := e.OnBlockAnnounce(attacker, ann.MarshalAnnounce())
		sent++
		if v.Score != 0 {
			peers.Adjust(attacker, v.Score)
		}
		if peers.Banned(attacker) {
			banned = true
			break
		}
	}

	// The number that costs anything is the number of epochs the node did NOT
	// already hold, so the log reports that rather than the count — a key the
	// table would have served is a held-key hash wearing a cold epoch's price
	// tag — a factor of about thirty, which is the whole quantity §2 publishes.
	epochs := work.distinctKeys()
	forced := epochs
	if work.sawKey(held) {
		forced--
	}
	t.Logf("banned=%v after %d headers spanning %d distinct key epochs, %d of "+
		"them never held by this node; at ~%.1f s per never-held epoch that is "+
		"%.1f s of CPU per identity, against %.1f s had they all shared the "+
		"epoch this node holds",
		banned, sent, epochs, forced, secondsPerNewEpoch,
		float64(forced)*secondsPerNewEpoch,
		float64(sent)*secondsPerHeldEpochHash)

	if !banned {
		t.Fatalf("a peer forced %d distinct key epochs without being banned; "+
			"the epoch cost is not self-limiting", epochs)
	}

	// Anti-vacuity, and it comes first because every number above is worthless
	// without it: an epoch the node already holds costs a hash, not a cache, so
	// counting one as forced is how the ~30x figure in testnet-measurements §2
	// silently becomes ~20x.
	if work.sawKey(held) {
		t.Fatalf("one of the %d epochs charged for is the epoch this node's own "+
			"tip is in, so it was not forced at all: this test would be counting "+
			"a ~%.0f ms hash as a ~%.1f s cache initialisation, and the heights "+
			"are no longer aligned to epoch starts",
			epochs, secondsPerHeldEpochHash*1000, secondsPerNewEpoch)
	}

	// The bound, derived from the same two constants as the test above: an
	// identity cannot force more epochs than it can send charged messages.
	//
	// It is worth saying why this can fire at all, given the ban assertion
	// above already bounds the MESSAGE count. It fires when one message forces
	// more than one epoch, which is not hypothetical: the citation-work loop
	// was exactly that — a KindBlock whose citations forced five key epochs
	// from a single message — and the hoist that closed it lives on the other
	// ingress path. A change that let an announcement cite, or otherwise reach,
	// a second height would land here.
	budget := (-ScoreBanThreshold + (-ScoreInvalidMessage) - 1) / (-ScoreInvalidMessage)
	if forced > budget {
		t.Errorf("one identity forced %d never-held key epochs before the ban; "+
			"the scoring constants imply at most %d, and each of them costs "+
			"about thirty times a hash under the epoch this node holds",
			forced, budget)
	}

	// **Zero, and the expensive half of the flood has been priced out.**
	//
	// This arm used to demand that the budget be REACHABLE — `forced` equal to
	// it — so that the test could not drift back into measuring the cheap case
	// wearing an expensive name. Under the commitment rule the premise is gone.
	// These headers declare the rule's own target and carry no work at all, so
	// their commitment misses that target and pow.CheckWork answers from the
	// header's own bytes. The engine is never asked for a key, so no epoch is
	// instantiated and none can be forced.
	//
	// That is the strongest possible answer to the question this test asks. The
	// worst case it exists to publish — a height-varying flood buying
	// never-held key epochs at ~0.5 s of cache initialisation each — is no
	// longer bounded at the scoring budget; it is zero, because the sender must
	// now do the work before the receiver spends any. The ~30x figure
	// testnet-measurements §2 draws from this test is a cost that a flood of
	// unsolved headers can no longer impose at all.
	//
	// The assertion is inverted rather than deleted, and its anti-vacuity is
	// carried by what stands above it: `banned` says the flood was judged,
	// charged and terminated, and the `forced > budget` bound still fires if
	// any epoch is ever forced again. Together they make "0 never-held epochs"
	// mean "refused before the engine was asked" rather than "never looked at".
	if forced != 0 {
		t.Fatalf("%d headers forced %d never-held key epochs, want 0: a header "+
			"whose commitment misses its declared target is refused from its "+
			"own bytes, so no key is ever built for one, and a non-zero count "+
			"means that cheap refusal is not being taken and the flood is "+
			"buying cache initialisations again", sent, forced)
	}
}

// TestAnAnnouncersOwnTargetBuysABoundedNumberOfKeyEpochs is the half the two
// tests above do NOT bound, and it is now bounded.
//
// It replaces TestAnAnnouncersOwnTargetForcesEpochsTheScoringNeverBounds, which
// asserted the defect deliberately so that no document could cite the bounded
// pair as covering the class, and which said in its own failure messages that
// it would fail on the day somebody fixed it. It did. This is the same
// arrangement — one identity, fifty announcements at its own declared target,
// heights aimed at successive key-epoch starts — asserting what the arrangement
// now costs.
//
// # The mechanism is unchanged, and that is deliberate
//
// `pow.CheckWork` still compares the digest against **`h.Target`, the header's
// own declared field**, and still clamps it against nothing:
//
//	digest := e.Hash(key, h.PoWInput())
//	if u256.FromLEBytes(digest).Gt(h.Target) { return ErrWorkTooLow }
//
// At `Target = u256.Max` no digest can exceed it, so the check still PASSES,
// and it is still evaluated under `pow.KeyFor(h.Height, p)` at a height the
// sender chose. Bounding the accepted target was rejected in
// `docs/adversarial/sync.md` §6.1 because difficulty may legitimately
// fall, and a height window around this node's tip was built and reverted
// (I7-H4) because it broke catch-up. Neither rejection is reopened here.
//
// What changed is that the epoch now has a **price** in front of it:
// `Engine.spendKeyEpoch` charges one credit per announcement naming a key epoch
// outside the ones this node is itself working in, `MaxUnheldKeyEpochsPerPeer`
// of them per connection, refilled at the rate the honest chain crosses key
// epochs. Past that the announcement is refused at `CostBudgeted` **before**
// the work check runs, so the epoch is never built.
//
// # What this test asserts, and why the number is 1 + the budget
//
// The heights walk epoch starts from `tipEpoch+1` upward. The first of them
// lands in `tipEpoch+1`, which is an epoch this node is working in — an honest
// peer announces into it for the whole interval it takes this node's tip to
// cross a boundary — so it is free and it is meant to be. Every height after it
// is outside, and the budget covers `MaxUnheldKeyEpochsPerPeer` of those. So
// one identity buys `1 + MaxUnheldKeyEpochsPerPeer` distinct key epochs and no
// more, however many messages it sends.
//
// Stated as an equality in both directions, like the sibling above. Above the
// bound means the price stopped being charged; below it means something else
// refuses these first, and the worst case this test publishes would be
// understated rather than failing.
//
// # Both variants, because Header.Time used to decide whether anything charges
//
//   - **present-dated** — accepted announcements still enter `pending`, and
//     `ReapUnservedBodies` still charges `ScoreUnservedBody` for the bodies
//     that never arrive. What is bounded now is how many there can be. They are
//     no longer *forwarded*: Option A relays an announcement only from a
//     node that holds the body, so the amplification this row used to bound is
//     gone rather than bounded, and the charge lands on the announcer.
//   - **future-dated** — `tooFarAhead` still returns `CostFree` at
//     `ScoreFutureBlock` and still enters the id into *neither* `seenBlocks`
//     nor `pending`, both deliberately (R1-H2, and so that the re-announcement
//     is not deduped away once the clock catches up). So nothing charges and
//     nothing dedupes on that path, which is what made it unbounded: each
//     message still bought a RandomX evaluation, and once the key-epoch price
//     existed, a credit against it as well. The future-time check now stands
//     AHEAD of both, so this row forces **zero** epochs and spends **zero**
//     credits. That is the point of asserting both, and the two rows now differ
//     in the direction that costs the receiver nothing.
func TestAnAnnouncersOwnTargetBuysABoundedNumberOfKeyEpochs(t *testing.T) {
	// Comfortably past the bound. Nothing here is tuned: any number above it
	// makes the point, and this one keeps the test instant under the dev
	// engine. It is also the count the superseded characterisation test used,
	// so the two are read against the same arrangement.
	const send = 50
	// One free working epoch plus the budget. Derived from the constant rather
	// than restated, so this cannot drift from the code it measures.
	const bound = 1 + MaxUnheldKeyEpochsPerPeer

	// run drives one identity through `send` announcements at its own declared
	// target and reports what the node did about it.
	run := func(t *testing.T, attacker string, future bool) (epochs, charged, forwarded, accepted, budgeted, reaped int, banned bool) {
		t.Helper()
		p := spec.Devnet()
		c, err := chain.Open(t.TempDir(), p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		peers, err := NewPeerStore("")
		if err != nil {
			t.Fatal(err)
		}
		work := newEpochCounter()
		e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")

		tip := c.Tip()
		tipEpoch := pow.SeedEpochFor(tip.Height, p)
		for i := 0; i < send; i++ {
			height := p.RandomXKeyLag + (tipEpoch+1+uint64(i))*p.RandomXKeyInterval
			when := tip.Time + p.TargetBlockSeconds
			if future {
				when = uint64(time.Now().Unix()) + 100*p.FutureTimeLimitSeconds
			}
			h := types.Header{
				Version: types.HeaderVersion,
				Height:  height,
				// A parent this node does not hold, and NOT the tip.
				//
				// This test's header is at a height whole key epochs away from
				// the tip, so naming the tip as its parent described a block
				// that cannot exist — free while nothing on the announce path
				// read the field, and no longer free: an announcement naming
				// this node's own tip must carry the target the difficulty rule
				// gives, and this one deliberately does not. Left as the tip it
				// would be refused before the work check and every count below
				// would measure that refusal.
				//
				// **This test is the one cited as the counter-example to "do
				// not forward what you cannot attribute", and the citation
				// still holds with this parent.** It held with the tip as
				// parent too: the ghost was forwarded and reaped either way, at
				// identical cost, which is exactly the indistinguishability the
				// finding was about — and the forward half of it is what Option
				// A removed.
				ParentID: types.Hash{0xab},
				Time:     when,
				// The ATTACKER's target, not the rule's. This one field is
				// what separates this test from the two above.
				Target:   u256.Max,
				CertRoot: certRoot(nil, p),
				PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p)},
			}
			h.PoW.Nonce = uint32(i) | 1<<31
			// The digest of this header's own blob, which the work rule now
			// requires. At u256.Max every commitment passes, so this is one
			// evaluation rather than a search — the announcement is still as
			// cheap to make as the finding says, and it still PASSES the work
			// check, which is the whole premise below.
			sealDev(&h, p)

			// Anti-vacuity, on the first header and asked of a bare pow.Dev so
			// that the instrument is not seeded with the answer: the work check
			// must ACCEPT these. If it ever refuses them, every count below is
			// a measurement of the work check and none of it is about the
			// budget this test exists for.
			if i == 0 {
				if err := pow.CheckWork(pow.Dev{}, h, p); err != nil {
					t.Fatalf("setup: the declared-target header does not pass "+
						"CheckWork (%v); at u256.Max no commitment can exceed the "+
						"target and the whole finding is that it passes", err)
				}
			}

			ann := BlockAnnounce{Header: h, CertExemplars: nil}
			v := e.OnBlockAnnounce(attacker, ann.MarshalAnnounce())
			if v.Score < 0 {
				charged++
			}
			if v.Forward {
				forwarded++
			}
			// Accepted is what entered `pending` and therefore what the reaper
			// can charge for. It used to be read off `Forward`, which stopped
			// being the same set when Option A took the forward away and
			// left everything else on that return where it was.
			if v.Reply != nil {
				accepted++
			}
			if v.Cost == CostBudgeted {
				budgeted++
				// A budget refusal must not also move the score. Free, Deduped
				// and Budgeted all say the sender's score does not move
				// (wire.md §10.2), and a Budgeted verdict that scored would ban
				// the honest peers a node behind the chain depends on — which
				// is the failure that reverted the tip-window guard.
				if v.Score != 0 {
					t.Fatalf("a CostBudgeted refusal carried Score %d; the "+
						"budget is the price, and scoring on top of it turns a "+
						"price into the ban I7-H4 reverted", v.Score)
				}
			}
			if v.Score != 0 {
				peers.Adjust(attacker, v.Score)
			}
		}
		// Long past PendingBodyTimeout: whatever the reaper is ever going to
		// charge for these, it has charged by now.
		for _, addr := range e.ReapUnservedBodies(time.Now().Add(time.Hour)) {
			_ = addr
			reaped++
		}
		return work.distinctKeys(), charged, forwarded, accepted, budgeted, reaped, peers.Banned(attacker)
	}

	for _, tc := range []struct {
		name      string
		attacker  string
		future    bool
		forwarded int
		accepted  int
		epochs    int
		budgeted  int
	}{
		// Present-dated announcements are accepted up to the bound, and since
		// Option A none of them is relayed — so the amplification this
		// row used to bound is gone rather than bounded, and what the bound
		// still governs is how many key epochs this node itself builds.
		{"present-dated", "10.66.0.3:5000", false, 0, bound, bound, send - bound},
		// A withheld block is not relayed (R1-H2), so this variant never had
		// the amplification and still does not — and since the future-time
		// check moved ahead of the price and the work check, it no
		// longer forces an epoch or spends a credit either. Zero, not the
		// bound: the clock this node already owns answers before anything the
		// sender chose is evaluated.
		{"future-dated", "10.66.0.4:5000", true, 0, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			epochs, charged, forwarded, accepted, budgeted, reaped, banned := run(t, tc.attacker, tc.future)
			t.Logf("%d announcements at the announcer's own target: %d epochs "+
				"forced, %d charged at announce time, %d forwarded, %d accepted, "+
				"%d refused unevaluated, %d reaped as unserved, banned=%v — bound "+
				"is %d (one working epoch plus a budget of %d), and at ~%.1f s per "+
				"never-held epoch that is %.1f s of CPU rather than %.1f s",
				send, epochs, charged, forwarded, accepted, budgeted, reaped, banned,
				tc.epochs, MaxUnheldKeyEpochsPerPeer, secondsPerNewEpoch,
				float64(epochs)*secondsPerNewEpoch, float64(send)*secondsPerNewEpoch)

			// The property. Above it the price stopped being charged.
			if epochs > tc.epochs {
				t.Fatalf("%d announcements from one identity forced %d distinct "+
					"key epochs, above the bound of %d; the price on a key epoch "+
					"this node is not working in has stopped being charged, and "+
					"the price is not being charged", send, epochs, tc.epochs)
			}
			// And below it, which is what stops this test drifting into
			// measuring some other refusal wearing this one's name. The heights
			// walk epoch starts, so every one of the budgeted messages really
			// can be spent on a fresh epoch, and a count below the bound means
			// something refuses them earlier than the budget does.
			if epochs < tc.epochs {
				t.Fatalf("%d announcements forced only %d distinct key epochs "+
					"against a reachable bound of %d; something now refuses "+
					"these before the budget does, so this test measures that "+
					"instead and the worst case it publishes is understated",
					send, epochs, tc.epochs)
			}
			// The refusals are the price, and there must be some: with send
			// well above the bound, a run in which nothing was refused is a run
			// in which the guard never fired.
			if budgeted != tc.budgeted {
				t.Errorf("%d of %d announcements were refused at CostBudgeted, "+
					"want %d; every message past the bound is refused "+
					"unevaluated, and any other split means the epochs above "+
					"were bounded by something else", budgeted, send, tc.budgeted)
			}
			// Nothing is scored at announce time, and that is unchanged and
			// deliberate. The work check accepts a declared target — see
			// sync.md §6.1 — so there is no invalid message to charge for, and
			// charging for the budget refusal would ban a node's honest peers
			// while it is behind.
			if charged != 0 {
				t.Errorf("%d announcements were charged at announce time; the "+
					"work check still accepts a declared target, so a charge "+
					"here means adversarial/sync.md §6.1's rejection of "+
					"bounding h.Target has been reopened without saying so",
					charged)
			}
			if banned {
				t.Errorf("the announcer was banned. The budget is a price, not " +
					"a judgement: a node that is behind receives announcements " +
					"far ahead from the honest peers it depends on, and banning " +
					"for that is what reverted I7-H4's tip-window guard " +
					"(TestCatchingUpDoesNotBanTheHonestPeersItDependsOn)")
			}
			// Zero on both rows, and on the present-dated row that is
			// Option A rather than this test's bound: forwarding is what made
			// one message cost the whole network an epoch, and a node relays an
			// announcement only once it holds the body.
			if forwarded != tc.forwarded {
				t.Errorf("%d of %d announcements were forwarded, want %d; "+
					"forwarding is what makes one message cost the whole "+
					"network an epoch, so this is the amplification bound and "+
					"not a detail", forwarded, send, tc.forwarded)
			}
			// And the row still has to reach the acceptances it is about, or
			// the zero above is a measurement of a refusal rather than of the
			// forward (`PROTOCOL.md` rule 24).
			if accepted != tc.accepted {
				t.Errorf("%d of %d announcements were accepted, want %d; the "+
					"forward count above only means anything on announcements "+
					"that got past every refusal", accepted, send, tc.accepted)
			}
			// The delayed charge that was the present-dated variant's only
			// bound is still there and is now the smaller of the two: it
			// reaches the bounded number of accepted announcements, one
			// PendingBodyTimeout late, rather than all fifty.
			wantReaped := tc.accepted
			if reaped != wantReaped {
				t.Errorf("the unserved-body reaper charged %d, want %d: it "+
					"charges for the announcements this node accepted and "+
					"entered into pending, and a budget refusal must not enter "+
					"one", reaped, wantReaped)
			}
		})
	}
}
