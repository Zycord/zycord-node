package p2p

import (
	"fmt"
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// floodEngine builds an engine with a clock the test drives, so the liveness
// halves of the work-eval budget can advance time across whole refill periods
// deterministically rather than leaning on the wall clock.
func floodEngine(t *testing.T) (*Engine, *params.Params, *countingPoW, *int64) {
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
	work := &countingPoW{}
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")
	// Anchored one second past the tip's timestamp so a header dated at 'now'
	// sits within the future-time limit rather than behind the tip.
	clock := new(int64)
	*clock = int64(c.Tip().Time) + 1
	e.Now = func() time.Time { return time.Unix(*clock, 0) }
	return e, p, work, clock
}

// workingAnnounce is one distinct, well-formed announcement in a key epoch this
// node is working in (height tip+1), carrying the announcer's own target so the
// work check accepts it, and a non-tip parent so the difficulty-vs-tip gate is
// skipped. nonce makes each one distinct; when dates it.
func workingAnnounce(p *params.Params, tip types.Header, nonce uint32, when int64) []byte {
	height := tip.Height + 1
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   height,
		ParentID: types.Hash{0xab},
		Time:     uint64(when),
		Target:   u256.Max,
		CertRoot: certRoot(nil, p),
		PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p), Nonce: nonce | 1<<31},
	}
	return BlockAnnounce{Header: h, CertExemplars: nil}.MarshalAnnounce()
}

// TestWorkEvalCeilingBoundsTheAggregateUnderIdentityChurn is the test the
// hostile review of the per-connection-only version demanded, and the one the
// per-connection budget alone fails.
//
// The defeat it pins: a per-connection (per-identity) budget is keyed on an
// identity, and an identity is free to mint, so a fresh identity per connection
// restores the flood in full — the aggregate work is N x MaxWorkEvalsPerConn,
// linear in identities, because eviction readmits a fresh budget and keypairs
// cost nothing. This drives N distinct identities, each burning MORE than its
// per-connection budget of distinct announcements, and asserts the AGGREGATE
// number of work.Check evaluations is bounded by the node-wide ceiling rather
// than by N x MaxWorkEvalsPerConn.
//
// It is also the mutation check: disable nodeWorkEvalsExhausted (the node-wide
// layer) and the aggregate returns to identities x MaxWorkEvalsPerConn — 1280
// here against a ceiling of 256 — failing the bound below. The non-vacuity
// guard makes that gap explicit: the arrangement is sized so the churned
// per-connection sum is far above the ceiling, so a pass genuinely measures the
// shared bucket and not the per-connection one.
func TestWorkEvalCeilingBoundsTheAggregateUnderIdentityChurn(t *testing.T) {
	e, p, work, _ := floodEngine(t)
	tip := e.Chain.Tip()
	ceiling, _ := workEvalCeiling()

	const identities = 10
	// Comfortably past the per-connection budget, so each identity would, on its
	// own, run MaxWorkEvalsPerConn evaluations.
	const perIdentity = MaxWorkEvalsPerConn + 72

	// Fixed clock: no credit refills inside the run, so the aggregate is the raw
	// ceiling and the assertion is exact.
	var salt uint32
	for k := 0; k < identities; k++ {
		conn := fmt.Sprintf("10.20.%d.1:5000", k) // a fresh identity per connection
		for i := 0; i < perIdentity; i++ {
			e.OnBlockAnnounceFrom(conn, conn, workingAnnounce(p, tip, salt, int64(tip.Time)))
			salt++
		}
	}
	agg := work.count()
	t.Logf("%d churned identities x %d distinct announcements each: %d aggregate "+
		"work.Check evaluations, node-wide ceiling %d, per-connection-only bound "+
		"would be %d", identities, perIdentity, agg, ceiling, identities*MaxWorkEvalsPerConn)

	// Non-vacuity first: the churned per-connection sum must be far above the
	// ceiling, or a bounded aggregate would not distinguish the two layers.
	if identities*MaxWorkEvalsPerConn <= int(ceiling) {
		t.Fatalf("arrangement is too small: %d identities x %d per-connection budget = %d, "+
			"not above the node ceiling %d, so a bounded aggregate proves nothing about churn",
			identities, MaxWorkEvalsPerConn, identities*MaxWorkEvalsPerConn, ceiling)
	}
	// The property: the aggregate is the shared ceiling, not the per-connection
	// sum. Above it, the node-wide layer stopped charging (the churn defeat is
	// back); the exact equality also fails if the ceiling were reverted, since
	// that returns the aggregate to identities x MaxWorkEvalsPerConn.
	if agg != int(ceiling) {
		t.Fatalf("%d churned identities forced %d aggregate work evaluations, want exactly "+
			"the node-wide ceiling of %d. Above it the shared bucket stopped binding and "+
			"identity churn (free keypairs) restored an N x %d flood; this is the "+
			"defect the hostile review of the per-connection-only fix reproduced.",
			identities, agg, ceiling, MaxWorkEvalsPerConn)
	}
}

// TestHonestAnnounceVolumeIsNotThrottled is the first half of the liveness
// trap: honest gossip, in honest volume, must keep flowing under both budget
// layers.
//
// Two shapes, each the honest counterpart of an attacker one:
//
//   - steady state over many periods. An honest peer announces about one new
//     block per TargetBlockSeconds, the refill rate, and node-wide honest demand
//     is that same one-or-two blocks per period (not per peer). Sent three times
//     the per-connection burst at that rate, none of it is throttled.
//   - honest fan-out. Many peers announce the SAME blocks, and the seen-set
//     dedups across them: only the first announcer of each block runs a work
//     check, every other peer's announcement of it returns CostDeduped. So fan-
//     out does not multiply work and does not approach the node-wide ceiling —
//     which is exactly why that ceiling, sized for honest DISTINCT-block demand,
//     does not throttle a large honest peer set.
func TestHonestAnnounceVolumeIsNotThrottled(t *testing.T) {
	e, p, work, clock := floodEngine(t)
	tip := e.Chain.Tip()
	period := int64(workEvalPeriod(p))
	if period <= 0 {
		t.Fatalf("refill period is %d; a non-positive period would make this test vacuous", period)
	}

	// (1) Steady state at the honest rate: one new block per refill period, three
	// per-connection bursts long. Neither the per-connection budget nor the
	// node-wide ceiling throttles it — each refills at or above one per period.
	const conn = "10.0.0.1:5000"
	const rounds = 3 * MaxWorkEvalsPerConn
	for i := 0; i < rounds; i++ {
		v := e.OnBlockAnnounceFrom(conn, conn, workingAnnounce(p, tip, uint32(i), *clock))
		if v.Cost == CostBudgeted {
			t.Fatalf("honest announcement %d of %d at the honest rate (one new block per "+
				"refill period) was throttled; the budgets refill at least this fast, so "+
				"honest steady-state gossip must never deplete them", i, rounds)
		}
		if v.Reply == nil {
			t.Fatalf("honest announcement %d was not accepted: %v", i, v.Err)
		}
		*clock += period
	}
	if got := work.count(); got != rounds {
		t.Fatalf("honest steady state ran %d work checks over %d announcements; every "+
			"honest announcement must reach the work check", got, rounds)
	}

	// (2) Honest fan-out at one instant: D distinct new blocks, each announced by
	// C peers. Only the first announcer of each pays a work check; the rest
	// dedup. So the work is D, not D x C, and D is well under the node ceiling.
	const distinct = 32
	const peersPer = 8
	before := work.count()
	deduped, accepted := 0, 0
	for d := 0; d < distinct; d++ {
		raw := workingAnnounce(p, tip, uint32(1)<<20+uint32(d), *clock)
		for c := 0; c < peersPer; c++ {
			conn := fmt.Sprintf("10.9.%d.%d:5000", c, d%250)
			v := e.OnBlockAnnounceFrom(conn, conn, raw)
			switch {
			case v.Cost == CostBudgeted:
				t.Fatalf("honest fan-out was throttled: block %d from peer %d dropped. "+
					"Honest peers announce the same blocks and the seen-set dedups them, "+
					"so fan-out must never approach the work-eval ceiling", d, c)
			case v.Cost == CostDeduped:
				deduped++
			case v.Reply != nil:
				accepted++
			}
		}
	}
	// Exactly one work check per distinct block, and the rest deduped: fan-out
	// carried no extra CPU.
	if got := work.count() - before; got != distinct {
		t.Fatalf("honest fan-out of %d blocks across %d peers ran %d work checks, want %d "+
			"(one per distinct block); the seen-set is not deduping across peers", distinct, peersPer, got, distinct)
	}
	if accepted != distinct || deduped != distinct*(peersPer-1) {
		t.Fatalf("fan-out accepted %d and deduped %d, want %d accepted and %d deduped: "+
			"the first announcer of each block pays, every other dedups", accepted, deduped, distinct, distinct*(peersPer-1))
	}
}

// TestAValidBlockStaysObtainableThroughASaturatedNode is the second half of the
// trap: the throttle drops the cheap ANNOUNCEMENT, never the block's
// obtainability. A valid block announced while the node-wide ceiling is spent is
// dropped without a score and without being remembered, and stays reachable —
// re-announced once the ceiling refills. The gate must never blacklist a valid
// block.
func TestAValidBlockStaysObtainableThroughASaturatedNode(t *testing.T) {
	e, p, _, clock := floodEngine(t)
	tip := e.Chain.Tip()
	ceiling, _ := workEvalCeiling()
	period := int64(workEvalPeriod(p))

	// Saturate the NODE-WIDE ceiling: it takes more than one connection's budget
	// to fill, so spend it across enough connections to run the ceiling dry.
	var salt uint32
	conns := int(ceiling)/MaxWorkEvalsPerConn + 1
	for k := 0; k <= conns; k++ {
		conn := fmt.Sprintf("10.30.%d.1:5000", k)
		for i := 0; i < MaxWorkEvalsPerConn; i++ {
			e.OnBlockAnnounceFrom(conn, conn, workingAnnounce(p, tip, salt, int64(tip.Time)))
			salt++
		}
	}

	// A specific, valid block B, distinct from all the saturating junk.
	rawB := workingAnnounce(p, tip, 0xB10C, int64(tip.Time))
	annB, err := UnmarshalAnnounce(rawB)
	if err != nil {
		t.Fatal(err)
	}
	idB := annB.Header.ID()

	// B announced while the node ceiling is spent: dropped at CostBudgeted, on
	// the node-wide (own=false) arm, unscored, and — the load-bearing half — NOT
	// entered into seenBlocks, so a later announcement is not deduped away.
	const fresh = "10.40.0.1:5000"
	vDrop := e.OnBlockAnnounceFrom(fresh, fresh, rawB)
	if vDrop.Cost != CostBudgeted {
		t.Fatalf("B was not dropped while the node ceiling was spent (cost %v); the setup "+
			"did not saturate the ceiling", vDrop.Cost)
	}
	if vDrop.Reply != nil {
		t.Fatal("a dropped announcement issued a get-block; it was not dropped unevaluated")
	}
	if vDrop.Score != 0 {
		t.Fatalf("the dropped announcement scored %d; a node-wide-ceiling drop can be "+
			"caused by another peer's flood and must never be scored", vDrop.Score)
	}
	e.mu.Lock()
	_, seenAfterDrop := e.seenBlocks[idB]
	e.mu.Unlock()
	if seenAfterDrop {
		t.Fatal("the dropped block was entered into seenBlocks; a re-announcement would be " +
			"deduped away and a valid block made permanently unobtainable")
	}
	if e.Peers.Banned(fresh) {
		t.Fatal("the announcer of a valid block was banned; the gate must not blacklist")
	}

	// The ceiling refills, and the same valid block is now accepted and reaches
	// the fetch path — pending plus a get-block. The block stayed obtainable;
	// only the cheap announcement while the node was saturated was dropped.
	*clock += period
	vGet := e.OnBlockAnnounceFrom(fresh, fresh, rawB)
	if vGet.Reply == nil {
		t.Fatalf("after the ceiling refilled, a valid block was still refused: %v — the "+
			"throttle made it permanently unobtainable", vGet.Err)
	}
	if vGet.Reply.Kind != KindGetBlock {
		t.Fatalf("the accepted announcement replied with %v, not a get-block; the block is "+
			"not being fetched", vGet.Reply.Kind)
	}
	e.mu.Lock()
	_, pend := e.pending[idB]
	_, seenAfterAccept := e.seenBlocks[idB]
	e.mu.Unlock()
	if !pend || !seenAfterAccept {
		t.Fatalf("the accepted block did not enter pending (%v) / seen (%v); it is not on "+
			"the fetch path", pend, seenAfterAccept)
	}
}
