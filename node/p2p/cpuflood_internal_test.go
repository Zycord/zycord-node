package p2p

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// workingEpochFlood drives `send` distinct, well-formed announcements from a
// single connection, every one of them in a key epoch this node is working in
// (so spendKeyEpoch exempts it) and carrying the announcer's own target (so the
// work check accepts it), and reports how many RandomX evaluations the flood
// bought and how the node scored the connection.
//
// It is the shared arrangement of the work-eval reproduction and of the two liveness
// halves the fix must not break, so the three tests below read the same setup
// from three angles rather than three subtly different ones.
func workingEpochFlood(t *testing.T, conn string, send int) (evals int, banned bool, accepted int, budgeted int) {
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

	tip := c.Tip()
	tipEpoch := pow.SeedEpochFor(tip.Height, p)

	for i := 0; i < send; i++ {
		// Height tip.Height+1 lands in the epoch this node's own tip is in
		// (the working epoch), so spendKeyEpoch returns free — this is the
		// working-epoch exemption, the exact hole the non-working
		// key-epoch budget does not cover.
		height := tip.Height + 1
		h := types.Header{
			Version: types.HeaderVersion,
			Height:  height,
			// A parent this node does not hold, and NOT the tip: the
			// difficulty-vs-tip gate only fires when ParentID == tip, so a
			// non-tip parent walks straight past it to the work check.
			ParentID: types.Hash{0xab},
			Time:     tip.Time + p.TargetBlockSeconds,
			// The announcer's own target: at u256.Max no commitment can exceed
			// it, so CheckWork passes and the announcement is accepted with a
			// non-negative score — it accrues no ban.
			Target:   u256.Max,
			CertRoot: certRoot(nil, p),
			PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p)},
		}
		// Distinct every message, so ann.Header.ID() differs and the seen-set
		// dedup read never hits.
		h.PoW.Nonce = uint32(i) | 1<<31
		// The digest of this header's own blob, which is what the work rule now
		// requires. At u256.Max every commitment passes, so the attacker's cost
		// is one evaluation per announcement rather than a search — still cheap
		// enough that the flood this test reproduces is a flood, but no longer
		// literally free. See the note on the property below.
		sealDev(&h, p)

		if i == 0 {
			// Anti-vacuity: the header must reach and pass the work check, and
			// the epoch it selects must be one the node is working in. If either
			// is false every count below measures a refusal rather than the
			// flood.
			if err := pow.CheckWork(pow.Dev{}, h, p); err != nil {
				t.Fatalf("setup: the declared-target header does not pass CheckWork (%v)", err)
			}
			if !workingKeyEpoch(pow.SeedEpochFor(height, p), tipEpoch) {
				t.Fatalf("setup: height %d selects epoch %d, outside the working set around %d; "+
					"this would measure the key-epoch budget, not the working-epoch hole",
					height, pow.SeedEpochFor(height, p), tipEpoch)
			}
		}

		ann := BlockAnnounce{Header: h, CertExemplars: nil}
		v := e.OnBlockAnnounceFrom(conn, conn, ann.MarshalAnnounce())
		if v.Reply != nil {
			accepted++
		}
		if v.Cost == CostBudgeted {
			budgeted++
		}
		if v.Score != 0 {
			peers.Adjust(conn, v.Score)
		}
		if peers.Banned(conn) {
			banned = true
		}
	}
	return work.count(), banned, accepted, budgeted
}

// TestWorkingEpochAnnounceFloodRunsUnchargedRandomX is the reproduction: a
// single unprivileged connection forces one memory-hard RandomX evaluation per
// distinct announcement, in a key epoch this node is working in, with no
// per-connection work charge to terminate it. It fails once a per-connection
// work-evaluation budget caps the flood.
//
// The three gates that make this free are each read off the code in the issue:
// the seen-set dedup read misses on distinct ids; spendKeyEpoch returns free in
// the working epoch (before nodeKeyEpochsExhausted, which exempts it); and the
// difficulty-vs-tip gate is skipped because the parent is not the tip. So the
// work check runs, and nothing scores the connection, so it is never banned.
func TestWorkingEpochAnnounceFloodRunsUnchargedRandomX(t *testing.T) {
	const send = 500
	const conn = "10.66.0.5:5000"

	evals, banned, accepted, budgeted := workingEpochFlood(t, conn, send)
	t.Logf("%d distinct working-epoch announcements from one connection: %d RandomX "+
		"evaluations, %d accepted, %d refused unevaluated, banned=%v",
		send, evals, accepted, budgeted, banned)

	// The property. Before the fix, evals == send (1:1, no ceiling — the whole
	// finding); after it, the per-connection budget caps the burst at
	// MaxWorkEvalsPerConn and the rest are dropped before the work check. The
	// whole flood runs in well under one refill period on the real clock, so no
	// credit comes back inside it and the bound is exact.
	//
	// This assertion is also the mutation check the briefing asks for: revert the
	// spendWorkEval gate ahead of work.Check and evals goes straight back to send
	// (measured: 500), failing here. The bound is stated as the constant rather
	// than a literal so the test cannot drift from the code it measures.
	if evals > MaxWorkEvalsPerConn {
		t.Fatalf("a single connection bought %d RandomX evaluations from %d distinct "+
			"working-epoch announcements, above the per-connection budget of %d. This "+
			"is the CPU-exhaustion face of the unbounded seen-set: uncharged work ahead of the "+
			"seen-set. Each evaluation is a memory-hard hash (15-55 ms under a held "+
			"key), so an unbounded count saturates a core at zero proof-of-work cost.",
			evals, send, MaxWorkEvalsPerConn)
	}
	// And below it, which stops the test drifting into measuring some cheaper
	// refusal wearing this one's name: every one of the budgeted burst really can
	// be spent on an evaluation, so a count under the budget means something
	// refused these ahead of the work check and this no longer reproduces the flood.
	if evals != MaxWorkEvalsPerConn {
		t.Fatalf("a single connection bought only %d evaluations against a reachable "+
			"budget of %d; something now refuses these before the work budget does, "+
			"so this test measures that instead of the flood under test", evals, MaxWorkEvalsPerConn)
	}
	// The rest are dropped unevaluated, and exactly the accepted ones are the
	// ones that ran the work check.
	if accepted != MaxWorkEvalsPerConn || budgeted != send-MaxWorkEvalsPerConn {
		t.Fatalf("%d accepted and %d dropped, want %d accepted and %d dropped: the "+
			"budget admits exactly its burst and drops the rest",
			accepted, budgeted, MaxWorkEvalsPerConn, send-MaxWorkEvalsPerConn)
	}
	// The drop is a price, not a judgement: a CostBudgeted refusal carries no
	// score, so the flooding connection is never banned. Banning here would be
	// the I7-H4 tip-window failure — a node behind the chain receives many
	// announcements from the honest peers it depends on.
	if banned {
		t.Fatal("the flooding connection was banned; the work budget is a price, and " +
			"scoring on top of it turns a price into the ban I7-H4 reverted")
	}
}
