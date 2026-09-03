package p2p_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/p2p"
)

// TestTheFreeKeyEpochsFollowThisNodesOwnTip separates the one term of the
// key-epoch price that had no input separating it: whose tip decides which key
// epochs are free.
//
// `spendKeyEpoch` exempts `workingKeyEpoch(epoch, pow.SeedEpochFor(chain
// height))`, and every other test of that price runs against a chain at
// genesis, where that expression is zero. So the whole suite could not tell the
// node's own tip epoch from the constant 0 — replacing the argument with 0
// leaves every one of them passing. That is not a small gap: if the exempt set
// were pinned at epoch 0 rather than following the tip, every honest
// announcement a running node ever receives would fall outside it, the budget
// would drain against the peers it depends on, and the price would have become
// the refusal that reverted I7-H4's tip-window guard.
//
// It is in the external test package because separating the term needs a chain
// past a key boundary and this package already has the miner that produces one
// — the same one TestCatchingUpDoesNotBanTheHonestPeersItDependsOn uses, at
// the same cost. With the tip in epoch >= 2 the free set {own, own+1} is
// disjoint from {0, 1}, so the two rows below own are also reachable through
// OnBlockAnnounce for the first time rather than only through the predicate.
func TestTheFreeKeyEpochsFollowThisNodesOwnTip(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "victim", p, key(t, 1).Persistent())

	// Past the second key boundary, so `own` is at least 2 and every row below
	// is a genuine epoch rather than an underflow.
	blocks := n.mine(t, int(2*p.RandomXKeyInterval+p.RandomXKeyLag+8))
	own := pow.SeedEpochFor(n.chain.Height(), p)
	if own < 2 {
		t.Fatalf("setup: the node's tip is in key epoch %d at height %d; the "+
			"whole point of this test is a tip epoch that is neither 0 nor 1, "+
			"and nothing below separates anything without one", own, n.chain.Height())
	}

	// An empty block's own CertRoot is the root of an empty exemplar list, and
	// that is what the announcements below carry. Taken from the miner rather
	// than recomputed, because the unexported helper that computes it is not
	// reachable from here and a second implementation of it would be a second
	// thing to get wrong.
	tip := blocks[len(blocks)-1]
	if len(tip.CertExemplars()) != 0 {
		t.Fatalf("setup: the mined tip carries %d certificates, so its CertRoot "+
			"is not the empty root the announcements below claim",
			len(tip.CertExemplars()))
	}
	emptyRoot := tip.Header.CertRoot

	announce := func(peer string, epoch, nonce uint64) p2p.Verdict {
		t.Helper()
		height := p.RandomXKeyLag + epoch*p.RandomXKeyInterval
		hd := types.Header{
			Version:  types.HeaderVersion,
			Height:   height,
			ParentID: tip.Header.ID(),
			Time:     tip.Header.Time,
			Target:   u256.Max,
			CertRoot: emptyRoot,
			PoW:      types.PoWSeal{Nonce: uint32(nonce) | 1<<31, SeedEpoch: pow.SeedEpochFor(height, p)},
		}
		// Anti-vacuity: a header that the work check refuses would be refused
		// below for a reason that is not the budget's.
		if err := pow.CheckWork(pow.Dev{}, hd, p); err != nil {
			t.Fatalf("setup: header at epoch %d does not pass CheckWork (%v)", epoch, err)
		}
		if got := pow.SeedEpochFor(height, p); got != epoch {
			t.Fatalf("setup: height %d is in key epoch %d, not %d", height, got, epoch)
		}
		return n.engine.OnBlockAnnounce(peer, p2p.BlockAnnounce{Header: hd}.MarshalAnnounce())
	}

	const peer = "10.71.0.1:5000"
	// Drain the budget somewhere far from the tip, so that everything after
	// this is decided by the exempt set and by nothing else.
	for i := 0; i < p2p.MaxUnheldKeyEpochsPerPeer; i++ {
		if v := announce(peer, own+100+uint64(i), uint64(i)); v.Cost == p2p.CostBudgeted {
			t.Fatalf("setup: message %d was refused before the budget was spent", i)
		}
	}
	if v := announce(peer, own+200, 900); v.Cost != p2p.CostBudgeted {
		t.Fatalf("setup: the budget is not spent after %d messages, so a free "+
			"row below would prove nothing", p2p.MaxUnheldKeyEpochsPerPeer)
	}

	for _, row := range []struct {
		name  string
		epoch uint64
		free  bool
	}{
		{"the tip's own epoch", own, true},
		{"the epoch after the tip's", own + 1, true},
		{"the epoch after that", own + 2, false},
		{"the epoch below the tip's", own - 1, false},
		{"epoch zero", 0, false},
	} {
		v := announce(peer, row.epoch, 1000+row.epoch)
		// "Not budgeted" is only evidence of a free epoch if the message was
		// otherwise judged. A row answered from the seen-set, or refused for
		// some other reason, is not budgeted either, and reading that as free
		// is how a table like this reports a term it never exercised.
		if row.free && v.Cost != p2p.CostScored {
			t.Errorf("%s (epoch %d) was priced %v rather than judged (%v); this "+
				"row proves nothing about the exempt set", row.name, row.epoch, v.Cost, v.Err)
			continue
		}
		budgeted := v.Cost == p2p.CostBudgeted
		if budgeted == row.free {
			verb := "charged against the spent budget"
			if !budgeted {
				verb = "free"
			}
			t.Errorf("%s (epoch %d, tip epoch %d) was %s; the exempt set is "+
				"{own, own+1} and it must follow this node's tip rather than "+
				"sitting at a fixed epoch", row.name, row.epoch, own, verb)
		}
	}
}

// TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget is
// the liveness property this price had to keep, driven at the point where it is
// actually at risk.
//
// TestCatchingUpDoesNotBanTheHonestPeersItDependsOn is the pin the fix inherited
// and it passes — but it sends ONE announcement, which spends one credit of
// MaxUnheldKeyEpochsPerPeer, so it never reaches the state this budget creates.
// The guard whose revert this price exists to avoid (I7-H4's tip window) failed
// exactly there: a node far behind, acting on announcements far ahead. So the
// case has to be a node whose budget is EMPTY and whose only source of progress
// is the peers it just stopped paying for.
//
// Ordinary gossip, not a flood: the source mines, announces each block once, and
// every announcement is honest and well-formed. The node is more than one key
// epoch behind, so every one of them names an epoch outside {own, own+1} and
// costs a credit. That is the regime, and the numbers it produces are logged
// rather than asserted, because they are properties of the parameter set.
//
// What is asserted is the four things a node in a long catch-up cannot lose.
func TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	source := newNode(t, "source", p, key(t, 2).Persistent())

	// Three key epochs ahead of a victim still at genesis, so nothing the
	// source announces is in {own, own+1} and the exemption cannot explain a
	// pass.
	blocks := source.mine(t, int(3*p.RandomXKeyInterval+p.RandomXKeyLag+4))
	own := pow.SeedEpochFor(victim.chain.Height(), p)
	ahead := pow.SeedEpochFor(source.chain.Height(), p)
	if own != 0 || ahead < own+2 {
		t.Fatalf("setup: victim is in key epoch %d and source in %d; the source "+
			"has to be at least two epochs ahead or every announcement below is "+
			"free by the exemption rather than by the budget", own, ahead)
	}

	const peer = "10.72.0.1:9421"
	victim.peers.Add(peer)
	handshake(t, victim, peer)
	before := scoreOf(t, victim, peer)

	// The last 40 blocks the source mined, announced one at a time exactly as
	// gossip would.
	tail := blocks[len(blocks)-40:]
	admitted, refused, firstRefusal := 0, 0, -1
	for i, b := range tail {
		ann := p2p.BlockAnnounce{Header: b.Header, CertExemplars: b.CertExemplars()}
		v := victim.engine.Handle(peer, p2p.KindBlockAnnounce, ann.MarshalAnnounce())
		switch v.Cost {
		case p2p.CostBudgeted:
			refused++
			if firstRefusal < 0 {
				firstRefusal = i
			}
		default:
			admitted++
		}
	}
	t.Logf("of %d ordinary honest announcements %d were admitted and %d refused "+
		"unevaluated, first refusal at message %d; honest demand is one credit "+
		"per %d s against a refill of one per %d s — a factor of %d "+
		"(randomx_key_interval)", len(tail), admitted, refused, firstRefusal,
		p.TargetBlockSeconds, p.RandomXKeyInterval*p.TargetBlockSeconds, p.RandomXKeyInterval)

	// Asserted and not only logged, because these two numbers are published:
	// the accepted cost in the PR quotes both the 87.5%% refusal rate and the
	// message the first refusal lands on, and an instrument that logs a figure
	// it does not assert cannot be the evidence for it. Measured: with the
	// budget comparison weakened so that nothing is ever admitted, `refused >
	// 0` alone still passes.
	if refused == 0 {
		t.Fatal("no honest announcement was refused, so the budget was never " +
			"exhausted and nothing below is a test of the exhausted state")
	}
	if admitted != p2p.MaxUnheldKeyEpochsPerPeer || firstRefusal != p2p.MaxUnheldKeyEpochsPerPeer {
		t.Errorf("%d admitted with the first refusal at message %d, want %d and "+
			"%d: an honest peer far ahead gets exactly the budget and not one "+
			"message more, and the refusal rate this test is quoted for is "+
			"(%d-%d)/%d", admitted, firstRefusal, p2p.MaxUnheldKeyEpochsPerPeer,
			p2p.MaxUnheldKeyEpochsPerPeer, len(tail), p2p.MaxUnheldKeyEpochsPerPeer, len(tail))
	}

	// 1. The peers a node needs to climb back are not penalised for being ahead.
	if after := scoreOf(t, victim, peer); after < before {
		t.Errorf("an honest peer lost %d points (%d -> %d) for announcing blocks "+
			"this node is behind on; that is the failure that reverted I7-H4's "+
			"tip-window guard", before-after, before, after)
	}
	// 2. And are not banned, which also removes them from candidacy (R5).
	if victim.peers.Banned(peer) {
		t.Fatal("a node catching up banned the honest peer feeding it")
	}
	// 3. The sync driver still knows how far ahead it is. This is the half that
	// makes the refusal a price rather than a refusal to APPLY: recordAnnounce
	// runs on the over-budget path for exactly this.
	var tip p2p.PeerTip
	for _, c := range victim.engine.SyncCandidates() {
		if c.Conn == peer {
			tip = c
		}
	}
	if tip.Conn != peer {
		t.Fatalf("with its budget spent the node dropped the only peer ahead of " +
			"it from SyncCandidates(); catch-up has no source left")
	}
	// 4. And knows it exactly, not as of the last credit it could pay for.
	if want := source.chain.Height(); tip.Height != want {
		t.Errorf("the peer's recorded height is %d, want %d: the record stopped "+
			"tracking when the budget ran out, so the node would ask for a tip "+
			"that is no longer the tip", tip.Height, want)
	}
}
