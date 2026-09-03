package p2p_test

import (
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/p2p"
)

// TestAppearingInTheCandidateSetDoesNotPreemptTheRotation.
//
// The property, in one sentence: **a peer that has only just appeared MUST NOT
// be selected ahead of a peer the rotation has gone longer without asking.**
//
// Sync candidacy through PeerTip.OffersUnknown costs one hash: the announce
// path checks work against the header's own declared target, and re-deriving
// the real target needs the ancestors that hash-first relay exists to avoid
// fetching (R4-H1). The issue scores the impact as rotation *dilution* — an
// attacker holding a share of the candidate set takes that share of the rounds
// — and that is the right description of the steady state.
//
// It was not the right description of the transient. NextSyncPeer read the zero
// time for a rotation key it did not know, so "never tried" sorted ahead of
// every peer that had been. A rotation key is not scarce — it is the advertised
// address, or the connection address for a peer that cannot be dialled —
// and the prune drops the memory of any key that stops being a candidate. So a
// peer that keeps appearing under a fresh key was never-tried on every round
// and took the front of the rotation on every round, at the price of one hash.
//
// Two scenarios, because the guard has two things to separate:
//
//   - offers-unknown: the newcomer's candidacy comes only through a forged
//     MaxTarget announcement, which is the cheap-candidacy shape exactly.
//   - highest-claim: the newcomer also claims the largest height of anyone, so
//     the `tried.Equal(bestTried) && c.Height > best.Height` tie-break points at
//     the newcomer. Only the stamp ordering can exclude it, which is what makes
//     this scenario the separating input for the fix rather than for the
//     tie-break that was already there.
func TestAppearingInTheCandidateSetDoesNotPreemptTheRotation(t *testing.T) {
	for _, sc := range []struct {
		name string
		// offersUnknownOnly builds a newcomer that is a candidate solely
		// because of an announcement it cannot be made to pay for.
		offersUnknownOnly bool
	}{
		{name: "offers-unknown", offersUnknownOnly: true},
		{name: "highest-claim", offersUnknownOnly: false},
	} {
		t.Run(sc.name, func(t *testing.T) {
			p := devnetEasy()
			victim := newNode(t, "victim", p, key(t, 1).Persistent())
			victim.mine(t, 4)
			tip := victim.chain.Tip()

			hello := func(listen string, height uint64, work u256.U256) []byte {
				return p2p.Hello{
					Protocol:   p2p.ProtocolVersion,
					NetworkID:  victim.chain.NetworkID(),
					Height:     height,
					Work:       work.Bytes(),
					ListenAddr: listen,
				}.MarshalHello()
			}

			// Two honest peers, plainly ahead, each on its own connection.
			honest := map[string]bool{"10.1.0.1:9421": true, "10.2.0.1:9421": true}
			i := 0
			for addr := range honest {
				victim.peers.Add(addr)
				victim.engine.Handle("conn:honest:"+itoa(i), p2p.KindHello,
					hello(addr, tip.Height+8, u256.FromUint64(1<<20)))
				i++
			}

			// Establish the rotation: every honest peer is asked once, so every
			// one of them carries a stamp. Without this there is nothing for a
			// newcomer to preempt and the test would assert nothing.
			for round := 0; round < len(honest); round++ {
				peer, ok := victim.node.NextSyncPeer()
				if !ok {
					t.Fatalf("round %d: no candidate at all", round)
				}
				if !honest[peer.SyncKeyForTest()] {
					t.Fatalf("round %d: selected %q, which is not one of the two "+
						"honest peers — the setup is not what this test assumes",
						round, peer.SyncKeyForTest())
				}
				victim.node.MarkSyncTried(peer.SyncKeyForTest())
			}

			// The newcomer appears: a fresh connection under a fresh advertised
			// address, which is a rotation key this node has never seen.
			const conn, listen = "203.0.113.7:51000", "203.0.113.7:9500"
			victim.peers.Add(listen)
			claimed := uint64(1) << 30
			work := u256.FromUint64(1 << 40)
			if sc.offersUnknownOnly {
				// Strictly behind on both claims the handshake carries, so
				// nothing but the announcement can make this a candidate.
				claimed, work = tip.Height-1, u256.One
			}
			victim.engine.Handle(conn, p2p.KindHello, hello(listen, claimed, work))

			if sc.offersUnknownOnly {
				for _, c := range victim.engine.SyncCandidates() {
					if c.Dial == listen {
						t.Fatal("the newcomer is already a candidate on its " +
							"handshake claims, so the announcement below is not " +
							"what makes it one")
					}
				}
				// A header nobody paid for: MaxTarget is its own declared
				// target, and that is what the announce path checks it against
				// (R4-H1). Sibling of the victim's tip, so it cannot be placed.
				ghost := types.Header{
					Version:      types.HeaderVersion,
					Height:       tip.Height,
					ParentID:     tip.ParentID,
					Time:         tip.Time,
					EmissionAddr: key(t, 9).Persistent(),
					Target:       p.MaxTarget,
				}
				ghost.PoW.Nonce = 1 << 31
				blk := &types.Block{Header: ghost}
				blk.Header.CertRoot = blk.ComputeCertRoot(p)
				ann := p2p.BlockAnnounce{Header: blk.Header}
				if v := victim.engine.Handle(conn, p2p.KindBlockAnnounce, ann.MarshalAnnounce()); v.Err != nil {
					t.Fatalf("the forged announcement was refused (%v), so this "+
						"test would pass for a benign reason", v.Err)
				}
			}

			// Non-vacuity: the newcomer must really be in the candidate set. A
			// peer that is not a candidate cannot preempt anything, and a test
			// that reached this line with an empty attack would pass while
			// measuring nothing.
			var present bool
			for _, c := range victim.engine.SyncCandidates() {
				if c.Dial == listen {
					present = true
				}
			}
			if !present {
				t.Fatal("the newcomer is not a sync candidate, so this test does " +
					"not exercise the rotation at all")
			}

			peer, ok := victim.node.NextSyncPeer()
			if !ok {
				t.Fatal("no candidate after the newcomer appeared")
			}
			if !honest[peer.SyncKeyForTest()] {
				t.Fatalf("the round after a fresh identity appeared went to %q "+
					"rather than to one of the two peers already in the "+
					"rotation. Appearing preempts, so the front of the rotation "+
					"costs exactly what candidacy costs, which is one "+
					"hash.", peer.SyncKeyForTest())
			}
		})
	}
}

// TestCandidatesFirstSeenOnOneRoundShareOnePlaceInTheRotation pins the half of
// the fix that the preemption test does not reach.
//
// The property: **candidates first seen on the same round are placed at the
// back *together*, so claimed height still decides between them** — which is
// what §4 of docs/adversarial/sync.md means by height breaking ties among
// equally-stale candidates, and what makes the first round of a fresh node
// start exactly where it did before the fix.
//
// This is a separate claim from "a newcomer does not preempt", and it is the
// one that says *how* newcomers are ordered against each other rather than
// against incumbents. Numbering each new candidate individually satisfies
// preemption just as well and breaks this: SyncCandidates ranges over the
// e.tips map, so per-candidate numbering hands first-round order to Go's
// randomised map iteration instead of to the claimed height the policy names.
// The seeding loop's shared sequence number was credited in the code comment,
// in docs/adversarial/sync.md §6.1 and in the PR body, and pinned by nothing;
// a mutant replacing it with a per-candidate increment survived the entire
// rotation and candidacy suite.
//
// Map iteration order is randomised per range, so one observation proves
// nothing: this measures a **rate** over independent rounds, each on a fresh
// node. With per-candidate numbering the winner is whichever candidate the map
// yielded first — uniform over the eight — so a single round would survive the
// mutant 1 time in 8, and the reported denominator is what makes the check
// capable of coming back negative.
func TestCandidatesFirstSeenOnOneRoundShareOnePlaceInTheRotation(t *testing.T) {
	const (
		peers  = 8
		rounds = 20
	)
	p := devnetEasy()

	// The highest claim is deliberately not the first address, the last
	// address, or the one that sorts first or last by string — so no ordering
	// this node could accidentally be using coincides with the right answer.
	heights := []uint64{3, 7, 1, 9, 2, 12, 5, 4} // the maximum, 12, is at index 5
	want := "10.0.0.6:9421"

	var correct int
	var picked = map[string]int{}
	for round := 0; round < rounds; round++ {
		victim := newNode(t, "victim", p, key(t, 1).Persistent())
		for i, h := range heights {
			addr := "10.0.0." + itoa(i+1) + ":9421"
			victim.peers.Add(addr)
			victim.engine.Handle("conn:"+itoa(i), p2p.KindHello, p2p.Hello{
				Protocol:   p2p.ProtocolVersion,
				NetworkID:  victim.chain.NetworkID(),
				Height:     h,
				Work:       u256.FromUint64(h).Bytes(),
				ListenAddr: addr,
			}.MarshalHello())
		}
		// Non-vacuity: every peer must really be a candidate, or the round is
		// choosing from a smaller set than this test claims it is.
		if got := len(victim.engine.SyncCandidates()); got != peers {
			t.Fatalf("round %d: %d candidates, want %d — the setup is not what "+
				"this test measures", round, got, peers)
		}
		peer, ok := victim.node.NextSyncPeer()
		if !ok {
			t.Fatalf("round %d: no candidate at all", round)
		}
		picked[peer.SyncKeyForTest()]++
		if peer.SyncKeyForTest() == want {
			correct++
		}
	}

	if correct != rounds {
		t.Fatalf("the highest-claiming candidate won %d of %d first rounds, want "+
			"%d (selections: %v). Candidates first seen on one round are not "+
			"sharing one place in the rotation, so first-round order is decided "+
			"by map iteration rather than by claimed height.",
			correct, rounds, rounds, picked)
	}
	t.Logf("the highest-claiming candidate won %d/%d first rounds over %d "+
		"candidates (a per-candidate sequence number would win ~%d/%d)",
		correct, rounds, peers, rounds/peers, rounds)
}
