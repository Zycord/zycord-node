package p2p_test

import (
	"testing"
	"time"

	"zycord/core/u256"
	"zycord/node/p2p"
)

// TestALapsedCandidateKeepsItsPlaceWhileItsConnectionIsUp pins the rotation's
// liveness set.
//
// The property, in one sentence: **a peer whose candidacy lapses while its
// connection stays up keeps its position in the rotation, so the wait before it
// is served is bounded by the cycle length and not restarted by the lapse.**
//
// The rotation places a first-seen candidate at the back so that appearing cannot
// preempt a peer that has waited longer. Seeding fires for any rotation key
// absent from the map, and the prune deliberately dropped every key that
// stopped being a candidate, so the two composed: a peer that lapsed out of
// candidacy and returned was seeded again and went to the back on every
// re-entry. For a peer ahead by height or claimed work that happens once ever.
// For one whose candidacy rests on OffersUnknown alone it happened once per
// lapse, and it was bounded only while a whole cycle fitted inside the window:
//
//	len(candidates) * SyncInterval <= offersUnknownWindow
//
// This test drives that inequality across its own boundary. The lapser is
// served at round len(candidates)-1, because a peer seeded at the back waits
// for every other candidate to take a turn, and it is present for
// offersUnknownWindow/SyncInterval + 1 rounds of each period. So the boundary
// is an integer, and the two sides of it are full service and no service --
// which is why the sizes below straddle it rather than sampling one regime.
//
// The bound asserted is derived rather than fitted: once the peer holds the
// lowest sequence number it is selected on the first round it is present, and
// it reaches the lowest sequence number after at most every other candidate has
// been served once. So the longest gap between services is at most one cycle
// plus one duty cycle, len(candidates) + period rounds, whatever the constants
// are. Before the fix the gap is not merely larger, it is unbounded: past the
// boundary the peer is never selected at all.
func TestALapsedCandidateKeepsItsPlaceWhileItsConnectionIsUp(t *testing.T) {
	// The lapse period in rounds. Longer than the live window, so the peer is
	// genuinely absent for part of every period -- which is the state the prune
	// used to forget it in.
	const period = 24

	for _, incumbents := range []int{4, 8, 9, 10, 11, 12, 20, 40} {
		t.Run("incumbents="+itoa(incumbents), func(t *testing.T) {
			const rounds = 330

			p := devnetEasy()
			victim := newNode(t, "victim", p, key(t, 1).Persistent())
			victim.mine(t, 4)
			own := victim.chain.Tip().Height
			interval := victim.node.SyncInterval

			hello := func(listen string, height uint64, work u256.U256) []byte {
				return p2p.Hello{
					Protocol:   p2p.ProtocolVersion,
					NetworkID:  victim.chain.NetworkID(),
					Height:     height,
					Work:       work.Bytes(),
					ListenAddr: listen,
				}.MarshalHello()
			}

			// Incumbents are ahead by height, so they are candidates on every
			// round for ever and never lapse. They are what makes the cycle
			// long.
			for i := 0; i < incumbents; i++ {
				addr := "10.0.0." + itoa(i+1) + ":9421"
				victim.peers.Add(addr)
				victim.engine.Handle("conn:in:"+itoa(i), p2p.KindHello,
					hello(addr, own+8, u256.FromUint64(1<<20)))
			}

			// The lapser is behind on both claims the handshake carries, so
			// nothing but a fresh OffersUnknown stamp can make it a candidate.
			// That is exactly the population the prune's liveness set is
			// about, and it is also the fork holder: a shorter-but-heavier side branch.
			const lapseConn, lapseAddr = "203.0.113.9:51000", "203.0.113.9:9500"
			victim.peers.Add(lapseAddr)
			victim.engine.Handle(lapseConn, p2p.KindHello,
				hello(lapseAddr, own-1, u256.One))

			isCandidate := func() bool {
				for _, c := range victim.engine.SyncCandidates() {
					if c.SyncKeyForTest() == lapseAddr {
						return true
					}
				}
				return false
			}

			var served, presentRounds, absentRounds int
			lastServed := -1
			worstGap := 0
			for r := 0; r < rounds; r++ {
				// Gossip refreshes the stamp at the top of each period and
				// nothing refreshes it afterwards, so its age across the period
				// is what the passage of time would make it.
				//
				// The extra nanosecond is not a fudge, and it moves the measured
				// boundary by a whole integer. SyncCandidates tests staleness
				// with a strict `>`, and real elapsed time never lands on an
				// exact multiple of SyncInterval, so a real peer at exactly
				// offersUnknownWindow of age is stale. Ageing by an exact
				// multiple leaves that to the clock's granularity instead: where
				// time.Since(time.Now().Add(-d)) returns exactly d, the
				// comparison reads "not stale" and the peer gets one live round
				// more than wall clock would give it, which puts the cliff at 11
				// rather than the 10 the derivation and §6.1 of
				// docs/adversarial/sync.md pin.
				victim.engine.LapseCandidacyForTest(lapseConn,
					time.Duration(r%period)*interval+time.Nanosecond)

				if isCandidate() {
					presentRounds++
				} else {
					absentRounds++
				}

				peer, ok := victim.node.NextSyncPeer()
				if !ok {
					t.Fatalf("round %d: no candidate at all, so this round "+
						"measures nothing", r)
				}
				victim.node.MarkSyncTried(peer.SyncKeyForTest())
				if peer.SyncKeyForTest() != lapseAddr {
					continue
				}
				served++
				if lastServed >= 0 && r-lastServed > worstGap {
					worstGap = r - lastServed
				}
				lastServed = r
			}

			// Non-vacuity, both halves. A run in which the peer never lapsed
			// would pass while measuring nothing, and so would one in which it
			// was never a candidate at all: the first makes the fix irrelevant,
			// the second makes service impossible for a benign reason.
			if presentRounds == 0 {
				t.Fatalf("the lapser was never a candidate in %d rounds, so "+
					"this test cannot distinguish the fix from starvation",
					rounds)
			}
			if absentRounds == 0 {
				t.Fatalf("the lapser never lapsed in %d rounds, so the prune "+
					"this test exists to exercise never dropped it", rounds)
			}

			// The derived bound: at most one cycle plus one duty cycle. The
			// cycle is every candidate, which is the incumbents plus the
			// lapser itself.
			maxGap := incumbents + 1 + period
			t.Logf("incumbents=%d served=%d/%d rounds (present %d, absent %d), "+
				"worst gap %d rounds, bound %d",
				incumbents, served, rounds, presentRounds, absentRounds,
				worstGap, maxGap)

			if served == 0 {
				t.Fatalf("the lapser was served 0 times in %d rounds against %d "+
					"incumbents. A cycle of %d rounds does not fit inside the "+
					"rounds per period it is present for, so it never reaches "+
					"the front before lapsing and is re-seeded to the back on "+
					"return: starved permanently rather than delayed.",
					rounds, incumbents, incumbents+1)
			}
			if worstGap > maxGap {
				t.Fatalf("the lapser waited %d rounds between services against "+
					"%d incumbents, past the %d-round bound (one cycle plus one "+
					"lapse period). The lapse is costing it position rather "+
					"than only the rounds it is absent for.",
					worstGap, incumbents, maxGap)
			}
		})
	}
}

// TestADisconnectedPeerLosesItsPlaceInTheRotation is the converse of that
// rule, and it is what makes the memory bound a bound rather than a promise.
//
// The property: **the rotation remembers a position for exactly as long as the
// peer holds a connection, and not one round longer.** Retaining across a lapse
// is only safe because the retention is bounded by something admission already
// prices. A fix that retained across a *disconnect* would be the unbounded
// growth docs/adversarial/sync.md section 4 was written to prevent, and it
// would pass the lapse test above identically -- so that test alone cannot
// separate the two, and this one is not a duplicate of it.
func TestADisconnectedPeerLosesItsPlaceInTheRotation(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 4)
	own := victim.chain.Tip().Height

	hello := func(listen string, height uint64) []byte {
		return p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     height,
			Work:       u256.FromUint64(height).Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	const (
		aConn, aAddr = "conn:a", "10.0.0.1:9421"
		bConn, bAddr = "conn:b", "10.0.0.2:9421"
	)
	victim.peers.Add(aAddr)
	victim.peers.Add(bAddr)
	// b claims more, so a selection that ignored position entirely would point
	// at b through the height tie-break and this test would pass for the wrong
	// reason. It does not: after the establishing rounds the two carry
	// different stamps, and the stamp is what decides.
	victim.engine.Handle(aConn, p2p.KindHello, hello(aAddr, own+8))
	victim.engine.Handle(bConn, p2p.KindHello, hello(bAddr, own+9))

	// Establish the rotation: b first (it claims more and both are fresh), then
	// a. So b is now the peer gone longest without being asked.
	for round := 0; round < 2; round++ {
		peer, ok := victim.node.NextSyncPeer()
		if !ok {
			t.Fatalf("round %d: no candidate at all", round)
		}
		victim.node.MarkSyncTried(peer.SyncKeyForTest())
	}
	peer, ok := victim.node.NextSyncPeer()
	if !ok || peer.SyncKeyForTest() != bAddr {
		t.Fatalf("after two rounds the front of the rotation is ok=%v key=%q, "+
			"want %q -- the setup is not what this test assumes",
			ok, peer.SyncKeyForTest(), bAddr)
	}

	// b disconnects and comes straight back on a fresh socket under the same
	// advertised address, which is a stable rotation key by construction.
	victim.engine.ForgetPeerForTest(bConn)
	if n := victim.node.SyncRotationSizeForTest(); n != 2 {
		t.Fatalf("the rotation holds %d keys before the next selection, want 2 "+
			"-- nothing has pruned yet, so this pins the starting state", n)
	}
	if _, ok := victim.node.NextSyncPeer(); !ok {
		t.Fatal("no candidate after b disconnected")
	}
	if n := victim.node.SyncRotationSizeForTest(); n != 1 {
		t.Fatalf("the rotation holds %d keys after b's tip was dropped, want 1. "+
			"Memory is being retained for a peer this node no longer holds a "+
			"connection to, which is the unbounded growth the prune exists to "+
			"prevent (section 4).", n)
	}

	victim.engine.Handle("conn:b2", p2p.KindHello, hello(bAddr, own+9))
	peer, ok = victim.node.NextSyncPeer()
	if !ok {
		t.Fatal("no candidate after b reconnected")
	}
	if peer.SyncKeyForTest() != aAddr {
		t.Fatalf("the round after b reconnected went to %q, want %q. A peer "+
			"that returns on a new connection must re-enter at the back: "+
			"it is the connection, not the candidacy, that bounds how "+
			"long a position is remembered.", peer.SyncKeyForTest(), aAddr)
	}
}

// TestTheRotationRemembersNoMoreKeysThanTheNodeHoldsTips pins the bound itself.
//
// The property: **len(syncTried) <= len(Engine.tips) after every selection**,
// where Engine.tips is the snapshot that selection read. The scope is part of
// the property rather than a caveat on it, and the paragraphs below say why.
// That is what replaces the candidate-set bound, and it is the whole reason
// retaining across a lapse does not reintroduce unbounded growth: a rotation
// key requires a tip, a tip requires a connection admission has already
// counted, and forgetPeer drops it on the one teardown a connection has.
//
// Driven by churn rather than by a steady set, because the growth section 4
// feared is a function of how many addresses have ever been seen and not of how
// many are live at once.
//
// What it does NOT separate: it drives NextSyncPeer from one goroutine, so the
// candidate list and the prune's liveness set see the same tips whether they
// are read under one acquisition of e.mu or two, and no single-threaded test in
// this package can tell one read from two. That half is established by
// construction and pinned only at the seam, by the test below. What the single
// acquisition buys is that syncTried is a subset of THE SNAPSHOT the selection
// read; it orders two reads against each other and not either of them against a
// third goroutine.
//
// Against the LIVE map the bound is not an at-rest one, and quiescence does not
// close the gap. The prune is LAZY: it runs only inside NextSyncPeer, and only
// on the path that HAS a candidate, since the empty-candidate early return
// leaves before n.mu and before the prune. So an ordinary sequential teardown
// exhibits it on one goroutine with nothing racing anything, and it lasts until
// the next selection that has a candidate rather than merely until the next
// selection. Driven single-threaded: three candidates and one selection give
// keys=3 tips=3; two ForgetPeer calls with no further selection give keys=3
// tips=1; fifty consecutive selections with every peer gone still give keys=3
// tips=0; one selection that has a candidate restores keys=1 tips=1, which is
// what shows the cause is the prune's per-selection cadence rather than the
// teardown itself. The two tests after this one pin that residual and the
// population it reaches.
//
// It does not rest on unregister's lock order, and the counterfactual is why:
// were unregister to hold n.mu across both of its statements, NextSyncPeer --
// which takes its snapshot before n.mu -- would simply block there, forgetPeer
// would run inside the hold, and the prune would still proceed against a stale
// set. Same window, same outcome. Closing it needs e.mu held across the prune,
// which nests the node's lock inside the engine's; this path deliberately does
// not do that (see the comment at the syncRotationView call site). That remedy
// is named and NOT priced -- nobody has enumerated Node.mu's acquisition sites
// for the reverse nesting -- so it describes what a fix would create and is not
// a claim that it would be safe. It is a residual at the FIRST link of section
// 4's chain, and a different one from the middle link's, which is an undriven
// ordering question inside unregister's own n.mu gap. Nothing is claimed either
// way about that one, and the race detector is not the instrument that would
// settle it -- for two reasons, and the second is the structural one.
//
// It is undriven: every test in this file runs on one goroutine, so there is no
// interleaving for any instrument to observe. And even driven, the question is
// not a data race. Both sides of the gap are already under a mutex -- retire
// deletes from n.conns under n.mu and releases it before calling forgetPeer,
// which takes e.mu to drop the tip -- so what is open is the staleness between
// two separately-locked sections, and unsynchronised access is the only thing a
// happens-before detector reports. Settling it needs a test that drives
// unregister against NextSyncPeer concurrently and asserts on the resulting
// key set, not a build flag. (An earlier note here said -race needs cgo and
// this machine has no C toolchain; that was false and is retracted.)
//
// The 48 is unaffected, and the reason is a mechanism rather than a qualifier:
// the seeding loop is ALSO below the empty-candidate early return, so while
// there is no candidate nothing is added either. syncTried is frozen, not
// growing -- it holds whatever the last non-empty selection left, and that
// snapshot was bounded by the admission caps. Unbounded in time is not
// unbounded in size.
//
// Between selections the size also needs MarkSyncTried to rewrite only a key
// the snapshot already held, and that is a fact about the ONE non-test caller
// it has today rather than a structural guarantee. MarkSyncTried is exported
// and takes an arbitrary addr, so a second production caller passing a key with
// no tip would falsify the between-selections half while leaving the
// per-selection bound above intact. That makes the call-graph residual
// load-bearing here rather than merely informational.
func TestTheRotationRemembersNoMoreKeysThanTheNodeHoldsTips(t *testing.T) {
	const churn = 200

	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 4)
	own := victim.chain.Tip().Height

	hello := func(listen string, height uint64) []byte {
		return p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     height,
			Work:       u256.FromUint64(1 << 20).Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	// One peer that never goes away, so the node always has a candidate and no
	// round is skipped for a benign reason.
	const anchor = "10.9.9.9:9421"
	victim.peers.Add(anchor)
	victim.engine.Handle("conn:anchor", p2p.KindHello, hello(anchor, own+8))

	var peak int
	check := func(i int, when string) {
		t.Helper()
		keys := victim.node.SyncRotationSizeForTest()
		tips := victim.engine.SyncTipCountForTest()
		if keys > peak {
			peak = keys
		}
		if keys > tips {
			t.Fatalf("churn %d, %s: the rotation holds %d keys against %d "+
				"tips. The memory is no longer bounded by the connection set, "+
				"which is the only thing that makes retaining across a lapse "+
				"safe.", i, when, keys, tips)
		}
	}

	for i := 0; i < churn; i++ {
		conn := "conn:churn:" + itoa(i)
		addr := "198.51.100." + itoa(i%254+1) + ":" + itoa(20000+i)
		victim.peers.Add(addr)
		victim.engine.Handle(conn, p2p.KindHello, hello(addr, own+8))

		peer, ok := victim.node.NextSyncPeer()
		if !ok {
			t.Fatalf("churn %d: no candidate at all", i)
		}
		victim.node.MarkSyncTried(peer.SyncKeyForTest())

		// Measured while the churned peer is still connected as well as after
		// it leaves. Only the first point can ever exceed one key, so a check
		// taken only after the teardown would compare one against one for two
		// hundred rounds and could not come back dirty.
		check(i, "while connected")

		// The connection dies immediately, which is the cheapest thing an
		// address this node has never dialled can do.
		victim.engine.ForgetPeerForTest(conn)

		if _, ok := victim.node.NextSyncPeer(); !ok {
			t.Fatalf("churn %d: no candidate after the churned peer left", i)
		}
		check(i, "after the teardown")
	}

	// Non-vacuity: a run whose peak never rose above the anchor alone would
	// satisfy the bound without a churned key ever entering the map, so the
	// check would have had no failing value available to it.
	if peak < 2 {
		t.Fatalf("the rotation never held more than %d keys across %d churned "+
			"peers, so no churned key ever entered it and this test asserts "+
			"nothing", peak, churn)
	}
	t.Logf("peak rotation size %d over %d churned connections, final %d against "+
		"%d tips", peak, churn, victim.node.SyncRotationSizeForTest(),
		victim.engine.SyncTipCountForTest())
}

// TestTheRotationPrunesAgainstASetThatContainsEveryKeyItSeeds pins the subset
// relation the memory bound rests on.
//
// The property: **every candidate key NextSyncPeer seeds is present in the key
// set it prunes against.** The prune runs first and the seeding second, so any
// key the prune drops and the seeding re-enters is retained whatever the prune
// did -- and if the two sets came from different snapshots of Engine.tips the
// retained set would be bounded by their union rather than by the tip set,
// which is twice the figure section 4 states.
//
// Asserted on the snapshot itself rather than inferred from a selection,
// because a second acquisition of e.mu returns the same tips to a
// single-threaded caller. What this pins is that the wider set really is wider
// and that every candidate sits inside it; what it cannot pin is the number of
// acquisitions, which is why the two are separated here rather than merged.
func TestTheRotationPrunesAgainstASetThatContainsEveryKeyItSeeds(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 4)
	own := victim.chain.Tip().Height

	hello := func(listen string, height uint64, work u256.U256) []byte {
		return p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     height,
			Work:       work.Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	// Two peers ahead by height, so they are candidates on every round.
	for i := 0; i < 2; i++ {
		addr := "10.0.0." + itoa(i+1) + ":9421"
		victim.peers.Add(addr)
		victim.engine.Handle("conn:ahead:"+itoa(i), p2p.KindHello,
			hello(addr, own+8, u256.FromUint64(1<<20)))
	}

	// Two peers behind on both claims the handshake carries, with their
	// OffersUnknown stamps aged well past the window: each holds a tip on a
	// connection that is still up and is not a candidate. That is exactly the
	// population the rotation keeps a position for, and it is what makes the key set
	// wider than the candidate list here.
	//
	// Two rather than one, so that each assertion below has an input that
	// separates it. With a single lapsed peer, dropping a candidate's key from
	// the set takes the width check to equality and fires it, and the subset
	// loop -- the assertion that carries the property -- is then unreachable by
	// any mutant at all.
	lapsed := map[string]string{
		"203.0.113.9:51000":  "203.0.113.9:9500",
		"203.0.113.17:51000": "203.0.113.17:9500",
	}
	for conn, addr := range lapsed {
		victim.peers.Add(addr)
		victim.engine.Handle(conn, p2p.KindHello, hello(addr, own-1, u256.One))
		victim.engine.LapseCandidacyForTest(conn, time.Hour)
	}

	candidates, keys := victim.engine.SyncRotationViewForTest()

	// Non-vacuity, both halves. With no candidates the subset loop below ranges
	// over nothing; with a key set no wider than the candidate list, a set built
	// from the candidates themselves would satisfy the loop -- and that is the
	// spelling of the defect this test exists to refuse.
	if len(candidates) == 0 {
		t.Fatal("no candidates, so the subset check below ranges over nothing " +
			"and asserts nothing")
	}
	if len(keys) <= len(candidates) {
		t.Fatalf("%d rotation keys against %d candidates: the key set is not "+
			"wider than the candidate list, so it carries no peer that is not a "+
			"candidate and this test cannot tell a tip-set snapshot from a "+
			"candidate-set one", len(keys), len(candidates))
	}
	for _, addr := range lapsed {
		if _, ok := keys[addr]; !ok {
			t.Fatalf("the lapsed peer's key %q is absent from the rotation key "+
				"set, so the prune would drop a peer whose connection is up", addr)
		}
	}
	for _, c := range candidates {
		if _, ok := keys[c.SyncKeyForTest()]; !ok {
			t.Fatalf("candidate key %q is absent from the set the prune keeps: "+
				"the seeding loop re-enters it after the prune, so the retained "+
				"set is bounded by the union of two snapshots rather than by the "+
				"tip set (section 4)", c.SyncKeyForTest())
		}
	}
	t.Logf("%d candidates inside %d rotation keys", len(candidates), len(keys))
}

// TestAnEmptyCandidateListSkipsThePruneSoTheRotationHoldsDeadKeys pins the
// cadence the memory bound's first link depends on.
//
// The property: **the prune runs only on a selection that HAS a candidate, so
// while the node has none the rotation keeps keys for tips that are gone --
// unbounded in time, and closed by the next non-empty selection rather than by
// the node coming to rest.**
//
// It is committed rather than left as prose because a residual stated only in
// a comment drifts, and the remedy is an instrument that holds the property
// instead of a reader who keeps checking it.
//
// The empty-candidate arm is the one pinned, deliberately: it subsumes the
// sequential-teardown case. A teardown between two selections leaves the keys
// only until the next selection, whereas an empty candidate list leaves them
// for as long as the node has no candidates. That population is wider than it
// looks: having no candidate is not having no peers, so its common member is
// a node that is simply CAUGHT UP, every peer connected and every tip live.
// The test below this one pins that case; this one pins the arm where the
// tip set empties as well.
//
// Nothing here is a concurrency claim. It is one goroutine and there is nothing
// to interleave, which is the point: the window is a property of the prune's
// cadence rather than of any ordering between goroutines.
//
// This pins a RESIDUAL, so read a failure the right way round. If the middle
// assertion fails because the prune was moved above the early return, the
// window has been CLOSED, which is an improvement -- and section 7 of
// docs/adversarial/sync.md then describes behaviour the code no longer has.
// Update that residual and this test together; do not delete this test to
// make a build green, because then nothing holds the property in either
// direction.
func TestAnEmptyCandidateListSkipsThePruneSoTheRotationHoldsDeadKeys(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 4)
	own := victim.chain.Tip().Height

	hello := func(listen string) []byte {
		return p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     own + 8,
			Work:       u256.FromUint64(1 << 20).Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	conns := []string{"conn:a", "conn:b", "conn:c"}
	for i, c := range conns {
		addr := "10.0.0." + itoa(i+1) + ":9421"
		victim.peers.Add(addr)
		victim.engine.Handle(c, p2p.KindHello, hello(addr))
	}
	if _, ok := victim.node.NextSyncPeer(); !ok {
		t.Fatal("no candidate at seed, so nothing below is exercised")
	}
	seeded := victim.node.SyncRotationSizeForTest()
	if seeded == 0 {
		t.Fatal("the rotation seeded no keys, so the retention below asserts nothing")
	}

	for _, c := range conns {
		victim.engine.ForgetPeerForTest(c)
	}

	// Every peer gone, so each call takes the empty-candidate early return
	// above the prune. The loop guard is an assertion, not a formality: if any
	// round found a candidate this would be measuring the ordinary path.
	const idle = 50
	for i := 0; i < idle; i++ {
		if _, ok := victim.node.NextSyncPeer(); ok {
			t.Fatalf("round %d returned a candidate, so this test is not driving "+
				"the empty-candidate path it is named for", i)
		}
	}
	keys, tips := victim.node.SyncRotationSizeForTest(), victim.engine.SyncTipCountForTest()
	if tips != 0 {
		t.Fatalf("%d tips survive the teardowns, so the node is not in the "+
			"no-candidate state this test needs", tips)
	}
	if keys != seeded {
		t.Fatalf("the rotation holds %d keys after %d idle selections against %d "+
			"seeded: the prune ran on a path with no candidate, or the map moved "+
			"for some other reason", keys, idle, seeded)
	}

	// The failing value, and the whole reason the two assertions above mean
	// anything: a rotation that simply never prunes would satisfy them
	// identically. One selection WITH a candidate must close the window, which
	// is what shows the gate is candidacy rather than elapsed calls.
	victim.peers.Add("10.0.0.9:9421")
	victim.engine.Handle("conn:z", p2p.KindHello, hello("10.0.0.9:9421"))
	if _, ok := victim.node.NextSyncPeer(); !ok {
		t.Fatal("expected a candidate after a fresh tip")
	}
	keys, tips = victim.node.SyncRotationSizeForTest(), victim.engine.SyncTipCountForTest()
	if keys > tips {
		t.Fatalf("the rotation still holds %d keys against %d tips after a "+
			"selection that had a candidate: the prune is gated on something "+
			"other than the candidate list, so the window this test pins is not "+
			"closed by the event it names", keys, tips)
	}
	t.Logf("seeded %d keys; %d idle selections held them against 0 tips; one "+
		"non-empty selection left %d against %d", seeded, idle, keys, tips)
}

// TestACaughtUpNodeWithEveryPeerConnectedStillSkipsThePrune pins the POPULATION
// the residual above reaches, which is wider than the test before it shows.
//
// The property: **having no candidate is not the same as having no peers.** The
// prune is gated on the candidate list, so a node holding a full complement of
// connected peers with live tips still skips it whenever none of them is ahead
// -- the ordinary state of a node that is simply caught up, which is where a
// healthy node spends most of its life.
//
// Separated from the test above because that one empties the tip set as well,
// and a reader can take from it that dead keys only pile up on a node that has
// lost its peers. Here two tips stay LIVE and a dead key sits beside them.
//
// The falsifier, stated so the claim is attackable: if the middle row came back
// with keys equal to tips, the prune would be running on some path other than a
// candidate-bearing selection and the population sentence would be wrong.
func TestACaughtUpNodeWithEveryPeerConnectedStillSkipsThePrune(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 4)

	hello := func(listen string, h uint64) []byte {
		return p2p.Hello{
			Protocol:  p2p.ProtocolVersion,
			NetworkID: victim.chain.NetworkID(),
			Height:    h,
			// Minimal claimed work, deliberately. Candidacy is height OR work,
			// so a peer claiming more work than this node has stays a candidate
			// however far the node mines -- which would silently defeat the
			// caught-up state this test is built on.
			Work:       u256.One.Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	conns := []string{"conn:a", "conn:b", "conn:c"}
	for i, c := range conns {
		addr := "10.0.0." + itoa(i+1) + ":9421"
		victim.peers.Add(addr)
		victim.engine.Handle(c, p2p.KindHello, hello(addr, victim.chain.Tip().Height+8))
	}
	if _, ok := victim.node.NextSyncPeer(); !ok {
		t.Fatal("no candidate at seed, so nothing below is exercised")
	}
	seeded := victim.node.SyncRotationSizeForTest()

	// The node catches up past every peer and their OffersUnknown goes stale,
	// so nobody is a candidate. Every socket stays up.
	victim.mine(t, 20)
	for _, c := range conns {
		victim.engine.LapseCandidacyForTest(c, time.Hour)
	}
	// Exactly one peer drops, so a dead key can be observed beside live ones.
	victim.engine.ForgetPeerForTest("conn:c")

	const idle = 50
	for i := 0; i < idle; i++ {
		if _, ok := victim.node.NextSyncPeer(); ok {
			t.Fatalf("round %d returned a candidate, so this node is not in the "+
				"caught-up state the test is named for", i)
		}
	}
	keys, tips := victim.node.SyncRotationSizeForTest(), victim.engine.SyncTipCountForTest()
	if tips == 0 {
		t.Fatalf("no tips survive, so this is the lost-its-peers case the test " +
			"above already pins and not the wider population this one exists for")
	}
	if keys != seeded || keys <= tips {
		t.Fatalf("%d keys against %d live tips after %d idle selections (%d "+
			"seeded): a dead key did not survive beside live ones, so the "+
			"population is narrower than the residual claims",
			keys, tips, idle, seeded)
	}

	// Non-vacuity the other way, and the failing value for everything above: a
	// rotation that never prunes at all would satisfy it identically. A FRESH
	// connection is required -- Handle refuses a second handshake on a conn it
	// already holds, so reusing one would test nothing.
	victim.peers.Add("10.0.0.9:9421")
	victim.engine.Handle("conn:z", p2p.KindHello,
		hello("10.0.0.9:9421", victim.chain.Tip().Height+8))
	if _, ok := victim.node.NextSyncPeer(); !ok {
		t.Fatal("expected a candidate from the fresh connection")
	}
	idleKeys, idleTips := keys, tips
	keys, tips = victim.node.SyncRotationSizeForTest(), victim.engine.SyncTipCountForTest()
	if keys > tips {
		t.Fatalf("%d keys against %d tips after a candidate-bearing selection: "+
			"the prune is gated on something other than the candidate list",
			keys, tips)
	}
	// Each pair is printed from the variables captured at its own moment:
	// reusing the post-recovery values here would report the idle row as 3
	// against 3 when it was 3 against 2.
	t.Logf("caught up: %d keys against %d LIVE tips over %d idle selections; "+
		"one non-empty selection left %d against %d",
		idleKeys, idleTips, idle, keys, tips)
}
