package p2p_test

import (
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/p2p"
	"zycord/node/sync"
)

// Sync peer selection under a lying peer (R5-M1).
//
// The sync driver used to pick the peer claiming the greatest height. That is an
// argmax over unverified claims, and its failure mode needs no swarm at all: one
// peer that says it is at height one billion is the maximum on every tick,
// forever, so the honest peer holding the real chain is never asked and the
// victim never syncs. Re-derivation — the difficulty-rule check that makes work
// a fact rather than a claim — bounds what a liar can make a node *believe*. It
// does nothing about what a liar can stop a node from *hearing*.
//
// Selection is now least-recently-tried, which gives the property that ranking
// cannot: no peer is asked twice until every other candidate has been asked
// once. It holds without deciding whether any claim is true.

// TestSyncSelectionRotatesRatherThanRanking is the property, stated directly.
func TestSyncSelectionRotatesRatherThanRanking(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	// Three peers. One claims an absurd height; two are plausible. Under the old
	// argmax the liar was selected on every tick and the others never.
	liar := "10.0.0.1:9421"
	honestA := "10.1.0.1:9421"
	honestB := "10.2.0.1:9421"
	for addr, height := range map[string]uint64{
		liar: 1 << 30, honestA: 12, honestB: 9,
	} {
		victim.peers.Add(addr)
		victim.engine.Handle(addr, p2p.KindHello, p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     height,
			Work:       u256.FromUint64(height).Bytes(),
			ListenAddr: addr,
		}.MarshalHello())
	}

	got := victim.engine.SyncCandidates()
	if len(got) != 3 {
		t.Fatalf("%d sync candidates, want 3; selection cannot rotate over peers "+
			"it does not consider", len(got))
	}

	// Anti-vacuity: the liar must genuinely be the highest claim, or this test
	// is not exercising the case it exists for.
	var maxHeight uint64
	var maxAddr string
	for _, c := range got {
		if c.Height > maxHeight {
			maxHeight, maxAddr = c.Height, c.Dial
		}
	}
	if maxAddr != liar {
		t.Fatalf("setup: the liar is not the maximum claim (%s at %d is)", maxAddr, maxHeight)
	}

	// Rotate. Every candidate must be reached before any is repeated.
	seen := map[string]int{}
	for i := 0; i < len(got); i++ {
		peer, ok := victim.node.NextSyncPeer()
		if !ok {
			t.Fatalf("no candidate on round %d", i)
		}
		seen[peer.Dial]++
		victim.node.MarkSyncTried(peer.Dial)
	}
	for _, addr := range []string{liar, honestA, honestB} {
		if seen[addr] != 1 {
			t.Fatalf("peer %s was selected %d times in the first full rotation, want 1: "+
				"selection is ranking, not rotating, so a single liar starves the rest",
				addr, seen[addr])
		}
	}
}

// TestBannedPeersAreNotSyncCandidates: the score used to be computed and then
// discarded by the very path that computed it — nothing on the road to "who do I
// talk to" ever consulted the ban list, so misbehaviour cost a peer nothing that
// mattered.
func TestBannedPeersAreNotSyncCandidates(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	bad := "10.9.0.1:9421"
	victim.peers.Add(bad)
	victim.engine.Handle(bad, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		Height:     500,
		Work:       u256.FromUint64(500).Bytes(),
		ListenAddr: bad,
	}.MarshalHello())

	if len(victim.engine.SyncCandidates()) != 1 {
		t.Fatal("setup: the peer is not a candidate before being banned, so banning " +
			"it proves nothing")
	}
	for !victim.peers.Banned(bad) {
		victim.peers.Adjust(bad, p2p.ScoreProtocolViolation)
	}
	if !victim.peers.Banned(bad) {
		t.Fatal("setup: the peer did not reach the ban threshold")
	}
	if got := victim.engine.SyncCandidates(); len(got) != 0 {
		t.Fatalf("a banned peer is still a sync candidate (%d): the ban is advisory", len(got))
	}
}

// TestACompetingSiblingBlockCostsTheSenderNothing pins the case that R5's ban
// filter made dangerous.
//
// Two miners produce blocks at the same height all the time; every node receives
// the one it did not mine. That block is not better and does not extend the tip,
// and it is not misbehaviour in any sense — it is what a healthy network looks
// like. Charging for it bans the peers that are fastest at telling you things,
// and since R5 a ban also removes a peer from sync candidacy, so the node would
// have taught itself to stop syncing from exactly the peers worth syncing from.
//
// The narrower sibling of this case — Apply returning ErrWrongParent because the
// tip moved between the engine's parent check and the write lock — is now
// non-penalising too, and falls through to fork choice rather than being
// dropped. That path is a genuine race and is **not** covered by a test: forcing
// it deterministically needs a hook into the lock, and a test that claimed to
// cover it without one would be measuring the branch below it. Said here rather
// than implied by a test name.
func TestACompetingSiblingBlockCostsTheSenderNothing(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	rival := newNode(t, "rival", p, key(t, 2).Persistent())

	victim.mine(t, 1)
	rival.clock += p.TargetBlockSeconds
	rival.mine(t, 1)

	competing, err := rival.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: the two blocks must genuinely be siblings at the same
	// height, or this is not the race being tested.
	own, err := victim.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	if competing.Header.ID() == own.Header.ID() {
		t.Fatal("setup: the two nodes mined the same block; there is no race here")
	}
	if competing.Header.ParentID != own.Header.ParentID {
		t.Fatal("setup: the blocks are not siblings")
	}

	addr := "10.5.0.1:9421"
	victim.peers.Add(addr)
	handshake(t, victim, addr)
	before := scoreOf(t, victim, addr)

	// Deliver the competing sibling ten times. Every one loses the race.
	for i := 0; i < 10; i++ {
		victim.engine.Handle(addr, p2p.KindBlock, deliver(competing))
	}

	if after := scoreOf(t, victim, addr); after < before {
		t.Fatalf("losing a mining race cost the sender %d points (%d -> %d): an "+
			"honest, well-connected peer is banned for being fast",
			before-after, before, after)
	}
	if victim.peers.Banned(addr) {
		t.Fatal("a peer was banned for sending valid blocks that lost a race")
	}
}

// TestASecondHandshakeIsAProtocolViolation closes the hole that made every
// address-keyed defence attacker-controlled.
//
// The sync rotation, the peer store and the ban filter are all keyed on a
// peer's self-declared listen address. If a peer may re-handshake at will it
// mints a fresh identity each time — never tried, so it wins the rotation on
// every tick, defeating the rotation by rotating the key.
func TestASecondHandshakeIsAProtocolViolation(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	hello := func(listen string) []byte {
		return p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     100,
			Work:       u256.FromUint64(100).Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	const conn = "10.6.0.1:55555"
	if v := victim.engine.Handle(conn, p2p.KindHello, hello("10.6.0.1:9421")); v.Err != nil {
		t.Fatalf("the first handshake was refused: %v", v.Err)
	}
	if n := len(victim.engine.SyncCandidates()); n != 1 {
		t.Fatalf("setup: %d candidates after one handshake, want 1", n)
	}

	// Now claim a different address on the same connection, nine more times.
	for i := 0; i < 9; i++ {
		v := victim.engine.Handle(conn, p2p.KindHello, hello(sybilAddr(i)))
		if v.Score > p2p.ScoreProtocolViolation {
			t.Fatalf("a repeat handshake on one connection scored %d, want a "+
				"protocol violation: identities keyed on a self-declared address "+
				"are free if a peer may re-declare it", v.Score)
		}
	}
	// At most one candidate from one connection. Zero is also correct here and
	// is in fact what happens: nine protocol violations ban the peer outright,
	// which is the ban filter doing its job. What must never happen is *more*
	// than one, because that is an identity minted for free.
	if n := len(victim.engine.SyncCandidates()); n > 1 {
		t.Fatalf("one connection produced %d sync candidates: the rotation can be "+
			"defeated by rotating the key", n)
	}
}

func scoreOf(t *testing.T, n *testNode, addr string) int {
	t.Helper()
	peer, ok := n.peers.Get(addr)
	if !ok {
		t.Fatalf("peer %s is not in the store", addr)
	}
	return peer.Score
}

// TestAnnouncementBeforeHelloDoesNotBreakTheHandshake guards the fix for repeat
// handshakes against its own false positive.
//
// The one-handshake rule needs to know whether a connection has handshaked. The
// obvious test — "is there an entry for this connection?" — is wrong, because a
// block announcement creates one too. Reusing that as evidence would disconnect
// a peer for sending its own first Hello.
//
// Handle itself cannot reach this shape any more: there is a handshake gate
// there now, so a real connection can no longer get a block-announce dispatched
// ahead of its hello — Handle now refuses it outright, before OnBlockAnnounce
// ever runs. That closes the scenario on the wire, but OnBlockAnnounce is still
// an independently callable method, and its own bookkeeping (recordAnnounce
// creating a tips entry) must still not corrupt what OnHello's duplicate-
// handshake check reads. Calling it directly, bypassing Handle's gate, is what
// keeps that guarantee under its own test rather than retiring it as
// unreachable.
func TestAnnouncementBeforeHelloDoesNotBreakTheHandshake(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	src := newNode(t, "src", p, key(t, 2).Persistent())
	blocks := src.mine(t, 1)

	const conn = "10.7.0.1:44444"
	ann := p2p.BlockAnnounce{Header: blocks[0].Header, CertExemplars: blocks[0].CertExemplars()}
	victim.engine.OnBlockAnnounce(conn, ann.MarshalAnnounce())

	v := victim.engine.Handle(conn, p2p.KindHello, p2p.Hello{
		Protocol: p2p.ProtocolVersion, NetworkID: victim.chain.NetworkID(),
		Height: 50, Work: u256.FromUint64(50).Bytes(), ListenAddr: "10.7.0.1:9421",
	}.MarshalHello())
	if v.Score <= p2p.ScoreProtocolViolation {
		t.Fatalf("a peer's FIRST handshake was rejected as a repeat (score %d) "+
			"because it had already announced a block: announcements create the "+
			"tips entry, so presence in that map is not evidence of a handshake", v.Score)
	}
}

// TestRotationSurvivesAnIdentityThatKeepsChanging is the test the first version
// of the rotation could not express.
//
// TestSyncSelectionRotatesRatherThanRanking records each peer's handshake once
// and then rotates over a candidate set whose addresses are frozen for the
// test's lifetime. Under that assumption the rotation is unbreakable by
// construction — it cannot tell "rotation over stable identities" apart from
// "rotation over identities the adversary reissues", which is the only
// distinction that matters. It was structurally incapable of failing against
// the attack it was written to prove impossible.
//
// So this one lets the attacker do what the protocol previously allowed: send a
// fresh Hello with a new advertised address between every rotation step. If the
// rotation key is mutable, the attacker is never "recently tried" and wins every
// tick forever; the honest peers are reached zero times.
func TestRotationSurvivesAnIdentityThatKeepsChanging(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	hello := func(listen string, height uint64) []byte {
		return p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     height,
			Work:       u256.FromUint64(height).Bytes(),
			ListenAddr: listen,
		}.MarshalHello()
	}

	// Two honest peers, each on its own connection.
	honest := []string{"10.1.0.1:9421", "10.2.0.1:9421"}
	for i, addr := range honest {
		victim.peers.Add(addr)
		victim.engine.Handle("conn:honest:"+itoa(i), p2p.KindHello, hello(addr, 12))
	}
	// One attacker, on one connection, claiming an enormous height.
	const attackerConn = "203.0.113.7:51000"
	victim.engine.Handle(attackerConn, p2p.KindHello, hello("203.0.113.7:9421", 1<<30))

	reached := map[string]int{}
	for tick := 0; tick < 20; tick++ {
		// Every tick the attacker reissues its identity from the same socket.
		victim.engine.Handle(attackerConn, p2p.KindHello,
			hello("203.0.113.7:"+itoa(9422+tick), 1<<30))

		peer, ok := victim.node.NextSyncPeer()
		if !ok {
			continue
		}
		reached[peer.Dial]++
		victim.node.MarkSyncTried(peer.Dial)
	}

	var honestReached int
	for _, addr := range honest {
		honestReached += reached[addr]
	}
	if honestReached == 0 {
		t.Fatalf("over 20 ticks the honest peers were reached 0 times (selections: %v). "+
			"The rotation is keyed on an address the peer may reissue at will, so "+
			"it is defeated by rotating the key.", reached)
	}
	t.Logf("honest peers reached %d/20 ticks (selections: %v)", honestReached, reached)
}

// TestAnEqualHeightHeavierBranchIsASyncCandidate pins a permanent fork that a
// 20-minute soak walked into and sat in for an hour.
//
// Fork choice decides by accumulated work. Sync candidacy decided by height. The
// two disagree exactly where it matters: an equal-height branch can be strictly
// heavier, and a node gated on height alone will never ask about it. The soak
// ended with one node at height 537 on one tip and two more at height 537 on
// another, every one of them reporting no peer ahead. Nothing was broken, and
// nothing was going to fix itself.
func TestAnEqualHeightHeavierBranchIsASyncCandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 3)

	own := victim.chain.Height()
	ownWork := victim.chain.TotalWork()

	announce := func(conn, dial string, height uint64, work u256.U256) {
		victim.peers.Add(dial)
		victim.engine.Handle(conn, p2p.KindHello, p2p.Hello{
			Protocol:   p2p.ProtocolVersion,
			NetworkID:  victim.chain.NetworkID(),
			Height:     height,
			Work:       work.Bytes(),
			ListenAddr: dial,
		}.MarshalHello())
	}

	// A peer at the same height carrying strictly more work: a heavier branch of
	// the same length, which is what a difficulty difference produces.
	announce("conn:heavier", "10.1.0.1:9421", own, ownWork.SatAdd(u256.One))
	// And one at the same height with the same work, which is a genuine tie and
	// must NOT be chased — first-seen wins and there is nothing to fetch.
	announce("conn:tie", "10.2.0.1:9421", own, ownWork)

	var sawHeavier, sawTie bool
	for _, c := range victim.engine.SyncCandidates() {
		switch c.Dial {
		case "10.1.0.1:9421":
			sawHeavier = true
		case "10.2.0.1:9421":
			sawTie = true
		}
	}

	if !sawHeavier {
		t.Fatal("a peer at equal height with strictly more work is not a sync " +
			"candidate: fork choice decides by work and candidacy decides by " +
			"height, so an equal-height heavier branch is never fetched and the " +
			"fork is permanent")
	}
	// Anti-vacuity: if everything were a candidate the assertion above would
	// pass against a filter that does nothing at all.
	if sawTie {
		t.Fatal("a peer at equal height and equal work is a sync candidate: " +
			"there is nothing to fetch, and chasing ties spends a round trip per " +
			"tick on every peer that agrees with us")
	}
}

// TestAnUnplaceableAnnouncementKeepsAPeerACandidate closes the hole in the
// equal-height fix that made it inert on the connections that matter.
//
// `PeerTip.Work` is written once, at the handshake, and gossip cannot honestly
// update it: an announcement carries a header, not a chain, so there is no way
// to derive a peer's accumulated work from it. As both nodes advance, the frozen
// number stops being greater than ours and candidacy-by-work quietly switches
// itself off. The 30-minute soak did not catch this because 115 kills and 215
// partitions churn connections constantly, so handshakes were never stale — the
// fix worked in the environment that tested it and not in the one that ships.
//
// The signal that survives is an announcement this node cannot place: the peer
// demonstrably holds a block we do not, at a height where it matters, and it
// paid proof of work to say so.
func TestAnUnplaceableAnnouncementKeepsAPeerACandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	rival := newNode(t, "rival", p, key(t, 2).Persistent())

	victim.mine(t, 4)
	rival.clock += p.TargetBlockSeconds
	rival.mine(t, 4)

	const conn = "10.4.0.1:44444"
	const dial = "10.4.0.1:9421"
	victim.peers.Add(dial)

	// A handshake that is honest and immediately goes stale: the rival reports
	// the height and work it had *then*, and both nodes move on.
	victim.engine.Handle(conn, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		Height:     1,
		Work:       u256.One.Bytes(),
		ListenAddr: dial,
	}.MarshalHello())

	if n := len(victim.engine.SyncCandidates()); n != 0 {
		t.Fatalf("setup: %d candidates from a stale handshake behind our tip, want 0", n)
	}

	// Now the rival announces its own block 4 — same height as ours, different
	// block. Nothing about the handshake changed.
	rivalBlk, err := rival.chain.BlockAt(4)
	if err != nil {
		t.Fatal(err)
	}
	ann := p2p.BlockAnnounce{Header: rivalBlk.Header, CertExemplars: rivalBlk.CertExemplars()}
	victim.engine.Handle(conn, p2p.KindBlockAnnounce, ann.MarshalAnnounce())

	got := victim.engine.SyncCandidates()
	if len(got) != 1 {
		t.Fatalf("a peer that announced a block we cannot place is not a sync "+
			"candidate (%d candidates): its handshake work is frozen and stale, "+
			"so candidacy by work is inert and the equal-height fork is permanent", len(got))
	}
	if got[0].Dial != dial {
		t.Fatalf("wrong candidate: %s", got[0].Dial)
	}
}

// TestAnAlreadyKnownAnnouncementDoesNotMakeAPeerACandidate is the anti-vacuity
// half: if any announcement made a peer a candidate, every peer would be one on
// every block and the rotation would spend a round trip per tick on nodes that
// agree with us entirely.
func TestAnAlreadyKnownAnnouncementDoesNotMakeAPeerACandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	blocks := victim.mine(t, 3)

	const conn = "10.5.0.1:44444"
	const dial = "10.5.0.1:9421"
	victim.peers.Add(dial)
	victim.engine.Handle(conn, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		Height:     1,
		Work:       u256.One.Bytes(),
		ListenAddr: dial,
	}.MarshalHello())

	// Announce a block this node mined itself.
	own := blocks[len(blocks)-1]
	ann := p2p.BlockAnnounce{Header: own.Header, CertExemplars: own.CertExemplars()}
	victim.engine.Handle(conn, p2p.KindBlockAnnounce, ann.MarshalAnnounce())

	if n := len(victim.engine.SyncCandidates()); n != 0 {
		t.Fatalf("announcing a block we already have made the peer a sync "+
			"candidate (%d): every peer would be a candidate on every block", n)
	}
}

// TestAnEvictedCertificateCanBeGossipedAgain pins the censorship fix.
//
// A certificate that every node admitted and then evicted — the base fee rose
// past its bid, or its deposit stopped covering, both consensus state and so
// simultaneous network-wide — must be able to return once the condition passes.
// A permanent dedup cache made that impossible: every peer dropped the re-offer
// before consulting its pool, there is no rebroadcast loop, and resubmission was
// answered "accepted" and then silently discarded by everyone.
func TestAnEvictedCertificateCanBeGossipedAgain(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())
	n.mine(t, int(p.CoinbaseMaturity)+2)

	cert := buildCert(t, n, key(t, 1), 0)
	raw := cert.MarshalSSZ()

	handshake(t, n, "peer:1")
	if v := n.engine.Handle("peer:1", p2p.KindCertificate, raw); !v.Forward {
		t.Fatalf("setup: the certificate was not admitted and forwarded: %v", v.Err)
	}
	// A second offer while it is pooled is correctly redundant.
	if v := n.engine.Handle("peer:1", p2p.KindCertificate, raw); v.Forward {
		t.Fatal("a certificate still in the pool was forwarded twice")
	}

	// Now evict it the way a fee-floor or deposit re-screen would.
	n.pool.Remove(cert.ID())
	if n.pool.Has(cert.ID()) {
		t.Fatal("setup: eviction did not remove it")
	}

	// It must be able to come back.
	v := n.engine.Handle("peer:1", p2p.KindCertificate, raw)
	if !v.Forward {
		t.Fatalf("a certificate that was evicted from the pool could not be "+
			"re-gossiped (%v): every node evicts simultaneously on consensus "+
			"state, so this is permanent network-wide censorship of a valid "+
			"certificate, with no error anywhere", v.Err)
	}
}

// TestReapUnservedBodiesScoresAndForgetsALatePeer: PendingBodies was
// built for exactly this and had no caller, so an announced block whose body
// never arrived was never scored (wire.md §9 rule 5 was enforced on the sync
// path, via SyncPenalty, and nowhere on gossip) and its entry never left the
// map (written on every announcement, deleted only when a body arrived).
func TestReapUnservedBodiesScoresAndForgetsALatePeer(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	src := newNode(t, "src", p, key(t, 2).Persistent())
	blk := src.mine(t, 1)[0]

	const addr = "10.9.9.20:1"
	handshake(t, victim, addr)
	ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, ann.MarshalAnnounce())
	if v.Reply == nil {
		t.Fatalf("setup: the announcement was not accepted: %v", v.Err)
	}
	if len(victim.engine.PendingBodies()) != 1 {
		t.Fatal("setup: the announcement did not leave a pending body")
	}

	// Too soon: the window has not passed, so nothing is charged or forgotten.
	before := scoreOf(t, victim, addr)
	victim.engine.ReapUnservedBodies(time.Now())
	if len(victim.engine.PendingBodies()) != 1 {
		t.Fatal("a pending body was reaped before its window passed")
	}
	if after := scoreOf(t, victim, addr); after != before {
		t.Fatalf("score moved from %d to %d before the window passed", before, after)
	}

	// Past the window: the announcer is charged ScoreUnservedBody, and the
	// entry is gone either way.
	victim.engine.ReapUnservedBodies(time.Now().Add(p2p.PendingBodyTimeout + time.Second))
	if after := scoreOf(t, victim, addr); after != before+p2p.ScoreUnservedBody {
		t.Fatalf("an unserved body cost the peer %d points, want %d",
			after-before, p2p.ScoreUnservedBody)
	}
	if len(victim.engine.PendingBodies()) != 0 {
		t.Fatal("a reaped entry was left in the map")
	}

	// Reaping again must not charge it a second time — the entry is gone, and
	// a stale response should not be billed for as long as the reaper runs.
	again := scoreOf(t, victim, addr)
	victim.engine.ReapUnservedBodies(time.Now().Add(2 * p2p.PendingBodyTimeout))
	if got := scoreOf(t, victim, addr); got != again {
		t.Fatalf("a peer was charged twice for one unserved body: %d -> %d", again, got)
	}
}

// TestReapUnservedBodiesDoesNotChargeABlockThatArrivedAnotherWay: sync answers
// no announcement and never touches the pending map — on either transport,
// since it may run over a gossip connection too (wire.md §12) — so a
// block that landed on chain by that route was never "served" from this map's
// point of view even though it is exactly what this node needed. Charging the
// announcer for it would be the same mistake ErrWrongParent and the
// orphan-window refusals exist to avoid elsewhere in this package: a peer is
// not at fault for something that is a fact about this node's own state.
func TestReapUnservedBodiesDoesNotChargeABlockThatArrivedAnotherWay(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	src := newNode(t, "src", p, key(t, 2).Persistent())
	blk := src.mine(t, 1)[0]

	const addr = "10.9.9.21:1"
	handshake(t, victim, addr)
	ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, ann.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("setup: the announcement was not accepted: %v", v.Err)
	}

	// The exact same block lands by a route that never touches pending —
	// direct application, standing in for headers-first sync.
	if _, err := victim.chain.Apply(blk); err != nil {
		t.Fatalf("setup: applying the block directly: %v", err)
	}

	before := scoreOf(t, victim, addr)
	victim.engine.ReapUnservedBodies(time.Now().Add(p2p.PendingBodyTimeout + time.Second))
	if after := scoreOf(t, victim, addr); after != before {
		t.Fatalf("a peer was charged %d points for a body this node no longer needed", before-after)
	}
	if len(victim.engine.PendingBodies()) != 0 {
		t.Fatal("the stale entry for an already-canonical block was left in the map")
	}
}

// TestAnAnsweredAnnouncementIsNotAlsoChargedAsUnserved is the seam between
// the unserved-body reaper and every other refusal in OnBlock.
//
// `delete(e.pending, id)` used to sit below the block's validity checks, so
// every early return past the decode left the entry standing: a peer that
// announced a block and then *did* deliver its body paid ScoreInvalidMessage
// for whatever was wrong with it, and then ScoreUnservedBody sixty seconds
// later for not serving the thing it had served. Post-merge that second charge
// also lands on the identity ledger, which is the one a peer cannot shed.
//
// wire.md §9 rule 5 charges an announcer *once*, and only for not serving.
// Whether what it served was any good is a different question with its own
// verdict, and the two must not be billed as one.
//
// The vehicle is a body refused by the genesis-height citation guard, which is
// reachable precisely because an announcement carries no cited-header list and
// wire.md §5 says CitesRoot is therefore not checkable at announce time — so
// the announcement is legitimately accepted and the body legitimately refused.
func TestAnAnsweredAnnouncementIsNotAlsoChargedAsUnserved(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	src := newNode(t, "src", p, key(t, 2).Persistent())
	blk := src.mine(t, 1)[0]

	// A body citing a genesis-height header, and the header that commits to it.
	cited := types.Header{
		Version:      types.HeaderVersion,
		Height:       0,
		ParentID:     types.Hash{0xee},
		Time:         p.GenesisTime,
		EmissionAddr: key(t, 3).Persistent(),
		Target:       u256.One,
	}
	blk.Cites = []*types.Header{&cited}
	blk.Header.CitesRoot = blk.ComputeCitesRoot(p)

	const addr = "10.9.9.22:1"
	handshake(t, victim, addr)

	ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, ann.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("setup: the announcement was refused, so nothing is pending: %v", v.Err)
	}
	// Baselined after the announcement, which is itself worth a point.
	base := scoreOf(t, victim, addr)
	if len(victim.engine.PendingBodies()) != 1 {
		t.Fatal("setup: the announcement left no pending body")
	}

	v := victim.engine.Handle(addr, p2p.KindBlock, deliver(blk))
	if v.Score >= 0 {
		t.Fatalf("setup: the body was not refused (score %d), so there is no "+
			"double charge to look for", v.Score)
	}
	served := scoreOf(t, victim, addr)
	if served != base+v.Score {
		t.Fatalf("delivery moved the score by %d, want %d", served-base, v.Score)
	}
	if len(victim.engine.PendingBodies()) != 0 {
		t.Fatal("the body arrived and the announcement is still recorded as pending")
	}

	victim.engine.ReapUnservedBodies(time.Now().Add(p2p.PendingBodyTimeout + time.Second))
	if got := scoreOf(t, victim, addr); got != served {
		t.Fatalf("a peer that delivered a body it was asked for was charged a "+
			"further %d for not serving it: one delivery, two penalties",
			got-served)
	}
}

// TestAWithheldBodyAnswersItsAnnouncement is the same seam against the withhold
// queue, which reaches it without an invalid block at all.
//
// `Engine.now` reads a wall clock through `.Unix()`, which discards Go's
// monotonic reading, so an NTP step backwards can put a body past the
// future-time limit that its own announcement was comfortably inside of. The
// body is then queued rather than judged — the correct outcome — and used to
// leave `pending` standing, so the peer that served it was charged for not
// serving it a minute later. Nothing about the fix should depend on an argument
// about clocks being monotonic, and after it nothing does.
func TestAWithheldBodyAnswersItsAnnouncement(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	src := newNode(t, "src", p, key(t, 2).Persistent())
	blk := src.mine(t, 1)[0]

	now := blk.Header.Time
	victim.engine.Now = fixedClock(&now)

	const addr = "10.9.9.23:1"
	handshake(t, victim, addr)

	ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, ann.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("setup: the announcement was refused: %v", v.Err)
	}
	// Baselined after the announcement, which is itself worth a point.
	base := scoreOf(t, victim, addr)

	// The clock steps backwards, far enough that the same block is now ahead of
	// the limit it was inside of a moment ago.
	announcedAt := time.Unix(int64(now), 0)
	now -= p.FutureTimeLimitSeconds + 60

	v := victim.engine.Handle(addr, p2p.KindBlock, deliver(blk))
	if !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("setup: the body was not withheld (%v), so the case under test "+
			"was never reached", v.Err)
	}
	if v.Score != p2p.ScoreFutureBlock {
		t.Fatalf("a withheld body scored %d; being early is not an offence", v.Score)
	}
	if len(victim.engine.PendingBodies()) != 0 {
		t.Fatal("a body that arrived and was queued left its announcement pending")
	}

	victim.engine.ReapUnservedBodies(announcedAt.Add(p2p.PendingBodyTimeout + time.Second))
	if got := scoreOf(t, victim, addr); got != base {
		t.Fatalf("a peer whose body was queued rather than judged was charged %d "+
			"for not serving it; the queue is a fact about this node's clock",
			got-base)
	}
}

// TestCatchingUpDoesNotBanTheHonestPeersItDependsOn is the ban family, pinned
// as one defect.
//
// A node far enough behind that announcements fall outside the orphan height
// window used to fine every peer that answered its own `GetBlock` request —
// `ScoreInvalidMessage` for a condition that is a fact about the node's own
// backlog. Six blocks took an honest peer from the score ceiling to a permanent
// ban, and since R5 a ban also removes a peer from sync candidacy, so the node
// cut off precisely the peers it needed to climb back. Observed in the
// long-distance catch-up regime: a joiner 168 blocks behind reached
// `min_score=-104` and banned one of three peers.
//
// Three application points, one defect: charging for out-of-window orphans,
// laundering transport failures into `ErrBodyUnavailable`, and a score with no
// floor. Fixing any one alone leaves the pit reachable through the others.
func TestCatchingUpDoesNotBanTheHonestPeersItDependsOn(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	source := newNode(t, "source", p, key(t, 2).Persistent())

	// The source runs far ahead — past the orphan height window, which is the
	// condition that arms this.
	blocks := source.mine(t, 200)
	if source.chain.Height() <= 128 {
		t.Fatalf("setup: source is at height %d, not past the 128-block window",
			source.chain.Height())
	}

	const peer = "10.8.0.1:9421"
	victim.peers.Add(peer)
	handshake(t, victim, peer)
	before := scoreOf(t, victim, peer)

	// The source announces its tip; the victim asks for it, as it should.
	tip := blocks[len(blocks)-1]
	ann := p2p.BlockAnnounce{Header: tip.Header, CertExemplars: tip.CertExemplars()}
	v := victim.engine.Handle(peer, p2p.KindBlockAnnounce, ann.MarshalAnnounce())
	if v.Reply == nil || v.Reply.Kind != p2p.KindGetBlock {
		t.Fatal("setup: the victim did not request the announced block, so what " +
			"follows is not an answer to its own request")
	}

	// The answer arrives, twenty times, and every one lands outside the window.
	for i := 0; i < 20; i++ {
		victim.engine.Handle(peer, p2p.KindBlock, deliver(tip))
	}

	after := scoreOf(t, victim, peer)
	if after < before {
		t.Errorf("answering this node's own block request cost the peer %d points "+
			"(%d -> %d): the block is out of window because *this* node is behind, "+
			"which is not the sender's doing", before-after, before, after)
	}
	if victim.peers.Banned(peer) {
		t.Fatal("a node catching up banned the honest peer feeding it — the peers " +
			"it needs to climb back are the ones it cuts off first")
	}
}

// TestAScoreHasAFloor: a ban must be a state, not a pit. Without a floor a
// score sinks without bound, so a peer that dipped below the threshold could
// never climb back even in principle.
func TestAScoreHasAFloor(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())
	const peer = "10.9.0.1:9421"
	n.peers.Add(peer)

	for i := 0; i < 200; i++ {
		n.peers.Adjust(peer, p2p.ScoreProtocolViolation)
	}
	got := scoreOf(t, n, peer)
	if got < p2p.ScoreFloor {
		t.Fatalf("score sank to %d, below the floor of %d: the distance back is "+
			"unbounded, so no decay or probation could ever recover it",
			got, p2p.ScoreFloor)
	}
	if !n.peers.Banned(peer) {
		t.Fatal("the floor is above the ban threshold, so nothing can ever be banned")
	}
}

// Charging a peer for this node's own packet loss (R7 §3).
//
// A sync round over a long gap is hundreds of round trips, so the chance of at
// least one severed socket approaches certainty exactly when a node most needs
// the peer serving it. `SyncPenalty` therefore declines to charge a transport
// fault — and that guard was written, reviewed and merged in a state where it
// could never fire, because `sync.Fetch` wrapped the inner error with `%v`
// instead of `%w` and the sentinel it tests for did not survive the wrapping.
//
// The consequence was a ratchet with no release. Every severed body fetch cost
// an honest peer -10; nothing decays a score; and the +1 for a useful sync is
// awarded only on the whole-round success that a lossy link prevents. Ten
// severances ban the peer, a banned peer is dropped from sync candidacy, and
// the node that loses is the one that could not catch up.
//
// **The error is taken from `sync.Run`, not built by hand**, and that is the
// whole design of this test. A first draft constructed the wrapped error itself
// and asserted on it — and passed with the `%v` restored, because it was
// measuring its own string formatting rather than the code's. Mutation found
// it. A test of an error classification has to classify an error the system
// actually produced.
//
// **What this fixture must never do is invent an error production cannot
// produce.** Its refusing half used to return a bare `errors.New("not
// serving")`, which asserted that a peer serving *nothing* is charged -10 — a
// branch nothing on this path reaches, because `connSource.Body` wraps every
// round-trip failure in `ErrTransport` and the guard exempts all of them. The
// test passed, the sentence it pinned was false, and it is what hid the finding
// that a peer refusing a body during sync was never charged. The two shapes
// below are the ones the request path really produces: a wrapped transport
// fault (served nothing) and a real block that is not the one asked for (served
// bytes that were a lie).
type severedBodySource struct {
	chain *chain.Chain
	// wrongBody makes the peer answer with a genuine, valid block that is not
	// the one asked for: the *only* shape of misconduct reachable on the
	// request path, and what keeps the transport exemption from being
	// indistinguishable from not scoring at all. The peer answers — that is
	// the whole point, and the axis the charge is keyed on.
	wrongBody bool
}

func (s *severedBodySource) Tip() (uint64, u256.U256) {
	return s.chain.Height(), s.chain.TotalWork()
}

func (s *severedBodySource) Headers(from uint64, count uint32) ([]types.Header, error) {
	var out []types.Header
	for h := from; h <= s.chain.Height() && len(out) < int(count); h++ {
		blk, err := s.chain.BlockAt(h)
		if err != nil {
			break
		}
		out = append(out, blk.Header)
	}
	return out, nil
}

func (s *severedBodySource) Body(id types.Hash) (*types.Block, error) {
	if s.wrongBody {
		// A real, valid block, honestly served — just not the one asked for.
		// The error under test is then produced by production `sync.Fetch`
		// (`node/sync/sync.go`, "peer served a different block"), not written
		// here, which is the same rule the transport half follows.
		for h := s.chain.Height(); h >= 1; h-- {
			blk, err := s.chain.BlockAt(h)
			if err != nil {
				return nil, err
			}
			if blk.Header.ID() != id {
				return blk, nil
			}
		}
		return nil, errors.New("setup: the chain holds only the block that was asked for")
	}
	// Byte for byte what connSource.Body produces when the round trip fails —
	// a dropped socket, a silent peer, a locally closed descriptor all arrive
	// here in this one shape (syncdriver.go, `fmt.Errorf("%w: %v", ErrTransport, err)`).
	return nil, fmt.Errorf("%w: %v", p2p.ErrTransport, io.EOF)
}

func TestATransportFaultIsNotChargedToThePeer(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "source", p, key(t, 1).Persistent())
	source.mine(t, 6)

	// A peer that answers no body request at all. On this path that is the
	// *whole* served-nothing population — the honest bootstrap whose socket
	// died, the node an operator killed mid-redeploy, and the peer withholding
	// on purpose all arrive as this one error — and it is deliberately worth
	// nothing, keyed on who initiated rather than on what was observed.
	victim := newNode(t, "victim", p, key(t, 2).Persistent())
	_, err := sync.Run(victim.chain, pow.Dev{}, &severedBodySource{chain: source.chain}, 8)

	// Anti-vacuity: the run must actually have failed on a body fetch, or
	// "nothing was charged" is the correct answer for the wrong reason.
	if err == nil {
		t.Fatal("setup: the sync succeeded against a peer that never served a body")
	}
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("setup: the failure is not a body-unavailable report (%v), so the "+
			"scoring branch under test is not the one this error reaches", err)
	}

	if got := p2p.SyncPenalty(err); got != 0 {
		t.Fatalf("a severed socket charged the serving peer %d for this node's own "+
			"packet loss. Nothing decays a score, and the +1 for a useful sync "+
			"needs the whole-round success a lossy link prevents — so this is a "+
			"ratchet: %d severances ban an honest peer, a banned peer leaves sync "+
			"candidacy, and the node that pays is the one that cannot catch up. "+
			"The error was %v.", got, p2p.ScoreBanThreshold/got, err)
	}

	// The other half, or the exemption would be indistinguishable from having
	// deleted the score. It is **served-but-wrong**, not served-nothing: on
	// this path a peer that answers nothing is exempt by design (see
	// `SyncPenalty` and `ScoreUnservedBody` — the charge prices a block a peer
	// volunteered by announcing it, and request-path withholding is carried by
	// rotation, docs/adversarial/sync.md §5). What is still charged is a peer
	// that answered with bytes that were a lie.
	liar := newNode(t, "lied-to", p, key(t, 3).Persistent())
	_, err = sync.Run(liar.chain, pow.Dev{}, &severedBodySource{chain: source.chain, wrongBody: true}, 8)
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("setup: a peer serving the wrong block did not produce a "+
			"body-unavailable report: %v", err)
	}
	if errors.Is(err, p2p.ErrTransport) {
		t.Fatalf("setup: a peer that answered was reported as a transport fault "+
			"(%v), so this half is measuring the exemption rather than the charge", err)
	}
	if got := p2p.SyncPenalty(err); got != p2p.ScoreUnservedBody {
		t.Fatalf("a peer that answered a body request with a block that was not "+
			"the one asked for was charged %d, want %d: served-but-wrong is the "+
			"only charge this path can reach, and an exemption that swallows it "+
			"has disarmed the score rather than corrected it", got, p2p.ScoreUnservedBody)
	}

	// A peer describing a chain that cannot exist is a third thing again, and
	// keeps the classification from collapsing into two cases.
	forged := fmt.Errorf("%w: header 3", sync.ErrForgedTarget)
	if got := p2p.SyncPenalty(forged); got != p2p.ScoreInvalidMessage {
		t.Fatalf("a forged difficulty target was charged %d, want %d",
			got, p2p.ScoreInvalidMessage)
	}
}

// TestANodeThatCaughtUpBySyncCanStillMine is the `sync-no-onblock` candidate
// from the drain queue, armed because the sync-stranding fix made it reachable:
// a fix that creates the conditions for a known defect owns that defect.
//
// `Pool.OnBlock` is the only thing that removes committed certificates from the
// pool. The gossip path calls it; the sync path never did. `Candidates()`
// returns the pool unfiltered and `Select` takes no state, so a node that
// caught up by sync assembles its next block from a pool still holding
// certificates the chain it just adopted already committed — and B3
// ([blockrules.go](../../core/fold/blockrules.go)) makes re-inclusion
// **block-invalid**. The node catches up and then cannot produce a block.
//
// It was masked by gossip density: a synced node applies a gossiped block
// within seconds and *that* path clears the pool before the miner's next tick.
// It is reachable where the window is long — a node whose only catch-up route
// is sync, which is precisely the node I5-H9 exists to rescue. Fixing the
// stranding without fixing this would have converted a node that could not
// catch up into a node that catches up and then mines invalid blocks, which is
// not obviously an improvement.
//
// No gossip anywhere in this test, deliberately. Gossip is the mask.
func TestANodeThatCaughtUpBySyncCanStillMine(t *testing.T) {
	p := devnetEasy()
	signer := key(t, 4)

	// There is no premine and no faucet, so the only way to hold a coin is to
	// have mined one: the signer's address is the payout.
	source := newNode(t, "source", p, signer.Persistent())
	source.mine(t, int(p.CoinbaseMaturity)+2)

	// The victim shares the funding prefix — same state, so the same
	// certificate is admissible to its pool — and none of what follows.
	victim := newNode(t, "victim", p, signer.Persistent())
	for h := uint64(1); h <= source.chain.Height(); h++ {
		blk, err := source.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := victim.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	victim.clock = source.clock

	cert := buildCert(t, source, signer, 0)
	if err := source.pool.Add(cert, source.chain.Snapshot().State, source.chain.Height()); err != nil {
		t.Fatalf("setup: the source would not pool its own certificate: %v", err)
	}
	if err := victim.pool.Add(cert, victim.chain.Snapshot().State, victim.chain.Height()); err != nil {
		t.Fatalf("setup: the victim would not pool the certificate, so there is "+
			"nothing for it to wrongly re-include: %v", err)
	}
	source.mine(t, 1) // commits the certificate on the source's chain

	// Anti-vacuity, both halves. The certificate must really be committed on
	// the chain about to be synced, and must really still be in the victim's
	// pool — otherwise "the victim mines fine" is true for a reason that has
	// nothing to do with the defect.
	tip, err := source.chain.BlockAt(source.chain.Height())
	if err != nil {
		t.Fatal(err)
	}
	var committed bool
	for _, c := range tip.Certs {
		if c.ID() == cert.ID() {
			committed = true
		}
	}
	if !committed {
		t.Fatal("setup: the certificate was not included, so syncing this chain " +
			"commits nothing and the case under test does not arise")
	}
	if victim.pool.Stats().Size == 0 {
		t.Fatal("setup: the victim's pool is empty before the sync")
	}

	// Catch up through the real driver, over a real socket, because the defect
	// is a missing call rather than a wrong computation. Driving `sync.Run`
	// directly would exercise the sync package and prove nothing about whether
	// anything calls what it needs to — and "correct, complete, tested and
	// called from nowhere" is a shape this project has shipped twice already
	// (I5-L8).
	serveSyncTo(t, source)
	if err := victim.node.SyncFrom(source.node.ListenAddr()); err != nil {
		t.Fatalf("catching up by sync: %v", err)
	}
	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatal("setup: the victim did not catch up, so it never committed the " +
			"certificate and the pool is right to still hold it")
	}

	if _, _, err := victim.miner.MineOne(1 << 20); err != nil {
		t.Fatalf("a node that caught up by sync could not mine: %v\n\n"+
			"Pool.OnBlock is the only thing that removes committed certificates "+
			"from the pool, and the sync path never called it. Candidates() is "+
			"unfiltered and Select takes no state, so the miner assembled a block "+
			"re-including a certificate the chain it had just adopted already "+
			"committed, and B3 makes that block invalid. The node catches up and "+
			"then cannot produce a block, indefinitely — and the only thing that "+
			"rescues it is a gossiped block, which is exactly what a node "+
			"catching up by sync alone does not have.", err)
	}
}

// serveSyncTo makes a test node answer sync over a real socket.
//
// The in-process harness delivers messages by schedule, which is the right tool
// for partitions and eclipses. It is the wrong tool here: the question is
// whether `SyncFrom` — the driver, the connection, the handshake and everything
// it does to the mempool afterwards — is wired to what it needs, and a
// scheduled message never enters that function.
func serveSyncTo(t *testing.T, n *testNode) {
	t.Helper()
	if err := n.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(n.node.Stop)
}

// TestSyncFromRecordsAWithheldPass is the sync half of the slow-clock stall
// across the seam that joins its two ends, and it exists because mutation found
// nothing covered that seam.
//
// node/sync pins that a withheld pass carries its reason on the Result, and
// node/p2p pins that Engine.RecordSyncWithheld counts one. Neither says the
// driver connects them: deleting the one call in SyncFrom left the whole tree
// green — the same "correct piece called from nowhere" shape as the defect
// beside it, on the sensor the finding names explicitly.
//
// Over a real socket, because the question is whether SyncFrom is wired to what
// it needs, and an in-process delivery never enters that function.
func TestSyncFromRecordsAWithheldPass(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "source", p, key(t, 1).Persistent())
	source.mine(t, 6)

	victim := newNode(t, "victim", p, key(t, 2).Persistent())
	serveSyncTo(t, source)

	// The victim's clock reads an hour before genesis, so every header it is
	// offered — including the first — is past its future-time limit.
	const slowBy = 3600
	restore := sync.Clock
	sync.Clock = func() time.Time { return time.Unix(int64(p.GenesisTime-slowBy), 0) }
	t.Cleanup(func() { sync.Clock = restore })

	if r := victim.engine.BeyondHorizon(); r.SyncPasses != 0 {
		t.Fatalf("setup: %d withheld passes before syncing", r.SyncPasses)
	}
	addr := source.node.ListenAddr()
	if err := victim.node.SyncFrom(addr); err != nil {
		t.Fatalf("a range this node's clock cannot reach is not the peer's fault: %v", err)
	}

	r := victim.engine.BeyondHorizon()
	if r.SyncPasses == 0 {
		t.Fatal("a sync pass took nothing because this node's clock is slow, and " +
			"nothing recorded it; an empty Result reads exactly like a node with " +
			"nothing to do, which is the stall on this path")
	}
	if r.MaxSkewSeconds < slowBy {
		t.Fatalf("skew recorded as %ds against a clock %ds slow", r.MaxSkewSeconds, slowBy)
	}
	// Charged to the peer that served the range, so the same breadth evidence
	// separates a slow local clock from one peer with a fast one.
	if want := p2p.AddressGroup(addr); r.Groups != 1 || r.FirstGroup != want {
		t.Fatalf("the pass recorded %d group(s) / first %q, want 1 / %q — evidence "+
			"charged to nobody cannot tell the two readings apart",
			r.Groups, r.FirstGroup, want)
	}
	// And nothing else moved: this path counts passes, not messages.
	if r.Count != r.SyncPasses {
		t.Fatalf("%+v: a withheld sync pass moved a gossip counter", r)
	}
}

// TestASyncDrivenReorgReturnsItsCertificatesToThePool is the driver half of
// I5-H11, and it exists because mutation found that nothing covered it.
//
// `sync.Run` reporting `Undone` is pinned in node/sync. That the *driver* acts
// on the report was not pinned anywhere: deleting the `Pool.Readmit` call left
// every test green. The same shape as the defect it guards — a correct piece
// called from nowhere — so it needed its own scenario rather than a note.
//
// The property: a certificate confirmed on this node's branch and then reorged
// away by a sync must be back in this node's pool. Losing it means it vanishes
// from the chain and from every mempool at the same moment, and nobody is told.
func TestASyncDrivenReorgReturnsItsCertificatesToThePool(t *testing.T) {
	p := devnetEasy()
	signer := key(t, 5)

	source := newNode(t, "source", p, signer.Persistent())
	source.mine(t, int(p.CoinbaseMaturity)+2)

	victim := newNode(t, "victim", p, signer.Persistent())
	for h := uint64(1); h <= source.chain.Height(); h++ {
		blk, err := source.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := victim.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	victim.clock = source.clock

	// The victim confirms a certificate on its own branch.
	cert := buildCert(t, victim, signer, 0)
	if err := victim.pool.Add(cert, victim.chain.Snapshot().State, victim.chain.Height()); err != nil {
		t.Fatalf("setup: the victim would not pool the certificate: %v", err)
	}
	mined, _, err := victim.miner.MineOne(1 << 20)
	if err != nil {
		t.Fatalf("setup: the victim could not mine its certificate: %v", err)
	}
	var confirmed bool
	for _, c := range mined.Certs {
		if c.ID() == cert.ID() {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatal("setup: the victim's block does not contain the certificate, so " +
			"reorging it away removes nothing")
	}
	// Anti-vacuity: mining it took it out of the pool. If it were still there,
	// finding it there after the reorg would prove nothing.
	if victim.pool.Stats().Size != 0 {
		t.Fatalf("setup: the pool still holds %d certificates after mining them, "+
			"so a certificate found there after the reorg need not have been "+
			"readmitted", victim.pool.Stats().Size)
	}

	// A heavier branch that does not contain it.
	source.mine(t, 3)
	if !source.chain.TotalWork().Gt(victim.chain.TotalWork()) {
		t.Fatal("setup: the other branch is not heavier, so refusing it would be correct")
	}

	serveSyncTo(t, source)
	if err := victim.node.SyncFrom(source.node.ListenAddr()); err != nil {
		t.Fatalf("syncing the heavier branch: %v", err)
	}
	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatal("setup: the reorg did not happen, so nothing was undone")
	}

	if _, ok := victim.pool.Get(cert.ID()); !ok {
		t.Fatal("a certificate was confirmed on this node's branch, reorged away " +
			"by a sync, and not returned to the pool. It is gone from the chain " +
			"and from the mempool at the same moment, with nothing reported — " +
			"the defect fixed for the gossip path and left open on this one.")
	}
}

// TestAPeerAnnouncingAReorgedAwayBlockStillOffersSomethingUnknown.
//
// The property: "can this node place the announced block?" means "is it on my
// chain?", not "have I ever heard of it?".
//
// OffersUnknown is the third and most durable path to sync candidacy — the one
// that still works an hour into a connection, because gossip refreshes it while
// the handshake's height and work claims stay frozen. It fires when a peer
// shows this node a block it cannot place.
//
// Retaining the headers of reorged-out blocks broke that test. A node that lost
// a segment keeps its headers, so a peer announcing that segment — because the
// peer won there — reads as announcing something already held, and never gets
// marked as offering anything new. Two nodes on opposite sides of a fork each
// conclude the other has nothing, and neither ever asks. That is
// healed-network-stays-forked, which is the failure this file's opening comment
// names and the one the minority-branch-rejoin defect is about.
func TestAPeerAnnouncingAReorgedAwayBlockStillOffersSomethingUnknown(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 4)

	losing, err := victim.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}

	// A heavier two-block branch takes heights 3 and 4 off the victim's chain,
	// keeping the resulting height at 4 — recordAnnounce below only marks a
	// peer as offering something unknown when the announced block's height is
	// within one of this node's own, so the replacement must not run past it.
	// The first block ties the honest chain's own (a block's target is fixed
	// entirely by the window that precedes it, with no freedom relative to a
	// shared ancestor); the second is timestamped identically to its parent —
	// the most aggressive solve time NextTarget can read — which is enough to
	// double its work over a two-pair window and outweigh the pair it replaces.
	ancestor, err := victim.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	branch := buildHarderBranch(t, victim.chain, p, key(t, 7).Persistent(), ancestor.Header, 2, 0)
	if !branch.Work().Gt(worthOf(t, victim.chain, 3, 4)) {
		t.Fatal("setup: the branch does not carry more work than the two blocks it replaces")
	}
	reorg, err := victim.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the harder branch: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("setup: the heavier branch was not adopted, so nothing was orphaned")
	}
	if _, err := victim.chain.Header(losing.Header.ID()); err != nil {
		t.Fatalf("setup: the orphaned header was not retained, so there is no "+
			"way for this to go wrong: %v", err)
	}

	// A peer on the other side of the fork connects and announces the block the
	// victim reorged away. Its handshake claims nothing the victim does not
	// already beat, so OffersUnknown is the only thing that can make it a
	// candidate.
	const addr = "10.0.0.1:9421"
	victim.peers.Add(addr)
	victim.engine.Handle(addr, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		Height:     losing.Header.Height,
		Work:       u256.One.Bytes(),
		ListenAddr: addr,
	}.MarshalHello())

	if got := victim.engine.SyncCandidates(); len(got) != 0 {
		t.Fatalf("setup: the peer is already a candidate on its handshake claims "+
			"(%d), so the announce below cannot be what makes it one", len(got))
	}

	victim.engine.Handle(addr, p2p.KindBlockAnnounce, p2p.BlockAnnounce{
		Header:        losing.Header,
		CertExemplars: losing.CertExemplars(),
	}.MarshalAnnounce())

	if got := victim.engine.SyncCandidates(); len(got) != 1 {
		t.Fatalf("a peer announcing a block this node reorged away is not a sync "+
			"candidate (%d): the node holds the header but not the body and is not "+
			"built on it, so it cannot place the block — and neither side of the "+
			"fork will ever ask the other for it", len(got))
	}
}

// A whole-attempt deadline for SyncFrom.
//
// docs/adversarial/sync.md conceded the gap in writing: `await` tolerates up
// to sixteen unsolicited messages at twenty seconds each (320s) before giving
// up on *one* request, but a sync attempt is many requests — extendToCover
// issues header round trips and Fetch issues one body round trip per header —
// and nothing bounded their sum. A peer that answers every individual
// request just inside its own 320s budget, forever, could hold syncLoop
// hostage for hours while never once failing a per-read deadline.
//
// stallingPeer below is exactly that peer, reduced to its essential: it
// completes the real handshake — so SyncFrom gets past the checks that would
// otherwise end the attempt for an unrelated reason — and then answers
// nothing else, ever. It never has to time an answer to survive per-read
// deadlines because it never has to answer at all; the only thing that can
// end the attempt is the whole-attempt deadline itself.

// stallingPeer completes the p2p handshake honestly and then answers nothing
// else, ever, on every connection it accepts. Returns the dialable address.
func stallingPeer(t *testing.T, networkID types.Hash) string {
	t.Helper()
	id, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	// hold parks each accepted handler so it stays silent instead of
	// returning (and thereby closing the connection) after its first Receive.
	//
	// Closed before ln.Close() rather than after, so every parked handler is
	// released and runs its own deferred conn.Close() as part of teardown
	// instead of outliving the test. One t.Cleanup runs exactly once, so the
	// close needs no sync.Once around it.
	hold := make(chan struct{})
	t.Cleanup(func() {
		close(hold)
		ln.Close()
	})

	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The handshake has to succeed, or SyncFrom ends the attempt
				// for a reason this test is not about (ErrWrongNetwork).
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, _, err := conn.Receive(); err != nil {
					return
				}
				hello := p2p.Hello{
					Protocol:  p2p.ProtocolVersion,
					NetworkID: networkID,
					Height:    1 << 20,
					Work:      u256.FromUint64(1 << 20).Bytes(),
				}
				if conn.Send(p2p.KindHello, hello.MarshalHello()) != nil {
					return
				}
				// And now nothing, ever: no reply to GetHeaders, no error, no
				// unsolicited junk either — just silence, until the victim's
				// own whole-attempt deadline (or Stop) forces the connection
				// closed from its end.
				//
				// The block on `hold` is the point of this helper, and it is
				// load-bearing rather than defensive: without it this handler
				// returned as soon as one Receive did, ran its deferred
				// conn.Close(), and handed the victim an immediate EOF. Every
				// test built on this peer then passed in a few milliseconds
				// for that reason alone — never reaching, never consuming and
				// never exercising the whole-attempt deadline they exist to
				// pin. Verified by mutation: with clampDeadline neutered and
				// SyncFrom's watcher disabled — the entire fix disabled —
				// they still passed, because `err=EOF` at ~3ms is what they
				// were really observing. Staying parked here until the test
				// tears the listener down is what makes a stall a stall.
				<-hold
			}()
		}
	}()
	return addr
}

// TestSyncFromAbortsAStallingPeerWithinTheWholeAttemptDeadline is the
// property itself: a peer that never fails a single read cannot hold one
// SyncFrom call open past its configured whole-attempt budget.
//
// SyncAttemptTimeout is set far below the default (which a test should not
// wait real minutes for) so the property is checked directly rather than
// inferred from a long sleep — mirroring why syncAttemptTimeout is a Node
// field and not only a package constant.
func TestSyncFromAbortsAStallingPeerWithinTheWholeAttemptDeadline(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.node.SyncAttemptTimeout = 200 * time.Millisecond

	addr := stallingPeer(t, victim.chain.NetworkID())

	start := time.Now()
	err := victim.node.SyncFrom(addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("SyncFrom against a peer that never answers a single request " +
			"succeeded — the setup is not exercising a stall")
	}
	// Generous relative to the 200ms budget, and tiny relative to what the
	// unbounded code could take against this exact peer: await alone
	// tolerates 320s per request before erroring, and a sync attempt is many
	// requests, so the old behaviour was bounded only by patience.
	if elapsed > 5*time.Second {
		t.Fatalf("SyncFrom took %s against a peer that never answers anything, "+
			"with a 200ms whole-attempt deadline configured: the deadline did "+
			"not bound the attempt, which is the liveness bug", elapsed)
	}

	// The peer never lied and never failed to serve — it simply never
	// answered — so this must not cost it score, for the same reason
	// TestATransportFaultIsNotChargedToThePeer already pins for a severed
	// socket: a slow-but-honest peer on a long catch-up is indistinguishable
	// from this at the point the penalty would be charged.
	if got := p2p.SyncPenalty(err); got != 0 {
		t.Fatalf("a whole-attempt timeout charged the peer %d points (err: %v): "+
			"a peer this indistinguishable from an honest one on a slow link "+
			"must not be scored down for it, only rotated away from — which "+
			"NextSyncPeer already does for any peer SyncFrom was just tried "+
			"against, timeout or not", got, err)
	}
}

// TestStopReturnsPromptlyDespiteAStuckSyncAttempt is its second half: a
// stalling peer must not be able to block a clean shutdown either.
//
// syncLoop holds an n.wg entry for as long as SyncFrom runs (Start calls
// n.wg.Add(1) before `go n.syncLoop()`), and SyncFrom's own connection is
// never registered in n.conns — it is a dedicated, ephemeral socket SyncFrom
// opens itself, not one of the long-lived gossip connections Stop's own
// teardown loop closes. Before this fix, Stop's wg.Wait had nothing to
// interrupt a SyncFrom stuck on an unbounded read: it would wait for the
// stalling peer for as long as the peer cared to stall, indefinitely.
//
// This is unrelated to (and not fixed by) the accept-lifecycle work: that
// bounded the *inbound* handshake and reply paths so a silent inbound
// connection cannot wedge acceptLoop's own wg entry. syncLoop's stuck
// *outbound* dial-and-read is a different goroutine on a different
// connection, still capable of wedging Stop after that fix, unless SyncFrom's own
// deadline mechanism also watches n.quit — which it now does.
//
// SyncAttemptTimeout is set far longer than this test's patience, so a pass
// can only be explained by Stop interrupting the stuck read directly, not by
// racing the whole-attempt timeout to the same result.
func TestStopReturnsPromptlyDespiteAStuckSyncAttempt(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.node.SyncAttemptTimeout = 5 * time.Minute
	victim.node.SyncInterval = 10 * time.Millisecond
	victim.node.MaxOutbound = 0 // isolate the sync connection from dialLoop's own

	addr := stallingPeer(t, victim.chain.NetworkID())
	victim.peers.Add(addr)
	victim.engine.Handle(addr, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		Height:     1 << 20,
		Work:       u256.FromUint64(1 << 20).Bytes(),
		ListenAddr: addr,
	}.MarshalHello())
	if got := victim.engine.SyncCandidates(); len(got) != 1 {
		t.Fatalf("setup: the stalling peer is not a sync candidate (%d), so "+
			"syncLoop below has nothing to get stuck on", len(got))
	}

	victim.node.Start()
	// Give syncLoop time to tick, dial, complete the handshake and land inside
	// the blocked read that never returns on its own.
	time.Sleep(300 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		victim.node.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Node.Stop did not return while syncLoop was stuck inside a " +
			"stalling SyncFrom call, with a 5-minute whole-attempt deadline " +
			"configured: a stuck sync attempt still blocks a clean shutdown, " +
			"which is what stands between an operator's Ctrl-C and the one " +
			"call to PeerStore.Save that follows it (cmd/zycordd)")
	}
}

// junkDripPeer completes the handshake and then floods the connection with a
// steady stream of wrong-kind frames until stop is closed, rather than going
// silent like stallingPeer.
//
// This is the shape stallingPeer cannot exercise. connSource.await discards
// any frame that is not the kind it asked for and loops back for another,
// resetting its own SetReadDeadline(+20s) on every iteration — so a peer
// that keeps *anything* arriving gives that reset repeated chances to land
// after SyncFrom's whole-attempt watcher forces the connection's deadline to
// "now", racing a read that already has data available and potentially
// completing it anyway (a documented, narrow race in net.Conn's own
// contract, not a misuse of it). A one-shot forced deadline can lose that
// race once and then have nothing left to reapply it; a peer that never
// stops sending keeps offering more chances to lose it, for as long as the
// attempt runs. stallingPeer, by contrast, never has anything in flight for
// the race to occur against, so it cannot see this at all.
func junkDripPeer(t *testing.T, networkID types.Hash, stop <-chan struct{}, period time.Duration) string {
	t.Helper()
	id, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	addr := ln.Addr().String()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// The handshake has to succeed, or SyncFrom ends the attempt for a
		// reason this test is not about (ErrWrongNetwork).
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := conn.Receive(); err != nil {
			return
		}
		hello := p2p.Hello{
			Protocol:  p2p.ProtocolVersion,
			NetworkID: networkID,
			Height:    1 << 20,
			Work:      u256.FromUint64(1 << 20).Bytes(),
		}
		if conn.Send(p2p.KindHello, hello.MarshalHello()) != nil {
			return
		}
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				// KindGetPeers: a legal kind connSource.await never asks for
				// on the sync connection, so it is always "wrong kind" and
				// silently discarded — cheap, harmless junk that keeps
				// something perpetually in flight.
				if conn.Send(p2p.KindGetPeers, nil) != nil {
					return
				}
			}
		}
	}()
	return addr
}

// TestSyncFromEnforcesTheDeadlineAgainstAPeerThatKeepsSomethingInFlight pins
// the property TestSyncFromAbortsAStallingPeerWithinTheWholeAttemptDeadline
// cannot: the whole-attempt deadline must interrupt a read even when the
// peer never goes quiet, not only when it does.
//
// Run as many short trials rather than one, mirroring how the race was
// found: it is intermittent, not deterministic, so a single trial passing
// proves nothing, and the property worth pinning is the *bound* across many
// attempts, not any one of them. A one-shot forced deadline measurably loses
// this race often enough to matter — reverting SyncFrom's watcher to a
// single SetDeadline(time.Now()) call and running exactly this test found
// 12 trials out of 2,000 exceeding 200ms, worst case 491.8ms, against a
// 15ms configured budget. Rerunning this test's own 1,500-trial form against
// that same deliberately-reverted watcher reliably reproduces multi-hundred-
// ms outliers (observed up to ~610ms); against the fix, thousands of trials
// across repeated runs on this same (heavily loaded, many-parallel-process)
// sandbox stayed under 150ms. `bound` sits well above ordinary scheduling
// jitter and well below what a lost race produces once the attempt falls
// through to await's own per-request tolerance instead of the whole-attempt
// deadline.
func TestSyncFromEnforcesTheDeadlineAgainstAPeerThatKeepsSomethingInFlight(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.node.SyncAttemptTimeout = 500 * time.Millisecond

	// junkPeriod is the load-bearing constant here, and it has to clear a
	// higher bar than it first appears: await's own sixteen-frame counter is
	// a second, independent way for the attempt to end, so this test only
	// measures the deadline if that counter cannot finish *within the bound
	// asserted below* — not merely within the budget.
	//
	// Both weaker settings were tried and both were vacuous:
	//
	//   - At 1ms, sixteen frames arrive in ~16ms and the counter ends every
	//     attempt. Measured by raising SyncAttemptTimeout 300x, to 60s:
	//     maxElapsed stayed at 20ms, unchanged, so the budget was plainly
	//     never reached.
	//   - At 50ms, sixteen frames need ~800ms. That is above the 200ms
	//     budget, which looks sufficient, but the counter still terminated
	//     first and 810ms then sat comfortably under a 2s bound. Same
	//     diagnostic, same result: 60s budget, maxElapsed=810ms, identical
	//     on clean and fully-mutated code.
	//
	// Both therefore passed with clampDeadline neutered and the watcher
	// disabled — the whole fix removed — which is the definition of pinning
	// nothing.
	//
	// At 200ms the counter needs ~3.2s, which is above the 2s bound, so it
	// cannot be what ends a passing attempt: inside the bound, the deadline
	// is the only terminator available. The check below re-derives that
	// relationship from the constants rather than trusting this comment to
	// stay true if one of them is edited.
	const trials = 60
	const junkPeriod = 200 * time.Millisecond
	// Two seconds against a 200ms budget. The margin is deliberately wide
	// because the quantity that must not be exceeded is coarse: a failure
	// here means the attempt fell through to await's own per-read window,
	// which is twenty seconds — an order of magnitude clear of this bound,
	// and measured at exactly 20.007s when the fix is disabled by mutation.
	// A tighter bound would only trade that signal for flakes against
	// -race's scheduling latency, which was the earlier version's actual
	// failure mode (3 of 8 -race runs, all just over a 200ms bound).
	const bound = 2 * time.Second

	// The guard that keeps this test honest. await gives up after
	// awaitAttempts wrong-kind frames; at junkPeriod apart that takes
	// counterFloor. If counterFloor ever drops below `bound`, the counter
	// becomes a way for a trial to finish inside the bound without the
	// deadline doing anything, and the test silently stops measuring what
	// it is named for — which is exactly how it passed with the whole fix
	// mutated out, twice, before this check existed.
	const awaitAttempts = 16 // syncdriver.go's await loop bound
	const counterFloor = awaitAttempts * junkPeriod
	if counterFloor <= bound {
		t.Fatalf("vacuous by construction: await's %d-frame counter completes "+
			"in %s at junkPeriod=%s, which is inside the %s bound asserted "+
			"below — so a trial can pass without the whole-attempt deadline "+
			"ever firing, and this test would measure that counter instead. "+
			"Raise junkPeriod (or lower bound) until the counter cannot "+
			"finish inside the bound",
			awaitAttempts, counterFloor, junkPeriod, bound)
	}
	// And the budget itself must sit below the bound, or the deadline has no
	// room to fire inside it either.
	if victim.node.SyncAttemptTimeout >= bound {
		t.Fatalf("vacuous by construction: SyncAttemptTimeout=%s is not below "+
			"the %s bound, so the deadline cannot fire inside it",
			victim.node.SyncAttemptTimeout, bound)
	}
	var maxElapsed time.Duration
	for i := 0; i < trials; i++ {
		stop := make(chan struct{})
		addr := junkDripPeer(t, victim.chain.NetworkID(), stop, junkPeriod)

		start := time.Now()
		err := victim.node.SyncFrom(addr)
		elapsed := time.Since(start)
		close(stop)

		if err == nil {
			t.Fatalf("trial %d: SyncFrom against a peer that never sends the "+
				"awaited kind succeeded — the setup is not exercising a stall", i)
		}
		if elapsed > maxElapsed {
			maxElapsed = elapsed
		}
		if elapsed > bound {
			t.Fatalf("trial %d: SyncFrom took %s against a peer sending junk "+
				"every %s, with a %s whole-attempt deadline configured — bounded "+
				"only by await's own per-request tolerance (up to 320s), not by "+
				"SyncAttemptTimeout. This is what a forced deadline that fires "+
				"once, and never re-arms, looks like when it loses its race "+
				"against await's own SetReadDeadline reset: the interrupt is "+
				"missed once and nothing is left to reapply it for the rest of "+
				"the attempt (deadline follow-up)", i, elapsed, junkPeriod,
				victim.node.SyncAttemptTimeout)
		}
	}
	t.Logf("maxElapsed=%s", maxElapsed)
}

// TestSyncFromBoundsAWriteToAPeerThatNeverReads covers the half of the
// attempt the deadline tests above do not: the writes.
//
// node.go's writeTimeout says it "bounds every write this node makes to a
// peer connection", but syncdriver.go's three sends — the handshake in
// SyncFrom, connSource.Headers' get-headers, connSource.Body's get-block —
// were the exception: they called conn.Send, which sets no write deadline at
// all. A peer that completes the TCP and TLS handshakes and then simply never
// reads fills the socket buffer and pins the writing goroutine there, which
// is syncLoop's only goroutine.
//
// The whole-attempt watcher does still interrupt such a write, because
// closing the connection unblocks a parked Write the same way it unblocks a
// parked Read — so this was bounded at SyncAttemptTimeout rather than
// unbounded. It is now bounded at writeTimeout instead, clamped to the
// attempt deadline like every read, which is both an order of magnitude
// tighter and consistent with what writeTimeout's own doc comment claims
// about the invariant it holds.
func TestSyncFromBoundsAWriteToAPeerThatNeverReads(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	// Far longer than this test's patience, so a pass cannot be explained by
	// the whole-attempt deadline firing: only a per-write bound gets here in
	// time.
	victim.node.SyncAttemptTimeout = 5 * time.Minute

	id, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	t.Cleanup(func() {
		close(hold)
		ln.Close()
	})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept the connection and then never read a single frame from it,
		// so the victim's own writes are what has to time out.
		<-hold
	}()

	start := time.Now()
	err = victim.node.SyncFrom(ln.Addr().String())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("SyncFrom against a peer that never reads succeeded — the " +
			"setup is not exercising a blocked write")
	}
	// writeTimeout is 10s; allow generous headroom for it plus TLS setup,
	// while staying far below the 5-minute whole-attempt deadline that would
	// otherwise be the only thing bounding this.
	if elapsed > 60*time.Second {
		t.Fatalf("SyncFrom took %s against a peer that never reads, with a "+
			"5-minute whole-attempt deadline configured: the write was "+
			"bounded only by that deadline, not by writeTimeout, so "+
			"syncLoop's only goroutine is pinned for far longer than "+
			"node.go's writeTimeout invariant claims any write can be",
			elapsed)
	}
}

// TestClampDeadlineNeverExtendsPastTheAttempt pins clampDeadline directly.
//
// Every other test in this file reaches the clamp only through SyncFrom,
// where it is deliberately redundant with the whole-attempt watcher: either
// mechanism alone bounds a stalling peer, so none of them fails when only
// the clamp is broken. That is the intended design — but it leaves the clamp
// with no behavioural witness, and an unwitnessed mechanism is one that can
// be silently reverted. It was: `_ = attempt; return fresh` was committed to
// syncdriver.go once, and the entire p2p suite still passed. This test is
// what makes that impossible rather than merely unlikely.
func TestClampDeadlineNeverExtendsPastTheAttempt(t *testing.T) {
	base := time.Now()
	attempt := base.Add(time.Second)

	for _, tc := range []struct {
		name  string
		fresh time.Time
		want  time.Time
	}{
		{"fresh before attempt is kept", base.Add(100 * time.Millisecond), base.Add(100 * time.Millisecond)},
		{"fresh past attempt is clamped", base.Add(20 * time.Second), attempt},
		{"fresh equal to attempt is kept", attempt, attempt},
		{"an already-expired attempt clamps to the past", base.Add(20 * time.Second), attempt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p2p.ClampDeadlineForTest(tc.fresh, attempt); !got.Equal(tc.want) {
				t.Fatalf("clampDeadline(%s, %s) = %s, want %s: a per-operation "+
					"deadline that outlives the attempt's own budget is how a "+
					"read or write silently gets a fresh window after the "+
					"whole-attempt deadline has already passed",
					tc.fresh.Sub(base), attempt.Sub(base), got.Sub(base), tc.want.Sub(base))
			}
		})
	}

	// The property the table above is sampling, stated once as an invariant:
	// the result is never later than the attempt deadline, whatever is asked
	// for.
	for _, d := range []time.Duration{-time.Hour, 0, time.Nanosecond, time.Second, time.Hour} {
		if got := p2p.ClampDeadlineForTest(base.Add(d), attempt); got.After(attempt) {
			t.Fatalf("clampDeadline(base%+s, attempt) = base%+s, which is past "+
				"the attempt deadline", d, got.Sub(base))
		}
	}
}
