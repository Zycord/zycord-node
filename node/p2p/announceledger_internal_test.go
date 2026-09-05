package p2p

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// I8-H2, closed. These tests are the announcer's half of the finding, and they
// exist because the victim's half — thirdpartyban_internal_test.go — cannot see
// this fix at all: that file drives V's engine only, and the repair lives
// entirely in A's serve path. Asserting the closure there would be a guard that
// cannot fail, which is the defect PROTOCOL rule 24 and I8-L1 exist to catch.
//
// The property, in one sentence:
//
//	A node serves every block body it announced to a peer, even when its
//	node-wide reply ceiling has been drained by somebody else.
//
// Everything below drives that sentence or one of its bounds.

// announceLedgerFixture is A: a chain with blocks on it, an engine over that
// chain with a driveable clock, and the payer string a peer's get-block arrives
// under.
type announceLedgerFixture struct {
	*budgetFixture
	e *Engine
}

func newAnnounceLedgerFixture(t *testing.T) *announceLedgerFixture {
	t.Helper()
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	// connSet = 2 is the live two-node testnet, the finding's cheapest case:
	// the node-wide ceiling is 2 x BlockByteCapacity, two identities' worth.
	e.SetConnectionSet(2, 0)
	return &announceLedgerFixture{budgetFixture: f, e: e}
}

// drain spends A's node-wide reply ceiling from identities that are not the
// victim, and asserts it really was spent — a drain that silently failed would
// make every test below pass for the wrong reason.
func (f *announceLedgerFixture) drain(t *testing.T) {
	t.Helper()
	for i := byte(1); i <= 2; i++ {
		attacker := replyBudgetKey("203.0.113.5:5000", identity(i))
		if _, _, v := serveUntilRefused(f.e, attacker, 1_000_000); v.Reply != nil {
			t.Fatalf("attacker %d never drained its budget: the ceiling is not reachable this way", i)
		}
	}
}

// announcedBlock is the id of a block A holds, together with its body size.
func (f *announceLedgerFixture) announcedBlock(t *testing.T) (types.Hash, int) {
	t.Helper()
	id := f.ids[len(f.ids)-1]
	body, err := f.chain.BlockRaw(id)
	if err != nil {
		t.Fatalf("A does not hold the block it is about to announce: %v", err)
	}
	return id, len(body)
}

// TestADrainedNodeStillServesTheBodyItAnnounced is the closure of I8-H2 at the
// announcer, and it is the test the finding turns on.
//
// Property: a node whose node-wide reply ceiling has been drained by a third
// party still serves a body it announced to a peer that has spent nothing.
//
// Without the ledger this is exactly
// TestAThirdPartyDrainsTheSharedBudgetSoAnHonestNodeRefusesALegitimateRequest,
// which asserts the refusal. The one difference between the two setups is the
// announcement, so the announcement is what the assertion is about.
func TestADrainedNodeStillServesTheBodyItAnnounced(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	id, _ := f.announcedBlock(t)
	victim := replyBudgetKey("198.51.100.9:7000", identity(9))

	// The control, before the drain: the block is servable at all, so a
	// refusal after the drain cannot be read as the block having been
	// unavailable all along.
	if v := f.e.OnGetBlock(replyBudgetKey("198.51.100.7:6000", identity(8)), (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()); v.Reply == nil {
		t.Fatalf("get-block is not servable on this fixture at all: %+v", v)
	}

	f.e.recordAnnounced(victim, id, f.e.wallClock())
	f.drain(t)

	// The anti-vacuity check, and it is the one that matters here: a peer with
	// NO promise must still be refused, or the drain did not take and the
	// assertion below is measuring an unconstrained budget.
	stranger := replyBudgetKey("198.51.100.11:7100", identity(10))
	if v := f.e.OnGetBlock(stranger, (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()); v.Reply != nil {
		t.Fatalf("a peer holding no promise was served past the drained ceiling: %+v", v)
	}

	v := f.e.OnGetBlock(victim, (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock())
	if v.Reply == nil {
		t.Fatalf("A refused a body it announced, because a third party drained its node-wide ceiling: %+v (err %v)", v, v.Err)
	}
	if v.Reply.Kind != KindBlock {
		t.Fatalf("served %v, want a block chunk", v.Reply.Kind)
	}
	if v.Score != 0 {
		t.Fatalf("the announced peer was scored %d for redeeming a promise", v.Score)
	}
}

// TestAPromiseIsSpentOnceAndTheSecondRequestIsRefusedAsBefore bounds the lane.
//
// Property: redemption is capped by cumulative bytes per (peer, block), so a
// promise is not a standing exemption from the ceiling.
//
// The cap is announcedRedemptionFactor bodies, so on the one-chunk regime every
// committed parameter set produces today that is two served chunks and then the
// ordinary refusal. The second redemption is the retry slack the chunked regime
// needs; the third is the re-request lane the cap exists to close.
func TestAPromiseIsSpentOnceAndTheSecondRequestIsRefusedAsBefore(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	id, body := f.announcedBlock(t)
	victim := replyBudgetKey("198.51.100.9:7000", identity(9))
	req := (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()

	f.e.recordAnnounced(victim, id, f.e.wallClock())
	f.drain(t)

	// The setup this test is about: the body is one chunk here, so one
	// redemption is one whole body and the cap is reached in exactly
	// announcedRedemptionFactor requests. If an era re-pin ever made bodies
	// multi-chunk this assertion is what says so, rather than the count below
	// silently meaning something else.
	if ChunkCount(body) != 1 {
		t.Fatalf("this fixture's body is %d chunks; the per-request accounting below assumes one", ChunkCount(body))
	}

	served := 0
	for i := 0; i < announcedRedemptionFactor+3; i++ {
		v := f.e.OnGetBlock(victim, req)
		if v.Reply == nil {
			break
		}
		served++
	}
	if served != announcedRedemptionFactor {
		t.Fatalf("a promise redeemed %d times, want %d: redemption is capped by cumulative bytes at %dx the body",
			served, announcedRedemptionFactor, announcedRedemptionFactor)
	}

	// And past the cap the peer is an ordinary over-budget asker again: the
	// same silent, unscored refusal it would have had with no promise at all.
	v := f.e.OnGetBlock(victim, req)
	if v.Reply != nil {
		t.Fatalf("a spent promise still served: %+v", v)
	}
	if v.Score != 0 {
		t.Fatalf("a spent promise scored the asker %d; a budget refusal is a price and not a judgement", v.Score)
	}
	if !errors.Is(v.Err, ErrReplyBudget) {
		t.Fatalf("refused with %v, want ErrReplyBudget", v.Err)
	}
}

// TestAPromiseCoversOnlyTheBlockItNames bounds the lane in the other direction.
//
// Property: a promise about one block buys nothing for any other block, so an
// announcement is not a general exemption from the ceiling.
func TestAPromiseCoversOnlyTheBlockItNames(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	promised, _ := f.announcedBlock(t)
	other := f.ids[len(f.ids)-2]
	if promised == other {
		t.Fatal("the fixture handed back the same block twice")
	}
	victim := replyBudgetKey("198.51.100.9:7000", identity(9))

	f.e.recordAnnounced(victim, promised, f.e.wallClock())
	f.drain(t)

	if v := f.e.OnGetBlock(victim, (GetBlock{ID: promised, Chunk: 0}).MarshalGetBlock()); v.Reply == nil {
		t.Fatalf("the promised block was refused: %+v", v)
	}
	if v := f.e.OnGetBlock(victim, (GetBlock{ID: other, Chunk: 0}).MarshalGetBlock()); v.Reply != nil {
		t.Fatalf("a promise about one block served another: %+v", v)
	}
}

// TestAPromiseCoversOnlyThePeerItWasMadeTo is the third bound, and it is the one
// that keeps the lane from being an amplifier under identity churn.
//
// Property: a promise is keyed on the payer it was announced to, so a peer that
// was never announced anything cannot redeem another peer's promise.
func TestAPromiseCoversOnlyThePeerItWasMadeTo(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	id, _ := f.announcedBlock(t)
	announced := replyBudgetKey("198.51.100.9:7000", identity(9))
	stranger := replyBudgetKey("198.51.100.10:7000", identity(10))

	f.e.recordAnnounced(announced, id, f.e.wallClock())
	f.drain(t)

	if v := f.e.OnGetBlock(stranger, (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()); v.Reply != nil {
		t.Fatalf("a peer this node never announced to redeemed somebody else's promise: %+v", v)
	}
	if v := f.e.OnGetBlock(announced, (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()); v.Reply == nil {
		t.Fatalf("the announced peer was refused: %+v", v)
	}
}

// TestAPromiseExpires bounds the lane in time.
//
// Property: a promise past announcedTTL is not redeemable, so the ledger cannot
// be turned into a standing reservation by announcing once and asking later.
func TestAPromiseExpires(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	id, _ := f.announcedBlock(t)
	victim := replyBudgetKey("198.51.100.9:7000", identity(9))

	f.e.recordAnnounced(victim, id, f.e.wallClock())

	// The drain is re-applied after every clock move, and that is not
	// housekeeping. The node-wide ceiling refills every TargetBlockSeconds — 5 s
	// on devnet against a 120 s TTL — so a test that advanced the clock and did
	// not re-drain would be asserting against a REFILLED budget, and every
	// request would be served on the ordinary path with the ledger untouched.
	// That version of this test passed while measuring nothing.
	f.drain(t)

	// One second inside the TTL still redeems, so the assertion below is about
	// the boundary and not about the ledger being empty for some other reason.
	f.clock += uint64(announcedTTL/time.Second) - 1
	f.drain(t)
	if v := f.e.OnGetBlock(victim, (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()); v.Reply == nil {
		t.Fatalf("a promise inside its TTL was refused: %+v", v)
	}

	// Past it, and a fresh promise for a different block so the byte cap on the
	// first one is not what refuses.
	other := f.ids[len(f.ids)-2]
	f.e.recordAnnounced(victim, other, f.e.wallClock())
	f.clock += uint64(announcedTTL/time.Second) + 2
	f.drain(t)
	if v := f.e.OnGetBlock(victim, (GetBlock{ID: other, Chunk: 0}).MarshalGetBlock()); v.Reply != nil {
		t.Fatalf("a promise past announcedTTL still redeemed: %+v", v)
	}
}

// TestTheAnnouncedLedgerIsBoundedPerPeer is the memory bound.
//
// Property: the promises held for one peer never exceed maxAnnouncedPerPeer,
// however many announcements go to it.
//
// There is no announce storm in production to drive this — an announcement costs
// its sender a block — so the bound is asserted directly against the ledger
// rather than through a scenario that cannot occur.
func TestTheAnnouncedLedgerIsBoundedPerPeer(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	victim := replyBudgetKey("198.51.100.9:7000", identity(9))
	now := f.e.wallClock()
	for i := 0; i < maxAnnouncedPerPeer*4; i++ {
		var id types.Hash
		id[0], id[1] = byte(i), byte(i>>8)
		f.e.recordAnnounced(victim, id, now)
	}
	if got := f.e.AnnouncedPromises(victim); got != maxAnnouncedPerPeer {
		t.Fatalf("the ledger holds %d promises for one peer, want at most %d", got, maxAnnouncedPerPeer)
	}
}

// TestTheAnnouncedLedgerIsReapedAcrossPeers is the other memory bound, and it is
// the one a per-peer cap does not reach: the number of distinct payers.
//
// Property: promises past announcedTTL are dropped from every payer's bucket on
// the sweep that already reaps pending and seenBlocks, and a payer left with no
// promises is dropped with them.
func TestTheAnnouncedLedgerIsReapedAcrossPeers(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	now := f.e.wallClock()
	const peers = 64
	for i := 0; i < peers; i++ {
		var id types.Hash
		id[0] = byte(i)
		f.e.recordAnnounced(replyBudgetKey("198.51.100.9:7000", identity(byte(i))), id, now)
	}
	f.e.mu.Lock()
	before := len(f.e.announced)
	f.e.mu.Unlock()
	if before != peers {
		t.Fatalf("the ledger holds %d payers, want %d — the setup did not take", before, peers)
	}

	f.e.ReapUnservedBodies(now.Add(announcedTTL + time.Second))

	f.e.mu.Lock()
	after := len(f.e.announced)
	f.e.mu.Unlock()
	if after != 0 {
		t.Fatalf("%d payers survived the reap past announcedTTL, want 0", after)
	}
}

// TestAnOutboundAnnouncementRecordsAPromiseAtTheBroadcastSeam covers the seam
// rather than the map, which is the lesson I8-H1b left behind: a guard proven
// against a direct call to the thing it guards says nothing about whether the
// production path reaches it.
//
// Property: Node.Broadcast of a KindBlockAnnounce records a promise for every
// connection it sent to, under the same payer string the serve path will be
// handed, and records nothing for any other message kind.
func TestAnOutboundAnnouncementRecordsAPromiseAtTheBroadcastSeam(t *testing.T) {
	f := newAnnounceLedgerFixture(t)
	id, _ := f.announcedBlock(t)
	hdr, err := f.chain.CanonicalHeader(id)
	if err != nil {
		t.Fatal(err)
	}

	nodeID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(nodeID, f.e, peers, 1)

	const addr = "10.7.0.2:9421"
	peerID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	// The far end must be drained or SendDeadline blocks to its deadline and
	// the send fails, which would make the "no promise" assertions below pass
	// for the wrong reason. The reader is what makes this a successful send.
	go io.Copy(io.Discard, remote)
	c := &Conn{Conn: local, Addr: addr, PeerKey: peerID.PublicKey()}
	n.conns[addr] = c

	payer := replyBudgetKey(addr, peerID.PublicKey())

	// A message that is not an announcement promises nothing.
	n.Broadcast(KindCertificate, []byte{0}, "")
	if got := f.e.AnnouncedPromises(payer); got != 0 {
		t.Fatalf("a non-announcement recorded %d promises, want 0", got)
	}

	ann := BlockAnnounce{Header: *hdr}
	n.Broadcast(KindBlockAnnounce, ann.MarshalAnnounce(), "")
	if got := f.e.AnnouncedPromises(payer); got != 1 {
		t.Fatalf("Broadcast of an announcement recorded %d promises for %s, want 1", got, addr)
	}

	// And the promise is the right one: it redeems the announced block past a
	// drained ceiling, which is the whole point of recording it.
	f.drain(t)
	if v := f.e.OnGetBlock(payer, (GetBlock{ID: id, Chunk: 0}).MarshalGetBlock()); v.Reply == nil {
		t.Fatalf("the promise recorded at the Broadcast seam did not redeem: %+v", v)
	}
}

// TestAThirdPartyDrainDoesNotBanAnHonestMinerAcrossTwoEngines is I8-H2 driven end
// to end across BOTH endpoints, which is what the V-side test in
// thirdpartyban_internal_test.go structurally cannot do.
//
// Property: with A's node-wide ceiling drained by a third party throughout,
// twelve of A's announcements to V leave V's score against A at zero on both
// tallies, and V tracks A block for block.
//
// It is the same twelve-round setup as the V-side test, with A's serve path
// spliced in where that test simply let the body never arrive. The drain is
// re-applied every round, after the announcement, because the node-wide bucket
// refills each TargetBlockSeconds — a sustained drain is the condition that
// defeated the requester-retry candidate, so it is the condition this has to
// survive, and re-draining is what keeps the test from measuring a refilled
// budget.
func TestAThirdPartyDrainDoesNotBanAnHonestMinerAcrossTwoEngines(t *testing.T) {
	p := spec.Devnet()
	open := func() *chain.Chain {
		c, err := chain.Open(t.TempDir(), p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	aChain, vChain := open(), open()

	// A: the honest miner, with its own engine, its own clock, and a node-wide
	// ceiling a third party is about to drain.
	aPeers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	a := NewEngine(aChain, mempool.New(p, mempool.DefaultPolicy()), aPeers, pow.Dev{}, "n:2")
	aClock := uint64(1_700_000_017)
	a.Now = func() time.Time { return time.Unix(int64(aClock), 0) }
	a.SetConnectionSet(2, 0)

	// V: the victim, at the Node seam so both tallies move.
	vPeers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	v := NewEngine(vChain, mempool.New(p, mempool.DefaultPolicy()), vPeers, pow.Dev{}, "n:1")
	vID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	vNode := NewNode(vID, v, vPeers, 1)

	const honest = "10.7.0.1:9421"
	vPeers.Add(honest)
	aID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aKey := aID.PublicKey()
	vNode.conns[honest] = &Conn{Addr: honest, PeerKey: aKey}

	// The payer string V's get-block arrives at A under. V dials A, so this is
	// A's own listen address paired with A's view of V's identity — what
	// matters is only that the two halves agree, which is the property
	// replyBudgetKey exists to give.
	vAtA := replyBudgetKey("10.7.0.9:9421", vID.PublicKey())

	m := &miner.Miner{
		Chain: aChain, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: pow.Dev{},
		Payout: [32]byte{0x02, 7, 7, 7},
		Now:    func() uint64 { return aChain.Tip().Time + p.TargetBlockSeconds },
	}

	// The third party drains A's node-wide ceiling and keeps it drained: the
	// bucket refills every TargetBlockSeconds, so the drain is re-applied each
	// round exactly as a sustained flood would. This is the condition that
	// defeated the requester-retry candidate, so it is the condition the fix
	// has to survive.
	drain := func() {
		t.Helper()
		for i := byte(1); i <= 2; i++ {
			attacker := replyBudgetKey("203.0.113.5:5000", identity(i))
			serveUntilRefused(a, attacker, 1_000_000)
		}
		if v := a.OnGetBlock(replyBudgetKey("203.0.113.6:5000", identity(3)),
			(GetBlock{ID: aChain.Tip().ID(), Chunk: 0}).MarshalGetBlock()); v.Reply != nil {
			t.Fatal("the drain did not take: an unpromised stranger was still served")
		}
	}

	const rounds = 12
	vTipAtStart := vChain.Tip().ID()
	now := time.Now()
	accepted, namedVsTip, servedByA := 0, 0, 0
	for round := 0; round < rounds; round++ {
		blk, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("round %d: A could not mine on its own chain: %v", round, err)
		}
		id := blk.Header.ID()
		if blk.Header.ParentID == vChain.Tip().ID() {
			namedVsTip++
		}

		// A announces to V, which is what records the promise. Recorded through
		// the engine rather than through Node.Broadcast because this test needs
		// two engines and not two sockets; the seam that Broadcast really
		// reaches this call is pinned by the test above.
		a.recordAnnounced(vAtA, id, a.wallClock())

		// The drain is re-applied here, AFTER the announcement, so the promise
		// is not simply being redeemed against a ceiling that had refilled.
		drain()

		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		vd := v.OnBlockAnnounce(honest, ann.MarshalAnnounce())
		if vd.Err != nil {
			t.Fatalf("round %d: an honest miner's announcement was refused: %v", round, vd.Err)
		}
		if vd.Reply == nil || vd.Reply.Kind != KindGetBlock {
			t.Fatalf("round %d: the announcement produced no get-block (%+v)", round, vd.Reply)
		}
		accepted++

		// V's get-block reaches A's serve path. This is the line the whole
		// finding turns on: before the fix A refused here, silently, because a
		// third party had spent its node-wide ceiling.
		av := a.OnGetBlock(vAtA, vd.Reply.Payload)
		if av.Reply == nil {
			t.Fatalf("round %d: A refused the body it had just announced (err %v) — I8-H2 is not closed", round, av.Err)
		}
		servedByA++

		// And V receives it, which is what clears the pending entry the reap
		// would otherwise charge.
		bv := v.OnBlockChunk(honest, av.Reply.Payload)
		if bv.Err != nil && !errors.Is(bv.Err, chain.ErrUnknownAncestor) &&
			!errors.Is(bv.Err, chain.ErrWrongParent) {
			t.Fatalf("round %d: V could not take the body A served: %v", round, bv.Err)
		}

		now = now.Add(PendingBodyTimeout + time.Second)
		vNode.reapUnservedBodies(now)
		aClock += p.TargetBlockSeconds
	}

	// The shape is the point, so it is asserted rather than assumed — the same
	// three checks the V-side test makes, because a fix that quietly changed
	// the shape would have proved nothing.
	if accepted != rounds {
		t.Fatalf("only %d of %d announcements were accepted", accepted, rounds)
	}
	if servedByA != rounds {
		t.Fatalf("A served %d of %d announced bodies past its drained ceiling", servedByA, rounds)
	}
	// **The shape inverts, and that is the result rather than a complication.**
	//
	// thirdpartyban_internal_test.go asserts that V's tip NEVER advances and
	// that exactly 1 of 12 announcements names it: under the drain A serves
	// nothing, so V is frozen and A runs away from it, and every announcement
	// after the first arrives as an orphan. That shape is what defeated the
	// tip-extension candidate — the discriminator was sound and covered 1
	// charge in 12.
	//
	// With the promise honoured V is not frozen: it receives each body, applies
	// it, and tracks A block for block. So all 12 announcements name V's tip
	// here, and V's height matches A's at the end. Asserting that is what stops
	// this test passing for a lazy reason: a fix that made A serve nothing while
	// V happened not to charge would leave V at height 0, and a fix that made V
	// stop charging without A serving would leave namedVsTip at 1. Both are
	// caught here.
	if vChain.Height() != aChain.Height() {
		t.Fatalf("V is at height %d and A at %d: V did not track A, so the bodies A served did not arrive",
			vChain.Height(), aChain.Height())
	}
	if vChain.Tip().ID() == vTipAtStart {
		t.Fatal("V's tip never moved: A served no body V could apply, so nothing here measures a promise being kept")
	}
	if namedVsTip != rounds {
		t.Fatalf("%d of %d announcements named V's tip, want all %d: a V that keeps up sees every announcement as a tip-extension",
			namedVsTip, rounds, rounds)
	}

	got, _ := vPeers.Get(honest)
	t.Logf("I8-H2 (closed): %d announcements, %d served by A, %d named V's tip, addr score %d, addr banned=%v, identity banned=%v",
		accepted, servedByA, namedVsTip, got.Score, vPeers.Banned(honest), vPeers.BannedKey(aKey))

	// **The closure.** This is the inverse of thirdpartyban_internal_test.go's
	// final assertion, driven where a fix at A can actually reach it.
	if vPeers.Banned(honest) || vPeers.BannedKey(aKey) {
		t.Fatalf("an honest miner was still banned by a third party's drain (addr score %d, addr banned=%v, identity banned=%v)",
			got.Score, vPeers.Banned(honest), vPeers.BannedKey(aKey))
	}
	if got.Score < 0 {
		t.Fatalf("V charged the honest miner %d for bodies it served", got.Score)
	}
}
