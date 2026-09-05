package p2p

import (
	"errors"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// I8-H2: a third party gets an honest peer permanently banned at a victim it
// never contacts.
//
// OnGetBlock refuses an over-budget request with no reply and no retry. The
// second arm of that budget is node-wide — a shared `connSet × BlockByteCapacity`
// ceiling keyed on nothing — so an attacker who floods honest miner A until the
// ceiling is spent makes A refuse victim V's legitimate get-block. V's request
// WAS sent, so its pending entry is legitimate (unlike I8-H1) and times out; V
// charges A ScoreUnservedBody, and ten blocks later bans A on both tallies. The
// score persists to disk with no decay, so the ban is permanent — and the
// attacker was never connected to V.
//
// On a small network the ceiling is the cheap case, not the safe one: at
// connSet = 2 (the live testnet) it is 2 × BlockByteCapacity = two identities'
// worth of traffic, barely above the per-peer budget it backs.
//
// The fix bounds ScoreUnservedBody's downward reach at ScoreUnservedBodyFloor,
// above ScoreBanThreshold: this ambiguous, unattributable signal can leave a
// peer heavily penalised but never bans it alone. This test drove A to −120,
// banned, against the pre-fix tree; it settles at the floor, unbanned, now.
//
// The first half proves the premise a reading confirmed and this exercises: the
// drained node-wide budget really does make an honest node refuse a legitimate
// request, with no reply and no score against the requester.
func TestAThirdPartyDrainsTheSharedBudgetSoAnHonestNodeRefusesALegitimateRequest(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	// connSet = 2 is the live two-node testnet: node ceiling = 2 ×
	// BlockByteCapacity, the finding's cheapest case.
	e.SetConnectionSet(2, 0)

	block := GetBlock{ID: f.ids[len(f.ids)-1], Chunk: 0}.MarshalGetBlock()

	// Control BEFORE the drain: the block is servable, so a refusal after the
	// drain cannot be read as the budget working when the block was unservable
	// all along.
	if v := e.OnGetBlock(replyBudgetKey("198.51.100.7:6000", identity(9)), block); v.Reply == nil {
		t.Fatalf("get-block is not servable on this fixture at all: %+v", v)
	}

	// Two attacker identities spend the shared ceiling. Each drains its own
	// whole per-identity budget (BlockByteCapacity); together they reach the
	// node-wide ceiling (connSet × BlockByteCapacity).
	for i := byte(1); i <= 2; i++ {
		attacker := replyBudgetKey("203.0.113.5:5000", identity(i))
		if _, _, v := serveUntilRefused(e, attacker, 1_000_000); v.Reply != nil {
			t.Fatalf("attacker %d never drained its budget: the ceiling is not reachable this way", i)
		}
	}

	// A fresh victim that has spent nothing of its own budget. A refuses it on
	// the shared node-wide arm.
	victim := replyBudgetKey("198.51.100.9:7000", identity(9))
	v := e.OnGetBlock(victim, block)
	if v.Reply != nil {
		t.Fatalf("the honest node served V despite its node-wide budget being spent by a third party: %+v", v)
	}
	if v.Score != 0 {
		t.Fatalf("V was scored %d for a refusal caused by another peer's flood: a shared-ceiling refusal must be unscored", v.Score)
	}
	if !errors.Is(v.Err, ErrReplyBudget) {
		t.Fatalf("refused with %v, want ErrReplyBudget — the budgeted refusal that reaches V as plain silence", v.Err)
	}
}

// TestAThirdPartyDrainingTheSharedBudgetCannotBanAnHonestPeer is the consequence
// at V, and the before/after the fix turns on. It bans on the pre-fix tree
// (measured: −120, both tallies) and must not now.
//
// Driven at the Node seam so BOTH tallies the reap charges move: the address
// (Engine.ReapUnservedBodies) and the identity (Node.reapUnservedBodies). The
// ban check is Banned(addr) || BannedKey(key), so a fix to only one half would
// still ban on the other — this catches that.
//
// The announcements go through OnBlockAnnounce, so each one genuinely produces
// the get-block V sends: the pending entry is a request that LEFT this node,
// which is what makes this I8-H2 (V's books are correct) and not I8-H1 (a request
// this node never sent). Nothing here forgets the entry — the body simply never
// arrives, because A refused it, which the test above establishes.
//
// The mined blocks extend V's tip, so each is a genuine tip-extension — the case
// the bound covers, asserted in the loop (announcedBody.atTip). That is the axis
// of the fix: a tip-extension carries real proof-of-work and cannot be minted
// cheaply, so bounding its charge cannot disarm the ghost-flood ban, which fires
// on cheap orphan announcements and is pinned by the ghost-flood tests.
func TestAThirdPartyDrainingTheSharedBudgetCannotBanAnHonestPeer(t *testing.T) {
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
	pool := mempool.New(p, mempool.DefaultPolicy())
	work := &countingPoW{}
	e := NewEngine(c, pool, peers, work, "n:1")
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, e, peers, 1)

	const honest = "10.7.0.1:9421"
	peers.Add(honest)
	announcer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key := announcer.PublicKey()
	n.conns[honest] = &Conn{Addr: honest, PeerKey: key}

	mine := func(payout byte) *types.Block {
		m := &miner.Miner{
			Chain: c, Pool: pool, Engine: work,
			Payout: [32]byte{0x02, payout, payout, payout},
			Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
		}
		b, err := m.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Seal(b, 1<<20); err != nil {
			t.Fatal(err)
		}
		return b
	}

	// Twelve is past the ban threshold at ScoreUnservedBody: 12 × −10 = −120,
	// which is how the pre-fix tree reached −120 < ScoreBanThreshold.
	const rounds = 12
	now := time.Now()
	for round := 0; round < rounds; round++ {
		blk := mine(byte(round + 1))
		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		v := e.OnBlockAnnounce(honest, ann.MarshalAnnounce())
		if v.Err != nil {
			t.Fatalf("round %d: the honest announcement was refused: %v", round, v.Err)
		}
		// Anti-vacuity: the announcement must have produced the get-block V
		// sends, or there is no legitimately-requested body to go unserved and
		// this measures nothing.
		if v.Reply == nil || v.Reply.Kind != KindGetBlock {
			t.Fatalf("round %d: the announcement produced no get-block (%+v); "+
				"without a request that left this node there is no I8-H2 to reproduce", round, v.Reply)
		}
		e.mu.Lock()
		entry, waiting := e.pending[blk.Header.ID()]
		e.mu.Unlock()
		if !waiting {
			t.Fatalf("round %d: no pending entry was written", round)
		}
		// Anti-vacuity on the discriminator: this must be a tip-extension, or the
		// reap would charge it unbounded and the test would exercise the wrong
		// path (and could not distinguish the fix from a no-op).
		if !entry.atTip {
			t.Fatalf("round %d: the announcement was not recorded as a tip-extension; "+
				"the bound under test applies only to atTip entries", round)
		}

		// The body never arrives — A refused it because a third party drained
		// its node-wide budget. The request was genuine, so nothing forgets the
		// entry; PendingBodyTimeout elapses and V charges A on both tallies.
		now = now.Add(PendingBodyTimeout + time.Second)
		n.reapUnservedBodies(now)
	}

	got, _ := peers.Get(honest)
	if peers.Banned(honest) || peers.BannedKey(key) {
		t.Fatalf("a third party draining the shared reply budget drove an honest peer "+
			"to a ban (addr score %d, addr banned=%v, identity banned=%v): %d blocks it "+
			"announced and could not serve because its node-wide budget was spent by traffic "+
			"V never saw. The attacker is not connected to V at all.",
			got.Score, peers.Banned(honest), peers.BannedKey(key), rounds)
	}

	// Anti-vacuity on the fix: the charges must have LANDED and stopped exactly
	// at the floor. A score that never moved would pass the ban check above
	// while proving nothing; a floor set wrong would show here.
	if got.Score != ScoreUnservedBodyFloor {
		t.Fatalf("the address score settled at %d, want the floor %d (charges must land, and stop at the floor)",
			got.Score, ScoreUnservedBodyFloor)
	}
	if ks := identityScore(t, peers, key); ks != ScoreUnservedBodyFloor {
		t.Fatalf("the identity score settled at %d, want the floor %d", ks, ScoreUnservedBodyFloor)
	}
}

// TestTheUnservedBodyFloorDoesNotWeakenAnAttributableBan is the other side of
// the trade the fix makes: bounding ScoreUnservedBody must leave every
// ATTRIBUTABLE penalty able to ban, or it would be a hole rather than a fix.
func TestTheUnservedBodyFloorDoesNotWeakenAnAttributableBan(t *testing.T) {
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	// An attributable charge (ScoreInvalidMessage) still reaches the ban
	// threshold on its own — the fix touches only the unserved-body charge.
	const addr = "10.9.9.9:9421"
	peers.Add(addr)
	for i := 0; i < 5; i++ { // 5 × −20 = −100
		peers.Adjust(addr, ScoreInvalidMessage)
	}
	if !peers.Banned(addr) {
		got, _ := peers.Get(addr)
		t.Fatalf("an attributable charge no longer bans (score %d): the floor was applied where it must not be", got.Score)
	}

	// And a peer already parked at the unserved-body floor still crosses into a
	// ban when it earns an attributable charge — the bound blocks the ambiguous
	// signal, it does not shelter a peer from a real one.
	const mixed = "10.9.9.10:9421"
	peers.Add(mixed)
	for i := 0; i < 12; i++ {
		peers.AdjustNotBelow(mixed, ScoreUnservedBody, ScoreUnservedBodyFloor)
	}
	if peers.Banned(mixed) {
		t.Fatal("the unserved-body floor failed to hold: a run of unserved-body charges banned")
	}
	// ScoreUnservedBodyFloor is -50; a run of attributable -20s from there still
	// reaches -100.
	for i := 0; i < 3; i++ { // -50, then 3 × -20 = -110
		peers.Adjust(mixed, ScoreInvalidMessage)
	}
	if !peers.Banned(mixed) {
		got, _ := peers.Get(mixed)
		t.Fatalf("a peer at the unserved-body floor was sheltered from an attributable ban (score %d)", got.Score)
	}
}
