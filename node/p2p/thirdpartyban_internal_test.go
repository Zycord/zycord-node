package p2p

import (
	"errors"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// I8-H2: a third party gets an honest peer permanently banned at a victim it
// never contacts. **This finding is OPEN. Both tests below describe the defect
// as it stands, and the second one ASSERTS IT.** When I8-H2 is closed, the
// second test's final assertion is the one that must be inverted.
//
// `OnGetBlock` refuses an over-budget request with no reply and no retry. The
// second arm of that budget is node-wide — a shared `connSet × BlockByteCapacity`
// ceiling keyed on nothing — so an attacker who floods honest miner A until the
// ceiling is spent makes A refuse victim V's legitimate get-block. V's request
// WAS sent, so its pending entry is legitimate (unlike I8-H1) and times out; V
// charges A ScoreUnservedBody and, twelve blocks later, has banned A on both
// tallies. The score persists to disk with no decay, so the ban is permanent.
//
// On a small network the ceiling is the cheap case, not the safe one: at
// connSet = 2 (the live testnet) it is 2 × BlockByteCapacity = two identities'
// worth of traffic, barely above the per-peer budget it backs.
//
// The first test proves the premise: a drained node-wide budget really does make
// an honest node refuse a legitimate request, with no reply and no score against
// the requester — so A's silence at V is caused by a third party and is
// unattributable.
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

// TestAThirdPartyStillDrivesAnHonestPeerToABan is the consequence at V, driven on
// the shape the attack actually has. **It asserts the OPEN defect: the honest
// peer IS banned.** Invert the final assertion when I8-H2 is closed.
//
// The shape matters, and an earlier version of this test got it wrong in the
// direction that flatters a fix. A real miner builds each block on **its own**
// tip. Under the drain A serves nothing on any path — KindGetBlock is the single
// dispatch case for both the announce fetch and the sync body fetch — so **V's
// tip never advances**. A therefore runs away from V: only A's FIRST
// announcement names V's tip, and every one after it is, at V, an orphan whose
// parent V does not hold.
//
// So A and V get separate chains here, and A mines with MineOne, which applies
// each block and advances A's tip. Mining siblings on V's own chain object
// instead (Assemble/Seal, never advancing) makes every announcement a
// tip-extension and is not this attack — that is the mistake this comment exists
// to stop the next author repeating.
//
// Driven at the Node seam so BOTH tallies move: the address
// (Engine.ReapUnservedBodies) and the identity (Node.reapUnservedBodies). The
// ban check is Banned(addr) || BannedKey(key).
func TestAThirdPartyStillDrivesAnHonestPeerToABan(t *testing.T) {
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

	vPeers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	v := NewEngine(vChain, mempool.New(p, mempool.DefaultPolicy()), vPeers, pow.Dev{}, "n:1")
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, v, vPeers, 1)

	const honest = "10.7.0.1:9421"
	vPeers.Add(honest)
	announcer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key := announcer.PublicKey()
	n.conns[honest] = &Conn{Addr: honest, PeerKey: key}

	m := &miner.Miner{
		Chain: aChain, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: pow.Dev{},
		Payout: [32]byte{0x02, 7, 7, 7},
		Now:    func() uint64 { return aChain.Tip().Time + p.TargetBlockSeconds },
	}

	// Twelve × ScoreUnservedBody = −120, past ScoreBanThreshold at −100.
	const rounds = 12
	vTipAtStart := vChain.Tip().ID()
	now := time.Now()
	accepted, namedVsTip := 0, 0
	for round := 0; round < rounds; round++ {
		blk, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("round %d: A could not mine on its own chain: %v", round, err)
		}
		if blk.Header.ParentID == vChain.Tip().ID() {
			namedVsTip++
		}
		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		vd := v.OnBlockAnnounce(honest, ann.MarshalAnnounce())
		if vd.Err != nil {
			t.Fatalf("round %d: an honest miner's announcement was refused: %v", round, vd.Err)
		}
		// Anti-vacuity: each announcement must produce the get-block V sends, or
		// there is no legitimately-requested body to go unserved and this
		// measures nothing. This is what makes it I8-H2 and not I8-H1.
		if vd.Reply == nil || vd.Reply.Kind != KindGetBlock {
			t.Fatalf("round %d: the announcement produced no get-block (%+v)", round, vd.Reply)
		}
		accepted++

		// The body never arrives: A refused it because a third party drained its
		// node-wide budget (the test above). Nothing forgets the entry, so
		// PendingBodyTimeout elapses and V charges A on both tallies.
		now = now.Add(PendingBodyTimeout + time.Second)
		n.reapUnservedBodies(now)
	}

	// The shape is the point, so it is asserted rather than assumed.
	if accepted != rounds {
		t.Fatalf("only %d of %d announcements were accepted; the reap had nothing to charge for the rest", accepted, rounds)
	}
	if vChain.Tip().ID() != vTipAtStart {
		t.Fatal("V's tip advanced; under the drain V can never apply a block, and a moving tip would make every announcement a tip-extension")
	}
	if namedVsTip != 1 {
		t.Fatalf("%d of %d announcements named V's tip, want exactly 1: A runs away from a stuck V, so only its first block extends V's tip",
			namedVsTip, rounds)
	}

	got, _ := vPeers.Get(honest)
	t.Logf("I8-H2 (open): %d announcements, %d named V's tip, addr score %d, addr banned=%v, identity banned=%v",
		accepted, namedVsTip, got.Score, vPeers.Banned(honest), vPeers.BannedKey(key))

	// **The open defect.** Invert this when I8-H2 is closed.
	if !vPeers.Banned(honest) || !vPeers.BannedKey(key) {
		t.Fatalf("I8-H2 appears closed (addr score %d, addr banned=%v, identity banned=%v). "+
			"If that is intended, invert this assertion and update docs/adversarial/I8-p2p.md",
			got.Score, vPeers.Banned(honest), vPeers.BannedKey(key))
	}
}
