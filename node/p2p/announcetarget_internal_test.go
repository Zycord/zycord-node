package p2p

import (
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
	"zycord/wallet"
)

// announceChain builds a chain and an engine on it, deep enough that
// RecentHeaders(DifficultyWindow+1) reads a real window rather than a short
// prefix when the caller asks for one.
func announceChain(tb testing.TB, blocks int) (*chain.Chain, *Engine, *epochCountingPoW) {
	tb.Helper()
	p := spec.Devnet()
	c, err := chain.Open(tb.TempDir(), p)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		tb.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	wk, err := wallet.KeyFromSeed(seed)
	if err != nil {
		tb.Fatal(err)
	}
	clock := p.GenesisTime
	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{}, Payout: wk.Persistent(),
		Now: func() uint64 { clock += p.TargetBlockSeconds; return clock },
	}
	for i := 0; i < blocks; i++ {
		if _, _, err := m.MineOne(1 << 22); err != nil {
			tb.Fatal(err)
		}
	}
	// The engine hashes through a counter so a test can assert that a header
	// refused by the target check never reached the work function at all.
	counter := newEpochCounter()
	return c, NewEngine(c, pool, peers, counter, "n:1"), counter
}

// tipHeaderAt builds an announcement header naming c's tip as its parent,
// carrying the target given, and solved against that target.
func tipHeaderAt(tb testing.TB, c *chain.Chain, target u256.U256, salt uint64) types.Header {
	tb.Helper()
	p := c.Params()
	tip := c.Tip()
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   tip.Height + 1,
		ParentID: tip.ID(),
		Time:     tip.Time + p.TargetBlockSeconds,
		CertRoot: certRoot(nil, p),
		Target:   target,
		PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(tip.Height+1, p)},
	}
	for n := uint64(0); n < 1<<22; n++ {
		h.PoW.Nonce = n ^ (salt << 40)
		if pow.CheckWork(pow.Dev{}, h, p) == nil {
			return h
		}
	}
	tb.Fatalf("no solution for target %s", target.String())
	return h
}

func ruleTarget(c *chain.Chain) u256.U256 {
	p := c.Params()
	return pow.NextTarget(c.RecentHeaders(int(p.DifficultyWindow)+1), p)
}

// TestAGhostOnTheReceiversOwnTipIsRefusedInsteadOfRelayed is the ghost-
// announcement attack at the one distance the receiver can answer it.
//
// The header names **this node's own tip** as its parent and declares
// `max_target`, which no digest can exceed, so `pow.CheckWork` passes it for
// about thirty-one expected hashes on devnet and sixty-four on mainnet. Before
// the announce path re-derived the target, that header was entered into
// `seenBlocks`, entered into `pending` keyed to the connection it arrived on,
// and returned `Forward: true` — and `ReapUnservedBodies` then charged
// `ScoreUnservedBody` to whichever honest relay handed it over, which §8 had
// required to forward it.
//
// This is an existential and not a bound (`PROTOCOL.md` rule 21): it says that
// this construction — the one `TestAnAnnouncersOwnTargetBuysABoundedNumberOf-
// KeyEpochs` builds and the one named as the counter-example to "do not forward
// what you cannot attribute" — no longer reaches the point at which a charge is
// due. It says nothing about a ghost whose parent this node does not hold; that
// half is the open remainder and wire.md §5 says so.
func TestAGhostOnTheReceiversOwnTipIsRefusedInsteadOfRelayed(t *testing.T) {
	c, e, work := announceChain(t, 4)
	const attacker = "10.66.0.2:5000"

	ghost := tipHeaderAt(t, c, c.Params().MaxTarget, 1)
	if ghost.Target.Eq(ruleTarget(c)) {
		t.Fatal("the ghost declares the rule's own target, so this arrangement " +
			"cannot separate the two and would pass whatever the engine did")
	}
	v := e.OnBlockAnnounce(attacker, BlockAnnounce{Header: ghost}.MarshalAnnounce())

	if v.Forward {
		t.Fatal("a ghost declaring its own target on this node's tip was forwarded, " +
			"which is what makes the ghost flood transitive across the mesh")
	}
	if v.Reply != nil {
		t.Fatal("a body was requested for a ghost this node can refuse from the window it holds")
	}
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("ghost scored %d, want ScoreInvalidMessage (%d): the charge has to land "+
			"on the announcer, which is the one party here the protocol can attribute",
			v.Score, ScoreInvalidMessage)
	}
	if n := len(e.PendingBodies()); n != 0 {
		t.Fatalf("%d pending bodies after a refused ghost; ReapUnservedBodies charges "+
			"whatever it finds there to the last hop, so an entry here is the defect", n)
	}
	e.mu.Lock()
	_, seen := e.seenBlocks[ghost.ID()]
	e.mu.Unlock()
	if seen {
		t.Fatal("a refused ghost was entered into seenBlocks, which would dedupe away " +
			"a real block that later claims the same id")
	}
	if charged := e.ReapUnservedBodies(time.Now().Add(2 * PendingBodyTimeout)); len(charged) != 0 {
		t.Fatalf("the reap charged %v after a refused ghost; there is nobody to charge", charged)
	}
	// **The refusal stands AHEAD of the work check, and this is what says so.**
	//
	// The outcome would be the same either way — refused, unforwarded,
	// unpended — so nothing above separates the two orderings, and an ordering
	// that no test observes is an ordering the next reader may move. It is a
	// resource property rather than a verdict property: `work.Check` under
	// `randomx-v1` is a memory-hard evaluation the sender's 232 bytes would
	// otherwise buy, and this gate is LAUNCH.md section 3 case 3 — cheap
	// remote resource exhaustion. A ghost this node can refuse from the window
	// it already holds must not cost it one hash.
	if n := work.hashes(); n != 0 {
		t.Fatalf("a ghost refused by the target check still cost %d proof-of-work "+
			"evaluations; the check has to stand ahead of work.Check, or the "+
			"refusal bounds a verdict rather than a resource", n)
	}
}

// TestTheRuleAgreesWithTheOneTheHonestAnnouncerAppliedIsStillAccepted is the
// other side of the same input: the header a real miner on this tip produces
// carries exactly `pow.NextTarget`'s answer, so the check that refuses the
// ghost must let it through untouched.
func TestTheRuleAgreesWithTheOneTheHonestAnnouncerAppliedIsStillAccepted(t *testing.T) {
	c, e, _ := announceChain(t, 4)
	honest := tipHeaderAt(t, c, ruleTarget(c), 2)

	v := e.OnBlockAnnounce("10.66.0.3:5000", BlockAnnounce{Header: honest}.MarshalAnnounce())
	if v.Reply == nil {
		t.Fatalf("no body was requested for a well-formed tip extension: %v", v.Err)
	}
	if v.Score != ScoreUsefulMessage {
		t.Fatalf("honest tip extension scored %d, want %d", v.Score, ScoreUsefulMessage)
	}
	// Accepted and requested, and NOT relayed — Option A. Acceptance is
	// asserted first and on its own terms above, because `Forward == false` is
	// also what a refusal produces: read alone it would agree with the truth
	// everywhere except where it matters (`PROTOCOL.md` rule 24).
	if v.Forward {
		t.Fatal("an accepted announcement was relayed; under Option A a node " +
			"forwards an announcement only once it holds the body, and this node " +
			"has just asked for it")
	}
}

// TestAnAnnouncementNamingAParentThisNodeDoesNotHoldIsStillAccepted is the
// liveness half, and it is the reason the check is keyed on the tip.
//
// The rule is a function of the window preceding the parent, and this node
// holds that window exactly when the parent is its own tip. Measured on the
// multi-node harness, a receiver one block behind its peer sees 19 of 20 honest
// announcements name a parent it does not hold, and a node rejoining after
// fifteen blocks sees 14 of 15 — so a check that refused, or merely declined to
// relay, an announcement it cannot verify would silence the lagging fringe of
// the mesh, which is the failure that reverted I7-H4's tip window.
//
// This asserts the existential that keeps that from happening: there is an
// announcement whose parent is unknown to this node and whose declared target
// the node therefore cannot check, and it is accepted, requested and unscored
// exactly as it was before.
//
// **It used to say "relayed", and Option A is what changed the verb
// without changing the property.** An accepted announcement is no longer
// forwarded by anybody — a node relays one only once it holds the body — so
// relaying is no longer the thing that separates the lagging fringe from a
// refusal. What separates them is what it always was underneath: this node
// still asks for the body and still does not score the announcer down, so the
// peers a node behind depends on stay peers it will ask.
//
// **The header it uses declares `max_target`, and that is deliberate rather
// than incidental.** A header carrying the rule's own answer cannot separate
// this behaviour from its opposite — the check would let it through whichever
// parent it named — and a probe that inverted the parent comparison survived
// against exactly that arrangement. So the input here is a header this node
// would refuse if it could, and the assertion is that it does not, because it
// cannot: it holds no window for that parent. **That is the remaining half
// stated as a test rather than as prose.** Re-deriving the target reaches the
// tip and nothing else, the honest rows above are why it must not reach
// further, and closing the rest is a gossip-semantics decision about what a
// node does with an announcement it cannot verify — not a check it can add.
func TestAnAnnouncementNamingAParentThisNodeDoesNotHoldIsStillAccepted(t *testing.T) {
	c, e, _ := announceChain(t, 4)
	p := c.Params()

	// A parent id nothing on this chain produces, so the window is out of reach.
	var unknown types.Hash
	unknown[0] = 0xAB
	if _, err := c.CanonicalHeader(unknown); err == nil {
		t.Fatal("the arrangement's unknown parent is on this chain after all")
	}
	tip := c.Tip()
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   tip.Height + 1,
		ParentID: unknown,
		Time:     tip.Time + p.TargetBlockSeconds,
		CertRoot: certRoot(nil, p),
		Target:   p.MaxTarget,
		PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(tip.Height+1, p)},
	}
	if h.Target.Eq(ruleTarget(c)) {
		t.Fatal("the unverifiable header declares the rule's own answer, so this " +
			"arrangement cannot separate a check keyed on the tip from one that " +
			"is not, and would pass whatever the engine did")
	}
	for n := uint64(0); n < 1<<22; n++ {
		h.PoW.Nonce = n
		if pow.CheckWork(pow.Dev{}, h, p) == nil {
			break
		}
	}

	v := e.OnBlockAnnounce("10.66.0.4:5000", BlockAnnounce{Header: h}.MarshalAnnounce())
	if v.Reply == nil {
		t.Fatalf("no body was requested for an announcement whose parent this node "+
			"does not hold: %v", v.Err)
	}
	if v.Score < 0 {
		t.Fatalf("an announcement whose parent this node does not hold was scored %d; "+
			"a node that is behind depends on exactly these", v.Score)
	}
	if v.Cost != CostScored {
		t.Fatalf("an announcement whose parent this node does not hold was priced %v, "+
			"want scored; a refusal here is what silences the lagging fringe", v.Cost)
	}
}

// TestTheGhostsAnnouncerIsBannedAndTheRelayIsNever is the ghost flood's shape
// end to end, on two real engines.
//
// A: the attacker. B: an honest relay at ScoreCeiling on both sides. C: B's
// downstream. Every ghost B accepts is one B forwards, one C pends against B,
// and one C charges to B when the body never comes — that is the whole finding,
// and it is why "five kilobytes ejects an honest node" was the audit's NO-GO.
//
// Here every ghost dies at A. B forwards none, C pends none, and C never
// charges B; A itself walks to ScoreBanThreshold at ScoreInvalidMessage a
// message, which is the attributable party paying. The count of ghosts is a
// property of this arrangement's schedule and not of the attack — so this
// asserts only that A is banned within the arrangement and that B never is.
func TestTheGhostsAnnouncerIsBannedAndTheRelayIsNever(t *testing.T) {
	cb, b, _ := announceChain(t, 4)
	cc, cEng, _ := announceChain(t, 4)
	if cb.Tip().ID() != cc.Tip().ID() {
		t.Fatal("the two engines were meant to start on the same tip")
	}
	const (
		attacker = "10.66.0.2:5000"
		relay    = "10.66.0.3:5000"
	)
	b.Peers.Adjust(attacker, ScoreCeiling)
	cEng.Peers.Adjust(relay, ScoreCeiling)

	forwarded, chargedRelay := 0, 0
	for i := 0; i < 30 && !b.Peers.Banned(attacker); i++ {
		ghost := tipHeaderAt(t, cb, cb.Params().MaxTarget, uint64(i)+1)
		v := b.OnBlockAnnounce(attacker, BlockAnnounce{Header: ghost}.MarshalAnnounce())
		if v.Score != 0 {
			b.Peers.Adjust(attacker, v.Score)
		}
		if v.Forward {
			forwarded++
			w := cEng.OnBlockAnnounce(relay, BlockAnnounce{Header: ghost}.MarshalAnnounce())
			if w.Score != 0 {
				cEng.Peers.Adjust(relay, w.Score)
			}
		}
		chargedRelay += len(cEng.ReapUnservedBodies(time.Now().Add(2 * PendingBodyTimeout)))
	}

	if forwarded != 0 {
		t.Fatalf("the relay forwarded %d ghosts; each one is a pending entry on its "+
			"downstream keyed to the relay itself", forwarded)
	}
	if chargedRelay != 0 {
		t.Fatalf("the downstream charged an unserved body %d times with nothing "+
			"forwarded to it", chargedRelay)
	}
	if cEng.Peers.Banned(relay) {
		t.Fatal("the honest relay was banned by its own downstream, which is the defect")
	}
	if !b.Peers.Banned(attacker) {
		t.Fatal("the announcer of the ghosts was never banned; the charge has to land " +
			"on the party this node can attribute, and here that party is the announcer")
	}
}

// TestAnAnnouncementOnThisNodesTipAtAnyHeightButItsSuccessorIsRefused.
//
// A block whose parent is a given block is at that block's height plus one.
// `core/fold` and `chain.Apply` enforce that from state and `ConsiderBranch`
// enforces it along a branch; the announce wire carries the pair unconstrained,
// so before this check a header could name this node's own tip as its parent
// and claim any height at all. The header here does exactly that, and it is
// otherwise a header this node cannot fault: it declares the target the
// difficulty rule gives for the tip's successor — a public value — and it is
// solved against it, so it costs its announcer a real block's work and passes
// every other line on this path.
//
// **The height is whole key epochs above the tip, and that is the consequence
// rather than a decoration.** The height is what picks the RandomX key
// (`pow.KeyFor`), so the free half of an already-paid header was the right to
// name a key epoch this node does not hold — the resource the key-epoch budget prices
// for the honest peers a node behind the chain depends on. The assertion is the
// refusal; the epoch is asserted separately below so that a later reader cannot
// read this as a test about the tip's own epoch.
//
// The hash count is what says which line answered. The refusal must be this
// comparison, which stands ahead of `work.Check` for the reason the target line does —
// a header this node can fault from state it already holds must not cost it a
// memory-hard evaluation, still less a key build.
func TestAnAnnouncementOnThisNodesTipAtAnyHeightButItsSuccessorIsRefused(t *testing.T) {
	c, e, work := announceChain(t, 4)
	p := c.Params()
	tip := c.Tip()
	rule := ruleTarget(c)

	// Two key epochs above the successor's, so the height is one this node is
	// not working in and the input is the one under test rather than a
	// neighbouring height.
	height := tip.Height + 1 + 2*p.RandomXKeyInterval
	if pow.SeedEpochFor(height, p) <= pow.SeedEpochFor(tip.Height+1, p) {
		t.Fatalf("setup: height %d is in key epoch %d and the tip's successor is in "+
			"%d; this test is about a height whose key epoch this node does not "+
			"hold, and at the same epoch it would be about nothing",
			height, pow.SeedEpochFor(height, p), pow.SeedEpochFor(tip.Height+1, p))
	}
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   height,
		ParentID: tip.ID(),
		Time:     tip.Time + p.TargetBlockSeconds,
		CertRoot: certRoot(nil, p),
		// The rule's OWN answer for the tip's successor. Anything else is
		// refused by the target line one statement above, and this test would
		// then pass whatever the height comparison did.
		Target: rule,
		PoW:    types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p)},
	}
	solved := false
	for n := uint64(0); n < 1<<22 && !solved; n++ {
		h.PoW.Nonce = n
		solved = pow.CheckWork(pow.Dev{}, h, p) == nil
	}
	if !solved {
		t.Fatal("setup: no solution at the rule's own target, so the header would be " +
			"refused by the work check and this test would separate nothing")
	}

	v := e.OnBlockAnnounce("10.66.0.6:5000", BlockAnnounce{Header: h}.MarshalAnnounce())

	if v.Score != ScoreInvalidMessage {
		t.Fatalf("an announcement naming this node's tip as its parent at height %d, "+
			"where that tip's successor is at %d, scored %d, want ScoreInvalidMessage "+
			"(%d): the block it describes cannot exist and the announcer is the one "+
			"party on this path this node can attribute (%v)",
			h.Height, tip.Height+1, v.Score, ScoreInvalidMessage, v.Err)
	}
	if v.Forward {
		t.Fatal("an announcement describing a block that cannot exist was forwarded")
	}
	if v.Reply != nil {
		t.Fatal("a body was requested for a block that cannot exist")
	}
	if n := len(e.PendingBodies()); n != 0 {
		t.Fatalf("%d pending bodies after the refusal; an entry here is a get-block "+
			"this node paid for a block no chain can contain", n)
	}
	e.mu.Lock()
	_, seen := e.seenBlocks[h.ID()]
	e.mu.Unlock()
	if seen {
		t.Fatal("the refused header was entered into seenBlocks")
	}
	// Ahead of the work check, and this is what says so. Under `randomx-v1` a
	// height in an unheld key epoch costs a full key initialisation rather than
	// a hash — about thirty times as much — which is exactly the resource the
	// missing comparison left an already-paid header free to demand.
	if n := work.hashes(); n != 0 {
		t.Fatalf("the refusal cost %d proof-of-work evaluations; it has to stand "+
			"ahead of work.Check, or it bounds a verdict rather than the resource "+
			"the height picks", n)
	}
}

// TestTheSuccessorHeightIsWhatThatCheckReadsAndNotMerelyBeingAbove is the
// anti-vacuity partner of the test above: the comparison is an EQUALITY against
// `tip.Height + 1`, not a ceiling and not a window.
//
// A probe that weakened it to `Height > tip.Height + 1` — refusing only the
// forward case, and so admitting anything at or below the successor — survives
// the row above, since that row drives a height far ahead and such a probe
// still refuses it. This drives the other side: a header naming the tip as its
// parent at the tip's OWN height, which is equally a block that cannot exist,
// and one naming it at the successor height, which must still be accepted. That
// forward-only weakening is the mutant this row kills alone; the backwards-only
// one, `Height <= tip.Height`, is the row above's to kill.
func TestTheSuccessorHeightIsWhatThatCheckReadsAndNotMerelyBeingAbove(t *testing.T) {
	c, e, _ := announceChain(t, 4)
	p := c.Params()
	tip := c.Tip()

	build := func(height uint64, nonceSalt uint64) types.Header {
		t.Helper()
		h := types.Header{
			Version:  types.HeaderVersion,
			Height:   height,
			ParentID: tip.ID(),
			Time:     tip.Time + p.TargetBlockSeconds,
			CertRoot: certRoot(nil, p),
			Target:   ruleTarget(c),
			PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p)},
		}
		for n := uint64(0); n < 1<<22; n++ {
			h.PoW.Nonce = n ^ (nonceSalt << 40)
			if pow.CheckWork(pow.Dev{}, h, p) == nil {
				return h
			}
		}
		t.Fatalf("setup: no solution at the rule's target for height %d", height)
		return h
	}

	behind := build(tip.Height, 3)
	v := e.OnBlockAnnounce("10.66.0.7:5000", BlockAnnounce{Header: behind}.MarshalAnnounce())
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("an announcement naming this node's tip as its parent at the tip's own "+
			"height %d scored %d, want ScoreInvalidMessage (%d); the comparison is an "+
			"equality against tip.Height+1 and a one-sided one leaves this input "+
			"admitted (%v)", behind.Height, v.Score, ScoreInvalidMessage, v.Err)
	}

	successor := build(tip.Height+1, 4)
	w := e.OnBlockAnnounce("10.66.0.8:5000", BlockAnnounce{Header: successor}.MarshalAnnounce())
	if w.Reply == nil {
		t.Fatalf("no body was requested for a header at the tip's successor height "+
			"carrying the rule's own target: the check refuses the block every honest "+
			"miner on this tip produces (%v)", w.Err)
	}
	if w.Score != ScoreUsefulMessage {
		t.Fatalf("an honest tip extension scored %d, want %d", w.Score, ScoreUsefulMessage)
	}
}

// extendChain mines one block onto c, dated `seconds` after the current tip.
//
// The interval is a parameter because the difficulty rule reads solve times: at
// exactly `TargetBlockSeconds` the rule's answer does not move from one tip to
// the next, and a test of a memo keyed on the tip cannot separate a stale answer
// from a fresh one on a chain whose answer never changes.
func extendChain(tb testing.TB, c *chain.Chain, seconds uint64) {
	tb.Helper()
	p := c.Params()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	wk, err := wallet.KeyFromSeed(seed)
	if err != nil {
		tb.Fatal(err)
	}
	clock := c.Tip().Time
	m := &miner.Miner{
		Chain: c, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: pow.Dev{},
		Payout: wk.Persistent(),
		Now:    func() uint64 { clock += seconds; return clock },
	}
	if _, _, err := m.MineOne(1 << 22); err != nil {
		tb.Fatal(err)
	}
}

// TestTheTargetMemoIsKeyedOnTheTipAndNotMerelyOnHavingOne is the memo's own
// correctness, and it is separate from every test above because none of them can
// reach it.
//
// The memo makes the check affordable — reading the difficulty window on every
// announcement costs about thirty times what parsing the announcement costs and
// allocates about a hundred times as much — but an answer cached across a tip
// move is a wrong answer, and the party it convicts is an honest announcer whose
// header carries the CURRENT rule's target. A probe that dropped the key
// comparison survived the honest multi-node rows, because that harness mines at
// exactly `TargetBlockSeconds` and the rule's answer never moves there. So this
// test moves it, and asserts the fresh answer is what comes back.
func TestTheTargetMemoIsKeyedOnTheTipAndNotMerelyOnHavingOne(t *testing.T) {
	c, e, _ := announceChain(t, 6)

	_, before, ok := e.tipNextTarget(c.Tip())
	if !ok {
		t.Fatal("the window did not end at the tip on a chain nothing else is touching")
	}

	// Slow blocks: the rule reads a longer average solve time and the target
	// rises. The clamp is per sample, so this stays inside it.
	for i := 0; i < 3; i++ {
		extendChain(t, c, c.Params().TargetBlockSeconds*8)
	}

	fresh := ruleTarget(c)
	if fresh.Eq(before) {
		t.Fatal("the difficulty rule gives the same answer either side of the tip " +
			"move, so this arrangement cannot separate a stale memo from a fresh " +
			"one and would pass whatever the engine did")
	}

	id, got, ok := e.tipNextTarget(c.Tip())
	if !ok {
		t.Fatal("the window did not end at the tip after the chain was extended")
	}
	if id != c.Tip().ID() {
		t.Fatal("the memo returned an id that is not this node's tip")
	}
	if !got.Eq(fresh) {
		t.Fatalf("the memo answered %s after the tip moved; the rule gives %s. An "+
			"honest announcer building on the NEW tip carries the new target, so a "+
			"stale answer scores it invalid for this node's own bookkeeping",
			got.String(), fresh.String())
	}
}

// TestATipExtensionDeclaringAHarderTargetThanTheRuleIsAlsoRefused pins the
// direction of §5 step 4's comparison that nothing else reaches.
//
// The rule is an EQUALITY — "the target the difficulty rule gives", not "no
// easier than" — and every other test in this family drives the easier side,
// because that is where the cheap ghost lives. A reviewer's probe weakened the
// comparison from `!Eq` to `Gt` and it survived the whole batch: harmless in
// production, since a header declaring a harder target has to solve it, but an
// unpinned normative direction is one a later reader may relax on purpose.
//
// It is deliberately driven with an UNMEETABLE target rather than a merely
// harder one, and the hash count is what makes that sound: the refusal must be
// the target check's, which stands ahead of the work check, and not the work
// check's. Zero evaluations is the proof of which line answered.
func TestATipExtensionDeclaringAHarderTargetThanTheRuleIsAlsoRefused(t *testing.T) {
	c, e, work := announceChain(t, 4)
	p := c.Params()
	tip := c.Tip()

	hard := u256.One
	if hard.Eq(ruleTarget(c)) {
		t.Fatal("the harder target is the rule's own answer, so this arrangement " +
			"separates nothing")
	}
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   tip.Height + 1,
		ParentID: tip.ID(),
		Time:     tip.Time + p.TargetBlockSeconds,
		CertRoot: certRoot(nil, p),
		Target:   hard,
		PoW:      types.PoWSeal{Nonce: 1 << 63, SeedEpoch: pow.SeedEpochFor(tip.Height+1, p)},
	}

	v := e.OnBlockAnnounce("10.66.0.5:5000", BlockAnnounce{Header: h}.MarshalAnnounce())
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("a tip extension declaring a target harder than the rule scored %d, "+
			"want ScoreInvalidMessage (%d): the rule is an equality (%v)",
			v.Score, ScoreInvalidMessage, v.Err)
	}
	if v.Forward {
		t.Fatal("a tip extension that does not carry the rule's target was forwarded")
	}
	if n := work.hashes(); n != 0 {
		t.Fatalf("the refusal cost %d proof-of-work evaluations, so it was the work "+
			"check that answered and this test pins nothing about step 4", n)
	}
}
