package p2p

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// The price on a key epoch has three terms, and this file gives each of
// them an input that separates it. TestAnAnnouncersOwnTargetBuysABoundedNumber-
// OfKeyEpochs measures the whole thing end to end; a bound that passes as a
// whole while one of its terms is inert is the shape this file exists to make
// impossible.
//
//	refused  ⇔  ¬workingKeyEpoch(epoch, own)  ∧  spent ≥ MaxUnheldKeyEpochsPerPeer
//	workingKeyEpoch(epoch, own)  ≡  epoch == own  ∨  epoch == own+1
//
// so the terms are: `epoch == own`, `epoch == own+1`, and the budget
// comparison — plus the refill arithmetic that makes the budget a rate rather
// than a lifetime allowance, and the ORDER of the whole thing against the work
// check, which is the only reason any of it saves anything.

// budgetHarness is one engine, one chain, and an epoch counter in front of the
// work function.
type budgetHarness struct {
	e    *Engine
	c    *chain.Chain
	work *epochCountingPoW
	now  time.Time
}

func newBudgetHarness(t *testing.T) *budgetHarness {
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
	work := newEpochCounter()
	h := &budgetHarness{
		c:    c,
		work: work,
		// A fixed clock, so the refill below is driven rather than waited for.
		// The engine's own seam, not a second one: Engine.Now is documented as
		// the only wall clock in the block path.
		now: time.Unix(int64(c.Tip().Time), 0),
	}
	h.e = NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")
	h.e.Now = func() time.Time { return h.now }
	return h
}

// announceAtEpoch sends one announcement whose height is the first height of
// the given key epoch, at the announcer's own maximal target, and returns the
// verdict.
//
// nonce distinguishes otherwise identical announcements: without it the second
// call would be answered from seenBlocks and would measure the dedup rather
// than the budget.
func (h *budgetHarness) announceAtEpoch(t *testing.T, peer string, epoch, nonce uint64) Verdict {
	t.Helper()
	return h.announceAtEpochFrom(t, peer, peer, epoch, nonce)
}

// announceAtEpochFrom is announceAtEpoch with the payer named separately from
// the connection address, which is the pair the identity keying is about: the
// address is "ip:ephemeral_port" and the payer is what replyBudgetKey produces
// from an authenticated handshake.
func (h *budgetHarness) announceAtEpochFrom(t *testing.T, peer, payer string, epoch, nonce uint64) Verdict {
	t.Helper()
	return h.e.OnBlockAnnounceFrom(peer, payer, h.headerAtEpoch(t, epoch, nonce, u256.Max).announce())
}

// announcement is a marshalled announcement plus the header it carries, so a
// caller can assert on both.
type announcement struct{ hd types.Header }

func (a announcement) announce() []byte {
	return BlockAnnounce{Header: a.hd}.MarshalAnnounce()
}

// headerAtEpoch builds one header whose height is the first height of the given
// key epoch, at the declared target given.
func (h *budgetHarness) headerAtEpoch(t *testing.T, epoch, nonce uint64, target u256.U256) announcement {
	t.Helper()
	p := h.c.Params()
	height := p.RandomXKeyLag + epoch*p.RandomXKeyInterval
	hd := types.Header{
		Version: types.HeaderVersion,
		Height:  height,
		// A parent this node does not hold, and NOT the tip.
		//
		// It used to be the tip, which was free while nothing on the announce
		// path looked at parentage — and it was also a header that cannot
		// exist, since a block whose parent is the tip is at tip.Height+1 and
		// these heights are whole key epochs away. The tip-parent target rule
		// made the field mean something: an announcement naming this node's own
		// tip must now carry the target the difficulty rule gives, so a
		// tip-parented header at u256.Max is refused before it reaches the work
		// check and every count below would measure that refusal instead of the
		// budget. The successor-height rule then closed the other half of the
		// same input on the same branch: a tip-parented header at a height that
		// is not the tip's successor is refused on the height, ahead of the
		// target line, whatever target it declares — so naming the tip here
		// would now be refused even at the rule's own answer. The realistic
		// shape for a header this far from the tip is an unknown parent, which
		// is what keyepoch_internal_test.go already used, so this is the same
		// arrangement stated correctly rather than a different one.
		ParentID: types.Hash{0xab},
		// Dated at this harness's own clock, so a test that MOVES that clock
		// keeps announcing present-dated headers. The future-time check stands
		// ahead of the key-epoch price, so a header pinned to the tip's time
		// silently becomes future-dated the moment a test steps the clock back
		// — and every count after that measures tooFarAhead rather than the
		// budget. This clock starts at the tip's own time, so nothing that
		// leaves it alone sees a different header.
		Time:     uint64(h.now.Unix()),
		Target:   target,
		CertRoot: certRoot(nil, p),
		PoW:      types.PoWSeal{Nonce: nonce | 1<<63, SeedEpoch: pow.SeedEpochFor(height, p)},
	}
	// Anti-vacuity for every call: at the maximal target the header must PASS
	// the work check, or a refusal downstream is the work check's and not the
	// budget's. Asked of a bare pow.Dev so the instrument is not seeded with
	// the answer. A caller that deliberately builds an unmeetable target is
	// asking for the opposite and is checked for the opposite.
	err := pow.CheckWork(pow.Dev{}, hd, p)
	if target == u256.Max && err != nil {
		t.Fatalf("setup: header at epoch %d does not pass CheckWork (%v); the "+
			"whole finding is that a declared u256.Max target passes", epoch, err)
	}
	if target != u256.Max && err == nil {
		t.Fatalf("setup: header at epoch %d PASSES CheckWork at a target meant "+
			"to be unmeetable; a test of the work check's refusal would be "+
			"measuring nothing", epoch)
	}
	if got := pow.SeedEpochFor(height, p); got != epoch {
		t.Fatalf("setup: height %d is in key epoch %d, not %d; the heights no "+
			"longer address epochs and every count in this test is about "+
			"something else", height, got, epoch)
	}
	return announcement{hd: hd}
}

// TestOnlyTheEpochsThisNodeIsWorkingInAreFreeToAnnounceInto gives each term of
// workingKeyEpoch an input that separates it.
//
// The set is `{own, own+1}`. Dropping `epoch == own` makes the `own` rows
// charge; dropping `epoch == own+1` makes the `own+1` rows charge; widening
// either term to `own+2` makes the `own+2` rows free; and the rows BELOW the
// tip's epoch are what say this is membership in a set that starts AT the tip's
// epoch rather than a distance of one in either direction.
//
// It is in two halves because the reachable inputs and the claim do not
// coincide. The table drives the predicate directly, which is where the claim
// is made and the only place an epoch below this node's own can be presented —
// a chain at genesis has no epoch below its tip's, and mining a devnet past its
// first key boundary to manufacture one would make this a test of the miner.
// The handler rows then drive the three cases a chain at genesis can actually
// present, so the predicate is not merely correct in isolation but is the thing
// OnBlockAnnounce consults.
func TestOnlyTheEpochsThisNodeIsWorkingInAreFreeToAnnounceInto(t *testing.T) {
	// The pure predicate first, because this is where the claim is made. A
	// behavioural test alone cannot separate `epoch == own+1` from
	// `epoch <= own+1` on a node whose tip epoch is 0, where `own-1` does not
	// exist.
	for _, tc := range []struct {
		epoch, own uint64
		want       bool
		why        string
	}{
		{0, 0, true, "the tip's own epoch: this node verified its tip under that key"},
		{1, 0, true, "the next epoch: an honest peer announces into it at a boundary"},
		{2, 0, false, "two epochs ahead: nothing honest announces there to a node at epoch 0"},
		{0, 1, false, "below the tip's epoch: a reorg across a boundary, which the budget covers"},
		{0, 2, false, "further below, and the underflow form would decide this the same way by accident"},
		{9, 8, true, "the pair is relative to the tip, not to zero"},
		{8, 9, false, "and it is not symmetric about it"},
	} {
		if got := workingKeyEpoch(tc.epoch, tc.own); got != tc.want {
			t.Errorf("workingKeyEpoch(epoch=%d, own=%d) = %v, want %v — %s",
				tc.epoch, tc.own, got, tc.want, tc.why)
		}
	}

	// And the three reachable cases through the handler.
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())

	const peer = "10.70.0.1:5000"
	for i, tc := range []struct {
		epoch    uint64
		budgeted bool
		why      string
	}{
		{own, false, "the tip's own epoch is free"},
		{own + 1, false, "and so is the next one"},
		{own + 2, true, "two ahead is not, and it is charged from the first message"},
	} {
		// Each row is driven with a peer that has already spent its whole
		// budget, so that "free" below means the epoch test let it through
		// rather than the budget having room. Without this every row would
		// pass whatever workingKeyEpoch answered, for the first
		// MaxUnheldKeyEpochsPerPeer messages.
		addr := fmt.Sprintf("%s%d", peer, i)
		// The drain epochs and nonces are per-row, and that is not tidiness:
		// with a shared sequence the second row's drain reproduces the first
		// row's headers byte for byte, is answered from seenBlocks at
		// CostDeduped, and spends nothing — so the row it is meant to arm
		// reports "free" while the budget was never drained at all. Measured:
		// the first version of this test did exactly that and passed its
		// `own+1` row vacuously.
		for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
			v := h.announceAtEpoch(t, addr, own+10+uint64(100*i+n), uint64(1000*i+n))
			if v.Cost != CostScored {
				t.Fatalf("setup: draining the budget was priced %v at message "+
					"%d of %d, so the row below measures a budget that was "+
					"never spent", v.Cost, n, MaxUnheldKeyEpochsPerPeer)
			}
		}
		// And the drain really did empty it: without this the rows below pass
		// whatever workingKeyEpoch answers.
		if v := h.announceAtEpoch(t, addr, own+90+uint64(i), uint64(9000+i)); v.Cost != CostBudgeted {
			t.Fatalf("setup: after %d unheld-epoch announcements the budget of "+
				"%d still admitted one (priced %v)", MaxUnheldKeyEpochsPerPeer,
				MaxUnheldKeyEpochsPerPeer, v.Cost)
		}
		v := h.announceAtEpoch(t, addr, tc.epoch, 999)
		if got := v.Cost == CostBudgeted; got != tc.budgeted {
			t.Errorf("an announcement at key epoch %d (this node's tip is in %d) "+
				"was budgeted=%v, want %v — %s; verdict cost=%v err=%v",
				tc.epoch, own, got, tc.budgeted, tc.why, v.Cost, v.Err)
		}
	}
}

// TestABudgetedAnnouncementIsRefusedBeforeItsKeyEpochIsBuilt is the ordering
// term, and it is the only reason any of this saves anything.
//
// A budget checked AFTER the work check bounds nothing: the 256 MiB allocation
// and the Argon2 fill have already happened, and all the refusal buys is a
// verdict. So the property is not "the message was refused", it is "the message
// was refused and the work function was never asked about its key".
//
// Measured on DISTINCT keys rather than on the hash count, for the reason
// epochCountingPoW's own comment gives: a hash under a held key is 15–55 ms and
// a key the engine does not hold is ~0.55 s, and only the second is what this
// budget is about.
func TestABudgetedAnnouncementIsRefusedBeforeItsKeyEpochIsBuilt(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const peer = "10.70.0.2:5000"

	// Spend the budget, one fresh epoch per message.
	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := h.announceAtEpoch(t, peer, own+2+uint64(n), uint64(n)); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d of the budget was already refused", n)
		}
	}
	spent := h.work.distinctKeys()
	if spent != MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("setup: %d messages forced %d distinct key epochs, want %d; "+
			"the heights are no longer one epoch apart and what follows would "+
			"measure nothing", MaxUnheldKeyEpochsPerPeer, spent, MaxUnheldKeyEpochsPerPeer)
	}

	// Now a hundred more, every one at an epoch of its own.
	const past = 100
	for n := 0; n < past; n++ {
		epoch := own + 2 + uint64(MaxUnheldKeyEpochsPerPeer) + uint64(n)
		v := h.announceAtEpoch(t, peer, epoch, uint64(1000+n))
		if v.Cost != CostBudgeted {
			t.Fatalf("announcement %d past the budget of %d was priced %v, want "+
				"budgeted: the budget is not a bound if the messages past it "+
				"are still evaluated", n, MaxUnheldKeyEpochsPerPeer, v.Cost)
		}
		if !errors.Is(v.Err, ErrKeyEpochBudget) {
			t.Fatalf("refused with %v, want ErrKeyEpochBudget; any other refusal "+
				"means this test passes for a reason other than the price it names",
				v.Err)
		}
		// The epoch this message named must not have been built for it.
		if h.work.sawKey(pow.KeyFor(h.c.Params().RandomXKeyLag+epoch*h.c.Params().RandomXKeyInterval, h.c.Params())) {
			t.Fatalf("the key for epoch %d was evaluated for a message the "+
				"budget refused: the price is charged after the CPU is spent, "+
				"which bounds a verdict and not a resource", epoch)
		}
	}
	if got := h.work.distinctKeys(); got != spent {
		t.Fatalf("%d refused announcements at %d distinct epochs moved the "+
			"engine from %d key epochs to %d; a refused announcement must cost "+
			"no epoch at all", past, past, spent, got)
	}
}

// TestASpentKeyEpochBudgetRefillsAtTheChainsOwnEpochRate is the refill term.
//
// Without it the budget is a lifetime allowance per connection, and a
// connection that stays up for the months this node is meant to run for would
// be permanently unable to announce anything outside the two epochs around this
// node's tip — including, at every key boundary the node itself is slow to
// cross, an honest peer's ordinary gossip. The rate is not invented: it is
// `randomx_key_interval` blocks at `target_block_seconds` each, which is the
// time the honest chain takes to enter one new key epoch, so an honest peer
// needs exactly one credit per period and gets exactly one.
//
// Three inputs, because the arithmetic has three cases and only the middle one
// is interesting: nothing before the period elapses, one credit at it, and no
// more than the budget however long the connection idles.
func TestASpentKeyEpochBudgetRefillsAtTheChainsOwnEpochRate(t *testing.T) {
	h := newBudgetHarness(t)
	p := h.c.Params()
	own := pow.SeedEpochFor(h.c.Tip().Height, p)
	period := keyEpochPeriod(p)
	const peer = "10.70.0.3:5000"

	if period != p.RandomXKeyInterval*p.TargetBlockSeconds {
		t.Fatalf("setup: the refill period is %d s, not the schedule's own "+
			"%d x %d; this test would be measuring a different rate from the "+
			"one the comment claims", period, p.RandomXKeyInterval, p.TargetBlockSeconds)
	}

	next := own + 2
	spend := func() Verdict {
		next++
		return h.announceAtEpoch(t, peer, next, next)
	}

	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := spend(); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d of %d was refused before the budget was "+
				"spent", n, MaxUnheldKeyEpochsPerPeer)
		}
	}
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatalf("the message past the budget was priced %v, want budgeted", v.Cost)
	}

	// One second short of the period: still nothing. This is the input that
	// separates a refill that measures the period from one that grants a credit
	// on any elapsed time at all.
	h.now = h.now.Add(time.Duration(period-1) * time.Second)
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatalf("a credit arrived %d s into a %d s period (verdict %v); the "+
			"refill is not measuring the schedule and an attacker can spend "+
			"faster than the chain earns", period-1, period, v.Cost)
	}

	// And at the period: exactly one, and exactly one.
	h.now = h.now.Add(time.Second)
	if v := spend(); v.Cost == CostBudgeted {
		t.Fatalf("no credit had arrived after a full %d s period; the budget is "+
			"a lifetime allowance per connection rather than a rate, and an "+
			"honest peer is silenced for the life of the connection", period)
	}
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatalf("a second message was admitted on one period's credit "+
			"(verdict %v); the refill grants more than the chain earns", v.Cost)
	}

	// However long it idles, the burst never exceeds the budget: a connection
	// quiet for a thousand periods comes back with MaxUnheldKeyEpochsPerPeer
	// and not with a thousand.
	h.now = h.now.Add(time.Duration(period) * 1000 * time.Second)
	admitted := 0
	for n := 0; n < 4*MaxUnheldKeyEpochsPerPeer; n++ {
		if v := spend(); v.Cost != CostBudgeted {
			admitted++
		}
	}
	if admitted != MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("after idling 1000 periods the connection was admitted %d "+
			"messages, want %d: credits accumulate without a ceiling, so an "+
			"attacker banks them and spends the lot at once",
			admitted, MaxUnheldKeyEpochsPerPeer)
	}

	// A bucket that refills completely restarts its clock at `now` and drops
	// the remainder, and that choice needs its own input or it is a comment.
	//
	// Carrying the remainder forward instead — advancing the settle time by
	// credits x period rather than to now — leaves the connection already part
	// of the way into the NEXT period the moment it is full, so the credit
	// after that arrives early by however much it idled past a whole number of
	// periods. That is slack a sender schedules: idle just under a period more
	// than it needs, and the next credit is nearly free. Every other assertion
	// in this test passes with the remainder carried, because none of them
	// idles by a non-multiple of the period.
	//
	// A second connection, because the first one's settle time is now a
	// function of everything above it.
	const idler = "10.70.0.9:5000"
	nextIdle := own + 2000
	spendIdle := func() Verdict {
		nextIdle++
		return h.announceAtEpoch(t, idler, nextIdle, nextIdle)
	}
	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := spendIdle(); v.Cost == CostBudgeted {
			t.Fatalf("setup: idler message %d was refused before its budget "+
				"was spent", n)
		}
	}
	// Long enough to refill completely, plus half a period that is owed to
	// nobody. The call that observes it also takes the first credit back.
	h.now = h.now.Add(time.Duration(uint64(MaxUnheldKeyEpochsPerPeer)*period+period/2) * time.Second)
	if v := spendIdle(); v.Cost == CostBudgeted {
		t.Fatalf("setup: no credit after idling %d full periods", MaxUnheldKeyEpochsPerPeer)
	}
	for n := 1; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := spendIdle(); v.Cost == CostBudgeted {
			t.Fatalf("setup: refilled budget ran out after %d of %d messages",
				n, MaxUnheldKeyEpochsPerPeer)
		}
	}
	if v := spendIdle(); v.Cost != CostBudgeted {
		t.Fatalf("setup: the refilled budget admitted more than %d messages",
			MaxUnheldKeyEpochsPerPeer)
	}
	// One second short of a period since the bucket filled. Nothing is owed.
	h.now = h.now.Add(time.Duration(period-1) * time.Second)
	if v := spendIdle(); v.Cost != CostBudgeted {
		t.Fatalf("a credit arrived %d s after the bucket refilled, in a %d s "+
			"period (verdict %v): the refill kept the remainder of the idle "+
			"stretch instead of restarting its clock, so a sender that idles "+
			"just past a whole period gets the next credit early", period-1,
			period, v.Cost)
	}
}

// TestABudgetedAnnouncementIsNeitherRememberedNorHeldAgainstThePeer pins the
// two halves that keep this a price rather than the refusal that reverted
// I7-H4's tip-window guard.
//
// A node that is behind receives announcements far ahead from exactly the peers
// it depends on to climb back. Two things would turn the price into that
// refusal: scoring the peer for it, which bans the peers it needs; and entering
// the id into seenBlocks, which dedupes away the re-announcement that arrives
// once a credit is back, so a message refused for want of a credit would be
// refused forever.
//
// It also asserts the third: the peer's advertised height is still recorded, so
// a node that is behind keeps learning who is ahead of it. recordAnnounce's own
// comment says what that is worth — the announce path never re-derives the
// target, so it "decides only who is worth asking" — which is why running it
// ahead of the work check takes nothing away that was ever there.
func TestABudgetedAnnouncementIsNeitherRememberedNorHeldAgainstThePeer(t *testing.T) {
	h := newBudgetHarness(t)
	p := h.c.Params()
	own := pow.SeedEpochFor(h.c.Tip().Height, p)
	const peer = "10.70.0.4:5000"

	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := h.announceAtEpoch(t, peer, own+2+uint64(n), uint64(n)); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d was refused before the budget was spent", n)
		}
	}

	// The message that does not fit. Same nonce as the one replayed after the
	// refill below, so the two are the same announcement and the same id.
	const refusedEpochOffset = 40
	const nonce = 777
	epoch := own + refusedEpochOffset
	v := h.announceAtEpoch(t, peer, epoch, nonce)
	if v.Cost != CostBudgeted {
		t.Fatalf("the message past the budget was priced %v, want budgeted", v.Cost)
	}
	if v.Score != 0 {
		t.Fatalf("the budget refusal charged the peer %d; a node that is behind "+
			"would ban the peers feeding it, which is the failure that reverted "+
			"the tip-window guard (I7-H4)", v.Score)
	}
	if v.Forward {
		t.Fatal("a refused announcement was forwarded: this node would relay a " +
			"message it declined to evaluate")
	}
	if v.Reply != nil {
		t.Fatalf("a refused announcement asked for the body (%v); the point of "+
			"refusing is not to spend anything on it", v.Reply.Kind)
	}

	// The peer is still visible to the sync driver as being ahead.
	height := p.RandomXKeyLag + epoch*p.RandomXKeyInterval
	h.e.mu.Lock()
	tip := h.e.tips[peer]
	h.e.mu.Unlock()
	if tip.Height != height {
		t.Errorf("after a budgeted refusal the peer's recorded height is %d, "+
			"want %d: a node that is behind stops learning which peers are "+
			"ahead of it, and the price has become a refusal to apply", tip.Height, height)
	}

	// And the refusal left no memory of the id, so the same announcement is
	// judged afresh once a credit is back.
	h.now = h.now.Add(time.Duration(keyEpochPeriod(p)) * time.Second)
	again := h.announceAtEpoch(t, peer, epoch, nonce)
	if again.Cost == CostBudgeted {
		t.Fatal("the same announcement was refused again after a full refill " +
			"period; the credit did not arrive")
	}
	if again.Cost == CostDeduped {
		t.Fatal("the re-announcement was deduped: the refused id was entered " +
			"into seenBlocks, so a message refused for want of a credit is " +
			"refused forever — a rejection wearing a cache's clothes")
	}
	// Treated as an ordinary announcement means accepted, requested and
	// rewarded. It does NOT mean relayed: under Option A no accepted
	// announcement is, so `Forward` no longer separates "ordinary" from
	// "refused" and asserting on it would agree with a refusal too
	// (`PROTOCOL.md` rule 24).
	if again.Reply == nil || again.Score != ScoreUsefulMessage {
		t.Errorf("the re-announcement was not accepted (cost=%v score=%d err=%v); "+
			"after the refill it is an ordinary announcement and must be treated "+
			"as one", again.Cost, again.Score, again.Err)
	}
}

// TestAnOverBudgetAnnouncementRefreshesBothHalvesOfTheCandidacyRecord pins
// the free-chain-lookup residual, whose answer is that nothing changes on this
// path.
//
// The budget's refusal calls recordAnnounce ahead of `work.Check`, so an
// over-budget connection reaches a chain lookup without paying even a hash. A
// partial refresh was listed as one way to shrink that residual: keep the
// `Height` write and skip the `CanonicalHeader` lookup that sets
// `OffersUnknown`, on the argument that the first half is what a node climbing
// back needs and the second is the half that grants candidacy. The decision
// recorded at the call site is to keep BOTH, because `OffersUnknown` is the
// *only* candidacy signal for a peer holding a heavier branch that ends below
// this node's tip — it is behind by height and by claimed work, so
// dropping the second half would make it invisible, and that is the
// healed-network-stays-forked failure recordAnnounce's own comment names.
//
// A decision to change nothing still needs a test, or the next reader
// implements the alternative and nothing objects. This is that test: it is what
// the partial refresh would have to break, and the height half alone passes
// `TestABudgetedAnnouncementIsNeitherRememberedNorHeldAgainstThePeer` and
// `TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget`
// next door, both of which assert `Height` and neither of which reads
// `OffersUnknown`. Measured: with the `CanonicalHeader` gate mutated so
// `OffersUnknown` is never set on this path, those two still pass and this one
// fails.
//
// The budget is spent from one connection address and the refused announcement
// arrives on ANOTHER, with the same payer. That is not decoration: the budget is
// per identity while `Engine.tips` is keyed by connection, so a fresh
// address gives the subject an entry that the over-budget message alone can have
// created — otherwise the admitted setup messages would have written both fields
// already and the assertions below would hold vacuously.
func TestAnOverBudgetAnnouncementRefreshesBothHalvesOfTheCandidacyRecord(t *testing.T) {
	h := newBudgetHarness(t)
	p := h.c.Params()
	own := pow.SeedEpochFor(h.c.Tip().Height, p)
	const payer = "over-budget-identity"
	const spender, subject = "10.70.0.9:5000", "10.70.0.10:5000"

	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := h.announceAtEpochFrom(t, spender, payer, own+2+uint64(n), uint64(n)); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d was refused before the budget was spent", n)
		}
	}

	// Well clear of the epochs the setup spent, so this is a distinct id and a
	// distinct epoch and neither dedup nor the working-epoch exemption answers
	// it.
	const refusedEpochOffset, nonce = 61, 991
	epoch := own + refusedEpochOffset
	v := h.announceAtEpochFrom(t, subject, payer, epoch, nonce)
	if v.Cost != CostBudgeted {
		t.Fatalf("the message past the budget was priced %v (score %d, err %v), "+
			"want budgeted: nothing below measures the over-budget path unless "+
			"this one does", v.Cost, v.Score, v.Err)
	}

	h.e.mu.Lock()
	tip, held := h.e.tips[subject]
	h.e.mu.Unlock()
	if !held {
		t.Fatal("the over-budget announcement left no tip entry at all: " +
			"recordAnnounce did not run, so the price has become the refusal to " +
			"apply that reverted I7-H4's tip-window guard")
	}

	// Half one: how far ahead the peer says it is. This is what keeps a node
	// that is behind able to find a source.
	if want := p.RandomXKeyLag + epoch*p.RandomXKeyInterval; tip.Height != want {
		t.Errorf("after a budgeted refusal the peer's recorded height is %d, want "+
			"%d: the node stopped learning who is ahead of it", tip.Height, want)
	}
	// Half two, and the one the decision keeps. The announced block is one
	// this node cannot place and its height is above this node's own, so
	// recordAnnounce's CanonicalHeader gate fires — unless it has been skipped.
	if tip.OffersUnknown.IsZero() {
		t.Error("after a budgeted refusal the peer is not recorded as offering " +
			"anything this node cannot place: the CanonicalHeader half of " +
			"recordAnnounce was skipped on the over-budget path, which is the " +
			"partial refresh. That is the sole candidacy signal for a peer on a " +
			"heavier branch ending below this node's tip, and the decision " +
			"recorded at the call site is to keep it")
	}
}

// TestTheKeyEpochBudgetIsPerIdentityAndNotShared pins the axis the price is
// charged against, from the side that would make it a lever.
//
// A budget shared across senders is a denial of service delivered through the
// defence itself: one identity spends it and every other peer is refused. The
// node-wide ceiling above it IS shared, deliberately, which is why this test
// stays well inside DefaultMaxUnheldKeyEpochsPerNode — the two layers are separated by
// TestTheNodeWideKeyEpochCeilingBoundsTheAggregateOverIdentities next door.
func TestTheKeyEpochBudgetIsPerIdentityAndNotShared(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const attacker, honest = "attacker-identity", "honest-identity"

	spent := 0
	for n := 0; n < 4*MaxUnheldKeyEpochsPerPeer; n++ {
		if h.announceAtEpochFrom(t, "10.70.0.5:5000", attacker, own+2+uint64(n), uint64(n)).Cost != CostBudgeted {
			spent++
		}
	}
	if spent != MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("setup: the attacker was admitted %d times against a budget of "+
			"%d", spent, MaxUnheldKeyEpochsPerPeer)
	}
	if v := h.announceAtEpochFrom(t, "10.70.0.6:5000", honest, own+901, 2); v.Cost == CostBudgeted {
		t.Fatal("a second identity was refused on a budget the first one spent: " +
			"the price is charged against the node rather than against the " +
			"sender, so one identity silences every peer")
	}
}

// TestOneIdentityCannotRebuyTheKeyEpochBudgetByReconnecting measures the
// identity keying from the far side.
//
// The budget used to live in Engine.tips, keyed by the peerAddr Engine.Handle
// is given, and forgetPeer deletes that entry on unregister — the one teardown
// a connection has. PeerStore.AdjustKey's own comment says what that key is:
// "ip:ephemeral_port: a value the OS picks fresh on every reconnect, not the
// peer ... A banned peer sheds that ban for the cost of one TLS handshake by
// reconnecting on a new source port". That was closed for the SCORE by adding
// an identity-keyed store; the budget was on the address-keyed side of the same
// line, so it was shed the same way — measured at 40 unheld key epochs across
// eight reconnects with the clock frozen, `[5 5 5 5 5 5 5 5]` per round,
// against a derived budget of 5.
//
// The arrangement below is that measurement unchanged: same eight reconnects,
// same frozen clock, same forgetPeer between rounds. What changes is the payer.
// Every round presents a NEW connection address and the SAME authenticated
// identity, which is what an attacker completing eight TLS handshakes with one
// keypair presents, and the budget is charged to the identity.
//
// The connection address moving every round is the anti-vacuity: a fix that
// simply stopped deleting the entry would pass a test that reconnected on one
// address, and would still be shed by the ephemeral port that makes a
// connection-keyed budget a defect rather than an inefficiency.
func TestOneIdentityCannotRebuyTheKeyEpochBudgetByReconnecting(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())

	// The clock never moves, so nothing below is a refill: every credit this
	// identity spends after the first round would have come from a reconnect.
	const rounds = 8
	const identity = "one-ed25519-identity"
	epoch := own + 2
	spentPerRound := make([]int, 0, rounds)
	for r := 0; r < rounds; r++ {
		conn := fmt.Sprintf("10.70.0.9:%d", 40000+r)
		spent := 0
		for n := 0; n <= MaxUnheldKeyEpochsPerPeer; n++ {
			v := h.announceAtEpochFrom(t, conn, identity, epoch, epoch)
			epoch++
			if v.Cost != CostBudgeted {
				spent++
			}
		}
		spentPerRound = append(spentPerRound, spent)
		// The disconnect. Node.unregister calls exactly this and nothing else
		// that touches the budget.
		h.e.forgetPeer(conn)
	}

	forced := h.work.distinctKeys()
	t.Logf("one identity, %d reconnects on %d distinct connection addresses, "+
		"clock frozen: %d unheld key epochs forced (%v per round) against a "+
		"derived per-identity budget of %d",
		rounds, rounds, forced, spentPerRound, MaxUnheldKeyEpochsPerPeer)

	if forced > MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("one identity forced %d key epochs across %d reconnects with "+
			"the clock frozen, against a budget of %d (%v per round). The "+
			"budget is keyed on something the sender mints, so it is re-bought "+
			"for the price of one TLS handshake",
			forced, rounds, MaxUnheldKeyEpochsPerPeer, spentPerRound)
	}
	// The control: it is the budget that is holding, and not that the harness
	// stopped forcing epochs at all.
	if forced != MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("one identity forced %d key epochs, want exactly the budget of "+
			"%d; below the budget the arrangement is no longer the one that was "+
			"measured and the bound above proves nothing",
			forced, MaxUnheldKeyEpochsPerPeer)
	}
}

// TestAHandshakeDoesNotClearASpentKeyEpochBudget pins the budget against the
// one write on PeerTip that used to be able to clear it.
//
// recordTip rebuilds the PeerTip entry as a composite literal, which assigns
// every field it names and silently zeroes every field it does not. It carries
// Dial and lastGetPeers by hand — lastGetPeers precisely because "a rewrite
// here would be a rate limit a peer can clear by re-handshaking" — and
// the key-epoch budget was added beside them and was not carried, so a spent
// budget was reset to zero by a hello.
//
// The budget no longer lives on PeerTip at all, so recordTip cannot reach it
// and no future field-carrying mistake can: the state that was wrong is not
// representable rather than merely not written. This test therefore asserts the
// BEHAVIOUR the field carry existed for, through the handler, and it is what
// would catch the defect returning by any route — including a route through the
// identity store.
func TestAHandshakeDoesNotClearASpentKeyEpochBudget(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const peer = "10.70.0.11:5000"

	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := h.announceAtEpoch(t, peer, own+3000+uint64(n), 3000+uint64(n)); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d was refused before the budget was spent", n)
		}
	}
	if v := h.announceAtEpoch(t, peer, own+3100, 3100); v.Cost != CostBudgeted {
		t.Fatalf("setup: the budget is not spent, so a carry below proves nothing")
	}

	// This connection's FIRST handshake, which OnHello accepts.
	if v := h.e.OnHello(peer, h.e.Hello()); v.Err != nil {
		t.Fatalf("setup: the first handshake on this connection was refused: %v", v.Err)
	}
	h.e.mu.Lock()
	handshaked := h.e.tips[peer].Handshaked
	h.e.mu.Unlock()
	if !handshaked {
		t.Fatal("setup: recordTip did not run, so nothing below is about what it does")
	}

	if v := h.announceAtEpoch(t, peer, own+3200, 3200); v.Cost != CostBudgeted {
		t.Fatalf("after a handshake the sender was admitted again (cost %v); "+
			"the budget is one handshake from empty to full", v.Cost)
	}
}

// TestAPartialRefillMeasuresFromWhatTheScheduleEarned is the partial-refill
// branch's own separating input, and it is the mirror of the full-refill one.
//
// The two branches make OPPOSITE choices about the remainder and only one of
// them was defended. A bucket that refills completely restarts its clock at
// `now` and drops the remainder, because keeping it would hand out the next
// credit early. A bucket that refills partially advances its clock by exactly
// `credits x period` and KEEPS the remainder, because the remainder is time the
// schedule has already run and dropping it would charge an honest peer for it
// twice. Both are right and they are not the same rule, so each needs a case:
// with `+= credits * period` replaced by `= now` every other assertion in this
// file still passes, and an honest peer waits up to a full period longer than
// the schedule earned.
//
// The idle stretches are deliberately not whole periods. A whole number of
// periods leaves no remainder, which is precisely the input that cannot tell
// the two forms apart.
func TestAPartialRefillMeasuresFromWhatTheScheduleEarned(t *testing.T) {
	h := newBudgetHarness(t)
	p := h.c.Params()
	period := keyEpochPeriod(p)
	own := pow.SeedEpochFor(h.c.Tip().Height, p)
	const peer = "10.70.0.12:5000"

	next := own + 4000
	spend := func() Verdict {
		next++
		return h.announceAtEpoch(t, peer, next, next)
	}
	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := spend(); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d was refused before the budget was spent", n)
		}
	}
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatal("setup: the budget is not spent")
	}

	// One and a half periods: one credit earned, half a period the schedule has
	// also already run. The call that observes it spends the credit again, so
	// the budget is full once more and the half period is the only thing in
	// dispute.
	h.now = h.now.Add(time.Duration(period+period/2) * time.Second)
	if v := spend(); v.Cost == CostBudgeted {
		t.Fatalf("setup: no credit after %d s of a %d s period", period+period/2, period)
	}
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatal("setup: more than one credit arrived in one and a half periods")
	}

	// Three fifths of a period more. Measured from what the schedule earned,
	// 1.1 periods have now passed since the last credit and the next one is
	// due. Measured from `now` at the last refill, only 0.6 has.
	h.now = h.now.Add(time.Duration(period*3/5) * time.Second)
	if v := spend(); v.Cost == CostBudgeted {
		t.Fatalf("no credit %d s after a partial refill that had already banked "+
			"%d s of the period (verdict %v); the partial branch restarted its "+
			"clock at now instead of advancing it by credits x period, so an "+
			"honest peer waits up to a full period longer than the schedule "+
			"earned", period*3/5, period/2, v.Cost)
	}
}

// TestAClockThatStepsBackwardsGrantsNoKeyEpochCredits is the guard on the
// subtraction, and the guard is the whole of `case now > t.unheldEpochsAt`.
//
// Engine.Now is a wall clock. Wall clocks step backwards — NTP corrects one,
// a VM resumes from a snapshot, an operator sets one — and `now -
// t.unheldEpochsAt` is unsigned. With the comparison inert the subtraction
// underflows to something near 2^64, the division yields credits by the
// million, and the bucket refills completely: a spent budget is handed back in
// full to whichever connection is holding it when the clock moves. That is the
// underflow family this package already carries a trap from, in the direction
// that disables a guard rather than the one that wraps a bound.
//
// Nothing pins it: replacing the comparison with `true` passes every other case
// in this file, because none of them moves the clock backwards.
func TestAClockThatStepsBackwardsGrantsNoKeyEpochCredits(t *testing.T) {
	h := newBudgetHarness(t)
	p := h.c.Params()
	period := keyEpochPeriod(p)
	own := pow.SeedEpochFor(h.c.Tip().Height, p)
	const peer = "10.70.0.13:5000"

	next := own + 5000
	spend := func() Verdict {
		next++
		return h.announceAtEpoch(t, peer, next, next)
	}
	for n := 0; n < MaxUnheldKeyEpochsPerPeer; n++ {
		if v := spend(); v.Cost == CostBudgeted {
			t.Fatalf("setup: message %d was refused before the budget was spent", n)
		}
	}
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatal("setup: the budget is not spent, so a refusal below proves nothing")
	}

	// The clock steps back by two full periods, which is what a correction
	// looks like from inside this function.
	settled := h.now
	h.now = h.now.Add(-time.Duration(2*period) * time.Second)
	if !h.now.Before(settled) {
		t.Fatalf("setup: the clock did not move backwards (%v -> %v)", settled, h.now)
	}
	if v := spend(); v.Cost != CostBudgeted {
		t.Fatalf("a backwards clock refilled the budget (verdict %v): the "+
			"subtraction in the refill underflowed and handed back every credit "+
			"at once, so any peer holding a connection across a clock correction "+
			"gets its budget back for free", v.Cost)
	}
	// And the connection is not left permanently unable to earn: once the clock
	// is past where it was, the schedule resumes.
	h.now = settled.Add(time.Duration(period) * time.Second)
	if v := spend(); v.Cost == CostBudgeted {
		t.Fatal("after the clock caught up and a full period elapsed no credit " +
			"arrived; refusing to refill across a step back must not become a " +
			"refusal to refill at all")
	}
}

// TestAnInvalidHeaderFloodIsSelfLimitingWhateverGoodwillTheSenderHas is the
// work-check amnesty, stated from the far side of its fix.
//
// The price stands ahead of work.Check, which is the whole saving, and it
// follows that past the budget a header the work check WOULD refuse is never
// refused by it. While the over-budget verdict was unconditionally unscored,
// ScoreInvalidMessage therefore never fired: measured at sixty headers from
// +20 and from ScoreCeiling, banned neither time, with a recorded height taken
// from headers carrying no valid proof of work. Since the budget IS the ratio
// ScoreBanThreshold/ScoreInvalidMessage, the budget and the ban coincided only
// at score zero, so every peer that had ever relayed anything useful was
// exempt — and ScoreUsefulMessage is +1 against a ceiling of 100, so that is
// the steady state of an ordinary gossiping peer rather than an exotic one.
//
// What separates a flood from an honest catch-up peer is not the budget and
// not the score: it is whether the work check has ever refused THIS identity's
// announcements. An honest peer's header meets the target its own header
// declares, so an honest peer cannot set that fact, and
// TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget is
// the row that would fail if it could. An invalid-header flood sets it on its
// first EVALUATED message, which is inside the budget by construction.
//
// The three rows are the three goodwill levels measured. All three must
// now ban, and the count is the assertion: from zero the budget alone reaches
// the threshold, and from goodwill G the flood pays for G as well, so the bound
// is (G + -ScoreBanThreshold)/-ScoreInvalidMessage messages and NOT the sixty
// this test sends.
//
// The scores are applied here the way node.go applies them, because the engine
// returns a verdict and never scores anything itself; without that this would
// measure a verdict rather than a bound.
func TestAnInvalidHeaderFloodIsSelfLimitingWhateverGoodwillTheSenderHas(t *testing.T) {
	const peer = "10.70.0.14:5000"
	const send = 60

	// A target no digest can meet, so pow.CheckWork refuses every one of these
	// headers — the charged half the budget contrasts itself with.
	unmeetable := u256.FromUint64(1)

	for _, start := range []int{0, -ScoreInvalidMessage, ScoreCeiling} {
		h := newBudgetHarness(t)
		p := h.c.Params()
		own := pow.SeedEpochFor(h.c.Tip().Height, p)
		h.e.Peers.Add(peer)
		h.e.Peers.Adjust(peer, start)

		sent, refusedUnevaluated, evaluated := 0, 0, 0
		for n := 0; n < send; n++ {
			if h.e.Peers.Banned(peer) {
				break
			}
			epoch := own + 2 + uint64(n)
			hd := h.headerAtEpoch(t, epoch, uint64(n), unmeetable).hd
			v := h.e.OnBlockAnnounce(peer, BlockAnnounce{Header: hd}.MarshalAnnounce())
			sent++
			switch {
			case v.Cost == CostBudgeted:
				refusedUnevaluated++
			case v.Score == ScoreInvalidMessage && errors.Is(v.Err, ErrKeyEpochBudget):
				// Over budget AND scored: the conjunct this test is about.
			default:
				evaluated++
			}
			// Exactly what node.go does with a verdict.
			if v.Score != 0 {
				h.e.Peers.Adjust(peer, v.Score)
			}
		}

		banned := h.e.Peers.Banned(peer)
		end, _ := h.e.Peers.Get(peer)
		t.Logf("start %+d: sent %d, %d evaluated by the work check, %d refused "+
			"unevaluated and unscored, banned=%v, end score %d",
			start, sent, evaluated, refusedUnevaluated, banned, end.Score)

		if !banned {
			t.Errorf("start %+d: a peer was NOT banned by %d headers the work "+
				"check refuses. Past the budget such a header never reaches the "+
				"work check, so an unconditionally unscored refusal is an "+
				"amnesty and the flood stops terminating", start, sent)
			continue
		}
		// The count, not merely the ban: a flood that ends after sixty messages
		// and one that ends after the derived number are both "banned", and only
		// the second says the refusal is charged at ScoreInvalidMessage.
		want := (start + -ScoreBanThreshold) / -ScoreInvalidMessage
		if sent != want {
			t.Errorf("start %+d: banned after %d headers, want exactly %d "+
				"(goodwill %d plus the threshold %d, at %d each). A different "+
				"count means the over-budget refusal is charged at some other "+
				"rate than the work check's own",
				start, sent, want, start, -ScoreBanThreshold, -ScoreInvalidMessage)
		}
		// Anti-vacuity in the direction that matters: the ban must not be
		// reachable without the budget ever refusing anything, or this row is
		// TestAUniqueInvalidHeaderFloodIsSelfLimiting under another name.
		if start != 0 && evaluated >= sent {
			t.Errorf("start %+d: every one of the %d headers reached the work "+
				"check, so the budget refused nothing and this row does not "+
				"exercise the over-budget path at all", start, sent)
		}
	}
}

// TestAnHonestCatchUpPeerNeverLosesTheUnscoredRefusal is the other side of the
// conjunct above, and it is what stops that fix from being the liveness bug
// that reverted I7-H4's tip window.
//
// The over-budget refusal is scored only for an identity the work check has
// already refused. This drives the honest arrangement — every header PASSES the
// work check, which is what an honest announcer sends — far past the budget,
// and requires that nothing is ever scored and nothing is ever banned.
//
// Two separating inputs, not one: without the workRefused conjunct every row
// here would be charged ScoreInvalidMessage and banned within
// MaxUnheldKeyEpochsPerPeer of the budget running out; without the budget
// itself nothing would be refused and the loop would prove nothing. The
// refusal count is asserted for the second reason.
func TestAnHonestCatchUpPeerNeverLosesTheUnscoredRefusal(t *testing.T) {
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	const peer = "10.70.0.15:5000"
	const send = 40
	h.e.Peers.Add(peer)

	refused, scored := 0, 0
	for n := 0; n < send; n++ {
		v := h.announceAtEpoch(t, peer, own+2+uint64(n), uint64(n))
		if v.Cost == CostBudgeted {
			refused++
		}
		if v.Score < 0 {
			scored++
			h.e.Peers.Adjust(peer, v.Score)
		}
	}
	t.Logf("an honest peer at valid work, %d announcements outside the working "+
		"epochs: %d refused unevaluated, %d scored, banned=%v",
		send, refused, scored, h.e.Peers.Banned(peer))

	if scored != 0 {
		t.Errorf("%d of %d honest announcements were charged a negative score. "+
			"A node behind the chain receives these legitimately, and scoring "+
			"them is the failure that reverted the tip-window guard", scored, send)
	}
	if h.e.Peers.Banned(peer) {
		t.Error("an honest peer was banned by ordinary announcements outside " +
			"this node's working key epochs")
	}
	if refused != send-MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("%d of %d announcements were refused unevaluated, want %d; "+
			"the budget is not doing the refusing, so the absence of a score "+
			"above is not about the over-budget path",
			refused, send, send-MaxUnheldKeyEpochsPerPeer)
	}
}
