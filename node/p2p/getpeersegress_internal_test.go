package p2p

import (
	"errors"
	"testing"
	"time"
)

// Peer exchange against the node-wide egress layer.
//
// The two served-reply kinds carry a per-identity reply-byte budget, and a
// second layer sits over it keyed on nothing a sender presents. This
// handler stood outside the second layer, and the cost of that was a false
// sentence rather than a resource hole: chargeReplyBytes derives the node-wide
// layer from "the total this node emits", wire.md §10.4's second normative
// bullet says the same, and the counter behind both held the total of the two
// *other* kinds. One connection buys at most one ~1.2 KB reply per memo window,
// so the uncounted traffic is a fraction of a percent of the ceiling and no
// arrangement of peers exhausts anything — what these tests hold down is that
// the counter now holds what it is documented to hold, and that moving it there
// did not cost the two bounds this handler already had.
//
// Four properties, four separating inputs, because the change is four decisions
// and not one:
//
//	served     ⇒  the reply's bytes are added to servedBytes
//	refused    ⇐  servedBytes ≥ replyByteCeiling, unscored
//	refused    ⇒  the asker's memo window is NOT spent
//	inside the window  ⇒  Scored(excess request), ceiling spent or not
//
// The last is the ordering, and it is a property rather than an implementation
// detail: a ceiling refusal is never scored, so deciding it ahead of the memo
// window would turn a flood inside the window into an unscored refusal exactly
// when this node is busiest.

// exhaustNodeEgress spends this node's whole node-wide reply-byte ceiling at
// the fixture's current clock, the way a window's worth of get-block and
// get-headers replies to other peers would, and returns the two derived numbers
// so a test can move the clock by a real period rather than a retyped one.
//
// It charges the layer directly instead of mining a chain and serving real
// bodies: what is under test here is this handler's reaction to a spent
// ceiling, and TestTheAggregateServedIsBoundedOverIdentityChurnAndNotOnly-
// PerIdentity next door is what pins that real replies fill it.
func exhaustNodeEgress(t *testing.T, e *Engine) (budget, period uint64) {
	t.Helper()
	budget, period = replyByteBudget(e.Chain.Params())
	if period == 0 {
		t.Fatal("the fixture's parameters disable the reply-byte layers entirely; " +
			"every assertion about a spent ceiling below would be vacuous")
	}
	e.chargeNodeServedBytes(replyByteCeiling(e.connSetLocked(), budget), budget, period, e.now())
	if !e.nodeServedBytesExhausted(budget, period, e.now()) {
		t.Fatal("the fixture did not manage to spend the node-wide ceiling; the " +
			"refusals below would be asserted against a layer that is not exhausted")
	}
	return budget, period
}

// nodeServed reads the node-wide total under the lock that owns it.
func nodeServed(e *Engine) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.servedBytes
}

// TestAServedGetPeersReplyIsCountedByTheNodeWideEgressLayer is the half
// that is about the counter rather than about a refusal: the bytes this node
// puts on the wire answering peer exchange are bytes its own node-wide total
// counts.
//
// The assertion is on the exact byte count and not on "moved", because the
// documented quantity is a total and a total that moves by the wrong amount is
// the same defect one step later.
func TestAServedGetPeersReplyIsCountedByTheNodeWideEgressLayer(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 512, &clock)
	const honest = "10.66.0.1:5000"
	getPeersHandshake(t, e, honest)

	before := nodeServed(e)
	v := e.Handle(honest, KindGetPeers, nil)
	if v.Reply == nil || v.Err != nil {
		t.Fatalf("the request was not served: reply=%v err=%v", v.Reply, v.Err)
	}
	// Anti-vacuity: a zero-byte reply would make the equality below hold for
	// both the charged and the uncharged program.
	sent := uint64(len(v.Reply.Payload))
	if sent == 0 {
		t.Fatal("the fixture served a zero-byte peers frame; a charge of nothing " +
			"is indistinguishable from no charge at all")
	}
	if got := nodeServed(e) - before; got != sent {
		t.Errorf("a %d-byte peers reply moved this node's node-wide served total by "+
			"%d. chargeReplyBytes derives that layer from \"the total this node "+
			"emits\" and wire.md §10.4 says the same; a served kind outside it "+
			"makes the counter hold a different total from the one both sentences "+
			"name", sent, got)
	}
	// And the reply is priced as what it now is. wire.md §10.3's `get-peers` /
	// Served row reads `Budgeted`, and a class the table does not carry for this
	// kind is instance sixteen of the cost-discipline programme.
	if v.Cost != CostBudgeted {
		t.Errorf("a served peers reply is priced %v, want %v (wire.md §10.3)", v.Cost, CostBudgeted)
	}
	if v.Score != 0 {
		t.Errorf("a served peers reply charged the asker %d; serving an asker on "+
			"the interval this node's own rule names is not misbehaviour", v.Score)
	}
}

// TestGetPeersIsRefusedOnceTheNodeWideCeilingIsSpent is the other direction of
// the same sentence: a layer that counts a reply and would still emit it past
// its own bound is a meter, not a ceiling.
func TestGetPeersIsRefusedOnceTheNodeWideCeilingIsSpent(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 512, &clock)
	const honest = "10.66.0.1:5000"
	getPeersHandshake(t, e, honest)
	exhaustNodeEgress(t, e)

	before := nodeServed(e)
	v := e.Handle(honest, KindGetPeers, nil)
	if v.Reply != nil {
		t.Fatalf("a peers reply of %d bytes was served past the node-wide ceiling; "+
			"the layer counts the bytes and does not bound them", len(v.Reply.Payload))
	}
	if v.Cost != CostBudgeted {
		t.Errorf("the refusal is priced %v, want %v: a bounded resource this node "+
			"had already committed was spent (wire.md §10.2)", v.Cost, CostBudgeted)
	}
	// Never scored, and this is the conjunct that keeps a shared lever off an
	// innocent peer: this asker may have sent nothing at all this window and
	// still meet the ceiling somebody else drained.
	if v.Score != 0 {
		t.Errorf("the node-wide ceiling charged the asker %d. A ceiling keyed on "+
			"nothing the sender presents can be drained by traffic this peer never "+
			"sent, so wire.md §10.4 charges the excess-request score only where the "+
			"sender's OWN budget refused it", v.Score)
	}
	if v.Err != ErrGetPeersNodeEgress {
		t.Errorf("the refusal reports %v, want ErrGetPeersNodeEgress: the refusal "+
			"names which layer refused, and refuseUnbudgeted's sentence about the "+
			"peer's own budget would be a false one here", v.Err)
	}
	if !errors.Is(v.Err, ErrReplyBudget) {
		t.Errorf("the refusal does not match ErrReplyBudget; it is the family " +
			"sentinel a caller sorting refusals from failures matches on")
	}
	if got := nodeServed(e) - before; got != 0 {
		t.Errorf("a refused request still moved the node-wide total by %d bytes; "+
			"nothing was sent", got)
	}
}

// TestACeilingRefusalDoesNotSpendTheAskersMemoWindow: the shared layer's
// refusal is not the asker's fault, so it must not cost the asker anything
// either — including the one thing this handler charges, which is the memo
// window.
//
// The separating input is the whole point of the ordering: the ceiling refills
// in one block interval, which on this fixture is well inside
// GetPeersMinInterval, so an honest peer refused by somebody else's traffic
// comes back before its own window has closed. If the refusal had stamped
// lastGetPeers, that return is answered ErrGetPeersTooOften and scored -
// somebody else's traffic having cost this peer both the reply and the charge.
func TestACeilingRefusalDoesNotSpendTheAskersMemoWindow(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 512, &clock)
	const honest = "10.66.0.1:5000"
	getPeersHandshake(t, e, honest)
	_, period := exhaustNodeEgress(t, e)

	refill := time.Duration(period) * time.Second
	if refill >= GetPeersMinInterval {
		t.Fatalf("this fixture refills the ceiling in %v, at or past the %v memo "+
			"window: the retry below would be served whether or not the refusal "+
			"stamped the window, so this test separates nothing", refill, GetPeersMinInterval)
	}
	if v := e.Handle(honest, KindGetPeers, nil); v.Err != ErrGetPeersNodeEgress {
		t.Fatalf("the request past the ceiling was answered %v; this test needs the "+
			"ceiling refusal it is about", v.Err)
	}

	clock = clock.Add(refill)
	v := e.Handle(honest, KindGetPeers, nil)
	if v.Err == ErrGetPeersTooOften {
		t.Fatalf("a request %v after a refusal by the SHARED ceiling was refused as "+
			"a repeat: the refusal consumed the asker's %v memo window, so traffic "+
			"this peer never sent cost it both the reply and the interval",
			refill, GetPeersMinInterval)
	}
	if v.Reply == nil || v.Err != nil {
		t.Fatalf("the retry after the ceiling refilled was not served: reply=%v err=%v",
			v.Reply, v.Err)
	}
}

// TestARepeatInsideTheWindowIsStillScoredWhileTheCeilingIsSpent pins the order
// of the two refusals against each other.
//
// The excess-request charge is what makes a flood of get-peers terminate:
// ScoreExcessRequest against ScoreBanThreshold ends it in twenty frames. A
// ceiling refusal carries no score, deliberately, so deciding the ceiling first
// would silently move every repeat inside the window into the unscored class
// for as long as the ceiling is spent - which is precisely when this node can
// least afford an unterminating flood. The memo window is decided first, and
// this is the input that separates the two orders.
func TestARepeatInsideTheWindowIsStillScoredWhileTheCeilingIsSpent(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 512, &clock)
	const attacker = "10.66.0.1:5000"
	getPeersHandshake(t, e, attacker)

	// One served request, which is what puts the attacker inside its window.
	if v := e.Handle(attacker, KindGetPeers, nil); v.Reply == nil {
		t.Fatalf("the first request was not served: %v", v.Err)
	}
	exhaustNodeEgress(t, e)

	clock = clock.Add(time.Millisecond)
	v := e.Handle(attacker, KindGetPeers, nil)
	if v.Err != ErrGetPeersTooOften {
		t.Fatalf("a repeat inside the %v window was refused with %v, not %v: the "+
			"node-wide ceiling decided a refusal the memo window owns",
			GetPeersMinInterval, v.Err, ErrGetPeersTooOften)
	}
	if v.Cost != CostScored || v.Score != ScoreExcessRequest {
		t.Fatalf("the repeat was priced %v/%d, want %v/%d. An unscored refusal "+
			"terminates no flood (wire.md §10.2), and the flood does not stop "+
			"being a flood because this node is busy",
			v.Cost, v.Score, CostScored, ScoreExcessRequest)
	}
}
