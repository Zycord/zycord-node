package p2p_test

import (
	"testing"
	"time"

	"zycord/node/p2p"
)

// The inbound budget and the sync connection (R7 §2).
//
// `Listener.Accept` bounds inbound connections per *address group* — the /16 —
// which is the eclipse defence and is correct: one source must not fill a node's
// inbound slots. But sync opens its own dedicated connection (spec/wire.md §12)
// and that socket was charged to the same budget as the long-lived gossip
// connections. A node whose slots were full by ordinary peering refused the very
// connection a peer needed in order to catch up: two classes with opposite
// lifetimes sharing one allowance, which is a conflation rather than a policy.
//
// It bites hardest for the population the whitepaper targets. Behind CGNAT or
// any shared residential prefix, honest peers land in one group by default, and
// sync doubles the connection demand exactly when a node is behind.
//
// The fix is a small separate allowance for connections that do not *hold*. The
// listener cannot ask which class a connection is — it accepts before any frame
// is exchanged — so the class is defined by behaviour: a reserve connection may
// exist, but may not persist.
//
// These tests are deterministic. The soak sees the consequence when the timing
// lines up; these see the mechanism every run.

func fillHeldBudget(t *testing.T, ln *p2p.Listener, dialer *p2p.Identity,
	accepted <-chan *p2p.Conn, n int) []*p2p.Conn {
	t.Helper()
	var held []*p2p.Conn
	for i := 0; i < n; i++ {
		c, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("peer connection %d refused before the budget was full: %v", i, err)
		}
		held = append(held, c)
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatalf("peer connection %d was never accepted", i)
		}
	}
	return held
}

func listenerHarness(t *testing.T, perSource int) (*p2p.Listener, *p2p.Identity, chan *p2p.Conn) {
	t.Helper()
	id, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", perSource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan *p2p.Conn, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dialer, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return ln, dialer, accepted
}

// TestASyncConnectionFitsInTheReserve is the fix: a catching-up peer gets in
// even when ordinary peering has filled the holding budget.
func TestASyncConnectionFitsInTheReserve(t *testing.T) {
	const perSource = 3
	ln, dialer, accepted := listenerHarness(t, perSource)

	held := fillHeldBudget(t, ln, dialer, accepted, perSource)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	sync, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("the sync connection could not be dialled: %v", err)
	}
	defer sync.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("a catching-up peer's sync connection was refused because ordinary " +
			"peering had filled the inbound budget: behind CGNAT or any shared " +
			"prefix this is the common path, and it refuses exactly the connection " +
			"a node behind the chain needs")
	}
}

// TestTheReserveIsBounded: it is a reserve, not a second helping. Without this
// the fix would simply widen the eclipse bound.
func TestTheReserveIsBounded(t *testing.T) {
	const perSource = 3
	ln, dialer, accepted := listenerHarness(t, perSource)

	held := fillHeldBudget(t, ln, dialer, accepted, perSource+p2p.DefaultInboundReserve)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	over, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
	if err == nil {
		defer over.Close()
	}
	select {
	case <-accepted:
		t.Fatalf("a source held %d inbound connections against a budget of %d + a "+
			"reserve of %d: the reserve has become an unlimited second helping and "+
			"the eclipse bound means nothing",
			perSource+p2p.DefaultInboundReserve+1, perSource, p2p.DefaultInboundReserve)
	case <-time.After(2 * time.Second):
	}
}

// TestTheReserveDoesNotPersist is the half that keeps the eclipse bound honest.
//
// A reserve connection may exist; it may not persist. If it could, the reserve
// would be two extra permanent slots per source — a straight widening of the
// bound this defence exists to impose, dressed as a fix.
func TestTheReserveDoesNotPersist(t *testing.T) {
	const perSource = 2
	ln, dialer, accepted := listenerHarness(t, perSource)
	ln.SetProbation(300 * time.Millisecond)

	held := fillHeldBudget(t, ln, dialer, accepted, perSource)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	squatter, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("setup: the reserve connection was not accepted")
	}

	if got := ln.ExpiredProbation(); len(got) != 0 {
		t.Fatalf("a reserve connection was reported expired immediately (%v): the "+
			"window is not being applied", got)
	}

	time.Sleep(500 * time.Millisecond)
	expired := ln.ExpiredProbation()
	if len(expired) == 0 {
		t.Fatal("a reserve connection outstayed its window and was not reported: " +
			"the reserve is two extra permanent inbound slots per source, which is " +
			"a wider eclipse bound wearing the fix's clothes")
	}

	// And a held connection is never reported: the holding budget is a
	// different class and is allowed to persist indefinitely.
	for _, addr := range expired {
		for _, h := range held {
			if addr == h.Addr {
				t.Fatal("a connection inside the holding budget was reported as an " +
					"expired reserve connection")
			}
		}
	}
}

// TestARefusedInboundIsCountable arms an instrument rather than a hypothesis.
//
// Dimension (b) was "an outbound-only node specifically", on a correlation with
// a sample size of one node. Reading the code says what is different about such
// a node — it advertises no dialable address, so no peer can ever dial it, add
// it to a peer store, or sync *from* it; it can only pull — but none of that
// explains a node that pulls and fails. What does bear on it is capacity, and
// capacity was unobservable.
//
// Every peer in the soak reaches a node through that node's chaos proxy, so
// every inbound connection arrives from 127.0.0.1 and the whole network shares
// ONE address group. That is deliberate — it is the CGNAT case the whitepaper's
// target population lives in, and `assertOneAddressGroup` states it as a
// precondition. The consequence is arithmetic: `perSource` (3) held slots and
// `DefaultInboundReserve` (2) reserve slots are shared by *every* peer, so at
// most two peers in the group can be catching up at any moment. A third is
// refused — before the TLS handshake, with no log line here and a bare EOF
// there.
//
// So the two candidate explanations for a stranded node's 166 EOF sync attempts
// — a severed link and a refused accept — were the same observation from both
// ends. This does not decide between them. It makes them different observations,
// which is the prerequisite for deciding.
//
// A counter and not an alarm, deliberately. A refusal is the eclipse defence
// doing exactly its job, and a check that fires for a benign reason is noise
// with authority (CONTRIBUTING). It becomes a signal only beside the sync
// failures at the other end.
func TestARefusedInboundIsCountable(t *testing.T) {
	const perSource = 3
	ln, dialer, accepted := listenerHarness(t, perSource)

	// Ordinary peering fills the holding budget, then the reserve fills with
	// the sync connections of peers that are catching up.
	held := fillHeldBudget(t, ln, dialer, accepted, perSource+p2p.DefaultInboundReserve)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	// Anti-vacuity: nothing has been refused yet, so a non-zero count below is
	// caused by the dial that follows and not by the setup.
	if got := ln.Refused(); got != 0 {
		t.Fatalf("%d connections were already refused before the budget was full; "+
			"the count below would not be attributable to anything", got)
	}

	over, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
	if err == nil {
		defer over.Close()
	}
	select {
	case <-accepted:
		t.Fatal("setup: the connection past the budget was accepted, so nothing " +
			"was refused and this test is measuring the wrong thing")
	case <-time.After(2 * time.Second):
	}

	if got := ln.Refused(); got == 0 {
		t.Fatalf("a connection was turned away for a full inbound budget and the "+
			"node recorded nothing. The socket is closed before the TLS handshake, "+
			"so the dialer sees a bare EOF and this node sees no event at all — "+
			"which makes 'my peer is full' and 'my link was severed' the same "+
			"observation from both ends. With every peer in one address group, "+
			"%d held plus %d reserve slots are shared by the whole network, so at "+
			"most %d peers can be catching up at once however many there are.",
			perSource, p2p.DefaultInboundReserve, p2p.DefaultInboundReserve)
	}
}

// TestASquatterIsNotForgivenByTheNextConnection closes the hole that made the
// reserve's second half a no-op.
//
// The reserve's whole justification is "may exist, may not persist": a
// connection past its window is reported by `ExpiredProbation` and closed by
// `Node.probationLoop`. But `expireProbationLocked` runs inside `Accept` on
// every new inbound connection from the same group, and it *deletes* the
// expired entry — freeing the reserve slot without closing anything.
//
// So a squatter only has to survive until the next connection from its own
// address group arrives. That erases the reaper's only record of it, the
// connection persists indefinitely, and the slot it vacated can be taken
// again. One group holds unbounded persistent inbound connections, which is
// the eclipse bound this defence exists to impose, defeated by the bookkeeping
// meant to enforce it.
//
// `TestTheReserveDoesNotPersist` cannot see it: it never dials again after the
// window passes, so the erasing path is never taken.
func TestASquatterIsNotForgivenByTheNextConnection(t *testing.T) {
	const perSource = 2
	ln, dialer, accepted := listenerHarness(t, perSource)
	ln.SetProbation(300 * time.Millisecond)

	held := fillHeldBudget(t, ln, dialer, accepted, perSource)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	squatter, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("setup: the reserve connection was never accepted")
	}

	time.Sleep(500 * time.Millisecond)
	// Anti-vacuity: it must be reported expired before the next dial, or the
	// erasure below has nothing to erase.
	if len(ln.ExpiredProbation()) == 0 {
		t.Fatal("setup: the squatter was not reported expired, so the window is " +
			"not being applied and this test arms nothing")
	}

	// The next connection from the same group. This is the whole scenario.
	next, err := dialer.Dial(ln.Addr().String(), 5*time.Second)
	if err == nil {
		defer next.Close()
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
	}

	if len(ln.ExpiredProbation()) == 0 {
		t.Fatal("a squatter past its window stopped being reported the moment " +
			"another connection arrived from its own address group. Nothing closes " +
			"it now: the reserve is two extra permanent inbound slots per group, " +
			"refreshed for free by any new connection, and the eclipse bound the " +
			"whole defence exists to impose is gone.")
	}
}
