package p2p

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// budgetNode is the smallest Node the dial-budget reservation is visible in:
// the connection map, the reservation map, the two capacity fields, and the
// collaborators serve dereferences on the paths below.
//
// The Engine is a bare struct rather than a wired one. Every call the paths
// under test make on it — SetDialledGroups, forgetPeer — is bookkeeping over
// its own maps, and giving it a chain would only add ways for these tests to
// fail for a reason that is not the property.
func budgetNode(t *testing.T, maxOut int) *Node {
	t.Helper()
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	return &Node{
		Engine: &Engine{},
		Peers:  ps,
		// A bare Listener, and no socket. The only thing the inbound path below
		// asks of it is Release(0), which every Conn this test builds carries
		// and which is a documented no-op — so binding a port would be a real
		// resource bought to exercise nothing.
		listener:        &Listener{},
		MaxInbound:      32,
		MaxOutbound:     maxOut,
		conns:           map[string]*Conn{},
		outboundTargets: map[string]bool{},
	}
}

// dialBudget is the quantity the defect consumes, read exactly as dialTargets
// computes it. Asserting on this rather than on len(outboundTargets) is what
// keeps these tests about the failure — a node that stops dialling — rather
// than about a map.
func dialBudget(n *Node) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.MaxOutbound - len(n.outboundTargets)
}

func reserved(n *Node, addr string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.outboundTargets[addr]
}

// serveOnce runs the real serve, synchronously, on a socket that goes nowhere.
// The paths these tests drive all return before the first frame is written, so
// a pipe is the whole transport they need; its peer end is closed with the
// test so a path that did try to write cannot block instead of failing.
func serveOnce(t *testing.T, n *Node, c *Conn, outbound bool) {
	t.Helper()
	peer, local := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	c.Conn = local
	n.wg.Add(1) // serve's own deferred Done, which Start would otherwise pair.
	n.serve(c, outbound)
}

// TestARefusedOutboundDialGivesBackItsDialBudget is the counter property, and
// it is a loop for the reason a counter bug is a counter bug: a single refusal
// leaves a budget that is wrong by one, which is indistinguishable from noise,
// and the failure this issue describes is what that one costs after it has
// happened MaxOutbound times. The assertion is that the budget is where it
// started — not that some particular refusal was survived.
//
// The refusal driven here is register's duplicate-address term, on an outbound
// connection. That term is unconditional (it does not care about direction, see
// TestInboundAdmissionRefusesAtCapacityAndOnlyThere), so an outbound dial can
// be refused by it whenever the address it dialled has become held since
// dialTargets last looked — an inbound connection observed at that same
// address, arriving during the round, is the reachable case.
func TestARefusedOutboundDialGivesBackItsDialBudget(t *testing.T) {
	const maxOut = 8
	// Three times the whole budget, so a leak of one per refusal does not merely
	// dent the budget, it exhausts it — the state in which the node has stopped
	// dialling out altogether.
	const rounds = 3 * maxOut

	n := budgetNode(t, maxOut)
	start := dialBudget(n)
	if start != maxOut {
		t.Fatalf("setup: a node that has dialled nothing must have its whole budget, got %d", start)
	}

	for r := 0; r < rounds; r++ {
		addr := fmt.Sprintf("203.0.113.%d:9000", r+1)

		// Somebody else already holds the address. This is what makes the
		// register below refuse, and it is the only thing that does: the
		// capacity term cannot fire on an outbound connection.
		n.mu.Lock()
		n.conns[addr] = &Conn{Addr: addr}
		n.mu.Unlock()

		// Exactly what topUp does after a successful dial, and before it hands
		// the connection to serve.
		n.reserveOutboundTarget(addr)
		if got := dialBudget(n); got != start-1 {
			t.Fatalf("round %d: the reservation was not taken: budget %d, want %d. "+
				"Everything below this line asserts nothing if the claim is a no-op",
				r, got, start-1)
		}

		serveOnce(t, n, &Conn{Addr: addr}, true)

		if reserved(n, addr) {
			t.Fatalf("round %d: the refused dial to %s kept its reservation", r, addr)
		}
		if got := dialBudget(n); got != start {
			t.Fatalf("round %d of %d: a refused outbound dial did not give back its "+
				"dial budget: %d of %d slots left, and the loss is permanent — "+
				"outboundTargets is never swept",
				r, rounds, got, start)
		}
	}

	// The connection map is where the refusals came from, so it must have grown
	// by exactly the addresses this test parked in it and nothing else: a
	// register that had admitted the duplicates would have made every round
	// above vacuous.
	n.mu.Lock()
	held := len(n.conns)
	n.mu.Unlock()
	if held != rounds {
		t.Fatalf("expected the %d parked addresses and no admitted duplicates, got %d entries", rounds, held)
	}
}

// TestAnAdmittedOutboundDialGivesBackItsDialBudget separates the other half of
// serve's exit: the connection that register admits and that then ends.
//
// It is not a weaker version of the test above. The two rows separate the one
// condition the release is guarded by from the position it is installed at: a
// release attached to the refusal alone passes the test above and fails this
// one, and a release attached to admission alone — which is what the defect
// was — passes this one and fails that.
//
// The exit taken here is the banned-identity return, because it is the first
// exit past the admission gate and it needs no handshake.
func TestAnAdmittedOutboundDialGivesBackItsDialBudget(t *testing.T) {
	const maxOut = 8
	const rounds = 3 * maxOut

	n := budgetNode(t, maxOut)
	start := dialBudget(n)

	for r := 0; r < rounds; r++ {
		addr := fmt.Sprintf("198.51.100.%d:9000", r+1)
		key := bannedKeyForTest(t, n, r)

		n.reserveOutboundTarget(addr)
		if got := dialBudget(n); got != start-1 {
			t.Fatalf("round %d: the reservation was not taken: budget %d, want %d", r, got, start-1)
		}

		serveOnce(t, n, &Conn{Addr: addr, PeerKey: key}, true)

		if reserved(n, addr) {
			t.Fatalf("round %d: the admitted dial to %s kept its reservation after it ended", r, addr)
		}
		if got := dialBudget(n); got != start {
			t.Fatalf("round %d of %d: an admitted outbound dial did not give back its "+
				"dial budget when it ended: %d of %d slots left", r, rounds, got, start)
		}
		n.mu.Lock()
		_, stillHeld := n.conns[addr]
		n.mu.Unlock()
		if stillHeld {
			t.Fatalf("round %d: %s was admitted and never unregistered, so this round "+
				"never reached the exit it is about", r, addr)
		}
	}
}

// TestAnInboundRefusalDoesNotSpendSomebodyElsesDialBudget is the separating row
// for the one condition the release is guarded by, and it exists because the
// obvious simplification — release unconditionally, the address is the key
// either way — is wrong in the direction nothing else here would catch.
//
// n.conns is keyed by observed address and holds one connection per address, so
// an inbound connection whose observed address collides with an address this
// node has dialled is refused by the same duplicate-address term. Releasing on
// its way out would drop a reservation belonging to an outbound connection that
// is still up, and the node would then dial a replacement for a peer it has not
// lost: a connection set that grows past MaxOutbound, without bound, which is
// the same accounting defect with the sign flipped.
//
// The collision this needs is the same collision the refused outbound dial
// needs, so this mirror is reachable exactly when the defect is — it is not a
// weaker hypothetical bolted onto a real one.
func TestAnInboundRefusalDoesNotSpendSomebodyElsesDialBudget(t *testing.T) {
	const maxOut = 8
	const rounds = 3 * maxOut
	const addr = "192.0.2.10:9000"

	n := budgetNode(t, maxOut)
	start := dialBudget(n)

	// One live outbound connection, admitted, holding its reservation.
	n.reserveOutboundTarget(addr)
	n.mu.Lock()
	n.conns[addr] = &Conn{Addr: addr}
	n.mu.Unlock()
	if got := dialBudget(n); got != start-1 {
		t.Fatalf("setup: budget %d, want %d", got, start-1)
	}

	for r := 0; r < rounds; r++ {
		// An inbound arrival observed at the very address the outbound
		// connection above is registered under. register refuses it.
		serveOnce(t, n, &Conn{Addr: addr}, false)

		if !reserved(n, addr) {
			t.Fatalf("round %d: an inbound refusal released the outbound reservation for %s, "+
				"which is still connected. The dial budget is now larger than the "+
				"connections this node actually holds", r, addr)
		}
		if got := dialBudget(n); got != start-1 {
			t.Fatalf("round %d of %d: the dial budget grew on an inbound refusal: %d, want %d",
				r, rounds, got, start-1)
		}
	}

	// And the outbound side's own serve still returns it, so what the loop above
	// pins is "not released by the wrong connection" and not "never released".
	// This serve is itself refused — the entry standing in for the live outbound
	// connection is exactly the duplicate register objects to — which is the
	// point: the direction is the whole difference between this call and the
	// twenty-four before it.
	serveOnce(t, n, &Conn{Addr: addr}, true)
	if got := dialBudget(n); got != start {
		t.Fatalf("the outbound connection's own exit did not return its reservation: %d, want %d", got, start)
	}
}

// TestConcurrentRefusedDialsReturnTheWholeDialBudget drives the release from
// the goroutines it actually runs on.
//
// topUp reserves on the dial loop and releases on one serve goroutine per
// connection, so the reservation map is read and written from several
// goroutines at once and the accounting is only worth as much as the mutex
// discipline around it. The rows above are single-threaded by construction and
// say nothing about that; this is the row worth running under -race.
//
// The assertion is still the same one: the budget is where it started.
func TestConcurrentRefusedDialsReturnTheWholeDialBudget(t *testing.T) {
	const maxOut = 8
	const dials = 64

	n := budgetNode(t, maxOut)
	start := dialBudget(n)

	conns := make([]*Conn, 0, dials)
	for i := 0; i < dials; i++ {
		addr := fmt.Sprintf("203.0.113.%d:9000", i+1)
		peer, local := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		n.mu.Lock()
		n.conns[addr] = &Conn{Addr: addr} // held, so every dial below is refused
		n.mu.Unlock()
		n.reserveOutboundTarget(addr)
		conns = append(conns, &Conn{Conn: local, Addr: addr})
	}
	if got := dialBudget(n); got != start-dials {
		t.Fatalf("setup: %d reservations were not all taken: budget %d, want %d", dials, got, start-dials)
	}

	begin := make(chan struct{})
	for _, c := range conns {
		n.wg.Add(1)
		go func(c *Conn) {
			<-begin
			n.serve(c, true)
		}(c)
	}
	close(begin)
	n.wg.Wait()

	if got := dialBudget(n); got != start {
		t.Fatalf("%d concurrent refused dials left the budget at %d of %d", dials, got, start)
	}
}

// logGate is an io.Writer that blocks the goroutine writing to it until the
// test lets it go, and reports when it was entered.
//
// It exists to place a goroutine at a known instruction without sampling for
// it. Node.log is the last thing serve does before its defers run on the
// banned-identity exit, so a writer that parks there parks a connection that
// has provably been admitted and has provably not begun its teardown.
type logGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *logGate) Write(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return len(p), nil
}

// TestTeardownNeverShowsAReservationWithoutItsConnection pins that the two
// deletions a retiring outbound connection makes are one step as far as the
// dial loop is concerned.
//
// The pair (reserved, not connected) is the state that must not be observable.
// dialTargets excludes n.conns outright but only *charges* outboundTargets
// against the diversity budgets — PeerStore.selectLocked never excludes held,
// and its fallback pass admits up to MaxFallbackPerGroup addresses per group —
// so an address seen in that window is a legal dial target again while a
// release is still owed on it, and that release then lands on the *new*
// connection's reservation. A dial budget larger than the connections this node
// holds is the same reservation leak with the sign flipped.
//
// **This is deterministic, not a race hunt, and two locks are what make it so.**
//
// First the log gate, which parks the connection after register (and after the
// connection-set publication register makes, which takes e.mu and would
// otherwise be the acquisition this test caught) and before any defer has run.
// Only then does the test take e.mu. Both teardown orders publish the dialled
// groups after their first deletion, so e.mu parks the goroutine at a known
// instruction — past whatever it has already deleted, short of anything it has
// not — and the test reads both maps under n.mu at leisure. A split teardown is
// parked with n.conns cleared and the reservation still standing; an atomic one
// is parked with both already gone. No sampling, no interleaving, no rounds.
func TestTeardownNeverShowsAReservationWithoutItsConnection(t *testing.T) {
	const addr = "192.0.2.77:9000"

	n := budgetNode(t, 8)
	key := bannedKeyForTest(t, n, 0)
	gate := &logGate{entered: make(chan struct{}), release: make(chan struct{})}
	n.Logger = log.New(gate, "", 0)

	// Exactly what topUp leaves behind: the reservation, and a connection on its
	// way to register. register is serve's to make, not the test's.
	n.reserveOutboundTarget(addr)

	peer, local := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	n.wg.Add(1)
	go func() {
		defer close(done)
		n.serve(&Conn{Conn: local, Addr: addr, PeerKey: key}, true)
	}()

	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("serve never reached the banned-identity log line, so it never got " +
			"past register and this test never reached the teardown it is about")
	}
	n.mu.Lock()
	_, connected := n.conns[addr]
	stillReserved := n.outboundTargets[addr]
	n.mu.Unlock()
	if !connected || !stillReserved {
		close(gate.release)
		<-done
		t.Fatalf("setup: connected=%v reserved=%v, want both true before the teardown starts",
			connected, stillReserved)
	}

	// Arm the park, then let the connection go.
	n.Engine.mu.Lock()
	close(gate.release)

	// The connection leaving n.conns is the first thing either teardown order
	// does, so it is the signal that the goroutine is inside its teardown — and,
	// e.mu being held, that it cannot leave it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.mu.Lock()
		_, connected := n.conns[addr]
		stillReserved := n.outboundTargets[addr]
		n.mu.Unlock()
		if !connected {
			if stillReserved {
				n.Engine.mu.Unlock()
				<-done
				t.Fatalf("%s was reserved and not connected at the same time. The dial "+
					"loop may hand this address back to topUp here, and the release "+
					"still owed on it would then drop the new connection's reservation",
					addr)
			}
			break
		}
		if time.Now().After(deadline) {
			n.Engine.mu.Unlock()
			<-done
			t.Fatal("the connection never left n.conns, so this test never reached the teardown it is about")
		}
		runtime.Gosched()
	}

	n.Engine.mu.Unlock()
	<-done

	if got := dialBudget(n); got != n.MaxOutbound {
		t.Fatalf("after the teardown finished the budget is %d of %d", got, n.MaxOutbound)
	}
}

// bannedKeyForTest mints one identity and scores it out, so serve's
// banned-identity return is reached on a connection that register has already
// admitted.
func bannedKeyForTest(t *testing.T, n *Node, seq int) ed25519.PublicKey {
	t.Helper()
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	key[0] = byte(seq + 1)
	key[1] = byte((seq + 1) >> 8)
	n.Peers.AdjustKey(key, ScoreBanThreshold)
	if !n.Peers.BannedKey(key) {
		t.Fatalf("setup: identity %d is not banned, so serve would not take the exit this test is about", seq)
	}
	return key
}
