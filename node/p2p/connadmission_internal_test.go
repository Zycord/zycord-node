package p2p

import (
	"runtime"
	"strconv"
	"sync"
	"testing"
)

// admissionNode is the smallest Node the admission decision reads: the
// connection map and the two capacity fields. Nothing else in register is
// touched, so building a whole Node (sockets, loops, a chain behind the
// Engine) would only add ways for this test to fail for a reason that is not
// the property.
//
// The Engine is left nil deliberately, and that is a second property rather
// than an omission: register publishes the connection set to the Engine on
// every call (publishConnectionSet, for Engine.unheldKeyEpochCeiling), and a
// publication that a Node without an Engine cannot survive would make the
// admission decision depend on a collaborator it does not read.
func admissionNode(maxIn, maxOut int) *Node {
	return &Node{
		MaxInbound:  maxIn,
		MaxOutbound: maxOut,
		conns:       map[string]*Conn{},
	}
}

func fill(n *Node, k int) {
	for i := 0; i < k; i++ {
		n.conns["held-"+strconv.Itoa(i)] = &Conn{Addr: "held-" + strconv.Itoa(i)}
	}
}

// TestInboundAdmissionRefusesAtCapacityAndOnlyThere separates each term of
// register's guard, because the guard is a conjunction and a single passing
// case cannot tell which term carried it.
//
// Three terms: the connection is inbound, the table is at capacity, the
// address is already held. Four inputs, each of which flips exactly one term
// away from the admitting case.
func TestInboundAdmissionRefusesAtCapacityAndOnlyThere(t *testing.T) {
	const maxIn, maxOut = 3, 2
	cap := maxIn + maxOut

	t.Run("under capacity, fresh address, inbound: admitted", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		fill(n, cap-1)
		if !n.register(&Conn{Addr: "fresh"}, false) {
			t.Fatal("an inbound connection below capacity must be admitted")
		}
		if len(n.conns) != cap {
			t.Fatalf("expected %d connections, got %d", cap, len(n.conns))
		}
	})

	// Separates the capacity term: identical to the case above except that
	// the table is one entry fuller.
	t.Run("at capacity, fresh address, inbound: refused", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		fill(n, cap)
		if n.register(&Conn{Addr: "fresh"}, false) {
			t.Fatal("an inbound connection at capacity must be refused")
		}
		if len(n.conns) != cap {
			t.Fatalf("a refused connection must not be inserted: got %d", len(n.conns))
		}
	})

	// Separates the outbound term: identical to the case above except for the
	// direction. An inbound flood must not be able to stop this node dialling
	// out, so the capacity gate deliberately does not apply here.
	t.Run("at capacity, fresh address, outbound: admitted", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		fill(n, cap)
		if !n.register(&Conn{Addr: "fresh"}, true) {
			t.Fatal("an outbound dial must not be refused by the inbound capacity gate")
		}
	})

	// Separates the duplicate term: below capacity, where the capacity term
	// provably cannot be what refuses it.
	t.Run("under capacity, duplicate address: refused", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		fill(n, 1)
		if n.register(&Conn{Addr: "held-0"}, false) {
			t.Fatal("a second connection on a held address must be refused")
		}
		if len(n.conns) != 1 {
			t.Fatalf("expected the map unchanged, got %d entries", len(n.conns))
		}
		// And outbound does not buy a way past it either: the duplicate term
		// is unconditional, unlike the capacity term above.
		if n.register(&Conn{Addr: "held-0"}, true) {
			t.Fatal("an outbound duplicate must be refused too")
		}
	})
}

// TestConcurrentInboundAdmissionCannotOvershootCapacity pins the property the
// separate check-then-act could not hold: the connection set is a bound and
// not an average.
//
// acceptLoop spawns one serve goroutine per accepted connection with nothing
// between them, so the number of goroutines simultaneously deciding whether
// there is room is the arrival burst's width. When the comparison and the
// insert are in different critical sections every one of them reads the same
// under-capacity count and every one of them then inserts, and the resulting
// overshoot is durable: an admitted connection holds its entry until it
// disconnects. This matters beyond sockets because the connection set is the
// multiplier on the reassembly memory the byte budget does not count.
//
// **The loop is the whole test, and one round is not a weaker version of it —
// it is a different and much poorer assertion.** A split critical section
// leaves a window of a few instructions, so a single round of racers loses the
// race almost every time and passes against the exact shape this test exists
// to refuse. Reviewed and confirmed: with one round, a register that keeps its
// gate but splits the lock survives. What one round pins is that a comparison
// exists somewhere; what the loop pins is that the comparison and the insert
// are the same atomic step. Do not reduce the round count to make this faster.
//
// The assertion is on the invariant and not on a schedule, so no interleaving
// can make it fail against correct code — the loop raises the probability of
// catching a wrong one, it does not add flakiness to a right one.
func TestConcurrentInboundAdmissionCannotOvershootCapacity(t *testing.T) {
	const maxIn, maxOut = 3, 2
	const capacity = maxIn + maxOut
	const racers = 64
	// Sized from the measurement, not by feel: a split critical section
	// overshoots within the first handful of rounds, and this is three orders
	// of magnitude above that at well under a second.
	const rounds = 2000

	// Real parallelism is a precondition of this test, not a detail of the
	// machine it runs on. Measured: against a split critical section this
	// test kills 20/20 runs at GOMAXPROCS=4 and 0/20 at GOMAXPROCS=1 — with
	// one P the racers are interleaved rather than simultaneous, the window
	// between the two critical sections is a few instructions wide, and no
	// goroutine is ever inside it when another commits. Left to the ambient
	// value the test would silently assert nothing on a single-core runner
	// or under a constrained CI container, which is the failure mode where a
	// green tick is worse than no test. Restored so no later test inherits it.
	if prev := runtime.GOMAXPROCS(4); prev != 4 {
		defer runtime.GOMAXPROCS(prev)
	}

	worst, filled := 0, 0
	for r := 0; r < rounds; r++ {
		n := admissionNode(maxIn, maxOut)
		fill(n, capacity-1)

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				n.register(&Conn{Addr: "racer-" + strconv.Itoa(i)}, false)
			}(i)
		}
		close(start)
		wg.Wait()

		got := len(n.conns)
		if got > worst {
			worst = got
		}
		if got == capacity {
			filled++
		}
		if got > capacity {
			t.Fatalf("round %d of %d: the connection set overshot its cap: %d connections against a cap of %d",
				r, rounds, got, capacity)
		}
	}
	// Not vacuous, and pinned at the measured value rather than at the
	// weakest threshold that passes: every round must fill the last free
	// slot. `filled == 0` would also catch a register that refuses
	// unconditionally, but it would sit two thousand rounds below what this
	// actually does, and a guard parked at the loosest passing value is the
	// same shape as every other defect this unit found. If contention ever
	// makes a round finish with the slot unclaimed, that is a real change in
	// behaviour and this should fail and be read, not absorbed.
	if filled != rounds {
		t.Fatalf("%d of %d rounds left the last free slot unclaimed: the racers are not contending for it",
			rounds-filled, rounds)
	}
	t.Logf("worst observed %d against a cap of %d, %d/%d rounds filled the last slot (%d racers each)",
		worst, capacity, filled, rounds, racers)
}
