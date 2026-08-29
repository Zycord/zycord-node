package p2p

import (
	"crypto/ed25519"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

// identityKeyN returns a distinct, stable Ed25519-shaped public key per index.
// The bytes never leave register's bytes.Equal comparison, so they need to be
// distinct and the right length rather than a real key: generating 64 real
// keypairs would make this test slower for nothing the property reads.
func identityKeyN(i int) ed25519.PublicKey {
	k := make(ed25519.PublicKey, ed25519.PublicKeySize)
	k[0] = byte(i)
	k[1] = byte(i >> 8)
	return k
}

// hold inserts k connections for one identity directly, bypassing register, so
// the arrangement of a case is never the thing under test.
func holdForIdentity(n *Node, key ed25519.PublicKey, prefix string, k int) {
	for i := 0; i < k; i++ {
		addr := prefix + "-" + strconv.Itoa(i)
		n.conns[addr] = &Conn{Addr: addr, PeerKey: key}
	}
}

// TestRegisterCapsConnectionsPerIdentity separates every term of the
// per-identity gate. The guard is a conjunction like the capacity one
// beside it, so a single passing case cannot say which term carried it.
//
// Terms: the newcomer's PeerKey is non-empty, and the identity already holds
// MaxConnsPerIdentity live entries. Direction is deliberately *not* a term —
// unlike the capacity gate, this one applies to both legs — so it is asserted
// as its own case rather than assumed.
func TestRegisterCapsConnectionsPerIdentity(t *testing.T) {
	// Capacity far above anything these cases insert: the property under test
	// is the per-identity bound, and a refusal that the table-capacity gate
	// could also explain would prove nothing.
	const maxIn, maxOut = 64, 64

	key := identityKeyN(1)
	other := identityKeyN(2)

	t.Run("first connection for an identity: admitted", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		if !n.register(&Conn{Addr: "a", PeerKey: key}, false) {
			t.Fatal("the first connection from an identity must be admitted")
		}
	})

	// The honest crossing dial: this node's outbound leg meeting the same
	// peer's inbound leg. The cap starts above this pair precisely so it
	// survives without a simultaneous-open tie-break; the dedicated sync leg
	// that makes the honest set larger still is pinned over a real socket, in
	// TestSyncSurvivesAPeerThatAlreadyHoldsACrossingPair.
	t.Run("second connection for an identity: admitted", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		holdForIdentity(n, key, "held", 1)
		if !n.register(&Conn{Addr: "b", PeerKey: key}, true) {
			t.Fatal("the honest crossing dial (second leg) must be admitted")
		}
		if len(n.conns) != 2 {
			t.Fatalf("expected 2 connections, got %d", len(n.conns))
		}
	})

	// The property. Identical to the case above except that the identity
	// already holds MaxConnsPerIdentity, so the cap is the only term that
	// changed.
	t.Run("one connection past the cap, inbound: refused", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		holdForIdentity(n, key, "held", MaxConnsPerIdentity)
		if n.register(&Conn{Addr: "c", PeerKey: key}, false) {
			t.Fatalf("connection number %d from one identity must be refused: "+
				"the cap is %d", MaxConnsPerIdentity+1, MaxConnsPerIdentity)
		}
		if len(n.conns) != MaxConnsPerIdentity {
			t.Fatalf("a refused connection must not be inserted: got %d entries",
				len(n.conns))
		}
	})

	// Separates the direction term: outbound buys no way past the cap, unlike
	// the inbound-only table-capacity gate.
	t.Run("one connection past the cap, outbound: refused", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		holdForIdentity(n, key, "held", MaxConnsPerIdentity)
		if n.register(&Conn{Addr: "c", PeerKey: key}, true) {
			t.Fatal("the per-identity cap applies to outbound legs too")
		}
	})

	// Separates the identity term: a different key at the same table depth is
	// admitted, so what refused the case above was the identity match and not
	// the number of held connections.
	t.Run("one past another identity's cap, different identity: admitted", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		holdForIdentity(n, key, "held", MaxConnsPerIdentity)
		if !n.register(&Conn{Addr: "c", PeerKey: other}, false) {
			t.Fatal("a different identity must not be refused by another's cap")
		}
	})

	// Separates the non-empty-key term. An unkeyed Conn is a test fixture or a
	// future non-TLS leg; if the guard treated an absent key as an identity,
	// every such connection would collapse into one and the whole table would
	// cap at MaxConnsPerIdentity.
	t.Run("connections with no PeerKey: never refused by this guard", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  ed25519.PublicKey
		}{{"nil", nil}, {"empty", ed25519.PublicKey{}}} {
			t.Run(tc.name, func(t *testing.T) {
				n := admissionNode(maxIn, maxOut)
				for i := 0; i < MaxConnsPerIdentity+3; i++ {
					addr := "unkeyed-" + strconv.Itoa(i)
					if !n.register(&Conn{Addr: addr, PeerKey: tc.key}, false) {
						t.Fatalf("connection %d with a %s PeerKey was refused: "+
							"the per-identity guard must not key on an absent identity", i, tc.name)
					}
				}
			})
		}
	})

	// The cap is on *live* entries, not on connections ever seen: an identity
	// that disconnects gets its slot back. Without this, the cap would be a
	// lifetime quota and a long-running honest peer would eventually be locked
	// out of a node it had merely reconnected to often enough.
	t.Run("a departed connection frees the slot", func(t *testing.T) {
		n := admissionNode(maxIn, maxOut)
		holdForIdentity(n, key, "held", MaxConnsPerIdentity)
		if n.register(&Conn{Addr: "c", PeerKey: key}, false) {
			t.Fatal("precondition: the identity must be at its cap")
		}
		delete(n.conns, "held-0")
		if !n.register(&Conn{Addr: "c", PeerKey: key}, false) {
			t.Fatal("a slot freed by a disconnect must be re-admittable")
		}
	})
}

// TestConcurrentAdmissionCannotOvershootPerIdentityCap pins that the count and
// the insert are one atomic step, which is the same property
// TestConcurrentInboundAdmissionCannotOvershootCapacity pins for the table
// bound and for the same reason: acceptLoop spawns one serve goroutine per
// accepted connection with nothing between them, so the number of goroutines
// simultaneously counting an identity's live entries is the arrival burst's
// width. A count taken outside the lock that guards the insert bounds nothing
// — every racer reads the same under-cap number and every one of them then
// inserts — and the overshoot is durable, because an admitted connection keeps
// its entry until it disconnects. That is exactly the multiplier this cap
// exists to remove.
//
// The loop is the test. A split critical section leaves a window a few
// instructions wide, so one round of racers loses the race almost every time
// and would pass against the shape this refuses. The assertion is on the
// invariant rather than on a schedule, so no interleaving can make it fail
// against correct code.
func TestConcurrentAdmissionCannotOvershootPerIdentityCap(t *testing.T) {
	const maxIn, maxOut = 256, 256
	const racers = 64
	const rounds = 2000

	// Real parallelism is a precondition, not a property of the machine: with
	// one P the racers interleave rather than run simultaneously and no
	// goroutine is ever inside the window when another commits, so the test
	// would silently assert nothing. Restored so no later test inherits it.
	if prev := runtime.GOMAXPROCS(4); prev != 4 {
		defer runtime.GOMAXPROCS(prev)
	}

	key := identityKeyN(7)
	worst, filled := 0, 0
	for r := 0; r < rounds; r++ {
		n := admissionNode(maxIn, maxOut)
		holdForIdentity(n, key, "held", MaxConnsPerIdentity-1)

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				n.register(&Conn{Addr: "racer-" + strconv.Itoa(i), PeerKey: key}, false)
			}(i)
		}
		close(start)
		wg.Wait()

		got := len(n.conns)
		if got > worst {
			worst = got
		}
		if got == MaxConnsPerIdentity {
			filled++
		}
		if got > MaxConnsPerIdentity {
			t.Fatalf("round %d of %d: one identity holds %d connections against a cap of %d",
				r, rounds, got, MaxConnsPerIdentity)
		}
	}
	// Not vacuous: every round must claim the identity's last free slot. A
	// register that refused unconditionally would satisfy the bound above and
	// fail here.
	if filled != rounds {
		t.Fatalf("%d of %d rounds left the identity's last slot unclaimed: the racers are not contending for it",
			rounds-filled, rounds)
	}
	t.Logf("worst observed %d against a per-identity cap of %d, %d/%d rounds filled the last slot (%d racers each)",
		worst, MaxConnsPerIdentity, filled, rounds, racers)
}
