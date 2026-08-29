package p2p

import (
	"net"
	"testing"
	"time"
)

// The property: this node asks for addresses, and asks exactly one peer it
// chose to dial, at most once per GetPeersInterval.
//
// Every revision before discovery existed sent no KindGetPeers at all, so the
// whole file fails without the fix —
// TestDiscoveryAsksAnOutboundPeerForAddresses times out waiting for a frame
// that is never framed. The other three exist because "it sends something" is
// the easy half: each pins one of the narrowings in askForPeers, and each was
// checked against the mutant that removes it.

// framedPeer is one end of an in-memory connection, with a reader draining it
// into a channel. net.Pipe is unbuffered, so a Send blocks until something
// reads; without the drain the assertions below would deadlock rather than
// fail, which is a worse failure to read.
type framedPeer struct {
	conn  *Conn
	kinds chan MessageKind
}

func newFramedPeer(t *testing.T, addr string) *framedPeer {
	t.Helper()
	ours, theirs := net.Pipe()
	t.Cleanup(func() { ours.Close(); theirs.Close() })
	p := &framedPeer{
		conn:  &Conn{Conn: ours, Addr: addr},
		kinds: make(chan MessageKind, 8),
	}
	go func() {
		for {
			kind, _, err := ReadFrame(theirs)
			if err != nil {
				return
			}
			p.kinds <- kind
		}
	}()
	return p
}

// received reports the next frame kind, or false if none arrives in time.
//
// The negative assertions below use this too, which is why the wait is a
// real duration rather than a non-blocking poll: a "nothing was sent" claim
// checked with a zero-length wait passes against a send that is merely
// scheduled, and would be vacuous.
func (p *framedPeer) received(d time.Duration) (MessageKind, bool) {
	select {
	case k := <-p.kinds:
		return k, true
	case <-time.After(d):
		return 0, false
	}
}

// newDiscoveryNode returns a node with no chain, no listener and no sockets:
// askForPeers reaches none of them, and a test that had to stand one up would
// be testing the harness.
func newDiscoveryNode(t *testing.T) *Node {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return NewNode(id, &Engine{}, nil, 1)
}

// register wires a connection in as outbound (this node dialled it) or
// inbound (the peer dialled this node). The difference is exactly
// outboundTargets, which is what askForPeers is required to read.
func register(n *Node, p *framedPeer, outbound bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.conns[p.conn.Addr] = p.conn
	if outbound {
		n.outboundTargets[p.conn.Addr] = true
	}
}

func TestDiscoveryAsksAnOutboundPeerForAddresses(t *testing.T) {
	n := newDiscoveryNode(t)
	p := newFramedPeer(t, "203.0.113.7:9999")
	register(n, p, true)

	n.askForPeers()

	kind, ok := p.received(2 * time.Second)
	if !ok {
		t.Fatal("no frame was sent to the one outbound peer: discovery is inert, which is the state under test")
	}
	if kind != KindGetPeers {
		t.Fatalf("sent kind %d, want KindGetPeers (%d)", kind, KindGetPeers)
	}
}

func TestDiscoveryNeverAsksAnInboundPeer(t *testing.T) {
	n := newDiscoveryNode(t)
	// Inbound only. An inbound connection is chosen by the peer, so asking it
	// lets an attacker that merely connects here nominate itself as this
	// node's address source.
	in := newFramedPeer(t, "198.51.100.4:41231")
	register(n, in, false)

	n.askForPeers()

	if kind, ok := in.received(300 * time.Millisecond); ok {
		t.Fatalf("asked an inbound peer for addresses (kind %d)", kind)
	}
	// The silence must be *because there was nobody to ask*, and not because
	// the interval was spent on an empty set: a node whose first connection is
	// inbound would otherwise fall silent for a full GetPeersInterval after it
	// finally dials someone. This is the half that fails if askForPeers arms
	// the timer before it has a target.
	n.mu.Lock()
	armed := !n.nextGetPeers.IsZero()
	n.mu.Unlock()
	if armed {
		t.Fatal("the interval was armed with no peer to ask, so the first real ask is delayed by a full interval")
	}
	// And the node is not permanently mute: give it an outbound peer and the
	// very next call asks. Without this the assertion above would also pass
	// against an askForPeers that never sends anything at all.
	out := newFramedPeer(t, "203.0.113.7:9999")
	register(n, out, true)
	n.askForPeers()
	if _, ok := out.received(2 * time.Second); !ok {
		t.Fatal("no frame after an outbound peer appeared, so the inbound assertion above proves nothing")
	}
	if kind, ok := in.received(300 * time.Millisecond); ok {
		t.Fatalf("the inbound peer was asked once an outbound one existed (kind %d)", kind)
	}
}

func TestDiscoveryAsksOnePeerPerInterval(t *testing.T) {
	n := newDiscoveryNode(t)
	// Two outbound peers, so "one ask" is a claim about the ask and not about
	// the peer count. Both are drained, so a second frame to *either* is seen.
	a := newFramedPeer(t, "203.0.113.7:9999")
	b := newFramedPeer(t, "192.0.2.9:9999")
	register(n, a, true)
	register(n, b, true)

	n.askForPeers()
	first := 0
	for _, p := range []*framedPeer{a, b} {
		if _, ok := p.received(2 * time.Second); ok {
			first++
		}
	}
	if first != 1 {
		t.Fatalf("first round sent %d frames across 2 outbound peers, want exactly 1", first)
	}

	// The dial loop calls this every DialInterval — seconds — while
	// GetPeersInterval is minutes, so this is the ordinary case and not an
	// edge one.
	n.askForPeers()
	n.askForPeers()
	for _, p := range []*framedPeer{a, b} {
		if kind, ok := p.received(300 * time.Millisecond); ok {
			t.Fatalf("a further ask (kind %d) went out inside one GetPeersInterval", kind)
		}
	}

	// Not merely off: due again once the interval has passed. Without this the
	// assertion above passes against an askForPeers that asks once per process.
	n.mu.Lock()
	n.nextGetPeers = time.Now().Add(-time.Nanosecond)
	n.mu.Unlock()
	n.askForPeers()
	second := 0
	for _, p := range []*framedPeer{a, b} {
		if _, ok := p.received(2 * time.Second); ok {
			second++
		}
	}
	if second != 1 {
		t.Fatalf("after the interval elapsed, %d frames went out, want exactly 1", second)
	}
}

func TestDiscoveryIsOffWhenTheIntervalIsNotSet(t *testing.T) {
	// A Node built by something other than NewNode — the zero value — must
	// not start asking merely by being constructed. This is the escape hatch
	// an operator or a test uses to get the inert behaviour back.
	n := newDiscoveryNode(t)
	n.GetPeersInterval = 0
	p := newFramedPeer(t, "203.0.113.7:9999")
	register(n, p, true)

	n.askForPeers()

	if kind, ok := p.received(300 * time.Millisecond); ok {
		t.Fatalf("asked for peers with GetPeersInterval unset (kind %d)", kind)
	}
	// Same guard as above: prove the silence is the interval and not the
	// harness.
	n.GetPeersInterval = DefaultGetPeersInterval
	n.askForPeers()
	if _, ok := p.received(2 * time.Second); !ok {
		t.Fatal("no frame with the interval set, so the assertion above proves nothing")
	}
}

// The property: the dial loop is what drives discovery, so the send side is
// reachable in a running node and not only from a test that calls it.
//
// askForPeers is unexported and every assertion above calls it directly, so
// deleting the one call site in dialLoop leaves all of them green while the
// node never asks anybody for an address again — the exact inert state. This
// test is the only thing standing between that mutant and a silent regression.
func TestDiscoveryIsDrivenByTheDialLoop(t *testing.T) {
	n := newDiscoveryNode(t)
	p := newFramedPeer(t, "203.0.113.7:9999")
	register(n, p, true)
	// One outbound slot, already filled by p, so topUp finds need <= 0 and
	// returns before it reaches the (nil) peer store. The loop under test is
	// the loop, not the dialling.
	n.MaxOutbound = 1
	n.DialInterval = 10 * time.Millisecond

	n.wg.Add(1)
	go n.dialLoop()
	t.Cleanup(func() { close(n.quit); n.wg.Wait() })

	kind, ok := p.received(2 * time.Second)
	if !ok {
		t.Fatal("the dial loop ran and no get-peers went out: askForPeers is not wired to anything a running node executes")
	}
	if kind != KindGetPeers {
		t.Fatalf("dial loop sent kind %d, want KindGetPeers (%d)", kind, KindGetPeers)
	}
}

// The property: a dialled address is only an ask target once its connection
// has been registered, because outboundTargets is written before the
// connection is.
//
// topUp records outboundTargets[addr] under n.mu and only then starts the
// serve goroutine that puts the connection into n.conns, and dialLoop calls
// askForPeers immediately after topUp returns. So the state this test builds
// — an outbound target with no connection — is the ordinary state right after
// every successful dial, not a contrived one, and it is at its most likely on
// a node's first dial, when nextGetPeers is still the zero value and the ask
// is already due. Without the liveness filter in askForPeers the candidate
// list contains that address, c is nil, and the send panics the dial loop out
// of the process.
func TestDiscoverySkipsADialledPeerThatHasNoConnectionYet(t *testing.T) {
	n := newDiscoveryNode(t)
	// The window: dialled and recorded, serve has not registered it.
	n.mu.Lock()
	n.outboundTargets["203.0.113.7:9999"] = true
	n.mu.Unlock()

	n.askForPeers() // must not panic

	// And it must not have spent the interval either: the node has nobody it
	// can ask yet, so the first real ask must still be due immediately.
	n.mu.Lock()
	armed := !n.nextGetPeers.IsZero()
	n.mu.Unlock()
	if armed {
		t.Fatal("the interval was armed against a dialled peer with no connection, delaying the first real ask by a full interval")
	}

	// Positive control: once a connection exists for a recorded target, the
	// very next call asks it. Without this the assertions above would also
	// pass against an askForPeers that never sends.
	p := newFramedPeer(t, "203.0.113.7:9999")
	register(n, p, true)
	n.askForPeers()
	if _, ok := p.received(2 * time.Second); !ok {
		t.Fatal("no frame once the connection was registered, so the assertions above prove nothing")
	}
}

// nextAsked reports which of the two peers received a frame, or "" if neither
// did. Both channels are watched in one select so a round costs the wait only
// when nothing was sent at all — a per-peer poll would pay the timeout on the
// peer that was not chosen, every round.
func nextAsked(a, b *framedPeer, d time.Duration) string {
	select {
	case <-a.kinds:
		return a.conn.Addr
	case <-b.kinds:
		return b.conn.Addr
	case <-time.After(d):
		return ""
	}
}

// The property: consecutive asks are spread across the outbound set by a
// uniform draw, so no single peer is this node's standing address source.
//
// The sorted candidate list exists for reproducibility, and stating only that
// leaves the draw itself looking like an implementation detail. It is not:
// replace n.rng.Intn(len(candidates)) with candidates[0] and every other test
// in this file still passes, while the peer whose address happens to sort
// first becomes the *only* peer this node ever asks, permanently and across
// restarts. That collapses the bound in networking.md §12.4 — an attacker
// holding one of MaxOutbound slots draws about 1/MaxOutbound of the asks —
// to 1/1, for the price of choosing an address that sorts low. It also makes
// the ask target survive an attacker's own reconnections, which is the shape
// an eclipse wants.
//
// Node.rng is seeded, so this is deterministic rather than flaky: the run
// below either spreads or it does not.
func TestDiscoveryRotatesAcrossOutboundPeers(t *testing.T) {
	n := newDiscoveryNode(t)
	// b's address sorts before a's, so a fixed candidates[0] pick lands on b
	// and never on a. The assertion is on both, so either fixed choice fails.
	a := newFramedPeer(t, "203.0.113.7:9999")
	b := newFramedPeer(t, "192.0.2.9:9999")
	register(n, a, true)
	register(n, b, true)

	const rounds = 16
	seen := map[string]int{}
	for i := 0; i < rounds; i++ {
		// Each round is a fresh interval, which is what the dial loop
		// produces over time; the interval itself is pinned elsewhere.
		n.mu.Lock()
		n.nextGetPeers = time.Time{}
		n.mu.Unlock()
		n.askForPeers()
		who := nextAsked(a, b, 2*time.Second)
		if who == "" {
			t.Fatalf("round %d sent nothing", i)
		}
		seen[who]++
	}
	if len(seen) < 2 {
		t.Fatalf("all %d asks went to one peer (%v): the target is fixed, so whichever peer wins it is this node's sole address source", rounds, seen)
	}
}

// The property: the interval between asks is re-drawn per ask, so a node's
// asks do not present one recognisable period.
//
// Deleting the jitter term leaves every other test in this file green — they
// all assert that an ask is or is not due, never how far away the next one
// is. What a fixed period costs is stated in networking.md §12.3: the send
// times across every connection this node holds become one phase, which is a
// correlator across connections.
func TestDiscoveryIntervalIsJittered(t *testing.T) {
	n := newDiscoveryNode(t)
	p := newFramedPeer(t, "203.0.113.7:9999")
	register(n, p, true)

	gaps := map[time.Duration]bool{}
	for i := 0; i < 8; i++ {
		before := time.Now()
		n.mu.Lock()
		n.nextGetPeers = time.Time{}
		n.mu.Unlock()
		n.askForPeers()
		if _, ok := p.received(2 * time.Second); !ok {
			t.Fatalf("round %d sent nothing", i)
		}
		n.mu.Lock()
		due := n.nextGetPeers
		n.mu.Unlock()
		// Rounded to the second: the wall-clock instant this ask happened is
		// not reproducible, but the drawn offset is, and a second is far
		// coarser than the scheduling noise and far finer than the 150s
		// jitter range.
		gaps[due.Sub(before).Round(time.Second)] = true
	}
	if len(gaps) < 2 {
		t.Fatalf("every ask armed the same interval (%v): the period is fixed, so this node's asks are one phase across every connection it holds", gaps)
	}
	// The jitter must be an addition to the interval and not a replacement
	// for it: a draw that could come out short would let the rate rise above
	// the one the cost in §12.3 was computed against.
	for g := range gaps {
		if g < n.GetPeersInterval || g > n.GetPeersInterval+n.GetPeersInterval/2 {
			t.Fatalf("armed interval %v outside [%v, %v]", g, n.GetPeersInterval, n.GetPeersInterval+n.GetPeersInterval/2)
		}
	}
}
