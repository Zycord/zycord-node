package p2p

import (
	"net"
	"testing"
	"time"
)

// TestHandshakeCapBoundsInFlightHandshakes pins the half of the global cap
// that preemption must not cost: the ceiling itself.
//
// Preempting the oldest handshake instead of refusing the newcomer is what
// keeps a silent flood from locking honest peers out (see
// TestSilentConnectionsCannotStarveAnHonestPeer), but it would be worthless
// if it also let the map grow — the cap exists to bound goroutines and file
// descriptors, and an attacker with enough address diversity is exactly who
// tests it. Internal, because len(pending) is the quantity under test and the
// listener deliberately exposes no accessor for it.
func TestHandshakeCapBoundsInFlightHandshakes(t *testing.T) {
	server, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// perSource far above the cap: every dial comes from 127.0.0.1, so the
	// per-group budget must not be what bounds anything here.
	ln, err := server.Listen("127.0.0.1:0", 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const cap = 8
	ln.SetMaxHandshakes(cap)

	const attempts = 200
	for i := 0; i < attempts; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("silent connection %d: %v", i, err)
		}
		defer c.Close()
		// Sample the live count as the flood arrives, not only at the end: a
		// cap that overshoots during a burst and settles afterwards is still
		// a cap that does not bind.
		ln.pendingMu.Lock()
		got := len(ln.pending)
		ln.pendingMu.Unlock()
		if got > cap {
			t.Fatalf("%d handshakes in flight after %d silent connections, cap is %d",
				got, i+1, cap)
		}
	}

	time.Sleep(200 * time.Millisecond)
	ln.pendingMu.Lock()
	got := len(ln.pending)
	ln.pendingMu.Unlock()
	if got > cap {
		t.Fatalf("%d handshakes in flight after %d silent connections settled, cap is %d",
			got, attempts, cap)
	}
	if ln.Preempted() == 0 {
		t.Fatalf("%d silent connections against a cap of %d preempted nothing: the cap was "+
			"never reached and this test proved nothing", attempts, cap)
	}
}

// TestAnAuthenticatedPeerIsNeverPreempted pins why pending is emptied the
// moment a handshake completes rather than when its goroutine returns.
//
// A connection that has finished its TLS handshake is waiting to be handed to
// Accept, not handshaking. Leaving it in the map would count it against the
// budget that bounds *unproven* connections and — worse — make it eligible to
// be preempted, so a peer that had already proved its identity could be cut
// down by an attacker's unauthenticated flood arriving behind it.
func TestAnAuthenticatedPeerIsNeverPreempted(t *testing.T) {
	server, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := server.Listen("127.0.0.1:0", 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.SetMaxHandshakes(2)

	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Deliberately do not call Accept: the authenticated connection is now
	// parked waiting to be delivered. It must not be occupying the handshake
	// budget while it waits.
	time.Sleep(200 * time.Millisecond)
	ln.pendingMu.Lock()
	got := len(ln.pending)
	ln.pendingMu.Unlock()
	if got != 0 {
		t.Fatalf("%d entries still counted as handshakes in flight while the only connection "+
			"is an authenticated peer waiting for Accept", got)
	}

	// It must still be delivered, unharmed, after a flood that would have
	// preempted it had it still been in the map.
	for i := 0; i < 10; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("silent connection %d: %v", i, err)
		}
		defer c.Close()
	}
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("the authenticated peer was never delivered: %v", err)
	}
	if accepted.Addr != conn.LocalAddr().String() {
		t.Fatalf("Accept delivered %s, want the authenticated peer at %s",
			accepted.Addr, conn.LocalAddr())
	}
}

// TestVictimIsTakenFromTheHeaviestGroup pins how the preemption victim is
// chosen, which is the difference between a cap that protects honest peers
// and one that hunts them.
//
// Oldest-first alone says "evict the slowest", and the slowest handshake in
// the map is a distant honest peer on a long round trip — never the attacker,
// who controls its own connection lifetime and can always arrive later. Group
// share is the signal that does not invert: perSource+reserve bounds one
// group to five handshakes in flight, so filling the cap takes breadth, and
// the honest peer arrives as the only connection from its own group.
//
// This has to be a unit test on victimLocked rather than a socket test: every
// loopback address lives in one /16, so a test that actually dials cannot
// present two address groups at all.
func TestVictimIsTakenFromTheHeaviestGroup(t *testing.T) {
	l := &Listener{pending: map[net.Conn]pendingHandshake{}}

	conn := func() net.Conn { c, _ := net.Pipe(); return c }
	// The honest peer: alone in its group, and the oldest thing in the map by
	// a wide margin — exactly the shape oldest-first gives away first.
	honest := conn()
	l.pending[honest] = pendingHandshake{token: 1, group: "198.51"}
	// An attacker across two groups, every connection newer than the honest
	// peer's, one group heavier than the other.
	attacker := map[net.Conn]pendingHandshake{}
	for i, p := range []pendingHandshake{
		{token: 10, group: "203.0"},
		{token: 11, group: "203.0"},
		{token: 12, group: "203.0"},
		{token: 13, group: "192.0"},
		{token: 14, group: "192.0"},
	} {
		c := conn()
		l.pending[c] = p
		attacker[c] = p
		_ = i
	}

	victim := l.victimLocked()
	if victim == honest {
		t.Fatal("the honest peer, alone in its address group, was chosen as the preemption " +
			"victim over an attacker holding five handshakes across two groups: victim " +
			"selection is still oldest-first, which is the rule that picks the slowest " +
			"peer rather than the greediest one")
	}
	got, ok := attacker[victim]
	if !ok {
		t.Fatal("victimLocked returned a connection that is not in the pending map")
	}
	if got.group != "203.0" {
		t.Fatalf("victim came from group %q holding 2 handshakes, want the heaviest group "+
			"%q holding 3", got.group, "203.0")
	}
	if got.token != 10 {
		t.Fatalf("victim inside the heaviest group has token %d, want %d — the oldest of "+
			"that group", got.token, 10)
	}
}

// TestSetMaxHandshakesCannotDisableTheCap guards a cap that silently means its
// own opposite. Zero cannot mean "accept nothing": there is no handshake to
// preempt when the map is empty, so an unclamped zero would admit everything
// and turn the bound off in the one direction a caller passing zero cannot
// have intended.
func TestSetMaxHandshakesCannotDisableTheCap(t *testing.T) {
	server, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := server.Listen("127.0.0.1:0", 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.SetMaxHandshakes(0)

	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("silent connection %d: %v", i, err)
		}
		defer c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	ln.pendingMu.Lock()
	got := len(ln.pending)
	ln.pendingMu.Unlock()
	if got > 1 {
		t.Fatalf("%d handshakes in flight after SetMaxHandshakes(0): a zero cap disabled the "+
			"bound instead of clamping to the smallest one that can hold", got)
	}
}
