package p2p

import (
	"net"
	"testing"
	"time"
)

// TestALostRegisterRaceReleasesTheInboundSlot is the inbound slot leak's second
// half, and its own regression: a first version of this fix kept classOf keyed
// by address, so two connections charged for the same address still shared one
// map slot and the second Release still silently no-opped (round 2 review
// finding). This test now runs both connections in the collision down to
// completion — not just the loser — and pins that the group returns all the way
// to zero.
//
// Two connections that land on the same Conn.Addr race for register's map
// entry. The loser used to return before unregister's defer — the only thing
// that used to call Listener.Release — was ever installed, leaking the slot
// the loser had already been charged for at Accept. Separately, even once
// serve released on every exit, a shared address string as the release *key*
// meant the second of two same-address releases still found nothing to
// release, because the first one had already deleted the one record both were
// forced to share. Repeated, either bug permanently refuses the whole address
// group.
//
// This is an internal test because reproducing the exact real-world trigger
// (two inbound connections sharing an observed RemoteAddr — an attacker
// binding a specific local port, closing, and reconnecting from it before
// this node's Release for the first one runs) is a timing/OS-level trick
// rather than a property of this code. What is being tested is narrower and
// exactly what the fix guarantees: every connection's own, independent
// per-token release still finds its own record and runs correctly, even when
// two connections were charged for the identical address — so the charge and
// release are reproduced directly against the Listener's own bookkeeping,
// which this package can do and an external test cannot.
func TestALostRegisterRaceReleasesTheInboundSlot(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", 1) // perSource=1: any leak shows immediately
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	n := NewNode(id, &Engine{}, nil, 1)
	n.listener = ln

	const addr = "10.0.0.1:4000"
	const group = "10.0.0.0/16"

	// charge mints a fresh per-connection token and charges a slot exactly as
	// acceptRaw would for a connection from this address, without needing a
	// real socket collision to reproduce it. Two calls with the same addr
	// charge two independent records — the whole point being tested.
	charge := func() uint64 {
		ln.mu.Lock()
		ln.held[group]++
		ln.nextToken++
		token := ln.nextToken
		ln.classOf[token] = slotCharge{group: group}
		ln.mu.Unlock()
		return token
	}
	held := func() int {
		ln.mu.Lock()
		defer ln.mu.Unlock()
		return ln.held[group]
	}

	// The winner: registers first and stays registered, so the loser has a
	// real occupied map entry to collide with.
	wServer, wClient := net.Pipe()
	defer wClient.Close()
	winnerToken := charge()
	winner := &Conn{Conn: wServer, Addr: addr, slotToken: winnerToken}
	if !n.register(winner, false) {
		t.Fatal("setup: the winner could not register")
	}
	defer n.unregister(winner)

	if got := held(); got != 1 {
		t.Fatalf("setup: expected 1 held slot after charging the winner, got %d", got)
	}

	// The loser: same Addr, charged its own slot at Accept exactly as the
	// winner was, and about to lose the register race.
	lServer, lClient := net.Pipe()
	defer lClient.Close()
	loserToken := charge()
	loser := &Conn{Conn: lServer, Addr: addr, slotToken: loserToken}
	if got := held(); got != 2 {
		t.Fatalf("setup: expected 2 held slots after charging the loser, got %d", got)
	}

	n.wg.Add(1)
	done := make(chan struct{})
	go func() {
		n.serve(loser, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("setup: the loser's serve did not return")
	}

	if got := held(); got != 1 {
		t.Fatalf("the loser's Listener slot was not released after it lost the "+
			"register race: held = %d, want 1 (only the winner's)", got)
	}

	// The extended check (round 2 review finding): running the winner down
	// too must bring the group all the way back to zero. Before this token
	// fix, classOf was keyed by the shared address string, so the loser's
	// release above had already deleted the one record both connections were
	// forced to share — the winner's own release then found nothing left,
	// and held got stuck at 1 forever even though both connections are gone.
	ln.Release(winnerToken)
	if got := held(); got != 0 {
		t.Fatalf("the winner's Listener slot was not released after both "+
			"connections that shared an address disconnected: held = %d, want 0. "+
			"A shared address string as the release key means the second "+
			"connection's release silently no-ops, leaking the slot forever, "+
			"even though serve calls Release on every exit", got)
	}
}
