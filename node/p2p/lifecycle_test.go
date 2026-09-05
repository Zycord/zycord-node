package p2p_test

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"zycord/node/p2p"
)

// Regression tests for the accept-path and connection-lifecycle defects: the
// inline handshake that stalled all inbound accepts, the leaked inbound slot,
// the ban shed by reconnecting on a fresh port, and the unbounded write.
// transport_test.go and inbound_test.go cover the Listener in isolation; these
// drive a real Node end to end, because the defects are about what Node.serve
// and Node.Stop do with a connection once the Listener has handed it over.

// TestStopReturnsPromptlyDespiteAWedgedHandshake is the accept stall's second
// half: a silent connection must not be able to block a clean shutdown, because
// a clean shutdown is what stands between an operator's Ctrl-C and the one call
// to PeerStore.Save (cmd/zycordd's shutdown deferral runs Stop, then Save).
//
// Before the fix, acceptLoop performed the TLS handshake inline with no
// deadline, so a connection that completed the TCP handshake and sent
// nothing wedged the goroutine holding acceptLoop's own wg entry — and
// closing the listener does not interrupt a handshake already in progress on
// an already-accepted socket. Stop's wg.Wait would never return.
func TestStopReturnsPromptlyDespiteAWedgedHandshake(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	if err := victim.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}

	// A silent connection: completes the TCP handshake and then sends
	// nothing, ever. It is deliberately never closed by this test — the
	// property under test is that Stop does not need it to be.
	silent, err := net.Dial("tcp", victim.node.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })

	// Give the accept side a moment to actually pick the connection up and
	// start its handshake, so Stop races a real in-flight handshake rather
	// than a socket still sitting in the kernel's backlog.
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		victim.node.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Node.Stop did not return while a silent connection's TLS handshake " +
			"was in flight: a wedged accept blocks a clean shutdown, and therefore " +
			"blocks whatever an operator relies on running after Stop returns — the " +
			"peer store's only Save call, in cmd/zycordd")
	}
}

// TestOverCapacityRejectionReleasesTheInboundSlot is the slot leak's first
// half. Zeroing MaxInbound/MaxOutbound makes every accepted connection take the
// over-capacity rejection path in serve, isolating exactly that leak without
// needing to fill the budget with long-lived connections first.
func TestOverCapacityRejectionReleasesTheInboundSlot(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.node.MaxInbound = 0
	victim.node.MaxOutbound = 0
	if err := victim.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(victim.node.Stop)

	dialer, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// More attempts than perSource(3) + DefaultInboundReserve(2): if the slot
	// the over-capacity path charges is never released, the Listener itself
	// starts refusing this source well before this loop ends, and dialling
	// fails outright rather than merely being rejected after connecting.
	for i := 0; i < 10; i++ {
		c, err := dialer.Dial(victim.node.ListenAddr(), 2*time.Second)
		if err != nil {
			t.Fatalf("connection %d was refused by the listener itself: the inbound "+
				"slot the over-capacity path in serve charges was never released, so "+
				"this source group ran out after nothing but over-capacity "+
				"rejections: %v", i, err)
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}

	if refused := victim.node.InboundRefused(); refused != 0 {
		t.Fatalf("the listener recorded %d refusals from a single source after only "+
			"over-capacity rejections at the node level: the slot was charged but "+
			"never released", refused)
	}
}

// TestBannedIdentitySurvivesAReconnectOnANewPort: a peer banned on one
// connection must not be able to shed that ban by reconnecting on a fresh
// ephemeral source port, which costs it nothing but one more TLS handshake.
func TestBannedIdentitySurvivesAReconnectOnANewPort(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	if err := victim.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(victim.node.Stop)

	// Anti-vacuity control: an identity that never misbehaves must still be
	// served normally, or a failure below could just as well mean every
	// connection is refused for an unrelated reason.
	honest, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := honest.Dial(victim.node.ListenAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	hc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if kind, _, err := hc.Receive(); err != nil || kind != p2p.KindHello {
		t.Fatalf("setup: an honest, never-misbehaving identity was refused: "+
			"kind=%v err=%v", kind, err)
	}
	hc.Close()

	attacker, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// First connection: flood past ScoreBanThreshold (-100) with invalid
	// certificates (ScoreInvalidMessage, -20 each) so the identity — not just
	// this connection's address — is banned.
	first, err := attacker.Dial(victim.node.ListenAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Drain the victim's own hello first: it arrives regardless of anything
	// the client goes on to send, and reading it back must not be mistaken
	// for "the connection is still being served".
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if kind, _, err := first.Receive(); err != nil || kind != p2p.KindHello {
		t.Fatalf("setup: did not receive the victim's hello: kind=%v err=%v", kind, err)
	}
	// The handshake first, because Handle refuses every other kind until it has
	// happened — and a protocol violation is a *drop*, not a ban: it costs
	// ScoreProtocolViolation (-50) and closes the connection on the first frame,
	// so an unhandshaked flood never reaches ScoreBanThreshold on one connection
	// and this test would arm nothing. Identifying itself is also what a real
	// attacker does here: the ban it is buying its way to is the point.
	first.Send(p2p.KindHello, victim.engine.Hello().MarshalHello())
	for i := 0; i < 6; i++ {
		first.Send(p2p.KindCertificate, []byte{byte(i), 9, 9, 9})
	}
	// A disconnect must show up as the connection actually closing (io.EOF or
	// similar), well inside a short deadline — not as a plain read timeout,
	// which would just as well mean the victim is still serving it and
	// nothing more happened to arrive.
	first.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, _, err := first.Receive(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("setup: flooding invalid certificates did not disconnect the first "+
			"connection within 1s (err=%v), so the identity was never banned and this "+
			"test arms nothing", err)
	}
	first.Close()

	// Reconnect with the same identity — same keypair, same TLS certificate —
	// on a brand new socket, which the OS gives a brand new ephemeral source
	// port. Conn.Addr on the server side is therefore a different string than
	// the first connection's, and the address-keyed ban (Banned(addr)) has
	// nothing to say about it.
	second, err := attacker.Dial(victim.node.ListenAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	kind, _, err := second.Receive()
	if err == nil {
		t.Fatalf("a banned identity reconnected on a new source port and was served "+
			"as if nothing had happened (received %v): the address-keyed ban forgot "+
			"everything the moment the ephemeral port changed, and nothing else "+
			"remembered", kind)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("setup: the reconnect neither received a hello nor was refused " +
			"within 2s; inconclusive")
	}
}

// TestSyncFromRefusesABannedIdentity extends identity-keyed banning to the
// dedicated sync connection: SyncCandidates' ban filter is necessarily
// address-only (it operates on peers this node has not yet connected to), so
// the connection SyncFrom itself opens is the only place left to catch a peer
// banned on its gossip connection but never scored on its dialable address.
func TestSyncFromRefusesABannedIdentity(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	peer := newNode(t, "peer", p, key(t, 2).Persistent())
	if err := peer.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.node.Stop)

	// As if this identity had already been scored out on a gossip
	// connection — a case SyncCandidates' address-only filter cannot see,
	// since candidacy is keyed by the peer's *dialable* address and scoring
	// by the inbound connection's ephemeral one.
	victim.peers.AdjustKey(peer.node.Identity.PublicKey(), p2p.ScoreBanThreshold)

	err := victim.node.SyncFrom(peer.node.ListenAddr())
	if !errors.Is(err, p2p.ErrIdentityBanned) {
		t.Fatalf("SyncFrom a banned identity returned %v, want ErrIdentityBanned", err)
	}
}
