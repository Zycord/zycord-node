package p2p

import (
	"testing"
	"time"

	"zycord/spec"
)

// TestABlockChunksBytesAreChargedAndNotOnlyItsHeaderCousins separates the
// second charge site.
//
// Both kinds refusing past the budget is not the same property as both kinds
// paying into it: delete the charge in OnGetBlock and every refusal test still
// passes, because they all spend the budget on headers. Here the budget is
// spent on bodies first and finished with headers, so an uncharged body path
// shows up as more total bytes than one window can hold.
func TestABlockChunksBytesAreChargedAndNotOnlyItsHeaderCousins(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	budget, _ := f.budget()
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))

	var bodyBytes uint64
	for round := 0; round < 2; round++ {
		for _, id := range f.ids {
			v := e.OnGetBlock(payer, GetBlock{ID: id, Chunk: 0}.MarshalGetBlock())
			if v.Reply == nil {
				t.Fatalf("a body chunk was refused after only %d bytes: %+v", bodyBytes, v)
			}
			bodyBytes += uint64(len(v.Reply.Payload))
		}
	}

	served, headerBytes, v := serveUntilRefused(e, payer, 4096)
	if v.Reply != nil {
		t.Fatal("the budget never ran out")
	}
	reply := headerBytes / uint64(served)
	total := bodyBytes + headerBytes
	// The margin this test lives on, stated rather than assumed: the body
	// bytes have to exceed one header reply, or an uncharged body path hides
	// inside the overshoot the budget already allows.
	if bodyBytes <= reply {
		t.Fatalf("the %d body bytes spent are not more than one %d-byte header "+
			"reply, so this test cannot tell a charged body path from an "+
			"uncharged one", bodyBytes, reply)
	}
	if total >= budget+reply {
		t.Errorf("%d body bytes plus %d header bytes = %d were served against a "+
			"budget of %d: a served block chunk is not being charged",
			bodyBytes, headerBytes, total, budget)
	}
	t.Logf("%d body bytes then %d header bytes = %d against a budget of %d, "+
		"largest reply %d; body bytes exceed one reply by %dx",
		bodyBytes, headerBytes, total, budget, reply, bodyBytes/reply)
}

// TestNodeChargesAServedReplyToTheConnectionsAuthenticatedIdentity is the
// wiring test, and it is the only one here that goes through a socket.
//
// Everything else in this file calls the engine directly, so every one of them
// still passes if Node.serve goes back to calling Handle without the peer key —
// the budget would be there and would be charged to an ephemeral source port,
// which is the defect the identity keying answers next door rather than a fix.
// What this pins is the one production call site: a real TLS connection, a real
// handshake, one real get-headers, and the bytes charged under the DIALLER's
// public key rather than under the address the OS gave the socket.
func TestNodeChargesAServedReplyToTheConnectionsAuthenticatedIdentity(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), 8)
	e := f.engine(t)
	peers := e.Peers

	serverID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(serverID, e, peers, 1)
	if err := n.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	n.Start()
	t.Cleanup(n.Stop)

	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(n.ListenAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	h := e.Hello()
	h.ListenAddr = ""
	if err := c.Send(KindHello, h.MarshalHello()); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(KindGetHeaders, GetHeaders{From: 0, Count: MaxHeadersPerResponse}.MarshalGetHeaders()); err != nil {
		t.Fatal(err)
	}

	var reply []byte
	deadline := time.Now().Add(10 * time.Second)
	for reply == nil {
		if err := c.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		kind, payload, err := c.Receive()
		if err != nil {
			t.Fatalf("no headers frame arrived: %v", err)
		}
		if kind == KindHeaders {
			reply = payload
		}
	}

	peers.identityMu.Lock()
	byKey := peers.identity[string(client.PublicKey())]
	entries := len(peers.identity)
	peers.identityMu.Unlock()

	if byKey.served != uint64(len(reply)) {
		t.Fatalf("the identity store charged %d bytes to the dialler's public key, "+
			"want the %d bytes it was actually sent; %d identity entries exist. "+
			"Node.serve is not passing Conn.PeerKey, so the budget is keyed on an "+
			"ephemeral source port and is re-bought per handshake",
			byKey.served, len(reply), entries)
	}
	t.Logf("one real get-headers over TLS: %d bytes replied, %d charged to the "+
		"dialler's Ed25519 identity, %d identity entries", len(reply), byKey.served, entries)
}
