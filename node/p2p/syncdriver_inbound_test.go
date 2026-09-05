package p2p_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/p2p"
)

// A node that only has peers which dialled *it* froze at the first block
// it had to pull rather than receive.
//
// Gossip hides this until one block is missed. From that moment the node needs
// to pull, and candidacy was gated on being able to dial the peer back — so a
// peer with no advertised listen address (behind NAT, or simply started
// without one, which wire.md requires it to advertise as empty) was never
// asked. Observed in production on the shape docs/RUNNING.md recommends:
// height 217 for 45 minutes next to a peer at 268, through a reconnect and
// through a restart of each side, with ahead_peers=0 and nothing logged.

// TestAPeerWithNoAdvertisedAddressIsStillASyncCandidate is the property, stated
// at the point the decision is made.
func TestAPeerWithNoAdvertisedAddressIsStillASyncCandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	// An inbound connection: the address is the peer's ephemeral source port,
	// and it advertises nothing because it accepts no connections.
	inbound := "10.0.0.7:54123"
	victim.engine.Handle(inbound, p2p.KindHello, p2p.Hello{
		Protocol:  p2p.ProtocolVersion,
		NetworkID: victim.chain.NetworkID(),
		Height:    500,
		Work:      u256.FromUint64(500).Bytes(),
	}.MarshalHello())

	got := victim.engine.SyncCandidates()
	if len(got) != 1 {
		t.Fatalf("%d sync candidates for a peer 500 blocks ahead on an inbound "+
			"connection, want 1: a node whose peers all dialled it can never "+
			"pull, and reports ahead_peers=0 while it freezes", len(got))
	}
	if got[0].Dial != "" {
		t.Fatalf("setup: the candidate advertised %q, so this test is not "+
			"exercising the undialable case at all", got[0].Dial)
	}
	if got[0].Conn != inbound {
		t.Fatalf("candidate carries connection %q, want %q: without the socket "+
			"it was learned on there is no route to an undialable peer",
			got[0].Conn, inbound)
	}

	// Anti-vacuity: candidacy must still be a judgement about being ahead, not
	// a blanket yes. The same connection, behind rather than ahead, is not a
	// candidate — so the assertion above cannot be passed by removing the test
	// altogether.
	behind := "10.0.0.8:54124"
	victim.engine.Handle(behind, p2p.KindHello, p2p.Hello{
		Protocol:  p2p.ProtocolVersion,
		NetworkID: victim.chain.NetworkID(),
		Height:    0,
		Work:      u256.FromUint64(0).Bytes(),
	}.MarshalHello())
	for _, c := range victim.engine.SyncCandidates() {
		if c.Conn == behind {
			t.Fatal("a peer at this node's own height became a candidate: " +
				"candidacy stopped meaning 'ahead' and now means 'connected'")
		}
	}

	// And the ban filter still reaches it. An undialable peer is scored by its
	// connection address, which is the only address it has.
	for !victim.peers.Banned(inbound) {
		victim.peers.Adjust(inbound, p2p.ScoreProtocolViolation)
	}
	if n := len(victim.engine.SyncCandidates()); n != 0 {
		t.Fatalf("%d candidates after banning the inbound peer, want 0: making "+
			"undialable peers candidates put them beyond the ban list", n)
	}
}

// TestUndialablePeersDoNotShareOneRotationSlot pins the key, not just the
// membership.
//
// The rotation's memory is keyed per peer. Keying an undialable peer by its
// (empty) advertised address would give every such peer the same key, so asking
// one would count as having asked all of them — the starvation the rotation
// exists to prevent, re-created by the key rather than by the ranking, and
// invisible because the candidate set would still look right.
func TestUndialablePeersDoNotShareOneRotationSlot(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	conns := []string{"10.0.0.1:41001", "10.0.0.2:41002", "10.0.0.3:41003"}
	for i, c := range conns {
		victim.engine.Handle(c, p2p.KindHello, p2p.Hello{
			Protocol:  p2p.ProtocolVersion,
			NetworkID: victim.chain.NetworkID(),
			Height:    uint64(10 + i),
			Work:      u256.FromUint64(uint64(10 + i)).Bytes(),
		}.MarshalHello())
	}
	if n := len(victim.engine.SyncCandidates()); n != len(conns) {
		t.Fatalf("setup: %d candidates, want %d", n, len(conns))
	}

	seen := map[string]int{}
	for range conns {
		peer, ok := victim.node.NextSyncPeer()
		if !ok {
			t.Fatal("no candidate mid-rotation")
		}
		if peer.Dial != "" {
			t.Fatalf("setup: candidate %q advertises an address", peer.Dial)
		}
		seen[peer.Conn]++
		victim.node.MarkSyncTried(peer.SyncKeyForTest())
	}
	for _, c := range conns {
		if seen[c] != 1 {
			t.Fatalf("connection %s was chosen %d times in the first full "+
				"rotation, want 1: undialable peers share a rotation key, so "+
				"asking one is recorded as having asked every one of them", c, seen[c])
		}
	}
}

// TestAListeningNodeCatchesUpFromThePeerThatDialledIt drives that end to end, over
// real sockets and through the real driver.
//
// The reduced harness cannot show this: the defect was never a wrong
// computation, it was that nothing on the path from "a peer is ahead" to "ask
// it" could be reached at all for a peer this node cannot dial. Driving
// sync.Run directly would prove the sync package works, which was never in
// question.
func TestAListeningNodeCatchesUpFromThePeerThatDialledIt(t *testing.T) {
	p := devnetEasy()

	// The documented bootstrap shape: listening, no --peers of its own, and so
	// never dialling anybody.
	core := newNode(t, "core", p, key(t, 1).Persistent())
	core.node.MaxOutbound = 0
	core.node.SyncInterval = 20 * time.Millisecond
	core.node.SyncAttemptTimeout = 20 * time.Second
	if err := core.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listening: %v", err)
	}

	// The peer: a miner that dials out and accepts nothing, so it advertises no
	// listen address. This is the laptop-behind-NAT case the whitepaper's Era 0
	// demographic is made of.
	edge := newNode(t, "edge", p, key(t, 2).Persistent())
	edge.engine = p2p.NewEngine(edge.chain, edge.pool, edge.peers, pow.Dev{}, "")
	edgeID, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	edge.node = p2p.NewNode(edgeID, edge.engine, edge.peers, 2)
	edge.node.SyncInterval = time.Hour // it is ahead; it must not sync from core
	const ahead = 12
	edge.mine(t, ahead)
	if edge.chain.Height() != ahead {
		t.Fatalf("setup: the edge node is at height %d, want %d", edge.chain.Height(), ahead)
	}
	if core.chain.Height() != 0 {
		t.Fatalf("setup: the core node starts at height %d, want 0", core.chain.Height())
	}
	if edge.engine.Hello().ListenAddr != "" {
		t.Fatal("setup: the edge node advertises a listen address, so it is " +
			"dialable and the case under test does not arise")
	}

	edge.peers.Add(core.node.ListenAddr())
	core.node.Start()
	edge.node.Start()
	t.Cleanup(edge.node.Stop)
	t.Cleanup(core.node.Stop)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if core.chain.Tip().ID() == edge.chain.Tip().ID() {
			// The connection must be the one the edge node opened, or this
			// passed for a reason that has nothing to do with the inbound route.
			listening, in, out := core.node.Reachability()
			if !listening || in != 1 || out != 0 {
				t.Fatalf("the core node caught up, but its topology is "+
					"listening=%v inbound=%d outbound=%d: it was not "+
					"inbound-only, so this is not the frozen shape", listening, in, out)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, in, out := core.node.Reachability()
	t.Fatalf("the core node is stuck at height %d while the peer that dialled "+
		"it is at %d (inbound=%d outbound=%d), with %d sync candidates: a "+
		"listening node with no --peers of its own never pulls, which is the "+
		"production freeze",
		core.chain.Height(), edge.chain.Height(), in, out,
		len(core.engine.SyncCandidates()))
}

// TestAGossipBodyChunkIsNotStolenByAnOutstandingSyncRequest pins the boundary
// the shared connection introduces.
//
// Sync over a gossip connection means both paths read block chunks off one
// socket. Claiming every chunk while a sync request is outstanding would take
// the gossip body-fetch path's answers away from Engine.OnBlockChunk — a
// second freeze traded for the first. The claim is therefore narrowed to the
// exact block and chunk index the request named.
func TestAGossipBodyChunkIsNotStolenByAnOutstandingSyncRequest(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	wanted := types.Hash{1}
	other := types.Hash{2}
	addr := "10.0.0.9:5555"

	release := n.node.ArmSyncWaitForTest(addr, p2p.KindBlock, wanted, 0)
	defer release()

	mine := p2p.BlockChunk{ID: wanted, Chunk: 0, Total: 1, Data: []byte("a")}
	theirs := p2p.BlockChunk{ID: other, Chunk: 0, Total: 1, Data: []byte("b")}

	// The refusals go first, deliberately. The mailbox holds one answer, so a
	// delivery that succeeded would leave every later attempt refused for a
	// reason that has nothing to do with matching — and this test would pass
	// with the match removed entirely.
	if n.node.DeliverSyncResponseForTest(addr, p2p.KindBlock, theirs.MarshalBlockChunk()) {
		t.Fatal("a chunk for a different block was claimed by the outstanding " +
			"sync request: the gossip body-fetch path loses its answers, and " +
			"OnBlockChunk never sees, scores or assembles them")
	}
	// A different connection is a different peer's socket entirely.
	if n.node.DeliverSyncResponseForTest("10.0.0.10:5555", p2p.KindBlock, mine.MarshalBlockChunk()) {
		t.Fatal("a chunk arriving on another connection was routed to this " +
			"request: answers are matched by content and not by who sent them")
	}
	// And a kind nobody is waiting for is left alone.
	if n.node.DeliverSyncResponseForTest(addr, p2p.KindHeaders, p2p.MarshalHeaders(nil)) {
		t.Fatal("a headers frame was claimed by a request waiting for a block")
	}
	// A malformed chunk cannot be shown to answer anything, so it falls through
	// to the gossip handler, which is where it gets scored.
	if n.node.DeliverSyncResponseForTest(addr, p2p.KindBlock, []byte{0x01}) {
		t.Fatal("an undecodable frame was claimed as an answer")
	}
	// Only now the one that must land. Every refusal above happened against an
	// empty mailbox.
	if !n.node.DeliverSyncResponseForTest(addr, p2p.KindBlock, mine.MarshalBlockChunk()) {
		t.Fatal("the chunk this sync request asked for was not delivered to it")
	}
	// And a second copy, now that the mailbox is full, is *not* claimed. A full
	// mailbox that swallowed frames would be a free channel: a peer could keep
	// resending while a request is outstanding and never be decoded, deduped or
	// scored by Engine.Handle at all.
	if n.node.DeliverSyncResponseForTest(addr, p2p.KindBlock, mine.MarshalBlockChunk()) {
		t.Fatal("a frame arriving against a mailbox that already holds an " +
			"answer was claimed and dropped: it answers nothing, so it must " +
			"fall through to the gossip handler and be scored there")
	}
}

// TestASharedSyncRequestIsArmedBeforeItIsSent pins the ordering the shared
// connection stands or falls on.
//
// serve reads the gossip socket on another goroutine, so the mailbox must
// exist before the request is on the wire. Registering it afterwards leaves a
// window in which the answer arrives, finds no mailbox, is handed to
// Engine.Handle as unsolicited and is lost — after which the request waits out
// its whole window and the attempt fails. That is the freeze's own symptom recreated
// inside the fix for it, and it is invisible against a loopback peer: it needs
// only that this goroutine be descheduled for a moment between the two.
//
// The test observes from the peer's side. net.Pipe is unbuffered, so the read
// below returns at the instant the request is written — the earliest moment
// any answer could possibly come back — and the mailbox must already be there.
func TestASharedSyncRequestIsArmedBeforeItIsSent(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	ours, peer := net.Pipe()
	defer ours.Close()
	defer peer.Close()
	const addr = "10.0.0.11:6001"

	// The peer side reads continuously, and records — at the instant the
	// request lands, which for an unbuffered pipe is the instant it is written
	// — whether the mailbox for it already exists.
	armed := make(chan bool, 1)
	go func() {
		_, _, err := p2p.ReadFrame(peer)
		if err != nil {
			armed <- false
			return
		}
		armed <- n.node.SyncInboxArmedForTest(addr)
		io.Copy(io.Discard, peer)
	}()

	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		_, payload, err := n.node.SharedSyncRoundTripForTest(
			ours, addr, p2p.KindGetHeaders, p2p.KindHeaders, time.Now().Add(10*time.Second))
		done <- result{payload, err}
	}()

	select {
	case ok := <-armed:
		if !ok {
			t.Fatal("the request was on the wire before its mailbox existed: an " +
				"answer arriving this promptly goes to the gossip handler instead " +
				"and is lost, and the request then waits out its whole window — " +
				"the freeze, re-created inside the fix for it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the peer")
	}

	// Anti-vacuity: arming early is only right if the answer still lands.
	if !n.node.DeliverSyncResponseForTest(addr, p2p.KindHeaders, p2p.MarshalHeaders(nil)) {
		t.Fatal("the armed mailbox refused the answer it was armed for")
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("the round trip failed with its answer delivered: %v", got.err)
	}
	if n.node.SyncInboxArmedForTest(addr) {
		t.Fatal("the mailbox outlived the request that armed it")
	}
}

// TestAnAdvertisedAddressStillKeysAPeerThatDialledUs is the other half of the
// rotation key, and the half a candidate-set test cannot see.
//
// syncKey falls back to the connection address only where there is no
// advertised one. Keying *every* peer by its connection would be invisible in
// the candidate set and wrong in two places at once: an inbound peer that does
// advertise an address would be remembered — and penalised — by an ephemeral
// source port the persisted peer store has never heard of, so its rotation slot
// and its score would both be discarded on every reconnect.
func TestAnAdvertisedAddressStillKeysAPeerThatDialledUs(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	// Inbound — an ephemeral source port — but it does accept connections, so
	// it advertises where.
	const conn = "10.0.0.12:61234"
	const advertised = "10.0.0.12:9999"
	victim.engine.Handle(conn, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		ListenAddr: advertised,
		Height:     500,
		Work:       u256.FromUint64(500).Bytes(),
	}.MarshalHello())

	got := victim.engine.SyncCandidates()
	if len(got) != 1 {
		t.Fatalf("%d candidates, want 1", len(got))
	}
	if got[0].Conn != conn {
		t.Fatalf("setup: candidate connection %q, want %q", got[0].Conn, conn)
	}
	if k := got[0].SyncKeyForTest(); k != advertised {
		t.Fatalf("this peer is keyed by %q, want its advertised address %q: an "+
			"address the peer store and the ban list have never heard of "+
			"cannot carry a rotation slot or a penalty across a reconnect", k, conn)
	}
}

// TestAMalformedHeadersFrameIsNotClaimedByASyncRequest closes the cost class on
// the headers path, where the first cut left it open.
//
// wire.md §6 is normative about this frame: it "MUST still be decoded, so that
// a malformed one is scored as invalid", and Engine.Handle's KindHeaders case
// is the only place that charges ScoreInvalidMessage for one. A shared
// connection that claimed *any* headers frame while a request was armed would
// divert an undecodable one away from that case, and SyncPenalty charges
// nothing for an unmarshal error — so a malformed headers frame would be free
// for as long as a sync request was outstanding. chunkAnswers already refuses
// an undecodable body chunk for exactly this reason; the asymmetry was the bug.
func TestAMalformedHeadersFrameIsNotClaimedByASyncRequest(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	ours, peer := net.Pipe()
	defer ours.Close()
	defer peer.Close()
	const addr = "10.0.0.13:7001"

	done := make(chan error, 1)
	go func() {
		done <- n.node.SharedSyncHeadersForTest(ours, addr, time.Now().Add(10*time.Second))
	}()
	if _, _, err := p2p.ReadFrame(peer); err != nil {
		t.Fatalf("the request never reached the peer: %v", err)
	}

	// A headers frame that cannot be decoded. It answers nothing, so it must
	// fall through to the gossip handler rather than be swallowed here.
	if n.node.DeliverSyncResponseForTest(addr, p2p.KindHeaders, []byte{0xff}) {
		t.Fatal("an undecodable headers frame was claimed by the outstanding " +
			"sync request: Engine.Handle is the only thing that charges " +
			"ScoreInvalidMessage for one and SyncPenalty charges nothing for " +
			"an unmarshal error, so claiming it makes a malformed frame free")
	}
	// Anti-vacuity: the refusal must be about decodability, not about headers
	// frames in general. A well-formed one still lands.
	if !n.node.DeliverSyncResponseForTest(addr, p2p.KindHeaders, p2p.MarshalHeaders(nil)) {
		t.Fatal("a well-formed headers frame was refused too, so this request " +
			"can never be answered at all and the assertion above proves nothing")
	}
	if err := <-done; err != nil {
		t.Fatalf("the round trip failed with a valid answer delivered: %v", err)
	}
}

// TestAFrameOfAnotherKindIsNotClaimedByASyncRequest pins the kind check on its
// own.
//
// The payload below is a valid headers encoding carried by a frame of another
// kind, so the match function cannot be what refuses it — only the want/kind
// comparison can. Isolating it matters because roundTrip returns the kind that
// was *asked for* rather than the kind that arrived, which leaves connSource's
// own "if kind != …" guards unreachable on this path: the comparison inside
// deliverSyncResponse is the only enforcement left, so nothing else would
// notice if it went.
func TestAFrameOfAnotherKindIsNotClaimedByASyncRequest(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	const addr = "10.0.0.14:7002"
	release := n.node.ArmSyncWaitForTest(addr, p2p.KindHeaders, types.Hash{}, 0)
	defer release()

	if n.node.DeliverSyncResponseForTest(addr, p2p.KindBlockAnnounce, p2p.MarshalHeaders(nil)) {
		t.Fatal("a frame of another kind was delivered to a request waiting " +
			"for headers, on a payload the match function accepts: the kind " +
			"comparison is the only thing between a sync attempt and whatever " +
			"else the peer chooses to send down the same socket")
	}
	if !n.node.DeliverSyncResponseForTest(addr, p2p.KindHeaders, p2p.MarshalHeaders(nil)) {
		t.Fatal("setup: the same payload under the right kind was refused as " +
			"well, so the assertion above proves nothing about the kind")
	}
}

// TestAClaimedFrameDoesNotAlsoReachTheGossipHandler pins routing exclusivity.
//
// serve claims a frame *or* hands it to Engine.Handle, never both. Doing both
// would feed a sync attempt's own answer back in as unsolicited gossip and
// score the peer for this node's own request. The property is serve's
// `continue`, which nothing below serve can observe, so this drives the real
// read loop over a real socket.
//
// The observable is the ban edge rather than a score reading: the peer is
// brought to exactly one invalid message short of ScoreBanThreshold, so any
// verdict at all reaching Engine.Handle tips it over and any that does not
// leaves it alone.
func TestAClaimedFrameDoesNotAlsoReachTheGossipHandler(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	ours, peer := net.Pipe()
	const addr = "10.0.0.15:7003"
	defer peer.Close()

	// One invalid message short of the ban threshold.
	for !n.peers.Banned(addr) {
		n.peers.Adjust(addr, p2p.ScoreInvalidMessage)
	}
	n.peers.Adjust(addr, -p2p.ScoreInvalidMessage)
	if n.peers.Banned(addr) {
		t.Fatal("setup: the peer is already banned, so nothing below can move")
	}

	go n.node.ServeForTest(ours, addr)
	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// serve greets first; read it or its write never completes.
	if _, _, err := p2p.ReadFrame(peer); err != nil {
		t.Fatalf("no hello from serve: %v", err)
	}

	id := types.Hash{9}
	release := n.node.ArmSyncWaitForTest(addr, p2p.KindBlock, id, 0)
	defer release()

	// A single-chunk body carrying bytes that are not a block. Claimed, it is
	// this attempt's answer and connSource is what judges it. Handed to
	// Engine.Handle as well, it is scored — this peer has not even handshaked
	// — and the peer crosses the ban threshold for answering a question this
	// node asked it.
	chunk := p2p.BlockChunk{ID: id, Chunk: 0, Total: 1, Data: []byte("not a block")}
	if err := p2p.Frame(peer, p2p.KindBlock, chunk.MarshalBlockChunk()); err != nil {
		t.Fatalf("writing the chunk: %v", err)
	}

	// The mailbox is armed by the harness and never drained, so there is no
	// edge to wait on: settle instead, long enough for serve to have read the
	// frame and done whatever it was going to do with it. Under the mutant
	// this fires immediately, so the wait only costs a passing run.
	time.Sleep(300 * time.Millisecond)
	if n.peers.Banned(addr) {
		t.Fatal("the peer was scored for a frame this node asked it for: " +
			"serve handed a claimed frame to Engine.Handle as well, so a sync " +
			"answer is judged a second time as unsolicited gossip")
	}
}

// TestASyncAttemptOverGossipRefusesABannedIdentity pins the third bullet of the
// eclipse argument, which nothing else asserted.
//
// An inbound peer is reached at an ephemeral source port, so the address-keyed
// ban filter cannot see through a reconnect; the identity-keyed one can, and it
// must refuse before the attempt sends its first byte — otherwise a banned peer
// buys a fresh sync attempt for the price of one TLS handshake, on the
// one path where being asked is the whole privilege.
func TestASyncAttemptOverGossipRefusesABannedIdentity(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	ours, peer := net.Pipe()
	defer ours.Close()
	defer peer.Close()
	const addr = "10.0.0.16:7004"
	banned := ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))
	n.node.AdoptConnForTest(ours, addr, banned)
	for !n.peers.BannedKey(banned) {
		n.peers.AdjustKey(banned, p2p.ScoreProtocolViolation)
	}

	// Nothing reads `peer`, so an attempt that got as far as sending its first
	// request would block on the unbuffered pipe rather than return. The
	// assertion is that it never gets there.
	errc := make(chan error, 1)
	go func() { errc <- n.node.SyncOverGossipForTest(p2p.TipForTest(addr, 500)) }()
	select {
	case err := <-errc:
		if !errors.Is(err, p2p.ErrIdentityBanned) {
			t.Fatalf("a banned identity was refused with %v, want ErrIdentityBanned", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a banned identity was asked for headers over the connection " +
			"it opened: the identity ban is the only filter that survives a " +
			"reconnect on a fresh source port, and this is the path on which " +
			"an inbound peer is reached")
	}
}

// The same freeze through its other branch: a peer that advertises an address
// nobody answers at.
//
// The first cut asked a peer over the socket it opened only when it advertised
// *nothing*. But an advertisement is a claim about reachability and nothing
// checks it, so a peer naming an address no one can reach was dialled every
// rotation and never once asked — the same permanent freeze, reached through
// the other branch. It is the harder half to see: this time the peer *is* a
// candidate and `ahead_peers` counts it, so the one signal that named the
// first freeze reports the second as healthy. The shape is `zycordd`'s
// default, not an exotic one — `--advertise` falls back to `--listen`, so a
// NAT'd node given `--listen 0.0.0.0:9421` advertises `0.0.0.0:9421`.
func TestAListeningNodeCatchesUpFromAPeerWhoseAdvertisedAddressDoesNotAnswer(t *testing.T) {
	p := devnetEasy()

	// The documented bootstrap shape again: listening, no --peers of its own.
	core := newNode(t, "core", p, key(t, 1).Persistent())
	core.node.MaxOutbound = 0
	core.node.SyncInterval = 20 * time.Millisecond
	core.node.SyncAttemptTimeout = 20 * time.Second
	if err := core.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listening: %v", err)
	}

	// A port this machine is not listening on, obtained by binding one and
	// closing it: an address that refuses immediately, which is what a
	// forwarded port that was never forwarded does from outside.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unanswered := dead.Addr().String()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", unanswered, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("setup: %s answered, so nothing below is about an "+
			"unreachable advertisement", unanswered)
	}

	// The peer: ahead, dials out, and advertises the address above.
	edge := newNode(t, "edge", p, key(t, 2).Persistent())
	edge.engine = p2p.NewEngine(edge.chain, edge.pool, edge.peers, pow.Dev{}, unanswered)
	edgeID, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	edge.node = p2p.NewNode(edgeID, edge.engine, edge.peers, 2)
	edge.node.SyncInterval = time.Hour // it is ahead; it must not sync from core
	const ahead = 12
	edge.mine(t, ahead)
	if edge.engine.Hello().ListenAddr != unanswered {
		t.Fatalf("setup: the edge node advertises %q, want %q — the case "+
			"under test is an advertisement that cannot be reached, not the "+
			"absent one the first cut already covers",
			edge.engine.Hello().ListenAddr, unanswered)
	}

	edge.peers.Add(core.node.ListenAddr())
	core.node.Start()
	edge.node.Start()
	t.Cleanup(edge.node.Stop)
	t.Cleanup(core.node.Stop)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if core.chain.Tip().ID() == edge.chain.Tip().ID() {
			listening, in, out := core.node.Reachability()
			if !listening || in != 1 || out != 0 {
				t.Fatalf("the core node caught up, but its topology is "+
					"listening=%v inbound=%d outbound=%d: it was not "+
					"inbound-only, so this is not the frozen shape",
					listening, in, out)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, in, out := core.node.Reachability()
	cands := core.engine.SyncCandidates()
	t.Fatalf("the core node is stuck at height %d while the peer that dialled "+
		"it is at %d (inbound=%d outbound=%d), with %d sync candidates: it "+
		"kept dialling an address that does not answer instead of asking the "+
		"peer over the connection that peer opened",
		core.chain.Height(), edge.chain.Height(), in, out, len(cands))
}

// TestAnUnansweredDialIsReRoutedAndChargedToTheSocket pins both halves of the
// decision above at the point it is made.
//
// The liveness half is not the whole property. Attribution is the half that
// could weaken address trust: a re-routed attempt is answered over the
// socket the peer owns, so its verdict belongs to that socket. Charging it to
// the advertised address instead would let any inbound peer file its own
// misbehaviour against whatever address it names — a ban an attacker writes
// for a victim it has never met — and no liveness test can see the difference,
// because both routes catch up.
func TestAnUnansweredDialIsReRoutedAndChargedToTheSocket(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())
	n.node.SyncAttemptTimeout = 2 * time.Second

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unanswered := dead.Addr().String()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}

	// No connection is adopted for this candidate, so the re-routed attempt
	// ends at ErrNoSyncRoute — which only syncOverGossip returns, and is
	// therefore itself the evidence that the attempt was re-routed rather
	// than abandoned at the failed dial.
	tip := p2p.TipForTest("10.0.0.21:41010", 500)
	tip.Dial = unanswered
	from, err := n.node.SyncOnceForTest(tip)
	if !errors.Is(err, p2p.ErrNoSyncRoute) {
		t.Fatalf("a peer whose advertised address refuses the connection "+
			"failed with %v, want ErrNoSyncRoute: the attempt stopped at the "+
			"dial instead of falling back to the socket the peer opened, "+
			"which is the freeze through an advertisement nobody "+
			"can reach", err)
	}
	if from != tip.Conn {
		t.Fatalf("the attempt was charged to %q, want the connection %q: a "+
			"verdict earned on the socket the peer owns, filed against an "+
			"address the peer merely named, is a ban any inbound peer can "+
			"write for any address it chooses", from, tip.Conn)
	}

	// Anti-vacuity: the re-route is triggered by the dial failing, not by
	// there being a socket. A peer that answers and then serves nothing is
	// that peer's own doing — it keeps its own route and its own name, and
	// waits for its next turn in the rotation.
	answering := p2p.TipForTest("10.0.0.22:41011", 500)
	answering.Dial = stallingPeer(t, n.chain.NetworkID())
	from, err = n.node.SyncOnceForTest(answering)
	if err == nil {
		t.Fatal("setup: the stalling peer served a sync attempt, so nothing " +
			"below separates a failed dial from a failed sync")
	}
	if errors.Is(err, p2p.ErrNoSyncRoute) {
		t.Fatalf("a peer that answered its dial was re-routed anyway (%v): "+
			"the fallback fires on any failure, so the dedicated connection "+
			"has stopped being the rule wire.md §12 says it is", err)
	}
	if from != answering.Dial {
		t.Fatalf("an attempt over a dialled connection was charged to %q, "+
			"want the address it dialled %q", from, answering.Dial)
	}
}

// TestTheDriverFilesAReRoutedVerdictAgainstTheSocket carries the property above
// one call further, to the line that consumes it.
//
// The test above stops at syncOnce's return value: it establishes which address
// the attempt says its verdict belongs to, and nothing more. Filing that
// verdict is a second decision, made in syncLoop, where the candidate is still
// in scope and still carries the advertised address — so `n.Peers.Adjust(from,
// penalty)` becomes `n.Peers.Adjust(peer.syncKey(), penalty)` by one word, and
// syncKey() returns Dial whenever there is one, which for the re-routed case is
// exactly the address that did not answer. That reinstates the address-trust
// hole whole: any inbound peer files its own misbehaviour against whatever
// address it cares to name, a ban an attacker writes for a victim it has never
// met. Verified by mutation: until this test existed, every test in this
// package passed with that word changed, because none of them ran the consumer.
//
// The socket's own entry is asserted as well as the advertised one, and that
// half is not decoration: a test that only checked the advertised address would
// pass just as happily with the charge deleted altogether — a peer that lies
// over the connection it opened paying nothing at all, which is a worse defect
// wearing this one's clothes.
func TestTheDriverFilesAReRoutedVerdictAgainstTheSocket(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())
	n.node.SyncInterval = 10 * time.Millisecond
	n.node.SyncAttemptTimeout = 5 * time.Second

	// The advertised address: bound, then closed, so it refuses a connection
	// immediately — what a port forward nobody configured does from outside.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unanswered := dead.Addr().String()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}

	// The socket the peer owns: live and registered, so the re-route has
	// somewhere to go and the attempt reaches a verdict worth attributing.
	ours, peer := net.Pipe()
	defer ours.Close()
	defer peer.Close()
	const conn = "10.0.0.31:41031"
	n.node.AdoptConnForTest(ours, conn,
		ed25519.PublicKey(bytes.Repeat([]byte{3}, ed25519.PublicKeySize)))

	// The handshake is what pins Dial, so the candidate the rotation hands the
	// driver is the re-routed shape: an advertisement nobody answers, on a peer
	// reachable only over the connection it opened.
	n.engine.Handle(conn, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  n.chain.NetworkID(),
		ListenAddr: unanswered,
		Height:     500,
		Work:       u256.FromUint64(500).Bytes(),
	}.MarshalHello())
	cands := n.engine.SyncCandidates()
	if len(cands) != 1 || cands[0].Dial != unanswered || cands[0].Conn != conn {
		t.Fatalf("setup: %d candidates (%+v), want exactly one advertising %q "+
			"on socket %q: the driver has to be handed the re-routed shape or "+
			"nothing below is about attribution at all",
			len(cands), cands, unanswered, conn)
	}

	// Both entries already exist — OnHello's AddFrom made the advertised one and
	// MarkConnected the socket's — so "untouched" below is a fact about where
	// the charge was filed, not about an address the store would have refused to
	// admit. Adjust is non-strict and both addresses are already in the store, so
	// it returns at admitLocked's fast path: whichever of the two the driver
	// names is the one that moves.
	socketBefore := scoreOf(t, n, conn)
	advertisedBefore := scoreOf(t, n, unanswered)

	// The single answer the peer gives: a header that attaches to genesis and
	// claims to stand at height 500. That is a chain that cannot exist
	// (sync.ErrNotContiguous), which is one of the failures SyncPenalty charges
	// ScoreInvalidMessage for — unlike a stall or a severed socket, which it
	// deliberately charges nothing for and which would leave this test asserting
	// that zero had been filed against the right address.
	lie := p2p.MarshalHeaders([]types.Header{{
		Version:  types.HeaderVersion,
		Height:   500,
		ParentID: n.chain.Tip().ID(),
	}})
	delivered := make(chan bool, 1)
	go func() {
		kind, _, err := p2p.ReadFrame(peer)
		if err != nil || kind != p2p.KindGetHeaders {
			delivered <- false
			return
		}
		delivered <- n.node.DeliverSyncResponseForTest(conn, p2p.KindHeaders, lie)
	}()

	n.node.RunSyncLoopForTest()
	t.Cleanup(n.node.Stop)

	select {
	case ok := <-delivered:
		if !ok {
			t.Fatal("setup: the peer's answer was not claimed by the outstanding " +
				"sync request, so the attempt ends on a timeout — which is not " +
				"scored, and no address would be charged anything below")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the driver never asked this peer for headers over the socket it " +
			"opened: the attempt never reached a verdict, so there is nothing " +
			"for it to have attributed to anybody")
	}

	// Wait for the verdict to land *anywhere*. Polling the socket's entry alone
	// would spend the whole timeout under the mis-attribution this test exists
	// to catch and then report it as "nothing was charged", which names the
	// wrong defect and sends the reader to the wrong line.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if scoreOf(t, n, conn) != socketBefore ||
			scoreOf(t, n, unanswered) != advertisedBefore {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Stopped before the assertions read anything, so what they read is the
	// driver's whole output rather than a value the next tick is already moving.
	n.node.Stop()

	if got := scoreOf(t, n, unanswered); got != advertisedBefore {
		t.Fatalf("the advertised address %q was charged %d for a sync answered "+
			"over the socket %q: a verdict earned on the socket a peer owns, "+
			"filed against an address that peer merely named, is a ban any "+
			"inbound peer can write for any address it chooses",
			unanswered, got-advertisedBefore, conn)
	}
	if got := scoreOf(t, n, conn); got != socketBefore+p2p.ScoreInvalidMessage {
		t.Fatalf("the socket %q was charged %d for describing a chain that "+
			"cannot exist, want exactly %d: at zero the peer that served the "+
			"lie pays nothing, so a failed sync costs its author as much as "+
			"an honest one and the assertion above passes on an untouched "+
			"store rather than a correctly attributed one; anything else and "+
			"the charge that landed here is not the one SyncPenalty prices "+
			"this failure at",
			conn, got-socketBefore, p2p.ScoreInvalidMessage)
	}
}

// lyingPeer completes the p2p handshake honestly, answers the first GetHeaders
// it is asked with `headers`, and then goes silent on every connection it ever
// accepts, including that one. Returns the dialable address.
//
// A peer that answers is the half stallingPeer cannot stand in for. SyncPenalty
// deliberately charges nothing for a stall or a severed socket — those are the
// network's fault, not the peer's — so an attribution test built on one would be
// asserting that zero had been filed against the right address. Only a peer that
// serves something a chain could not contain reaches ScoreInvalidMessage, which
// is the charge there is any point in tracing to an address.
//
// The answer is given once rather than on every connection because the driver is
// a rotation and this is its only candidate: it comes back every SyncInterval
// for as long as the loop runs. One answer makes the total charge a known
// constant instead of a function of how fast the test's own goroutine noticed,
// and every later attempt ends in a stall the penalty rule ignores.
func lyingPeer(t *testing.T, networkID types.Hash, headers []byte) string {
	t.Helper()
	id, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// perSource is generous because each parked handler below holds its slot
	// until teardown, and a driver that never lands its charge — which is
	// exactly what a mutation run looks like — keeps rotating back here.
	ln, err := id.Listen("127.0.0.1:0", 8)
	if err != nil {
		t.Fatal(err)
	}
	// hold parks each accepted handler so it stays silent instead of returning
	// (and thereby closing the connection) after its last Send. Closed before
	// ln.Close() so every parked handler is released and runs its own deferred
	// conn.Close() as part of teardown instead of outliving the test.
	hold := make(chan struct{})
	t.Cleanup(func() {
		close(hold)
		ln.Close()
	})
	// A one-shot token rather than a counter: whichever handler takes it is the
	// one that answers, and there is no second one to take.
	first := make(chan struct{}, 1)
	first <- struct{}{}

	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The handshake has to succeed, or SyncFrom ends the attempt
				// for a reason this test is not about (ErrWrongNetwork).
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, _, err := conn.Receive(); err != nil {
					return
				}
				hello := p2p.Hello{
					Protocol:  p2p.ProtocolVersion,
					NetworkID: networkID,
					Height:    500,
					Work:      u256.FromUint64(500).Bytes(),
				}
				if conn.Send(p2p.KindHello, hello.MarshalHello()) != nil {
					return
				}
				select {
				case <-first:
				default:
					<-hold
					return
				}
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				kind, _, err := conn.Receive()
				if err != nil || kind != p2p.KindGetHeaders {
					return
				}
				if conn.Send(p2p.KindHeaders, headers) != nil {
					return
				}
				<-hold
			}()
		}
	}()
	return addr
}

// TestTheDriverFilesADialledVerdictAgainstTheAddressItDialled is the same
// decision as the test above, taken through the branch that succeeds.
//
// syncOnce re-routes only a dial that produced no connection; when the dial
// works it returns t.Dial, so the candidate's socket and the address its verdict
// belongs to are two different strings in this direction too. The test above
// cannot see that: in the re-routed shape it builds, `from` *is* peer.Conn, so
// `n.Peers.Adjust(from, penalty)` and `n.Peers.Adjust(peer.Conn, penalty)` name
// one entry and no assertion on it can tell them apart. Verified by mutation:
// until this test existed, the socket spelling passed the whole package.
//
// What it costs is that hole inverted. A peer this node dialled successfully, which
// then described a chain that cannot exist, would have its charge filed against
// the ephemeral source port it happened to gossip from rather than against the
// listening address it was reached at. That port names nothing durable: it goes
// away with the connection, taking the charge with it, while the advertised
// address the rotation dials again next tick stays clean — a peer that can lie
// for free for as long as it reconnects.
//
// Both entries are asserted, for the reason the test above gives: an assertion
// that only checked the socket had stayed untouched would pass just as happily
// with the charge deleted altogether, which is a worse defect wearing this
// one's clothes.
func TestTheDriverFilesADialledVerdictAgainstTheAddressItDialled(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())
	n.node.SyncInterval = 10 * time.Millisecond
	n.node.SyncAttemptTimeout = 5 * time.Second

	// The single answer the peer gives: a header that attaches to genesis and
	// claims to stand at height 500. That is a chain that cannot exist
	// (sync.ErrNotContiguous), which is one of the failures SyncPenalty charges
	// ScoreInvalidMessage for.
	lie := p2p.MarshalHeaders([]types.Header{{
		Version:  types.HeaderVersion,
		Height:   500,
		ParentID: n.chain.Tip().ID(),
	}})
	dialable := lyingPeer(t, n.chain.NetworkID(), lie)

	// The socket the peer opened to this node. An inbound connection's address
	// is the peer's ephemeral source port, which is what makes it a different
	// string from the address that peer advertises — and a candidate whose two
	// addresses differ is the only shape in which attribution is observable.
	const conn = "10.0.0.41:41041"
	n.engine.Handle(conn, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  n.chain.NetworkID(),
		ListenAddr: dialable,
		Height:     500,
		Work:       u256.FromUint64(500).Bytes(),
	}.MarshalHello())
	cands := n.engine.SyncCandidates()
	if len(cands) != 1 || cands[0].Dial != dialable || cands[0].Conn != conn {
		t.Fatalf("setup: %d candidates (%+v), want exactly one advertising %q "+
			"on socket %q: unless the two addresses differ, every assertion "+
			"below is satisfied by either of them",
			len(cands), cands, dialable, conn)
	}

	// Both entries already exist — OnHello's AddFrom made the advertised one and
	// MarkConnected the socket's — so "untouched" below is a fact about where
	// the charge was filed, not about an address the store would have refused to
	// admit. Adjust is non-strict and both addresses are already in the store, so
	// it returns at admitLocked's fast path: whichever of the two the driver
	// names is the one that moves.
	dialBefore := scoreOf(t, n, dialable)
	socketBefore := scoreOf(t, n, conn)

	n.node.RunSyncLoopForTest()
	t.Cleanup(n.node.Stop)

	// Wait for the verdict to land *anywhere*, for the reason the test above
	// gives: polling the dialled address alone would spend the whole timeout
	// under the mis-attribution this test exists to catch and then report it as
	// "nothing was charged", which names the wrong defect.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if scoreOf(t, n, dialable) != dialBefore ||
			scoreOf(t, n, conn) != socketBefore {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Stopped before the assertions read anything, so what they read is the
	// driver's whole output rather than a value the next tick is already moving.
	n.node.Stop()

	if got := scoreOf(t, n, conn); got != socketBefore {
		t.Fatalf("the socket %q was charged %d for a sync this node ran over a "+
			"connection it dialled to %q: a verdict earned at an address that "+
			"answers, filed against an ephemeral source port, is a charge that "+
			"disappears with the connection while the address the rotation "+
			"dials again keeps a clean record",
			conn, got-socketBefore, dialable)
	}
	if got := scoreOf(t, n, dialable); got != dialBefore+p2p.ScoreInvalidMessage {
		t.Fatalf("the dialled address %q was charged %d for describing a chain "+
			"that cannot exist, want exactly %d: at zero the peer that served "+
			"the lie pays nothing, so the assertion above passes on an "+
			"untouched store rather than a correctly attributed one; anything "+
			"else and the charge that landed here is not the one SyncPenalty "+
			"prices this failure at",
			dialable, got-dialBefore, p2p.ScoreInvalidMessage)
	}
}
