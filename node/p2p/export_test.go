package p2p

import (
	"context"
	"crypto/ed25519"
	"net"
	"time"

	"zycord/core/types"
	"zycord/core/u256"
)

// ResolveBootstrapForTest exposes resolveBootstrap to the package's external
// test binary, which is where the operator-facing --peers behaviour is
// exercised. The function itself stays unexported: it is a detail of Start,
// not an interface anything outside this package should call.
func ResolveBootstrapForTest(addr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapResolveTimeout)
	defer cancel()
	return resolveBootstrap(ctx, addr)
}

// ClampDeadlineForTest exposes clampDeadline to the package's external test
// binary.
//
// It needs its own test rather than relying on the sync-attempt tests,
// because clampDeadline and SyncFrom's watcher are deliberately redundant
// for the timeout: either one alone still bounds a stalling peer, so no
// behavioural test fails when only the clamp is broken. That redundancy is
// the design, but it means a neutered clampDeadline is invisible to the
// suite — which is not hypothetical: `_ = attempt; return fresh` was
// committed to this file's sibling once and the whole p2p suite still
// passed. The function itself stays unexported; it is a detail of how
// SyncFrom and connSource bound their reads and writes.
func ClampDeadlineForTest(fresh, attempt time.Time) time.Time {
	return clampDeadline(fresh, attempt)
}

// SyncKeyForTest exposes the rotation key a candidate is remembered by.
//
// The key is not observable from any behaviour a candidate-set test can see —
// a wrong key gives the right candidates and the wrong rotation — so it is
// asserted directly rather than inferred.
func (t PeerTip) SyncKeyForTest() string { return t.syncKey() }

// DeliverSyncResponseForTest exposes the routing decision serve makes on every
// frame arriving on a shared gossip connection.
func (n *Node) DeliverSyncResponseForTest(addr string, kind MessageKind, payload []byte) bool {
	return n.deliverSyncResponse(addr, kind, payload)
}

// ArmSyncWaitForTest registers exactly the mailbox sharedTransport.await
// registers, so a test can drive the routing decision without a peer that has
// to be persuaded to answer at the right moment.
func (n *Node) ArmSyncWaitForTest(addr string, kind MessageKind, id types.Hash, chunk uint32) func() {
	m := &syncMailbox{want: kind, ch: make(chan []byte, 1)}
	switch kind {
	case KindBlock:
		m.match = chunkAnswers(id, chunk)
	case KindHeaders:
		m.match = headersAnswer
	}
	n.mu.Lock()
	if n.syncInbox == nil {
		n.syncInbox = map[string]*syncMailbox{}
	}
	n.syncInbox[addr] = m
	n.mu.Unlock()
	return func() {
		n.mu.Lock()
		delete(n.syncInbox, addr)
		n.mu.Unlock()
	}
}

// SharedSyncRoundTripForTest runs one sync request over a shared gossip
// connection, on a caller-supplied socket, so a test can observe the order in
// which arming and sending happen.
func (n *Node) SharedSyncRoundTripForTest(c net.Conn, addr string, ask, want MessageKind, deadline time.Time) (MessageKind, []byte, error) {
	return sharedTransport{n: n, conn: &Conn{Conn: c, Addr: addr}}.
		roundTrip(ask, nil, want, nil, deadline)
}

// SyncInboxArmedForTest reports whether a sync request is registered and
// waiting for an answer on this connection.
func (n *Node) SyncInboxArmedForTest(addr string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.syncInbox[addr]
	return ok
}

// ServeForTest runs the real gossip read loop on a caller-supplied socket, so
// a test can assert what serve does with a frame rather than what
// deliverSyncResponse would have said about it in isolation.
func (n *Node) ServeForTest(c net.Conn, addr string) {
	n.wg.Add(1) // serve's own deferred Done, which Start would otherwise pair.
	n.serve(&Conn{Conn: c, Addr: addr}, true)
}

// SharedSyncHeadersForTest issues one real headers request over a shared
// connection, through connSource — so the match connSource chooses for a
// headers response is the one under test, rather than one the harness picked.
func (n *Node) SharedSyncHeadersForTest(c net.Conn, addr string, deadline time.Time) error {
	s := &connSource{
		t:        sharedTransport{n: n, conn: &Conn{Conn: c, Addr: addr}},
		params:   n.Engine.Chain.Params(),
		deadline: deadline,
	}
	_, err := s.Headers(1, 1)
	return err
}

// AdoptConnForTest registers a connection under an identity, the way the
// accept path would, so a test can drive a path that looks one up.
func (n *Node) AdoptConnForTest(c net.Conn, addr string, key ed25519.PublicKey) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns == nil {
		n.conns = map[string]*Conn{}
	}
	n.conns[addr] = &Conn{Conn: c, Addr: addr, PeerKey: key}
}

// SyncOverGossipForTest exposes one sync attempt over a shared connection.
func (n *Node) SyncOverGossipForTest(t PeerTip) error { return n.syncOverGossip(t) }

// TipForTest builds the candidate syncOverGossip is handed, without needing a
// handshake to produce one.
func TipForTest(conn string, height uint64) PeerTip {
	return PeerTip{Height: height, Work: u256.FromUint64(height), Conn: conn}
}

// SyncOnceForTest exposes the route one sync attempt takes and the address its
// outcome is charged to.
//
// Both are decisions rather than computations, and neither is observable from
// the outside: a wrong route still syncs from *somebody*, and a wrong
// attribution still bans *something*. syncLoop is the only caller and it runs
// on a timer, so driving it would observe the timer.
func (n *Node) SyncOnceForTest(t PeerTip) (string, error) { return n.syncOnce(t) }

// RunSyncLoopForTest starts the real sync driver loop, and only it, so a test
// can observe what syncLoop does with the address SyncOnceForTest reports.
//
// The two are one call apart and that call is a second decision. syncOnce says
// which address an attempt is attributable to; syncLoop is what turns that into
// a peer store entry, with the candidate — advertised address and all — still in
// scope beside it. Nothing outside this package could reach that line: syncLoop
// is its only caller and runs on a timer, and Start brings four other loops with
// it, including a dial loop that connects to whatever is in the peer store and a
// probation loop that rewrites scores, so a score read after Start is not
// attributable to the sync driver. This starts that one goroutine under the same
// wg entry Start gives it, and Stop ends it exactly as it ends Start's.
func (n *Node) RunSyncLoopForTest() {
	n.wg.Add(1)
	go n.syncLoop()
}

// LapseCandidacyForTest ages a peer's OffersUnknown stamp by d without
// touching its tip, its connection or anything else.
//
// It exists because the only honest way to drive a candidacy lapse is to let
// offersUnknownWindow expire, and that constant is thirty seconds: a test that
// waited would measure the clock rather than the rotation. Ageing the stamp is
// exactly what the passage of time does to it, and it keeps the distinction
// the rotation's prune turns on — the socket is still up, so this is a lapse and not a
// disconnect. ForgetPeerForTest is the disconnect.
func (e *Engine) LapseCandidacyForTest(conn string, d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.tips[conn]
	t.OffersUnknown = time.Now().Add(-d)
	e.tips[conn] = t
}

// ForgetPeerForTest drops a peer's tip the way a disconnect does.
func (e *Engine) ForgetPeerForTest(conn string) { e.forgetPeer(conn) }

// SyncRotationSizeForTest reports how many rotation keys the node is holding.
//
// The size is not observable from any selection a test can make — the wrong
// bound gives the right answer for as long as nothing has been dropped — so
// the memory claim about the rotation's key set is asserted directly rather
// than inferred.
func (n *Node) SyncRotationSizeForTest() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.syncTried)
}

// SyncRotationViewForTest exposes the one snapshot NextSyncPeer selects from:
// the candidate list and the rotation-key set, read under a single acquisition
// of e.mu.
//
// The relation between the two is not observable from any selection a test can
// make — a second acquisition returns the same tips to a single-threaded
// caller, so one read and two give identical answers — so it is asserted
// directly rather than inferred.
func (e *Engine) SyncRotationViewForTest() ([]PeerTip, map[string]struct{}) {
	return e.syncRotationView()
}

// SyncTipCountForTest reports how many peers this node holds a tip for, which
// is the set the rotation's memory is bounded by.
func (e *Engine) SyncTipCountForTest() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.tips)
}
