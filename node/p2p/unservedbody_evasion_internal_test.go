package p2p

import (
	"testing"
	"time"

	"zycord/core/types"
)

// The debt an announcement creates MUST NOT be cancellable by anything a peer
// puts on the wire.
//
// `Engine.pending` records "this peer announced this block and has not served
// it", and `ReapUnservedBodies` charges it once the window elapses (wire.md §9
// rule 5). Three of `OnBlockChunk`'s refusals are this node's own doing — a
// chunk continuing no transfer, the per-peer eviction, the reassembly byte
// budget — and none of them scores, which is what wire.md §5.1 requires: "A
// receiver MUST NOT penalise a peer for a chunk that continues no transfer,
// for the per-peer eviction, or for the byte budget." That prohibition is on
// scoring **a chunk**, and it already holds; the reaper's charge is for the
// **announcement**, a different object, and §9 rule 5 grants it exactly one
// receiver-caused exemption — a block already canonical when the window
// elapses — which these are not.
//
// So the standing invitation is to clear `pending` on those three paths, and
// these tests are the wire across it. Every field the refusals key on is
// attacker-supplied or attacker-arrangeable:
//
//   - `BlockChunk.ID` is read straight off the wire and cross-checked against
//     nothing at the point the refusals fire.
//   - `pending` is keyed by block id **alone**, with no peer in the key, so an
//     unscoped mutation lets any peer cancel any other peer's debt.
//   - the per-peer eviction victim is ordered by `started`, which follows the
//     order that same peer opened its transfers in.
//   - the reassembly byte budget is global, and the reachable connection set
//     multiplies past it (socketBound: 48 sockets × MaxTransfersPerPeer ×
//     BlockChunkBytes ≈ 768 MiB against a 256 MiB budget — the relation
//     TestReassemblyMagnitudeRelationsHold asserts), so a peer population can
//     put the node into the saturated state on demand.
//
// Each test therefore states one evasion and requires the charge to survive
// it. They are written against the attacker's capability rather than against
// any particular implementation of a fix, so a future "excuse" mechanism has
// to defeat the capability to pass, not merely be shaped differently.
//
// Internal because `pending` and `partialBytes` are private and the point is
// to seed and inspect them directly: routing through OnBlockAnnounce would
// make the tests depend on proof of work, which is not what is under test.

// seedAnnouncement records an outstanding announcement exactly as
// OnBlockAnnounce does, without paying its proof of work.
func seedAnnouncement(e *Engine, id types.Hash, peerAddr string, at time.Time) {
	e.mu.Lock()
	e.pending[id] = announcedBody{peerAddr: peerAddr, announced: at}
	e.mu.Unlock()
}

// reapAfterWindow runs the reaper far enough past the window that every seeded
// entry is late, and reports who was charged.
func reapAfterWindow(e *Engine, at time.Time) []string {
	return e.ReapUnservedBodies(at.Add(PendingBodyTimeout + time.Second))
}

func chargedWith(charged []string, addr string) bool {
	for _, c := range charged {
		if c == addr {
			return true
		}
	}
	return false
}

// fullChunk is a well-formed non-final chunk payload. UnmarshalBlockChunk
// requires every chunk but the last to be exactly BlockChunkBytes, so a
// shorter one is ErrMalformed and would make these tests exercise nothing.
func fullChunk() []byte { return make([]byte, BlockChunkBytes) }

// TestAnAnnouncerCannotCancelItsOwnUnservedBodyWithAChunkThatContinuesNothing
// is the evasion: one frame naming the announcer's own announced id, tripping
// ErrNoSuchTransfer, and buying the debt back.
func TestAnAnnouncerCannotCancelItsOwnUnservedBodyWithAChunkThatContinuesNothing(t *testing.T) {
	e := testEngine(t)
	const attacker = "10.66.0.1:5000"
	var announced types.Hash
	announced[0] = 0xA1
	at := time.Now()
	seedAnnouncement(e, announced, attacker, at)

	// A chunk naming the announced id that continues no transfer. Chunk 1 of a
	// claimed 2, with nothing held under that id.
	v := e.OnBlockChunk(attacker, BlockChunk{
		ID: announced, Chunk: 1, Total: 2, Data: []byte("x"),
	}.MarshalBlockChunk())
	if v.Score != 0 {
		t.Fatalf("the refusal scored %d: wire.md §5.1 forbids penalising a peer "+
			"for a chunk that continues no transfer", v.Score)
	}

	charged := reapAfterWindow(e, at)
	if !chargedWith(charged, attacker) {
		t.Fatalf("the announcer cancelled its own unserved-body debt with one "+
			"chunk naming an id it chose: charged=%v. BlockChunk.ID is "+
			"attacker-supplied and cross-checked against nothing here, so "+
			"clearing pending on this path is a free evasion of wire.md §9 "+
			"rule 5 rather than a fix for the false positive it looks like",
			charged)
	}
}

// TestAPeerCannotCancelAnotherPeersUnservedBody is the same evasion aimed
// sideways, and it is worse: Engine.pending is keyed by block id with no peer
// in the key, so an excuse that is not scoped to the announcer lets any peer
// clear any other peer's debt — including an honest peer's, which turns the
// fix into a way to suppress the rule entirely.
func TestAPeerCannotCancelAnotherPeersUnservedBody(t *testing.T) {
	e := testEngine(t)
	const honest = "10.66.0.2:5000"
	const attacker = "10.66.0.1:5000"
	var announced types.Hash
	announced[0] = 0xB2
	at := time.Now()
	seedAnnouncement(e, announced, honest, at)

	// The attacker names the *honest* peer's announced id from its own
	// connection. It never announced anything and owes nothing.
	v := e.OnBlockChunk(attacker, BlockChunk{
		ID: announced, Chunk: 1, Total: 2, Data: []byte("x"),
	}.MarshalBlockChunk())
	if v.Score != 0 {
		t.Fatalf("the refusal scored %d, which §5.1 forbids", v.Score)
	}

	charged := reapAfterWindow(e, at)
	if !chargedWith(charged, honest) {
		t.Fatalf("a peer cancelled a different peer's unserved-body debt: "+
			"charged=%v. pending is keyed by block id alone, so any mutation "+
			"of it from a chunk path must be scoped to the announcing peer or "+
			"it hands every peer a veto over every other peer's accountability",
			charged)
	}
}

// TestAnAnnouncerCannotCancelItsOwnUnservedBodyByTrippingThePerPeerEviction:
// the eviction victim is chosen by `started`, which follows the order this
// same peer opened its transfers in, so "this node evicted my transfer" is a
// condition the peer arranges rather than one it suffers.
func TestAnAnnouncerCannotCancelItsOwnUnservedBodyByTrippingThePerPeerEviction(t *testing.T) {
	e := testEngine(t)
	const attacker = "10.66.0.1:5000"
	var announced types.Hash
	announced[0] = 0xC3
	at := time.Now()
	seedAnnouncement(e, announced, attacker, at)

	// Open a transfer under the announced id first, so that it is the oldest
	// and therefore the one this node will evict.
	if v := e.OnBlockChunk(attacker, BlockChunk{
		ID: announced, Chunk: 0, Total: 2, Data: fullChunk(),
	}.MarshalBlockChunk()); v.Err != nil || v.Score < 0 {
		t.Fatalf("setup: chunk 0 refused: err=%v score=%d", v.Err, v.Score)
	}
	// Then push past the per-peer bound with transfers under ids of its own
	// choosing, which evicts the oldest — the announced one.
	for i := 0; i < MaxTransfersPerPeer; i++ {
		var filler types.Hash
		filler[0] = 0xC3
		filler[1] = byte(i + 1)
		if v := e.OnBlockChunk(attacker, BlockChunk{
			ID: filler, Chunk: 0, Total: 2, Data: fullChunk(),
		}.MarshalBlockChunk()); v.Score < 0 {
			t.Fatalf("setup: filler %d scored %d", i, v.Score)
		}
	}

	// Confirm the eviction actually happened, so the test is not vacuous: the
	// announced transfer must be gone from the table.
	e.mu.Lock()
	_, stillHeld := e.partial[attacker][announced]
	e.mu.Unlock()
	if stillHeld {
		t.Fatal("setup: the announced transfer was not evicted, so this test " +
			"never reached the branch it is written for")
	}

	charged := reapAfterWindow(e, at)
	if !chargedWith(charged, attacker) {
		t.Fatalf("the announcer cancelled its own debt by making this node "+
			"evict its transfer: charged=%v. The eviction victim is ordered by "+
			"`started`, which follows the peer's own open order, so an excuse "+
			"minted here is minted by the party it excuses", charged)
	}
}

// TestAnAnnouncerCannotCancelItsOwnUnservedBodyByTrippingTheByteBudget: the
// reassembly byte budget is global and the count bounds multiply past it, so a
// peer can saturate it with its own well-formed chunk 0s and then trip it on
// its own announced id.
func TestAnAnnouncerCannotCancelItsOwnUnservedBodyByTrippingTheByteBudget(t *testing.T) {
	e := testEngine(t)
	const attacker = "10.66.0.1:5000"
	var announced types.Hash
	announced[0] = 0xD4
	at := time.Now()
	seedAnnouncement(e, announced, attacker, at)

	// Open the transfer for the announced id, then put the node in the
	// saturated state, so that the next chunk for the announced id is refused
	// by saturation rather than by anything the sender did wrong.
	//
	// partialBytes is set directly rather than filled from 16 other
	// connections. The two are the same state as far as this refusal is
	// concerned — it reads partialBytes and nothing else — and the arrival
	// path that reaches it is already covered by TestReassemblyMemoryIsBounded.
	// What this test is about is which entry survives in `pending`, and
	// spending 256 MiB of chunk payloads to get there would only make the
	// suite slower and no more load-bearing.
	if v := e.OnBlockChunk(attacker, BlockChunk{
		ID: announced, Chunk: 0, Total: 3, Data: fullChunk(),
	}.MarshalBlockChunk()); v.Err != nil || v.Score < 0 {
		t.Fatalf("setup: chunk 0 refused: err=%v score=%d", v.Err, v.Score)
	}
	e.mu.Lock()
	e.partialBytes = MaxReassemblyBytes
	e.mu.Unlock()

	v := e.OnBlockChunk(attacker, BlockChunk{
		ID: announced, Chunk: 1, Total: 3, Data: fullChunk(),
	}.MarshalBlockChunk())
	if v.Err == nil {
		t.Fatal("setup: the byte budget did not refuse the chunk, so this test " +
			"never reached the branch it is written for")
	}
	if v.Score != 0 {
		t.Fatalf("the byte-budget refusal scored %d, which §5.1 forbids", v.Score)
	}

	charged := reapAfterWindow(e, at)
	if !chargedWith(charged, attacker) {
		t.Fatalf("the announcer cancelled its own debt by saturating the "+
			"reassembly byte budget and then tripping it on its own announced "+
			"id: charged=%v. The budget is global and the count bounds "+
			"multiply to four times it, so saturation is a state a peer "+
			"arranges rather than one it encounters", charged)
	}
}

// TestTheSingleChunkPathStillAnswersAnAnnouncement guards the other direction,
// and it is the one that matters today: a total=1 transfer goes straight to
// OnBlock and is the only reachable body path at every committed parameter
// set. A fix that made the reaper stricter must not make a peer that actually
// served a body pay for it — §9 rule 5's "a body that arrives answers the
// announcement, whatever the receiver then decides about it".
func TestTheSingleChunkPathStillAnswersAnAnnouncement(t *testing.T) {
	e := testEngine(t)
	const peer = "10.66.0.3:5000"
	blk := &types.Block{Header: types.Header{Version: types.HeaderVersion, Height: 9}}
	body := blk.MarshalSSZ()
	id := blk.Header.ID()
	at := time.Now()
	seedAnnouncement(e, id, peer, at)

	if got := ChunkCount(len(body)); got != 1 {
		t.Fatalf("setup: the body is %d chunks, not the single-chunk shape "+
			"under test", got)
	}
	e.OnBlockChunk(peer, BlockChunk{
		ID: id, Chunk: 0, Total: 1, Data: body,
	}.MarshalBlockChunk())

	if charged := reapAfterWindow(e, at); chargedWith(charged, peer) {
		t.Fatalf("a peer that delivered a single-chunk body was charged for an "+
			"unserved one: charged=%v. This is the only body path reachable at "+
			"every committed parameter set, so a regression here ships "+
			"immediately", charged)
	}
}
