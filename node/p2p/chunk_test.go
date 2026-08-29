package p2p_test

import (
	"errors"
	"testing"

	"zycord/core/types"
	"zycord/node/p2p"
)

// Chunked block transfer (wire.go, engine.go). The single-chunk path is
// exercised by every other test in this package — a block at the genesis
// ceiling is one chunk — so what is tested here is the multi-chunk machinery
// those tests cannot reach: the codec's bounds, reassembly fidelity, and the
// allocation defences around the partial-transfer table.
//
// Bodies here are sized against `block_byte_capacity` rather than against
// `BlockChunkBytes × total`, because the two are not the same bound and only
// the first is what a real transfer may reach: at the current constants a
// legitimate block is at most two chunks, the second of them short. A test
// that sent two *full* chunks would be sending 8,388,608 bytes against an
// 8,000,000-byte capacity and would be exercising the capacity check by
// accident while believing it exercised reassembly.

// multiChunkBody returns a body large enough to need two chunks and small
// enough to stay inside the consensus byte capacity, with its chunk sequence.
func multiChunkBody(t *testing.T, capacity int) ([]byte, []p2p.BlockChunk, types.Hash) {
	t.Helper()
	size := p2p.BlockChunkBytes + 805_696 // 5,000,000: two chunks, the second short
	if size > capacity {
		t.Fatalf("setup: a two-chunk body of %d exceeds the byte capacity %d", size, capacity)
	}
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i*131 + i>>9)
	}
	var id types.Hash
	id[0] = 0x5A
	total := uint32(p2p.ChunkCount(len(body)))
	chunks := make([]p2p.BlockChunk, total)
	for i := range chunks {
		chunks[i] = p2p.BlockChunk{ID: id, Chunk: uint32(i), Total: total, Data: p2p.ChunkOf(body, i)}
	}
	return body, chunks, id
}

// twoChunk returns the chunk sequence for a transfer under a given id, sized
// like multiChunkBody's.
func twoChunk(id types.Hash) []p2p.BlockChunk {
	return []p2p.BlockChunk{
		{ID: id, Chunk: 0, Total: 2, Data: make([]byte, p2p.BlockChunkBytes)},
		{ID: id, Chunk: 1, Total: 2, Data: make([]byte, 805_696)},
	}
}

func TestBlockChunkCodecRoundTrips(t *testing.T) {
	var id types.Hash
	id[0] = 7
	c := p2p.BlockChunk{ID: id, Chunk: 2, Total: 4, Data: make([]byte, p2p.BlockChunkBytes)}
	got, err := p2p.UnmarshalBlockChunk(c.MarshalBlockChunk())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Chunk != c.Chunk || got.Total != c.Total || len(got.Data) != len(c.Data) {
		t.Fatalf("round trip changed the chunk: %+v", got)
	}

	g := p2p.GetBlock{ID: id, Chunk: 3}
	back, err := p2p.UnmarshalGetBlock(g.MarshalGetBlock())
	if err != nil {
		t.Fatal(err)
	}
	if back != g {
		t.Fatalf("round trip changed the request: %+v", back)
	}
}

// TestBlockChunkCodecRefusesEveryMalformedShape pins each bound in
// UnmarshalBlockChunk on its own, because each closes a different attack: a
// zero or oversized total claims a transfer that cannot exist, a chunk at or
// past its total breaks reassembly indexing, an oversized chunk is an
// allocation the frame limit was supposed to bound, and a short non-final
// chunk stretches a transfer into arbitrarily many messages.
func TestBlockChunkCodecRefusesEveryMalformedShape(t *testing.T) {
	var id types.Hash
	full := make([]byte, p2p.BlockChunkBytes)
	cases := map[string]p2p.BlockChunk{
		"zero total":            {ID: id, Chunk: 0, Total: 0, Data: full},
		"total over the bound":  {ID: id, Chunk: 0, Total: p2p.MaxBlockChunks + 1, Data: full},
		"chunk at its total":    {ID: id, Chunk: 2, Total: 2, Data: full},
		"short non-final chunk": {ID: id, Chunk: 0, Total: 2, Data: full[:100]},
		"empty final chunk":     {ID: id, Chunk: 1, Total: 2, Data: nil},
		"oversized chunk":       {ID: id, Chunk: 0, Total: 2, Data: make([]byte, p2p.BlockChunkBytes+1)},
	}
	for name, c := range cases {
		if _, err := p2p.UnmarshalBlockChunk(c.MarshalBlockChunk()); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	if _, err := p2p.UnmarshalGetBlock(p2p.GetBlock{ID: id, Chunk: p2p.MaxBlockChunks}.MarshalGetBlock()); err == nil {
		t.Error("a request past MaxBlockChunks decoded")
	}
}

// TestChunkedReassemblyIsByteFaithful is the differential for the reassembly
// path: a multi-chunk transfer must hand OnBlock exactly the bytes that were
// split, no more, no fewer, in order. The body is deliberately not a valid
// block — validity is OnBlock's business, tested elsewhere — so the property
// asserted is that the reassembled path and the direct path fail *identically*,
// which they can only do if the bytes match.
func TestChunkedReassemblyIsByteFaithful(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	body, chunks, id := multiChunkBody(t, p.BlockByteCapacity)
	total := uint32(len(chunks))
	if total < 2 {
		t.Fatal("setup: the body is a single chunk, so nothing is reassembled")
	}

	direct := n.engine.OnBlock("direct:1", body)
	if direct.Err == nil {
		t.Fatal("setup: the synthetic body decoded as a block; the differential needs a failing body")
	}

	handshake(t, n, "peer:1")
	for i := uint32(0); i < total; i++ {
		c := chunks[i]
		v := n.engine.Handle("peer:1", p2p.KindBlock, c.MarshalBlockChunk())
		if i < total-1 {
			if v.Reply == nil || v.Reply.Kind != p2p.KindGetBlock {
				t.Fatalf("chunk %d did not request a successor", i)
			}
			next, err := p2p.UnmarshalGetBlock(v.Reply.Payload)
			if err != nil || next.ID != id || next.Chunk != i+1 {
				t.Fatalf("chunk %d requested %+v, want chunk %d of the same transfer", i, next, i+1)
			}
			continue
		}
		if v.Reply != nil {
			t.Fatal("the final chunk requested a successor")
		}
		if v.Err == nil || v.Err.Error() != direct.Err.Error() {
			t.Fatalf("reassembled delivery failed with %v, direct delivery with %v: the bytes differ",
				v.Err, direct.Err)
		}
	}
}

// TestChunkContinuingNoTransferIsRefused: a chunk must continue a transfer
// this node is holding — matching id, total and next index — or it is dropped.
// Anything looser lets a peer splice bytes across transfers or replay chunks
// out of order into a body nobody sent.
//
// The refusal must **not** score. This node evicts transfers of its own accord
// — on disconnect, and past the per-peer bound — so the branch fires for
// benign reasons as readily as hostile ones, and CONTRIBUTING's rule applies:
// a check that can fire benignly is noise with authority.
func TestChunkContinuingNoTransferIsRefused(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	var id, other types.Hash
	id[0], other[0] = 1, 2
	a, b := twoChunk(id), twoChunk(other)

	handshake(t, n, "peer:1")
	// No transfer in flight: a continuation from nowhere.
	v := n.engine.Handle("peer:1", p2p.KindBlock, a[1].MarshalBlockChunk())
	if v.Err == nil {
		t.Fatal("a chunk continuing no transfer was accepted")
	}
	if v.Score < 0 {
		t.Fatalf("a chunk continuing no transfer scored %d; this node's own eviction "+
			"produces exactly this message from an honest peer", v.Score)
	}

	// A chunk whose total disagrees with the live transfer is refused, and
	// drops it.
	n.engine.Handle("peer:1", p2p.KindBlock, a[0].MarshalBlockChunk())
	mismatched := p2p.BlockChunk{ID: id, Chunk: 1, Total: 3, Data: make([]byte, p2p.BlockChunkBytes)}
	v = n.engine.Handle("peer:1", p2p.KindBlock, mismatched.MarshalBlockChunk())
	if v.Err == nil || v.Score < 0 {
		t.Fatalf("a chunk with a mismatched total was accepted or scored: err=%v score=%d", v.Err, v.Score)
	}
	v = n.engine.Handle("peer:1", p2p.KindBlock, a[1].MarshalBlockChunk())
	if v.Err == nil {
		t.Fatal("a continuation of a dropped transfer was accepted")
	}

	// A chunk 0 for a different id starts a second transfer rather than
	// evicting the first — the property TestConcurrentTransfersFromOnePeer
	// covers in full.
	v = n.engine.Handle("peer:1", p2p.KindBlock, b[0].MarshalBlockChunk())
	if v.Err != nil {
		t.Fatalf("a second transfer was refused: %v", v.Err)
	}
}

// TestConcurrentTransfersFromOnePeer is the regression for the defect this
// design had when transfers were keyed by peer alone.
//
// Every accepted announcement fires its own get-block and nothing bounds how
// many a peer may have in flight, so two overlapping fetches from one honest
// peer — a fork, or any burst — interleaved: the second's chunk 0 evicted the
// first, the first's chunk 1 then continued nothing, and both fetches stalled
// while the peer that served them correctly was scored down to a ban.
func TestConcurrentTransfersFromOnePeer(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	var idA, idB types.Hash
	idA[0], idB[0] = 0xAA, 0xBB
	a, b := twoChunk(idA), twoChunk(idB)

	handshake(t, n, "peer:1")
	// Interleaved exactly as a peer serving two requests in order would. Both
	// final chunks must *complete* their transfer: what the defect produced
	// was ErrNoSuchTransfer on each, which is the assertion here. The
	// completed bodies are synthetic and fail to decode as blocks, and that
	// verdict is OnBlock's business and correctly the sender's fault — so the
	// discriminator is the sentinel, never the score.
	for i, c := range []p2p.BlockChunk{a[0], b[0], a[1], b[1]} {
		v := n.engine.Handle("peer:1", p2p.KindBlock, c.MarshalBlockChunk())
		if errors.Is(v.Err, p2p.ErrNoSuchTransfer) {
			t.Fatalf("message %d: an honest peer's interleaved transfer was dropped as continuing nothing", i)
		}
	}
}

// TestTransfersPerPeerAreBounded: a peer may hold several transfers, but not
// unboundedly many — past the bound the oldest is evicted, and the peer is
// never scored for a burst of announcements, which is honest behaviour.
func TestTransfersPerPeerAreBounded(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())
	full := make([]byte, p2p.BlockChunkBytes)

	handshake(t, n, "peer:1")
	for i := 0; i < p2p.MaxTransfersPerPeer+3; i++ {
		var id types.Hash
		id[0] = byte(i)
		v := n.engine.Handle("peer:1", p2p.KindBlock,
			p2p.BlockChunk{ID: id, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
		if v.Err != nil || v.Score < 0 {
			t.Fatalf("transfer %d refused or scored: err=%v score=%d", i, v.Err, v.Score)
		}
	}
	if pr, ok := n.peers.Get("peer:1"); ok && pr.Score < 0 {
		t.Fatalf("a burst of announcements left an honest peer at %d", pr.Score)
	}
	// The oldest is gone; the most recent survives. The discriminator is the
	// sentinel: a surviving transfer completes and then fails to decode as a
	// block, which is a different verdict from never having been held.
	var newest types.Hash
	newest[0] = byte(p2p.MaxTransfersPerPeer + 2)
	if v := n.engine.Handle("peer:1", p2p.KindBlock,
		twoChunk(newest)[1].MarshalBlockChunk()); errors.Is(v.Err, p2p.ErrNoSuchTransfer) {
		t.Fatal("the most recent transfer was evicted")
	}
	var oldest types.Hash
	if v := n.engine.Handle("peer:1", p2p.KindBlock,
		twoChunk(oldest)[1].MarshalBlockChunk()); !errors.Is(v.Err, p2p.ErrNoSuchTransfer) {
		t.Fatal("the oldest transfer survived past the per-peer bound")
	}
}

// TestChunkedTransferCannotExceedTheByteCapacity: the reassembly buffer is
// bounded by the consensus byte capacity, checked as chunks arrive — a peer
// declaring a large total buys no allocation with the claim and is cut off at
// the bound with the bytes it actually sent.
func TestChunkedTransferCannotExceedTheByteCapacity(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	var id types.Hash
	id[0] = 3
	full := make([]byte, p2p.BlockChunkBytes)
	total := uint32(p2p.MaxBlockChunks)

	handshake(t, n, "peer:1")
	sent := 0
	for i := uint32(0); i < total; i++ {
		v := n.engine.Handle("peer:1", p2p.KindBlock,
			p2p.BlockChunk{ID: id, Chunk: i, Total: total, Data: full}.MarshalBlockChunk())
		sent += len(full)
		if sent > p.BlockByteCapacity {
			if v.Err == nil || v.Score >= 0 {
				t.Fatalf("chunk %d pushed the transfer to %d bytes against a capacity of %d and was accepted",
					i, sent, p.BlockByteCapacity)
			}
			return
		}
		if v.Err != nil {
			t.Fatalf("chunk %d refused below the capacity: %v", i, v.Err)
		}
	}
	t.Fatal("the transfer completed without ever crossing the capacity; the bound was not exercised")
}

// TestPartialTransferTableIsBounded: at most MaxPartialTransfers peers may hold
// a reassembly buffer, and a peer refused for table pressure is not scored
// down — a full table is this node's condition, not the peer's fault.
func TestPartialTransferTableIsBounded(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "n", p, key(t, 1).Persistent())

	var id types.Hash
	id[0] = 4
	full := make([]byte, p2p.BlockChunkBytes)
	start := p2p.BlockChunk{ID: id, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk()

	for i := 0; i < p2p.MaxPartialTransfers; i++ {
		addr := string(rune('a'+i%26)) + string(rune('a'+i/26)) + ":1"
		handshake(t, n, addr)
		if v := n.engine.Handle(addr, p2p.KindBlock, start); v.Err != nil {
			t.Fatalf("transfer %d refused with the table below its bound: %v", i, v.Err)
		}
	}
	handshake(t, n, "zz:1")
	v := n.engine.Handle("zz:1", p2p.KindBlock, start)
	if v.Err == nil {
		t.Fatal("the partial-transfer table grew past its bound")
	}
	if v.Score < 0 {
		t.Fatal("a peer was scored down for this node's full table")
	}
}
