package p2p

import (
	"bytes"
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/storage"
	"zycord/spec"
)

// TestServingABlockChunkCopiesStoredBytesRatherThanReEncodingThem pins the
// property: answering get-block must cost a copy of the stored record and
// nothing that scales with what the record decodes into.
//
// As with the header-range responder, the WORK cannot be told apart by the
// served bytes: for any block a node actually stored, decode-then-re-encode
// reproduces the stored encoding exactly, so before the fix and after it the
// chunk is byte-identical. Only the work differs — a full types.UnmarshalBlock,
// allocating a *types.Certificate per certificate, per chunk request.
//
// That byte-identity is itself a claim about the wire, so it is checked here
// rather than assumed: on the healthy chain, before anything is corrupted,
// BlockRaw's record is compared against blk.MarshalSSZ(). If those ever
// diverged, this would be a wire-format change wearing a performance fix's
// commit message.
//
// So the seam is a stored body record that is not decodable. A responder that
// copies the record answers; a responder that calls Chain.Block gets
// chain.ErrLocal from types.UnmarshalBlock and refuses. The anti-vacuity guard
// proves the seam bites by showing Chain.Block really does fail on this store,
// and the second half proves the responder is not simply answering everything:
// an id the store does not hold is still refused.
//
// The state is synthetic and is meant to be. Every write of a body record
// (node/chain/store.go commit and rollbackLocked's counterpart, and switchTo
// in node/chain/forkchoice.go) writes b.MarshalSSZ() of a block this node
// already decoded and folded, so a record this node wrote is decodable by
// construction. The corruption here is a seam for observing which operation
// the responder performs, not a scenario a node reaches by its own writes.
func TestServingABlockChunkCopiesStoredBytesRatherThanReEncodingThem(t *testing.T) {
	p := spec.Devnet()
	dir := t.TempDir()

	c, err := chain.Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{},
		Payout: [32]byte{0x02, 9, 9, 9},
		Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
	}
	blk, _, err := m.MineOne(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	id := blk.Header.ID()

	// The wire-format claim, checked directly rather than argued: the responder
	// replaces a re-encode with a copy of the stored record, so on a healthy
	// chain the bytes a peer reassembles must be exactly the bytes
	// MarshalSSZ produces. Anything else here is a wire-format change.
	encoded := blk.MarshalSSZ()
	raw, err := c.BlockRaw(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, encoded) {
		t.Fatalf("the stored record is %d bytes and MarshalSSZ produces %d; "+
			"BlockRaw's byte-identity contract does not hold and this changes the wire",
			len(raw), len(encoded))
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// Replace the stored record with bytes no decoder accepts, keeping the key.
	// The store is only reachable with the chain closed: it takes the datadir
	// lock. More than one chunk long, deliberately. A single-chunk record
	// cannot tell "serves the chunk that was asked for" apart from "always
	// serves chunk 0", and this change moved which byte string is being
	// indexed, so that correspondence is exactly what a regression here would
	// break.
	corrupt := make([]byte, BlockChunkBytes+1000)
	for i := range corrupt {
		corrupt[i] = byte(i*7 + 3)
	}
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	key := append([]byte("b/"), id[:]...)
	if _, ok := s.Get(key); !ok {
		t.Fatalf("no body stored for %x; the key encoding this test assumes has changed", id[:8])
	}
	var b storage.Batch
	b.Put(key, corrupt)
	if err := s.Commit(&b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	c, err = chain.Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	// Anti-vacuity: the seam must actually be able to fail the decoding path,
	// or the assertion below proves nothing about which operation was used.
	if _, err := c.Block(id); err == nil {
		t.Fatal("the corrupted record still decodes; the seam does not bite and this test asserts nothing")
	}

	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(c, pool, peers, pow.Dev{}, "n:1")

	v := e.OnGetBlock("p:1", GetBlock{ID: id, Chunk: 0}.MarshalGetBlock())
	if v.Err != nil {
		t.Fatalf("get-block refused a stored record: %v; "+
			"the responder is decoding the block to serve bytes it already has", v.Err)
	}
	if v.Reply == nil {
		t.Fatal("get-block produced no reply")
	}
	got, err := UnmarshalBlockChunk(v.Reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, corrupt[:BlockChunkBytes]) {
		t.Fatalf("served %d bytes that are not chunk 0 of the stored record", len(got.Data))
	}
	if got.Total != uint32(ChunkCount(len(corrupt))) {
		t.Fatalf("chunk count %d is not derived from the stored record's length", got.Total)
	}
	if got.Total < 2 {
		t.Fatal("the fixture record is one chunk long; the chunk-index assertion below asserts nothing")
	}

	// The served slice follows req.Chunk. Without this, serving chunk 0 for
	// every index passes every other assertion in this test.
	v = e.OnGetBlock("p:1", GetBlock{ID: id, Chunk: 1}.MarshalGetBlock())
	if v.Err != nil {
		t.Fatalf("get-block refused chunk 1 of a stored record: %v", v.Err)
	}
	tail, err := UnmarshalBlockChunk(v.Reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tail.Data, corrupt[BlockChunkBytes:]) {
		t.Fatalf("chunk 1 served %d bytes that are not the record's second chunk", len(tail.Data))
	}

	// Not-vacuous in the other direction: serving from the store must still be
	// a lookup, not an unconditional yes. An id the store does not hold is
	// refused, and so is a chunk index outside the record.
	var absent types.Hash
	absent[0] = 0xff
	if v := e.OnGetBlock("p:1", GetBlock{ID: absent, Chunk: 0}.MarshalGetBlock()); v.Err == nil {
		t.Fatal("get-block answered for an id the store does not hold")
	}
	v = e.OnGetBlock("p:1", GetBlock{ID: id, Chunk: uint32(ChunkCount(len(corrupt)))}.MarshalGetBlock())
	if v.Err == nil {
		t.Fatal("get-block answered for a chunk index past the end of the record")
	}
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("an out-of-range chunk request scored %d, not ScoreInvalidMessage", v.Score)
	}
}
