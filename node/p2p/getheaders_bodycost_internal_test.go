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

// TestServingAHeaderRangeNeverReadsABlockBody pins the property:
// answering get-headers must cost one header read per height and nothing that
// scales with what the bodies at those heights contain.
//
// The assertion is deliberately NOT on the served bytes. Before the fix and
// after it a healthy chain serves byte-identical headers — that is the whole
// reason the bug survived: the responses are equal, and only the work spent
// producing them differs. A test that compares responses, or that runs on the
// empty blocks most fixtures produce, passes while the bug is fully live.
//
// So this asserts on the primitive instead, and it does it structurally rather
// than by timing: every block BODY record is deleted from the store while
// every header record is left in place. A responder that reads headers answers
// in full; a responder that decodes a block per height (the old
// Chain.BlockAt loop) gets ErrNotFound at the first height and breaks out with
// an empty list. The anti-vacuity guard below proves the seam bites, by
// showing BlockAt really does fail on this store.
//
// Do not "simplify" this by leaving the bodies in place: with bodies present
// both implementations return the same headers and the test asserts nothing.
//
// The state it builds is synthetic and is meant to be. There are exactly two
// PRODUCTION sites that delete a block body, and neither can produce this
// state: switchTo (node/chain/forkchoice.go, which deliberately retains the
// loser's header) and rollbackLocked (node/chain/store.go). A third deletion
// exists at node/chain/depth_work_test.go:141 and is test-only. Both delete heightKey in the same
// batch group as the body record and drop c.height with it, so neither leaves
// a canonical height at or below the tip whose header resolves and whose body
// does not. The deletion here is a seam for observing which record the
// responder reads, not a scenario a node can reach.
func TestServingAHeaderRangeNeverReadsABlockBody(t *testing.T) {
	p := spec.Devnet()
	dir := t.TempDir()

	c, err := chain.Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{},
		Payout: [32]byte{0x02, 7, 7, 7},
		Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
	}
	const blocks = 6
	ids := make([]types.Hash, 0, blocks)
	want := make([]types.Header, 0, blocks+1)
	want = append(want, c.Tip()) // genesis, height 0
	for i := 0; i < blocks; i++ {
		blk, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, blk.Header.ID())
		want = append(want, blk.Header)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// Remove the bodies, keep the headers. The store is only reachable with
	// the chain closed: it takes the datadir lock.
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var b storage.Batch
	for _, id := range ids {
		key := append([]byte("b/"), id[:]...)
		if _, ok := s.Get(key); !ok {
			t.Fatalf("no body stored for %x; the key encoding this test assumes has changed", id[:8])
		}
		b.Delete(key)
	}
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

	// Anti-vacuity: the seam must actually be able to fail the body path, or
	// the test below proves nothing about which record was read.
	if _, err := c.BlockAt(1); err == nil {
		t.Fatal("a body survived the deletion; the seam does not bite and this test asserts nothing")
	}

	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(c, pool, peers, pow.Dev{}, "n:1")

	v := e.OnGetHeaders("p:1", GetHeaders{From: 0, Count: MaxHeadersPerResponse}.MarshalGetHeaders())
	if v.Err != nil {
		t.Fatalf("get-headers refused: %v", v.Err)
	}
	if v.Reply == nil {
		t.Fatal("get-headers produced no reply")
	}
	got, err := UnmarshalHeaders(v.Reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("served %d headers for a %d-height chain whose bodies are gone: "+
			"the responder is reading block bodies to answer a header request",
			len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].MarshalSSZ(), want[i].MarshalSSZ()) {
			t.Fatalf("header at height %d is not the canonical one", i)
		}
	}

	// The two stopping rules the old loop had must survive: a request that
	// starts past the tip answers with an empty list, not an error.
	v = e.OnGetHeaders("p:1", GetHeaders{From: uint64(blocks) + 5, Count: 8}.MarshalGetHeaders())
	if v.Err != nil {
		t.Fatalf("a request past the tip was refused: %v", v.Err)
	}
	past, err := UnmarshalHeaders(v.Reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(past) != 0 {
		t.Fatalf("a request starting past the tip served %d headers", len(past))
	}
}
