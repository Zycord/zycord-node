package p2p

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/storage"
	"zycord/spec"
)

// syncBuf is a Writer a test goroutine can read while serve's goroutine is
// still writing to it. log.Logger serialises its own writes, but the test's
// read of the accumulated bytes is a second reader and needs its own lock.
type syncBuf struct {
	mu  gosync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// mineChainWithPayout opens a fresh chain in dir and mines n blocks onto it,
// crediting payout — the only thing that differs between the two chains this
// test builds, and therefore the whole of the fork between them.
func mineChainWithPayout(t *testing.T, dir string, payout [32]byte, n int) (*chain.Chain, []*types.Block) {
	t.Helper()
	p := spec.Devnet()
	c, err := chain.Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{},
		Payout: payout,
		Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
	}
	var mined []*types.Block
	for i := 0; i < n; i++ {
		blk, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatal(err)
		}
		mined = append(mined, blk)
	}
	return c, mined
}

// TestALocalFaultOnTheGossipPathIsLogged pins the second, locality-keyed log
// predicate in serve.
//
// A gossip refusal caused by *this node's own* fault comes back as
// `Verdict{Cost: CostFree, Score: 0, Err: err}` — correct, because an innocent
// peer must not pay for our disk. But the only log gate serve had was the
// `v.Score <= ScoreProtocolViolation` drop, which is keyed on peer
// culpability, so the one class of error that is definitely this node's
// problem was the one class guaranteed to be silent. `LAUNCH.md` §3 case 4 is
// about exactly that shape of failure: a node that stops working and says
// nothing.
//
// The seam is a stored header this node can no longer decode. A block that
// forks below it makes fork choice read the canonical headers between the fork
// point and the tip (`workSince`), which hits the damaged record and returns
// `chain.ErrLocal`. Corrupting a *middle* header rather than the tip's is
// deliberate: the chain must still open, so that what is under test is the
// gossip path and not the startup path.
//
// The state is synthetic and is meant to be — every header record is written
// from a header this node already decoded, so a record this node wrote is
// decodable by construction. It is a seam for reaching the local-fault verdict
// on the gossip path, not a scenario a node reaches by its own writes.
//
// EXPECTED DIRECTION, declared before the run: the operator's log must name
// the fault, and the peer that delivered the block must NOT be dropped for it.
func TestALocalFaultOnTheGossipPathIsLogged(t *testing.T) {
	p := spec.Devnet()
	dirA, dirB := t.TempDir(), t.TempDir()

	// The node under test: three blocks, so the header at height 2 can be
	// damaged without touching the tip the chain reopens on.
	cA, _ := mineChainWithPayout(t, dirA, [32]byte{0x02, 1, 1, 1}, 3)
	victimID, ok := cA.CanonicalIDAt(2)
	if !ok {
		t.Fatal("setup: no canonical block at height 2")
	}
	if err := cA.Close(); err != nil {
		t.Fatal(err)
	}

	// A competing block at height 1, mined from the same genesis under a
	// different payout: valid, correctly targeted and timed, and forking below
	// the damaged header. Nothing about it is the sender's fault.
	cB, minedB := mineChainWithPayout(t, dirB, [32]byte{0x02, 2, 2, 2}, 1)
	fork := minedB[0]
	if err := cB.Close(); err != nil {
		t.Fatal(err)
	}
	body := fork.MarshalSSZ()
	if ChunkCount(len(body)) != 1 {
		t.Fatalf("setup: the fork block is %d chunks; this test feeds one frame", ChunkCount(len(body)))
	}

	// Replace the stored header record with bytes no decoder accepts, keeping
	// the key. The store is only reachable with the chain closed: it takes the
	// datadir lock.
	s, err := storage.Open(dirA, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	key := append([]byte("h/"), victimID[:]...)
	if _, held := s.Get(key); !held {
		t.Fatalf("no header stored for %x; the key encoding this test assumes has changed", victimID[:8])
	}
	var b storage.Batch
	b.Put(key, []byte("not a header"))
	if err := s.Commit(&b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	c, err := chain.Open(dirA, p)
	if err != nil {
		t.Fatalf("the chain no longer opens with a damaged mid-chain header: %v; "+
			"this test needs the fault to be reachable from the gossip path", err)
	}
	t.Cleanup(func() { c.Close() })

	// Anti-vacuity, part one: the seam bites, and it is attributed locally.
	if _, err := c.Header(victimID); !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("reading the damaged header gives %v, want chain.ErrLocal; "+
			"the seam this test is built on does not bite", err)
	}

	pool := mempool.New(p, mempool.DefaultPolicy())
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	chunk := BlockChunk{ID: fork.Header.ID(), Chunk: 0, Total: 1, Data: body}.MarshalBlockChunk()

	// Anti-vacuity, part two — and the whole reason this issue exists. The
	// verdict this frame produces must carry ErrLocal AND a score the old
	// predicate lets through, or serve's existing drop gate would have logged
	// it and the second predicate proves nothing. A separate engine, because
	// the one under test below must meet this frame for the first time.
	probe := NewEngine(c, pool, peers, pow.Dev{}, "n:2")
	if hv := probe.Handle("probe:1", KindHello, probe.Hello().MarshalHello()); hv.Err != nil {
		t.Fatalf("setup: the probe handshake was refused: %v", hv.Err)
	}
	v := probe.HandleFrom("probe:1", nil, KindBlock, chunk)
	if v.Err == nil || !errors.Is(v.Err, chain.ErrLocal) {
		t.Fatalf("the forking block gave verdict err %v, want one wrapping chain.ErrLocal; "+
			"the gossip path is not reaching the damaged record", v.Err)
	}
	if v.Score <= ScoreProtocolViolation {
		t.Fatalf("the local fault scored %d, at or below ScoreProtocolViolation (%d): the "+
			"pre-existing drop gate already logs this, so this test asserts nothing",
			v.Score, ScoreProtocolViolation)
	}

	// The real read loop, over a real socket.
	e := NewEngine(c, pool, peers, pow.Dev{}, "n:1")
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	n := NewNode(id, e, peers, 1)
	n.Logger = log.New(&out, "", 0)
	t.Cleanup(n.Stop)

	ours, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	const addr = "10.0.0.44:7009"
	go n.ServeForTest(ours, addr)

	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// serve greets first; read it or its write never completes.
	if _, _, err := ReadFrame(peer); err != nil {
		t.Fatalf("no hello from serve: %v", err)
	}
	if err := Frame(peer, KindHello, e.Hello().MarshalHello()); err != nil {
		t.Fatalf("writing the handshake: %v", err)
	}
	if err := Frame(peer, KindBlock, chunk); err != nil {
		t.Fatalf("writing the block chunk: %v", err)
	}

	// The frame is refused, so there is no reply to wait on. Settle instead,
	// long enough for serve to have read it and done whatever it was going to
	// do. Under the mutant nothing is ever written, so the wait only costs a
	// passing run.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "local fault") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	got := out.String()
	if !strings.Contains(got, "local fault") {
		t.Fatalf("serve logged %q for a refusal caused by this node's own damaged store. "+
			"The operator is told nothing: the only log gate on the gossip path is keyed on "+
			"the peer's culpability, and a local fault has none by construction", got)
	}
	if !strings.Contains(got, addr) {
		t.Fatalf("the local-fault log line %q does not name the connection it was handling; "+
			"an operator cannot act on it", got)
	}
	if strings.Contains(got, "dropping") {
		t.Fatalf("serve dropped the peer over this node's own fault: %q. The scoring decision "+
			"is deliberate and must not change — an innocent peer does not pay for our disk", got)
	}
	if peers.Banned(addr) {
		t.Fatal("the peer was banned for a fault of this node's own; logging must not " +
			"have widened into scoring")
	}
}
