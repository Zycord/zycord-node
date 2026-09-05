package p2p

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// testEngine is a real Engine over a real chain on a temp dir — the least the
// internal tests in this package need to drive an ingress path.
func testEngine(t *testing.T) *Engine {
	t.Helper()
	return testEngineWith(t, spec.Devnet())
}

// testEngineWith is testEngine over a caller-supplied parameter set, so a test
// can drive the ingress path at a capacity other than the one committed today.
func testEngineWith(t *testing.T, p *params.Params) *Engine {
	t.Helper()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, pow.Dev{}, "n:1")
}

// TestReassemblyBufferHoldsExactlyTheBytesSent inspects the partial-transfer
// buffer directly, because the external differential in chunk_test.go can only
// compare failure shapes: two garbage bodies fail UnmarshalBlock alike, so a
// reassembly that scrambled chunk order could still pass it. This test is the
// fidelity check proper — after each chunk, the buffer must equal the exact
// prefix sent so far, byte for byte.
func TestReassemblyBufferHoldsExactlyTheBytesSent(t *testing.T) {
	e := testEngine(t)

	// Two chunks, the second short: the largest multi-chunk transfer the
	// consensus byte capacity admits at the current constants.
	body := make([]byte, BlockChunkBytes+805_696)
	for i := range body {
		body[i] = byte(i*131 + i>>9)
	}
	var id types.Hash
	id[0] = 6

	total := uint32(ChunkCount(len(body)))
	for i := uint32(0); i+1 < total; i++ {
		chunk := BlockChunk{ID: id, Chunk: i, Total: total, Data: ChunkOf(body, int(i))}
		if v := e.OnBlockChunk("peer:1", chunk.MarshalBlockChunk()); v.Err != nil {
			t.Fatalf("chunk %d refused: %v", i, v.Err)
		}
		partial := e.partial["peer:1"][id]
		if partial == nil {
			t.Fatalf("no transfer in flight after chunk %d", i)
		}
		want := body[:int(i+1)*BlockChunkBytes]
		if !bytes.Equal(partial.buf, want) {
			t.Fatalf("after chunk %d the buffer holds %d bytes that are not the prefix sent", i, len(partial.buf))
		}
	}

	// The final chunk completes the transfer: the buffer must be gone whatever
	// OnBlock made of the bytes.
	last := BlockChunk{ID: id, Chunk: total - 1, Total: total, Data: ChunkOf(body, int(total-1))}
	e.OnBlockChunk("peer:1", last.MarshalBlockChunk())
	if e.partial["peer:1"] != nil {
		t.Fatal("a completed transfer left its buffer behind")
	}
}

// TestReassemblyMemoryIsBounded pins the bound that actually is memory.
//
// The count bounds do not bound bytes, and treating them as if they did was
// the gap here: countImpliedBound, 48 connections × MaxTransfersPerPeer ×
// BlockByteCapacity, is about 1.54 GB, reachable by peers that send chunk 0
// and stop. (48 is maxConnections, MaxInbound + 2 × MaxOutbound — the
// connection-set bound Node.register enforces, the inbound gate being
// inbound-only; see the reassembly-bounds note in engine.go and magnitudes.go.
// It is not the honest steady state's 40, honestSteadyStateConns.) This asserts
// that the held total never passes MaxReassemblyBytes however many peers and
// transfers are in play, and that the refusal does not score — a saturated
// node is not the sender's fault.
func TestReassemblyMemoryIsBounded(t *testing.T) {
	e := testEngine(t)

	full := make([]byte, BlockChunkBytes)
	refused := false
	for peer := 0; peer < MaxPartialTransfers; peer++ {
		for tr := 0; tr < MaxTransfersPerPeer; tr++ {
			var id types.Hash
			id[0], id[1] = byte(peer), byte(tr)
			v := e.OnBlockChunk(fmt.Sprintf("peer:%d", peer),
				BlockChunk{ID: id, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
			if v.Err != nil {
				refused = true
				if v.Score < 0 {
					t.Fatalf("a peer was scored %d for this node's own saturation", v.Score)
				}
			}
			if e.partialBytes > MaxReassemblyBytes {
				t.Fatalf("held %d bytes against a budget of %d", e.partialBytes, MaxReassemblyBytes)
			}
		}
	}
	if !refused {
		t.Fatal("the budget was never reached; the bound was not exercised")
	}
}

// TestReassemblyByteAccountingMatchesTheBuffers is the mirror check for the
// counter itself.
//
// partialBytes is a running total maintained apart from the map it describes,
// so it can drift — and a drifted counter fails in the reassuring direction,
// under-reporting until the budget stops bounding anything. Rather than trust
// that every removal path decrements, this walks the map and compares.
func TestReassemblyByteAccountingMatchesTheBuffers(t *testing.T) {
	e := testEngine(t)
	full := make([]byte, BlockChunkBytes)
	short := make([]byte, 805_696)

	var a, b, c types.Hash
	a[0], b[0], c[0] = 1, 2, 3

	// Start three transfers across two peers, complete one, evict one by
	// disconnect, and drop one by mismatch — every removal path in the file.
	e.OnBlockChunk("p1:1", BlockChunk{ID: a, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
	e.OnBlockChunk("p1:1", BlockChunk{ID: b, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
	e.OnBlockChunk("p2:1", BlockChunk{ID: c, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
	assertByteAccounting(t, e, "after three starts")

	e.OnBlockChunk("p1:1", BlockChunk{ID: a, Chunk: 1, Total: 2, Data: short}.MarshalBlockChunk())
	assertByteAccounting(t, e, "after a completion")

	e.OnBlockChunk("p1:1", BlockChunk{ID: b, Chunk: 1, Total: 3, Data: full}.MarshalBlockChunk())
	assertByteAccounting(t, e, "after a mismatch drop")

	e.forgetPeer("p2:1")
	assertByteAccounting(t, e, "after a disconnect")
	if e.partialBytes != 0 {
		t.Fatalf("every transfer is gone but %d bytes are still counted", e.partialBytes)
	}
}

func assertByteAccounting(t *testing.T, e *Engine, when string) {
	t.Helper()
	held := 0
	for _, byID := range e.partial {
		for _, p := range byID {
			// cap and not len: the budget's subject is the memory the buffer
			// owns. The two are equal because growTransfer sizes every
			// write exactly, and this asserts that rather than assuming it, so
			// that a future append here is caught at every checkpoint any of
			// these tests already takes.
			if cap(p.buf) != len(p.buf) {
				t.Fatalf("%s: a reassembly buffer holds %d bytes in %d of capacity, which the budget cannot see", when, len(p.buf), cap(p.buf))
			}
			held += cap(p.buf)
		}
	}
	if held != e.partialBytes {
		t.Fatalf("%s: the buffers hold %d bytes and the counter says %d", when, held, e.partialBytes)
	}
}

// TestTheReassemblyBudgetCountsOwnedCapacityAndNotChunkLengths pins the
// property: what a reassembly buffer *retains* is its capacity, and a budget
// that counts the chunk lengths a sender delivered bounds only a fraction of
// that — a fraction the sender's chunking chooses, not one this node picks.
//
// The measurement is the point. The test replays the exact chunk sequence the
// wire admits (every chunk but the last is exactly BlockChunkBytes,
// UnmarshalBlockChunk enforces it) through both growth strategies and asserts
// that they differ: append leaves capacity the counter cannot see, growTransfer
// leaves none. Without the fix growTransfer *is* append and the second half
// fails.
func TestTheReassemblyBudgetCountsOwnedCapacityAndNotChunkLengths(t *testing.T) {
	full := make([]byte, BlockChunkBytes)

	// The slack is what makes this a real defect rather than a definition, so
	// it is measured here and not asserted from a table. Two chunks at the
	// wire's own chunk size is the honest shape, and the worst of the three
	// that were measured.
	var appended []byte
	appended = append(appended, full...)
	appended = append(appended, full...)
	slack := cap(appended) - len(appended)
	if slack <= 0 {
		t.Fatalf("this test's premise no longer holds on this toolchain: append over %d chunks of BlockChunkBytes returned len %d cap %d, so capacity and length no longer differ and the slack must be re-derived",
			2, len(appended), cap(appended))
	}
	t.Logf("append over two chunks of BlockChunkBytes: delivered %d, owned %d, uncounted %d (%.2f%%)",
		len(appended), cap(appended), slack, 100*float64(slack)/float64(cap(appended)))

	// The same sequence through growTransfer owns exactly what it was sent,
	// at every step and not only at the end — the budget is charged per chunk,
	// so a strategy that were exact only on completion would still under-count
	// every transfer in flight.
	var grown []byte
	counted := 0
	for i := 0; i < 4; i++ {
		owned := cap(grown)
		grown = growTransfer(grown, full)
		counted += cap(grown) - owned
		if cap(grown) != len(grown) {
			t.Fatalf("after chunk %d the buffer holds %d bytes in %d of capacity, so the budget counts %d of what it owns",
				i, len(grown), cap(grown), len(grown))
		}
		if counted != cap(grown) {
			t.Fatalf("after chunk %d the counter says %d and the buffer owns %d", i, counted, cap(grown))
		}
	}
}

// TestForgetPeerReleasesTransfers is the regression for the leak this design
// had before review.
//
// `partial` is keyed by connection address — ephemeral port included, so never
// reused — and forgetPeer is the only teardown a connection has. Cleaning
// `tips` and not `partial` meant a transfer interrupted by a disconnect was
// held for the life of the process, so MaxPartialTransfers connect / chunk-0 /
// disconnect cycles filled the table permanently and every multi-chunk
// transfer afterwards was refused, at no score to whoever did it.
func TestForgetPeerReleasesTransfers(t *testing.T) {
	e := testEngine(t)

	var id types.Hash
	id[0] = 1
	start := BlockChunk{ID: id, Chunk: 0, Total: 2, Data: make([]byte, BlockChunkBytes)}.MarshalBlockChunk()

	// Every cycle leaves a transfer in flight and disconnects. Without the
	// release the table fills and never drains.
	for i := 0; i < MaxPartialTransfers*2; i++ {
		conn := fmt.Sprintf("attacker:%d", 40000+i)
		if v := e.OnBlockChunk(conn, start); v.Err != nil {
			t.Fatalf("cycle %d: a fresh transfer was refused, so the table never drained: %v", i, v.Err)
		}
		e.forgetPeer(conn)
		if len(e.partial) != 0 {
			t.Fatalf("cycle %d left %d transfer(s) behind after teardown", i, len(e.partial))
		}
		if e.partialBytes != 0 {
			t.Fatalf("cycle %d released the transfer but left %d bytes on the budget", i, e.partialBytes)
		}
	}
}

// TestReleaseRelayFallsBackToAnAnnouncementPastOneChunk covers the branch that
// nothing else reaches.
//
// `relayReleased` sends a released block's *body*, because a peer whose clock
// has not yet reached the release point withholds a body and keeps nothing at
// all from an announcement. Past one chunk there is no body frame to send —
// `KindBlock` carries one `BlockChunk`, and the flood path cannot forward a
// multi-chunk transfer either — so the relay falls back to announcing, and the
// peer pays a round trip instead of getting nothing.
//
// No block at the *genesis* byte ceiling reaches it — `BlockChunkBytes` is 4 MiB
// against 2.5 MB — but it does not take an era re-pin either: `block_byte_capacity`
// is 8 MB in both committed parameter sets, and that is the ceiling the byte
// limit scales toward under ordinary demand. So it is a live branch that no
// other test enters, and replacing the fallback with a panic used to leave the
// whole suite green.
//
// It is also the one caller of `Released.Decode`, and therefore the only place
// one-representation rule still needs the block's structure rather than its bytes.
func TestReleaseRelayFallsBackToAnAnnouncementPastOneChunk(t *testing.T) {
	p := spec.Devnet()

	// A block whose encoding crosses BlockChunkBytes. Nothing here judges the
	// block's *contents* — the relay only measures and frames it — but it must
	// DECODE, because the fallback branch is the one that reads its structure.
	//
	// That is a real constraint and it was previously unmet: this test used to
	// build certificates carrying 8192 signatures against a `max_sigs` of 16,
	// and got away with it because the old `releaseRelay` took an
	// already-decoded `*types.Block` and never round-tripped the bytes. The
	// block it framed was therefore one no peer could ever have sent. Staying
	// inside the per-certificate list limits is what makes this a test of the
	// branch rather than of an impossible input.
	fat := &types.Block{Header: types.Header{Version: types.HeaderVersion, Height: 7}}
	for len(fat.MarshalSSZ()) <= BlockChunkBytes {
		sigs := make([]types.Sig, p.MaxSigs)
		for i := range sigs {
			// Sorted by public key with no duplicates, as the decoder requires.
			sigs[i].PubKey[0] = byte(i)
		}
		fat.Certs = append(fat.Certs, &types.Certificate{
			ChainID: 1, Seq: uint64(len(fat.Certs)),
			Program: types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{}},
			Sigs:    sigs,
		})
	}
	body := fat.MarshalSSZ()
	// The premise of the whole test: these bytes are ones a peer could have
	// delivered. Without this the fallback could be fed anything.
	if _, err := types.UnmarshalBlock(body, p); err != nil {
		t.Fatalf("the test block does not decode, so it is not a block any peer "+
			"could have sent and the branch is not being tested with one: %v", err)
	}
	if got := ChunkCount(len(body)); got < 2 {
		t.Fatalf("the test block is %d bytes, %d chunk(s): it does not reach the "+
			"branch under test", len(body), got)
	}

	kind, payload, err := releaseRelay(Released{ID: fat.Header.ID(), Raw: body}, p)
	if err != nil {
		t.Fatalf("framing a %d-chunk release failed: %v", ChunkCount(len(body)), err)
	}
	if kind != KindBlockAnnounce {
		t.Fatalf("a %d-chunk block was relayed as %s; KindBlock carries one chunk "+
			"of a body, so this frame names a transfer no peer is holding",
			ChunkCount(len(body)), kind)
	}
	ann, err := UnmarshalAnnounce(payload)
	if err != nil {
		t.Fatalf("the fallback produced an announcement a peer cannot decode: %v", err)
	}
	if ann.Header.ID() != fat.Header.ID() {
		t.Fatal("the fallback announced a different block")
	}

	// And the single-chunk block beside it still goes as a body, so the test
	// discriminates between the branches rather than only entering one.
	small := &types.Block{Header: types.Header{Version: types.HeaderVersion, Height: 8}}
	smallRaw := small.MarshalSSZ()
	kind, payload, err = releaseRelay(Released{ID: small.Header.ID(), Raw: smallRaw}, p)
	if err != nil {
		t.Fatalf("framing a one-chunk release failed: %v", err)
	}
	if kind != KindBlock {
		t.Fatalf("a one-chunk block was relayed as %s rather than as a body", kind)
	}
	c, err := UnmarshalBlockChunk(payload)
	if err != nil {
		t.Fatalf("the body frame does not decode as a chunk: %v", err)
	}
	if c.Total != 1 || c.Chunk != 0 || !bytes.Equal(c.Data, smallRaw) {
		t.Fatalf("the body frame is chunk %d of %d and does not carry the block",
			c.Chunk, c.Total)
	}
}

// TestRestartingATransferReleasesTheBudgetItReplaces pins the property that
// repeated chunk-0 restarts of one transfer do not shrink the budget.
//
// wire.md §5.1 makes the restart intentional — "a chunk 0 starts or restarts
// the transfer under its id" — so the discarded buffer is dropped by
// replacement rather than by any of the removal paths
// TestReassemblyByteAccountingMatchesTheBuffers enumerates. That is exactly
// what makes it a leak: partialBytes is repaid only in dropTransfer, and
// forgetPeer cannot repay a buffer that no longer exists, so every restart
// retired BlockChunkBytes of the global budget for the life of the process.
// Unscored and unexported, so neither the attacker nor the victim pays for it.
func TestRestartingATransferReleasesTheBudgetItReplaces(t *testing.T) {
	e := testEngine(t)

	full := make([]byte, BlockChunkBytes)
	var id types.Hash
	id[0] = 9
	start := BlockChunk{ID: id, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk()

	// Two past MaxReassemblyBytes/BlockChunkBytes: enough that with the leak
	// the counter reaches the budget and the later frames are refused, and no
	// more, because the invariant is re-checked every iteration and fails on
	// the first — further iterations buy churn, not coverage.
	for i := 0; i < MaxReassemblyBytes/BlockChunkBytes+2; i++ {
		if v := e.OnBlockChunk("attacker:1", start); v.Err != nil {
			t.Fatalf("restart %d was refused, so the budget had already been retired: %v", i, v.Err)
		}
		assertByteAccounting(t, e, fmt.Sprintf("after restart %d", i))
	}
	if e.partialBytes != BlockChunkBytes {
		t.Fatalf("one buffer is held but %d bytes are counted", e.partialBytes)
	}

	// And the budget the restarts borrowed comes back when the connection
	// goes, so an honest peer arriving afterwards is not refused.
	e.forgetPeer("attacker:1")
	if e.partialBytes != 0 {
		t.Fatalf("the attacker left but %d bytes are still counted", e.partialBytes)
	}
	var honest types.Hash
	honest[0] = 10
	if v := e.OnBlockChunk("honest:1",
		BlockChunk{ID: honest, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk()); v.Err != nil {
		t.Fatalf("an honest peer was refused after the attacker left: %v", v.Err)
	}
}

// TestConcurrentRestartsKeepTheByteAccountingExact drives the restart path the
// way production reaches it: OnBlockChunk is called from every connection's
// serve loop at once, so the whole safety case for the restart's transient
// state — the peer's entry momentarily absent from e.partial, the re-read of
// byID — rests on e.mu covering it. That was reasoned twice and never driven.
// A lost update or a missed re-read shows up here as counter drift with no
// detector needed, which is what makes this worth running: -race is
// unavailable in this environment (the toolchain requires cgo for it), so
// plain concurrency and the invariant are the whole instrument.
//
// Both shapes are in play: several goroutines restarting the *same* id under
// one peer, which is the contended path, and goroutines on distinct ids and
// peers, which is the one that exercises the map create/delete churn.
func TestConcurrentRestartsKeepTheByteAccountingExact(t *testing.T) {
	e := testEngine(t)
	full := make([]byte, BlockChunkBytes)

	const goroutines, rounds = 8, 16
	var shared types.Hash
	shared[0] = 11

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var own types.Hash
			own[0], own[1] = 12, byte(g)
			for r := 0; r < rounds; r++ {
				// Contended: one id, one peer, every goroutine restarting it.
				e.OnBlockChunk("attacker:1",
					BlockChunk{ID: shared, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
				// Uncontended: this goroutine's own peer and id, so the peer
				// map is created and deleted around the restarts as well.
				e.OnBlockChunk(fmt.Sprintf("attacker:%d", 40000+g),
					BlockChunk{ID: own, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk())
			}
		}(g)
	}
	wg.Wait()

	e.mu.Lock()
	assertByteAccounting(t, e, "after concurrent restarts")
	// The invariant alone would hold vacuously if a future regression refused
	// every frame: nothing held, nothing counted, test green. The live total
	// is deterministic whatever order the restarts interleaved in — one shared
	// transfer plus one per goroutine, each holding exactly chunk 0 — so pin
	// it, and the counter has to have been non-zero for this to pass.
	if want := (goroutines + 1) * BlockChunkBytes; e.partialBytes != want {
		t.Fatalf("the restarts should leave %d bytes in flight and the counter says %d", want, e.partialBytes)
	}
	e.mu.Unlock()

	e.forgetPeer("attacker:1")
	for g := 0; g < goroutines; g++ {
		e.forgetPeer(fmt.Sprintf("attacker:%d", 40000+g))
	}
	if e.partialBytes != 0 {
		t.Fatalf("every connection is gone but %d bytes are still counted", e.partialBytes)
	}
}

// TestForgettingAPeerReleasesEveryTransferItHolds pins the property that a
// disconnect repays the budget for *all* of a peer's buffers, not just one.
//
// dropPeerTransfers used to subtract the bytes itself in a single pass; it now
// calls dropTransfer per id, and dropTransfer deletes the peer's map from
// e.partial the moment that map empties — a delete of the enclosing entry
// while the inner map is being ranged over. Every existing disconnect test
// tore down a peer holding exactly one transfer, where a loop that stops after
// the first id is indistinguishable from a correct one. This holds
// MaxTransfersPerPeer at once, so an implementation that visits fewer than all
// of them leaves bytes on the budget and fails here (review finding).
func TestForgettingAPeerReleasesEveryTransferItHolds(t *testing.T) {
	e := testEngine(t)
	full := make([]byte, BlockChunkBytes)

	for i := 0; i < MaxTransfersPerPeer; i++ {
		var id types.Hash
		id[0], id[1] = 13, byte(i)
		if v := e.OnBlockChunk("p1:1",
			BlockChunk{ID: id, Chunk: 0, Total: 2, Data: full}.MarshalBlockChunk()); v.Err != nil {
			t.Fatalf("transfer %d was refused: %v", i, v.Err)
		}
	}
	if want := MaxTransfersPerPeer * BlockChunkBytes; e.partialBytes != want {
		t.Fatalf("the peer holds %d transfers but %d bytes are counted, not %d",
			MaxTransfersPerPeer, e.partialBytes, want)
	}

	e.forgetPeer("p1:1")
	if e.partialBytes != 0 {
		t.Fatalf("the peer left holding %d transfers but %d bytes are still counted",
			MaxTransfersPerPeer, e.partialBytes)
	}
	if len(e.partial) != 0 {
		t.Fatalf("the peer left but %d entries remain in the table", len(e.partial))
	}
}

// TestABudgetedTransferHeldAcrossChunksOwnsOnlyWhatItWasSent is the
// ingress-path detector for a reintroduced append.
//
// It exists because every other test in this file is structurally blind to the
// capacity slack. UnmarshalBlockChunk requires every chunk but the last to
// carry exactly BlockChunkBytes, and block_byte_capacity is 8,000,000 against a
// 4 MiB chunk, so a buffer that is *held* between chunks is always exactly one
// chunk -- where append happens to return cap == len. Reintroducing append
// therefore leaves every assertion that goes through OnBlockChunk green, and
// the only test that fails is the one calling growTransfer directly. That is a
// thin place for the fix to rest: a rewrite of this code that keeps
// growTransfer's signature but not its guarantee, or that stops routing through
// it, would be caught by nothing on the path a peer actually reaches.
//
// So this drives OnBlockChunk itself at the one parameter set where a held
// buffer is multi-chunk and the two growth strategies therefore differ on the
// ingress path. The claim is exactly that and no more: it is a mutation
// detector, NOT evidence that the defect is coming. Whether the slack ever
// becomes live is genuinely unsettled -- params.json says a block_byte_capacity re-pin
// arrives with "the accompanying node release raises the transport constants
// through the same test", and if BlockChunkBytes scales with the capacity then
// the one-chunk property survives the re-pin and the slack never arms at all. The
// fix stands on being correct by construction, not on that forecast.
//
// The fixture is still required to be a parameter set a release could legally
// ship -- params.Validate is called on it here rather than assumed -- because
// a detector built on an impossible input tests an impossible input.
func TestABudgetedTransferHeldAcrossChunksOwnsOnlyWhatItWasSent(t *testing.T) {
	// The re-pin: the ratio Validate enforces between the gas and byte
	// capacities is preserved, so this is a legal parameter set and not a
	// hand-edited one that could never exist.
	p := spec.Devnet()
	p.BlockByteCapacity = 10_000_000
	// 4x the 2,500,000 byte limit, which is the ratio the gas side has to match:
	// 4 x devnet's seq_gas_target_genesis of 1,600,000. The re-pin the fixture
	// models is on the BYTE capacity, and the gas capacity is the dependent half
	// Validate's cross-multiplication fixes.
	p.SeqGasCapacity = 6_400_000
	if err := p.Validate(); err != nil {
		t.Fatalf("the re-pinned fixture is not a legal parameter set, so this test would prove nothing about any release: %v", err)
	}
	if p.BlockByteCapacity < 2*BlockChunkBytes {
		t.Fatalf("the fixture does not admit a two-chunk held buffer (%d < %d), so it does not reach the defect",
			p.BlockByteCapacity, 2*BlockChunkBytes)
	}

	full := make([]byte, BlockChunkBytes)
	var id types.Hash
	id[0] = 13

	// The discriminator first: at the committed capacity the same two chunks
	// cannot be held, which is the whole reason the fixture exists. Without
	// this the test could silently become one that proves nothing the
	// committed parameters do not already prove.
	today := testEngine(t)
	today.OnBlockChunk("peer:1", BlockChunk{ID: id, Chunk: 0, Total: 3, Data: full}.MarshalBlockChunk())
	if v := today.OnBlockChunk("peer:1", BlockChunk{ID: id, Chunk: 1, Total: 3, Data: full}.MarshalBlockChunk()); v.Err == nil {
		t.Fatal("the committed parameters now hold a two-chunk buffer, so the capacity slack is live on the ingress path without a fixture and this test should be rewritten against spec.Devnet() directly")
	}

	e := testEngineWith(t, p)
	for i := uint32(0); i < 2; i++ {
		if v := e.OnBlockChunk("peer:1",
			BlockChunk{ID: id, Chunk: i, Total: 3, Data: full}.MarshalBlockChunk()); v.Err != nil {
			t.Fatalf("chunk %d was refused under the re-pinned capacity: %v", i, v.Err)
		}
		// Every chunk, not only the last: the budget is charged per chunk, so
		// a buffer that owned more than it was sent would be under-counted
		// while it waits for its successor -- which is the state the measured 57 MiB
		// at saturation is made of.
		assertByteAccounting(t, e, fmt.Sprintf("holding %d chunk(s) under the re-pinned capacity", i+1))
	}

	// Non-vacuity: the transfer really is held across two chunks, and the
	// counter really is at the two-chunk figure. With append the buffer would
	// own 10,248,192 of it and the counter would still say 8,388,608.
	held := e.partial["peer:1"][id]
	if held == nil {
		t.Fatal("no transfer is in flight, so the accounting assertion above held over nothing")
	}
	if want := 2 * BlockChunkBytes; len(held.buf) != want || e.partialBytes != want {
		t.Fatalf("the transfer should hold %d bytes and the counter say the same; got %d held and %d counted",
			want, len(held.buf), e.partialBytes)
	}

	e.forgetPeer("peer:1")
	if e.partialBytes != 0 {
		t.Fatalf("the peer left but %d bytes are still counted", e.partialBytes)
	}
}
