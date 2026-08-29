package p2p_test

import (
	"testing"
	"time"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/mempool"
	"zycord/node/p2p"
	"zycord/spec"
	"zycord/wallet"
)

// elasticAt presents spec.Devnet() at a sequential target k times its genesis
// value, by scaling every quantity that scales with T together.
//
// **This is a chain state, not a parameter change.** `BlockByteLimit(t)` and
// `MaxCertsPerBlock(t)` are `genesis × t / SeqGasTargetGenesis` and
// `SeqGasBurst(t)` is `4t`, so the ceilings a node reads at T = k·T₀ are
// exactly the genesis values of this copy. Nothing here invents headroom the
// elastic ceiling does not reach on its own under sustained demand.
//
// **k = 3 rather than the crossing, and the reason is this harness and not the
// protocol.** A block crosses `BlockChunkBytes` at T = 4,194,304 / 2,500,000 =
// **1.678·T₀** on all three shipped networks, where the count ceiling admits
// 429 certificates — so the crossing needs an average certificate of 9,776
// bytes. The widest shape this file builds is a 32-move transfer at **7,823
// bytes**, which is the *first* of the three figures `PROTOCOL.md` rule 21
// records for "the widest Era-0 certificate" and is **48.8% short** of the
// 15,277 bytes of body that story ends on. That endpoint is not a fourth
// search result: it is derived from `max_reads`, `max_writes`,
// `max_sigs` and the encoding (`era0CertByteCeiling`) and attained by a
// certificate sim builds, so it moves with the parameters instead of waiting
// to be falsified. A maximal-width certificate reaches one chunk at the
// crossing; this one needs 544, and 544 needs the count ceiling of 3·T₀.
func elasticAt(k uint64) *params.Params {
	p := *spec.Devnet()
	p.SeqGasTargetGenesis *= k
	p.BlockByteLimitGenesis *= int(k)
	if p.BlockByteLimitGenesis > p.BlockByteCapacity {
		p.BlockByteLimitGenesis = p.BlockByteCapacity
	}
	p.MaxCertsPerBlockGenesis *= int(k)
	// And the signature ceiling with them. MaxSigsPerBlock(T) scales by
	// T/seq_gas_target_genesis exactly as the count ceiling does, so scaling
	// the target alone leaves B18 pinned at its genesis value while every
	// other ceiling triples -- and this harness's 544 single-signature
	// certificates would be refused by B18 rather than reaching the transport
	// property the file is about. Widening every block ceiling by the same k is
	// what "elastic at k" means; leaving one behind would make the fixture a
	// measurement of that one.
	p.MaxSigsPerBlockGenesis *= int(k)
	return &p
}

// fatValidBlock mines a block whose encoding crosses BlockChunkBytes and which
// is **valid**: every certificate signed, funded, and applied by the fold.
//
// It returns the miner, a second node on the identical prefix, the block, and
// its wire bytes. The two chains are byte-identical up to the fork point
// because newNode mines deterministically from a fixed seed and clock.
func fatValidBlock(t *testing.T) (*testNode, *testNode, *types.Block, []byte) {
	t.Helper()
	p := elasticAt(3)
	signer := key(t, 42)
	payout := signer.Persistent()

	const prefix = 24 // past coinbase_maturity, so the payout is spendable
	// **The pool policy is widened, and it is node policy rather than
	// consensus.** `MaxPerUnderwriter` is 64 by default so that one funded key
	// cannot fill a pool; `docs/adversarial/mempool.md` §4 and the constant's
	// own comment say these are local and "nodes may differ without forking
	// anything". Filling a block from one key is the harness's convenience, not
	// a property under test — the alternative is nine funded underwriters, which
	// changes nothing a receiver can observe about the block that comes out.
	pol := mempool.DefaultPolicy()
	pol.MaxPerUnderwriter = 4096
	a := newNodeWithPool(t, "a", p, payout, pol)
	b := newNodeWithPool(t, "b", p, payout, pol)
	a.mine(t, prefix)
	b.mine(t, prefix)
	if a.chain.Tip().ID() != b.chain.Tip().ID() {
		t.Fatal("setup: the two nodes did not mine the same prefix")
	}

	seqBase := a.chain.Snapshot().State.Get(types.SeqBaseFeeSlot())
	parBase := a.chain.Snapshot().State.Get(types.ParBaseFeeSlot())

	moves := func(salt uint64) []types.Move {
		out := make([]types.Move, 0, p.MaxMovesPerTransfer)
		for i := 0; i < p.MaxMovesPerTransfer; i++ {
			var dst types.Address
			dst[0] = crypto.AddrVersionPersistent
			dst[1] = byte(salt)
			dst[2] = byte(salt >> 8)
			dst[3] = byte(i)
			dst[4] = 0x7f
			out = append(out, types.Move{
				Asset: types.NativeAsset, Src: payout, Dst: dst, Amount: u256.FromUint64(1)})
		}
		return out
	}
	build := func(seq uint64) *types.Certificate {
		c, err := (&wallet.Builder{
			Params: p, Program: wallet.Transfer(moves(seq)...),
			Seq: seq, TTL: a.chain.Height() + 10,
			Deposit: wallet.SelfDeposit(payout, payout),
			FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 8),
			Signers: []*wallet.Key{signer},
		}).Build()
		if err != nil {
			t.Fatalf("building certificate %d: %v", seq, err)
		}
		return c
	}

	// Sized from one certificate rather than by re-marshalling a growing block.
	one := build(0)
	want := p2p.BlockChunkBytes/one.SizeBytes() + 8
	view := a.chain.Snapshot()
	if err := a.pool.Add(one, view.State, a.chain.Height()); err != nil {
		t.Fatalf("pooling certificate 0: %v", err)
	}
	for seq := uint64(1); seq < uint64(want); seq++ {
		if err := a.pool.Add(build(seq), view.State, a.chain.Height()); err != nil {
			t.Fatalf("pooling certificate %d: %v", seq, err)
		}
	}

	blk, _, err := a.miner.MineOne(1 << 30)
	if err != nil {
		t.Fatalf("mining the fat block: %v", err)
	}
	body := blk.MarshalSSZ()

	// Anti-vacuity, stated against the three ceilings this block has to be
	// inside and the one it has to be outside. A block that misses any of them
	// makes every assertion below a measurement of something else.
	tgt := p.SeqGasTargetGenesis
	if n := p2p.ChunkCount(len(body)); n < 2 {
		t.Fatalf("the mined block is %d bytes, %d chunk(s): it does not reach the "+
			"branch under test (byte ceiling %d, %d certificates of %d bytes)",
			len(body), n, p.BlockByteLimit(tgt), len(blk.Certs), one.SizeBytes())
	}
	if len(body) > p.BlockByteLimit(tgt) {
		t.Fatalf("the mined block is %d bytes against a byte ceiling of %d: B13 "+
			"refuses it and it is not a valid block", len(body), p.BlockByteLimit(tgt))
	}
	if len(blk.Certs) > p.MaxCertsPerBlock(tgt) {
		t.Fatalf("the mined block carries %d certificates against a ceiling of %d",
			len(blk.Certs), p.MaxCertsPerBlock(tgt))
	}
	t.Logf("valid multi-chunk block: %d bytes, %d chunks, %d certificates, "+
		"byte ceiling %d, count ceiling %d, burst %d",
		len(body), p2p.ChunkCount(len(body)), len(blk.Certs),
		p.BlockByteLimit(tgt), p.MaxCertsPerBlock(tgt), p.SeqGasBurst(tgt))
	return a, b, blk, body
}

// TestAReassembledBodyNamesItsReplacementOnTheVerdictThatCarriesIt is the
// assertion that binds the propagation repair to the ingress path.
//
// **It exists because a competent mutation grid missed the wiring.** Six
// mutants killed `reframeAcceptedBody` and `forwardFrame` as *functions* —
// every one of them aimed at what a test calls directly. Deleting the
// **assignment** in `OnBlockChunk` left the whole package green, and with it
// the `pre-launch` defect live and nothing noticing. That is the same family as
// this unit's own finding one level down: an instrument that agrees with the
// truth everywhere the drivable regime reaches.
//
// The reason nobody had driven it is a claim this PR made and had to retract:
// that no parameter set can produce a block both larger than one chunk and
// valid. `ParGasLimit` is not a validity rule (`core/fold/blockrules.go` says
// so at its own call site), so the only byte rule in validity is B13's
// `BlockByteLimit`, which is clamped at `BlockByteCapacity` = 8,000,000 on all
// three shipped networks — above `BlockChunkBytes`. The crossing is at
// T = 1.678·T₀, inside the launch era, and `wire.md` §5.1 already said it:
// *"At the genesis byte capacity `n ≤ 2`."*
//
// EXPECTED DIRECTION, declared before the run (`PROTOCOL.md` rule 22): the
// completing chunk must produce a verdict with `Forward` set **and** a
// replacement naming this block. `Forward` without a replacement is the stall live;
// a replacement without `Forward` would mean the reframe had escaped the gate
// that keeps it past the fold.
func TestAReassembledBodyNamesItsReplacementOnTheVerdictThatCarriesIt(t *testing.T) {
	_, b, blk, body := fatValidBlock(t)

	total := uint32(p2p.ChunkCount(len(body)))
	var last p2p.Verdict
	for i := uint32(0); i < total; i++ {
		chunk := p2p.BlockChunk{ID: blk.Header.ID(), Chunk: i, Total: total,
			Data: p2p.ChunkOf(body, int(i))}
		last = b.engine.OnBlockChunk("a:1", chunk.MarshalBlockChunk())
		if i+1 < total && last.Reply == nil {
			t.Fatalf("chunk %d did not ask for its successor: %v", i, last.Err)
		}
	}

	if b.chain.Tip().ID() != blk.Header.ID() {
		t.Fatalf("the reassembled block was not applied (%v); every assertion below "+
			"would be about a refusal", last.Err)
	}
	if !last.Forward {
		t.Fatalf("an applied multi-chunk body was not marked for broadcast: %v", last.Err)
	}
	if last.ForwardAs == nil {
		t.Fatal("a body reassembled from more than one chunk was left to flood as the " +
			"frame that arrived; that frame is the LAST chunk, and a peer holding no " +
			"transfer under this id drops it unscored — the stall is live again")
	}
	if last.ForwardAs.Kind != p2p.KindBlockAnnounce {
		t.Fatalf("the replacement is %s rather than an announcement", last.ForwardAs.Kind)
	}
	ann, err := p2p.UnmarshalAnnounce(last.ForwardAs.Payload)
	if err != nil {
		t.Fatalf("the replacement does not decode as an announcement: %v", err)
	}
	if ann.Header.ID() != blk.Header.ID() {
		t.Fatal("the replacement announces a different block")
	}
}

// TestTheServeLoopFloodsTheAnnouncementAReassemblySets is the other half of the
// same wiring, read off the socket rather than off a verdict.
//
// A test that asserts on `Verdict.ForwardAs` says what the engine decided; it
// says nothing about whether `Node.serve` acts on it, and deleting that one
// consultation also left the package green. So this one reads what actually
// went to a peer.
//
// EXPECTED DIRECTION, declared before the run: the downstream connection must
// receive a `block-announce` naming this block. Receiving a `block` frame is
// the stall exactly — the last chunk of a transfer the downstream never opened.
func TestTheServeLoopFloodsTheAnnouncementAReassemblySets(t *testing.T) {
	_, relay, blk, body := fatValidBlock(t)
	if err := relay.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.node.Stop)

	// Two peers of the relay: one feeds it the transfer, the other only
	// listens for what the relay floods.
	open := func(name string) *p2p.Conn {
		t.Helper()
		id, err := p2p.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		c, err := id.Dial(relay.node.ListenAddr(), 10*time.Second)
		if err != nil {
			t.Fatalf("%s could not dial the relay: %v", name, err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if kind, _, err := c.Receive(); err != nil || kind != p2p.KindHello {
			t.Fatalf("setup: %s was refused by the relay: kind=%v err=%v", name, kind, err)
		}
		if err := c.Send(p2p.KindHello, relay.engine.Hello().MarshalHello()); err != nil {
			t.Fatalf("setup: %s could not complete the handshake: %v", name, err)
		}
		return c
	}
	listener := open("listener")
	feeder := open("feeder")

	total := uint32(p2p.ChunkCount(len(body)))
	for i := uint32(0); i < total; i++ {
		chunk := p2p.BlockChunk{ID: blk.Header.ID(), Chunk: i, Total: total,
			Data: p2p.ChunkOf(body, int(i))}
		if err := feeder.Send(p2p.KindBlock, chunk.MarshalBlockChunk()); err != nil {
			t.Fatalf("feeding chunk %d: %v", i, err)
		}
		if i+1 < total {
			// The relay asks for the successor before the next chunk is sent,
			// which is what keeps this a real transfer rather than a burst.
			feeder.SetReadDeadline(time.Now().Add(10 * time.Second))
			kind, _, err := feeder.Receive()
			if err != nil || kind != p2p.KindGetBlock {
				t.Fatalf("after chunk %d the relay asked for kind=%v (err=%v), want a "+
					"get-block for the successor", i, kind, err)
			}
		}
	}

	// Anti-vacuity: the relay has to have APPLIED the block, or what it floods
	// (or does not) is a fact about a refusal.
	deadline := time.Now().Add(15 * time.Second)
	for relay.chain.Tip().ID() != blk.Header.ID() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if relay.chain.Tip().ID() != blk.Header.ID() {
		t.Fatal("the relay did not apply the block it was fed, so nothing below is " +
			"about what it floods")
	}

	listener.SetReadDeadline(time.Now().Add(15 * time.Second))
	kind, payload, err := listener.Receive()
	if err != nil {
		t.Fatalf("the relay flooded nothing to a peer that did not send it the "+
			"block: %v; a multi-chunk body would stop at the first hop", err)
	}
	if kind != p2p.KindBlockAnnounce {
		t.Fatalf("the relay flooded %s to a peer holding no transfer under this id. "+
			"That is the stall: the frame is the last chunk of a transfer this peer never "+
			"opened, and wire.md §5.1 has it dropped unscored", kind)
	}
	ann, err := p2p.UnmarshalAnnounce(payload)
	if err != nil {
		t.Fatalf("the relay flooded an announcement no peer can decode: %v", err)
	}
	if ann.Header.ID() != blk.Header.ID() {
		t.Fatal("the relay announced a different block")
	}
}
