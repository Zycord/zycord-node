package p2p

import (
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/spec"
)

// fatBody builds a block whose encoding crosses BlockChunkBytes and which
// DECODES, using the technique chunk_internal_test.go's multi-chunk test
// already established: certificates inside the per-certificate list limits,
// appended until the encoding is past one chunk.
//
// **No parameter set this repository ships can produce a block that is both
// larger than one chunk and VALID**, and that is the same fact the propagation
// stall is about rather than a shortcut here: block_byte_limit_genesis is
// 2,500,000 against a BlockChunkBytes of 4,194,304 on all three networks, and
// the widest Era-0 certificate is a few kilobytes against a genesis certificate
// ceiling of 256. So the framing rule is pinned on bytes a peer could have sent
// — which is what releaseRelay and reframeAcceptedBody both operate on — and
// never on a block the fold would accept.
func fatBody(t *testing.T, p *params.Params) ([]byte, types.Hash) {
	t.Helper()
	fat := &types.Block{Header: types.Header{Version: types.HeaderVersion, Height: 7}}
	addCert := func() {
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
	// Sized from one certificate's marginal cost rather than re-marshalling the
	// whole growing block per certificate, which is quadratic and was measured
	// at eighteen seconds for one body.
	addCert()
	per := len(fat.MarshalSSZ())
	for len(fat.Certs)*per <= BlockChunkBytes {
		addCert()
	}
	for len(fat.MarshalSSZ()) <= BlockChunkBytes {
		addCert()
	}
	body := fat.MarshalSSZ()
	if _, err := types.UnmarshalBlock(body, p); err != nil {
		t.Fatalf("the fat block does not decode, so it is not bytes any peer could "+
			"have sent and the branch is not being driven with one: %v", err)
	}
	if got := ChunkCount(len(body)); got < 2 {
		t.Fatalf("the fat block is %d bytes, %d chunk(s): it does not reach the "+
			"branch under test", len(body), got)
	}
	return body, fat.Header.ID()
}

// TestAReassembledBodyIsFloodedAsAnAnnouncementAndASingleChunkOneIsNot.
//
// **The defect Option A introduced.** `Node.serve` re-sends the frame it
// received, and `OnBlockChunk` sets `Forward` only on the chunk that *completes*
// a transfer — so the single frame a completing node floods is the LAST chunk.
// A peer that never opened a transfer under that id refuses it as continuing
// nothing, unscored and silently (wire.md §5.1), so the block stops at the first
// hop. The announcement flood used to be what made every node open its own
// transfer, and Option A stopped it travelling past one hop.
//
// **The repair is Option A applied to the second half of the same path**: a node
// that has completed a transfer holds the body, which is exactly the condition
// §8 requires of a forwarder, so what it owes its peers at that instant is an
// announcement.
//
// # Why the branch is driven here and not on a mesh
//
// `reframeAcceptedBody` is a pure function of the reassembled bytes, so both of
// its branches are reachable with bytes a peer could have sent — which is the
// only kind of input the framing rule ever sees. What no test in this tree can
// build is a block that is both over one chunk and *valid*: no committed
// parameter set can produce one, which is the same fact that makes the stall
// unreachable at launch. `TestReleaseRelayFallsBackToAnAnnouncementPastOneChunk`
// has stood under that limit since it was written, and this test shares its
// technique deliberately rather than inventing a weaker one.
func TestAReassembledBodyIsFloodedAsAnAnnouncementAndASingleChunkOneIsNot(t *testing.T) {
	p := spec.Devnet()

	t.Run("a body past one chunk is reframed as an announcement", func(t *testing.T) {
		body, id := fatBody(t, p)
		out, ok := reframeAcceptedBody(id, body, p)
		if !ok {
			t.Fatal("a decodable body past one chunk could not be reframed at all; " +
				"false means discard, so the block would stop here")
		}
		if out == nil {
			t.Fatalf("a %d-byte body travelling as %d chunks was left to flood as the "+
				"frame that arrived; that frame is the LAST chunk, and a peer holding "+
				"no transfer under this id drops it unscored",
				len(body), ChunkCount(len(body)))
		}
		if out.Kind != KindBlockAnnounce {
			t.Fatalf("a %d-chunk body was reframed as %s", ChunkCount(len(body)), out.Kind)
		}
		ann, err := UnmarshalAnnounce(out.Payload)
		if err != nil {
			t.Fatalf("the reframe produced an announcement a peer cannot decode: %v", err)
		}
		if ann.Header.ID() != id {
			t.Fatal("the reframe announced a different block")
		}
	})

	t.Run("a single-chunk body still floods as the frame that arrived", func(t *testing.T) {
		small := &types.Block{Header: types.Header{Version: types.HeaderVersion, Height: 8}}
		raw := small.MarshalSSZ()
		if got := ChunkCount(len(raw)); got != 1 {
			t.Fatalf("the small block is %d chunks; this row discriminates nothing", got)
		}
		// Nil and not an equivalent frame: re-marshalling the body a node just
		// received would copy up to four mebibytes per block for no change, and
		// every block at every committed genesis parameter set is this row.
		if out, ok := reframeAcceptedBody(small.Header.ID(), raw, p); !ok || out != nil {
			t.Fatalf("a single-chunk body was reframed as %s; the frame that arrived "+
				"is already the whole body", out.Kind)
		}
	})

	t.Run("a reassembled body this node refused is never reframed", func(t *testing.T) {
		// The whole multi-chunk ingress path, driven for real: two chunks, the
		// second short, reassembled by OnBlockChunk and handed to OnBlock,
		// which refuses these bytes because they carry no work.
		//
		// **This is the gate rather than a detail.** reframeAcceptedBody
		// decodes the body and marshals an announcement, so reaching it on a
		// body this node refused would let a sender buy a decode and a marshal
		// of four mebibytes for the price of sending them — the asymmetric cost
		// shape refused on the announce path. The body used here DECODES, which
		// is what makes the assertion load-bearing: an undecodable one would
		// leave ForwardAs nil whether the gate existed or not.
		body, id := fatBody(t, p)
		c, e, _ := announceChain(t, 4)
		_ = c
		const attacker = "10.66.0.10:5000"
		total := uint32(ChunkCount(len(body)))
		var last Verdict
		for i := uint32(0); i < total; i++ {
			chunk := BlockChunk{ID: id, Chunk: i, Total: total, Data: ChunkOf(body, int(i))}
			last = e.OnBlockChunk(attacker, chunk.MarshalBlockChunk())
		}
		if last.Forward {
			t.Fatalf("the fat body was accepted; this row needs a refusal to say "+
				"anything: %v", last.Err)
		}
		if last.ForwardAs != nil {
			t.Fatalf("a body this node REFUSED was reframed as %s; the reframe stands "+
				"past OnBlock's accept precisely so that a sender cannot buy a "+
				"four-mebibyte decode and marshal with bytes nobody vouched for",
				last.ForwardAs.Kind)
		}
	})

	t.Run("the serve loop floods the replacement only when there is one", func(t *testing.T) {
		body, id := fatBody(t, p)
		arrived := BlockChunk{ID: id, Chunk: 1, Total: 2, Data: []byte("tail")}.MarshalBlockChunk()

		v := Verdict{Cost: CostScored, Forward: true}
		if k, pl := forwardFrame(v, KindBlock, arrived); k != KindBlock || len(pl) != len(arrived) {
			t.Fatalf("with no replacement the serve loop flooded %s/%d bytes rather "+
				"than the frame that arrived", k, len(pl))
		}
		v.ForwardAs, _ = reframeAcceptedBody(id, body, p)
		k, pl := forwardFrame(v, KindBlock, arrived)
		if k != KindBlockAnnounce {
			t.Fatalf("with a replacement named, the serve loop still flooded %s", k)
		}
		if ann, err := UnmarshalAnnounce(pl); err != nil || ann.Header.ID() != id {
			t.Fatalf("the serve loop flooded something other than the replacement: %v", err)
		}
	})
}

// TestTheAnnouncementAReassemblyEmitsIsOneItsSenderCanServe is the first of the
// two directions this repair was required to be measured against, and it is the
// one that would undo the ghost-flood fix if it came back the other way.
//
// **Declared before it runs: the announcement a node emits after applying a
// block MUST NOT put a charge on that node, because it holds the body and can
// answer the get-block it provokes.** If a charge lands, announce-on-completion
// has reintroduced exactly the mis-aimed `ScoreUnservedBody` that Option A
// removed, and the repair is worse than the defect.
//
// That is the whole difference between this announcement and the one §8 used to
// require. A relay forwarding an announcement had, by construction, not yet
// received the body — `pending` is written on the path that asks for it — so it
// could never answer. A node reframing a body it has just applied has the
// opposite property by the same construction: `reframeAcceptedBody` is reached
// only past `OnBlock`'s accept.
func TestTheAnnouncementAReassemblyEmitsIsOneItsSenderCanServe(t *testing.T) {
	ca, holder, _ := announceChain(t, 4)
	_, down, _ := announceChain(t, 4)
	const (
		holderAddr = "10.66.0.7:5000"
		downAddr   = "10.66.0.8:5000"
	)
	down.Peers.Adjust(holderAddr, ScoreCeiling)

	// One real block the holder has applied — the state a node is in at the
	// moment reframeAcceptedBody is called.
	extendChain(t, ca, ca.Params().TargetBlockSeconds)
	blk, err := ca.BlockAt(ca.Height())
	if err != nil {
		t.Fatal(err)
	}
	raw := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}.MarshalAnnounce()

	v := down.OnBlockAnnounce(holderAddr, raw)
	if v.Reply == nil || v.Score != ScoreUsefulMessage {
		t.Fatalf("the downstream did not accept the announcement (cost=%v score=%d): %v",
			v.Cost, v.Score, v.Err)
	}
	if v.Forward {
		t.Fatal("the downstream relayed the announcement; Option A is unchanged by " +
			"this repair — an announcement is still relayed only by a node that " +
			"holds the body, and this one has just asked for it")
	}

	// The holder answers, which is the fact the whole charge turns on.
	served := holder.OnGetBlock(downAddr, v.Reply.Payload)
	if served.Reply == nil {
		t.Fatalf("the node that emitted the announcement could not serve the body it "+
			"had just applied: %v; that is the property announce-on-completion rests "+
			"on and it has stopped holding", served.Err)
	}
	if d := down.OnBlockChunk(holderAddr, served.Reply.Payload); d.Err != nil {
		t.Fatalf("the downstream refused the body it asked for: %v", d.Err)
	}

	// And the window elapses with nothing owed.
	charged := down.ReapUnservedBodies(time.Now().Add(2 * PendingBodyTimeout))
	if len(charged) != 0 {
		t.Fatalf("the reaper charged %v after an announcement whose sender served the "+
			"body; announce-on-completion has reintroduced the mis-aimed charge that "+
			"landed on the last hop", charged)
	}
	if down.Peers.Banned(holderAddr) {
		t.Fatal("the node that announced a block it holds was banned by its downstream")
	}
	if n := len(down.PendingBodies()); n != 0 {
		t.Fatalf("%d pending entries survived a body that arrived", n)
	}
}

// TestAGhostFloodReachesNeitherForwardNorReframe is the second declared
// direction: that announce-on-completion cannot flood worse than the path it
// replaces.
//
// **Declared before it runs: a flood of ghost announcements MUST produce zero
// forwards and zero reframed forwards, and MUST still end with the announcer
// banned.** A ghost has no body, so it can never reach either.
//
// # What this test does NOT establish, stated because the first draft claimed it
//
// It does not pin the `v.Forward` gate in front of the reframe. The header here
// used to say it observed that branch because `reframeAcceptedBody` is the only
// producer of `ForwardAs` — which is an argument about the POSITIVE direction,
// and this test asserts the negative. `nil` is the value on every path that
// never reaches the branch at all, so a ghost flood agrees with "the gate
// holds" and with "there is no gate" alike. Driven: with the gate deleted this
// test still passed and still logged zero, because a ghost's chunk is refused
// by ErrNoSuchTransfer long before OnBlock — structurally, whatever the gate
// does. That is `PROTOCOL.md` rule 24 in its exact form, committed by the probe
// that quoted rule 24.
//
// The gate is pinned by the two rows that reach the branch with a body: the
// refused-body row above, which needs a body that DECODES so that only the gate
// can stop it, and TestAReassembledBodyNamesItsReplacementOnTheVerdictThat-
// CarriesIt, which reaches it with a body the fold accepted. This test is the
// weaker, cheaper statement it can actually make: the attacker's own traffic
// buys nothing on either ingress path.
func TestAGhostFloodReachesNeitherForwardNorReframe(t *testing.T) {
	cb, e, _ := announceChain(t, 4)
	const attacker = "10.66.0.9:5000"
	e.Peers.Adjust(attacker, ScoreCeiling)

	reframed, accepted, forwarded := 0, 0, 0
	const send = 40
	for i := 0; i < send && !e.Peers.Banned(attacker); i++ {
		ghost := unheldParentGhost(t, cb, uint64(i)+1)
		v := e.OnBlockAnnounce(attacker, BlockAnnounce{Header: ghost}.MarshalAnnounce())
		if v.Score != 0 {
			e.Peers.Adjust(attacker, v.Score)
		}
		if v.Reply != nil {
			accepted++
		}
		if v.Forward {
			forwarded++
		}
		if v.ForwardAs != nil {
			reframed++
		}
		// The body the ghost never sends, offered as the last chunk of a
		// transfer nobody opened. It is refused by ErrNoSuchTransfer, which is
		// structural and says nothing about the reframe — see this test's
		// header. What it does pin is that such a frame is neither forwarded
		// nor priced as anything but a budget refusal, which is wire.md §5.1.
		tail := BlockChunk{ID: ghost.ID(), Chunk: 1, Total: 2, Data: []byte("nothing")}
		w := e.OnBlockChunk(attacker, tail.MarshalBlockChunk())
		if w.Forward || w.ForwardAs != nil {
			t.Fatalf("a chunk continuing no transfer was propagated: %v", w.Err)
		}
		if w.Cost != CostBudgeted || w.Score != 0 {
			t.Fatalf("a chunk continuing no transfer was priced %v at score %d, "+
				"want budgeted and unscored (wire.md 5.1)", w.Cost, w.Score)
		}
		e.ReapUnservedBodies(time.Now().Add(2 * PendingBodyTimeout))
	}

	t.Logf("ghost flood: %d accepted announcements, %d forwarded, %d reframed forwards",
		accepted, forwarded, reframed)
	if accepted == 0 {
		t.Fatal("no ghost was accepted, so this flood exercises nothing")
	}
	if forwarded != 0 {
		t.Fatalf("a ghost flood produced %d forwards", forwarded)
	}
	if reframed != 0 {
		t.Fatalf("a ghost flood produced %d reframed forwards; the reframe is supposed "+
			"to be reachable only past a body this node accepted, and an attacker with "+
			"no body has just reached it", reframed)
	}
	if !e.Peers.Banned(attacker) {
		t.Fatal("the announcer was not banned; the unserved-body charge is still the " +
			"only terminator and this repair must not have touched it")
	}
}
