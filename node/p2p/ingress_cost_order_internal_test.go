package p2p

import (
	"testing"

	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// The measurement behind docs/spec/wire.md §10.1, driven through the engine's
// own entry points.
//
// §10.1 says an ingress pipeline orders its checks structural → dedup/window →
// read-only budget → signature or proof-of-work → any gate that mutates shared
// state, and it draws two consequences that are properties rather than advice:
// a message refused before step 4 has cost no work, and a message that has not
// reached step 4 has mutated nothing. Both are *orderings*, and an ordering is
// the thing a refactor changes silently while every unit test stays green —
// which is exactly how the cost-discipline programme accumulated fifteen instances.
//
// So this file measures rather than reads. Proof of work goes through
// pow.Engine, which is an interface, so the hash count is a real counter and
// not an inference (countingPoW, workcache_internal_test.go).
//
// Signature verification has no such counter: core/crypto is stdlib-only
// consensus code and a global counter does not belong in it. The ordering of
// the signature check is therefore pinned three other ways, and none of them is
// this file: TestSignatureWorkIsOrderedAfterTheCheapChecks in sim/wiring
// asserts it on engine.go's syntax tree,
// TestADuplicateCertificateIsAnsweredWithoutVerifyingItsSignature separates the
// dedup gate from the signature check by behaviour — a signature-mutilated
// twin carries the honest id, so the two orderings return different verdicts
// for it — and node/mempool's TestAnUnverifiedCertificateNeverEvicts pins the
// mutating half on the pool. Said here so that a reader of this file does not
// conclude the signature half is unguarded, and so that nobody adds a claim
// about Ed25519 to these test names that the assertions do not support.

// TestACheapRefusalBuysNoProofOfWork: a message refused for a structural
// reason, as a duplicate, or for being outside a window this node will
// consider, costs zero work evaluations.
//
// One separating input per (handler × refusal reason) rather than one input
// per handler. The three reasons are three different gates in three different
// places, and a pipeline can get any one of them right while getting the other
// two wrong — which is how the class stayed open: each finding was one gate in
// one handler, and the handler's other gates were fine.
func TestACheapRefusalBuysNoProofOfWork(t *testing.T) {
	e, work, blk := ingressFixture(t)
	const peer = "10.3.0.1:41000"

	// The accepted announcement and body come first: they are what make the
	// duplicate cases duplicates, and their cost is the anti-vacuity floor for
	// everything below. An announcement that cost nothing would make every
	// "zero" here meaningless.
	ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	before := work.count()
	if v := e.OnBlockAnnounce(peer, ann.MarshalAnnounce()); v.Err != nil {
		t.Fatalf("the honest announcement was refused: %v", v.Err)
	}
	if got := work.count() - before; got == 0 {
		t.Fatal("an accepted announcement cost no work evaluation; the counter " +
			"is measuring nothing and every zero below is vacuous")
	}
	if v := e.OnBlock(peer, blk.MarshalSSZ()); v.Err != nil {
		t.Fatalf("the honest body was refused: %v", v.Err)
	}

	// A header with a real block's shape and an unknown version: it decodes,
	// so the refusal is a structural *check* rather than a failed decode. The
	// two are different gates and a pipeline can pass one and fail the other.
	badVersion := ann
	badVersion.Header.Version = types.HeaderVersion + 1
	badVersion.Header.PoW.Nonce ^= 1 // a different id, so dedup cannot answer it

	// A header at height 0. This is the "outside a window this node will
	// consider" case for the announce path, and it is the sharpest one: at
	// height 0 pow.CheckWork returns nil unconditionally, so a node that
	// checked work here would not even find out it had been cheated.
	genesisHeight := ann
	genesisHeight.Header.Height = 0

	// A block chunk continuing a transfer this node is not holding. The
	// reassembly table is the budget, and the refusal is what keeps it one.
	orphanChunk := BlockChunk{ID: blk.Header.ID(), Chunk: 3, Total: 4, Data: []byte("payload")}

	cases := []struct {
		name string
		want CostClass
		run  func() Verdict
	}{
		{"announce/structurally-invalid: undecodable frame", CostScored, func() Verdict {
			return e.OnBlockAnnounce(peer, []byte{0x01, 0x02, 0x03})
		}},
		{"announce/structurally-invalid: unknown header version", CostScored, func() Verdict {
			return e.OnBlockAnnounce(peer, badVersion.MarshalAnnounce())
		}},
		{"announce/duplicate: an id already seen", CostDeduped, func() Verdict {
			return e.OnBlockAnnounce(peer, ann.MarshalAnnounce())
		}},
		{"announce/out-of-window: height 0 is never announced", CostScored, func() Verdict {
			return e.OnBlockAnnounce(peer, genesisHeight.MarshalAnnounce())
		}},
		{"block/structurally-invalid: undecodable body", CostScored, func() Verdict {
			return e.OnBlock(peer, []byte{0xff, 0xff, 0xff, 0xff})
		}},
		{"block/duplicate: a body already delivered and vetted", CostDeduped, func() Verdict {
			return e.OnBlock(peer, blk.MarshalSSZ())
		}},
		{"chunk/structurally-invalid: undecodable chunk frame", CostScored, func() Verdict {
			return e.OnBlockChunk(peer, []byte{0x00})
		}},
		{"chunk/out-of-window: continues no transfer this node holds", CostBudgeted, func() Verdict {
			return e.OnBlockChunk(peer, orphanChunk.MarshalBlockChunk())
		}},
		{"certificate/structurally-invalid: undecodable certificate", CostScored, func() Verdict {
			return e.OnCertificate(peer, []byte{0x07, 0x07})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := work.count()
			v := tc.run()
			if v.Err == nil {
				t.Fatalf("expected a refusal, got an acceptance: %+v", v)
			}
			if got := work.count() - before; got != 0 {
				t.Errorf("a cheap refusal cost %d proof-of-work evaluations; "+
					"wire.md §10.1 orders structural, dedup and window checks "+
					"in front of work precisely so this is zero. At the "+
					"measured RandomX cost of ~55 ms each that is %.0f ms of "+
					"CPU bought by one frame.", got, float64(got)*55)
			}
			if v.Cost != tc.want {
				t.Errorf("cost class %v, want %v (wire.md §10.3)", v.Cost, tc.want)
			}
		})
	}
}

// TestAnAnnouncementThatFailsItsWorkCheckMutatesNothing: the second consequence
// of §10.1 — a structurally-valid but unauthenticated message buys no write.
//
// The amendment to that programme is what this pins. Run its original
// ordering literally and a budget gate that *mutates* lands in front of the
// authentication, and then an unauthenticated stranger gets a write for the
// price of one frame; the measurement on the mempool half was a forged
// certificate evicting ten honest residents. On the announce path the writes
// are seenBlocks and pending, and the damage from an early one is precise and
// permanent: an id entered into seenBlocks by a header carrying no work is an
// id this node will never accept again, from anybody, because every honest
// re-announcement of the real block is deduped against it. That is censorship
// of a real block bought with a nonce.
func TestAnAnnouncementThatFailsItsWorkCheckMutatesNothing(t *testing.T) {
	e, work, blk := ingressFixture(t)
	const attacker = "10.3.0.9:41999"

	// The honest announcement, with the work broken and nothing else touched:
	// same height, same parent, same declared target, same certificate root.
	// Every check before the work check passes, so this input separates the
	// work gate from all of them.
	forged := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	forged.Header.PoW.Nonce ^= 1 << 30

	before := work.count()
	v := e.OnBlockAnnounce(attacker, forged.MarshalAnnounce())
	if v.Err == nil {
		t.Fatal("a header that does not satisfy its declared target was accepted")
	}
	if v.Score >= 0 {
		t.Fatalf("score %d: a header carrying no work is a claim about the "+
			"block, and wire.md §10.3 prices it Scored(invalid)", v.Score)
	}
	// **Zero, and that is the answer the commitment rule gives.**
	//
	// This assertion used to demand exactly one evaluation, on the reasoning
	// that "0 would mean this input never reached the gate it is here to
	// separate". That reasoning was correct under the old rule and is wrong
	// under this one: flipping a nonce bit changes the commitment, the
	// commitment misses the target, and pow.CheckWork answers from the header's
	// own bytes without calling the engine. The input DID reach the work gate;
	// the gate simply no longer costs a hash to answer.
	//
	// So the assertion is inverted rather than relaxed, and the anti-vacuity it
	// carried is preserved by the checks above and below: v.Err is non-nil and
	// v.Score is negative, so the header was judged and refused, and the state
	// assertions that follow say nothing was written. A test that merely
	// dropped the count would lose the claim; this one makes the stronger claim
	// the change earned.
	if got := work.count() - before; got != 0 {
		t.Fatalf("the forged announcement cost %d work evaluations, want 0: a "+
			"header whose commitment misses its declared target is refused from "+
			"its own bytes, and an evaluation here means the cheap rejection path "+
			"is not being taken", got)
	}

	e.mu.Lock()
	seen, pending, orphans, withheld := len(e.seenBlocks), len(e.pending), len(e.orphans), len(e.withheld)
	e.mu.Unlock()
	if seen != 0 || pending != 0 || orphans != 0 || withheld != 0 {
		t.Fatalf("an unauthenticated announcement wrote to shared state: "+
			"seenBlocks=%d pending=%d orphans=%d withheld=%d, want all zero "+
			"(wire.md §10.1)", seen, pending, orphans, withheld)
	}

	// And the consequence, stated as behaviour rather than as a map length: the
	// real block is still acceptable afterwards. A test that only counted the
	// maps would pass against a write to any other record with the same effect.
	honest := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := e.OnBlockAnnounce("10.3.0.2:41001", honest.MarshalAnnounce()); v.Err != nil {
		t.Fatalf("the honest announcement of the same block was refused after "+
			"the forgery: %v — the forgery poisoned the id", v.Err)
	}
}

// ingressFixture builds an engine on a real devnet chain, plus one honest
// sealed block on its tip, and the counting proof-of-work engine the
// measurements above are taken with.
func ingressFixture(t *testing.T) (*Engine, *countingPoW, *types.Block) {
	t.Helper()
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	work := &countingPoW{}
	e := NewEngine(c, pool, peers, work, "n:1")

	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: work,
		Payout: [32]byte{0x02, 4, 4, 4},
		Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
	}
	blk, err := m.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Seal(blk, 1<<20); err != nil {
		t.Fatal(err)
	}
	// Sealing is the only thing in this fixture that hashes, and it hashes a
	// lot; the counter is read relative to a baseline everywhere above, but
	// zeroing it here keeps a failure message honest about what it counted.
	work.mu.Lock()
	work.n = 0
	work.mu.Unlock()
	return e, work, blk
}
