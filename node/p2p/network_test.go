package p2p_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/p2p"
	"zycord/node/storage"
	"zycord/spec"
	"zycord/wallet"
)

// The adversarial network harness (M2).
//
// Nodes are wired in process and messages are delivered by an explicit
// schedule. That is deliberately stronger than driving real sockets: a
// partition, a heal, an eclipse and a flood are all message schedules, and a
// test that controls the schedule deterministically reproduces from a seed
// where one that hopes the network cooperates does not.
//
// The transport is exercised separately in transport_test.go. Here the question
// is what the protocol *does*, not how the bytes arrive.

func key(t *testing.T, n byte) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

// deliver wraps a block body in the single-chunk envelope KindBlock carries on
// the wire. Every test block fits one chunk; multi-chunk transfers have their
// own tests.
func deliver(b *types.Block) []byte {
	return p2p.BlockChunk{ID: b.Header.ID(), Chunk: 0, Total: 1, Data: b.MarshalSSZ()}.MarshalBlockChunk()
}

// handshake completes the one handshake Handle requires from addr before it
// will dispatch anything else. It uses n's own network id, which is
// sufficient in a harness where the "peer" behind addr is synthetic and only
// the ordering gate — not the identity behind it — is what the test needs.
func handshake(t *testing.T, n *testNode, addr string) {
	t.Helper()
	// Asserted, not fired and forgotten. A helper that silently no-ops when
	// the hello is refused — a params change moving the network id, a second
	// hello on one address, a decode change — hands every test that calls it
	// back the exact vacuity it exists to remove, and does it invisibly. That
	// is the mirror shape CONTRIBUTING names: an instrument that inherits the
	// failure it was built to catch.
	v := n.engine.Handle(addr, p2p.KindHello, n.engine.Hello().MarshalHello())
	if v.Err != nil || v.Score != p2p.ScoreUsefulMessage {
		t.Fatalf("setup: the handshake for %s was refused (score %d): %v; every "+
			"later Handle call in this test would be refused by the gate rather "+
			"than judged", addr, v.Score, v.Err)
	}
}

// devnetEasy is the parameter set behind most of this file — the partition and
// heal tests, the gossip-healing walk, the orphan and forwarding tests.
//
// # What it cannot measure
//
// Raising MaxTarget to u256.Max does not only make work free. It also makes
// `pow.NextTarget` *return* u256.Max on these parameters, and that is the part
// the "work is free" reading hides: the difficulty rule's own answer and an
// R4-H1 ghost's declared target become the same number. Every rule of the form
// "the declared target must be the one the rule derives" — wire.md §9 rule 1,
// and §5 step 4 for the announce path — is therefore satisfied on this harness
// by a header that declares `max_target`, and is satisfied just as well if the
// check is deleted. **No test built on devnetEasy is evidence for or against a
// target-derivation rule, in either direction.** The rule holds vacuously here
// and its absence is equally invisible.
//
// Nothing is wrong: this is a stated limit, not a discovered failure. The two
// tests that do have to separate the honest target from the ghost's run on
// `spec.Devnet()` instead, and say so at their own headers —
// `TestTheHonestAnnouncementSurvivesTheTargetRederivation` and the second arm
// of `TestAGossipedBlockMustCarryRealWork`. A new test whose subject is a
// declared target belongs on devnet's real parameters for the same reason.
//
// The blind spot is pinned by
// `TestDevnetEasyCannotSeparateAnR4H1GhostFromTheRule` below, so that this
// paragraph cannot quietly go stale, and carried in `docs/DEFERRED.md`. The
// fuller remedy — a second easy parameter set that keeps max_target above
// genesis_target, so target derivation stays observable on the multi-node
// harness — is deliberately not taken here.
func devnetEasy() *params.Params {
	p := *spec.Devnet()
	// Work costs nothing here, so that only the rule under test can refuse a
	// block. Both target fields have to move together: with GenesisTarget at
	// Max and the ceiling left at the devnet value, NextTarget would clamp the
	// tip's target back below Max after the first retarget and the harness's
	// unsolved fake blocks would start failing CheckWork instead of reaching
	// the bound they are aimed at. Keep the two assignments adjacent — this
	// pair is the whole "work is free" setting.
	//
	// The result is deliberately not a parameter set Validate would accept,
	// and the relation it fails is max_target < 2^255 (the point at which
	// BlockWork collapses to one), not genesis_target <= max_target: the two
	// are equal here, so that second relation holds. Fine in a harness,
	// which is not a chain.
	p.GenesisTarget = u256.Max
	p.MaxTarget = u256.Max
	return &p
}

// TestDevnetEasyCannotSeparateAnR4H1GhostFromTheRule pins the limit devnetEasy's
// comment states, so that the statement is checked rather than merely asserted.
//
// It is a guard on the harness, not on production code, and it is written to
// fail in exactly one situation: someone changes devnetEasy so that the
// difficulty rule's answer is no longer the value an R4-H1 attacker declares.
// That is a good change — it is the fuller remedy — but it makes the
// paragraph above wrong and the `docs/DEFERRED.md` entry stale, and both have to
// move with it. Deleting this test to make such a change pass is the one
// response that loses the record.
//
// The second half is the anti-vacuity: on devnet's real parameters the same two
// values differ, so the first half is a property of these parameters and not of
// how the comparison is written.
func TestDevnetEasyCannotSeparateAnR4H1GhostFromTheRule(t *testing.T) {
	// u256.Max is what the R4-H1 adversary declares — the same constant the
	// forged header in TestAGossipedBlockMustCarryRealWork's second arm uses.
	const ghostIsMax = "the easiest target a header can declare"

	easy := devnetEasy()
	easyNode := newNode(t, "easy", easy, key(t, 1).Persistent())
	// Past the first retarget, so this is the rule's steady answer and not the
	// genesis target handed back for a window shorter than two headers.
	easyNode.mine(t, int(easy.DifficultyWindow)+2)
	easyRule := pow.NextTarget(
		easyNode.chain.RecentHeaders(int(easy.DifficultyWindow)+1), easy)
	if !easyRule.Eq(u256.Max) {
		t.Fatalf("on devnetEasy the difficulty rule now gives %s, not %s (%s). "+
			"That is the blind spot closing: target-derivation "+
			"rules have become observable on this harness. Update devnetEasy's "+
			"comment and the docs/DEFERRED.md entry rather than this test.",
			easyRule.String(), u256.Max.String(), ghostIsMax)
	}

	real := spec.Devnet()
	realNode := newNode(t, "real", real, key(t, 2).Persistent())
	realNode.mine(t, 3)
	realRule := pow.NextTarget(
		realNode.chain.RecentHeaders(int(real.DifficultyWindow)+1), real)
	if realRule.Eq(u256.Max) {
		t.Fatalf("on spec.Devnet() the difficulty rule also gives %s, so the "+
			"comparison above distinguishes nothing and the blind spot is not "+
			"devnetEasy's. Every target-derivation test in this package is "+
			"vacuous if this holds.", u256.Max.String())
	}
}

// testNode is a chain, a pool, a miner and a protocol engine.
type testNode struct {
	name   string
	p      *params.Params
	chain  *chain.Chain
	pool   *mempool.Pool
	miner  *miner.Miner
	engine *p2p.Engine
	peers  *p2p.PeerStore
	// node is the connection manager. The in-process harness drives the engine
	// directly, but peer *selection* lives on the node, so a test of the sync
	// rotation needs one even without sockets.
	node  *p2p.Node
	clock uint64
}

func newNode(t *testing.T, name string, p *params.Params, payout types.Address) *testNode {
	return newNodeWith(t, name, p, payout, storage.Options{})
}

// newNodeWith builds a node with explicit storage options, so a test can make
// the disk fail on purpose. A local fault is a different thing from a peer's
// misbehaviour and the difference has to be arm-able to be tested.
func newNodeWith(t *testing.T, name string, p *params.Params, payout types.Address,
	opts storage.Options) *testNode {
	return newNodeWithPoolAndStorage(t, name, p, payout, opts, mempool.DefaultPolicy())
}

// newNodeWithPool builds a node with an explicit mempool policy. The policy is
// local — `docs/adversarial/mempool.md` §4 says nodes may differ without
// forking anything — so a test that needs a block shape the default admission
// limits make awkward to assemble may widen it without changing what any
// receiver of that block can observe.
func newNodeWithPool(t *testing.T, name string, p *params.Params, payout types.Address,
	pol mempool.Policy) *testNode {
	return newNodeWithPoolAndStorage(t, name, p, payout, storage.Options{}, pol)
}

func newNodeWithPoolAndStorage(t *testing.T, name string, p *params.Params, payout types.Address,
	opts storage.Options, pol mempool.Policy) *testNode {
	t.Helper()
	c, err := chain.OpenWith(t.TempDir(), p, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	peers, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	n := &testNode{
		name: name, p: p, chain: c,
		pool:  mempool.New(p, pol),
		peers: peers,
		clock: p.GenesisTime,
	}
	n.miner = &miner.Miner{
		Chain: c, Pool: n.pool, Engine: pow.Dev{}, Payout: payout,
		// Advance, then never sit behind the chain this node is on. A node
		// that accepted blocks from a peer has a tip whose timestamps came
		// from that peer's clock, while its own counter only moves when it
		// mines — so an idle follower that starts mining is behind its own
		// tip, and the miner refuses to build there (miner.ErrTooEarly),
		// correctly and for the same reason a node started before genesis
		// refuses. A real node's wall clock does not fall behind a tip it
		// just accepted; the counter has to be told. Two call sites used to
		// bump `clock` by hand for exactly this; the floor generalises them.
		Now: func() uint64 {
			n.clock += p.TargetBlockSeconds
			if tip := c.Tip().Time; n.clock <= tip {
				n.clock = tip + p.TargetBlockSeconds
			}
			return n.clock
		},
	}
	n.engine = p2p.NewEngine(c, n.pool, peers, pow.Dev{}, name+":1")
	identity, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n.node = p2p.NewNode(identity, n.engine, peers, 1)
	return n
}

func (n *testNode) mine(t *testing.T, blocks int) []*types.Block {
	t.Helper()
	var out []*types.Block
	for i := 0; i < blocks; i++ {
		b, _, err := n.miner.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("%s mining: %v", n.name, err)
		}
		out = append(out, b)
	}
	return out
}

// network delivers messages between nodes, with a partition set the test
// controls.
type network struct {
	t         *testing.T
	nodes     map[string]*testNode
	partition map[string]int // node name -> partition id; same id can talk
}

func newNetwork(t *testing.T, nodes ...*testNode) *network {
	n := &network{t: t, nodes: map[string]*testNode{}, partition: map[string]int{}}
	for _, node := range nodes {
		n.nodes[node.name] = node
		n.partition[node.name] = 0
	}
	// Complete the handshake between every ordered pair, so the harness's
	// message schedule can drive Handle directly the way every helper below
	// does — by connection address, with no socket behind it — without each
	// one re-deriving the handshake-ordering gate.
	for _, a := range nodes {
		for _, b := range nodes {
			if a == b {
				continue
			}
			a.engine.Handle(b.name+":1", p2p.KindHello, b.engine.Hello().MarshalHello())
		}
	}
	return n
}

func (n *network) split(groups map[string]int) { n.partition = groups }

func (n *network) heal() {
	for name := range n.nodes {
		n.partition[name] = 0
	}
}

// announce delivers a block from one node to every reachable peer, following
// the hash-first path: announce, then serve the body on request.
func (n *network) announce(from *testNode, b *types.Block) {
	n.t.Helper()
	ann := p2p.BlockAnnounce{Header: b.Header, CertExemplars: b.CertExemplars()}
	payload := ann.MarshalAnnounce()

	for name, to := range n.nodes {
		if name == from.name || n.partition[name] != n.partition[from.name] {
			continue
		}
		v := to.engine.Handle(from.name+":1", p2p.KindBlockAnnounce, payload)
		if v.Reply == nil {
			continue // already known, or refused
		}
		// The receiver asked for the body; the announcer serves it.
		served := from.engine.Handle(name+":1", p2p.KindGetBlock, v.Reply.Payload)
		if served.Reply == nil {
			continue
		}
		to.engine.Handle(from.name+":1", p2p.KindBlock, served.Reply.Payload)
	}
}

// syncFrom replays every block a source holds into a target, in order. It is
// the sync path reduced to its essential: a node must re-derive state rather
// than trust it.
func (n *network) syncFrom(target, source *testNode) {
	n.t.Helper()
	for h := uint64(1); h <= source.chain.Height(); h++ {
		b, err := source.chain.BlockAt(h)
		if err != nil {
			n.t.Fatal(err)
		}
		target.engine.Handle(source.name+":1", p2p.KindBlock, deliver(b))
	}
}

// TestNetworkConvergesAfterPartition is the distributed extension of
// TestReorgBillsExactlyOnce: partition, mine both sides, heal, and every node
// must converge on one chain with one state root.
func TestNetworkConvergesAfterPartition(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	b := newNode(t, "b", p, key(t, 2).Persistent())
	net := newNetwork(t, a, b)

	// A shared prefix, so both sides agree on where they forked from.
	for _, blk := range a.mine(t, 3) {
		net.announce(a, blk)
	}
	if b.chain.Height() != 3 {
		t.Fatalf("setup: b is at height %d, want 3", b.chain.Height())
	}

	// Partition, and mine on both sides.
	net.split(map[string]int{"a": 1, "b": 2})
	aBlocks := a.mine(t, 2)
	bBlocks := b.mine(t, 4)
	for _, blk := range aBlocks {
		net.announce(a, blk)
	}
	for _, blk := range bBlocks {
		net.announce(b, blk)
	}
	if a.chain.Tip().ID() == b.chain.Tip().ID() {
		t.Fatal("setup: the partition did not produce two chains")
	}

	// Heal. The heavier chain must win everywhere.
	net.heal()
	net.syncFrom(a, b)
	net.syncFrom(b, a)

	if a.chain.Tip().ID() != b.chain.Tip().ID() {
		t.Fatalf("the network did not converge: a at %d, b at %d",
			a.chain.Height(), b.chain.Height())
	}
	if a.chain.StateRoot() != b.chain.StateRoot() {
		t.Fatal("the network converged on one chain but two states")
	}
	if !a.chain.TotalWork().Eq(b.chain.TotalWork()) {
		t.Fatal("converged nodes disagree about accumulated work")
	}
	// And it converged on the *heavier* side, not merely on one of them.
	if a.chain.Height() != 7 {
		t.Fatalf("converged at height %d, want 7 — the longer branch", a.chain.Height())
	}
}

// TestInvalidCertificatesAreNeverForwarded is M2-G3, and it is the property
// that makes relay cheap: a node needs zero consensus state to filter
// structurally invalid traffic, so a flood cannot amplify.
func TestInvalidCertificatesAreNeverForwarded(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, int(p.CoinbaseMaturity)+2)

	// Garbage, a truncated certificate, and a well-formed one with a broken
	// signature: three shapes an attacker actually sends.
	good := buildCert(t, a, key(t, 1), 0)
	corrupt := append([]byte(nil), good.MarshalSSZ()...)
	corrupt[len(corrupt)-1] ^= 0xff

	// The third case really is a corrupted signature, and it is worth saying
	// why the obvious reading is wrong. SSZ writes the fixed section first and
	// appends the variable-length fields after it in declaration order, and
	// Sigs is the last variable field of certLayout — so the final byte of any
	// certificate that carries a signature is the last byte of its last one,
	// never the fee bid's. (The qualifier is real: a zero-signature certificate
	// ends in Writes. It decodes, and dies at V1 rather than at the decoder, so
	// it is a shape that exists — it is just never a shape this test builds.)
	// The fee bid is fixed-size and sits in the fixed section, at bytes
	// [200, 328) of the 848 below. Measured on the corpus:
	// 848 bytes with its signature region at [752, 848), and flipping byte 847
	// leaves the id unmoved, moves the exemplar hash, and fails
	// `V2: signature 0 does not verify`.
	//
	// So since the id stopped covering the signatures this payload IS a
	// mutilated exemplar wearing the honest id, which is the collision the id
	// used to make impossible. It is covered here for the arrival order that
	// reaches validity.Check.
	// TestAMutilatedExemplarIsNotHeldAgainstTheAuthorization covers what this
	// one cannot see: that the honest exemplar is still accepted afterwards.
	cases := map[string][]byte{
		"garbage":       {1, 2, 3, 4},
		"truncated":     good.MarshalSSZ()[:20],
		"bad signature": corrupt,
	}
	handshake(t, a, "attacker:1")
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			before := a.engine.Forwarded
			v := a.engine.Handle("attacker:1", p2p.KindCertificate, payload)
			if v.Forward {
				t.Fatal("an invalid certificate was forwarded; a flood would amplify")
			}
			if v.Score >= 0 {
				t.Fatal("sending an invalid certificate cost the sender nothing")
			}
			if a.engine.Forwarded != before {
				t.Fatal("the forward counter moved for an invalid message")
			}
		})
	}

	// A valid one is forwarded, so the test is not passing by refusing
	// everything.
	handshake(t, a, "honest:1")
	if v := a.engine.Handle("honest:1", p2p.KindCertificate, good.MarshalSSZ()); !v.Forward {
		t.Fatalf("a valid certificate was not forwarded: %v", v.Err)
	}
}

// TestAMutilatedExemplarIsNotHeldAgainstTheAuthorization is the second
// obligation that moving signatures out of the certificate id's preimage
// creates (spec/wire.md §3.1): **relay treats exemplars, not ids.**
//
// Since the id covers the authorizing fields and not the signatures, an
// attacker in transit can mangle a signature and produce an invalid
// certificate carrying the *honest* id. If a node cached that id as invalid,
// as seen, or as pooled, one bad body would censor a valid payment on that
// node permanently — and it would cost the attacker one message.
//
// What the neighbouring test does not reach is the second half. Its "bad
// signature" case does collide with the honest id — the last byte of a
// certificate's encoding is a signature byte, not the fee bid's — but it stops
// at "not forwarded, and it cost the sender". It never asks the question that
// matters, which is whether the honest exemplar still gets through afterwards.
// That is the property one message would otherwise buy an attacker, and it is
// what this test exists for.
//
// Both arrival orders are exercised, because they are not the same test and
// only one of them was being run. Mutilated-first reaches validity.Check and is
// scored. Honest-first does not: OnCertificate deduplicates on the id before
// verifying anything, so the mutilated copy is answered "already known" and
// costs its sender nothing. That is deliberate and is argued at the dedupe
// itself — what MUST hold in both orders is that the authorization survives.
func TestAMutilatedExemplarIsNotHeldAgainstTheAuthorization(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, int(p.CoinbaseMaturity)+2)

	good := buildCert(t, a, key(t, 1), 0)

	mutilated := *good
	mutilated.Sigs = append([]types.Sig(nil), good.Sigs...)
	mutilated.Sigs[0].Sig[0] ^= 0xFF

	// The whole point of the fixture: same authorization, same id, and the
	// network must refuse these particular bytes.
	if mutilated.ID() != good.ID() {
		t.Fatal("mutilating a signature moved the id; this test is not about the id collision")
	}
	if mutilated.ExemplarHash() == good.ExemplarHash() {
		t.Fatal("mutilating a signature did not change the encoding")
	}

	handshake(t, a, "attacker:1")
	v := a.engine.Handle("attacker:1", p2p.KindCertificate, mutilated.MarshalSSZ())
	if v.Forward {
		t.Fatal("a certificate with a broken signature was forwarded")
	}
	if v.Score >= 0 {
		t.Fatal("sending a mutilated exemplar cost the sender nothing")
	}

	// And the honest exemplar of that same id must still get through. If this
	// fails, one message bought permanent censorship of a valid payment.
	handshake(t, a, "honest:1")
	if v := a.engine.Handle("honest:1", p2p.KindCertificate, good.MarshalSSZ()); !v.Forward {
		t.Fatalf("the honest exemplar was refused after a mutilated one arrived first: %v", v.Err)
	}

	// The other arrival order, which is the ordinary one on a live network: the
	// honest exemplar is already pooled when the mutilated copy arrives.
	//
	// It must still not be forwarded, and the authorization must still be
	// intact afterwards. It is NOT scored, and that is pinned here rather than
	// left to be discovered: the id is now a function of the body, so the
	// dedupe recognises this copy as an authorization the pool already holds
	// and returns before any signature is verified. Scoring it would mean
	// verifying before deduplicating, which is the validation-cost denial of
	// service the ordering exists to prevent. The attacker gains nothing by it
	// — replaying the honest bytes was always answered the same way at the same
	// cost — and the reasoning is written at node/p2p/engine.go's dedupe.
	handshake(t, a, "attacker:2")
	v = a.engine.Handle("attacker:2", p2p.KindCertificate, mutilated.MarshalSSZ())
	if v.Forward {
		t.Fatal("a mutilated exemplar of a pooled authorization was forwarded")
	}
	if v.Score != 0 {
		t.Fatalf("the dedupe path scored %d; if this is now deliberate, say so at "+
			"the dedupe and here, because it changes what a flood costs", v.Score)
	}
	if v := a.engine.Handle("honest:1", p2p.KindCertificate, good.MarshalSSZ()); v.Forward {
		t.Fatal("the honest exemplar was forwarded twice; the pool is not deduplicating")
	}
	// Has(id) would be tautological here — the mutilated copy returns at the
	// dedupe branch and never reaches Pool.Add, so the slot cannot be empty, and
	// the id is the one thing both exemplars share. Ask for the bytes.
	pooled, ok := a.pool.Get(good.ID())
	if !ok {
		t.Fatal("the honest exemplar left the pool")
	}
	if pooled.ExemplarHash() != good.ExemplarHash() {
		t.Fatal("the pool is holding the mutilated exemplar under the honest id")
	}
}

// TestFloodOfInvalidCertificatesBansTheSender: scoring has to actually
// disconnect, or it is bookkeeping.
func TestFloodOfInvalidCertificatesBansTheSender(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())

	handshake(t, a, "flooder:1")
	for i := 0; i < 20; i++ {
		a.engine.Handle("flooder:1", p2p.KindCertificate, []byte{byte(i), 9, 9, 9})
	}
	if !a.peers.Banned("flooder:1") {
		peer, _ := a.peers.Get("flooder:1")
		t.Fatalf("a flooder scored %d and was not banned", peer.Score)
	}
	// An honest peer is untouched by someone else's misbehaviour.
	if a.peers.Banned("honest:1") {
		t.Fatal("an honest peer was banned")
	}
}

// TestARepeatBlockBodyIsRejectedCheaply pins the body path's second half: OnBlock did
// not consult seenBlocks at all, so a block already vetted paid the same
// decode-and-hash cost on every re-arrival, amplified by 1 + len(Cites) per
// copy. Gossip produces exactly this: OnBlock's own success case re-forwards
// the raw KindBlock payload (Node.serve broadcasts whatever a Verdict marks
// Forward), so a well-connected mesh naturally delivers one body from more
// than one upstream.
//
// seenBlocks alone is the wrong test for this, and that is worth pinning
// directly: OnBlockAnnounce sets it at announce time, before any body has
// even been requested, so a naive "if seenBlocks[id], reject" at the top of
// OnBlock also matches the *first* legitimate delivery of an announced block
// and silently discards it — a correctness bug, not an optimisation, and
// exactly what an early version of this fix did. The first delivery below
// must be applied; only the second, identical one may be rejected cheaply.
func TestARepeatBlockBodyIsRejectedCheaply(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	src := newNode(t, "src", p, key(t, 2).Persistent())
	blk := src.mine(t, 1)[0]

	const addr = "10.9.9.30:1"
	handshake(t, victim, addr)
	ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, ann.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("setup: the announcement was not accepted: %v", v.Err)
	}

	// The first delivery must be applied, not silently discarded as "already
	// known" — the case a naive seenBlocks check gets wrong.
	first := victim.engine.Handle(addr, p2p.KindBlock, deliver(blk))
	if victim.chain.Height() != 1 {
		t.Fatalf("the first legitimate delivery of an announced block was not "+
			"applied (height %d)", victim.chain.Height())
	}
	if !first.Forward {
		t.Fatalf("the first delivery was not forwarded: %v", first.Err)
	}

	// A second, byte-identical delivery — what a flood-forwarding mesh
	// produces naturally — must be rejected cheaply and not re-forwarded.
	forwardedBefore := victim.engine.Forwarded
	second := victim.engine.Handle(addr, p2p.KindBlock, deliver(blk))
	if !errors.Is(second.Err, p2p.ErrNotUseful) {
		t.Fatalf("got %v, want ErrNotUseful for a repeat delivery", second.Err)
	}
	if second.Forward {
		t.Fatal("a repeat block body was forwarded again")
	}
	if second.Score != 0 {
		t.Fatalf("a repeat block body scored %d, want 0", second.Score)
	}
	if victim.engine.Forwarded != forwardedBefore {
		t.Fatal("the forward counter moved for a repeat delivery")
	}
}

// TestAnnouncementsAreCheckedBeforeBodiesAreFetched is R1-M3: ghost
// announcements must cost the announcer real work rather than costing every
// receiver a fetch.
func TestAnnouncementsAreCheckedBeforeBodiesAreFetched(t *testing.T) {
	p := *devnetEasy()
	// A target nothing can meet, so the announcement's work check fails.
	p.GenesisTarget = u256.One
	hard := &p

	a := newNode(t, "a", hard, key(t, 1).Persistent())

	ghost := types.Header{
		Version:      types.HeaderVersion,
		Height:       1,
		ParentID:     a.chain.Tip().ID(),
		Time:         hard.GenesisTime + 1,
		EmissionAddr: key(t, 2).Persistent(),
		Target:       u256.One,
	}
	blk := &types.Block{Header: ghost}
	blk.Header.CertRoot = blk.ComputeCertRoot(hard)
	ann := p2p.BlockAnnounce{Header: blk.Header}

	handshake(t, a, "ghost:1")
	v := a.engine.Handle("ghost:1", p2p.KindBlockAnnounce, ann.MarshalAnnounce())
	if v.Reply != nil {
		t.Fatal("a body was requested for an announcement whose work does not check out")
	}
	if v.Forward {
		t.Fatal("an unworked announcement was forwarded")
	}
	if v.Score >= 0 {
		t.Fatal("a ghost announcement cost the announcer nothing")
	}
	if len(a.engine.PendingBodies()) != 0 {
		t.Fatal("a ghost announcement left a pending body")
	}
}

// TestAnnouncementMustMatchItsCertificateRoot: an id list that does not produce
// the header's root describes a block that does not exist, and that is
// checkable from the announcement alone.
func TestAnnouncementMustMatchItsCertificateRoot(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	blocks := a.mine(t, 1)

	b := newNode(t, "b", p, key(t, 2).Persistent())
	ann := p2p.BlockAnnounce{
		Header:        blocks[0].Header,
		CertExemplars: []types.Hash{{1, 2, 3}}, // not what the header commits to
	}
	handshake(t, b, "liar:1")
	v := b.engine.Handle("liar:1", p2p.KindBlockAnnounce, ann.MarshalAnnounce())
	if v.Forward || v.Reply != nil {
		t.Fatal("an announcement inconsistent with its own header was accepted")
	}
	if v.Score >= 0 {
		t.Fatal("an inconsistent announcement cost its sender nothing")
	}
}

// TestWrongNetworkDisconnectsAtTheHandshake is M2-G6: devnet and mainnet must
// be structurally unable to exchange a block, not merely unlikely to accept
// one.
func TestWrongNetworkDisconnectsAtTheHandshake(t *testing.T) {
	devnet := devnetEasy()
	mainnet := spec.Mainnet()

	d := newNode(t, "devnet", devnet, key(t, 1).Persistent())
	m := newNode(t, "mainnet", mainnet, key(t, 2).Persistent())

	v := d.engine.Handle("mainnet:1", p2p.KindHello, m.engine.Hello().MarshalHello())
	if !errors.Is(v.Err, p2p.ErrWrongNetwork) {
		t.Fatalf("got %v, want a wrong-network refusal at the handshake", v.Err)
	}
	if v.Score >= 0 {
		t.Fatal("a cross-network handshake cost the peer nothing")
	}

	// And a parameter difference that is not the chain id is caught too — the
	// network id commits to every consensus parameter (R3-1).
	edited := *devnet
	edited.TTLMax = devnet.TTLMax + 1
	other := newNode(t, "edited", &edited, key(t, 3).Persistent())
	v = d.engine.Handle("edited:1", p2p.KindHello, other.engine.Hello().MarshalHello())
	if !errors.Is(v.Err, p2p.ErrWrongNetwork) {
		t.Fatalf("got %v, want a refusal: a node with different parameters is a different network", v.Err)
	}

	// A matching node is accepted, so the test is not passing by refusing all.
	same := newNode(t, "same", devnet, key(t, 4).Persistent())
	if v := d.engine.Handle("same:1", p2p.KindHello, same.engine.Hello().MarshalHello()); v.Err != nil {
		t.Fatalf("a node on the same network was refused: %v", v.Err)
	}
}

// TestNonHelloMessagesAreRefusedBeforeTheHandshake: Handle used to
// dispatch every kind from the first frame on a connection, so hello was
// optional for an attacker and, transitively, so was the network-id check
// wire.md §4 states as a MUST — get-headers, get-block and get-peers were
// served for free, and certificates, announcements and bodies were validated
// and forwarded for a peer whose network was never compared. Every kind but
// hello must now be refused, as a protocol violation, until this connection's
// handshake has completed.
func TestNonHelloMessagesAreRefusedBeforeTheHandshake(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, int(p.CoinbaseMaturity)+2)
	cert := buildCert(t, a, key(t, 1), 0)

	const addr = "10.9.9.9:1"
	cases := map[string]struct {
		kind    p2p.MessageKind
		payload []byte
	}{
		"certificate": {p2p.KindCertificate, cert.MarshalSSZ()},
		"get-headers": {p2p.KindGetHeaders, p2p.GetHeaders{From: 0, Count: 1}.MarshalGetHeaders()},
		"get-block":   {p2p.KindGetBlock, p2p.GetBlock{ID: types.Hash{1}, Chunk: 0}.MarshalGetBlock()},
		"get-peers":   {p2p.KindGetPeers, nil},
		"headers":     {p2p.KindHeaders, p2p.MarshalHeaders(nil)},
		"peers":       {p2p.KindPeers, p2p.MarshalPeers(nil)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v := a.engine.Handle(addr, c.kind, c.payload)
			if !errors.Is(v.Err, p2p.ErrHandshakeRequired) {
				t.Fatalf("got %v, want ErrHandshakeRequired", v.Err)
			}
			if v.Score != p2p.ScoreProtocolViolation {
				t.Fatalf("scored %d, want the protocol-violation penalty %d", v.Score, p2p.ScoreProtocolViolation)
			}
			if v.Reply != nil {
				t.Fatal("a pre-handshake request was served")
			}
			if v.Forward {
				t.Fatal("a pre-handshake message was forwarded")
			}
		})
	}

	// The same connection is served normally once it has handshaked, so the
	// test above is not passing by refusing every connection permanently.
	handshake(t, a, addr)
	req := p2p.GetHeaders{From: 0, Count: 1}.MarshalGetHeaders()
	if v := a.engine.Handle(addr, p2p.KindGetHeaders, req); v.Reply == nil {
		t.Fatalf("a get-headers request was refused after a valid handshake: %v", v.Err)
	}
}

// TestUnsolicitedHeadersScoreNothing pins the headers half of "a frame nothing
// validated earns no positive score".
//
// A `headers` frame reaching Handle is one no outstanding sync request
// claimed, and nothing here can establish that it answers one.
//
// The send side is unchanged by sync over a shared connection:
// connSource.Headers is still this node's only source of an outbound
// get-headers, on both transports, because connSource is constructed over each
// of them and is the sole caller of roundTrip(KindGetHeaders, ...). What
// changed is where the answer lands. Sync answers no longer arrive only on a
// dedicated connection — over a shared gossip connection they arrive on the
// socket Handle also reads — so what keeps them off Handle is
// deliverSyncResponse claiming them in serve first (wire.md §12), not the
// choice of socket. Handle is left the frames no outstanding request *did*
// claim — which includes a frame that could have answered one, when the waiter
// already holds an answer — and this test drives Handle directly with no
// attempt registered, the simplest such case. Before the fix it was never even
// decoded, and a 9-byte frame claiming zero headers bought ScoreUsefulMessage
// for free, repeatedly.
func TestUnsolicitedHeadersScoreNothing(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	const addr = "10.9.9.10:1"
	handshake(t, a, addr)

	// Malformed: still not decodable, and must be charged like any other
	// invalid message rather than waved through.
	if v := a.engine.Handle(addr, p2p.KindHeaders, []byte{1, 2, 3}); v.Score >= 0 {
		t.Fatalf("a malformed headers frame scored %d, want negative", v.Score)
	}

	// Well-formed but unsolicited: nothing on this connection asked for it, so
	// it earns no score in either direction.
	before := scoreOf(t, a, addr)
	v := a.engine.Handle(addr, p2p.KindHeaders, p2p.MarshalHeaders(nil))
	if v.Score != 0 {
		t.Fatalf("an unsolicited headers frame scored %d, want 0", v.Score)
	}
	if !errors.Is(v.Err, p2p.ErrUnsolicited) {
		t.Fatalf("got %v, want ErrUnsolicited", v.Err)
	}
	if after := scoreOf(t, a, addr); after != before {
		t.Fatalf("score moved from %d to %d for an unsolicited message", before, after)
	}
}

// TestUnsolicitedPeersScoreNothing pins the other half. This node does send
// KindGetPeers (Node.askForPeers), so a `peers` frame is no longer unsolicited
// by construction; the verdict is unchanged because wire.md §12 has no request
// ids, so a frame this node solicited is indistinguishable from one it did not
// and neither can be scored positively (wire.md §7). The addresses are still
// worth recording — they are cheap, and easy to discard later — but recording
// is not the same as scoring, and wire.md §10 reserves ScoreUsefulMessage for a
// message that is both new and valid, not merely well-formed.
func TestUnsolicitedPeersScoreNothing(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	const addr = "10.9.9.11:1"
	handshake(t, a, addr)

	before := scoreOf(t, a, addr)
	v := a.engine.Handle(addr, p2p.KindPeers, p2p.MarshalPeers([]string{"203.0.113.9:9420"}))
	if v.Score != 0 {
		t.Fatalf("an unsolicited peers frame scored %d, want 0", v.Score)
	}
	if !errors.Is(v.Err, p2p.ErrUnsolicited) {
		t.Fatalf("got %v, want ErrUnsolicited", v.Err)
	}
	if after := scoreOf(t, a, addr); after != before {
		t.Fatalf("score moved from %d to %d for an unsolicited message", before, after)
	}
	if _, ok := a.peers.Get("203.0.113.9:9420"); !ok {
		t.Fatal("an unsolicited but well-formed peer address was not recorded")
	}
}

// TestPeerSelectionIsAddressDiverse is M2-G4. An attacker with a thousand
// addresses in one hosting range must not fill every outbound slot: that is an
// eclipse, cheaply.
func TestPeerSelectionIsAddressDiverse(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// A Sybil range, plus a handful of genuinely distinct peers.
	for i := 0; i < 200; i++ {
		ps.Add(sybilAddr(i))
	}
	for _, a := range []string{"10.1.0.1:9000", "172.16.0.1:9000", "198.51.100.1:9000"} {
		ps.Add(a)
	}

	selected := ps.SelectDiverse(4, nil)
	if len(selected) != 4 {
		t.Fatalf("selected %d peers, want 4", len(selected))
	}
	groups := map[string]int{}
	for _, a := range selected {
		groups[p2p.AddressGroup(a)]++
	}
	for g, n := range groups {
		if n > 1 {
			t.Fatalf("%d of the selected peers are in group %s; one subnet fills the slots", n, g)
		}
	}
	if len(groups) != 4 {
		t.Fatalf("selection covered %d groups, want 4", len(groups))
	}
}

// junkAddr builds an invented but perfectly well-formed IPv4 dial target, each
// one in its own /16 diversity group, and each sorting ahead of the honest
// documentation ranges below on the lexicographic tie-break SelectDiverse's
// primary sort ends in.
//
// It is deliberately *not* the hostname the first version of this regression
// test used ("junk-host-N.invalid:1"). That version passed against a fix that
// only required Add's addresses to have an IP host, and the pass was an
// artefact of the test data: an attacker does not need a hostname to mint a
// diversity group, because any four bytes are a valid IPv4 address and 65,536
// of them are 65,536 distinct /16s. Measured against that fix, this junk —
// same count, same one frame, same 80-odd bytes — took 8 of 8 outbound slots
// where the hostname junk took none. What actually prices the attack is
// MaxPerSource, and this is the junk that shows it.
func junkAddr(i int) string {
	return "11." + itoa(i) + ".0.1:8333"
}

// TestJunkPeersFrameCannotDisplaceKnownHonestPeers reproduces the attack
// documented for the unbounded store and the diversity fallback: twenty
// invented addresses in one `peers` frame, against a victim that already knows
// three honest peers. Whether the victim asked for the frame is irrelevant to
// this defence and always was — wire.md §12 has no request ids, so nothing here
// could tell an answer from a volunteer, and what the store must survive is a
// frame arriving at all.
//
// Every one of the twenty is a syntactically perfect, IP-hosted dial target in
// its own /16, so address diversity has nothing to say about them and the
// store cannot tell them from honest gossip by looking at them. What separates
// them is that one connection told this node about all twenty, and
// MaxPerSource bounds what one teller may decide.
func TestJunkPeersFrameCannotDisplaceKnownHonestPeers(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	honest := []string{"203.0.113.9:8333", "198.51.100.9:8333", "192.0.2.9:8333"}
	for _, a := range honest {
		victim.peers.Add(a)
	}

	junk := make([]string, 20)
	for i := range junk {
		junk[i] = junkAddr(i)
	}
	// OnPeers directly, rather than through Handle: Handle also scores the
	// sender's own connection (Adjust(peerAddr, ...)), which would add the
	// attacker's own socket address to the store as a fourth honest-looking
	// entry and confuse the assertion below. OnPeers is exactly the surface
	// those two defences are about: what one `peers` payload does to the store.
	// ErrUnsolicited is the expected verdict, not a rejection: it records that
	// nothing here established the frame was asked for, which stays true even
	// now that this node asks, because there is no request id to establish it
	// with, and the addresses are still recorded. What must not happen is the
	// frame being refused outright — that would make this test pass for a
	// reason that has nothing to do with the defence it pins.
	if v := victim.engine.OnPeers("198.18.7.7:9421", p2p.MarshalPeers(junk)); v.Err != nil && !errors.Is(v.Err, p2p.ErrUnsolicited) {
		t.Fatalf("an unsolicited peers frame was rejected outright, which is not this defence: %v", v.Err)
	}
	if victim.peers.Len() == 0 {
		t.Fatal("the peers frame was not recorded at all, so this test would pass without any defence")
	}

	selected := victim.peers.SelectDialTargets(8, nil, nil)
	took := 0
	for _, a := range selected {
		for _, j := range junk {
			if a == j {
				took++
			}
		}
	}
	if took > p2p.MaxPerSource {
		t.Fatalf("one unsolicited peers frame took %d of 8 outbound slots, want at most %d (MaxPerSource); selected=%v",
			took, p2p.MaxPerSource, selected)
	}
	for _, h := range honest {
		want := false
		for _, a := range selected {
			if a == h {
				want = true
			}
		}
		if !want {
			t.Fatalf("known honest peer %s was displaced by junk from a single peers frame; selected=%v", h, selected)
		}
	}
}

// TestJunkPeersFrameCannotEclipseAColdNode is the harsher half of the same
// scenario: a node with no peers yet — freshly started, or just restarted
// — is exactly the state in which an eclipse is cheapest, and the
// demonstrated attack took all 8 outbound slots here.
//
// A cold node is also where the fallback pass fires, so this pins the decision
// recorded in SelectDiverse: the fallback relaxes the per-group bound and does
// *not* relax the per-source one, which means a cold node fed nothing but one
// peer's gossip comes away under-connected rather than eclipsed.
func TestJunkPeersFrameCannotEclipseAColdNode(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	junk := make([]string, 20)
	for i := range junk {
		junk[i] = junkAddr(i)
	}
	victim.engine.OnPeers("198.18.7.7:9421", p2p.MarshalPeers(junk))

	if selected := victim.peers.SelectDialTargets(8, nil, nil); len(selected) > p2p.MaxPerSource {
		t.Fatalf("a cold node got %d of 8 dial targets out of one unsolicited peers frame, want at most %d: %v",
			len(selected), p2p.MaxPerSource, selected)
	}
}

// TestPeerStoreStaysOpenToHonestAddressesWhenFloodedFull is the other half of
// the cap, and the failure an earlier revision of this change shipped.
//
// Capping the store at MaxPeers closes its unbounded growth. Refusing new
// addresses once it is full closes it by making the store unable to learn
// anything again: an attacker fills MaxPeers with well-formed, unproven,
// invented addresses, and from then on every honest address is refused —
// including the operator's own bootstrap list on the next start — because a
// never-contacted honest address is never *better* than a never-contacted junk
// one. The eclipse survives the fix that was supposed to end it, and survives
// a restart with it.
//
// What the store does instead is charge the eviction to the cohort that is
// over-represented, which under a flood is the flood.
func TestPeerStoreStaysOpenToHonestAddressesWhenFloodedFull(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// One teller cannot fill the store on its own — MaxPerSourceStored — so
	// fill it the way it would take an attacker to fill it: from enough
	// distinct sources to cover the cap.
	sources := p2p.MaxPeers / p2p.MaxPerSourceStored
	for i := 0; i < p2p.MaxPeers; i++ {
		from := fmt.Sprintf("198.%d.7.7:9421", 18+i%sources)
		ps.AddFrom(fmt.Sprintf("11.%d.%d.%d:8333", i/65536%256, i/256%256, i%256), from)
	}
	if ps.Len() != p2p.MaxPeers {
		t.Fatalf("store holds %d entries, want the cap %d", ps.Len(), p2p.MaxPeers)
	}

	const honest = "203.0.113.9:8333"
	ps.Add(honest)
	if _, ok := ps.Get(honest); !ok {
		t.Fatalf("a store filled with one source's unproven gossip refused an honest address; "+
			"the cap has locked the store shut rather than bounded it (len=%d)", ps.Len())
	}
	if ps.Len() > p2p.MaxPeers {
		t.Fatalf("store grew past the cap to %d", ps.Len())
	}
}

// TestOneSourceCannotOutweighManyInTheStore pins the eviction rule itself: the
// victim comes from the most over-represented cohort, so a flood evicts its
// own entries and the honest singleton beside it is untouched. This is
// docs/decisions/networking.md §5's accept-path finding — "Group share is the
// one signal that does not invert" — carried to the peer store.
func TestOneSourceCannotOutweighManyInTheStore(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const honest = "203.0.113.9:8333"
	ps.Add(honest)
	// Fill the rest, and then keep going well past the cap.
	for i := 0; i < p2p.MaxPeers*2; i++ {
		ps.AddFrom(fmt.Sprintf("11.%d.%d.%d:8333", i/65536%256, i/256%256, i%256), "198.18.7.7:9421")
	}
	if ps.Len() > p2p.MaxPeers {
		t.Fatalf("store grew past the cap to %d", ps.Len())
	}
	if _, ok := ps.Get(honest); !ok {
		t.Fatalf("an honest address was evicted by %d gossiped addresses from a single source", p2p.MaxPeers*2)
	}
	// And one teller cannot own the store even by flooding it: with a single
	// source gossiping twice the cap, the store must still be holding room for
	// everyone else rather than sitting full of that one teller's addresses.
	if ps.Len() >= p2p.MaxPeers {
		t.Fatalf("one source filled %d of the store's %d entries; no per-cohort ceiling is holding",
			ps.Len()-1, p2p.MaxPeers)
	}
}

// TestProvenPeersOutrankCohortShareWhenEvicting pins the order of the two
// eviction keys, which an earlier revision had the wrong way round.
//
// Cohort share is the signal that separates a flood from a peer list, but only
// among entries that are otherwise indistinguishable. A peer this node has
// actually connected to is not indistinguishable from an invented string, and
// when share decided first, three score-100 peers sharing one teller were
// evicted ahead of thousands of score-0 invented entries that each had a
// cohort to themselves.
func TestProvenPeersOutrankCohortShareWhenEvicting(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// Three proven peers, all from one teller, so they share a cohort and are
	// the largest cohort in the store by share alone.
	proven := []string{"203.0.113.1:9421", "203.1.113.1:9421", "203.2.113.1:9421"}
	for _, a := range proven {
		ps.AddFrom(a, "198.18.7.7:9421")
		ps.MarkConnected(a)
		ps.Adjust(a, p2p.ScoreCeiling)
	}
	// Fill the rest with unproven strangers, each in a cohort of its own.
	for i := len(proven); i < p2p.MaxPeers; i++ {
		// Each stranger genuinely in a cohort of its own: the source must vary
		// in the octets AddressGroup keeps, not the ones it masks off.
		ps.AddFrom(fmt.Sprintf("11.%d.%d.%d:8333", i/65536%256, i/256%256, i%256),
			fmt.Sprintf("%d.%d.7.7:9421", 20+i/256, i%256))
	}
	// Now push newcomers in and watch what the store gives up.
	for i := 0; i < 16; i++ {
		ps.Add(fmt.Sprintf("192.0.%d.1:9421", i))
	}
	for _, a := range proven {
		if _, ok := ps.Get(a); !ok {
			t.Fatalf("a peer this node had connected to (score %d) was evicted for an unproven newcomer, "+
				"because it shared a cohort with two others", p2p.ScoreCeiling)
		}
	}
}

// TestBootstrapHostnamesResolveToDialTargets guards the operator-facing
// interface docs/RUNNING.md documents:
//
//	zycordd --dir ./data --peers node1.example:9421,node2.example:9421
//
// The store holds IP-hosted addresses only — an address with no /16 has no
// diversity group — so a hostname handed straight to it is silently dropped
// and the node starts with no peers and no message saying why. Bootstrap
// entries are resolved to addresses first.
func TestBootstrapHostnamesResolveToDialTargets(t *testing.T) {
	got, err := p2p.ResolveBootstrapForTest("localhost:9421")
	if err != nil || len(got) == 0 {
		t.Fatal("a hostname bootstrap entry resolved to no dial targets; --peers with a hostname is documented in docs/RUNNING.md")
	}
	for _, a := range got {
		if host, _, err := net.SplitHostPort(a); err != nil || net.ParseIP(host) == nil {
			t.Fatalf("resolved bootstrap entry %q is not an ip:port the peer store will accept", a)
		}
	}
	// An address is already a dial target and is passed through untouched.
	if got, err := p2p.ResolveBootstrapForTest("203.0.113.9:8333"); err != nil || len(got) != 1 || got[0] != "203.0.113.9:8333" {
		t.Fatalf("an ip:port bootstrap entry was not passed through: %v (%v)", got, err)
	}
	// A name that does not resolve reports why, rather than leaving a peerless
	// node and no message saying so — the same silence this guards against.
	if _, err := p2p.ResolveBootstrapForTest("no-such-host-xyzzy.invalid:9421"); err == nil {
		t.Fatal("an unresolvable bootstrap entry was dropped silently")
	}
}

// TestDialBudgetsSpanRoundsNotCalls is the defect that made both bounds
// decorative: they are counted per call, and the dial loop calls the selector
// once per round with the peers it already has in `exclude`, which removes
// them from the candidate list before either counter is built. Every round
// therefore started the budgets at zero.
//
// Measured on the revision that did this, simulating Node.topUp exactly: one
// teller reached 2, then 4, then 6, then 8 of 8 outbound slots over four
// rounds — about eight seconds at the default DialInterval — and the same
// laundering applied to the per-/16 bound that predates the per-source one,
// which is the MUST in wire.md §11 about address diversity.
func TestDialBudgetsSpanRoundsNotCalls(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		ps.AddFrom(junkAddr(i), "198.18.7.7:9421")
	}

	// Exactly what Node.topUp does: dial what the selector returns, then come
	// back next round with those connections held.
	connected := map[string]bool{}
	var held []string
	for round := 0; round < 8; round++ {
		need := 8 - len(held)
		if need <= 0 {
			break
		}
		for _, a := range ps.SelectDialTargets(need, connected, held) {
			connected[a] = true
			held = append(held, a)
		}
	}
	if len(held) > p2p.MaxPerSource {
		t.Fatalf("one teller accreted %d of 8 outbound slots across dial rounds, want at most %d (MaxPerSource): %v",
			len(held), p2p.MaxPerSource, held)
	}

	// The same laundering, on the per-group bound: one /16, many addresses.
	ps2, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		ps2.Add(sybilAddr(i))
	}
	connected = map[string]bool{}
	held = nil
	for round := 0; round < 8; round++ {
		need := 8 - len(held)
		if need <= 0 {
			break
		}
		for _, a := range ps2.SelectDialTargets(need, connected, held) {
			connected[a] = true
			held = append(held, a)
		}
	}
	if len(held) > p2p.MaxFallbackPerGroup {
		t.Fatalf("one /16 accreted %d of 8 outbound slots across dial rounds, want at most %d; wire.md §11 says one hosting range MUST NOT fill them: %v",
			len(held), p2p.MaxFallbackPerGroup, held)
	}
}

// TestGetPeersResponseIsNotThrottledByGossipSource pins the split between the
// two selectors. The per-source bound protects *this* node's outbound slots;
// whose gossip taught this node an address says nothing about the eclipse risk
// of the node asking for it. Applying the dial-path bound to peer exchange
// throttled honest dissemination instead of an attacker — a young node holding
// hundreds of addresses from one honest bootstrap peer answered with 2 of a
// permitted 64.
func TestGetPeersResponseIsNotThrottledByGossipSource(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		ps.AddFrom(fmt.Sprintf("11.%d.0.1:8333", i%256), "198.18.7.7:9421")
	}
	if got := len(ps.SelectDiverse(64, nil)); got < 64 {
		t.Fatalf("peer exchange offered %d addresses of a permitted 64 from a store of 200; "+
			"the dial-path source bound has leaked into gossip dissemination", got)
	}
}

// TestSelectDiverseFallbackBoundsPerGroup is the diversity defence's second,
// originally-suspected mechanism: when the store has fewer distinct address
// groups than slots to fill, SelectDiverse falls back to the best remaining
// peers rather than sitting under-connected (wire.md §11) — but the fallback
// used to hand a single group every remaining slot once it ran, which is
// exactly the concentration address diversity exists to price.
func TestSelectDiverseFallbackBoundsPerGroup(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// One address group, several addresses in it — the state a thin, freshly
	// restarted store can be in after gossip from a single hosting range.
	for i := 0; i < 10; i++ {
		ps.Add(sybilAddr(i))
	}

	selected := ps.SelectDiverse(8, nil)
	groups := map[string]int{}
	for _, a := range selected {
		groups[p2p.AddressGroup(a)]++
	}
	for g, n := range groups {
		if n > p2p.MaxFallbackPerGroup {
			t.Fatalf("group %s took %d of the selected slots, want at most %d (MaxFallbackPerGroup)",
				g, n, p2p.MaxFallbackPerGroup)
		}
	}
	if len(selected) != p2p.MaxFallbackPerGroup {
		t.Fatalf("selected %d peers from a single-group store, want exactly %d (the fallback's own bound, since no other group exists to draw from)",
			len(selected), p2p.MaxFallbackPerGroup)
	}
}

// fillerAddr builds a distinct, real IPv4 address for i in [0, 65536): every
// bit of i round-trips into the second and third octets, so distinct i values
// never collide.
func fillerAddr(i int) string {
	return "10." + itoa((i>>8)&0xFF) + "." + itoa(i&0xFF) + ".1:9000"
}

// TestPeerStoreCapEvictsWorstFirst: without a cap, a single unsolicited
// `peers` frame — or ordinary gossip accumulated over a long uptime — grows
// the store, and the peers.json it persists, without bound. This pins the
// policy that replaces the unbounded map: the store never exceeds MaxPeers,
// and a demonstrably worse entry (lower score, or one that has failed to
// connect) is evicted to make room before a healthy one ever would be.
//
// It does *not* pin a refusal at the cap. An earlier revision refused there —
// a newcomer was declined whenever the worst entry held was no worse than a
// brand-new one — and that is a lock rather than a bound; see
// TestPeerStoreStaysOpenToHonestAddressesWhenFloodedFull for what it cost, and
// admitLocked for what answers the churn instead.
func TestPeerStoreCapEvictsWorstFirst(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < p2p.MaxPeers; i++ {
		ps.Add(fillerAddr(i))
	}
	if got := ps.Len(); got != p2p.MaxPeers {
		t.Fatalf("store holds %d peers after filling to the cap, want %d", got, p2p.MaxPeers)
	}

	// Demote one entry so it is unambiguously the worst in the store.
	worst := fillerAddr(0)
	ps.Adjust(worst, -10)
	ps.MarkFailed(worst)

	newcomer := "203.0.113.200:9000"
	ps.Add(newcomer)

	if got := ps.Len(); got != p2p.MaxPeers {
		t.Fatalf("store holds %d peers after an eviction, want %d (the cap), not one more", got, p2p.MaxPeers)
	}
	if _, ok := ps.Get(worst); ok {
		t.Fatal("the demoted (lower-score, failed) peer survived while the store was at its cap")
	}
	if _, ok := ps.Get(newcomer); !ok {
		t.Fatal("a new address was refused even though a strictly worse entry was evictable")
	}

	// The store is now back at the cap, full of addresses with an identical,
	// empty track record (score 0, no failures). One more such address is
	// admitted anyway, by evicting one of them — the cap bounds the store, it
	// does not lock it shut. An earlier revision refused here, on the reasoning
	// that a churn of interchangeable unproven addresses replays the
	// unbounded growth one eviction at a time; see
	// TestPeerStoreStaysOpenToHonestAddressesWhenFloodedFull for what that
	// costs, and admitLocked for why the churn is answered by charging the
	// eviction to the arriving cohort instead of by refusing the arrival.
	before := ps.Len()
	unproven := "198.51.100.222:9000"
	ps.Add(unproven)
	if got := ps.Len(); got != before {
		t.Fatalf("store size moved from %d to %d admitting an address into a full store; the cap must hold either way",
			before, got)
	}
	if _, ok := ps.Get(unproven); !ok {
		t.Fatal("a full store refused a well-formed address instead of evicting for it")
	}
}

// TestPeerStoreSurvivesRestart is the other half of M2-G4: a node that rebooted
// into a blank slate would take whatever peer set it was handed next, which is
// exactly when an eclipse is cheapest.
func TestPeerStoreSurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/peers.json"

	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ps.Add("203.0.113.7:9420")
	ps.Add("198.51.100.9:9420")
	ps.Adjust("203.0.113.7:9420", 40)
	ps.Adjust("198.51.100.9:9420", p2p.ScoreBanThreshold)
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 2 {
		t.Fatalf("a restart kept %d peers, want 2", reopened.Len())
	}
	// Earned goodwill is not restored: a file cannot vouch for a peer.
	// What must survive is the peer itself and the accusation against it.
	good, ok := reopened.Get("203.0.113.7:9420")
	if !ok || good.Score != 0 {
		t.Fatalf("a restart restored score %d; a stored positive score is privilege a file must not hand out", good.Score)
	}
	if !reopened.Banned("198.51.100.9:9420") {
		t.Fatal("a restart forgave a banned peer, which is a free reset for an attacker")
	}
	if got := reopened.SelectDiverse(5, nil); len(got) != 1 {
		t.Fatalf("selection returned %d peers, want only the unbanned one", len(got))
	}
}

// TestBannedPeersAreNotSelected: scoring must feed selection, or it is
// bookkeeping that changes nothing.
func TestBannedPeersAreNotSelected(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	ps.Add("203.0.113.1:9420")
	ps.Add("198.51.100.1:9420")
	ps.Adjust("203.0.113.1:9420", p2p.ScoreBanThreshold)

	got := ps.SelectDiverse(5, nil)
	sort.Strings(got)
	if len(got) != 1 || got[0] != "198.51.100.1:9420" {
		t.Fatalf("selection returned %v; a banned peer must not be dialled", got)
	}
}

// buildCert makes a valid, funded certificate on a node's chain.
func buildCert(t *testing.T, n *testNode, signer *wallet.Key, seq uint64) *types.Certificate {
	t.Helper()
	addr := signer.Persistent()
	seqBase := n.chain.Snapshot().State.Get(types.SeqBaseFeeSlot())
	parBase := n.chain.Snapshot().State.Get(types.ParBaseFeeSlot())

	b := &wallet.Builder{
		Params:  n.p,
		Program: wallet.Tip(types.NativeAsset, addr, key(t, 200).Persistent(), drops(1_000)),
		Seq:     seq,
		TTL:     n.chain.Height() + 10,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 8),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sybilAddr(i int) string {
	return "192.0.2." + itoa(i%250+1) + ":" + itoa(9000+i)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// R4-H1: the orphan pool must not be priced by an attacker.
//
// An orphan's declared Target cannot be checked against the LWMA rule without
// its ancestor headers, so without bounds an attacker declares a trivial
// target, produces structurally-valid "blocks" at no cost, and exhausts memory
// at a price it sets. These are the mitigations; headers-first is the fix.

// fakeOrphan builds a structurally-valid block that does not attach to anything
// the node knows — the shape an attacker floods with.
func fakeOrphan(t *testing.T, p *params.Params, height uint64, target u256.U256, nonce uint64) *types.Block {
	t.Helper()
	var parent types.Hash
	parent[0] = byte(nonce)
	parent[1] = byte(nonce >> 8)
	parent[2] = byte(height)
	b := &types.Block{Header: types.Header{
		Version:      types.HeaderVersion,
		Height:       height,
		ParentID:     parent,
		Time:         p.GenesisTime + height*p.TargetBlockSeconds,
		EmissionAddr: key(t, 3).Persistent(),
		Target:       target,
		PoW:          types.PoWSeal{Nonce: nonce},
	}}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	return b
}

func TestOrphanPoolIsBounded(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 5)

	// A flood of cheap orphans, all inside the window and at the tip's target
	// so only the bounds can stop them.
	handshake(t, a, "flooder:1")
	for i := 0; i < 2_000; i++ {
		blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, uint64(i))
		a.engine.Handle("flooder:1", p2p.KindBlock, deliver(blk))
	}
	if got := a.engine.OrphanCount(); got > p2p.DefaultOrphanLimits().MaxBlocks {
		t.Fatalf("the orphan pool holds %d blocks against a limit of %d; "+
			"an attacker sets the memory price", got, p2p.DefaultOrphanLimits().MaxBlocks)
	}
	if a.engine.OrphanCount() == 0 {
		t.Fatal("nothing was held at all; the test is not exercising the pool")
	}
}

func TestOrphansOutsideTheHeightWindowAreRefused(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 5)

	far := fakeOrphan(t, p, a.chain.Height()+p2p.DefaultOrphanLimits().HeightWindow+10,
		a.chain.Tip().Target, 1)
	handshake(t, a, "attacker:1")
	v := a.engine.Handle("attacker:1", p2p.KindBlock, deliver(far))
	if !errors.Is(v.Err, p2p.ErrOrphanOutOfWindow) {
		t.Fatalf("got %v, want an out-of-window refusal", v.Err)
	}
	if a.engine.OrphanCount() != 0 {
		t.Fatal("a far-future block was held")
	}

	// A block just inside the window is held: the test is not passing by
	// refusing everything.
	near := fakeOrphan(t, p, a.chain.Height()+2, a.chain.Tip().Target, 2)
	handshake(t, a, "peer:1")
	a.engine.Handle("peer:1", p2p.KindBlock, deliver(near))
	if a.engine.OrphanCount() == 0 {
		t.Fatal("a nearby orphan was refused")
	}
}

func TestOrphansWithImplausibleTargetsAreRefused(t *testing.T) {
	p := *devnetEasy()
	// A tip target well below the maximum, so "easier than any legitimate
	// branch could reach" is a statement with content.
	p.GenesisTarget = u256.MustFromDecimal("100000000000000000000")
	hard := &p

	a := newNode(t, "a", hard, key(t, 1).Persistent())

	// Two blocks from the tip, the LWMA clamp allows at most clamp^2. A block
	// declaring the maximum target is claiming work it cannot have done.
	cheat := fakeOrphan(t, hard, a.chain.Height()+2, u256.Max, 1)
	handshake(t, a, "attacker:1")
	v := a.engine.Handle("attacker:1", p2p.KindBlock, deliver(cheat))
	if !errors.Is(v.Err, p2p.ErrOrphanImplausible) {
		t.Fatalf("got %v, want an implausible-target refusal", v.Err)
	}
	if v.Score >= 0 {
		t.Fatal("declaring impossible work cost the sender nothing")
	}

	// The same distance at the tip's own target is plausible and held.
	honest := fakeOrphan(t, hard, a.chain.Height()+2, a.chain.Tip().Target, 2)
	handshake(t, a, "peer:1")
	if v := a.engine.Handle("peer:1", p2p.KindBlock, deliver(honest)); errors.Is(v.Err, p2p.ErrOrphanImplausible) {
		t.Fatal("a plausible target was refused")
	}
}

// TestReorgedOutCertificatesReturnToThePool closes a silent transaction-loss
// bug found while auditing the mempool's API surface (R5).
//
// `Pool.Readmit` existed, was documented for exactly this, and was called from
// nowhere. The consequence was not subtle: a certificate confirmed in a block
// leaves the mempool when that block is applied, and undoing the block does not
// put it back — so a transaction that was confirmed and then reorged out
// disappeared from the chain and from every mempool at the same moment. Nothing
// would ever have re-broadcast it, because every node believed it had already
// been included.
//
// It survived because nothing tested a reorg and the mempool together: the
// reorg tests live in node/chain, which cannot see a mempool, and the mempool
// tests never reorg.
func TestReorgedOutCertificatesReturnToThePool(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	rival := newNode(t, "rival", p, key(t, 1).Persistent())

	// A shared prefix long enough for a coinbase to mature, so the certificate's
	// deposit is covered. Both nodes mine the same payout so the prefix is
	// byte-identical and the fork is where the test puts it.
	prefix := int(p.CoinbaseMaturity) + 2
	victim.mine(t, prefix)
	rival.mine(t, prefix)
	if victim.chain.Tip().ID() != rival.chain.Tip().ID() {
		t.Fatal("setup: the two nodes disagree at the fork point")
	}
	ancestor := victim.chain.Tip()

	// A certificate the victim mines into its own block.
	cert := buildCert(t, victim, key(t, 1), 0)
	if err := victim.pool.Add(cert, victim.chain.Snapshot().State, victim.chain.Height()); err != nil {
		t.Fatalf("pooling the certificate: %v", err)
	}
	blk, _, err := victim.miner.MineOne(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(blk.Certs) != 1 {
		t.Fatalf("setup: the victim's block carries %d certificates, want 1", len(blk.Certs))
	}
	if victim.pool.Has(cert.ID()) {
		t.Fatal("setup: the certificate is still pooled after being mined; " +
			"this test cannot observe its return if it never left")
	}

	// The rival builds a heavier branch from the shared ancestor.
	rival.clock += p.TargetBlockSeconds
	rival.mine(t, 4)
	var branch chain.Branch
	for h := ancestor.Height + 1; h <= rival.chain.Height(); h++ {
		b, err := rival.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		branch.Blocks = append(branch.Blocks, b)
	}

	// Deliver it the way the network would: through the engine, which owns both
	// the chain and the pool and is therefore the only layer that can do this.
	handshake(t, victim, "peer:1")
	for _, b := range branch.Blocks {
		victim.engine.Handle("peer:1", p2p.KindBlock, deliver(b))
	}

	if victim.chain.Tip().ID() != rival.chain.Tip().ID() {
		t.Fatalf("setup: the victim did not adopt the heavier branch (height %d)",
			victim.chain.Height())
	}
	// The reorg must have actually removed the victim's block, or nothing was
	// reorged out and the test proves nothing.
	if victim.chain.Stats().BlocksUndone == 0 {
		t.Fatal("no block was undone; the branch extended rather than replaced")
	}

	if !victim.pool.Has(cert.ID()) {
		t.Fatal("a certificate confirmed and then reorged out did not return to " +
			"the mempool: it is gone from the chain and from the pool at once, " +
			"and nothing will ever re-broadcast it")
	}
}

// TestALocalStorageFaultIsNotThePeersFault arms a defect that has never been
// observed, in the only way it can be: by making the disk fail on purpose.
//
// `ConsiderBranch` surfaces storage failures — a commit that did not land, an
// undo log that is missing — through the same error return as a peer's invalid
// branch, and the gossip path charged `ScoreInvalidMessage` for anything it did
// not explicitly exempt. So a node with a failing disk fines whichever peer
// happened to deliver the block, and since R5 a ban also removes a peer from
// sync candidacy: a node with bad hardware would systematically disconnect
// itself from the network that could still serve it, and the log would name the
// peers rather than the disk.
//
// This can never appear in a soak, because the soak's disks work. It needs the
// fault injected, which is the whole reason the injector exists.
func TestALocalStorageFaultIsNotThePeersFault(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "source", p, key(t, 2).Persistent())
	blocks := source.mine(t, 3)

	// A victim whose commits fail from the second one onward: genesis lands, and
	// every block after it hits the disk fault.
	var commits int
	victim := newNodeWith(t, "victim", p, key(t, 1).Persistent(), storage.Options{
		FaultInjector: func(record []byte) ([]byte, error) {
			commits++
			if commits > 1 {
				return record, errors.New("disk on fire")
			}
			return record, nil
		},
	})

	const peer = "10.11.0.1:9421"
	victim.peers.Add(peer)
	handshake(t, victim, peer)
	before := scoreOf(t, victim, peer)

	// Deliver a branch that does not extend the tip, so it goes through fork
	// choice and hits the failing commit.
	for _, b := range blocks {
		victim.engine.Handle(peer, p2p.KindBlock, deliver(b))
	}

	after := scoreOf(t, victim, peer)
	if after < before {
		t.Errorf("this node's own disk failure cost the peer %d points (%d -> %d): "+
			"a node with bad hardware fines the peers still willing to serve it, "+
			"and a ban now removes them from sync candidacy too — so the node "+
			"disconnects itself from the network and blames everyone else",
			before-after, before, after)
	}
	if victim.peers.Banned(peer) {
		t.Fatal("a peer was banned because this node could not write to its own disk")
	}
}

// TestAnAnnouncementCannotPanicTheNode is a remote, unauthenticated, zero-cost
// crash — found by an adversarial review of a region this milestone did not
// touch, which is the argument for reviewing beyond the diff.
//
// The chain: `UnmarshalAnnounce` bounds the id list by `MaxAnnouncedCerts`
// (100,000), a transport-level ceiling that has nothing to do with consensus.
// `OnBlockAnnounce` then hands that list to `certRoot`, which calls
// `ssz.Merkleize(ids, params.CertListCapacity)` — the static structural bound
// CertRoot's merkle depth is fixed to, the same on devnet and mainnet — and
// `Merkleize` **panics** when handed more chunks than its limit. Nothing on
// the peer message path recovers, so the process dies.
//
// The work check does not stand in the way. `pow.CheckWork` returns nil
// immediately for height 0, because genesis carries no work — correct for the
// fold, and it means an attacker needs no proof of work at all here. One TCP
// connection, one handshake, one small message, every node on the network.
//
// Two fixes, because they close different things. An announcement claiming more
// certificates than a block may contain is describing a block that cannot
// exist, and is refused as a lie rather than survived as a shape. And a
// genesis-height announcement is refused outright: every node already has
// genesis, so such an announcement is never useful, and accepting one is what
// let this bypass the work check for free.
func TestAnAnnouncementCannotPanicTheNode(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	// Anti-vacuity: the message has to get past the decoder, or the engine is
	// never reached and this test is measuring `UnmarshalAnnounce`. The
	// engine's refusal is at the reachable ceiling — the most certificates a
	// valid block at the maximal target can hold — which sits under the
	// decoder's transport bound, so a list one past it still decodes.
	reachable := p.MaxCertsPerBlock(p.SeqGasCapacity)
	ids := make([]types.Hash, reachable+1)
	for i := range ids {
		ids[i][0], ids[i][1] = byte(i), byte(i>>8)
	}
	if len(ids) <= reachable {
		t.Fatal("setup: the id list is not over the reachable ceiling")
	}
	if len(ids) > p2p.MaxAnnouncedCerts {
		t.Fatal("setup: the id list is over the transport bound, so the decoder would refuse it first")
	}
	// Height 1 with a trivially easy target, NOT height 0.
	//
	// The first draft used height 0 and passed against a tree where the count
	// guard had been removed — because the genesis refusal below catches a
	// height-0 header first, so the message never reached the code this test is
	// named for. Mutation found it. The two guards close different doors and
	// each needs a message that reaches only its own.
	raw := p2p.BlockAnnounce{
		Header: types.Header{
			Version: types.HeaderVersion,
			Height:  1,
			Target:  u256.Max, // passes CheckWork, so the work check is not what stops it
		},
		CertExemplars: ids,
	}.MarshalAnnounce()
	if _, err := p2p.UnmarshalAnnounce(raw); err != nil {
		t.Fatalf("setup: the decoder rejected the message, so it never reaches "+
			"the root check this test exists for: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an unauthenticated peer message panicked the node: %v.\n\n"+
				"Nothing on the peer message path recovers, so this is the whole "+
				"process. And at height 0 — refused separately now — pow.CheckWork "+
				"returns nil immediately, so the same message cost the sender no "+
				"proof of work at all: one connection, one message, every node on "+
				"the network.", r)
		}
	}()
	handshake(t, victim, "attacker:1")
	v := victim.engine.Handle("attacker:1", p2p.KindBlockAnnounce, raw)

	// Surviving is not enough — the sender must be charged, or an attacker
	// repeats it for free until something else gives.
	if v.Score >= 0 {
		t.Fatalf("an announcement describing a block that cannot exist scored %d: "+
			"a message that is refused but costs its sender nothing is an "+
			"invitation to send it again", v.Score)
	}
	if v.Forward {
		t.Fatal("an announcement that cannot describe a real block was relayed on")
	}
}

// TestAGenesisAnnouncementIsRefused pins the second half on its own, because it
// is a distinct property and a fix for one must not be read as covering both.
//
// Height 0 is the one height at which `pow.CheckWork` costs an attacker
// nothing. Every node already holds genesis, so an announcement of it can never
// be useful — refusing it removes a free path into everything downstream of the
// work check, whatever else lives there now or later.
func TestAGenesisAnnouncementIsRefused(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	genesis, err := victim.chain.BlockAt(0)
	if err != nil {
		t.Fatal(err)
	}
	// A genuine, internally consistent genesis announcement: correct header,
	// correct cert root. Nothing about it is malformed — the point is that it
	// is useless, and that useless-but-free is what an attacker wants.
	raw := p2p.BlockAnnounce{
		Header:        genesis.Header,
		CertExemplars: genesis.CertExemplars(),
	}.MarshalAnnounce()

	handshake(t, victim, "attacker:1")
	v := victim.engine.Handle("attacker:1", p2p.KindBlockAnnounce, raw)
	if v.Forward {
		t.Fatal("a genesis announcement was relayed to the whole network")
	}
	if v.Reply != nil {
		t.Fatal("a genesis announcement made this node request a body it already has")
	}
}

// TestABlockCitingAGenesisHeightHeaderIsRefused pins the second half of the
// genesis-height free pass: the same free pass, one level down, on the headers
// a block cites.
//
// `pow.CheckWork` returns nil for any height-0 header, and the cited-header
// loop in OnBlock calls it once per citation — so a block that paid real work
// for its own header could pad its citation list with genesis-height headers
// that cost nothing to fabricate. Nothing else on the body path looks at a
// citation's height before the block reaches the orphan pool.
//
// **This refusal is not a consensus change, and it is only permissible
// because it is not.** spec/wire.md §9 rule 7 records that the fold's citation
// checks are exhaustive and that adding one is as much a consensus change as
// removing one. A height-0 citation is already refused by the fold on every
// path that applies a block — core/fold's checkCites permits no citations at
// all below height 2, and above it requires cited.Height == h.Height-1, which
// no height-0 header can satisfy — so this guard rejects, earlier and with a
// score, only blocks that were already unconditionally invalid.
//
// The anti-vacuity half is the same block with its citation list emptied: it
// is admitted to the orphan pool, so the refusal above is about the citation
// and not about the block carrying it.
func TestABlockCitingAGenesisHeightHeaderIsRefused(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 5)

	// A genesis-height citation carrying no work at all: an unmeetable target
	// and an unsolved nonce, which CheckWork never looks at because the height
	// short-circuits it first.
	cited := types.Header{
		Version:      types.HeaderVersion,
		Height:       0,
		ParentID:     types.Hash{0xee},
		Time:         p.GenesisTime,
		EmissionAddr: key(t, 3).Persistent(),
		Target:       u256.One,
		PoW:          types.PoWSeal{Nonce: 0},
	}
	// Anti-vacuity: confirm the citation genuinely fails its declared target,
	// so what admits it below can only be the height exemption.
	if digest := (pow.Dev{}).Hash(pow.KeyFor(cited.Height, p), cited.PoWInput()); !u256.FromBytes(digest).Gt(cited.Target) {
		t.Fatal("setup: the forged citation happens to meet its declared target")
	}

	blk := fakeOrphan(t, p, victim.chain.Height()+1, victim.chain.Tip().Target, 42)
	blk.Cites = []*types.Header{&cited}
	blk.Header.CitesRoot = blk.ComputeCitesRoot(p)

	handshake(t, victim, "attacker:1")
	before := victim.engine.OrphanCount()
	v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(blk))
	if v.Score >= 0 {
		t.Fatalf("a block citing a genesis-height header scored %d: the citation "+
			"cost nothing to fabricate and nothing charged for it", v.Score)
	}
	if v.Forward {
		t.Fatal("a block with a free citation was forwarded")
	}
	if victim.engine.OrphanCount() != before {
		t.Fatal("a block whose citation carries no work was admitted to the orphan pool")
	}

	// The negation: the identical block without the citation is held. Without
	// this the test would pass against a node that refused the block for any
	// other reason — its parent, its target, its shape.
	plain := fakeOrphan(t, p, victim.chain.Height()+1, victim.chain.Tip().Target, 42)
	if v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(plain)); v.Score < 0 {
		t.Fatalf("the same block without the citation was refused too (%v), so "+
			"the case above is not measuring the citation", v.Err)
	}
	if victim.engine.OrphanCount() != before+1 {
		t.Fatal("the citation-free block was not held; the comparison above is empty")
	}

	// And the third case, which is what makes this a test of the *rule* rather
	// than of a stricter one. `if len(blk.Cites) > 0 { refuse }` passes both
	// cases above and is badly wrong: it would refuse, decline to relay, and
	// charge -20 for every valid citing block — contradicting core/fold, whose
	// checkCites accepts those, and suppressing the competing-header signal
	// whitepaper 8.1's health gate reads. So a well-formed citation, at the one
	// height the fold permits, must still be held.
	good := fakeOrphan(t, p, victim.chain.Height()+1, victim.chain.Tip().Target, 43)
	sibling := types.Header{
		Version:      types.HeaderVersion,
		Height:       good.Header.Height - 1,
		ParentID:     types.Hash{0xcd},
		Time:         good.Header.Time - p.TargetBlockSeconds,
		EmissionAddr: key(t, 4).Persistent(),
		Target:       victim.chain.Tip().Target,
	}
	good.Cites = []*types.Header{&sibling}
	good.Header.CitesRoot = good.ComputeCitesRoot(p)
	if v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(good)); v.Score < 0 {
		t.Fatalf("a block citing a well-formed header one height below its own was "+
			"refused (%v): the guard is refusing citations rather than "+
			"genesis-height citations", v.Err)
	}
	if victim.engine.OrphanCount() != before+2 {
		t.Fatal("the validly-citing block was not held")
	}
}

// TestAGenesisBlockBodyIsRefused pins the OnBlock half of the same guard.
//
// OnBlockAnnounce refuses height 0 outright, and the reason is not specific to
// announcements: `pow.CheckWork` returns nil for *any* height-0 header,
// announced or not, before it even reads the declared target. OnBlock is
// reachable directly off the wire — a KindBlock body needs no prior
// announcement, no handshake beyond the connection's own — so a handler that
// does not carry the same guard hands an attacker a header that costs no work
// at all, real or forged.
//
// The consequence this test pins is concrete rather than hypothetical: the
// orphan pool's plausibility ceiling only bounds a *declared* target against
// the tip's, and while a node's tip sits within the pool's 128-block
// HeightWindow of genesis — true of every node until then — a height-0 orphan
// at any target within that ceiling is admitted for free. This is the gap
// the genesis-height free pass raised, folded into the handler rework as "the
// shared prelude" while that handler was being reworked for the seenBlocks
// dedupe, and left open when the rework landed.
func TestAGenesisBlockBodyIsRefused(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	victim.mine(t, 5) // tip well inside the orphan window, so the window is not
	// what refuses this

	// A forged height-0 header carrying no real work: an outlandish target and
	// an unsolved nonce. Content aside, this is exactly the header a height-0
	// guard has to refuse on its own terms, because CheckWork gives *any*
	// height-0 header a pass regardless of what its hash says.
	forged := &types.Block{Header: types.Header{
		Version:      types.HeaderVersion,
		Height:       0,
		ParentID:     types.Hash{0xff},
		Time:         p.GenesisTime,
		EmissionAddr: key(t, 3).Persistent(),
		Target:       u256.One,
		PoW:          types.PoWSeal{Nonce: 0},
	}}
	forged.Header.CertRoot = forged.ComputeCertRoot(p)

	// Anti-vacuity: bypass the height-0 exemption by hand and confirm the hash
	// genuinely fails the declared target. If it happened to pass, this test
	// would not be exercising the exemption at all.
	digest := pow.Dev{}.Hash(pow.KeyFor(forged.Header.Height, p), forged.Header.PoWInput())
	if !u256.FromBytes(digest).Gt(forged.Header.Target) {
		t.Fatal("setup: the forged header happens to meet its declared target, " +
			"so this case is not exercising the height-0 exemption")
	}

	handshake(t, victim, "attacker:1")
	v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(forged))

	if v.Score >= 0 {
		t.Fatalf("a genesis-height block body scored %d: an attacker gets a free "+
			"path past the work check for nothing", v.Score)
	}
	if v.Forward {
		t.Fatal("a genesis-height block body was relayed to every peer")
	}
	if victim.engine.OrphanCount() != 0 {
		t.Fatal("a genesis-height body with no work behind it was admitted to the " +
			"orphan pool — free of charge, and only because CheckWork exempts " +
			"height 0 unconditionally")
	}
}

// TestAGossipedBlockMustCarryRealWork is the hole that swallowed the whole
// point of proof of work, on the one path gossip actually uses.
//
// `pow.CheckWork` had exactly two call sites in the tree: `OnBlockAnnounce`,
// which checks the *announcement*, and `node/sync`, which checks headers it
// pulled. `OnBlock` — where a block body arrives and is applied — had none, and
// neither does `Chain.Apply` or `fold.CheckBlockRules`. Nothing on that path
// asked whether the work had been done.
//
// A block message is unsolicited: `Node.serve` dispatches whatever arrives, so
// an attacker needs no announcement, no handshake and no prior relationship.
// One message with a header that does not meet its own declared target was
// applied, scored +1 as a useful message, and **relayed to every peer**.
//
// The damage is not one bad block. Accumulated work is computed from the
// *declared* target, so a block declaring `Target = 1` claims 2^255 work —
// more than any honest chain can ever reach. `ConsiderBranch` weighs branches
// by work, so after one such message no honest branch can ever outweigh the
// node's tip again: it is permanently forked, it pays the attacker's emission
// address, and it has already forwarded the message to everyone it knows.
//
// Two things are checked here, and they are different questions:
//
//   - the hash must meet the target the header declares — `pow.CheckWork`;
//   - the target it declares must be the one the difficulty rule produces —
//     `pow.NextTarget`, which is R4-H1 and the reason headers-first sync
//     exists. Without the second, an attacker declares `Target = 2^256-1`,
//     solves it in one hash, and walks in through the first check.
func TestAGossipedBlockMustCarryRealWork(t *testing.T) {
	t.Run("a hash that does not meet its declared target", func(t *testing.T) {
		// Real devnet parameters, and the header declares the target the rule
		// actually produces — so the rule check below cannot be what stops it.
		// Only `pow.CheckWork` can, which is the point: this case isolates the
		// guard that also covers the orphan path, where the rule cannot be
		// recomputed at all.
		real := spec.Devnet()
		victim := newNode(t, "victim1", real, key(t, 1).Persistent())
		tip := victim.chain.Tip()
		want := pow.NextTarget(victim.chain.RecentHeaders(int(real.DifficultyWindow)+1), real)

		forged := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + real.TargetBlockSeconds,
			EmissionAddr: key(t, 3).Persistent(),
			Target:       want, // honest target, no work behind it
		}}
		forged.Header.CertRoot = forged.ComputeCertRoot(real)

		// Anti-vacuity, both halves: the work must genuinely be missing, and the
		// target must genuinely be the rule's, or something else does the work
		// of catching this and the guard under test is not exercised.
		if err := pow.CheckWork(pow.Dev{}, forged.Header, real); err == nil {
			t.Fatal("setup: the header happens to meet its target, so no work is missing")
		}
		if !forged.Header.Target.Eq(want) {
			t.Fatal("setup: the declared target is not the rule's, so the rule check " +
				"would catch this and CheckWork is not the guard being tested")
		}

		before := victim.chain.Tip().ID()
		handshake(t, victim, "attacker:1")
		v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(forged))

		if victim.chain.Tip().ID() != before {
			t.Fatal("a block with no proof of work behind it was applied. Nothing " +
				"on the block-body path asked whether the work had been done: " +
				"pow.CheckWork was called on announcements and in node/sync, and a " +
				"block message needs neither. Chain.Apply does not check it and " +
				"neither does the fold, which judges a block's contents rather " +
				"than its cost.")
		}
		if v.Forward {
			t.Fatal("and it was relayed to every peer, so one message poisons the network")
		}
		if v.Score >= 0 {
			t.Fatalf("a block with no work behind it scored %d: refusing it while "+
				"charging nothing invites the sender to keep going", v.Score)
		}
	})

	t.Run("a target the difficulty rule would never produce", func(t *testing.T) {
		// Real devnet parameters, not the easy variant: the rule's target has to
		// be a genuine one, or declaring the easiest possible target is not a lie
		// and nothing is armed.
		real := spec.Devnet()
		victim := newNode(t, "victim2", real, key(t, 1).Persistent())
		tip := victim.chain.Tip()

		// The R4-H1 adversary, built by hand rather than mined: declare a
		// trivially easy target and solve it for almost nothing. The hash meets
		// the target it declares, so the plain work check passes; the rule says
		// the target is a lie.
		forged := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + real.TargetBlockSeconds,
			EmissionAddr: key(t, 3).Persistent(),
			Target:       u256.Max,
		}}
		forged.Header.CertRoot = forged.ComputeCertRoot(real)
		if !pow.Solve(pow.Dev{}, &forged.Header, real, 1<<16) {
			t.Fatal("setup: could not solve a trivially easy target")
		}
		if err := pow.CheckWork(pow.Dev{}, forged.Header, real); err != nil {
			t.Fatalf("setup: the cheap header fails the plain work check (%v), so "+
				"this case is indistinguishable from the one above", err)
		}
		want := pow.NextTarget(victim.chain.RecentHeaders(int(real.DifficultyWindow)+1), real)
		if forged.Header.Target.Eq(want) {
			t.Fatalf("setup: the declared target IS the rule's target (%s), so "+
				"nothing is forged", want.String())
		}

		before := victim.chain.Tip().ID()
		handshake(t, victim, "attacker:1")
		v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(forged))

		if victim.chain.Tip().ID() != before {
			t.Fatalf("a block declaring a target the difficulty rule does not "+
				"produce was applied. The rule gives %s and the header declared "+
				"%s, solved in a handful of hashes. That is R4-H1 — the attack "+
				"headers-first sync exists to remove — walking in through the "+
				"gossip path, where the rule was never checked at all.",
				want.String(), forged.Header.Target.String())
		}
		if v.Forward {
			t.Fatal("and it was relayed on")
		}
	})
}

// TestGossipHealsBackToASegmentThisNodeOrphaned is the fifth call site.
//
// The property: a branch assembled from held orphans walks back to a block this
// node is *built on*, not merely to one it remembers.
//
// assembleBranch stops when it reaches "a block this chain knows". Retaining
// the headers of reorged-out blocks made that test answer yes for exactly the
// blocks the walk has to walk *past* — the losing segment's own. The branch is
// then truncated and anchored on a block this node does not follow,
// ConsiderBranch returns ErrUnknownAncestor, and nothing scores or logs it.
//
// The consequence is the one the four sites fixed before it share: a node that
// moved from segment A to segment B, and later sees A become the heavier chain
// again, never takes it back over gossip. It waits for sync, which is the slow
// path, and until then two halves of a healed network sit on different chains
// with every diagnostic reporting health.
//
// The competing segment wins on length rather than on difficulty, and that is
// forced rather than incidental: a rival block at a much harder target makes
// the honest segment's own blocks fail R4-H1's plausibility ceiling — "a target
// no legitimate branch could reach" — so they never reach the orphan pool and
// the walk under test never runs.
func TestGossipHealsBackToASegmentThisNodeOrphaned(t *testing.T) {
	p := devnetEasy()
	origin := newNode(t, "origin", p, key(t, 1).Persistent())
	victim := newNode(t, "victim", p, key(t, 2).Persistent())

	// Segment A, and the victim follows it.
	origin.mine(t, 5)
	net := &network{t: t}
	handshake(t, victim, "origin:1")
	net.syncFrom(victim, origin)
	if victim.chain.Height() != 5 {
		t.Fatalf("setup: victim is at height %d, want 5", victim.chain.Height())
	}
	orphanedTip, err := victim.chain.BlockAt(5)
	if err != nil {
		t.Fatal(err)
	}

	// Segment B: four blocks from height 2, at the same target the honest chain
	// uses, so it outweighs A's three by being longer.
	forkPoint, err := victim.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	var rivals []*types.Block
	parent := forkPoint.Header
	for i := 0; i < 4; i++ {
		b := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       parent.Height + 1,
			ParentID:     parent.ID(),
			Time:         parent.Time + p.TargetBlockSeconds,
			EmissionAddr: key(t, 7).Persistent(),
			Target:       forkPoint.Header.Target,
		}}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		rivals = append(rivals, b)
		parent = b.Header
	}
	reorg, err := victim.chain.ConsiderBranch(chain.Branch{Blocks: rivals})
	if err != nil {
		t.Fatalf("setup: considering segment B: %v", err)
	}
	if !reorg.Adopted || victim.chain.Height() != 6 {
		t.Fatalf("setup: adopted=%v at height %d, want the victim moved to B",
			reorg.Adopted, victim.chain.Height())
	}
	// The retained headers are the whole point: without them the walk has
	// nothing to trip over and the assertion below holds trivially.
	if _, err := victim.chain.Header(orphanedTip.Header.ID()); err != nil {
		t.Fatalf("setup: the orphaned headers were not retained: %v", err)
	}

	// A grows until it is the heavier chain again.
	origin.mine(t, 4)
	if !origin.chain.TotalWork().Gt(victim.chain.TotalWork()) {
		t.Fatalf("setup: segment A carries %s work against the victim's %s; the "+
			"victim has no reason to switch back",
			origin.chain.TotalWork().String(), victim.chain.TotalWork().String())
	}

	// A arrives over gossip, oldest first, exactly as a relaying peer sends it.
	handshake(t, victim, "peer:1")
	for h := uint64(3); h <= origin.chain.Height(); h++ {
		b, err := origin.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		victim.engine.Handle("peer:1", p2p.KindBlock, deliver(b))
	}

	if victim.chain.Tip().ID() != origin.chain.Tip().ID() {
		t.Fatalf("the victim is at height %d on a different chain from the heavier "+
			"one at %d: the branch walk stopped at a header retained from the "+
			"segment the victim reorged away, so every assembled branch anchored "+
			"on a block the victim does not follow and ConsiderBranch rejected the "+
			"lot — unscored, unlogged, invisible to every diagnostic",
			victim.chain.Height(), origin.chain.Height())
	}
}

// worthOf returns the accumulated work of the blocks from height `from` to
// `to` inclusive.
func worthOf(t *testing.T, ch *chain.Chain, from, to uint64) u256.U256 {
	t.Helper()
	total := u256.Zero
	for h := from; h <= to; h++ {
		b, err := ch.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		total = total.SatAdd(chain.BlockWork(b.Header.Target))
	}
	return total
}

// fastSolveSeconds times a buildHarderBranch block far below
// TargetBlockSeconds, so the difficulty rule computes a genuinely harder
// target for it — the only way left to make a hand-built branch outweigh
// another now that ConsiderBranch re-derives every declared target
// instead of trusting it.
const fastSolveSeconds = 1

// buildHarderBranch constructs a branch of empty blocks descending from an
// ancestor on ch, each carrying the target and time the difficulty rule and
// the median-time floor actually require for it.
//
// ConsiderBranch re-derives both the target and the time bounds for every block
// on a branch, so a hand-built header can no longer declare an arbitrary target
// and pass: this runs the same LWMA computation the real chain does, walking
// the same preceding window pow.NextTarget reads. A block's own target is fixed
// entirely by the window that precedes it, so the *first* block after a shared
// ancestor always ties whatever the honest chain computed for the same position
// — a branch meant to beat more than one replaced block needs more than one
// block of its own, with solveSeconds compounding from the second on.
func buildHarderBranch(t *testing.T, ch *chain.Chain, p *params.Params, payout types.Address,
	ancestor types.Header, count int, solveSeconds uint64) chain.Branch {
	t.Helper()

	window := headersEndingAt(t, ch, ancestor.ID(), int(p.DifficultyWindow)+1)

	var blocks []*types.Block
	parent := ancestor.ID()
	parentTime := ancestor.Time
	for i := 0; i < count; i++ {
		target := pow.NextTarget(window, p)
		when := parentTime + solveSeconds
		if floor := pow.MedianTime(window, p); when <= floor {
			when = floor + 1
		}

		b := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       ancestor.Height + uint64(i) + 1,
			ParentID:     parent,
			Time:         when,
			EmissionAddr: payout,
			Target:       target,
		}}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		blocks = append(blocks, b)

		parent = b.Header.ID()
		parentTime = b.Header.Time
		window = append(window, b.Header)
		if len(window) > int(p.DifficultyWindow)+1 {
			window = window[len(window)-(int(p.DifficultyWindow)+1):]
		}
	}
	return chain.Branch{Blocks: blocks}
}

// headersEndingAt walks ch from id back toward genesis via parent links,
// returning up to want headers oldest-first — the shape pow.NextTarget and
// pow.CheckMedianTime read.
func headersEndingAt(t *testing.T, ch *chain.Chain, id types.Hash, want int) []types.Header {
	t.Helper()
	var out []types.Header
	cursor := id
	for len(out) < want {
		hdr, err := ch.Header(cursor)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *hdr)
		if hdr.Height == 0 {
			break
		}
		cursor = hdr.ParentID
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// TestForwardedCountsAnAcceptedBlock is the behavioural half of the miscounted
// verdicts: a block this node accepts and forwards must move the counter.
// Before the fix the accept path returned Forward: true and counted nothing.
func TestForwardedCountsAnAcceptedBlock(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	b := newNode(t, "b", p, key(t, 2).Persistent())

	blk := a.mine(t, 1)[0]

	const addr = "10.9.9.40:1"
	handshake(t, b, addr)
	ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := b.engine.Handle(addr, p2p.KindBlockAnnounce, ann.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("setup: the announcement was not accepted: %v", v.Err)
	}

	before := b.engine.Forwarded
	v := b.engine.Handle(addr, p2p.KindBlock, deliver(blk))
	if v.Err != nil {
		t.Fatalf("delivering a fresh block: %v", v.Err)
	}
	if !v.Forward {
		t.Fatal("a fresh, valid block was not forwarded")
	}
	if got := b.engine.Forwarded; got != before+1 {
		t.Fatalf("Forwarded = %d after accepting and forwarding a block, want %d", got, before+1)
	}
}

// TestForwardedCountsAnAdoptedReorg is the other half, and the one the
// first fix missed. A branch that wins fork choice is relayed onward, so it
// must move the counter — but that path spelled its verdict
// `Verdict{Forward: reorg.Adopted}` rather than `Forward: true`, which is
// invisible both to a reader scanning for the literal and to a regression test
// that scans the source for it.
//
// Measured before the fix: three forwarding verdicts, counter moved by two.
func TestForwardedCountsAnAdoptedReorg(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	rival := newNode(t, "rival", p, key(t, 1).Persistent())

	// A byte-identical shared prefix, so the fork is where the test puts it.
	prefix := int(p.CoinbaseMaturity) + 2
	victim.mine(t, prefix)
	rival.mine(t, prefix)
	if victim.chain.Tip().ID() != rival.chain.Tip().ID() {
		t.Fatal("setup: the two nodes disagree at the fork point")
	}
	ancestor := victim.chain.Tip()

	// The victim commits to its own block, so the rival's branch replaces
	// rather than extends — otherwise this exercises the accept path instead.
	victim.mine(t, 1)

	rival.clock += p.TargetBlockSeconds
	rival.mine(t, 4)
	var branch chain.Branch
	for h := ancestor.Height + 1; h <= rival.chain.Height(); h++ {
		b, err := rival.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		branch.Blocks = append(branch.Blocks, b)
	}

	handshake(t, victim, "peer:1")
	before := victim.engine.Forwarded
	forwards := 0
	for _, b := range branch.Blocks {
		if v := victim.engine.Handle("peer:1", p2p.KindBlock, deliver(b)); v.Forward {
			forwards++
		}
	}

	if victim.chain.Tip().ID() != rival.chain.Tip().ID() {
		t.Fatalf("setup: the victim did not adopt the heavier branch (height %d)",
			victim.chain.Height())
	}
	if victim.chain.Stats().BlocksUndone == 0 {
		t.Fatal("setup: nothing was undone, so this branch extended rather than " +
			"replaced and the adoption path was never reached")
	}
	if forwards == 0 {
		t.Fatal("setup: adopting a heavier branch produced no forwarding verdict")
	}
	if got := victim.engine.Forwarded - before; got != uint64(forwards) {
		t.Fatalf("Forwarded moved by %d across %d forwarding verdicts: the "+
			"reorg-adoption path relays without counting", got, forwards)
	}
}

// TestHelloListenAddrCannotEclipseOutboundSlots pins the property that a
// single source cannot fill this node's outbound slots with addresses it
// merely claims: the bound is on who told this node about an address, and a
// `hello`'s listen address is told, not observed.
//
// The attack is the `peers`-frame eclipse routed through a different message.
// Ephemeral ports are free, so one attacker address yields as many connections
// as it likes; each handshake advertises one invented listen address in its own
// /16, so address diversity has nothing to say about them. Before a claimed
// listen address was recorded with its teller, those entries were recorded with
// no teller at all, and both MaxPerSource (selection) and cohort() (storage)
// exempt an entry with no teller — so twenty hellos from one /16 took the dial
// slots outright while the same twenty addresses in a `peers` frame were
// bounded at MaxPerSource. The two doors must price the same claim the same
// way.
//
// The test constrains the rule, not the scenario: the rejected alternative of
// counting empty-Src entries by their own address group would still hand this
// scenario 8 of 8 slots, because each invented address is its own /16 — so
// only recording the teller changes the answer here.
func TestHelloListenAddrCannotEclipseOutboundSlots(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	honest := []string{"203.0.113.9:8333", "198.51.100.9:8333", "192.0.2.9:8333"}
	for _, a := range honest {
		victim.peers.Add(a)
	}

	junk := make([]string, 20)
	for i := range junk {
		junk[i] = junkAddr(i)
	}
	// One attacker address, twenty sockets: a second hello on one connection is
	// already a protocol violation, so the attacker pays what it actually
	// costs — an ephemeral port, which is free — and never a second /16.
	// Driven concurrently because that is how it arrives: OnHello runs on
	// `go n.serve(conn, ...)`, one goroutine per connection, so twenty sockets
	// hello in parallel by construction and a serial loop would not model the
	// admission the bound has to hold under.
	errs := make([]error, len(junk))
	var wg sync.WaitGroup
	for i, j := range junk {
		wg.Add(1)
		go func(i int, j string) {
			defer wg.Done()
			h := victim.engine.Hello()
			h.ListenAddr = j
			errs[i] = victim.engine.OnHello(fmt.Sprintf("198.18.7.7:%d", 40000+i), h).Err
		}(i, j)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("setup: handshake %d was refused, so nothing was recorded and this "+
				"test would pass without any defence: %v", i, err)
		}
	}
	for _, j := range junk {
		if _, ok := victim.peers.Get(j); !ok {
			t.Fatalf("advertised address %s was not recorded at all; this test must pin the "+
				"bound on a recorded address, not its absence", j)
		}
	}

	selected := victim.peers.SelectDialTargets(8, nil, nil)
	took := 0
	for _, a := range selected {
		for _, j := range junk {
			if a == j {
				took++
			}
		}
	}
	if took > p2p.MaxPerSource {
		t.Fatalf("one source's self-advertised listen addresses took %d of 8 outbound slots, "+
			"want at most %d (MaxPerSource); selected=%v", took, p2p.MaxPerSource, selected)
	}
	for _, h := range honest {
		found := false
		for _, a := range selected {
			if a == h {
				found = true
			}
		}
		if !found {
			t.Fatalf("known honest peer %s was displaced by one source's advertised listen "+
				"addresses; selected=%v", h, selected)
		}
	}
}

// TestHostileStoreCannotOutrankBootstrapOnFirstDial pins the property that a
// peers.json this node did not write cannot buy the front of the dial order.
//
// The planted addresses are chosen to sort *behind* the bootstrap address
// lexically ("233." > "203."), so the address tie-break cannot be what puts
// them first. With equal scores the bootstrap entry wins on that tie-break;
// only an unclamped restored score can invert it. Each planted address also
// sits in its own /16, so the diversity bound is not doing the work either.
func TestHostileStoreCannotOutrankBootstrapOnFirstDial(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	var planted []string
	hostile := "["
	for i := 0; i < 8; i++ {
		addr := fmt.Sprintf("233.%d.0.1:9420", i)
		planted = append(planted, addr)
		if i > 0 {
			hostile += ","
		}
		hostile += fmt.Sprintf(`{"addr":%q,"score":100,"last_seen":1750000000}`, addr)
	}
	hostile += "]"
	if err := os.WriteFile(path, []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}

	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// The operator's bootstrap list, added fresh after the restart exactly as
	// Node.addBootstrap adds it: no score, no history, and not chosen by the
	// file or by any peer.
	ps.AddBootstrap("203.0.113.7:9420")

	got := ps.SelectDialTargets(1, nil, nil)
	if len(got) != 1 || got[0] != "203.0.113.7:9420" {
		t.Fatalf("first dial after restart selected %v, want the bootstrap address; a stored score outranked it", got)
	}
	// And the planted entries are still known — this is a clamp, not a purge.
	if ps.Len() != len(planted)+1 {
		t.Fatalf("store holds %d entries, want %d", ps.Len(), len(planted)+1)
	}
}

// TestRestoredEntriesAreUnprovenSoEvictionStillReachesThem pins the second
// half of the restored-evidence clamp: a peers.json cannot make its entries
// unevictable either.
//
// proven() is `LastSeen != 0 || Score > 0`, so clamping only the score leaves
// `last_seen` as a second way to buy evictionTier 2 — and evictOneLocked's
// second pass takes a victim only from tier 1. A store restored entirely at
// tier 2 therefore leaves the operator's freshly-added bootstrap address as
// the only entry eviction can reach, and the next admission spends it.
//
// The planted addresses are deliberately given *lower* /16s than the
// bootstrap address so that the cohort scan reaches them first once they are
// evictable at all, and they are spread over 16 groups of 256 — under
// MaxPerSourceStored (MaxPeers/8 = 512), so the load-time cohort trim is not
// what decides this either. The only variable is the tier the file bought.
func TestRestoredEntriesAreUnprovenSoEvictionStillReachesThem(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 4096; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"addr":"10.%d.%d.1:9420","last_seen":1750000000}`, i/256, i%256)
	}
	b.WriteString("]")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Len() != 4096 {
		t.Fatalf("loaded %d entries, want the full store", ps.Len())
	}
	const boot = "203.0.113.7:9420"
	ps.Add(boot)
	if _, ok := ps.Get(boot); !ok {
		t.Fatal("a full store refused the operator's bootstrap address")
	}
	// One more well-formed address arrives, as one gossip frame would bring.
	// Something has to go; it must not be the one entry the operator chose.
	ps.AddFrom("198.51.100.5:9420", "198.51.100.6:9420")
	if _, ok := ps.Get(boot); !ok {
		t.Fatal("the bootstrap address was the entry eviction reached; a restored last_seen made every planted entry proven and left it the only tier-1 candidate")
	}
}

// TestRestartedNodeDialsPeersItHasMetBeforeInventedGossip pins the other half
// of the same clamp: a store that forgets everything is as exploitable as one
// that trusts everything.
//
// Score does not survive a restart any more, so if nothing else did either,
// selectLocked's residual key would be the address — the one key an attacker
// picks for free. The invented addresses here all sort *ahead* of the honest
// ones ("1." < "203."), come from four distinct tellers so MaxPerSource cannot
// exhaust them, and sit in distinct /16s so the diversity bound cannot either:
// the only thing that can keep the honest peers in front is the bit saying this
// node once connected to them.
func TestRestartedNodeDialsPeersItHasMetBeforeInventedGossip(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	honest := map[string]bool{}
	for i := 0; i < 8; i++ {
		addr := fmt.Sprintf("203.%d.113.7:9420", i)
		honest[addr] = true
		ps.Add(addr)
		ps.MarkConnected(addr)
		ps.Adjust(addr, 30)
	}
	// Gossip an attacker never has to pay for: invented strings, four tellers.
	//
	// The tellers must sit in four *distinct* /16s, because Peer.Src is the
	// teller reduced to its address group: four addresses differing only in
	// the third octet are one Src, and MaxPerSource would then cap the
	// invented set at 2 rather than 8, understating the regression this pins.
	for teller := 0; teller < 4; teller++ {
		from := fmt.Sprintf("198.%d.51.1:9420", teller)
		for i := 0; i < 16; i++ {
			ps.AddFrom(fmt.Sprintf("1.%d.0.1:9420", teller*16+i), from)
		}
	}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.SelectDialTargets(8, nil, nil)
	met := 0
	for _, a := range got {
		if honest[a] {
			met++
		}
	}
	if met != 8 {
		t.Fatalf("first dial round after restart selected %v: %d of 8 peers this node had met; an invented address outranked a met one", got, met)
	}
}

// TestFileAssertedArrivalOrderDoesNotChooseTheEvictionVictim pins the first
// half of the file-asserted arrival order: peers.json carries no arrival order
// this node will act on.
//
// betterVictim gives up the newest entry of the largest cohort first, and the
// revision this replaces rebuilt Seq as a dense 1..N "in the order the file
// implies" — so the writer of the file still picked which of its own entries
// eviction would reach. The planted entry named here carries the file's
// highest seq, which under that rule makes it the newest and the victim
// (the absolute value is discarded by renumbering; the order is not), and it is
// given the *lowest* address in its cohort, which is the only key left once
// the order is collapsed into one bucket. The two point opposite ways on
// purpose: if the file's order still decided, this entry would be gone.
func TestFileAssertedArrivalOrderDoesNotChooseTheEvictionVictim(t *testing.T) {
	const listedLast = "203.0.0.1:9420"
	path := t.TempDir() + "/peers.json"
	var b strings.Builder
	b.WriteString("[")
	// 3584 filler entries in 14 cohorts of 256, each well under the largest
	// cohort below, so the cohort scan does not stop at one of them.
	for i := 0; i < 3584; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"addr":"10.%d.%d.1:9420","seq":%d}`, i/256, i%256, i+1)
	}
	// 512 entries sharing one cohort ("own:203.0.0.0/16"), which makes it the
	// largest and so the first the eviction scan visits. listedLast carries
	// the highest seq in the file, which is what "newest" is read from.
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&b, `,{"addr":"203.0.%d.2:9420","seq":%d}`, i, 3585+i)
	}
	for i := 255; i >= 1; i-- {
		fmt.Fprintf(&b, `,{"addr":"203.0.%d.1:9420","seq":%d}`, i, 3841+(255-i))
	}
	fmt.Fprintf(&b, `,{"addr":%q,"seq":100000}`, listedLast)
	b.WriteString("]")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Len() != 4096 {
		t.Fatalf("loaded %d entries, want a full store", ps.Len())
	}
	// One gossiped address arrives at a full store, so exactly one entry is
	// given up.
	ps.AddFrom("198.51.100.5:9420", "198.51.100.6:9420")
	if _, ok := ps.Get(listedLast); !ok {
		t.Fatalf("the entry the file numbered newest was the one eviction reached: a "+
			"file still chooses its own arrival order, so it chooses the victim; "+
			"store holds %d entries", ps.Len())
	}
}

// TestConfiguredAddressSurvivesUntilThisNodeHasDialledIt pins the second half
// of the same defence: an address the operator configured is not spent by gossip before
// the dial loop has reached it once.
//
// The planted entries pack the configured address's own /16, which makes that
// cohort the largest and so the first the eviction scan visits. Everything in
// it is restored and unproven, and the configured address is the one entry in
// it this process admitted — the newest, whatever the file claims — so under
// "newest of the largest cohort first" it is the victim of the very next
// admission. It has no score, no LastSeen and no failures to defend it,
// because it has never been dialled: being the operator's choice is the whole
// of the evidence for it.
func TestConfiguredAddressSurvivesUntilThisNodeHasDialledIt(t *testing.T) {
	const boot = "203.0.113.7:9420"
	path := t.TempDir() + "/peers.json"
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 3585; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"addr":"10.%d.%d.1:9420"}`, i/256, i%256)
	}
	// 511 entries in the configured address's own /16, so admitting it does
	// not itself trip the per-cohort ceiling, and the cohort is the largest in
	// the store either side of that admission.
	for i := 0; i < 511; i++ {
		fmt.Fprintf(&b, `,{"addr":"203.0.%d.%d:9420"}`, i/256, i%256)
	}
	b.WriteString("]")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Len() != 4096 {
		t.Fatalf("loaded %d entries, want a full store", ps.Len())
	}
	ps.AddBootstrap(boot)
	if _, ok := ps.Get(boot); !ok {
		t.Fatal("a full store refused the address the operator configured")
	}
	// Gossip keeps arriving, as it does on a live node. Each admission gives
	// up one entry; none of them may be the address nobody on the network
	// chose.
	for i := 0; i < 8; i++ {
		ps.AddFrom(fmt.Sprintf("198.51.%d.5:9420", i), fmt.Sprintf("198.51.%d.6:9420", i))
		if _, ok := ps.Get(boot); !ok {
			t.Fatalf("the configured address was evicted after %d gossip admissions, "+
				"before this node had dialled it even once", i+1)
		}
	}
	// And the exemption ends at the first dial: once the address has been
	// tried, it is ranked on the evidence like everything else.
	ps.MarkFailed(boot)
	for i := 0; i < 8; i++ {
		ps.AddFrom(fmt.Sprintf("198.52.%d.5:9420", i), fmt.Sprintf("198.52.%d.6:9420", i))
	}
	if _, ok := ps.Get(boot); ok {
		t.Fatal("a configured address that this node has dialled and that never answered " +
			"is still exempt from eviction: the exemption is a resting state, not a first-dial grace")
	}
}

// An address this node connected to and has since failed to dial is not better
// evidence than one the operator configured and has never tried: dialRank's top
// rank is refuted by a failure, so an inbound connection's undiallable
// ip:ephemeral_port entry cannot hold a dial slot ahead of the
// bootstrap list forever.
func TestAnEntryThatKeepsFailingDoesNotOutrankTheOperatorsUntriedAddress(t *testing.T) {
	ps, err := p2p.NewPeerStore(t.TempDir() + "/peers.json")
	if err != nil {
		t.Fatal(err)
	}
	// The undialable-socket shape: an inbound connection is recorded by the
	// socket it arrived on, so this node "met" it, and every dial to it fails.
	const ephemeral = "198.18.7.7:40000"
	ps.MarkConnected(ephemeral)
	for i := 0; i < 5; i++ {
		ps.MarkFailed(ephemeral)
	}
	ps.AddBootstrap("203.0.113.7:9420")

	got := ps.SelectDialTargets(1, nil, nil)
	if len(got) != 1 || got[0] != "203.0.113.7:9420" {
		t.Fatalf("selected %v, want the operator's address; an entry that answered once and "+
			"has failed five dials since still held the top evidence rank", got)
	}
}

// A peer this node has failed to dial does not out-rank one it has never
// tried. dialRank sits above the failures key and Failures is never reset, so
// a rank that survived a failure would be a one-way ratchet: main recycles
// those slots after one round and this node must too.
func TestAPeerThisNodeFailedToDialDoesNotOutrankOneItHasNeverTried(t *testing.T) {
	// (i) rank 2: a stale --peers list must not hold every outbound slot
	// forever. Eight dead addresses in eight distinct /16s, so address
	// diversity cannot be what recycles the slots, against eight fresh
	// gossip addresses from eight distinct tellers, so MaxPerSource cannot be.
	t.Run("stale configured list", func(t *testing.T) {
		ps, err := p2p.NewPeerStore(t.TempDir() + "/peers.json")
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 8; i++ {
			dead := fmt.Sprintf("10.%d.0.1:9000", i)
			ps.AddBootstrap(dead)
			ps.MarkFailed(dead)
			ps.AddFrom(fmt.Sprintf("11.%d.0.1:9000", i), fmt.Sprintf("12.%d.0.1:9000", i))
		}
		got := ps.SelectDialTargets(8, nil, nil)
		for _, a := range got {
			if strings.HasPrefix(a, "10.") {
				t.Fatalf("selected %v: a configured address that has already failed still holds an "+
					"outbound slot, so a stale --peers list starves the node of gossip permanently", got)
			}
		}
	})
	// (ii) rank 1: an inbound ip:ephemeral_port entry that scores nothing
	// gets LastSeen from MarkConnected and then blackholes every dial.
	// It must not sit above untried gossip forever.
	t.Run("scoreless inbound blackhole", func(t *testing.T) {
		ps, err := p2p.NewPeerStore(t.TempDir() + "/peers.json")
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 8; i++ {
			dead := fmt.Sprintf("10.%d.0.1:9000", i)
			ps.MarkConnected(dead)
			ps.MarkFailed(dead)
			ps.AddFrom(fmt.Sprintf("11.%d.0.1:9000", i), fmt.Sprintf("12.%d.0.1:9000", i))
		}
		got := ps.SelectDialTargets(8, nil, nil)
		for _, a := range got {
			if strings.HasPrefix(a, "10.") {
				t.Fatalf("selected %v: an address that answered once, scored nothing and has "+
					"blackholed every dial since still out-ranks one never tried", got)
			}
		}
	})
}

// The eviction exemption for an operator-supplied address reads no field the
// file wrote: a hostile peers.json that stamps last_seen on the operator's own
// addresses must not be able to spend them before this node has dialled them
// at all.
func TestAFileCannotStripTheConfiguredAddressExemptionByClaimingItWasMet(t *testing.T) {
	const boot = "203.0.113.7:9420"
	path := t.TempDir() + "/peers.json"
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 3584; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"addr":"10.%d.%d.1:9420"}`, i/256, i%256)
	}
	// The operator's own address, claimed as met long ago, and 511 entries in
	// its /16 claimed as met recently: the cohort is the largest in the store
	// and worsePeer's LastSeen key — which this same file chose — makes the
	// operator's address the worst entry in it.
	fmt.Fprintf(&b, `,{"addr":%q,"last_seen":1}`, boot)
	for i := 0; i < 511; i++ {
		fmt.Fprintf(&b, `,{"addr":"203.0.%d.%d:9420","last_seen":999999}`, i/256, i%256)
	}
	b.WriteString("]")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Len() != 4096 {
		t.Fatalf("loaded %d entries, want a full store", ps.Len())
	}
	// The operator supplies the same address again this run, as addBootstrap
	// does on every start.
	ps.AddBootstrap(boot)
	for i := 0; i < 8; i++ {
		ps.AddFrom(fmt.Sprintf("198.51.%d.5:9420", i), fmt.Sprintf("198.51.%d.6:9420", i))
		if _, ok := ps.Get(boot); !ok {
			t.Fatalf("the configured address was evicted after %d gossip admissions because the "+
				"file claimed this node had met it long ago: the exemption reads what the file "+
				"wrote, which reinstates the eclipse-by-attrition", i+1)
		}
	}
}

// A file may accuse a peer the network gave this node; it may not accuse the
// address the operator supplied this run. Banned() is filtered before dialRank
// is consulted, so a restored ban on the whole --peers list is a cheaper and
// more complete eclipse than the score inflation the clamp closes.
func TestAFileCannotBanTheAddressesTheOperatorSuppliedThisRun(t *testing.T) {
	const boot = "203.0.113.7:9420"
	path := t.TempDir() + "/peers.json"
	body := fmt.Sprintf(`[{"addr":%q,"score":-150}]`, boot)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ps.AddBootstrap(boot)
	if ps.Banned(boot) {
		t.Fatal("a file banned the address the operator configured for this run")
	}
	if got := ps.SelectDialTargets(1, nil, nil); len(got) != 1 || got[0] != boot {
		t.Fatalf("first dial selected %v, want the operator's address; a file deleted the whole "+
			"bootstrap list from the candidate set, which is a stronger eclipse than the "+
			"score inflation", got)
	}
	// A ban this node adjudicates in this process is still evidence it
	// gathered, and is not laundered by the address being configured.
	ps.Adjust(boot, p2p.ScoreBanThreshold)
	if !ps.Banned(boot) {
		t.Fatal("being on the operator's list made a peer unbannable, which is a free pass earned by configuration")
	}
}

// No entry is both exempt from eviction and in the tier eviction reaches
// first, so a full store can always still learn. tier 0 is
// `Score < 0 || (Failures > 0 && LastSeen == 0)`, and a restored ban on an
// address that is also in --peers used to be tier 0 and exempt at once:
// permanently unevictable, and enough to make a full store refuse every
// further admission while tier-1 victims sat untouched. What makes the two
// disjoint is AddBootstrap clearing the restored negative score, so that is
// what this exercises; the tier-0 scan's fall-through is declared-unreachable
// defence in depth and is deliberately not what this pins.
func TestNoEntryIsBothExemptFromEvictionAndInTheTierEvictionReachesFirst(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	var b strings.Builder
	b.WriteString("[")
	// Eight addresses the file bans, which are also on the operator's list:
	// the whole of tier 0, and every one of them exempt.
	for i := 0; i < 8; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"addr":"203.0.113.%d:9420","score":-150}`, i)
	}
	// The rest of a full store, unproven and evictable.
	for i := 0; i < 4088; i++ {
		fmt.Fprintf(&b, `,{"addr":"10.%d.%d.1:9420"}`, i/256, i%256)
	}
	b.WriteString("]")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		ps.AddBootstrap(fmt.Sprintf("203.0.113.%d:9420", i))
	}
	if ps.Len() != 4096 {
		t.Fatalf("store holds %d entries, want a full store", ps.Len())
	}
	// A full store must still be able to learn.
	ps.AddFrom("198.51.100.5:9420", "198.51.100.6:9420")
	if _, ok := ps.Get("198.51.100.5:9420"); !ok {
		t.Fatal("a full store refused every further admission: every entry in tier 0 was also " +
			"exempt from eviction, so the tier-0 scan found no victim it was allowed to take " +
			"and gave up instead of falling through to tier 1")
	}
}

// A ban this node adjudicated online does not survive a restart for an address
// the operator supplies again: peers.json carries the negative score, the load
// restores it, and AddBootstrap clears it. This pins the accepted cost of "the
// operator's list is the fresher assertion" across the Save/reload cycle where
// it is actually paid, not just in-process. It is the price of not
// letting whoever can write peers.json delete the whole bootstrap list from
// the candidate set, and the ban is re-earned in the round it takes the peer
// to violate the protocol again.
func TestABanThisNodeSavedDoesNotOutliveTheOperatorSupplyingTheAddressAgain(t *testing.T) {
	const boot = "203.0.113.7:9420"
	const gossiped = "198.51.100.9:9420"
	path := t.TempDir() + "/peers.json"

	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ps.AddBootstrap(boot)
	ps.AddFrom(gossiped, "198.51.100.6:9420")
	// Both banned by this node, for conduct this node observed.
	ps.Adjust(boot, p2p.ScoreBanThreshold)
	ps.Adjust(gossiped, p2p.ScoreBanThreshold)
	if !ps.Banned(boot) || !ps.Banned(gossiped) {
		t.Fatal("a ban this process adjudicated did not take effect in this process")
	}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	// The restart. The operator supplies the same list again, as addBootstrap
	// does on every start; nobody re-supplies the gossiped address.
	reopened, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Banned(boot) {
		t.Fatal("the load itself forgave a saved ban; the clearing rule must be AddBootstrap's " +
			"alone, or an address that is no longer configured would be forgiven too")
	}
	reopened.AddBootstrap(boot)
	if reopened.Banned(boot) {
		t.Fatal("a saved ban outlived the operator re-supplying the address, so a file that writes " +
			"ScoreFloor for every --peers address still deletes the bootstrap list from the candidate set")
	}
	// And the cost is bounded to the operator's own list: an address the
	// network gave this node keeps its ban across the restart.
	if !reopened.Banned(gossiped) {
		t.Fatal("a restart forgave a banned peer the operator never configured, which is a free reset")
	}
	got := reopened.SelectDialTargets(2, nil, nil)
	if len(got) != 1 || got[0] != boot {
		t.Fatalf("first dial after restart selected %v, want only the re-supplied configured address", got)
	}
}

// TestObservedSocketIsNotADialCandidate pins the property that an inbound
// connection's accepted socket — `ip:ephemeral_port`, which no peer listens on
// — never wins an outbound dial slot, while the listen address the same peer
// advertised still can.
//
// It is the second half of the measurement
// TestHelloListenAddrCannotEclipseOutboundSlots takes. That test bounds what
// the attacker *claims* at MaxPerSource; the sockets those claims arrived on
// were bounded by nothing but MaxFallbackPerGroup, so the same twenty hellos
// also bought two slots on addresses that can never answer a dial. Four
// of eight, from one /16, for the price of twenty ephemeral ports.
//
// The scenario is deliberately identical to that test's, so the two numbers
// are comparable: same victim, same honest peers, same twenty hellos from one
// attacker address.
func TestObservedSocketIsNotADialCandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())

	honest := []string{"203.0.113.9:8333", "198.51.100.9:8333", "192.0.2.9:8333"}
	for _, a := range honest {
		victim.peers.Add(a)
	}

	sockets := make([]string, 20)
	junk := make([]string, 20)
	errs := make([]error, len(junk))
	var wg sync.WaitGroup
	for i := range junk {
		junk[i] = junkAddr(i)
		sockets[i] = fmt.Sprintf("198.18.7.7:%d", 40000+i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := victim.engine.Hello()
			h.ListenAddr = junk[i]
			errs[i] = victim.engine.OnHello(sockets[i], h).Err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("setup: handshake %d was refused, so nothing was recorded and this "+
				"test would pass without any defence: %v", i, err)
		}
	}
	// The entry must exist, or this test passes for the wrong reason: the fix
	// keeps the observed socket in the store — it carries the address-keyed
	// score and ban that Node.serve consults — and only bars it from the dial
	// set.
	for _, s := range sockets {
		if _, ok := victim.peers.Get(s); !ok {
			t.Fatalf("observed socket %s was not recorded at all; this test must pin that a "+
				"recorded entry is undialable, not that it is absent", s)
		}
	}
	// And the advertised address must still be selectable, or "no socket was
	// selected" would be satisfied by a store that returned nothing at all.
	selected := victim.peers.SelectDialTargets(8, nil, nil)
	advertised := false
	for _, a := range selected {
		for _, j := range junk {
			if a == j {
				advertised = true
			}
		}
	}
	if !advertised {
		t.Fatalf("no advertised listen address was selected at all, so this test cannot "+
			"distinguish an undialable socket from an empty candidate set; selected=%v", selected)
	}

	for _, a := range selected {
		for _, s := range sockets {
			if a == s {
				t.Fatalf("the socket %s an inbound connection arrived on won an outbound dial "+
					"slot; nothing listens on an ephemeral source port, so the slot is spent "+
					"on an address that cannot answer; selected=%v", s, selected)
			}
		}
	}
	for _, h := range honest {
		found := false
		for _, a := range selected {
			if a == h {
				found = true
			}
		}
		if !found {
			t.Fatalf("known honest peer %s was displaced; selected=%v", h, selected)
		}
	}
}

// TestObservedSocketDoesNotSurviveARestartAsADialCandidate pins the half of the
// undialable-socket rule the selector cannot see: the flag that bars an
// observed socket is a fact about this process, so if the entry were persisted
// it would come back with the flag gone *and* with last_seen set — dialable
// again, and ranked as an address this node has met (dialRank). Save drops it
// instead.
func TestObservedSocketDoesNotSurviveARestartAsADialCandidate(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	ps, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const socket = "198.18.7.7:40000"
	const listen = "198.51.100.9:8333"
	ps.Add(listen)
	ps.MarkConnected(socket)
	if _, ok := ps.Get(socket); !ok {
		t.Fatal("setup: the observed socket was not recorded, so nothing is being persisted")
	}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := p2p.NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// The claimed address must survive, or this test would pass against a Save
	// that wrote nothing at all.
	if _, ok := reloaded.Get(listen); !ok {
		t.Fatal("the claimed listen address did not survive the restart, so this test cannot " +
			"tell a dropped socket from a dropped file")
	}
	if _, ok := reloaded.Get(socket); ok {
		t.Fatalf("the observed socket %s came back from peers.json, where nothing records "+
			"that it was only observed: it is a dial candidate again, and last_seen makes it "+
			"a proven one", socket)
	}
	for _, a := range reloaded.SelectDialTargets(8, nil, nil) {
		if a == socket {
			t.Fatalf("the observed socket %s is a dial target after a restart", socket)
		}
	}
}

// TestClaimingAnObservedSocketMakesItDialableAgain pins the rule that keeps
// that fix from being a trap for an honest peer: a node that dials out from
// the port it also listens on is first seen as an observed socket, and would
// otherwise stay undialable for as long as its entry lived. A claim — a
// `hello`'s ListenAddr, a `peers` frame, the operator's own list — is what
// makes an address a candidate, so it clears the flag.
//
// It confers nothing else. The rejected alternative, letting the claim also
// (re)stamp the entry's teller, would let an inbound peer relabel an
// operator's address into its own cohort; Src is stamped once at creation and
// this test would give the same answer either way, so the assertion below is
// on candidacy alone and TestFirstTellerWinsOnReGossip holds the other half.
func TestClaimingAnObservedSocketMakesItDialableAgain(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const addr = "198.51.100.9:8333"
	ps.MarkConnected(addr)
	if got := ps.SelectDialTargets(8, nil, nil); len(got) != 0 {
		t.Fatalf("setup: an observed-only socket is already a dial target, so this test would "+
			"pass without the claim doing anything; selected=%v", got)
	}
	ps.AddFrom(addr, "203.0.113.1:8333")
	got := ps.SelectDialTargets(8, nil, nil)
	if len(got) != 1 || got[0] != addr {
		t.Fatalf("a peer that listens on the port it dialled out from is still undialable "+
			"after its listen address was claimed; selected=%v", got)
	}
}

// TestOrdinaryConnectionActivityDoesNotRestoreAnObservedSocket pins the half of
// the rule that the other tests leave open, and that production hits on every
// inbound connection: only a *claim* clears Peer.observed, and the ordinary
// traffic of a live inbound connection is not a claim.
//
// It matters because the non-strict admitters are not called once. Engine.Handle
// calls Adjust(peerAddr, ...) for every scored message, and peerAddr for an
// inbound peer is the ephemeral socket — so a rule that un-observed an entry on
// any touch rather than on a strict one would restore candidacy after a single
// message, and a filter that exempted a socket with a non-zero score would do
// the same as soon as the peer said anything useful. Both were confirmed to
// leave every other test in this family green.
func TestOrdinaryConnectionActivityDoesNotRestoreAnObservedSocket(t *testing.T) {
	ps, err := p2p.NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const socket = "198.18.7.7:40000"
	const claimed = "198.51.100.9:8333"
	ps.Add(claimed)
	ps.MarkConnected(socket)

	// Exactly what a live inbound connection does to its own socket entry: it
	// is scored for the messages it sends, and it can be marked failed. None of
	// it asserts the address is a listen address.
	ps.Adjust(socket, 5)
	ps.MarkConnected(socket)
	ps.MarkFailed(socket)
	ps.Adjust(socket, 5)

	got := ps.SelectDialTargets(8, nil, nil)
	// Anti-vacuity: the claimed address must be selected, or "the socket is
	// absent" would be satisfied by an empty candidate set.
	if len(got) != 1 || got[0] != claimed {
		t.Fatalf("the claimed listen address is not the sole dial target, so this test cannot "+
			"tell a barred socket from an empty selection; selected=%v", got)
	}
	if p, ok := ps.Get(socket); !ok || p.Score <= 0 {
		t.Fatalf("setup: the socket entry is absent or carries no positive score, so this test "+
			"does not exercise a scored observed entry; peer=%+v ok=%v", p, ok)
	}
}
