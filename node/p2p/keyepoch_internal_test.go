package p2p

import (
	"strings"
	"sync"
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// epochCountingPoW records the DISTINCT keys the work function is asked to
// evaluate under.
//
// Counting hashes is not enough for this property. A RandomX key is a cache
// initialisation — ~0.54 s from `core/pow/randomx`'s own BenchmarkInitCache,
// cross-checked against the 574.9 ms cold reading randomx.go records — and a
// hash under an already-held key is 15–25 ms depending on the machine, so the
// quantity an attacker amplifies is the number of distinct keys one message
// demands, not the number of digests. countingPoW next door measures the
// digests; this measures the price.
//
// (This comment said "~1.7 s on the machine core/pow/randomx records". That
// machine records 574.9 ms. See the constants in flood_internal_test.go.)
type epochCountingPoW struct {
	mu    sync.Mutex
	keys  []types.Hash
	seen  map[types.Hash]bool
	total int
}

func newEpochCounter() *epochCountingPoW {
	return &epochCountingPoW{seen: make(map[types.Hash]bool)}
}

func (c *epochCountingPoW) Name() string { return pow.Dev{}.Name() }
func (c *epochCountingPoW) Hash(key types.Hash, in []byte) types.Hash {
	c.mu.Lock()
	c.total++
	if !c.seen[key] {
		c.seen[key] = true
		c.keys = append(c.keys, key)
	}
	c.mu.Unlock()
	return pow.Dev{}.Hash(key, in)
}

// hashes is how many times the work function was actually evaluated, which
// distinguishes a check that refused a header from one that never reached it.
func (c *epochCountingPoW) hashes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

func (c *epochCountingPoW) distinctKeys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// sawKey reports whether one particular key was among them.
//
// distinctKeys counts; this identifies. The difference matters exactly once,
// and it is the difference between a cost and no cost: a key the node ALREADY
// HOLDS is a 15–55 ms hash, and a key it does not is a ~0.55 s cache
// initialisation. A test that only counts cannot tell the two apart, so it can
// report an epoch as forced when the engine would have served it from the
// table — which is how a thirty-fold cost becomes a twenty-fold one on paper
// without anything failing.
func (c *epochCountingPoW) sawKey(k types.Hash) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[k]
}

// TestOneBlockBodyCannotBuyManyKeyEpochs pins the structure-before-cost
// property: the number of DISTINCT proof-of-work key epochs one KindBlock
// message can force this node to initialise does not depend on the heights its
// sender chose for the headers it cites.
//
// The mechanism the property defends against: pow.KeyFor derives a key from a
// header's own height, so a citation at an arbitrary height names an arbitrary
// key epoch. The citation work loop used to run before any height rule, so one
// body carrying MaxCitesPerBlock citations at widely separated heights demanded
// 1 + MaxCitesPerBlock distinct epochs — for free, because nothing on this path
// bounds a DECLARED target, and unscored, because the verdict such a block
// finally earns is ErrOrphanOutOfWindow at score 0.
//
// Built on spec.Devnet() rather than devnetEasy(), deliberately. The free
// target here is the attacker's own declaration (u256.Max), not a parameter the
// harness relaxed; a harness that makes work free would be measuring itself
// (a scenario built from a uniform input cannot pin a rule that only
// fires on non-uniform input).
func TestOneBlockBodyCannotBuyManyKeyEpochs(t *testing.T) {
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

	work := newEpochCounter()
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")

	// The carrier: far from the tip, at a target no digest can exceed, so its
	// sender spent zero hashes on it.
	const carrierHeight = 1_000_000
	blk := &types.Block{Header: types.Header{
		Version:  types.HeaderVersion,
		Height:   carrierHeight,
		ParentID: types.Hash{0xab},
		Time:     p.GenesisTime + carrierHeight*p.TargetBlockSeconds,
		Target:   u256.Max,
		PoW:      types.PoWSeal{Nonce: 1, SeedEpoch: pow.SeedEpochFor(carrierHeight, p)},
	}}
	// Citations at heights in DIFFERENT key epochs. Citations a few blocks
	// apart share an epoch and would measure nothing at all.
	epochs := map[uint64]bool{pow.SeedEpochFor(carrierHeight, p): true}
	for i := uint64(1); i <= uint64(p.MaxCitesPerBlock); i++ {
		h := i * 7 * p.RandomXKeyInterval
		epochs[pow.SeedEpochFor(h, p)] = true
		blk.Cites = append(blk.Cites, &types.Header{
			Version:  types.HeaderVersion,
			Height:   h,
			ParentID: types.Hash{byte(i)},
			Time:     p.GenesisTime + h*p.TargetBlockSeconds,
			Target:   u256.Max,
			PoW:      types.PoWSeal{Nonce: uint32(i)},
		})
	}
	blk.Header.CertRoot = blk.ComputeCertRoot(p)
	blk.Header.CitesRoot = blk.ComputeCitesRoot(p)

	// Anti-vacuity 1: the scenario is only interesting if the citations really
	// do name distinct epochs. If the parameters ever make them collide, this
	// test measures nothing and must say so rather than pass.
	if len(epochs) < 2 {
		t.Fatalf("setup: the forged citations name %d key epoch(s); this test "+
			"can only measure amplification across at least 2", len(epochs))
	}
	// Anti-vacuity 2: every forged header must actually PASS pow.CheckWork, or
	// the citation loop would be refusing them on their own work rather than
	// never reaching them, and the test would be measuring the work check.
	//
	// Checked against a bare pow.Dev rather than against `work`, because
	// asking the instrument the question would seed it with every answer and
	// leave the measurement below reading zero either way.
	for i, h := range append([]*types.Header{&blk.Header}, blk.Cites...) {
		if err := pow.CheckWork(pow.Dev{}, *h, p); err != nil {
			t.Fatalf("setup: forged header %d does not pass CheckWork (%v); at "+
				"u256.Max no digest can exceed the target and it must", i, err)
		}
	}
	if n := work.distinctKeys(); n != 0 {
		t.Fatalf("setup: %d key epochs were already demanded before the message "+
			"was delivered; the count below would not be the message's", n)
	}

	v := e.OnBlock("attacker:1", blk.MarshalSSZ())
	t.Logf("verdict: score=%d err=%v", v.Score, v.Err)

	// The property. One message may cost at most the carrier's own epoch —
	// which this node has to hold anyway to judge the carrier — however many
	// citations it carries and wherever its sender put them.
	//
	// The rejected rule ("check the work of every citation, then let the fold's
	// height rule refuse the block") gives a different answer in this very
	// scenario: it demands 1 + MaxCitesPerBlock = 5 epochs, which is why the
	// bound is stated as 1 and not as len(blk.Cites)+1.
	//
	// Stated as equality, not as an upper bound: `> 1` would also pass if the
	// carrier's own header stopped being hashed at all, which would be a hole
	// rather than an improvement. Exactly one epoch — the carrier's — is the
	// property, and the residual that one epoch represents is the carrier's own
	// declared target, which is a separate matter.
	if got := work.distinctKeys(); got != 1 {
		t.Fatalf("one KindBlock message (%d bytes, zero hashes spent by its "+
			"sender) demanded %d distinct key epochs, want exactly 1 (the "+
			"carrier's own); a citation's height is the sender's to choose, so "+
			"anything above 1 is amplification it was never charged for, and "+
			"anything below it means the carrier went unhashed",
			len(blk.MarshalSSZ()), got)
	}

	// And the second half of the finding: *unscored*. The amplification was
	// free because the verdict such a block finally earned was
	// ErrOrphanOutOfWindow at score 0, so a bound on the epochs alone would
	// leave the flood merely cheaper rather than charged for.
	//
	// The error is asserted by identity, not just the score, because several
	// later refusals on this path also carry ScoreInvalidMessage: with the
	// may-not-cite rule removed this very message is refused by the orphan
	// pool's plausibility ceiling at the same score, and a test that read only
	// the score could not tell the two apart.
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("the message scored %d, want %d: an amplification refused for "+
			"free is still repeatable forever", v.Score, ScoreInvalidMessage)
	}
	if v.Err == nil || !strings.Contains(v.Err.Error(), "cites a header at height") {
		t.Fatalf("refused with %v, want the citation height rule; any other "+
			"refusal means the count above was bounded for some other reason", v.Err)
	}
}

// TestABlockAtHeightOneStillMayNotCiteGenesis pins the rule that carries the
// genesis-height free pass's second half after the structure-before-cost hoist
// replaced it.
//
// The old rule refused a genesis-height citation by name, because pow.CheckWork returns
// nil for a height-0 header before it even reads the target: a genesis-height
// citation is the one citation that costs its sender nothing at all, so a list
// of them is a list of free competitors. That named guard is gone, and the
// claim replacing it is that the height rule subsumes it. It does not subsume
// it everywhere. At a carrier height of 1, `cited.Height != Height-1` reads
// `0 != 0` and lets a genesis-height citation straight through to the work
// loop, where it passes for free. The rule that refuses it there is the
// may-not-cite rule, and this test is the only thing pinning that rule: the
// amplification tests above are built on a carrier a million blocks up, and
// they pass with the may-not-cite rule deleted.
//
// The rejected rule gives a different answer in this very scenario: with the
// height rule alone, this block is accepted past the citation stage carrying a
// header its sender never mined.
//
// core/fold's checkCites refuses the same block unconditionally ("block at
// height 1 may not cite"), so this is a refusal moved earlier and scored, not
// a new consensus rule.
func TestABlockAtHeightOneStillMayNotCiteGenesis(t *testing.T) {
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
	work := newEpochCounter()
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, work, "n:1")

	blk := &types.Block{Header: types.Header{
		Version:  types.HeaderVersion,
		Height:   1,
		ParentID: types.Hash{0xab},
		Time:     p.GenesisTime + p.TargetBlockSeconds,
		Target:   u256.Max,
		PoW:      types.PoWSeal{Nonce: 1, SeedEpoch: pow.SeedEpochFor(1, p)},
	}}
	blk.Cites = append(blk.Cites, &types.Header{
		Version:  types.HeaderVersion,
		Height:   0,
		ParentID: types.Hash{0x01},
		Time:     p.GenesisTime,
		Target:   u256.Max,
	})
	blk.Header.CertRoot = blk.ComputeCertRoot(p)
	blk.Header.CitesRoot = blk.ComputeCitesRoot(p)

	// Anti-vacuity: the citation must satisfy the height rule in this scenario,
	// or the may-not-cite rule is not the thing being measured.
	if blk.Cites[0].Height != blk.Header.Height-1 {
		t.Fatal("setup: the citation does not satisfy the height rule here, so " +
			"this test would pin the height rule rather than the may-not-cite rule")
	}
	// Anti-vacuity: and it must pass pow.CheckWork, which is the whole of the free
	// pass — a height-0 header passes before the target is read, for free.
	if err := pow.CheckWork(pow.Dev{}, *blk.Cites[0], p); err != nil {
		t.Fatalf("setup: the genesis-height citation does not pass CheckWork (%v); "+
			"the rule exists because it does", err)
	}

	v := e.OnBlock("attacker:1", blk.MarshalSSZ())
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("a block at height 1 citing a genesis-height header scored %d, "+
			"want %d: the sender is charged for a block the fold refuses "+
			"unconditionally", v.Score, ScoreInvalidMessage)
	}
	if v.Err == nil || !strings.Contains(v.Err.Error(), "may not cite") {
		t.Fatalf("refused with %v, want the may-not-cite rule; any other refusal "+
			"means this test passes for a reason other than the rule it names", v.Err)
	}
}
