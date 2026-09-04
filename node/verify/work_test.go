package verify_test

import (
	"sync"
	"testing"

	pparams "zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/verify"
	"zycord/spec"
)

// countingEngine reports how many times the work function was actually
// evaluated. Without it every test here would pass against a cache that caches
// nothing, which is the whole property under test.
type countingEngine struct {
	mu sync.Mutex
	n  int
	e  pow.Engine
}

func (c *countingEngine) Name() string { return c.e.Name() }
func (c *countingEngine) Hash(key types.Hash, in []byte) types.Hash {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.e.Hash(key, in)
}
func (c *countingEngine) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func solved(t *testing.T, e pow.Engine, p *pparams.Params, height uint64) types.Header {
	t.Helper()
	h := types.Header{Version: types.HeaderVersion, Height: height, Time: 1000 + height, Target: p.GenesisTarget}
	if !pow.Solve(e, &h, p, 1<<20) {
		t.Fatalf("could not solve height %d", height)
	}
	return h
}

// TestTheSameHeaderIsHashedOnce is the point of the type. A block relayed
// hash-first is verified twice today — once as an announcement, once when its
// body lands — and at RandomX's cost that duplicate is real money.
func TestTheSameHeaderIsHashedOnce(t *testing.T) {
	p := spec.Devnet()
	ce := &countingEngine{e: pow.Dev{}}
	h := solved(t, pow.Dev{}, p, 1)

	c := verify.NewWorkCache(64)
	before := ce.count()
	for i := 0; i < 10; i++ {
		if err := c.Check(ce, h, p); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if got := ce.count() - before; got != 1 {
		t.Fatalf("the work function ran %d times for one header; the cache is "+
			"not caching", got)
	}
}

// TestAFailedVerdictIsCachedToo: a peer re-presenting the same invalid header
// is precisely the case worth making cheap.
func TestAFailedVerdictIsCachedToo(t *testing.T) {
	p := spec.Devnet()
	ce := &countingEngine{e: pow.Dev{}}
	bad := types.Header{Version: types.HeaderVersion, Height: 1, Time: 1001,
		Target: u256.One} // no nonce meets this

	c := verify.NewWorkCache(64)
	first := c.Check(ce, bad, p)
	if first == nil {
		t.Fatal("setup: the header happens to satisfy an impossible target")
	}
	n := ce.count()
	for i := 0; i < 5; i++ {
		if err := c.Check(ce, bad, p); err != first {
			t.Fatalf("attempt %d returned a different verdict: %v", i, err)
		}
	}
	if ce.count() != n {
		t.Fatalf("the work function ran again for a header already refused")
	}
}

// TestTheCacheIsBounded: an unbounded map keyed by anything a peer can generate
// is a memory exhaustion primitive.
func TestTheCacheIsBounded(t *testing.T) {
	p := spec.Devnet()
	c := verify.NewWorkCache(8)
	for i := uint64(1); i <= 64; i++ {
		h := types.Header{Version: types.HeaderVersion, Height: i, Time: 1000 + i,
			Target: p.GenesisTarget}
		c.Check(pow.Dev{}, h, p)
		if n := c.Len(); n > 8 {
			t.Fatalf("after %d headers the cache holds %d verdicts, bound is 8", i, n)
		}
	}
}

// TestDistinctHeadersAreEachHashed is the anti-vacuity twin of the first test,
// and the honesty check on what this type does NOT do. A flood of DISTINCT
// headers that reach the work function pays in full, every time; the cache is
// not a defence against it and nothing here should let a reader believe
// otherwise.
//
// **The target is u256.Max and that is now load-bearing rather than
// incidental.** Under the commitment rule, pow.CheckWork answers a header whose
// commitment misses the target WITHOUT evaluating the work function at all —
// that is the whole point of the 32 bytes the header grew. At GenesisTarget
// essentially every header here misses, so this loop would count zero
// evaluations and the test would fail for a reason that is a feature. At
// u256.Max every commitment passes, every header reaches the engine, and the
// count means what the assertion says it means.
//
// The property that moved is worth naming because it changes what this type is
// for. A flood of distinct headers used to cost one full evaluation each,
// unavoidably; it now costs one BLAKE2b each unless the sender did the work,
// and the cache's job has narrowed to REPEATS of headers that pass the
// commitment. TestAFloodOfDistinctJunkCostsNoEvaluations below is the other
// half of that statement.
func TestDistinctHeadersAreEachHashed(t *testing.T) {
	p := spec.Devnet()
	ce := &countingEngine{e: pow.Dev{}}
	c := verify.NewWorkCache(1024)

	// The headers are sealed FIRST, with an engine the count does not watch,
	// so that the loop below measures only what Check spends. An honest header
	// carries the digest of its own blob; without it the identity half refuses
	// and the count would be right for the wrong reason.
	const n = 32
	headers := make([]types.Header, 0, n)
	for i := uint64(1); i <= n; i++ {
		h := types.Header{Version: types.HeaderVersion, Height: 1, Time: 1000 + i,
			Target: u256.Max}
		h.PoWHash = pow.Dev{}.Hash(pow.KeyFor(h.Height, p), h.PoWInput())
		headers = append(headers, h)
	}
	for _, h := range headers {
		if err := c.Check(ce, h, p); err != nil {
			t.Fatalf("a header sealed against u256.Max was refused: %v", err)
		}
	}
	if got := ce.count(); got != n {
		t.Fatalf("%d distinct headers cost %d evaluations; they must each cost "+
			"one, or this test is measuring collisions rather than caching",
			n, got)
	}
}

// TestAFloodOfDistinctJunkCostsNoEvaluations states the asymmetry the header's
// 32-byte growth was traded for, as an executable claim rather than as prose in
// a decision record.
//
// Distinct headers with no work done on them — the cheapest thing an attacker
// can generate, and the case the work-memo cache explicitly does NOT defend
// against — must now cost ZERO evaluations of the work function, because their
// commitments miss the target and pow.CheckWork answers from the header alone.
//
// The contrast with the test above is the measurement: same count, same cache,
// same engine, and the only difference is whether the target admits them.
func TestAFloodOfDistinctJunkCostsNoEvaluations(t *testing.T) {
	p := spec.Devnet()
	ce := &countingEngine{e: pow.Dev{}}
	c := verify.NewWorkCache(1024)

	const n = 32
	var refused int
	for i := uint64(1); i <= n; i++ {
		h := types.Header{Version: types.HeaderVersion, Height: 1, Time: 1000 + i,
			Target: p.GenesisTarget}
		if c.Check(ce, h, p) != nil {
			refused++
		}
	}
	// ANTI-VACUITY: if the headers had been accepted, "no evaluations" would
	// mean the rule was not being applied rather than that it was applied
	// cheaply.
	if refused != n {
		t.Fatalf("%d of %d junk headers were accepted; the zero-evaluation claim "+
			"below would then be a claim that nothing was checked", n-refused, n)
	}
	if got := ce.count(); got != 0 {
		t.Fatalf("%d distinct headers with no work done on them cost %d "+
			"evaluations of the work function, want 0: the commitment rule is not "+
			"short-circuiting, and the 32 bytes the header grew bought nothing",
			n, got)
	}
}

// TestConcurrentCheckersAgree drives the path the node actually uses: the
// gossip engine, the sync driver and the miner share one cache.
func TestConcurrentCheckersAgree(t *testing.T) {
	p := spec.Devnet()
	h := solved(t, pow.Dev{}, p, 3)
	c := verify.NewWorkCache(64)

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Check(pow.Dev{}, h, p); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent check disagreed: %v", err)
	}
}
