package pow_test

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/ssz"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// The key schedule is the half of RandomX that is consensus rather than
// cryptography: two nodes that disagree about which key a height uses compute
// different digests from the same header and fork, without either of them
// having done anything wrong. So it is arithmetic, and it is tested as
// arithmetic — against the boundaries it is defined by, not against a snapshot
// of what the code happens to return.

// TestSeedEpochForShiftsTheBoundaryByTheLag pins the exact heights at which
// the epoch changes, on both parameter sets.
//
// The lag is the whole content of the rule. Without it the boundary would sit
// at multiples of the interval; with it the boundary is at multiples of the
// interval *plus the lag*, which is what makes the key for any height settled
// long before that height can be mined. Every row here fails if the lag is
// dropped from the expression, and the rows straddling each boundary fail if
// it is added on the wrong side.
func TestSeedEpochForShiftsTheBoundaryByTheLag(t *testing.T) {
	for _, net := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"devnet", spec.Devnet()},
	} {
		t.Run(net.name, func(t *testing.T) {
			p := net.p
			interval, lag := p.RandomXKeyInterval, p.RandomXKeyLag

			cases := []struct {
				height uint64
				want   uint64
				why    string
			}{
				{0, 0, "genesis, which carries no proof of work at all"},
				{lag, 0, "at the lag but still inside the first interval"},
				{interval, 0, "at the interval but below the shifted boundary"},
				{interval + lag - 1, 0, "the last height of epoch 0"},
				{interval + lag, 1, "the first height of epoch 1"},
				{2*interval + lag - 1, 1, "the last height of epoch 1"},
				{2*interval + lag, 2, "the first height of epoch 2"},
				{7*interval + lag, 7, "a boundary well past the first two"},
				{7*interval + lag - 1, 6, "one below it"},
			}
			for _, c := range cases {
				if got := pow.SeedEpochFor(c.height, p); got != c.want {
					t.Errorf("height %d (%s): epoch %d, want %d",
						c.height, c.why, got, c.want)
				}
			}
		})
	}
}

// TestSeedEpochForReKeysExactlyOncePerInterval sweeps a range of heights and
// asserts the schedule does what its name says: the epoch never goes
// backwards, never jumps by more than one, and every completed epoch is
// exactly RandomXKeyInterval blocks wide.
//
// The width assertion is the one that matters. A rule that changes the epoch
// at the right *heights* but changes it twice, or skips one, still re-keys at
// the wrong rate — which is the failure Validate's lag-below-interval check
// exists to make unreachable, measured here from the other side.
func TestSeedEpochForReKeysExactlyOncePerInterval(t *testing.T) {
	p := spec.Devnet() // the small interval is what makes a sweep affordable
	interval, lag := p.RandomXKeyInterval, p.RandomXKeyLag

	const epochsToCross = 6
	last := pow.SeedEpochFor(0, p)
	transitions := make([]uint64, 0, epochsToCross)

	for h := uint64(1); h <= epochsToCross*interval+lag; h++ {
		got := pow.SeedEpochFor(h, p)
		switch {
		case got == last:
		case got == last+1:
			transitions = append(transitions, h)
			last = got
		default:
			t.Fatalf("height %d: epoch jumped %d -> %d; the schedule must "+
				"advance by exactly one or not at all", h, last, got)
		}
	}

	// Anti-vacuity: a sweep that crossed no boundary proves nothing, and a
	// off-by-one in the loop bound is exactly how that happens silently.
	if len(transitions) != epochsToCross {
		t.Fatalf("crossed %d boundaries over %d epochs of heights; the sweep "+
			"is not measuring what it claims to",
			len(transitions), epochsToCross)
	}
	for i, h := range transitions {
		if want := uint64(i+1)*interval + lag; h != want {
			t.Errorf("boundary %d at height %d, want %d", i+1, h, want)
		}
	}
	for i := 1; i < len(transitions); i++ {
		if w := transitions[i] - transitions[i-1]; w != interval {
			t.Errorf("epoch %d is %d blocks wide, want %d", i, w, interval)
		}
	}
}

// TestKeyForIsConstantWithinAnEpochAndChangesAtEveryBoundary is the property
// the engine actually depends on: a cache built for one epoch stays valid for
// every height in it, and is never silently reused across a boundary.
func TestKeyForIsConstantWithinAnEpochAndChangesAtEveryBoundary(t *testing.T) {
	p := spec.Devnet()
	interval, lag := p.RandomXKeyInterval, p.RandomXKeyLag

	seen := map[types.Hash]uint64{}
	for epoch := uint64(0); epoch < 5; epoch++ {
		var first uint64
		if epoch > 0 {
			first = epoch*interval + lag
		}
		key := pow.KeyFor(first, p)

		// Constant across the whole epoch.
		for _, h := range []uint64{first, first + 1, first + interval/2, first + interval - 1} {
			if got := pow.KeyFor(h, p); got != key {
				t.Fatalf("epoch %d: height %d has a different key from height %d",
					epoch, h, first)
			}
		}
		// And never equal to any earlier epoch's.
		if prev, dup := seen[key]; dup {
			t.Fatalf("epoch %d has the same key as epoch %d", epoch, prev)
		}
		seen[key] = epoch
	}
}

// TestKeyForSeparatesNetworks: work done on one chain is worth nothing on
// another at the same height, even when the two parameter sets are otherwise
// identical — which is exactly the configuration a public testnet mirroring
// mainnet runs in, and the one where an accidental collision would be worth
// real money.
func TestKeyForSeparatesNetworks(t *testing.T) {
	a := *spec.Mainnet()
	b := *spec.Mainnet()
	b.ChainID = a.ChainID + 1

	for _, h := range []uint64{0, 1, a.RandomXKeyInterval + a.RandomXKeyLag, 10_000_000} {
		if pow.KeyFor(h, &a) == pow.KeyFor(h, &b) {
			t.Fatalf("height %d: two chain ids produced the same work key", h)
		}
	}
}

// TestKeyForMatchesItsIndependentDerivation re-derives the key from the domain
// tag and the two integers, rather than recording what the function returned.
// A snapshot would pass for any derivation at all, including the wrong one; a
// second implementer is measured by this, so it has to state the preimage.
func TestKeyForMatchesItsIndependentDerivation(t *testing.T) {
	for _, net := range []*params.Params{spec.Mainnet(), spec.Devnet()} {
		for _, h := range []uint64{0, 1, net.RandomXKeyLag, net.RandomXKeyInterval,
			net.RandomXKeyInterval + net.RandomXKeyLag, 3*net.RandomXKeyInterval + net.RandomXKeyLag} {

			epoch := pow.SeedEpochFor(h, net)
			preimage := append(ssz.Uint64(net.ChainID), ssz.Uint64(epoch)...)
			want := crypto.Sum(crypto.TagPoWKey, preimage)

			if got := pow.KeyFor(h, net); got != want {
				t.Fatalf("%s height %d: key %x, want blake3(%q ‖ le64(%d) ‖ le64(%d)) = %x",
					net.Name, h, got, crypto.TagPoWKey, net.ChainID, epoch, want)
			}
		}
	}
}

// TestTheScheduleIsTotal: CheckWork's whole reason for deriving the key from
// the height is that it can always do so. A height the arithmetic panics on,
// or underflows at, would put that back — so the degenerate ends are asserted
// rather than assumed.
func TestTheScheduleIsTotal(t *testing.T) {
	p := spec.Mainnet()
	for h := uint64(0); h <= p.RandomXKeyLag+1; h++ {
		if e := pow.SeedEpochFor(h, p); e != 0 {
			t.Fatalf("height %d below the first boundary reports epoch %d", h, e)
		}
		pow.KeyFor(h, p)
	}
	// The top of the range: no wrap, and the epoch is what the division says.
	top := pow.SeedEpochFor(math.MaxUint64, p)
	if want := (math.MaxUint64 - p.RandomXKeyLag) / p.RandomXKeyInterval; top != want {
		t.Fatalf("epoch at MaxUint64 is %d, want %d", top, want)
	}
	pow.KeyFor(math.MaxUint64, p)
}

// TestTheSolverAgreesWithCheckWork is the guard on the one duplication in this
// package.
//
// Solver.Try and CheckWork answer the same question by different routes: Try
// reuses a precomputed seed and writes the nonce into a buffer, CheckWork
// rebuilds the whole input from the header. That duplication is what makes the
// nonce loop affordable, and it is also how a miner comes to produce headers
// its own network rejects — the failure would look like every block this node
// mines being orphaned, with nothing logged anywhere.
//
// Driven across the seam that matters: nonces at both ends of uint64 and around
// the byte boundaries of the little-endian encoding, where a truncated write
// would show up.
func TestTheSolverAgreesWithCheckWork(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  p.RandomXKeyInterval + p.RandomXKeyLag, // past a key boundary
		Time:    1000,
		Target:  p.GenesisTarget,
	}
	// The boundaries of the 32-bit nonce space (types.PoWSeal), plus the byte
	// and half-word edges the blob's little-endian writes cross. The top two
	// matter most: they are the values a solver that still wrote eight bytes,
	// or wrote them at the wrong offset, would disagree with the rule about.
	nonces := []uint32{
		0, 1, 2, 255, 256, 65535, 65536,
		1 << 23, 1 << 24, 1 << 31,
		math.MaxUint32 - 1, math.MaxUint32,
	}
	// A contiguous run on top of the boundaries, because the boundaries alone
	// do not reach a solution. At MaxTarget roughly one nonce in thirty-four
	// solves, and all twelve values above miss — so without this run the true
	// arm of the comparison is never taken at either target and the whole
	// test degenerates to `false == false`. 256 is far more than enough to
	// make that essentially impossible while staying instant against pow.Dev;
	// the anti-vacuity check below is what actually holds the property, so a
	// future engine change that moved the rate cannot silently re-hollow it.
	for n := uint32(0); n < 256; n++ {
		nonces = append(nonces, n)
	}

	// **Both targets, and the second one is what makes this test bite.**
	//
	// At GenesisTarget no nonce in the list satisfies the rule, so `viaRule`
	// and `viaSolver` are both false at every one of them and the comparison
	// is `false == false`. That is a test which passes however the solver is
	// broken: measured directly, a Try that wrote the nonce at the old offset
	// 32, and a Try that read the digest big-endian while CheckWork read it
	// little-endian, BOTH survived this test when it ran at GenesisTarget
	// alone. It agreed with the rule by never reaching a solution on either
	// route.
	//
	// MaxTarget is where essentially every nonce solves, so the true arm is
	// exercised too and a divergence between the two routes has somewhere to
	// show. Keeping both is the point: one target proves they agree on
	// rejection, the other that they agree on acceptance, and a solver only
	// has to disagree on one of the two to hand a miner blocks its own
	// network refuses.
	for _, target := range []struct {
		name string
		t    u256.U256
	}{
		{"GenesisTarget", p.GenesisTarget},
		{"MaxTarget", p.MaxTarget},
	} {
		h.Target = target.t
		s := pow.NewSolver(pow.Dev{}, h, p)

		var solved int
		for _, nonce := range nonces {
			h.PoW.Nonce = nonce
			// The solver returns the digest as well as the verdict, because
			// the digest is a header field now. Writing it into the header
			// before calling CheckWork is what an honest miner does, and it is
			// what keeps this a comparison of the TARGET rule on both routes
			// rather than a comparison of "did the miner fill the field in".
			//
			// It is taken from the solver deliberately, even though CheckWork
			// would recompute it: the whole hazard this test guards is the two
			// routes drifting, and re-deriving the digest here with a third
			// call would hide a solver that computed the commitment over the
			// wrong digest. If the solver's digest is wrong, CheckWork's
			// identity half rejects the header and the verdicts disagree —
			// which is exactly the signal wanted.
			digest, viaSolver := s.TryHash(nonce)
			h.PoWHash = digest
			viaRule := pow.CheckWork(pow.Dev{}, h, p) == nil
			if viaRule {
				solved++
			}
			if viaSolver != viaRule {
				t.Fatalf("%s, nonce %d: solver says %v, CheckWork says %v",
					target.name, nonce, viaSolver, viaRule)
			}
		}

		// Anti-vacuity, stated per target rather than assumed: at MaxTarget the
		// list must contain a solution, or the run above compared false against
		// false at every nonce and measured nothing at all.
		if target.name == "MaxTarget" && solved == 0 {
			t.Fatal("no nonce in the list solves at MaxTarget, so the agreement " +
				"between the two routes was only ever checked on rejection and a " +
				"solver that accepts what the rule refuses would pass this test")
		}
	}
}

// TestACloneSolvesIndependently drives two clones CONCURRENTLY, because that
// is the only regime in which the property means anything.
//
// A parallel miner gives each worker its own Solver, and Try writes the nonce
// into the solver's own buffer. A Clone that shared the buffer would have
// workers overwriting each other's nonce: hashes computed for nonces nobody
// searched, and a "solution" reported at a nonce that does not satisfy the
// target — a miner producing headers its own network rejects.
//
// Be precise about what catches that, because the first version of this test
// ran the two solvers one after the other and a shared buffer passed it
// cleanly. Sequential use of a shared buffer is harmless. What catches it is
// the RACE DETECTOR, and `make race` runs this package; the value corruption
// is real but probabilistic and would make a flaky test rather than a failing
// one. Mutation-checked: making Clone share the buffer is reported by -race
// here and is invisible without it.
func TestACloneSolvesIndependently(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{Version: types.HeaderVersion, Height: 7, Time: 9, Target: p.GenesisTarget}
	base := pow.NewSolver(pow.Dev{}, h, p)

	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := base.Clone()
			for i := uint32(0); i < 256; i++ {
				// Each worker walks its own high region, so the clones are
				// genuinely testing different nonces rather than racing over
				// one range. The shift is 20 rather than 40 because the nonce
				// is 32 bits now; a 40-bit shift would collapse every worker
				// onto region zero and the test would pass while measuring
				// nothing.
				nonce := uint32(w)<<20 | i
				digest, got := s.TryHash(nonce)

				hh := h
				hh.PoW.Nonce = nonce
				// The digest the clone computed, written into the header the
				// rule is then asked about — see TestTheSolverAgreesWithCheckWork
				// for why it is taken from the solver rather than re-derived.
				// Here it carries a second load: a Clone that shared its
				// buffer with the base solver would compute the digest of some
				// other worker's nonce, and the rule would refuse the header
				// for a mismatch rather than merely disagreeing about the
				// target — a louder failure for the same defect.
				hh.PoWHash = digest
				if want := pow.CheckWork(pow.Dev{}, hh, p) == nil; got != want {
					errs <- fmt.Errorf("worker %d nonce %d: solver %v, rule %v", w, nonce, got, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// recordingEngine is a Dev engine that remembers which keys it was told to keep
// warm and which keys it was actually asked to hash under.
//
// Both halves matter: the value of the announcement is that it names the SAME
// key the solver then hashes with, and an announcement that drifted from it
// would point a keyed engine's fast path at the wrong epoch — which is the
// prefetch/mining-key collision with the sign flipped.
type recordingEngine struct {
	mu       sync.Mutex
	told     []types.Hash
	hashedAt []types.Hash
}

func (r *recordingEngine) Name() string { return pow.Dev{}.Name() }

func (r *recordingEngine) Hash(key types.Hash, input []byte) types.Hash {
	r.mu.Lock()
	r.hashedAt = append(r.hashedAt, key)
	r.mu.Unlock()
	return pow.Dev{}.Hash(key, input)
}

func (r *recordingEngine) MineOn(key types.Hash) {
	r.mu.Lock()
	r.told = append(r.told, key)
	r.mu.Unlock()
}

// TestTheSolverTellsAKeyedEngineWhichKeyItWillHammer.
//
// RandomX keeps one ~2 GiB dataset and it can hold one key at a time, so the
// engine has to be told which key that is; nothing else in the tree hashes the
// same key more than a handful of times, and nothing else can justify the
// fill. Building a Solver is the moment that intent exists, so it is where the
// announcement is made.
//
// The property is not "MineOn was called" — it is that the key announced is
// exactly the key the solver then hashes under, at every height including the
// ones either side of a boundary. An engine told about one epoch and asked
// about another would answer correctly and slowly if it is honest about its
// fast path, and would be the prefetch/mining-key collision all over again if
// it is not.
func TestTheSolverTellsAKeyedEngineWhichKeyItWillHammer(t *testing.T) {
	p := spec.Devnet()
	boundary := p.RandomXKeyInterval + p.RandomXKeyLag

	var e recordingEngine
	var epochs []uint64
	for _, height := range []uint64{1, boundary - 1, boundary, boundary + 1, 4 * boundary} {
		e.mu.Lock()
		e.told, e.hashedAt = nil, nil
		e.mu.Unlock()

		h := types.Header{
			Version: types.HeaderVersion,
			Height:  height,
			Time:    1000,
			Target:  p.GenesisTarget,
		}
		s := pow.NewSolver(&e, h, p)
		s.Try(7)

		want := pow.KeyFor(height, p)
		if len(e.told) != 1 {
			t.Fatalf("height %d: the engine was told about %d keys, want exactly one "+
				"per candidate block", height, len(e.told))
		}
		if e.told[0] != want {
			t.Fatalf("height %d: the engine was told to warm %x, the schedule gives %x",
				height, e.told[0][:8], want[:8])
		}
		if len(e.hashedAt) == 0 {
			t.Fatalf("height %d: the solver hashed nothing, so this proves nothing", height)
		}
		for i, k := range e.hashedAt {
			if k != e.told[0] {
				t.Fatalf("height %d: attempt %d hashed under %x, the engine was told "+
					"to warm %x: the announcement and the search disagree about the epoch",
					height, i, k[:8], e.told[0][:8])
			}
		}
		epochs = append(epochs, pow.SeedEpochFor(height, p))
	}

	// Anti-vacuity: a run that never left epoch 0 would pass with an
	// announcement hard-coded to the genesis key.
	distinct := map[uint64]bool{}
	for _, ep := range epochs {
		distinct[ep] = true
	}
	if len(distinct) < 2 {
		t.Fatalf("every height tested sat in the same epoch (%v); the test cannot "+
			"see an announcement that ignores the height", epochs)
	}
}

// TestAnEngineWithNoFastPathIsUnaffected. The announcement is an optional
// interface and pow.Dev does not implement it, which is the case every test
// and every devnet in this tree runs. It must stay a no-op rather than a
// requirement, because which representations an engine keeps warm is not a
// consensus fact and must never become one.
func TestAnEngineWithNoFastPathIsUnaffected(t *testing.T) {
	if _, ok := pow.Engine(pow.Dev{}).(pow.HotKeyEngine); ok {
		t.Fatal("pow.Dev implements HotKeyEngine; this test no longer covers the " +
			"engine that does not")
	}
	p := spec.Devnet()
	h := types.Header{Version: types.HeaderVersion, Height: 5, Time: 9, Target: p.GenesisTarget}
	s := pow.NewSolver(pow.Dev{}, h, p)
	h.PoW.Nonce = 3
	if got, want := s.Try(3), pow.CheckWork(pow.Dev{}, h, p) == nil; got != want {
		t.Fatalf("solver says %v, the rule says %v", got, want)
	}
}

// TestTheScheduleIsTotalAtTheExtremesValidateAccepts is TestTheScheduleIsTotal
// over the parameter sets nobody ships and everybody may configure.
//
// The property: for every (interval, lag) pair Params.Validate accepts,
// SeedEpochFor returns 0 for every height below the first boundary and the
// quotient above it — never a wrapped value, at any height including 0 and
// MaxUint64.
//
// TestTheScheduleIsTotal already sweeps the degenerate *heights*; what it
// cannot see is the degenerate *parameters*, because it runs on mainnet's
// 2048/64 where interval+lag is nowhere near the top of uint64. That is
// exactly where the wrapped-boundary defect lived: the guard was one
// addition, the addition wrapped, and the wrapped guard admitted height 0
// into the division it exists to keep height 0 out of. The rows below are
// chosen against Validate's own frontier rather than against round numbers:
// interval = MaxUint64-lag is the largest pair Validate now accepts, and the
// pair one step past it is the one it refuses (asserted in core/params,
// TestValidateRefusesAKeyScheduleBoundary- ThatCannotBeWrittenDown) and which
// this function must survive anyway.
func TestTheScheduleIsTotalAtTheExtremesValidateAccepts(t *testing.T) {
	for _, c := range []struct {
		name     string
		interval uint64
		lag      uint64
		// valid records whether Params.Validate accepts the pair. The
		// overflowing pair is included precisely because it does not: this
		// function states a property about its own arithmetic and must not
		// borrow it from a validator that may not have run.
		valid bool
	}{
		{"mainnet", 2048, 64, true},
		{"smallest schedule", 2, 1, true},
		{"lag one below the interval", 1 << 40, 1<<40 - 1, true},
		{"largest sum Validate accepts", math.MaxUint64 - 1, 1, true},
		{"largest interval with a large lag", math.MaxUint64 - (1 << 32), 1 << 32, true},
		{"the pair whose sum wraps, which Validate now refuses", math.MaxUint64, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := spec.Devnet()
			p.RandomXKeyInterval, p.RandomXKeyLag = c.interval, c.lag
			if got := p.Validate() == nil; got != c.valid {
				t.Fatalf("Validate accepted=%v, want %v (err %v)", got, c.valid, p.Validate())
			}
			// Below the first boundary the epoch is 0. The boundary is
			// interval+lag, computed here in a width the sum cannot wrap in so
			// that the test does not repeat the defect it is pinning.
			boundary := new(big.Int).Add(
				new(big.Int).SetUint64(c.interval), new(big.Int).SetUint64(c.lag))
			for _, h := range heightsAround(c.interval, c.lag) {
				got := pow.SeedEpochFor(h, p)
				var want uint64
				if new(big.Int).SetUint64(h).Cmp(boundary) >= 0 {
					want = (h - c.lag) / c.interval
				}
				if got != want {
					t.Fatalf("height %d: epoch %d, want %d (interval %d lag %d)",
						h, got, want, c.interval, c.lag)
				}
				pow.KeyFor(h, p)
			}
		})
	}
}

// heightsAround returns the heights worth asking about for one schedule: the
// bottom of the range, the neighbourhood of the lag and of the boundary, and
// the top of uint64. Each is produced with saturating arithmetic so that the
// generator cannot wrap where the function under test must not.
func heightsAround(interval, lag uint64) []uint64 {
	hs := []uint64{0, 1, math.MaxUint64, math.MaxUint64 - 1}
	for _, base := range []uint64{lag, satAdd(interval, lag), interval} {
		for _, d := range []int{-1, 0, 1} {
			switch {
			case d < 0 && base == 0:
			case d < 0:
				hs = append(hs, base-1)
			case d == 0:
				hs = append(hs, base)
			default:
				hs = append(hs, satAdd(base, 1))
			}
		}
	}
	return hs
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
