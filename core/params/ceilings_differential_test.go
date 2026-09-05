// The block-ceiling scaling law, checked against a computation that cannot
// import this package.
//
// What the sixth external audit measured: both folds call ONE implementation
// of every ceiling, so the differential runner cannot see a ceiling change —
// SeqGasBurst was moved from 4T to 8T, B5's hard validity bound, and `go test
// ./spec` stayed green. The golden-vector corpus is not the second opinion
// either, because a vector records a parameter set by NAME and the name is
// resolved at replay back through the same shared function: for the ceilings
// the corpus is one computation performed twice rather than two computations
// compared.
//
// core/params/naive is the second computation. It is written from
// ARCHITECTURE §15's ceiling table, spec/README.md and spec/params.json's own
// notes, it reads the seven constants out of the raw parameter file through
// its own struct tags as string literals, and it carries its own exact 128-bit
// multiply-then-divide instead of u256.MulDiv64. `make check-imports` enforces
// that it cannot reach core/params or core/u256 by any path; without those two
// stanzas this file stops being evidence of anything.
package params_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/core/params/naive"
	"zycord/spec"
)

// ceilingSet is one point in the seven-dimensional space the scaling law is
// parameterised over, plus the one expectation about that point which a
// parameter change could silently invalidate.
type ceilingSet struct {
	name string
	raw  []byte
	// certClampReachable declares, before the test runs, whether
	// MaxCertsPerBlock's clamp to CertListCapacity can fire anywhere in T ∈ [0,
	// SeqGasCapacity]. It is not a derived convenience: it is FALSE for every
	// set params.Parse admits, because Validate pairs cert_list_capacity upward
	// the way it already paired the byte capacity — and that is exactly why the
	// sweep below cannot see a mutation to that clamp. The field is kept rather
	// than deleted because the declaration is what makes the blind spot visible:
	// a change that made the clamp reachable would have to say so here, and the
	// Validate rule that forbids it would have to have been removed first.
	certClampReachable bool
}

// ceilingSets is the parameter space the differential is driven over: the
// three embedded networks, the parameter set the current gas schedule
// superseded, and three synthetic sets chosen for the corners the shipped
// values do not occupy.
//
// The synthetic sets exist because three networks are three points, and the
// three have never been three distinct ones. Before the current gas schedule
// two carried identical ceiling constants; that change split mainnet away from
// testnet and devnet for a while; a later respin put all three back on one gas
// schedule, so mainnet and testnet are identical again and devnet differs only
// in max_certs_per_block_genesis. That is the whole reason the superseded set
// below is kept rather than deleted: the shipped networks cover LESS of the
// space than the count of them suggests, and a scaling law wrong only for
// values none of them holds would still survive an embedded-networks-only
// sweep — the same shape of blind spot the audit found, one level up.
//
// Every set goes through params.Parse, so every one is Validate-clean: the
// space swept here is the space the protocol admits, not an arbitrary one.
func ceilingSets(t *testing.T) []ceilingSet {
	t.Helper()
	sets := []ceilingSet{}
	for _, network := range spec.Networks() {
		raw, err := spec.RawFor(network)
		if err != nil {
			t.Fatalf("spec.RawFor(%q): %v", network, err)
		}
		sets = append(sets, ceilingSet{name: network, raw: raw})
	}
	mainnet, err := spec.RawFor("mainnet")
	if err != nil {
		t.Fatalf("spec.RawFor: %v", err)
	}
	sets = append(sets,
		// That parameter change has LANDED, so the set that used to
		// hold its pending values now holds the ones it superseded. The claim
		// that set was written to measure — "this computation does not need
		// editing when those land" — was answered when they landed:
		// core/params/naive names no parameter value at all and did not move.
		//
		// It is kept, pointed backwards, for two reasons. Seven parameter sets stay
		// seven: pointed forwards it is now byte-identical to the mainnet set and
		// the sweep would quietly lose a point. And the superseded pair is the one
		// corner NO shipped network occupies any more — testnet and devnet held it
		// until the respin moved them onto mainnet's schedule — in which the
		// parallel multiple is large (10) and the sequential target is high: the
		// combination every figure in the repository was measured at until the gas
		// schedule moved, so a scaling law that is right only for the new values is
		// caught here rather than in prose. §15's pairing holds on both sides,
		// 6,400,000 × 2,500,000 == 2,000,000 × 8,000,000, so Parse accepts it.
		ceilingSet{name: "mainnet+superseded-parameters", raw: withNumbers(t, mainnet, map[string]uint64{
			"par_gas_ratio":          10,
			"seq_gas_target_genesis": 2000000,
			"seq_gas_capacity":       6400000,
		})},
		// A certificate-list capacity sized against the DOMAIN rather than
		// against the end of §8.1's curve — the tight corner none of the shipped
		// networks occupies, where the count clamp sits just above the top of the
		// domain instead of 2,621× (mainnet) or 40,960× (devnet) above it. The
		// gas capacity is lowered with the byte capacity so §15's pairing still
		// holds and Parse still accepts the set — and lowered far, because the
		// domain is what this test costs.
		//
		// Until Validate began pairing cert_list_capacity upward, this set carried
		// cert_list_capacity = 5,000 and was the one point at which the count
		// clamp fired INSIDE the domain, declared below as certClampReachable.
		// That set is no longer admissible and could not be replaced by another:
		// Validate now requires cert_list_capacity × seq_gas_target_genesis ≥
		// max_certs_per_block_genesis × seq_gas_capacity, which is 6,400 here, so
		// no Validate-clean set reaches the clamp inside its own domain. What
		// replaced the coverage is the clamp-arithmetic targets in the second test
		// below, which run above the domain and never depended on a set reaching
		// it, and 12,800 — twice the pairing floor — keeps the first clamping
		// target at 1,920,001, a factor of two above the domain rather than
		// thousands.
		//
		// T₀ is 600,000 rather than a divisor of block_byte_limit_genesis, and
		// that was not the first choice: at 500,000 the byte ceiling is exactly
		// 5T at every target, its division never truncates, and the sweep's
		// anti-vacuity guard rejected the set. The guard was right — a set on
		// which one of the two floors is unreachable is a set that tests one
		// less thing than it appears to.
		ceilingSet{name: "synthetic/tight-cert-capacity", raw: withNumbers(t, mainnet, map[string]uint64{
			"cert_list_capacity":     12800,
			"seq_gas_target_genesis": 600000,
			"seq_gas_capacity":       960000,
			"block_byte_capacity":    4000000,
		})},
		// Constants that share no factors, so the floor in X × T / T₀ bites at
		// targets a round-numbered set never reaches. T₀ is prime, and the two
		// genesis ceilings are one above the round numbers mainnet uses.
		ceilingSet{name: "synthetic/coprime-constants", raw: withNumbers(t, mainnet, map[string]uint64{
			"max_certs_per_block_genesis": 4001,
			"block_byte_limit_genesis":    2500001,
			"seq_gas_target_genesis":      999983,
			"par_gas_ratio":               7,
			"seq_gas_capacity":            999983,
			"block_byte_capacity":         2500001,
		})},
		// The degenerate parallel multiple, where ParGasTarget(T) is T itself
		// and ParGasLimit(T) is SeqGasLimit(T). If the two parallel ceilings
		// were ever conflated with the two sequential ones, this is the set on
		// which the confusion is invisible — so it is the set that says the
		// others are doing the work.
		//
		// The two capacities are 1.2x their genesis ceilings rather than
		// mainnet's 3.2x, and they had to move when T₀ did: §15's pairing is a
		// cross-multiplication against seq_gas_target_genesis, so a set that
		// inherits mainnet's T0 and pins its own capacities stops parsing the
		// moment T0 moves. 1,920,000 / 1,600,000 == 3,000,000 / 2,500,000.
		ceilingSet{name: "synthetic/par-gas-ratio-one", raw: withNumbers(t, mainnet, map[string]uint64{
			"par_gas_ratio":       1,
			"seq_gas_capacity":    1920000,
			"block_byte_capacity": 3000000,
		})},
	)
	return sets
}

// TestEveryBlockCeilingAgreesWithASecondComputationAtItsBoundaryTargets is the
// form of the differential that runs in `make ci`, and the targeted target set
// is a considered choice rather than a budget cut.
//
// Rule 21's argument for enumerating a space is an argument about
// UNKNOWN-UNKNOWNS in a space nobody has bounded — the widest Era-0
// certificate was published wrong three times because the optimum sat in the
// interior of a multi-dimensional region and every search fixed the rest of
// the dimensions on an edge. The fourth figure holds because it stopped
// resting on a search and was DERIVED from the decode limits and the
// encoding. The block ceilings are not that space. They are a CLOSED FORM
// with named clamps: floor(genesis × T / T₀) capped at a constant, plus four
// fixed multiples of T. Monotone between two discontinuities whose addresses
// are known in advance, so targeted values AT those addresses are not a
// weaker check than enumeration, they are the right one — and enumeration
// over a closed form is cost without coverage.
//
// Measured: of this branch's nine production mutants, M5, M7 and M9 die
// against the O(1) clamp test alone, and M2 and M4 are constant-multiple
// errors visible at a single T ≥ 1. The exhaustive form's 133,679,934
// comparisons killed nothing a dozen targeted values do not, and roughly
// doubled this package's test time on every run. It is kept, behind
// `-tags ceilingsweep` in ceilings_sweep_test.go, for the case its own
// argument does not cover: a CHANGE to the scaling law, where the closed form
// is the thing in question and the discontinuities stop having known
// addresses.
//
// The axes it covers: T, at the boundaries of the closed form; and the seven
// genesis constants, at seven points (three shipped, one superseded, three
// synthetic). It does not cover the rest of that seven-dimensional
// space, and the sets were chosen for corners rather than sampled — a
// statement about where it was looked, not a maximum.
func TestEveryBlockCeilingAgreesWithASecondComputationAtItsBoundaryTargets(t *testing.T) {
	for _, set := range ceilingSets(t) {
		t.Run(set.name, func(t *testing.T) {
			shipped, second := parseBoth(t, set.raw)
			if got, want := second.SeqGasCapacity(), shipped.SeqGasCapacity; got != want {
				t.Fatalf("the two computations disagree about the domain itself: naive %d, shipped %d", got, want)
			}

			var certTruncations, byteTruncations int
			distinct := map[uint64]struct{}{}
			targets := boundaryTargets(shipped)
			for _, target := range targets {
				certs, blockBytes := compareAt(t, shipped, second, target)
				distinct[certs] = struct{}{}
				if certs*shipped.SeqGasTargetGenesis != uint64(shipped.MaxCertsPerBlockGenesis)*target {
					certTruncations++
				}
				if blockBytes*shipped.SeqGasTargetGenesis != uint64(shipped.BlockByteLimitGenesis)*target {
					byteTruncations++
				}
			}

			// Anti-vacuity. A targeted set earns its place only if it actually
			// lands on the features it claims to target: both floors must
			// truncate somewhere, and the scaled ceilings must take several
			// different values. Without these the target list could be
			// silently reduced to {0} and still be green.
			if certTruncations == 0 {
				t.Fatal("no boundary target made the certificate ceiling's division truncate; the floor is untested")
			}
			if byteTruncations == 0 {
				t.Fatal("no boundary target made the byte ceiling's division truncate; the floor is untested")
			}
			// Measured minimum across the seven sets is 8, at
			// synthetic/coprime-constants where T₀ == SeqGasCapacity collapses
			// several addresses; the others reach 9 to 12. The floor is 5, so
			// the margin is 3 and it is stated here rather than left to be
			// rediscovered when a set is added.
			if len(distinct) < 5 {
				t.Fatalf("the boundary targets produced only %d distinct certificate ceilings; the scaling law is barely being exercised", len(distinct))
			}
			t.Logf("%d targets, %d comparisons; %d distinct certificate ceilings; %d and %d truncating targets (count, bytes)",
				len(targets), 6*len(targets), len(distinct), certTruncations, byteTruncations)
		})
	}
}

// TestTheCapacityClampsAgreeWhereNothingInTheDomainCanReachThem is named for
// what it found rather than for what it was built to check, and the finding is
// why it is a separate test.
//
// WITHIN the domain ARCHITECTURE §15 defines, NEITHER capacity clamp can fire —
// not on the shipped networks, but on any parameter set at all. §15 requires
// SeqGasCapacity/SeqGasTargetGenesis == BlockByteCapacity/BlockByteLimitGenesis
// and Validate enforces it as an exact cross-multiplication, so
// BlockByteLimit(SeqGasCapacity) is BlockByteCapacity exactly and never more.
// The certificate clamp is unreachable for the same reason and not a weaker
// per-network one: Validate pairs CertListCapacity upward against the
// same domain, as an inequality rather than an equality because that capacity is
// frozen for the life of the chain and is deliberately oversized — 2,621× above
// the pairing floor on mainnet and 40,960× on devnet.
//
// The consequence for the sweep above is that a mutation to either clamp
// survives it — and a survivor nobody declared is indistinguishable from a
// probe that missed. So the clamps are checked here, at the targets that do
// reach them, including targets strictly between half a capacity and the
// capacity, which is the only band where a clamp firing at the WRONG threshold
// is visible at all.
//
// The reading being checked above SeqGasCapacity is DECLARED, because spec/
// does not fix it: the ceilings clamp their OUTPUT and do not re-clamp T. That
// is the one place core/params was read rather than derived (see
// core/params/naive's package comment, item 3). It is a silence over a domain
// nothing enters — Validate, NextSeqGasTarget's clamp-before-floor, genesis
// and spec/gen between them make a T above SeqGasCapacity unpresentable by any
// chain or vector — so what these targets fix is the CLAMP ARITHMETIC, on
// inputs chosen to reach it, and not a rule any block is judged by.
func TestTheCapacityClampsAgreeWhereNothingInTheDomainCanReachThem(t *testing.T) {
	for _, set := range ceilingSets(t) {
		t.Run(set.name, func(t *testing.T) {
			shipped, second := parseBoth(t, set.raw)
			atCap := shipped.SeqGasCapacity

			// The byte ceiling reaches its capacity exactly at the top of the
			// domain and never exceeds it. Asserted rather than remarked: this
			// is §15's pairing observed through the ceiling instead of through
			// Validate's cross-multiplication, and if it ever stops holding,
			// the sweep's stated blind spot has moved.
			if got := uint64(shipped.BlockByteLimit(atCap)); got != uint64(shipped.BlockByteCapacity) {
				t.Fatalf("BlockByteLimit(SeqGasCapacity) = %d, want exactly BlockByteCapacity = %d — §15's pairing no longer holds", got, shipped.BlockByteCapacity)
			}
			// And the same claim for the count clamp, which is universal rather
			// than per-set: the declaration still travels with the set, but no
			// admissible set may declare it true, so a set that had to would be
			// announcing that Validate's upward pairing is gone.
			reachable := shipped.MaxCertsPerBlock(atCap) >= shipped.CertListCapacity
			if reachable != set.certClampReachable {
				t.Fatalf("the certificate clamp is reachable=%v inside the domain, declared %v; the sweep's blind spot has moved", reachable, set.certClampReachable)
			}
			if set.certClampReachable {
				t.Fatal("a Validate-clean set declared the count clamp reachable inside its own domain; Validate's upward pairing on cert_list_capacity no longer holds")
			}

			// firstClamping is computed from the parameters rather than
			// written down, so that it follows a parameter change: for a
			// ceiling scaled by g/t0 and clamped at cap, the first target whose
			// unclamped value can exceed cap is floor(cap × t0 / g) + 1.
			t0 := shipped.SeqGasTargetGenesis
			firstByteClamp := uint64(shipped.BlockByteCapacity)*t0/uint64(shipped.BlockByteLimitGenesis) + 1
			firstCertClamp := uint64(shipped.CertListCapacity)*t0/uint64(shipped.MaxCertsPerBlockGenesis) + 1

			// Three shapes per clamp, and the third took a second pass to get
			// right. The far side of a clamp and its exact edge both leave the
			// THRESHOLD untested — a clamp firing at half its capacity still
			// returns the capacity for every target at or above the edge. The
			// 3/4 targets land strictly between half the capacity and the
			// capacity, which is the only band where a wrong threshold shows;
			// without them the halved-clamp mutants survive.
			targets := []uint64{
				firstByteClamp - 1, firstByteClamp, firstByteClamp + 1, 2 * firstByteClamp,
				firstCertClamp - 1, firstCertClamp, firstCertClamp + 1,
				firstByteClamp / 4 * 3, firstCertClamp / 4 * 3,
				1 << 40, 1 << 55, ^uint64(0) / 4, ^uint64(0),
			}
			var clampedBytes, clampedCerts, betweenHalfAndCap int
			for _, target := range targets {
				gotBytes, wantBytes := uint64(shipped.BlockByteLimit(target)), second.BlockByteLimit(target)
				if gotBytes != wantBytes {
					t.Fatalf("T=%d: BlockByteLimit above the domain: shipped %d, second computation %d", target, gotBytes, wantBytes)
				}
				gotCerts, wantCerts := uint64(shipped.MaxCertsPerBlock(target)), second.MaxCertsPerBlock(target)
				if gotCerts != wantCerts {
					t.Fatalf("T=%d: MaxCertsPerBlock above the domain: shipped %d, second computation %d", target, gotCerts, wantCerts)
				}
				if gotBytes == uint64(shipped.BlockByteCapacity) && target >= firstByteClamp {
					clampedBytes++
				}
				if gotCerts == uint64(shipped.CertListCapacity) {
					clampedCerts++
				}
				half := uint64(shipped.BlockByteCapacity) / 2
				if gotBytes > half && gotBytes < uint64(shipped.BlockByteCapacity) {
					betweenHalfAndCap++
				}
			}
			// Anti-vacuity, and it is the whole point of this test: if no
			// target reached a clamp, or none landed in the band where a wrong
			// threshold is visible, the clamps are still unchecked and this
			// test is decoration.
			if clampedBytes == 0 {
				t.Fatal("no target reached the byte capacity clamp")
			}
			if clampedCerts == 0 {
				t.Fatal("no target reached the certificate list capacity clamp")
			}
			if betweenHalfAndCap == 0 {
				t.Fatal("no target landed between half the byte capacity and the byte capacity; a clamp at the wrong threshold would survive")
			}
			t.Logf("domain [0,SeqGasCapacity=%d]: the byte clamp first fires at T=%d, %d above the domain; the certificate clamp at T=%d, reachable in the domain=%v",
				atCap, firstByteClamp, firstByteClamp-atCap, firstCertClamp, reachable)
		})
	}
}

// TestTheSecondComputationReadsTheParameterFileByItsOwnKeys fixes the property
// that makes core/params/naive a second computation rather than a second copy:
// it resolves the eight constants through its own string literals, so a
// parameter file that no longer spells a key the way it expects fails loudly
// instead of scaling a ceiling by zero.
//
// This is the analogue of core/state/naive's own domain tag literals.
// A key inherited from core/params's struct would move with that struct and the
// differential could not see it move — and a ceiling silently scaled by the
// wrong parameter is exactly the divergence nothing else in the tree can
// observe.
func TestTheSecondComputationReadsTheParameterFileByItsOwnKeys(t *testing.T) {
	raw, err := spec.RawFor("mainnet")
	if err != nil {
		t.Fatalf("spec.RawFor: %v", err)
	}
	for _, key := range []string{
		"max_certs_per_block_genesis",
		"max_sigs_per_block_genesis",
		"block_byte_limit_genesis",
		"seq_gas_target_genesis",
		"par_gas_ratio",
		"cert_list_capacity",
		"block_byte_capacity",
		"seq_gas_capacity",
	} {
		if _, err := naive.FromJSON(renameJSONKey(t, raw, key, key+"_renamed")); err == nil {
			t.Fatalf("naive.FromJSON accepted a parameter file with no %q", key)
		}
		if _, err := naive.FromJSON(withNumbers(t, raw, map[string]uint64{key: 0})); err == nil {
			t.Fatalf("naive.FromJSON accepted %q = 0", key)
		}
	}
}

func parseBoth(t *testing.T, raw []byte) (*params.Params, *naive.Ceilings) {
	t.Helper()
	shipped, err := params.Parse(raw)
	if err != nil {
		t.Fatalf("params.Parse: %v", err)
	}
	second, err := naive.FromJSON(raw)
	if err != nil {
		t.Fatalf("naive.FromJSON: %v", err)
	}
	return shipped, second
}

// compareAt checks all seven ceilings at one target and returns the two scaled
// ones, which are the only two the caller's counters need.
//
// No t.Helper() here on purpose: it takes the test's own mutex, and this runs
// tens of millions of times. Every failure below names the target and the
// ceiling, so the line number a helper frame would recover buys nothing.
func compareAt(t *testing.T, shipped *params.Params, second *naive.Ceilings, target uint64) (certs, blockBytes uint64) {
	seqLimit, err := second.SeqGasLimit(target)
	if err != nil {
		t.Fatalf("T=%d: naive.SeqGasLimit inside its own domain: %v", target, err)
	}
	seqBurst, err := second.SeqGasBurst(target)
	if err != nil {
		t.Fatalf("T=%d: naive.SeqGasBurst inside its own domain: %v", target, err)
	}
	parLimit, err := second.ParGasLimit(target)
	if err != nil {
		t.Fatalf("T=%d: naive.ParGasLimit inside its own domain: %v", target, err)
	}
	parTarget, err := second.ParGasTarget(target)
	if err != nil {
		t.Fatalf("T=%d: naive.ParGasTarget inside its own domain: %v", target, err)
	}
	certs = second.MaxCertsPerBlock(target)
	sigs := second.MaxSigsPerBlock(target)
	blockBytes = second.BlockByteLimit(target)

	if got := shipped.SeqGasLimit(target); got != seqLimit {
		t.Fatalf("T=%d: SeqGasLimit: shipped %d, second computation %d", target, got, seqLimit)
	}
	if got := shipped.SeqGasBurst(target); got != seqBurst {
		t.Fatalf("T=%d: SeqGasBurst: shipped %d, second computation %d", target, got, seqBurst)
	}
	if got := shipped.ParGasLimit(target); got != parLimit {
		t.Fatalf("T=%d: ParGasLimit: shipped %d, second computation %d", target, got, parLimit)
	}
	if got := shipped.ParGasTarget(target); got != parTarget {
		t.Fatalf("T=%d: ParGasTarget: shipped %d, second computation %d", target, got, parTarget)
	}
	if got := uint64(shipped.MaxCertsPerBlock(target)); got != certs {
		t.Fatalf("T=%d: MaxCertsPerBlock: shipped %d, second computation %d", target, got, certs)
	}
	if got := shipped.MaxSigsPerBlock(target); got != sigs {
		t.Fatalf("T=%d: MaxSigsPerBlock: shipped %d, second computation %d", target, got, sigs)
	}
	if got := uint64(shipped.BlockByteLimit(target)); got != blockBytes {
		t.Fatalf("T=%d: BlockByteLimit: shipped %d, second computation %d", target, got, blockBytes)
	}
	return certs, blockBytes
}

// boundaryTargets is the closed form's own feature list, in T.
//
// Every entry is an address rather than a sample, and each is here for a named
// reason. The two ends of the domain and their neighbours, because a ceiling
// that is off by one target is off at an end. T₀ and its neighbours, because
// it is the divisor and the permanent floor, and it is the one target at which
// a divide-first scaling law agrees with a multiply-first one by accident.
// T₀ + T₀/Γ, the first rung of §8.1's maximal growth ladder, because it is the
// first target a live chain can actually reach after genesis. The midpoint and
// its successor, because the byte ceiling passes half its capacity there. And
// four offsets that are coprime to nothing in particular, because both scaled
// ceilings floor and a list of round numbers samples only the exact divisions
// — which is how spec/params.json's own note on max_certs_per_block_genesis
// reported the wrong utilisation interval once.
//
// The clamp edges and the overflow point are NOT here: they lie above
// SeqGasCapacity, so they belong to the clamp test, which computes them from
// the parameters rather than writing them down.
func boundaryTargets(p *params.Params) []uint64 {
	t0 := p.SeqGasTargetGenesis
	top := p.SeqGasCapacity
	out := []uint64{
		0, 1, 2,
		t0 - 1, t0, t0 + 1,
		t0 + t0/p.CeilingGrowthDivisor,
		top - 1, top,
		top / 2, top/2 + 1,
		t0 + 7, t0 + 499, top - 3, top/3*2 + 1,
		// Fractions of the domain rather than offsets from T₀, because a set
		// whose T₀ IS its capacity collapses every t0+k onto the same target.
		// synthetic/coprime-constants is such a set, and without these it
		// reached the distinct-ceiling floor with a margin of zero.
		top / 4, top / 4 * 3, top/7*3 + 1,
	}
	// A target above the domain is not a target: clamp rather than drop, so a
	// small synthetic set still contributes every address it has.
	for i, v := range out {
		if v > top {
			out[i] = top
		}
	}
	return out
}

func renameJSONKey(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	return replaceOnce(t, raw, `"`+from+`":`, `"`+to+`":`)
}

// withNumbers rewrites top-level numeric parameters in place. It edits the raw
// bytes rather than round-tripping through a decoder, because a round trip
// through core/params would defeat the point of every test in this file.
func withNumbers(t *testing.T, raw []byte, values map[string]uint64) []byte {
	t.Helper()
	out := raw
	// Sorted iteration is not needed for correctness — each key is rewritten
	// independently — but keys are applied in a fixed order so a failure is
	// reproducible from the log.
	for _, key := range sortedKeys(values) {
		re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `":\s*\d+`)
		loc := re.FindIndex(out)
		if loc == nil {
			t.Fatalf("the parameter file has no numeric %q to rewrite", key)
		}
		out = append(append(append([]byte{}, out[:loc[0]]...),
			[]byte(fmt.Sprintf("%q: %d", key, values[key]))...), out[loc[1]:]...)
	}
	return out
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// replaceOnce rewrites the FIRST occurrence, which for every key used here is
// the top-level one: spec/params.json repeats several key names inside its
// "notes" object, and that object is written last.
func replaceOnce(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	s := string(raw)
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("the parameter file does not contain %q", from)
	}
	return []byte(s[:i] + to + s[i+len(from):])
}
