package spec_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/spec"
)

// TestGoldenVectors replays every committed vector.
//
// This is the conformance suite, and it is deliberately the dullest code in the
// repository: load a pre-state, decode a block, fold it, compare everything.
// An independent implementation should be able to write the same fifty lines
// against its own fold and pass.
func TestGoldenVectors(t *testing.T) {
	vectors, err := spec.LoadVectors("vectors")
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("the vector corpus is empty; run `go run ./spec/gen`")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			s, err := v.Pre.BuildState()
			if err != nil {
				t.Fatal(err)
			}
			b, err := v.DecodeBlock(p)
			if err != nil {
				t.Fatalf("the block does not decode: %v", err)
			}

			res, applyErr := fold.ApplyBlock(s, b, p)

			if !v.Expect.Valid {
				if applyErr == nil {
					t.Fatalf("the block was accepted; the vector says it is invalid (%s)", v.Expect.Reason)
				}
				if !errors.Is(applyErr, fold.ErrInvalidBlock) {
					t.Fatalf("got %v, want an invalid-block error", applyErr)
				}
				// The rule, not the wording. Without this line the corpus says
				// only that *something* rejected the block, and an
				// implementation missing the rule the vector is named for
				// passes it on the strength of some other rule — or, as
				// invalid-cap-below-base was one deleted rule away from, on an
				// internal conservation assertion. Agreeing on "invalid" while
				// disagreeing on which rule refused is a real incompatibility.
				if v.Expect.Rule == "" {
					t.Fatal("an invalid vector names no rule; regenerate the corpus with `go run ./spec/gen`")
				}
				if got := fold.Rule(applyErr); got != v.Expect.Rule {
					t.Fatalf("rejected by %s, the vector pins %s (%v)", ruleOrNone(got), v.Expect.Rule, applyErr)
				}
				if got := spec.Snapshot(s); !got.Equal(v.Expect.Post) {
					t.Fatal("a rejected block changed the state")
				}
				return
			}
			if applyErr != nil {
				t.Fatalf("the block was rejected: %v", applyErr)
			}

			if len(res.Outcomes) != len(v.Expect.Outcomes) {
				t.Fatalf("got %d outcomes, want %d", len(res.Outcomes), len(v.Expect.Outcomes))
			}
			for i, want := range v.Expect.Outcomes {
				got := res.Outcomes[i]
				if id := "0x" + hex.EncodeToString(got.ID[:]); id != want.ID {
					t.Fatalf("outcome %d: fold order differs (%s, want %s)", i, id, want.ID)
				}
				if got.Outcome.String() != want.Outcome {
					t.Fatalf("outcome %d: %s, want %s", i, got.Outcome, want.Outcome)
				}
				if got.Charged.String() != want.Charged {
					t.Fatalf("outcome %d: charged %s, want %s", i, got.Charged.String(), want.Charged)
				}
				if got.Refunded.String() != want.Refunded {
					t.Fatalf("outcome %d: refunded %s, want %s", i, got.Refunded.String(), want.Refunded)
				}
				wantBurned := want.RefundBurned
				if wantBurned == "" {
					wantBurned = "0"
				}
				if got.RefundBurned.String() != wantBurned {
					t.Fatalf("outcome %d: burned refund %s, want %s", i, got.RefundBurned.String(), wantBurned)
				}
				wantSwept := want.Swept
				if wantSwept == "" {
					wantSwept = "0"
				}
				if got.Swept.String() != wantSwept {
					t.Fatalf("outcome %d: swept %s, want %s", i, got.Swept.String(), wantSwept)
				}
				wantStranded := want.SweptStranded
				if wantStranded == "" {
					wantStranded = "0"
				}
				if got.SweptStranded.String() != wantStranded {
					t.Fatalf("outcome %d: stranded sweep %s, want %s",
						i, got.SweptStranded.String(), wantStranded)
				}
				if got.StrandedCells != want.StrandedCells {
					t.Fatalf("outcome %d: %d cells stranded, want %d",
						i, got.StrandedCells, want.StrandedCells)
				}
			}

			if res.SeqGasUsed != v.Expect.SeqGasUsed {
				t.Fatalf("sequential gas %d, want %d", res.SeqGasUsed, v.Expect.SeqGasUsed)
			}
			if res.ParGasUsed != v.Expect.ParGasUsed {
				t.Fatalf("parallel gas %d, want %d", res.ParGasUsed, v.Expect.ParGasUsed)
			}
			if res.SeqGasApplied != v.Expect.SeqGasApplied {
				t.Fatalf("applied sequential gas %d, want %d", res.SeqGasApplied, v.Expect.SeqGasApplied)
			}
			if res.ParGasApplied != v.Expect.ParGasApplied {
				t.Fatalf("applied parallel gas %d, want %d", res.ParGasApplied, v.Expect.ParGasApplied)
			}
			if res.Burned.String() != v.Expect.Burned {
				t.Fatalf("burned %s, want %s", res.Burned.String(), v.Expect.Burned)
			}
			if res.MinerReward.String() != v.Expect.MinerReward {
				t.Fatalf("miner reward %s, want %s", res.MinerReward.String(), v.Expect.MinerReward)
			}
			if res.Treasury.String() != v.Expect.Treasury {
				t.Fatalf("treasury %s, want %s", res.Treasury.String(), v.Expect.Treasury)
			}
			if res.Matured.String() != v.Expect.Matured {
				t.Fatalf("matured %s, want %s", res.Matured.String(), v.Expect.Matured)
			}
			if v.Expect.PostRoot != "" {
				if got := "0x" + hex.EncodeToString(res.StateRoot[:]); got != v.Expect.PostRoot {
					t.Fatalf("state root %s, want %s", got, v.Expect.PostRoot)
				}
			}
			if got := spec.Snapshot(s); !got.Equal(v.Expect.Post) {
				t.Fatal("the post-state differs from the vector")
			}
		})
	}
}

// TestGoldenDifficultyVectors replays every committed difficulty vector.
//
// fold.ApplyBlock never evaluates the difficulty rule — core/fold's only
// contact with Header.Target is recording the declared value, never checking
// it — so a (pre-state, block) vector cannot constrain pow.NextTarget at all.
// This is the second, parallel replay path spec/README.md describes: no
// state, no fold, just the one pure function a real node calls to derive and
// to verify a target. An independent implementation's conformance harness
// needs exactly one more call site than TestGoldenVectors's fifty dull lines
// to cover it: decode the headers, call pow.NextTarget, compare.
func TestGoldenDifficultyVectors(t *testing.T) {
	vectors, err := spec.LoadDifficultyVectors("vectors/difficulty")
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("the difficulty vector corpus is empty; run `go run ./spec/gen`")
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			headers, err := v.DecodeHeaders()
			if err != nil {
				t.Fatalf("a header does not decode: %v", err)
			}

			got := pow.NextTarget(headers, p)
			if got.String() != v.Expect.NextTarget {
				t.Fatalf("next target %s, want %s", got.String(), v.Expect.NextTarget)
			}
		})
	}
}

// outcomeExemptions is the closed table of outcomes the corpus does not carry,
// each with the reason it cannot. An entry here is a claim about the protocol,
// not a note about work outstanding, and TestVectorCoverage holds it to that:
// the table must be a subset of what core/fold declares, and an entry a vector
// actually reaches is a failure rather than a pass.
var outcomeExemptions = map[string]string{
	"SKIPPED_OVERFLOW": "unreachable in Era 0 (docs/adversarial/I1.md, I1-L8): for any " +
		"asset the sum of every balance cell equals its minted cell, which a GUARD_LE " +
		"holds at or below the asset's immutable cap, so no credit can carry a cell " +
		"past 2^256. core/fold's TestMaxCapSupplyBoundsEveryCreditBelowOverflow runs " +
		"the fold at that boundary; this corpus states nothing about the outcome",
}

// TestVectorCoverage keeps the corpus honest: every outcome the fold can
// produce must appear somewhere or be exempted by name, and both verdicts a
// block can receive must appear.
//
// **The outcome set is derived, not listed.** Until this test derived it the
// demand was a hand-written three — APPLIED, SKIPPED_STALE, DROPPED — while
// spec/README.md promised every outcome the fold can produce. That is a promise
// wider than its check, and it hid a real gap: SKIPPED_OVERFLOW is in no
// vector, and nothing here said so. Worse than the gap, a fourth outcome added
// to core/fold would have inherited the same silence. The pattern used to close
// it is the one this tree uses wherever a document lists what the code defines:
// derive the set from the source of truth and let the document be checked
// against the tree rather than maintained beside it.
//
// **Two scans, each accounting for the other.** derivedOutcomes reads the
// Outcome constant block out of core/fold's own source and walks String() over
// the same range. A constant with no arm in String() fails, and an arm past the
// last constant fails — so neither half of the vocabulary can grow without the
// other, and neither can grow without arriving here.
//
// **What the exemption table is and is not.** It is not a way to quiet this
// test. An entry must name an outcome core/fold still declares, and it must
// still be absent from the corpus: the era that makes SKIPPED_OVERFLOW
// reachable produces a vector, the exemption goes stale, and this test says so
// instead of passing over it.
func TestVectorCoverage(t *testing.T) {
	vectors, err := spec.LoadVectors("vectors")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	var valid, invalid int
	for _, v := range vectors {
		if v.Expect.Valid {
			valid++
		} else {
			invalid++
		}
		for _, o := range v.Expect.Outcomes {
			seen[o.Outcome] = true
		}
	}

	outcomes := derivedOutcomes(t)
	declared := map[string]bool{}
	for _, o := range outcomes {
		declared[o] = true
	}

	// A stale exemption is a claim about an outcome that no longer exists, and
	// it would sit here forever excusing nothing.
	for name, why := range outcomeExemptions {
		if !declared[name] {
			t.Errorf("the exemption table names the outcome %q, which core/fold no longer "+
				"declares (%q); the entry excuses nothing and its reason (%s) is now "+
				"about a value the fold cannot produce", name, outcomes, why)
		}
	}

	var covered int
	for _, want := range outcomes {
		why, exempt := outcomeExemptions[want]
		switch {
		case seen[want] && exempt:
			t.Errorf("the outcome %s is exempted as %s, and a vector in this corpus produces "+
				"it. The exemption is stale: delete the entry, because the corpus now states "+
				"the outcome and the table says it cannot", want, why)
		case seen[want]:
			covered++
		case exempt:
			t.Logf("%s: no vector, exempt — %s", want, why)
		default:
			t.Errorf("no vector produces the outcome %s, and it is in no exemption table. "+
				"spec/README.md's Coverage section promises every outcome core/fold can "+
				"produce either appears in the corpus or is exempted by name with a reason; "+
				"add a vector, or add an entry to outcomeExemptions saying why none can "+
				"exist", want)
		}
	}
	if covered == 0 {
		t.Errorf("no outcome at all is covered by a vector; this gate would pass over an "+
			"empty corpus (%d vectors loaded)", len(vectors))
	}

	if valid == 0 || invalid == 0 {
		t.Errorf("the corpus has %d valid and %d invalid blocks; it needs both", valid, invalid)
	}
}

// derivedOutcomes returns the fold's outcome vocabulary in wire form, read out
// of core/fold rather than restated here.
//
// It is deliberately two independent readings of the same thing. The AST scan
// answers "which outcomes does the type declare"; String() answers "what does
// each one call itself on the wire". A vocabulary is only as trustworthy as the
// agreement between those two, because a vector records the *string*: a
// constant with no String() arm would be a producible outcome no vector could
// ever be written for, and a String() arm past the last constant would be a
// name nothing produces.
func derivedOutcomes(t *testing.T) []string {
	t.Helper()

	const src = "../core/fold/fold.go"
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", src, err)
	}

	var idents []string
	ast.Inspect(f, func(n ast.Node) bool {
		if len(idents) > 0 {
			return false
		}
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST || len(gd.Specs) == 0 {
			return true
		}
		first, ok := gd.Specs[0].(*ast.ValueSpec)
		if !ok {
			return true
		}
		if id, ok := first.Type.(*ast.Ident); !ok || id.Name != "Outcome" {
			return true
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				idents = append(idents, name.Name)
			}
		}
		return false
	})

	// Lower bound rather than an equality: a bound survives someone adding a
	// fifth outcome, and an equality pinned from this same scan would only echo
	// it. Four is what Era 0 declares — applied, two skips and a drop.
	if len(idents) < 4 {
		t.Fatalf("the scan found %d Outcome constants in %s, want at least 4 (%q): it has "+
			"stopped seeing the const block, and this gate would then demand nothing",
			len(idents), src, idents)
	}

	wire := make([]string, 0, len(idents))
	byName := map[string]string{}
	for i, ident := range idents {
		s := fold.Outcome(i).String()
		if s == "UNKNOWN" {
			t.Fatalf("core/fold declares the outcome constant %s at index %d and String() "+
				"does not name it. A vector records the wire name, so an outcome without "+
				"one can be produced by the fold and pinned by nothing", ident, i)
		}
		if prev, dup := byName[s]; dup {
			t.Fatalf("the outcome constants %s and %s both render as %q; two producible "+
				"outcomes sharing a wire name make the corpus unable to tell them apart",
				prev, ident, s)
		}
		byName[s] = ident
		wire = append(wire, s)
	}
	if s := fold.Outcome(len(idents)).String(); s != "UNKNOWN" {
		t.Fatalf("String() names %q at index %d, past the %d constants the scan found in "+
			"%s: the switch and the const block disagree about how many outcomes exist, "+
			"and this gate covers whichever of the two is shorter", s, len(idents),
			len(idents), src)
	}
	return wire
}

// TestParamsAreValid: the embedded parameter files must parse and satisfy every
// invariant, or the binary has no protocol. Every name spec.Networks() lists
// must also resolve, so that the list and ParamsFor cannot drift apart — the
// list is what TestEveryEmbeddedNetworkHasAPinnedGenesis enumerates, and a name
// it carries that resolves to nothing would make that check pass over a gap.
func TestParamsAreValid(t *testing.T) {
	chainIDs := map[uint64]string{}
	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The chain id is the network's name in every certificate and the
		// field V1 compares, and it is the one field a mis-edited copy of
		// another network's file would most plausibly keep. Two embedded
		// networks sharing one is refused here rather than left to a later
		// rule.
		//
		// Be exact about what a duplicate would and would not cost, because
		// widening the signing preimage moved it. The signing domain is now
		// (chain id, consensus root), so
		// two networks whose parameter files differ anywhere do NOT accept
		// each other's certificates even sharing an id -- V1 passes and V2
		// refuses. What a duplicate still breaks is the ledger rule
		// spec/chain-ids.json states, which is about allocation over time and
		// is what covers the case no preimage can: an id handed to a network
		// whose parameter values are identical to a spent one.
		if other, dup := chainIDs[p.ChainID]; dup {
			t.Fatalf("%s and %s share chain id %d. This is the allocation rule in "+
				"spec/chain-ids.json broken, not a replay: the two files differ at "+
				"least in `name`, which is a consensus parameter, so their consensus "+
				"roots differ and V2 already refuses each network the other's "+
				"certificates. What a shared id costs is that one id names two "+
				"networks in every certificate, every log line and every operator's "+
				"--params file, and that the ledger can no longer say which genesis "+
				"spent it. Allocate a second id",
				other, name, p.ChainID)
		}
		chainIDs[p.ChainID] = name
	}
	if len(chainIDs) != len(spec.Networks()) {
		t.Fatalf("%d embedded parameter sets produced %d chain ids", len(spec.Networks()), len(chainIDs))
	}
}

// TestEveryEmbeddedNetworkHasAPinnedGenesis: an embedded parameter set whose
// genesis is not in the corpus is a network exempt from the compatibility
// contract, and the corpus cannot say so by omission — which is why the public
// testnet's parameters were shipped for one release with nothing asserting the
// state root they produce.
//
// The check is over spec.Networks() rather than over a written list of vector
// names, so the failure lands on whoever adds the fourth parameter set instead
// of on nobody.
func TestEveryEmbeddedNetworkHasAPinnedGenesis(t *testing.T) {
	vectors, err := spec.LoadVectors("vectors")
	if err != nil {
		t.Fatal(err)
	}
	// Networks() is the list this check enumerates, so the list itself has to
	// be held to the directory: dropping a name from it would otherwise drop
	// that network from the guard silently, which is the failure mode the guard
	// exists to prevent one level down.
	files, err := filepath.Glob("params*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no parameter files found; the check would pass vacuously")
	}
	for _, f := range files {
		onDisk, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var embedded bool
		for _, name := range spec.Networks() {
			raw, err := spec.RawFor(name)
			if err != nil {
				t.Fatalf("%s is in Networks() but ParamsFor/RawFor do not resolve it: %v", name, err)
			}
			if bytes.Equal(raw, onDisk) {
				embedded = true
				break
			}
		}
		if !embedded {
			t.Errorf("spec/%s is embedded under no name in spec.Networks(); its network "+
				"is exempt from the compatibility contract", f)
		}
	}

	byName := map[string]*spec.Vector{}
	for _, v := range vectors {
		byName[v.Name] = v
	}

	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		// RawFor and ParamsFor are two answers to "which file is this
		// network", and the directory check above only proves each file is
		// embedded under *some* name: it is satisfied by any bijection between
		// names and files, so swapping two arms of RawFor leaves every file
		// matched and every genesis pinned, and passes. What that swap breaks
		// is RawFor's own contract — "the embedded bytes of a named parameter
		// set" — and with it every caller outside this package that resolves a
		// network by name and then reads or hashes the bytes it got back. So
		// the two answers are compared here: the raw bytes a name returns must
		// parse to the parameters that name resolves to.
		raw, err := spec.RawFor(name)
		if err != nil {
			t.Fatalf("%s is in Networks() but RawFor does not resolve it: %v", name, err)
		}
		fromRaw, err := params.Parse(raw)
		if err != nil {
			t.Fatalf("RawFor(%q) does not parse: %v", name, err)
		}
		if fromRaw.ConsensusRoot() != p.ConsensusRoot() || fromRaw.Name != p.Name {
			t.Errorf("RawFor(%q) carries %q and ParamsFor(%q) carries %q; a caller that "+
				"resolves this network by name reads another network's file",
				name, fromRaw.Name, name, p.Name)
			continue
		}
		// The other half of "pinned". Everything above pins the consensus
		// identity — the root, the genesis id, the state root — and none of it
		// touches the value a release announcement actually publishes
		// alongside them: blake3 over the file's bytes. That value is
		// unreachable from the consensus root in both directions. A hardcoded
		// accessor (`TestnetParamsHash` returning Hash(devnetJSON)) moves it
		// while every root stays put, and an edit to a `notes` string — the one
		// field ConsensusRoot excludes — moves it while nothing else in this
		// package changes at all. Both are silent without a literal here.
		//
		// So the announced hash is written down. Changing a parameter file,
		// prose included, is meant to fail this test: the commitment a release
		// publishes has moved, and updating this constant is how that becomes a
		// decision somebody made rather than a byte that drifted.
		announced := map[string]string{
			// Mainnet's genesis_time is its launch day, 2026-09-15T00:00:00Z; the
			// public testnet's is 2026-09-06T00:00:00Z, the day it was respun. Both are round UTC values, as
			// RELEASE.md section 2 requires, and both are consensus fields: the
			// consensus root, the genesis id and the state root all derive from them,
			// so moving either regenerates that network's golden vectors and moves
			// its hash below with them. Devnet is reset freely and pins nothing.
			"mainnet": "0x0cdab31d391541c66a25510715bd3cea35f619e58fe45b1594b624e28ded1775",
			"testnet": "0x196b736a71b36bb3e943519a8da816a9d6edf072d7f7847b21b95a683ff07021",
			"devnet":  "0xf1425bab784a24c737c61e95e99f0bb657ba3847936771fb7fa9e8969023d08a",
		}
		want, ok := announced[name]
		if !ok {
			t.Errorf("%s is embedded but its parameter hash is not pinned here; a "+
				"network ships with a commitment or it does not ship", name)
		} else {
			h := spec.Hash(raw)
			if got := "0x" + hex.EncodeToString(h[:]); got != want {
				t.Errorf("%s announces parameter hash %s; the embedded bytes hash to %s",
					name, want, got)
			}
		}
		// And the accessors have to agree with RawFor, because they read their
		// own package-level variable rather than going through it: they are
		// what a release tool calls, and they have no other caller in this tree
		// to keep them honest.
		if acc, ok := map[string]func() crypto.Hash{
			"mainnet": spec.MainnetParamsHash,
			"testnet": spec.TestnetParamsHash,
		}[name]; ok {
			if acc() != spec.Hash(raw) {
				t.Errorf("the %s parameter-hash accessor does not hash the bytes RawFor(%q) returns", name, name)
			}
		}
		v, ok := byName["genesis-"+name]
		if !ok {
			t.Errorf("the corpus pins no genesis for %s; add one with `go run ./spec/gen`", name)
			continue
		}
		// Naming the vector after the network is not the same as replaying it
		// against that network: without this, a genesis vector generated from
		// the wrong parameter set would pin a real root for the wrong file.
		if v.Params != name {
			t.Errorf("%s is replayed against the %s parameters", v.Name, v.Params)
			continue
		}
		// The root the shipped bytes actually produce, derived by the path
		// `zcd genesis` uses rather than by the fold path TestGoldenVectors
		// replays: the vector is the launch commitment for this network, so
		// both paths have to arrive at the same value.
		b, _, err := genesis.Build(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := "0x" + hex.EncodeToString(b.Header.StateRoot[:]); got != v.Expect.PostRoot {
			t.Errorf("%s pins state root %s; the embedded parameters build %s",
				v.Name, v.Expect.PostRoot, got)
		}
	}
}

// ruleOrNone reads better than an empty string in a failure message, and the
// empty answer is the interesting one: it means the block was refused by a
// conservation assertion rather than by a rule.
func ruleOrNone(rule string) string {
	if rule == "" {
		return "no rule (an internal assertion)"
	}
	return rule
}
