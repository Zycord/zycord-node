// The RandomX local-net recipe, and the three things that have to keep agreeing
// about it.
//
// docs/localnet/params.randomx-localnet.json is a parameter file that NOTHING
// embeds. That is deliberate — it is a throwaway network run through --params,
// not something a release ships — but it costs the file every guard the
// embedded sets get for free. spec/vector_test.go globs `spec/params*.json` and
// would demand a pinned genesis; spec/chainid_allocation_test.go walks the
// networks in spec.Networks(). This file is in neither list, so without this
// test the recipe could stop parsing, stop validating, or quietly drift into
// claiming something its own README contradicts, and every suite in the tree
// would stay green.
//
// The failure that matters is not "the JSON is malformed" — that is loud the
// first time somebody runs it. It is the slow one: a parameter the file
// inherits from devnet changes meaning, or the key schedule is "tidied", and
// the boundary the whole recipe exists to reach moves out to somewhere a short
// run never gets to. A recipe that no longer does the thing it was written for,
// while still starting cleanly, is worse than one that fails.
package wiring_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
)

// localnetParamsPath is the recipe, relative to this test's directory.
const localnetParamsPath = "../../docs/localnet/params.randomx-localnet.json"

func loadLocalnet(t *testing.T) *params.Params {
	t.Helper()
	raw, err := os.ReadFile(localnetParamsPath)
	if err != nil {
		t.Fatalf("the local-net recipe is missing: %v", err)
	}
	var p params.Params
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("the local-net recipe does not parse: %v", err)
	}
	// Validate is what the node runs before it will touch a --params file, so a
	// recipe that does not pass it is a recipe that cannot be run at all.
	if err := p.Validate(); err != nil {
		t.Fatalf("the local-net recipe is not a valid parameter set: %v", err)
	}
	return &p
}

// TestTheLocalNetRecipeRunsTheRealEngine pins the single value that is the
// reason the file exists.
//
// devnet already provides a fast local network; what it cannot provide is the
// RandomX path, because it declares dev-blake3. If this value ever drifts back
// to the development engine the recipe still starts, still mines, still crosses
// its boundaries — and covers exactly nothing that devnet did not already
// cover, while its README goes on claiming otherwise.
func TestTheLocalNetRecipeRunsTheRealEngine(t *testing.T) {
	p := loadLocalnet(t)
	if p.PoWEngine != "randomx-v2" {
		t.Errorf("the local-net recipe declares pow_engine %q; it exists to exercise "+
			"the RandomX path, and on any other engine it is devnet with extra steps",
			p.PoWEngine)
	}
}

// TestTheLocalNetCrossesAKeyBoundaryQuickly is the property the recipe is FOR,
// asserted as arithmetic rather than as a promise in prose.
//
// The issue this recipe answers asks for seed-epoch boundaries reachable "in
// minutes, not days". That is a claim about (key interval, lag, block time)
// together, so it is checked on the derived quantity — when the first re-key
// actually lands — rather than on any one parameter. Someone may retune the
// three; what they may not do is leave the first boundary an hour out while
// docs/localnet/README.md tells a reader to expect it at ninety seconds.
//
// The bound is generous on purpose. It is not trying to pin the current values
// (16/2 at a 5 s block, so height 18 and ~90 s); it is trying to catch a drift
// into a regime where a short run observes no re-key at all, which is the only
// way this file stops doing its job while still looking fine.
func TestTheLocalNetCrossesAKeyBoundaryQuickly(t *testing.T) {
	p := loadLocalnet(t)

	// pow.SeedEpochFor is the schedule itself, so this reads the real rule
	// rather than reimplementing interval+lag arithmetic that could drift.
	var firstBoundary uint64
	for h := uint64(1); h <= 10_000; h++ {
		if pow.SeedEpochFor(h, p) != 0 {
			firstBoundary = h
			break
		}
	}
	if firstBoundary == 0 {
		t.Fatal("the local net never leaves seed epoch 0 within 10,000 blocks; the " +
			"recipe cannot exercise a re-key at all")
	}

	const budget = 10 * 60 // seconds: "minutes, not days", with room to retune.
	if secs := firstBoundary * p.TargetBlockSeconds; secs > budget {
		t.Errorf("the first key boundary is at height %d, about %d seconds in; the "+
			"recipe exists so that an end-to-end run REACHES a boundary, and past "+
			"about %d seconds nobody watching a short run will see one",
			firstBoundary, secs, budget)
	}

	// And it must keep re-keying, not just cross once: the mining pause is the
	// thing being measured, and one sample is not a measurement.
	if pow.SeedEpochFor(firstBoundary+p.RandomXKeyInterval, p) <= pow.SeedEpochFor(firstBoundary, p) {
		t.Error("the schedule does not advance an epoch one interval past the first " +
			"boundary, so a run would observe a single re-key and then nothing")
	}
}

// TestTheLocalNetKeepsTheLagRatio holds the one relationship that is a rule
// rather than a tuning choice.
//
// params.Validate already refuses a lag at or above the interval, so this is
// not repeating that. What it pins is the 1:8 ratio both shipped networks keep
// (mainnet 2048/64, devnet 64/8): the lag means "slack inside one interval, so
// the key a height needs was settled before that height could be mined", and a
// local net that shrank the interval without shrinking the lag with it would be
// exercising a schedule whose shape no real network has.
func TestTheLocalNetKeepsTheLagRatio(t *testing.T) {
	p := loadLocalnet(t)
	if p.RandomXKeyLag == 0 {
		t.Fatal("randomx_key_lag is zero; the boundary would not be shifted at all")
	}
	if got := p.RandomXKeyInterval / p.RandomXKeyLag; got != 8 {
		t.Errorf("the local net's interval:lag ratio is %d:1 (%d/%d); both shipped "+
			"networks keep 8:1, and the ratio is what the lag means",
			got, p.RandomXKeyInterval, p.RandomXKeyLag)
	}
}

// TestTheLocalNetIsNotShipped keeps the recipe out of the release surface.
//
// The moment this file lands in spec/ it is picked up by the `params*.json`
// glob in spec/vector_test.go and becomes a network that must announce a
// parameter hash and pin a genesis — i.e. a network the project ships. It is
// not one. Keeping it under docs/ is what makes "throwaway" true rather than
// merely stated.
func TestTheLocalNetIsNotShipped(t *testing.T) {
	strays, err := filepath.Glob("../../spec/params*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range strays {
		if strings.Contains(filepath.Base(f), "localnet") {
			t.Errorf("%s is under spec/, where it becomes an embedded network that "+
				"has to announce a parameter hash and pin a genesis; the local net is "+
				"a throwaway run through --params and belongs under docs/", f)
		}
	}
}

// TestTheMakefileRunsTheRecipeTheReadmeDocuments is the wiring half.
//
// docs/localnet/README.md tells a reader that `make localnet` is the whole
// recipe. That sentence is only true while the target exists, points at this
// parameter file, and uses the randomx-tagged binary — a target built on the
// pure-Go `zycordd` would refuse to start against a randomx-v2 network, which
// is correct behaviour producing a completely mystifying experience for
// somebody following the documented path.
func TestTheMakefileRunsTheRecipeTheReadmeDocuments(t *testing.T) {
	raw, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mk := string(raw)

	body, ok := targetBody(mk, "localnet:")
	if !ok {
		t.Fatal("the Makefile has no `localnet` target, but docs/localnet/README.md " +
			"tells a reader `make localnet` is the whole recipe")
	}
	for _, want := range []string{
		"docs/localnet/params.randomx-localnet.json", // the recipe itself
		"zycordd-randomx", // the only binary that can run it
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the `localnet` target does not mention %q; the README's "+
				"documented path would not do what the README says", want)
		}
	}
	if !strings.Contains(mk, "localnet: build-randomx") {
		t.Error("the `localnet` target does not depend on build-randomx, so `make " +
			"localnet` on a clean tree runs a binary that refuses this network")
	}
}

// targetBody returns the recipe lines of a Make target: everything from the
// target line to the first line that is neither blank nor tab-indented.
func targetBody(mk, target string) (string, bool) {
	lines := strings.Split(mk, "\n")
	for i, ln := range lines {
		if !strings.HasPrefix(ln, target) {
			continue
		}
		var body []string
		for _, next := range lines[i+1:] {
			if next != "" && !strings.HasPrefix(next, "\t") {
				break
			}
			body = append(body, next)
		}
		return strings.Join(body, "\n"), true
	}
	return "", false
}
