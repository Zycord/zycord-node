// The canonical build's artefacts, and the comparison that has a term for the
// one a release actually ships.
//
// This file exists because `make canonical` overwrote the artefact it had just
// produced, and it is the same shape as the workflow checks beside it: a build
// that was correct, complete, and connected to nothing that would notice it
// destroying its own output.
//
// `make canonical` runs `make build build-randomx` in ONE container invocation.
// `build` wrote bin/zcd and bin/zycordd; `build-randomx` wrote bin/zcd and
// bin/zycordd too, because $(EXE) is empty on Linux and the two targets differed
// only by that variable. So the cgo binaries silently replaced the pure-Go ones,
// the canonical build certified an artefact no release contains, and the
// artefact every release does contain was deleted by the same command.
//
// Nothing caught it, and the reason is the part worth keeping. The canonical CI
// job of the day ran `make canonical` twice and diffed the checksums, which
// reads like exactly the check for this. It was not: both sides of that diff
// are the surviving binary, so the comparison has no term for what was lost and
// is structurally incapable of reporting it. A check whose signal is derived
// from the state the defect corrupts is the mirror CONTRIBUTING.md tabulates.
// That job no longer exists — nothing but the release build runs on a hosted
// runner now, and sim/wiring/workflow_test.go records why — so the comparison
// below is run from the release checklist instead.
//
// Two properties are pinned here, and they are the two halves of the fix.
//
//	disjoint outputs   no output path is written by both `build` and
//	                   `build-randomx`. That is what makes running them in one
//	                   invocation safe, and it is checked with $(EXE) removed,
//	                   because $(EXE) expanding to nothing is the whole
//	                   mechanism — comparing the recipes as written would have
//	                   called `$(BIN)/zcd$(EXE)` and `$(BIN)/zcd` two different
//	                   paths and passed on the defect itself.
//
//	the missing diff   the canonical build's pure-Go output is compared against
//	                   the linux binary `make dist` stages, which is what every
//	                   archive contains and what release.yml publishes. That
//	                   comparison has both terms, so the overwrite cannot come
//	                   back silently — and the architecture it compares is read
//	                   out of the container rather than written down, or the
//	                   comparison fails on arm64 hardware for a reason that is
//	                   not this defect while saying that it is.
//
// Read from the Makefile and the workflow rather than by running them: `make
// canonical` needs a container, which is what section 5 of the audit records as
// the reason this defect was inferred and never observed. What can be checked
// without Docker is that the recipes still say what they were changed to say,
// and that CI still calls the target that makes the comparison.
package wiring_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// releaseDocPath is the release procedure, which is where the caller of
// `canonical-dist-diff` lives now that no workflow runs it.
const releaseDocPath = repoRoot + "/docs/RELEASE.md"

// outputFlag finds a `go build -o PATH` argument in a recipe.
var outputFlag = regexp.MustCompile(`-o\s+(\S+)`)

// outputPaths returns the -o arguments of a Make recipe, with `$(EXE)` removed.
//
// The removal is the point rather than a convenience. `$(EXE)` is empty on every
// platform but Windows, so `$(BIN)/zcd$(EXE)` and `$(BIN)/zcd` are the same file
// on the platform every release is built on. A comparison of the recipes as
// typed sees two different strings and reports no collision — which is the
// defect reading itself and calling itself well.
func outputPaths(recipe string) []string {
	var out []string
	for _, m := range outputFlag.FindAllStringSubmatch(recipe, -1) {
		out = append(out, strings.ReplaceAll(m[1], "$(EXE)", ""))
	}
	return out
}

// readMakefile returns the Makefile, or fails the test.
func readMakefile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(makefilePath))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	return string(b)
}

// TestTheTaggedBuildCannotOverwriteTheUntaggedOne is the overwrite at its
// source.
//
// The property: **`build` and `build-randomx` write disjoint sets of files.**
//
// `canonical` invokes both in one container invocation, so a shared output path
// is not a collision that might happen — it is one target deleting the other's
// work, every time, with no error and no log line.
func TestTheTaggedBuildCannotOverwriteTheUntaggedOne(t *testing.T) {
	makefile := readMakefile(t)

	pure, ok := recipeFor(makefile, "build")
	if !ok {
		t.Fatal("the Makefile has no `build:` target")
	}
	tagged, ok := recipeFor(makefile, "build-randomx")
	if !ok {
		t.Fatal("the Makefile has no `build-randomx:` target")
	}

	pureOut := outputPaths(pure)
	taggedOut := outputPaths(tagged)
	if len(pureOut) == 0 || len(taggedOut) == 0 {
		t.Fatalf("no `-o` output found in one of the build recipes; this check has gone blind.\n"+
			"build:\n%s\nbuild-randomx:\n%s", pure, tagged)
	}

	written := map[string]bool{}
	for _, p := range pureOut {
		written[p] = true
	}
	for _, p := range taggedOut {
		if written[p] {
			t.Errorf("`build` and `build-randomx` both write %s.\n"+
				"`make canonical` runs them in ONE container invocation, so the second\n"+
				"silently replaces the first: the canonical build then certifies the cgo\n"+
				"binary, which no release contains, and destroys the pure-Go one, which\n"+
				"every release does. Compared with $(EXE) removed, because $(EXE)\n"+
				"is empty on Linux and that is the platform releases are built on.\n"+
				"build:         %v\nbuild-randomx: %v", p, pureOut, taggedOut)
		}
	}
}

// TestTheCanonicalBuildIsComparedAgainstWhatDistShips is the other half of the
// fix: the guard that keeps the overwrite from returning.
//
// The property: **a Makefile target compares the canonical build's pure-Go
// output against the linux binary `make dist` stages for the container's own
// architecture, and the canonical CI job runs it.**
//
// The two conditions are one property split across two files, and neither half
// is worth anything alone — a target nothing calls is the state where a fix
// lands in the Makefile and never reaches the job that was failing, and a CI
// step calling a target that no longer makes the comparison is the same thing
// wearing a green tick.
func TestTheCanonicalBuildIsComparedAgainstWhatDistShips(t *testing.T) {
	makefile := readMakefile(t)

	const target = "canonical-dist-diff"
	recipe, ok := recipeFor(makefile, target)
	if !ok {
		t.Fatalf("the Makefile has no `%s:` target.\n"+
			"Diffing `make canonical` against itself compares the surviving binary with\n"+
			"itself, so it has no term for the artefact a release ships. This target is\n"+
			"the comparison that does.", target)
	}

	// The dist half. Without it the target compares the canonical build against
	// something else entirely, or against nothing.
	for _, want := range []string{"dist", "PLATFORMS=linux/"} {
		if !strings.Contains(recipe, want) {
			t.Errorf("the `%s` recipe no longer mentions %q:\n%s\n"+
				"The comparison is against what `make dist` stages for linux —\n"+
				"the binary every archive contains and release.yml publishes.",
				target, want, recipe)
		}
	}

	// And the architecture it stages is READ from the container rather than
	// written into the recipe.
	//
	// `canonical` runs `make build`, which sets no GOOS/GOARCH and therefore
	// produces the container's NATIVE binaries. A hard-coded `linux/amd64`
	// compares those against a cross-compiled amd64 archive on an arm64 host —
	// build/Dockerfile pins a Go checksum for arm64, and RELEASE §5 records that
	// this project has arm64 hardware — so the hashes can never match and the
	// target reports the architecture difference in the words "one target
	// overwriting the other's output". A check that is wrong on the maintainer's
	// own machine, with authority, is the failure mode `require-clean-tree` exists
	// to avoid, and it is the one that gets a check deleted on the day it is
	// right.
	if !strings.Contains(recipe, "go env GOARCH") {
		t.Errorf("the `%s` recipe does not read GOARCH out of the container:\n%s\n"+
			"`canonical` builds the container's native binaries, so the `dist` half has\n"+
			"to be staged for the container's own architecture or the comparison is\n"+
			"native-vs-cross and fails on any non-amd64 host.", target, recipe)
	}
	if m := regexp.MustCompile(`linux/(?:amd64|arm64|386|arm|riscv64|ppc64le|s390x)\b`).FindString(recipe); m != "" {
		t.Errorf("the `%s` recipe hard-codes %q:\n%s\n"+
			"The platform has to follow the container's own GOARCH; a literal one makes\n"+
			"the comparison native-vs-cross on every other host and blames the\n"+
			"overwrite for the difference.", target, m, recipe)
	}

	// The pure-Go half: the canonical outputs it compares are `build`'s, not
	// `build-randomx`'s. Comparing the tagged binary against a dist archive
	// that has never contained one would fail for a reason that is not this
	// defect, and would be "fixed" by deleting the check.
	pure, ok := recipeFor(makefile, "build")
	if !ok {
		t.Fatal("the Makefile has no `build:` target")
	}
	for _, p := range outputPaths(pure) {
		if !strings.Contains(recipe, p) {
			t.Errorf("the `%s` recipe does not name %s, which is what `build` writes and\n"+
				"what a release archive contains:\n%s", target, p, recipe)
		}
	}

	// And something calls it. This used to read ci.yml's canonical job; there is
	// no ci.yml any more — see sim/wiring/workflow_test.go for why nothing but
	// the release build runs on a hosted runner — so the caller is a person
	// working through the release checklist, and the checklist is what has to
	// name the target.
	//
	// That is a weaker guarantee than a job and it is stated rather than
	// glossed: a checklist item can be skipped and a job cannot. What has not
	// changed is the failure this half exists to prevent, which was never a
	// runner going missing but a fix landing in the Makefile and reaching
	// nothing — the target existing while no caller of it does. A checklist
	// item is a caller, and one that has been deleted is the same silence as a
	// deleted job.
	if !strings.Contains(readRepoFile(t, releaseDocPath), "make "+target) {
		t.Errorf("docs/RELEASE.md does not name `make %s`.\n"+
			"The target existing is not the guard; running it is. Nothing runs on a\n"+
			"hosted runner except the release build, so the release checklist is the\n"+
			"only caller this target has — and a comparison nobody is told to make is\n"+
			"the state that let the canonical build certify a binary no release\n"+
			"contains.", target)
	}
}

// TestTheCanonicalCheckSeesBothPairsOfBinaries pins the consequence of the
// rename that is easy to lose.
//
// The property: **the canonical build's RandomX outputs are named by the
// canonical check.**
//
// Before the rename there was one pair of files and the byte-identical check
// hashed it without knowing which build had produced it. There are now four
// files, and a check that still hashes only `bin/zcd` and `bin/zycordd` leaves
// the binary a RandomX network actually runs uncompared — the cgo half, which is
// the half a C toolchain can make irreproducible, which is why the container
// exists at all.
//
// Read from the Makefile alone. It used to also read ci.yml's canonical job,
// because the check could reasonably live in either; there is no ci.yml now, and
// a workflow read that can only ever come back empty is a term that quietly
// stops carrying its half of the condition.
func TestTheCanonicalCheckSeesBothPairsOfBinaries(t *testing.T) {
	makefile := readMakefile(t)

	tagged, ok := recipeFor(makefile, "build-randomx")
	if !ok {
		t.Fatal("the Makefile has no `build-randomx:` target")
	}

	var seen strings.Builder
	if recipe, ok := recipeFor(makefile, "canonical"); ok {
		seen.WriteString(recipe)
	}
	if recipe, ok := recipeFor(makefile, "canonical-dist-diff"); ok {
		seen.WriteString(recipe)
	}
	text := seen.String()

	for _, p := range outputPaths(tagged) {
		// The recipes write $(BIN)/…; a workflow step writes bin/… . Compare on
		// the file name, which both spell the same way.
		name := p[strings.LastIndexByte(p, '/')+1:]
		if !strings.Contains(text, name) {
			t.Errorf("nothing in the canonical job or the canonical Make targets names %q,\n"+
				"which `build-randomx` writes. The container pins the C toolchain, so the\n"+
				"cgo binaries are the ones whose reproducibility it exists to check; a\n"+
				"canonical check that hashes only the pure-Go pair leaves them unchecked.",
				name)
		}
	}
}
