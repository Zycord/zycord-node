// The Go toolchain pin, and the three files that have to keep agreeing about it.
//
// This file exists because nothing on the build path pinned a Go toolchain, so
// third-party reproducible-build verification failed by default. The defect it
// guards is not a bug in any program: it is that nothing CHOSE a compiler.
//
//	go.mod             said `go 1.25.0` and carried no `toolchain` line
//	build/Dockerfile   installed 1.26.2
//	a stranger         got whatever was on their PATH
//
// Three answers for one source tree, and the project's own release workflow
// recorded the consequence as three separate SHA-256 values for one commit and
// one flag set (go1.25.0, go1.26.0, go1.26.6). Reproducible builds are what this
// project offers INSTEAD of a code-signing certificate, and docs/INSTALL.md
// tells a verifier that a hash mismatch "looks like a compromised binary" — so
// the documented check produced a false alarm as its normal result, which is the
// most reliable way there is to train people to ignore a real one.
//
// The correction that is easy to lose, and the reason this file's first test is
// about GOTOOLCHAIN rather than about go.mod: **a `toolchain` directive does not
// pin anything.** Under GOTOOLCHAIN=auto, the default, `go` and `toolchain` are
// a FLOOR — "at least this much" — so a verifier with a newer Go installed still
// builds with the newer Go. GOTOOLCHAIN is the ceiling, and a ceiling is what a
// reproducibility claim needs.
//
// Four properties are pinned here:
//
//	the ceiling      the Makefile exports GOTOOLCHAIN at a concrete version, so
//	                 every `go` it runs is that compiler.
//	the refusal      `make build` will not produce a binary with another one. A
//	                 machine that cannot reach the pinned toolchain gets a
//	                 sentence about it instead of an unexplained hash mismatch.
//	one version      the Makefile, go.mod and build/Dockerfile name the SAME
//	                 version. The three-way disagreement is the defect; two of
//	                 them agreeing is not the fix.
//	it is written    docs/INSTALL.md names the version, because the page that
//	                 tells a stranger to rebuild and compare is where the missing
//	                 fact was missing.
//
// Read from the files rather than by running them, for the same reason
// canonical_test.go beside this gives: the canonical build needs a container,
// and what can be checked without one is that the recipes still say what they
// were changed to say.
package wiring_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The three files that name the toolchain, relative to this package.
const (
	goModPath      = repoRoot + "/go.mod"
	dockerfilePath = repoRoot + "/build/Dockerfile"
	installDocPath = repoRoot + "/docs/INSTALL.md"
)

var (
	// `GO_TOOLCHAIN := go1.26.2` in the Makefile — the pin itself.
	makefilePin = regexp.MustCompile(`(?m)^GO_TOOLCHAIN\s*[:?]?=\s*(go[0-9][^\s#]*)`)
	// `export GOTOOLCHAIN := $(GO_TOOLCHAIN)` — the pin made binding.
	makefileExport = regexp.MustCompile(`(?m)^export\s+GOTOOLCHAIN\s*[:?]?=\s*(\S+)`)
	// `toolchain go1.26.2` in go.mod — what CI installs.
	goModToolchain = regexp.MustCompile(`(?m)^toolchain\s+(go[0-9]\S*)`)
	// `ARG GO_VERSION=1.26.2` in build/Dockerfile — the container's Go.
	dockerfileGo = regexp.MustCompile(`(?m)^ARG\s+GO_VERSION=(\S+)`)
	// A concrete toolchain name: go1.26.2, not go1.26 and not `auto`.
	concreteToolchain = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)
)

// readRepoFile returns a file from the repository root, or fails the test.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// makefileToolchain returns the version the Makefile pins, or fails the test.
func makefileToolchain(t *testing.T, makefile string) string {
	t.Helper()
	m := makefilePin.FindStringSubmatch(makefile)
	if m == nil {
		t.Fatalf("the Makefile defines no GO_TOOLCHAIN.\n" +
			"That variable is the reproducibility pin: it is what GOTOOLCHAIN is\n" +
			"exported to, what `require-toolchain` compares against, and what go.mod\n" +
			"and build/Dockerfile have to agree with.")
	}
	return m[1]
}

// prerequisitesOf returns the prerequisite list of a Make target — everything
// after `name:` on the target's own line.
//
// Separate from recipeFor, which deliberately returns only the tab-indented
// command lines. A guard that runs BEFORE a recipe is not in the recipe, so a
// helper that reads recipes cannot see it at all.
func prerequisitesOf(makefile, name string) (string, bool) {
	for _, line := range strings.Split(makefile, "\n") {
		if !strings.HasPrefix(line, name+":") {
			continue
		}
		rest := strings.TrimPrefix(line, name+":")
		// A double-colon rule, and `::=`, are not what this reads.
		return strings.TrimSpace(strings.TrimPrefix(rest, ":")), true
	}
	return "", false
}

// TestTheBuildPinsAConcreteGoToolchain is the ceiling.
//
// The property: **the Makefile exports GOTOOLCHAIN at one concrete Go version.**
//
// Exported rather than set on a single recipe, because the pin has to reach
// every `go` this build runs: `build`, `dist`, `dist-randomx`, the wallet, the
// sub-makes `repro` spawns into its export directories, and the `make build`
// that runs inside the canonical container. A pin one recipe honours and the
// next does not is not a pin, it is a coincidence with a comment.
//
// And concrete — go1.26.2, not go1.26 and not `auto`. GOTOOLCHAIN accepts names
// that mean "resolve this later", and later is the machine of whoever happens
// to be building, which is the unpinned state this file exists to refuse.
func TestTheBuildPinsAConcreteGoToolchain(t *testing.T) {
	makefile := readMakefile(t)
	pin := makefileToolchain(t, makefile)

	if !concreteToolchain.MatchString(pin) {
		t.Errorf("GO_TOOLCHAIN is %q, which does not name one Go release.\n"+
			"A pin that still has to be resolved is resolved on the builder's machine,\n"+
			"which is the three-different-hashes state this pin exists to end. Use a full\n"+
			"goX.Y.Z.", pin)
	}

	m := makefileExport.FindStringSubmatch(makefile)
	if m == nil {
		t.Fatalf("the Makefile does not export GOTOOLCHAIN.\n"+
			"GO_TOOLCHAIN is %s, but a variable nothing exports changes no build. And\n"+
			"go.mod cannot do this job: under GOTOOLCHAIN=auto the `go` and `toolchain`\n"+
			"directives are a FLOOR, never a ceiling, so a verifier with a newer Go\n"+
			"installed still builds with the newer Go and still gets different bytes.\n"+
			"GOTOOLCHAIN is the only ceiling there is.", pin)
	}
	if got := strings.TrimSpace(m[1]); got != "$(GO_TOOLCHAIN)" && got != pin {
		t.Errorf("GOTOOLCHAIN is exported as %q while GO_TOOLCHAIN is %s.\n"+
			"Two versions in one file is the defect at a smaller scale: the pin has to\n"+
			"be one value that everything reads.", got, pin)
	}
}

// TestMakeBuildRefusesAnotherToolchain is the half that speaks.
//
// The property: **`build` runs a guard that compares `go env GOVERSION` against
// the pin and fails.**
//
// The export above forces the compiler wherever it can be forced. Where it
// cannot — no network to fetch the pinned toolchain, a GOTOOLCHAIN pinned
// elsewhere in the environment, a Go too old to switch at all — the build would
// otherwise succeed and produce a binary that does not match
// SHA256SUMS.binaries, with nothing said about why. docs/INSTALL.md tells the
// person holding that mismatch it "looks like a compromised binary". A refusal
// carrying the reason is the difference between a build system and a false
// accusation.
//
// `go env GOVERSION` specifically: it reports the toolchain that will actually
// run, after any switch, rather than what is on PATH. Checking the compiler is
// the point; checking PATH would pass on exactly the machines this is for.
func TestMakeBuildRefusesAnotherToolchain(t *testing.T) {
	makefile := readMakefile(t)
	pin := makefileToolchain(t, makefile)

	const guard = "require-toolchain"

	prereqs, ok := prerequisitesOf(makefile, "build")
	if !ok {
		t.Fatal("the Makefile has no `build:` target")
	}
	if !strings.Contains(prereqs, guard) {
		t.Errorf("`build` does not depend on `%s` (its prerequisites are %q).\n"+
			"The guard existing is not the check; `make build` running it is. This is\n"+
			"the target a verifier following docs/INSTALL.md invokes, so it is the one\n"+
			"that has to refuse a compiler other than %s.", guard, prereqs, pin)
	}

	recipe, ok := recipeFor(makefile, guard)
	if !ok {
		t.Fatalf("the Makefile has no `%s:` target.\n"+
			"Without it a wrong toolchain produces a binary whose hash silently\n"+
			"disagrees with the release, which docs/INSTALL.md teaches the reader to\n"+
			"read as tampering.", guard)
	}
	// Only the lines that DO something. This recipe prints eight lines of
	// explanation on the failure path, and every term this test looks for
	// appears in that prose — so a check over the whole recipe would be
	// satisfied by the message about the guard after the guard itself was
	// gone. That is the vacuous-assertion failure recipeFor's own header
	// records, arriving one level further in.
	var commands []string
	for _, line := range strings.Split(recipe, "\n") {
		if t := strings.TrimSpace(line); !strings.HasPrefix(t, "echo") {
			commands = append(commands, line)
		}
	}
	acting := strings.Join(commands, "\n")

	for _, want := range []string{"env GOVERSION", "$(GO_TOOLCHAIN)"} {
		if !strings.Contains(acting, want) {
			t.Errorf("no command in the `%s` recipe mentions %q:\n%s\n"+
				"It has to compare the toolchain that will actually compile against the\n"+
				"pinned one; anything else checks a different question.",
				guard, want, recipe)
		}
	}
	if !strings.Contains(recipe, "exit 1") {
		t.Errorf("the `%s` recipe never exits non-zero:\n%s\n"+
			"A guard that prints a warning and builds anyway still ships the mismatched\n"+
			"binary, and now with a line in the log saying it was expected.",
			guard, recipe)
	}
}

// TestTheThreeToolchainPinsAgree is the defect in its original shape: three
// files naming three Go versions for one source tree.
//
// The property: **the Makefile, go.mod and build/Dockerfile name the same Go
// version.**
//
// These are not three copies of a preference. Each is read by something
// different — the Makefile pins every build, go.mod is what every workflow's
// `go-version-file:` installs on a runner, and the Dockerfile is the Go inside
// the container `make canonical` certifies with — so a disagreement is three
// build paths producing three binaries, which is exactly the state the audit
// found and exactly what the release workflow's three recorded hashes are.
//
// Held here rather than by review because the last time it was held by review it
// drifted by a whole minor version and stayed that way through a release
// pipeline that recorded the divergence in its own comments.
func TestTheThreeToolchainPinsAgree(t *testing.T) {
	pin := makefileToolchain(t, readMakefile(t))

	gomod := goModToolchain.FindStringSubmatch(readRepoFile(t, goModPath))
	if gomod == nil {
		t.Errorf("go.mod carries no `toolchain` directive.\n"+
			"It is not the pin — a directive is a floor, never a ceiling — but it IS\n"+
			"what every `go-version-file: go.mod` in .github/workflows/ installs, so\n"+
			"without it the release runners resolve the `go` line (an older version)\n"+
			"and then have to fetch %s to obey the Makefile. Name %s here.", pin, pin)
	} else if gomod[1] != pin {
		t.Errorf("go.mod pins %s and the Makefile pins %s.\n"+
			"CI installs go.mod's; every build obeys the Makefile's. Two versions on\n"+
			"one build path is the defect.", gomod[1], pin)
	}

	docker := dockerfileGo.FindStringSubmatch(readRepoFile(t, dockerfilePath))
	if docker == nil {
		t.Errorf("build/Dockerfile declares no `ARG GO_VERSION=`.\n" +
			"The canonical container's Go is the compiler `make canonical` certifies\n" +
			"with; it cannot be left to the image.")
	} else if got := "go" + docker[1]; got != pin {
		t.Errorf("build/Dockerfile installs %s and the Makefile pins %s.\n"+
			"`make canonical` runs `make build` INSIDE that container, so the Makefile's\n"+
			"exported GOTOOLCHAIN would ask a container holding one Go to build with\n"+
			"another — a download an offline build image cannot make, and a silent\n"+
			"substitution if it could.", got, pin)
	}
}

// TestTheInstallDocsNameTheGoVersion is the part that reaches the reader.
//
// The property: **docs/INSTALL.md names the pinned Go version.**
//
// That page is where a stranger is told to `git clone && make build` and where
// it says of the resulting hashes "They must match exactly". At the time of the
// audit nothing on it named a Go version at all, while five lines were spent on
// CRLF line endings — so the one variable that decided whether the comparison
// could succeed was the one fact the instructions omitted.
//
// The Makefile now refuses rather than letting the mismatch happen, but a
// refusal is a thing you meet after deciding to build. The version belongs where
// the decision is made.
func TestTheInstallDocsNameTheGoVersion(t *testing.T) {
	pin := makefileToolchain(t, readMakefile(t))
	doc := readRepoFile(t, installDocPath)

	if !strings.Contains(doc, pin) {
		t.Errorf("docs/INSTALL.md never names %s.\n"+
			"It is the page that says `git clone && make build` and then says the hashes\n"+
			"\"must match exactly\". Which compiler produces those hashes is not a detail\n"+
			"of the build, it is a term of the comparison.", pin)
	}
	if !strings.Contains(doc, "GOTOOLCHAIN") {
		t.Errorf("docs/INSTALL.md does not mention GOTOOLCHAIN.\n" +
			"Naming a version without saying that the build enforces it invites the\n" +
			"reader to treat it as a minimum and use whatever newer Go they have —\n" +
			"which is precisely the floor-not-ceiling mistake this pin prevents.")
	}
	if !strings.Contains(doc, "go version -m") {
		t.Errorf("docs/INSTALL.md does not show `go version -m`.\n" +
			"Go stamps the toolchain into the binary, so a verifier can read the\n" +
			"expected version straight out of the released artefact instead of trusting\n" +
			"this documentation about it. That is the cheapest independent check on\n" +
			"this page and it costs one line.")
	}
}
