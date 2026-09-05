// Anonymity, asked by the build rather than by whoever remembers.
//
// This project publishes pseudonymously and the repository goes public at
// launch, so everything in the tree is published with it. `RELEASE.md` §3 and
// `PROTOCOL.md` rule 4 both say to grep before committing, and the grep is
// correct — it is just a grep a human has to remember to run, and the cost of
// forgetting it once is not symmetric with the cost of running it: publication
// is a one-way door, and a leak that has already been pushed is mitigable
// rather than removable.
//
// So the same move this package already makes for wiring: take the question off
// the person and give it to the build.
//
// # The identity class is not here, and cannot be
//
// Real name, account handle, the codename of any other project: none of those
// can be carried by a tracked regexp, because writing the handle into a tracked
// pattern *publishes the handle*. The eight classes below are the ones a
// committed pattern can assert. The ninth is covered by the manual grep in
// `RELEASE.md` §3, and by `TestNoAbsoluteGitHubURLIsPublished` in
// `github_url_test.go` for the one *shape* of it that can live in git — an
// absolute forge URL, whose first path segment is an account name by
// construction. Neither is a substitute for the other.
//
// # What this does not cover
//
// Read this list before treating a green run as an answer.
//
//  1. **Real names, account handles, and the names of the author's other
//     projects.** See above: asserted by nobody in this file. `RELEASE.md` §3
//     carries it as a human obligation.
//  2. **Operating-system versions and GOOS/GOARCH**, because the question they
//     turn on is one no regexp can ask: *does the string tell a reader
//     something they need about the software, or only something about where the
//     author sits?* `core/pow/randomx/randomx_cgo.go` says a missing
//     `pthread_jit_write_protect_np` call is a SIGBUS every time on a named
//     platform and toolchain — that platform is the *subject* of the sentence,
//     it is where the crash reproduces, and without it the claim stops being
//     falsifiable. A machine model quoted ahead of a memory figure is the
//     opposite case: there the numbers are the point and the model adds
//     nothing, and it is the model that goes. Over-sanitising is
//     a real cost rather than a safe default, so the mechanised half takes what
//     a pattern can decide and leaves what it cannot.
//  3. **A maker-less product name with no vendor word on its line.** The bare
//     `core`-plus-digit branch was removed, not narrowed: it reported six of
//     ten ordinary systems sentences as CPU models, and rule 4's own sanctioned
//     wording -- describe a machine by its core count -- sits right beside it.
//     A product name of that era essentially always carries the maker word, on
//     which `classVendor` fires unconditionally, so what is actually given up
//     is the maker-less quotation. That residue is here rather than papered
//     over.
//  4. **Encoded payloads inside files that are text.** A leak base64'd or
//     hex-encoded into a `.json` or `.md` passes every pattern here. Nothing
//     is decoded.
//  5. **Prose voice.** `RELEASE.md` §4 is about first-language-influenced
//     phrasing and repeated typos. No regexp sees them; that pass stays human.
//  6. **Anything outside the tree.** Commit messages, PR bodies and issue text
//     are published too and are not reachable from here. `PROTOCOL.md` rule 4
//     covers them and remains a human obligation.
//
// One *shape* of limit 1 is taken back by `TestNoAbsoluteGitHubURLIsPublished`
// in `github_url_test.go`: it needs no untracked file and cannot be forgotten,
// because the literal it keys on is a service name rather than an identity. It
// still cannot see a handle as a handle; nothing tracked can.
package wiring_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	classCPU     = "CPU model"
	classApple   = "Apple silicon model"
	classGPU     = "GPU model"
	classVendor  = "hardware vendor"
	classPath    = "home-directory path"
	classMachine = "machine name"
	classEmail   = "e-mail address"
	classTZ      = "timezone"
)

// identifiers is the closed list of classes recognised by a tracked pattern.
//
// **Each pattern is narrow enough not to fire on legitimate protocol content,
// because a pattern that cries wolf gets suppressed and a suppressed check is
// not one** — this repository's own milestones are named M0..M5, so the Apple
// rule requires the literal "Apple" or it would fire on every milestone mention
// in `ARCHITECTURE.md` and be dead within a week.
//
// **But narrow patterns catch only the shapes their author thought of, and a
// guard that covers the imagined cases is not a guard.** Written tight, the
// model patterns below miss current part-number shapes entirely. They are wide
// here, and
// `classVendor` is the backstop for the shapes nobody imagined: a sentence in
// this repository that names a CPU or GPU maker at all is reported, whatever
// model string follows it.
var identifiers = []identifier{
	{
		class: classCPU,
		// **Two shapes and a word list, and the closing `\b` is gone from both
		// shapes on purpose.**
		//
		// The previous version ended every alternative with `\b` after a fixed
		// run of digits or letters, and that is not a widening that can be
		// completed by adding literals -- it excludes whole families by
		// construction. `\b` needs a word/non-word transition, so a suffix that
		// ends in a digit after its letters (`i7-1165G7`) has no boundary after
		// the letters and none after the digits either, and the match fails at
		// both. Anchoring the END of a part number is the error: a part number
		// is a prefix followed by whatever the vendor felt like.
		//
		// Likewise `ryzen( ai)? [0-9]\b` required a family digit and so missed
		// every SKU quoted without one (`Ryzen 7950X`), while seven sibling
		// makers next to it were already bare. `ryzen` is bare now, like them.
		//
		// This is the defect that a probe set cannot catch, and the arming
		// below is why the distinction matters: a probe set proves the patterns catch
		// the shapes their author thought of, and nothing more. The claim that has to
		// hold is about the SHAPE.
		pattern: regexp.MustCompile(`(?i)` +
			// Intel-style part numbers: family digit, optional separator, SKU
			// digits, then any tail the vendor chose. Unanchored at the end.
			`\bi[3-9][- ]?[0-9]{3,5}[a-z]{0,3}[0-9]{0,2}` +
			// Family names that take a SKU on the same or a following token.
			// `core` cannot be bare (this repository is full of `core/`), so it
			// carries the smallest suffix that makes it a product name: the
			// maker-prefixed form and the tier-named one.
			//
			// **A third alternative, bare `core` followed by any digit, was
			// removed rather than narrowed, and the difference matters.** It
			// was not quietened because it was noisy; it was wrong. It matched
			// ordinary systems prose -- a per-core buffer size, a pinned worker
			// index, a hyphenated lane name, a single-core speedup -- six of
			// ten legitimate sentences probed. That is the false-positive class
			// the comment on this list warns about two paragraphs up, and it is
			// worse here than anywhere: `PROTOCOL.md` rule 4 now tells authors
			// to describe a machine by its CORE COUNT, so the sanctioned
			// replacement wording sits directly beside the pattern. The tree is
			// green today by accident of phrasing, and the first commit that
			// phrases it otherwise turns this red for a non-leak, under time
			// pressure -- which is how the exemption gets added and the guard
			// dies.
			//
			// It costs no coverage in practice: a bare product name of that era
			// essentially always carries the maker word, which classVendor
			// fires on unconditionally. What is genuinely given up is the
			// maker-less form quoted with no vendor word anywhere on the line,
			// and that is recorded in the limits above rather than papered over.
			`|\bcore[ -](i[3-9]|ultra[ -]?[0-9])` +
			// Bare maker and family words: a SKU beside any of these is caught
			// by the word, whatever shape the SKU has.
			`|\b(ryzen|threadripper|epyc|xeon|pentium|celeron|athlon|snapdragon|exynos|kryo)\b`),
	},
	{
		class: classApple,
		// "Apple" is required: milestone M1 is all over this repository. The
		// second alternative catches the tier names, which do not repeat as
		// milestones.
		pattern: regexp.MustCompile(`(?i)\bApple M[0-9]\b|\bM[0-9] (Pro|Max|Ultra)\b`),
	},
	{
		class: classGPU,
		// Same rule as classCPU: the maker words are bare, and the SKU shapes
		// are not anchored at their end (`RTX 4090D`, `RTX 5090 Ti`).
		pattern: regexp.MustCompile(`(?i)\b(geforce|radeon|quadro|rtx ?[0-9]{3,4}[a-z]{0,3}|gtx ?[0-9]{3,4}[a-z]{0,3}|arc a[0-9]{3})`),
	},
	{
		class: classVendor,
		// The backstop for a model string this file has never heard of.
		// "Apple" is deliberately absent: it is unavoidable in this repository
		// for reasons that have nothing to do with hardware -- Developer ID,
		// `com.apple.quarantine`, the plist DTD -- and the model form is
		// already covered by classApple.
		pattern: regexp.MustCompile(`(?i)\b(intel|amd|nvidia|qualcomm|mediatek)\b`),
	},
	{
		class: classPath,
		// The shape a build path, a shell transcript or a stack trace leaks:
		// the separator is followed by an actual account name.
		pattern: regexp.MustCompile(`(?i)(/home/[a-z_][a-z0-9_.-]*|/Users/[a-z_][a-z0-9_.-]*|[a-z]:[\\/]Users[\\/])`),
	},
	{
		class:   classMachine,
		pattern: regexp.MustCompile(`(?i)(\bDESKTOP-[A-Z0-9]{7}\b|\bLAPTOP-[A-Z0-9]{7}\b|\bMacBook\b|\biMac\b|\bMac ?mini\b)`),
	},
	{
		class: classEmail,
		// Go module versions (`golang.org/x/crypto@v0.54.0`) do not match: the
		// domain half here must end in letters.
		pattern: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}`),
	},
	{
		class:   classTZ,
		pattern: regexp.MustCompile(`\b(America|Europe|Asia|Africa|Australia)/[A-Za-z_]+\b`),
	},
}

type identifier struct {
	class   string
	pattern *regexp.Regexp
}

// selfPath is this file, which necessarily contains every tracked pattern and
// would otherwise be the one file that always fails.
//
// It is a single path rather than a prefix, so it cannot grow into a place to
// put things, and this file quotes no leak: the removed laptop model is
// *described* above rather than repeated, precisely because this is the one
// path the scan skips.
const selfPath = "sim/wiring/anonymity_test.go"

// skipped is the complete list of places this guard does not look, and it is
// deliberately keyed on a class as well as a path.
//
// **An earlier version skipped the whole vendored tree for every class, and
// claiming that as an exemption-free guard was wrong.** It was broader than its
// own reason in both dimensions at once: 88 files, when the reason applies to
// 26 of them, and all eight classes, when the reason applies to two. Measured
// by disabling it: 71 findings under that prefix, every one an e-mail address
// in a BSD licence header, plus 4 vendor-name mentions. A hardware model, a
// home path or a machine name planted anywhere under it was invisible.
//
// So the scope is now the narrowest thing that justifies itself:
//
//   - classEmail under `vendored`: the upstream author's address in a BSD
//     licence notice. Reproducing that notice is a licence obligation, and
//     removing it would be a licence violation dressed as a privacy fix. It
//     identifies upstream, not us.
//   - classVendor under `vendored`: upstream's own commentary on x86
//     microarchitecture (`decodes to 2 uOPs on Intel CPUs`), an `.intel_syntax`
//     assembler directive, and an `__INTEL_COMPILER` feature macro. Those are
//     statements about CPUs the code runs on, not about the machine it was
//     built on.
//
// Every other class is asserted over the vendored tree exactly as it is over
// ours.
// runnerLabel matches the GitHub-hosted runner labels that carry a hardware
// vendor's name in them.
//
// There is exactly one today and the pattern is written tightly enough that a
// second one has to be added deliberately: `macos-<n>-intel`, which is what
// GitHub calls its x86-64 macOS image now that the numbered Intel images have
// reached end of life. A workflow cannot spell it any other way -- `runs-on`
// takes a literal label, not an expression that could be assembled from parts
// -- so the choice is this pattern or no x86-64 macOS build at all.
var runnerLabel = regexp.MustCompile(`\bmacos-[0-9]+-intel\b`)

// vendorInRunnerLabel reports whether a hardware-vendor match sits INSIDE a
// runner label in a workflow file, which is the one place the class fires on
// something that is not about this machine.
//
// **This is the narrowest exemption the guard has and it is deliberately not
// shaped like the other one.** `skipped` exempts a whole file for a whole
// class; this exempts a single match, at a single position, on a line of a
// workflow file, and only when that position falls inside a label GitHub
// publishes. A vendor name anywhere else on the same line still fires, and so
// does one in a workflow comment.
//
// The reasoning the class encodes is "a CPU vendor in this tree narrows who
// wrote it". A runner label narrows nothing: it names a machine GitHub owns and
// rents to everybody, and it is in the tree because the release has to build
// for that architecture. Weighed the other way, the cost of not having it is
// every x86-64 Mac losing the only archive that can join a network -- a real
// population, paying for a false positive.
func vendorInRunnerLabel(rel, class, line string, at []int) bool {
	if class != classVendor || !strings.HasPrefix(rel, ".github/workflows/") {
		return false
	}
	for _, span := range runnerLabel.FindAllStringIndex(line, -1) {
		if at[0] >= span[0] && at[1] <= span[1] {
			return true
		}
	}
	return false
}

func skipped(rel, class string) bool {
	if rel == selfPath {
		// This file contains every pattern it scans for, so without the skip it
		// would be the one file that always fails. The cost is exact and worth
		// naming: this path is the one place a leak could be quoted into without
		// the sweep reading it. That is why `selfPath` is a single file and
		// never a prefix — an exemption that can grow is an exemption that will.
		return true
	}
	if strings.HasPrefix(rel, vendored) {
		return class == classEmail || class == classVendor
	}
	return false
}

// TestNoMachineIdentifierIsPublished scans every file the repository would
// publish -- its contents and its path -- for the classes above.
//
// The subject is the git tree rather than the working directory, because the
// git tree is exactly what publication copies: an ignored build output in the
// working directory is not published, and a tracked one is.
func TestNoMachineIdentifierIsPublished(t *testing.T) {
	root := filepath.Join("..", "..")
	tracked := trackedFiles(t, root)
	// Every pattern this guard has is a tracked literal, so the closed list is
	// the whole set: nothing is loaded at run time and nothing can be absent.
	patterns := identifiers

	// Every match on a line is reported, not the first: a report that stops at
	// one match tells whoever is fixing it that they are done when they are not.
	var findings []string

	for _, f := range tracked {
		// The PATH is published too, and a leak can sit entirely in a file
		// name while its contents are blameless.
		for _, id := range patterns {
			if skipped(f.path, id.class) {
				continue
			}
			for _, m := range id.pattern.FindAllString(f.path, -1) {
				findings = append(findings,
					f.path+"  [filename: "+id.class+"] "+m)
			}
		}

		if f.symlink() {
			continue // TestNothingPublishedIsOpaqueToTheTextScan owns these.
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.path)))
		if err != nil {
			t.Fatalf("read tracked file %s: %s", f.path, reason(err))
		}
		if !isText(body) {
			continue // likewise.
		}
		for lineNo, line := range strings.Split(string(body), "\n") {
			for _, id := range patterns {
				if skipped(f.path, id.class) {
					continue
				}
				for _, at := range id.pattern.FindAllStringIndex(line, -1) {
					if vendorInRunnerLabel(f.path, id.class, line, at) {
						continue
					}
					findings = append(findings, f.path+":"+strconv.Itoa(lineNo+1)+
						"  ["+id.class+"] "+line[at[0]:at[1]])
				}
			}
		}
	}

	if len(findings) > 0 {
		t.Fatalf("%d identifier(s) would be published with this tree:\n  %s\n\n"+
			"This repository is published pseudonymously and going public is a\n"+
			"one-way door: fix it here, because after the push the options are\n"+
			"mitigation and acceptance rather than removal.\n"+
			"Describe a machine only as far as the measurement requires -- core or\n"+
			"thread count, and whether it was loaded (PROTOCOL.md rule 4).",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// TestNothingPublishedIsOpaqueToTheTextScan is the half the sweep above cannot
// do for itself.
//
// A scan over text is a statement about text. A tracked binary is published
// byte for byte and can hold every class in `identifiers`: Go writes the
// absolute path of every compiled source file into the binary, so a build
// artefact carries the author's home directory whether or not anybody thought
// about it. `git grep -I` skips those files **silently**, which is the failure
// mode this test exists to remove — the scan does not get to be quiet about
// what it could not read. It is not a hypothetical: the sweep that produced
// this file found one 4 MB build artefact tracked in the root directory,
// carrying a home-directory path in thirty-three places, that every text grep
// run against this repository had passed over without a word.
//
// Three shapes are opaque, and only the first is obvious:
//
//   - A file with a NUL byte anywhere in it. The scan reads the **whole** file
//     rather than the first 8 KiB. Git's own rule is head-only, and a file
//     that is plausible text for 8 KiB and a binary payload afterwards passes a
//     head-only test while publishing whatever is past the boundary.
//   - A **symlink**, whose published blob content is the target path while
//     `os.ReadFile` follows it and returns the target's bytes. The guard would
//     read something other than what is published. There are none today.
//   - A **gitlink**: a submodule commit this repository publishes a pointer to
//     and whose contents no scan here can reach.
//
// **There is no exemption list here, and its absence is the design.** An
// exemption table is where a guard goes to stop being one: the entry is written
// with a reason, the reason stops being true, and the table keeps passing
// green. If a tracked file cannot be read as text, either it does not belong in
// a repository that is published pseudonymously, or the argument for keeping it
// is strong enough to be made in a review rather than in a map literal.
func TestNothingPublishedIsOpaqueToTheTextScan(t *testing.T) {
	root := filepath.Join("..", "..")

	var opaque []string
	for _, f := range trackedFiles(t, root) {
		switch {
		case f.symlink():
			opaque = append(opaque, f.path+"  (symlink: the published blob is "+
				"the target path, which is not what a reader of this file sees)")
			continue
		case f.gitlink():
			opaque = append(opaque, f.path+"  (submodule: contents unreachable "+
				"from this repository)")
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.path)))
		if err != nil {
			t.Fatalf("read tracked file %s: %s", f.path, reason(err))
		}
		if !isText(body) {
			opaque = append(opaque, f.path+"  (binary)")
		}
	}

	if len(opaque) > 0 {
		t.Fatalf("%d tracked file(s) the text scan cannot read:\n  %s\n\n"+
			"A binary is published byte for byte and carries build paths the text\n"+
			"scan is blind to. Nothing in this repository needs to be shipped as an\n"+
			"opaque blob; if something does, that is a review conversation and not\n"+
			"an entry in an exemption table.",
			len(opaque), strings.Join(opaque, "\n  "))
	}
}

// TestTheRunnerLabelExemptionIsNarrow arms the one exemption that could hide a
// real leak, because an exemption nobody probes is a hole nobody sees.
//
// Every occurrence on a line is judged, not the first. That is how the guard
// itself works and it is the whole point of the mixed case below: a line
// carrying the label AND a genuine mention must exempt one and report the
// other, which a test that looked at a single match would call either way and
// be wrong half the time.
func TestTheRunnerLabelExemptionIsNarrow(t *testing.T) {
	const wf = ".github/workflows/release.yml"
	// Assembled rather than written out, so this file does not itself carry a
	// vendor name the sweep would then have to be taught to ignore.
	vendor := "int" + "el"
	word := regexp.MustCompile(`(?i)\b` + vendor + `\b`)

	for _, c := range []struct {
		name string
		path string
		line string
		// want[i] is whether the i-th occurrence on the line is exempted.
		want []bool
	}{
		{"the label itself", wf, "          - os: macos-15-" + vendor, []bool{true}},
		{"the label under runs-on", wf, "    runs-on: macos-15-" + vendor, []bool{true}},
		{"label and a real mention together", wf,
			"          - os: macos-15-" + vendor + "  # built on my " + vendor + " box",
			[]bool{true, false}},
		{"prose in a workflow", wf,
			"      # measured on an " + vendor + " laptop", []bool{false}},
		{"a version that is not a label", wf,
			"    runs-on: macos-" + vendor, []bool{false}},
		{"the same label outside a workflow", "docs/RELEASE.md",
			"we build on macos-15-" + vendor, []bool{false}},
	} {
		t.Run(c.name, func(t *testing.T) {
			found := word.FindAllStringIndex(c.line, -1)
			if len(found) != len(c.want) {
				t.Fatalf("fixture carries %d occurrence(s), want[] has %d: %q",
					len(found), len(c.want), c.line)
			}
			for i, at := range found {
				got := vendorInRunnerLabel(c.path, classVendor, c.line, at)
				if got != c.want[i] {
					t.Errorf("occurrence %d at %d: exempted=%v, want %v\n"+
						"  path: %s\n  line: %s\n"+
						"The exemption covers a vendor name INSIDE a runner label in a\n"+
						"workflow file and nothing else. If this now passes something\n"+
						"wider, the class has stopped meaning what it says.",
						i, at[0], got, c.want[i], c.path, c.line)
				}
			}
		})
	}
}
