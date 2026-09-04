// The third half of the identity-and-history guard: a document that only makes
// sense next to a history the reader does not have.
//
// `anonymity_test.go` keeps a name out of the published bytes and
// `github_url_test.go` keeps an absolute forge URL out of them. Both are about
// *identity*. This one is about *reachability*, and it exists because of what
// the fix in `github_url_test.go` deliberately left behind: sixty-eight absolute
// forge URLs were rewritten to bare issue numbers, and that was recorded at the
// time as a waypoint rather than a terminal form.
//
// The terminal form is decided by how this repository is published. It is
// published as **files**: a fresh `git init` under an unlinked origin, with no
// history, no issue tracker and no pull requests coming along. In that tree an
// issue number resolves to nothing, an abbreviated commit hash resolves to
// nothing, and a sentence whose argument was carried by one of them has quietly
// lost that argument. That
// is worse than a broken hyperlink, because nothing looks broken: the prose
// still reads as if the reasoning were one click away.
//
// # The rule this asserts
//
// In the swept part of the tree, a document may not lean on an issue number or a
// commit hash. The remedy is never deletion on its own — deleting the token
// drops whatever it was carrying — it is to move the meaning inline: name the
// mechanism, restate the derivation, or cite a section of a document that is in
// the tree.
//
// # Why a swept list and not the whole tree
//
// Because the whole tree is not swept yet, and a guard that is red on the day it
// lands is a guard somebody switches off. `swept` is a **ratchet**: paths go in
// as they are finished and never come out, so nothing that has been made
// self-contained can quietly regress. It is not an exemption table — the entries
// are the covered set, not the excused one, and the direction of drift is
// therefore toward more coverage rather than less.
//
// `TestTheUnsweptRemainderIsRecorded` is what stops the ratchet from stalling in
// silence: while any tracked file outside `swept` still carries a reference of
// this shape, the deferral record naming what is left has to exist.
//
// **The sweep has now reached the whole tree.** `swept` covers every tracked
// path except the three `frozen` parameter files, the deferral record has been
// deleted, and the pair of tests is no longer a ratchet over a partial tree: the
// first is effectively unconditional, and the second is what catches a NEW
// region — a directory none of the prefixes below reaches — arriving with
// references in it and no record saying so.
//
// # What is deliberately not swept, and never will be
//
// `spec/params.json` and its two siblings. The `notes` field is inside the bytes
// the announced parameter hash covers, so it is frozen at genesis and cannot be
// rewritten at migration time — an edit there is a network respin, not a
// documentation pass. The choice was between rewriting those notes into
// self-contained derivations before the freeze and accepting bare issue numbers
// in them permanently, and the second is taken: the freeze has happened, the notes
// already state their derivations in full beside the token, and a bare number
// leaks no identity. They are opaque historical markers, and `frozen` below says
// so in the one place that could otherwise be read as an oversight.
package wiring_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// swept is the part of the tree that has been made self-contained, and the only
// part this guard asserts over. An entry ending in `/` is a directory prefix;
// any other entry is one exact repository-relative path.
//
// Growing this list was the unit of work while the sweep ran, and it is
// finished: between these entries and `frozen` below, every tracked path in the
// tree today is accounted for, and the three files in `frozen` are the whole of
// what this guard does not assert over. Shrinking the list is a regression, and there
// is no reason to do it that is not "the sweep was undone".
//
// spec/ is listed file by file rather than as the prefix `spec/`, and the
// reason is `frozen` below: the three parameter files live under that prefix
// and are declared unreachable, so a prefix entry would put them in both lists
// and the scan below would refuse the pair. Everything else under spec/ is
// swept, and a new file added there has to be added here too — the alternative
// was to weaken the both-lists check, which is the one thing keeping `frozen`
// from becoming an exemption table.
//
// `sim/` is one prefix rather than a file list. It was a file list for as long
// as four files of that tree each held a token inside a *string something
// compares* — an operand rather than a citation — because retiring one of those
// is a change to an assertion and not to prose. All four are discharged: the
// liveness harness reports "after start number 2" rather than a hash sigil, the
// `sim/refold` doc test requires the mechanism the package comment states
// rather than the three tokens it used to cite, and the forge-URL guard's
// arming probe carries prose in its link text. Both halves of each moved in one
// change, so every one of those tests still asserts what it asserted before.
//
// The build and packaging surface is in, and `.github/` is in with it: the
// republication copies FILES, so a workflow travels to the new origin exactly
// as a source file does and a comment there resolves to nothing for the same
// reader. That was the open question about this region and it is answered here
// rather than left to be answered by whoever sweeps next.
//
// `Makefile` went last, for the reason the four `sim/` files did: what was left
// in it was not comment prose. Five tokens sat inside `echo` lines in recipes —
// text a target PRINTS to an operator when it refuses — so editing one edits
// what the target does rather than what a reader of the file is told. Each of
// the five sat beside a sentence in the same message that already gave the whole
// argument, so what went was a citation and not a reason, and nothing in those
// recipes moved but the text inside the five `echo` arguments.
var swept = []string{
	"docs/",
	"core/",
	"node/",
	"spec/README.md",
	"spec/chain-ids.json",
	"spec/checkpoints.json",
	"spec/checkpoints.go",
	"spec/chainids.go",
	"spec/spec.go",
	"spec/vector.go",
	"spec/cert_list_capacity_note_test.go",
	"spec/chainid_allocation_test.go",
	"spec/chainid_runtime_test.go",
	"spec/chainids_internal_test.go",
	"spec/difficulty_mutation_test.go",
	"spec/duplicate_key_test.go",
	"spec/invalid_rules_test.go",
	"spec/testnet_deviation_test.go",
	"spec/vector_refs_test.go",
	"spec/vector_test.go",
	"spec/gen/",
	"spec/vectors/",
	"README.md",
	"CONTRIBUTING.md",
	"SECURITY.md",
	"attestations/",
	"cmd/",
	"wallet/",
	"desktop/",
	"update/",

	".github/",
	".gitattributes",
	".gitignore",
	"build/",
	"go.mod",
	"go.sum",
	"LICENSE",
	"Makefile",
	"packaging/",

	"sim/",
}

// frozen is the set this guard will never reach, with the reason. It is short by
// construction: the only thing that qualifies is a file whose bytes are covered
// by a hash that shipped, because rewriting one of those is a consensus event
// rather than an edit.
var frozen = map[string]string{
	"spec/params.json":         "notes are inside the announced params hash; frozen at genesis",
	"spec/params.testnet.json": "notes are inside the announced params hash; frozen at genesis",
	"spec/params.devnet.json":  "notes are inside the announced params hash; frozen at genesis",
}

// issueRef matches the shape a tracker reference takes in this tree.
//
// One to four digits, because that is the range this project's tracker reached
// and a longer run is a quantity rather than a reference: `#123456` is not
// matched, and neither is a six-digit colour. The trailing `\b` is what stops a
// four-digit quantity from being read as a reference to its first digit.
var issueRef = regexp.MustCompile(`#[0-9]{1,4}\b`)

// commitRef matches an abbreviated commit hash written the way this tree writes
// one: alone inside backticks, all hexadecimal, seven characters or more.
//
// A hex *constant* in this tree carries its `0x`, and `x` is not in the class,
// so `0xdf140a7a` does not match. The requirement that the backticks hold
// nothing else is what keeps this from firing on prose.
var commitRef = regexp.MustCompile("`[0-9a-f]{7,40}`")

// linkTarget is a markdown link target, stripped before the scan.
//
// A link whose target carries a section fragment resolves for a reader holding
// only these files, so it is not a dangling reference — but a numbered fragment
// has exactly `issueRef`'s shape. Stripping the target is narrower than weakening
// the pattern.
var linkTarget = regexp.MustCompile(`\]\([^)]*\)`)

// notOurs is the one subtree the sweep steps over, and it is not an excuse in
// the sense `frozen` is.
//
// core/pow/randomx/upstream/ is a byte-identical copy of a tevador/RandomX tag.
// vendor.sh's own header says DO NOT PATCH IT, PINNED and pinned.go carry a
// SHA-256 over its bytes, and TestVendoredTreeMatchesPinned fails the build if
// one of them moves — so a finding here could not be acted on without breaking
// the property that makes auditing the work function a `diff` against upstream
// rather than a review of somebody's copy.
//
// What it actually contains is not a tracker reference at all. RandomX v2.0.1
// added RISC-V assembly whose comments cite upstream's own specification by URL
// fragment — a link to `doc/specs.md` ending in a hash sign, a section number
// and a slug — and a numbered fragment has exactly issueRef's shape. It
// resolves for any reader, which is the opposite of dangling; `linkTarget` does
// not strip it only because this is assembly rather than markdown. (The tokens
// are described rather than quoted here, because quoting them would make this
// comment fail the guard it is explaining.)
//
// **The exclusion is by subtree and not by pattern**, deliberately. Teaching
// issueRef to ignore a numbered fragment after `specs.md` would weaken the
// guard everywhere
// to accommodate one directory, and this guard's whole value is that it is
// blunt. Nothing outside upstream/ is excluded, and the vendored tree is
// covered instead by the tree hash, which is a stronger check than a text scan.
const vendoredUpstream = "core/pow/randomx/upstream/"

// notOurs reports whether a path is somebody else's bytes, held here verbatim.
//
// It is a THIRD category beside `swept` and `frozen`, and the distinction from
// each is what justifies it. `swept` is "this guard asserts over it"; `frozen`
// is "this guard would assert over it but the bytes shipped"; this is "these
// are not our words, and the sentence the guard enforces — write what you mean
// inline, because the reader has only these files — is not addressed to their
// author."
//
// **It is excluded from BOTH guards, not moved from one to the other.** Merely
// dropping it out of `swept` would push it into TestTheUnsweptRemainderIsRecorded's
// remainder, which would then demand a deferral record saying the sweep is
// unfinished. It is not unfinished: there is no edit that would finish it,
// because editing upstream/ is forbidden by vendor.sh, pinned.go and
// TestVendoredTreeMatchesPinned. A record claiming otherwise would be false.
func notOurs(rel string) bool { return strings.HasPrefix(rel, vendoredUpstream) }

// covered reports whether a repository-relative path is in the swept set.
func covered(rel string) bool {
	for _, entry := range swept {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(rel, entry) {
				return true
			}
			continue
		}
		if rel == entry {
			return true
		}
	}
	return false
}

// historyRefs returns every dangling-history reference in one file's text,
// already formatted as a finding.
func historyRefs(rel string, body []byte) []string {
	var out []string
	for lineNo, line := range strings.Split(string(body), "\n") {
		stripped := linkTarget.ReplaceAllString(line, "]()")
		for _, pattern := range []*regexp.Regexp{issueRef, commitRef} {
			for _, m := range pattern.FindAllString(stripped, -1) {
				out = append(out, rel+":"+strconv.Itoa(lineNo+1)+"  "+m)
			}
		}
	}
	return out
}

// TestNoDanglingHistoryReferenceIsPublished is the guard.
//
// Subject is the git index, for the reason `anonymity_test.go` gives: the index
// is what publication copies, and it is not the working directory.
func TestNoDanglingHistoryReferenceIsPublished(t *testing.T) {
	root := filepath.Join("..", "..")

	var findings []string
	sweptFiles := 0
	for _, f := range trackedFiles(t, root) {
		if !covered(f.path) || notOurs(f.path) || f.symlink() || f.gitlink() {
			continue
		}
		if _, ok := frozen[f.path]; ok {
			t.Fatalf("%s is in both `swept` and `frozen`, so this guard both "+
				"asserts and excuses it. One of the two lists is wrong.", f.path)
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.path)))
		if err != nil {
			t.Fatalf("read tracked file %s: %s", f.path, reason(err))
		}
		if !isText(body) {
			continue // TestNothingPublishedIsOpaqueToTheTextScan owns these.
		}
		sweptFiles++
		findings = append(findings, historyRefs(f.path, body)...)
	}

	if sweptFiles == 0 {
		t.Fatal("the swept set reached no file: the guard would pass by asserting " +
			"nothing, and its silence would mean nothing")
	}
	if len(findings) > 0 {
		t.Fatalf("%d reference(s) into a history this tree is published without:\n  %s\n\n"+
			"The repository is republished as files under a fresh origin: no issue\n"+
			"tracker and no commit history come with it, so each of these resolves to\n"+
			"nothing for the reader who has only this tree.\n"+
			"Do not just delete the token — that drops the argument it was carrying.\n"+
			"Move the meaning inline: name the mechanism, restate the derivation, or\n"+
			"cite a section of a document that is in the tree.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// deferralRecord is the path a record of an unswept remainder has to be written
// to. It does not exist, and that is the finished state: the sweep reached the
// whole tree, the remainder went to zero, and the second branch of the test
// below is what deleted the file that used to be here.
const deferralRecord = "docs/deferred/self-containment-sweep.md"

// TestTheVendoredExclusionReachesNothingOfOurs pins how far `notOurs` reaches.
//
// **It exists because a mutation survived.** Widening `vendoredUpstream` from
// `core/pow/randomx/upstream/` to `core/pow/randomx/` — one path segment, the
// kind of edit that looks like tidying — silently drops the binding, the
// engine, the pinning test and the cross-vector file out of both guards, and
// every test in this package still passes. An exclusion nothing constrains is
// an exclusion that grows.
//
// The property asserted is the one that matters and it is checkable without
// naming a file list: everything `notOurs` excludes must be a file vendor.sh
// wrote, and the tree hash in pinned.go is what says which those are. So the
// prefix must name a directory that (a) exists, (b) contains no Go source —
// every Go file under core/pow/randomx belongs to this project, and upstream
// ships none — and (c) is strictly inside the package directory rather than
// equal to it.
func TestTheVendoredExclusionReachesNothingOfOurs(t *testing.T) {
	root := filepath.Join("..", "..")

	const pkg = "core/pow/randomx/"
	if vendoredUpstream == pkg || !strings.HasPrefix(vendoredUpstream, pkg) {
		t.Fatalf("the vendored-upstream prefix is %q; it must be strictly inside "+
			"%q. Widening it to the package directory would drop the binding, the "+
			"engine and the cross-vector file out of both guards at once.",
			vendoredUpstream, pkg)
	}

	dir := filepath.Join(root, filepath.FromSlash(vendoredUpstream))
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("%q is not a directory in this tree; an exclusion that names "+
			"nothing excludes nothing and hides that it does", vendoredUpstream)
	}

	// No Go source may be excluded. Upstream ships C, C++ and assembly and no
	// Go at all, so a .go file under this prefix means the prefix has moved.
	var goFiles, total int
	for _, f := range trackedFiles(t, root) {
		if !notOurs(f.path) {
			continue
		}
		total++
		if strings.HasSuffix(f.path, ".go") {
			goFiles++
			t.Errorf("%s is excluded from the history guards, but it is Go source "+
				"and therefore ours", f.path)
		}
	}
	if total == 0 {
		t.Fatal("the exclusion reached no tracked file, so it is either stale or " +
			"pointed at nothing; either way it should be deleted rather than kept")
	}
	if goFiles > 0 {
		t.Fatalf("%d Go file(s) of %d excluded: the prefix has grown past the "+
			"vendored tree", goFiles, total)
	}
}

// TestTheUnsweptRemainderIsRecorded keeps the ratchet from stalling quietly.
//
// A partial sweep is defensible; a partial sweep nobody can see is not. While
// anything outside `swept` still carries a reference of this shape, the record
// that says so has to be in the tree — and when the sweep finished, that record
// was deleted and this test is what said so rather than passing on vacuously.
//
// It is not vacuous now that the sweep is done, and this is the case it is left
// standing for: a NEW region of the tree — a directory none of `swept`'s
// prefixes reaches — arriving with references of this shape in it. The first
// guard cannot see such a region at all, because it asserts only over `swept`;
// this one does, and it demands the same choice the sweep faced. Either make
// the new region self-contained and add it to `swept`, or write the record that
// says what is left in it and why.
func TestTheUnsweptRemainderIsRecorded(t *testing.T) {
	root := filepath.Join("..", "..")

	remaining := 0
	for _, f := range trackedFiles(t, root) {
		if covered(f.path) || notOurs(f.path) || f.symlink() || f.gitlink() {
			continue
		}
		if _, ok := frozen[f.path]; ok {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.path)))
		if err != nil {
			t.Fatalf("read tracked file %s: %s", f.path, reason(err))
		}
		if !isText(body) {
			continue
		}
		remaining += len(historyRefs(f.path, body))
	}

	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(deferralRecord)))
	switch {
	case remaining > 0 && err != nil:
		t.Fatalf("%d reference(s) of this shape remain outside the swept set and "+
			"%s does not exist.\n\n"+
			"An unfinished sweep is a decision and has to be readable as one. Either "+
			"widen `swept` until the remainder is zero, or write the record that says "+
			"what is left and why.", remaining, deferralRecord)
	case remaining == 0 && err == nil:
		t.Fatalf("nothing outside the swept set carries a reference of this shape, "+
			"but %s is still in the tree.\n\n"+
			"The sweep is finished: fold the remaining entries into `swept`, delete "+
			"that record, and this guard becomes unconditional.", deferralRecord)
	}
}

// TestTheHistoryReferenceGuardActuallyFires is the arming charge.
//
// A guard nobody has seen fail is a guard nobody has seen. It pins both
// directions: the shapes that must be caught, and the shapes that must not be,
// because a guard that fires on a section heading or on a colour is a guard that
// gets suppressed within a week.
//
// The probes are assembled from pieces rather than written out, for the reason
// `github_url_test.go` gives about its own: `swept` is meant to grow until it
// covers this file too, and a probe spelled out in full would then make the
// guard fail on its own source. The alternative is a self-exemption, and an
// exempted path is the one place the thing being guarded against can be quoted.
func TestTheHistoryReferenceGuardActuallyFires(t *testing.T) {
	const hash = "chosen because the change in `" + "5ed12c7" + "` moved it"
	for _, probe := range []string{
		"the reason is #" + "392, which lowered the target",
		"see #" + "70 for the push",
		"closed in #" + "1234 and re-opened later",
		hash,
	} {
		if got := historyRefs("x.md", []byte(probe)); len(got) == 0 {
			t.Errorf("no finding on %q: this is the shape the guard exists for", probe)
		}
	}

	// Shapes that must stay invisible. Each one is in the tree today, and each
	// one would be a false positive that costs the guard its life.
	for _, clean := range []string{
		"## 14. Launch: Three Eras, Zero Premine",
		"### 12.3 The cost of saying no",
		"see [the rotation rule](sync.md#4-rotation-not-ranking) for the guarantee",
		"a block of 4000 floor certificates is 2,248,268 bytes",
		"the params hash is `0xdf140a7a` and not the genesis id",
		"`#!/bin/sh` is not a reference",
		"the colour token #123456 is six digits and is not one either",
	} {
		if got := historyRefs("x.md", []byte(clean)); len(got) != 0 {
			t.Errorf("%q reported %v; a guard that fires on ordinary prose is one "+
				"somebody switches off", clean, got)
		}
	}

	// The swept set has to mean something. A prefix that matches nothing, or an
	// entry that also sits in `frozen`, makes the coverage claim a fiction.
	if len(swept) == 0 {
		t.Fatal("the swept set is empty: this guard asserts nothing")
	}
	for _, entry := range swept {
		if _, ok := frozen[entry]; ok {
			t.Errorf("%q is both swept and frozen", entry)
		}
	}
	// The negative probe is `spec/params.json` rather than some file the sweep
	// has merely not reached yet, and that is deliberate: every such file
	// eventually becomes swept and silently turns this probe vacuous, which is
	// how the probe reached a path already covered once before. A frozen file
	// can never enter `swept` — the loop just above refuses any path in both
	// lists — so this one answers `false` for as long as the guard is honest.
	// It is also why `spec/` is listed file by file: a `spec/` prefix would
	// cover the parameter files, and this line would go red.
	if !covered("docs/ARCHITECTURE.md") || covered("spec/params.json") {
		t.Error("`covered` no longer answers for the two cases the ratchet turns " +
			"on: a swept path, and a path outside the swept set")
	}
}
