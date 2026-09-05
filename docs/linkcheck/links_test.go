// Package linkcheck asks one question of this repository's prose: does every
// relative markdown link in it point at something that exists?
//
// It exists because an argument about pointers was true of links as a class and
// false of this tree. A milestone record in `docs/adversarial/` discharges its
// obligation to a reader by carrying a **link** to the document that owns the
// mechanism today, rather than by carrying a dateline — and half the reason for
// choosing the link was that a link is an artefact a machine can check while a
// dateline is not. `*as of M3*` rots in silence, the absence of an `*Amended.*`
// block is undetectable by construction, but a relative link either resolves or
// it does not. Nothing in the tree checked that, so the property the
// choice rested on was being asserted rather than held.
//
// **What a green run here does not say**, stated up front rather than left to be
// discovered. A resolving link proves the target *exists*. It does not prove the
// target still supersedes the finding that cites it, and it does not force a
// newly written record to carry a link at all. Both remain review obligations;
// this is the one of the three levels that convention names that is a mechanism,
// worth having on exactly that basis.
//
// Scope, and why each edge is where it is:
//
//   - **`docs/` and the root documents, not one directory.** The convention's
//     whole point is that the link crosses directories — `I4.md` cites
//     `../spec/wire.md` and `../../CONTRIBUTING.md` — and a check scoped to
//     `docs/adversarial/` could not see either target move.
//   - **Files, not fragments.** `[sync.md §4](sync.md)` names a section in prose
//     and not in the anchor, which is this tree's house style; asserting that
//     a slugged section anchor exists would fail on every existing
//     citation. A `#fragment` is stripped and the path in front of it is what is
//     asserted.
//   - **Relative targets only.** `http:`, `mailto:` and any other scheme name
//     something outside the tree, and a check that reaches the network is a
//     check that fails when the network does. A site-absolute `/path` is not a
//     path in this repository either.
//
// CI does not run today, so this is reached by `make check-links` and is a line
// in the §8 release checklist of docs/RELEASE.md, beside the `[X]`-placeholder
// grep that is the model for it. It is an ordinary test as well, so `make test`
// keeps it honest between releases.
package linkcheck_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot is the repository root, relative to this package.
const repoRoot = "../.."

// checked is the part of the tree this check covers: the documentation
// directory and the documents at the root. Widening it is one entry here, and
// the reason it is a list rather than "every tracked .md" is that the other
// markdown in the tree (`packaging/`, `attestations/`, `desktop/`) is
// README-shaped material for a different audience — including it is a decision
// about those documents, not a side effect of this one.
var checked = []string{"docs/", ""}

// link is one relative markdown link, located.
type link struct {
	file   string // repository-relative, slash-separated
	line   int    // 1-based
	target string // as written, fragment and all
}

func (l link) String() string { return fmt.Sprintf("%s:%d: %s", l.file, l.line, l.target) }

// TestEveryRelativeMarkdownLinkResolves is the check itself.
func TestEveryRelativeMarkdownLinkResolves(t *testing.T) {
	files := documents(t, repoRoot)
	if len(files) == 0 {
		t.Fatal("no markdown documents found; the check would pass vacuously")
	}

	var links []link
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		found, openFence := scan(f, body)
		if openFence {
			// Everything after the unclosed fence was skipped, so a green verdict
			// for this document would be a statement about its first half.
			t.Errorf("%s ends inside an unclosed code fence, so the links after it "+
				"were never read", f)
		}
		links = append(links, found...)
	}
	// The sweep this check came out of measured 21 relative links in the two
	// documents it was written about.
	// A scanner that silently stopped matching would report zero broken links
	// out of zero and print `ok`, which is the way a check like this dies.
	if len(links) == 0 {
		t.Fatalf("no relative links found across %d documents; the scanner matched "+
			"nothing, which is not the same as a clean tree", len(files))
	}

	var broken []string
	for _, l := range links {
		if err := resolve(repoRoot, l); err != nil {
			broken = append(broken, l.String()+"  ("+err.Error()+")")
		}
	}
	if len(broken) > 0 {
		t.Fatalf("%d relative markdown link(s) do not resolve:\n  %s\n\n"+
			"A document that cites another by a link that no longer resolves has\n"+
			"the failure mode a link was chosen to avoid: it reads as current and\n"+
			"points nowhere. Fix the link, or the move that broke it.",
			len(broken), strings.Join(broken, "\n  "))
	}
	t.Logf("%d relative links resolved across %d documents", len(links), len(files))
}

// TestTheScannerSeesABrokenLink is what makes the test above evidence.
//
// The tree is green today and is meant to stay green, so nothing in a passing
// run distinguishes a working check from one that matches nothing, resolves
// nothing, or treats every target as fine. This plants each failure the check
// exists to catch, and each shape it must *not* fire on, in a tree built for the
// purpose.
func TestTheScannerSeesABrokenLink(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/sub/target.md", "the target\n")
	write("CONTRIBUTING.md", "a root document\n")
	write("packaging/README.md", "out of scope\n")
	// Line 8 below is a scheme with no `//`, which is the shape being covered.
	// It is deliberately not a `mailto:` one: sim/wiring's anonymity sweep reads
	// every tracked file and reports an e-mail address wherever it finds one,
	// exemption-free by design, so a fixture address here would fail that guard
	// rather than this one.
	write("docs/doc.md", strings.Join([]string{
		"[ok](sub/target.md)",                                    //  1: resolves
		"[frag](sub/target.md#a-section)",                        //  2: fragment stripped
		"[up](../CONTRIBUTING.md)",                               //  3: crosses out of docs/
		"[dir](sub)",                                             //  4: a directory resolves
		"[titled](sub/target.md \"A title\")",                    //  5: the title is not the path
		"[angle](<sub/target.md>)",                               //  6: angle-bracketed
		"[web](https://example.com/missing.md)",                  //  7: not ours to check
		"[ipfs](ipfs:QmExample)",                                 //  8: not a path
		"[here](#a-section)",                                     //  9: a bare fragment
		"[site](/docs/sub/target.md)",                            // 10: not a path in this tree
		"![img](sub/target.md)",                                  // 11: an image link is a link
		"```",                                                    // 12
		"[fenced](nowhere.md)",                                   // 13: an example, not a claim
		"~~~ the other marker does not close a ``` block",        // 14
		"[still fenced](nowhere.md)",                             // 15: still an example
		"```",                                                    // 16
		"[gone](sub/moved.md)",                                   // 17: BROKEN, plainly
		"[case](SUB/target.md)",                                  // 18: BROKEN on Linux
		"[deep](sub/../sub/target.md)",                           // 19: resolves once cleaned
		"text [not a link] (spaced.md) and on",                   // 20: `] (` is not one
		"[two](sub/target.md) on [one](../CONTRIBUTING.md) line", // 21: both are seen
	}, "\n")+"\n")

	want := []string{"CONTRIBUTING.md", "docs/doc.md", "docs/sub/target.md"}
	if got := walk(t, root); !equal(got, want) {
		t.Fatalf("covered documents = %v, want %v", got, want)
	}

	body, err := os.ReadFile(filepath.Join(root, "docs", "doc.md"))
	if err != nil {
		t.Fatal(err)
	}
	links, openFence := scan("docs/doc.md", body)
	if openFence {
		t.Fatal("the fixture's fences are balanced; the scanner thinks one is open")
	}

	// An unclosed fence makes the rest of a document invisible, so the scanner
	// has to say so rather than report the half it managed to read.
	if _, open := scan("x.md", []byte("prose\n```\n[a](b.md)\n")); !open {
		t.Error("an unclosed fence went unreported, so a truncated read would pass as clean")
	}

	// Every line the scanner is required to see, and no line it must not.
	wantLines := []int{1, 2, 3, 4, 5, 6, 11, 17, 18, 19, 21, 21}
	var gotLines []int
	for _, l := range links {
		gotLines = append(gotLines, l.line)
	}
	if !equalInts(gotLines, wantLines) {
		t.Errorf("scanned lines %v, want %v\nlinks: %v", gotLines, wantLines, links)
	}

	var broken []string
	for _, l := range links {
		if err := resolve(root, l); err != nil {
			broken = append(broken, fmt.Sprintf("%d:%s", l.line, l.target))
		}
	}
	wantBroken := []string{"17:sub/moved.md", "18:SUB/target.md"}
	if !equal(broken, wantBroken) {
		t.Errorf("broken = %v, want %v", broken, wantBroken)
	}
}

// documents is every markdown file the check covers, repository-relative and
// slash-separated, sorted.
//
// It shells out to git rather than walking the directory for the reason
// sim/wiring's anonymity sweep gives: the working directory and the published
// tree are not the same set. An untracked scratch document is not published and
// its links are nobody's problem; a tracked one is. It fails rather than skips
// when git cannot answer, because `make check-links` runs without -v and a skip
// there is indistinguishable from a pass.
func documents(t *testing.T, root string) []string {
	t.Helper()

	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--", "*.md").Output()
	if err != nil {
		t.Fatalf("git ls-files in %s: %v\n\n"+
			"This check's subject is the tree that gets published, and git is how "+
			"that tree is named.", root, err)
	}

	var files []string
	for _, raw := range bytes.Split(out, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		if covered(string(raw)) {
			files = append(files, string(raw))
		}
	}
	sort.Strings(files)
	return files
}

// walk enumerates the covered markdown files under a tree git does not know
// about, which is what the scanner's own fixture tree is.
func walk(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); covered(rel) {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(files)
	return files
}

// covered reports whether a repository-relative path is in scope: under one of
// the checked directories, or a document at the root.
func covered(file string) bool {
	for _, prefix := range checked {
		if prefix == "" {
			if !strings.Contains(file, "/") {
				return true
			}
			continue
		}
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	return false
}

// scan extracts the relative links from one document, and reports whether the
// document ended inside a code fence.
//
// Fenced blocks are skipped. A document that documents markdown quotes links
// that were never meant to resolve, and a check that fires on an example is the
// false positive CONTRIBUTING.md calls worse than silence.
func scan(file string, body []byte) (links []link, openFence bool) {
	// The marker that opened the block being skipped, or "". Only the marker
	// that opened a fence closes it: a `~~~` line inside a ``` block is content,
	// and treating it as a toggle would make the rest of the document invisible
	// — the failure this scanner has to be least willing to have.
	fence := ""
	for n, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case fence != "":
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			continue
		case strings.HasPrefix(trimmed, "```"):
			fence = "```"
			continue
		case strings.HasPrefix(trimmed, "~~~"):
			fence = "~~~"
			continue
		}
		for _, target := range targets(line) {
			if relative(target) {
				links = append(links, link{file: file, line: n + 1, target: target})
			}
		}
	}
	return links, fence != ""
}

// targets returns the `](...)` targets on one line, title stripped.
//
// Inline links rather than reference-style ones, and one line at a time: a link
// whose parentheses do not close on the line that opened them is not matched at
// all, which is the quiet direction to be wrong in. Failing to see a link costs
// this check one link; inventing one costs it its credibility.
func targets(line string) []string {
	var out []string
	for i := 0; i+1 < len(line); i++ {
		if line[i] != ']' || line[i+1] != '(' {
			continue
		}
		j := i + 2
		// [text](<a target with spaces in it>)
		if j < len(line) && line[j] == '<' {
			end := strings.IndexByte(line[j:], '>')
			if end < 0 {
				continue
			}
			out = append(out, line[j+1:j+end])
			i = j + end
			continue
		}
		// Balanced, because a target may legitimately contain parentheses.
		depth, k := 1, j
		for ; k < len(line); k++ {
			if line[k] == '(' {
				depth++
			} else if line[k] == ')' {
				if depth--; depth == 0 {
					break
				}
			}
		}
		if depth != 0 {
			continue
		}
		target := ""
		// [text](path "Title") — the title is not part of the path.
		if fields := strings.Fields(line[j:k]); len(fields) > 0 {
			target = fields[0]
		}
		out = append(out, target)
		i = k
	}
	return out
}

// relative reports whether a target names a path in this repository.
func relative(target string) bool {
	if target == "" || strings.HasPrefix(target, "#") {
		return false
	}
	// A site-absolute or protocol-relative target is not a path in this tree.
	if strings.HasPrefix(target, "/") {
		return false
	}
	// A URI scheme — http, https, mailto, and anything else that is not ours.
	for i := 0; i < len(target); i++ {
		c := target[i]
		switch {
		case c == ':':
			return false
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '+', c == '-', c == '.':
			continue
		}
		break
	}
	return true
}

// resolve reports why a link does not resolve, or nil.
func resolve(root string, l link) error {
	target := l.target
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	// The only percent-escape this tree uses. A general unescape would also have
	// to decide what a literal `%` in a filename means, and no such file exists.
	target = strings.ReplaceAll(target, "%20", " ")
	if target == "" {
		return nil
	}
	rel := path.Join(path.Dir(l.file), target)

	// Element by element, matching case exactly, rather than one os.Stat.
	//
	// os.Stat is case-insensitive on Windows and on a default macOS volume, so a
	// link written `docs/Adversarial/I4.md` is green on the machine that wrote it
	// and red on the Linux host that publishes the tree — which is the one
	// arrangement worse than not checking at all.
	cur := root // where to look, relative to this package
	dir := "."  // the same place, named the way the reader of a failure names it
	where := func() string {
		if dir == "." {
			return "the repository root"
		}
		return dir
	}
	for _, elem := range strings.Split(rel, "/") {
		switch elem {
		case "", ".":
			continue
		case "..":
			cur, dir = filepath.Join(cur, ".."), path.Join(dir, "..")
			continue
		}
		entries, err := os.ReadDir(cur)
		if err != nil {
			return fmt.Errorf("reading %s: %w", where(), err)
		}
		found := false
		for _, e := range entries {
			if e.Name() == elem {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no %q in %s", elem, where())
		}
		cur, dir = filepath.Join(cur, elem), path.Join(dir, elem)
	}
	return nil
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func equalInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
