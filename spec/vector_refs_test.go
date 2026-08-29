package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestProseNamesLiveVectors is a guard against a class of rot this corpus is
// unusually good at producing: vector filenames carry their list position, so
// inserting one renumbers every file above it, and every document that cited a
// vector by number now points at a different statement about the protocol.
//
// It is written because the rot was found rather than imagined. When the
// one-shot burn vectors inserted one file into the middle of the corpus,
// `spec/README.md` was already naming
// `041-mainnet-invalid-cert-count-over-ceiling` and the key-schedule range
// `041`-`046` from a numbering two insertions old, and
// `sim/elastic_ceiling_test.go` was pointing at `spec/vectors/022-028` for the
// citation vectors that had since moved to `031`-`038`. Nothing failed,
// because a stale number in prose fails nothing — which is exactly why it
// needs a check rather than a habit.
//
// Scope is deliberately narrow: it resolves references of the shape
// `NNN-some-name`, which is the only form that can silently point somewhere
// real and wrong. A bare number in prose is left alone, because a document may
// legitimately quote a count, a height or a parameter that looks like one.
func TestProseNamesLiveVectors(t *testing.T) {
	// Every markdown document in the tree, plus this package's own README and
	// the one Go file that cites the corpus by number. A hardcoded list would
	// have to be extended by whoever adds the next document that cites a
	// vector, which is precisely the person who will not know this check
	// exists.
	sources := []string{"README.md", "../README.md", "../CONTRIBUTING.md",
		"../sim/elastic_ceiling_test.go"}
	for _, dir := range []string{"../docs", "../docs/decisions", "../docs/adversarial", "../docs/spec"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".md") {
				sources = append(sources, filepath.Join(dir, e.Name()))
			}
		}
	}
	ref := regexp.MustCompile(`\b(\d{3})-([a-z0-9]+(?:-[a-z0-9]+)+)\b`)

	live := map[string]bool{}
	for _, dir := range []string{"vectors", filepath.Join("vectors", "difficulty")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				live[strings.TrimSuffix(e.Name(), ".json")] = true
			}
		}
	}
	if len(live) == 0 {
		t.Fatal("no vectors found; the check would pass vacuously")
	}

	var checked int
	for _, src := range sources {
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("reading %s: %v", src, err)
		}
		for _, m := range ref.FindAllStringSubmatch(string(body), -1) {
			name := m[1] + "-" + m[2]
			// Only names that look like a vector: a name nothing in the corpus
			// has ever carried is prose about something else.
			if !live[name] && !anySuffix(live, m[2]) {
				continue
			}
			checked++
			if !live[name] {
				t.Errorf("%s cites vector %q, which does not exist; the corpus renumbered "+
					"and the prose did not", src, name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no document cited a vector by name; the check proved nothing")
	}
	t.Logf("%d vector references resolved across %d files", checked, len(sources))
}

// anySuffix reports whether some live vector carries this name under a
// different number — which is precisely the stale-reference case, and the one
// worth reporting rather than skipping.
func anySuffix(live map[string]bool, name string) bool {
	for k := range live {
		if i := strings.IndexByte(k, '-'); i >= 0 && k[i+1:] == name {
			return true
		}
	}
	return false
}
