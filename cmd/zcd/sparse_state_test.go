package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file pins one thing: the CLI does not hold a consensus state.
//
// It used to. nodeState carried a *state.State copied field-by-field out of a
// session.View, and that state is the sparse one -- it holds only the cells
// the three fetched addresses were asked about. The two sets that make it
// answerable live on the view, unexported, behind CoversCertificate, and they
// did not come across. A sparse state without its coverage record answers
// every question benignly: an unfetched balance reads zero, an unfetched
// address reads not-spent. That is the fail-open direction the sparse-reader
// class has already been fixed open four times for: the absent-versus-zero
// balance conflation, the absent-versus-unspent conflation, and both axes of
// the payee/refund destination reads.
//
// The field was written once and read nowhere, so it was never a live defect
// -- it was the loaded gun the fifth instance would have picked up. Deleting
// it removed cmd/zcd's only reference to zycord/core/state, which is what
// makes the property below checkable at the import rather than at the field: a
// field can be reintroduced under any name and any shape, but it cannot be
// reintroduced without the import.
//
// See docs/decisions/sparse-state-readers.md, and
// core/state/sparse_population_test.go, which counts where a state.State is
// created and explicitly does not follow one that is passed on -- this package
// being the propagation that motivated saying so.

// statePkgPath is the import path this package must not reach.
const statePkgPath = "zycord/core/state"

// TestPackageMainDoesNotImportCoreState is the tripwire.
//
// Scoped to this package's own non-test files on purpose. The tree-wide
// question -- who else holds a sparse state -- is left to
// core/state/sparse_population_test.go, and answering it in general needs a
// whole-module type-check rather than a one-directory import scan. This makes
// no claim about anywhere else.
func TestPackageMainDoesNotImportCoreState(t *testing.T) {
	files := nonTestGoFilesHere(t)
	if len(files) == 0 {
		t.Fatal("no non-test .go files found beside this test, so this test " +
			"asserts nothing; the scan is broken, not the package")
	}

	fset := token.NewFileSet()
	offenders := []string(nil)
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Base(path), err)
		}
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquoting import %s: %v",
					filepath.Base(path), spec.Path.Value, err)
			}
			if p == statePkgPath {
				offenders = append(offenders,
					filepath.Base(path)+":"+
						strconv.Itoa(fset.Position(spec.Pos()).Line))
			}
		}
	}

	if len(offenders) > 0 {
		t.Errorf("cmd/zcd imports %s at %s.\n"+
			"\n"+
			"The only state.State this CLI can obtain is the sparse one inside\n"+
			"a session.View, and a bare *state.State cannot answer \"was this\n"+
			"cell fetched?\" -- an unfetched balance reads zero and an unfetched\n"+
			"address reads not-spent. Both are the fail-open direction: the\n"+
			"wallet approves a spend it could not actually check.\n"+
			"Carry the *session.View instead, so CoversCertificate travels with\n"+
			"the cells, and read the state through it.\n"+
			"If a command genuinely needs the package for something that is not\n"+
			"a sparse view -- there is no such use today -- this test is the\n"+
			"place to argue for it, not to delete.",
			statePkgPath, strings.Join(offenders, ", "))
	}
}

// nonTestGoFilesHere lists this package's non-test .go files, as absolute
// paths. It reads the directory rather than taking a list, so a new file in
// cmd/zcd is covered the moment it exists.
func nonTestGoFilesHere(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	out := []string(nil)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		abs, err := filepath.Abs(name)
		if err != nil {
			t.Fatalf("resolving %s: %v", name, err)
		}
		out = append(out, abs)
	}
	sort.Strings(out)
	return out
}
