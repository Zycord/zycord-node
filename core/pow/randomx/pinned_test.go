package randomx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestVendoredTreeMatchesPinned recomputes the hash of upstream/ and compares
// it with what vendor.sh recorded.
//
// It is the second half of a defence whose first half is pinned.go itself, and
// the failure it guards is one of the most confusing this repository could
// produce. The shims #include from upstream/, a SUBDIRECTORY, and Go's build
// cache hashes only files in the package directory. So a hand edit under
// upstream/ does not invalidate anything: `go test` reuses the object built
// from the previous contents, every test passes, and the engine appears
// correct while running code that is not there any more.
//
// That is not hypothetical. It is how this package was written: four separate
// mutations of the ARM64 code generator — including deleting the fix for a bug
// that splits the chain between ARM and x86 machines — all reported green,
// because none of them was ever compiled. The tests were fine. The build was
// lying, and no tool in the toolchain said so.
//
// Re-running vendor.sh rewrites pinned.go and fixes the cache. This test is
// what notices the case vendor.sh cannot: somebody editing upstream/ by hand.
//
// It deliberately does NOT carry the `randomx` build tag. The whole point is
// that it runs in the ordinary `go test ./...`, with no C toolchain, so a
// modified vendor tree is caught by every contributor rather than only by the
// ones who build with cgo.
func TestVendoredTreeMatchesPinned(t *testing.T) {
	got, err := hashTree("upstream")
	if err != nil {
		t.Fatalf("hashing upstream/: %v", err)
	}
	if got != UpstreamTreeHash {
		t.Fatalf(`the vendored RandomX tree does not match PINNED.

  recomputed: %s
  pinned.go:  %s  (tag %s, commit %s)

Either upstream/ was edited by hand, or vendor.sh was run and pinned.go was not
committed with it. Both matter more than they look:

  - upstream/ is meant to be byte-identical to the tag, so that auditing the
    work function is a diff against tevador's tree rather than a review of
    somebody's copy. If a fix is needed, take it upstream or carry it in a
    shim.
  - Go's build cache does not see into upstream/, so a hand edit there does not
    rebuild anything. Whatever you changed is almost certainly NOT what your
    tests just ran.

Run: sh core/pow/randomx/vendor.sh`, got, UpstreamTreeHash, UpstreamTag, UpstreamCommit)
	}
}

// hashTree reproduces vendor.sh's tree hash in Go: sha256 of every file, the
// per-file lines sorted by path, hashed again. LICENSE is excluded there and
// here — it is copied from the repository root rather than from src/.
//
// Reimplemented rather than shelled out to, so that the check runs identically
// on a machine with no shell utilities, and so that the two implementations
// have to agree about what "the tree" means.
func hashTree(root string) (string, error) {
	// Keyed by path and sorted BY PATH, because that is what `find ... | sort
	// -z | xargs shasum` does. Sorting the output lines instead sorts by hash,
	// which is a different order and a different answer — and it is the first
	// way this function was written.
	byPath := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "LICENSE" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		byPath["./"+filepath.ToSlash(rel)] = sum[:]
		return nil
	})
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	outer := sha256.New()
	for _, p := range paths {
		fmt.Fprintf(outer, "%x  %s\n", byPath[p], p)
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}
