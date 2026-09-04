package randomx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

// TestTheJITCodeBufferIsSizedForTheLargerV2Program pins the one line in the
// vendored x86 code generator that stands between rx/2 and a heap overflow on
// every hash.
//
// rx/2 raised the program length from 256 instructions to 384. The JIT emits
// into a fixed buffer sized at compile time, and the instruction buffer,
// the loop bounds and that size are three separate expressions in three
// separate files. Upstream widened all of them — `Program::programBuffer` and
// `JitCompilerX86`'s `instructionOffsets` to `RANDOMX_PROGRAM_MAX_SIZE`, the
// loops to `getSize(flags)`, and `RandomXCodeSize` to `MAX_SIZE` as well. If
// any ONE of them had been left at the v1 constant while the others moved, the
// generator would write past the end of the buffer.
//
// The x86 generator keeps its own `std::vector<int32_t>` for instruction
// offsets rather than using CompilerState's fixed array, so on THIS build the
// whole of the protection is RandomXCodeSize. The array is pinned anyway
// because it is real code sized by MAX_SIZE and the RV64 compiler builds on
// it.
//
// **This is not a hypothetical, it is a measurement.** Compiling a
// 384-instruction program built entirely from the largest-emitting opcode
// reaches 13442 bytes; the buffer is 16384. Recomputing `RandomXCodeSize` from
// the v1 constant instead gives 12288, and the same program overflows it by
// 1154 bytes — into the superscalar hash region that sits immediately after.
// The sweep behind those numbers is exhaustive over all 256 opcodes rather
// than random, so it is a bound and not a sample.
//
// What is checked here is the SOURCE, not the behaviour, and deliberately so.
// A behavioural test would need the private C++ headers and would run only on
// amd64; this runs everywhere, without a C toolchain, and fails on exactly the
// edit that would reintroduce the defect — a `MAX_SIZE` quietly changed back
// to a version-specific constant.
func TestTheJITCodeBufferIsSizedForTheLargerV2Program(t *testing.T) {
	// The buffer must be sized by the MAXIMUM program length, never by a
	// version-specific one: the generator does not know which version it will
	// be asked for until setFlags, and the buffer is allocated in the
	// constructor, before that.
	for _, c := range []struct{ file, want string }{
		{"jit_compiler_x86.cpp", "MaxRandomXInstrCodeSize * RANDOMX_PROGRAM_MAX_SIZE"},
		{"program.hpp", "Instruction programBuffer[RANDOMX_PROGRAM_MAX_SIZE]"},
		{"jit_compiler.hpp", "int32_t instructionOffsets[RANDOMX_PROGRAM_MAX_SIZE]"},
		{"vm_interpreted.hpp", "InstructionByteCode bytecode[RANDOMX_PROGRAM_MAX_SIZE]"},
		// The arm64 generator patches a fixed template rather than emitting a
		// free-standing program, so its bound lives in the ASSEMBLY: the slot
		// the program body is written into is a .fill sized by MAX_SIZE. Its
		// emit32 is an unchecked store exactly as x86's is, and this is the
		// one instance of the invariant that no C++ reader would look for.
		{"jit_compiler_a64_static.S", "RANDOMX_PROGRAM_MAX_SIZE*12"},
	} {
		b, err := os.ReadFile(filepath.Join("upstream", c.file))
		if err != nil {
			t.Fatalf("reading vendored %s: %v", c.file, err)
		}
		if !strings.Contains(string(b), c.want) {
			t.Errorf("upstream/%s no longer contains %q.\n"+
				"Every buffer the program is written into, and the code buffer "+
				"the JIT emits into, must be sized by RANDOMX_PROGRAM_MAX_SIZE. "+
				"Sizing any of them by RANDOMX_PROGRAM_SIZE_V1 while rx/2 runs "+
				"384-instruction programs is a write past the end of the "+
				"allocation on every hash.", c.file, c.want)
		}
	}

	// And the two sizes must still bracket each other the way the delta
	// assumes. If upstream ever raised V2 above MAX, every bound above would
	// be too small while still mentioning MAX_SIZE.
	b, err := os.ReadFile(filepath.Join("upstream", "configuration.h"))
	if err != nil {
		t.Fatalf("reading vendored configuration.h: %v", err)
	}
	sizes := map[string]int{}
	for _, name := range []string{"RANDOMX_PROGRAM_SIZE_V1", "RANDOMX_PROGRAM_SIZE_V2", "RANDOMX_PROGRAM_MAX_SIZE"} {
		m := regexp.MustCompile(`(?m)^#define\s+` + name + `\s+(\d+)`).FindStringSubmatch(string(b))
		if m == nil {
			t.Fatalf("configuration.h no longer defines %s", name)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s is not a number: %v", name, err)
		}
		sizes[name] = n
	}
	if sizes["RANDOMX_PROGRAM_MAX_SIZE"] < sizes["RANDOMX_PROGRAM_SIZE_V2"] ||
		sizes["RANDOMX_PROGRAM_MAX_SIZE"] < sizes["RANDOMX_PROGRAM_SIZE_V1"] {
		t.Fatalf("RANDOMX_PROGRAM_MAX_SIZE=%d does not cover V1=%d/V2=%d; "+
			"every buffer sized by MAX_SIZE is now too small for the program "+
			"that will be written into it",
			sizes["RANDOMX_PROGRAM_MAX_SIZE"], sizes["RANDOMX_PROGRAM_SIZE_V1"], sizes["RANDOMX_PROGRAM_SIZE_V2"])
	}
}
