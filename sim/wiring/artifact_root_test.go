package wiring_test

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// upload-artifact roots an artefact at the common ancestor of its paths, and
// that is a property of the LIST rather than of any line in it.
//
// This test exists because of a release that failed after every build had
// succeeded. The RandomX artefact listed three paths, all under dist/randomx/,
// so its files landed at the artefact root — and `randomx-smoke-windows`, the
// job that downloads that artefact and starts the Windows binary, looks in the
// root without recursing.
//
// A fourth path was added for the Debian package: dist/*.deb. One level up. The
// common ancestor moved from dist/randomx/ to dist/, every archive inside the
// artefact moved down a directory, and the smoke job threw "no windows randomx
// archive in the artefact" — about an archive that was right there, one level
// below where it looked.
//
// Nothing local was wrong. The added line is correct, the consuming job is
// correct, and the breakage lives in the relationship between them. That is the
// shape this package exists for, so the rule is a test rather than the comment
// it started as: **every path in one upload-artifact block must share a
// directory.**
//
// It is stricter than upload-artifact requires and deliberately so. Two paths
// with different parents are legal and merely change the layout; what they
// cannot do is change it *quietly*, which is the only failure mode that matters
// here.
func TestAnArtefactsPathsShareOneDirectory(t *testing.T) {
	// Every workflow, so a multi-path upload added to a new one is covered the
	// day it lands rather than the day somebody remembers this file.
	entries, err := os.ReadDir("../../.github/workflows")
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		wf := filepath.Join("../../.github/workflows", e.Name())
		b, err := os.ReadFile(wf)
		if err != nil {
			t.Fatalf("%s: %v", wf, err)
		}
		blocks := uploadPathBlocks(string(b))
		total += len(blocks)
		for _, blk := range blocks {
			dirs := map[string][]string{}
			for _, p := range blk.paths {
				dirs[path.Dir(p)] = append(dirs[path.Dir(p)], p)
			}
			if len(dirs) > 1 {
				t.Errorf("%s: the upload near line %d lists paths from %d different directories, "+
					"so the artefact root sits above all of them and every file inside moves:\n  %v\n"+
					"Give one of them its own artefact instead. A job that downloads this and looks "+
					"in the root will stop finding what it came for, and will say the file is absent "+
					"rather than moved.", wf, blk.line, len(dirs), dirs)
			}
		}
	}
	// The arming check, over the whole directory rather than per file: a
	// workflow may have no multi-path upload at all, and requiring one from each
	// is how the first version of this test failed on a workflow while the
	// parser was working perfectly. There is one workflow left and it carries
	// four such uploads, so the floor still has room under it.
	if total < 3 {
		t.Fatalf("found %d multi-path uploads across every workflow; the parser has probably "+
			"stopped matching, which would make this test pass by seeing nothing", total)
	}
}

type uploadBlock struct {
	line  int
	paths []string
}

var pathLine = regexp.MustCompile(`^\s+([A-Za-z0-9_./*${}-]+)\s*$`)

// uploadPathBlocks finds every `path: |` list and returns the paths in each.
//
// It does not try to prove the block belongs to an upload-artifact step, and
// does not need to: in these workflows `path: |` appears nowhere else --
// download-artifact writes `path: dl`, a scalar. Matching on the block shape
// rather than on the step above it is one less thing to get wrong, and a false
// positive here would be a list of paths that genuinely should share a
// directory anyway.
func uploadPathBlocks(src string) []uploadBlock {
	lines := strings.Split(src, "\n")
	var out []uploadBlock
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "path: |" {
			continue
		}
		blk := uploadBlock{line: i + 1}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		for _, nxt := range lines[i+1:] {
			if strings.TrimSpace(nxt) == "" {
				break
			}
			if ni := len(nxt) - len(strings.TrimLeft(nxt, " ")); ni <= indent {
				break
			}
			if strings.HasPrefix(strings.TrimSpace(nxt), "#") {
				continue
			}
			m := pathLine.FindStringSubmatch(nxt)
			if m == nil {
				break
			}
			blk.paths = append(blk.paths, m[1])
		}
		if len(blk.paths) > 1 {
			out = append(out, blk)
		}
	}
	return out
}
