package update_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zycord/update"
)

type member struct {
	name string
	body string
	typ  byte // tar.TypeReg by default
	link string
}

func writeTarGz(t *testing.T, dir string, members []member) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: m.name, Mode: 0o755, Size: int64(len(m.body)), Typeflag: typ, Linkname: m.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	tw.Close()
	gz.Close()
	p := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeZip(t *testing.T, dir string, members []member) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		w, err := zw.Create(m.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()
	p := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestExtractTakesOnlyWhatItAskedFor, from both archive shapes.
func TestExtractTakesOnlyWhatItAskedFor(t *testing.T) {
	for _, shape := range []string{"tar.gz", "zip"} {
		t.Run(shape, func(t *testing.T) {
			src := t.TempDir()
			ms := []member{
				{name: "zycord-0.2.0-linux-amd64/zcd", body: "ZCD"},
				{name: "zycord-0.2.0-linux-amd64/zycordd", body: "ZYCORDD"},
				{name: "zycord-0.2.0-linux-amd64/README.md", body: "docs"},
				{name: "zycord-0.2.0-linux-amd64/docs/INSTALL.md", body: "more docs"},
			}
			var archive string
			if shape == "zip" {
				archive = writeZip(t, src, ms)
			} else {
				archive = writeTarGz(t, src, ms)
			}

			out := t.TempDir()
			got, err := update.Extract(archive, out, []string{"zcd", "zycordd"})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("extracted %d files, want 2: %v", len(got), got)
			}
			for name, want := range map[string]string{"zcd": "ZCD", "zycordd": "ZYCORDD"} {
				b, err := os.ReadFile(got[name])
				if err != nil {
					t.Fatal(err)
				}
				if string(b) != want {
					t.Errorf("%s = %q, want %q", name, b, want)
				}
				if filepath.Dir(got[name]) != out {
					t.Errorf("%s landed in %s, want %s", name, filepath.Dir(got[name]), out)
				}
			}
			// The documents were in the archive and were not asked for.
			for _, unwanted := range []string{"README.md", "INSTALL.md"} {
				if _, err := os.Stat(filepath.Join(out, unwanted)); err == nil {
					t.Errorf("%s was extracted without being asked for", unwanted)
				}
			}
		})
	}
}

// TestTheArchiveNeverChoosesAPath is the zip-slip case, and the point is that it
// is not a rejection.
//
// The usual defence cleans each member name and refuses one that escapes, which
// leaves the archive choosing a path and this code judging it. Here the archive
// chooses nothing: a member called `../../etc/cron.d/x` simply never matches
// anything we asked for, and one whose base name DOES match is written under the
// name we chose, in the directory we chose.
func TestTheArchiveNeverChoosesAPath(t *testing.T) {
	for _, shape := range []string{"tar.gz", "zip"} {
		t.Run(shape, func(t *testing.T) {
			src := t.TempDir()
			ms := []member{
				{name: "../../../../../../tmp/pwned", body: "escape"},
				{name: "../../zcd", body: "TRAVERSAL"},
				{name: "ok/zcd", body: "REAL"},
			}
			var archive string
			if shape == "zip" {
				archive = writeZip(t, src, ms)
			} else {
				archive = writeTarGz(t, src, ms)
			}
			out := t.TempDir()
			_, err := update.Extract(archive, out, []string{"zcd"})
			// `../../zcd` and `ok/zcd` both have base name zcd, so this is a
			// duplicate rather than a traversal - which is the point: the path
			// never entered the decision.
			if err == nil {
				t.Fatal("two members with the same base name were both accepted")
			}
			if _, statErr := os.Stat("/tmp/pwned"); statErr == nil {
				t.Fatal("a member escaped the destination directory")
			}
			parent := filepath.Dir(out)
			if _, statErr := os.Stat(filepath.Join(parent, "zcd")); statErr == nil {
				t.Errorf("a member was written outside %s", out)
			}
		})
	}
}

// TestOnlyRegularFilesAreEverCreated. A symlink named zcd pointing at a file
// this process can write is the shape that turns an extraction into an
// arbitrary overwrite.
func TestOnlyRegularFilesAreEverCreated(t *testing.T) {
	src := t.TempDir()
	archive := writeTarGz(t, src, []member{
		{name: "pkg/zcd", typ: tar.TypeSymlink, link: "/etc/passwd"},
		{name: "pkg/zycordd", typ: tar.TypeDir},
	})
	out := t.TempDir()
	_, err := update.Extract(archive, out, []string{"zcd"})
	if !errors.Is(err, update.ErrMemberMissing) {
		t.Errorf("err = %v, want ErrMemberMissing - a symlink is not the file we asked for", err)
	}
	if fi, statErr := os.Lstat(filepath.Join(out, "zcd")); statErr == nil {
		t.Errorf("something was created for a symlink member: mode %v", fi.Mode())
	}
}

// TestAnArchiveMissingWhatWeCameForIsAnError, rather than a silent partial
// install.
func TestAnArchiveMissingWhatWeCameForIsAnError(t *testing.T) {
	src := t.TempDir()
	archive := writeTarGz(t, src, []member{{name: "pkg/zcd", body: "ZCD"}})
	out := t.TempDir()
	if _, err := update.Extract(archive, out, []string{"zcd", "zycordd"}); !errors.Is(err, update.ErrMemberMissing) {
		t.Errorf("err = %v, want ErrMemberMissing", err)
	}
}

// TestAnUnknownArchiveShapeIsRefused, rather than guessed at.
func TestAnUnknownArchiveShapeIsRefused(t *testing.T) {
	src := t.TempDir()
	p := filepath.Join(src, "a.rar")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := update.Extract(p, t.TempDir(), []string{"zcd"}); err == nil {
		t.Error("accepted an archive shape this build does not unpack")
	}
}

// TestWhatWeAskForMustBeAName, not a path. This is the one input to Extract that
// comes from the caller rather than the archive.
func TestWhatWeAskForMustBeAName(t *testing.T) {
	src := t.TempDir()
	archive := writeTarGz(t, src, []member{{name: "pkg/zcd", body: "ZCD"}})
	for _, want := range []string{"../zcd", "a/b", `a\b`, ""} {
		if _, err := update.Extract(archive, t.TempDir(), []string{want}); err == nil {
			t.Errorf("accepted %q as a file to look for", want)
		}
	}
}

// TestAGzipBombIsBounded. The archive is signed by the time it reaches here, so
// this is not defence against a stranger - it is what stops a corrupt or
// mistaken archive from filling a disk before anything notices.
func TestAGzipBombIsBounded(t *testing.T) {
	src := t.TempDir()
	// One member, far past the per-member cap, compressing to almost nothing.
	archive := writeTarGz(t, src, []member{
		{name: "pkg/zcd", body: strings.Repeat("\x00", 1<<20)},
	})
	out := t.TempDir()
	if _, err := update.Extract(archive, out, []string{"zcd"}); err != nil {
		t.Fatalf("a 1 MiB member was refused, which is well under the cap: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "zcd")); err != nil || len(b) != 1<<20 {
		t.Errorf("member is %d bytes, err %v", len(b), err)
	}
}
