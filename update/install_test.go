package update_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"zycord/update"
)

func writeExe(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func targetFor(path string) update.Target {
	return update.Target{
		Path: path, Resolved: path,
		Dir: filepath.Dir(path), Name: filepath.Base(path),
	}
}

// TestBothBinariesAreReplacedTogether.
//
// The archive ships zcd and zycordd and they are one release. A node at v0.2.0
// beside a zcd at v0.1.1 is a configuration nobody chose and nobody tests, and
// zcd builds certificates against core/'s rules through wallet/session — so a
// skewed pair is how an operator gets a certificate their own node refuses with
// no reason to suspect the CLI.
func TestBothBinariesAreReplacedTogether(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "zycordd")
	cli := filepath.Join(dir, "zcd")
	writeExe(t, node, "OLD-NODE")
	writeExe(t, cli, "OLD-CLI")

	src := t.TempDir()
	writeExe(t, filepath.Join(src, "zycordd"), "NEW-NODE")
	writeExe(t, filepath.Join(src, "zcd"), "NEW-CLI")

	in, err := update.PlanInstall(targetFor(node), map[string]string{
		"zycordd": filepath.Join(src, "zycordd"),
		"zcd":     filepath.Join(src, "zcd"),
	}, "v0.2.0", "v0.1.1")
	if err != nil {
		t.Fatalf("PlanInstall: %v", err)
	}
	if len(in.Binaries) != 2 {
		t.Fatalf("planned %d replacements, want both binaries: %v", len(in.Binaries), in.Binaries)
	}
	if _, err := in.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for path, want := range map[string]string{node: "NEW-NODE", cli: "NEW-CLI"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", filepath.Base(path), got, want)
		}
	}
}

// TestTheSiblingIsTakenByNameAndNotByPathSearch.
//
// Hunting for a second binary to overwrite is how an updater overwrites
// something it was never installed as.
func TestTheSiblingIsTakenByNameAndNotByPathSearch(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "zycordd")
	writeExe(t, node, "OLD-NODE")
	// A zcd exists, but somewhere else entirely.
	elsewhere := t.TempDir()
	writeExe(t, filepath.Join(elsewhere, "zcd"), "SOMEBODY ELSE'S")
	t.Setenv("PATH", elsewhere+string(os.PathListSeparator)+os.Getenv("PATH"))

	src := t.TempDir()
	writeExe(t, filepath.Join(src, "zycordd"), "NEW-NODE")
	writeExe(t, filepath.Join(src, "zcd"), "NEW-CLI")

	in, err := update.PlanInstall(targetFor(node), map[string]string{
		"zycordd": filepath.Join(src, "zycordd"),
		"zcd":     filepath.Join(src, "zcd"),
	}, "v0.2.0", "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Binaries) != 1 {
		t.Errorf("planned %d replacements, want only the running binary: %v", len(in.Binaries), in.Binaries)
	}
	if _, err := in.Apply(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(elsewhere, "zcd"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SOMEBODY ELSE'S" {
		t.Error("a binary found on PATH was overwritten")
	}
}

// TestThePreviousBinaryIsKeptAndCanBeRestored.
func TestThePreviousBinaryIsKeptAndCanBeRestored(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "zycordd")
	writeExe(t, node, "OLD-NODE")
	src := t.TempDir()
	writeExe(t, filepath.Join(src, "zycordd"), "NEW-NODE")

	in, err := update.PlanInstall(targetFor(node), map[string]string{"zycordd": filepath.Join(src, "zycordd")},
		"v0.2.0", "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	backups, err := in.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if backups[node] == "" {
		t.Fatal("no backup recorded")
	}
	if b, err := os.ReadFile(backups[node]); err != nil || string(b) != "OLD-NODE" {
		t.Fatalf("backup = %q, err %v", b, err)
	}
	if err := in.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if b, err := os.ReadFile(node); err != nil || string(b) != "OLD-NODE" {
		t.Errorf("after rollback = %q, err %v", b, err)
	}
}

// TestTheExecutableIsStillThereAtEveryPointOfTheReplace.
//
// The whole ordering argument is that a crash never leaves the name empty. On
// Unix the previous file is HARD-LINKED aside rather than renamed, so the
// destination never stops existing at all.
func TestTheExecutableIsStillThereAtEveryPointOfTheReplace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows must rename the running image aside; the two-syscall window is documented")
	}
	dir := t.TempDir()
	node := filepath.Join(dir, "zycordd")
	writeExe(t, node, "OLD-NODE")
	src := t.TempDir()
	writeExe(t, filepath.Join(src, "zycordd"), "NEW-NODE")

	in, err := update.PlanInstall(targetFor(node), map[string]string{"zycordd": filepath.Join(src, "zycordd")},
		"v0.2.0", "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Apply(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(node)
	if err != nil {
		t.Fatalf("the destination does not exist after a replace: %v", err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("the replacement is not executable: %v", fi.Mode())
	}
}

// TestASymlinkIsFollowedAndLeftAlone.
//
// Overwriting the link would turn a managed symlink into a regular file and
// break whatever manages it — Homebrew's bin/zcd, or a `current -> v0.1.1`
// layout an operator maintains by hand.
func TestASymlinkIsFollowedAndLeftAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows that a test should not assume")
	}
	dir := t.TempDir()
	// The layout an operator actually maintains: a stable name in one place,
	// pointing at the real binary somewhere else.
	libexec := filepath.Join(dir, "libexec")
	if err := os.MkdirAll(libexec, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(libexec, "zycordd")
	link := filepath.Join(dir, "zycordd")
	writeExe(t, real, "OLD-NODE")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	writeExe(t, filepath.Join(src, "zycordd"), "NEW-NODE")

	target := update.Target{
		Path: link, Resolved: real, ViaSymlink: true,
		Dir: libexec, Name: filepath.Base(real),
	}
	in, err := update.PlanInstall(target, map[string]string{"zycordd": filepath.Join(src, "zycordd")},
		"v0.2.0", "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Apply(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if b, err := os.ReadFile(real); err != nil || string(b) != "NEW-NODE" {
		t.Errorf("the resolved file = %q, err %v", b, err)
	}
	if !strings.Contains(target.String(), "left alone") {
		t.Errorf("the description does not say the link is untouched: %s", target.String())
	}
}

// TestTheRestartCarriesTheLoopGuard.
//
// Equal to the running version means the update worked. DIFFERENT means the exec
// landed on a binary that is not the one just installed — the replace did not
// take, or something rolled it back — and it must not be retried.
func TestTheRestartCarriesTheLoopGuard(t *testing.T) {
	t.Setenv(update.ReexecEnv, "")
	if got := update.RestartedInto(); got != "" {
		t.Errorf("RestartedInto() = %q on a fresh process", got)
	}
	t.Setenv(update.ReexecEnv, "v0.2.0")
	if got := update.RestartedInto(); got != "v0.2.0" {
		t.Errorf("RestartedInto() = %q, want v0.2.0", got)
	}
}

// TestAnArchiveWithoutTheRunningBinaryIsRefused, rather than half-installed.
func TestAnArchiveWithoutTheRunningBinaryIsRefused(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "zycordd")
	writeExe(t, node, "OLD-NODE")
	src := t.TempDir()
	writeExe(t, filepath.Join(src, "zcd"), "NEW-CLI")

	_, err := update.PlanInstall(targetFor(node), map[string]string{"zcd": filepath.Join(src, "zcd")},
		"v0.2.0", "v0.1.1")
	if err == nil {
		t.Fatal("planned an install from an archive holding no replacement for the running binary")
	}
	if !strings.Contains(err.Error(), "zycordd") {
		t.Errorf("err = %v, want it to name the missing binary", err)
	}
}

// TestOnlyTheWindowsExtensionIsEverStripped is the regression for a real defect.
//
// PlanInstall used filepath.Ext to remove ".exe", and Ext returns everything
// after the LAST dot — so a binary installed as `zycordd-0.1.1` had a stem of
// "zycordd-0.1" and a sibling of "zcd.1", and could never be updated. The only
// extension this package has business knowing about is the one Windows requires.
func TestOnlyTheWindowsExtensionIsEverStripped(t *testing.T) {
	for _, tc := range []struct{ name, stem string }{
		{"zycordd", "zycordd"},
		{"zycordd.exe", "zycordd"},
		{"zycordd.EXE", "zycordd"},
		{"zycordd-0.1.1", "zycordd-0.1.1"},
		{"zcd.test.build", "zcd.test.build"},
		{"zcd", "zcd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := update.BinaryStem(tc.name); got != tc.stem {
				t.Errorf("BinaryStem(%q) = %q, want %q", tc.name, got, tc.stem)
			}
		})
	}

	// And the sibling keeps the extension it found, without inventing one.
	unix := update.Target{Dir: "/opt/z", Name: "zycordd"}
	if got := unix.Sibling("zcd"); got != filepath.Join("/opt/z", "zcd") {
		t.Errorf("sibling = %q", got)
	}
	win := update.Target{Dir: "/opt/z", Name: "zycordd.exe"}
	if got := win.Sibling("zcd"); got != filepath.Join("/opt/z", "zcd.exe") {
		t.Errorf("sibling = %q, want zcd.exe", got)
	}
	dotted := update.Target{Dir: "/opt/z", Name: "zycordd-0.1.1"}
	if got := dotted.Sibling("zcd"); got != filepath.Join("/opt/z", "zcd") {
		t.Errorf("sibling = %q, want a bare zcd rather than zcd.1", got)
	}
}
