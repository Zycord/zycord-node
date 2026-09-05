package update_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"zycord/update"
)

// TestAPackageManagedInstallIsRefusedWithItsOwnCommand.
//
// Every one of these is a case where the operator CAN update — through the
// package manager that put the file there. A refusal that said only "no" would
// teach them that updating is somebody else's problem, so each carries the
// command that actually works.
func TestAPackageManagedInstallIsRefusedWithItsOwnCommand(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    []string
		env     map[string]string
		wantCmd string
	}{
		{
			name:    "a Homebrew Cellar path",
			path:    []string{"opt", "homebrew", "Cellar", "zycord", "0.1.1", "bin"},
			wantCmd: "brew upgrade",
		},
		{
			name:    "a linuxbrew path",
			path:    []string{"linuxbrew", ".linuxbrew", "bin"},
			wantCmd: "brew upgrade",
		},
		{
			name:    "a Scoop apps path",
			path:    []string{"users", "someone", "scoop", "apps", "zycord", "0.1.1"},
			wantCmd: "scoop update",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(append([]string{root}, tc.path...)...)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			exe := filepath.Join(dir, "zycordd")
			writeExe(t, exe, "OLD")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			r := update.Guard(targetFor(exe), "v0.1.1")
			if r == nil {
				t.Fatal("a package-managed install was accepted for in-place replacement")
			}
			if !strings.Contains(r.Advice, tc.wantCmd) {
				t.Errorf("advice = %q, want it to name %q", r.Advice, tc.wantCmd)
			}
			if r.Reason == "" {
				t.Error("no reason given")
			}
		})
	}
}

// TestHomebrewIsRecognisedByItsPrefixEnvironment covers the install that is not
// under any of the well-known roots.
func TestHomebrewIsRecognisedByItsPrefixEnvironment(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "somewhere", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "zycordd")
	writeExe(t, exe, "OLD")

	if r := update.Guard(targetFor(exe), "v0.1.1"); r != nil {
		t.Fatalf("refused before HOMEBREW_PREFIX was set: %v", r)
	}
	t.Setenv("HOMEBREW_PREFIX", root)
	r := update.Guard(targetFor(exe), "v0.1.1")
	if r == nil {
		t.Fatal("HOMEBREW_PREFIX was ignored")
	}
	if !strings.Contains(r.Advice, "brew upgrade") {
		t.Errorf("advice = %q", r.Advice)
	}
}

// TestAVersionNamedDirectoryIsRefused backstops the package-manager checks and
// catches the hand-rolled layout.
func TestAVersionNamedDirectoryIsRefused(t *testing.T) {
	for _, dirName := range []string{"v0.1.1", "0.1.1"} {
		t.Run(dirName, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "zycord", dirName)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			exe := filepath.Join(dir, "zycordd")
			writeExe(t, exe, "OLD")
			r := update.Guard(targetFor(exe), "v0.1.1")
			if r == nil {
				t.Fatal("a version-named directory was accepted")
			}
			if !strings.Contains(r.Reason, "named for its own version") {
				t.Errorf("reason = %q", r.Reason)
			}
		})
	}
	// And a directory that merely contains digits is not one.
	root := t.TempDir()
	dir := filepath.Join(root, "bin64")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "zycordd")
	writeExe(t, exe, "OLD")
	if r := update.Guard(targetFor(exe), "v0.1.1"); r != nil {
		t.Errorf("bin64 was treated as a version directory: %v", r)
	}
}

// TestAnAppImageIsRefused. The filesystem is read-only for the life of the
// process; there is nothing here that can be replaced.
func TestAnAppImageIsRefused(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zycordd")
	writeExe(t, exe, "OLD")
	t.Setenv("APPIMAGE", "/somewhere/Zycord.AppImage")
	r := update.Guard(targetFor(exe), "v0.1.1")
	if r == nil {
		t.Fatal("an AppImage was accepted for in-place replacement")
	}
	if !strings.Contains(r.Reason, "read-only") {
		t.Errorf("reason = %q", r.Reason)
	}
}

// TestAnUnwritableDirectoryIsRefusedByProbingIt.
//
// A probe rather than a reading of mode bits: it performs the exact operation
// the replace needs, which is the only check that gets read-only mounts, ACLs,
// SELinux and Windows' permission model right.
func TestAnUnwritableDirectoryIsRefusedByProbingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not deny directory writes on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can write to a 0500 directory, which is the point of the ownership guard instead")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "zycordd")
	writeExe(t, exe, "OLD")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	r := update.Guard(targetFor(exe), "v0.1.1")
	if r == nil {
		t.Fatal("an unwritable directory was accepted")
	}
	if !strings.Contains(r.Reason, dir) {
		t.Errorf("reason = %q, want it to name the DIRECTORY (the replace is a rename into it)", r.Reason)
	}
}

// TestAnOrdinaryInstallIsAccepted, so the guards are not simply refusing
// everything.
func TestAnOrdinaryInstallIsAccepted(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zycordd")
	writeExe(t, exe, "OLD")
	if r := update.Guard(targetFor(exe), "v0.1.1"); r != nil {
		t.Errorf("an ordinary writable install was refused: %v", r)
	}
}

// TestAGuardRefusalReadsAsOneMessage.
func TestAGuardRefusalReadsAsOneMessage(t *testing.T) {
	r := &update.Refusal{Reason: "because.", Advice: "  do this"}
	if got := r.Error(); !strings.Contains(got, "because.") || !strings.Contains(got, "do this") {
		t.Errorf("Error() = %q", got)
	}
	bare := &update.Refusal{Reason: "because."}
	if got := bare.Error(); got != "because." {
		t.Errorf("Error() = %q, want no trailing blank lines when there is no advice", got)
	}
}

// TestTheMostSpecificRefusalWins.
//
// A Homebrew install is ALSO unwritable when brew's prefix is root-owned, and
// the useful thing to say there is `brew upgrade`, not "permission denied". The
// order of the checks is the whole of what produces the better message, so it is
// asserted rather than left to the order they happen to be listed in.
func TestTheMostSpecificRefusalWins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not deny directory writes on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can write to a 0500 directory")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "opt", "homebrew", "Cellar", "zycord", "0.1.1", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "zycordd")
	writeExe(t, exe, "OLD")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	r := update.Guard(targetFor(exe), "v0.1.1")
	if r == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(r.Advice, "brew upgrade") {
		t.Errorf("advice = %q; an unwritable Homebrew install should still be told to use brew, "+
			"not that it lacks permission", r.Advice)
	}
}

// TestABinaryOwnedByThePackageManagerIsRefused.
//
// The ownership guard already stops the common case: a node runs unprivileged
// and the package's binary is root-owned, so it cannot be written. An operator
// running the node as root has no such protection, and replacing a file dpkg
// owns leaves the package database describing bytes that are no longer there —
// the next upgrade overwrites the update, and `dpkg -V` reports a modified file
// from then on.
//
// This asks dpkg about a path it certainly owns on a Debian-family machine, and
// skips where there is no dpkg to ask, because the guard's own answer there is
// "no package to conflict with" and that is correct rather than untested.
func TestABinaryOwnedByThePackageManagerIsRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("dpkg is a Debian-family thing")
	}
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("no dpkg-query on this machine, which is the case the guard returns nil for")
	}
	// A path dpkg owns on every Debian-family install.
	owned := "/bin/sh"
	if _, err := os.Stat(owned); err != nil {
		t.Skip("no /bin/sh to ask about")
	}
	resolved, err := filepath.EvalSymlinks(owned)
	if err != nil {
		t.Skip(err)
	}
	if out, err := exec.Command("dpkg-query", "-S", resolved).Output(); err != nil || len(out) == 0 {
		t.Skipf("dpkg does not own %s on this machine", resolved)
	}

	r := update.Guard(update.Target{
		Path: resolved, Resolved: resolved,
		Dir: filepath.Dir(resolved), Name: filepath.Base(resolved),
	}, "v0.1.2")
	if r == nil {
		t.Fatal("a binary owned by an installed package was accepted for in-place replacement")
	}
	if !strings.Contains(r.Reason, "package") {
		t.Errorf("reason = %q, want it to name the package manager", r.Reason)
	}
}
