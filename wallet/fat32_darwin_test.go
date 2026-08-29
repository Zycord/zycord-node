//go:build darwin

package wallet

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSaveKeyFileOnAFilesystemWithoutHardLinks is the test the review of the
// no-clobber publish asked for: a real hard-link-incapable filesystem, not
// just a theory about one. It formats and mounts an actual FAT32 volume with
// hdiutil (macOS's disk-image tool — no root required, unlike a Linux loopback
// mount) and runs SaveKeyFile/LoadKeyFile against a path on it.
//
// FAT32 and exFAT cannot hard-link at all, and they are exactly the formats a
// cold-storage USB backup of a key file is likely to use — the audience the
// "losing one is losing money" framing targets. That makes them the
// filesystems this fix most has to work on, not the ones it is allowed to
// degrade on, which is why this test asserts all three properties and not just
// that the write succeeds:
//
//  1. os.Link really does fail here (so the test is exercising what it claims)
//     while renamex_np(RENAME_EXCL) — the tier that publishes a key file on
//     this filesystem — really does work, both publishing and refusing an
//     existing destination without disturbing it;
//  2. SaveKeyFile works here at all (a link-only implementation fails
//     unconditionally — os.Link reports ENOTSUP on macOS's msdos driver and
//     EPERM on Linux's vfat/exfat drivers, neither of which is fs.ErrExist);
//  3. the no-clobber guarantee still refuses a second write; and
//  4. **the crash-safety guarantee holds here too** — a crash mid-write leaves
//     nothing at the destination and a plain rerun recovers. Asserting that on
//     a real FAT32 volume is the whole point: it is the difference between
//     fixing the torn-key-file defect and fixing it everywhere except where it
//     matters most.
//
// Skips rather than fails when hdiutil is unavailable or a disk image cannot
// be created and mounted (sandboxing, missing entitlements, CI without disk
// arbitration) — this is the one platform-specific integration test in the
// package, kept out of the default `go test ./...` guarantee on purpose. It
// is darwin-only (hdiutil has no equivalent elsewhere in this tree); a real
// FAT32/exFAT mount on Linux needs a loopback mount, which needs root, which
// this repo's CI does not have and should not be given for one test. The
// Linux side of the table in writeFileNoClobber's doc comment was measured
// the same way, in a privileged container, rather than assumed.
func TestSaveKeyFileOnAFilesystemWithoutHardLinks(t *testing.T) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not on PATH; this test only runs where it can create a real FAT32 volume")
	}

	imgDir := t.TempDir()
	imgPath := filepath.Join(imgDir, "fat32.dmg")

	create := exec.Command("hdiutil", "create", "-size", "16m", "-fs", "MS-DOS",
		"-volname", "ZCDTEST", imgPath)
	if out, err := create.CombinedOutput(); err != nil {
		t.Skipf("could not create a FAT32 disk image (sandboxed environment?): %v: %s", err, out)
	}

	attach := exec.Command("hdiutil", "attach", imgPath)
	out, err := attach.CombinedOutput()
	if err != nil {
		t.Skipf("could not attach the FAT32 disk image (sandboxed environment?): %v: %s", err, out)
	}

	mountPoint := parseMountPoint(string(out))
	if mountPoint == "" {
		t.Skipf("could not determine the FAT32 volume's mount point from hdiutil output:\n%s", out)
	}
	t.Cleanup(func() {
		exec.Command("hdiutil", "detach", mountPoint, "-force").Run()
	})

	// Confirm the premise of the test before trusting its result: this must
	// actually be a filesystem that refuses hard links, or the "it now
	// works" assertion below would be meaningless.
	probeA := filepath.Join(mountPoint, "probe-a")
	probeB := filepath.Join(mountPoint, "probe-b")
	if err := os.WriteFile(probeA, []byte("x"), 0o600); err != nil {
		t.Skipf("could not write to the mounted FAT32 volume: %v", err)
	}
	linkErr := os.Link(probeA, probeB)
	if linkErr == nil {
		t.Skip("os.Link unexpectedly succeeded on this FAT32 mount; premise of the test not met here")
	}
	if errors.Is(linkErr, fs.ErrExist) {
		t.Skipf("os.Link failed with %v, which is the no-clobber refusal, not the missing-capability failure this test exists to exercise", linkErr)
	}
	t.Logf("premise confirmed: os.Link on this FAT32 mount fails with %v", linkErr)
	os.Remove(probeB)

	// And the claim: the exclusive rename — the tier that actually publishes
	// a key file here, precisely because the hard link above cannot — does
	// work on this filesystem, and refuses an existing destination without
	// disturbing it. Both halves, measured on the real volume, because this
	// is the guarantee that would otherwise rest on a check-then-rename race.
	probeC := filepath.Join(mountPoint, "probe-c")
	if err := renameNoReplace(probeA, probeC); err != nil {
		t.Fatalf("renamex_np(RENAME_EXCL) must publish on FAT32, got %v", err)
	}
	probeD := filepath.Join(mountPoint, "probe-d")
	if err := os.WriteFile(probeD, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(probeD, probeC); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("renamex_np(RENAME_EXCL) must refuse an existing destination on FAT32 with fs.ErrExist, got %v", err)
	}
	if got, err := os.ReadFile(probeC); err != nil || string(got) != "x" {
		t.Fatalf("the refused destination was disturbed: %q %v", got, err)
	}
	os.Remove(probeC)
	os.Remove(probeD)

	// The actual regression check: SaveKeyFile must succeed on this volume,
	// not fail unconditionally the way a Link-only implementation would.
	keyPath := filepath.Join(mountPoint, "wallet.json")
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("fat32 test passphrase")
	if err := SaveKeyFile(keyPath, k, pass); err != nil {
		t.Fatalf("SaveKeyFile failed on a real FAT32 volume: %v", err)
	}

	loaded, err := LoadKeyFile(keyPath, pass)
	if err != nil {
		t.Fatalf("LoadKeyFile failed reading back what was just written to FAT32: %v", err)
	}
	if loaded.Persistent() != k.Persistent() {
		t.Fatal("the key read back from FAT32 does not match the one written")
	}

	// The no-clobber guarantee must survive the fallback too.
	k2, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyFile(keyPath, k2, []byte("different passphrase")); err == nil {
		t.Fatal("expected SaveKeyFile to refuse to overwrite the existing key file on FAT32")
	}
	// And the original must still be intact.
	loaded, err = LoadKeyFile(keyPath, pass)
	if err != nil || loaded.Persistent() != k.Persistent() {
		t.Fatal("the original FAT32 key file was disturbed by the refused overwrite")
	}

	// The crash-safety guarantee itself, on the filesystem it is most needed on:
	// a crash mid-write must leave nothing at the destination, and rerunning the
	// same command to the same path must then simply work. Under a direct
	// O_CREATE|O_EXCL write to the final name — what this package did before
	// writeFileNoClobber existed, and what a fallback that gave up on crash
	// safety here would have reintroduced — the first half leaves a torn file and
	// the second half is refused by O_EXCL, permanently, with the seed nowhere
	// else.
	crashPath := filepath.Join(mountPoint, "crash.json")
	crashErr := errors.New("simulated crash on FAT32")
	// t.Cleanup, not a plain assignment after the call: if anything below
	// calls t.Fatal, runtime.Goexit fires and a plain restore never runs,
	// leaving the seam armed and poisoning every later test in the package.
	old := crashAfterWrite
	crashAfterWrite = func() error { return crashErr }
	t.Cleanup(func() { crashAfterWrite = old })
	k3, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	err = SaveKeyFile(crashPath, k3, pass)
	crashAfterWrite = nil
	if !errors.Is(err, crashErr) {
		t.Fatalf("expected the simulated crash to surface, got %v", err)
	}
	if _, statErr := os.Stat(crashPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("FAT32: the destination must not exist after a crash mid-write, got stat error %v", statErr)
	}
	if err := SaveKeyFile(crashPath, k3, pass); err != nil {
		t.Fatalf("FAT32: rerunning after a crashed write must recover, got %v", err)
	}
	if loaded, err := LoadKeyFile(crashPath, pass); err != nil || loaded.Persistent() != k3.Persistent() {
		t.Fatalf("FAT32: the recovered key file does not read back: %v", err)
	}
}

// parseMountPoint extracts the volume path from hdiutil attach's output,
// which looks like:
//
//	/dev/disk4          	FDisk_partition_scheme
//	/dev/disk4s1        	DOS_FAT_32                     	/Volumes/ZCDTEST
func parseMountPoint(hdiutilOutput string) string {
	for _, line := range strings.Split(hdiutilOutput, "\n") {
		if idx := strings.Index(line, "/Volumes/"); idx >= 0 {
			return strings.TrimSpace(line[idx:])
		}
	}
	return ""
}
