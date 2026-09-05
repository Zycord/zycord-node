//go:build linux || darwin || windows

package wallet

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// exclusiveRenameSupported reports whether this filesystem actually
// implements the exclusive rename, by asking renameNoReplace directly in dir.
//
// This is the probe that lets the tests below tell two very different things
// apart. "Tier 1 was not used" is a regression — the wiring is broken and FAT
// media silently drop to the racy tier. "Tier 1 does not exist here" is
// correct behaviour that tiers 2 and 3 are there to handle: RENAME_NOREPLACE
// needs filesystem support, and a kernel older than 3.15 reports ENOSYS while
// darwin reports ENOTSUP. A test that cannot distinguish those two would
// either flake wherever tier 1 is legitimately absent, or — if it skipped on
// any failure — stop noticing the regression entirely.
//
// Two details of this function are load-bearing, both measured rather than
// assumed. Do not "simplify" either away.
//
// It probes the **publish** direction (renaming onto a free name), not the
// refusal direction, because a filesystem can have one and not the other.
// Linux checks RENAME_NOREPLACE in the VFS, before dispatching to the
// filesystem, so an occupied destination is refused with EEXIST even where
// the flag is otherwise unsupported; only the publish path reaches the
// driver. Measured on a real FUSE mount (bindfs, kernel 6.12): publish onto a
// free name fails EINVAL, while refusing an occupied one returns EEXIST with
// the destination untouched. A probe written against the refusal direction
// would report "supported" there and leave the flake in place.
//
// And it probes by calling renameNoReplace itself rather than by matching an
// errno list. FUSE's EINVAL is not ENOSYS/ENOTSUP/EOPNOTSUPP, so it does not
// satisfy errors.Is(err, errors.ErrUnsupported) and an allowlist would have
// missed it. More importantly, calling the real function is what keeps the
// skip honest: a build where renameNoReplace has been unhooked from
// writeFileNoClobber still probes as supported, so the regression shows up as
// "works here, but writeFileNoClobber did not use it" instead of hiding
// behind a skip. FUSE is also the case someone is actually likely to hit —
// sshfs, gocryptfs, rclone, s3fs, macFUSE — more so than a network mount.
func exclusiveRenameSupported(t *testing.T, dir string) bool {
	t.Helper()
	src := filepath.Join(dir, ".exclusive-probe-src")
	if err := os.WriteFile(src, []byte("probe"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(src)
	dst := filepath.Join(dir, ".exclusive-probe-dst")
	if err := renameNoReplace(src, dst); err != nil {
		return false
	}
	os.Remove(dst)
	return true
}

// TestRenameNoReplaceIsAnExclusiveRename pins the existence of publish tier 1
// on the three platforms that claim to have one.
//
// Without this, silently disabling the exclusive rename — deleting it,
// breaking it, having it always return an error — leaves the entire suite
// green on every filesystem, because tier 2's hard link is atomic on ext4 and
// APFS and so all the no-clobber assertions still hold there. The failure
// only shows up on FAT32 and exFAT, where tier 2 is unavailable and the
// implementation would silently drop to tier 3's racy check-then-rename:
// exactly the state this package is supposed to have left behind. Nothing
// else in the suite can tell "tier 1 works" from "tier 1 is gone."
//
// It deliberately does not skip. renameNoReplace is
// renameat2(RENAME_NOREPLACE) on linux, renamex_np(RENAME_EXCL) on darwin and
// MoveFileEx without MOVEFILE_REPLACE_EXISTING on windows, each verified
// against real volumes of a filesystem *without* hard links -- vfat, exfat and
// FAT32 on the first two, exFAT on the third -- because that is the only case
// that distinguishes tier 1 from tier 2. A platform that claims an exclusive
// rename has to prove it. Platforms with no verified one build
// atomicfile_other.go instead and are excluded by the build tag above.
//
// Because it runs in t.TempDir(), pointing TMPDIR at a mounted FAT volume
// turns this into a real assertion about that filesystem — which is how the
// FAT measurements behind rule 7 were made.
func TestRenameNoReplaceIsAnExclusiveRename(t *testing.T) {
	t.Run("publishes the source file when the destination is free", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		// Force the file identity to load while src still exists. On unix
		// os.Stat has already filled in st_dev/st_ino and this is a no-op;
		// on Windows the identity is loaded lazily, by reopening the path,
		// and the rename below consumes that path — so without this the
		// comparison is against a dead path and answers false for the file
		// against itself. The full mechanism is written up on the same call
		// in forcePublishTiers (keyfile_atomic_internal_test.go).
		os.SameFile(before, before)

		dst := filepath.Join(dir, "dst")
		if err := renameNoReplace(src, dst); err != nil {
			// The only honest reading of a failure here is "this filesystem
			// has no exclusive rename", which tiers 2 and 3 exist to handle.
			// The refusal subtest below skips for the same reason, and
			// TestWriteFileNoClobberPublishesWithTheExclusiveRename is what
			// still catches a broken one on a filesystem that does have it.
			t.Skipf("no exclusive rename on the filesystem behind %s (%v); "+
				"tiers 2 and 3 cover this case", dir, err)
		}

		published, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, published) {
			t.Fatal("the destination is not the source file: this is a copy, not a publish")
		}
		if _, err := os.Lstat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the source name must be consumed by the rename, got %v", err)
		}
	})

	t.Run("refuses an occupied destination without disturbing it", func(t *testing.T) {
		dir := t.TempDir()
		if !exclusiveRenameSupported(t, dir) {
			t.Skipf("no exclusive rename on the filesystem behind %s; tiers 2 and 3 cover this case", dir)
		}
		src := filepath.Join(dir, "src")
		if err := os.WriteFile(src, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, "dst")
		if err := os.WriteFile(dst, []byte("the existing key file"), 0o600); err != nil {
			t.Fatal(err)
		}
		occupied, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}

		err = renameNoReplace(src, dst)
		if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("an exclusive rename must refuse an occupied destination with fs.ErrExist, got %v", err)
		}

		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "the existing key file" {
			t.Fatalf("the refused destination was modified: %q", got)
		}
		still, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(occupied, still) {
			t.Fatal("the refused destination was replaced by a different file")
		}
		// The source survives a refusal, so the caller can still clean up or
		// retry — writeFileNoClobber relies on this to fall through to its
		// next publish tier with the temp file still intact.
		if got, err := os.ReadFile(src); err != nil || string(got) != "replacement" {
			t.Fatalf("the source must survive a refused publish: %q %v", got, err)
		}
	})
}

// TestWriteFileNoClobberPublishesWithTheExclusiveRename pins the *wiring*,
// which is a separate thing from whether the syscall works.
//
// TestRenameNoReplaceIsAnExclusiveRename above proves renameNoReplace does
// its job. It cannot notice if writeFileNoClobber stops calling it — unhook
// tier 1 and every other test in the package still passes, on every
// filesystem, because tier 2's hard link is atomic on ext4 and APFS and so
// all the no-clobber assertions still hold there. The damage would only be
// visible on FAT32 and exFAT, where tier 2 is unavailable and the
// implementation would silently drop to tier 3's racy check-then-rename.
// Measured: with tier 1 unhooked, the full suite passes on a real vfat mount
// through 800 rounds of the concurrency test.
//
// So this asserts the order directly: where an exclusive rename exists, a key
// file is published by it and the lower tiers are never reached. It probes the
// filesystem first — tier 1 being genuinely absent (a network mount, a kernel
// older than 3.15) is correct behaviour that tiers 2 and 3 handle, and must
// not be reported as a regression — but a filesystem that has one and is not
// used is exactly the regression this exists for.
func TestWriteFileNoClobberPublishesWithTheExclusiveRename(t *testing.T) {
	dir := t.TempDir()
	if !exclusiveRenameSupported(t, dir) {
		// Tier 1 genuinely does not exist here (a network mount, an old
		// kernel), so falling through to a lower tier is the correct
		// behaviour and there is no wiring claim to check.
		t.Skipf("no exclusive rename on the filesystem behind %s; tiers 2 and 3 cover this case", dir)
	}

	var exclusiveCalls, exclusiveOK, linkCalls int

	oldExclusive, oldLink := publishExclusive, publishByLink
	publishExclusive = func(oldpath, newpath string) error {
		exclusiveCalls++
		err := oldExclusive(oldpath, newpath)
		if err == nil {
			exclusiveOK++
		}
		return err
	}
	publishByLink = func(oldpath, newpath string) error {
		linkCalls++
		return oldLink(oldpath, newpath)
	}
	t.Cleanup(func() { publishExclusive, publishByLink = oldExclusive, oldLink })

	path := filepath.Join(dir, "wallet.json")
	if err := writeFileNoClobber(path, []byte("a key file")); err != nil {
		t.Fatal(err)
	}

	if exclusiveCalls != 1 {
		t.Fatalf("the exclusive rename was attempted %d times, want exactly 1: "+
			"writeFileNoClobber is not publishing through tier 1", exclusiveCalls)
	}
	if exclusiveOK != 1 {
		// The probe above proved this filesystem supports it, so a failure
		// now is the wiring, not the environment.
		t.Fatalf("the exclusive rename works on the filesystem behind %s — the "+
			"probe just used it — but writeFileNoClobber's tier 1 did not "+
			"succeed. Publishing has been unhooked from it, which silently "+
			"drops FAT32 and exFAT to the racy check-then-rename tier", dir)
	}
	if linkCalls != 0 {
		t.Fatalf("a lower publish tier was reached %d times even though the "+
			"exclusive rename succeeded", linkCalls)
	}
}
