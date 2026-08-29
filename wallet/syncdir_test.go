package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSyncDirOnlyIgnoresUnsupportedPlatformErrors pins the classification
// syncDir rests on, and it is the mirror of node/storage's test of the same
// name because it guards the same rule in the other tree.
//
// It is here because the wallet's half of that rule was missing for as long as
// this package has had a Windows build, and nothing failed: syncDir is the last
// step of every publish tier, so on Windows `zcd key new`, `zcd ui` and the
// desktop wallet each wrote the encrypted seed, published it correctly, and
// then reported failure — and the suite that proves the publish is atomic on
// five tiers said nothing, because it only ever ran where a directory can be
// fsynced. The classification is the fix; this is what keeps it.
func TestSyncDirOnlyIgnoresUnsupportedPlatformErrors(t *testing.T) {
	// The rows every platform agrees on. What must be ignored is "there was never
	// anything to sync"; what must propagate is every way a sync can genuinely
	// fail, which is the whole point of the classification — the version before
	// it returned nil for every Sync failure alike.
	cases := []struct {
		name   string
		err    error
		ignore bool
	}{
		{"ENOTSUP", syscall.ENOTSUP, true},
		{"EINVAL", syscall.EINVAL, true},
		{"EIO", syscall.EIO, false},
		{"ENOSPC", syscall.ENOSPC, false},
		{"a generic error", errors.New("disk on fire"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUnsupportedDirSync(c.err); got != c.ignore {
				t.Fatalf("isUnsupportedDirSync(%v) = %v, want %v", c.err, got, c.ignore)
			}
		})
	}

	// The platform's own answer, measured rather than named.
	//
	// This is the row that differs — ENOTSUP on some unix filesystems,
	// ERROR_ACCESS_DENIED on Windows always — and writing either constant here
	// would assert the classification against itself. So the error is obtained
	// the way syncDir obtains it, from a real directory on the filesystem this
	// test is running on, and the requirement is stated once for every
	// platform: whatever fsyncing a directory fails with *here*, syncDir has to
	// be able to tell it apart from a failure.
	//
	// On unix this branch does not fire, because the sync succeeds. On Windows
	// it fires on every machine, and it is the assertion that would have caught
	// the wallet being unable to save a key.
	t.Run("the error this platform actually returns", func(t *testing.T) {
		dir := t.TempDir()
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := f.Sync(); err != nil && !isUnsupportedDirSync(err) {
			t.Fatalf("fsync of a directory on this platform fails with %v, and "+
				"isUnsupportedDirSync does not recognise it — so every wallet "+
				"save here reports failure after writing and publishing the key", err)
		}
	})

	// And the assertion that follows from it: a real directory syncs, or is
	// classified as one that cannot, and either way syncDir returns nil.
	t.Run("a real directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "wallet.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := syncDir(dir); err != nil {
			t.Fatalf("syncDir on a real directory: %v", err)
		}
	})
}
