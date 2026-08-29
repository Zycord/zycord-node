//go:build !linux && !darwin && !windows

package wallet

import "errors"

// errNoExclusiveRename reports that this platform has no verified exclusive
// rename. It is deliberately not fs.ErrExist, so writeFileNoClobber falls
// through to its next publish mechanism.
var errNoExclusiveRename = errors.New("wallet: no verified exclusive rename on this platform")

// renameNoReplace has no verified implementation on this platform, so it
// always fails and writeFileNoClobber falls through to os.Link — which
// refuses an existing destination just as atomically, on every filesystem
// that has hard links at all.
//
// That last clause is the load-bearing one, and it is a real condition rather
// than a formality: where it does not hold, this fall-through lands on tier 3,
// whose refusal is not atomic. Linux, darwin and Windows each have an
// exclusive rename of their own — renameat2(RENAME_NOREPLACE),
// renamex_np(RENAME_EXCL) and MoveFileEx without MOVEFILE_REPLACE_EXISTING —
// and all three are implemented in their own files here, each verified
// against real volumes of a filesystem *without* hard links, because that is
// the only case that distinguishes tier 1 from tier 2. Windows was the last
// of the three, and it was not a formality either: on exFAT os.Link fails
// with ERROR_INVALID_FUNCTION, which is not fs.ErrExist, so before
// atomicfile_windows.go existed a key file written to a FAT-formatted stick
// from Windows was published by the racy tier.
//
// So what is left building this file is the BSDs, which do not appear to have
// an exclusive rename at all. An unverified guess at this particular
// guarantee is worth less than an honest fall-through, precisely because the
// fall-through is itself atomic wherever hard links exist — which on those
// platforms is UFS, ZFS and every filesystem they normally use, though not a
// FAT stick mounted on one. If you add one, verify it against a real volume
// of a filesystem without hard links, the way the other three were —
// TestRenameNoReplaceIsAnExclusiveRename is the test to extend, and it
// deliberately does not skip.
func renameNoReplace(oldpath, newpath string) error {
	return errNoExclusiveRename
}
