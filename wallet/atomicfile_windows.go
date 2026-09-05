package wallet

import (
	"os"

	"golang.org/x/sys/windows"
)

// renameNoReplace publishes oldpath as newpath and fails with
// ERROR_ALREADY_EXISTS if newpath already exists — both atomically, in one
// call.
//
// Windows spells this MoveFileEx *without* MOVEFILE_REPLACE_EXISTING. The
// no-replace behaviour is the default: MoveFileEx fails on an occupied
// destination unless that flag is passed. Which error it fails with is not
// documented, so it is measured rather than assumed — ERROR_ALREADY_EXISTS
// (183), and syscall.Errno.Is maps that to fs.ErrExist, which is exactly what
// writeFileNoClobber's tier-1 branch tests for. An existing *directory* at the
// destination is refused the same way -- also measured, not read: the
// documentation's only sentence about a directory destination sits inside the
// MOVEFILE_REPLACE_EXISTING row, a flag this call does not pass, and it names
// no error code. Measured on NTFS with MOVEFILE_WRITE_THROUGH alone, a free
// name succeeds and an existing file, an existing empty directory and an
// existing non-empty directory all fail with errno 183.
//
// This file exists because the fall-through it replaces was not equivalent
// here, on the filesystem it matters most on. atomicfile_other.go reasoned
// that Windows could publish by hard link instead, "which refuses an existing
// destination just as atomically, on every filesystem that has hard links at
// all, which is every filesystem these platforms normally use". That holds on
// NTFS and fails on exFAT — the format a cold-storage USB backup is most
// likely to carry. Measured on a real exFAT volume:
//
//	                     link (free / occupied)          exclusive rename
//	Windows NTFS         ok / EEXIST                     ok / EEXIST
//	Windows exFAT        ERROR_INVALID_FUNCTION / same   ok / EEXIST
//
// and ERROR_INVALID_FUNCTION is not fs.ErrExist, so on exFAT the tier-2
// branch did not short-circuit and control fell through to tier 3 — the
// check-then-rename whose refusal is explicitly not atomic. docs/WALLET.md
// said "no measured filesystem reaches that tier"; on Windows one did, and
// the measurements behind that sentence were taken on Linux and macOS.
//
// Verified the same way renameat2 and renamex_np were, on real volumes of
// both formats rather than reasoned about from documentation: publishing onto
// a free name succeeds and consumes the temporary name, an occupied
// destination is refused with fs.ErrExist and left byte-identical, and the
// source survives the refusal so writeFileNoClobber can still fall through.
// TestRenameNoReplaceIsAnExclusiveRename now builds here and asserts all of
// it; it deliberately does not skip on a platform that claims tier 1.
//
// Two flag decisions, and the reason for each, since a flag argument is where
// a wrong assumption hides best.
//
// MOVEFILE_WRITE_THROUGH is passed, and what it is worth here is stated
// exactly rather than generously. Microsoft documents it as: "The function
// does not return until the file is actually moved on the disk. Setting this
// value guarantees that a move performed as a copy and delete operation is
// flushed to disk before the function returns." The *explicit* guarantee in
// the second sentence is about the copy-and-delete case, which is not the case
// here — a publish onto a name in the same directory is a metadata rename —
// so on this path the flag rests on the first sentence alone. That is weaker
// than an fsync and is not a substitute for one. It is passed because it is
// the strongest ordering request this call accepts, and because there is
// nothing to fall back on: on unix the ordering comes from the syncDir after
// this publish, and on Windows a directory cannot be opened for fsync at all,
// so syncDir is a documented no-op (syncdir_windows.go) and the durability of
// the new directory entry rests on NTFS journaling its own metadata. It costs
// one already-durable temp file's metadata write.
//
// MOVEFILE_COPY_ALLOWED is deliberately *not* passed, and that is a guarantee
// rather than an omission. With it, a destination on another volume is
// simulated with CopyFile plus DeleteFile — which is not one atomic operation,
// and on which "refuses an existing destination atomically" would mean nothing.
// Without it such a move fails instead, so whatever this function returns nil
// for was a rename. writeFileNoClobber creates its temp file with os.CreateTemp
// in filepath.Dir(path), so the two names are always in one directory and the
// case never arises — but the flag's absence is what makes that a property of
// the code rather than of the caller.
//
// Any error other than fs.ErrExist still falls through to the lower tiers,
// unchanged: writeFileNoClobber classifies nothing, so a filesystem where
// MoveFileEx behaves in some way not measured here degrades exactly as it did
// before this file existed.
//
// Unlike its Linux and darwin siblings, which return a bare errno, this
// returns *os.LinkError — deliberately, and it changes nothing that matters.
// errors.Is still reaches fs.ErrExist through it (LinkError unwraps), which is
// the only property writeFileNoClobber tests. The wrapper is here because this
// function cannot be a one-liner anyway — MoveFileEx takes UTF-16 pointers, and
// the conversion has its own error to report — and because naming both paths is
// what os.Rename itself does for the same operation.
func renameNoReplace(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}
