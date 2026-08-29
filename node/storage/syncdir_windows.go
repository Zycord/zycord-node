package storage

import (
	"errors"
	"io/fs"
	"syscall"
)

// isUnsupportedDirSync reports whether err means "this platform cannot fsync a
// directory", which on Windows includes a permission error, for a reason that
// is structural rather than environmental.
//
// Go's os.File.Sync reaches syscall.Fsync, and on Windows that is
// FlushFileBuffers, which is documented to require the handle to carry
// GENERIC_WRITE. syncDir obtains its handle from os.Open — read-only, so
// GENERIC_READ — and the standard library offers no way to open a *directory*
// for writing (a directory handle needs FILE_FLAG_BACKUP_SEMANTICS, which
// os.OpenFile only applies on the read path). So the call returns
// ERROR_ACCESS_DENIED, and syscall.Errno.Is maps that to fs.ErrPermission and
// deliberately not to errors.ErrUnsupported — so the unix classification below
// would let it through as a real I/O failure.
//
// The consequence of not classifying it is not a lost fsync but a node that
// cannot run: syncDir sits on Open's fresh-datadir path, on replayLog's
// torn-tail repair, and inside compactLocked, so a Windows node would fail to
// start on a new directory and fail to reopen after an ordinary crash. That is
// exactly the "platforms where opening a directory for sync is not supported"
// case syncDir's own doc comment already reserves — Windows simply reports it
// as a permission error rather than as ENOTSUP.
//
// What this costs is stated rather than glossed: on Windows the ordering
// syncDir exists to enforce (a rename or a truncate reaching stable storage
// before the log is destroyed) rests on NTFS journaling its own metadata
// operations rather than on a barrier this package issued. That is weaker than
// the unix path. It is not a choice between the two — there is no directory
// fsync on Windows to prefer.
//
// This function used to close by saying "and CI is ubuntu-only, so this
// platform is built and not exercised", which was true when it was written and
// is not any more: the `windows` job in .github/workflows/ci.yml runs the whole
// suite on windows/amd64, and node/storage is one of the packages that was
// failing there when it was added — not here, but one line away, in
// compactLocked's truncate (truncate_windows.go).
func isUnsupportedDirSync(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, fs.ErrPermission)
}
