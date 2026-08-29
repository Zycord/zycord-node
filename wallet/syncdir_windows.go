package wallet

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
// deliberately not to errors.ErrUnsupported — so the unix classification would
// let it through as a real I/O failure.
//
// The consequence of not classifying it is not a lost fsync but a wallet that
// cannot save a key: syncDir is the last step of every tier of
// writeFileNoClobber's publish, so `zcd key new`, `zcd ui` and the desktop
// wallet would each write the encrypted seed, publish it correctly, and then
// report failure — on Windows, always. That is exactly the "platforms where a
// directory cannot be opened for fsync at all" case syncDir's own doc comment
// already reserves; Windows simply reports it as a permission error rather
// than as ENOTSUP.
//
// What this costs is stated rather than glossed, in the same terms
// node/storage/syncdir_windows.go states it: on Windows the ordering syncDir
// exists to enforce (the new directory entry reaching stable storage, not just
// the bytes behind it) rests on NTFS journaling its own metadata operations
// rather than on a barrier this package issued. That is weaker than the unix
// path. It is not a choice between the two — there is no directory fsync on
// Windows to prefer.
//
// Note that this is *not* the FAT32/exFAT row of writeFileNoClobber's table:
// there fsync(dir) was measured working, because that measurement was taken on
// Linux and macOS, where a directory can be opened for sync at all. A FAT32
// USB stick read on Windows lands here for the platform's reason, not the
// filesystem's.
func isUnsupportedDirSync(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, fs.ErrPermission)
}
