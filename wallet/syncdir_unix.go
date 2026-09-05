//go:build unix

package wallet

import (
	"errors"
	"syscall"
)

// isUnsupportedDirSync reports whether err is specifically "this platform or
// filesystem does not support fsync on a directory at all" — ENOTSUP (the
// operation is not supported) or EINVAL (what some filesystems return for the
// same condition instead) — and nothing broader. Neither means the sync
// silently failed; both mean there was never anything to sync in the first
// place, so treating them as success does not weaken the durability guarantee
// syncDir exists to provide.
//
// Everything else — EIO, ENOSPC — propagates. This is the same classification
// node/storage/syncdir_unix.go makes for the same reason, and it is mirrored
// rather than shared for the reason writeFileNoClobber's doc comment gives
// about the sequence it copies: core/ and node/ are third-party-free and the
// wallet is not, so the two trees do not import each other.
func isUnsupportedDirSync(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EINVAL)
}
