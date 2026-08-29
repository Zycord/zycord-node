//go:build unix

package storage

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
// Everything else — EIO, ENOSPC — propagates, which is the whole point: a
// discarded fsync error is a rename reported durable when it is not, and the
// previous version returned nil for every Sync failure alike.
func isUnsupportedDirSync(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EINVAL)
}
