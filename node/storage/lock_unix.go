//go:build unix

package storage

import (
	"errors"
	"os"
	"syscall"
)

// dirLock holds the open lock file. The flock itself lives in the kernel
// against this file descriptor; closing it (in release) is what lets it go.
type dirLock struct {
	f *os.File
}

// errLockHeld is a package-local sentinel distinguishing "someone else holds
// the lock" from any other failure to lock (a real I/O error, permissions,
// ...), which acquireDirLock maps to the exported ErrLocked with the
// directory name attached.
var errLockHeld = errors.New("storage: lock held")

// tryFlock takes a non-blocking exclusive lock. Non-blocking is the point:
// Open must fail fast and say so, not hang the node waiting for a lock a
// human needs to notice is contended.
func tryFlock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return errLockHeld
		}
		return err
	}
	return nil
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
