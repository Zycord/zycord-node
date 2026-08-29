//go:build windows

package storage

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// dirLock holds the open lock file. The lock lives against this handle in
// the kernel; closing it (in release) is what lets it go.
type dirLock struct {
	f *os.File
}

// errLockHeld is a package-local sentinel distinguishing "someone else holds
// the lock" from any other failure to lock, which acquireDirLock maps to the
// exported ErrLocked with the directory name attached.
var errLockHeld = errors.New("storage: lock held")

// Windows has no equivalent to POSIX flock in the standard syscall package
// (unlike unix builds, which call syscall.Flock directly), so this calls
// LockFileEx/UnlockFileEx in kernel32.dll directly through syscall.NewLazyDLL
// -- part of the standard library on windows, not a third-party dependency,
// which node/ is not permitted to carry (see go.mod and `make
// check-imports`). This is the same primitive golang.org/x/sys/windows wraps;
// calling it directly avoids the dependency for one function.
var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const (
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001

	// errorLockViolation is Win32 error 33 (ERROR_LOCK_VIOLATION): the region
	// is already locked by another handle. Not exported by the standard
	// syscall package on windows, so named here from the stable Win32 error
	// code rather than pulled in from a dependency.
	errorLockViolation = syscall.Errno(33)
)

// overlapped mirrors the Win32 OVERLAPPED struct. LockFileEx/UnlockFileEx
// require one even for a whole-file lock at offset 0.
type overlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       syscall.Handle
}

// tryFlock takes a non-blocking exclusive lock on the whole file. Non-
// blocking is the point: Open must fail fast and say so, not hang the node
// waiting for a lock a human needs to notice is contended.
func tryFlock(f *os.File) error {
	var ol overlapped
	r1, _, e1 := procLockFileEx.Call(
		uintptr(f.Fd()),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,    // reserved, must be zero
		1, 0, // lock the first byte; that is enough to exclude a second opener
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		if e1 == errorLockViolation {
			return errLockHeld
		}
		return e1
	}
	return nil
}

func unlockFile(f *os.File) error {
	var ol overlapped
	r1, _, e1 := procUnlockFileEx.Call(
		uintptr(f.Fd()),
		0,
		1, 0,
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}
