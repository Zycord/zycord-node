//go:build windows

package wallet

import (
	"os"

	"golang.org/x/sys/windows"
)

// openTempInodeForMarker opens path for reading and writing without blocking
// the publish that is about to rename it.
//
// This cannot be os.OpenFile here. Windows refuses a rename whose source has an
// open handle that did not grant FILE_SHARE_DELETE — MoveFileEx needs DELETE
// access on the source, and a handle without that share bit denies it — and
// os.OpenFile does not grant it: syscall.Open passes
// FILE_SHARE_READ|FILE_SHARE_WRITE and nothing else (go1.26,
// src/syscall/syscall_windows.go, the sharemode line; only the os.Root family
// in internal/syscall/windows adds FILE_SHARE_DELETE). A descriptor held across
// the publish for the marker check would therefore make tier 1 fail with
// ERROR_SHARING_VIOLATION and turn this suite red on the one platform it was
// written for. Note that writeFileNoClobber itself closes the temp file before
// publishing, so production never meets this.
//
// Granting the bit is the documented way to allow it, and it is what os.Root
// does for the same reason. That said: it has *not* been run on Windows — no
// machine was available — which is why nothing depends on it working.
// probePublishObservability measures whether a descriptor really does survive
// a rename here before any test holds one across a real publish, so if this
// open is wrong the marker channel simply reports unavailable and the test
// says so, rather than failing or, worse, passing on a broken publish.
func openTempInodeForMarker(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
