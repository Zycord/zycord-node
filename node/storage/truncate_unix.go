//go:build unix

package storage

import "os"

// truncateOpenLog shortens the store's own append handle to size.
//
// On unix the handle can do it itself: O_APPEND affects where writes land, not
// what the descriptor is allowed to do, so ftruncate(2) on it is exactly the
// one atomic metadata operation compactLocked's comment relies on.
func truncateOpenLog(f *os.File, size int64) error {
	return f.Truncate(size)
}
