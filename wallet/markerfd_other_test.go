//go:build !windows

package wallet

import "os"

// openTempInodeForMarker opens path for reading and writing, in a way that
// leaves the publish about to happen to it undisturbed. On unix that is an
// ordinary open: a descriptor names the inode, a rename moves only the name,
// and neither interferes with the other. See probePublishObservability for the
// Windows half of this, which is not ordinary at all.
func openTempInodeForMarker(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}
