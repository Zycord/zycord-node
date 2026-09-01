//go:build !unix && !windows

package update

import (
	"errors"
	"path/filepath"
)

func backupName(dir, name string) string { return filepath.Join(dir, "."+name+".old") }

// replaceBinary refuses rather than guessing.
//
// The Unix and Windows paths each depend on a specific, verified property of
// their filesystem semantics — that a running image can be renamed over, or
// renamed aside. A platform that is neither has not been checked for either, and
// an updater that assumed one would be betting an operator's only binary on it.
func replaceBinary(string, string) (string, error) {
	return "", errors.New("update: this platform has no verified in-place replace path; update by hand")
}

func restoreBinary(string) error {
	return errors.New("update: this platform has no verified in-place replace path")
}
