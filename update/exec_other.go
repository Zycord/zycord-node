//go:build !unix && !windows

package update

import "errors"

// Reexec is unavailable on a platform whose process model this package has not
// verified. replace_other.go refuses to get this far.
func Reexec(string, []string, []string) error {
	return errors.New("update: this platform has no verified restart path; start the new binary yourself")
}

const reexecReplacesTheProcess = false
