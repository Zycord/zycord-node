//go:build !unix && !windows

package update

// guardOwnership is unimplemented on platforms that are neither, so it defers to
// the writability probe rather than claiming a check it did not make.
func guardOwnership(Target, string) *Refusal { return nil }

// guardDpkg has nothing to check on this platform.
func guardDpkg(Target, string) *Refusal { return nil }
