//go:build !unix && !windows

package update

// syncDir is a no-op on a platform this package has not verified.
//
// It sits beside guard_other.go and replace_other.go, which refuse to replace a
// binary at all on such a platform — so nothing here is relied on for
// durability. It exists so the package still compiles and its pure logic
// (manifest, version, tier) can be built and tested anywhere.
func syncDir(string) error { return nil }
