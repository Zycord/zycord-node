package update

// guardOwnership has no meaning on Windows.
//
// os.Getuid returns -1 there and the ownership model is ACL-based, so there is
// no uid comparison to make. The writability probe in guard.go is what answers
// the same question on this platform, and it answers it better than any
// permission reading could: it performs the operation.
func guardOwnership(Target, string) *Refusal { return nil }

// guardDpkg has nothing to check on this platform.
func guardDpkg(Target, string) *Refusal { return nil }
