package update

// syncDir is a no-op on Windows.
//
// There is no handle to a directory that can be flushed the way fsync(2) flushes
// one: opening a directory for the purpose is not something the API offers, and
// FlushFileBuffers wants a file handle. The durability of the new directory
// entry rests on NTFS's own metadata journal instead. wallet/syncdir_windows.go
// records the same thing about the same problem, and this mirrors it rather than
// pretending to a guarantee the platform does not give.
func syncDir(string) error { return nil }
