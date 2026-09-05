package storage

// crashClose drops the OS handles a dead process would drop: no sync, no
// truncation, no lock release, nothing written anywhere. It is the in-process
// stand-in for a SIGKILL, and every test that simulates a crash uses it.
//
// It exists as one function rather than as `s.log.Close()` written out fifteen
// times because a store now holds TWO files — the log and the commit sidecar
// — and the idiom's whole meaning is "this process stopped existing",
// which has to name every handle the process holds. Spelled by hand it named
// one: the sidecar's handle stayed open, and on Windows an open handle blocks
// the unlink, so t.TempDir's cleanup failed and took the test with it. The next
// file this store learns to hold will find one place to be added rather than
// fifteen places to be forgotten.
func (s *Store) crashClose() {
	if s.log != nil {
		s.log.Close()
	}
	if s.commits != nil {
		s.commits.Close()
	}
}
