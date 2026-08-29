package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The datadir-lock suite.
//
// Two zycordd processes pointed at the same -dir used to be free to both
// load the same snapshot and log into independent in-memory views and both
// append to the same file with no coordination at all. Open now takes an
// advisory, exclusive, non-blocking lock on a LOCK file inside the directory
// (see lock.go for why flock rather than a PID file) and refuses to open a
// directory another live holder has locked.
//
// The cross-process half of this — proving the lock is actually released
// when the holder is killed rather than closed cleanly, which is the whole
// argument for flock over a PID file — lives in process_test.go next to the
// other test that proves the operating system agrees with the in-process
// fault injection.

// TestSecondOpenOnSameDirIsRefused is the fast, single-process case: flock
// locks are scoped to the open file description, not the process, so a
// second Open from the *same* process must conflict with the first exactly
// as it would from a different one.
func TestSecondOpenOnSameDirIsRefused(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v, want ErrLocked while the first handle is still open", err)
	}

	// The directory must otherwise be untouched by the refused Open: no
	// partial state, no half-initialised second store to worry about cleaning
	// up.
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	defer s2.Close()
}

// TestLockIsPerDirectory: two different directories must never contend with
// each other -- the lock is scoped to the datadir, not process-global.
func TestLockIsPerDirectory(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	sa, err := Open(dirA, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()

	sb, err := Open(dirB, Options{})
	if err != nil {
		t.Fatalf("a lock on %s should not block opening %s: %v", dirA, dirB, err)
	}
	defer sb.Close()
}

// TestFailedOpenDoesNotLeakTheLock: if Open fails after acquiring the lock
// (a corrupt snapshot, say), the lock must not be left held -- otherwise a
// single bad Open would wedge every future Open against that directory,
// including one meant to fix the corruption.
func TestFailedOpenDoesNotLeakTheLock(t *testing.T) {
	dir := t.TempDir()

	// Produce a directory whose snapshot fails to decode, so Open fails after
	// acquireDirLock has already succeeded.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, snapshotName), []byte("not a snapshot"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); err == nil {
		t.Fatal("setup: expected the corrupt snapshot to fail Open")
	}

	// The lock must have been released on that failure path: a second Open
	// (still against the same corrupt snapshot, so it fails too, but for the
	// *right* reason) must not additionally report ErrLocked.
	if _, err := Open(dir, Options{}); errors.Is(err, ErrLocked) {
		t.Fatal("a failed Open leaked the datadir lock")
	}
}
