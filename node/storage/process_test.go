package storage_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"zycord/node/storage"
)

// The kill-9 torture test (M1-G1).
//
// The deterministic fault injection in torture_test.go proves the *recovery
// logic* at every byte offset. This proves something else and equally
// necessary: that the operating system agrees. It re-executes the test binary
// as a child, lets it commit in a tight loop, kills it with SIGKILL at an
// arbitrary moment, and then demands that whatever is on disk is a state the
// writer could actually have been in.
//
// The child writes generation-numbered values across several keys plus a
// height. A store that committed non-atomically would leave keys from two
// generations side by side; that is the thing being ruled out.

const (
	childEnv     = "ZCD_STORAGE_TORTURE_DIR"
	lockChildEnv = "ZCD_STORAGE_LOCK_TORTURE_DIR"
	torturedKeys = 12
)

// TestMain lets the test binary act as its own crash victim.
func TestMain(m *testing.M) {
	if dir := os.Getenv(childEnv); dir != "" {
		runChild(dir)
		return
	}
	if dir := os.Getenv(lockChildEnv); dir != "" {
		runLockChild(dir)
		return
	}
	os.Exit(m.Run())
}

// runChild commits forever until it is killed. It never exits cleanly, and it
// never gets the chance to close the store.
func runChild(dir string) {
	s, err := storage.Open(dir, storage.Options{CompactAfterBytes: 4096})
	if err != nil {
		fmt.Fprintln(os.Stderr, "child open:", err)
		os.Exit(1)
	}
	for gen := 0; ; gen++ {
		b := &storage.Batch{}
		for i := 0; i < torturedKeys; i++ {
			b.Put([]byte(fmt.Sprintf("key-%02d", i)), []byte(strconv.Itoa(gen)))
		}
		b.Put([]byte("height"), []byte(strconv.Itoa(gen)))
		if err := s.Commit(b); err != nil {
			fmt.Fprintln(os.Stderr, "child commit:", err)
			os.Exit(1)
		}
	}
}

// runLockChild opens the store, signals readiness by dropping a marker file
// next to the datadir, and then holds the lock until killed. It never exits
// cleanly and never gets the chance to release the lock through Close.
func runLockChild(dir string) {
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "lock child open:", err)
		os.Exit(1)
	}
	defer s.Close() // unreached when killed; here for the rare clean-exit path
	if err := os.WriteFile(dir+".ready", []byte("ready\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "lock child ready marker:", err)
		os.Exit(1)
	}
	// Hold the lock until SIGKILL. Not select{}: with a single goroutine and
	// nothing else runnable, Go's own deadlock detector treats that as a
	// program error and aborts the process on its own, releasing the lock
	// before the parent ever gets to test that a live holder blocks it.
	for {
		time.Sleep(time.Hour)
	}
}

// TestDatadirLockIsReleasedWhenTheHolderDies is the datadir lock's
// cross-process half.
//
// The in-process suite in lock_test.go proves a second Open is refused while
// a handle is open; the harder claim, and the entire argument for using
// flock rather than a PID file (see the comment on acquireDirLock in
// lock.go), is that the lock does not outlive the process that held it —
// including when that process never gets to run a single deferred Close,
// which is what SIGKILL guarantees and what this test forces.
func TestDatadirLockIsReleasedWhenTheHolderDies(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a child process")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "store")
	readyPath := dir + ".ready"

	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), lockChildEnv+"="+dir)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Safety net: if the test fails before the explicit kill below, do not
	// leave a hung child behind.
	defer cmd.Process.Kill()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the lock-holding child never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The child holds the lock: a competing Open must be refused immediately
	// (LOCK_NB is the whole point -- a node must never hang at startup
	// waiting for a lock a human needs to notice is contended), not just
	// eventually.
	if _, err := storage.Open(dir, storage.Options{}); !errors.Is(err, storage.ErrLocked) {
		t.Fatalf("got %v, want ErrLocked while another process holds the datadir", err)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	// The kernel released the flock the instant the process died, with no
	// stale file to clean up and no liveness check to get wrong.
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatalf("reopen after the lock holder was killed: %v", err)
	}
	defer s.Close()
}

func TestSurvivesSigkillDuringCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	// Vary the kill delay so the signal lands at different points in the commit
	// cycle across rounds, including during compaction.
	for round := 0; round < 12; round++ {
		t.Run(fmt.Sprintf("round=%d", round), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")

			cmd := exec.Command(exe)
			cmd.Env = append(os.Environ(), childEnv+"="+dir)
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}

			delay := time.Duration(3+round*4) * time.Millisecond
			time.Sleep(delay)
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()

			// Whatever is on disk must be a state the writer was actually in.
			s, err := storage.Open(dir, storage.Options{})
			if err != nil {
				t.Fatalf("a SIGKILL left the store unopenable: %v", err)
			}
			defer s.Close()

			height, ok := s.Get([]byte("height"))
			if !ok {
				// Killed before the first commit reached disk: legitimate.
				return
			}
			for i := 0; i < torturedKeys; i++ {
				v, ok := s.Get([]byte(fmt.Sprintf("key-%02d", i)))
				if !ok {
					t.Fatalf("key-%02d is missing at height %s", i, height)
				}
				if string(v) != string(height) {
					t.Fatalf("SIGKILL left key-%02d at generation %s while the height "+
						"says %s: a batch was applied in part", i, v, height)
				}
			}

			// And the store must still accept writes after recovery.
			b := &storage.Batch{}
			b.Put([]byte("after-recovery"), []byte("ok"))
			if err := s.Commit(b); err != nil {
				t.Fatalf("the store is unusable after recovery: %v", err)
			}
		})
	}
}
