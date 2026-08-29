package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// lockFileName is the advisory-lock file kept inside every store directory.
const lockFileName = "LOCK"

// ErrLocked is returned by Open when another process already holds the
// datadir's lock.
var ErrLocked = errors.New("storage: datadir is locked by another process")

// dirLock is the datadir's exclusivity guard, held for the lifetime of a
// Store and released by Close.
//
// Two zycordd processes pointed at the same -dir would otherwise each load
// the same snapshot and log into an independent in-memory view and both
// append to the same file with no coordination at all. That is not
// merely two writers racing for the same offset: O_APPEND makes each
// individual write(2) atomic only up to PIPE_BUF, and a block record is
// routinely megabytes, so the appends themselves can physically interleave
// and tear a record apart, not just logically disagree about what the chain
// looks like.
//
// This takes flock, not a PID file, and that is a deliberate choice, not the
// first thing that worked:
//
//   - A PID file records who *opened* the directory. It says nothing about
//     who still holds it after a SIGKILL, because nothing removes it when the
//     process dies uncleanly -- which is the ordinary case this whole package
//     is built to survive (see torture_test.go and process_test.go). Telling
//     "the owner is dead" from "the owner is alive but slow" then needs a
//     liveness check, which is itself racy and platform-specific (PIDs
//     recycle; querying a PID on another container or another machine that
//     happens to share the datadir over NFS is not even meaningful).
//   - flock's lock lives on the *open file description* in the kernel, not on
//     bytes in the file and not on the process's bookkeeping. The kernel
//     releases it the instant every descriptor referring to that open is
//     closed, which includes a process dying for any reason -- including the
//     SIGKILLs this package's own tests inject. There is nothing to clean up
//     and nothing that can go stale.
//
// One limit is worth stating rather than leaving to be discovered, since the
// comment above already reasons about NFS for the mechanism it rejected:
// flock's guarantee is the kernel's, and on a datadir shared over NFS it may
// not reach the other host. Linux maps flock() to a whole-file POSIX lock on
// NFSv3 only when the mount and the server's lock manager (lockd/rpc.statd)
// cooperate, and NFSv3 mounts with -o nolock — or an NFS server without a
// working lock manager — degrade it to a purely local lock, where two hosts
// both "acquire" the same datadir and neither is told. There is no advisory
// primitive that fixes this from inside the process; a network filesystem
// that does not implement locking cannot be made to. A datadir is a local
// directory, and this is the reason it has to be.
//
// bbolt takes the same position: it flocks its data file directly for the life
// of the DB handle (bbolt/db.go, the flock call inside Open). LevelDB and
// RocksDB instead lock a dedicated LOCK file, but with fcntl(F_SETLK) rather
// than flock -- and the LevelDB source notes the price of that choice in a
// comment on its PosixLockTable: fcntl locks are scoped to the *process*, not
// the open file description, so a second open of the same file from the same
// process would not conflict with the first, and LevelDB has to keep its own
// in-process registry of locked paths to compensate (google/leveldb,
// util/env_posix.cc, and LevelDB's own issue tracker on the same point). flock
// has no such gap -- two independent opens in one process really do conflict,
// which is the simpler and more obviously correct semantics for "one Store, one
// lock" -- so this package follows bbolt's choice of primitive, while still
// using a separate LOCK file rather than locking the log directly, so a reader
// never has to reason about lock bytes mixed into data it replays.
func acquireDirLock(dir string) (*dirLock, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := tryFlock(f); err != nil {
		f.Close()
		if errors.Is(err, errLockHeld) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, dir)
		}
		return nil, err
	}

	// Best-effort and purely diagnostic: identifies who holds the lock to a
	// human running `cat LOCK`. Not load-bearing -- the lock itself is the
	// flock taken above, not this content, so a failure here does not affect
	// correctness and is not worth failing Open over.
	if err := f.Truncate(0); err == nil {
		fmt.Fprintf(f, "%d\n", os.Getpid())
		f.Sync()
	}

	return &dirLock{f: f}, nil
}

func (l *dirLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	unlockErr := unlockFile(l.f)
	closeErr := l.f.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
