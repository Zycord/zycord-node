//go:build race || zcdguard

package chain

import (
	"fmt"
	"runtime"
	"sync"
)

// The guarded build (R5-G2).
//
// Built when the race detector is on, or explicitly with `-tags zcdguard`.
// Both exist for a reason. `-race` is what CI runs; `zcdguard` is what the
// multi-hour chaos soak builds its binaries with, because `-race` slows a node
// enough to change the timing of a soak that is measuring timing. A guard that
// is only armed under `-race` would be disarmed in the one run long enough to
// find something — which is this milestone's own lesson, applied to the fix for
// this milestone's own bug.
//
// Nothing here runs in a shipped binary.
const guardEnabled = true

// ReentrancyGuardEnabled reports whether the *reentrancy* check is compiled in.
//
// Named precisely rather than "the guard": the borrow-lifetime check (rule 1) is
// always on, in every build. Only this one is optional, because only this one is
// expensive. A node logs it at startup so a run that believes it is guarded can
// be checked rather than assumed — a build tag is one typo away from silently
// disarming every check that depends on it.
const ReentrancyGuardEnabled = true

// ---------------------------------------------------------------------------
// Rule 2 — a Read callback must not re-enter the chain.
// ---------------------------------------------------------------------------
//
// This is detected rather than left to deadlock, and the reason is that the two
// reentrant shapes fail *differently* and the quiet one is the dangerous one.
// Measured against Go's sync.RWMutex:
//
//	RLock -> Lock  (Read then Apply)        always blocks
//	RLock -> RLock (Read then Read), idle    SUCCEEDS
//	RLock -> RLock (Read then Read), writer waiting   blocks
//
// So a nested Read works in a quiet test suite and deadlocks in production
// under write pressure, which is precisely the class of bug this project keeps
// finding: correct-looking, load-dependent, and invisible to the tests that
// exist. Waiting for the deadlock would catch it only on the day it matters.
//
// Detection therefore happens *before* the lock is taken, so the failure is a
// located panic with the offending Read frame still on the stack, rather than a
// process that stops responding.

// readHeld tracks which chains a goroutine currently holds a Read on.
//
// Keyed by the pair, not by the goroutine, because an in-process test can run
// several Chains at once and `chainA.Read(func(){ chainB.Apply(...) })` is not
// reentrancy — the mutexes are different and nothing deadlocks. Keying by
// goroutine alone would panic on it, and a guard with false positives is a guard
// somebody switches off.
//
// (Two chains nested in *opposite* orders on two goroutines would be a genuine
// ABBA deadlock. That is out of scope here and cannot arise in a node, which has
// exactly one chain; the lock order that can arise — chain then mempool — is
// held by an import rule in `make check-imports` instead.)
//
// A sync.Map rather than a mutex-guarded map on purpose: a lock here would
// serialise every read in the guarded build, and a guarded build whose
// concurrency is different from the real one is measuring something else.
type readKey struct {
	gid   uint64
	chain *Chain
}

var readHeld sync.Map // readKey -> struct{}

// goroutineID reads the current goroutine's id out of its stack header.
//
// This is the only way to get goroutine identity in Go without unsafe access to
// runtime internals, and it costs roughly three microseconds. That is far too
// expensive for a shipped binary and entirely irrelevant in a guarded one, where
// reads happen tens of times a second. It is confined to this file so that the
// shipped build cannot pay for it even by accident.
// It returns 0 if the header cannot be parsed, and every caller treats 0 as
// "unknown" and skips the check. **A tripwire must fail open.** If parsing broke
// — a future Go changes the header format, say — returning 0 for everybody would
// make all goroutines collide on one key, and the guard would panic on perfectly
// correct concurrent code. A guard that fails closed on its own malfunction gets
// switched off, and then it is protecting nothing at all.
func goroutineID() uint64 {
	var buf [40]byte
	n := runtime.Stack(buf[:], false)
	const prefix = len("goroutine ")
	if n <= prefix {
		return 0
	}
	var id uint64
	var digits int
	for i := prefix; i < n; i++ {
		c := buf[i]
		if c < '0' || c > '9' {
			break
		}
		id = id*10 + uint64(c-'0')
		digits++
	}
	if digits == 0 {
		return 0
	}
	return id
}

func (c *Chain) enterRead() {
	if gid := goroutineID(); gid != 0 {
		readHeld.Store(readKey{gid, c}, struct{}{})
	}
}

func (c *Chain) exitRead() {
	if gid := goroutineID(); gid != 0 {
		readHeld.Delete(readKey{gid, c})
	}
}

// assertNotInRead panics if this goroutine is inside a Read on THIS chain.
func (c *Chain) assertNotInRead(op string) {
	gid := goroutineID()
	if gid == 0 {
		return // identity unavailable; fail open rather than accuse
	}
	if _, held := readHeld.Load(readKey{gid, c}); held {
		panic(fmt.Sprintf("chain: %s was called from inside a Read callback on the "+
			"same chain. The lock is not reentrant, so this either deadlocks now "+
			"(a write) or deadlocks later under write pressure (a nested read, "+
			"which succeeds quietly until a writer queues up behind it). Take what "+
			"you need from the View, or use Chain.Snapshot outside the callback.", op))
	}
}
