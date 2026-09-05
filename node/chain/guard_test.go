package chain_test

import (
	"strings"
	"testing"

	"zycord/core/types"
	"zycord/node/chain"
)

// Rule 1 — a borrowed StateRef must not outlive its callback (R5-G2).
//
// These tests exist because of the milestone's own lesson. A mechanism that
// enforces a rule is worth exactly as much as the evidence that it *fails* when
// the rule is broken — and every instrument this project has trusted without
// that evidence turned out to be measuring nothing. So the rule is deliberately
// violated here in each of the shapes a reviewer would plausibly miss, and the
// panic is asserted including its wording, because a panic from somewhere else
// would pass a test that only checked "it panicked".
//
// **These carry no build tag**, because rule 1 carries none: the check is
// compiled into every binary, including the shipped one. Reentrancy — rule 2 —
// is the expensive half and its tests are in guard_reentrancy_test.go.

// mustPanic runs fn and returns the panic message, failing if it did not panic.
func mustPanic(t *testing.T, what string, fn func()) string {
	t.Helper()
	var msg string
	func() {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			if s, ok := r.(string); ok {
				msg = s
				return
			}
			if err, ok := r.(error); ok {
				msg = err.Error()
			}
		}()
		fn()
	}()
	if msg == "" {
		t.Fatalf("%s did not panic; the guard is not enforcing this rule", what)
	}
	return msg
}

// TestBorrowedStateIsInvalidAfterTheCallback is rule 1, the one whose violation
// re-creates I4-H1.
func TestBorrowedStateIsInvalidAfterTheCallback(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)
	n.mine(t, 1)

	// The escape a reviewer is most likely to miss: assignment to an outer
	// variable. It looks like nothing.
	var escaped chain.StateRef
	n.chain.Read(func(v chain.View) { escaped = v.State })

	msg := mustPanic(t, "using a borrowed StateRef after its callback returned", func() {
		_ = escaped.Get(types.SeqBaseFeeSlot())
	})
	if !strings.Contains(msg, "after its Read callback returned") {
		t.Fatalf("panicked for the wrong reason: %s", msg)
	}
}

// TestBorrowedStateEscapingThroughAStructIsCaught: copying the reference into a
// field does not shed the guard, because StateRef is a value type carrying it.
func TestBorrowedStateEscapingThroughAStructIsCaught(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)
	n.mine(t, 1)

	type holder struct{ st chain.StateRef }
	var h holder
	n.chain.Read(func(v chain.View) { h = holder{st: v.State} })

	mustPanic(t, "using a StateRef stored in a struct field", func() {
		_ = h.st.IsSpent(types.Address{})
	})
}

// TestBorrowedStateEscapingIntoAGoroutineIsCaught: the shape that would look
// most innocent in review and is the closest to the original bug — a goroutine
// started inside the callback, reading state after the lock is gone.
func TestBorrowedStateEscapingIntoAGoroutineIsCaught(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)
	n.mine(t, 1)

	var ref chain.StateRef
	n.chain.Read(func(v chain.View) { ref = v.State })

	done := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- "panicked"
				return
			}
			done <- "did not panic"
		}()
		_ = ref.Root()
	}()
	if got := <-done; got != "panicked" {
		t.Fatal("a StateRef read from another goroutine after the callback returned " +
			"was not caught; this is the shape of the original data race")
	}
}

// TestReadIsUsableAgainAfterTheCallback: the depth counter must come back down.
// A guard that latched on would make every later read panic, which would pass
// every test above while breaking the node entirely.
func TestReadIsUsableAgainAfterTheCallback(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)

	for i := 0; i < 3; i++ {
		n.chain.Read(func(v chain.View) { _ = v.State.Get(types.SeqBaseFeeSlot()) })
	}
	// And a write after a read must still work.
	if _ = n.chain.Height(); n.chain.Height() != 0 {
		t.Fatal("height changed unexpectedly")
	}
	n.mine(t, 1)
}

// TestOwnedSnapshotStateSurvivesTheCall is the anti-vacuity guard on this whole
// file.
//
// Every test above asserts that something panics. If the guard were simply
// panicking on all state access they would all pass while the mechanism was
// useless. Snapshot hands out *owned* state, and using it long after the call is
// the entire point of that method — so it must NOT panic, and the tests above
// only mean something because this one holds.
func TestOwnedSnapshotStateSurvivesTheCall(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)
	n.mine(t, 2)

	snap := n.chain.Snapshot()

	// Mutate the chain underneath it. An owned snapshot is a copy, so this must
	// change nothing about what the snapshot reads.
	rootAtSnapshot := snap.State.Root()
	n.mine(t, 2)

	if got := snap.State.Root(); got != rootAtSnapshot {
		t.Fatal("an owned snapshot changed when the chain advanced; it is not detached")
	}
	if snap.State.Root() == n.chain.StateRoot() {
		t.Fatal("the chain did not advance, so this test proves nothing about detachment")
	}
	if snap.Height != 2 {
		t.Fatalf("snapshot height is %d, want the height at the time it was taken", snap.Height)
	}
}

// TestBorrowedStateReadAcrossTheCallbackReturnIsCaught is the narrow window that
// a check-before-use guard has, and it was found by attacking this guard rather
// than by writing it.
//
// A check and the read that follows it are two steps. A goroutine started inside
// the callback can pass the check while the callback is still on the stack, and
// then perform the actual map walk after the callback has returned and the lock
// is gone. Checking only beforehand misses that completely: driven 200 times
// against the first version of this guard, it fired **zero** times — and `-race`
// reported nothing either, because a data race is only reported when a writer
// happens to write.
//
// `stillValid` re-checks after the read and closes it for detection. The read
// cannot be prevented — nothing at this layer can do that without holding the
// lock, which is the thing the callback exists to bound — but a value that may
// have come from memory another goroutine was writing is refused rather than
// returned.
//
// Not every trial panics, and that is correct rather than a weakness: a read
// that both begins and ends before the callback returns happened entirely under
// the read lock and is legitimate. Those are the survivors. What the assertion
// pins is that reads spanning the return are caught **at all**, which is exactly
// what was untrue before.
func TestBorrowedStateReadAcrossTheCallbackReturnIsCaught(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)
	n.mine(t, 4)

	const trials = 200
	// See the loop below: enough reads to span the callback's return many times
	// over, few enough that a guard which never fires ends the test instead of
	// stalling it.
	const spinLimit = 1_000_000
	var caught, completedInTime int
	for i := 0; i < trials; i++ {
		ready := make(chan struct{})
		done := make(chan string, 1)
		n.chain.Read(func(v chain.View) {
			ref := v.State
			go func() {
				defer func() {
					msg, _ := recover().(string)
					done <- msg
				}()
				close(ready)
				// The check runs here, with the callback still on the stack, so
				// the borrow is live. What follows races the callback's return.
				//
				// This is a loop rather than a single read because the window a
				// single read leaves is a property of how long that read takes,
				// and the incremental state root made Root() short: with the
				// root cached, one call is a few nanoseconds and the return
				// essentially never lands inside it. The loop keeps a read in
				// flight continuously instead, so the moment of invalidation
				// falls inside one. The guard being tested is unchanged; only
				// the odds of arming it were, and a scenario that cannot arm
				// the mechanism it names is the vacuity this file exists to
				// avoid.
				//
				// Bounded, because an unbounded spin here fails the wrong way.
				// The loop's only exit is a panic, so a future change that
				// weakened `check` as well as `stillValid` would hang CI
				// instead of failing it — and a test that hangs is read as
				// infrastructure trouble, which is how a real regression gets
				// waited out rather than looked at. The bound costs nothing:
				// the callback returns microseconds after `ready` closes, and
				// spinLimit at ~117 ns a call is ~0.1 s of continuous reading,
				// three orders of magnitude more window than is needed.
				for k := 0; k < spinLimit; k++ {
					_ = ref.Root()
				}
			}()
			<-ready
		})
		// Which guard fired matters. check() firing means the read began after
		// the callback returned — a real catch, but of the easy case, and
		// counting it here would let this test pass with stillValid deleted.
		// Only the "across" message is evidence for the property claimed.
		switch msg := <-done; {
		case strings.Contains(msg, "read *across* the return"):
			caught++
		default:
			completedInTime++
		}
	}

	t.Logf("reads racing the callback's return: %d caught by stillValid, %d not "+
		"(the read finished under the lock, or began after it and check fired)",
		caught, completedInTime)

	if caught == 0 {
		t.Fatalf("not one of %d reads spanning the callback's return was caught. "+
			"The guard checks before the read and not after, so a borrowed "+
			"reference can be used across the moment the lock is released and "+
			"return a value nobody can account for.", trials)
	}
}
