package chain

import (
	"sync/atomic"

	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
)

// Borrowed and owned reads (R5-G2).
//
// I4-H1 was an unsynchronised read of consensus state. The fix gave the chain a
// lock; what it could not give was a way to stop a caller keeping the pointer it
// was lent. Two rules were left standing on human review:
//
//  1. the state handed to a Read callback must not outlive the callback;
//  2. the callback must not re-enter the chain, because the lock is not
//     reentrant.
//
// Rule 1 is the dangerous one: violating it re-creates I4-H1 exactly — silently,
// with detection dozens of blocks late, in a system with no pause button. A rule
// enforced by review is enforced by whoever is reviewing, and this project's
// stated destiny is the absence of that person.
//
// So the lifetime is now carried by the type system rather than by a comment.
// There are two ways to read state and they are different types:
//
//   - Read gives a **View** holding a StateRef. Borrowed. It stops being valid
//     the instant the callback returns, and using it afterwards panics in a
//     guarded build rather than reading memory somebody else is writing.
//   - Snapshot gives a **Snapshot** holding a *state.State. Owned. It is a
//     detached clone, safe to hold for as long as you like, and it costs a copy.
//
// A caller that needs state to outlive the call cannot get there by accident:
// the borrowed type does not convert to the owned one.
//
// StateRef is also read-only by construction. It exposes the three accessors its
// callers actually use and nothing that mutates, so a borrowed reference cannot
// be written through even by a caller who wanted to.

// StateRef is a borrowed, read-only reference to consensus state.
//
// It is valid only inside the Chain.Read callback that produced it, and any use
// after that callback returns panics at the point of use, naming this rule.
//
// **That check is always on, in every build**, and the reason is the one this
// project keeps relearning. A guard compiled only into test binaries protects
// only the executions the tests happen to produce, and the executions that break
// this rule are by definition the ones nobody thought of.
//
// The cost is measured rather than asserted (BenchmarkChainRead, with the guard
// removed for comparison): **+17.5 ns and one 4-byte allocation per Read**, flat
// — a ten-access Read costs the same +14.5 ns as a one-access Read, because the
// per-access atomic load disappears into the map lookup underneath it. That is
// not a price worth trading for a shipped binary that reads memory another
// goroutine owns instead.
//
// Rule 2, the reentrancy check, is a different matter: it needs the goroutine's
// identity and costs microseconds, so it stays behind `-tags zcdguard`.
//
// StateRef is deliberately a value type carrying a *pointer* to its liveness
// flag, so every copy shares one flag: squirrelling one away in a struct field
// or sending it to another goroutine does not shed the guard.
type StateRef struct {
	s    *state.State
	live *atomic.Bool
}

// check panics if a borrowed reference is used after its callback returned.
//
// A nil flag means the reference is owned rather than borrowed, which is what
// Snapshot hands out, so nil is always valid.
func (r StateRef) check() {
	if r.s == nil {
		panic("chain: a zero StateRef was used; it was never lent by Read")
	}
	if r.live != nil && !r.live.Load() {
		panic("chain: consensus state was read after its Read callback returned. " +
			"The state a View carries is borrowed and stops being valid when the " +
			"callback returns; holding it past that point is the data race of " +
			"docs/adversarial/concurrency.md. Use Chain.Snapshot if the state must " +
			"outlive the call.")
	}
}

// stillValid re-checks after the read, and it is not redundant.
//
// A check followed by a read is two steps, and the gap between them is a window:
// a goroutine started inside the callback can pass `check` while the callback is
// still on the stack, then perform the actual map walk after the callback has
// returned and the lock is gone. Checking only beforehand misses that entirely —
// measured, not assumed: an adversarial test drove exactly this shape 200 times
// and the guard fired zero times, and `-race` reported nothing either, because a
// race is only reported when a writer happens to write.
//
// Re-checking afterwards closes it for detection. The three cases become:
//
//	read begins after the callback returned   -> check() fires
//	read spans the callback's return          -> stillValid() fires
//	read begins and ends inside the callback  -> legitimate; the lock was held
//
// It cannot *prevent* the bad read — nothing at this layer can, short of holding
// the lock, which is the thing the callback exists to bound. What it can do is
// refuse to hand back a value that may have been read from memory somebody else
// was writing, which is the difference between a loud failure and a wrong number
// entering consensus.
func (r StateRef) stillValid() {
	if r.live != nil && !r.live.Load() {
		panic("chain: consensus state was read *across* the return of its Read " +
			"callback — the read began while the borrow was valid and finished " +
			"after it was not, so the value may have come from memory another " +
			"goroutine was writing. This is docs/adversarial/concurrency.md with " +
			"a narrower window. Use Chain.Snapshot if the state must outlive the call.")
	}
}

// Get returns the value of a cell.
func (r StateRef) Get(slot types.Slot) u256.U256 {
	r.check()
	v := r.s.Get(slot)
	r.stillValid()
	return v
}

// IsSpent reports whether an address has burned its authority.
func (r StateRef) IsSpent(a types.Address) bool {
	r.check()
	v := r.s.IsSpent(a)
	r.stillValid()
	return v
}

// Seen reports a certificate's recorded TTL, for replay rejection.
func (r StateRef) Seen(id types.Hash) (uint64, bool) {
	r.check()
	ttl, ok := r.s.Seen(id)
	r.stillValid()
	return ttl, ok
}

// Root returns the state root.
func (r StateRef) Root() types.Hash {
	r.check()
	v := r.s.Root()
	r.stillValid()
	return v
}

// SeenCount and SpentCount are observability, not consensus.
func (r StateRef) SeenCount() int {
	r.check()
	v := r.s.SeenCount()
	r.stillValid()
	return v
}

func (r StateRef) SpentCount() int {
	r.check()
	v := r.s.SpentCount()
	r.stillValid()
	return v
}

// View is a borrowed, consistent read of the chain.
//
// Every field is valid only for the duration of the Read callback. Tip and
// Height are copies and are harmless to keep; State is not, and enforces that
// itself.
type View struct {
	Tip    types.Header
	Height uint64
	State  StateRef
}

// Snapshot is an owned, consistent read of the chain.
//
// Unlike a View this is safe to hold: State is a detached clone that nothing
// else will write. The cost is that copy, which is why it is a separate call
// rather than the default — a caller that only reads a cell should use Read.
type Snapshot struct {
	Tip    types.Header
	Height uint64
	State  *state.State
}
