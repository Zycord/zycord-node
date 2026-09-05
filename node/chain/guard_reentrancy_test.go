//go:build race || zcdguard

package chain_test

import (
	"strings"
	"testing"

	"zycord/node/chain"
)

// Rule 2 — a Read callback must not re-enter the chain.
//
// These compile only in a guarded build (`-race` or `-tags zcdguard`), which is
// the honest scope of the guarantee: detecting reentrancy needs the goroutine's
// identity, which costs microseconds, so a shipped binary does not carry it.
// Rule 1's tests are in guard_test.go and run everywhere, because rule 1 is
// always on.

// mustPanicGuarded runs fn and returns the panic message, failing if it did not
// panic.
func mustPanicGuarded(t *testing.T, what string, fn func()) string {
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
			}
		}()
		fn()
	}()
	if msg == "" {
		t.Fatalf("%s did not panic; the guard is not enforcing this rule", what)
	}
	return msg
}

// TestReentrantReadIsCaught is rule 2, and specifically the quiet half of it.
//
// A nested RLock *succeeds* in Go when no writer is queued, so this violation
// passes an idle test suite and deadlocks later under write pressure. Detecting
// it before the lock is taken is the whole point; waiting for the deadlock would
// mean finding it on the day it costs the most.
func TestReentrantReadIsCaught(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)

	msg := mustPanicGuarded(t, "calling Read from inside a Read callback", func() {
		n.chain.Read(func(chain.View) {
			n.chain.Read(func(chain.View) {})
		})
	})
	if !strings.Contains(msg, "not reentrant") {
		t.Fatalf("panicked for the wrong reason: %s", msg)
	}
}

// TestWriteFromInsideReadIsCaught is the loud half of rule 2. Without the guard
// this deadlocks rather than failing, which is a worse outcome than a panic
// because a hung node reports nothing at all.
func TestWriteFromInsideReadIsCaught(t *testing.T) {
	n := openNode(t, t.TempDir(), devnetEasy(), key(t, 1).Persistent())
	defer n.close(t)
	n.mine(t, 1)

	blk, err := n.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	mustPanicGuarded(t, "calling Apply from inside a Read callback", func() {
		n.chain.Read(func(chain.View) {
			_, _ = n.chain.Apply(blk)
		})
	})
}
