package mempool_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/node/mempool"
)

// probeDelay is how long a reader is given to come back before the probe calls
// it blocked. Ed25519 verification is tens of microseconds, so any value orders
// of magnitude above that separates "waiting for the lock" from "scheduled
// late" without making the test slow.
const probeDelay = 200 * time.Millisecond

// readerReturnsDuring reports whether a concurrent Stats() reader completes
// while during-the-callback is executing.
func readerReturnsDuring(t *testing.T, pool *mempool.Pool) bool {
	t.Helper()
	done := make(chan struct{})
	go func() { pool.Stats(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(probeDelay):
		return false
	}
}

// TestVerificationDoesNotHoldThePoolLock is the concurrency half of the cost
// reorder that put the cheap gates ahead of the Ed25519 pass.
//
// The property: **Add pays for V2 with pool.mu released, so one certificate's
// Ed25519 pass never stalls another goroutine's read of the pool.**
//
// It matters because a forged certificate is never pooled, so it never raises
// the aggregate deposit screen or the per-underwriter count that would bound it
// — one funded deposit cell screens an unbounded stream of distinct forgeries.
// If verification held the write lock, that stream would be a way to stall
// Candidates(), IDs(), Stats() and every RPC reader for the price of gossip.
// docs/adversarial/mempool.md §2.6 identifies that lock as the contention that
// matters, and §2.8 records why the reorder must not put signature work under
// it.
//
// The first Add of the reorder held the lock across V2 and this test fails
// against it: the reader does not return until the verification finishes.
func TestVerificationDoesNotHoldThePoolLock(t *testing.T) {
	w := newWorld(t, smallPolicy())
	c := w.cert(key(t, 41_500), 0, 10, 1)

	var readerReturned bool
	n := mempool.WhileVerifying(
		func() { readerReturned = readerReturnsDuring(t, w.pool) },
		func() {
			if err := w.pool.Add(c, w.state, 1); err != nil {
				t.Fatalf("Add: %v", err)
			}
		},
	)

	if n != 1 {
		t.Fatalf("the probe saw %d verifications, want exactly 1 — it did not observe V2 at all", n)
	}
	if !readerReturned {
		t.Fatal("a reader blocked for the whole of V2: Add is verifying under pool.mu")
	}

	// Anti-vacuity. The probe must be able to report a blocked reader, or the
	// assertion above passes for a pool that never locks anything.
	blockedUnderTheLock := true
	w.pool.WhileWriteLocked(func() { blockedUnderTheLock = readerReturnsDuring(t, w.pool) })
	if blockedUnderTheLock {
		t.Fatal("the probe reported a reader returning while the write lock was held; it cannot detect a held lock, so the assertion above proves nothing")
	}
}

// TestAdmissionIsStillAtomicAcrossTheReleasedLock is the correctness half.
//
// Add releases pool.mu to verify and retakes it to insert, so the admission
// decision must be re-taken on the second acquisition — otherwise two arrivals
// racing through the gap could both be admitted against a screen only one of
// them passed. The observable form of that: concurrent Adds of the same
// certificate id admit it exactly once, and every other caller is told it was
// already pooled.
func TestAdmissionIsStillAtomicAcrossTheReleasedLock(t *testing.T) {
	w := newWorld(t, smallPolicy())
	c := w.cert(key(t, 41_600), 0, 10, 1)

	const racers = 16
	errs := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			errs <- w.pool.Add(c, w.state, 1)
		}()
	}
	close(start)

	admitted := 0
	for i := 0; i < racers; i++ {
		if err := <-errs; err == nil {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of %d concurrent Adds of one certificate succeeded, want exactly 1", admitted, racers)
	}
	if got := w.pool.Stats().Size; got != 1 {
		t.Fatalf("the pool holds %d certificates after the race, want 1", got)
	}
}

// TestTheAggregateDepositScreenSurvivesTheReleasedLock is the atomicity test
// the one above is not.
//
// Racing a single id proves only that the `byID` map is consulted under the
// second acquisition — a map that would catch a duplicate however the rest of
// Add were written. The gates an attacker can actually straddle are the budget
// gates, and the aggregate deposit screen (§2.5) is the one that matters: it
// sums over the underwriter's already-pooled certificates, so its answer for
// the second arrival depends on whether the first has landed yet.
//
// The property: **two distinct certificates from one underwriter, against a
// deposit cell funded for exactly one of them, admit exactly one however they
// are interleaved.** With the re-screen deleted both are admitted, because both
// evaluate the screen before either has been inserted — the pool ends up
// backing two certificates with one certificate's worth of deposit, which is
// precisely the amplification the aggregate deposit screen closed.
//
// Anti-vacuity is built into the funding, as in
// TestDepositScreenSumsAcrossPooledCertificates: the cell covers either
// certificate alone, so nothing here is refused for being unaffordable on its
// own — only the sum is out of reach.
func TestTheAggregateDepositScreenSurvivesTheReleasedLock(t *testing.T) {
	w := newWorld(t, smallPolicy())
	signer := key(t, 41_700)
	addr := signer.Persistent()

	first := w.cert(signer, 0, 100, 1)
	second := w.cert(signer, 1, 100, 1)

	ceiling1, ok := first.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	ceiling2, ok := second.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}

	// Enough for either alone, not for both. w.cert topped the cell up for
	// each, so this overwrites rather than adds.
	balance := ceiling1.SatAdd(ceiling1.MulDiv64(1, 2))
	w.state.Set(types.NativeBalanceSlot(addr), balance)
	if balance.Lt(ceiling1) || balance.Lt(ceiling2) {
		t.Fatalf("setup: the cell does not cover each certificate alone, so a serial screen "+
			"would already refuse one and the race would prove nothing "+
			"(ceiling1=%s ceiling2=%s balance=%s)",
			ceiling1.String(), ceiling2.String(), balance.String())
	}
	if !balance.Lt(ceiling1.SatAdd(ceiling2)) {
		t.Fatalf("setup: the cell covers both certificates, so admitting both would be correct "+
			"(ceiling1=%s ceiling2=%s balance=%s)",
			ceiling1.String(), ceiling2.String(), balance.String())
	}

	errs := make(chan error, 2)
	start := make(chan struct{})
	for _, c := range []*types.Certificate{first, second} {
		go func() {
			<-start
			errs <- w.pool.Add(c, w.state, 1)
		}()
	}
	close(start)

	admitted := 0
	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of 2 concurrent Adds admitted against a one-certificate deposit, want 1", admitted)
	}
	if got := w.pool.Stats().Size; got != 1 {
		t.Fatalf("the pool holds %d certificates backed by one certificate's deposit, want 1", got)
	}
}

// TestNoTestInThisPackageRunsInParallel enforces the precondition the signature
// counters state but could not previously back.
//
// CountSignatureChecks and WhileVerifying swap an unshared package variable, so
// two tests running concurrently would see each other's verifier. Nothing in
// the language stops a later test from adding t.Parallel(), so this reads the
// package's own sources and says so.
func TestNoTestInThisPackageRunsInParallel(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		found++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Parallel" {
				return true
			}
			t.Errorf("%s calls t.Parallel(); mempool.CountSignatureChecks and mempool.WhileVerifying swap a package variable and are not safe against a concurrent test", name)
			return true
		})
	}
	if found == 0 {
		t.Fatal("no _test.go files were read, so this check asserts nothing")
	}
}
