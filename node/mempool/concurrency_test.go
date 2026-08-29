package mempool_test

import (
	"sync"
	"testing"

	"zycord/core/types"
)

// The mempool under concurrent access.
//
// The pool is written to by every peer's message loop (an arriving certificate)
// and by the miner (OnBlock re-screening after a block), and read by the
// builder and the RPC at the same time. It has a mutex; what this asks is
// whether the *compound* operations are inside one critical section, because
// screen-then-insert and evict-then-admit are each two decisions that must not
// interleave with another writer's.
//
// This is the audit named in docs/adversarial/concurrency.md §8. It exists
// because the chain's race was invisible to `-race` for exactly one reason:
// nothing ran the code concurrently. A pool with a mutex and no concurrent test
// is in the same position — the lock might be correct, but nothing has asked.
func TestPoolSurvivesConcurrentAccess(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// Pre-build the certificates, so the goroutines contend on the pool rather
	// than on the wallet builder.
	const writers = 8
	const each = 25
	certs := make([][]*types.Certificate, writers)
	for i := 0; i < writers; i++ {
		for j := 0; j < each; j++ {
			certs[i] = append(certs[i], w.cert(key(t, 40_000+i), uint64(j), uint64(1_000+j), 1))
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for _, c := range certs[i] {
				// Refusals are expected — the quota and the eviction margin both
				// bind here. The question is memory safety and invariant
				// consistency, not admission.
				_ = w.add(c)
			}
		}(i)
	}

	// A reader doing what the builder and the RPC do.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			st := w.pool.Stats()
			cands := w.pool.Candidates()
			// The invariant that a torn read would break: the pool never reports
			// more residents than its own limit, and the candidate list never
			// exceeds the reported size.
			if st.Size > smallPolicy().MaxCertificates {
				t.Errorf("pool reports %d residents, limit is %d",
					st.Size, smallPolicy().MaxCertificates)
				return
			}
			if len(cands) > st.Size+writers {
				t.Errorf("candidate list (%d) far exceeds the reported size (%d)",
					len(cands), st.Size)
				return
			}
		}
	}()

	wg.Wait()

	// The bookkeeping must agree with itself: every resident is counted against
	// exactly one underwriter, so the per-underwriter counts must sum to the
	// size. A lost update in either map shows up here.
	st := w.pool.Stats()
	if st.Size > smallPolicy().MaxCertificates {
		t.Fatalf("pool ended with %d residents, limit is %d", st.Size, smallPolicy().MaxCertificates)
	}
	if got := len(w.pool.Candidates()); got != st.Size {
		t.Fatalf("the pool holds %d candidates but reports %d residents", got, st.Size)
	}
}
