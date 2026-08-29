// Package verify is the stateless-validity pipeline: the stage that turns a
// pile of certificates into a verdict per certificate, using nothing but their
// bytes.
//
// It lives outside core/ deliberately. The predicate itself is consensus and
// belongs to core/validity, which is single-threaded, allocation-shy and free
// of anything that could make two nodes disagree. *How fast* a node evaluates
// that predicate is not consensus at all — it is a scheduling question, and
// scheduling is where goroutines, batching and eventually a GPU belong. Keeping
// the two apart is what lets the second change without anybody re-auditing the
// first.
//
// There is deliberately no Verifier interface here yet. One was written and
// removed: nothing in the tree took it as a parameter, and an interface with no
// consumer is a guess about a future call site rather than a seam. The two
// concrete implementations below already demonstrate that the shape is
// substitutable, and the day something accepts a verifier as an argument the
// interface can be extracted in a minute from whatever it actually needs. The
// unreferenced-export guard in sim/wiring exists because this project has twice
// shipped code that worked and was called from nowhere; taking an exemption
// from it for a third piece would have been the wrong way to answer it.
//
// Determinism note, because it is the thing that would matter if it were
// wrong: the pool is concurrent but its output is not order-dependent. Every
// certificate is checked independently against its own bytes, results are
// written to a per-index slot rather than appended, and the predicate reads no
// shared state. Two runs over the same batch produce the same verdicts in the
// same positions, whatever order the workers happened to finish in.
package verify

import (
	"runtime"
	"sync"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/validity"
)

// Both implementations answer the same question — are these certificates
// stateless-valid — and both return one result per input, positionally
// aligned: a nil entry means the certificate at that index is valid, a non-nil
// entry is the first rule it broke.
//
// Sequential is the reference implementation: one certificate at a time, in
// order, with no concurrency at all.
//
// It exists to be the thing the concurrent one is compared against. A pool that
// disagrees with it on any batch is broken, and that is a cheaper test to write
// than a proof about the pool.
type Sequential struct{}

// Verify checks each certificate in order, on one goroutine.
func (Sequential) Verify(certs []*types.Certificate, p *params.Params) []error {
	out := make([]error, len(certs))
	for i, c := range certs {
		out[i] = validity.Check(c, p)
	}
	return out
}

// Pool verifies a batch across a fixed number of goroutines.
//
// Certificates are handed out by atomic index rather than split into
// contiguous chunks, because the cost of checking one varies by a large factor
// — a certificate with sixteen signatures costs sixteen times one with a
// single signature — and a static split leaves workers idle behind whichever
// chunk drew the expensive certificates.
type Pool struct {
	// Workers is the number of goroutines. Zero means GOMAXPROCS.
	Workers int
}

// NewPool returns a Pool sized to the machine.
func NewPool() *Pool { return &Pool{Workers: runtime.GOMAXPROCS(0)} }

// Verify checks the batch across the pool's goroutines, returning results in
// input order however the workers finished.
func (pl *Pool) Verify(certs []*types.Certificate, p *params.Params) []error {
	out := make([]error, len(certs))
	workers := pl.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	// Below this, the goroutines cost more than the work they take on. The
	// threshold is a guess and is allowed to be: it changes throughput and
	// nothing else, which is the whole reason this package is not in core/.
	if workers > len(certs) {
		workers = len(certs)
	}
	if workers <= 1 {
		return Sequential{}.Verify(certs, p)
	}

	var next atomicIndex
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := next.take()
				if i >= len(certs) {
					return
				}
				// Each worker writes only to its own index, so there is no
				// shared mutable state and no lock on the hot path.
				out[i] = validity.Check(certs[i], p)
			}
		}()
	}
	wg.Wait()
	return out
}

// FirstError returns the index and error of the first invalid certificate in a
// result slice, or (-1, nil) when every certificate passed. Callers that only
// need a yes-or-no answer for a whole block use this.
func FirstError(results []error) (int, error) {
	for i, err := range results {
		if err != nil {
			return i, err
		}
	}
	return -1, nil
}
