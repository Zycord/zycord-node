package verify_test

import (
	"strconv"
	"testing"

	"zycord/core/crypto"
	"zycord/core/validity"
	"zycord/node/verify"
	"zycord/spec"
)

// The whitepaper's §14 puts a number on stateless verification, and this is
// where it comes from. The claim being measured is the one the whole design
// rests on: a certificate is checkable from its bytes alone, so checking a pile
// of them is embarrassingly parallel and scales with cores.
//
// What is *not* measured here, deliberately: batch signature verification. It
// does not exist — core/crypto verifies one signature at a time, and building
// randomized batch Ed25519 by hand is exactly the kind of security-critical
// wheel the dependency rule says not to reinvent. Until it exists, the honest
// figure is per-core throughput of single verification, which is what these
// benchmarks report. §14 says so rather than quoting a number for code nobody
// has written.

// BenchmarkVerifySequential is the baseline: one certificate at a time on one
// goroutine. Divide into it to get certificates per second per core.
func BenchmarkVerifySequential(b *testing.B) {
	p := spec.Devnet()
	batch := certs(b, p, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verify.Sequential{}.Verify(batch, p)
	}
}

// BenchmarkVerifyPool is the same work across GOMAXPROCS goroutines. The ratio
// against the sequential figure is the scaling claim, measured rather than
// asserted — and a ratio well below the core count would be the finding.
func BenchmarkVerifyPool(b *testing.B) {
	p := spec.Devnet()
	batch := certs(b, p, 256)
	pool := verify.NewPool()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Verify(batch, p)
	}
}

// BenchmarkVerifyPoolWorkers sweeps the worker count on a fixed batch, so the
// shape of the scaling curve is visible instead of a single point on it.
func BenchmarkVerifyPoolWorkers(b *testing.B) {
	p := spec.Devnet()
	batch := certs(b, p, 512)
	for _, w := range []int{1, 2, 4, 8} {
		b.Run(workers(w), func(b *testing.B) {
			pool := &verify.Pool{Workers: w}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pool.Verify(batch, p)
			}
		})
	}
}

// BenchmarkVerifyStructural isolates everything except the signatures, so the
// split between "cheap structural rules" and "expensive cryptography" is a
// measurement. It is also what a batch verifier would leave behind: whatever
// this costs is the floor that batching cannot go below.
func BenchmarkVerifyStructural(b *testing.B) {
	p := spec.Devnet()
	batch := certs(b, p, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range batch {
			if err := validity.CheckStructural(c, p); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkSignatureVerify is the primitive on its own: one strict Ed25519
// verification, small-order check included.
func BenchmarkSignatureVerify(b *testing.B) {
	p := spec.Devnet()
	c := certs(b, p, 1)[0]
	msg := c.SigningMessage(p)
	sig := c.Sigs[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !crypto.VerifyStrict(sig.PubKey, msg, sig.Sig) {
			b.Fatal("signature did not verify")
		}
	}
}

func workers(n int) string { return "workers=" + strconv.Itoa(n) }
