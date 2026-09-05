package verify_test

import (
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/spec"
)

// V2 recomputes params.ConsensusRoot() once per certificate, reflectively, on
// the block-verification path (core/fold/blockrules.go folds every certificate
// in every block through validity.Check; node/verify does the same for a
// batch). The cost is therefore per certificate, and it scales with the
// certificates-per-block quantity every ceiling in this project is about.
//
// The figure that matters is not the absolute microseconds — those are a
// property of whatever machine happened to run them — but the *ratio* against
// one strict Ed25519 verification, which is what the same path already pays
// per signature. So both halves are measured here, in the same package, on the
// same machine, in the same run: BenchmarkConsensusRoot is the numerator and
// BenchmarkSignatureVerify (bench_test.go) is the denominator, and
// TestConsensusRootStaysCheapRelativeToOneSignature runs both and holds the
// quotient to a budget. The audit that put the per-certificate reflective walk
// on the record closed on that ratio, and the ratio was a remembered number
// from one throwaway run rather than something in the tree; this is the tree's
// copy.
//
// THE HAZARD THIS BENCHMARK EXISTS TO GUARD. The obvious response to a
// per-certificate reflective walk is to memoise the root on the Params struct.
// Do not, unless the memoisation makes "not yet computed" impossible to
// observe. A cached field has to be populated by somebody, and the failure
// mode of forgetting is silent rather than loud: a params.Params built by
// struct literal would carry a zero root, every node that forgot would agree
// with every other node that forgot, and all of them would disagree with
// everyone who did not — a fork, arriving through a performance optimisation,
// on a path where nothing would ever report an error. That trade is only worth
// opening if the ratio below stops being small, so measure it here first.

// benchRootSink keeps the compiler from eliminating the walk whose cost is the
// entire point of the benchmark.
var benchRootSink crypto.Hash

// BenchmarkConsensusRoot is the numerator: one reflective walk over a
// parameter set, which is exactly what V2 adds per certificate. Both shipped
// parameter sets are measured because the walk's cost depends on the values
// (string lengths are length-prefixed into the preimage), not only on the
// struct shape.
func BenchmarkConsensusRoot(b *testing.B) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"devnet", spec.Devnet()},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchRootSink = tc.p.ConsensusRoot()
			}
		})
	}
}

// consensusRootBudget is the fraction of one strict Ed25519 verification that
// the per-certificate root recomputation is allowed to cost.
//
// It is deliberately loose. The measured value on the tree that introduced
// this test is a few percent, so the budget carries roughly an order of
// magnitude of headroom, and it is a ratio of two timings taken back to back
// on the same machine — a slow or loaded machine moves both halves together
// and the quotient stays put. What it does catch is the thing worth catching:
// a change that makes the walk structurally more expensive — many more
// parameters, a field type whose encoding is not O(size), or a walk that stops
// being linear — at which point the tradeoff in the comment at the top of this
// file has to be reopened rather than absorbed.
const consensusRootBudget = 0.25

// TestConsensusRootStaysCheapRelativeToOneSignature measures both halves of
// the ratio and fails if the root recomputation stops being a rounding error
// against the signature verification that dominates the same path.
//
// It reports the numbers on every run, so the ratio is a measurement anybody
// can read out of `go test ./node/verify -run ConsensusRootStaysCheap -v`
// rather than a figure quoted from a comment.
func TestConsensusRootStaysCheapRelativeToOneSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; needs a benchtime budget")
	}

	p := spec.Mainnet()
	root := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchRootSink = p.ConsensusRoot()
		}
	})

	// The denominator, built the same way BenchmarkSignatureVerify builds it:
	// one strict verification, small-order check included.
	sp := spec.Devnet()
	c := certs(t, sp, 1)[0]
	msg := c.SigningMessage(sp)
	sig := c.Sigs[0]
	verify := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !crypto.VerifyStrict(sig.PubKey, msg, sig.Sig) {
				b.Fatal("signature did not verify")
			}
		}
	})

	if root.N == 0 || verify.N == 0 {
		t.Fatalf("degenerate measurement: root n=%d, verify n=%d", root.N, verify.N)
	}
	rootNs, verifyNs := root.NsPerOp(), verify.NsPerOp()
	if rootNs <= 0 || verifyNs <= 0 {
		t.Fatalf("degenerate measurement: root %d ns/op, verify %d ns/op", rootNs, verifyNs)
	}

	ratio := float64(rootNs) / float64(verifyNs)
	t.Logf("ConsensusRoot %d ns/op, %d allocs/op (n=%d); strict Ed25519 verify %d ns/op (n=%d); ratio %.4f",
		rootNs, root.AllocsPerOp(), root.N, verifyNs, verify.N, ratio)

	if ratio > consensusRootBudget {
		t.Errorf("per-certificate ConsensusRoot costs %.2f%% of one strict Ed25519 verification, "+
			"over the budget of %.2f%%; the root recomputation is no longer a rounding error on the "+
			"block-verification path. Read the memoisation hazard at the top of this file before "+
			"reaching for a cache",
			ratio*100, consensusRootBudget*100)
	}
}
