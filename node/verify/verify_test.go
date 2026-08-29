package verify_test

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/verify"
	"zycord/spec"
	"zycord/wallet"
)

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

func key(t testing.TB, n uint64) *wallet.Key {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(n >> (8 * (uint(i) % 8)))
	}
	k, err := wallet.KeyFromSeed(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// certs builds n distinct, individually valid certificates.
func certs(t testing.TB, p *params.Params, n int) []*types.Certificate {
	t.Helper()
	out := make([]*types.Certificate, n)
	dst := key(t, 9_999_999).Persistent()
	for i := 0; i < n; i++ {
		signer := key(t, uint64(1_000_000+i))
		addr := signer.Persistent()
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, addr, dst, drops(1_000)),
			TTL:     20,
			Deposit: wallet.SelfDeposit(addr, addr),
			FeeBid:  wallet.Bid(drops(1_000_000), drops(10), drops(1_000_000), drops(10)),
			Signers: []*wallet.Key{signer},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = c
	}
	return out
}

// TestPoolAgreesWithSequential is the only correctness property the pool has
// to have, and it is worth stating as a comparison rather than as a claim: the
// concurrent implementation must produce exactly what the one-at-a-time
// implementation produces, verdict for verdict, position for position.
//
// The batch deliberately mixes valid and invalid certificates, because a pool
// that dropped results on the floor would still look right on an all-valid
// batch — every entry would be nil either way.
func TestPoolAgreesWithSequential(t *testing.T) {
	p := spec.Devnet()
	batch := certs(t, p, 32)

	// Corrupt a few, at spread-out positions, so an off-by-one in the
	// hand-out would move an error to the wrong index.
	for _, i := range []int{0, 7, 8, 23, 31} {
		batch[i].Sigs[0].Sig[0] ^= 0xff
	}

	want := verify.Sequential{}.Verify(batch, p)
	for _, workers := range []int{1, 2, 3, 4, 8, 64} {
		pool := &verify.Pool{Workers: workers}
		got := pool.Verify(batch, p)
		if len(got) != len(want) {
			t.Fatalf("%d workers: %d results, want %d", workers, len(got), len(want))
		}
		for i := range want {
			if (got[i] == nil) != (want[i] == nil) {
				t.Fatalf("%d workers: certificate %d: pool says %v, sequential says %v",
					workers, i, got[i], want[i])
			}
			// Compared by message rather than by identity: the V-rules build
			// their errors per call, so two runs never share a value even
			// when they name the same broken rule.
			if got[i] != nil && got[i].Error() != want[i].Error() {
				t.Fatalf("%d workers: certificate %d: pool says %q, sequential says %q",
					workers, i, got[i], want[i])
			}
		}
	}
}

// TestPoolIsDeterministic runs the same batch repeatedly through the pool. The
// predicate reads nothing shared, so scheduling must not be observable — and
// this is the test that would fail first if someone later gave the verifier a
// cache, a counter, or any other reason to remember one call in the next.
func TestPoolIsDeterministic(t *testing.T) {
	p := spec.Devnet()
	batch := certs(t, p, 24)
	batch[5].Sigs[0].Sig[0] ^= 0xff

	pool := verify.NewPool()
	first := pool.Verify(batch, p)
	for run := 0; run < 20; run++ {
		got := pool.Verify(batch, p)
		for i := range first {
			if (got[i] == nil) != (first[i] == nil) {
				t.Fatalf("run %d: certificate %d changed verdict between runs", run, i)
			}
		}
	}
}

// TestFirstError reports the earliest failure, not merely some failure, so a
// caller rejecting a block names the certificate a reader would name.
func TestFirstError(t *testing.T) {
	p := spec.Devnet()
	batch := certs(t, p, 8)
	batch[6].Sigs[0].Sig[0] ^= 0xff
	batch[3].Sigs[0].Sig[0] ^= 0xff

	idx, err := verify.FirstError(verify.NewPool().Verify(batch, p))
	if idx != 3 || err == nil {
		t.Fatalf("first error at %d (%v), want index 3", idx, err)
	}

	clean := certs(t, p, 4)
	if idx, err := verify.FirstError(verify.NewPool().Verify(clean, p)); idx != -1 || err != nil {
		t.Fatalf("clean batch reported an error at %d: %v", idx, err)
	}
}

// TestEmptyBatch: the pool sizes its worker count from the batch, so an empty
// batch is the edge where that arithmetic could spawn nothing, or hang.
func TestEmptyBatch(t *testing.T) {
	p := spec.Devnet()
	if got := verify.NewPool().Verify(nil, p); len(got) != 0 {
		t.Fatalf("empty batch returned %d results", len(got))
	}
}
