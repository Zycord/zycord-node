//go:build randomx

package randomx

import (
	"testing"
	"time"

	"zycord/core/crypto/blake2b"
	"zycord/core/types"
)

// BenchmarkVerify measures what a node pays to check one header's proof of
// work: light mode, one goroutine, the configuration every non-mining node
// runs.
//
// This is the number the sync path's cost is made of, and it is not a detail.
// A header range is bounded by thousands, and every header in it is one of
// these. Publish it per ARCHITECTURE §15's rules — its own process, medians
// over runs, an idle machine — rather than reading it off a `make bench`
// transcript.
func BenchmarkVerify(b *testing.B) {
	e, err := New(Options{Keys: 1, MaxVMs: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer e.(*Engine).Close()

	var key types.Hash
	copy(key[:], "benchmark key")
	e.Hash(key, []byte("warm")) // pay the cache initialisation outside the loop

	in := make([]byte, 40)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in[0] = byte(i)
		in[1] = byte(i >> 8)
		e.Hash(key, in)
	}
}

// BenchmarkVerifyV2 is BenchmarkVerify for rx/2, which is the function mainnet
// and the public testnet run.
//
// The pair exists so the two can be measured in one process, interleaved, on
// one machine, at one moment. That is the only comparison this hardware can
// support: ARCHITECTURE §15's protocol asks for an idle machine, and a shared
// one is not that, so a v2 figure taken today against a v1 figure taken in
// another session measures the machine's mood. Run them together, take the
// ratio, and report the ratio.
func BenchmarkVerifyV2(b *testing.B) {
	e, err := New(Options{Keys: 1, MaxVMs: 1, V2: true})
	if err != nil {
		b.Fatal(err)
	}
	defer e.(*Engine).Close()

	var key types.Hash
	copy(key[:], "benchmark key")
	e.Hash(key, []byte("warm"))

	in := make([]byte, 40)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in[0] = byte(i)
		in[1] = byte(i >> 8)
		e.Hash(key, in)
	}
}

// BenchmarkInitCacheV2 is BenchmarkInitCache for rx/2.
//
// **It is expected to be identical, and measuring it is how that expectation
// stops being an assumption.** Cache construction is Argon2 over
// RANDOMX_ARGON_MEMORY with RANDOMX_ARGON_SALT, and `src/configuration.h` is
// byte-identical between v1.2.3 and v2.0.1 in both — so the seed-epoch stall
// this tree already measured and prefetches against should not move at all.
// A difference here would mean the version flag is reaching allocation, which
// nothing in the upstream diff suggests it should.
func BenchmarkInitCacheV2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e, err := New(Options{Keys: 1, MaxVMs: 1, V2: true})
		if err != nil {
			b.Fatal(err)
		}
		var key types.Hash
		key[0] = byte(i)
		e.Hash(key, []byte("x"))
		e.(*Engine).Close()
	}
}

// BenchmarkInitDatasetV2 is BenchmarkInitDataset for rx/2, and the same
// expectation applies: RANDOMX_DATASET_BASE_SIZE and _EXTRA_SIZE did not move
// between the tags, and dataset construction is superscalar hashing over the
// cache rather than program execution, so the version should not reach it.
func BenchmarkInitDatasetV2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e, err := New(Options{Keys: 1, MaxVMs: 1, FullMemory: true, V2: true})
		if err != nil {
			b.Skipf("fast mode unavailable: %v", err)
		}
		var key types.Hash
		key[0] = byte(i)
		t0 := time.Now()
		e.Hash(key, []byte("x"))
		b.ReportMetric(float64(time.Since(t0).Seconds()), "s/dataset")
		e.(*Engine).Close()
	}
}

// BenchmarkCommitment measures the cheap half of the work rule: the BLAKE2b
// that turns a header's declared digest into the value compared against the
// target.
//
// It is the number the header's 32-byte growth was traded for, so it belongs
// beside the verify figure rather than in a comment. The ratio between the two
// is what makes a cited-header flood affordable.
func BenchmarkCommitment(b *testing.B) {
	buf := make([]byte, 43+32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf[0] = byte(i)
		blake2b.Sum256(buf)
	}
}

// BenchmarkInitCache measures the per-key-epoch cost a verifying node pays at
// every key boundary, during which it holds the engine lock and verifies
// nothing.
func BenchmarkInitCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e, err := New(Options{Keys: 1, MaxVMs: 1})
		if err != nil {
			b.Fatal(err)
		}
		var key types.Hash
		key[0] = byte(i)
		e.Hash(key, []byte("x")) // forces one cache initialisation
		e.(*Engine).Close()
	}
}

// BenchmarkInitDataset measures the mining-side cost of a key change: the full
// ~2 GiB build, across InitThreads goroutines.
//
// It is a benchmark rather than a test because it is slow enough to be worth
// opting into, and it is here because the number is not what was assumed. A
// first devnet run under RandomX produced ZERO blocks in 200 seconds while
// this was in progress, which is what put it in the tree.
func BenchmarkInitDataset(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e, err := New(Options{Keys: 1, MaxVMs: 1, FullMemory: true})
		if err != nil {
			b.Skipf("fast mode unavailable: %v", err)
		}
		var key types.Hash
		key[0] = byte(i)
		t0 := time.Now()
		e.Hash(key, []byte("x"))
		b.ReportMetric(float64(time.Since(t0).Seconds()), "s/dataset")
		e.(*Engine).Close()
	}
}

// BenchmarkInitCacheNodeConfig is BenchmarkInitCache at the Options a node
// actually runs, which is not the Options that benchmark uses.
//
// cmd/zycordd builds `randomx.New(randomx.Options{FullMemory: mining})`, so a
// verifying node takes the zero value on every other field: Keys 2 and MaxVMs
// GOMAXPROCS, against the Keys 1 / MaxVMs 1 above. The Argon2 fill is the same
// 256 MiB either way; what differs structurally is that one key init also
// creates GOMAXPROCS virtual machines rather than one, and a VM is a scratchpad
// plus a JIT compile.
//
// **That structural difference is not a measured difference here, and must not
// be reported as one.** Two independent five-run samples at
// `-benchtime=1x -count=5` put this benchmark's median and BenchmarkInitCache's
// about 1 ms apart, with fully overlapping ranges; an earlier revision of this
// comment attributed a 24 ms gap from a single sample to the extra VMs, which a
// second sample does not reproduce. Separating the VM term needs the protocol
// ARCHITECTURE §15 asks for — an idle machine, a settled b.N, many runs — not
// five single iterations.
//
// What this benchmark is for is the magnitude rather than the delta: the cost
// an attacker forces, at the Options a node actually runs, taken instead of
// inherited. Both configurations agree that it is about 0.55 s.
func BenchmarkInitCacheNodeConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		e, err := New(Options{})
		if err != nil {
			b.Fatal(err)
		}
		var key types.Hash
		key[0] = byte(i)
		e.Hash(key, []byte("x")) // forces one cache initialisation
		e.(*Engine).Close()
	}
}
