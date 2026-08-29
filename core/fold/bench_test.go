package fold_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
)

// The whitepaper's §3 makes a throughput claim about the fold and §14 has to
// put a number on it. These benchmarks are where that number comes from.
//
// The measurement problem worth stating, because it decides how to read every
// figure below: ApplyBlock is not the fold. Its first act is CheckBlockRules,
// which runs full stateless validity — Ed25519 included — over every
// certificate in the block. That work is real and a node does it, but it is the
// *parallel* half of the system, and timing it alongside the sequential half
// answers a question nobody asked.
//
// The fold used to be reported as the difference between the two benchmarks
// here. It no longer is, and the reason is worth keeping: the fold is about a
// sixth of what ApplyBlock measures, so the difference is a small residue of
// two large, independently noisy quantities, and on a loaded machine it has
// been observed to come out negative. BenchmarkFoldLoop times the sequential
// stage directly instead. What these two are for now is the end-to-end pair
// §14 quotes — validate in X, fold in Y — and a reconciliation: fold + rules
// should land near ApplyBlock, and if it does not, one of the three is lying.
//
// The reconciliation does not close, and saying so is more useful than a
// number that pretends it does. ApplyBlock exceeds FoldLoop plus BlockRules by
// roughly the fold's own magnitude — about 3% of the total here, 5% on another
// machine. Two explanations have been tested and both are wrong: it is not
// that FoldLoop warmed its slots and these did not (Clone leaves the map hot,
// and warmed, unwarmed and post-cache-thrash folds all measure the same), and
// it is not cache eviction by the signature checks that run in between
// (evicting 64 MB between the clone and the fold changes nothing). The cause
// is unknown. The check is earning its place by refusing to reconcile.
//
// Two conditions the numbers depend on, in the spirit of "a measurement is true
// about the conditions it was taken under":
//
//   - Epoch boundaries recompute the state root from scratch over the whole
//     cell set, so a block on one is measuring a Merkle tree, not a fold. The
//     benchmarks below stay off boundaries deliberately.
//   - The working set is pre-populated with real balance cells, because a fold
//     over an empty map measures Go's map growth rather than steady-state slot
//     access.
//
// The largest block size here is 2,900 certificates and not the parameter set's
// MAX_CERTS_PER_BLOCK of 4,000, because a block of 4,000 ordinary transfers does
// not exist: at ~848 bytes each it is 3.4 MB against a BLOCK_BYTE_LIMIT of 2.5
// MB. **For this certificate shape the byte ceiling binds first, and the
// certificate ceiling is not reachable.** Which of the two limits actually binds
// is a fact about the parameters that only shows up when something tries to
// build a full block; it is recorded here because a benchmark claiming to
// measure a full block should measure one that could be mined.
//
// One methodological warning, measured rather than assumed. Running this whole
// suite in a single process contaminates whatever runs last: the same
// single-signature verification measures ~70 µs alone and cold, and ~117 µs
// after twelve seconds of sustained load in the same process — a 65% error, all
// of it systematic, none of it visible in the variance of a single pass.
// Publishable figures come from running one benchmark per process (RELEASE.md
// §8), not from reading a `make bench` transcript top to bottom.

// benchKey is the test suite's key helper widened to a 64-bit seed. The shared
// one repeats a single byte, which is exactly right for a test naming a handful
// of actors and useless for a benchmark that needs four thousand distinct
// signers. Still fully deterministic: a benchmark that cannot be reproduced
// from source is not evidence.
func benchKey(b *testing.B, n uint64) *wallet.Key {
	b.Helper()
	seed := make([]byte, 32)
	for i := 0; i < 8; i++ {
		seed[i] = byte(n >> (8 * i))
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		b.Fatal(err)
	}
	return k
}

// benchParams is mainnet with a trivially easy target: the ceilings that bound
// a real block are mainnet's, and those are what the published figure should
// be taken under.
func benchParams() *params.Params {
	p := spec.Mainnet()
	p.GenesisTarget = u256.Max
	return p
}

// populate fills a state with n native balance cells, so the fold's slot
// access is measured against a working set of a stated size rather than
// against whatever the test happened to leave behind.
func populate(s *state.State, n int) {
	for i := 0; i < n; i++ {
		var addr types.Address
		addr[0] = 0x02
		addr[1] = byte(i)
		addr[2] = byte(i >> 8)
		addr[3] = byte(i >> 16)
		s.Set(types.NativeBalanceSlot(addr), u256.FromUint64(1_000_000_000))
	}
}

// benchBlock builds a block of n transfers and the state it applies against,
// funded so that every certificate applies. Returns the state, the block, and
// the number of declared slot operations the fold will perform on it.
func benchBlock(b *testing.B, p *params.Params, n, workingSet int) (*state.State, *types.Block, int) {
	b.Helper()

	s := state.New()
	populate(s, workingSet)
	// The protocol cells genesis writes and every later block reads. This
	// state is built by hand rather than by folding block 0, so anything the
	// fold expects to find already there has to be seeded here — and the
	// failure mode when one is missing is not subtle but it is misleading:
	// an absent cell reads as zero, so a missing sequential target makes
	// every derived ceiling zero and the block is rejected for holding "100
	// certificates, ceiling 0" rather than for the thing that is actually
	// wrong.
	s.Set(types.SeqBaseFeeSlot(), p.InitialSeqBaseFee)
	s.Set(types.ParBaseFeeSlot(), p.InitialParBaseFee)
	s.Set(types.SeqGasTargetSlot(), u256.FromUint64(p.SeqGasTargetGenesis))

	dst := benchKey(b, 9_000_001).Persistent()
	certs := make([]*types.Certificate, n)
	slotOps := 0
	for i := 0; i < n; i++ {
		signer := benchKey(b, uint64(3_000_000+i))
		addr := signer.Persistent()
		bld := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, addr, dst, drops(1_000)),
			TTL:     240,
			Deposit: wallet.SelfDeposit(addr, addr),
			FeeBid:  wallet.Bid(drops(2_000), drops(10), drops(200), drops(10)),
			Signers: []*wallet.Key{signer},
		}
		c, err := bld.Build()
		if err != nil {
			b.Fatal(err)
		}
		ceiling, ok := c.FeeCeiling(p)
		if !ok {
			b.Fatal("ceiling overflow")
		}
		s.Set(types.NativeBalanceSlot(addr), ceiling.SatAdd(drops(1_000_000_000)))
		certs[i] = c
		slotOps += len(c.Reads) + len(c.Writes)
	}

	// Height 1 is not an epoch boundary on any parameter set worth measuring,
	// so no state root is computed and the fold is the whole of the work.
	blk := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       1,
			ParentID:     types.Hash{1},
			Time:         p.GenesisTime + p.TargetBlockSeconds,
			EmissionAddr: benchKey(b, 9_000_002).Persistent(),
			Target:       p.GenesisTarget,
		},
		Certs: certs,
	}
	blk.Header.CertRoot = blk.ComputeCertRoot(p)
	blk.Header.CitesRoot = blk.ComputeCitesRoot(p)
	return s, blk, slotOps
}

// BenchmarkApplyBlock times everything a node does to commit a block: the
// stateless checks and the sequential fold together.
func BenchmarkApplyBlock(b *testing.B) {
	p := benchParams()
	for _, n := range []int{100, 1000, 2900} {
		b.Run(certCount(n), func(b *testing.B) {
			s, blk, slotOps := benchBlock(b, p, n, 100_000)
			b.ReportMetric(float64(slotOps), "slotops/block")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				work := s.Clone()
				b.StartTimer()
				if _, err := fold.ApplyBlock(work, blk, p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBlockRules times the stateless half alone — the part that is
// embarrassingly parallel and that a real node runs on a worker pool before the
// sequential pass ever starts.
//
// It clones per iteration even though CheckBlockRules mutates nothing, purely
// so that its cache conditions match BenchmarkApplyBlock's. They did not
// before: ApplyBlock folded into a freshly cloned map while this ran hot over
// the same one, and the difference between them — once used as the fold's
// figure — collected that asymmetry as if it were fold work.
func BenchmarkBlockRules(b *testing.B) {
	p := benchParams()
	for _, n := range []int{100, 1000, 2900} {
		b.Run(certCount(n), func(b *testing.B) {
			s, blk, _ := benchBlock(b, p, n, 100_000)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				work := s.Clone()
				b.StartTimer()
				if err := fold.CheckBlockRules(work, blk, p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func certCount(n int) string { return "certs=" + itoa(n) }
func cellCount(n int) string { return "cells=" + itoa(n) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
