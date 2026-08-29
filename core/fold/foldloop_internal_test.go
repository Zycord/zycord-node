package fold

import (
	"crypto/ed25519"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
)

// BenchmarkFoldLoop measures the sequential stage directly, which is the whole
// reason this file is inside the package rather than beside the others.
//
// The number the whitepaper's §3 and §14 publish — slot operations per second
// per core — used to be derived by subtracting BenchmarkBlockRules from
// BenchmarkApplyBlock. That method does not survive contact with a busy
// machine, and it was right to say so: the fold is about a sixth of what
// ApplyBlock measures, so the answer is a small difference between two large,
// independently noisy quantities. On a loaded host the subtraction has been
// observed to go *negative*, which is not a slow fold but a broken instrument.
// A published figure should not be an arithmetic residue.
//
// So the loop is timed on its own. applyCertificate and journal are
// unexported, and an internal benchmark reaches them without opening anything
// up for production code to misuse.
//
// Two conditions, both deliberate and both affecting how the figure reads:
//
//   - The working set is cloned per iteration, because the fold mutates and
//     applying one block twice is not a thing the protocol permits. The clone
//     is not timed. An explicit warming pass over the slots the block touches
//     used to sit here on the theory that a freshly cloned map would be cold;
//     it was measured and removed, because Clone copies every entry and leaves
//     the map hot by construction. Warm, unwarmed and post-cache-thrash all
//     measure the same, so the figure is steady-state either way.
//   - Only certificates are folded here. The maturity ring and the two base-fee
//     updates are O(1) per block against ~11k slot operations, and folding them
//     in would change the fourth significant figure while making the quantity
//     harder to name.
func BenchmarkFoldLoop(b *testing.B) {
	p := benchLoopParams()
	for _, n := range []int{100, 1000, 2900} {
		b.Run(loopLabel(n), func(b *testing.B) {
			base, certs, slotOps := loopFixture(b, p, n, 100_000)
			// The ids are computed outside the timed section on purpose, and
			// the choice needs stating because apply() computes them inside.
			// An id is blake3 over the certificate's own bytes: it consults no
			// state, depends on no ordering, and is exactly the kind of work
			// the parallel stage exists to absorb. Timing it here would report
			// hashing throughput under the name of slot throughput. What is
			// measured below is the part that genuinely cannot be moved off
			// the sequential path — the state touches.
			carried := carry(certs)
			seqBase := base.Get(types.SeqBaseFeeSlot())
			parBase := base.Get(types.ParBaseFeeSlot())

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				work := base.Clone()
				res := &Result{Undo: &state.UndoLog{}}
				j := &journal{s: work, log: res.Undo}
				b.StartTimer()

				for _, cy := range foldOrder(carried) {
					if _, _, err := applyCertificate(j, cy.cert, cy.id, p, seqBase, parBase, res); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(slotOps)*float64(b.N)/b.Elapsed().Seconds(), "slotops/s")
			b.ReportMetric(float64(slotOps), "slotops/block")
		})
	}
}

func benchLoopParams() *params.Params {
	p := spec.Mainnet()
	p.GenesisTarget = u256.Max
	return p
}

// loopFixture builds the state and the certificates the loop folds.
//
// It assembles certificates from core/validity and the standard library rather
// than from wallet.Builder, which would have been fewer lines and the wrong
// ones. This file is `package fold`, so its imports are the consensus package's
// own; reaching outward to wallet/ would point a dependency arrow the wrong way
// inside the one tree where that rule is load-bearing. The import guard would
// not have caught it — `go list -deps` does not follow test imports — which is
// a reason to be careful here rather than a reason to relax.
func loopFixture(b *testing.B, p *params.Params, n, workingSet int) (*state.State, []*types.Certificate, int) {
	b.Helper()

	s := state.New()
	for i := 0; i < workingSet; i++ {
		var addr types.Address
		addr[0] = crypto.AddrVersionPersistent
		addr[1], addr[2], addr[3] = byte(i), byte(i>>8), byte(i>>16)
		s.Set(types.NativeBalanceSlot(addr), u256.FromUint64(1_000_000_000))
	}
	s.Set(types.SeqBaseFeeSlot(), p.InitialSeqBaseFee)
	s.Set(types.ParBaseFeeSlot(), p.InitialParBaseFee)

	_, dst := loopKey(b, 9_000_001)
	certs := make([]*types.Certificate, n)
	slotOps := 0
	for i := 0; i < n; i++ {
		priv, addr := loopKey(b, uint64(3_000_000+i))
		c := loopCert(b, p, priv, addr, dst)

		ceiling, ok := c.FeeCeiling(p)
		if !ok {
			b.Fatal("ceiling overflow")
		}
		s.Set(types.NativeBalanceSlot(addr), ceiling.SatAdd(u256.FromUint64(1_000_000_000)))
		certs[i] = c
		slotOps += len(c.Reads) + len(c.Writes)
	}
	return s, certs, slotOps
}

// loopCert mirrors what a wallet does: derive the read/write set, size the
// deposit against the fee ceiling with placeholder signatures in place, then
// sign. Signatures are excluded from the signed body and fixed-width, so one
// pass settles the size and there is no fixed point to chase.
func loopCert(b *testing.B, p *params.Params, priv ed25519.PrivateKey, from, to types.Address) *types.Certificate {
	b.Helper()

	prog := types.Program{
		Kind: types.ProgramTransfer,
		Transfer: &types.TransferArgs{Moves: []types.Move{{
			Asset: types.NativeAsset, Src: from, Dst: to, Amount: u256.FromUint64(1_000),
		}}},
	}
	reads, writes, err := validity.Derive(prog, p.ChainID, 0)
	if err != nil {
		b.Fatal(err)
	}

	var pub crypto.PubKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))

	c := &types.Certificate{
		ChainID: p.ChainID,
		Program: prog,
		Reads:   reads,
		Writes:  writes,
		Deposit: types.Deposit{Cell: types.NativeBalanceSlot(from), RefundTo: types.NativeBalanceSlot(from)},
		TTL:     240,
		FeeBid: types.FeeBid{
			SeqMax: u256.FromUint64(2_000), SeqPriority: u256.FromUint64(10),
			ParMax: u256.FromUint64(200), ParPriority: u256.FromUint64(10),
		},
		Sigs: []types.Sig{{PubKey: pub}},
	}
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		b.Fatal("ceiling overflow")
	}
	c.Deposit.Amount = ceiling

	var sig types.SigBytes
	copy(sig[:], ed25519.Sign(priv, c.SigningMessage(p)))
	c.Sigs[0].Sig = sig

	if err := validity.Check(c, p); err != nil {
		b.Fatalf("the fixture built an invalid certificate: %v", err)
	}
	return c
}

// loopKey derives a deterministic key and its persistent address. A benchmark
// that cannot be reproduced from source is not evidence.
func loopKey(b *testing.B, n uint64) (ed25519.PrivateKey, types.Address) {
	b.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := 0; i < 8; i++ {
		seed[i] = byte(n >> (8 * i))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var pub crypto.PubKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return priv, crypto.DeriveAddress(crypto.AddrVersionPersistent, pub[:])
}

func loopLabel(n int) string {
	digits := []byte{}
	for v := n; v > 0; v /= 10 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
	}
	if len(digits) == 0 {
		digits = []byte{'0'}
	}
	return "certs=" + string(digits)
}

// BenchmarkCertificateID measures what the fold pays to learn a certificate's
// identity, which turned out to be a larger share of the sequential stage than
// §3's "no cryptography" would let a reader expect.
//
// The id is blake3 over the certificate's authorizing fields — the whole
// encoding with an empty signature list — so asking for it re-serialises the
// body and hashes on the order of 850 bytes. The fold asks more than once per
// certificate per block: CheckBlockRules needs it for the duplicate and seen
// checks, foldOrder needs it for the order's final tiebreak, and
// applyCertificate needs it to mark the certificate seen.
func BenchmarkCertificateID(b *testing.B) {
	p := benchLoopParams()
	_, certs, _ := loopFixture(b, p, 1, 0)
	c := certs[0]
	b.SetBytes(int64(c.SizeBytes()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idSink = c.ID()
	}
}

var idSink types.Hash

// BenchmarkFoldWorkingSet asks whether the sequential stage cares how much
// state exists. Slot access is a hash-map lookup, so §3's claim is that it does
// not, and a result that is not flat would be the more interesting finding.
//
// It used to time ApplyBlock, which could not answer the question: at a
// thousand certificates that measurement is roughly nine parts signature
// verification to one part fold, so a tenfold change in the working set moved
// it by well under a percent and the flatness said almost nothing. An outside
// run reported §3 confirmed on exactly that basis, which was generous to a
// benchmark that could not have shown the opposite. It times the fold loop now,
// where the whole quantity is slot access and the answer is legible.
func BenchmarkFoldWorkingSet(b *testing.B) {
	p := benchLoopParams()
	for _, cells := range []int{1_000, 100_000, 1_000_000} {
		b.Run(cellLabel(cells), func(b *testing.B) {
			base, certs, slotOps := loopFixture(b, p, 1000, cells)
			carried := carry(certs)
			seqBase := base.Get(types.SeqBaseFeeSlot())
			parBase := base.Get(types.ParBaseFeeSlot())

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				work := base.Clone()
				res := &Result{Undo: &state.UndoLog{}}
				j := &journal{s: work, log: res.Undo}
				b.StartTimer()

				for _, cy := range foldOrder(carried) {
					if _, _, err := applyCertificate(j, cy.cert, cy.id, p, seqBase, parBase, res); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(slotOps)*float64(b.N)/b.Elapsed().Seconds(), "slotops/s")
		})
	}
}

func cellLabel(n int) string {
	digits := []byte{}
	for v := n; v > 0; v /= 10 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
	}
	return "cells=" + string(digits)
}
