package chain_test

import (
	"testing"

	"zycord/core/types"
	"zycord/node/chain"
)

// The cost of the always-on borrow guard (R5-G2).
//
// stateref.go claims the check is worth paying for in every build because it
// costs "one atomic load per access and one small allocation per Read —
// nanoseconds against the map lookup underneath it". That is a performance claim
// in a document, which is exactly the kind of thing this project has learned not
// to take on trust. This measures it.
func BenchmarkChainRead(b *testing.B) {
	n := openNodeB(b)
	slot := types.SeqBaseFeeSlot()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Read(func(v chain.View) { _ = v.State.Get(slot) })
	}
}

// BenchmarkChainReadTenCells is the shape a real handler has: one Read, several
// accesses. The per-Read allocation amortises; the per-access atomic load does
// not, so this is where the guard would show up if it were expensive.
func BenchmarkChainReadTenCells(b *testing.B) {
	n := openNodeB(b)
	slot := types.SeqBaseFeeSlot()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Read(func(v chain.View) {
			for j := 0; j < 10; j++ {
				_ = v.State.Get(slot)
			}
		})
	}
}

// BenchmarkChainSnapshot is the owned read, for contrast: it copies the whole
// state, which is the cost Read exists to avoid.
func BenchmarkChainSnapshot(b *testing.B) {
	n := openNodeB(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.Snapshot()
	}
}

func openNodeB(b *testing.B) *chain.Chain {
	b.Helper()
	p := devnetEasy()
	c, err := chain.Open(b.TempDir(), p)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	return c
}
