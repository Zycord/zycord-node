package miner_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// BenchmarkAssembleIsWhatAGetjobCosts prices one Assemble() against a real
// chain, because node/stratum's `getjob` runs exactly one per call, is
// unscored, and is reachable by any connection that has logged in.
//
// The number this reports is the amplification factor of a getjob flood: the
// work one JSON line of a few dozen bytes buys on the node.
func BenchmarkAssembleIsWhatAGetjobCosts(b *testing.B) {
	p := spec.Devnet()
	c, err := chain.Open(b.TempDir(), p)
	if err != nil {
		b.Fatalf("opening a chain: %v", err)
	}
	defer c.Close()

	clock := p.GenesisTime
	m := &miner.Miner{
		Chain:  c,
		Pool:   mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{},
		Payout: [32]byte{0x02, 1, 2, 3},
		Now: func() uint64 {
			clock += p.TargetBlockSeconds
			return clock
		},
	}
	// Grow the chain so the difficulty window is populated, which is what
	// pow.NextTarget walks on every Assemble.
	for i := 0; i < int(p.DifficultyWindow)+2; i++ {
		blk, err := m.Assemble()
		if err != nil {
			b.Fatalf("assemble %d: %v", i, err)
		}
		if err := m.Seal(blk, 1<<22); err != nil {
			b.Fatalf("seal %d: %v", i, err)
		}
		if _, err := c.Apply(blk); err != nil {
			b.Fatalf("apply %d: %v", i, err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Assemble(); err != nil {
			b.Fatalf("assemble: %v", err)
		}
	}
}
