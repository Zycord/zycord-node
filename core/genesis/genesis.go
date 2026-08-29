// Package genesis builds block 0.
//
// Genesis is a reproducible artifact, not a ceremony. `zcd genesis --params
// spec/params.json` emits this block and its id, in milliseconds, on any
// machine — empty state, initialised beacon and fee cells, an empty spent
// registry, and no allocation of any kind to anybody.
//
// A launch announcement commits, weeks in advance, to the code tag, the
// parameter hash, the genesis id and the launch height. Anyone can rebuild all
// four. There is nothing else to trust.
package genesis

import (
	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
)

// NetworkID is the identity two nodes must share to be on the same network:
// the genesis block id, which commits to every consensus parameter.
//
// At M2 this is what the peer handshake exchanges. A devnet block is then
// structurally unable to enter a mainnet node rather than merely unlikely to.
func NetworkID(p *params.Params) (types.Hash, error) {
	b, _, err := Build(p)
	if err != nil {
		return types.Hash{}, err
	}
	return b.Header.ID(), nil
}

// Build returns the genesis block and the state that results from folding it.
//
// The genesis block carries no proof of work: solving it would make block 0
// unreproducible without the miner's nonce, and there is no attack a genesis
// nonce prevents — a competing genesis is a different network, not a fork.
// Every later block is checked against the target this one declares.
func Build(p *params.Params) (*types.Block, *state.State, error) {
	b := &types.Block{
		Header: types.Header{
			Version: types.HeaderVersion,
			Height:  0,
			// The genesis block has no parent, so the field is free — and it
			// carries the consensus root instead (R3-1). The parameters are
			// what the chain descends from, and stating that costs zero bytes
			// in every later block.
			//
			// The consequence is the point: two nodes configured differently
			// derive different genesis ids, so they refuse each other at the
			// handshake rather than gossiping happily and diverging at the
			// first rule they disagree about.
			ParentID: p.ConsensusRoot(),
			Time:     p.GenesisTime,
			Target:   p.GenesisTarget,
		},
	}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	// Genesis cites nothing — no block at height 0 or 1 can have a sibling
	// worth citing (fold/blockrules.go's checkCites) — but the empty list
	// still has a root, and the header must commit to it like any other.
	b.Header.CitesRoot = b.ComputeCitesRoot(p)

	s := state.New()
	root, err := fold.SealStateRoot(s, b, p)
	if err != nil {
		return nil, nil, err
	}
	b.Header.StateRoot = root

	if _, err := fold.ApplyBlock(s, b, p); err != nil {
		return nil, nil, err
	}
	return b, s, nil
}
