package miner

import "zycord/core/types"

// CheckDeclaredTarget exposes the unexported target re-derivation to the
// external test package, so a block whose declared target has been tampered
// with can be fed through the same check MineOneWhile runs before Chain.Apply
// without needing a full seal.
func (m *Miner) CheckDeclaredTarget(b *types.Block) error {
	return m.checkDeclaredTarget(b)
}

// SetNonceSpaceForTest narrows the nonce space so the exhaustion path can be
// reached without spending 2^32 hash evaluations, and restores it afterwards.
//
// It exists in a _test.go file on purpose: nothing in a built binary can call
// it, so the production width stays a fact of the code rather than something a
// caller could set. The exhaustion branch is unreachable on any real network —
// 2^32 RandomX hashes against a 30-second interval — and a branch that can only
// be reached by waiting for hardware to change is a branch that goes untested
// until it fires in production.
func SetNonceSpaceForTest(n uint64) func() {
	prev := nonceSpace
	nonceSpace = n
	return func() { nonceSpace = prev }
}
