package miner

import "zycord/core/types"

// CheckDeclaredTarget exposes the unexported target re-derivation to the
// external test package, so a block whose declared target has been tampered
// with can be fed through the same check MineOneWhile runs before Chain.Apply
// without needing a full seal.
func (m *Miner) CheckDeclaredTarget(b *types.Block) error {
	return m.checkDeclaredTarget(b)
}
