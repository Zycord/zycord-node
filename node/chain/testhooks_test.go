package chain

// SetMutationBudgetForTest overrides how large a single part of a reorg's
// storage transaction may grow before switchTo's batchGroup starts a new one
// without needing a real multi-gigabyte reorg, and returns a function that
// restores the previous value.
//
// It exists so a test can force the chunked, multi-record commit path with a
// handful of small blocks, rather than needing to actually build something
// near UNDO_DEPTH * BLOCK_BYTE_CAPACITY of real block data to cross the
// production default. It is only reachable from a test binary — this file
// compiles for every package chain test, internal or external, exactly like
// any other _test.go file, and carries no production behaviour of its own.
func SetMutationBudgetForTest(n int) (restore func()) {
	old := mutationBudget
	mutationBudget = n
	return func() { mutationBudget = old }
}
