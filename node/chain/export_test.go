package chain

import (
	"encoding/binary"
	"fmt"

	"zycord/node/storage"
)

// This file exists only for tests, and only to see past Chain's exported
// surface into storage.Store directly (the undo-pruning tests need to tell "the
// undo log is gone" from "the undo log was never asked for", which nothing
// exported distinguishes). Everything below is unexported and compiled only
// into test binaries.

// UndoLogPresentForTest reports whether the undo log for the block at height
// h — canonical or not — is currently present in storage. Tests use it to
// observe pruning directly instead of inferring it from reorg behaviour.
func (c *Chain) UndoLogPresentForTest(h uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, ok := c.canonicalIDAtLocked(h)
	if !ok {
		return false
	}
	return c.store.Has(hashKey(prefixUndo, id))
}

// UndoPrunedThroughForTest returns the value of metaUndoPruned (the highest
// height whose undo log has already been deleted, inclusive) and whether the
// key has been written at all.
func (c *Chain) UndoPrunedThroughForTest() (uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	raw, ok := c.store.Get([]byte(metaUndoPruned))
	if !ok || len(raw) != 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(raw), true
}

// CorruptForTest replaces the stored bytes at one of this chain's own keys, or
// deletes them, simulating the damaged local store that the three unwind
// exits exist to survive. It writes through storage.Batch exactly as a commit
// does, so what it produces is a state the engine could genuinely be reopened
// into — a lost key or an undecodable record — rather than a mock.
//
// Test-only, and deliberately not reachable from production code: nothing here
// is on Chain's exported surface (this is a _test.go file, compiled only into
// test binaries), which is the same reason the two accessors above live here.
func (c *Chain) CorruptForTest(kind string, h uint64, garbage []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	id, ok := c.canonicalIDAtLocked(h)
	if !ok {
		return fmt.Errorf("no canonical block at height %d", h)
	}
	var key []byte
	switch kind {
	case "block":
		key = hashKey(prefixBlock, id)
	case "header":
		key = hashKey(prefixHeader, id)
	case "undo":
		key = hashKey(prefixUndo, id)
	default:
		return fmt.Errorf("unknown key kind %q", kind)
	}

	batch := &storage.Batch{}
	if garbage == nil {
		batch.Delete(key)
	} else {
		batch.Put(key, garbage)
	}
	return c.store.Commit(batch)
}

// StoreVersionForTest exposes the on-disk layout version so a test can age a
// directory to the version before it.
func StoreVersionForTest() uint64 { return storeVersion }

// WriteStoreVersionForTest rewrites a closed directory's recorded layout
// version. It exists so TestAnOlderLayoutVersionRefusesToOpen can age a
// database this build actually wrote, rather than assemble one by hand and
// prove only that the assembler works.
func WriteStoreVersionForTest(dir string, version uint64) error {
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		return err
	}
	defer s.Close()
	var b storage.Batch
	b.Put([]byte(metaVersion), le64(version))
	return s.Commit(&b)
}
