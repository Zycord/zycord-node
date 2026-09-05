package storage_test

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"zycord/node/storage"
)

// The store under concurrent access.
//
// The property the store actually offers is **per-read atomicity**: a single
// Get, Has or ScanPrefix never observes a batch half-applied, because Commit
// holds the write lock from the fsync through to the in-memory apply.
//
// It does *not* offer cross-call consistency, and the first version of this
// test asserted that it did — two Gets of two keys written by the same batch,
// expecting them to agree. They need not: a commit can land between the calls,
// and each call is individually correct. The test failed, and the store was
// right. Recorded here because it is a small worked example of the rule in
// CONTRIBUTING: the property has to exist before a test can observe it, and
// "this failed" is not the same as "this is broken".
//
// Callers that need several keys consistent take a lock of their own across the
// reads. That is what chain.Read is, and why it is a callback.
//
// Third of the three audits in docs/adversarial/concurrency.md §8.
func TestStoreReadsAreNeverHalfApplied(t *testing.T) {
	s, err := storage.Open(t.TempDir(), storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Every batch writes the same counter to four keys under one prefix. A
	// ScanPrefix that returns two different values has seen a partial batch.
	keys := [][]byte{[]byte("k/1"), []byte("k/2"), []byte("k/3"), []byte("k/4")}
	if err := s.Commit(batchOf(keys, 0)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const rounds = 300

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint64(1); i <= rounds; i++ {
			if err := s.Commit(batchOf(keys, i)); err != nil {
				t.Errorf("commit %d: %v", i, err)
				return
			}
		}
	}()

	var scans int
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds*2; i++ {
				var seen []uint64
				err := s.ScanPrefix([]byte("k/"), func(_, value []byte) error {
					seen = append(seen, binary.LittleEndian.Uint64(value))
					return nil
				})
				if err != nil {
					t.Errorf("scan: %v", err)
					return
				}
				if len(seen) != len(keys) {
					t.Errorf("scan returned %d keys, want %d", len(seen), len(keys))
					return
				}
				for _, v := range seen {
					if v != seen[0] {
						t.Errorf("a multi-key read observed a half-applied batch: %v", seen)
						return
					}
				}
			}
		}()
		scans++
	}
	wg.Wait()

	// Anti-vacuity: the writer must actually have been racing the readers. If
	// the commits had all landed before the scans started, every scan would
	// trivially agree and this test would prove nothing.
	final, ok := s.Get(keys[0])
	if !ok || binary.LittleEndian.Uint64(final) != rounds {
		t.Fatalf("the writer did not finish; the readers may not have raced it")
	}
}

func batchOf(keys [][]byte, v uint64) *storage.Batch {
	raw := binary.LittleEndian.AppendUint64(nil, v)
	batch := &storage.Batch{}
	for _, k := range keys {
		batch.Put(k, raw)
	}
	return batch
}

// TestGetReturnsACopyNotTheLiveValue pins a property callers outside this
// package depend on and nothing asserted.
//
// Get copies the value out of the live map rather than handing back the slice
// the store holds. Two things ride on that. A caller that mutates what it read
// must not corrupt the store — the live map is the durable state until the
// next commit, and an aliased return would let a reader silently rewrite a
// committed record. And a caller that prices work by what a read cost it (see
// node/rpc's block-byte budget, which charges len(raw) for a record it read
// and may then discard) is charging for a copy that really was made; if Get
// aliased, that accounting would bill for work the store never did.
//
// The cost is the point rather than an accident, so it is asserted here.
func TestGetReturnsACopyNotTheLiveValue(t *testing.T) {
	dir := t.TempDir()
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	original := []byte{1, 2, 3, 4}
	batch := &storage.Batch{}
	batch.Put([]byte("k"), original)
	if err := s.Commit(batch); err != nil {
		t.Fatal(err)
	}

	// Mutating what Put was handed must not reach the store either: Batch.Put
	// copies its arguments for the same reason.
	original[0] = 0xff

	got, ok := s.Get([]byte("k"))
	if !ok {
		t.Fatal("the key committed above is not there")
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("Get returned %v, want %v: Batch.Put did not copy its value, so "+
			"mutating the caller's buffer after the commit changed a committed record",
			got, []byte{1, 2, 3, 4})
	}

	// Mutating what Get returned must not reach the store.
	got[0] = 0xee
	again, ok := s.Get([]byte("k"))
	if !ok {
		t.Fatal("the key disappeared between two reads")
	}
	if !bytes.Equal(again, []byte{1, 2, 3, 4}) {
		t.Fatalf("a second Get returned %v, want %v: Get aliased the live value, so a "+
			"reader that writes to what it read rewrites a committed record — and a "+
			"caller pricing work by the length it read would be billing for a copy "+
			"the store never made", again, []byte{1, 2, 3, 4})
	}
}
