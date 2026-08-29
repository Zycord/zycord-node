package chain

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"zycord/node/storage"
)

// Adversarial suite for the reorg-commit chunking, written by a reviewer.

type mut struct {
	del   bool
	key   []byte
	value []byte
}

// TestAttackBatchGroupPreservesEveryMutationExactly stages a randomised
// stream of puts and deletes through batchGroup at a range of budgets,
// commits the result to a real store, and demands the store's final content
// is byte-identical to replaying the same stream into a single batch. This
// catches a chunk boundary that drops, duplicates, or reorders a mutation —
// including the case that matters most, the same key written in two
// different parts.
func TestAttackBatchGroupPreservesEveryMutationExactly(t *testing.T) {
	for _, budget := range []int{1, 2, 7, 16, 33, 64, 1000} {
		for seed := int64(0); seed < 12; seed++ {
			rng := rand.New(rand.NewSource(seed*1000 + int64(budget)))
			var stream []mut
			for i := 0; i < 200; i++ {
				k := []byte(fmt.Sprintf("k%02d", rng.Intn(25)))
				if rng.Intn(4) == 0 {
					stream = append(stream, mut{del: true, key: k})
					continue
				}
				v := make([]byte, rng.Intn(30))
				rng.Read(v)
				stream = append(stream, mut{key: k, value: v})
			}

			restore := SetMutationBudgetForTest(budget)
			g := newBatchGroup()
			for _, m := range stream {
				if m.del {
					g.Delete(m.key)
				} else {
					g.Put(m.key, m.value)
				}
			}
			restore()

			// Reference: the same stream in one batch.
			wantDir := t.TempDir()
			ws, err := storage.Open(wantDir, storage.Options{})
			if err != nil {
				t.Fatal(err)
			}
			ref := &storage.Batch{}
			for _, m := range stream {
				if m.del {
					ref.Delete(m.key)
				} else {
					ref.Put(m.key, m.value)
				}
			}
			if err := ws.Commit(ref); err != nil {
				t.Fatal(err)
			}

			gotDir := t.TempDir()
			gs, err := storage.Open(gotDir, storage.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := g.commit(gs); err != nil {
				t.Fatalf("budget=%d seed=%d: %v", budget, seed, err)
			}

			for i := 0; i < 25; i++ {
				k := []byte(fmt.Sprintf("k%02d", i))
				wv, wok := ws.Get(k)
				gv, gok := gs.Get(k)
				if wok != gok || !bytes.Equal(wv, gv) {
					t.Fatalf("budget=%d seed=%d parts=%d: key %s is (%q,%v) chunked but "+
						"(%q,%v) unchunked — chunking changed the transaction's meaning",
						budget, seed, len(g.parts), k, gv, gok, wv, wok)
				}
			}
			ws.Close()
			gs.Close()
		}
	}
}

// TestAttackNoPartIsEmptyOrOversized: an empty part would make CommitGroup
// silently drop a record from the transaction it was told to write (it
// filters empty batches), and an oversized one would make encodeRecord refuse
// the whole reorg.
func TestAttackNoPartIsEmptyOrOversized(t *testing.T) {
	for _, budget := range []int{1, 3, 9, 40, 128} {
		restore := SetMutationBudgetForTest(budget)
		g := newBatchGroup()
		total := 0
		for i := 0; i < 300; i++ {
			g.Put([]byte(fmt.Sprintf("key-%03d", i)), make([]byte, i%37))
			total++
		}
		restore()
		sum := 0
		for i, p := range g.parts {
			if p.Len() == 0 {
				t.Fatalf("budget=%d: part %d is empty — CommitGroup drops empty batches, "+
					"so a part that is empty is a part of the transaction that vanishes", budget, i)
			}
			sum += p.Len()
		}
		if sum != total {
			t.Fatalf("budget=%d: %d mutations staged, %d landed in parts", budget, total, sum)
		}
	}
}

// TestAttackBudgetMarginAgainstMaxRecordLen is the arithmetic the margin
// comment asserts without showing.
//
// mutationBudget counts len(key)+len(value); the encoder writes 9 more bytes
// per Put and 5 more per Delete. A part is allowed to reach exactly
// mutationBudget counted bytes, so the margin is sufficient iff
//
//	mutationBudget * worstAchievableRatio <= storage.MaxRecordLen
//
// The ratio that matters is not the worst single mutation shape but the worst
// shape that can DOMINATE a part in bulk, because switchTo emits some shapes
// only in fixed proportions (the three deletes per undone block always come
// together) or in fixed tiny counts (seven metadata puts per transaction).
// Both numbers are logged, because the gap between them is the whole margin.
func TestAttackBudgetMarginAgainstMaxRecordLen(t *testing.T) {
	type shape struct {
		name    string
		counted int
		encoded int
		bulk    bool // can this shape fill an entire part on its own?
	}
	shapes := []shape{
		// writeState — each of these can be the whole content of a part, for
		// a reorg that touches enough cells / spent addresses / seen ids.
		{"cell put (c/+64 key, 32 value)", 66 + 32, 66 + 32 + 9, true},
		{"cell delete (c/+64)", 66, 66 + 5, true},
		{"spent put (s/+32 key, 1 value)", 34 + 1, 34 + 1 + 9, true},
		{"spent delete (s/+32)", 34, 34 + 5, true},
		{"seen put (n/+32 key, 8 value)", 34 + 8, 34 + 8 + 9, true},
		{"seen delete (n/+32)", 34, 34 + 5, true},
		// Per undone block: always all three, never one alone.
		{"undo delete (u/+32)", 34, 34 + 5, false},
		{"block delete (b/+32)", 34, 34 + 5, false},
		{"height delete (i/+8)", 10, 10 + 5, false},
		{"undone block triple (u/ + b/ + i/)", 34 + 34 + 10, 39 + 39 + 15, true},
		// Per applied block: header, block, height index, undo log — the
		// first two carry SSZ values of thousands of bytes, so the quad's
		// ratio is dominated by them. Modelled with the smallest plausible
		// block (a few hundred bytes) to stay pessimistic.
		{"height put (i/+8 key, 32 value)", 10 + 32, 10 + 32 + 9, false},
		{"applied block quad, tiny blocks", 34 + 300 + 34 + 300 + 42 + 34 + 100,
			39 + 300 + 39 + 300 + 51 + 39 + 100, true},
		// writeHead — exactly seven per transaction, never in bulk.
		{"meta version put (m/version, 8 value)", 9 + 8, 9 + 8 + 9, false},
	}

	worstAny, worstAnyName := 0.0, ""
	worstBulk, worstBulkName := 0.0, ""
	for _, sh := range shapes {
		r := float64(sh.encoded) / float64(sh.counted)
		t.Logf("%-42s counted=%4d encoded=%4d ratio=%.4f bulk=%v",
			sh.name, sh.counted, sh.encoded, r, sh.bulk)
		if r > worstAny {
			worstAny, worstAnyName = r, sh.name
		}
		if sh.bulk && r > worstBulk {
			worstBulk, worstBulkName = r, sh.name
		}
	}
	limit := float64(storage.MaxRecordLen) / float64(mutationBudget)
	t.Logf("worst shape overall: %.4f (%s) — not reachable in bulk", worstAny, worstAnyName)
	t.Logf("worst shape reachable in bulk: %.4f (%s)", worstBulk, worstBulkName)
	t.Logf("budget %d of MaxRecordLen %d leaves headroom for %.4fx; margin over the "+
		"worst bulk shape is %.1f%%", mutationBudget, storage.MaxRecordLen, limit,
		100*(limit/worstBulk-1))

	if worstBulk > limit {
		t.Fatalf("a part made entirely of %q encodes to %.4fx its counted size, past the "+
			"%.4fx mutationBudget leaves: such a part encodes to %d bytes and the whole "+
			"reorg fails with ErrBatchTooBig", worstBulkName, worstBulk, limit,
			int64(float64(mutationBudget)*worstBulk))
	}
}

// TestAttackRealisticReorgMixEncodesUnderTheLimit is the same question asked
// empirically: build a part right up against the budget out of the mutation
// shapes a reorg emits in their real proportions, encode it, and check the
// record fits. Scaled down (budget and limit divided by the same factor) so
// the test does not have to allocate a gigabyte.
func TestAttackRealisticReorgMixEncodesUnderTheLimit(t *testing.T) {
	const scale = 1 << 14 // 1 GiB / 16384 = 64 KiB
	budget := mutationBudget / scale
	limit := storage.MaxRecordLen / scale

	restore := SetMutationBudgetForTest(budget)
	defer restore()

	g := newBatchGroup()
	// The densest-overhead shape a reorg can produce in bulk: the three
	// deletes per undone block, one of which is the 10-byte height key.
	for i := 0; ; i++ {
		if len(g.parts) > 1 {
			break
		}
		var id [32]byte
		id[0], id[1], id[2], id[3] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24)
		g.Delete(append([]byte("u/"), id[:]...))
		g.Delete(append([]byte("b/"), id[:]...))
		g.Delete(append([]byte("i/"), make([]byte, 8)...))
	}
	// parts[0] is the one that was filled to the budget. Measure it the only
	// way the storage package exposes: commit it and read the log's size.
	dir := t.TempDir()
	st, err := storage.Open(dir, storage.Options{CompactAfterBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Commit(g.parts[0]); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := int(info.Size()) - 32 // minus the record header
	t.Logf("a full part of undone-block deletes: %d mutations, %d encoded payload bytes "+
		"against a scaled limit of %d (%.4f of it)", g.parts[0].Len(), encoded, limit,
		float64(encoded)/float64(limit))
	if encoded > limit {
		t.Fatalf("a part filled to mutationBudget encodes to %d bytes, past "+
			"storage.MaxRecordLen (%d at this scale)", encoded, limit)
	}
}
