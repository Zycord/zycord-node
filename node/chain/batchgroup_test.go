package chain

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"zycord/node/storage"
)

// TestBatchGroupSplitsWhenBudgetExceeded is a white-box unit test of the
// chunking logic switchTo relies on for a reorg too big for one storage record:
// once the current part would cross mutationBudget, a new one starts, and every
// mutation staged still lands in exactly one part — none dropped, none
// duplicated.
func TestBatchGroupSplitsWhenBudgetExceeded(t *testing.T) {
	restore := SetMutationBudgetForTest(50)
	defer restore()

	g := newBatchGroup()
	const n = 10
	for i := 0; i < n; i++ {
		g.Put([]byte(fmt.Sprintf("key-%02d", i)), make([]byte, 20))
	}

	if len(g.parts) <= 1 {
		t.Fatalf("got %d part(s) with a 50-byte budget and %d writes of ~24 bytes each, "+
			"want more than one", len(g.parts), n)
	}
	for i, p := range g.parts {
		if p.Len() == 0 {
			t.Fatalf("part %d is empty; rollIfNeeded must never start a part it leaves unused", i)
		}
	}

	total := 0
	for _, p := range g.parts {
		total += p.Len()
	}
	if total != n {
		t.Fatalf("parts hold %d mutations total, want %d: chunking dropped or duplicated one", total, n)
	}
}

// TestBatchGroupSingleSmallBatchStaysOnePart: ordinary usage — a handful of
// small mutations well under the budget — must not split at all, which is
// what keeps the fast path (batchGroup.commit calling Store.Commit rather
// than Store.CommitGroup) actually fast for every ordinary block.
func TestBatchGroupSingleSmallBatchStaysOnePart(t *testing.T) {
	g := newBatchGroup()
	g.Put([]byte("a"), []byte("1"))
	g.Put([]byte("b"), []byte("2"))
	g.Delete([]byte("c"))

	if len(g.parts) != 1 {
		t.Fatalf("got %d parts for three small mutations under the default budget, want 1", len(g.parts))
	}
}

// TestTheEscapeExpansionLeavesMutationBudgetUnderMaxRecordLen is the bound
// the magic-escaping decision has to close, and it closes with the constants
// as they stand.
//
// The storage layer escapes recordMagic out of every payload it writes, which
// expands it by up to 5/4. If the largest part this group can build could then
// cross storage.MaxRecordLen, an ordinary reorg over blocks that were valid on
// the wire would fail the commit with ErrBatchTooBig — a liveness failure
// needing the operator, which is LAUNCH.md §3 case 4, bought to close a
// storage bug. The escape would have stopped being a node-local change.
//
// Two things had to hold, and both are measured here rather than argued:
//
//  1. g.size is the encoded payload length EXACTLY, not an estimate of it with
//     the per-mutation overhead left to a margin. It used to be the latter.
//  2. mutationBudget * 5/4 <= MaxRecordLen.
//
// The rival reading this has to rule out is the one that made the old margin
// look sufficient: that the overhead is "small" relative to real keys. That is
// true of node/chain's 34- and 66-byte keys and false of a one-byte key, and a
// bound that holds only for the key sizes somebody had in mind is a bound that
// breaks when a key size changes. Counting the overhead removes the dependence
// instead of sizing a margin against it.
func TestTheEscapeExpansionLeavesMutationBudgetUnderMaxRecordLen(t *testing.T) {
	const escapeNumerator, escapeDenominator = 5, 4
	worst := mutationBudget + mutationBudget/escapeDenominator
	if worst > storage.MaxRecordLen {
		t.Fatalf("the largest part this group can build is %d bytes of payload, which the "+
			"escape can expand to %d, past storage.MaxRecordLen (%d). A reorg over valid "+
			"blocks would fail with ErrBatchTooBig. Lower mutationBudget or re-derive the "+
			"escape's expansion; do not widen MaxRecordLen, which is the bound that stops a "+
			"corrupt length field from allocating arbitrarily.",
			mutationBudget, worst, storage.MaxRecordLen)
	}
	t.Logf("mutationBudget %d, worst escaped %d, MaxRecordLen %d (%d%% of the limit)",
		mutationBudget, worst, storage.MaxRecordLen, 100*worst/storage.MaxRecordLen)

	// The header length is measured off the store rather than restated, so a
	// framing change moves this test's arithmetic with it instead of leaving
	// it quietly reading the wrong bytes (rule 24).
	one := logSizeAfter(t, [][2][]byte{{[]byte("kkkkkkkk"), []byte("vvvvvvvv")}})
	two := logSizeAfter(t, [][2][]byte{
		{[]byte("kkkkkkkk"), []byte("vvvvvvvv")},
		{[]byte("KKKKKKKK"), []byte("VVVVVVVV")},
	})
	header := 2*one - two
	if header <= 0 || header >= one {
		t.Fatalf("the record header measured %d bytes against a %d-byte log; the calibration "+
			"below would be nonsense", header, one)
	}

	// (1) Exactness. A mix of puts and deletes, with no 'C','A','P' anywhere,
	// so the escape is a no-op and g.size is comparable to the bytes on disk.
	g := newBatchGroup()
	g.Put([]byte("kkkkkkkkkkkk"), []byte("vvvv"))
	g.Delete([]byte("dddddddd"))
	g.Put([]byte("kkkk"), bytes.Repeat([]byte{0x11}, 300))
	if len(g.parts) != 1 {
		t.Fatalf("the fixture split into %d parts; it is sized to stay in one", len(g.parts))
	}
	onDisk := commitAndSize(t, g.parts[0]) - header
	if onDisk != g.size {
		t.Fatalf("the group accounted %d payload bytes and the store wrote %d. The budget "+
			"bounds what it counts, so a difference is exactly the margin this test exists "+
			"to remove", g.size, onDisk)
	}

	// (2) Direction, and the anti-vacuity for the ratio above: with the magic
	// dense in a value the store writes MORE than the group counted, and the
	// excess must stay inside 5/4. A fixture where the escape never fired would
	// make the equality above look like the whole story.
	dense := newBatchGroup()
	dense.Put([]byte("kkkkkkkkkkkk"), bytes.Repeat([]byte{'C', 'A', 'P', 4}, 256))
	grown := commitAndSize(t, dense.parts[0]) - header
	if grown <= dense.size {
		t.Fatalf("a payload of repeated magic did not grow (%d counted, %d written), so the "+
			"escape never fired and the 5/4 factor above is untested here", dense.size, grown)
	}
	if grown > dense.size*escapeNumerator/escapeDenominator {
		t.Fatalf("a payload of %d counted bytes was written as %d, past the %d/%d the budget "+
			"is derived against", dense.size, grown, escapeNumerator, escapeDenominator)
	}
	t.Logf("accounting exact at %d bytes; a magic-dense payload grew %d -> %d, inside 5/4",
		g.size, dense.size, grown)
}

// logSizeAfter commits one batch of the given mutations to a fresh store and
// returns the log's size.
func logSizeAfter(t *testing.T, muts [][2][]byte) int {
	t.Helper()
	b := &storage.Batch{}
	for _, m := range muts {
		b.Put(m[0], m[1])
	}
	return commitAndSize(t, b)
}

func commitAndSize(t *testing.T, b *storage.Batch) int {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}
