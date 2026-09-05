package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The multi-record transaction suite.
//
// CommitGroup extends the package's one guarantee — a batch is durable or it
// is absent, never partial — across more than one physical record, for a
// transition too large to fit in one (a deep reorg: node/chain forkchoice.go).
// The mechanism is a commit record: every part but the last says more of the
// transaction follows, and replay applies nothing until it reads the last.
//
// These tests attack that claim from both ends: a crash at every byte offset
// of a group, and the states a crash leaves behind on disk (an incomplete
// transaction, a torn part, a corrupted header field).

// groupParts builds a group of n batches, each holding several keys stamped
// with gen, so a partially applied transaction is visible as a mixture.
func groupParts(n, gen int) []*Batch {
	parts := make([]*Batch, n)
	for p := 0; p < n; p++ {
		b := &Batch{}
		for i := 0; i < 4; i++ {
			b.Put([]byte(fmt.Sprintf("part-%d-key-%d", p, i)), []byte(fmt.Sprintf("gen-%d", gen)))
		}
		parts[p] = b
	}
	return parts
}

// assertGeneration demands that every key of every part reads the same
// generation — the whole transaction or none of it, never a mixture.
func assertGeneration(t *testing.T, s *Store, n int, want string) {
	t.Helper()
	for p := 0; p < n; p++ {
		for i := 0; i < 4; i++ {
			key := []byte(fmt.Sprintf("part-%d-key-%d", p, i))
			v, ok := s.Get(key)
			if want == "" {
				if ok {
					t.Fatalf("%s is present (%q) but no generation should be", key, v)
				}
				continue
			}
			if !ok {
				t.Fatalf("%s is absent, want %q", key, want)
			}
			if string(v) != want {
				t.Fatalf("%s = %q, want %q — a strict subset of the transaction was applied",
					key, v, want)
			}
		}
	}
}

// TestCommitGroupIsAllOrNothingAtEveryOffset is
// TestCommitIsAllOrNothingAtEveryOffset for a transaction spanning three
// records: the process dies at every cumulative byte offset of the group,
// including inside every part and exactly on every part boundary.
func TestCommitGroupIsAllOrNothingAtEveryOffset(t *testing.T) {
	const parts = 3

	// Total encoded size, so the sweep knows how far to run.
	total := 0
	for i, b := range groupParts(parts, 1) {
		rec, err := encodeRecord(b, uint64(i), uint32(parts-1-i))
		if err != nil {
			t.Fatal(err)
		}
		total += len(rec)
	}

	for offset := 0; offset <= total; offset++ {
		t.Run(fmt.Sprintf("offset=%d", offset), func(t *testing.T) {
			dir := t.TempDir()

			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CommitGroup(groupParts(parts, 0)); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			// Die once the group has written `offset` bytes in total.
			crashed, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			budget := offset
			crashed.writeHook = func(record []byte) ([]byte, error) {
				if budget >= len(record) {
					budget -= len(record)
					return record, nil
				}
				out := record[:budget]
				budget = 0
				return out, errCrash
			}
			err = crashed.CommitGroup(groupParts(parts, 1))
			if offset == total {
				// Every byte reached the disk, so there was no crash to
				// simulate: this is the one offset where the transaction
				// legitimately lands.
				if err != nil {
					t.Fatalf("a group that wrote every byte failed: %v", err)
				}
			} else if !errors.Is(err, errCrash) {
				t.Fatalf("expected the simulated crash, got %v", err)
			}
			crashed.crashClose()
			crashed.lock.release()

			reopened, err := Open(dir, Options{})
			if err != nil {
				t.Fatalf("reopen after a crash at offset %d: %v", offset, err)
			}
			defer reopened.Close()

			// Generation 1 is visible only if the whole group landed, which
			// takes every byte of it.
			want := "gen-0"
			if offset == total {
				want = "gen-1"
			}
			assertGeneration(t, reopened, parts, want)
		})
	}
}

// TestIncompleteGroupIsNeverAppliedAndNeverCompletedLater is the failure the
// commit-record design exists to make unreachable: a transaction whose final
// record never landed must not be applied — not on the restart that finds it,
// and not on any later one, where an ordinary commit's record would otherwise
// arrive behind its parts and act as the missing commit record.
func TestIncompleteGroupIsNeverAppliedAndNeverCompletedLater(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, logName)

	// Two parts of a three-part transaction, written by hand exactly as
	// CommitGroup would have written them, and nothing else.
	var raw []byte
	for i, b := range groupParts(3, 1)[:2] {
		rec, err := encodeRecord(b, uint64(i), uint32(3-1-i))
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, rec...)
	}
	if err := os.WriteFile(logPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("an incomplete transaction is not corruption and must open: %v", err)
	}
	assertGeneration(t, s, 3, "")

	// The orphaned bytes must be gone, so that the next commit cannot land
	// behind them.
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("log is %d bytes after replay dropped an incomplete transaction, want 0",
			info.Size())
	}

	after := &Batch{}
	after.Put([]byte("after"), []byte("ordinary-commit"))
	if err := s.Commit(after); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if v, ok := reopened.Get([]byte("after")); !ok || string(v) != "ordinary-commit" {
		t.Fatalf("the commit after an incomplete transaction did not survive (ok=%v, v=%q)", ok, v)
	}
	// And the incomplete transaction still did not sneak in on the back of it.
	assertGeneration(t, reopened, 3, "")
}

// TestCorruptedMoreFieldCannotApplyASubsetOfATransaction pins the field the
// header checksum has to cover for the guarantee to mean anything.
//
// Flipping the remaining-part count of a complete group's first record — one
// well-formed wrong value, the only corruption a checksum over the payload
// alone cannot catch — would otherwise make replay treat that record as a
// whole transaction and apply it by itself.
func TestCorruptedMoreFieldCannotApplyASubsetOfATransaction(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitGroup(groupParts(3, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, logName)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(raw[recordMoreOff:]); got != 2 {
		t.Fatalf("setup: first record declares %d further parts, want 2", got)
	}
	// "This record is the whole transaction" — the lie the header checksum
	// has to catch.
	binary.LittleEndian.PutUint32(raw[recordMoreOff:], 0)
	if err := os.WriteFile(logPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, Options{})
	if err == nil {
		defer reopened.Close()
		assertGeneration(t, reopened, 3, "")
		t.Fatal("opening a log whose group header was corrupted applied part of a transaction")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt: a corrupted header with intact records behind it "+
			"is interior corruption, not a crash tail", err)
	}
}

// TestTornGroupPartPoisonsTheStore: a torn write inside a group is a
// torn write like any other, and the store must stop accepting commits rather
// than let later ones land behind bytes the next restart will truncate away.
func TestTornGroupPartPoisonsTheStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Part index 1 is torn: half its bytes reach the disk, then the write
	// errors — a partial write under ENOSPC, not a process death.
	part := 0
	s.writeHook = func(record []byte) ([]byte, error) {
		if part == 1 {
			part++
			return record[:len(record)/2], errCrash
		}
		part++
		return record, nil
	}
	if err := s.CommitGroup(groupParts(3, 1)); !errors.Is(err, errCrash) {
		t.Fatalf("setup: expected the torn write to surface an error, got %v", err)
	}
	s.writeHook = nil // the disk "recovers"; the process does not die

	survivor := &Batch{}
	survivor.Put([]byte("survivor-key"), []byte("must-not-vanish"))
	err = s.Commit(survivor)
	if err == nil {
		t.Fatal("a commit after a torn group part was accepted: the next restart's tail " +
			"repair would discard it silently")
	}
	if !errors.Is(err, errCrash) {
		t.Fatalf("got %v, want the poisoned-store error naming the original write failure", err)
	}

	s.crashClose()
	s.lock.release()

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after a torn group part: %v", err)
	}
	defer reopened.Close()
	// Nothing from the torn transaction, and nothing was ever accepted after
	// it — so there is nothing that could have been silently discarded.
	assertGeneration(t, reopened, 3, "")
	if _, ok := reopened.Get([]byte("survivor-key")); ok {
		t.Fatal("a commit the store refused is present on disk")
	}
}

// TestSingleBatchGroupIsAnOrdinaryRecord pins the common case: a group that
// needs only one record must be byte-for-byte what Commit writes, so nothing
// about the ordinary block path changes.
func TestSingleBatchGroupIsAnOrdinaryRecord(t *testing.T) {
	write := func(b *Batch) {
		b.Put([]byte("k1"), []byte("v1"))
		b.Delete([]byte("k2"))
	}

	viaCommit := t.TempDir()
	s, err := Open(viaCommit, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &Batch{}
	write(b)
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	viaGroup := t.TempDir()
	g, err := Open(viaGroup, Options{})
	if err != nil {
		t.Fatal(err)
	}
	only := &Batch{}
	write(only)
	// Empty batches are not records and must not become any.
	if err := g.CommitGroup([]*Batch{{}, only, {}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(filepath.Join(viaCommit, logName))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(viaGroup, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("a single-batch group wrote %d bytes, Commit wrote %d — the ordinary path "+
			"must be untouched", len(got), len(want))
	}
}

// TestEmptyGroupWritesNothing: a transaction with nothing in it is not a
// transaction.
func TestEmptyGroupWritesNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CommitGroup([]*Batch{{}, {}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitGroup(nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("log is %d bytes after two empty groups, want 0", info.Size())
	}
}

// TestGroupSurvivesRestartAndKeepsTheSequenceGoing checks the boring path: a
// complete group is applied on replay, and the records that follow it continue
// the same sequence space the tail discriminator depends on.
func TestGroupSurvivesRestartAndKeepsTheSequenceGoing(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitGroup(groupParts(4, 7)); err != nil {
		t.Fatal(err)
	}
	if s.nextSeq != 4 {
		t.Fatalf("nextSeq = %d after a four-record transaction, want 4", s.nextSeq)
	}
	after := &Batch{}
	after.Put([]byte("after"), []byte("yes"))
	if err := s.Commit(after); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertGeneration(t, reopened, 4, "gen-7")
	if v, ok := reopened.Get([]byte("after")); !ok || string(v) != "yes" {
		t.Fatalf("the commit after the group did not survive (ok=%v, v=%q)", ok, v)
	}
	if reopened.nextSeq != 5 {
		t.Fatalf("nextSeq = %d after replaying five records, want 5", reopened.nextSeq)
	}
}

// TestCrashInsideAGroupThenReuseOfTheLog is the sequence-space half of the
// incomplete-transaction repair: after the orphaned parts are cut away, the
// numbers they used are free again, and the next commit must reuse them
// rather than leave a hole replayLog would refuse to open across.
func TestCrashInsideAGroupThenReuseOfTheLog(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	first := &Batch{}
	first.Put([]byte("first"), []byte("committed"))
	if err := s.Commit(first); err != nil {
		t.Fatal(err)
	}

	// Die after the group's first record only.
	written := 0
	s.writeHook = func(record []byte) ([]byte, error) {
		if written == 0 {
			written++
			return record, nil
		}
		return record[:0], errCrash
	}
	if err := s.CommitGroup(groupParts(3, 1)); !errors.Is(err, errCrash) {
		t.Fatalf("expected the simulated crash, got %v", err)
	}
	s.crashClose()
	s.lock.release()

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertGeneration(t, reopened, 3, "")
	if v, ok := reopened.Get([]byte("first")); !ok || string(v) != "committed" {
		t.Fatalf("the commit before the abandoned transaction was lost (ok=%v, v=%q)", ok, v)
	}
	if reopened.nextSeq != 1 {
		t.Fatalf("nextSeq = %d after dropping an abandoned transaction, want 1 — the "+
			"sequence numbers it used are free again", reopened.nextSeq)
	}

	next := &Batch{}
	next.Put([]byte("next"), []byte("after-the-repair"))
	if err := reopened.Commit(next); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	final, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after reusing the repaired log: %v", err)
	}
	defer final.Close()
	if v, ok := final.Get([]byte("next")); !ok || string(v) != "after-the-repair" {
		t.Fatalf("the commit written after the repair did not survive (ok=%v, v=%q)", ok, v)
	}
	assertGeneration(t, final, 3, "")
}

// TestCommitRecordIsWrittenOnlyAfterItsPartsAreDurable pins the barrier in
// front of the commit record.
//
// Without it, the record that makes a transaction visible can reach stable
// storage while a part it depends on has not — a hole rather than a prefix,
// and the one crash shape the replay path is not written to survive. The
// property is checked where it is created: at the fsync, the last record must
// not be in the file yet, and every earlier one must be.
func TestCommitRecordIsWrittenOnlyAfterItsPartsAreDurable(t *testing.T) {
	const parts = 3
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sizes := make([]int, parts)
	total := 0
	for i, b := range groupParts(parts, 1) {
		rec, err := encodeRecord(b, uint64(i), uint32(parts-1-i))
		if err != nil {
			t.Fatal(err)
		}
		sizes[i] = len(rec)
		total += len(rec)
	}
	beforeCommitRecord := total - sizes[parts-1]

	// The ordering under test is now a THREE-BARRIER sequence, and the third is
	// what closed both ambiguous-cut shapes: the parts, then the commit record,
	// then the out-of-band record that the commit record's barrier RETURNED. The
	// order is the whole mechanism — a sidecar written before that barrier
	// records an intention, and both crash histories intend the same thing —
	// so the barriers are recorded in order and checked as a sequence rather
	// than counted.
	type barrier struct {
		file string
		size int64
	}
	var seen []barrier
	inner := s.sync
	s.sync = func(f *os.File) error {
		which := "other"
		switch f {
		case s.log:
			which = "log"
		case s.commits:
			which = "commits"
		}
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, barrier{which, info.Size()})
		return inner(f)
	}
	if err := s.CommitGroup(groupParts(parts, 1)); err != nil {
		t.Fatal(err)
	}
	s.sync = inner // Close's own sync is not this test's business

	want := []barrier{
		// Covers every part, and runs before the commit record is written.
		{"log", int64(beforeCommitRecord)},
		// Covers the commit record.
		{"log", int64(total)},
		// And only then the sidecar, whose size never changes.
		{"commits", commitsFileLen},
	}
	if len(seen) != len(want) {
		t.Fatalf("a %d-part transaction issued %d barriers (%v), want %d", parts,
			len(seen), seen, len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("barrier %d was %+v, want %+v — the durability ordering moved, and it is "+
				"the ordering rather than the count that makes recovery decidable",
				i+1, seen[i], want[i])
		}
	}
}

// TestAHoleInATransactionIsRefusedNotPartiallyApplied is the failure the
// barrier above prevents, forced by hand: the commit record is present and a
// part before it is not.
//
// Replay must never apply what is there. The sequence check is what catches
// it — the record after the hole is not the one expected next — and the
// answer is a refusal to open, not a repair by deletion and not a subset of
// somebody's reorg.
func TestAHoleInATransactionIsRefusedNotPartiallyApplied(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, logName)

	all := groupParts(3, 1)
	var raw []byte
	for i, b := range all {
		if i == 1 {
			continue // the hole
		}
		rec, err := encodeRecord(b, uint64(i), uint32(len(all)-1-i))
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, rec...)
	}
	if err := os.WriteFile(logPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, Options{})
	if err == nil {
		defer s.Close()
		assertGeneration(t, s, 3, "")
		t.Fatal("a transaction with a hole in it opened cleanly")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}
