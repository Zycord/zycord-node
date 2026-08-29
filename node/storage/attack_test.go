package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Adversarial suite for the multi-record transaction, written by a
// reviewer trying to break the atomicity claim rather than to demonstrate it.

// attackKeys are the twelve keys a three-part group writes, in order.
func attackKeys() []string {
	var out []string
	for p := 0; p < 3; p++ {
		for i := 0; i < 4; i++ {
			out = append(out, fmt.Sprintf("part-%d-key-%d", p, i))
		}
	}
	return out
}

// buildAttackLog returns the raw bytes of a log holding, in order: an
// ordinary commit ("before"), a three-record group (gen-1), and another
// ordinary commit ("after"). Sequence numbers 0..4.
func buildAttackLog(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	before := &Batch{}
	before.Put([]byte("before"), []byte("v0"))
	if err := s.Commit(before); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitGroup(groupParts(3, 1)); err != nil {
		t.Fatal(err)
	}
	after := &Batch{}
	after.Put([]byte("after"), []byte("v4"))
	if err := s.Commit(after); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// assertNoSubset opens a store over the supplied log and demands that the
// visible state is one of the four legal prefixes of the write history. Any
// other shape — above all a strict subset of the group's twelve keys — is the
// failure the whole design exists to make unreachable.
func assertNoSubset(t *testing.T, raw []byte, what string) (opened bool) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, Options{})
	if err != nil {
		// A refusal is always a safe answer.
		return false
	}
	defer s.Close()

	present := 0
	for _, k := range attackKeys() {
		v, ok := s.Get([]byte(k))
		if !ok {
			continue
		}
		present++
		if string(v) != "gen-1" {
			t.Fatalf("%s: key %s = %q, want gen-1", what, k, v)
		}
	}
	if present != 0 && present != len(attackKeys()) {
		t.Fatalf("%s: %d of %d group keys are visible — a STRICT SUBSET of one "+
			"transaction was applied", what, present, len(attackKeys()))
	}
	_, hasBefore := s.Get([]byte("before"))
	_, hasAfter := s.Get([]byte("after"))
	if present > 0 && !hasBefore {
		t.Fatalf("%s: the group is visible but the commit before it is not", what)
	}
	if hasAfter && present == 0 {
		t.Fatalf("%s: the commit after the group is visible but the group is not — "+
			"a later record completed or skipped an abandoned transaction", what)
	}
	if hasAfter && !hasBefore {
		t.Fatalf("%s: the last commit is visible but the first is not", what)
	}
	return true
}

// TestAttackBitFlipAnywhereNeverAppliesASubset flips every single bit of a
// log that interleaves ordinary commits with a three-record transaction, and
// demands after each one that replay either refuses or shows a whole-history
// prefix. This is post-fsync corruption: the writer did everything right and
// the medium lied afterwards.
func TestAttackBitFlipAnywhereNeverAppliesASubset(t *testing.T) {
	base := buildAttackLog(t)
	opens := 0
	for i := range base {
		for bit := 0; bit < 8; bit++ {
			raw := append([]byte(nil), base...)
			raw[i] ^= 1 << bit
			if assertNoSubset(t, raw, fmt.Sprintf("bit %d of byte %d", bit, i)) {
				opens++
			}
		}
	}
	t.Logf("%d single-bit corruptions: %d opened, %d refused", len(base)*8, opens, len(base)*8-opens)
}

// setMore rewrites the remaining-part count of the record starting at off and
// repairs both checksums, so the forgery is indistinguishable from something
// a writer produced on purpose. A bit flip cannot do this; a buggy writer, a
// different build, or an attacker with the file can.
func setMore(t *testing.T, raw []byte, off int, more uint32) {
	t.Helper()
	rec := raw[off:]
	binary.LittleEndian.PutUint32(rec[recordMoreOff:], more)
	binary.LittleEndian.PutUint32(rec[recordHdrCRCOff:], crc32.ChecksumIEEE(rec[:recordHdrCRCOff]))
	length := binary.LittleEndian.Uint64(rec[recordLenOff:])
	h := crc32.NewIEEE()
	h.Write(rec[:recordCRCOff])
	h.Write(rec[recordHeaderLen : recordHeaderLen+int(length)])
	binary.LittleEndian.PutUint32(rec[recordCRCOff:], h.Sum32())
}

// recordOffsets walks a log and returns where each record starts.
func recordOffsets(t *testing.T, raw []byte) []int {
	t.Helper()
	var offs []int
	for off := 0; off < len(raw); {
		_, _, _, n, status := decodeRecord(raw[off:])
		if status != decodeOK {
			t.Fatalf("record at %d does not decode: %v", off, status)
		}
		offs = append(offs, off)
		off += n
	}
	return offs
}

// TestAttackForgedMoreFieldNeverAppliesASubset re-signs a forged
// remaining-part count on every record, for every plausible value. The header
// checksum is no defence here — the forgery recomputes it — so the only thing
// standing between this log and a partially applied transaction is the
// countdown check in replay.
func TestAttackForgedMoreFieldNeverAppliesASubset(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	for _, off := range offs {
		for _, more := range []uint32{0, 1, 2, 3, 4, 7, 1 << 20, ^uint32(0)} {
			raw := append([]byte(nil), base...)
			setMore(t, raw, off, more)
			assertNoSubset(t, raw, fmt.Sprintf("record at %d forged to more=%d", off, more))
		}
	}
}

// TestAttackForgedMoreOnTwoRecords is the same forgery applied to a pair at a
// time, so a countdown that stays self-consistent while describing a
// transaction nobody wrote is reachable.
func TestAttackForgedMoreOnTwoRecords(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	for a := range offs {
		for b := range offs {
			if a == b {
				continue
			}
			for _, pair := range [][2]uint32{{1, 0}, {2, 1}, {3, 2}, {2, 0}, {1, 1}} {
				raw := append([]byte(nil), base...)
				setMore(t, raw, offs[a], pair[0])
				setMore(t, raw, offs[b], pair[1])
				assertNoSubset(t, raw, fmt.Sprintf("records %d,%d forged to more=%v", a, b, pair))
			}
		}
	}
}

// TestAttackTruncationAtEveryOffsetOfTheWholeLog cuts the log at every byte
// offset — a crash that lost an arbitrary suffix — and demands the same
// prefix property. This covers the sequence store-crash-restart with no
// writer cooperation at all.
func TestAttackTruncationAtEveryOffsetOfTheWholeLog(t *testing.T) {
	base := buildAttackLog(t)
	for cut := 0; cut <= len(base); cut++ {
		assertNoSubset(t, base[:cut], fmt.Sprintf("truncated at %d", cut))
	}
}

// TestAttackAbandonedGroupBytesFollowedByAnOrdinaryCommit probes the one
// on-disk shape replay cannot defend against on its own: a transaction's
// non-final parts with an unrelated later commit written behind them, whose
// record then acts as a commit record for a transaction nobody committed.
//
// Replay HAS no group identity — no group id, no "this record belongs to
// transaction X" — so it folds them. The whole defence is that the shape is
// unreachable: a fault poisons the store so this process appends nothing
// more, and the next Open truncates the parts away before a byte is written
// on top of them. This test documents the dependency rather than asserting a
// bug; TestAttackAbandonedGroupBytesAreGoneBeforeAnythingIsAppended below is
// the reachability half.
func TestAttackAbandonedGroupBytesFollowedByAnOrdinaryCommit(t *testing.T) {
	dir := t.TempDir()
	parts := groupParts(3, 1)

	var raw []byte
	for i := 0; i < 2; i++ {
		rec, err := encodeRecord(parts[i], uint64(i), uint32(3-1-i))
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, rec...)
	}
	later := &Batch{}
	later.Put([]byte("later"), []byte("unrelated"))
	rec, err := encodeRecord(later, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, rec...)
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, Options{})
	if err != nil {
		t.Logf("refused: %v", err)
		return
	}
	defer s.Close()
	seen := 0
	for _, k := range attackKeys()[:8] {
		if _, ok := s.Get([]byte(k)); ok {
			seen++
		}
	}
	t.Logf("hand-written abandoned parts + a later ordinary commit: %d/8 abandoned "+
		"mutations applied. Replay carries no group identity, so truncate-at-open is "+
		"the ONLY thing preventing this.", seen)
}

// TestAttackAbandonedGroupBytesAreGoneBeforeAnythingIsAppended is the
// reachability half: after a crash inside a group, the very next Open must
// cut the file back to the transaction's first record, so the shape above
// cannot exist by the time any writer appends.
func TestAttackAbandonedGroupBytesAreGoneBeforeAnythingIsAppended(t *testing.T) {
	for stop := 1; stop <= 2; stop++ {
		dir := t.TempDir()
		s, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		pre := &Batch{}
		pre.Put([]byte("pre"), []byte("kept"))
		if err := s.Commit(pre); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, logName))
		if err != nil {
			t.Fatal(err)
		}
		groupStart := info.Size()

		n := 0
		s.writeHook = func(r []byte) ([]byte, error) {
			if n < stop {
				n++
				return r, nil
			}
			return r[:len(r)/2], errCrash
		}
		if err := s.CommitGroup(groupParts(3, 1)); !errors.Is(err, errCrash) {
			t.Fatalf("expected the crash, got %v", err)
		}
		s.crashClose()
		s.lock.release()

		re, err := Open(dir, Options{})
		if err != nil {
			t.Fatalf("stop=%d: reopen: %v", stop, err)
		}
		info, err = os.Stat(filepath.Join(dir, logName))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != groupStart {
			t.Fatalf("stop=%d: after reopening, the log is %d bytes; the abandoned "+
				"transaction started at %d and must have been cut away before "+
				"anything could be appended behind it", stop, info.Size(), groupStart)
		}
		re.Close()
	}
}

// TestAttackCrashRestartCommitRestartCrashRestart runs the full cycle the
// review asked for: crash inside a group, restart, commit, restart, crash
// inside another group, restart. At every stage exactly the committed history
// must be visible and nothing else.
func TestAttackCrashRestartCommitRestartCrashRestart(t *testing.T) {
	dir := t.TempDir()

	crashInGroup := func(afterRecords int, gen int) {
		t.Helper()
		s, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		s.writeHook = func(record []byte) ([]byte, error) {
			if n < afterRecords {
				n++
				return record, nil
			}
			return record[:len(record)/2], errCrash
		}
		if err := s.CommitGroup(groupParts(3, gen)); !errors.Is(err, errCrash) {
			t.Fatalf("expected the simulated crash, got %v", err)
		}
		// A hard crash: no Close, so nothing else is written.
		s.crashClose()
		s.lock.release()
	}

	// 1. A real commit that must survive everything below.
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &Batch{}
	b.Put([]byte("k1"), []byte("v1"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 2. Crash part-way through a group.
	crashInGroup(1, 7)

	// 3. Restart, and commit on top of the repaired log.
	s, err = Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertGeneration(t, s, 3, "")
	b2 := &Batch{}
	b2.Put([]byte("k2"), []byte("v2"))
	if err := s.Commit(b2); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 4. Restart, crash inside a second group at a different point.
	s, err = Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	crashInGroup(2, 8)

	// 5. Final restart.
	final, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("final reopen: %v", err)
	}
	defer final.Close()
	assertGeneration(t, final, 3, "")
	for k, want := range map[string]string{"k1": "v1", "k2": "v2"} {
		v, ok := final.Get([]byte(k))
		if !ok || string(v) != want {
			t.Fatalf("%s = %q,%v after two crashes; want %q — a committed record was eaten "+
				"by the repair of an abandoned transaction", k, v, ok, want)
		}
	}
	// And the repaired log is usable again.
	b3 := &Batch{}
	b3.Put([]byte("k3"), []byte("v3"))
	if err := final.Commit(b3); err != nil {
		t.Fatal(err)
	}
}

// TestAttackGroupAtEveryCrashOffsetWithSurroundingCommits is
// TestCommitGroupIsAllOrNothingAtEveryOffset with ordinary commits on both
// sides, so the repair has real data in front of it to eat and the sequence
// space is not starting at zero.
func TestAttackGroupAtEveryCrashOffsetWithSurroundingCommits(t *testing.T) {
	total := 0
	for i, b := range groupParts(3, 1) {
		rec, err := encodeRecord(b, uint64(i+1), uint32(3-1-i))
		if err != nil {
			t.Fatal(err)
		}
		total += len(rec)
	}

	for offset := 0; offset <= total; offset++ {
		dir := t.TempDir()
		s, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		pre := &Batch{}
		pre.Put([]byte("pre"), []byte("kept"))
		if err := s.Commit(pre); err != nil {
			t.Fatal(err)
		}
		budget := offset
		s.writeHook = func(record []byte) ([]byte, error) {
			if budget >= len(record) {
				budget -= len(record)
				return record, nil
			}
			out := record[:budget]
			budget = 0
			return out, errCrash
		}
		err = s.CommitGroup(groupParts(3, 1))
		landed := offset == total
		if landed && err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		if !landed && !errors.Is(err, errCrash) {
			t.Fatalf("offset %d: expected the crash, got %v", offset, err)
		}
		s.crashClose()
		s.lock.release()

		re, err := Open(dir, Options{})
		if err != nil {
			t.Fatalf("offset %d: reopen: %v", offset, err)
		}
		if v, ok := re.Get([]byte("pre")); !ok || string(v) != "kept" {
			t.Fatalf("offset %d: the commit before the group was destroyed by the repair", offset)
		}
		want := ""
		if landed {
			want = "gen-1"
		}
		assertGeneration(t, re, 3, want)
		// The repaired log must still accept writes and survive another trip.
		post := &Batch{}
		post.Put([]byte("post"), []byte("ok"))
		if err := re.Commit(post); err != nil {
			t.Fatalf("offset %d: commit after repair: %v", offset, err)
		}
		if err := re.Close(); err != nil {
			t.Fatal(err)
		}
		re2, err := Open(dir, Options{})
		if err != nil {
			t.Fatalf("offset %d: second reopen: %v", offset, err)
		}
		if v, ok := re2.Get([]byte("post")); !ok || string(v) != "ok" {
			t.Fatalf("offset %d: the post-repair commit did not survive", offset)
		}
		assertGeneration(t, re2, 3, want)
		re2.Close()
	}
}

// TestAttackStickyFailureStillHoldsForTheOrdinarySingleRecordPath is a
// regression guard for the sticky-failure rule against the Commit ->
// commitOneLocked refactor: one failed write must poison the store for every
// later Commit, CommitGroup and Compact, in this process, until it is reopened.
func TestAttackStickyFailureStillHoldsForTheOrdinarySingleRecordPath(t *testing.T) {
	for _, mode := range []string{"write", "sync"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()

			armed := true
			if mode == "write" {
				s.writeHook = func(record []byte) ([]byte, error) {
					if armed {
						armed = false
						return record[:3], errCrash
					}
					return record, nil
				}
			} else {
				inner := s.sync
				s.sync = func(f *os.File) error {
					if armed {
						armed = false
						return errCrash
					}
					return inner(f)
				}
			}

			b := &Batch{}
			b.Put([]byte("a"), []byte("1"))
			if err := s.Commit(b); !errors.Is(err, errCrash) {
				t.Fatalf("expected the injected failure, got %v", err)
			}
			// Every later durability call is refused, and the refusal names
			// the original fault.
			b2 := &Batch{}
			b2.Put([]byte("b"), []byte("2"))
			if err := s.Commit(b2); !errors.Is(err, errCrash) {
				t.Fatalf("Commit after a %s failure returned %v — the store was not poisoned", mode, err)
			}
			if err := s.CommitGroup(groupParts(3, 1)); !errors.Is(err, errCrash) {
				t.Fatalf("CommitGroup after a %s failure returned %v", mode, err)
			}
			if err := s.Compact(); !errors.Is(err, errCrash) {
				t.Fatalf("Compact after a %s failure returned %v", mode, err)
			}
			if _, ok := s.Get([]byte("b")); ok {
				t.Fatal("a refused commit became visible")
			}
		})
	}
}

// TestAttackCommitGroupPoisonsAtEveryStage checks the same for every point a
// group can fail: inside a non-final part, at the barrier fsync, inside the
// commit record, and at the final fsync.
func TestAttackCommitGroupPoisonsAtEveryStage(t *testing.T) {
	stages := []struct {
		name string
		// mayLandAnyway: the failure happened at or after the point where
		// every byte of the transaction, commit record included, was already
		// in the file. An fsync that reports an error may still have made
		// them durable — the ordinary single-record Commit path has always
		// had exactly this ambiguity — so a restart is allowed to see the
		// whole transaction. It is never allowed to see part of one.
		mayLandAnyway bool
		setup         func(s *Store)
	}{
		{"first part", false, func(s *Store) {
			s.writeHook = func(r []byte) ([]byte, error) { return r[:1], errCrash }
		}},
		{"second part", false, func(s *Store) {
			n := 0
			s.writeHook = func(r []byte) ([]byte, error) {
				if n == 0 {
					n++
					return r, nil
				}
				return r[:1], errCrash
			}
		}},
		{"barrier fsync", false, func(s *Store) {
			s.sync = func(f *os.File) error { return errCrash }
		}},
		{"commit record", false, func(s *Store) {
			n := 0
			s.writeHook = func(r []byte) ([]byte, error) {
				if n < 2 {
					n++
					return r, nil
				}
				return r[:1], errCrash
			}
		}},
		{"final fsync", true, func(s *Store) {
			n := 0
			inner := s.sync
			s.sync = func(f *os.File) error {
				n++
				if n == 1 {
					return inner(f)
				}
				return errCrash
			}
		}},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			st.setup(s)
			if err := s.CommitGroup(groupParts(3, 1)); !errors.Is(err, errCrash) {
				t.Fatalf("expected the injected failure, got %v", err)
			}
			assertGeneration(t, s, 3, "")
			b := &Batch{}
			b.Put([]byte("after"), []byte("x"))
			if err := s.Commit(b); !errors.Is(err, errCrash) {
				t.Fatalf("the store accepted a commit after a group failed at the %s: %v", st.name, err)
			}
			s.crashClose()
			s.lock.release()

			re, err := Open(dir, Options{})
			if err != nil {
				t.Fatalf("reopen after failure at the %s: %v", st.name, err)
			}
			defer re.Close()
			want := ""
			if st.mayLandAnyway {
				if _, ok := re.Get([]byte(attackKeys()[0])); ok {
					want = "gen-1"
				}
			}
			assertGeneration(t, re, 3, want)
			if _, ok := re.Get([]byte("after")); ok {
				t.Fatal("a refused commit survived a restart")
			}
		})
	}
}

// TestAttackInteriorCorruptionInsideAGroupIsRefusedNotRepaired guards the tail
// discriminator for the group path: damage inside a transaction with intact
// records after it is interior corruption, and must never be "repaired" by
// deleting the intact records behind it.
func TestAttackInteriorCorruptionInsideAGroupIsRefusedNotRepaired(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	// offs[1..3] is the group; damage the payload of each in turn, leaving
	// the trailing ordinary commit intact.
	for _, i := range []int{1, 2, 3} {
		raw := append([]byte(nil), base...)
		raw[offs[i]+recordHeaderLen] ^= 0xff
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir, Options{})
		if err == nil {
			s.Close()
			t.Fatalf("record %d: a log with interior corruption and an intact record "+
				"behind it opened cleanly", i)
		}
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("record %d: got %v, want ErrCorrupt", i, err)
		}
		// The discriminator, not the wording. Each of these three records has a
		// verified frame and a damaged payload, so replayLog searches from past
		// the record's declared end and a hit really is data some writer
		// produced after it — which is the only reason this refuses instead of
		// truncating. Opening the operator's second door split that message in
		// two, because the same sentence was false for the other half (a frame
		// that failed its own checksum forces the search to begin *inside* the
		// record, where a hit may be nothing but record-shaped bytes in a block
		// body), and the wording "later, intact record" went with the split.
		// What the message has to keep saying is that an intact record was
		// found behind the damage, and that this is therefore damage inside the
		// log.
		for _, want := range []string{"intact record exists at offset", "damage inside the log"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("record %d: %v — the message does not name the discriminator (%q)",
					i, err, want)
			}
		}
	}
}

// TestAttackGroupAcrossCompaction: a compaction folds a group's records into
// the snapshot and resets the sequence space. A crash in a group written
// after that must still be all-or-nothing, and must not resurrect anything
// from before the compaction.
func TestAttackGroupAcrossCompaction(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitGroup(groupParts(3, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	if s.nextSeq != 0 {
		t.Logf("nextSeq after compaction is %d", s.nextSeq)
	}
	// Crash inside a second group that would overwrite every key.
	n := 0
	s.writeHook = func(r []byte) ([]byte, error) {
		if n < 2 {
			n++
			return r, nil
		}
		return r[:5], errCrash
	}
	if err := s.CommitGroup(groupParts(3, 2)); !errors.Is(err, errCrash) {
		t.Fatalf("expected the crash, got %v", err)
	}
	s.crashClose()
	s.lock.release()

	re, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after a crash in a post-compaction group: %v", err)
	}
	defer re.Close()
	assertGeneration(t, re, 3, "gen-1")
}

// TestAttackSizePrecheckIsExactNotMerelyConservative guards the arithmetic
// encodeRecord now uses to refuse an oversized batch before building its
// payload. A pre-check that under-counts would let an oversized record
// through to the writer; one that over-counts would refuse a legal batch.
// Neither is acceptable, so it is checked against the real encoding.
func TestAttackSizePrecheckIsExactNotMerelyConservative(t *testing.T) {
	b := &Batch{}
	for i := 0; i < 50; i++ {
		b.Put([]byte{byte(i), byte(i >> 8)}, make([]byte, i*7))
		b.Delete([]byte{byte(i)})
	}
	predicted := 0
	for _, m := range b.mutations {
		predicted += 1 + 4 + len(m.key)
		if m.op == opPut {
			predicted += 4 + len(m.value)
		}
	}
	rec, err := encodeRecord(b, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rec) - recordHeaderLen; got != predicted {
		t.Fatalf("the pre-check predicted a %d-byte payload; encodeRecord produced %d",
			predicted, got)
	}
}
