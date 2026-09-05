package storage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Second adversarial pass over the multi-record transaction. The first pass
// swept crash offsets, bit flips, forged `more` fields and poisoning. These
// attack what it did not: the compaction that CommitGroup itself triggers,
// concurrent readers across a group's two fsyncs, and what replay is willing to
// hold in memory.

// ---------------------------------------------------------------------------
// Compaction triggered by the group commit itself.
// ---------------------------------------------------------------------------

// TestAttack2GroupTriggersItsOwnCompaction: CommitGroup calls
// compactIfDueLocked at the end, exactly as Commit does. With a small
// CompactAfterBytes a single group crosses the threshold, so the snapshot is
// written and the log truncated in the same call that just wrote the
// transaction. The transaction must survive that, and the sequence space must
// be consistent for the next writer.
func TestAttack2GroupTriggersItsOwnCompaction(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitGroup(groupParts(4, 1)); err != nil {
		t.Fatal(err)
	}
	// The group is bigger than 128 bytes, so the commit must have compacted.
	if s.logBytes != 0 || s.nextSeq != 0 {
		t.Fatalf("a group that crossed the compaction threshold left logBytes=%d nextSeq=%d, "+
			"want 0/0 — compactIfDueLocked did not run after CommitGroup", s.logBytes, s.nextSeq)
	}
	assertGeneration(t, s, 4, "gen-1")

	// A second group on top of the freshly compacted log, then a hard restart.
	if err := s.CommitGroup(groupParts(4, 2)); err != nil {
		t.Fatal(err)
	}
	s.crashClose()
	s.lock.release()

	re, err := Open(dir, Options{CompactAfterBytes: 128})
	if err != nil {
		t.Fatalf("reopen after a group that compacted itself: %v", err)
	}
	defer re.Close()
	assertGeneration(t, re, 4, "gen-2")
}

// TestAttack2CompactionFailsRightAfterAGroup: the compaction that a group
// triggers can fail at any of its own steps. A failed compaction is explicitly
// documented as "not a failed commit" — the group is already durable in the
// log. So CommitGroup must still return nil, the transaction must still be
// whole after a restart, and nothing may be left in a state that makes the
// next Open refuse.
//
// The sequence-number hazard the compaction comment names is exactly
// the one a group makes worse: a group advances nextSeq by len(parts), not by
// one, so a stale nextSeq after a half-done compaction is off by more than a
// single record.
func TestAttack2CompactionFailsRightAfterAGroup(t *testing.T) {
	// syncN selects which s.sync call fails: 1 = the group's barrier,
	// but we only fault calls that happen *after* the group is durable, so
	// the group itself always succeeds. A group of 4 parts makes 2 syncs;
	// compaction makes 2 more (the snapshot tmp, and the confirming one
	// after Truncate).
	for _, faultAt := range []int{3, 4} {
		t.Run(fmt.Sprintf("sync#%d", faultAt), func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{CompactAfterBytes: 128})
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			inner := s.sync
			s.sync = func(f *os.File) error {
				n++
				if n == faultAt {
					return errCrash
				}
				return inner(f)
			}
			if err := s.CommitGroup(groupParts(4, 1)); err != nil {
				t.Fatalf("a group whose *compaction* failed returned an error: %v — "+
					"the transaction was already durable in the log", err)
			}
			if n < faultAt {
				t.Skipf("only %d sync(s) happened; fault point %d unreachable", n, faultAt)
			}
			// Visible in memory regardless.
			assertGeneration(t, s, 4, "gen-1")

			// The store must not be poisoned by a compaction failure.
			s.sync = inner
			b := &Batch{}
			b.Put([]byte("after"), []byte("x"))
			if err := s.Commit(b); err != nil {
				t.Fatalf("the store refused a commit after a failed compaction: %v", err)
			}
			s.crashClose()
			s.lock.release()

			re, err := Open(dir, Options{CompactAfterBytes: 128})
			if err != nil {
				t.Fatalf("compaction failing at sync#%d after a group left the store "+
					"unopenable: %v", faultAt, err)
			}
			defer re.Close()
			assertGeneration(t, re, 4, "gen-1")
			if _, ok := re.Get([]byte("after")); !ok {
				t.Fatal("the commit that followed a failed compaction did not survive")
			}
			if _, err := os.Stat(filepath.Join(dir, snapshotTmp)); err == nil {
				t.Fatal("a failed compaction orphaned snapshot.tmp")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Readers across the group's window.
// ---------------------------------------------------------------------------

// TestAttack2ReadersNeverSeeAHalfAppliedGroup hammers ScanPrefix from several
// goroutines while groups commit, and demands every snapshot it returns holds
// exactly one generation. CommitGroup holds the write lock across several
// record writes and two fsyncs; the claim under test is that the visibility
// boundary is the single apply loop at the end, not the individual writes.
//
// ScanPrefix is the right instrument: it collects every matching key under one
// RLock, so a mixture inside one scan can only mean the writer made a group
// visible in pieces. A loop of individual Get calls proves nothing here — each
// takes its own RLock, so seeing two generations across twenty of them is an
// ordinary interleaving, not a torn transaction. (An earlier draft of this
// test used Get that way and "failed" for exactly that reason.)
//
// Run with -race this also covers the lock discipline itself.
func TestAttack2ReadersNeverSeeAHalfAppliedGroup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CommitGroup(groupParts(5, 0)); err != nil {
		t.Fatal(err)
	}

	const gens = 40
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad []string
	var badMu sync.Mutex

	reader := func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			seen := map[string]int{}
			if err := s.ScanPrefix([]byte("part-"), func(k, v []byte) error {
				seen[string(v)]++
				return nil
			}); err != nil {
				badMu.Lock()
				bad = append(bad, err.Error())
				badMu.Unlock()
				return
			}
			if n := len(seen); n != 1 || seen[keyOf(seen)] != 20 {
				badMu.Lock()
				bad = append(bad, fmt.Sprintf("one scan under one read lock saw %v — "+
					"a group became visible in pieces", seen))
				badMu.Unlock()
				return
			}
		}
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go reader()
	}
	for g := 1; g <= gens; g++ {
		if err := s.CommitGroup(groupParts(5, g)); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	wg.Wait()
	badMu.Lock()
	defer badMu.Unlock()
	if len(bad) > 0 {
		t.Fatal(bad[0])
	}
}

func keyOf(m map[string]int) string {
	for k := range m {
		return k
	}
	return ""
}

// TestAttack2ConcurrentCommitGroupAndCommit runs groups and ordinary commits
// from several goroutines at once. The sequence numbers on disk must come out
// gapless and in order, which is what replay's expectedSeq check demands — a
// lost-update on nextSeq under concurrency would produce a log that refuses to
// reopen.
func TestAttack2ConcurrentCommitGroupAndCommit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				if i%2 == 0 {
					b := &Batch{}
					b.Put([]byte(fmt.Sprintf("solo-%d-%d", w, i)), []byte("v"))
					if err := s.Commit(b); err != nil {
						t.Error(err)
						return
					}
					continue
				}
				parts := make([]*Batch, 3)
				for p := range parts {
					pb := &Batch{}
					pb.Put([]byte(fmt.Sprintf("grp-%d-%d-%d", w, i, p)), []byte("v"))
					parts[p] = pb
				}
				if err := s.CommitGroup(parts); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	want := s.nextSeq
	s.crashClose()
	s.lock.release()

	re, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatalf("a log written by concurrent Commit/CommitGroup will not reopen: %v", err)
	}
	defer re.Close()
	if re.nextSeq != want {
		t.Fatalf("replay recovered nextSeq=%d, the writer had %d", re.nextSeq, want)
	}
	for w := 0; w < 8; w++ {
		for i := 0; i < 15; i++ {
			if i%2 == 0 {
				if _, ok := re.Get([]byte(fmt.Sprintf("solo-%d-%d", w, i))); !ok {
					t.Fatalf("solo-%d-%d did not survive", w, i)
				}
				continue
			}
			for p := 0; p < 3; p++ {
				if _, ok := re.Get([]byte(fmt.Sprintf("grp-%d-%d-%d", w, i, p))); !ok {
					t.Fatalf("grp-%d-%d-%d did not survive", w, i, p)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// What replay is willing to hold.
// ---------------------------------------------------------------------------

// TestAttack2ForgedMoreCannotMakeReplayHoldMoreThanTheLog: replay accumulates a
// transaction's parts in `pending` before applying any of them, so a hostile
// or corrupt log controls how much replay buffers. The bound that must hold is
// that it never buffers materially more than the log file's own size — a
// header-valid `more` of 2^32-1 must not make replay reserve anything for the
// records it promises but does not contain.
func TestAttack2ForgedMoreCannotMakeReplayHoldMoreThanTheLog(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &Batch{}
	b.Put([]byte("k"), []byte("v"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Forge the single record into "the first of 4294967295 parts".
	setMore(t, raw, 0, ^uint32(0))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	re, err := Open(dir, Options{})
	if err != nil {
		// Refusing is a fine answer.
		t.Logf("refused, as it may: %v", err)
		return
	}
	defer re.Close()
	// If it opened, the forged transaction must be gone entirely: it never
	// got its commit record.
	if _, ok := re.Get([]byte("k")); ok {
		t.Fatal("a record forged as the first part of an unfinished transaction was applied")
	}
	sz := int64(0)
	if info, err := os.Stat(path); err == nil {
		sz = info.Size()
	}
	if sz != 0 {
		t.Fatalf("the unfinished transaction's bytes were left on disk (%d bytes)", sz)
	}
}

// TestAttack2ReplayHoldsAtMostTheLogsOwnBytes measures what replay actually
// buffers for a large legitimate group, so the "worst case is the log's own
// size" claim is a number rather than an assertion. It fails only if replay
// holds a wild multiple of the file — a genuine amplification bug.
func TestAttack2ReplayHoldsAtMostTheLogsOwnBytes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	const parts, perPart, valLen = 8, 64, 4096
	group := make([]*Batch, parts)
	val := make([]byte, valLen)
	for p := range group {
		b := &Batch{}
		for i := 0; i < perPart; i++ {
			b.Put([]byte(fmt.Sprintf("big-%02d-%03d", p, i)), val)
		}
		group[p] = b
	}
	if err := s.CommitGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	logSize := info.Size()

	peak := measurePeakAlloc(t, func() {
		re, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
		if err != nil {
			t.Fatal(err)
		}
		re.Close()
	})
	t.Logf("log %d bytes, replay peak heap delta %d bytes (%.1fx)",
		logSize, peak, float64(peak)/float64(logSize))
	// Replay legitimately holds: the mmap'd/read file, the decoded batches
	// (key+value copies), and the live map. A handful of copies is expected;
	// an order of magnitude is not.
	if peak > 12*logSize {
		t.Fatalf("replay of a %d-byte log peaked at %d bytes of heap (%.1fx) — "+
			"the group path amplifies memory", logSize, peak, float64(peak)/float64(logSize))
	}
}

func measurePeakAlloc(t *testing.T, fn func()) int64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	d := int64(after.TotalAlloc - before.TotalAlloc)
	if d < 0 {
		d = 0
	}
	return d
}

// ---------------------------------------------------------------------------
// Sequence continuity after a group that failed.
// ---------------------------------------------------------------------------

// TestAttack2FailedGroupDoesNotAdvanceSequenceOnDisk: a group that failed
// part-way wrote real records with real sequence numbers, but the in-memory
// nextSeq was deliberately not advanced. The store is poisoned so nothing can
// write on top of it in this process — but the *next* process must pick the
// sequence back up from what replay actually kept, not from what the failed
// writer intended.
func TestAttack2FailedGroupDoesNotAdvanceSequenceOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Two good ordinary commits first, so the group starts at seq 2 and the
	// truncation target is not offset 0.
	for i := 0; i < 2; i++ {
		b := &Batch{}
		b.Put([]byte(fmt.Sprintf("pre-%d", i)), []byte("v"))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	seqBefore := s.nextSeq
	n := 0
	s.writeHook = func(r []byte) ([]byte, error) {
		n++
		if n <= 2 {
			return r, nil // two parts land whole
		}
		return r[:7], errCrash // the commit record is torn
	}
	if err := s.CommitGroup(groupParts(4, 1)); !errors.Is(err, errCrash) {
		t.Fatalf("expected the injected crash, got %v", err)
	}
	if s.nextSeq != seqBefore {
		t.Fatalf("a failed group advanced nextSeq to %d from %d", s.nextSeq, seqBefore)
	}
	s.crashClose()
	s.lock.release()

	re, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after a torn group: %v", err)
	}
	defer re.Close()
	assertGeneration(t, re, 4, "")
	if re.nextSeq != seqBefore {
		t.Fatalf("replay resumed at sequence %d; the last durable record was %d, so the "+
			"next one must be %d", re.nextSeq, seqBefore-1, seqBefore)
	}
	// And the log must actually be back to where the group started, so the
	// next commit writes at that offset rather than behind the dead parts.
	b := &Batch{}
	b.Put([]byte("resumed"), []byte("y"))
	if err := re.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := re.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after resuming past a discarded group: %v", err)
	}
	defer again.Close()
	if _, ok := again.Get([]byte("resumed")); !ok {
		t.Fatal("the commit written after a discarded group did not survive")
	}
	assertGeneration(t, again, 4, "")
}

// ---------------------------------------------------------------------------
// Forgery combined with truncation, and forgery of all three records at once.
// ---------------------------------------------------------------------------

// TestAttack2ForgeMoreThenTruncate combines the two attacks the first pass ran
// separately — forging the remaining-part count, and cutting the log — because
// only their combination removes the witness the countdown check depends on.
//
// The finding, and it is a limit rather than a bug: forge the group's FIRST
// record to declare itself last (more=0) and cut the log immediately after it,
// and replay applies four of the transaction's twelve keys. It cannot do
// otherwise. What it reads is a record whose header checksum verifies, whose
// payload checksum verifies, whose sequence is the expected one, and which
// says "this transaction ends here" — byte-for-byte indistinguishable from a
// legitimate single-record commit. No reader can tell them apart, because
// CRC32 is an error detector, not an authenticator: an adversary who can
// re-sign a header can write any state they like into the log directly, so
// this buys them nothing they did not already have.
//
// That is why this test excludes the forgery of the group's first record: it
// is out of the package's declared threat model (crashes, torn writes, bit
// rot — see docs/adversarial/I2.md), and every case that IS in the model is
// swept here. Corruption that a medium can actually produce is covered by the
// first pass's bit-flip sweep, which flips every bit of this same log and
// never reaches this shape, because a flipped `more` also breaks the header
// checksum.
//
// Everything else in the cross product — forging any of the other four
// records, at any value, cut anywhere — must still hold the prefix property.
func TestAttack2ForgeMoreThenTruncate(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	// offs[0] is "before"; offs[1..3] are the group; offs[4] is "after".
	// offs[1] is excluded: see the doc comment.
	for i, off := range offs {
		if i == 1 {
			continue
		}
		for _, more := range []uint32{0, 1, 2, 3, ^uint32(0)} {
			for _, cut := range offs {
				if cut <= off {
					continue
				}
				raw := append([]byte(nil), base...)
				setMore(t, raw, off, more)
				assertNoSubset(t, raw[:cut],
					fmt.Sprintf("record %d forged to more=%d, log cut at %d", i, more, cut))
			}
			// Byte-level cuts behind the forgery, sampled rather than
			// exhaustive: each one is a full Open over a fresh directory, and
			// the exhaustive sweep put minutes on the package's runtime for
			// coverage the record-boundary cuts above already carry.
			for cut := off + recordHeaderLen; cut < len(base); cut += 47 {
				raw := append([]byte(nil), base...)
				setMore(t, raw, off, more)
				assertNoSubset(t, raw[:cut],
					fmt.Sprintf("record %d forged to more=%d, torn at %d", i, more, cut))
			}
		}
	}
}

// TestAttack2TheForgeAndTruncateLimitIsExactlyWhereItIsClaimed pins the limit
// the test above documents, so it is a checked statement rather than a comment
// that could quietly stop being true. If a future change makes replay reject
// this shape, this test fails and the comment above should be deleted.
func TestAttack2TheForgeAndTruncateLimitIsExactlyWhereItIsClaimed(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	raw := append([]byte(nil), base...)
	setMore(t, raw, offs[1], 0)
	raw = raw[:offs[2]]

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, Options{})
	if err != nil {
		t.Logf("replay now refuses the forge-and-truncate shape (%v) — the documented "+
			"limit in TestAttack2ForgeMoreThenTruncate is stale and should be removed", err)
		return
	}
	defer s.Close()
	present := 0
	for _, k := range attackKeys() {
		if _, ok := s.Get([]byte(k)); ok {
			present++
		}
	}
	if present == 0 || present == len(attackKeys()) {
		t.Logf("replay no longer applies a subset here (%d/%d visible) — the documented "+
			"limit is stale and should be removed", present, len(attackKeys()))
		return
	}
	t.Logf("documented limit holds: a re-signed more=0 on a group's first record plus a "+
		"truncation makes %d of %d keys visible. Unreachable by corruption (CRC32 is not "+
		"an authenticator); reachable only by an adversary who could write the state "+
		"directly anyway.", present, len(attackKeys()))
}

// TestAttack2ForgeAllThreeGroupRecords forges the countdown on all three
// records of the group simultaneously, over the whole small cross product. Two
// at a time (the first pass) cannot express a countdown that is self-consistent
// across a three-record group while describing a different transaction than
// the one that was written; three at a time can.
func TestAttack2ForgeAllThreeGroupRecords(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	group := offs[1:4]
	vals := []uint32{0, 1, 2, 3, 4}
	for _, a := range vals {
		for _, b := range vals {
			for _, c := range vals {
				raw := append([]byte(nil), base...)
				setMore(t, raw, group[0], a)
				setMore(t, raw, group[1], b)
				setMore(t, raw, group[2], c)
				assertNoSubset(t, raw, fmt.Sprintf("group forged to more=%d,%d,%d", a, b, c))
			}
		}
	}
}

// TestAttack2ForgedGroupSpillingIntoTheFollowingCommit: forge the group's last
// record to say a further part follows. The record after it is an ordinary,
// entirely unrelated commit ("after"), which replay would then swallow into
// the transaction — making a commit that was independently durable become
// conditional on a transaction it has nothing to do with, and the transaction
// become one record longer than anyone wrote. Either the whole extended thing
// applies or none of it does; what is forbidden is "after" applying while the
// group does not, or vice versa.
func TestAttack2ForgedGroupSpillingIntoTheFollowingCommit(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	raw := append([]byte(nil), base...)
	setMore(t, raw, offs[3], 1) // the group's commit record now claims one more part
	opened := assertNoSubset(t, raw, "the group's last record forged to claim another part")
	if !opened {
		return
	}
	// If it opened, check the extended transaction is coherent: "after" was
	// swept in as the group's real terminator, so all of it is visible, or
	// none of the group is.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, Options{})
	if err != nil {
		return
	}
	defer s.Close()
	_, groupVisible := s.Get([]byte(attackKeys()[0]))
	_, afterVisible := s.Get([]byte("after"))
	if groupVisible != afterVisible {
		t.Fatalf("the forged extension left the group %v and the following commit %v — "+
			"one part of the reader's idea of the transaction applied and the other did not",
			groupVisible, afterVisible)
	}
}

// TestAttack2DiscardedGroupDoesNotLeakItsCountIntoTheNextOne: replay resets
// `pending` with pending[:0] between transactions but leaves groupMore holding
// the last group's count. If a later group's first record were ever checked
// against that stale value the countdown check would fire on a perfectly good
// log. Two consecutive groups of *different* lengths, back to back, is the
// shape that exposes it.
func TestAttack2DiscardedGroupDoesNotLeakItsCountIntoTheNextOne(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	// Lengths chosen so consecutive groups never share a part count, and so a
	// short group follows a long one and vice versa.
	lengths := []int{5, 2, 4, 2, 6, 3}
	for gen, n := range lengths {
		parts := make([]*Batch, n)
		for p := range parts {
			b := &Batch{}
			b.Put([]byte(fmt.Sprintf("g%d-p%d", gen, p)), []byte(fmt.Sprintf("gen-%d", gen)))
			parts[p] = b
		}
		if err := s.CommitGroup(parts); err != nil {
			t.Fatalf("group %d (%d parts): %v", gen, n, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	re, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatalf("a log of consecutive groups of differing lengths will not replay: %v — "+
			"the countdown check is comparing against a stale count", err)
	}
	defer re.Close()
	for gen, n := range lengths {
		for p := 0; p < n; p++ {
			v, ok := re.Get([]byte(fmt.Sprintf("g%d-p%d", gen, p)))
			if !ok || string(v) != fmt.Sprintf("gen-%d", gen) {
				t.Fatalf("g%d-p%d = %q/%v after replay", gen, p, v, ok)
			}
		}
	}
}

// TestAttack2GroupOfOneThousandParts: nothing bounds how many records a group
// may span. A reorg at mainnet parameters chunked at a small budget could
// produce a very large number of them, and both the writer's encode-everything
// -first loop and replay's pending slice grow with it. This is the scale check
// the first pass did not run — three parts everywhere.
func TestAttack2GroupOfOneThousandParts(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	const n = 1000
	parts := make([]*Batch, n)
	for p := range parts {
		b := &Batch{}
		b.Put([]byte(fmt.Sprintf("k%04d", p)), []byte("v"))
		parts[p] = b
	}
	if err := s.CommitGroup(parts); err != nil {
		t.Fatalf("a 1000-part group: %v", err)
	}
	if s.nextSeq != n {
		t.Fatalf("nextSeq is %d after a %d-part group", s.nextSeq, n)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	re, err := Open(dir, Options{CompactAfterBytes: 1 << 30})
	if err != nil {
		t.Fatalf("replaying a 1000-part group: %v", err)
	}
	defer re.Close()
	for p := 0; p < n; p++ {
		if _, ok := re.Get([]byte(fmt.Sprintf("k%04d", p))); !ok {
			t.Fatalf("k%04d is missing after replaying a 1000-part group", p)
		}
	}
	if re.nextSeq != n {
		t.Fatalf("replay recovered nextSeq=%d, want %d", re.nextSeq, n)
	}
}

// TestAttack2GroupDoesNotDoubleBufferTheTransaction answers, with a
// measurement, the question the chunking naturally raises: how many copies of
// a multi-gigabyte reorg are alive at once, and is that worse than the
// single-batch code it replaced?
//
// The suspicion is reasonable. CommitGroup deliberately encodes every part
// before writing any of them ("an oversized part must fail the whole
// transaction with nothing on disk"), so at the first write it holds N encoded
// records simultaneously — where the old path held exactly one. If those N
// records were an extra copy ON TOP of what a single record cost, a mainnet
// reorg (undo_depth 1024 x block_byte_capacity 8 MB, spec/params.json ~ 8 GB)
// would carry a multi-gigabyte penalty in a process that already holds the
// whole live state in RAM.
//
// It is not. N records of size X/N sum to X, the same X the one record held,
// so the peak is the caller's batches plus one copy of the transaction either
// way. Measured below at ~2.0x the payload for BOTH paths, within noise of
// each other. The chunking is memory-neutral, and the "encode everything
// first" choice costs nothing beyond what Commit already cost.
//
// Getting this number right requires care: the transient payload slice
// encodeRecord builds and then copies into the record is garbage by the time
// the write hook fires, and the caller's batches are unreachable in the
// single-Commit arm unless pinned. An earlier draft of this test omitted both
// and "found" a 2.6x-vs-1.0x regression that does not exist.
func TestAttack2GroupDoesNotDoubleBufferTheTransaction(t *testing.T) {
	const parts, perPart, valLen = 16, 32, 8192

	live := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}

	// arm commits the same payload either as one batch or as a group, and
	// returns the live heap at the instant of the first record write — which
	// is right after CommitGroup's encode loop, and right after Commit's
	// single encode.
	arm := func(t *testing.T, group bool) (batchCost, atWrite, payload uint64) {
		t.Helper()
		dir := t.TempDir()
		s, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		val := make([]byte, valLen)
		base := live()
		batches := make([]*Batch, parts)
		for p := range batches {
			b := &Batch{}
			for i := 0; i < perPart; i++ {
				k := []byte(fmt.Sprintf("x-%02d-%03d", p, i))
				b.Put(k, val)
				payload += uint64(len(k) + valLen)
			}
			batches[p] = b
		}
		batchCost = live() - base

		seen := false
		s.writeHook = func(r []byte) ([]byte, error) {
			if !seen {
				seen = true
				atWrite = live() - base
			}
			return r, nil
		}
		if group {
			err = s.CommitGroup(batches)
		} else {
			all := &Batch{}
			for _, b := range batches {
				all.mutations = append(all.mutations, b.mutations...)
			}
			err = s.Commit(all)
		}
		// Without this the batches are unreachable in the single-Commit arm
		// by the time the hook runs, and the two arms are not comparable.
		runtime.KeepAlive(batches)
		if err != nil {
			t.Fatal(err)
		}
		return batchCost, atWrite, payload
	}

	oneBatches, onePeak, payload := arm(t, false)
	grpBatches, grpPeak, _ := arm(t, true)

	t.Logf("payload %d bytes", payload)
	t.Logf("  single Commit: batches %d (%.2fx), live at the write %d (%.2fx)",
		oneBatches, float64(oneBatches)/float64(payload), onePeak, float64(onePeak)/float64(payload))
	t.Logf("  CommitGroup:   batches %d (%.2fx), live at the write %d (%.2fx)",
		grpBatches, float64(grpBatches)/float64(payload), grpPeak, float64(grpPeak)/float64(payload))

	// The group path must not cost materially more than the single-record
	// path. A genuine extra buffering of the transaction would show up as a
	// whole additional multiple, not as the few percent of noise seen here.
	if grpPeak > onePeak+payload/2 {
		t.Fatalf("CommitGroup holds %d bytes live at the first write against the single "+
			"path's %d over a %d-byte payload — the group path buffers the transaction "+
			"an extra time", grpPeak, onePeak, payload)
	}
	if grpPeak > 3*payload {
		t.Fatalf("CommitGroup's live peak is %.1fx the payload; two copies (the caller's "+
			"batches and the encoded records) is what the design implies",
			float64(grpPeak)/float64(payload))
	}
}

// TestAttack2SinglePartGroupIsByteIdenticalToCommit is the evidence for a
// small piece of duplication in the branch: node/chain's batchGroup.commit
// special-cases `len(parts) == 1` and calls Store.Commit, and CommitGroup
// contains exactly the same fallback (`len(nonEmpty) == 1` -> commitOneLocked)
// with a paragraph explaining it.
//
// If the two produce identical bytes then the chain-side branch is redundant —
// CommitGroup alone would give the same on-disk result, and the caller would
// have one path instead of two. This measures that rather than asserting it.
// (group_test.go's TestSingleBatchGroupIsAnOrdinaryRecord shows a one-batch
// group is an ordinary record; what is checked here is the stronger claim the
// duplication rests on: byte-for-byte equality with what Commit writes.)
func TestAttack2SinglePartGroupIsByteIdenticalToCommit(t *testing.T) {
	build := func() *Batch {
		b := &Batch{}
		b.Put([]byte("alpha"), []byte("one"))
		b.Delete([]byte("beta"))
		b.Put([]byte("gamma"), []byte("three"))
		return b
	}
	write := func(t *testing.T, group bool) []byte {
		t.Helper()
		dir := t.TempDir()
		s, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
		if err != nil {
			t.Fatal(err)
		}
		if group {
			// An empty batch alongside the real one, because that is what a
			// caller passing g.parts can hand over.
			err = s.CommitGroup([]*Batch{build(), {}})
		} else {
			err = s.Commit(build())
		}
		if err != nil {
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
	viaCommit := write(t, false)
	viaGroup := write(t, true)
	if !bytes.Equal(viaCommit, viaGroup) {
		t.Fatalf("a one-batch CommitGroup wrote %d bytes and Commit wrote %d, and they "+
			"differ — node/chain's batchGroup.commit special-case is NOT redundant "+
			"after all\n commit: %x\n group:  %x", len(viaCommit), len(viaGroup),
			viaCommit, viaGroup)
	}
	t.Logf("a one-batch CommitGroup is byte-identical to Commit (%d bytes) — "+
		"node/chain's batchGroup.commit `len(parts) == 1` branch duplicates a "+
		"decision CommitGroup already makes, and could be deleted", len(viaCommit))
}

// TestAttack2TearInsideAGroupWithLaterGroupPartsIntact is the collision between
// the tail discriminator and the multi-record group that the first pass did not
// construct: a tear lands on a group's SECOND record while its THIRD (the
// commit record) is fully intact behind it.
//
// This is the shape a bit of media rot produces, not a crash — a crash cannot
// write a record after the one it died on. Replay's forward search finds an
// intact record past the damage, which is exactly the "interior corruption,
// refuse rather than repair by deletion" signal, and refusing is the right
// answer here for a second reason too: applying what is behind the hole would
// be applying part of a transaction.
//
// The requirement is that it refuses rather than either (a) truncating away
// the intact commit record, or (b) sweeping the surviving parts into
// something applied.
func TestAttack2TearInsideAGroupWithLaterGroupPartsIntact(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	// Damage the payload of the group's middle record (offs[2]), leaving the
	// commit record at offs[3] and the trailing commit at offs[4] untouched.
	for _, delta := range []int{0, 3, 9} {
		raw := append([]byte(nil), base...)
		pos := offs[2] + recordHeaderLen + delta
		if pos >= offs[3] {
			continue
		}
		raw[pos] ^= 0xff

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir, Options{})
		if err != nil {
			// The expected and correct outcome.
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("delta %d: refused, but not as corruption: %v", delta, err)
			}
			// And it must not have "repaired" by truncating the intact tail.
			info, statErr := os.Stat(filepath.Join(dir, logName))
			if statErr != nil {
				t.Fatal(statErr)
			}
			if info.Size() != int64(len(raw)) {
				t.Fatalf("delta %d: replay refused AND truncated the log from %d to %d "+
					"bytes — intact records behind interior corruption were deleted",
					delta, len(raw), info.Size())
			}
			continue
		}
		// If it opened at all, no subset may be visible.
		func() {
			defer s.Close()
			present := 0
			for _, k := range attackKeys() {
				if _, ok := s.Get([]byte(k)); ok {
					present++
				}
			}
			if present != 0 && present != len(attackKeys()) {
				t.Fatalf("delta %d: a tear inside a group left %d of %d keys visible",
					delta, present, len(attackKeys()))
			}
			if _, ok := s.Get([]byte("after")); ok && present == 0 {
				t.Fatalf("delta %d: the commit after the group is visible but the group "+
					"is not", delta)
			}
		}()
	}
}

// TestAttack2GroupWhoseFinalRecordIsTornButSequenceIntact: the commit record's
// payload is damaged while everything before it is whole. This is the exact
// crash the barrier fsync is designed around (parts durable, commit record
// not), arriving as corruption instead. Nothing of the transaction may appear.
func TestAttack2GroupWhoseFinalRecordIsTornButSequenceIntact(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	for _, cut := range []int{offs[3] + recordHeaderLen, offs[3] + recordHeaderLen + 4, offs[4] - 1} {
		raw := append([]byte(nil), base[:cut]...)
		assertNoSubset(t, raw, fmt.Sprintf("the group's commit record cut at %d", cut))

		// And the same damaged (not truncated) at the last byte before the
		// following commit.
		dmg := append([]byte(nil), base...)
		dmg[cut] ^= 0x01
		assertNoSubset(t, dmg, fmt.Sprintf("the group's commit record damaged at %d", cut))
	}
}

// TestAttack2OversizedPartLeavesNothingOnDiskAndNoPoison is the property the
// "encode everything before writing anything" loop exists for, checked rather
// than assumed — and it checks the half the comment does not mention: that the
// store is still USABLE afterwards.
//
// A part too large for one record is a caller bug, not a durability fault, so
// it must not trip the store's sticky poisoning the way a torn write does. If it did,
// a single oversized reorg part would take the node's store offline until
// restart for what is a rejected argument.
func TestAttack2OversizedPartLeavesNothingOnDiskAndNoPoison(t *testing.T) {
	// The oversized part is placed last, so every part before it encoded
	// successfully and the failure is genuinely late in the loop.
	for _, position := range []string{"first", "last"} {
		t.Run(position, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			// A commit before the group, so "nothing on disk" is measured
			// against a non-empty log.
			pre := &Batch{}
			pre.Put([]byte("pre"), []byte("v"))
			if err := s.Commit(pre); err != nil {
				t.Fatal(err)
			}
			sizeBefore := logSize(t, dir)
			seqBefore := s.nextSeq

			huge := &Batch{}
			huge.Put([]byte("huge"), make([]byte, MaxRecordLen+1))
			small := func(n int) *Batch {
				b := &Batch{}
				b.Put([]byte(fmt.Sprintf("small-%d", n)), []byte("v"))
				return b
			}
			var group []*Batch
			if position == "first" {
				group = []*Batch{huge, small(1), small(2)}
			} else {
				group = []*Batch{small(1), small(2), huge}
			}
			if err := s.CommitGroup(group); !errors.Is(err, ErrBatchTooBig) {
				t.Fatalf("a group with an oversized part returned %v, want ErrBatchTooBig", err)
			}
			if got := logSize(t, dir); got != sizeBefore {
				t.Fatalf("the log grew from %d to %d bytes for a group that was refused "+
					"before any write", sizeBefore, got)
			}
			if s.nextSeq != seqBefore {
				t.Fatalf("a refused group advanced nextSeq to %d from %d", s.nextSeq, seqBefore)
			}
			for _, n := range []int{1, 2} {
				if _, ok := s.Get([]byte(fmt.Sprintf("small-%d", n))); ok {
					t.Fatalf("small-%d from a refused group is visible", n)
				}
			}
			// And, the point: the store still works. An oversized batch is a
			// caller error, not a durability failure, so the sticky poisoning must
			// not fire.
			after := &Batch{}
			after.Put([]byte("after"), []byte("v"))
			if err := s.Commit(after); err != nil {
				t.Fatalf("the store refused a later commit after rejecting an oversized "+
					"group: %v — a caller's argument error poisoned the store", err)
			}
		})
	}
}

func logSize(t *testing.T, dir string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
