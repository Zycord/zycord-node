package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// The replay classification suite.
//
// Property, in one sentence: a hole among the parts of a multi-record
// transaction whose commit record never landed is discardable exactly like a
// transaction whose parts simply stop, and the presence of that
// transaction's commit record — and nothing less than it — is what turns the
// same hole into a refusal to open.
//
// The two halves are pinned against each other on purpose. The first alone
// would pass for a store that discarded everything it could not parse, which is
// the interior-corruption data-loss bug; the second alone would pass for
// today's code, which refuses on any surviving part. Only the pair says the
// classification is drawn in the right place.

// classFixture is one committed single-record commit followed by a
// four-record group, laid out as separate byte slices so a test can assemble
// any prefix of the group and damage any part of it in place.
type classFixture struct {
	committed []byte
	parts     [][]byte
}

const classGroupParts = 4

func buildClassFixture(t *testing.T) classFixture {
	t.Helper()
	return buildGroupFixture(t, classGroupParts)
}

// buildGroupFixture is buildClassFixture for a group of any size, and the size
// is a variable because production has no bound on it: CommitGroup writes
// parts 0..n-2 before its barrier, and node/chain's batchGroup.rollIfNeeded
// splits a reorg's mutations into as many parts as mutationBudget dictates. A
// rule read off a four-part group alone read the frame after the surviving run
// as the commit record's slot, which is true only when the run reaches it —
// see commitRecordSlotOccupied.
//
// Part i's payload does not depend on n, so the records of an n-part group and
// of an m-part group agree in everything but their countdowns: two fixtures
// can be compared with one variable moved.
func buildGroupFixture(t *testing.T, parts int) classFixture {
	t.Helper()

	survivor := &Batch{}
	survivor.Put([]byte("committed-key"), []byte("committed-value"))
	committed, err := encodeRecord(survivor, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	f := classFixture{committed: committed}
	for i, b := range groupParts(parts, 1) {
		// seq 1..n, more counting n-1..0 — exactly what CommitGroup emits.
		rec, err := encodeRecord(b, uint64(1+i), uint32(parts-1-i))
		if err != nil {
			t.Fatal(err)
		}
		f.parts = append(f.parts, rec)
	}
	return f
}

// writeClassLog concatenates the committed record and the given group parts,
// zeroing every part whose index appears in holes. Zeroing preserves length,
// so the parts after a hole sit at exactly the offsets a crash would have
// left them at — the whole point of the scenario is that they are intact and
// in place.
//
// IT ALSO WRITES THE COMMIT SIDECAR, and which value it writes is now a
// statement about WHICH HISTORY the fixture is. The same log bytes come
// from two histories, so a fixture that supplies only the log is a fixture that
// has not said what it is a fixture OF. This one says the group was ABANDONED:
// the sidecar names the seed commit at sequence 0 and nothing after it, which
// is what a store looks like when CommitGroup's second barrier never returned.
// Use writeClassLogCommitted for the opposite history.
//
// The choice is the conservative one for this suite: an abandoned-group sidecar
// can never withhold a cut here, because every cut these tests offer removes
// sequence 1 or above. So every scenario that does not name the sidecar keeps
// exactly the answer it had before the sidecar existed.
func writeClassLog(t *testing.T, f classFixture, keep int, holes ...int) string {
	t.Helper()
	dir := writeClassLogRaw(t, f, keep, holes...)
	writeSidecar(t, dir, 1)
	return dir
}

// writeClassLogCommitted is writeClassLog for the history in which the group
// WAS reported committed: both of CommitGroup's barriers returned, the caller
// was told the transaction landed, and the damage came afterwards. The sidecar
// therefore names the group's last sequence.
func writeClassLogCommitted(t *testing.T, f classFixture, keep int, holes ...int) string {
	t.Helper()
	dir := writeClassLogRaw(t, f, keep, holes...)
	writeSidecar(t, dir, uint64(len(f.parts))+1)
	return dir
}

func writeClassLogRaw(t *testing.T, f classFixture, keep int, holes ...int) string {
	t.Helper()
	dir := t.TempDir()
	raw := append([]byte(nil), f.committed...)
	for i := 0; i < keep; i++ {
		part := append([]byte(nil), f.parts[i]...)
		for _, h := range holes {
			if h == i {
				for j := range part {
					part[j] = 0
				}
			}
		}
		raw = append(raw, part...)
	}
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// assertOpensWithOnlyTheCommittedRecord demands the abandoned transaction be
// gone and the commit that preceded it be intact. The second half is the
// guard against a benign pass: a store that discarded the whole log would
// also "open cleanly", and that is the failure this package exists to stop.
func assertOpensWithOnlyTheCommittedRecord(t *testing.T, dir string) {
	t.Helper()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("refused to open: %v", err)
	}
	defer s.Close()

	v, ok := s.Get([]byte("committed-key"))
	if !ok || string(v) != "committed-value" {
		t.Fatalf("the committed record was lost (present=%v value=%q) — the log was "+
			"truncated too far, which is the interior-corruption failure, not the "+
			"abandoned-group classification", ok, v)
	}
	assertGeneration(t, s, classGroupParts, "")
	if s.nextSeq != 1 {
		t.Fatalf("nextSeq = %d, want 1 — the abandoned group's bytes were not cut away, "+
			"so the next commit would land behind them", s.nextSeq)
	}
}

func assertRefuses(t *testing.T, dir, why string) {
	t.Helper()
	s, err := Open(dir, Options{})
	if err == nil {
		s.Close()
		t.Fatalf("opened, want a refusal: %s", why)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("refused with %v, want ErrCorrupt: %s", err, why)
	}
	t.Logf("refused as required (%s): %v", why, err)
}

// TestAbandonedGroupWithAHoleIsDiscardedLikeAnAbandonedGroupWithout is the
// property itself: the same uncommitted transaction, recoverable or fatal purely as a
// function of which parts writeback happened to flush.
func TestAbandonedGroupWithAHoleIsDiscardedLikeAnAbandonedGroupWithout(t *testing.T) {
	f := buildClassFixture(t)

	// Control: the group simply stops after part 0. Nothing to search, so
	// this opened cleanly before this change too.
	t.Run("prefix", func(t *testing.T) {
		assertOpensWithOnlyTheCommittedRecord(t, writeClassLog(t, f, 1))
	})

	// The hole case: part 1 is a hole and part 2 reached the disk behind it. The
	// commit record (part 3) never landed, so nothing here was ever
	// acknowledged to a caller.
	t.Run("hole", func(t *testing.T) {
		assertOpensWithOnlyTheCommittedRecord(t, writeClassLog(t, f, 3, 1))
	})
}

// TestAHoleUnderAPresentCommitRecordStillRefuses pins the other side of the
// boundary, one record away from the case above. CommitGroup fsyncs parts
// 0..n-2 before the commit record is written at all, so a commit record on
// disk proves those parts were durable and a hole among them is interior
// corruption of a committed transaction — cutting the group away would
// delete data the caller was told had landed.
func TestAHoleUnderAPresentCommitRecordStillRefuses(t *testing.T) {
	f := buildClassFixture(t)

	t.Run("commit record present", func(t *testing.T) {
		assertRefuses(t, writeClassLog(t, f, classGroupParts, 1),
			"part 1 is a hole but the group's commit record is on disk")
	})

	// And the same hole with an ordinary commit behind the completed group,
	// so the refusal is not resting on the commit record being last.
	t.Run("committed record after the group", func(t *testing.T) {
		later := &Batch{}
		later.Put([]byte("after-key"), []byte("after-value"))
		rec, err := encodeRecord(later, uint64(1+classGroupParts), 0)
		if err != nil {
			t.Fatal(err)
		}
		dir := writeClassLog(t, f, classGroupParts, 1)
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, rec...), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRefuses(t, dir, "an ordinary commit sits behind the damaged group")
	})
}

// TestHoleClassificationIgnoresOnlyThisGroupsOwnSequences is the mutation
// test: the widened sequence floor must be exactly the group's own range and
// not one record wider or narrower. It walks the hole across every non-final
// part and asserts the answer flips solely on whether the commit record is
// present, never on which part the hole hit or how many parts survived it.
func TestHoleClassificationIgnoresOnlyThisGroupsOwnSequences(t *testing.T) {
	f := buildClassFixture(t)
	for hole := 1; hole < classGroupParts-1; hole++ {
		for keep := hole + 1; keep <= classGroupParts; keep++ {
			name := fmt.Sprintf("hole=%d,keep=%d", hole, keep)
			t.Run(name, func(t *testing.T) {
				dir := writeClassLog(t, f, keep, hole)
				if keep == classGroupParts {
					assertRefuses(t, dir, name+": the commit record landed")
					return
				}
				assertOpensWithOnlyTheCommittedRecord(t, dir)
			})
		}
	}
}

// TestAHoleInAGroupsFirstPartStillRefuses records the residual this change
// does not close, as behaviour rather than as a comment.
//
// The classification derives a group's extent from the countdown in a part
// this replay already read in sequence. When the hole lands on the group's
// *first* part, that is the record destroyed: replay has read nothing saying
// a transaction begins here, so the intact parts behind the hole are, on the
// evidence available, records after damage and nothing more. It refuses.
//
// This is the safe direction — a refusal, never a truncation — and closing it
// would mean letting a record found *by the scan* declare, through its own
// more field, that the bytes in front of it are discardable. That is a
// truncation lever driven by attacker-shapeable bytes, which is the trade
// this file consistently declines to make, and it is left open deliberately.
//
// The refusal is not the end of the operator's road, and the two tests say so
// jointly: this store — same fixture, same three parts, same hole — is the one
// TestRepairRecoversAnAbandonedGroupWithAHoleInItsFirstPart cuts. `repair`
// reaches it without the lever because it asks a different question of the
// same bytes. This scan asks "did the writer keep going", which any intact
// record answers, so it needs a group extent to dismiss the group's own parts
// — and the extent is what the hole destroyed. findTerminalRecordWithin asks
// "is a committed transaction back there", which only a more == 0 record
// answers; the surviving parts all declare further parts to follow, so no
// extent is needed and no discovered header authorises anything. What keeps
// that question out of Open is not its safety but its anchor: unattended,
// replay will discard a transaction only when the log's honest in-sequence
// prefix proved one was open at the damage. Without that anchor the same
// discard rests on the damaged region's own testimony, which is where the
// operator's explicit authorisation belongs.
func TestAHoleInAGroupsFirstPartStillRefuses(t *testing.T) {
	f := buildClassFixture(t)
	assertRefuses(t, writeClassLog(t, f, 3, 0),
		"the hole destroyed the record that would have declared the group's extent")
}

// TestTheRefusedStoreIsByteIdenticalToTheOneRepairCuts is the load-bearing
// half of the paragraph above, made checkable.
//
// The claim "that permanent refusal is recoverable by `repair`" is only
// true if the two tests are talking about the same store, and they are two
// separate call sites with two spellings of the same argument (3 and
// classGroupParts-1). Either could be edited alone, the two tests would go on
// passing, and the argument would be quietly false. This pins the bytes.
func TestTheRefusedStoreIsByteIdenticalToTheOneRepairCuts(t *testing.T) {
	f := buildClassFixture(t)
	refused, err := os.ReadFile(filepath.Join(writeClassLog(t, f, 3, 0), logName))
	if err != nil {
		t.Fatal(err)
	}
	// The exact fixture TestRepairRecoversAnAbandonedGroupWithAHoleInItsFirstPart
	// builds for its "commit record never landed" case.
	cut, err := os.ReadFile(filepath.Join(writeClassLog(t, f, classGroupParts-1, 0), logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(refused, cut) {
		t.Fatalf("the store Open refuses (%d bytes) is not the store repair cuts (%d bytes) — "+
			"one of the two call sites moved, and the claim that the refusal is "+
			"recoverable no longer follows from these tests", len(refused), len(cut))
	}
}

// TestTwoDamageSitesInOneGroupRefuseRatherThanDiscardACommit is why the
// first-part hole is not closed by deriving the group's extent from the scan's
// own first hit.
//
// The refined rule looks safe against the forged countdown, and is: dismissal
// requires more == groupFinalSeq-seq with seq < groupFinalSeq, so no more == 0
// record is ever dismissible under any extent an attacker can name, and
// truncation is reached only through scanNothingFound. What it actually loses
// is the anchor. Today the extent comes from a part read *in sequence*, ahead
// of the damage; derived from the scan it comes from inside the damaged
// region, and then two damage sites in one group are enough:
//
//	part 0 (the opener) and part 3 (the commit record) are both holes, parts
//	1 and 2 survive. The commit record was fsynced before the damage, so this
//	transaction was reported committed.
//
// Today no group is open, part 1 is intact evidence, and Open refuses. Under
// the refined rule part 1 declares the extent, parts 1 and 2 are then dismissed
// as its own members, the scan comes back empty and replay truncates a
// committed transaction. No forgery is required — honest headers suffice — so
// the second assertion below is the discriminator: it shows the rejected rule
// gives the opposite answer on this test's own bytes.
func TestTwoDamageSitesInOneGroupRefuseRatherThanDiscardACommit(t *testing.T) {
	f := buildClassFixture(t)
	dir := writeClassLogCommitted(t, f, classGroupParts, 0, classGroupParts-1)
	assertRefuses(t, dir, "a committed transaction's opener and commit record are both holes")

	// THE CONTROL IS THE SAME BYTES UNDER THE OTHER HISTORY, and it is what
	// makes the refusal above a discrimination rather than a blanket. Under the
	// abandoned history nothing was ever reported committed, so `repair` must
	// still OFFER the cut — that offer is the recovery, and withholding it
	// turns a store an operator can rescue into a resync.
	abandoned := writeClassLog(t, f, classGroupParts, 0, classGroupParts-1)
	if digest(t, filepath.Join(dir, logName)) != digest(t, filepath.Join(abandoned, logName)) {
		t.Fatal("the two histories no longer share a log, so this test compares two things")
	}
	assertRefuses(t, abandoned, "Open cannot tell the two histories apart and must not guess")
	if d := diagnose(t, abandoned); !d.Repairable {
		t.Fatalf("that recovery became a resync on a transaction nothing ever reported "+
			"committed: %s", d.Explanation)
	}

	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	region := raw[len(f.committed):]
	if _, res := findNextRecord(region, 1, 0); res != scanFound {
		t.Fatalf("the surviving parts must read as evidence, got %v", res)
	}
	// The rejected rule, spelled out: the extent the scan would have derived
	// from its own first hit (part 1: seq 2, more 2).
	if _, res := findNextRecord(region, 1, classGroupParts); res != scanNothingFound {
		t.Fatalf("scan under a scan-derived extent = %v, want scanNothingFound — the rejected "+
			"rule no longer differs here, so this test has stopped discriminating", res)
	}

	// And the mirror image, now a property rather than a record of a wrong
	// answer: `repair` must refuse this same store too.
	//
	// findTerminalRecordWithin read "no record behind the damage declares
	// itself the last of its transaction" as "nothing back there was ever
	// reported committed". That inference holds while the only reason such a
	// record can be missing is that it was never written; here it was written
	// and fsynced, and the second hole destroyed it. The distinction comes from
	// outside the log — the sidecar this fixture's committed history carries —
	// because the abandoned control above is byte-identical to it and no
	// function of these bytes is right about both.
	if d := diagnose(t, dir); d.Repairable {
		t.Fatalf("a cut was offered over a transaction that was reported committed and whose "+
			"commit record the second hole destroyed: %s", d.Explanation)
	}
}

// TestAForgedCountdownCannotAuthoriseDiscardingCommittedData is the attack the
// classification has to survive, and the reason the group's parts are
// dismissed by a positive claim of membership rather than by a sequence floor.
//
// The countdown is a header field. Its checksum proves nothing about its
// honesty — attack_test's setMore recomputes both checksums — so an actor able
// to write the file can turn any committed single-record commit into a group
// opener declaring a commit record that could never fit in this log. Under a
// floor at that declared sequence, every genuinely committed record behind the
// damage sits below the floor, the scan reports nothing, and replay truncates
// data the caller was told had landed. Under the membership rule those records
// do not point at the forged commit record, so they still count as evidence
// and replay refuses.
func TestAForgedCountdownCannotAuthoriseDiscardingCommittedData(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"k0", "k1", "k2", "k3"}
	for i, k := range keys {
		b := &Batch{}
		b.Put([]byte(k), []byte{byte('a' + i)})
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	offs := recordOffsets(t, raw)
	if len(offs) != len(keys) {
		t.Fatalf("built %d records, want %d", len(offs), len(keys))
	}
	// Record 1 becomes a group opener naming a commit record 1000 records
	// away; record 2 is zeroed so replay has damage to classify; records 0
	// and 3 are untouched committed data.
	setMore(t, raw, offs[1], 1000)
	for i := offs[2]; i < offs[3]; i++ {
		raw[i] = 0
	}
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, logName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRefuses(t, dir2, "a forged countdown must not push committed records below the evidence bar")
}

// TestASurvivingPartMustClaimThisGroupToBeDismissed is the same rule stated on
// an otherwise legitimate abandoned group: take the discardable hole scenario
// and forge only the countdown of the part that survived the hole, so it no
// longer points at this group's commit record. It is then a record of unknown
// provenance sitting after damage, and the answer must flip from discard to
// refuse. Without this the dismissal could be a sequence range test and pass.
func TestASurvivingPartMustClaimThisGroupToBeDismissed(t *testing.T) {
	f := buildClassFixture(t)
	dir := writeClassLog(t, f, 3, 1)
	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	offs := []int{0, len(f.committed)}
	offs = append(offs, offs[1]+len(f.parts[0]))
	surviving := offs[2] + len(f.parts[1])
	// Part 2 legitimately carries more=1 (seq 3 + 1 == the commit record's
	// sequence 4). Forge it to 0 and it claims to be a transaction's last
	// record, which this group's commit record is not.
	setMore(t, raw, surviving, 0)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRefuses(t, dir, "the surviving record no longer claims membership in the open group")
}

// resign repairs both checksums of the record at off after its header has
// been rewritten in place, so a forgery is indistinguishable from something a
// writer produced on purpose. setMore does this for the countdown alone;
// these tests also rewrite the sequence.
func resign(t *testing.T, raw []byte, off int) {
	t.Helper()
	rec := raw[off:]
	binary.LittleEndian.PutUint32(rec[recordHdrCRCOff:], crc32.ChecksumIEEE(rec[:recordHdrCRCOff]))
	length := binary.LittleEndian.Uint64(rec[recordLenOff:])
	h := crc32.NewIEEE()
	h.Write(rec[:recordCRCOff])
	h.Write(rec[recordHeaderLen : recordHeaderLen+int(length)])
	binary.LittleEndian.PutUint32(rec[recordCRCOff:], h.Sum32())
}

// TestAWrappedSequenceCannotForgeGroupMembership is why the membership test is
// written as a subtraction under a `<` guard rather than as `seq+more ==
// groupFinalSeq`.
//
// Both forms agree on every sequence a writer can produce. They disagree on
// one an attacker can: a record claiming sequence 2^64-1 with a countdown
// chosen so the *sum* wraps to exactly this group's commit-record sequence.
// Under the addition form that record is dismissed as one of the group's own
// parts and the committed data behind the damage is truncated away; under the
// subtraction form the `<` guard rejects it before any arithmetic, because a
// record cannot both be a non-final part of this group and carry a sequence
// above its commit record.
func TestAWrappedSequenceCannotForgeGroupMembership(t *testing.T) {
	f := buildClassFixture(t)
	dir := writeClassLog(t, f, 3, 1)
	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	surviving := len(f.committed) + len(f.parts[0]) + len(f.parts[1])

	// The group's commit record would carry sequence 4. Choose seq and more
	// so that seq+more wraps to exactly 4.
	const forgedSeq = ^uint64(0)
	var commitRecordSeq uint64 = classGroupParts
	forgedMore := uint32(commitRecordSeq - forgedSeq)
	if forgedSeq+uint64(forgedMore) != commitRecordSeq {
		t.Fatalf("the fixture no longer wraps: %d + %d = %d",
			forgedSeq, forgedMore, forgedSeq+uint64(forgedMore))
	}
	binary.LittleEndian.PutUint64(raw[surviving+recordSeqOff:], forgedSeq)
	binary.LittleEndian.PutUint32(raw[surviving+recordMoreOff:], forgedMore)
	resign(t, raw, surviving)

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRefuses(t, dir, "a sequence above the commit record is not a part of this group, "+
		"however its countdown wraps")
}

// TestAPhantomGroupOverlappingARealOneStillRefuses builds the collision on
// real CommitGroup output rather than on hand-assembled records: forging the
// countdown of the ordinary commit *in front of* a genuine three-part group
// opens a phantom group whose commit-record sequence coincides with the real
// group's, so the real group's non-final parts satisfy the membership test and
// are dismissed. The real group's own commit record is not — it carries
// more=0 and sits at exactly groupFinalSeq, which the `<` guard excludes — so
// the evidence survives the collision and replay refuses.
//
// This is the general form of the rule that keeps it safe: dismissal requires
// more >= 1, so no record declaring itself the end of a transaction can ever
// be dismissed, and every committed transaction ends in exactly such a record.
func TestAPhantomGroupOverlappingARealOneStillRefuses(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	if len(offs) != 5 {
		t.Fatalf("attack log has %d records, want 5", len(offs))
	}
	// Drop the trailing ordinary commit at seq 4, so the only record left
	// that can serve as evidence is the real group's own commit record at
	// seq 3 — precisely the one sitting at the phantom group's groupFinalSeq.
	raw := append([]byte(nil), base[:offs[4]]...)
	// The real group is seq 1..3, so its parts all satisfy seq+more == 3.
	// Give the commit at seq 0 the same final sequence.
	setMore(t, raw, offs[0], 3)
	// Damage the group's first part so replay has to classify something.
	for i := offs[1]; i < offs[2]; i++ {
		raw[i] = 0
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRefuses(t, dir, "a phantom group's range covers the real group's parts, but not "+
		"the real group's commit record")
}

// TestAForgedCountdownCannotSplitATransaction is the countdown check's own
// test, and it exists because the pre-existing TestAttackForgedMore* pair does
// not discriminate it: deleting `seq+uint64(more) != groupFinalSeq` outright
// leaves both of them green, because every forgery they try produces a legal
// prefix of the write history rather than a strict subset.
//
// This one produces a strict subset. Two rewrites of a real log: the group's
// first part is demoted to an ordinary commit, so it applies alone, and the
// group's last part is promoted to a non-final one, so what remains never
// closes and is discarded at end of log. Four of the transaction's twelve keys
// become visible — the exact outcome the countdown check exists to prevent —
// unless the check fires on the promoted record, whose seq+more overshoots the
// group its predecessor opened.
func TestAForgedCountdownCannotSplitATransaction(t *testing.T) {
	base := buildAttackLog(t)
	offs := recordOffsets(t, base)
	if len(offs) != 5 {
		t.Fatalf("attack log has %d records, want 5", len(offs))
	}
	// Drop the trailing ordinary commit: with it in place the leftover group
	// would find a more=0 record to close on and apply in full.
	raw := append([]byte(nil), base[:offs[4]]...)
	setMore(t, raw, offs[1], 0)
	setMore(t, raw, offs[3], 1)
	assertNoSubset(t, raw, "group's first part demoted to a commit, last part promoted to a part")
}
