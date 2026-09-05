package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The commit sidecar suite.
//
// The property, in one sentence: two crash histories that leave BYTE-IDENTICAL
// logs get opposite recovery answers, because the fact that separates them —
// whether the log's own barrier returned — is recorded outside the log, and
// because that record is only ever read in the direction that withholds a cut.
//
// Both halves are pinned against each other on purpose, and neither alone would
// mean anything. The first alone would pass for a store that refused everything
// it could not parse, which is a node that never boots. The second alone would
// pass for a store that ignores the sidecar entirely. Only the pair says the
// evidence is being read, and read in one direction.
//
// Every history below is DRIVEN through the real Store — real batches, real
// barriers, real fault injection — rather than assembled from bytes, because
// the claim being tested is about an ordering between two fsyncs and an
// assembled fixture cannot have one.

var errSidecarCrash = errors.New("simulated crash")

// writeSidecar plants a sidecar carrying highPlusOne, which is the encoding the
// slot uses: 0 means "nothing committed in this log generation", n means
// "sequences 0..n-1 were reported committed".
func writeSidecar(t *testing.T, dir string, highPlusOne uint64) {
	t.Helper()
	if err := writeCommitsFile(dir, highPlusOne); err != nil {
		t.Fatal(err)
	}
}

func sidecarOf(t *testing.T, dir string) commitEvidence {
	t.Helper()
	e, err := readCommitEvidence(dir)
	if err != nil {
		t.Fatalf("readCommitEvidence: %v", err)
	}
	return e
}

func digest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// holePart zeroes the group part with the given index in a log built as
// `committed` followed by parts of equal size. Zeroing preserves length, so
// every later record stays at exactly the offset a writeback hole would have
// left it at — the whole point being that the surviving parts are intact and in
// place.
func holeParts(t *testing.T, dir string, prefix int, partLen int, idx ...int) {
	t.Helper()
	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range idx {
		at := prefix + i*partLen
		if at+partLen > len(raw) {
			t.Fatalf("part %d does not fit in a %d-byte log", i, len(raw))
		}
		for j := at; j < at+partLen; j++ {
			raw[j] = 0
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildTwoHistories drives the two crash histories the sidecar's ordering
// argument was measured against, and returns their directories.
//
// H1, the ordinary crash: parts 0..n-2 are written and fsynced, the commit
// record is written, and the process dies BEFORE THE SECOND BARRIER RETURNS.
// CommitGroup therefore returns an error, no caller was ever told the
// transaction committed, and nothing is recorded out of band — which is the
// whole point, since the sidecar is written after that barrier returns and the
// barrier never did.
//
// H2, the committed transaction: both barriers return, CommitGroup returns nil,
// the sidecar is written. Two later media faults then zero the same two parts.
//
// The two logs come out byte-identical. That is not an artefact of this test —
// it is the reason both ambiguous-cut shapes exist, and it is asserted here rather than
// assumed, because a fixture in which the two logs differ would make every
// assertion below pass for the wrong reason.
func buildTwoHistories(t *testing.T, parts int, holes ...int) (h1, h2 string) {
	t.Helper()

	seed := func(dir string) int {
		b := &Batch{}
		b.Put([]byte("committed-key"), []byte("committed-value"))
		s, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, logName))
		if err != nil {
			t.Fatal(err)
		}
		return int(info.Size())
	}

	h1, h2 = t.TempDir(), t.TempDir()
	prefix := seed(h1)
	if got := seed(h2); got != prefix {
		t.Fatalf("the two histories start from different prefixes: %d and %d", got, prefix)
	}

	// H1: die before the commit record's barrier returns.
	s1, err := Open(h1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	real1 := s1.sync
	barriers := 0
	s1.sync = func(f *os.File) error {
		if f == s1.log {
			barriers++
			if barriers == 2 {
				// The record's bytes are in the file; the barrier never
				// returned. This is the instant the process dies.
				return errSidecarCrash
			}
		}
		return real1(f)
	}
	if err := s1.CommitGroup(groupParts(parts, 1)); !errors.Is(err, errSidecarCrash) {
		t.Fatalf("H1: expected the simulated crash at the second barrier, got %v", err)
	}
	s1.crashClose()
	s1.lock.release()

	// H2: the same transaction, committed in full.
	s2, err := Open(h2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.CommitGroup(groupParts(parts, 1)); err != nil {
		t.Fatalf("H2: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	a, err := os.ReadFile(filepath.Join(h1, logName))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(h2, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("the two histories left different logs (%d and %d bytes) before any fault was "+
			"applied, so this fixture cannot demonstrate anything about evidence", len(a), len(b))
	}
	partLen := (len(a) - prefix) / parts
	holeParts(t, h1, prefix, partLen, holes...)
	holeParts(t, h2, prefix, partLen, holes...)

	if digest(t, filepath.Join(h1, logName)) != digest(t, filepath.Join(h2, logName)) {
		t.Fatal("the faults left different logs; the fixture is not the ambiguous-cut one")
	}
	return h1, h2
}

// TestTwoHistoriesWithIdenticalLogsGetOppositeAnswers is the deliverable of
// the sidecar and the reason the second barrier was priced and ratified.
//
// The two stores' logs are byte-identical — asserted, not assumed — so no
// function of those bytes can be right about both. The sidecar is the only
// thing that differs, and the answers are opposite: the abandoned transaction
// is discarded and the node boots, and the committed one is refused rather than
// deleted in silence.
//
// The shape is the boot-time silent discard's second row: an INTERIOR part and
// the commit record are both destroyed. On that store the group's opener is
// intact and read in sequence, so its extent is honest and available and still
// decides nothing; and no anchor exists at any sequence, so `successorRunEnd`
// never reached it either. It is the row the owner's disposition split left as
// needing this and nothing else.
func TestTwoHistoriesWithIdenticalLogsGetOppositeAnswers(t *testing.T) {
	const parts = 4
	crashed, committed := buildTwoHistories(t, parts, 2, 3)

	// Non-vacuity: the sidecars must actually differ, or the assertions below
	// would be reading one fact twice.
	if e := sidecarOf(t, crashed); !e.verified || e.has != true || e.high != 0 {
		t.Fatalf("the crashed history's sidecar is %+v, want the seed commit's sequence 0 and "+
			"nothing from the abandoned group — if it names the group, the record was written "+
			"before the barrier returned and the whole ordering argument is inverted", e)
	}
	if e := sidecarOf(t, committed); !e.verified || !e.has || e.high != uint64(parts) {
		t.Fatalf("the committed history's sidecar is %+v, want high = %d", e, parts)
	}

	// The crashed history: nothing was ever reported committed, so the node
	// must start and discard the transaction, exactly as it did before the sidecar.
	s, err := Open(crashed, Options{})
	if err != nil {
		t.Fatalf("the abandoned transaction denied a boot: %v", err)
	}
	if v, ok := s.Get([]byte("committed-key")); !ok || string(v) != "committed-value" {
		t.Fatalf("the committed record before the group was lost (present=%v value=%q)", ok, v)
	}
	assertGeneration(t, s, parts, "")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The committed history: the same bytes, and a refusal.
	beforeRefusal, err := os.ReadFile(filepath.Join(committed, logName))
	if err != nil {
		t.Fatal(err)
	}
	err = assertRefusesToOpen(t, committed, "a committed transaction lost an interior part and "+
		"its commit record — the interior-part hole")
	for _, want := range []string{"was reported committed", "resync"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Fatalf("the refusal does not say %q: %v", want, err)
		}
	}
	// A REFUSAL THAT SHORTENS THE FILE FIRST IS STILL A REFUSAL FROM THE
	// OUTSIDE, and that is how a third site went uncovered. replayLog's three
	// checks overlap: delete the one in front of the in-loop truncation and the
	// clean-log one still refuses — but only AFTER the truncate has run, so the
	// committed group is destroyed on the way to the error. Every assertion
	// about the verdict stayed green. The bytes are what separate "refused" from
	// "emptied, then refused".
	afterRefusal, err := os.ReadFile(filepath.Join(committed, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeRefusal, afterRefusal) {
		t.Fatalf("the REFUSED Open shortened the log from %d to %d byte(s) — the committed "+
			"transaction was destroyed on the way to the refusal", len(beforeRefusal),
			len(afterRefusal))
	}

	// And `repair` must agree with the boot path on both, because disagreeing
	// about the same bytes IS the drift: `zycordd repair` printed "Nothing to repair
	// — start the node" about a store the start deleted a transaction from.
	if d := diagnose(t, crashed); d.Damaged {
		t.Fatalf("repair calls the abandoned store damaged, but the node boots it: %s",
			d.Explanation)
	}
	d := diagnose(t, committed)
	if d.Repairable || !d.Damaged {
		t.Fatalf("repair offers a cut over a transaction the store reported committed "+
			"(Damaged=%v Repairable=%v): %s", d.Damaged, d.Repairable, d.Explanation)
	}
}

// TestTheSidecarRefusesTheTailShapeAtEveryTruncationDepth closes the residual
// the removed machinery was accepted with, and it does so at every depth rather
// than above a threshold.
//
// The ambiguous-cut tail fixture: one committed record, then a second
// single-record commit, and the log then ends k bytes into that second record.
// T1 is an ordinary crash mid-write — nothing committed. T2 is that record
// COMMITTED and then truncated through by a second fault. The two logs are
// identical at every k.
//
// The rule this replaces could only refuse T2 at k = len(record), because a
// surviving genuine header whose frame overruns the file decodes as a proven
// short write and was read as "the writer stopped" — the residual
// docs/RUNNING.md spent three paragraphs on. The sidecar never reads the region
// at all, so it refuses at EVERY k. That is the whole difference between
// bounding evidence and bounding work.
func TestTheSidecarRefusesTheTailShapeAtEveryTruncationDepth(t *testing.T) {
	build := func(t *testing.T) (dir string, prefix, recLen int) {
		t.Helper()
		dir = t.TempDir()
		s, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		first := &Batch{}
		first.Put([]byte("committed-key"), []byte("committed-value"))
		if err := s.Commit(first); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, logName))
		if err != nil {
			t.Fatal(err)
		}
		prefix = int(info.Size())
		second := &Batch{}
		second.Put([]byte("second-key"), []byte("second-value"))
		if err := s.Commit(second); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		info, err = os.Stat(filepath.Join(dir, logName))
		if err != nil {
			t.Fatal(err)
		}
		return dir, prefix, int(info.Size()) - prefix
	}

	full, prefix, recLen := build(t)
	whole, err := os.ReadFile(filepath.Join(full, logName))
	if err != nil {
		t.Fatal(err)
	}

	// k = recLen is not in the sweep and is the control below it: there the
	// record survived whole, both stores are the same healthy store, and a
	// refusal would be a false one.
	refusedAt, discardedAt := 0, 0
	for k := 0; k < recLen; k++ {
		t.Run(fmt.Sprintf("k=%d", k), func(t *testing.T) {
			// T1: nothing was ever committed past the prefix.
			t1 := t.TempDir()
			if err := os.WriteFile(filepath.Join(t1, logName), whole[:prefix+k], 0o600); err != nil {
				t.Fatal(err)
			}
			writeSidecar(t, t1, 1) // sequence 0 committed, and nothing else.

			// T2: sequence 1 was committed, then truncated through.
			t2 := t.TempDir()
			if err := os.WriteFile(filepath.Join(t2, logName), whole[:prefix+k], 0o600); err != nil {
				t.Fatal(err)
			}
			writeSidecar(t, t2, 2) // sequences 0..1 committed.

			if digest(t, filepath.Join(t1, logName)) != digest(t, filepath.Join(t2, logName)) {
				t.Fatal("the two stores' logs differ, so this k proves nothing")
			}

			// T2 refuses at every k, including k = 0 and k = recLen.
			assertRefusesToOpen(t, t2, "a committed record was truncated through")
			if d := diagnose(t, t2); d.Repairable {
				t.Fatalf("a cut was offered over a committed record: %s", d.Explanation)
			}
			refusedAt++

			// T1 must still recover, at every k, or the sidecar has become a
			// blanket refusal rather than a discriminator.
			s, err := Open(t1, Options{})
			if err != nil {
				t.Fatalf("an ordinary crash mid-write denied a boot at k=%d: %v", k, err)
			}
			if v, ok := s.Get([]byte("committed-key")); !ok || string(v) != "committed-value" {
				t.Fatalf("the committed record was lost at k=%d", k)
			}
			if _, ok := s.Get([]byte("second-key")); ok {
				t.Fatalf("an uncommitted record was applied at k=%d", k)
			}
			s.Close()
			discardedAt++
		})
	}
	// Anti-vacuity in both directions: a sweep that refused everything, or that
	// discarded everything, would pass every assertion above one-sidedly.
	if refusedAt == 0 || discardedAt == 0 {
		t.Fatalf("the sweep is one-sided: %d refusals and %d recoveries over %d depths",
			refusedAt, discardedAt, recLen)
	}

	// The control at k = recLen: the record survived whole, so BOTH histories
	// are the healthy store and neither may be refused. Without it every
	// assertion above would pass for a rule that refuses any store whose
	// sidecar names a sequence at all.
	t.Run("k=recLen the record survived whole", func(t *testing.T) {
		for _, high := range []uint64{1, 2} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, logName), whole, 0o600); err != nil {
				t.Fatal(err)
			}
			writeSidecar(t, dir, high)
			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatalf("an intact log with a sidecar naming %d was refused: %v", high-1, err)
			}
			if v, ok := s.Get([]byte("second-key")); !ok || string(v) != "second-value" {
				t.Fatalf("the second record was not applied (present=%v value=%q)", ok, v)
			}
			s.Close()
		}
	})
}

// downgradeRepairClause is the cause-attribution sentence the clean-log refusal
// must carry, pinned here as a literal rather than imported from the source, so
// that editing the message is what fails this test.
//
// It is a GOLDEN, in the sense the report goldens in repair_test.go are: the
// exact words are an operator contract, and the only way to change them is to
// change this constant in a diff a human reads.
const downgradeRepairClause = "This is also the state left behind by `zycordd repair` run with " +
	"a binary older than this one — see docs/RUNNING.md: run repair with the same binary the " +
	"node runs."

// TestTheCleanLogRefusalNamesDowngradeRepairAsACause pins the one legibility
// clause the downgrade-repair triage settled on, in both readers.
//
// THE FAILURE IS FORWARD IN TIME, and that is the whole reason the clause
// exists. An operator runs `zycordd repair` with a pre-sidecar binary: that
// build shortens the log and leaves `commits` naming what the log used to hold.
// Nothing is wrong yet, as far as anyone can see. The damage surfaces only after
// an upgrade, at which point the old binary is gone and the evidence is a
// directory the new one refuses to open — a clean log that cannot account for a
// committed sequence, which is exactly the state a media fault that removed a
// record whole also produces.
//
// That triage put the gate on legibility rather than on mechanism: a refusal
// that names the cause and the remedy is LAUNCH.md §3 case 4 handled, and one
// that reads as unexplained corruption is a node that "does not come back". The
// message already named the evidence and the remedy; what it did not name was
// the operator's own last action as a suspect. Someone who does not already know
// about the sidecar cannot get from "it is gone" to "I did this with the old
// binary" unaided.
//
// The fixture is the k = 0 row of the tail sweep above, isolated: a log that
// reads cleanly to its end and a sidecar naming one sequence past it. That is
// the ONLY shape that reaches both clean-log branches — every other store in
// this suite ends in damage and routes through a truncation site instead — so
// the two assertions below are on the two messages the decision names, and not
// on their neighbours.
func TestTheCleanLogRefusalNamesDowngradeRepairAsACause(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &Batch{}
	b.Put([]byte("committed-key"), []byte("committed-value"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The sidecar names sequence 1 as reported committed; the log holds only
	// sequence 0 and ends on a record boundary. This is byte for byte what an
	// older `repair` leaves behind after it shortens the log without lowering
	// the sidecar.
	writeSidecar(t, dir, 2)

	// Non-vacuity on the shape: the log must be undamaged, or this is one of
	// the damaged fixtures under a new name and neither clean-log branch runs.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, st := decodeRecord(raw); st != decodeOK {
		t.Fatalf("the fixture's first record does not decode (status %v), so the readers reach "+
			"their damage branches rather than the clean-log ones", st)
	}

	// The boot path: replayLog's third site.
	err = assertRefusesToOpen(t, dir, "a clean log cannot account for a committed sequence")
	if !strings.Contains(err.Error(), "reads cleanly to its end") {
		t.Fatalf("the refusal is not the clean-log one, so this test is pinning the wrong "+
			"message: %v", err)
	}
	if !strings.Contains(err.Error(), downgradeRepairClause) {
		t.Fatalf("the clean-log refusal does not name downgrade-repair as a cause. An operator "+
			"who does not already know about the sidecar reads this as corruption, which is the "+
			"LAUNCH.md §3 case-4 shape this clause was gated on.\nwant to contain: %s\ngot: %v",
			downgradeRepairClause, err)
	}

	// The instrument the operator actually runs: Diagnose's clean-log site. The
	// two must say the same thing about the same directory, which is the boot/repair
	// agreement rule and the reason the clause is added in both places.
	d := diagnose(t, dir)
	if !d.Damaged || d.Repairable {
		t.Fatalf("repair says Damaged=%v Repairable=%v about a store Open refuses: %s",
			d.Damaged, d.Repairable, d.Explanation)
	}
	if !strings.Contains(d.Explanation, "reads to its end and accounts for sequences") {
		t.Fatalf("the diagnosis is not the clean-log one, so this test is pinning the wrong "+
			"message: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, downgradeRepairClause) {
		t.Fatalf("`repair`'s clean-log diagnosis does not name downgrade-repair as a cause, so "+
			"the two readers disagree about the same directory.\nwant to contain: %s\ngot: %s",
			downgradeRepairClause, d.Explanation)
	}
}

// TestACommitRecordRemovedWholeIsRefusedByBothReaders is the fixture two
// `withholds` call sites had no test, and it is here because a review found
// them by mutating every site rather than two of five.
//
// THE SHAPE IS THE ONE NEITHER OTHER FIXTURE REACHES: a committed group whose
// commit record is removed WHOLE, so the log ends exactly on a record boundary.
// Every other store in this suite ends in damage — a hole, a torn frame, a
// partial record — and damage is what routes recovery through the two sites the
// grid did mutate. Here nothing is damaged at all. The prefix walk consumes the
// file to its last byte with a transaction still open, and both readers take
// their OTHER branch:
//
//	replayLog reaches the `len(pending) > 0` truncation after the loop, which
//	asks withholds(groupSeq);
//	Diagnose reaches `consumed == len(raw)` with groupOpen, which asks
//	withholds(firstMissing).
//
// What each mutant does when it survives is why this is not a coverage tidy-up.
// Delete replayLog's and a REFUSED Open truncates the log first — the committed
// group is destroyed on the way to a refusal, so the store is emptied and then
// bricked, which is both failures this change exists to prevent, at once.
// Delete Diagnose's and the drift comes back verbatim: "Nothing to repair — start the
// node" about a store the node will not start.
//
// The log is compared byte for byte across the refused Open, because a refusal
// that shortens the file first is still a refusal from the outside.
func TestACommitRecordRemovedWholeIsRefusedByBothReaders(t *testing.T) {
	f := buildClassFixture(t)

	// The group's parts 0..2 are on disk and its commit record is not. Under
	// the committed history both barriers returned before the fault removed it.
	committed := writeClassLogCommitted(t, f, classGroupParts-1)
	abandoned := writeClassLog(t, f, classGroupParts-1)

	before, err := os.ReadFile(filepath.Join(committed, logName))
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(filepath.Join(abandoned, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, other) {
		t.Fatal("the two histories left different logs, so the opposite answers below are " +
			"not attributable to the sidecar")
	}
	// Non-vacuity on the shape: the log must end on a record boundary with a
	// transaction open, or this fixture is one of the damaged ones under a new
	// name and it exercises neither site.
	if _, _, _, n, st := decodeRecord(before[len(before)-len(f.parts[2]):]); st != decodeOK ||
		n != len(f.parts[2]) {
		t.Fatalf("the log does not end on a whole record (status %v, n=%d), so it is damaged "+
			"and reaches the branches the other fixtures already cover", st, n)
	}

	// replayLog's `len(pending) > 0` site.
	err2 := assertRefusesToOpen(t, committed, "a committed group's commit record was removed whole")
	if !strings.Contains(err2.Error(), "was reported committed") {
		t.Fatalf("the refusal does not rest on the commit record sidecar: %v", err2)
	}
	after, err := os.ReadFile(filepath.Join(committed, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the REFUSED Open shortened the log from %d to %d byte(s) — the committed "+
			"transaction was destroyed on the way to the refusal, which leaves the store both "+
			"emptied and unbootable", len(before), len(after))
	}

	// Diagnose's `consumed == len(raw)` site. The two readers must agree, and
	// the sentence that must not appear is the most confident one this
	// instrument has.
	d := diagnose(t, committed)
	if !d.Damaged || d.Repairable {
		t.Fatalf("repair says Damaged=%v Repairable=%v about a store Open refuses: %s",
			d.Damaged, d.Repairable, d.Explanation)
	}
	if strings.Contains(d.Explanation, "Nothing to repair") {
		t.Fatalf("the drift, verbatim: repair tells an operator to start a node that refuses to "+
			"start: %s", d.Explanation)
	}

	// The control, in both readers: nothing was ever reported committed, so the
	// node discards the abandoned transaction and `repair` says start the node.
	if d := diagnose(t, abandoned); d.Damaged || d.Repairable {
		t.Fatalf("repair calls an abandoned transaction damaged (Damaged=%v Repairable=%v): %s",
			d.Damaged, d.Repairable, d.Explanation)
	}
	assertOpensWithOnlyTheCommittedRecord(t, abandoned)
}

// TestEveryCallSiteOfTheRecoveryRuleIsRegistered is the guard that binds the
// NEXT change, and it exists because two rounds of review found the same defect
// at three levels and the third level was this one.
//
// The recovery rule is one function, commitEvidence.withholds, and it is called
// from several places. A mutation grid that mutates the FUNCTION and two of its
// CALL SITES has measured two call sites, not the rule — and reporting it as
// "the rule is covered" is an enumeration along one named axis presented as
// coverage of the space, which is PROTOCOL rule 21's shape. That is not a
// hypothetical: the two sites the first grid skipped BOTH survived the entire
// suite, and instrumenting all of them then found a third nobody had named.
// Deleting site 1 makes a REFUSED Open truncate the committed group away
// first — every assertion about the verdict stayed green while the data went.
//
// A grid is a thing someone runs. This is a thing that runs. The table below is
// the register of call sites, and the count is asserted against the package's
// own syntax tree, so a site added without a row fails here rather than sailing
// past a check nobody re-ran.
//
// IT COUNTS BY AST, NOT BY TEXT, and that is deliberate. A grep for
// `evidence.withholds(` assumes the receiver is spelled `evidence`, and a grep
// for `.withholds(` also matches the prose in three doc comments. Both are the
// same failure this package keeps meeting: a discovery rule that hides a case
// through the shape it assumes. Counting *ast.CallExpr whose selector is
// `withholds` assumes only that it is a call.
func TestEveryCallSiteOfTheRecoveryRuleIsRegistered(t *testing.T) {
	// The register. One row per call site, in file order, naming the branch it
	// guards and the probe that killed it at the head this was written for.
	// Adding a call site means adding a row AND a probe; the row alone is a
	// claim, and a claim is what this test exists to stop.
	registered := map[string][]string{
		"store.go": {
			"replayLog, the in-loop truncation of a damaged record — probe M13",
			"replayLog, the truncation of a group whose parts simply stop — probe M11",
			"replayLog, a clean log that cannot account for a committed sequence — probe M5",
		},
		"repair.go": {
			"Diagnose, a clean log that cannot account for a committed sequence — probe M12",
			"Diagnose, before a cut is offered — probe M6",
		},
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}

	found := map[string]int{}
	files := 0
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			files++
			name := filepath.Base(path)
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "withholds" {
					found[name]++
				}
				return true
			})
		}
	}

	// Anti-vacuity, in both halves. A scan that parsed nothing, or that found no
	// call sites at all, would satisfy every comparison below by being empty —
	// which is the failure mode this whole test is about, one level down.
	if files == 0 {
		t.Fatal("the scan parsed no non-test files, so it measured nothing")
	}
	total := 0
	for _, n := range found {
		total += n
	}
	if total == 0 {
		t.Fatal("the scan found no call sites of the recovery rule at all. Either the rule was " +
			"renamed — in which case this test is looking for the wrong selector and is now " +
			"measuring nothing — or every reader stopped consulting it, which is the change " +
			"this test exists to make loud")
	}

	for name, count := range found {
		rows, ok := registered[name]
		if !ok {
			t.Fatalf("%s calls the recovery rule %d time(s) and is not in the register. Add a "+
				"row naming the branch each call guards, and a mutation probe that deletes it — "+
				"a call site nothing mutates is a call site nothing measures, and both sites "+
				"the first grid skipped survived the whole suite", name, count)
		}
		if count != len(rows) {
			t.Fatalf("%s calls the recovery rule %d time(s); the register lists %d:\n  %s\n"+
				"Every call site needs a row AND a probe that deletes it. If a site was removed, "+
				"delete its row and say so; if one was added, add both.",
				name, count, len(rows), strings.Join(rows, "\n  "))
		}
	}
	for name, rows := range registered {
		if _, ok := found[name]; !ok {
			t.Fatalf("the register lists %d call site(s) in %s and the scan found none — the "+
				"register is describing a file that no longer calls the rule", len(rows), name)
		}
	}
}

// TestNoSidecarContentMakesTheStoreDiscardMoreThanItKeepsWithout pins the
// property the owner's ratification named as the one the implementation must
// hold: THERE IS NO BYTE STRING IN `commits` THAT MAKES THIS STORE DELETE
// SOMETHING IT KEEPS TODAY.
//
// The claim is existential-shaped on purpose (PROTOCOL rule 21). It is NOT
// "no content anywhere can do this" — that is a statement about a space nobody
// enumerated. It is: over the contents named below, on the damaged stores named
// below, no content moved any store from "refuses" to "cuts", and at least one
// moved a store the other way. The structural reason the wider claim holds is
// in commits.go and is one line of code: the evidence is consulted through
// commitEvidence.withholds and nowhere else, and withholds can only return an
// error.
//
// The axis searched is the SIDECAR'S CONTENT, holding the log fixed. It says
// nothing about logs this suite did not build.
func TestNoSidecarContentMakesTheStoreDiscardMoreThanItKeepsWithout(t *testing.T) {
	f := buildClassFixture(t)
	stores := []struct {
		name  string
		holes []int
	}{
		{"an abandoned group with an interior hole", []int{2}},
		{"an abandoned group with a hole in its opener", []int{0}},
		{"two damage sites: the opener and the commit record", []int{0, classGroupParts - 1}},
		{"three damage sites", []int{0, 2, classGroupParts - 1}},
	}

	garbage := bytes.Repeat([]byte{0xA5}, commitsFileLen)
	wrongMagic := append([]byte(nil), encodeCommitSlot(9, 99)...)
	wrongMagic[0] ^= 0xFF
	tornSlot := append([]byte(nil), encodeCommitSlot(9, 99)...)
	tornSlot[commitSlotLen-1] ^= 0xFF

	// The lower-slot shape: the slot with the HIGHER write counter fails its checksum
	// and the lower one survives, so the reader falls back to a number one
	// commit below the truth. It belongs in this sweep because the sweep is the
	// monotone-refuse property, and an under-reporting sidecar is the one input
	// that could plausibly break it in the offering direction.
	newestTorn := make([]byte, commitsFileLen)
	copy(newestTorn[commitSlotStride:], encodeCommitSlot(1, 2))
	tornTop := append([]byte(nil), encodeCommitSlot(2, uint64(classGroupParts)+1)...)
	tornTop[commitCRCOff] ^= 0xFF
	copy(newestTorn, tornTop)

	contents := []struct {
		name  string
		write func(t *testing.T, dir string)
	}{
		{"absent", func(t *testing.T, dir string) {}},
		{"all zero", func(t *testing.T, dir string) {
			mustWrite(t, dir, make([]byte, commitsFileLen))
		}},
		{"garbage", func(t *testing.T, dir string) { mustWrite(t, dir, garbage) }},
		{"both slots corrupt", func(t *testing.T, dir string) {
			raw := make([]byte, commitsFileLen)
			copy(raw, tornSlot)
			copy(raw[commitSlotStride:], tornSlot)
			mustWrite(t, dir, raw)
		}},
		{"the newest slot corrupt, the older surviving", func(t *testing.T, dir string) {
			mustWrite(t, dir, newestTorn)
		}},
		{"a foreign magic", func(t *testing.T, dir string) {
			raw := make([]byte, commitsFileLen)
			copy(raw, wrongMagic)
			mustWrite(t, dir, raw)
		}},
		{"nothing committed", func(t *testing.T, dir string) { writeSidecar(t, dir, 0) }},
		{"only the seed commit", func(t *testing.T, dir string) { writeSidecar(t, dir, 1) }},
		{"the whole group committed", func(t *testing.T, dir string) {
			writeSidecar(t, dir, uint64(classGroupParts)+1)
		}},
		{"a sequence far beyond the log", func(t *testing.T, dir string) {
			writeSidecar(t, dir, 1<<40)
		}},
		{"the maximum representable sequence", func(t *testing.T, dir string) {
			writeSidecar(t, dir, ^uint64(0))
		}},
	}

	moved := 0
	for _, st := range stores {
		base := writeClassLog(t, f, classGroupParts, st.holes...)
		baseCut := diagnose(t, base).Repairable
		for _, c := range contents {
			t.Run(st.name+"/"+c.name, func(t *testing.T) {
				dir := writeClassLog(t, f, classGroupParts, st.holes...)
				c.write(t, dir)
				got := diagnose(t, dir).Repairable
				if got && !baseCut {
					t.Fatalf("MONOTONE-REFUSE VIOLATED: with no sidecar this store is refused, "+
						"and with %q a cut is offered — the sidecar authorised a deletion, "+
						"which it must never do in any direction", c.name)
				}
				if !got && baseCut {
					moved++
				}
			})
		}
	}
	// Anti-vacuity: if no content ever withheld a cut, the loop above proved
	// only that nothing happens.
	if moved == 0 {
		t.Fatal("no sidecar content withheld a cut on any store, so this sweep is measuring " +
			"an inert file rather than a rule")
	}
}

func mustWrite(t *testing.T, dir string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, commitsName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestASidecarWriteFailureCostsEvidenceAndNotTheCommit pins the one place this
// design deliberately declines to be strict, and it is a limit rather than a
// guarantee.
//
// By the time the sidecar is written the log's own barrier has returned: the
// transaction IS durable and WILL be replayed. Failing the call would tell a
// caller a transaction failed that in fact committed, and would leave this
// process's live view missing a mutation its own log holds. So the failure is
// logged and swallowed, the commit stands, and the store falls back to reading
// the log alone until it is reopened — which is exactly the pre-sidecar behaviour,
// and exactly as much protection as a store written by a build without the
// sidecar has.
//
// What this test also pins is the recovery: one clean Open restates the sidecar
// from what replay accounted for, so the evidence comes back without an
// operator.
func TestASidecarWriteFailureCostsEvidenceAndNotTheCommit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The sidecar's file is made unusable, so the WRITE fails rather than only
	// its barrier: a slot that reached the page cache and not the platter is a
	// slot this process can still read back, which would make the assertion
	// below pass for the wrong reason.
	if err := s.commits.Close(); err != nil {
		t.Fatal(err)
	}
	b := &Batch{}
	b.Put([]byte("k"), []byte("v"))
	if err := s.Commit(b); err != nil {
		t.Fatalf("a commit whose log barrier returned was reported as failed: %v", err)
	}
	if s.failed != nil {
		t.Fatalf("the store was poisoned by a sidecar failure, so a node stops committing over "+
			"lost evidence rather than over lost data: %v", s.failed)
	}
	if e := sidecarOf(t, dir); e.has {
		t.Fatalf("the sidecar recorded the commit despite its own barrier failing: %+v", e)
	}
	s.crashClose()
	s.lock.release()

	// One clean boot restates it.
	re, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer re.Close()
	if v, ok := re.Get([]byte("k")); !ok || string(v) != "v" {
		t.Fatalf("the committed record was lost (present=%v value=%q)", ok, v)
	}
	if e := sidecarOf(t, dir); !e.verified || !e.has || e.high != 0 {
		t.Fatalf("the sidecar was not restated by a clean boot: %+v", e)
	}
}

// TestCompactionLowersTheSidecarBeforeTheLogIsTruncated pins the ordering that
// keeps compaction from bricking a store.
//
// Sequence numbers restart at zero when the log does, so a sidecar carrying the
// previous generation's highest sequence would, against the new log, claim
// commits that generation never had — and would refuse every cut that store
// could ever legitimately need, starting with its own first torn tail. The
// order is the same rule the commit path follows in the mirror: make the LOW
// value durable first.
//
// The ordering is observed at the instant it happens rather than inferred from
// the end state, because the end state is the same whichever order ran.
func TestCompactionLowersTheSidecarBeforeTheLogIsTruncated(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		b := &Batch{}
		b.Put([]byte{byte(i)}, []byte("v"))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if e := sidecarOf(t, dir); !e.has || e.high != 2 {
		t.Fatalf("precondition: sidecar is %+v, want high=2", e)
	}

	real := s.sync
	logSizeAtReset := int64(-1)
	s.sync = func(f *os.File) error {
		err := real(f)
		if f == s.commits {
			if info, statErr := os.Stat(filepath.Join(dir, logName)); statErr == nil {
				logSizeAtReset = info.Size()
			}
		}
		return err
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	if logSizeAtReset <= 0 {
		t.Fatalf("the sidecar was reset when the log was already %d bytes — the truncate ran "+
			"first, so a crash in between leaves a HIGH sidecar against an empty log, which "+
			"refuses every future cut this store can need", logSizeAtReset)
	}
	if e := sidecarOf(t, dir); !e.verified || e.has {
		t.Fatalf("after compaction the sidecar is %+v, want a verified \"nothing committed\"", e)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// THE COMPACTED STORE'S FIRST TORN TAIL IS STILL DISCARDABLE, and this is
	// the half that catches the failure a stale-high sidecar would cause. After
	// compaction the sequence space restarts at zero, so the very first commit
	// in the new generation is sequence 0 and a cut over it removes sequence 0 —
	// which is the one firstCutSeq a "verified, nothing committed" sidecar could
	// wrongly withhold if the rule stopped distinguishing "no commit" from
	// "sequence 0 committed". Nothing else in this suite reaches firstCutSeq 0.
	re, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	// A genuine torn tail: half the record reached the file and the process
	// died. Failing only the barrier would leave the record INTACT on disk, and
	// an intact record is applied rather than discarded — a different scenario
	// with the same name.
	re.writeHook = func(record []byte) ([]byte, error) {
		return record[:len(record)/2], errSidecarCrash
	}
	first := &Batch{}
	first.Put([]byte("after-compaction"), []byte("v"))
	if err := re.Commit(first); !errors.Is(err, errSidecarCrash) {
		t.Fatalf("expected the staged crash at the barrier, got %v", err)
	}
	re.crashClose()
	re.lock.release()

	again, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
	if err != nil {
		t.Fatalf("a compacted store could not discard its own first torn tail: %v", err)
	}
	defer again.Close()
	if _, ok := again.Get([]byte("after-compaction")); ok {
		t.Fatal("a record whose barrier never returned was applied")
	}
	if v, ok := again.Get([]byte{0}); !ok || string(v) != "v" {
		t.Fatalf("the snapshot's contents were lost (present=%v value=%q)", ok, v)
	}
}

// TestApplyLeavesTheSidecarNamingExactlyWhatSurvivesTheCut pins Apply's
// post-condition.
//
// This is the one operation in the design that can brick a store: a sidecar
// left claiming more than the log holds refuses every future boot, permanently,
// with no door behind this one. So the rewrite is a post-condition of the cut
// and not a judgement call, and the repaired store is booted here to prove it.
func TestApplyLeavesTheSidecarNamingExactlyWhatSurvivesTheCut(t *testing.T) {
	// The first-part-hole store: an abandoned group whose commit record never
	// landed, with a hole in its FIRST part. Open refuses — the surviving later
	// parts are not dismissed, because no group ever opened — and `repair`
	// offers the cut, which is the precondition Apply needs.
	f := buildClassFixture(t)
	dir := writeClassLog(t, f, classGroupParts-1, 0)
	assertRefusesToOpen(t, dir, "a hole in an abandoned group's first part")

	d := diagnose(t, dir)
	if !d.Repairable {
		t.Fatalf("precondition: no cut offered: %s", d.Explanation)
	}
	if d.RecordsKept != 1 {
		t.Fatalf("precondition: RecordsKept = %d, want 1", d.RecordsKept)
	}
	r, err := OpenForRepair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(d); err != nil {
		t.Fatal(err)
	}
	r.Close()

	if e := sidecarOf(t, dir); !e.verified || !e.has || e.high != 0 {
		t.Fatalf("after a cut keeping 1 record the sidecar is %+v, want high=0 — anything "+
			"higher refuses the store an operator just repaired, for ever", e)
	}
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("the repaired store does not boot: %v", err)
	}
	defer s.Close()
	if v, ok := s.Get([]byte("committed-key")); !ok || string(v) != "committed-value" {
		t.Fatalf("the repair kept the wrong record (present=%v value=%q)", ok, v)
	}
}

// TestAnAheadOfWriteRecordWouldNotHaveSeparatedTheHistories is the ordering
// correction, kept as a test because the design this file was commissioned
// under prescribes the other order in three places and someone will read it.
//
// That design requires the out-of-band record to be fsynced AHEAD of the log write.
// That records what the writer was ABOUT TO DO — and both histories were about
// to do the same thing, because an ordinary crash lands after the commit
// record's write and before its barrier returns. This drives H1 and asserts
// that at the instant of the crash the commit record's bytes are already in the
// log: an intent fsynced before that write would have been durable in H1 too,
// so it separates nothing, and the rule it feeds would refuse a boot after an
// ordinary crash.
func TestAnAheadOfWriteRecordWouldNotHaveSeparatedTheHistories(t *testing.T) {
	const parts = 4
	crashed, committed := buildTwoHistories(t, parts, 2, 3)

	// The logs were identical BEFORE the faults (buildTwoHistories asserts it),
	// which is the fact this test is about: everything the writer intended, and
	// everything it wrote, is the same in both. Only the barrier differs.
	if digest(t, filepath.Join(crashed, logName)) != digest(t, filepath.Join(committed, logName)) {
		t.Fatal("the fixture no longer produces identical logs")
	}
	e1, e2 := sidecarOf(t, crashed), sidecarOf(t, committed)
	if e1.high == e2.high {
		t.Fatalf("the sidecars agree (%+v and %+v), so the after-the-barrier order records "+
			"nothing the before-the-write order would not have — which is the claim the "+
			"measurement refuted, now failing in the direction that would reinstate it", e1, e2)
	}
	if e1.high >= 1 {
		t.Fatalf("the crashed history's sidecar names sequence %d, which belongs to a "+
			"transaction whose barrier never returned. The record is being written before the "+
			"barrier, and a rule fed by it refuses a boot after an ordinary crash "+
			"(LAUNCH.md section 3 case 4)", e1.high)
	}
}

// twoSlotSidecar plants a file holding both slots: `older` under write counter
// 1 and `newer` under write counter 2, each encoded by the production encoder
// and placed at the offset nextCommitSlotOffset gives its counter. The values
// are highPlusOne, the slot's own encoding.
//
// The bytes are laid down directly rather than by calling the writer twice, and
// that is deliberate: these tests are about which slot the READER picks, so a
// fixture built through writeCommitsFile — which reads the file to choose the
// next counter — would be asking the code under test to set up its own exam.
func twoSlotSidecar(t *testing.T, dir string, older, newer uint64) {
	t.Helper()
	raw := make([]byte, commitsFileLen)
	copy(raw[nextCommitSlotOffset(1):], encodeCommitSlot(1, older))
	copy(raw[nextCommitSlotOffset(2):], encodeCommitSlot(2, newer))
	mustWrite(t, dir, raw)
	for _, off := range []int64{0, commitSlotStride} {
		if _, _, ok := rawSlot(t, dir, off); !ok {
			t.Fatalf("the slot at %d does not verify, so both slots were not planted", off)
		}
	}
}

// rawSlot decodes one slot straight out of the file.
func rawSlot(t *testing.T, dir string, off int64) (counter, highPlusOne uint64, ok bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, commitsName))
	if err != nil {
		t.Fatal(err)
	}
	return decodeCommitSlot(raw[off : off+commitSlotLen])
}

// newestSlotOffset is where the slot with the greater WRITE COUNTER sits,
// derived from the file rather than from readCommitEvidence, so that a test can
// corrupt "the newest slot" without borrowing the selection rule it is checking.
func newestSlotOffset(t *testing.T, dir string) int64 {
	t.Helper()
	c0, _, ok0 := rawSlot(t, dir, 0)
	c1, _, ok1 := rawSlot(t, dir, commitSlotStride)
	if !ok0 || !ok1 {
		t.Fatal("both slots must verify before one can be called the newest")
	}
	if c0 > c1 {
		return 0
	}
	return commitSlotStride
}

// corruptSlot breaks one slot's checksum in place, leaving its magic, version
// and number legible. Breaking only the checksum is what separates "this slot
// does not verify" from "this file is not a sidecar", which a wholesale
// overwrite would also trip.
func corruptSlot(t *testing.T, dir string, off int64) {
	t.Helper()
	path := filepath.Join(dir, commitsName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[int(off)+commitCRCOff] ^= 0xFF
	if _, _, ok := decodeCommitSlot(raw[off : int(off)+commitSlotLen]); ok {
		t.Fatalf("the slot at %d still verifies, so this fixture is not the one it claims", off)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestATornNewestSlotCostsOneCommitOfEvidenceAndNotAllOfIt pins the lower-slot
// under-report in the direction it is actually safe in, and pins it against the
// fix that finding names.
//
// The finding measures that corrupting the slot with the HIGHER write counter leaves
// `readCommitEvidence` returning evidence marked verified carrying a high-water
// mark one commit below the truth, and observes that this is harmless only
// because the read is one-directional. Its suggested fix — require the highest
// counter slot to verify, rather than accepting evidence that verifies on the
// lower slot alone — is a fix for an AUTHORISING read. Applied to the read this
// package actually has, it is a REGRESSION, and this test is what makes that
// concrete rather than an argument.
//
// The store below has the group's commit record holed, so the cut removes
// sequence 1 onward. The newest slot names sequence 4; the older names sequence
// 1. Corrupting the newest costs three sequences of evidence — and the one that
// survives is STILL AT OR ABOVE the first sequence the cut would remove, so the
// store still refuses. Discard the surviving slot instead, as that fix would,
// and this store boots and deletes a transaction it reported committed.
//
// The second half of the test is the anti-vacuity control: with BOTH slots
// broken the same store boots and discards, so the refusal above is being
// carried by the surviving slot rather than by anything else in the fixture.
func TestATornNewestSlotCostsOneCommitOfEvidenceAndNotAllOfIt(t *testing.T) {
	f := buildClassFixture(t)

	dir := writeClassLogRaw(t, f, classGroupParts, 1, classGroupParts-1)
	twoSlotSidecar(t, dir, 2, uint64(len(f.parts))+1)
	newest := newestSlotOffset(t, dir)
	survivor := commitSlotStride - newest // the file holds exactly two slots
	survivorCounter, _, _ := rawSlot(t, dir, survivor)
	corruptSlot(t, dir, newest)

	got := sidecarOf(t, dir)
	if !got.verified || !got.has {
		t.Fatalf("evidence = %+v, want the older slot still supplying evidence. A newest slot "+
			"that fails its checksum must cost ONE COMMIT of evidence, not all of it: "+
			"discarding the surviving slot is the suggested fix, and against a "+
			"one-directional read it permits the deletion this package exists to withhold", got)
	}
	if got.high != 1 || got.counter != survivorCounter {
		t.Fatalf("evidence = %+v, want high=1 from write counter %d — the reader must fall back "+
			"to the surviving slot's own number, not invent one", got, survivorCounter)
	}

	s, err := Open(dir, Options{})
	if err == nil {
		s.Close()
		t.Fatal("the store opened. The cut removes sequence 1 onward and the surviving slot " +
			"says sequence 1 was reported committed, so the boot path must refuse: the " +
			"under-report is one commit deep, and this store is deeper than " +
			"that inside it")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("refused with %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "was reported committed") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// Control: break the survivor too and the same store must boot, or the
	// refusal above proves nothing about which slot carried it.
	both := writeClassLogRaw(t, f, classGroupParts, 1, classGroupParts-1)
	twoSlotSidecar(t, both, 2, uint64(len(f.parts))+1)
	corruptSlot(t, both, 0)
	corruptSlot(t, both, commitSlotStride)
	if e := sidecarOf(t, both); e.verified {
		t.Fatalf("evidence = %+v, want none — the control is not the control it claims", e)
	}
	if n := survivorsAfterBoot(t, both); n != 1 {
		t.Fatalf("survivors = %d, want 1 — with no slot verifying this store must fall back to "+
			"reading the log alone and discard the abandoned group", n)
	}
}

// TestTheReaderTakesTheHigherCounterAndNeverTheHigherHigh pins the other half
// of the selection rule, and it is the half that can brick a store.
//
// The number in a slot is NOT monotone. Compaction resets it to "nothing
// committed" before the log is truncated, Repairer.Apply lowers it before the
// cut, and Open's restatement can lower it — and every one of those leaves the
// previous, HIGHER number in the other slot, intact and verifying. So a reader
// that resolved the two slots by taking the greater NUMBER, rather than the
// greater WRITE COUNTER, would read a pre-compaction generation's high-water
// mark against a log whose sequences restarted at zero. That is the one state
// this design cannot recover from — a sidecar claiming more than the log holds
// refuses every future boot, permanently.
//
// It is worth pinning separately from the under-report because "take the higher
// number" is the obvious way to make that under-report go away, and it trades a
// bounded under-report for an unbounded over-report in the direction that has
// no second door behind it.
func TestTheReaderTakesTheHigherCounterAndNeverTheHigherHigh(t *testing.T) {
	f := buildClassFixture(t)

	// The shape compaction and Apply both leave behind: the stale slot carries
	// the higher number, the current one carries the lowered value.
	dir := writeClassLogRaw(t, f, classGroupParts, 1, classGroupParts-1)
	twoSlotSidecar(t, dir, uint64(len(f.parts))+1, 1)

	got := sidecarOf(t, dir)
	if !got.verified || !got.has {
		t.Fatalf("evidence = %+v, want the newest slot's lowered value", got)
	}
	if got.high != 0 {
		t.Fatalf("evidence = %+v, want high=0 — the reader took the greater NUMBER instead of "+
			"the greater WRITE COUNTER, which resurrects a superseded generation's high-water "+
			"mark and makes a lowered sidecar impossible to write", got)
	}

	// And the consequence, at the boot path: the cut removes sequence 1 onward
	// and the current value names only sequence 0, so it must not withhold.
	if n := survivorsAfterBoot(t, dir); n != 1 {
		t.Fatal("the store refused. A superseded slot was believed over the one that " +
			"superseded it, which is a store no compaction and no repair can ever unstick")
	}
}
