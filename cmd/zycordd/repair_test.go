package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zycord/node/storage"
)

// The `zycordd repair` command surface.
//
// Everything this command decides about *what may be cut* lives in
// node/storage and is tested there. What lives here is the half that stands
// between an operator and an irreversible deletion: which flag wins, what
// counts as consent, and what the exit code says. Those are not incidental —
// a --yes that overrides --dry-run, or a prompt that takes a stray "y",
// deletes a node's data — and by-inspection is not how this repository
// establishes a rule.
//
// noCompaction keeps the store from folding the log into a snapshot, which
// would move every offset these tests damage.
var noCompaction = storage.Options{CompactAfterBytes: 1 << 40}

// commitKeys appends one single-record commit per key and closes the store,
// so the log on disk is exactly those records.
func commitKeys(t *testing.T, dir string, keys ...string) {
	t.Helper()
	s, err := storage.Open(dir, noCompaction)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range keys {
		b := &storage.Batch{}
		b.Put([]byte(k), []byte{byte(i)})
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// repairableDir builds the one shape this command exists for, using nothing
// but the public API, a truncation and a hole punched in the file: three
// ordinary commits, then a three-part transaction that lost its commit record
// to a crash and whose surviving *first* part is destroyed.
//
// The second part survives intact, and with no group open — the first part is
// unreadable — replay cannot dismiss it as a member of anything, so it reads
// as a writer that kept going and the node refuses to start (this is the
// orphaned-second-part shape). Yet it carries more >= 1, so it terminates no
// transaction, the group was never committed, and a cut back to the third
// commit costs nothing. See node/storage,
// TestRepairRecoversAnAbandonedGroupWithAHoleInItsFirstPart.
//
// The three parts hold equal-sized batches, so the record length divides out
// of the file size and the crash can be staged without reaching into the
// format. It returns the directory and the size the log had before the
// abandoned transaction, which is exactly the size a correct repair leaves
// behind.
func repairableDir(t *testing.T) (string, int64) {
	t.Helper()
	dir := t.TempDir()
	commitKeys(t, dir, "a", "b", "c")
	committed := logSize(t, dir)

	// THE GROUP IS CRASHED RATHER THAN COMMITTED AND THEN TRUNCATED, and that is
	// the fixture's meaning rather than a detail of how it is built. A store
	// records the highest sequence it has reported committed out of band
	// (node/storage/commits.go), so committing the group and then removing its
	// commit record would build the OTHER history — one in which a transaction
	// the caller was told had landed is now unreadable — and on that store the
	// correct answer is a refusal, not the cut this whole file is about. The two
	// stores are byte-identical in the log, which is exactly why the fixture has
	// to say which one it is.
	crashGroupBeforeItsCommitRecord(t, dir, "p", "q", "r")

	// The surviving first part is destroyed by a media fault.
	holeAt(t, dir, committed, 8)
	if s, err := storage.Open(dir, noCompaction); err == nil {
		s.Close()
		t.Fatal("setup: the node opens this store, so there is no repair to authorise and " +
			"every check below would be measuring nothing")
	}
	return dir, committed
}

// crashGroupBeforeItsCommitRecord writes every part of a transaction but its
// last, then kills the writer. Nothing is reported committed, so the store's
// out-of-band commit record does not name the group, which is what makes the
// resulting log an abandoned transaction rather than a damaged committed one.
func crashGroupBeforeItsCommitRecord(t *testing.T, dir string, keys ...string) {
	t.Helper()
	opts := noCompaction
	written := 0
	opts.FaultInjector = func(record []byte) ([]byte, error) {
		written++
		if written < len(keys) {
			return record, nil
		}
		return nil, errStagedCrash
	}
	s, err := storage.Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	var group []*storage.Batch
	for _, k := range keys {
		b := &storage.Batch{}
		b.Put([]byte(k), []byte(k))
		group = append(group, b)
	}
	if err := s.CommitGroup(group); err == nil {
		t.Fatal("setup: the group committed, so this is not the abandoned history")
	}
	// The store is poisoned by the staged failure, so Close reports it; the
	// files and the lock are still released, which is all this needs.
	s.Close()
}

var errStagedCrash = errors.New("staged crash")

// holeAt destroys n bytes in place, which is what a lost sector does: the
// records after it stay at the offsets a crash would have left them at.
func holeAt(t *testing.T, dir string, at, n int64) {
	t.Helper()
	path := filepath.Join(dir, "log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := at; i < at+n && i < int64(len(raw)); i++ {
		raw[i] = 0
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func logSize(t *testing.T, dir string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

type repairRun struct {
	code   int
	stdout string
	stderr string
}

func repairCmd(t *testing.T, stdin string, args ...string) repairRun {
	t.Helper()
	var out, errOut strings.Builder
	code := runRepair(args, strings.NewReader(stdin), &out, &errOut)
	return repairRun{code, out.String(), errOut.String()}
}

// TestRepairCommandNeverCutsWithoutTheWholeWordTyped.
//
// The table is the point: every input other than the word itself must leave
// the log byte-for-byte as it was. A prompt that accepts "y" accepts a stray
// keystroke, and an EOF — a repair run from a script with nothing on stdin —
// is not a human agreeing to anything. The consenting rows are what keeps the
// rest from passing for a command that never repairs anything.
func TestRepairCommandNeverCutsWithoutTheWholeWordTyped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stdin   string
		consent bool
	}{
		{"the whole word", "yes\n", true},
		{"the whole word with no newline", "yes", true},
		{"surrounding space", "  yes  \n", true},
		{"a single keystroke", "y\n", false},
		{"nothing at all, as from a script", "", false},
		{"an empty line", "\n", false},
		{"a refusal", "no\n", false},
		{"the word inside a sentence", "yes please\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, want := repairableDir(t)
			before := logSize(t, dir)
			got := repairCmd(t, tc.stdin, "--dir", dir)

			if !strings.Contains(got.stdout, "proposal:") {
				t.Fatalf("the operator was not shown what would be discarded:\n%s", got.stdout)
			}
			if tc.consent {
				if got.code != 0 {
					t.Fatalf("exit %d after consent: %s%s", got.code, got.stdout, got.stderr)
				}
				if size := logSize(t, dir); size != want {
					t.Fatalf("log is %d byte(s) after the repair, want %d", size, want)
				}
				s, err := storage.Open(dir, noCompaction)
				if err != nil {
					t.Fatalf("the store still does not open after a repair reported as done: %v", err)
				}
				s.Close()
				return
			}
			if got.code == 0 {
				t.Fatalf("exit 0 without consent, which reads as \"repaired\":\n%s", got.stdout)
			}
			if !strings.Contains(got.stdout, "declined") {
				t.Fatalf("the command did not say it declined:\n%s", got.stdout)
			}
			if size := logSize(t, dir); size != before {
				t.Fatalf("%d byte(s) were discarded without consent (log %d -> %d)",
					before-size, before, size)
			}
		})
	}
}

// TestDryRunOutranksYes. These two flags pull in opposite directions and both
// can appear on one command line — in a runbook, in shell history, in a
// script that grew a --yes. --dry-run is the one that promises nothing
// changes, and a promise a second flag can quietly revoke is not one.
func TestDryRunOutranksYes(t *testing.T) {
	dir, want := repairableDir(t)
	before := logSize(t, dir)

	got := repairCmd(t, "", "--dir", dir, "--dry-run", "--yes")
	if got.code != 0 {
		t.Fatalf("exit %d: %s%s", got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stdout, "nothing was changed") {
		t.Fatalf("--dry-run did not report that it changed nothing:\n%s", got.stdout)
	}
	if size := logSize(t, dir); size != before {
		t.Fatalf("--yes overrode --dry-run and discarded %d byte(s)", before-size)
	}

	// The same directory with --yes alone does cut, or the check above would
	// pass for a command that never repairs anything.
	if got := repairCmd(t, "", "--dir", dir, "--yes"); got.code != 0 {
		t.Fatalf("--yes alone did not repair: exit %d: %s%s", got.code, got.stdout, got.stderr)
	}
	if size := logSize(t, dir); size != want {
		t.Fatalf("--yes alone left the log at %d byte(s), want %d, so the --dry-run check "+
			"above proves nothing", size, want)
	}
}

// TestRepairCommandRefusesAStoreANodeHasOpen. The lock is the whole answer to
// "may this run against a live node", and the message has to say what to do.
func TestRepairCommandRefusesAStoreANodeHasOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := storage.Open(dir, noCompaction)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got := repairCmd(t, "yes\n", "--dir", dir)
	if got.code != 1 {
		t.Fatalf("exit %d against a live node, want 1: %s%s", got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stderr, "Stop the node first") {
		t.Fatalf("the refusal does not tell the operator what to do:\n%s", got.stderr)
	}
}

// TestRepairCommandRefusesInteriorDamageAndChangesNothing. The class this
// command must never appear to fix: committed records sit behind the damage,
// so there is no honest cut, and the exit code must not read as success.
func TestRepairCommandRefusesInteriorDamageAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	commitKeys(t, dir, "a")
	firstEnd := logSize(t, dir)
	commitKeys(t, dir, "b", "c", "d", "e")

	holeAt(t, dir, firstEnd, 8)
	before := logSize(t, dir)

	got := repairCmd(t, "yes\n", "--dir", dir)
	if got.code == 0 {
		t.Fatalf("exit 0 over damage with committed records behind it:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "NOT REPAIRABLE") {
		t.Fatalf("the verdict does not say the store cannot be repaired:\n%s", got.stdout)
	}
	if size := logSize(t, dir); size != before {
		t.Fatalf("%d byte(s) were discarded over interior damage", before-size)
	}
}

// TestRepairCommandWithoutADirectoryIsAUsageError, kept apart from the
// failure exit code: a mistyped command line must not be indistinguishable
// from a store that needs a resync.
func TestRepairCommandWithoutADirectoryIsAUsageError(t *testing.T) {
	got := repairCmd(t, "")
	if got.code != 2 {
		t.Fatalf("exit %d for a missing --dir, want 2", got.code)
	}
	if got.stdout != "" {
		t.Fatalf("a usage error wrote a report to stdout:\n%s", got.stdout)
	}
}

// TestRepairCommandOnAHealthyStoreDoesNothingAndSaysSo. Consent is on stdin
// and is deliberately ignored: there is nothing to consent to.
func TestRepairCommandOnAHealthyStoreDoesNothingAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	commitKeys(t, dir, "a")
	before := logSize(t, dir)

	got := repairCmd(t, "yes\n", "--dir", dir)
	if got.code != 0 {
		t.Fatalf("exit %d on an undamaged store: %s%s", got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stdout, "Nothing to repair") {
		t.Fatalf("the finding does not say the store is fine:\n%s", got.stdout)
	}
	if size := logSize(t, dir); size != before {
		t.Fatal("an undamaged log was truncated")
	}
}

// groupInteriorRepairableDir builds the store this command reports on WRONGLY
// before the records-read/records-kept distinction was drawn, using nothing
// but the public API and two holes.
//
// Three ordinary commits, then a three-part transaction, then a second
// transaction truncated to its own opener. The first transaction loses its
// middle part AND its commit record to holes, so replay stops inside it with
// the transaction still open; the second transaction's opener is behind the
// damage, belongs to nothing replay has open, and terminates nothing, which
// is what keeps this store on the OFFER path instead of being discarded by
// the node itself.
//
// The cut therefore goes back to the first transaction's opener — one record
// further back than the damage — so the records replay READ and the records
// that SURVIVE differ, which is the whole point of the fixture.
//
// It returns the directory and the size the log had before the first
// transaction, which is exactly what a correct repair leaves behind.
func groupInteriorRepairableDir(t *testing.T) (string, int64) {
	t.Helper()
	dir := t.TempDir()
	commitKeys(t, dir, "a", "b", "c")
	committed := logSize(t, dir)

	s, err := storage.Open(dir, noCompaction)
	if err != nil {
		t.Fatal(err)
	}
	var first []*storage.Batch
	for _, k := range []string{"p", "q", "r"} {
		b := &storage.Batch{}
		b.Put([]byte(k), []byte(k))
		first = append(first, b)
	}
	if err := s.CommitGroup(first); err != nil {
		t.Fatal(err)
	}
	firstEnd := logSize(t, dir)
	var second []*storage.Batch
	for _, k := range []string{"x", "y"} {
		b := &storage.Batch{}
		b.Put([]byte(k), []byte(k))
		second = append(second, b)
	}
	if err := s.CommitGroup(second); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The second transaction's own commit record never reached the disk.
	partLen := (firstEnd - committed) / 3
	secondPartLen := (logSize(t, dir) - firstEnd) / 2
	if err := os.Truncate(filepath.Join(dir, "log"), firstEnd+secondPartLen); err != nil {
		t.Fatal(err)
	}
	// The first transaction's middle part and its commit record are holes.
	holeAt(t, dir, committed+partLen, partLen)
	holeAt(t, dir, committed+2*partLen, partLen)

	// THIS FIXTURE IS A DATA DIRECTORY WRITTEN BY A BUILD WITHOUT THE COMMIT
	// SIDECAR, and it has to be, which is a finding rather than a convenience.
	//
	// The shape this row needs — a cut that runs back over an OPEN transaction,
	// so the records replay read are more than the records that remain — needs an
	// intact record behind the damage that does not belong to that open
	// transaction. Replay dismisses the transaction's own surviving parts, so the
	// record has to come from a LATER one, and a later transaction can only exist
	// on disk if the earlier one committed: a writer whose group is abandoned is
	// poisoned and appends nothing more. So every honest history with this shape
	// is one in which the open transaction really was reported committed, and
	// with the sidecar present the correct answer is a refusal, not a cut.
	//
	// Removing the file is therefore not a workaround for the rule; it selects
	// the one case the rule deliberately does not reach — a store written before
	// this file existed, which gets the protection after one clean start. What
	// is under test here is the CLI's own arithmetic, and this is the only
	// history that still reaches it.
	if err := os.Remove(filepath.Join(dir, "commits")); err != nil {
		t.Fatal(err)
	}

	if s, err := storage.Open(dir, noCompaction); err == nil {
		s.Close()
		t.Fatal("setup: the node opens this store, so there is no repair to authorise and " +
			"every check below would be measuring nothing")
	}
	return dir, committed
}

// TestRepairCommandSaysHowManyRecordsRemainAndNotHowManyItRead is the CLI half
// of the records-read/records-kept distinction, and it is here rather than in
// node/storage because this is where the claim is made: the last line an
// operator sees after an irreversible deletion.
//
// Inside an open transaction the cut goes back to that transaction's first
// record, so the records replay read are not the records that remain. This
// line printed the number replay read. On the store below it said four when
// three remained — over-reporting what survived a deletion, by exactly the
// parts of the transaction the same run discarded.
//
// The pair is the assertion. The orphaned-second-part shape, where no
// transaction is open and the two numbers coincide, is the control that keeps
// this from passing for a command that simply prints a smaller constant.
// repairedVerdict is the whole verdict line this command prints after an
// irreversible deletion, with the row's own numbers.
//
// A substring assertion on the count alone is satisfied by a DECIMAL PREFIX —
// "13 record(s) remain" contains "3 record(s) remain", and a mutant that
// printed RecordsKept+10 survived both rows below. That is the same defect the
// golden in node/storage/repair_test.go was written to remove, reappearing one
// package away, so the answer is the same one: the whole rendered line,
// including the byte count, which anchors the number on both sides.
func repairedVerdict(discarded int64, kept uint64) string {
	return fmt.Sprintf("verdict:   repaired. %d byte(s) discarded; %d record(s) remain. "+
		"Start the node normally.", discarded, kept)
}

// proposalLine is the whole line an operator types `yes` against.
//
// NEITHER NUMBER IN IT WAS ASSERTED ANYWHERE, in either package: `d.Discard+10`
// and `d.Offset+10` both survived every test in this file, while a control that
// renamed the label to "proposalX:" was killed — so the line is rendered and
// reached under this filter, and those two survived for want of an assertion
// rather than want of execution.
//
// It is the strictly more load-bearing of this command's two counted lines.
// The verdict line reports a deletion that already happened; this one is the
// consent screen. The command's own contract is that it "prints the exact
// offset and byte count before asking" and "cannot widen the cut it offered",
// and Apply re-derives the cut from d.Offset — so a divergence between the
// number shown and the number cut breaks that guarantee SILENTLY, with the
// operator's yes attached to a number that is not the one deleted.
//
// Whole line rather than a substring, for the reason repairedVerdict gives one
// line up: a count assertion open at either end is satisfied by a decimal
// prefix, and this file has been bitten by that once already.
func proposalLine(discard, offset int64) string {
	return fmt.Sprintf("proposal:  discard %d byte(s) at offset %d and keep everything "+
		"before it. This is not reversible.", discard, offset)
}

// readableLine is the count line, whole and with its label.
//
// It was `intact:    N record(s)`, and it is the LARGER and more reassuring of
// two adjacent counts on the consent screen — the other being the finding's
// "keeps N record(s)", which is what actually survives. Both numbers are true
// and they measure different things; unlabelled and first, the one that does
// not answer "what will I still have" was the one an operator read. The label
// is asserted whole here, so dropping it fails rather than silently restoring
// the adjacency the two rows below exist to separate.
func readableLine(n uint64) string {
	return fmt.Sprintf("readable:  %d record(s) (records replay could read)", n)
}

func TestRepairCommandSaysHowManyRecordsRemainAndNotHowManyItRead(t *testing.T) {
	t.Run("a cut inside an open transaction", func(t *testing.T) {
		dir, want := groupInteriorRepairableDir(t)
		before := logSize(t, dir)
		r := repairCmd(t, "yes\n", "--dir", dir)
		if r.code != 0 {
			t.Fatalf("exit %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
		}
		if !strings.Contains(r.stdout, readableLine(4)) {
			t.Fatalf("replay must read four records here or the two counts coincide and "+
				"this row separates nothing:\n%s", r.stdout)
		}
		// The consent screen, checked before the verdict. `want` is the offset a
		// correct repair cuts at, so both numbers here are the row's own and
		// neither is read back out of the output being checked.
		if proposal := proposalLine(before-want, want); !strings.Contains(r.stdout, proposal) {
			t.Fatalf("the proposal line is not %q:\n%s", proposal, r.stdout)
		}
		if verdict := repairedVerdict(before-want, 3); !strings.Contains(r.stdout, verdict) {
			t.Fatalf("the verdict line is not %q:\n%s", verdict, r.stdout)
		}
		// The claim, checked against the store rather than against itself.
		if got := logSize(t, dir); got != want {
			t.Fatalf("log is %d byte(s), want %d", got, want)
		}
		s, err := storage.Open(dir, noCompaction)
		if err != nil {
			t.Fatalf("the repaired store does not open: %v", err)
		}
		defer s.Close()
		for _, k := range []string{"a", "b", "c"} {
			if _, ok := s.Get([]byte(k)); !ok {
				t.Fatalf("%q was discarded, so the cut went too far", k)
			}
		}
		for _, k := range []string{"p", "q", "r", "x"} {
			if _, ok := s.Get([]byte(k)); ok {
				t.Fatalf("%q survived, so the transaction was not discarded whole", k)
			}
		}
	})

	t.Run("a cut with no transaction open", func(t *testing.T) {
		dir, want := repairableDir(t)
		before := logSize(t, dir)
		r := repairCmd(t, "yes\n", "--dir", dir)
		if r.code != 0 {
			t.Fatalf("exit %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
		}
		if !strings.Contains(r.stdout, readableLine(3)) {
			t.Fatalf("replay must read three records here — the pair only separates the two "+
				"counts if they COINCIDE on this row:\n%s", r.stdout)
		}
		// The consent screen, checked before the verdict. `want` is the offset a
		// correct repair cuts at, so both numbers here are the row's own and
		// neither is read back out of the output being checked.
		if proposal := proposalLine(before-want, want); !strings.Contains(r.stdout, proposal) {
			t.Fatalf("the proposal line is not %q:\n%s", proposal, r.stdout)
		}
		if verdict := repairedVerdict(before-want, 3); !strings.Contains(r.stdout, verdict) {
			t.Fatalf("the verdict line is not %q:\n%s", verdict, r.stdout)
		}
		if got := logSize(t, dir); got != want {
			t.Fatalf("log is %d byte(s), want %d", got, want)
		}
	})
}

// TestTheFourRefusalStatesGetFourDistinctVerdictLinesAndTheSameExitCode is the
// operator-facing half of the four-refusal-states distinction.
//
// There are four states behind Repairable == false. All four refuse and all
// four exit 1, but only ProvenUnsafeToCut is a store that is unsafe to cut on
// its merits; in the other three the store may be perfectly recoverable and
// is being resynced for want of an instrument that can settle the question.
// Until this change they shared one sentence, so a runbook step — which is
// what actually runs on a public network — could not tell them apart.
//
// The table is checked in BOTH directions. Every line must be distinct from
// every other, so a state that quietly fell back to a neighbour's sentence
// fails here rather than in an operator's terminal.
//
// THE EXIT CODE IS ASSERTED AS UNCHANGED, once per state, and that is a
// property this test exists to hold rather than a detail it happens to
// observe. An exit-code split was considered on its own merits and declined,
// and an exit code is the surface most likely to grow an automated lever out
// of a distinction that is only meant to be read.
func TestTheFourRefusalStatesGetFourDistinctVerdictLinesAndTheSameExitCode(t *testing.T) {
	// The states, built as reports rather than as stores. What is under test
	// is the sentence this command selects for a given diagnosis, and storage
	// already pins which diagnosis each damaged store produces
	// (node/storage, TestRepairAssertsACommittedTransactionOnly...,
	// TestOnlyASearchBehindTheDamageNamesOneOfTheFourStates). Building the
	// four stores again here would re-test that and reach this selection
	// through it; the end-to-end row below keeps the two halves joined.
	states := []struct {
		name string
		d    storage.LogDiagnosis
		must []string
		not  []string
	}{
		{
			name: "proven unsafe to cut",
			d:    storage.LogDiagnosis{Damaged: true, Verdict: storage.ProvenUnsafeToCut},
			must: []string{"Resync this store from the network"},
			not:  []string{"not proven either way"},
		},
		{
			name: "the record found was disproved",
			d:    storage.LogDiagnosis{Damaged: true, Verdict: storage.FoundRecordDisproved},
			// The disproof reads like permission and is not: the search stopped at its
			// first candidate. The clause saying so is the half that keeps this state
			// from growing the override flag this command has twice been asked for and
			// twice refused.
			must: []string{"disproved", "never read past it", "not proven either way",
				"resync is the only remedy this tool can offer"},
			not: []string{"Resync this store from the network"},
		},
		{
			name: "blocked by a second damage site",
			d: storage.LogDiagnosis{Damaged: true, Verdict: storage.BlockedBySecondDamage,
				SecondDamageOffset: 4096},
			// The offset is information the operator reads nowhere else, so it is named
			// in the verdict line itself.
			must: []string{"second damaged record at offset 4096", "not proven either way",
				"resync is the only remedy this tool can offer"},
			not: []string{"Resync this store from the network"},
		},
		{
			name: "the search had to begin inside the damage",
			d:    storage.LogDiagnosis{Damaged: true, Verdict: storage.SearchBeganInsideDamage},
			must: []string{"failed its checksum", "that record's own payload",
				"not proven either way", "resync is the only remedy this tool can offer"},
			not: []string{"Resync this store from the network"},
		},
	}

	seen := map[string]string{}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			line := refusalVerdict(&st.d)
			if !strings.HasPrefix(line, "verdict:   NOT REPAIRABLE. Nothing was changed.") {
				t.Fatalf("the verdict line does not open with the refusal every state "+
					"shares:\n%s", line)
			}
			for _, want := range st.must {
				if !strings.Contains(line, want) {
					t.Fatalf("the verdict line does not carry %q:\n%s", want, line)
				}
			}
			for _, unwanted := range st.not {
				if strings.Contains(line, unwanted) {
					t.Fatalf("the verdict line carries %q, which belongs to another "+
						"state:\n%s", unwanted, line)
				}
			}
			if other, dup := seen[line]; dup {
				t.Fatalf("%q and %q print the same verdict line, so an operator cannot tell "+
					"them apart:\n%s", st.name, other, line)
			}
			seen[line] = st.name
		})
	}
	if len(seen) != 4 {
		t.Fatalf("%d distinct verdict lines for four states, want 4", len(seen))
	}

	// The states and this command joined end to end, on a real store. Without it
	// every row above is satisfied by a function nothing calls, and the exit code
	// — the surface this test pins as UNCHANGED — is never observed.
	t.Run("end to end, on a store whose search began inside the damage", func(t *testing.T) {
		dir := t.TempDir()
		commitKeys(t, dir, "a")
		firstEnd := logSize(t, dir)
		commitKeys(t, dir, "b", "c", "d", "e")
		holeAt(t, dir, firstEnd, 8)
		// THE OUT-OF-BAND COMMIT RECORD IS REMOVED, and that is what puts this store
		// in the state the row is named for rather than in the one before it. With
		// `commits` present the refusal is decided by the sidecar's evidence — the
		// store was told sequence 4 landed — and Diagnose returns before any search
		// behind the damage runs, which is VerdictNone and a different sentence. A
		// store written by a build without that file is the documented case here
		// (docs/RUNNING.md), and it is the one where the log's own bytes have to
		// answer.
		if err := os.Remove(filepath.Join(dir, "commits")); err != nil {
			t.Fatal(err)
		}
		before := logSize(t, dir)

		got := repairCmd(t, "yes\n", "--dir", dir)
		if got.code != 1 {
			t.Fatalf("exit %d over a refusal, want 1 — the four states are told apart by the "+
				"verdict line and by nothing else:\n%s%s", got.code, got.stdout, got.stderr)
		}
		want := refusalVerdict(&storage.LogDiagnosis{
			Damaged: true, Verdict: storage.SearchBeganInsideDamage})
		if !strings.Contains(got.stdout, want) {
			t.Fatalf("the command did not print this state's own verdict line.\nwant: %s"+
				"\ngot:\n%s", want, got.stdout)
		}
		if !strings.Contains(got.stdout, readableLine(1)) {
			t.Fatalf("the count line is not labelled:\n%s", got.stdout)
		}
		if size := logSize(t, dir); size != before {
			t.Fatalf("%d byte(s) were discarded over a refusal", before-size)
		}
	})
}
