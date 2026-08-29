package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repair suite: the operator's second door, opened because a storage
// refusal to open was otherwise permanent, undocumented and had no recovery
// path.
//
// Property, in one sentence: `repair` offers to discard the tail of a log
// exactly when no intact record behind the damage declares itself the last
// record of its transaction, so it recovers the two stores Open refuses over
// damage that cost nothing committed, and refuses the store where a committed
// transaction sits behind the damage.
//
// Every test here is written as a pair against a scenario that differs in one
// field, because the single-sided versions are all vacuous. "Repair recovers
// this store" alone passes for a command that truncates anything it is
// pointed at — which is the interior-corruption data-loss bug wearing a prompt. "Repair
// refuses this store" alone passes for the code as it was before this change,
// where every damage class was permanent. Only the pair says the line is
// drawn where it is claimed to be.

// commitChain is a log of n ordinary single-record commits, each a distinct
// key, kept as separate slices so a test can damage one in place without
// moving any other.
type commitChain struct {
	records [][]byte
}

func buildCommitChain(t *testing.T, n int) commitChain {
	t.Helper()
	var c commitChain
	for i := 0; i < n; i++ {
		b := &Batch{}
		b.Put([]byte(fmt.Sprintf("key-%d", i)), []byte(fmt.Sprintf("value-%d", i)))
		rec, err := encodeRecord(b, uint64(i), 0)
		if err != nil {
			t.Fatal(err)
		}
		c.records = append(c.records, rec)
	}
	return c
}

// frameUnescaped writes a record the way format version 3 did: the batch's
// payload framed verbatim, with no escape.
//
// Every caller below needs record-shaped bytes sitting INSIDE a payload, and
// since format version 4 no writer in this package produces those —
// encodeRecord escapes recordMagic out of every payload it writes (see
// escapePayload), which is what closed the payload-plant carrier. Routing these
// fixtures through encodeRecord would leave them asserting nothing at all,
// silently, because the plant would simply not be in the log.
//
// So the provenance of the bytes changes and the change is stated rather than
// hidden: they are no longer bytes a remote party delivers through a value.
// What the rows still pin is the READER's rules — which record the forward scan
// stops on, whether that record's countdown terminates a transaction, whether
// it sits on a frame boundary — and those have to hold for record-shaped bytes
// however they arrived. They can still arrive: the escape does not cover the
// record's own header, whose checksum field is forceable to the magic (see
// TestTheRecordChecksumFieldIsAnUnescapedCarrier). Deleting these rows because
// the cheap route closed would leave the reader's rules undefended against the
// expensive one.
func frameUnescaped(t *testing.T, b *Batch, seq uint64, more uint32) []byte {
	t.Helper()
	payload, err := encodeBatchPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := frameRecord(payload, seq, more)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (c commitChain) offsetOf(i int) int {
	off := 0
	for j := 0; j < i; j++ {
		off += len(c.records[j])
	}
	return off
}

// writeChain assembles the log, applying each damage function to the record
// it names. Damage is always length-preserving so the records after it sit at
// exactly the offsets a crash would have left them at.
func writeChain(t *testing.T, c commitChain, damage map[int]func([]byte)) string {
	t.Helper()
	dir := t.TempDir()
	var raw []byte
	for i, rec := range c.records {
		part := append([]byte(nil), rec...)
		if f, ok := damage[i]; ok {
			f(part)
		}
		raw = append(raw, part...)
	}
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// breakHeader flips one bit inside the span the header checksum covers, which
// is what an ordinary crash does to a record whose header and payload landed
// on different pages (see decodeHeaderUntrusted). It leaves the record's bytes
// in place and its length untouched.
func breakHeader(rec []byte) { rec[recordSeqOff] ^= 0x01 }

func zeroAll(rec []byte) {
	for i := range rec {
		rec[i] = 0
	}
}

func diagnose(t *testing.T, dir string) *LogDiagnosis {
	t.Helper()
	r, err := OpenForRepair(dir)
	if err != nil {
		t.Fatalf("OpenForRepair: %v", err)
	}
	defer r.Close()
	d, err := r.Diagnose()
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	return d
}

func repair(t *testing.T, dir string) {
	t.Helper()
	r, err := OpenForRepair(dir)
	if err != nil {
		t.Fatalf("OpenForRepair: %v", err)
	}
	defer r.Close()
	d, err := r.Diagnose()
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !d.Repairable {
		t.Fatalf("no cut offered: %s", d.Explanation)
	}
	if err := r.Apply(d); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// assertRefusesToOpen is the precondition every scenario here rests on: if
// Open did not refuse, there would be nothing for a repair to be the second
// door to, and a passing repair test would be measuring nothing.
func assertRefusesToOpen(t *testing.T, dir, why string) error {
	t.Helper()
	s, err := Open(dir, Options{})
	if err == nil {
		s.Close()
		t.Fatalf("Open succeeded, so this scenario does not need a repair at all: %s", why)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open refused with %v, want ErrCorrupt: %s", err, why)
	}
	return err
}

func assertOpensWithKeys(t *testing.T, dir string, present, absent []int) {
	t.Helper()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("still refuses to open after a repair: %v", err)
	}
	defer s.Close()
	for _, i := range present {
		v, ok := s.Get([]byte(fmt.Sprintf("key-%d", i)))
		if !ok || string(v) != fmt.Sprintf("value-%d", i) {
			t.Fatalf("record %d was lost (present=%v value=%q) — the repair cut too far, which "+
				"is the interior-corruption data-loss failure with a confirmation prompt in front of it", i, ok, v)
		}
	}
	for _, i := range absent {
		if _, ok := s.Get([]byte(fmt.Sprintf("key-%d", i))); ok {
			t.Fatalf("record %d survived a cut that was supposed to discard it", i)
		}
	}
}

// TestRepairCutsATailWhoseOwnPayloadLooksLikeARecordAndRefusesWhenItCommits
// is the second door itself, on the exact shape that made the refusal need
// one: a crash that damages a record's header turning a discardable torn tail
// into a permanent refusal to open.
//
// A record's payload holds record-shaped bytes. If the node crashes mid-write
// on that record, Open's forward search — which, with the frame unusable, has
// to begin at the damaged record's own first byte — finds them and refuses
// forever. Nothing is actually lost: the damaged record is the last one.
//
// Those bytes used to arrive from the network: a node writes a block body it
// received into the log verbatim, and the payload-plant measurement showed what
// that cost. The payload escape closed that route — see frameUnescaped for why
// this fixture now frames the carrier the way format version 3 did, and for the
// route that is still open.
//
// The two halves differ in one field of the *embedded* record, the countdown
// that says whether it terminates a transaction. With more == 1 nothing
// behind the damage was ever committed and repair offers the cut; with
// more == 0 the same bytes claim a completed transaction and repair refuses.
// That single field is the whole rule, and testing only one side would not
// show it exists.
func TestRepairCutsATailWhoseOwnPayloadLooksLikeARecordAndRefusesWhenItCommits(t *testing.T) {
	for _, tc := range []struct {
		name           string
		embeddedMore   uint32
		wantRepairable bool
	}{
		{"embedded record does not terminate a transaction", 1, true},
		{"embedded record claims a completed transaction", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &Batch{}
			inner.Put([]byte("bait-key"), []byte("bait-value"))
			// Sequence 9 is past anything replay expects here, so it clears
			// findNextRecord's minSeq gate and the search really does stop
			// on it.
			embedded, err := encodeRecord(inner, 9, tc.embeddedMore)
			if err != nil {
				t.Fatal(err)
			}

			c := buildCommitChain(t, 3)
			carrier := &Batch{}
			carrier.Put([]byte("key-3"), embedded)
			c.records = append(c.records, frameUnescaped(t, carrier, 3, 0))

			dir := writeChain(t, c, map[int]func([]byte){3: breakHeader})
			openErr := assertRefusesToOpen(t, dir, "a crashed tail carrying record-shaped bytes")

			damageAt := c.offsetOf(3)
			d := diagnose(t, dir)
			// Anti-divergence: Diagnose walks the intact prefix itself
			// rather than sharing replayLog's loop, so the two could drift
			// into disagreeing about where the damage is — and a repair that
			// cuts at a different offset than the one Open stopped at is the
			// worst bug this command could have.
			want := fmt.Sprintf("offset %d", damageAt)
			if !strings.Contains(openErr.Error(), want) || !strings.Contains(d.Explanation, want) {
				t.Fatalf("Open and Diagnose disagree about where the damage is (want %q)\n"+
					"open:     %v\ndiagnose: %s", want, openErr, d.Explanation)
			}
			if d.RecordsIntact != 3 {
				t.Fatalf("RecordsIntact = %d, want 3", d.RecordsIntact)
			}

			if !tc.wantRepairable {
				if d.Repairable {
					t.Fatalf("a cut was offered although a record behind the damage declares a "+
						"completed transaction: %s", d.Explanation)
				}
				assertRefusesToOpen(t, dir, "a diagnosis that offers no cut must change nothing")
				return
			}

			if !d.Repairable {
				t.Fatalf("no cut offered for a tail that costs nothing: %s", d.Explanation)
			}
			if d.Offset != int64(damageAt) {
				t.Fatalf("Offset = %d, want %d — the cut must start at the damaged record, not "+
					"before it", d.Offset, damageAt)
			}
			repair(t, dir)
			assertOpensWithKeys(t, dir, []int{0, 1, 2}, []int{3})
		})
	}
}

// TestRepairRecoversAnAbandonedGroupWithAHoleInItsFirstPart pins the shape
// a hole in a group's FIRST part leaves open, and pins it against the one record
// that changes the answer.
//
// Such a hole leaves replay with no group open, so the open-group
// membership dismissal never applies and the surviving later parts read as
// proof that the writer kept going: Open refuses. But every one of those
// parts carries more >= 1, so none of them terminates a transaction and the
// whole group was abandoned — a repair costs nothing committed.
//
// With the group's commit record also on disk the answer inverts, and it must:
// CommitGroup fsyncs parts 0..n-2 before the commit record is written at all,
// so that record's presence proves the earlier parts were durable and the hole
// is interior damage to a transaction the caller was told had landed.
func TestRepairRecoversAnAbandonedGroupWithAHoleInItsFirstPart(t *testing.T) {
	f := buildClassFixture(t)

	for _, tc := range []struct {
		name           string
		keep           int
		wantRepairable bool
	}{
		{"commit record never landed", classGroupParts - 1, true},
		{"commit record is on disk", classGroupParts, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeClassLog(t, f, tc.keep, 0)
			assertRefusesToOpen(t, dir, "a hole in a group's first part")

			d := diagnose(t, dir)
			if d.Repairable != tc.wantRepairable {
				t.Fatalf("Repairable = %v, want %v: %s", d.Repairable, tc.wantRepairable,
					d.Explanation)
			}
			if !tc.wantRepairable {
				return
			}
			if d.Offset != int64(len(f.committed)) {
				t.Fatalf("Offset = %d, want %d — the cut must take the abandoned transaction "+
					"whole, from its first part", d.Offset, len(f.committed))
			}
			repair(t, dir)
			assertOpensWithOnlyTheCommittedRecord(t, dir)
		})
	}
}

// TestRepairRefusesDamageWithACommittedRecordBehindIt is the general interior
// case, and its second half is the guard that keeps the first from passing
// benignly: the same damage function applied to the same log at a different
// record must give the opposite answer, or the check is not reading the
// scan at all.
func TestRepairRefusesDamageWithACommittedRecordBehindIt(t *testing.T) {
	c := buildCommitChain(t, 4)

	interior := writeChain(t, c, map[int]func([]byte){1: zeroAll})
	assertRefusesToOpen(t, interior, "interior damage with commits behind it")
	if d := diagnose(t, interior); d.Repairable {
		t.Fatalf("a cut was offered over two committed records: %s", d.Explanation)
	}

	// The same damage on the last record instead. Nothing committed is behind
	// it, so the answer inverts — and it inverts to "not damaged, start the
	// node", not to a cut: Open discards this tail itself. If this half also
	// refused, the check above would be reading nothing.
	tail := writeChain(t, c, map[int]func([]byte){3: zeroAll})
	d := diagnose(t, tail)
	if d.Damaged || d.Repairable {
		t.Fatalf("a cut was offered for a tail the node discards on its own: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "start the node") {
		t.Fatalf("the finding does not tell the operator the node recovers this itself: %s",
			d.Explanation)
	}
	assertOpensWithKeys(t, tail, []int{0, 1, 2}, []int{3})
}

// TestRepairOffersNoCutForDamageTheNodeDiscardsItself is the boundary the
// whole command rests on, stated from the other side: `repair` exists for the
// stores Open *refuses*, and a tool whose only effect is an irreversible
// deletion must not propose one where booting the node has the same effect
// and costs nothing.
//
// The pair differs in one byte of the damaged record's payload — the
// countdown of a record-shaped sequence buried in it. Without it Open's own
// forward search comes back empty and Open truncates unattended, so the right
// report is "start the node". With it Open's search has a hit it cannot
// explain and refuses forever, and only then is there a door to open. Before
// this check, both halves reported REPAIRABLE and offered the same
// irreversible cut behind a yes/no prompt, and the first half's cut was one
// the node was going to make for itself.
func TestRepairOffersNoCutForDamageTheNodeDiscardsItself(t *testing.T) {
	// frameUnescaped rather than encodeRecord: the baited half needs the
	// record-shaped bytes to survive into the payload, and since the escape they do
	// not. See frameUnescaped.
	build := func(payload []byte) string {
		c := buildCommitChain(t, 3)
		carrier := &Batch{}
		carrier.Put([]byte("key-2"), payload)
		c.records[2] = frameUnescaped(t, carrier, 2, 0)
		return writeChain(t, c, map[int]func([]byte){2: breakHeader})
	}

	plain := build([]byte("an ordinary block body with no record-shaped bytes in it"))
	if d := diagnose(t, plain); d.Damaged || d.Repairable {
		t.Fatalf("a cut was offered for a crashed tail the node truncates itself: %s",
			d.Explanation)
	}
	assertOpensWithKeys(t, plain, []int{0, 1}, []int{2})

	inner := &Batch{}
	inner.Put([]byte("bait-key"), []byte("bait-value"))
	embedded, err := encodeRecord(inner, 9, 1)
	if err != nil {
		t.Fatal(err)
	}
	baited := build(embedded)
	assertRefusesToOpen(t, baited, "a crashed tail carrying record-shaped bytes")
	if d := diagnose(t, baited); !d.Repairable {
		t.Fatalf("no cut offered for the store Open refuses: %s", d.Explanation)
	}
}

// TestRepairRefusesAWellFormedRecordOutOfSequence pins the class where the
// bytes are provably somebody's writes rather than an unfinished one, so no
// scan is run and no cut is ever offered.
func TestRepairRefusesAWellFormedRecordOutOfSequence(t *testing.T) {
	c := buildCommitChain(t, 3)
	stray := &Batch{}
	stray.Put([]byte("key-7"), []byte("value-7"))
	rec, err := encodeRecord(stray, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.records[2] = rec

	dir := writeChain(t, c, nil)
	assertRefusesToOpen(t, dir, "a well-formed record out of sequence")
	d := diagnose(t, dir)
	if d.Repairable {
		t.Fatalf("a cut was offered over a record that decodes completely: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "sequence number 7") {
		t.Fatalf("the finding does not name the offending sequence: %s", d.Explanation)
	}
}

// TestRepairRefusesAStoreANodeHasOpen. A repair reads the log, decides on an
// offset and truncates there; a node appending records between those steps
// would make each of them describe a different file.
func TestRepairRefusesAStoreANodeHasOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := OpenForRepair(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("OpenForRepair on a live store = %v, want ErrLocked", err)
	}
}

// TestRepairDiscardsOnlyWhatWasApproved. The operator agreed to lose a stated
// number of bytes at a stated offset. If the file is not the one they were
// shown, Apply must not recompute a fresh — and possibly larger — cut behind
// their back.
func TestRepairDiscardsOnlyWhatWasApproved(t *testing.T) {
	c := buildCommitChain(t, 3)
	dir := writeChain(t, c, map[int]func([]byte){2: breakHeader})

	// A damaged last record with a clean payload: Open truncates this one
	// itself, so build the refusing shape instead by burying a bait record.
	inner := &Batch{}
	inner.Put([]byte("bait"), []byte("bait"))
	embedded, err := encodeRecord(inner, 9, 1)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &Batch{}
	carrier.Put([]byte("key-2"), embedded)
	// frameUnescaped: encodeRecord would otherwise take the bait record's
	// magic out of the payload and this store would open. See frameUnescaped.
	c.records[2] = frameUnescaped(t, carrier, 2, 0)
	dir = writeChain(t, c, map[int]func([]byte){2: breakHeader})
	assertRefusesToOpen(t, dir, "a crashed tail carrying record-shaped bytes")

	r, err := OpenForRepair(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	shown, err := r.Diagnose()
	if err != nil {
		t.Fatal(err)
	}
	if !shown.Repairable {
		t.Fatalf("no cut offered: %s", shown.Explanation)
	}

	path := filepath.Join(dir, logName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), before...), before...), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := r.Apply(shown); err == nil {
		t.Fatal("Apply performed a cut against a log that is no longer the one that was approved")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2*len(before) {
		t.Fatalf("the log was truncated anyway: %d byte(s), want %d", len(after), 2*len(before))
	}
}

// TestRepairRefusesAForeignFormatVersion. A log this build cannot read is not
// damaged, and discarding it would destroy a log the right binary reads fine.
func TestRepairRefusesAForeignFormatVersion(t *testing.T) {
	c := buildCommitChain(t, 2)
	dir := writeChain(t, c, map[int]func([]byte){0: func(rec []byte) { rec[3] = FormatVersion + 1 }})

	d := diagnose(t, dir)
	if d.Repairable {
		t.Fatalf("a cut was offered over a foreign format version: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "run the matching binary") {
		t.Fatalf("the finding does not send the operator to the right binary: %s", d.Explanation)
	}
}

// TestTheRefusalSaysWhichQuestionIsOpenRatherThanAssertingTheAnswer pins the
// half of the second door that is text, and it is not cosmetic: the message an operator
// gets is the only instrument they have for choosing between `repair` and a
// resync, and the one they used to get answered a question this reader cannot
// answer, in the direction that sends them away from the recovery that works.
//
// The two cases differ only in whether the damaged record's frame verified,
// which is exactly what decides whether the forward search was allowed to
// begin outside the record or had to begin inside it.
func TestTheRefusalSaysWhichQuestionIsOpenRatherThanAssertingTheAnswer(t *testing.T) {
	// Frame unusable: the search starts inside the damaged record, so a hit
	// may be its own payload and this may be an ordinary crashed tail.
	inner := &Batch{}
	inner.Put([]byte("bait-key"), []byte("bait-value"))
	embedded, err := encodeRecord(inner, 9, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := buildCommitChain(t, 3)
	carrier := &Batch{}
	carrier.Put([]byte("key-3"), embedded)
	// frameUnescaped: see its doc — encodeRecord no longer emits a payload
	// containing recordMagic, so this row would refuse nothing.
	c.records = append(c.records, frameUnescaped(t, carrier, 3, 0))
	untrusted := assertRefusesToOpen(t,
		writeChain(t, c, map[int]func([]byte){3: breakHeader}),
		"a crashed tail carrying record-shaped bytes").Error()

	for _, banned := range []string{"not a crash mid-write", "not repaired by deleting"} {
		if strings.Contains(untrusted, banned) {
			t.Fatalf("the refusal still asserts %q for a log whose only damage is at the end, "+
				"which is false and points the operator away from `zycordd repair`:\n%s",
				banned, untrusted)
		}
	}
	if !strings.Contains(untrusted, "cannot tell which") {
		t.Fatalf("the refusal does not say the question is open:\n%s", untrusted)
	}

	// Frame verified: the search began past this record's own last byte, so a
	// hit really is data some writer produced after it. Here the stronger
	// reading is sound and must still be stated, or the message would have
	// been made vague rather than accurate.
	c2 := buildCommitChain(t, 4)
	verified := assertRefusesToOpen(t,
		writeChain(t, c2, map[int]func([]byte){1: func(rec []byte) {
			rec[len(rec)-1] ^= 0x01 // payload only; the header still checks out
		}}),
		"a damaged payload inside a verified frame").Error()
	if !strings.Contains(verified, "damage inside the log") {
		t.Fatalf("the refusal no longer states the conclusion it can actually reach:\n%s", verified)
	}
	if strings.Contains(verified, "cannot tell which") {
		t.Fatalf("the refusal hedges a case it can settle:\n%s", verified)
	}
}

// TestTheTornTailLineDoesNotCallAnAbandonedTransactionATornWrite pins the
// second wrong message. When the cut runs back over a multi-record
// transaction, the bytes discarded include records that are individually
// intact and the damage that opened the cut may be a hole rather than a
// prefix — so "torn byte(s) ... after a crash mid-write" was wrong
// about both the bytes and the shape.
func TestTheTornTailLineDoesNotCallAnAbandonedTransactionATornWrite(t *testing.T) {
	f := buildClassFixture(t)
	// Parts 0 and 1 intact, part 2 holed, commit record never written.
	dir := writeClassLog(t, f, 3, 2)

	var buf strings.Builder
	s, err := Open(dir, Options{Logger: log.New(&buf, "", 0)})
	if err != nil {
		t.Fatalf("refused to open an abandoned transaction: %v", err)
	}
	defer s.Close()

	line := buf.String()
	if line == "" {
		t.Fatal("the recovery was silent, which is the one thing this log line exists to prevent")
	}
	for _, banned := range []string{"torn byte", "crash mid-write"} {
		if strings.Contains(line, banned) {
			t.Fatalf("the recovery line still says %q about intact records discarded with an "+
				"abandoned transaction:\n%s", banned, line)
		}
	}
	if !strings.Contains(line, "incomplete multi-record transaction") {
		t.Fatalf("the recovery line does not say what was actually discarded:\n%s", line)
	}
}

// TestARepairInsideAnOpenTransactionCutsBackToItsFirstRecord.
//
// Reaching this at all takes care, and the shape is worth stating because a
// first attempt at this test could not reach it: with the open-group dismissal
// in place, damage inside an open transaction with only that transaction's own
// parts behind it is something Open already recovers unattended, so there is no
// repair to make. The case where a repair is both needed and lands inside an
// open transaction is the one where the forward search finds something that is
// *not* a member of it — here a bait record in the damaged part's own payload,
// which claims a sequence past the transaction's end and so is not dismissed by
// the open-group membership rule.
//
// The cut must then go back to the transaction's first record, not to the
// damaged one. Its earlier parts are individually intact but were never
// applied, and leaving them on disk would put them in front of whatever the
// next commit writes, where a record declaring itself the end of a
// transaction would sweep them into one that never happened. "All or nothing"
// has to survive the repair as well as the crash.
func TestARepairInsideAnOpenTransactionCutsBackToItsFirstRecord(t *testing.T) {
	survivor := &Batch{}
	survivor.Put([]byte("key-0"), []byte("value-0"))
	committed, err := encodeRecord(survivor, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	bait := &Batch{}
	bait.Put([]byte("bait-key"), []byte("bait-value"))
	// Sequence 9 is past this transaction's own final sequence (3), so the
	// membership rule cannot dismiss it and Open refuses; more == 1 means it
	// terminates nothing, so repair may still offer the cut.
	embedded, err := encodeRecord(bait, 9, 1)
	if err != nil {
		t.Fatal(err)
	}

	first := &Batch{}
	first.Put([]byte("part-1"), []byte("part-1"))
	partOne, err := encodeRecord(first, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	second := &Batch{}
	second.Put([]byte("part-2"), embedded)
	// frameUnescaped: the bait has to survive into part two's payload, and
	// encodeRecord would otherwise escape it out. See frameUnescaped.
	partTwo := frameUnescaped(t, second, 2, 1)
	breakHeader(partTwo)

	dir := t.TempDir()
	raw := append(append(append([]byte(nil), committed...), partOne...), partTwo...)
	if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRefusesToOpen(t, dir, "damage inside an open transaction with a non-member record behind it")

	d := diagnose(t, dir)
	if !d.Repairable {
		t.Fatalf("no cut offered for an abandoned transaction: %s", d.Explanation)
	}
	if d.Offset != int64(len(committed)) {
		t.Fatalf("Offset = %d, want %d — the cut starts at the damaged record instead of the "+
			"first record of the transaction it belongs to, so an intact but unapplied part "+
			"would be left on disk in front of the next commit",
			d.Offset, len(committed))
	}
	repair(t, dir)

	info, err := os.Stat(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len(committed)) {
		t.Fatalf("log is %d byte(s) after the repair, want %d", info.Size(), len(committed))
	}
	assertOpensWithKeys(t, dir, []int{0}, nil)
}

// TestRepairRefusesAVerifiedHeaderDeclaringAnImpossiblePayload pins a refusal
// class that had no test at all, which for a command whose only effect is a
// deletion is the same as not having the rule: nothing would have noticed if
// this class had started scanning and offering cuts instead.
//
// The pair differs only in whether the header checksum was recomputed over
// the impossible length. Recomputed, the length is a fact some writer wrote,
// decodeMaxLenExceeded, and no cut may be offered over bytes a writer put
// there on purpose. Not recomputed, the same edit is an ordinary broken
// header and lands in a different class entirely — so the refusal below is
// being drawn by the class and not by the mangled length.
func TestRepairRefusesAVerifiedHeaderDeclaringAnImpossiblePayload(t *testing.T) {
	c := buildCommitChain(t, 3)
	at := c.offsetOf(2)

	forged := writeChain(t, c, map[int]func([]byte){2: func(rec []byte) {
		binary.LittleEndian.PutUint64(rec[recordLenOff:], MaxRecordLen+1)
		binary.LittleEndian.PutUint32(rec[recordHdrCRCOff:], crc32.ChecksumIEEE(rec[:recordHdrCRCOff]))
	}})
	raw, err := os.ReadFile(filepath.Join(forged, logName))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, st := decodeRecord(raw[at:]); st != decodeMaxLenExceeded {
		t.Fatalf("setup: record 2 decodes as %v, want decodeMaxLenExceeded", st)
	}
	assertRefusesToOpen(t, forged, "a verified header declaring an impossible payload")
	d := diagnose(t, forged)
	if d.Repairable {
		t.Fatalf("a cut was offered over a length no crash can produce: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "resync this store") {
		t.Fatalf("the finding does not send the operator to a resync: %s", d.Explanation)
	}

	// The same edit without re-signing the header: a broken header, not a
	// writer's claim, and the answer must not be this refusal.
	flipped := writeChain(t, c, map[int]func([]byte){2: func(rec []byte) {
		binary.LittleEndian.PutUint64(rec[recordLenOff:], MaxRecordLen+1)
	}})
	if d := diagnose(t, flipped); d.Repairable == false && strings.Contains(d.Explanation, "larger than this format ever writes") {
		t.Fatalf("a merely broken header was read as a writer's declared length: %s", d.Explanation)
	}
}

// TestRepairRefusesAPartWhoseCountdownDoesNotPointAtItsOwnGroup pins the
// second untested refusal class. A record that passed both of its checksums
// and sits in sequence, yet disagrees with the transaction it is inside about
// where that transaction ends, was written that way — a crash cannot forge a
// checksum — so whatever else that writer put on this disk is not something
// to discard on an operator's say-so.
//
// The pair differs in that one field. With the countdown pointing at its own
// group the same log is an ordinary unfinished transaction and there is
// nothing to repair at all.
func TestRepairRefusesAPartWhoseCountdownDoesNotPointAtItsOwnGroup(t *testing.T) {
	build := func(more uint32) string {
		committed := &Batch{}
		committed.Put([]byte("key-0"), []byte("value-0"))
		rec0, err := encodeRecord(committed, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		first := &Batch{}
		first.Put([]byte("part-1"), []byte("part-1"))
		partOne, err := encodeRecord(first, 1, 2)
		if err != nil {
			t.Fatal(err)
		}
		second := &Batch{}
		second.Put([]byte("part-2"), []byte("part-2"))
		partTwo, err := encodeRecord(second, 2, 1)
		if err != nil {
			t.Fatal(err)
		}
		raw := append(append(append([]byte(nil), rec0...), partOne...), partTwo...)
		setMore(t, raw, len(rec0)+len(partOne), more)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	d := diagnose(t, build(5))
	if d.Repairable {
		t.Fatalf("a cut was offered over a part that disagrees with its own group: %s",
			d.Explanation)
	}
	if !strings.Contains(d.Explanation, "resync this store") {
		t.Fatalf("the finding does not send the operator to a resync: %s", d.Explanation)
	}

	if d := diagnose(t, build(1)); d.Damaged || d.Repairable {
		t.Fatalf("an unfinished transaction with a consistent countdown was treated as "+
			"damage: %s", d.Explanation)
	}
}

// TestTheTerminalScanReportsExhaustionRatherThanAbsence is the boundary the
// whole command turns on, and it cannot be reached through Diagnose: that
// budget starts at 64 gibibytes of checksummed bytes, which no honest test
// can spend. So it is pinned where findNextRecordWithin's is, at the function
// that takes the budget.
//
// scanNothingFound is the one result that becomes a deletion. A budget that ran
// out has established nothing, and must never be reported as "nothing is back
// there" — the same three-valued discipline the tail discriminator put into
// replay, on the path where a human is about to approve the cut.
func TestTheTerminalScanReportsExhaustionRatherThanAbsence(t *testing.T) {
	b := &Batch{}
	b.Put([]byte("key"), []byte("value"))
	rec, err := encodeRecord(b, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	off, result := findTerminalRecordWithin(rec, 0, 1<<20)
	if result != scanFound || off != 0 {
		t.Fatalf("with an ample budget: offset %d, %v; want 0, scanFound", off, result)
	}

	// One byte less than this candidate costs to check.
	if _, result := findTerminalRecordWithin(rec, 0, int64(recordCRCOff)+int64(len(rec)-recordHeaderLen)-1); result != scanInconclusive {
		t.Fatalf("a scan that ran out of budget reported %v; scanNothingFound or scanFound "+
			"here is a cut offered on the strength of work that was never done", result)
	}
}

// TestRepairRefusesToCallAForeignSnapshotDamage. The snapshot is checked
// before the log, so on any store that has ever compacted — which is every
// long-lived one — the log's own format-version branch is unreachable and
// this is the only place the distinction can be drawn. Without it, a node
// started against the wrong binary was told its store was destroyed and to
// resync: a runbook that throws away a directory whose bytes are perfectly
// intact.
//
// The pair differs in whether the snapshot's magic still identifies it as a
// snapshot at all. Intact magic with a version this build does not read is
// not damage and no cut may be offered *and no resync suggested*. Bytes that
// are not a snapshot at all are damage, and no log cut can recover it.
func TestRepairRefusesToCallAForeignSnapshotDamage(t *testing.T) {
	build := func(edit func([]byte) []byte) string {
		dir := t.TempDir()
		s, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		b := &Batch{}
		b.Put([]byte("key"), []byte("value"))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
		if err := s.Compact(); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, snapshotName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, edit(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	foreign := build(func(raw []byte) []byte {
		raw[7] = FormatVersion + 1
		return raw
	})
	if _, err := Open(foreign, Options{}); !errors.Is(err, ErrFormat) {
		t.Fatalf("setup: Open reports %v, want ErrFormat", err)
	}
	d := diagnose(t, foreign)
	if d.Damaged || d.Repairable {
		t.Fatalf("a snapshot this build cannot read was reported as damage: %s", d.Explanation)
	}
	if strings.Contains(d.Explanation, "resync") {
		t.Fatalf("the finding tells the operator to throw away an intact store: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "run the matching binary") {
		t.Fatalf("the finding does not send the operator to the right binary: %s", d.Explanation)
	}

	// The other side: bytes that are not a snapshot at all really are damage,
	// and no cut to the log can recover one.
	broken := build(func(raw []byte) []byte {
		raw[0] ^= 0xff
		return raw
	})
	d = diagnose(t, broken)
	if !d.Damaged || d.Repairable {
		t.Fatalf("a destroyed snapshot was not reported as damage: %s", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "resynced from the network") {
		t.Fatalf("the finding does not say the store has to be resynced: %s", d.Explanation)
	}
}

// TestRepairRefusesWhenTheCommitRecordCouldHaveBeenDestroyed covers the cut
// that would delete a committed transaction when a group loses both its first
// part and its commit record, and the three cases are the guard's three inputs
// rather than three symptoms.
//
// Property, in one sentence: repair may read "no terminal record behind the
// damage" as "nothing back there was committed" only when the log *ends*
// where the surviving parts of that transaction end, because a writer that
// never wrote a commit record leaves nothing after them and a writer whose
// commit record was destroyed leaves bytes there.
//
// The guard has two terms and each has its own separating store, built from
// the same fixture so the comparison is between logs that differ in one thing:
//
//   - "commit record destroyed": holes at the group's opener AND at its
//     commit record. Parts 1 and 2 survive, the log continues past them, and
//     the transaction really was reported committed. This is the case that
//     fails without the fix — repair offered a 544-byte cut and told the
//     operator, in the sentence they type `yes` against, that it "loses
//     nothing that was reported committed".
//   - "commit record never landed": the same hole at the opener alone, so the
//     log ends at part 2. Separates the "the log continues" term: nothing was
//     ever committed here and the cut must still be offered, which is the
//     first-part hole's recovery and must not become a resync.
//   - "the run is not the damaged record's successor": the destroyed-commit
//     store with part 1's sequence forged one higher, so no intact record
//     carries expectedSeq+1. Separates the anchor term. It is also the shape
//     the second door repairs — a record-shaped forgery inside a crashed record's own
//     payload sits at whatever sequence its author picked — and it must stay
//     repairable or `repair` stops answering the question it exists for.
func TestRepairRefusesWhenTheCommitRecordCouldHaveBeenDestroyed(t *testing.T) {
	f := buildClassFixture(t)
	part1At := len(f.committed) + len(f.parts[0])
	runEnd := part1At + len(f.parts[1]) + len(f.parts[2])

	t.Run("commit record destroyed", func(t *testing.T) {
		dir := writeClassLogCommitted(t, f, classGroupParts, 0, classGroupParts-1)
		assertRefusesToOpen(t, dir, "a group's opener and its commit record are both holes")
		d := diagnose(t, dir)
		if d.Repairable {
			t.Fatalf("a cut was offered over a committed transaction: %s", d.Explanation)
		}
		// Non-vacuity: a refusal for the *wrong* reason would read the same
		// from Repairable alone. The finding must rest on the out-of-band
		// record — the only thing here that separates this store from the
		// byte-identical one two subtests down, which must stay repairable.
		if !strings.Contains(d.Explanation, "was reported committed") ||
			!strings.Contains(d.Explanation, "would remove sequence 1 onward") {
			t.Fatalf("the refusal does not rest on the commit record sidecar: %s", d.Explanation)
		}
		if err := (&Repairer{}).Apply(d); !errors.Is(err, ErrNotRepairable) {
			t.Fatalf("Apply on a refused diagnosis = %v, want ErrNotRepairable", err)
		}
	})

	t.Run("commit record never landed", func(t *testing.T) {
		dir := writeClassLog(t, f, classGroupParts-1, 0)
		assertRefusesToOpen(t, dir, "a hole in a group's first part")
		d := diagnose(t, dir)
		if !d.Repairable {
			t.Fatalf("the first-part hole's recovery became a resync: %s", d.Explanation)
		}
		if d.Offset != int64(len(f.committed)) {
			t.Fatalf("Offset = %d, want %d", d.Offset, len(f.committed))
		}
		// The two stores differ only in the presence of the commit record's
		// bytes, so the opposite answers above are attributable to that and
		// to nothing else.
		full, err := os.ReadFile(filepath.Join(
			writeClassLogCommitted(t, f, classGroupParts, 0, classGroupParts-1), logName))
		if err != nil {
			t.Fatal(err)
		}
		short, err := os.ReadFile(filepath.Join(dir, logName))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(full[:runEnd], short) || len(full) <= runEnd {
			t.Fatalf("the refused store is not the cut store plus trailing bytes "+
				"(%d vs %d, run ends at %d) — the two cases no longer differ in one thing",
				len(full), len(short), runEnd)
		}
	})

	// The second door's own shape has to stay repairable, and this is the
	// sharpest form of it in this fixture family: a record-shaped forgery
	// inside a crashed record's payload sits at whatever sequence its author
	// picked. Under the abandoned history the cut must still be offered — the
	// sidecar says nothing was committed past the seed, and a forged sequence
	// cannot change that, because the sidecar is not in the log.
	t.Run("a forged sequence behind the damage does not withhold the cut", func(t *testing.T) {
		dir := writeClassLog(t, f, classGroupParts, 0, classGroupParts-1)
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// The damaged record carries sequence 1, so its successor is 2.
		// Part 1 legitimately carries 2; forge it to 3 and no intact record
		// anchors the run to the damage any more.
		binary.LittleEndian.PutUint64(raw[part1At+recordSeqOff:], 3)
		resign(t, raw, part1At)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		assertRefusesToOpen(t, dir, "the same two holes, unanchored run")
		if d := diagnose(t, dir); !d.Repairable {
			t.Fatalf("a run discovered inside the damaged region, at a sequence the damage "+
				"cannot account for, withheld the cut this command exists to offer: %s", d.Explanation)
		}
	})

	// A record belonging to no transaction this log is in the middle of sits
	// where the commit record belongs. Under the committed history the store
	// must still refuse: the sidecar names a sequence this log cannot account
	// for, and no rearrangement of the log's bytes can answer that, which is
	// exactly why the answer was moved out of the log.
	t.Run("a foreign record in the commit slot does not release the refusal", func(t *testing.T) {
		dir := writeClassLogCommitted(t, f, classGroupParts, 0)
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Rewrite the commit record in place — same length, so every offset
		// behind it is the one a crash would have left — into a record that
		// belongs to no open transaction and terminates none.
		binary.LittleEndian.PutUint64(raw[runEnd+recordSeqOff:], 99)
		binary.LittleEndian.PutUint32(raw[runEnd+recordMoreOff:], 1)
		resign(t, raw, runEnd)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		assertRefusesToOpen(t, dir, "the group's commit slot holds a foreign record")
		d := diagnose(t, dir)
		if d.Repairable {
			t.Fatalf("a cut was offered over a transaction the store reported committed, "+
				"because a foreign record occupied the slot: %s", d.Explanation)
		}
		if !strings.Contains(d.Explanation, "was reported committed") {
			t.Fatalf("the refusal does not rest on the commit record sidecar: %s", d.Explanation)
		}
	})
}

// TestThreeDamageSitesStillOfferACut records what the commit-slot guard does
// NOT close, as behaviour rather than as a comment, in the shape the original
// finding itself used.
//
// The run is anchored at expectedSeq+1 — the sequence the damaged record's
// own successor must carry — because that anchor is what keeps the rule
// attached to the log's honest in-sequence prefix instead of to the damaged
// region's testimony, and it is what leaves the second door's bait record repairable.
// The price is that the anchor is one record wide. Hole the group's opener
// AND the part after it, so no surviving record carries expectedSeq+1, and
// the anchor is not found; hole the commit record too and the cut is offered
// again over a transaction that was reported committed.
//
// This is the same wrong answer, on a store that needs three damage sites
// rather than two, and it needs the same thing to fix: the group's extent
// recorded out of band, so a destroyed commit record is still known to have
// existed. Do not relax this assertion — if it fails because the anchor was
// widened, check first that the widened rule still leaves "the run is not the
// damaged record's successor" above repairable, because that is the case
// `repair` exists for. THE THIRD SITE HAS TWO PLACES TO GO, and the second of
// them is what the commit-slot term costs. In front of the run, the anchor is
// gone and nothing locates the slot; behind it, the run stops before reaching
// the slot, so lastMore != 1 and the frame there is read as another part's
// rather than the commit record's. Both offer a cut over a transaction that
// really was reported committed, both need three faults inside one transaction,
// and both want the out-of-band record. The second row was a refusal before the
// commit-slot term was narrowed, and it is a deliberately accepted cost rather
// than an oversight: what the term buys is a node that starts after an ordinary
// crash, which needs no faults at all.
func TestThreeDamageSitesStillOfferACut(t *testing.T) {
	f := buildClassFixture(t)
	for _, row := range []struct {
		name  string
		holes []int
	}{
		{"the third site is in front of the run, so no anchor is found",
			[]int{0, 1, classGroupParts - 1}},
		{"the third site is behind the run, so it stops short of the commit slot",
			[]int{0, 2, classGroupParts - 1}},
	} {
		t.Run(row.name, func(t *testing.T) {
			// THE RESIDUAL IS CLOSED, and closed for any number of faults
			// rather than for three, because the answer no longer depends on
			// the region: under the committed history the cut is withheld.
			committed := writeClassLogCommitted(t, f, classGroupParts, row.holes...)
			assertRefusesToOpen(t, committed, "three damage sites in one committed group")
			if d := diagnose(t, committed); d.Repairable {
				t.Fatalf("three faults inside one committed transaction still hand back the "+
					"cut, so the residual this row was filed for is open: %s", d.Explanation)
			}

			// And the control the residual's old row was: with nothing ever
			// reported committed, the same three faults must still be
			// recoverable, or this is a blanket refusal wearing a rule's name.
			dir := writeClassLog(t, f, classGroupParts, row.holes...)
			assertRefusesToOpen(t, dir, "three damage sites in one abandoned group")
			d := diagnose(t, dir)
			if !d.Repairable {
				t.Fatalf("Repairable = false, want true — nothing was ever reported committed "+
					"here, so this store is the first-part hole's recovery, not a resync: %s", d.Explanation)
			}
			if d.Offset != int64(len(f.committed)) {
				t.Fatalf("Offset = %d, want %d — the whole group is what is offered",
					d.Offset, len(f.committed))
			}
		})
	}
}

// TestTheCommitSlotCheckHoldsWhereTheDamagedPayloadIsExcluded runs the
// commit-slot property in the other region shape, which the rest of this suite
// never reaches (found by review).
//
// Every other case here damages a record's *header*, so the frame length is
// unusable and the searched region has to begin at the damaged record's own
// first byte — it contains that record's payload. When only the payload fails
// its checksum the header is still trustworthy, `Diagnose` sets
// scanFrom = frameLen, and the region begins after the damaged frame at an
// honest boundary. The guard must give the same answers there; "the check is
// region-shape-agnostic" was a belief until this measured it.
func TestTheCommitSlotCheckHoldsWhereTheDamagedPayloadIsExcluded(t *testing.T) {
	f := buildClassFixture(t)
	openerAt := len(f.committed)

	// Corrupt the opener's payload only: its header checksum still passes, so
	// the frame length survives and the damaged payload is excluded from the
	// region. Doing it after writeClassLog keeps every later offset exactly
	// where a crash would have left it.
	payloadBadOpener := func(t *testing.T, dir string) {
		t.Helper()
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[openerAt+recordHeaderLen] ^= 0x01
		// Without this the test does not pin the region shape its name
		// asserts: flip a header byte instead and every assertion below
		// passes identically, in the decodeHeaderUntrusted shape four other
		// subtests already cover. The one thing this test exists to
		// demonstrate would be the one thing it did not check.
		if _, _, _, _, st := decodeRecord(raw[openerAt:]); st != decodePayloadBad {
			t.Fatalf("the opener is %v, not decodePayloadBad — this test is not in the "+
				"region shape its name claims", st)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("commit record destroyed", func(t *testing.T) {
		dir := writeClassLogCommitted(t, f, classGroupParts, classGroupParts-1)
		payloadBadOpener(t, dir)
		assertRefusesToOpen(t, dir, "payload-damaged opener and a holed commit record")
		d := diagnose(t, dir)
		if d.Repairable {
			t.Fatalf("a cut was offered over a committed transaction: %s", d.Explanation)
		}
		if !strings.Contains(d.Explanation, "was reported committed") {
			t.Fatalf("the refusal does not rest on the commit record sidecar: %s", d.Explanation)
		}
	})

	// The separating control, so the refusal above is attributable to the
	// commit record's bytes and not to the region shape: same payload damage,
	// log ending where the surviving parts end.
	t.Run("commit record never landed", func(t *testing.T) {
		dir := writeClassLog(t, f, classGroupParts-1)
		payloadBadOpener(t, dir)
		assertRefusesToOpen(t, dir, "payload-damaged opener, no commit record")
		d := diagnose(t, dir)
		if !d.Repairable {
			t.Fatalf("an abandoned group became a resync in this region shape: %s",
				d.Explanation)
		}
		if d.Offset != int64(openerAt) {
			t.Fatalf("Offset = %d, want %d", d.Offset, openerAt)
		}
	})
}

// TestATornCommitRecordIsNotADestroyedOne is the boundary the commit-slot guard
// first drew in the wrong place (found by review).
//
// Property, in one sentence: bytes left in the commit record's slot withhold
// the cut only when they could have BEEN a commit record, and a proven short
// write could not have been one.
//
// The first fix asked "does the log continue past the surviving parts", which
// is a test for any leftover byte at all. A crash that dies part-way through
// writing the commit record leaves exactly such bytes — an ordinary torn
// tail, the commonest damage there is — and one byte was enough to turn a
// repairable store into "resync this store", with an operator message saying
// a committed transaction sat behind the damage when none ever did.
//
// The two cases are distinguishable, and by a proof this package already
// relies on rather than a new heuristic: decodeTorn means the writer was cut
// off mid-record, so nothing at or past that point reached stable storage.
// replayLog discards such a tail without even scanning, and decodeStatus says
// why in terms — "there is provably nothing after this point to lose".
//
// Both ends of the boundary are pinned, because a boundary has two sides:
// recordHeaderLen is the smallest torn tail this property can be asserted
// about, and one byte short of the whole record is the largest. Beyond it the
// record is complete, the transaction really was reported committed, and the
// answer must invert.
//
// WHY THE SMALL END IS recordHeaderLen AND NOT ONE. An earlier revision of this
// test also ran n = 1 and n = 20, and both passed — but they passed for a
// property this test does not name. Substituting make([]byte, n) for
// commit[:n], i.e. arbitrary bytes that are explicitly NOT a short write,
// leaves n = 1 and n = 20 green and fails n = 40 and n = 135 (review mutant
// T2). Below recordHeaderLen decodeRecord returns decodeTorn on length alone,
// so those two corners pin "fewer than a header's bytes remain" and not "this
// was a short write": the name was doing the asserting. At n = 32 the header is
// present and verifies, so decodeTorn is reached by the incomplete-frame branch
// instead — a proof about the writer rather than about how much is left — and
// the fixture separates torn from not-torn for the first time. The corners that
// were removed are not lost coverage: they are the resolution limit, and they
// are now pinned as such, on both sides, by
// TestTheCutIsWithheldOnlyWhereTheSlotDoesNotDecodeAsTorn.
func TestATornCommitRecordIsNotADestroyedOne(t *testing.T) {
	f := buildClassFixture(t)
	commit := f.parts[classGroupParts-1]
	cutAt := int64(len(f.committed))

	// A partial write of the group's real commit record, n bytes of it.
	tornBy := func(t *testing.T, n int) string {
		t.Helper()
		dir := writeClassLog(t, f, classGroupParts-1, 0)
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, commit[:n]...), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	for _, n := range []int{recordHeaderLen, 40, len(commit) - 1} {
		t.Run(fmt.Sprintf("torn after %d byte(s)", n), func(t *testing.T) {
			dir := tornBy(t, n)
			assertRefusesToOpen(t, dir, "a hole in the opener and a torn commit record")
			d := diagnose(t, dir)
			if !d.Repairable {
				t.Fatalf("a torn commit record was treated as a destroyed one, so the "+
					"recovery `repair` exists to offer became a resync: %s", d.Explanation)
			}
			if d.Offset != cutAt {
				t.Fatalf("Offset = %d, want %d", d.Offset, cutAt)
			}
			// Non-vacuity: the store must really contain those trailing
			// bytes, or this is the no-tail case under a different name.
			if d.Discard != int64(len(f.parts[0])+len(f.parts[1])+len(f.parts[2])+n) {
				t.Fatalf("Discard = %d does not account for the %d torn byte(s)", d.Discard, n)
			}
			repair(t, dir)
			assertOpensWithOnlyTheCommittedRecord(t, dir)
		})
	}

	// The far side: the commit record landed whole. The transaction WAS
	// reported committed, and the same store must refuse. Without this the
	// test above would pass for a rule that never withholds anything.
	t.Run("the commit record landed whole", func(t *testing.T) {
		dir := tornBy(t, len(commit))
		assertRefusesToOpen(t, dir, "the commit record is complete")
		if d := diagnose(t, dir); d.Repairable {
			t.Fatalf("a cut was offered over a completed transaction: %s", d.Explanation)
		}
	})

	// And the destroyed-commit side, on the same fixture: the same shape under
	// the history in which the transaction really was reported committed.
	t.Run("the slot holds a destroyed commit record", func(t *testing.T) {
		dir := writeClassLogCommitted(t, f, classGroupParts, 0, classGroupParts-1)
		if d := diagnose(t, dir); d.Repairable {
			t.Fatalf("the destroyed-commit refusal regressed: %s", d.Explanation)
		}
	})
}

// TestTheCutIsWithheldAtEveryDepthOfTheCommitRecordsSlot is the successor to
// TestTheCutIsWithheldOnlyWhereTheSlotDoesNotDecodeAsTorn, and the change of
// name is the finding: THE RESIDUAL THAT TEST EXISTED TO PIN IS CLOSED.
//
// The old rule read the commit record's slot and asked whether the surviving
// bytes could have BEEN a commit record. It got two different answers depending
// on how the second fault destroyed the record, because a destroyed record and
// a short write are byte-identical when the fault TRUNCATES:
//
//	OVERWRITTEN in place — foreign bytes, which withhold the cut from
//	recordHeaderLen on;
//	TRUNCATED through — the real record's own header, which decodes as a
//	proven short write and hands the cut back at every k up to len(commit)-1.
//
// So under a truncating fault the residual ran to one byte short of the whole
// record, and docs/RUNNING.md spent three paragraphs telling operators where
// their protection stopped. The sidecar never reads the slot — it never reads
// the region at all — so the destruction shape is not a variable any more and
// the answer is the same at every k in both shapes.
//
// The table below is therefore the OLD table with its answers collapsed, and it
// keeps both shapes and both edges so that a future rule which reintroduced a
// dependence on the slot's bytes would fail here rather than pass quietly.
func TestTheCutIsWithheldAtEveryDepthOfTheCommitRecordsSlot(t *testing.T) {
	f := buildClassFixture(t)
	commit := f.parts[classGroupParts-1]
	runEnd := len(f.committed) + len(f.parts[0]) + len(f.parts[1]) + len(f.parts[2])

	// build assembles the store for one (shape, k) and one history. committed
	// says whether the group's barrier returned before the damage.
	build := func(t *testing.T, shape string, k int, committed bool) string {
		t.Helper()
		var dir string
		write := writeClassLog
		if committed {
			write = writeClassLogCommitted
		}
		if shape == "overwritten" {
			// The commit record was written and then destroyed in place, and
			// the log ends k bytes into its slot.
			dir = write(t, f, classGroupParts, 0, classGroupParts-1)
			path := filepath.Join(dir, logName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw[:runEnd+k], 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}
		// The first k bytes of the REAL commit record survive: simultaneously
		// what a writer that stopped leaves and what a fault truncating through
		// a durable commit record leaves. The same bytes, both histories.
		dir = write(t, f, classGroupParts-1, 0)
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, commit[:k]...), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	withheld, offered := 0, 0
	for _, shape := range []string{"overwritten", "truncated"} {
		for _, k := range []int{0, 1, recordHeaderLen - 1, recordHeaderLen, 40,
			len(commit) - 1, len(commit)} {
			t.Run(fmt.Sprintf("%s/%d byte(s) survive", shape, k), func(t *testing.T) {
				committed := build(t, shape, k, true)
				abandoned := build(t, shape, k, false)

				// The two histories must be byte-identical in the log, or the
				// opposite answers below are not attributable to the sidecar.
				a, err := os.ReadFile(filepath.Join(committed, logName))
				if err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(filepath.Join(abandoned, logName))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(a, b) {
					t.Fatalf("the two histories left different logs (%d and %d bytes)",
						len(a), len(b))
				}

				assertRefusesToOpen(t, committed, "a committed transaction lost its opener "+
					"and its commit record")
				if d := diagnose(t, committed); d.Repairable {
					t.Fatalf("%s/k=%d: a cut was offered over a transaction the store reported "+
						"committed — this is the residual the slot check could not close: %s",
						shape, k, d.Explanation)
				}
				withheld++

				// The abandoned history must keep its recovery at every k, or
				// the sidecar has become a blanket refusal.
				assertRefusesToOpen(t, abandoned, "Open cannot separate the two and must not guess")
				d := diagnose(t, abandoned)
				if k == len(commit) && shape == "truncated" {
					// The commit record survived whole, so the older
					// membership rule finds it and refuses first, in both histories.
					if d.Repairable {
						t.Fatalf("a cut was offered with an intact commit record present: %s",
							d.Explanation)
					}
					return
				}
				if !d.Repairable {
					t.Fatalf("%s/k=%d: the recovery `repair` exists to offer became a resync on "+
						"a transaction nothing ever reported committed: %s", shape, k,
						d.Explanation)
				}
				if d.Offset != int64(len(f.committed)) {
					t.Fatalf("Offset = %d, want %d", d.Offset, len(f.committed))
				}
				offered++
			})
		}
	}
	// Anti-vacuity in both directions: a sweep that refused everything, or that
	// offered everything, would satisfy one half of this and mean nothing.
	if withheld == 0 || offered == 0 {
		t.Fatalf("the sweep is one-sided: %d withheld and %d offered", withheld, offered)
	}
}

// Every phrase a refusal can carry, and the shape of report that may carry
// it. This table is the assertion: assertReportShape walks ALL of it on every
// row, so each row states the presence AND the absence of each phrase, and a
// phrase that leaks into a message it does not belong in fails there.
//
// One-directional assertions are the mistake this suite keeps making. Four
// times now a marker added to catch a report claiming too much was itself
// checked only for presence, so the next mutant put the claim it was policing
// into a neighbouring message and every row stayed green — including, twice,
// the message the payload-plant defect is actually about.
//
// This table closes that for the phrases it lists, in both directions, on
// every row. It does NOT close it for a claim written in NEW words that no
// entry matches — measured, and stated as a limit in the PR body rather than
// as a property. What closes that is the golden below, which pins the whole
// rendered sentence; this table pins which claim each shape may carry, which
// the golden cannot, because editing a golden to match a moved claim is one
// keystroke and editing this table is a deliberate statement about meaning.
// Neither subsumes the other and both are asserted on every row.
type reportShape int

const (
	// reportProvedCommitted — the frame verified and the walk landed on the
	// record found, so a writer framed it and it declares a completed
	// transaction. The only refusal that asserts anything.
	reportProvedCommitted reportShape = iota

	// reportProvedInsideAPayload — the frame verified and the walk stepped
	// over the record found, so it is content a record carries. A proof in
	// the opposite direction, which is why it needs the search-stopped clause
	// as much as the others need a hedge.
	reportProvedInsideAPayload

	// reportBlockedBySecondDamage — the frame verified and a second damaged
	// record stopped the walk before it reached the hit. Nothing established.
	reportBlockedBySecondDamage

	// reportRegionBeganInsideTheDamage — the payload plant: the frame failed its own
	// checksum, so the search had to begin inside the damaged record and the
	// region contains that record's own payload. Nothing established.
	reportRegionBeganInsideTheDamage
)

func (r reportShape) String() string {
	switch r {
	case reportProvedCommitted:
		return "reportProvedCommitted"
	case reportProvedInsideAPayload:
		return "reportProvedInsideAPayload"
	case reportBlockedBySecondDamage:
		return "reportBlockedBySecondDamage"
	case reportRegionBeganInsideTheDamage:
		return "reportRegionBeganInsideTheDamage"
	}
	return fmt.Sprintf("reportShape(%d)", int(r))
}

const (
	// The two CLAIMS, in opposite directions. Exactly one refusal shape makes
	// each, and no shape makes both.
	committedAssertion = "A transaction that was reported committed sits past the damage"
	insidePayloadProof = "so they committed nothing"

	// The hedge, shared with replayLog deliberately so the two instruments
	// cannot drift into disagreeing about the same bytes.
	openQuestionMarker = "cannot tell which"

	// The REASONS. A report that hedges for the wrong reason has told the
	// operator the opposite of what happened to their store, so each reason
	// is pinned to its own shape in both directions.
	secondDamageMarker           = "is damaged too"
	insideTheDamagedRecordMarker = "records had to begin inside it"

	// The clause that keeps the one positive nothing-is-there claim from
	// reading as "this store is fine and I still will not cut it" — which is
	// the pressure that produces the operator force-cut flag every pass over this
	// command has rejected. It is form-independent where the rest of that message is a
	// form-dependent proof, so it is the half most easily lost.
	searchStoppedMarker = "still unread"
)

// reportPhrases is every phrase above against the shapes that carry it.
// replayLog's own messages carry the two that both instruments share, which
// is what lets one table check both readers.
var reportPhrases = []struct {
	phrase string
	in     []reportShape
}{
	{committedAssertion, []reportShape{reportProvedCommitted}},
	{insidePayloadProof, []reportShape{reportProvedInsideAPayload}},
	{searchStoppedMarker, []reportShape{reportProvedInsideAPayload}},
	{openQuestionMarker, []reportShape{reportBlockedBySecondDamage, reportRegionBeganInsideTheDamage}},
	{secondDamageMarker, []reportShape{reportBlockedBySecondDamage}},
	{insideTheDamagedRecordMarker, []reportShape{reportRegionBeganInsideTheDamage}},
}

// reportPhraseCount pins the table's size. Deleting a row silently drops both
// directions of that phrase's coverage, and an unused const is legal Go, so
// there is no compiler backstop — measured: removing the secondDamageMarker
// row leaves every subtest green. Trimming this table has to be a deliberate
// act, so it costs a second edit here.
const reportPhraseCount = 6

// sharedWithReplayLog are the phrases Open's own refusal must agree about on
// the same bytes. The narrower ones describe a walk replayLog never does.
var sharedWithReplayLog = map[string]bool{
	openQuestionMarker:           true,
	insideTheDamagedRecordMarker: true,
}

// assertReportShape requires text to carry exactly the phrases want carries
// and none of the others. Both directions, every phrase, every row.
func assertReportShape(t *testing.T, who, text string, want reportShape, sharedOnly bool) {
	t.Helper()
	for _, p := range reportPhrases {
		if sharedOnly && !sharedWithReplayLog[p.phrase] {
			continue
		}
		expect := false
		for _, sh := range p.in {
			if sh == want {
				expect = true
			}
		}
		if got := strings.Contains(text, p.phrase); got != expect {
			verb := "must not carry"
			if expect {
				verb = "must carry"
			}
			t.Fatalf("%s reports %v, so it %s %q, but present = %v: %s",
				who, want, verb, p.phrase, got, text)
		}
	}
}

// The exact sentence each shape renders, offsets as verbs. A GOLDEN, not a
// property, and deliberately so.
//
// Four rounds of review on this file each found the same thing: an assertion
// that says where something must be is silent about everywhere else, so the
// next mutant put a claim somewhere the assertion was not looking. Six slot
// templates checked six offsets and left the payload-plant message's two unchecked;
// one of the six was satisfied by a decimal PREFIX; and a claim added in new
// words passed every one of them. Each fix was another positive assertion
// with its own new gap.
//
// A golden has no gap by construction: any change to any of these sentences —
// a clause added, a clause deleted, an offset moved between slots, a number
// scaled — fails here and has to be answered by editing the constant, which
// is a deliberate act a human reads in the diff. That is the discipline
// spec/vectors already imposes on this repo, and every pass over this command
// has treated these strings as an operator contract, which is what they are: the entire
// output of the instrument that decides whether a data directory is
// destroyed.
//
// What it cannot do is answer "is this new sentence a CLAIM?". Nothing
// mechanical can. What it does is convert that question from silent to loud.
const (
	textProvedCommitted = "the record at offset %d has a damaged payload inside a frame that " +
		"passed its own checksum, so the search for committed records began past that " +
		"record's last byte — and walking whole records forward from there reaches an intact " +
		"record at offset %d that declares itself the last record of its transaction. A " +
		"transaction that was reported committed sits past the damage, and cutting here would " +
		"delete it. No cut is offered — resync this store."

	textProvedInsideAPayload = "the record at offset %d has a damaged payload inside a frame " +
		"that passed its own checksum, so the search for committed records began past that " +
		"record's last byte — and walking whole records forward from there steps straight over " +
		"offset %d, where a record declaring itself the last of its transaction was decoded. " +
		"Those bytes are inside the record that begins at offset %d — content that record " +
		"carries, not a record of this log — so they committed nothing. The search stopped at " +
		"that first candidate, so what lies past it is still unread. No cut is offered — " +
		"resync this store."

	textBlockedBySecondDamage = "the record at offset %d has a damaged payload inside a frame " +
		"that passed its own checksum, so the search for committed records began past that " +
		"record's last byte — but the record at offset %d is damaged too, so walking whole " +
		"records forward stops there and never reaches offset %d, where a record declaring " +
		"itself the last of its transaction was decoded. That is either a transaction that was " +
		"reported committed sitting past the damage, or record-shaped bytes inside a later " +
		"record's own payload. This reader cannot tell which, and no checksum can. No cut is " +
		"offered — resync this store."

	textRegionBeganInsideTheDamage = "the record at offset %d is damaged, and its frame failed " +
		"its own checksum, so the search for committed records had to begin inside it — and a " +
		"record decoded at offset %d declares itself the last record of its transaction. That " +
		"is either a transaction that was reported committed sitting past the damage, or " +
		"record-shaped bytes inside this record's own payload, which is a block body this node " +
		"accepted over the network and wrote verbatim. This reader cannot tell which, and no " +
		"checksum can. No cut is offered — the bytes it would discard may be intact, but " +
		"nothing here can establish that, so resync this store."
)

func (r reportShape) text() string {
	switch r {
	case reportProvedCommitted:
		return textProvedCommitted
	case reportProvedInsideAPayload:
		return textProvedInsideAPayload
	case reportBlockedBySecondDamage:
		return textBlockedBySecondDamage
	case reportRegionBeganInsideTheDamage:
		return textRegionBeganInsideTheDamage
	}
	t := fmt.Sprintf("no golden for %v", r)
	return t
}

// verdict is the machine-readable half of the same statement the golden above
// pins in prose. The two are separate assertions on purpose: the
// sentence is what an operator reads and the field is what a runbook branches
// on, and a change that moved one without the other would put the instrument
// and the script that drives it into disagreement about the same store.
//
// The mapping is one-to-one and every row below asserts it, so a Verdict left
// unset, set to a neighbour's value, or set on a shape that established
// nothing fails on the row that reaches that shape.
func (r reportShape) verdict() Verdict {
	switch r {
	case reportProvedCommitted:
		return ProvenUnsafeToCut
	case reportProvedInsideAPayload:
		return FoundRecordDisproved
	case reportBlockedBySecondDamage:
		return BlockedBySecondDamage
	case reportRegionBeganInsideTheDamage:
		return SearchBeganInsideDamage
	}
	return VerdictNone
}

// assertReport is the whole check a row makes on repair's own report: the
// phrase table for WHICH claim the shape may carry, the golden for the exact
// sentence it rendered, and the Verdict field the sentence's machine-readable
// twin. The offsets are passed as the caller's own independently derived
// values, so the golden subsumes every per-slot check that used to be here —
// an offset moved between slots, replaced, or scaled changes the rendered
// string and fails.
func assertReport(t *testing.T, d *LogDiagnosis, want reportShape, offsets ...any) {
	t.Helper()
	if len(reportPhrases) != reportPhraseCount {
		t.Fatalf("reportPhrases has %d rows, want %d — a phrase gained or lost its coverage "+
			"in both directions; update reportPhraseCount deliberately if that was the intent",
			len(reportPhrases), reportPhraseCount)
	}
	assertReportShape(t, "repair", d.Explanation, want, false)
	if got := d.Explanation; got != fmt.Sprintf(want.text(), offsets...) {
		t.Fatalf("the report is not the sentence %v renders."+"\n got: %s"+"\nwant: %s",
			want, got, fmt.Sprintf(want.text(), offsets...))
	}
	if got, wantV := d.Verdict, want.verdict(); got != wantV {
		t.Fatalf("the report reads %v but names Verdict %v, want %v — the sentence an "+
			"operator reads and the field a runbook branches on disagree about this store: %s",
			want, got, wantV, d.Explanation)
	}
	// The second damage SITE, which `zycordd repair` prints in this state's
	// verdict line and which the operator reads nowhere else. It is slot 1 of
	// textBlockedBySecondDamage, so this asserts the field against the same
	// independently derived offset the golden already checks the prose
	// against — and asserts its ABSENCE everywhere else, because a stale site
	// named on a store that has none is a second damage report invented out
	// of the previous row.
	wantSite := int64(0)
	if want == reportBlockedBySecondDamage {
		site, ok := offsets[1].(int)
		if !ok {
			t.Fatalf("this row passes %T as the blocker's offset; assertReport cannot check "+
				"SecondDamageOffset against it", offsets[1])
		}
		wantSite = int64(site)
	}
	if d.SecondDamageOffset != wantSite {
		t.Fatalf("the report reads %v and names SecondDamageOffset %d, want %d",
			want, d.SecondDamageOffset, wantSite)
	}
}

// TestRepairReportsTheSameQuestionAsOpenRatherThanAnsweringIt pins the payload
// plant's operator-facing half: whether a record found behind damaged bytes
// proves a committed transaction depends entirely on where the search was
// allowed to begin, and BOTH instruments an operator consults must say so, or
// neither.
//
// replayLog has been conditioned on this since the second door opened — with
// the frame unusable its message says a hit "is either data written after this
// one or record-shaped bytes inside this one's own payload. This reader cannot
// tell which". Diagnose's was not, and stated the stronger reading
// unconditionally. So on the shape the payload plant describes the node said
// the question was open while `zycordd repair`, the instrument the operator
// runs next to decide whether to discard the directory, told them a committed
// transaction was provably behind the damage. It is not provable there and no
// checksum can make it so.
//
// The verdict is not what this fixes and must not move: every row here refuses,
// before and after. A false "not repairable" costs a resync; a false
// "repairable" costs committed transactions the chain above expects to find.
//
// Each row asserts its own region shape, because without that a row can pass
// in the shape it exists to be different from and the pair stops separating
// anything (a lesson learned from mutant S9 of this suite's own grid).
func TestRepairReportsTheSameQuestionAsOpenRatherThanAnsweringIt(t *testing.T) {
	// The frame's own checksum failed, so the region begins at the damaged
	// record's first byte and contains its payload, and the payload here
	// carries a fully-formed record declaring a completed transaction — the
	// forgery the payload plant is about.
	t.Run("frame unusable, terminal record inside the damaged payload", func(t *testing.T) {
		inner := &Batch{}
		inner.Put([]byte("bait-key"), []byte("bait-value"))
		embedded, err := encodeRecord(inner, 9, 0)
		if err != nil {
			t.Fatal(err)
		}
		c := buildCommitChain(t, 3)
		carrier := &Batch{}
		carrier.Put([]byte("key-3"), embedded)
		// frameUnescaped: encodeRecord would otherwise take the magic out of the
		// payload, so the plant would not be in the log at all and this row
		// would assert nothing. See frameUnescaped.
		c.records = append(c.records, frameUnescaped(t, carrier, 3, 0))
		dir := writeChain(t, c, map[int]func([]byte){3: breakHeader})
		assertRegionShape(t, dir, c.offsetOf(3), decodeHeaderUntrusted)
		assertAgreeTheQuestionIsOpen(t, dir, reportRegionBeganInsideTheDamage,
			c.offsetOf(3), plantOffset(t, dir, embedded))
	})

	// The same region shape with a genuinely committed record behind the
	// damage. The report must read the same way, because what the reader
	// cannot establish is the same thing: the branch is keyed on the region,
	// not on whether the record found is a forgery. A message that named the
	// forgery would be claiming to have detected one.
	t.Run("frame unusable, genuine commits behind the damage", func(t *testing.T) {
		c := buildCommitChain(t, 4)
		dir := writeChain(t, c, map[int]func([]byte){1: breakHeader})
		assertRegionShape(t, dir, c.offsetOf(1), decodeHeaderUntrusted)
		assertAgreeTheQuestionIsOpen(t, dir, reportRegionBeganInsideTheDamage,
			c.offsetOf(1), c.offsetOf(2))
	})

	// The separating input. The header checksum survived, so the record's end
	// is a fact, the search begins past its last byte and no planted byte can
	// enter the region. Here the hit really is data a writer produced
	// afterwards, and both instruments must say so outright — a report that
	// hedged here would be refusing to state a fact it has.
	t.Run("frame verified, region begins past the damaged record", func(t *testing.T) {
		c := buildCommitChain(t, 4)
		dir := writeChain(t, c, nil)
		at := c.offsetOf(1)
		breakPayloadAt(t, dir, at)
		assertRegionShape(t, dir, at, decodePayloadBad)
		assertAgreeTheQuestionIsOpen(t, dir, reportProvedCommitted, at, c.offsetOf(2))
	})
}

// assertRegionShape fails unless the damaged record decodes as the status
// whose region the caller means to be testing in. Without it a row passes
// identically in the other shape and pins nothing.
func assertRegionShape(t *testing.T, dir string, at int, want decodeStatus) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, st := decodeRecord(raw[at:]); st != want {
		t.Fatalf("the damaged record at offset %d is %s, not %s — this row is not in the "+
			"region shape its name claims", at, decodeStatusName(st), decodeStatusName(want))
	}
}

// decodeStatusName names a decodeStatus in a failure message. The constants
// are unexported ints with no String method, so %v prints the number and the
// one assertion that exists to say WHICH region shape a row landed in reports
// it as "2, not 4" — a diagnostic that names the wrong thing is how a
// property stays invisible.
func decodeStatusName(s decodeStatus) string {
	switch s {
	case decodeOK:
		return "decodeOK"
	case decodeTorn:
		return "decodeTorn"
	case decodeHeaderUntrusted:
		return "decodeHeaderUntrusted"
	case decodePayloadBad:
		return "decodePayloadBad"
	case decodeMaxLenExceeded:
		return "decodeMaxLenExceeded"
	}
	return fmt.Sprintf("decodeStatus(%d)", int(s))
}

// assertAgreeTheQuestionIsOpen runs both instruments over one store and
// requires them to report the same shape, then requires the verdict to be a
// refusal either way.
//
// It checks the whole phrase table on repair's report and the shared half of
// it on Open's, so a row states the ABSENCE of every claim it does not make.
// Presence-only was the gap that let a mutant put the committed assertion
// into the payload plant's own message with all 51 subtests green.
func assertAgreeTheQuestionIsOpen(t *testing.T, dir string, want reportShape,
	offsets ...any) {
	t.Helper()
	openErr := assertRefusesToOpen(t, dir, "damage with a terminal record behind it")
	d := diagnose(t, dir)
	if d.Repairable {
		t.Fatalf("a cut was offered where a record behind the damage terminates a "+
			"transaction: %s", d.Explanation)
	}
	// Open's own message embeds a data directory path, so it gets the shared
	// half of the phrase table rather than a golden. That half is the mirrored
	// -guard property and nothing else carries it.
	assertReportShape(t, "Open", openErr.Error(), want, true)
	assertReport(t, d, want, offsets...)
}

// TestRepairAssertsACommittedTransactionOnlyWhereTheRecordFoundSitsOnAFrameBoundary
// pins the half of the payload plant that survives a verified frame.
//
// findTerminalRecordWithin is a magic search, and followSequenceRun's doc says
// what that means: "A search would find records anywhere, including inside a
// payload." Beginning the search past a verified frame's last byte takes the
// DAMAGED record's payload out of the region and nothing else. Every record
// written after it carries a payload too — so the forgery fits inside one of
// them, one record further on, and a report keyed only on where the region
// begins asserts a committed transaction it has not got.
//
// What settles it is tiling whole records forward from the region's start,
// which the verified frame proves is a boundary. The walk has three outcomes
// and the rows below reach each of them by an input that reaches only it, in
// BOTH the degenerate and the non-degenerate form of its output offset:
//
//   - LANDED, zero steps and two steps. The two-step row is the one the
//     induction is made of; the zero-step row alone left three mutants alive.
//   - STEPPED OVER, with the carrier at the region's start and one record in.
//   - BLOCKED, by a blocker whose extent is a fact and by one with none —
//     the decodeOK test's two jobs — both one record into the region.
//
// Every row asserts the WHOLE phrase table (presence and absence) and the
// offsets by slot, because an offset that moves between slots leaves every
// number present and every meaning wrong.
//
// The verdict does not move in any of them. Every row refuses.
func TestRepairAssertsACommittedTransactionOnlyWhereTheRecordFoundSitsOnAFrameBoundary(t *testing.T) {
	// The hit is the region's own first byte, which the verified frame proves
	// is where a writer put a record. The walk takes ZERO steps, so on its own
	// this row pins only the premise.
	t.Run("landed: the record found is the writer's own next record", func(t *testing.T) {
		c := buildCommitChain(t, 4)
		dir := writeChain(t, c, nil)
		breakPayloadAt(t, dir, c.offsetOf(1))
		assertRegionShape(t, dir, c.offsetOf(1), decodePayloadBad)

		d := assertRefusesWithoutOffering(t, dir)
		assertReport(t, d, reportProvedCommitted, c.offsetOf(1), c.offsetOf(2))
	})

	// Behind the damage sits a real three-record transaction. The search skips
	// the two parts that terminate nothing and hits the third, so the walk
	// must take TWO whole steps and land on it. Without this row the loop body
	// and the stride are never executed at all.
	t.Run("landed: the record found is two whole records past the region's start", func(t *testing.T) {
		c := buildCommitChain(t, 2)
		appendGroup(t, &c, 2, []uint32{2, 1, 0}, -1, nil)
		dir := writeChain(t, c, nil)
		breakPayloadAt(t, dir, c.offsetOf(1))
		assertRegionShape(t, dir, c.offsetOf(1), decodePayloadBad)

		d := assertRefusesWithoutOffering(t, dir)
		assertReport(t, d, reportProvedCommitted, c.offsetOf(1), c.offsetOf(4))
	})

	// The payload plant's forgery, moved one record along. The carrier is the
	// region's own first record, so the walk steps over from its very first
	// frame and the offset it reports is ZERO relative to the region: this row
	// cannot tell a tracked offset from a hard-coded 0, which is what the next
	// row is for.
	t.Run("stepped over: the carrier is the region's first record", func(t *testing.T) {
		c := buildCommitChain(t, 2)
		plant := appendGroup(t, &c, 2, []uint32{1}, 0, nil)
		dir := writeChain(t, c, nil)
		breakPayloadAt(t, dir, c.offsetOf(1))
		assertRegionShape(t, dir, c.offsetOf(1), decodePayloadBad)

		d := assertRefusesWithoutOffering(t, dir)
		assertReport(t, d, reportProvedInsideAPayload,
			c.offsetOf(1), plantOffset(t, dir, plant), c.offsetOf(2))
	})

	// The same, one record further in: a benign opener, then the part whose
	// payload carries the plant. The walk steps one whole record BEFORE
	// stepping over, so the carrier offset it reports is non-zero and this row
	// separates a tracked offset from a constant.
	t.Run("stepped over: the carrier is one record into the region", func(t *testing.T) {
		c := buildCommitChain(t, 2)
		plant := appendGroup(t, &c, 2, []uint32{2, 1}, 1, nil)
		dir := writeChain(t, c, nil)
		breakPayloadAt(t, dir, c.offsetOf(1))
		assertRegionShape(t, dir, c.offsetOf(1), decodePayloadBad)

		d := assertRefusesWithoutOffering(t, dir)
		assertReport(t, d, reportProvedInsideAPayload,
			c.offsetOf(1), plantOffset(t, dir, plant), c.offsetOf(3))
	})

	// Blocked by a record whose frame length is a FACT. decodeRecord returns a
	// meaningful n for decodePayloadBad, so the walk could cross this and stay
	// sound; it stops instead, and that is a policy. The blocker is one record
	// into the region, so the offset reported is non-zero.
	t.Run("blocked: the blocker's extent is still a fact", func(t *testing.T) {
		c := buildCommitChain(t, 2)
		appendGroup(t, &c, 2, []uint32{1, 0, 0}, -1, nil)
		dir := writeChain(t, c, nil)
		breakPayloadAt(t, dir, c.offsetOf(1))
		breakPayloadAt(t, dir, c.offsetOf(3))
		assertRegionShape(t, dir, c.offsetOf(1), decodePayloadBad)
		assertRegionShape(t, dir, c.offsetOf(3), decodePayloadBad)

		d := assertRefusesWithoutOffering(t, dir)
		assertReport(t, d, reportBlockedBySecondDamage,
			c.offsetOf(1), c.offsetOf(3), c.offsetOf(4))
	})

	// Blocked by a record with NO usable extent. decodeRecord returns n == 0
	// for decodeHeaderUntrusted, so a walk that advanced here would not
	// advance: this is the input on which deleting the decodeOK test gives not
	// a wrong answer but no answer at all, and an unbudgeted walk in a
	// recovery instrument has nothing else to stop it.
	t.Run("blocked: the blocker has no usable extent", func(t *testing.T) {
		c := buildCommitChain(t, 2)
		appendGroup(t, &c, 2, []uint32{1, 0, 0}, -1, map[int]func([]byte){1: breakHeader})
		dir := writeChain(t, c, nil)
		breakPayloadAt(t, dir, c.offsetOf(1))
		assertRegionShape(t, dir, c.offsetOf(1), decodePayloadBad)
		assertRegionShape(t, dir, c.offsetOf(3), decodeHeaderUntrusted)

		d := assertRefusesWithoutOffering(t, dir)
		assertReport(t, d, reportBlockedBySecondDamage,
			c.offsetOf(1), c.offsetOf(3), c.offsetOf(4))
	})
}

// TestOnlyASearchBehindTheDamageNamesOneOfTheFourStates is the other
// direction of the Verdict field, and it is the half a positive-only assertion
// leaves open.
//
// Verdict names WHICH of the four states a refusal behind the damage is in.
// Every other outcome of Diagnose — an undamaged log, an offered cut, a
// refusal decided before any search ran — established none of those four
// things, so it must name none of them. A zero value that drifted into
// meaning "state 1" would tell `zycordd repair` to print an assertion about a
// store nothing walked, and the sentence it would print is the one that sends
// an operator to a resync on its merits.
//
// The last row is the positive control. Without it every check here is
// satisfied by a field that is never set at all, which is exactly the mutant
// the rest of this file keeps catching one assertion too late.
func TestOnlyASearchBehindTheDamageNamesOneOfTheFourStates(t *testing.T) {
	// The tail of TestRepairCutsATailWhoseOwnPayloadLooksLikeARecord..., whose
	// embedded record declares a further part and so terminates nothing: the
	// search runs, finds nothing committed, and a cut IS offered.
	offeredCut := func(t *testing.T) string {
		t.Helper()
		inner := &Batch{}
		inner.Put([]byte("bait-key"), []byte("bait-value"))
		embedded, err := encodeRecord(inner, 9, 1)
		if err != nil {
			t.Fatal(err)
		}
		c := buildCommitChain(t, 3)
		carrier := &Batch{}
		carrier.Put([]byte("key-3"), embedded)
		c.records = append(c.records, frameUnescaped(t, carrier, 3, 0))
		return writeChain(t, c, map[int]func([]byte){3: breakHeader})
	}

	// A well-formed record carrying a sequence nothing expects. Diagnose
	// returns on the decodeOK arm, before scanFrom is ever consulted.
	outOfSequence := func(t *testing.T) string {
		t.Helper()
		c := buildCommitChain(t, 3)
		stray := &Batch{}
		stray.Put([]byte("key-7"), []byte("value-7"))
		rec, err := encodeRecord(stray, 7, 0)
		if err != nil {
			t.Fatal(err)
		}
		c.records[2] = rec
		return writeChain(t, c, nil)
	}

	for _, tc := range []struct {
		name string
		dir  func(*testing.T) string
		want Verdict
	}{
		{"a log that reads to its end", func(t *testing.T) string {
			return writeChain(t, buildCommitChain(t, 3), nil)
		}, VerdictNone},
		{"a cut this command offers", offeredCut, VerdictNone},
		{"a refusal decided before any search ran", outOfSequence, VerdictNone},
		{"a refusal the search did decide", func(t *testing.T) string {
			return writeChain(t, buildCommitChain(t, 4), map[int]func([]byte){1: zeroAll})
		}, SearchBeganInsideDamage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := diagnose(t, tc.dir(t))
			if d.Verdict != tc.want {
				t.Fatalf("Verdict = %v, want %v: %s", d.Verdict, tc.want, d.Explanation)
			}
			if d.SecondDamageOffset != 0 {
				t.Fatalf("SecondDamageOffset = %d on a store with no second damage site, so "+
					"the verdict line would name one: %s", d.SecondDamageOffset, d.Explanation)
			}
		})
	}
}

// appendGroup appends len(more) records to c, sequence firstSeq onward, each
// declaring the countdown its slot in more gives. The record at index
// plantIn (relative to the group, -1 for none) carries a fully-formed
// more == 0 record at sequence 9 inside its payload — the payload plant's forgery — and
// that record's bytes are returned so a caller can locate it in the log.
// damage names group-relative records to corrupt before they are written.
func appendGroup(t *testing.T, c *commitChain, firstSeq uint64, more []uint32, plantIn int,
	damage map[int]func([]byte)) []byte {
	t.Helper()
	var plant []byte
	if plantIn >= 0 {
		inner := &Batch{}
		inner.Put([]byte("bait-key"), []byte("bait-value"))
		var err error
		if plant, err = encodeRecord(inner, 9, 0); err != nil {
			t.Fatal(err)
		}
	}
	for i, m := range more {
		b := &Batch{}
		var rec []byte
		if i == plantIn {
			b.Put([]byte(fmt.Sprintf("g-%d", i)), plant)
			// The carrier is framed the way format version 3 did it, because
			// the plant has to reach the payload and encodeRecord no longer
			// lets it. See frameUnescaped. Only the carrier: every
			// other part goes through the ordinary writer, so a row that
			// needed no plant is unaffected.
			rec = frameUnescaped(t, b, firstSeq+uint64(i), m)
		} else {
			b.Put([]byte(fmt.Sprintf("g-%d", i)), []byte(fmt.Sprintf("gv-%d", i)))
			var err error
			if rec, err = encodeRecord(b, firstSeq+uint64(i), m); err != nil {
				t.Fatal(err)
			}
		}
		if f, ok := damage[i]; ok {
			f(rec)
		}
		c.records = append(c.records, rec)
	}
	return plant
}

// plantOffset finds the planted record's own first byte in the written log.
// The search reports the offset it hit, and that is inside another record's
// payload, so it cannot be computed from the chain's frame lengths.
func plantOffset(t *testing.T, dir string, plant []byte) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(raw, plant)
	if at < 0 {
		t.Fatal("the planted record is not in the log, so this row is not the fixture it claims")
	}
	return at
}

// breakPayloadAt flips one bit in the first payload byte of the record at
// offset at, which leaves the header checksum passing and the record's length
// a fact — the decodePayloadBad shape.
func breakPayloadAt(t *testing.T, dir string, at int) {
	t.Helper()
	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[at+recordHeaderLen] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertRefusesWithoutOffering is the precondition both rows above share and
// the property neither may move: Open refuses, and repair offers no cut.
func assertRefusesWithoutOffering(t *testing.T, dir string) *LogDiagnosis {
	t.Helper()
	assertRefusesToOpen(t, dir, "a damaged payload with record-shaped bytes behind it")
	d := diagnose(t, dir)
	if d.Repairable {
		t.Fatalf("a cut was offered where a terminal record was found behind the damage: %s",
			d.Explanation)
	}
	return d
}

// The survivor-count goldens.
//
// Whole rendered sentences, offsets and counts supplied by each row as its
// own independently derived values, for the same reason the refusal goldens
// above exist: an assertion that checks where a number must be is silent
// about the number that is somewhere else, and the number this suite kept
// not looking at is the one that says how much of the store is left.
//
// These are NOT added to reportPhrases. That table's own doc scopes it to
// every phrase a REFUSAL can carry, and every shape in it refuses; these
// sentences are the two reports that tell an operator the store is
// recoverable. Widening the table to cover them would make every refusal row
// assert the absence of a phrase from a message it has no relationship to.
// reportPhraseCount therefore stays at 6, deliberately.
const (
	// The clause every offer now ends on, and the reason it is a constant:
	// what an operator types `yes` against must state what this reader
	// established and what it did not, and the four offers must not be able
	// to drift into saying that differently from one another.
	textTheAbsenceIsNotAProof = " That absence is not a proof: a commit record that was " +
		"written and then destroyed is missing from this search in exactly the way one that " +
		"was never written is, and nothing in these bytes separates the two — copy this " +
		"directory before you answer."

	textOfferInsideAnOpenTransaction = "the record at offset %d is damaged, and no record " +
		"behind it terminates a transaction, so nothing this reader can find behind the " +
		"damage was ever reported committed; the damage falls inside the multi-record " +
		"transaction beginning at offset %d (sequence %d), which is discarded whole. " +
		"Discarding %d byte(s) from offset %d keeps %d record(s) (sequence 0..%d)." +
		textTheAbsenceIsNotAProof

	textOfferInsideAnOpenTransactionKeepingNothing = "the record at offset %d is damaged, and " +
		"no record behind it terminates a transaction, so nothing this reader can find behind " +
		"the damage was ever reported committed; the damage falls inside the multi-record " +
		"transaction beginning at offset %d (sequence %d), which is discarded whole. " +
		"Discarding %d byte(s) from offset %d keeps no records — this log's intact prefix is " +
		"entirely inside that transaction." + textTheAbsenceIsNotAProof

	textOfferOutsideAnyTransactionKeepingNothing = "the record at offset %d is damaged, and no " +
		"record behind it terminates a transaction, so nothing this reader can find behind the " +
		"damage was ever reported committed. Discarding %d byte(s) from offset %d keeps no " +
		"records — this log has no intact prefix at all." + textTheAbsenceIsNotAProof

	textOfferOutsideAnyTransaction = "the record at offset %d is damaged, and no record behind " +
		"it terminates a transaction, so nothing this reader can find behind the damage was " +
		"ever reported committed. Discarding %d byte(s) from offset %d keeps %d record(s) " +
		"(sequence 0..%d)." + textTheAbsenceIsNotAProof

	textBootDiscardsAnOpenTransaction = "the log ends part-way through the multi-record " +
		"transaction beginning at offset %d (sequence %d), and starting the node discards " +
		"them on its own; the %d record(s) before that are intact. Nothing to repair — start " +
		"the node."

	textBootDiscardsAnUnreadableTail = "the log ends in %d unreadable byte(s) at offset %d, and " +
		"starting the node discards them on its own; the %d record(s) before that are intact. " +
		"Nothing to repair — start the node."

	textLogEndsInsideAnOpenTransaction = "the log ends part-way through a multi-record " +
		"transaction (beginning at sequence %d), and starting the node discards that " +
		"transaction on its own; the %d record(s) before it are intact. Nothing to repair."
)

// assertExplanation compares the whole rendered report against the golden the
// row names, with the row's own numbers. Put where the claim is made: the
// claim is a sentence, so the assertion is over the sentence.
func assertExplanation(t *testing.T, d *LogDiagnosis, golden string, args ...any) {
	t.Helper()
	if want := fmt.Sprintf(golden, args...); d.Explanation != want {
		t.Fatalf("the report is not the sentence this shape renders."+
			"\n got: %s"+"\nwant: %s", d.Explanation, want)
	}
}

// survivorsAfterBoot opens the store and returns how many records replay
// leaves behind it. nextSeq is the sequence the next append would carry, so
// on a densely numbered log it IS the count of surviving records, and it is
// fixture-independent in a way counting keys is not.
func survivorsAfterBoot(t *testing.T, dir string) uint64 {
	t.Helper()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("Open refused after the store was declared recoverable: %v", err)
	}
	defer s.Close()
	return s.nextSeq
}

// foreignRecordAt overwrites the record at off, in place and at its own
// length, with one that belongs to no open transaction and terminates none.
//
// It is what keeps a store on the OFFER path with a transaction still open:
// replayLog's own search dismisses an open group's surviving parts as its
// members, so a store whose only records behind the damage are that
// group's parts is self-healing and never reaches an operator at all.
func foreignRecordAt(t *testing.T, dir string, off int) {
	t.Helper()
	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(raw[off+recordSeqOff:], 99)
	binary.LittleEndian.PutUint32(raw[off+recordMoreOff:], 1)
	resign(t, raw, off)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAReportNamesTheRecordsThatSurviveItsOwnCutAndNotTheOnesReplayRead is
// the survivor-count defect on the path that reaches an operator with a yes/no
// prompt.
//
// Property, in one sentence: every number a report gives for what is left of
// the store is the number that is left of the store after the action the same
// report describes.
//
// Inside an open transaction the cut goes back to that transaction's first
// record — replayLog's rule, carried across, and the whole reason a first-part
// hole is recoverable. The count did not move with it. So a report could say,
// in one clause, that the transaction "is discarded whole", and in the next
// that the cut "keeps 3 record(s) (sequence 0..2)" — sequences 1 and 2 being
// that transaction's own parts. `zycordd repair` then printed "3 record(s)
// remain" after the deletion. One record remained.
//
// This is the same direction: the instrument that decides whether a data
// directory is destroyed understating what the offered action costs. It is not
// the destroyed-commit-record problem itself and does not close it — see the
// residuals — but it is the half that needs no out-of-band evidence to fix,
// because the number that is true is already in the same function.
//
// THE GUARD HAS ONE CONJUNCT, groupOpen, and it selects a PAIR. Every row
// below therefore comes with its opposite: an offer with a transaction open
// and an offer with none, a boot with one and a boot with none. A row on its
// own passes for a rule that always reports groupSeq — which is zero outside
// a group — as well as for the correct one.
func TestAReportNamesTheRecordsThatSurviveItsOwnCutAndNotTheOnesReplayRead(t *testing.T) {
	f := buildClassFixture(t)
	openerAt := len(f.committed)
	part2At := openerAt + len(f.parts[0]) + len(f.parts[1])
	part3At := part2At + len(f.parts[2])

	t.Run("an offered cut inside an open transaction", func(t *testing.T) {
		// The opener and part 1 are read in sequence, so the group is open
		// and its extent is honest; part 2 is a hole; part 3's slot holds a
		// record that terminates nothing, which is what keeps replayLog's
		// search from coming back empty and self-healing the store.
		dir := writeClassLog(t, f, classGroupParts, 2)
		foreignRecordAt(t, dir, part3At)
		assertRefusesToOpen(t, dir, "a hole inside an open transaction, foreign record behind")

		d := diagnose(t, dir)
		if !d.Repairable {
			t.Fatalf("no cut offered, so this row measures nothing: %s", d.Explanation)
		}
		// Non-vacuity, and the whole point of the row: the two counts must
		// actually DIFFER on this store, or naming either one would pass.
		if d.RecordsIntact != 3 {
			t.Fatalf("RecordsIntact = %d, want 3 — replay must read past the group's opener "+
				"here or the two counts coincide and this row separates nothing",
				d.RecordsIntact)
		}
		if d.RecordsKept != 1 {
			t.Fatalf("RecordsKept = %d, want 1", d.RecordsKept)
		}
		if d.Offset != int64(openerAt) {
			t.Fatalf("Offset = %d, want %d — the cut must go back to the transaction's "+
				"first record or there is no gap for the count to fall into",
				d.Offset, openerAt)
		}
		assertExplanation(t, d, textOfferInsideAnOpenTransaction,
			part2At, openerAt, 1, d.Discard, openerAt, 1, 0)

		// The claim, checked against the store rather than against itself.
		repair(t, dir)
		if got := survivorsAfterBoot(t, dir); got != d.RecordsKept {
			t.Fatalf("the cut left %d record(s); the report offered it as keeping %d",
				got, d.RecordsKept)
		}
	})

	t.Run("an offered cut with no transaction open", func(t *testing.T) {
		// The separating control for the one conjunct: same offer path, no
		// group, so the cut stays at the damage and the count stays at what
		// replay read. A rule that always names the group's first sequence
		// would say 0 here.
		//
		// An opener behind the damage is what keeps Open from self-healing
		// this store: every ordinary commit carries more == 0, so a chain
		// with an intact record behind the damage is refused by the older
		// membership rule instead and never reaches the offer at all.
		c := buildCommitChain(t, 4)
		opener := &Batch{}
		opener.Put([]byte("opener-key"), []byte("opener-value"))
		rec, err := encodeRecord(opener, 4, 1)
		if err != nil {
			t.Fatal(err)
		}
		c.records = append(c.records, rec)
		dir := writeChain(t, c, map[int]func([]byte){3: breakHeader})
		assertRefusesToOpen(t, dir, "a damaged header with nothing committed behind it")

		d := diagnose(t, dir)
		if !d.Repairable {
			t.Fatalf("no cut offered, so this row measures nothing: %s", d.Explanation)
		}
		if d.RecordsIntact != 3 || d.RecordsKept != 3 {
			t.Fatalf("RecordsIntact = %d, RecordsKept = %d, want 3 and 3",
				d.RecordsIntact, d.RecordsKept)
		}
		assertExplanation(t, d, textOfferOutsideAnyTransaction,
			c.offsetOf(3), d.Discard, c.offsetOf(3), 3, 2)

		repair(t, dir)
		if got := survivorsAfterBoot(t, dir); got != d.RecordsKept {
			t.Fatalf("the cut left %d record(s); the report offered it as keeping %d",
				got, d.RecordsKept)
		}
	})

	t.Run("an offered cut that keeps nothing", func(t *testing.T) {
		// The second conjunct: the "keeps no records" clause was keyed on
		// how many records replay READ, not on how many survive. A log whose
		// FIRST record opens a transaction separates them — replay reads one
		// record and the cut keeps none — and the old wording offered a cut
		// that "keeps 1 record(s) (sequence 0..0)" over an empty log.
		//
		// Moving that guard is not the whole of it, and the REASON the clause
		// gives has to move with it. Here the log does have an intact prefix —
		// RecordsIntact is 1, and `zycordd repair` prints "readable:  1
		// record(s)" two lines above the finding — so the sentence this row
		// used to assert, "this log has no intact prefix at all", was false on
		// the store it was asserted against, and the next row is its opposite.
		parts := make([][]byte, classGroupParts)
		for i, b := range groupParts(classGroupParts, 1) {
			rec, err := encodeRecord(b, uint64(i), uint32(classGroupParts-1-i))
			if err != nil {
				t.Fatal(err)
			}
			parts[i] = rec
		}
		var raw []byte
		raw = append(raw, parts[0]...)
		raw = append(raw, make([]byte, len(parts[1]))...)
		raw = append(raw, make([]byte, len(parts[2]))...)
		raw = append(raw, parts[3]...)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		foreignRecordAt(t, dir, len(parts[0])+len(parts[1])+len(parts[2]))
		assertRefusesToOpen(t, dir, "a transaction opening the log, holed, foreign record behind")

		d := diagnose(t, dir)
		if !d.Repairable {
			t.Fatalf("no cut offered, so this row measures nothing: %s", d.Explanation)
		}
		if d.RecordsIntact != 1 {
			t.Fatalf("RecordsIntact = %d, want 1 — replay must read the opener here or the "+
				"two counts coincide at zero and this row separates nothing", d.RecordsIntact)
		}
		if d.RecordsKept != 0 || d.Offset != 0 {
			t.Fatalf("RecordsKept = %d, Offset = %d, want 0 and 0", d.RecordsKept, d.Offset)
		}
		assertExplanation(t, d, textOfferInsideAnOpenTransactionKeepingNothing,
			len(parts[0]), 0, 0, d.Discard, 0)

		repair(t, dir)
		if got := survivorsAfterBoot(t, dir); got != d.RecordsKept {
			t.Fatalf("the cut left %d record(s); the report offered it as keeping %d",
				got, d.RecordsKept)
		}
	})

	t.Run("an offered cut that keeps nothing with no transaction open", func(t *testing.T) {
		// The separating control for the REASON the clause above gives. Here
		// the log's own first record is damaged, so replay reads nothing at
		// all and no transaction is open: kept == 0 for the other reason, and
		// "no intact prefix at all" is the true sentence. A rule that renders
		// either sentence on both stores passes one of these two rows and
		// fails the other.
		//
		// The foreign record behind the damage is what keeps this on the offer
		// path at all: with nothing intact back there replayLog's own search
		// comes back empty and the node discards the tail itself.
		dir := t.TempDir()
		raw := append(make([]byte, len(f.parts[0])), f.parts[1]...)
		if err := os.WriteFile(filepath.Join(dir, logName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		foreignRecordAt(t, dir, len(f.parts[0]))
		assertRefusesToOpen(t, dir, "the log's first record is a hole, foreign record behind")

		d := diagnose(t, dir)
		if !d.Repairable {
			t.Fatalf("no cut offered, so this row measures nothing: %s", d.Explanation)
		}
		if d.RecordsIntact != 0 || d.RecordsKept != 0 || d.Offset != 0 {
			t.Fatalf("RecordsIntact = %d, RecordsKept = %d, Offset = %d, want 0, 0 and 0 — "+
				"both counts must reach zero here for a DIFFERENT reason than in the row "+
				"above, or the pair separates nothing",
				d.RecordsIntact, d.RecordsKept, d.Offset)
		}
		assertExplanation(t, d, textOfferOutsideAnyTransactionKeepingNothing, 0, d.Discard, 0)

		repair(t, dir)
		if got := survivorsAfterBoot(t, dir); got != d.RecordsKept {
			t.Fatalf("the cut left %d record(s); the report offered it as keeping %d",
				got, d.RecordsKept)
		}
	})

	t.Run("a boot that discards an open transaction", func(t *testing.T) {
		// No cut is offered here — Open does it — but the report is the same
		// instrument telling the operator what the boot costs, and it named
		// the same wrong number.
		dir := writeClassLog(t, f, classGroupParts-1, 2)
		d := diagnose(t, dir)
		if d.Damaged || d.Repairable {
			t.Fatalf("Damaged = %v, Repairable = %v, want false and false: %s",
				d.Damaged, d.Repairable, d.Explanation)
		}
		if d.RecordsIntact != 3 {
			t.Fatalf("RecordsIntact = %d, want 3 — the two counts must differ here",
				d.RecordsIntact)
		}
		assertExplanation(t, d, textBootDiscardsAnOpenTransaction, openerAt, 1, 1)
		if got := survivorsAfterBoot(t, dir); got != 1 {
			t.Fatalf("the boot left %d record(s); the report said 1", got)
		}
	})

	t.Run("a boot that discards an unreadable tail", func(t *testing.T) {
		// The separating control for the boot report: same branch, no group
		// open, so the count is what replay read.
		c := buildCommitChain(t, 4)
		dir := writeChain(t, c, map[int]func([]byte){3: zeroAll})
		d := diagnose(t, dir)
		if d.Damaged || d.Repairable {
			t.Fatalf("Damaged = %v, Repairable = %v, want false and false: %s",
				d.Damaged, d.Repairable, d.Explanation)
		}
		assertExplanation(t, d, textBootDiscardsAnUnreadableTail,
			len(c.records[3]), c.offsetOf(3), 3)
		if got := survivorsAfterBoot(t, dir); got != 3 {
			t.Fatalf("the boot left %d record(s); the report said 3", got)
		}
	})

	t.Run("a boot that discards a proven short write", func(t *testing.T) {
		// The third region shape, and it is here because nothing else in
		// this file builds one. Every other store above damages a record in
		// place, so `selfHealing := status == decodeTorn` — the branch that
		// skips the search entirely on a proven short write — had no
		// separating input before this store existed: replacing that initialiser with
		// `false` left the whole repair suite green while turning the
		// commonest damage there is, a half-written last record, from
		// "start the node" into an irreversible deletion behind a prompt.
		c := buildCommitChain(t, 4)
		dir := writeChain(t, c, nil)
		torn := int64(c.offsetOf(3) + 40)
		if err := os.Truncate(filepath.Join(dir, logName), torn); err != nil {
			t.Fatal(err)
		}
		d := diagnose(t, dir)
		if d.Damaged || d.Repairable {
			t.Fatalf("Damaged = %v, Repairable = %v, want false and false — a proven short "+
				"write is what the node discards on its own: %s",
				d.Damaged, d.Repairable, d.Explanation)
		}
		assertExplanation(t, d, textBootDiscardsAnUnreadableTail, 40, c.offsetOf(3), 3)
		if got := survivorsAfterBoot(t, dir); got != 3 {
			t.Fatalf("the boot left %d record(s); the report said 3", got)
		}
	})

	t.Run("a log that ends on a part boundary inside an open transaction", func(t *testing.T) {
		// The third report that counts, reached when the log ends exactly
		// where a part ends: nothing is unreadable at all, and the whole
		// transaction still goes.
		dir := writeClassLog(t, f, classGroupParts-1)
		d := diagnose(t, dir)
		if d.Damaged || d.Repairable {
			t.Fatalf("Damaged = %v, Repairable = %v, want false and false: %s",
				d.Damaged, d.Repairable, d.Explanation)
		}
		if d.RecordsIntact != 4 {
			t.Fatalf("RecordsIntact = %d, want 4 — the two counts must differ here",
				d.RecordsIntact)
		}
		assertExplanation(t, d, textLogEndsInsideAnOpenTransaction, 1, 1)
		if got := survivorsAfterBoot(t, dir); got != 1 {
			t.Fatalf("the boot left %d record(s); the report said 1", got)
		}
	})
}

// assertTheTwoStoresDifferOnlyInTheCommitRecord is the precondition that makes
// every row below a LOSS rather than a discard: the commit record occupies its
// slot in the log, so the writer wrote it, so CommitGroup's barrier had
// already returned and the transaction was reported committed. The store with
// the same interior hole and no second one is the same length and differs.
func assertTheTwoStoresDifferOnlyInTheCommitRecord(t *testing.T, damaged, full string) {
	t.Helper()
	a, err := os.ReadFile(filepath.Join(damaged, logName))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(full, logName))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) || bytes.Equal(a, b) {
		t.Fatalf("the two stores are %d and %d bytes and equal = %v — they no longer "+
			"differ in exactly the commit record's bytes", len(a), len(b), bytes.Equal(a, b))
	}
}

// TestAGroupThatLosesAnInteriorPartAndItsCommitRecordIsNotDiscardedOnBoot is
// the boot-side half of the silent discard, and it closes by WIRING rather than
// by new evidence.
//
// Its sibling is about `repair` offering a cut over a committed transaction. The same
// absence of evidence was read the same way one function earlier, by
// replayLog's own search, and there the answer was not an offer behind a
// yes/no prompt: the node booted, discarded the transaction, and said nothing.
// `repair` run against the same store said "Nothing to repair — start the
// node", which is the most confident sentence this instrument has.
//
// The mechanism is that sibling's exactly. CommitGroup fsyncs the parts before it
// writes the commit record, so once that record lands the transaction has been
// reported committed. Hole an interior part AND the commit record and the
// surviving parts are dismissed as members of an open group, the search
// comes back empty, and replay reads "no evidence behind the damage" as
// "nothing back there was committed".
//
// WHAT WAS MISSING WAS THE CONSULT, NOT THE EVIDENCE, and that is what makes
// this half closable at all. The damaged record carries sequence 2 and its
// successor, sequence 3, survives intact and in place, so successorRunEnd
// finds the run, and the commit record's slot one frame past it decodes
// decodeHeaderUntrusted rather than decodeTorn — exactly the condition the
// commit-slot guard added, on a path that never asked it. replayLog now asks, with the
// same function and the same budget, so the two readers cannot disagree about
// the same bytes.
//
// The hole-2 row of this shape is NOT here, because it is held open by the
// evidence and not by the wiring — see
// TestAGroupWhoseCommitRecordSlotHasNoAnchorIsStillDiscardedOnBoot.
//
// Nothing is deleted by the refusal, and that is asserted rather than assumed:
// a refusal that truncated first would be the failure this whole file exists
// to stop, arrived at from the other side.
func TestAGroupThatLosesAnInteriorPartAndItsCommitRecordIsNotDiscardedOnBoot(t *testing.T) {
	f := buildClassFixture(t)
	dir := writeClassLogCommitted(t, f, classGroupParts, 1, classGroupParts-1)
	assertTheTwoStoresDifferOnlyInTheCommitRecord(t,
		dir, writeClassLogCommitted(t, f, classGroupParts, 1))

	before, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}

	assertRefuses(t, dir, "an interior part and the commit record are both holes")

	after, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the log was rewritten during the refused Open: %d byte(s) before, %d after",
			len(before), len(after))
	}

	// And the instrument an operator runs next must agree with the node,
	// because disagreeing about these exact bytes is the defect.
	d := diagnose(t, dir)
	if !d.Damaged || d.Repairable {
		t.Fatalf("repair says Damaged=%v Repairable=%v about a store Open refuses: %s",
			d.Damaged, d.Repairable, d.Explanation)
	}
	if !strings.Contains(d.Explanation, "was reported committed") {
		t.Fatalf("repair refused for some other reason than this one: %s", d.Explanation)
	}

	// The control that makes the refusal a discrimination: the same bytes with
	// nothing ever reported committed must still boot and discard, or a node
	// stops starting after an ordinary crash.
	abandoned := writeClassLog(t, f, classGroupParts, 1, classGroupParts-1)
	raw, err := os.ReadFile(filepath.Join(abandoned, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, raw) {
		t.Fatal("the two histories no longer share a log")
	}
	assertOpensWithOnlyTheCommittedRecord(t, abandoned)
}

// TestAGroupWhoseCommitRecordSlotHasNoAnchorIsRefusedOnBoot is the silent
// discard's second half, AND THIS TEST'S PREVIOUS REVISION PINNED TODAY'S WRONG
// ANSWER ON PURPOSE. It was named ...IsStillDiscardedOnBoot and it asserted
// that the node booted, discarded a transaction it had reported committed, and
// said nothing. Its own comment said what would have to happen for it to be
// rewritten as a refusal. The commit sidecar is what made that possible, and
// this is the rewrite.
//
// Hole the part at expectedSeq+1 as well — here, the group's part 2 together
// with its commit record — and no surviving record anywhere in the log carries
// the damaged record's own sequence successor. Nothing local locates the commit
// record's frame, and the bytes that would answer the question are inside a
// record whose declared length failed its own checksum. That is why this row,
// alone among the two, was never reachable by any discriminator reading the
// log, and the owner's disposition split the two rows on exactly that.
//
// The two stores are byte-identical — a group whose interior part was zeroed
// and whose commit record was never written, and one whose interior part AND
// commit record were zeroed after the barrier returned. Opposite correct
// answers, one set of bytes, and the sidecar is the only thing that differs.
//
// The control below is the half that must not move. The second door's shape
// keeps booting: refusing whenever the region holds unreadable bytes would
// close this row and deny a boot after an ordinary crash, and the whole
// remainder of the log is a legal reading of the damaged record's own payload.
func TestAGroupWhoseCommitRecordSlotHasNoAnchorIsRefusedOnBoot(t *testing.T) {
	f := buildClassFixture(t)
	committed := writeClassLogCommitted(t, f, classGroupParts, 2, classGroupParts-1)
	abandoned := writeClassLog(t, f, classGroupParts, 2, classGroupParts-1)

	a, err := os.ReadFile(filepath.Join(committed, logName))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(abandoned, logName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("the two histories left different logs (%d and %d bytes), so the opposite "+
			"answers below are not attributable to the sidecar", len(a), len(b))
	}

	// The committed history: refuse rather than boot, and `repair` must say the
	// same thing rather than "Nothing to repair — start the node", which is the
	// sentence the silent discard is about.
	assertRefuses(t, committed, "an interior part and the commit record of a committed "+
		"transaction are both holes, with no anchor anywhere")
	d := diagnose(t, committed)
	if !d.Damaged || d.Repairable {
		t.Fatalf("repair says Damaged=%v Repairable=%v about a store Open refuses: %s",
			d.Damaged, d.Repairable, d.Explanation)
	}

	// The abandoned history: boot, discard, and keep the record in front.
	if got := survivorsAfterBoot(t, abandoned); got != 1 {
		t.Fatalf("survivors = %d, want 1 — nothing was ever reported committed here, so the "+
			"node must start and discard the abandoned transaction", got)
	}
	s, err := Open(abandoned, Options{})
	if err != nil {
		t.Fatalf("an ordinary crash denied a boot: %v", err)
	}
	defer s.Close()
	assertGeneration(t, s, classGroupParts, "")
}

// TestAnOrdinaryCrashInAGroupTooLongForItsSurvivingRunStillBoots is the
// liveness half of the boot-path refusal, and it is here because the first
// revision of that refusal failed it.
//
// A NODE THAT WILL NOT START AFTER AN ORDINARY CRASH IS LAUNCH.md §3 CASE 4,
// and the store below is an ordinary crash: no media fault, no forgery,
// nothing ever reported committed. CommitGroup writes parts 0..n-2 before
// syncLocked, and n is unbounded in production because node/chain's
// batchGroup.rollIfNeeded splits a reorg on mutationBudget. Five parts, the
// crash lands before the barrier so the commit record (sequence 5) is never
// written at all, and writeback leaves holes at parts 1 and 3.
//
// The frame one past the surviving run is then part 3's slot, not the commit
// record's, and the sentence the refusal was built on — "the record that would
// have committed that transaction belongs in those bytes" — is simply false
// about it. It is the same unsupported assertion this change removes from the
// consent screen, sign flipped, and it reinstates the property that a
// dismissal exists to hold: recoverability of an abandoned transaction as a
// function of writeback order.
//
// THE SEPARATION IS ONE VARIABLE WIDE, and it is asserted rather than
// arranged. The four-part store with the same holes must still refuse, and the
// two logs are the same length and differ only in the countdowns of the
// records that survived — nothing else in either file moves.
func TestAnOrdinaryCrashInAGroupTooLongForItsSurvivingRunStillBoots(t *testing.T) {
	// Parts 0..3 of a five-part group reached the disk; part 4 is the commit
	// record and never did.
	crashed := writeClassLog(t, buildGroupFixture(t, classGroupParts+1), classGroupParts, 1,
		classGroupParts-1)
	refusing := writeClassLog(t, buildClassFixture(t), classGroupParts, 1, classGroupParts-1)

	a, err := os.ReadFile(filepath.Join(crashed, logName))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(refusing, logName))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) || bytes.Equal(a, b) {
		t.Fatalf("the crashed and the refusing store are %d and %d bytes and equal = %v — "+
			"they no longer differ in exactly the surviving parts' countdowns",
			len(a), len(b), bytes.Equal(a, b))
	}

	// The control: the same holes at the same offsets, under a history in which
	// the transaction WAS reported committed, must still refuse. Without it the
	// assertion below would pass for a boot path that had stopped consulting the
	// out-of-band record at all.
	//
	// This control used to be the four-part store, on the grounds that its
	// surviving run reached the commit record's slot and the five-part store's
	// did not. That distinction is gone with the machinery that drew it, and
	// the control is now the one that always mattered: what the store reported
	// committed, not how many frames a run walked.
	committedFive := writeClassLogCommitted(t, buildGroupFixture(t, classGroupParts+1),
		classGroupParts, 1, classGroupParts-1)
	assertRefuses(t, committedFive, "the same crash shape, but the transaction was reported "+
		"committed before the damage")

	// `repair` is asked first, while the damaged bytes are still on disk: the
	// two readers disagreeing about these bytes is the defect this whole
	// change is, and after a boot there would be nothing left to disagree on.
	if d := diagnose(t, crashed); d.Damaged {
		t.Fatalf("repair calls a store the node boots damaged: %s", d.Explanation)
	}

	s, err := Open(crashed, Options{})
	if err != nil {
		t.Fatalf("Open refused a store no fault and no attacker produced: %v", err)
	}
	defer s.Close()
	if v, ok := s.Get([]byte("committed-key")); !ok || string(v) != "committed-value" {
		t.Fatalf("the committed record was lost (present=%v value=%q) — the log was truncated "+
			"too far, which is the interior-corruption failure, not this one", ok, v)
	}
	assertGeneration(t, s, classGroupParts+1, "")
	if s.nextSeq != 1 {
		t.Fatalf("nextSeq = %d, want 1 — the abandoned group's bytes were not cut away",
			s.nextSeq)
	}
}

// TestTheBootPathRefusalTurnsOnEachOfItsTermsSeparately is why the row above
// is a claim about a rule rather than a claim about one fixture.
//
// THE CONJUNCTION IS NOW TWO TERMS AND IT USED TO BE FIVE, which is the whole
// point of the sidecar: the five were an attempt to infer, from the log's own bytes,
// whether a commit record had ever been written, and no such inference can be
// right, because the two histories leave identical bytes. The two that remain
// are read from a durable answer instead:
//
//	the sidecar VERIFIES and records a commit — falsified three ways below:
//	an absent sidecar, one whose slots do not verify, and one that verifies and
//	says nothing was committed in this log generation;
//
//	its highest committed sequence is AT OR ABOVE the first sequence the cut
//	would remove — falsified by a sidecar naming only records in front of the
//	damage.
//
// Each falsifying row must come back to "boot and discard", because a table
// that only ever showed the refusal firing would pass for a boot path that
// refuses every damaged group — which is the failure the membership dismissal
// exists to prevent, where recoverability of an abandoned transaction depended
// on which parts writeback happened to flush. The last two rows are the
// pre-existing log-based refusals, kept here so the two rules stay separable:
// they refuse for their OWN reasons and say so, and a sidecar that had quietly
// become the only rule would fail them.
func TestTheBootPathRefusalTurnsOnEachOfItsTermsSeparately(t *testing.T) {
	f := buildClassFixture(t)

	// The offsets of the class fixture's records, derived rather than typed.
	offsetOf := func(part int) int {
		off := len(f.committed)
		for i := 0; i < part; i++ {
			off += len(f.parts[i])
		}
		return off
	}

	rewrite := func(t *testing.T, dir string, fn func(raw []byte) []byte) string {
		t.Helper()
		path := filepath.Join(dir, logName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, fn(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	for _, row := range []struct {
		name   string
		build  func(t *testing.T) string
		refuse string // the phrase the refusal must carry; "" means it must boot
	}{
		{
			name: "both terms hold",
			build: func(t *testing.T) string {
				return writeClassLogCommitted(t, f, classGroupParts, 1, classGroupParts-1)
			},
			refuse: "was reported committed",
		},
		{
			name: "the sidecar is absent",
			build: func(t *testing.T) string {
				dir := writeClassLogCommitted(t, f, classGroupParts, 1, classGroupParts-1)
				if err := os.Remove(filepath.Join(dir, commitsName)); err != nil {
					t.Fatal(err)
				}
				return dir
			},
		},
		{
			// Only the CHECKSUMS are broken, so the magic and the version still
			// read correctly and the sequence is still legible. A rule that
			// stopped verifying the slot would find a perfectly plausible
			// number here and refuse; the row exists to separate that term from
			// the magic check, which a wholesale corruption would also trip.
			name: "neither slot verifies",
			build: func(t *testing.T) string {
				dir := writeClassLogCommitted(t, f, classGroupParts, 1, classGroupParts-1)
				path := filepath.Join(dir, commitsName)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, off := range []int{0, commitSlotStride} {
					raw[off+commitCRCOff] ^= 0xFF
				}
				for _, off := range []int{0, commitSlotStride} {
					if _, _, ok := decodeCommitSlot(raw[off : off+commitSlotLen]); ok {
						t.Fatalf("slot at %d still verifies, so this row is not the one it "+
							"claims to be", off)
					}
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				return dir
			},
		},
		{
			name: "the sidecar verifies and records nothing committed",
			build: func(t *testing.T) string {
				dir := writeClassLogCommitted(t, f, classGroupParts, 1, classGroupParts-1)
				writeSidecar(t, dir, 0)
				return dir
			},
		},
		{
			name: "the sidecar names only records in front of the damage",
			build: func(t *testing.T) string {
				// The cut removes sequence 1 onward, so a sidecar naming
				// sequence 0 is strictly below it and must not withhold.
				return writeClassLog(t, f, classGroupParts, 1, classGroupParts-1)
			},
		},
		{
			name: "a surviving part claims to end a transaction",
			build: func(t *testing.T) string {
				dir := writeClassLog(t, f, classGroupParts, 1, classGroupParts-1)
				return rewrite(t, dir, func(raw []byte) []byte {
					setMore(t, raw, offsetOf(2), 0)
					return raw
				})
			},
			refuse: "record-shaped bytes inside this one's own payload",
		},
		{
			name: "the log alone refuses a well-formed record out of sequence",
			build: func(t *testing.T) string {
				dir := writeClassLog(t, f, classGroupParts, 1, classGroupParts-1)
				return rewrite(t, dir, func(raw []byte) []byte {
					copy(raw[offsetOf(1):], f.committed)
					return raw
				})
			},
			refuse: "refusing to guess which is right",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := row.build(t)
			if row.refuse == "" {
				if got := survivorsAfterBoot(t, dir); got != 1 {
					t.Fatalf("survivors = %d, want 1 — this row falsifies one term of "+
						"the refusal and must therefore boot and discard", got)
				}
				return
			}
			s, err := Open(dir, Options{})
			if err == nil {
				s.Close()
				t.Fatal("opened, want a refusal")
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("refused with %v, want ErrCorrupt", err)
			}
			if !strings.Contains(err.Error(), row.refuse) {
				t.Fatalf("refused for the wrong reason.\n got: %v\nwant a refusal carrying: %s",
					err, row.refuse)
			}
		})
	}
}
