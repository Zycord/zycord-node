package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The escape suite: the payload escape, and the format bump that carries it.
//
// What is pinned here is the property the fix rests on and NOT a claim that the
// forgery is impossible. escapePayload's doc carries the derivation; the short
// version is that the plant's free, universal 32-byte constant becomes an offline
// preimage grind, because the record's own unescaped header still holds a
// CRC32 field an attacker can force to the magic. Payable became not payable.
// payloadplant_reach_test.go drives both halves, including the one that still
// works.

// escapeCorpus is the input side of the invariant, and it is built to contain
// the shapes a naive stuffer gets wrong rather than the shapes that are easy to
// write. Named rather than generated so a failure says which shape broke.
func escapeCorpus() []struct {
	name string
	in   []byte
} {
	magic := recordMagic[:]
	esc := []byte{recordEscape}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	corpus := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"no magic bytes at all", []byte("an ordinary block body")},
		{"the magic alone", append([]byte(nil), magic...)},
		{"the magic repeated", bytes.Repeat(magic, 64)},
		{"a full forged terminal record", forgeTerminalRecord(1 << 40)},
		// The overlap case. A scanner that finds "CAP" and then jumps four
		// bytes steps over the second run entirely, so this is the shape that
		// separates walking the output from walking the input.
		{"overlapping runs", cat([]byte("CAPCAP"), []byte{FormatVersion})},
		{"CAP followed by something else", []byte("CAPCAPQ")},
		{"trailing CAP with nothing after it", []byte("body then CAP")},
		{"CAP then the version at the very end", cat([]byte("CAP"), []byte{FormatVersion})},
		// The escape byte itself has to be escaped after a CAP, or the
		// reverse direction cannot tell a literal from a stuffing byte.
		{"CAP then the escape byte", cat([]byte("CAP"), esc)},
		{"CAP then escape then version", cat([]byte("CAP"), esc, []byte{FormatVersion})},
		{"CAP then two escape bytes", cat([]byte("CAP"), esc, esc)},
		{"an escape byte with no CAP in front", cat([]byte("xx"), esc, []byte{FormatVersion})},
		{"magic buried in a longer value", cat(bytes.Repeat([]byte{0}, 40), magic, bytes.Repeat([]byte{0xAB}, 40))},
		{"every byte value in order", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return cat([]byte("CAP"), b, []byte("CAP"), b)
		}()},
	}

	// Random inputs drawn from a tiny alphabet, so the magic and the escape
	// byte occur densely instead of never. A uniform random byte string is
	// worthless here: it contains the magic with probability ~2^-32 per
	// position and would make this a test of nothing.
	alphabet := []byte{'C', 'A', 'P', FormatVersion, recordEscape, 'Q'}
	rng := rand.New(rand.NewSource(276))
	for i := 0; i < 64; i++ {
		b := make([]byte, 1+rng.Intn(200))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		corpus = append(corpus, struct {
			name string
			in   []byte
		}{fmt.Sprintf("dense random %d", i), b})
	}
	return corpus
}

// TestNoPayloadThisWriterProducesContainsTheRecordMagic is the invariant that
// closes the payload-plant carrier, and the counters below are the reason it is
// an instrument rather than a green light.
//
// findNextRecordWithin anchors on bytes.Index(raw, recordMagic). If no payload
// contains that sequence, no plant inside a payload can be found, and the
// 32-byte constant that satisfied every store forever is not in the log.
//
// Direction, declared before the run: the corpus MUST contain the magic before
// escaping — if it does not, the invariant below is vacuous and the whole file
// proves nothing — and MUST NOT contain it after. The test fails loudly on
// either, and reports both counts on success, so "all clear" is a number and
// not silence.
func TestNoPayloadThisWriterProducesContainsTheRecordMagic(t *testing.T) {
	var carriedMagic, expanded int
	for _, tc := range escapeCorpus() {
		out := escapePayload(tc.in)
		if bytes.Contains(tc.in, recordMagic[:]) {
			carriedMagic++
		}
		if len(out) != len(tc.in) {
			expanded++
		}
		if i := bytes.Index(out, recordMagic[:]); i >= 0 {
			t.Fatalf("%s: the escaped payload still contains recordMagic at offset %d\n"+
				"in:  %x\nout: %x", tc.name, i, tc.in, out)
		}
		back, ok := unescapePayload(out)
		if !ok {
			t.Fatalf("%s: unescapePayload rejected what escapePayload produced", tc.name)
		}
		if !bytes.Equal(back, tc.in) {
			t.Fatalf("%s: round trip lost the payload\nin:   %x\nback: %x", tc.name, tc.in, back)
		}
	}
	if carriedMagic == 0 {
		t.Fatalf("no corpus case contained recordMagic before escaping, so the invariant above " +
			"is vacuous — the corpus, not the escape, is what this run measured")
	}
	if expanded == 0 {
		t.Fatalf("the escape never stuffed a byte on any of %d cases, so the reverse direction "+
			"was never exercised either", len(escapeCorpus()))
	}
	t.Logf("escape invariant held: %d of %d cases carried recordMagic before escaping, "+
		"%d were expanded, 0 contained it after", carriedMagic, len(escapeCorpus()), expanded)
}

// TestTheEscapeByteCannotStandWhereTheMagicStands is the one-line invariant the
// whole scheme rests on, and it has no other home.
//
// If recordEscape were one of the magic's own four bytes, a stuffing byte could
// complete the magic it was inserted to break, and the reverse direction could
// not tell a stuffing byte from a literal. Both constants are edited by hand,
// in two different places, for unrelated reasons — FormatVersion moves whenever
// the on-disk layout changes — so the pairing is exactly the kind that goes
// wrong quietly.
func TestTheEscapeByteCannotStandWhereTheMagicStands(t *testing.T) {
	for i, b := range recordMagic {
		if recordEscape == b {
			t.Fatalf("recordEscape (%#x) is recordMagic[%d]; a stuffing byte that can stand "+
				"where a magic byte stands breaks the escape in both directions", recordEscape, i)
		}
	}
	// The version byte is recordMagic[3], so the loop above already covers it.
	// Stated separately because FormatVersion is what moves: the next bump has
	// to pass this row, and 0xFF is the reason it will.
	if recordEscape == FormatVersion {
		t.Fatalf("recordEscape (%#x) equals FormatVersion", recordEscape)
	}
}

// TestTheEscapeExpansionIsBoundedAtFiveQuarters pins the number node/chain's
// mutationBudget is derived against, and it pins it as a REACHED bound rather
// than a claimed maximum (rule 21).
//
// The derivation: a stuffing byte is emitted only when the output already ends
// in 'C', 'A', 'P' and the next input byte is FormatVersion or recordEscape.
// Those four input bytes are distinct positions, and none of them can be
// charged to a second stuffing, because the escaped byte is never one of 'C',
// 'A', 'P'. So stuffed <= n/4.
//
// The existential is the half that matters and it is constructed: a payload of
// repeated recordMagic reaches exactly n/4, so the bound is tight and a caller
// budgeting against it is not leaving room it will never need. Anything
// claiming a smaller factor has to beat this fixture.
func TestTheEscapeExpansionIsBoundedAtFiveQuarters(t *testing.T) {
	worst := bytes.Repeat(recordMagic[:], 4096)
	got := len(escapePayload(worst))
	want := len(worst) + len(worst)/4
	if got != want {
		t.Fatalf("a payload of repeated recordMagic escaped to %d bytes, want exactly %d "+
			"(5/4 of %d) — the bound node/chain budgets against is not the bound this "+
			"code implements", got, want, len(worst))
	}

	for _, tc := range escapeCorpus() {
		out := escapePayload(tc.in)
		if len(out) > len(tc.in)+len(tc.in)/4 {
			t.Fatalf("%s: %d bytes escaped to %d, past the 5/4 bound",
				tc.name, len(tc.in), len(out))
		}
	}
	t.Logf("expansion bound 5/4 reached exactly at %d bytes and never exceeded across the corpus",
		len(worst))
}

// TestUnescapeAcceptsOnlyTheFormTheEscapeProduces keeps the on-disk form of a
// payload unique.
//
// Non-canonical shapes are not a hypothetical: the record checksum covers the
// escaped bytes, and anyone who can compute a CRC32 can author a payload that
// is a valid record and is not in escapePayload's image. Interpreting one
// would mean two byte strings decoding to the same batch, which is a second way
// to write a record — exactly the kind of second door this package spends its
// whole design closing. They are refused instead.
//
// Direction: each row below MUST be rejected. A row that round-trips means the
// reverse direction is guessing.
func TestUnescapeAcceptsOnlyTheFormTheEscapeProduces(t *testing.T) {
	esc := recordEscape
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"a stuffing byte with nothing after it", []byte{'C', 'A', 'P', esc}},
		{"a stuffing byte before a byte that needed no escape", []byte{'C', 'A', 'P', esc, 'Q'}},
		{"a stuffing byte before a zero", []byte{'C', 'A', 'P', esc, 0}},
		{"the same, buried in a longer payload", []byte{1, 2, 3, 'C', 'A', 'P', esc, 'Z', 9}},
	} {
		if out, ok := unescapePayload(tc.in); ok {
			t.Fatalf("%s: accepted a payload escapePayload cannot produce, decoding %x to %x",
				tc.name, tc.in, out)
		}
	}

	// Anti-vacuity: the neighbouring shapes that ARE in the image must be
	// accepted, or the four rows above would pass for a function that rejects
	// everything.
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"an escaped version byte", []byte{'C', 'A', 'P', esc, FormatVersion}},
		{"an escaped escape byte", []byte{'C', 'A', 'P', esc, esc}},
		{"a literal escape byte not after CAP", []byte{'X', esc, 'Q'}},
	} {
		if _, ok := unescapePayload(tc.in); !ok {
			t.Fatalf("%s: rejected a payload escapePayload does produce (%x)", tc.name, tc.in)
		}
	}
}

// TestAPayloadOutsideTheEscapesImageIsPayloadBadAndNotARecord walks the
// rejection above out to the classification replayLog actually reads.
//
// The point is which decodeStatus it lands in. decodePayloadBad means "the
// frame is trustworthy, this record's contents are not", so the reader scans
// forward from the record's own end and never inside it. A non-canonical
// payload getting any other classification — decodeOK above all — would put an
// attacker-authored batch into the store's live map.
func TestAPayloadOutsideTheEscapesImageIsPayloadBadAndNotARecord(t *testing.T) {
	// A payload the writer would never emit: a stuffing byte before a byte
	// that needed no escaping.
	payload := []byte{opPut, 3, 0, 0, 0, 'C', 'A', 'P', recordEscape, 'Q', 0, 0, 0, 0}
	rec, err := frameRecord(payload, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, n, st := decodeRecord(rec)
	if st != decodePayloadBad {
		t.Fatalf("a payload outside the escape's image decoded as %v, want decodePayloadBad — "+
			"a reader that accepts it is accepting a batch this writer cannot produce", st)
	}
	if n != len(rec) {
		t.Fatalf("n = %d, want the full framed length %d: decodePayloadBad has to carry the "+
			"record's extent or the forward scan starts in the wrong place", n, len(rec))
	}
}

// TestAForgedRecordPlantedInAValueDoesNotSurviveEncodeRecord is the end-to-end
// half, through the one path a remote party actually reaches.
//
// node/chain writes an accepted block's own encoding into a value verbatim, so
// a value is where the plant's 32 bytes arrive. After the escape those bytes are
// still delivered — the batch that comes back out is byte-identical — and they
// are no longer findable by the scan's anchor.
func TestAForgedRecordPlantedInAValueDoesNotSurviveEncodeRecord(t *testing.T) {
	plant := forgeTerminalRecord(1<<63 - 1)
	value := make([]byte, 128)
	copy(value[48:], plant)

	b := &Batch{}
	b.Put([]byte("block-body"), value)
	rec, err := encodeRecord(b, 3, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The header is the record's own and starts with the magic; everything
	// past it must not.
	if i := bytes.Index(rec[recordHeaderLen:], recordMagic[:]); i >= 0 {
		t.Fatalf("the plant survived encodeRecord at payload offset %d", i)
	}
	// Anti-vacuity, and it is the row that separates "the escape worked" from
	// "the plant was never there": the plant's own tail, which carries no
	// magic, must still be present verbatim.
	if !bytes.Contains(rec, plant[4:]) {
		t.Fatalf("the plant's tail is not in the record either, so this row would pass for " +
			"a writer that dropped the value entirely")
	}
	if len(rec) <= recordHeaderLen+len(value)+1+4+len("block-body")+4 {
		t.Fatalf("the record did not grow, so no byte was stuffed and the row measured nothing")
	}

	back, seq, more, n, st := decodeRecord(rec)
	if st != decodeOK || seq != 3 || more != 0 || n != len(rec) {
		t.Fatalf("the record does not decode: st=%v seq=%d more=%d n=%d", st, seq, more, n)
	}
	if len(back.mutations) != 1 || !bytes.Equal(back.mutations[0].value, value) {
		t.Fatalf("the value did not survive the round trip; the escape has to be invisible " +
			"to the caller, not merely reversible in principle")
	}

	// And the scan, which is the instrument the plant defeated, finds nothing.
	if at, res := findNextRecord(rec[recordHeaderLen:], 0, 0); res != scanNothingFound {
		t.Fatalf("the forward scan found a record at payload offset %d (%v); the plant is "+
			"still reachable through the anchor", at, res)
	}
}

// TestAStoreInThePreviousFormatIsRefusedByVersionAndNotReportedAsCorruption is
// the format bump's operator-facing half, and the assertion that matters is the
// one about the boolean rather than the one about the prose.
//
// The bump to format 4 makes every store this project has ever written a
// previous-format store. What such a store must get is a version refusal:
// Open returns ErrFormat naming both numbers, and `zycordd repair` neither
// offers a cut nor prescribes the destructive remedy. Before this unit the
// Explanation said "that is not damage" while Damaged was true, and
// cmd/zycordd/repair.go reads the field, so the CLI would have answered a
// version mismatch with "NOT REPAIRABLE ... Resync this store from the
// network" — reporting an intact directory as corruption, over a number.
func TestAStoreInThePreviousFormatIsRefusedByVersionAndNotReportedAsCorruption(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, logName), previousFormatLog(t), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Open(dir, Options{})
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("Open returned %v, want ErrFormat: a build that half-reads a store it does "+
			"not understand is corruption by another route", err)
	}
	if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "3") ||
		!strings.Contains(err.Error(), fmt.Sprint(FormatVersion)) {
		t.Fatalf("the refusal does not name both versions (%v); an operator cannot tell which "+
			"binary to run from it", err)
	}
	if errors.Is(err, ErrCorrupt) {
		t.Fatalf("a previous-format store was refused as corruption: %v", err)
	}

	d := diagnose(t, dir)
	if d.Damaged {
		t.Fatalf("Diagnose reports a previous-format log as damaged, so `zycordd repair` prints "+
			"NOT REPAIRABLE and tells the operator to resync a directory whose bytes are "+
			"intact: %s", d.Explanation)
	}
	if d.Repairable {
		t.Fatalf("a cut was offered over a version mismatch: %s", d.Explanation)
	}
	if strings.Contains(d.Explanation, "resync") {
		t.Fatalf("the finding sends the operator to a resync over a version number: %s",
			d.Explanation)
	}
	if !strings.Contains(d.Explanation, "run the matching binary") {
		t.Fatalf("the finding does not send the operator to the right binary: %s", d.Explanation)
	}

	// Anti-vacuity for the pair of assertions above: a genuinely destroyed log
	// in this same directory shape must still be reported as damage, or the
	// rows above would pass for a Diagnose that calls nothing damaged.
	broken := writeChain(t, buildCommitChain(t, 3), map[int]func([]byte){1: zeroAll})
	if d := diagnose(t, broken); !d.Damaged {
		t.Fatalf("interior damage was not reported as damage, so the version rows above "+
			"measured nothing: %s", d.Explanation)
	}
}

// previousFormatLog builds what a version-3 build wrote: the same layout, the
// same checksum arithmetic, an unescaped payload, and a 3 in the magic's last
// byte. Built here rather than checked in as a binary fixture so it stays
// legible, and framed by hand because this build's writer cannot emit a
// version it does not carry.
func previousFormatLog(t *testing.T) []byte {
	t.Helper()
	b := &Batch{}
	b.Put([]byte("key-0"), []byte("value-0"))
	payload, err := encodeBatchPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, recordHeaderLen, recordHeaderLen+len(payload))
	copy(rec[recordMagicOff:], recordMagic[:])
	rec[3] = FormatVersion - 1
	binary.LittleEndian.PutUint64(rec[recordSeqOff:], 0)
	binary.LittleEndian.PutUint32(rec[recordMoreOff:], 0)
	binary.LittleEndian.PutUint64(rec[recordLenOff:], uint64(len(payload)))
	binary.LittleEndian.PutUint32(rec[recordHdrCRCOff:], crc32.ChecksumIEEE(rec[:recordHdrCRCOff]))
	h := crc32.NewIEEE()
	h.Write(rec[:recordCRCOff])
	h.Write(payload)
	binary.LittleEndian.PutUint32(rec[recordCRCOff:], h.Sum32())
	return append(rec, payload...)
}
