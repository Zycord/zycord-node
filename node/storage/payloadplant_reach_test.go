package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// The payload-plant suite: bytes shaped like a completed transaction, planted
// inside a crashed record's own payload by whoever authored the block, making
// recovery permanently unavailable.
//
// It began as that defect's PREMISE rather than its verdict, because the verdict
// had been re-argued six times while the premise was never measured.
// Two questions no test asked: can a party who authors nothing but the bytes of
// a value reach this state at all, and once reached, is the refusal an incident
// a later run clears or a terminal state for every local instrument. Measured:
// yes, and terminal.
//
// The payload escape answered it, and this file now carries the answer in both
// directions. The payload carrier is closed — the escape takes recordMagic out
// of every payload the writer emits, so the plant is not in the log to be
// found. The HEADER carrier is not, and
// TestTheRecordChecksumFieldIsAnUnescapedCarrier drives it, because the
// decision was recorded as pricing and a file that only showed the good half
// would let the next reader write "impossible".
//
// The rows that still need record-shaped bytes inside a payload frame them the
// way format version 3 did (see plantedTailStore's `escaped` parameter). That
// is what keeps the BEFORE column of the measurement available instead of
// leaving an AFTER column asserted against itself.
//
// forgeTerminalRecord is what makes the first question answerable in one
// place: a complete record in exactly recordHeaderLen bytes, carrying more == 0
// and a payload length of zero, so the record checksum covers the header and
// nothing else. Both checksums are unkeyed and both are computed here by the
// same arithmetic the writer uses, which is the property attack_test's setMore
// already relies on — the difference is that setMore edits a record this
// package wrote, and this builds one from nothing.
func forgeTerminalRecord(seq uint64) []byte {
	var b [recordHeaderLen]byte
	copy(b[recordMagicOff:], recordMagic[:])
	binary.LittleEndian.PutUint64(b[recordSeqOff:], seq)
	binary.LittleEndian.PutUint32(b[recordMoreOff:], 0)
	binary.LittleEndian.PutUint64(b[recordLenOff:], 0)
	binary.LittleEndian.PutUint32(b[recordHdrCRCOff:], crc32.ChecksumIEEE(b[:recordHdrCRCOff]))
	binary.LittleEndian.PutUint32(b[recordCRCOff:], crc32.ChecksumIEEE(b[:recordCRCOff]))
	return b[:]
}

// TestTheForgedSequenceIsBoundedOnlyFromBelow pins the cost of the forgery
// the defect is about, in the one dimension anybody has ever proposed pricing it in.
//
// findTerminalRecordWithin tests `seq >= minSeq` and nothing else, so a single
// sequence — the largest one — satisfies every store, at every log length,
// forever. That matters twice. It is why the plant needs no knowledge of the
// victim: the sequence a log has reached is the only per-store number in a
// record header, and this one does not have to be guessed. And it is why the
// obvious tightening is worth stating before someone reaches for it: an upper
// bound IS available and IS sound — the region begins at the damaged record,
// records tile it, and each is at least recordHeaderLen bytes, so a genuine
// record at region offset p carries at most minSeq + p/recordHeaderLen — but
// it prices the attack in bytes of payload rather than closing it, and it can
// only turn a refusal into an offer, which is the fatal direction of this
// package's two.
//
// So this row is a change detector on purpose. Adding the bound must fail it,
// and the author must then write down which sequences the bound excludes and
// why no genuine record can carry one.
func TestTheForgedSequenceIsBoundedOnlyFromBelow(t *testing.T) {
	bait := forgeTerminalRecord(math.MaxUint64)
	if len(bait) != recordHeaderLen {
		t.Fatalf("the forgery is %d bytes, not recordHeaderLen (%d)", len(bait), recordHeaderLen)
	}
	if _, _, _, n, st := decodeRecord(bait); st != decodeOK || n != recordHeaderLen {
		t.Fatalf("the forgery does not decode as a whole record on its own: %v, n=%d; "+
			"this row proves nothing about a scan if the scan would never accept it", st, n)
	}
	for _, minSeq := range []uint64{0, 1, 1 << 20, 1 << 40, math.MaxUint64 - 1, math.MaxUint64} {
		at, res := findTerminalRecordWithin(bait, minSeq, int64(len(bait)))
		if res != scanFound || at != 0 {
			t.Fatalf("with minSeq %d the scan reported (%d, %v); one sequence has to satisfy "+
				"every minSeq, or the plant is a guess and its cost is not what it says",
				minSeq, at, res)
		}
	}
}

// plantedTailStore builds the store the defect describes and nothing else: an intact
// prefix, then a final record whose value carries `plant`, then that record's
// header checksum broken the way a crash breaks it (breakHeader).
//
// The plant goes in a VALUE and never in a key, a header or a frame, because
// that is the whole reachability question. A value is the only part of a record
// that this package copies from a caller verbatim, and the caller above it
// copies it from the network: node/chain writes b.MarshalSSZ() for an accepted
// block, and the certificate fields inside it include ones no rule constrains.
//
// escaped says which of the two writers builds the carrier. True is the one
// this build has: encodeRecord, which escapes recordMagic out of the payload,
// so the plant arrives as bytes and not as a record. False frames the payload
// verbatim, which is what the version-3 writer did and what no writer here can
// do any more — it is how the fixtures below keep the BEFORE column of the
// escape's measurement instead of asserting the after column against itself.
func plantedTailStore(t *testing.T, plant []byte, escaped bool) (dir string, damagedAt int) {
	t.Helper()
	c := buildCommitChain(t, 3)
	// 64 bytes so the plant is strictly interior to the value it rides in:
	// a row where the plant were the whole value would also pass if the
	// scan only ever looked at value boundaries, which it does not.
	value := make([]byte, 64)
	copy(value[16:], plant)
	carrier := &Batch{}
	carrier.Put([]byte("block-body"), value)

	var rec []byte
	var err error
	if escaped {
		rec, err = encodeRecord(carrier, 3, 0)
	} else {
		var payload []byte
		if payload, err = encodeBatchPayload(carrier); err == nil {
			rec, err = frameRecord(payload, 3, 0)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	c.records = append(c.records, rec)
	return writeChain(t, c, map[int]func([]byte){3: breakHeader}), c.offsetOf(3)
}

// TestAPlantInsideAValueNoLongerReachesTheLog is the payload carrier closed,
// and the three rows are what make the close a measurement rather than an
// assertion.
//
// The defect: without the plant, this exact damage is one the node repairs by
// itself — the scan comes back empty, Diagnose reports Damaged == false and
// tells the operator to start the node. With 32 bytes moved into a value, and
// nothing else in the store changed, both instruments refused and the
// operator's route became a resync. 32 bytes, arriving on an ordinary
// certificate, cost the data directory of every node that later crashed.
//
// The rival hypothesis this test has to rule out is the one that makes a fix
// look real when it is not: *the store opens now because the fixture stopped
// planting anything.* Two rows exist to refute it. The BEFORE row frames the
// same value with the same plant through the version-3 writer — no escape —
// and it still refuses, so the fixture is intact and the refusal is still
// exactly one plant away. The AFTER row then asserts the plant's own bytes are
// still in the log, minus the magic, so the escape moved four bytes and did not
// drop the value.
//
// What this does NOT show is that a record-shaped run is unrepresentable. It is
// not: see TestTheRecordChecksumFieldIsAnUnescapedCarrier, which still finds
// one. The defect moved from a free universal constant to an offline preimage grind.
func TestAPlantInsideAValueNoLongerReachesTheLog(t *testing.T) {
	plant := forgeTerminalRecord(math.MaxUint64)

	// Control: the same crash, no plant. This is the self-healing tail the
	// armed rows are measured against.
	controlDir, controlAt := plantedTailStore(t, nil, true)
	assertRegionShape(t, controlDir, controlAt, decodeHeaderUntrusted)
	control := diagnose(t, controlDir)
	if control.Damaged || control.Repairable {
		t.Fatalf("the control store is not the self-healing tail this row needs it to be "+
			"(damaged=%v, repairable=%v), so the rows below separate nothing: %s",
			control.Damaged, control.Repairable, control.Explanation)
	}

	// Before: the plant framed verbatim, which is what every writer in this
	// package did up to format version 3. The defect, still reproducible on
	// demand — and required to be, or the row below is measuring a fixture
	// that stopped working rather than an escape that started.
	beforeDir, beforeAt := plantedTailStore(t, plant, false)
	assertRegionShape(t, beforeDir, beforeAt, decodeHeaderUntrusted)
	assertRefusesToOpen(t, beforeDir,
		"a terminal record framed verbatim inside the crashed tail's own value")
	if d := diagnose(t, beforeDir); !d.Damaged || d.Repairable {
		t.Fatalf("the unescaped store did not refuse (damaged=%v, repairable=%v), so this "+
			"fixture no longer reproduces the defect and the escape row proves nothing: %s",
			d.Damaged, d.Repairable, d.Explanation)
	}

	// After: the same plant, through this build's writer.
	dir, at := plantedTailStore(t, plant, true)
	assertRegionShape(t, dir, at, decodeHeaderUntrusted)

	// Read the log before any instrument touches it. A self-healing tail is
	// discarded by the first Open, so the bytes this row is about exist only
	// until then — reading afterwards would measure the truncation, not the
	// escape.
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: the plant is still delivered, all of it except the four
	// bytes the escape broke. Without this the rows below would pass for a
	// writer that silently dropped the value.
	if !bytes.Contains(raw, plant[4:]) {
		t.Fatal("the plant's tail is not in the log, so the store would open because the " +
			"value was lost rather than because the magic was escaped")
	}
	// And the log's only occurrences of the magic are at genuine record
	// boundaries. This is the property the scan's anchor rests on.
	for i := 0; i+len(recordMagic) <= len(raw); i++ {
		if !bytes.Equal(raw[i:i+len(recordMagic)], recordMagic[:]) {
			continue
		}
		if !isRecordBoundary(t, raw, i) {
			t.Fatalf("recordMagic occurs at offset %d, which is not a record boundary", i)
		}
	}

	d := diagnose(t, dir)
	if d.Damaged || d.Repairable {
		t.Fatalf("the escaped store still refuses (damaged=%v, repairable=%v): %s",
			d.Damaged, d.Repairable, d.Explanation)
	}
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("Open still refuses a crashed tail whose value carried a plant: %v", err)
	}
	defer s.Close()
	// The three records behind the damage are the ones the refusal used to
	// take with it. They are what the defect cost.
	for i := 0; i < 3; i++ {
		if v, ok := s.Get([]byte(fmt.Sprintf("key-%d", i))); !ok ||
			string(v) != fmt.Sprintf("value-%d", i) {
			t.Fatalf("record %d did not survive (present=%v value=%q)", i, ok, v)
		}
	}
}

// isRecordBoundary walks the log's frames from the start and reports whether
// off is one of them. It walks rather than searches, because "is there a record
// header here" is the question the scan already answers wrongly on planted
// bytes — asking it again would be the same instrument twice.
func isRecordBoundary(t *testing.T, raw []byte, off int) bool {
	t.Helper()
	for at := 0; at < len(raw); {
		if at == off {
			return true
		}
		_, _, _, n, st := decodeRecord(raw[at:])
		if n == 0 {
			// The damaged tail: its frame is unusable, so no boundary past
			// this point is known and the only honest answer is that off is
			// inside it.
			return false
		}
		if st != decodeOK && st != decodePayloadBad {
			return false
		}
		at += n
	}
	return false
}

// TestTheRecordChecksumFieldIsAnUnescapedCarrier is the row that keeps the word
// "impossible" out of this package, and it is a change detector on purpose.
//
// The escape covers payloads. It does not cover the record's own 32-byte
// header, and recordCRCOff holds a CRC32 — an affine function, so a handful of
// chosen payload bytes force that field to any four-byte value, recordMagic
// included. The end state a grind would produce is built here directly and fed
// to the real scan: a host record whose checksum field holds the magic and
// whose payload's first 28 bytes are an empty terminal record's tail. The scan
// returns scanFound at region offset 28. Same verdict as the payload plant,
// sourced from the header instead of the payload, and the escape never reaches
// it — the plant's tail carries no magic, so escapePayload passes it through
// unchanged.
//
// Direction, declared before the run: this row MUST find the record. If it ever
// stops finding one, the escape has grown to cover the header, and the pricing
// framing in escapePayload's doc — not impossible, merely unpayable — has to be
// re-derived rather than quietly kept.
//
// What is NOT claimed: that this end state is reachable. It is not known to be.
// A candidate anchored at offset 28 reaches only ~34 bytes into the payload, so
// its own more and length fields fall inside the batch's first key, and every
// durable key in node/chain is a fixed prefix plus a hash-derived run —
// an offline preimage grind, ~2^76 for the cheapest construction derived and
// ~2^160 for the empty-terminal one. Not constructed, and not proven
// impossible; per rule 21 the claim stops there. The guard in node/chain
// defends the clause it rests on.
func TestTheRecordChecksumFieldIsAnUnescapedCarrier(t *testing.T) {
	plant := forgeTerminalRecord(math.MaxUint64)

	// The payload a grind would have had to author: the plant's 28-byte tail,
	// then filler. The four bytes the candidate needs first are not in the
	// payload at all — they are the host's own checksum field.
	payload := make([]byte, 64)
	copy(payload, plant[4:])

	host := make([]byte, recordHeaderLen+len(payload))
	copy(host[recordMagicOff:], recordMagic[:])
	binary.LittleEndian.PutUint64(host[recordSeqOff:], 3)
	binary.LittleEndian.PutUint32(host[recordMoreOff:], 0)
	binary.LittleEndian.PutUint64(host[recordLenOff:], uint64(len(payload)))
	binary.LittleEndian.PutUint32(host[recordHdrCRCOff:], crc32.ChecksumIEEE(host[:recordHdrCRCOff]))
	// The forced field. A real attacker reaches this value through CRC32's
	// linearity over chosen payload bytes; the arithmetic is not the point of
	// this row, the byte position is.
	copy(host[recordCRCOff:], recordMagic[:])
	copy(host[recordHeaderLen:], payload)

	// The crash that opens the scan region at all.
	breakHeader(host)
	if _, _, _, _, st := decodeRecord(host); st != decodeHeaderUntrusted {
		t.Fatalf("the host record decodes as %v, want decodeHeaderUntrusted: without an "+
			"unusable frame the scan never begins inside this record", st)
	}

	// The escape does not touch it, and that is the whole finding.
	if got := escapePayload(payload); !bytes.Equal(got, payload) {
		t.Fatalf("escapePayload changed the plant's tail, so this row is measuring a payload " +
			"carrier and not the header carrier it claims")
	}

	at, res := findTerminalRecordWithin(host, 0, bootScanBudget(len(host)))
	if res != scanFound || at != recordCRCOff {
		t.Fatalf("the scan reported (%d, %v), want scanFound at %d.\n"+
			"THIS IS A DIRECTION FAILURE, NOT A REGRESSION: the escape is documented as "+
			"pricing this attack and not removing it, and that documentation is now wrong "+
			"in one direction or the other. Re-derive escapePayload's doc before changing "+
			"this row.", at, res, recordCRCOff)
	}
	if _, seq, more, n, st := decodeRecord(host[at:]); st != decodeOK || more != 0 ||
		n != recordHeaderLen || seq != math.MaxUint64 {
		t.Fatalf("the accepted window is not a complete terminal record (st=%v seq=%d more=%d "+
			"n=%d), so this row overstates what the header carrier reaches", st, seq, more, n)
	}
}

// TestTheRefusalOverAPlantedTerminalRecordIsPermanent is the consequence half,
// and it is the one that separates an incident from a dead store.
//
// "Permanently unavailable" is the expensive word in the defect's own
// description and it had never been measured. A refusal a later run clears
// costs a restart; one that no later run can clear costs the data directory.
// The instrument loop is the whole local surface an operator has — Diagnose,
// Apply with the report they were shown, Open — and Apply is the only member of
// it that may write to the log at all.
//
// The store is framed by the version-3 writer, because this build's writer can
// no longer produce it. That is deliberate rather than a leftover: what
// this row pins is what a plant COSTS once it is in the log, and the header
// carrier above is a route that is still open. Softening this row because the
// cheap route closed would leave the expensive one undocumented.
//
// The log's digest is the assertion rather than the directory's, deliberately.
// A refused Open still creates the lock file, so a directory-wide digest moves
// on the first cycle for a reason that has nothing to do with the verdict, and
// a row that failed there would be reporting bookkeeping as recovery.
func TestTheRefusalOverAPlantedTerminalRecordIsPermanent(t *testing.T) {
	dir, _ := plantedTailStore(t, forgeTerminalRecord(math.MaxUint64), false)
	before := logDigest(t, dir)
	const cycles = 8
	for i := 0; i < cycles; i++ {
		r, err := OpenForRepair(dir)
		if err != nil {
			t.Fatalf("cycle %d: OpenForRepair: %v", i, err)
		}
		d, err := r.Diagnose()
		if err != nil {
			r.Close()
			t.Fatalf("cycle %d: Diagnose: %v", i, err)
		}
		if d.Repairable {
			r.Close()
			t.Fatalf("cycle %d offered a cut where cycle 0 refused, so the verdict is not a "+
				"function of the bytes on disk: %s", i, d.Explanation)
		}
		if err := r.Apply(d); !errors.Is(err, ErrNotRepairable) {
			r.Close()
			t.Fatalf("cycle %d: Apply returned %v, want ErrNotRepairable", i, err)
		}
		r.Close()
		assertRefusesToOpen(t, dir, "a store whose planted refusal must not decay into a boot")
		if now := logDigest(t, dir); now != before {
			t.Fatalf("cycle %d moved bytes in the log (%s -> %s); nothing in this loop is "+
				"allowed to write to it", i, before, now)
		}
	}
}

// logDigest is the log's contents and length, so a truncation to a prefix and
// an edit in place are both visible. Length alone would miss the second and
// content alone reads the same for a file that was rewritten to the same
// bytes at a different size only by accident.
func logDigest(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, logName))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x@%d", sha256.Sum256(raw), len(raw))
}
