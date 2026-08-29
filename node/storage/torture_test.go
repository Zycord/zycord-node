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
	"syscall"
	"testing"
)

// The atomicity torture suite (M1-G1).
//
// M0's risk was a wrong rule. M1's is a right rule persisted wrongly: a node
// that restarts into a state no fold ever produced diverges silently, and the
// trigger is a crash schedule rather than anything in the code. These tests are
// the substitute for the compiler and the differential fold, neither of which
// can see this layer.
//
// The crashes here are injected deterministically rather than by killing a
// process, which is strictly stronger: a SIGKILL lands wherever it lands, while
// this covers *every byte offset* of a commit. A real SIGKILL test lives in
// process_test.go as well, because the two prove different things — one proves
// the recovery logic, the other proves the operating system agrees.

// crashAt returns a store whose next commit dies after writing n bytes.
func crashAt(t *testing.T, dir string, n int) *Store {
	t.Helper()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.writeHook = func(record []byte) ([]byte, error) {
		if n >= len(record) {
			return record, errCrash
		}
		return record[:n], errCrash
	}
	return s
}

var errCrash = errors.New("simulated crash")

// TestCommitIsAllOrNothingAtEveryOffset is the core of G1.
//
// For every byte offset within a commit, the process dies there. On reopen the
// store must hold either the state before that commit or the state after it —
// never a mixture, and never a mixture of the *keys within* the batch, which is
// what a non-atomic engine would produce.
func TestCommitIsAllOrNothingAtEveryOffset(t *testing.T) {
	// A batch touching several keys, so a partial application would be visible.
	write := func(b *Batch, gen int) {
		for i := 0; i < 8; i++ {
			b.Put([]byte(fmt.Sprintf("key-%d", i)), []byte(fmt.Sprintf("gen-%d", gen)))
		}
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
	}

	// Size one record so the loop knows how far to go. The sequence number is
	// a fixed-width field either way, so the placeholder seq here does not
	// change the encoded length.
	probe := &Batch{}
	write(probe, 1)
	record, err := encodeRecord(probe, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	for offset := 0; offset <= len(record); offset++ {
		t.Run(fmt.Sprintf("offset=%d", offset), func(t *testing.T) {
			dir := t.TempDir()

			// Commit generation 0 cleanly.
			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			b0 := &Batch{}
			write(b0, 0)
			if err := s.Commit(b0); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			// Die part-way through generation 1.
			crashed := crashAt(t, dir, offset)
			b1 := &Batch{}
			write(b1, 1)
			if err := crashed.Commit(b1); !errors.Is(err, errCrash) {
				t.Fatalf("expected the simulated crash, got %v", err)
			}
			// No clean close: that is the point. Real process death takes every
			// file descriptor down with it, including the datadir lock, without
			// the flush Store.Close performs — so both are torn down by hand
			// here, unsynced, rather than calling Close.
			crashed.crashClose()
			crashed.lock.release()

			// Reopen and demand internal consistency.
			reopened, err := Open(dir, Options{})
			if err != nil {
				t.Fatalf("reopen after a crash at offset %d: %v", offset, err)
			}
			defer reopened.Close()

			height, ok := reopened.Get([]byte("height"))
			if !ok {
				t.Fatal("the first committed generation vanished")
			}
			for i := 0; i < 8; i++ {
				v, ok := reopened.Get([]byte(fmt.Sprintf("key-%d", i)))
				if !ok {
					t.Fatalf("key-%d vanished", i)
				}
				want := fmt.Sprintf("gen-%s", height)
				if string(v) != want {
					t.Fatalf("crash at offset %d left key-%d at %q while height says %q: "+
						"a batch was applied in part", offset, i, v, height)
				}
			}
		})
	}
}

// TestTornTailIsDiscarded: garbage appended to the log — a half-written record,
// a corrupted one, or an unrelated byte — must not be mistaken for data.
func TestTornTailIsDiscarded(t *testing.T) {
	cases := map[string][]byte{
		"single stray byte":  {0x00},
		"partial magic":      {'C', 'A'},
		"magic then nothing": append([]byte(nil), recordMagic[:]...),
		"length runs past end of file": func() []byte {
			// A header that verifies against its own checksum -- so its
			// length field is known to be exactly what the writer wrote --
			// declaring a payload of which not one byte actually follows.
			// That is the shape of an in-progress record the process never
			// finished, and the *verified* header is what makes it provable
			// rather than merely plausible: replayLog may discard from here
			// without scanning, because the writer's own frame says nothing
			// later can have started before its end.
			return recordHeaderFor(1, 1000) // well under MaxRecordLen
		}(),
		"length runs past end of file, header not verifiable": func() []byte {
			// The same bytes with the header checksum left wrong, so the
			// frame proves nothing and replayLog searches the remaining bytes
			// instead of trusting the length. It finds nothing -- there is
			// nothing after it -- and discards, same as above.
			//
			// This pair does NOT discriminate between the two branches, and
			// the comment here used to claim it did. A hostile review checked:
			// with nothing on disk past the record, every branch ends in the
			// same truncation, so both cases still pass when the "never scan a
			// proven short write" rule and the "always scan an unverifiable
			// header" rule are each negated. They are scenario tests -- the
			// two shapes must both come back up -- and the branch itself is
			// pinned by TestPayloadBaitDoesNotDefeatTheTailDiscriminator and
			// TestInteriorLengthCorruptionOverrunningTheFileIsRefused, which
			// do fail under exactly one mutation each. Saying so here rather
			// than leaving the false claim standing: a test believed to
			// constrain something it does not is worse than no test, because
			// it stops anyone looking (CONTRIBUTING, "A property must exist
			// before a test can observe it").
			out := recordHeaderFor(1, 1000)
			out[recordHdrCRCOff] ^= 0xff
			return out
		}(),
		"bad checksum": func() []byte {
			b := &Batch{}
			b.Put([]byte("k"), []byte("v"))
			rec, _ := encodeRecord(b, 1, 0)
			rec[len(rec)-1] ^= 0xff
			return rec
		}(),
	}

	for name, tail := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			b := &Batch{}
			b.Put([]byte("good"), []byte("value"))
			if err := s.Commit(b); err != nil {
				t.Fatal(err)
			}
			s.Close()

			f, err := os.OpenFile(filepath.Join(dir, logName), os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(tail); err != nil {
				t.Fatal(err)
			}
			f.Close()

			reopened, err := Open(dir, Options{})
			if err != nil {
				t.Fatalf("a torn tail made the store unopenable: %v", err)
			}
			defer reopened.Close()

			if v, ok := reopened.Get([]byte("good")); !ok || string(v) != "value" {
				t.Fatal("the committed record did not survive a torn tail")
			}

			// And the log must have been truncated, so the next append starts
			// from a record boundary rather than after the garbage.
			b2 := &Batch{}
			b2.Put([]byte("after"), []byte("recovery"))
			if err := reopened.Commit(b2); err != nil {
				t.Fatal(err)
			}
			reopened.Close()

			final, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer final.Close()
			if _, ok := final.Get([]byte("after")); !ok {
				t.Fatal("a commit made after recovering from a torn tail was lost")
			}
		})
	}
}

// TestCompactionIsCrashSafe: a snapshot that lands without the log truncation,
// or a truncation without the snapshot, must both recover to the same state.
func TestCompactionIsCrashSafe(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 20; gen++ {
		b := &Batch{}
		b.Put([]byte(fmt.Sprintf("k%d", gen)), []byte(fmt.Sprintf("v%d", gen)))
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	// After compaction the log is empty and everything lives in the snapshot.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 20; gen++ {
		if v, ok := reopened.Get([]byte(fmt.Sprintf("k%d", gen))); !ok || string(v) != fmt.Sprintf("v%d", gen) {
			t.Fatalf("k%d was lost across compaction", gen)
		}
	}
	reopened.Close()

	// Now simulate the crash window: a snapshot exists *and* the log still
	// holds the records it already contains. Replay must be idempotent. The
	// log was truncated by the compaction above, so sequence numbers in its
	// next lifetime legitimately restart at 0 — these are written as if they
	// were the first 20 records after that compaction, which is exactly the
	// shape a real crash in this window would leave on disk.
	logPath := filepath.Join(dir, logName)
	var replay []byte
	for gen := 0; gen < 20; gen++ {
		b := &Batch{}
		b.Put([]byte(fmt.Sprintf("k%d", gen)), []byte(fmt.Sprintf("v%d", gen)))
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		rec, err := encodeRecord(b, uint64(gen), 0)
		if err != nil {
			t.Fatal(err)
		}
		replay = append(replay, rec...)
	}
	if err := os.WriteFile(logPath, replay, 0o644); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if v, ok := again.Get([]byte("height")); !ok || string(v) != "19" {
		t.Fatalf("replaying records already in the snapshot changed the state: height = %q", v)
	}
}

// TestAutomaticCompactionPreservesEverything exercises the size-triggered path.
func TestAutomaticCompactionPreservesEverything(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	const n = 400
	for i := 0; i < n; i++ {
		b := &Batch{}
		b.Put([]byte(fmt.Sprintf("key%04d", i)), []byte(fmt.Sprintf("value%04d", i)))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for i := 0; i < n; i++ {
		if v, ok := reopened.Get([]byte(fmt.Sprintf("key%04d", i))); !ok || string(v) != fmt.Sprintf("value%04d", i) {
			t.Fatalf("key%04d did not survive automatic compaction", i)
		}
	}
}

// TestDeletesSurviveRestart: a deletion is a mutation like any other, and must
// not reappear after a snapshot or a replay.
func TestDeletesSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &Batch{}
	b.Put([]byte("gone"), []byte("x"))
	b.Put([]byte("kept"), []byte("y"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	b2 := &Batch{}
	b2.Delete([]byte("gone"))
	if err := s.Commit(b2); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Has([]byte("gone")) {
		t.Fatal("a deleted key came back")
	}
	if !reopened.Has([]byte("kept")) {
		t.Fatal("a live key was lost")
	}
}

// TestScanPrefixIsSorted: consensus state is rebuilt by scanning, so the order
// has to be deterministic rather than whatever the map felt like.
func TestScanPrefixIsSorted(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	b := &Batch{}
	for i := 200; i >= 0; i-- {
		b.Put([]byte(fmt.Sprintf("p/%04d", i)), []byte{byte(i)})
	}
	b.Put([]byte("other/1"), []byte{1})
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}

	var seen []string
	if err := s.ScanPrefix([]byte("p/"), func(k, _ []byte) error {
		seen = append(seen, string(k))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 201 {
		t.Fatalf("scanned %d keys, want 201", len(seen))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i-1] >= seen[i] {
			t.Fatal("ScanPrefix is not in sorted order")
		}
	}
}

// TestUnknownFormatVersionIsRefused: a store written by another version of the
// format must be refused, not guessed at.
//
// This is the one kind of corruption no checksum catches, because the bytes are
// intact and it is the *interpretation* that is wrong — the same class as the
// well-formed-wrong-value case that motivates the chain's startup integrity
// check.
func TestUnknownFormatVersionIsRefused(t *testing.T) {
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
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Rewrite the snapshot's version byte, leaving its checksum valid: the file
	// is intact, it just means something this build does not know.
	path := filepath.Join(dir, snapshotName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[7] = FormatVersion + 1
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want a format-version refusal: a node must not half-read "+
			"a store it does not understand", err)
	}
}

// The sticky-failure suite.
//
// A failed write or sync used to leave the store perfectly usable: no sticky
// error, s.closed untouched, logBytes not advanced. The process kept
// accepting and durably committing records on top of a torn one, and the next
// restart's replayLog had no way to tell "torn, then nothing" from "torn,
// then N more real commits" — so it discarded everything from the tear
// onward, silently rewinding the chain by however much landed after the
// original fault. TestCommitIsAllOrNothingAtEveryOffset and
// TestSurvivesSigkillDuringCommit never issued a second Commit on the wounded
// store, so neither ever observed this: the gap in the suite was exactly one
// more commit before the reopen.

// TestFailedWriteIsSticky is F-STOR-1: once a write or sync fails, the store
// must refuse every later commit rather than keep appending on top of the
// torn record — even if whatever caused the failure (a full disk, say) turns
// out to be transient and a later write would have succeeded cleanly.
func TestFailedWriteIsSticky(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	good := &Batch{}
	good.Put([]byte("height"), []byte("0"))
	if err := s.Commit(good); err != nil {
		t.Fatal(err)
	}

	// Wound the store: the next write reaches disk only halfway.
	s.writeHook = func(record []byte) ([]byte, error) {
		return record[:len(record)/2], errCrash
	}
	wounding := &Batch{}
	wounding.Put([]byte("height"), []byte("1"))
	if err := s.Commit(wounding); !errors.Is(err, errCrash) {
		t.Fatalf("expected the injected fault, got %v", err)
	}

	// The fault was transient (as if the disk that filled up just freed some
	// space): remove the hook and try to keep going. Before the fix this
	// commit would succeed and land, complete and durable, right after the
	// torn "wounding" bytes.
	s.writeHook = nil
	after := &Batch{}
	after.Put([]byte("height"), []byte("2"))
	if err := s.Commit(after); err == nil {
		t.Fatal("a commit after a write failure was accepted; the store must be " +
			"poisoned and refuse to commit until it is reopened")
	}

	// A second attempt must fail identically -- the poison does not clear
	// itself.
	if err := s.Commit(after); err == nil {
		t.Fatal("a second commit on a poisoned store was accepted")
	}

	// No clean close, matching the crash-recovery tests: real process death
	// does not get to flush.
	s.crashClose()
	s.lock.release()

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopen after a poisoned store: %v", err)
	}
	defer reopened.Close()

	// Generation 1 (the torn write) and 2 (the commit that should have been
	// refused) must both be absent -- not a mixture, and not generation 2
	// alone with the tear silently skipped over.
	height, ok := reopened.Get([]byte("height"))
	if !ok || string(height) != "0" {
		t.Fatalf(`height = %q, want "0": nothing committed after the write failure `+
			"should have reached disk", height)
	}

	// And the reopened store must be healthy.
	next := &Batch{}
	next.Put([]byte("post-recovery"), []byte("ok"))
	if err := reopened.Commit(next); err != nil {
		t.Fatalf("the reopened store is unusable: %v", err)
	}
}

// TestPoisonedStoreRefusesCompactToo: the sticky failure has to cover every
// path that touches the log, not only Commit's automatic trigger.
func TestPoisonedStoreRefusesCompactToo(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		s.crashClose()
		s.lock.release()
	}()

	b := &Batch{}
	b.Put([]byte("k"), []byte("v"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}

	s.writeHook = func(record []byte) ([]byte, error) { return nil, errCrash }
	if err := s.Commit(&Batch{mutations: []mutation{{op: opPut, key: []byte("x"), value: []byte("y")}}}); err == nil {
		t.Fatal("setup: expected the injected fault")
	}

	if err := s.Compact(); err == nil {
		t.Fatal("Compact succeeded on a poisoned store")
	}
}

// The corruption-vs-tail suite.
//
// replayLog used to treat any decode failure, at any offset, as a torn tail
// and truncate the file there — correct reasoning for the very last record,
// applied unconditionally to every one of them. A single flipped bit in an
// interior record silently deleted every record after it, even when those
// records were fully intact on disk. The fix gives every record a monotonic
// sequence number and checksums the whole header (not just the payload), so
// replayLog can scan past a damaged record and tell "the writer stopped here"
// from "something damaged this record, but there is more data after it".

// TestInteriorCorruptionRefusesToOpenRatherThanDeletingSurvivingRecords is
// F-STOR-2: damage to a record that is not the last one in the file must
// refuse to open, not silently discard every record after it.
func TestInteriorCorruptionRefusesToOpenRatherThanDeletingSurvivingRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 5; gen++ {
		b := &Batch{}
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sizeBefore := int64(len(raw))

	// Flip one bit inside record 2 (0-indexed) -- records 3 and 4 sit
	// intact right after it, still on disk, still valid.
	_, _, _, n0, status := decodeRecord(raw)
	if status != decodeOK {
		t.Fatal("setup: record 0 does not decode")
	}
	_, _, _, n1, status := decodeRecord(raw[n0:])
	if status != decodeOK {
		t.Fatal("setup: record 1 does not decode")
	}
	corruptOffset := n0 + n1 + recordHeaderLen + 2 // inside record 2's payload
	raw[corruptOffset] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt: interior damage with intact records after it "+
			"must refuse to open, not repair by deletion", err)
	}

	// And nothing must have been deleted: the file on disk is byte-for-byte
	// what it was before the failed Open.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(after)) != sizeBefore {
		t.Fatalf("the log shrank from %d to %d bytes even though Open refused to "+
			"succeed -- interior corruption must not repair by deletion", sizeBefore, len(after))
	}
}

// TestInteriorCorruptionInTheLastFewBytesOfARecordStillFound: corruption need
// not land in the payload to be interior damage. Damage to record 1's own
// length field is exactly as detectable, and exactly as much not a tail, as
// damage to its payload -- *provided* the corrupted length still fits inside
// the bytes on disk. (A length corrupted so far that it no longer fits is a
// different, and now deliberately different, case: see
// TestPayloadBaitDoesNotDefeatTheTailDiscriminator. This test's corruption is
// built to land on the "fits, but the checksum now disagrees" side of that
// line, deterministically, rather than leaving it to how a specific byte
// happens to XOR.)
func TestInteriorCorruptionInTheLastFewBytesOfARecordStillFound(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 4; gen++ {
		b := &Batch{}
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, n0, status := decodeRecord(raw)
	if status != decodeOK {
		t.Fatal("setup: record 0 does not decode")
	}
	// Shrink record 1's declared length by one, in place, leaving its stored
	// checksum (computed over the original, longer payload) untouched. The
	// declared frame still fits comfortably inside the file -- it can only get
	// smaller -- so decodeRecord reaches the checksum comparison, and it now
	// disagrees: the CRC on file was never computed over "payload minus its
	// last byte". This is the header-corruption case the tail discriminator was
	// built for: the old CRC never covered the length field at all, so this
	// kind of corruption was previously undetectable as such.
	lengthOff := n0 + 12
	length := binary.LittleEndian.Uint64(raw[lengthOff : lengthOff+8])
	if length == 0 {
		t.Fatal("setup: record 1's payload is empty, this corruption needs at least one byte")
	}
	binary.LittleEndian.PutUint64(raw[lengthOff:lengthOff+8], length-1)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}

// TestPayloadBaitDoesNotDefeatTheTailDiscriminator is the adversarial review's
// finding on the tail discriminator (R2-STOR): an ordinary short write --
// nothing ever written past the cut, exactly what a crash mid-commit leaves on
// disk -- must not be misclassified as interior corruption merely because the
// in-flight record's own *payload* (ordinary, writer-controlled content: a
// certificate field, a block body, anything gossiped in from the network)
// happens to contain bytes that parse as a second, self-contained,
// checksum-valid record. CRC32 is not secret, so building a "valid" fake record
// inside a payload value needs no collision search -- just arithmetic -- which
// is exactly why the old scan (triggered on *any* decode failure, including
// "this record's own declared length does not fit") was not a safe
// discriminator.
func TestPayloadBaitDoesNotDefeatTheTailDiscriminator(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	good := &Batch{}
	good.Put([]byte("height"), []byte("0"))
	if err := s.Commit(good); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A self-contained, checksum-valid fake record: magic + an
	// arbitrarily-large sequence (guaranteed >= whatever replayLog expects
	// next) + a zero length + the CRC32 that combination actually produces.
	// Nothing here is secret or hard to compute -- an attacker supplying an
	// ordinary batch value (over the network, as a certificate or block-body
	// field) can embed exactly this.
	// Both checksums are computed, not guessed: CRC32 is not secret, so an
	// attacker supplying an ordinary batch value (over the network, as a
	// certificate or block-body field) can embed a record that verifies
	// completely. The header checksum raises no bar against a deliberate
	// forgery -- it is not a MAC and does not claim to be. What it does is
	// let the *reader* establish that the damaged record's own frame is
	// genuine, and a genuine frame is what makes this region off limits to
	// the scan in the first place.
	bait := recordHeaderFor(^uint64(0), 0)
	h := crc32.NewIEEE()
	h.Write(bait[:recordCRCOff])
	binary.LittleEndian.PutUint32(bait[recordCRCOff:], h.Sum32())
	if _, _, _, _, status := decodeRecord(bait); status != decodeOK {
		t.Fatalf("setup: the bait is not a fully valid record (status %v); this test would "+
			"prove nothing against a scan that only believes valid records", status)
	}

	value := append([]byte("prefix-"), bait...)
	value = append(value, []byte("-trailing padding well past the embedded bait")...)
	wounding := &Batch{}
	wounding.Put([]byte("height"), value)

	// The payload escape closed the route these bytes used to arrive by, and
	// the assertion comes first because it is the stronger of the two: put
	// through this build's writer, the bait is not in the record at all.
	// encodeRecord escapes recordMagic out of every payload (see
	// escapePayload), so a value gossiped in from the network cannot carry a
	// record shape into the log.
	if escaped, err := encodeRecord(wounding, 1, 0); err != nil {
		t.Fatal(err)
	} else if at := bytes.Index(escaped, bait); at >= 0 {
		t.Fatalf("the bait survived encodeRecord at offset %d; the payload-plant carrier is open again", at)
	}

	// The row below then pins the reader's rule on bytes that reach the log
	// some other way, framed the way format version 3 framed them. The rule has
	// to hold however record-shaped bytes got into a payload, and the escape is
	// not the only thing standing between an attacker and one: it does not
	// cover the record's own header (see TestTheRecordChecksumFieldIsAn-
	// UnescapedCarrier). A reader that started scanning inside payloads because
	// "payloads are escaped now" would be resting a data-loss decision on the
	// writer's transformation instead of on the frame.
	record := frameUnescaped(t, wounding, 1, 0)

	// Simulate an ordinary short write: everything up to a point comfortably
	// past the bait, and nothing more -- exactly what a crash mid-write
	// leaves on disk. This is not corruption of an existing record: it is an
	// honest record, in the middle of being written, that the process never
	// finished. The bait's offset inside the fully-encoded record depends on
	// the mutation-encoding overhead ahead of it (op byte, length-prefixed
	// key, length-prefixed value) -- found by search rather than hand-summed,
	// so this test does not silently start truncating *inside* the bait
	// itself if that framing ever changes.
	baitOffset := bytes.Index(record, bait)
	if baitOffset < 0 {
		t.Fatal("setup: the bait is not found verbatim in the encoded record")
	}
	cut := baitOffset + len(bait) + 5
	if cut >= len(record) {
		t.Fatalf("setup: cut (%d) does not truncate the record (%d bytes)", cut, len(record))
	}
	path := filepath.Join(dir, logName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(record[:cut]); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("an honest short write was misclassified as interior corruption because its "+
			"own payload happened to contain record-shaped bytes: %v", err)
	}
	defer reopened.Close()

	if v, ok := reopened.Get([]byte("height")); !ok || string(v) != "0" {
		t.Fatalf(`height = %q, ok=%v; want "0": the last fully-durable commit must survive `+
			"a torn write that follows it", v, ok)
	}

	// And the store must still be usable: a torn tail heals the same way any
	// other one does.
	next := &Batch{}
	next.Put([]byte("after"), []byte("ok"))
	if err := reopened.Commit(next); err != nil {
		t.Fatalf("the reopened store is unusable: %v", err)
	}
}

// TestMaxLenExceededIsRefusedNotTruncated is a third review's finding on the
// tail discriminator (R3-STOR): fix 1 folded "declares a length greater than
// MaxRecordLen" into the same decodeTorn bucket as "declares a length that runs
// past the end of the file", so the scan that would have caught it was skipped
// and the record was silently discarded along with everything after it.
//
// That is wrong specifically for this case, not just risky: encodeRecord
// refuses to write a payload bigger than MaxRecordLen (ErrBatchTooBig)
// before any bytes reach disk, and write(2)'s prefix guarantee means a
// *full* header actually present on disk was written whole, never damaged by
// the write process itself. So a full header naming a length above
// MaxRecordLen can only mean the bytes were corrupted after they were
// already durable -- the interior-corruption defect's own original example,
// verbatim: "a latent sector error flips a bit in record 37's length field".
// Silently discarding it (and, in this reproduction, three intact records after
// it) is exactly the failure the discriminator exists to close.
//
// Reproduced two ways, matching the adversarial review: corrupting a
// mid-file record's length to a value past MaxRecordLen, and (in
// TestInteriorCorruptionInTheLastFewBytesOfARecordStillFound, already in
// this file) corrupting one to a value that stays under MaxRecordLen but
// still overruns the actual remaining bytes -- which must still resolve via
// the ambiguous/scan path, not this one. Both must refuse; neither may
// silently repair by truncation.
func TestMaxLenExceededIsRefusedNotTruncated(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 5; gen++ {
		b := &Batch{}
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sizeBefore := int64(len(raw))

	// Corrupt record 2's (0-indexed) length field to a value past
	// MaxRecordLen -- records 3 and 4 sit intact right after it, still on
	// disk, still valid.
	_, _, _, n0, status := decodeRecord(raw)
	if status != decodeOK {
		t.Fatal("setup: record 0 does not decode")
	}
	_, _, _, n1, status := decodeRecord(raw[n0:])
	if status != decodeOK {
		t.Fatal("setup: record 1 does not decode")
	}
	rec2 := n0 + n1
	binary.LittleEndian.PutUint64(raw[rec2+recordLenOff:rec2+recordLenOff+8], MaxRecordLen+1)
	// Recompute the header checksum over the impossible length, so this test
	// lands on decodeMaxLenExceeded rather than on decodeHeaderUntrusted.
	// Without this the corruption would be caught by the *other* branch (the
	// header no longer verifying, then a scan finding records 3 and 4), and
	// the test would pass while asserting nothing about this one. The
	// bit-flip form -- which is what a latent sector error actually produces,
	// and which does break the header checksum -- is covered by
	// TestInteriorLengthCorruptionOverrunningTheFileIsRefused.
	binary.LittleEndian.PutUint32(raw[rec2+recordHdrCRCOff:],
		crc32.ChecksumIEEE(raw[rec2:rec2+recordHdrCRCOff]))
	if _, _, _, _, status := decodeRecord(raw[rec2:]); status != decodeMaxLenExceeded {
		t.Fatalf("setup: record 2 decodes as %v, want decodeMaxLenExceeded", status)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt: a length field corrupted past MaxRecordLen is "+
			"unconditional proof of damage to an already-durable record, never an honest "+
			"short write, and must refuse rather than silently discard the intact records "+
			"after it", err)
	}

	// And nothing must have been deleted: the file on disk is byte-for-byte
	// what it was before the failed Open.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(after)) != sizeBefore {
		t.Fatalf("the log shrank from %d to %d bytes even though Open refused to succeed -- "+
			"a length past MaxRecordLen must not repair by deletion", sizeBefore, len(after))
	}
}

// TestTornTailTruncationIsLogged: a genuine tail tear is still repaired
// automatically -- a node has to come back up on its own after an ordinary
// crash -- but the repair must not be silent: a node that quietly shortens its
// own durability log is exactly the event an operator has to be able to notice.
func TestTornTailTruncationIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	dir := t.TempDir()
	s, err := Open(dir, Options{Logger: logger})
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

	f, err := os.OpenFile(filepath.Join(dir, logName), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	buf.Reset()
	reopened, err := Open(dir, Options{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	if !strings.Contains(buf.String(), "discard") {
		t.Fatalf("a torn tail was recovered without a word about it; log output = %q", buf.String())
	}

	// A store opened without a Logger must not panic or block on the missing
	// sink -- silence is the explicit default, not a nil dereference.
	quiet := t.TempDir()
	qs, err := Open(quiet, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := qs.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := qs.Close(); err != nil {
		t.Fatal(err)
	}
	qf, err := os.OpenFile(filepath.Join(quiet, logName), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	qf.Write([]byte{0xff})
	qf.Close()
	requiet, err := Open(quiet, Options{})
	if err != nil {
		t.Fatal(err)
	}
	requiet.Close()
}

// The compaction-failure suite.

// TestCompactionRenameFailureDoesNotOrphanTheTempSnapshot: every failure path
// in compactLocked except the rename used to clean up snapshot.tmp. Force the
// rename to fail by pre-occupying its target with a directory (rename onto an
// existing directory fails on every platform this runs on) and check the
// orphan is gone.
func TestCompactionRenameFailureDoesNotOrphanTheTempSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	b := &Batch{}
	b.Put([]byte("k"), []byte("v"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}

	// Occupy the rename target so os.Rename(tmpPath, snapshotName) fails.
	if err := os.Mkdir(filepath.Join(dir, snapshotName), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := s.Compact(); err == nil {
		t.Fatal("Compact succeeded despite the occupied rename target")
	}

	if _, err := os.Stat(filepath.Join(dir, snapshotTmp)); !os.IsNotExist(err) {
		t.Fatalf("snapshot.tmp was left behind after a failed rename (stat err = %v)", err)
	}
}

// TestFailedCompactionResyncsLogBytesWithReality: a compaction that fails
// after truncating the log (but before confirming the truncation is durable)
// used to leave logBytes at its stale, pre-compaction value forever --
// wedging every future commit into retrying a full snapshot rewrite, because
// the auto-compact threshold check never saw logBytes drop. logBytes must
// track what is actually on disk even when compactLocked fails partway.
func TestFailedCompactionResyncsLogBytesWithReality(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{CompactAfterBytes: 1}) // compact on every commit
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	realSync := s.sync
	logSyncCalls := 0
	s.sync = func(f *os.File) error {
		// The snapshot's own sync (a different *os.File, tmp) must succeed, and
		// so must the *first* sync of s.log -- that is the ordinary
		// post-write durability barrier every Commit performs, before
		// compaction is even considered. Only the *second* sync of s.log is
		// compactLocked's own final confirmation, called after it has already
		// truncated the log to zero -- that is the one this test breaks.
		if f == s.log {
			logSyncCalls++
			if logSyncCalls == 2 {
				return errCrash
			}
		}
		return realSync(f)
	}

	b := &Batch{}
	b.Put([]byte("k"), []byte("v"))
	if err := s.Commit(b); err != nil {
		t.Fatalf("a failed *compaction* must not fail the commit that triggered it: %v", err)
	}

	info, err := s.log.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if s.logBytes != info.Size() {
		t.Fatalf("logBytes = %d after a failed compaction, want it resynced to the real "+
			"file size %d — otherwise every future commit retries the compaction forever",
			s.logBytes, info.Size())
	}

	// A later commit must complete the compaction it retries.
	b2 := &Batch{}
	b2.Put([]byte("k2"), []byte("v2"))
	if err := s.Commit(b2); err != nil {
		t.Fatal(err)
	}
	if s.logBytes != 0 {
		t.Fatalf("logBytes = %d, want 0: the retried compaction should have succeeded", s.logBytes)
	}
}

// TestFailedCompactionResyncsSequenceNumberWithReality is a second,
// independent review's finding on the same fault this package's own
// TestFailedCompactionResyncsLogBytesWithReality injects: compactLocked's
// failure path resynced logBytes from the real file size, but nothing
// resynced nextSeq the same way.
//
// If Truncate(0) succeeds and only the *confirming* fsync immediately after
// it fails -- an ordinary transient I/O hiccup, exactly the fault the sibling
// test above injects -- the physical log really is empty from that instant
// on, but nextSeq used to stay at its stale pre-compaction value. The next
// legitimate, fully-durable commit then wrote a record numbered from that
// stale sequence into what was, on disk, a fresh empty log. On the next
// restart, replayLog always starts a fresh log at expectedSeq 0, saw the
// mismatch, and hit the very "refuse to guess" branch the tail discriminator added --
// permanently bricking a store that was never actually corrupted. logBytes
// has an os.Stat to resync from after the fact; nextSeq does not, which is
// why the fix has to be in compactLocked itself rather than in the caller.
func TestFailedCompactionResyncsSequenceNumberWithReality(t *testing.T) {
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

	// Fail compaction at the post-truncate confirming sync, same fault shape
	// as the sibling test: the log is truncated to empty, then the sync on it
	// fails.
	realSync := s.sync
	failOnce := true
	s.sync = func(f *os.File) error {
		if failOnce && f == s.log {
			failOnce = false
			return errCrash
		}
		return realSync(f)
	}
	if err := s.Compact(); !errors.Is(err, errCrash) {
		t.Fatalf("expected the injected fault from Compact, got %v", err)
	}
	s.sync = realSync

	if s.logBytes != 0 {
		t.Fatalf("setup: logBytes = %d after the post-truncate sync failure, want 0", s.logBytes)
	}
	if s.nextSeq != 0 {
		t.Fatalf("nextSeq = %d after a compaction failed at the post-truncate sync, want 0: "+
			"the physical log is already empty regardless of what failed afterward, and its "+
			"next lifetime must restart sequence numbering there", s.nextSeq)
	}

	// The fault was transient -- the same premise TestFailedWriteIsSticky
	// uses -- and the store must go on writing correctly-numbered records
	// into what is, on disk, genuinely a fresh empty log.
	b2 := &Batch{}
	b2.Put([]byte("k2"), []byte("v2"))
	if err := s.Commit(b2); err != nil {
		t.Fatalf("a commit after a transient compaction failure was refused: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The bug only shows up on a restart: it is replayLog, on the *next*
	// Open, that compares the record's stored sequence against the fresh
	// expectedSeq=0 every log replay starts from.
	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("reopening after a transient compaction failure refused a store that was "+
			"never actually corrupted: %v", err)
	}
	defer reopened.Close()
	if v, ok := reopened.Get([]byte("k2")); !ok || string(v) != "v2" {
		t.Fatalf("k2 = %q, ok=%v; want the post-compaction-failure commit to survive", v, ok)
	}
	if v, ok := reopened.Get([]byte("k")); !ok || string(v) != "v" {
		t.Fatalf("k = %q, ok=%v; want the pre-compaction commit, now in the snapshot, to survive", v, ok)
	}
}

// TestSyncDirOnlyIgnoresUnsupportedPlatformErrors is the swallowed-fsync half
// of the sticky-failure rule: syncDir must swallow exactly ENOTSUP/EINVAL (the
// documented "this platform cannot fsync a directory" case) and propagate
// everything else, rather than returning nil for any Sync failure whatsoever.
func TestSyncDirOnlyIgnoresUnsupportedPlatformErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		ignore bool
	}{
		{"ENOTSUP", syscall.ENOTSUP, true},
		{"EINVAL", syscall.EINVAL, true},
		{"EIO", syscall.EIO, false},
		{"ENOSPC", syscall.ENOSPC, false},
		{"a generic error", errors.New("disk on fire"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUnsupportedDirSync(c.err); got != c.ignore {
				t.Fatalf("isUnsupportedDirSync(%v) = %v, want %v", c.err, got, c.ignore)
			}
		})
	}

	// And the happy path: syncing a real, valid directory must still succeed.
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir on a real directory failed: %v", err)
	}
}

// TestTruncateOpenLogWorksOnTheAppendHandle pins the three properties
// compactLocked's last step rests on, on whatever platform this runs.
//
// It exists because the naive spelling of that step — (*os.File).Truncate on
// the store's own log handle — is correct on unix and fails outright on
// Windows, where O_APPEND without O_TRUNC gives up the FILE_WRITE_DATA right
// that setting a length needs. Nothing else in this package notices: the
// engine's own tests all reach the truncate through Commit or Compact, so the
// failure arrived as "compaction did not run" and "fault point 4 unreachable"
// several layers away from its cause. This is the test that names it.
//
// The log is opened with exactly the flags Open uses, deliberately, because
// the flags *are* the subject.
func TestTruncateOpenLogWorksOnTheAppendHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write([]byte("records from before the compaction")); err != nil {
		t.Fatal(err)
	}

	// 1. The truncate itself succeeds on the handle the store holds.
	if err := truncateOpenLog(f, 0); err != nil {
		t.Fatalf("truncateOpenLog on the store's own append handle: %v", err)
	}

	// 2. It is visible immediately, to a reader that is not this handle —
	// which is what compactLocked's comment about a future replayLog claims.
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Size() != 0 {
		t.Fatalf("after truncateOpenLog the log is %d bytes, want 0", fi.Size())
	}

	// 3. The handle still appends correctly afterwards, at the *new* end.
	// On Windows the truncate is issued through a second handle, so "the
	// append handle needs no repositioning" is a claim and not a tautology.
	if _, err := f.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "after" {
		t.Fatalf("log = %q, want %q: the append landed somewhere other than the new end of file", got, "after")
	}

	// And a non-zero size, since compaction is not the only caller shape a
	// future change might introduce.
	if _, err := f.Write([]byte("XYZ")); err != nil {
		t.Fatal(err)
	}
	if err := truncateOpenLog(f, 5); err != nil {
		t.Fatalf("truncateOpenLog to a non-zero size: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != "after" {
		t.Fatalf("log = %q, want %q", got, "after")
	}
}

// recordHeaderFor builds a record header carrying seq and length, with a
// correct header checksum and no record checksum, for tests that need to hand
// replayLog a frame it will accept as genuine.
func recordHeaderFor(seq, length uint64) []byte {
	out := make([]byte, recordHeaderLen)
	copy(out[recordMagicOff:], recordMagic[:])
	binary.LittleEndian.PutUint64(out[recordSeqOff:], seq)
	binary.LittleEndian.PutUint64(out[recordLenOff:], length)
	binary.LittleEndian.PutUint32(out[recordHdrCRCOff:],
		crc32.ChecksumIEEE(out[:recordHdrCRCOff]))
	return out
}

// TestInteriorLengthCorruptionOverrunningTheFileIsRefused is the
// interior-corruption defect's own opening example, byte for byte: "a latent
// sector error flips a bit in record 37's length field", with records 38..
// still intact on disk behind it. It must not be repaired by deletion.
//
// This is the case the first three rounds of this fix left open. The design
// at that point said: a record whose declared length runs past the end of the
// file is an honest short write, so do not scan -- because scanning inside a
// torn record's own payload finds writer-controlled bytes, not evidence
// (TestPayloadBaitDoesNotDefeatTheTailDiscriminator). That reasoning is
// sound, but only if the declared length is the writer's. A bit flipped into
// a length field produces the identical shape and the identical decision, and
// there the "payload" being skipped is not payload at all -- it is records
// 38 onward, which were then silently deleted.
//
// A length past MaxRecordLen was carved out (see
// TestMaxLenExceededIsRefusedNotTruncated) but that is only the large end of
// the same corruption: the bit flipped here is bit 20, worth one mebibyte,
// nowhere near the 1 GiB cap and far past the two hundred bytes this file
// actually holds. Nothing about the flip is chosen to be awkward; it is the
// ordinary magnitude.
//
// What closes it is the header checksum: the frame is verified before its
// length is read, so a corrupted length is now provably not the writer's,
// the record's claim on the bytes behind it falls away with it, and the scan
// runs after all. Mutating that -- dropping the header checksum comparison in
// verifyHeader -- makes this test fail with a silent truncation, which is
// what it exists to pin down.
func TestInteriorLengthCorruptionOverrunningTheFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 5; gen++ {
		b := &Batch{}
		b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sizeBefore := len(raw)

	off := 0
	for i := 0; i < 2; i++ {
		_, _, _, n, status := decodeRecord(raw[off:])
		if status != decodeOK {
			t.Fatalf("setup: record %d does not decode", i)
		}
		off += n
	}
	lengthOff := off + recordLenOff
	length := binary.LittleEndian.Uint64(raw[lengthOff : lengthOff+8])
	flipped := length ^ (1 << 20)
	if flipped > MaxRecordLen {
		t.Fatal("setup: this reproduction needs a length that stays under MaxRecordLen")
	}
	if flipped <= uint64(sizeBefore-off) {
		t.Fatal("setup: the flipped length must overrun the bytes actually on disk")
	}
	binary.LittleEndian.PutUint64(raw[lengthOff:lengthOff+8], flipped)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt: records 3 and 4 are intact on disk behind a "+
			"record whose length field was corrupted, and deleting them is the silent "+
			"rewind the tail discriminator exists to close", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != sizeBefore {
		t.Fatalf("the log shrank from %d to %d bytes even though Open refused: interior "+
			"corruption must never repair by deletion", sizeBefore, len(after))
	}
}

// TestPayloadCorruptionScansFromTheEndOfTheFrameNotIntoIt: when a record's
// header verifies but its payload does not, the frame is still a fact. The
// intact records after it must be found -- and the search must start at the
// end of the damaged record's own frame, never inside it, because the inside
// is writer-controlled bytes.
func TestPayloadCorruptionScansFromTheEndOfTheFrameNotIntoIt(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Record 1's payload carries a bait that verifies completely. If the
	// scan started at the damaged record rather than after it, this is what
	// it would find -- and it would then be reporting the record's own
	// payload back to itself as proof of a later writer.
	bait := recordHeaderFor(^uint64(0), 0)
	h := crc32.NewIEEE()
	h.Write(bait[:recordCRCOff])
	binary.LittleEndian.PutUint32(bait[recordCRCOff:], h.Sum32())

	for gen := 0; gen < 3; gen++ {
		b := &Batch{}
		if gen == 1 {
			b.Put([]byte("height"), append(append([]byte("x"), bait...), []byte("yyyy")...))
		} else {
			b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		}
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, n0, status := decodeRecord(raw)
	if status != decodeOK {
		t.Fatal("setup: record 0 does not decode")
	}
	// Damage a payload byte of record 1, leaving its header -- and therefore
	// its frame -- intact and verifiable.
	raw[n0+recordHeaderLen+1] ^= 0xff
	if _, _, _, _, status := decodeRecord(raw[n0:]); status != decodePayloadBad {
		t.Fatalf("setup: record 1 decodes as %v, want decodePayloadBad", status)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir, Options{})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt: record 2 is intact behind the damaged one", err)
	}
	// And the record it reports must be the real one after the frame, not the
	// bait inside it.
	frameEnd := 0
	{
		_, _, _, n1, _ := decodeRecord(raw[n0:])
		frameEnd = n0 + n1
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("offset %d", frameEnd)) {
		t.Fatalf("the refusal names the wrong later record; want the one at offset %d "+
			"(the end of the damaged record's frame), got: %v", frameEnd, err)
	}
}

// TestInteriorDamageWithIntactRecordsBehindItRefusesRatherThanDiscarding is a hostile review's
// finding on this fix, and it is the same mistake in miniature that the whole
// file is about: findNextRecord returned one boolean for two different
// reasons.
//
// "I scanned to the end of the buffer and nothing intact is there" and "I gave
// up before I got there" both arrived at replayLog as
// found=false, and replayLog treated the second like the first -- taking the
// torn-tail branch and truncating. An exhausted budget establishes nothing:
// the intact records it was looking for may sit just past where it stopped.
//
// It is reachable without touching the datadir. A candidate spends one attempt
// by passing the header checksum, and CRC32 is not secret, so 28 well-formed
// bytes are pure arithmetic. node/chain puts a whole serialized block --
// network-supplied -- into the log as one batch value, so ~7 KB of such bytes
// inside one block body is enough. Corrupt that record's length field by one
// ordinary bit afterwards (a latent sector error, the defect's own example) and the
// scan starts inside the payload, burns its budget on the duds, and deletes
// every intact record behind the damage with no error at all.
//
// 255 duds refuses correctly; 256 used to silently truncate. The fix is that
// exhaustion is its own outcome (scanInconclusive) and replayLog refuses on
// it, because "not established" must never be spent as "nothing there".
//
// The dud count was once a table of 255 / 256 / 300 around
// findNextRecordMaxAttempts, and crossing that bound was how this test reached
// exhaustion. That was replaced with a budget of checksummed bytes, and these
// duds declare a zero-length payload, so every one of those counts now costs
// 28 bytes against a gibibyte: the three subtests had become the same case
// three times, under names implying a boundary that no longer exists, which is
// how a table gets misread as coverage. One case remains. The scenario still
// pins something real — interior damage with intact records behind it must
// refuse, and it does, now via scanFound — so the test is named for that
// instead of for a mechanism it no longer exercises. Exhaustion itself is
// pinned directly by TestAnExhaustedScanBudgetIsInconclusiveNotNothingFound.
func TestInteriorDamageWithIntactRecordsBehindItRefusesRatherThanDiscarding(t *testing.T) {
	// A dud: passes verifyHeader (correct header checksum) so the scan looks
	// at it, but can never reach decodeOK (deliberately wrong record
	// checksum) so it is never mistaken for the record the scan is after.
	dud := func() []byte {
		out := make([]byte, recordHeaderLen)
		copy(out[recordMagicOff:], recordMagic[:])
		binary.LittleEndian.PutUint32(out[recordHdrCRCOff:],
			crc32.ChecksumIEEE(out[:recordHdrCRCOff]))
		binary.LittleEndian.PutUint32(out[recordCRCOff:], 0xdeadbeef)
		return out
	}

	const duds = 300

	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for gen := 0; gen < 4; gen++ {
		b := &Batch{}
		if gen == 1 {
			// The shape a block record takes: one ordinary value
			// holding network-supplied bytes.
			v := []byte("blockbody")
			for i := 0; i < duds; i++ {
				v = append(v, dud()...)
			}
			b.Put([]byte("height"), v)
		} else {
			b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
		}
		if err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, logName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sizeBefore := len(raw)
	_, _, _, n0, status := decodeRecord(raw)
	if status != decodeOK {
		t.Fatal("setup: record 0 does not decode")
	}
	lengthOff := n0 + recordLenOff
	length := binary.LittleEndian.Uint64(raw[lengthOff : lengthOff+8])
	binary.LittleEndian.PutUint64(raw[lengthOff:lengthOff+8], length^(1<<20))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt: records 2 and 3 are intact on disk behind "+
			"the damaged one, and a scan that ran out of budget has not established "+
			"otherwise", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != sizeBefore {
		t.Fatalf("the log shrank from %d to %d bytes even though Open refused",
			sizeBefore, len(after))
	}
}

// TestDamagedHeaderOnTheLastRecordStaysADiscardableTornTail pins the property
// that the shape of the *last* record's payload may not decide whether the
// node comes back up.
//
// The scan a damaged header triggers starts at that record's own first byte,
// because an unverifiable frame says nothing about where the record ends. For
// the last record in the log that region is its payload — and a block record
// is the serialized block, network-supplied, written verbatim. So the bytes an
// attacker gossips end up inside the region a crashed node searches.
//
// Under a budget counted in candidates, headers that pass the 24-byte header
// checksum and declare a span running past the end of the buffer each spent an
// attempt while costing the scan nothing: no payload was ever checksummed for
// them. 300 of them — under 10 KB, pure precomputed arithmetic — exhausted the
// budget, produced scanInconclusive, and left Open refusing forever, with no
// documented repair, on a log whose only real damage was a torn tail. The same
// log with a benign payload recovers cleanly, which is the whole point: the
// difference was attacker-chosen content, not the damage.
//
// The two subtests are the discriminator. Both damage the same byte of the
// same header; only the tail record's payload differs. They must reach the
// same outcome — recovered, with every committed record before the tear still
// readable, and the log cut back to exactly where the tear began.
func TestDamagedHeaderOnTheLastRecordStaysADiscardableTornTail(t *testing.T) {
	// Passes verifyHeader, declares a span far past the end of any buffer it
	// can appear in, so no payload of it is ever checksummed.
	dud := func() []byte {
		out := make([]byte, recordHeaderLen)
		copy(out[recordMagicOff:], recordMagic[:])
		binary.LittleEndian.PutUint64(out[recordLenOff:], 1<<40)
		binary.LittleEndian.PutUint32(out[recordHdrCRCOff:],
			crc32.ChecksumIEEE(out[:recordHdrCRCOff]))
		return out
	}

	for _, tc := range []struct {
		name string
		bait int
	}{
		{"benign tail payload", 0},
		{"tail payload full of header-checksum-valid bait", 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			for gen := 0; gen < 3; gen++ {
				b := &Batch{}
				b.Put([]byte("height"), []byte(fmt.Sprintf("%d", gen)))
				if err := s.Commit(b); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, logName)
			beforeTail, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tailAt := len(beforeTail)

			// The last record: the shape a block record takes, one ordinary
			// value holding network-supplied bytes.
			//
			// IT IS WRITTEN WITHOUT ITS BARRIER RETURNING, and that is the
			// fixture's meaning rather than a detail of how it is built. The
			// damaged-header store is a process that died part-way through this
			// write: the caller was never told the record committed, so nothing
			// is recorded out of band, and recovery may discard it. Committing
			// it normally and then corrupting it would be a DIFFERENT history —
			// one in which a record the caller was told had landed is now
			// unreadable — and on that store a refusal is the correct answer
			// and this test would be asserting data loss. The two stores are
			// byte-identical, which is exactly why the fixture has to say which
			// one it is.
			v := []byte("blockbody")
			for i := 0; i < tc.bait; i++ {
				v = append(v, dud()...)
			}
			b := &Batch{}
			b.Put([]byte("body"), v)
			inner := s.sync
			s.sync = func(f *os.File) error {
				if f == s.log {
					// Every byte of the record is in the file; the barrier
					// never returned. This is the instant the process dies.
					return errCrash
				}
				return inner(f)
			}
			if err := s.Commit(b); !errors.Is(err, errCrash) {
				t.Fatalf("expected the simulated crash at the barrier, got %v", err)
			}
			s.crashClose()
			s.lock.release()

			// The crash: one byte lost inside the last record's header. A
			// write reaching stable storage is a hole, not a prefix (see
			// CommitGroup), and a record of two pages or more puts the header
			// and the payload on different pages.
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lengthOff := tailAt + recordLenOff
			length := binary.LittleEndian.Uint64(raw[lengthOff : lengthOff+8])
			binary.LittleEndian.PutUint64(raw[lengthOff:lengthOff+8], length^(1<<20))
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			s2, err := Open(dir, Options{})
			if err != nil {
				t.Fatalf("Open refused a torn tail: %v", err)
			}
			defer s2.Close()

			// Nothing behind the tear may be lost, and the tail may not
			// survive: it was never applied, so leaving it would put it in
			// front of whatever the next commit writes.
			if got, ok := s2.Get([]byte("height")); !ok || string(got) != "2" {
				t.Fatalf(`height = %q (present=%v), want "2": the records before the tear were committed`,
					got, ok)
			}
			if _, ok := s2.Get([]byte("body")); ok {
				t.Fatal("the torn record was applied")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != tailAt {
				t.Fatalf("log truncated to %d bytes, want %d (the first byte of the torn record)",
					len(after), tailAt)
			}
		})
	}
}

// TestAnExhaustedScanBudgetIsInconclusiveNotNothingFound pins the one rule the
// three-valued scanResult exists for: a scan that stops because it ran out of
// work has established nothing, and must not be reported as the scan that
// reached the end and found nothing — because replayLog truncates on the
// latter.
//
// It drives findNextRecordWithin directly. The byte budget made the derived budget a
// gibibyte of checksummed bytes, which no test can reach honestly, so the
// end-to-end route to this branch is gone; asserting the rule through the
// budget parameter is what keeps it asserted at all.
//
// The pair is the discriminator: the same buffer, the same intact record in
// it, only the budget differs. With enough budget the scan reaches the record
// and says scanFound. With too little it must say scanInconclusive — and the
// rejected rule, "out of budget means nothing is there", would say
// scanNothingFound on this very input, which is the answer that deletes it.
func TestAnExhaustedScanBudgetIsInconclusiveNotNothingFound(t *testing.T) {
	rec, err := encodeRecord(func() *Batch {
		b := &Batch{}
		b.Put([]byte("height"), []byte("7"))
		return b
	}(), 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A candidate ahead of the real record that passes verifyHeader, declares
	// an in-bounds span, and so is charged its span -- the shape that spends
	// budget without ever decoding.
	decoy := make([]byte, recordHeaderLen+64)
	copy(decoy[recordMagicOff:], recordMagic[:])
	binary.LittleEndian.PutUint64(decoy[recordLenOff:], 64)
	binary.LittleEndian.PutUint32(decoy[recordHdrCRCOff:],
		crc32.ChecksumIEEE(decoy[:recordHdrCRCOff]))
	binary.LittleEndian.PutUint32(decoy[recordCRCOff:], 0xdeadbeef)

	raw := append(append([]byte{}, decoy...), rec...)

	if off, res := findNextRecordWithin(raw, 3, 0, 1<<30); res != scanFound {
		t.Fatalf("with budget to spare: got result %v at %d, want scanFound at %d",
			res, off, len(decoy))
	} else if off != len(decoy) {
		t.Fatalf("found the wrong record: offset %d, want %d", off, len(decoy))
	}

	// Enough to charge the decoy (recordCRCOff+64) and no more, so the scan
	// stops with the intact record still ahead of it.
	if _, res := findNextRecordWithin(raw, 3, 0, int64(recordCRCOff)+64); res != scanInconclusive {
		t.Fatalf("out of budget with an intact record still ahead: got %v, want "+
			"scanInconclusive; scanNothingFound here is the interior-corruption defect -- replayLog "+
			"truncates on it and the record above is committed data", res)
	}
}

// TestASpanThatOverrunsTheBufferFromItsOwnPositionIsChargedNothing pins the
// half of the byte budget's guard that the end-to-end tests do not reach: a
// candidate is free when its declared span runs past the end of the buffer
// *measured from that candidate's own position*, not merely when the span is
// absurd in absolute terms.
//
// decodeRecord's torn rejection is `recordHeaderLen+length > len(raw[pos:])`,
// so the guard has to be its exact negation. Dropping the `-pos` term leaves a
// guard that still looks right and still prices the reported bait — those duds
// declare 1<<40, which overruns any buffer from anywhere — while charging full
// span for a candidate whose length merely fits the file. That is the liveness
// bug again: headers that cost crc32 nothing spending budget, packable in
// quantity into a value the network supplies, so the whole scan ends in
// scanInconclusive and Open refuses a log whose only damage is a torn tail.
//
// The discriminator is the budget: it is exactly what the one intact record
// costs. The correct guard charges the decoy nothing and finds the record; a
// guard missing `-pos` charges the decoy first and never gets there.
func TestASpanThatOverrunsTheBufferFromItsOwnPositionIsChargedNothing(t *testing.T) {
	rec, err := encodeRecord(func() *Batch {
		b := &Batch{}
		b.Put([]byte("height"), []byte("7"))
		return b
	}(), 3, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Leading filler so that a span can be in bounds counted from offset 0 and
	// out of bounds counted from the decoy. It holds no magic, so the scan
	// walks straight past it.
	filler := make([]byte, 64)

	// Declares one byte more than the bytes that actually follow it, which is
	// decodeTorn: no payload of it is ever checksummed.
	decoy := make([]byte, recordHeaderLen)
	copy(decoy[recordMagicOff:], recordMagic[:])
	binary.LittleEndian.PutUint64(decoy[recordLenOff:], uint64(len(rec))+1)
	binary.LittleEndian.PutUint32(decoy[recordHdrCRCOff:],
		crc32.ChecksumIEEE(decoy[:recordHdrCRCOff]))

	raw := append(append(append([]byte{}, filler...), decoy...), rec...)
	if _, _, _, _, status := decodeRecord(raw[len(filler):]); status != decodeTorn {
		t.Fatalf("setup: the decoy classifies as %v, want decodeTorn", status)
	}
	if int64(recordHeaderLen)+int64(len(rec))+1 > int64(len(raw)) {
		t.Fatal("setup: the decoy's span must be in bounds counted from offset 0")
	}

	// Exactly what the intact record costs and not one byte more.
	budget := int64(recordCRCOff) + int64(len(rec)-recordHeaderLen)
	off, res := findNextRecordWithin(raw, 3, 0, budget)
	if res != scanFound {
		t.Fatalf("got %v, want scanFound at %d: the decoy is rejected by arithmetic and "+
			"reads no payload, so it must be charged nothing", res, len(filler)+len(decoy))
	}
	if off != len(filler)+len(decoy) {
		t.Fatalf("found the wrong record: offset %d, want %d", off, len(filler)+len(decoy))
	}
}
