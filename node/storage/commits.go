package storage

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
)

// The commit sidecar: one durable answer to the only question recovery cannot
// ask the log. It closes two shapes: a cut that deletes a committed
// transaction when a group loses both its first part and its commit record,
// and the silent boot-time discard of a group that loses an interior part and
// its commit record.
//
// Recovery has one hard question left after the interior-corruption defect, the
// damaged-header refusal, the holed uncommitted group, the missing operator
// recovery path and the payload-plant defect have each taken their turn at it:
// when the log is damaged and no record behind the damage declares itself the
// last of its transaction, was a commit record never written, or was one
// written, fsynced, and then destroyed? Those two histories are BYTE-IDENTICAL
// — reproduced three times, most recently as a 613-byte log with sha256
// ce31a49… produced by driving the real Store down both paths — so no function
// of this log's bytes can separate them. Every attempt to separate them from
// inside the file is a guess, and this package has now shipped three of them.
//
// The fact that separates the two histories is not in the log and cannot be put
// there: it is WHETHER THE LOG'S OWN FSYNC RETURNED. A record of that fact must
// therefore be ordered after that fsync, and making the record itself durable
// needs a second fsync. Two barriers is a lower bound on answering the question
// at all, not an implementation cost — which is why the price was put to the
// owner and ratified rather than optimised away: one extra device flush per
// commit.
//
// # What is written
//
// A separate file, `commits`, preallocated to one page and never resized, so
// no commit ever changes its length, allocates a block, or touches a directory
// entry. It holds two self-checksummed 32-byte slots written alternately; the
// reader takes the verifying slot with the higher write counter. The slots are
// a device sector apart so that one torn sector write cannot damage both — the
// surviving one then holds the previous commit's value, which is stale by one
// commit and therefore LOW. The reader orders the two by WRITE COUNTER and
// never by the number they carry; see readCommitEvidence for why that is not
// interchangeable and for what it costs when the newest slot is the damaged
// one.
//
// # Why the ordering this file was commissioned with is the wrong one
//
// The design this file was written to required, twice over in its own text,
// that the sidecar be fsynced AHEAD of the log
// write. That was measured false in both halves and the correction is
// load-bearing here. An ordinary crash lands after the commit record's write and
// before the barrier returns, so an intent fsynced ahead of that write is
// already durable in the crashed history too: both histories were about to do
// the same thing, the directory digests come out identical, and the rule the
// record feeds then REFUSES A BOOT AFTER AN ORDINARY CRASH — LAUNCH.md §3 case
// 4. Recording what the writer intended separates nothing. Recording that the
// barrier returned separates everything, and can only be done after it returns.
//
// The objection to the after order does not survive the same look: a crash
// between the log's fsync and this one leaves the sidecar stale, and stale here
// is stale LOW, which is exactly today's answer. CommitGroup had not returned,
// so no caller was ever told the transaction committed.
//
// # What the number means, and what that obliges of a reader
//
// THE CONTRACT, STATED ONCE AND HERE: the slot holds the highest sequence this
// store HAS REPORTED COMMITTED, OR HAS APPLIED FROM ITS OWN LOG ON A CLEAN
// REPLAY. Two producers write it, and they are not the same sentence:
//
//   - recordCommitLocked, after the log's own fsync RETURNED — the instant at
//     which, and not before, a caller was told the transaction landed. That is
//     the sentence the ordering argument above rests on, and it is the whole
//     reason this file can separate two byte-identical histories.
//   - Open's restatement, from what a clean replayLog just accounted for: the
//     highest sequence the log holds, in a store that replayed without
//     refusing. Weaker, and load-bearing for a different job — it heals a
//     sidecar left stale-low by a failed write, and it converts a data
//     directory written by a build that had no sidecar.
//
// They disagree on exactly one crash: one landing between a commit record's
// write and its barrier returning. The record is complete and in sequence, so
// replay applies it and the restatement names it — but Commit returned an error
// or never returned, and no caller was ever told. Each site used to document
// only its own sentence, so the field meant "a caller was told" on one boot and
// "this log holds it and replay applied it" on the next. The union is stated
// instead of either half, because this whole file exists because a reader
// inferred something a field could not support, and one field carrying two
// meanings is that same trap rebuilt.
//
// WHAT A READER MAY INFER IS THEREFORE THE WEAKER HALF ONLY: nothing tells a
// reader which producer wrote the value in its hand, so a reader that is correct
// only under "a caller was told" is asking this file for a fact it does not
// carry. The one reader today is withholds, and it passes — it withholds cuts
// and authorises none, and declining to discard a sequence this log held and a
// clean replay applied is conservative under both sentences.
//
// One residual is recorded rather than half-fixed: the refusal text store.go and
// repair.go print still names the stronger producer ("written and fsynced after
// the log's own barrier returned"), which overstates for a restated value. The
// operator's action is `resync` under either sentence, and the two sites have to
// move together — a boot path and a `repair` explaining one rule in two
// spellings is exactly the drift that let a store be discarded on boot while
// `repair` said there was nothing to repair.
//
// # How it is read, and the property that makes it safe
//
// In ONE DIRECTION ONLY: recovery refuses a cut when the sidecar verifies and
// its highest committed sequence is at or above the first sequence the cut would
// remove. It never authorises a cut, never lowers a refusal to an offer, and is
// never consulted to decide anything else. So THERE IS NO BYTE STRING IN
// `commits` THAT MAKES THIS STORE DELETE SOMETHING IT KEEPS TODAY — absent,
// stale, torn, unreadable and deliberately deleted all degrade to "no evidence",
// and no evidence is today's behaviour. That is the property the owner's
// ratification named as the one the implementation must pin, and it is why this
// file needs no recovery story of its own.
//
// The direction is deliberately not symmetric. A verifying sidecar whose high
// is BELOW the cut is a proof that nothing committed sits behind the damage, so
// it could authorise a cut where the scan found record-shaped bytes inside a
// payload — which would close the payload-plant defect. Taking that would make
// the file readable in both directions and destroy the property above: a deleted
// `commits` would then authorise a deletion. The payload-plant defect stays open;
// see docs/RUNNING.md's recovery section for what remains of it.
//
// # The one state this cannot recover from, and who can create it
//
// A sidecar naming MORE than the log holds refuses every future boot, because
// replayLog treats a clean log that cannot account for a committed sequence as
// the fault having removed the record rather than damaged it. Every writer here
// avoids it by making the low value durable first: the commit path writes after
// the log's barrier, compaction resets before the truncate, Apply lowers before
// the cut.
//
// A BUILD WITHOUT THIS FILE DOES NOT. `zycordd repair` from an older binary
// shortens the log and leaves `commits` untouched, and a newer binary opened on
// that directory afterwards refuses it permanently. The format version is
// deliberately not bumped — an old build ignoring this file and a new build
// finding none both degrade correctly — so nothing stops the downgrade, and the
// remedy is the one the refusal already names: resync. Run the repair with the
// binary the node runs.
const commitsName = "commits"

const (
	// commitSlotLen is one slot; see the layout comment on encodeCommitSlot.
	commitSlotLen = 32

	// commitSlotStride puts the two slots in different 512-byte device
	// sectors. A torn write is a sector-granularity event, so this is what
	// makes "at most one slot can be damaged by one write" a statement about
	// the device rather than a hope about the file system.
	commitSlotStride = 512

	// commitsFileLen is one page, preallocated at creation and never changed.
	// A commit's write is a pwrite into an already-allocated, already-named
	// file: no size change, no block allocation, no directory entry to fsync.
	// That is what keeps the ratified cost at exactly one extra device flush
	// rather than a flush plus a metadata transaction.
	commitsFileLen = 4096
)

// commitsMagic prefixes each slot. Its last byte is the format version, for the
// same reason recordMagic's is: a slot written by another build must read as
// absent rather than as a number.
var commitsMagic = [4]byte{'C', 'M', 'T', FormatVersion}

// Slot field offsets.
const (
	commitMagicOff   = 0
	commitCounterOff = 4
	commitHighOff    = 12
	commitCRCOff     = 28
)

// encodeCommitSlot lays out one slot:
//
//	[0:4]   magic, last byte the format version
//	[4:12]  writeCounter, little-endian; the reader takes the higher
//	[12:20] highPlusOne, little-endian; ZERO MEANS "nothing committed"
//	[20:28] reserved, zero
//	[28:32] crc32 over [0:28]
//
// highPlusOne rather than the sequence itself, because sequence 0 is a real
// committed sequence and a fresh or just-compacted log has to be able to say
// "none" without saying "sequence 0 committed". Encoding "none" as a zero
// sequence would make a brand-new log refuse its own first torn tail, since the
// rule's test is high >= firstCutSeq and firstCutSeq is 0 there.
func encodeCommitSlot(counter, highPlusOne uint64) []byte {
	var slot [commitSlotLen]byte
	copy(slot[commitMagicOff:], commitsMagic[:])
	binary.LittleEndian.PutUint64(slot[commitCounterOff:], counter)
	binary.LittleEndian.PutUint64(slot[commitHighOff:], highPlusOne)
	binary.LittleEndian.PutUint32(slot[commitCRCOff:], crc32.ChecksumIEEE(slot[:commitCRCOff]))
	return slot[:]
}

// decodeCommitSlot reads one slot, reporting ok only when the magic, the
// version and the checksum all agree.
func decodeCommitSlot(raw []byte) (counter, highPlusOne uint64, ok bool) {
	if len(raw) < commitSlotLen {
		return 0, 0, false
	}
	for i := range commitsMagic {
		if raw[i] != commitsMagic[i] {
			return 0, 0, false
		}
	}
	if binary.LittleEndian.Uint32(raw[commitCRCOff:]) !=
		crc32.ChecksumIEEE(raw[:commitCRCOff]) {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(raw[commitCounterOff:]),
		binary.LittleEndian.Uint64(raw[commitHighOff:]), true
}

// commitEvidence is what the sidecar established, and it is deliberately a
// two-field answer rather than a sequence with a sentinel.
//
// `verified` false is "no evidence" — file absent, unreadable, both slots
// failing their checksums, or written by another format version. `verified`
// true with `has` false is the positive statement "nothing is committed in this
// log generation", which is what a fresh directory and a just-compacted store
// both say. Only `verified && has` can withhold a cut.
type commitEvidence struct {
	verified bool
	has      bool
	high     uint64
	counter  uint64
}

// withholds reports whether this evidence forbids a cut whose first discarded
// sequence is firstCutSeq.
//
// This is the whole recovery rule, in one place, so that replayLog's boot path
// and Diagnose's operator path cannot drift into two spellings of it — which is
// exactly the drift this file exists to prevent: `repair` asked a question the
// boot path did not, and printed "Nothing to repair — start the node" about a
// store the start deleted a committed transaction from.
func (e commitEvidence) withholds(firstCutSeq uint64) bool {
	return e.verified && e.has && e.high >= firstCutSeq
}

// readCommitEvidence reads the sidecar out of a data directory.
//
// Every failure is "no evidence", including an I/O error, and that is a
// decision rather than an oversight. The only thing evidence can do is withhold
// a cut, so failing open here returns precisely today's behaviour; failing
// closed would invent a new way for a node not to start, on a file that did not
// exist yesterday. Absent, stale, unreadable, or both slots failing their
// checksums all supply no evidence.
//
// The error is returned alongside so a caller on the boot path can say so out
// loud without acting on it.
//
// # The selection rule: the higher COUNTER, never the higher HIGH
//
// Of the slots that verify, this takes the one whose write counter is greater,
// and it reads that slot's number. It does NOT take the greatest number it can
// find. The distinction looks like a nicety and is the difference between a
// store that boots and one that cannot, because THE VALUE IS NOT MONOTONE. Three
// writers deliberately LOWER it — compaction resets it to "none" before the log
// is truncated, Repairer.Apply lowers it before the cut, and Open's restatement
// can lower it to what a clean replay accounted for — and each of them leaves
// the previous, HIGHER number sitting in the other slot, which is still intact
// and still verifies. A reader that took the greater number would resurrect the
// pre-compaction generation's high-water mark against a log whose sequences
// restarted at zero, which is precisely the sidecar-claims-more-than-the-log-
// holds state this design cannot recover from: every future boot refused, for
// ever. The counter is the only field that is monotone, so the counter is what
// orders the slots.
//
// # What that costs when the newest slot is the damaged one
//
// It follows that damaging the slot with the HIGHER counter makes this function
// return the previous commit's number: verified evidence carrying a high-water
// mark one commit below the truth. That is measured and it is inherent, not an
// oversight — the surviving slot is the only number on the device that can be
// trusted, and there is no way to tell a torn write of counter c+1 from later
// rot on a durable counter c-1.
//
// It degrades in the withholding direction, and the amount lost is one commit's
// worth of evidence rather than all of it. THAT SECOND HALF IS THE PART TO
// PROTECT. The named fix, if this ever needs closing, is "require the
// highest counter slot to verify, rather than accepting evidence that verifies
// on the lower slot alone". Applied TODAY that is a regression and it was
// measured as one: on the class fixture with the group's commit record holed,
// corrupting the newest slot takes the evidence from high=4 to high=1, and
// high=1 STILL WITHHOLDS the cut, because the cut removes sequence 1 onward.
// Discarding the surviving slot would take the evidence to none, and the store
// would then boot and delete a transaction it reported committed — the exact
// class this file exists to remove, reintroduced by a hardening.
//
// The reason that fix is right in the abstract and wrong here is the one the
// finding itself gives: it is a fix for an AUTHORISING read, where an
// under-report becomes a proof that permits a deletion. This read is
// one-directional, so an under-report can only permit what today's behaviour
// already permits. THE CONDITION THAT REVERSES THIS PARAGRAPH IS THEREFORE
// EXACTLY THE REOPENING TRIGGER FOR THAT FINDING: any change that lets a
// sidecar read cause the store to discard something it would otherwise keep.
// Whoever proposes such a change owns this comment, and the two tests below it
// — nothing about the encoding needs to change first.
func readCommitEvidence(dir string) (commitEvidence, error) {
	raw, err := os.ReadFile(filepath.Join(dir, commitsName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return commitEvidence{}, nil
		}
		return commitEvidence{}, err
	}
	var best commitEvidence
	for _, off := range []int{0, commitSlotStride} {
		if off+commitSlotLen > len(raw) {
			continue
		}
		counter, highPlusOne, ok := decodeCommitSlot(raw[off : off+commitSlotLen])
		if !ok {
			continue
		}
		if best.verified && counter <= best.counter {
			continue
		}
		best = commitEvidence{verified: true, counter: counter}
		if highPlusOne > 0 {
			best.has, best.high = true, highPlusOne-1
		}
	}
	return best, nil
}

// nextCommitSlotOffset is where the slot carrying `counter` belongs. Alternating
// is what keeps the previous value readable across a torn write of the new one.
func nextCommitSlotOffset(counter uint64) int64 {
	if counter%2 == 0 {
		return 0
	}
	return commitSlotStride
}

// openCommits opens or creates the sidecar and preallocates it.
//
// Creation is the one place a directory entry is made, and it is fsynced here,
// off the commit path, for the reason Open already syncs the directory when it
// creates the log: a file whose contents are durable and whose name is not is a
// file that vanishes across a power loss. On Windows that directory fsync is
// classified as unsupported and swallowed (syncdir_windows.go), so the name's
// durability there rests on NTFS journalling its own metadata rather than on a
// barrier this package issued. That weakness degrades in the safe direction and
// only in the safe direction: a sidecar whose name did not survive reads as
// absent, absent is no evidence, and no evidence is today's behaviour.
func (s *Store) openCommits() (commitEvidence, error) {
	path := filepath.Join(s.dir, commitsName)
	prior, readErr := readCommitEvidence(s.dir)
	if readErr != nil {
		s.logger.Printf("storage: %s: the commit record sidecar could not be read (%v); "+
			"recovery has already run without it, and this store continues with the log alone",
			s.dir, readErr)
	}
	s.commitCounter = prior.counter
	_, statErr := os.Stat(path)
	isNew := errors.Is(statErr, os.ErrNotExist)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return prior, err
	}
	if isNew {
		if err := f.Truncate(commitsFileLen); err != nil {
			f.Close()
			return prior, err
		}
		if err := s.sync(f); err != nil {
			f.Close()
			return prior, err
		}
		if err := syncDir(s.dir); err != nil {
			f.Close()
			return prior, err
		}
	}
	s.commits = f
	return prior, nil
}

// writeCommitsLocked writes the next slot and makes it durable.
//
// CALLERS MUST ALREADY HAVE TAKEN THE LOG'S BARRIER. Every one of them is
// ordered after a syncLocked that returned, and that ordering is the entire
// mechanism — see this file's opening comment. Writing this before the log's
// fsync returns records an intention rather than a fact, and an intention does
// not separate the two histories.
func (s *Store) writeCommitsLocked(highPlusOne uint64) error {
	if s.commits == nil {
		return nil
	}
	counter := s.commitCounter + 1
	if _, err := s.commits.WriteAt(encodeCommitSlot(counter, highPlusOne),
		nextCommitSlotOffset(counter)); err != nil {
		return err
	}
	if err := s.sync(s.commits); err != nil {
		return err
	}
	s.commitCounter = counter
	return nil
}

// recordCommitLocked publishes that the transaction ending at sequence `seq`
// has been reported committed. It is the second barrier the design costs.
//
// A failure here does NOT fail the commit and does NOT poison the store, and
// that is the one place this file deliberately declines to be strict. By the
// time it runs the log's own fsync has returned: the transaction IS durable and
// WILL be replayed, so returning an error would tell a caller a transaction
// failed that in fact committed — and would leave this process's in-memory view
// missing a mutation its own log holds. The honest degradation is the one the
// design already has a name for: the sidecar stays stale-low, which is no
// evidence, which is today's behaviour. It is logged because a durability
// barrier that stopped working is something an operator needs to be able to
// notice at all.
func (s *Store) recordCommitLocked(seq uint64) {
	if err := s.writeCommitsLocked(seq + 1); err != nil {
		s.logger.Printf("storage: %s: the commit record sidecar could not be updated (%v); "+
			"recovery loses the out-of-band evidence that would refuse a cut over a committed "+
			"transaction, and falls back to reading the log alone", s.dir, err)
	}
}

// writeCommitsFile writes a slot into a data directory without holding an open
// store, for Repairer.Apply.
//
// Apply is the one operation in this design that can brick a store — a sidecar
// left claiming more than the log holds refuses every future boot — so the
// rewrite is a post-condition of the cut rather than a judgement call, and
// Apply calls it BEFORE the truncation, so that a crash in between leaves the
// sidecar low against a log that was not shortened rather than high against one
// that was.
//
// THIS COMMENT SAID THE OPPOSITE, and the correction is recorded rather than
// quietly applied because after-first is precisely the brick. It was not a
// typo: "fsynced after the truncation is durable" is the design document's own
// wording, written before the clean-log refusal existed, and the code
// in repair.go and store.go moved to lowered-first without it. So the sentence
// to trust is the one in Repairer.Apply, which is next to the two statements it
// orders; if this file and that one ever disagree again, that one is right and
// this one is a document that outlived its design. A review found it here, on
// the only function in the package whose ordering can make a store unbootable.
func writeCommitsFile(dir string, highPlusOne uint64) error {
	path := filepath.Join(dir, commitsName)
	prior, err := readCommitEvidence(dir)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < commitsFileLen {
		if err := f.Truncate(commitsFileLen); err != nil {
			return err
		}
	}
	counter := prior.counter + 1
	if _, err := f.WriteAt(encodeCommitSlot(counter, highPlusOne),
		nextCommitSlotOffset(counter)); err != nil {
		return err
	}
	return f.Sync()
}
