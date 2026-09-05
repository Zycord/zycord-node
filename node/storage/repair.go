package storage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Repair is the operator-invoked half of the recovery policy, and it exists
// because Open's half is deliberately incomplete.
//
// Open refuses whenever it cannot *prove* that discarding the tail of the log
// loses nothing committed. That refusal is the right default — a reader that
// guesses is the bug this package spent three findings removing — but on its
// own it turns a class of recoverable damage into a node that never boots
// again: the damaged-header refusal, where the last record of a crashed log
// carries a network-supplied block body that happens to contain record-shaped
// bytes, is an ordinary torn tail that Open declines to treat as one. There was
// no second door — a storage refusal to open was permanent, undocumented and
// had no operator recovery path. This is it.
//
// What separates this door from simply relaxing Open is that a human opens
// it, having been shown what goes and what stays, and that it is narrower
// than "delete the tail" in the one direction that matters. The rule it
// enforces is the one the holed-uncommitted-group analysis settled, carried
// across:
//
//	a cut is offered only when no record behind the damage decodes intact
//	and declares itself the last record of its transaction.
//
// Every committed transaction — an ordinary commit or a group — ends in a
// record with more == 0. So if none is found behind the damage, the only
// things back there are parts of a transaction whose own terminal record is
// unreadable, and no reader could ever have applied that transaction. The cut
// then loses nothing that was reported committed. If one *is* found, that
// record is a committed transaction sitting behind the damage, cutting would
// delete it, and this command says so and stops: that store needs a resync,
// not a repair.
//
// This rule is strictly stronger than "is the damage at the end of the file",
// and it is what makes a hole in a group's FIRST part recoverable rather than
// terminal. Such a hole leaves replay with no group open, so the surviving
// later parts are not dismissed and Open refuses — yet every one of them
// carries more >= 1, so no terminal record is behind the damage and the
// transaction is abandoned. Repair may cut it. Interior damage with real
// commits behind it is refused by the same test, with no special case for
// either.
//
// Repair never touches the snapshot and never rewrites a record. Its only
// effect on disk is to shorten the log at one offset, durably.
type Repairer struct {
	dir  string
	lock *dirLock
}

// repairScanBudgetMultiple scales findNextRecord's boot budget for a scan
// that is not on the boot path.
//
// The boot budget is sized to bound work a *remote* party can provoke on
// every start (see findNextRecordScanBudgetFloor); running out there is
// scanInconclusive and a refusal to open. Here the scan runs once, offline,
// in a process an operator started on purpose and can stop, so the same
// exhaustion is the worse of the two trades — it is the difference between
// recovering the node and not — and buying more of it costs no availability.
// It is a multiple rather than "unbounded" because the work is quadratic in
// the region against crafted input, and an unbounded scan is a repair command
// that never returns and reports nothing, which helps no one.
const repairScanBudgetMultiple int64 = 64

// OpenForRepair takes the data directory's lock and holds it until Close.
//
// Taking the same lock Open takes is the whole answer to "may this run
// against a live node": it may not. A repair reads the log, decides on an
// offset, and truncates there; a node appending records concurrently would
// make each of those three steps describe a different file. The refusal is
// ErrLocked, and it names the directory.
func OpenForRepair(dir string) (*Repairer, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	lock, err := acquireDirLock(dir)
	if err != nil {
		return nil, err
	}
	return &Repairer{dir: dir, lock: lock}, nil
}

// Close releases the directory lock.
func (r *Repairer) Close() error { return r.lock.release() }

// Verdict names WHICH of the four Repairable == false states a refusal
// behind the damage is in.
//
// It exists because the verdict line and the exit code otherwise collapse
// "proven unsafe to cut" into "not proven safe to cut".
//
// All four refuse, all four exit 1, and only ONE of them is a store that is
// provably unsafe to cut. The other three are stores that may be perfectly
// recoverable and are being resynced for want of an instrument, and until
// this field existed an operator reading the last line of `zycordd repair`
// could not tell them apart — nor could a runbook step, which is the shape
// that matters on a public network where the runbook is what actually runs.
//
// IT IS A REPORT AND NOTHING ELSE, and that is the constraint to keep. The
// reason repair refuses in the three unproven states is not that it lacks a
// flag; it is that no local instrument can answer the question at all. A field
// that DISTINGUISHES them is a report; a field that could be OVERRIDDEN would
// be the operator force-cut flag that was proposed and rejected twice, wearing
// a different name — and FoundRecordDisproved is the most dangerous one to hang
// a lever off, because "the record found was disproved" reads like "safe to
// cut" and is not: the search stopped at its first candidate and never looked
// past it. So nothing in this package reads this field to decide anything,
// Apply does not consult it, and there is no setter, flag or environment
// variable that lets it alter what repair offers.
type Verdict int

const (
	// VerdictNone: this report is not one of the four states below. Every
	// other outcome carries it — an undamaged store, a version mismatch, a
	// damaged snapshot, a refusal that needed no search behind the damage,
	// and an offered cut. It is the zero value so that a report which never
	// reached the search cannot accidentally read as one that did.
	VerdictNone Verdict = iota

	// ProvenUnsafeToCut: the damaged record's frame verified, so its end is a
	// fact, and walking whole records forward from that end lands exactly on
	// the record the search found. A writer framed that record and it
	// declares a completed transaction. This is the only one of the four that
	// asserts anything, and the only one where "resync this store" is right
	// on its merits rather than for want of an instrument.
	ProvenUnsafeToCut

	// FoundRecordDisproved: the frame verified and the walk steps straight
	// over the offset from inside one of its own frames, so those bytes are
	// content a record carries — a block body accepted over the network and
	// written verbatim — and they committed nothing. A proof in the opposite
	// direction. The store is STILL refused, because the search stopped at
	// that first candidate and what lies past it is unread.
	FoundRecordDisproved

	// BlockedBySecondDamage: the walk was stopped by a second damaged record
	// before it reached the offset, so nothing past the blocker was
	// established. SecondDamageOffset names that blocker, which is
	// exactly the information about a second damage site that the operator gets
	// nowhere else, and which decides whether a cut is safe at all.
	BlockedBySecondDamage

	// SearchBeganInsideDamage: the damaged record's own frame failed its
	// checksum, so there was no honest end to search from and the region
	// began at that record's first byte — including its payload. The
	// payload-plant defect proper.
	SearchBeganInsideDamage
)

// String names a Verdict in operator- and test-facing output. Without it %v
// prints an integer, and a diagnostic that reports "2, not 4" about the field
// whose whole purpose is telling four states apart is the defect one level up.
func (v Verdict) String() string {
	switch v {
	case VerdictNone:
		return "VerdictNone"
	case ProvenUnsafeToCut:
		return "ProvenUnsafeToCut"
	case FoundRecordDisproved:
		return "FoundRecordDisproved"
	case BlockedBySecondDamage:
		return "BlockedBySecondDamage"
	case SearchBeganInsideDamage:
		return "SearchBeganInsideDamage"
	}
	return fmt.Sprintf("Verdict(%d)", int(v))
}

// LogDiagnosis is what a repair scan established, in terms an operator can
// act on. It is deliberately a report and not a decision: Apply re-derives it
// rather than trusting it.
type LogDiagnosis struct {
	Path string
	Size int64

	// RecordsIntact is how many records replay reads before it stops.
	//
	// It is NOT how many survive the cut this report offers, and an earlier
	// revision of this comment said it was. Inside an open transaction the
	// cut goes back to that transaction's first record, so every part of it
	// replay already read is discarded with it — see RecordsKept, which is
	// the number an operator is deciding about.
	RecordsIntact uint64

	// RecordsKept is how many records survive the cut this report offers:
	// sequences 0..RecordsKept-1 remain. Meaningful only when Repairable.
	//
	// It is a separate field rather than a second reading of RecordsIntact
	// because the two are separate facts and collapsing them is what let a
	// report offer to discard a multi-record transaction whole and, in the
	// same sentence, name that transaction's own parts among what it keeps.
	RecordsKept uint64

	// Damaged is false when Open would succeed on this directory as it
	// stands — including the case where Open performs its own truncation.
	Damaged bool

	// Offset is the first byte a repair would discard, and Discard is how
	// many bytes that is. Meaningful only when Repairable.
	Offset  int64
	Discard int64

	// Repairable is whether a cut at Offset is offered at all.
	Repairable bool

	// Verdict names which of the four refusal states this report is in, or
	// VerdictNone for every other outcome. See Verdict: it is read only to
	// choose which sentence an operator is shown, never to decide anything.
	Verdict Verdict

	// SecondDamageOffset is the offset of the second damaged record that
	// stopped the frame walk. Meaningful only when Verdict is
	// BlockedBySecondDamage.
	//
	// It is an offset and not a count, deliberately: no third count-shaped field
	// may join RecordsIntact and RecordsKept, because two adjacent unlabelled
	// counts are exactly what let a report offer to discard a transaction whole
	// while naming a number that described something else. A second
	// damage SITE is a different fact and the operator has nowhere else to
	// read it.
	SecondDamageOffset int64

	// Explanation is the finding in operator-facing terms: what the damage
	// is, and either what the cut costs or why no cut is offered.
	Explanation string
}

// ErrNotRepairable is returned by Apply when the diagnosis offers no cut.
var ErrNotRepairable = errors.New("storage: this damage is not repairable by truncation")

// Diagnose inspects the directory and changes nothing on disk.
//
// It re-walks the log's intact prefix with the same rules replayLog uses,
// rather than sharing that loop, because the two ask different questions:
// replayLog decides what a *boot* may do unattended, this decides what an
// operator may authorise, and the answers deliberately differ. Sharing the
// loop would be one policy pretending to be two. The prefix walk must not
// drift, though, so a test pins the offset this reports against the offset
// Open's own refusal names.
func (r *Repairer) Diagnose() (*LogDiagnosis, error) {
	path := filepath.Join(r.dir, logName)
	d := &LogDiagnosis{Path: path}

	// The snapshot is checked first and is never repaired. A log cut cannot
	// recover a damaged snapshot — the log holds only what was written since
	// it — so offering one would be offering to delete data for no benefit.
	snap, err := os.ReadFile(filepath.Join(r.dir, snapshotName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if _, decErr := decodeSnapshot(snap); decErr != nil {
			// A snapshot this build cannot read is not a damaged one, and the
			// distinction has to be drawn here and not only for the log. The
			// snapshot is checked first, so on any store that has ever
			// compacted the log's own version branch below is unreachable —
			// a node started against the wrong binary would have been told
			// its store was destroyed and to resync, which is a runbook that
			// throws away a directory whose bytes are perfectly intact.
			if errors.Is(decErr, ErrFormat) {
				d.Explanation = fmt.Sprintf("%v. That is not damage — those bytes mean "+
					"something this build does not read, and discarding them would destroy a "+
					"snapshot some other build reads perfectly. No cut is offered — run the "+
					"matching binary.", decErr)
				return d, nil
			}
			d.Damaged = true
			d.Explanation = fmt.Sprintf("the snapshot is damaged (%v); the log holds only what "+
				"was written after it, so no cut to the log can recover this. No cut is "+
				"offered — this store has to be resynced from the network.", decErr)
			return d, nil
		}
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		d.Explanation = "there is no log in this directory; nothing to repair."
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.Size = int64(len(raw))

	if len(raw) >= 4 && raw[0] == recordMagic[0] && raw[1] == recordMagic[1] &&
		raw[2] == recordMagic[2] && raw[3] != FormatVersion {
		// Damaged stays false, and the boolean is the whole point of this
		// correction. The prose here has always said "that is not damage"
		// while the field said the opposite, and cmd/zycordd/repair.go reads
		// the field: with Damaged true and Repairable false it prints "NOT
		// REPAIRABLE ... Resync this store from the network" — a runbook that
		// throws away a directory whose bytes are perfectly intact, over a
		// version number. That is the exact failure the snapshot branch above
		// was written to avoid, arriving through the flag instead of the text.
		//
		// It was unreachable until now: with no version-2 store anywhere, no
		// log could carry a version this build refuses. The bump to format 4 makes
		// every existing store hit this branch, so the mismatch would have
		// shipped as its first observable behaviour. An old store is refused by
		// version and NOT reported as corruption; the operator is sent to the
		// matching binary, and it is the owner's decision — not this
		// diagnosis — that the remedy before genesis is a resync.
		d.Explanation = fmt.Sprintf("this log was written in format version %d and this build "+
			"reads version %d. That is not damage, and discarding it would destroy a log some "+
			"other build can read. No cut is offered — run the matching binary.",
			raw[3], FormatVersion)
		return d, nil
	}

	var (
		consumed      int
		expectedSeq   uint64
		groupStart    int
		groupSeq      uint64
		groupFinalSeq uint64
		groupOpen     bool
		status        decodeStatus
		frameLen      int
		badSeq        uint64
	)
	for consumed < len(raw) {
		_, seq, more, n, st := decodeRecord(raw[consumed:])
		status, frameLen, badSeq = st, n, seq
		if st != decodeOK || seq != expectedSeq {
			break
		}
		if groupOpen && seq+uint64(more) != groupFinalSeq {
			// A verified header, in sequence, declaring the wrong countdown.
			// These bytes are as some writer wrote them, so this is not an
			// unfinished write, and a cut here would discard whatever else
			// that writer put behind it.
			d.Damaged = true
			d.Explanation = fmt.Sprintf("the record at offset %d carries a header that passed "+
				"its own checksum yet declares %d further part(s) of the transaction beginning "+
				"at offset %d, where %d was expected. A crash cannot produce that; something "+
				"wrote it. No cut is offered — resync this store.",
				consumed, more, groupStart, groupFinalSeq-seq)
			return d, nil
		}
		if more > 0 {
			if !groupOpen {
				groupOpen, groupStart, groupSeq, groupFinalSeq = true, consumed, seq, seq+uint64(more)
			}
		} else {
			groupOpen = false
		}
		consumed += n
		expectedSeq++
	}
	d.RecordsIntact = expectedSeq

	// The out-of-band evidence, read once and consulted through the same
	// commitEvidence.withholds replayLog uses. Reading it here rather than
	// re-deriving anything is the whole answer to the wiring half of the
	// boot/repair drift: the boot path and this one now ask ONE function about
	// ONE durable fact, so "Nothing to repair — start the node" cannot be
	// printed about a store the start refuses, and no cut can be offered over a
	// transaction the store reported committed.
	//
	// A read failure is no evidence, exactly as on the boot path, and for the
	// same reason: evidence can only withhold a cut.
	evidence, _ := readCommitEvidence(r.dir)

	if consumed == len(raw) {
		// A log with no damage in it can still fail to account for a committed
		// sequence, if the fault REMOVED the record rather than damaging it.
		// replayLog refuses there; this must say the same thing, or the
		// instrument an operator runs prints the most confident sentence it has
		// about a store the node will not start (that same drift, arrived at
		// from the undamaged side).
		firstMissing := expectedSeq
		if groupOpen {
			firstMissing = groupSeq
		}
		if evidence.withholds(firstMissing) {
			d.Damaged = true
			d.Explanation = fmt.Sprintf("the log reads to its end and accounts for sequences up "+
				"to %d, but this store's commit record, written and fsynced after the log's own "+
				"barrier returned, says sequence %d was reported committed. The record that "+
				"committed it is not in this log. This is also the state left behind by "+
				"`zycordd repair` run with a binary older than this one — see docs/RUNNING.md: "+
				"run repair with the same binary the node runs. No cut is offered — nothing to "+
				"cut would bring it back; resync this store.", firstMissing, evidence.high)
			return d, nil
		}
		// Either the log is wholly intact, or it ends part-way through a
		// transaction with every surviving part readable. Open handles the
		// second case itself and reports what it discarded, so there is
		// nothing here for an operator to authorise.
		if groupOpen {
			// groupSeq is both the sequence the discarded transaction begins
			// at and the count of records in front of it, because the prefix
			// walk above breaks on seq != expectedSeq and so numbers the
			// readable prefix densely from zero. expectedSeq is the wrong
			// number here and reads as the reassuring one: it counts the
			// parts this transaction already wrote, which go with it.
			d.Explanation = fmt.Sprintf("the log ends part-way through a multi-record "+
				"transaction (beginning at sequence %d), and starting the node discards that "+
				"transaction on its own; the %d record(s) before it are intact. Nothing to "+
				"repair.", groupSeq, groupSeq)
			return d, nil
		}
		d.Explanation = fmt.Sprintf("the log reads to its end; %d record(s) intact. Nothing to "+
			"repair.", expectedSeq)
		return d, nil
	}

	d.Damaged = true

	// Where a repair would cut. Inside an open transaction the cut goes back
	// to that transaction's first record, for replayLog's reason: its earlier
	// parts were never applied, and leaving them on disk would put them in
	// front of whatever the next commit writes, where a later record
	// declaring itself the end of a transaction would sweep them in.
	//
	// The number of records that survive that cut travels WITH it, in the same
	// assignment, because they are one fact: the cut lands where record number
	// `kept` begins, so sequences 0..kept-1 are what is left. They were two
	// statements, and only one of them moved when the cut moved back to
	// groupStart — so a report that said in one clause that the transaction "is
	// discarded whole" said in the next that the cut kept that transaction's
	// own parts. Measured on a store where the offer named three surviving
	// records and the repair left one.
	cut, kept := int64(consumed), expectedSeq
	if groupOpen {
		cut, kept = int64(groupStart), groupSeq
	}

	// scanFrom is where the search for committed data behind the damage may
	// begin, relative to consumed. -1 means the damage itself already proves
	// no cut can be offered, so no search is run. These cases match
	// replayLog's, and for the same reasons — see decodeStatus.
	scanFrom := -1
	switch status {
	case decodeOK:
		d.Explanation = fmt.Sprintf("the record at offset %d is completely intact — header "+
			"checksum, record checksum and contents — but carries sequence number %d where %d "+
			"was expected. A crash produces a missing or truncated record, never a well-formed "+
			"one out of order, so these bytes were written by something this store did not "+
			"expect. No cut is offered — resync this store.", consumed, badSeq, expectedSeq)
		return d, nil
	case decodeMaxLenExceeded:
		d.Explanation = fmt.Sprintf("the record at offset %d carries a header that passed its "+
			"own checksum and declares a payload larger than this format ever writes. A flipped "+
			"bit would have broken that checksum, so these bytes are as some writer wrote them. "+
			"No cut is offered — resync this store.", consumed)
		return d, nil
	case decodeTorn:
		// Proven short write: nothing can exist past it, so there is nothing
		// to search for.
	case decodeHeaderUntrusted:
		scanFrom = 0
	case decodePayloadBad:
		scanFrom = frameLen
	}

	// Before offering anything, ask whether Open would refuse this at all.
	//
	// A tool that deletes data on purpose must not offer to delete data that
	// nothing needed deleted. replayLog truncates a tail itself whenever its
	// own broad search — any intact record, the boot budget, the open group's
	// own membership dismissal — comes back empty, and a proven short write skips
	// that search and is truncated outright. In both of those the node boots
	// and discards exactly these bytes on its own, so the honest report is
	// "start the node", not an irreversible cut behind a yes/no prompt. This
	// asks replayLog's question with replayLog's own function and its own
	// boot budget, because the answer being mirrored is literally "what will
	// Open do"; a scanInconclusive here is Open refusing, and is precisely
	// the case the wider budget below exists to settle.
	selfHealing := status == decodeTorn
	if !selfHealing && scanFrom >= 0 && scanFrom <= len(raw)-consumed {
		openGroupFinalSeq := uint64(0)
		if groupOpen {
			openGroupFinalSeq = groupFinalSeq
		}
		bootRegion := raw[consumed+scanFrom:]
		if _, res := findNextRecord(bootRegion, expectedSeq, openGroupFinalSeq); res == scanNothingFound {
			selfHealing = true
		}
	}
	// kept is the count of records in front of the cut and, because the prefix
	// walk numbers them densely from zero, it is also the FIRST SEQUENCE THE CUT
	// REMOVES — which is what the rule compares against.
	if evidence.withholds(kept) {
		d.Explanation = fmt.Sprintf("the record at offset %d is damaged, and discarding from "+
			"offset %d would remove sequence %d onward — but this store's commit record, "+
			"written and fsynced after the log's own barrier returned, says sequence %d was "+
			"reported committed. A commit record this log can no longer account for did land, "+
			"so the transaction it committed is behind the damage. No cut is offered — resync "+
			"this store.", consumed, cut, kept, evidence.high)
		return d, nil
	}
	if selfHealing {
		d.Damaged = false
		what := fmt.Sprintf("the log ends in %d unreadable byte(s) at offset %d",
			int64(len(raw))-cut, cut)
		if groupOpen {
			what = fmt.Sprintf("the log ends part-way through the multi-record transaction "+
				"beginning at offset %d (sequence %d)", groupStart, groupSeq)
		}
		d.Explanation = fmt.Sprintf("%s, and starting the node discards them on its own; the "+
			"%d record(s) before that are intact. Nothing to repair — start the node.",
			what, kept)
		return d, nil
	}

	if scanFrom >= 0 && scanFrom <= len(raw)-consumed {
		region := raw[consumed+scanFrom:]
		budget := repairScanBudgetMultiple * bootScanBudget(len(region))
		at, result := findTerminalRecordWithin(region, expectedSeq, budget)
		switch result {
		case scanFound:
			// What a hit means depends on where the search was allowed to
			// begin, and this is the same test replayLog applies to the same
			// question one function away — deliberately spelled the same way
			// so the two cannot drift into disagreeing about the same bytes.
			//
			// They did disagree. replayLog has been conditioned on the region
			// since the second door was opened: with the frame unusable it says
			// a hit "is either data written after this one or record-shaped
			// bytes inside this one's own payload. This reader cannot tell
			// which". This sentence stated the stronger reading
			// unconditionally, so on the shape the payload-plant defect
			// describes the node said the question was open and the instrument
			// an operator runs *next*, to decide whether to throw the directory
			// away, told them a committed transaction was provably behind the
			// damage. The verdict was right; the reason given for it was a
			// guess presented as a fact, in the direction that costs a resync
			// of a store that may be intact.
			//
			// The verdict is unchanged in every branch below. Nothing here
			// can offer a cut that was not offered before; one of them
			// asserts, and only where the assertion is proved.
			hit := consumed + scanFrom + at
			if scanFrom > 0 {
				// The frame verified, so the record's end is a fact and the
				// search began past its last byte: whatever sits at the hit,
				// some writer put it there AFTER this record. That much is
				// established, and it is what separates this from the branch
				// below — this is damage inside the log, not a crashed tail.
				//
				// It is not yet a *committed transaction*, and the region alone
				// cannot make it one. findTerminalRecordWithin is a magic
				// search, not a frame walk, and followSequenceRun's own doc
				// says what that costs: "A search would find records anywhere,
				// including inside a payload." Keeping the damaged record's
				// payload out of the region does not keep the payloads of the
				// records AFTER it out, and those are block bodies this node
				// accepted over the network and wrote verbatim too. So the same
				// forgery the payload-plant defect is about fits one record
				// further on, and beginning past a verified frame does nothing
				// to it.
				//
				// What does settle it is tiling: the region begins on a boundary
				// this branch has proved, so walking whole records forward from
				// there decides the hit three ways — landed on it, stepped over
				// it, or stopped at a second damage site before reaching it.
				// Only the first is an assertion. The other two are different
				// facts and are reported as different facts, because a report
				// that gave one of them the other's reason would be naming a
				// cause that did not happen to this store.
				switch outcome, mark := walkFramesTo(region, at); outcome {
				case walkLanded:
					d.Verdict = ProvenUnsafeToCut
					d.Explanation = fmt.Sprintf("the record at offset %d has a damaged payload "+
						"inside a frame that passed its own checksum, so the search for committed "+
						"records began past that record's last byte — and walking whole records "+
						"forward from there reaches an intact record at offset %d that declares "+
						"itself the last record of its transaction. A transaction that was "+
						"reported committed sits past the damage, and cutting here would delete "+
						"it. No cut is offered — resync this store.", consumed, hit)
				case walkSteppedOver:
					d.Verdict = FoundRecordDisproved
					d.Explanation = fmt.Sprintf("the record at offset %d has a damaged payload "+
						"inside a frame that passed its own checksum, so the search for committed "+
						"records began past that record's last byte — and walking whole records "+
						"forward from there steps straight over offset %d, where a record "+
						"declaring itself the last of its transaction was decoded. Those bytes "+
						"are inside the record that begins at offset %d — content that record "+
						"carries, not a record of this log — so they committed nothing. The "+
						"search stopped at that first candidate, so what lies past it is still "+
						"unread. No cut is offered — resync this store.",
						consumed, hit, consumed+scanFrom+mark)
				case walkBlocked:
					d.Verdict, d.SecondDamageOffset = BlockedBySecondDamage, int64(consumed+scanFrom+mark)
					d.Explanation = fmt.Sprintf("the record at offset %d has a damaged payload "+
						"inside a frame that passed its own checksum, so the search for committed "+
						"records began past that record's last byte — but the record at offset "+
						"%d is damaged too, so walking whole records forward stops there and "+
						"never reaches offset %d, where a record declaring itself the last of "+
						"its transaction was decoded. That is either a transaction that was "+
						"reported committed sitting past the damage, or record-shaped bytes "+
						"inside a later record's own payload. This reader cannot tell which, and "+
						"no checksum can. No cut is offered — resync this store.",
						consumed, consumed+scanFrom+mark, hit)
				default:
					// Unreachable: walkFramesTo returns three outcomes and all
					// three are above. It is here because the alternative was
					// `default:` on the blocked case, which would hand a fourth
					// outcome that message — telling an operator a record is
					// "damaged too" when nothing established that. A wrong
					// state made unrepresentable beats a comment saying it
					// cannot happen, and the cost is one branch that claims
					// nothing: no assertion, no cause, no second damage site.
					//
					// Verdict stays VerdictNone here for the same reason the
					// sentence claims nothing: naming one of the four states
					// would be asserting a walk outcome that did not happen.
					d.Explanation = fmt.Sprintf("the record at offset %d is damaged, and a "+
						"record declaring itself the last of its transaction was decoded at "+
						"offset %d behind it, but whether those bytes are a record at all was "+
						"not established. This reader cannot tell which, and no checksum can. "+
						"No cut is offered — resync this store.", consumed, hit)
				}
				return d, nil
			}
			// The payload-plant defect. The frame failed its own checksum, so
			// there is no honest end to search from and the region begins at
			// the damaged record's own first byte — which means it includes
			// that record's payload, and a payload is a block body this node
			// accepted over the network and wrote verbatim. A record with more
			// == 0 planted there is indistinguishable from a real one: CRC32 is
			// not secret, and attack_test's setMore recomputes both checksums.
			// Refusing is still the right verdict, because a false "not
			// repairable" costs a resync and a false "repairable" costs
			// committed transactions — but it is a refusal to decide, not a
			// decision, and the operator is told so.
			//
			// "Resync this store" is the whole remedy and not a hedge, and
			// that was measured rather than assumed (payloadplant_reach_test.go). The
			// verdict is a function of bytes nothing in this package may
			// write: Diagnose changes nothing, Apply is handed a report that
			// offers no cut and returns ErrNotRepairable without touching the
			// file, and Open refuses before it creates anything but the lock.
			// So the loop an operator has runs to a fixed point on the first
			// pass — a later attempt is the same attempt. What this costs is
			// therefore the data directory, not a restart, and the sentence
			// below is the last thing this store will ever say.
			d.Verdict = SearchBeganInsideDamage
			d.Explanation = fmt.Sprintf("the record at offset %d is damaged, and its frame "+
				"failed its own checksum, so the search for committed records had to begin "+
				"inside it — and a record decoded at offset %d declares itself the last record "+
				"of its transaction. That is either a transaction that was reported "+
				"committed sitting past the damage, or record-shaped bytes inside this "+
				"record's own payload, which is a block body this node accepted over the "+
				"network and wrote verbatim. This reader cannot tell which, and no checksum "+
				"can. No cut is offered — the bytes it would discard may be intact, but "+
				"nothing here can establish that, so resync this store.", consumed, hit)
			return d, nil
		case scanInconclusive:
			d.Explanation = fmt.Sprintf("the record at offset %d is damaged, and the search for "+
				"committed records behind it spent its work limit without reaching the end of "+
				"the log. Nothing was established, so nothing is offered for deletion — resync "+
				"this store.", consumed)
			return d, nil
		}
	}

	d.Repairable = true
	d.Offset, d.Discard, d.RecordsKept = cut, int64(len(raw))-cut, kept
	what := fmt.Sprintf("the record at offset %d is damaged, and no record behind it terminates "+
		"a transaction, so nothing this reader can find behind the damage was ever reported "+
		"committed", consumed)
	if groupOpen {
		what += fmt.Sprintf("; the damage falls inside the multi-record transaction beginning "+
			"at offset %d (sequence %d), which is discarded whole", groupStart, groupSeq)
	}
	// TWO DIFFERENT STORES KEEP NOTHING and they do not have the same reason,
	// so they do not get the same sentence. This clause was keyed on
	// expectedSeq == 0 — on what replay READ — and moving the guard to kept
	// without moving the wording repeated, one line down, the very defect
	// above: with a transaction open, kept == 0 means the log's intact prefix
	// is entirely inside the transaction the clause before this one already
	// says is discarded whole, and "no intact prefix at all" is then false.
	// `zycordd repair` prints that prefix's length as "readable:  N record(s)"
	// two lines above this sentence, so the instrument contradicted itself in
	// one screen, on the offer that deletes the whole log.
	//
	// groupOpen is the whole separation, and it is exact in both directions:
	// without it kept is expectedSeq, so kept == 0 means no record was read at
	// all; with it kept is groupSeq, so kept == 0 means the group opened at
	// sequence 0 and every record read is one of its parts.
	survives := fmt.Sprintf("keeps %d record(s) (sequence 0..%d)", kept, kept-1)
	switch {
	case kept > 0:
		// The sentence above already reads correctly; nothing to override.
	case groupOpen:
		survives = "keeps no records — this log's intact prefix is entirely inside that " +
			"transaction"
	default:
		survives = "keeps no records — this log has no intact prefix at all"
	}
	// THE CLAUSE THIS SENTENCE USED TO END ON WAS AN ASSERTION NO LOCAL RULE
	// CAN SUPPORT, and it is the sentence an operator types `yes` against.
	// "and loses nothing that was reported committed" was inferred from an
	// absence: findTerminalRecordWithin found no record behind the damage
	// declaring itself the last of its transaction. commitRecordSlotOccupied
	// narrows the shapes in which that inference is wrong; it does not close
	// them. A commit record destroyed by a TRUNCATING second fault leaves the
	// same bytes on disk as an ordinary torn tail, and a third damage site
	// removes the anchor that locates the slot at all — two stores built by
	// opposite histories, identical in every byte of every file at every
	// truncation depth measured, with opposite correct answers. No
	// function of this log's bytes is correct on both, so this one must not
	// claim to be.
	//
	// docs/RUNNING.md has said exactly that for two paragraphs — "in both
	// cases a cut will be offered, and taking it can delete a transaction that
	// really was reported committed" — while the instrument an operator
	// actually runs said the opposite, in one clause, on the screen where the
	// deletion is authorised. The manual is not the consent screen.
	//
	// NO VERDICT MOVES. The cut is offered exactly where it was offered
	// before, because withholding it here is exactly the store that must stay
	// repairable and the whole reason this second door exists. What moves is
	// that the report now states what it established and what it did not,
	// which is the line every refusal in this function already holds.
	d.Explanation = fmt.Sprintf("%s. Discarding %d byte(s) from offset %d %s. That absence is "+
		"not a proof: a commit record that was written and then destroyed is missing from this "+
		"search in exactly the way one that was never written is, and nothing in these bytes "+
		"separates the two — copy this directory before you answer.",
		what, d.Discard, d.Offset, survives)
	return d, nil
}

// walkOutcome names what tiling whole records forward from a proved boundary
// established about one offset behind the damage. Three answers, because
// there are three, and collapsing the last two tells an operator a cause that
// did not happen to their store.
type walkOutcome int

const (
	// walkLanded: the walk stopped exactly on the offset, so a writer framed
	// a record there and what was decoded there is that record.
	walkLanded walkOutcome = iota

	// walkSteppedOver: the walk crossed the offset from inside one of its own
	// frames. The offset is strictly interior to a record the writer framed,
	// so what was decoded there is content that record carries — a block body
	// accepted over the network and written verbatim — and it committed
	// nothing. This is a proof, not a hedge.
	walkSteppedOver

	// walkBlocked: a record between the start and the offset does not decode,
	// so where the boundaries lie past it was never established and the
	// offset is neither proved nor disproved. A second damage site, which is
	// a fact about a second damage site in its own right.
	walkBlocked
)

// walkFramesTo tiles whole records forward from the start of raw — which the
// caller must already have proved is a record boundary — and reports what
// that establishes about the offset at.
//
// This is the difference between "record-shaped bytes are here" and "a record
// is here", and findTerminalRecordWithin cannot tell them apart on its own: it
// is a magic search, and followSequenceRun's doc says what a search costs — "A
// search would find records anywhere, including inside a payload." So a hit is
// proof of a committed transaction only once something else places it on a
// boundary. Beginning the search past a verified frame's last byte keeps the
// DAMAGED record's payload out of the region and nothing else; every record
// after it carries a payload too, and those are block bodies this node accepted
// over the network and wrote verbatim, so the payload-plant forgery fits inside
// one of them just as well.
//
// Tiling settles it because decodeOK verifies a frame whose length the header
// checksum covers, over bytes an attacker never authors: a record's header
// begins at a boundary and a payload's reach begins 32 bytes later, so every
// position this walk decodes at is one the writer chose. From a genuine
// boundary the next boundary is genuine and the induction carries. A record
// planted at payload offset d inside a genuine frame is strictly interior to
// it, so the walk steps over it and can never be made to stop on one, for any
// choice of any record's length. It errs only toward "not proved".
//
// THE decodeOK TEST BELOW DOES TWO SEPARATE JOBS and only one of them is
// structural. For decodeTorn, decodeHeaderUntrusted and decodeMaxLenExceeded
// decodeRecord returns n == 0, so advancing would not advance and the loop
// would not terminate — deleting the test hangs this walk on a reachable
// store, and since the walk carries no budget nothing else would stop it.
// For decodePayloadBad n is NOT zero: decodeRecord returns the full framed
// length there and says so in terms ("n is meaningful whenever the header
// verified — that is, for decodeOK and decodePayloadBad"). That frame's
// extent is a fact, so crossing it would be sound, and stopping is a POLICY:
// a second damage site is something the operator is told about rather than
// walked through, and refusing to cross it is the conservative direction of
// an epistemic claim. It is a policy with a separating input, not a rule that
// could not be otherwise.
//
// It takes no budget, and that is not an omission — but the termination above
// is what makes budget-freeness safe, so the two are one argument, not two.
// The frames it decodes are disjoint and tile [0, at), so the bytes it feeds
// to crc32 are bounded by at plus a header per frame: linear in the region
// and intrinsic to this function. It is called once, from the single
// scanFound case, on findTerminalRecordWithin's FIRST hit, so there is no
// per-hit walk and nothing quadratic. Independently, every frame it decodes
// begins at a magic that findTerminalRecordWithin already reached and already
// charged for at the same price (recordCRCOff + length), because the search
// returned scanFound at at and so processed every candidate before it; the
// walk's charge is a sub-multiset of one that already fit the budget. The
// linear bound is the one to rely on — it holds whatever the other
// function's charging discipline does next.
func walkFramesTo(raw []byte, at int) (walkOutcome, int) {
	pos := 0
	for pos < at {
		_, _, _, n, status := decodeRecord(raw[pos:])
		if status != decodeOK {
			return walkBlocked, pos
		}
		if pos+n > at {
			return walkSteppedOver, pos
		}
		pos += n
	}
	return walkLanded, pos
}

// findTerminalRecordWithin scans for an intact record carrying a sequence at
// least minSeq that declares itself the last record of its transaction
// (more == 0).
//
// It is not findNextRecordWithin with a filter bolted on, and the difference
// is the point. findNextRecordWithin asks "did the writer get past this
// damage", which any intact record answers; it then has to dismiss an open
// group's own parts by an explicit membership test, because those are durable
// but inert. This asks the narrower question an operator's
// authorisation actually turns on — "is a *committed* transaction back there"
// — and only a more == 0 record answers that one, so the dismissal falls out
// of the question instead of being a rule with its own attack surface.
//
// The charging discipline is findNextRecordWithin's, deliberately unchanged:
// candidates rejected by arithmetic cost nothing and are charged nothing
// — a bound that charged for them made an ordinary torn tail unrepairable —
// and only bytes actually fed to crc32 are billed.
//
// PRECONDITION, inherited verbatim from findNextRecordWithin and load-bearing
// for the same reasons: raw must run to the end of the log. Pricing a span
// that overruns the buffer at zero is sound only because a record whose frame
// runs past the end of the file cannot exist on disk, and "no terminal record
// found" means "none in the log" only when the buffer ends where the log
// does. A bounded search window would change both, and must revisit this — and a
// checkpoint boundary must not fall inside a group, for the reason
// findNextRecordWithin's own precondition gives.
//
// The region this searches is also *why* the payload-plant defect is open. For
// a damaged frame the caller has no honest end to search from, so the region
// begins at the damaged record's first byte and therefore includes its payload
// — a block body accepted over the network and written verbatim. A more == 0
// record planted there reads exactly like a committed transaction, and no
// checksum separates the two (attack_test's setMore recomputes both). The
// refusal that results is the safe direction, not a correct answer.
//
// THE REGION IS NOT THE WHOLE OF IT, and a caller that reads a hit as a fact
// because the region began past the damaged record will be wrong. This is a
// search: it lands wherever the magic is, including inside the payload of a
// record written LATER, which is another block body accepted over the network
// and written verbatim. What a hit proves on its own is that record-shaped
// bytes are at that offset. A caller that needs "a writer framed a record
// here" has to establish it — see walkFramesTo.
//
// A PERIODIC CHECKPOINT INDEX IS OFTEN CREDITED WITH CLOSING THE PAYLOAD-PLANT
// DEFECT, AND THAT CREDIT IS TOO WIDE — bounding the search's WORK and bounding
// its EVIDENCE want different things, and a periodic index supplies only the
// first. The crafted-span budget wants the region's SIZE bounded, and one
// checkpoint interval bounds it. The payload-plant defect wants the damaged
// record's own payload OUT of the region, which needs the damaged record's END.
// Those are not the same fact. Call the damaged record's frame [D, E): a
// recorded boundary at any offset X > E is a boundary, not E, and the records
// tiling [E, X) are still unknown, so the search still has to start at D and
// the payload is still in it. The payload leaves the region only where a
// checkpoint falls at E exactly — one boundary per interval — and the defect's
// own scenario excludes that by construction, since there the damaged record is
// the log's LAST and E is the end of the file. A bound on work is being
// credited with a bound on evidence.
//
// What reaches the payload-plant defect is a record's extent, or the last
// committed sequence, held OUT OF BAND and fsynced ahead of the log write, so
// the question is answered without reading the damaged region at all. That is a
// second file, a second barrier on the commit path and a damage class of its
// own — a durability/throughput decision with its own record, not a tightening
// available here; see commits.go, which is that second file. The crafted-span
// budget is neither solved nor pre-empted by this note.
func findTerminalRecordWithin(raw []byte, minSeq uint64, budget int64) (offset int, result scanResult) {
	for i := 0; i+recordHeaderLen <= len(raw); {
		idx := bytes.Index(raw[i:], recordMagic[:])
		if idx < 0 {
			return 0, scanNothingFound
		}
		pos := i + idx
		if pos+recordHeaderLen > len(raw) {
			return 0, scanNothingFound
		}
		if _, _, length, ok := verifyHeader(raw[pos:]); ok {
			if length <= MaxRecordLen && int64(recordHeaderLen)+int64(length) <= int64(len(raw)-pos) {
				cost := int64(recordCRCOff) + int64(length)
				if cost > budget {
					return 0, scanInconclusive
				}
				budget -= cost
				if _, seq, more, _, status := decodeRecord(raw[pos:]); status == decodeOK &&
					seq >= minSeq && more == 0 {
					return pos, scanFound
				}
			}
		}
		i = pos + 1
	}
	return 0, scanNothingFound
}

// Apply performs the cut the diagnosis offered, and only that one.
//
// It re-derives the diagnosis under the lock it still holds and refuses
// unless the file and the offer are the ones the operator was shown. A repair
// that recomputed a *fresh* offer here could discard more than the human
// agreed to, which is the one failure mode a tool that deletes data on
// purpose must not have.
func (r *Repairer) Apply(shown *LogDiagnosis) error {
	if shown == nil || !shown.Repairable {
		return ErrNotRepairable
	}
	now, err := r.Diagnose()
	if err != nil {
		return err
	}
	if !now.Repairable || now.Offset != shown.Offset || now.Discard != shown.Discard ||
		now.Size != shown.Size {
		return fmt.Errorf("storage: %s no longer matches the repair that was approved; "+
			"nothing was discarded", now.Path)
	}
	// THE SIDECAR IS LOWERED FIRST, and the order is what keeps this command
	// from bricking a store.
	//
	// The log is about to hold sequences 0..RecordsKept-1 and nothing else, so
	// the out-of-band record has to say exactly that. Leaving it claiming more
	// than the log holds is the one state this design cannot recover from:
	// replayLog refuses a clean log that cannot account for a committed
	// sequence, so every future boot would refuse the store an operator just
	// repaired, permanently, with no second door behind this one.
	//
	// So it follows the same make-the-low-value-durable-first rule compaction
	// does, and for the same reason. A crash between the two steps leaves a LOW
	// sidecar against a log that was not shortened: no evidence, which is a
	// store that still needs this repair and will be offered it again. The other
	// order leaves a HIGH sidecar against a shortened log, which is the brick.
	if err := writeCommitsFile(r.dir, now.RecordsKept); err != nil {
		return err
	}
	if err := truncateDurably(now.Path, now.Offset); err != nil {
		return err
	}
	return syncDir(r.dir)
}
