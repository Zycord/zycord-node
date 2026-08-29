// Package storage is a crash-safe key-value store with atomic batch commit.
//
// It exists to provide exactly one guarantee, and the whole design is shaped by
// it: **a batch is durable or it is absent — never partial.** A node that
// restarted into a state no fold ever produced would diverge silently, which is
// the storage-schedule consensus split of I1-C3 reborn as a crash schedule.
//
// The engine is a write-ahead log plus periodic snapshots — around 760 lines
// of code in this file, and rather more comment than that, using nothing
// outside the standard library. That is a deliberate
// deviation from the architecture spec's decisions log, which named Pebble; the
// argument is in docs/adversarial/I2.md. The short version: the guarantee above
// is the entire requirement, it is auditable by reading this file, and the
// alternative brought twenty-six modules — including a telemetry SDK — into a
// tree whose case for being trusted is that there is very little of it.
//
// The live view is held in memory. That matches the spec's storage target — the
// hot set in RAM, the fold never blocking on disk — and it is what makes an
// engine this small sufficient for Era 0. When state outgrows memory the engine
// is replaced behind this interface, and these tests become its acceptance
// criteria.
package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// File names inside a store directory.
const (
	logName      = "log"
	snapshotName = "snapshot"
	snapshotTmp  = "snapshot.tmp"
)

// FormatVersion is the on-disk format of the log and the snapshot.
//
// A format with no version field is a migration that can only be performed with
// a flay day, and a node that silently misreads an older file is corruption by
// another route — the kind no checksum catches, because the bytes are
// well-formed and the *interpretation* is wrong. An unknown version is refused
// rather than guessed at.
//
// Bumped to 2 for the record format change that closed the
// interior-corruption-read-as-torn-tail defect: each record now carries a
// monotonic sequence number, and it carries two checksums — one over the header
// alone and one over the header and the payload together — rather than a single
// one over the payload.
//
// Bumped to 3 for the group field that closed the oversized reorg record: each
// record also carries the number of records still to come in the same
// transaction, so a commit too large for one record can span several and still
// land all-or-nothing (see CommitGroup). There is no deployed chain yet to
// migrate — this is the flag day the doc above already anticipated, taken twice
// before genesis rather than left as a migration after it.
//
// Bumped to 4 for the payload escape that closed the payload-plant defect: a
// record's payload no longer contains recordMagic, because encodeRecord stuffs
// it out (see escapePayload). A version-3 log and a version-4 log are the same
// layout with different payload bytes, which is the migration a version field
// exists to refuse rather than guess at — the two are indistinguishable by
// shape and a version-3 payload read as version 4 would silently drop bytes. An
// old store is refused by version (ErrFormat, naming both numbers) by
// replayLog, decodeSnapshot and repair's preflight, so the operator sees a
// version refusal and not a corruption report: a resync, not a fork. The log is
// node-local — FormatVersion has no reference outside this package, core/ does
// not import it, and ConsensusRoot() reflects only over params.Params — so the
// bump costs a resync and nothing on the consensus surface. Taken before
// genesis, on the same reasoning as the two above.
const FormatVersion = 4

// recordMagic prefixes every log record. A record that does not start with it
// is a torn write, not a record. The last byte is the format version.
var recordMagic = [4]byte{'C', 'A', 'P', FormatVersion}

// snapshotMagic prefixes a snapshot file; its last byte is the format version.
var snapshotMagic = [8]byte{'C', 'A', 'P', 'B', 'S', 'N', 'P', FormatVersion}

// The log record layout. The two checksums are the whole discriminator a
// recovery reader needs to tell interior damage from a torn tail, and the
// reason there are two of them rather than one is the point of the design, so
// it is stated here rather than left to be inferred:
//
// Recovery has exactly one hard question — is a record that failed to decode
// the *tail* of a crashed write (discard it, come back up) or *interior* damage
// with intact records still sitting behind it (refuse, do not delete them)? The
// only structure that can answer it is the record's own framing: a header that
// says "my payload is N bytes long" also says "no other record begins before my
// end". That claim is what lets replayLog decline to go looking for later
// records inside a torn record's own payload, which it must decline to do,
// because a payload is writer-controlled bytes (see
// TestPayloadBaitDoesNotDefeatTheTailDiscriminator). Since the payload escape
// those bytes can no longer be made to look like a record — escapePayload takes
// the magic out of them — but the framing rule stands on its own and does not
// become decoration: it is what keeps the reader from having to trust an escape
// at all, and a reader that scanned inside a payload would be resting a
// data-loss decision on the writer's transformation rather than on the frame.
//
// But the claim is only usable if the framing can be *verified* on its own,
// before any of the bytes it frames are read. A single checksum over header
// and payload together cannot do that: reaching it requires already having
// trusted the length field to find the payload's end. So the header carries
// its own checksum, covering the magic, the sequence and the length, and the
// reader validates it first. From there every failure has a provable
// classification instead of an assumed one — see decodeStatus.
//
// Two-tier checksumming of this shape is what ext4's journal does with
// metadata_csum (a descriptor block, which is the framing, carries its own
// checksum in jbd2_journal_block_tail, separate from the per-block tag
// checksums covering the data it frames), and what ZFS's ZIL does with the
// chain header's checksum over the next-block pointer, separate from each
// log block's own. The systems that skip it — LevelDB's and RocksDB's log
// readers, whose record checksum famously does not cover the length field —
// buy back the missing framing another way, by cutting the log into
// fixed 32 KiB blocks that give the reader resync points no length field can
// move. This log is not block-structured, so the checksum has to be.
//
// Three alternatives were rejected, and the two cheap ones were each tried
// first and found to lose real data:
//
//   - One checksum over header and payload, always scanning forward when a
//     record fails to decode. Loses to R2-STOR: the scan runs through the
//     torn record's own payload, which is writer-controlled — a value that
//     arrived over the network can contain something that parses as a
//     record — so an ordinary crash is misreported as interior corruption
//     and the node refuses to start, taking every durable commit with it.
//   - One checksum, never scanning when the declared length overruns the
//     file. Loses the other way, and silently: a bit flipped into an
//     interior record's length field produces exactly that shape, and every
//     intact record behind it is deleted with no error — the opening example
//     of the interior-corruption defect, still open after three rounds of this
//     fix. See
//     TestInteriorLengthCorruptionOverrunningTheFileIsRefused.
//   - Block-structured framing, LevelDB-style. It solves the same problem
//     and needs no second checksum, but it re-frames every record, splits
//     batches across block boundaries, and replaces a format that can be
//     read end to end in one pass with one that cannot. Four bytes per
//     record buys the same property here without touching anything else.
//
// The header carries one field the paragraphs above do not explain, because
// it answers a different question: more, the number of records still to come
// in the same transaction (see CommitGroup). It sits inside the
// header-checksummed span for the same reason the length does — a reader
// that believed a corrupted more would apply a strict subset of a
// transaction, which is precisely the partial state this package exists to
// make unreachable.
const (
	recordMagicOff  = 0
	recordSeqOff    = 4
	recordMoreOff   = 12
	recordLenOff    = 16
	recordHdrCRCOff = 24
	recordCRCOff    = 28
	// recordHeaderLen is magic + sequence + the group's remaining-part count
	// + payload length + the header checksum + the whole-record checksum.
	recordHeaderLen = 32
)

// MaxRecordLen bounds a single record's payload, so that a corrupt length
// field cannot make the reader allocate arbitrarily.
//
// It is exported because it bounds what a caller may put in one batch, and a
// caller with more than that to commit atomically has to know where to split
// (node/chain's reorg commit does — see CommitGroup). It bounds one record,
// not one transaction: a group of records commits as a unit and its total
// size is bounded only by what the caller can hold.
//
// It bounds the payload AS WRITTEN, which since format 4 is the escaped payload
// (escapePayload), not the caller's mutations. A caller sizing a batch against
// this constant must therefore leave the escape's 5/4 worst case inside its
// own budget rather than against a margin — node/chain's mutationBudget does,
// and pins the arithmetic.
const MaxRecordLen = 1 << 30

// Errors returned by the store.
var (
	ErrClosed      = errors.New("storage: store is closed")
	ErrCorrupt     = errors.New("storage: log or snapshot is corrupt")
	ErrBatchTooBig = errors.New("storage: batch exceeds the maximum record size")
	ErrFormat      = errors.New("storage: unknown on-disk format version")
)

// Operation kinds inside a batch.
const (
	opPut    byte = 1
	opDelete byte = 2
)

type mutation struct {
	op    byte
	key   []byte
	value []byte
}

// Batch is a set of mutations that commit together or not at all.
//
// Everything one block changes — cells, the spent registry, the seen set, the
// undo log, headers, the height — belongs in a single Batch. Splitting a block
// across two commits is the bug this type exists to make awkward.
type Batch struct {
	mutations []mutation
}

// Put stages a write. The key and value are copied, so callers may reuse their
// buffers.
func (b *Batch) Put(key, value []byte) {
	b.mutations = append(b.mutations, mutation{
		op:    opPut,
		key:   append([]byte(nil), key...),
		value: append([]byte(nil), value...),
	})
}

// Delete stages a removal.
func (b *Batch) Delete(key []byte) {
	b.mutations = append(b.mutations, mutation{op: opDelete, key: append([]byte(nil), key...)})
}

// Len returns the number of staged mutations.
func (b *Batch) Len() int { return len(b.mutations) }

// Store is a durable map. It is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	dir  string
	log  *os.File
	live map[string][]byte
	// logBytes tracks the log size so compaction can be triggered without a
	// stat on every commit.
	logBytes int64
	// compactAt is the log size beyond which a commit also writes a snapshot.
	compactAt int64
	closed    bool

	// failed is set once a write or fsync on the durability path returns an
	// error, and makes the store refuse every commit from then on.
	//
	// The alternative is silently continuing to accept and durably commit
	// records on top of a torn one: the next restart's replayLog cannot tell
	// "torn, then nothing" from "torn, then N more real records", so it must
	// discard everything from the tear onward, and a store that kept working
	// after the fault is what lets that discard eat commits nobody knew were
	// at risk. Once failed is set the only way out is a fresh Open, which
	// replays exactly what is durable — no more, no less.
	failed error

	// nextSeq is the sequence number the next record appended to the
	// *current* log file will carry. It resets to 0 whenever the log is
	// empty — a fresh directory, or immediately after compactLocked truncates
	// it — because sequence numbers only need to be unique and increasing
	// within one log file's lifetime. That is what lets replayLog tell "the
	// next record is corrupt" apart from "there is no next record".
	nextSeq uint64

	// lock holds the datadir's exclusivity guard for the life of the store
	// and is released by Close.
	lock *dirLock

	// commits is the out-of-band commit record and commitCounter is the write
	// counter of the slot last written to it. What the number means is stated in
	// commits.go and deliberately not restated here, because one field carrying
	// two differently-worded contracts is the trap the sidecar exists to close:
	// it is the one fact recovery needs that the log cannot hold, because the
	// fact is that the log's own fsync returned.
	commits       *os.File
	commitCounter uint64

	// logger receives the store's operator-facing diagnostics: today, exactly
	// the messages emitted when replayLog discards a torn tail, and when an
	// automatic compaction fails. Defaults to a discarding logger — matching
	// node/p2p's Logger convention of "nil means quiet" — so tests are not
	// forced to filter output; cmd/zycordd wires log.Default() the same way
	// it already does for p2p.Node, so a real deployment is never silent
	// about a rewind.
	logger *log.Logger

	// sync is the durability barrier, indirected for the fault-injection tests
	// that prove the atomicity guarantee.
	sync func(*os.File) error
	// writeHook, when set, may truncate or fail a record write mid-way. Tests
	// use it to crash the process at every byte offset of a commit.
	writeHook func(record []byte) ([]byte, error)
}

// Options configure a store.
type Options struct {
	// CompactAfterBytes is the log size that triggers a snapshot. Zero selects
	// a sensible default.
	CompactAfterBytes int64

	// FaultInjector simulates a process dying part-way through a commit. It is
	// given the encoded record and returns the prefix that reached the disk
	// plus an error; whatever it returns is written, and the commit then fails.
	//
	// It exists so that crash-atomicity can be proven at *every byte offset* of
	// a commit rather than wherever a SIGKILL happens to land. Nil in
	// production, and there is no configuration path that sets it — the field
	// is reachable only from Go code that constructs Options directly.
	FaultInjector func(record []byte) ([]byte, error)

	// Logger receives the store's rare operator-facing diagnostics. Nil (the
	// default) is silent. See the Store.logger field doc for why the default
	// is quiet rather than log.Default(): this is a library, and a caller
	// that wants the message wires it, the way cmd/zycordd does.
	Logger *log.Logger
}

// Open loads a store from a directory, creating it if needed.
//
// The datadir is locked first: a second Open against the same
// directory, from this process or another, is refused with ErrLocked rather
// than silently interleaving writes with the first.
//
// Recovery is the interesting path: the snapshot is loaded, then log records
// are replayed in order until one fails its checksum or runs past the end of
// the file. That record was being written when the process died, so it is
// truncated away and everything before it stands. Replay is idempotent —
// mutations are absolute, not relative — so a snapshot that already contains
// some replayed records is harmless.
//
// A record that fails to decode is not automatically that record: replayLog
// distinguishes a genuine torn tail from interior corruption with intact
// records after it, and refuses to open in the second case rather than
// repairing by deletion.
func Open(dir string, opts Options) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lock, err := acquireDirLock(dir)
	if err != nil {
		return nil, err
	}

	compactAt := opts.CompactAfterBytes
	if compactAt <= 0 {
		compactAt = 64 << 20
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	s := &Store{
		dir:       dir,
		live:      make(map[string][]byte),
		compactAt: compactAt,
		sync:      func(f *os.File) error { return f.Sync() },
		writeHook: opts.FaultInjector,
		lock:      lock,
		logger:    logger,
	}

	if err := s.loadSnapshot(); err != nil {
		lock.release()
		return nil, err
	}
	if err := s.replayLog(); err != nil {
		lock.release()
		return nil, err
	}

	logPath := filepath.Join(dir, logName)
	_, statErr := os.Stat(logPath)
	logIsNew := errors.Is(statErr, os.ErrNotExist)
	logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		lock.release()
		return nil, err
	}
	if logIsNew {
		// A brand-new log file's directory entry is not durable until the
		// directory itself is synced. Without this, a power loss right after a
		// fresh node's first commits can leave the log's *contents* fsynced but
		// its name absent, and the next Open takes replayLog's ErrNotExist
		// early return and starts from an empty store — the same silent rewind
		// by another route. Only on creation: an existing entry is already
		// durable, and this is not on the commit path.
		if err := syncDir(dir); err != nil {
			logFile.Close()
			lock.release()
			return nil, err
		}
	}
	info, err := logFile.Stat()
	if err != nil {
		logFile.Close()
		lock.release()
		return nil, err
	}
	s.log = logFile
	s.logBytes = info.Size()

	// The commit sidecar is opened and then RESTATED to whatever a clean replay
	// just accounted for, and both halves matter.
	//
	// The restatement is the WEAKER of the two producers in the contract
	// commits.go states, and this comment no longer restates that contract in a
	// second, differently-worded sentence of its own: what a reader may
	// infer from the field is settled there, in one place, for both producers.
	//
	// Restating heals a sidecar that is stale LOW — the shape an ordinary crash
	// between the log's barrier and the sidecar's leaves behind — and it is what
	// converts a data directory written by a build that had no sidecar: after
	// one clean boot such a store carries the evidence, which is why the two
	// ambiguous-cut shapes close for existing directories only from their first
	// successful open and not before.
	//
	// It is ordered after replayLog, so the value written can never exceed what
	// the log on disk holds: replayLog either verified every record it counted
	// or truncated durably before returning. And it runs only where replayLog
	// did NOT refuse, so a sidecar that withheld a cut is never overwritten by
	// the boot it just denied.
	//
	// expectedSeq, carried out as nextSeq, is exactly the slot's highPlusOne
	// encoding: the log accounts for sequences 0..nextSeq-1, and nextSeq == 0 is
	// "nothing committed in this log generation".
	prior, err := s.openCommits()
	if err != nil {
		logFile.Close()
		lock.release()
		return nil, err
	}
	//
	// The restatement is skipped when it would change nothing, and the test is
	// written against what the RULE reads rather than against the bytes: an
	// unverified sidecar and a verified one saying "nothing committed" are the
	// same answer to withholds, so a fresh directory needs no write and the
	// common reopen-a-healthy-store path pays no barrier at all.
	haveEvidence := prior.verified && prior.has
	if haveEvidence != (s.nextSeq > 0) || (haveEvidence && prior.high != s.nextSeq-1) {
		if err := s.writeCommitsLocked(s.nextSeq); err != nil {
			s.commits.Close()
			logFile.Close()
			lock.release()
			return nil, err
		}
	}
	return s, nil
}

// Get returns a value and whether the key is present. The returned slice is a
// copy.
func (s *Store) Get(key []byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.live[string(key)]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), v...), true
}

// Has reports whether a key is present, without copying its value.
func (s *Store) Has(key []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.live[string(key)]
	return ok
}

// ScanPrefix calls fn for every key with the given prefix, in sorted key order.
// Iteration order is deterministic because consensus state is rebuilt from it.
func (s *Store) ScanPrefix(prefix []byte, fn func(key, value []byte) error) error {
	s.mu.RLock()
	keys := make([]string, 0, len(s.live))
	for k := range s.live {
		if len(k) >= len(prefix) && k[:len(prefix)] == string(prefix) {
			keys = append(keys, k)
		}
	}
	values := make([][]byte, len(keys))
	sort.Strings(keys)
	for i, k := range keys {
		values[i] = append([]byte(nil), s.live[k]...)
	}
	s.mu.RUnlock()

	for i, k := range keys {
		if err := fn([]byte(k), values[i]); err != nil {
			return err
		}
	}
	return nil
}

// Commit applies a batch atomically and durably.
//
// The order is: encode the whole batch into one record, append it, fsync, and
// only then touch the in-memory view. A crash before the fsync returns leaves
// the record absent or torn, and recovery discards it; a crash after leaves it
// complete, and recovery replays it. There is no interleaving in which half a
// block is visible.
func (s *Store) Commit(b *Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}
	if b.Len() == 0 {
		return nil
	}
	return s.commitOneLocked(b)
}

// commitOneLocked is Commit's body with the store's lock held and its
// preconditions already checked. CommitGroup falls back to it for a group
// that turns out to hold a single non-empty batch, so that case is
// byte-for-byte what Commit has always written rather than a second encoding
// of the same thing.
func (s *Store) commitOneLocked(b *Batch) error {
	seq := s.nextSeq
	record, err := encodeRecord(b, seq, 0)
	if err != nil {
		return err
	}
	written, err := s.appendRecordLocked(record)
	if err != nil {
		return err
	}
	if err := s.syncLocked(); err != nil {
		return err
	}
	// The barrier returned, so this transaction has been reported committed —
	// and that fact, not the intention to write it, is what recovery cannot
	// find in the log. It is recorded here, after the return and before
	// the batch is applied or the call returns to the caller.
	s.recordCommitLocked(seq)

	// Durable. Only now does the batch become visible.
	s.apply(b)
	s.logBytes += written
	s.nextSeq = seq + 1
	s.compactIfDueLocked()
	return nil
}

// CommitGroup applies several batches as one atomic, durable transaction
// spanning as many log records as it takes.
//
// It exists because one legal transition can be larger than one record may
// be. A reorg within the declared undo horizon carries up to UNDO_DEPTH
// blocks at BLOCK_BYTE_CAPACITY each — gigabytes at mainnet parameters,
// where MaxRecordLen is one — and that bound is not arbitrary: it is what
// stops a corrupt length field from making the reader allocate arbitrarily,
// which is a reason to bound one record, not a reason a legal reorg should
// be impossible to commit. Raising it merely moves the wall, since the
// byte ceiling a legal reorg can reach grows with the chain's own capacity
// curve.
//
// Splitting the write does not split the guarantee, and the mechanism is the
// oldest one in journalling: every record but the last declares that more of
// the transaction follows, and the last one declares that it does not. That
// final record is the commit point. Replay holds a transaction's parts
// without applying any of them until it reads that last record, so a crash
// anywhere in the middle leaves a transaction that is durable, inert, and
// discarded on the way back up — the same "all or nothing" a single record
// gets, over as many records as the caller needs. It is what ext4's jbd2
// does with a commit block terminating a transaction's descriptor and data
// blocks, and what ARIES-style write-ahead logs have done with a commit
// record since the 1990s; nothing here is novel except that this log was
// previously one record per transaction and so never needed it.
//
// There are exactly two fsyncs, and where they sit is not an optimisation
// but the correctness argument. Every part but the last is written, then
// fsynced *before* the final record is written at all; the final record is
// then written and fsynced in turn. That is jbd2's rule for a journal commit
// block, and the reason is the same: file writes reach stable storage in
// whatever order the kernel and the device choose, so without a barrier in
// front of it the commit record can be durable while a part it claims is
// durable is not — a hole, not a prefix. Replay would then read a record
// whose sequence is not the one it expects and refuse to open the store,
// which is loud rather than silent (a hole can never make replay apply a
// subset: the sequence check catches it) but is still a node that will not
// start after an ordinary crash. The barrier makes what survives a crash
// always a prefix of what was written, which is the shape every branch
// below assumes.
//
// It is two barriers per transaction rather than one per part: whether the
// non-final parts are made durable in one fsync or a hundred changes
// nothing, since none of them mean anything until the commit record lands.
//
// A group of zero or one non-empty batches takes the ordinary single-record
// path, so nothing about Commit's behaviour or its on-disk shape changes for
// the case every block but a deep reorg is.
//
// Like Commit, a write or fsync failure here poisons the store: it refuses
// every later commit until it is reopened. That matters more here than
// there, because a torn record inside a group is a torn record like any
// other, and letting the process keep appending on top of it is what makes
// the next restart's tail repair eat commits that came after the fault
// — the group path inherits that torn-write failure shape whole.
func (s *Store) CommitGroup(batches []*Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}

	nonEmpty := make([]*Batch, 0, len(batches))
	for _, b := range batches {
		if b.Len() > 0 {
			nonEmpty = append(nonEmpty, b)
		}
	}
	if len(nonEmpty) == 0 {
		return nil
	}
	if len(nonEmpty) == 1 {
		// One record, written exactly as Commit writes it: same encoding,
		// same more=0 header, same single fsync. A reader cannot tell this
		// call from an ordinary commit, which is the point — the group
		// machinery only exists for transactions that genuinely need it.
		return s.commitOneLocked(nonEmpty[0])
	}

	// Encode everything before writing anything: an oversized part must fail
	// the whole transaction with nothing on disk, not half-way through it.
	seq := s.nextSeq
	records := make([][]byte, len(nonEmpty))
	for i, b := range nonEmpty {
		record, err := encodeRecord(b, seq+uint64(i), uint32(len(nonEmpty)-1-i))
		if err != nil {
			return err
		}
		records[i] = record
	}

	// Whatever reaches the file counts toward the log's size whether this
	// call succeeds or not: an abandoned transaction's bytes are still bytes,
	// and undercounting them only delays compaction. One deferred credit
	// rather than one per exit, so no failure path can forget it.
	var written int64
	defer func() { s.logBytes += written }()

	for _, record := range records[:len(records)-1] {
		n, err := s.appendRecordLocked(record)
		written += n
		if err != nil {
			// Whatever landed is an incomplete transaction: replay will find
			// no final record and discard the lot. The store is poisoned
			// (appendRecordLocked did that), so nothing else can be written
			// on top of it in this process either.
			return err
		}
	}
	// The barrier in front of the commit record — see the doc comment.
	if err := s.syncLocked(); err != nil {
		return err
	}
	n, err := s.appendRecordLocked(records[len(records)-1])
	written += n
	if err != nil {
		return err
	}
	if err := s.syncLocked(); err != nil {
		return err
	}
	// The commit record's barrier returned: the transaction is committed, and
	// the sequence recorded is this transaction's LAST record.
	//
	// NO RECOVERY OUTCOME SEPARATES THIS FROM RECORDING THE OPENER'S SEQUENCE,
	// and the narrowness of that sentence is the point. Every cut this rule can
	// withhold begins at or below a group's opening sequence: damage inside an
	// open group cuts back to groupStart, and damage the group is not open at is
	// damage replay reached in sequence, which means the group's terminal was
	// already applied and the next cut starts strictly above it. A mutation to
	// `seq` survives every refusal, every offer and every boot in the suite.
	//
	// The first draft of this comment said "no input separates them", and the
	// mutation probe killed it: a test asserts the RECORDED VALUE directly, so
	// the field is pinned even though no decision reads the difference. That is
	// deliberate and it is why the value is the last record's sequence — it is
	// what "reported committed" MEANS on the commit path, which is the stronger
	// of the two producers commits.go's contract names, and a reader of this file
	// has to be able to take the field at its word. The equivalence is a property
	// of today's cut sites, not of the field.
	s.recordCommitLocked(seq + uint64(len(nonEmpty)) - 1)

	// Durable, in full. Only now does any of it become visible.
	for _, b := range nonEmpty {
		s.apply(b)
	}
	s.nextSeq = seq + uint64(len(nonEmpty))

	// The deferred credit above has not run yet, and compaction has to see a
	// log size that includes what this call just wrote — otherwise a group
	// that crosses the threshold never triggers the compaction it caused.
	s.logBytes += written
	written = 0
	s.compactIfDueLocked()
	return nil
}

// appendRecordLocked writes one encoded record to the log, honouring the
// fault injector, and poisons the store if the write fails. It returns how
// many bytes the caller should credit to logBytes once the write is known to
// have landed.
func (s *Store) appendRecordLocked(record []byte) (int64, error) {
	if s.writeHook != nil {
		out, err := s.writeHook(record)
		if err != nil {
			// The hook simulates a process death part-way through the write.
			// Whatever reached the file stays there; recovery must cope.
			if len(out) > 0 {
				s.log.Write(out)
			}
			s.poison(err)
			return int64(len(out)), err
		}
		record = out
	}
	if _, err := s.log.Write(record); err != nil {
		s.poison(err)
		return 0, err
	}
	return int64(len(record)), nil
}

// syncLocked is the durability barrier, poisoning the store on failure.
func (s *Store) syncLocked() error {
	if err := s.sync(s.log); err != nil {
		s.poison(err)
		return err
	}
	return nil
}

// compactIfDueLocked snapshots and truncates the log once it has grown past
// the configured threshold.
func (s *Store) compactIfDueLocked() {
	if s.logBytes < s.compactAt {
		return
	}
	if err := s.compactLocked(); err != nil {
		// A failed compaction is not a failed commit: the data is already
		// durable in the log exactly as written above, and compactLocked
		// never truncates the log until the new snapshot is itself fully
		// durable — so nothing here is unsafe to leave as is.
		//
		// What must not happen is pretending nothing went wrong: silently
		// discarding this error used to leave logBytes stuck at its
		// pre-compaction value forever (compactLocked only zeroed it on full
		// success), so every later commit re-ran a full snapshot rewrite —
		// silently, since Store had no logger. This is now loud. compactLocked
		// itself resets logBytes and nextSeq the instant Truncate(0) succeeds
		// rather than only on its own full success (a second review found the
		// bug in relying on this call site alone: nextSeq has no
		// os.Stat-equivalent to resync from after the fact, so the reset has to
		// happen at the source) — the re-stat here is now a defensive backstop,
		// not the only fix, for whatever compactLocked did to the file before
		// an earlier failure that never reached the truncate at all.
		s.logger.Printf("storage: %s: automatic compaction failed, will retry: %v", s.dir, err)
		if info, statErr := s.log.Stat(); statErr == nil {
			s.logBytes = info.Size()
		}
	}
}

// poison marks the store terminal after a write or sync failure on the
// durability path. From here every Commit and Compact is refused until
// the process reopens the store, which is the only way back to a state
// replayLog has actually verified.
//
// This is deliberately the *only* remedial action taken here: no seek-back,
// no truncate attempt against a file whose most recent I/O just failed (very
// possibly with ENOSPC or EIO, in which case another write is not obviously
// safer than doing nothing). Whatever is on disk when a caller stops
// committing is, by construction, either a complete earlier record or a torn
// tail with nothing valid after it — exactly the shape replayLog already
// knows how to recover from, now that it can tell a torn tail from interior
// corruption.
func (s *Store) poison(cause error) {
	if s.failed != nil {
		return
	}
	s.failed = fmt.Errorf("storage: store is no longer accepting commits after a write "+
		"failure; reopen the directory to recover: %w", cause)
	s.logger.Printf("storage: %s: %v", s.dir, s.failed)
}

func (s *Store) apply(b *Batch) {
	for _, m := range b.mutations {
		switch m.op {
		case opPut:
			s.live[string(m.key)] = m.value
		case opDelete:
			delete(s.live, string(m.key))
		}
	}
}

// Close flushes and releases the store, including the datadir lock.
//
// Close always attempts every release step — sync, close the log,
// release the lock — rather than stopping at the first error, so a failure
// syncing never leaks the file descriptor or the lock. The first error
// encountered is what is returned; a poisoned store (see poison) skips the
// redundant sync (it already failed once) but still closes the file and
// releases the lock, and reports the original failure if nothing else went
// wrong on the way out.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var err error
	if s.log != nil {
		if s.failed == nil {
			err = s.sync(s.log)
		}
		if cerr := s.log.Close(); err == nil {
			err = cerr
		}
	}
	// No sync of the sidecar on the way out: every value it has ever held was
	// fsynced at the moment it was written, because a value that is not durable
	// when the barrier it describes returns is not evidence of anything.
	if s.commits != nil {
		if cerr := s.commits.Close(); err == nil {
			err = cerr
		}
	}
	if lerr := s.lock.release(); err == nil {
		err = lerr
	}
	if err == nil {
		err = s.failed
	}
	return err
}

// Compact writes a snapshot and truncates the log.
func (s *Store) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}
	return s.compactLocked()
}

// compactLocked writes the live view to a new snapshot, then truncates the log.
//
// The order matters and is the usual one: write to a temporary file, fsync it,
// rename it over the old snapshot (atomic on POSIX), fsync the directory, and
// only then truncate the log. A crash anywhere in that sequence leaves either
// the old snapshot with a full log, or the new snapshot with a log whose
// records it already contains. Replay is idempotent, so both recover correctly.
func (s *Store) compactLocked() error {
	tmpPath := filepath.Join(s.dir, snapshotTmp)
	tmp, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	body := encodeSnapshot(s.live)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := s.sync(tmp); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(s.dir, snapshotName)); err != nil {
		// Every other failure path in this function removes tmpPath; this one
		// used to be the exception, orphaning snapshot.tmp on a failed rename
		// (the same class of swallowed cleanup failure).
		os.Remove(tmpPath)
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}

	// The sidecar is reset to "nothing committed" BEFORE the log is truncated,
	// and that order is the same rule the whole design turns on — make the LOW
	// value durable first.
	//
	// Sequence numbers restart at zero when the log does, so a sidecar carrying
	// the pre-compaction generation's highest sequence would, against the new
	// log, claim commits that generation never had: it would refuse every cut
	// this store could ever legitimately need, including its own first torn
	// tail. Resetting after the truncate instead leaves exactly that state
	// durable across a crash in between. Resetting before it leaves the mirror
	// image — a low sidecar against a log that was not truncated — which is no
	// evidence, which is today's behaviour.
	//
	// A failure here returns before the truncate, so nothing is destroyed: the
	// snapshot is published and the log still holds everything it held, which
	// is a state replay already handles idempotently. compactIfDueLocked logs
	// the failure and retries on a later commit.
	if err := s.writeCommitsLocked(0); err != nil {
		return err
	}

	// truncateOpenLog rather than s.log.Truncate: on Windows the log's own
	// append handle is not allowed to set the file's length, and the truncate
	// has to be issued through a second handle. See truncate_windows.go —
	// without it every compaction on that platform failed here, after the new
	// snapshot was already published.
	if err := truncateOpenLog(s.log, 0); err != nil {
		return err
	}
	// The physical file is empty from this instant on, regardless of whether
	// anything below succeeds: the truncate is one atomic metadata operation, and
	// any reader — including this same process's own replayLog on a future
	// Open — sees a zero-length file the moment it returns, whether or not
	// the confirming fsync a few lines down ever lands.
	//
	// logBytes and nextSeq are reset *here*, immediately, rather than only on
	// this function's full success. A second, independent adversarial review
	// found the bug this guards against: a transient failure in the
	// *confirming* sync below used to leave nextSeq at its stale pre-compaction
	// value while the file really was already empty. The caller's failure
	// handler resynced logBytes from a fresh os.Stat (which happened to read
	// back 0 and looked fine), but nothing resynced nextSeq the same way —
	// os.Stat has no analogous way to recover "the next sequence number" short
	// of replaying the log, so the only reliable fix is to never let it go
	// stale in the first place. The next legitimate commit then durably wrote a
	// record numbered from the stale sequence, and on the next restart
	// replayLog — which always starts a fresh log at expectedSeq 0 — hit the
	// very "refuse to guess" branch the tail discriminator added, and
	// permanently refused to open a store that was never actually corrupted.
	s.logBytes = 0
	s.nextSeq = 0
	if _, err := s.log.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := s.sync(s.log); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadSnapshot() error {
	raw, err := os.ReadFile(filepath.Join(s.dir, snapshotName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	live, err := decodeSnapshot(raw)
	if err != nil {
		return err
	}
	s.live = live
	return nil
}

// replayLog applies every intact record in order, then truncates the file at
// a genuine torn tail — and only a genuine torn tail.
//
// A record that fails to decode used to be treated as "the process died
// writing this one; discard it and everything after it" unconditionally, at
// every offset. That reasoning only holds for the very last record in the
// file: a torn tail looks exactly like a partial or garbled record with
// nothing usable after it, because nothing was ever written after it. A bit
// flip in record 37 of 4,000 looks identical at the point of failure, but
// records 38 through 4,000 are sitting right there, intact, on disk — and the
// old code deleted them anyway, silently, because it had no way to tell the
// two cases apart.
//
// The discriminator has two halves, and they answer two different questions.
//
// The per-record sequence number answers "is there anything after this?": a
// later record whose own sequence is at least the one expected next is proof
// the writer kept going past the damage, which a crash tail cannot be.
//
// The header checksum answers the question that has to be settled *first* — "am
// I allowed to go looking?". A record's header claims a span; if that claim is
// genuine then no later record can begin inside it, and searching there would
// only turn up the damaged record's own payload, which is writer-controlled
// bytes that can be shaped to parse as a record (R2-STOR). If the claim is not
// genuine — a bit flipped into the length field, issue the interior-corruption
// defect's own opening example — then the span is a fiction and the intact
// records behind it are exactly what must not be deleted. Verifying the header
// on its own, before reading anything it frames, is what tells those two apart;
// without it the reader has to guess, and either guess loses real data in one
// of the two cases. See the record layout comment near the top of this file.
//
// So: a verified header that overruns the file is a short write, discarded
// without a search. An unverifiable header is searched in full. A verified
// header with a damaged payload is searched from the end of its own frame.
// A search that finds a later record makes replayLog refuse to open rather
// than delete what is behind the damage — the same policy decodeSnapshot
// already applies to the other half of this format. A search that finds
// nothing, or that was never permitted, means the damage is the tail: it is
// discarded, and logged rather than performed in silence, because a repair a
// node makes to its own durability log is precisely the kind of event an
// operator needs to be able to notice happened at all.
//
// "A later record" needs one qualification, and it decides a third case.
// Damage inside a multi-record transaction whose commit record never
// landed is not interior corruption, however many of that transaction's other
// parts survived it: those parts are durable, inert and about to be cut away
// anyway, so finding one proves nothing about committed data. So the three
// categories this function separates are a torn tail (discard), an abandoned
// group — with or without holes in it (discard the whole group), and interior
// damage, meaning an intact record at or beyond the point where committed
// data begins (refuse). Only the third refuses.
//
// The dismissal is narrow, and the statement of how narrow is the cleanest
// justification of the whole rule: a record is dismissed only if it claims to
// be a *non-final* part of the open group, so dismissal requires more >= 1 and
// no record with more == 0 can ever be dismissed. Every committed transaction
// — ordinary commit or group — terminates in a more == 0 record. So this
// classification can discard a committed transaction only when that
// transaction's own terminal record is already unreadable, in which case no
// reader could have applied it anyway. See openGroupFinalSeq below.
func (s *Store) replayLog() error {
	path := filepath.Join(s.dir, logName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	// A log written by a different format version is refused outright, the
	// same way decodeSnapshot refuses a foreign snapshot version: it is not
	// corruption, and scanning it record-by-record with today's layout would
	// either fail every record (and get truncated to nothing, as a "torn
	// tail" scan finds no bytes it can even try to parse) or, worse, decode
	// garbage that happens to look plausible. One log cannot legitimately mix
	// versions — FormatVersion is fixed at build time — so checking the first
	// record suffices.
	if len(raw) >= 4 && raw[0] == recordMagic[0] && raw[1] == recordMagic[1] &&
		raw[2] == recordMagic[2] && raw[3] != FormatVersion {
		return fmt.Errorf("%w: log is version %d, this build reads %d",
			ErrFormat, raw[3], FormatVersion)
	}

	// A transaction that spans several records (CommitGroup) is applied only
	// once its final record — the one declaring no further parts — has been
	// read intact. Until then its batches sit here, durable on disk but
	// invisible, and group* remembers where the transaction began so an
	// incomplete one can be cut away rather than left for a later commit to
	// be mistakenly folded into.
	var pending []*Batch
	var groupStart int
	var groupSeq uint64
	// groupFinalSeq is the sequence the group's commit record will carry:
	// seq+more is invariant across a group, because each further part adds
	// one to the sequence and takes one off the countdown, and the last part
	// declares more=0. It is stored rather than the raw countdown because the
	// same number answers both questions this replay asks about a group — is
	// this part where the countdown says it should be, and is the commit
	// record present — so the two cannot drift apart into disagreement.
	var groupFinalSeq uint64

	// The out-of-band evidence, read once, before anything in the log is
	// believed. Every truncation point below consults it through
	// commitEvidence.withholds and through nothing else, so the boot path and
	// Diagnose's operator path cannot come to disagree about the same bytes —
	// which is what they once did: `repair` printed "nothing to repair" about a
	// store the boot path deleted a committed transaction from.
	//
	// A read failure is not fatal here. See readCommitEvidence: no evidence is
	// today's behaviour, and the only thing evidence can do is withhold a cut.
	evidence, evErr := readCommitEvidence(s.dir)
	if evErr != nil {
		s.logger.Printf("storage: %s: the commit record sidecar could not be read (%v); "+
			"recovery falls back to reading the log alone, which cannot tell a commit record "+
			"that was never written from one that was written and destroyed", s.dir, evErr)
	}

	var consumed int
	var expectedSeq uint64
	for consumed < len(raw) {
		batch, seq, more, n, status := decodeRecord(raw[consumed:])

		// scanFrom is where a forward search for "did the writer keep going
		// past this point?" may legitimately begin, as an offset relative to
		// consumed. -1 means no search is permitted at all. The distinction
		// is the entire discriminator: searching a region the damaged
		// record's own *verified* header already claims as its payload finds
		// writer-controlled bytes, not evidence (R2-STOR).
		scanFrom := -1

		switch status {
		case decodeOK:
			if seq == expectedSeq {
				// Inside a group the remaining-part count counts down by
				// exactly one per record. A verified header that says
				// otherwise was not written by this code (CommitGroup emits
				// count-1-i and nothing else does), and a reader that
				// shrugged at it could apply a strict subset of a
				// transaction — the one outcome this whole path exists to
				// prevent. Refuse, the same way an out-of-sequence record is
				// refused, rather than guess which count is right.
				if len(pending) > 0 && seq+uint64(more) != groupFinalSeq {
					return fmt.Errorf("%w: record at offset %d in %s belongs to the group "+
						"starting at offset %d but declares %d further part(s) where %d was "+
						"expected — refusing to apply part of a transaction",
						ErrCorrupt, consumed, path, groupStart, more,
						groupFinalSeq-seq)
				}
				if more > 0 {
					// Not the transaction's last record. Hold it.
					if len(pending) == 0 {
						groupStart, groupSeq = consumed, seq
						// seq is expectedSeq here, which this loop counts up
						// from zero, so the sum cannot overflow however large
						// a crafted header's more field is.
						groupFinalSeq = seq + uint64(more)
					}
					pending = append(pending, batch)
					consumed += n
					expectedSeq++
					continue
				}
				// The transaction's final record: everything it was waiting
				// on is durable, so the whole thing becomes visible now, in
				// the order it was written.
				for _, part := range pending {
					s.apply(part)
				}
				pending = pending[:0]
				s.apply(batch)
				consumed += n
				expectedSeq++
				continue
			}
			// The record is intact — header checksum, record checksum and
			// all — but its sequence number is not the one that should
			// follow what was just applied. A crash never produces a
			// well-formed record out of sequence, only a missing or
			// truncated one. Something wrote here that this replay did not
			// expect (interior corruption, a log from before a compaction
			// that was never truncated, two writers) — refuse rather than
			// guess.
			return fmt.Errorf("%w: record at offset %d in %s has sequence %d, expected %d — "+
				"refusing to guess which is right", ErrCorrupt, consumed, path, seq, expectedSeq)

		case decodeMaxLenExceeded:
			return fmt.Errorf("%w: record at offset %d in %s carries a verified header "+
				"declaring a payload longer than this build ever writes — encodeRecord "+
				"refuses a batch that large before any byte reaches disk, so these bytes "+
				"did not come from this format", ErrCorrupt, consumed, path)

		case decodeHeaderUntrusted:
			// The frame itself failed its checksum, so nothing it says about
			// where this record ends may be believed — including, and
			// especially, a length that appears to run past the end of the
			// file. Search everything that is left.
			scanFrom = 0

		case decodePayloadBad:
			// The frame verified, so the record's end is a fact even though
			// its contents are damaged. Search from that end forward, and
			// never from inside the payload.
			scanFrom = n

		case decodeTorn:
			// Proven short write; nothing exists past it to find. See
			// decodeTorn.
		}

		// What counts as proof that committed data sits behind this damage —
		// the only reason to refuse rather than cut. Outside a group, any
		// intact record carrying at least expectedSeq: a writer that kept
		// going, and a single-record commit is durable the moment it is
		// written.
		//
		// Inside an open group one class of record is dismissed: this
		// group's own remaining non-final parts. Such a part is
		// durable, inert and about to be cut away, so it proves nothing —
		// CommitGroup's argument that "none of them mean anything until the
		// commit record lands" has to hold for replay as well as for apply.
		// Treating a surviving part as proof made the same abandoned
		// transaction recoverable or fatal purely as a function of writeback
		// order: part never written, discarded and open; part zeroed with
		// the next part durable, permanent refusal.
		//
		// The dismissal is a positive claim of membership, not a sequence
		// floor, and that distinction is the whole defence. A floor at
		// groupFinalSeq would let a forged countdown — the header checksum
		// is no defence, attack_test's setMore recomputes it — name a commit
		// record far past the end of the file, pushing every genuinely
		// committed record behind the damage below the floor and converting
		// this refusal into a truncation. Requiring the record to point at
		// exactly this group's commit record means an attacker must forge
		// every surviving record consistently, and a log where every part
		// agrees it belongs to one uncommitted transaction *is* an abandoned
		// transaction.
		//
		// The group's commit record itself is never dismissed, and that is
		// the half that keeps this conservative: CommitGroup fsyncs parts
		// 0..n-2 *before* the commit record is written at all, so a commit
		// record on disk proves that barrier returned and that every earlier
		// part was durable. Damage under a present commit record cannot be a
		// crash artefact — it is interior corruption of committed data, and
		// cutting the group away would delete a transaction the caller was
		// told had committed.
		openGroupFinalSeq := uint64(0)
		if len(pending) > 0 {
			openGroupFinalSeq = groupFinalSeq
		}

		if scanFrom >= 0 && scanFrom <= len(raw)-consumed {
			region := raw[consumed+scanFrom:]
			off, result := findNextRecord(region, expectedSeq, openGroupFinalSeq)
			switch result {
			case scanNothingFound:
				// The search came back empty. Whether that means "nothing was
				// ever committed back there" is NOT a question these bytes can
				// answer, and the truncation below no longer pretends it is:
				// the sidecar check a few lines down is what settles it, and it
				// settles it for any number of damage sites rather than for two
				// once and for all.
				//
				// Three attempts to settle it from inside the log preceded
				// this one — successorRunEnd, commitRecordSlotOccupied, and its
				// lastMore == 1 term — and each was a guess wearing a proof's
				// clothing: the two histories are byte-identical, so no
				// function of these bytes is correct on both. They are gone
				// rather than kept as a fallback, because a store carrying both
				// a durable answer and an inference from the same bytes has two
				// sources and no test that says which one to believe.
			case scanFound:
				at := consumed + scanFrom + off
				// What a hit means depends on where the search was allowed to
				// begin, and this message used to state the stronger of the two
				// readings unconditionally — in both of its halves, and both
				// were false for the shape a crash-damaged record header takes.
				//
				// With the frame verified (scanFrom is the record's own end)
				// the hit lies past this record's last byte, so some writer
				// really did produce data after it: damage inside the log,
				// and cutting here would delete that data.
				//
				// With the frame unusable there is no honest end to search
				// from, so the search starts at the damaged record's own
				// first byte and its region includes that record's payload —
				// which is a network-supplied block body, written verbatim.
				// A hit there may be nothing but record-shaped bytes inside
				// the last record of a crashed log, which is precisely a
				// crash mid-write, and which discarding from this offset
				// onward is precisely the repair for. Telling an operator
				// otherwise pointed them away from the only recovery that
				// works. Open still refuses either way, because it cannot
				// tell the two apart and a silent guess is what the old reader did; the
				// difference is that the operator is now told which question
				// is open, and `zycordd repair` can be told to answer it.
				if scanFrom > 0 {
					return fmt.Errorf("%w: the record at offset %d in %s, where sequence %d was "+
						"expected, has a damaged payload inside a frame that verified — and an "+
						"intact record exists at offset %d, past the end that frame declares, so "+
						"a writer kept going after this record: this is damage inside the log, "+
						"and deleting from here would delete that record too. See docs/RUNNING.md, "+
						"\"Recovering a damaged data directory\"", ErrCorrupt, consumed, path,
						expectedSeq, at)
				}
				return fmt.Errorf("%w: the record at offset %d in %s, where sequence %d was "+
					"expected, has a frame that failed its own checksum, so the search for later "+
					"records had to begin inside it — and a record decoded at offset %d, which is "+
					"either data written after this one or record-shaped bytes inside this one's "+
					"own payload. This reader cannot tell which, and refuses rather than guess. "+
					"See docs/RUNNING.md, \"Recovering a damaged data directory\"",
					ErrCorrupt, consumed, path, expectedSeq, at)
			case scanInconclusive:
				// The scan hit its work limit before it could rule the log
				// either way, so nothing has been established — and "not
				// established" must never fall through to the truncate. See
				// scanInconclusive.
				return fmt.Errorf("%w: the record at offset %d in %s, where sequence %d was "+
					"expected, is damaged, and the search for intact records after it exceeded "+
					"its work limit without settling the question — refusing rather than "+
					"discarding data that may be intact. See docs/RUNNING.md, \"Recovering a "+
					"damaged data directory\"", ErrCorrupt, consumed, path, expectedSeq)
			}
		}

		// A genuine torn tail: either the damage proved on its own terms
		// that nothing could follow it, or a search that was allowed to look
		// turned up nothing. Safe to discard — but say so, loudly, rather
		// than performing a silent repair to the node's own durability log.
		//
		// If the tear landed inside a multi-record transaction, the cut goes
		// back to that transaction's first record, not to the damaged one:
		// its earlier parts are individually intact but collectively
		// meaningless, they were never applied above, and leaving them on
		// disk would put them in front of whatever the next commit writes —
		// where a later record declaring itself the end of a transaction
		// would sweep them in. Cutting at the start of the group is what
		// makes "all or nothing" survive the repair as well as the crash.
		//
		// The line this emits does not name a cause, and that is deliberate. It
		// used to say "torn byte(s) ... after a crash mid-write", which the
		// abandoned-group analysis retired twice over. The cut may run back
		// over records that are individually intact — a whole abandoned
		// transaction — so "torn" is wrong about the bytes; and the damage that
		// opened the cut may be a hole rather than a prefix (CommitGroup: what
		// reaches stable storage is "a hole, not a prefix"), so "mid-write" is
		// wrong about the shape. What replayLog actually established is that
		// nothing intact follows, and that is what the line now reports.
		abandonedGroup := len(pending) > 0

		// THE OUT-OF-BAND REFUSAL — the commit sidecar, closing both ambiguous-cut
		// shapes: the cut that deletes a committed transaction when a group loses
		// both its first part and its commit record, and the silent boot-time
		// discard of a group that loses an interior part and its commit record.
		//
		// firstCutSeq is the first sequence this truncation would remove: the
		// sequence expected at the damage, or — where the cut runs back over an
		// abandoned group — that group's opening sequence, because every part
		// of it goes too. If the sidecar verifies and says a transaction at or
		// above that sequence was reported committed, then a commit record this
		// log cannot account for did land, and cutting would delete it.
		//
		// This is a REFUSAL and never an authorisation. It cannot fire on any
		// store where the log alone already settles the question, because the
		// branches above have all returned by now; and it cannot turn a refusal
		// into a cut, because the only thing it does is return an error.
		firstCutSeq, cutAt := expectedSeq, consumed
		if abandonedGroup {
			firstCutSeq, cutAt = groupSeq, groupStart
		}
		if evidence.withholds(firstCutSeq) {
			return fmt.Errorf("%w: the record at offset %d in %s, where sequence %d was "+
				"expected, is damaged, and discarding from offset %d would remove sequence %d "+
				"onward — but this store's commit record, written and fsynced after the log's "+
				"own barrier returned, says sequence %d was reported committed. A commit record "+
				"this log can no longer account for did land, so the transaction it committed "+
				"is behind the damage and the discard would delete it. This store cannot be "+
				"repaired locally; resync it. See docs/RUNNING.md, \"Recovering a damaged data "+
				"directory\"", ErrCorrupt, consumed, path, expectedSeq, cutAt,
				firstCutSeq, evidence.high)
		}

		if abandonedGroup {
			consumed, expectedSeq = groupStart, groupSeq
			pending = pending[:0]
		}
		discarded := len(raw) - consumed
		recovered := "no record before it was intact"
		if expectedSeq > 0 {
			recovered = fmt.Sprintf("%d record(s) recovered (sequence 0..%d)",
				expectedSeq, expectedSeq-1)
		}
		if abandonedGroup {
			s.logger.Printf("storage: %s: discarded %d byte(s) at offset %d — an incomplete "+
				"multi-record transaction beginning at sequence %d, whose remaining records are "+
				"damaged or absent; its own intact parts go with it, because none of them meant "+
				"anything without the commit record. Nothing intact follows; %s",
				path, discarded, consumed, groupSeq, recovered)
		} else {
			s.logger.Printf("storage: %s: discarded %d unreadable byte(s) at offset %d — an "+
				"unfinished write at the end of the log. Nothing intact follows; %s",
				path, discarded, consumed, recovered)
		}
		if err := truncateDurably(path, int64(consumed)); err != nil {
			return err
		}
		if err := syncDir(s.dir); err != nil {
			return err
		}
		break
	}

	// A transaction whose parts are all intact but whose final record never
	// arrived: the log simply ends part-way through a CommitGroup. Nothing
	// of it was applied, and — exactly as in the torn-tail case above — its
	// bytes have to go, or the next commit's record would arrive behind them
	// and complete a transaction that never happened.
	//
	// That last clause is load-bearing and worth stating plainly, because an
	// adversarial pass over this design found it by hand: a record carries
	// no transaction identity, only a countdown, so abandoned parts with an
	// unrelated later record behind them *would* be folded together. What
	// makes that shape unreachable rather than merely unlikely is a pair of
	// facts, and both have to keep holding. A write or fsync failure poisons
	// the store, so the process that suffered one appends nothing further;
	// and this truncation runs inside Open, before the log file is
	// opened for appending at all, so no writer can put a record behind
	// these bytes without passing through here first.
	if len(pending) > 0 {
		// The same out-of-band refusal as above, at replayLog's second and last
		// truncation point. The rule is spelled once, in commitEvidence, and
		// asked twice: a store whose log simply ENDS part-way through a
		// transaction is the shape the ambiguous-cut tail fixture takes after a
		// truncating second fault, and it reaches the truncate by this path
		// rather than by the loop's.
		if evidence.withholds(groupSeq) {
			return fmt.Errorf("%w: the log in %s ends part-way through the multi-record "+
				"transaction beginning at offset %d (sequence %d), and discarding it would "+
				"remove sequence %d onward — but this store's commit record, written and "+
				"fsynced after the log's own barrier returned, says sequence %d was reported "+
				"committed. A commit record this log can no longer account for did land. This "+
				"store cannot be repaired locally; resync it. See docs/RUNNING.md, "+
				"\"Recovering a damaged data directory\"",
				ErrCorrupt, path, groupStart, groupSeq, groupSeq, evidence.high)
		}
		s.logger.Printf("storage: %s: discarded %d byte(s) at offset %d — a multi-record "+
			"transaction (sequence %d..%d) whose final record never landed; none of it was "+
			"applied", path, len(raw)-groupStart, groupStart, groupSeq, expectedSeq-1)
		if err := truncateDurably(path, int64(groupStart)); err != nil {
			return err
		}
		if err := syncDir(s.dir); err != nil {
			return err
		}
		expectedSeq = groupSeq
	}

	// THE THIRD SITE, AND IT IS NOT A TRUNCATION POINT. A log that reads
	// cleanly to its end can still fail to account for a committed sequence, if
	// the fault REMOVED the record rather than damaging it: truncate a durable
	// commit record away entirely and what is left is a clean prefix ending on a
	// record boundary, with no damage for either of the branches above to find.
	// The node would boot, silently missing a transaction it reported committed,
	// and `repair` would say "the log reads to its end. Nothing to repair".
	//
	// Found by the k = 0 row of TestTheSidecarRefusesTheTailShapeAtEveryTruncat-
	// ionDepth, which is the same sweep as every other k and has no damage in
	// it. The design's own summary says the rule sits "at each of replayLog's
	// two truncation points"; that is where a CUT can be withheld, and this is
	// the case where there is nothing to cut and the transaction is gone anyway.
	//
	// It is the same conjunction and the same direction — refuse, never
	// authorise — so it adds no lever. What it does add is a constraint on
	// Repairer.Apply, which must therefore lower the sidecar BEFORE it
	// truncates: the other order would leave a high sidecar against a shortened
	// log, and this branch would then refuse the store an operator just
	// repaired, for ever.
	if evidence.withholds(expectedSeq) {
		return fmt.Errorf("%w: the log in %s reads cleanly to its end and accounts for "+
			"sequences up to %d, but this store's commit record, written and fsynced after "+
			"the log's own barrier returned, says sequence %d was reported committed. The "+
			"record that committed it is not in this log and was not discarded by this "+
			"recovery — it is gone. This is also the state left behind by `zycordd repair` "+
			"run with a binary older than this one — see docs/RUNNING.md: run repair with "+
			"the same binary the node runs. This store cannot be repaired locally; resync "+
			"it. See docs/RUNNING.md, \"Recovering a damaged data directory\"",
			ErrCorrupt, path, expectedSeq, evidence.high)
	}

	// The next record this store writes, in this process or the next one that
	// opens this (now possibly truncated) log, continues the sequence replay
	// just verified.
	s.nextSeq = expectedSeq
	return nil
}

// truncateDurably shortens a file and fsyncs it, so the new size is on stable
// storage before anything is written on top of it.
//
// os.Truncate alone is not enough, and syncing the parent directory does not
// substitute for it: a directory fsync makes the file's *name* durable, not
// its length. A truncation that is still only in the page cache when the
// machine loses power leaves the old bytes past the cut, and the records the
// next replay appends land in front of them — so a stale record from before
// the repair can reappear behind fresh ones. Those stale bytes verify (they
// were a real record once, checksums and all) and carry sequence numbers from
// the same space this log is reusing.
//
// The loud outcome is that replayLog finds one, believes the writer continued
// past the damage, and refuses to open a store that was never corrupt. The
// worse one is quiet: a stale record whose sequence happens to equal the one
// expected next decodes cleanly and is *applied*, so a mutation from before
// the repair lands in a state no fold ever produced — the exact failure this
// package's opening paragraph exists to prevent. Making the repair durable
// before anything builds on it is what keeps both from being reachable.
func truncateDurably(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// The forward scan's work bound is a budget of *checksummed bytes*, not a
// count of candidates.
//
// Both forms exist to stop the same shape, which chance does not produce and
// an attacker gets for free: a run of well-formed headers, each claiming a
// payload spanning nearly the rest of the buffer, so that checksumming each
// claimed span does close to O(n²) work. Those headers are cheap to
// manufacture (CRC32 is not secret) and they arrive inside an ordinary batch
// value, because a block record is the serialized block, network-supplied,
// put into the log verbatim.
//
// Counting candidates charged the cheap ones and the expensive ones the same,
// and that is what made this bound a liveness bug in its own right. A
// header whose declared span runs past the end of the buffer, or past
// MaxRecordLen, is rejected by arithmetic — no payload is ever checksummed
// for it — yet it spent an attempt. 257 such headers — 8224 precomputed
// bytes, sitting in one block body — exhausted the budget and turned a torn
// tail (which the very same log recovers from cleanly when the payload is
// benign) into scanInconclusive and a permanent refusal to open. Charging the
// bytes actually fed to crc32 prices those headers at zero, which is what
// they cost.
//
// The floor is absolute rather than proportional to the log, because a
// proportional budget is the attacker's friend: it grows with the buffer he
// is allowed to fill. The proportional term is there only so that an honest
// log larger than the floor keeps the guarantee that an honest scan can never
// bind, and its factor is derived, not picked. The genuine records in a
// scanned region are disjoint frames, so summing recordHeaderLen (32) + len_i
// over them is at most the region size n; each is charged recordCRCOff (28) +
// len_i, which is 4 bytes less apiece. An honest scan therefore costs at most
// n, not 2n as an earlier draft of this comment had it. The factor 4 is not
// load-bearing for honest data at any store size — 1 would do — and is left
// as slack.
//
// Only the payload checksum is charged. verifyHeader's own 24-byte CRC
// (recordHdrCRCOff, not the 20 two earlier drafts of this file claimed) runs
// uncharged on every occurrence of the magic. That is linear in the region
// whatever is in it, and the constant is worth writing down so the next
// reader need not re-derive it: recordMagic has no proper border, so its
// occurrences are at least 4 apart and a region of nothing else yields at
// most n/4 candidates — about 6n bytes of free CRC. The border argument rests
// on FormatVersion != 'C'; if that ever ceased to hold the bound would loosen
// to 8n and no further, so the failure mode is benign. Linear and cheap
// against a bound that exists to stop quadratic work, so it is left free
// rather than given a second budget.
//
// This bound is not starvation-proof, and the price it puts on starvation is
// worth stating exactly, because an earlier draft of this comment stated it
// as a single number and that number was wrong in the direction that matters.
//
// A charged candidate may cost as much as the whole region: one 32-byte
// header can declare a span that is in bounds and reaches the end of the
// buffer from its own position, and that span is charged in full. So the
// crafted bytes needed to exhaust budget = 2^30 + 4n are
//
//	k > 4 + 2^30/n headers, i.e. A(n) = recordHeaderLen * (4 + 2^30/n) bytes
//
// which *decreases* in the scanned region n. It is ~185 KB only near
// n ~= 185 KB; it is 1184 bytes (37 headers) at n = 32 MiB — measured, not
// estimated — and a few hundred bytes on a log of a gibibyte. Below the old
// attempt bound's 8224 bytes for every n above ~4.2 MB.
//
// That is a knowing trade, made with the numbers in view. The pricing defect
// this bound fixes was a *liveness* bug that fired on honest crashed nodes:
// headers costing crc32 nothing spent budget, so an ordinary torn tail became a
// permanent refusal to open. Fixing it costs worst-case attacker price on large
// regions. The outcome on both sides of the trade is scanInconclusive — a loud
// refusal, never a truncation — so no data is at risk either way; what moves is
// how cheaply an attacker can stop a node that has also crashed with a damaged
// header from booting.
//
// A per-candidate cap does not close it, in either of the two forms it
// suggests itself in, and both are worth naming because each looks safe.
//
// Capping the *charge* — bill a candidate less than the bytes actually fed to
// crc32 — unbinds the budget from the work, which is the quadratic-CPU attack
// this bound exists to stop.
//
// Capping the *work* is the more tempting of the two, because bounding what
// goes into crc32 looks like bounding work by definition. It is the worse
// one. An over-cap candidate is then never checksummed, which leaves only two
// exits and no third. Skip it uncharged, and a genuine large record becomes
// invisible: the scan runs to the end, returns scanNothingFound — the one
// result replayLog truncates on — and committed data is deleted silently.
// That is not a cheaper refusal, it is the data-loss failure this whole file
// exists to prevent, arrived at from the other side. Or refuse on it, and one
// 32-byte header buys the boot denial outright, for less than the 1184 bytes
// above.
//
// Bounding the *region* is what closes it, and that bound is still open — which
// this makes load-bearing rather than a residual, since it is now the only thing
// standing between this scan and a sub-kilobyte boot denial.
const (
	findNextRecordScanBudgetFloor  int64 = 1 << 30
	findNextRecordScanBudgetPerLen int64 = 4
)

// bootScanBudget is the budget the boot path spends on a region of n bytes.
//
// It is spelled once because three callers have to ask the boot path's
// question on the boot path's terms: findNextRecord, replayLog's commit-slot
// consult, and the mirror in Diagnose that exists to report what Open will do.
// A second spelling of this arithmetic is a mirror that answers a question
// Open was never asked.
func bootScanBudget(n int) int64 {
	return findNextRecordScanBudgetFloor + findNextRecordScanBudgetPerLen*int64(n)
}

// scanResult is what a forward scan established. Three outcomes, deliberately
// not two: an exhausted budget is not evidence of absence, and collapsing it
// into "found nothing" is what turned this bound into a silent deletion.
type scanResult int

const (
	// scanNothingFound: the scan reached the end of the buffer having decoded
	// every candidate in it. Nothing intact follows, so the damage really does
	// reach the end of the log and may be discarded.
	scanNothingFound scanResult = iota

	// scanFound: a later record decoded completely and carries a sequence at
	// least the one expected. The writer produced data past the damage, so
	// this is not a crash tail.
	scanFound

	// scanInconclusive: the scan spent its work budget before it
	// reached the end of the buffer. It has ruled out nothing — the intact
	// records it was looking for may sit past the point where it stopped.
	//
	// This is its own outcome because the alternative was a live bug. Folding
	// it into scanNothingFound let replayLog take the torn-tail branch and
	// truncate, so ~7 KB of record-shaped bytes inside one batch value — bytes
	// a node accepts over the network and writes to the log verbatim — silently
	// deleted every intact record behind a damaged one, which is the
	// interior-corruption defect's failure reproduced through the bound meant
	// to be free. The irony is worth keeping in view: the bug was one boolean
	// standing for two different reasons, which is what this whole file exists
	// to stop doing. replayLog now refuses on it.
	scanInconclusive
)

// findNextRecord scans raw for a record that decodes completely — header
// checksum, record checksum, mutation encoding — and whose sequence number is
// at least minSeq. Finding one is proof that the writer produced more data
// after whatever damaged the bytes at the start of raw, which is what tells
// interior corruption apart from a crash tail.
//
// The scan is anchored on the magic and then gated on the header checksum
// before any payload is touched, so a coincidental 4-byte match costs
// recordHdrCRCOff (24) bytes of CRC rather than a checksum over a length
// field's worth of buffer. A candidate has to clear ~2^-32 on the header
// checksum and ~2^-32 on the record checksum to be believed, which is what
// keeps a false "this is interior corruption" refusal off an honest crashed
// node. groupFinalSeq, when non-zero, says a multi-record transaction is open
// and names the sequence its commit record will carry. A record that positively
// claims membership in that transaction — it sits below the commit record and
// its own countdown points at exactly it — is one of the parts about to be cut
// away, so it is not evidence of anything and the scan keeps looking. See
// replayLog. Zero means no group is open and every intact in-sequence record
// counts.
func findNextRecord(raw []byte, minSeq, groupFinalSeq uint64) (offset int, result scanResult) {
	return findNextRecordWithin(raw, minSeq, groupFinalSeq, bootScanBudget(len(raw)))
}

// findNextRecordWithin is findNextRecord with the budget supplied rather than
// derived. It exists so the boundary the three-valued result was built for — a
// budget that runs out is scanInconclusive and never scanNothingFound — can be
// exercised at all. The derived budget starts at a gibibyte of checksummed
// bytes, which no test can reach honestly, and since the budget became one of
// checksummed bytes the end-to-end test that used to reach the old attempt
// bound no longer does; an untestable safety boundary is one that quietly stops
// holding.
//
// PRECONDITION: raw must run to the end of the log. Two of this function's
// rules are sound only because of it, and neither says so at its own site.
// Pricing an overrunning span at zero is sound because a record whose frame
// runs past the end of the file cannot exist on disk — over a prefix window it
// merely runs past the window, so a genuine record would become an uncharged
// skip. And scanNothingFound, the one result replayLog truncates on, means
// "nothing intact follows in the log" only when the buffer's end is the log's
// end. And the group membership rule below is sound only because a group that
// opened in the log has all of its surviving records inside this buffer: a
// window that ends inside a group hides that group's commit record, which then
// reads as absent-because-never-written rather than
// absent-because-out-of-window, and replayLog truncates a committed
// transaction. A checkpoint boundary must therefore not fall inside a group.
// Bounding the search region would mean handing this function a bounded window;
// doing so changes what all three of those mean, silently, and must revisit
// them here.
func findNextRecordWithin(raw []byte, minSeq, groupFinalSeq uint64, budget int64) (offset int, result scanResult) {
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
			// decodeRecord rejects these two by arithmetic and reads no
			// payload, so the candidate costs nothing and is charged nothing.
			// Skipping the call is exactly equivalent to making it; what is
			// not equivalent is pretending it was expensive.
			if length <= MaxRecordLen && int64(recordHeaderLen)+int64(length) <= int64(len(raw)-pos) {
				// What a full decode will hand to crc32: the header up to the
				// record checksum, plus the whole span the header claims.
				cost := int64(recordCRCOff) + int64(length)
				if cost > budget {
					return 0, scanInconclusive
				}
				budget -= cost
				if _, seq, more, _, status := decodeRecord(raw[pos:]); status == decodeOK && seq >= minSeq {
					// Written as a subtraction rather than seq+more so a
					// forged sequence cannot wrap the comparison: the guard
					// establishes seq < groupFinalSeq first.
					partOfOpenGroup := groupFinalSeq != 0 && seq < groupFinalSeq &&
						uint64(more) == groupFinalSeq-seq
					if !partOfOpenGroup {
						return pos, scanFound
					}
				}
			}
		}
		i = pos + 1
	}
	return 0, scanNothingFound
}

// recordEscape is the byte escapePayload stuffs in to break an occurrence of
// recordMagic. Any value outside {'C', 'A', 'P', FormatVersion} would do; what
// the choice must not be is one of the four, because the stuffing byte itself
// has to be incapable of standing where the magic's own bytes stand.
const recordEscape byte = 0xFF

// escapePayload returns payload with every occurrence of recordMagic broken,
// and it is what closes the payload-plant defect.
//
// # What it buys, in the framing the measurement earned
//
// The plant was a free, universal, 32-byte constant: a complete terminal
// record — magic, largest sequence, more == 0, length == 0, both unkeyed CRC32
// fields — costs 32 bytes, satisfies every store at every log length forever,
// and rides into the log inside an ordinary value a remote party authored.
// findNextRecordWithin anchors on bytes.Index(raw, recordMagic), so those 32
// bytes sitting in a payload are a record the scan finds.
//
// After this, they are not. An escaped payload provably does not contain
// recordMagic, so a plant inside a payload cannot be found by the anchor at
// all. What that leaves is NOT structural impossibility, and the difference is
// the whole decision:
//
//	The escape covers payloads. It does not cover the record's own
//	unescaped 32-byte header, and the record-checksum field at recordCRCOff
//	is forceable to any four-byte value — recordMagic included — because
//	CRC32 is affine. A candidate anchored on a forced magic there was driven,
//	not argued: the real scan returns scanFound at region offset 28.
//
// So this is PRICING, not impossibility. The price is what makes it worth
// taking: a candidate anchored at recordCRCOff spans at most the payload's
// first ~34 bytes, so its own more and length fields fall inside payload[5,
// 5+keylen) — the batch's first key. Every durable Put and Delete in node/chain
// writes a key that is a fixed prefix followed by a hash-derived run, so those
// bytes cannot be authored; they can only be ground for offline. The cheapest
// instance derived needs 20 targeted bytes of a hash-derived key (~2^160); a
// cleverer non-empty construction reached ~2^76. Neither was constructed, and
// per rule 21 the claim stops at "not found, not proven impossible" — what is
// derived is the floor's NATURE: an offline preimage grind, which the 96 bytes
// an ISSUE certificate lets a signer choose freely do NOT reduce, because those
// bytes land at payload offset 75, past the candidate's reach, and are escaped
// here in any case. Issuing more certificates buys online samples of the same
// derivation, not offline work.
//
// The defect therefore moves from PAYABLE — one ordinary transaction — to NOT
// PAYABLE. It does not move to impossible, and writing "impossible" anywhere
// near this code would be the third time on this defect that a property measured
// under one condition was carried past it.
//
// # The clause this rests on is armed, not assumed
//
// "No durable write begins a payload with attacker-chosen bytes" is true today
// by enumeration of node/chain's keys, and it is the reopening trigger: the day
// a feature needs an attacker-chosen key at the start of a payload, the grind
// collapses and the payload-plant defect reopens by its own terms. It is defended by
// TestNoDurableWriteBeginsAPayloadWithAttackerChosenBytes in node/chain, which
// fails with that sentence rather than with a byte diff.
//
// # The named upgrade path, for whoever has to break that guard
//
// If that guard ever has to break — a feature genuinely needs an
// attacker-chosen key at a payload start — the escape stops being sufficient on
// its own and the upgrade is NOT another escape. It is a per-store secret: a
// salt generated at store init, living in the data directory, never derived
// from anything public, keying the record checksums. That removes the forgery
// class outright rather than pricing it, header carrier included: a
// record-shaped run cannot validate without the store's secret, and an actor
// who has the secret already has write access to the directory, where direct
// corruption is strictly cheaper. Its costs, so the next reader does not have
// to rediscover them: it is the first keyed integrity primitive in this package
// (every checksum here is CRC32 IEEE over content, none of it per-store), and a
// lost or corrupt salt is a resync. It was authorized by the owner and then
// declined for now, in favour of shipping the measured change — and the path is
// recorded here because this is where somebody stands when they need it.
//
// # The scheme, and why this one
//
// Walking the output rather than the input: a byte is appended after a
// recordEscape whenever appending it directly would put a magic in the output.
// The escaped byte is either FormatVersion (which would complete the magic) or
// recordEscape itself (which would otherwise be indistinguishable from a
// stuffing byte on the way back).
//
// The expansion this produces is bounded at 5/4, and the bound is the reason
// for the shape rather than a happy accident: every stuffing byte is charged to
// four distinct input bytes — the 'C', 'A', 'P' that put the output in the
// escaping state plus the byte escaped — and no input byte is charged twice,
// because the escaped byte is never one of 'C', 'A', 'P'. So
// len(escapePayload(p)) <= len(p) + len(p)/4, with equality reached by a
// payload of repeated recordMagic. A scheme that stuffed after every "CAP"
// regardless of what followed would be simpler and would expand by 4/3; this
// bound is what lets node/chain's mutationBudget stay under MaxRecordLen with
// the expansion inside the derivation rather than absorbed by a margin.
func escapePayload(payload []byte) []byte {
	// Nothing to break unless the first three magic bytes appear at all, which
	// is the ordinary case: the input is returned as it stands, and no
	// allocation happens on the commit path for a payload that carries no
	// "CAP". The caller owns the buffer either way — encodeRecord builds it
	// and appends it into the record — so handing the same slice back is safe
	// and the escape does not become a per-commit copy.
	if !bytes.Contains(payload, recordMagic[:3]) {
		return payload
	}
	out := make([]byte, 0, len(payload)+len(payload)/4)
	for _, c := range payload {
		if (c == FormatVersion || c == recordEscape) && endsWithMagicPrefix(out) {
			out = append(out, recordEscape)
		}
		out = append(out, c)
	}
	return out
}

// unescapePayload reverses escapePayload, and it is strict in both directions:
// it accepts only what escapePayload can produce, so the on-disk form of a
// payload is unique. ok is false for anything else — a stuffing byte at the end
// of the buffer, or one followed by a byte escapePayload would never have
// escaped. Both shapes are unreachable for this writer and both are cheap to
// author for someone who computes the record checksum himself, so they are
// refused rather than interpreted; decodeRecord reports that as decodePayloadBad,
// the same classification an unparseable mutation encoding already gets.
func unescapePayload(payload []byte) (out []byte, ok bool) {
	if !bytes.Contains(payload, recordMagic[:3]) {
		return payload, true
	}
	out = make([]byte, 0, len(payload))
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c == recordEscape && endsWithMagicPrefix(out) {
			i++
			if i == len(payload) {
				return nil, false
			}
			if payload[i] != FormatVersion && payload[i] != recordEscape {
				return nil, false
			}
			c = payload[i]
		}
		out = append(out, c)
	}
	return out, true
}

// endsWithMagicPrefix reports whether out's last three bytes are the magic's
// first three, which is the state in which the next byte decides whether a
// magic appears. It reads the OUTPUT and never the input, which is what makes
// the invariant hold for overlapping matches: "CAPCAP" + FormatVersion escapes
// at the second run even though a scan advancing four bytes at a time past the
// first run would have stepped over it.
func endsWithMagicPrefix(out []byte) bool {
	n := len(out)
	return n >= 3 && out[n-3] == recordMagic[0] &&
		out[n-2] == recordMagic[1] && out[n-1] == recordMagic[2]
}

// encodeRecord frames one batch as one log record. more is how many further
// records belong to the same transaction (0 for an ordinary commit and for
// the last part of a group) — see CommitGroup.
func encodeRecord(b *Batch, seq uint64, more uint32) ([]byte, error) {
	payload, err := encodeBatchPayload(b)
	if err != nil {
		return nil, err
	}
	// The escape is applied before the length field and both checksums, so
	// everything downstream — the frame, the two CRCs, the scan's arithmetic —
	// describes the bytes that are actually on disk. That is why this change
	// forces no call site: it moves what encodeRecord puts between the header
	// and the caller's bytes, and nothing else. See escapePayload.
	return frameRecord(escapePayload(payload), seq, more)
}

// encodeBatchPayload renders a batch's mutations as a record payload, before
// the escape. Split from encodeRecord for the same reason frameRecord is: the
// payload-plant fixtures need the two halves apart, so they can frame a payload the
// escape would otherwise have taken their plant out of.
func encodeBatchPayload(b *Batch) ([]byte, error) {
	// Refuse an oversized batch by arithmetic, before building anything. The
	// check used to run on the finished payload, which meant a batch a
	// gigabyte over the limit was materialised in full and then thrown away
	// — wasteful for one record, and worse for a group, where every part is
	// encoded before any is written, so one oversized part paid that cost
	// on top of holding all its siblings' encodings at once.
	size := 0
	for _, m := range b.mutations {
		size += 1 + 4 + len(m.key)
		if m.op == opPut {
			size += 4 + len(m.value)
		}
		if size > MaxRecordLen {
			return nil, ErrBatchTooBig
		}
	}

	payload := make([]byte, 0, size)
	for _, m := range b.mutations {
		payload = append(payload, m.op)
		payload = appendBytes(payload, m.key)
		if m.op == opPut {
			payload = appendBytes(payload, m.value)
		}
	}
	return payload, nil
}

// frameRecord wraps an already-escaped payload in the record header.
//
// It is split out of encodeRecord for one reason, and the reason is worth
// stating because the split is otherwise an invitation to misuse: the fixtures
// that document the payload-plant defect have to author a payload containing
// recordMagic, and after escapePayload no writer in this package can produce
// one. They call this directly, which is honest — the bytes they need are bytes
// this format no longer emits — where calling encodeRecord would silently
// escape the plant and leave the row asserting nothing. Production has exactly
// one caller, above, and it escapes first. Anything else that reaches for this
// is writing a payload the reader will refuse.
func frameRecord(payload []byte, seq uint64, more uint32) ([]byte, error) {
	// Checked on the escaped length, because the escape is what decides how
	// many bytes the record occupies. The bound is derived rather than hoped
	// for: escapePayload expands by at most 5/4 and node/chain's mutationBudget
	// counts encoded bytes and stays at 3/4 of MaxRecordLen, so the largest
	// part a reorg can build lands at 15/16 of the limit. See
	// TestTheEscapeExpansionLeavesMutationBudgetUnderMaxRecordLen in node/chain.
	if len(payload) > MaxRecordLen {
		return nil, ErrBatchTooBig
	}

	out := make([]byte, recordHeaderLen, recordHeaderLen+len(payload))
	copy(out[recordMagicOff:], recordMagic[:])
	binary.LittleEndian.PutUint64(out[recordSeqOff:], seq)
	binary.LittleEndian.PutUint32(out[recordMoreOff:], more)
	binary.LittleEndian.PutUint64(out[recordLenOff:], uint64(len(payload)))

	// The header checksum covers the magic, the sequence, the remaining-part
	// count and the length, and nothing else, so that a reader can establish
	// that the frame is genuine before it reads a single byte the frame
	// describes. See the layout comment at the top of this file for why that
	// ordering is the whole point.
	binary.LittleEndian.PutUint32(out[recordHdrCRCOff:],
		crc32.ChecksumIEEE(out[:recordHdrCRCOff]))

	// The record checksum covers the header and the payload together, which
	// is what binds one to the other: a payload cannot be moved between
	// records, nor a header re-pointed at a different payload, without
	// failing it.
	h := crc32.NewIEEE()
	h.Write(out[:recordCRCOff])
	h.Write(payload)
	binary.LittleEndian.PutUint32(out[recordCRCOff:], h.Sum32())

	return append(out, payload...), nil
}

// decodeStatus classifies why decodeRecord did or did not return an intact
// record. replayLog uses it to decide, for a record it failed to apply,
// whether it may treat the failure as an ordinary crash tail, must refuse
// outright, or has to go looking for evidence one way or the other.
//
// Every value below is a *proof* about the bytes, not a heuristic reading of
// them, and which one applies turns on a single question: did the header
// checksum verify? If it did, the frame is exactly what the writer produced,
// so what the frame says about where this record ends is true, and the
// classification follows from it. If it did not, nothing about the framing
// can be relied on and the reader has to fall back to searching.
type decodeStatus int

const (
	// decodeOK: the record's header and its payload both verified.
	decodeOK decodeStatus = iota

	// decodeTorn: an ordinary short write — the writer intended more bytes
	// than reached the disk. Two shapes qualify, and both are proofs rather
	// than guesses:
	//
	//   - Fewer bytes remain than a header needs. No record can begin in
	//     them either, since a record is at least recordHeaderLen bytes, so
	//     there is provably nothing after this point to lose.
	//   - The header verified, and the payload length it genuinely carries
	//     runs past the last byte on disk. Because the header is now known
	//     to be the writer's own, its span is a fact: the writer was in the
	//     middle of this record, no later record can have started before its
	//     end, and its end is past everything that exists.
	//
	// replayLog discards from here without scanning. Scanning would be
	// actively wrong, not merely wasteful: the bytes in the unfinished span
	// are this record's own payload, writer-controlled content that can be
	// made to contain something that parses as a later record (R2-STOR).
	decodeTorn

	// decodeHeaderUntrusted: recordHeaderLen bytes are present but they do
	// not verify against the header checksum — a wrong magic, a wrong
	// sequence, a wrong length, or all three.
	//
	// The frame is therefore unusable, and this is precisely the case the first
	// version of this fix got wrong. It read the length field anyway and,
	// finding it ran past the end of the file, called that a short write — so a
	// single bit flipped into the length field of an interior record (the
	// interior-corruption defect's own opening example) made replayLog discard
	// every intact record behind it, silently. Here nothing is read from the
	// frame at all. replayLog scans the whole remaining buffer for a later
	// record that verifies, and refuses if it finds one; only a scan that finds
	// nothing lets it treat the damage as a tail.
	//
	// One residual is worth stating rather than leaving to be discovered.
	// This scan does start at the damaged record's own first byte, because
	// with the frame unusable there is no honest way to know where its
	// payload ends — so if the damaged record is the *last* one, and its
	// payload happens to contain something that parses as a record, the scan
	// finds it and Open refuses a log whose only real problem was at the end.
	//
	// Two payload shapes reach that refusal. A record that decodes completely
	// and carries a high enough sequence trips scanFound. Candidates that
	// merely pass the 24-byte header checksum and never decode trip
	// scanInconclusive.
	//
	// THIS COMMENT CALLED THE FIRST SHAPE "a full forgery" AND THE SECOND
	// "far cheaper", AND THAT ORDERING IS BACKWARDS — measured, not argued
	// on the plant. The complete forgery is recordHeaderLen bytes: declare a
	// payload length of zero and the record checksum covers the header and
	// nothing else, so there is no payload to fabricate. Both checksums are
	// unkeyed and both are computed by the arithmetic in this file. And the
	// scan bounds the sequence only from BELOW, so the largest sequence
	// satisfies every store at every log length — the one per-store number in
	// a record header does not have to be known. One 32-byte constant, valid
	// everywhere, forever. The shape this comment called cheap is not the
	// cheaper one.
	//
	// Where those 32 bytes came from was the other half, and it was not a
	// privileged position: a value is copied from its caller verbatim, and
	// node/chain writes an accepted block's own encoding as one.
	//
	// THAT CARRIER IS CLOSED, AND THE CLOSE IS PRICING RATHER THAN
	// IMPOSSIBILITY. encodeRecord escapes recordMagic out of every payload it
	// writes, so bytes.Index can no longer find a plant among the caller's
	// bytes — the free, universal, 32-byte constant is gone. What is NOT gone
	// is the record's own unescaped 32-byte header: recordCRCOff holds a CRC32,
	// CRC32 is affine, and a handful of chosen payload bytes force that field
	// to any four-byte value, recordMagic included. A candidate anchored there
	// reaches only ~34 bytes into the payload, so its own more and length
	// fields have to come out of the batch's first key, and every durable key
	// in node/chain is a fixed prefix plus a hash-derived run — an offline
	// preimage grind (>= 2^76 for the cheapest construction anyone has
	// derived), not a fee. Payable became not payable. It did not become
	// impossible, and this file must not say that it did. See escapePayload for
	// the derivation, the reopening trigger and the named upgrade path, and
	// payloadplant_reach_test.go, which drives both halves: the payload carrier
	// is dead and the header carrier still returns scanFound.
	//
	// That second shape used to be free, because the scan's bound
	// counted candidates and a header declaring an impossible span was
	// rejected by arithmetic without a byte being checksummed — 8224 bytes of
	// precomputed headers refused the log forever. The bound is now a budget
	// of checksummed *bytes* (see findNextRecordScanBudgetFloor), which
	// prices those at what they cost: nothing. What remains is candidates
	// with in-bounds spans, ~185 KB of crafted payload; bounding the search region
	// is what would close that, and it is still open.
	//
	// Do not read this residual as needing a hardware fault. The premise this
	// comment once rested on — that a crash leaves the header intact — is
	// false, and the damaged-header refusal is where it was retired:
	// CommitGroup's own doc says a write reaching stable storage is "a hole,
	// not a prefix", and any record of two pages or more, which is every block
	// record, puts its header and its payload on different pages. An ordinary
	// crash can damage a header. The refusal is still the safe direction of the
	// two — a loud refusal, not a silent deletion. The obvious tightening,
	// requiring the record the scan finds to begin a chain that reaches the end
	// of the file, was rejected: a second damaged record anywhere later would
	// break the chain and turn this back into a silent truncation, trading a
	// rare loud failure for a rare quiet one.
	decodeHeaderUntrusted

	// decodeMaxLenExceeded: the header verified and declares a payload
	// longer than MaxRecordLen. encodeRecord refuses such a batch
	// (ErrBatchTooBig) before a byte reaches disk, so this build never wrote
	// it, and the header checksum says these are the bytes some writer did
	// write. That is not a crash mid-write and not a bit flip either — a
	// flipped bit would have broken the header checksum. Refuse on sight;
	// there is nothing a scan could add.
	decodeMaxLenExceeded

	// decodePayloadBad: the header verified and its span fits inside the
	// bytes on disk, but the payload does not check out — the record
	// checksum disagrees, or the mutation encoding inside it does not parse.
	//
	// The frame is trustworthy here, so replayLog knows exactly where this
	// record ends and scans from that point *forward* — never inside the
	// payload, which is the writer-controlled region. A later record found
	// beyond the frame is interior corruption; nothing found means the
	// damage is at the end of the log and can be discarded.
	decodePayloadBad
)

// verifyHeader checks a record header against its own checksum and returns
// the sequence, the remaining-part count and the payload length it carries.
// Callers must not read any of them unless ok is true: an unverified length
// field is exactly the input that made the previous version of this reader
// delete intact data, and an unverified more field would let a reader
// apply part of a transaction.
func verifyHeader(raw []byte) (seq uint64, more uint32, length uint64, ok bool) {
	if len(raw) < recordHeaderLen {
		return 0, 0, 0, false
	}
	if crc32.ChecksumIEEE(raw[:recordHdrCRCOff]) !=
		binary.LittleEndian.Uint32(raw[recordHdrCRCOff:recordCRCOff]) {
		return 0, 0, 0, false
	}
	// The magic is inside the checksummed span, so a header that verifies
	// but does not start with it was written by something that is not this
	// format at all rather than damaged — still not a record here.
	if string(raw[:4]) != string(recordMagic[:]) {
		return 0, 0, 0, false
	}
	return binary.LittleEndian.Uint64(raw[recordSeqOff:recordMoreOff]),
		binary.LittleEndian.Uint32(raw[recordMoreOff:recordLenOff]),
		binary.LittleEndian.Uint64(raw[recordLenOff:recordHdrCRCOff]), true
}

// decodeRecord returns the batch, its sequence number, how many further
// records belong to the same transaction, the number of bytes
// the record occupies, and a decodeStatus classifying the result. See
// decodeStatus for what replayLog does with each one. n is meaningful
// whenever the header verified — that is, for decodeOK and decodePayloadBad,
// where it is the full framed length of the record — and zero otherwise.
func decodeRecord(raw []byte) (batch *Batch, seq uint64, more uint32, n int, status decodeStatus) {
	if len(raw) < recordHeaderLen {
		return nil, 0, 0, 0, decodeTorn
	}
	seq, more, length, ok := verifyHeader(raw)
	if !ok {
		return nil, 0, 0, 0, decodeHeaderUntrusted
	}
	if length > MaxRecordLen {
		return nil, 0, 0, 0, decodeMaxLenExceeded
	}
	end := recordHeaderLen + int(length)
	if end > len(raw) {
		return nil, 0, 0, 0, decodeTorn
	}
	payload := raw[recordHeaderLen:end]

	h := crc32.NewIEEE()
	h.Write(raw[:recordCRCOff])
	h.Write(payload)
	if h.Sum32() != binary.LittleEndian.Uint32(raw[recordCRCOff:recordHeaderLen]) {
		return nil, 0, 0, end, decodePayloadBad
	}

	// Unescape after the record checksum has verified, never before: the
	// checksum covers what is on disk, and running a transformation over bytes
	// that have not been established as the writer's own is how a reader ends
	// up trusting an attacker's framing. See escapePayload.
	payload, ok = unescapePayload(payload)
	if !ok {
		return nil, 0, 0, end, decodePayloadBad
	}

	b := &Batch{}
	for len(payload) > 0 {
		op := payload[0]
		payload = payload[1:]
		key, rest, ok := takeBytes(payload)
		if !ok {
			return nil, 0, 0, end, decodePayloadBad
		}
		payload = rest
		switch op {
		case opPut:
			value, rest, ok := takeBytes(payload)
			if !ok {
				return nil, 0, 0, end, decodePayloadBad
			}
			payload = rest
			b.mutations = append(b.mutations, mutation{op: opPut, key: key, value: value})
		case opDelete:
			b.mutations = append(b.mutations, mutation{op: opDelete, key: key})
		default:
			return nil, 0, 0, end, decodePayloadBad
		}
	}
	return b, seq, more, end, decodeOK
}

func encodeSnapshot(live map[string][]byte) []byte {
	keys := make([]string, 0, len(live))
	for k := range live {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var body []byte
	for _, k := range keys {
		body = appendBytes(body, []byte(k))
		body = appendBytes(body, live[k])
	}

	out := make([]byte, 0, len(snapshotMagic)+12+len(body))
	out = append(out, snapshotMagic[:]...)
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(body)))
	out = append(out, lenBuf[:]...)
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(body))
	out = append(out, crcBuf[:]...)
	return append(out, body...)
}

func decodeSnapshot(raw []byte) (map[string][]byte, error) {
	const header = 8 + 8 + 4
	if len(raw) < header {
		return nil, fmt.Errorf("%w: bad header", ErrCorrupt)
	}
	// A snapshot written by a different format version is refused outright. It
	// is not corruption and must not be reported as such: the bytes may be
	// perfectly intact and simply mean something else.
	if string(raw[:7]) == string(snapshotMagic[:7]) && raw[7] != FormatVersion {
		return nil, fmt.Errorf("%w: snapshot is version %d, this build reads %d",
			ErrFormat, raw[7], FormatVersion)
	}
	if string(raw[:8]) != string(snapshotMagic[:]) {
		return nil, fmt.Errorf("%w: bad header", ErrCorrupt)
	}
	length := binary.LittleEndian.Uint64(raw[8:16])
	if uint64(len(raw)-header) != length {
		return nil, fmt.Errorf("%w: truncated body", ErrCorrupt)
	}
	body := raw[header:]
	if crc32.ChecksumIEEE(body) != binary.LittleEndian.Uint32(raw[16:20]) {
		return nil, fmt.Errorf("%w: checksum mismatch", ErrCorrupt)
	}

	live := make(map[string][]byte)
	for len(body) > 0 {
		key, rest, ok := takeBytes(body)
		if !ok {
			return nil, fmt.Errorf("%w: truncated key", ErrCorrupt)
		}
		value, rest2, ok := takeBytes(rest)
		if !ok {
			return nil, fmt.Errorf("%w: truncated value", ErrCorrupt)
		}
		live[string(key)] = value
		body = rest2
	}
	return live, nil
}

func appendBytes(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	return append(append(dst, lenBuf[:]...), b...)
}

func takeBytes(raw []byte) (value, rest []byte, ok bool) {
	if len(raw) < 4 {
		return nil, nil, false
	}
	n := int(binary.LittleEndian.Uint32(raw[:4]))
	if n < 0 || 4+n > len(raw) {
		return nil, nil, false
	}
	return raw[4 : 4+n], raw[4+n:], true
}

// syncDir fsyncs a directory so that a rename or truncate against a file
// inside it is durable. On platforms and filesystems where opening a
// directory for Sync is not supported at all, the error is ignored, because
// there the rename is already durable without it.
//
// Only that specific, documented case is ignored: the previous version returned
// nil for *any* Sync failure, including EIO and ENOSPC. compactLocked's
// documented sequence is write the snapshot, fsync it, rename it over the old
// one, fsync the directory, and only *then* truncate the log — and that fourth
// step existed to make the third durable before the fifth destroys the only
// other copy of the data. Swallowing a real I/O error there let the log be
// truncated on the strength of a rename that was never confirmed to have
// reached disk.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if isUnsupportedDirSync(err) {
			return nil
		}
		return err
	}
	return nil
}
