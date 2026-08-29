// Package chain persists the chain and drives the fold over it.
//
// This is the layer where a correct rule can be broken by an incorrect commit,
// so it has exactly one structural rule of its own: **everything one block
// changes lands in one storage batch.** Cells, the spent registry, the seen
// set, the undo log, the header, the body, the height index and the state root
// go together or not at all. Splitting them is the storage-schedule consensus
// split of I1-C3 reborn as a crash schedule (M1-G1).
package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/storage"
)

// Key prefixes. One byte each, chosen so a prefix scan reconstructs exactly one
// kind of thing.
const (
	prefixCell   = "c/" // slot -> value
	prefixSpent  = "s/" // address -> present
	prefixSeen   = "n/" // certificate id -> ttl
	prefixHeader = "h/" // block id -> ssz(header)
	prefixBlock  = "b/" // block id -> ssz(block)
	prefixIndex  = "i/" // height -> block id
	prefixUndo   = "u/" // block id -> encoded undo log
	prefixMeta   = "m/" // fixed metadata keys
)

// Metadata keys.
const (
	metaNetwork    = prefixMeta + "network"    // the genesis id: the network's identity
	metaHeight     = prefixMeta + "height"     // the tip height
	metaTip        = prefixMeta + "tip"        // the tip block id
	metaStateRoot  = prefixMeta + "stateroot"  // the state root after the tip
	metaWork       = prefixMeta + "work"       // accumulated work up to the tip
	metaVersion    = prefixMeta + "version"    // the on-disk layout version
	metaStats      = prefixMeta + "stats"      // the counters in node/chain/stats.go
	metaUndoPruned = prefixMeta + "undopruned" // highest height whose undo log is already deleted
)

// storeVersion is the on-disk layout version. A mismatch is a refusal to open,
// never a silent migration.
//
// **It must move whenever the meaning of stored bytes changes, not only when
// their shape does**, and the certificate-id redefinition from the pre-testnet
// adversarial sweep is the case that proves the distinction is not academic.
// That change redefined the certificate id — the key this store writes under
// prefixSeen — without altering a single field of any record. Two guards would
// normally refuse a database written under the old meaning, and this one is the
// only one that can:
//
//   - metaNetwork holds the genesis id, and the genesis id did not move,
//     because no header or block encoding changed;
//   - the state-root check cannot see it either. The seen set is deliberately
//     excluded from the root (core/state.Root), being prunable and derivable
//     from recent history, so a seen set keyed under the old rule still
//     reconciles against a correct root.
//
// So a pre-upgrade database opened cleanly, and every certificate in it with a
// live TTL became includable again on the upgraded node while a node synced
// from genesis rejected the same block. That is a chain split by upgrade path
// rather than by content — the worst shape, because both sides are internally
// consistent and neither can be shown wrong from its own data. Bounded by
// TTLMax and confined to devnet before genesis, which is why one constant is
// the whole fix.
//
// The rule to carry forward: ask not "did a record's layout change" but "would
// a byte written yesterday still mean today what it meant then". Consensus
// keys held outside the state root are exactly where those two questions come
// apart, and this constant is the only thing watching them.
const storeVersion = 2

// Errors returned by the chain store.
var (
	ErrWrongNetwork = errors.New("chain: this directory belongs to a different network")
	ErrWrongVersion = errors.New("chain: on-disk layout version mismatch")
	ErrCorruptState = errors.New("chain: stored state does not match its committed root")
	// ErrLocal marks a failure that is this node's own — a commit that did not
	// land, an undo log that is missing, storage that will not answer.
	//
	// It exists because ConsiderBranch surfaces those through the same error
	// return as a peer's invalid branch, and the gossip path scored anything it
	// did not explicitly exempt. A node with a failing disk therefore fined
	// whichever peer happened to deliver the block, and since a ban also removes
	// a peer from sync candidacy, a node with bad hardware would disconnect
	// itself from the network still willing to serve it — and its log would name
	// the peers instead of the disk.
	//
	// Every local-fault return is wrapped with this. What is left unwrapped is a
	// claim about the *block*, which is the only thing a peer can be answerable
	// for.
	ErrLocal           = errors.New("chain: local failure, not the peer's doing")
	ErrNotFound        = errors.New("chain: not found")
	ErrWrongParent     = errors.New("chain: block does not extend the tip")
	ErrUndoUnavailable = errors.New("chain: undo log for the tip is unavailable")
)

// Chain is a persisted chain plus the in-memory state the fold runs against.
//
// **Every field below is guarded by mu.** A running node touches this from at
// least four goroutines — the miner, a message loop per peer, the sync driver,
// and the RPC server — and consensus state read while another goroutine writes
// it is not merely a stale read. A miner that seals an epoch state root from a
// torn view commits to a root no fold ever produced, and because roots are only
// checked at epoch boundaries the divergence surfaces dozens of blocks later,
// somewhere else entirely.
//
// That is not hypothetical: it is what the chaos soak found, and `go test
// -race` had reported nothing because every test drove the chain from a single
// goroutine. A race detector only sees the concurrency the tests create.
type Chain struct {
	params *params.Params
	store  *storage.Store

	// mu guards state, height and tip together. They are one value in three
	// fields — a tip without the state it produced is not a consistent read of
	// anything — so they are never locked separately.
	mu     sync.RWMutex
	state  *state.State
	height uint64
	tip    types.Header

	// stats counts what this node did, guarded by mu with everything else.
	stats Stats

	// networkID is set once during Open and never written again.
	networkID types.Hash
}

// Open loads a chain from a directory, creating and folding genesis if the
// directory is empty.
//
// Two checks run before anything else touches the chain, and both are cheap
// enough to be unconditional:
//
//   - The stored network id must equal this build's genesis id. Since the
//     genesis id commits to every consensus parameter (R3-1), a node restarted
//     with an edited parameter file refuses to open rather than continuing onto
//     a chain it now disagrees with.
//   - The state root is recomputed from what was loaded and compared with the
//     one stored alongside it (M1-G3). Disk corruption or a persistence bug is
//     caught before the node mines, relays or serves a byte, rather than after
//     it has built on rotten state.
func Open(dir string, p *params.Params) (*Chain, error) {
	return OpenWith(dir, p, storage.Options{})
}

// OpenWith is Open with explicit storage options. Tests use it to inject the
// crash that proves a reorg is atomic; nothing in production passes anything
// but the zero value.
func OpenWith(dir string, p *params.Params, opts storage.Options) (*Chain, error) {
	store, err := storage.Open(dir, opts)
	if err != nil {
		return nil, err
	}

	c := &Chain{params: p, store: store, state: state.New()}

	genesisBlock, _, err := genesis.Build(p)
	if err != nil {
		store.Close()
		return nil, err
	}
	c.networkID = genesisBlock.Header.ID()

	if raw, ok := store.Get([]byte(metaVersion)); ok {
		if len(raw) != 8 || binary.LittleEndian.Uint64(raw) != storeVersion {
			store.Close()
			return nil, ErrWrongVersion
		}
	}
	if raw, ok := store.Get([]byte(metaNetwork)); ok {
		var stored types.Hash
		copy(stored[:], raw)
		if stored != c.networkID {
			store.Close()
			return nil, fmt.Errorf("%w: stored %x, this build %x",
				ErrWrongNetwork, stored[:8], c.networkID[:8])
		}
		if err := c.load(); err != nil {
			store.Close()
			return nil, err
		}
		return c, nil
	}

	// A fresh directory. Fold genesis and commit it like any other block, so
	// there is exactly one commit path.
	if err := c.initGenesis(genesisBlock); err != nil {
		store.Close()
		return nil, err
	}
	return c, nil
}

// Close releases the chain.
func (c *Chain) Close() error {
	c.assertNotInRead("Close")
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Close()
}

// Params returns the parameter set this chain runs.
func (c *Chain) Params() *params.Params { return c.params }

// NetworkID is the genesis id: the identity two nodes must share to be on the
// same network.
func (c *Chain) NetworkID() types.Hash { return c.networkID }

// Height returns the tip height.
func (c *Chain) Height() uint64 {
	c.assertNotInRead("Height")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.height
}

// Tip returns the tip header.
func (c *Chain) Tip() types.Header {
	c.assertNotInRead("Tip")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tip
}

// Read runs fn under the chain's read lock, lending it a borrowed View.
//
// This is the only way to read live consensus state, and it is a callback
// rather than an accessor for one reason: an accessor returning `*state.State`
// would hand the caller a live pointer into memory another goroutine is about
// to write, and no amount of documentation makes that safe. A callback makes
// the safe window syntactically visible.
//
// Two rules apply, and since R5-G2 both are **machine-checked in a guarded
// build** rather than left to review (see stateref.go and guard_on.go):
//
//  1. The View's State is borrowed and stops being valid when fn returns. Using
//     it afterwards panics at the point of use.
//  2. fn must not call back into the chain. The lock is not reentrant, and
//     a nested read succeeds quietly until a writer queues up behind it — so
//     this is detected before the lock is taken rather than left to deadlock on
//     the one day it is under load.
//
// A caller that needs state outliving the call wants Snapshot, which is a
// different type precisely so the two cannot be confused.
func (c *Chain) Read(fn func(View)) {
	c.assertNotInRead("Read")
	c.mu.RLock()
	live := new(atomic.Bool)
	live.Store(true)
	c.enterRead()
	defer func() {
		c.exitRead()
		live.Store(false)
		c.mu.RUnlock()
	}()
	fn(View{
		Tip:    c.tip,
		Height: c.height,
		State:  StateRef{s: c.state, live: live},
	})
}

// Snapshot returns an owned copy of the chain's state together with the tip it
// belongs to.
//
// Safe to hold for as long as the caller likes — a miner assembling a block, a
// mempool re-screening its residents — at the cost of copying the state. That
// cost is why this is a separate call rather than the default: a caller that
// only reads a cell should use Read and pay nothing.
func (c *Chain) Snapshot() Snapshot {
	c.assertNotInRead("Snapshot")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Snapshot{Tip: c.tip, Height: c.height, State: c.state.Clone()}
}

// StateRoot returns the root of the in-memory state.
func (c *Chain) StateRoot() types.Hash {
	c.assertNotInRead("StateRoot")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state.Root()
}

func (c *Chain) initGenesis(b *types.Block) error {
	res, err := fold.ApplyBlock(c.state, b, c.params)
	if err != nil {
		return err
	}
	return c.commit(b, res)
}

// load rebuilds the in-memory state from storage and verifies it.
func (c *Chain) load() error {
	if err := c.store.ScanPrefix([]byte(prefixCell), func(key, value []byte) error {
		slot, err := decodeSlotKey(key)
		if err != nil {
			return err
		}
		var v [32]byte
		if len(value) != 32 {
			return fmt.Errorf("%w: cell value is %d bytes", ErrCorruptState, len(value))
		}
		copy(v[:], value)
		c.state.Set(slot, u256.FromBytes(v))
		return nil
	}); err != nil {
		return err
	}
	if err := c.store.ScanPrefix([]byte(prefixSpent), func(key, _ []byte) error {
		addr, err := decodeAddrKey(key)
		if err != nil {
			return err
		}
		c.state.MarkSpent(addr)
		return nil
	}); err != nil {
		return err
	}
	if err := c.store.ScanPrefix([]byte(prefixSeen), func(key, value []byte) error {
		id, err := decodeHashKey(key, prefixSeen)
		if err != nil {
			return err
		}
		if len(value) != 8 {
			return fmt.Errorf("%w: seen ttl is %d bytes", ErrCorruptState, len(value))
		}
		c.state.MarkSeen(id, binary.LittleEndian.Uint64(value))
		return nil
	}); err != nil {
		return err
	}

	raw, ok := c.store.Get([]byte(metaHeight))
	if !ok || len(raw) != 8 {
		return fmt.Errorf("%w: no height", ErrCorruptState)
	}
	c.height = binary.LittleEndian.Uint64(raw)

	tipRaw, ok := c.store.Get([]byte(metaTip))
	if !ok {
		return fmt.Errorf("%w: no tip", ErrCorruptState)
	}
	var tipID types.Hash
	copy(tipID[:], tipRaw)
	hdr, err := c.headerLocked(tipID)
	if err != nil {
		return err
	}
	c.tip = *hdr

	// M1-G3: the integrity check. One tree rebuild, before anything is served.
	if raw, ok := c.store.Get([]byte(metaStats)); ok {
		c.stats = decodeStats(raw)
	}

	storedRoot, ok := c.store.Get([]byte(metaStateRoot))
	if !ok || len(storedRoot) != 32 {
		return fmt.Errorf("%w: no state root", ErrCorruptState)
	}
	var want types.Hash
	copy(want[:], storedRoot)
	if got := c.state.Root(); got != want {
		return fmt.Errorf("%w: rebuilt %x, committed %x", ErrCorruptState, got[:8], want[:8])
	}
	// On an epoch boundary the header carries a consensus-verified root, so the
	// stored value can be cross-checked against something an attacker could not
	// have chosen.
	if c.params.IsEpochBoundary(c.height) && c.tip.StateRoot != want {
		return fmt.Errorf("%w: the tip header commits to %x, storage holds %x",
			ErrCorruptState, c.tip.StateRoot[:8], want[:8])
	}
	return nil
}

// Apply folds a block onto the tip and commits it in one batch.
func (c *Chain) Apply(b *types.Block) (*fold.Result, error) {
	c.assertNotInRead("Apply")
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyLocked(b)
}

// applyLocked is Apply with the write lock already held.
//
// The parent check happens **inside** the lock, which is what makes optimistic
// block assembly correct: a miner builds against a snapshot without holding
// anything, and if the tip moved while it was hashing, this rejects the block
// rather than folding it onto a chain it does not extend.
func (c *Chain) applyLocked(b *types.Block) (*fold.Result, error) {
	if b.Header.Height != c.height+1 || b.Header.ParentID != c.tip.ID() {
		return nil, fmt.Errorf("%w: block %d parent %x, tip %d id %x",
			ErrWrongParent, b.Header.Height, b.Header.ParentID[:8], c.height, c.tip.ID())
	}
	res, err := fold.ApplyBlock(c.state, b, c.params)
	if err != nil {
		c.recordRejection()
		return nil, err
	}
	if err := c.commit(b, res); err != nil {
		// The fold already mutated memory; undo it so that memory and disk do
		// not disagree. The caller sees a failed apply either way.
		fold.UndoBlock(c.state, res.Undo)
		// Marked as local: the block was valid enough to fold, and what failed
		// was this node's storage. Charging that to whoever sent the block is
		// how a node with a bad disk bans the network.
		return nil, fmt.Errorf("%w: %w", ErrLocal, err)
	}
	// commit persisted the updated counters; memory follows only now, so the two
	// agree whether or not the commit landed.
	c.stats = c.stats.withBlock(res)
	return res, nil
}

// touched is the union of state keys a transition changed. Collecting it lets a
// multi-block reorg produce one batch rather than one per block (R4-M1).
type touched struct {
	cells map[types.Slot]struct{}
	spent map[types.Address]struct{}
	seen  map[types.Hash]struct{}
}

func newTouched() *touched {
	return &touched{
		cells: map[types.Slot]struct{}{},
		spent: map[types.Address]struct{}{},
		seen:  map[types.Hash]struct{}{},
	}
}

// record folds an undo log into the touched set. Direction does not matter: the
// batch is written from the *final* state, so all that is needed is which keys
// to look at.
func (t *touched) record(log *state.UndoLog) {
	for _, c := range log.Cells {
		t.cells[c.Slot] = struct{}{}
	}
	for _, a := range log.SpentAdded {
		t.spent[a] = struct{}{}
	}
	for _, id := range log.SeenAdded {
		t.seen[id] = struct{}{}
	}
	for _, e := range log.SeenRemoved {
		t.seen[e.ID] = struct{}{}
	}
}

// recordWriter is the subset of *storage.Batch that writeState and writeHead
// need. It exists so a reorg large enough to need more than one storage
// record (batchGroup, forkchoice.go) can stage into the same helpers an
// ordinary single-block commit uses, rather than duplicating them: both a
// *storage.Batch and a *batchGroup satisfy it.
type recordWriter interface {
	Put(key, value []byte)
	Delete(key []byte)
}

// writeState stages every touched key at its current value.
func (c *Chain) writeState(batch recordWriter, t *touched) {
	for slot := range t.cells {
		key := cellKey(slot)
		v := c.state.Get(slot)
		if v.IsZero() {
			batch.Delete(key)
			continue
		}
		val := v.Bytes()
		batch.Put(key, val[:])
	}
	for addr := range t.spent {
		if c.state.IsSpent(addr) {
			batch.Put(addrKey(addr), []byte{1})
			continue
		}
		batch.Delete(addrKey(addr))
	}
	for id := range t.seen {
		if ttl, ok := c.state.Seen(id); ok {
			batch.Put(hashKey(prefixSeen, id), le64(ttl))
			continue
		}
		batch.Delete(hashKey(prefixSeen, id))
	}
}

// writeHead stages the metadata that names the tip.
//
// This is the atomic point of the whole design: until these keys land, the node
// is on the old chain; once they land, it is on the new one. There is no
// in-between state to crash into (M1-G1, R4-M1).
func (c *Chain) writeHead(batch recordWriter, tip types.Header, work u256.U256, stats Stats) {
	id := tip.ID()
	root := c.state.Root()
	w := work.Bytes()
	batch.Put([]byte(metaNetwork), c.networkID[:])
	batch.Put([]byte(metaVersion), le64(storeVersion))
	batch.Put([]byte(metaHeight), le64(tip.Height))
	batch.Put([]byte(metaTip), id[:])
	batch.Put([]byte(metaStateRoot), root[:])
	batch.Put([]byte(metaWork), w[:])
	// The counters ride the same batch as everything else.
	//
	// They were in memory only, which meant every restart reset them to zero —
	// and the checks built on them (the soak's history horizon validated against
	// the deepest observed reorg, its assertion that no block was refused by the
	// fold) are asserted in runs where nodes are killed constantly. A metric
	// that resets on the event it is meant to survive is measuring the time
	// since the last crash, not the thing it names.
	batch.Put([]byte(metaStats), stats.encode())
}

// commit writes everything one block changed, atomically (M1-G1).
//
// Only the touched slots are written, and the undo log already names them —
// which is the same property that makes reorgs cheap, reused here to make
// commits small.
func (c *Chain) commit(b *types.Block, res *fold.Result) error {
	batch := &storage.Batch{}
	id := b.Header.ID()

	t := newTouched()
	t.record(res.Undo)
	c.writeState(batch, t)

	batch.Put(hashKey(prefixHeader, id), b.Header.MarshalSSZ())
	batch.Put(hashKey(prefixBlock, id), b.MarshalSSZ())
	batch.Put(heightKey(b.Header.Height), id[:])
	batch.Put(hashKey(prefixUndo, id), encodeUndo(res.Undo))

	// A single-block commit's own new height is never within the pruning
	// range (it always equals newHeight, and the range stops strictly below
	// newHeight - UndoDepth < newHeight), so there is no pending id for
	// pruneUndoLocked to need here — unlike switchTo, which can apply many
	// heights in one batch.
	c.pruneUndoLocked(batch, b.Header.Height, nil)

	c.writeHead(batch, b.Header, c.totalWorkLocked().SatAdd(BlockWork(b.Header.Target)),
		c.stats.withBlock(res))

	if err := c.store.Commit(batch); err != nil {
		return err
	}
	c.height = b.Header.Height
	c.tip = b.Header
	return nil
}

// undoPrunedThroughLocked reports the highest height whose undo log this node
// has already deleted (inclusive), and whether any pruning has been recorded at
// all.
//
// One reader, because two callers have to agree on what "already pruned" means
// and disagreeing is silent: pruneUndoLocked advances the bookmark, and
// switchTo's unwind reads it to tell an undo log this node deleted on purpose
// from one the disk lost. Two open-coded decodes of the same key are two
// chances for that agreement to drift.
func (c *Chain) undoPrunedThroughLocked() (uint64, bool) {
	raw, ok := c.store.Get([]byte(metaUndoPruned))
	if !ok || len(raw) != 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(raw), true
}

// pruneUndoLocked stages deletions for undo logs that have fallen behind
// UNDO_DEPTH now that the tip is moving to newHeight, and folds them into the
// same batch as the transition that makes the deletion safe.
//
// docs/ARCHITECTURE.md §14 is normative here: "undo beyond UNDO_DEPTH" is
// pruned, full stop, and considerBranchLocked already refuses any reorg whose
// depth exceeds UNDO_DEPTH (forkchoice.go) — so an undo log more than
// UNDO_DEPTH blocks behind the tip is not merely unlikely to be needed, it is
// unreachable by any reorg this node will ever accept. Deleting it costs
// nothing this process could still use.
//
// One block of slack, on purpose. The two boundaries otherwise meet
// with exactly zero margin: considerBranchLocked admits depth == UNDO_DEPTH,
// whose unwind needs the log at newHeight - UNDO_DEPTH + 1, and pruning
// through newHeight - UNDO_DEPTH stops one height below that. Provably tight,
// and therefore correct — which is why this is slack rather than a fix. So the
// horizon below is newHeight - UNDO_DEPTH - 1, and the retained set is
// UNDO_DEPTH+1 logs rather than UNDO_DEPTH.
//
// The precedent is F10 in core/fold/fold.go, which makes the same trade for
// the same class of decision and says why in the words this borrows: a seen
// entry is already unincludable at the current height, and it still prunes at
// height-1 because "one block of slack costs nothing and keeps the boundary
// obvious". It costs one undo log here too. What it buys: a tight bound and a
// bound that is wrong by one are no longer separated by zero, so an edit to
// either constant has somewhere test-visible to land before a reorg is the
// thing that finds it — and the band of heights a *retreated* horizon leaves
// admissible-but-pruned (the deliberately-open edge described below, which the
// documented tip-drop case operates right at) is one height narrower.
//
// Inline, not a background sweep. The alternative — a periodic goroutine that
// walks old heights and deletes their undo logs on its own schedule — would be
// a second, independent path that can run, crash, or race relative to a
// commit, which is exactly the class of bug storage.Store's sticky-failure and
// sequence-number machinery — the answer to a discarded log write and to an
// interior corruption read as a torn tail — exists to not have to reason about a
// second time. Folding the delete into the *same* batch that advances the tip
// means storage.Store's existing guarantee — the whole record lands or none of
// it does — already covers pruning for free: there is no state where the tip
// moved but the stale undo log did not get deleted, or vice versa, whether the
// process dies before the fsync (nothing landed, prune included) or after
// (everything landed, prune included). A background sweep would need its own
// answer to "what if the process dies mid-sweep", and the honest answer is
// that answer is this function, called once more per commit instead of on a
// timer.
//
// metaUndoPruned tracks the highest height already pruned (inclusive) so a
// long-lived chain does not rescan its own history on every block — each call
// only walks the (almost always single-height) span that newly crossed the
// horizon since the last commit.
//
// One edge case is deliberately left open rather than defended against: a
// reorg can *lower* the tip height (a shorter, harder-working branch beating a
// longer, softer one — TestMoreWorkWinsOverMoreBlocks exercises exactly this),
// and considerBranchLocked's depth check is relative to whatever the tip is
// *at the time of that reorg*. If the tip has ever been higher than it is now,
// a later reorg can legitimately ask (by that check) for an undo log at a
// height this function already pruned while the tip was higher. That reorg
// then fails loudly with ErrPrunedUndoHorizon, wrapped in ErrLocal — a refusal,
// not silent corruption or a wrong answer, carrying the same "resync required"
// instruction the codebase already gives for any reorg past UNDO_DEPTH.
//
// It reported ErrUndoUnavailable until this split, which is the error for a
// *damaged* store. That conflated the two ways an undo log goes missing under
// one name: the disk lost it, or this function deleted it on purpose. The
// operator was pointed at a healthy disk while the actual remedy went unnamed,
// and unlike a damaged store this state does not clear itself — see
// ErrPrunedUndoHorizon. The refusal was right; only the diagnosis attached to
// it was wrong. That is a claim about switchTo, not a hope: its unwind loop
// puts every block it already rolled back in memory back on before reporting
// the gap (see Chain.unwound), so the refusal leaves the tip and the state
// exactly where it found them.
// TestARefusedDeepReorgLeavesTheStateWhereItFoundIt drives this whole path —
// the tip drops, the horizon retreats, the deep reorg is refused — and pins it.
// How wide that gap gets is measured, not assumed, in dropUndoParams's comment
// in prune_test.go: the largest legal tip drop approaches UNDO_DEPTH itself
// (112 blocks at devnet's undo_depth of 128), because the branch needed to
// out-work a fork grows only logarithmically as the fork depth doubles. So this
// is not a vanishingly narrow edge that shrinks with real parameters — it
// scales up with UNDO_DEPTH, and after a large drop a whole band of heights the
// depth check still admits has already been pruned. What keeps it acceptable is
// the *consequence*, not the odds: every one of those reorgs is refused loudly
// and safely, leaving tip and state exactly where they were, which is the same
// "resync required" outcome the codebase already accepts for any reorg past
// UNDO_DEPTH — and it is now reported as that outcome rather than as a disk
// fault, which is what makes "the operator can act on it" true rather than
// merely intended. Closing it properly means retaining meaningfully more than
// UNDO_DEPTH — which is what ARCHITECTURE.md §14 says to prune — so it is left
// open deliberately, with the cost stated.
//
// pending resolves height -> id for blocks *this same batch* is about to
// write, and must be consulted ahead of c.store.Get. A reorg's incoming
// branch can be longer than UNDO_DEPTH — node/sync deliberately allows this
// on its resync path (extendToCover sizes maxHeaders as depth + UndoDepth) —
// so the horizon can land inside the range of heights switchTo is applying in
// this very transition. c.store.Get(heightKey(h)) only ever sees durable,
// pre-batch state, so for such a height it returns whatever id was canonical
// there *before* the reorg — which, whenever at least one block was also
// rolled back, is a real but stale id (harmlessly re-deleting an entry the
// undone-blocks loop already deletes), not the new chain's id at that height.
// The new id's own undo log — written unconditionally by the loop that fills
// br.Blocks into this batch — would then never be targeted for deletion at
// all, and because metaUndoPruned advances past that height regardless,
// no later commit ever reconsiders it: a single entry retained forever,
// silently defeating the pruning this function exists to do. pending closes
// that gap by giving the *correct* id for a height this batch is populating,
// so the delete lands on the entry that will actually still be live once the
// batch commits.
func (c *Chain) pruneUndoLocked(batch recordWriter, newHeight uint64, pending map[uint64]types.Hash) {
	if newHeight <= c.params.UndoDepth {
		return
	}
	// The -1 is the block of slack (see the doc comment). The guard above
	// leaves newHeight - UndoDepth >= 1, so this cannot underflow.
	horizon := newHeight - c.params.UndoDepth - 1

	start := uint64(0)
	if through, ok := c.undoPrunedThroughLocked(); ok {
		start = through + 1
	}
	if start > horizon {
		// The horizon retreated (tip height dropped) or did not move past
		// what is already pruned. Never step backwards: metaUndoPruned only
		// advances, and there is nothing new to delete this commit.
		return
	}

	// lastPruned tracks how far this loop actually got, which is not always
	// horizon: a height whose index entry is not yet visible (below) ends the
	// loop early, and metaUndoPruned must record only genuine progress.
	var lastPruned uint64
	made := false
	for h := start; h <= horizon; h++ {
		var id types.Hash
		if pid, ok := pending[h]; ok {
			id = pid
		} else {
			raw, ok := c.store.Get(heightKey(h))
			if !ok {
				// Nothing committed at this height yet, and nothing pending
				// for it either — can only happen for a height a *forward*
				// extension (no blocks undone) just advanced past in one
				// jump, since switchTo's pending map above covers every
				// height a reorg with undone blocks touches. Stop here; the
				// gap is picked up on a later commit.
				break
			}
			copy(id[:], raw)
		}
		batch.Delete(hashKey(prefixUndo, id))
		lastPruned = h
		made = true
	}
	if !made {
		return
	}
	batch.Put([]byte(metaUndoPruned), le64(lastPruned))
}

// Rollback undoes the tip block, restoring state and storage together.
func (c *Chain) Rollback() error {
	c.assertNotInRead("Rollback")
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rollbackLocked()
}

func (c *Chain) rollbackLocked() error {
	if c.height == 0 {
		return errors.New("chain: cannot roll back genesis")
	}
	id := c.tip.ID()
	raw, ok := c.store.Get(hashKey(prefixUndo, id))
	if !ok {
		return ErrUndoUnavailable
	}
	undo, err := decodeUndo(raw)
	if err != nil {
		return err
	}

	parent, err := c.headerLocked(c.tip.ParentID)
	if err != nil {
		return err
	}

	fold.UndoBlock(c.state, undo)

	batch := &storage.Batch{}
	for _, cell := range undo.Cells {
		key := cellKey(cell.Slot)
		v := c.state.Get(cell.Slot)
		if v.IsZero() {
			batch.Delete(key)
			continue
		}
		val := v.Bytes()
		batch.Put(key, val[:])
	}
	for _, addr := range undo.SpentAdded {
		batch.Delete(addrKey(addr))
	}
	for _, seen := range undo.SeenAdded {
		batch.Delete(hashKey(prefixSeen, seen))
	}
	for _, restored := range undo.SeenRemoved {
		batch.Put(hashKey(prefixSeen, restored.ID), le64(restored.TTL))
	}
	batch.Delete(hashKey(prefixUndo, id))
	batch.Delete(hashKey(prefixBlock, id))
	batch.Delete(heightKey(c.height))
	// The header stays, on the same terms as a reorg's loser: both functions
	// take a block off this chain for the same reason, and an id that survives
	// one and not the other is a rule nobody can state. Rollback has only test
	// callers today, so aligning costs nothing and not aligning means
	// inheriting the inconsistency on the day it gets a real one.

	root := c.state.Root()
	work := c.totalWorkLocked().SatSub(BlockWork(c.tip.Target)).Bytes()
	batch.Put([]byte(metaHeight), le64(parent.Height))
	batch.Put([]byte(metaTip), c.tip.ParentID[:])
	batch.Put([]byte(metaStateRoot), root[:])
	batch.Put([]byte(metaWork), work[:])

	if err := c.store.Commit(batch); err != nil {
		// Memory moved and disk did not; put memory back.
		if _, redoErr := fold.ApplyBlock(c.state, mustBlock(c, id), c.params); redoErr != nil {
			return fmt.Errorf("chain: rollback failed and could not be undone: %w", err)
		}
		return err
	}
	c.height = parent.Height
	c.tip = *parent
	return nil
}

func mustBlock(c *Chain, id types.Hash) *types.Block {
	b, err := c.blockLocked(id)
	if err != nil {
		return &types.Block{}
	}
	return b
}

// Header returns a stored header.
func (c *Chain) Header(id types.Hash) (*types.Header, error) {
	c.assertNotInRead("Header")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headerLocked(id)
}

func (c *Chain) headerLocked(id types.Hash) (*types.Header, error) {
	raw, ok := c.store.Get(hashKey(prefixHeader, id))
	if !ok {
		return nil, fmt.Errorf("%w: header %x", ErrNotFound, id[:8])
	}
	hdr, err := types.UnmarshalHeader(raw)
	if err != nil {
		// Bytes this node wrote itself no longer decode: that is this disk's
		// problem, not the sender's, and it must say so. Unmarshalling a
		// *peer's* header happens on the wire path, far from here; everything
		// reaching this function was already committed locally. Returning the
		// bare SSZ error let node/p2p's fall-through charge a corrupt local
		// header to whoever happened to deliver a branch that read it —
		// -20 apiece, banned at -100, so five honest peers — which is exactly
		// the self-isolation the ErrLocal check in OnBranch exists to prevent
		// on this path.
		return nil, fmt.Errorf("%w: header %x: %w", ErrLocal, id[:8], err)
	}
	return hdr, nil
}

// Block returns a stored block with its bodies.
func (c *Chain) Block(id types.Hash) (*types.Block, error) {
	c.assertNotInRead("Block")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blockLocked(id)
}

func (c *Chain) blockLocked(id types.Hash) (*types.Block, error) {
	raw, err := c.blockRawLocked(id)
	if err != nil {
		return nil, err
	}
	return c.decodeBlock(id, raw)
}

// decodeBlock turns a stored record into a block, attributing a failure the
// way headerLocked does: a body this node committed and can no longer decode
// is a local fault, and must not be scored against the peer that prompted the
// read. Every caller that decodes a *stored* record goes through here, so the
// attribution does not depend on which entry point was used.
func (c *Chain) decodeBlock(id types.Hash, raw []byte) (*types.Block, error) {
	blk, err := types.UnmarshalBlock(raw, c.params)
	if err != nil {
		return nil, fmt.Errorf("%w: block %x: %w", ErrLocal, id[:8], err)
	}
	return blk, nil
}

// BlockRaw returns a block's stored SSZ encoding without decoding it — the
// same bytes types.UnmarshalBlock would be handed, and the same bytes
// b.MarshalSSZ() produced when the block was committed (commit and switchTo
// both write exactly this under this key).
//
// A caller that needs to price a request by the record's length before
// paying for the decode reads this first: the store already knows the
// length once Get returns, and nothing here parses a single field.
func (c *Chain) BlockRaw(id types.Hash) ([]byte, error) {
	c.assertNotInRead("BlockRaw")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blockRawLocked(id)
}

// BlockRawAt resolves a height and reads that block's stored SSZ encoding
// under a single lock, returning the id it resolved to alongside the bytes.
//
// The atomicity is the point. Resolving the height and reading the body as
// two separate acquisitions lets a reorg land in between: the height index
// entry a caller just read is deleted and rewritten to the winning block, and
// the body it then asks for by the *old* id is gone — so a height that is
// still occupied answers "not found". Every batch that moves a block writes
// heightKey and the body record together (commit, switchTo, rollbackLocked),
// which makes them consistent to any reader that looks at both at once, and
// only to such a reader.
//
// The bytes come back undecoded for the same reason BlockRaw's do: a caller
// pricing a request against a byte budget has to know the record's length
// before it pays for the decode.
func (c *Chain) BlockRawAt(height uint64) (types.Hash, []byte, error) {
	c.assertNotInRead("BlockRawAt")
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, ok := c.canonicalIDAtLocked(height)
	if !ok {
		return types.Hash{}, nil, fmt.Errorf("%w: height %d", ErrNotFound, height)
	}
	raw, err := c.blockRawLocked(id)
	if err != nil {
		return types.Hash{}, nil, err
	}
	return id, raw, nil
}

// DecodeBlock decodes bytes this node stored under id, attributing a failure
// as a local fault exactly as Block does.
//
// A caller that had to read the raw record first — to price it against a
// budget before paying for the decode (node/rpc's block route) — would
// otherwise have to call types.UnmarshalBlock itself and lose that
// attribution, reporting this node's own bad disk as the caller's bad
// request. The rule that a record this node cannot decode is this node's
// fault belongs to the store that wrote it, not to each caller that reads it.
//
// It takes no lock and reads no store: c.params is fixed at construction (see
// Params, which likewise does not lock), and the bytes are the caller's. That
// is what makes it safe to call with a record read a moment ago rather than
// under the same lock that read it — the decode's result does not depend on
// anything the chain can move underneath it.
func (c *Chain) DecodeBlock(id types.Hash, raw []byte) (*types.Block, error) {
	return c.decodeBlock(id, raw)
}

func (c *Chain) blockRawLocked(id types.Hash) ([]byte, error) {
	raw, ok := c.store.Get(hashKey(prefixBlock, id))
	if !ok {
		return nil, fmt.Errorf("%w: block %x", ErrNotFound, id[:8])
	}
	return raw, nil
}

// HasBlockBody reports whether a block's body is still retained, without
// copying it (unlike BlockRaw/Block, which do). A block that lost a reorg
// keeps its header and loses its body (see switchTo and rollbackLocked), so
// this is how a caller distinguishes "known, body gone" from "unknown id"
// without paying a copy proportional to block size just to find out the body
// is not there — or, worse, paying it and then discarding the answer because
// the caller only wanted to know whether to charge for one.
func (c *Chain) HasBlockBody(id types.Hash) bool {
	c.assertNotInRead("HasBlockBody")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store.Has(hashKey(prefixBlock, id))
}

// BlockAt returns the block committed at a height.
func (c *Chain) BlockAt(height uint64) (*types.Block, error) {
	c.assertNotInRead("BlockAt")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blockAtLocked(height)
}

func (c *Chain) blockAtLocked(height uint64) (*types.Block, error) {
	raw, ok := c.store.Get(heightKey(height))
	if !ok {
		return nil, fmt.Errorf("%w: height %d", ErrNotFound, height)
	}
	var id types.Hash
	copy(id[:], raw)
	return c.blockLocked(id)
}

// CanonicalHeader returns a header only if it is on the canonical chain.
//
// Header answers for anything the store holds, and since a reorg's loser keeps
// its header that now includes blocks this node is not built on. Every caller
// that means "does this attach to me?" wants this function instead.
//
// The distinction is new only in that it became visible. Before headers were
// retained, a reorg deleted the loser's, so "the store knows this header" and
// "this header is on my chain" were the same test — and callers were written
// against the second while asking the first. depthOf already knew the
// difference and checked it by hand; nothing else did.
func (c *Chain) CanonicalHeader(id types.Hash) (*types.Header, error) {
	c.assertNotInRead("CanonicalHeader")
	c.mu.RLock()
	defer c.mu.RUnlock()
	hdr, err := c.headerLocked(id)
	if err != nil {
		return nil, err
	}
	if got, ok := c.canonicalIDAtLocked(hdr.Height); !ok || got != id {
		return nil, fmt.Errorf("%w: %x is known but not on this chain", ErrNotFound, id[:8])
	}
	return hdr, nil
}

// TipAndCanonicalIDAt returns the tip and the id committed at a height, read
// under one lock.
//
// Two calls would be cheaper and wrong. A caller that reads the height index
// and then the tip can have a reorg land between them, and then it is holding
// an answer derived from the old chain labelled with the new tip — which for
// anything that caches by tip means publishing a stale answer under a fresh
// name. That is how a block that had left the chain went on being served as
// canonical from a cache, so the atomicity is the point rather than a tidiness.
func (c *Chain) TipAndCanonicalIDAt(height uint64) (types.Header, types.Hash, bool) {
	c.assertNotInRead("TipAndCanonicalIDAt")
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, ok := c.canonicalIDAtLocked(height)
	return c.tip, id, ok
}

// CanonicalIDAt returns the block id committed at a height, and whether the
// height is committed at all.
//
// It is how a caller tells a block that is on the chain from one that was
// reorged off it. Presence in the store is not the test: a block that lost a
// reorg keeps its header, so `Header(id)` answers for both, and only the
// height index knows which of two blocks at the same height won.
func (c *Chain) CanonicalIDAt(height uint64) (types.Hash, bool) {
	c.assertNotInRead("CanonicalIDAt")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.canonicalIDAtLocked(height)
}

func (c *Chain) canonicalIDAtLocked(height uint64) (types.Hash, bool) {
	var id types.Hash
	raw, ok := c.store.Get(heightKey(height))
	if !ok {
		return id, false
	}
	copy(id[:], raw)
	return id, true
}

// RecentHeaders returns up to n headers ending at the tip, oldest first. The
// difficulty rule and the median-time rule both need a window.
func (c *Chain) RecentHeaders(n int) []types.Header {
	c.assertNotInRead("RecentHeaders")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headersEndingAtHeightLocked(c.height, n)
}

// HeadersEndingAt returns up to n canonical headers ending at height, oldest
// first, read under ONE acquisition of the chain lock.
//
// The single acquisition is the whole point and it is correctness rather than
// speed. node/sync built this window by calling BlockAt once per header —
// ninety-two separate lock acquisitions for a mainnet difficulty window — so a
// reorg landing between two of them produced a window mixing headers from two
// branches. pow.NextTarget then computed a target from that mixture, the
// honest peer's header did not match it, and the peer was SCORED DOWN for
// this node's own race. The failure is silent, blames the wrong party, and
// (I5-M5) a ban also removes a peer from sync candidacy, so it costs liveness
// rather than just reputation.
//
// It reads headers, never bodies, for the reason the locked form below gives:
// a difficulty window is a computation over headers and has never needed a
// block. That it is also much cheaper than decoding ninety-two bodies is a
// side effect, not the argument.
func (c *Chain) HeadersEndingAt(height uint64, n int) []types.Header {
	c.assertNotInRead("HeadersEndingAt")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headersEndingAtHeightLocked(height, n)
}

// headersEndingAtHeightLocked returns up to n canonical headers ending at
// height, oldest first — the shape pow.NextTarget and pow.CheckMedianTime
// both read.
//
// It underlies RecentHeaders (which always ends at the tip) and fork choice's
// branch validation (forkchoice.go), which needs the same window ending at a
// branch's ancestor instead — anywhere from the tip down to UndoDepth blocks
// below it. Every header it touches comes from headerLocked, never blockLocked:
// the window is a difficulty computation, not a state read, and has never
// needed a block body.
func (c *Chain) headersEndingAtHeightLocked(height uint64, n int) []types.Header {
	if n <= 0 {
		return nil
	}
	start := uint64(0)
	if height >= uint64(n) {
		start = height - uint64(n) + 1
	}
	out := make([]types.Header, 0, height-start+1)
	for h := start; h <= height; h++ {
		id, ok := c.canonicalIDAtLocked(h)
		if !ok {
			continue
		}
		hdr, err := c.headerLocked(id)
		if err != nil {
			continue
		}
		out = append(out, *hdr)
	}
	return out
}

// CanonicalHeadersFrom returns up to count canonical headers starting at
// height from, oldest first, read under ONE acquisition of the chain lock and
// without ever touching a block body.
//
// It is the ascending counterpart of HeadersEndingAt, and it exists for the
// same two reasons that one does. The lock is taken once so the window cannot
// mix two branches across a reorg landing mid-walk. The headers come from
// canonicalHeaderAtLocked rather than from blockAtLocked because a header
// range is a question about headers: serving one by decoding a block body per
// height cost O(sum of body bytes) to produce O(types.HeaderSize x count) of
// answer, which is what made node/p2p's get-headers responder an amplifier a
// remote peer could drive for 12 bytes a shot.
//
// The walk stops at the tip and stops at the first height it cannot read,
// returning what it has rather than an error: a request that runs past the
// end of this chain is answered with a short list, which is how a syncing
// peer learns where this node ends.
func (c *Chain) CanonicalHeadersFrom(from uint64, count int) []types.Header {
	c.assertNotInRead("CanonicalHeadersFrom")
	c.mu.RLock()
	defer c.mu.RUnlock()
	if count <= 0 || from > c.height {
		return nil
	}
	// Size the buffer to the range that actually exists, not to the count asked
	// for. count arrives clamped to p2p.MaxHeadersPerResponse, so trusting it
	// would still be bounded - but it would let a peer 12 bytes from a freshly
	// started node reserve that many headers of buffer per frame off a
	// three-block chain, which is the same shape of asymmetry the get-headers
	// amplifier is about, just smaller. The available height range is known
	// here for free.
	if avail := c.height - from + 1; avail < uint64(count) {
		count = int(avail)
	}
	out := make([]types.Header, 0, count)
	for h := from; h <= c.height && len(out) < count; h++ {
		hdr, err := c.canonicalHeaderAtLocked(h)
		if err != nil {
			break
		}
		out = append(out, *hdr)
	}
	return out
}

// canonicalHeaderAtLocked returns the header committed at a height, without
// ever decoding the block body stored alongside it.
func (c *Chain) canonicalHeaderAtLocked(height uint64) (*types.Header, error) {
	id, ok := c.canonicalIDAtLocked(height)
	if !ok {
		return nil, fmt.Errorf("%w: height %d", ErrNotFound, height)
	}
	return c.headerLocked(id)
}

// StoredStateRoot returns the root committed alongside the tip.
func (c *Chain) StoredStateRoot() types.Hash {
	c.assertNotInRead("StoredStateRoot")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.storedStateRootLocked()
}

func (c *Chain) storedStateRootLocked() types.Hash {
	var root types.Hash
	if raw, ok := c.store.Get([]byte(metaStateRoot)); ok {
		copy(root[:], raw)
	}
	return root
}

// ---------------------------------------------------------------------------
// Key and value encodings
// ---------------------------------------------------------------------------

func cellKey(s types.Slot) []byte {
	out := make([]byte, 0, len(prefixCell)+64)
	out = append(out, prefixCell...)
	out = append(out, s.Addr[:]...)
	return append(out, s.Word[:]...)
}

func decodeSlotKey(key []byte) (types.Slot, error) {
	var s types.Slot
	body := key[len(prefixCell):]
	if len(body) != 64 {
		return s, fmt.Errorf("%w: cell key is %d bytes", ErrCorruptState, len(body))
	}
	copy(s.Addr[:], body[:32])
	copy(s.Word[:], body[32:])
	return s, nil
}

func addrKey(a types.Address) []byte {
	out := make([]byte, 0, len(prefixSpent)+32)
	out = append(out, prefixSpent...)
	return append(out, a[:]...)
}

func decodeAddrKey(key []byte) (types.Address, error) {
	var a types.Address
	body := key[len(prefixSpent):]
	if len(body) != 32 {
		return a, fmt.Errorf("%w: spent key is %d bytes", ErrCorruptState, len(body))
	}
	copy(a[:], body)
	return a, nil
}

func hashKey(prefix string, h types.Hash) []byte {
	out := make([]byte, 0, len(prefix)+32)
	out = append(out, prefix...)
	return append(out, h[:]...)
}

func decodeHashKey(key []byte, prefix string) (types.Hash, error) {
	var h types.Hash
	body := key[len(prefix):]
	if len(body) != 32 {
		return h, fmt.Errorf("%w: key is %d bytes", ErrCorruptState, len(body))
	}
	copy(h[:], body)
	return h, nil
}

// heightKey is big-endian so that a prefix scan is in height order.
func heightKey(h uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h)
	out := make([]byte, 0, len(prefixIndex)+8)
	out = append(out, prefixIndex...)
	return append(out, b[:]...)
}

func le64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

func encodeUndo(log *state.UndoLog) []byte {
	var out []byte
	out = append(out, le64(uint64(len(log.Cells)))...)
	for _, c := range log.Cells {
		out = append(out, c.Slot.Addr[:]...)
		out = append(out, c.Slot.Word[:]...)
		v := c.Old.Bytes()
		out = append(out, v[:]...)
	}
	out = append(out, le64(uint64(len(log.SpentAdded)))...)
	for _, a := range log.SpentAdded {
		out = append(out, a[:]...)
	}
	out = append(out, le64(uint64(len(log.SeenAdded)))...)
	for _, id := range log.SeenAdded {
		out = append(out, id[:]...)
	}
	out = append(out, le64(uint64(len(log.SeenRemoved)))...)
	for _, e := range log.SeenRemoved {
		out = append(out, e.ID[:]...)
		out = append(out, le64(e.TTL)...)
	}
	return out
}

func decodeUndo(raw []byte) (*state.UndoLog, error) {
	log := &state.UndoLog{}
	read := func(n int) ([]byte, error) {
		if len(raw) < n {
			return nil, fmt.Errorf("%w: truncated undo log", ErrCorruptState)
		}
		out := raw[:n]
		raw = raw[n:]
		return out, nil
	}
	count := func() (uint64, error) {
		b, err := read(8)
		if err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(b), nil
	}

	n, err := count()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		b, err := read(96)
		if err != nil {
			return nil, err
		}
		var cu state.CellUndo
		copy(cu.Slot.Addr[:], b[:32])
		copy(cu.Slot.Word[:], b[32:64])
		var v [32]byte
		copy(v[:], b[64:96])
		cu.Old = u256.FromBytes(v)
		log.Cells = append(log.Cells, cu)
	}

	if n, err = count(); err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		b, err := read(32)
		if err != nil {
			return nil, err
		}
		var a types.Address
		copy(a[:], b)
		log.SpentAdded = append(log.SpentAdded, a)
	}

	if n, err = count(); err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		b, err := read(32)
		if err != nil {
			return nil, err
		}
		var h types.Hash
		copy(h[:], b)
		log.SeenAdded = append(log.SeenAdded, h)
	}

	if n, err = count(); err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		b, err := read(40)
		if err != nil {
			return nil, err
		}
		var e state.SeenEntry
		copy(e.ID[:], b[:32])
		e.TTL = binary.LittleEndian.Uint64(b[32:40])
		log.SeenRemoved = append(log.SeenRemoved, e)
	}
	return log, nil
}
