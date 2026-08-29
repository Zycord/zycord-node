package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
)

// The future-time limit, and the queue that makes it a withhold rather than a
// rejection (R1-H2, docs/ARCHITECTURE.md §12).
//
// The rule the architecture states is asymmetric on purpose. The *lower* time
// bound is validity: a header must be later than the median of the last 11, and
// every node computes that from the same chain, so every node gets the same
// answer. The *upper* bound cannot be validity, because it is a comparison
// against the receiver's wall clock: make it a validity rule and an attacker
// mines a block exactly FTL seconds ahead, half the network accepts it, half
// rejects it, and the split is manufactured at will and costs one block.
//
// So a block from the future is neither accepted nor rejected. It is held until
// the local clock reaches `Time - FTL`, and then judged normally — by which
// point every node judges it the same way, because by then it is not from the
// future for anybody.
//
// `pow.IsTooFarAhead` was the only piece of this that had ever been written; it
// had no callers, so nothing bounded a block's timestamp on any ingress path.
// That is what made the chain-freeze attack reachable: a miner landing 6
// of any 11 consecutive blocks with `Time = now + 10^9` drags the median-time-
// past arbitrarily forward, every honest block after it reports a ~1 s solve
// against a 30 s goal, the LWMA's lower clamp fires every block, and the target
// divides by 16 per block to the floor. Neither of the two obvious fixes closes
// it — signed solve times and MTP-derived solve times both leave the poisoned
// chain advancing 1 s per block, which is still below the clamp — because the
// only quantity that matters is how far the median can be *pushed*. This queue
// is the bound on that push.
//
// **Clock boundary.** This is the node layer and it reads a clock; that is the
// whole point of the mechanism and it is why the mechanism cannot live in
// `core/`. `core/pow.IsTooFarAhead` takes `now` as an argument and consensus
// never supplies one. Everything below `Engine` — `node/chain`, `core/fold`,
// `core/pow` — stays clockless. The single reading is `Engine.now()`, and it is
// injectable so that tests drive time rather than sleep through it.

// WithholdLimits bound the withhold queue.
//
// The bound is not optional. A withheld block is a *cheaper* memory-pricing
// surface than the orphan pool it sits beside (the R4-H1 shape that
// docs/spec/wire.md §9 exists to prevent): an orphan must at least name a
// parent and sit inside a height window near the tip, whereas a withheld block
// need never attach to anything at all — its whole claim is "judge me later".
// Without a cap, "later" is free storage priced by the sender.
type WithholdLimits struct {
	// MaxBlocks and MaxBytes cap the queue outright.
	MaxBlocks int
	MaxBytes  int
	// HorizonSeconds is how far ahead a block may be and still be worth
	// holding. Beyond it the block is dropped rather than queued.
	//
	// "Never rejected" cannot mean "held for as long as the sender says". The
	// attack timestamp is `now + 10^9` — 31 years — and a queue that
	// honours it is a queue whose retention period the attacker chooses.
	// Dropping past the horizon is not a validity judgement and it does not
	// score the peer: the block may be re-sent at any time, and once the clock
	// is within the horizon it will be held and released like any other. The
	// horizon is deliberately far larger than FTL (180 s) so that ordinary
	// clock skew, even gross skew, is held rather than dropped.
	HorizonSeconds uint64
}

// DefaultWithholdLimits returns bounds sized for clock skew, not for a flood.
//
// 64 blocks is more future-dated blocks than a healthy network produces in an
// hour; 8 MiB is a quarter of the orphan pool's allowance, because a withheld
// block has done less to earn the space. The horizon is one hour: two orders of
// magnitude past FTL, and still finite.
func DefaultWithholdLimits() WithholdLimits {
	return WithholdLimits{MaxBlocks: 64, MaxBytes: 8 << 20, HorizonSeconds: 3600}
}

// withheldBlock is one queued block and the moment it becomes judgeable.
//
// **One representation of the block, not two, and that is the byte bound's
// correctness rather than a saving.** An earlier version kept the
// decoded `*types.Block` here beside `raw` for the whole life of the entry,
// and `withheldBytes` counted only `raw`. The queue's whole memory argument is
// `MaxBytes` (wire.md §9 rule 8: "A node MUST bound whatever it holds — by
// count and by bytes"), so counting one of two held things made the bound
// understate the real footprint by the decode expansion factor.
//
// **Measured between roughly 1.05x and 1.4x, and the conditions belong beside
// the number.** Heap retained by N live decodes of one block, HeapAlloc delta
// after a forced GC, on arm64. The top of that range is the shape that
// maximises *certificate count* for a given byte budget — a block of minimal
// certificates, whose 337-byte encoded floor buys a pointer, a slice header and
// a struct per certificate — and it was measured on synthetic blocks built to
// hit that shape, reaching 1.40x flat from 1,024 to 32,768 certificates. Blocks
// pinned instead to the real 2,500,000-byte genesis ceiling measure 1.07x to
// 1.21x across minimal, read-heavy, write-heavy and signature-heavy shapes.
// Signature- and move-heavy blocks sit at the bottom of the range, near 1.03x,
// because their bytes are payload rather than structure. So: a full 8 MiB queue
// held about 16.5 MiB for the shapes a chain actually produces, and up to about
// 19 MiB for a shape a sender is free to choose. The spread is exactly why an
// *estimate* is the wrong instrument here — the factor is content-dependent and
// the content is the sender's.
//
// Holding one representation makes the bound exact by
// construction instead of approximately right by estimate, and it is the same
// shape the orphan pool beside it already has: `holdOrphan` keeps the decoded
// block alone and counts `blk.SizeBytes()`, the *encoded* length. Whichever
// representation a pool keeps, "bytes" means the encoded size of the one
// thing held — and the withhold queue was the only pool in the package that
// held two.
type withheldBlock struct {
	id types.Hash
	// raw is the marshalled body as it was delivered, kept so that the release
	// path can re-judge it through the ordinary ingress path rather than
	// re-encode a decoded block and risk judging bytes nobody sent.
	//
	// It is also all the relay needs. `Node.releaseRelay` used to frame a
	// released block by calling `MarshalSSZ` on the decoded copy, and for bytes
	// that decoded that call reproduces exactly these bytes — so the decoded
	// block was a cache of them, priced at up to 40 % of them and counted at
	// nothing.
	//
	// The property that licenses this is the *decoder's*, not the encoder's,
	// and the distinction is why `core/ssz`'s canonicality docstring is not the
	// citation. What is needed is "every byte string that decodes re-encodes to
	// itself", which holds only if the decoder rejects every non-canonical
	// encoding. Tested rather than assumed: 300,000 random 1-3 byte mutations
	// of a real 40-certificate block, every mutant that decoded re-encoded and
	// compared — 239,914 decoded, 239,914 identical, no counterexample. And
	// nothing reaches this field without having decoded: `withhold` has one
	// call site, inside `OnBlock` and below its `UnmarshalBlock`.
	raw []byte
	// peer is the address the block arrived from, carried so that the verdict
	// the *release* produces is charged to whoever sent it.
	//
	// Without it the queue is an opt-out from peer scoring: any block-level
	// offence — a forged target, a backdated header, a bad citation — is
	// laundered by dating the block up to FTL ahead, because it is then queued,
	// judged later with no connection attached, and the ScoreInvalidMessage it
	// earns is applied to nobody. The block is still refused, so there is no
	// consensus harm; what is lost is the mechanism that prices *repeating* it,
	// for the cost of at most FTL seconds of delay. Empty when the caller is
	// not a peer, and then nothing is scored.
	peer string
	// releaseAt is the first local-clock second at which the block is no longer
	// too far ahead: Time - FTL. Derived once, so the release order cannot
	// drift from the admission decision.
	releaseAt uint64
}

// Errors the withhold path produces. None of them is a validity verdict.
var (
	// ErrBlockWithheld reports that a block was queued, not judged.
	ErrBlockWithheld = errors.New("p2p: block is dated ahead of the future-time limit; withheld")
	// ErrBlockBeyondHorizon reports a block so far ahead that holding it is
	// storage the sender priced.
	ErrBlockBeyondHorizon = errors.New("p2p: block is dated beyond the withhold horizon; dropped")
)

// now returns this node's clock in seconds, through the one injectable seam.
func (e *Engine) now() uint64 {
	return uint64(e.wallClock().Unix())
}

// wallClock is that same seam undivided by the truncation to seconds, for the
// callers that hold a time.Time rather than a header timestamp — today, the
// announcement bookkeeping ReapUnservedBodies reads. The Engine.Now doc calls
// itself "the only [wall clock] in the block path"; a direct time.Now beside
// it made that false and put the announce-to-reap window out of reach of the
// clock every other timing rule in this file is driven by.
func (e *Engine) wallClock() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// withhold queues a block that is too far ahead to judge.
//
// Returns ErrBlockBeyondHorizon if the block is past the horizon, or if the
// queue is full of blocks that all become valid sooner than this one — in both
// cases nothing is stored and nothing is scored.
func (e *Engine) withhold(peerAddr string, blk *types.Block, raw []byte) error {
	now := e.now()
	ftl := e.Chain.Params().FutureTimeLimitSeconds
	if blk.Header.Time > now+e.withholdLimits.HorizonSeconds {
		e.recordBeyondHorizon(peerAddr, blk.Header.Time-now)
		return fmt.Errorf("%w: dated %d, this node's clock reads %d",
			ErrBlockBeyondHorizon, blk.Header.Time, now)
	}
	// make+copy rather than `append([]byte(nil), raw...)`, and that is the byte
	// bound again rather than a style choice. append sizes the new slice
	// through Go's allocator size classes, so what it retains is cap and what
	// `withheldBytes` counts is len — and the gap between them is a function of
	// the block's length, which is the sender's to choose. Swept across every
	// size class up to block_byte_capacity (8,000,000) on go1.26 arm64: 0.04 %
	// at 8,000,000 bytes and 0.27 % at the 2,500,000-byte genesis ceiling, but
	// 12.50 % at 65,537 and **25.00 % at 32,769**, which is the worst point a
	// body can reach and is an ordinary small block rather than an exotic size
	// — a little larger than the 31,676-byte devnet block this issue was
	// measured on. Small in absolute terms against MaxBlocks = 64, and the same
	// shape of error as the decoded block this change removed: an under-count
	// whose factor the sender picks. make+copy allocates exactly len, so
	// cap == len and the accounting is the allocation.
	body := make([]byte, len(raw))
	copy(body, raw)
	entry := &withheldBlock{
		id:        blk.Header.ID(),
		raw:       body,
		peer:      peerAddr,
		releaseAt: blk.Header.Time - ftl,
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dup := e.withheld[entry.id]; dup {
		// Already queued, so nothing new is stored and this *block* is not
		// counted twice — the dedupe is local to this branch, and the other
		// paths deliberately count per delivery, since a block dropped eight
		// times cost this node eight refusals. But *this* sender is new
		// evidence, and dropping it here was a defect. A block gossiped by eight peers reaches withhold eight times
		// and matched this branch seven of them, so the breadth set held one
		// group where eight had sent it. Measured on a node 200-400 s slow with
		// eight peers in eight groups: Groups read 1, and the report named a
		// single peer as the suspect on a node whose own clock was the outlier
		// — the diagnosis inverted, in the exact band the withheld counter was
		// added for.
		e.recordSkewEvidenceLocked(peerAddr, blk.Header.Time-now)
		return ErrBlockWithheld
	}
	for len(e.withheld) >= e.withholdLimits.MaxBlocks ||
		e.withheldBytes+len(entry.raw) > e.withholdLimits.MaxBytes {
		if !e.evictFurthestWithheldLocked(entry.releaseAt) {
			e.recordWithholdOverflowLocked(peerAddr, blk.Header.Time-now)
			return fmt.Errorf("%w: the queue holds only blocks that mature sooner",
				ErrBlockBeyondHorizon)
		}
	}
	e.withheld[entry.id] = entry
	e.withheldBytes += len(entry.raw)
	e.recordFutureWithheldLocked(peerAddr, blk.Header.Time-now)
	return nil
}

// evictFurthestWithheldLocked drops the queued block that matures last, unless
// the incoming block matures later still.
//
// Eviction by distance-from-validity rather than by arrival order, and it is
// deterministic: the furthest-future block is the one whose claim on the space
// is weakest, and admitting a nearer block in its place is the only exchange
// that shortens the queue's expected life. Ties break on the block id, so two
// nodes holding the same set evict the same entry — a queue whose contents
// depend on map iteration order would make "which blocks did I relay on
// release" a per-node accident.
func (e *Engine) evictFurthestWithheldLocked(incoming uint64) bool {
	var worst *withheldBlock
	for _, w := range e.withheld {
		if worst == nil || w.releaseAt > worst.releaseAt ||
			(w.releaseAt == worst.releaseAt && bytes.Compare(w.id[:], worst.id[:]) > 0) {
			worst = w
		}
	}
	if worst == nil || worst.releaseAt <= incoming {
		return false
	}
	delete(e.withheld, worst.id)
	e.withheldBytes -= len(worst.raw)
	return true
}

// WithheldCount reports how many blocks are queued, for tests and metrics.
func (e *Engine) WithheldCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.withheld)
}

// WithheldBytes reports the queue's byte accounting — the quantity MaxBytes
// bounds, and therefore the quantity that has to be checkable against what the
// queue really retains.
//
// It exists because the bound was unobservable. `MaxBytes` is the whole
// of the queue's memory argument under wire.md §9 rule 8, and nothing outside
// this file could read the number it bounds, so no test could compare it to the
// footprint and the two were free to disagree — which is exactly what they did
// while a decoded block was retained beside the counted frame. A bound that
// cannot be observed cannot be defended by a test.
//
// **It counts what the queue holds, and held is not the same as live.** This is
// the same distinction MaxReassemblyBytes carries in engine.go one pool over,
// and it is here for the same reason. ReleaseWithheld deletes every due entry
// and repays its bytes under a single lock, then judges the collected slice
// entry by entry with the lock released. Across that loop up to
// WithholdLimits.MaxBytes of bodies are still resident — `due` pins every one
// of them, each `w.raw` stays alive through its OnBlock call, and they leave
// the function again inside the returned Released values — while this counter
// has already read them as gone. So WithheldBytes() may report 0 with a full
// queue's worth of bodies live, and the honest transient bound on this node's
// block-body footprint is
//
//	WithholdLimits.MaxBytes + the live reassembly figure documented at
//	MaxReassemblyBytes (MaxReassemblyBytes + C x BlockByteCapacity)
//
// which is the figure any future re-sizing of MaxBytes has to be argued against,
// not the constant alone.
//
// The gap is the counter's *name* over a transient interval and not a hole in
// the bound: admission is what enforces MaxBytes, the release is one pass over
// exactly what admission had already capped, and nothing a sender chooses widens
// it — so wire.md §9 rule 8 and §10.2's "bounded independently of anything the
// sender chooses" both still hold. Repaying after OnBlock returns instead was
// weighed and rejected for era-0, and that decision owns the reopen triggers.
func (e *Engine) WithheldBytes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.withheldBytes
}

// Released is the outcome of judging one block that has matured.
type Released struct {
	// ID is the released block's identifier, taken from the header at
	// admission rather than recomputed here.
	ID types.Hash
	// Raw is the marshalled body exactly as it was delivered — the same bytes
	// that were judged, so a relay forwards what this node accepted rather
	// than a re-encoding of what it decoded.
	//
	// It is the bytes and not a decoded `*types.Block` because the queue no
	// longer holds one: counting `raw` while retaining a decoded block
	// beside it made `MaxBytes` understate the queue's real footprint, and the
	// decoded block was only ever used to reach `MarshalSSZ` on this path.
	// Since `core/ssz` is canonical, these bytes *are* that result.
	//
	// Callers that need the structure — the multi-chunk relay fallback is the
	// only one — decode it with `Decode`, which costs one decode of a block
	// that has by then waited up to FUTURE_TIME_LIMIT_SECONDS.
	//
	// **These bytes are a peer's, and carrying them here is not a judgement of
	// them.** Every release is returned, including the ones OnBlock refused —
	// that is the point of Verdict sitting beside this field. A caller that
	// relays Raw without reading Verdict.Forward first would forward blocks
	// this node has just rejected, which is the failure the withhold rule
	// exists to prevent one hop further out. Node.withholdLoop checks Forward;
	// anything else that grows a use for this field must too.
	Raw []byte
	// Verdict is what OnBlock made of it, now that it is no longer early. It
	// carries Forward, which is what decides relay: a withheld block is *never*
	// relayed while it is withheld, only once it has been judged and accepted.
	// Relaying it earlier would propagate a timestamp this node cannot yet
	// validate, and would make the withhold rule pointless one hop away.
	Verdict Verdict
}

// Decode returns the released block's structure.
//
// Separate from Raw and not a field, because the relay path a release feeds
// does not need it: `Node.releaseRelay` frames the body it already has, and
// only the multi-chunk fallback — which must build a BlockAnnounce out of the
// header and the certificate exemplar hashes — has to look inside. Making it a
// call is what keeps the queue holding one representation instead of two.
//
// The cost is one decode of a block that has already waited up to
// FUTURE_TIME_LIMIT_SECONDS to be judged, on a path that runs from a one-second
// ticker rather than from a peer's message, so it is on no latency path. It is
// also not a *new* decode of these bytes in the ordinary case: ReleaseWithheld
// judges every released block through OnBlock, which decodes the same bytes,
// so a caller reaching here is asking for a second copy of something the
// release already proved decodable.
//
// The error is returned rather than swallowed because these bytes are a peer's
// and this type must not invite a caller to assume otherwise — though in
// practice a Released whose Verdict accepted the block has already decoded.
func (r Released) Decode(p *params.Params) (*types.Block, error) {
	return types.UnmarshalBlock(r.Raw, p)
}

// ReleaseWithheld judges every queued block whose time has come.
//
// This is the re-evaluation trigger the rule needs: nothing else would ever
// revisit a held block, because the event that makes it judgeable is the local
// clock advancing and no message arrives to announce that. `Node.withholdLoop`
// calls it on a ticker; a caller with its own clock discipline can call it
// directly.
//
// The bytes are repaid to withheldBytes while `due` is collected, so from there
// on up to WithholdLimits.MaxBytes of bodies are live and uncounted — see the
// WithheldBytes doc for the bound that describes them.
func (e *Engine) ReleaseWithheld() []Released {
	now := e.now()

	e.mu.Lock()
	var due []*withheldBlock
	for id, w := range e.withheld {
		if w.releaseAt <= now {
			due = append(due, w)
			delete(e.withheld, id)
			e.withheldBytes -= len(w.raw)
		}
	}
	e.mu.Unlock()
	if len(due) == 0 {
		return nil
	}

	// Oldest first, so that a run of withheld blocks forming a chain is offered
	// to fork choice in the order it was mined rather than in map order.
	sortWithheld(due)

	out := make([]Released, 0, len(due))
	for _, w := range due {
		// Through the ordinary ingress path, deliberately: a released block has
		// been judged by nothing yet.
		//
		// But the peer attribution is gated on the peer still being connected.
		// OnBlock calls recordAnnounce for any non-empty address, which creates
		// or refreshes an e.tips entry, and the only remover of e.tips is
		// forgetPeer at disconnect — which already ran, keyed on the
		// connection, and does not touch this withhold queue, keyed on the
		// block id. So a block released from a peer that hung up between
		// delivery and release (about a second, or a whole horizon, later)
		// would resurrect a tips entry under a dead ephemeral address that
		// nothing reaps, breaking the declared invariant len(e.tips) <=
		// len(Node.conns) and — since undialable peers stay in candidacy —
		// seeding a permanent, undialable sync candidate for zero attacker
		// cost. Passing "" suppresses exactly the recordAnnounce/tips mutation
		// (OnBlock guards it on a non-empty address) while the block still
		// reaches fork choice through the Released return below, which is the
		// whole and only effect of the release. A peer still connected at
		// release time registers its tip as before.
		onBlockPeer := w.peer
		if onBlockPeer != "" && !e.handshaked(onBlockPeer) {
			onBlockPeer = ""
		}
		v := e.OnBlock(onBlockPeer, w.raw)
		// And the verdict is charged to the peer that delivered it. This call
		// does not go through Handle, which is where every other ingress path
		// applies a score, so without this line the queue would be a way to
		// send invalid blocks for free: date them ahead, and the penalty lands
		// on nobody. Scoring the sender of a block that turns out *useful* is
		// the same rule read the other way, and both are the ordinary path's
		// semantics arriving late rather than a new judgement.
		if w.peer != "" && v.Score != 0 {
			e.Peers.Adjust(w.peer, v.Score)
		}
		// And counted here for the same reason, one field over: this is the
		// engine's second exit, so a released block that is relayed onward
		// (withholdLoop broadcasts exactly these) would otherwise be the one
		// forward the counter never sees.
		e.countVerdict(v)
		out = append(out, Released{ID: w.id, Raw: w.raw, Verdict: v})
	}
	return out
}

// sortWithheld orders by release time, then by id, with no dependence on map
// iteration order.
func sortWithheld(w []*withheldBlock) {
	for i := 1; i < len(w); i++ {
		for j := i; j > 0; j-- {
			a, b := w[j-1], w[j]
			if a.releaseAt < b.releaseAt ||
				(a.releaseAt == b.releaseAt && bytes.Compare(a.id[:], b.id[:]) <= 0) {
				break
			}
			w[j-1], w[j] = b, a
		}
	}
}

// tooFarAhead is the predicate, read through this node's clock.
func (e *Engine) tooFarAhead(h types.Header) bool {
	return pow.IsTooFarAhead(h, e.now(), e.Chain.Params())
}

// maxSkewGroups bounds the set of senders remembered against the future-dated
// counters.
//
// The set exists to answer "one sender, or most of them", and that question is
// settled long before 32. Bounding it is not decoration: the key is derived
// from an address the remote end chooses, the withhold path runs before any
// scoring, and an unbounded set keyed on it is storage a peer prices — the same
// objection WithholdLimits above exists for.
const maxSkewGroups = 32

// recordFutureWithheldLocked notes a block queued for being dated ahead of FTL.
// Called with e.mu held, from the end of withhold's admission path.
//
// **This is the bound a slow clock reaches first, and it drops nothing at all.**
// A block dated more than FTL ahead is queued and released when the local clock
// reaches Time-FTL, so a node slow by S runs permanently S-FTL behind the
// network while losing no block and refusing nobody. That is the slow-clock
// stall exactly — silently falling permanently behind — and it begins at
// S > FTL, which is 180 s, not at the 3600 s horizon.
//
// Measured on devnet, 300 honest blocks arriving one per interval with the
// queue drained every second as withholdLoop drains it:
//
//	skew        100   200   300   400   500
//	withheld      0   300   300   300   300
//	dropped       0     0     0     0     0
//
// Nothing was dropped and nothing was counted anywhere in that range, while the
// standing queue depth — which is the lag — grew with the skew. That depth is
// (S-FTL)/TargetBlockSeconds in the steady state: 4, 24, 44 and 64 blocks for
// those four columns, and a probe measures within one block of it depending on
// where in the interval it samples.
//
// Counting only what is *dropped* reports zero across the whole of that range,
// which is why this counter exists beside the two that do count drops.
func (e *Engine) recordFutureWithheldLocked(peer string, skew uint64) {
	e.futureWithheld++
	e.recordSkewEvidenceLocked(peer, skew)
}

// recordFutureAnnouncement notes an announcement dropped for being dated ahead
// of FTL.
//
// **This is the earliest of the five sensors, and the only one a node with a
// single upstream ever gets.** Blocks gossip hash-first — Node.AnnounceBlock
// broadcasts a header, and a body only floods one hop later, when some peer has
// accepted it and node.go's serve loop re-broadcasts what it received. A node
// whose only peer is the block's origin therefore sees announcements and never
// a body, and OnBlockAnnounce drops a future-dated one without asking for the
// body. Measured before this existed: a victim 4000 s slow, fed six future-
// dated announcements, reported every counter at zero and logged nothing, while
// node/sync turned each pass into a silent Result{} — a node in exactly that
// condition with no sensor of any kind.
//
// Dropped and not queued, so it is counted apart from the three withhold
// bounds: the announcement costs this node nothing to lose, since the network
// re-sends it for free and the id is deliberately kept out of seenBlocks. What
// it costs is the block, until some peer floods the body or sync fetches it.
// onFutureAnnouncement is everything a future-dated announcement does.
//
// The tip refresh is the point. PeerTip.OffersUnknown is the one sync
// candidacy signal that is not frozen at the handshake, and OnBlockAnnounce
// reaches recordAnnounce only on the path that survives the future-time check.
// So a node whose clock is slow by more than the future-time limit stops
// refreshing every peer's tip at the exact moment it stops accepting their
// gossip: it cannot take blocks from gossip, and it degrades its own view of
// who is worth asking, which is the one mechanism it has left. The two
// failures compound, and the second is self-inflicted.
//
// Recording the tip is not believing the block. The announcement is still
// dropped, still not relayed, still not entered into seenBlocks; what is kept
// is that this peer showed us a header we cannot place, at a height where it
// could matter — the same class of claim a Hello carries and is already
// trusted with at handshake time. It is not proof of anything: on this path
// the work check reads the header's own declared target and never re-derives
// it (R4-H1), so a MaxTarget header costs its sender one hash. That is
// tolerable only because of what it buys, which is a place in the list of
// peers worth asking. It decides who is asked, never what is believed: every
// header a sync answer carries is re-derived from the difficulty rule before
// any body is fetched.
func (e *Engine) onFutureAnnouncement(peer string, h types.Header, skew uint64) {
	// Before the counters and not inside them: recordAnnounce asks the chain
	// outside e.mu and then takes it itself, so it cannot run under the lock
	// recordFutureAnnouncement holds.
	e.recordAnnounce(peer, h)
	e.recordFutureAnnouncement(peer, skew)
}

func (e *Engine) recordFutureAnnouncement(peer string, skew uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.futureAnnounced++
	e.recordSkewEvidenceLocked(peer, skew)
}

// RecordSyncWithheld notes a headers-first sync pass that could do nothing
// because the range it was offered started ahead of this node's clock.
//
// The fifth ingress this condition reaches, and the one named explicitly.
// node/sync.ValidateHeaders stops a range at the first header this node's clock
// cannot reach; when that is header 0 there is nothing to validate, runOnce
// turns it into a successful empty Result, and nothing is scored or logged —
// correctly, since the peer did nothing wrong. What was missing is that the
// same emptiness is what an up-to-date node returns, so a node stuck at a fixed
// lag was indistinguishable from a node with nothing to do.
//
// Counted with the gossip evidence rather than beside it, because it is the
// same fact arriving by another road and an operator has one clock to fix. It
// is the *coarsest* of the five — one event per pass rather than per message,
// and only against the peer sync happened to select — which is why it is not
// the only sensor and why the gossip paths are instrumented too.
func (e *Engine) RecordSyncWithheld(peer string, skew uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncWithheld++
	e.recordSkewEvidenceLocked(peer, skew)
}

// recordBeyondHorizon notes a block dropped for being dated past the horizon:
// how far past this node's clock it was, and who sent it.
//
// skew is the raw gap between the block's timestamp and local time, so it is
// the sender's clock plus this node's error and not a measurement of either
// alone. That is precisely why these are *diagnostics* and not inputs to
// anything, and why the sender is recorded alongside them: one such block says
// a peer is fast or this node is slow, and only the *breadth* of senders tells
// the two apart. A count, however large, cannot — a single peer can produce any
// count it likes for the price of sending, which is the forward-dating shape
// exactly.
//
// peer may be empty: OnBlock is exported and takes the address as an argument,
// so a caller that is not a connection can reach here. No production path does
// — Node.serve passes conn.Addr, and ReleaseWithheld passes the address the
// block originally arrived from — but the guard is what makes that a fact about
// callers rather than an assumption. An empty address is counted in the totals
// and left out of the breadth set, since "nobody sent it" is not evidence about
// anybody.
func (e *Engine) recordBeyondHorizon(peer string, skew uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.beyondHorizon++
	e.recordSkewEvidenceLocked(peer, skew)
}

// recordWithholdOverflowLocked notes a block dropped because the queue was full
// of blocks that all mature sooner than it. Called with e.mu already held, from
// inside withhold's admission loop.
//
// This is the middle of the withhold path's three bounds. The queue holds a
// block for Time-FTL,
// so a node slow by S carries (S-FTL)/TargetBlockSeconds of them at once, and
// once the queue is full every further block is refused here instead of queued.
// Which of MaxBlocks and MaxBytes binds depends on block size — 64 blocks, or
// 8 MiB, whichever is reached first, so at the 2.5 MB genesis byte ceiling the
// queue holds three blocks rather than sixty-four and this bound arrives far
// sooner than the block count alone suggests.
//
// **It is not by itself evidence about a clock**, and the shape of the refusal
// does not make it so. "Everything queued matures sooner" says the arriving
// block is the furthest into the future this node knows of — which a steadily
// slow clock produces, and so does any peer sending a non-decreasing run of
// future timestamps, at about 64 hashes a block (see the pricing note above the
// withhold call in engine.go). Only breadth separates them, which is why every
// one of these paths records the sender and why the report is gated on the
// senders rather than on the count.
func (e *Engine) recordWithholdOverflowLocked(peer string, skew uint64) {
	e.withholdOverflow++
	e.recordSkewEvidenceLocked(peer, skew)
}

// recordSkewEvidenceLocked records the part every recording path shares: how
// far ahead, and which address group it came from.
//
// **Grouped by address group, not by address.** peerAddr for an inbound
// connection is
// RemoteAddr().String(), an ip:port whose port is ephemeral — the resettable
// half that node.go's own reconnect note calls out. Keyed on it, one host on
// two source ports counts as two senders, which is what defeated the first
// version of this. AddressGroup is the Sybil unit this package already uses for
// the listener's per-source limit and for peer selection — /16 for IPv4 and /32
// for IPv6, and every address it cannot parse collapses to one group — so this
// uses it for the same reason and inherits the same coarseness.
func (e *Engine) recordSkewEvidenceLocked(peer string, skew uint64) {
	if skew > e.maxSkewSeconds {
		e.maxSkewSeconds = skew
	}
	if peer == "" {
		return
	}
	group := AddressGroup(peer)
	if e.firstSkewGroup == "" {
		e.firstSkewGroup = group
	}
	if e.skewGroups == nil {
		// Lazily, because an Engine built as a struct literal — which the
		// tests in this package do — never ran NewEngine.
		e.skewGroups = make(map[string]string, maxSkewGroups)
	}
	// A group this node dialled is admitted whatever the cap says, and that
	// exemption is the difference between a bound and a suppression lever.
	//
	// The set saturates by *insertion order*, so with a flat cap an attacker
	// who lands maxSkewGroups forged announcements from that many address
	// groups first keeps every dialled peer out of the evidence for the whole
	// episode. Measured: 32 primed groups, then a genuine 4000 s local clock
	// fault delivering 800 honest messages from all eight dialled peers, and
	// the report still read "0 of them among the 8 peer(s) this node dialled"
	// — the same shape a forgery makes, on a node that really was slow. The
	// forge cost is about 31 hashes a header, since OnBlockAnnounce checks the
	// work a header *declares*, and ScoreFutureBlock is zero, so the priming
	// is free and can be repeated after every ResetSkewEvidence.
	//
	// Exempting them is safe precisely because this node chose them: the set
	// of dialled groups is its own, bounded by MaxOutbound, and not something
	// a sender can grow by sending.
	if _, dialled := e.dialledGroups[group]; dialled {
		e.skewGroups[group] = peer
		return
	}
	if len(e.skewGroups) < maxSkewGroups {
		e.skewGroups[group] = peer
	}
}

// SetDialledGroups tells the Engine which address groups this node has dialled,
// so evidence from them is never crowded out of the bounded set above.
//
// Pushed by the Node when its outbound set changes rather than read at report
// time, because the crowding-out happens at *record* time: by the time a report
// is built, the group that was excluded has already been excluded. The Engine
// cannot derive this for itself — which connections this node initiated is the
// Node's bookkeeping, and it is the same distinction Topology draws.
func (e *Engine) SetDialledGroups(groups map[string]struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dialledGroups = groups
}

// SkewReport is what the future-dated counters know, taken together.
//
// Returned as a struct rather than as a tuple because the fields are only
// meaningful read together: the counts say how bad it is and by which bound,
// MaxSkewSeconds says by how much, and Groups is the only one of them that
// bears on *whose fault it is*. A caller handed the counts alone can do no
// better than guess, which is what a two-value form invites.
type SkewReport struct {
	// Count is how many future-dated messages this node has seen in the current
	// episode: Announced + Withheld + QueueFull + BeyondHorizon + SyncPasses.
	Count uint64
	// Announced is how many announcements were dropped for being dated ahead.
	// The earliest signal, and the only one a single-upstream node receives.
	Announced uint64
	// SyncPasses is how many headers-first sync passes could do nothing because
	// the range began ahead of this node's clock. One per pass, so it is small
	// beside the others and is the reason rather than the magnitude.
	SyncPasses uint64
	// Withheld is how many were queued and released late rather than lost.
	// This is the earliest and mildest bound — S > FTL — and the one under
	// which a node falls permanently behind without losing a single block.
	Withheld uint64
	// QueueFull is how many arrived to a queue holding only blocks that mature
	// sooner, and were dropped. See recordWithholdOverflowLocked.
	QueueFull uint64
	// BeyondHorizon is how many were dated past the horizon outright.
	BeyondHorizon uint64
	// MaxSkewSeconds is the largest gap observed between such a block's
	// timestamp and this node's clock. The raw gap, not the excess over a bound.
	MaxSkewSeconds uint64
	// Groups is how many distinct address groups sent them (AddressGroup: /16
	// for IPv4, /32 for IPv6), saturating at maxSkewGroups.
	Groups int
	// Senders is one recorded address per group, so a caller can weigh the
	// evidence against the peers it chose for itself rather than against
	// everyone who dialled in. A bare count cannot be weighed that way, and a
	// count read against connections an attacker opens is a ratio he sets — see
	// Node.reportClockSkew.
	//
	// **Addresses, not groups, because agreement is matched exactly.** Matching
	// on the group instead lets one host inside a dialled peer's /16 be counted
	// as that peer agreeing: measured on a node whose clock was exactly right,
	// with its eight dialled peers silent and one attacker inside each of their
	// eight /16s, the report read "8 of them among the 8 peer(s) this node
	// dialled" and sent the operator to check an NTP that was fine. Exact
	// matching costs nothing to Sybil resistance here, because the addresses
	// being matched against are ones *this node chose to dial* — the "one host,
	// two source ports" objection applies to senders, whose breadth is still
	// counted by group.
	//
	// One address per group, so the slice stays bounded with the group set.
	// Unordered: it is consumed by lookup.
	Senders []string
	// FirstGroup is the group of the first such sender, so a report about a
	// single one can name it. Empty if every one of them arrived with no
	// address attached.
	FirstGroup string
	// QueueDepth is how many blocks are queued right now. On a slow clock this
	// is the lag, one block per TargetBlockSeconds of it, and it is the number
	// that says the condition is still going rather than over.
	QueueDepth int
}

// BeyondHorizon reports the future-dated blocks the withhold path has seen: how
// many, by which path refused each one, how far ahead, and from how many distinct
// address groups.
//
// Nonzero counts from *most of this node's peers at once* is the signature of a
// clock problem on this machine. The withhold path exists so that skew is
// absorbed rather than punished, so blocks arriving ahead from every direction
// mean the local clock is the outlier, and the consequence is quiet: below the
// queue bound nothing is even lost, the node simply runs late for as long as
// the skew lasts.
//
// The same counts from *one* group are the opposite reading and must not be
// dressed up as this one: that is a peer dating blocks forward, which the
// withhold path is refusing correctly. Deciding between the two needs the
// connected peer set, which the Engine does not have — see Node.reportClockSkew.
//
// The counters describe the current episode, not the process lifetime;
// ResetSkewEvidence ends one.
func (e *Engine) BeyondHorizon() SkewReport {
	e.mu.Lock()
	defer e.mu.Unlock()
	senders := make([]string, 0, len(e.skewGroups))
	for _, addr := range e.skewGroups {
		senders = append(senders, addr)
	}
	return SkewReport{
		Count: e.futureAnnounced + e.futureWithheld + e.withholdOverflow +
			e.beyondHorizon + e.syncWithheld,
		Announced:      e.futureAnnounced,
		SyncPasses:     e.syncWithheld,
		Withheld:       e.futureWithheld,
		QueueFull:      e.withholdOverflow,
		BeyondHorizon:  e.beyondHorizon,
		MaxSkewSeconds: e.maxSkewSeconds,
		Groups:         len(e.skewGroups),
		Senders:        senders,
		FirstGroup:     e.firstSkewGroup,
		QueueDepth:     len(e.withheld),
	}
}

// ResetSkewEvidence clears the counters, so the next future-dated block starts
// a fresh episode.
//
// Episodes rather than lifetime totals, because the report is rate-limited by
// doubling and a monotonic counter turns that into a silencer. Two ways, both
// measured: after a 5000-drop episode the operator has already fixed, a genuine
// new one stays quiet for 5000 further blocks; and an attacker who can produce
// blocks at ~64 hashes each can run the count to 10^6 for seconds of CPU, after
// which a real mainnet clock fault at 8 blocks per 30 s is silent for 43 days.
// A threshold that only ever rises is a threshold an adversary can set.
//
// Called by Node.withholdLoop when the condition has stopped, which is the only
// point at which "how bad is it" has a new answer rather than a stale one.
func (e *Engine) ResetSkewEvidence() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.futureAnnounced = 0
	e.syncWithheld = 0
	e.futureWithheld = 0
	e.withholdOverflow = 0
	e.beyondHorizon = 0
	e.maxSkewSeconds = 0
	e.skewGroups = nil
	e.firstSkewGroup = ""
}

// WithholdHorizonSeconds reports the configured horizon, so a caller
// diagnosing clock skew can name the bound a block exceeded.
func (e *Engine) WithholdHorizonSeconds() uint64 {
	return e.withholdLimits.HorizonSeconds
}
