package p2p

import (
	"context"
	"errors"
	"fmt"
	gosync "sync"
	"time"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/sync"
)

// The sync driver.
//
// `node/sync` validates header chains; this runs it against peers. Without it a
// node only ever learns about blocks gossiped *after* it connected: a fresh node
// stays at height zero forever, and two nodes that diverged never fetch the
// ancestors they are missing, so a healed network stays forked.
//
// That gap was found by the chaos soak rather than by any unit test, which is
// the argument for the soak: every piece worked and nothing connected them.
//
// Sync runs on a **dedicated connection** rather than sharing the gossip loop.
// Request/response interleaved with unsolicited gossip needs correlation ids and
// a state machine; a separate connection needs neither, and the cost is one
// socket per sync round.
//
// That is the rule and it is no longer unconditional (wire.md 12). A peer
// advertising no listen address cannot be dialled, so there is no dedicated
// connection to open and sync against it runs over the gossip connection it
// opened to this node - see syncOverGossip below. That path pays the state
// machine this comment declines: one outstanding request per connection, and a
// frame claimed only when it could answer it (headersAnswer, chunkAnswers).

// offersUnknownWindow is how long an unplaceable announcement keeps a peer
// worth asking. A few sync intervals: long enough to survive a partition
// healing, short enough that a peer stops being a candidate once it has nothing
// new to show.
const offersUnknownWindow = 30 * time.Second

// ErrTransport marks a sync failure that is the network's doing rather than the
// peer's: a severed connection, a read deadline, a peer that restarted.
//
// It exists because `sync.Fetch` cannot tell the difference — at the BodyFetcher
// interface a refusal and a dead socket are both an error — and charging a peer
// for packet loss is how an honest peer on a lossy link gets banned. Over a long
// catch-up a single sync round is hundreds of round trips, so the chance of at
// least one transport fault approaches certainty exactly when the node most
// needs that peer.
var ErrTransport = errors.New("p2p: sync transport failure")

// ErrIdentityBanned marks a sync attempt refused because the peer's
// authenticated identity — not just its dial address — has scored itself
// out. See SyncFrom.
var ErrIdentityBanned = errors.New("p2p: peer identity is banned")

// ErrAttemptExpired marks a sync attempt that ended because it ran out of its
// own whole-attempt time budget (syncAttemptTimeout), rather than because the
// peer did anything wrong.
//
// It exists for the operator, not for the score. A cold sync of a chain
// longer than one attempt can serve is *expected* to end this way, repeatedly:
// the deadline fires, every in-flight read fails with an i/o timeout, and
// `sync.Fetch` — which cannot see the deadline and correctly does not try to —
// reports the failure in the only vocabulary it has, `ErrBodyUnavailable`
// ("peer will not serve a body for a header it advertised"). syncLoop's log
// then names the honest bootstrap peer as a withholder for doing nothing but
// being slower than a ten-minute budget on a long chain.
//
// Nothing was ever charged for it — `connSource.Body` wraps every round-trip
// failure in ErrTransport and SyncPenalty exempts all of them, so the penalty
// on this path is zero under any parameter set — but the log line was still
// wrong, and it is the only thing an operator sees. Reclassifying happens here
// because this is the only layer that knows the attempt's deadline; the inner
// error is kept with %w, so ErrTransport and ErrBodyUnavailable still match
// and SyncPenalty stays zero by construction.
//
// Deliberately *not* applied to a transport failure that arrives before the
// deadline: a peer that genuinely vanished mid-attempt keeps reading as a
// transport failure, which is what it is.
var ErrAttemptExpired = errors.New("p2p: sync attempt reached its time budget")

// ErrUndialable marks a sync attempt that never got a connection at all: the
// address the peer advertised did not answer.
//
// It is separated from every other transport fault because it is the only one
// that says nothing about the peer. The peer is still there, on the socket it
// opened; what failed is the route this node chose to reach it, and syncOnce
// re-asks it over the socket instead. Every other fault happened *after* a
// connection existed, and re-asking on the spot would only ask the same peer
// the same question twice in one turn of the rotation.
var ErrUndialable = fmt.Errorf("%w: the address this peer advertised did not answer", ErrTransport)

// syncAttemptTimeout is the default whole-attempt deadline for SyncFrom: a
// hard ceiling on the wall-clock time *one* sync attempt against *one* peer
// may run, on top of and independent of every per-read deadline inside it.
//
// docs/adversarial/sync.md names the gap this closes: `await` tolerates up to
// sixteen unsolicited messages at twenty seconds each (320s) before giving up
// on *one* request — but a sync attempt is not one request. `extendToCover`
// can issue many header round trips and `Fetch` one body round trip per
// header, so a peer that answers every individual request just inside its own
// 320s budget, forever, can hold `syncLoop` — which drives one attempt at a
// time, synchronously — hostage for as long as it keeps doing that. Nothing
// bounded the sum before this.
//
// The value is sized off real data volumes, not guessed:
//
//   - A header batch (syncBatch=128 * types.HeaderSize=228B ≈ 28.5 KiB) is
//     negligible next to everything below it, at any link speed this project
//     assumes.
//   - A block body is capped by spec/params.json's block_byte_capacity
//     (8,000,000 bytes): the structural ceiling every era's real per-block
//     limit (block_byte_limit_genesis=2,500,000 today) is clamped under, and
//     so the largest body this node can ever be legitimately asked to
//     receive for one header.
//   - docs/decisions/testnet-measurements.md and capacity-eras.md give the
//     sustained-bandwidth floor the network is provisioned against at each
//     end of that range: ~0.7 Mbit/s (87.5 KB/s) at the genesis byte ceiling,
//     ~2.1 Mbit/s (262.5 KB/s) at the structural one — both deliberately
//     calibrated so a maximally-sized block transfers in about one block
//     interval (target_block_seconds=30s) at the slowest link the design
//     tolerates: 8,000,000B / 262.5KB/s ≈ 30.5s.
//
// Ten minutes, at those floors, buys roughly 21 genesis-ceiling blocks
// (50 MiB / 2.5 MB) or 19 structural-ceiling blocks (150 MiB / 8 MB) of real
// progress per attempt — several batches' worth on an honest, merely slow,
// link — while comfortably exceeding await's own existing 320s per-request
// tolerance, so a single legitimate round trip that needs its *entire*
// existing budget still has room to spare rather than being cut off by this
// new, coarser bound. Partial progress is not lost when the deadline does
// fire: Fetch lands an extending candidate's blocks as it goes, and
// BodyCache retains a reorg candidate's bodies across attempts (both
// pre-existing), so a large catch-up simply resumes on the next rotation
// rather than restarting.
//
// Against the adversary: this turns "hours, reachable" (the issue's own
// figure for the unbounded case, since maxHeaders/batch header round trips
// and one body round trip per header can each individually run 320s) into a
// fixed ten minutes, paid at most once per full rotation of candidates
// (NextSyncPeer already will not ask the same peer again until every other
// candidate has had a turn) — the same "wasted round trip per rotation is
// bounded and accepted" cost model docs/adversarial/sync.md §5 already
// assigns to an ordinary uncooperative peer, just with the per-attempt cost
// now actually bounded rather than open-ended.
//
// Prior art agrees on "minutes, not hours" for the same class of decision,
// for the same reason — bound a peer's patience budget without punishing
// real network variance:
//   - Bitcoin Core's headers-sync stall timeout is
//     HEADERS_DOWNLOAD_TIMEOUT_BASE (15 minutes) plus
//     HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER (1ms) per expected header
//     (net_processing.cpp); a peer that has not kept pace by then is
//     disconnected.
//   - go-ethereum's downloader gives each request an adaptive RTT-based
//     timeout capped by ttlLimit = 1 minute (eth/downloader/peer.go),
//     dropping a peer that cannot answer inside it.
//
// A Node field (SyncAttemptTimeout) rather than only this constant, mirroring
// SyncInterval/DialInterval, so a test can shorten it instead of waiting real
// minutes for the property under test; this constant is what NewNode defaults
// it to.
const syncAttemptTimeout = 10 * time.Minute

// clampDeadline returns the earlier of a freshly computed per-read deadline
// and a whole attempt's own absolute deadline.
//
// Used everywhere SyncFrom or connSource is about to set a per-operation
// deadline — every SetReadDeadline, and every SendDeadline — so that a
// per-operation reset can never silently extend a read or a write past the
// attempt's own budget. This is what actually closes the whole-attempt
// deadline race described on SyncFrom's watcher: it is not that one read
// occasionally dodges one external SetDeadline(time.Now()) call — it is
// that nothing stopped the *next* deadline computation from re-extending
// past the budget regardless. Clamping every computation removes the
// question rather than racing to win it.
func clampDeadline(fresh, attempt time.Time) time.Time {
	if fresh.After(attempt) {
		return attempt
	}
	return fresh
}

// syncBatch is how many headers are requested at a time.
const syncBatch = 128

// PeerTip records how far ahead a peer claims to be.
//
// It is keyed by connection address and carries both routes to the peer,
// because sync opens its own connection only where it can. Dial is the address
// the peer advertised, preferred while it answers; Conn is the socket the tip
// was learned on, and the only route to a peer that advertises nothing — or
// advertises somewhere nobody can reach.
type PeerTip struct {
	Height uint64
	Work   u256.U256
	Dial   string
	// Conn is the address of the live connection this tip was learned on.
	//
	// It is not a substitute for Dial and is never dialled: for an inbound peer
	// it is an ephemeral source port with nothing listening behind it. It is
	// what identifies the *socket*, which is the only route to a peer that
	// advertises no listen address, and the fallback route to one whose
	// advertised address does not answer — see syncOnce. Filled in by
	// SyncCandidates from the map key, so it cannot drift from it.
	Conn string
	Seen time.Time
	// OffersUnknown is when this peer last announced a block we do not have,
	// at a height fork choice could still adopt: at or above our own, or below
	// it by no more than the reorg horizon.
	//
	// It exists because Work is frozen. A handshake is one sample; announcements
	// carry a header, not a chain, so there is no honest way to update a peer's
	// *accumulated* work from gossip — and a connection outlives its handshake
	// by hours. Comparing a stale Work against our current work is a comparison
	// that stops being true almost immediately, and it is what makes candidacy
	// by work inert on any stable connection.
	//
	// An announcement this node cannot place is the signal that survives: it is
	// a fact about what the peer just showed us rather than a claim about how
	// much work it has. It is not evidence that the block is real — the
	// announce path checks work against the header's own declared target and
	// never re-derives it (R4-H1) — so it decides only who is worth asking.
	OffersUnknown time.Time
	// Handshaked records that this connection completed its one handshake.
	//
	// A separate flag rather than "is there an entry", because an entry can also
	// be created by a block announcement that arrives before the handshake —
	// legal, and treating it as a completed handshake would disconnect a peer
	// for its own first Hello.
	Handshaked bool
	// lastGetPeers is when this connection was last served peer exchange, and
	// it is what GetPeersMinInterval is measured from.
	//
	// It is unexported and lives here rather than in a map of its own because
	// this map already has exactly the lifetime the rate limit needs - one
	// entry per connection this node is talking to - so the limit adds no state
	// that has to be reaped separately, and none a peer can mint by asking.
	// Zero means never served.
	lastGetPeers time.Time
	// lastPeers is when this connection last had a `peers` frame *accepted*,
	// and it is what PeersMinInterval is measured from.
	//
	// It is the ingress mirror of lastGetPeers above and lives here for exactly
	// the same reason: this map already has one entry per connection this node
	// is talking to, so the limit adds no state to reap and none a peer can
	// mint by sending. A refused frame does not stamp it, so a flood cannot
	// push its own window forward and starve the honest frame behind it.
	// Zero means never accepted.
	lastPeers time.Time
}

// syncKey identifies this peer for the sync rotation.
//
// The advertised address where there is one, because that survives a
// reconnect on a fresh ephemeral port and is what the persisted peer store
// and the ban filter are keyed by. The connection address otherwise: without
// it every undialable peer would share the empty key, and one rotation entry
// shared by all of them means asking one counts as asking all — the starvation
// NextSyncPeer's rotation exists to prevent, re-created by the key rather than
// by the ranking.
func (t PeerTip) syncKey() string {
	if t.Dial != "" {
		return t.Dial
	}
	return t.Conn
}

// recordTip stores a peer's advertised head from its handshake.
func (e *Engine) recordTip(conn string, h Hello) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tips == nil {
		e.tips = map[string]PeerTip{}
	}
	// The dialable address is pinned by the first handshake and never rewritten.
	//
	// It is the key for the sync rotation *and* for the ban filter, so leaving it
	// mutable would let one socket mint a fresh never-tried identity on demand —
	// defeating the rotation by rotating the key — and shed any accumulated ban
	// with it. Pinning is belt to the braces of refusing a second handshake at
	// all: either alone closes the hole, and the two together mean a future
	// change to one does not silently reopen it.
	//
	// The entry is MUTATED IN PLACE and not rebuilt as a composite literal, and
	// that is a bound rather than a style. A literal here assigns every field
	// this function knows about and silently zeroes every field it does not, so
	// each field added to PeerTip afterwards is a fresh chance to write a rate
	// limit a peer can clear by re-handshaking. That is not hypothetical:
	// lastGetPeers and lastPeers below had to be carried by hand when the two
	// peer-exchange rate limits landed; the key-epoch budget was added beside
	// them and was NOT, and a spent budget of MaxUnheldKeyEpochsPerPeer was
	// reset to zero by this assignment. Mutating in place inverts the default —
	// a new field is carried unless this function says otherwise — so the state
	// the standard calls wrong is unrepresentable rather than merely absent.
	// Carrying is still braces to a belt in both cases — a second handshake is
	// refused on this connection anyway — but the belt is one gate away and the
	// braces are here.
	//
	// Nothing else is carried by accident. Height, Work and Seen are exactly
	// what a handshake reports and are overwritten either way; Conn is filled
	// by the reader (syncRotationView) and never stored; OffersUnknown can only
	// be non-zero here if an announcement arrived before the handshake, which
	// Handle's own gate makes unreachable today — and where it is reachable,
	// keeping a true observation is the correct answer rather than the
	// incidental one a literal gave.
	t := e.tips[conn]
	if t.Dial == "" {
		t.Dial = h.ListenAddr
	}
	t.Height = h.Height
	t.Work = u256.FromBytes(h.Work)
	t.Seen = time.Now()
	t.Handshaked = true
	e.tips[conn] = t
}

// recordAnnounce refreshes a peer's height from a block it showed this node.
//
// **Announced or delivered**, and the name is narrower than the callers. It is
// reached from `OnBlockAnnounceFrom` on both the accepted and the over-budget
// paths, from `onFutureAnnouncement` for a header this node's clock refuses,
// and from `OnBlock` for a body a peer delivers. The question it answers
// is the same in all four — "did this peer just show us a header we cannot
// place" — and the delivery case is the one that arrived last, so the name kept
// the announce it was written for.
//
// The handshake is a single sample taken when the connection opened, and a
// connection outlives it by hours. Without this the sync driver would compare
// against a number that stopped being true one block after the peer connected,
// which is the same as not having it.
//
// Only the height is taken. The header's *work* is not trustworthy here — that
// is precisely R4-H1, a declared target nobody can check without the ancestors
// — so this decides who to ask, never what to believe.
func (e *Engine) recordAnnounce(conn string, h types.Header) {
	// Whether this node can place the announced block is a question for the
	// chain, so it is asked outside the engine's lock.
	own := e.Chain.Height()
	// Asked outside the lock for the same reason as the height above.
	horizon := e.Chain.Params().UndoDepth
	// Canonical, not merely known. A block this node reorged away keeps its
	// header, so Header would report it as one we already have — and a peer
	// announcing that segment because it won there would stop looking like a
	// peer offering anything new. Two nodes on either side of a fork would each
	// decide the other had nothing, which is the healed-network-stays-forked
	// failure this file's opening comment names.
	_, missing := e.Chain.CanonicalHeader(h.ID())

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tips == nil {
		e.tips = map[string]PeerTip{}
	}
	t := e.tips[conn]
	if h.Height > t.Height {
		t.Height = h.Height
	}
	// A block we do not have, at a height where it could matter. That is the
	// equal-height case and the ahead case.
	//
	// This is a *weaker* signal than it looks, and the difference matters
	// (R4-H1). An announced header is checked against h.Target, its own
	// declared target: pow.checkWorkWith never re-derives the target on this
	// path, because re-deriving needs the ancestors and the point of hash-first
	// relay is to decide before fetching them. Only OnBlock re-derives. So a
	// header declaring MaxTarget, with an empty exemplar list and a CertRoot
	// that matches it, reaches this line for the cost of one hash. What this
	// records is therefore that the peer showed us *a header we cannot place*,
	// not that it paid for one — which is fine, because the only thing it
	// buys is a place in the list of peers worth asking.
	//
	// "Where it could matter" is the reorg horizon, not our own height.
	// Fork choice decides by accumulated work, so a branch can be strictly
	// heavier while ending *below* our tip — HANDOFF §7 records an observed
	// 154-block reorg onto a branch 30 blocks shorter. The old bound here was
	// one height, which made every such peer invisible to candidacy: its height
	// loses, its handshake work sample predates the divergence, and its
	// announcement fell outside the window. Neither side asks the other and the
	// fork never heals.
	//
	// The horizon is params.UndoDepth because that is the depth ConsiderBranch
	// itself refuses past (node/chain/forkchoice.go, ErrBeyondUndoHorizon): a
	// fork point deeper than that can never be adopted, so its holder is not
	// worth a round trip. The announced height bounds the fork point from
	// above: the announced block sits on the branch, so the fork point is at
	// h.Height-1 or lower, and own-h.Height+1 is a lower bound on the reorg
	// depth this branch would need.
	//
	// The bound is therefore deliberately inclusive by one. The tight necessary
	// condition is own-h.Height < UndoDepth, because at a distance of exactly
	// UndoDepth the implied reorg is UndoDepth+1 deep for *every* possible fork
	// point and ConsiderBranch refuses it. <= is kept anyway: this decides who
	// is asked, and asking one peer we did not have to is a round trip, while
	// not asking is a heavier-but-shorter branch nobody ever pulls. The slack
	// is one block against a horizon of 1024, and it is the safe direction.
	//
	// Written as a subtraction guarded by the ordering rather than as
	// h.Height+UndoDepth >= own, which is hygiene rather than a defence: that
	// addition only wraps if our own height is within UndoDepth of 2^64, so the
	// two forms are equivalent on any reachable chain. This form is preferred
	// because it does not require the reader to establish that.
	if missing != nil && (h.Height >= own || own-h.Height <= horizon) {
		t.OffersUnknown = time.Now()
	}
	t.Seen = time.Now()
	e.tips[conn] = t
}

// forgetPeer drops a disconnected peer's advertised head and any block
// transfers it had in flight.
//
// The second is not tidiness. `partial` is keyed by connection address —
// ephemeral port included, so never reused — and this is the only teardown
// hook a connection has, so a transfer interrupted by a disconnect would
// otherwise be held for the life of the process. Sixty-four connect /
// chunk-0 / disconnect cycles would fill the table permanently, refusing
// every multi-chunk transfer afterwards.
func (e *Engine) forgetPeer(conn string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.tips, conn)
	e.dropPeerTransfers(conn)
}

// syncRotationView returns the sync candidates and the rotation key of every
// peer this node currently holds a tip for, candidate or not, from ONE
// acquisition of e.mu.
//
// The key set is what bounds NextSyncPeer's memory, and it is
// deliberately wider than the candidate list and narrower than "every address
// ever seen". Wider: a peer whose candidacy has lapsed — OffersUnknown gone
// stale on a connection that is still up — is one the rotation must still
// remember a position for, or its return costs it a full cycle it has already
// waited. Narrower: the tip goes when the connection does (forgetPeer), so
// nothing is kept for a peer that cannot be offered to the rotation again
// without one.
//
// Both from one acquisition, and that is the bound rather than tidiness.
// NextSyncPeer retains the intersection of its old memory with the key set and
// then seeds every candidate key, so the seeding runs after the prune and
// re-enters any key the prune has just dropped. Under two acquisitions those
// are two snapshots of e.tips: a key that was a candidate at the first read and
// whose tip was gone by the second is pruned and seeded straight back in, and
// the retained set is bounded by the *union* of the two snapshots — twice the
// connection bound and not the connection bound. One acquisition makes the
// candidate keys a subset of the key set by construction, which is what makes
// len(syncTried) <= len(Engine.tips) an inequality rather than an
// approximation. It also makes a union of the candidate keys into the prune's
// liveness set provably inert rather than merely unnecessary, since a union
// with a subset is the identity.
func (e *Engine) syncRotationView() ([]PeerTip, map[string]struct{}) {
	own := e.Chain.Height()
	ownWork := e.Chain.TotalWork()
	e.mu.Lock()
	defer e.mu.Unlock()
	keys := make(map[string]struct{}, len(e.tips))
	for conn, t := range e.tips {
		// Conn from the map key for the reason syncCandidatesLocked gives: a
		// tip must never carry a socket it was not learned on, and syncKey
		// falls back to Conn for a peer that advertises no address at all.
		t.Conn = conn
		keys[t.syncKey()] = struct{}{}
	}
	return e.syncCandidatesLocked(own, ownWork), keys
}

// SyncCandidates returns the dialable, unbanned peers claiming to be ahead of
// this node — by height, or by work at the same height.
//
// **Both**, and the second one is not an optimisation. Gating on height alone
// leaves two branches of equal height permanently unresolved: fork choice
// decides by accumulated work, so an equal-height branch can be strictly
// heavier, and neither node will ever ask the other for it. A 20-minute soak
// ended exactly there — node b at height 537 on one tip, nodes c and d at
// height 537 on another, all three reporting no peer ahead of them, for an
// hour. Nothing was broken and nothing was going to fix itself.
//
// Claimed work is no more verifiable than claimed height, and that is fine for
// the same reason: this only decides who is worth a round trip. Every claim a
// peer then makes is re-derived from the difficulty rule before a single body is
// fetched, so the trigger cannot be used to make this node believe anything.
// What it can do is make the trigger agree with the rule that actually decides —
// a node that chooses branches by work should ask about branches by work.
//
// It returns *all* of them rather than the maximum, and that is the whole point.
// An argmax over unverified claims is a starvation vector: a single peer that
// says it is at height one billion is the maximum on every tick, forever, and
// the honest peer holding the real chain is never asked. Re-derivation bounds
// what a liar can make this node *believe*; it does nothing about what a liar
// can stop this node from *hearing*. Choosing among candidates is the caller's
// job, and it is done by fairness rather than by ranking.
func (e *Engine) SyncCandidates() []PeerTip {
	own := e.Chain.Height()
	ownWork := e.Chain.TotalWork()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.syncCandidatesLocked(own, ownWork)
}

// syncCandidatesLocked is SyncCandidates' body, split out so syncRotationView
// can take the candidate list and the rotation keys from one acquisition of
// e.mu rather than two. e.mu must be held.
//
// own and ownWork are parameters rather than reads because e.Chain is
// deliberately consulted before e.mu is taken and not under it.
func (e *Engine) syncCandidatesLocked(own uint64, ownWork u256.U256) []PeerTip {
	var out []PeerTip
	for conn, t := range e.tips {
		// The connection address comes from the map key rather than from the
		// entry, so a tip can never carry a socket it was not learned on.
		t.Conn = conn
		// A peer with no advertised address used to be dropped here, and that
		// is the never-sync-from-an-inbound-peer freeze: candidacy was gated on
		// *dialability*, so the one shape docs/RUNNING.md recommends —
		// listening, no --peers of its own — froze at the first block it had to
		// pull, because every peer it had was one that dialled *it*. Observed
		// in production: a node held at height 217 for 45 minutes next to a
		// peer at 268, through reconnects and through restarts of both sides,
		// reporting ahead_peers=0 and logging nothing. A peer that cannot be
		// dialled can still be asked over the connection it opened
		// (syncOverGossip); which socket carries the request is settled by what
		// answers, and by nothing else.
		//
		// Ahead by height, by claimed work, or by having shown us a block we
		// cannot place. The third is the one that still works an hour into a
		// connection, because it is refreshed by gossip rather than frozen at
		// the handshake.
		behind := t.Height <= own && !t.Work.Gt(ownWork)
		stale := time.Since(t.OffersUnknown) > offersUnknownWindow
		if behind && stale {
			continue
		}
		// A banned peer is not a candidate. The score was computed and then
		// discarded before this: nothing consulted it on the path that decided
		// who to talk to, so misbehaviour cost a peer nothing that mattered.
		//
		// Both addresses are checked, because scoring and candidacy are keyed
		// differently. Gossip scores the *connection* address, which for an
		// inbound peer is an ephemeral source port; candidacy needs the
		// *advertised* address, which is the only one anybody can dial back.
		// Checking one alone means an inbound peer's misbehaviour never reaches
		// the filter that is supposed to act on it.
		//
		// Dial is checked only when there is one: an undialable peer has no
		// advertised address to ban, and asking the store about "" would be
		// asking about an entry no peer can own.
		if (t.Dial != "" && e.Peers.Banned(t.Dial)) || e.Peers.Banned(conn) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// syncLoop periodically catches up with a peer that claims to be ahead.
//
// The peer is chosen **least-recently-tried first**, not highest-claim first,
// and that choice is the defence. It gives the property that matters and that
// ranking cannot give:
//
//	no peer is asked twice until every other candidate has been asked once.
//
// It holds without deciding whether any claim is true, which is what makes it
// survive a calibrated lie. A liar can still waste one round trip per rotation;
// it cannot own the rotation. Height breaks ties among equally-stale
// candidates, so an honest network still asks its best peer first.
func (n *Node) syncLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.quit:
			return
		case <-time.After(n.SyncInterval):
		}

		peer, ok := n.NextSyncPeer()
		if !ok {
			continue
		}
		n.MarkSyncTried(peer.syncKey())

		from, err := n.syncOnce(peer)
		if err != nil {
			n.log("sync from %s: %v", from, err)
			if penalty := SyncPenalty(err); penalty != 0 {
				n.Peers.Adjust(from, penalty)
			}
		}
	}
}

// syncOnce runs one attempt against one candidate and reports the address the
// outcome is attributable to.
//
// A dedicated connection where this node can open one, and the connection the
// peer already opened where it cannot. The choice is forced by reachability,
// not by preference: wire.md §12's reasons for a dedicated socket (no request
// ids, no state machine) still hold, and syncOverGossip pays for them with a
// per-request match instead.
//
// **Advertising an address is not answering at one, and the first fix closed
// only the half where nothing was advertised.** A peer that advertises an address
// nobody can reach was still dialled — every rotation, forever — and that is
// the same permanent freeze entered through the other branch: the node is
// behind, connected to a peer that is ahead, and never receives a block again.
// It is the harder half to see, because this time the peer *is* a candidate
// and `ahead_peers` counts it, so the one signal that named the first freeze
// reports the second as healthy. The shape is not exotic: `zycordd` falls
// `--advertise` back to `--listen`, so a NAT'd node given `--listen
// 0.0.0.0:9421` advertises `0.0.0.0:9421`, and every listening node it dials
// records that as its dialable address. Reachability is a fact about a route
// and only a connection attempt establishes it; a claim is where to look
// first, not what to conclude.
//
// Only a dial that produced no connection is re-routed. A peer that answered
// and then served badly is that peer's own doing, and re-asking it on the spot
// would ask one peer twice in one turn of a rotation whose whole property is
// that it does not. The cost is one refused connect per rotation for such a
// peer, ahead of an attempt that then does real work, and Dial's own timeout
// bounds it.
//
// The address is returned rather than re-derived by the caller because the two
// routes attribute differently, and conflating them is where this could weaken
// address trust — one admission door, and no unearned rank. A re-routed attempt
// is answered over the socket the peer owns, so its verdict belongs to that
// socket — the address gossip already scores it by (I5). Charging it to the
// advertised address instead would let any inbound peer file its own
// misbehaviour against whatever address it cares to name, which is a ban an
// attacker writes for a victim it has never met.
func (n *Node) syncOnce(t PeerTip) (string, error) {
	if t.Dial != "" {
		if err := n.SyncFrom(t.Dial); !errors.Is(err, ErrUndialable) {
			return t.Dial, err
		}
	}
	return t.Conn, n.syncOverGossip(t)
}

// SyncPenalty is what a failed sync costs the peer that served it.
//
// Exported and named because it is a policy decision, and an unnamed policy
// decision inlined in a loop is one nothing can observe. This one was wrong for
// a while in a way no test could see: the guard below separates a peer that
// answered badly from every failure of the round trip itself, and it was
// defeated by a `%v` in sync.Fetch that flattened the transport sentinel into a
// string. The guard read correctly, reviewed correctly, and never fired.
//
// A peer must not be charged for this node's own packet loss. Over a long
// catch-up a sync round is hundreds of round trips, so the chance of at least
// one transport fault approaches certainty exactly when the node most needs
// that peer — and a ban also removes the peer from sync candidacy, so the
// charge falls on the node that cannot catch up rather than on anyone at fault.
func SyncPenalty(err error) int {
	penalty := 0
	// The only charge reachable here is **served-but-wrong**, and that is the
	// rule rather than an accident of the guard.
	//
	// `connSource.Body` wraps every round-trip failure — a dropped socket, a
	// silent peer, a locally closed descriptor — in `ErrTransport`, so the
	// exemption below removes every "the peer answered nothing" case. What is
	// left is the set of `ErrBodyUnavailable` sites that require the peer to
	// have answered: a different block, a bad cert root, a bad cites root, an
	// illegal citation, an unknown citation version, a citation at the wrong
	// height, a citation without work — plus `connSource.Body`'s own unwrapped
	// returns for an undecodable chunk, a chunk continuing a different
	// transfer, an over-capacity body, and an undecodable block. Every one of
	// them is a peer that served bytes that were a lie.
	//
	// Served-nothing is **deliberately uncharged on this path**, not merely
	// unreachable. `ScoreUnservedBody` prices a block a peer volunteered by
	// announcing it (Engine.ReapUnservedBodies), not a question this node
	// asked; there is no "no" frame on this wire (docs/spec/wire.md §9), so an
	// honest peer on a bad link and a peer withholding on purpose reach exactly
	// the same observations and no predicate over them separates the two.
	// Request-path withholding is carried by rotation — docs/adversarial/sync.md
	// §5, "Wasted round trips per rotation | Nothing, and nothing should".
	if errors.Is(err, sync.ErrBodyUnavailable) && !errors.Is(err, ErrTransport) {
		penalty += ScoreUnservedBody
	}
	if errors.Is(err, sync.ErrForgedTarget) || errors.Is(err, sync.ErrBadWork) ||
		errors.Is(err, sync.ErrNotContiguous) || errors.Is(err, sync.ErrBrokenLinkage) ||
		errors.Is(err, sync.ErrBadTime) || errors.Is(err, sync.ErrBadVersion) {
		// Every one of these is a peer describing a chain that cannot exist.
		// They were free before: the score was only charged for two of the six
		// ways to lie.
		penalty += ScoreInvalidMessage
	}
	// `sync.ErrContradictsCheckpoint` and `sync.ErrBelowMinChainWork` are
	// **deliberately absent from both lists**.
	//
	// Every error above is a peer breaking a rule of the protocol. Those two
	// are a peer breaking *this client's release policy*: a checkpoint table
	// and a chain-work floor that ship in `spec/checkpoints.json`, are refreshed
	// every release, and are outside `ConsensusRoot()` precisely because they
	// are not consensus. A wrong value in that file would, if it were charged
	// here, ban the honest network from every node that took the release —
	// turning an editing mistake into a partition. So the refusal costs this
	// node its sync attempt and costs the peer nothing, and it is
	// `node/sync.Admit`'s comment that owns the argument.
	return penalty
}

// NextSyncPeer picks the candidate this node has gone longest without asking.
//
// Exported so the rotation property can be tested directly rather than inferred
// from whether a soak happened to converge. The peer-selection bug it replaces
// was invisible for exactly that reason: nothing observed the choice, only its
// downstream effect, and the effect looked like ordinary slowness.
func (n *Node) NextSyncPeer() (PeerTip, bool) {
	// One acquisition of e.mu for both, so the candidate list and the prune's
	// liveness set are the same snapshot of Engine.tips — see syncRotationView
	// for why that is the bound rather than tidiness. Read outside n.mu, so the
	// prune below introduces no nesting of the node's lock around the engine's
	// that did not already exist here.
	candidates, live := n.Engine.syncRotationView()
	if len(candidates) == 0 {
		return PeerTip{}, false
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.syncTried == nil {
		n.syncTried = map[string]uint64{}
	}

	// Prune to the peers this node still holds a tip for, before choosing.
	//
	// The rotation's memory is keyed by a peer's advertised address, and
	// addresses come and go — so without this the map only ever grows, for the
	// whole life of a process that is meant to run for months. It is bounded by
	// liveness rather than by a cap or a timeout: a cap needs a number and
	// invites eviction pressure, and a timeout is a clock this node would have
	// to defend.
	//
	// The liveness set is the *tip* set and not the *candidate* set, and that
	// distinction is what makes the rotation a rotation. Bounding on candidacy
	// was justified as the only bound with a meaning — "an address that is not
	// a candidate is one this node has no reason to remember having asked" —
	// and the reason it names is the wrong one. This map does not record who
	// was asked; it orders who is asked next, and that reason survives for
	// exactly as long as the peer can return without a new connection.
	// Candidacy resting on OffersUnknown alone lapses after offersUnknownWindow
	// while the socket stays up, so pruning on candidacy forgot a peer that had
	// not gone anywhere, and the seeding below then re-entered it at the back
	// on every return. Where len(candidates) * SyncInterval >
	// offersUnknownWindow that is permanent starvation rather than a delay, and
	// admission admits far more connections than that inequality allows
	// candidates.
	//
	// Bounding by the tip set keeps every property the candidate bound had. It
	// is still liveness, it still needs no number, and it still cannot be
	// inflated without paying for what bounds it:
	//
	//	len(syncTried) <= len(Engine.tips) <= len(Node.conns)
	//	              <= MaxInbound + 2*MaxOutbound = 48
	//
	// The two links hold for different reasons and are not equally exact, so
	// they are stated apart rather than read off one line.
	//
	// The FIRST is exact by construction. candidates and live come from one
	// acquisition of e.mu (syncRotationView), so every key the seeding loop
	// below enters is already in the set the prune keeps, and what this map
	// holds after a selection is a subset of the tip set that selection read.
	// Two acquisitions would make it the union of two snapshots instead, which
	// is twice this bound and not this bound. No single-threaded caller can
	// separate one read from two, because it gets the same tips from either, so
	// this half is established by construction rather than by an outcome.
	//
	// It is exact against that snapshot and not against the live map, and
	// quiescence does not close the gap. With no candidates the early return
	// above leaves before n.mu and before the prune, so a node holding no
	// candidate at all sits with syncTried keyed on tips that are gone until
	// the next selection that has one. That population is wider than an idle
	// node: having no candidate is not having no peers, and its common member
	// is a node that is simply caught up, every peer connected and every tip
	// live.
	//
	// The CARDINALITY is untouched by that and is the reason the figure still
	// means something: the seeding loop is also below the early return, so with
	// no candidates nothing is added either and syncTried is frozen rather than
	// growing. Unbounded in time is not unbounded in size. Between selections
	// the size also rests on MarkSyncTried only ever rewriting a key the
	// snapshot already held, which is a fact about the one non-test caller it
	// has today rather than a structural guarantee.
	//
	// The SECOND link is exact while no connection is being torn down. That is
	// an ordering read off unregister rather than an interleaving anyone here
	// has driven: unregister deletes from Node.conns under n.mu, releases it,
	// and only then calls Engine.forgetPeer, so between those two statements a
	// tip outlives the connection entry it was admitted against. Creation is
	// the safe way round — the tip is written by Handle, which serve reaches
	// only after register has stored the connection. The window predates this rule
	// and is untouched by it: it belongs to unregister's lock order rather than
	// to this rule, and closing it means reordering a teardown, so it is named
	// here and left alone.
	//
	// MaxInbound + 2*MaxOutbound rather than MaxInbound + MaxOutbound because
	// register's capacity gate is inbound-only and topUp bounds outbound
	// separately (engine.go states the same product for the same reason).
	//
	// The middle link is a choke point and a key rather than a list of function
	// names, because an enumeration of spellings is never a property. Engine
	// holds tips in a map it never lets escape — it is never returned, assigned
	// away or passed as an argument — so nothing outside this package can
	// insert. Every write keys on the peerAddr handed to Engine.Handle, which
	// has exactly one non-test caller (node.go, in serve), and it passes
	// conn.Addr: the same string register has already stored in Node.conns. So
	// keys(Engine.tips) is a subset of keys(Node.conns) by construction, and
	// forgetPeer deletes the entry on unregister, the one teardown a connection
	// has. Only the non-escape half of that survives a future edit: because
	// tips is unexported and never escapes, a new write has to be written
	// inside this package, where the same census sees it. The provenance half
	// is a statement about the write sites that exist today, not about ones
	// nobody has written — an in-package helper need not be reached through
	// Handle at all, since syncLoop and probationLoop already run from timers
	// Handle never touches, and it could key a write on something other than
	// conn.Addr.
	//
	// Connections are priced by admission; candidacy is not, so the
	// bound moves off the unpriced grant onto the priced one.
	//
	// No union with the candidate keys: with one acquisition above they are a
	// subset of live, so a union would be the identity.
	for addr := range n.syncTried {
		if _, ok := live[addr]; !ok {
			delete(n.syncTried, addr)
		}
	}

	// A candidate seen for the first time enters the rotation at the back, not
	// at the front.
	//
	// This used to read the zero time for an unknown key, so "never tried"
	// sorted ahead of every peer that had been. That made the front of the
	// rotation cost exactly what candidacy costs, and candidacy is free: the
	// announce path checks work against the header's own declared target, which
	// nobody can re-derive without the ancestors (R4-H1), so a MaxTarget header
	// buys OffersUnknown for one hash. The rotation key is not scarce either —
	// it is the advertised address, or the connection address for a peer that
	// cannot be dialled — and the prune above deliberately drops the memory of
	// any key that stops being a candidate. So an identity that keeps
	// *appearing* was never-tried on every round and won every round. That
	// surface was first scored as rotation dilution; it was starvation, which
	// is a different thing: measured on this rotation, 20 rounds against two
	// honest peers and one fresh identity per round reached the honest peers
	// twice.
	//
	// Minting identities is not even required, and that is the sharper form of
	// the bug. Candidacy only has to be cheap to *drop and regain*, because the
	// prune forgets and the old code re-entered at the front: one address whose
	// candidacy flaps, reusing a single rotation key, took 28 of 30 rounds from
	// three equal honest peers. What is cheap here is the re-entry, not the
	// identity.
	//
	// Seeding is a claim about ordering rather than a threshold: the rotation
	// asks the peer it has gone longest without asking, and a peer that has just
	// entered has not been waiting. Any peer already in the rotation carries a
	// lower sequence number, so entering cannot preempt one.
	//
	// The cost is one cycle — len(candidates) * SyncInterval — and it is paid on
	// every *entry* to the candidate set, because seeding fires for any key the
	// prune has dropped. With the prune bounded by the tip set that is once per
	// connection: a peer whose candidacy lapses while its socket stays up is
	// never dropped, so it is never re-seeded.
	//
	// The prune used to be bounded by the candidate set and the cycle was
	// paid on every lapse instead, which made service conditional on a whole
	// cycle fitting inside the staleness window:
	//
	//	len(candidates) * SyncInterval <= offersUnknownWindow
	//
	// Past that a lapsing peer never reached the front before lapsing again, was
	// re-seeded to the back on return, and was starved permanently rather than
	// delayed — worst for a peer claiming neither more height nor more work,
	// which is the shorter-but-heavier fork holder OffersUnknown exists to reach.
	// The boundary is sharp to the integer and lands at ten candidates on the
	// shipped constants. §6.1 of docs/adversarial/sync.md carries the
	// derivation, the measured cliff and the claim-position tables; it is worth
	// reading before touching the prune, because it is the argument that decided
	// which set bounds it.
	//
	// Narrow, and the old rule was not a regression either. Anything ahead by
	// height or claimed work is continuously a candidate and never lapses; only
	// a peer ahead on neither was exposed — and under the old seeding that same peer
	// preempted everything. The trade was forced: the mechanism that let a
	// lapsing honest peer jump the queue is the one that let an attacker own the
	// rotation.
	//
	// The current rule closes it without taking either side of that trade, by changing
	// neither the seeding nor the ranking but the prune's liveness set. The
	// peer keeps the position it earned, so it does not have to jump the queue,
	// and an identity that is genuinely new still enters at the back. The
	// condition above no longer gates service: the wait is len(candidates)
	// rounds plus whatever the peer is absent for when its turn arrives, which
	// has no term in offersUnknownWindow at all and so survives parameter sets
	// that decouple the two constants. That matters here rather than in the
	// abstract, because tuning either constant toward the other used to narrow
	// the margin silently and mainnet's target_block_seconds is already exactly
	// equal to the window.
	//
	// The scope is a peer whose *socket* stays up. One that disconnects loses
	// its tip and with it its position, which is the memory bound working as
	// intended and has a starvation regime of its own at a different constant,
	// quantified in §7 of docs/adversarial/sync.md.
	//
	// Note this bounds what candidacy *buys*, not who gets it. Nothing here
	// changes what is accepted, relayed or believed.
	//
	// Every candidate first seen on this round shares one sequence number, so
	// they are placed at the back *together* and the height tie-break below
	// still orders them against each other — which is what §4 of
	// docs/adversarial/sync.md means by claimed height breaking ties among
	// equally-stale candidates. On the very first round every candidate is new,
	// they all tie, and the rotation starts exactly where it did before.
	var seeded bool
	for _, c := range candidates {
		if _, known := n.syncTried[c.syncKey()]; !known {
			if !seeded {
				n.syncSeq++
				seeded = true
			}
			n.syncTried[c.syncKey()] = n.syncSeq
		}
	}

	var best PeerTip
	var bestTried uint64
	var found bool
	for _, c := range candidates {
		tried := n.syncTried[c.syncKey()]
		switch {
		case !found:
		case tried < bestTried:
		case tried == bestTried && c.Height > best.Height:
		default:
			continue
		}
		best, bestTried, found = c, tried, true
	}
	return best, found
}

// MarkSyncTried records that a peer was just asked, advancing the rotation.
func (n *Node) MarkSyncTried(addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.syncTried == nil {
		n.syncTried = map[string]uint64{}
	}
	n.syncSeq++
	n.syncTried[addr] = n.syncSeq
}

// SyncFrom runs headers-first sync against one peer over a fresh connection,
// bounded by a whole-attempt deadline independent of and on top of every
// per-read deadline inside it. See syncAttemptTimeout's doc for how that
// number was chosen, and n.SyncAttemptTimeout to override it (used by tests).
func (n *Node) SyncFrom(addr string) error {
	conn, err := n.Identity.Dial(addr, 10*time.Second)
	if err != nil {
		// A self-connection is refused here too, by the same post-handshake
		// key comparison the dial loop meets, and is scored as an ordinary
		// failed dial. It is deliberately NOT recorded in Node.selfAddrs:
		// that set is attacker-inducible — an on-path relay to this
		// node's own listener produces a genuine self-verdict about an
		// address that is not this node's — so it gets exactly one writer,
		// the dial loop, rather than every place a dial can happen. The
		// sync path loses nothing by it: a candidate that is really this
		// process is dropped from the dial set by topUp on its own next
		// round, and until then this costs one refused handshake per sync
		// attempt, against an interval measured in seconds.
		n.Peers.MarkFailed(addr)
		return fmt.Errorf("%w: %w", ErrUndialable, err)
	}
	defer conn.Close()

	// A peer banned on its gossip connection is refused here too, before a
	// single byte is sent — otherwise it sheds that ban for the cost of one
	// more handshake, on a connection SyncCandidates' address-only ban filter
	// cannot see through: candidacy is keyed by the peer's *dialable* address
	// (t.Dial), which a purely inbound gossip connection never scores.
	if n.Peers.BannedKey(conn.PeerKey) {
		return ErrIdentityBanned
	}

	timeout := n.SyncAttemptTimeout
	if timeout <= 0 {
		timeout = syncAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Always ok: WithTimeout always installs one.
	attemptDeadline, _ := ctx.Deadline()

	// closed signals that this call is returning, so the watcher goroutine
	// below can stop rather than run forever.
	//
	// Its defer is registered *after* conn.Close()'s, which — defers being
	// LIFO — is what makes it run *before* conn.Close() on the way out, so
	// the watcher observes "we're done" and returns rather than racing the
	// teardown. That ordering is a convenience, not a correctness
	// requirement: conn.Close() is safe to call twice, from this function
	// and the watcher both, per net.Conn's contract.
	closed := make(chan struct{})
	defer close(closed)

	// Force any blocked or future read/write on this connection to fail the
	// moment the whole-attempt deadline expires or the node starts shutting
	// down (n.quit), whichever comes first — interrupting an in-progress
	// Receive/Send rather than merely refusing to start the next one.
	//
	// This closes the connection outright rather than setting a deadline,
	// and that is a correction, not a style choice: an earlier version of
	// this fix called SetDeadline(time.Now()) instead, once, and that is
	// not a reliable interrupt against a peer that keeps anything arriving.
	// net.Conn's deadline only gates the *blocking* wait; a read that finds
	// data already sitting in the kernel's receive buffer returns it
	// without ever consulting the deadline at all, expired or not — that is
	// the fast path, not a bug, and it means a peer sending junk faster than
	// the reads can drain it can keep every read succeeding regardless of
	// how many times or how often the deadline is reasserted. Confirmed two
	// ways: a raw net.Conn read racing a concurrent SetDeadline against a
	// write landing ~150-200µs away completed anyway in ~1.9% of trials in
	// isolation, and a repro against this exact path — a peer sending junk
	// every ~1ms against a 15ms SyncAttemptTimeout — kept producing
	// occasional trials tens to hundreds of ms over budget even after this
	// watcher was changed to re-arm the deadline on a short tick instead of
	// setting it once, because re-arming *more* deadline values does not
	// help when the read that matters never blocks long enough to consult
	// any of them.
	//
	// Closing does not have that failure mode: once the underlying file
	// descriptor is gone, a read cannot return buffered data through it
	// regardless of what was sitting in the kernel's socket buffer, because
	// there is no longer a descriptor to read it through. Go's runtime
	// coordinates this with the netpoller specifically so a concurrent
	// Close unblocks a parked Read/Write cleanly, which is the same
	// documented "safe to call concurrently" contract the deadline approach
	// relied on — the difference is what happens to data that arrived
	// first, not whether concurrent use is safe. One call is therefore
	// enough; there is nothing to re-arm.
	//
	// The per-operation deadlines below and in connSource are clamped to
	// attemptDeadline (clampDeadline), and the two mechanisms are
	// deliberately redundant for the timeout: measured by isolated
	// mutation, removing either one alone still leaves a stalling peer
	// bounded, and only removing both together unbounds it (at which point
	// the attempt runs to await's own 20s per-read window). Neither is
	// therefore "the" enforcement, and this comment should not claim one
	// is.
	//
	// They cover different shapes, which is why both are kept. The clamp
	// bounds a read or write that has *not started yet*: once the attempt
	// deadline has passed, every subsequent deadline computation lands in
	// the past, so the operation fails immediately instead of being handed
	// a fresh 15s/20s/writeTimeout window. Closing bounds one that is
	// *already parked*, which no future deadline computation can reach.
	//
	// The redundancy is not free of asymmetry: n.quit reaches only this
	// watcher, never the clamp, so shutdown is closing's alone. Removing
	// the watcher leaves the timeout bounded but hangs Node.Stop behind a
	// stalling peer, which is exactly what
	// TestStopReturnsPromptlyDespiteAStuckSyncAttempt fails on.
	//
	// n.quit is folded in here rather than left to Stop's own connection
	// teardown, because SyncFrom's connection was never registered in
	// n.conns — it is a dedicated, ephemeral socket this call opened, not
	// one of the long-lived gossip connections Stop already closes (see
	// unregister). Before this, a SyncFrom stuck on an unbounded read was
	// the one thing left in n.wg (syncLoop holds an entry for the whole
	// time it is blocked here) that Stop's wg.Wait could still hang on
	// indefinitely — unrelated to the accept-path fix, which bounded
	// the *inbound* handshake and reply paths but never touched this
	// outbound one.
	go func() {
		select {
		case <-ctx.Done():
		case <-n.quit:
		case <-closed:
			return
		}
		conn.Close()
	}()

	// The handshake is not optional even here. Until the network ids match,
	// nothing this peer says is worth parsing (M2-G6).
	if err := conn.SendDeadline(KindHello, n.Engine.Hello().MarshalHello(),
		clampDeadline(time.Now().Add(writeTimeout), attemptDeadline)); err != nil {
		return err
	}
	conn.SetReadDeadline(clampDeadline(time.Now().Add(15*time.Second), attemptDeadline))
	kind, payload, err := conn.Receive()
	if err != nil {
		return err
	}
	if kind != KindHello {
		return fmt.Errorf("%w: peer answered a handshake with %s", ErrWrongProtocol, kind)
	}
	hello, err := UnmarshalHello(payload)
	if err != nil {
		return err
	}
	if hello.NetworkID != n.Engine.Chain.NetworkID() {
		return ErrWrongNetwork
	}

	// The body cache outlives the connection, and that is its whole purpose.
	// A reorg has to be applied whole, so a severed link discards every body it
	// had already carried unless something remembers them across attempts —
	// and the node, not the socket, is the thing that lives long enough.
	src := n.bodyCache().Source(&connSource{
		t:     dedicatedTransport{conn: conn},
		hello: hello, params: n.Engine.Chain.Params(), deadline: attemptDeadline,
	})
	res, err := sync.Run(n.Engine.Chain, n.Engine.Engine, src, syncBatch)
	return n.applySyncResult(addr, res, err, attemptDeadline)
}

// applySyncResult lands what an attempt achieved and reports what it cost.
//
// Factored out of SyncFrom because syncOverGossip must do all of it
// identically: which socket carried the request changes nothing about what the
// blocks that arrived mean. Leaving it inlined would have made the shared
// connection a second, quietly divergent copy of the rules below.
//
// attemptDeadline is the caller's own whole-attempt budget, needed only to
// classify the error on the way out (see classifyAttemptError). A zero value
// means "no budget was set", and then nothing is reclassified.
func (n *Node) applySyncResult(addr string, res *sync.Result, err error, attemptDeadline time.Time) error {
	// Progress first, error second. `sync.Run` returns both — blocks that
	// landed before the link died are on disk — so everything below is done
	// for a failed attempt that made progress exactly as for a clean one.
	if res != nil && res.HeadersWithheld {
		// The sync half of the slow-clock stall. This pass did nothing and
		// scored nobody, which is right — but "nothing to do because the peer's
		// chain starts ahead of this node's clock" is a different fact from
		// "nothing to do because this node is up to date", and only the first
		// one means the node will stay behind. Charged to the peer that served
		// the range, so the same breadth evidence separates a slow local clock
		// from one peer with a fast one.
		n.Engine.RecordSyncWithheld(addr, res.WithheldSkewSeconds)
	}
	if res != nil && res.Applied > 0 {
		// Retention has done its job: these blocks are on the chain now, and
		// holding a second copy of them is waste.
		n.bodyCache().Reset()
	}
	if res != nil && (res.Applied > 0 || len(res.Undone) > 0) {
		// The two halves the gossip path does in `applyToPool`, in the same
		// order and for the same reasons.
		//
		// Readmit first: the certificates in blocks a reorg *removed* have to
		// go back, or they are lost from the chain and the pool at the same
		// moment. That branch used to sit inside `if res.Adopted` and could
		// never run at all, because `sync.Run` never populated `Undone`.
		//
		// Then bring the pool into line with what was applied, or the miner's
		// next template re-includes a certificate this node has just committed
		// and B3 refuses the block — a node that catches up and then cannot
		// mine. `Rescreen` rather than a replay of every applied block: the
		// screen is a function of state, not of blocks, so one pass covers a
		// catch-up of any length.
		//
		// Order, because doing it the other way round can readmit a certificate
		// the adopted blocks contain.
		var readmit []*types.Certificate
		for _, blk := range res.Undone {
			readmit = append(readmit, blk.Certs...)
		}
		n.Engine.Chain.Read(func(v chain.View) {
			if len(readmit) > 0 {
				n.Engine.Pool.Readmit(readmit, v.State, v.Height)
			}
			n.Engine.Pool.Rescreen(v.State, v.Height)
		})
	}
	if err != nil {
		return n.classifyAttemptError(err, attemptDeadline)
	}
	if res.Adopted {
		n.log("synced %d blocks from %s (heights %d..%d)", res.Applied, addr, res.From, res.To)
		n.Peers.Adjust(addr, ScoreUsefulMessage)
	}
	return nil
}

// classifyAttemptError separates "this attempt ran out of its own time budget"
// from "this peer failed us", for the two facts that are otherwise identical
// at the wire: both arrive as a read that did not complete.
//
// The test is the deadline itself, evaluated at the moment the error is
// observed. Every per-read deadline inside the attempt is clamped to
// attemptDeadline (clampDeadline) and the watcher closes the socket outright
// when it fires, so once the budget has passed, a transport failure is the
// expiry — there is nothing else left that could have produced one, and the
// clamp guarantees no read got a window reaching beyond it.
//
// It rewraps rather than replaces: %w on the inner error keeps ErrTransport
// and ErrBodyUnavailable matching, so SyncPenalty(err) is unchanged (zero on
// this path, by the ErrTransport exemption at SyncPenalty's guard) and every
// caller that tests for a transport fault still sees one. All that moves is
// which sentence an operator reads first.
//
// A transport failure *before* the deadline is left exactly as it was: a peer
// that really did disappear mid-attempt must not read as an expiry.
func (n *Node) classifyAttemptError(err error, attemptDeadline time.Time) error {
	if attemptDeadline.IsZero() || !errors.Is(err, ErrTransport) {
		return err
	}
	if time.Now().Before(attemptDeadline) {
		return err
	}
	// What the attempt did land, not what it was asked for: an aborted attempt
	// keeps its extending prefix (sync.Fetch's salvage), so this is the number
	// the next attempt starts from and the one an operator needs to see
	// advancing across a run of expiries.
	var height uint64
	n.Engine.Chain.Read(func(v chain.View) { height = v.Height })
	return fmt.Errorf("%w after reaching height %d: %w", ErrAttemptExpired, height, err)
}

// ErrNoSyncRoute marks a candidate whose connection went away between being
// chosen and being asked. Not the peer's fault and not scored: a disconnect is
// the transport's business, and the next rotation simply will not see it.
var ErrNoSyncRoute = fmt.Errorf("%w: the connection this peer was reached on is gone", ErrTransport)

// syncMailbox is one sync request waiting for its answer on a shared gossip
// connection.
//
// One at a time, and that is not a limitation: sync.Run issues one request and
// waits for it before issuing the next, so a second concurrent request on one
// connection would be a bug rather than a case to support. Registering a
// second one is refused rather than overwriting the first, so the bug would
// surface as a failed attempt instead of as an answer delivered to the wrong
// waiter.
type syncMailbox struct {
	want  MessageKind
	match func([]byte) bool
	// ch is buffered so deliverSyncResponse never blocks the serve goroutine
	// that is reading the peer's socket.
	ch chan []byte
}

// deliverSyncResponse hands a frame to a sync attempt waiting for it on this
// connection, reporting whether it took it.
//
// Called from serve before Engine.Handle. It claims a frame only when an
// attempt is registered on this exact connection, waiting for this exact kind,
// and - for a body chunk - for this exact block and index. Anything else is
// left to the gossip handler, which is what keeps an unsolicited frame scored
// exactly as it was before sync could run over this socket at all.
func (n *Node) deliverSyncResponse(addr string, kind MessageKind, payload []byte) bool {
	n.mu.Lock()
	m := n.syncInbox[addr]
	n.mu.Unlock()
	if m == nil || m.want != kind {
		return false
	}
	if m.match != nil && !m.match(payload) {
		return false
	}
	select {
	case m.ch <- payload:
		return true
	default:
		// The waiter already has an answer, or has given up and not yet
		// deregistered. Either way this frame answers nothing, so it goes to
		// the gossip handler to be judged there rather than being dropped.
		return false
	}
}

// sharedTransport is sync over the gossip connection a peer opened to this
// node, for a peer this node cannot dial.
//
// The write half is ordinary: Conn.SendDeadline takes the connection's write
// mutex, so a request interleaves with gossip writes safely. The read half is
// the whole difference. serve owns the only read on this socket, so this side
// never touches the connection at all - it registers a mailbox, and serve
// routes the matching frame into it.
//
// That inversion removes machinery rather than adding it. SyncFrom needs a
// watcher goroutine to close its socket, because a read parked in the kernel
// cannot be interrupted by a deadline; here the wait is on a channel, so the
// attempt deadline and n.quit are just two more cases in one select - and
// closing the connection on a timeout would be wrong anyway, since it is the
// peer's gossip link, not a socket this attempt owns.
type sharedTransport struct {
	n    *Node
	conn *Conn
}

// roundTrip arms the mailbox **before** the request leaves, and that order is
// the whole correctness argument on this side.
//
// serve reads this socket on another goroutine. Sending first and registering
// afterwards leaves a window in which the answer arrives, finds no mailbox, is
// handed to Engine.Handle as unsolicited, and is gone - after which this
// request waits out its full window and the attempt fails. The window is a few
// instructions wide, so it is invisible against a loopback peer and entirely
// ordinary under a GC pause or a preemption of this goroutine. Measured: a 5ms
// pause inserted between the two reproduces the freeze's own symptom exactly - a
// listening node stuck at height 0 next to a peer at 12 for the full deadline.
// Arming first removes the window rather than narrowing it.
func (t sharedTransport) roundTrip(ask MessageKind, payload []byte, want MessageKind, match func([]byte) bool, deadline time.Time) (MessageKind, []byte, error) {
	addr := t.conn.Addr
	m := &syncMailbox{want: want, match: match, ch: make(chan []byte, 1)}

	t.n.mu.Lock()
	if t.n.syncInbox == nil {
		t.n.syncInbox = map[string]*syncMailbox{}
	}
	if _, busy := t.n.syncInbox[addr]; busy {
		t.n.mu.Unlock()
		return 0, nil, errors.New("p2p: a sync request is already outstanding on this connection")
	}
	t.n.syncInbox[addr] = m
	t.n.mu.Unlock()
	defer func() {
		t.n.mu.Lock()
		// Deregistered by identity, not by key. The busy guard makes a second
		// registration impossible today; checking identity means a later second
		// caller would lose its own answer rather than have this one silently
		// unregister a mailbox it does not own.
		if t.n.syncInbox[addr] == m {
			delete(t.n.syncInbox, addr)
		}
		t.n.mu.Unlock()
	}()

	if err := t.conn.SendDeadline(ask, payload, clampDeadline(time.Now().Add(writeTimeout), deadline)); err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}

	// The per-request window is the same twenty seconds a dedicated
	// connection's read gets, clamped to the whole attempt's own deadline for
	// the same reason: a per-request window that can be reset without limit is
	// not a bound on the attempt.
	timer := time.NewTimer(time.Until(clampDeadline(time.Now().Add(20*time.Second), deadline)))
	defer timer.Stop()
	select {
	case answer := <-m.ch:
		return want, answer, nil
	case <-timer.C:
		return 0, nil, errors.New("p2p: peer never answered the request")
	case <-t.n.quit:
		return 0, nil, ErrTransport
	}
	// A connection that dies *after* the request went out is not signalled
	// here: the wait simply runs out its window and the attempt ends. That
	// costs one window, once, and it is not scored (SyncPenalty ignores a
	// timeout), so it is accepted rather than plumbed - a close signal on Conn
	// would reach into the transport for a bounded stall.
}

// connFor returns the live connection to an address, or nil.
func (n *Node) connFor(addr string) *Conn {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.conns[addr]
}

// syncOverGossip runs one sync attempt against a peer this node cannot dial,
// over the connection that peer opened to it.
//
// This is the half of candidacy that used to be missing. A peer behind NAT, or
// one simply started without a listen address, advertises none (wire.md 7
// MUSTs that), so SyncFrom has nothing to dial - and this is what that costs:
// the node stops at the first block it has to pull rather than receive,
// silently, for as long as its peers are all peers that dialled it.
//
// **Why this is not a new eclipse surface.** An inbound peer has told this node
// less about itself than one this node chose to dial, and candidacy is where
// that difference could matter. Three things bound it, and none of them is new:
//
//   - Candidacy decides who is asked, never what is believed. Every header is
//     re-derived against the difficulty rule and its proof of work before a
//     single body is fetched (sync.ValidateHeaders), exactly as on the dialled
//     path, so a hostile candidate cannot make this node adopt anything.
//
//   - What a liar can do is waste attention, and rotation bounds that:
//     least-recently-tried selection means one round trip per candidate per
//     rotation, and the number of inbound candidates is capped by MaxInbound
//     and by the listener's per-source bound (wire.md 11) - the same caps that
//     already bound how many inbound sockets an attacker may hold. Being asked
//     for headers is strictly less than being connected, which he already is.
//
//     Two claims, separated here because the rotation's liveness set turns on
//     the difference. A cap
//     on the candidate set bounds the attacker's cost per cycle; it says
//     nothing on its own about whether any given candidate is *reached* inside
//     one, and that needs the service rate - one candidate per SyncInterval.
//     A cycle is therefore len(candidates) * SyncInterval, at most
//     (MaxInbound + 2*MaxOutbound) * SyncInterval = 144 s at the shipped
//     values, and every candidate whose connection lasts that long is reached
//     within it. That qualifier is load-bearing and is the premise this
//     sentence would otherwise hide in its turn: a reserve-charged inbound
//     slot is closed after DefaultInboundProbation (90 s) plus at most one
//     15 s probation sweep, so it lives 90-105 s and does NOT outlast a
//     worst-case cycle. See the disconnect residual in
//     docs/adversarial/sync.md 7. That second half held
//     only for a peer whose candidacy never lapsed until the prune above was
//     rebound to the tip set; the cap named here sat more than three times
//     past the point where it stopped holding for one that did.
//
//     The cycle is written against the whole connection set rather than
//     against MaxInbound because MaxInbound does not bound the inbound count
//     on its own: register's gate reads len(n.conns), which holds inbound and
//     outbound together, and there is no separate inbound counter. So the
//     bound available here is the total, MaxInbound + 2*MaxOutbound = 48
//     (engine.go says the same, for the same reason), and the sentence above
//     naming MaxInbound is describing the intent of the cap rather than a
//     quantity anything measures. The listener's per-source bound is what
//     prices reaching that total across address groups (wire.md 11).
//
//   - Ban and score reach this path *better* than the dialled one. Gossip
//     scores the connection address; an undialable peer's rotation key, ban
//     check and penalty are all that same address, so misbehaviour lands on the
//     identity that committed it instead of on an advertised name that never
//     scored anything (I5).
//
// The accepted cost: an inbound-only peer contributes nothing to this node's
// long-term topology - it is not in the peer store and cannot be re-reached
// after the socket dies - so a node whose *only* candidates are inbound is
// still one restart away from having none. That is the undialable-socket
// question and the discovery decision, not something this change can carry.
func (n *Node) syncOverGossip(t PeerTip) error {
	conn := n.connFor(t.Conn)
	if conn == nil {
		return ErrNoSyncRoute
	}
	// The same refusal SyncFrom makes before its first byte: a banned identity
	// does not get served by re-arriving on a socket the address-keyed filter
	// cannot see through.
	if n.Peers.BannedKey(conn.PeerKey) {
		return ErrIdentityBanned
	}

	timeout := n.SyncAttemptTimeout
	if timeout <= 0 {
		timeout = syncAttemptTimeout
	}
	attemptDeadline := time.Now().Add(timeout)

	// No handshake. This connection completed one when it was accepted - it is
	// where t.Height and t.Work came from - and Engine.OnHello refuses a second
	// one on the same connection as a protocol violation, so sending another
	// here would have this node ban the peer for its own request.
	src := n.bodyCache().Source(&connSource{
		t:        sharedTransport{n: n, conn: conn},
		hello:    Hello{Height: t.Height, Work: t.Work.Bytes()},
		params:   n.Engine.Chain.Params(),
		deadline: attemptDeadline,
	})
	res, err := sync.Run(n.Engine.Chain, n.Engine.Engine, src, syncBatch)
	return n.applySyncResult(t.Conn, res, err, attemptDeadline)
}

// bodyCache returns this node's retention across sync attempts, creating it on
// first use so a Node built by any route has one.
func (n *Node) bodyCache() *sync.BodyCache {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.syncBodies == nil {
		n.syncBodies = sync.NewBodyCache()
	}
	return n.syncBodies
}

// connSource answers header and body requests over either transport below.
//
// Every response is checked against what was asked for. A peer that answers a
// header request with headers from somewhere else, or a body request with a
// different block, is lying rather than merely unhelpful. On a dedicated
// connection there is no ambiguity about which request an answer belongs to,
// because nothing else is on the socket; on a shared one that ambiguity is
// real, and the two guards below answer it differently.
//
// chunkAnswers removes it: a chunk carries the block id and index the request
// named, so a frame answering a different block is not claimed. headersAnswer
// removes nothing and cannot - there are no request ids, so nothing
// distinguishes one headers response from another, and it checks only that
// the payload decodes. It is justified on cost rather than on matching: a
// malformed frame it declined to claim reaches the one handler that scores it
// (wire.md 6, 10.2). Headers matching on a shared connection is irreducibly
// ambiguous, and saying so here is what stops a reader inferring otherwise.
type connSource struct {
	// t is how a request leaves and an answer comes back. Two implementations:
	// a dedicated connection this node dialled (dedicatedTransport), and the
	// gossip connection an undialable peer opened to this node
	// (sharedTransport). Everything above this line — what is asked for, and
	// every check on what comes back — is identical either way, which is the
	// point of splitting only the transport out.
	t      syncTransport
	hello  Hello
	params *params.Params
	// deadline is the whole SyncFrom attempt's own absolute deadline. await
	// clamps every per-read deadline it sets to this, rather than blindly
	// extending it on every loop iteration — see SyncFrom's watcher comment
	// for why that clamp, not just an external forced expiry, is what
	// actually closes the whole-attempt-deadline race.
	deadline time.Time

	mu gosync.Mutex
}

func (s *connSource) Tip() (uint64, u256.U256) {
	return s.hello.Height, u256.FromBytes(s.hello.Work)
}

func (s *connSource) Headers(from uint64, count uint32) ([]types.Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kind, payload, err := s.t.roundTrip(KindGetHeaders,
		GetHeaders{From: from, Count: count}.MarshalGetHeaders(),
		KindHeaders, headersAnswer, s.deadline)
	if err != nil {
		return nil, err
	}
	if kind != KindHeaders {
		return nil, fmt.Errorf("p2p: expected headers, got %s", kind)
	}
	return UnmarshalHeaders(payload)
}

func (s *connSource) Body(id types.Hash) (*types.Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A body travels as chunks (wire.go): request each in turn, learn the
	// total from the first, and hold the peer to complete consistency — any
	// chunk that disagrees with the transfer it continues fails the fetch.
	var body []byte
	for chunk, total := uint32(0), uint32(1); chunk < total; chunk++ {
		kind, payload, err := s.t.roundTrip(KindGetBlock,
			GetBlock{ID: id, Chunk: chunk}.MarshalGetBlock(),
			KindBlock, chunkAnswers(id, chunk), s.deadline)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTransport, err)
		}
		if kind != KindBlock {
			return nil, fmt.Errorf("p2p: expected a block chunk, got %s", kind)
		}
		c, err := UnmarshalBlockChunk(payload)
		if err != nil {
			return nil, err
		}
		if chunk == 0 {
			total = c.Total
		}
		if c.ID != id || c.Chunk != chunk || c.Total != total {
			return nil, fmt.Errorf("p2p: block chunk continues a different transfer")
		}
		body = append(body, c.Data...)
		if len(body) > s.params.BlockByteCapacity {
			return nil, fmt.Errorf("p2p: chunked block exceeds the consensus byte capacity")
		}
	}
	return types.UnmarshalBlock(body, s.params)
}

// syncTransport carries one sync request and brings back one answer.
//
// `match` is the caller's statement of which frame would answer *this*
// request. It is advisory: a dedicated connection has no ambiguity about which
// request an answer belongs to and ignores it, keeping that path byte-for-byte
// what it was. A shared connection has nothing but ambiguity, and match is
// what removes it.
type syncTransport interface {
	roundTrip(ask MessageKind, payload []byte, want MessageKind, match func([]byte) bool, deadline time.Time) (MessageKind, []byte, error)
}

// headersAnswer reports whether a KindHeaders frame could answer a headers
// request at all, which on a shared connection means only: does it decode.
//
// There are no request ids (wire.md 12), so nothing distinguishes one headers
// response from another and the only thing this can check is well-formedness -
// but checking it is not optional. wire.md 6 is normative: a headers frame
// "MUST still be decoded, so that a malformed one is scored as invalid", and
// Engine.Handle's KindHeaders case is the only place that charges
// ScoreInvalidMessage for one. Claiming an undecodable frame here would divert
// it from that case, and SyncPenalty charges nothing for an unmarshal error -
// so a malformed headers frame would become free for as long as any sync
// request is outstanding on the connection. Refusing it leaves it to the
// gossip handler, which is where it gets scored.
//
// This is the same rule chunkAnswers already applies to a body chunk, and the
// asymmetry between them was the hole: the cost class was closed on one path
// and open on the other.
func headersAnswer(payload []byte) bool {
	_, err := UnmarshalHeaders(payload)
	return err == nil
}

// chunkAnswers reports whether a KindBlock frame answers this exact chunk
// request.
//
// It exists for the shared connection, where the same socket also carries the
// gossip body-fetch path's chunks. Claiming a frame that answers a *different*
// block would take a chunk away from Engine.OnBlockChunk — so the claim is
// narrowed to the id and index this request named, and every other chunk falls
// through to the gossip handler and is scored there exactly as before.
//
// A malformed payload matches nothing: an undecodable frame cannot be shown to
// answer anything, and letting it through to the gossip handler is where it
// gets scored.
func chunkAnswers(id types.Hash, chunk uint32) func([]byte) bool {
	return func(payload []byte) bool {
		c, err := UnmarshalBlockChunk(payload)
		return err == nil && c.ID == id && c.Chunk == chunk
	}
}

// dedicatedTransport is sync over a connection this node dialled for it.
type dedicatedTransport struct{ conn *Conn }

// roundTrip sends, then reads until the expected kind arrives. Send-then-wait
// is safe here and only here: this goroutine owns the only read on this socket,
// so no answer can be consumed before it starts reading. match is ignored for
// the same reason - there is nothing else on this socket to confuse it with.
func (d dedicatedTransport) roundTrip(ask MessageKind, payload []byte, want MessageKind, _ func([]byte) bool, deadline time.Time) (MessageKind, []byte, error) {
	if err := d.conn.SendDeadline(ask, payload, clampDeadline(time.Now().Add(writeTimeout), deadline)); err != nil {
		return 0, nil, err
	}
	return d.await(want, deadline)
}

// await reads until the expected kind arrives, tolerating the gossip a peer may
// push down the same socket before answering.
func (d dedicatedTransport) await(want MessageKind, deadline time.Time) (MessageKind, []byte, error) {
	for attempts := 0; attempts < 16; attempts++ {
		// Clamped to the whole attempt's own deadline, not just
		// a fresh 20s window, so this reset can never silently extend a read
		// past the attempt's budget — see SyncFrom's watcher comment.
		d.conn.SetReadDeadline(clampDeadline(time.Now().Add(20*time.Second), deadline))
		kind, payload, err := d.conn.Receive()
		if err != nil {
			return 0, nil, err
		}
		if kind == want {
			return kind, payload, nil
		}
		// Anything else on this connection is unsolicited and ignored: the
		// gossip loop on the other connection is where that belongs.
	}
	return 0, nil, errors.New("p2p: peer never answered the request")
}
