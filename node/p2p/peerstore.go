package p2p

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Peer management: scoring, diversity, and a store that survives restart.
//
// Eclipse resistance is the property this file exists for (M2-G4). An attacker
// who monopolises a victim's connections controls its whole view — it can feed
// it a private fork, hide certificates, and be its entire network. Three
// defences, all cheap now and expensive to retrofit:
//
//   - **Address diversity.** Outbound connections are spread across distinct
//     /16 networks, so a thousand addresses in one hosting range count once.
//   - **Bounded inbound per source.** A single origin cannot fill the inbound
//     slots and crowd out everyone else.
//   - **A persisted peer store.** A node that rebooted into a blank slate would
//     take whatever peers it was handed next, which is exactly the moment an
//     attacker wants. Known-good peers survive a restart.

// Score thresholds. A peer that misbehaves is disconnected rather than
// tolerated: gossip only works if the cost of sending garbage lands on the
// sender.
const (
	// ScoreInvalidMessage is charged for a message that fails to decode or
	// fails the V-rules. It is the main defence against a validation-cost
	// denial of service.
	ScoreInvalidMessage = -20
	// ScoreProtocolViolation is charged for a peer that breaks the protocol
	// itself — an unexpected message, a bad handshake, an oversized frame.
	ScoreProtocolViolation = -50
	// ScoreUnservedBody prices a block a peer *volunteered* and then did not
	// back: it announced the block, this node asked for the body inside the
	// window, and the window closed with nothing. Body availability is
	// consensus, so a peer that announces what it cannot serve is wasting
	// everyone's time, and the announcement is the obligation that makes
	// "nothing arrived" chargeable at all.
	//
	// It deliberately does **not** price a question this node asked and got no
	// answer to. The axis is who initiated, not what was observed. Where the
	// peer volunteered there is an obligation and a clock; where this node
	// asked there is neither — only an error value, and `connSource.Body`
	// flattens every round-trip failure into `ErrTransport`, so a peer that
	// serves nothing on the request path is indistinguishable from a link that
	// died mid-serve. Request-path withholding is therefore carried by
	// rotation rather than by score (`docs/adversarial/sync.md` §5: "Wasted
	// round trips per rotation | Nothing, and nothing should"), deliberately
	// unscored — the cost is one wasted attempt per rotation cycle, and the
	// alternative bans the honest bootstrap that a catching-up node depends on.
	//
	// The reachable charge on the request path is a peer that served bytes
	// that were a lie; see `SyncPenalty` (node/p2p/syncdriver.go).
	ScoreUnservedBody = -10
	// ScoreUsefulMessage rewards a message that turned out to be new and valid.
	ScoreUsefulMessage = 1
	// ScoreFutureBlock is charged for a block dated beyond the future-time
	// limit: nothing at all, deliberately.
	//
	// The future side of the time rule is *not* a validity rule (R1-H2,
	// docs/ARCHITECTURE.md §12). Whether a block is too far ahead is a fact
	// about the receiver's wall clock, not about the block, and two nodes
	// whose clocks differ by a second will disagree about the same header at
	// the boundary. Charging for it would let an attacker with a fast clock
	// score down every honest relay on the network by doing nothing but
	// forwarding ordinary blocks — and would punish the peer for this node's
	// clock skew. A withheld block is neither accepted nor an offence; it is
	// early. The constant exists so that the third state is named at the call
	// site rather than being an unexplained literal zero.
	ScoreFutureBlock = 0
	// ScoreExcessRequest is charged for asking this node to serve something
	// again, faster than the answer it would get can have changed.
	//
	// It exists because cheap is not the same as free, and the asymmetry is not
	// only CPU: a get-peers frame is 5 bytes and its answer is up to 1.2 KB, so
	// an unpriced request is a ~240x bandwidth amplifier however fast the
	// selection becomes. Memoizing bounds what one request costs this node in
	// CPU; charging for it is what makes a flood of them terminate.
	//
	// Milder than ScoreInvalidMessage on purpose. The peer is not sending
	// something wrong - its timer is fast, or it reconnected and asked again -
	// so the charge is sized to end a flood in about 20 frames while leaving an
	// implementation that asks an order of magnitude more often than
	// GetPeersInterval a long way from a ban. A peer that keeps flooding
	// reaches the threshold regardless: the charge does not decay per request.
	ScoreExcessRequest = -5
	// ScoreBanThreshold is the score at which a peer is dropped.
	ScoreBanThreshold = -100
	// ScoreFloor bounds how far a score can sink, symmetric with the ceiling.
	// A ban at the threshold is a state; a score of minus infinity is a pit.
	ScoreFloor = -200
	// ScoreCeiling bounds accumulated goodwill, so a peer cannot bank a long
	// history of good behaviour and then spend it on an attack.
	ScoreCeiling = 100
	// ScoreUnservedBodyFloor bounds how far the unserved-body charge may sink a
	// peer's score when the unserved announcement was a genuine TIP-EXTENSION.
	// It sits above ScoreBanThreshold, so a run of such charges cannot on its
	// own ban a peer (I8-H2). Applied by the reap only for atTip announcements
	// (announcedBody.atTip); an orphan/ghost is charged unbounded and still bans.
	//
	// ScoreUnservedBody prices "announced and would not serve", but a victim
	// cannot tell an announcer that will not serve from an honest one that could
	// not. I8-H2: an honest miner whose OnGetBlock refused a legitimate request
	// only because a THIRD PARTY drained its node-wide reply budget — the shared
	// `connSet × BlockByteCapacity` ceiling, third-party drainable and, on a
	// small network, barely above the per-peer budget it backs — could be driven
	// to a permanent, on-disk ban at a victim it never contacted. That case is a
	// tip-extension: an honest miner announces a block extending the tip, which
	// the difficulty gate forces to carry real proof-of-work, so it is expensive
	// to mint and cannot be floored cheaply. Bounding it costs the attacker its
	// ban and costs the network nothing it can measure.
	//
	// An orphan/ghost announcement is the opposite: cheap to mint (max-target,
	// unheld parent), third-party floodable, and the reap ban is its ONLY
	// terminator. So the bound is deliberately NOT applied there — it would
	// disarm the ghost-flood defence the ghost-flood tests guard. And every
	// attributable penalty — ScoreInvalidMessage, ScoreProtocolViolation,
	// SyncPenalty (a peer that served bytes that were a lie), ScoreExcessRequest
	// — is unbounded everywhere and still reaches ScoreBanThreshold. A peer at
	// this floor that then earns an attributable charge still crosses into a ban
	// on that charge's account, not this one. So no genuine ban is weakened.
	ScoreUnservedBodyFloor = ScoreBanThreshold / 2
)

// MaxPeers bounds how many addresses the store will ever hold.
//
// Without a cap, a single unsolicited `peers` frame grows the store — and the
// peers.json it persists — without bound: nothing correlates a `peers` frame
// to a request (wire.md §12 removes request ids), so a peer may send one at
// any time whether or not it was asked, and OnPeers (engine.go) calls Add for
// every address in it.
//
// This node now does send KindGetPeers — Node.askForPeers, once per
// GetPeersInterval, to one outbound peer — so the older and stronger
// form of this sentence, that every arriving `peers` frame is unsolicited *by
// construction*, no longer holds. The cap is unaffected, and that is the
// point: it never rested on the asking, only on the fact that arrival is the
// sender's decision. See docs/decisions/networking.md §12.
//
// The number is policy, not protocol. Flood gossip is "comfortable into the
// low thousands of nodes" (docs/decisions/networking.md §5, an estimate rather
// than a measurement); MaxPeers is sized to hold several times that, so a
// well-connected node has real room to keep addresses spread across many /16s,
// while still being a bounded, evictable structure rather than the unbounded
// map it replaces. Bitcoin Core's addrman takes the same shape at a much larger
// scale — a hard cap in the tens of thousands across its new/tried tables, with
// worst-first eviction when full — and this is that principle, sized down for
// a pre-genesis network rather than copied at its constant.
const MaxPeers = 4096

// MaxFallbackPerGroup bounds how many of SelectDiverse's slots a single
// address group may take once the fallback (below) runs.
//
// Two, not one: the fallback exists because the store sometimes cannot fill n
// slots one-per-group, and refusing to fill them at all is its own eclipse risk
// (wire.md §11's "SHOULD keep dialling toward its outbound target"). But an
// unconstrained fallback hands every remaining slot to whichever addresses sort
// best, which — on a thin store, exactly the state in which an eclipse is
// cheapest — can be almost all of them. Two per group caps that
// concentration without making the fallback pointless on a store that
// genuinely has few groups to offer.
const MaxFallbackPerGroup = 2

// MaxPerSource bounds how many of SelectDiverse's slots may go to addresses
// this node learned from one and the same gossip source (Peer.Src).
//
// This is the constraint address diversity cannot supply on its own, and the
// reason is arithmetic rather than judgement: an address in a gossip frame is
// four bytes an attacker invents, so *n* invented addresses are *n* distinct
// /16 groups for the price of one frame. Measured against the store as it
// stood before this bound: twenty invented IPv4 addresses in twenty distinct
// /16s, delivered in one unsolicited `peers` frame, took **8 of 8** outbound
// slots from a victim that already knew three honest peers — the same result,
// at the same price, that requiring an IP host was supposed to have closed.
// Requiring an IP host only changes which characters the junk is spelled with.
//
// What an attacker cannot invent is the address it is speaking *from*: that
// one is a real TCP connection this node accepted or dialled, and widening it
// means acquiring real addresses in distinct /16s. Bounding a single source's
// share therefore prices the attack in the one resource that is not free.
// It is the same signal, and the same reasoning, that
// docs/decisions/networking.md §5 already settled on for the accept path —
// "choosing the victim by address group rather than by age alone. Group share
// is the one signal that does not invert" — applied to the dial path.
//
// Two, matching MaxFallbackPerGroup: enough that a node bootstrapped from a
// single honest peer still fills slots from what that peer knows, low enough
// that no one teller decides who this node talks to. Addresses with an empty
// Src are exempt: they were not gossiped to this node at all (see Peer.Src),
// so there is no teller to bound.
//
// Bitcoin Core's addrman reaches the same place by a different route — a new
// address's bucket is chosen from a hash of the *source* group, so everything
// one peer gossips lands in a bounded slice of the table rather than across
// all of it. This is that property, expressed at selection rather than at
// insertion, which is where a store this size can carry it.
const MaxPerSource = 2

// Peer is a known network participant.
type Peer struct {
	Addr string `json:"addr"`
	// Score accumulates behaviour. It is deliberately a small integer with
	// obvious arithmetic rather than a decaying float: a scoring system nobody
	// can reason about under load is a scoring system that gets disabled.
	Score int `json:"score"`
	// LastSeen is when this peer was last connected to successfully.
	LastSeen int64 `json:"last_seen"`
	// Failures counts dials that did not answer, so a peer that has never once
	// answered is deprioritised without being forgotten: evictionTier pairs
	// Failures > 0 with LastSeen == 0 to put such a peer in tier 0, and
	// worsePeer breaks a score tie on more failures — it is a victim
	// comparator, so more failures means evicted sooner.
	//
	// It had an Attempts counterpart, incremented by MarkConnected and
	// MarkFailed and read by nothing — no rule, no test, no document, no part
	// of the wallet UI. The deprioritisation this comment describes was always
	// Failures and LastSeen doing the work; Attempts was the residue of a ratio
	// nobody ever computed. A number written on every dial and consulted by
	// nothing invites exactly the reading it cannot support, which is what a
	// counter nobody read already cost this package once. A count of
	// *successful* connections would be a reasonable thing to expose, and it
	// needs a reader and somewhere that names it; `attempts` had neither. A
	// peers.json written by an older build still loads, because the loader
	// takes what it knows and ignores the rest.
	Failures int `json:"failures"`
	// Src is the address group (AddressGroup) of the peer that gossiped this
	// address, or empty for an address this node did not learn from gossip:
	// a bootstrap address the operator supplied, a socket this node actually
	// connected to, or an entry restored from a peers.json written before this
	// field existed.
	//
	// It is the one thing about a gossiped address that is not free. The
	// address itself costs an attacker nothing — any 4 bytes is a syntactically
	// valid IPv4 host, and 65,536 of them are 65,536 distinct /16 diversity
	// groups — so address diversity alone prices nothing when the addresses are
	// invented rather than owned. Who *told* this node about them is a fact
	// about a real, authenticated TCP connection from a real address, and
	// bounding a single teller's share is the constraint that actually costs
	// the attacker something to widen. See MaxPerSource.
	Src string `json:"src,omitempty"`
	// observed marks an entry this node created only because it was in
	// contact with that socket — an inbound connection's accepted
	// `ip:ephemeral_port` source address — rather than because anyone asserted
	// it was a listen address. Such an entry is not a dial candidate: nothing
	// listens on an ephemeral source port, so a slot spent on it is spent on
	// an address that cannot answer, and the dial loop is serial so the loss
	// is the whole dial timeout.
	//
	// It is set by the admission path, not by the selector, because the
	// selector could only guess from the port number. The three non-strict
	// admitters — Adjust, MarkConnected, MarkFailed — name a socket this node
	// has actually been in contact with; every *dialable* address they can be
	// called with is already in the store, because it came out of
	// SelectDialTargets or SyncCandidates in the first place. So creation by a
	// non-strict caller is exactly the "observed, never claimed" case, and a
	// strict caller re-asserting the address clears the flag again (see
	// admitLocked).
	//
	// Like bootstrap and restored it is a fact about this process rather than
	// about the peer, and it is not persisted — Save skips these entries
	// outright. Persisting one would be worse than useless: the loader keeps
	// last_seen across a restart as the "this node has met it" bit, so a
	// reloaded socket would come back both dialable and proven, out-ranking
	// honest addresses on the first post-restart round.
	observed bool
	// bootstrap marks an address the operator supplied for this run. Like
	// restored it is a fact about this process rather than about the peer, and
	// it is not persisted: an operator's list is re-read from configuration
	// every start, so a file claiming to be on it proves nothing.
	bootstrap bool
	// restored marks an entry this process read out of peers.json and has not
	// since connected to. It is deliberately not persisted: it is a fact about
	// this process, not about the peer, and it is what keeps a file's claims
	// out of proven().
	restored bool
	// Seq is the order this node first learned the address, monotonic per
	// store and carried across restarts.
	//
	// It exists to break ties inside a cohort by *arrival* rather than by
	// address, which is the difference between a flood evicting itself and a
	// flood evicting what it named first. Unproven entries are
	// indistinguishable by record, so the tie-break is the whole policy there,
	// and an attacker chooses the addresses it gossips: with the address as
	// the tie-break it simply picks flood addresses that sort ahead of the
	// real ones it claimed. Arrival order is the one key it cannot pick after
	// the fact.
	Seq int64 `json:"seq,omitempty"`

	// group memoizes AddressGroup(Addr): the diversity group this entry
	// occupies. Unexported, so it is never written to or read from peers.json
	// - it is derived, and a derived value in an operator-editable file would
	// be a second, forgeable source of truth for the eclipse defence.
	//
	// It is a cache of a pure function of an immutable field, so it needs no
	// invalidation: Addr is the map key and never changes. It exists because
	// AddressGroup is SplitHostPort + ParseIP + IP.String - three calls that
	// allocate - and selectLocked called it up to twice per candidate per
	// request over the whole store, re-deriving the same answer for an address
	// that had not moved.
	group string
}

// diversityGroup returns the entry's memoized address group, deriving it for a
// Peer that never went through indexLocked.
//
// The fallback is not defensive decoration and it is not there for a fixture
// that happens to exist today. Peer is exported and its fields are settable, so
// a Peer{Addr: x} built anywhere in this package has group == "", and reading
// that empty string as the diversity group would put every such candidate in
// one group: selectLocked's diverse pass takes one slot per group, so the
// answer collapses to a single address plus whatever MaxFallbackPerGroup lets
// back in. That is a silent failure of the selector, not a loud one, and it is
// the reason the empty case is answered rather than trusted. The wrong state is
// not representable away - nothing can stop a struct literal - so it is
// answered here instead.
//
// The fallback does not write: entries in the store are read under an RLock by
// selectLocked, and a lazy write there would be a data race on the eclipse
// defence's own input.
func (p *Peer) diversityGroup() string {
	if p.group == "" {
		return AddressGroup(p.Addr)
	}
	return p.group
}

// Banned reports whether the peer has scored below the threshold.
func (p Peer) Banned() bool { return p.Score <= ScoreBanThreshold }

// PeerStore holds known peers and persists them.
type PeerStore struct {
	mu    sync.RWMutex
	path  string
	peers map[string]*Peer
	// cohorts indexes peers by the group their eviction cost is charged to
	// (see cohort). It holds exactly the same *Peer values as peers and is
	// maintained beside it, never derived on demand: eviction runs on the
	// admission path, which runs once per address in every unsolicited `peers`
	// frame, and rebuilding a 4096-entry index there — under the write lock
	// that Engine.Handle's own Adjust call needs for every scored message from
	// every peer — turns admission into the denial of service admission exists
	// to bound. A cohort key is fixed at creation (Src never changes, Addr
	// never changes), so the index needs no invalidation.
	cohorts map[string]map[string]*Peer
	// tier0 indexes the entries in evictionTier 0 — scored below zero, or
	// dialled and never once answered. They are given up before anything else
	// wherever they sit, so eviction has to be able to find them without
	// walking the store; keeping them in a set is what lets the common case
	// below not walk it.
	tier0 map[string]*Peer
	// nextSeq issues Peer.Seq. It resumes above the highest value loaded from
	// disk, so arrival order survives a restart.
	nextSeq int64
	now     func() time.Time

	// identityMu and identity hold live scores keyed by a peer's
	// authenticated Ed25519 identity rather than its connection address. See
	// AdjustKey. Kept separate from mu/peers rather than folded into the same
	// map: it is a different keyspace with different persistence semantics
	// (never written to path), and separating the lock keeps this store's
	// address-keyed half — dial selection, diversity, the persisted list —
	// exactly as contended as it was before.
	identityMu sync.Mutex
	identity   map[string]identityEntry

	// diverseMu guards the memoized SelectDiverse answer. It is taken *before*
	// mu and never while mu is held, so the two cannot deadlock, and it is held
	// across a rebuild on purpose: a flood arriving on many sockets at once
	// then costs one rebuild between them all rather than one each, which is
	// the case the memoisation was measured against.
	diverseMu sync.Mutex
	diverseN  int
	diverse   []string
	diverseAt time.Time
}

// DiverseCacheTTL bounds how stale the answer SelectDiverse serves may be, and
// with it how often the store-sized half of that answer is computed at all.
//
// The property this buys is the one the memo is about: after it, a get-peers frame
// buys at most a walk of the memoized list (at most MaxPeersPerResponse map
// lookups), and the work proportional to store size happens at most once per
// TTL no matter how many peers ask or how fast. The rebuild rate is bounded by
// elapsed time rather than by request count.
//
// Thirty seconds, derived from the load the node actually carries rather than
// picked round. A conforming node sends one get-peers per
// GetPeersInterval (five minutes), and the node that pays is the one with a
// saturated *inbound* set - NewNode's MaxInbound default of 32 - so the busiest
// honest serving node sees a request every ~9.4 s on average. A TTL under that
// memoizes nothing on the honest path and would bound only a flood; 30 s covers
// that gap with margin. What it costs is dissemination delay: an address this
// node learned may wait up to 30 s to enter a list that is asked for once per
// 300 s, a 10% delay on a hint the receiver has to dial to believe anyway.
// Nothing downstream is wrong if it is momentarily absent.
//
// A time bound rather than a dirty flag set by the mutators. A dirty flag is
// only as correct as the completeness of the set of writers that remember to
// set it, and this store is written from Add, AddFrom, Adjust, MarkConnected,
// MarkFailed, every eviction path and the loader; one forgotten call site there
// is an answer that is stale without bound and silently. A TTL is stale by at
// most TTL no matter which writer is added next.
const DiverseCacheTTL = 30 * time.Second

// NewPeerStore loads a peer store from disk, or creates an empty one.
func NewPeerStore(path string) (*PeerStore, error) {
	ps := &PeerStore{
		path:    path,
		peers:   map[string]*Peer{},
		cohorts: map[string]map[string]*Peer{},
		tier0:   map[string]*Peer{},
		now:     time.Now,
	}
	if path == "" {
		return ps, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ps, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*Peer
	if err := json.Unmarshal(raw, &list); err != nil {
		// A damaged peer store is not worth failing a node over — it is a
		// cache, not consensus. Start empty and rewrite it.
		return ps, nil
	}
	for _, p := range list {
		// plausibleAddr also drops anything left over from before non-IP hosts
		// were refused: a peers.json written by the old code could hold non-IP
		// hosts that used to each mint their own diversity group. Loading them
		// back unfiltered would keep that poison one restart deep even after
		// the fix landed.
		if !plausibleAddr(p.Addr) {
			continue
		}
		// Src is validated, not trusted. It is written by this node and read
		// back by it, but peers.json is an operator-visible file on disk: a
		// hand edit or a corruption that gave every entry a distinct Src would
		// make every cohort a singleton and disarm the eviction policy that
		// reads it, and one that stamped an honest peer's group onto junk
		// would hand that peer the bill. Anything that is not the output shape
		// AddressGroup produces is dropped back to "no teller", which is the
		// safe reading of an unreadable field.
		if !validGroup(p.Src) {
			p.Src = ""
		}
		// A restored score may accuse, never vouch.
		//
		// Src and Seq are already validated rather than trusted, for a reason
		// that applies verbatim to the field selection actually ranks on:
		// selectLocked sorts by Score first, and a bootstrap address the
		// operator supplied is Add-ed at Score 0. So *any* positive score a
		// file can assert sorts the whole bootstrap list behind it on the
		// first dial round after every restart — there is no "small enough"
		// retained credit, which is why this clamps to 0 rather than to some
		// fraction of the ceiling. Goodwill is re-earned online in the one
		// round it takes; it is not something a file gets to hand out.
		//
		// A negative score is kept: it costs the entry, and forgetting it
		// would make a restart a free reset for a peer this node banned
		// (TestPeerStoreSurvivesRestart). The floor is re-applied because a
		// file can also claim a score below anything Adjust can reach.
		if p.Score > 0 {
			p.Score = 0
		}
		if p.Score < ScoreFloor {
			p.Score = ScoreFloor
		}
		// The same rule reaches proven(), and clamping Score without it would
		// have left the door open under a different name.
		//
		// proven() is `LastSeen != 0 || Score > 0`, so a file that sets
		// last_seen buys evictionTier 2 whatever its score says. Tier 2 is not
		// a ranking nicety: evictOneLocked's second pass only ever takes a
		// *tier 1* victim, so a store restored entirely at tier 2 leaves the
		// operator's freshly-Added bootstrap addresses as the only entries
		// eviction can reach, and every subsequent admission spends one of
		// them — the same eclipse the score clamp closes, arrived at by
		// attrition instead of by rank. A completed connection is evidence
		// this node gathered; a file asserting one is not, so a restored entry
		// is unproven until this node connects to it again.
		//
		// LastSeen itself is kept, because erasing it costs more than it
		// saves: with Score flat and LastSeen gone, selectLocked's residual
		// key is the address — the one key an attacker picks for free — and
		// every honest node measurably spends its whole first post-restart
		// dial round on invented gossip. It is read on the dial path as a bit,
		// "has this node ever completed a connection here", never as recency,
		// so a forged last_seen buys a tie with an honestly met peer and never
		// a lead over one.
		//
		// Failures is KEPT, and the clamp it used to get is now aimed at the
		// one route that made dropping it look necessary.
		//
		// It used to be zeroed here, on the argument that a hostile file could
		// stamp the operator's own bootstrap addresses with a failure count to
		// sort them last in selectLocked and into evictionTier 0. That argument
		// is about the operator's list specifically, and AddBootstrap already
		// answers exactly that shape of forgery for the score — "the operator's
		// list is re-read from configuration outside the network on every
		// start, so it is the fresher assertion of the two" — so the failure
		// count is cleared there instead, for restored entries only, and only
		// for the addresses the operator re-supplied.
		//
		// What zeroing cost was the other direction, and it is the direction an
		// eclipse comes from: an invented address this node dialled and that
		// never answered came back after every restart indistinguishable from
		// an honest address it had never tried, ranked identically by
		// selectLocked and back in evictionTier 1 where eviction reaches it
		// last. A flood therefore only had to survive one restart to have its
		// refutation forgotten, while the honest peers it displaced did not
		// improve. Demonstrated-bad is the cheapest true thing this node knows
		// about a gossiped address, and it is the one an attacker cannot forge
		// in its own favour: a file can only ever *add* failures, which demotes
		// the entry, and it cannot subtract the ones this node wrote about
		// addresses the operator did not configure.
		//
		// A count of 0 confers no privilege, because 0 is what a brand-new
		// entry has. A negative count is not something this node ever writes,
		// so it is clamped rather than trusted.
		//
		// What persistence still carries is the address, its teller, a ban,
		// the bit that this node once met it, a refuted dial, and a *relative*
		// arrival order that is itself only as trustworthy as the file.
		p.restored = true
		if p.Failures < 0 {
			p.Failures = 0
		}
		if p.Failures > MaxStoredFailures {
			p.Failures = MaxStoredFailures
		}
		// A duplicate Addr would overwrite in peers while filing *both*
		// records in cohorts, and the orphan left behind is a live eviction
		// candidate: evicting it unindexes its own cohort entry and then
		// deletes the surviving record under that address, silently losing a
		// peer the store meant to keep, while every cohort count it inflated
		// stays wrong. peers.json is an operator-visible file and this loader
		// already assumes it may have been edited — that is what validGroup is
		// for — so the first record for an address wins and the rest are
		// dropped.
		if _, dup := ps.peers[p.Addr]; dup {
			continue
		}
		ps.peers[p.Addr] = p
		ps.indexLocked(p)
	}
	ps.renumberLocked()
	// A file written before MaxPeers existed — or edited by hand — can already
	// be over the cap. Carrying the excess forward would mean the cap only ever
	// stops future growth and never undoes past growth, which is exactly the
	// "poisons peers.json permanently" failure MaxPeers exists to close. No
	// lock: ps has not been returned to a caller yet, so nothing else can be
	// reading or writing it concurrently. Trim by sort, not by repeated
	// eviction. An over-cap file costs O(excess x n) that way, and a peers.json
	// is exactly the input that can be arbitrarily over cap: 40,000 entries
	// measured at 92 seconds of startup, which is a node that looks hung. One
	// sort of the excess is the same policy applied all at once.
	if len(ps.peers) > MaxPeers {
		ordered := make([]*Peer, 0, len(ps.peers))
		for _, p := range ps.peers {
			ordered = append(ordered, p)
		}
		sort.Slice(ordered, func(i, j int) bool {
			a, b := ordered[i], ordered[j]
			if ta, tb := evictionTier(a), evictionTier(b); ta != tb {
				return ta < tb
			}
			return worsePeer(a, a.Addr, b, b.Addr)
		})
		for _, p := range ordered[:len(ps.peers)-MaxPeers] {
			ps.unindexLocked(p)
			delete(ps.peers, p.Addr)
		}
	}
	// The per-cohort ceiling is applied to the loaded set too, for the reason
	// the cap itself is: a bound that only ever stops future growth never
	// undoes past growth, and a file written by hand — or by a build from
	// before the ceiling existed — can already be over it.
	for c, m := range ps.cohorts {
		for len(m) > MaxPerSourceStored {
			if !ps.evictWorstInCohortLocked(c) {
				break
			}
		}
	}
	return ps, nil
}

// Save writes the peer store.
//
// A node that rebooted into a blank slate would accept whatever peer set it was
// offered next, which is precisely when an eclipse is cheapest. Persisting is
// the defence.
func (ps *PeerStore) Save() error {
	if ps.path == "" {
		return nil
	}
	// Values, not pointers.
	//
	// This is what the comment here used to claim and the code did not do: it
	// copied the *pointers* under the lock and then sorted and marshalled
	// through them after releasing it, while Adjust, MarkFailed and
	// MarkConnected write those same fields from the gossip and dial
	// goroutines. The race is real — the detector reports it on
	// json.MarshalIndent against Adjust — and it went unseen because the only
	// production caller (cmd/zycordd's shutdown deferral) runs after
	// Node.Stop, so nothing is writing by then. A safety the comment asserts
	// and the code does not have is worse than neither.
	ps.mu.RLock()
	list := make([]Peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		// An observed socket is not written back. It is undialable now and it
		// would come back dialable, because observed is a fact about this
		// process and has no place in the file; and it would come back
		// *proven*, because the loader deliberately keeps last_seen across a restart
		// as the bit that says this node once met the address. See
		// Peer.observed.
		if p.observed {
			continue
		}
		list = append(list, *p)
	}
	ps.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool { return list[i].Addr < list[j].Addr })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := ps.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(ps.path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ps.path)
}

// Add records a peer address, ignoring duplicates and unusable addresses.
//
// "Unusable" now includes anything whose host is not a parseable IP: a
// non-IP host used to be admitted and then fell through AddressGroup's
// "anything unparseable" case to become its own brand-new diversity group, so
// a handful of junk strings in one `peers` frame could win every slot in
// SelectDiverse's diverse pass ahead of real peers. Nothing in
// docs/spec/wire.md §4/§7 asks a peer address to be a hostname — a listen
// address is specified only as "UTF-8, no NUL" — and every dial in this
// codebase already goes through net.Dial with an ip:port, so requiring an IP
// host here narrows what this store remembers, not the protocol.
//
// The store is also capped (MaxPeers); see admitLocked for what happens
// once it is full.
//
// Add records an address with no gossip source (Peer.Src empty): a bootstrap
// address the operator supplied, or a peer this node learned about by some
// route other than a peer telling it. Anything a peer claimed — an address in
// a `peers` frame, a `hello`'s listen address — must go through AddFrom
// instead, so the teller is recorded and MaxPerSource can bound it.
func (ps *PeerStore) Add(addr string) {
	ps.AddFrom(addr, "")
}

// AddBootstrap records an address the operator configured for this run.
//
// It is Add plus the one thing that separates the operator's list from every
// other address this node holds: it came from outside the network, so no peer
// and no file chose it. That is what earns it the first post-restart dial
// round ahead of anything peers.json merely claims this node had met —
// without it, a hostile store that sets last_seen out-ranks the whole
// bootstrap list, which is the bug this closes. The flag is per-process and
// is never written back.
//
// The admission and the flag happen under one lock hold on purpose: this is
// called from the DNS resolution goroutine, which runs concurrently with the
// dial loop, and a full store can evict a just-admitted entry between an
// unlocked AddFrom and a second lock acquisition — silently dropping the one
// bit that makes it the operator's address.
func (ps *PeerStore) AddBootstrap(addr string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if p, ok := ps.admitLocked(addr, "", true); ok {
		p.bootstrap = true
		// A restored accusation does not survive the operator re-asserting the
		// address. "A restored score may accuse, never vouch" was argued from
		// the route where the accusation is the node's own — its Save writing
		// back a ban it adjudicated online. Against the hostile file writer
		// this change assumes, the accusation is cheaper and more complete than
		// the score inflation being closed: selectLocked filters Banned()
		// *before* dialRank is consulted, so a file that writes Score =
		// ScoreFloor for every --peers address makes SelectDialTargets return
		// nothing at all. The operator's list is re-read from configuration
		// outside the network on every start, so it is the fresher assertion of
		// the two, and a file does not get to delete it from the candidate set.
		//
		// Only a *restored* negative is cleared, so a ban this process earned
		// against a bootstrap peer is untouched while the process lives, and
		// addBootstrap runs once per process so nothing can re-enter here to
		// launder one.
		//
		// The stated cost, which is real and is the price of the rule: a ban
		// this node itself adjudicated does not survive a restart for a
		// configured address. Save writes the negative score, the next load
		// restores it, and the operator re-supplying the address clears it —
		// so a peer banned for protocol violations is a dial candidate again
		// on the next start. That reaches the DNS path too: a poisoned
		// resolver for a --peers name can name a previously banned address,
		// up to maxBootstrapAddrs of them, and clear its ban. This is
		// accepted rather than overlooked, because the alternative is that
		// whoever can write peers.json can delete the operator's whole list
		// from the candidate set, which is a total eclipse against a strictly
		// weaker precondition. The ban is re-earned online in the round it
		// takes the peer to violate the protocol again.
		if p.restored && p.Score < 0 {
			p.Score = 0
			ps.retierLocked(p)
		}
		// The same rule for the same reason, on the field the loader used to
		// blanket-zero for it. A restored Failures count demotes an
		// entry to dialRank 0 and to evictionTier 0, so whoever can write
		// peers.json could otherwise sort the operator's whole --peers list
		// behind every invented address in the file. Clearing it here confines
		// the answer to the addresses the operator actually re-supplied, and
		// leaves a refuted gossip address refuted — which is what keeping the
		// count across a restart is for. Restored only, so a failure this
		// process recorded against a bootstrap address still counts, and
		// AddBootstrap runs once per process per address so nothing can
		// re-enter here to launder one.
		if p.restored && p.Failures > 0 {
			p.Failures = 0
			ps.retierLocked(p)
		}
	}
}

// AddFrom records a peer address learned from the peer at address from.
//
// from is the connection address of the peer that gossiped addr; it is stored
// reduced to its address group, because that is the granularity at which it is
// expensive to widen (an attacker gets every ephemeral port on an address for
// free, and every address in a /16 for nearly free). An empty from means the
// address was not gossiped at all — see Add.
func (ps *PeerStore) AddFrom(addr, from string) {
	if !plausibleAddr(addr) {
		return
	}
	src := ""
	if from != "" {
		src = AddressGroup(from)
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	// admitLocked stamps Src at creation and never afterwards: the first teller
	// wins and a later one cannot overwrite it. Otherwise an attacker
	// re-gossiping an address it did not originate could relabel an operator's
	// bootstrap entry into its own cohort — or relabel its own entries as an
	// honest peer's, and hand that peer the eviction bill.
	ps.admitLocked(addr, src, true)
}

// plausibleAddr reports whether addr is a syntactically dialable target: a
// non-empty "host:port" under the length limit, with a host that parses as an
// IP address.
func plausibleAddr(addr string) bool {
	if addr == "" || len(addr) > MaxAddrLen {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// admitLocked returns the peer record for addr, creating one if this is the
// first time it has been seen, and enforces MaxPeers while doing it. src is
// recorded as Peer.Src on creation and ignored for an address already known.
// Callers hold ps.mu.
//
// strict means the caller's addr is an untrusted string and must satisfy
// plausibleAddr — a real, IP-hosted dial target — or admission is
// refused outright. Add/AddFrom are strict, because their input is exactly
// that: a string out of a gossip frame or a bootstrap flag, taken on faith.
// Adjust, MarkConnected and MarkFailed are not: every call to them names a
// peer this node has actually dialled, been dialled by, or exchanged a message
// with, so addr is either a real socket address or, in tests exercising engine
// logic without a real socket, a stand-in for one — a difference this store
// cannot see from the string alone.
//
// strict is therefore also the answer to "is this a dialable address?", and
// admission records it as such: an entry a non-strict caller creates is marked
// Peer.observed and is not a dial candidate. The two coincide because
// every dialable address a non-strict caller can name is already in the store
// — its addr came out of SelectDialTargets or SyncCandidates — so the only
// entry a non-strict caller ever *creates* is an inbound connection's
// ephemeral source socket.
//
// With one exhaustively audited exception, which lands on the right side of
// the same rule: SyncCandidates returns Engine.tips[..].Dial, which is a
// hello's ListenAddr recorded whether or not AddFrom admitted it, so a peer
// advertising a name rather than an IP is a sync candidate without a store
// entry, and SyncFrom's Adjust/MarkFailed then creates one. Marking it
// observed is what plausibleAddr already decided about that string on the
// strict path: it is not a dial target, and it was only ever a
// candidate through this back door.
//
// **A well-formed address is never refused for want of room.** When the store
// is full, admission evicts; it does not decline. An earlier revision of this
// change declined instead, refusing a strict caller whenever the worst entry
// held was already at least as good as a brand-new, never-contacted address
// (score >= 0, no failures). That gate is a lock, not a floor, and it was
// measured: 4096 invented IPv4 addresses — one flood, all well-formed, all
// unproven, all score 0 — fill the store and every honest address offered
// afterwards is refused, including the operator's own bootstrap list on the
// next start, because a never-contacted honest address is never *better* than
// a never-contacted junk one. It closes the store's unbounded growth by making
// the store unable to learn anything again.
//
// That is the same failure the identity-keyed store next door already reasoned
// its way out of ("Refusing it instead ... freezes the store solid", AdjustKey)
// and the same one docs/decisions/networking.md §5 settled for the accept path
// ("Refusing at the cap is not [right], and it re-creates the issue the accept
// path was rewritten for"). This store now agrees with both.
//
// **What stops the churn is who pays for it.** The objection the floor existed
// to answer is real: without one, an unbounded stream of interchangeable junk
// evicts an honest entry per arrival, replaying the unbounded growth one
// eviction at a time instead of one insertion at a time. The answer is not to
// refuse the arrival but to charge it to its own cohort — see evictOneLocked,
// which takes the victim from the most over-represented cohort in the store. A
// flood is by construction the largest cohort, so a flood evicts itself, and
// the honest singleton beside it is untouched. That is networking.md §5's
// accept-path finding verbatim — "Group share is the one signal that does not
// invert" — carried to the peer store.
//
// A non-nil *Peer plus ok=false never happens; the two are always reported
// together so callers can check one value.
func (ps *PeerStore) admitLocked(addr, src string, strict bool) (*Peer, bool) {
	if p, ok := ps.peers[addr]; ok {
		// A strict caller asserts this address is a dialable listen address —
		// an operator's bootstrap entry, a `peers` frame, a `hello`'s
		// ListenAddr. That assertion is what makes an address a candidate, so
		// it also un-observes one this node had only ever seen as a socket:
		// a peer that dials out from the port it listens on would otherwise
		// stay undialable for as long as the entry lived. It confers nothing
		// else — Src, bootstrap, score and Seq are untouched, so this cannot
		// relabel a cohort or strip an eviction exemption — and the
		// entry it hands back is bounded by MaxPerSource like any other
		// claimed address.
		if strict {
			p.observed = false
		}
		return p, true
	}
	if strict && !plausibleAddr(addr) {
		return nil, false
	}
	ps.nextSeq++
	p := &Peer{Addr: addr, Src: src, Seq: ps.nextSeq, observed: !strict}
	// A cohort at its ceiling pays for its own growth, and pays before the
	// store's global cap is even consulted: the marginal address costs the
	// teller one of its own entries and costs nobody else anything. This is
	// also the path a flood takes, so it is the one that must be cheap.
	c := cohort(p)
	if len(ps.cohorts[c]) >= MaxPerSourceStored {
		if !ps.evictWorstInCohortLocked(c) {
			return nil, false
		}
	}
	for len(ps.peers) >= MaxPeers {
		if !ps.evictOneLocked() {
			return nil, false
		}
	}
	ps.peers[addr] = p
	ps.indexLocked(p)
	return p, true
}

// cohort is the group an entry's eviction cost is charged to.
//
// For an address this node was told about, it is the teller (Peer.Src): a
// gossip flood is one cohort however many distinct /16s the invented addresses
// span, because the one thing the attacker could not invent is the connection
// it spoke from.
//
// For an address this node was not told about — a bootstrap entry, a socket it
// connected to, an entry restored from an older peers.json — there is no
// teller, so the cohort is the address's own group.
//
// The two are separate keyspaces and the prefixes are load-bearing, not
// decoration. Both produce AddressGroup strings, so without them an attacker
// whose *connection* is in the same /16 as an operator's bootstrap peers
// shares their cohort and floods it to the ceiling from inside: measured on
// the revision that had no prefixes, 512 gossiped strings — eight `peers`
// frames — evicted 30 of 30 operator bootstrap addresses, and co-location in a
// /16 with a bootstrap peer is the ordinary case for a cloud-region
// deployment. Prefixed, a teller can only ever evict from the pool of what it
// itself gossiped. That is what bounds the other unbounded-insertion path in
// this file: MarkConnected records an inbound connection's
// "ip:ephemeral_port", and one address yields as many of those as the OS has
// ports, all of them in a single /16. Those entries are no longer dial
// candidates (Peer.observed), but they are still entries, so the
// storage bound is the one that keeps them from crowding the store out.
func cohort(p *Peer) string {
	if p.Src != "" {
		return "src:" + p.Src
	}
	return "own:" + AddressGroup(p.Addr)
}

// renumberLocked collapses every loaded Peer.Seq into a single arrival bucket
// older than anything this process learns afterwards, and sets nextSeq so the
// first address admitted after the load is strictly newer than all of them.
//
// Seq decides which entry a full cohort gives up (betterVictim: newest first),
// and the persisted value is asserted by whoever wrote the file. An earlier
// revision renumbered to a dense 1..N "in the order the file implies", which
// discarded the absolute number — the overflow bug, a file claiming Seq =
// MaxInt64 making every later address the entry eviction never reaches — but
// kept the *relative* order, which is the half the writer of the file still
// chooses. Measured on that revision: 511 entries packed into the bootstrap
// address's own /16 make it the largest cohort, and the operator's
// freshly-added address is the newest tier-1 entry in it, so it is evicted
// after a single gossip admission.
//
// One bucket removes the choice rather than sanitising it: a file can no longer
// order its own entries against each other at all. What it costs is the only
// legitimate thing the order carried — a restart no longer re-ages the store
// relative to itself — and that is worth giving up, because the file still
// separates its own restored entries on every key it is *allowed* to move them
// on. The loader flattens a claimed score to at most 0 and keeps the failure
// count the file recorded; failures sort above seq in both selectLocked and
// dialRank, so two restored unproven entries that differ are already separated
// before seq is consulted. That key is safe to leave to the file precisely
// because it only ever demotes — a file can add failures to an entry, never
// subtract this node's own — whereas a relative arrival order is a free
// promotion for whichever entries the writer lists first. Collapsing seq takes
// away the promotion and keeps the demotion.
//
// Making the bucket the *oldest* one, rather than the newest, is deliberate:
// these are the addresses this node chose to remember, so a flood arriving
// after the load must spend its own arrivals before it reaches any of them.
//
// Callers hold ps.mu, or hold ps before it is published as NewPeerStore does.
func (ps *PeerStore) renumberLocked() {
	for _, p := range ps.peers {
		p.Seq = 1
	}
	ps.nextSeq = 1
}

// validGroup reports whether s is a group key of the shape AddressGroup
// produces, or the empty "no teller" value. Anything else read back from disk
// is not something this node wrote.
func validGroup(s string) bool {
	if s == "" {
		return true
	}
	if s == invalidGroup {
		return true
	}
	host, mask, ok := strings.Cut(s, "/")
	if !ok || (mask != "16" && mask != "32") {
		return false
	}
	return net.ParseIP(host) != nil
}

// indexLocked and unindexLocked keep cohorts in step with peers. Callers hold
// ps.mu (or hold ps before it is published, as NewPeerStore does).
func (ps *PeerStore) indexLocked(p *Peer) {
	// Every entry that enters ps.peers passes through here - admitLocked and
	// the loader are the only two assignments to ps.peers - so this is the one
	// place the memoized diversity group has to be stamped.
	p.group = AddressGroup(p.Addr)
	c := cohort(p)
	m := ps.cohorts[c]
	if m == nil {
		m = map[string]*Peer{}
		ps.cohorts[c] = m
	}
	m[p.Addr] = p
	ps.retierLocked(p)
}

func (ps *PeerStore) unindexLocked(p *Peer) {
	c := cohort(p)
	m := ps.cohorts[c]
	delete(m, p.Addr)
	if len(m) == 0 {
		delete(ps.cohorts, c)
	}
	delete(ps.tier0, p.Addr)
}

// retierLocked keeps the tier0 set in step with a peer's record. It is called
// wherever Score, Failures or LastSeen change — which is every mutating entry
// point, all of which already hold ps.mu.
func (ps *PeerStore) retierLocked(p *Peer) {
	if evictionTier(p) == 0 {
		ps.tier0[p.Addr] = p
		return
	}
	delete(ps.tier0, p.Addr)
}

// proven reports whether this node has evidence about a peer beyond the
// string: a connection it completed (LastSeen) or score it earned. An
// unproven entry is indistinguishable from an invented one — that is the
// whole difficulty — so an unproven entry is what the store gives up first,
// and cohort share only decides which unproven entry goes.
//
// Without this, cohort share decides ahead of everything and the ordering
// inverts against exactly the peers the store exists to remember: measured on
// the revision that had cohorts but not this, three score-100 peers this node
// had actually connected to were evicted ahead of 4093 score-0 invented
// entries, because the three shared one cohort and the 4093 each had their own.
// A restored entry is excluded whatever the file said about it: peers.json can
// assert LastSeen and Score, and evidence this node did not gather is not
// evidence.
func proven(p *Peer) bool { return !p.restored && (p.LastSeen != 0 || p.Score > 0) }

// metInProcess reports whether this node has itself completed a connection to
// the address since it started: MarkConnected stamps LastSeen and clears
// restored, and those two together are a fact nothing off the wire and nothing
// in peers.json can assert. A restored entry claiming last_seen is excluded for
// the same reason proven excludes it.
//
// It is the exemption from MaxPerSource. Peer.Src is a claim about who first
// *mentioned* an address; a completed connection is this node's own check of
// that address, and evidence a node gathered itself outranks a stranger's
// first-teller claim. See selectLocked.
func metInProcess(p *Peer) bool { return !p.restored && p.LastSeen != 0 }

// dialRank orders candidates in selectLocked under Score by how good this
// node's evidence for the address is, highest dialled first. It exists because
// Score no longer survives a restart: without it the first post-restart round
// ranks on the address string, which is the one key an attacker picks for free.
//
//	3 — met in this process: a connection this node completed since it started.
//	    Nothing a file says can reach here.
//	2 — supplied by the operator for this run. Not chosen by any peer.
//	1 — peers.json says this node once met it. Forgeable by whoever can write
//	    the file, which is why it sits under the operator's own list rather
//	    than over it; under the route that is actually a boundary — the node's
//	    own Save writing back what an attacker earned online — it buys the
//	    attacker a tie with honestly met peers and never a lead.
//	0 — a string this node was told about and has never reached.
//
// No rank above 0 is a resting state. The first successful dial to a
// restored entry calls MarkConnected, which clears restored and moves it 1→3;
// a bootstrap address that answers moves 2→3 the same way. So the operator's
// list leads only over peers this node has not yet re-reached in this process,
// and each of them overtakes it the moment it answers — one dial round, no
// decay to tune, and no permanent preference for the configured list.
func dialRank(p *Peer) int {
	// A dial this node made and that did not answer refutes every rank above 0,
	// uniformly. Failures is never reset on success — the only assignment to
	// zero in this file is AddBootstrap, on restored entries the operator
	// re-supplied, and the loader's clamp of a negative count the file claimed
	// — and dialRank sits *above* the failures key, so a rank that survived a
	// failure would be a one-way ratchet with no way down: a stale --peers list
	// would hold every outbound slot at rank 2 forever and the node could never
	// fall back to gossip, and an inbound ip:ephemeral_port entry that scores
	// nothing would hold rank 1 above every untried address forever. main
	// self-heals from both cases on the failures key; anything less than a
	// uniform condition here would make this diff strictly worse than main for
	// them. Demoting to rank 0 hands the decision back to that same failures
	// key.
	//
	// A restored entry now carries the failure count the file recorded,
	// so a peers.json entry this node had dialled and never reached
	// comes back at rank 0 instead of at rank 1. That is the point: the
	// refutation is the cheapest true thing this node knows about a gossiped
	// address, and forgetting it across a restart made a flood only have to
	// outlive one. The honest-restart property this rank exists for is
	// untouched, because it is about the *operator's* list, and AddBootstrap
	// clears a restored failure count for exactly the addresses the operator
	// re-supplied.
	if p.Failures > 0 {
		return 0
	}
	switch {
	case p.LastSeen != 0 && !p.restored:
		return 3
	case p.bootstrap:
		return 2
	case p.LastSeen != 0:
		return 1
	default:
		return 0
	}
}

// evictionTier ranks an entry by what this node knows about it, lowest given
// up first. It is the outer key of betterVictim; the keys under it only ever
// decide between entries of the same tier.
//
//	0 — demonstrated bad: it scored below zero, or it has been dialled and has
//	    never once answered. Nothing about who gossiped it changes that.
//	1 — unproven: never contacted, nothing scored. Every entry here has an
//	    identical record, which is precisely why cohort share and arrival order
//	    have to decide between them — there is nothing else.
//	2 — proven: a connection this node completed, or score it earned. A peer
//	    with a long record and one failed redial is here, not in tier 0.
func evictionTier(p *Peer) int {
	if p.Score < 0 || (p.Failures > 0 && p.LastSeen == 0) {
		return 0
	}
	if proven(p) {
		return 2
	}
	return 1
}

// MaxPerSourceStored bounds how many of the store's MaxPeers entries any one
// cohort may hold at once (see cohort).
//
// It is the bound that makes eviction fair by construction rather than by
// argument. An earlier revision had eviction take its victim from whichever
// cohort was simply largest, which reads as "a flood evicts itself" and is
// only true when the flood is the largest thing in the store. On a node
// bootstrapped from one honest peer the largest cohort is that peer's address
// book, and it was measured: 200 invented addresses from one attacker source
// evicted 200 honest addresses at zero cost to the attacker, and a claim-then-
// flood — gossip real addresses first, so first-teller-wins stamps them with
// the attacker's own Src, then flood from the same source — removed 30 of 30
// real peer addresses from a victim's store, persistently.
//
// A per-cohort ceiling removes the asymmetry instead of arguing about it. No
// cohort can grow past MaxPeers/8, so no cohort can be large enough to be
// everyone else's eviction source, and a cohort at its ceiling evicts strictly
// from itself: the marginal invented address costs the attacker one of its own
// entries and costs nobody else anything. Filling the store therefore takes
// eight distinct tellers, which is eight real addresses in eight real /16s.
//
// Eight, so that a node bootstrapped from a single peer still remembers 512
// addresses from it — far more than the 8 outbound and 32 inbound slots it
// will ever dial — while no single teller can be more than an eighth of what
// this node knows.
const MaxPerSourceStored = MaxPeers / 8

// evictOneLocked removes exactly one entry and reports whether it did.
//
// The victim is chosen by three keys in order: unproven before proven, then
// larger cohort before smaller, then worsePeer. Quality outranks cohort share
// because an entry this node has actually connected to is the thing the store
// exists to hold, and cohort share outranks quality *within* the unproven
// tier because unproven entries are indistinguishable from one another by
// construction — a never-contacted honest address and a never-contacted
// invented one have identical records — so share is the only signal left that
// separates a flood from a peer list.
//
// This is the general path, taken when the store is full and the arriving
// address's own cohort is not.
//
// An earlier version of this comment claimed a flood does not reach here,
// because a cohort at MaxPerSourceStored evicts from itself through
// evictWorstInCohortLocked. Measurement says the opposite: a flood is by
// construction the largest cohort, so this path evicts from it, so it never
// grows to its ceiling and the cheap path never fires at all — 3000 flood
// admissions took the general path 3000 times, and the attacker's cohort
// never approached its ceiling of 512 — how far below depends on how the rest
// of the store is shaped, measured between 99 and 456. That is good behaviour and a false
// comment, and it hid the cost: at 160µs an admission, one attacker holding
// 10ms of this store's write lock per `peers` frame — the same lock
// Engine.Handle needs to score every message from every peer.
//
// Hence the shape below. Tier 0 is a set, so the first phase costs its own
// size. The second visits cohorts largest first and stops at the first one
// holding an unproven entry, so a flood costs its own cohort rather than the
// store: 20.5µs an admission, against 123µs for the uncapped store this
// replaced.
//
// Callers hold ps.mu.
func (ps *PeerStore) evictOneLocked() bool {
	// Tier 0 first, wherever it sits. It is kept as a set precisely so that
	// finding it does not cost a walk of the store.
	if len(ps.tier0) > 0 {
		var victimAddr string
		var victim *Peer
		// No configuredAndUntried skip here, unlike the two scans below:
		// the exemption and this tier are disjoint by construction, because
		// the exemption requires Score >= 0 and Failures == 0 and tier 0 is
		// exactly the negation of one of those. A revision that had the skip
		// here could reach the state below.
		for addr, p := range ps.tier0 {
			if victim == nil || worsePeer(p, addr, victim, victimAddr) {
				victim, victimAddr = p, addr
			}
		}
		// Declared unreachable, kept as defence in depth: a non-empty tier 0
		// always yields a victim under the disjointness above. If a later
		// change breaks that, returning false here would refuse every further
		// admission while tier-1 victims sat untouched — a full store that
		// cannot learn — so fall through instead of returning.
		if victim != nil {
			return ps.removeLocked(victimAddr, victim)
		}
	}

	// Then the newest entry of the largest cohort that has an unproven entry
	// to give. Cohorts are visited largest first, so the flood — which is the
	// largest cohort by construction, that being what makes it a flood — is
	// the first one looked at, and the scan costs its size rather than the
	// store's.
	keys := make([]string, 0, len(ps.cohorts))
	for c := range ps.cohorts {
		keys = append(keys, c)
	}
	sort.Slice(keys, func(i, j int) bool {
		if a, b := len(ps.cohorts[keys[i]]), len(ps.cohorts[keys[j]]); a != b {
			return a > b
		}
		return keys[i] < keys[j]
	})
	for _, c := range keys {
		var victimAddr string
		var victim *Peer
		for addr, p := range ps.cohorts[c] {
			if evictionTier(p) != 1 || configuredAndUntried(p) {
				continue
			}
			if victim == nil || betterVictim(p, addr, 0, victim, victimAddr, 0) {
				victim, victimAddr = p, addr
			}
		}
		if victim != nil {
			return ps.removeLocked(victimAddr, victim)
		}
	}

	// Nothing unproven anywhere: every entry is one this node has met. Give up
	// the worst of them.
	var victimAddr string
	var victim *Peer
	for addr, p := range ps.peers {
		if configuredAndUntried(p) {
			continue
		}
		if victim == nil || worsePeer(p, addr, victim, victimAddr) {
			victim, victimAddr = p, addr
		}
	}
	return ps.removeLocked(victimAddr, victim)
}

// removeLocked drops one entry from both the peer map and every index.
func (ps *PeerStore) removeLocked(addr string, p *Peer) bool {
	if p == nil {
		return false
	}
	ps.unindexLocked(p)
	delete(ps.peers, addr)
	return true
}

// configuredAndUntried reports whether p is an address the operator supplied
// for this run that this node has not yet dialled even once.
//
// Such an entry is exempt from eviction. It has no evidence for or against it,
// so every eviction key ranks it with the cheapest thing an attacker can
// manufacture — and the one property that separates it from gossip, that no
// peer and no file chose it, is invisible to those keys. Without the exemption
// a single `peers` frame can spend the operator's whole list before the dial
// loop has reached any of it, which is the same eclipse-by-attrition the
// restored-score clamp closes on the selection side.
//
// A restored LastSeen does not end it, and a restored Score cannot start it.
// The file writer is the adversary this change assumes, so reading either field
// as evidence here would hand that adversary the exact attack the exemption
// exists to stop: stamping last_seen on the operator's own addresses makes the
// exemption false for them, and the oldest-bucket rule does not save them
// because betterVictim falls through to worsePeer's LastSeen key, which the
// same file chose. Restored entries are therefore treated exactly as proven()
// treats them — the claim is not evidence. The Score clause is the mirror: an
// entry the *node* banned in this process must stay evictable, and it also
// keeps this predicate disjoint from evictionTier's tier 0 (Score < 0), which
// no exemption may ever cover.
//
// The exemption leans on a choice made in another unit: Engine.OnHello records
// a peer's claimed listen address with AddFrom and marks only the connection's
// own address with MarkConnected. If it marked the claimed address
// instead, an inbound peer could name an operator address in a hello, set its
// LastSeen, and strip this exemption from it without the operator's address
// ever having been dialled. That coupling is load-bearing, not incidental.
//
// The exemption is not a resting state and cannot accumulate: it ends at the
// first dial attempt, which either succeeds (MarkConnected sets LastSeen) or
// fails (MarkFailed increments Failures). It is also bounded by the size of a
// configured list, so it cannot be grown from the network. If a store were
// somehow full of nothing but untried configured addresses, eviction finds no
// victim and admission refuses the new address instead — refusing to learn is
// the safe direction when the alternative is forgetting what the operator
// asked for.
func configuredAndUntried(p *Peer) bool {
	return p.bootstrap && (p.restored || p.LastSeen == 0) && p.Failures == 0 && p.Score >= 0
}

// betterVictim reports whether a (at addrA, in a cohort of size sizeA) should
// be evicted before b. See evictOneLocked for the ordering and why it is in
// that order.
func betterVictim(a *Peer, addrA string, sizeA int, b *Peer, addrB string, sizeB int) bool {
	if ta, tb := evictionTier(a), evictionTier(b); ta != tb {
		return ta < tb
	}
	if evictionTier(a) != 1 {
		return worsePeer(a, addrA, b, addrB)
	}
	if sizeA != sizeB {
		return sizeA > sizeB
	}
	// Newest first, among entries neither of which this node has any evidence
	// about. Two unproven entries have identical records by construction, so
	// whatever breaks the tie *is* the policy, and the previous tie-break —
	// worsePeer's final fall-through to the address string — is a key the
	// attacker chooses: it gossips real addresses first so first-teller-wins
	// files them under its own cohort, then floods that cohort with addresses
	// that sort ahead of them. Measured on the revision that tied on the
	// address: 2030 gossiped strings, about 32 `peers` frames, evicted 30 of
	// 30 real addresses the attacker had named first.
	//
	// Arrival order cannot be chosen after the fact *by a peer*, so a cohort at
	// its ceiling recycles its own most recent arrivals and the flood pays for
	// itself. It can be chosen by whoever writes peers.json, which is why
	// everything restored from one shares a single bucket and ties here
	// (renumberLocked): the file gets no say in which of its own entries
	// is given up, only in whether they are older than what arrives later.
	// Proven entries are already out of this tier, so this never ages out a
	// peer this node has actually met.
	if a.Seq != b.Seq {
		return a.Seq > b.Seq
	}
	return worsePeer(a, addrA, b, addrB)
}

// evictWorstInCohortLocked removes the worst entry of one cohort — unproven
// first, then worsePeer — and reports whether it did. Callers hold ps.mu.
//
// This is the path a flood takes, and it is deliberately the cheap one: it
// scans at most MaxPerSourceStored entries rather than the whole store, which
// matters because admission runs once per address in every unsolicited `peers`
// frame and holds the same write lock Engine.Handle needs to score every
// message from every peer.
func (ps *PeerStore) evictWorstInCohortLocked(c string) bool {
	var victimAddr string
	var victim *Peer
	for addr, p := range ps.cohorts[c] {
		if configuredAndUntried(p) {
			continue
		}
		if victim == nil || betterVictim(p, addr, 0, victim, victimAddr, 0) {
			victim, victimAddr = p, addr
		}
	}
	return ps.removeLocked(victimAddr, victim)
}

// worsePeer reports whether a (at address addrA) should be evicted before b
// (at address addrB): lower score is worse; a tied score breaks on more
// failures; a further tie breaks on being less recently seen (a peer never
// successfully connected has LastSeen 0, the oldest possible value); and a
// full tie — same score, same failures, same LastSeen — breaks on the address
// itself, purely so eviction is deterministic and reproducible from a log, the
// same reason SelectDiverse's own sort and evictFurthestOrphanLocked's both
// end in one.
func worsePeer(a *Peer, addrA string, b *Peer, addrB string) bool {
	if a.Score != b.Score {
		return a.Score < b.Score
	}
	if a.Failures != b.Failures {
		return a.Failures > b.Failures
	}
	if a.LastSeen != b.LastSeen {
		return a.LastSeen < b.LastSeen
	}
	return addrA > addrB
}

// Adjust changes a peer's score, clamped at the ceiling.
func (ps *PeerStore) Adjust(addr string, delta int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.admitLocked(addr, "", false)
	if !ok {
		return
	}
	p.Score += delta
	if p.Score > ScoreCeiling {
		p.Score = ScoreCeiling
	}
	// And a floor, symmetric with the ceiling.
	//
	// Without one a score sinks without bound past the ban threshold, so a peer
	// that dipped below could never climb back even in principle — and since it
	// is banned it receives no messages to earn the +1 with, which makes the
	// state absorbing in fact as well as in arithmetic. Observed at -104 on a
	// node that had done nothing wrong.
	//
	// The floor does not unban anything by itself; it makes the distance back a
	// bounded one, so that a future decay or probation has something finite to
	// work against instead of an arbitrarily deep hole.
	if p.Score < ScoreFloor {
		p.Score = ScoreFloor
	}
	ps.retierLocked(p)
}

// AdjustNotBelow applies a negative delta to an address-keyed score but will
// not carry it past `floor` in the downward direction. It is how a charge that
// must not, by itself, ban a peer is applied — the unserved-body reap, whose
// signal is not attributable to a misbehaving peer (see ScoreUnservedBodyFloor).
//
// A score at or above floor stops exactly at floor; a score already below floor
// — driven there by other, ATTRIBUTABLE charges — is left unchanged, so this
// charge neither bans on its own nor undoes a ban another charge earned. The
// ceiling and ScoreFloor clamps still apply, exactly as Adjust.
func (ps *PeerStore) AdjustNotBelow(addr string, delta, floor int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.admitLocked(addr, "", false)
	if !ok {
		return
	}
	next := p.Score + delta
	if next < floor {
		if p.Score < floor {
			next = p.Score
		} else {
			next = floor
		}
	}
	if next > ScoreCeiling {
		next = ScoreCeiling
	}
	if next < ScoreFloor {
		next = ScoreFloor
	}
	p.Score = next
	ps.retierLocked(p)
}

// MarkConnected records a successful connection.
func (ps *PeerStore) MarkConnected(addr string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.admitLocked(addr, "", false)
	if !ok {
		return
	}
	p.LastSeen = ps.now().Unix()
	// This node has now met the peer itself, so the record stops being a claim
	// the file made and becomes one this node can back.
	p.restored = false
	ps.retierLocked(p)
}

// MaxStoredFailures caps Peer.Failures.
//
// The count is a rank, never a magnitude: dialRank reads `Failures > 0`,
// evictionTier reads `Failures > 0 && LastSeen == 0`, and worsePeer and
// selectLocked compare two counts against each other. Nothing multiplies by it
// and nothing waits for it, so there is no answer it can give above the cap
// that it does not already give at the cap.
//
// Capping it is what makes the field safe to persist. peers.json is an
// operator-visible file this loader already assumes may have been edited, so an
// unbounded count read back from disk is an unbounded integer inside the
// eclipse defence's own comparator — and selectLocked snapshots it into an
// int32, where a large enough claimed value would wrap to negative and sort a
// forged entry *ahead* of every honestly-tried address. The cap removes the
// representable state rather than arguing about it, on both the load path and
// the increment.
const MaxStoredFailures = 1 << 20

// MarkFailed records a failed connection.
func (ps *PeerStore) MarkFailed(addr string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.admitLocked(addr, "", false)
	if !ok {
		return
	}
	if p.Failures < MaxStoredFailures {
		p.Failures++
	}
	ps.retierLocked(p)
}

// Health is the raw scoring state, before any policy reads it.
//
// It exists because of the fourth instrument in CONTRIBUTING's table: the
// heartbeat's `ahead_peers` is computed from SyncCandidates, which applies the
// ban filter *before* returning — so a node that has banned every peer able to
// tell it it is behind reports `ahead_peers=0`, byte-identical to a node at the
// tip. A signal derived downstream of the policy it monitors cannot report on
// that policy.
//
// These numbers are upstream of every filter. Nothing consults them to make a
// decision; they exist to be looked at.
type Health struct {
	Known    int
	Banned   int
	MinScore int
	MaxScore int
}

// Health returns the raw scoring state.
func (ps *PeerStore) Health() Health {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	h := Health{Known: len(ps.peers)}
	first := true
	for _, p := range ps.peers {
		if p.Banned() {
			h.Banned++
		}
		if first || p.Score < h.MinScore {
			h.MinScore = p.Score
		}
		if first || p.Score > h.MaxScore {
			h.MaxScore = p.Score
		}
		first = false
	}
	return h
}

// Banned reports whether an address has scored itself out.
func (ps *PeerStore) Banned(addr string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	p, ok := ps.peers[addr]
	return ok && p.Banned()
}

// MaxIdentities bounds how many distinct authenticated identities the live,
// unpersisted identity-keyed store (AdjustKey/BannedKey) holds at once.
//
// Without a cap, one throwaway TLS connection plus one throwaway scored
// message plants a permanent entry: Ed25519 keygen and a self-signed cert
// cost nothing (see AdjustKey's own doc comment), and AdjustKey is called on
// every scored message — node.go's serve loop, before the connection is even
// evaluated for disconnection. A persistent attacker could grow this map
// without bound for the life of the process: the same unbounded-growth shape
// the address-keyed store had, reopened here in a new keyspace (round 2 review
// finding).
//
// The number is policy, not protocol, chosen the same way MaxPeers is sized:
// several times docs/decisions/networking.md §5's "low thousands of nodes"
// estimate for comfortable flood-gossip scale, so a well-connected node has
// real headroom before anything is evicted. Kept as this store's own constant
// rather than a reference to MaxPeers so the two stores stay independently
// tunable — they bound different keyspaces with different admission costs (a
// real TLS handshake here, a free gossip string there).
const MaxIdentities = 4096

// identityEntry is one identity's live score record: the score itself, and
// when it was last touched, so a full store has a deterministic, meaningful
// order to evict from.
type identityEntry struct {
	score    int
	lastSeen int64
	// served is how many bytes of query reply this identity has been served
	// inside the current budget window, and servedAt is the second that level
	// was last settled at. Zero means nothing served. ChargeServedBytes is the
	// only writer and ServedBytesExhausted the only other reader; an unbudgeted
	// served reply is why there is a budget and node/p2p/engine.go's
	// replyByteBudget is where the two numbers that bound it are derived.
	//
	// They live on THIS entry, next to the score, rather than in a map of their
	// own, and the reason is the one AdjustKey's own comment gives for this
	// keyspace existing at all: a budget keyed on Conn.Addr is keyed on "a
	// value the OS picks fresh on every reconnect, not the peer", so it is
	// re-bought for the price of one TLS handshake — measured happening to the
	// budget next door. Sharing the entry also means a banned identity and a
	// spent budget occupy one of MaxIdentities slots between them rather than
	// two.
	served   uint64
	servedAt uint64
	// unheldEpochs is how many announcements this identity has spent on
	// proof-of-work key epochs outside the two the receiving node is itself
	// working in, net of refill, and unheldEpochsAt is the second that level
	// was last settled at. Zero means nothing spent. SpendUnheldKeyEpoch is
	// the only writer; Engine.spendKeyEpoch (engine.go) is its only caller and
	// MaxUnheldKeyEpochsPerPeer the ceiling it passes.
	//
	// They live HERE, and that move is the whole of the identity keying. The
	// budget was on PeerTip, keyed by the connection address Engine.Handle is
	// given, and Engine.forgetPeer deletes that entry on unregister — so an
	// inbound peer, whose Conn.Addr is "ip:ephemeral_port", re-bought the whole
	// budget for the cost of one TLS handshake. Measured: one identity, eight
	// reconnects, forty never-held key epochs against a budget of five. That is
	// the same defect identity-keyed scoring closed for the SCORE by adding
	// this keyspace, and the same one served/servedAt above cites for choosing
	// it. An identity survives the reconnect an address does not, so the budget
	// now does too.
	unheldEpochs   uint32
	unheldEpochsAt uint64
	// workRefused records that this identity has had a block announcement
	// refused by the proof-of-work check itself — a header whose digest did
	// not meet the target the header declared.
	//
	// It exists to end the amnesty an over-budget announcement bought from the
	// work check's score, and it is one bit rather than a count because it
	// answers a yes/no question: has this identity ever been shown to send
	// headers carrying no valid work? Past the key epoch budget an announcement
	// never reaches that check, so ScoreInvalidMessage never fires and an
	// identity with goodwill floods invalid headers without ever crossing
	// ScoreBanThreshold. The bit lets the over-budget refusal be scored for
	// exactly the identities that have already failed the check, and stay
	// unscored for every identity that has not — which is what keeps the honest
	// catch-up peer of
	// TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget
	// unbanned, because an honest announcement always meets the target its own
	// header declares and so can never set this.
	//
	// Sticky, and deliberately: it is not reputation that decays but a fact
	// about what this identity has been observed to send, and an identity is
	// abandoned rather than repaired. It costs nothing to hold — it shares the
	// entry a score already occupies, so it takes no MaxIdentities slot of its
	// own.
	workRefused bool
	// workEvals is how many proof-of-work evaluations this identity has spent on
	// block announcements inside the current budget window, net of refill, and
	// workEvalsAt is the second that level was last settled at. Zero means
	// nothing spent. SpendWorkEval is the only writer; Engine.spendWorkEval
	// (engine.go) is its only caller and MaxWorkEvalsPerConn the ceiling it
	// passes.
	//
	// This is a SEPARATE budget from unheldEpochs above, and the separation is
	// the whole of the work-eval budget. unheldEpochs charges only
	// announcements naming a key epoch this node is NOT working in —
	// spendKeyEpoch exempts the working epoch (workingKeyEpoch), because an
	// honest peer announces the block after this node's tip into it for the
	// whole interval it takes the tip to cross a key boundary, so charging the
	// working epoch there would throttle every honest peer at once. That
	// exemption is exactly the hole: a distinct announcement in the working
	// epoch reaches the memory-hard work.Check with no per-connection charge in
	// front of it, so one connection forces one RandomX evaluation per distinct
	// announce at zero cost. This budget is the charge the working epoch's
	// exemption leaves uncovered — it is unconditional on the epoch and stands
	// immediately ahead of work.Check, so it bounds the CPU one connection can
	// force whichever epoch it names, while unheldEpochs keeps bounding the far
	// more expensive never-held-epoch CACHE fills the working exemption never
	// touched.
	//
	// It lives HERE, on the identity entry, for the reason that moved
	// unheldEpochs here: a budget keyed on the raw connection address is keyed on
	// "a value the OS picks fresh on every reconnect", so an inbound peer
	// re-buys it for the price of one TLS handshake. Sharing the entry also means
	// a spent work budget takes no MaxIdentities slot of its own beyond the one
	// the score and the two sibling budgets already occupy.
	workEvals   uint32
	workEvalsAt uint64
}

// refilledServed returns what an identity has been served after crediting back
// every whole window that has elapsed, and the second that level is settled at.
//
// Pure, and that is what lets ServedBytesExhausted be a genuine read.
// wire.md §10.1 puts a budget check at step 3 and every charge, reservation
// and record at step 5, and draws the line at exactly this property: "a budget
// gate is safe to run before authentication precisely while it only reads."
// The refill is arithmetic here and a write only where ChargeServedBytes
// stores it back.
//
// The two refill arms are not one arm with a rounding choice. A window that
// refunds the bucket completely restarts the clock at now and discards the
// remainder, because keeping it would make the NEXT window arrive early — a
// free window per idle stretch, and a sender schedules its idle stretches. A
// PARTIAL refund advances the clock by exactly what was earned and banks the
// leftover, because that is time the schedule has already run and restarting
// at now would charge an honest peer for it twice. spendKeyEpoch (engine.go)
// splits the same pair for the same reason.
//
// The ceiling division is written out rather than as (served+budget-1)/budget
// so that a saturated served — ChargeServedBytes clamps at 2^64-1 rather than
// wrapping — cannot overflow the numerator. Below it, credits*budget < served
// and credits*period <= now-servedAt both hold by construction, so neither
// subtraction underflows and neither addition wraps.
//
// There is deliberately no `credits == 0` early return, although the shape
// invites one. It would be a conjunct no input separates where it matters: for
// a non-empty bucket the partial arm already returns exactly (served,
// servedAt) when credits is zero, and for an empty one the two forms differ
// only in whether an already-empty bucket re-anchors its clock, which no
// caller can observe — and that is checkable rather than merely asserted:
// ChargeServedBytes is the only writer and always adds at least one byte on
// top of whatever this returns, so a stored entry with served == 0 and
// servedAt != 0 is not a reachable state. The only call that arrives with
// served == 0 is one on an entry that has never been charged, and servedAt is
// zero there too, so the first arm takes it before the guard would have.
// ServedBytesExhausted, the only other reader, discards the clock entirely. A
// guard nobody can check is worth deleting rather than documenting.
func refilledServed(served, servedAt, budget, period, now uint64) (uint64, uint64) {
	switch {
	// A fresh entry anchors its clock and earns nothing, exactly as
	// spendKeyEpoch's first arm does: without it the division below measures
	// from the unix epoch and hands back a full bucket on the first call.
	case servedAt == 0:
		return served, now
	// A clock that has not advanced earns nothing, and a clock that has moved
	// BACKWARDS earns nothing either — the subtraction below is unsigned, so
	// without this comparison a corrected wall clock underflows into windows
	// by the million and returns a spent budget in full.
	case now > servedAt:
		credits := (now - servedAt) / period
		windows := served / budget
		if served%budget != 0 {
			windows++
		}
		if credits >= windows {
			return 0, now
		}
		return served - credits*budget, servedAt + credits*period
	}
	return served, servedAt
}

// ServedBytesExhausted reports whether a peer has already been served its whole
// reply-byte budget for the current window.
//
// key is what the bytes are charged to: the peer's authenticated Ed25519
// identity where the caller has one, and its connection address where it does
// not. See replyBudgetKey (engine.go) for which, and why the two share this
// keyspace: they are the same question — "who is this" — answered with the most
// durable identifier available, and an address string can never equal a 32-byte
// Ed25519 point that a peer would have to produce a private key for.
//
// An identity absent from the store has been served nothing, which is the same
// default BannedKey gives a key it has never seen. Reading rather than writing
// is deliberate; see refilledServed.
func (ps *PeerStore) ServedBytesExhausted(key string, budget, period, now uint64) bool {
	if key == "" || budget == 0 || period == 0 {
		return false
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	e, ok := ps.identity[key]
	if !ok {
		return false
	}
	served, _ := refilledServed(e.served, e.servedAt, budget, period, now)
	return served >= budget
}

// ChargeServedBytes adds n bytes of served reply to a peer's budget window.
//
// Admission is AdjustKey's, for the same reason and with the same residual: a
// newcomer is never refused, something is always evicted for it, and what goes
// is the entry worth least by lessWorthKeeping. A served-only entry sits at
// score zero and is therefore worth nothing to that ordering, so entries
// planted here are given up before any ban or any earned goodwill — which is
// the direction that matters, because the alternative would let a peer that
// only ever asks for headers push out an identity ban.
//
// What that leaves — an attacker shedding its own spent budget by making its
// entry the least worthy in a full store — is no longer an unbounding, and that
// the answer to the shed rather than its price. Engine.replyByteCeiling stands over
// this layer and is keyed on nothing a sender can present at all, so a re-bought
// per-identity window is drawn from a node-wide bucket that has no table and no
// eviction, exactly as the node-wide key-epoch ceiling stands over
// SpendUnheldKeyEpoch's own eviction residual. The price of the shed —
// on the order of MaxIdentities completed handshakes to fill the store and as
// many again to walk the eviction order round to one's own entry — is still what
// the shed costs; what has changed is what it buys, which is a share of a
// ceiling rather than a fresh window on top of one.
//
// lastSeen is set from the caller's clock rather than from ps.now, so that the
// whole budget — refill and eviction order alike — moves on the one seam
// Engine.Now already injects. In production they are the same wall clock.
func (ps *PeerStore) ChargeServedBytes(key string, n, budget, period, now uint64) {
	if key == "" || n == 0 || budget == 0 || period == 0 {
		return
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	if ps.identity == nil {
		ps.identity = map[string]identityEntry{}
	}
	e, ok := ps.identity[key]
	if !ok && len(ps.identity) >= MaxIdentities {
		victim, found := ps.findEvictableIdentityLocked()
		if !found {
			return
		}
		delete(ps.identity, victim)
	}
	e.served, e.servedAt = refilledServed(e.served, e.servedAt, budget, period, now)
	// Saturating rather than wrapping: a wrapped total is a SMALLER one, and a
	// smaller one hands back a budget the peer has already spent.
	if e.served+n < e.served {
		e.served = ^uint64(0)
	} else {
		e.served += n
	}
	e.lastSeen = int64(now)
	ps.identity[key] = e
}

// refilledUnheldEpochs returns how many unheld-key-epoch credits an identity is
// still holding spent after crediting back every whole period that has elapsed,
// and the second that level is settled at.
//
// Pure, so that the caller's only write is the one it makes under its own lock,
// exactly as refilledServed is pure for ServedBytesExhausted's sake.
//
// perPeriod credits per period, not the whole bucket per period, and that is
// what makes this a different function from refilledServed above rather than a
// call to it. The rate is derived: keyEpochPeriod (engine.go) is the time the
// honest chain takes to cross one key epoch, so ONE payer gets back one credit
// per key epoch the network actually enters and passes perPeriod = 1. The burst
// the bucket holds is what carries an honest peer across a boundary; the rate
// is what the chain earns.
//
// **The rate is a parameter because a bucket's recovery time is its size
// divided by its rate, and this function serves two buckets of very different
// sizes.** The node-wide ceiling (engine.go) is the per-payer budget multiplied
// by the connection set, and at one credit per period it took that multiple of
// periods to come back — measured at 240 periods, which is 1024 h on the public
// testnet's 512 x 30 s schedule and about 170 days on mainnet's 2048 x 30 s. A
// bound whose recovery is measured in months is not a bound, it is a one-way
// latch: 48 sequential handshakes drained it, two honest identities holding
// untouched budgets of their own were then refused, and one identity sending
// one announcement per period held it at zero indefinitely. Its caller now
// passes the connection set, so both buckets recover in
// MaxUnheldKeyEpochsPerPeer periods and the two layers state the same thing
// about time as they already state about size.
//
// A rate of zero is clamped to one rather than trusted from the caller, because
// zero is exactly the latch above: credits never arrive while the settle clock
// keeps advancing, so the bucket empties permanently. Neither caller can pass
// it — unheldKeyEpochCeiling derives its rate from a connection set it keeps at
// or above one, and SpendUnheldKeyEpoch passes the literal 1 — and it is owned
// here anyway, on the same principle keyEpochPeriod's saturation follows:
// arithmetic carries its own property rather than borrowing it from a caller.
//
// The two refill arms are the pair refilledServed splits for the same reason,
// and neither is a rounding choice. A fully refilled bucket restarts its clock
// at now and discards the remainder, because keeping it would make the NEXT
// credit arrive up to a period early — a free credit per idle stretch, and a
// sender schedules its idle stretches. A PARTIAL refill advances the clock by
// exactly what was earned and banks the leftover, because that is time the
// schedule has already run and restarting at now would charge an honest peer
// for it twice.
//
// The `now > at` comparison is load-bearing on its own: the subtraction is
// unsigned, so without it a wall clock corrected BACKWARDS underflows into
// credits by the million and hands a spent budget back in full.
func refilledUnheldEpochs(spent uint32, at, period, now uint64, perPeriod uint32) (uint32, uint64) {
	if perPeriod == 0 {
		perPeriod = 1
	}
	switch {
	// A fresh entry anchors its clock and earns nothing, exactly as
	// refilledServed's first arm does: without it the division below measures
	// from the unix epoch and hands back a full bucket on the first call.
	case at == 0:
		return spent, now
	case now > at:
		// Integer division and not a loop: the periods owed can be arbitrarily
		// many after an idle stretch, and `periods*period <= now - at` holds by
		// construction, so the addition below cannot overflow whatever the
		// parameters say.
		periods := (now - at) / period
		// Whole periods alone already cover the level, because perPeriod is at
		// least one. Short-circuiting on the periods rather than on the credits
		// is also what keeps the multiplication below inside uint64 without a
		// second guard: past this line both factors are under 2^32.
		if periods >= uint64(spent) {
			return 0, now
		}
		credits := periods * uint64(perPeriod)
		// No `credits == 0` arm, for the reason refilledServed gives for not
		// having one: `spent == 0 && at != 0` is not a state either writer can
		// store. SpendUnheldKeyEpoch stores the refusal only when the refilled
		// level is at or above the budget, and stores the admission with one
		// added on top; chargeNodeKeyEpoch always adds one on top; and
		// nodeKeyEpochsExhausted stores nothing at all. For every `spent > 0`
		// the arm would be byte-identical to the fall-through below —
		// `spent - 0, at + 0` — so it is a guard no input can separate, which
		// is worth deleting rather than documenting.
		if credits >= uint64(spent) {
			return 0, now
		}
		// The clock advances by the whole PERIODS that elapsed and never by the
		// credits they earned. At perPeriod = 1 the two are the same number and
		// the distinction is invisible; above it, advancing by the credits would
		// move the settle time past `now` and turn every later refill into the
		// backwards-clock case the `now > at` guard exists to refuse.
		return spent - uint32(credits), at + periods*period
	}
	return spent, at
}

// SpendUnheldKeyEpoch charges one announcement against an identity's allowance
// for proof-of-work key epochs the receiving node is not working in, and
// reports whether it could be paid for.
//
// key is what the epoch is charged to: the peer's authenticated Ed25519
// identity where the caller has one, and its connection address where it does
// not — replyBudgetKey (engine.go) decides which, and this shares that keyspace
// with the reply-byte budget for the reason stated there. The two answer one
// question, "who is this", with the most durable identifier available.
//
// Admission is AdjustKey's, for the same reason and with the same residual: a
// newcomer is never refused, something is always evicted for it, and what goes
// is the entry worth least by lessWorthKeeping. A budget-only entry sits at
// score zero and is therefore given up before any ban or any earned goodwill.
// What that leaves — an attacker evicting its own spent entry by presenting
// MaxIdentities fresh ones — is no longer an unbounding, because
// Engine.spendKeyEpoch's node-wide ceiling stands over this one and is keyed on
// nothing a sender can present at all.
//
// A zero budget or a zero period admits rather than refuses, which is the
// direction replyByteBudget's own zero arm takes and the opposite of
// keyEpochPeriod's: an unpayable announcement is one message, but a store
// misconfigured into refusing all of them is a node that stops evaluating
// gossip.
func (ps *PeerStore) SpendUnheldKeyEpoch(key string, budget uint32, period, now uint64) bool {
	if key == "" || budget == 0 || period == 0 {
		return true
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	if ps.identity == nil {
		ps.identity = map[string]identityEntry{}
	}
	e, ok := ps.identity[key]
	if !ok && len(ps.identity) >= MaxIdentities {
		victim, found := ps.findEvictableIdentityLocked()
		if !found {
			return false
		}
		delete(ps.identity, victim)
	}
	// One credit per period, which is this layer's whole rate: the budget is
	// MaxUnheldKeyEpochsPerPeer and it therefore comes back in
	// MaxUnheldKeyEpochsPerPeer periods. The node-wide layer above passes its
	// own connection set so that it recovers in the same number of periods
	// from a bucket that is that multiple larger.
	e.unheldEpochs, e.unheldEpochsAt = refilledUnheldEpochs(e.unheldEpochs, e.unheldEpochsAt, period, now, 1)
	e.lastSeen = int64(now)
	if e.unheldEpochs >= budget {
		// Stored even on the refusal, so the refill clock keeps advancing for a
		// peer that keeps asking. Dropping the write here would leave the clock
		// anchored at the last SUCCESSFUL spend, which is the same level, so the
		// two forms agree on credits — but only while the entry exists, and an
		// entry that is never written back can never be created at all, so a
		// first announcement from a spent-budget identity would be free.
		ps.identity[key] = e
		return false
	}
	e.unheldEpochs++
	ps.identity[key] = e
	return true
}

// UnheldKeyEpochsExhausted reports whether an identity has already spent its
// whole allowance of never-held key epochs for the current window, WITHOUT
// charging it anything.
//
// It is SpendUnheldKeyEpoch's read-only twin, and it is ServedBytesExhausted
// one primitive over: the served path has carried that pair — a genuine read
// beside the charging call — since the reply-byte budget shipped, and this
// budget shipped with the charging call alone, and a drained ceiling
// sheltering the identities the work check had already caught is what the
// missing half cost.
//
// **Why a read and not a second call to the spender.** Engine.spendKeyEpoch
// reads the node-wide ceiling FIRST and the payer's own budget second, so a
// ceiling refusal never reaches SpendUnheldKeyEpoch and `own` is therefore
// false for every payer at once while the ceiling is down — including an
// identity this node's own work check has already refused, whose own budget is
// long spent. The score conjunct at the call site is conjoined with
// `own` and so goes inert for the guilty along with the innocent. The
// repair is NOT to swap the two layers: SpendUnheldKeyEpoch mutates, so read
// first it would spend a per-payer credit for a refusal the shared ceiling
// caused, and TestAnAnnounceRefusalByTheSharedKeyEpochCeilingIsNeverScored
// measures that mutant at 26 of 30 refusals scored, -520 against a ban
// threshold of -100. What the ceiling arm needs is this: the same
// question SpendUnheldKeyEpoch answers on its way past, asked without the
// charge.
//
// The refill is the spender's own — refilledUnheldEpochs at one credit per
// period, which is pure, exactly as refilledServed is pure so that
// ServedBytesExhausted can be a genuine read — so the two agree on every input
// by construction rather than by a second copy of the arithmetic. Nothing is
// stored: no entry is created for an unknown key, no clock is re-anchored, and
// no lastSeen is touched, so calling this can neither plant an entry nor move
// the eviction order.
//
// An identity absent from the store has spent nothing, and a zero budget or a
// zero period is not exhausted — the same direction ServedBytesExhausted takes
// for the same reason, and the read-side complement of SpendUnheldKeyEpoch's
// zero arm admitting rather than refusing: a misconfigured store must not
// manufacture attributable refusals.
func (ps *PeerStore) UnheldKeyEpochsExhausted(key string, budget uint32, period, now uint64) bool {
	if key == "" || budget == 0 || period == 0 {
		return false
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	e, ok := ps.identity[key]
	if !ok {
		return false
	}
	spent, _ := refilledUnheldEpochs(e.unheldEpochs, e.unheldEpochsAt, period, now, 1)
	return spent >= budget
}

// SpendWorkEval charges one proof-of-work evaluation against an identity's
// per-connection work budget and reports whether it could be paid for.
//
// It is SpendUnheldKeyEpoch's twin — same keyspace, same bounded identity map,
// same eviction admission, same pure refill helper (refilledUnheldEpochs at one
// credit per period) — and it exists because that sibling has a hole this one
// covers. spendKeyEpoch charges the unheld-epoch budget only for announcements
// naming a key epoch this node is not working in, and exempts the working epoch
// outright; a distinct announcement in the working epoch therefore reaches the
// memory-hard work.Check with nothing in front of it, and one connection forces
// one RandomX evaluation per distinct announce at zero cost — the
// CPU-exhaustion face of the unbounded announce seen-set. This budget is
// unconditional on the epoch and is spent immediately ahead of work.Check, so
// it bounds that CPU per connection whichever epoch the header names.
//
// **This is the attributable tier-1 layer, not the bound on the aggregate.**
// The key is an identity, and an identity is free to mint, so N churned
// connections each spend a fresh budget for N x MaxWorkEvalsPerConn total — this
// layer bounds one static connection and localises its cost, and the churn-proof
// bound on the sum is Engine.spendWorkEval's node-wide ceiling above it, keyed
// on nothing, the twin of the unheld-key-epoch node ceiling over this budget's
// own sibling.
//
// key is what the evaluation is charged to: the peer's authenticated Ed25519
// identity where the caller has one and its connection address where it does
// not, exactly as SpendUnheldKeyEpoch and the reply-byte budget key, and for
// the reason the identity keying records — an identity survives a reconnect the
// address does not.
//
// Refusal is a PRICE and not a judgement, and the caller keeps it that way: a
// refused announcement is dropped at CostBudgeted without a score and without
// being entered into seenBlocks or pending, so the same valid block stays
// obtainable — re-announced by this connection once the budget refills, or by
// any other peer against its own fresh budget, or fetched by body. Scoring here
// would ban the honest peers a node behind the chain depends on, which is the
// failure that reverted I7-H4's tip-window guard, and the budget is generous
// enough (MaxWorkEvalsPerConn, refilling at the honest announce rate of one per
// TargetBlockSeconds) that an honest connection never reaches it.
//
// A zero budget or a zero period admits rather than refuses, the direction
// SpendUnheldKeyEpoch takes for the same reason: a store misconfigured into
// refusing every announcement is a node that stops evaluating gossip, which is
// a worse failure than the one unbounded work is.
func (ps *PeerStore) SpendWorkEval(key string, budget uint32, period, now uint64) bool {
	if key == "" || budget == 0 || period == 0 {
		return true
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	if ps.identity == nil {
		ps.identity = map[string]identityEntry{}
	}
	e, ok := ps.identity[key]
	if !ok && len(ps.identity) >= MaxIdentities {
		victim, found := ps.findEvictableIdentityLocked()
		if !found {
			return false
		}
		delete(ps.identity, victim)
	}
	e.workEvals, e.workEvalsAt = refilledUnheldEpochs(e.workEvals, e.workEvalsAt, period, now, 1)
	e.lastSeen = int64(now)
	if e.workEvals >= budget {
		// Stored even on the refusal, so the refill clock keeps advancing for a
		// connection that keeps asking — the same reason SpendUnheldKeyEpoch
		// writes back on its refusal.
		ps.identity[key] = e
		return false
	}
	e.workEvals++
	ps.identity[key] = e
	return true
}

// MarkWorkRefusedKey records that an identity sent a block announcement whose
// proof of work the work check refused.
//
// The setter for identityEntry.workRefused; see there for why the fact is kept
// at all. Admission is AdjustKey's, and the entry it plants sits at score zero,
// so it is given up before any ban or any earned goodwill — losing it is a
// return to the default this identity had before it was caught, which is the
// safe direction for a store under pressure.
func (ps *PeerStore) MarkWorkRefusedKey(key string, now uint64) {
	if key == "" {
		return
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	if ps.identity == nil {
		ps.identity = map[string]identityEntry{}
	}
	e, ok := ps.identity[key]
	if !ok && len(ps.identity) >= MaxIdentities {
		victim, found := ps.findEvictableIdentityLocked()
		if !found {
			return
		}
		delete(ps.identity, victim)
	}
	e.workRefused = true
	e.lastSeen = int64(now)
	ps.identity[key] = e
}

// WorkRefusedKey reports whether this identity has had an announcement refused
// by the work check.
//
// An identity absent from the store has not, which is the same default
// BannedKey and ServedBytesExhausted give a key they have never seen.
func (ps *PeerStore) WorkRefusedKey(key string) bool {
	if key == "" {
		return false
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	return ps.identity[key].workRefused
}

// identityWorth is how much an entry can still change an outcome: its
// distance from zero.
//
// Both ends of the range are load-bearing, and getting that wrong is what the
// two previous versions of this policy each got wrong in opposite directions.
// A score at or under ScoreBanThreshold is the answer BannedKey exists to
// give. A score up at ScoreCeiling is earned headroom — it is how many more
// penalties a peer with a long good history absorbs before it crosses the
// threshold, so discarding it does not merely forget something neutral, it
// halves an honest peer's budget. What is worth nothing is the entry in the
// middle: it answers BannedKey with the same "no" an absent key gets, and it
// buys its peer no headroom either. So the store's value lives at its
// extremes, and the middle is what it should give up first.
func identityWorth(e identityEntry) int {
	if e.score < 0 {
		return -e.score
	}
	return e.score
}

// lessWorthKeeping reports whether entry a (key ka) should be evicted before
// entry b (key kb): less worth first; a tie breaks on being staler; a full tie
// breaks on the identity's own key bytes, purely so eviction is deterministic
// and reproducible from a log — the same reason evictFurthestOrphanLocked
// (engine.go) and SelectDiverse's own sort both end in one.
//
// The staleness tie-break is not a security boundary and should not be read
// as one, nor should the key-bytes tie-break under it, which exists only so
// eviction is reproducible from a log. An earlier version of this comment
// claimed the tie-break let a peer escalate against a flood of one-shot
// identities, on the reasoning that the escalating peer is the one still
// sending and therefore the freshest of its tier. It is the freshest only
// until the next arrival, and measurement says so: one flood arrival between
// the target's messages — one TLS handshake apiece — keeps a peer at -20 out
// of the store indefinitely. No key grinding and no clock games are needed.
//
// That limit is inherent rather than a property of this ordering. A bounded
// store and free identities cannot both hold, so a sustained flood of fresh
// identities can always displace an entry that has not yet distinguished
// itself from one. What the ordering decides is how far it reaches, and this
// one confines it to the first tier: a peer that has taken one more penalty
// than the flood carries — worth 40 against worth 20 — is untouchable, and
// measured untouched across 12,288 arrivals. The previous ordering, lowest
// score first, had the opposite property, and it is worth recording as the
// reason this one is shaped the way it is: there, escalating made a peer the
// *preferred* victim, so the same flood evicted it at every tier, not just
// the first.
//
// None of this weakens what identity-keyed scoring claims, which is narrow: an ordinary
// reconnect — same key, new source port — no longer resets reputation. That
// needs no flood, and absent a flood escalation works against a full store.
// An attacker who can sustain this flood can already shed identity bans far
// more cheaply by rotating its own key every connection, which AdjustKey's
// doc comment concedes is free and unpreventable.
func lessWorthKeeping(a identityEntry, ka string, b identityEntry, kb string) bool {
	if wa, wb := identityWorth(a), identityWorth(b); wa != wb {
		return wa < wb
	}
	if a.lastSeen != b.lastSeen {
		return a.lastSeen < b.lastSeen
	}
	return ka > kb
}

// findEvictableIdentityLocked returns the entry the store gives up first, by
// lessWorthKeeping's ordering. Callers hold identityMu.
func (ps *PeerStore) findEvictableIdentityLocked() (string, bool) {
	var key string
	var entry identityEntry
	found := false
	for k, e := range ps.identity {
		if !found || lessWorthKeeping(e, k, entry, key) {
			entry, key, found = e, k, true
		}
	}
	return key, found
}

// AdjustKey changes a peer's score keyed by its authenticated Ed25519
// identity rather than its connection address, clamped exactly as Adjust.
//
// Adjust — and everything upstream of it, including Engine.Handle — is keyed
// by Conn.Addr, which for an inbound connection is "ip:ephemeral_port": a
// value the OS picks fresh on every reconnect, not the peer. A banned peer
// sheds that ban for the cost of one TLS handshake by reconnecting on a new
// source port; nothing about the ban itself has to change.
//
// The identity TLS actually authenticates — extracted by
// VerifyPeerCertificate and carried as Conn.PeerKey — does not change on
// reconnect, so a second, independent score keyed on it closes that gap:
// BannedKey still says yes after the ephemeral port changes, even once
// Banned(addr) has forgotten everything.
//
// Deliberately unpersisted, and deliberately not a replacement for the
// address-keyed store. A node's own peer key is ephemeral by design
// (docs/decisions/networking.md §10: regenerated every restart, never
// written to disk), so a reputation keyed to a peer's identity has no more
// meaning across this node's own restart than that peer's key does — it
// lives only as long as the process that observed it. The address-keyed
// store keeps doing everything it already did — dial selection, diversity,
// the persisted peer list — untouched.
//
// Bounded at MaxIdentities, and what it gives up when full is the entry worth
// least — nearest zero, then stalest. See identityWorth: a ban and a full
// goodwill balance are both worth keeping, and an entry in the middle is worth
// nothing to either reader or peer.
//
// A newcomer is never refused; something is always evicted for it. The
// alternative — admit only what is worth more than the cheapest entry held —
// looks tighter and is far worse: it lets an attacker freeze the store shut
// and disable identity banning outright, permanently, for 4096 connections.
//
// What is left is irreducible and is not claimed otherwise. Free identities
// and bounded memory cannot both be had, so an attacker who drives each of
// MaxIdentities throwaway identities all the way to the ban threshold — five
// invalid messages apiece, since one does not disconnect it — can push an
// older ban out. That is five times the price of the one cheap message the
// previous ordering charged, it buys one eviction rather than the whole
// store, and it cannot stop a new ban from being recorded.
func (ps *PeerStore) AdjustKey(key ed25519.PublicKey, delta int) {
	if len(key) == 0 {
		return
	}
	k := string(key)
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	if ps.identity == nil {
		ps.identity = map[string]identityEntry{}
	}
	e, ok := ps.identity[k]
	if !ok && len(ps.identity) >= MaxIdentities {
		// A newcomer is always admitted, by giving up the entry worth least.
		// Refusing it instead — which an earlier revision did, whenever the
		// newcomer was not worth more than the cheapest entry held — freezes
		// the store solid: fill it with entries at the ban threshold and no
		// first delta is ever worth more than -100, so nothing is admitted
		// again and no peer can ever be identity-banned for the life of the
		// process. 4096 connections and 20,480 invalid messages bought that,
		// permanently, and nothing here expires to undo it.
		victim, found := ps.findEvictableIdentityLocked()
		if !found {
			return
		}
		delete(ps.identity, victim)
	}
	e.score = clampIdentityScore(e.score + delta)
	e.lastSeen = ps.now().Unix()
	ps.identity[k] = e
}

// AdjustKeyNotBelow is AdjustKey with AdjustNotBelow's bound: a negative delta
// that will not carry the identity-keyed score past `floor` downward. Both
// tallies the unserved-body reap charges — the address (Engine.ReapUnservedBodies)
// and the identity (Node.reapUnservedBodies) — must be bounded, or the OR in the
// ban check (Banned(addr) || BannedKey(key)) still bans on the unbounded half.
func (ps *PeerStore) AdjustKeyNotBelow(key ed25519.PublicKey, delta, floor int) {
	if len(key) == 0 {
		return
	}
	k := string(key)
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	if ps.identity == nil {
		ps.identity = map[string]identityEntry{}
	}
	e, ok := ps.identity[k]
	if !ok && len(ps.identity) >= MaxIdentities {
		victim, found := ps.findEvictableIdentityLocked()
		if !found {
			return
		}
		delete(ps.identity, victim)
	}
	next := e.score + delta
	if next < floor {
		if e.score < floor {
			next = e.score
		} else {
			next = floor
		}
	}
	e.score = clampIdentityScore(next)
	e.lastSeen = ps.now().Unix()
	ps.identity[k] = e
}

// clampIdentityScore bounds a score to the same range Adjust bounds the
// address-keyed one to.
func clampIdentityScore(score int) int {
	if score > ScoreCeiling {
		return ScoreCeiling
	}
	if score < ScoreFloor {
		return ScoreFloor
	}
	return score
}

// BannedKey reports whether a peer identity has scored itself out. See
// AdjustKey. An empty key — there should never be one on a connection that
// completed its TLS handshake — is never banned, rather than panicking or
// being conflated with every other empty key. An identity absent from the
// store (never scored, or evicted to make room for a worse one) reads as
// score zero, i.e. not banned — the same default a never-seen address gets
// from Banned.
func (ps *PeerStore) BannedKey(key ed25519.PublicKey) bool {
	if len(key) == 0 {
		return false
	}
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	return ps.identity[string(key)].score <= ScoreBanThreshold
}

// Len returns how many peers are known.
func (ps *PeerStore) Len() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.peers)
}

// Get returns a copy of a peer record.
func (ps *PeerStore) Get(addr string) (Peer, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	p, ok := ps.peers[addr]
	if !ok {
		return Peer{}, false
	}
	return *p, true
}

// SelectDiverse chooses up to n addresses from distinct address groups, best
// first. It is the address-diversity selector, and it is what this node serves
// to a peer that asks for addresses (Engine.OnGetPeers).
//
// It deliberately does *not* apply the per-source bound SelectDialTargets
// applies. Whose gossip taught *this* node an address says nothing about the
// eclipse risk of the node receiving it, and applying the bound here throttles
// dissemination instead of an attacker: measured, a young node holding 500
// addresses across 256 /16s learned from one honest bootstrap peer answered a
// `get-peers` with 2 addresses instead of the 64 it is permitted, a 32×
// reduction in how fast honest addresses spread. The bound belongs on the dial
// path, where this node's own outbound slots are what is at stake. The answer
// is memoized for DiverseCacheTTL. It is served to whoever asks, so the cost of
// producing it must not scale with how often it is asked for: this is the only
// caller of selectLocked a remote peer can drive, and before the memo a 5-byte
// get-peers frame bought a snapshot and a sort of the entire store - measured
// on this revision at 3.0 ms and 429 KB end to end through Engine.Handle at
// MaxPeers, superlinear in store size, so a node that had done the diversity
// work the eclipse defence depends on was the softer target.
//
// The memo cannot be steered by a requester and cannot outlive a ban:
//
//   - It is filled by selectLocked, unchanged. Every entry in it satisfied the
//     one-slot-per-group rule at the moment it was chosen, and the filter
//     applied on the way out only ever removes entries, so the diversity
//     guarantee survives: a subset of a set with at most one address per group
//     has at most one address per group.
//   - It is filtered against the live store on every hit, so an address that
//     has since been banned or evicted is not served from it. That is the one
//     staleness that would matter, and it costs at most n map lookups rather
//     than a sort of the store.
//   - Nothing a requester sends selects, orders or extends it. A peer chooses
//     only *when* to ask, and asking more often now returns the same bytes for
//     less of this node's work, which is the point.
//
// The residual, stated as a cost rather than argued away: a hit can return
// fewer addresses than a rebuild would, because entries drop out of the live
// filter and nothing replaces them until the TTL expires. The floor is what the
// store still holds, the window is DiverseCacheTTL, and the receiver of a short
// list is not harmed by it - it asks again next interval.
//
// A caller that passes exclude gets a fresh selection: exclude is a property of
// that caller's question, not of the store, and caching per-question is how a
// memo turns back into the unbounded work it replaced.
func (ps *PeerStore) SelectDiverse(n int, exclude map[string]bool) []string {
	if len(exclude) > 0 {
		return ps.selectLocked(n, exclude, nil, false)
	}
	ps.diverseMu.Lock()
	defer ps.diverseMu.Unlock()
	now := ps.now()
	if ps.diverse != nil && ps.diverseN == n && now.Sub(ps.diverseAt) < DiverseCacheTTL {
		return ps.liveSubset(ps.diverse)
	}
	out := ps.selectLocked(n, nil, nil, false)
	ps.diverse, ps.diverseN, ps.diverseAt = out, n, now
	return ps.liveSubset(out)
}

// liveSubset drops from a memoized selection anything the store no longer holds
// or has since banned, and copies what is left so the caller cannot write
// through into the memo.
func (ps *PeerStore) liveSubset(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	ps.mu.RLock()
	for _, a := range addrs {
		if p, ok := ps.peers[a]; ok && !p.Banned() {
			out = append(out, a)
		}
	}
	ps.mu.RUnlock()
	return out
}

// SelectDialTargets chooses up to n *dial* targets, subject to both bounds:
// one slot per address group, and at most MaxPerSource slots for everything
// one teller gossiped.
//
// held is the addresses this node already holds outbound connections to, and
// passing it is not optional bookkeeping — it is what makes either bound a
// bound at all. Both are per-call counters, and the dial loop calls this once
// per round with the peers it is already connected to in exclude, which drops
// them from the candidate list *before* the counters are built. Every round
// therefore started both budgets at zero and handed the same teller another
// MaxPerSource slots. Measured on the revision that did this: a single teller
// reached 2, then 4, then 6, then 8 of 8 outbound slots over four dial rounds
// — about eight seconds at the default DialInterval — and the same laundering
// applied to the /16 bound that predates this, so one hosting range could fill
// every outbound slot the same way, which is what the MUST in wire.md §11 is
// about.
//
// Charging held connections up front makes the budget span the connections
// rather than the call. exclude still says "do not return these"; held says
// "these already spent budget".
//
// held is the *outbound* set specifically, not every connection. An inbound
// connection is chosen by the peer, not by this node, so counting it would let
// an attacker with connections from many groups veto this node's dials into
// exactly those groups — spending this node's budget on its behalf.
func (ps *PeerStore) SelectDialTargets(n int, exclude map[string]bool, held []string) []string {
	return ps.selectLocked(n, exclude, held, true)
}

func (ps *PeerStore) selectLocked(n int, exclude map[string]bool, held []string, bySource bool) []string {
	// Snapshot the fields, not the pointers.
	//
	// This used to collect *Peer and then sort and read Score, Failures and
	// Addr through them *after* releasing the lock, while Adjust, MarkFailed
	// and MarkConnected write those same fields from the gossip and dial
	// goroutines. That is an unsynchronised read deciding who this node dials —
	// the eclipse defence choosing on a torn value — and it is the shape of the
	// race this project already shipped once in consensus state.
	//
	// The field widths are not decoration either. This slice is allocated at
	// len(ps.peers) on a path a `get-peers` frame reaches (SelectDiverse), and
	// TestGetPeersRebuildDoesNotReDeriveEveryAddressGroup holds the per-rebuild
	// allocation under a ceiling at MaxPeers — so seq and connected are paid
	// for by narrowing score, failures and met into the padding the three
	// machine words already wasted, and the struct is the same 72 bytes it was
	// before the eclipse-cluster pass. Every narrowed field is bounded at its
	// source: Score is clamped to [ScoreFloor, ScoreCeiling], Failures to [0,
	// MaxStoredFailures] and dialRank returns 0..3, so none of the conversions
	// below can wrap.
	type snap struct {
		addr  string
		src   string
		group string
		// seq is Peer.Seq: the order this node first learned the address. It
		// is carried here because it is the selection path's final tie-break
		// — see the sort below.
		seq      int64
		score    int32
		failures int32
		met      int8
		// connected records that this node has itself completed a connection
		// to this address in this process (metInProcess). It exempts the entry
		// from the per-teller bound — see the srcCount pass below.
		connected bool
	}
	ps.mu.RLock()
	candidates := make([]snap, 0, len(ps.peers))
	for _, p := range ps.peers {
		if p.Banned() || exclude[p.Addr] {
			continue
		}
		// An observed socket is evidence that a peer exists, not an address to
		// dial — one admission door, and no unearned rank. It keeps its entry —
		// Node.serve consults Banned(conn.Addr) on it and Engine.Handle scores
		// it — and loses only its candidacy. The same filter serves
		// SelectDiverse, so this node also stops gossiping ephemeral source
		// ports to peers that ask for addresses.
		if p.observed {
			continue
		}
		candidates = append(candidates, snap{
			addr:      p.Addr,
			src:       p.Src,
			group:     p.diversityGroup(),
			score:     int32(p.Score),
			met:       int8(dialRank(p)),
			failures:  int32(p.Failures),
			seq:       p.Seq,
			connected: metInProcess(p),
		})
	}
	ps.mu.RUnlock()

	// Shuffle before sorting, and sort *stably*, so that candidates the
	// comparator below cannot separate come out in a fresh random order on
	// every call rather than in map-iteration order.
	//
	// This is the second half of the tie-break repair. The unproven tier is where an
	// eclipse is decided and every entry in it has an identical record, so a
	// residual order that is a deterministic function of anything the
	// gossiping peer supplies is a residual order the gossiping peer controls.
	// Arrival order (seq) removes the address from that decision; the shuffle
	// removes what arrival order cannot separate — every entry restored from
	// peers.json shares one arrival bucket by construction (renumberLocked), so
	// without it a hostile file would still get to pick the winner among them
	// by whatever order the map happened to yield. Randomising a genuine tie
	// costs nothing: the entries are indistinguishable by record, which is
	// exactly what makes the tie a tie.
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	// Best first: score, then a peer this node has actually completed a
	// connection to, then fewest failures, then *arrival order* — earliest
	// learned first.
	//
	// The evidence rank sits under Score and is a rank, not a timestamp, on
	// purpose. Score no longer survives a restart, so without it the first
	// post-restart dial round would rank on the address, and an address is the
	// one thing an attacker picks for free: measured, a node with eight peers
	// it had met spent 8 of 8 outbound slots on invented gossip addresses that
	// merely sorted low. Reading it as recency rather than as a bit would just
	// move the forgery — a file claiming a huge last_seen would out-rank the
	// peers this node really met, instead of tying with them.
	//
	// The final key used to be `a.addr < b.addr`, and that was the whole
	// eclipse. docs/spec/wire.md §11 states as a MUST that the final
	// tie-break "MUST NOT be anything the gossiping peer chooses, the address
	// included"; the rule had been discharged on the eviction path — betterVictim
	// ranks by Peer.Seq — and never on the selection path, whose snapshot did not
	// even carry Seq. An honest address learned by gossip and not yet dialled is
	// identical by score, evidence rank and failures to a freshly invented one,
	// so the decision fell entirely to a string the teller picked: measured, 8
	// honest addresses from 8 honest tellers against 8 flood addresses from 4
	// source groups returned 8 of 8 flood addresses and 0 honest ones.
	//
	// Seq is the same key betterVictim already uses and for the same reason: it
	// is the one property of a gossiped address the sender cannot choose after
	// the fact. The sign is opposite there because that is a victim comparator
	// (newest given up first) and this is a preference (earliest learned first).
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if a.met != b.met {
			return a.met > b.met
		}
		if a.failures != b.failures {
			return a.failures < b.failures
		}
		return a.seq < b.seq
	})

	// Two independent bounds, and they are not the same bound twice.
	//
	// seenGroup is address diversity: one slot per /16, so a thousand addresses
	// in one hosting range count once. It prices addresses an attacker *owns*.
	//
	// srcCount is source diversity: at most MaxPerSource slots for everything
	// one gossip source told this node, however many distinct /16s that
	// amounts to. It prices addresses an attacker merely *claims*, which is
	// the half address diversity cannot reach — inventing twenty IPv4 strings
	// in twenty /16s costs one frame, and before this bound it bought 8 of 8
	// outbound slots against a victim that already knew three honest peers.
	// See MaxPerSource.
	//
	// **An address this node has itself connected to is exempt from the source
	// bound, and only from that one.** Peer.Src is stamped once, by the first
	// teller, and never updated — not by a later teller and, before this, not
	// by MarkConnected either. So an attacker that gossips honest addresses
	// *first* owns their Src label for the life of the entry, and MaxPerSource
	// then bounds all of them together: measured, 20 honest addresses
	// first-told by one attacker connection, re-gossiped by 20 distinct honest
	// tellers and then all 20 actually connected, yielded exactly 2 dial
	// targets, and 0 on the next round.
	//
	// The rule this restores is the one the whole file is built on: evidence
	// this node gathered itself outranks a stranger's claim. Src prices an
	// address the teller merely *claimed*; once this node has completed a
	// connection to that address, the claim has been checked and the entry is
	// no longer something the teller invented for free. Address diversity is
	// untouched — the exemption is from srcCount, never from seenGroup — so an
	// attacker cannot widen it without owning addresses in distinct /16s, which
	// is exactly the cost address diversity exists to charge. It is the same
	// promotion Bitcoin Core's addrman makes when an address moves from `new`
	// (bucketed by source group) to `tried` (bucketed by its own group).
	//
	// **The exemption is on the candidate side only; a held connection is still
	// charged to its teller.** The two are different questions and relaxing
	// both would re-create the diversity hole with an extra step. The held
	// charge is what makes either budget span the rounds rather than the call —
	// see this function's own doc comment — so exempting a held connection too
	// would let a teller *convert* its allowance into more allowance: dial 2,
	// have them answer, come back next round with the budget clear, and ratchet
	// 2 → 4 → 6 → 8 exactly as the pre-held revision measured. Charging held
	// keeps the teller's claims bounded at MaxPerSource for as long as this
	// node holds them, while the candidate exemption keeps an address this node
	// has itself reached from ever being *refused* on account of who first
	// mentioned it. The ratchet needs both halves; the first-teller cap needs
	// only the second, so only the second moves.
	seenGroup := map[string]bool{}
	srcCount := map[string]int{}
	out := make([]string, 0, n)
	// Charge what is already held before spending anything new.
	if len(held) > 0 {
		ps.mu.RLock()
		for _, a := range held {
			seenGroup[AddressGroup(a)] = true
			if p, ok := ps.peers[a]; ok && p.Src != "" {
				srcCount[p.Src]++
			}
		}
		ps.mu.RUnlock()
	}
	for _, p := range candidates {
		if len(out) >= n {
			break
		}
		g := p.group
		if seenGroup[g] {
			continue
		}
		if bySource && p.src != "" && !p.connected && srcCount[p.src] >= MaxPerSource {
			continue
		}
		seenGroup[g] = true
		if !p.connected {
			srcCount[p.src]++
		}
		out = append(out, p.addr)
	}

	// If diversity alone cannot fill the slots, fall back to the best remaining
	// peers rather than sitting under-connected — being under-connected is its
	// own eclipse risk (wire.md §11). But the fallback must not hand the
	// constraint away entirely: it fires precisely when the store is thin — a
	// fresh or just-restarted node — which is the state in which an eclipse is
	// cheapest, so an unconstrained fallback would let one group take every
	// remaining slot for the cost the diverse pass above was built to price
	// higher. MaxFallbackPerGroup bounds it instead of dropping it.
	if len(out) < n {
		taken := map[string]bool{}
		groupCount := map[string]int{}
		for _, a := range held {
			groupCount[AddressGroup(a)]++
		}
		for _, a := range out {
			taken[a] = true
			groupCount[AddressGroup(a)]++
		}
		for _, p := range candidates {
			if len(out) >= n {
				break
			}
			if taken[p.addr] {
				continue
			}
			g := p.group
			if groupCount[g] >= MaxFallbackPerGroup {
				continue
			}
			// The source bound is *not* relaxed here, and that is the
			// difference between this fallback and no fallback at all. The
			// fallback fires exactly when the store is thin — a cold or
			// freshly restarted node — which is both the state where
			// under-connection hurts and the state an eclipse is cheapest in.
			// Relaxing the per-group bound there is safe, because the groups
			// it hands out still had to be owned. Relaxing the per-source
			// bound would hand every remaining slot back to whichever peer
			// gossiped the most invented addresses, which is the attack this
			// pass would then be reintroducing one line below the pass that
			// stops it.
			//
			// So this can return fewer than n. That is deliberate, and it is
			// the same trade MaxFallbackPerGroup already makes: wire.md §11
			// asks a node to keep dialling toward its outbound target, not to
			// dial anything at all rather than dial less. An under-connected
			// node syncs slowly; an eclipsed one accepts a false chain.
			//
			// The connected exemption above carries here unchanged, and for
			// the same reason: it is not a relaxation of the bound but a
			// statement that an address this node has itself reached is no
			// longer only a teller's claim.
			if bySource && p.src != "" && !p.connected && srcCount[p.src] >= MaxPerSource {
				continue
			}
			out = append(out, p.addr)
			taken[p.addr] = true
			groupCount[g]++
			if !p.connected {
				srcCount[p.src]++
			}
		}
	}
	return out
}

// invalidGroup is the single group every unparseable address collapses into.
const invalidGroup = "invalid"

// AddressGroup returns the diversity group of an address: the /16 for IPv4,
// the /32 for IPv6, and a single shared group for anything that is not a
// parseable IP.
//
// It used to return the raw host for anything unparseable, so every non-IP
// string became its own brand-new diversity group and an attacker gossiping
// arbitrary junk could mint one group per string, winning a slot in
// SelectDiverse's primary pass for each — ahead of real peers, and without the
// per-group fallback constraint above ever being consulted. PeerStore.Add now
// refuses anything but a real IP:port before it ever reaches the store, so this
// branch should be unreachable for addresses that came through PeerStore; it
// stays a shared, unmintable group rather than a raw pass-through as a second
// line of defence for any caller that hands SelectDiverse or AddressGroup
// something the store did not validate.
func AddressGroup(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return invalidGroup
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return invalidGroup
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IP(append([]byte(nil), v4[0], v4[1], 0, 0)).String() + "/16"
	}
	masked := ip.Mask(net.CIDRMask(32, 128))
	return masked.String() + "/32"
}
