package p2p

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/ssz"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/verify"
)

// Engine is the protocol logic: what a node does with a message, independent of
// how the bytes arrived.
//
// Separating it from the transport is what makes the adversarial cases testable
// at all. A partition, a heal, an eclipse and a flood of invalid certificates
// are all just message schedules, and a test that can control the schedule
// deterministically is worth more than one that hopes a socket cooperates.
type Engine struct {
	Chain  *chain.Chain
	Pool   *mempool.Pool
	Peers  *PeerStore
	Engine pow.Engine
	// work memoizes proof-of-work verdicts by block id.
	//
	// It is not an optimisation in the ordinary sense. Hash-first relay checks
	// an announcement's header and then checks the same header again when the
	// body lands, which was free against the BLAKE3 stand-in and is about
	// 55 ms per relayed block against RandomX (core/pow/randomx records the
	// measurement). Citations repeat across blocks and are the same story.
	//
	// Sound because the key comes from the header's height, so the verdict is a
	// pure function of the header's bytes — see node/verify's own note on what
	// this would cost under upstream RandomX's key-block schedule, where it
	// would be unsound rather than merely unhelpful.
	work *verify.WorkWasChecked
	// ListenAddr is advertised in the handshake; empty means inbound-only.
	ListenAddr string
	// Now is this node's wall clock, and the only one in the block path. It is
	// a field rather than a call to time.Now so that a test can drive the
	// withhold queue's release without sleeping. Nil means time.Now.
	//
	// The clock lives here and stops here: nothing below the engine —
	// node/chain, core/fold, core/pow — reads a clock, and the future-time rule
	// is precisely the rule that cannot be evaluated without one, which is why
	// it is a withhold rather than a validity rule (R1-H2).
	Now func() time.Time

	mu sync.Mutex
	// seenBlocks deduplicates gossip. Without it a flood re-propagates forever.
	//
	// The value is the wall-clock time the id was entered, and it is the whole
	// of the unbounded-seen-set fix: the set used to be a
	// `map[types.Hash]struct{}` written once per accepted announcement
	// (engine.go's accept return) and **never** deleted, capped or aged
	// anywhere — `ReapUnservedBodies` reaped `pending` and left this untouched,
	// so every distinct valid header a peer flooded in a working key epoch
	// (uncharged by the key-epoch budget, which exempts the epochs this node is
	// working in) minted an immortal entry, an unbounded leak on a
	// remote-reachable ingress path. That is the same shape `seenCerts` carried
	// and shed (OnCertificate's dedup comment): "written once, never pruned,
	// never bounded". Certificates could dedup against the pool and the chain's
	// own TTL'd seen-set, both already bounded; a block announcement has no
	// equally cheap authoritative record to consult *before* the body arrives —
	// the chain does not hold a block it has only been told about — so this
	// keeps the residual p2p set the block path needs and bounds it directly
	// instead, in the discipline the orphan pool and the work cache already
	// use: a hard cap (MaxSeenBlocks, evicting the oldest) so the size never
	// exceeds N however fast the flood, and a TTL (SeenBlockTTL, swept by
	// ReapUnservedBodies on the same ticker that reaps pending) so the honest
	// steady state stays near the announcement-then-body working set rather
	// than growing to the cap.
	//
	// The read semantics are unchanged, which is what preserves the dedup
	// liveness both R1-H2 and the body-path fast dedup depend on: an id is
	// still entered only on the accept return and still kept OUT of the set on
	// every future-dated, over-budget or work-refused path, so a re-announcement
	// that arrives once the clock or the budget catches up is not deduped away.
	// The only behavioural change is that an entry may be forgotten after the TTL
	// or under cap pressure, which re-propagates or re-fetches a block at most
	// once more — a liveness-safe redundancy, never a loss.
	//
	// One further deletion, on the same liveness side of the ledger: when
	// ReapUnservedBodies charges an announcer for a body it never served, it
	// drops that id from here as well, so the announcement is forgotten in both
	// maps at once and a late body is not deduped away by a window that has
	// already expired — see that function's note on forgetting both halves of an
	// announcement at once.
	seenBlocks map[types.Hash]time.Time
	// pending holds announced blocks whose bodies have not arrived, keyed by
	// block id, together with who announced each one and when. The peer and
	// timestamp are what ReapUnservedBodies needs to charge the right peer
	// once the window has passed — wire.md §9 rule 5: a peer that advertises
	// headers it will not back MUST be scored down.
	pending map[types.Hash]announcedBody
	// tipTargetTip, tipTargetID and tipTarget memoize the difficulty rule's
	// answer for the block after one particular tip, so that
	// OnBlockAnnounceFrom's re-derivation costs a struct comparison rather than
	// a window read and a hash.
	//
	// **The memo is the affordability of the check, not a tidy-up.** The rule
	// needs `DifficultyWindow+1` headers, and `chain.RecentHeaders` reads them
	// one canonical id and one header at a time out of the store — a hundred and
	// eighty store reads and ninety-one header decodes, driven by a 232-byte
	// message an unprivileged peer sends for free. Measured as a ratio against
	// the parse and the id hash that every announcement already pays — a ratio
	// because a wall-clock number on a shared machine is not evidence — deriving
	// from the window costs **at least 30x** that floor and allocates at least
	// 100x it, while through this memo it costs about a fifth of it and allocates
	// a third. Lower bounds and not estimates: an independent run of the same
	// benchmarks measured 50.8x the CPU, 101.5x the bytes and 182x the
	// allocations, so the figure to carry forward is the direction and not the
	// digit. Closing an asymmetric-cost hole with a smaller one is not closing
	// it. announcetarget_bench_internal_test.go is the instrument.
	//
	// **Keyed on the whole tip header rather than on its id**, because the id is
	// the expensive half: `Header.ID()` is an SSZ marshal and a hash, and a
	// header is fixed-width and comparable, so the memo answers without either.
	// One entry, self-invalidating on any tip move, and its size is independent
	// of how many peers announce.
	tipTargetTip types.Header
	tipTargetID  types.Hash
	tipTarget    u256.U256
	tipTargetOK  bool
	// tips records what each peer advertised in its handshake, which is how the
	// sync driver decides who is worth catching up with.
	tips map[string]PeerTip
	// orphans holds blocks that do not extend this node's tip.
	//
	// They cannot be judged one at a time: a competing branch is heavier than
	// what it replaces only *in total*, so every individual block on it loses
	// on work and would be rejected. A node that judged block-by-block could
	// never adopt a longer fork at all — it would sit on its own branch
	// forever, which is a partition that never heals.
	//
	// The pool is bounded, windowed and target-filtered (R4-H1). An orphan's
	// declared Target cannot be checked against the LWMA rule without its 90
	// ancestor headers, so without those bounds an attacker declares a trivial
	// target, produces thousands of structurally-valid "blocks" at no cost, and
	// exhausts memory at a price it sets rather than one the protocol sets.
	// The declared work is forgeable by the same route, so work-based eviction
	// alone does not close it.
	//
	// These are mitigations, not the fix. The fix is headers-first sync, where
	// the LWMA target sequence is computable link by link and "orphan bodies"
	// stop existing as a concept.
	orphans      map[types.Hash]*types.Block
	orphanBytes  int
	orphanLimits OrphanLimits

	// withheld holds blocks dated beyond the future-time limit, keyed by id.
	// See withhold.go: they are neither accepted nor rejected, and the two
	// pools are separate because the questions are separate — an orphan is
	// waiting for a *parent* and may need it forever, a withheld block is
	// waiting for a *clock* and has a known release time. Their bounds are
	// independent for the same reason: a flood of one must not evict the other.
	// A block can be both, and the withhold check runs first, so it is held
	// here and never reaches the orphan pool until it is judgeable — which
	// makes the cheaper surface the one an attacker cannot reach.
	withheld       map[types.Hash]*withheldBlock
	withheldBytes  int
	withholdLimits WithholdLimits

	// partial holds in-flight chunked block transfers, per peer and then per
	// block id. Each buffer is bounded by the consensus byte capacity, the
	// transfers per peer by MaxTransfersPerPeer, and the peers by
	// MaxPartialTransfers — reassembly must never be a cheaper allocation for
	// the sender than the single-frame path it replaces.
	//
	// **Keyed by block id and not by peer alone**, because one buffer per peer
	// is a bookkeeping choice that an honest peer pays for. Every accepted
	// announcement fires its own `get-block`, and nothing bounds how many a
	// peer may have in flight, so two overlapping fetches — a fork, or any
	// burst of announcements — would interleave: the second transfer's chunk 0
	// would evict the first, and the first's next chunk would then arrive
	// continuing nothing. Both fetches stall, and the peer that served them
	// correctly is charged for it.
	partial map[string]map[types.Hash]*partialBlock
	// transferSeq orders transfers for eviction within a peer.
	transferSeq uint64
	// partialBytes is the total held across every reassembly buffer, bounded
	// by MaxReassemblyBytes. Counts and byte budgets are different bounds and
	// only the second one is memory, which is the same reason the orphan pool
	// beside it carries both.
	//
	// It counts the capacity the buffers *own*, not the chunk lengths that were
	// delivered into them: a budget that counts what a sender said it sent
	// bounds a fraction of what this node holds, and the fraction is the
	// sender's to choose. wire.md §9 rule 8, as amended, requires "the count
	// MUST be of the block's own length and not of a copy's capacity" —
	// growTransfer satisfies that by leaving no capacity beyond the length, and
	// both readings coincide as a result. What stays outside both is the
	// runtime's size class under the allocation, which no Go program can
	// observe.
	partialBytes int

	// futureAnnounced, syncWithheld, futureWithheld, withholdOverflow and
	// beyondHorizon count the messages this node saw dated ahead of FTL, split
	// by which path refused each one; maxSkewSeconds is the largest gap seen between such a
	// block's timestamp and this node's clock, and skewGroups is the set of
	// address groups they came from.
	//
	// They exist because the withhold path is sized to absorb clock skew — see
	// WithholdLimits.HorizonSeconds, "ordinary clock skew, even gross skew, is
	// held rather than dropped" — so blocks arriving ahead of it are the signal
	// that this node's own clock is the outlier. Before this sensor that condition was
	// completely silent: holding a block is not a validity judgement and scores
	// nobody, so nothing logged and nothing counted, and a node slow past the
	// horizon simply stopped seeing gossip.
	//
	// **Five counters, because the failure starts long before the horizon, on a
	// different message, and on a second ingress entirely.** Gossip is
	// hash-first, so the first thing a slow node sees dated ahead is an
	// *announcement*, dropped here without a body ever being requested
	// (futureAnnounced) — and on a node whose only peer is the block's origin
	// it is the only thing it ever sees. Above FTL a body that does arrive is
	// queued and released late, so the node runs permanently behind while
	// losing nothing (futureWithheld). Once the queue is full — MaxBlocks or
	// MaxBytes, whichever binds — the rest are dropped (withholdOverflow). Past
	// the horizon they are dropped outright (beyondHorizon). And headers-first
	// sync, a separate ingress entirely, spends whole passes taking nothing
	// (syncWithheld), which is the half the slow-clock stall is about.
	// Measured, a node between the first two withhold bounds counted zero on a
	// horizon-only counter while carrying a standing backlog of tens of blocks;
	// the tables are on the record* functions in withhold.go.
	//
	// **skewGroups is the discriminator, and no count is one.** A gap is the
	// sender's clock plus this node's error, so neither a single block nor a
	// large number of them says which end is wrong. What says it is *breadth*:
	// a slow local clock makes every peer look ahead at once, whereas a peer
	// dating blocks forward — the median-ratchet shape, at now+10^9 — is one
	// sender among many. Grouped by /16 rather than by address, because an
	// ip:port lets one host be several senders for the price of a second
	// socket. Bounded, because a set keyed on what a peer chooses is memory the
	// peer prices.
	//
	// It does not partition such a node. The finding says "the node stays at its
	// height", and it does not: node/sync.ValidateHeaders returns
	// ErrHeadersWithheld only when the FIRST header of a range is too far
	// ahead; otherwise it truncates and the pass proceeds, so the node keeps
	// syncing every header dated at or below local_now+FTL. It tracks the chain
	// permanently lagged by roughly the skew — quieter and longer-lived than a
	// partition, and the reason counters are the fix rather than a refusal.
	// connSet is the concurrent connection set the Node above this Engine will
	// hold — MaxInbound + 2*MaxOutbound — pushed in by Node.publishConnectionSet
	// the same way dialledGroups is, and read only by unheldKeyEpochCeiling.
	// Zero means nothing has published yet and the defaults apply.
	//
	// Here rather than as a package constant because the ceiling below is the
	// connection set multiplied by a per-payer budget, and a bootstrap node
	// raising MaxInbound was getting a ceiling sized for a set it does not run:
	// see unheldKeyEpochCeiling for the measurement.
	connSet int
	// unheldEpochs is how many never-held proof-of-work key epochs this node
	// has agreed to build for announcements inside the current window, added
	// over every sender, and unheldEpochsAt is the second that level was last
	// settled at. unheldKeyEpochCeiling is the ceiling and the refill rate and
	// says why they are those numbers; chargeNodeKeyEpoch is the only writer
	// and nodeKeyEpochsExhausted the only other reader.
	//
	// One counter and not a map, deliberately. Every other budget in this
	// package is keyed on something — an address, an address group, an
	// identity — and the measurement is that each of those is a currency the
	// sender either mints or shares. This one is keyed on nothing, so there is
	// no table to evict from, no eviction rule to use as a suppression lever,
	// and no honest-address distribution needed to size it.
	unheldEpochs   uint32
	unheldEpochsAt uint64
	// nodeWorkEvals is how many block-announce proof-of-work evaluations this
	// node has agreed to run inside the current window, added over every sender
	// at once, and nodeWorkEvalsAt is the second that level was last settled at.
	// workEvalCeiling is the ceiling and the refill rate; chargeNodeWorkEval is
	// the only writer and nodeWorkEvalsExhausted the only other reader.
	//
	// **One counter keyed on nothing, and that is the whole of the work-eval
	// budget's second layer.** The per-connection budget beside it
	// (identityEntry.workEvals) is keyed on the payer, and the measurement is
	// that any per-identity key is a currency the sender mints for the price of
	// a handshake: N fresh identities each spend a fresh MaxWorkEvalsPerConn,
	// so the aggregate work is N x MaxWorkEvalsPerConn, linear in identities
	// and unbounded because keypairs are free — the per-connection budget
	// bounds one static connection and nothing about the sum. This counter is
	// the sum's bound. It is shared by every sender, so identity churn has no
	// per-identity multiplier to aggregate against it, exactly as unheldEpochs
	// is the churn-proof layer over the per-identity key-epoch budget. Sized
	// against CPU time rather than against the connection set — see
	// workEvalCeiling.
	nodeWorkEvals   uint32
	nodeWorkEvalsAt uint64
	// servedBytes is how many reply bytes this node has handed out inside the
	// current window, added over every peer at once, and servedBytesAt is the
	// second that level was last settled at. replyByteCeiling is the ceiling
	// and says why it is that number; chargeNodeServedBytes is the only writer
	// and nodeServedBytesExhausted the only other reader.
	//
	// One counter and not a map, for the reason unheldEpochs above is one: the
	// measurement is that the per-identity reply budget is keyed on an Ed25519
	// identity, and an identity is free to mint, so bounding the rate per
	// identity does not bound the total. This layer is keyed on nothing a
	// sender presents, so there is no table to evict from and no eviction rule
	// to use as a suppression lever — which is also what answers the eviction
	// lever, since a budget shed through the identity store's eviction is
	// re-bought under a ceiling that has no eviction at all.
	servedBytes      uint64
	servedBytesAt    uint64
	futureAnnounced  uint64
	syncWithheld     uint64
	futureWithheld   uint64
	withholdOverflow uint64
	beyondHorizon    uint64
	maxSkewSeconds   uint64
	// skewGroups maps each sending address group to one address seen from it,
	// so a caller can match agreement against the exact peers it dialled while
	// still counting breadth by group.
	skewGroups     map[string]string
	firstSkewGroup string
	// dialledGroups is the address groups this node initiated connections to,
	// pushed in by the Node (SetDialledGroups). Evidence from them is exempt
	// from the maxSkewGroups cap, because a cap that fills first-come is a
	// suppression lever for anyone willing to send first.
	dialledGroups map[string]struct{}

	// Forwarded counts the verdicts that left through Handle or
	// ReleaseWithheld with Forward set — the two paths a Node uses, and the
	// two that countVerdict is called from.
	//
	// Said that precisely on purpose. The On* judges are exported, so a
	// verdict obtained by calling one directly is *not* counted, exactly as it
	// is not scored. Writing "every verdict this engine returns" would promise
	// a property nothing enforces, which is the mistake this field has already
	// made twice.
	//
	// It counts the *decision* to relay, not a relay that completed. The two
	// differ: node.go's serve loop sends a Verdict's Reply before it
	// broadcasts, and abandons the connection if that send fails, so an
	// announcement can be counted here and never leave. Naming the decision is
	// deliberate — it is the quantity the engine can actually observe, and a
	// counter that claims more than its own layer knows is the defect this
	// field already had once.
	//
	// It deliberately has no Dropped counterpart. One existed and was removed
	// rather than repaired: nothing in the tree ever read it, it missed roughly
	// ten refusal paths in OnBlock alone (unmarshal failure, ErrLocal, all
	// three orphan refusals, the assembleBranch miss, four ConsiderBranch
	// errors), and it counted a withheld block as dropped even when that block
	// was later released and accepted — so a block this node went on to build
	// its own tip from was recorded as a drop. A counter that is read by
	// nothing and wrong for the cases it does cover is worse than no counter,
	// because it invites exactly the reading it cannot support.
	//
	// If a refusal counter is wanted later, it needs to be defined first:
	// "messages refused" and "messages not forwarded" are different sets
	// (a duplicate is the second and not the first), and the withhold path
	// belongs to neither until its outcome is known.
	Forwarded uint64
}

// announcedBody is one entry in Engine.pending: an announced block's body has
// not arrived yet, and this is who announced it and when.
type announcedBody struct {
	peerAddr  string
	announced time.Time
}

// OrphanLimits bound the orphan pool.
type OrphanLimits struct {
	// MaxBlocks and MaxBytes cap the pool outright.
	MaxBlocks int
	MaxBytes  int
	// HeightWindow rejects orphans whose declared height is further than this
	// from the tip. A healing partition produces branches near the tip; a
	// branch a thousand blocks away is either an attack or a resync, and a
	// resync is what sync is for.
	HeightWindow uint64
}

// DefaultOrphanLimits returns bounds sized for a healing partition rather than
// for a hostile flood.
func DefaultOrphanLimits() OrphanLimits {
	return OrphanLimits{MaxBlocks: 256, MaxBytes: 32 << 20, HeightWindow: 128}
}

// NewEngine returns an engine over a chain and a pool.
func NewEngine(c *chain.Chain, pool *mempool.Pool, peers *PeerStore, e pow.Engine, listen string) *Engine {
	return &Engine{
		Chain:          c,
		Pool:           pool,
		Peers:          peers,
		Engine:         e,
		ListenAddr:     listen,
		work:           verify.NewWorkCache(DefaultWorkCacheEntries),
		seenBlocks:     map[types.Hash]time.Time{},
		pending:        map[types.Hash]announcedBody{},
		orphans:        map[types.Hash]*types.Block{},
		orphanLimits:   DefaultOrphanLimits(),
		withheld:       map[types.Hash]*withheldBlock{},
		withholdLimits: DefaultWithholdLimits(),
		partial:        map[string]map[types.Hash]*partialBlock{},
	}
}

// DefaultWorkCacheEntries bounds the memoized proof-of-work verdicts.
//
// 4096 is roughly an hour of mainnet blocks and comfortably more than any
// announcement-then-body window, which is what the cache exists to close. It
// is a node policy number and an invented one: docs/decisions/testnet-
// measurements.md §2 is where numbers of this kind are supposed to end up with
// a measurement behind them.
const DefaultWorkCacheEntries = 4096

// Verdict is what a node decides about an inbound message.
type Verdict struct {
	// Forward reports whether the message should be re-propagated. Nothing is
	// forwarded before it has been validated — that is the whole spam firewall
	// (M2-G3), and it works because a certificate is checkable from its bytes
	// with no consensus state at all.
	Forward bool
	// ForwardAs, when non-nil and Forward is set, is what the flood carries
	// **instead of** the frame that arrived.
	//
	// It exists for exactly one input: a body that arrived as a multi-chunk
	// transfer. The serve loop re-sends the frame it received, and only the
	// chunk that *completes* a transfer sets Forward — so the single frame a
	// completing node would flood is the LAST chunk, which continues no
	// transfer at any peer that never opened one, and is dropped there unscored
	// (wire.md §5.1). Before announcements stopped being relayed on sight, the
	// announcement flood is what made every node open its own transfer; a node
	// that forwards an announcement only once it holds the body owes its peers
	// an announcement at that moment instead.
	//
	// Nil is the ordinary answer and means "flood the frame that arrived",
	// which for a single-chunk body is the whole body and is byte-identical to
	// the behaviour that preceded this field. reframeAcceptedBody is the only
	// producer, and it is a pure function of the reassembled bytes.
	ForwardAs *Outbound
	// Score is the peer-score delta this message earns its sender.
	Score int
	// Reply, when non-nil, is a message to send back.
	Reply *Outbound
	// Err explains a rejection.
	Err error
	// Cost names what this message cost the peer that sent it.
	//
	// It is the cost-discipline mechanism — every byte a peer sends is priced
	// before it buys work: an outcome with no cost class is the defect, not an
	// omission in the reader's understanding. Fifteen separate findings in this
	// package were all the same shape - a handler refused something and charged
	// nothing, so the sender could send it again forever - and each was found
	// by an adversarial sweep noticing the next handler rather than by anything
	// the build asked. Naming the class at every return makes the question
	// mechanical: TestEveryVerdictIsPriced in sim/wiring reads this file's
	// syntax tree and fails on a Verdict literal that leaves the field at
	// CostUnpriced.
	//
	// docs/spec/wire.md section 10 carries the same taxonomy as a table per
	// (message kind x outcome), so the spec and this field are checkable
	// against each other by a reader rather than by belief.
	Cost CostClass
}

// CostClass is what an inbound message cost its sender.
//
// Free is a category and not a hole: a duplicate in flood gossip and a block
// held for a clock disagreement are both deliberately free, and wire.md section
// 10 says why for each. What the class exists to make impossible is the
// *unnamed* free - a refusal nobody decided the price of.
type CostClass uint8

const (
	// CostUnpriced is the zero value and is never a valid answer. It exists so
	// that "the author did not say" is distinguishable from "the author said
	// free", which is exactly the distinction the fifteen findings turned on.
	CostUnpriced CostClass = iota
	// CostFree is charged nothing, deliberately, with a reason in wire.md
	// section 10. Duplicate gossip (penalising it penalises the topology
	// working), a withheld block (section 9 rule 8: whether a block is early is
	// a fact about this node's clock), and a refusal that is this node's local
	// policy rather than the peer's fault are the three shapes.
	CostFree
	// CostScored moves the peer's score by Verdict.Score, which carries the n
	// in the epic's Scored(n). A negative score is the only cost class that
	// terminates a flood of *distinct* messages, so it is the right class
	// whenever the sender could have known better.
	CostScored
	// CostDeduped is answered from a record this node already holds, so the
	// second and later copies cost a lookup and nothing behind it. The record
	// is what bounds the repetition; a dedup answer with no record behind it is
	// CostFree wearing a disguise.
	CostDeduped
	// CostBudgeted is refused because a bounded resource this node had already
	// committed - reassembly bytes, a transfer table slot, a request window -
	// was exhausted or was never held. The budget is what bounds it, and the
	// budget must itself be bounded independently of the sender's choices.
	CostBudgeted
)

// String names the class for a log line or a test failure.
//
// CostUnpriced has its own arm and the default does not: a value that is not
// one of the five is not "the author did not say", it is not a CostClass at
// all, and printing both as "unpriced" merges the one distinction this type
// exists to carry (wire.md §10.2). A reader chasing an unpriced verdict in a
// log needs to know whether they are looking at a Verdict nobody filled in or
// at a byte that was never a class.
func (c CostClass) String() string {
	switch c {
	case CostUnpriced:
		return "unpriced"
	case CostFree:
		return "free"
	case CostScored:
		return "scored"
	case CostDeduped:
		return "deduped"
	case CostBudgeted:
		return "budgeted"
	default:
		return fmt.Sprintf("cost(%d)", uint8(c))
	}
}

// Outbound is a message to send.
type Outbound struct {
	Kind    MessageKind
	Payload []byte
}

// Errors an engine can produce.
var (
	ErrWrongNetwork  = errors.New("p2p: peer is on a different network")
	ErrWrongProtocol = errors.New("p2p: peer speaks a different protocol version")
	ErrNotUseful     = errors.New("p2p: message is already known")
	// ErrNoSuchTransfer reports a block chunk that continues no transfer this
	// node is holding. It is exported because it is the one refusal on this
	// path that is **not** the sender's fault — this node evicts transfers of
	// its own accord — so callers and tests must be able to tell it apart from
	// a reassembled body that turned out not to be a block.
	ErrNoSuchTransfer = errors.New("p2p: block chunk continues no transfer")
	// ErrKeyEpochBudget reports an announcement refused because the connection
	// has spent its budget of proof-of-work key epochs outside the ones this
	// node is working in.
	//
	// Exported for the same reason ErrNoSuchTransfer is: it is a refusal that
	// is not a judgement about the message. The header may be perfectly good
	// and the block may be real — this node has declined to pay for the epoch
	// now, and the same announcement is judged afresh once a credit is back.
	ErrKeyEpochBudget = errors.New("p2p: announcement refused unevaluated")
	// ErrWorkEvalBudget reports an announcement dropped ahead of the work check
	// because a work-evaluation budget was spent — either the payer's own
	// per-connection budget or this node's shared node-wide ceiling.
	//
	// Exported for the same reason ErrKeyEpochBudget is, and it makes the same
	// promise about a different resource: this is a price on the RANDOMX
	// evaluation itself, not a judgement about the header. The block may be real
	// — this node has declined to pay the CPU for it now, and the same
	// announcement is judged afresh once the budget refills, the moment any other
	// peer announces the same block, or when sync reaches it. The id is kept out
	// of seenBlocks precisely so that re-announcement is not deduped away.
	ErrWorkEvalBudget = errors.New("p2p: announcement dropped unevaluated")
	// ErrReplyBudget reports a query refused because the peer identity that
	// sent it has already been served its whole reply-byte budget for the
	// current window.
	//
	// Exported for the same reason ErrKeyEpochBudget is, and it says the same
	// thing about a different resource: the request may be perfectly good and
	// the block or the header range may be right here. This node has declined
	// to spend the bytes now, and the identical request is answered once the
	// budget refills.
	//
	// It is the family sentinel rather than one layer's: refusals by the
	// node-wide ceiling wrap it too, and ErrGetPeersNodeEgress is the one that
	// says which layer refused in its own text.
	ErrReplyBudget = errors.New("p2p: query refused unserved")
	// ErrHandshakeRequired reports a message other than hello arriving before
	// this connection's one handshake has completed.
	//
	// wire.md §4: hello is sent by both sides immediately, before anything
	// else, and a network-id mismatch closes the connection before parsing any
	// further message. That guarantee holds only if hello is not optional —
	// before this gate, a peer that simply never sent one had every other kind
	// dispatched anyway: get-headers, get-block and get-peers served for free,
	// and certificates, announcements and bodies validated and forwarded for a
	// peer whose network id was never compared.
	ErrHandshakeRequired = errors.New("p2p: message received before the handshake")
	// ErrUnsolicited reports a well-formed response (headers, peers) that
	// answers no request this node made on this connection.
	//
	// Request/response on the gossip connection has no correlation id
	// (wire.md §12), and neither kind is unsolicited *by construction* any
	// more. Both stopped being so, for different reasons, and the verdict is
	// unchanged by both.
	//
	// A headers frame stopped being unsolicited when a node learned to sync
	// from an inbound peer. This node's outbound get-headers used to come only
	// from the dedicated sync connection, which never routes through Handle;
	// syncOverGossip now sends one over the gossip connection an undialable
	// peer opened. What keeps the verdict right is routing rather than
	// construction: deliverSyncResponse runs in serve ahead of Handle and
	// claims only a frame the outstanding request named, so a headers frame
	// reaching Handle is one no outstanding request did claim. Only-if, not if:
	// a mailbox already holding an answer declines the next frame
	// (deliverSyncResponse's default arm), and it arrives here.
	//
	// A peers frame stopped being unsolicited when peer discovery stopped being
	// inert: this node sends get-peers on the gossip connection, so one of
	// these may genuinely answer a request. It still scores as neither, and the
	// name is still accurate, because the absence of a correlation id means
	// nothing here can establish *which* frame answers it — see
	// docs/decisions/networking.md §12.2. Either way it is not useful, since
	// nothing here established that this frame was asked for, and not obviously
	// hostile either — a positive score for a frame nothing validated is
	// exactly the free credit that made the ban threshold unreachable. The
	// weaker verb is the point: this package does send get-peers
	// (Node.askForPeers), so "nothing asked for it" would contradict the
	// paragraph above.
	ErrUnsolicited = errors.New("p2p: response answers no request on this connection")
)

// Hello builds this node's handshake.
func (e *Engine) Hello() Hello {
	work := e.Chain.TotalWork().Bytes()
	return Hello{
		Protocol:   ProtocolVersion,
		NetworkID:  e.Chain.NetworkID(),
		Height:     e.Chain.Height(),
		Work:       work,
		ListenAddr: e.ListenAddr,
	}
}

// OnHello judges a peer's handshake.
//
// The network id is the genesis block id, which commits to every consensus
// parameter (R3-1). A mismatch is an immediate disconnect, not a filtered-later
// condition: a devnet node and a mainnet node must be structurally unable to
// exchange a single block, rather than merely unlikely to accept one (M2-G6).
func (e *Engine) OnHello(peerAddr string, h Hello) Verdict {
	if h.Protocol != ProtocolVersion {
		return Verdict{Cost: CostScored, Score: ScoreProtocolViolation, Err: fmt.Errorf("%w: %d", ErrWrongProtocol, h.Protocol)}
	}
	if h.NetworkID != e.Chain.NetworkID() {
		return Verdict{
			Cost:  CostScored,
			Score: ScoreProtocolViolation,
			Err: fmt.Errorf("%w: peer %x, this node %x",
				ErrWrongNetwork, h.NetworkID[:8], e.Chain.NetworkID()),
		}
	}
	// One handshake per connection, and a second is a protocol violation.
	//
	// Without this, everything keyed on a peer's self-declared address is
	// attacker-controlled at will: re-sending Hello with a fresh ListenAddr
	// mints a brand-new identity that has never been tried, so it wins the sync
	// rotation on every tick — defeating the rotation by rotating the key — and
	// adds another entry to the persisted peer store each time. The handshake
	// happens once because there is nothing a second one could legitimately say.
	e.mu.Lock()
	repeat := e.tips[peerAddr].Handshaked
	e.mu.Unlock()
	if repeat {
		return Verdict{
			Cost:  CostScored,
			Score: ScoreProtocolViolation,
			Err:   fmt.Errorf("%w: a second handshake on one connection", ErrWrongProtocol),
		}
	}

	// AddFrom, not Add: a listen address in a `hello` is a claim this
	// connection makes, exactly like an address in a `peers` frame, so the
	// teller is recorded and MaxPerSource / MaxPerSourceStored can bound it.
	// With Add the entry got an empty Peer.Src, which those bounds deliberately
	// exempt (an empty Src means "not gossiped to this node at all"), and
	// cohort() then charged it to "own:" plus a group the attacker chose. One
	// TCP connection per ephemeral port therefore minted one unbounded address
	// in any /16 it named, and twenty hellos took every outbound slot from a
	// node that already knew honest peers (I-series finding H4). What the
	// attacker cannot invent is the address it is speaking from
	// (docs/decisions/networking.md §5), which is what peerAddr carries.
	if h.ListenAddr != "" {
		e.Peers.AddFrom(h.ListenAddr, peerAddr)
	}
	e.Peers.MarkConnected(peerAddr)
	e.recordTip(peerAddr, h)
	return Verdict{Cost: CostScored, Score: ScoreUsefulMessage}
}

// OnCertificate validates a gossiped certificate and decides whether to
// re-propagate it.
//
// Validation happens **before** forwarding, always. That is what stops an
// invalid-certificate flood from amplifying through the network. It costs at
// most one signature check per certificate, and never more than one: the
// V-rules are a pure function of the bytes — no database, no history, no tip —
// so they are run once, by Pool.Add, and the verdict is read off its error
// once and no more.
func (e *Engine) OnCertificate(peerAddr string, raw []byte) Verdict {
	cert, err := types.UnmarshalCertificate(raw, e.Chain.Params())
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}

	id := cert.ID()

	// Deduplication asks the two places that actually know, rather than a cache
	// that remembers forever.
	//
	// There used to be a `seenCerts` set here: written once, never pruned, never
	// bounded, and consulted *before* the pool. That made the trigger permanent
	// while the reason behind it was transient, which is the failure R7 named.
	// A certificate is evicted from every pool at once when the base fee rises
	// past its bid or its deposit stops covering — both are consensus state, so
	// the eviction is simultaneous and network-wide by construction. Base fees
	// then come back down, and the fold would apply the certificate again. But
	// no node could ever re-acquire it: every peer that had once seen it dropped
	// the re-offer before consulting its pool, there is no rebroadcast loop, and
	// even direct resubmission was answered `{"accepted": true}` and then
	// silently dropped by every peer. Permanent censorship of a valid
	// certificate, with no error anywhere.
	//
	// Both replacements are bounded and both are authoritative. The pool knows
	// what it is holding; the chain's seen-set knows what has been committed and
	// prunes itself by TTL. A certificate that is in neither is one this node
	// has no current reason to refuse, so it is re-evaluated — which costs
	// exactly what an unseen certificate costs, so it is no cheaper to attack
	// with than the traffic that already exists.
	var known bool
	e.Chain.Read(func(v chain.View) {
		_, committed := v.State.Seen(id)
		known = committed
	})
	if known || e.Pool.Has(id) {
		// Not misbehaviour — gossip duplicates constantly — but not worth
		// forwarding again either.
		//
		// Since the certificate id was redefined to name an authorization rather than
		// an encoding of one, this also absorbs a *mutilated* exemplar of an
		// authorization already pooled or committed, because the id no longer
		// covers the signatures: a copy with a mangled signature has the honest
		// id and is answered here, unscored, instead of falling through to the
		// V-rules in Pool.Add and earning ScoreInvalidMessage as it did while
		// the id covered the bytes. That is deliberate, and the alternative is
		// worse.
		//
		// The reason is not that scoring it would be expensive. It would be
		// cheap on the pool half — Pool.Get already returns the exemplar this
		// node holds, so a differing ExemplarHash could gate the verify and an
		// honest byte-duplicate would never reach it — and on the seen-set half
		// it is a matter of an index rather than an impossibility, since every
		// committed body is on disk behind Chain.Block. Two earlier drafts of
		// this comment claimed otherwise on both counts and were wrong.
		//
		// The reason is that a differing exemplar is not evidence of
		// misbehaviour. Under that same redefinition an honest wallet may retry
		// a stuck payment at a fresh nonce — that is the point of the change,
		// and the golden vector invalid-resigned-replay is exactly that
		// certificate — so a peer relaying a re-signed retry of something
		// already pooled is behaving correctly and would be charged
		// ScoreInvalidMessage for it. Scoring on exemplar mismatch trades a
		// false negative nobody can exploit for a false positive against honest
		// relays, and ScoreInvalidMessage is documented as "a message that
		// fails the V-rules", which this node has not established.
		//
		// It also concedes nothing new. Replaying the honest bytes reaches this
		// same branch at this same price and always did — same decode, same
		// marshalBody, same lookup — so the cheapest unscored message here is
		// unchanged; one more shape lands in a channel that was already free.
		// What MUST NOT happen is the reverse — holding the bad exemplar against
		// the id — and this branch does not: nothing is marked, nothing is
		// cached, and the honest exemplar is admitted normally whichever arrives
		// first (docs/spec/wire.md §3.1,
		// TestAMutilatedExemplarIsNotHeldAgainstTheAuthorization).
		return Verdict{Cost: CostDeduped, Err: ErrNotUseful}
	}

	// The V-rules are NOT checked here, and their absence is what stops every
	// gossiped certificate being Ed25519-verified twice.
	//
	// Pool.Add runs the complete stateless predicate itself, unconditionally:
	// the structural rules (V1, V3-V7), then every O(1) policy gate, then V2 —
	// the Ed25519 pass — last, outside the pool lock (cost discipline, step 2). A
	// validity.Check at this call site therefore verified nothing Add does not,
	// against the same *params.Params (cmd/zycordd wires one value into both
	// chain.OpenWith and mempool.New) and the same era, so every certificate
	// this node admitted from gossip paid for two identical Ed25519 passes.
	//
	// Deleting it is an ordering fix and not only a saving. validity.Check here
	// is a step-4 check standing in front of Add's step-2 and step-3 gates —
	// the TTL window, the deposit screen, the fee floor, the per-underwriter
	// cap — so a certificate whose TTL had already passed, which needs no funds
	// and is replayable forever, bought a signature verification before this
	// node ever looked at its TTL. wire.md §10.1 forbids exactly that: "a
	// message that fails at step 1, 2 or 3 MUST NOT have caused a signature
	// verification". Nothing moves in the other direction: the only mutation on
	// this path is inside Add, still behind V2 there, so the step-5 boundary is
	// where it was.
	//
	// The verdict is read off Add's error instead. Add wraps validity failures
	// as fmt.Errorf("mempool: %w", err) and validity.RuleError implements
	// Unwrap, so validity.Rule names the failed V-rule through the wrapper and
	// an invalid certificate is still Scored(invalid) (wire.md §10.3).
	//
	// One consequence is deliberate rather than accidental. Because V2
	// now runs after the policy gates, a certificate that fails a policy gate
	// AND V2 is named by the policy gate, and is refused unscored where the
	// pre-Add check would have charged ScoreInvalidMessage. That is a peer this
	// node declines to penalise for relaying an invalid certificate it was
	// going to drop anyway, and it is the right call: ScoreInvalidMessage is
	// documented as "a message that fails the V-rules" (§10.5), and on that
	// path this node has not established that it does — it stopped at its own
	// local condition. Charging for a verdict not reached is the same error as
	// the exemplar-mismatch scoring rejected at the dedupe above. The refusal
	// stays free of signature work, which is what bounds it.
	//
	// The deposit screen inside Add is the one tip-dependent check a relay
	// applies. A certificate whose deposit does not cover at this node's tip is
	// not forwarded, which is what stops unfunded spam propagating for free.
	var addErr error
	e.Chain.Read(func(v chain.View) { addErr = e.Pool.Add(cert, v.State, v.Height) })
	if err := addErr; err != nil {
		if validity.Rule(err) != "" {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
		}
		// Pool policy is local, so a refusal here is not the peer's fault and
		// earns no penalty — but it is not forwarded either.
		return Verdict{Cost: CostFree, Err: err}
	}

	return Verdict{Cost: CostScored, Forward: true, Score: ScoreUsefulMessage}
}

// OnBlockAnnounce judges a hash-first block announcement from a caller that
// has no authenticated identity for the sender.
//
// The fallback and not the design, exactly as replyBudgetKey's address arm is:
// it is reached by Engine.Handle, which exists for tests and for callers that
// never completed a TLS handshake. Node.serve reaches HandleFrom with
// Conn.PeerKey instead, and the key-epoch budget is charged to that.
func (e *Engine) OnBlockAnnounce(peerAddr string, raw []byte) Verdict {
	return e.OnBlockAnnounceFrom(peerAddr, peerAddr, raw)
}

// tipNextTarget is tip's id and the difficulty rule's answer for the block
// after it, or ok=false when this node cannot vouch for that answer right now.
//
// **It confirms the tip out of the window rather than trusting the caller's.**
// `RecentHeaders` always ends at the tip and takes the chain lock once, so the
// window it returns is internally consistent; the caller's tip was read before
// that acquisition and a tip move in between would pair one branch's window
// with another branch's tip. `chain.HeadersEndingAt`'s own note is what that
// costs: `pow.NextTarget` computes a target from the mixture, the honest peer's
// header does not match it, and the peer is scored down for this node's race.
// So a window that does not end where the caller looked returns ok=false and
// the caller declines to judge — this node's race is never the sender's fault,
// and declining is exactly the behaviour that preceded this check.
func (e *Engine) tipNextTarget(tip types.Header) (types.Hash, u256.U256, bool) {
	e.mu.Lock()
	if e.tipTargetOK && e.tipTargetTip == tip {
		id, want := e.tipTargetID, e.tipTarget
		e.mu.Unlock()
		return id, want, true
	}
	e.mu.Unlock()

	p := e.Chain.Params()
	window := e.Chain.RecentHeaders(int(p.DifficultyWindow) + 1)
	if len(window) == 0 || window[len(window)-1] != tip {
		return types.Hash{}, u256.U256{}, false
	}
	id, want := tip.ID(), pow.NextTarget(window, p)

	e.mu.Lock()
	e.tipTargetTip, e.tipTargetID, e.tipTarget, e.tipTargetOK = tip, id, want, true
	e.mu.Unlock()
	return id, want, true
}

// OnBlockAnnounceFrom judges a hash-first block announcement.
//
// The header's proof of work is verified **before** any body is requested
// (R1-M3). Ghost announcements therefore cost the announcer real work rather
// than costing every receiver a fetch.
//
// payer is what the key epoch this announcement demands is charged to; see
// replyBudgetKey, which produces it, and spendKeyEpoch, which spends it. It is
// a second parameter rather than a second lookup inside the engine because the
// engine has no map from a connection address to the key that authenticated
// it — HandleFrom already holds both, and a budget keyed on the half of that
// pair the sender mints is one the sender re-buys per handshake.
func (e *Engine) OnBlockAnnounceFrom(peerAddr, payer string, raw []byte) Verdict {
	ann, err := UnmarshalAnnounce(raw)
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}

	id := ann.Header.ID()
	e.mu.Lock()
	_, known := e.seenBlocks[id]
	e.mu.Unlock()
	if known {
		return Verdict{Cost: CostDeduped, Err: ErrNotUseful}
	}

	if ann.Header.Version != types.HeaderVersion {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: errors.New("p2p: unknown header version")}
	}
	// Genesis is never announced, and refusing it is not tidiness.
	//
	// Height 0 is the one height at which `pow.CheckWork` costs a sender
	// nothing — it returns nil immediately, correctly, because genesis carries
	// no work. That makes a genesis-height header a free ticket past the work
	// check and into everything downstream of it. Every node already holds
	// genesis, so an announcement of it cannot be useful to anybody, and the
	// only party with a reason to send one is a party looking for a free path.
	if ann.Header.Height == 0 {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage,
			Err: errors.New("p2p: genesis is never announced")}
	}
	// An announcement may not describe a block that could not exist.
	//
	// `UnmarshalAnnounce` bounds the exemplar list by `MaxAnnouncedCerts`, which is a
	// transport ceiling and has nothing to do with what a block may hold. The
	// bound a block *can* hold is `MaxCertsPerBlock(SeqGasCapacity)` — the
	// certificate ceiling at the maximal sequential target, which no valid
	// block at any height exceeds — so an announcement above it describes a
	// block that cannot exist and is refused on that ground.
	//
	// The refusal also stands in front of a panic. `certRoot` below merkleises
	// against `cert_list_capacity`, where `ssz.Merkleize` **panics** rather
	// than returning an error, because inside the consensus zone being handed
	// an oversized list is a caller's bug rather than an input. That capacity
	// is sized as merkle headroom for era re-pins (its note in
	// spec/params.json) and sits far above both this ceiling and the transport
	// bound, so the panic needs an in-process caller's bug to reach — but the
	// reachable-ceiling check here refuses long before either limit, and
	// nothing on the peer message path recovers. Without this line one
	// unauthenticated message could otherwise end the process: paired with the
	// height-0 exemption above it would cost an attacker one connection and no
	// proof of work, against every node on the network.
	if max := e.Chain.Params().MaxCertsPerBlock(e.Chain.Params().SeqGasCapacity); len(ann.CertExemplars) > max {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage,
			Err: fmt.Errorf("p2p: announcement lists %d certificates, a block holds at most %d",
				len(ann.CertExemplars), max)}
	}
	// A block from the future is not requested, not relayed, and not held
	// against the sender (R1-H2).
	//
	// The announcement is dropped rather than queued, and the two decisions are
	// different: the queue holds *bodies*, because a body is the thing that
	// would otherwise have to be fetched again, and an announcement is
	// re-sent by the network for free. Crucially the id is **not** entered into
	// seenBlocks — marking it seen would dedupe the re-announcement that
	// arrives once the clock has caught up, and the block would be lost to this
	// node permanently, which is a rejection wearing a cache's clothes.
	//
	// **This stands ahead of both the key-epoch price and the work check, and
	// that ordering is the future-dated half of pricing an announcement.** It
	// used to stand behind them, so a future-dated announcement paid a RandomX
	// evaluation — and, once the key-epoch price existed, a credit against it —
	// before this node looked at a clock it already owned. That evaluation
	// bought nothing, and onFutureAnnouncement's own comment is what says so:
	// "on this path the work check reads the header's own declared target and
	// never re-derives it (R4-H1), so a MaxTarget header costs its sender one
	// hash". A check a sender passes by declaring its own target is not
	// evidence, so running it first only moves the cost onto the receiver, and
	// the measurement is that the future-dated path charges nothing and dedupes
	// nothing — so the cost had no bound in front of it. Now it is a parse and
	// a clock read.
	//
	// It also repairs, rather than accepts, the cost the key-epoch price recorded
	// here: the clock-skew sensor lives in this branch, and while it stood below
	// the budget an over-budget announcement never reached it, so futureAnnounced
	// and maxSkewSeconds froze at MaxUnheldKeyEpochsPerPeer for a node both
	// behind the chain and behind the clock. Above the budget they move again.
	//
	// **What it gives up, at full width, because a concession trimmed to its
	// most comfortable half is worse than none.** Everything below this line is
	// now unreachable for a future-dated announcement, and three of those things
	// used to charge the sender:
	//
	//   - **the work check's ScoreInvalidMessage.** A future-dated header whose
	//     proof of work `work.Check` would refuse is now dropped at CostFree and
	//     ScoreFutureBlock instead of at CostScored and ScoreInvalidMessage. This
	//     is the widest of the three and it is the one the earlier wording left
	//     out: a flood of future-dated headers carrying unmeetable targets no
	//     longer accumulates toward ScoreBanThreshold on this path at all.
	//   - **MarkWorkRefusedKey.** The same drop means the identity bit that
	//     records "this sender has had an announcement refused by the work
	//     check" is never set from a future-dated message, so the score conjunct
	//     below — which reads exactly that bit — cannot be armed by one either.
	//     An attacker that only ever sends future-dated headers keeps a clean
	//     bit however many it sends.
	//   - **certRoot's ScoreInvalidMessage.** A future-dated header whose
	//     exemplar list does not produce its own CertRoot is dropped free,
	//     because certRoot moved below this line with the work check.
	//
	// **What limits the concession, and it is a bound rather than an argument.**
	// A future-dated announcement is refused by a comparison against this node's
	// own clock, so it is never relayed, never requested, never entered into
	// seenBlocks and never entered into pending — it buys the sender nothing on
	// this node beyond the parse and the clock read, and buys nothing downstream
	// because nothing is forwarded. The residual is therefore a scoring loss and
	// not a resource loss: an attacker willing to date its headers ahead is
	// exempt from the ban this path used to earn it, and pays instead by having
	// every message it sends discarded. The bound on the branch it lands in is
	// maxSkewGroups, which is sized for unauthenticated senders already and says
	// so. What an attacker CANNOT do is have it both ways in one message —
	// getting a header evaluated, relayed or deduped requires dating it inside
	// FTL, and inside FTL every charge above is live again.
	//
	// The certRoot half additionally takes nothing at all, which is worth
	// keeping separate from the two that do: an empty exemplar list matches
	// certRoot(nil, p), so a sender wanting the free path never needed a
	// mismatched root and does not gain one.
	if e.tooFarAhead(ann.Header) {
		e.onFutureAnnouncement(peerAddr, ann.Header, ann.Header.Time-e.now())
		return Verdict{Cost: CostFree, Score: ScoreFutureBlock, Err: fmt.Errorf("%w: dated %d",
			ErrBlockWithheld, ann.Header.Time)}
	}
	// The price of the key epoch the work check below is about to demand.
	// It is charged *before* the check, because the check is what
	// spends the epoch, and afterwards is a bill for CPU already burnt.
	//
	// See spendKeyEpoch for the whole argument. What matters at this call site
	// is the ordering: every refusal above this line is free to this node, the
	// certificate-root merkleisation below it is cheap, and `work.Check` is
	// the one step whose cost the sender chooses.
	if epoch, ok, own := e.spendKeyEpoch(payer, ann.Header.Height); !ok {
		// Still recorded, and that is the half that keeps this a price rather
		// than the height window I7-H4 reverted.
		//
		// recordAnnounce decides who is worth *asking*, and its own comment
		// says what it is worth: "the announce path checks work against the
		// header's own declared target and never re-derives it (R4-H1) — so it
		// decides only who is worth asking". A declared-target header reaches
		// it today for one hash, so moving it ahead of the work check takes
		// nothing away that was ever there. Dropping it instead would stop a
		// node that is behind from refreshing the candidacy of the peers it
		// depends on to climb back, which is the failure that reverted the
		// tip-window guard and is pinned by
		// TestCatchingUpDoesNotBanTheHonestPeersItDependsOn.
		//
		// **The record is taken in FULL here, and that is a decision to leave
		// it that way rather than an omission.** Standing ahead of the work
		// check, this call lets an over-budget connection reach, per message
		// and unpaid, `Chain.Height()`, `Chain.Params().UndoDepth`, one
		// `Chain.CanonicalHeader` index lookup and one `types.Header.ID()`
		// hash, on top of the announcement's own unmarshal. Before the
		// key-epoch price existed the same message paid a `work.Check`
		// evaluation instead, so this is a regression in *unit* cost and an
		// improvement in *total* cost — named anyway, because "cheaper than
		// what it replaced" is not "priced".
		//
		// The alternative considered was a partial refresh: take `Height` and
		// skip the `CanonicalHeader` lookup that sets `OffersUnknown`, on the
		// argument that the first half is what a node climbing back needs and
		// the second is the half that grants candidacy. **Rejected**, on two
		// grounds, and neither of them is the duplication that kept it out of
		// the key-epoch change — a shared body with a flag would have answered that.
		//
		//   - It removes a fraction of the residual rather than the residual.
		//     The height read, the params read, the `ID()` hash and the
		//     unmarshal all stay unpaid on the same path, and the index lookup
		//     is the cheapest of the four. What bounds the aggregate is
		//     unchanged either way: the connection set, and the per-connection
		//     message rate limit nothing has built yet. Sizing this
		//     specifically needs a number no testnet has produced, and a
		//     threshold nobody measured is worse than a residual somebody named.
		//   - It would take away a signal that is not always redundant.
		//     `syncCandidatesLocked` drops a peer only when it is behind on
		//     height AND on claimed work AND its `OffersUnknown` has gone
		//     stale, so for a peer that is *ahead* the height refresh alone
		//     carries candidacy — that is the catch-up case this branch exists
		//     for, and the one
		//     TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget
		//     pins. It is not the *fork* case: a peer holding a heavier branch
		//     that ends below this node's tip is behind by height and by
		//     claimed work, and `OffersUnknown` is the only thing that can make
		//     it a candidate at all (the one-height refresh window, and the
		//     healed-network-stays-forked failure recordAnnounce's own comment
		//     names). Whether such a branch lands outside the two working key
		//     epochs is `undo_depth` against `randomx_key_interval` — 1024
		//     against 512 on testnet — so it is reachable by ordinary
		//     parameters rather than hypothetical.
		//
		// So the answer taken here is the third of the three considered:
		// **nothing**, on the grounds that candidacy is already obtainable for
		// one hash (`docs/adversarial/sync.md` §6.1) and this path makes it
		// obtainable for zero without changing what it buys or what bounds it.
		// That is a decision taken here rather than an inference from §6.1.
		// What reopens it: a per-connection message rate limit, still unbuilt,
		// which subsumes this residual along with the ones it shares a bound
		// with, or testnet evidence that this lookup is reachable at a rate the
		// connection set does not already cap. Pinned by
		// TestAnOverBudgetAnnouncementRefreshesBothHalvesOfTheCandidacyRecord,
		// which is what the partial refresh would have to break.
		e.recordAnnounce(peerAddr, ann.Header)
		// The id is deliberately NOT entered into seenBlocks, for the same
		// reason the future-dated path above does not enter it: this is a
		// refusal to spend *now*, and marking it seen would dedupe away the
		// re-announcement that arrives after the budget refills, turning a
		// price into a permanent rejection wearing a cache's clothes.
		//
		// **Scored exactly for the identities the work check has already
		// caught, and that conjunct is what keeps an over-budget announcement
		// from buying an amnesty from the work check's score.** An over-budget
		// announcement never reaches work.Check, so ScoreInvalidMessage never
		// fires for it; the measurement is what that buys — an identity at
		// ScoreCeiling sending sixty headers whose declared target no digest
		// can meet is never banned, because the budget stops the evaluation
		// five messages before the score would have. CostClass says a negative
		// score "is the only cost class that terminates a flood of distinct
		// messages", and an unconditional CostBudgeted moved those messages out
		// of it.
		//
		// The separating fact is one this node has already established for
		// itself and did not throw away: whether THIS identity has ever had an
		// announcement refused by the work check. An honest peer cannot set
		// that bit — a header meets the target its own header declares, or its
		// announcer built it wrong — so the honest catch-up peer of
		// TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpoch-
		// Budget still refuses 35 of 40 unscored and unbanned, which is the
		// liveness failure that reverted I7-H4's tip window and the one this
		// whole guard exists to avoid. An identity that has failed the check
		// keeps no amnesty, so its flood terminates at ScoreBanThreshold as it
		// did before the budget existed.
		//
		// **And charged only where the payer's OWN budget refused it, never
		// where the shared node-wide ceiling did.** That disjunct keeps the
		// score off a peer another peer's flood refused; it is the served
		// path's `own` disjunct one primitive over, and it is not a refinement
		// of the conjunct above but a precondition of it: the conjunct asks
		// "has this identity been caught", which is a fact about the identity,
		// and it is only evidence about THIS message if this message is one the
		// identity's own attributable budget refused. The ceiling is keyed on
		// nothing a sender presents, so a refusal there can be caused entirely
		// by traffic the payer never sent — and 55,680 bytes from 48 minted
		// identities, at no proof of work, is what causing it costs — a keypair
		// is free, so the aggregate over identities is whatever the attacker
		// cares to present. Scoring somebody for another peer's flood is the
		// guard I7-H4 reverted rather than a repair of it, which is the reason
		// refuseUnbudgeted gives for the identical disjunct on the served path.
		//
		// **The ceiling arm asks a SECOND question before it grants that
		// amnesty, and that second question is what stops a drained ceiling
		// sheltering the identities the work check has already caught.** `own`
		// is false for EVERY payer at once while the ceiling is down —
		// spendKeyEpoch returns before the per-payer layer is reached — so
		// conjoining the work-refused bit with `own` alone switched the
		// terminating class off for the identities work.Check had already
		// caught as well as for the ones it had not, for as long as an attacker
		// held the ceiling at zero. unheldKeyEpochCeiling prices holding it
		// there at the connection set per period, which a free keypair makes
		// roughly ten fresh identities at the defaults.
		//
		// The repair is a non-mutating read of whether this payer's own budget is
		// already SPENT. That is a different question from whether it is what
		// refused THIS message, and it is the one that still has an answer when
		// the ceiling is what refused it: an identity that has already burnt its
		// whole attributable allowance is attributable on that evidence whichever
		// layer refuses the next message, and one holding an untouched budget is
		// not.
		//
		// **Reordering the two layers is still the wrong fix, and this is not
		// it.** SpendUnheldKeyEpoch mutates, so reading the per-payer layer first
		// makes a ceiling refusal SPEND a credit it never owed, which
		// TestAnAnnounceRefusalByTheSharedKeyEpochCeilingIsNeverScored kills at 26
		// of 30 refusals scored, −520 against a ban threshold of −100.
		// ownKeyEpochsExhausted charges nothing, so the amnesty keeps its whole
		// purpose: the honest peer this arm was written for — one whose budget the
		// ceiling never let it spend — is still never scored for a flood it did
		// not send, and the sheltered-flood residual stays bounded because the
		// refusal still stands ahead of work.Check either way.
		//
		// refuseUnbudgeted still ships the unrefined shape one primitive over,
		// where the read it would need (ServedBytesExhausted) already exists.
		if !own {
			if e.ownKeyEpochsExhausted(payer) && e.workRefused(payer) {
				return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
					"%w: key epoch %d is outside the epochs this node is working in, this "+
						"identity has already spent its own budget of %d, and its "+
						"announcements have already been refused by the work check",
					ErrKeyEpochBudget, epoch, MaxUnheldKeyEpochsPerPeer)}
			}
			ceiling, _ := unheldKeyEpochCeiling(e.connSetLocked())
			return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
				"%w: key epoch %d is outside the epochs this node is working in, and "+
					"this node has spent its whole ceiling of %d on epochs it does "+
					"not hold",
				ErrKeyEpochBudget, epoch, ceiling)}
		}
		if e.workRefused(payer) {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
				"%w: key epoch %d is outside the epochs this node is working in, this "+
					"identity has spent its budget of %d, and its announcements have "+
					"already been refused by the work check",
				ErrKeyEpochBudget, epoch, MaxUnheldKeyEpochsPerPeer)}
		}
		return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
			"%w: key epoch %d is outside the epochs this node is working in, and "+
				"this identity has spent its budget of %d",
			ErrKeyEpochBudget, epoch, MaxUnheldKeyEpochsPerPeer)}
	}
	// An announcement that names this node's own tip as its parent must declare
	// the target the difficulty rule gives, and this is the one ingress path
	// that never asked.
	//
	// `work.Check` below tests the digest against `ann.Header.Target` — the
	// field the sender wrote — and nothing above bounds it. At `max_target` no
	// digest can exceed it, so a header costs about 64 expected hashes on
	// mainnet and 31 on devnet, passes, and is entered into `pending` keyed to
	// the connection it arrived on. It used to be returned `Forward: true` as
	// well, and every node downstream then charged `ScoreUnservedBody` to an
	// honest relay that never had the body and that §8 required to forward it,
	// at 232 B per announcement; Option A closed that half at the accept return
	// below, and this check is what stops the ghost buying the `pending` entry
	// and the `get-block` in the first place at the one distance this node can
	// judge.
	//
	// **This is the same line `OnBlock` already carries on its tip-extension
	// branch, and its comment there names the reason: "declare a trivial target,
	// solve it in a handful of hashes, and claim whatever work you like — it is
	// the attack headers-first sync was built to remove. It was removed there
	// and nowhere else, so it walked in here."** `node/sync.ValidateHeaders` and
	// `chain.ConsiderBranch` re-derive it too. The announce path was the only
	// ingress that did not, and wire.md §9's own list of the paths that enforce
	// the rule omits it.
	//
	// **Only when the parent is this node's tip, and that is a limit rather than
	// a policy.** The rule is a function of the window preceding the parent, and
	// this node holds that window exactly when the parent is its own tip. It is
	// deliberately NOT extended to a header whose parent is unknown: measured on
	// the multi-node harness, a receiver one block behind its peer sees 19 of 20
	// honest announcements name a parent it does not hold and a rejoining node
	// sees 14 of 15, so refusing or withholding those silences the lagging fringe
	// — the failure that reverted I7-H4's tip window. Such an announcement is
	// judged exactly as it was before this check existed. What that leaves open
	// is recorded in wire.md §5.
	//
	// Ahead of `work.Check` rather than behind it, for the reason the key-epoch
	// price gives one branch up: the check the sender cannot cheapen should stand
	// in front of the one whose cost the sender chooses. A comparison against a
	// memoized u256 refuses the ghost without a proof-of-work evaluation ever
	// being paid for it.
	tip := e.Chain.Tip()
	if tipID, want, ok := e.tipNextTarget(tip); ok && ann.Header.ParentID == tipID {
		// **And it must be at that tip's successor height, which is the same
		// branch and a different rule.**
		//
		// A block whose parent is a given block is at that block's height plus
		// one. `core/fold`'s `checkCites` and `chain.Apply` both enforce it from
		// state, and `chain.ConsiderBranch` enforces it along a branch — but on
		// this wire the pair (ParentID, Height) is unconstrained, so a header
		// could name this node's own tip as its parent and claim any height at
		// all. Past the target line above it carries the tip's real target, so
		// producing one costs a real block's work rather than the ~31 expected
		// hashes on devnet a `max_target` header costs; what the missing
		// comparison left free was the *height* on an already-paid header, and
		// the height is what picks the RandomX key. So the header named a key
		// epoch this node does not hold and the cost landed on the key-epoch
		// budget — a resource priced for honest peers a node behind depends on,
		// spent here by a header that describes a block no chain can contain.
		//
		// It stands ahead of the target comparison rather than behind it, and
		// the reason is which of the two is meaningful. `want` is the difficulty
		// rule's answer for the block *after* this tip; a header at some other
		// height is not a candidate for that block at all, so "declares the
		// wrong target" is the wrong thing to say about it. Refusing on the
		// height first names the fact that is true, and it is what makes the two
		// §10.3 rows a function rather than a pair that both match this input.
		if ann.Header.Height != tip.Height+1 {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
				"p2p: announcement names this node's tip as its parent at height %d, "+
					"a block whose parent is that tip is at height %d",
				ann.Header.Height, tip.Height+1)}
		}
		if !ann.Header.Target.Eq(want) {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
				"p2p: announcement declares target %s on this node's tip, the difficulty "+
					"rule gives %s", ann.Header.Target.String(), want.String())}
		}
	}
	// A budget for the RandomX evaluation below, spent here because this is the
	// one line whose cost the sender chooses and the seen-set read at the top of
	// this function does not catch a flood of DISTINCT announcements — the
	// CPU-exhaustion face of the unbounded seen-set.
	//
	// **This is the charge the key-epoch price above leaves uncovered.**
	// spendKeyEpoch exempts the working epoch — an honest peer announces the
	// block after this node's tip into it for the whole interval the tip takes
	// to cross a key boundary, so charging it there throttles every honest peer
	// at once — so a distinct announcement in the working epoch reaches this
	// point with nothing in front of the memory-hard work.Check. The seen-set
	// read never dedupes it (distinct id), the difficulty-vs-tip gate never fires
	// (parent is not the tip), and a max-target header passes work.Check with a
	// non-negative score, so scoring never terminates it either.
	//
	// **Two layers, and the second is the one the hostile review forced.**
	// spendWorkEval charges a per-connection budget (localised, attributable) UP
	// TO a node-wide ceiling keyed on nothing. The per-connection layer alone
	// bounds one static connection but not the aggregate: identities are free, so
	// N churned connections spend N x MaxWorkEvalsPerConn and the sum is linear
	// and unbounded. The node-wide ceiling is the sum's bound — one bucket every
	// sender shares, so churn has no per-identity multiplier to aggregate against
	// it — exactly as unheldEpochs bounds the sum the per-identity key-epoch
	// budget cannot. Honest gossip does not reach it: the seen-set dedups across
	// peers, so only the first announcer of a block runs a work check, and
	// node-wide honest demand is a block or two per period against a ceiling of
	// hundreds. And it does not throttle catch-up: the sync driver's own header
	// and body requests never consult this ceiling, so a node behind climbs by
	// sync even with the bucket at zero.
	//
	// **A price, not a judgement, on either arm.** CostBudgeted carries no
	// score — scoring a budget refusal would ban the honest peers a node behind
	// the chain depends on (the failure that reverted I7-H4's tip-window
	// guard), and the node-wide arm can have been driven to zero by another
	// peer's flood, so scoring it would be scoring somebody for another peer's
	// flood — and the id is NOT entered into seenBlocks below, exactly as the
	// key-epoch and future-dated refusals are not, so the same valid block
	// stays obtainable: re-announced once the bucket refills, announced by
	// another peer, or reached by sync. The throttle drops the cheap
	// announcement; it never makes a valid block unreachable and never
	// blacklists one.
	//
	// **Charged only for the working epoch, the face spendKeyEpoch leaves free.**
	// An announcement naming a key epoch this node is NOT working in was already
	// charged and node-wide-bounded by spendKeyEpoch above — and that budget is
	// sized for the ~0.55 s cache build such an epoch forces, the expensive term.
	// Charging it here too would double-bound it, and worse would make this
	// ceiling — sized for cheap in-epoch hashes over one block time — the binding
	// limit on the far larger key-epoch ceiling an operator sized for cache
	// builds over one key-epoch period. So work-eval covers exactly the hole:
	// the in-epoch announcements spendKeyEpoch admits for free.
	if e.announceWorkingEpoch(ann.Header.Height) {
		if ok, own := e.spendWorkEval(payer); !ok {
			// Both arms are CostBudgeted and NEITHER carries a score. A budget
			// drop is a price, not a judgement — the header would pass work.Check,
			// so there is no invalid message to charge for — and the node-wide arm
			// in particular must never score, because it can have been driven to
			// zero by another peer's flood — the same reason
			// spendKeyEpoch's `own` disjunct exists. The id is deliberately NOT
			// entered into seenBlocks below on either arm, so the same valid block
			// stays obtainable once the bucket refills, from another peer, or
			// through sync.
			if !own {
				ceiling, _ := workEvalCeiling()
				return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
					"%w: this node has run its ceiling of %d proof-of-work "+
						"evaluations for this period", ErrWorkEvalBudget, ceiling)}
			}
			return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
				"%w: this connection has spent its budget of %d proof-of-work "+
					"evaluations for this period", ErrWorkEvalBudget, MaxWorkEvalsPerConn)}
		}
	}
	// Work before bodies. This is the whole point of hash-first relay.
	if err := e.work.Check(e.Engine, ann.Header, e.Chain.Params()); err != nil {
		// Remembered against the identity, not only charged to it. The score
		// decays toward zero through ScoreUsefulMessage and is clamped at
		// ScoreCeiling, so it cannot answer "has this sender ever been caught";
		// the budget refusal above needs that answer and nothing else records
		// it. See identityEntry.workRefused.
		if e.Peers != nil {
			e.Peers.MarkWorkRefusedKey(payer, e.now())
		}
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	// And the announcement must be internally consistent: the exemplar list has
	// to produce the root the header commits to, or the announcer is describing
	// a block that does not exist.
	if root := certRoot(ann.CertExemplars, e.Chain.Params()); root != ann.Header.CertRoot {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: errors.New("p2p: announcement does not match its certificate root")}
	}

	now := e.wallClock()
	e.mu.Lock()
	// Bounded on entry, not only reaped on a ticker. The TTL sweep in
	// ReapUnservedBodies keeps the honest steady state small, but a flood can
	// insert faster than a 15 s ticker sweeps, so the cap is what makes "the set
	// never exceeds N" true however fast distinct valid headers arrive — the
	// same reason the orphan pool evicts on insert rather than trusting a
	// reaper. Evicting the oldest keeps whatever is most recently in flight,
	// which is what the announcement-then-body dedup window is about.
	if len(e.seenBlocks) >= MaxSeenBlocks {
		e.evictOldestSeenLocked()
	}
	e.seenBlocks[id] = now
	e.pending[id] = announcedBody{peerAddr: peerAddr, announced: now}
	e.mu.Unlock()
	e.recordAnnounce(peerAddr, ann.Header)

	// **The announcement is accepted and NOT relayed, and that is the whole of
	// Option A: a node forwards an announcement only once it holds the
	// body.** This return is the one that does not hold it.
	//
	// The rule reads as a condition and lands as a straight line because this
	// engine has exactly one forwarding announce path, and it is the path that
	// writes `pending`. `pending` is written at one line — the one above — and
	// it is written precisely when the body has *not* arrived, which is why the
	// `get-block` below is issued at all. So "hold the body" is false wherever
	// the forward could have been taken, and the branch collapses rather than
	// being absent. Every return above this one already forwards nothing.
	//
	// **What it repairs.** §9 rule 5 requires a node to charge the announcer
	// once when the window elapses with no body, and `pending` names the
	// connection the announcement arrived on. Under §8's flood rule that
	// connection is the *last hop*, not the announcer, so the charge landed on
	// whichever honest peer §8 obliged to relay. Measured over two real
	// Engines, ghosts naming an invented parent at tip+100 and declaring
	// `max_target`: 23 forwarded, 5,336 B, the honest relay banned by its own
	// downstream at −108, and that downstream never scoring the announcer at
	// all. The count is a property of the reap schedule and not of the tree;
	// banned / not banned is the property.
	//
	// **Why forwarding could never have been useful here.** A relay cannot
	// answer the `get-block` its own forward provokes: the forward existed only
	// on this path, this path is the one where the body has not arrived, and a
	// downstream's request therefore comes back `CostFree` with `chain: not
	// found`. §9 rule 5 describes a peer that advertises what it will not back,
	// and §8 required every relay to be one. What actually carries a block past
	// the first hop is the body broadcast `OnBlock` performs on acceptance,
	// which the serve loop floods to every peer but the sender.
	//
	// **Priced before it was taken, paired and lock-step, single-chunk bodies,
	// `spec.Devnet()`, dev hasher — the axis it was searched along
	// (`PROTOCOL.md` rule 21).** A line of 6 and a ring of 8 reach full
	// propagation in the same number of rounds relayed and not relayed, at
	// 0.43x and 0.46x the bytes. Rounds are a schedule of that harness; the
	// equality is not.
	//
	// **The liveness row this used to cost is paid off rather than accepted.**
	// `e.tips` is refreshed by the handshake and by `recordAnnounce` and never
	// by a delivered body, so a node fed only through a relay dropped from 1
	// sync candidate to 0 — `LAUNCH.md` §3 case 4. Candidacy is now refreshed from
	// a delivered body, and with it this node counts *every* peer that fed it
	// rather than the one that won the announce race, so the row ends above
	// where the announce path left it. It had to land first, and it did.
	//
	// **What is deliberately unchanged.** `recordAnnounce` still runs on the
	// line above — an announcement is still the candidacy signal a node behind
	// depends on, and this changes who hears the announcement, not who
	// this node is willing to ask. `seenBlocks` and `pending` are still written,
	// so the charge that terminates a ghost flood from a directly connected peer
	// stays armed against the party that chose to announce: deleting it was
	// measured at 60 ghosts accepted, 60 forwarded and no score ever negative.
	//
	// wire.md §8 carries the normative half.
	return Verdict{
		Cost:  CostScored,
		Score: ScoreUsefulMessage,
		Reply: &Outbound{Kind: KindGetBlock, Payload: GetBlock{ID: id}.MarshalGetBlock()},
	}
}

// MaxUnheldKeyEpochsPerPeer bounds how many announcements one identity may
// spend on proof-of-work key epochs this node is not already working in,
// before the next one is refused without being evaluated.
//
// **It is derived and not chosen.** An identity sending headers the work check
// REFUSES — headers carrying `pow.NextTarget`'s own answer — is charged
// ScoreInvalidMessage each and banned at ScoreBanThreshold, so it can force
// exactly this many never-held key epochs before it is gone. That is not an
// estimate: TestAHeightVaryingFloodIsBoundedInEpochsToo aims its heights at
// epoch starts and asserts the count equals this budget in both directions. The
// observation the budget answers is that a header declaring its OWN target buys
// the same resource with no bound in front of it at all, so the number here is
// the one the charged half already lives under, and the fix is that both halves
// now pay the same price for the same thing. A different number would be a
// claim that an *accepted* announcement should buy more key epochs than a
// refused one, which nothing supports.
//
// **The reference quantity was altered by the change that cites it, and is
// restored by the score conjunct in OnBlockAnnounce.** Because the
// price stands ahead of work.Check, a header the work check WOULD refuse is,
// past the budget, never refused by it — so for a while ScoreInvalidMessage
// never fired and the ban never arrived. ScoreUsefulMessage is +1 against
// ScoreCeiling = 100, so an ordinary long-lived gossiping peer sits near the
// ceiling, and for it the invalid-header flood stopped being self-limiting:
// measured at 60 messages from +20 and from +100, banned neither time
// (TestAnUnpayableAnnouncementIsAlsoAnAmnestyFromTheWorkChecksScore). The
// over-budget refusal now carries ScoreInvalidMessage for exactly those
// identities whose announcements the work check has already refused, which an
// honest peer cannot become and an invalid-header flood is by its first
// evaluated message, so the equation this constant rests on holds again in the
// only case where its two sides can differ.
//
// The ceiling of the ratio, not the floor: a peer starts at zero and is banned
// at `<=` the threshold, so the message that crosses the line is itself
// charged and counted.
//
// **The derivation is now exact in the axis as well as in the number**, which
// it was not when it shipped, and which is the whole reason the budget is keyed
// on the identity rather than on the connection. Both quantities are counted
// against one ed25519 identity: PeerStore.AdjustKey scores the identity and
// BannedKey follows it across every connection it holds, and this budget lives
// on the same identityEntry, charged through PeerStore.SpendUnheldKeyEpoch by
// way of replyBudgetKey. It was on PeerTip, keyed by the connection address,
// and forgetPeer dropped it on disconnect — so an inbound peer, whose address
// is "ip:ephemeral_port", re-bought the whole budget for one TLS handshake,
// measured at 40 never-held epochs across eight reconnects against a budget of
// 5. The two sides differ only in decay, and in the safe direction: the score
// is permanent and this refills, at the rate the honest chain crosses key
// epochs.
//
// **What one identity cannot mint, a thousand identities can**, so this bound
// is the rate and not the total: a keypair is free, and the measurement is that the
// aggregate over identities is whatever the attacker cares to present.
// DefaultMaxUnheldKeyEpochsPerNode is the layer that bounds the total, and it is
// keyed on nothing at all.
const MaxUnheldKeyEpochsPerPeer = (-ScoreBanThreshold + (-ScoreInvalidMessage) - 1) / (-ScoreInvalidMessage)

// MaxWorkEvalsPerConn is how many proof-of-work evaluations one connection may
// force on the block-announce path inside one refill period before further
// distinct announcements are dropped ahead of the evaluation. It is the burst
// the per-connection work budget holds; the refill rate is workEvalPeriod.
//
// A node-policy number, invented in the discipline MaxSeenBlocks is and with a
// measurement deferred to docs/decisions/testnet-measurements.md §2, NOT a
// consensus parameter: two nodes handed the same announcement stream may cap it
// at different points without disagreeing about any block. It bounds only the
// RATE of ingress work, never a block's admissibility — an announcement past
// the burst is dropped at CostBudgeted, the block it names stays obtainable.
//
// Sized to be generous against honest gossip and tight against a flood. An
// honest peer announces the block after this node's tip at most about once per
// TargetBlockSeconds — the announce path is steady-state gossip, and catch-up
// runs on headers-first sync, a different ingress — so at a refill of one
// credit per TargetBlockSeconds an honest connection sits at full budget
// indefinitely and never reaches this number. 128 is far above any honest burst
// (roughly an hour of devnet blocks) and far below the hundreds of evaluations
// per second one connection forced before this budget existed: it turns
// an unbounded per-connection CPU cost into 128 evaluations plus one per period,
// which at ~15-55 ms each is a small fraction of a core rather than a saturated
// one.
//
// **This is the attributable tier-1 layer and NOT the bound on the aggregate.**
// It is keyed on the payer, and a payer is an identity a sender mints for the
// price of a handshake, so N churned identities each spend a fresh
// MaxWorkEvalsPerConn and the total work is N x 128 — linear in identities and
// unbounded, because keypairs are free and the identity store readmits a fresh
// budget on eviction. This layer bounds one static connection and localises the
// cost to the identity that spent it; the churn-proof bound on the sum is the
// node-wide workEvalCeiling below, keyed on nothing, exactly as unheldEpochs is
// the churn-proof layer over the per-identity key-epoch budget.
const MaxWorkEvalsPerConn = 128

// workEvalPeriod is how long one spent work-evaluation credit takes to come
// back: one TargetBlockSeconds, which is the rate a single honest connection
// announces new blocks at, so the honest steady state neither depletes the
// budget nor is throttled by it.
//
// Saturating rather than trusting a zero, on the principle keyEpochPeriod states
// for itself: a zero period would make SpendWorkEval admit every
// announcement — the safe direction, an unbounded cost being less bad than a
// node that stops evaluating gossip — but returning MaxUint64 here keeps the
// refill arithmetic well-defined instead of leaning on that admit arm, and a
// parameter set with TargetBlockSeconds == 0 is refused by params.Validate
// anyway.
func workEvalPeriod(p *params.Params) uint64 {
	if p.TargetBlockSeconds == 0 {
		return math.MaxUint64
	}
	return p.TargetBlockSeconds
}

// The node-wide work-evaluation ceiling: the burst of announce proof-of-work
// evaluations this node will run added over EVERY sender at once, and the rate
// it refills at. workEvalCeiling returns the pair; nodeWorkEvals is the counter.
//
// **Sized against CPU TIME directly, not against the connection set, and that
// is the difference from unheldKeyEpochCeiling.** The key-epoch ceiling is
// connSet x MaxUnheldKeyEpochsPerPeer because a key-epoch charge is a rare
// ~0.55 s cache build and the honest demand for it scales with how many peers
// announce out of epoch. A work evaluation is a ~15-55 ms check demanded at
// thousands per second, and the honest demand for it does NOT scale with peer
// count: the seen-set dedup read at the top of OnBlockAnnounceFrom fires across
// peers, so only the FIRST announcer of a given block id runs a work check and
// every other peer's announcement of the same id returns CostDeduped before
// reaching this layer. So honest node-wide demand is about the number of
// DISTINCT new blocks per period — one or two — while a flood's distinct junk
// ids never dedup and each want an evaluation. The ceiling is therefore a flat
// CPU budget, not a per-connection product: what one core can absorb without
// contending with mining, which at ~10% of a core over a refill period is on
// the order of tens of evaluations sustained, with a burst several times that.
//
// **These are node-policy numbers in the discipline of MaxSeenBlocks, invented
// and with a measurement deferred to docs/decisions/testnet-measurements.md §2,
// NOT consensus parameters** — two nodes may cap the same announcement stream at
// different points without disagreeing about any block. The window they sit in
// is wide and that is what makes the exact value not load-bearing: honest demand
// is ~2 per period, ~54 per period is an absorbable ~10% of a core, and a flood
// wants thousands. NodeWorkEvalRefillPerPeriod is set inside that window and
// NodeWorkEvalCeiling a burst above it; both are round numbers chosen for the
// window rather than crawled to a measured edge.
//
// **Why this does not strangle honest propagation, and it is a property of the
// sync path rather than of this number.** The sync driver's own header and body
// requests never consult this ceiling (the same independence
// unheldKeyEpochCeiling documents: "the sync driver's own header and body
// requests never consult this ceiling"). A node that is behind learns blocks
// through headers-first SYNC even with this bucket at zero. What the ceiling can
// suppress is GOSSIP of newly announced tips — bounded and recoverable, and
// strictly better than the CPU saturation it replaces: a saturated node runs no
// consensus at all, whereas a node holding this ceiling at zero stays
// responsive, falls back on sync, and recovers within a few refill periods once
// the flood stops. The refusal also keeps recordAnnounce and does not enter the
// id into seenBlocks, so a suppressed block is re-learnable the moment the
// bucket refills, another peer announces it, or sync reaches it.
const (
	// NodeWorkEvalCeiling is the burst the node-wide work-eval bucket holds.
	NodeWorkEvalCeiling = 256
	// NodeWorkEvalRefillPerPeriod is how many work-eval credits return per
	// workEvalPeriod — the sustained rate this node absorbs, set inside the
	// window between honest demand (~2) and what saturates a core (thousands).
	NodeWorkEvalRefillPerPeriod = 64
)

func workEvalCeiling() (ceiling, perPeriod uint32) {
	return NodeWorkEvalCeiling, NodeWorkEvalRefillPerPeriod
}

// keyEpochPeriod is how long one spent unheld-epoch credit takes to come back:
// the time the honest chain itself takes to cross one key epoch.
//
// Derived from the schedule rather than invented, which is the whole reason
// this refill can be defended. `randomx_key_interval` blocks at
// `target_block_seconds` each is one re-key — "roughly every 4.2 hours instead
// of every 17" is how spec/params.testnet.json describes the same product — so
// this grants one credit per new key epoch the honest chain enters.
//
// What it does NOT say, because the charge is per announcement and not per
// distinct epoch: that an honest peer's demand is one credit per period. In
// the only regime where an honest peer spends credits at all — this node more
// than one key epoch behind, so a peer at the network tip announces outside
// {own, own+1} — that peer announces once per block and therefore wants one
// credit per `target_block_seconds`, which is `randomx_key_interval` times
// this rate. In the regime where the claim holds, an honest peer needs zero.
// The budget still bounds, and the burst it allows is what carries an honest
// peer across a boundary; but the liveness cost of a long catch-up is the
// budget, not the period, and it is stated as a cost on the PR rather than
// derived away here. Charging per distinct epoch would match the dimension and
// would be weaker, because a two-entry key table means the same epoch really
// can be rebuilt.
//
// Saturating rather than wrapping. params.Validate constrains the lag against
// the interval and neither against target_block_seconds, so the product can
// exceed uint64; a wrapped period is a SHORTER one, and a shorter one hands
// out credits the chain never earned. A parameter set whose key epoch outlasts
// any node's uptime therefore grants no credits at all, which refuses rather
// than over-grants, and that is the safe direction here. Stating the
// arithmetic's own property, rather than borrowing it from the validator, is the
// precedent an underflow guard defeated by an overflowing sum already set.
func keyEpochPeriod(p *params.Params) uint64 {
	if p.TargetBlockSeconds == 0 || p.RandomXKeyInterval > math.MaxUint64/p.TargetBlockSeconds {
		return math.MaxUint64
	}
	if period := p.RandomXKeyInterval * p.TargetBlockSeconds; period != 0 {
		return period
	}
	return math.MaxUint64
}

// workingKeyEpoch reports whether a header at this height is judged under a key
// epoch this node is itself working in, and therefore costs a hash rather than
// a 256 MiB allocation and an Argon2 fill.
//
// Two epochs, and each is there for its own input rather than for symmetry.
// The tip's own, because this node verified its tip under that key and cannot
// be announced anything at its own height without needing it anyway. The next
// one, because an honest announcement extends the announcer's tip: at a key
// boundary the block after this node's tip is the first block of the following
// epoch, and every honest peer announces into it for the whole interval it
// takes this node's own tip to cross. Charging that would throttle every
// honest peer at every boundary at once, which is a cost bug traded for a
// liveness bug.
//
// The epoch BELOW the tip's is deliberately not exempt, even though a reorg
// across a boundary is an honest reason to be sent one. It is rare, the budget
// covers a burst of them, and a third exempt epoch is a third fixed epoch an
// attacker can hash into for free.
//
// Written as membership in a two-element set rather than as `epoch >= own &&
// epoch-own <= 1`, and the difference is not style. That form carries a
// conjunct with no separating input: unsigned subtraction on a LOWER epoch
// already underflows to a value far above 1, so `epoch >= own` can be deleted
// without changing a single answer, and a guard whose terms cannot be told
// apart by any input is a guard nobody can check. The form below has one input
// per term. It pays for that with an addition that wraps at `own == 2^64-1` — a
// tip epoch no reachable chain has — which is the trade the other way round
// from that underflow guard's: there the wrap DISABLED a guard, here the wrap
// it can have is unreachable while the underflow the subtraction form leans on
// is load-bearing on every call.
func workingKeyEpoch(epoch, own uint64) bool {
	return epoch == own || epoch == own+1
}

// spendKeyEpoch prices the key epoch a header's height selects, per connection,
// and reports the epoch and whether this announcement may have it.
//
// # What is being priced
//
// `pow.CheckWork` evaluates the work function under `pow.KeyFor(h.Height, p)`
// BEFORE it compares anything, and the height is the sender's to choose. Under
// randomx-v1 a key this node does not hold is a 256 MiB allocation and an
// Argon2 fill against 15–55 ms for a hash under a key it does hold. So an
// announcement's height, not its target and not its bytes, is what decides its
// cost to this node, and until this budget existed nothing looked at it before
// the money was spent.
//
// **The fill is 0.554 s, measured on the node's own configuration rather than
// inherited.** core/pow/randomx.BenchmarkInitCacheNodeConfig, `-tags randomx
// -benchtime=1x -count=5`, median of five single-iteration runs on a loaded
// 20-thread machine — load can only inflate, so it is an upper bound: 553.9 ms,
// range 541.8–563.1 ms. Its sibling BenchmarkInitCache, which uses Keys 1 /
// MaxVMs 1 instead of what cmd/zycordd builds, gives 529.7 ms on the same runs.
//
// **The gap between those two rows is NOT a measured result, and an earlier
// revision of this comment claimed it was.** It read the 24 ms between them as
// the GOMAXPROCS virtual machines a real key init also creates. An independent
// repetition at the same sample size put the two medians about 1 ms apart with
// fully overlapping ranges, so that difference is real in the code and not
// separated from noise by five single iterations. What both samples do agree on
// is the only thing this layer needs from them: the magnitude is about 0.55 s,
// not the 1.7 s the family was written against.
//
// **0.554 s is the half this budget can SEE, and the marginal cost to the node
// is up to twice it.** The engine's key table is an LRU of Keys entries — two
// at the Options cmd/zycordd builds — and {tipEpoch, tipEpoch+1} exactly fills
// it. That pair is not hypothetical: workingKeyEpoch exempts both precisely
// because honest peers announce into tipEpoch+1 for the whole interval this
// node's tip takes to cross a boundary, so the table is full of keys this node
// needs exactly when it is busiest. Engine.entryFor evicts e.keys[0], the least
// recently used, so an attacker-forced build in that state evicts a WORKING
// key — and the honest rebuild that follows is inside {tipEpoch, tipEpoch+1},
// where workingKeyEpoch returns true, spendKeyEpoch never charges, and no
// counter in this file records it at all. One forced build therefore costs this
// node up to 2 x 0.554 s, of which the budget charges one.
//
// **"Up to", and what caps it is INTERLEAVING rather than run length.** Traced
// against entryFor with Keys at 2 and both working keys resident: the first
// forced build evicts one working key and the second evicts the OTHER, so only
// the third churns a slot the sender itself owns. A long uninterrupted run
// therefore costs two working-key evictions in total and then recycles the
// sender's own two entries — a burst is the case that does NOT sustain the
// doubling. What sustains it is alternation: honest traffic rebuilds a working
// key for free, the next forced build evicts it again, and every such pair pays
// the full 2 x. (With only tipEpoch resident the table is not yet full, so the
// first build evicts nothing and the second takes the working key — the same
// conclusion one build later.)
//
// Away from a key boundary only tipEpoch NEED be resident, because own+1's
// cache is built only once something announces into that epoch. That is a
// statement about honest traffic and not a bound on a sender: workingKeyEpoch
// exempts own+1 unconditionally and charges nothing for it, so a sender can
// populate the second slot for free whenever it wants the table full. It does
// not move the figure above.
//
// That does not loosen the bound: what is bounded here is the NUMBER of forced
// builds, and that number is unchanged. It is the honest width of what one
// costs. It went missing for the reason such terms do — the charged half was
// correct, so nothing looked past it.
//
// **The configuration is the load-bearing half of that number and it is settled
// structurally, not assumed.** A verifying node is
// `randomx.New(Options{FullMemory: false})` (cmd/zycordd), so every key init is
// light. A MINING node sets FullMemory, but Engine.hashRaw serves the dataset
// only when the requested key equals `fastKey`, which MineOn is the sole writer
// of; every other key falls through to build(), which passes nil for the
// dataset and creates VMs from flags carrying no FULL_MEM — the wrong-key-seal
// fix, stated there as a property of the structure. And an epoch charged here is
// outside {tipEpoch, tipEpoch+1} by construction, which is where a miner's own
// key lives. So the attack forces a cache-only fill on every node
// configuration, and the 2 GiB dataset figure is not reachable through it.
//
// This number had no instrument until it was taken. The figure the whole family
// was written against was ~1.7 s, three times this and re-derivable by nobody —
// a transcribed magnitude that stays true while the argument it supports
// weakens is a standing hazard in this tree, and the standing claim that
// core/pow/randomx could not compile on the measuring machine is why it
// survived as long as it did.
//
// # Why a price, and not either of the two guards that were tried
//
// Bounding the accepted `h.Target` was rejected in adversarial/sync.md §6.1:
// difficulty may legitimately fall, so a node whose tip is old cannot
// bound the network's current target from below and would refuse honest
// announcements precisely while far behind. A window on the height around this
// node's tip was built and reverted (I7-H4): a node that is behind legitimately
// receives announcements far ahead and must act on them.
//
// Both of those refuse. This one charges. An announcement naming an epoch this
// node is not working in is evaluated, forwarded and acted on exactly as
// before — it costs the sender one of a small number of credits, and the
// credits come back at the rate the honest chain crosses key epochs. A node
// that is behind still requests the block a peer announced far ahead; what it
// no longer does is let one identity buy an unbounded number of distinct
// epochs at that height.
//
// # Why this does not ask the engine "do you hold this key"
//
// ARCHITECTURE §20 records the intended shape as a method on
// `pow.Engine`. It is not built that way, and the reason is not convenience:
//
//   - The engine's key table is an LRU of `Keys` entries (two by default), so
//     "do you hold this key" is a function of whatever traffic ran most
//     recently — which the attacker also sends. An identity cycling two epochs
//     of its own choosing evicts the epoch an honest peer is announcing into,
//     and every honest announcement then reads as unheld. CostClass's own
//     documentation requires the opposite: "the budget must itself be bounded
//     independently of the sender's choices".
//   - It would make an ingress verdict — Forward, Score — depend on engine
//     cache state, so two nodes handed the same message answer differently.
//     This one is an argument and is offered as one, because the nearest
//     thing to a rule already written is about something else:
//     pow.HotKeyEngine says which internal representation an engine keeps
//     warm "is not a consensus fact and must never be one", and closes "an
//     engine that ignores this hint computes exactly the same digests, more
//     slowly". That is a line about DIGESTS, and an ingress verdict is not a
//     consensus fact either way. Same resource, different line — what it
//     supports is that the tree already refuses to let cache state change an
//     answer, not that it has already refused this.
//   - The only implementation for which the answer is non-trivial is
//     core/pow/randomx, which compiles only under a build tag and a C
//     toolchain. A defence whose sole live implementation no ordinary test
//     builds is a defence nothing observes.
//
// The height and the node's own tip answer the same question without any of
// that, and they are facts this node owns. The third return is `own`, and it is
// `replyBudgetExhausted`'s second return under the same name because it is the
// same distinction. Both layers refuse, and only one of them names a party: the
// per-identity budget is keyed on the authenticated identity, so its refusal is
// attributable to the payer in front of it, and the node-wide ceiling is keyed
// on nothing at all, so its refusal can have been caused entirely by traffic
// this payer never sent. `own` is true only on the second of those, and it is
// false whenever `ok` is true — a refusal is the only state in which the
// question means anything.
//
// **Without it the two refusals were one value, and the measurement is what
// that costs.** 48 identities x 5 announcements — 55,680 bytes and no proof of
// work at all, since this function stands ahead of `work.Check` — drain the
// shared ceiling; a third identity whose own budget is untouched is then
// refused by the ceiling, and the conjunct at the call site charged it
// `ScoreInvalidMessage` and banned it in five, under an error string that said
// it had spent a budget it had not touched. That is scoring somebody for
// another peer's flood, which is the shape the served path's `own` disjunct
// forbids one primitive over and which
// `TestARefusalByTheSharedCeilingIsNeverScored` already pins for `get-headers`
// and `get-block`. The announce path had both layers and the score conjunct and
// was missing only the disjunct beside them.
func (e *Engine) spendKeyEpoch(payer string, height uint64) (epoch uint64, ok, own bool) {
	// Chain and params read outside the engine lock, as recordAnnounce's own
	// chain reads are, and for the same reason.
	p := e.Chain.Params()
	epoch = pow.SeedEpochFor(height, p)
	if workingKeyEpoch(epoch, pow.SeedEpochFor(e.Chain.Height(), p)) {
		return epoch, true, false
	}
	period := keyEpochPeriod(p)
	now := e.now()
	// The node-wide ceiling is read first and charged last, so that an
	// announcement refused by the payer's own budget does not consume a
	// node-wide credit it never spent. Read-then-charge rather than one
	// critical section, mirroring replyBudgetExhausted / chargeReplyBytes next
	// door: two handlers racing here can overshoot the ceiling by at most the
	// number of announcements in flight, which is bounded by the connection
	// set and not by the sender.
	if e.nodeKeyEpochsExhausted(period, now) {
		return epoch, false, false
	}
	if e.Peers != nil && !e.Peers.SpendUnheldKeyEpoch(payer, MaxUnheldKeyEpochsPerPeer, period, now) {
		return epoch, false, true
	}
	e.chargeNodeKeyEpoch(period, now)
	return epoch, true, false
}

// ownKeyEpochsExhausted reports whether this payer's own unheld-key-epoch
// budget is already spent, and charges nothing for asking.
//
// It exists for one caller and one arm: the node-wide-ceiling refusal above,
// where `own` is false. `own` answers "did THIS payer's own budget refuse this
// message", and while the ceiling is down the answer is no for everybody,
// because spendKeyEpoch returns before SpendUnheldKeyEpoch is ever reached.
// That is correct as far as it goes and it is why the never-score-a-shared-
// ceiling-refusal disjunct is keyed on it — but conjoined with the work-refused
// bit it switched off the only terminating class the announce path has, for the
// caught identities as well as the uncaught ones, for as long as an attacker
// holds the ceiling at zero.
//
// This is the second question, and it is a different one: not "was this message
// refused by the payer's own budget" but "is the payer's own budget spent". A
// caught identity that has already burnt its whole attributable allowance is
// attributable on that evidence whichever layer happens to refuse the next
// message, and an identity holding an intact budget is not — so the ceiling
// arm's amnesty keeps its whole purpose, which is that an honest peer whose
// budget the ceiling never let it spend is never scored for somebody else's
// flood.
//
// **The read must not charge, and that is the whole reason it is a new peer
// store method rather than a second SpendUnheldKeyEpoch call.** Reading the
// per-payer layer first, or calling the spender here, would spend a credit for
// a refusal the shared ceiling caused; that mutant was driven and killed at 26
// of 30 refusals scored
// (TestAnAnnounceRefusalByTheSharedKeyEpochCeilingIsNeverScored is where it
// dies). UnheldKeyEpochsExhausted reuses the spender's own refill helper, so
// the two cannot drift.
//
// No peer store is not exhausted, which matches spendKeyEpoch's own nil-store
// arm: without a store there is no per-identity budget to have spent, so there
// is nothing this payer can be held to.
func (e *Engine) ownKeyEpochsExhausted(payer string) bool {
	if e.Peers == nil {
		return false
	}
	return e.Peers.UnheldKeyEpochsExhausted(payer, MaxUnheldKeyEpochsPerPeer,
		keyEpochPeriod(e.Chain.Params()), e.now())
}

// spendWorkEval charges one proof-of-work evaluation ahead of work.Check and
// reports whether this announcement may run it, and — when it may not — whether
// the refusal is attributable to the payer's own budget (own) or to the shared
// node-wide ceiling (own=false).
//
// It is the charge on the RandomX evaluation itself, and it stands beside
// spendKeyEpoch rather than inside it because the two answer different
// questions. spendKeyEpoch bounds how many key epochs this node is NOT working
// in one sender can force it to BUILD — a ~0.54 s cache fill each — and exempts
// the working epoch for a liveness reason: an honest peer announces the block
// after this node's tip into the working epoch for the whole interval the tip
// takes to cross a key boundary, so charging it there throttles every honest
// peer at once. That exemption is exactly the hole this charge closes: in the
// working epoch a distinct announcement reaches the memory-hard work.Check with
// nothing in front of it, at ~15-55 ms each.
//
// **Two layers, and the second is the one that survives identity churn.** The
// node-wide ceiling is read FIRST and charged LAST, exactly as spendKeyEpoch
// reads nodeKeyEpochsExhausted before charging the payer, so a refusal by the
// payer's own budget never consumes a node-wide credit it did not spend:
//
//   - node-wide ceiling exhausted -> refuse, own=false. Keyed on nothing, so a
//     churned population of fresh identities shares one bucket and their
//     aggregate cannot exceed it. This is the bound the hostile review of the
//     per-connection-only version defeated: N identities each spent a fresh
//     MaxWorkEvalsPerConn for N x 128 total, and only a shared counter caps the
//     sum.
//   - payer's own per-connection budget exhausted -> refuse, own=true. The
//     attributable tier-1 layer; it localises a static flooder's cost to the
//     identity that spent it and is charged only when the node-wide ceiling had
//     room, so it is a fact about this payer.
//   - otherwise -> charge the node-wide counter and admit.
//
// own exists for the caller's scoring decision and mirrors spendKeyEpoch's
// third return: a node-wide-ceiling refusal can have been caused entirely by
// another peer's flood, so it must never be scored. This path scores neither
// refusal — a max-target header passes work.Check, so there is no invalid
// message to charge for on either arm — but the distinction is surfaced so the
// call site states which layer refused, and so a later change cannot score the
// shared-ceiling arm by accident.
//
// The per-identity layer is skipped where e.Peers is nil or the payer is empty
// (OnBlockAnnounce's pre-handshake fallback); the node-wide ceiling still
// applies, because it is keyed on nothing a caller has to present.
// announceWorkingEpoch reports whether an announcement at this height selects a
// key epoch this node is working in — the epochs spendKeyEpoch admits for free.
// It is what scopes the work-eval budget to its actual hole: out-of-epoch
// announcements are charged and node-wide-bounded by the key-epoch budget
// instead, so they are not counted twice.
func (e *Engine) announceWorkingEpoch(height uint64) bool {
	p := e.Chain.Params()
	return workingKeyEpoch(pow.SeedEpochFor(height, p), pow.SeedEpochFor(e.Chain.Height(), p))
}

func (e *Engine) spendWorkEval(payer string) (ok, own bool) {
	period, now := workEvalPeriod(e.Chain.Params()), e.now()
	if e.nodeWorkEvalsExhausted(period, now) {
		return false, false
	}
	if e.Peers != nil && !e.Peers.SpendWorkEval(payer, MaxWorkEvalsPerConn, period, now) {
		return false, true
	}
	e.chargeNodeWorkEval(period, now)
	return true, false
}

// nodeWorkEvalsExhausted reports whether this node has already run its node-wide
// allowance of announce work evaluations for the current window. A read and
// nothing else, so spendWorkEval can consult it before charging; the refill it
// accounts for is arithmetic in refilledUnheldEpochs and written back only by
// chargeNodeWorkEval. A zero period disables the ceiling rather than refusing
// every announcement, the direction nodeKeyEpochsExhausted takes.
func (e *Engine) nodeWorkEvalsExhausted(period, now uint64) bool {
	if period == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ceiling, perPeriod := workEvalCeiling()
	spent, _ := refilledUnheldEpochs(e.nodeWorkEvals, e.nodeWorkEvalsAt, period, now, perPeriod)
	return spent >= ceiling
}

// chargeNodeWorkEval adds one announce work evaluation to this node's window.
func (e *Engine) chargeNodeWorkEval(period, now uint64) {
	if period == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, perPeriod := workEvalCeiling()
	e.nodeWorkEvals, e.nodeWorkEvalsAt = refilledUnheldEpochs(e.nodeWorkEvals, e.nodeWorkEvalsAt, period, now, perPeriod)
	// Saturating rather than wrapping, the direction chargeNodeKeyEpoch takes: a
	// wrapped total is a smaller one and hands back a ceiling already spent.
	if e.nodeWorkEvals == ^uint32(0) {
		return
	}
	e.nodeWorkEvals++
}

// DefaultMaxUnheldKeyEpochsPerNode is the node-wide ceiling on how many
// announcements this node will evaluate under proof-of-work key epochs it is
// not already working in, added over every sender at once, at the connection
// set NewNode installs. unheldKeyEpochCeiling is the live ceiling and reads the
// operator's own configuration; this is that function at the defaults.
//
// **It is the ceiling the per-identity budget already implied at an instant,
// made true over time as well, and that is the whole of its derivation.** The
// per-identity budget is keyed on an Ed25519 identity, which is measurably
// free to mint — a keypair costs nothing, so bounding the rate per identity
// does not bound the total. This layer is keyed on nothing at all: there is
// one counter, no table to evict from, and no identifier a sender presents.
// That is what CostClass asks for when it requires "the budget must itself be
// bounded independently of the sender's choices", and it is the one axis for
// which the sentence is true by construction.
//
// The number is the connection set this node admits multiplied by what one
// payer may spend: Node.register admits inbound below MaxInbound+MaxOutbound
// and topUp dials up to MaxOutbound above that gate, so the concurrent set is
// MaxInbound + 2*MaxOutbound — 48 at the defaults, the same 48 engine.go's
// reassembly arithmetic and syncdriver.go's syncTried bound are each sized
// against, and the set 240 unheld epochs were measured across. So no
// arrangement of peers that could reach a key epoch before this ceiling existed
// is refused by it at an instant; what it removes is the multiplication
// over identities and over time, that made the same 240 arrive again
// every time the sender chose.
const DefaultMaxUnheldKeyEpochsPerNode = (DefaultMaxInbound + 2*DefaultMaxOutbound) * MaxUnheldKeyEpochsPerPeer

// maxUnheldConnectionSet clamps the configured connection set the ceiling is
// derived from, so that the product below fits uint32 on a 32-bit int as well
// as a 64-bit one. A million concurrent connections is far above any file
// descriptor limit a node runs under; the clamp is here so this arithmetic owns
// its own range rather than borrowing it from whatever an operator types, which
// is the principle keyEpochPeriod's saturation already follows.
const maxUnheldConnectionSet = 1 << 20

// unheldKeyEpochCeiling returns the node-wide ceiling on never-held key epochs
// and the rate, in credits per keyEpochPeriod, that it refills at.
//
// **Both come out of one number so that they cannot drift, and that pairing is
// the fix for a defect this layer shipped with.** The ceiling is the connection
// set multiplied by MaxUnheldKeyEpochsPerPeer; the refill is the connection set
// itself. Dividing one by the other leaves MaxUnheldKeyEpochsPerPeer periods
// for a drained ceiling to come back — exactly the recovery time one payer's
// own budget has, because that budget is MaxUnheldKeyEpochsPerPeer credits
// refilling at one per period. The two layers now say the same thing about time
// that they already said about size.
//
// **What it was, and why one credit per period was not a bound.** This bucket
// refilled at the per-payer layer's rate rather than at its own scale, so a
// drained ceiling took DefaultMaxUnheldKeyEpochsPerNode periods to return: measured,
// one admission after each of three successive periods and the full 240 only
// after 240 of them, which is 1024 h on the public testnet's 512 x 30 s
// schedule and about 170 days on mainnet's 2048 x 30 s. The consequences were
// measured too, and they are the layer inverting its own purpose: 48 sequential
// handshakes from one address drained it, two fresh honest identities holding
// untouched budgets of their own were then refused, and one identity sending a
// single announcement per period held it at zero indefinitely. A bound whose
// recovery is a third of a year is a one-way latch, not a ceiling. The cost of
// the latch was bounded — gossip relay of out-of-epoch blocks, with the sync
// driver untouched — which is why it was not launch-blocking; it is fixed here
// because bounded and recoverable are different properties.
//
// **What the rate leaves an attacker is a real cost and is stated rather than
// argued away.** The sustained charge is one never-held epoch build per
// connection slot per key epoch the honest chain enters — 48 builds per period
// at the defaults. At the 0.554 s spendKeyEpoch measures that is 26.6 s of
// Argon2 per period: under 0.2% of one core on the testnet's 4.2 h period and
// under 0.05% on mainnet's 17 h. Both percentages are arithmetic over a
// measured fill rather than over an inherited one, and they were computed
// against the same 0.55 s before the fill was taken, so the measurement
// confirmed them rather than moving them.
//
// **Double them for the term this budget cannot see.** spendKeyEpoch's own
// comment records it: the engine holds Keys: 2 caches, {tipEpoch, tipEpoch+1}
// fills the table, so a forced build can evict a working key and the honest
// rebuild that follows is exempt and charged to nobody. So the node-visible
// sustained cost of this rate is up to 53 s per period rather than 26.6 s —
// under 0.4% of one core on testnet and under 0.1% on mainnet. Still small,
// and now stated at its full width instead of at its charged half.
//
// The old text on this line claimed 240 per period; that was
// the bucket, not the rate, wrong by the size of the bucket and wrong in the
// direction that understated what the layer costs in liveness rather than what
// it costs in CPU.
//
// **A shared budget is a lever, and this one is shared on purpose.** That is
// the objection TestTheKeyEpochBudgetIsPerIdentityAndNotShared exists to
// enforce against the layer below, and it is conceded rather than argued away
// here: one sender can spend this whole ceiling, and every other peer is then
// refused an unheld-epoch evaluation until it refills. At the defaults that
// costs an attacker ten fresh identities per period to hold at zero, and a
// keypair is free, so the concession is that it CAN be held there for as long
// as the attacker keeps paying.
//
// **What is reachable, stated as what the code does rather than as what would
// be convenient.** An announcement is charged here whenever the key epoch its
// height selects is outside {tipEpoch, tipEpoch+1} — which is not the same set
// as "this node is far behind", and this comment used to say it was. Three
// arrangements reach it, and only the first is a node in trouble:
//
//   - a node more than one key epoch behind, for which every honest peer at the
//     network tip announces out of epoch — 17 h on mainnet, 4.3 h on the public
//     testnet;
//   - **a node exactly at the tip**, on any announcement whose height sits
//     BELOW its own epoch. workingKeyEpoch exempts {own, own+1} and its own
//     comment names this input — "the epoch BELOW the tip's is deliberately not
//     exempt, even though a reorg across a boundary is an honest reason to be
//     sent one" — so workingKeyEpoch(3, 5) and workingKeyEpoch(4, 5) are both
//     false, and a tip that has just crossed a key boundary charges for every
//     short fork below it. Measured on devnet parameters: a tip at height 456
//     is epoch 7, a fork block at 455 is epoch 6, and it is charged;
//   - any sender naming an arbitrary height, which is the case the whole layer
//     exists for.
//
// So the trade is not payable because nobody near the tip can notice. It is
// payable because of what a refusal costs and how fast it lifts. What is lost
// is gossip-driven relay of an out-of-epoch block — a class that at the tip is
// short forks across a boundary, and behind the tip is blocks the node was
// going to fetch anyway. What is NOT lost is progress: the sync driver's own
// header and body requests never consult this ceiling, and the refusal keeps
// recordAnnounce, so the peers a catching-up node depends on stay sync
// candidates with their heights tracked exactly
// (TestACatchingUpNodeKeepsThePeersItDependsOnWithAnExhaustedKeyEpochBudget).
// And the ceiling now returns at the connection set per period rather than at
// one credit per period, so an attacker that stops paying stops suppressing
// within MaxUnheldKeyEpochsPerPeer periods instead of within the months
// measured above.
//
// **It follows the operator's own configuration, and that is not a
// refinement.** A package constant sized on DefaultMaxInbound gave a node
// configured at MaxInbound 144 a ceiling of 240 against a per-payer aggregate
// of 800, so only 48 of its 160 connection slots could ever have an
// out-of-epoch announcement evaluated and the rest were refused before their
// own budgets were consulted at all; at 256/16 it was 48 of 288. A bootstrap
// node is exactly the machine that raises MaxInbound and exactly the machine
// whose refusals cost the network most, so "sized for the defaults" was not the
// safe half of the trade — it made the ceiling, rather than the per-payer
// budget, the binding constraint on every peer above the 48th.
//
// **And that is a trade, not a repair, because following the configuration also
// multiplies what the same machine absorbs.** At 256/16 the ceiling goes
// 240 -> 1440, so a fully drained ceiling is about 798 s of Argon2 rather than
// about 133 s — roughly 400 s of wall clock once serialised on the engine's
// Keys-wide build gate — and the sustained charge goes from 48 to 288 builds
// per period, about 1.0% of one core on testnet's 4.2 h period against the 0.2%
// the defaults cost. It is still the right direction: an operator who raises
// MaxInbound is asking to serve more peers, and the alternative is refusing
// them before their own budgets are read. But a trade stated with only its
// benefit is not a trade, so both halves are here. What does not move with the
// configuration is the shape: the per-payer layer, the ban, and the sync
// driver's independence from this ceiling are the same at every setting, and
// the refill scales with the bucket so recovery stays MaxUnheldKeyEpochsPerPeer
// periods rather than growing with MaxInbound.
//
// A set of zero or less means nothing has been published yet and the defaults
// apply, rather than a ceiling of zero. That is the direction SpendUnheldKeyEpoch's
// own zero arm takes: a node that refuses all out-of-epoch gossip is a worse
// failure than an unpayable announcement.
func unheldKeyEpochCeiling(connSet int) (ceiling, perPeriod uint32) {
	set := connSet
	if set <= 0 {
		set = DefaultMaxInbound + 2*DefaultMaxOutbound
	}
	if set > maxUnheldConnectionSet {
		set = maxUnheldConnectionSet
	}
	return uint32(set) * MaxUnheldKeyEpochsPerPeer, uint32(set)
}

// SetConnectionSet tells the Engine how large a concurrent connection set the
// Node above it will hold, which is what the node-wide key-epoch ceiling is
// derived from.
//
// Pushed in by the Node rather than read out of it, the same shape and for the
// same reason as SetDialledGroups: the Engine is the protocol logic and does
// not own a connection table, and a package constant that has to be kept in
// step with Node.register's gate by hand is exactly the drift this replaces.
// Node.publishConnectionSet calls it from register itself, so the ceiling is
// sized from the same two fields the gate reads, at the moment it reads them.
//
// The set is MaxInbound + 2*MaxOutbound and not MaxInbound + MaxOutbound,
// because register's gate is inbound-only and topUp dials up to MaxOutbound
// above it — the same product engine.go's reassembly arithmetic and
// syncdriver.go's syncTried bound are each sized against.
// The sum is stored raw and is range-checked in exactly one place,
// unheldKeyEpochCeiling, which clamps above and takes the defaults at or below
// zero. A second clamp here was written first and then deleted: every value it
// could refuse, the one there already refuses, so no input separated the two and
// a guard nobody can check is worth deleting rather than documenting — the
// standard refilledServed sets in this package and the one refilledUnheldEpochs'
// own credits == 0 arm was deleted under. An operator large enough to overflow
// this addition lands on one of those two arms whichever way it wraps, so the
// product is bounded either way.
func (e *Engine) SetConnectionSet(maxInbound, maxOutbound int) {
	e.mu.Lock()
	e.connSet = maxInbound + 2*maxOutbound
	e.mu.Unlock()
}

// nodeKeyEpochsExhausted reports whether this node has already spent its
// node-wide allowance of never-held key epochs for the current window.
//
// A read and nothing else, which is what lets spendKeyEpoch consult it before
// charging the payer; the refill it accounts for is arithmetic in
// refilledUnheldEpochs and is written back only by chargeNodeKeyEpoch.
//
// A zero period disables the ceiling rather than refusing every announcement,
// for the reason SpendUnheldKeyEpoch's own zero arm gives: a node that refuses
// all gossip is a worse failure than an unpayable announcement. keyEpochPeriod
// saturates rather than returning zero, so this arm needs a caller that does
// not use it.
func (e *Engine) nodeKeyEpochsExhausted(period, now uint64) bool {
	if period == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ceiling, perPeriod := unheldKeyEpochCeiling(e.connSet)
	spent, _ := refilledUnheldEpochs(e.unheldEpochs, e.unheldEpochsAt, period, now, perPeriod)
	return spent >= ceiling
}

// chargeNodeKeyEpoch adds one never-held key epoch to this node's own window.
func (e *Engine) chargeNodeKeyEpoch(period, now uint64) {
	if period == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, perPeriod := unheldKeyEpochCeiling(e.connSet)
	e.unheldEpochs, e.unheldEpochsAt = refilledUnheldEpochs(e.unheldEpochs, e.unheldEpochsAt, period, now, perPeriod)
	// Saturating rather than wrapping: a wrapped total is a SMALLER one, and a
	// smaller one hands back a ceiling this node has already spent. Unreachable
	// while the read above refuses at the ceiling, and stated here so the
	// arithmetic carries its own property rather than borrowing it from a
	// caller.
	if e.unheldEpochs == ^uint32(0) {
		return
	}
	e.unheldEpochs++
}

// growTransfer returns a reassembly buffer holding buf followed by data, in an
// allocation sized to exactly that.
//
// append would do the same job and is what this was, but append's amortised
// growth leaves the buffer owning capacity nobody asked for and the budget was
// never told about — 18.15% of the allocation on the honest two-chunk transfer
// at the wire's own chunk size, measured on the toolchain this was written
// against, and the sender picks the chunking that decides it. Sizing
// every write exactly makes cap > len unreachable for a reassembly buffer, so
// the budget is right by construction rather than by carrying a second
// accounting of the slack.
//
// The cost this trades for exactness is a full recopy of the prefix on every
// chunk, so the bytes copied over a transfer are quadratic in its chunk count
// and the work happens under e.mu. What bounds it is BlockByteCapacity and not
// MaxBlockChunks: the capacity is rechecked after every write, so a transfer
// is dropped once it passes it and the buffer is regrown at most
// BlockByteCapacity/BlockChunkBytes + 1 times whatever Total a sender claims.
// At the committed parameters that is one regrowth of 4 MiB, which is nothing.
// It is named here because it scales with (BlockByteCapacity/BlockChunkBytes)^2
// and that ratio is exactly what an era boundary re-pins: raising the capacity
// without raising BlockChunkBytes with it puts this copy, not the allocation,
// on the critical path under the engine lock.
func growTransfer(buf, data []byte) []byte {
	grown := make([]byte, len(buf)+len(data))
	copy(grown, buf)
	copy(grown[len(buf):], data)
	return grown
}

// partialBlock is one in-flight chunked transfer.
type partialBlock struct {
	id    types.Hash
	total uint32
	next  uint32
	buf   []byte
	// started orders transfers for eviction. A counter and not a clock:
	// consensus code forbids clocks, and this file has no business
	// introducing one for bookkeeping a monotonic integer settles.
	started uint64
}

// The reassembly bounds. Three of them, because they bound three different
// things and only the last one is memory.
//
// MaxPartialTransfers bounds how many peers may hold buffers at once, and
// MaxTransfersPerPeer how many each may hold — the second sized for the
// announcement bursts an honest peer produces (a fork, a catch-up) rather
// than for a hostile flood, since past it the oldest transfer is evicted and
// not the peer.
//
// **Neither of those is a memory bound, and saying so was the mistake this
// third constant fixes.** Counts multiply: the connection set is bounded by
// Node.register at MaxInbound + 2 x MaxOutbound = 48 — maxConnections, the C
// of the arithmetic below, not MaxInbound+MaxOutbound, because the gate is
// inbound-only — and is itself under MaxPartialTransfers, so the product a
// hostile population can pin is countImpliedBound, 48 × MaxTransfersPerPeer ×
// BlockByteCapacity ≈ 1.54 GB — reached by peers that send chunk 0 and stop.
// Keying transfers per block (which honest peers need) multiplied that by
// four, so the count bounds alone stopped describing the memory behind them.
//
// MaxReassemblyBytes is therefore the bound that matters, and it is checked
// as bytes arrive rather than derived from counts. Its value sits above what
// the honest network peaks at — honestSteadyStatePeakBytes: every peer
// mid-transfer on a multi-chunk block, 40 × BlockChunkBytes = 160 MiB, and
// only once the elastic ceiling has grown past one chunk at all, since a
// single-chunk transfer never buffers — and far under the count-implied worst
// case. TestReassemblyMemoryIsBounded pins it.
//
// **That 40 is honestSteadyStateConns and not maxConnections, and the two are
// not interchangeable.** It is an expectation over the *honest* connection set
// at the configured defaults (MaxInbound + MaxOutbound = 32 + 8); C = 48 is
// the worst-case interleaving an adversary can arrange, and using it here
// would overstate an honest steady state — the opposite error, and a harder
// one to spot because it would look like consistency. The two quantities used
// to be spelled as the same bare numeral with nothing distinguishing them,
// which is why they now have two names. magnitudes.go carries both, and
// magnitudes_internal_test.go asserts the relations this paragraph and the
// ones below argue from rather than the figures they quote.
//
// **It bounds buffered bytes, and buffered is not the same as live.** Read as
// this node's whole reassembly footprint it is wrong, and a future re-sizing
// done against it alone would be done against the wrong figure. Two
// classes of byte sit outside it, both at the completion boundary:
// dropTransfer repays cap(p.buf) before the lock is released and `body` keeps
// that buffer alive for the whole of OnBlock, and a single-chunk transfer
// (c.Total == 1) never enters the counter at all. So the live figure is
// liveReassemblyBound,
//
//	MaxReassemblyBytes + C x BlockByteCapacity
//
// where C is the connection set: serve is one goroutine per connection and it
// runs Handle to completion before reading the next frame, so a connection
// contributes at most one body. C is maxConnections, bounded by Node.register
// — inbound admitted only below MaxInbound+MaxOutbound, outbound bounded
// separately by topUp — at MaxInbound + 2 x MaxOutbound. At the committed
// parameters that is 48 x 8,000,000 = 384 MB beside a 256 MiB budget, so the
// uncounted half is the larger one, and the live total is 652,435,456 B ~
// 622 MiB.
//
// That 8,000,000 is BlockByteCapacity, the era ceiling, and so is the bound
// over the whole curve rather than today's reachable figure. At the genesis
// ceiling BlockByteLimit is 2,500,000, below BlockChunkBytes, so every block
// is single-chunk: the reachable per-connection body is BlockChunkBytes and
// the uncounted term is 48 x 4 MiB = 192 MiB. The multi-chunk half of it is
// currently zero, which is why repaying the charge after OnBlock returns
// would repair the term that does not yet exist and leave the one that does
// — a budget repaid before the bytes are released is not the bound across its
// own handoff.
//
// The second term is what an era boundary re-pins, twice over: it carries
// BlockByteCapacity directly, and BlockChunkBytes decides which transfers are
// single-chunk and therefore never counted at all.
//
// The bound holds only because C is bounded. It was not, until the inbound
// gate stopped comparing and inserting in two critical sections: the
// inbound gate compared and inserted in two different critical sections, so
// an arrival burst chose C rather than the operator, and this term had no
// bound in it. Nothing here rests on a peer-supplied value otherwise —
// c.Total is bounded by MaxBlockChunks, len(c.Data) by BlockChunkBytes in
// UnmarshalBlockChunk, and len(p.buf) by the BlockByteCapacity re-check after
// every write.
const (
	MaxPartialTransfers = 64
	MaxTransfersPerPeer = 4
	MaxReassemblyBytes  = 256 << 20
)

// OnBlockChunk is the wire entry for a delivered block chunk. A single-chunk
// transfer — which a block at the genesis ceiling is, and which blocks stop
// being as the elastic ceiling grows past BlockChunkBytes — goes straight to
// OnBlock; a multi-chunk transfer reassembles and requests its successor, so
// the conversation stays one reply per message and the serve loop stays
// untouched.
//
// Transfers are tracked per (peer, block id): a peer may have several in
// flight, because this node fires a `get-block` for every announcement it
// accepts and nothing bounds how many a peer may send.
func (e *Engine) OnBlockChunk(peerAddr string, raw []byte) Verdict {
	return e.OnBlockChunkFrom(peerAddr, peerAddr, raw)
}

// OnBlockChunkFrom reassembles a chunked block body and hands it to OnBlockFrom,
// charging the reassembled body's key epoch to payer. It carries payer for the
// same reason OnBlockFrom does: the body it produces reaches the same
// proof-of-work key-epoch gate, and the gossip path is the one that holds the
// authenticated identity to charge it to (HandleFrom).
func (e *Engine) OnBlockChunkFrom(peerAddr, payer string, raw []byte) Verdict {
	c, err := UnmarshalBlockChunk(raw)
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	if c.Total == 1 {
		e.mu.Lock()
		e.dropTransfer(peerAddr, c.ID)
		e.mu.Unlock()
		return e.OnBlockFrom(peerAddr, payer, c.Data)
	}

	e.mu.Lock()
	byID := e.partial[peerAddr]
	p := byID[c.ID]
	if c.Chunk == 0 {
		// A chunk 0 restarts the transfer under its id (wire.md §5.1), and a
		// restart is a *replacement*: the buffer it discards has to be
		// released like any other removal, or its bytes stay charged to
		// partialBytes with nothing holding them. The budget is repaid only
		// where a transfer leaves the map — dropTransfer — and this branch
		// made one leave without going there. forgetPeer cannot repair that
		// afterwards, because it can only repay a buffer that still exists,
		// so without this call one connection repeating chunk 0 retires the
		// global budget permanently, unscored and invisible, and honest peers
		// are refused after it leaves.
		if p != nil {
			e.dropTransfer(peerAddr, c.ID)
			// The re-read is load-bearing: dropTransfer takes the peer's map
			// with it once it empties, and writing the new transfer into an
			// orphaned map would charge its bytes to a buffer forgetPeer can
			// never reach — the same leak one level up. Clearing p is only a
			// belt, so the eviction loop's p == nil guard stays honest if the
			// per-peer bound ever changes; today the drop leaves len(byID)
			// below it, so that loop cannot run either way.
			byID, p = e.partial[peerAddr], nil
		}
		if byID == nil {
			if len(e.partial) >= MaxPartialTransfers {
				e.mu.Unlock()
				return Verdict{Cost: CostBudgeted, Err: errors.New("p2p: partial-transfer table is full")}
			}
			byID = map[types.Hash]*partialBlock{}
			e.partial[peerAddr] = byID
		}
		// Past the per-peer bound the oldest transfer goes, not the peer: a
		// burst of announcements is honest behaviour, and evicting a transfer
		// costs a refetch while scoring would cost a peer we depend on.
		for len(byID) >= MaxTransfersPerPeer && p == nil {
			var oldest types.Hash
			first := true
			for id, t := range byID {
				if first || t.started < byID[oldest].started {
					oldest, first = id, false
				}
			}
			e.dropTransfer(peerAddr, oldest)
			if byID = e.partial[peerAddr]; byID == nil {
				byID = map[types.Hash]*partialBlock{}
				e.partial[peerAddr] = byID
			}
		}
		// The claimed total is not an allocation: the buffer grows only as
		// chunks actually arrive, so lying about Total costs the liar the
		// bytes, not this node the memory.
		e.transferSeq++
		p = &partialBlock{id: c.ID, total: c.Total, started: e.transferSeq}
		byID[c.ID] = p
	} else if p == nil || p.total != c.Total || p.next != c.Chunk {
		// A chunk continuing nothing this node is holding. Drop that transfer
		// and say so, but **do not score**: this node evicts transfers of its
		// own accord (above, and on disconnect), so the branch fires for
		// benign reasons as readily as hostile ones, and a check that can
		// fire benignly is noise with authority. The sender pays the
		// bandwidth; that is the whole cost, and it is the same discipline
		// §2 of the whitepaper applies to a mutilated exemplar.
		if p != nil {
			e.dropTransfer(peerAddr, c.ID)
		}
		e.mu.Unlock()
		return Verdict{Cost: CostBudgeted, Err: ErrNoSuchTransfer}
	}
	// The global byte budget, checked before the append rather than after, so
	// that the bytes a refusal rejects are never held even briefly. Refusing
	// and not evicting: eviction here would let one peer flush another's
	// transfers, and this node's own saturation is not the sender's fault, so
	// it does not score either.
	if e.partialBytes+len(c.Data) > MaxReassemblyBytes {
		e.dropTransfer(peerAddr, c.ID)
		e.mu.Unlock()
		return Verdict{Cost: CostBudgeted, Err: errors.New("p2p: reassembly byte budget is full")}
	}
	// The sole write to a partialBlock's buf in this package, which is what
	// makes cap == len a total invariant for a reassembly buffer rather than a
	// property each site has to maintain. Every claim the byte accounting
	// makes rests on that; a second write site would end it.
	owned := cap(p.buf)
	p.buf = growTransfer(p.buf, c.Data)
	p.next++
	// Charged as the capacity the buffer gained, not as the length the chunk
	// carried, so that the counter reads this node's memory and not the
	// sender's claim. The two are equal because growTransfer sizes
	// every write exactly, which is also what lets the budget check above —
	// necessarily made before the allocation — stay exact. Writing it from
	// cap() is a belt over that invariant and not an enforcement of it:
	// len(c.Data) here would compile and pass, so what the tests pin is the
	// invariant, not the expression.
	e.partialBytes += cap(p.buf) - owned
	if limit := e.Chain.Params().BlockByteCapacity; len(p.buf) > limit {
		e.dropTransfer(peerAddr, c.ID)
		e.mu.Unlock()
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: errors.New("p2p: chunked block exceeds the consensus byte capacity")}
	}
	if p.next < p.total {
		e.mu.Unlock()
		return Verdict{Cost: CostBudgeted, Reply: &Outbound{Kind: KindGetBlock,
			Payload: GetBlock{ID: c.ID, Chunk: p.next}.MarshalGetBlock()}}
	}
	e.dropTransfer(peerAddr, c.ID)
	body := p.buf
	e.mu.Unlock()
	v := e.OnBlockFrom(peerAddr, payer, body)
	// **Only past Forward, and that ordering is the security half of the
	// forward-as-announcement rule rather than tidiness.** reframeAcceptedBody
	// decodes the body and marshals an announcement, so a sender that could
	// reach it on a refused body would buy a decode and a marshal of up to four
	// mebibytes for the price of sending them — the asymmetric-cost shape
	// refused on the announce path, one primitive over. Past Forward the block
	// has met the work check, the citation checks and the fold, so the sender
	// paid a block's work for it, and the extra decode is a rounding error
	// beside what it already cost this node to accept it.
	if v.Forward {
		if out, ok := reframeAcceptedBody(c.ID, body, e.Chain.Params()); ok {
			v.ForwardAs = out
		} else {
			// **Discard rather than fall back to the frame that arrived**, and
			// that choice is the whole point: the arriving frame is the last chunk,
			// so a fallback would reopen the defect silently on the one path
			// nobody is watching. relayReleased logs and drops for the same
			// input; the two callers of releaseRelay now agree about its
			// failure as well as about its answer.
			v.Forward = false
		}
	}
	return v
}

// reframeAcceptedBody is what a node floods after accepting a body it
// reassembled, when re-sending the frame that arrived would name a transfer
// nobody opened. Nil means the arriving frame is the right thing to flood.
//
// **The whole of the multi-chunk propagation fix is here, and it is Option A
// applied to the second half of the same path.** A node that has just completed
// a transfer *holds the body*, which is precisely the condition wire.md §8
// requires of a forwarder — so what it owes its peers at that moment is an
// announcement. The last chunk of a transfer is not: a peer that never opened
// one refuses it as continuing no transfer, unscored and silently, so the block
// stops at the first hop.
//
// **Flooding chunk 0 instead was weighed and rejected**, and the reason is the
// rule this unit exists to establish: chunk 0 makes the receiver open a
// transfer and start pulling, which is re-propagation *before* anybody has
// vouched for the body — the exact property Option A removes from the announce
// path. It would also make a node re-send bytes that did not arrive on the
// frame it is answering, and need a rule about who serves the remainder.
//
// It is separated from OnBlockChunk for the reason releaseRelay is separated
// from relayReleased, and it delegates to releaseRelay rather than repeating
// it: the framing rule now has two callers — a matured withheld block and an
// ordinary accepted one — and two copies of it could disagree about which
// bodies travel as announcements. One function cannot.
func reframeAcceptedBody(id types.Hash, body []byte, p *params.Params) (*Outbound, bool) {
	if ChunkCount(len(body)) == 1 {
		// The frame that arrived IS the whole body, so flooding it is both
		// correct and free. This is every block at every committed genesis
		// parameter set (block_byte_limit_genesis 2,500,000 against a
		// BlockChunkBytes of 4,194,304), which is why the multi-chunk stall is
		// unreachable at launch and reachable as the elastic byte ceiling grows toward
		// block_byte_capacity.
		//
		// **Unreachable from OnBlockChunk, and kept anyway because it is the
		// function's contract rather than a defence.** That caller
		// short-circuits at `Total == 1` before any transfer is opened, and
		// UnmarshalBlockChunk requires every non-final chunk to be exactly
		// BlockChunkBytes, so a body that completed a transfer is over one
		// chunk by construction. Deleting the row would make the answer for a
		// one-chunk body depend on which caller asked.
		return nil, true
	}
	kind, payload, err := releaseRelay(Released{ID: id, Raw: body}, p)
	if err != nil {
		// The caller only asks past OnBlock's accept, so the body decoded and
		// releaseRelay's only error cannot fire — but "cannot" is not a thing
		// to flood on. false means DISCARD, never fall back: the frame that
		// arrived is the last chunk, so a fallback reopens the propagation stall in
		// silence.
		return nil, false
	}
	return &Outbound{Kind: kind, Payload: payload}, true
}

// forwardFrame is what the serve loop floods for one judged message: the frame
// that arrived, unless the verdict named a replacement.
//
// Separated from the sending so that both of its branches can be tested, which
// is the same reason releaseRelay is separated from relayReleased — and the
// same reason it matters here, because the replacement branch is reached only
// by a body larger than one chunk.
func forwardFrame(v Verdict, kind MessageKind, payload []byte) (MessageKind, []byte) {
	if v.ForwardAs != nil {
		return v.ForwardAs.Kind, v.ForwardAs.Payload
	}
	return kind, payload
}

// dropTransfer removes one transfer, releases its owned capacity from the
// budget, and drops the peer's entry with it if that was the last. It is the
// *only* way a transfer is removed, so that the byte accounting cannot drift
// from the map: every other path calls here. The caller holds e.mu.
func (e *Engine) dropTransfer(peerAddr string, id types.Hash) {
	byID := e.partial[peerAddr]
	if byID == nil {
		return
	}
	if p := byID[id]; p != nil {
		e.partialBytes -= cap(p.buf)
		delete(byID, id)
	}
	if len(byID) == 0 {
		delete(e.partial, peerAddr)
	}
}

// dropPeerTransfers releases everything a peer holds. It goes through
// dropTransfer per id rather than subtracting the bytes itself, so that
// dropTransfer's claim to be the single repayment site is literally true and
// not merely nearly true: a second site that repays the budget its own way is
// somewhere the next "a replacement is not a removal" defect can hide, which is
// exactly how the chunk-0 budget leak survived review here. Deleting from the
// map being ranged over is defined behaviour, and dropTransfer removes the
// peer's entry once it empties; the delete below is the belt for a peer whose
// map was already empty. The caller holds e.mu.
func (e *Engine) dropPeerTransfers(peerAddr string) {
	for id := range e.partial[peerAddr] {
		e.dropTransfer(peerAddr, id)
	}
	delete(e.partial, peerAddr)
}

// OnBlock applies a delivered block body. It charges the key epoch its work
// check demands to peerAddr, which is the right payer for a body that arrived
// with no authenticated identity — an exported call, a withheld-block replay,
// or a test. The gossip path has the identity and threads it through
// OnBlockFrom, exactly as OnBlockAnnounce wraps OnBlockAnnounceFrom.
func (e *Engine) OnBlock(peerAddr string, raw []byte) Verdict {
	return e.OnBlockFrom(peerAddr, peerAddr, raw)
}

// OnBlockFrom applies a delivered block body, charging the proof-of-work key
// epoch the body's carrier header demands to payer.
//
// payer is what that key epoch is charged to; see replyBudgetKey, which
// produces it, and spendKeyEpoch, which spends it — the same second parameter,
// for the same reason, that OnBlockAnnounceFrom carries. HandleFrom holds both
// the connection address and the key that authenticated it; the engine has no
// map from one to the other, and a budget keyed on the mintable half of that
// pair is one the sender re-buys per handshake.
func (e *Engine) OnBlockFrom(peerAddr, payer string, raw []byte) Verdict {
	// A cheap look at the header alone, before the full body decode and the
	// proof-of-work checks it costs — 1 + len(Cites) hashes, below. Bodies
	// arrive more than once in the ordinary course of gossip: OnBlock's own
	// success case forwards the raw KindBlock payload to every other peer
	// (node.go's serve loop broadcasts whatever a Verdict marks Forward), so a
	// well-connected mesh delivers the same body to a node from more than one
	// upstream. A block whose id is in seenBlocks *and* no longer pending has
	// already been fully vetted by an earlier delivery — pending is cleared
	// right where that vetting happens, a few lines down — so a repeat has
	// nothing left to teach this node.
	//
	// seenBlocks alone is not the right test: OnBlockAnnounce sets it at
	// announce time, before the body has even been requested, so the *first*
	// legitimate delivery of an announced block also finds it true. Requiring
	// pending to be gone as well is what tells "already delivered" apart from
	// "just announced, body in flight" — the header is blockLayout's
	// fixed-size first field, so this costs one small decode rather than the
	// certificate and citation lists behind it.
	//
	// **What this gate knowingly costs, and why that is accepted.** An upstream
	// that loses both the announce race and the body race for the same block
	// returns here, ahead of the recordAnnounce call below, so it is never
	// refreshed as a sync candidate until it happens to win an announce race.
	// That gap is real and it is not an oversight: it was ratified as accepted
	// for era-0. Adding a body-side seenBlocks entry to narrow it was built and
	// measured — it heals candidate breadth one block at a time rather than at
	// once — but marking a delivered block seen can dedupe the re-delivery an
	// orphan depends on, and losing a block to save a candidate inverts the
	// priority the future-dated drop and the key-epoch refusal both already
	// set. The gap is liveness-only and self-healing (node/sync polls
	// regardless), so the zero-code option wins.
	//
	// Do not re-derive the fix here without both reopen measurements: a
	// real-mesh showing candidacy starvation that node/sync polling does not
	// already cover, and one showing the body-side entry leaves the orphan
	// re-delivery path intact. Until then seenBlocks keeps exactly one writer,
	// the announce-accept path in OnBlockAnnounceFrom above.
	if len(raw) >= types.HeaderSize {
		if hdr, err := types.UnmarshalHeader(raw[:types.HeaderSize]); err == nil {
			id := hdr.ID()
			e.mu.Lock()
			_, seen := e.seenBlocks[id]
			_, waiting := e.pending[id]
			e.mu.Unlock()
			if seen && !waiting {
				return Verdict{Cost: CostDeduped, Err: ErrNotUseful}
			}
		}
	}

	blk, err := types.UnmarshalBlock(raw, e.Chain.Params())
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	id := blk.Header.ID()

	// The body arrived, so the announcement is answered — and that is decided
	// here, before any judgement of the block, not after.
	//
	// It used to sit below the checks that follow, which meant every early
	// return past this point left the entry standing: a peer that announced a
	// block and then delivered a body refused for *any* reason — a genesis
	// height, a failed work check, a genesis-height citation, or a timestamp
	// that put it in the withhold queue — paid ScoreInvalidMessage at delivery
	// and ScoreUnservedBody again sixty seconds later, on both tallies, for a
	// body it did serve. wire.md §9 rule 5 charges an announcer *once*, and
	// only for not serving; whether what it served was any good is a separate
	// question already priced by a separate verdict. The withhold case made
	// that reachable without an invalid block at all, since Engine.now reads a
	// wall clock through .Unix() and an NTP step backwards can put a body past
	// a limit the announcement was inside of.
	//
	// Keyed on the id decoded from the bytes rather than on anything the sender
	// claimed, so a peer that answers `get-block(X)` with some other real block
	// Y clears Y's entry, if any, and leaves X's standing to be reaped — which
	// is wire.md §9 rule 4's distinction between lying and not serving, arrived
	// at for free.
	e.mu.Lock()
	delete(e.pending, id)
	e.mu.Unlock()

	// Genesis is never delivered, for the same reason OnBlockAnnounce never
	// lets one through: height 0 is the one height at which `pow.CheckWork`
	// costs a sender nothing — it returns nil immediately, before the target
	// is even read, because genesis carries no work. That makes a
	// genesis-height body a free ticket past the check below and into
	// everything downstream of it, including the orphan pool further down,
	// whose plausibility ceiling only bounds a *declared* target and never
	// asks whether it was earned. Every node already holds genesis from its
	// own params, so a genesis-height body can never be useful, and the only
	// party with a reason to send one is a party looking for a free path.
	// It began as a rule of its own — a genesis-height body and its citations
	// passed the work check for free — and was folded into this handler's rework.
	if blk.Header.Height == 0 {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage,
			Err: errors.New("p2p: genesis is never delivered")}
	}

	// The work, before anything else is done with this block.
	//
	// This check was absent, and its absence was the whole of proof of work on
	// the only path gossip uses. `pow.CheckWork` had two call sites — the
	// *announcement* handler and `node/sync` — and neither is on the road a
	// block body actually travels: `Node.serve` dispatches whatever arrives, so
	// a `KindBlock` needs no announcement, no handshake and no prior
	// relationship. `Chain.Apply` does not check work either, and neither does
	// `fold.CheckBlockRules`; the fold judges a block's *contents*, and nothing
	// judged its cost.
	//
	// One message was enough. Accumulated work is computed from the target a
	// header *declares*, so a block declaring `Target = 1` claims 2^255 — more
	// than any honest chain will ever reach — and after it lands no honest
	// branch can outweigh the tip again. The node was permanently forked, paid
	// the sender's emission address, and relayed the message onward with a
	// `ScoreUsefulMessage` for its trouble.
	//
	// The price of the key epoch that work check is about to demand,
	// charged *before* the check because the check is what spends the epoch and
	// afterwards is a bill for CPU already burnt. This is the announce path's
	// spendKeyEpoch gate (OnBlockAnnounceFrom, engine.go:951) hoisted onto the
	// body path, which was measured to be outside both the per-identity
	// budget and the node-wide ceiling: a single unprivileged host sending
	// unsolicited KindBlock bodies at ascending foreign epochs forced one
	// ~0.55 s / 256 MiB cache initialisation each, free (the carrier declares a
	// target no digest can exceed, so the sender spends no work) and unbounded
	// across minted identities (per-identity ScoreInvalidMessage alone does not
	// bound a total, as engine.go's own comment near line 1494 says). A KindBlock
	// "needs no announcement", so this path never passed spendKeyEpoch, and
	// unsolicited bodies are normal — OnBlock's success case floods the body to
	// every peer — so requiring solicitation is not an available fix.
	//
	// workingKeyEpoch exempts {tipEpoch, tipEpoch+1}, so a node syncing at the
	// tip — which receives bodies in its own working epochs routinely — is never
	// charged; only bodies whose declared height names an epoch this node is not
	// working in reach the budget, and those do not arrive on the honest gossip
	// path (deep catch-up runs through node/sync, not OnBlock). The refusal split
	// is spendKeyEpoch's and identical to the announce path's refuseUnbudgeted:
	// a refusal by the shared ceiling is never scored — it can be caused by
	// traffic this payer never sent — a refusal by the payer's own budget is
	// scored only once its blocks have already been refused by the work check
	// (the conjunct that terminates a minted-identity flood), and a
	// first-time own-budget refusal is priced but not scored.
	if epoch, ok, own := e.spendKeyEpoch(payer, blk.Header.Height); !ok {
		// The ceiling arm carries the announce path's second-question
		// refinement too, and it is the same three lines because it is the same
		// defect: `own` is false for every payer while the ceiling is down, so
		// the work-refused conjunct below would be inert for a caught identity
		// whose own budget is long spent. ownKeyEpochsExhausted is the
		// non-mutating read that keeps it live; it charges nothing, so a payer
		// with an intact budget is still never scored for a ceiling somebody
		// else drained.
		if !own {
			if e.ownKeyEpochsExhausted(payer) && e.workRefused(payer) {
				return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
					"%w: key epoch %d is outside the epochs this node is working in, this "+
						"identity has already spent its own budget of %d, and its blocks "+
						"have already been refused by the work check",
					ErrKeyEpochBudget, epoch, MaxUnheldKeyEpochsPerPeer)}
			}
			ceiling, _ := unheldKeyEpochCeiling(e.connSetLocked())
			return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
				"%w: key epoch %d is outside the epochs this node is working in, and "+
					"this node has spent its whole ceiling of %d on epochs it does "+
					"not hold",
				ErrKeyEpochBudget, epoch, ceiling)}
		}
		if e.workRefused(payer) {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
				"%w: key epoch %d is outside the epochs this node is working in, this "+
					"identity has spent its budget of %d, and its blocks have already "+
					"been refused by the work check",
				ErrKeyEpochBudget, epoch, MaxUnheldKeyEpochsPerPeer)}
		}
		return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
			"%w: key epoch %d is outside the epochs this node is working in, and "+
				"this identity has spent its budget of %d",
			ErrKeyEpochBudget, epoch, MaxUnheldKeyEpochsPerPeer)}
	}
	if err := e.work.Check(e.Engine, blk.Header, e.Chain.Params()); err != nil {
		// Remembered against the identity, not only charged to it, exactly as the
		// announce path does after its own work.Check: the score decays and is
		// clamped, so it cannot answer "has this sender ever been caught", and the
		// budget refusal above needs that answer and nothing else records it. An
		// honest peer cannot set this bit — a real block meets the target its own
		// header declares — so only a sender whose body failed the work check
		// keeps it, and its next over-budget body is scored rather than sheltered.
		if e.Peers != nil {
			e.Peers.MarkWorkRefusedKey(payer, e.now())
		}
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}

	// Structure before cost. Every one of these refusals is a rule the
	// fold already applies unconditionally to the same list, hoisted in front
	// of the work loop below so that a citation must be *structurally* capable
	// of being a competitor before this node will pay a memory-hard hash to
	// find out whether it was mined.
	//
	// The hoist is the whole fix, and the reason it is needed is that a key is
	// derived from a header's height (`pow.KeyFor`), not from any block this
	// node holds. A citation at an arbitrary height therefore names an
	// arbitrary RandomX key epoch, and a distinct epoch is a cache
	// initialisation rather than a hash — about 0.54 s against 15–25 ms, from
	// core/pow/randomx's BenchmarkInitCache and BenchmarkVerify. (The original
	// analysis said the wall-clock consequence was a model rather than a
	// measurement, and it was right: this comment carried ~1.7 s against ~55
	// ms, attributed to what core/pow/randomx publishes, and that package
	// publishes neither. The amplification factor was always the counted fact;
	// the seconds are now taken from the benchmarks.) Nothing downstream
	// charged for it: no rule on this path bounds a *declared* target, so a
	// sender declaring `2^256-1` spends zero hashes; `verify.WorkWasChecked` is
	// keyed on the header id, so one byte of nonce defeats it; and the verdict
	// a far-from-tip block finally earns is `ErrOrphanOutOfWindow`, which
	// scores 0 deliberately so that catch-up does not ban honest peers. One
	// ~1.2 KB message bought 1 + MaxCitesPerBlock = 5 attacker-chosen key
	// epochs, unscored and repeatable. After the hoist every surviving citation
	// sits at `Height-1` and so shares the carrier's own epoch — the one this
	// node must hold a cache for anyway — so the factor is 1. It is not 0: the
	// carrier's own header is still hashed at a height and a declared target
	// its sender chose, which is a separate residual and not this change.
	//
	// It refuses on two fields of the same message and never consults this
	// node's tip, so it cannot refuse a block for being far from the tip and
	// cannot break a node catching up. That is the wrong answer docs/adversarial/I7
	// already eliminated, and this is not it.
	//
	// Not a consensus change, and only permissible because it is not
	// (spec/wire.md §9 rule 7: the fold's citation checks are exhaustive, and
	// adding one is as much a consensus change as removing one). These are not
	// additions: `core/fold`'s `checkCites` permits no citations at all below
	// height 2, and above it requires a citation's version to be
	// `types.HeaderVersion` and its height to be exactly `h.Height-1`. A block
	// failing any of them is already unconditionally invalid on every path that
	// applies a block; this rejects it earlier, and scores the sender for it.
	//
	// The height-0 refusal that used to stand alone here is subsumed rather
	// than dropped: a genesis-height citation fails the height rule whenever
	// the carrier is at height 2 or above, and the may-not-cite rule below
	// that. It was never a special case — it was the only instance of this rule
	// anybody had needed yet.
	//
	// Duplicated deliberately into node/sync/sync.go rather than shared: the two
	// call sites return different types and only one of them has a salvage step,
	// and the height-0 rule this replaces was duplicated the same way. Whoever
	// edits this rule must edit that copy too — a policy with two homes drifts
	// toward whichever one nobody measures, so the height rule is measured on
	// both paths. The may-not-cite rule is measured on this path only; sync.go
	// states why its copy is there for parity rather than for price.
	if len(blk.Cites) != 0 && blk.Header.Height <= 1 {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage,
			Err: fmt.Errorf("p2p: a block at height %d may not cite", blk.Header.Height)}
	}
	for _, cited := range blk.Cites {
		if cited.Version != types.HeaderVersion {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage,
				Err: fmt.Errorf("p2p: a block cites a header of unknown version %d", cited.Version)}
		}
		if cited.Height != blk.Header.Height-1 {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage,
				Err: fmt.Errorf("p2p: a block at height %d cites a header at height %d",
					blk.Header.Height, cited.Height)}
		}
	}

	// And only then the work, for every header this block cites (whitepaper
	// §8.1's health signal). core/fold checks a citation's height, parentage and
	// declared target from state (fold/blockrules.go's checkCites) — everything a
	// citation's *bytes* can prove — but not that the work was real: not
	// because it could not import the engine, but because running a
	// memory-hard work function up to MaxCitesPerBlock times per block is
	// exactly the cost whitepaper §3 keeps out of the sequential stage.
	//
	// **This check is consensus, not policy.** cited_count feeds the health
	// gate, which gates whether the sequential target T may grow, so a node
	// that skipped it would count citations backed by no work and derive a
	// different T from its peers — a chain split, arrived at one epoch later
	// than a skipped block-level work check would produce one. It is
	// specified normatively in spec/wire.md §9 rule 7.
	//
	// A second pass rather than a branch inside the first: no work is paid for
	// until the whole list is known to be structurally sound, so a list whose
	// last entry is the forged one costs nothing for the entries before it.
	for _, cited := range blk.Cites {
		if err := e.work.Check(e.Engine, *cited, e.Chain.Params()); err != nil {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf("p2p: cited header fails proof of work: %w", err)}
		}
	}

	// The future-time limit, after the work checks and before anything else.
	//
	// After the work, so that a block whose proof of work does not even meet its
	// own declared target is refused as invalid rather than queued as early —
	// the cheapest check that can refuse it should be the one that does.
	//
	// **That is a filter, not a price, and the difference matters here.**
	// `pow.CheckWork` above tests the digest against the target the header
	// *declares*, and nothing on this path bounds a declared target: `MaxTarget`
	// is applied inside `pow.NextTarget`, and the `NextTarget` equality check is
	// further down, on the tip-extension branch — i.e. *after* this gate. A
	// header declaring `max_target` costs about 64 expected hashes (spec/
	// params.json's own note on `max_target`: floor(2^256 / (2^250 + 1)) = 63),
	// so filling all 64 slots of the queue costs a few thousand hashes, not
	// proof of work. This comment used to claim "the sender should have paid for
	// it in hashes"; it is untrue at this call site, and a later reader would
	// have trusted it. What keeps the queue safe is that it is *bounded* — 64
	// blocks, 8 MiB, a one-hour horizon — the same footing the orphan pool sits
	// on, and R4-H1 rather than a pricing argument.
	//
	// Before the pending map, the tip comparison and the orphan pool, because a
	// block this node cannot yet judge must not be judged — not as a tip
	// extension, not as a branch, and not as an orphan.
	//
	// This is the call site `pow.IsTooFarAhead` was written for and never had.
	// It closes the median-ratchet freeze's *downward* collapse: the
	// median-time-past can no longer be pushed arbitrarily forward, so the
	// honest solve times the LWMA reads can no longer be driven to the lower
	// clamp by a timestamp alone. It does **not** close the upward direction —
	// a miner dating at exactly `now + FTL - 1` is still never withheld and
	// never scored here — but that direction is closed, in the difficulty rule
	// rather than at this gate: `pow.NextTarget`'s accumulator was made signed
	// and clamped symmetrically, so the donation a forward-dated block makes is
	// cancelled by the charge on the interval after it. The `max(0, delta)`
	// clip an earlier revision of this comment blamed is not in the shipped
	// rule, and the `goal/FTL` threshold it quoted (16.7 % on mainnet, 2.8 % on
	// devnet) is that retired rule's, not this one's. Driven over 600 blocks at
	// attacker shares of 10 %, 16 %, 17 %, 25 % and 50 % on mainnet, all of
	// them dating every block they win at `now + FTL - 1`, the peak target is
	// about 1.13x `GenesisTarget` against a `MaxTarget` 4096x above it, and
	// none reaches the ceiling. `sim/timestamp_test.go` measures both
	// directions; the back-dating equilibrium is closed.
	if e.tooFarAhead(blk.Header) {
		if err := e.withhold(peerAddr, blk, raw); err != nil {
			return Verdict{Cost: CostFree, Score: ScoreFutureBlock, Err: err}
		}
		return Verdict{Cost: CostFree, Score: ScoreFutureBlock, Err: fmt.Errorf("%w: dated %d",
			ErrBlockWithheld, blk.Header.Time)}
	}

	// A delivered body refreshes the sender's sync candidacy, exactly as an
	// announcement does — and this is the one signal the body path never had.
	//
	// `PeerTip.OffersUnknown` is the only candidacy signal that is not frozen at
	// the handshake, and until this line it was written from exactly two places:
	// `recordTip` (the handshake) and `recordAnnounce` (the announce path,
	// including `onFutureAnnouncement`'s copy). **Delivering a block was not one
	// of them.** So a peer that hands this node a block it cannot place — the
	// strongest evidence of being ahead that a peer can give — bought no
	// candidacy from it at all, and its `Height` stayed at whatever its Hello
	// said, which `recordAnnounce`'s own comment describes as a number that
	// "stopped being true one block after the peer connected".
	//
	// **That is reachable today, and not only in theory.** `OnBlockAnnounceFrom`
	// dedupes on `seenBlocks` and returns *ahead* of its `recordAnnounce` call,
	// so in a mesh where two upstreams hold the same block only the first
	// announcement to arrive refreshes anybody. The second upstream then
	// delivers the body — measured, a node fifteen blocks behind with two
	// upstreams at height 20, both feeding it, had exactly one of them as a sync
	// candidate and the other frozen at its handshake height of 0. Fed only by
	// the peer it does not count, that node has nobody to ask.
	//
	// **Better evidence than the announce path's, not weaker.** By this line the
	// block has passed `work.Check` on its own header, the citation structure
	// rules, `work.Check` on every cited header, and the future-time limit. The
	// announce path records on a header that has passed the first of those and
	// nothing else. What is recorded is still only "this peer showed us a header
	// we cannot place" — the declared target is no more re-derived here than
	// there for a block off the tip — and it still decides only who is worth
	// asking, never what to believe.
	//
	// **Placed here, and the position is three separate constraints.** After
	// `tooFarAhead`, because a withheld block is judged by nothing yet and
	// `ReleaseWithheld` runs it through this same function when its clock
	// arrives — so the refresh happens once, on release, which is the discipline
	// `onFutureAnnouncement` already states for the announce path. Before the
	// tip-extension branch, because `recordAnnounce` sets `OffersUnknown` only
	// while the block is *not* canonical, and `Chain.Apply` a few lines down
	// makes it canonical — recording after would silently reduce this to a
	// height update and lose the whole signal for the node that applies what it
	// is fed. And before `holdOrphan`, because the node this repairs is by
	// definition one whose parent is missing: its bodies are orphans or refused
	// out of window, and every path below returns without reaching here.
	//
	// **Deliberately behind the dedup gate at the top of this function, which is
	// therefore NOT repaired by this change.** A repeat body returns
	// `CostDeduped` before the decode, and moving the refresh in front of it
	// would put three chain reads and a header hash on a path whose rate an
	// unprivileged peer sets by replaying bytes it has already sent — the
	// asymmetric-cost shape that rejected a memoisable check on the announce
	// path. Behind the gate the cost is bounded by what already stands in front
	// of it: a RandomX evaluation dominates three chain reads by orders of
	// magnitude, so this adds nothing to the ratio a sender controls. The
	// residual — the second upstream whose body arrives *after* the first, and
	// whose announcement was deduped — is left open and recorded.
	//
	// **What it does NOT widen, because the obvious objection is that it makes
	// every peer that feeds this node a permanent sync candidate.** It does —
	// `recordAnnounce` runs while the block is still missing, so `OffersUnknown`
	// is set even for a body this node then applies, measured directly. And the
	// announce path has done exactly that for every block since `OffersUnknown`
	// existed: the steady-state measurement is 40 announcements, all naming the
	// receiver's own tip as parent, every one of them recorded. So in any mesh
	// where announcements flow — every mesh at this revision — the candidate set
	// this produces is one the announce path had already produced, and the only
	// peers it adds are the ones the announce path *missed*. Candidacy decides
	// who is asked and never what is believed; `SyncCandidates`' own comment is
	// why that is affordable, and every header a sync answer carries is
	// re-derived from the difficulty rule before a body is fetched.
	//
	// Guarded on a non-empty address because `recordAnnounce` creates the entry
	// it updates. `Handle` gates every kind but hello on a completed handshake,
	// so a peer reaching here always has a tip entry already and `forgetPeer`
	// reaps it on disconnect; the guard exists so that the one caller that does
	// not go through `Handle` — `ReleaseWithheld`, whose `w.peer` it already
	// checks for emptiness itself — cannot mint an entry under the empty key,
	// which `syncKey` would hand to the rotation as a shared, undialable key.
	if peerAddr != "" {
		e.recordAnnounce(peerAddr, blk.Header)
	}

	// Extending the tip is the common case and needs no fork choice.
	if blk.Header.ParentID == e.Chain.Tip().ID() {
		// And the target it declared must be the one the rule produces.
		//
		// The check above only asks whether the hash meets the target the header
		// chose for itself, and a header may choose anything. That is R4-H1 —
		// declare a trivial target, solve it in a handful of hashes, and claim
		// whatever work you like — and it is the attack headers-first sync was
		// built to remove. It was removed there and nowhere else, so it walked
		// in here.
		//
		// Only on this branch, because the rule is a function of the preceding
		// window and this node holds that window precisely when the parent is
		// its own tip. That is not an asymmetry in the *rule* any more: a block
		// on some other branch is held as an orphan and judged by fork choice,
		// and `chain.ConsiderBranch` now re-derives the target and the
		// median-time floor there too, against the ancestor window it has
		// already established is canonical and within the undo horizon. The
		// older "validating against a chain we do not have" objection applied to
		// orphans not yet attached to known history; by the time fork choice
		// weighs a branch, it is attached, and the window is exactly the one the
		// rule needs. So this check is a cheap early refusal on the common path,
		// not the only place the rule is enforced.
		p := e.Chain.Params()
		window := e.Chain.RecentHeaders(int(p.DifficultyWindow) + 1)
		if want := pow.NextTarget(window, p); !blk.Header.Target.Eq(want) {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf(
				"p2p: block declares target %s, the difficulty rule gives %s",
				blk.Header.Target.String(), want.String())}
		}
		// And the lower time bound, from the same window — MedianTimeBlocks is
		// 11 against a difficulty window of 90, so the median reads the tail of
		// the slice NextTarget already needed and this check is free.
		//
		// It is validity, and it was enforced on exactly one ingress path:
		// `node/sync.ValidateHeaders`. A block dated at or below the median of
		// the last 11 was therefore accepted by every node fed by gossip and
		// refused by every node fed by headers-first sync, permanently, for the
		// cost of one ordinary block — a consensus split by arrival path rather
		// than by content, which is the class this project treats as
		// unrecoverable.
		//
		// This is the tip-extension branch's copy of the rule, exactly like the
		// target check above and for the same reason: the rule needs the window
		// of preceding headers, and this node holds that window precisely when
		// the parent is its own tip. A block on some other branch goes to the
		// orphan pool and is judged by `chain.ConsiderBranch`, which re-derives
		// the median-time floor there as well — so the rule is now
		// path-independent, and this line is the early refusal rather than the
		// only enforcement.
		if err := pow.CheckMedianTime(blk.Header, window, p); err != nil {
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: fmt.Errorf("p2p: %w", err)}
		}
		_, err := e.Chain.Apply(blk)
		switch {
		case err == nil:
			e.Chain.Read(func(v chain.View) { e.Pool.OnBlock(blk, v.State, v.Height) })
			return Verdict{Cost: CostScored, Forward: true, Score: ScoreUsefulMessage}
		case errors.Is(err, chain.ErrLocal):
			// This node's storage, not the sender's block. Same reasoning as the
			// fork-choice path below.
			return Verdict{Cost: CostFree, Err: err}
		case errors.Is(err, chain.ErrWrongParent):
			// The tip moved between the check above and the write lock inside
			// Apply. That is ordinary on a live network — it is the same race the
			// miner sees as ErrStaleTemplate — and it is emphatically not the
			// sender's fault.
			//
			// It used to cost the sender ScoreInvalidMessage. Five lost races
			// would ban an honest, well-connected peer, and since R5 a ban also
			// removes a peer from sync candidacy: the node would have taught
			// itself to stop talking to whoever was fastest at telling it things.
			//
			// The block is not discarded either. It still describes a branch,
			// so it falls through to fork choice like any other.
		default:
			return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
		}
	}

	// Otherwise it belongs to some other branch. Hold it — subject to the
	// bounds that stop the pool being priced by an attacker (R4-H1) — and see
	// whether the blocks collected so far now form a branch heavy enough to
	// adopt.
	if err := e.holdOrphan(blk); err != nil {
		// Out of window is a fact about *this node's* backlog, not about the
		// sender — and this node asked for the block: OnBlockAnnounce replies
		// with GetBlock. Charging for it means a node more than HeightWindow
		// behind fines every honest peer that answers its own request, six
		// blocks from the score ceiling to a permanent ban, at exactly the
		// moment it needs those peers to climb back. Observed: a late joiner
		// 168 blocks behind reached min_score -104 and banned a peer while
		// trying to catch up.
		//
		// The pool being full is likewise this node's condition, not the
		// peer's. What remains scoreable is a block that fails the plausibility
		// ceiling, which is a claim about the block itself.
		if errors.Is(err, ErrOrphanOutOfWindow) || errors.Is(err, ErrOrphanPoolFull) {
			return Verdict{Cost: CostBudgeted, Err: err}
		}
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}

	branch, ok := e.assembleBranch(blk)
	if !ok {
		// Nothing to judge yet — the branch does not reach a block this node
		// has. That is ordinary during sync, not misbehaviour.
		return Verdict{Cost: CostFree, Err: chain.ErrUnknownAncestor}
	}

	reorg, err := e.Chain.ConsiderBranch(branch)
	if err != nil {
		// Not-better and unknown-ancestor are ordinary in a live network: a
		// peer on a different branch is not misbehaving. Beyond-horizon is a
		// node-operator event, not a peer's fault either.
		if errors.Is(err, chain.ErrNotBetter) ||
			errors.Is(err, chain.ErrUnknownAncestor) ||
			errors.Is(err, chain.ErrBeyondUndoHorizon) {
			return Verdict{Cost: CostFree, Err: err}
		}
		// A local failure is not the sender's doing. A commit that did not land
		// or a missing undo log says something about this node's disk, and
		// charging it to whoever delivered the block means a node with bad
		// hardware bans the peers still willing to serve it — then, since a ban
		// removes a peer from sync candidacy, disconnects itself from the network
		// that could have helped it, while its log names the peers.
		if errors.Is(err, chain.ErrLocal) {
			return Verdict{Cost: CostFree, Err: err}
		}
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	if reorg.Adopted {
		e.forgetBranch(branch)
		e.applyToPool(branch, reorg)
	}
	return Verdict{Cost: CostScored, Forward: reorg.Adopted, Score: ScoreUsefulMessage}
}

// applyToPool brings the mempool into line with a branch switch.
//
// Two halves, and the second was missing entirely. Certificates in the adopted
// blocks leave the pool, which is what OnBlock has always done. Certificates in
// the blocks a reorg *removed* have to go back — the pool dropped them when
// those blocks were applied, and undoing the blocks does not return them, so a
// transaction that was confirmed and then reorged out vanished from the chain
// and from every mempool at once. `Pool.Readmit` was written for this and was
// called from nowhere.
//
// Readmission is not unconditional: Add re-runs the whole admission path against
// the *new* tip, so a certificate whose deposit no longer covers, whose TTL has
// expired, or which the winning branch already includes is simply refused. That
// is the correct outcome and it is why this is a re-admission rather than an
// insertion.
//
// Order matters. Readmit first, then remove what the new branch includes:
// doing it the other way round can readmit a certificate that the adopted
// blocks contain.
func (e *Engine) applyToPool(branch chain.Branch, reorg chain.Reorg) {
	var readmit []*types.Certificate
	for _, blk := range reorg.Undone {
		readmit = append(readmit, blk.Certs...)
	}
	e.Chain.Read(func(v chain.View) {
		if len(readmit) > 0 {
			e.Pool.Readmit(readmit, v.State, v.Height)
		}
		for _, blk := range branch.Blocks {
			e.Pool.OnBlock(blk, v.State, v.Height)
		}
	})
}

// Orphan-pool errors.
var (
	ErrOrphanOutOfWindow = errors.New("p2p: orphan height is outside the window")
	ErrOrphanImplausible = errors.New("p2p: orphan declares a target no legitimate branch could reach")
	ErrOrphanPoolFull    = errors.New("p2p: orphan pool is full")
)

// holdOrphan admits a block to the orphan pool, or refuses it.
func (e *Engine) holdOrphan(blk *types.Block) error {
	p := e.Chain.Params()
	tip := e.Chain.Tip()

	// The height window. A branch far from the tip is not a healing partition.
	distance := int64(blk.Header.Height) - int64(tip.Height)
	if distance < 0 {
		distance = -distance
	}
	if uint64(distance) > e.orphanLimits.HeightWindow {
		return fmt.Errorf("%w: %d blocks from the tip", ErrOrphanOutOfWindow, distance)
	}

	// Target plausibility. The LWMA clamps each step to a factor of
	// DifficultyClampFactor, so from the tip's target no legitimate branch can
	// reach an easier target than clamp^distance within that distance. An
	// orphan claiming easier than that is claiming work it cannot have done.
	//
	// The bound weakens with distance and saturates — at which point it admits
	// anything, which is the honest answer: at that range a node genuinely
	// cannot tell without the ancestor headers. That is why the window is
	// tight and why headers-first is the real fix.
	if blk.Header.Target.Gt(plausibleCeiling(tip.Target, uint64(distance), p.DifficultyClampFactor)) {
		return fmt.Errorf("%w: target %s at distance %d",
			ErrOrphanImplausible, blk.Header.Target.String(), distance)
	}

	size := blk.SizeBytes()

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, held := e.orphans[blk.Header.ID()]; held {
		return nil
	}
	for (len(e.orphans) >= e.orphanLimits.MaxBlocks ||
		e.orphanBytes+size > e.orphanLimits.MaxBytes) && len(e.orphans) > 0 {
		if !e.evictFurthestOrphanLocked(tip.Height) {
			break
		}
	}
	if len(e.orphans) >= e.orphanLimits.MaxBlocks || e.orphanBytes+size > e.orphanLimits.MaxBytes {
		return ErrOrphanPoolFull
	}
	e.orphans[blk.Header.ID()] = blk
	e.orphanBytes += size
	return nil
}

// evictFurthestOrphanLocked drops the held block furthest from the tip, ties
// broken by id so eviction is deterministic and reproducible from a log.
func (e *Engine) evictFurthestOrphanLocked(tipHeight uint64) bool {
	var worstID types.Hash
	var worstDist uint64
	var found bool
	for id, b := range e.orphans {
		d := b.Header.Height
		if d > tipHeight {
			d -= tipHeight
		} else {
			d = tipHeight - d
		}
		if !found || d > worstDist || (d == worstDist && string(id[:]) > string(worstID[:])) {
			worstID, worstDist, found = id, d, true
		}
	}
	if !found {
		return false
	}
	e.orphanBytes -= e.orphans[worstID].SizeBytes()
	delete(e.orphans, worstID)
	return true
}

// plausibleCeiling is the easiest target a legitimate branch could declare at a
// given distance from the tip, given the per-step LWMA clamp. It saturates,
// because past a certain distance there is no bound to give.
func plausibleCeiling(tipTarget u256.U256, distance, clamp uint64) u256.U256 {
	if clamp < 2 {
		clamp = 2
	}
	ceiling := tipTarget
	for i := uint64(0); i < distance; i++ {
		next, overflow := ceiling.Mul(u256.FromUint64(clamp))
		if overflow || next.Gte(u256.Max) {
			return u256.Max
		}
		ceiling = next
	}
	return ceiling
}

// assembleBranch walks back from a block through the held orphans until it
// reaches a block this chain already has, and returns the branch in ascending
// height order.
//
// The walk is bounded by the number of orphans held, so a peer cannot make it
// run long by sending a chain of fabricated parents — every step must be a
// block already accepted into the orphan set, and that set is bounded.
func (e *Engine) assembleBranch(tip *types.Block) (chain.Branch, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var reversed []*types.Block
	current := tip
	for i := 0; i <= len(e.orphans); i++ {
		reversed = append(reversed, current)
		if _, err := e.Chain.CanonicalHeader(current.Header.ParentID); err == nil {
			// Reached a block this chain is built on: the branch attaches here.
			//
			// Canonical, not merely known. Since a reorg's loser keeps its
			// header, "this chain knows it" answers yes for exactly the blocks
			// this walk has to walk *past* — the losing segment's own — and the
			// branch would be truncated and anchored on a block this node does
			// not follow. ConsiderBranch rejects that with ErrUnknownAncestor,
			// which nothing scores and nothing logs, so a node that moved off a
			// segment and later sees it become the heaviest chain again would
			// never take it back over gossip.
			out := make([]*types.Block, len(reversed))
			for j, b := range reversed {
				out[len(reversed)-1-j] = b
			}
			return chain.Branch{Blocks: out}, true
		}
		parent, held := e.orphans[current.Header.ParentID]
		if !held {
			return chain.Branch{}, false
		}
		current = parent
	}
	return chain.Branch{}, false
}

// forgetBranch drops adopted blocks from the orphan set.
func (e *Engine) forgetBranch(br chain.Branch) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range br.Blocks {
		if held, ok := e.orphans[b.Header.ID()]; ok {
			e.orphanBytes -= held.SizeBytes()
			delete(e.orphans, b.Header.ID())
		}
	}
}

// OrphanCount reports how many blocks are held awaiting a branch. A number that
// only grows is a node that is not converging.
func (e *Engine) OrphanCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.orphans)
}

// replyByteBudget returns how many bytes of query reply one peer identity may
// be served, and over how many seconds that whole allowance comes back.
//
// # The gap this closes
//
// Each individual reply on the serving path is capped and always was: a
// get-headers answer at MaxHeadersPerResponse × types.HeaderSize, a get-block
// answer at BlockChunkBytes. What had no bound is the number of requests per
// second, and therefore the aggregate — wire.md §10.4 states the MUST and
// names this as the one rule in that section the implementation did not
// satisfy.
//
// # The rate, derived
//
// **It is the sustained-bandwidth floor this project has already committed
// to, and it is not a round number.** docs/decisions/testnet-measurements.md
// and docs/decisions/capacity-eras.md state that floor as "the genesis byte
// ceiling is ~0.7 Mbit/s sustained and the capacity 2.1"; syncAttemptTimeout's
// own derivation (node/p2p/syncdriver.go) restates the same pair as 87.5 KB/s
// and 262.5 KB/s and sizes the ten-minute attempt deadline off them, on the
// stated grounds that ten minutes then "buys roughly 21 genesis-ceiling blocks
// (50 MiB / 2.5 MB) or 19 structural-ceiling blocks (150 MiB / 8 MB) of real
// progress per attempt". Those two rates are those two ratios ROUNDED, and
// the rounding is worth naming rather than eliding: capacity-eras.md derives
// its figure from the ratio itself — "8 MB per 30-second block is ~2.1 Mbit/s
// sustained" — so the identity is the document's own, but 2.1 Mbit/s is
// 262,500 B/s against BlockByteCapacity/TargetBlockSeconds = 266,667, and
// 0.7 Mbit/s is 87,500 against BlockByteLimitGenesis/TargetBlockSeconds =
// 83,333. Both docs write "~". The larger pair is the one the timeout's
// arithmetic assumes an honest attempt achieves, and the direction of its
// rounding is the one that matters here: 262,500 is BELOW the ratio, so a
// budget set at the ratio clears the stated floor rather than sitting under
// it. It is therefore the smallest rate derivable from the two constants that
// contradicts nothing already written down, and not the smallest rate that
// contradicts nothing at all — 262,500 would also do, and is a rounding
// rather than a constant.
//
// So the second is a FLOOR this tree has already committed to rather than a
// number picked here: a serve budget below it does not merely inconvenience a
// syncing peer, it falsifies syncAttemptTimeout — an honest attempt would stop
// making the progress that constant's derivation assumes inside the window
// that constant allows, and ten minutes would begin firing on honest peers.
// And any rate above it bounds strictly less while buying nothing the design
// says either end of the link can use. The smallest rate that does not
// contradict a constant already in the tree is therefore the whole answer:
//
//	BlockByteCapacity bytes per TargetBlockSeconds seconds
//
// # The catch-up factor falls out; it is not chosen either
//
// Real blocks are capped by Params.BlockByteLimit(t), clamped to
// BlockByteLimitGenesis today, so the honest chain grows at most
// BlockByteLimitGenesis/TargetBlockSeconds bytes per second while this budget
// serves BlockByteCapacity/TargetBlockSeconds. A syncing peer therefore
// downloads at BlockByteCapacity/BlockByteLimitGenesis = 8,000,000/2,500,000 =
// 3.2x the rate the chain grows — capacity-eras.md's own "3.2x its genesis
// throughput" ratio, reached here from the same two constants — and a node
// offline for T catches up in T/(3.2-1) = T/2.2. In a later era whose real
// blocks reach BlockByteCapacity the factor is 1.0, and that is a statement
// about the committed link rather than about this budget: there the floor and
// the chain's own growth are the same number and no serve budget can create
// bandwidth. capacity-eras.md §"sustained bandwidth" is where that re-pin is
// tracked, and this function moves with it because it reads the same fields.
//
// # The window, and why the burst it implies is safe
//
// TargetBlockSeconds, the same interval the floor is calibrated on — "a
// maximally-sized block transfers in about one block interval" is how
// syncAttemptTimeout puts it. So the bucket holds BlockByteCapacity bytes and
// refills once per block interval. One window's burst is the budget plus at
// most one reply, not the budget: replyBudgetExhausted reads BEFORE
// chargeReplyBytes writes — it has to, or an exhausted peer would buy the
// chain read the refusal exists to save — so a peer one byte short of its
// budget is still served one whole reply. What keeps that from being a per
// window surcharge is that refilledServed's PARTIAL arm carries the excess
// into the next window as debt instead of forgiving it, which holds the
// sustained rate at budget/period rather than at budget/period plus a reply.
// TestManyWindowsDeliverTheirBudgetAndNotTheirBudgetPlusOneReplyEach drives
// eight windows and pins that total under n*budget + one reply.
//
// That burst has to clear the largest single reply either budgeted kind can
// produce, or a transfer exists that the budget can never afford and the price
// becomes a rejection. It does, with room: BlockChunkBytes is 4,194,304 and
// MaxHeadersPerResponse × types.HeaderSize is 512 × 228 = 116,736, both under
// BlockByteCapacity's 8,000,000. TestBlockByteCapacityFitsChunkedTransfer
// already pins the same pair from the other side.
//
// # It scales with the network rather than being one figure
//
// Read off the chain's own params, so devnet's five-second blocks give
// 1.6 MB/s against mainnet's 266,667 B/s — six times the rate because devnet's
// chain grows six times faster. A budget written as a package constant would
// have been right for at most one of them.
//
// Zero for either field disables the budget rather than refusing everything,
// and that is the opposite direction from keyEpochPeriod's saturating exits on
// purpose. There, refusing is safe: an unpayable announcement is one message.
// Here, "budget zero" would mean this node serves no headers and no bodies to
// anyone, ever — a liveness failure for the whole network rather than a tight
// bound. params.Validate does not permit either field to be zero on a loadable
// parameter set; this arm states what the arithmetic does if one ever is.
func replyByteBudget(p *params.Params) (budget, period uint64) {
	if p.BlockByteCapacity <= 0 {
		return 0, 0
	}
	return uint64(p.BlockByteCapacity), p.TargetBlockSeconds
}

// replyBudgetKey returns what a served reply's bytes are charged to.
//
// **The authenticated identity where there is one, and that is the whole
// decision this function encodes.** The open question was whether the budget
// should live on the connection (simpler, resets on reconnect) or follow the
// peer. It has been measured twice on the budget next door: one identity
// re-buys a connection-lifetime budget eight times over for the price of eight
// TLS handshakes — 40 key epochs against a budget of 5, linear in handshakes
// with no ceiling in it — because Engine.forgetPeer drops the entry on
// disconnect and an inbound Conn.Addr is "ip:ephemeral_port".
// PeerStore.AdjustKey's own comment calls that "a value the OS picks fresh on
// every reconnect, not the peer", and exactly this hole was closed for the
// SCORE by adding the identity-keyed store this budget now lives in.
// CostClass's contract — "the budget must itself be bounded independently of
// the sender's choices" — is not met by anything the sender mints, and a
// connection is minted by the sender.
//
// The connection address is the fallback and not the design. It is reached
// only by a caller that has no authenticated key: Engine.Handle, which exists
// for tests and for callers that never completed a TLS handshake.
// Node.serve calls HandleFrom with Conn.PeerKey, which node.go's own comment
// records as "always populated by this point" for inbound and outbound alike.
// The fallback is deliberately not "no budget": an unbudgeted path reachable
// by omitting an argument is the wrong state made representable, and a
// per-address budget is weaker than a per-identity one rather than absent.
//
// The two share one keyspace because they answer one question — who is this —
// with the most durable identifier available. They cannot collide: a key here
// is the raw 32 bytes of an Ed25519 point, and producing one that spells an
// ASCII "ip:port" means choosing a public key's encoding, which needs the
// discrete log rather than a lucky address.
func replyBudgetKey(peerAddr string, peerKey ed25519.PublicKey) string {
	if len(peerKey) > 0 {
		return string(peerKey)
	}
	return peerAddr
}

// replyByteCeiling is the node-wide bound on reply bytes: the connection set
// this node admits multiplied by what one payer may be served in a window.
//
// **It is the ceiling the per-identity budget already implied at an instant,
// made true over identities and over time as well, and that is the whole of its
// derivation** — the same sentence unheldKeyEpochCeiling writes about the
// budget next door, because the mintable-identity aggregate applies to this
// primitive too. The per-identity reply budget is keyed on the authenticated
// Ed25519 identity, which is the durable name a sender cannot mint *for a given
// connection* — but a keypair is free, so the aggregate over identities is
// whatever the attacker cares to present, and the only thing standing behind it
// was the socket, so the node's total egress was bounded by a socket rather
// than by a number anyone picked.
//
// The set is Node.register's own — MaxInbound + 2*MaxOutbound, pushed in by
// SetConnectionSet — so no arrangement of peers that could be served before this
// ceiling existed is refused by it at an instant: 48 concurrent identities each
// holding a full budget is exactly the ceiling at the defaults. What it removes
// is the multiplication over identity churn: a peer that drains a budget, hangs
// up and returns under a fresh key used to buy a fresh budget for the price of a
// TLS handshake, and the aggregate was linear in handshakes with no ceiling in
// it — the shape measured for key epochs, and the same shape this budget meets
// when a spent budget is shed through its own store's eviction.
//
// **Recovery is one period, and it is one period at the layer below too.** There
// is no separate rate to keep in step, because refilledServed credits a whole
// bucket per period at whatever size the bucket is: the per-identity layer comes
// back in one window and so does this one. That is the identity that had to be
// repaired by hand for the key-epoch pair, where the bucket was a multiple of the
// per-payer budget and the rate was not — a bound whose recovery is measured in
// months is a one-way latch rather than a ceiling — and here it holds by
// construction rather than by pairing.
//
// **What it costs, stated as a cost.** It is a shared lever, exactly as the
// key-epoch ceiling is: one identity bulk-syncing at full rate can hold a share
// of it, and enough of them can hold all of it, so a peer that has spent nothing
// of its own budget can be refused. That is bounded by what refusal means here —
// the asker retries in the next window, and node/sync's own header and body
// requests to *other* peers are unaffected because they are this node's egress
// on its own connections, not a reply it is being asked for.
//
// **What it deliberately does not do is pick the operator's link rate.** The
// arithmetic is that 48 x 266,667 B/s is about 102 Mbit/s against a design that
// commits its operators to 2.1 Mbit/s, and closing that gap needs a number that
// is a policy input rather than a derivation — docs/decisions/capacity-eras.md
// §"sustained bandwidth" is waiting on exactly that measurement. This ceiling
// makes the *reply* total bounded by a number the protocol picked instead of by
// the socket; tightening that number to the committed link is a separate
// decision with an owner's ratification behind it, and inventing one here would
// be choosing a protocol constant by inference.
//
// **The reply total is not this node's egress, and reading it as one is the
// error this comment made until it was measured** — it said "the total". Gossip
// forwarding is not a reply and is outside both layers. Every reply a peer asks
// for is now inside this layer — chargeReplyBytes for the two budgeted kinds,
// and OnGetPeers charging chargeNodeServedBytes directly, which is why that
// handler's `Served` row moved with it — but everything a peer does not have to
// ask for is still outside both layers, and above all gossip forwarding, where
// Node.Broadcast writes one copy of every accepted payload to every connection
// but the sender's — up to 39 of them at the defaults (honestSteadyStateConns,
// MaxInbound + MaxOutbound = 40, less the sender; not maxConnections, which is
// the adversarial 48). Forwarding is the dominant egress term, so no
// arrangement of these two ceilings bounds what this node sends.
//
// That is stated rather than fixed, on purpose. Metering forwarding is not a
// tighter version of this ceiling but a different decision: a node that stops
// forwarding because it hit a bound partitions the mesh quietly, which is worse
// than the amplification it would be trading away, and what makes forwarding
// cheap to buy in the first place is an announcement admitted on a self-declared
// target rather than the absence of a ceiling here.
//
// A set of zero or less means nothing has been published yet and the defaults
// apply, and the clamp is unheldKeyEpochCeiling's, for the reason stated there:
// this arithmetic owns its own range rather than borrowing it from whatever an
// operator types.
//
// A zero budget yields a zero ceiling, and the two callers below read that as
// "disabled" rather than as "refuse everything" — replyByteBudget's own
// direction and the opposite of keyEpochPeriod's, because "budget zero" here
// would mean this node serves nothing to anyone, ever. **They read it through
// the period and not through the ceiling**, because replyByteBudget hands back
// (0, 0) together or a budget of at least one, and the set below is at least
// one: a zero ceiling is a zero period, spelled differently.
// TestAZeroReplyByteCeilingIsAlwaysAZeroPeriod pins that over the whole domain a
// loadable parameter set can present, so the callers' `period == 0` covers this
// paragraph as well as its own.
//
// The zero falls out of the multiplication rather than being guarded here: an
// explicit `budget == 0` arm was written first and then deleted, because every
// input it could catch the product below already answers with the same zero, so
// no input separates the two — measured, not assumed, by a mutant that removed
// it and was not killed. That is the standard refilledServed and
// SetConnectionSet already set in this package: a guard nobody can check is
// worth deleting rather than documenting.
func replyByteCeiling(connSet int, budget uint64) uint64 {
	set := connSet
	if set <= 0 {
		set = DefaultMaxInbound + 2*DefaultMaxOutbound
	}
	if set > maxUnheldConnectionSet {
		set = maxUnheldConnectionSet
	}
	return uint64(set) * budget
}

// nodeServedBytesExhausted reports whether this node has already handed out its
// whole node-wide allowance of reply bytes for the current window.
//
// A read and nothing else, which is what lets replyBudgetExhausted consult it at
// wire.md §10.1 step 3; the refill it accounts for is arithmetic in
// refilledServed and is written back only by chargeNodeServedBytes.
//
// A zero period disables the ceiling rather than refusing everything, and it is
// the whole guard — the same one nodeKeyEpochsExhausted and chargeNodeKeyEpoch
// read one screen up, so the four sites of this shape in this package read the
// same. A `ceiling == 0` conjunct stood here and was deleted, and both mutants —
// the one that removes the deleted clause and the one that removes the clause
// that stayed — survive the grid. **They survive for opposite reasons, and the
// line between them is the rule, not a preference:**
//
//	Delete a clause NO INPUT CAN SEPARATE.
//	Keep a clause AN INPUT SEPARATES BUT NO CALLER SUPPLIES.
//
// `ceiling == 0` was the first. It is absorbed by its own sibling — replyByteBudget
// returns (0, 0) together or a budget of at least one, and replyByteCeiling's set
// is at least one — so on EVERY input, reachable or not, the same return fires
// whether the clause is there or not. That is a tautology wearing a guard's
// clothes, not a guard, and no test anywhere could tell the two programs apart.
// TestAZeroReplyByteCeilingIsAlwaysAZeroPeriod is the proof of the absorption.
//
// `period == 0` is the second, and its separating input is not merely a wrong
// answer — it is a crash. Driven directly, refilledServed's second arm computes
// (now - servedAt) / period and served / budget, both zero in that state, so the
// call is `runtime error: integer divide by zero` as soon as the clock has moved
// (measured, by calling refilledServed(1, 1, 0, 0, 2)). What makes it
// unreachable is params.Validate rejecting a zero target_block_seconds — an
// EXTERNAL PRECONDITION THIS FUNCTION NEITHER SEES NOR ENFORCES — so the clause
// is the only thing making the documented direction true standalone rather than
// by the caller's grace: a disabled budget disables this layer instead of taking
// the node down, and refusing every reply would be a liveness failure for the
// whole network besides. That is the kept case exactly, and
// nodeKeyEpochsExhausted says the same of its own arm ("this arm needs a caller
// that does not use it").
func (e *Engine) nodeServedBytesExhausted(budget, period, now uint64) bool {
	ceiling := replyByteCeiling(e.connSetLocked(), budget)
	if period == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	served, _ := refilledServed(e.servedBytes, e.servedBytesAt, ceiling, period, now)
	return served >= ceiling
}

// chargeNodeServedBytes adds n bytes of served reply to this node's own window.
//
// The guard is the read's, for the reason stated there: `period == 0` alone,
// because `ceiling == 0` is the same condition spelled a second way and this
// package now implements the shape identically at all four of its sites.
func (e *Engine) chargeNodeServedBytes(n, budget, period, now uint64) {
	ceiling := replyByteCeiling(e.connSetLocked(), budget)
	if period == 0 || n == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.servedBytes, e.servedBytesAt = refilledServed(e.servedBytes, e.servedBytesAt, ceiling, period, now)
	// Saturating rather than wrapping, for the reason ChargeServedBytes gives
	// one field over: a wrapped total is a SMALLER one, and a smaller one hands
	// back a ceiling this node has already spent. Unreachable while the read
	// above refuses at the ceiling — the level can exceed it only by the replies
	// in flight, which the connection set bounds — so no input separates this
	// arm and a mutant that deletes it is not killed. It is kept rather than
	// deleted, exactly as chargeNodeKeyEpoch keeps its own, because it is the
	// arithmetic carrying its own property rather than borrowing it from a
	// caller; that is a different case from a guard whose whole answer the
	// expression below already gives, which is why replyByteCeiling's zero arm
	// was deleted and this one was not.
	if e.servedBytes+n < e.servedBytes {
		e.servedBytes = ^uint64(0)
		return
	}
	e.servedBytes += n
}

// connSetLocked reads the published connection set. Named for what it is not:
// it takes e.mu itself, so the two callers above must read it BEFORE they take
// the lock for their own accounting.
func (e *Engine) connSetLocked() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connSet
}

// replyBudgetExhausted reports whether a reply to this payer must be refused,
// and whether it was the payer's OWN budget that refused it rather than the
// node-wide ceiling standing over it.
//
// Two layers, because no single axis is both exact and unmintable — the rule
// settled for the key-epoch primitive, applied to this one. The
// per-identity budget is the exact half: it is attributable, so one peer's
// demand is charged to that peer. The node-wide ceiling is the unmintable half:
// it is keyed on nothing at all, so identity churn does not multiply it.
//
// The ceiling is read FIRST and charged LAST, mirroring spendKeyEpoch: two
// handlers racing here can overshoot by at most the replies in flight, which is
// bounded by the connection set and not by the sender.
//
// The second return is what keeps the refusal's score off the wrong peer. A refusal by
// the shared ceiling can be caused by somebody else's traffic entirely, so it is
// never scored; only a payer that has exhausted its own attributable budget can
// be charged for asking again, and only under the further conjunct refuseUnbudgeted
// states.
//
// A read and nothing else, which is what lets it sit at wire.md §10.1 step 3 —
// "read-only rate and budget checks" — ahead of the chain read and the marshal
// that step 5 charges for. The refill it accounts for is arithmetic in
// refilledServed and is written back only by chargeReplyBytes.
func (e *Engine) replyBudgetExhausted(payer string) (refused, own bool) {
	budget, period := replyByteBudget(e.Chain.Params())
	if e.nodeServedBytesExhausted(budget, period, e.now()) {
		return true, false
	}
	if e.Peers == nil {
		return false, false
	}
	if e.Peers.ServedBytesExhausted(payer, budget, period, e.now()) {
		return true, true
	}
	return false, false
}

// workRefused reports whether this node's own work check has already refused an
// announcement from this identity. See identityEntry.workRefused for why the
// fact is kept, and refuseUnbudgeted for what reads it here.
func (e *Engine) workRefused(payer string) bool {
	return e.Peers != nil && e.Peers.WorkRefusedKey(payer)
}

// chargeReplyBytes charges a served reply against its payer's window.
//
// The bytes actually sent, counted from the marshalled payload rather than
// estimated from a ceiling. A peer near this node's tip asks for headers and
// is answered with three of them; charging it MaxHeadersPerResponse would
// price the request rather than the reply, and the first open question —
// bytes or requests — is decided here for exactly that reason. Requests are
// not comparable across kinds: one 12-byte get-headers frame buys on the order
// of 116 KB and one get-block frame buys up to BlockChunkBytes, so a
// request-count budget would have to be sized for the larger and would then be
// some 36x too loose for the smaller. Bytes are the resource a served reply
// spends, and bytes are what is counted.
//
// Charged to both layers, and the node-wide one is charged even where there is
// no peer store: a store is what makes a reply *attributable*, and the total
// this node emits is a fact about this node whether or not it can name who
// asked. That sentence is why OnGetPeers charges chargeNodeServedBytes
// directly rather than calling this function: it has the one layer keyed on
// nothing to answer to and not the other, since its own rate limit is keyed on
// the connection rather than on the identity this budget is keyed on.
//
// **That last sentence has no instrument behind it, and this is the note saying
// so.** Moving the chargeNodeServedBytes call below the `e.Peers == nil` return
// is a mutant that no test in this tree kills, and **none production-reachable
// does**: an input separates it — construct an Engine with a nil Peers, charge,
// and assert servedBytes moved — but Node.serve is the only production caller
// and it never arrives here with a nil store. So this is a KEPT case under the
// line nodeServedBytesExhausted draws, on the same side as its `period == 0`
// arm, and not an unkillable one: what is missing is the pinning, not the
// separating input. The ordering is kept because the sentence is the reason the
// node-wide layer is keyed on nothing — a layer that quietly needed an identity
// store would be the per-identity layer again — but until something drives that
// input it is an argument about what the code should mean rather than a property
// a test is holding down. Stated rather than left to read as pinned, which is
// the failure PROTOCOL.md rule 2 records four times over.
func (e *Engine) chargeReplyBytes(payer string, n int) {
	if n <= 0 {
		return
	}
	budget, period := replyByteBudget(e.Chain.Params())
	e.chargeNodeServedBytes(uint64(n), budget, period, e.now())
	if e.Peers == nil {
		return
	}
	e.Peers.ChargeServedBytes(payer, uint64(n), budget, period, e.now())
}

// refuseUnbudgeted is the exhaustion path, and it is one function rather than
// two copies because fixing this per handler would repeat the mistake cost
// discipline exists to stop: one rule with two homes drifts toward whichever
// one nobody measures.
//
// **Refused, not stalled, and unscored.** Stalling is friendlier to an honest
// peer and ties up the serve goroutine and the connection slot behind it,
// which hands a cheap frame a resource that is not bytes; wire.md §10.4's own
// rule is that the answer stops, not that it waits.
//
// Unscored is the half that keeps this from being the guard that was reverted.
// The budget is sized at the committed link floor, so an honest peer on a
// FASTER link reaches it in the ordinary course of bulk sync — it is not
// misbehaving, it is downloading. ScoreExcessRequest is -5 and
// ScoreBanThreshold is -100, so scoring the refusal would ban a fast honest
// syncer in 20 frames. That is I7-H4's revert exactly: a guard that breaks
// catch-up. The same reasoning the key-epoch budget makes for its own refusal,
// from the other end of the wire.
//
// The refusal is nonetheless priced, in the class wire.md §10.2 requires:
// CostBudgeted, with a bounded resource named. What it costs the sender is
// that the amplification it was buying goes to zero — this node reads no
// chain record, marshals no reply and sends no bytes, so past the budget a
// query costs this node strictly less than the honest path it replaces while
// returning the asker nothing.
//
// **Unscored EXCEPT for an identity this node's own work check has already
// refused, and that conjunct is this path's half of the same decision the
// announce path made.** CostClass says a negative score "is the only cost class
// that terminates a flood of distinct messages", and an unconditionally unscored
// refusal moved every over-budget query out of that class: a peer past its
// budget could go on asking, be answered nothing, and accumulate nothing against
// itself, forever. The separating fact is one this node established for itself
// and did not throw away — identityEntry.workRefused, set only where work.Check
// refused an announcement from this identity. An honest peer cannot acquire it:
// a header meets the target its own header declares, or its announcer built it
// wrong. So the fast honest syncer of TestAnHonestBulkSyncRateIsNeverThrottled
// keeps the unscored refusal, which is the whole reason the refusal was unscored,
// and an identity already caught lying keeps no amnesty on this path either.
//
// Never scored for a refusal by the node-wide ceiling, only for one by the
// payer's own budget: the ceiling is shared, so a refusal there can be caused by
// traffic this payer never sent, and scoring somebody for another peer's flood is
// the shape of the guard I7-H4 reverted rather than a repair of it.
//
// **What is deliberately still not bounded is the request RATE for an identity
// this node has never caught**, and that is stated as an accepted cost rather
// than argued away, because wire.md §10.4's MUST has two conjuncts and this
// discharges the second and half of the first. **Measured on this head rather
// than inferred**, by the two benchmarks in egressceiling_internal_test.go on a
// loaded 20-thread machine: a refused get-headers is 335 ns, 160 B and 3
// allocations, against 1.03 ms, 1.31 MB and 3,606 allocations for the reply it
// replaces — about 3,000x cheaper in time and 8,000x in bytes. The sender pays
// a 17-byte frame (5-byte header, 12-byte payload) and a round trip for each
// one and is answered nothing, so the amplification past the budget is below 1
// where the honest path is on the order of 116 KB per 17-byte frame. The
// per-connection read loop in Node.serve is synchronous, so one connection's
// refusal rate is its own round trips, and the concurrent connection set is
// Node.register's gate. So the flood is bounded by the sender's own bandwidth
// and by a number the protocol picked; what it is not bounded by is a count per
// window, and a count per window would need a refusal rate an honest syncer
// never exceeds, which is a number no measurement in this tree supplies.
func refuseUnbudgeted(kind string, caught bool) Verdict {
	if caught {
		return Verdict{Cost: CostScored, Score: ScoreExcessRequest, Err: fmt.Errorf(
			"%w: this peer identity has been served its whole %s byte budget for this "+
				"window, and its announcements have already been refused by the work check",
			ErrReplyBudget, kind)}
	}
	return Verdict{Cost: CostBudgeted, Err: fmt.Errorf(
		"%w: this peer identity has been served its whole %s byte budget for this window",
		ErrReplyBudget, kind)}
}

// OnGetBlock serves one chunk of a block body.
//
// Body availability is consensus: a block whose bodies cannot be retrieved is
// not valid. A peer that announces what it will not serve is therefore wasting
// the network's time, and the caller scores it down. Serving is stateless: the
// requester names the chunk, so this node holds nothing between requests.
//
// payer is what the reply's bytes are charged to; see replyBudgetKey. The
// budget check sits after the decode and before Chain.BlockRaw, so a malformed
// frame is still Scored(invalid) rather than being swallowed by the refusal,
// and an exhausted peer buys no store read — wire.md §10.1's order, with the
// structural check at step 1 and the read-only budget check at step 3.
func (e *Engine) OnGetBlock(payer string, raw []byte) Verdict {
	req, err := UnmarshalGetBlock(raw)
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	if refused, own := e.replyBudgetExhausted(payer); refused {
		return refuseUnbudgeted("block", own && e.workRefused(payer))
	}
	// The stored encoding, not a decode-and-re-encode of it. Chain.Block
	// paid for a full types.UnmarshalBlock - a *types.Certificate allocated
	// per certificate in the block - and MarshalSSZ then paid to build the
	// same bytes again, to hand back a slice of a record the store already
	// held verbatim. A sender of a fixed-size get-block frame bought both,
	// once per chunk, for every chunk of every block it asked for.
	//
	// BlockRaw's contract is that these are the bytes MarshalSSZ produced
	// when the block was committed, so the chunking is over the same byte
	// string as before and a peer reassembling chunks still hashes to req.ID.
	body, err := e.Chain.BlockRaw(req.ID)
	if err != nil {
		return Verdict{Cost: CostFree, Err: err}
	}
	total := ChunkCount(len(body))
	if int(req.Chunk) >= total {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: errors.New("p2p: block chunk request out of range")}
	}
	chunk := BlockChunk{ID: req.ID, Chunk: req.Chunk, Total: uint32(total), Data: ChunkOf(body, int(req.Chunk))}
	payload := chunk.MarshalBlockChunk()
	e.chargeReplyBytes(payer, len(payload))
	return Verdict{Cost: CostBudgeted, Reply: &Outbound{Kind: KindBlock, Payload: payload}}
}

// OnGetHeaders serves a header range for sync.
//
// It reads headers and never bodies. That is what keeps the handler from
// being an amplifier: this loop used to call Chain.BlockAt per height, so a
// 12-byte frame naming Count=MaxHeadersPerResponse bought that many full
// types.UnmarshalBlock calls - a record copy and a *types.Certificate per
// certificate per height - of which types.HeaderSize bytes each were kept and
// the rest discarded. Cost to the responder was O(sum of body bytes over the
// range) for an O(types.HeaderSize x Count) answer, and the two are unrelated:
// the request does not pay for the bodies and the answer does not contain
// them.
//
// Chain.CanonicalHeadersFrom also takes the chain lock once for the whole
// range instead of once per height, and reproduces this loop's two stopping
// rules exactly: it stops at the tip, and it stops at the first height it
// cannot read, so a request past the end of this chain still answers with a
// short list rather than an error.
// payer is what the reply's bytes are charged to; see replyBudgetKey, and
// OnGetBlock for why the check sits between the decode and the chain read.
func (e *Engine) OnGetHeaders(payer string, raw []byte) Verdict {
	req, err := UnmarshalGetHeaders(raw)
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	if refused, own := e.replyBudgetExhausted(payer); refused {
		return refuseUnbudgeted("header", own && e.workRefused(payer))
	}
	out := e.Chain.CanonicalHeadersFrom(req.From, int(req.Count))
	payload := MarshalHeaders(out)
	e.chargeReplyBytes(payer, len(payload))
	return Verdict{Cost: CostBudgeted, Reply: &Outbound{Kind: KindHeaders, Payload: payload}}
}

// GetPeersMinInterval is how often one connection may be served peer exchange.
//
// It is DiverseCacheTTL, and that is the whole argument for the number: the
// selection this node serves cannot change more often than that, so a second
// request from the same connection inside the window is a request for bytes
// that connection has already been given. Anything at or above the interval is
// served and charged nothing, and GetPeersInterval — the rate a conforming node
// asks at — is ten times it, so a conforming asker never comes near this floor.
const GetPeersMinInterval = DiverseCacheTTL

// ErrGetPeersTooOften reports a peer-exchange request repeated inside
// GetPeersMinInterval. It is refused rather than answered: answering is what
// makes the 5-byte request a bandwidth amplifier.
var ErrGetPeersTooOften = errors.New("p2p: get-peers repeated inside the minimum interval")

// ErrGetPeersNodeEgress reports a peer-exchange reply refused because **this
// node** has already emitted its whole node-wide reply-byte ceiling for the
// window.
//
// It wraps ErrReplyBudget because it is the same family of refusal — the query
// is good and nothing was served — but it deliberately does not say what
// refuseUnbudgeted says, because no identity was consulted and none is named.
// The ceiling is keyed on nothing the sender presents, so a connection
// that has asked once in its life meets this refusal when other traffic
// entirely has drained the ceiling. That is exactly why it carries no score:
// wire.md §10.4 charges the excess-request score only where the sender's own
// budget refused it, never where the shared ceiling did.
var ErrGetPeersNodeEgress = fmt.Errorf("%w: this node has emitted its whole node-wide reply-byte ceiling for this window", ErrReplyBudget)

// OnGetPeers serves peer exchange.
//
// Three things bound what a request costs, and they are not the same bound
// three times. PeerStore.SelectDiverse memoizes the selection, so a request no
// longer buys a snapshot and a sort of the whole store - measured on this
// revision at 3.0 ms and 429 KB per 5-byte frame at MaxPeers, superlinear in
// store size. The interval below bounds how often the remaining work -
// marshalling up to MaxPeersPerResponse addresses into a ~1.2 KB reply - is
// done for one connection at all, and charges the peer for asking again inside
// it. Without the second bound the handler is still an amplifier: cheaper per
// frame, still unpriced per peer.
//
// **The third is the node-wide egress layer, and it is here because the total
// this node emits is a fact about this node.** chargeReplyBytes says so
// in as many words about the layer keyed on nothing, and while this handler
// stood outside it the sentence was false: a `peers` frame was bytes this node
// sent that its own node-wide total neither refused when the ceiling was spent
// nor counted once it was served. The magnitude is not the reason — 48
// connections asking as often as the interval allows is ~57.6 KB per window
// against a ceiling six thousand times larger, which exhausts nothing — the
// reason is that a counter documented as "the total this node emits" must hold
// that total, or a reader checking the invariant repairs the comment instead of
// the code.
//
// **The per-identity budget is still not charged here, and that is the half the
// served-reply change was right to refuse.** replyByteBudget's other layer is
// keyed on the authenticated identity, while the interval below is keyed on
// PeerTip.lastGetPeers and therefore on the connection. Charging that budget
// without first moving the interval onto the identity keyspace would put two
// limits on one handler keyed on two different names, which is the conflation
// measured next door rather than a fix. The node-wide layer has no keyspace at
// all, so there is nothing for it to conflate with, and that is the whole of
// why one of the two layers moves and the other does not.
//
// **The ceiling is read before the lock and consulted after the interval
// check**, in that order for two separate reasons. Before the lock because
// nodeServedBytesExhausted takes e.mu itself. After the interval check because
// the per-connection rate limit must keep deciding the repeats it already
// decides: a peer hammering this handler inside its window is still
// Scored(excess request) while the ceiling is spent, rather than being handed
// an unscored refusal that terminates no flood. A ceiling refusal also leaves
// lastGetPeers unstamped, so an honest asker refused by somebody else's traffic
// has not spent its window on nothing.
//
// The last-served stamp lives on PeerTip because that is the map whose entries
// already have exactly the right lifetime - one per connection this node is
// talking to, and this handler is unreachable without a completed handshake
// (Handle) - so the rate limit needs no state of its own to grow or to reap,
// and none a peer can mint by asking.
func (e *Engine) OnGetPeers(peerAddr string) Verdict {
	now := e.wallClock()
	budget, period := replyByteBudget(e.Chain.Params())
	overCeiling := e.nodeServedBytesExhausted(budget, period, e.now())
	e.mu.Lock()
	tip, ok := e.tips[peerAddr]
	if ok && !tip.lastGetPeers.IsZero() && now.Sub(tip.lastGetPeers) < GetPeersMinInterval {
		e.mu.Unlock()
		return Verdict{Cost: CostScored, Score: ScoreExcessRequest, Err: ErrGetPeersTooOften}
	}
	if overCeiling {
		e.mu.Unlock()
		return Verdict{Cost: CostBudgeted, Err: ErrGetPeersNodeEgress}
	}
	if ok {
		tip.lastGetPeers = now
		e.tips[peerAddr] = tip
	}
	e.mu.Unlock()
	addrs := e.Peers.SelectDiverse(MaxPeersPerResponse, nil)
	payload := MarshalPeers(addrs)
	// Charged last, mirroring the two budgeted handlers: the read above happens
	// before this write, so a request that arrives one byte under the ceiling is
	// still answered in full and the overshoot is one reply, bounded by the
	// connection set rather than by the sender.
	e.chargeNodeServedBytes(uint64(len(payload)), budget, period, e.now())
	return Verdict{Cost: CostBudgeted, Reply: &Outbound{Kind: KindPeers, Payload: payload}}
}

// PeersMinInterval is how often one connection may have a `peers` frame
// accepted.
//
// It is GetPeersMinInterval, and the symmetry is the argument — this is the
// ingress half of the eclipse cluster's peer-exchange defect. This node serves
// peer exchange at most once per GetPeersMinInterval per connection, and
// GetPeersInterval — the rate a conforming node *asks* at — is ten times that,
// so a conforming peer's answer arrives at most once per five minutes on the
// one connection it was asked on. Anything at or above this floor is accepted
// and charged nothing; a peer would have to send addresses ten times faster
// than the protocol ever asks for them to meet it.
//
// Sizing the ingress floor to the egress floor rather than to some number of
// its own also means the two cannot drift into a rule where a node that obeys
// one is punished by the other.
const PeersMinInterval = GetPeersMinInterval

// ErrPeersTooOften reports a `peers` frame repeated inside PeersMinInterval.
// It is refused rather than recorded: recording is what makes an unsolicited
// frame a free write-lock acquisition per address.
var ErrPeersTooOften = errors.New("p2p: peers frame repeated inside the minimum interval")

// OnPeers records addresses from peer exchange, attributed to the peer that
// sent them.
//
// This node does send KindGetPeers: Node.askForPeers sends one per
// GetPeersInterval to one outbound peer. The verdict here is deliberately
// unchanged by that, and the reason is wire.md §12 — there are no request ids,
// so a `peers` frame cannot be correlated to the request it claims to answer,
// and a frame this node solicited is indistinguishable from one it did not.
// ErrUnsolicited is therefore still the honest verdict for every frame: it
// records that nothing here established the frame was asked for, which remains
// true. Recording the addresses is still worth doing — it is cheap, and an
// address is easy to discard later if it turns out to be bad — but
// "unsolicited" is not "useful", and wire.md §10 reserves ScoreUsefulMessage
// for a message that is both new and valid, not merely well-formed. wire.md
// §7's rule points the same way: a node MUST NOT score a `peers` frame
// positively unless it sent the `get-peers` it answers, and this node cannot
// show that it did. See docs/decisions/networking.md §12.
//
// from is load-bearing rather than bookkeeping, and it is what makes the
// recording safe to do at all: the addresses in the frame are strings the
// sender invented for free, and the only fact this node can charge them
// against is which connection they arrived on. PeerStore.AddFrom keeps that
// attribution so MaxPerSource can bound how much of this node's outbound set
// any one teller decides. An empty from — no connection, as in a direct
// unit-test call — records the addresses as ungossiped, i.e. unbounded, so
// tests that mean to exercise the bound must pass a sender.
func (e *Engine) OnPeers(from string, raw []byte) Verdict {
	addrs, err := UnmarshalPeers(raw)
	if err != nil {
		return Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
	}
	// The ingress rate limit, in the same shape and on the same keyspace as
	// the egress one OnGetPeers already applies.
	//
	// The stamp is taken before the work, and the work is the reason: below
	// this line are up to MaxPeersPerResponse calls to PeerStore.AddFrom, each
	// taking the store's write lock — the same lock Adjust takes for every
	// scored message from every peer and every dial selection read-takes — and
	// the verdict was CostFree, so nothing anywhere in the p2p layer bounded
	// how often one connection could ask for that. Measured across three
	// harnesses at 0.58 ms, 3.5 ms and 46 ms per 64-address frame, i.e. one
	// core saturated somewhere between ~35 KB/s and ~4 Mbit/s of attacker
	// upload; the spread is store-fill state and the fix does not depend on
	// which end of it is right.
	//
	// It is what made the rest of the eclipse cheap rather than a separate
	// attack: (a) and (b) both need a high free address-injection rate, and
	// this handler was the supply.
	//
	// A repeat is refused rather than partially applied, and charged
	// ScoreExcessRequest — wire.md §10.4's excess-request class, the same
	// verdict ErrGetPeersTooOften carries, because it is the same fact about
	// the sender: it asked for work inside a window it had already been given.
	// A refusal leaves lastPeers unstamped, so a flood does not push the window
	// out from under the honest frame behind it.
	//
	// A connection with no tip entry is not limited, and cannot be one that
	// matters: Handle gates every kind but hello on a completed handshake, and
	// recordTip creates the entry. The empty `from` of a direct unit-test call
	// lands in the same place, exactly as this function's doc comment already
	// says of the attribution it does not have.
	now := e.wallClock()
	e.mu.Lock()
	tip, ok := e.tips[from]
	if ok && !tip.lastPeers.IsZero() && now.Sub(tip.lastPeers) < PeersMinInterval {
		e.mu.Unlock()
		return Verdict{Cost: CostScored, Score: ScoreExcessRequest, Err: ErrPeersTooOften}
	}
	if ok {
		tip.lastPeers = now
		e.tips[from] = tip
	}
	e.mu.Unlock()
	for _, a := range addrs {
		e.Peers.AddFrom(a, from)
	}
	return Verdict{Cost: CostFree, Err: ErrUnsolicited}
}

// handshaked reports whether peerAddr has completed the one handshake a
// connection gets. Both "no entry at all" and "an entry whose Handshaked flag
// is false" (the latter meaning nothing but a hello has arrived so far — see
// PeerTip.Handshaked's own comment) read as not yet handshaked.
func (e *Engine) handshaked(peerAddr string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tips[peerAddr].Handshaked
}

// Handle dispatches an inbound message, applies the resulting peer score, and
// counts the verdict.
//
// Those last two are why ingress goes through here rather than to the On*
// judges directly. The judges decide; this decides *and* records. The only
// other place that does both is ReleaseWithheld, which cannot reuse this one
// because a matured block arrives on the clock rather than on a connection —
// so it repeats both steps, and says so. Anything else in this package that
// grows a shortcut to a judge silently stops scoring peers and stops moving
// Engine.Forwarded — and a counter that does not move looks exactly like a
// path that was not taken, which is what made the miscounted verdicts take two
// attempts to see.
//
// Every kind but hello is gated on the handshake having completed first.
// Without the gate, hello was optional for an attacker: nothing
// required it before the rest of the switch below ran, so a peer that never
// identified its network still had get-headers, get-block and get-peers
// served, and its certificates, announcements and bodies validated and
// forwarded — the exact guarantee wire.md §4 states as a MUST. A message
// refused here is a protocol violation, not merely an invalid one: the peer
// is not describing something wrong, it is declining to say who it is before
// asking this node to do work.
func (e *Engine) Handle(peerAddr string, kind MessageKind, payload []byte) Verdict {
	return e.HandleFrom(peerAddr, nil, kind, payload)
}

// HandleFrom is Handle with the peer's authenticated Ed25519 identity, which
// is the only durable name this node has for the far end of a connection.
//
// It exists because a served reply is charged to an identity and not to a
// socket, and there is a measurement of what happens when a per-peer
// budget is keyed on the socket instead: one identity, eight reconnects, eight
// full budgets. Nothing else reads the key here; Adjust stays keyed on the
// address exactly as it was, and node.go goes on applying the same verdict to
// AdjustKey separately, so this adds a budget seam and moves no scoring.
//
// Handle is kept, delegating with a nil key, rather than being replaced. Every
// caller that has an authenticated key is inside Node.serve, and there is one
// of those; a package-wide signature change across the rest would be a large
// diff that renames the same argument list. The nil-key path is not an
// unbudgeted one — replyBudgetKey falls back to the connection address, which
// is weaker and not absent.
func (e *Engine) HandleFrom(peerAddr string, peerKey ed25519.PublicKey, kind MessageKind, payload []byte) Verdict {
	var v Verdict
	payer := replyBudgetKey(peerAddr, peerKey)
	if kind != KindHello && !e.handshaked(peerAddr) {
		v = Verdict{Cost: CostScored, Score: ScoreProtocolViolation, Err: ErrHandshakeRequired}
	} else {
		switch kind {
		case KindHello:
			h, err := UnmarshalHello(payload)
			if err != nil {
				v = Verdict{Cost: CostScored, Score: ScoreProtocolViolation, Err: err}
				break
			}
			v = e.OnHello(peerAddr, h)
		case KindCertificate:
			v = e.OnCertificate(peerAddr, payload)
		case KindBlockAnnounce:
			v = e.OnBlockAnnounceFrom(peerAddr, payer, payload)
		case KindGetBlock:
			v = e.OnGetBlock(payer, payload)
		case KindBlock:
			v = e.OnBlockChunkFrom(peerAddr, payer, payload)
		case KindGetHeaders:
			v = e.OnGetHeaders(payer, payload)
		case KindHeaders:
			// Never decoded once: a 9-byte frame claiming zero headers
			// bought ScoreUsefulMessage with nothing checked at all. Decoding
			// it closes that; awarding it no score (rather than punishing it)
			// reflects that a well-formed one is merely unsolicited, not
			// invalid — see ErrUnsolicited.
			if _, err := UnmarshalHeaders(payload); err != nil {
				v = Verdict{Cost: CostScored, Score: ScoreInvalidMessage, Err: err}
				break
			}
			v = Verdict{Cost: CostFree, Err: ErrUnsolicited}
		case KindGetPeers:
			v = e.OnGetPeers(peerAddr)
		case KindPeers:
			v = e.OnPeers(peerAddr, payload)
		default:
			v = Verdict{Cost: CostScored, Score: ScoreProtocolViolation, Err: ErrUnknownKind}
		}
	}
	if v.Score != 0 {
		e.Peers.Adjust(peerAddr, v.Score)
	}
	e.countVerdict(v)
	return v
}

// PendingBody describes one announced block whose body has not arrived.
//
// It carried a PeerAddr until an audit removed it, and nothing in the
// repository ever read it: the composite literal below was its only reference,
// and a key in a struct literal sets a field rather than consulting one.
// ReapUnservedBodies — which this comment used to name as the caller that turns
// it into a score — walks e.pending directly, because it has to delete under
// the same lock it reads under, so the announcer's address reaches the scoring
// path without passing through here.
//
// ID and Announced are equally unread today: every caller of PendingBodies is a
// test taking its len. They stay because narrowing an exported accessor to a
// count is a decision about this package's observability surface, not about the
// check that noticed, and it is left as it stands deliberately.
type PendingBody struct {
	ID        types.Hash
	Announced time.Time
}

// PendingBodies returns the announced blocks whose bodies have not arrived.
// A peer that leaves entries here is one that announced what it will not serve.
func (e *Engine) PendingBodies() []PendingBody {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]PendingBody, 0, len(e.pending))
	for id, p := range e.pending {
		out = append(out, PendingBody{ID: id, Announced: p.announced})
	}
	return out
}

// PendingBodyTimeout is how long an announced block may go unserved before
// its announcer is charged for it.
//
// Generous relative to a single round trip on purpose: a body can travel as
// up to MaxBlockChunks chunks, each its own request/response, so a large
// transfer over a slow link legitimately takes longer than one message would.
// The window has to be wide enough that a peer honestly serving a big block
// is not mistaken for one that will not serve at all.
const PendingBodyTimeout = 60 * time.Second

// MaxSeenBlocks caps the block-announce dedup set.
//
// It is the hard bound the "the set never exceeds N under a flood" property
// rests on: SeenBlockTTL keeps the honest steady state far below it, but a
// flooder inserts faster than the reap ticker sweeps, so the cap — enforced on
// insert by evicting the oldest — is what bounds the size regardless of arrival
// rate or hash cost (the hash-cost throttle evaporates on dev-blake3). Sized
// like the work cache beside it (DefaultWorkCacheEntries): comfortably above any
// announcement-then-body window, so eviction never touches an id still being
// gossiped in honest operation, and a node policy number rather than a consensus
// one. docs/decisions/testnet-measurements.md §2 is where a measurement behind
// it would live.
const MaxSeenBlocks = 4096

// SeenBlockTTL is how long a deduped announcement id is remembered.
//
// The set exists to stop a block re-propagating or being re-fetched while it is
// actively gossiped and to dedup the repeat body deliveries a healthy mesh
// produces, both of which happen within seconds to a minute of the first sight.
// Ten minutes is generous relative to that window — many block intervals — so an
// honest re-announcement is still deduped, while an id whose block long since
// settled is not kept forever. Forgetting one early only re-propagates or
// re-fetches its block at most once more, which is liveness-safe; the TTL is not
// a correctness bound, the cap above is.
const SeenBlockTTL = 10 * time.Minute

// evictOldestSeenLocked drops the oldest entry from seenBlocks, ties broken by
// id so eviction is deterministic and reproducible from a log — the same
// discipline evictFurthestOrphanLocked uses. Called with e.mu held.
func (e *Engine) evictOldestSeenLocked() {
	var oldestID types.Hash
	var oldestAt time.Time
	var found bool
	for id, at := range e.seenBlocks {
		if !found || at.Before(oldestAt) ||
			(at.Equal(oldestAt) && string(id[:]) < string(oldestID[:])) {
			oldestID, oldestAt, found = id, at, true
		}
	}
	if found {
		delete(e.seenBlocks, oldestID)
	}
}

// reapSeenBlocksLocked forgets every deduped id older than SeenBlockTTL. Called
// with e.mu held, from the ReapUnservedBodies sweep that already reaps pending
// on the same ticker.
func (e *Engine) reapSeenBlocksLocked(now time.Time) {
	for id, at := range e.seenBlocks {
		if now.Sub(at) >= SeenBlockTTL {
			delete(e.seenBlocks, id)
		}
	}
}

// ReapUnservedBodies charges ScoreUnservedBody to every peer whose announced
// block has gone unserved past PendingBodyTimeout, and forgets the entry
// either way.
//
// **Forgetting means both halves of the announcement, not just `pending`.**
// The reap used to clear `pending[id]` and leave `seenBlocks[id]`
// standing, and those two facts are exactly what OnBlock's dedup gate reads:
// `seen && !waiting`. The moment the window elapsed the gate went true and
// stayed true, so the *first* gossip delivery of that body — the honest
// slow-link case §9 rule 5's window constraint exists for, "a peer honestly
// serving a large block over a slow link must not be mistaken for one that
// will not serve at all" — came back CostDeduped and the block was thrown
// away. The slow peer was penalised twice: once in score, and once by having
// its work discarded. So the charging branch below deletes the seen entry too,
// and the announcement is fully forgotten rather than half-forgotten.
//
// This is the third instance of one rule, not a new one: the future-dated drop
// and the key-epoch budget refusal both deliberately keep the id OUT of
// `seenBlocks` so that a refusal to spend now does not become a permanent
// rejection wearing a cache's clothes. The reap is the same shape and now
// reads the same way.
//
// **Only the charging branch.** A block that is already canonical when the
// window elapses is uncharged here (rule 5 constraint 3) and keeps its seen
// entry: deduping a body the chain already holds is what the gate is for. Nor
// is the gate itself loosened — letting any body through whenever the chain
// does not hold the block would let a peer replay bodies of unapplied blocks
// into the decode and PoW path over and over, the asymmetric-cost surface the
// gate bounds, and the mirror of decoding an unsolicited body before any work
// check.
//
// The cost is bounded and self-limiting: a re-announcement of a reaped id is
// processed as new, which is at most one extra announce-processing per id per
// window and creates a fresh obligation that can be charged again — charge
// once per window, which is what rule 5 asks for. An announcer that keeps
// announcing and keeps not serving keeps paying ScoreUnservedBody every cycle.
//
// wire.md §9 rule 5 is what requires the score: "a peer that advertises
// headers it will not back MUST be scored down." That was enforced on the
// sync path (SyncPenalty) and nowhere on gossip — PendingBodies existed for
// exactly this and had no caller, so the map only grew: written on every
// announcement, deleted only when a body actually arrived.
//
// Forgetting the entry regardless of outcome is what bounds the map; scoring
// only once per entry, at the first reap that finds it late, is what stops a
// single slow response being charged over and over for as long as this
// reaper keeps running.
//
// A block that arrived by some other route — sync answers no announcement and
// never touches this map, whichever connection it ran over — is not charged:
// the peer is not at fault for a body this node no longer needs, the same
// reasoning ErrWrongParent and the orphan-window refusals apply elsewhere in
// this file.
//
// **A multi-chunk transfer this node refused of its own accord is still
// charged, and that is a decision rather than an oversight.**
// OnBlockChunk refuses three ways that are this node's doing rather than the
// sender's — a chunk continuing no transfer, the per-peer eviction, the
// reassembly byte budget — and none of them scores, which is the whole of what
// wire.md §5.1 requires: it forbids penalising a peer *for a chunk*, and those
// three paths return Score 0. The charge here is for the *announcement*, a
// different object, and §9 rule 5 is deliberately narrow about what answers
// one: "a body that arrives answers the announcement". An evicted transfer
// produced no body, and the single receiver-caused exemption rule 5 grants —
// a block already canonical when the window elapses — is checked above and is
// not this. The two rules are not in tension; they are about different events.
//
// The tempting fix is to clear the entry on those three paths, and every
// version of it is an evasion rather than a fix, because **the condition that
// would mint the excuse is one the announcer arranges**:
//
//   - `BlockChunk.ID` is read off the wire and cross-checked against nothing
//     there, so one frame naming the announcer's own id trips
//     ErrNoSuchTransfer at zero cost.
//   - `pending` is keyed by block id *alone*, with no peer in the key, so an
//     unscoped delete lets any peer cancel any other peer's debt — including
//     an honest peer's, which suppresses the rule rather than refining it.
//   - scoping the delete to `pending[id].peerAddr` closes that third-party
//     case and closes nothing else: in the self-cancel case the announcer *is*
//     that peer and the id *is* its own announcement.
//   - the eviction victim is ordered by `started`, which follows the order
//     that same peer opened its transfers in, so a peer picks which of its own
//     ids this node evicts — five frames, no other peer involved.
//   - the reassembly byte budget is global, and the connection set alone
//     multiplies past it: socketBound is 48 sockets (maxConnections, the C of
//     the reassembly-bounds note above, MaxInbound + 2 x MaxOutbound) ×
//     MaxTransfersPerPeer × BlockChunkBytes ≈ 768 MiB against a 256 MiB
//     budget, so saturation is a state a peer population arranges on demand
//     rather than one it happens to meet. (tableBound, 64 × 4 × 4 MiB ≈ 1 GiB,
//     is still the larger figure — it holds while maxConnections <=
//     MaxPartialTransfers, which TestReassemblyMagnitudeRelationsHold asserts
//     rather than leaving to the next reviewer — but the reachable one is what
//     settles this, the same discipline the reassembly-bounds note above
//     applies.)
//
// So there is no key here an attacker cannot name *or arrange*, which is the
// property that matters — the finding asked for a record "an attacker cannot
// name", and naming was never the binding constraint. A record keyed on the
// announced id would additionally be per-announcement state a hostile peer
// grows, which §9 rule 8 requires be bounded by count and by bytes, bought to
// obtain an excuse that does not work.
//
// The second instinct, once clearing the entry is seen to be an evasion, is to
// **re-request** the evicted or refused transfer instead — no excuse minted,
// the honest peer gets another chance. It does not survive either, and the
// reason is structural rather than a judgement call:
//
//   - Verdict carries one Reply. On the eviction path the reply slot is
//     already owed to the chunk in hand — the transfer that just displaced the
//     victim, whose successor must be requested or that transfer stalls too —
//     so re-requesting the victim means dropping a request this node needs,
//     and trading one stalled transfer for another is not a fix. Emitting both
//     would mean a second reply channel on the path whose contract is one
//     reply per message.
//   - On the byte-budget path the slot is free, and the request is worse for
//     being possible: the refusal fires *because* this node is at
//     MaxReassemblyBytes, so the re-request asks a peer to resend the bytes
//     that do not fit, from chunk 0, into the saturation that rejected them.
//   - Unbounded, either becomes a pump the attacker drives: chunk 0 for A,
//     chunk 0 for B, evict A, request A, and so on for one request per chunk,
//     indefinitely. A once-per-announcement bound would stop the pump, but it
//     stops nothing about the two objections above.
//
// The third instinct is to attack the eviction rather than the charge: make
// the victim search **skip transfers whose id is still in `pending`**, so that
// a solicited transfer is never the one this node throws away. It is the most
// appealing of the three, because unlike the others it mints no excuse at all
// — it changes which transfer dies, not who is charged — and it was proposed
// against this note. It does not work, and the reason is arithmetic rather
// than adversarial: **the false positive is conserved.**
//
// Past the per-peer bound one of the peer's transfers has to go, and if every
// resident one is pending-backed there is nothing left to prefer. The gate can
// only reorder the casualty: today the oldest is evicted, under the gate the
// *newest* is refused admission. Measured both ways with one peer answering
// MaxTransfersPerPeer+1 of this node's own get-blocks — every id solicited,
// so every id in `pending` — the peer ends holding 4 transfers and owing the
// same charges under each. Identical outcome, different victim.
//
// It is worse than neutral on a second count. A pending entry lives for
// PendingBodyTimeout, so the gate makes a peer's buffers unevictable for a
// full minute where the per-peer bound recycles them now. That is socketBound,
// 48 sockets × MaxTransfersPerPeer × BlockChunkBytes ≈ 768 MiB of pinned
// demand against a 256 MiB budget, which does not vanish — it moves the
// refusal off the
// per-peer path, where it costs one peer one transfer, and onto the global
// byte budget, where it costs *other* peers theirs. Trading a local false
// positive for a cross-peer one is the wrong direction.
//
// unservedbody_evasion_internal_test.go holds one test per evasion above and
// fails if any future change makes one of them succeed. Its per-peer eviction
// test guards its own setup — it fails loudly if the announced transfer is not
// evicted, rather than passing vacuously — so a future gate of this shape
// shows up as an unreached branch and not as a green suite.
//
// The addresses charged are returned so that the caller can also charge the
// *identity* behind them, which this engine cannot do itself: it is handed a
// connection address and never a public key. Every other ingress path scores
// both tallies — Handle adjusts the address and Node.serve adjusts the key
// beside it — and a penalty that moved only the address-keyed half
// would be shed by reconnecting on a fresh ephemeral port, which is the exact
// hole identity-keyed scoring closed everywhere else.
func (e *Engine) ReapUnservedBodies(now time.Time) []string {
	e.mu.Lock()
	var late []struct {
		id   types.Hash
		peer string
	}
	for id, p := range e.pending {
		if now.Sub(p.announced) < PendingBodyTimeout {
			continue
		}
		late = append(late, struct {
			id   types.Hash
			peer string
		}{id, p.peerAddr})
		delete(e.pending, id)
	}
	// The seen-set is aged on the same sweep that reaps pending: pending
	// is the announced-but-unserved window and this is the wider dedup window
	// over it, so one ticker maintains both. The cap on the insert path is the
	// hard bound; this keeps the honest steady state near the working set.
	e.reapSeenBlocksLocked(now)
	e.mu.Unlock()

	var charged []string
	var forget []types.Hash
	for _, s := range late {
		if _, err := e.Chain.CanonicalHeader(s.id); err == nil {
			continue
		}
		e.Peers.Adjust(s.peer, ScoreUnservedBody)
		charged = append(charged, s.peer)
		forget = append(forget, s.id)
	}
	if len(forget) > 0 {
		e.mu.Lock()
		for _, id := range forget {
			delete(e.seenBlocks, id)
		}
		e.mu.Unlock()
	}
	return charged
}

// countVerdict records what a finished verdict says, and is called once where
// a verdict leaves the engine — never where one is built.
//
// **That distinction is the whole fix for the miscounted verdicts, and it is
// not a style preference.** A counter maintained beside each `return` is only
// correct while every author of a new return remembers it, and this is what
// that costs: `Forwarded` missed the block-acceptance return from the day it
// was written, and the reorg-adoption return — spelled `Verdict{Forward:
// reorg.Adopted}` rather than `Forward: true` — was missed again by the first
// attempt to repair it. Each miss is invisible, because a counter that does not
// move looks exactly like a path that was not taken.
//
// Counting at the exit has no per-path obligation to forget. However a verdict
// was constructed, whatever it was spelled, if it leaves with Forward set it is
// counted; a new forwarding path added tomorrow is counted by code nobody has
// to remember to write.
//
// `Score` has always been applied this way — see Handle, and the note in
// ReleaseWithheld explaining why that second exit must repeat it. Forwarded is
// simply the sibling field of the same struct, finally read at the same place.
func (e *Engine) countVerdict(v Verdict) {
	if !v.Forward {
		return
	}
	e.mu.Lock()
	e.Forwarded++
	e.mu.Unlock()
}

// certRoot recomputes the certificate root from an announced exemplar list.
//
// An announcement whose exemplar hashes do not produce the root its header
// commits to is describing a block that does not exist, which is checkable
// from the announcement alone — no bodies, no state.
func certRoot(exemplars []types.Hash, p *params.Params) types.Hash {
	return ssz.ListRoot(exemplars, p.CertListCapacity)
}
