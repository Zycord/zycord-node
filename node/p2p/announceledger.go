package p2p

import (
	"time"

	"zycord/core/types"
)

// The announced-body ledger: this node's memory of the bodies it has promised.
//
// **I8-H2.** An outbound block announcement is this node's own discretionary
// act, and it is a promise: the peer it reaches has no other way to learn the
// block exists, and the only thing it can do with the announcement is ask for
// the body. `docs/adversarial/I8-p2p.md` records what happens when the promise
// is broken by something that is not the asker's doing. The reply-byte ceiling
// in `replyBudgetExhausted` has a node-wide arm keyed on nothing, read first, so
// an attacker who floods this node with requests until that arm is spent makes
// this node refuse — silently, `refuseUnbudgeted` sends no reply — the very body
// it just announced to somebody else. Sixty seconds later the announced peer
// charges `ScoreUnservedBody`, and twelve blocks of that is a permanent
// address-keyed ban, at a victim the attacker never connected to.
//
// The rule this file implements, stated once:
//
//	An outbound block announcement reserves the right of each announced peer to
//	fetch that body once, and the node-wide ceiling cannot starve that lane.
//
// **Why the fix lives at the announcer and not at the scorer.** Four earlier
// candidates all taught the *victim* leniency — bound the charge, bound it for a
// tip-extension only, retry before charging, decay the score — and the record
// measures each one failing: the first disarms the ghost-flood ban that
// `ScoreUnservedBody` is the sole terminator of, the second covers 1 charge in
// 12 because the drain itself keeps the victim behind so the announcements
// arrive as orphans, the third meets the same refusal on every retry because a
// sustained drain holds the bucket empty, and the fourth cannot be tuned — any
// decay slow enough to leave the ghost-flood ban intact is far too slow to save
// an honest miner under a drain measured in block intervals. A wire
// answer ("budgeted, ask later") fails differently and worse: it is forgeable,
// so a ghost flooder claims it and escapes the ban outright. This ledger grants
// no leniency anywhere at the scorer. It changes only which requests **this
// node serves**, and it is not forgeable by anybody, because it is this node's
// record of its own sends and no peer can write to it.
//
// **The safety precondition, named because it is what makes the promise
// honourable.** Every outbound `KindBlockAnnounce` this node emits stands behind
// a successful `Chain.Apply`: the two `AnnounceBlock` call sites announce a
// block the caller has just applied (`cmd/zycordd` after `miner.MineOne`,
// `node/stratum` after `chain.Apply`), the gossip forward at `engine.go`'s
// tip-extension branch is returned only in the `err == nil` arm of `Apply`, the
// fork-choice forward carries `reorg.Adopted`, and the withhold release
// re-propagates a body this node accepted. So an announcement implies the body
// is held, and every entry recorded here is one this node can actually redeem.
// If a future change ever emits an announcement ahead of holding the body, the
// TTL below stops being belt-and-braces and becomes load-bearing.
//
// **What this deliberately does not do.** It does not touch a scoring rule, a
// wire kind, or anything in the consensus zone. It does not fix sync-path
// refusals — those are uncharged today (`syncdriver.go` exempts `ErrTransport`),
// so no ban rides them, but whoever makes a sync-path refusal chargeable must
// route it around budget refusals or through this same ledger, or this attack
// returns through the new door.

// announcedTTL is how long a promise stands.
//
// Two `PendingBodyTimeout`, stated against that constant rather than in block
// intervals — the interval inverts between devnet at 5 s and mainnet at 30 s,
// so "a few block intervals" would mean two different things on two networks
// while the window this must cover is the same window on both. The receiver
// charges at `PendingBodyTimeout` after its own announcement arrived, so one of
// these covers the whole window in which a charge can be earned, and the second
// is slack for the request's round trip and for the receiver's clock.
const announcedTTL = 2 * PendingBodyTimeout

// maxAnnouncedPerPeer bounds the ledger per peer.
//
// 32 against a ban distance of 10 charges: a peer would have to have 32 promises
// outstanding at once, all inside `announcedTTL`, before the oldest is evicted,
// and it takes 10 unserved bodies to ban. There is no announce storm to size
// against — this node emits an announcement only at chain-accept rate, and proof
// of work is the ticket for that — so the bound is a backstop on memory and not
// a rate limit. At roughly 48 bytes an entry the whole ledger is a few kilobytes
// against the 48-connection maximum.
const maxAnnouncedPerPeer = 32

// announcedRedemptionFactor caps how many bytes one promise may redeem, as a
// multiple of the announced body's own size.
//
// It is 2 and not 1, and the reason is the chunked regime rather than
// generosity. The budget gate runs once per chunk, so a promise consumed on
// first use would serve chunk 0 past the ceiling and then refuse every chunk
// after it — leaving the receiver holding a partial transfer it still gets
// charged for, which is strictly worse than today. So a promise persists by
// cumulative bytes instead: it covers the whole chunk sequence, with one body's
// worth of slack so that a transfer torn by a dropped connection can be retried
// once rather than being refused on the retry. Beyond that the promise is spent,
// which is what keeps redemption from becoming an unbounded re-request lane.
//
// Inert at every committed parameter set — `block_byte_limit_genesis` is
// 2,500,000 against a `BlockChunkBytes` of 4,194,304, so a body is one chunk and
// one redemption — and live after an era re-pin toward `block_byte_capacity`
// (8,000,000). The rule is written for both regimes because only one of them is
// testable today.
const announcedRedemptionFactor = 2

// announcedPromise is one outstanding promise: what was announced, when, and how
// much of it has been redeemed.
type announcedPromise struct {
	sentAt   time.Time
	redeemed int
	// cap is the byte ceiling on this promise, fixed when the first redemption
	// reads the body's real size. Zero until then, which is the "not yet
	// measured" state and not a ceiling of zero — see redeemAnnounced.
	cap int
}

// recordAnnounced enters a promise for one peer and one block id.
//
// Keyed on `payer` — the string `replyBudgetKey` produces, the authenticated
// identity where there is one and the connection address otherwise — because
// that is exactly what `OnGetBlock` is handed when the promise is redeemed. Any
// other key would make the two halves disagree about who a peer is, and the
// disagreement would be invisible: promises would simply never be found.
//
// Re-announcing an id to the same peer refreshes the timestamp and does not
// widen the promise: the existing entry keeps its redeemed total, so a peer
// cannot buy a second body's worth by inducing a second announcement. No
// production path re-announces the same id to the same peer today — the mining
// loop emits one announcement per mined block, the forward path stands behind a
// `seen && !waiting` dedup, and the withhold release fires once — so this arm is
// a property of the ledger rather than one of the caller's schedule.
func (e *Engine) recordAnnounced(payer string, id types.Hash, now time.Time) {
	if payer == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.announced == nil {
		e.announced = map[string]map[types.Hash]*announcedPromise{}
	}
	byID := e.announced[payer]
	if byID == nil {
		byID = map[types.Hash]*announcedPromise{}
	}
	if p := byID[id]; p != nil {
		p.sentAt = now
		return
	}
	// Expire before evicting, so that a peer whose bucket is full of dead
	// promises gets room without losing a live one. The bucket is written back
	// unconditionally below and is never deleted here — a bucket emptied by
	// expiry is about to receive this promise, and dropping the payer first
	// would leave the write landing in a map nothing holds a reference to.
	// Cross-payer expiry, which is where a payer key is actually forgotten,
	// lives in reapAnnouncedLocked.
	for old, p := range byID {
		if now.Sub(p.sentAt) > announcedTTL {
			delete(byID, old)
		}
	}
	if len(byID) >= maxAnnouncedPerPeer {
		e.evictOldestAnnouncedLocked(byID)
	}
	byID[id] = &announcedPromise{sentAt: now}
	e.announced[payer] = byID
}

// evictOldestAnnouncedLocked makes room by dropping this peer's oldest promise.
// The caller holds e.mu.
//
// Oldest and not arbitrary, because the promise nearest its TTL is the one
// closest to being worthless anyway: the receiver either asked inside its own
// `PendingBodyTimeout` or has already been charged, and the charge is what this
// ledger exists to prevent rather than to unwind. A map iteration would evict
// whichever entry Go's randomised order reached first, which is the newest
// promise as often as the oldest.
func (e *Engine) evictOldestAnnouncedLocked(byID map[types.Hash]*announcedPromise) {
	var oldest types.Hash
	var at time.Time
	found := false
	for id, p := range byID {
		if !found || p.sentAt.Before(at) {
			oldest, at, found = id, p.sentAt, true
		}
	}
	if found {
		delete(byID, oldest)
	}
}

// hasAnnouncedPromise reports whether a live promise stands for this peer and
// this block id. A map read and a clock comparison, nothing else — it is what
// the serve path consults BEFORE buying a chain read, so it must not itself buy
// anything. It does not mutate: an expired entry is left for redeemAnnounced or
// the next recordAnnounced to reap, because a read on the serve path that
// deletes is a write on the serve path.
func (e *Engine) hasAnnouncedPromise(payer string, id types.Hash) bool {
	if payer == "" {
		return false
	}
	now := e.wallClock()
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.announced[payer][id]
	return p != nil && now.Sub(p.sentAt) <= announcedTTL
}

// redeemAnnounced reports whether this peer may be served `n` bytes of `id`
// against a promise this node made it, and consumes that much of the promise.
//
// **The exemption is granted only where this node is the one that broke the
// promise**, which is why the caller applies it after the budget has already
// refused rather than instead of asking. A request that the budget would have
// served is served on the ordinary path and touches nothing here.
//
// `body` is the announced body's real size, read from this node's own store
// rather than claimed by the asker, and it fixes the promise's ceiling on first
// redemption. The asker names a chunk index and nothing else, so there is no
// number in the request this can be inflated by.
//
// **The lookup and the spend are two acquisitions of the lock, deliberately.**
// hasAnnouncedPromise runs before the chain read and this runs after it, so two
// concurrent requests against one promise can both pass the lookup. That is the
// same read-first / charge-last shape replyBudgetExhausted documents one screen
// up, and it is bounded the same way: the spend below is atomic under the lock
// and enforces the cap, so the overshoot is at most the replies in flight, which
// the connection set bounds and the sender does not. Holding the lock across the
// store read to close the window would put a disk read inside the mutex every
// other handler contends on, which is a worse trade than a bounded overshoot.
//
// The bytes are still debited to both budget layers by the caller. The overshoot
// is deliberate and it is bounded: the node-wide ceiling is a leaky bucket that
// drains at the refill rate, so an exempt reply cannot latch it, and the total
// exempt egress per window is at most one body per announced peer per announced
// block — which is exactly the quantity `connSet × BlockByteCapacity` was sized
// for in the first place. Leaving the bytes uncounted would instead hide this
// node's own egress from the counter that exists to make it visible.
func (e *Engine) redeemAnnounced(payer string, id types.Hash, body, n int) bool {
	if payer == "" || n <= 0 {
		return false
	}
	now := e.wallClock()
	e.mu.Lock()
	defer e.mu.Unlock()
	byID := e.announced[payer]
	if byID == nil {
		return false
	}
	p := byID[id]
	if p == nil {
		return false
	}
	if now.Sub(p.sentAt) > announcedTTL {
		delete(byID, id)
		if len(byID) == 0 {
			delete(e.announced, payer)
		}
		return false
	}
	if p.cap == 0 {
		// The cap is denominated in the bytes this node actually SENDS, which
		// is what `n` counts, so the body size is converted into that unit
		// rather than compared against it. A chunk frame carries the body plus
		// its own header — the id, the chunk index and the count — so a body
		// delivered as `total` chunks costs `body + total x blockChunkOverhead`
		// on the wire, and a cap set to the raw body size would refuse the tail
		// of the very first delivery. Getting this wrong is not a rounding
		// error: it is a promise that cannot be redeemed in full, which is the
		// defect this whole file exists to remove, reintroduced one layer down.
		total := ChunkCount(body)
		if total < 1 {
			total = 1
		}
		p.cap = (body + total*blockChunkOverhead) * announcedRedemptionFactor
	}
	if p.redeemed+n > p.cap {
		return false
	}
	p.redeemed += n
	return true
}

// reapAnnouncedLocked drops every promise past its TTL, across every payer.
//
// **This is what bounds the ledger's other dimension, and it is the one a
// per-peer cap does not reach.** `maxAnnouncedPerPeer` bounds the promises held
// for any one payer; the number of distinct payers is bounded by nothing at that
// level, because a `payer` is an authenticated identity or an ephemeral inbound
// address, and both are minted by the peer. There is deliberately no teardown
// hook: the key is `payer` and not the connection, so a peer whose identity
// outlives one socket keeps its promises across a reconnect — which is the
// behaviour the promise needs, since the receiver's `pending` entry and its
// sixty-second window survive a reconnect too. Expiry is therefore the whole
// bound in that direction, and it runs on the ticker that already reaps
// `pending` and `seenBlocks`, so the three announcement-shaped maps age on one
// clock instead of three.
//
// The caller holds e.mu.
func (e *Engine) reapAnnouncedLocked(now time.Time) {
	for payer, byID := range e.announced {
		for id, p := range byID {
			if now.Sub(p.sentAt) > announcedTTL {
				delete(byID, id)
			}
		}
		if len(byID) == 0 {
			delete(e.announced, payer)
		}
	}
}

// AnnouncedPromises reports how many promises stand for one payer. Test-facing
// and diagnostic: nothing on the message path reads it.
func (e *Engine) AnnouncedPromises(payer string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.announced[payer])
}
