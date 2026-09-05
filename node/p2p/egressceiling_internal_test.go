package p2p

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// What a peer's bytes are allowed to cost on the way out, in one place.
//
// The two served-reply kinds carry a per-identity byte budget. Four separate
// findings were filed against that budget afterwards — an unscored refusal, no
// aggregate ceiling, a budget shed through the identity store's eviction, and a
// served kind outside the node-wide layer — which is LAUNCH.md §4.3's
// threshold, so this file pins a rule rather than a site. The rule has three
// clauses and each one has its own separating input below:
//
//	refused  ⇔  nodeServed ≥ replyByteCeiling  ∨  ownServed ≥ replyByteBudget
//	scored   ⇔  refused  ∧  own  ∧  WorkRefusedKey(payer)
//
// so the terms are: the node-wide ceiling (which is also what answers the
// eviction shed), the per-identity budget (already pinned next door), the `own`
// disjunct that keeps a shared ceiling's refusal off a peer that did not cause
// it, and the workRefused conjunct, which is this path's answer and the announce
// path's, one primitive apart.

// churnFixture is budgetFixture with the two knobs these tests turn: a
// connection set, because replyByteCeiling is derived from it, and a fresh
// identity per call, because the missing ceiling is precisely the
// multiplication over identities that a per-identity budget does not see.
type churnFixture struct {
	*budgetFixture
	e *Engine
}

func newChurnFixture(t *testing.T, maxInbound, maxOutbound int) *churnFixture {
	t.Helper()
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	c := &churnFixture{budgetFixture: f, e: f.engine(t)}
	c.e.SetConnectionSet(maxInbound, maxOutbound)
	return c
}

// serveFreshIdentity drives get-headers from one never-seen identity until
// something refuses it, and reports what it was served and the largest single
// reply it saw. The second is measured rather than computed from
// MaxHeadersPerResponse x types.HeaderSize, because the overshoot every bound
// below allows is one real reply and not a derived one.
func (c *churnFixture) serveFreshIdentity(n byte) (bytes, maxReply uint64) {
	payer := replyBudgetKey(fmt.Sprintf("10.0.0.%d:51000", n), identity(n))
	req := headerRequest()
	for i := 0; i < 4096; i++ {
		v := c.e.OnGetHeaders(payer, req)
		if v.Reply == nil {
			return bytes, maxReply
		}
		got := uint64(len(v.Reply.Payload))
		bytes += got
		if got > maxReply {
			maxReply = got
		}
	}
	return bytes, maxReply
}

// TestTheAggregateServedIsBoundedOverIdentityChurnAndNotOnlyPerIdentity is
// the aggregate: a budget keyed on an identity bounds one identity, and a keypair is
// free, so the total was bounded by the socket and by nothing the protocol
// chose.
//
// The clock never moves, so nothing below can be refill. Every identity is
// fresh, which is the whole attack: hang up, mint a keypair, come back, buy
// another full window for the price of a TLS handshake. TestOneIdentityCannot-
// RebuyTheReplyBudgetByReconnecting next door asserts the *lower* bound on
// exactly this arrangement — eight identities must each get a window — and this
// is the upper bound the same arrangement never had.
func TestTheAggregateServedIsBoundedOverIdentityChurnAndNotOnlyPerIdentity(t *testing.T) {
	const set = 2
	c := newChurnFixture(t, set, 0)
	budget, _ := c.budget()
	ceiling := replyByteCeiling(set, budget)

	var total, reply uint64
	served := make([]uint64, 0, 8)
	for n := byte(1); n <= 8; n++ {
		got, max := c.serveFreshIdentity(n)
		served = append(served, got)
		total += got
		if max > reply {
			reply = max
		}
	}
	if reply == 0 {
		t.Fatal("no identity was served a single reply; nothing below measures a ceiling")
	}
	t.Logf("connection set %d, ceiling %d bytes (%d x %d): 8 fresh identities, "+
		"one frozen window, bought %d bytes in total; per identity %v",
		set, ceiling, set, budget, total, served)

	// The bound, and it is one reply wide because replyBudgetExhausted READS
	// before chargeReplyBytes WRITES — it has to, or an exhausted peer would buy
	// the chain read the refusal exists to save.
	if total > ceiling+reply {
		t.Errorf("8 fresh identities were served %d bytes against a node-wide "+
			"ceiling of %d (+%d, one reply of read-before-charge overshoot). "+
			"A budget keyed on an identity bounds an identity, and a keypair is "+
			"free, so without a layer keyed on nothing the aggregate is bounded "+
			"by the socket rather than by a number anyone picked",
			total, ceiling, reply)
	}
	// Anti-vacuity in the direction that matters: a ceiling that refuses
	// everything would also pass the line above.
	if total < budget {
		t.Fatalf("8 fresh identities were served only %d bytes, under one "+
			"identity's own budget of %d: the ceiling is refusing traffic the "+
			"per-identity budget would have served, so the bound above is not "+
			"about identity churn at all", total, budget)
	}
	// And the churn has to be doing something, or this is
	// TestOneIdentityIsServedAtMostOneWindowBudgetOfReplyBytes under a longer
	// name: at least one identity beyond the connection set must be served
	// nothing at all.
	starved := 0
	for _, got := range served {
		if got == 0 {
			starved++
		}
	}
	if starved == 0 {
		t.Errorf("every one of the 8 fresh identities was served something, so " +
			"no identity was ever refused by the node-wide layer and this test " +
			"exercises only the per-identity budget")
	}
}

// servedAWholeWindow reports whether an identity that drew `got` bytes in
// replies of at most `max` bytes each got its whole budget, given that `prior`
// identities were served ahead of it out of the same node-wide ceiling.
//
// **The tolerance is one reply PER IDENTITY SERVED, and it used to be one reply
// flat.** That is the whole content of this helper and it is a real property of
// the ceiling rather than a fudge for a test.
//
// The per-identity budget admits a reply that STARTS under budget, so an
// identity is served until it crosses its budget and therefore overruns by up
// to one reply. Those overruns come out of the shared node-wide ceiling and
// they ACCUMULATE: after `prior` identities the ceiling is short by up to
// `prior` replies, so the next identity stops up to `prior + 1` replies below
// its own budget while still having been served everything the ceiling could
// give it.
//
// The old form, `got + max >= budget`, allowed exactly one reply of slack and
// so encoded "the overrun never accumulates past one". That held at
// HeaderSize 228, where a 512-header reply is 116,740 bytes and one identity
// overruns by 55,060 — two identities' overruns still under one reply. It stops
// holding at HeaderSize 260, where the reply is 133,124 bytes and the overrun
// is 120,564: by the third identity the ceiling is short 241,128, which is more
// than a reply, and the third identity lands 145,684 below its budget having
// drawn everything there was.
//
// **So the test was measuring a rounding artefact of one particular header
// width, not the ceiling's liveness.** Nothing about the ceiling changed; the
// header grew 32 bytes for the commitment rule and the artefact grew with it.
// Stating the tolerance in replies-per-identity makes the assertion a claim
// about the ceiling — every identity in the connection set is served everything
// the ceiling can give — at any header width.
func servedAWholeWindow(got, max, budget uint64, prior int) bool {
	return got+max*uint64(prior+1) >= budget
}

// TestTheNodeWideCeilingRefusesNothingTheConnectionSetCouldReachAtAnInstant is
// the liveness half, and it is what keeps the ceiling from being a throttle.
//
// The claim is exact rather than approximate: the ceiling is the connection set
// multiplied by one identity's window, so exactly `set` identities are served
// their whole budget before the ceiling binds. Two rows at different sets,
// because a suite in which no row varies the connection set cannot tell a
// derivation from a constant that happens to equal it — the objection
// TestTheReplyBudgetIsSizedFromTheChainsOwnCapacityAndInterval makes about the
// budget itself.
func TestTheNodeWideCeilingRefusesNothingTheConnectionSetCouldReachAtAnInstant(t *testing.T) {
	for _, set := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("set=%d", set), func(t *testing.T) {
			c := newChurnFixture(t, set, 0)
			budget, _ := c.budget()

			full, any := 0, 0
			for n := byte(1); n <= byte(set)+2; n++ {
				got, max := c.serveFreshIdentity(n)
				if got > 0 {
					any++
				}
				// "Its whole budget" is budget minus at most one reply per
				// identity already served out of the shared ceiling — see
				// servedAWholeWindow for why the tolerance accumulates.
				if servedAWholeWindow(got, max, budget, full) {
					full++
				}
			}
			t.Logf("connection set %d: %d of %d fresh identities were served a "+
				"whole window, %d were served anything at all", set, full, set+2, any)

			if full != set {
				t.Errorf("connection set %d: %d identities were served a whole "+
					"window, want exactly %d. Fewer means the ceiling refuses an "+
					"arrangement of peers this node admits and could serve before "+
					"it existed; more means it is not derived from the set at all",
					set, full, set)
			}
		})
	}
}

// TestTheNodeWideEgressCeilingComesBackInOneWindow is the recovery property,
// and it is the one that had to be repaired by hand on the primitive next door.
//
// There the bucket was a multiple of the per-payer budget while the rate was
// not, so a drained ceiling took that multiple of periods to return — about 170
// days on mainnet, a one-way latch rather than a ceiling. Here recovery is one
// period at both layers by construction, because refilledServed credits a whole
// bucket per period at whatever size the bucket is. Driven rather than argued.
//
// **At a connection set above one, because at set = 1 the ceiling and one
// identity's budget are the same number and the property is unobservable.** That
// is not a hypothetical: a mutant crediting the refill against the per-identity
// budget instead of against the ceiling survived a version of this test pinned
// at set = 1, and what it implements is that latch exactly — a ceiling that
// comes back one identity's window per period takes `set` periods to return.
func TestTheNodeWideEgressCeilingComesBackInOneWindow(t *testing.T) {
	for _, set := range []int{1, 3} {
		t.Run(fmt.Sprintf("set=%d", set), func(t *testing.T) {
			c := newChurnFixture(t, set, 0)
			budget, period := c.budget()

			whole := func(first byte) (full int, total uint64) {
				for n := byte(0); n < byte(set); n++ {
					got, max := c.serveFreshIdentity(first + n)
					total += got
					if servedAWholeWindow(got, max, budget, full) {
						full++
					}
				}
				return full, total
			}

			// Drain the whole ceiling, and confirm it is drained.
			drainedFull, drained := whole(1)
			blocked, _ := c.serveFreshIdentity(90)
			// One period, and the WHOLE ceiling must be back — not one identity's
			// share of it.
			c.clock += period
			backFull, back := whole(20)

			t.Logf("connection set %d: %d identities drew %d bytes and filled the "+
				"ceiling (%d whole windows), a further identity drew %d, then one "+
				"period (%d s) later %d identities drew %d bytes (%d whole windows)",
				set, set, drained, drainedFull, blocked, period, set, back, backFull)

			if blocked != 0 {
				t.Fatalf("a further identity drew %d bytes inside the drained window, "+
					"so the ceiling never bound and the refill below measures nothing",
					blocked)
			}
			if drainedFull != set {
				t.Fatalf("only %d of %d identities drew a whole window before the "+
					"ceiling bound; the ceiling was not full when the clock moved", drainedFull, set)
			}
			if backFull != set {
				t.Errorf("one whole period after the ceiling was drained, only %d of "+
					"%d identities could draw a window, want all %d. A ceiling that "+
					"credits one identity's share per period takes %d periods to "+
					"return, which is a one-way latch rather than a bound (pass one)",
					backFull, set, set, set)
			}
		})
	}
}

// TestTheNodeWideCeilingIsExhaustedAtExactlyTheCeiling pins the comparison
// itself, which nothing driven through the handler can reach.
//
// A served reply is 116,740 bytes against a ceiling of 8,000,000, so a node
// driven by real requests lands at 8,055,060 and never on the boundary: `>=`
// and `>` are indistinguishable there, and a mutant that weakened one to the
// other survived the whole driven grid. TestAPeerServedExactlyItsBudgetIs-
// Exhausted is the same row for the layer below and exists for the same reason.
func TestTheNodeWideCeilingIsExhaustedAtExactlyTheCeiling(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), 1)
	budget, period := f.budget()
	ceiling := replyByteCeiling(1, budget)

	for _, row := range []struct {
		charge uint64
		want   bool
	}{
		{charge: ceiling - 1, want: false},
		{charge: ceiling, want: true},
		{charge: ceiling + 1, want: true},
	} {
		e := f.engine(t)
		e.SetConnectionSet(1, 0)
		e.chargeNodeServedBytes(row.charge, budget, period, f.clock)
		if got := e.nodeServedBytesExhausted(budget, period, f.clock); got != row.want {
			t.Errorf("served exactly %d of a %d-byte ceiling: exhausted=%v, want %v. "+
				"A peer served its whole ceiling has been served its whole ceiling; "+
				"the boundary is the one input no driven test reaches",
				row.charge, ceiling, got, row.want)
		}
	}
}

// TestTheCeilingsReadAndItsChargeCreditTheSameBucket pins the one argument the
// two halves of this layer could disagree about, and it is the argument a
// first review pass found wrong on the primitive next door.
//
// nodeServedBytesExhausted and chargeNodeServedBytes both refill through
// refilledServed, and a refill credits one whole bucket per period. If the read
// credits the per-identity budget while the charge credits the ceiling, the two
// disagree about how much time has bought — which at a connection set of `set`
// is a factor of `set`, in the direction that keeps a drained ceiling refusing.
//
// **No traffic reaches the input that separates them**, and that is stated
// rather than worked around: the charge stops at the ceiling, so the level never
// exceeds it by more than the replies in flight, and below `ceiling + budget`
// the two credits give the same answer to the same comparison. A mutant that
// swapped the read's bucket survived the whole driven grid for exactly that
// reason. The arithmetic is pinned here at the level a driven test cannot plant,
// because "unreachable" is a property of today's callers and the equality is a
// property of the layer.
func TestTheCeilingsReadAndItsChargeCreditTheSameBucket(t *testing.T) {
	const set = 3
	f := newBudgetFixture(t, spec.Devnet(), 1)
	budget, period := f.budget()
	ceiling := replyByteCeiling(set, budget)

	e := f.engine(t)
	e.SetConnectionSet(set, 0)
	e.chargeNodeServedBytes(ceiling+budget, budget, period, f.clock)
	if !e.nodeServedBytesExhausted(budget, period, f.clock) {
		t.Fatalf("a level of %d against a ceiling of %d does not read as exhausted; "+
			"nothing below measures a refill", ceiling+budget, ceiling)
	}

	// One period credits one whole CEILING, leaving one budget outstanding
	// against a ceiling of three, so the node is servable again.
	if e.nodeServedBytesExhausted(budget, period, f.clock+period) {
		t.Errorf("one period after a level of %d (ceiling + one identity's window) "+
			"the ceiling still reads as exhausted. One period credits one whole "+
			"ceiling, not one identity's share of it; crediting the share is the "+
			"latch measured at about 170 days on the primitive next door",
			ceiling+budget)
	}
	// And two periods clear it entirely, which is what says the arm above is the
	// partial refill rather than the whole-bucket one.
	if e.nodeServedBytesExhausted(budget, period, f.clock+2*period) {
		t.Error("two periods did not clear a level of one ceiling plus one window")
	}
}

// TestSheddingThePerIdentityBudgetDoesNotShedTheNodeWideCeiling covers the
// budget shed through the identity store's own eviction.
//
// The per-identity budget lives on PeerStore.identityEntry, which is bounded at
// MaxIdentities and evicts, and a served-only entry sits at score zero and is
// therefore what the store gives up first. So an attacker can shed its own spent
// window by making its entry the least worthy in a full store, priced
// at roughly MaxIdentities handshakes to fill and as many again to walk the
// eviction order round to its own entry.
//
// What is driven here is stronger than any eviction an attacker can buy: the
// whole store is replaced, so every identity's budget is not merely shed but
// erased. If the aggregate still holds after that, it holds after any eviction,
// because the ceiling is the one layer with no table to evict from.
func TestSheddingThePerIdentityBudgetDoesNotShedTheNodeWideCeiling(t *testing.T) {
	c := newChurnFixture(t, 1, 0)
	budget, _ := c.budget()

	before, _ := c.serveFreshIdentity(1)
	if before == 0 {
		t.Fatal("the first identity was served nothing; nothing below measures a shed")
	}
	// The shed, at its widest.
	fresh, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	c.e.Peers = fresh
	after, _ := c.serveFreshIdentity(1)

	t.Logf("connection set 1 (ceiling %d): one identity drew %d bytes, then the "+
		"entire identity store was discarded and the same identity drew %d more",
		budget, before, after)

	if after != 0 {
		t.Errorf("discarding the whole identity store bought %d further bytes "+
			"inside one window. A budget that can be shed through the store it "+
			"lives in is a budget the sender re-buys, and only a layer keyed on "+
			"nothing refuses that", after)
	}
}

// TestTheNodeWideCeilingHoldsUnderConcurrentServes drives the ceiling from as
// many goroutines as this node has connection slots, which is how it is reached
// in production: Node.serve runs one loop per connection and they all charge the
// same counter.
//
// The bound it asserts is the one the code claims and not a tighter one. The
// ceiling is read before the reply is charged — it has to be, or an exhausted
// peer would buy the chain read the refusal exists to save — so serves racing
// here can overshoot by at most one reply each, bounded by the number in flight,
// which is bounded by the connection set and never by the sender. Asserting no
// overshoot at all would be asserting a critical section this code deliberately
// does not have; asserting an unbounded one would assert nothing.
func TestTheNodeWideCeilingHoldsUnderConcurrentServes(t *testing.T) {
	const set, servers = 2, 8
	c := newChurnFixture(t, set, 0)
	budget, _ := c.budget()
	ceiling := replyByteCeiling(set, budget)

	var total, maxReply uint64
	var mu sync.Mutex
	var wg sync.WaitGroup
	req := headerRequest()
	for n := 0; n < servers; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			payer := replyBudgetKey(fmt.Sprintf("10.1.0.%d:51000", n), identity(byte(100+n)))
			for i := 0; i < 4096; i++ {
				v := c.e.OnGetHeaders(payer, req)
				if v.Reply == nil {
					return
				}
				got := uint64(len(v.Reply.Payload))
				mu.Lock()
				total += got
				if got > maxReply {
					maxReply = got
				}
				mu.Unlock()
			}
		}(n)
	}
	wg.Wait()

	slack := uint64(servers) * maxReply
	t.Logf("%d concurrent servers against a ceiling of %d bytes: %d served, "+
		"overshoot %d against an in-flight allowance of %d x %d",
		servers, ceiling, total, int64(total)-int64(ceiling), servers, maxReply)

	if maxReply == 0 {
		t.Fatal("nothing was served at all; this test measures no ceiling")
	}
	if total > ceiling+slack {
		t.Errorf("%d concurrent servers were served %d bytes against a ceiling of "+
			"%d, past the %d bytes of read-before-charge overshoot the connection "+
			"set can hold in flight", servers, total, ceiling, slack)
	}
	if total < budget {
		t.Errorf("%d concurrent servers were served %d bytes in total, under one "+
			"identity's own budget of %d: the ceiling is throttling rather than "+
			"bounding", servers, total, budget)
	}
}

// armWorkRefused makes this node's own work check refuse one announcement from
// payer, which is what sets identityEntry.workRefused.
//
// Through the real path and not through MarkWorkRefusedKey directly, because
// what the guard below claims is that the bit an honest peer cannot acquire is
// the bit that arms the score — and a test that plants the bit proves the
// second half while assuming the first.
func armWorkRefused(t *testing.T, f *budgetFixture, e *Engine, peerAddr string, key ed25519.PublicKey) string {
	t.Helper()
	payer := replyBudgetKey(peerAddr, key)
	p := f.chain.Params()
	height := f.chain.Height() + 1
	hd := types.Header{
		Version: types.HeaderVersion,
		Height:  height,
		// A parent this node does not hold, so that the check that refuses this
		// header is the WORK check and nothing else.
		//
		// The announce path has a target re-derivation on the tip-
		// extension branch: an announcement naming this node's own tip must
		// declare the target the difficulty rule gives, and this one declares 1.
		// Left as the tip it would be refused there, one line ahead of
		// work.Check — same ScoreInvalidMessage, so the score assertion below
		// would still pass, and the workRefused bit would silently never be set.
		// The bit is what every row of this test reads, and the second assertion
		// below is what caught it.
		ParentID: types.Hash{0xab},
		Time:     f.clock,
		// A target no digest meets, which is what work.Check refuses. The
		// height is the tip's own successor, so the key epoch is one this node
		// is already working in and the key-epoch price never intervenes.
		Target:   u256.FromUint64(1),
		CertRoot: certRoot(nil, p),
		PoW:      types.PoWSeal{Nonce: 1 << 31, SeedEpoch: pow.SeedEpochFor(height, p)},
	}
	v := e.OnBlockAnnounceFrom(peerAddr, payer, BlockAnnounce{Header: hd}.MarshalAnnounce())
	if v.Score != ScoreInvalidMessage {
		t.Fatalf("the arming announcement was scored %d, want ScoreInvalidMessage (%d): "+
			"err=%v. It has to be the WORK CHECK that refuses it, or the bit under "+
			"test is not set and every row below is vacuous",
			v.Score, ScoreInvalidMessage, v.Err)
	}
	if !e.Peers.WorkRefusedKey(payer) {
		t.Fatal("work.Check refused the announcement and the workRefused bit is still clear")
	}
	return payer
}

// TestAnOverBudgetRefusalIsScoredOnlyForAnIdentityTheWorkCheckHasAlreadyRefused
// is the unscored-refusal half.
//
// wire.md §10.4 requires a node to bound "the rate at which a peer may issue
// requests and the total bytes it can make this node send in reply", and the
// byte budget discharged the second conjunct only: the refusal was priced Budgeted and
// carried no score, and CostClass says a negative score is the only class that
// terminates a flood of distinct messages. So a peer past its budget could ask
// forever, be answered nothing, and accumulate nothing.
//
// Two rows and not one, because the fix has to be the conjunct rather than the
// score. Scoring every over-budget refusal is I7-H4's revert from the serving
// end: the budget is sized at the sustained-bandwidth floor, so an honest peer
// on a FASTER link reaches it by bulk-syncing rather than by misbehaving, and at
// ScoreExcessRequest it would be banned in twenty frames.
//
// And both priced kinds, not one. The budget is a single allowance across the
// two (TestTheBudgetIsOneAllowanceAcrossBothPricedKinds), but the conjunct is
// written at each call site, so a grid that floods only get-headers leaves the
// get-block site unmeasured — a mutant that dropped it there was what said so.
func TestAnOverBudgetRefusalIsScoredOnlyForAnIdentityTheWorkCheckHasAlreadyRefused(t *testing.T) {
	for _, kind := range []struct {
		name string
		ask  func(e *Engine, f *budgetFixture, payer string) Verdict
	}{
		{"get-headers", func(e *Engine, _ *budgetFixture, payer string) Verdict {
			return e.OnGetHeaders(payer, headerRequest())
		}},
		{"get-block", func(e *Engine, f *budgetFixture, payer string) Verdict {
			return e.OnGetBlock(payer, GetBlock{ID: f.ids[0], Chunk: 0}.MarshalGetBlock())
		}},
	} {
		for _, row := range []struct {
			name   string
			caught bool
		}{
			{"an honest fast syncer", false},
			{"an identity the work check has already refused", true},
		} {
			t.Run(kind.name+"/"+row.name, func(t *testing.T) {
				f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
				e := f.engine(t)
				const addr = "10.9.0.4:51000"
				key := identity(4)
				payer := replyBudgetKey(addr, key)
				if row.caught {
					payer = armWorkRefused(t, f, e, addr, key)
				}

				// The budget is drained with get-headers whatever the flood is,
				// because one allowance covers both kinds and get-headers reaches
				// it in sixty-nine replies rather than in tens of thousands.
				served, _, first := serveUntilRefused(e, payer, 4096)
				if first.Err == nil || !errors.Is(first.Err, ErrReplyBudget) {
					t.Fatalf("after %d served replies the refusal was %v, not ErrReplyBudget; "+
						"nothing below is about the budget", served, first.Err)
				}
				// Past the budget, and long past it: this is the flood the score is
				// supposed to terminate.
				const flood = 40
				refusals, scored := 0, 0
				banned := 0
				for n := 0; n < flood; n++ {
					v := kind.ask(e, f, payer)
					if v.Reply != nil {
						t.Fatalf("request %d past an exhausted budget was SERVED", n)
					}
					refusals++
					if v.Score != 0 {
						if v.Score != ScoreExcessRequest {
							t.Fatalf("an over-budget refusal was scored %d, want ScoreExcessRequest (%d)",
								v.Score, ScoreExcessRequest)
						}
						scored++
						e.Peers.AdjustKey(key, v.Score)
					}
					if banned == 0 && e.Peers.BannedKey(key) {
						banned = refusals
					}
				}
				t.Logf("%s, %s: %d replies served, then %d refusals, %d of them scored, "+
					"banned after %d refusals (0 = never)",
					kind.name, row.name, served, refusals, scored, banned)

				if !row.caught {
					if scored != 0 {
						t.Errorf("%d of %d refusals were scored against a peer this node "+
							"has never caught. The budget is the sustained-bandwidth floor, "+
							"so an honest peer on a faster link reaches it by downloading; "+
							"scoring that is the guard I7-H4 reverted", scored, refusals)
					}
					if banned != 0 {
						t.Errorf("an honest bulk syncer was banned after %d over-budget requests", banned)
					}
					return
				}
				if scored != refusals {
					t.Errorf("only %d of %d refusals were scored for an identity whose "+
						"announcements the work check has already refused. An identity "+
						"already caught keeps no amnesty (the same conjunct one primitive over)",
						scored, refusals)
				}
				// The count, not merely the ban: a flood that ends somewhere and one
				// that ends at the derived number are both "banned", and only the
				// second says the refusal is charged at ScoreExcessRequest.
				want := -ScoreBanThreshold / -ScoreExcessRequest
				if banned != want {
					t.Errorf("banned after %d over-budget requests, want exactly %d "+
						"(the threshold %d at %d each). A different count means the "+
						"refusal is charged at some other rate",
						banned, want, -ScoreBanThreshold, -ScoreExcessRequest)
				}
			})
		}
	}
}

// TestARefusalByTheSharedCeilingIsNeverScored is the `own` disjunct, and it is
// the input that separates the two layers in the scoring rule rather than in
// the refusing rule.
//
// The node-wide ceiling is shared on purpose — it has to be, or it would be
// keyed on something and the aggregate would still be unbounded — so a refusal
// there can be caused by traffic the refused peer never sent. Charging a peer
// for another peer's flood is the shape of the guard that was reverted rather
// than a repair of it, so the score follows the payer's OWN exhausted budget
// and nothing else.
//
// Without the `own` disjunct this row is scored and banned; without the
// workRefused conjunct the row above is; and neither test alone separates them.
func TestARefusalByTheSharedCeilingIsNeverScored(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	e.SetConnectionSet(1, 0)

	// A caught identity that has spent NOTHING of its own budget.
	const addr = "10.9.0.7:51000"
	key := identity(7)
	victim := armWorkRefused(t, f, e, addr, key)

	// Somebody else drains the whole node-wide ceiling.
	flooder := replyBudgetKey("10.9.0.8:51000", identity(8))
	drained, drainedBytes, _ := serveUntilRefused(e, flooder, 4096)

	refusals, scored := 0, 0
	req := headerRequest()
	for n := 0; n < 30; n++ {
		v := e.OnGetHeaders(victim, req)
		if v.Reply != nil {
			t.Fatalf("the ceiling was drained by %d replies (%d bytes) and request "+
				"%d was still served; this test measures nothing", drained, drainedBytes, n)
		}
		refusals++
		if v.Score != 0 {
			scored++
			e.Peers.AdjustKey(key, v.Score)
		}
	}
	t.Logf("connection set 1: another identity drew %d bytes and drained the "+
		"ceiling; a caught identity that has spent none of its own budget was "+
		"refused %d times, %d of them scored, banned=%v",
		drainedBytes, refusals, scored, e.Peers.BannedKey(key))

	if scored != 0 {
		t.Errorf("%d of %d refusals by the SHARED ceiling were scored against an "+
			"identity that has spent none of its own budget. The ceiling is keyed "+
			"on nothing, so a refusal there is not attributable and must not be "+
			"charged to whoever happens to ask next", scored, refusals)
	}
	if e.Peers.BannedKey(key) {
		t.Error("a peer was banned for another peer's flood against the shared ceiling")
	}
}

// TestTheCeilingIsDerivedFromTheConnectionSetAndTheChainsOwnBudget varies each
// input the ceiling is a function of and requires the ceiling to move with it,
// including both sides of the clamp and the at-or-below-zero default.
//
// A ceiling that happened to equal the right number on the defaults and ignored
// its arguments would pass every driven test above, because every one of them
// runs on one parameter set.
func TestTheCeilingIsDerivedFromTheConnectionSetAndTheChainsOwnBudget(t *testing.T) {
	base, _ := replyByteBudget(spec.Devnet())
	if base == 0 {
		t.Fatal("devnet has no reply budget; every row below is vacuous")
	}
	defaultSet := uint64(DefaultMaxInbound + 2*DefaultMaxOutbound)

	for _, row := range []struct {
		set    int
		budget uint64
		want   uint64
	}{
		{set: -5, budget: base, want: defaultSet * base},
		{set: 0, budget: base, want: defaultSet * base},
		{set: 1, budget: base, want: base},
		{set: 3, budget: base, want: 3 * base},
		{set: 48, budget: base, want: 48 * base},
		{set: 288, budget: base, want: 288 * base},
		// The clamp, from both sides, so it is a bound rather than a constant.
		{set: maxUnheldConnectionSet, budget: base, want: maxUnheldConnectionSet * base},
		{set: maxUnheldConnectionSet + 1, budget: base, want: maxUnheldConnectionSet * base},
		// The budget is the other factor, so the ceiling moves with the chain's
		// own capacity and not only with the operator's configuration.
		{set: 4, budget: 2 * base, want: 8 * base},
		// A disabled budget disables the ceiling rather than refusing everything,
		// which is replyByteBudget's own direction.
		{set: 4, budget: 0, want: 0},
	} {
		if got := replyByteCeiling(row.set, row.budget); got != row.want {
			t.Errorf("replyByteCeiling(%d, %d) = %d, want %d", row.set, row.budget, got, row.want)
		}
	}
}

// TestAZeroReplyByteCeilingIsAlwaysAZeroPeriod is why the two node-wide sites
// guard on `period == 0` alone.
//
// Both of them once read `ceiling == 0 || period == 0`, and a mutant deleting
// the first clause from either was not killed — because the clause is a second
// spelling of the second and not a second condition. This test is the proof of
// that, done mechanically rather than by reading the two functions: it sweeps
// every input replyByteBudget and replyByteCeiling take together and requires
// the pair (ceiling == 0, period != 0) never to occur.
//
// Read it as the postcondition of the composition, not of either half:
// replyByteBudget hands back (0, 0) together or a budget of at least one, and
// replyByteCeiling's set is at least one after the default and the clamp, so the
// product is zero exactly when the budget is — and the budget is zero exactly
// when the period is.
//
// The sweep's upper end is not arbitrary, and the second assertion below is what
// makes the domain a checked claim rather than a stated one: the product could
// wrap to zero at a budget beyond 2^64 / maxUnheldConnectionSet, so the test
// requires the transport bound on BlockByteCapacity — MaxBlockChunks x
// BlockChunkBytes, the pair TestBlockByteCapacityFitsChunkedTransfer holds
// together — to leave that wrap out of reach. A capacity above it is not a
// parameter set a node can load, because the block it describes cannot be
// transmitted.
func TestAZeroReplyByteCeilingIsAlwaysAZeroPeriod(t *testing.T) {
	// The domain, checked. Every loadable budget is at or below the chunked
	// transfer bound, and every set is at or below the clamp, so the product
	// below cannot wrap — which is the one way a non-zero budget could have
	// produced a zero ceiling.
	maxLoadableBudget := uint64(MaxBlockChunks * BlockChunkBytes)
	if maxLoadableBudget == 0 || uint64(maxUnheldConnectionSet) > math.MaxUint64/maxLoadableBudget {
		t.Fatalf("the ceiling can wrap inside its own domain: %d x %d overflows",
			maxUnheldConnectionSet, maxLoadableBudget)
	}

	capacities := []int{
		math.MinInt, -8_000_000, -1, 0, 1, 2, 8_000_000, int(maxLoadableBudget),
	}
	periods := []uint64{0, 1, 5, 30, 180, math.MaxUint64}
	sets := []int{
		math.MinInt, -1, 0, 1, 2, 3, 48,
		maxUnheldConnectionSet - 1, maxUnheldConnectionSet, maxUnheldConnectionSet + 1,
		math.MaxInt,
	}

	sawZeroCeiling, sawNonZeroCeiling := false, false
	for _, capacity := range capacities {
		for _, secs := range periods {
			p := spec.Devnet()
			p.BlockByteCapacity = capacity
			p.TargetBlockSeconds = secs
			budget, period := replyByteBudget(p)
			for _, set := range sets {
				ceiling := replyByteCeiling(set, budget)
				if ceiling == 0 {
					sawZeroCeiling = true
				} else {
					sawNonZeroCeiling = true
				}
				if ceiling == 0 && period != 0 {
					t.Errorf("capacity=%d target_block_seconds=%d set=%d: ceiling 0 with period %d; "+
						"the deleted `ceiling == 0` clause would have separated this input",
						capacity, secs, set, period)
				}
			}
		}
	}
	// Without these the sweep could pass by never reaching either side.
	if !sawZeroCeiling || !sawNonZeroCeiling {
		t.Fatalf("the sweep is vacuous: zero ceiling seen %v, non-zero seen %v",
			sawZeroCeiling, sawNonZeroCeiling)
	}
}

// BenchmarkAnOverBudgetGetHeadersRefusal and BenchmarkAServedGetHeaders are the
// number to have written down rather than inferred: what one refused
// request costs this node against what the honest reply it replaces costs.
//
// They exist because "the refusal is cheaper than the answer" is the whole
// argument for leaving the request rate of an uncaught identity unbounded, and
// an argument of that shape is worth exactly as much as its measurement.
func BenchmarkAnOverBudgetGetHeadersRefusal(b *testing.B) {
	f := newBudgetFixture(b, spec.Devnet(), budgetChainHeight)
	e := f.engine(b)
	payer := replyBudgetKey("10.4.0.8:51000", identity(8))
	if _, _, v := serveUntilRefused(e, payer, 4096); v.Reply != nil {
		b.Fatal("the budget never refused; this benchmark times the wrong path")
	}
	req := headerRequest()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if v := e.OnGetHeaders(payer, req); v.Reply != nil {
			b.Fatal("served inside the refusal benchmark")
		}
	}
}

// BenchmarkAServedGetHeaders is the same handler on the path the refusal
// replaces. The peer store is detached and the connection set is the clamp, so
// neither layer of the budget binds inside the loop and what is timed is the
// answer: the chain read and the marshal.
func BenchmarkAServedGetHeaders(b *testing.B) {
	f := newBudgetFixture(b, spec.Devnet(), budgetChainHeight)
	e := f.engine(b)
	e.Peers = nil
	e.SetConnectionSet(maxUnheldConnectionSet, 0)
	payer := replyBudgetKey("10.4.0.9:51000", identity(9))
	req := headerRequest()
	probe := e.OnGetHeaders(payer, req)
	if probe.Reply == nil {
		b.Fatalf("refused before the loop: %v", probe.Err)
	}
	b.SetBytes(int64(len(probe.Reply.Payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if v := e.OnGetHeaders(payer, req); v.Reply == nil {
			b.Fatalf("refused inside the served benchmark: %v", v.Err)
		}
	}
}
