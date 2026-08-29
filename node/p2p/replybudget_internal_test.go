package p2p

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// budgetChainHeight is one height below MaxHeadersPerResponse, so that a
// get-headers request for MaxHeadersPerResponse is answered with exactly that
// many headers (genesis plus this many blocks) on every call.
//
// The size is chosen so one reply is large — 4 + MaxHeadersPerResponse ×
// types.HeaderSize bytes — because the number of requests these tests have to
// issue to reach the budget is BlockByteCapacity divided by that. A short chain
// would make every one of them sixty-eight times longer for no extra property.
const budgetChainHeight = MaxHeadersPerResponse - 1

// budgetFixture is a chain, a pool and an injectable clock the tests below
// share. The chain is read-only for every path they exercise, so one is built
// per test function and each arm gets a fresh Engine and a fresh PeerStore —
// which is what resets a budget, since the budget lives in the store.
type budgetFixture struct {
	p     *params.Params
	chain *chain.Chain
	pool  *mempool.Pool
	clock uint64
	ids   []types.Hash
}

// testing.TB and not *testing.T, so that the benchmarks in
// egressceiling_internal_test.go time the real handler over the real chain
// rather than over a second fixture written to be benchmarkable. Nothing here
// uses anything outside the TB interface.
func newBudgetFixture(t testing.TB, p *params.Params, height int) *budgetFixture {
	t.Helper()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	pool := mempool.New(p, mempool.DefaultPolicy())
	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{},
		Payout: [32]byte{0x02, 7, 7, 7},
		Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
	}
	f := &budgetFixture{p: p, chain: c, pool: pool}
	for i := 0; i < height; i++ {
		blk, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatal(err)
		}
		f.ids = append(f.ids, blk.Header.ID())
	}
	if got := c.Height(); got != uint64(height) {
		t.Fatalf("built a chain of height %d, want %d", got, height)
	}
	// Deliberately not zero and not a round multiple of any period under test:
	// refilledServed's first arm anchors an entry's clock at whatever "now"
	// reads, and a fixture that started at the unix epoch would make that arm
	// indistinguishable from the fall-through.
	f.clock = 1_700_000_017
	return f
}

// engine returns a fresh engine over the shared chain, with its own peer store
// and therefore its own budget state, reading this fixture's clock.
func (f *budgetFixture) engine(t testing.TB) *Engine {
	t.Helper()
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(f.chain, f.pool, peers, pow.Dev{}, "")
	e.Now = func() time.Time { return time.Unix(int64(f.clock), 0) }
	return e
}

// budget returns the two derived numbers under test, read off the chain the
// engine is serving rather than retyped.
func (f *budgetFixture) budget() (budget, period uint64) { return replyByteBudget(f.p) }

// headerRequest is the 12-byte frame the tests spend, and headerReplyBytes is
// what one costs this node to answer on this fixture. Measured by asking, not
// computed from MaxHeadersPerResponse × types.HeaderSize: the point of the
// unit is what the node actually sends.
func headerRequest() []byte {
	return GetHeaders{From: 0, Count: MaxHeadersPerResponse}.MarshalGetHeaders()
}

// identity returns a distinct 32-byte Ed25519-shaped key. The tests never
// verify a signature with it, and they must not: what is under test is that
// the budget follows this value across connections, not that TLS produced it.
func identity(n byte) ed25519.PublicKey {
	k := make([]byte, ed25519.PublicKeySize)
	k[0], k[31] = n, 0xA7
	return k
}

// serveUntilRefused drives get-headers at this payer until the budget refuses
// one, and reports how many were served, how many bytes they carried, and the
// refusing verdict. It stops at maxCalls to keep a broken budget from hanging
// the run rather than failing it.
func serveUntilRefused(e *Engine, payer string, maxCalls int) (served int, bytes uint64, v Verdict) {
	req := headerRequest()
	for i := 0; i < maxCalls; i++ {
		v = e.OnGetHeaders(payer, req)
		if v.Reply == nil {
			return served, bytes, v
		}
		served++
		bytes += uint64(len(v.Reply.Payload))
	}
	return served, bytes, Verdict{}
}

// TestOneIdentityIsServedAtMostOneWindowBudgetOfReplyBytes is the hostile half
// of the budget's acceptance: drive a peer past the budget and the reply stops.
//
// It also re-derives the gap. The frames spent and the bytes bought are both
// counted here, so the amplification the budget is bounding is a measurement
// on this head rather than a figure quoted from the issue.
func TestOneIdentityIsServedAtMostOneWindowBudgetOfReplyBytes(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	budget, period := f.budget()
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))

	// One reply first, so the ceiling below is stated against a measured reply
	// size rather than an assumed one.
	first := e.OnGetHeaders(payer, headerRequest())
	if first.Reply == nil {
		t.Fatalf("the first get-headers of a fresh budget was refused: %+v", first)
	}
	reply := uint64(len(first.Reply.Payload))
	if reply == 0 {
		t.Fatal("an empty headers reply: this fixture asserts nothing about bytes")
	}

	served, bytes, v := serveUntilRefused(e, payer, 4096)
	served, bytes = served+1, bytes+reply

	if v.Reply != nil {
		t.Fatalf("4096 get-headers frames were all served: the budget does not stop the reply")
	}
	if v.Cost != CostBudgeted {
		t.Errorf("the refusal is priced %v, want CostBudgeted (wire.md §10.3)", v.Cost)
	}
	if !errors.Is(v.Err, ErrReplyBudget) {
		t.Errorf("the refusal reports %v, want ErrReplyBudget", v.Err)
	}
	// The bound, in both directions. Below budget would be a throttle tighter
	// than the derivation; at or above budget+reply would mean the check ran
	// after the charge rather than before it.
	if bytes < budget {
		t.Errorf("stopped after %d bytes, below the derived budget of %d: "+
			"this is tighter than replyByteBudget claims", bytes, budget)
	}
	if bytes >= budget+reply {
		t.Errorf("served %d bytes against a budget of %d with a largest reply of %d: "+
			"the overshoot exceeds one reply", bytes, budget, reply)
	}

	spent := uint64(served) * uint64(len(headerRequest()))
	t.Logf("devnet, clock frozen: %d get-headers frames of %d bytes (%d bytes spent) "+
		"bought %d bytes of reply and the %dth was refused unserved; "+
		"budget %d bytes per %d s = %d B/s; amplification per frame %d:1, "+
		"per window %d:1 and no longer unbounded",
		served, len(headerRequest()), spent, bytes, served+1,
		budget, period, budget/period, reply/uint64(len(headerRequest())), budget/spent)
}

// TestTheBudgetIsOneAllowanceAcrossBothPricedKinds separates the two kinds.
// Spending it on headers must stop a block chunk too, or the "budget" is two
// per-handler counters and the cross-handler requirement is unmet.
func TestTheBudgetIsOneAllowanceAcrossBothPricedKinds(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))
	other := replyBudgetKey("1.2.3.4:51001", identity(2))
	block := GetBlock{ID: f.ids[len(f.ids)-1], Chunk: 0}.MarshalGetBlock()

	// A control taken BEFORE the spend, so that a get-block failing for any
	// reason other than the budget cannot be read as the budget working.
	if v := e.OnGetBlock(other, block); v.Reply == nil {
		t.Fatalf("get-block is not servable on this fixture at all: %+v", v)
	}

	if _, _, v := serveUntilRefused(e, payer, 4096); v.Reply != nil {
		t.Fatal("the header budget never ran out")
	}
	if v := e.OnGetBlock(payer, block); v.Reply != nil {
		t.Errorf("a block chunk was served to an identity that had already spent " +
			"its whole budget on headers: the two kinds hold separate counters")
	} else if v.Cost != CostBudgeted || !errors.Is(v.Err, ErrReplyBudget) {
		t.Errorf("get-block refused as %v/%v, want CostBudgeted/ErrReplyBudget", v.Cost, v.Err)
	}
	// And the control again, after: a different identity is unaffected.
	if v := e.OnGetBlock(other, block); v.Reply == nil {
		t.Errorf("a second identity was refused a block chunk because the first " +
			"exhausted its budget: the budget is not per peer")
	}
}

// TestAMalformedQueryIsStillScoredInvalidPastTheBudget separates the ordering
// conjunct: the decode runs before the budget check, so exhausting the budget
// does not buy an amnesty from ScoreInvalidMessage.
//
// This is the failure mode recorded for the guard next door, where a price in
// front of the work check took the invalid-header flood out of the class that
// terminates it. Here the price sits behind the decode instead.
func TestAMalformedQueryIsStillScoredInvalidPastTheBudget(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))
	if _, _, v := serveUntilRefused(e, payer, 4096); v.Reply != nil {
		t.Fatal("the budget never ran out")
	}
	for _, tc := range []struct {
		name string
		run  func() Verdict
	}{
		{"get-headers", func() Verdict { return e.OnGetHeaders(payer, []byte{0x01, 0x02}) }},
		{"get-block", func() Verdict { return e.OnGetBlock(payer, []byte{0x01, 0x02}) }},
	} {
		v := tc.run()
		if v.Cost != CostScored || v.Score != ScoreInvalidMessage {
			t.Errorf("a malformed %s from an exhausted peer is priced %v/%d, "+
				"want CostScored/%d: the budget check has moved in front of the "+
				"decode and a spent peer now floods malformed frames unscored",
				tc.name, v.Cost, v.Score, ScoreInvalidMessage)
		}
	}
}

// TestOneIdentityCannotRebuyTheReplyBudgetByReconnecting is the conjunct that
// decides where the budget lives, and it has three arms because two of them are
// controls for the third.
//
// The failure this arm is written against was measured on the budget next
// door: one identity, eight reconnects, eight full budgets, because that budget
// is keyed on Conn.Addr — "a value the OS picks fresh on every reconnect, not
// the peer" (PeerStore.AdjustKey). The instrument here is the same shape,
// so a budget keyed on the connection fails arm 1 and passes arms 2 and 3.
func TestOneIdentityCannotRebuyTheReplyBudgetByReconnecting(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	budget, _ := f.budget()
	const reconnects = 8

	run := func(t *testing.T, key func(i int) ed25519.PublicKey) (total uint64) {
		e := f.engine(t)
		for i := 0; i < reconnects; i++ {
			// A fresh ephemeral source port each time, which is exactly what a
			// reconnecting inbound peer presents.
			addr := fmt.Sprintf("1.2.3.4:%d", 51000+i)
			h := e.Hello()
			h.ListenAddr = ""
			if v := e.HandleFrom(addr, key(i), KindHello, h.MarshalHello()); v.Err != nil {
				t.Fatalf("handshake %d refused: %v", i, v.Err)
			}
			req := headerRequest()
			for n := 0; n < 4096; n++ {
				v := e.HandleFrom(addr, key(i), KindGetHeaders, req)
				if v.Reply == nil {
					break
				}
				total += uint64(len(v.Reply.Payload))
			}
			e.forgetPeer(addr)
		}
		return total
	}

	// Arm 1: one identity across eight connections. The clock never moves, so
	// none of what follows can be refill.
	one := run(t, func(int) ed25519.PublicKey { return identity(1) })
	// Arm 2: eight identities, same eight addresses, same everything else.
	many := run(t, func(i int) ed25519.PublicKey { return identity(byte(10 + i)) })
	// Arm 3: no identity at all, so replyBudgetKey falls back to the address.
	// This is what a per-connection budget would do in arm 1 as well, and it is
	// here so that arm 1's number is read as the keying rather than as some
	// unrelated saturation.
	none := run(t, func(int) ed25519.PublicKey { return nil })

	t.Logf("clock frozen, %d connections each: one identity bought %d bytes; "+
		"%d identities bought %d bytes; no identity (address-keyed) bought %d bytes; "+
		"one window's budget is %d bytes",
		reconnects, one, reconnects, many, none, budget)

	if one >= 2*budget {
		t.Errorf("one identity bought %d bytes across %d reconnects against a "+
			"budget of %d: the budget is re-bought per connection",
			one, reconnects, budget)
	}
	if many < uint64(reconnects)*budget {
		t.Errorf("%d distinct identities bought only %d bytes, under %d x %d: "+
			"the budget is not per peer at all", reconnects, many, reconnects, budget)
	}
	if none < uint64(reconnects)*budget {
		t.Errorf("the address-keyed fallback bought %d bytes across %d addresses, "+
			"under %d x %d: this control no longer separates keying from saturation",
			none, reconnects, reconnects, budget)
	}
	// Both control arms are bounded ABOVE as well, and that is not symmetry
	// for its own sake. A one-sided control cannot tell "one budget per
	// connection" from "no budget at all", and both arms read as controls for
	// arm 1 only while they are known to be budgeted. Measured: widening
	// replyBudgetKey's guard to len(peerKey) >= 0 turns the fallback into no
	// key, no charge and no bound, and the arm below is what refuses to call
	// 3.8 GB of reply a passing control.
	ceiling := uint64(reconnects) * 2 * budget
	if many >= ceiling {
		t.Errorf("%d distinct identities bought %d bytes, at or over %d x 2 x %d: "+
			"each identity is buying more than one window, so this arm is not "+
			"measuring a budget", reconnects, many, reconnects, budget)
	}
	if none >= ceiling {
		t.Errorf("the address-keyed fallback bought %d bytes across %d addresses, "+
			"at or over %d x 2 x %d: the fallback is unbudgeted rather than "+
			"weaker, so replyBudgetKey is not keying on the address either",
			none, reconnects, reconnects, budget)
	}
}

// TestTheReplyBudgetIsSizedFromTheChainsOwnCapacityAndInterval varies both
// inputs the price is a function of and requires the price to move with each.
//
// A suite in which no row varies BlockByteCapacity, or none varies
// TargetBlockSeconds, cannot tell replyByteBudget's derivation from a constant
// that happens to equal it on devnet.
func TestTheReplyBudgetIsSizedFromTheChainsOwnCapacityAndInterval(t *testing.T) {
	base := spec.Devnet()

	halfCapacity := spec.Devnet()
	halfCapacity.BlockByteCapacity = base.BlockByteCapacity / 2
	halfCapacity.SeqGasCapacity = base.SeqGasCapacity / 2

	mainnetInterval := spec.Devnet()
	mainnetInterval.TargetBlockSeconds = spec.Mainnet().TargetBlockSeconds

	for _, tc := range []struct {
		name         string
		p            *params.Params
		wantBudget   uint64
		wantInterval uint64
	}{
		{"devnet as shipped", base, uint64(base.BlockByteCapacity), base.TargetBlockSeconds},
		{"half the byte capacity", halfCapacity, uint64(base.BlockByteCapacity / 2), base.TargetBlockSeconds},
		{"mainnet's block interval", mainnetInterval, uint64(base.BlockByteCapacity), spec.Mainnet().TargetBlockSeconds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget, period := replyByteBudget(tc.p)
			if budget != tc.wantBudget || period != tc.wantInterval {
				t.Fatalf("replyByteBudget = (%d, %d), want (%d, %d)",
					budget, period, tc.wantBudget, tc.wantInterval)
			}
			// Driven, not asserted from the struct: the price a peer actually
			// pays has to move with the parameter, not merely the accessor.
			f := newBudgetFixture(t, tc.p, budgetChainHeight)
			e := f.engine(t)
			payer := replyBudgetKey("1.2.3.4:51000", identity(1))
			_, bytes, v := serveUntilRefused(e, payer, 4096)
			if v.Reply != nil {
				t.Fatal("the budget never ran out")
			}
			if bytes < budget {
				t.Errorf("served %d bytes before refusing, under this parameter "+
					"set's budget of %d", bytes, budget)
			}
			if bytes >= budget+budget/4 {
				t.Errorf("served %d bytes against a budget of %d: the price did "+
					"not follow block_byte_capacity", bytes, budget)
			}
			// And the refill follows target_block_seconds: one second short of
			// the period grants nothing, the period itself grants the lot.
			f.clock += period - 1
			if v := e.OnGetHeaders(payer, headerRequest()); v.Reply != nil {
				t.Errorf("a credit arrived %d s into a %d s window", period-1, period)
			}
			f.clock++
			if v := e.OnGetHeaders(payer, headerRequest()); v.Reply == nil {
				t.Errorf("no credit after a full %d s window: %+v", period, v)
			}
			t.Logf("%s: budget %d bytes per %d s = %d B/s; refused after %d bytes; "+
				"refill at %d s and not at %d s",
				tc.name, budget, period, budget/period, bytes, period, period-1)
		})
	}
}

// TestAnHonestBulkSyncRateIsNeverThrottled is the other half of the budget's
// acceptance, and it is the half this lane has been burned on: I7-H4's tip
// window was reverted for breaking catch-up, and a budget that refuses the
// workload it protects is a denial of service wearing a bound's clothes.
//
// The rate driven here is not invented for the test. It is the sustained floor
// replyByteBudget derives the budget from — BlockByteCapacity bytes per
// TargetBlockSeconds — which is the same rate syncAttemptTimeout's own
// derivation assumes an honest attempt achieves.
func TestAnHonestBulkSyncRateIsNeverThrottled(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	budget, period := f.budget()
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))
	req := headerRequest()

	const windows = 4
	var delivered uint64
	var requests int
	start := f.clock
	for w := 0; w < windows; w++ {
		var inWindow uint64
		for {
			// An honest peer paced at the committed floor stops asking once the
			// next reply would carry it past that floor for this interval. It
			// is the rate that is honest; the granularity is one reply.
			v := e.OnGetHeaders(payer, req)
			requests++
			if v.Reply == nil {
				t.Fatalf("window %d, request %d: an honest peer pacing at "+
					"%d bytes per %d s was refused after %d bytes this window "+
					"and %d bytes overall — the budget is a denial of service "+
					"against bulk sync: %+v",
					w, requests, budget, period, inWindow, delivered, v)
			}
			n := uint64(len(v.Reply.Payload))
			delivered += n
			inWindow += n
			if inWindow+n > budget {
				break
			}
		}
		if w < windows-1 {
			f.clock += period
		}
	}

	elapsed := (f.clock - start) + period
	floor := budget / period
	got := delivered / elapsed
	if delivered < uint64(windows)*(budget-budget/64) {
		t.Errorf("delivered %d bytes over %d windows, under %d x (budget - one reply): "+
			"an honest peer at the floor is being throttled",
			delivered, windows, windows)
	}
	t.Logf("honest bulk sync, %d windows: %d requests, %d bytes delivered, "+
		"0 refused; %d B/s against the committed floor of %d B/s "+
		"(block_byte_capacity %d / target_block_seconds %d); the honest chain "+
		"grows at most %d B/s (block_byte_limit_genesis %d / %d), so this is a "+
		"catch-up factor of %d.%02dx",
		windows, requests, delivered, got, floor,
		f.p.BlockByteCapacity, period,
		uint64(f.p.BlockByteLimitGenesis)/period, f.p.BlockByteLimitGenesis, period,
		f.p.BlockByteCapacity/f.p.BlockByteLimitGenesis,
		(uint64(f.p.BlockByteCapacity)*100/uint64(f.p.BlockByteLimitGenesis))%100)

	// Anti-vacuity, and it does not share a filter with the instrument above:
	// the same peer, the same window, asking FASTER than the floor is refused
	// within a couple of replies. Without this the test above passes for a
	// budget that is never reached at all.
	over := 0
	for {
		v := e.OnGetHeaders(payer, req)
		if v.Reply == nil {
			break
		}
		over++
		if over > 8 {
			t.Fatalf("the same peer went %d replies past the floor inside one "+
				"window without being refused: the loop above proves nothing", over)
		}
	}
	t.Logf("anti-vacuity: %d further replies inside the same window before the "+
		"budget refused, so the honest run above was pacing against a live bound", over)
}

// TestAWholeChainSyncsWithoutARefusal drives the literal workload: a peer that
// downloads every header and every block body this node holds.
//
// It is deliberately reported rather than only asserted. This chain's whole
// header-and-body volume is well under one window on devnet, so what this test
// pins is that nothing about the budget interferes with a complete sync, not
// that the budget is generous — the rate claim is the test above.
func TestAWholeChainSyncsWithoutARefusal(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))

	var delivered uint64
	var requests int
	for from := uint64(0); from <= uint64(budgetChainHeight); from += syncBatch {
		v := e.OnGetHeaders(payer, GetHeaders{From: from, Count: syncBatch}.MarshalGetHeaders())
		requests++
		if v.Reply == nil {
			t.Fatalf("a header batch at height %d was refused during a whole-chain sync: %+v", from, v)
		}
		delivered += uint64(len(v.Reply.Payload))
	}
	for _, id := range f.ids {
		for chunk := uint32(0); ; chunk++ {
			v := e.OnGetBlock(payer, GetBlock{ID: id, Chunk: chunk}.MarshalGetBlock())
			requests++
			if v.Reply == nil {
				t.Fatalf("a body chunk of block %x was refused during a whole-chain sync: %+v", id[:8], v)
			}
			c, err := UnmarshalBlockChunk(v.Reply.Payload)
			if err != nil {
				t.Fatal(err)
			}
			delivered += uint64(len(v.Reply.Payload))
			if chunk+1 >= c.Total {
				break
			}
		}
	}
	budget, period := f.budget()
	t.Logf("whole-chain sync of %d blocks: %d requests, %d bytes, 0 refused, "+
		"inside one %d s window of a %d byte budget", len(f.ids), requests, delivered, period, budget)
}

// TestTheRefillIsAWindowAndNotALifetimeAllowance separates refilledServed's
// arms one at a time. Each row names the arm it is the only input to reach.
func TestTheRefillIsAWindowAndNotALifetimeAllowance(t *testing.T) {
	const budget, period = 1000, 60
	for _, tc := range []struct {
		name             string
		served, servedAt uint64
		now              uint64
		wantServed       uint64
		wantAt           uint64
	}{
		// The servedAt == 0 arm. The first row is the shape and separates
		// nothing on its own — an empty bucket answers the same either way. The
		// SECOND row is the separator: delete the arm and the division measures
		// from the unix epoch, so a spend of 700 is refunded in full on its very
		// first settle.
		{"a fresh entry anchors its clock", 0, 0, 1_700_000_000, 0, 1_700_000_000},
		{"an entry whose clock was never set keeps what it spent", 700, 0, 1_700_000_000, 700, 1_700_000_000},
		// The now > servedAt arm. A clock corrected backwards must not refund.
		{"a clock that steps backwards refunds nothing", 700, 1_700_000_000, 1_699_999_000, 700, 1_700_000_000},
		{"a clock that has not moved refunds nothing", 700, 1_700_000_000, 1_700_000_000, 700, 1_700_000_000},
		// Part of a window earns nothing. There is no separate guard for this:
		// the partial arm returns exactly this, which is why refilledServed
		// carries no credits == 0 early return.
		{"part of a window earns nothing", 700, 1_700_000_000, 1_700_000_059, 700, 1_700_000_000},
		// The FULL arm: the bucket empties and the clock restarts at now,
		// discarding the remainder rather than banking a head start.
		{"a full window empties the bucket and restarts the clock", 700, 1_700_000_000, 1_700_000_075, 0, 1_700_000_075},
		// The PARTIAL arm: only reachable above one window's worth of spend,
		// and it advances the clock by exactly what was earned.
		{"a partial refund banks the remainder of the schedule", 2500, 1_700_000_000, 1_700_000_075, 1500, 1_700_000_060},
		{"two windows of a three-window debt", 2500, 1_700_000_000, 1_700_000_135, 500, 1_700_000_120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served, at := refilledServed(tc.served, tc.servedAt, budget, period, tc.now)
			if served != tc.wantServed || at != tc.wantAt {
				t.Fatalf("refilledServed(%d, %d, %d, %d, %d) = (%d, %d), want (%d, %d)",
					tc.served, tc.servedAt, budget, period, tc.now, served, at,
					tc.wantServed, tc.wantAt)
			}
		})
	}
}

// TestAServedReplyIsPricedBudgetedAndNotFree pins the class on the SERVED
// path, which is a different claim from the class on the refusal.
//
// wire.md §10.3 says `Served` is `Budgeted` for both kinds now, and before
// this unit both said `Free`. Nothing else here reads Verdict.Cost on a reply
// that arrived: every other assertion in these files looks at the refusal.
// Measured on this head: reverting either served literal to CostFree left the
// whole node/p2p suite green. sim/wiring's class-totality check catches the
// get-headers half — it has no `Free` row left — and cannot catch the
// get-block half, because `get-block` keeps a legitimate `Free` row for the
// block this node does not hold. So the behavioural pin has to be here, on
// both kinds, or the spec row is decoration for one of them.
//
// Score is asserted with it: `Budgeted` is a class, and a served reply that
// also moved the peer's score would be `Scored` wearing it.
func TestAServedReplyIsPricedBudgetedAndNotFree(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), 4)
	e := f.engine(t)
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))

	for _, tc := range []struct {
		name string
		run  func() Verdict
	}{
		{"get-headers", func() Verdict { return e.OnGetHeaders(payer, headerRequest()) }},
		{"get-block", func() Verdict {
			return e.OnGetBlock(payer, GetBlock{ID: f.ids[len(f.ids)-1], Chunk: 0}.MarshalGetBlock())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.run()
			if v.Reply == nil {
				t.Fatalf("nothing was served, so this row prices no reply: %+v", v)
			}
			if v.Cost != CostBudgeted {
				t.Errorf("a served %s reply of %d bytes is priced %v, want CostBudgeted: "+
					"wire.md §10.3's Served row for this kind says Budgeted, and the "+
					"bytes ARE charged, so a Free here is a row the code stopped "+
					"honouring", tc.name, len(v.Reply.Payload), v.Cost)
			}
			if v.Score != 0 {
				t.Errorf("a served %s reply carried Score %d; Budgeted is not Scored",
					tc.name, v.Score)
			}
		})
	}
}

// TestAPeerServedExactlyItsBudgetIsExhausted separates the boundary of the one
// comparison the whole bound reduces to.
//
// Every other test here reaches exhaustion by overshooting it: one devnet
// header reply is 116,740 bytes and the budget is 8,000,000, so `served` steps
// 7,938,320 -> 8,055,060 and never lands on the budget itself. No input in the
// suite therefore separates `served >= budget` from `served > budget`, and
// measured on this head, weakening it to `>` left every test green. The row
// that matters is the equal one; the two either side of it are what make the
// equal row readable as a boundary rather than as an arbitrary triple.
//
// Driven through the store rather than asserted of refilledServed, because the
// comparison under test is ServedBytesExhausted's own and the refill table next
// door never calls it.
func TestAPeerServedExactlyItsBudgetIsExhausted(t *testing.T) {
	const budget, period = 8_000_000, 30
	const now = 1_700_000_017
	for _, tc := range []struct {
		name  string
		spend uint64
		want  bool
	}{
		{"one byte short of the budget", budget - 1, false},
		{"exactly the budget", budget, true},
		{"one byte past the budget", budget + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := NewPeerStore("")
			if err != nil {
				t.Fatal(err)
			}
			key := string(identity(1))
			ps.ChargeServedBytes(key, tc.spend, budget, period, now)
			if got := ps.ServedBytesExhausted(key, budget, period, now); got != tc.want {
				t.Fatalf("a peer served %d of a %d byte budget reports exhausted=%v, "+
					"want %v: the budget is the bound, so being served all of it is "+
					"being served all of it", tc.spend, budget, got, tc.want)
			}
		})
	}
}

// TestManyWindowsDeliverTheirBudgetAndNotTheirBudgetPlusOneReplyEach is the
// SUSTAINED half of the bound, and every other test here measures a single
// window.
//
// The budget check reads before the charge — it has to, or an exhausted peer
// would buy the chain read the refusal exists to save — so a peer one byte
// under its budget is served one whole reply on top of it. That overshoot is a
// one-time constant only because refilledServed's partial arm carries it into
// the next window as debt; if a window instead forgave it, the sustained rate
// would be the floor plus one reply per period forever. On mainnet the largest
// reply is BlockChunkBytes = 4,194,304 against a budget of 8,000,000, so the
// two readings differ by about half the budget in sustained egress. The rate
// this unit is sized at is a sustained rate, so the sustained reading is the
// one that has to be pinned.
//
// The bound asserted is exact rather than approximate: with the partial arm
// carrying, a window opens at (previous total - budget), so after n windows
// the total delivered is (n-1) x budget plus whatever the last window has
// spent, and the last window stops within one reply of the budget. Hence
// total < n x budget + one reply, for every n. Forgiving the overshoot makes
// it n x (budget + overshoot) instead, which crosses that line as soon as n
// overshoots exceed one reply.
func TestManyWindowsDeliverTheirBudgetAndNotTheirBudgetPlusOneReplyEach(t *testing.T) {
	f := newBudgetFixture(t, spec.Devnet(), budgetChainHeight)
	e := f.engine(t)
	budget, period := f.budget()
	payer := replyBudgetKey("1.2.3.4:51000", identity(1))

	const windows = 8
	var total uint64
	var reply uint64
	perWindow := make([]uint64, 0, windows)
	for w := 0; w < windows; w++ {
		served, bytes, v := serveUntilRefused(e, payer, 4096)
		if v.Reply != nil {
			t.Fatalf("window %d never ran out of budget", w)
		}
		if reply == 0 {
			reply = bytes / uint64(served)
		}
		total += bytes
		perWindow = append(perWindow, bytes)
		f.clock += period
	}

	// The margin this test lives on, stated rather than assumed: the first
	// window must actually overshoot, or there is no debt to carry and the
	// assertion below holds for any refill at all.
	if perWindow[0] <= budget {
		t.Fatalf("the first window delivered %d bytes, at or under the %d byte "+
			"budget: nothing overshot, so this test separates nothing",
			perWindow[0], budget)
	}
	ceiling := uint64(windows)*budget + reply
	if total >= ceiling {
		t.Errorf("%d windows delivered %d bytes, at or over %d x %d + one %d-byte "+
			"reply = %d: the overshoot is being forgiven each window instead of "+
			"carried, so the sustained rate is the floor plus a reply per period "+
			"and the budget's own rate figure is wrong (%v)",
			windows, total, windows, budget, reply, ceiling, perWindow)
	}
	// Anti-vacuity from the other side: a budget that refused almost everything
	// would pass the ceiling trivially.
	if floor := uint64(windows) * (budget - reply); total < floor {
		t.Errorf("%d windows delivered only %d bytes, under %d x (budget - one "+
			"reply) = %d: this is a throttle below the floor, not a carry",
			windows, total, windows, floor)
	}
	t.Logf("%d windows at %d bytes per %d s: %v = %d bytes total, against "+
		"%d x budget = %d and a ceiling of %d (one %d-byte reply of overshoot, "+
		"carried rather than repeated); sustained %d B/s against a floor of %d B/s",
		windows, budget, period, perWindow, total, windows, uint64(windows)*budget,
		ceiling, reply, total/(uint64(windows)*period), budget/period)
}
