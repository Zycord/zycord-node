package mempool_test

import (
	"errors"
	"runtime"
	"sort"
	"testing"

	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/mempool"
	"zycord/spec"
	"zycord/wallet"
)

// Eviction under pressure (docs/adversarial/mempool.md).
//
// The M1 pool refused arrivals when full, which is a cheap censorship vector
// once there is a network: flood with minimum priority and legitimate traffic
// is refused at the door, exactly when the fee market should be resolving the
// contention. These tests pin the replacement.

// key takes testing.TB rather than *testing.T so it (and, transitively,
// world) can be shared between tests and BenchmarkRejectedArrivalIsSizeIndependent
// — the benchmark needs the exact same pool construction a test would
// use, and duplicating it would be one more place to keep in sync.
func key(t testing.TB, n int) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	seed[0] = byte(n)
	seed[1] = byte(n >> 8)
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

// world is a funded state plus a pool, sized so the water marks are reachable
// in a test rather than at twenty thousand certificates.
type world struct {
	t      testing.TB
	p      *params.Params
	state  *state.State
	pool   *mempool.Pool
	policy mempool.Policy
}

func newWorld(t testing.TB, policy mempool.Policy) *world {
	t.Helper()
	p := spec.Devnet()
	return &world{t: t, p: p, state: state.New(), pool: mempool.New(p, policy), policy: policy}
}

// smallPolicy shrinks the pool enough to test in a second, while keeping a
// hysteresis gap wide enough to observe. A gap of one is not hysteresis: the
// pool would evict on every arrival, which is the thrashing the gap exists to
// prevent.
func smallPolicy() mempool.Policy {
	pol := mempool.DefaultPolicy()
	pol.MaxCertificates = 100
	pol.EvictionHighWater = 90 // engages at 90
	pol.EvictionLowWater = 80  // clears to 80, leaving room for ten arrivals
	return pol
}

// fillToHighWater adds certificates at a uniform priority until the next
// arrival would trigger eviction, and returns how many landed.
func (w *world) fillToHighWater(priority uint64) int {
	w.t.Helper()
	limit := w.policy.MaxCertificates * int(w.policy.EvictionHighWater) / 100
	for i := 0; w.pool.Stats().Size < limit; i++ {
		if err := w.add(w.cert(key(w.t, 1_000_000+i), 0, priority, 1)); err != nil {
			w.t.Fatalf("filling: %v", err)
		}
	}
	return w.pool.Stats().Size
}

// fillToHighWaterWith is fillToHighWater with both priorities chosen.
func (w *world) fillToHighWaterWith(seqPriority, parPriority uint64) int {
	w.t.Helper()
	limit := w.policy.MaxCertificates * int(w.policy.EvictionHighWater) / 100
	for i := 0; w.pool.Stats().Size < limit; i++ {
		if err := w.add(w.cert(key(w.t, 2_000_000+i), 0, seqPriority, parPriority)); err != nil {
			w.t.Fatalf("filling: %v", err)
		}
	}
	return w.pool.Stats().Size
}

// cert builds and funds a certificate offering the given sequential priority.
//
// The maxima are the baseline 1,000,000 in each market, raised to the declared
// priority whenever the caller asks for more than that. A priority above its
// own maximum is not a canonical fee bid: UnmarshalFeeBid has refused it ever
// since FeeBid's canonical form was written down as "priority <= maximum in
// each market", so a fixture that pinned the maximum at 1,000,000 while the
// ordering tests bid millions was always building bytes no peer could decode.
//
// What is new is only who says so first. V1 was given the canonical-form rule
// the decoder already enforced (core/validity/validity.go), and
// wallet.Builder.Build run validity.Check, so this helper now fails at build
// time instead of handing the pool a certificate no peer could have sent it.
// Raising these maxima is therefore not a fixture bending around a new bound;
// it is a fixture being brought into a canonical form that predates every test
// in this file.
//
// Raising the maximum is free: it is a solvency bound, not a price
// (wallet.Bid). It changes nothing these tests measure, because the eviction
// floor is read off SeqPriority alone; the only other thing it moves is
// FeeCeiling, and the funding below is computed from that ceiling.
func (w *world) cert(signer *wallet.Key, seq uint64, seqPriority, parPriority uint64) *types.Certificate {
	w.t.Helper()
	addr := signer.Persistent()

	const baseMax = 1_000_000
	seqMax, parMax := uint64(baseMax), uint64(baseMax)
	if seqPriority > seqMax {
		seqMax = seqPriority
	}
	if parPriority > parMax {
		parMax = parPriority
	}

	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, addr, key(w.t, 9999).Persistent(), drops(1_000)),
		Seq:     seq,
		TTL:     20,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  wallet.Bid(drops(seqMax), drops(seqPriority), drops(parMax), drops(parPriority)),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		w.t.Fatal(err)
	}
	// Fund the deposit cell so the screen passes; the pool's job here is
	// eviction, not admission. Topped up rather than overwritten: the screen
	// is now a sum across a signer's already-pooled certificates, so a
	// second certificate from the same signer (a chain, or repeated calls in a
	// loop) must find the cell funded for both, not just the newest one.
	ceiling, ok := c.FeeCeiling(w.p)
	if !ok {
		w.t.Fatal("ceiling overflow")
	}
	slot := types.NativeBalanceSlot(addr)
	w.state.Set(slot, w.state.Get(slot).SatAdd(ceiling).SatAdd(drops(1_000_000_000)))
	return c
}

func (w *world) add(c *types.Certificate) error {
	return w.pool.Add(c, w.state, 1)
}

// TestFloodDoesNotCensorHigherPayingArrivals is the attack from §1.
//
// A pool filled with minimum-priority certificates must still admit a
// high-priority one. Per the anti-vacuity rule, the test first proves that the
// *old* behaviour would have refused it: the pool is genuinely at its
// high-water mark, so a refusing pool has no room by construction.
func TestFloodDoesNotCensorHigherPayingArrivals(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// The flood: the pool driven to its high-water mark at minimum priority, by
	// distinct identities so the per-sender quota is not what does the work.
	filled := w.fillToHighWater(1)

	// The victim: a legitimate certificate paying far more for the scarce
	// resource. A refusing pool would have no room for it.
	victim := w.cert(key(t, 5000), 0, 10_000, 1)
	if err := w.add(victim); err != nil {
		t.Fatalf("a high-priority certificate was censored by a flood: %v", err)
	}
	if !w.pool.Has(victim.ID()) {
		t.Fatal("the high-priority certificate was not pooled")
	}
	if w.pool.Stats().Size > filled {
		t.Fatal("the pool grew past its high-water mark instead of evicting")
	}
	if w.pool.Stats().Evicted == 0 {
		t.Fatal("room was made without evicting anything; the test is not measuring eviction")
	}
}

// TestEvictionRanksBySequentialPriority: the scarce resource decides, not the
// abundant one. Ranking by parallel tip would evict exactly the certificates a
// rational miner most wants — R2-H2's error one layer up.
func TestEvictionRanksBySequentialPriority(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// One resident that is cheap in parallel but valuable in sequential. A pool
	// ranking by total fee would evict it first.
	protected := w.cert(key(t, 6000), 0, 5_000, 1)
	if err := w.add(protected); err != nil {
		t.Fatal(err)
	}

	// Fill the rest with certificates that are expensive in parallel and cheap
	// in sequential, then force repeated evictions.
	w.fillToHighWaterWith(1, 50_000)
	for i := 0; i < 30; i++ {
		if err := w.add(w.cert(key(t, 7000+i), 0, 9_000, 1)); err != nil {
			t.Fatalf("arrival %d: %v", i, err)
		}
	}

	if !w.pool.Has(protected.ID()) {
		t.Fatal("a high sequential-priority certificate was evicted in favour of high parallel-priority ones; " +
			"the pool is ranking by the abundant resource")
	}
}

// TestEvictionRequiresABump: displacement for one drop, repeated, is itself a
// denial of service — it forces the evicted certificate to be re-gossiped
// forever.
func TestEvictionRequiresABump(t *testing.T) {
	pol := smallPolicy()
	pol.EvictionBumpPercent = 10
	w := newWorld(t, pol)

	w.fillToHighWater(1_000)

	// One drop above the residents: refused.
	if err := w.add(w.cert(key(t, 8000), 0, 1_001, 1)); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("got %v, want a refusal: displacing for one drop must not be free", err)
	}
	// Ten percent above: admitted.
	if err := w.add(w.cert(key(t, 8001), 0, 1_100, 1)); err != nil {
		t.Fatalf("a certificate meeting the bump was refused: %v", err)
	}
}

// TestDisplacementAlwaysCostsAtLeastOneDrop is §2.2's bump at the bottom of the
// price range, where the flood of §1 lives.
//
// The bump is `resident * EvictionBumpPercent / 100` in integer arithmetic, and
// it truncates. At the default 10% that is zero for every resident declaring
// fewer than ten drops, and the comparison is `>=`, so an arrival declaring
// *exactly* what the resident declares displaced it — for free, repeatedly.
// §1 says a zero-priority certificate is perfectly valid and costs only a
// refundable deposit, so this is not a corner of the range, it is the corner an
// attacker starts in.
//
// The pool already required a strict increase against a resident declaring
// zero. This asserts the same rule one drop up, and that it does not decay into
// a churn loop.
func TestDisplacementAlwaysCostsAtLeastOneDrop(t *testing.T) {
	// Every price at which the percentage bump truncates to nothing, plus the
	// first one at which it does not.
	for _, price := range []uint64{0, 1, 5, 9, 10} {
		w := newWorld(t, smallPolicy())
		w.fillToHighWater(price)
		if bump := drops(price).MulDiv64(w.policy.EvictionBumpPercent, 100); price < 10 && !bump.IsZero() {
			t.Fatalf("setup: the percentage bump at %d is %s, not zero — this price does "+
				"not exercise the truncation the test is about", price, bump)
		}
		before := w.pool.Stats()
		err := w.add(w.cert(key(t, 90_000), 0, price, 1))
		if !errors.Is(err, mempool.ErrBelowEvictionFloor) {
			t.Fatalf("an arrival declaring %d displaced residents declaring %d — the same "+
				"price, so displacement was free: err=%v, evicted %d", price, price, err,
				w.pool.Stats().Evicted-before.Evicted)
		}
		// One drop more is enough, and must be: a bump that rounded *up* to a
		// percentage would price honest traffic out of the bottom of the range.
		if err := w.add(w.cert(key(t, 91_000), 0, price+1, 1)); err != nil {
			t.Fatalf("an arrival declaring %d was refused against residents declaring %d, so "+
				"the minimum bump is more than one drop: %v", price+1, price, err)
		}
	}

	// And the loop the bump exists to break: same price, over and over.
	w := newWorld(t, smallPolicy())
	w.fillToHighWater(5)
	for i := 0; i < 20; i++ {
		if err := w.add(w.cert(key(t, 92_000+i), 0, 5, 1)); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
			t.Fatalf("round %d: a certificate declaring 5 displaced one declaring 5 (err=%v); "+
				"the pool has evicted %d certificates for no bid at all",
				i, err, w.pool.Stats().Evicted)
		}
	}
}

// TestEvictionNeverStrandsADependentChain: evicting the middle of a Seq chain
// leaves the certificates above it unable to ever apply, so the pool would keep
// offering miners work guaranteed to skip. Chains truncate from the tail.
func TestEvictionNeverStrandsADependentChain(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// A chain of three from one signer, at the lowest priority in the pool, so
	// a naive evictor would take its base first.
	chain := key(t, 100)
	var chainIDs []types.Hash
	for seq := uint64(0); seq < 3; seq++ {
		c := w.cert(chain, seq, 1, 1)
		if err := w.add(c); err != nil {
			t.Fatalf("chain %d: %v", seq, err)
		}
		chainIDs = append(chainIDs, c.ID())
	}

	// Fill and then push hard, forcing many evictions.
	w.fillToHighWater(5)
	for i := 0; i < 60; i++ {
		_ = w.add(w.cert(key(t, 400+i), 0, 100_000, 1))
	}

	// Whatever survived, the chain must be a prefix: never a hole.
	var present []bool
	for _, id := range chainIDs {
		present = append(present, w.pool.Has(id))
	}
	seenAbsent := false
	for seq, ok := range present {
		if !ok {
			seenAbsent = true
			continue
		}
		if seenAbsent {
			t.Fatalf("Seq %d is pooled but a lower Seq from the same signer was evicted: "+
				"the chain has a hole and everything above it is stranded", seq)
		}
	}
}

// TestChainedFloodCannotPinTheEvictionFloor crosses the two mitigations against
// the floor-pinning flood.
//
// TestFloodDoesNotCensorHigherPayingArrivals floods with *independent*
// certificates, so the whole pool is evictable and the floor is honest.
// TestEvictionNeverStrandsADependentChain exercises chains *in isolation*, with
// no attacker pricing them. Neither covers the interaction, and the interaction
// was the bug: §2.3 makes only an underwriter's highest pooled Seq evictable, so
// a flooder holding Seq chains left almost nothing evictable and could declare
// any price it liked on the few tails that were. Taking the floor from the
// cheapest evictable *tail* therefore let the attacker name the market price of
// entry without paying it — §1's censorship vector, reopened by the mitigation
// meant to close it.
//
// The property, as it stands after the floor was re-denominated: the flood
// cannot pin *which residents leave*. It is the eviction order that a chained
// flood cannot buy, and the arrival's price is measured against the residents it
// actually removes.
//
// What this test no longer claims, and why — the change is a withdrawal of a
// claim, not a weakening of a check. It used to assert that an arrival declaring
// 10 was admitted against flood tails declaring 100,000, on the reasoning that
// the flood's chains are worth what their cheapest member is worth. That is
// exactly the rule that let an arrival declaring 2 evict certificates declaring
// 1,000,000 with no attacker present, because "chain with a cheap base and a dear
// tail" is fee bumping and not an attack shape: the pool cannot tell the flood's
// chains from an honest user's, since they are the same declaration. The
// invariant that must hold is that an arrival beats what it removes, so an
// arrival at 10 is now refused here — and that refusal is asserted below rather
// than dropped. The flood's upward vector is open at the flood's price; see
// docs/adversarial/mempool.md §2.1.
func TestChainedFloodCannotPinTheEvictionFloor(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// The flood. Ten identities, eight certificates each. Within a chain only the
	// Seq 7 tail is evictable, and that tail declares a priority a hundred
	// thousand times the base's.
	const (
		chains     = 10
		perChain   = 8
		basePrice  = 1
		pinnedTail = 100_000
	)
	var tails []types.Hash
	for c := 0; c < chains; c++ {
		signer := key(t, 40_000+c)
		for seq := uint64(0); seq < perChain; seq++ {
			price := uint64(basePrice)
			if seq == perChain-1 {
				price = pinnedTail
			}
			cert := w.cert(signer, seq, price, 1)
			if err := w.add(cert); err != nil {
				t.Fatalf("flood chain %d seq %d: %v", c, seq, err)
			}
			if seq == perChain-1 {
				tails = append(tails, cert.ID())
			}
		}
	}

	// Ten honest independent residents, priced well above the arrival, taking the
	// pool to its high-water mark of ninety. They are here so the test can see
	// *which* residents the eviction pass chooses: a pool that gated on the chain
	// but still ranked by the tail's own price would admit the arrival below and
	// then evict these instead of the flood, which is the same censorship with an
	// extra step.
	const honestResidentPrice = 1_000
	var honestResidents []types.Hash
	for i := 0; i < 10; i++ {
		cert := w.cert(key(t, 42_000+i), 0, honestResidentPrice, 1)
		if err := w.add(cert); err != nil {
			t.Fatalf("honest resident %d: %v", i, err)
		}
		honestResidents = append(honestResidents, cert.ID())
	}
	if got := w.pool.Stats().Size; got != chains*perChain+10 {
		t.Fatalf("setup: the pool holds %d certificates, want %d at the high-water mark",
			got, chains*perChain+10)
	}

	// The invariant first, in the direction that used to be asserted the other
	// way round. An arrival at ten times the flood's *base* bid removes nothing
	// here: everything that may leave — the pinned tails and the honest residents
	// alike — declares more than it does. The old rule admitted it and peeled ten
	// tails declaring a hundred thousand, which is the regression this test now
	// pins rather than permits.
	const belowTheTails = 10
	evictedBeforeCheap := w.pool.Stats().Evicted
	if err := w.add(w.cert(key(t, 41_500), 0, belowTheTails, 1)); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("an arrival declaring %d was admitted although every resident it could "+
			"remove declares at least %d: err=%v", belowTheTails, honestResidentPrice, err)
	}
	if w.pool.Stats().Evicted != evictedBeforeCheap {
		t.Fatalf("a refused arrival evicted %d certificates",
			w.pool.Stats().Evicted-evictedBeforeCheap)
	}

	// Anti-vacuity for the ordering rule, which is what the rest of this test
	// measures. The rejected rule — ranking evictable residents by the tail's own
	// declared price — would put the honest residents at 1,000 *ahead* of the
	// flood's tails at 100,000, so the two orders genuinely disagree in this
	// scenario. Assert that before asserting which one the pool implements.
	oldFloor := cheapestEvictableTailPrice(t, w)
	if !oldFloor.Eq(drops(honestResidentPrice)) {
		t.Fatalf("setup: the cheapest evictable tail declares %s, want %d — the honest "+
			"residents must be the cheapest thing a tail-ordered pool would take", oldFloor, honestResidentPrice)
	}
	if oldFloor.Gte(drops(pinnedTail)) {
		t.Fatalf("setup: the flood's tails do not declare more than the honest residents, " +
			"so the two orderings do not disagree here")
	}

	// An honest arrival that does outbid the flood's tails by the bump. It must
	// be admitted, and what it removes must be the flood — not the honest
	// residents, which declare a hundred times less and would go first under an
	// order keyed on the tail's own declaration.
	const honestPrice = pinnedTail + pinnedTail/10
	honest := w.cert(key(t, 41_000), 0, honestPrice, 1)
	if err := w.add(honest); err != nil {
		t.Fatalf("a chained flood pinned the eviction floor and censored an honest "+
			"arrival that outbids every tail it would remove: %v", err)
	}
	if !w.pool.Has(honest.ID()) {
		t.Fatal("the honest certificate was not pooled")
	}
	if w.pool.Stats().Evicted == 0 {
		t.Fatal("room was made without evicting anything; the test is not measuring eviction")
	}

	// What left must be the flood, not the honest residents. The flooder's tails
	// declare a hundred times more than these residents do, so a pool ranking by
	// the declared tail price would have taken the residents first.
	for i, id := range honestResidents {
		if !w.pool.Has(id) {
			t.Fatalf("honest resident %d was evicted in favour of a chain whose base bids %d: "+
				"the pool is ranking by the flooder's declared tail price", i, basePrice)
		}
	}
	var tailsGone int
	for _, id := range tails {
		if !w.pool.Has(id) {
			tailsGone++
		}
	}
	if tailsGone == 0 {
		t.Fatal("no flooded chain was peeled; the eviction pass did not touch the flood")
	}

	// The chain-safety rule (§2.3) is not the price paid for this. Whatever the
	// eviction pass removed, no surviving certificate may sit above a hole.
	assertNoStrandedChains(t, w)
}

// assertNoStrandedChains reads the pool back and checks that every underwriter's
// surviving certificates are a prefix of its Seq sequence. A hole means the
// certificates above it can never apply and the pool is offering miners work
// guaranteed to skip.
func assertNoStrandedChains(t *testing.T, w *world) {
	t.Helper()
	bySigner := map[types.Address][]uint64{}
	for _, c := range w.pool.Candidates() {
		bySigner[c.UnderwriterID()] = append(bySigner[c.UnderwriterID()], c.Seq)
	}
	for signer, seqs := range bySigner {
		// Contiguity of the *distinct* Seq values, not of the certificate count.
		// Seq is an ordering key rather than a nonce, so one underwriter may
		// legitimately pool several certificates at the same Seq — replace-by-fee
		// does — and counting certificates would report a hole where there is
		// none, with a confidently wrong message.
		seen := map[uint64]bool{}
		var min, max uint64 = seqs[0], seqs[0]
		for _, s := range seqs {
			seen[s] = true
			if s < min {
				min = s
			}
			if s > max {
				max = s
			}
		}
		if min != 0 {
			t.Fatalf("underwriter %x holds Seq %d..%d with no Seq 0: its base was evicted "+
				"and everything above it is stranded", signer[:4], min, max)
		}
		for seq := uint64(0); seq <= max; seq++ {
			if !seen[seq] {
				t.Fatalf("underwriter %x holds Seq up to %d but not %d: the chain has a "+
					"hole and everything above it is stranded", signer[:4], max, seq)
			}
		}
	}
}

// cheapestEvictableTailPrice recomputes the *rejected* eviction floor from the
// pool's own contents: the minimum own-priority over each underwriter's highest
// pooled Seq. It exists so the test can prove the old rule and the new one give
// different answers in this scenario, rather than asserting that from prose.
func cheapestEvictableTailPrice(t *testing.T, w *world) u256.U256 {
	t.Helper()
	type tail struct {
		seq   uint64
		price u256.U256
	}
	tails := map[types.Address]tail{}
	for _, c := range w.pool.Candidates() {
		u := c.UnderwriterID()
		if cur, ok := tails[u]; !ok || c.Seq > cur.seq {
			tails[u] = tail{seq: c.Seq, price: c.FeeBid.SeqPriority}
		}
	}
	if len(tails) == 0 {
		t.Fatal("setup: the pool is empty")
	}
	var floor u256.U256
	first := true
	for _, tl := range tails {
		if first || tl.price.Lt(floor) {
			floor, first = tl.price, false
		}
	}
	return floor
}

// beatsByBumpForTest is the pool's own bump rule, reached through a test hook
// rather than copied. A copy would let a change to the rule silently
// desynchronise the anti-vacuity assertions, whose whole job is to not drift.
var beatsByBumpForTest = mempool.BeatsByBump

// chainPriceOf recomputes §2.1's chain price from the pool's own contents: for
// each underwriter, the minimum SeqPriority over its pooled certificates.
func chainPriceOf(w *world) map[types.Address]u256.U256 {
	out := map[types.Address]u256.U256{}
	for _, c := range w.pool.Candidates() {
		u := c.UnderwriterID()
		if cur, ok := out[u]; !ok || c.FeeBid.SeqPriority.Lt(cur) {
			out[u] = c.FeeBid.SeqPriority
		}
	}
	return out
}

// minChainPrice is the *rejected* floor rule: the minimum chain price over the
// whole pool. Because every underwriter's highest pooled Seq is evictable by
// construction, this is identical to "the cheapest chain price among evictable
// residents", and identical again to the pool-wide minimum SeqPriority.
func minChainPrice(t *testing.T, w *world) u256.U256 {
	t.Helper()
	prices := chainPriceOf(w)
	if len(prices) == 0 {
		t.Fatal("setup: the pool is empty")
	}
	var floor u256.U256
	first := true
	for _, p := range prices {
		if first || p.Lt(floor) {
			floor, first = p, false
		}
	}
	return floor
}

// nthSmallestDeclaredPrice recomputes the live floor rule from the pool's own
// contents: the n-th smallest own-declared SeqPriority among the residents that
// may leave. At n = 1 it is the *rejected* cheapest-victim rule.
func nthSmallestDeclaredPrice(t *testing.T, w *world, n int) u256.U256 {
	t.Helper()
	tails := map[types.Address]uint64{}
	for _, c := range w.pool.Candidates() {
		u := c.UnderwriterID()
		if cur, ok := tails[u]; !ok || c.Seq > cur {
			tails[u] = c.Seq
		}
	}
	var declared []u256.U256
	for _, c := range w.pool.Candidates() {
		if c.Seq == tails[c.UnderwriterID()] {
			declared = append(declared, c.FeeBid.SeqPriority)
		}
	}
	if len(declared) == 0 {
		t.Fatal("setup: nothing in the pool is evictable")
	}
	sort.Slice(declared, func(i, j int) bool { return declared[i].Lt(declared[j]) })
	if n > len(declared) {
		n = len(declared)
	}
	if n < 1 {
		n = 1
	}
	return declared[n-1]
}

// nthSmallestChainPrice is the *rejected* floor rule — the marginal cut, not
// the minimum: the n-th smallest chain price among the evictable residents —
// the price at the low-water cut, in the chain metric. It is recomputed from
// the pool's own contents so the witness can prove that rule would have decided
// differently here.
func nthSmallestChainPrice(t *testing.T, w *world, n int) u256.U256 {
	t.Helper()
	prices := chainPriceOf(w)
	tails := map[types.Address]uint64{}
	for _, c := range w.pool.Candidates() {
		u := c.UnderwriterID()
		if cur, ok := tails[u]; !ok || c.Seq > cur {
			tails[u] = c.Seq
		}
	}
	var evictable []u256.U256
	for _, c := range w.pool.Candidates() {
		if c.Seq == tails[c.UnderwriterID()] {
			evictable = append(evictable, prices[c.UnderwriterID()])
		}
	}
	if len(evictable) == 0 {
		t.Fatal("setup: nothing in the pool is evictable")
	}
	sort.Slice(evictable, func(i, j int) bool { return evictable[i].Lt(evictable[j]) })
	if n > len(evictable) {
		n = len(evictable)
	}
	if n < 1 {
		n = 1
	}
	return evictable[n-1]
}

// TestEvictionFloorIsTheCheapestRemovableNotThePoolMinimum is the regression a
// pool-wide-minimum floor introduces, and it needs no attacker at all.
//
// A floor taken as the cheapest chain price in the pool dissolves §2.2's bump
// guarantee everywhere, because a chain whose base bids less than its tail is
// the ordinary fee-bumping shape — one honest user doing an ordinary thing sets
// the price of entry for the whole pool at their cheapest certificate.
//
// What separates the two rules is §2.3's evictability filter, and this test is
// what pins that it is applied: a chain base cannot leave without stranding
// what sits above it, so it is not a price anyone can be admitted against. The
// floor is the cheapest **removable** declaration, which here is a million even
// though the pool contains a certificate declaring one.
//
// The witness is minimal and entirely honest: expensive independent residents,
// one two-certificate chain, one cheap arrival.
func TestEvictionFloorIsTheCheapestRemovableNotThePoolMinimum(t *testing.T) {
	w := newWorld(t, smallPolicy())

	const (
		residentPrice = 1_000_000
		chainBase     = 1
		residents     = 88
	)

	var residentIDs []types.Hash
	for i := 0; i < residents; i++ {
		c := w.cert(key(t, 60_000+i), 0, residentPrice, 1)
		if err := w.add(c); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
		residentIDs = append(residentIDs, c.ID())
	}

	// One honest two-certificate chain: a cheap setup certificate and a tail that
	// bids what everybody else bids. Nothing adversarial — this is fee bumping.
	chainSigner := key(t, 61_000)
	base := w.cert(chainSigner, 0, chainBase, 1)
	if err := w.add(base); err != nil {
		t.Fatalf("chain base: %v", err)
	}
	tail := w.cert(chainSigner, 1, residentPrice, 1)
	if err := w.add(tail); err != nil {
		t.Fatalf("chain tail: %v", err)
	}
	if got, want := w.pool.Stats().Size, residents+2; got != want {
		t.Fatalf("setup: the pool holds %d certificates, want %d at the high-water mark", got, want)
	}

	// Anti-vacuity: the rejected rule — floor = the cheapest chain price in the
	// pool — *would* have admitted this arrival in this same scenario. Assert
	// that before asserting anything about the rule that replaced it.
	const arrivalPrice = 2
	rejectedFloor := minChainPrice(t, w)
	if !rejectedFloor.Eq(drops(chainBase)) {
		t.Fatalf("setup: the rejected floor is %s, want %d — the honest chain's base must be "+
			"the pool minimum or the two rules are not being distinguished", rejectedFloor, chainBase)
	}
	if !beatsByBumpForTest(drops(arrivalPrice), rejectedFloor, w.policy.EvictionBumpPercent) {
		t.Fatalf("the rejected rule would also have refused an arrival at %d against a floor "+
			"of %s, so this scenario does not distinguish the two rules", arrivalPrice, rejectedFloor)
	}

	evictedBefore := w.pool.Stats().Evicted
	cheap := w.cert(key(t, 62_000), 0, arrivalPrice, 1)
	err := w.add(cheap)
	if !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("an arrival declaring %d was admitted against residents declaring %d: the "+
			"eviction floor tracks the cheapest certificate anywhere in the pool rather than "+
			"the residents the arrival actually displaces (err=%v)", arrivalPrice, residentPrice, err)
	}
	if w.pool.Stats().Evicted != evictedBefore {
		t.Fatalf("a refused arrival evicted %d certificates",
			w.pool.Stats().Evicted-evictedBefore)
	}
	for i, id := range residentIDs {
		if !w.pool.Has(id) {
			t.Fatalf("resident %d, declaring %d, was evicted by an arrival declaring %d",
				i, residentPrice, arrivalPrice)
		}
	}

	// The floor must be a floor, not a wall: an arrival that does beat the
	// cheapest removable resident by the bump is still admitted, so the pool has
	// not simply stopped evicting.
	rich := w.cert(key(t, 63_000), 0, residentPrice+residentPrice/10, 1)
	if err := w.add(rich); err != nil {
		t.Fatalf("an arrival that outbids the cheapest removable resident by the bump "+
			"was refused: %v", err)
	}
	if w.pool.Stats().Evicted == evictedBefore {
		t.Fatal("the qualifying arrival was admitted without evicting anything")
	}
	assertNoStrandedChains(t, w)
}

// TestArrivalMustOutbidEveryResidentItRemoves is the dual of the anti-pinning
// test, and the direction the suite lacked.
//
// TestChainedFloodCannotPinTheEvictionFloor asks "can a flood keep an honest
// arrival out?". This asks the opposite: can an under-priced arrival displace
// residents that outbid it? Both must be no, and a floor is only correct if it
// answers both — a floor set too high censors, a floor set too low licenses
// churn that §2.2's bump exists to price.
//
// Two things about this test are load-bearing and were both absent from the
// version that shipped with the marginal-cut rule, which is why it passed on a
// pool that was violating its own name:
//
//   - It compares the arrival against **each removed certificate's own
//     FeeBid.SeqPriority**. The earlier version compared it against the removed
//     certificate's *chain* price — the very quantity the floor was computed
//     from — and so asserted a tautology, reporting zero violations on a pool
//     that had just evicted ten certificates declaring a million.
//   - Every chain here is **fee bumped**: the base declares less than the tail.
//     The earlier fixture built both members of every chain at the same price, so
//     the base/tail divergence that is the entire subject of the bug never
//     occurred anywhere in it.
//
// The fixture both directions of the invariant are measured against: fee-bumped
// chains at three price levels plus independent rich residents, filled to the
// high-water mark. Built by a helper because each direction needs it fresh —
// an eviction pass leaves the pool below high water, and a second measurement
// taken there would not run a pass at all.
const (
	cheapChains  = 5
	cheapBase    = 100
	cheapTail    = 8_000
	middleChains = 8
	middleBase   = 200
	middleTail   = 5_000
	richPrice    = 20_000

	// One chain whose base is the cheapest thing in the pool and whose tail is
	// the dearest. Chain-unit ordering puts it at the head of the eviction
	// order, so it is the first certificate a pass reaches and the last one it
	// may take. It is what makes the per-victim check in makeRoomFor
	// observable: a pass that trusted the floor and removed the order's prefix
	// unconditionally would take this tail.
	outlierBase = 1
	outlierTail = 1_000_000
)

func outbidFixture(t *testing.T) (*world, []types.Hash) {
	t.Helper()
	w := newWorld(t, smallPolicy())

	// Fee bumping: a cheap setup certificate and a tail that pays for the pair.
	addChain := func(k *wallet.Key, base, tail uint64) {
		t.Helper()
		for seq, price := range []uint64{base, tail} {
			if err := w.add(w.cert(k, uint64(seq), price, 1)); err != nil {
				t.Fatalf("chain seq %d at %d: %v", seq, price, err)
			}
		}
	}
	addChain(key(t, 69_000), outlierBase, outlierTail)
	for i := 0; i < cheapChains; i++ {
		addChain(key(t, 70_000+i), cheapBase, cheapTail)
	}
	for i := 0; i < middleChains; i++ {
		addChain(key(t, 71_000+i), middleBase, middleTail)
	}
	var richIDs []types.Hash
	for i := 0; w.pool.Stats().Size < 90; i++ {
		c := w.cert(key(t, 72_000+i), 0, richPrice, 1)
		if err := w.add(c); err != nil {
			t.Fatalf("rich resident %d: %v", i, err)
		}
		richIDs = append(richIDs, c.ID())
	}
	return w, richIDs
}

func TestArrivalMustOutbidEveryResidentItRemoves(t *testing.T) {
	w, richIDs := outbidFixture(t)

	// Direction one: under-priced arrival, refused. Anti-vacuity first — the
	// rejected pool-minimum rule would have admitted it here.
	const underpriced = 1_000
	rejectedFloor := minChainPrice(t, w)
	if !rejectedFloor.Eq(drops(outlierBase)) {
		t.Fatalf("setup: the rejected floor is %s, want %d", rejectedFloor, outlierBase)
	}
	if !beatsByBumpForTest(drops(underpriced), rejectedFloor, w.policy.EvictionBumpPercent) {
		t.Fatalf("the rejected rule would also have refused an arrival at %d against a floor "+
			"of %s, so this scenario does not distinguish the two rules", underpriced, rejectedFloor)
	}
	if err := w.add(w.cert(key(t, 73_000), 0, underpriced, 1)); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("an arrival at %d was admitted although reaching the low-water mark requires "+
			"removing tails declaring %d: err=%v", underpriced, middleTail, err)
	}

	// Direction two: an arrival that clears the dearest thing the pass will
	// remove is admitted — and then every certificate it removed must be one it
	// beat on that certificate's *own* declaration.
	declared := map[types.Hash]u256.U256{}
	chainPrice := map[types.Hash]u256.U256{}
	prices := chainPriceOf(w)
	for _, c := range w.pool.Candidates() {
		declared[c.ID()] = c.FeeBid.SeqPriority
		chainPrice[c.ID()] = prices[c.UnderwriterID()]
	}
	const qualifying = cheapTail + cheapTail/10
	if err := w.add(w.cert(key(t, 74_000), 0, qualifying, 1)); err != nil {
		t.Fatalf("an arrival at %d that outbids every certificate it removes was refused: %v",
			qualifying, err)
	}

	removed, diverged := 0, 0
	for id, price := range declared {
		if w.pool.Has(id) {
			continue
		}
		removed++
		if chainPrice[id].Lt(price) {
			diverged++
		}
		if !beatsByBumpForTest(drops(qualifying), price, w.policy.EvictionBumpPercent) {
			t.Fatalf("an arrival declaring %d removed a certificate declaring %s without beating "+
				"it by the bump: the floor is denominated in a different metric from the victims "+
				"(that certificate's chain price is %s)", qualifying, price, chainPrice[id])
		}
	}
	if removed == 0 {
		t.Fatal("nothing was evicted; the test is not measuring the eviction pass")
	}
	// The scenario must actually contain the divergence it is testing for.
	// Without this, a pool that gated on chain prices would satisfy the loop
	// above for free, which is how the previous version of this test passed.
	if diverged == 0 {
		t.Fatal("every certificate the pass removed declares exactly its chain price, so this " +
			"scenario cannot tell a declared-price floor from a chain-price one")
	}
	for i, id := range richIDs {
		if !w.pool.Has(id) {
			t.Fatalf("rich resident %d, declaring %d, was evicted by an arrival declaring %d",
				i, richPrice, qualifying)
		}
	}
	assertNoStrandedChains(t, w)
}

// TestAPartiallyQualifyingArrivalIsAdmittedAndTakesWhatItBeats is the other
// half of the floor's correctness condition, and the direction the marginal
// floor got wrong.
//
// A floor set too low licenses churn that §2.2's bump exists to price; a floor
// set too high censors, which is §1. An arrival that outbids the cheapest
// removable resident but not the whole low-water cut sits between the two, and
// the pool admits it: the per-victim check already stops it from taking anything
// it did not outbid, so refusing it only keeps the pool full — and a pool that
// stays full runs an eviction pass on the *next* arrival too. Hysteresis is
// best-effort, exactly as §2.3 already required of a pass over few evictable
// chains.
func TestAPartiallyQualifyingArrivalIsAdmittedAndTakesWhatItBeats(t *testing.T) {
	w, _ := outbidFixture(t)

	// Anti-vacuity: the rejected marginal-victim rule would have refused this
	// arrival, so the two rules are genuinely distinguished by this scenario.
	// TestOneDearTailCannotSetThePoolsAdmissionPrice is what that refusal costs.
	const partial = middleTail + middleTail/10
	cheapestVictim := nthSmallestDeclaredPrice(t, w, 1)
	if !cheapestVictim.Eq(drops(middleTail)) {
		t.Fatalf("setup: the cheapest removable certificate declares %s, want %d",
			cheapestVictim, middleTail)
	}
	need := w.policy.MaxCertificates * int(w.policy.EvictionHighWater-w.policy.EvictionLowWater) / 100
	marginalVictim := nthSmallestDeclaredPrice(t, w, need)
	if beatsByBumpForTest(drops(partial), marginalVictim, w.policy.EvictionBumpPercent) {
		t.Fatalf("the rejected marginal-victim rule (floor %s at the %d-th removable "+
			"certificate) would also have admitted an arrival at %d, so this scenario does "+
			"not distinguish it from the cheapest-removable rule", marginalVictim, need, partial)
	}
	partialDeclared := map[types.Hash]u256.U256{}
	for _, c := range w.pool.Candidates() {
		partialDeclared[c.ID()] = c.FeeBid.SeqPriority
	}
	sizeBefore := w.pool.Stats().Size
	if err := w.add(w.cert(key(t, 73_500), 0, partial, 1)); err != nil {
		t.Fatalf("an arrival at %d that outbids the cheapest removable certificate (%s) by "+
			"the bump was refused: err=%v", partial, cheapestVictim, err)
	}
	partialRemoved := 0
	for id, price := range partialDeclared {
		if w.pool.Has(id) {
			continue
		}
		partialRemoved++
		if !beatsByBumpForTest(drops(partial), price, w.policy.EvictionBumpPercent) {
			t.Fatalf("a partially-qualifying arrival declaring %d removed a certificate "+
				"declaring %s without beating it by the bump", partial, price)
		}
	}
	if partialRemoved == 0 {
		t.Fatalf("the partially-qualifying arrival was admitted without evicting anything; "+
			"the pool grew from %d", sizeBefore)
	}
	if partialRemoved >= need {
		t.Fatalf("the partially-qualifying arrival removed %d certificates, reaching the "+
			"low-water cut of %d — the scenario is not partial and proves nothing about it",
			partialRemoved, need)
	}
	assertNoStrandedChains(t, w)

}

// TestOneDearTailCannotSetThePoolsAdmissionPrice is §1's censorship attack,
// reintroduced by a floor quantified at the low-water cut, and it needs no
// attacker either.
//
// The cut's price is the `need`-th smallest declaration among the residents that
// may leave. §2.3 makes only an underwriter's highest pooled Seq removable, so
// that set has one entry per underwriter, not one per certificate: as chains
// grow longer it shrinks toward `need`, the floor climbs toward the *dearest*
// removable declaration, and at or below `need` removable residents it is
// exactly that. One resident declaring high then sets the admission price for
// the whole pool — which is the floor-pinning vector, arrived at from the
// other side and at a price of one certificate rather than one per identity.
//
// The pool here is ordinary honest traffic: every certificate declares 100
// except one user's newest, who is in a hurry and declares a million. Under the
// rejected rule an arrival at 50,000 — five hundred times the market rate — was
// refused. Note that the rule this replaced admitted it too; this is the one
// place the marginal floor was a regression against the code it replaced, and
// the reason the floor is a minimum again.
func TestOneDearTailCannotSetThePoolsAdmissionPrice(t *testing.T) {
	w := newWorld(t, smallPolicy())

	const (
		market   = 100
		inAHurry = 1_000_000
	)
	high := w.policy.MaxCertificates * int(w.policy.EvictionHighWater) / 100
	need := w.policy.MaxCertificates * int(w.policy.EvictionHighWater-w.policy.EvictionLowWater) / 100
	// Chains long enough that the removable set is smaller than the cut, which
	// is what drives the rejected floor to the top of the pool.
	chains := need - 1
	depth := high / chains
	if chains*depth != high {
		t.Fatalf("setup: %d chains of %d do not fill the pool to %d", chains, depth, high)
	}

	var marketTails []types.Hash
	var dearTail types.Hash
	for i := 0; i < chains; i++ {
		k := key(t, 80_000+i)
		for seq := 0; seq < depth; seq++ {
			price := uint64(market)
			if i == 0 && seq == depth-1 {
				price = inAHurry
			}
			c := w.cert(k, uint64(seq), price, 1)
			if err := w.add(c); err != nil {
				t.Fatalf("chain %d seq %d: %v", i, seq, err)
			}
			if seq == depth-1 {
				if i == 0 {
					dearTail = c.ID()
				} else {
					marketTails = append(marketTails, c.ID())
				}
			}
		}
	}
	if got := w.pool.Stats().Size; got != high {
		t.Fatalf("setup: the pool holds %d certificates, want %d at the high-water mark", got, high)
	}
	if got := w.pool.Stats().Underwriters; got >= need {
		t.Fatalf("setup: %d removable residents is not fewer than the cut of %d, so the "+
			"rejected floor is not being driven to the top of the pool", got, need)
	}

	// Anti-vacuity: the rejected rule really would have refused this arrival, and
	// really would have priced it at the dear tail rather than at the market.
	const arrival = 50_000
	rejectedFloor := nthSmallestDeclaredPrice(t, w, need)
	if !rejectedFloor.Eq(drops(inAHurry)) {
		t.Fatalf("setup: the rejected floor is %s, want %d — the scenario does not reproduce "+
			"the rule it is a regression test for", rejectedFloor, inAHurry)
	}
	if beatsByBumpForTest(drops(arrival), rejectedFloor, w.policy.EvictionBumpPercent) {
		t.Fatalf("the rejected rule would also have admitted an arrival at %d, so this "+
			"scenario does not distinguish the two rules", arrival)
	}

	declared := map[types.Hash]u256.U256{}
	for _, c := range w.pool.Candidates() {
		declared[c.ID()] = c.FeeBid.SeqPriority
	}
	if err := w.add(w.cert(key(t, 81_000), 0, arrival, 1)); err != nil {
		t.Fatalf("an arrival declaring %d was refused by a pool whose residents declare %d, "+
			"because one unrelated certificate declares %d: err=%v",
			arrival, market, inAHurry, err)
	}

	// Admitted — but still bound by the invariant. The dear tail survives, and
	// every certificate that left was one the arrival outbid.
	if !w.pool.Has(dearTail) {
		t.Fatalf("the certificate declaring %d was evicted by an arrival declaring %d",
			inAHurry, arrival)
	}
	removed := 0
	for id, price := range declared {
		if w.pool.Has(id) {
			continue
		}
		removed++
		if !beatsByBumpForTest(drops(arrival), price, w.policy.EvictionBumpPercent) {
			t.Fatalf("an arrival declaring %d removed a certificate declaring %s without "+
				"beating it by the bump", arrival, price)
		}
	}
	if removed == 0 {
		t.Fatal("the arrival was admitted without evicting anything")
	}
	// It should have taken the market-priced tails it outbids, not stopped at one.
	if removed != len(marketTails) {
		t.Fatalf("the arrival removed %d certificates; it outbids %d removable residents "+
			"and the cut is %d, so it should have taken all of them", removed, len(marketTails), need)
	}
	assertNoStrandedChains(t, w)
}

// TestAnEvictionPassSortsOnlyWhatTheArrivalCanTake is the cost half of the
// floor rule, and it is a denial-of-service property rather than a nicety.
//
// Because the floor is the *cheapest* removable declaration, an arrival that
// beats only the pool's cheapest resident is admitted — which is §1's rule and
// the point of the whole section. The failure mode that opens is on the other
// side of the lock: one identity rents the cheapest slot and churns it a drop
// at a time, so every arrival clears the floor (its own previous certificate)
// while every other resident outbids it. If the eviction pass sorts the whole
// removable set before discovering it may take exactly one of them, that is an
// O(n log n) sort under the write lock, per certificate, for the price of one
// deposit cell.
//
// So the invariant and the own-chain rule are applied when the candidate list
// is *built*, not when it is walked, and this pins that they are: the pass sees
// one candidate, not ninety. Timing would be flaky; the candidate count is the
// structural quantity the timing follows from.
func TestAnEvictionPassSortsOnlyWhatTheArrivalCanTake(t *testing.T) {
	w := newWorld(t, smallPolicy())
	high := w.policy.MaxCertificates * int(w.policy.EvictionHighWater) / 100

	// Everyone declares a fortune except the attacker's rented slot.
	const rich = 1_000_000
	for i := 0; w.pool.Stats().Size < high-1; i++ {
		if err := w.add(w.cert(key(t, 30_000+i), 0, rich, 1)); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
	}
	if err := w.add(w.cert(key(t, 31_000), 0, 1, 1)); err != nil {
		t.Fatalf("the rented slot: %v", err)
	}
	if got := w.pool.Stats().Size; got != high {
		t.Fatalf("setup: the pool holds %d, want %d at the high-water mark", got, high)
	}

	// One rung up the ladder. It clears the floor, and it can take exactly the
	// certificate that set the floor.
	arrival := w.cert(key(t, 31_001), 0, 2, 1)
	if got := w.pool.EvictionCandidateCount(arrival); got != 1 {
		t.Fatalf("the pass would sort %d candidates for an arrival that can take one of "+
			"them; the invariant is being applied while walking the order instead of while "+
			"building it, so the sort is over the whole pool", got)
	}
	// Anti-vacuity: the count is not trivially one. An arrival that outbids
	// everybody sees the whole removable set.
	whale := w.cert(key(t, 31_002), 0, rich*2, 1)
	if got, want := w.pool.EvictionCandidateCount(whale), w.pool.Stats().Underwriters; got != want {
		t.Fatalf("an arrival that outbids every resident sees %d candidates, want %d — the "+
			"filter is dropping certificates it should not", got, want)
	}

	// And the behaviour the count is a proxy for is unchanged: exactly one
	// eviction, and it is the certificate the arrival outbid.
	before := w.pool.Stats()
	if err := w.add(arrival); err != nil {
		t.Fatalf("the arrival was refused: %v", err)
	}
	if got := w.pool.Stats().Evicted - before.Evicted; got != 1 {
		t.Fatalf("the pass evicted %d certificates, want 1", got)
	}
	assertNoStrandedChains(t, w)
}

// TestOccupancyNeverRisesAboveTheHighWaterMark pins what makes the pool's hard
// cap unreachable, and it is the reason the floor and the candidate set are one
// function rather than two.
//
// The floor is a minimum. Read it over every *removable* resident and a user
// extending their own chain sets it with their own cheap base — a certificate
// §2.3 then forbids the pass to take. The gate says yes at a price no candidate
// carries, the pass finds nothing to do, and the arrival is admitted having
// outbid nobody. Occupancy climbs past the high-water mark on every such
// arrival, up to `MaxCertificates`, and hysteresis never engages.
//
// Reading it over the residents this arrival *could* take instead makes the two
// agree: clearing the floor means beating the cheapest candidate, so an accepted
// pass always removes at least one certificate. The user above is refused with
// ErrBelowEvictionFloor, which is the honest answer — every certificate they
// could have displaced outbids them.
func TestOccupancyNeverRisesAboveTheHighWaterMark(t *testing.T) {
	w := newWorld(t, smallPolicy())
	high := w.policy.MaxCertificates * int(w.policy.EvictionHighWater) / 100

	const rich = 1_000_000
	for i := 0; w.pool.Stats().Size < high-1; i++ {
		if err := w.add(w.cert(key(t, 32_000+i), 0, rich, 1)); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
	}
	extender := key(t, 33_000)
	if err := w.add(w.cert(extender, 0, 1, 1)); err != nil {
		t.Fatalf("chain base: %v", err)
	}
	if got := w.pool.Stats().Size; got != high {
		t.Fatalf("setup: the pool holds %d, want %d", got, high)
	}

	// Anti-vacuity: a floor read over every removable resident — the rejected
	// rule — would be this user's own base, and would have admitted them.
	overRemovable := nthSmallestDeclaredPrice(t, w, 1)
	if !overRemovable.Eq(drops(1)) {
		t.Fatalf("setup: the cheapest removable declaration is %s, want 1 — the scenario "+
			"does not distinguish the two floors", overRemovable)
	}
	extension := w.cert(extender, 1, 2, 1)
	if !beatsByBumpForTest(drops(2), overRemovable, w.policy.EvictionBumpPercent) {
		t.Fatal("the rejected floor would also have refused this extension, so this " +
			"scenario does not distinguish the two rules")
	}

	// The arrival's own chain base is not a candidate, so it does not set the
	// price the arrival is judged at.
	if got := w.pool.EvictionCandidateCount(extension); got != 0 {
		t.Fatalf("the pass offers %d candidates to an arrival that may take none of them "+
			"— its own chain base is being counted as removable", got)
	}
	err := w.add(extension)
	if !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("an arrival declaring 2 was admitted against a pool in which every "+
			"certificate it could take declares %d: err=%v", rich, err)
	}
	if got := w.pool.Stats().Size; got != high {
		t.Fatalf("the pool holds %d certificates, above the high-water mark of %d, on an "+
			"arrival that evicted nothing", got, high)
	}
	if got := w.pool.Stats().Evicted; got != 0 {
		t.Fatalf("the pass evicted %d certificates, all of which outbid the arrival", got)
	}

	// And the general property, over a mixed workload: every accepted arrival
	// removes at least one certificate, so occupancy never leaves the band.
	for i := 0; i < 200; i++ {
		price := uint64(rich) + uint64(i)*rich/5
		before := w.pool.Stats()
		if err := w.add(w.cert(key(t, 34_000+i), 0, price, 1)); err != nil {
			continue
		}
		if w.pool.Stats().Evicted == before.Evicted && before.Size >= high {
			t.Fatalf("arrival %d was admitted at high water without evicting anything", i)
		}
		if got := w.pool.Stats().Size; got > high {
			t.Fatalf("the pool holds %d certificates, above the high-water mark of %d", got, high)
		}
	}
	assertNoStrandedChains(t, w)
}

// TestFeeBumpedChainsDoNotCollapseTheEvictionFloor is the regression witness, and
// it contains no attacker at all.
//
// Every resident here is either an independent certificate declaring a million or
// an ordinary two-certificate fee bump: Seq 0 at 1, Seq 1 at a million. A floor
// read from chain prices — the minimum over a chain's members — is the *base's*
// price, while the certificate the pass removes is the *tail*. Once as many as
// `need` residents are fee-bumped chains, every chain price at the low-water cut
// is a base price, the floor collapses to the cheap end, and an arrival declaring
// 2 removes `need` certificates declaring a million.
//
// The threshold is exactly need = highWater - lowWater, which is ten under
// smallPolicy and a thousand under the shipped defaults — about 11% of the pool
// in fee-bumping traffic, which is a busy day rather than an attack budget. The
// test sits at the threshold on purpose.
func TestFeeBumpedChainsDoNotCollapseTheEvictionFloor(t *testing.T) {
	w := newWorld(t, smallPolicy())

	const (
		dear         = 1_000_000
		base         = 1
		arrivalPrice = 2
	)
	// need = highWater - lowWater, computed from the policy rather than written
	// down, so the witness tracks the threshold if the water marks move.
	need := w.policy.MaxCertificates*int(w.policy.EvictionHighWater)/100 -
		w.policy.MaxCertificates*int(w.policy.EvictionLowWater)/100

	var tails []types.Hash
	for i := 0; i < need; i++ {
		signer := key(t, 80_000+i)
		if err := w.add(w.cert(signer, 0, base, 1)); err != nil {
			t.Fatalf("chain %d base: %v", i, err)
		}
		tail := w.cert(signer, 1, dear, 1)
		if err := w.add(tail); err != nil {
			t.Fatalf("chain %d tail: %v", i, err)
		}
		tails = append(tails, tail.ID())
	}
	var singles []types.Hash
	for i := 0; w.pool.Stats().Size < 90; i++ {
		c := w.cert(key(t, 81_000+i), 0, dear, 1)
		if err := w.add(c); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
		singles = append(singles, c.ID())
	}

	// Anti-vacuity: the rejected rule — the need-th smallest *chain* price — would
	// have admitted this arrival in this same scenario, because all need of the
	// cheapest chain prices are the bases at 1.
	rejectedFloor := nthSmallestChainPrice(t, w, need)
	if !rejectedFloor.Eq(drops(base)) {
		t.Fatalf("setup: the rejected floor is %s, want %d — fewer than %d cheap-based chains "+
			"are pooled, so this scenario does not reach the threshold", rejectedFloor, base, need)
	}
	if !beatsByBumpForTest(drops(arrivalPrice), rejectedFloor, w.policy.EvictionBumpPercent) {
		t.Fatalf("the rejected rule would also have refused an arrival at %d against a floor of "+
			"%s, so this scenario does not distinguish the two rules", arrivalPrice, rejectedFloor)
	}

	evictedBefore := w.pool.Stats().Evicted
	err := w.add(w.cert(key(t, 82_000), 0, arrivalPrice, 1))
	if !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("an arrival declaring %d was admitted against a pool in which every removable "+
			"certificate declares %d: the floor is read from chain minimums while the pass "+
			"removes tails (err=%v)", arrivalPrice, dear, err)
	}
	for i, id := range tails {
		if !w.pool.Has(id) {
			t.Fatalf("fee-bumped tail %d, declaring %d, was evicted by an arrival declaring %d",
				i, dear, arrivalPrice)
		}
	}
	for i, id := range singles {
		if !w.pool.Has(id) {
			t.Fatalf("resident %d, declaring %d, was evicted by an arrival declaring %d",
				i, dear, arrivalPrice)
		}
	}
	if w.pool.Stats().Evicted != evictedBefore {
		t.Fatalf("a refused arrival evicted %d certificates", w.pool.Stats().Evicted-evictedBefore)
	}

	// A floor, not a wall: an arrival that does beat the residents by the bump is
	// admitted and does evict.
	if err := w.add(w.cert(key(t, 83_000), 0, dear+dear/10, 1)); err != nil {
		t.Fatalf("an arrival that outbids every resident it removes was refused: %v", err)
	}
	if w.pool.Stats().Evicted == evictedBefore {
		t.Fatal("the qualifying arrival was admitted without evicting anything")
	}
	assertNoStrandedChains(t, w)
}

// TestAnArrivalNeverEvictsItsOwnChainBase is §2.3 from the arrival's side, and it
// needs no reorg — an ordinary user extending their own chain reaches it.
//
// The eviction pass ranks chains as units, so a user whose Seq 0 declares little
// has the cheapest chain in the pool. When their Seq 1 arrives at a price that
// clears the floor, the first victim in the order is that same user's Seq 0 — and
// removing it while admitting the certificate that depends on it is the hole the
// whole eviction rule exists to avoid, created on behalf of the arrival.
func TestAnArrivalNeverEvictsItsOwnChainBase(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// Fill to one below the high-water mark, so the base lands without an
	// eviction pass and the *tail's* arrival is what triggers one.
	for i := 0; w.pool.Stats().Size < 89; i++ {
		if err := w.add(w.cert(key(t, 95_000+i), 0, 1_000, 1)); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
	}

	signer := key(t, 96_000)
	base := w.cert(signer, 0, 1, 1)
	if err := w.add(base); err != nil {
		t.Fatalf("chain base: %v", err)
	}
	if got := w.pool.Stats().Size; got != 90 {
		t.Fatalf("setup: the pool holds %d certificates, want 90 at the high-water mark", got)
	}
	// Anti-vacuity: the base must be the cheapest chain in the pool, or the
	// eviction order would not reach it first and the scenario proves nothing.
	if floor := minChainPrice(t, w); !floor.Eq(drops(1)) {
		t.Fatalf("setup: the cheapest chain price is %s, want 1 — the arrival's own base is not "+
			"at the head of the eviction order", floor)
	}

	tail := w.cert(signer, 1, 100_000, 1)
	if err := w.add(tail); err != nil {
		t.Fatalf("chain tail: %v", err)
	}
	if w.pool.Has(tail.ID()) && !w.pool.Has(base.ID()) {
		t.Fatal("the arrival evicted its own Seq 0 to make room for its Seq 1: the chain has a " +
			"hole and the admitted certificate is guaranteed to skip")
	}
	assertNoStrandedChains(t, w)

	// The rule is `Seq <`, and the bound matters in both directions. An arrival
	// may still take its own underwriter's certificates at or above its own Seq:
	// what it depends on is the chain *below* it, and removing anything above
	// strands nothing. Widening the exclusion to the whole underwriter would be
	// strictly more conservative and would pass every other assertion in this
	// file, which is why this one exists.
	other := newWorld(t, smallPolicy())
	holder := key(t, 98_000)
	for seq := 0; seq < 2; seq++ {
		if err := other.add(other.cert(holder, uint64(seq), 1, 1)); err != nil {
			t.Fatalf("holder seq %d: %v", seq, err)
		}
	}
	for i := 0; other.pool.Stats().Size < 90; i++ {
		if err := other.add(other.cert(key(t, 97_000+i), 0, 1_000, 1)); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
	}
	holderTail := other.cert(holder, 1, 1, 1)
	if !other.pool.Has(holderTail.ID()) {
		t.Fatal("setup: the holder's own tail is not pooled, so the bound is not exercised")
	}
	// A fresh Seq 0 from the same underwriter. Its underwriter's pooled tail sits
	// at Seq 1, above it, so that tail must be a candidate.
	fresh := other.cert(holder, 0, 100_000, 1)
	sawOwnTail := false
	for _, c := range other.pool.Candidates() {
		if c.ID() == holderTail.ID() {
			sawOwnTail = true
		}
	}
	if !sawOwnTail {
		t.Fatal("setup: the holder's tail left the pool before the measurement")
	}
	if got := other.pool.EvictionCandidateCount(fresh); got == 0 {
		t.Fatal("an arrival at Seq 0 sees no candidate at all, though its own underwriter's " +
			"pooled certificates sit above it and the rest of the pool declares less: the " +
			"own-chain exclusion is wider than the chain the arrival depends on")
	}
	if err := other.add(fresh); err != nil {
		t.Fatalf("an arrival at Seq 0 outbidding the whole pool was refused: %v", err)
	}
	if other.pool.Has(holderTail.ID()) {
		t.Fatal("the arrival did not take its own underwriter's tail at a higher Seq, which " +
			"it may: nothing depends on that certificate")
	}
	assertNoStrandedChains(t, other)

	// The bound is strict for a reason, and this is the case that decides it:
	// replace-by-fee. Seq is an ordering key, not a nonce, so raising a bid means
	// pooling a *second* certificate at the same Seq. Under `Seq <` the stale one
	// is a candidate and the re-bid displaces it. Under `Seq <=` it is excluded,
	// the re-bid sees nothing it may take, and a user cannot outbid their own
	// stale certificate in a full pool.
	rbf := newWorld(t, smallPolicy())
	rebidder := key(t, 99_000)
	stale := rbf.cert(rebidder, 0, 1, 1)
	if err := rbf.add(stale); err != nil {
		t.Fatalf("stale bid: %v", err)
	}
	for i := 0; rbf.pool.Stats().Size < 90; i++ {
		if err := rbf.add(rbf.cert(key(t, 94_000+i), 0, 1_000_000, 1)); err != nil {
			t.Fatalf("resident %d: %v", i, err)
		}
	}
	rebid := rbf.cert(rebidder, 0, 100, 1)
	if got := rbf.pool.EvictionCandidateCount(rebid); got != 1 {
		t.Fatalf("a re-bid at the same Seq sees %d candidates, want 1 — its own stale "+
			"certificate is the only thing it outbids, and excluding it means a user "+
			"cannot replace their own bid in a full pool", got)
	}
	if err := rbf.add(rebid); err != nil {
		t.Fatalf("a re-bid at the same Seq, outbidding its own stale certificate, was "+
			"refused: %v", err)
	}
	if rbf.pool.Has(stale.ID()) || !rbf.pool.Has(rebid.ID()) {
		t.Fatalf("the re-bid did not replace the stale certificate: stale pooled=%v, "+
			"re-bid pooled=%v", rbf.pool.Has(stale.ID()), rbf.pool.Has(rebid.ID()))
	}
	assertNoStrandedChains(t, rbf)
}

// TestReadmitNeverHolesADependentChain closes §2.3 through the front door.
//
// Eviction is careful never to hole a chain. Readmission was not: it fed a
// reorg's certificates to Add one at a time, discarded the errors, and Add gates
// each certificate individually against a pool that is at its high-water mark
// during a reorg. A member refused — or admitted and then evicted by the very
// next member's own eviction pass — left everything above it pooled and
// guaranteed to skip, which is precisely the state §2.3 exists to prevent.
//
// The sweep is over *which* member is the cheap one, because that is what decides
// where the pass bites. On main the holes appeared at the high-water boundaries;
// with chain-unit ordering they appeared almost everywhere, since one cheap
// member makes the whole chain the pool's first victim while its own successors
// are still being readmitted.
func TestReadmitNeverHolesADependentChain(t *testing.T) {
	const chainLen = 40

	for cheapAt := 0; cheapAt < chainLen; cheapAt++ {
		w := newWorld(t, smallPolicy())
		w.fillToHighWater(1_000)

		signer := key(t, 90_000)
		var branch []*types.Certificate
		for seq := 0; seq < chainLen; seq++ {
			price := uint64(50_000)
			if seq == cheapAt {
				price = 1
			}
			branch = append(branch, w.cert(signer, uint64(seq), price, 1))
		}
		w.pool.Readmit(branch, w.state, 1)

		var seqs []uint64
		for _, c := range w.pool.Candidates() {
			if c.UnderwriterID() == signer.Persistent() {
				seqs = append(seqs, c.Seq)
			}
		}
		present := map[uint64]bool{}
		for _, s := range seqs {
			present[s] = true
		}
		for s := 0; s < chainLen; s++ {
			if !present[uint64(s)] {
				// Everything above the first gap must be absent too.
				for above := s + 1; above < chainLen; above++ {
					if present[uint64(above)] {
						t.Fatalf("cheap member at Seq %d: the readmitted chain holds Seq %d but "+
							"not Seq %d — the chain has a hole and everything above it is stranded",
							cheapAt, above, s)
					}
				}
				break
			}
		}
		assertNoStrandedChains(t, w)
	}
}

// certWithBounds is `cert` with the ceiling and the deadline chosen, so a
// chain's members can differ in what a rescreen will judge them by. A user
// setting a modest bound on a routine payment and a higher one on an urgent
// follow-up is ordinary; the shared harness cannot express it.
func (w *world) certWithBounds(signer *wallet.Key, seq, seqMax, seqPriority, ttl uint64) *types.Certificate {
	w.t.Helper()
	addr := signer.Persistent()
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, addr, key(w.t, 9999).Persistent(), drops(1_000)),
		Seq:     seq,
		TTL:     ttl,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  wallet.Bid(drops(seqMax), drops(seqPriority), drops(1_000_000), drops(1)),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		w.t.Fatal(err)
	}
	ceiling, ok := c.FeeCeiling(w.p)
	if !ok {
		w.t.Fatal("ceiling overflow")
	}
	// Additively, never flat and never merely raised to this cert's own
	// requirement. Members of one chain share a deposit cell but not their
	// ceilings, and the deposit screen is a *sum* across everything a cell
	// backs — so funding for the largest single ceiling still underfunds
	// a chain of two, which the rescreen would then drop for a reason the test
	// is not about.
	slot := types.NativeBalanceSlot(addr)
	w.state.Set(slot, w.state.Get(slot).SatAdd(ceiling).SatAdd(drops(1_000_000_000)))
	return c
}

// TestRescreenTruncatesAChainItStrands is §2.3's third door.
//
// The eviction pass truncates from the tail and Readmit restores a prefix, but
// the rescreen sweep answers to neither: a certificate that has stopped being
// admissible has to go wherever in a chain it sits. Dropping the middle strands
// everything above it — certificates that can never apply, offered to miners
// forever, which is the state §2.3 exists to prevent.
//
// Both witnesses are ordinary traffic. Neither needs an attacker, and neither
// needs anything more exotic than a chain whose members declare different
// ceilings or different deadlines.
//
// The fourth doom reason is deliberately *not* stranding, and the test pins that
// too: a committed base means its successor is next in line, and truncating
// there would throw away the chain that is about to become the pool's most
// valuable. A fix that truncated on every reason would pass the first two
// assertions and fail the third.
func TestRescreenTruncatesAChainItStrands(t *testing.T) {
	t.Run("the base falls below a risen base fee", func(t *testing.T) {
		w := newWorld(t, smallPolicy())
		k := key(t, 60_400)
		base := w.certWithBounds(k, 0, 10_000, 100, 20)
		tail := w.certWithBounds(k, 1, 5_000_000, 100, 20)
		for _, c := range []*types.Certificate{base, tail} {
			if err := w.add(c); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		// Above the base's maximum, below the tail's.
		w.state.Set(types.SeqBaseFeeSlot(), drops(20_000))
		w.pool.Rescreen(w.state, 1)

		if w.pool.Has(base.ID()) {
			t.Fatal("setup: the base survived the rescreen, so nothing was stranded and " +
				"this scenario proves nothing")
		}
		if w.pool.Has(tail.ID()) {
			t.Fatal("the base was dropped for being under the base fee — it never applied — " +
				"and its Seq 1 is still pooled: it can never apply either, and the pool will " +
				"keep offering miners work guaranteed to skip")
		}
		assertNoStrandedChains(t, w)
	})

	t.Run("the base's TTL expires first", func(t *testing.T) {
		w := newWorld(t, smallPolicy())
		k := key(t, 60_500)
		base := w.certWithBounds(k, 0, 1_000_000, 100, 12)
		tail := w.certWithBounds(k, 1, 1_000_000, 100, 30)
		for _, c := range []*types.Certificate{base, tail} {
			if err := w.add(c); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		w.pool.Rescreen(w.state, 15) // next = 16: past the base's TTL, not the tail's

		if w.pool.Has(base.ID()) {
			t.Fatal("setup: the base survived, so nothing was stranded")
		}
		if w.pool.Has(tail.ID()) {
			t.Fatal("the base expired and its Seq 1 is still pooled: the chain is holed and " +
				"the survivor can never apply")
		}
		assertNoStrandedChains(t, w)
	})

	t.Run("a committed base is not stranding", func(t *testing.T) {
		w := newWorld(t, smallPolicy())
		k := key(t, 60_600)
		base := w.certWithBounds(k, 0, 1_000_000, 100, 20)
		tail := w.certWithBounds(k, 1, 1_000_000, 100, 20)
		for _, c := range []*types.Certificate{base, tail} {
			if err := w.add(c); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		w.state.MarkSeen(base.ID(), 1)
		w.pool.Rescreen(w.state, 1)

		if w.pool.Has(base.ID()) {
			t.Fatal("setup: a committed certificate was not dropped")
		}
		if !w.pool.Has(tail.ID()) {
			t.Fatal("the base committed, so its Seq 1 is next in line — truncating there " +
				"throws away a chain that is about to become the pool's most valuable")
		}
	})

	t.Run("the cut is the lowest stranding Seq, not any of them", func(t *testing.T) {
		// Seq 1 and Seq 3 both fall below the risen base fee. Truncating from
		// Seq 3 would leave Seq 2 pooled with its predecessor gone — still
		// stranded, and *which* Seq got picked would depend on map iteration
		// order, so two nodes would disagree. The cut has to be the minimum.
		for repeat := 0; repeat < 20; repeat++ {
			w := newWorld(t, smallPolicy())
			k := key(t, 60_800)
			var chain []*types.Certificate
			for seq := uint64(0); seq < 4; seq++ {
				max := uint64(5_000_000)
				if seq == 1 || seq == 3 {
					max = 10_000 // doomed by the risen base fee
				}
				c := w.certWithBounds(k, seq, max, 100, 20)
				chain = append(chain, c)
				if err := w.add(c); err != nil {
					t.Fatalf("seq %d: %v", seq, err)
				}
			}
			w.state.Set(types.SeqBaseFeeSlot(), drops(20_000))
			w.pool.Rescreen(w.state, 1)

			if !w.pool.Has(chain[0].ID()) {
				t.Fatal("setup: Seq 0 was dropped, so the cut is not where the test thinks")
			}
			if w.pool.Has(chain[1].ID()) || w.pool.Has(chain[3].ID()) {
				t.Fatal("setup: a certificate under the base fee survived the rescreen")
			}
			if w.pool.Has(chain[2].ID()) {
				t.Fatalf("repeat %d: Seq 2 is still pooled although Seq 1 was dropped and "+
					"never applied — the cut was taken at a stranding Seq other than the "+
					"lowest, which also makes it depend on map iteration order", repeat)
			}
			assertNoStrandedChains(t, w)
		}
	})

	t.Run("a duplicate at the lowest vacancy does not cover a higher one", func(t *testing.T) {
		// The shape a whole-underwriter re-occupancy veto gets wrong. Seq 0 is
		// vacated and immediately re-occupied by its own duplicate, so the chain
		// is still reachable through Seq 0 — but Seq 1 is vacated with nothing
		// standing in it, and everything above Seq 1 is therefore stranded. A
		// rule that asks "does a survivor sit at the *lowest* vacated Seq?" and
		// then exempts the whole underwriter leaves Seq 2 pooled and guaranteed
		// to skip. The cut is 1, not 0.
		w := newWorld(t, smallPolicy())
		k := key(t, 60_900)
		dropped0 := w.certWithBounds(k, 0, 1_000_000, 100, 12)  // vacates Seq 0
		standing0 := w.certWithBounds(k, 0, 1_000_000, 101, 30) // re-occupies it
		dropped1 := w.certWithBounds(k, 1, 1_000_000, 100, 12)  // vacates Seq 1
		top := w.certWithBounds(k, 2, 1_000_000, 100, 30)
		for _, c := range []*types.Certificate{dropped0, standing0, dropped1, top} {
			if err := w.add(c); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		w.pool.Rescreen(w.state, 15) // next = 16: TTL 12 has passed, TTL 30 has not

		if w.pool.Has(dropped0.ID()) || w.pool.Has(dropped1.ID()) {
			t.Fatal("setup: an expired certificate survived the rescreen")
		}
		if !w.pool.Has(standing0.ID()) {
			t.Fatal("setup: the surviving Seq 0 was dropped, so there is no duplicate at " +
				"the lowest vacancy and the scenario is not the one being tested")
		}
		if w.pool.Has(top.ID()) {
			t.Fatal("Seq 2 is still pooled although Seq 1 was vacated with nothing standing " +
				"in it: re-occupancy was tested for the underwriter rather than for each " +
				"vacated Seq, so a duplicate at Seq 0 covered a hole at Seq 1")
		}
	})

	t.Run("a duplicate Seq keeps the chain reachable", func(t *testing.T) {
		w := newWorld(t, smallPolicy())
		k := key(t, 60_700)
		// Two certificates at Seq 0: one will be dropped, one will not. Seq is an
		// ordering key rather than a nonce, so the survivor still carries the
		// chain and Seq 1 must stay.
		doomed := w.certWithBounds(k, 0, 10_000, 100, 20)
		alive := w.certWithBounds(k, 0, 5_000_000, 100, 20)
		tail := w.certWithBounds(k, 1, 5_000_000, 100, 20)
		for _, c := range []*types.Certificate{doomed, alive, tail} {
			if err := w.add(c); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		w.state.Set(types.SeqBaseFeeSlot(), drops(20_000))
		w.pool.Rescreen(w.state, 1)

		if w.pool.Has(doomed.ID()) {
			t.Fatal("setup: the doomed certificate survived")
		}
		if !w.pool.Has(alive.ID()) {
			t.Fatal("setup: the surviving Seq 0 was dropped, so the scenario is not about " +
				"a duplicate Seq at all")
		}
		if !w.pool.Has(tail.ID()) {
			t.Fatal("Seq 1 was truncated although another Seq 0 is still pooled and can " +
				"still carry the chain: the rule is reading the removal rather than the " +
				"state it left behind")
		}
	})
}

// TestEvictionHysteresis: eviction engages at the high-water mark and clears to
// the low-water mark, so the marginal certificate does not thrash on every
// arrival.
func TestEvictionHysteresis(t *testing.T) {
	w := newWorld(t, smallPolicy())

	atHighWater := w.fillToHighWater(1_000)

	// One qualifying arrival should clear down to the low-water mark, not evict
	// exactly one and sit at capacity.
	if err := w.add(w.cert(key(t, 9000), 0, 100_000, 1)); err != nil {
		t.Fatal(err)
	}
	after := w.pool.Stats().Size
	if after >= atHighWater {
		t.Fatalf("the pool stayed at %d after an eviction; there is no hysteresis gap", after)
	}

	// The gap is the point: the next several arrivals must fit without evicting
	// anything at all. A pool that evicts on every arrival is thrashing, and
	// every eviction is a certificate the network re-gossips.
	evictedBefore := w.pool.Stats().Evicted
	for i := 0; i < 5; i++ {
		if err := w.add(w.cert(key(t, 9100+i), 0, 100_000, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if w.pool.Stats().Evicted != evictedBefore {
		t.Fatalf("arrivals below the high-water mark evicted %d certificates; the pool is thrashing",
			w.pool.Stats().Evicted-evictedBefore)
	}
}

// TestEvictionIsDeterministic: two pools given the same arrivals in the same
// order must hold the same set. Not consensus — but a node that cannot be
// reproduced against its own logs cannot be debugged from a bug report.
func TestEvictionIsDeterministic(t *testing.T) {
	build := func() map[types.Hash]bool {
		w := newWorld(t, smallPolicy())
		for i := 0; i < 140; i++ {
			_ = w.add(w.cert(key(t, i), 0, uint64(i%7)*1_000+1, 1))
		}
		out := map[types.Hash]bool{}
		for _, c := range w.pool.Candidates() {
			out[c.ID()] = true
		}
		return out
	}

	first := build()
	for round := 0; round < 5; round++ {
		again := build()
		if len(again) != len(first) {
			t.Fatalf("round %d holds %d certificates, first held %d", round, len(again), len(first))
		}
		for id := range first {
			if !again[id] {
				t.Fatalf("round %d holds a different set; eviction is not deterministic", round)
			}
		}
	}
}

// TestPerSenderQuotaStillBinds: price-eviction must not let one funded identity
// own the pool. The quota is what forces an attacker to spread across
// identities, each of which must be funded from mined coins.
func TestPerSenderQuotaStillBinds(t *testing.T) {
	pol := smallPolicy()
	pol.MaxPerUnderwriter = 3
	w := newWorld(t, pol)

	whale := key(t, 777)
	var admitted int
	for seq := uint64(0); seq < 12; seq++ {
		if err := w.add(w.cert(whale, seq, 1_000_000, 1)); err == nil {
			admitted++
		}
	}
	if admitted > pol.MaxPerUnderwriter {
		t.Fatalf("one identity placed %d certificates against a quota of %d",
			admitted, pol.MaxPerUnderwriter)
	}
}

// TestAdmissionRequiresACoveredDepositIsTheSybilDefence pins §2.5.
//
// The per-sender quota bounds one *identity*, and identities cost nothing to
// make — so the quota cannot be what makes flooding expensive. The deposit
// screen is: a certificate is admitted only if its signer's deposit is covered
// by funds that exist in state now, which in Era 0 means mined coins.
//
// The test is written so that the quota cannot be what refuses the certificates
// (every one comes from a distinct identity) and so that the *only* difference
// between the admitted and refused cases is whether the cell is funded.
func TestAdmissionRequiresACoveredDepositIsTheSybilDefence(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// A hundred unfunded identities: free to generate, and each one distinct so
	// the per-underwriter quota never binds.
	var admitted int
	for i := 0; i < 100; i++ {
		signer := key(t, 20_000+i)
		c := w.cert(signer, 0, 1_000, 1)
		// w.cert funds the deposit cell for convenience. Undo that: an attacker
		// with a fresh key has nothing.
		w.state.Set(types.NativeBalanceSlot(signer.Persistent()), drops(0))
		if err := w.add(c); err == nil {
			admitted++
		} else if !errors.Is(err, mempool.ErrUnderfunded) {
			t.Fatalf("identity %d was refused for the wrong reason: %v", i, err)
		}
	}
	if admitted != 0 {
		t.Fatalf("%d unfunded identities placed certificates; keys are free, so the "+
			"pool is flooded at no cost", admitted)
	}

	// Anti-vacuity: the same certificates, from the same kind of fresh identity,
	// are admitted once the deposit is covered. Without this the test above
	// would pass against a pool that refuses everything.
	funded := key(t, 30_000)
	c := w.cert(funded, 0, 1_000, 1)
	if err := w.add(c); err != nil {
		t.Fatalf("a funded identity was refused, so the test above proves nothing: %v", err)
	}
}

// TestIDsAgreesWithItselfAtEveryBound: a bounded request does bounded work and
// returns the same prefix the unbounded one would.
//
// The pending list is the surface's second asymmetric answer — a short request
// that used to copy and sort the whole pool under the read lock no matter how
// few ids were asked for, contending with the relay's Add and the miner's
// Candidates on every poll. Only /block carries a byte budget, so this one has
// to be cheap by construction instead. Swapping a full sort for a bounded
// selection is only safe if the two agree, which is what this pins.
func TestIDsAgreesWithItselfAtEveryBound(t *testing.T) {
	w := newWorld(t, smallPolicy())
	w.fillToHighWater(100)

	full := w.pool.IDs(-1)
	if len(full) < 8 {
		t.Fatalf("setup: the pool holds %d certificates, too few to measure a bound", len(full))
	}
	// The unbounded answer is sorted, which every bounded one is a prefix of.
	for i := 1; i < len(full); i++ {
		if string(full[i-1][:]) >= string(full[i][:]) {
			t.Fatal("setup: the unbounded list is not in id order")
		}
	}

	for _, limit := range []int{1, 2, len(full) / 2, len(full) - 1} {
		got := w.pool.IDs(limit)
		if len(got) != limit {
			t.Fatalf("IDs(%d) returned %d ids", limit, len(got))
		}
		for i := range got {
			if got[i] != full[i] {
				t.Fatalf("IDs(%d)[%d] = %x, but the full order has %x there: the "+
					"bounded selection and the total one disagree, so a reader sees "+
					"a different pool depending on how much of it it asked for",
					limit, i, got[i][:8], full[i][:8])
			}
		}
	}
	if n := len(w.pool.IDs(len(full) + 10)); n != len(full) {
		t.Fatalf("a limit above the pool size returned %d ids, want %d", n, len(full))
	}
	if n := len(w.pool.IDs(0)); n != 0 {
		t.Fatalf("IDs(0) returned %d ids", n)
	}
}

// TestIDsDoesWorkProportionalToTheAnswer arms the bound itself.
//
// TestIDsAgreesWithItselfAtEveryBound pins that the bounded selection returns
// the same prefix the total order would — which is the correctness half, and
// which a full sort followed by a truncation also satisfies. The reason for the
// selection is the other half: a poll asking for ten ids must not copy and sort
// the whole pool under the read lock, contending with the relay's Add and the
// miner's Candidates every time.
//
// Without this the property that motivated the change is undefended, and a
// later refactor puts the full sort back in green.
func TestIDsDoesWorkProportionalToTheAnswer(t *testing.T) {
	// A pool big enough that "proportional to the pool" and "proportional to
	// the answer" are different numbers. smallPolicy holds ninety, which is not.
	pol := smallPolicy()
	pol.MaxCertificates = 800
	w := newWorld(t, pol)
	held := w.fillToHighWater(100)
	if held < 200 {
		t.Fatalf("setup: the pool holds %d certificates, too few for the two costs "+
			"to be distinguishable", held)
	}

	const limit = 8
	allocated := func(n int) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := 0; i < 200; i++ {
			sink = w.pool.IDs(n)
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / 200
	}

	small := allocated(limit)
	whole := allocated(-1)

	// The unbounded call is the yardstick: it genuinely has to materialise the
	// pool, so it shows what "proportional to the pool" costs on this fixture.
	if whole < uint64(held)*32 {
		t.Fatalf("setup: listing the whole pool allocated %d bytes for %d ids, "+
			"which is too little to be measuring what this test thinks", whole, held)
	}
	// A bounded answer must not be within an order of magnitude of it.
	if small > whole/10 {
		t.Fatalf("IDs(%d) allocated %d bytes against %d for the whole pool of %d: "+
			"the bounded request is doing work proportional to the pool rather "+
			"than to the answer, which is a copy and a sort of everything under "+
			"the read lock on every poll", limit, small, whole, held)
	}
}

// sink defeats the optimiser without changing what is measured.
var sink []types.Hash
