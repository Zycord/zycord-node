package p2p

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/spec"
)

// Peer exchange is the one handler a peer can drive whose work was proportional
// to the whole peer store rather than to the reply. The tests here pin
// the two halves of the answer: the store-sized work is bounded by elapsed time
// rather than by request count, and asking again inside that window is priced.
//
// A rule this file learned the hard way, three times, and which is why some of
// the tests below look redundant:
//
//	When a test's name generalises over a conjunction, count the conjuncts and
//	check each one has an input that separates them. A guard with k terms needs
//	k separating inputs, not one passing test.
//
// liveSubset is "banned OR evicted" and only banned was separated; the memo key
// is "same exclude AND same n" and only exclude was separated. Both times the
// mutated and unmutated expressions agreed on every input the existing test
// produced, so no amount of running it could catch the mutant, while the test's
// name said it was covered. Both were found by mutation and neither would have
// been found by reading. The check is cheap and does not need a run: read the
// guard, count its terms, and find the input that distinguishes each one.
//
// It is also why several tests below assert a *negative* about their own
// fixture - that the victim is not banned, that the two counts genuinely differ.
// Those lines are not decoration; without them the other conjunct carries the
// test and the pairing above stops being a pairing.

// getPeersEngine builds an engine whose only interesting state is a peer store
// of n addresses, with both clocks under the test's control.
func getPeersEngine(t *testing.T, n int, clock *time.Time) (*Engine, *PeerStore) {
	t.Helper()
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	peers.now = func() time.Time { return *clock }
	fillPeerStore(t, peers, n)
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, pow.Dev{}, "n:1")
	e.Now = func() time.Time { return *clock }
	return e, peers
}

// fillPeerStore adds n addresses spread over many /16s, so the diversity pass
// has real work to do rather than collapsing onto the first group.
func fillPeerStore(t *testing.T, ps *PeerStore, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ps.Add(fmt.Sprintf("%d.%d.%d.%d:8333", 10+(i/65536)%200, (i/256)%256, i%256, 1))
	}
	if ps.Len() != n {
		t.Fatalf("fixture holds %d entries, wanted %d", ps.Len(), n)
	}
}

// getPeersHandshake completes the one handshake Handle requires before it will
// serve anything, so these tests run through the real dispatcher.
func getPeersHandshake(t *testing.T, e *Engine, addr string) {
	t.Helper()
	h := Hello{Protocol: ProtocolVersion, NetworkID: e.Chain.NetworkID(), ListenAddr: addr}
	if v := e.Handle(addr, KindHello, h.MarshalHello()); v.Err != nil {
		t.Fatalf("handshake refused: %v", v.Err)
	}
}

// TestGetPeersServedWorkIsBoundedByTimeNotByRequestCount pins the property the
// memo exists for: inside one DiverseCacheTTL the store-sized selection runs
// once however many times it is asked for, and it runs again once the window
// has passed.
//
// It observes the rebuild rather than counting it, and it observes it through
// the only thing a rebuild can change: a new best address the store now holds.
// Before the memo that address appeared in the very next reply; after it, it
// appears only once the window closes.
func TestGetPeersServedWorkIsBoundedByTimeNotByRequestCount(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 512, &clock)

	first := servedPeers(t, e, "10.66.0.1:5000")
	if len(first) == 0 {
		t.Fatal("the fixture served nothing; this test would assert nothing")
	}

	// A brand-new address in a group nothing else occupies, scored above every
	// other entry so the selector must place it first if it recomputes.
	const fresh = "203.0.113.7:8333"
	ps.Add(fresh)
	ps.Adjust(fresh, 50)

	// Anti-vacuity: a recomputed selection genuinely contains it. If this ever
	// stops holding, the assertions below pass for the wrong reason.
	if !containsAddr(ps.selectLocked(MaxPeersPerResponse, nil, nil, false), fresh) {
		t.Fatal("a fresh top-scored address is not chosen by the selector itself; " +
			"the fixture cannot distinguish a memo hit from a rebuild")
	}

	// Many requests, from many connections, all inside the window: none of them
	// pays for a rebuild, so none of them sees the new address.
	for i := 0; i < 50; i++ {
		clock = clock.Add(DiverseCacheTTL / 100)
		got := servedPeers(t, e, fmt.Sprintf("10.77.%d.%d:5000", i/256, i%256))
		if containsAddr(got, fresh) {
			t.Fatalf("request %d inside the %v window recomputed the whole-store "+
				"selection: a 5-byte frame still buys work proportional to the store",
				i, DiverseCacheTTL)
		}
	}

	// One tick past the window, the very next request rebuilds.
	clock = clock.Add(DiverseCacheTTL)
	if got := servedPeers(t, e, "10.99.0.1:5000"); !containsAddr(got, fresh) {
		t.Fatalf("the selection was not recomputed after %v; the memo is stale without bound",
			DiverseCacheTTL)
	}
}

// TestGetPeersMemoNeverServesABannedAddress pins the one staleness that would
// matter: the memo is a snapshot, and a snapshot that outlived a ban would keep
// gossiping an address this node has since scored out.
func TestGetPeersMemoNeverServesABannedAddress(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 512, &clock)

	served := servedPeers(t, e, "10.66.0.1:5000")
	if len(served) < 2 {
		t.Fatalf("the fixture served %d addresses; this test needs at least two", len(served))
	}
	victim := served[0]

	ps.Adjust(victim, ScoreFloor)
	if !ps.Banned(victim) {
		t.Fatalf("%s is not banned after the adjustment; the test would assert nothing", victim)
	}

	// Same window, so this is answered from the memo, which still holds the
	// banned address unless it is filtered on the way out.
	clock = clock.Add(DiverseCacheTTL / 10)
	again := servedPeers(t, e, "10.66.0.2:5000")
	if containsAddr(again, victim) {
		t.Fatalf("a memoized reply still gossips %s after it was banned", victim)
	}
	// The rest of the answer survived: this filters, it does not empty.
	if len(again) != len(served)-1 {
		t.Fatalf("banning one address changed the reply from %d to %d addresses; the "+
			"filter removes more than the entry it was asked to remove", len(served), len(again))
	}

	// Diversity survives the filter: a subset of a bounded-per-group set is
	// still bounded per group.
	groups := map[string]int{}
	for _, a := range again {
		g := AddressGroup(a)
		groups[g]++
		if groups[g] > MaxFallbackPerGroup {
			t.Fatalf("the memoized reply hands %d slots to group %s", groups[g], g)
		}
	}
}

// TestGetPeersRepeatedInsideTheWindowIsRefusedAndCharged pins the second half:
// the memo makes a request cheap, and cheap is not free. A 5-byte frame whose
// answer cannot have changed buys no reply and costs the sender score.
func TestGetPeersRepeatedInsideTheWindowIsRefusedAndCharged(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 512, &clock)
	const attacker = "10.66.0.1:5000"
	getPeersHandshake(t, e, attacker)

	first := e.Handle(attacker, KindGetPeers, nil)
	if first.Reply == nil || first.Err != nil {
		t.Fatalf("the first request was not served: reply=%v err=%v", first.Reply, first.Err)
	}
	if first.Score != 0 {
		t.Fatalf("the first request was charged %d; an honest asker must pay nothing", first.Score)
	}
	replyAddrs := mustPeers(t, first)
	// The handshake itself is scored, so the flood does not start from zero.
	startPeer, ok := ps.Get(attacker)
	if !ok {
		t.Fatal("the attacker has no store entry after a handshake")
	}
	startScore := startPeer.Score

	// Flood inside the window. Every frame after the first is refused, and the
	// charge is what makes the flood terminate.
	sent, banned := 1, false
	for i := 0; i < 200; i++ {
		clock = clock.Add(time.Millisecond)
		v := e.Handle(attacker, KindGetPeers, nil)
		sent++
		if v.Reply != nil {
			t.Fatalf("frame %d inside the %v window was answered: the reply is still an "+
				"amplifier of a 5-byte request", sent, GetPeersMinInterval)
		}
		if v.Err != ErrGetPeersTooOften {
			t.Fatalf("frame %d was refused with %v, not %v", sent, v.Err, ErrGetPeersTooOften)
		}
		if v.Score != ScoreExcessRequest {
			t.Fatalf("frame %d was charged %d, not %d", sent, v.Score, ScoreExcessRequest)
		}
		if ps.Banned(attacker) {
			banned = true
			break
		}
	}
	if !banned {
		t.Fatalf("%d get-peers frames inside one %v window did not reach the ban "+
			"threshold: the flood is unpriced and does not terminate", sent, GetPeersMinInterval)
	}
	// The number of frames is not a magic constant: it is the distance from the
	// score the peer had when it started to the ban threshold, divided by the
	// charge. Deriving it here is what makes the charge, and not something
	// else, the thing that ended the flood.
	charges := (startScore - ScoreBanThreshold + (-ScoreExcessRequest) - 1) / (-ScoreExcessRequest)
	if want := 1 + charges; sent != want {
		t.Fatalf("the flood terminated after %d frames, expected %d (one served at score "+
			"%d, then %d charges of %d against a %d threshold)",
			sent, want, startScore, charges, ScoreExcessRequest, ScoreBanThreshold)
	}
	t.Logf("from score %d, one served reply of %d addresses then %d refusals reaches "+
		"the ban threshold", startScore, len(replyAddrs), sent-1)
}

// TestGetPeersAtTheIntervalIsServedAndUnscored pins the boundary the charge is
// sized at: at or above GetPeersMinInterval a request is ordinary traffic. A
// conforming node asks once per five minutes, ten times this floor, and the
// charge must never reach it.
//
// Unscored and not Free: a served reply is `Budgeted`, because its
// bytes are charged against this node's node-wide egress ceiling. What this
// test is about is the score, which is what the asker pays, and that is still
// zero — the name said Free while the cost class no longer does, and a test
// name that contradicts wire.md §10.3 is the failure mode that whole change is
// an instance of.
func TestGetPeersAtTheIntervalIsServedAndUnscored(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 512, &clock)
	const honest = "10.66.0.1:5000"
	getPeersHandshake(t, e, honest)

	if v := e.Handle(honest, KindGetPeers, nil); v.Reply == nil {
		t.Fatalf("the first request was not served: %v", v.Err)
	}
	// Exactly at the interval: the comparison is strict, so this is served.
	clock = clock.Add(GetPeersMinInterval)
	v := e.Handle(honest, KindGetPeers, nil)
	if v.Reply == nil || v.Err != nil {
		t.Fatalf("a request exactly at %v was refused (%v); an asker on the interval "+
			"this node's own rule names must never be charged", GetPeersMinInterval, v.Err)
	}
	if v.Score != 0 {
		t.Fatalf("a request exactly at %v was charged %d", GetPeersMinInterval, v.Score)
	}
	// The headroom the charge's sizing argument rests on, asserted rather than
	// left in prose. GetPeersInterval is not importable from here, so its value
	// is written out.
	const getPeersIntervalDoc = 5 * time.Minute
	if GetPeersMinInterval*10 > getPeersIntervalDoc {
		t.Fatalf("GetPeersMinInterval is %v, leaving under 10x headroom against the %v "+
			"a conforming node asks on: an honest peer with a fast clock would "+
			"be scored for conforming", GetPeersMinInterval, getPeersIntervalDoc)
	}
}

// TestGetPeersStampSurvivesARepeatedHandshake pins that the rate limit is not
// clearable by the peer. The stamp lives on PeerTip, which recordTip rewrites
// wholesale; a rewrite that dropped it would be a limit a peer resets by saying
// hello again.
func TestGetPeersStampSurvivesARepeatedHandshake(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 512, &clock)
	const attacker = "10.66.0.1:5000"
	getPeersHandshake(t, e, attacker)

	if v := e.Handle(attacker, KindGetPeers, nil); v.Reply == nil {
		t.Fatalf("the first request was not served: %v", v.Err)
	}
	// recordTip is what a second hello reaches. Handle refuses a second
	// handshake on a connection, so the rewrite is driven directly: this test is
	// about the field carry-forward, not about the gate that also stops it.
	e.recordTip(attacker, Hello{Protocol: ProtocolVersion, NetworkID: e.Chain.NetworkID(), ListenAddr: attacker})

	clock = clock.Add(time.Millisecond)
	v := e.Handle(attacker, KindGetPeers, nil)
	if v.Err != ErrGetPeersTooOften {
		t.Fatalf("re-handshaking cleared the peer-exchange rate limit: the repeat was "+
			"answered with reply=%v err=%v", v.Reply, v.Err)
	}
}

// TestGetPeersCostDoesNotScaleWithStoreSize is the finding's own instrument.
// The complaint is that the cost is superlinear in store size, so the
// healthiest node is the softest target; this measures a served request against
// store size and fails if the per-request cost is store-shaped again.
//
// It asserts on allocation rather than on wall time. Allocation is what this
// change removes and it is deterministic; a timing threshold on a machine
// running other work is a check that fires for a benign reason.
func TestGetPeersCostDoesNotScaleWithStoreSize(t *testing.T) {
	// Per-request allocation measured on the revision before the memo, through
	// this same fixture and this same dispatcher path: a whole-store snapshot
	// plus two AddressGroup passes over every candidate, per frame.
	before := map[int]int{64: 31483, 256: 51656, 1024: 130128, 4096: 428609}

	const reps = 200
	for _, n := range []int{64, 256, 1024, 4096} {
		clock := time.Unix(1_700_000_000, 0)
		e, ps := getPeersEngine(t, n, &clock)
		// One handshaked connection per measured request, all established
		// before the measurement starts, so what is measured is the get-peers
		// frame and not the hello. A distinct connection each time also means
		// the per-connection interval never binds: this is the served path,
		// not the refusal.
		conns := make([]string, 0, reps+8)
		for i := 0; i < reps+8; i++ {
			a := fmt.Sprintf("10.%d.%d.%d:5000", 66+i/65536, (i/256)%256, i%256)
			getPeersHandshake(t, e, a)
			conns = append(conns, a)
		}
		var got []string
		i := 0
		perReq := allocPerCall(reps, func(int) {
			got = servedPeers(t, e, conns[i%len(conns)])
			i++
		})
		t.Logf("seeded %5d, store holds %5d: %7d B allocated per served request "+
			"(was %7d), reply %2d addresses", n, ps.Len(), perReq, before[n], len(got))

		// One reply's worth of bytes, generously bounded, and flat in n. The
		// reply is capped at MaxPeersPerResponse addresses however large the
		// store is, so the ceiling does not have to move with n.
		const perRequestCeiling = 8 << 10
		if perReq > perRequestCeiling {
			t.Fatalf("a served get-peers allocates %d B at a store of %d entries (ceiling "+
				"%d B): the per-request cost is proportional to the store again",
				perReq, n, perRequestCeiling)
		}
	}
}

// TestGetPeersUnderConcurrentAskersRebuildsOnce drives the handler the way
// production does - one goroutine per socket, Node.serve calls Engine.Handle
// from each - because the memo is shared state and a flood arriving on many
// sockets at once is the case that was measured. All of them must get the same
// answer, and between them they must buy one rebuild, not one each.
//
// It asserts on the answers rather than on the absence of a race, and that is
// a choice about which instrument can fail rather than a constraint on what is
// available. A happens-before detector reports the unsynchronised accesses an
// interleaving actually performs, so a clean run is evidence about the
// scheduling that run happened to take. Disagreeing answers are evidence about
// the memo itself: a read outside its mutex shows up here as askers disagreeing
// about a store nothing wrote to during the window, and that verdict does not
// depend on the scheduler cooperating.
//
// This is NOT because -race is unavailable. The note here used to say the
// environment had no C toolchain and could not run the detector; that was
// false and is retracted. Scoped to this one test the detector builds
// and passes clean, and running it is worth doing whenever this handler's
// locking changes — as a second instrument beside the assertions below, never
// as the one they rest on.
func TestGetPeersUnderConcurrentAskersRebuildsOnce(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 512, &clock)

	const askers = 32
	conns := make([]string, 0, askers)
	for i := 0; i < askers; i++ {
		a := fmt.Sprintf("10.%d.%d.%d:5000", 66+i/65536, (i/256)%256, i%256)
		getPeersHandshake(t, e, a)
		conns = append(conns, a)
	}
	// Warm the memo, then change the store. A rebuild would pick the new
	// address up; a hit cannot.
	if len(servedPeers(t, e, conns[0])) == 0 {
		t.Fatal("the fixture served nothing; this test would assert nothing")
	}
	const fresh = "203.0.113.7:8333"
	ps.Add(fresh)
	ps.Adjust(fresh, 50)
	if !containsAddr(ps.selectLocked(MaxPeersPerResponse, nil, nil, false), fresh) {
		t.Fatal("a fresh top-scored address is not chosen by the selector itself; " +
			"the fixture cannot distinguish a memo hit from a rebuild")
	}

	replies := make([][]string, askers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 1; i < askers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			v := e.Handle(conns[i], KindGetPeers, nil)
			if v.Reply == nil {
				return
			}
			addrs, err := UnmarshalPeers(v.Reply.Payload)
			if err != nil {
				return
			}
			replies[i] = addrs
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 1; i < askers; i++ {
		if len(replies[i]) == 0 {
			t.Fatalf("asker %d got no usable reply", i)
		}
		if containsAddr(replies[i], fresh) {
			t.Fatalf("asker %d saw an address added after the window opened: %d "+
				"concurrent askers bought more than one rebuild of the whole store",
				i, askers-1)
		}
		if !equalAddrs(replies[i], replies[1]) {
			t.Fatalf("asker %d got %v, asker 1 got %v: concurrent askers disagree about "+
				"a selection nothing wrote to", i, replies[i], replies[1])
		}
	}
}

// TestGetPeersRebuildDoesNotReDeriveEveryAddressGroup pins the other half of
// the per-request cost, the half the memo does not reach: the rebuild itself,
// which still runs once per DiverseCacheTTL and is where the superlinearity in
// store size lives.
//
// selectLocked called AddressGroup - SplitHostPort, ParseIP and IP.String, all
// three allocating - up to twice for every candidate in the store, on an
// address that cannot change, because Addr is the map key. Peer.group is that
// answer stamped once at insertion. Without it the rebuild allocates roughly
// what it did before this change; the ceiling below is between the two, so it
// fails if the stamp is dropped and passes with room if the rest of the
// selector is touched.
func TestGetPeersRebuildDoesNotReDeriveEveryAddressGroup(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, MaxPeers, &clock)

	conns := make([]string, 0, 128)
	for i := 0; i < 128; i++ {
		a := fmt.Sprintf("10.%d.%d.%d:5000", 66+i/65536, (i/256)%256, i%256)
		getPeersHandshake(t, e, a)
		conns = append(conns, a)
	}
	var got []string
	i := 0
	perRebuild := allocPerCall(len(conns)-8, func(int) {
		// Past the window every time, so every one of these is a rebuild and
		// none of them is a memo hit.
		clock = clock.Add(DiverseCacheTTL + time.Second)
		got = servedPeers(t, e, conns[i%len(conns)])
		i++
	})
	t.Logf("store %d: %d B allocated per rebuilt selection (was 428609 on the parent "+
		"revision), reply %d addresses", ps.Len(), perRebuild, len(got))

	// The parent revision allocated 428609 B here. Halfway is a ratchet, not a
	// microbenchmark: it cannot fire for a benign reason at this margin, and it
	// does fire if every candidate's group is re-derived again.
	const rebuildCeiling = 320 << 10
	if perRebuild > rebuildCeiling {
		t.Fatalf("rebuilding the selection over %d entries allocates %d B (ceiling %d B): "+
			"the diversity group of every candidate is being re-derived per request",
			ps.Len(), perRebuild, rebuildCeiling)
	}
}

// TestDiverseCacheTTLCoversTheBusiestHonestNodesArrivalGap pins the derivation
// DiverseCacheTTL's value comes from, so the number cannot be lowered back to
// something that memoizes nothing on the path that actually carries the load.
//
// A conforming node sends one get-peers per GetPeersInterval. The node that
// pays is the one whose inbound set is saturated, because it is asked by
// everything that dialled it: NewNode's MaxInbound default of 32 requests per
// interval, a mean gap of GetPeersInterval/32. A TTL shorter than that gap is a
// cache that misses on every honest request and bounds a flood only - and the
// discovery decision record (networking.md 12.4) states this cost as baseline
// load, not as an attack.
func TestDiverseCacheTTLCoversTheBusiestHonestNodesArrivalGap(t *testing.T) {
	// Neither is importable here: GetPeersInterval belongs to the discovery change
	// and MaxInbound is a Node config field with no package-level constant, so
	// the two values the derivation uses are written out here.
	const getPeersIntervalDoc = 5 * time.Minute
	const maxInboundDefault = 32

	gap := getPeersIntervalDoc / maxInboundDefault
	if DiverseCacheTTL < gap {
		t.Fatalf("DiverseCacheTTL is %v but the busiest honest serving node is asked "+
			"every %v (%v / %d inbound peers): the memo misses on every honest "+
			"request and bounds only a flood, leaving the baseline cost "+
			"exactly where it was", DiverseCacheTTL, gap, getPeersIntervalDoc, maxInboundDefault)
	}
	// And the other side of it: the charge is measured from this same window,
	// so a TTL at or above the interval would score a conforming asker.
	if GetPeersMinInterval >= getPeersIntervalDoc {
		t.Fatalf("GetPeersMinInterval is %v, at or above the %v a conforming node asks "+
			"on: conforming traffic would be charged", GetPeersMinInterval, getPeersIntervalDoc)
	}
}

// allocPerCall reports bytes allocated per call of f, warmed first.
func allocPerCall(reps int, f func(i int)) int {
	for i := 0; i < 3; i++ {
		f(i)
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	for i := 0; i < reps; i++ {
		f(i)
	}
	runtime.ReadMemStats(&m1)
	return int((m1.TotalAlloc - m0.TotalAlloc) / uint64(reps))
}

// servedPeers drives one get-peers through the real dispatcher, from a
// connection that has completed a handshake, and decodes the reply.
func servedPeers(t *testing.T, e *Engine, from string) []string {
	t.Helper()
	if !e.handshaked(from) {
		getPeersHandshake(t, e, from)
	}
	v := e.Handle(from, KindGetPeers, nil)
	if v.Err != nil {
		t.Fatalf("get-peers from %s refused: %v", from, v.Err)
	}
	return mustPeers(t, v)
}

func mustPeers(t *testing.T, v Verdict) []string {
	t.Helper()
	if v.Reply == nil {
		t.Fatal("get-peers produced no reply")
	}
	addrs, err := UnmarshalPeers(v.Reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return addrs
}

func equalAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsAddr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestGetPeersMinIntervalIsTheMemoWindow pins the only justification the
// refusal has. Lowering GetPeersMinInterval to one second left every other test
// in this file green, and a one-second floor is not a weaker version of this
// rule - it is the absence of it. The memo makes a repeat cheap in CPU, not in
// bytes: the reply is still up to MaxPeersPerResponse addresses for a 5-byte
// frame, so a peer allowed to ask every second is served the same ~240x
// amplification the memo does nothing about.
//
// The refusal is defensible only because the answer cannot have changed inside
// the window, and that is true exactly when the window is the memo's. Anything
// shorter refuses nothing that matters and serves bytes for free; anything
// longer refuses an answer that has genuinely been rebuilt.
func TestGetPeersMinIntervalIsTheMemoWindow(t *testing.T) {
	if GetPeersMinInterval < DiverseCacheTTL {
		t.Fatalf("GetPeersMinInterval is %v, under the %v the selection is memoized "+
			"for: a peer may ask again and be served a fresh ~1.2 KB reply for a "+
			"5-byte frame, which is the amplification the charge exists to end",
			GetPeersMinInterval, DiverseCacheTTL)
	}
	if GetPeersMinInterval > DiverseCacheTTL {
		t.Fatalf("GetPeersMinInterval is %v, over the %v the selection is memoized "+
			"for: a request in the gap is refused an answer this node has genuinely "+
			"rebuilt since it last replied", GetPeersMinInterval, DiverseCacheTTL)
	}
}

// TestSelectDiverseWithExcludeIsNotAnsweredFromTheMemo pins the bypass at the
// top of SelectDiverse. Deleting it left the whole package green, because no
// production caller passes exclude today - the memo would then answer an
// excluded question with the unexcluded list, and would also be *filled* by
// one caller's exclusions and served to everyone else.
//
// The property is the memo's key, not peer exchange: an answer may only be
// reused by a question identical to the one that produced it.
func TestSelectDiverseWithExcludeIsNotAnsweredFromTheMemo(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	ps.now = func() time.Time { return clock }
	fillPeerStore(t, ps, 512)

	// Warm the memo with the unexcluded question.
	base := ps.SelectDiverse(MaxPeersPerResponse, nil)
	if len(base) < 2 {
		t.Fatalf("the fixture selected %d addresses; this test needs at least two", len(base))
	}
	banned := map[string]bool{base[0]: true}

	// Same window, so a memo that ignored the question would answer from it.
	clock = clock.Add(DiverseCacheTTL / 10)
	got := ps.SelectDiverse(MaxPeersPerResponse, banned)
	if containsAddr(got, base[0]) {
		t.Fatalf("SelectDiverse returned %s while asked to exclude it: the memoized "+
			"answer to a different question was served", base[0])
	}

	// And the excluded question did not overwrite the memo for everyone else:
	// the next unexcluded ask, still inside the window, is unchanged.
	after := ps.SelectDiverse(MaxPeersPerResponse, nil)
	if !equalAddrs(after, base) {
		t.Fatalf("an excluded ask rewrote the shared memo: %v became %v", base, after)
	}
}

// TestGetPeersMemoNeverServesAnEvictedAddress is the eviction half of
// liveSubset, and it exists because the ban half does not cover it.
//
// Found by mutating `ok && !p.Banned()` to `!ok || !p.Banned()`: that mutant
// survived every test in this file, including
// TestGetPeersMemoNeverServesABannedAddress, because for an entry the store
// still holds the two expressions agree exactly. They differ only for an
// address the store no longer holds at all - which is the case liveSubset's own
// doc comment, and this PR's claim about the memo, are half about.
//
// An evicted address served out of a memo is a node gossiping an address it has
// itself decided not to keep, for up to DiverseCacheTTL after deciding it.
func TestGetPeersMemoNeverServesAnEvictedAddress(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 512, &clock)

	served := servedPeers(t, e, "10.66.0.1:5000")
	if len(served) < 2 {
		t.Fatalf("the fixture served %d addresses; this test needs at least two", len(served))
	}
	victim := served[0]

	// removeLocked is the single primitive every eviction path in this file
	// funnels through, so this is the production removal and not an imitation
	// of it. The victim is left unbanned on purpose: a banned entry is caught
	// by the other half of the filter, and this test must fail if only that
	// half is present.
	ps.mu.Lock()
	if !ps.removeLocked(victim, ps.peers[victim]) {
		ps.mu.Unlock()
		t.Fatalf("%s was not in the store; the test would assert nothing", victim)
	}
	ps.mu.Unlock()
	if _, ok := ps.Get(victim); ok {
		t.Fatalf("%s survived removal; the test would assert nothing", victim)
	}
	if ps.Banned(victim) {
		t.Fatalf("%s reads as banned after removal, so this test would pass through "+
			"the ban half of the filter rather than the eviction half", victim)
	}

	// Same window, so this is answered from the memo, which still names the
	// evicted address unless the filter checks presence as well as ban.
	clock = clock.Add(DiverseCacheTTL / 10)
	again := servedPeers(t, e, "10.66.0.2:5000")
	if containsAddr(again, victim) {
		t.Fatalf("a memoized reply still gossips %s after the store evicted it", victim)
	}
	if len(again) != len(served)-1 {
		t.Fatalf("evicting one address changed the reply from %d to %d addresses; the "+
			"filter removes more than the entry it was asked to remove", len(served), len(again))
	}
}

// TestSelectDiverseMemoIsNotReusedForADifferentCount is the count half of the
// memo key, and it exists because the exclude half does not cover it.
//
// Found by deleting `ps.diverseN == n` from the memo key: that mutant survives
// TestSelectDiverseWithExcludeIsNotAnsweredFromTheMemo, which states the general
// property - a memo may only be reused by an identical question - but pins only
// the exclude term of "identical". n is the other term, and it is the one a
// caller varies without varying anything else.
//
// Both directions are wrong and both are silent. A memo built for a large count
// answering a small one returns more addresses than were asked for, which is a
// cap the caller stated and this store ignored. A memo built for a small count
// answering a large one returns fewer, which is peer exchange quietly serving a
// short list for up to DiverseCacheTTL - the dissemination failure the memo's
// stated cost is supposed to bound at "a hit can return fewer than a rebuild
// would", not at "a hit can return two".
func TestSelectDiverseMemoIsNotReusedForADifferentCount(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	ps.now = func() time.Time { return clock }
	fillPeerStore(t, ps, 512)

	const small = 2
	full := ps.selectLocked(MaxPeersPerResponse, nil, nil, false)
	// Anti-vacuity: the two counts must give genuinely different answers, or
	// neither direction below distinguishes a hit from a rebuild.
	if len(full) <= small {
		t.Fatalf("the fixture selects %d addresses at n=%d, which is not more than the "+
			"n=%d this test contrasts it with; the test would assert nothing",
			len(full), MaxPeersPerResponse, small)
	}

	// Large first, then small inside the same window.
	if got := ps.SelectDiverse(MaxPeersPerResponse, nil); len(got) != len(full) {
		t.Fatalf("the warming call returned %d addresses, the selector returns %d", len(got), len(full))
	}
	clock = clock.Add(DiverseCacheTTL / 10)
	got := ps.SelectDiverse(small, nil)
	if len(got) > small {
		t.Fatalf("SelectDiverse returned %d addresses for n=%d: the answer memoized for "+
			"n=%d was served to a different question", len(got), small, MaxPeersPerResponse)
	}

	// And the other direction, from a store whose memo now holds the small
	// answer: asking for the large count must not be served the short list.
	clock = clock.Add(DiverseCacheTTL / 10)
	if again := ps.SelectDiverse(MaxPeersPerResponse, nil); len(again) != len(full) {
		t.Fatalf("SelectDiverse returned %d addresses for n=%d where the selector returns "+
			"%d: the answer memoized for n=%d was served to a different question, so peer "+
			"exchange serves a short list for up to %v",
			len(again), MaxPeersPerResponse, len(full), small, DiverseCacheTTL)
	}
}
