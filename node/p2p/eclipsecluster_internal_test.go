package p2p

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The four composing defects of the eclipse cluster, one file.
//
// They are tested together because the audit that found them insists they are
// one attack: "do all four - any three leave the attack standing". Each test
// below reproduces one of the audit's own measurements, and each states the
// number the unfixed tree returned, so a revert is visible as that number
// coming back rather than as an assertion nobody can size.
//
//	(a) the outbound selector's final tie-break was the address string
//	(b) first-teller Src stamping capped honest outbound at MaxPerSource forever
//	(c) the admitted-connection table was first-come-first-served with no eviction
//	(d) inbound `peers` frames were unmetered, unscored and took the store's
//	    write lock up to MaxPeersPerResponse times per frame

// ---------------------------------------------------------------------------
// (a) arrival order, not the address, decides between unproven candidates
// ---------------------------------------------------------------------------

// TestFloodDoesNotWinTheUnprovenTieBreak is the audit's measurement for defect (a):
// 8 honest addresses from 8 honest tellers against 8 flood addresses from 4
// source groups returned **8 of 8 flood addresses and 0 honest ones**.
//
// Everything about the two sets is identical to the selector — score 0, no
// completed connection, no failures — so the whole decision falls to the last
// key in the comparator. That key was `a.addr < b.addr`, and the flood picks
// its own addresses: spelling them so they sort first is free. The honest
// addresses are learned first here, which is the one thing the flood cannot
// arrange after the fact, and it is what Peer.Seq records.
//
// The per-source bound is why the flood needs 4 source groups rather than 1:
// MaxPerSource is 2, so four tellers buy exactly the 8 slots on offer. That is
// the bound working as designed — it prices claims, and the attacker paid the
// price — and it is precisely why the tie-break underneath it has to be right.
func TestFloodDoesNotWinTheUnprovenTieBreak(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	honest := make([]string, 8)
	for i := range honest {
		honest[i] = fmt.Sprintf("203.%d.0.1:8333", 10+i)
		// Eight distinct honest tellers, so the honest set is not the one the
		// per-source bound is holding back.
		ps.AddFrom(honest[i], fmt.Sprintf("198.%d.0.1:8333", 10+i))
	}
	flood := make([]string, 8)
	for i := range flood {
		flood[i] = fmt.Sprintf("10.%d.0.1:8333", 10+i)
		ps.AddFrom(flood[i], fmt.Sprintf("172.%d.0.1:8333", 20+i%4))
	}

	// Anti-vacuity for the mechanism, not for the outcome: if the flood
	// addresses stopped sorting ahead of the honest ones this test would pass
	// against the unfixed selector and prove nothing.
	for _, f := range flood {
		for _, h := range honest {
			if !(f < h) {
				t.Fatalf("fixture: flood address %q does not sort ahead of honest address %q, "+
					"so the address tie-break this test is about would not choose it", f, h)
			}
		}
	}

	got := ps.SelectDialTargets(8, nil, nil)
	if len(got) != 8 {
		t.Fatalf("the selector returned %d of 8 targets from a store holding 16 "+
			"candidates in 16 distinct groups: %v", len(got), got)
	}
	isFlood := map[string]bool{}
	for _, f := range flood {
		isFlood[f] = true
	}
	floods := 0
	for _, a := range got {
		if isFlood[a] {
			floods++
		}
	}
	if floods > 0 {
		t.Fatalf("%d of %d dial targets went to the flood (%v). The honest addresses "+
			"were learned first and are identical to the flood by every other key, so "+
			"the final tie-break decided — and wire.md §11 states as a MUST that it "+
			"MUST NOT be anything the gossiping peer chooses, the address included. "+
			"The unfixed tree returned 8 of 8 here", floods, len(got), got)
	}
}

// TestEquallyRankedUnprovenCandidatesAreRandomised pins the second half of
// defect (a). Arrival order removes the address from the decision, but it cannot
// separate entries that share an arrival: renumberLocked deliberately collapses
// every entry loaded from peers.json into one bucket, so a restarted node's
// whole candidate set is one tie. Without a shuffle the residual order is
// whatever the comparator falls through to, which is a deterministic function
// of data the file's writer supplied.
//
// The property is observable and not merely asserted: ask for one target, many
// times, and count the distinct answers. On the unfixed selector the answer is
// the lowest address, every time, forever — one distinct answer.
func TestEquallyRankedUnprovenCandidatesAreRandomised(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")

	body := "[\n"
	for i := 0; i < 32; i++ {
		if i > 0 {
			body += ",\n"
		}
		body += fmt.Sprintf(`  {"addr":"203.%d.0.1:8333","score":0,"last_seen":0,"failures":0,"seq":%d}`, 10+i, i+1)
	}
	body += "\n]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Len() != 32 {
		t.Fatalf("fixture loaded %d entries, want 32", ps.Len())
	}

	seen := map[string]bool{}
	for i := 0; i < 400; i++ {
		got := ps.SelectDialTargets(1, nil, nil)
		if len(got) != 1 {
			t.Fatalf("call %d returned %d targets, want 1", i, len(got))
		}
		seen[got[0]] = true
	}
	if len(seen) < 2 {
		t.Fatalf("400 selections over 32 indistinguishable restored candidates "+
			"returned %d distinct address(es): %v. Every one of them shares an "+
			"arrival bucket by construction, so a single answer means the residual "+
			"order is still a function of something the file chose",
			len(seen), seen)
	}
	t.Logf("400 selections over 32 tied candidates returned %d distinct addresses", len(seen))
}

// TestFailuresSurviveTheStoreReload pins the third piece of defect (a).
//
// A dial this node made and that did not answer is the cheapest true thing it
// knows about a gossiped address, and it is the one an attacker cannot forge in
// its own favour. The loader used to zero it, so a flood only had to outlive one
// restart to have its refutation forgotten while the honest addresses it
// displaced did not improve.
//
// The second half is the reason the reset was there: the operator's own list
// must not be demotable by whoever can write the file. That answer now lives in
// AddBootstrap, next to the identical one it already gives for a restored ban,
// and it is confined to the addresses the operator actually re-supplied.
func TestFailuresSurviveTheStoreReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const junk = "10.99.0.1:8333"
	const configured = "203.0.113.9:8333"
	ps.AddFrom(junk, "172.20.0.1:5000")
	ps.Add(configured)
	ps.MarkFailed(junk)
	ps.MarkFailed(configured)
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := reloaded.Get(junk)
	if !ok {
		t.Fatalf("%s did not survive the reload at all", junk)
	}
	if p.Failures == 0 {
		t.Fatalf("a gossiped address this node dialled and never reached came back " +
			"from peers.json with 0 failures. A flood then only has to outlive one " +
			"restart to be indistinguishable from an address never tried")
	}
	if got := dialRank(&Peer{Addr: junk, Failures: p.Failures, restored: true}); got != 0 {
		t.Fatalf("a restored, refuted address ranks %d, want 0", got)
	}

	// The operator re-supplies the second address for this run, exactly as
	// Start does from --peers. The file does not get to keep it demoted.
	reloaded.AddBootstrap(configured)
	q, ok := reloaded.Get(configured)
	if !ok {
		t.Fatalf("%s did not survive the reload at all", configured)
	}
	if q.Failures != 0 {
		t.Fatalf("the operator re-supplied %s and it still carries %d failures from "+
			"the file. Whoever can write peers.json can then sort the whole --peers "+
			"list behind every invented address in it", configured, q.Failures)
	}
}

// TestStoredFailuresCannotWrapTheComparator pins the bound that makes the field
// safe to read back off disk at all. selectLocked narrows Failures into an
// int32; a file claiming a count above what that holds would sort a forged
// entry ahead of every honestly-tried address instead of behind it.
func TestStoredFailuresCannotWrapTheComparator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	body := `[{"addr":"10.1.0.1:8333","score":0,"last_seen":0,"failures":9007199254740992}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ps.Get("10.1.0.1:8333")
	if !ok {
		t.Fatal("the entry did not load")
	}
	if p.Failures != MaxStoredFailures {
		t.Fatalf("a file claiming %d failures loaded as %d, want the cap of %d",
			9007199254740992, p.Failures, MaxStoredFailures)
	}
	if int32(p.Failures) < 0 {
		t.Fatalf("the stored failure count narrows to %d, which sorts ahead of an "+
			"address with none", int32(p.Failures))
	}
}

// ---------------------------------------------------------------------------
// (b) a completed connection outranks a stranger's first-teller claim
// ---------------------------------------------------------------------------

// TestFirstTellerCannotCapAddressesThisNodeHasMet is the audit's measurement for
// defect (b): 20 honest addresses first-told by one attacker connection,
// re-gossiped by 20 distinct honest tellers, then **all 20 actually connected**
// — SelectDialTargets(8) returned **exactly 2**, and a second call holding those
// 2 returned **0**.
//
// Peer.Src is written once, by the first teller, and never updated. So an
// attacker that gossips honest addresses before anyone else owns their label
// permanently — the field is persisted, so it survives restarts too — and
// MaxPerSource then bounds every one of them together at 2 of this node's 8
// outbound slots. That is not the bound doing its job: the bound prices
// addresses a teller merely *claims*, and this node has since dialled every one
// of these and been answered.
func TestFirstTellerCannotCapAddressesThisNodeHasMet(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const attacker = "172.20.0.1:5000"
	honest := make([]string, 20)
	for i := range honest {
		honest[i] = fmt.Sprintf("203.%d.0.1:8333", 10+i)
		// First-teller wins: the attacker names them all before anyone else.
		ps.AddFrom(honest[i], attacker)
	}
	for i, a := range honest {
		// Twenty distinct honest tellers corroborate, and are ignored — Src is
		// stamped at creation and never afterwards.
		ps.AddFrom(a, fmt.Sprintf("198.%d.0.1:8333", 10+i))
	}
	for _, a := range honest {
		if p, ok := ps.Get(a); !ok || p.Src != AddressGroup(attacker) {
			t.Fatalf("fixture: %s is labelled %q, want the attacker's group %q — the "+
				"first-teller stamp is what this test is about", a, p.Src, AddressGroup(attacker))
		}
	}

	// Before any of them has been reached, the bound holds and must: they are
	// still only what one teller claimed.
	if got := ps.SelectDialTargets(8, nil, nil); len(got) != MaxPerSource {
		t.Fatalf("unreached addresses from one teller yielded %d targets, want %d. "+
			"MaxPerSource must keep bounding a teller's claims", len(got), MaxPerSource)
	}

	// This node now dials and reaches every one of them.
	for _, a := range honest {
		ps.MarkConnected(a)
	}

	got := ps.SelectDialTargets(8, nil, nil)
	if len(got) < 8 {
		t.Fatalf("after this node itself connected to all 20 addresses, the selector "+
			"returned %d of 8 outbound slots: %v. The unfixed tree returned exactly 2, "+
			"permanently, because one attacker had said their names first",
			len(got), got)
	}
	// The second call the audit made: holding the first two must not zero the
	// rest.
	if second := ps.SelectDialTargets(8, map[string]bool{got[0]: true, got[1]: true}, got[:2]); len(second) == 0 {
		t.Fatalf("a second round holding 2 of the connected addresses returned no " +
			"targets at all. The unfixed tree returned 0 here")
	}
}

// TestHeldConnectionsStillSpendTheirTellersBudget is the other side of
// defect (b), and it is the reason the exemption is on the candidate side only.
//
// Relaxing the held charge as well would let a teller convert its allowance
// into more allowance: dial 2, have them answer, come back next round with the
// budget clear. This drives the dial loop across rounds — the caller, which is
// where the per-source bound's own regression lives — and holds it to MaxPerSource.
func TestHeldConnectionsStillSpendTheirTellersBudget(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		ps.AddFrom(fmt.Sprintf("11.%d.0.1:8333", i), "198.18.7.7:9421")
	}
	n := &Node{Peers: ps, MaxOutbound: 8, conns: map[string]*Conn{}, outboundTargets: map[string]bool{}}
	for round := 0; round < 8; round++ {
		targets := n.dialTargets()
		if len(targets) == 0 {
			break
		}
		for _, addr := range targets {
			// Exactly what topUp does on a successful dial, minus the socket.
			ps.MarkConnected(addr)
			n.conns[addr] = &Conn{Addr: addr}
			n.outboundTargets[addr] = true
		}
	}
	if got := len(n.outboundTargets); got > MaxPerSource {
		t.Fatalf("one teller accreted %d of %d outbound slots across dial rounds, want "+
			"at most %d. Exempting a *held* connection from its teller's budget is what "+
			"turns the per-round counter back into a ratchet",
			got, n.MaxOutbound, MaxPerSource)
	}
}

// TestADialRoundDialsItsTargetsConcurrently is the last piece of defect (a), and
// the one the tie-break alone does not reach.
//
// The round used to be a serial loop, so it cost the *sum* of its dial timeouts
// rather than the longest one: eight unreachable targets at DialTimeout is a
// forty-second round in which this node dials nobody else, and an attacker's
// invented addresses are unreachable by construction. That is why the audit
// measured 0 honest outbound connections over ten simulated rounds — the honest
// addresses did not have to be out-ranked for long, only stalled behind.
//
// The margin is wide on purpose: eight targets, so serial is eight blocking
// units and concurrent is one, and the assertion sits at two.
func TestADialRoundDialsItsTargetsConcurrently(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		// Eight distinct /16s and eight distinct tellers, so neither diversity
		// bound trims the round this test is timing.
		ps.AddFrom(fmt.Sprintf("203.%d.0.1:8333", 10+i), fmt.Sprintf("198.%d.0.1:8333", 10+i))
	}
	const block = 200 * time.Millisecond
	var mu sync.Mutex
	attempted := map[string]bool{}
	n := &Node{
		Peers:           ps,
		MaxOutbound:     8,
		conns:           map[string]*Conn{},
		outboundTargets: map[string]bool{},
		dialFn: func(addr string, _ time.Duration) (*Conn, error) {
			mu.Lock()
			attempted[addr] = true
			mu.Unlock()
			time.Sleep(block)
			return nil, errors.New("unreachable")
		},
	}

	start := time.Now()
	n.topUp()
	elapsed := time.Since(start)

	if len(attempted) != 8 {
		t.Fatalf("the round attempted %d of its 8 targets", len(attempted))
	}
	if elapsed >= 4*block {
		t.Fatalf("a round of 8 targets that each block for %v took %v. Serially that "+
			"is %v, and a round that costs the sum of its timeouts is a round an "+
			"attacker's unreachable addresses stall outright",
			block, elapsed, 8*block)
	}
	// Anti-vacuity: the round must actually have waited for its dials, or the
	// measurement above is timing a function that returned early.
	if elapsed < block {
		t.Fatalf("the round returned in %v, under the %v a single dial blocks for: "+
			"it did not wait for the goroutines it started", elapsed, block)
	}
	// And the bookkeeping still happened, on this goroutine, for every target.
	for a := range attempted {
		p, ok := ps.Get(a)
		if !ok || p.Failures == 0 {
			t.Fatalf("%s was dialled and did not answer, but the store records "+
				"%d failures", a, p.Failures)
		}
	}
}

// ---------------------------------------------------------------------------
// (c) the admitted-connection table evicts by address-group share
// ---------------------------------------------------------------------------

// pipeConn is a Conn whose socket can be closed without a network. register
// closes the connection it evicts, so a victim built out of a struct literal
// with a nil net.Conn is not a fixture this policy can be driven with.
func pipeConn(t *testing.T, addr string) *Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &Conn{Conn: a, Addr: addr}
}

func evictionNode(t *testing.T) *Node {
	t.Helper()
	return &Node{MaxInbound: 32, MaxOutbound: 8, conns: map[string]*Conn{}}
}

// TestInboundTableEvictsTheConcentratedGroupAndSparesTheSingletons is the
// audit's defect (c): 14 addresses across distinct /16s at 3 connections each is
// 42 against a table of 40, and the table refused at capacity and never evicted.
// A connection costs nothing to hold — a 9-byte count-0 frame every under-60s
// keeps it alive and is scored nothing — so the door closed behind the other
// three defects and no honest peer could ever open an inbound connection again.
//
// The handshake budget one gate earlier has had exactly this since the inbound
// slot leak was closed (Listener.victimLocked). This is that policy on the
// admitted table.
func TestInboundTableEvictsTheConcentratedGroupAndSparesTheSingletons(t *testing.T) {
	n := evictionNode(t)
	capacity := n.MaxInbound + n.MaxOutbound

	// Twelve attacker groups holding three connections each, and four honest
	// peers each alone in its own group: 40, the table full.
	attacker := map[string]bool{}
	for g := 0; g < 12; g++ {
		for k := 0; k < 3; k++ {
			addr := fmt.Sprintf("10.%d.0.%d:5000", 20+g, 10+k)
			if !n.register(pipeConn(t, addr), false) {
				t.Fatalf("fixture: %s refused below capacity", addr)
			}
			attacker[addr] = true
		}
	}
	honest := make([]string, 4)
	for i := range honest {
		honest[i] = fmt.Sprintf("203.%d.0.1:5000", 30+i)
		if !n.register(pipeConn(t, honest[i]), false) {
			t.Fatalf("fixture: %s refused below capacity", honest[i])
		}
	}
	if len(n.conns) != capacity {
		t.Fatalf("fixture holds %d connections, want the table full at %d", len(n.conns), capacity)
	}

	const arriving = "203.0.113.7:5000"
	if !n.register(pipeConn(t, arriving), false) {
		t.Fatalf("an honest peer arriving alone in its own /16 was refused against a " +
			"table 36/40 held by twelve groups of three. That is defect (c): the table " +
			"was first-come-first-served and permanent")
	}
	if n.Evicted() != 1 {
		t.Fatalf("admission reported %d evictions, want exactly 1", n.Evicted())
	}
	if len(n.conns) != capacity {
		t.Fatalf("the table holds %d connections after an eviction and an admission, "+
			"want %d", len(n.conns), capacity)
	}
	if _, ok := n.conns[arriving]; !ok {
		t.Fatal("the arrival was not inserted after an eviction was taken for it")
	}
	for _, h := range honest {
		if _, ok := n.conns[h]; !ok {
			t.Fatalf("%s was evicted. It is the only connection in its address group, "+
				"and the diverse subset is exactly what group-share eviction exists to "+
				"protect", h)
		}
	}
	gone := 0
	for a := range attacker {
		if _, ok := n.conns[a]; !ok {
			gone++
		}
	}
	if gone != 1 {
		t.Fatalf("%d of the concentrated group's connections were given up, want 1", gone)
	}
}

// TestAFullTableOfDiversePeersIsNotChurned pins the other half of the policy.
// Eviction is for concentration, not for capacity: when every connection is
// alone in its group there is nothing over-represented to take, and refusing
// the arrival is the same answer this node gave before eviction existed. A policy that
// evicted anyway would hand an attacker a free way to cycle honest peers out.
func TestAFullTableOfDiversePeersIsNotChurned(t *testing.T) {
	n := evictionNode(t)
	capacity := n.MaxInbound + n.MaxOutbound
	for i := 0; i < capacity; i++ {
		addr := fmt.Sprintf("10.%d.0.1:5000", 20+i)
		if !n.register(pipeConn(t, addr), false) {
			t.Fatalf("fixture: %s refused below capacity", addr)
		}
	}
	if n.register(pipeConn(t, "203.0.113.7:5000"), false) {
		t.Fatal("an arrival was admitted against a table of 40 peers in 40 distinct " +
			"groups. Nothing there is over-represented, so admitting means evicting " +
			"an honest peer to make room for a stranger")
	}
	if n.Evicted() != 0 {
		t.Fatalf("%d evictions against a table with no concentration at all", n.Evicted())
	}
	if len(n.conns) != capacity {
		t.Fatalf("the table holds %d connections, want %d unchanged", len(n.conns), capacity)
	}
}

// TestOutboundConnectionsAreNeverEvicted pins the exemption that keeps this
// policy from becoming the attack it defends against. An outbound connection is
// one this node chose, from an address that survived SelectDialTargets'
// diversity and source bounds; letting an inbound arrival evict one would hand
// a peer that merely connects here the power to unpick this node's own dialling
// — which is the eclipse the rest of this file is about.
func TestOutboundConnectionsAreNeverEvicted(t *testing.T) {
	n := evictionNode(t)
	// Every outbound connection in ONE group, so if outbound legs counted they
	// would be the most concentrated thing in the table by a wide margin.
	out := make([]string, n.MaxOutbound)
	for i := range out {
		out[i] = fmt.Sprintf("10.20.0.%d:8333", 10+i)
		if !n.register(pipeConn(t, out[i]), true) {
			t.Fatalf("fixture: outbound %s refused", out[i])
		}
	}
	for i := 0; i < n.MaxInbound; i++ {
		addr := fmt.Sprintf("203.%d.0.1:5000", 30+i)
		if !n.register(pipeConn(t, addr), false) {
			t.Fatalf("fixture: inbound %s refused below capacity", addr)
		}
	}
	if n.register(pipeConn(t, "198.51.100.7:5000"), false) {
		t.Fatal("an inbound arrival was admitted against a table whose only " +
			"concentration is this node's own outbound set")
	}
	for _, a := range out {
		if _, ok := n.conns[a]; !ok {
			t.Fatalf("outbound connection %s was evicted by an inbound arrival", a)
		}
	}
}

// TestTheLeastUsefulConnectionInTheGroupGoesFirst pins the "recently useful"
// half of the protected subset. Within the group that is over-represented, a
// connection that has delivered something worth scoring is kept over one that
// has only ever held the slot open.
//
// The signal is the scored verdict and not traffic on purpose: the connections
// this policy exists to reach are kept alive by a count-0 frame that returns
// CostFree, so anything counting bytes or frames would rank a squatter as this
// node's busiest peer.
func TestTheLeastUsefulConnectionInTheGroupGoesFirst(t *testing.T) {
	n := evictionNode(t)
	capacity := n.MaxInbound + n.MaxOutbound

	// One over-represented group of two, and the rest singletons.
	useful := pipeConn(t, "10.20.0.11:5000")
	idle := pipeConn(t, "10.20.0.12:5000")
	for _, c := range []*Conn{useful, idle} {
		if !n.register(c, false) {
			t.Fatalf("fixture: %s refused below capacity", c.Addr)
		}
	}
	for i := 0; i < capacity-2; i++ {
		addr := fmt.Sprintf("203.%d.0.1:5000", 30+i)
		if !n.register(pipeConn(t, addr), false) {
			t.Fatalf("fixture: %s refused below capacity", addr)
		}
	}
	// Exactly what serve stamps on a positively scored verdict.
	useful.lastUseful.Store(time.Now().UnixNano())

	if !n.register(pipeConn(t, "198.51.100.7:5000"), false) {
		t.Fatal("an arrival was refused against a table holding a group of two")
	}
	if _, ok := n.conns[idle.Addr]; ok {
		t.Fatalf("%s was kept: it has never delivered a scored message, and its "+
			"group-mate has", idle.Addr)
	}
	if _, ok := n.conns[useful.Addr]; !ok {
		t.Fatalf("%s was evicted ahead of a connection in its own group that has "+
			"never been useful", useful.Addr)
	}
}

// TestAnEvictedConnectionDoesNotDeleteItsReplacement pins the teardown half of
// defect (c). An evicted connection leaves the table immediately; its own serve
// goroutine reaches retire some time later, after the far end notices the
// reset — by which point the churn the eviction provoked may have brought the
// same address back on a new connection. Retiring on the address alone would
// then delete the live entry and forget the live peer's tip, silently.
func TestAnEvictedConnectionDoesNotDeleteItsReplacement(t *testing.T) {
	n := evictionNode(t)
	// retire publishes to the Engine and forgets the peer's tip, so this one
	// case needs a real one.
	clock := time.Unix(1_700_000_000, 0)
	n.Engine, _ = getPeersEngine(t, 8, &clock)
	capacity := n.MaxInbound + n.MaxOutbound
	for g := 0; g < 12; g++ {
		for k := 0; k < 3; k++ {
			addr := fmt.Sprintf("10.%d.0.%d:5000", 20+g, 10+k)
			if !n.register(pipeConn(t, addr), false) {
				t.Fatalf("fixture: %s refused below capacity", addr)
			}
		}
	}
	for i := 0; i < capacity-36; i++ {
		addr := fmt.Sprintf("203.%d.0.1:5000", 30+i)
		if !n.register(pipeConn(t, addr), false) {
			t.Fatalf("fixture: %s refused below capacity", addr)
		}
	}
	// Find who gets evicted by watching the table.
	before := map[string]bool{}
	for a := range n.conns {
		before[a] = true
	}
	if !n.register(pipeConn(t, "198.51.100.7:5000"), false) {
		t.Fatal("the arrival was refused")
	}
	var victimAddr string
	for a := range before {
		if _, ok := n.conns[a]; !ok {
			victimAddr = a
		}
	}
	if victimAddr == "" {
		t.Fatal("nothing was evicted")
	}
	victim := n.conns[victimAddr]
	if victim != nil {
		t.Fatalf("the evicted address %s is still in the table", victimAddr)
	}

	// The evicted peer reconnects on the same address before its old serve
	// goroutine has noticed anything. Room is made for it by hand rather than
	// through unregister, which would publish to an Engine this fixture does
	// not have.
	delete(n.conns, "198.51.100.7:5000")
	replacement := pipeConn(t, victimAddr)
	if !n.register(replacement, false) {
		t.Fatalf("the reconnecting peer was refused at %d/%d", len(n.conns), capacity)
	}
	// Now the old connection's teardown finally runs. It must not touch the
	// entry that has taken its place.
	old := &Conn{Addr: victimAddr, evicted: true}
	n.retire(old, false, true)
	held, ok := n.conns[victimAddr]
	if !ok {
		t.Fatalf("the evicted connection's teardown deleted %s, which by then "+
			"belonged to a live reconnection", victimAddr)
	}
	if held != replacement {
		t.Fatalf("%s is held by an unexpected connection after the teardown", victimAddr)
	}
}

// ---------------------------------------------------------------------------
// (d) inbound `peers` frames are rate-limited per connection
// ---------------------------------------------------------------------------

func floodPeers(first int, n int) []byte {
	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("%d.%d.0.1:8333", 100+((first+i)/256)%100, (first+i)%256)
	}
	return MarshalPeers(addrs)
}

// TestPeersFramesAreRateLimitedPerConnection is defect (d).
//
// OnPeers called PeerStore.AddFrom up to MaxPeersPerResponse times per frame,
// each taking the store's write lock — the same lock Adjust takes for every
// scored message from every peer and every dial selection read-takes — and
// returned CostFree. There was no per-connection message rate limit anywhere in
// the p2p layer, so nothing bounded how often one connection could ask for that
// work: measured at 0.58 ms, 3.5 ms and 46 ms per 64-address frame across three
// harnesses, i.e. one core saturated somewhere between ~35 KB/s and ~4 Mbit/s of
// attacker upload.
//
// It is also what made the other three cheap rather than separate: (a) and (b)
// both need a high free address-injection rate, and this handler supplied one.
func TestPeersFramesAreRateLimitedPerConnection(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 64, &clock)
	const attacker = "172.20.0.1:5000"
	getPeersHandshake(t, e, attacker)

	first := e.Handle(attacker, KindPeers, floodPeers(0, 8))
	if first.Err != ErrUnsolicited {
		t.Fatalf("the first frame was refused with %v, want the ordinary %v", first.Err, ErrUnsolicited)
	}
	if first.Score != 0 {
		t.Fatalf("the first frame was charged %d; a conforming peer must pay nothing", first.Score)
	}
	if _, ok := ps.Get("100.0.0.1:8333"); !ok {
		t.Fatal("the first frame's addresses were not recorded")
	}

	clock = clock.Add(time.Millisecond)
	second := e.Handle(attacker, KindPeers, floodPeers(64, 8))
	if second.Err != ErrPeersTooOften {
		t.Fatalf("a second frame %v after the first was refused with %v, want %v",
			time.Millisecond, second.Err, ErrPeersTooOften)
	}
	if second.Score != ScoreExcessRequest {
		t.Fatalf("the repeat was charged %d, not the excess-request class %d "+
			"(wire.md §10.4)", second.Score, ScoreExcessRequest)
	}
	if second.Cost != CostScored {
		t.Fatalf("the repeat's cost class is %v, want %v", second.Cost, CostScored)
	}
	if _, ok := ps.Get("100.64.0.1:8333"); ok {
		t.Fatal("a refused frame's addresses were recorded anyway: the refusal has to " +
			"be what stops the work, not merely what names it")
	}

	// The charge is what makes a flood terminate rather than merely be noticed.
	start, ok := ps.Get(attacker)
	if !ok {
		t.Fatal("the attacker has no store entry after a handshake")
	}
	banned := false
	for i := 0; i < 500; i++ {
		clock = clock.Add(time.Millisecond)
		e.Handle(attacker, KindPeers, floodPeers(1024+i*8, 8))
		if ps.Banned(attacker) {
			banned = true
			break
		}
	}
	if !banned {
		t.Fatalf("a flood of `peers` frames inside one %v window never reached the ban "+
			"threshold from a starting score of %d: the flood is unpriced and does not "+
			"terminate", PeersMinInterval, start.Score)
	}
}

// TestAPeersFrameAtTheIntervalIsAcceptedAndUnscored pins the boundary the
// charge is sized at, and it is the anti-vacuity for the test above: a limit
// that refused everything would also pass there.
//
// PeersMinInterval is GetPeersMinInterval, and GetPeersInterval — the
// rate a conforming node asks at — is ten times it, so a conforming peer's
// answer never comes near this floor.
func TestAPeersFrameAtTheIntervalIsAcceptedAndUnscored(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, ps := getPeersEngine(t, 64, &clock)
	const honest = "198.51.100.4:5000"
	getPeersHandshake(t, e, honest)

	if v := e.Handle(honest, KindPeers, floodPeers(0, 4)); v.Err != ErrUnsolicited {
		t.Fatalf("the first frame was refused: %v", v.Err)
	}
	// Exactly at the interval: the comparison is strict, so this is accepted.
	clock = clock.Add(PeersMinInterval)
	v := e.Handle(honest, KindPeers, floodPeers(200, 4))
	if v.Err != ErrUnsolicited {
		t.Fatalf("a frame exactly at %v was refused with %v; a peer on the interval "+
			"this node's own rule names must never be charged", PeersMinInterval, v.Err)
	}
	if v.Score != 0 {
		t.Fatalf("a frame exactly at %v was charged %d", PeersMinInterval, v.Score)
	}
	if _, ok := ps.Get("100.200.0.1:8333"); !ok {
		t.Fatal("a frame at the interval was accepted but its addresses were not recorded")
	}
	if PeersMinInterval*10 > DefaultGetPeersInterval {
		t.Fatalf("PeersMinInterval is %v, leaving under 10x headroom against the %v a "+
			"conforming node answers on: conforming traffic would be charged",
			PeersMinInterval, DefaultGetPeersInterval)
	}
}

// TestOnePeersFloodDoesNotSpendAnotherConnectionsWindow pins the keyspace. The
// limit lives on PeerTip, one entry per connection, so a flood on one socket
// cannot refuse the honest frame arriving on another.
func TestOnePeersFloodDoesNotSpendAnotherConnectionsWindow(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	e, _ := getPeersEngine(t, 64, &clock)
	const attacker = "172.20.0.1:5000"
	const honest = "198.51.100.4:5000"
	getPeersHandshake(t, e, attacker)
	getPeersHandshake(t, e, honest)

	for i := 0; i < 20; i++ {
		clock = clock.Add(time.Millisecond)
		e.Handle(attacker, KindPeers, floodPeers(i*8, 8))
	}
	if v := e.Handle(honest, KindPeers, floodPeers(900, 4)); v.Err != ErrUnsolicited {
		t.Fatalf("an honest peer's first frame was refused with %v after somebody "+
			"else's flood: the limit is keyed on the connection", v.Err)
	}
}
