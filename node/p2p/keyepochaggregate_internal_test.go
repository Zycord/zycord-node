package p2p

import (
	"fmt"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
)

// The AGGREGATE half of the ban-budget key-epoch question — one identity can
// spend its whole ban budget forcing never-held RandomX key epochs, and nothing
// bounds the aggregate over identities — which has never had an instrument.
//
// It has two halves. The per-identity half has two instruments and names them —
// TestAUniqueInvalidHeaderFloodIsSelfLimiting and
// TestAHeightVaryingFloodIsBoundedInEpochsToo, both in flood_internal_test.go —
// and the key-epoch price added six more. The second half, "nothing bounds the
// aggregate over identities", has none, which is why the issue can only say of
// the three constants it names that "none of those has been measured against a
// real adversary".
//
// This file measures it. It asserts what is true today rather than what should
// be true, so every test here is a characterisation test: each says in its own
// failure message that a bound has appeared and that it should be deleted and
// replaced by a statement of the bound.
//
// **WHICH HALF EVERY COUNT BELONGS TO, because there are two and they are not
// interchangeable.** Every count in this file except the last test's is on the
// UNCHARGED path: announceAtEpoch declares Target = u256.Max and asserts
// pow.CheckWork PASSES, so the verdict is ScoreUsefulMessage, nothing is ever
// charged and no ban is reachable. The identity is free there, so the aggregate
// is bounded by address resources alone and that is what the numbers below are.
//
// The original table and decisions/testnet-measurements.md §2's sentence naming a
// Sybil count as the missing input are scoped to the CHARGED half — headers
// carrying the target the rule computes, which the work check refuses at
// ScoreInvalidMessage. On that half node.go accumulates the score on the
// ed25519 key (Peers.AdjustKey) and gates on Peers.BannedKey, so one identity
// is bounded at MaxUnheldKeyEpochsPerPeer however many connections it opens,
// and §2's sentence is CORRECT for it. TestTheChargedHalfsAggregateIsStillBounded-
// PerIdentityByTheBan measures both arms so that no figure here can be read
// across the boundary: charged 5 (10 from the ceiling) and banned, uncharged 240
// and never banned.
//
// What is measured, and the three claims are separate:
//
//  1. The engine applies NOTHING across connections. The whole of the price is
//     Engine.spendKeyEpoch against Engine.tips[conn]; there is no second
//     accumulator and no ceiling over the map.
//  2. The only ceiling anywhere is Node.register's concurrent connection count,
//     it lives in a different file, and it does not survive a disconnect —
//     Node.unregister calls Engine.forgetPeer, which deletes the budget.
//  3. Neither of the two diversity currencies this tree already prices Sybils
//     in is consulted: not AddressGroup, which withhold.go's skewGroups uses
//     for exactly this kind of bounding, and not the peer store, whose
//     SelectDiverse / SelectDialTargets rules bound a different set entirely.

// aggregateHarness drains a set of connections and reports the total number of
// distinct never-held key epochs they forced between them.
//
// It reuses budgetHarness — one engine, one devnet chain at genesis, a frozen
// clock and an epoch counter in front of the work function — so that the counts
// below are the same quantity keyepochbudget_internal_test.go measures, and are
// comparable with the per-connection figures published for the price itself.
type aggregateHarness struct {
	*budgetHarness
	// epoch walks upward forever so that no two announcements in a run ever
	// name the same key epoch. Without that the second connection's drain
	// would reuse the first's keys and distinctKeys() would report the epochs
	// one connection can force rather than the epochs the set can.
	epoch uint64
	nonce uint64
}

func newAggregateHarness(t *testing.T) *aggregateHarness {
	t.Helper()
	h := newBudgetHarness(t)
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	// Start two epochs above the tip's, because {own, own+1} is exempt by
	// design (workingKeyEpoch) and an announcement into either of them is free
	// and would not be counted against any budget at all.
	return &aggregateHarness{budgetHarness: h, epoch: own + 2}
}

// drain spends one connection's whole budget and returns how many
// announcements were admitted before the refusal.
//
// The refusal is required, not merely awaited: a drain that ran out of
// patience rather than out of credits would silently under-report, and every
// total in this file is a sum of these.
func (a *aggregateHarness) drain(t *testing.T, conn string) int {
	t.Helper()
	admitted := 0
	for {
		v := a.announceAtEpoch(t, conn, a.epoch, a.nonce)
		a.epoch++
		a.nonce++
		if v.Cost == CostBudgeted {
			return admitted
		}
		admitted++
		if admitted > MaxUnheldKeyEpochsPerPeer {
			t.Fatalf("connection %q was admitted %d unheld key epochs against a "+
				"budget of %d: the price is not being charged at all, and every "+
				"aggregate in this file is measuring something else",
				conn, admitted, MaxUnheldKeyEpochsPerPeer)
		}
	}
}

// TestTheEngineAppliesNoBoundAcrossConnectionsToTheKeyEpochPrice measures the
// aggregate at its instantaneous ceiling — the largest connection set
// Node.register will hold at once — and finds it to be the per-connection
// budget multiplied by that set, exactly.
//
// The multiplication is the finding. The price is derived from what ONE
// identity may spend before ScoreBanThreshold removes it, and a ban is applied
// by node.go as Peers.AdjustKey(conn.PeerKey, ...) — against the ed25519 key,
// so it is one budget however many connections the identity holds. The key
// epoch price is charged against Engine.tips[peerAddr], so it is one budget per
// connection. Nothing in the engine adds them up and nothing compares the sum
// with anything.
//
// Both ceilings are read from NewNode rather than retyped, and BOTH of
// register's conjuncts are given a separating input, because the gate is
//
//	if !outbound && len(n.conns) >= n.MaxInbound+n.MaxOutbound
//
// and a test that only ever registers inbound varies one term of a two-term
// guard. The (cap+1)-th INBOUND registration is required to be refused, which
// is what the length term does; the same registration made OUTBOUND is
// required to be ADMITTED, which is what the !outbound term does. That second
// row is why the figure this test reports is MaxInbound + 2 x MaxOutbound and
// not MaxInbound + MaxOutbound — the product engine.go's reassembly arithmetic
// and syncdriver.go's syncTried bound both already state for this connection
// set, each giving the same reason: "register's capacity gate is inbound-only
// and topUp bounds outbound separately". node.go's dialLoop supplies the
// outbound half in production (serve(conn, true)), and serve skips
// Listener.Release for it, so the LISTENER never charges an outbound
// connection against a group in its own table. (It is not uncharged
// everywhere: SelectDialTargets applies its own one-slot-per-/16 rule and
// MaxFallbackPerGroup when this node chooses those targets. What is being said
// is that the listener's per-group table, which is what the group price below
// is denominated in, never sees them.)
//
// **One term of the 48 is arithmetic and is declared rather than driven.** The
// inbound gate is measured (A7) and the !outbound bypass is measured (S1), but
// that outbound is bounded at MaxOutbound is topUp's doing and topUp is not
// exercised here — this loop simply runs MaxOutbound times. Raising topUp's
// `need` leaves every test in this file passing. Driving it needs real dials
// against real peers, which is dialLoop's own test ground; the 2 x MaxOutbound
// term is therefore inherited from engine.go and syncdriver.go rather than
// established here.
func TestTheEngineAppliesNoBoundAcrossConnectionsToTheKeyEpochPrice(t *testing.T) {
	a := newAggregateHarness(t)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, a.e, nil, 1)
	// Where the gate refuses, and what the set reaches once topUp has dialled
	// its own MaxOutbound on top of a full inbound table.
	inboundCap := n.MaxInbound + n.MaxOutbound
	full := n.MaxInbound + 2*n.MaxOutbound

	total := 0
	for i := 0; i < inboundCap; i++ {
		// One address group per connection, which is the arrangement the
		// listener's perSource bound permits: it holds at most perSource
		// connections from any one origin, so a set this size is a set of
		// distinct origins.
		conn := fmt.Sprintf("10.%d.0.2:5000", i+1)
		if !n.register(&Conn{Addr: conn}, false) {
			t.Fatalf("setup: registration %d of %d was refused, so the inbound "+
				"table is not full", i+1, inboundCap)
		}
		total += a.drain(t, conn)
	}
	inbound, inboundTotal := a.work.distinctKeys(), total

	// Conjunct one, the length term: the inbound table really is full, so
	// `inboundCap` is a bound this node sets and not the number this loop
	// chose to run.
	if n.register(&Conn{Addr: "10.250.0.2:5000"}, false) {
		t.Fatalf("setup: an inbound connection was admitted above %d, so the "+
			"length term of register's gate is not MaxInbound+MaxOutbound and "+
			"neither figure below is measured at a ceiling", inboundCap)
	}

	// Conjunct two, the !outbound term, and it is the separating input the
	// figure above does not have: the SAME registration that was just refused
	// is admitted when it is outbound, so the inbound cap is not the size of
	// the connection set and the aggregate does not stop there.
	for i := 0; i < n.MaxOutbound; i++ {
		conn := fmt.Sprintf("10.200.%d.2:5000", i+1)
		if !n.register(&Conn{Addr: conn}, true) {
			t.Fatalf("an outbound registration was refused above the inbound "+
				"cap of %d: register's gate is no longer inbound-only, so the "+
				"connection set is bounded at %d rather than %d — this "+
				"characterisation test has served its purpose, delete it and "+
				"state the aggregate at that ceiling instead", inboundCap,
				inboundCap, full)
		}
		total += a.drain(t, conn)
	}

	if got := len(n.conns); got != full {
		t.Fatalf("the connection set holds %d connections, want %d = "+
			"MaxInbound + 2 x MaxOutbound", got, full)
	}

	forced := a.work.distinctKeys()
	wantInbound := inboundCap * MaxUnheldKeyEpochsPerPeer
	want := full * MaxUnheldKeyEpochsPerPeer
	t.Logf("a saturated INBOUND table of %d connections (MaxInbound %d + "+
		"MaxOutbound %d) holds %d unheld key epochs at once; register's gate "+
		"is inbound-only, so topUp's own %d outbound connections are admitted "+
		"on top and the full concurrent set of %d holds %d (budget %d per "+
		"connection, %d admitted announcements) — the engine's aggregate is "+
		"the product and nothing else",
		inboundCap, n.MaxInbound, n.MaxOutbound, inbound, n.MaxOutbound, full,
		forced, MaxUnheldKeyEpochsPerPeer, total)

	if inbound != wantInbound || inboundTotal != wantInbound {
		t.Fatalf("the saturated inbound table forced %d unheld key epochs over "+
			"%d admitted announcements, want %d for both", inbound, inboundTotal,
			wantInbound)
	}
	if total != want || forced != want {
		t.Fatalf("the connection set forced %d unheld key epochs over %d "+
			"admitted announcements, want %d for both: either the engine has "+
			"acquired a bound across connections — in which case this "+
			"characterisation test has served its purpose, delete it and state "+
			"the aggregate bound instead — or the drains stopped selecting one "+
			"fresh epoch each and this file measures less than an attacker buys",
			forced, total, want)
	}
}

// TestTheKeyEpochAggregateHasACeilingOverTime is the mintable-identity
// aggregate, stated from the far side of its fix, and it keeps BOTH of the
// separating inputs the defect had.
//
// The budget used to live in Engine.tips[conn], and two independent things
// handed it back — a single row cannot tell them apart, because in production
// they happen together:
//
//   - **the key changed.** An inbound peer's Conn.Addr is "ip:ephemeral_port",
//     which PeerStore.AdjustKey's own comment calls "a value the OS picks fresh
//     on every reconnect, not the peer". A reconnect was a different map key, so
//     it was a different budget, whatever the engine remembered.
//   - **the entry was deleted.** Node.unregister calls Engine.forgetPeer, whose
//     body is delete(e.tips, conn). So even a sender coming back on the SAME
//     address — transport.go's own comment says two accepted connections can
//     share an observed RemoteAddr, because "an attacker with a direct IP can
//     bind a specific local port, close, and reconnect from it before this
//     node's Release for the first one runs" — found a fresh budget waiting.
//
// Measured then: 4 rounds x 40 connections with the clock frozen forced 800
// unheld key epochs, [200 200 200 200] per round, linear in handshakes with
// nothing in front of it.
//
// **Both reasons are still live and both are now harmless**, which is why the
// rows are kept rather than deleted. Engine.forgetPeer still deletes the
// PeerTip entry and the address is still what the OS picks; the budget simply
// is not there any more. What each connection presents as a payer here is its
// own address, so this arrangement is the WORST case for the identity layer —
// every round buys a fresh per-identity budget, exactly as measured — and
// what stops it is the layer above, which is keyed on nothing a sender presents
// at all.
//
// So the assertion is DefaultMaxUnheldKeyEpochsPerNode and not the per-identity
// budget, and the two rows differ by design: the first presents fresh payers
// every round and is capped by the node-wide ceiling, and the second presents
// the same payers every round and is capped LOWER, by their own spent budgets.
// A fix that only stopped forgetPeer deleting would pass the second row and
// fail the first, which is what makes this two rows rather than one.
//
// The clock never advances in either row, so no credit below is a refill, and
// the ceiling is a rate rather than a lifetime allowance:
// TestASpentKeyEpochBudgetRefillsAtTheChainsOwnEpochRate is where the refill is
// separated.
func TestTheKeyEpochAggregateHasACeilingOverTime(t *testing.T) {
	const rounds = 4

	run := func(t *testing.T, addr func(conn, round int) string, wantMax int) {
		t.Helper()
		a := newAggregateHarness(t)
		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		n := NewNode(id, a.e, nil, 1)
		cap := n.MaxInbound + n.MaxOutbound

		perRound := make([]int, 0, rounds)
		for r := 0; r < rounds; r++ {
			round := 0
			for i := 0; i < cap; i++ {
				conn := addr(i, r)
				if !n.register(&Conn{Addr: conn}, false) {
					t.Fatalf("setup: round %d registration %d refused", r, i)
				}
				round += a.drain(t, conn)
				n.unregister(&Conn{Addr: conn})
			}
			perRound = append(perRound, round)
		}

		forced := a.work.distinctKeys()
		unbounded := rounds * cap * MaxUnheldKeyEpochsPerPeer
		t.Logf("%d rounds x %d connections, clock frozen: %d unheld key epochs "+
			"forced (%v per round), against %d with no ceiling over time and a "+
			"node-wide ceiling of %d",
			rounds, cap, forced, perRound, unbounded, DefaultMaxUnheldKeyEpochsPerNode)

		if forced > DefaultMaxUnheldKeyEpochsPerNode {
			t.Fatalf("%d rounds forced %d unheld key epochs against a node-wide "+
				"ceiling of %d. The aggregate grows with the handshakes the "+
				"sender chooses to pay for, so the budget is keyed on a currency "+
				"the sender mints",
				rounds, forced, DefaultMaxUnheldKeyEpochsPerNode)
		}
		// Anti-vacuity, and it is per row: a ceiling that holds because the
		// harness stopped forcing epochs proves nothing. Each row states the
		// largest total its own arrangement can reach, so a fix that refused
		// everything fails here.
		if forced != wantMax {
			t.Fatalf("%d rounds forced %d unheld key epochs, want exactly %d for "+
				"this arrangement. Below that, something refuses these before "+
				"the budget does and the ceiling above is measuring that instead",
				rounds, forced, wantMax)
		}
		if unbounded <= DefaultMaxUnheldKeyEpochsPerNode {
			t.Fatalf("this arrangement reaches only %d epochs without any "+
				"ceiling at all, which is at or under the ceiling of %d, so it "+
				"cannot separate one from the other",
				unbounded, DefaultMaxUnheldKeyEpochsPerNode)
		}
	}

	// Reason one: the address the OS picks was the map key, so each round is a
	// fresh payer and the node-wide ceiling is the only thing left holding.
	t.Run("a fresh ephemeral port each round", func(t *testing.T) {
		run(t, func(conn, round int) string {
			return fmt.Sprintf("10.%d.0.2:%d", conn+1, 40000+round)
		}, DefaultMaxUnheldKeyEpochsPerNode)
	})

	// Reason two, and the separating input for forgetPeer's delete: the sender
	// returns on the address it left from, so the payer is identical across
	// rounds and its own budget is spent after the first — which is BELOW the
	// node-wide ceiling, and is the row that says the per-identity layer is
	// carrying its share rather than being masked by the layer above.
	t.Run("the same address each round", func(t *testing.T) {
		run(t, func(conn, round int) string {
			return fmt.Sprintf("10.%d.0.2:5000", conn+1)
		}, 40*MaxUnheldKeyEpochsPerPeer)
	})
}

// TestTheNodeWideKeyEpochCeilingBoundsTheAggregateOverIdentities is the
// separating input for the layer that is keyed on nothing at all.
//
// The per-identity budget bounds the RATE one identity forces epochs at, and
// the measurement is that it cannot bound the TOTAL, because an ed25519
// keypair is free: a sender presenting a fresh identity per announcement is
// never over its own budget and every message is its first. This drives exactly
// that — one fresh payer per announcement, so the per-identity layer refuses
// nothing at all — and requires the node-wide ceiling to be what stops it.
//
// It is the conjunct the test above cannot separate. There, every arrangement
// also spends per-identity budgets, so a fix that only moved the budget onto
// the identity would move those numbers; here nothing is ever charged twice to
// one payer, so a node with no ceiling forces one epoch per message forever.
func TestTheNodeWideKeyEpochCeilingBoundsTheAggregateOverIdentities(t *testing.T) {
	a := newAggregateHarness(t)
	const send = 4 * DefaultMaxUnheldKeyEpochsPerNode

	refused := 0
	for n := 0; n < send; n++ {
		payer := fmt.Sprintf("fresh-identity-%d", n)
		v := a.announceAtEpochFrom(t, "10.80.0.1:5000", payer, a.epoch, a.nonce)
		a.epoch++
		a.nonce++
		if v.Cost == CostBudgeted {
			refused++
		}
	}
	forced := a.work.distinctKeys()
	t.Logf("%d announcements, a fresh identity for each, clock frozen: %d "+
		"unheld key epochs forced, %d refused unevaluated, against a node-wide "+
		"ceiling of %d", send, forced, refused, DefaultMaxUnheldKeyEpochsPerNode)

	if forced != DefaultMaxUnheldKeyEpochsPerNode {
		t.Fatalf("%d fresh identities forced %d unheld key epochs, want exactly "+
			"the node-wide ceiling of %d. A keypair is free, so a bound keyed "+
			"on the identity bounds the rate and never the total",
			send, forced, DefaultMaxUnheldKeyEpochsPerNode)
	}
	if refused != send-DefaultMaxUnheldKeyEpochsPerNode {
		t.Fatalf("%d of %d announcements were refused unevaluated, want %d; the "+
			"refusals and the epochs must account for every message, or the "+
			"count above is not the ceiling doing the work",
			refused, send, send-DefaultMaxUnheldKeyEpochsPerNode)
	}
}

// TestTheKeyEpochPriceIsNotKeyedOnTheAddressGroup separates the one currency
// this tree already prices Sybils in.
//
// AddressGroup — /16 for IPv4, /32 for IPv6 — is what Listener.perSource
// charges against, what SelectDiverse's one-slot-per-group rule is written in,
// and what withhold.go's skewGroups uses for a bounded set keyed on a sender.
// That last one is the closest precedent in this package for the shape a bound
// on this aggregate would take, and its comment gives the reason in one line:
// "Grouped by /16 rather than by address, because an ip:port lets one host be
// several senders for the price of a second socket."
//
// The key epoch price is keyed by address. This test is the separating input:
// the same number of connections, drained the same way, once with every
// connection in its OWN group and once with every connection in ONE group. The
// totals are equal, which is what "the group is not consulted" means as a
// measurement rather than as a reading of the code.
func TestTheKeyEpochPriceIsNotKeyedOnTheAddressGroup(t *testing.T) {
	const conns = 8

	measure := func(t *testing.T, addr func(i int) string) (int, map[string]bool) {
		t.Helper()
		a := newAggregateHarness(t)
		groups := map[string]bool{}
		for i := 0; i < conns; i++ {
			c := addr(i)
			groups[AddressGroup(c)] = true
			a.drain(t, c)
		}
		return a.work.distinctKeys(), groups
	}

	spread, spreadGroups := measure(t, func(i int) string {
		return fmt.Sprintf("10.%d.0.2:5000", i+1)
	})
	// One host, one group, one socket each — exactly the arrangement
	// skewGroups exists to refuse to be fooled by.
	single, singleGroups := measure(t, func(i int) string {
		return fmt.Sprintf("10.70.0.2:%d", 40000+i)
	})

	// Anti-vacuity, and it is the whole test: the two arrangements must
	// genuinely differ in the quantity being probed, or equal totals prove
	// nothing.
	if len(spreadGroups) != conns {
		t.Fatalf("setup: the spread arrangement occupies %d address groups, "+
			"want %d — the two rows do not differ in the group count and the "+
			"comparison below is between two copies of the same input",
			len(spreadGroups), conns)
	}
	if len(singleGroups) != 1 {
		t.Fatalf("setup: the single-group arrangement occupies %d address "+
			"groups, want 1", len(singleGroups))
	}

	t.Logf("%d connections across %d address groups forced %d unheld key "+
		"epochs; the same %d connections inside ONE group forced %d — the "+
		"price is charged per address, and an ip:port is a second socket",
		conns, len(spreadGroups), spread, conns, single)

	if single != spread {
		t.Fatalf("one address group bought %d unheld key epochs where %d "+
			"groups bought %d: the price now depends on the address group, so "+
			"the aggregate is denominated in the currency the eclipse defences "+
			"already use — delete this test and state that bound instead",
			single, len(spreadGroups), spread)
	}
	if single != conns*MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("%d connections in one group forced %d unheld key epochs, "+
			"want %d", conns, single, conns*MaxUnheldKeyEpochsPerPeer)
	}
}

// TestTheKeyEpochPriceDoesNotConsultThePeerStore separates the other currency.
//
// The analysis lists "MaxInbound, the /16 address-diversity rule and the reserved
// inbound slot" as what bounds the number of concurrent identities. Two of
// those are the listener's and are measured above. The third, the peer store's
// diversity machinery, bounds a set this aggregate is not drawn from at all:
// SelectDialTargets chooses which addresses THIS node dials, and SelectDiverse
// chooses which addresses this node SERVES to a peer that asks — and
// SelectDiverse's own comment records that it "deliberately does not apply the
// per-source bound SelectDialTargets applies". Neither is consulted when an
// announcement arrives on a connection somebody else opened.
//
// Measured rather than read: the aggregate is identical whether the store is
// empty or saturated from a single source, and the anti-vacuity arm shows the
// store really does bound the thing it bounds.
func TestTheKeyEpochPriceDoesNotConsultThePeerStore(t *testing.T) {
	const conns = 8

	measure := func(t *testing.T, seed func(ps *PeerStore)) int {
		t.Helper()
		a := newAggregateHarness(t)
		seed(a.e.Peers)
		for i := 0; i < conns; i++ {
			a.drain(t, fmt.Sprintf("10.%d.0.2:5000", i+1))
		}
		return a.work.distinctKeys()
	}

	empty := measure(t, func(*PeerStore) {})

	var saturated *PeerStore
	fromOne := measure(t, func(ps *PeerStore) {
		saturated = ps
		// Every address learned from one teller, across many groups: the
		// input SelectDialTargets' per-source bound exists for.
		for i := 0; i < 64; i++ {
			ps.AddFrom(fmt.Sprintf("10.%d.0.9:5000", 100+i), "10.99.0.1:5000")
		}
	})

	// Anti-vacuity: the store this node was handed is one the diversity rule
	// really does constrain, so "the aggregate did not move" is a statement
	// about the price and not about the store being inert.
	if got := len(saturated.SelectDialTargets(conns, nil, nil)); got > MaxPerSource {
		t.Fatalf("setup: SelectDialTargets returned %d addresses from a single "+
			"teller, above MaxPerSource = %d — the store is not constrained "+
			"and the comparison below proves nothing", got, MaxPerSource)
	}

	t.Logf("aggregate with an empty peer store: %d unheld key epochs; with a "+
		"store SelectDialTargets will draw at most %d from: %d — the price on "+
		"an inbound announcement is not drawn from the store at all",
		empty, MaxPerSource, fromOne)

	if fromOne != empty {
		t.Fatalf("the aggregate moved from %d to %d when the peer store "+
			"changed: the key epoch price now consults the store, so the "+
			"address-diversity rule bounds it — delete this test and state "+
			"that bound instead", empty, fromOne)
	}
	if empty != conns*MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("%d connections forced %d unheld key epochs, want %d",
			conns, empty, conns*MaxUnheldKeyEpochsPerPeer)
	}
}

// TestTheReachableConcurrentKeyEpochAggregateCostsAddressGroups puts the group
// price on the concurrent figure the first test measures — and DRIVES the
// listener to find that price rather than reading a field off it.
//
// The first test fills the connection set without asking what a connection
// costs. Two layers charge for one: Node.register admits an inbound connection
// only below MaxInbound+MaxOutbound, and the listener charges each accepted
// connection against its origin's address group.
//
// **The share one group holds is perSource + reserve, not perSource.**
// acceptRaw's switch admits while `held[group] < perSource` OR while
// `probationary[group] < reserve`, and BOTH classes are delivered by Accept,
// reach serve, reach register, enter Node.conns and get their own
// Engine.tips budget. expireProbationLocked deliberately reclaims nothing —
// its own comment says "the slot returns when the close does" — so at an
// instant a probationary connection is every bit as concurrent as a held one.
// node/p2p.TestTheReserveIsBounded says the same thing next door: it fills with
// perSource + DefaultInboundReserve and asserts the connection after that is
// refused. An earlier version of this file divided by perSource alone and
// published 14 groups; the figure is attached to what is held AT ONCE, and at
// an instant the reserve is concurrent, so it is ceil(cap/(perSource+reserve)).
//
// The share is therefore MEASURED here, through real TLS dials against the
// listener Node.Listen builds, and not read off Listener.perSource. Reading the
// field cannot see the reserve at all: with the field read, raising
// DefaultInboundReserve to 20 (one group then really holds 23, so the real
// price is 2 groups) and deleting the per-group gate outright both left this
// test reporting 14 and passing. Driving it is what makes the number a price.
//
// The DURABLE share is the smaller one and is reported beside it: probationary
// connections are closed by Node.probationLoop after DefaultInboundProbation,
// so holding the table without re-handshaking costs ceil(cap/perSource).
//
// The INBOUND table is what this test prices, deliberately, and it is the half
// an attacker buys directly. The outbound connections that take the concurrent
// set to MaxInbound + 2 x MaxOutbound (first test) are dialled by this node
// from its own peer store under SelectDialTargets' per-source and /16 rules,
// and serve never charges them against the LISTENER at all — so they are not
// priced in this currency and are not counted here.
//
// Every count here is on the UNCHARGED path: see this file's header.
func TestTheReachableConcurrentKeyEpochAggregateCostsAddressGroups(t *testing.T) {
	a := newAggregateHarness(t)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, a.e, nil, 1)
	cap := n.MaxInbound + n.MaxOutbound

	// The admission parameters, taken from the listener Node.Listen actually
	// builds rather than retyped.
	if err := n.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	perGroup := n.listener.perSource
	reserve := n.listener.reserve
	// Closed before the measurement: Node.acceptLoop would consume the
	// connections this test needs to count, and it is the LISTENER's admission
	// arithmetic that is being priced, not serve's.
	n.listener.Close()

	// The price, measured: an equivalent listener, configured from the fields
	// above so that nothing here is retyped, dialled from one origin until it
	// stops accepting. Every loopback dial is one address group, so this is
	// exactly "what does one /16 hold at once".
	probe, err := id.Listen("127.0.0.1:0", perGroup)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	share := measureOneGroupsConcurrentShare(t, probe, cap+1)

	// Anti-vacuity, and it is the assertion the field read could not make: one
	// group must hold strictly fewer connections than the table, or a single
	// group fills the table and there is no group price to report at all.
	if share >= cap {
		t.Fatalf("one address group held %d concurrent inbound connections "+
			"against a table of %d: the listener no longer bounds one group "+
			"below the connection set, so the aggregate costs ONE group and "+
			"this test has served its purpose — delete it and state that",
			share, cap)
	}
	// The measured share is the two constants that produce it. Raising either
	// moves both sides and moves the reported price with them; that is the
	// argument class this row is in.
	if want := perGroup + reserve; share != want {
		t.Fatalf("one address group held %d concurrent inbound connections, "+
			"want perSource + reserve = %d + %d = %d — the listener's admission "+
			"arithmetic has changed and the group price below is not it",
			share, perGroup, reserve, want)
	}

	groups := (cap + share - 1) / share
	durable := (cap + perGroup - 1) / perGroup

	total, held := 0, 0
	for held < cap {
		g := held/share + 1
		for i := 0; i < share && held < cap; i++ {
			conn := fmt.Sprintf("10.%d.0.%d:5000", g, i+2)
			if !n.register(&Conn{Addr: conn}, false) {
				t.Fatalf("setup: registration %d refused below the cap of %d", held, cap)
			}
			held++
			total += a.drain(t, conn)
		}
	}

	forced := a.work.distinctKeys()
	want := cap * MaxUnheldKeyEpochsPerPeer
	t.Logf("measured by dialling the shipped listener: one address group holds "+
		"%d concurrent inbound connections (perSource %d + reserve %d), so "+
		"filling the inbound table of %d costs %d address groups and holds %d "+
		"never-held key epochs at once (budget %d per connection); holding it "+
		"WITHOUT re-handshaking costs %d groups, since the %d probationary "+
		"connections per group are closed after DefaultInboundProbation; this "+
		"node's own %d outbound connections are admitted above the gate and "+
		"charged against no group in the listener's table at all; and none of "+
		"it survives a disconnect",
		share, perGroup, reserve, cap, groups, forced,
		MaxUnheldKeyEpochsPerPeer, durable, reserve, n.MaxOutbound)

	if forced != want || total != want {
		t.Fatalf("the reachable inbound table forced %d unheld key epochs over "+
			"%d admitted announcements, want %d for both: a bound has appeared "+
			"across connections, so delete this test and state it", forced, total, want)
	}
}

// measureOneGroupsConcurrentShare dials ln from a single origin until it stops
// accepting, and reports how many connections that one address group held at
// once. Both admission classes count, because both reach register.
func measureOneGroupsConcurrentShare(t *testing.T, ln *Listener, give int) int {
	t.Helper()
	accepted := make(chan *Conn, give+1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dialer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var open []*Conn
	t.Cleanup(func() {
		for _, c := range open {
			c.Close()
		}
	})
	share := 0
	for i := 0; i < give; i++ {
		c, err := dialer.Dial(ln.Addr().String(), 2*time.Second)
		if err != nil {
			// Refused by the listener: the group is full.
			break
		}
		open = append(open, c)
		select {
		case s := <-accepted:
			open = append(open, s)
			share++
			continue
		case <-time.After(2 * time.Second):
			// Accepted at the socket but never delivered: also full.
		}
		break
	}
	return share
}

// TestTheChargedHalfsAggregateIsStillBoundedPerIdentityByTheBan is the control
// for every other count in this file, and it is what says which half
// they belong to.
//
// The two halves are priced in different currencies. Every other test here
// drives announceAtEpoch, which declares Target = u256.Max and asserts
// pow.CheckWork PASSES — that is the UNCHARGED path, where the verdict is
// ScoreUsefulMessage and no ban is ever reachable. The original table, and
// decisions/testnet-measurements.md §2's sentence naming a Sybil count as the
// missing input, are scoped to the CHARGED half: headers carrying the target
// the rule itself computes, which the work check REFUSES at
// ScoreInvalidMessage.
//
// On that half the identity is not a currency the sender mints for free.
// node.go applies the verdict as Peers.AdjustKey(conn.PeerKey, v.Score) and
// gates on Peers.BannedKey(conn.PeerKey), so one ed25519 key carries ONE tally
// across every connection it holds — which is exactly what the second,
// identity-keyed store was built for. So the charged aggregate is bounded per
// identity by the ban however many connections that identity opens, and its
// aggregate over identities really is that bound times a Sybil count.
//
// This test measures both arms so that no number in this file can be read as
// applying to the other half.
func TestTheChargedHalfsAggregateIsStillBoundedPerIdentityByTheBan(t *testing.T) {
	charged := func(t *testing.T, start int) (epochs, sent int, banned bool) {
		t.Helper()
		a := newAggregateHarness(t)
		p := a.c.Params()
		tip := a.c.Tip()
		honest := pow.NextTarget(a.c.RecentHeaders(int(p.DifficultyWindow)+1), p)

		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		key := id.PublicKey()
		a.e.Peers.AdjustKey(key, start)

		n := NewNode(id, a.e, nil, 1)
		full := n.MaxInbound + 2*n.MaxOutbound
		epoch := a.epoch
		for c := 0; c < full && !banned; c++ {
			conn := fmt.Sprintf("10.%d.0.2:5000", c+1)
			for m := 0; m < 20 && !banned; m++ {
				height := p.RandomXKeyLag + epoch*p.RandomXKeyInterval
				epoch++
				hd := types.Header{
					Version: types.HeaderVersion,
					Height:  height,
					// A parent this node does not hold, and NOT the tip — the
					// same move `headerAtEpoch` made under the tip-parent
					// target rule and for the same reason one rule over. A
					// block whose parent is the tip is at tip.Height+1, and
					// these heights are whole key epochs away, so a
					// tip-parented header here is one no chain can contain and
					// is now refused ahead of the work check. This arm is
					// defined by the work check refusing — that is what
					// "charged" means in the two columns below — so it has to
					// reach it; with the tip named, the charged column measured
					// a different refusal and reported zero forced epochs.
					ParentID: types.Hash{0xab},
					Time:     tip.Time + p.TargetBlockSeconds,
					Target:   honest, // the RULE's target: the work check refuses
					CertRoot: certRoot(nil, p),
					PoW: types.PoWSeal{Nonce: uint32(sent) | 1<<31,
						SeedEpoch: pow.SeedEpochFor(height, p)},
				}
				v := a.e.OnBlockAnnounce(conn, BlockAnnounce{Header: hd}.MarshalAnnounce())
				sent++
				// Exactly the two statements node.go applies (:1330, :1336).
				if v.Score != 0 {
					a.e.Peers.AdjustKey(key, v.Score)
				}
				banned = a.e.Peers.BannedKey(key)
			}
		}
		return a.work.distinctKeys(), sent, banned
	}

	fromZero, sentZero, bannedZero := charged(t, 0)
	fromCeiling, sentCeiling, bannedCeiling := charged(t, ScoreCeiling)

	// The uncharged arm, same harness and the same whole connection set, so the
	// two are separated by the declared target and by nothing else.
	a := newAggregateHarness(t)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, a.e, nil, 1)
	full := n.MaxInbound + 2*n.MaxOutbound
	for i := 0; i < full; i++ {
		a.drain(t, fmt.Sprintf("10.%d.0.2:5000", i+1))
	}
	uncharged := a.work.distinctKeys()
	unchargedBanned := a.e.Peers.BannedKey(id.PublicKey())

	t.Logf("one identity across the whole connection set of %d. CHARGED (the "+
		"rule's own target, work check refuses): from score 0, %d never-held "+
		"key epochs over %d messages, BannedKey=%v; from ScoreCeiling, %d over "+
		"%d, BannedKey=%v. UNCHARGED (declared u256.Max, work check passes): "+
		"%d, BannedKey=%v. The charged half is bounded per IDENTITY by the "+
		"ed25519 ban, so its aggregate is that bound times a Sybil count; the "+
		"uncharged half is not, and every other count in this file is on it",
		full, fromZero, sentZero, bannedZero, fromCeiling, sentCeiling,
		bannedCeiling, uncharged, unchargedBanned)

	if !bannedZero || !bannedCeiling {
		t.Fatalf("the charged flood did not reach a ban from score 0 (%v) or "+
			"from the ceiling (%v) across %d connections: the identity-keyed "+
			"tally has stopped bounding the charged half per identity, so "+
			"the aggregate sentence and §2's Sybil input are no longer "+
			"about a bounded quantity — delete this test and state that",
			bannedZero, bannedCeiling, full)
	}
	if fromZero != MaxUnheldKeyEpochsPerPeer {
		t.Fatalf("the charged flood from score 0 forced %d never-held key "+
			"epochs before the ban, want %d", fromZero, MaxUnheldKeyEpochsPerPeer)
	}
	// The two starting scores now force the SAME number of epochs, and that
	// equality is the score conjunct's doing rather than a weakening of this
	// test. While the over-budget refusal was unconditionally unscored,
	// goodwill bought epochs: the from-ceiling row forced twice the from-zero
	// row and was never banned across sixty messages. The refusal is now
	// charged ScoreInvalidMessage for an identity the work check has already
	// refused, so goodwill buys MESSAGES — sentCeiling above sentZero, which is
	// the ban absorbing the goodwill — and buys no additional epochs at all.
	if fromCeiling != fromZero {
		t.Fatalf("the charged flood forced %d never-held key epochs from the "+
			"ceiling against %d from score zero. Past the budget a header never "+
			"reaches the work check, so an unscored refusal lets goodwill buy "+
			"epochs and the flood stops terminating",
			fromCeiling, fromZero)
	}
	if sentCeiling <= sentZero {
		t.Fatalf("the flood from the ceiling was banned after %d messages and "+
			"the one from zero after %d: goodwill must still cost the flood "+
			"messages, or this row is not starting where it says it is",
			sentCeiling, sentZero)
	}
	// And the two halves are still separated by the declared target, which is
	// what every other count in this file rests on: the uncharged half reaches
	// the node-wide ceiling because no ban is reachable on it.
	if fromZero >= uncharged {
		t.Fatalf("the charged flood forced %d and the uncharged one %d: the two "+
			"halves are no longer separated by the declared target",
			fromZero, uncharged)
	}
	if uncharged != DefaultMaxUnheldKeyEpochsPerNode {
		t.Fatalf("the uncharged flood across the whole connection set forced %d "+
			"never-held key epochs, want the node-wide ceiling of %d",
			uncharged, DefaultMaxUnheldKeyEpochsPerNode)
	}
	if unchargedBanned {
		t.Fatalf("the uncharged flood reached a ban: it is now scored, so the " +
			"aggregate this file measures is bounded per identity too")
	}
}
