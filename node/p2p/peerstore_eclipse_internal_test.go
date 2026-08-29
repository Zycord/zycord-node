package p2p

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func writeBootstrapFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDialLoopHonoursTheBudgetsAcrossRounds drives the dial loop's own
// selection, not the selector it calls.
//
// The distinction is the finding this test exists for. Both outbound bounds
// are counters built inside one selection call, and the dial loop calls it
// once per round; the defect was in what the caller passed, not in what the
// selector did with it. A test written against PeerStore alone re-implements
// the loop by hand and therefore cannot see the caller getting it wrong — with
// only that test, reverting node.go to pass nil, or to call SelectDiverse,
// left the whole suite green.
func TestDialLoopHonoursTheBudgetsAcrossRounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fill  func(ps *PeerStore)
		limit int
	}{
		{
			name: "one teller",
			fill: func(ps *PeerStore) {
				for i := 0; i < 40; i++ {
					ps.AddFrom(fmt.Sprintf("11.%d.0.1:8333", i), "198.18.7.7:9421")
				}
			},
			limit: MaxPerSource,
		},
		{
			name: "one /16",
			fill: func(ps *PeerStore) {
				for i := 0; i < 40; i++ {
					ps.Add(fmt.Sprintf("192.0.%d.1:8333", i))
				}
			},
			limit: MaxFallbackPerGroup,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := NewPeerStore("")
			if err != nil {
				t.Fatal(err)
			}
			tc.fill(ps)
			n := &Node{Peers: ps, MaxOutbound: 8, conns: map[string]*Conn{}, outboundTargets: map[string]bool{}}

			// Exactly what topUp does with what dialTargets returns, minus the
			// socket: every target is treated as a successful dial.
			for round := 0; round < 8; round++ {
				targets := n.dialTargets()
				if len(targets) == 0 {
					break
				}
				for _, addr := range targets {
					ps.MarkConnected(addr)
					n.conns[addr] = &Conn{Addr: addr}
					n.outboundTargets[addr] = true
				}
			}
			if got := len(n.outboundTargets); got > tc.limit {
				t.Fatalf("accreted %d of %d outbound slots across dial rounds, want at most %d: %v",
					got, n.MaxOutbound, tc.limit, n.outboundTargets)
			}
		})
	}
}

// TestClaimThenFloodCannotEvictWhatItClaimed is the attack the arrival-order
// tie-break exists for.
//
// First-teller-wins files an address under whoever gossiped it first, so an
// attacker that gossips *real* addresses before anyone else puts them in its
// own cohort — and a cohort at its ceiling evicts from inside. While the
// tie-break inside that cohort was the address string, the attacker simply
// chose flood addresses that sorted ahead of the real ones it had claimed, and
// removed 30 of 30 of them for about 32 `peers` frames.
func TestClaimThenFloodCannotEvictWhatItClaimed(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const attacker = "203.0.113.7:5555"
	claimed := make([]string, 30)
	for i := range claimed {
		claimed[i] = fmt.Sprintf("172.16.%d.1:9000", i)
		ps.AddFrom(claimed[i], attacker)
	}
	// Flood the same cohort, with addresses chosen to sort ahead of the
	// claimed ones on any address-based tie-break.
	for i := 0; i < MaxPerSourceStored*4; i++ {
		ps.AddFrom(fmt.Sprintf("10.%d.%d.1:9000", i/256%256, i%256), attacker)
	}
	lost := 0
	for _, a := range claimed {
		if _, ok := ps.Get(a); !ok {
			lost++
		}
	}
	if lost > 0 {
		t.Fatalf("claim-then-flood evicted %d of %d real addresses the attacker had named first", lost, len(claimed))
	}
}

// TestGossipedAndUngossipedGroupsAreSeparateCohorts is why cohort keys are
// namespaced by kind.
//
// A gossiped address is charged to its teller and an ungossiped one to its own
// address group. Both are AddressGroup strings, so unnamespaced they are the
// same key, and an attacker whose connection sits in the same /16 as the
// operator's bootstrap peers — the ordinary case in a cloud region — is
// charged to their population: the two then share one ceiling, and the
// attacker's flood spends the room the operator's own list needs.
//
// The observable property is exactly that: filling a teller's ceiling from a
// /16 must not reduce what the store will hold of ungossiped addresses in the
// same /16.
func TestGossipedAndUngossipedGroupsAreSeparateCohorts(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// The attacker speaks from the bootstrap peers' own /16 and fills its
	// ceiling.
	for i := 0; i < MaxPerSourceStored; i++ {
		ps.AddFrom(fmt.Sprintf("10.%d.%d.1:9000", i/256%256, i%256), "172.16.99.99:5555")
	}
	// The operator's list, ungossiped, in that same /16.
	bootstrap := make([]string, MaxPerSourceStored)
	for i := range bootstrap {
		bootstrap[i] = fmt.Sprintf("172.16.%d.%d:9421", i/256%256, i%256)
		ps.Add(bootstrap[i])
	}
	lost := 0
	for _, a := range bootstrap {
		if _, ok := ps.Get(a); !ok {
			lost++
		}
	}
	if lost > 0 {
		t.Fatalf("an attacker gossiping from the bootstrap peers' own /16 cost the operator's list %d of %d entries; "+
			"the teller's cohort and the address group's are sharing one key", lost, len(bootstrap))
	}
}

// TestCohortShareDecidesAmongUnprovenEntries pins the middle eviction key on
// its own.
//
// Isolating it takes care, and the first version of this test did not: the key
// below it is arrival order, newest first, so a test whose small cohort holds
// an *old* entry passes whether or not share is consulted at all. The entry
// share has to protect is the one arrival order would give up — the newest —
// so the lone entry of the small teller is added last, immediately before the
// probe.
func TestCohortShareDecidesAmongUnprovenEntries(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const big, small = "198.18.1.1:9421", "198.19.1.1:9421"
	bigAddrs := MaxPerSourceStored - 1
	for i := 0; i < bigAddrs; i++ {
		ps.AddFrom(fmt.Sprintf("11.%d.%d.1:9000", i/256%256, i%256), big)
	}
	for i := len(ps.peers); i < MaxPeers-1; i++ {
		ps.AddFrom(fmt.Sprintf("13.%d.%d.1:9000", i/256%256, i%256),
			fmt.Sprintf("%d.%d.7.7:9421", 20+i/256, i%256))
	}
	// Newest in the store, and the only entry its teller has.
	lone := "12.0.0.1:9000"
	ps.AddFrom(lone, small)
	if len(ps.peers) != MaxPeers {
		t.Fatalf("store holds %d, want the cap %d before probing", len(ps.peers), MaxPeers)
	}

	ps.AddFrom("14.0.0.1:9000", "198.20.1.1:9421")
	if _, ok := ps.Get(lone); !ok {
		t.Fatalf("eviction gave up the only entry of a one-address teller while a %d-address teller sat beside it; "+
			"arrival order decided where cohort share should have", bigAddrs)
	}
}

// TestLoadedStoreSurvivesADuplicatedAddress: peers.json is operator-visible,
// and a duplicated Addr used to file two records in the cohort index under one
// map key. The orphan is a live eviction candidate whose removal deletes the
// *surviving* record under that address — a peer silently lost — and leaves
// every cohort count it inflated permanently wrong.
func TestLoadedStoreSurvivesADuplicatedAddress(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/peers.json"
	writeBootstrapFile(t, path, `[
	  {"addr":"203.0.113.9:9421","src":"198.18.0.0/16"},
	  {"addr":"203.0.113.9:9421","src":"198.19.0.0/16"},
	  {"addr":"203.0.113.10:9421"}
	]`)
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	indexed := 0
	for _, m := range ps.cohorts {
		indexed += len(m)
	}
	if indexed != len(ps.peers) {
		t.Fatalf("cohort index holds %d entries against %d peers; a duplicated address in peers.json desynchronised it",
			indexed, len(ps.peers))
	}
}

// TestLoadedSrcIsValidated: a hand-edited or corrupted peers.json could
// otherwise give every entry a distinct Src — making every cohort a singleton
// and disarming the policy that reads it — or stamp an honest peer's group
// onto junk and hand that peer the eviction bill.
func TestLoadedSrcIsValidated(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	writeBootstrapFile(t, path, `[
	  {"addr":"203.0.113.9:9421","src":"`+strings.Repeat("x", 1000)+`"},
	  {"addr":"203.0.113.10:9421","src":"not-a-group"},
	  {"addr":"203.0.113.11:9421","src":"198.18.0.0/16"}
	]`)
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for addr, p := range ps.peers {
		if !validGroup(p.Src) {
			t.Fatalf("peer %s loaded with an unvalidated Src %q", addr, p.Src)
		}
	}
	if got := ps.peers["203.0.113.11:9421"].Src; got != "198.18.0.0/16" {
		t.Fatalf("a legitimate Src was dropped on load: %q", got)
	}
	// invalidGroup is a value this node itself writes, and must survive.
	if !validGroup(invalidGroup) {
		t.Fatal("validGroup rejects the group AddressGroup produces for an unparseable address")
	}
}

// TestBootstrapExpansionIsCappedAndDeduped: a name is answered by a resolver,
// and the resolver is not necessarily the operator's.
func TestBootstrapExpansionIsCappedAndDeduped(t *testing.T) {
	var ips []net.IPAddr
	for i := 0; i < 40; i++ {
		ips = append(ips, net.IPAddr{IP: net.ParseIP(fmt.Sprintf("198.51.100.%d", i%3))})
	}
	got := bootstrapTargets(ips, "9421")
	if len(got) != 3 {
		t.Fatalf("40 answers over 3 distinct addresses expanded to %d targets, want 3 deduplicated: %v", len(got), got)
	}
	ips = nil
	for i := 0; i < 40; i++ {
		ips = append(ips, net.IPAddr{IP: net.ParseIP(fmt.Sprintf("198.51.100.%d", i))})
	}
	if got := bootstrapTargets(ips, "9421"); len(got) != maxBootstrapAddrs {
		t.Fatalf("40 distinct answers expanded to %d targets, want the cap %d", len(got), maxBootstrapAddrs)
	}
}

// TestUnresolvableBootstrapEntryIsReported: a bootstrap name that does not
// resolve produces exactly the silent, peerless node resolving exists to
// prevent, unless something says so.
func TestUnresolvableBootstrapEntryIsReported(t *testing.T) {
	var buf bytes.Buffer
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{
		Peers:     ps,
		Logger:    log.New(&buf, "", 0),
		conns:     map[string]*Conn{},
		quit:      make(chan struct{}),
		Bootstrap: []string{"no-such-host-xyzzy.invalid:9421"},
	}
	n.addBootstrap()
	done := make(chan struct{})
	go func() { n.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * bootstrapResolveTimeout):
		t.Fatal("bootstrap resolution did not finish")
	}
	if !strings.Contains(buf.String(), "no-such-host-xyzzy.invalid:9421") {
		t.Fatalf("an unresolvable bootstrap entry was dropped without a word; log=%q", buf.String())
	}
}

func TestLoadedSeqIsOneBucketOlderThanAnythingLearnedAfterwards(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	writeBootstrapFile(t, path, `[
	  {"addr":"10.0.0.1:9000","seq":9223372036854775807},
	  {"addr":"10.0.0.2:9000","seq":1},
	  {"addr":"10.0.0.3:9000"}
	]`)
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// The absolute value is not trusted: a file claiming MaxInt64 must not
	// leave nextSeq anywhere near it, or every address learned afterwards
	// overflows to a negative Seq and becomes the entry eviction never reaches.
	if ps.nextSeq != 1 {
		t.Fatalf("nextSeq is %d after loading three entries; the file's absolute values were trusted", ps.nextSeq)
	}
	// Nor is the relative order: the file gets no say in which of its own
	// entries is given up first, so all three share one arrival bucket.
	a, b, c := ps.peers["10.0.0.3:9000"], ps.peers["10.0.0.2:9000"], ps.peers["10.0.0.1:9000"]
	if !(a.Seq == b.Seq && b.Seq == c.Seq) {
		t.Fatalf("the file still ordered its own entries against each other: %d, %d, %d", a.Seq, b.Seq, c.Seq)
	}
	// And the bucket is the oldest one, so a flood arriving after the load
	// spends its own arrivals before it reaches anything this node chose to
	// remember.
	ps.Add("10.0.0.4:9000")
	if got := ps.peers["10.0.0.4:9000"].Seq; got <= a.Seq {
		t.Fatalf("an address learned after the load got Seq=%d against the restored bucket's %d, "+
			"so it sorts no newer than them and eviction reaches the restored entries first", got, a.Seq)
	}
}

// TestLoadIsDeterministicAcrossRestarts: Go map iteration is randomised, so
// renumbering without a total order would assign a different arrival order on
// every load and the store would evict differently after each restart.
func TestLoadIsDeterministicAcrossRestarts(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	writeBootstrapFile(t, path, `[
	  {"addr":"10.0.0.1:9000"},{"addr":"10.0.0.2:9000"},{"addr":"10.0.0.3:9000"},
	  {"addr":"10.0.0.4:9000"},{"addr":"10.0.0.5:9000"},{"addr":"10.0.0.6:9000"}
	]`)
	var first map[string]int64
	for i := 0; i < 8; i++ {
		ps, err := NewPeerStore(path)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int64{}
		for addr, p := range ps.peers {
			got[addr] = p.Seq
		}
		if first == nil {
			first = got
			continue
		}
		for addr, seq := range got {
			if first[addr] != seq {
				t.Fatalf("load %d assigned %s Seq=%d where the first load assigned %d; "+
					"arrival order is not stable across restarts", i, addr, seq, first[addr])
			}
		}
	}
}

// TestLoadedCohortIsTrimmedToItsCeiling: a bound that only ever stops future
// growth never undoes past growth. A peers.json written by a build from before
// the ceiling — or edited by hand — can hold one teller far past it, and
// loading it unfiltered keeps that concentration one restart deep, which is
// the same "poisons peers.json permanently" failure the store cap exists to
// close.
func TestLoadedCohortIsTrimmedToItsCeiling(t *testing.T) {
	path := t.TempDir() + "/peers.json"
	var entries []string
	for i := 0; i < MaxPerSourceStored*3; i++ {
		entries = append(entries, fmt.Sprintf(`{"addr":"10.%d.%d.%d:9000","src":"198.18.0.0/16"}`,
			i/65536%256, i/256%256, i%256))
	}
	writeBootstrapFile(t, path, "["+strings.Join(entries, ",")+"]")
	ps, err := NewPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ps.cohorts["src:198.18.0.0/16"]); got > MaxPerSourceStored {
		t.Fatalf("a single teller loaded %d entries against a ceiling of %d; "+
			"an over-ceiling peers.json survives a restart", got, MaxPerSourceStored)
	}
}

// TestFirstTellerWinsOnReGossip: the cohort key is fixed at creation, and
// everything downstream relies on that. Letting a later teller relabel an
// address it did not originate lets an attacker adopt an operator's bootstrap
// entry into its own cohort, relabel addresses out of an honest teller's, and
// — because the entry is already filed in the index under its original key —
// desynchronise the cohort index against the peer map.
func TestFirstTellerWinsOnReGossip(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const addr = "198.51.100.7:9000"
	ps.AddFrom(addr, "192.0.2.1:9421")
	ps.AddFrom(addr, "203.0.113.1:9421")
	bootstrap := "198.51.100.8:9000"
	ps.Add(bootstrap)
	ps.AddFrom(bootstrap, "203.0.113.1:9421")

	if got := ps.peers[addr].Src; got != "192.0.0.0/16" {
		t.Fatalf("a second teller relabelled an address it did not originate: Src=%q", got)
	}
	if got := ps.peers[bootstrap].Src; got != "" {
		t.Fatalf("gossip adopted an operator bootstrap entry into a teller's cohort: Src=%q", got)
	}
	// And the index still agrees with the map.
	for a, p := range ps.peers {
		if ps.cohorts[cohort(p)][a] != p {
			t.Fatalf("peer %s is filed under a cohort key that is no longer its own", a)
		}
	}
}

// TestEvictionTierUsesEveryClauseOfItsEvidence pins the two clauses that
// distinguish the tiers, each of which shipped once with no assertion behind
// it while networking.md §11 states both directions as a rule.
func TestEvictionTierUsesEveryClauseOfItsEvidence(t *testing.T) {
	// Score > 0 alone is evidence, without a completed connection: a peer that
	// has only ever sent useful messages over an inbound connection has earned
	// standing even though this node never dialled it.
	scored := &Peer{Addr: "203.0.113.1:9421", Score: 5}
	if got := evictionTier(scored); got != 2 {
		t.Fatalf("a peer with earned score but no completed dial is tier %d, want 2 (proven)", got)
	}
	// Failures without a single success is evidence *against*, and must rank
	// below a never-tried address rather than beside it.
	failed := &Peer{Addr: "203.0.113.2:9421", Failures: 3}
	untried := &Peer{Addr: "203.0.113.3:9421"}
	if got := evictionTier(failed); got != 0 {
		t.Fatalf("a peer dialled %d times and never once answered is tier %d, want 0", failed.Failures, got)
	}
	if got := evictionTier(untried); got != 1 {
		t.Fatalf("a never-tried address is tier %d, want 1 (unproven)", got)
	}
	// A long record plus one failed redial is not evidence against.
	established := &Peer{Addr: "203.0.113.4:9421", Score: 50, LastSeen: 1, Failures: 1}
	if got := evictionTier(established); got != 2 {
		t.Fatalf("a peer with a record and one failed redial is tier %d, want 2", got)
	}
}

// TestScoringKeepsTheTierIndexInStep pins retierLocked at the two entry points
// that change a peer's tier without creating or destroying it.
//
// tier0 is a second index over the same peers, and a second index is only ever
// as good as the discipline that maintains it. Both directions matter: an
// entry that scores below zero has to enter the set, or eviction stops finding
// the worst thing in the store; and one that climbs back out has to leave it,
// or eviction keeps giving up an entry that no longer deserves it while a
// genuinely worse one sits elsewhere.
func TestScoringKeepsTheTierIndexInStep(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const addr = "203.0.113.1:9421"
	ps.Add(addr)
	if _, in := ps.tier0[addr]; in {
		t.Fatal("a never-tried address is in the tier-0 set")
	}

	ps.Adjust(addr, -5)
	if _, in := ps.tier0[addr]; !in {
		t.Fatal("a peer scored below zero did not enter the tier-0 set; eviction can no longer find it")
	}
	ps.Adjust(addr, +10)
	if _, in := ps.tier0[addr]; in {
		t.Fatal("a peer that scored back above zero stayed in the tier-0 set; eviction keeps giving it up")
	}

	// MarkFailed on an address that has never once answered is the other way in.
	const failing = "203.0.113.2:9421"
	ps.Add(failing)
	ps.MarkFailed(failing)
	if _, in := ps.tier0[failing]; !in {
		t.Fatal("an address dialled and never answered did not enter the tier-0 set")
	}
	// And a peer with a real record plus one failed redial is not tier 0.
	const established = "203.0.113.3:9421"
	ps.Add(established)
	ps.MarkConnected(established)
	ps.MarkFailed(established)
	if _, in := ps.tier0[established]; in {
		t.Fatal("a peer with a completed connection and one failed redial was filed as tier 0")
	}
}

// TestTierIndexDecidesTheVictim is the consequence of the two above: the point
// of keeping tier0 in step is that eviction gives up the demonstrably bad entry
// rather than an unproven one, wherever in the store it sits.
func TestTierIndexDecidesTheVictim(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// One entry that scored itself down, alone in its cohort, against a store
	// otherwise full of untried addresses spread over many tellers.
	const bad = "203.0.113.9:9421"
	ps.AddFrom(bad, "192.0.2.1:9421")
	ps.Adjust(bad, -5)
	for i := len(ps.peers); i < MaxPeers; i++ {
		ps.AddFrom(fmt.Sprintf("11.%d.%d.1:9000", i/256%256, i%256),
			fmt.Sprintf("%d.%d.7.7:9421", 20+i/256, i%256))
	}
	ps.Add("198.51.100.1:9421")
	if _, ok := ps.Get(bad); ok {
		t.Fatal("eviction gave up an untried address while a peer that had scored itself below zero remained")
	}
}
