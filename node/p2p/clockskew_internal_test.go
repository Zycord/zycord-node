package p2p

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"strings"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/storage"
	"zycord/spec"
)

// skewHarness is a Node wired to a bare Engine and a buffer, with n connected
// address groups, which is all reportClockSkew reads.
func skewHarness(dialled int) (*Engine, *Node, *bytes.Buffer) {
	var buf bytes.Buffer
	e := &Engine{withholdLimits: DefaultWithholdLimits(), withheld: map[types.Hash]*withheldBlock{}}
	n := &Node{
		Engine: e, Logger: log.New(&buf, "", 0),
		conns:           map[string]*Conn{},
		outboundTargets: map[string]bool{},
	}
	for i := 0; i < dialled; i++ {
		addr := fmt.Sprintf("10.%d.0.1:9000", i)
		n.conns[addr] = nil
		n.outboundTargets[addr] = true
	}
	// What topUp and unregister do on every change to the outbound set. The
	// Engine needs it at *record* time, not at report time, so a harness that
	// skipped it would test a node that never dialled anything.
	n.mu.Lock()
	groups := n.dialledGroupsLocked()
	n.mu.Unlock()
	e.SetDialledGroups(groups)
	return e, n, &buf
}

// TestClockSkewIsReportedAtEveryDropRate is the operator-facing half of the
// slow-clock stall, and the regression test for the way the first version of it
// failed.
//
// The counter alone is not the fix: a node whose clock is slow has to *say* so,
// and it has to say it on a schedule that survives the condition being
// permanent. Doubling is that schedule. What this pins is that the schedule
// holds no matter how many blocks land between two ticks of withholdLoop.
//
// That is not a hypothetical parameter. A node in this condition receives one
// copy of each block from each of its peers — OnBlockAnnounce drops a
// future-dated announcement before it reaches seenBlocks, so OnBlock's
// "seen && !waiting" dedupe never fires, and node.go's serve loop re-broadcasts
// an accepted body to every peer but the sender — while this loop ticks once a
// second and blocks arrive every TargetBlockSeconds. The count therefore steps
// by the peer count, and the first version of this test stepped it by one,
// which is the only step size at which the bug it missed does not bite.
func TestClockSkewIsReportedAtEveryDropRate(t *testing.T) {
	// Peer counts a real node has. The guard this replaces logged nothing at
	// all for 3, 5, 7 and 10 — a multiple of p is a power of two only when p
	// is a power of two.
	for _, perTick := range []uint64{1, 2, 3, 4, 5, 6, 7, 8, 10, 13} {
		t.Run(fmt.Sprintf("%d-per-tick", perTick), func(t *testing.T) {
			e, n, buf := skewHarness(8)

			// Ten minutes of withholdLoop at its one-second default.
			var lineAt []uint64
			for tick := 0; tick < 600; tick++ {
				for i := uint64(0); i < perTick; i++ {
					e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i%4), 3600+perTick)
				}
				before := buf.Len()
				n.reportClockSkew()
				if buf.Len() != before {
					lineAt = append(lineAt, e.BeyondHorizon().Count)
				}
			}

			if len(lineAt) == 0 {
				t.Fatalf("%d blocks per tick, %d in total, and the node never said "+
					"a word — which is the silence this sensor exists to end",
					perTick, e.BeyondHorizon().Count)
			}
			for i := 1; i < len(lineAt); i++ {
				if lineAt[i] < lineAt[i-1]*2 {
					t.Fatalf("lines at %v: %d follows %d without the count doubling",
						lineAt, lineAt[i], lineAt[i-1])
				}
			}
			// And it must not go quiet either. The first line is owed at the
			// first count observed — one step, so perTick — and one more at
			// every doubling from there, which over 600 ticks is log2(600)
			// whatever the step size is. That invariance is the point.
			total := 600 * perTick
			if lineAt[0] != perTick {
				t.Fatalf("the first line came at %d blocks, want it at the first "+
					"count observed (%d)", lineAt[0], perTick)
			}
			want := 0
			for at := perTick; at <= total; at *= 2 {
				want++
			}
			if len(lineAt) != want {
				t.Fatalf("%d lines at %v for %d blocks in steps of %d, want %d — the "+
					"schedule is skipping doublings", len(lineAt), lineAt, total, perTick, want)
			}
		})
	}
}

// TestClockSkewSaysNothingWithoutEvidence pins that a healthy node is silent.
func TestClockSkewSaysNothingWithoutEvidence(t *testing.T) {
	_, n, buf := skewHarness(8)
	for tick := 0; tick < 100; tick++ {
		n.reportClockSkew()
	}
	if buf.Len() != 0 {
		t.Fatalf("a node with no future-dated blocks logged %q", buf.String())
	}
}

// TestOneHostOnTwoPortsIsOneSender is the Sybil the first breadth rule was
// built to survive and did not.
//
// peerAddr for an inbound connection is RemoteAddr().String(), whose port is
// ephemeral. Keyed on that, one machine reconnecting on a second source port is
// two senders — which satisfied a "more than one sender" rule and told an
// honest node with a correct clock to go and fix its NTP, for the price of a
// second socket.
func TestOneHostOnTwoPortsIsOneSender(t *testing.T) {
	e, n, buf := skewHarness(8)
	for i := 0; i < 2000; i++ {
		// One host, two source ports, alternating.
		e.recordBeyondHorizon(fmt.Sprintf("203.0.113.9:%d", 40001+i%2), 3600)
		n.reportClockSkew()
	}
	if r := e.BeyondHorizon(); r.Groups != 1 {
		t.Fatalf("two source ports on one host counted as %d senders, want 1: the "+
			"evidence has to be grouped by address group, which is this package's "+
			"Sybil unit", r.Groups)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("2000 future-dated blocks and nothing logged at all")
	}
	// The line has to make the reading obvious: one group out of eight is a
	// peer, not this machine's clock.
	if !strings.Contains(out, "from 1 address group(s), first 203.0.0.0/16") {
		t.Errorf("the line does not name the single group it is evidence about, "+
			"which is the one thing an operator can act on; log=%q", out)
	}
}

// TestTheLineCarriesEvidenceAgainstDialledPeers pins the numbers a reader
// needs, and the fact that the node does not decide for them.
//
// Two rules that *did* decide were tried and both were wrong. "More than one
// sender" fell to two source ports. "A majority of connected address groups"
// was worse in two directions at once: an attacker holding nine silent
// connections from distinct groups pushes an honest majority under the
// threshold and suppresses a true diagnosis, and the rule is unreachable by
// construction on a loopback test net, a 192.168 LAN, a docker bridge, or a
// node whose peers sit in one IPv6 /32 — the population least likely to be
// running NTP at all. So the line reports and the operator judges.
func TestTheLineCarriesEvidenceAgainstDialledPeers(t *testing.T) {
	// Eight of eight: what a slow local clock looks like.
	e, n, buf := skewHarness(8)
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i), 3608)
	}
	n.reportClockSkew()
	out := buf.String()
	if !strings.Contains(out, ", 8 of them among the 8 peer(s) this node dialled") {
		t.Errorf("the line does not report 8 of 8 dialled peers; log=%q", out)
	}
	for _, want := range []string{"3608", "NTP", "clock"} {
		if !strings.Contains(out, want) {
			t.Errorf("the line never mentions %q; log=%q", want, out)
		}
	}

	// A single group on a node with one connection — a LAN, a docker bridge, a
	// loopback devnet. A rule requiring more than one connected group would say
	// nothing here forever; this must still report.
	e, n, buf = skewHarness(1)
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon("192.168.1.5:9000", 3608)
	}
	n.reportClockSkew()
	if buf.Len() == 0 {
		t.Fatal("a node whose peers are all inside one address group — a LAN, a " +
			"docker bridge, a loopback devnet — logged nothing at any skew, which " +
			"is the population least likely to have NTP at all")
	}
}

// TestAnOngoingEpisodeIsNeverSilentForLong closes the adversary-settable
// silencer.
//
// The doubling schedule alone can be aimed: an attacker producing blocks at a
// few thousand hashes each runs the count to 10^6 for seconds of CPU, and the
// next line then needs 10^6 more. Ending the episode does not close it either,
// because the reset needs skewEpisodeIdleTicks *consecutive* quiet ticks and
// one message every fifty-nine ticks keeps it open forever. Measured on the
// version without the floor: a genuine mainnet clock fault at 8 blocks per 30 s
// logged nothing for a simulated day — 23,040 blocks — on its way to 43 of them.
func TestAnOngoingEpisodeIsNeverSilentForLong(t *testing.T) {
	e, n, buf := skewHarness(8)

	// A flood sets the threshold out of reach.
	for i := 0; i < 1_000_000; i++ {
		e.recordBeyondHorizon("203.0.113.9:40001", 4000)
	}
	n.reportClockSkew()
	buf.Reset()

	// Now a real fault, trickling far below the threshold, and a trickle slow
	// enough that the episode never idles out either.
	lines := 0
	for tick := 0; tick < skewMaxSilentTicks*3; tick++ {
		if tick%(skewEpisodeIdleTicks-1) == 0 {
			e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", tick%8), 4000)
		}
		before := buf.Len()
		n.reportClockSkew()
		if buf.Len() != before {
			lines++
		}
	}
	if lines == 0 {
		t.Fatalf("an ongoing episode logged nothing across %d ticks because a "+
			"flood had set the threshold to %d; that is a rate limiter an "+
			"adversary can aim", skewMaxSilentTicks*3, n.skew.next)
	}
	// And the floor must bound the noise as well as the silence.
	if lines > 6 {
		t.Fatalf("%d lines across %d ticks; the floor is meant to bound the noise "+
			"at about one per %d ticks", lines, skewMaxSilentTicks*3, skewMaxSilentTicks)
	}
}

// TestAnEpisodeEndsSoTheNextOneIsHeard is the other half of the same attack,
// and of the benign case that motivates it.
//
// The threshold only ever rises, so a counter that never resets is a silencer:
// after an episode of N the next line needs N more. Measured on the version
// without this, a 5000-block episode the operator had already fixed kept the
// next genuine one quiet for 4999 further blocks.
func TestAnEpisodeEndsSoTheNextOneIsHeard(t *testing.T) {
	e, n, buf := skewHarness(8)

	for i := 0; i < 5000; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i%8), 4000)
	}
	n.reportClockSkew()
	if buf.Len() == 0 {
		t.Fatal("setup: the first episode logged nothing")
	}

	// The operator fixes the clock. Nothing further arrives.
	for tick := 0; tick < skewEpisodeIdleTicks+1; tick++ {
		n.reportClockSkew()
	}
	if r := e.BeyondHorizon(); r.Count != 0 {
		t.Fatalf("the episode did not end: %d blocks still counted after %d idle "+
			"ticks with an empty queue", r.Count, skewEpisodeIdleTicks+1)
	}
	buf.Reset()

	// A new fault, one block in, must be heard at once.
	e.recordBeyondHorizon("10.0.0.1:9000", 4000)
	n.reportClockSkew()
	if buf.Len() == 0 {
		t.Fatalf("a fresh episode was silent because the previous one had set the " +
			"threshold to 10000; that is a rate limiter an adversary can aim")
	}
}

// TestAStandingQueueKeepsTheEpisodeOpen pins that "no new blocks" is not the
// same as "recovered".
//
// Below the queue bound a slow clock loses nothing — every block is held and
// released late — so a node still carrying a backlog is still running behind.
// Resetting on idleness alone would forget the condition while it was going on.
func TestAStandingQueueKeepsTheEpisodeOpen(t *testing.T) {
	e, n, _ := skewHarness(8)
	e.mu.Lock()
	e.withheld[types.Hash{1}] = &withheldBlock{}
	e.mu.Unlock()
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i), 4000)
	}
	n.reportClockSkew()

	for tick := 0; tick < skewEpisodeIdleTicks*3; tick++ {
		n.reportClockSkew()
	}
	if r := e.BeyondHorizon(); r.Count == 0 {
		t.Fatal("the episode was reset while a block was still queued; a standing " +
			"backlog is the condition continuing, not a node recovered")
	}
}

// TestSkewGroupSetIsBounded pins that the set answering "how many senders"
// cannot be grown without limit by the senders being counted.
func TestSkewGroupSetIsBounded(t *testing.T) {
	e, _, _ := skewHarness(8)
	for i := 0; i < maxSkewGroups*10; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("%d.%d.0.1:9000", 10+i/256, i%256), 3601)
	}
	r := e.BeyondHorizon()
	if r.Groups != maxSkewGroups {
		t.Fatalf("the skew group set holds %d entries, want it saturated at %d",
			r.Groups, maxSkewGroups)
	}
	if r.Count != uint64(maxSkewGroups*10) {
		t.Fatalf("the count is %d, want %d — saturating the group set must not "+
			"stop the counting", r.Count, maxSkewGroups*10)
	}
}

// TestSkewRecordsTheFirstSenderNotTheLast pins which sender a single-group
// report names. A report that renamed its suspect on every block would be
// useless to whoever is chasing it.
func TestSkewRecordsTheFirstSenderNotTheLast(t *testing.T) {
	e, _, _ := skewHarness(8)
	e.recordBeyondHorizon("203.0.113.9:40001", 3601)
	for i := 0; i < 10; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("198.51.%d.7:5000", i), 3601)
	}
	if got := e.BeyondHorizon().FirstGroup; got != "203.0.0.0/16" {
		t.Fatalf("FirstGroup is %q, want the first sender's group 203.0.0.0/16", got)
	}
}

// TestSkewIgnoresAnUnaddressedSender covers the guard on OnBlock's exported
// address argument, and the line it produces.
func TestSkewIgnoresAnUnaddressedSender(t *testing.T) {
	e, n, buf := skewHarness(8)
	e.recordBeyondHorizon("", 3601)
	e.recordBeyondHorizon("", 3602)
	r := e.BeyondHorizon()
	if r.Count != 2 {
		t.Fatalf("counted %d, want 2: a sender-less block is still a block", r.Count)
	}
	if r.Groups != 0 {
		t.Fatalf("%d groups from two unaddressed blocks — \"nobody sent it\" is not "+
			"evidence about anybody", r.Groups)
	}
	n.reportClockSkew()
	if out := buf.String(); !strings.Contains(out, "from 0 address group(s),") {
		t.Errorf("the line does not report that no sender was recorded, so it "+
			"claims more than it knows; log=%q", out)
	}
}

// TestWorstSkewIsTheMaxNotTheLatest pins the only quantitative number in the
// line.
//
// MaxSkewSeconds is documented as the number an operator would set their clock
// by, and every other test here happens to record equal or rising skews — so
// "track the latest" passed the whole suite. A report that follows the last
// message tells the operator whatever the most recent sender happened to say.
func TestWorstSkewIsTheMaxNotTheLatest(t *testing.T) {
	e, _, _ := skewHarness(4)
	e.recordBeyondHorizon("10.0.0.1:9000", 4000)
	e.recordBeyondHorizon("10.1.0.1:9000", 200)
	e.recordFutureAnnouncement("10.2.0.1:9000", 50)
	e.RecordSyncWithheld("10.3.0.1:9000", 10)
	if got := e.BeyondHorizon().MaxSkewSeconds; got != 4000 {
		t.Fatalf("worst skew reported as %ds after a 4000s message followed by "+
			"smaller ones, want 4000: the field is the worst seen, not the last",
			got)
	}
}

// TestResetSkewEvidenceClearsEverything pins that an episode really ends.
//
// A field left behind is a fact from a condition that is over, reported as
// though it were current — and maxSkewSeconds in particular is the number an
// operator would set their clock by.
func TestResetSkewEvidenceClearsEverything(t *testing.T) {
	e, _, _ := skewHarness(8)
	e.recordFutureAnnouncement("10.1.0.1:9000", 4000)
	e.recordBeyondHorizon("10.2.0.1:9000", 5000)
	e.RecordSyncWithheld("10.3.0.1:9000", 6000)
	e.mu.Lock()
	e.recordWithholdOverflowLocked("10.4.0.1:9000", 7000)
	e.recordFutureWithheldLocked("10.5.0.1:9000", 8000)
	e.mu.Unlock()

	if before := e.BeyondHorizon(); before.Count != 5 {
		t.Fatalf("setup: five paths recorded %d", before.Count)
	}
	e.ResetSkewEvidence()
	got := e.BeyondHorizon()
	if got.Count != 0 || got.Announced != 0 || got.SyncPasses != 0 ||
		got.Withheld != 0 || got.QueueFull != 0 || got.BeyondHorizon != 0 ||
		got.MaxSkewSeconds != 0 || got.Groups != 0 || len(got.Senders) != 0 ||
		got.FirstGroup != "" {
		t.Fatalf("after ResetSkewEvidence the report is %+v, want every field "+
			"zeroed; a leftover is a fact from an episode that is over", got)
	}
}

// TestInboundConnectionsCannotMoveTheRatio is the suppression attack, and the
// reason the denominator is the peers this node dialled.
//
// Read against every connection, the ratio is a number an attacker sets from
// both ends. Measured on that version: eleven cheap inbound sockets took a
// genuine 8-of-8 local clock fault down to "8 of 19 connected", which reads as
// one bad peer — and ten sockets in ten address groups replaying one forged
// future-dated announcement produced "10 address group(s)" on a node whose
// clock was exactly right. Outbound targets are chosen by this node through
// SelectDiverse; nobody can add himself to them by connecting, and nobody can
// remove the honest ones.
func TestInboundConnectionsCannotMoveTheRatio(t *testing.T) {
	e, n, buf := skewHarness(8)

	// A genuine fault: all eight dialled peers look ahead.
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i), 4000)
	}

	// An attacker dials in from eleven fresh address groups.
	n.mu.Lock()
	for i := 0; i < 11; i++ {
		n.conns[fmt.Sprintf("203.%d.0.9:40000", i)] = nil
	}
	n.mu.Unlock()

	n.reportClockSkew()
	out := buf.String()
	if !strings.Contains(out, ", 8 of them among the 8 peer(s) this node dialled") {
		t.Fatalf("eleven inbound sockets moved the ratio the operator reads; the "+
			"denominator has to be the peers this node chose, or an attacker "+
			"suppresses a true diagnosis for the price of connecting; log=%q", out)
	}
}

// TestForgedBreadthDoesNotAgreeWithDialledPeers is the other half of the same
// attack: the numerator.
//
// A future-dated announcement costs about 64 hashes to forge — OnBlockAnnounce
// checks the work a header *declares* — and the announce path neither dedupes
// nor scores, so one header replayed from N address groups puts N groups into
// the evidence. What it cannot do is make those groups peers this node dialled,
// so the forgery shows up as a large group count with no agreement, which is
// visibly a different shape from a clock fault.
func TestForgedBreadthDoesNotAgreeWithDialledPeers(t *testing.T) {
	e, n, buf := skewHarness(8)
	for i := 0; i < 10; i++ {
		e.recordFutureAnnouncement(fmt.Sprintf("203.%d.0.9:40000", i), 3599)
	}
	n.reportClockSkew()
	out := buf.String()
	// Anchored: "10 of them …" contains "0 of them …", so the substring form of
	// this assertion agreed with a mutant that dropped the intersection
	// entirely and counted every evidence group as agreement.
	if !strings.Contains(out, ", 0 of them among the 8 peer(s) this node dialled") {
		t.Fatalf("forged breadth from ten address groups was counted as agreement "+
			"from this node's own peers; log=%q", out)
	}
	if !strings.Contains(out, "from 10 address group(s)") {
		t.Errorf("the line hides the forged breadth instead of showing its shape; log=%q", out)
	}
}

// TestDialledPeersAreNeverCrowdedOutOfTheEvidence closes the suppression
// attack's second route.
//
// The evidence set saturates at maxSkewGroups by *insertion order*, so a flat
// cap lets an attacker who sends first keep this node's own peers out of it for
// the whole episode. Measured on the version without the exemption: 32 primed
// groups, then a genuine 4000 s local clock fault delivering messages from all
// eight dialled peers, and the report still read "0 of them among the 8 peer(s)
// this node dialled" — the shape a forgery makes, on a node that really was
// slow. Priming costs about 31 hashes a header and is unscored, so it can be
// repeated after every episode reset.
func TestDialledPeersAreNeverCrowdedOutOfTheEvidence(t *testing.T) {
	e, n, buf := skewHarness(8)

	// The attacker primes the set to its cap, from groups this node never
	// dialled, before any honest evidence arrives.
	for i := 0; i < maxSkewGroups; i++ {
		e.recordFutureAnnouncement(fmt.Sprintf("%d.%d.0.9:40000", 100+i/256, i%256), 3599)
	}
	if got := e.BeyondHorizon().Groups; got != maxSkewGroups {
		t.Fatalf("setup: primed %d groups, want the cap at %d", got, maxSkewGroups)
	}

	// Now this node's clock goes wrong and all eight dialled peers say so.
	for i := 0; i < 8; i++ {
		for j := 0; j < 100; j++ {
			e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i), 4000)
		}
	}
	n.reportClockSkew()
	out := buf.String()
	if !strings.Contains(out, ", 8 of them among the 8 peer(s) this node dialled") {
		t.Fatalf("a saturated evidence set kept every dialled peer out, so a real "+
			"local clock fault reads as a forgery; a cap that fills first-come is "+
			"a suppression lever for anyone willing to send first; log=%q", out)
	}
}

// TestAStrangerInADialledPeersSubnetIsNotThatPeer is the last place the number
// an operator reads was cheaper to forge than the doc claimed.
//
// Breadth is counted by address group, because one host on two source ports
// must not be two senders. Agreement is a different question: matching it by
// group too lets one host anywhere inside a dialled peer's /16 be counted as
// that peer agreeing. Measured on a node whose clock was exactly right, with
// its eight dialled peers silent and one attacker inside each of their eight
// /16s: "8 of them among the 8 peer(s) this node dialled" — check an NTP that
// is fine, for eight IPs in eight publicly discoverable subnets and no
// SelectDiverse contest to win.
//
// Matching exactly costs nothing here, because the addresses matched against
// are the ones this node chose to dial.
func TestAStrangerInADialledPeersSubnetIsNotThatPeer(t *testing.T) {
	e, n, buf := skewHarness(8) // dials 10.0.0.1:9000 … 10.7.0.1:9000

	// A stranger inside each dialled peer's /16, while the peers themselves say
	// nothing. Same groups, different hosts.
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.99.99:40000", i), 4000)
	}
	n.reportClockSkew()
	out := buf.String()
	if !strings.Contains(out, ", 0 of them among the 8 peer(s) this node dialled") {
		t.Fatalf("strangers sharing a /16 with this node's dialled peers were "+
			"counted as those peers agreeing, which sends an operator with a "+
			"correct clock after their NTP for eight IPs; log=%q", out)
	}
	// Breadth is still by group — that half must not regress.
	if got := e.BeyondHorizon().Groups; got != 8 {
		t.Errorf("breadth counted %d groups, want 8: agreement is exact, breadth "+
			"is by group, and they are different questions", got)
	}

	// And the real peers still agree when it is really them.
	e, n, buf = skewHarness(8)
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i), 4000)
	}
	n.reportClockSkew()
	if out := buf.String(); !strings.Contains(out, ", 8 of them among the 8 peer(s) this node dialled") {
		t.Fatalf("exact matching lost the true positive; log=%q", out)
	}
}

// TestAHostnameBootstrapDoesNotExemptStrangers covers the other way the dialled
// set can be polluted.
//
// `-peers` takes free-form strings, so a hostname bootstrap gives AddressGroup
// nothing to parse and it returns one sentinel for every such address. Admitted
// to the dialled set, that sentinel exempts *every* unparseable sender from the
// evidence cap and counts them as this node's own peers.
func TestAHostnameBootstrapDoesNotExemptStrangers(t *testing.T) {
	var buf bytes.Buffer
	e := &Engine{withholdLimits: DefaultWithholdLimits(), withheld: map[types.Hash]*withheldBlock{}}
	n := &Node{
		Engine: e, Logger: log.New(&buf, "", 0),
		conns:           map[string]*Conn{},
		outboundTargets: map[string]bool{"seed1.example.com:9000": true},
	}
	n.mu.Lock()
	groups := n.dialledGroupsLocked()
	n.mu.Unlock()
	e.SetDialledGroups(groups)

	if len(groups) != 0 {
		t.Fatalf("a hostname bootstrap put %v in the dialled set; an address the "+
			"grouping cannot parse is one sentinel shared by every stranger", groups)
	}
	e.recordBeyondHorizon("203.0.113.9:40000", 4000)
	n.reportClockSkew()
	if out := buf.String(); strings.Contains(out, "1 of them among the") {
		t.Fatalf("a stranger was counted as this node's own peer because the "+
			"bootstrap address could not be grouped; log=%q", out)
	}
}

// TestTheDialledExemptionSurvivesAnEpisodeReset pins that ending an episode does
// not quietly restore the suppression attack.
//
// ResetSkewEvidence clears the skew state, and dialledGroups is deliberately not
// part of it: the exemption is republished only when the outbound set changes —
// reserveOutboundTarget and retire, the two ends of a dial — so on a
// stable node with a full outbound set nothing re-pushes it. Clearing it there —
// a natural tidy-up for a function whose job is "clear the skew state" — puts
// the first-come cap back in force one episode later, silently.
func TestTheDialledExemptionSurvivesAnEpisodeReset(t *testing.T) {
	e, n, _ := skewHarness(8)
	e.recordBeyondHorizon("10.0.0.1:9000", 4000)
	n.reportClockSkew()
	for tick := 0; tick <= skewEpisodeIdleTicks; tick++ {
		n.reportClockSkew()
	}
	if e.BeyondHorizon().Count != 0 {
		t.Fatal("setup: the episode did not end")
	}

	// A new episode, primed to the cap by strangers first.
	for i := 0; i < maxSkewGroups; i++ {
		e.recordFutureAnnouncement(fmt.Sprintf("%d.%d.0.9:40000", 100+i/256, i%256), 3599)
	}
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("10.%d.0.1:9000", i), 4000)
	}
	_, agreeing := n.outboundAgreement(e.BeyondHorizon().Senders)
	if agreeing != 8 {
		t.Fatalf("after one episode reset only %d of 8 dialled peers were admitted "+
			"to the evidence; the exemption has to outlive the counters, because "+
			"nothing republishes it on a node whose outbound set has not changed",
			agreeing)
	}
}

// TestNoDialledPeersIsSaidRatherThanGuessed covers the case with no adversary
// in it at all.
//
// chosen == 0 is "the test could not be run", not "nobody agrees", and reading
// it as the second is wrong every time. It is reachable on an empty or
// unreachable bootstrap list, a listener-only deployment, an exhausted peer
// store, or simply the window after boot before the first topUp — and on the
// version that did not separate them, a genuine 4000 s fault with eight inbound
// peers printed "0 of them among the 0 peer(s) this node dialled … the senders
// named are dating blocks forward".
func TestNoDialledPeersIsSaidRatherThanGuessed(t *testing.T) {
	e, n, buf := skewHarness(0)
	n.mu.Lock()
	for i := 0; i < 8; i++ {
		n.conns[fmt.Sprintf("198.%d.100.7:5000", 51+i)] = nil
	}
	n.mu.Unlock()
	for i := 0; i < 8; i++ {
		e.recordBeyondHorizon(fmt.Sprintf("198.%d.100.7:5000", 51+i), 4000)
	}
	n.reportClockSkew()
	out := buf.String()
	if strings.Contains(out, "dating blocks forward") {
		t.Fatalf("a node with nothing dialled read its inbound peers as the "+
			"culprits; with no peer of its own choosing there is no ratio to "+
			"read and the line must say so; log=%q", out)
	}
	if !strings.Contains(out, "dialled no peers") {
		t.Errorf("the line does not say why it cannot weigh the evidence; log=%q", out)
	}
	// It must still hand over the numbers, and still name the clock as a thing
	// to check — the operator is the only one who can break the tie.
	for _, want := range []string{"4000", "NTP"} {
		if !strings.Contains(out, want) {
			t.Errorf("the line never mentions %q; log=%q", want, out)
		}
	}
}

// TestOutboundAgreementCountsGroupsNotSockets pins the denominator's own
// grouping: eight connections to one host are one opinion about what time it
// is, not eight.
func TestOutboundAgreementCountsGroupsNotSockets(t *testing.T) {
	var buf bytes.Buffer
	n := &Node{Logger: log.New(&buf, "", 0), outboundTargets: map[string]bool{}}
	for i := 0; i < 8; i++ {
		n.outboundTargets[fmt.Sprintf("203.0.113.%d:900%d", i, i)] = true
	}
	n.outboundTargets["198.51.100.1:9000"] = true
	chosen, agreeing := n.outboundAgreement([]string{"203.0.113.0:9000"})
	if chosen != 2 {
		t.Fatalf("nine dialled connections across two address groups counted as "+
			"%d; counting sockets lets one host this node dialled nine times "+
			"read as nine opinions about the time", chosen)
	}
	if agreeing != 1 {
		t.Fatalf("agreement counted as %d, want 1", agreeing)
	}
	// Eight of those nine sockets share one /16, so agreement from all of them
	// is still one group agreeing — the numerator is deduplicated by group even
	// though it is matched by address.
	all := []string{
		"203.0.113.0:9000", "203.0.113.1:9001", "203.0.113.2:9002",
		"203.0.113.3:9003", "198.51.100.1:9000",
	}
	if _, agreeing = n.outboundAgreement(all); agreeing != 2 {
		t.Fatalf("agreement over %v counted as %d, want 2: four of those are one "+
			"host's sockets and cannot be four opinions", all, agreeing)
	}
	// Multi-element evidence, most of it from peers this node never dialled:
	// with one element, "intersect" and "count everything" agree.
	evidence := []string{"203.0.113.0:9000", "8.8.8.8:9000", "1.1.1.1:9000", "9.9.9.9:9000"}
	if _, agreeing = n.outboundAgreement(evidence); agreeing != 1 {
		t.Fatalf("agreement over %v counted as %d, want 1: three of those were "+
			"never dialled, and counting them is the whole attack this "+
			"denominator exists to refuse", evidence, agreeing)
	}
}

// TestTheThresholdSaturates pins that doubling cannot wrap.
//
// A wrapped threshold lands below the count that reached it, and then every
// tick satisfies it — the limiter fires forever, which is the failure the
// saturation exists to prevent.
func TestTheThresholdSaturates(t *testing.T) {
	e, n, buf := skewHarness(8)
	e.mu.Lock()
	e.beyondHorizon = math.MaxUint64 - 1
	e.skewGroups = map[string]string{"10.0.0.0/16": "10.0.0.1:9000"}
	e.mu.Unlock()
	n.reportClockSkew()
	if n.skew.next != math.MaxUint64 {
		t.Fatalf("threshold set to %d from a count of %d; doubling has to saturate "+
			"or it lands below the count that reached it", n.skew.next, uint64(math.MaxUint64-1))
	}
	buf.Reset()
	lines := 0
	for tick := 0; tick < 10; tick++ {
		e.mu.Lock()
		e.beyondHorizon++
		e.mu.Unlock()
		before := buf.Len()
		n.reportClockSkew()
		if buf.Len() != before {
			lines++
		}
	}
	if lines > 1 {
		t.Fatalf("%d lines in 10 ticks past the saturation point; a wrapped "+
			"threshold makes the limiter fire every tick", lines)
	}
}

// TestAnEpisodeNeedsTheFullIdlePeriod pins the constant, not just its use.
func TestAnEpisodeNeedsTheFullIdlePeriod(t *testing.T) {
	e, n, _ := skewHarness(8)
	e.recordBeyondHorizon("10.0.0.1:9000", 4000)
	n.reportClockSkew()
	for tick := 0; tick < skewEpisodeIdleTicks-1; tick++ {
		n.reportClockSkew()
	}
	if r := e.BeyondHorizon(); r.Count == 0 {
		t.Fatalf("the episode ended after %d idle ticks, short of the %d it is "+
			"documented to need", skewEpisodeIdleTicks-1, skewEpisodeIdleTicks)
	}
	n.reportClockSkew()
	if r := e.BeyondHorizon(); r.Count != 0 {
		t.Fatalf("the episode did not end after %d idle ticks", skewEpisodeIdleTicks)
	}
}

// TestASyncPassWithNothingToTakeIsCounted is the sync half of the same stall,
// which the finding names explicitly.
//
// runOnce turns ErrHeadersWithheld into a successful empty Result — right,
// since the peer did nothing wrong — and that made "stuck at a fixed lag" look
// exactly like "up to date". The reason now travels with the pass.
func TestASyncPassWithNothingToTakeIsCounted(t *testing.T) {
	e, n, buf := skewHarness(4)
	for i := 0; i < 4; i++ {
		e.RecordSyncWithheld(fmt.Sprintf("10.%d.0.1:9000", i), 900)
	}
	r := e.BeyondHorizon()
	if r.SyncPasses != 4 || r.Count != 4 || r.Groups != 4 {
		t.Fatalf("four withheld sync passes reported as %+v, want 4 passes from 4 "+
			"groups", r)
	}
	if r.MaxSkewSeconds != 900 {
		t.Fatalf("worst skew %ds, want 900: the gap is the number the operator "+
			"sets their clock by, and it was already computed for the error text",
			r.MaxSkewSeconds)
	}
	n.reportClockSkew()
	if out := buf.String(); !strings.Contains(out, "4 sync pass(es)") {
		t.Errorf("the line does not name the sync passes; log=%q", out)
	}
}

// socketNode is a Node with a real chain, a real identity and a real socket —
// the minimum topUp and unregister need, since one dials and the other runs off
// serve's defer, and neither is reachable from an in-process delivery.
func socketNode(t *testing.T) *Node {
	t.Helper()
	p := spec.Devnet()
	c, err := chain.OpenWith(t.TempDir(), p, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(c, mempool.New(p, mempool.DefaultPolicy()), peers, pow.Dev{}, "127.0.0.1:0")
	n := NewNode(id, e, peers, 1)
	if err := n.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(n.Stop)
	return n
}

// TestDiallingPublishesTheGroupToTheEngine covers the seam between the Node's
// outbound bookkeeping and the Engine's evidence set.
//
// The Engine cannot derive which connections this node initiated — that is the
// Node's bookkeeping — so the exemption that stops a saturated evidence set
// from crowding out this node's own peers depends entirely on the Node pushing
// it. Deleting either push left every other test in the tree green: both sides
// were covered and nothing crossed between them, which is the same "correct
// piece called from nowhere" shape as the defect it guards.
func TestDiallingPublishesTheGroupToTheEngine(t *testing.T) {
	listener := socketNode(t)
	dialler := socketNode(t)

	addr := listener.ListenAddr()
	dialler.Peers.Add(addr)

	want := AddressGroup(addr)
	if dialler.Engine.hasDialledGroup(want) {
		t.Fatal("setup: the group was published before anything was dialled")
	}

	dialler.topUp()
	if !dialler.Engine.hasDialledGroup(want) {
		t.Fatalf("dialling %s did not publish its group %q to the engine; without "+
			"it the engine cannot exempt this node's own peers from the evidence "+
			"cap, and a saturated set crowds them out", addr, want)
	}

	// And it is withdrawn when the connection goes — driven the way production
	// drives it, through serve's defer, rather than by calling unregister
	// directly. Calling unregister directly leaves serve blocked on a read
	// nobody will close, which is a 60 s stall and not a path any node takes.
	//
	// serve registers on its own goroutine, so poll for the connection first.
	var conn *Conn
	for deadline := time.Now().Add(5 * time.Second); conn == nil && time.Now().Before(deadline); {
		dialler.mu.Lock()
		for _, c := range dialler.conns {
			conn = c
		}
		dialler.mu.Unlock()
		if conn == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if conn == nil {
		t.Fatal("setup: topUp registered no connection")
	}
	conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	for dialler.Engine.hasDialledGroup(want) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if dialler.Engine.hasDialledGroup(want) {
		t.Fatalf("group %q kept its exemption after the connection to it was "+
			"dropped", want)
	}
}

// hasDialledGroup is a test-only read of what SetDialledGroups published.
func (e *Engine) hasDialledGroup(group string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.dialledGroups[group]
	return ok
}
