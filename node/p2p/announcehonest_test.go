package p2p_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/p2p"
	"zycord/spec"
)

// receiversRuleTarget is the target the difficulty rule gives for the block
// after this node's own tip — what the tip-keyed check compares against.
func receiversRuleTarget(to *testNode) types.Header {
	p := to.p
	return types.Header{Target: pow.NextTarget(to.chain.RecentHeaders(int(p.DifficultyWindow)+1), p)}
}

// parentStand is where an announcement's parent stood at the moment it arrived.
type parentStand struct{ tip, held, unknown int }

func (s *parentStand) record(t *testing.T, to *testNode, h types.Header) {
	t.Helper()
	switch {
	case h.ParentID == to.chain.Tip().ID():
		s.tip++
	default:
		if _, err := to.chain.CanonicalHeader(h.ParentID); err == nil {
			s.held++
		} else {
			s.unknown++
		}
	}
}

// TestTheHonestAnnouncementSurvivesTheTargetRederivation is the measurement the
// brief required before the check was built, taken again at this head
// with the check in place.
//
// The three scenarios are the ones the measurement published, and the counts
// they produce are what decides the SHAPE of the fix rather than its
// correctness: a receiver one block behind its peer sees almost every honest
// announcement name a parent it does not hold, so a rule keyed on "refuse what
// you cannot verify" would silence exactly the population that most needs
// gossip. The check this head carries is keyed on the tip instead, and these
// rows are the evidence that nothing outside the tip row is touched by it.
//
// The assertion is an existential per `PROTOCOL.md` rule 21 and deliberately
// not a count: every honest announcement in every row has its body requested
// and none is scored down. The counts are logged, not asserted, because they
// are properties of this arrangement's schedule — the same reason the ban count
// is not a property of the attack. The one count that IS asserted is an
// anti-vacuity floor: each row has to reach the parent position it exists to
// exercise, or it is measuring something else.
//
// # What these rows do and do not separate, measured rather than assumed
//
// **The second row varies its mining interval, and without that variation these
// rows would not distinguish this check from the dead direction at all.** A
// reviewer drove it: dropping the parent conjunct — applying the re-derivation
// to EVERY parent, which is exactly "refuse what you cannot verify" — left all
// three rows green. The reason is the harness blind spot, on the same
// parameters: a harness that mines at exactly `TargetBlockSeconds` produces a
// difficulty answer that never moves, so the receiver's own tip's target and
// every announcer's target are the same number and no rule keyed on their
// difference can fire. That blindness was diagnosed for the memo and not
// carried across to here, and the header used to claim these rows were
// "evidence that nothing outside the tip row is touched", which they were not.
//
// So the second row now moves the announcer's clock, and asserts as
// anti-vacuity that at least one announced header carries a target the receiver
// would NOT derive for its own tip. On that input the dead direction refuses an
// honest announcement and the row fails, which is what makes it evidence.
//
// It runs on `spec.Devnet()` rather than on this file's `devnetEasy`, and that
// is load-bearing: `devnetEasy` raises `MaxTarget` to `u256.Max`, at which the
// difficulty rule's own answer IS `u256.Max` and a ghost declaring it becomes
// indistinguishable from an honest header. On those parameters this test would
// pass with the check removed.
func TestTheHonestAnnouncementSurvivesTheTargetRederivation(t *testing.T) {
	t.Run("steady state, body served between announcements", func(t *testing.T) {
		p := spec.Devnet()
		a := newNode(t, "a", p, key(t, 1).Persistent())
		b := newNode(t, "b", p, key(t, 2).Persistent())
		c := newNode(t, "c", p, key(t, 3).Persistent())
		for _, n := range []*testNode{a, b, c} {
			handshake(t, n, "a:1")
			handshake(t, n, "b:1")
			handshake(t, n, "c:1")
		}

		var stand parentStand
		for i := 0; i < 20; i++ {
			blk := a.mine(t, 1)[0]
			ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
			for _, to := range []*testNode{b, c} {
				stand.record(t, to, blk.Header)
				v := to.engine.Handle("a:1", p2p.KindBlockAnnounce, ann.MarshalAnnounce())
				assertAdmitted(t, v, "steady state")
				// The body follows immediately, which is what keeps the next
				// announcement's parent this receiver's own tip.
				served := a.engine.Handle(to.name+":1", p2p.KindGetBlock, v.Reply.Payload)
				if served.Reply == nil {
					t.Fatal("the announcer did not serve the body it announced")
				}
				to.engine.Handle("a:1", p2p.KindBlock, served.Reply.Payload)
			}
		}
		t.Logf("steady state: parent==tip %d, parent held not tip %d, parent unknown %d",
			stand.tip, stand.held, stand.unknown)
		if stand.tip == 0 {
			t.Fatal("no announcement in the steady-state row arrived on the receiver's own tip, " +
				"so this row exercises nothing the re-derivation can reach")
		}
	})

	t.Run("announcements running ahead of bodies", func(t *testing.T) {
		p := spec.Devnet()
		a := newNode(t, "a", p, key(t, 1).Persistent())
		slow := newNode(t, "slow", p, key(t, 2).Persistent())
		handshake(t, a, "slow:1")
		handshake(t, slow, "a:1")

		var stand parentStand
		unverifiableTarget := 0
		for i := 0; i < 20; i++ {
			// Irregular intervals, so the difficulty rule's answer actually
			// moves away from the one the receiver would derive for its own
			// tip. See the note in this test's header for why a row mined at
			// exactly TargetBlockSeconds separates nothing.
			if i%2 == 1 {
				a.clock += p.TargetBlockSeconds * 8
			}
			blk := a.mine(t, 1)[0]
			ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
			stand.record(t, slow, blk.Header)
			if !blk.Header.Target.Eq(receiversRuleTarget(slow).Target) {
				unverifiableTarget++
			}
			assertAdmitted(t, slow.engine.Handle("a:1", p2p.KindBlockAnnounce,
				ann.MarshalAnnounce()), "ahead of bodies")
		}
		t.Logf("ahead of bodies: parent==tip %d, parent held not tip %d, parent unknown %d, "+
			"target the receiver would not derive for its own tip %d",
			stand.tip, stand.held, stand.unknown, unverifiableTarget)
		if stand.unknown == 0 {
			t.Fatal("no announcement in this row named a parent the receiver does not hold, " +
				"so the row that decides the shape of the fix is not being exercised")
		}
		if unverifiableTarget == 0 {
			t.Fatal("every honest announcement in this row declared the target the " +
				"receiver derives for its OWN tip, so the row cannot separate a check " +
				"keyed on the tip from one applied to every parent, and would stay " +
				"green under the dead direction")
		}
	})

	t.Run("a node rejoining after missing fifteen blocks", func(t *testing.T) {
		p := spec.Devnet()
		a := newNode(t, "a", p, key(t, 1).Persistent())
		back := newNode(t, "back", p, key(t, 2).Persistent())
		handshake(t, a, "back:1")
		handshake(t, back, "a:1")

		// Mined while the rejoining node was away: never announced to it.
		a.mine(t, 15)

		var stand parentStand
		for i := 0; i < 15; i++ {
			blk := a.mine(t, 1)[0]
			ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
			stand.record(t, back, blk.Header)
			assertAdmitted(t, back.engine.Handle("a:1", p2p.KindBlockAnnounce,
				ann.MarshalAnnounce()), "rejoining")
		}
		t.Logf("rejoining: parent==tip %d, parent held not tip %d, parent unknown %d",
			stand.tip, stand.held, stand.unknown)
		if stand.unknown == 0 {
			t.Fatal("the rejoining node held every announced parent, so this row is not " +
				"the one it was written to be")
		}
	})
}

// assertAdmitted is what these rows have to establish about an honest
// announcement: this node asked for the body and did not score the announcer
// down.
//
// **It used to also require the announcement be relayed, and Option A is
// what took that half away without weakening the property.** No accepted
// announcement is forwarded now — a node relays one only once it holds the body
// — so `Forward` no longer separates an honest announcement from a refused one
// and reading it would agree with the wrong answer (`PROTOCOL.md` rule 24).
// What silencing the lagging fringe would look like is a refusal or a negative
// score, and those are exactly the two facts below.
func assertAdmitted(t *testing.T, v p2p.Verdict, row string) {
	t.Helper()
	if v.Score < 0 {
		t.Fatalf("%s: an honest announcement was scored %d: %v", row, v.Score, v.Err)
	}
	if v.Reply == nil {
		t.Fatalf("%s: no body was requested for an honest announcement: %v", row, v.Err)
	}
	if v.Forward {
		t.Fatalf("%s: an accepted announcement was relayed; under Option A a node "+
			"forwards one only once it holds the body", row)
	}
}
