package p2p_test

import (
	"errors"
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/validity"
	"zycord/node/mempool"
	"zycord/node/p2p"
)

// mutilate returns a copy of c whose first signature does not verify, with
// nothing else changed.
//
// The id does not cover the signatures, so the copy carries the honest id. What
// these tests need from it is narrower than that: a certificate that passes
// every structural V-rule and fails V2.
func mutilate(t *testing.T, p *params.Params, c *types.Certificate) *types.Certificate {
	t.Helper()
	bad := *c
	bad.Sigs = append([]types.Sig(nil), c.Sigs...)
	bad.Sigs[0].Sig[0] ^= 0xFF
	if got := validity.Rule(validity.CheckSignatures(&bad, p)); got != "V2" {
		t.Fatalf("the mutilated copy fails rule %q, want V2; every assertion "+
			"below would be about a different certificate", got)
	}
	return &bad
}

// TestAPolicyRefusalIsNotChargedAsAnInvalidMessage pins the deliberate
// behavioural consequence of removing the engine's own validity.Check: a
// certificate refused by one of the pool's own read-only gates is refused
// **free**, even when its signature would also have failed, because this node
// never verified it and therefore never established that it fails a V-rule
// (wire.md 10.5).
//
// This is also the separating input for the ordering. The engine used to
// run validity.Check before Pool.Add, so a certificate that was both expired
// and forged was named by V2 and scored; after it, the expired gate - a step-2
// window check - answers first and no signature work is bought at all
// (wire.md 10.1). The two orderings return *different verdicts* for this one
// input, which is what makes it a measurement rather than a reading.
func TestAPolicyRefusalIsNotChargedAsAnInvalidMessage(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "a", p, key(t, 1).Persistent())
	n.mine(t, int(p.CoinbaseMaturity)+2)

	// TTL is tip+10 at build time; mining 11 more blocks puts the tip past it,
	// which is mempool.ErrExpired - the cheapest refusal the pool has, needing
	// no funds and replayable forever.
	stale := buildCert(t, n, key(t, 1), 0)
	n.mine(t, 11)
	if n.chain.Height() <= stale.TTL {
		t.Fatalf("tip %d has not passed the certificate's TTL %d; the gate under "+
			"test would not fire and the assertion would be vacuous",
			n.chain.Height(), stale.TTL)
	}

	v := n.engine.OnCertificate("attacker:1", mutilate(t, p, stale).MarshalSSZ())

	if v.Forward {
		t.Fatal("a certificate with a signature that does not verify was forwarded")
	}
	if !errors.Is(v.Err, mempool.ErrExpired) {
		t.Fatalf("refused with %v, want %v: the expired gate is a step-2 window "+
			"check and must answer before any signature work (wire.md 10.1). "+
			"A V2 error here means the engine verified first, which is the "+
			"double verification this removes.", v.Err, mempool.ErrExpired)
	}
	if got := validity.Rule(v.Err); got != "" {
		t.Fatalf("the refusal names V-rule %q; this node never ran the V-rules "+
			"on this certificate and must not claim it did", got)
	}
	if v.Cost != p2p.CostFree || v.Score != 0 {
		t.Fatalf("cost %v score %d, want %v and 0: a refusal this node reached "+
			"by its own local condition is Free (wire.md 10.3), and charging "+
			"ScoreInvalidMessage for a verdict it did not reach is the same "+
			"error as scoring an exemplar mismatch", v.Cost, v.Score, p2p.CostFree)
	}
}

// TestAnInvalidSignatureIsStillScoredWhenTheNodeReachesIt is the other half of
// the same conjunction, and the reason the removal is not a plain deletion: with the
// engine's own validity.Check gone, ScoreInvalidMessage has to be read off
// Pool.Add's error instead. validity.RuleError unwraps through Add's
// fmt.Errorf wrapper, so validity.Rule still names the failed rule.
//
// Same peer, same shape, same mutilation as the test above - the ONLY
// difference is that this certificate passes every pool gate, so V2 is
// actually reached. That is what separates "refused free because a cheap gate
// fired" from "refused free because the score was lost".
func TestAnInvalidSignatureIsStillScoredWhenTheNodeReachesIt(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "a", p, key(t, 1).Persistent())
	n.mine(t, int(p.CoinbaseMaturity)+2)

	live := buildCert(t, n, key(t, 1), 0)

	v := n.engine.OnCertificate("attacker:1", mutilate(t, p, live).MarshalSSZ())

	if v.Forward {
		t.Fatal("a certificate with a signature that does not verify was forwarded")
	}
	if got := validity.Rule(v.Err); got != "V2" {
		t.Fatalf("refused with %v (rule %q), want V2: the engine reads the "+
			"V-rule verdict off Pool.Add's error, and if that "+
			"unwrapping breaks, an invalid certificate becomes an unscored "+
			"local refusal", v.Err, got)
	}
	if v.Cost != p2p.CostScored || v.Score != p2p.ScoreInvalidMessage {
		t.Fatalf("cost %v score %d, want %v and %d: wire.md 10.3 prices a "+
			"certificate that fails a V-rule Scored(invalid), and that is the "+
			"only class that terminates a flood of distinct messages",
			v.Cost, v.Score, p2p.CostScored, p2p.ScoreInvalidMessage)
	}

	// Anti-vacuity: the honest exemplar of the same authorization is still
	// admitted and forwarded. Without this, every assertion above would also
	// pass on an engine that refused every certificate.
	if v := n.engine.OnCertificate("honest:1", live.MarshalSSZ()); !v.Forward {
		t.Fatalf("the honest certificate was refused: %v", v.Err)
	}
}
