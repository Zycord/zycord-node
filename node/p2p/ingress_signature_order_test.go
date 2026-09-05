package p2p_test

import (
	"testing"

	"zycord/core/types"
	"zycord/node/p2p"
)

// TestADuplicateCertificateIsAnsweredWithoutVerifyingItsSignature: the step-2
// dedup gate of docs/spec/wire.md §10.1 refuses a certificate before the
// step-4 signature verification, measured on behaviour rather than on source
// position.
//
// The property in one sentence: a certificate whose id this node already holds
// is answered from that record, and the answer is one `validity.Check` could
// not have produced.
//
// This is the seam sim/wiring's TestSignatureWorkIsOrderedAfterTheCheapChecks
// says does not exist, and the reason it was missed is that it is not a
// counter. Ed25519 verification cannot be counted from outside — core/crypto is
// stdlib-only consensus code and a global counter does not belong in it — but
// it does not have to be counted to be *separated*, because a certificate's
// signatures sit outside its id's preimage (core/types.Certificate.ID). So the
// honest certificate and a signature-mutilated twin carry the same id and
// different bytes, and the two candidate orderings disagree about the twin in a
// way that is visible in the returned verdict:
//
//   - dedup before verification, which is the rule: `Deduped`, score 0, because
//     the id answered and the bytes were never looked at.
//   - verification before dedup, which is the hoist: `Scored(invalid)`, because
//     V2 rejects the mutilated signature.
//
// A test that only asserted "refused" would pass under both and assert nothing;
// the class and the score are what separate them. This is strictly stronger
// than the syntax-tree check on this handler: it survives the verification
// moving into a helper, and it fails on a hoist however the source is arranged.
//
// It covers the certificate path only. The announce and block paths are
// measured with a real counter in node/p2p's TestACheapRefusalBuysNoProofOfWork,
// because proof of work does have a seam.
func TestADuplicateCertificateIsAnsweredWithoutVerifyingItsSignature(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, int(p.CoinbaseMaturity)+2)

	good := buildCert(t, a, key(t, 1), 0)

	mutilated := *good
	mutilated.Sigs = append([]types.Sig(nil), good.Sigs...)
	mutilated.Sigs[0].Sig[0] ^= 0xFF
	if mutilated.ID() != good.ID() {
		t.Fatal("mutilating a signature moved the id; this test needs the collision")
	}

	// The honest one first, so that the id is a record this node holds. Its
	// acceptance is the anti-vacuity floor: if it were refused, the assertion
	// below would be about an empty pool.
	if v := a.engine.OnCertificate("honest:1", good.MarshalSSZ()); !v.Forward {
		t.Fatalf("the honest certificate was refused: %v", v.Err)
	}

	// And the twin, whose signature does not verify. Reaching the signature
	// check at all is what this must not do.
	v := a.engine.OnCertificate("attacker:1", mutilated.MarshalSSZ())
	if v.Forward {
		t.Fatal("a certificate with a signature that does not verify was forwarded")
	}
	if v.Cost != p2p.CostDeduped {
		t.Errorf("cost class %v, want %v: wire.md §10.1 orders the dedup gate "+
			"in front of signature verification, so a certificate whose id is "+
			"already pooled is answered by the record. Reading %v instead means "+
			"validity.Check ran first and rejected the mutilated signature — "+
			"the hoist that lets an unauthenticated stranger buy signature work.",
			v.Cost, p2p.CostDeduped, v.Cost)
	}
	if v.Score != 0 {
		t.Errorf("score %d, want 0: a duplicate id costs a lookup and nothing "+
			"behind it (wire.md §10.3, `certificate` / already pooled). A "+
			"negative score here is validity.Check's answer, not the pool's.", v.Score)
	}
}
