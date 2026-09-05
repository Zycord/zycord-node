package validity_test

import (
	"bytes"
	"reflect"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/validity"
	"zycord/spec"
)

// The respin pair: two parameter sets that differ in genesis_time and in
// nothing else.
//
// This is the pair the incarnation binding is about, and it is deliberately the
// *narrowest* one. A relaunch of a network is dated to its own launch day, so
// genesis_time moves; a pair that differed in more than that would separate for
// reasons a reader could not attribute, and the field that did the work would
// be unknown.
//
// respinPair asserts the narrowness rather than trusting the two lines above
// it: it walks the struct and requires exactly one field to differ.
func respinPair(t *testing.T) (before, after *params.Params) {
	t.Helper()
	before = spec.Devnet()
	after = spec.Devnet()
	after.GenesisTime = before.GenesisTime + 1

	a, b := reflect.ValueOf(before).Elem(), reflect.ValueOf(after).Elem()
	typ := a.Type()
	var moved []string
	for i := 0; i < typ.NumField(); i++ {
		if !typ.Field(i).IsExported() {
			continue
		}
		if !reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
			moved = append(moved, typ.Field(i).Name)
		}
	}
	if len(moved) != 1 || moved[0] != "GenesisTime" {
		t.Fatalf("the two incarnations differ in %v, want only GenesisTime; a wider "+
			"pair cannot say which field separated them", moved)
	}
	if before.ChainID != after.ChainID {
		t.Fatal("the two incarnations carry different chain ids, so V1 would refuse " +
			"the certificate and this file would measure V1")
	}
	return before, after
}

// TestACertificateOfAPreviousIncarnationIsRefusedByV2 is the incarnation
// binding, end to end.
//
// A testnet respin that reuses its chain id used to accept, as valid, every
// certificate lifted off the incarnation it replaced: V1 compared c.ChainID
// against p.ChainID and passed, V2 verified a message that named only the chain
// id and passed, and the certificate was billed against a deposit on the new
// chain. Binding the consensus root into the signing message closes that in
// protocol rather than by an operator convention, because the genesis id is
// derived from the parameters and a respin always moves genesis_time.
//
// The three assertions are separate claims and each is load-bearing:
//
//  1. The certificate is refused on the new incarnation.
//  2. The refusal is V2's, and it is V2 that produced it rather than some other
//     rule reaching the certificate first — CheckStructural is asked directly
//     and has to pass, so the whole of the refusal lives in CheckSignatures.
//  3. The same certificate is still accepted on the incarnation it was signed
//     for. Without this the test would be satisfied by a change that broke
//     every certificate everywhere.
func TestACertificateOfAPreviousIncarnationIsRefusedByV2(t *testing.T) {
	before, after := respinPair(t)

	c, _ := validCert(t, before)

	if err := validity.Check(c, before); err != nil {
		t.Fatalf("the certificate is not valid on the incarnation it was signed for: %v", err)
	}

	err := validity.Check(c, after)
	if err == nil {
		t.Fatal("a certificate signed against the previous incarnation was accepted on the new one")
	}
	if got := validity.Rule(err); got != "V2" {
		t.Fatalf("the new incarnation refused it by rule %q, want V2: %v", got, err)
	}

	// Observe the branch, not a value that coincides with it. "Check answered
	// V2" is not the same claim as "V2 is what refuses it": every structural
	// rule has to pass under the new parameter set, so nothing but the
	// signature check can be producing the refusal.
	if err := validity.CheckStructural(c, after); err != nil {
		t.Fatalf("a structural rule also refuses the certificate on the new incarnation (%v); "+
			"the separation this test claims for V2 would hold with the binding removed", err)
	}
	if got := validity.Rule(validity.CheckSignatures(c, after)); got != "V2" {
		t.Fatalf("CheckSignatures answered %q on the new incarnation, want V2", got)
	}
}

// TestTheChainIDOnlyPreimageWouldStillAcceptTheReplay writes down the rival
// hypothesis and exhibits the input on which it disagrees.
//
// The rival is the preimage this tree carried before the consensus root was
// bound into it: blake3(TagSig || chain_id_le || cert_body_root), with no
// consensus root in it. It agrees with the shipped preimage on every question
// about chain ids -- which is why every chain-binding test here passes under
// both -- and disagrees on exactly one: whether a certificate crosses from
// one incarnation of a network to the next. A test that only asserted "the
// new rule refuses it" would be measured at a point where the two rules could
// still agree for some other reason, so the certificate below is signed the
// way the rival says to sign, and both rules are asked about the same bytes.
//
// The result is the defect and the fix on one input: everything except V2
// accepts the lifted certificate on the new incarnation, and the rival's own
// verification accepts it too -- so under the rival rule it is admitted and
// billed. V2 is what refuses it.
func TestTheChainIDOnlyPreimageWouldStillAcceptTheReplay(t *testing.T) {
	before, after := respinPair(t)

	if before.ConsensusRoot() == after.ConsensusRoot() {
		t.Fatal("moving genesis_time did not move the consensus root; the binding has nothing to bind")
	}

	c, alice := validCert(t, before)

	// The certificate as the world before that binding would have produced it:
	// the same body, signed over the chain-id-only message.
	lifted := *c
	lifted.Sigs = append([]types.Sig(nil), c.Sigs...)
	rival := rivalMessage(c.ChainID, c.BodyRoot())
	lifted.Sigs[0].Sig = alice.Sign(rival)

	if lifted.ID() != c.ID() {
		t.Fatal("replacing the signature moved the certificate id; the two rules are no longer " +
			"being asked about one authorization")
	}

	// The rival message carries no parameter input at all, so it is the same
	// bytes on both incarnations. That is the defect stated as a measurement
	// rather than as a sentence.
	if !bytes.Equal(rival, rivalMessage(c.ChainID, c.BodyRoot())) {
		t.Fatal("the rival message is not a pure function of the chain id and the body")
	}
	if !crypto.VerifyStrict(lifted.Sigs[0].PubKey, rival, lifted.Sigs[0].Sig) {
		t.Fatal("the lifted certificate does not verify under the rival preimage; the fixture " +
			"is not a certificate of the world this change replaces")
	}

	// Under the rival rule the new incarnation would admit and bill it: nothing
	// else in the stateless set objects.
	if err := validity.CheckStructural(&lifted, after); err != nil {
		t.Fatalf("a structural rule refuses the lifted certificate on the new incarnation (%v); "+
			"the replay this change stops would have been stopped anyway, and the input "+
			"separates nothing", err)
	}

	// And the shipped rule refuses it, on the new incarnation and on the old
	// one alike -- the second half being the honest consequence of moving a
	// frozen preimage, and the reason this lands before genesis rather than
	// after it.
	if got := validity.Rule(validity.CheckSignatures(&lifted, after)); got != "V2" {
		t.Fatalf("V2 answered %q to the lifted certificate on the new incarnation, want V2", got)
	}
	if got := validity.Rule(validity.CheckSignatures(&lifted, before)); got != "V2" {
		t.Fatalf("V2 answered %q to the lifted certificate on the old incarnation, want V2", got)
	}
}

// rivalMessage is core/crypto.SigningMessage as it stood before the consensus
// root was bound in, kept here so the comparison is against the rule that was
// actually replaced rather than against a paraphrase of it.
func rivalMessage(chainID uint64, body crypto.Hash) []byte {
	var cid [8]byte
	for i := 0; i < 8; i++ {
		cid[i] = byte(chainID >> (8 * i))
	}
	m := crypto.Sum(crypto.TagSig, cid[:], body[:])
	return m[:]
}
