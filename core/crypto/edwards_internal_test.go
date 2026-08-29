package crypto

// Unit tests for the decoder itself.
//
// These exist because the canonicality rule has no *reachable* exploit of its
// own: every non-canonical encoding that could ever verify is also low order,
// so removing the canonicality check from VerifyStrict would not flip any
// end-to-end test (see the count assertion in
// TestNonCanonicalPubKeysAreRefused). A rule that no test can observe being
// removed is a rule that will be removed, so it is observed here, directly.

import (
	"math/big"
	"testing"
)

func TestDecodeReportsCanonicality(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	enc := func(y *big.Int, sign byte) []byte {
		b := y.Bytes()
		out := make([]byte, PubKeySize)
		for i := 0; i < len(b); i++ {
			out[i] = b[len(b)-1-i]
		}
		out[31] |= sign << 7
		return out
	}

	// y = 1, the identity: canonical with the sign bit clear, non-canonical
	// with it set, because x = 0 has no sign.
	if _, st := decodeEdPoint(enc(big.NewInt(1), 0)); st != decodeCanonical {
		t.Errorf("the identity's canonical encoding was reported as %v", st)
	}
	if _, st := decodeEdPoint(enc(big.NewInt(1), 1)); st != decodeNonCanonical {
		t.Errorf("a sign bit on x = 0 was reported as %v, want non-canonical", st)
	}

	// Every unreduced encoding that fits in 255 bits must be non-canonical, and
	// there are 19 of them — not the two the report that found this defect named
	// (it said y = p and y = p+1 were the only ones). A y < p comparison gets all
	// 19; a two-value blocklist gets two.
	unreduced := 0
	for i := int64(0); i < 19; i++ {
		y := new(big.Int).Add(fieldP, big.NewInt(i))
		if y.Cmp(limit) >= 0 {
			t.Fatalf("p+%d does not fit in 255 bits", i)
		}
		for sign := byte(0); sign < 2; sign++ {
			p, st := decodeEdPoint(enc(y, sign))
			if st == decodeInvalid {
				continue
			}
			unreduced++
			if st != decodeNonCanonical {
				t.Errorf("y = p+%d, sign %d decoded as canonical", i, sign)
			}
			if p == nil {
				t.Fatalf("y = p+%d decoded to a nil point", i)
			}
		}
	}
	if unreduced < 10 {
		t.Fatalf("only %d unreduced encodings were on the curve; too few to be "+
			"evidence about the range", unreduced)
	}

	// A y that is on no curve point at all must be rejected outright rather
	// than silently reinterpreted.
	bad := make([]byte, PubKeySize)
	found := false
	for i := byte(2); i < 200 && !found; i++ {
		bad[0] = i
		if _, st := decodeEdPoint(bad); st == decodeInvalid {
			found = true
		}
	}
	if !found {
		t.Fatal("no off-curve y found in 200 tries; the decoder accepts everything")
	}

	if _, st := decodeEdPoint(make([]byte, 31)); st != decodeInvalid {
		t.Error("a short encoding was accepted")
	}
}

// TestDecodedCoordinatesAreReduced pins the invariant the rest of the file
// assumes: a point handed back by decodeEdPoint carries reduced coordinates.
//
// The case that broke it is the one this package exists for. For x = 0 with the
// sign bit set, the negation `x = p - x` used to run anyway and produce p — a
// value congruent to zero but not equal to it — so isIdentity(), whose test is
// x.Sign() != 0, answered *false for the identity point*. Nothing reached it:
// VerifyStrict refuses non-canonical encodings before inspecting the point, and
// isLowOrder/isTorsionFree reduce through mul. That is what makes it worth a
// test rather than a comment — it is unreachable today and silently wrong the
// first time someone calls isIdentity on a decoded point.
func TestDecodedCoordinatesAreReduced(t *testing.T) {
	enc := func(hexish string) []byte {
		out := make([]byte, PubKeySize)
		b, ok := new(big.Int).SetString(hexish, 16)
		if !ok {
			t.Fatalf("bad test constant %q", hexish)
		}
		bs := b.Bytes()
		for i := 0; i < len(bs); i++ {
			out[i] = bs[len(bs)-1-i]
		}
		return out
	}
	// y = 1 with the sign bit: the non-canonical spelling of the identity.
	// y = p-1 (ec ff..ff) with the sign bit: the non-canonical order-2 point.
	// y = p+1 (ee ff..ff) with the sign bit: the same identity, unreduced y too.
	cases := []struct {
		name     string
		enc      []byte
		identity bool
	}{
		{"identity, sign bit set", enc("8000000000000000000000000000000000000000000000000000000000000001"), true},
		{"order 2, sign bit set", enc("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"), false},
		{"identity, unreduced y, sign bit set", enc("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee"), true},
	}
	for _, tc := range cases {
		p, st := decodeEdPoint(tc.enc)
		if st != decodeNonCanonical {
			t.Fatalf("%s: status %v, want non-canonical", tc.name, st)
		}
		if p.x.Sign() != 0 {
			t.Errorf("%s: x = %s, want 0 — an unreduced coordinate escaped the decoder",
				tc.name, p.x.String())
		}
		if p.x.Cmp(fieldP) >= 0 || p.y.Cmp(fieldP) >= 0 {
			t.Errorf("%s: coordinates are not reduced", tc.name)
		}
		if got := p.isIdentity(); got != tc.identity {
			t.Errorf("%s: isIdentity() = %v, want %v", tc.name, got, tc.identity)
		}
		// Whatever the spelling, the order predicates must still agree.
		if !isLowOrder(p) {
			t.Errorf("%s: not reported low order", tc.name)
		}
	}
}

// TestPrefilterAgreesWithTheDecoder holds the byte-level canonicality test to
// the decoder's own answer. The prefilter exists only to make the cheapest
// rejection cheap; the moment it disagrees with decodeEdPoint on a point, it is
// a second, silent rule.
func TestPrefilterAgreesWithTheDecoder(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	enc := func(y *big.Int, sign byte) []byte {
		b := y.Bytes()
		out := make([]byte, PubKeySize)
		for i := 0; i < len(b); i++ {
			out[i] = b[len(b)-1-i]
		}
		out[31] |= sign << 7
		return out
	}

	checked, nonCanonical := 0, 0
	ys := []*big.Int{}
	for i := int64(0); i <= 64; i++ {
		ys = append(ys, big.NewInt(i))
	}
	// The whole non-canonical range, plus its neighbourhood below p.
	for i := int64(-20); i <= 18; i++ {
		ys = append(ys, new(big.Int).Add(fieldP, big.NewInt(i)))
	}
	for _, y := range ys {
		if y.Sign() < 0 || y.Cmp(limit) >= 0 {
			continue
		}
		for sign := byte(0); sign < 2; sign++ {
			b := enc(y, sign)
			_, st := decodeEdPoint(b)
			if st == decodeInvalid {
				// The prefilter deliberately says nothing about non-points;
				// the signature equation refuses those.
				continue
			}
			checked++
			if st == decodeNonCanonical {
				nonCanonical++
			}
			if want := st == decodeCanonical; isCanonicalEncoding(b) != want {
				t.Errorf("y = %s sign %d: prefilter %v, decoder %v",
					y.String(), sign, isCanonicalEncoding(b), st)
			}
		}
	}
	if checked < 40 || nonCanonical < 10 {
		t.Fatalf("swept %d encodings of which %d non-canonical; too few to be evidence",
			checked, nonCanonical)
	}
	if isCanonicalEncoding(make([]byte, 31)) {
		t.Error("a short encoding passed the prefilter")
	}
}

// TestOrderPredicatesAgreeWithTheCurve checks the two predicates against
// arithmetic rather than against expectations: the torsion subgroup is
// generated here, and every element of it must be low order and not
// torsion-free, while the base point's multiples must be the reverse.
func TestOrderPredicatesAgreeWithTheCurve(t *testing.T) {
	var sc edScratch
	// A point of order 8, obtained by killing the prime-order component of an
	// arbitrary curve point.
	var gen *edPoint
	for i := int64(2); i < 200 && gen == nil; i++ {
		y := big.NewInt(i)
		b := y.Bytes()
		enc := make([]byte, PubKeySize)
		for j := 0; j < len(b); j++ {
			enc[j] = b[len(b)-1-j]
		}
		p, st := decodeEdPoint(enc)
		if st == decodeInvalid {
			continue
		}
		var cand edPoint
		sc.scalarMul(&cand, groupL, p)
		var four edPoint
		sc.double(&four, &cand)
		sc.double(&four, &four)
		if four.isIdentity() {
			continue
		}
		var eight edPoint
		sc.double(&eight, &four)
		if eight.isIdentity() {
			gen = &cand
		}
	}
	if gen == nil {
		t.Fatal("no point of order 8 found")
	}

	var acc edPoint
	acc.setIdentity()
	for i := 0; i < 8; i++ {
		if !isLowOrder(&acc) {
			t.Errorf("[%d]T is not reported low order", i)
		}
		// Only the identity among them is torsion-free.
		if isTorsionFree(&acc) != (i == 0) {
			t.Errorf("[%d]T: torsion-free reported %v", i, isTorsionFree(&acc))
		}
		sc.addPoints(&acc, &acc, gen)
	}
	if !acc.isIdentity() {
		t.Fatal("the torsion subgroup did not close after eight elements")
	}

	// An honest public key: torsion-free, not low order. Derived here from a
	// point of large order rather than from a keypair, so this test needs no
	// signing machinery.
	var large *edPoint
	for i := int64(2); i < 200 && large == nil; i++ {
		y := big.NewInt(i)
		b := y.Bytes()
		enc := make([]byte, PubKeySize)
		for j := 0; j < len(b); j++ {
			enc[j] = b[len(b)-1-j]
		}
		p, st := decodeEdPoint(enc)
		if st == decodeInvalid {
			continue
		}
		// Clear the cofactor: [8]P has order dividing L.
		var q edPoint
		sc.double(&q, p)
		sc.double(&q, &q)
		sc.double(&q, &q)
		if !q.isIdentity() {
			large = &q
		}
	}
	if large == nil {
		t.Fatal("no large-order point found")
	}
	if isLowOrder(large) {
		t.Error("a cofactor-cleared point was reported low order")
	}
	if !isTorsionFree(large) {
		t.Error("a cofactor-cleared point was not reported torsion-free")
	}

	// And a mixed-order point is neither: not low order, so no blocklist could
	// ever name it, and not torsion-free, so this predicate is the only thing
	// that sees it.
	var mixed edPoint
	sc.addPoints(&mixed, large, gen)
	if isLowOrder(&mixed) {
		t.Error("a mixed-order point was reported low order")
	}
	if isTorsionFree(&mixed) {
		t.Error("a mixed-order point was reported torsion-free — the torsion check " +
			"that closes id-malleability under a valid authorization is not working")
	}
}
