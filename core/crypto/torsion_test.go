package crypto_test

// Tests for the strictness rules of VerifyStrict: canonical point encodings,
// low-order keys, and torsion.
//
// Everything curve-related below is derived here, independently of the
// implementation under test. The package computes its answers with its own
// arithmetic; this file computes the expected sets with arithmetic written
// separately, from the curve equation, and never imports an internal helper.
// That is the whole point: the defect being fixed was a *literal* that nobody
// could tell was short, so a test that asserted against another literal would
// reproduce the original failure exactly.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	"zycord/core/crypto"
)

var (
	tp = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	tl = func() *big.Int {
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return l
	}()
	td = func() *big.Int {
		n := big.NewInt(-121665)
		den := new(big.Int).ModInverse(big.NewInt(121666), tp)
		return n.Mod(n.Mul(n, den), tp)
	}()
	tsqrtM1 = func() *big.Int {
		e := new(big.Int).Rsh(new(big.Int).Sub(tp, big.NewInt(1)), 2)
		return new(big.Int).Exp(big.NewInt(2), e, tp)
	}()
)

// tPoint is an affine point; the test arithmetic is affine because it is
// clearer to read and nothing here is on a hot path.
type tPoint struct{ x, y *big.Int }

func tIdentity() tPoint { return tPoint{big.NewInt(0), big.NewInt(1)} }

func (p tPoint) equal(q tPoint) bool { return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0 }

// tAdd is the affine twisted-Edwards addition law with a = -1:
// x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2), y3 = (y1*y2 + x1*x2) / (1 - ...).
// It is complete on this curve, so it needs no special case for doubling or for
// the identity.
func tAdd(p, q tPoint) tPoint {
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), tp) }
	x1x2 := mul(p.x, q.x)
	y1y2 := mul(p.y, q.y)
	dxy := mul(td, mul(x1x2, y1y2))
	nx := new(big.Int).Mod(new(big.Int).Add(mul(p.x, q.y), mul(q.x, p.y)), tp)
	ny := new(big.Int).Mod(new(big.Int).Add(y1y2, x1x2), tp)
	dx := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Add(big.NewInt(1), dxy), tp), tp)
	dy := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), dxy), tp), tp)
	return tPoint{mul(nx, dx), mul(ny, dy)}
}

func tScalarMul(k *big.Int, p tPoint) tPoint {
	acc := tIdentity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = tAdd(acc, acc)
		if k.Bit(i) == 1 {
			acc = tAdd(acc, p)
		}
	}
	return acc
}

// tRecoverX solves the curve equation for x given y, returning the root with
// the requested low bit. It reports false when y names no point at all.
func tRecoverX(y *big.Int, sign byte) (*big.Int, bool) {
	y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), tp)
	u := new(big.Int).Mod(new(big.Int).Sub(y2, big.NewInt(1)), tp)
	v := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(td, y2), big.NewInt(1)), tp)
	if v.Sign() == 0 {
		return nil, false
	}
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, tp)), tp)
	e := new(big.Int).Rsh(new(big.Int).Add(tp, big.NewInt(3)), 3)
	x := new(big.Int).Exp(x2, e, tp)
	if new(big.Int).Mod(new(big.Int).Mul(x, x), tp).Cmp(x2) != 0 {
		x.Mod(x.Mul(x, tsqrtM1), tp)
	}
	if new(big.Int).Mod(new(big.Int).Mul(x, x), tp).Cmp(x2) != 0 {
		return nil, false
	}
	if byte(x.Bit(0)) != sign && x.Sign() != 0 {
		x.Sub(tp, x)
	}
	return x, true
}

// tEncode compresses a point the way the wire format does: 32 little-endian
// bytes of y, with the low bit of x in the top bit. yOverride lets a caller ask
// for a deliberately non-canonical spelling of the same y.
func tEncode(yEnc *big.Int, sign byte) crypto.PubKey {
	b := yEnc.Bytes()
	var out crypto.PubKey
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	out[31] |= sign << 7
	return out
}

func tDecodeKey(k crypto.PubKey) (tPoint, bool) {
	var le [32]byte
	for i := range le {
		le[i] = k[31-i]
	}
	sign := le[0] >> 7
	le[0] &= 0x7f
	yEnc := new(big.Int).SetBytes(le[:])
	y := new(big.Int).Mod(yEnc, tp)
	x, ok := tRecoverX(y, sign)
	if !ok {
		return tPoint{}, false
	}
	return tPoint{x, y}, true
}

// tTorsionSubgroup returns the eight points of order dividing 8, derived from
// the curve rather than written down. It finds a point of order 8 by taking an
// arbitrary curve point and multiplying by L, which annihilates the
// prime-order component and leaves the torsion component behind.
func tTorsionSubgroup(t *testing.T) []tPoint {
	t.Helper()
	var gen tPoint
	found := false
	for i := int64(2); i < 200 && !found; i++ {
		y := big.NewInt(i)
		x, ok := tRecoverX(y, 0)
		if !ok {
			continue
		}
		cand := tScalarMul(tl, tPoint{x, y})
		// Order exactly 8: [8]T = O and [4]T != O.
		four := tAdd(tAdd(cand, cand), tAdd(cand, cand))
		if !tAdd(four, four).equal(tIdentity()) || four.equal(tIdentity()) {
			continue
		}
		gen, found = cand, true
	}
	if !found {
		t.Fatal("no point of order 8 found; the test's own curve arithmetic is wrong")
	}
	pts := make([]tPoint, 0, 8)
	acc := tIdentity()
	for i := 0; i < 8; i++ {
		pts = append(pts, acc)
		acc = tAdd(acc, gen)
	}
	if !acc.equal(tIdentity()) {
		t.Fatal("the torsion subgroup did not close after eight elements")
	}
	return pts
}

// tLowOrderEncodings returns every 32-byte string that decodes to a low-order
// point under the two relaxations `crypto/ed25519` documents: an unreduced y
// (y + p, when that still fits in 255 bits) and a sign bit set on an x of zero.
// The set is derived, so it cannot be short.
func tLowOrderEncodings(t *testing.T) []crypto.PubKey {
	t.Helper()
	var out []crypto.PubKey
	seen := map[crypto.PubKey]bool{}
	add := func(k crypto.PubKey) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	for _, pt := range tTorsionSubgroup(t) {
		for _, yEnc := range []*big.Int{pt.y, new(big.Int).Add(pt.y, tp)} {
			if yEnc.Cmp(limit) >= 0 {
				continue
			}
			if pt.x.Sign() == 0 {
				// x = -x, so both sign bits decode to this same point; the set
				// bit is the non-canonical spelling.
				add(tEncode(yEnc, 0))
				add(tEncode(yEnc, 1))
				continue
			}
			add(tEncode(yEnc, byte(pt.x.Bit(0))))
		}
	}
	return out
}

// TestLowOrderKeysAreRefused walks the *derived* low-order set rather than a
// literal, which is the whole fix: the predecessor of this test hand-built two
// keys and checked them against a nine-entry table that was missing five live
// encodings, two of which decode to the identity and verify every signature.
func TestLowOrderKeysAreRefused(t *testing.T) {
	set := tLowOrderEncodings(t)
	if len(set) != 14 {
		t.Fatalf("derived %d low-order encodings, want 14", len(set))
	}
	for _, key := range set {
		if !crypto.IsSmallOrderPubKey(key) {
			t.Errorf("%x is not recognised as low order", key)
		}
		refusesAForgery(t, key, "derived low-order key")
	}

	// The five encodings the hand-written table was missing, named explicitly,
	// so that a future regression is reported as itself and not as a count.
	ff := func(first, last byte) crypto.PubKey {
		var k crypto.PubKey
		k[0] = first
		for i := 1; i < 31; i++ {
			k[i] = 0xff
		}
		k[31] = last
		return k
	}
	var zero crypto.PubKey
	identitySignSet := crypto.PubKey{0x01}
	identitySignSet[31] = 0x80
	for name, key := range map[string]crypto.PubKey{
		"all-zero (order 4)":        zero,
		"identity with sign bit":    identitySignSet,
		"order 2, y+p":              ff(0xec, 0xff),
		"y = p (order 4), sign set": ff(0xed, 0xff),
		"y = p+1 (identity), y+p":   ff(0xee, 0xff),
	} {
		if !seenIn(set, key) {
			t.Errorf("the derived set does not contain %s (%x)", name, key)
		}
		refusesAForgery(t, key, name)
	}

	// And the filter must not catch an honest key.
	pub, _, err := ed25519.GenerateKey(deterministicReader(11))
	if err != nil {
		t.Fatal(err)
	}
	var honest crypto.PubKey
	copy(honest[:], pub)
	if crypto.IsSmallOrderPubKey(honest) {
		t.Fatal("an ordinary key was reported as low order")
	}
}

func seenIn(set []crypto.PubKey, k crypto.PubKey) bool {
	for i := range set {
		if set[i] == k {
			return true
		}
	}
	return false
}

// TestDerivedSetSupersedesTheOldTable pins the regression itself. The literal
// below is the table VerifyStrict used to consult, copied verbatim from the
// commit this change replaces. Every entry of it must still be refused — the
// fix must not be a swap that loses ground — and the derived set must be
// strictly larger, by the five encodings the table was missing.
func TestDerivedSetSupersedesTheOldTable(t *testing.T) {
	ff := func(first byte, last byte) crypto.PubKey {
		var k crypto.PubKey
		k[0] = first
		for i := 1; i < 31; i++ {
			k[i] = 0xff
		}
		k[31] = last
		return k
	}
	hex8 := func(b ...byte) crypto.PubKey {
		var k crypto.PubKey
		copy(k[:], b)
		return k
	}
	orderEightA := []byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}
	orderEightB := []byte{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	}
	flipTop := func(b []byte) []byte {
		out := append([]byte(nil), b...)
		out[31] ^= 0x80
		return out
	}
	old := []crypto.PubKey{
		{0x01},
		ff(0xec, 0x7f),
		hex8(append(make([]byte, 31), 0x80)...),
		hex8(orderEightA...),
		hex8(orderEightB...),
		hex8(flipTop(orderEightA)...),
		hex8(flipTop(orderEightB)...),
		ff(0xee, 0x7f),
		ff(0xed, 0x7f),
	}

	derived := tLowOrderEncodings(t)
	for _, k := range old {
		if !seenIn(derived, k) {
			t.Errorf("the derived set lost an entry the old table had: %x", k)
		}
		refusesAForgery(t, k, "entry of the replaced table")
	}
	if len(derived)-len(old) != 5 {
		t.Errorf("the derived set has %d entries against the table's %d; the gap this "+
			"change closes is five", len(derived), len(old))
	}
}

// TestIdentityKeysForgeEverySignature is the executed attack, not the argument
// for it. Under A = identity the verification equation collapses to [S]B = R,
// so a signature can be produced with no private key for A at all — and the
// same body then has unboundedly many valid signature encodings, hence
// unboundedly many certificate ids, and the seen set (whitepaper §2's entire
// replay defence) stops holding.
//
// The test asserts both halves: that the standard library really does accept
// the forgery (otherwise the rest proves nothing), and that VerifyStrict does
// not.
func TestIdentityKeysForgeEverySignature(t *testing.T) {
	identity := crypto.PubKey{0x01}
	identitySignSet := identity
	identitySignSet[31] = 0x80
	var allZero crypto.PubKey // y = 0, the order-4 point

	msg := []byte("an authorization nobody signed")

	// The forgery: any (R, S) with [S]B = R. Take an honest keypair, use its
	// public key as R and its own clamped scalar as S.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	h := sha512.Sum512(seed)
	a := clampToScalar(h[:32])
	var sig crypto.Signature
	copy(sig[:32], priv.Public().(ed25519.PublicKey))
	copy(sig[32:], leBytes(new(big.Int).Mod(a, tl)))

	for name, key := range map[string]crypto.PubKey{
		"identity":               identity,
		"identity with sign bit": identitySignSet,
	} {
		if !ed25519.Verify(ed25519.PublicKey(key[:]), msg, sig[:]) {
			t.Fatalf("%s: the standard library rejected the forgery, so this test would "+
				"pass for the wrong reason", name)
		}
		if crypto.VerifyStrict(key, msg, sig) {
			t.Errorf("%s: a forged signature verified", name)
		}
	}

	// The all-zero key has order 4, so it does not accept every signature — but
	// it accepts one out of about four, which is a search of a few tries. Find
	// one with the standard library, then require VerifyStrict to refuse it.
	forged, ok := forgeUnderLowOrderKey(t, allZero)
	if !ok {
		t.Fatal("no accepted triple found under the all-zero key; the search, not the key, is wrong")
	}
	if !ed25519.Verify(ed25519.PublicKey(allZero[:]), forged.msg, forged.sig[:]) {
		t.Fatal("the search returned a triple the standard library rejects")
	}
	if crypto.VerifyStrict(allZero, forged.msg, forged.sig) {
		t.Error("the all-zero key verified a forged signature")
	}
}

type forgedTriple struct {
	msg []byte
	sig crypto.Signature
}

// refusesAForgery is the armed form of "VerifyStrict rejects this key".
//
// The unarmed form, which this replaces everywhere it was used, was
//
//	if crypto.VerifyStrict(key, []byte("anything"), crypto.Signature{})
//
// and it constrained nothing. crypto.Signature{} is S = 0 with an all-zero R;
// ed25519.Verify computes [0]B = identity, byte-compares it against the order-4
// point the all-zero R decodes to, and returns false for *every* key and every
// message. So the assertion held with all of VerifyStrict's strictness deleted —
// it measured the scenario rather than the rule, which is the vacuity CONTRIBUTING
// names. Stubbing VerifyStrict down to a bare ed25519.Verify left the whole of
// ./core/validity green and TestNonCanonicalPubKeysAreRefused green with it.
//
// Each key is therefore handed a signature the standard library genuinely
// accepts, and the assertion is that VerifyStrict does not. A key for which no
// such signature can be found is a failure, not a pass: it means the search is
// wrong, and a silent skip would restore exactly the vacuity being removed.
func refusesAForgery(t *testing.T, key crypto.PubKey, label string) {
	t.Helper()
	forged, ok := forgeUnderLowOrderKey(t, key)
	if !ok {
		t.Errorf("%s (%x): no signature the standard library accepts was found under "+
			"this key, so this assertion would constrain nothing", label, key)
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(key[:]), forged.msg, forged.sig[:]) {
		t.Fatalf("%s (%x): the search returned a triple the standard library rejects",
			label, key)
	}
	if crypto.VerifyStrict(key, forged.msg, forged.sig) {
		t.Errorf("%s (%x): a signature the standard library accepts under a low-order "+
			"key also verified here", label, key)
	}
}

// forgeUnderLowOrderKey searches for an (R, S) that the standard library
// accepts under a low-order key, with S = 0 and R ranging over the low-order
// encodings: the equation becomes O = R + [h]A, which holds whenever h lands in
// the right residue class mod the key's order.
func forgeUnderLowOrderKey(t *testing.T, key crypto.PubKey) (forgedTriple, bool) {
	t.Helper()
	for _, r := range tLowOrderEncodings(t) {
		for i := 0; i < 64; i++ {
			msg := []byte{byte(i), byte(i >> 8), 'f', 'o', 'r', 'g', 'e'}
			var sig crypto.Signature
			copy(sig[:32], r[:])
			if ed25519.Verify(ed25519.PublicKey(key[:]), msg, sig[:]) {
				return forgedTriple{msg, sig}, true
			}
		}
	}
	return forgedTriple{}, false
}

// TestNonCanonicalPubKeysAreRefused covers V2's point half, which the standard
// library does not enforce: `SetBytes` reduces y modulo p instead of rejecting
// y >= p, and it accepts a sign bit on an x of zero.
//
// There are exactly 19 unreduced encodings that fit in 255 bits — y_enc in
// [p, p+18], i.e. y in [0, 18] — and this walks all of them, both signs. Note
// what the count kills: the report that found this defect said the only
// in-range non-canonical values are y = p and y = p+1. There are nineteen,
// and a fix written from that sentence would be a two-value blocklist rather
// than a y < p comparison, which is the same failure the rule exists to
// close. This test is the guard on that: it asserts the whole range, not two
// entries.
//
// Only y in {0, 1} are low order; the rest are ordinary points whose discrete
// log nobody knows, which is why this rule has no exploit of its own and
// is not a reason to leave it unenforced — the rule is about what a verifier
// does with bytes, and a second implementation that accepts what this one
// rejects is a chain split.
//
// What that costs this test, stated rather than glossed. Only the four
// low-order members can be handed a signature the standard library accepts, so
// only those four assertions constrain VerifyStrict; they call refusesAForgery.
// For the other fifteen there is no such signature to build — that is the same
// unforgeability that makes the rule unexploitable — so their VerifyStrict
// assertion is a smoke check that would survive the rule being deleted. It is
// kept because it costs nothing, and it is *not* where the canonicality rule is
// guarded: that is TestDecodeReportsCanonicality and TestPrefilterAgreesWithThe
// Decoder, one level down, on the decoder and the byte prefilter, where the
// mutants do die. The count assertions below are the load-bearing part here.
func TestNonCanonicalPubKeysAreRefused(t *testing.T) {
	msg := []byte("zcd/noncanonical")
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	onCurve, lowOrder := 0, 0
	for i := int64(0); i < 19; i++ {
		yEnc := new(big.Int).Add(tp, big.NewInt(i))
		if yEnc.Cmp(limit) >= 0 {
			t.Fatalf("y_enc = p+%d does not fit in 255 bits; the range is wrong", i)
		}
		for sign := byte(0); sign < 2; sign++ {
			key := tEncode(yEnc, sign)
			if _, ok := tDecodeKey(key); !ok {
				continue
			}
			onCurve++
			if crypto.IsSmallOrderPubKey(key) {
				lowOrder++
				// The four low-order members are the only ones that can be armed,
				// and they are armed: a low-order key admits a signature the
				// standard library really accepts, so refusing it is a claim about
				// the rule. For the rest, see the note above the loop.
				refusesAForgery(t, key,
					fmt.Sprintf("non-canonical low-order key, y = p+%d, sign %d", i, sign))
				continue
			}
			if crypto.VerifyStrict(key, msg, crypto.Signature{}) {
				t.Errorf("a non-canonically encoded key (y = p+%d, sign %d) verified", i, sign)
			}
		}
	}
	if new(big.Int).Add(tp, big.NewInt(19)).Cmp(limit) < 0 {
		t.Fatal("p+19 still fits in 255 bits; the non-canonical range is larger than 19")
	}
	if onCurve == 0 {
		t.Fatal("no non-canonical encoding was on the curve; the test asserted nothing")
	}
	// y = 0 (order 4) and y = 1 (identity), each with both sign bits.
	if lowOrder != 4 {
		t.Errorf("%d of the non-canonical encodings are low order, want 4", lowOrder)
	}
	if onCurve <= lowOrder {
		t.Fatal("every non-canonical encoding on the curve was low order, so this test " +
			"is only re-testing the order check, not canonicality")
	}

	// The sign bit set on x = 0 is the other relaxation, and it must lose too.
	// y = 0 is the order-4 point, so this one is armable and is armed.
	var zeroSignSet crypto.PubKey
	zeroSignSet[31] = 0x80
	refusesAForgery(t, zeroSignSet, "x = 0 with the sign bit set")
}

// TestMixedOrderKeysAreRefused is the half a blocklist can never reach.
//
// A = A' + T with A' of large order and T of order 8 is not small order: there
// are about 2^252 such keys, and no table can name them. It is also exactly
// where a cofactored batch verifier and a cofactorless single verifier
// disagree. This test builds a signature that the standard library's
// cofactorless check *accepts* under such a key — the attacker grinds the
// torsion component of R until it cancels [h]T, which costs a handful of tries
// — and requires VerifyStrict to reject it.
//
// Zycord's choice is (a): cofactorless verification plus an explicit torsion
// rejection on A. R is not tested — not for torsion, which the equation refuses
// by itself (asserted at the end of this test), and not for low order, which
// would reject R = identity and break RFC 8032 conformance (see
// TestRIdentityIsAcceptedAsRFC8032Requires). With A in the prime-order subgroup,
// S*B - R - h*A lies in that subgroup, so it is the identity if and only if
// eight times it is: the future batch verifier may be cofactored, as batch
// verifiers normally are, and still agree with this function on every input —
// provided it applies A's rules before batching and rejects a torsion-carrying
// R, which cofactoring would otherwise let through.
func TestMixedOrderKeysAreRefused(t *testing.T) {
	torsion := tTorsionSubgroup(t)
	var order8 tPoint
	for _, pt := range torsion {
		four := tAdd(tAdd(pt, pt), tAdd(pt, pt))
		if !four.equal(tIdentity()) {
			order8 = pt
			break
		}
	}

	// An honest keypair, whose scalar we know.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0xa0 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	hs := sha512.Sum512(seed)
	a := clampToScalar(hs[:32])
	var honest crypto.PubKey
	copy(honest[:], priv.Public().(ed25519.PublicKey))
	honestPt, ok := tDecodeKey(honest)
	if !ok {
		t.Fatal("the honest public key did not decode")
	}

	// The mixed-order key: same signing power, a torsion component bolted on.
	mixedPt := tAdd(honestPt, order8)
	mixed := tEncode(mixedPt.y, byte(mixedPt.x.Bit(0)))
	if crypto.IsSmallOrderPubKey(mixed) {
		t.Fatal("the mixed-order key is small order; the construction is wrong")
	}

	msg := []byte("a signature under a key with a torsion component")

	// Grind: R = [r]B + T_r, and the equation holds cofactorlessly exactly when
	// T_r + [h]T is the identity.
	var found bool
	var sig crypto.Signature
	for n := 0; n < 512 && !found; n++ {
		rSeed := make([]byte, 32)
		rSeed[0] = byte(n)
		rSeed[1] = byte(n >> 8)
		rPriv := ed25519.NewKeyFromSeed(rSeed)
		rh := sha512.Sum512(rSeed)
		r := clampToScalar(rh[:32])
		var rBytes crypto.PubKey
		copy(rBytes[:], rPriv.Public().(ed25519.PublicKey))
		rPt, ok := tDecodeKey(rBytes)
		if !ok {
			continue
		}
		for _, tr := range torsion {
			full := tAdd(rPt, tr)
			enc := tEncode(full.y, byte(full.x.Bit(0)))
			hh := sha512.Sum512(concat(enc[:], mixed[:], msg))
			h := new(big.Int).Mod(leToInt(hh[:]), tl)
			// S = r + h*a mod L makes [S]B = [r]B + [h]A'. The residue is
			// T_r + [h]T, which must vanish.
			resid := tAdd(tr, tScalarMul(new(big.Int).Mod(h, big.NewInt(8)), order8))
			if !resid.equal(tIdentity()) {
				continue
			}
			s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(h, a)), tl)
			copy(sig[:32], enc[:])
			copy(sig[32:], leBytes(s))
			if ed25519.Verify(ed25519.PublicKey(mixed[:]), msg, sig[:]) {
				found = true
			}
			break
		}
	}
	if !found {
		t.Fatal("could not build a signature the standard library accepts under a " +
			"mixed-order key; without one this test asserts nothing")
	}
	if crypto.VerifyStrict(mixed, msg, sig) {
		t.Error("a mixed-order public key verified — cofactored batch verification and " +
			"cofactorless single verification disagree on exactly this input")
	}

	// An honest signature under an honest key must still verify — a strictness
	// change that rejects everything would pass every assertion above.
	honestSig := ed25519.Sign(priv, msg)
	var hs2 crypto.Signature
	copy(hs2[:], honestSig)
	if !crypto.VerifyStrict(honest, msg, hs2) {
		t.Fatal("an honest signature stopped verifying")
	}

	// And the reason VerifyStrict does not re-test R's torsion, asserted rather
	// than assumed: cofactorless verification reconstructs R as S*B - h*A, which
	// is torsion-free whenever A is, so no R carrying a torsion component can
	// ever satisfy the equation. A *cofactored* verifier gets no such guarantee,
	// which is precisely the obligation the doc comment places on the future
	// batch path. Every torsion offset of an honest R must be refused, by the
	// equation itself.
	honestR, ok := tDecodeKey(func() crypto.PubKey {
		var k crypto.PubKey
		copy(k[:], honestSig[:32])
		return k
	}())
	if !ok {
		t.Fatal("the honest R did not decode")
	}
	offsets := 0
	for _, tr := range torsion {
		if tr.equal(tIdentity()) {
			continue
		}
		shifted := tAdd(honestR, tr)
		var cand crypto.Signature
		enc := tEncode(shifted.y, byte(shifted.x.Bit(0)))
		copy(cand[:32], enc[:])
		copy(cand[32:], honestSig[32:])
		offsets++
		if ed25519.Verify(ed25519.PublicKey(honest[:]), msg, cand[:]) {
			t.Error("an R with a torsion component satisfied cofactorless verification " +
				"under a torsion-free key; VerifyStrict's omission of a torsion test on R " +
				"is no longer sound")
		}
		if crypto.VerifyStrict(honest, msg, cand) {
			t.Error("an R with a torsion component verified")
		}
	}
	if offsets != 7 {
		t.Errorf("tested %d torsion offsets of R, want 7", offsets)
	}
}

// TestRIdentityIsAcceptedAsRFC8032Requires is the guard on a rule that was
// added and then removed, and it exists so the rule cannot come back by looking
// symmetrical.
//
// An earlier draft ran `isLowOrder(a) || isLowOrder(r)`. The second half looks
// like prudence and is not: once [L]A is the identity, R = S*B - h*A lies in the
// prime-order subgroup, and the only low-order point in that subgroup is the
// identity — so isLowOrder(r) could fire on exactly one input, R = identity, and
// that input is a signature RFC 8032 accepts. A signer reaches it with a zero
// nonce: r = 0 gives R = O and S = h*a mod L, and [S]B = [h]A = O + [h]A closes.
//
// Nothing honest produces it (r is a hash, and publishing r = 0 hands the
// signing scalar to anyone who divides), but the rule this project is holding
// itself to is not "honest signers are unaffected" — it is that a second
// implementation written from the spec agrees with this one, byte for byte, on
// every input. ARCHITECTURE.md §7 says R's subgroup membership is *entailed*
// rather than checked, and the identity is in the subgroup, so the spec grants
// no licence to reject this. Rejecting it would be the non-canonical-encoding
// defect with the sign flipped: this client refusing what a conformant one
// accepts.
//
// The test asserts the standard library accepts it first, so it cannot pass
// because the construction quietly failed, and then requires VerifyStrict to
// agree. It also checks that accepting the *canonical* identity R grants nothing
// to its non-canonical spellings, which V2 still refuses.
func TestRIdentityIsAcceptedAsRFC8032Requires(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 11)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var pub crypto.PubKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	hs := sha512.Sum512(seed)
	a := clampToScalar(hs[:32])

	// R = the identity, canonically encoded, which is what a zero nonce yields.
	var rEnc crypto.PubKey
	rEnc[0] = 0x01

	msg := []byte("a signature whose nonce was zero")
	hh := sha512.Sum512(concat(rEnc[:], pub[:], msg))
	h := new(big.Int).Mod(leToInt(hh[:]), tl)
	s := new(big.Int).Mod(new(big.Int).Mul(h, a), tl)

	var sig crypto.Signature
	copy(sig[:32], rEnc[:])
	copy(sig[32:], leBytes(s))

	if !ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:]) {
		t.Fatal("the standard library rejected a zero-nonce signature, so this test " +
			"would pass for the wrong reason — the construction is wrong, not the rule")
	}
	if !crypto.VerifyStrict(pub, msg, sig) {
		t.Error("VerifyStrict rejected R = identity, which RFC 8032, crypto/ed25519 and " +
			"ARCHITECTURE.md §7 all accept: this client now splits from any conformant " +
			"second implementation: the non-canonical-encoding defect, sign flipped")
	}

	// Accepting the canonical identity says nothing about its other spellings.
	// V2 rejects those on the bytes, and must go on doing so.
	nonCanonical := map[string]crypto.PubKey{
		"identity with the sign bit set": func() crypto.PubKey {
			k := rEnc
			k[31] = 0x80
			return k
		}(),
		"y = p+1, the unreduced identity": func() crypto.PubKey {
			var k crypto.PubKey
			k[0] = 0xee
			for i := 1; i < 31; i++ {
				k[i] = 0xff
			}
			k[31] = 0x7f
			return k
		}(),
	}
	//
	// This is also where R's canonicality rule is pinned rather than merely
	// stated. Deleting isCanonicalEncoding(sig[:32]) from VerifyStrict does not
	// fail any test, because ed25519.Verify re-encodes the R it reconstructs and
	// byte-compares — so the standard library already refuses every spelling but
	// the canonical one. That makes our check redundant *today*, and V2 keeps it
	// anyway on the rule this project holds elsewhere: rejection is a consensus
	// rule, not an assumption about somebody's library. The assumption is
	// therefore asserted here, next to the rule it makes redundant. If a Go
	// release ever relaxed R the way SetBytes already relaxes the public key,
	// this loop starts failing, and the check in VerifyStrict stops being
	// redundant on the same day — which is the point of writing it down.
	for name, alt := range nonCanonical {
		var altSig crypto.Signature
		copy(altSig[:32], alt[:])
		copy(altSig[32:], sig[32:])
		if ed25519.Verify(ed25519.PublicKey(pub[:]), msg, altSig[:]) {
			t.Errorf("the standard library accepted R spelled as %s; VerifyStrict's "+
				"own canonicality check on R is now load-bearing rather than redundant, "+
				"and the mutation table must stop reporting it as an unkillable mutant", name)
		}
		if crypto.VerifyStrict(pub, msg, altSig) {
			t.Errorf("R spelled as %s verified; V2's encoding rule has been lost", name)
		}
	}
}

// TestCofactorlessVerificationIsPinned is the test that makes VerifyStrict's
// omission of a torsion check on R safe to keep.
//
// VerifyStrict tests torsion on A and not on R, on the argument that acceptance
// forces R = [S]B - [h]A as a point, which lies in the prime-order subgroup
// whenever A does. That argument is correct — but it is a property of
// `crypto/ed25519`, not of anything in this repository. Go does not document
// cofactorless verification as a compatibility guarantee, and cofactored /
// ZIP-215 semantics have repeatedly been proposed for exactly this API. If a
// future Go release adopted them, VerifyStrict would silently begin accepting
// the seven torsion offsets of every R — and because cert_id covers Sigs, that
// is eight ids for one authorization: the replay the PR's ZIP-215 rejection
// argues against, arriving through the back door of a toolchain bump.
//
// So the property is pinned rather than assumed. The signature built below is
// one a *cofactored* verifier accepts and a cofactorless one rejects:
//
//	R' = [r]B + T, with T of order 8;  h = H(R' ‖ A ‖ M);  S = r + h*a mod L
//
// Then [S]B = [r]B + [h]A = R' - T + [h]A, so [8][S]B = [8](R' + [h]A) and a
// cofactored check closes, while the cofactorless equality [S]B == R' + [h]A
// fails by exactly T. The test asserts the cofactored identity itself with its
// own arithmetic — so it cannot pass because the construction quietly failed —
// and then asserts that ed25519.Verify REJECTS it. A stdlib that starts
// accepting torsion in R fails this line, in CI, instead of in consensus.
func TestCofactorlessVerificationIsPinned(t *testing.T) {
	// The base point: y = 4/5, x even.
	byy := new(big.Int).Mod(new(big.Int).Mul(big.NewInt(4),
		new(big.Int).ModInverse(big.NewInt(5), tp)), tp)
	bx, ok := tRecoverX(byy, 0)
	if !ok {
		t.Fatal("the base point's y named no curve point")
	}
	base := tPoint{bx, byy}
	if !tScalarMul(tl, base).equal(tIdentity()) {
		t.Fatal("[L]B is not the identity; the base point is wrong")
	}

	// An honest, torsion-free key whose scalar we know.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x31 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	hs := sha512.Sum512(seed)
	a := clampToScalar(hs[:32])
	var pub crypto.PubKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	pubPt, ok := tDecodeKey(pub)
	if !ok {
		t.Fatal("the honest public key did not decode")
	}
	if !tScalarMul(tl, pubPt).equal(tIdentity()) {
		t.Fatal("the honest key is not torsion-free")
	}
	msg := []byte("R must be torsion-free because the verifier is cofactorless")

	// A nonce we choose, so we know r.
	rh := sha512.Sum512([]byte("nonce for the cofactorless pin"))
	r := new(big.Int).Mod(leToInt(rh[:]), tl)
	rPt := tScalarMul(r, base)

	tested := 0
	for _, tor := range tTorsionSubgroup(t) {
		if tor.equal(tIdentity()) {
			continue
		}
		shifted := tAdd(rPt, tor)
		enc := tEncode(shifted.y, byte(shifted.x.Bit(0)))
		hh := sha512.Sum512(concat(enc[:], pub[:], msg))
		h := new(big.Int).Mod(leToInt(hh[:]), tl)
		s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(h, a)), tl)

		var sig crypto.Signature
		copy(sig[:32], enc[:])
		copy(sig[32:], leBytes(s))

		// Non-vacuity, asserted with this file's own arithmetic: a cofactored
		// verifier accepts, i.e. [8]([S]B - R' - [h]A) is the identity, while
		// the cofactorless residual [S]B - R' - [h]A is not.
		resid := tAdd(tScalarMul(s, base),
			tNeg(tAdd(shifted, tScalarMul(h, pubPt))))
		if resid.equal(tIdentity()) {
			t.Fatalf("the crafted signature satisfies cofactorless verification too; "+
				"the construction is wrong and the test would assert nothing (T = %s)",
				tor.y.String())
		}
		eight := tAdd(tAdd(resid, resid), tAdd(resid, resid))
		eight = tAdd(eight, eight)
		if !eight.equal(tIdentity()) {
			t.Fatalf("a cofactored verifier would reject the crafted signature; "+
				"the construction is wrong (T = %s)", tor.y.String())
		}
		tested++

		// The pin. This is not a statement about VerifyStrict — it is a
		// statement about crypto/ed25519, which is where the property that
		// makes VerifyStrict's missing R-torsion check sound actually lives.
		if ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:]) {
			t.Fatalf("crypto/ed25519 accepted a signature whose R carries a torsion "+
				"component (T = %s). Go's verifier is no longer cofactorless, so "+
				"VerifyStrict's argument for not testing [L]R no longer holds: it must "+
				"start rejecting R that is not torsion-free, or an R carrying torsion "+
				"becomes id-malleability under a valid authorization again.", tor.y.String())
		}
		if crypto.VerifyStrict(pub, msg, sig) {
			t.Errorf("VerifyStrict accepted an R with a torsion component (T = %s)",
				tor.y.String())
		}
	}
	if tested != 7 {
		t.Fatalf("built %d crafted signatures, want 7", tested)
	}

	// The honest signature under the same key must still verify, so a verifier
	// that rejected everything could not pass this test.
	var good crypto.Signature
	copy(good[:], ed25519.Sign(priv, msg))
	if !crypto.VerifyStrict(pub, msg, good) {
		t.Fatal("an honest signature stopped verifying")
	}
}

func tNeg(p tPoint) tPoint {
	if p.x.Sign() == 0 {
		return tPoint{new(big.Int), new(big.Int).Set(p.y)}
	}
	return tPoint{new(big.Int).Sub(tp, p.x), new(big.Int).Set(p.y)}
}

func concat(parts ...[]byte) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		b.Write(p)
	}
	return b.Bytes()
}

// clampToScalar applies RFC 8032's clamping to the first half of the seed hash
// and reads it as a little-endian integer.
func clampToScalar(b []byte) *big.Int {
	var c [32]byte
	copy(c[:], b)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return leToInt(c[:])
}

func leToInt(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(rev)
}

func leBytes(v *big.Int) []byte {
	b := v.Bytes()
	out := make([]byte, 32)
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}
