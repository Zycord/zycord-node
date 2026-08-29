package main

// The construction behind the mixed-order signer vector: a public key
// A = A' + T, with A' of large order and T of order 8, together with a
// signature that the standard library's cofactorless verifier accepts under it.
//
// # Why this arithmetic is here rather than borrowed
//
// core/crypto answers the same questions with its own extended-coordinate
// arithmetic, and every one of those helpers is unexported — deliberately, since
// nothing outside V2 has any business decompressing a point. core/crypto's own
// torsion tests carry a second, affine implementation for the same reason this
// file does: a construction that reached into the code under test would be that
// code agreeing with itself — the exact defect the torsion audit found, where a
// rule was only ever exercised by the arithmetic that implements it, so an error
// in that arithmetic would have been confirmed rather than caught. This file is
// a third such implementation, and it is small enough
// to read end to end.
//
// # What it must be, and it is not a hot path
//
// It runs once per `go run ./spec/gen`, on values that are public by
// construction, so it is affine, allocating and written for legibility. What it
// does have to be is DETERMINISTIC: a regeneration that changed a vector is a
// consensus change (spec/README.md), so every seed, every loop bound and every
// iteration order below is fixed, and the torsion subgroup is derived by a
// scan whose starting point never moves.

import (
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"

	"zycord/core/crypto"
)

var (
	// edP is 2^255 - 19, the field prime.
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// edL is the order of the prime-order subgroup.
	edL = func() *big.Int {
		l, _ := new(big.Int).SetString(
			"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return l
	}()

	// edD is -121665/121666 mod p, the curve constant.
	edD = func() *big.Int {
		n := big.NewInt(-121665)
		den := new(big.Int).ModInverse(big.NewInt(121666), edP)
		return n.Mod(n.Mul(n, den), edP)
	}()

	// edSqrtM1 is a square root of -1 mod p, used to correct the square root
	// the exponentiation below returns.
	edSqrtM1 = func() *big.Int {
		e := new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2)
		return new(big.Int).Exp(big.NewInt(2), e, edP)
	}()

	edEight = big.NewInt(8)
)

// edPt is an affine curve point.
type edPt struct{ x, y *big.Int }

func edIdentity() edPt { return edPt{big.NewInt(0), big.NewInt(1)} }

func (p edPt) equal(q edPt) bool { return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0 }

// edAdd is the affine twisted-Edwards addition law with a = -1. It is complete
// on this curve, so it needs no special case for doubling or for the identity —
// which matters here, because every point this file handles is one of the
// awkward ones.
func edAdd(p, q edPt) edPt {
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), edP) }
	x1x2 := mul(p.x, q.x)
	y1y2 := mul(p.y, q.y)
	dxy := mul(edD, mul(x1x2, y1y2))
	nx := new(big.Int).Mod(new(big.Int).Add(mul(p.x, q.y), mul(q.x, p.y)), edP)
	ny := new(big.Int).Mod(new(big.Int).Add(y1y2, x1x2), edP)
	dx := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Add(big.NewInt(1), dxy), edP), edP)
	dy := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), dxy), edP), edP)
	return edPt{mul(nx, dx), mul(ny, dy)}
}

func edScalarMul(k *big.Int, p edPt) edPt {
	acc := edIdentity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = edAdd(acc, acc)
		if k.Bit(i) == 1 {
			acc = edAdd(acc, p)
		}
	}
	return acc
}

// edRecoverX solves the curve equation for x given y, returning the root whose
// low bit is `sign`. It reports false when y names no point.
func edRecoverX(y *big.Int, sign byte) (*big.Int, bool) {
	y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), edP)
	u := new(big.Int).Mod(new(big.Int).Sub(y2, big.NewInt(1)), edP)
	v := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1)), edP)
	if v.Sign() == 0 {
		return nil, false
	}
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, edP)), edP)
	e := new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3)
	x := new(big.Int).Exp(x2, e, edP)
	if new(big.Int).Mod(new(big.Int).Mul(x, x), edP).Cmp(x2) != 0 {
		x.Mod(x.Mul(x, edSqrtM1), edP)
	}
	if new(big.Int).Mod(new(big.Int).Mul(x, x), edP).Cmp(x2) != 0 {
		return nil, false
	}
	if byte(x.Bit(0)) != sign && x.Sign() != 0 {
		x.Sub(edP, x)
	}
	return x, true
}

// edEncode compresses a point the way the wire format does: 32 little-endian
// bytes of y, with the low bit of x in the top bit. Every point this file
// encodes has y < p, so every encoding it produces is canonical — which the
// caller asserts, because a non-canonical one would be refused by a different
// V2 clause and the vector would pin that instead.
func edEncode(p edPt) crypto.PubKey {
	b := p.y.Bytes()
	var out crypto.PubKey
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	out[31] |= byte(p.x.Bit(0)) << 7
	return out
}

func edDecode(k crypto.PubKey) (edPt, bool) {
	var le [32]byte
	for i := range le {
		le[i] = k[31-i]
	}
	sign := le[0] >> 7
	le[0] &= 0x7f
	y := new(big.Int).Mod(new(big.Int).SetBytes(le[:]), edP)
	x, ok := edRecoverX(y, sign)
	if !ok {
		return edPt{}, false
	}
	return edPt{x, y}, true
}

// edTorsionSubgroup returns the eight points of order dividing 8, derived from
// the curve rather than written down: multiplying an arbitrary curve point by L
// annihilates its prime-order component and leaves the torsion behind.
func edTorsionSubgroup() []edPt {
	var gen edPt
	found := false
	for i := int64(2); i < 200 && !found; i++ {
		y := big.NewInt(i)
		x, ok := edRecoverX(y, 0)
		if !ok {
			continue
		}
		cand := edScalarMul(edL, edPt{x, y})
		four := edAdd(edAdd(cand, cand), edAdd(cand, cand))
		// Order exactly 8: [8]T = O and [4]T != O.
		if !edAdd(four, four).equal(edIdentity()) || four.equal(edIdentity()) {
			continue
		}
		gen, found = cand, true
	}
	if !found {
		panic("gen: no point of order 8 was found; this file's curve arithmetic is wrong")
	}
	pts := make([]edPt, 0, 8)
	acc := edIdentity()
	for i := 0; i < 8; i++ {
		pts = append(pts, acc)
		acc = edAdd(acc, gen)
	}
	if !acc.equal(edIdentity()) {
		panic("gen: the torsion subgroup did not close after eight elements")
	}
	return pts
}

// mixedOrderKey is a public key A = A' + T whose honest half A' the holder can
// sign under, and whose torsion half T no blocklist of any finite size can name
// — there are about 2^252 such keys.
//
// It is the shape docs/ARCHITECTURE.md §7 warns about in its own words: "a
// small-order blocklist is not a weaker version of this rule, it is a different
// and insufficient one." A verifier built as a blocklist plus a cofactored batch
// path — which is what batch verifiers normally are — accepts what this key
// signs.
type mixedOrderKey struct {
	pub      crypto.PubKey
	honest   crypto.PubKey
	scalar   *big.Int // a, with A' = [a]B
	torsion8 edPt     // T, of order exactly 8
	subgroup []edPt
}

// newMixedOrderKey builds one from a fixed seed. The seed is arbitrary and
// fixed: what matters is that the same run produces the same key, because a
// regeneration that moved a vector would read as a consensus change.
func newMixedOrderKey(seed byte) *mixedOrderKey {
	subgroup := edTorsionSubgroup()
	var order8 edPt
	for _, pt := range subgroup {
		four := edAdd(edAdd(pt, pt), edAdd(pt, pt))
		if !four.equal(edIdentity()) {
			order8 = pt
			break
		}
	}

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(raw)
	hs := sha512.Sum512(raw)
	var honest crypto.PubKey
	copy(honest[:], priv.Public().(ed25519.PublicKey))
	honestPt, ok := edDecode(honest)
	if !ok {
		panic("gen: the honest public key did not decode")
	}

	k := &mixedOrderKey{
		honest:   honest,
		scalar:   edClampToScalar(hs[:32]),
		torsion8: order8,
		subgroup: subgroup,
	}
	k.pub = edEncode(edAdd(honestPt, order8))

	// The two facts the vector's whole claim rests on, asserted at the source
	// rather than inferred from the vector later.
	if crypto.IsSmallOrderPubKey(k.pub) {
		panic("gen: the mixed-order key is small order, so a blocklist would catch it and " +
			"the vector would separate nothing a blocklist does not already separate")
	}
	if crypto.VerifyStrict(k.pub, []byte("probe"), crypto.Signature{}) {
		panic("gen: VerifyStrict accepted an empty signature")
	}
	return k
}

// forge produces a signature over msg that satisfies the cofactorless
// verification equation under the mixed key.
//
// The equation is [S]B = R + [h]A. Writing A = A' + T and R = [r]B + T_r, and
// choosing S = r + h·a mod L so that [S]B = [r]B + [h]A', what is left over is
// the torsion residue T_r + [h]T, which must vanish. h is the challenge scalar
// and depends on R's encoding, so the search is over (r, T_r) pairs: for each
// candidate nonce, the eight torsion offsets of R are tried in the subgroup's
// derived order and the first whose residue is the identity wins. The residue
// lives in an 8-element group, so roughly one offset in eight closes it — a
// grind of a handful of tries rather than a construction problem.
func (k *mixedOrderKey) forge(msg []byte) crypto.Signature {
	for n := 0; n < 512; n++ {
		rSeed := make([]byte, 32)
		rSeed[0] = byte(n)
		rSeed[1] = byte(n >> 8)
		rPriv := ed25519.NewKeyFromSeed(rSeed)
		rh := sha512.Sum512(rSeed)
		r := edClampToScalar(rh[:32])
		var rBytes crypto.PubKey
		copy(rBytes[:], rPriv.Public().(ed25519.PublicKey))
		rPt, ok := edDecode(rBytes)
		if !ok {
			continue
		}
		for _, tr := range k.subgroup {
			full := edAdd(rPt, tr)
			enc := edEncode(full)
			hh := sha512.Sum512(append(append(append([]byte{}, enc[:]...), k.pub[:]...), msg...))
			h := new(big.Int).Mod(edLeToInt(hh[:]), edL)
			resid := edAdd(tr, edScalarMul(new(big.Int).Mod(h, edEight), k.torsion8))
			if !resid.equal(edIdentity()) {
				continue
			}
			s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(h, k.scalar)), edL)
			var sig crypto.Signature
			copy(sig[:32], enc[:])
			copy(sig[32:], edLeBytes(s))
			// The direction this construction has to satisfy, checked here and
			// not left to the vector: the standard library must ACCEPT it, or
			// the vector fails for a reason that is not the torsion clause.
			if !ed25519.Verify(ed25519.PublicKey(k.pub[:]), msg, sig[:]) {
				continue
			}
			return sig
		}
	}
	panic("gen: no signature the standard library accepts under the mixed-order key was found " +
		"in 512 nonces; without one the vector would assert nothing")
}

// edClampToScalar applies RFC 8032's clamping to the first half of a seed hash
// and reads it as a little-endian integer.
func edClampToScalar(b []byte) *big.Int {
	var c [32]byte
	copy(c[:], b)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return edLeToInt(c[:])
}

func edLeToInt(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(rev)
}

func edLeBytes(v *big.Int) []byte {
	b := v.Bytes()
	out := make([]byte, 32)
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}
