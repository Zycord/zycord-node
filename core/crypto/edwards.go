package crypto

// Just enough edwards25519 to make the strictness rules of VerifyStrict
// *computed* rather than looked up in a table a human has to remember to
// update. Nothing here signs, and nothing here needs to be constant time: every
// value it touches — a public key, a signature's R — is public by the time it
// arrives, and a certificate's bytes are chosen by whoever built it anyway.
//
// The arithmetic is `math/big` rather than a packed radix-2^51 field. That is a
// deliberate trade: `core/` may import nothing outside the standard library
// (CONTRIBUTING), so a fast field would have to be written here from scratch,
// and a hand-rolled field is exactly the kind of code whose bugs stay invisible
// until they are consensus-splitting. What is optimised is the one thing that
// can be optimised without that risk: reduction modulo p is done by folding on
// 2^255 = 19 rather than by division, and doubling uses the dedicated formula.
// The residual cost is measured in the PR; it is real, and it buys a check that
// no table can express.
//
// The addition law below is the unified twisted-Edwards law for a = -1. It is
// *complete* on this curve — no exceptional cases, no special path for the
// identity — because a = -1 is a square modulo p and d is not (Bernstein–Lange).
// That matters more here than in a signing implementation, because the points
// this file is asked about are precisely the awkward ones: the identity, the
// 2-, 4- and 8-torsion, and mixed-order points. A formula with exceptions at
// the identity would be wrong in the exact places this file exists to inspect.

import "math/big"

var (
	// fieldP is 2^255 - 19.
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// mask255 is 2^255 - 1, the low half of a fold step.
	mask255 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))

	big19 = big.NewInt(19)

	// twoP is 2p, added before a subtraction so that intermediate values never
	// go negative and the reduction can assume a non-negative input.
	twoP = new(big.Int).Lsh(fieldP, 1)

	// curveD is -121665/121666 mod p.
	curveD = func() *big.Int {
		num := new(big.Int).Neg(big.NewInt(121665))
		den := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		return num.Mod(num.Mul(num, den), fieldP)
	}()

	// curveD2 is 2d, the constant the addition law actually uses.
	curveD2 = new(big.Int).Mod(new(big.Int).Lsh(curveD, 1), fieldP)

	// sqrtM1 is 2^((p-1)/4), a square root of -1 mod p.
	sqrtM1 = func() *big.Int {
		e := new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 2)
		return new(big.Int).Exp(big.NewInt(2), e, fieldP)
	}()

	// groupL is the order of the prime-order subgroup,
	// 2^252 + 27742317777372353535851937790883648493.
	groupL = func() *big.Int {
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return l
	}()
)

// reduce brings a non-negative z below p by folding the bits above 2^255 back
// in with the identity 2^255 ≡ 19 (mod p). No division, and it terminates in at
// most three folds for any product of two reduced field elements.
func reduce(z, scratch *big.Int) {
	for z.BitLen() > 255 {
		scratch.Rsh(z, 255)
		z.And(z, mask255)
		scratch.Mul(scratch, big19)
		z.Add(z, scratch)
	}
	for z.Cmp(fieldP) >= 0 {
		z.Sub(z, fieldP)
	}
}

// edPoint is a curve point in extended coordinates (X:Y:Z:T), with x = X/Z,
// y = Y/Z and X*Y = Z*T.
type edPoint struct {
	x, y, z, t big.Int
}

func (p *edPoint) setIdentity() *edPoint {
	p.x.SetInt64(0)
	p.y.SetInt64(1)
	p.z.SetInt64(1)
	p.t.SetInt64(0)
	return p
}

func (p *edPoint) set(q *edPoint) *edPoint {
	p.x.Set(&q.x)
	p.y.Set(&q.y)
	p.z.Set(&q.z)
	p.t.Set(&q.t)
	return p
}

// isIdentity reports whether the point is the neutral element: x = 0, y = 1.
func (p *edPoint) isIdentity() bool {
	if p.x.Sign() != 0 {
		return false
	}
	return p.y.Cmp(&p.z) == 0
}

// edScratch holds the temporaries of the point operations. It exists so that a
// scalar multiplication allocates once instead of once per limb operation, and
// so that nothing in this file needs a package-level mutable value — signature
// verification runs on several goroutines at once in node/verify.
type edScratch struct {
	a, b, c, d, e, f, g, h, t0, t1, t2 big.Int
}

func (s *edScratch) mul(dst, x, y *big.Int) {
	dst.Mul(x, y)
	reduce(dst, &s.t0)
}

func (s *edScratch) sqr(dst, x *big.Int) { s.mul(dst, x, x) }

// sub sets dst = x - y mod p without ever going negative.
func (s *edScratch) sub(dst, x, y *big.Int) {
	dst.Add(x, twoP)
	dst.Sub(dst, y)
	reduce(dst, &s.t1)
}

func (s *edScratch) add(dst, x, y *big.Int) {
	dst.Add(x, y)
	reduce(dst, &s.t1)
}

// addPoints sets r = p + q with the unified, complete a = -1 law.
func (s *edScratch) addPoints(r, p, q *edPoint) {
	s.sub(&s.a, &p.y, &p.x)
	s.sub(&s.t2, &q.y, &q.x)
	s.mul(&s.a, &s.a, &s.t2)

	s.add(&s.b, &p.y, &p.x)
	s.add(&s.t2, &q.y, &q.x)
	s.mul(&s.b, &s.b, &s.t2)

	s.mul(&s.c, &p.t, &q.t)
	s.mul(&s.c, &s.c, curveD2)

	s.mul(&s.d, &p.z, &q.z)
	s.add(&s.d, &s.d, &s.d)

	s.sub(&s.e, &s.b, &s.a)
	s.sub(&s.f, &s.d, &s.c)
	s.add(&s.g, &s.d, &s.c)
	s.add(&s.h, &s.b, &s.a)

	s.mul(&r.x, &s.e, &s.f)
	s.mul(&r.y, &s.g, &s.h)
	s.mul(&r.t, &s.e, &s.h)
	s.mul(&r.z, &s.f, &s.g)
}

// double sets r = 2p with the dedicated formula, which is cheaper than the
// addition law and, in Edwards form, has no exceptional cases either.
func (s *edScratch) double(r, p *edPoint) {
	s.sqr(&s.a, &p.x)
	s.sqr(&s.b, &p.y)
	s.sqr(&s.c, &p.z)
	s.add(&s.c, &s.c, &s.c)
	// d = a*A with a = -1.
	s.sub(&s.d, fieldP, &s.a) // -A mod p

	s.add(&s.e, &p.x, &p.y)
	s.sqr(&s.e, &s.e)
	s.sub(&s.e, &s.e, &s.a)
	s.sub(&s.e, &s.e, &s.b)

	s.add(&s.g, &s.d, &s.b)
	s.sub(&s.f, &s.g, &s.c)
	s.sub(&s.h, &s.d, &s.b)

	s.mul(&r.x, &s.e, &s.f)
	s.mul(&r.y, &s.g, &s.h)
	s.mul(&r.t, &s.e, &s.h)
	s.mul(&r.z, &s.f, &s.g)
}

// scalarMul sets r = [k]q for k >= 0, with a 4-bit window. The schedule depends
// only on k, which at every call site here is a fixed public constant.
func (s *edScratch) scalarMul(r *edPoint, k *big.Int, q *edPoint) {
	var table [16]edPoint
	table[0].setIdentity()
	for i := 1; i < 16; i++ {
		s.addPoints(&table[i], &table[i-1], q)
	}

	var acc edPoint
	acc.setIdentity()
	nibbles := (k.BitLen() + 3) / 4
	for i := nibbles - 1; i >= 0; i-- {
		for j := 0; j < 4; j++ {
			s.double(&acc, &acc)
		}
		n := 0
		for b := 3; b >= 0; b-- {
			n = n<<1 | int(k.Bit(i*4+b))
		}
		if n != 0 {
			s.addPoints(&acc, &acc, &table[n])
		}
	}
	r.set(&acc)
}

// decodeStatus reports how a 32-byte compressed encoding was accepted.
type decodeStatus int

const (
	// decodeInvalid: the encoding does not name a curve point at all.
	decodeInvalid decodeStatus = iota
	// decodeNonCanonical: it names a point, but not by the one encoding that
	// point has. Either y >= p (the field element was not reduced), or x = 0
	// with the sign bit set (a sign for a coordinate that has no sign).
	decodeNonCanonical
	// decodeCanonical: the unique correct encoding of the point.
	decodeCanonical
)

func (d decodeStatus) String() string {
	switch d {
	case decodeCanonical:
		return "canonical"
	case decodeNonCanonical:
		return "non-canonical"
	default:
		return "invalid"
	}
}

// The canonicality rule, spelled in bytes.
//
// decodeEdPoint answers the same question, but it cannot answer it until it has
// computed a square root — a 252-bit modular exponentiation — so the cheapest
// possible rejection used to cost the most expensive primitive in the file.
// That is the wrong shape for a rule that is reachable from unauthenticated
// gossip: a peer sending 32 bytes of noise chooses the path, and the path
// should be the cheap one.
//
// It does not need to be expensive, because neither half of the rule needs the
// point. `y < p` is a comparison on the raw little-endian bytes. And x = 0
// happens exactly when y = 1 or y = -1 (x^2 = (y^2-1)/(dy^2+1) has a zero
// numerator only there), so "no sign bit on a zero x" is a comparison against
// two fixed encodings. Both are byte tests over the whole range, not an
// enumeration of cases — the same property that made the computed check
// replace the table in the first place.
var (
	pLE       = leEncodeField(fieldP)
	pMinus1LE = leEncodeField(new(big.Int).Sub(fieldP, big.NewInt(1)))
	oneLE     = leEncodeField(big.NewInt(1))
)

func leEncodeField(v *big.Int) [PubKeySize]byte {
	var be, le [PubKeySize]byte
	v.FillBytes(be[:])
	for i := range be {
		le[i] = be[PubKeySize-1-i]
	}
	return le
}

// isCanonicalEncoding reports whether b is the canonical spelling of the point
// it names — y < p, and no sign bit on an x that is zero — without decompressing
// it. For a well-formed 32-byte input it agrees with decodeEdPoint's
// decodeCanonical status on every value that decodes at all; for bytes that are
// not a point it says nothing, which is what its callers want, since those are
// refused by the signature equation anyway.
func isCanonicalEncoding(b []byte) bool {
	if len(b) != PubKeySize {
		return false
	}
	sign := b[PubKeySize-1] >> 7
	var y [PubKeySize]byte
	copy(y[:], b)
	y[PubKeySize-1] &= 0x7f

	// y < p, most significant byte first. Equality falls out of the loop with
	// less still false, which is correct: y = p is the first non-canonical one.
	less := false
	for i := PubKeySize - 1; i >= 0; i-- {
		if y[i] != pLE[i] {
			less = y[i] < pLE[i]
			break
		}
	}
	if !less {
		return false
	}
	if sign == 1 && (y == oneLE || y == pMinus1LE) {
		return false
	}
	return true
}

// decodeEdPoint decompresses a 32-byte little-endian y ‖ sign encoding.
//
// It decodes the two relaxations Go's own decoder documents — an unreduced y,
// and x = 0 with the sign bit set — and *reports* them rather than rejecting
// them, so a caller can tell "not a point" from "a point, spelled wrongly".
// VerifyStrict rejects both. IsSmallOrderPubKey has to answer for the
// spelled-wrongly ones too, because those are exactly the encodings some other
// verifier might accept.
func decodeEdPoint(b []byte) (*edPoint, decodeStatus) {
	if len(b) != PubKeySize {
		return nil, decodeInvalid
	}
	var le [PubKeySize]byte
	for i := range le {
		le[i] = b[PubKeySize-1-i]
	}
	sign := le[0] >> 7
	le[0] &= 0x7f
	yEnc := new(big.Int).SetBytes(le[:])

	// V2's point half, and the whole of the non-canonical-encoding defect:
	// y >= p is a second spelling of y - p, and a verifier that reduces
	// instead of rejecting is not an implementation of this rule. There
	// are 19 such values, not 2.
	canonical := yEnc.Cmp(fieldP) < 0
	y := new(big.Int).Mod(yEnc, fieldP)

	// x^2 = (y^2 - 1) / (d*y^2 + 1)
	var s edScratch
	y2 := new(big.Int)
	s.mul(y2, y, y)
	u := new(big.Int)
	s.sub(u, y2, big.NewInt(1))
	v := new(big.Int)
	s.mul(v, curveD, y2)
	s.add(v, v, big.NewInt(1))

	// x = u*v^3 * (u*v^7)^((p-5)/8), corrected by sqrt(-1) if needed.
	v3 := new(big.Int)
	s.sqr(v3, v)
	s.mul(v3, v3, v)
	v7 := new(big.Int)
	s.sqr(v7, v3)
	s.mul(v7, v7, v)
	exp := new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(5)), 3)
	x := new(big.Int)
	s.mul(x, u, v7)
	x.Exp(x, exp, fieldP)
	uv3 := new(big.Int)
	s.mul(uv3, u, v3)
	s.mul(x, x, uv3)

	check := new(big.Int)
	s.sqr(check, x)
	s.mul(check, check, v)
	negU := new(big.Int)
	s.sub(negU, fieldP, u)
	switch {
	case check.Cmp(u) == 0:
		// x is already a root.
	case check.Cmp(negU) == 0:
		s.mul(x, x, sqrtM1)
	default:
		return nil, decodeInvalid
	}

	if x.Sign() == 0 {
		// The sign bit distinguishes x from -x, and 0 = -0. An encoding that
		// sets it is naming a point that already has a shorter name.
		//
		// The negation below must be skipped in this case rather than merely
		// flagged. `x.Sub(fieldP, x)` on a zero x yields p, which is congruent
		// to 0 but is not 0, and every returned point in this file is assumed
		// to carry *reduced* coordinates — isIdentity() tests x.Sign() != 0 and
		// would answer false for the identity itself. Nothing depends on that
		// today (VerifyStrict refuses non-canonical encodings before looking at
		// the point, and the order predicates re-reduce through mul), but the
		// two encodings that reach this branch are the non-canonical identity
		// and the non-canonical order-2 point: the exact points this file
		// exists to recognise.
		if sign == 1 {
			canonical = false
		}
	} else if byte(x.Bit(0)) != sign {
		x.Sub(fieldP, x)
	}

	p := &edPoint{}
	p.x.Set(x)
	p.y.Set(y)
	p.z.SetInt64(1)
	s.mul(&p.t, x, y)

	if canonical {
		return p, decodeCanonical
	}
	return p, decodeNonCanonical
}

// isLowOrder reports whether [8]P is the identity, i.e. P lies in the 8-element
// torsion subgroup. This is the computed replacement for the byte table: the
// answer comes from the curve, so it cannot go stale or be short by an entry.
func isLowOrder(p *edPoint) bool {
	var s edScratch
	var q edPoint
	s.double(&q, p)
	s.double(&q, &q)
	s.double(&q, &q)
	return q.isIdentity()
}

// isTorsionFree reports whether [L]P is the identity, i.e. P lies in the
// prime-order subgroup and carries no torsion component.
//
// Strictly stronger than !isLowOrder: a mixed-order point A = A' + T, with A'
// of large order and T of order 8, is not low order, is caught by no blocklist
// of any finite size (there are about 2^252 of them), and is exactly where
// cofactored and cofactorless verification disagree.
func isTorsionFree(p *edPoint) bool {
	var s edScratch
	var q edPoint
	s.scalarMul(&q, groupL, p)
	return q.isIdentity()
}
