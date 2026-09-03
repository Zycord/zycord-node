package u256

import (
	"math/big"
	"math/rand"
	"testing"
)

func toBig(u U256) *big.Int {
	b := u.Bytes()
	return new(big.Int).SetBytes(b[:])
}

func fromBig(v *big.Int) U256 {
	var b [32]byte
	v.FillBytes(b[:])
	return FromBytes(b)
}

var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

// randU256 draws a value biased towards the interesting parts of the range:
// zero, small, near the limb boundaries, and near 2^256.
func randU256(rng *rand.Rand) U256 {
	switch rng.Intn(6) {
	case 0:
		return Zero
	case 1:
		return One
	case 2:
		return Max
	case 3:
		return FromUint64(rng.Uint64())
	case 4:
		v := new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(256)))
		v.Sub(v, big.NewInt(int64(rng.Intn(3))))
		v.Mod(v, two256)
		return fromBig(v)
	default:
		var b [32]byte
		rng.Read(b[:])
		return FromBytes(b)
	}
}

// TestArithmeticAgreesWithBigInt is the differential test for the arithmetic
// the fold depends on. A wrapped add here is a minted coin on chain.
func TestArithmeticAgreesWithBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		a, b := randU256(rng), randU256(rng)
		ba, bb := toBig(a), toBig(b)

		sum, overflow := a.Add(b)
		want := new(big.Int).Add(ba, bb)
		if overflow != (want.Cmp(two256) >= 0) {
			t.Fatalf("Add(%s,%s): overflow = %v", a.String(), b.String(), overflow)
		}
		if got := toBig(sum); got.Cmp(new(big.Int).Mod(want, two256)) != 0 {
			t.Fatalf("Add(%s,%s) = %s", a.String(), b.String(), sum.String())
		}

		diff, underflow := a.Sub(b)
		wantDiff := new(big.Int).Sub(ba, bb)
		if underflow != (wantDiff.Sign() < 0) {
			t.Fatalf("Sub(%s,%s): underflow = %v", a.String(), b.String(), underflow)
		}
		if got := toBig(diff); got.Cmp(new(big.Int).Mod(wantDiff, two256)) != 0 {
			t.Fatalf("Sub(%s,%s) = %s", a.String(), b.String(), diff.String())
		}

		prod, prodOverflow := a.Mul(b)
		wantProd := new(big.Int).Mul(ba, bb)
		if prodOverflow != (wantProd.Cmp(two256) >= 0) {
			t.Fatalf("Mul(%s,%s): overflow = %v", a.String(), b.String(), prodOverflow)
		}
		if got := toBig(prod); got.Cmp(new(big.Int).Mod(wantProd, two256)) != 0 {
			t.Fatalf("Mul(%s,%s) = %s", a.String(), b.String(), prod.String())
		}

		if cmp, wantCmp := a.Cmp(b), ba.Cmp(bb); cmp != wantCmp {
			t.Fatalf("Cmp(%s,%s) = %d, want %d", a.String(), b.String(), cmp, wantCmp)
		}
	}
}

func TestDivisionAgreesWithBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 20000; i++ {
		a := randU256(rng)
		d := rng.Uint64()
		if d == 0 {
			d = 1
		}
		q, r := a.Div64(d)
		wantQ, wantR := new(big.Int).QuoRem(toBig(a), new(big.Int).SetUint64(d), new(big.Int))
		if toBig(q).Cmp(wantQ) != 0 || new(big.Int).SetUint64(r).Cmp(wantR) != 0 {
			t.Fatalf("Div64(%s,%d) = (%s,%d)", a.String(), d, q.String(), r)
		}
	}
}

func TestMulDiv64AgreesWithBigInt(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 20000; i++ {
		a := randU256(rng)
		m, d := rng.Uint64(), rng.Uint64()
		if d == 0 {
			d = 1
		}
		got := a.MulDiv64(m, d)
		want := new(big.Int).Quo(new(big.Int).Mul(toBig(a), new(big.Int).SetUint64(m)), new(big.Int).SetUint64(d))
		if want.Cmp(two256) >= 0 {
			if got.Cmp(Max) != 0 {
				t.Fatalf("MulDiv64(%s,%d,%d) did not saturate", a.String(), m, d)
			}
			continue
		}
		if toBig(got).Cmp(want) != 0 {
			t.Fatalf("MulDiv64(%s,%d,%d) = %s, want %s", a.String(), m, d, got.String(), want.String())
		}
	}
}

// TestBytesRoundTrip pins the canonical wire form: big-endian, fixed width,
// one encoding per value.
func TestBytesRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < 5000; i++ {
		a := randU256(rng)
		if FromBytes(a.Bytes()) != a {
			t.Fatalf("round trip failed for %s", a.String())
		}
	}
}

// TestDecimalIsCanonical: exactly one textual form per value. The golden
// vectors are JSON, and a value with two spellings is a vector with two hashes.
func TestDecimalIsCanonical(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 5000; i++ {
		a := randU256(rng)
		back, err := FromDecimal(a.String())
		if err != nil {
			t.Fatalf("FromDecimal(%q): %v", a.String(), err)
		}
		if back != a {
			t.Fatalf("decimal round trip failed for %s", a.String())
		}
	}
	for _, bad := range []string{"", "007", "0x10", "-1", "1 ", " 1", "1e3",
		"115792089237316195423570985008687907853269984665640564039457584007913129639936"} {
		if _, err := FromDecimal(bad); err == nil {
			t.Fatalf("FromDecimal(%q) was accepted", bad)
		}
	}
	if v, err := FromDecimal("0"); err != nil || !v.IsZero() {
		t.Fatal(`FromDecimal("0") must be zero`)
	}
}

// TestFromLEBytesReadsTheOtherEnd pins the one property that makes
// FromLEBytes worth having: it is not FromBytes, and the difference is not a
// permutation a caller could paper over.
//
// The check is deliberately stated as a byte-reversal identity rather than as
// a table of golden values. A table would pass for any implementation that
// happened to agree on the samples chosen; the identity says the whole thing
// — FromLEBytes(b) is FromBytes(reverse(b)) for every b — which is exactly
// what "the two conventions read opposite ends" means, and it is the sentence
// the consensus rule in core/pow rests on.
func TestFromLEBytesReadsTheOtherEnd(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 5000; i++ {
		var b [32]byte
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		var rev [32]byte
		for j := range b {
			rev[j] = b[31-j]
		}
		if got, want := FromLEBytes(b), FromBytes(rev); got != want {
			t.Fatalf("FromLEBytes(%x) = %s, want %s", b, got, want)
		}
	}

	// The two fixed points, spelled out because they are the cases a
	// reversal identity cannot distinguish and a reader will want to see:
	// the least significant byte is byte 0 under LE and byte 31 under BE.
	var one [32]byte
	one[0] = 1
	if got := FromLEBytes(one); !got.Eq(One) {
		t.Fatalf("FromLEBytes(01 00..) = %s, want 1", got)
	}
	var top [32]byte
	top[31] = 1
	if got, want := FromLEBytes(top), (U256{lo: [4]uint64{0, 0, 0, 1 << 56}}); got != want {
		t.Fatalf("FromLEBytes(00.. 01) = %s, want 2^248", got)
	}
}

// TestFromLEBytesRoundTripsThroughReversedCanonicalBytes: a value's LE
// encoding is its canonical big-endian encoding read backwards, so the pair
// composes back to the identity. This is what lets a caller that has to
// produce an LE digest for a test build it from Bytes() and reverse.
func TestFromLEBytesRoundTripsThroughReversedCanonicalBytes(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	for i := 0; i < 5000; i++ {
		a := randU256(rng)
		be := a.Bytes()
		var le [32]byte
		for j := range be {
			le[j] = be[31-j]
		}
		if FromLEBytes(le) != a {
			t.Fatalf("LE round trip failed for %s", a.String())
		}
	}
}
