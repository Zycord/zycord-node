package u256

import (
	"encoding/json"
	"errors"
	"math/bits"
)

// ErrRange reports a decimal literal that does not fit in 256 bits.
var ErrRange = errors.New("u256: value out of range")

// ErrSyntax reports a malformed decimal literal.
var ErrSyntax = errors.New("u256: invalid decimal literal")

// FromDecimal parses an unsigned decimal literal. Leading zeros are rejected
// (except for "0" itself) so that every value has exactly one textual form —
// the golden vectors depend on that.
func FromDecimal(s string) (U256, error) {
	if s == "" {
		return Zero, ErrSyntax
	}
	if len(s) > 1 && s[0] == '0' {
		return Zero, ErrSyntax
	}
	var acc U256
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return Zero, ErrSyntax
		}
		var overflow bool
		acc, overflow = acc.Mul(FromUint64(10))
		if overflow {
			return Zero, ErrRange
		}
		acc, overflow = acc.Add(FromUint64(uint64(c - '0')))
		if overflow {
			return Zero, ErrRange
		}
	}
	return acc, nil
}

// MustFromDecimal is FromDecimal for compile-time constants in tests and
// generators. It panics on bad input, which is always a bug in this repository
// rather than untrusted data.
func MustFromDecimal(s string) U256 {
	v, err := FromDecimal(s)
	if err != nil {
		panic(err)
	}
	return v
}

// Div64 divides by a 64-bit divisor, returning quotient and remainder. It
// panics on a zero divisor: consensus code divides only by non-zero protocol
// constants and by gas targets, both of which are validated at load time.
func (u U256) Div64(d uint64) (U256, uint64) {
	if d == 0 {
		panic("u256: division by zero")
	}
	return u.divmodSmall(d)
}

// MulDiv64 computes u*m/d without intermediate 256-bit overflow, saturating at
// Max if the true quotient does not fit. Fee-market updates use it: the result
// must be deterministic on every node, and saturation is deterministic while
// wrapping is a consensus split.
func (u U256) MulDiv64(m, d uint64) U256 {
	if d == 0 {
		panic("u256: division by zero")
	}
	// 256 x 64 -> 320 bits, kept in five limbs, then divided by d.
	var wide [5]uint64
	var carry uint64
	for i := 0; i < 4; i++ {
		hi, lo := bits.Mul64(u.lo[i], m)
		var c uint64
		lo, c = bits.Add64(lo, carry, 0)
		hi += c
		wide[i] = lo
		carry = hi
	}
	wide[4] = carry

	// Long division from the most significant limb down. The running
	// remainder is always < d, which is exactly bits.Div64's precondition.
	var q [5]uint64
	var rem uint64
	for i := 4; i >= 0; i-- {
		q[i], rem = bits.Div64(rem, wide[i], d)
	}
	if q[4] != 0 {
		return Max
	}
	return U256{lo: [4]uint64{q[0], q[1], q[2], q[3]}}
}

// SatAdd returns u+v, saturating at Max instead of wrapping.
func (u U256) SatAdd(v U256) U256 {
	r, overflow := u.Add(v)
	if overflow {
		return Max
	}
	return r
}

// SatSub returns u-v, saturating at zero instead of wrapping.
func (u U256) SatSub(v U256) U256 {
	r, underflow := u.Sub(v)
	if underflow {
		return Zero
	}
	return r
}

// MinOf returns the smaller of a and b.
func MinOf(a, b U256) U256 {
	if a.Lt(b) {
		return a
	}
	return b
}

// MaxOf returns the larger of a and b.
func MaxOf(a, b U256) U256 {
	if a.Gt(b) {
		return a
	}
	return b
}

// MarshalJSON encodes the value as a decimal string. Numbers are avoided
// because JSON numbers are IEEE-754 doubles in most parsers, and a fee that
// rounds is a consensus failure.
func (u U256) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON parses a decimal string.
func (u *U256) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := FromDecimal(s)
	if err != nil {
		return err
	}
	*u = v
	return nil
}
