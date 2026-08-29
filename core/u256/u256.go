// Package u256 implements the unsigned 256-bit integer arithmetic used for
// every cell value in Zycord.
//
// Consensus code must never silently wrap: an arithmetic result that leaves
// [0, 2^256) is a SKIPPED_OVERFLOW outcome in the fold (F7), not a wrapped
// number. Every operation in this package therefore returns an explicit
// overflow/underflow flag and never panics.
//
// The representation is four little-endian 64-bit limbs. The canonical
// external form is 32 big-endian bytes, which is also the on-wire form of a
// cell value.
package u256

import (
	"math/bits"
	"strconv"
)

// U256 is an unsigned 256-bit integer. The zero value is 0.
//
// Limbs are little-endian: lo[0] is the least significant 64 bits.
type U256 struct {
	lo [4]uint64
}

// Zero is the additive identity.
var Zero = U256{}

// One is the multiplicative identity.
var One = U256{lo: [4]uint64{1, 0, 0, 0}}

// Max is 2^256 - 1.
var Max = U256{lo: [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}}

// FromUint64 lifts a 64-bit value.
func FromUint64(v uint64) U256 {
	return U256{lo: [4]uint64{v, 0, 0, 0}}
}

// FromBytes interprets b as a big-endian 256-bit integer.
func FromBytes(b [32]byte) U256 {
	var u U256
	for i := 0; i < 4; i++ {
		off := 24 - i*8
		u.lo[i] = uint64(b[off])<<56 | uint64(b[off+1])<<48 | uint64(b[off+2])<<40 |
			uint64(b[off+3])<<32 | uint64(b[off+4])<<24 | uint64(b[off+5])<<16 |
			uint64(b[off+6])<<8 | uint64(b[off+7])
	}
	return u
}

// Bytes returns the canonical big-endian 32-byte encoding.
func (u U256) Bytes() [32]byte {
	var b [32]byte
	for i := 0; i < 4; i++ {
		off := 24 - i*8
		v := u.lo[i]
		b[off] = byte(v >> 56)
		b[off+1] = byte(v >> 48)
		b[off+2] = byte(v >> 40)
		b[off+3] = byte(v >> 32)
		b[off+4] = byte(v >> 24)
		b[off+5] = byte(v >> 16)
		b[off+6] = byte(v >> 8)
		b[off+7] = byte(v)
	}
	return b
}

// IsZero reports whether u == 0.
func (u U256) IsZero() bool {
	return u.lo[0]|u.lo[1]|u.lo[2]|u.lo[3] == 0
}

// Uint64 returns the low 64 bits and whether the value fits in 64 bits.
func (u U256) Uint64() (uint64, bool) {
	return u.lo[0], u.lo[1]|u.lo[2]|u.lo[3] == 0
}

// Cmp returns -1, 0 or +1 as u is less than, equal to, or greater than v.
func (u U256) Cmp(v U256) int {
	for i := 3; i >= 0; i-- {
		if u.lo[i] != v.lo[i] {
			if u.lo[i] < v.lo[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Eq reports whether u == v.
func (u U256) Eq(v U256) bool { return u.Cmp(v) == 0 }

// Lt reports whether u < v.
func (u U256) Lt(v U256) bool { return u.Cmp(v) < 0 }

// Gt reports whether u > v.
func (u U256) Gt(v U256) bool { return u.Cmp(v) > 0 }

// Gte reports whether u >= v.
func (u U256) Gte(v U256) bool { return u.Cmp(v) >= 0 }

// Add returns u+v and whether the addition overflowed 2^256.
func (u U256) Add(v U256) (U256, bool) {
	var r U256
	var carry uint64
	for i := 0; i < 4; i++ {
		r.lo[i], carry = bits.Add64(u.lo[i], v.lo[i], carry)
	}
	return r, carry != 0
}

// Sub returns u-v and whether the subtraction underflowed below zero.
func (u U256) Sub(v U256) (U256, bool) {
	var r U256
	var borrow uint64
	for i := 0; i < 4; i++ {
		r.lo[i], borrow = bits.Sub64(u.lo[i], v.lo[i], borrow)
	}
	return r, borrow != 0
}

// Mul returns u*v and whether the product overflowed 2^256.
//
// Used for gas * price, where the overflow flag is a validity failure rather
// than a wrapped fee.
func (u U256) Mul(v U256) (U256, bool) {
	// Schoolbook 4x4 -> 8 limbs. Iteration i writes r[i..i+3] through the
	// inner loop and r[i+4] from the final carry; r[i+4] is provably still
	// zero at that point, so no accumulation can overflow.
	var r [8]uint64
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(u.lo[i], v.lo[j])
			var c uint64
			lo, c = bits.Add64(lo, carry, 0)
			hi += c // hi <= 2^64-2 before this add, so it cannot wrap
			r[i+j], c = bits.Add64(r[i+j], lo, 0)
			hi += c
			carry = hi
		}
		r[i+4] = carry
	}
	out := U256{lo: [4]uint64{r[0], r[1], r[2], r[3]}}
	overflow := r[4]|r[5]|r[6]|r[7] != 0
	return out, overflow
}

// String renders the value in decimal, unpadded.
//
// This is the canonical textual form of a U256 in this project, not a
// human-facing convenience: MarshalJSON encodes through it, so it is what
// spec/params*.json and the golden vectors carry, and decimal.go's comment has
// the reason it is a string at all. There is no hex form in this package — this
// comment used to open by describing a 0x-prefixed, zero-padded `Hex` that no
// caller can reach, so a reader looking for the encoder's choice should stop
// here rather than go looking for it.
func (u U256) String() string {
	if u.IsZero() {
		return "0"
	}
	if v, ok := u.Uint64(); ok {
		return strconv.FormatUint(v, 10)
	}
	// Repeated division by 10^19 (the largest power of ten below 2^64).
	const chunk = 10_000_000_000_000_000_000
	var parts []string
	cur := u
	for !cur.IsZero() {
		q, r := cur.divmodSmall(chunk)
		cur = q
		if cur.IsZero() {
			parts = append(parts, strconv.FormatUint(r, 10))
		} else {
			s := strconv.FormatUint(r, 10)
			for len(s) < 19 {
				s = "0" + s
			}
			parts = append(parts, s)
		}
	}
	out := ""
	for i := len(parts) - 1; i >= 0; i-- {
		out += parts[i]
	}
	return out
}

// divmodSmall divides u by a 64-bit divisor, returning quotient and remainder.
func (u U256) divmodSmall(d uint64) (U256, uint64) {
	var q U256
	var rem uint64
	for i := 3; i >= 0; i-- {
		q.lo[i], rem = bits.Div64(rem, u.lo[i], d)
	}
	return q, rem
}
