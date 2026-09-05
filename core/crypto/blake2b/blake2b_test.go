package blake2b

import (
	"encoding/hex"
	"testing"
)

// Every constant in this file came from OUTSIDE this repository, and that is
// the whole point of it. A vector produced by the implementation it is meant to
// check restates the code in hexadecimal and proves nothing — the failure this
// tree has already paid for twice.
//
// Sources, in order of what they bind:
//
//   - The published BLAKE2b-256 digests of the empty string and "abc" are the
//     standard vectors for this configuration (unkeyed, 32-byte output), which
//     is the configuration RandomX's commitment uses and the only one this
//     package implements.
//   - The block-boundary digests were taken from a SECOND, independent BLAKE2b
//     implementation (CPython's hashlib, which wraps the reference C code) over
//     inputs chosen to straddle the boundary this implementation is most likely
//     to get wrong. They are not upstream "vectors" in the standards sense and
//     are labelled as such below.
//   - TestTheRandomXCommitmentVector is the one that matters for consensus. It
//     is tevador's own, and §"Why this is the anchor" says why it is stronger
//     than the rest put together.

func hexOf(b [Size]byte) string { return hex.EncodeToString(b[:]) }

// TestPublishedVectors pins the two digests every BLAKE2b-256 implementation
// publishes.
func TestPublishedVectors(t *testing.T) {
	for _, v := range []struct{ in, want string }{
		{"", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{"abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
	} {
		if got := hexOf(Sum256([]byte(v.in))); got != v.want {
			t.Errorf("Sum256(%q):\n got  %s\n want %s", v.in, got, v.want)
		}
	}
}

// TestBlockBoundaries is the off-by-one guard, and it is written as a table of
// lengths around 128 rather than as one long input because the mistake this
// catches is length-specific rather than content-specific.
//
// BLAKE2b's finalisation flag belongs to the LAST compression. An input of
// exactly 128 bytes must therefore compress once, with the flag set — not
// twice, with a padded empty final block. The natural `for len(p) >= BlockSize`
// loop does the second thing and produces a stable, plausible, wrong digest for
// every exact multiple of 128, which is a class of input a "hash a few strings"
// test never reaches. 127, 128, 129 and 256 bracket both boundaries.
//
// The expected values are from an independent implementation (CPython hashlib
// over the reference C), not from this one.
func TestBlockBoundaries(t *testing.T) {
	seq := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 256)
		}
		return b
	}
	for _, v := range []struct {
		n    int
		want string
	}{
		{127, "f2fe67ff342e21b8f45e8f2e0bcd1d9243245d50ee6c78042e9c491388791c72"},
		{128, "c3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1"},
		{129, "f7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9"},
		{256, "39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835"},
	} {
		if got := hexOf(Sum256(seq(v.n))); got != v.want {
			t.Errorf("Sum256(%d bytes):\n got  %s\n want %s", v.n, got, v.want)
		}
	}
}

// TestTheRandomXCommitmentVector is the anchor this package exists to satisfy.
//
// # Why this is the anchor
//
// The vectors above say "this is BLAKE2b-256". This one says "this computes
// the number a stock rx/2 miner filters its shares on", which is a strictly
// stronger claim and the only one consensus depends on. It binds three things
// at once that the others bind separately or not at all: the function, the
// concatenation order (`input ‖ H`, not `H ‖ input`), and the fact that the
// commitment is UNKEYED BLAKE2b rather than the keyed mode BLAKE2b is equally
// famous for.
//
// # Where it came from
//
// tevador/RandomX v2.0.1 (commit aaafe71322df6602c21a5c72937ac284724ae561),
// src/tests/tests.cpp, the test named "Commitment test":
//
//	calcStringCommitment("test key 000", "This is a test", &hash);
//	assert(equalsHex(hash, "133be717399046b03ae82ce8ddd9d1ee4d3ea7fca03a50dec09b6848cbb98e18"));
//
// where calcStringCommitment is
//
//	randomx_calculate_hash(vm, input, H - 1, output);          // v2 VM
//	randomx_calculate_commitment(input, H - 1, output, output);
//
// and the VM is created with RANDOMX_FLAG_V2. The intermediate H —
// 22ec6b86… — is upstream's own published rx/2 digest for the same
// (key, input) pair, asserted separately in that file's `test_a` under the
// v2 flag.
//
// So this test takes upstream's H as GIVEN and checks only the commitment
// step, which is the half that lives in this package. The other half — that
// this tree's engine actually produces that H — is checked in
// core/pow/randomx, against the same upstream constant. Splitting them is
// deliberate: this test needs no cgo and runs in every build, so a commitment
// regression is caught by `go test ./core/...` rather than only under the
// randomx tag.
func TestTheRandomXCommitmentVector(t *testing.T) {
	const (
		input = "This is a test"
		hHex  = "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f"
		want  = "133be717399046b03ae82ce8ddd9d1ee4d3ea7fca03a50dec09b6848cbb98e18"
	)
	h, err := hex.DecodeString(hHex)
	if err != nil {
		t.Fatal(err)
	}
	got := hexOf(Sum256(append([]byte(input), h...)))
	if got != want {
		t.Fatalf("commitment over upstream's own rx/2 hash:\n got  %s\n want %s\n"+
			"this is the number a stock rx/2 miner compares against the job target; "+
			"a chain computing anything else refuses every share it should accept",
			got, want)
	}
}

// TestOrderMatters guards the concatenation direction, which is the one part of
// the commitment definition a reader is most likely to reconstruct backwards
// and which no amount of BLAKE2b conformance would catch.
func TestOrderMatters(t *testing.T) {
	h, _ := hex.DecodeString("22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f")
	in := []byte("This is a test")
	forward := Sum256(append(append([]byte{}, in...), h...))
	reverse := Sum256(append(append([]byte{}, h...), in...))
	if forward == reverse {
		t.Fatal("input‖H and H‖input hash the same, which is impossible; the test is broken")
	}
}
