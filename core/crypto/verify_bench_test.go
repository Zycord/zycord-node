package crypto_test

// The cost of strictness, on the two paths that matter.
//
// The valid path is what an honest node pays. The *invalid* path is what an
// attacker chooses, and it is the one a cost claim usually forgets: signature
// verification is reachable from unauthenticated gossip, so the cheapest
// rejection is the price of a byte of noise. These benchmarks are here so that
// both numbers exist, and so that a future change that moves an expensive check
// ahead of a cheap one is visible rather than inferred.

import (
	"crypto/ed25519"
	"testing"

	"zycord/core/crypto"
)

func benchInputs(b *testing.B) (crypto.PubKey, []byte, crypto.Signature) {
	b.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var pub crypto.PubKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	msg := []byte("a certificate's signing message is 32 bytes of blake3")
	var sig crypto.Signature
	copy(sig[:], ed25519.Sign(priv, msg))
	return pub, msg, sig
}

// BenchmarkStdVerify is the baseline every other number here is a ratio of.
func BenchmarkStdVerify(b *testing.B) {
	pub, msg, sig := benchInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:]) {
			b.Fatal("baseline signature did not verify")
		}
	}
}

// BenchmarkStdVerifyGarbageKey is the baseline for the cheapest rejection: the
// standard library refuses an undecompressable key without doing the equation.
func BenchmarkStdVerifyGarbageKey(b *testing.B) {
	_, msg, sig := benchInputs(b)
	var pub crypto.PubKey
	for i := range pub {
		pub[i] = byte(0x5a + i)
	}
	pub[0] = 0x00
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:])
	}
}

// BenchmarkVerifyStrictValid is the honest path: it pays for the torsion test.
func BenchmarkVerifyStrictValid(b *testing.B) {
	pub, msg, sig := benchInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !crypto.VerifyStrict(pub, msg, sig) {
			b.Fatal("valid signature did not verify")
		}
	}
}

// BenchmarkVerifyStrictGarbageKey is the attacker's cheapest input: 32 bytes
// whose y is on no curve point at all, so decompression fails. This is the path
// a flood takes, and it must cost about what ed25519.Verify costs on the same
// bytes — if it starts costing a modexp, the byte-level canonicality prefilter
// has been bypassed or reordered behind the decoder again.
func BenchmarkVerifyStrictGarbageKey(b *testing.B) {
	_, msg, sig := benchInputs(b)
	var pub crypto.PubKey
	for i := range pub {
		pub[i] = byte(0x5a + i)
	}
	pub[0] = 0x00 // makes y a value with no square root; decompression fails
	if crypto.VerifyStrict(pub, msg, sig) {
		b.Fatal("garbage key verified")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifyStrict(pub, msg, sig)
	}
}

// BenchmarkVerifyStrictBadSig is a well-formed key and R with a corrupt scalar:
// the equation refuses it, and no torsion test is ever run.
func BenchmarkVerifyStrictBadSig(b *testing.B) {
	pub, msg, sig := benchInputs(b)
	sig[40] ^= 0xff
	if crypto.VerifyStrict(pub, msg, sig) {
		b.Fatal("corrupt signature verified")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifyStrict(pub, msg, sig)
	}
}

// BenchmarkVerifyStrictNonCanonical is the rule this PR added: an unreduced y.
// It is refused by byte comparisons alone.
func BenchmarkVerifyStrictNonCanonical(b *testing.B) {
	_, msg, sig := benchInputs(b)
	var pub crypto.PubKey
	pub[0] = 0xee
	for i := 1; i < 32; i++ {
		pub[i] = 0xff
	}
	if crypto.VerifyStrict(pub, msg, sig) {
		b.Fatal("a non-canonical key verified")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifyStrict(pub, msg, sig)
	}
}
