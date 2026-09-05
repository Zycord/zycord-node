package harness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"math/big"

	"zycord/core/params"
	"zycord/core/types"
)

// The re-signing adversary.
//
// RFC 8032 verification accepts any (R, S) satisfying [S]B = R + [h(R‖A‖M)]A.
// The nonce is the signer's to choose and no verifier can tell which one was
// used, so one key has unboundedly many valid signatures over one message.
// `crypto/ed25519` will only ever emit the deterministic one, which is why
// every test in this repository that "replays a certificate" replayed *bytes*
// and none of them could reach the case where one authorization arrives twice
// under two signatures.
//
// This is that capability, in the simulator, where an adversary's tools belong.
// It is the whole apparatus the double-payment finding needed and did not have:
// one signature paying twice, which no bytes-replay fixture can express.

// ed25519Order is L, the order of the Ed25519 prime-order subgroup.
var ed25519Order, _ = new(big.Int).SetString(
	"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// ErrNotASigner reports a re-signing request naming a key that did not sign.
var ErrNotASigner = errors.New("harness: the key asked to re-sign is not among the signers")

// ErrDegenerateNonce reports a nonce that reproduced the deterministic
// signature, which would make the caller's fixture assert nothing.
var ErrDegenerateNonce = errors.New("harness: re-signing reproduced the deterministic signature")

// ReSign returns a valid Ed25519 signature by seed's key over message,
// produced at the caller's nonce rather than at RFC 8032's deterministic one.
//
// The nonce point [r]B is obtained by asking crypto/ed25519 for the public key
// of nonceSeed — which is [clamp(SHA-512(nonceSeed)[:32])]B — so the scalar r
// is known and this function needs no scalar multiplication of its own. The
// rest is the signature equation over math/big.
//
// The result is verified against crypto/ed25519 before it is returned. A
// scenario fed a signature the network would reject proves nothing at all, and
// a hand-rolled one is exactly where that goes wrong silently.
func ReSign(seed, nonceSeed, message []byte) (types.SigBytes, error) {
	var sig types.SigBytes
	if len(seed) != ed25519.SeedSize || len(nonceSeed) != ed25519.SeedSize {
		return sig, errors.New("harness: seeds must be 32 bytes")
	}

	a := clampedScalar(seed)
	var pub [32]byte
	copy(pub[:], ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	r := clampedScalar(nonceSeed)
	var rPoint [32]byte
	copy(rPoint[:], ed25519.NewKeyFromSeed(nonceSeed).Public().(ed25519.PublicKey))

	digest := sha512.New()
	digest.Write(rPoint[:])
	digest.Write(pub[:])
	digest.Write(message)
	h := new(big.Int).Mod(leToBig(digest.Sum(nil)), ed25519Order)

	s := new(big.Int).Mul(h, a)
	s.Add(s, r)
	s.Mod(s, ed25519Order)

	copy(sig[:32], rPoint[:])
	sLE := leBytes32(s)
	copy(sig[32:], sLE[:])

	if !ed25519.Verify(pub[:], message, sig[:]) {
		return types.SigBytes{}, errors.New("harness: the re-signed signature does not verify")
	}
	if bytes.Equal(sig[:], ed25519.Sign(ed25519.NewKeyFromSeed(seed), message)) {
		return types.SigBytes{}, ErrDegenerateNonce
	}
	return sig, nil
}

// ReSignCertificate returns a copy of c in which the signature contributed by
// seed's key is replaced by a different valid one over the same body.
//
// Every other signer's bytes are carried across untouched, which is the shape
// that makes the double-payment theft rather than self-harm: a co-signer mints
// a second encoding of an authorization the other parties gave once, and their
// authority rides along inside it.
func ReSignCertificate(c *types.Certificate, p *params.Params, seed []byte, nonce byte) (*types.Certificate, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("harness: seed must be 32 bytes")
	}
	var pub types.PubKey
	copy(pub[:], ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	nonceSeed := make([]byte, ed25519.SeedSize)
	for i := range nonceSeed {
		nonceSeed[i] = nonce
	}

	out := *c
	out.Sigs = append([]types.Sig(nil), c.Sigs...)

	found := false
	for i := range out.Sigs {
		if out.Sigs[i].PubKey != pub {
			continue
		}
		sig, err := ReSign(seed, nonceSeed, c.SigningMessage(p))
		if err != nil {
			return nil, err
		}
		out.Sigs[i].Sig = sig
		found = true
	}
	if !found {
		return nil, ErrNotASigner
	}
	return &out, nil
}

// clampedScalar is RFC 8032's secret scalar for a seed: the low half of
// SHA-512(seed), clamped, read little-endian.
func clampedScalar(seed []byte) *big.Int {
	h := sha512.Sum512(seed)
	s := h[:32]
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return leToBig(s)
}

func leToBig(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(rev)
}

func leBytes32(x *big.Int) [32]byte {
	var out [32]byte
	be := x.Bytes()
	for i := range be {
		out[i] = be[len(be)-1-i]
	}
	return out
}
