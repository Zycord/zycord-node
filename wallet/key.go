// Package wallet builds and signs certificates.
//
// Nothing here is consensus. A wallet that produces a certificate the V-rules
// reject has a bug in the wallet; a wallet that produces one they accept is
// correct by definition. That asymmetry is why this package may use whatever
// it likes from the ecosystem while core/ may not.
//
// The builders exist mostly so that the reference implementation cannot cheat:
// every test in the tree constructs certificates through the same path a user
// would, and a certificate that only the test helper can build is a
// certificate nobody can send.
package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"

	"zycord/core/crypto"
	"zycord/core/types"
)

// Key is an Ed25519 signing key.
//
// A key is not an address. The same key yields a one-shot address and a
// persistent address, and they are unrelated on chain — one-shot versus
// persistent is a wallet policy surfaced as an address bit, not two ledgers.
type Key struct {
	priv ed25519.PrivateKey
}

// NewKey generates a key from the system entropy source.
func NewKey() (*Key, error) { return NewKeyFrom(rand.Reader) }

// NewKeyFrom generates a key from an explicit entropy source.
func NewKeyFrom(r io.Reader) (*Key, error) {
	_, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

// KeyFromSeed derives a key from a 32-byte seed. Tests and vector generators
// use it so that every artifact in the repository is reproducible from source.
func KeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("wallet: seed must be 32 bytes")
	}
	return &Key{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// PubKey returns the public key.
func (k *Key) PubKey() types.PubKey {
	var pub types.PubKey
	copy(pub[:], k.priv.Public().(ed25519.PublicKey))
	return pub
}

// Seed returns the 32-byte seed. Callers are responsible for what they do with
// it; this package deliberately offers no on-disk format, because a key file
// format is a compatibility promise and Era 0 has enough of those.
func (k *Key) Seed() []byte { return append([]byte(nil), k.priv.Seed()...) }

// Zero overwrites the private key material in place and leaves the key
// unusable.
//
// A process that holds an unlocked key for as long as a person keeps a window
// open — `zcd ui`, the desktop wallet — needs a way to put that key beyond
// reach on demand, and waiting for a garbage collector that may never move
// the allocation and would not scrub it if it did is not one. Every method on
// a zeroed key panics rather than answering: a signature produced from zeroed
// material would be a valid-looking signature from the wrong key, which is
// strictly worse than a crash.
//
// This is best-effort in the way every in-process wipe is. It does not
// recover a copy the runtime made while growing a stack, and it does nothing
// about the page reaching swap. It removes the long-lived copy, which is the
// one an idle wallet is actually exposed on.
func (k *Key) Zero() {
	for i := range k.priv {
		k.priv[i] = 0
	}
	k.priv = nil
}

// Address derives one of this key's addresses.
func (k *Key) Address(version byte) types.Address {
	return crypto.AddressFromPubKey(version, k.PubKey())
}

// OneShot is the address a wallet derives per payment received. Debiting it
// burns it, which is what keeps the received amount unlinkable to the next one.
func (k *Key) OneShot() types.Address { return k.Address(crypto.AddrVersionOneShot) }

// Persistent is the reusable address: merchants, hot wallets, mining payouts.
func (k *Key) Persistent() types.Address { return k.Address(crypto.AddrVersionPersistent) }

// Sign produces a signature over an arbitrary message.
func (k *Key) Sign(message []byte) types.SigBytes {
	var out types.SigBytes
	copy(out[:], ed25519.Sign(k.priv, message))
	return out
}
