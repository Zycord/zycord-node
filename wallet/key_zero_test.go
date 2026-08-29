package wallet

import (
	"bytes"
	"testing"
)

// TestZeroWipesTheSeed pins what an idle auto-lock is worth. A wallet window
// left open holds the seed for as long as the process lives, so "lock" has to
// mean the bytes are gone rather than the reference is dropped.
func TestZeroWipesTheSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	k, err := KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	held := k.priv // the live allocation, not a copy
	if !bytes.Contains(held, seed) {
		t.Fatal("the seed is not where this test thinks it is; rewrite the test, not the code")
	}

	k.Zero()

	if !bytes.Equal(held[:32], make([]byte, 32)) {
		t.Fatal("Zero left the seed in the allocation the key was using")
	}
}

// TestZeroedKeyCannotSign: a zeroed key must not quietly produce a signature
// from zeroed material. That signature would verify against a public key
// nobody controls, and the certificate carrying it would be rejected by the
// network with no hint that the wallet had been locked underneath it.
func TestZeroedKeyCannotSign(t *testing.T) {
	k, err := KeyFromSeed(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	k.Zero()
	defer func() {
		if recover() == nil {
			t.Fatal("signing with a zeroed key returned instead of panicking")
		}
	}()
	k.Sign([]byte("anything"))
}
