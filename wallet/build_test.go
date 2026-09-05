package wallet_test

import (
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

func key(t *testing.T, n byte) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

// bid is the standard shape a wallet produces: maxima far above the base fees
// so the certificate survives its TTL window, and modest priorities that are
// what the miner is actually paid. The headroom is free (R2-H1).
func bid() types.FeeBid {
	return wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10))
}

// TestKeysAreDeterministic: every artifact in this repository must be
// reproducible from source, and a key derived from a seed is the base case.
func TestKeysAreDeterministic(t *testing.T) {
	a, b := key(t, 7), key(t, 7)
	if a.PubKey() != b.PubKey() {
		t.Fatal("the same seed produced two keys")
	}
	if a.Persistent() == a.OneShot() {
		t.Fatal("one key produced one address for both versions")
	}
	if _, err := wallet.KeyFromSeed(make([]byte, 31)); err == nil {
		t.Fatal("a short seed was accepted")
	}
}

// TestDepositCoversTheCeilingInOnePass. The fee ceiling depends on the encoded
// size, which depends on the number of signatures — but signatures are
// fixed-width and excluded from the signed body, so attaching placeholders of
// the right count fixes the size before anything is signed. There is no fixed
// point to iterate to, and this checks that claim rather than assuming it.
func TestDepositCoversTheCeilingInOnePass(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	for _, signers := range [][]*wallet.Key{{alice}, {alice, bob}} {
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Retire(alice.OneShot(), bob.OneShot()),
			TTL:     100,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: signers,
		}
		c, err := b.Build()
		if len(signers) == 1 {
			// One signer cannot authorise the other's address, so the builder
			// must refuse rather than emit something the network will reject.
			if err == nil {
				t.Fatal("a certificate was built without every required signature")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		ceiling, ok := c.FeeCeiling(p)
		if !ok {
			t.Fatal("the ceiling overflowed")
		}
		if c.Deposit.Amount.Lt(ceiling) {
			t.Fatalf("the deposit of %s is below the ceiling of %s",
				c.Deposit.Amount.String(), ceiling.String())
		}
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("the builder emitted an invalid certificate: %v", err)
		}
	}
}

// TestSignersAreCanonicalised: duplicates are dropped and the set is sorted, so
// a caller cannot accidentally produce a certificate V1 rejects.
func TestSignersAreCanonicalised(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Retire(alice.OneShot(), bob.OneShot()),
		TTL:     100,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{bob, alice, bob, alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sigs) != 2 {
		t.Fatalf("got %d signatures, want 2 after deduplication", len(c.Sigs))
	}
	for i := 1; i < len(c.Sigs); i++ {
		prev, cur := c.Sigs[i-1].PubKey, c.Sigs[i].PubKey
		if string(prev[:]) >= string(cur[:]) {
			t.Fatal("the signature set is not sorted by public key")
		}
	}
}

// TestBuilderRefusesInvalidPrograms: a wallet that ships an invalid certificate
// wastes the user's fee and the relay's patience.
func TestBuilderRefusesInvalidPrograms(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	cases := map[string]types.Program{
		"zero amount": wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), u256.Zero),
		"self move":   wallet.Tip(types.NativeAsset, alice.Persistent(), alice.Persistent(), drops(1)),
		"empty":       wallet.Transfer(),
	}
	for name, prog := range cases {
		t.Run(name, func(t *testing.T) {
			b := &wallet.Builder{
				Params:  p,
				Program: prog,
				TTL:     100,
				Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
				FeeBid:  bid(),
				Signers: []*wallet.Key{alice},
			}
			if _, err := b.Build(); err == nil {
				t.Fatal("the builder emitted a certificate derivation rejects")
			}
		})
	}

	if _, err := (&wallet.Builder{Params: p, Program: wallet.Transfer()}).Build(); err != wallet.ErrNoSigners {
		t.Fatal("a certificate with no signers was accepted")
	}
}

// TestRetireIsCanonicalised: the address list must be sorted and deduplicated,
// because canonical form is not the caller's problem to remember.
func TestRetireIsCanonicalised(t *testing.T) {
	a, b := key(t, 2).OneShot(), key(t, 3).OneShot()
	prog := wallet.Retire(b, a, b, a)
	if got := len(prog.Retire.Addrs); got != 2 {
		t.Fatalf("got %d addresses, want 2 after deduplication", got)
	}
	if string(prog.Retire.Addrs[0][:]) >= string(prog.Retire.Addrs[1][:]) {
		t.Fatal("the retire list is not sorted")
	}
	if _, _, err := validity.Derive(prog, spec.Devnet().ChainID, 0); err != nil {
		t.Fatalf("the canonicalised program does not derive: %v", err)
	}
}

// TestAssetAddressIsPredictable: a wallet must be able to tell a user which
// asset their ISSUE will create, before it is sent.
func TestAssetAddressIsPredictable(t *testing.T) {
	p := spec.Devnet()
	issuer := key(t, 5)
	const seq = 3

	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Issue(issuer.Persistent(), drops(1_000), 2, types.Hash{'X'}, issuer.PubKey()),
		Seq:     seq,
		TTL:     100,
		Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{issuer},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	want := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), seq)
	found := false
	for _, w := range c.Writes {
		if w.Slot == types.AssetCapSlot(want) {
			found = true
		}
	}
	if !found {
		t.Fatal("the certificate does not write the predicted asset's cap cell")
	}
	// A different Seq must yield a different asset, or a wallet could not issue
	// twice.
	if types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), seq+1) == want {
		t.Fatal("two sequence numbers derived the same asset address")
	}
	// And so must a different chain.
	if types.DeriveAssetAddress(p.ChainID+1, issuer.Persistent(), seq) == want {
		t.Fatal("two chains derived the same asset address")
	}
}

// TestMovesAreCanonicallyOrdered is the wallet half of R2-M2.
//
// The protocol does not order moves, so two orderings are two certificate ids
// with one effect — harmless for consensus (reordering invalidates the
// signatures, so only the signer can do it) but fatal for a wallet trying to
// tell "already sent" from "sent twice". Sorting makes a retry reproduce the
// same id.
func TestMovesAreCanonicallyOrdered(t *testing.T) {
	p := spec.Devnet()
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)

	m1 := types.Move{Src: alice.Persistent(), Dst: bob.Persistent(), Amount: drops(10)}
	m2 := types.Move{Src: alice.Persistent(), Dst: carol.Persistent(), Amount: drops(20)}

	build := func(moves ...types.Move) *types.Certificate {
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Transfer(moves...),
			TTL:     100,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	forward, reverse := build(m1, m2), build(m2, m1)
	if forward.ID() != reverse.ID() {
		t.Fatal("the same payment written in two orders produced two certificate ids; " +
			"a wallet cannot tell a retry from a second payment")
	}

	// And the ordering is stable across calls, not merely self-consistent.
	if build(m2, m1).ID() != forward.ID() {
		t.Fatal("move ordering is not deterministic")
	}
}
