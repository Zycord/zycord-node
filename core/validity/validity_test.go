package validity_test

import (
	"strings"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
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

// validCert is the baseline every negative test mutates: a plain transfer
// between two persistent addresses.
func validCert(t *testing.T, p *params.Params) (*types.Certificate, *wallet.Key) {
	t.Helper()
	alice, bob := key(t, 2), key(t, 3)
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c, alice
}

// resign re-signs a mutated certificate so that the test exercises the rule it
// is aiming at rather than tripping over V2 on the way.
func resign(p *params.Params, c *types.Certificate, keys ...*wallet.Key) {
	msg := c.SigningMessage(p)
	c.Sigs = c.Sigs[:0]
	for _, k := range keys {
		c.Sigs = append(c.Sigs, types.Sig{PubKey: k.PubKey(), Sig: k.Sign(msg)})
	}
}

func wantRule(t *testing.T, err error, rule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s to reject the certificate", rule)
	}
	if got := validity.Rule(err); got != rule {
		t.Fatalf("rejected by %s (%v), want %s", got, err, rule)
	}
}

func TestValidCertificatePasses(t *testing.T) {
	p := spec.Devnet()
	c, _ := validCert(t, p)
	if err := validity.Check(c, p); err != nil {
		t.Fatalf("the baseline certificate is invalid: %v", err)
	}
}

// V1 — canonical form, ordering, limits, chain binding.
func TestV1(t *testing.T) {
	p := spec.Devnet()

	t.Run("wrong chain", func(t *testing.T) {
		c, alice := validCert(t, p)
		c.ChainID = p.ChainID + 1
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V1")
	})

	t.Run("unsorted writes", func(t *testing.T) {
		c, alice := validCert(t, p)
		c.Writes[0], c.Writes[1] = c.Writes[1], c.Writes[0]
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V1")
	})

	t.Run("duplicate reads", func(t *testing.T) {
		c, alice := validCert(t, p)
		c.Reads = append(c.Reads, c.Reads[0])
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V1")
	})

	t.Run("no signatures", func(t *testing.T) {
		c, _ := validCert(t, p)
		c.Sigs = nil
		wantRule(t, validity.Check(c, p), "V1")
	})

	t.Run("unsorted signatures", func(t *testing.T) {
		c, alice := validCert(t, p)
		resign(p, c, alice)
		c.Sigs = append(c.Sigs, c.Sigs[0])
		wantRule(t, validity.Check(c, p), "V1")
	})
}

// V2 — every signature verifies, under strict rules.
func TestV2(t *testing.T) {
	p := spec.Devnet()

	t.Run("corrupted signature", func(t *testing.T) {
		c, _ := validCert(t, p)
		c.Sigs[0].Sig[0] ^= 0xff
		wantRule(t, validity.Check(c, p), "V2")
	})

	t.Run("signature over a different body", func(t *testing.T) {
		c, alice := validCert(t, p)
		resign(p, c, alice)
		c.TTL++ // changes the body root, so the signature no longer covers it
		wantRule(t, validity.Check(c, p), "V2")
	})

	t.Run("small order key is refused", func(t *testing.T) {
		// A small-order public key verifies many distinct messages under a
		// crafted signature, which would let a certificate claim authority it
		// does not hold.
		var identity types.PubKey
		identity[0] = 0x01
		if !crypto.IsSmallOrderPubKey(identity) {
			t.Fatal("the identity point is not recognised as small order")
		}
		if crypto.VerifyStrict(identity, []byte("anything"), types.SigBytes{}) {
			t.Fatal("a small-order key verified")
		}
	})
}

// V3 — the declared reads and writes must equal what the program derives.
func TestV3(t *testing.T) {
	p := spec.Devnet()

	t.Run("inflated credit", func(t *testing.T) {
		c, alice := validCert(t, p)
		for i := range c.Writes {
			if c.Writes[i].Op == types.OpDeltaAdd {
				c.Writes[i].Value = c.Writes[i].Value.SatAdd(drops(1))
			}
		}
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V3")
	})

	t.Run("weakened guard", func(t *testing.T) {
		c, alice := validCert(t, p)
		c.Reads[0].Operand = u256.Zero
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V3")
	})

	t.Run("extra write", func(t *testing.T) {
		c, alice := validCert(t, p)
		victim := key(t, 4).Persistent()
		c.Writes = append(c.Writes, types.Write{
			Slot:  types.NativeBalanceSlot(victim),
			Op:    types.OpDeltaAdd,
			Value: drops(1),
		})
		sortWrites(c)
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V3")
	})
}

// TestDerivationRejectsNonsense covers the statically detectable programs that
// never reach a read/write set at all.
func TestDerivationRejectsNonsense(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	cases := []struct {
		name string
		prog types.Program
	}{
		{"empty transfer", wallet.Transfer()},
		{"zero amount", wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), u256.Zero)},
		{"self move", wallet.Tip(types.NativeAsset, alice.Persistent(), alice.Persistent(), drops(1))},
		{"asset source", wallet.Tip(types.NativeAsset, types.DeriveAssetAddress(1, alice.Persistent(), 0), bob.Persistent(), drops(1))},
		{"protocol destination", wallet.Tip(types.NativeAsset, alice.Persistent(), crypto.ProtocolAddress, drops(1))},
		{"zero cap", wallet.Issue(alice.Persistent(), u256.Zero, 2, types.Hash{}, alice.PubKey())},
		{"mint over cap", wallet.Mint(types.DeriveAssetAddress(1, alice.Persistent(), 0), bob.Persistent(), drops(11), drops(10), alice.PubKey())},
		{"mint of a non-asset", wallet.Mint(alice.Persistent(), bob.Persistent(), drops(1), drops(10), alice.PubKey())},
		{"retire nothing", wallet.Retire()},
		{"retire a persistent address", wallet.Retire(alice.Persistent())},
		{
			"routed transfer",
			wallet.Transfer(
				types.Move{Src: alice.Persistent(), Dst: bob.Persistent(), Amount: drops(5)},
				types.Move{Src: bob.Persistent(), Dst: key(t, 4).Persistent(), Amount: drops(5)},
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := validity.Derive(tc.prog, p.ChainID, 0); err == nil {
				t.Fatal("derivation accepted a nonsense program")
			}
		})
	}
}

// TestMergedDebitsAreCoherent is R1-M1: two moves debiting one cell must be
// merged into a single guard against a single pre-state snapshot, not into two
// guards that each pass while their sum fails.
func TestMergedDebitsAreCoherent(t *testing.T) {
	p := spec.Devnet()
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)

	prog := wallet.Transfer(
		types.Move{Src: alice.Persistent(), Dst: bob.Persistent(), Amount: drops(60)},
		types.Move{Src: alice.Persistent(), Dst: carol.Persistent(), Amount: drops(70)},
	)
	reads, writes, err := validity.Derive(prog, p.ChainID, 0)
	if err != nil {
		t.Fatal(err)
	}

	src := types.NativeBalanceSlot(alice.Persistent())
	var guards, debits int
	for _, r := range reads {
		if r.Slot == src {
			guards++
			if r.Access != types.AccessGuardGE || !r.Operand.Eq(drops(130)) {
				t.Fatalf("guard on the source is %d/%s, want GUARD_GE 130", r.Access, r.Operand.String())
			}
		}
	}
	for _, w := range writes {
		if w.Slot == src {
			debits++
			if w.Op != types.OpDeltaSub || !w.Value.Eq(drops(130)) {
				t.Fatalf("debit on the source is %d/%s, want DELTA_SUB 130", w.Op, w.Value.String())
			}
		}
	}
	if guards != 1 || debits != 1 {
		t.Fatalf("got %d guards and %d debits on one slot, want exactly one of each", guards, debits)
	}
}

// V4 — authorisation is sufficient and minimal.
func TestV4(t *testing.T) {
	p := spec.Devnet()

	t.Run("missing signature", func(t *testing.T) {
		c, _ := validCert(t, p)
		// Sign with a key that authorises nothing in this certificate.
		resign(p, c, key(t, 9))
		wantRule(t, validity.Check(c, p), "V4")
	})

	t.Run("superfluous signature", func(t *testing.T) {
		// Minimality is what makes the certificate id sufficient.
		// The id's preimage excludes Sigs, so a certificate carrying a
		// signature that authorises nothing would be a *cheaper or dearer*
		// encoding of the same id: same authorization, different signature
		// count, different encoded length, different parallel gas and fee
		// ceiling. V4 is what keeps one id to one cost.
		c, alice := validCert(t, p)
		resign(p, c, alice, key(t, 9))
		if c.Sigs[0].PubKey == c.Sigs[1].PubKey {
			t.Fatal("setup: the two signers collided")
		}
		// Restore the canonical ordering so the failure is V4, not V1.
		sortSigs(c)
		wantRule(t, validity.Check(c, p), "V4")
	})

	t.Run("mint without the minter", func(t *testing.T) {
		issuer, thief, holder := key(t, 5), key(t, 6), key(t, 7)
		asset := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), 0)
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Mint(asset, holder.Persistent(), drops(10), drops(100), issuer.PubKey()),
			TTL:     100,
			Deposit: wallet.SelfDeposit(thief.Persistent(), thief.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{thief},
		}
		if _, err := b.Build(); err == nil {
			t.Fatal("a mint was built without the minter's key")
		}
	})
}

// V5 — the deposit must be reservable, refundable and sufficient.
func TestV5(t *testing.T) {
	p := spec.Devnet()

	t.Run("under-reserved", func(t *testing.T) {
		c, alice := validCert(t, p)
		c.Deposit.Amount = c.Deposit.Amount.SatSub(u256.One)
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V5")
	})

	t.Run("deposit is not a native balance cell", func(t *testing.T) {
		c, alice := validCert(t, p)
		c.Deposit.Cell.Word[0] ^= 0xff
		resign(p, c, alice)
		wantRule(t, validity.Check(c, p), "V5")
	})

	t.Run("refund into the burned cell", func(t *testing.T) {
		// R1-C3(i): the certificate burns this address, so settling into it
		// would strand the remainder in a cell nobody can ever read.
		alice, bob := key(t, 2), key(t, 3)
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(), drops(1_000_000)),
			TTL:     100,
			Deposit: wallet.SelfDeposit(alice.OneShot(), alice.OneShot()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}
		if _, err := b.Build(); err == nil {
			t.Fatal("a certificate refunding into its own burned cell was built")
		}
	})
}

// V6 — self-consistency and one-shot hygiene.
func TestV6(t *testing.T) {
	p := spec.Devnet()

	t.Run("one-shot debit without a burn", func(t *testing.T) {
		c, alice := validCert(t, p)
		// Move the deposit onto a one-shot address without adding the
		// MARK_SPENT the certificate would then owe.
		c.Deposit.Cell = types.NativeBalanceSlot(alice.OneShot())
		resign(p, c, alice)
		wantRule(t, validity.CheckSelfConsistency(c), "V6")
	})

	t.Run("mark spent on an asset address", func(t *testing.T) {
		c, alice := validCert(t, p)
		asset := types.DeriveAssetAddress(p.ChainID, alice.Persistent(), 0)
		c.Writes = append([]types.Write{{Slot: types.SpentSlot(asset), Op: types.OpMarkSpent}}, c.Writes...)
		sortWrites(c)
		resign(p, c, alice)
		// V3 rejects it first — derivation pins the Era-0 write set exactly —
		// so the rule itself is exercised directly. V6 is what will catch this
		// once the cEVM makes write sets open-ended.
		wantRule(t, validity.Check(c, p), "V3")
		wantRule(t, validity.CheckSelfConsistency(c), "V6")
	})
}

// oneShotDeposit builds a certificate through the reference wallet's ordinary
// path, funding it from a one-shot deposit cell.
//
// That it goes through wallet.Builder at all is half the point of the
// one-shot deposit fix: the deposit cell's MARK_SPENT comes from
// validity.DeriveCert, the same function V3 checks against, so there is
// nothing here for a test helper to reproduce by hand and nothing for a
// wallet to get wrong.
func oneShotDeposit(t *testing.T, p *params.Params, prog types.Program, depositAddr, refundTo types.Address, signers ...*wallet.Key) *types.Certificate {
	t.Helper()
	c, err := (&wallet.Builder{
		Params:  p,
		Program: prog,
		TTL:     100,
		Deposit: wallet.SweepDeposit(depositAddr, refundTo, drops(1_000_000_000)),
		FeeBid:  bid(),
		Signers: signers,
	}).Build()
	if err != nil {
		t.Fatalf("wallet.Builder refused a one-shot-funded certificate: %v", err)
	}
	return c
}

// TestOneShotDepositAcrossProgramKinds is F-VAL-5's table: whether a
// one-shot deposit cell can fund a certificate at all must not depend on the
// accident of the program kind also happening to spend that same address as
// a TRANSFER move source. Before the fix, only the TRANSFER-as-source case —
// where the two coincide — had a satisfiable certificate; every other cell of
// this table had none, because derivation never produced the deposit cell's
// own MARK_SPENT and V3 rejected anyone who added it by hand.
//
// Every case here is built by wallet.Builder rather than assembled locally.
// A rule the reference wallet cannot satisfy is not a fixed rule, it is a
// fixed rule and a broken wallet, and the reported impact was precisely
// that a user could not build the certificate.
func TestOneShotDepositAcrossProgramKinds(t *testing.T) {
	p := spec.Devnet()
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)

	t.Run("ISSUE funded solely from a one-shot address", func(t *testing.T) {
		prog := wallet.Issue(alice.OneShot(), drops(1_000), 0, types.Hash{}, alice.PubKey())
		c := oneShotDeposit(t, p, prog, alice.OneShot(), alice.Persistent(), alice)
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("an ISSUE funded from a one-shot deposit cell should be valid: %v", err)
		}
	})

	t.Run("MINT funded solely from the minter's one-shot address", func(t *testing.T) {
		asset := types.DeriveAssetAddress(p.ChainID, alice.Persistent(), 0)
		prog := wallet.Mint(asset, bob.Persistent(), drops(10), drops(1_000), alice.PubKey())
		c := oneShotDeposit(t, p, prog, alice.OneShot(), alice.Persistent(), alice)
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("a MINT funded from a one-shot deposit cell should be valid: %v", err)
		}
	})

	t.Run("TRANSFER whose deposit cell is not a move source", func(t *testing.T) {
		prog := wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000))
		// carol funds the deposit; she is not party to the move at all.
		c := oneShotDeposit(t, p, prog, carol.OneShot(), carol.Persistent(), alice, carol)
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("a TRANSFER whose one-shot deposit cell is not a source should be valid: %v", err)
		}
	})

	t.Run("TRANSFER whose deposit cell IS the move source (unaffected control case)", func(t *testing.T) {
		prog := wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(), drops(1_000))
		c := oneShotDeposit(t, p, prog, alice.OneShot(), alice.Persistent(), alice)
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("this case worked before the fix and must keep working: %v", err)
		}
		// One MARK_SPENT, not two: the deposit cell and the move source are
		// the same address, and derivation must not declare it twice.
		n := 0
		for _, w := range c.Writes {
			if w.Op == types.OpMarkSpent && w.Slot.Addr == alice.OneShot() {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("derived %d MARK_SPENT writes for one address, want 1", n)
		}
	})

	t.Run("RETIRE funded from a different one-shot address than the one retired", func(t *testing.T) {
		prog := wallet.Retire(bob.OneShot())
		c := oneShotDeposit(t, p, prog, alice.OneShot(), alice.Persistent(), alice, bob)
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("a RETIRE funded from an unrelated one-shot deposit cell should be valid: %v", err)
		}
	})

	t.Run("RETIRE of the very address funding it", func(t *testing.T) {
		// The deposit cell is also the RETIRE target, so derivation already
		// produced its MARK_SPENT: the fold-in must be a no-op, not a
		// duplicate write.
		prog := wallet.Retire(alice.OneShot())
		c := oneShotDeposit(t, p, prog, alice.OneShot(), alice.Persistent(), alice)
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("a RETIRE funded from the address it retires should be valid: %v", err)
		}
		if len(c.Writes) != 1 {
			t.Fatalf("declared %d writes, want the single MARK_SPENT", len(c.Writes))
		}
	})

	t.Run("a hand-declared write set that omits the deposit's MARK_SPENT is rejected by V3", func(t *testing.T) {
		// The pre-fix failure mode is now a single, unambiguous rejection
		// rather than a V6/V3 contradiction: whatever the program derives, a
		// one-shot deposit cell's burn is part of the certificate's write
		// set, and a certificate declaring anything else disagrees with V3.
		issuer := key(t, 5)
		c := oneShotDeposit(t, p,
			wallet.Issue(issuer.OneShot(), drops(1_000), 0, types.Hash{}, issuer.PubKey()),
			issuer.OneShot(), issuer.Persistent(), issuer)
		stripped := c.Writes[:0:0]
		for _, w := range c.Writes {
			if w.Op == types.OpMarkSpent && w.Slot.Addr == issuer.OneShot() {
				continue
			}
			stripped = append(stripped, w)
		}
		if len(stripped) == len(c.Writes) {
			t.Fatal("the certificate never declared the deposit cell's MARK_SPENT")
		}
		c.Writes = stripped
		resign(p, c, issuer)
		wantRule(t, validity.Check(c, p), "V3")
	})
}

// TestV6RejectsCreditsIntoItsOwnBurn is the write-side twin of F-FOLD-1: F8
// commits a certificate's value writes and its MARK_SPENTs together, so a
// credit to an address the same certificate burns is value destroyed on an
// APPLIED certificate — the same silent loss as a refund into one's own burn,
// one write earlier.
func TestV6RejectsCreditsIntoItsOwnBurn(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)
	asset := types.DeriveAssetAddress(p.ChainID, bob.Persistent(), 0)

	t.Run("a TRANSFER crediting a second asset to the one-shot source it sweeps", func(t *testing.T) {
		// Two different slots under one address, so nothing here is caught by
		// derivation's slot-both-ways check: alice's one-shot pays out its
		// native balance and is burned for it, while bob sends it an asset
		// balance nobody will ever be able to move.
		prog := wallet.Transfer(
			types.Move{Asset: types.NativeAsset, Src: alice.OneShot(), Dst: bob.Persistent(), Amount: drops(1_000)},
			types.Move{Asset: asset, Src: bob.Persistent(), Dst: alice.OneShot(), Amount: drops(5)},
		)
		_, err := (&wallet.Builder{
			Params:  p,
			Program: prog,
			TTL:     100,
			Deposit: wallet.SelfDeposit(bob.Persistent(), bob.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice, bob},
		}).Build()
		if err == nil {
			t.Fatal("a certificate crediting an address it burns was built")
		}
		wantRule(t, err, "V6")
	})

	t.Run("a MINT whose destination is its own one-shot deposit cell", func(t *testing.T) {
		prog := wallet.Mint(asset, alice.OneShot(), drops(10), drops(1_000), alice.PubKey())
		_, err := (&wallet.Builder{
			Params:  p,
			Program: prog,
			TTL:     100,
			Deposit: wallet.SweepDeposit(alice.OneShot(), alice.Persistent(), drops(1_000_000_000)),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err == nil {
			t.Fatal("a MINT into the one-shot address funding it was built")
		}
		wantRule(t, err, "V6")
	})

	t.Run("minting to a one-shot address that is not the deposit cell is fine", func(t *testing.T) {
		// Control: paying a fresh one-shot address is the zero-contention fast
		// path (§4), and nothing here burns it.
		prog := wallet.Mint(asset, alice.OneShot(), drops(10), drops(1_000), bob.PubKey())
		if _, err := (&wallet.Builder{
			Params:  p,
			Program: prog,
			TTL:     100,
			Deposit: wallet.SelfDeposit(bob.Persistent(), bob.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{bob},
		}).Build(); err != nil {
			t.Fatalf("a MINT into an untouched one-shot address should build: %v", err)
		}
	})
}

// TestV5RefundIntoOwnMarkSpent is F-FOLD-1: RefundTo must not name any
// address this certificate's own write set marks spent — not only the
// deposit cell itself, which is all the pre-fix clause checked.
//
// F8 commits a certificate's own MARK_SPENT writes before F9's settle runs,
// so a certificate that refunds into an address it burns in the very same
// certificate would pass every rule and then have settle burn the entire
// remainder, reporting it as an ordinary refund. Both scenarios below were
// buildable before this fix; neither is after it.
func TestV5RefundIntoOwnMarkSpent(t *testing.T) {
	p := spec.Devnet()

	t.Run("TRANSFER from a one-shot source, deposit paid from elsewhere, refund back into the source", func(t *testing.T) {
		// The primary scenario from the issue: Deposit.Cell is H, a persistent
		// hot-wallet address — not one-shot at all — so the old clause
		// (Cell.Addr[0]==OneShot && RefundTo==Cell) could never fire here no
		// matter what RefundTo named. The certificate still burns A (the
		// TRANSFER source) as a side effect, and RefundTo names A.
		hot, a, bob := key(t, 2), key(t, 6), key(t, 3)
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, a.OneShot(), bob.Persistent(), drops(1_000_000)),
			TTL:     100,
			Deposit: wallet.SelfDeposit(hot.Persistent(), a.OneShot()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{hot, a},
		}
		_, err := b.Build()
		if err == nil {
			t.Fatal("a certificate refunding into an address it marks spent in the same certificate was built")
		}
		wantRule(t, err, "V5")
	})

	t.Run("RETIRE with a persistent deposit cell, refunding into the address it retires", func(t *testing.T) {
		// The independent round-2 reproduction: RETIRE never touches
		// Deposit.Cell at all, so the narrow clause could not have caught
		// this even in principle, regardless of what Cell was.
		payer, victim := key(t, 2), key(t, 7)
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Retire(victim.OneShot()),
			TTL:     100,
			Deposit: wallet.SelfDeposit(payer.Persistent(), victim.OneShot()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{payer, victim},
		}
		_, err := b.Build()
		if err == nil {
			t.Fatal("a RETIRE refunding into the address it retires was built")
		}
		wantRule(t, err, "V5")
	})

	t.Run("refunding into a one-shot deposit cell is still V5, not V3", func(t *testing.T) {
		// The original R1-C3-i case. V3 would also reject the certificate a
		// wallet hands over here — the write set it derives is the one that
		// burns the deposit cell — but V5 must not need V3 to have run to be
		// right about a refund, so the clause is kept explicitly and this
		// pins which rule speaks.
		alice := key(t, 2)
		c := oneShotDeposit(t, p,
			wallet.Issue(alice.OneShot(), drops(1_000), 0, types.Hash{}, alice.PubKey()),
			alice.OneShot(), alice.Persistent(), alice)
		c.Deposit.RefundTo = types.NativeBalanceSlot(alice.OneShot())
		resign(p, c, alice)
		wantRule(t, validity.CheckDeposit(c, p), "V5")
	})

	t.Run("refund elsewhere is unaffected", func(t *testing.T) {
		// Control: the same shape, refunding somewhere the certificate does
		// not touch. Must still build and pass.
		payer, victim, elsewhere := key(t, 2), key(t, 7), key(t, 8)
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Retire(victim.OneShot()),
			TTL:     100,
			Deposit: wallet.SelfDeposit(payer.Persistent(), elsewhere.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{payer, victim},
		}
		if _, err := b.Build(); err != nil {
			t.Fatalf("a RETIRE refunding somewhere it does not touch should build: %v", err)
		}
	})
}

// V7 — certificates never write protocol cells.
func TestV7(t *testing.T) {
	p := spec.Devnet()
	c, alice := validCert(t, p)
	c.Writes = append([]types.Write{{
		Slot:  types.SeqBaseFeeSlot(),
		Op:    types.OpSet,
		Value: u256.One,
	}}, c.Writes...)
	sortWrites(c)
	resign(p, c, alice)
	// As with V6, derivation catches it first in Era 0; the rule is what will
	// hold the line when programs stop being four fixed shapes.
	wantRule(t, validity.Check(c, p), "V3")
	wantRule(t, validity.CheckProtocolExclusion(c), "V7")
}

// TestV9 pins the address-version whitelist directly against
// CheckAddressVersions, not against Check, because Check never reaches V9 in
// Era 0 — and demonstrating why is the point of the test, not a caveat on it.
//
// A read or write naming an unknown-version address is caught by V3 first:
// the closed Era-0 program set (§9) only ever derives 0x01/0x02/0x03
// addresses, so mutating a declared read or write to 0x04 makes it disagree
// with what the certificate's own program derives, and CheckDerivation fails
// before CheckAddressVersions ever runs. A mutated deposit or refund is
// caught by V5 first, and more directly still: CheckDeposit already requires
// crypto.IsUserAddress on both, which is narrower than V9's "known version"
// (it excludes 0x03 too). V9's non-redundant coverage is entirely reads and
// writes reached by a certificate that was never derived at all — which
// nothing in Era 0 can build, and which is exactly the shape Era S's hidden
// cells (0x04) would introduce if this rule were not already in place.
func TestV9(t *testing.T) {
	p := spec.Devnet()

	unknownAddr := func(kind byte) types.Address {
		a := key(t, kind).Persistent()
		a[0] = 0x04
		return a
	}

	c, _ := validCert(t, p)
	c.Reads[0].Slot.Addr = unknownAddr(9)
	wantRule(t, validity.CheckAddressVersions(c), "V9")

	c, alice := validCert(t, p)
	c.Writes[0].Slot.Addr = unknownAddr(10)
	wantRule(t, validity.CheckAddressVersions(c), "V9")
	// And confirm the Era-0 story: the full predicate rejects it too, but at
	// V3, because derivation never produces this write in the first place.
	// Restoring sort order first is what keeps the rejection at V3 rather
	// than at V1, which the address mutation disturbs incidentally.
	sortWrites(c)
	resign(p, c, alice)
	wantRule(t, validity.Check(c, p), "V3")

	c, _ = validCert(t, p)
	c.Deposit.Cell.Addr = unknownAddr(11)
	wantRule(t, validity.CheckAddressVersions(c), "V9")

	c, _ = validCert(t, p)
	c.Deposit.RefundTo.Addr = unknownAddr(12)
	wantRule(t, validity.CheckAddressVersions(c), "V9")
}

// TestStatelessness is the property the whole architecture rests on: the
// validity predicate must not consult anything but the certificate's bytes.
// It is asserted by construction — Check takes no state — and pinned here so
// that a future signature cannot quietly acquire one.
func TestStatelessness(t *testing.T) {
	p := spec.Devnet()
	c, _ := validCert(t, p)
	for i := 0; i < 3; i++ {
		if err := validity.Check(c, p); err != nil {
			t.Fatalf("validity is not a pure function of the bytes: %v", err)
		}
	}
}

func sortSigs(c *types.Certificate) {
	for i := 1; i < len(c.Sigs); i++ {
		for j := i; j > 0 && less(c.Sigs[j].PubKey[:], c.Sigs[j-1].PubKey[:]); j-- {
			c.Sigs[j], c.Sigs[j-1] = c.Sigs[j-1], c.Sigs[j]
		}
	}
}

func sortWrites(c *types.Certificate) {
	for i := 1; i < len(c.Writes); i++ {
		for j := i; j > 0 && c.Writes[j].Slot.Less(c.Writes[j-1].Slot); j-- {
			c.Writes[j], c.Writes[j-1] = c.Writes[j-1], c.Writes[j]
		}
	}
}

func less(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// TestTheIdPinsTheSignerSetAndThereforeTheCost is the premise the id-preimage
// fix rests on, checked rather than assumed.
//
// The certificate id hashes the authorizing fields and not the signatures. That
// is only a sound key if the body determines *which* signatures a valid
// certificate may carry — otherwise two certificates could share an id and
// differ in signer count, and a proposer could pick whichever exemplar of an
// authorization suited it, at a gas and fee ceiling the signer never agreed to.
//
// V4 supplies exactly that, in both directions, and this walks both:
//
//   - sufficiency — every address the body debits and every key the body names
//     must appear, so a certificate cannot carry *fewer* signatures than the
//     body implies;
//   - minimality — a signature that authorises nothing is invalid, so it cannot
//     carry *more*.
//
// Together: one id, one legal signer set, one encoded length, one cost. The
// assertions are on the derived quantities rather than on V4's verdict alone,
// because the verdict is not the property — the property is that the numbers
// downstream of it cannot move.
func TestTheIdPinsTheSignerSetAndThereforeTheCost(t *testing.T) {
	p := spec.Devnet()

	c, alice := validCert(t, p)
	if err := validity.Check(c, p); err != nil {
		t.Fatalf("setup: %v", err)
	}
	id := c.ID()
	sigs, size, parGas := len(c.Sigs), c.SizeBytes(), c.ParGas(p)
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		t.Fatal("setup: the fee ceiling overflows")
	}

	// One more signature. The id does not move — that is the point of the new
	// preimage — so if this were valid the same id would name two costs.
	fat, _ := validCert(t, p)
	resign(p, fat, alice, key(t, 9))
	sortSigs(fat)
	if fat.ID() != id {
		t.Fatal("adding a signature moved the id; this test is no longer about the premise")
	}
	if fat.SizeBytes() == size || fat.ParGas(p) == parGas {
		t.Fatal("setup: a superfluous signature did not change the cost, so nothing is at stake here")
	}
	if err := validity.Check(fat, p); err == nil {
		t.Fatal("V4 admitted a superfluous signature: one id now names two parallel-gas costs")
	}

	// One fewer. Same id again, and this time the certificate would be
	// authorised by nobody.
	thin, _ := validCert(t, p)
	thin.Sigs = nil
	if thin.ID() != id {
		t.Fatal("dropping a signature moved the id; this test is no longer about the premise")
	}
	if err := validity.Check(thin, p); err == nil {
		t.Fatal("V4 admitted a certificate with no signature at all")
	}

	// And the quantities a proposer bills against are what they were: the
	// exemplar this test started from is the only legal shape of this id.
	if len(c.Sigs) != sigs || c.SizeBytes() != size || c.ParGas(p) != parGas {
		t.Fatal("the baseline moved under the test")
	}
	if got, _ := c.FeeCeiling(p); got != ceiling {
		t.Fatal("the fee ceiling moved under the test")
	}
}

// handBuilt swaps a program into an already-valid certificate and restates the
// declared reads and writes from it, so that V3 agrees and the test reaches the
// rule it is aiming at. It bypasses wallet.Builder deliberately: Build
// round-trips through UnmarshalCertificate, so it cannot produce the
// population CheckCanonical exists for — a certificate no decoder has seen.
func handBuilt(t *testing.T, p *params.Params, prog types.Program) *types.Certificate {
	t.Helper()
	c, alice := validCert(t, p)
	c.Program = prog
	reads, writes, err := validity.DeriveCert(prog, c.ChainID, c.Seq, c.Deposit.Cell.Addr)
	if err != nil {
		t.Fatalf("the replacement program does not derive: %v", err)
	}
	c.Reads, c.Writes = reads, writes
	// The fee ceiling scales with the encoded size, and a bigger program moves
	// it; without restating the deposit, V5 refuses these witnesses before V1
	// is reached.
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		t.Fatal("fee ceiling overflows")
	}
	c.Deposit.Amount = ceiling
	resign(p, c, alice)
	return c
}

// TestV1BoundsTheProgramsOwnMoveList pins the property that a certificate
// validity.Check accepts is a certificate types.UnmarshalCertificate can
// decode, on the move-list axis.
//
// max_moves_per_transfer was enforced only by the decoder, and the derived
// write set is not a proxy for it: the assertions below show 33 moves out of
// one source landing inside max_reads and max_writes, so nothing else in V1
// could have caught it.
func TestV1BoundsTheProgramsOwnMoveList(t *testing.T) {
	p := spec.Devnet()
	alice := key(t, 2)
	moves := func(n int) types.Program {
		out := make([]types.Move, n)
		for i := range out {
			dst := key(t, byte(10+i)).Persistent()
			out[i] = types.Move{Asset: types.NativeAsset, Src: alice.Persistent(), Dst: dst, Amount: drops(1_000)}
		}
		return wallet.Transfer(out...)
	}

	// The separating input: one move fewer is accepted, so the rule that
	// fires below is this bound and not the program's size in general.
	atLimit := handBuilt(t, p, moves(p.MaxMovesPerTransfer))
	if err := validity.Check(atLimit, p); err != nil {
		t.Fatalf("%d moves is the limit and must be accepted: %v", p.MaxMovesPerTransfer, err)
	}

	over := handBuilt(t, p, moves(p.MaxMovesPerTransfer+1))
	if len(over.Reads) > p.MaxReads || len(over.Writes) > p.MaxWrites {
		t.Fatalf("this witness is refused by an older limit before the new one runs: "+
			"%d reads (max %d), %d writes (max %d)",
			len(over.Reads), p.MaxReads, len(over.Writes), p.MaxWrites)
	}
	if _, err := types.UnmarshalCertificate(over.MarshalSSZ(), p); err == nil {
		t.Fatal("this witness decodes, so it is not the accept/decode divergence under test")
	}
	wantRule(t, validity.Check(over, p), "V1")
}

// TestV1BoundsTheRetireList is the second conjunct of the same property. It
// runs against a parameter set whose max_writes is raised well above
// max_retire_addrs on purpose: on all three shipped networks the two are both
// 64, so an over-long retire list also exceeds max_writes and a test on
// shipped parameters would pass whether or not the retire bound exists.
//
// It drives CheckCanonical rather than Check, because a RETIRE of 64 one-shot
// targets cannot be authorised at all under max_sigs = 16 — V4 would refuse
// the at-limit witness for a reason that has nothing to do with this rule.
// CheckCanonical is the rule under test and Check runs it first, so a V1
// refusal here is a Check refusal.
func TestV1BoundsTheRetireList(t *testing.T) {
	p := spec.Devnet()
	wide := *p
	wide.MaxWrites = 4 * p.MaxRetireAddrs

	retire := func(n int) types.Program {
		addrs := make([]types.Address, n)
		for i := range addrs {
			addrs[i] = key(t, byte(1+i)).OneShot()
		}
		return wallet.Retire(addrs...)
	}

	atLimit := handBuilt(t, &wide, retire(wide.MaxRetireAddrs))
	if err := validity.CheckCanonical(atLimit, &wide); err != nil {
		t.Fatalf("%d retire targets is the limit and must be accepted: %v", wide.MaxRetireAddrs, err)
	}

	over := handBuilt(t, &wide, retire(wide.MaxRetireAddrs+1))
	if len(over.Writes) > wide.MaxWrites {
		t.Fatalf("this witness is refused by max_writes before the retire bound runs: %d writes (max %d)",
			len(over.Writes), wide.MaxWrites)
	}
	if _, err := types.UnmarshalCertificate(over.MarshalSSZ(), &wide); err == nil {
		t.Fatal("this witness decodes, so it is not the accept/decode divergence under test")
	}
	wantRule(t, validity.CheckCanonical(over, &wide), "V1")

	// The placement, on SHIPPED parameters rather than the widened set: there
	// max_retire_addrs and max_writes are both 64, so the same witness breaks
	// both bounds and only the order of the two checks decides which list the
	// refusal names. Both spell V1, so the rule id cannot separate them and
	// the message is the only evidence the operator gets.
	shipped := handBuilt(t, p, retire(p.MaxRetireAddrs+1))
	if len(shipped.Writes) <= p.MaxWrites {
		t.Fatalf("this witness no longer breaks max_writes too (%d writes, max %d), "+
			"so it cannot separate the two orderings", len(shipped.Writes), p.MaxWrites)
	}
	err := validity.CheckCanonical(shipped, p)
	wantRule(t, err, "V1")
	if !strings.Contains(err.Error(), "retire targets") {
		t.Fatalf("the refusal names the wrong list, so the specific bound does not run "+
			"before max_writes: %v", err)
	}
}
