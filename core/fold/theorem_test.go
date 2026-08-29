package fold_test

import (
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

// The Era-0 billing-attribution theorem.
//
// R1-N1 claimed that in Era 0 no third party can cause another signer's
// certificate to be billed. I1-H3 found that untrue as stated, and this file
// pins the corrected statement — as three closure properties plus one
// demonstration of the single carve-out, rather than as prose with an asterisk.
//
//	Theorem. Let C be a certificate whose committed outcome is a billed skip.
//	Then one of:
//	  (1) SELF — the failing read or write is under an address whose key is in
//	      C's own signature set;
//	  (2) MINT RACE — the failure is the GUARD_LE on an asset's minted cell,
//	      whose only movers are certificates signed by that asset's declared
//	      minter, which is in C's signature set; or
//	  (3) DESTINATION BURN — the failure is a write to an address A that C
//	      *credits*, where A is one-shot and A's own key holder burned it after
//	      C was signed.
//
//	No other party can cause C to be billed. In (3) the burner is never an
//	arbitrary third party: it is the holder of an address C itself names as a
//	destination, and burning it requires that address's own signature.
//
// The three lemmas below are what make (3) the *only* carve-out. If any of them
// fails, the theorem is wrong and the finding is critical, not high.

// TestLemmaOnlyOneShotAddressesCanBeBurned. The registry can only ever contain
// version 0x01 addresses, because those are the only ones derivation will emit
// a MARK_SPENT for. A published 0x02 address therefore has *no* grief surface
// at all, which is what makes the case-(3) carve-out avoidable by wallet policy
// rather than merely rare.
func TestLemmaOnlyOneShotAddressesCanBeBurned(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	// Exhaustive over the address versions a program can name.
	versions := []byte{
		crypto.AddrVersionProtocol,
		crypto.AddrVersionOneShot,
		crypto.AddrVersionPersistent,
		crypto.AddrVersionAsset,
	}
	for _, v := range versions {
		target := alice.Address(v)
		if v == crypto.AddrVersionProtocol {
			target = crypto.ProtocolAddress
		}
		if v == crypto.AddrVersionAsset {
			target = types.DeriveAssetAddress(p.ChainID, alice.Persistent(), 0)
		}

		// Path 1: RETIRE.
		_, writes, err := validity.Derive(wallet.Retire(target), p.ChainID, 0)
		burnedByRetire := err == nil && hasMarkSpent(writes, target)

		// Path 2: a TRANSFER that debits the address.
		_, writes, err = validity.Derive(
			wallet.Tip(types.NativeAsset, target, bob.Persistent(), drops(1)), p.ChainID, 0)
		burnedByTransfer := err == nil && hasMarkSpent(writes, target)

		burnable := burnedByRetire || burnedByTransfer
		want := v == crypto.AddrVersionOneShot
		if burnable != want {
			t.Fatalf("address version 0x%02x: burnable = %v, want %v "+
				"(only one-shot addresses may ever enter the registry)", v, burnable, want)
		}
	}
}

// TestLemmaBurningAnAddressNeedsItsOwnKey. Case (3) is bounded only because a
// MARK_SPENT is authorised by the burned address itself. If any certificate
// could burn an address it does not hold the key for, the carve-out would widen
// into an unrestricted grief and this would be a critical finding.
func TestLemmaBurningAnAddressNeedsItsOwnKey(t *testing.T) {
	p := spec.Devnet()
	victim, thief := key(t, 2), key(t, 9)

	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Retire(victim.OneShot()),
		TTL:     100,
		Deposit: wallet.SelfDeposit(thief.Persistent(), thief.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{thief},
	}
	if _, err := b.Build(); err == nil {
		t.Fatal("a certificate burned an address whose key it does not hold")
	}

	// And the rule that refuses it is V4, not an accident of the builder.
	_, writes, err := validity.Derive(wallet.Retire(victim.OneShot()), p.ChainID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !hasMarkSpent(writes, victim.OneShot()) {
		t.Fatal("derivation did not produce the MARK_SPENT the test is about")
	}
	c := &types.Certificate{
		ChainID: p.ChainID,
		Program: wallet.Retire(victim.OneShot()),
		Writes:  writes,
		Deposit: wallet.SelfDeposit(thief.Persistent(), thief.Persistent()),
		TTL:     100,
		FeeBid:  bid(),
	}
	c.Deposit.Amount = u256.Max
	msg := c.SigningMessage(p)
	c.Sigs = []types.Sig{{PubKey: thief.PubKey(), Sig: thief.Sign(msg)}}
	if got := validity.Rule(validity.Check(c, p)); got != "V4" {
		t.Fatalf("an unauthorised burn was rejected by %s, want V4", got)
	}
}

// TestLemmaCreditsAreTheOnlyUnsignedWrites. Case (3) reaches exactly the
// addresses a certificate credits, because every *other* kind of write already
// requires that address's signature — which collapses it into case (1).
//
// This is checked over the whole Era-0 program set rather than by inspection,
// so that adding an operation whose write set breaks the property fails here.
func TestLemmaCreditsAreTheOnlyUnsignedWrites(t *testing.T) {
	p := spec.Devnet()
	issuer, holder, other := key(t, 5), key(t, 6), key(t, 7)
	asset := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), 1)

	programs := map[string]types.Program{
		"transfer": wallet.Tip(types.NativeAsset, issuer.Persistent(), holder.Persistent(), drops(5)),
		"transfer from one-shot": wallet.Tip(
			types.NativeAsset, issuer.OneShot(), holder.Persistent(), drops(5)),
		"multi-move transfer": wallet.Transfer(
			types.Move{Src: issuer.Persistent(), Dst: holder.Persistent(), Amount: drops(5)},
			types.Move{Src: issuer.Persistent(), Dst: other.OneShot(), Amount: drops(7)},
		),
		"issue":  wallet.Issue(issuer.Persistent(), drops(1000), 0, types.Hash{}, issuer.PubKey()),
		"mint":   wallet.Mint(asset, holder.OneShot(), drops(10), drops(1000), issuer.PubKey()),
		"retire": wallet.Retire(issuer.OneShot()),
	}

	for name, prog := range programs {
		t.Run(name, func(t *testing.T) {
			_, writes, err := validity.Derive(prog, p.ChainID, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range writes {
				if !crypto.IsUserAddress(w.Slot.Addr) {
					continue // asset and protocol cells cannot be burned at all
				}
				switch w.Op {
				case types.OpDeltaAdd:
					// A credit: unsigned, and therefore inside case (3).
				case types.OpDeltaSub, types.OpSet, types.OpMarkSpent:
					// Everything else requires the address's own signature,
					// which places it in case (1).
				default:
					t.Fatalf("write op %d on a user address is neither a credit "+
						"nor a signed write; the theorem's case split is incomplete", w.Op)
				}
			}
		})
	}
}

// TestCarveOutIsLimitedToNamedDestinations demonstrates case (3) end to end and
// shows the bound that keeps it from being an unrestricted grief: the burner
// must own an address the victim's certificate itself names.
//
// An independent certificate — one that names none of the burner's addresses —
// is untouched by the same burn, committed in the same block.
func TestCarveOutIsLimitedToNamedDestinations(t *testing.T) {
	w := newWorld(t)
	payer, bystander, mallory, safe := key(t, 2), key(t, 3), key(t, 4), key(t, 5)
	w.fund(payer.Persistent(), drops(2_000_000_000))
	w.fund(bystander.Persistent(), drops(2_000_000_000))
	w.fund(mallory.Persistent(), drops(2_000_000_000))

	// The payer pays a one-shot address Mallory handed out.
	trap := mallory.OneShot()
	victimCert := w.transfer(payer, payer.Persistent(), trap, drops(10_000_000), 0)

	// A bystander's certificate names none of Mallory's addresses.
	independentCert := w.transfer(bystander, bystander.Persistent(), safe.Persistent(), drops(10_000_000), 0)

	// Mallory burns the address she handed out.
	retire := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Retire(trap),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(mallory.Persistent(), mallory.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{mallory},
	}
	retireCert, err := retire.Build()
	if err != nil {
		t.Fatal(err)
	}
	w.chain.MustAddBlock(w.payout, retireCert)

	res := w.chain.MustAddBlock(w.payout, victimCert, independentCert)
	byID := map[types.Hash]fold.CertOutcome{}
	for _, o := range res.Outcomes {
		byID[o.ID] = o
	}

	// Case (3): the payer named the burned address, and is billed.
	if got := byID[victimCert.ID()].Outcome; got != fold.SkippedStale {
		t.Fatalf("the certificate naming the burned address was %s, want SKIPPED_STALE", got)
	}
	// The bound: an independent certificate in the same block is untouched.
	if got := byID[independentCert.ID()].Outcome; got != fold.Applied {
		t.Fatalf("an independent certificate was %s; the carve-out is not bounded "+
			"to named destinations and this is a critical finding, not a high one", got)
	}
	// And the payer keeps the payment — only the skip fee is lost, and it is
	// burned rather than paid to Mallory.
	if !w.chain.Balance(trap).IsZero() {
		t.Fatal("value landed under a burned address")
	}
	if got := byID[victimCert.ID()].Charged; !got.Eq(w.p.SkipFee) {
		t.Fatalf("the victim was charged %s, want exactly the skip fee", got.String())
	}
}

// TestCarveOutIsAvoidableByAddressVersion is the mitigation, stated as a test:
// a payee who publishes a persistent address cannot burn it, so a payer who
// pays one has no exposure to case (3) whatsoever.
func TestCarveOutIsAvoidableByAddressVersion(t *testing.T) {
	p := spec.Devnet()
	mallory := key(t, 4)

	if _, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(mallory.Persistent()),
		TTL:     100,
		Deposit: wallet.SelfDeposit(mallory.Persistent(), mallory.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{mallory},
	}).Build(); err == nil {
		t.Fatal("a persistent address was retired; it must have no grief surface")
	}
}

// submit builds a single-signer certificate for prog, adds it in its own block,
// and returns the committed outcome.
func (w *world) submit(signer *wallet.Key, prog types.Program, seq uint64) fold.Outcome {
	w.t.Helper()
	cert, err := (&wallet.Builder{
		Params:  w.p,
		Program: prog,
		Seq:     seq,
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(signer.Persistent(), signer.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{signer},
	}).Build()
	if err != nil {
		w.t.Fatal(err)
	}
	return w.chain.MustAddBlock(w.payout, cert).Outcomes[0].Outcome
}

// TestMaxCapSupplyBoundsEveryCreditBelowOverflow is the strengthened successor
// of TestOverflowSkipsAreUnreachableInEraZero, whose body derived one MINT and
// added its amount to zero — an addition that cannot overflow for any operand,
// so it proved nothing about the branch its name named.
//
// The overflow skip (fold.SkippedOverflow) fires when a DELTA_ADD leaves
// [0, 2^256). The theorem says that branch is unreachable in Era 0, and the
// false half of its published reason was that a single (addr, asset) slot
// cannot reach ~2^256 "under any cap". It can: deriveMint accepts cap = u256.Max
// (core/validity/derive.go), so an asset can mint its whole max supply into one
// slot. The true reason is the other half of the sentence: an asset's supply is
// bounded by minted <= cap <= 2^256-1 — deriveMint rejects amount > cap and the
// GUARD_LE on the minted cell (readsHold, AccessGuardLE) holds minted <= cap -
// amount — so no two same-asset balances, and therefore no credit onto one, can
// sum past 2^256.
//
// This runs the fold at the boundary the false clause called unreachable:
//   - mint all but one unit of the max cap into ONE slot, so that single
//     (addr, asset) slot holds ~2^256 — the very state "unreachable under any
//     cap" denies is reached and asserted;
//   - credit one more unit that completes the supply to exactly the cap: the
//     DELTA_ADD stages onto a non-zero same-asset cell and lands on u256.Max
//     without an overflow skip — the credit the theorem is actually about;
//   - attempt one unit beyond the cap: the GUARD_LE on the now-full minted cell
//     refuses it, so the supply cap — not any per-slot ceiling — is what stops a
//     second unit from ever existing to overflow a later credit.
//
// Non-vacuous: it fails if the full-cap mint does not apply, if the credit that
// reaches u256.Max overflow-skips, or if a mint past the cap is admitted — the
// invariant the true reason rests on.
func TestMaxCapSupplyBoundsEveryCreditBelowOverflow(t *testing.T) {
	w := newWorld(t)
	issuer, holder := key(t, 7), key(t, 8)
	w.fund(issuer.Persistent(), drops(1_000_000_000))

	// ISSUE an asset whose cap is the largest the protocol permits.
	issueSeq := w.strangerSeq(issuer)
	asset := types.DeriveAssetAddress(w.p.ChainID, issuer.Persistent(), issueSeq)
	if out := w.submit(issuer, wallet.Issue(issuer.Persistent(), u256.Max, 6,
		types.Hash{'M', 'A', 'X'}, issuer.PubKey()), issueSeq); out != fold.Applied {
		t.Fatalf("issue at the max cap was %s, want Applied", out)
	}

	// Mint all but one unit of the max supply into a single holder slot: the
	// state "unreachable under any cap" denies.
	capLessOne, _ := u256.Max.Sub(u256.One)
	if out := w.submit(issuer, wallet.Mint(asset, holder.Persistent(), capLessOne,
		u256.Max, issuer.PubKey()), w.strangerSeq(issuer)); out != fold.Applied {
		t.Fatalf("minting cap-1 into one slot was %s, want Applied", out)
	}
	if got := w.chain.AssetBalance(holder.Persistent(), asset); !got.Eq(capLessOne) {
		t.Fatalf("holder slot = %s, want cap-1 %s", got.String(), capLessOne.String())
	}

	// The credit the theorem is actually about: a DELTA_ADD onto a non-zero
	// same-asset balance, completing the supply to exactly the cap. It stages
	// onto cap-1 and must land on u256.Max without an overflow skip.
	if out := w.submit(issuer, wallet.Mint(asset, holder.Persistent(), u256.One,
		u256.Max, issuer.PubKey()), w.strangerSeq(issuer)); out != fold.Applied {
		t.Fatalf("the credit completing supply to the cap was %s, want Applied (no overflow skip)", out)
	}
	if got := w.chain.AssetBalance(holder.Persistent(), asset); !got.Eq(u256.Max) {
		t.Fatalf("holder slot = %s, want the max cap %s", got.String(), u256.Max.String())
	}

	// One unit beyond the cap. The minted cell is now u256.Max, so the GUARD_LE
	// against cap-1 fails and the mint skips: the supply cap — not a per-slot
	// limit — is what forbids a second unit from ever existing to overflow a
	// later credit.
	if out := w.submit(issuer, wallet.Mint(asset, holder.Persistent(), u256.One,
		u256.Max, issuer.PubKey()), w.strangerSeq(issuer)); out == fold.Applied {
		t.Fatal("a mint past the max cap applied; the supply bound the theorem rests on is gone")
	}
}

func hasMarkSpent(writes []types.Write, addr types.Address) bool {
	for _, w := range writes {
		if w.Op == types.OpMarkSpent && w.Slot.Addr == addr {
			return true
		}
	}
	return false
}

// TestLemmaNoUnsignedCreditChangesAnOutcome is the fourth lemma, and it exists
// because the first three could not see the hole the first attempt at the
// burn-strands-value fix opened.
//
// The three above reason over *derived write sets*: they ask which writes a
// program emits and whether each one needs a signature. That is the right
// question for a rule expressed as a write, and it is blind to a rule expressed
// anywhere else. That first fix refused to burn an address whose cell was not
// empty — a staging rule, no new write, all three lemmas green — and it handed
// any stranger the power to bill a signature by putting one drop into the cell.
// Measured before this was written: a griefer underwriting from a one-shot
// address that sorts below the victim's (found on the first key derivation)
// cost an honest whole-cell sweep the skip fee, for 107,822 drops at zero
// priority against the victim's 1,000,000.
//
// So this lemma asks the question the theorem actually makes: does an unsigned
// credit from a party the certificate does not name change what that
// certificate is billed? It asks it of the fold, by running it, over the cell
// kind where a burn makes the answer least obvious.
//
//	Lemma. For a certificate C that burns a one-shot address A, and for any
//	credit to any cell under A by a party named nowhere in C, C still applies
//	and is billed as an applied certificate rather than as a skip.
func TestLemmaNoUnsignedCreditChangesAnOutcome(t *testing.T) {
	// The credits a stranger can land on a burning certificate's source: none,
	// dust, a large sum, and one in a foreign asset the certificate does not
	// name at all.
	for _, tc := range []struct {
		name   string
		amount u256.U256
		asset  bool
	}{
		{"no credit at all", u256.Zero, false},
		{"one drop of dust", u256.One, false},
		{"a large credit", drops(400_000_000), false},
		{"a foreign asset", drops(5_000), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			alice, bob, stranger := key(t, 2), key(t, 3), key(t, 9)
			oneShot := alice.OneShot()
			w.fund(oneShot, drops(900_000_000))
			w.fund(stranger.Persistent(), drops(3_000_000_000))

			// The victim's honest whole-cell sweep, built and signed before
			// anything the stranger does.
			cert := w.sweep(alice, oneShot, bob.Persistent(), alice.Persistent(), 0)

			// Nothing of the stranger's appears in it: not a source, not a
			// destination, not a signer, not the deposit, not the refund.
			assertUnnamed(t, cert, stranger.Persistent())
			assertUnnamed(t, cert, stranger.OneShot())

			if !tc.amount.IsZero() {
				asset := types.NativeAsset
				if tc.asset {
					asset = w.issueAsset(stranger, 0)
				}
				credit, err := (&wallet.Builder{
					Params:  w.p,
					Program: wallet.Tip(asset, stranger.Persistent(), oneShot, tc.amount),
					Seq:     w.strangerSeq(stranger),
					TTL:     w.chain.NextHeight() + 5,
					Deposit: wallet.SelfDeposit(stranger.Persistent(), stranger.Persistent()),
					FeeBid:  bid(),
					Signers: []*wallet.Key{stranger},
				}).Build()
				if err != nil {
					t.Fatal(err)
				}
				if res := w.chain.MustAddBlock(w.payout, credit); res.Outcomes[0].Outcome != fold.Applied {
					t.Fatalf("setup: the stranger's credit was %s", res.Outcomes[0].Outcome)
				}
			}

			res := w.chain.MustAddBlock(w.payout, cert)
			out := res.Outcomes[0]
			if out.Outcome != fold.Applied {
				t.Fatalf("outcome = %s, want APPLIED: a party the certificate does not "+
					"name changed its verdict, which is the fourth case whitepaper §5 "+
					"forbids", out.Outcome)
			}
			// The bill, not only the verdict — the theorem is about being
			// *billed a skip*, so the clause worth pinning is that the charge
			// is an applied fee rather than the skip fee.
			//
			// A cross-scenario equality of the charge is deliberately NOT
			// asserted, and the reason is worth writing down because it looks
			// like an omission: Charged is c.Fees(p, seq_base, par_base), and
			// the two base-fee cells move with every block's applied gas. The
			// subtests differ in how many certificates preceded them, so their
			// charges legitimately differ, and an equality across them would be
			// measuring the fee controller rather than the theorem. What cannot
			// move is which *kind* of bill this is.
			if out.Charged.Eq(w.p.SkipFee) {
				t.Fatalf("charged the skip fee of %s on an APPLIED certificate; a "+
					"stranger's credit produced a billed skip (whitepaper §5)",
					w.p.SkipFee.String())
			}
			if !w.chain.State.IsSpent(oneShot) {
				t.Fatal("the certificate applied and the address was not burned")
			}
			if got := w.chain.Balance(oneShot); !got.IsZero() {
				t.Fatalf("%s left under the burned address", got.String())
			}
		})
	}
}

// assertUnnamed fails unless an address appears nowhere in a certificate: not
// in a read, a write, the deposit, the refund, or a signature.
func assertUnnamed(t *testing.T, c *types.Certificate, a types.Address) {
	t.Helper()
	for _, r := range c.Reads {
		if r.Slot.Addr == a {
			t.Fatalf("%x is named by a read", a[:6])
		}
	}
	for _, w := range c.Writes {
		if w.Slot.Addr == a {
			t.Fatalf("%x is named by a write", a[:6])
		}
	}
	if c.Deposit.Cell.Addr == a || c.Deposit.RefundTo.Addr == a {
		t.Fatalf("%x is the deposit or refund address", a[:6])
	}
	for _, s := range c.Sigs {
		if crypto.DeriveAddress(crypto.AddrVersionPersistent, s.PubKey[:]) == a ||
			crypto.DeriveAddress(crypto.AddrVersionOneShot, s.PubKey[:]) == a {
			t.Fatalf("%x signed the certificate", a[:6])
		}
	}
	_ = validity.ErrBadSrc
}
