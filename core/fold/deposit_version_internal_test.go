package fold

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
)

// TestF3RefusesTheBlockForANonUserDepositCell separates F3's address-version
// clause, the residual of the treasury seal.
//
// The clause cannot be reached through ApplyBlock and never will be: B0 runs
// validity.Check over every certificate before the fold sees one, and V4 (an
// unconditional authorising signature for Deposit.Cell.Addr) and V5 ("deposit
// cell is not owned by a user address") both refuse a 0x00 or 0x03 deposit cell
// first. So the input is delivered where the term lives — a direct
// applyCertificate call — the same choice core/validity's per-site inputs make,
// and it is why this file is inside the package.
//
// Two things are asserted per arm, and the second is the one the seal is about:
//
//   - the fold rejects the BLOCK, naming F3. Not Dropped, which is what F3's
//     other two refusals answer with. A burned underwriter and a balance that
//     moved are states an honest proposer can legitimately assemble against; a
//     non-user deposit cell is not, because two stateless rules refuse it, so
//     reaching this line means one of them regressed. Dropping would bill
//     nothing and still let the block stand on a premise already known broken.
//     That is F13's reasoning and this takes F13's answer.
//   - the deposit cell is not debited. The treasury is
//     types.NativeBalanceSlot(crypto.ProtocolAddress) — an ordinary native
//     balance cell — and F3 debits Deposit.Cell outside the declared write set,
//     so V7 and F13 never see the debit. This arm funds the treasury and
//     requires it to survive; delete the clause and the fold drains it.
func TestF3RefusesTheBlockForANonUserDepositCell(t *testing.T) {
	var asset crypto.Address
	asset[0] = crypto.AddrVersionAsset
	for i := 1; i < len(asset); i++ {
		asset[i] = 0x5a
	}
	if crypto.IsUserAddress(asset) {
		t.Fatal("the 0x03 fixture is a user address; the arm below tests nothing")
	}

	for _, arm := range []struct {
		what string
		addr types.Address
	}{
		{"the protocol address, whose balance cell is the treasury", crypto.ProtocolAddress},
		{"an asset address, where a key could exist but V5 still says no", asset},
	} {
		t.Run(arm.what, func(t *testing.T) {
			addr := arm.addr
			p, s, c := depositVersionFixture(t, &addr)

			before := s.Root()
			funded := s.Get(types.NativeBalanceSlot(arm.addr))
			if funded.IsZero() || funded.Lt(c.Deposit.Amount) {
				t.Fatalf("the fixture left %s under %x, which is below the deposit of %s: "+
					"a fold with the clause deleted would drop on balance instead of "+
					"debiting, and this test would pass for the wrong reason",
					funded.String(), arm.addr[:4], c.Deposit.Amount.String())
			}

			res := &Result{Undo: &state.UndoLog{}}
			j := &journal{s: s, log: res.Undo}
			seqBase := s.Get(types.SeqBaseFeeSlot())
			parBase := s.Get(types.ParBaseFeeSlot())

			out, tip, err := applyCertificate(j, c, c.ID(), p, seqBase, parBase, res)
			if err == nil {
				t.Fatalf("the fold accepted a certificate depositing from %x and returned "+
					"outcome %v; F3 refuses the block", arm.addr[:4], out.Outcome)
			}
			if got := Rule(err); got != "F3" {
				t.Fatalf("the refusal names rule %q, want %q — the id is a conformance "+
					"requirement a second implementation reads out of ARCHITECTURE §8",
					got, "F3")
			}
			if !errors.Is(err, ErrInvalidBlock) {
				t.Fatalf("the refusal does not wrap ErrInvalidBlock, so a caller cannot tell "+
					"it apart from an internal failure: %v", err)
			}
			if !tip.IsZero() {
				t.Fatalf("a refused certificate returned a tip of %s", tip.String())
			}

			if after := s.Get(types.NativeBalanceSlot(arm.addr)); after != funded {
				t.Fatalf("the deposit cell under %x moved from %s to %s: F3 reserved from a "+
					"non-user address, which is the drain this clause seals",
					arm.addr[:4], funded.String(), after.String())
			}
			if got := s.Root(); got != before {
				t.Fatalf("the state root moved to %x on a refused certificate; the refusal "+
					"must leave nothing behind", got[:8])
			}
			if len(res.Undo.Cells) != 0 || len(res.Undo.SpentAdded) != 0 ||
				len(res.Undo.SeenAdded) != 0 {
				t.Fatalf("the refusal journalled %d cells, %d spends and %d seen ids",
					len(res.Undo.Cells), len(res.Undo.SpentAdded), len(res.Undo.SeenAdded))
			}
		})
	}

	// The control. The same fixture with a 0x02 deposit cell must get through F3
	// and be billed, or the arms above are refusals of the fixture rather than
	// of the address version.
	t.Run("a persistent user address is untouched by the clause", func(t *testing.T) {
		p, s, c := depositVersionFixture(t, nil)

		res := &Result{Undo: &state.UndoLog{}}
		j := &journal{s: s, log: res.Undo}
		out, _, err := applyCertificate(j, c, c.ID(), p,
			s.Get(types.SeqBaseFeeSlot()), s.Get(types.ParBaseFeeSlot()), res)
		if err != nil {
			t.Fatalf("the fold refused an ordinary user deposit: %v", err)
		}
		if out.Outcome != Applied {
			t.Fatalf("the control certificate came out %v, want Applied; the arms above "+
				"would then be comparing against a certificate that fails anyway", out.Outcome)
		}
	})
}

// depositVersionFixture builds a certificate that is valid in every respect,
// then retargets its deposit cell at the given address. A nil address means
// "leave the signer's own persistent address in place", which is the control.
// It is a pointer and not a zero-value sentinel because the protocol address
// IS the zero address, and a sentinel that collides with one of the arms would
// have quietly turned that arm into a second copy of the control.
//
// The retarget happens after validity.Check, deliberately: the certificate the
// fold is handed is one no proposer could have assembled, which is exactly the
// premise the clause exists for. The check is still run, because a fixture that
// was invalid for some unrelated reason would prove nothing about F3.
func depositVersionFixture(t *testing.T, deposit *types.Address) (
	*params.Params, *state.State, *types.Certificate) {
	t.Helper()

	p := spec.Mainnet()
	p.GenesisTarget = u256.Max

	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 0x11
	priv := ed25519.NewKeyFromSeed(seed)
	var pub crypto.PubKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	from := crypto.DeriveAddress(crypto.AddrVersionPersistent, pub[:])

	dstSeed := make([]byte, ed25519.SeedSize)
	dstSeed[0] = 0x22
	dstPub := ed25519.NewKeyFromSeed(dstSeed).Public().(ed25519.PublicKey)
	to := crypto.DeriveAddress(crypto.AddrVersionPersistent, dstPub)

	prog := types.Program{
		Kind: types.ProgramTransfer,
		Transfer: &types.TransferArgs{Moves: []types.Move{{
			Asset: types.NativeAsset, Src: from, Dst: to, Amount: u256.FromUint64(1_000),
		}}},
	}
	reads, writes, err := validity.Derive(prog, p.ChainID, 0)
	if err != nil {
		t.Fatalf("deriving the fixture program: %v", err)
	}

	c := &types.Certificate{
		ChainID: p.ChainID,
		Program: prog,
		Reads:   reads,
		Writes:  writes,
		Deposit: types.Deposit{
			Cell:     types.NativeBalanceSlot(from),
			RefundTo: types.NativeBalanceSlot(from),
		},
		TTL: 240,
		FeeBid: types.FeeBid{
			SeqMax: u256.FromUint64(2_000), SeqPriority: u256.FromUint64(10),
			ParMax: u256.FromUint64(200), ParPriority: u256.FromUint64(10),
		},
		Sigs: []types.Sig{{PubKey: pub}},
	}
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		t.Fatal("the fixture's fee ceiling overflowed")
	}
	c.Deposit.Amount = ceiling

	var sig types.SigBytes
	copy(sig[:], ed25519.Sign(priv, c.SigningMessage(p)))
	c.Sigs[0].Sig = sig

	if err := validity.Check(c, p); err != nil {
		t.Fatalf("the fixture built an invalid certificate: %v", err)
	}

	funded := from
	if deposit != nil {
		c.Deposit.Cell = types.NativeBalanceSlot(*deposit)
		funded = *deposit
	}

	s := state.New()
	s.Set(types.SeqBaseFeeSlot(), p.InitialSeqBaseFee)
	s.Set(types.ParBaseFeeSlot(), p.InitialParBaseFee)
	s.Set(types.NativeBalanceSlot(from), ceiling.SatAdd(u256.FromUint64(1_000_000_000)))
	s.Set(types.NativeBalanceSlot(funded), ceiling.SatAdd(u256.FromUint64(1_000_000_000)))

	return p, s, c
}
