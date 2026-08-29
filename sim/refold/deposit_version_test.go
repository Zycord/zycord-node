package refold

import (
	"crypto/ed25519"
	"errors"
	"math/big"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
)

// TestF3RefusesTheBlockForANonUserDepositCellInThisFold is the port of
// core/fold's TestF3RefusesTheBlockForANonUserDepositCell.
//
// It exists for the reason the health-gate comparator and the jointly
// unexercised F12 zero-reward arm each established, rather than for symmetry.
// The differential runner cannot hold this clause in either fold: checkBlock
// runs validity.Check over every certificate before applyCert sees one, and V4
// and V5 both refuse a 0x00 or 0x03 deposit cell, so no block the runner can
// generate — or that any proposer can assemble — reaches the clause on either
// side. It is *jointly unexercised*, which from the outside looks exactly like
// two implementations agreeing.
//
// The clause is written here anyway because PROTOCOL rule 12 makes an F-rule a
// thing both folds state, and a clause present in one fold and absent in the
// other is the drift nothing would catch: the frozen corpus separates none of
// the rules a second implementation must reproduce. Writing it without pinning
// it would be worse than not writing it: an unreached clause that no test
// drives is a second implementation only on paper.
func TestF3RefusesTheBlockForANonUserDepositCellInThisFold(t *testing.T) {
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
			funded := new(big.Int).Set(s.Get(types.NativeBalanceSlot(addr)))
			amount := toBig(c.Deposit.Amount.Bytes())
			if funded.Cmp(amount) < 0 {
				t.Fatalf("the fixture left %s under %x, below the deposit of %s: a fold "+
					"with the clause deleted would drop on balance rather than debit, and "+
					"this test would pass for the wrong reason",
					funded.String(), addr[:4], amount.String())
			}

			res := &Result{Burned: big.NewInt(0)}
			out, tip, err := applyCert(s, c, p,
				toBig(p.InitialSeqBaseFee.Bytes()), toBig(p.InitialParBaseFee.Bytes()), res)
			if err == nil {
				t.Fatalf("this fold accepted a certificate depositing from %x and returned "+
					"outcome %v; F3 refuses the block", addr[:4], out.Outcome)
			}
			if got := Rule(err); got != "F3" {
				t.Fatalf("the refusal names rule %q, want %q — the whole point of a second "+
					"fold spelling the id is that it is a property of the protocol rather "+
					"than of core/fold's control flow", got, "F3")
			}
			if !errors.Is(err, ErrInvalidBlock) {
				t.Fatalf("the refusal does not wrap ErrInvalidBlock: %v", err)
			}
			if tip.Sign() != 0 {
				t.Fatalf("a refused certificate returned a tip of %s", tip.String())
			}

			if after := s.Get(types.NativeBalanceSlot(addr)); after.Cmp(funded) != 0 {
				t.Fatalf("the deposit cell under %x moved from %s to %s: F3 reserved from a "+
					"non-user address, which is the treasury drain this clause seals",
					addr[:4], funded.String(), after.String())
			}
			// Stated over the whole state and not only over one cell: this
			// package's own Root() must not be able to tell the result apart
			// from a state the certificate never touched.
			if got := s.Root(); got != before {
				t.Fatalf("the state root moved to %x on a refused certificate", got[:8])
			}
		})
	}

	// The control, without which the arms above would be refusals of the
	// fixture rather than of the address version.
	t.Run("a persistent user address is untouched by the clause", func(t *testing.T) {
		p, s, c := depositVersionFixture(t, nil)

		res := &Result{Burned: big.NewInt(0)}
		out, _, err := applyCert(s, c, p,
			toBig(p.InitialSeqBaseFee.Bytes()), toBig(p.InitialParBaseFee.Bytes()), res)
		if err != nil {
			t.Fatalf("this fold refused an ordinary user deposit: %v", err)
		}
		if out.Outcome != Applied {
			t.Fatalf("the control certificate came out %v, want Applied", out.Outcome)
		}
	})
}

// depositVersionFixture builds a certificate core/validity accepts, then
// retargets its deposit cell at the given address. A nil address leaves the
// signer's own persistent address in place, which is the control — a pointer
// rather than a zero-value sentinel because the protocol address IS the zero
// address, and a sentinel colliding with an arm would silently turn that arm
// into a second copy of the control.
func depositVersionFixture(t *testing.T, deposit *types.Address) (
	*params.Params, *State, *types.Certificate) {
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

	// Run the stateless rules on the fixture BEFORE the retarget. It is both a
	// check that nothing unrelated is wrong with it and the statement of why
	// the retarget has to happen here: after this line the certificate is one
	// no proposer could assemble, which is exactly the premise F3's clause
	// exists for.
	if err := validity.Check(c, p); err != nil {
		t.Fatalf("the fixture built an invalid certificate: %v", err)
	}

	funded := from
	if deposit != nil {
		c.Deposit.Cell = types.NativeBalanceSlot(*deposit)
		funded = *deposit
		if err := validity.Check(c, p); err == nil {
			t.Fatal("core/validity accepts the retargeted certificate, so V4/V5 no longer " +
				"refuse a non-user deposit cell and this clause is not dead code after all")
		}
	}

	balance := new(big.Int).Add(toBig(ceiling.Bytes()), big.NewInt(1_000_000_000))
	s := New()
	s.Set(types.NativeBalanceSlot(from), new(big.Int).Set(balance))
	s.Set(types.NativeBalanceSlot(funded), new(big.Int).Set(balance))

	return p, s, c
}
