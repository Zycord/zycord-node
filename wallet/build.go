package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
)

// Builder assembles one certificate.
//
// The reads and writes are never supplied by the caller: they are derived from
// the program, exactly as V3 will re-derive them. A wallet that could choose
// its own declared reads would be a wallet that could sign a lie.
type Builder struct {
	Params  *params.Params
	Program types.Program
	// Seq orders this signer's own certificates. Increment it for every
	// certificate that depends on a previous one — receive-then-spend,
	// spend-then-sweep — or the fold's tiebreak will order them by hash and the
	// dependent one will skip against its own predecessor (R1-C2).
	Seq uint64
	// TTL is the last height at which the certificate may commit. It must be at
	// most TTL_MAX blocks ahead of the height it lands at, or the block
	// carrying it is invalid (B2).
	TTL     uint64
	Deposit types.Deposit
	FeeBid  types.FeeBid
	Signers []*Key
}

// ErrNoSigners reports a certificate with nobody to authorise it.
var ErrNoSigners = errors.New("wallet: certificate needs at least one signer")

// Build derives, funds, signs and verifies a certificate.
//
// The deposit amount is raised to the certificate's fee ceiling if the caller
// left it short: under-reserving is the single most common way to build a
// certificate that V5 rejects, and the correct amount is computable from the
// certificate alone.
func (b *Builder) Build() (*types.Certificate, error) {
	if len(b.Signers) == 0 {
		return nil, ErrNoSigners
	}

	// DeriveCert, not Derive: a one-shot deposit cell burns on the debit the fold
	// performs for it, so its MARK_SPENT belongs to the write set even though no
	// program produced it. Deriving from the same function V3 checks against is
	// what keeps "a wallet cannot sign a lie" true of the deposit as well as of
	// the program.
	reads, writes, err := validity.DeriveCert(b.Program, b.Params.ChainID, b.Seq, b.Deposit.Cell.Addr)
	if err != nil {
		return nil, err
	}

	c := &types.Certificate{
		ChainID: b.Params.ChainID,
		Seq:     b.Seq,
		Program: b.Program,
		Reads:   reads,
		Writes:  writes,
		Deposit: b.Deposit,
		TTL:     b.TTL,
		FeeBid:  b.FeeBid,
	}

	// Signatures are fixed-width and excluded from the signed body, so
	// attaching placeholders of the right count fixes the encoded size — and
	// therefore the parallel gas and the fee ceiling — before anything is
	// signed. One pass suffices; there is no fixed point to iterate to.
	keys := dedupeKeys(b.Signers)
	c.Sigs = make([]types.Sig, len(keys))
	for i, k := range keys {
		c.Sigs[i] = types.Sig{PubKey: k.PubKey()}
	}

	ceiling, ok := c.FeeCeiling(b.Params)
	if !ok {
		return nil, errors.New("wallet: fee bid overflows 256 bits")
	}
	if c.Deposit.Amount.Lt(ceiling) {
		c.Deposit.Amount = ceiling
	}

	msg := c.SigningMessage(b.Params)
	for i, k := range keys {
		c.Sigs[i] = types.Sig{PubKey: k.PubKey(), Sig: k.Sign(msg)}
	}

	// Build only ever emits certificates the network would accept. A wallet
	// that ships an invalid certificate wastes the user's fee and the relay's
	// patience, and the check costs one verification the sender was going to
	// pay for anyway.
	if err := validity.Check(c, b.Params); err != nil {
		return nil, err
	}

	// And the network reads bytes, not structs. validity.Check is the rule set;
	// the codec is a second authority with rules of its own, and their
	// disagreement once looked like this: a certificate both the builder and the
	// validator accepted, that UnmarshalCertificate refused on every ingress path
	// there is — peer, RPC and block decode — so it could never reach a peer,
	// never be included, and never be explained.
	//
	// This is deliberately not a check for any particular rule. It asserts
	// the property directly: what Build emits, a peer can decode. A rule the
	// codec gains tomorrow is covered on the day it is added, with no second
	// finding needed here.
	if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), b.Params); err != nil {
		return nil, fmt.Errorf("wallet: built a certificate no peer could decode from its own encoding: %w", err)
	}
	return c, nil
}

// dedupeKeys returns the signers sorted by public key with duplicates removed,
// which is the canonical signature order.
func dedupeKeys(in []*Key) []*Key {
	out := make([]*Key, 0, len(in))
	seen := make(map[types.PubKey]struct{}, len(in))
	for _, k := range in {
		pub := k.PubKey()
		if _, ok := seen[pub]; ok {
			continue
		}
		seen[pub] = struct{}{}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].PubKey(), out[j].PubKey()
		for x := range a {
			if a[x] != b[x] {
				return a[x] < b[x]
			}
		}
		return false
	})
	return out
}

// SelfDeposit builds the ordinary Era-0 deposit: reserve from an address, and
// refund the remainder to a second one.
//
// The refund address must differ from the deposit address whenever the deposit
// address is one-shot — the certificate burns it, and settling into a burned
// cell would strand the remainder (R1-C3-i). It must also be an address the
// certificate does not mark spent anywhere else, which V5 now enforces in
// general rather than for the deposit cell alone.
//
// For a one-shot deposit cell, prefer SweepDeposit: the amount left unreserved
// in a cell this certificate burns is stranded, and SelfDeposit leaves the
// amount to Build's fee-ceiling top-up.
func SelfDeposit(from, refundTo types.Address) types.Deposit {
	return types.Deposit{
		Cell:     types.NativeBalanceSlot(from),
		RefundTo: types.NativeBalanceSlot(refundTo),
	}
}

// SweepDeposit is the deposit a one-shot cell must use: it reserves the cell's
// whole native balance, so the certificate that burns the address also empties
// it.
//
// Reserving only the fee ceiling out of a one-shot cell is the expensive
// mistake, and it is expensive silently. The certificate marks the address
// spent (V6) — a signature from its key moves the cell to spent, permanently
// (whitepaper §4) — and whatever the reservation did not take stays in a cell
// no signature can ever open again, on a certificate that reports APPLIED.
// Reserving the whole balance costs nothing: settlement charges the actual fee
// and refunds the remainder to refundTo inside the same fold step (§10), so
// the liquidity is locked for one certificate lifetime either way.
//
// balance is the deposit cell's native balance as the caller last observed it.
// Over-reserving against a stale balance is the safe direction — a certificate
// whose deposit cell no longer covers the reservation is *dropped*, not
// billed, and is free to resubmit (§5) — while under-reserving is what strands
// funds.
//
// A persistent deposit cell needs none of this: it survives the certificate,
// so SelfDeposit is the right constructor for it.
func SweepDeposit(from, refundTo types.Address, balance u256.U256) types.Deposit {
	d := SelfDeposit(from, refundTo)
	d.Amount = balance
	return d
}

// Bid builds a fee bid from a maximum and a priority price in each market.
//
// Set the maxima generously and the priorities to what the ordering is actually
// worth. The maximum is a solvency bound — once the base fee passes it the
// certificate is unincludable (B4) and must be re-signed — while the priority
// is what a miner is paid. Raising the maximum costs nothing unless the market
// moves into it (R2-H1), so under-setting it is the expensive mistake and
// over-setting it is free.
func Bid(seqMax, seqPriority, parMax, parPriority u256.U256) types.FeeBid {
	return types.FeeBid{
		SeqMax:      seqMax,
		SeqPriority: seqPriority,
		ParMax:      parMax,
		ParPriority: parPriority,
	}
}

// BidWithHeadroom is the ordinary wallet path: name a priority in each market
// and let the maximum be a multiple of the base fee large enough to survive the
// certificate's whole TTL window.
//
// The multiple is the signer's tolerance for being stranded, and it is free.
func BidWithHeadroom(seqBase, parBase, seqPriority, parPriority u256.U256, headroom uint64) types.FeeBid {
	seqMax, _ := seqBase.Mul(u256.FromUint64(headroom))
	parMax, _ := parBase.Mul(u256.FromUint64(headroom))
	seqMax = seqMax.SatAdd(seqPriority)
	parMax = parMax.SatAdd(parPriority)
	return Bid(seqMax, seqPriority, parMax, parPriority)
}

// Transfer builds a TRANSFER program with its moves in canonical order.
//
// The protocol imposes no order on moves — reordering them derives the same
// reads and writes — so two orderings are two certificates with two ids and one
// effect. That is not a consensus problem: reordering changes the body and
// therefore invalidates every signature, so only a signer can produce a
// variant, which is indistinguishable from that signer authorising a second
// payment. Each has its own deposit and its own bill, and the billing law is
// untouched (R2-M2).
//
// It is a *wallet* problem. Sorting here means a retry of the same logical
// payment reproduces the same certificate id, so a wallet can tell "already
// sent" from "sent twice".
//
// Sorting is now the whole of it, and it did not used to be. The id covered
// the signature list, so this idempotency also rested on the signer being
// deterministic — a property no consensus rule stated, that spec/wire.md never
// told an independent implementation about, and that an HSM or any hedged
// signer is free to break. A wallet that randomised its Ed25519 nonce turned
// every retry of a stuck payment into a second payment, with no attacker
// anywhere. The id's preimage now excludes the signatures, so a retry
// re-signed at a fresh nonce is the same id and the network refuses it as the
// duplicate it is. Idempotency is a property the protocol does provide, and it
// provides it for every wallet rather than for the careful ones.
func Transfer(moves ...types.Move) types.Program {
	sorted := append([]types.Move(nil), moves...)
	sort.Slice(sorted, func(i, j int) bool { return moveLess(sorted[i], sorted[j]) })
	return types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{Moves: sorted}}
}

// moveLess orders moves by asset, then source, then destination, then amount.
func moveLess(a, b types.Move) bool {
	if c := bytes.Compare(a.Asset[:], b.Asset[:]); c != 0 {
		return c < 0
	}
	if c := bytes.Compare(a.Src[:], b.Src[:]); c != 0 {
		return c < 0
	}
	if c := bytes.Compare(a.Dst[:], b.Dst[:]); c != 0 {
		return c < 0
	}
	return a.Amount.Lt(b.Amount)
}

// Tip is the network's native verb: a single move, most often into a fresh
// cell, which costs the fold one commutative addition and can never conflict.
func Tip(asset, from, to types.Address, amount u256.U256) types.Program {
	return Transfer(types.Move{Asset: asset, Src: from, Dst: to, Amount: amount})
}

// Issue builds an ISSUE program. The asset address it will create is
// types.DeriveAssetAddress(chainID, issuer, seq).
func Issue(issuer types.Address, cap u256.U256, decimals uint8, symbol types.Hash, minter types.PubKey) types.Program {
	return types.Program{Kind: types.ProgramIssue, Issue: &types.IssueArgs{
		Issuer:     issuer,
		Cap:        cap,
		SymbolHash: symbol,
		Minter:     minter,
		Decimals:   decimals,
	}}
}

// Mint builds a MINT program. Cap and minter are the declared values of the
// asset's immutable cells; the fold's exact-match check is what makes the
// declaration binding.
func Mint(asset, dst types.Address, amount, cap u256.U256, minter types.PubKey) types.Program {
	return types.Program{Kind: types.ProgramMint, Mint: &types.MintArgs{
		Asset:  asset,
		Dst:    dst,
		Amount: amount,
		Cap:    cap,
		Minter: minter,
	}}
}

// Retire builds a RETIRE program over one-shot addresses the caller owns. The
// list is sorted and deduplicated, because canonical form is not the caller's
// problem to remember.
func Retire(addrs ...types.Address) types.Program {
	sorted := make([]types.Address, 0, len(addrs))
	seen := make(map[types.Address]struct{}, len(addrs))
	for _, a := range addrs {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		sorted = append(sorted, a)
	}
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		for x := range a {
			if a[x] != b[x] {
				return a[x] < b[x]
			}
		}
		return false
	})
	return types.Program{Kind: types.ProgramRetire, Retire: &types.RetireArgs{Addrs: sorted}}
}
