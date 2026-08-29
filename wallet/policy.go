package wallet

import (
	"errors"
	"fmt"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
)

// The rules in docs/WALLET.md, as code.
//
// Every one of them describes a way to lose money or fees that the protocol
// permits — deliberately, because the alternative was worse — and that a wallet
// must therefore prevent. A wallet that only documents them has moved the
// problem to the user, so these are the functions the CLI actually calls
// (M1-G6).

// Policy violations. Each states what is lost and why the protocol permits it,
// and names the audit row or fold rule behind it where there is one, so a user
// who hits one can go and read the argument in this tree rather than trust the
// message.
var (
	ErrPartialOneShotSpend = errors.New(
		"wallet: spending part of a one-shot address strands the remainder forever (I1-L4); sweep the whole cell")
	ErrRefundToBurned = errors.New(
		"wallet: the refund destination has burned its authority, so the remainder would be burned (I1-M2)")
	ErrRefundToSpentHere = errors.New(
		"wallet: the refund destination is the one-shot this certificate burns (R1-C3-i)")
	ErrPayingUsedOneShot = errors.New(
		"wallet: this one-shot address has already been credited or spent; paying it again risks a billed skip (I1-H3)")
	ErrHeadroomExceedsBalance = errors.New(
		"wallet: the fee maximum reserves more than the balance holds; lower the headroom or shorten the TTL (R2-H1)")
	ErrBurnedResidualGoesElsewhere = errors.New(
		"wallet: this certificate burns a one-shot address of yours and refunds to an address you do not control; anything the sweep understates would be delivered to them (F8b sweeps the residual to RefundTo instead of destroying it)")
	ErrMoveExceedsBalance = errors.New(
		"wallet: this certificate moves more than the source cell holds, so the fold can only skip it; every node admits it and no producer gains by including it, so the likely end is eviction at TTL unseen — but nothing refuses a producer that includes it anyway, and the fold then burns the skip fee out of the deposit")
)

// CheckSweepsWholeCell enforces rule 1: a debit burns a one-shot address, so
// anything left under it is unreachable forever.
//
// The check is on the *program and the deposit*, before signing: everything a
// one-shot cell gives up — what the moves send, plus what the deposit reserves
// — must equal what the cell holds.
//
// The deposit is not a footnote to that sum, it is the whole of it for a
// program with no moves, and for a RETIRE the sum must already be zero. `ISSUE`, `MINT` and `RETIRE` move no value, so a
// one-shot address funding one of them is emptied only by the reservation
// itself (wallet.SweepDeposit) — and this rule used to return early for every
// program that was not a `TRANSFER`, which is exactly the set that could not
// use a one-shot deposit cell at all before F-VAL-5 was fixed. The moment
// they could, they could also strand a balance silently.
func CheckSweepsWholeCell(prog types.Program, deposit types.Deposit, s *state.State, p *params.Params, feeCeiling u256.U256) error {
	// What leaves each one-shot cell this certificate burns.
	leaving := make(map[types.Slot]u256.U256)
	// A RETIRE target is burned and nothing leaves it, so it must already hold
	// nothing. RETIRE exists to erase an address "the moment it has served"
	// (whitepaper §11) — retiring one that still holds a balance strands it
	// exactly as a partial spend would, and the fix is the same: sweep first,
	// retire after.
	if prog.Kind == types.ProgramRetire {
		for _, a := range prog.Retire.Addrs {
			leaving[types.NativeBalanceSlot(a)] = u256.Zero
		}
	}
	// The deposit cell's entry is an assignment rather than an addition, and it
	// comes after the retire targets on purpose: an address that is both is
	// emptied by the reservation, not required to be empty already.
	if deposit.Cell.Addr[0] == crypto.AddrVersionOneShot {
		leaving[deposit.Cell] = reservation(deposit, feeCeiling)
	}
	if prog.Kind == types.ProgramTransfer {
		for _, m := range prog.Transfer.Moves {
			if m.Src[0] != crypto.AddrVersionOneShot {
				continue
			}
			slot := types.BalanceSlot(m.Src, m.Asset)
			sum, overflow := leaving[slot].Add(m.Amount)
			if overflow {
				return fmt.Errorf("wallet: move amounts overflow")
			}
			leaving[slot] = sum
		}
	}

	for slot, out := range leaving {
		held := s.Get(slot)
		if !out.Eq(held) {
			return fmt.Errorf("%w: address %x holds %s, this certificate takes %s out",
				ErrPartialOneShotSpend, slot.Addr[:6], held.String(), out.String())
		}
	}
	return nil
}

// reservation is what the deposit will actually take out of its cell: the
// declared amount, or the fee ceiling that Build tops it up to when the caller
// left it short. Callers hold this number before the certificate exists, which
// is why it is not simply read off a built one.
func reservation(deposit types.Deposit, feeCeiling u256.U256) u256.U256 {
	if deposit.Amount.Lt(feeCeiling) {
		return feeCeiling
	}
	return deposit.Amount
}

// CheckBurnedResidualComesHome enforces the half of rule 1 that only became a
// rule when the chain stopped destroying residuals and began returning them to
// the certificate's refund address.
//
// F8b delivers whatever a burned one-shot address still holds to the
// certificate's single Deposit.RefundTo. A certificate may burn addresses
// belonging to *several* parties, and it has only one refund address — so a
// residual under my cell can be delivered to somebody else's.
//
// That is a new incentive rather than a new loss, and it is the reason this
// check exists. Before F8b the residual was destroyed and nobody gained by an
// understated sweep; now the holder of RefundTo gains exactly the
// understatement. A source node that understates a balance is precisely the
// case where the signer cannot see the understatement — their node lied about
// the balance — so CheckSweepsWholeCell agrees with the lie and passes. This
// check does not depend on any balance, which is what makes it useful against
// a lying node: it reads only the certificate's own bytes and the caller's own
// address set.
//
// The rule: if this certificate marks spent an address **I** control, then
// RefundTo must also be an address I control. Anything burned that is not
// mine is not my exposure — the party who owns it runs this same check with
// their own set and refuses on their own behalf.
//
// # It is a set and not a key, and that is the whole of the second revision
//
// The first version compared each burned address against the *same public key*
// RefundTo derives from. That is correct for a single-key wallet and wrong for
// the model the whitepaper describes: §4 has one-shot addresses "generated
// fresh per payment received", and §12's stealth outputs ride the same rail.
// The moment a wallet derives a per-payment key, a consolidating sweep burns
// cells belonging to several of its own keys and the same-key rule refuses it
// — forcing the change into persistent(K_payment), a fresh account per
// payment, which is exactly the linkage the one-shot rail exists to avoid.
// Membership of the wallet's own key set has no such edge and still refuses
// the understated-sweep shape, where the residual goes to a counterparty's
// key.
//
// owned is every address the caller can spend from. A caller that passes none
// is asserting it controls nothing, and nothing is checked — which is why
// CheckAll takes the set rather than letting it default.
func CheckBurnedResidualComesHome(c *types.Certificate, owned []types.Address) error {
	mine := func(a types.Address) bool {
		for _, o := range owned {
			if o == a {
				return true
			}
		}
		return false
	}
	if mine(c.Deposit.RefundTo.Addr) {
		return nil
	}
	for _, w := range c.Writes {
		if w.Op != types.OpMarkSpent || !mine(w.Slot.Addr) {
			continue
		}
		return fmt.Errorf("%w: %x burns, refund goes to %x",
			ErrBurnedResidualGoesElsewhere, w.Slot.Addr[:6], c.Deposit.RefundTo.Addr[:6])
	}
	return nil
}

// CheckRefundDestination enforces rule 2: the remainder must land somewhere the
// signer can still use.
//
// V5 already rejects refunding into the one-shot this certificate burns. What
// it cannot see is an address burned by an *earlier* certificate — the fold
// burns that remainder rather than writing it into a cell nobody can read.
//
// Precondition, and it fails OPEN when unmet: s must already know whether
// deposit.RefundTo.Addr is spent. state.State conflates absent with not-spent
// — MarkSpent is written only for addresses the caller learned about — so a
// refund destination the caller never fetched reads live and this rule passes
// on a question it never asked. session.View.CoversCertificate answers it
// beside the fetch, and session.settle runs that before any rule here.
func CheckRefundDestination(prog types.Program, deposit types.Deposit, s *state.State) error {
	if s.IsSpent(deposit.RefundTo.Addr) {
		return fmt.Errorf("%w: %x", ErrRefundToBurned, deposit.RefundTo.Addr[:6])
	}
	if prog.Kind == types.ProgramTransfer {
		for _, m := range prog.Transfer.Moves {
			if m.Src[0] == crypto.AddrVersionOneShot && m.Src == deposit.RefundTo.Addr {
				return fmt.Errorf("%w: %x", ErrRefundToSpentHere, m.Src[:6])
			}
		}
	}
	if prog.Kind == types.ProgramRetire {
		for _, a := range prog.Retire.Addrs {
			if a == deposit.RefundTo.Addr {
				return fmt.Errorf("%w: %x", ErrRefundToSpentHere, a[:6])
			}
		}
	}
	return nil
}

// CheckPayeeIsFresh enforces rule 3 from the sender's side: refuse to pay a
// one-shot address that is visibly already used.
//
// A one-shot address is for exactly one expected payment. Paying one that has
// already been credited means racing whatever the payee does next — and if they
// sweep or retire it, the payer is billed a skip (I1-H3, both the malicious and
// the good-faith variant). Persistent addresses are exempt: they can never be
// burned, so they have no such surface.
//
// Precondition, and it fails OPEN when unmet: s must already hold both answers
// this rule reads about each one-shot destination — its spent flag and its
// balance under the move's asset. Absent reads as not-spent and absent reads
// as zero, and zero is exactly the "fresh" answer, so an unfetched payee
// passes both clauses. That is the accept direction of the same
// absent-versus-zero conflation the balance reads carry.
// session.View.CoversCertificate answers it beside the fetch, and
// session.settle runs that before any rule here.
func CheckPayeeIsFresh(prog types.Program, s *state.State) error {
	if prog.Kind != types.ProgramTransfer {
		return nil
	}
	for _, m := range prog.Transfer.Moves {
		if m.Dst[0] != crypto.AddrVersionOneShot {
			continue
		}
		if s.IsSpent(m.Dst) {
			return fmt.Errorf("%w: %x is spent", ErrPayingUsedOneShot, m.Dst[:6])
		}
		if !s.Get(types.BalanceSlot(m.Dst, m.Asset)).IsZero() {
			return fmt.Errorf("%w: %x already holds a balance", ErrPayingUsedOneShot, m.Dst[:6])
		}
	}
	return nil
}

// CheckHeadroomAffordable enforces rule 5's accepted cost: the maximum is free
// in fees but not in reserved balance, so it must fit inside what the deposit
// cell actually holds.
//
// A signer who cannot afford a wide maximum should shrink the *window*, not the
// safety: sign with a short TTL and re-sign on expiry, trading lockup for
// latency. That is the escape hatch for small balances.
func CheckHeadroomAffordable(deposit types.Deposit, s *state.State, ceiling u256.U256) error {
	held := s.Get(deposit.Cell)
	if held.Lt(ceiling) {
		return fmt.Errorf("%w: the cell holds %s, the maximum reserves %s",
			ErrHeadroomExceedsBalance, held.String(), ceiling.String())
	}
	return nil
}

// CheckAll runs every applicable rule against a built certificate.
//
// Every rule here reads state out of s, and a caller holding a sparse state
// (session.View) cannot answer all of it. Adding a rule, or a read to an
// existing one, requires a matching axis in session.View.CoversCertificate, or
// the unfetched case reads as the benign answer and the rule passes on a
// question it never asked.
// TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis derives that set
// from this package's source and fails when the two drift apart. It keys on
// which functions CheckAll calls rather than on their names, and follows
// helpers into other files, because "rename it" and "move the read one file
// over" are otherwise silent escapes from a pin whose whole purpose is that a
// new read cannot be added quietly.
//
// It takes the finished certificate because the fee ceiling — which several
// rules need — is only known once the signature count is fixed.
// owned is every address the caller can spend from. It is a plain parameter
// rather than a variadic option, and the compiler enforcing that is the point:
// CheckBurnedResidualComesHome is *vacuous* when the set is empty, so a caller
// that omits it gets a green from a rule that never ran. A caller controlling
// nothing passes nil and says so; a caller that forgets does not compile.
func CheckAll(c *types.Certificate, s *state.State, p *params.Params, owned []types.Address) error {
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		return fmt.Errorf("wallet: fee ceiling overflows")
	}
	if err := CheckHeadroomAffordable(c.Deposit, s, ceiling); err != nil {
		return err
	}
	if err := CheckRefundDestination(c.Program, c.Deposit, s); err != nil {
		return err
	}
	if err := CheckPayeeIsFresh(c.Program, s); err != nil {
		return err
	}
	if err := CheckBurnedResidualComesHome(c, owned); err != nil {
		return err
	}
	if err := CheckSweepsWholeCell(c.Program, c.Deposit, s, p, ceiling); err != nil {
		return err
	}
	// Last, and that position is load-bearing rather than stylistic. This is
	// the one rule a caller may deliberately override (session.SendOptions.
	// Force, `zcd wallet send --force`), because a source cell funded by a
	// deposit that lands inside the TTL window is a legitimate act the wallet
	// cannot see the future of. A rule that could be overridden while
	// standing in front of the others would let that override skip them too,
	// since CheckAll stops at the first refusal. Running it last makes
	// "everything else passed" a fact about any error the caller is allowed
	// to swallow, rather than a claim in a comment.
	return CheckMovesAreCovered(c.Program, c.Deposit, s, ceiling)
}

// SweepAmount returns what a one-shot address must send to empty itself, given
// what the deposit will reserve. It is the number rule 1 requires, so that a
// caller never has to compute it and get it wrong.
func SweepAmount(from types.Address, asset types.Address, deposit types.Deposit, s *state.State, ceiling u256.U256) u256.U256 {
	held := s.Get(types.BalanceSlot(from, asset))
	if types.BalanceSlot(from, asset) == deposit.Cell {
		// The reservation, not the ceiling: a deposit that reserves more than
		// the ceiling takes more out of the cell, and a move sized against the
		// ceiling would then ask for more than the cell holds and skip.
		return held.SatSub(reservation(deposit, ceiling))
	}
	return held
}

// CheckMovesAreCovered enforces the balance half of "the wallet refuses what
// the network refuses".
//
// A transfer above the source's balance is not rejected by anything: it is
// structurally valid, it passes every V-rule, every node admits it, and the
// fold then *skips* it at whatever height it is included — so no producer
// gains by including it, and the observed behaviour is that none does. The
// certificate expires at TTL having told its signer nothing.
//
// "Having cost its signer nothing" would be the wrong way to finish that
// sentence, and the difference is the whole reason this is a refusal rather
// than a warning. No rule stops a producer from including it: F6's readsHold
// fails the GUARD_GE the transfer derives, or F7's stageWrites underflows,
// and either way the fold settles at p.SkipFee — burned out of the deposit,
// paid to nobody (whitepaper §5). Skipping is the outcome nobody profits
// from, not the outcome nobody can cause. The wallet already holds the number
// that settles it: the source
// balance is fetched on this same path for CheckHeadroomAffordable, and was
// simply never compared against the amount.
//
// The comparison is per balance cell rather than per move, and it adds the
// deposit's reservation to whichever cell pays it, because a source that is
// also the deposit cell gives up both and a move sized against the raw
// balance would skip on the reservation alone.
//
// It is a >= and not an == on purpose: CheckSweepsWholeCell is the rule that
// demands equality, and it demands it only where the debit burns the cell.
//
// Precondition, and it is the caller's to meet: s must already hold every
// cell this certificate debits. state.State deliberately conflates absent and
// zero — Set deletes on zero — so an unfetched cell reads as empty and this
// function refuses a certificate the chain would have covered, reporting the
// caller's own view as if it were the chain's. CheckHeadroomAffordable and
// CheckSweepsWholeCell have always had the same precondition; exporting this
// one is what makes it worth stating.
//
// The sharp edge is on the asset axis rather than the address one.
// session.FetchState writes only NativeBalanceSlot, so a Session view cannot
// represent a non-native asset cell at all, and the first multi-asset TRANSFER
// built through one would be refused here as if the source were empty. "This
// cell was never fetched" is not a question state.State can answer, so the
// answer cannot live in this function; it lives beside the fetch, as
// session.View.CoversCertificate, which session.settle runs before any rule
// here. A caller that assembles its own state.State — a test, or a full node —
// still owns the precondition stated above.
func CheckMovesAreCovered(prog types.Program, deposit types.Deposit, s *state.State, feeCeiling u256.U256) error {
	need := make(map[types.Slot]u256.U256)
	// Ordered so the refusal names the same cell every run: a map's iteration
	// order would make the message a coin flip when two cells are short.
	var order []types.Slot
	add := func(slot types.Slot, v u256.U256) error {
		sum, overflow := need[slot].Add(v)
		if overflow {
			return fmt.Errorf("wallet: what this certificate takes out of %x overflows 256 bits", slot.Addr[:6])
		}
		if _, seen := need[slot]; !seen {
			order = append(order, slot)
		}
		need[slot] = sum
		return nil
	}

	if err := add(deposit.Cell, reservation(deposit, feeCeiling)); err != nil {
		return err
	}
	if prog.Kind == types.ProgramTransfer {
		for _, m := range prog.Transfer.Moves {
			if err := add(types.BalanceSlot(m.Src, m.Asset), m.Amount); err != nil {
				return err
			}
		}
	}

	for _, slot := range order {
		want := need[slot]
		if held := s.Get(slot); held.Lt(want) {
			return fmt.Errorf("%w: address %x holds %s, this certificate takes %s out",
				ErrMoveExceedsBalance, slot.Addr[:6], held.String(), want.String())
		}
	}
	return nil
}
