package session

import (
	"errors"
	"fmt"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/wallet"
)

// ErrChainIDMismatch reports that a node's self-reported chain id disagrees
// with the network the caller asserted. The node's word was once the only
// source for which network a certificate signs for, so pointing a wallet at
// the wrong node signed for the wrong network with no error at all.
var ErrChainIDMismatch = errors.New("wallet: the node's chain id does not match the network this wallet is signing for")

// ErrBalanceSourcesDisagree reports that the second source reported something
// different from the first. Neither is known to be right; the point of asking
// a second, independent source at all is that agreement is the only signal
// available without becoming a full node, so disagreement is a hard refusal
// rather than a pick-one.
var ErrBalanceSourcesDisagree = errors.New(
	"wallet: two independent nodes report different balances for the source address; refusing rather than guessing which one to believe")

// ErrConfirmRPCNotIndependent reports that the second source names the
// endpoint the first one does. A node cross-checking itself agrees with itself
// for exactly the reason CheckSweepsWholeCell does, and every display
// downstream would go on to report an independent confirmation that never
// happened.
var ErrConfirmRPCNotIndependent = errors.New(
	"wallet: the confirming endpoint is the same as the primary one, so it is not a second source")

// ErrNotApproved reports that an irreversible one-shot drain reached the
// point of submission without an approval.
//
// The zero value of SendOptions.Approve is nil, and nil refuses. That is the
// direction the default has to fail in: a front end that forgets to ask
// cannot spend, whereas a front end that forgets to ask under an
// approve-by-default policy burns a cell and finds out afterwards.
var ErrNotApproved = errors.New("wallet: an irreversible one-shot drain was not approved; nothing was submitted")

// ErrNoKey reports a spend attempted on a read-only session.
var ErrNoKey = errors.New("wallet: this session holds no key")

// ErrNothingToSweep reports a sweep whose source cannot cover its own fees.
var ErrNothingToSweep = errors.New("wallet: nothing to sweep")

// Session is an unlocked key and the nodes it talks to.
//
// Key may be nil, which makes the session read-only: balances and status can
// be asked for, and every spending path refuses with ErrNoKey. `zcd wallet
// balance --addr` is exactly that case.
type Session struct {
	Key    *wallet.Key
	Params *params.Params

	primary *Client
	confirm *Client
}

// New builds a session. confirmRPC may be empty; if it is not, it must name a
// different endpoint from rpc.
//
// params is the caller's own assertion of which network this is, defaulting to
// mainnet like every other zcd command — never the node's self-reported
// chain_id, which every call below verifies against this rather than trusting
// outright.
func New(key *wallet.Key, p *params.Params, rpc, confirmRPC string) (*Session, error) {
	if p == nil {
		return nil, errors.New("wallet: a session needs a parameter set to sign against")
	}
	s := &Session{Key: key, Params: p, primary: NewClient(rpc)}
	if confirmRPC != "" {
		if SameEndpoint(rpc, confirmRPC) {
			return nil, fmt.Errorf("%w: both name %s", ErrConfirmRPCNotIndependent, rpc)
		}
		s.confirm = NewClient(confirmRPC)
	}
	return s, nil
}

// Primary is the node this session asks. Confirm is the second, independent
// source, or nil when none was named.
// Owned is every address this session can spend from.
//
// It is a set rather than a pair because that is what the wallet model is
// heading for: whitepaper §4 generates a one-shot address per payment
// received, and §12's stealth outputs ride the same rail, so a wallet that
// derives per-payment keys owns many. The reference session holds one key and
// therefore two addresses; a caller with more returns more, and every policy
// rule that asks "is this mine" keeps working unchanged.
func (s *Session) Owned() []types.Address {
	if s.Key == nil {
		return nil
	}
	return []types.Address{s.Key.OneShot(), s.Key.Persistent()}
}

func (s *Session) Primary() *Client { return s.primary }

// Confirm is the second, independent source, or nil.
func (s *Session) Confirm() *Client { return s.confirm }

// ConfirmURL is the second source's endpoint, or "" when there is none. It is
// what a prompt names; a caller should not have to nil-check to print it.
func (s *Session) ConfirmURL() string {
	if s.confirm == nil {
		return ""
	}
	return s.confirm.URL()
}

// AssertChainID refuses a node whose self-reported chain id disagrees with
// the network the caller asserted, and returns the height it reports.
//
// This runs against every node a wallet asks, not only the primary. The
// assertion is the operator's and it is about the network; a second node is
// not exempt from it just because its answers are only being used to check a
// first one's.
func (s *Session) AssertChainID(c *Client) (uint64, error) {
	status, err := c.Status()
	if err != nil {
		return 0, err
	}
	if status.ChainID != s.Params.ChainID {
		return 0, fmt.Errorf(
			"%w: %s reports chain id %d (%q), but this wallet is signing for %q (chain id %d); "+
				"assert the network you actually intend, or point the wallet at the right node — "+
				"a node's self-reported identity is never trusted on its own",
			ErrChainIDMismatch, c.URL(), status.ChainID, status.Network, s.Params.Name, s.Params.ChainID)
	}
	return status.Height, nil
}

// Balance reports what one address holds, having first asserted the network
// and — when a second source was named — cross-checked the answer against it.
//
// A balance is not less load-bearing for being printed rather than signed: it
// is the number an operator reads before deciding to sweep.
func (s *Session) Balance(a types.Address) (Balance, error) {
	height, err := s.AssertChainID(s.primary)
	if err != nil {
		return Balance{}, err
	}
	b, err := s.primary.Balance(a)
	if err != nil {
		return Balance{}, err
	}
	if s.confirm != nil {
		confirmHeight, err := s.AssertChainID(s.confirm)
		if err != nil {
			return Balance{}, fmt.Errorf("second source: %w", err)
		}
		if err := s.crossCheck(height, confirmHeight, a, b); err != nil {
			return Balance{}, err
		}
	}
	return b, nil
}

// View is everything a wallet needs from a node to build a certificate: the
// network it is signing for, where the chain is, what a block costs, and a
// sparse state.State holding the few cells the policy rules will read.
type View struct {
	Params      *params.Params
	Height      uint64
	SeqBase     u256.U256
	ParBase     u256.U256
	FromBalance u256.U256
	State       *state.State

	// The balance cells State can actually answer for. It is not derivable from
	// State: state.State conflates absent and zero — Set deletes on zero — so a
	// cell that was fetched and holds nothing is indistinguishable from one that
	// was never asked about.
	fetched map[types.Slot]struct{}

	// The addresses State can answer the SPENT FLAG for. A second set rather than
	// a second use of fetched, because they are different questions with
	// different keys: a balance is per (address, asset) cell and a spent flag is
	// per address, and the payee axis needs one of them for a cell whose asset
	// was never fetched. It is likewise not derivable from State: MarkSpent is
	// written only when a fetched address came back spent, so an address that was
	// fetched and is live is indistinguishable from one that was never asked
	// about.
	fetchedSpent map[types.Address]struct{}
}

// ErrCellNotFetched is returned when a policy rule would read a balance cell
// this view never asked a node about.
var ErrCellNotFetched = errors.New("wallet: this view holds no answer for a balance cell this certificate's rules read")

// ErrSpentFlagNotFetched is returned when a policy rule would read the spent
// flag of an address this view never asked a node about.
//
// It is a separate sentinel from ErrCellNotFetched because it is a separate
// question with a separate source: state.State conflates absent with zero for
// a balance, and absent with not-spent for a marker, and a view can hold the
// answer to one and not the other. A caller that treats them as one refusal
// cannot say which answer it is missing.
var ErrSpentFlagNotFetched = errors.New("wallet: this view holds no answer for whether an address this certificate's rules read is spent")

// CoversCertificate reports whether this view holds an answer for every state
// read wallet.CheckAll performs on this certificate.
//
// # What a session View promises
//
// A View is a sparse state.State plus the record of what was actually asked
// for. state.State cannot be honest on its own: Set deletes on zero, so an
// unfetched balance cell is indistinguishable from an empty one, and MarkSpent
// is written only for fetched addresses, so an unfetched address is
// indistinguishable from an unspent one. Both conflations have a direction,
// and the dangerous one is that "absent" reads as the benign answer: empty
// source, fresh payee, live refund address.
//
// The promise is therefore: for the certificate handed to this function, the
// view answers every question the policy rules ask of it, or it refuses and
// names the answer it does not hold. It is not "the view holds the whole
// state" and it is not "every rule is checked" — it is the closure of
// wallet.CheckAll's state reads over one certificate, enumerated below.
//
// An earlier version deliberately scoped this to DEBITED balance cells,
// because the phrasing it replaced ("the balance question every policy rule is
// about to ask") was false: the function did not answer for the payee. The
// payee is the surviving axis. The promise is widened here rather than a
// second entry point added, and one is right for the reason the narrow one was
// wrong: the failure being fixed is a rule reading a cell nobody checked was
// fetched. Two entry points mean settle can call one and forget the other,
// which is the same failure relocated into the call site. One entry point puts
// the composition inside the object that owns the fetched set, so a new axis
// is added next to the set that would have to grow anyway.
//
// # The enumeration, rule by rule
//
// Every state read in wallet.CheckAll, and the axis here that covers it:
//
//   - CheckHeadroomAffordable reads s.Get(deposit.Cell) — coversDebitedCells.
//   - CheckSweepsWholeCell reads the deposit cell, each one-shot TRANSFER move
//     source, and each RETIRE target — coversDebitedCells.
//   - CheckMovesAreCovered reads each move source and the deposit cell —
//     coversDebitedCells.
//   - CheckPayeeIsFresh reads s.IsSpent(m.Dst) and s.Get(BalanceSlot(m.Dst,
//     m.Asset)) for each one-shot TRANSFER destination — coversCreditedPayees.
//   - CheckRefundDestination reads s.IsSpent(RefundTo.Addr) —
//     coversRefundDestination.
//   - CheckBurnedResidualComesHome reads no state at all.
//
// # What holds the enumeration, and what does not
//
// The per-axis tests pin that each axis refuses on its own separating input.
// They cannot pin that the axes are COMPLETE: a rule added tomorrow that reads
// a cell no axis covers leaves every one of them green, which is the
// uncovered-read failure exactly, one round later and failing open again.
//
// So the enumeration above is pinned separately and structurally, by
// wallet.TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis. That test reads the
// source of every non-test file in package wallet, derives the rules CheckAll
// calls — by which functions it calls, not by what they are named — and every
// read each one performs on the state it is handed, following helpers across
// files, and compares the result against
// the table above. Adding a rule to CheckAll, or a read to an existing rule,
// fails it and names what must grow here. Keep the two in step: this comment
// is the prose form of that table, not an independent claim.
//
// What that does NOT do is make the conflation go away. state.State still
// cannot distinguish absent from zero, and the structural fix — making it able
// to — remains rejected for the reason it was rejected the first time: it
// changes the type every consensus path reads, with Set-deletes-on-zero
// load-bearing for the state root. What is pinned is that every read this
// wallet's rules perform has an answer here, not that a read elsewhere in the
// tree cannot be conflated.
//
// # Refusing is the honest outcome, not a temporary one
//
// FetchState asks a node for an address's native balance only, so a view
// cannot represent a non-native asset cell at all; a multi-asset TRANSFER is
// refused here rather than misreported by the balance rules, and a one-shot
// payee under a non-native asset is refused rather than read as fresh. The
// missing piece is a node query for an arbitrary (address, asset) cell. Until
// one exists a session cannot cover such a certificate, and a wallet that
// cannot check a rule must not pretend it passed.
func (v *View) CoversCertificate(c *types.Certificate) error {
	// In enumeration order, and within each axis in program order, so a
	// certificate with two unanswerable reads names the same one every run.
	if err := v.coversDebitedCells(c); err != nil {
		return err
	}
	if err := v.coversCreditedPayees(c); err != nil {
		return err
	}
	return v.coversRefundDestination(c)
}

// coversDebitedCells answers for the balance cells the certificate DEBITS: the
// deposit cell, a TRANSFER's move sources, and a RETIRE's targets.
//
// The RETIRE arm is the one that failed OPEN before this function covered it:
// wallet.CheckSweepsWholeCell requires each target's native cell to hold
// nothing, because retiring an address that still holds a balance strands it
// (whitepaper §11), and an unfetched cell reads zero, so a target missing from
// the fetch set was accepted and whatever it held was burned with the address.
func (v *View) coversDebitedCells(c *types.Certificate) error {
	if _, ok := v.fetched[c.Deposit.Cell]; !ok {
		return fmt.Errorf("%w: deposit cell of %s", ErrCellNotFetched, HexAddr(c.Deposit.Cell.Addr))
	}
	switch c.Program.Kind {
	case types.ProgramTransfer:
		for _, m := range c.Program.Transfer.Moves {
			if _, ok := v.fetched[types.BalanceSlot(m.Src, m.Asset)]; !ok {
				return fmt.Errorf("%w: %s under asset %s", ErrCellNotFetched, HexAddr(m.Src), HexAddr(m.Asset))
			}
		}
	case types.ProgramRetire:
		for _, a := range c.Program.Retire.Addrs {
			if _, ok := v.fetched[types.NativeBalanceSlot(a)]; !ok {
				return fmt.Errorf("%w: retire target %s", ErrCellNotFetched, HexAddr(a))
			}
		}
	}
	return nil
}

// coversCreditedPayees answers for the two cells wallet.CheckPayeeIsFresh
// reads on a one-shot TRANSFER destination.
//
// This is the axis the first version disclosed and did not close, and it fails
// OPEN in both of its clauses. A one-shot address serves exactly one expected
// payment (whitepaper §4); paying one that is already spent or already
// credited races whatever the payee does next and bills the payer a skip
// (I1-H3). An unfetched payee reads not-spent and reads zero, and zero is
// exactly the "fresh" answer, so the rule passed on a question it had never
// asked.
//
// The one-shot test mirrors CheckPayeeIsFresh's own exactly. A persistent
// destination can never be burned, so that rule reads nothing for it and this
// one must require nothing for it — a coverage check that fired for a payee no
// rule will read would refuse for a benign reason.
func (v *View) coversCreditedPayees(c *types.Certificate) error {
	if c.Program.Kind != types.ProgramTransfer {
		return nil
	}
	for _, m := range c.Program.Transfer.Moves {
		if m.Dst[0] != crypto.AddrVersionOneShot {
			continue
		}
		if _, ok := v.fetchedSpent[m.Dst]; !ok {
			return fmt.Errorf("%w: one-shot payee %s", ErrSpentFlagNotFetched, HexAddr(m.Dst))
		}
		if _, ok := v.fetched[types.BalanceSlot(m.Dst, m.Asset)]; !ok {
			return fmt.Errorf("%w: one-shot payee %s under asset %s", ErrCellNotFetched, HexAddr(m.Dst), HexAddr(m.Asset))
		}
	}
	return nil
}

// coversRefundDestination answers for the spent flag
// wallet.CheckRefundDestination reads on Deposit.RefundTo.
//
// The same conflation as the payee's spent clause and the same direction: an
// unfetched refund address reads not-spent, the rule passes, and the remainder
// of a burned one-shot is delivered into an address that has already burned
// its authority — the loss I1-M2 names. It is a third read rather than a
// second case of the payee's, and it is here because the promise above is the
// closure of the rules' reads, not a list of the ones already reported.
func (v *View) coversRefundDestination(c *types.Certificate) error {
	if _, ok := v.fetchedSpent[c.Deposit.RefundTo.Addr]; !ok {
		return fmt.Errorf("%w: refund destination %s", ErrSpentFlagNotFetched, HexAddr(c.Deposit.RefundTo.Addr))
	}
	return nil
}

// FetchState assembles the wallet's entire view of consensus state, and it
// comes from wherever the session's nodes say it does. That is an unavoidable
// trust relationship for a wallet that is not itself a full node — see the
// package doc on trust boundaries in wallet/policy.go — but two of its
// consequences are avoidable and are handled here:
//
//   - Chain identity is not accepted from a node's own /status answer. The
//     session's parameter set is the caller's own assertion, and a node whose
//     chain_id disagrees is refused outright.
//   - If a second source was named, every address's balance and spent flag is
//     asked of it too and must agree, or the call refuses. This is the one
//     check here that can actually catch a lying or lagging primary, because
//     it is the one check whose answer does not come from the primary — and it
//     covers not just the source balance CheckSweepsWholeCell trusts but the
//     spent flags CheckPayeeIsFresh and CheckRefundDestination trust too,
//     which are the same single-source problem in miniature.
//
// Neither defeats a single node that lies consistently and alone — nothing
// short of independent chain validation can — but both close off the specific
// silent failure modes above: signing for the wrong network, and believing a
// single node that understates a balance.
//
// Addresses are fetched in the order given and duplicates are asked for once.
// from is the first address; its balance is reported separately because it is
// the number a sweep is sized against.
func (s *Session) FetchState(addrs ...types.Address) (*View, error) {
	if len(addrs) == 0 {
		return nil, errors.New("wallet: FetchState needs at least the source address")
	}
	height, err := s.AssertChainID(s.primary)
	if err != nil {
		return nil, err
	}
	// The second source is asserted against the same network as the first.
	// Without this it is only a second *node*, not a second source for this
	// chain: a node on another network answers /balance for these addresses
	// from its own state, and the addresses are derived from a key rather
	// than from a chain, so they exist everywhere and read zero on a chain
	// that has never seen them. Two nodes agreeing that a payee is unspent
	// when one of them has simply never heard of it is agreement about
	// nothing, and it is agreement a prompt would go on to report as an
	// independent confirmation.
	var confirmHeight uint64
	if s.confirm != nil {
		confirmHeight, err = s.AssertChainID(s.confirm)
		if err != nil {
			return nil, fmt.Errorf("second source: %w", err)
		}
	}

	fees, err := s.primary.Fees()
	if err != nil {
		return nil, err
	}

	view := state.New()
	fetched := make(map[types.Slot]struct{}, len(addrs))
	fetchedSpent := make(map[types.Address]struct{}, len(addrs))
	var fromBalance u256.U256
	seen := make(map[types.Address]struct{}, len(addrs))
	for i, a := range addrs {
		if _, dup := seen[a]; dup {
			if i == 0 {
				fromBalance = view.Get(types.NativeBalanceSlot(a))
			}
			continue
		}
		seen[a] = struct{}{}

		b, err := s.primary.Balance(a)
		if err != nil {
			return nil, err
		}
		view.Set(types.NativeBalanceSlot(a), b.Value)
		fetched[types.NativeBalanceSlot(a)] = struct{}{}
		// Recorded whether or not the flag came back set: "this node told us the
		// address is live" is the answer CheckPayeeIsFresh and
		// CheckRefundDestination need, and it is exactly the answer MarkSpent does
		// not record.
		fetchedSpent[a] = struct{}{}
		if b.Spent {
			view.MarkSpent(a)
		}
		if i == 0 {
			fromBalance = b.Value
		}
		if s.confirm != nil {
			if err := s.crossCheck(height, confirmHeight, a, b); err != nil {
				return nil, err
			}
		}
	}

	return &View{
		Params:       s.Params,
		Height:       height,
		SeqBase:      fees.SeqBase,
		ParBase:      fees.ParBase,
		FromBalance:  fromBalance,
		State:        view,
		fetched:      fetched,
		fetchedSpent: fetchedSpent,
	}, nil
}

// crossCheck asks the second source for the same address and refuses unless
// both its balance and its spent flag match what the first source said.
//
// The heights are in the message because the likeliest cause of a disagreement
// is not a liar. Two honest nodes one block apart disagree about any address
// that moved in that block — and a sweep source is a one-shot address that has
// just been paid, so "the payment landed on one node and not yet on the other"
// is the *expected* reason to see this, not an edge case. Refusing is still
// right: the wallet cannot tell that case from a node that is lying or
// lagging, and only one of the two is recoverable by waiting. But an operator
// who can see the two heights can tell in a second, so the numbers go in the
// error rather than in a support thread.
func (s *Session) crossCheck(height, confirmHeight uint64, a types.Address, first Balance) error {
	second, err := s.confirm.Balance(a)
	if err != nil {
		return fmt.Errorf("wallet: second source %s: %w", s.confirm.URL(), err)
	}
	if second.Value.Eq(first.Value) && second.Spent == first.Spent {
		return nil
	}
	// Deliberately no verdict on *which* node is wrong, and none on whether
	// lag explains it. The heights were read from /status several round-trips
	// before these balances, so equal heights here do not mean the two
	// answers came from the same height — a node that advanced a block in
	// between reports the older height and the newer balance. An earlier
	// version of this message concluded "same height, so this is not lag: one
	// of them is wrong", and it fired against two honest nodes. A wallet
	// whose whole argument is that it must not print assurances it has not
	// verified does not get to print an accusation it has not verified
	// either.
	hint := "these heights were read before the balances, so they do not settle it; " +
		"the common cause is one node lagging the other, and a payment to a one-shot " +
		"address that has only reached one of them looks exactly like this — let them " +
		"converge and retry before concluding either is lying"
	return fmt.Errorf("%w: %s (height %d) says %x holds %s drops (spent=%v), %s (height %d) says %s drops (spent=%v) — %s",
		ErrBalanceSourcesDisagree,
		s.primary.URL(), height, a[:6], first.Value.String(), first.Spent,
		s.confirm.URL(), confirmHeight, second.Value.String(), second.Spent, hint)
}
