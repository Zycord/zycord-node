package session

import (
	"errors"
	"fmt"

	"zycord/core/crypto"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/wallet"
)

// Default bid and window. Every interface starts from these, so the CLI and
// the graphical front ends cannot drift into offering different defaults for
// the same act.
const (
	// DefaultHeadroom is the fee maximum as a multiple of the current base
	// fee. It is free in fees and reserved from balance, so under-setting it
	// is the expensive mistake (R2-H1).
	DefaultHeadroom = 8
	// DefaultTTL is how many blocks ahead a certificate may commit.
	DefaultTTL = 30
)

// DefaultSendOptions is the starting point for a spend. A caller adjusts what
// it means to adjust and leaves the rest alone; nothing here is filled in
// silently by Send, so a front end that forgets a field gets an error rather
// than a number somebody else chose.
func DefaultSendOptions() SendOptions {
	return SendOptions{
		Headroom: DefaultHeadroom,
		TTL:      DefaultTTL,
		SeqTip:   u256.FromUint64(100),
		ParTip:   u256.FromUint64(5),
	}
}

// SendOptions is everything about a spend that is not "who gets how much".
type SendOptions struct {
	// From is the address being spent. The zero value means the key's
	// persistent address.
	From types.Address
	// Refund is where the deposit's remainder lands. The zero value means the
	// key's persistent address, which can never be burned and so can always
	// receive it (docs/WALLET.md rule 2).
	Refund types.Address
	// OneShot selects the key's one-shot address as the source. It is ignored
	// when From is set explicitly.
	OneShot bool
	// Sweep computes the amount instead of taking it: a one-shot source must
	// move its whole balance, because a debit burns it and anything left is
	// unreachable (rule 1).
	Sweep bool

	// Seq orders this signer's own dependent certificates (R1-C2).
	Seq uint64
	// TTL is how many blocks ahead of the node's height the certificate may
	// commit. Zero is refused rather than defaulted.
	TTL uint64
	// Headroom is the fee maximum as a multiple of the base fee. Zero is
	// refused rather than defaulted.
	Headroom uint64
	// SeqTip and ParTip are the priority prices, in drops per gas. Zero is a
	// legitimate choice — it buys no priority — so it is taken literally.
	SeqTip u256.U256
	ParTip u256.U256

	// DryRun builds and checks but never submits.
	DryRun bool

	// Force proceeds despite wallet.ErrMoveExceedsBalance, and despite
	// nothing else. It exists because "the source cannot cover this today" is
	// not the same statement as "this certificate is dead": a deposit landing
	// inside the TTL window makes it apply, and a wallet that refused it
	// outright would be refusing a legitimate act on the strength of a
	// snapshot.
	//
	// What it can bypass is exactly one of this wallet's own courtesy checks.
	// It cannot bypass anything the network enforces — every V-rule still
	// runs inside Builder.Build, the codec round-trip still runs, and the
	// chain-id assertion, the fee-reserve refusal (R2-H1) and the one-shot
	// drain approval are all untouched. A forced certificate is a valid
	// certificate that may skip; it is not an invalid one.
	//
	// A skip is not free, and a caller exposing this must say so. Nothing
	// stops a producer from including a certificate that will skip, and the
	// fold settles that at params.SkipFee, burned out of the deposit. The
	// override trades a certain refusal for a possible burned fee, which is a
	// trade only the person holding the key can make.
	Force bool

	// OnPreview, if set, is called once the certificate is built and every
	// policy rule has passed, before anything irreversible. A front end
	// renders the numbers here. Returning an error aborts without submitting.
	OnPreview func(*Preview) error

	// Approve is the gate in front of an irreversible one-shot drain. It is
	// called only when the certificate burns a one-shot source, and only
	// after OnPreview. A nil Approve refuses: see ErrNotApproved for why that
	// is the direction the default fails in.
	Approve func(*Preview) error
}

// Preview is the whole of what a caller needs to show a person before an
// irreversible act, and the whole of what it needs to report afterwards.
//
// Everything on it that a node supplied is marked as such by PrimaryURL: the
// payee and the refund address come from the caller and the key, so nothing a
// node says can change them. That is the point — this is where an operator
// compares the entire act against what they meant to do.
type Preview struct {
	Cert   *types.Certificate
	ID     types.Hash
	From   types.Address
	To     types.Address
	Refund types.Address

	// Amount is what the program moves. Held is what the primary node says
	// the source cell holds. Ceiling is what the deposit reserves and is
	// refunded within the same block; FeeNow is what the certificate costs at
	// the base fees in force, of which Tip is the producer's.
	Amount  u256.U256
	Held    u256.U256
	FeeNow  u256.U256
	Tip     u256.U256
	Ceiling u256.U256

	// Height is the node's height at build time; TTL is the last height this
	// certificate may commit at.
	Height uint64
	TTL    uint64

	// Underfunded is set when the source cell does not cover what this
	// certificate takes out of it and SendOptions.Force let it through anyway. A
	// front end that renders a preview without saying so is reporting a spend
	// that can only skip as an ordinary one, which is the whole point of carrying
	// it.
	Underfunded error

	// OneShotDrain is true when applying this certificate burns the source
	// address. It is the condition Approve is gated on, and it is a property of
	// the certificate rather than of which subcommand built it: `send --one-shot`
	// at the draining amount is the identical certificate `sweep` produces, and
	// must get the identical gate.
	OneShotDrain bool

	// PrimaryURL is the node every number above that came from a node came
	// from. ConfirmURL is the second, independent source, or "" when there
	// was none — a prompt that claims an independent confirmation must be
	// able to name it.
	PrimaryURL string
	ConfirmURL string
}

// Result is what a spend did.
type Result struct {
	*Preview
	Submitted bool
}

// Send builds, checks, previews, approves and submits a transfer.
//
// This is the one spending path in the system. `zcd wallet send`, `zcd
// wallet sweep`, `zcd ui` and the desktop application all arrive here, so
// wallet.CheckAll — and with it every rule in docs/WALLET.md — runs for all of
// them or for none of them.
func (s *Session) Send(to types.Address, amount u256.U256, opts SendOptions) (*Result, error) {
	if s.Key == nil {
		return nil, ErrNoKey
	}
	if opts.TTL == 0 {
		return nil, fmt.Errorf("wallet: a TTL of 0 would only be includable at the current height; start from DefaultSendOptions")
	}
	if opts.Headroom == 0 {
		return nil, fmt.Errorf("wallet: a headroom of 0 leaves the fee maximum at the priority price alone; start from DefaultSendOptions")
	}

	from := opts.From
	if from == (types.Address{}) {
		from = s.Key.Persistent()
		if opts.OneShot {
			from = s.Key.OneShot()
		}
	}
	refund := opts.Refund
	if refund == (types.Address{}) {
		refund = s.Key.Persistent()
	}
	if from[0] == crypto.AddrVersionOneShot && refund == from {
		return nil, fmt.Errorf("the refund address must differ from the one-shot being spent (R1-C3-i)")
	}

	view, err := s.FetchState(from, to, refund)
	if err != nil {
		return nil, err
	}
	bid := wallet.BidWithHeadroom(view.SeqBase, view.ParBase, opts.SeqTip, opts.ParTip, opts.Headroom)

	build := func(amount u256.U256) (*types.Certificate, error) {
		b := &wallet.Builder{
			Params:  view.Params,
			Program: wallet.Tip(types.NativeAsset, from, to, amount),
			Seq:     opts.Seq,
			TTL:     view.Height + opts.TTL,
			Deposit: wallet.SelfDeposit(from, refund),
			FeeBid:  bid,
			Signers: []*wallet.Key{s.Key},
		}
		return b.Build()
	}

	if opts.Sweep {
		// Size the sweep against the ceiling, which needs a certificate to
		// exist first. One probe with a placeholder amount fixes the size,
		// and therefore the ceiling, because signatures are fixed-width.
		probe, err := build(u256.One)
		if err != nil {
			return nil, err
		}
		ceiling, ok := probe.FeeCeiling(view.Params)
		if !ok {
			return nil, fmt.Errorf("fee ceiling overflows")
		}
		amount = view.FromBalance.SatSub(ceiling)
		if amount.IsZero() {
			return nil, fmt.Errorf("%w: the balance of %s does not exceed the fee ceiling of %s",
				ErrNothingToSweep, view.FromBalance.String(), ceiling.String())
		}
	}

	cert, err := build(amount)
	if err != nil {
		return nil, err
	}
	return s.settle(cert, view, from, to, refund, amount, opts)
}

// Retire burns the signing authority of one-shot addresses this key owns,
// which is how state stops carrying a cell that has served (whitepaper §11).
//
// The deposit is paid from the key's persistent address, never from an
// address being retired: a RETIRE moves no value, so a one-shot funding one
// is emptied by the reservation alone, and wallet.CheckSweepsWholeCell
// requires every retired address to hold nothing already. Sweep first, retire
// after.
func (s *Session) Retire(addrs []types.Address, opts SendOptions) (*Result, error) {
	if s.Key == nil {
		return nil, ErrNoKey
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("wallet: retire needs at least one address")
	}
	if opts.TTL == 0 || opts.Headroom == 0 {
		return nil, fmt.Errorf("wallet: retire needs a TTL and a headroom; start from DefaultSendOptions")
	}
	for _, a := range addrs {
		if a[0] != crypto.AddrVersionOneShot {
			return nil, fmt.Errorf("wallet: %s is not a one-shot address; only one-shot addresses can be retired", HexAddr(a))
		}
	}

	from := s.Key.Persistent()
	refund := opts.Refund
	if refund == (types.Address{}) {
		refund = from
	}

	// The deposit cell and every address whose spent flag the rules will read.
	want := append([]types.Address{from, refund}, addrs...)
	view, err := s.FetchState(want...)
	if err != nil {
		return nil, err
	}

	b := &wallet.Builder{
		Params:  view.Params,
		Program: wallet.Retire(addrs...),
		Seq:     opts.Seq,
		TTL:     view.Height + opts.TTL,
		Deposit: wallet.SelfDeposit(from, refund),
		FeeBid:  wallet.BidWithHeadroom(view.SeqBase, view.ParBase, opts.SeqTip, opts.ParTip, opts.Headroom),
		Signers: []*wallet.Key{s.Key},
	}
	cert, err := b.Build()
	if err != nil {
		return nil, err
	}
	return s.settle(cert, view, from, types.Address{}, refund, u256.Zero, opts)
}

// settle is the shared tail of every spending path: run every policy rule,
// show the caller what it is about to do, gate an irreversible drain behind an
// explicit approval, and only then submit.
//
// Nothing above this point submits, and nothing below it skips a check. A
// front end that wants to add a step adds it in the callbacks; it cannot
// remove one.
func (s *Session) settle(cert *types.Certificate, view *View, from, to, refund types.Address, amount u256.U256, opts SendOptions) (*Result, error) {
	// The key set, not just the two addresses this path used: rule 1's residual
	// clause asks whether the refund comes home, and "home" is everything this
	// wallet can spend from. Force narrows to one sentinel, and CheckAll runs the
	// rule it names last, so an error that survives this is proof the other rules
	// passed rather than proof they were skipped.
	//
	// Before any of them: the rules read balances out of view.State, and
	// state.State cannot distinguish a cell that holds nothing from one this
	// view never fetched.
	//
	// First rather than last, and the reason is the non-force path. Placed after
	// CheckAll this check would still fire and still refuse — settle returns on
	// it instead of folding it into underfunded, so Force does not reach past it
	// either way. What placement decides is which rule gets to answer: the
	// balance rules run on the same conflated state and refuse an unfetched cell
	// as ErrMoveExceedsBalance, misattributing the wallet's own blind spot to the
	// chain and telling a user their funded address is empty. Ask the view what
	// it can answer for first, so the refusal names the wallet.
	if err := view.CoversCertificate(cert); err != nil {
		return nil, err
	}
	underfunded := error(nil)
	if err := wallet.CheckAll(cert, view.State, view.Params, s.Owned()); err != nil {
		if !opts.Force || !errors.Is(err, wallet.ErrMoveExceedsBalance) {
			return nil, err
		}
		underfunded = err
	}
	charge, _, tip, _ := cert.Fees(view.Params, view.SeqBase, view.ParBase)
	ceiling, _ := cert.FeeCeiling(view.Params)

	p := &Preview{
		Cert:         cert,
		ID:           cert.ID(),
		From:         from,
		To:           to,
		Refund:       refund,
		Amount:       amount,
		Held:         view.State.Get(types.NativeBalanceSlot(from)),
		FeeNow:       charge,
		Tip:          tip,
		Ceiling:      ceiling,
		Height:       view.Height,
		TTL:          cert.TTL,
		OneShotDrain: from[0] == crypto.AddrVersionOneShot,
		Underfunded:  underfunded,
		PrimaryURL:   s.primary.URL(),
		ConfirmURL:   s.ConfirmURL(),
	}
	if opts.OnPreview != nil {
		if err := opts.OnPreview(p); err != nil {
			return nil, err
		}
	}
	if opts.DryRun {
		return &Result{Preview: p}, nil
	}

	// A one-shot drain is the case --confirm-rpc exists for: the amount was
	// computed entirely from what the primary node reported, and
	// CheckSweepsWholeCell can only check that number against itself — it cannot
	// catch a node that understated the balance. The wallet cannot make that
	// check meaningful on its own, so instead it puts the exact numbers in front
	// of the person about to make them irreversible and requires an explicit act,
	// the same principle a hardware wallet's trusted display uses against a
	// compromised host.
	//
	// Keyed on the certificate, not on which caller built it.
	// wallet.CheckSweepsWholeCell already refuses any one-shot-sourced
	// certificate that is not a full drain, so a partial spend never reaches
	// here and a `send` at the draining amount is the identical certificate
	// `sweep` produces — and gets the identical gate.
	if p.OneShotDrain {
		if opts.Approve == nil {
			return nil, ErrNotApproved
		}
		if err := opts.Approve(p); err != nil {
			return nil, err
		}
	}

	if err := s.primary.Submit(cert); err != nil {
		return nil, err
	}
	return &Result{Preview: p, Submitted: true}, nil
}
