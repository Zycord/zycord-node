package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/wallet"
	"zycord/wallet/session"

	"golang.org/x/term"
)

// The wallet commands implement docs/WALLET.md as *defaults*, not as
// documentation (M1-G6). Every rule there is enforced here, and the CLI names
// the finding when it refuses.

func cmdWallet(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zcd wallet <new|address|balance|send|sweep|retire>")
	}
	switch args[0] {
	case "new":
		return walletNew(args[1:])
	case "address":
		return walletAddress(args[1:])
	case "balance":
		return walletBalance(args[1:])
	case "send":
		return walletSend(args[1:], false)
	case "sweep":
		return walletSend(args[1:], true)
	case "retire":
		return walletRetire(args[1:])
	default:
		return fmt.Errorf("unknown wallet command %q", args[0])
	}
}

// walletFlags are shared by every command that needs a key or a node.
//
// The two halves are separate on purpose. A flag a command accepts and then
// ignores is worse than a flag it does not offer: `--devnet` on a command that
// never resolves parameters reads as an assertion the operator made and the
// tool honoured, and it is neither. That is the unasserted-network failure
// mode — the operator has no way to say which network they mean — wearing the
// costume of its own fix, so `zcd wallet address`, which never opens a socket,
// takes no node flags at all, and every command that does open one enforces
// them.
type walletFlags struct {
	*keyFlags
	*nodeFlags
}

// keyFlags are for the commands that open a key file.
type keyFlags struct {
	file    *string
	oneShot *bool
}

func addKeyFlags(fs *flag.FlagSet) *keyFlags {
	return &keyFlags{
		file:    fs.String("key", "", "path to an encrypted key file"),
		oneShot: fs.Bool("one-shot", false, "operate on the one-shot address rather than the persistent one"),
	}
}

// nodeFlags are for the commands that ask a node something. Every one of them
// runs the answer through the same two assertions, because a number a wallet
// prints and a number a wallet signs are read by the same person and are
// wrong in the same way.
type nodeFlags struct {
	rpc *string

	// params and devnet are the user's own assertion of which network they mean
	// to talk to — the same pair addNetworkFlags gives every other command. A
	// node's self-reported chain_id is otherwise the only source for that, and
	// trusting it blindly is how a wallet can end up signing for the wrong
	// network without any error. Every node this wallet asks is checked against
	// this assertion, including --confirm-rpc's.
	params  *string
	devnet  *bool
	testnet *bool

	// confirmRPC, if set, names a second node whose /balance answers must agree
	// with the first before an irreversible spend proceeds. It is the closest
	// thing available to Electrum's mitigation for a withholding or lying server
	// — cross-check against more than one independent source — applied here to
	// the numbers whose understatement is unrecoverable. Empty by default: a
	// single node is the common case, and requiring a second one by default would
	// make the wallet unusable for anyone who only runs one.
	confirmRPC *string
}

func addNodeFlags(fs *flag.FlagSet) *nodeFlags {
	path, devnet, testnet := addNetworkFlags(fs)
	return &nodeFlags{
		rpc:     fs.String("rpc", "http://127.0.0.1:9420", "node RPC address"),
		params:  path,
		devnet:  devnet,
		testnet: testnet,
		confirmRPC: fs.String("confirm-rpc", "",
			"a second, independent node to cross-check balances and spent flags against before an irreversible sweep (strongly recommended: without one, a single node's word is the only thing sizing a spend that cannot be undone)"),
	}
}

func addWalletFlags(fs *flag.FlagSet) *walletFlags {
	return &walletFlags{keyFlags: addKeyFlags(fs), nodeFlags: addNodeFlags(fs)}
}

// The trust errors the CLI reports are the session package's, named here so
// that a reader of this file — and `errors.Is` in a caller — finds them where
// the flags that trigger them are defined. The rules themselves live in
// wallet/session, because `zcd ui` and the desktop wallet enforce the same
// ones.
//
// ErrConfirmRPCNotIndependent: --confirm-rpc names the endpoint --rpc already
// names. A node cross-checking itself agrees with itself for exactly the
// reason CheckSweepsWholeCell does, and the confirmation prompt would go on to
// print "independently confirmed against ..." — a false assurance on the one
// display this whole change exists to make truthful.
var (
	ErrConfirmRPCNotIndependent = session.ErrConfirmRPCNotIndependent
	ErrChainIDMismatch          = session.ErrChainIDMismatch
	ErrBalanceSourcesDisagree   = session.ErrBalanceSourcesDisagree
)

// resolve turns the asserted network into a parameter set and rejects a
// second source that is not one.
//
// The endpoint comparison is textual, after trimming a trailing slash. It
// catches the copy-paste, which is the realistic mistake; it cannot catch two
// hostnames, or two addresses, that resolve to one node, and nothing short of
// comparing node identities could. That limit is stated rather than papered
// over: --confirm-rpc is only as independent as the operator's choice of
// endpoint makes it, and the prompt says "confirmed against <url>" — naming
// what was actually asked — rather than claiming independence it cannot
// verify.
func (n *nodeFlags) resolve(fs *flag.FlagSet) (*params.Params, error) {
	p, err := loadParams(fs, *n.params, *n.devnet, *n.testnet)
	if err != nil {
		return nil, err
	}
	if *n.confirmRPC != "" && session.SameEndpoint(*n.rpc, *n.confirmRPC) {
		return nil, fmt.Errorf("%w: both name %s", ErrConfirmRPCNotIndependent, *n.rpc)
	}
	return p, nil
}

// open builds the session every node-facing command runs through. key may be
// nil for the read-only commands.
func (n *nodeFlags) open(key *wallet.Key, p *params.Params) (*session.Session, error) {
	return session.New(key, p, *n.rpc, *n.confirmRPC)
}

func walletNew(args []string) error {
	fs := flag.NewFlagSet("wallet new", flag.ExitOnError)
	out := fs.String("out", "", "write an encrypted key file here (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("usage: zcd wallet new --out KEYFILE")
	}

	k, err := wallet.NewKey()
	if err != nil {
		return err
	}
	pass, err := readPassphrase("passphrase for the new key file: ", true)
	if err != nil {
		return err
	}
	defer zero(pass)

	if err := wallet.SaveKeyFile(*out, k, pass); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "key file\t%s\n", *out)
	fmt.Fprintf(w, "persistent address\t%s\n", hexAddr(k.Persistent()))
	fmt.Fprintf(w, "one-shot address\t%s\n", hexAddr(k.OneShot()))
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr,
		"\nThe key file is encrypted and the passphrase is not recoverable.\n"+
			"Use the persistent address for anything paid more than once — it can never\n"+
			"be burned, so it has no grief surface (docs/WALLET.md rule 3).")
	return nil
}

// walletAddress derives an address from a key file. It never opens a socket,
// so it takes no node flags: see the note on walletFlags for why offering
// --rpc, --devnet or --confirm-rpc here would be worse than not offering them.
func walletAddress(args []string) error {
	fs := flag.NewFlagSet("wallet address", flag.ExitOnError)
	f := addKeyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := openKey(*f.file)
	if err != nil {
		return err
	}
	fmt.Println(hexAddr(pick(k, *f.oneShot)))
	return nil
}

// walletBalance reports what a node says an address holds.
//
// It runs the same two assertions walletSend does, and for the same reason.
// A balance is not less load-bearing for being printed rather than signed:
// it is the number an operator reads before deciding to sweep, so a wrong
// network or a lying node misleads here exactly as it does one command later
// — and this is the command an operator uses to *check* before the one that
// cannot be undone. Before this, --devnet and --confirm-rpc were accepted
// here and silently discarded, which made the check read as more than it was.
func walletBalance(args []string) error {
	fs := flag.NewFlagSet("wallet balance", flag.ExitOnError)
	f := addWalletFlags(fs)
	addrHex := fs.String("addr", "", "address to query (defaults to the key file's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	expected, err := f.resolve(fs)
	if err != nil {
		return err
	}

	var addr types.Address
	if *addrHex != "" {
		parsed, err := parseAddress(*addrHex)
		if err != nil {
			return err
		}
		addr = parsed
	} else {
		k, err := openKey(*f.file)
		if err != nil {
			return err
		}
		addr = pick(k, *f.oneShot)
	}

	s, err := f.open(nil, expected)
	if err != nil {
		return err
	}
	b, err := s.Balance(addr)
	if err != nil {
		return err
	}

	fmt.Printf("%s drops", b.Value.String())
	if b.Spent {
		fmt.Print("  (address is spent: it can neither send nor receive)")
	}
	if *f.confirmRPC != "" {
		fmt.Printf("  [confirmed against %s]", *f.confirmRPC)
	}
	fmt.Println()
	return nil
}

// walletSend builds, checks, signs and submits a transfer.
//
// `sweep` is the same command with the amount computed rather than given: a
// one-shot source must move its whole balance, because a debit burns it and
// anything left is unreachable (rule 1). The CLI computes that number so a user
// never has to.
func walletSend(args []string, sweep bool) error {
	name := "wallet send"
	if sweep {
		name = "wallet sweep"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	f := addWalletFlags(fs)
	toHex := fs.String("to", "", "recipient address (required)")
	amountStr := fs.String("amount", "", "amount in drops")
	refundHex := fs.String("refund", "", "refund address (defaults to the persistent address)")
	headroom := fs.Uint64("headroom", session.DefaultHeadroom, "fee maximum as a multiple of the current base fee; free in fees, reserved from balance")
	seqTip := fs.String("seq-tip", "100", "sequential priority price, in drops per gas")
	parTip := fs.String("par-tip", "5", "parallel priority price, in drops per gas")
	ttl := fs.Uint64("ttl", session.DefaultTTL, "blocks ahead this certificate may be committed")
	dryRun := fs.Bool("dry-run", false, "build and check, but do not submit")
	force := fs.Bool("force", false,
		"submit even though the source cell does not cover what this certificate takes out of it, for the case where a deposit is expected to land inside the TTL window; if the funds do not arrive in time and a producer includes it anyway, the fold skips it and burns the skip fee out of your deposit; skips no other check and cannot make an invalid certificate valid")
	yes := fs.Bool("yes", false,
		"skip the interactive confirmation before an irreversible one-shot sweep; does not skip any policy check, chain-id assertion, or --confirm-rpc cross-check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *toHex == "" {
		return errors.New("--to is required")
	}
	if !sweep && *amountStr == "" {
		return errors.New("--amount is required (or use `zcd wallet sweep`)")
	}

	// The network to sign for is the caller's own assertion, defaulting to
	// mainnet like every other zcd command — never the node's self-reported
	// chain_id, which the session verifies against this rather than trusting
	// outright.
	expected, err := f.resolve(fs)
	if err != nil {
		return err
	}

	k, err := openKey(*f.file)
	if err != nil {
		return err
	}
	to, err := parseAddress(*toHex)
	if err != nil {
		return err
	}

	opts := session.DefaultSendOptions()
	opts.OneShot = *f.oneShot
	opts.Sweep = sweep
	opts.DryRun = *dryRun
	opts.Force = *force
	opts.TTL = *ttl
	opts.Headroom = *headroom
	if opts.SeqTip, err = u256.FromDecimal(*seqTip); err != nil {
		return fmt.Errorf("--seq-tip: %w", err)
	}
	if opts.ParTip, err = u256.FromDecimal(*parTip); err != nil {
		return fmt.Errorf("--par-tip: %w", err)
	}
	if *refundHex != "" {
		if opts.Refund, err = parseAddress(*refundHex); err != nil {
			return err
		}
	}
	amount := u256.Zero
	if !sweep {
		if amount, err = u256.FromDecimal(*amountStr); err != nil {
			return fmt.Errorf("--amount: %w", err)
		}
	}

	opts.OnPreview = printPreview
	opts.Approve = func(p *session.Preview) error {
		if !*yes {
			return confirmSweep(os.Stderr, p.PrimaryURL, p.ConfirmURL, p.From, p.To, p.Refund, p.Held, p.Amount, p.Ceiling)
		}
		// --yes is the operator taking the prompt's place, so it inherits the
		// prompt's job of saying what was and was not checked. With no second source
		// there is nothing behind this submission but one node's word — a single
		// unverified source sizing an irreversible spend, exactly the case
		// --confirm-rpc exists for — and a script that scrolls past this line has at
		// least been told.
		if p.ConfirmURL == "" {
			fmt.Fprintf(os.Stderr,
				"\nwarning: --yes skipped the confirmation for an irreversible one-shot sweep, and no\n"+
					"--confirm-rpc was given: %s is the only source for the %s drops this sweep is\n"+
					"sized against. Anything it failed to report is no longer destroyed — F8b\n"+
					"returns it to the refund address — but it is also not sent where you\n"+
					"meant it to go.\n",
				p.PrimaryURL, p.Held.String())
		} else {
			fmt.Fprintf(os.Stderr,
				"\nwarning: --yes skipped the confirmation for an irreversible one-shot sweep. %s\n"+
					"agreed with %s on the %s drops it is sized against; that holds only if the two are\n"+
					"genuinely independent nodes, which this wallet compared by URL and cannot verify.\n",
				p.ConfirmURL, p.PrimaryURL, p.Held.String())
		}
		return nil
	}

	s, err := f.open(k, expected)
	if err != nil {
		return err
	}
	res, err := s.Send(to, amount, opts)
	if err != nil {
		return err
	}
	if !res.Submitted {
		fmt.Println("\ndry run: not submitted")
		return nil
	}
	fmt.Println("\nsubmitted")
	return nil
}

// printPreview is the table every spending command shows once the certificate
// is built and every policy rule has passed.
func printPreview(p *session.Preview) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "certificate\t%s\n", "0x"+hex.EncodeToString(p.ID[:]))
	fmt.Fprintf(w, "from\t%s\n", hexAddr(p.From))
	if p.To != (types.Address{}) {
		fmt.Fprintf(w, "to\t%s\n", hexAddr(p.To))
	}
	fmt.Fprintf(w, "amount\t%s drops\n", p.Amount.String())
	fmt.Fprintf(w, "fee now\t%s drops (of which %s is the miner's tip)\n", p.FeeNow.String(), p.Tip.String())
	fmt.Fprintf(w, "reserved\t%s drops, refunded within the same block\n", p.Ceiling.String())
	fmt.Fprintf(w, "ttl\t height %d\n", p.TTL)
	if p.Underfunded != nil {
		// Inside the table the operator is actually reading, not on a log line
		// nobody sees. --force turns a refusal into a warning; it does not turn it
		// into silence, and a warning printed only to a log line nobody reads is
		// silence.
		fmt.Fprintf(w, "warning\t--force: %v\n", p.Underfunded)
	}
	return w.Flush()
}

// walletRetire burns the signing authority of one-shot addresses this key
// owns. It is how state stops carrying a cell that has served its purpose
// (whitepaper §11), and it is the command the usage string has advertised
// since M1 while the switch above had no case for it.
//
// The addresses default to this key's own one-shot address, which is the
// common case: a key whose one-shot has been swept and will never be used
// again. Retiring an address that still holds a balance strands it exactly as
// a partial spend would, and wallet.CheckSweepsWholeCell refuses it — sweep
// first, retire after.
func walletRetire(args []string) error {
	fs := flag.NewFlagSet("wallet retire", flag.ExitOnError)
	f := addWalletFlags(fs)
	var addrs addressList
	fs.Var(&addrs, "addr", "a one-shot address to retire; repeat for several (defaults to this key's own one-shot address)")
	headroom := fs.Uint64("headroom", session.DefaultHeadroom, "fee maximum as a multiple of the current base fee")
	seqTip := fs.String("seq-tip", "100", "sequential priority price, in drops per gas")
	parTip := fs.String("par-tip", "5", "parallel priority price, in drops per gas")
	ttl := fs.Uint64("ttl", session.DefaultTTL, "blocks ahead this certificate may be committed")
	dryRun := fs.Bool("dry-run", false, "build and check, but do not submit")
	yes := fs.Bool("yes", false, "skip the interactive confirmation; does not skip any policy check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	expected, err := f.resolve(fs)
	if err != nil {
		return err
	}
	k, err := openKey(*f.file)
	if err != nil {
		return err
	}
	targets := []types.Address(addrs)
	if len(targets) == 0 {
		targets = []types.Address{k.OneShot()}
	}

	opts := session.DefaultSendOptions()
	opts.DryRun = *dryRun
	opts.TTL = *ttl
	opts.Headroom = *headroom
	if opts.SeqTip, err = u256.FromDecimal(*seqTip); err != nil {
		return fmt.Errorf("--seq-tip: %w", err)
	}
	if opts.ParTip, err = u256.FromDecimal(*parTip); err != nil {
		return fmt.Errorf("--par-tip: %w", err)
	}
	opts.OnPreview = func(p *session.Preview) error {
		if err := printPreview(p); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, a := range targets {
			fmt.Fprintf(w, "retires\t%s\n", hexAddr(a))
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if *dryRun || *yes {
			return nil
		}
		// Retiring moves no value, so no policy rule can undo it either: the
		// address is burned for the life of the chain and can never receive
		// again. That is a smaller loss than a mis-sized sweep and it is the
		// same kind — irreversible on one node's word — so it gets the same
		// kind of gate rather than none.
		return confirmWord(os.Stderr, "retire",
			fmt.Sprintf("\nabout to retire %d address(es) — they can never sign or receive again.\n", len(targets)))
	}

	s, err := f.open(k, expected)
	if err != nil {
		return err
	}
	res, err := s.Retire(targets, opts)
	if err != nil {
		return err
	}
	if !res.Submitted {
		fmt.Println("\ndry run: not submitted")
		return nil
	}
	fmt.Println("\nsubmitted")
	return nil
}

// addressList collects a repeatable --addr flag.
type addressList []types.Address

func (l *addressList) String() string {
	out := make([]string, len(*l))
	for i, a := range *l {
		out[i] = hexAddr(a)
	}
	return strings.Join(out, ",")
}

func (l *addressList) Set(s string) error {
	a, err := parseAddress(s)
	if err != nil {
		return err
	}
	*l = append(*l, a)
	return nil
}

// confirmSweep is the human-in-the-loop check for an irreversible one-shot
// sweep. The wallet's own arithmetic cannot catch a source node that
// understates a balance, because the only number available to check it against
// is that same source's report — CheckSweepsWholeCell compares the node's
// number to itself. What a wallet *can* do is show the person about to make
// the spend irreversible exactly what it is about to do, and require an
// explicit act before doing it.
//
// This mirrors two established mitigations for the same class of problem:
// Electrum's response to a withholding or lying server is to cross-check
// against more than one independent source (see the --confirm-rpc branch
// below); a hardware wallet's trusted display shows the real destination and
// amount on a screen a compromised host cannot edit, and requires a physical
// confirmation before it signs. Neither actually validates the number against
// consensus — nothing short of the wallet becoming a full node can do that —
// but both convert a silent, automatic mistake into one that requires a
// deliberate, informed act to happen at all.
func confirmSweep(out io.Writer, rpc, confirmRPC string, from, to, refund types.Address, held, amount, ceiling u256.U256) error {
	fmt.Fprintf(out, "\nabout to sweep a one-shot address — this cannot be undone (docs/WALLET.md rule 1):\n")
	fmt.Fprintf(out, "  source                    %s\n", hexAddr(from))
	// The payee and the refund address are on the display because they are
	// what the cited prior art puts there: a hardware wallet's trusted screen
	// shows the destination, not only the amount. Neither is supplied by the
	// node — they come from --to and --refund, or from the key file — so
	// nothing a node can say changes them. That is the point: this is the
	// place an operator can compare the whole irreversible act against what
	// they meant to do, and half of it is the two addresses.
	fmt.Fprintf(out, "  payee                     %s\n", hexAddr(to))
	fmt.Fprintf(out, "  refund (change) goes to   %s\n", hexAddr(refund))
	fmt.Fprintf(out, "  %s reports it holds  %s drops\n", rpc, held.String())
	fmt.Fprintf(out, "  this certificate sends    %s drops\n", amount.String())
	fmt.Fprintf(out, "  plus reserved for fees    %s drops\n", ceiling.String())
	fmt.Fprintf(out, "  (the two above together account for the entire balance %s reported)\n", rpc)
	if confirmRPC != "" {
		fmt.Fprintf(out, "  %s was asked the same questions and gave the same answers.\n", confirmRPC)
		fmt.Fprintf(out, "  That is worth exactly as much as that node being genuinely independent of\n")
		fmt.Fprintf(out, "  %s, which this wallet cannot verify — it compared the two URLs, not the two\n", rpc)
		fmt.Fprintf(out, "  nodes. If both names reach the same machine, nothing was cross-checked.\n")
	} else {
		fmt.Fprintf(out, "\n  NOT independently confirmed — only %s was asked. If it is wrong, stale, or\n", rpc)
		fmt.Fprintf(out, "  simply on a losing fork, whatever it failed to report lands in the refund\n")
		fmt.Fprintf(out, "  address above rather than at the payee: the chain returns it instead of\n")
		fmt.Fprintf(out, "  destroying it (rule F8b), but the payment is short by that amount and the address\n")
		fmt.Fprintf(out, "  is burned either way. Consider rerunning with --confirm-rpc pointed at a\n")
		fmt.Fprintf(out, "  second, independent node.\n")
	}
	return confirmWord(out, "sweep", "")
}

// confirmWord requires the operator to type one exact word. preamble, when
// non-empty, is printed first.
//
// A typed word rather than y/n: the answer to "are you sure" is reflexively
// yes, and the point of this gate is to interrupt a reflex.
func confirmWord(out io.Writer, word, preamble string) error {
	if preamble != "" {
		fmt.Fprint(out, preamble)
	}
	fmt.Fprintf(out, "\ntype %q to submit, anything else to abort: ", word)

	line, err := readLine()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSweepNotConfirmed, err)
	}
	if strings.ToLower(strings.TrimSpace(line)) != word {
		return ErrSweepNotConfirmed
	}
	return nil
}

// ErrSweepNotConfirmed reports that the operator did not type the literal
// confirmation word before an irreversible one-shot drain went ahead — whether
// reached via `sweep` or via `send --one-shot` at the amount that drains the
// cell (the two are indistinguishable to wallet.CheckAll, and so to this
// gate). Named separately from the policy errors
// (wallet.ErrPartialOneShotSpend and friends) because it means something
// different to a caller: "ask again", not "the certificate itself is wrong".
var ErrSweepNotConfirmed = errors.New("wallet: sweep not confirmed; nothing was submitted")

// nodeState is the CLI's rendering of a session.View: everything the wallet
// needs from a node to build a certificate.
//
// It deliberately does NOT carry the view's *state.State. That state is the
// sparse one — it holds only the cells the three fetched addresses were asked
// about — and the two sets that make it answerable, the view's fetched slots
// and fetched-spent addresses, cannot come with it: they are unexported and
// CoversCertificate is a method on session.View, not on the state. A copy of
// the state alone is a sparse state with its coverage record dropped, and
// every read of one conflates "absent" with "zero", and "absent" with
// "unspent", in the fail-open direction — the same conflation already fixed
// four times over for balances, for spent flags, and for both the payee and
// the refund destination. It was written once here and read nowhere, so
// deleting it costs nothing and removes the loaded gun.
//
// A zcd command that genuinely needs consensus state must carry the
// *session.View itself, so that the object answering "was this cell fetched?"
// travels with the cells. TestPackageMainDoesNotImportCoreState in
// sparse_state_test.go is what says so if this is undone.
type nodeState struct {
	params      *params.Params
	height      uint64
	seqBase     u256.U256
	parBase     u256.U256
	fromBalance u256.U256
}

// fetchNodeState is the CLI's call into session.FetchState.
//
// The logic it used to hold — the chain-id assertion against the operator's
// own asserted network, the second-source cross-check, the sparse state
// assembly the policy rules read — now lives in wallet/session, so that `zcd
// ui` and the desktop wallet run it too rather than reimplementing it. This
// shape is kept because the trust-assertion regression suite in wallet_test.go
// is written against it, and that suite passing unedited is the evidence that
// moving the logic changed none of it.
func fetchNodeState(addr, confirmAddr string, from, to, refund types.Address, expected *params.Params) (*nodeState, error) {
	s, err := session.New(nil, expected, addr, confirmAddr)
	if err != nil {
		return nil, err
	}
	v, err := s.FetchState(from, to, refund)
	if err != nil {
		return nil, err
	}
	return &nodeState{
		params:      v.Params,
		height:      v.Height,
		seqBase:     v.SeqBase,
		parBase:     v.ParBase,
		fromBalance: v.FromBalance,
	}, nil
}

func openKey(path string) (*wallet.Key, error) {
	if path == "" {
		return nil, errors.New("--key is required")
	}
	pass, err := readPassphrase("passphrase for "+path+": ", false)
	if err != nil {
		return nil, err
	}
	defer zero(pass)
	return wallet.LoadKeyFile(path, pass)
}

// stdinReader is the process's one buffered reader over standard input.
// Every prompt in this file reads through it rather than wrapping os.Stdin in
// a fresh bufio.Reader each time, because a fresh one can silently swallow a
// second answer: bufio's underlying read can pull more bytes off the pipe
// than the single line it returns, and a second, independent bufio.Reader
// wrapping the same os.Stdin never sees what the first one already buffered
// and discarded when it went out of scope. That only bites once a command
// asks for more than one line in a row — which confirmSweep now does, right
// after openKey's passphrase prompt, for a scripted `zcd wallet sweep`.
//
// A var, not a val: tests reassign it (and, when they also swap os.Stdin
// itself, reassign it to wrap the replacement) to feed canned answers.
var stdinReader = bufio.NewReader(os.Stdin)

// readLine reads one line from stdinReader, stripping the trailing newline.
func readLine() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readPassphrase reads without echoing. A passphrase on a command line ends up
// in the shell history and in the process table, so there is no flag for it.
func readPassphrase(prompt string, confirm bool) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive use — scripts, tests — reads a line from stdin.
		line, err := readLine()
		if err != nil {
			return nil, err
		}
		return []byte(line), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return first, nil
	}
	fmt.Fprint(os.Stderr, "again: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("the two passphrases differ")
	}
	zero(second)
	return first, nil
}

func pick(k *wallet.Key, oneShot bool) types.Address {
	if oneShot {
		return k.OneShot()
	}
	return k.Persistent()
}

// parseAddress and hexAddr delegate rather than reimplement. Two copies of
// "what an address looks like" is two things to drift, and an address the CLI
// accepts but the wallet interface rejects — or worse, the other way round —
// is a difference nobody would find until somebody typed one in.
func parseAddress(s string) (types.Address, error) { return session.ParseAddress(s) }

func hexAddr(a types.Address) string { return session.HexAddr(a) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
