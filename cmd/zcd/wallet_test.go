package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
)

// The understating-source-node test suite.
//
// fetchNodeState is the wallet's entire view of consensus state, and the
// defect this suite is written against is what happens when the one node
// supplying that view understates a one-shot address's balance:
// CheckSweepsWholeCell can only compare that number to itself, so it can never
// catch the understatement, and the difference is burned the instant the sweep
// applies. These tests exercise the two things that changed in response — a
// node's self-reported chain_id is no longer trusted outright, and a second,
// independent --confirm-rpc source, if given, must agree with the first — plus
// the interactive confirmation that stands in front of every one-shot sweep
// regardless.

// mockNode is a tiny stand-in for a node's RPC surface, servable by
// httptest.Server. Balances are keyed by address so a test can hand back a
// different number per address, and submissions are counted so a test can
// assert that a refused sweep never reached the network.
type mockNode struct {
	mu        sync.Mutex
	chainID   uint64
	network   string
	height    uint64
	seqFee    string
	parFee    string
	balances  map[types.Address]string
	spent     map[types.Address]bool
	submitted int
}

func newMockNode(chainID uint64, network string) *mockNode {
	return &mockNode{
		chainID:  chainID,
		network:  network,
		height:   1000,
		seqFee:   "10",
		parFee:   "5",
		balances: map[types.Address]string{},
		spent:    map[types.Address]bool{},
	}
}

func (m *mockNode) balance(a types.Address, drops string) *mockNode {
	m.balances[a] = drops
	return m
}

func (m *mockNode) markSpent(a types.Address) *mockNode {
	m.spent[a] = true
	return m
}

func (m *mockNode) submitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.submitted
}

func (m *mockNode) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/status":
			fmt.Fprintf(w, `{"chain_id":%d,"height":%d,"network":%q}`, m.chainID, m.height, m.network)
		case r.URL.Path == "/fees":
			fmt.Fprintf(w, `{"seq_base_fee":%q,"par_base_fee":%q}`, m.seqFee, m.parFee)
		case r.URL.Path == "/balance":
			hexAddr := r.URL.Query().Get("addr")
			addr, err := parseAddress(hexAddr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			bal, ok := m.balances[addr]
			if !ok {
				bal = "0"
			}
			fmt.Fprintf(w, `{"balance":%q,"spent":%v}`, bal, m.spent[addr])
		case r.URL.Path == "/submit":
			m.mu.Lock()
			m.submitted++
			m.mu.Unlock()
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testKey(t *testing.T, n byte) *wallet.Key {
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

// TestFetchNodeStateRefusesChainIDMismatch is the network-assertion half of
// the fix: a node's self-reported chain_id must match the caller's own
// assertion (mainnet by default, same as every other zcd command), or the call
// refuses outright instead of silently signing for whatever network the node
// claims to be.
func TestFetchNodeStateRefusesChainIDMismatch(t *testing.T) {
	k := testKey(t, 1)
	from, to, refund := k.OneShot(), testKey(t, 2).Persistent(), k.Persistent()

	node := newMockNode(spec.Devnet().ChainID, "zycord-devnet")
	srv := node.server(t)

	_, err := fetchNodeState(srv.URL, "", from, to, refund, spec.Mainnet())
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("expected ErrChainIDMismatch, got %v", err)
	}
}

// TestFetchNodeStateAcceptsMatchingChainID is the control for the test above:
// the same setup succeeds once the caller's assertion matches the node.
func TestFetchNodeStateAcceptsMatchingChainID(t *testing.T) {
	k := testKey(t, 1)
	from, to, refund := k.OneShot(), testKey(t, 2).Persistent(), k.Persistent()

	node := newMockNode(spec.Devnet().ChainID, "zycord-devnet")
	node.balance(from, "500")
	srv := node.server(t)

	got, err := fetchNodeState(srv.URL, "", from, to, refund, spec.Devnet())
	if err != nil {
		t.Fatal(err)
	}
	if !got.fromBalance.Eq(u256.FromUint64(500)) {
		t.Fatalf("fromBalance = %s, want 500", got.fromBalance.String())
	}
}

// TestFetchNodeStateRefusesWhenConfirmRPCDisagrees is the core regression:
// --rpc understates the source balance (as a lying, stale, or forked node
// would), and --confirm-rpc reports the true, larger balance. Without a second
// source there is nothing to detect this by — the whole point being that
// CheckSweepsWholeCell cannot — so this is the one mechanism in this change
// that can actually catch it.
func TestFetchNodeStateRefusesWhenConfirmRPCDisagrees(t *testing.T) {
	k := testKey(t, 1)
	from, to, refund := k.OneShot(), testKey(t, 2).Persistent(), k.Persistent()

	lying := newMockNode(spec.Mainnet().ChainID, "zycord")
	lying.balance(from, "1000000000") // understates: the real cell holds far more
	lyingSrv := lying.server(t)

	honest := newMockNode(spec.Mainnet().ChainID, "zycord")
	honest.balance(from, "100000000000000")
	honestSrv := honest.server(t)

	_, err := fetchNodeState(lyingSrv.URL, honestSrv.URL, from, to, refund, spec.Mainnet())
	if !errors.Is(err, ErrBalanceSourcesDisagree) {
		t.Fatalf("expected ErrBalanceSourcesDisagree, got %v", err)
	}
}

// TestFetchNodeStateAcceptsWhenConfirmRPCAgrees is the control: two sources
// reporting the same balance for the source address proceed normally.
func TestFetchNodeStateAcceptsWhenConfirmRPCAgrees(t *testing.T) {
	k := testKey(t, 1)
	from, to, refund := k.OneShot(), testKey(t, 2).Persistent(), k.Persistent()

	a := newMockNode(spec.Mainnet().ChainID, "zycord")
	a.balance(from, "42")
	aSrv := a.server(t)

	b := newMockNode(spec.Mainnet().ChainID, "zycord")
	b.balance(from, "42")
	bSrv := b.server(t)

	got, err := fetchNodeState(aSrv.URL, bSrv.URL, from, to, refund, spec.Mainnet())
	if err != nil {
		t.Fatal(err)
	}
	if !got.fromBalance.Eq(u256.FromUint64(42)) {
		t.Fatalf("fromBalance = %s, want 42", got.fromBalance.String())
	}
}

// TestFetchNodeStateRefusesWhenConfirmRPCDisagreesOnPayeeSpentFlag covers the
// related variants of the same defect alongside the sweep-amount case: a
// falsified spent flag on the payee defeats wallet.CheckPayeeIsFresh the same
// way a falsified balance on the source defeats CheckSweepsWholeCell, and for
// the same reason — the check has no source but the one being audited. The
// --confirm-rpc cross-check applies to every address fetchNodeState fetches,
// not just the sweep source, so it catches this too.
func TestFetchNodeStateRefusesWhenConfirmRPCDisagreesOnPayeeSpentFlag(t *testing.T) {
	k := testKey(t, 1)
	from, to, refund := k.OneShot(), testKey(t, 2).OneShot(), k.Persistent()

	lying := newMockNode(spec.Mainnet().ChainID, "zycord")
	lying.balance(from, "100")
	// lying omits that `to` is already spent — exactly what a payee-side
	// attacker (or a stale node) would do to defeat CheckPayeeIsFresh.
	lyingSrv := lying.server(t)

	honest := newMockNode(spec.Mainnet().ChainID, "zycord")
	honest.balance(from, "100")
	honest.markSpent(to)
	honestSrv := honest.server(t)

	_, err := fetchNodeState(lyingSrv.URL, honestSrv.URL, from, to, refund, spec.Mainnet())
	if !errors.Is(err, ErrBalanceSourcesDisagree) {
		t.Fatalf("expected ErrBalanceSourcesDisagree over the payee's spent flag, got %v", err)
	}
}

// TestConfirmSweepRequiresTheExactWord checks the interactive gate on its
// own: only the literal word "sweep" (case-insensitively) proceeds, and the
// prompt shows the numbers a user would need to notice something is wrong.
func TestConfirmSweepRequiresTheExactWord(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool // true = should confirm (nil error)
	}{
		{"exact", "sweep\n", true},
		{"uppercase", "SWEEP\n", true},
		{"padded", "  sweep  \n", true},
		{"empty", "\n", false},
		{"yes", "yes\n", false},
		{"garbage", "asdf\n", false},
		{"eof", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := stdinReader
			stdinReader = bufio.NewReader(strings.NewReader(tc.input))
			t.Cleanup(func() { stdinReader = old })

			var out bytes.Buffer
			from := testKey(t, 3).OneShot()
			to, refund := testKey(t, 8).Persistent(), testKey(t, 3).Persistent()
			err := confirmSweep(&out, "http://node", "", from, to, refund,
				u256.FromUint64(1000), u256.FromUint64(900), u256.FromUint64(100))

			if tc.want && err != nil {
				t.Fatalf("expected confirmation to succeed, got %v", err)
			}
			if !tc.want && err == nil {
				t.Fatal("expected confirmation to be refused, got nil")
			}
		})
	}
}

// TestConfirmSweepWarnsWhenThereIsNoSecondSource checks the actual warning
// text — the one honest thing the wallet can say when it has only one source
// for the number it is about to make irreversible.
func TestConfirmSweepWarnsWhenThereIsNoSecondSource(t *testing.T) {
	old := stdinReader
	stdinReader = bufio.NewReader(strings.NewReader("abort\n"))
	t.Cleanup(func() { stdinReader = old })

	var out bytes.Buffer
	from := testKey(t, 4).OneShot()
	to, refund := testKey(t, 8).Persistent(), testKey(t, 4).Persistent()
	_ = confirmSweep(&out, "http://node", "", from, to, refund,
		u256.FromUint64(1000), u256.FromUint64(900), u256.FromUint64(100))

	printed := out.String()
	if !strings.Contains(printed, "NOT independently confirmed") {
		t.Fatalf("expected a warning about the missing second source, got:\n%s", printed)
	}
	if !strings.Contains(printed, "1000") || !strings.Contains(printed, "900") || !strings.Contains(printed, "100") {
		t.Fatalf("expected the exact numbers in the prompt, got:\n%s", printed)
	}
}

// TestConfirmSweepReportsIndependentConfirmationWhenPresent is the other
// half: when --confirm-rpc was used, the prompt says so instead of warning.
func TestConfirmSweepReportsIndependentConfirmationWhenPresent(t *testing.T) {
	old := stdinReader
	stdinReader = bufio.NewReader(strings.NewReader("abort\n"))
	t.Cleanup(func() { stdinReader = old })

	var out bytes.Buffer
	from := testKey(t, 5).OneShot()
	to, refund := testKey(t, 8).Persistent(), testKey(t, 5).Persistent()
	_ = confirmSweep(&out, "http://node-a", "http://node-b", from, to, refund,
		u256.FromUint64(1000), u256.FromUint64(900), u256.FromUint64(100))

	printed := out.String()
	if strings.Contains(printed, "NOT independently confirmed") {
		t.Fatalf("did not expect the missing-second-source warning, got:\n%s", printed)
	}
	if !strings.Contains(printed, "http://node-b was asked the same questions") {
		t.Fatalf("expected confirmation against the second source, got:\n%s", printed)
	}
}

// TestWalletSweepEndToEndRefusesWithoutConfirmation drives the whole `zcd
// wallet sweep` path against a mock node reporting an understated balance for
// a one-shot address — exactly the understating-source scenario — with no
// --confirm-rpc and no answer typed at the confirmation prompt. Before this
// fix, sweep sized and submitted the certificate unconditionally; the point of
// the test is that it no longer does, and that /submit is never even called.
func TestWalletSweepEndToEndRefusesWithoutConfirmation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(keyPath, k, []byte("testpass")); err != nil {
		t.Fatal(err)
	}
	to := testKey(t, 9).Persistent()

	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	// An understated balance: whatever the "real" chain holds, this mock only
	// ever admits to a small amount, the way a lying or lagging node would.
	node.balance(k.OneShot(), "5000000000000")
	srv := node.server(t)

	withStdin(t, "testpass\n", func() {
		err := walletSend([]string{
			"--key", keyPath,
			"--rpc", srv.URL,
			"--one-shot",
			"--to", hexAddr(to),
		}, true)
		if err == nil {
			t.Fatal("expected the sweep to be refused without a typed confirmation")
		}
	})

	if n := node.submitCount(); n != 0 {
		t.Fatalf("the certificate must never reach /submit when unconfirmed, got %d submissions", n)
	}
}

// TestWalletSweepEndToEndSubmitsOnExplicitConfirmation is the paired
// positive case: once the passphrase and the literal word "sweep" are both
// supplied, the same certificate that was refused above goes through. This
// documents the honest limit of the fix — a human who ignores the on-screen
// warning and confirms anyway is not something any wallet can stop without a
// second source — while proving the confirmation step itself is wired
// correctly end to end, not just unit-tested in isolation.
func TestWalletSweepEndToEndSubmitsOnExplicitConfirmation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(keyPath, k, []byte("testpass")); err != nil {
		t.Fatal(err)
	}
	to := testKey(t, 9).Persistent()

	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.OneShot(), "5000000000000")
	srv := node.server(t)

	withStdin(t, "testpass\nsweep\n", func() {
		if err := walletSend([]string{
			"--key", keyPath,
			"--rpc", srv.URL,
			"--one-shot",
			"--to", hexAddr(to),
		}, true); err != nil {
			t.Fatalf("expected the confirmed sweep to submit, got %v", err)
		}
	})

	if n := node.submitCount(); n != 1 {
		t.Fatalf("expected exactly one submission, got %d", n)
	}
}

// TestWalletSweepEndToEndYesSkipsThePromptButNotThePolicy proves --yes skips
// only the interactive step: it does not bypass the confirm-rpc cross-check.
func TestWalletSweepEndToEndYesSkipsThePromptButNotThePolicy(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(keyPath, k, []byte("testpass")); err != nil {
		t.Fatal(err)
	}
	to := testKey(t, 9).Persistent()

	lying := newMockNode(spec.Mainnet().ChainID, "zycord")
	lying.balance(k.OneShot(), "1000000000")
	lyingSrv := lying.server(t)

	honest := newMockNode(spec.Mainnet().ChainID, "zycord")
	honest.balance(k.OneShot(), "999999999999999")
	honestSrv := honest.server(t)

	withStdin(t, "testpass\n", func() {
		err := walletSend([]string{
			"--key", keyPath,
			"--rpc", lyingSrv.URL,
			"--confirm-rpc", honestSrv.URL,
			"--one-shot",
			"--to", hexAddr(to),
			"--yes",
		}, true)
		if !errors.Is(err, ErrBalanceSourcesDisagree) {
			t.Fatalf("expected ErrBalanceSourcesDisagree even with --yes, got %v", err)
		}
	})

	if n := lying.submitCount() + honest.submitCount(); n != 0 {
		t.Fatalf("must never submit when the sources disagree, got %d submissions", n)
	}
}

// TestWalletSendOneShotFullDrainGetsTheSameConfirmationAsSweep reproduces the
// bypass a review found in this PR: the confirmation gate used to be keyed on
// the sweep subcommand boolean rather than on whether the certificate is
// actually an irreversible one-shot drain. wallet.CheckAll (via
// wallet.CheckSweepsWholeCell) already refuses any one-shot-sourced
// certificate that isn't a full drain, whichever subcommand built it — so
// `zcd wallet send --one-shot --amount <held-ceiling>` builds the identical
// certificate `sweep` would have and reaches the identical point in
// walletSend, but the old `sweep &&` condition let it through with no prompt
// at all, --yes not even needed because the gate never fired for `send`.
//
// This computes the exact draining amount the same way walletSend's own
// sweep path does — probe-build once for the fee ceiling, then balance minus
// ceiling is the only amount CheckSweepsWholeCell will accept from a
// one-shot source — and drives `send`, not `sweep`, at that amount.
func TestWalletSendOneShotFullDrainGetsTheSameConfirmationAsSweep(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(keyPath, k, []byte("testpass")); err != nil {
		t.Fatal(err)
	}
	from := k.OneShot()
	refund := k.Persistent()
	to := testKey(t, 9).Persistent()

	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(from, "5000000000000")
	srv := node.server(t)

	// Replicate walletSend's own sizing so the --amount handed to `send`
	// below is exactly the one that drains the cell in full — anything else
	// would be refused by CheckAll before ever reaching the confirmation
	// gate, which would pass this test for the wrong reason.
	ns, err := fetchNodeState(srv.URL, "", from, to, refund, spec.Mainnet())
	if err != nil {
		t.Fatal(err)
	}
	seqPriority, _ := u256.FromDecimal("100")                                          // walletSend's --seq-tip default
	parPriority, _ := u256.FromDecimal("5")                                            // walletSend's --par-tip default
	bid := wallet.BidWithHeadroom(ns.seqBase, ns.parBase, seqPriority, parPriority, 8) // --headroom default
	build := func(amount u256.U256) (*types.Certificate, error) {
		b := &wallet.Builder{
			Params:  ns.params,
			Program: wallet.Tip(types.NativeAsset, from, to, amount),
			TTL:     ns.height + 30, // --ttl default
			Deposit: wallet.SelfDeposit(from, refund),
			FeeBid:  bid,
			Signers: []*wallet.Key{k},
		}
		return b.Build()
	}
	probe, err := build(u256.One)
	if err != nil {
		t.Fatal(err)
	}
	ceiling, ok := probe.FeeCeiling(ns.params)
	if !ok {
		t.Fatal("fee ceiling overflows")
	}
	drainAmount := ns.fromBalance.SatSub(ceiling)
	if drainAmount.IsZero() {
		t.Fatal("test setup produced a zero drain amount; balance too small relative to ceiling")
	}

	withStdin(t, "testpass\n", func() {
		err := walletSend([]string{
			"--key", keyPath,
			"--rpc", srv.URL,
			"--one-shot",
			"--to", hexAddr(to),
			"--amount", drainAmount.String(),
		}, false) // send, not sweep — this is exactly the reviewer's repro
		if !errors.Is(err, ErrSweepNotConfirmed) {
			t.Fatalf("expected send --one-shot at the full drain amount to be refused for lack of "+
				"confirmation (ErrSweepNotConfirmed), same as sweep; got %v", err)
		}
	})

	if n := node.submitCount(); n != 0 {
		t.Fatalf("send --one-shot at the draining amount must never reach /submit without a typed "+
			"confirmation, got %d submissions", n)
	}
}

// withStdin swaps os.Stdin (and the package's shared stdinReader over it, see
// the doc comment on stdinReader) for the duration of fn, restoring both
// afterward. Feeding one line at a time through a pipe, rather than a
// pre-buffered strings.Reader, is what makes this a faithful stand-in for a
// script piping multiple answers to a real process: it is exactly the
// scenario stdinReader exists to get right, since openKey's passphrase
// prompt and confirmSweep's prompt now read from stdin in the same run.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin, oldReader := os.Stdin, stdinReader
	os.Stdin = r
	stdinReader = bufio.NewReader(r)
	defer func() {
		os.Stdin = oldStdin
		stdinReader = oldReader
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.WriteString(input)
		w.Close()
	}()

	fn()
	<-done
	r.Close()
}

// TestWalletAddressTakesNoNodeFlags pins the flag surface of the command,
// because the defect it guards against is invisible at runtime: `zcd wallet
// address` never opens a socket, so --rpc, --devnet, --params and
// --confirm-rpc could only ever be accepted and discarded. A discarded
// --devnet reads to an operator as an assertion the tool honoured, which is
// the unasserted-network failure mode dressed as its fix.
//
// It drives walletAddress itself rather than the flag constructor. An earlier
// version of this test called addKeyFlags directly and passed even with
// walletAddress reverted to the full flag set — it pinned a helper nobody was
// accusing, not the command. Driving the command is the whole point, so the
// FlagSet is swapped to ContinueOnError first: walletAddress builds its own
// with ExitOnError, which would take the test process down with it.
func TestWalletAddressTakesNoNodeFlags(t *testing.T) {
	for _, name := range []string{"--rpc", "--devnet", "--params", "--confirm-rpc"} {
		t.Run(name, func(t *testing.T) {
			err := walletAddressFlagProbe(t, name)
			if err == nil {
				t.Fatalf("`zcd wallet address %s` was accepted; it must not be offered at all", name)
			}
			if !strings.Contains(err.Error(), "not defined") {
				t.Fatalf("%s was rejected for the wrong reason: %v", name, err)
			}
		})
	}
}

// walletAddressFlagProbe parses one flag against exactly the flag set
// walletAddress registers, without letting flag.ExitOnError end the test
// binary. Keeping the registration call identical to the command's is what
// makes this a test of the command and not of a helper.
func walletAddressFlagProbe(t *testing.T, name string) error {
	t.Helper()
	fs := flag.NewFlagSet("wallet address", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addKeyFlags(fs) // the same call walletAddress makes
	return fs.Parse([]string{name, "x"})
}

// TestWalletAddressRegistrationMatchesTheCommand fails if walletAddress ever
// stops using addKeyFlags, which is the assumption the probe above rests on.
func TestWalletAddressRegistrationMatchesTheCommand(t *testing.T) {
	src, err := os.ReadFile("wallet.go")
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(src, []byte("func walletAddress(args []string) error {"))
	if i < 0 {
		t.Fatal("walletAddress is gone; this test and its probe need rewriting")
	}
	// Bound the slice at the function's own closing brace, not at a byte
	// count. A fixed window overran walletAddress by 103 bytes into the next
	// function's doc comment, so an unrelated edit there could fail this test
	// with walletAddress untouched — a false accusation from the test that
	// exists to stop the command making false assurances.
	end := bytes.Index(src[i:], []byte("\n}\n"))
	if end < 0 {
		t.Fatal("cannot find the end of walletAddress")
	}
	body := src[i : i+end]
	if !bytes.Contains(body, []byte("addKeyFlags(fs)")) {
		t.Fatal("walletAddress no longer calls addKeyFlags; walletAddressFlagProbe " +
			"is now testing a flag set the command does not use")
	}
	if bytes.Contains(body, []byte("addWalletFlags(fs)")) || bytes.Contains(body, []byte("addNodeFlags(fs)")) {
		t.Fatal("walletAddress registers node flags again; it never opens a socket")
	}
}

// TestWalletBalanceRefusesChainIDMismatch is the other half of the same
// defect, and the live one: `zcd wallet balance --devnet` used to accept the
// assertion and query whatever node --rpc named, mainnet or not. A balance is
// the number an operator reads *before* deciding to sweep, so getting it from
// the wrong network is the same unasserted-network defect landing one command
// earlier than the signature.
func TestWalletBalanceRefusesChainIDMismatch(t *testing.T) {
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	addr := testKey(t, 1).OneShot()
	node.balance(addr, "12345")
	srv := node.server(t)

	err := walletBalance([]string{"--addr", hexAddr(addr), "--rpc", srv.URL, "--devnet"})
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("expected ErrChainIDMismatch, got %v", err)
	}
}

// TestWalletBalanceCrossChecksWhenAsked: --confirm-rpc used to be accepted and
// discarded here too, so an operator who cross-checked a balance before
// sweeping it had done nothing at all.
func TestWalletBalanceCrossChecksWhenAsked(t *testing.T) {
	addr := testKey(t, 1).OneShot()

	lying := newMockNode(spec.Mainnet().ChainID, "zycord")
	lying.balance(addr, "1")
	lyingSrv := lying.server(t)

	honest := newMockNode(spec.Mainnet().ChainID, "zycord")
	honest.balance(addr, "100000")
	honestSrv := honest.server(t)

	err := walletBalance([]string{"--addr", hexAddr(addr), "--rpc", lyingSrv.URL, "--confirm-rpc", honestSrv.URL})
	if !errors.Is(err, ErrBalanceSourcesDisagree) {
		t.Fatalf("expected ErrBalanceSourcesDisagree, got %v", err)
	}
}

// TestConfirmRPCMustNotBeTheSameEndpoint: a node cross-checking itself agrees
// with itself for exactly the reason CheckSweepsWholeCell does. Left
// unchecked, the confirmation prompt reports a second source that never
// existed — a false assurance printed on the one display this change exists
// to make truthful.
func TestConfirmRPCMustNotBeTheSameEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, rpc, confirm string
		want               bool
	}{
		{"identical", "http://node:9420", "http://node:9420", true},
		{"trailing slash", "http://node:9420", "http://node:9420/", true},
		{"different", "http://a:9420", "http://b:9420", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			n := addNodeFlags(fs)
			if err := fs.Parse([]string{"--rpc", tc.rpc, "--confirm-rpc", tc.confirm}); err != nil {
				t.Fatal(err)
			}
			_, err := n.resolve(fs)
			if got := errors.Is(err, ErrConfirmRPCNotIndependent); got != tc.want {
				t.Fatalf("refused = %v, want %v (err = %v)", got, tc.want, err)
			}
		})
	}
}

// TestFetchNodeStateAssertsTheSecondSourcesChainID: a second node on another
// network is a second node, not a second source for this chain. Wallet
// addresses are derived from a key rather than from a chain, so they exist on
// every network and read zero on one that has never seen them — two nodes
// "agreeing" that a payee is unspent when one has never heard of it is
// agreement about nothing, and the prompt would report it as an independent
// confirmation.
func TestFetchNodeStateAssertsTheSecondSourcesChainID(t *testing.T) {
	k := testKey(t, 1)
	from, to, refund := k.OneShot(), testKey(t, 2).Persistent(), k.Persistent()

	primary := newMockNode(spec.Mainnet().ChainID, "zycord")
	primary.balance(from, "500")
	primarySrv := primary.server(t)

	// Same balance, so the cross-check itself would pass; only the chain id
	// gives it away.
	other := newMockNode(spec.Devnet().ChainID, "zycord-devnet")
	other.balance(from, "500")
	otherSrv := other.server(t)

	_, err := fetchNodeState(primarySrv.URL, otherSrv.URL, from, to, refund, spec.Mainnet())
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("expected ErrChainIDMismatch for the second source, got %v", err)
	}
}

// TestConfirmSweepShowsPayeeAndRefund: the prompt's cited prior art is a
// hardware wallet's trusted display, and what that display exists to show is
// the destination. Neither address comes from a node, which is the point —
// this is the operator's one chance to compare the whole irreversible act
// against what they meant to do, and half of it is the two addresses.
func TestConfirmSweepShowsPayeeAndRefund(t *testing.T) {
	old := stdinReader
	stdinReader = bufio.NewReader(strings.NewReader("abort\n"))
	t.Cleanup(func() { stdinReader = old })

	var out bytes.Buffer
	k := testKey(t, 6)
	from, to, refund := k.OneShot(), testKey(t, 7).Persistent(), k.Persistent()
	_ = confirmSweep(&out, "http://node", "", from, to, refund,
		u256.FromUint64(1000), u256.FromUint64(900), u256.FromUint64(100))

	printed := out.String()
	for _, want := range []string{hexAddr(from), hexAddr(to), hexAddr(refund)} {
		if !strings.Contains(printed, want) {
			t.Fatalf("prompt does not name %s:\n%s", want, printed)
		}
	}
}
