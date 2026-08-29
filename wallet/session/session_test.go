package session_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"zycord/core/crypto"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
	"zycord/wallet/session"
)

// mockNode is a stand-in for a node's RPC surface. It is deliberately the same
// shape as the one in cmd/zcd's understating-source suite: the tests there pin
// the CLI against this package, and these pin the package itself.
type mockNode struct {
	mu        sync.Mutex
	chainID   uint64
	network   string
	height    uint64
	balances  map[types.Address]string
	spent     map[types.Address]bool
	submitted int
	// asked counts /balance requests per address, so a test can assert that
	// a duplicate address costs one round trip rather than two.
	asked map[types.Address]int
}

func newMockNode(chainID uint64, network string) *mockNode {
	return &mockNode{
		chainID:  chainID,
		network:  network,
		height:   1000,
		balances: map[types.Address]string{},
		spent:    map[types.Address]bool{},
		asked:    map[types.Address]int{},
	}
}

func (m *mockNode) balance(a types.Address, drops string) *mockNode {
	m.balances[a] = drops
	return m
}

func (m *mockNode) submitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.submitted
}

func (m *mockNode) askCount(a types.Address) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.asked[a]
}

func (m *mockNode) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			fmt.Fprintf(w, `{"chain_id":%d,"height":%d,"network":%q}`, m.chainID, m.height, m.network)
		case "/fees":
			fmt.Fprint(w, `{"seq_base_fee":"10","par_base_fee":"5","skip_fee":"1000"}`)
		case "/balance":
			addr, err := session.ParseAddress(r.URL.Query().Get("addr"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			m.asked[addr]++
			bal, ok := m.balances[addr]
			spent := m.spent[addr]
			m.mu.Unlock()
			if !ok {
				bal = "0"
			}
			fmt.Fprintf(w, `{"balance":%q,"spent":%v}`, bal, spent)
		case "/submit":
			m.mu.Lock()
			m.submitted++
			m.mu.Unlock()
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
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

// TestNilApproveRefusesAnIrreversibleDrain is the property that makes a second
// front end safe to write. A caller that never supplies an approval callback
// cannot burn a one-shot address: the zero value refuses. A GUI that forgets
// to ask therefore fails closed, which is the only direction this default can
// fail in without losing somebody's money.
func TestNilApproveRefusesAnIrreversibleDrain(t *testing.T) {
	k := testKey(t, 1)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.OneShot(), "5000000000000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := session.DefaultSendOptions()
	opts.OneShot = true
	opts.Sweep = true
	// opts.Approve deliberately left nil.

	_, err = s.Send(testKey(t, 9).Persistent(), u256.Zero, opts)
	if !errors.Is(err, session.ErrNotApproved) {
		t.Fatalf("expected ErrNotApproved, got %v", err)
	}
	if n := node.submitCount(); n != 0 {
		t.Fatalf("an unapproved drain must never reach /submit, got %d submissions", n)
	}
}

// TestApproveIsNotConsultedForAPersistentSource: the gate is on the
// certificate, not on the caller. A persistent address cannot be burned, so
// spending from one is not the irreversible act the prompt exists for and
// must not demand an approval nobody can meaningfully give.
func TestApproveIsNotConsultedForAPersistentSource(t *testing.T) {
	k := testKey(t, 2)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "5000000000000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := session.DefaultSendOptions()
	opts.Approve = func(*session.Preview) error {
		t.Fatal("Approve must not be called for a persistent source")
		return nil
	}
	res, err := s.Send(testKey(t, 9).Persistent(), u256.FromUint64(1000), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || node.submitCount() != 1 {
		t.Fatalf("expected exactly one submission, got submitted=%v count=%d", res.Submitted, node.submitCount())
	}
}

// TestDryRunNeverSubmits pins the one option a front end will reach for while
// showing numbers to a user.
func TestDryRunNeverSubmits(t *testing.T) {
	k := testKey(t, 3)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "5000000000000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := session.DefaultSendOptions()
	opts.DryRun = true
	var seen *session.Preview
	opts.OnPreview = func(p *session.Preview) error { seen = p; return nil }

	res, err := s.Send(testKey(t, 9).Persistent(), u256.FromUint64(1000), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Submitted || node.submitCount() != 0 {
		t.Fatal("a dry run must not submit")
	}
	if seen == nil || !seen.Amount.Eq(u256.FromUint64(1000)) {
		t.Fatalf("the preview did not carry the amount: %+v", seen)
	}
}

// TestOnPreviewErrorAborts: a front end that cannot render the numbers must be
// able to stop the spend, and stopping must be the default reading of an
// error rather than something the caller has to arrange separately.
func TestOnPreviewErrorAborts(t *testing.T) {
	k := testKey(t, 4)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "5000000000000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("the user closed the window")
	opts := session.DefaultSendOptions()
	opts.OnPreview = func(*session.Preview) error { return sentinel }

	if _, err := s.Send(testKey(t, 9).Persistent(), u256.FromUint64(1000), opts); !errors.Is(err, sentinel) {
		t.Fatalf("expected the preview's error, got %v", err)
	}
	if node.submitCount() != 0 {
		t.Fatal("an aborted preview must not submit")
	}
}

// TestFetchStateAsksEachAddressOnce: sending to yourself, or refunding to the
// source, names the same address twice. Asking twice doubles the round trips
// and — with a second source configured — doubles them again, for an answer
// already known.
func TestFetchStateAsksEachAddressOnce(t *testing.T) {
	k := testKey(t, 5)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "1000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	p := k.Persistent()
	v, err := s.FetchState(p, p, p)
	if err != nil {
		t.Fatal(err)
	}
	if got := node.askCount(p); got != 1 {
		t.Fatalf("asked the same address %d times, want 1", got)
	}
	if !v.FromBalance.Eq(u256.FromUint64(1000)) {
		t.Fatalf("fromBalance = %s, want 1000", v.FromBalance.String())
	}
}

// TestRetireRefusesAPersistentAddress: RETIRE acts on one-shot addresses
// only (core/validity), and a persistent address cannot enter the spent
// registry at all. Refusing here names the reason instead of leaving the
// derivation to reject it with a rule number.
func TestRetireRefusesAPersistentAddress(t *testing.T) {
	k := testKey(t, 6)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "5000000000000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Retire([]types.Address{k.Persistent()}, session.DefaultSendOptions())
	if err == nil || !strings.Contains(err.Error(), "one-shot") {
		t.Fatalf("expected a refusal naming one-shot addresses, got %v", err)
	}
}

// TestRetireSubmits drives the command the usage string has advertised since
// M1 and the switch had no case for. The one-shot being retired holds
// nothing, which is what wallet.CheckSweepsWholeCell requires: retiring an
// address that still holds a balance strands it exactly as a partial spend
// would.
func TestRetireSubmits(t *testing.T) {
	k := testKey(t, 7)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "5000000000000")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Retire([]types.Address{k.OneShot()}, session.DefaultSendOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || node.submitCount() != 1 {
		t.Fatalf("expected one submission, got submitted=%v count=%d", res.Submitted, node.submitCount())
	}
}

// TestRetireRefusesAnAddressThatStillHoldsValue is the rule the whitepaper's
// §11 implies and wallet/policy.go enforces: sweep first, retire after.
func TestRetireRefusesAnAddressThatStillHoldsValue(t *testing.T) {
	k := testKey(t, 8)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), "5000000000000")
	node.balance(k.OneShot(), "42")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire([]types.Address{k.OneShot()}, session.DefaultSendOptions()); err == nil {
		t.Fatal("expected a refusal: retiring an address that still holds a balance strands it")
	}
	if node.submitCount() != 0 {
		t.Fatal("nothing may be submitted when a policy rule refuses")
	}
}

// TestSameEndpointIsNotASecondSource: a node cross-checking itself agrees with
// itself, and every display downstream would report an independent
// confirmation that never happened.
func TestSameEndpointIsNotASecondSource(t *testing.T) {
	_, err := session.New(nil, spec.Mainnet(), "http://node:9420", "http://node:9420/")
	if !errors.Is(err, session.ErrConfirmRPCNotIndependent) {
		t.Fatalf("expected ErrConfirmRPCNotIndependent, got %v", err)
	}
}

// TestReadOnlySessionCannotSpend: `zcd wallet balance --addr` holds no key,
// and a session without one must refuse to sign rather than panic.
func TestReadOnlySessionCannotSpend(t *testing.T) {
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	url := node.serve(t)
	s, err := session.New(nil, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(testKey(t, 9).Persistent(), u256.One, session.DefaultSendOptions()); !errors.Is(err, session.ErrNoKey) {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
}

// TestSessionViewRefusesACellItNeverFetched pins the property that a session
// view answers only for cells it actually asked a node about, and says so
// rather than reporting its own blind spot as the chain's answer.
//
// The blind spot is on the asset axis. FetchState asks a node for an address's
// native balance and writes only types.NativeBalanceSlot, so a non-native
// asset cell is not representable in the view at all; state.State deletes on
// zero, so an unfetched cell and an empty one read identically. Before this,
// the first multi-asset TRANSFER built through a session would have been
// refused by wallet.CheckMovesAreCovered as if the funded source were empty —
// and that refusal is the one SendOptions.Force is allowed to swallow.
func TestSessionViewRefusesACellItNeverFetched(t *testing.T) {
	k := testKey(t, 11)
	from, to := k.Persistent(), testKey(t, 12).Persistent()
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(from, "5000000000000")
	node.balance(to, "0")
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.FetchState(from, to)
	if err != nil {
		t.Fatal(err)
	}

	build := func(prog types.Program) *types.Certificate {
		t.Helper()
		b := &wallet.Builder{
			Params:  v.Params,
			Program: prog,
			TTL:     v.Height + 10,
			Deposit: wallet.SelfDeposit(from, from),
			FeeBid:  wallet.BidWithHeadroom(v.SeqBase, v.ParBase, u256.FromUint64(10), u256.FromUint64(1), 2),
			Signers: []*wallet.Key{k},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// The separating input: the same move under the native asset is covered,
	// so what the view refuses below is the asset it never fetched and not
	// the addresses, the amount, or the shape of the certificate.
	native := build(wallet.Tip(types.NativeAsset, from, to, u256.FromUint64(1000)))
	if err := v.CoversCertificate(native); err != nil {
		t.Fatalf("a native move between two fetched addresses must be covered: %v", err)
	}

	var asset types.Address
	asset[0] = crypto.AddrVersionAsset
	asset[7] = 0xAA
	foreign := build(wallet.Tip(asset, from, to, u256.FromUint64(1000)))
	err = v.CoversCertificate(foreign)
	if !errors.Is(err, session.ErrCellNotFetched) {
		t.Fatalf("a move under an asset this view never fetched must be refused as uncovered, got %v", err)
	}
	// It must not be reported as a balance problem: that is the wrong claim
	// about whose state is short, and it is the error Force may override.
	if errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatal("an unfetched cell was reported as an underfunded one")
	}

	// The second conjunct, separated on its own. The rule is "every debited
	// cell was fetched" over the deposit cell AND the move sources; the two
	// witnesses above hold the deposit cell fixed and fetched, so they cannot
	// tell whether the deposit clause exists at all. Here the moves are all
	// covered and only the deposit cell is one this view never asked about.
	// The cell is swapped in after Build rather than built through it: the
	// deposit's owner must authorise it (V4), so a builder cannot emit this
	// shape, and it is the view's answer that is under test, not the codec's.
	unfetchedDeposit := build(wallet.Tip(types.NativeAsset, from, to, u256.FromUint64(1000)))
	unfetchedDeposit.Deposit.Cell = types.NativeBalanceSlot(testKey(t, 13).Persistent())
	if err := v.CoversCertificate(unfetchedDeposit); !errors.Is(err, session.ErrCellNotFetched) {
		t.Fatalf("a deposit cell this view never fetched must be refused as uncovered, got %v", err)
	}

	// The third conjunct, and the one that fails OPEN rather than closed.
	// wallet.CheckSweepsWholeCell requires each RETIRE target's native cell to
	// hold nothing; an unfetched cell reads zero and zero reads as "already
	// empty", so a target missing from the fetch set is accepted and whatever
	// it holds is stranded by the burn. The program is swapped in after Build
	// because retiring a one-shot needs that address's own signature (V4) and
	// this session does not hold it — the view's answer is what is under test.
	burn := testKey(t, 14).OneShot()
	retire := build(wallet.Tip(types.NativeAsset, from, to, u256.FromUint64(1000)))
	retire.Program = wallet.Retire(burn)
	if err := v.CoversCertificate(retire); !errors.Is(err, session.ErrCellNotFetched) {
		t.Fatalf("a retire target this view never fetched must be refused as uncovered, got %v", err)
	}
	// The separating input: the same certificate against a view that DID fetch
	// the target is covered, so what the arm above refuses is the missing
	// answer and not RETIRE as a program kind.
	node.balance(burn, "0")
	v2, err := s.FetchState(from, to, burn)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.CoversCertificate(retire); err != nil {
		t.Fatalf("a retire target this view fetched must be covered: %v", err)
	}
}

// TestSessionViewRefusesAOneShotPayeeItNeverFetched is the payee axis's
// separating input, driven end to end through FetchState rather than through a
// hand-built View.
//
// The property: the SAME certificate, paying the SAME one-shot address, is
// covered by a view built with FetchState(from, payee) and refused by one
// built with FetchState(from) — so what the view refuses is the answer it does
// not hold, and not the payment as a kind.
//
// It fails OPEN without the fix, which is the dangerous direction.
// wallet.CheckPayeeIsFresh reads s.IsSpent(m.Dst) and the destination's
// balance cell; MarkSpent is written only for fetched addresses and an
// unfetched balance cell reads zero, and "not spent, holds nothing" is exactly
// the fresh answer. So the unfetched payee below passed the rule that exists
// to refuse it (whitepaper §4, I1-H3).
//
// The payee here is deliberately LIVE and EMPTY on the node. That is the
// non-vacuity of the test: a spent or credited payee would be refused by
// CheckPayeeIsFresh itself once fetched, so the covered half would pass for
// the rule's reason rather than the view's. On this input the rule has no
// objection either way, and the only difference between the two views is
// whether the wallet ever asked.
func TestSessionViewRefusesAOneShotPayeeItNeverFetched(t *testing.T) {
	k := testKey(t, 21)
	from := k.Persistent()
	payee := testKey(t, 22).OneShot()

	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(from, "5000000000000")
	node.balance(payee, "0") // live and empty: the rule itself has no objection
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	covered, err := s.FetchState(from, payee)
	if err != nil {
		t.Fatal(err)
	}
	blind, err := s.FetchState(from)
	if err != nil {
		t.Fatal(err)
	}

	b := &wallet.Builder{
		Params:  covered.Params,
		Program: wallet.Tip(types.NativeAsset, from, payee, u256.FromUint64(1000)),
		TTL:     covered.Height + 10,
		Deposit: wallet.SelfDeposit(from, from),
		FeeBid:  wallet.BidWithHeadroom(covered.SeqBase, covered.ParBase, u256.FromUint64(10), u256.FromUint64(1), 2),
		Signers: []*wallet.Key{k},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	if err := covered.CoversCertificate(cert); err != nil {
		t.Fatalf("the view that fetched the payee must cover this certificate: %v", err)
	}
	err = blind.CoversCertificate(cert)
	if !errors.Is(err, session.ErrSpentFlagNotFetched) {
		t.Fatalf("a one-shot payee this view never fetched must be refused as unanswerable, got %v", err)
	}
	// And it must not be reported as the chain's answer. The wallet has not
	// established that this payee is used; it has established that it does not
	// know, and those are different claims to put in front of an operator.
	if errors.Is(err, wallet.ErrPayingUsedOneShot) {
		t.Fatal("an unfetched payee was reported as an already-used one-shot")
	}

	// FetchState must record the spent-flag answer for an address that came
	// back LIVE, not only for one that came back spent. state.MarkSpent is
	// written only in the spent case, which is precisely why the answer needs
	// its own set: the payee above is unspent on the node, and the covered
	// view still has to know that.
	if node.askCount(payee) == 0 {
		t.Fatal("the covered view never asked about the payee, so it is not the separating input it claims to be")
	}
}
