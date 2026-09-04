package webui_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/spec"
	"zycord/wallet"
	"zycord/wallet/session"
	"zycord/wallet/webui"
)

// A node stand-in, so the spending path can be driven end to end without a
// chain. It is the same shape as the one in cmd/zcd's understating-source
// suite and in wallet/session's, on purpose: the three interfaces are supposed
// to behave identically against identical answers, and identical fixtures are
// how that claim gets tested rather than asserted.
type fakeNode struct {
	mu        sync.Mutex
	balances  map[types.Address]string
	submitted int
	// beforeBalance, if set, runs before every /balance answer. It is how a
	// test stalls a spend in the middle of one.
	beforeBalance func()
	// tipTime is what /status reports as the tip's timestamp; zero means
	// now. floor is the checkpoint height it claims to enforce.
	tipTime int64
	floor   uint64
	// peers is what /network reports; zero means the default of three, and
	// a negative value means none.
	peers int
}

func (f *fakeNode) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			tip := f.tipTime
			if tip == 0 {
				tip = time.Now().Unix()
			}
			fmt.Fprintf(w, `{"chain_id":%d,"height":1000,"network":"zycord","time":%d,"min_chain_work_height":%d}`,
				spec.Mainnet().ChainID, tip, f.floor)
		case "/fees":
			fmt.Fprint(w, `{"seq_base_fee":"10","par_base_fee":"5","skip_fee":"1000"}`)
		case "/balance":
			if f.beforeBalance != nil {
				f.beforeBalance()
			}
			addr, err := session.ParseAddress(r.URL.Query().Get("addr"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			bal, ok := f.balances[addr]
			f.mu.Unlock()
			if !ok {
				bal = "0"
			}
			fmt.Fprintf(w, `{"balance":%q,"spent":false}`, bal)
		case "/network":
			peers := 3
			if f.peers != 0 {
				peers = max(f.peers, 0)
			}
			fmt.Fprintf(w, `{"enabled":true,"peers":%d,"listening":true,"inbound":2,"outbound":1,"reachable":true}`, peers)
		case "/submit":
			f.mu.Lock()
			f.submitted++
			f.mu.Unlock()
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeNode) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.submitted
}

func newUnlockedAPI(t *testing.T, node *fakeNode) (*webui.API, *wallet.Key) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")
	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(keyPath, k, []byte("testpass")); err != nil {
		t.Fatal(err)
	}
	if node.balances == nil {
		node.balances = map[types.Address]string{}
	}
	api := webui.NewAPI(webui.Config{
		KeyPath:   keyPath,
		Params:    spec.Mainnet(),
		RPC:       node.serve(t),
		LockAfter: time.Hour,
	})
	if _, err := api.Unlock("testpass"); err != nil {
		t.Fatal(err)
	}
	return api, k
}

// TestDryRunThenApprovedSendIsTheWholeFlow: the interface previews, the
// person approves the numbers they were shown, and only then does anything
// reach the node.
func TestDryRunThenApprovedSendIsTheWholeFlow(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.mu.Unlock()

	to := "0x" + strings.Repeat("02", 32)
	preview, err := api.Send(webui.SendRequest{To: to, Amount: "1000", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Submitted || node.count() != 0 {
		t.Fatal("a dry run must not submit")
	}
	if preview.Amount != "1000" {
		t.Fatalf("preview amount = %s, want 1000", preview.Amount)
	}

	res, err := api.Send(webui.SendRequest{
		To:       to,
		Amount:   "1000",
		Approved: &webui.Approval{To: preview.To, Amount: preview.Amount, Held: preview.Held},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || node.count() != 1 {
		t.Fatalf("expected one submission, got submitted=%v count=%d", res.Submitted, node.count())
	}
}

// TestApprovalDoesNotCarryToDifferentNumbers is the graphical equivalent of a
// hardware wallet's trusted display. The wallet re-reads the node before it
// signs, so a source balance that moved between the preview and the
// confirmation produces a different certificate — and an approval given for
// one set of numbers must not authorise another.
//
// This is the case that matters for a sweep, where the amount *is* a function
// of the reported balance.
func TestApprovalDoesNotCarryToDifferentNumbers(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.OneShot()] = "5000000000000"
	node.mu.Unlock()

	to := "0x02" + strings.Repeat("aa", 31)
	preview, err := api.Send(webui.SendRequest{To: to, OneShot: true, Sweep: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !preview.OneShotDrain {
		t.Fatal("a one-shot sweep must be reported as an irreversible drain")
	}

	// The node now reports a different balance, which is exactly the case a
	// second source exists for — whether because the cell was paid again or
	// because the node was lying the first time.
	node.mu.Lock()
	node.balances[k.OneShot()] = "9000000000000"
	node.mu.Unlock()

	_, err = api.Send(webui.SendRequest{
		To:       to,
		OneShot:  true,
		Sweep:    true,
		Approved: &webui.Approval{To: preview.To, Amount: preview.Amount, Held: preview.Held},
	})
	if err == nil {
		t.Fatal("expected the stale approval to be refused")
	}
	if !strings.Contains(err.Error(), "changed between the preview and the confirmation") {
		t.Fatalf("expected ErrPreviewChanged, got %v", err)
	}
	if node.count() != 0 {
		t.Fatalf("nothing may be submitted on a stale approval, got %d", node.count())
	}
}

// TestGraphicalSendObeysTheSamePolicyAsTheCLI: paying a one-shot address that
// already holds a balance is docs/WALLET.md rule 3, and the graphical wallet
// gets it from wallet/session rather than from anyone remembering to add it
// here. Removing the check from this package is impossible, which is the
// property routing every front end through wallet/session exists to create.
func TestGraphicalSendObeysTheSamePolicyAsTheCLI(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, k := newUnlockedAPI(t, node)

	payee, err := wallet.KeyFromSeed(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.balances[payee.OneShot()] = "42" // already credited: rule 3
	node.mu.Unlock()

	_, err = api.Send(webui.SendRequest{
		To:     session.HexAddr(payee.OneShot()),
		Amount: "1000",
		DryRun: true,
	})
	if err == nil || !strings.Contains(err.Error(), "already been credited") {
		t.Fatalf("expected wallet.ErrPayingUsedOneShot, got %v", err)
	}
}

// TestLockedAPIRefusesEverythingThatNeedsAKey.
func TestLockedAPIRefusesEverythingThatNeedsAKey(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, _ := newUnlockedAPI(t, node)
	api.Lock()

	if _, err := api.Balances(); err == nil {
		t.Fatal("balances must refuse while locked")
	}
	if _, err := api.Send(webui.SendRequest{To: "0x" + strings.Repeat("02", 32), Amount: "1", DryRun: true}); err == nil {
		t.Fatal("send must refuse while locked")
	}
	// The node screen still works: a locked wallet should say which network
	// and which node it is pointed at before a passphrase is typed.
	if info := api.Node(); !info.Reachable {
		t.Fatalf("the node screen must work while locked: %+v", info)
	}
}

// TestEveryExportedAPIMethodIsBindable.
//
// The desktop application binds *API into its JavaScript bridge by embedding
// it, and Wails marshals arguments and returns as JSON. A method that takes a
// channel, a function or an interface therefore cannot be bound — and the
// failure surfaces in the desktop build, at the moment somebody presses a
// button, rather than here where the change was made.
//
// The rule this pins is the one in API's doc comment: every exported method
// is bindable as it stands. Anything that is not gets an unexported name.
func TestEveryExportedAPIMethodIsBindable(t *testing.T) {
	at := reflect.TypeOf(&webui.API{})
	errType := reflect.TypeOf((*error)(nil)).Elem()
	for i := 0; i < at.NumMethod(); i++ {
		m := at.Method(i)
		for j := 1; j < m.Type.NumIn(); j++ { // 0 is the receiver
			if !jsonShaped(m.Type.In(j)) {
				t.Errorf("API.%s takes %s, which does not survive the desktop bridge; "+
					"give it an unexported name if it is not part of the front-end surface",
					m.Name, m.Type.In(j))
			}
		}
		for j := 0; j < m.Type.NumOut(); j++ {
			if out := m.Type.Out(j); out != errType && !jsonShaped(out) {
				t.Errorf("API.%s returns %s, which does not survive the desktop bridge", m.Name, out)
			}
		}
	}
}

func jsonShaped(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice:
		return jsonShaped(t.Elem())
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.Struct, reflect.Map:
		return true
	default:
		return false
	}
}

// TestNodePollingDoesNotDefeatTheIdleLock.
//
// The interface polls the node screen every few seconds to keep the height in
// its header current. If that counted as activity, the idle lock would never
// fire while a window was open — which is exactly and only the situation it
// exists for. Only what a person did counts.
func TestNodePollingDoesNotDefeatTheIdleLock(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")
	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(keyPath, k, []byte("testpass")); err != nil {
		t.Fatal(err)
	}
	api := webui.NewAPI(webui.Config{
		KeyPath:   keyPath,
		Params:    spec.Mainnet(),
		RPC:       node.serve(t),
		LockAfter: 30 * time.Millisecond,
	})
	if _, err := api.Unlock("testpass"); err != nil {
		t.Fatal(err)
	}

	// Poll the way the interface does, for longer than the idle interval.
	deadline := time.Now().Add(120 * time.Millisecond)
	for time.Now().Before(deadline) {
		api.Node()
		api.LockIfIdle()
		time.Sleep(10 * time.Millisecond)
	}
	if !api.Wallet().Locked {
		t.Fatal("polling the node screen kept the wallet unlocked; the idle lock is defeated by " +
			"the interface's own heartbeat")
	}
}

// TestAnApprovalDoesNotCarryToADifferentPayee.
//
// The payee is on the confirmation display for the reason a hardware wallet
// puts it on its screen: it is half of what a person is actually approving.
// An approval that only pinned the amounts would let a caller re-send the same
// numbers to a different address.
func TestAnApprovalDoesNotCarryToADifferentPayee(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.mu.Unlock()

	shown := "0x02" + strings.Repeat("aa", 31)
	preview, err := api.Send(webui.SendRequest{To: shown, Amount: "1000", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}

	elsewhere := "0x02" + strings.Repeat("bb", 31)
	_, err = api.Send(webui.SendRequest{
		To:       elsewhere,
		Amount:   "1000",
		Approved: &webui.Approval{To: preview.To, Amount: preview.Amount, Held: preview.Held},
	})
	if err == nil || !strings.Contains(err.Error(), "changed between the preview and the confirmation") {
		t.Fatalf("expected the approval to be refused for a different payee, got %v", err)
	}
	if node.count() != 0 {
		t.Fatalf("nothing may be submitted on an approval for another payee, got %d", node.count())
	}
}

// TestLockWaitsForASpendInFlight.
//
// The idle lock and an explicit lock both wipe the seed in place. A wipe that
// lands in the middle of Ed25519 signing does not produce an error — it
// produces a signature from zeroed material, which verifies against a public
// key nobody controls, on a certificate the network then rejects with no hint
// that the wallet was locked underneath it.
//
// The fix is that a spend holds the key under a read lock for its whole
// duration, so a lock waits rather than races. This drives that: a node that
// stalls mid-spend must block Lock until the spend finishes.
func TestLockWaitsForASpendInFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	node := &fakeNode{balances: map[types.Address]string{}, beforeBalance: func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.mu.Unlock()

	sent := make(chan error, 1)
	go func() {
		_, err := api.Send(webui.SendRequest{
			To:     "0x02" + strings.Repeat("cc", 31),
			Amount: "1000",
			DryRun: true,
		})
		sent <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the spend never reached the node")
	}

	locked := make(chan struct{})
	go func() {
		api.Lock()
		close(locked)
	}()

	select {
	case <-locked:
		close(release)
		t.Fatal("Lock returned while a spend was in flight; it could have wiped the seed mid-signature")
	case <-time.After(150 * time.Millisecond):
	}

	close(release)
	if err := <-sent; err != nil {
		t.Fatalf("the spend failed: %v", err)
	}
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("Lock never returned after the spend finished")
	}
	if !api.Wallet().Locked {
		t.Fatal("the wallet is not locked")
	}
}

// TestAnApprovalWithoutAPayeeIsRefused pins that Approval.To is required
// rather than checked-if-present.
//
// An optional security field is a security field a caller disables by
// omission, and this one is the payee — the half of a spend a hardware wallet
// puts on its trusted display precisely because the amounts alone do not
// identify who is being paid. SendOptions.Approve defaults to nil and nil
// refuses, for the same reason and in the same direction: what a front end
// forgets to say must not become what it is allowed to do.
func TestAnApprovalWithoutAPayeeIsRefused(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.mu.Unlock()

	to := "0x02" + strings.Repeat("07", 31)
	preview, err := api.Send(webui.SendRequest{To: to, Amount: "1000", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}

	_, err = api.Send(webui.SendRequest{
		To:     to,
		Amount: "1000",
		// Every field the old shape carried, and no payee.
		Approved: &webui.Approval{Amount: preview.Amount, Held: preview.Held},
	})
	if err == nil {
		t.Fatal("an approval naming no payee must not authorise a spend")
	}
	if !errors.Is(err, webui.ErrNotApproved) {
		t.Fatalf("expected ErrNotApproved, got %v", err)
	}
	if node.count() != 0 {
		t.Fatalf("nothing may be submitted, got %d", node.count())
	}
}
