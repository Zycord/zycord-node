package webui_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"zycord/spec"
	"zycord/wallet"
	"zycord/wallet/localnode"
	"zycord/wallet/webui"
)

// The first run of the desktop application, as the API sees it: no key file,
// a node that may or may not be there, and a person who has never used a
// command line. Everything below exists so that screen can be completed
// without `zcd`.

func newFirstRunAPI(t *testing.T, rpc string) *webui.API {
	t.Helper()
	return webui.NewAPI(webui.Config{
		Params:       spec.Mainnet(),
		RPC:          rpc,
		LockAfter:    time.Hour,
		Configurable: true,
	})
}

// TestCreateWritesAnEncryptedKeyFileAndOpensIt: the graphical form of `zcd
// wallet new`. The file it leaves behind is the same format the CLI reads,
// the wallet is unlocked on it afterwards, and the state carries the
// addresses the first screen shows.
func TestCreateWritesAnEncryptedKeyFileAndOpensIt(t *testing.T) {
	api := newFirstRunAPI(t, "http://127.0.0.1:9420")
	if !api.Wallet().NeedsKey {
		t.Fatal("a wallet with no key path must report needs_key")
	}
	path := filepath.Join(t.TempDir(), "new.json")
	state, err := api.Create(webui.CreateRequest{KeyPath: path, Passphrase: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	if state.Locked || state.NeedsKey || state.KeyPath != path {
		t.Fatalf("after Create: locked=%v needs_key=%v key_path=%q", state.Locked, state.NeedsKey, state.KeyPath)
	}
	if !strings.HasPrefix(state.Persistent, "0x02") || !strings.HasPrefix(state.OneShot, "0x01") {
		t.Fatalf("the state must carry both addresses, got %q and %q", state.Persistent, state.OneShot)
	}

	// The CLI can open what the interface wrote, with the same passphrase.
	k, err := wallet.LoadKeyFile(path, []byte("correct horse"))
	if err != nil {
		t.Fatalf("the file Create wrote is not a key file the CLI reads: %v", err)
	}
	if got := "0x" + fmt.Sprintf("%x", k.Persistent()); got != state.Persistent {
		t.Fatalf("the file holds a different key than the state reports: %s vs %s", got, state.Persistent)
	}
	if _, err := wallet.LoadKeyFile(path, []byte("wrong")); !errors.Is(err, wallet.ErrBadPassphrase) {
		t.Fatalf("a wrong passphrase must be refused, got %v", err)
	}
}

// TestCreateRefusesToOverwrite is docs/WALLET.md rule 7 reaching the
// interface: a key file already at the destination is never replaced, and the
// wallet stays on whatever it had.
func TestCreateRefusesToOverwrite(t *testing.T) {
	api := newFirstRunAPI(t, "http://127.0.0.1:9420")
	path := filepath.Join(t.TempDir(), "w.json")
	if _, err := api.Create(webui.CreateRequest{KeyPath: path, Passphrase: "one"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Create(webui.CreateRequest{KeyPath: path, Passphrase: "two"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected a refusal to overwrite, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the existing key file was modified by a refused Create")
	}
	if k, err := wallet.LoadKeyFile(path, []byte("one")); err != nil {
		t.Fatalf("the first key must still open: %v", err)
	} else {
		k.Zero()
	}
}

// TestCreateNeedsAPassphraseAndAPath: there is no unencrypted key format, and
// no default location that a person would not be told about.
func TestCreateNeedsAPassphraseAndAPath(t *testing.T) {
	api := newFirstRunAPI(t, "http://127.0.0.1:9420")
	if _, err := api.Create(webui.CreateRequest{KeyPath: filepath.Join(t.TempDir(), "k.json")}); err == nil {
		t.Fatal("an empty passphrase must be refused")
	}
	if _, err := api.Create(webui.CreateRequest{Passphrase: "x"}); err == nil {
		t.Fatal("an empty path must be refused")
	}
}

// TestCreateIsRefusedWhereConfigureIs: `zcd ui` was told its key file on the
// command line, and a page must not be able to swap it for one it made.
func TestCreateIsRefusedWhereConfigureIs(t *testing.T) {
	srv, _ := newTestServer(t)
	body := fmt.Sprintf(`{"key_path":%q,"passphrase":"x"}`, filepath.Join(t.TempDir(), "k.json"))
	w := do(t, srv, request(t, srv, http.MethodPost, "/api/create", body))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "command line") {
		t.Fatalf("POST /api/create on zcd ui = %d %s, want a refusal naming the command line", w.Code, w.Body.String())
	}
}

// stubNode writes an executable that does nothing but stay alive, so that
// Configure's node-starting path can be driven without compiling zycordd into
// this package's tests. localnode.Manager.Start returns once the process is
// started; it does not wait for RPC, which is what makes this enough.
//
// Skipped on Windows, where a shell script is not an executable. The path this
// stands in for is covered there by wallet/localnode's own tests, which build
// the real binary.
func stubNode(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no shell scripts on Windows; wallet/localnode covers this path with the real binary")
	}
	p := filepath.Join(t.TempDir(), "zycordd")
	script := "#!/bin/sh\n" +
		"case \"$1\" in --version) echo 'zycordd v0.0.0-stub'; exit 0;; esac\n" +
		"exec sleep 60\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestConfigureRunsTheWalletsOwnNodeForTheChosenNetwork: choosing a network is
// the whole of what a person decides, and the wallet answers it by starting
// its own node for that network and talking to whatever address it chose.
func TestConfigureRunsTheWalletsOwnNodeForTheChosenNetwork(t *testing.T) {
	mgr := &localnode.Manager{Binary: stubNode(t), DataRoot: t.TempDir(), Port: freeTestPort(t)}
	t.Cleanup(func() { _ = mgr.Stop() })
	api := webui.NewAPI(webui.Config{
		Params: spec.Mainnet(), RPC: "http://127.0.0.1:9420",
		LockAfter: time.Hour, Configurable: true, LocalNode: mgr,
	})

	state, err := api.Configure(webui.ConfigureRequest{
		RPC:     "http://a-stranger.example:9420",
		Network: spec.Testnet().Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Network != spec.Testnet().Name || state.ChainID != spec.Testnet().ChainID {
		t.Fatalf("configured for %q chain %d, want the testnet", state.Network, state.ChainID)
	}
	if state.NodeMode != "local" {
		t.Fatalf("node_mode = %q, want local; this wallet has no other mode", state.NodeMode)
	}
	if state.RPC != mgr.RPC() || state.RPC == "http://a-stranger.example:9420" {
		t.Fatalf("RPC = %q, want the address the wallet's own node was given", state.RPC)
	}
	info := mgr.Info()
	if !info.Running || info.Network != spec.Testnet().Name {
		t.Fatalf("the wallet did not start its own node for the chosen network: %+v", info)
	}
	if info.Version != "v0.0.0-stub" || state.NodeVersion != "v0.0.0-stub" {
		t.Fatalf("the node's version should be read off the binary and reported: info %q, state %q",
			info.Version, state.NodeVersion)
	}
}

// TestTheWalletKnowsTheTestnet: the public testnet is one of the networks a
// first run offers, by the same name every other zcd command uses.
func TestTheWalletKnowsTheTestnet(t *testing.T) {
	api := newFirstRunAPI(t, "http://127.0.0.1:9420")
	var names []string
	for _, n := range api.Networks() {
		names = append(names, n.Name)
	}
	for _, want := range []string{spec.Mainnet().Name, spec.Testnet().Name, spec.Devnet().Name} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Fatalf("Networks() = %v, missing %q", names, want)
		}
	}
	// The first run offers the two public networks and not the devnet, which
	// stays reachable from Settings.
	for _, n := range api.Networks() {
		if want := n.Name != spec.Devnet().Name; n.Public != want {
			t.Fatalf("%s public=%v, want %v", n.Name, n.Public, want)
		}
	}
}

// TestAConfigurableWalletIsAlwaysItsOwnNode: this version offers no way to
// name somebody else's node, so Configure ignores any address that reaches it
// and refuses outright when the package has no zycordd to run.
//
// The refusal is the point. A wallet that fell back to "tell me a node" the
// moment its own was missing would put a person's balance in a stranger's
// gift at exactly the moment they are least able to judge the offer.
func TestAConfigurableWalletIsAlwaysItsOwnNode(t *testing.T) {
	api := newFirstRunAPI(t, "http://127.0.0.1:9420")
	_, err := api.Configure(webui.ConfigureRequest{
		RPC:     "http://a-stranger.example:9420",
		Network: spec.Testnet().Name,
	})
	if !errors.Is(err, webui.ErrNoBundledNode) {
		t.Fatalf("Configure with no bundled node = %v, want ErrNoBundledNode", err)
	}
	st := api.Wallet()
	if st.RPC == "http://a-stranger.example:9420" {
		t.Fatal("a refused Configure must not adopt the address it was handed")
	}
	if st.LocalNodeAvailable {
		t.Fatal("a wallet built with no bundled node must not claim to have one")
	}
}

// TestTheWalletReportsItsOwnVersion: the version is shown, so it has to reach
// the state a front end renders.
func TestTheWalletReportsItsOwnVersion(t *testing.T) {
	api := webui.NewAPI(webui.Config{
		Version: "v9.9.9-test", Params: spec.Mainnet(),
		RPC: "http://127.0.0.1:9420", LockAfter: time.Hour,
	})
	if got := api.Wallet().Version; got != "v9.9.9-test" {
		t.Fatalf("Wallet().Version = %q, want the configured version", got)
	}
	if got := api.Wallet().NodeVersion; got != "" {
		t.Fatalf("with no bundled node, NodeVersion = %q, want empty", got)
	}
}

// TestFirstRunRoutesExist: the browser transport reaches the same three calls
// over HTTP, and each is guarded like every other route.
func TestFirstRunRoutesExist(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/networks", ""},
	} {
		w := do(t, srv, request(t, srv, tc.method, tc.path, tc.body))
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s = %d %s, want 200", tc.method, tc.path, w.Code, w.Body.String())
		}
		r := request(t, srv, tc.method, tc.path, tc.body)
		r.Header.Del("Authorization")
		if w := do(t, srv, r); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token = %d, want 401", tc.method, tc.path, w.Code)
		}
	}
	w := do(t, srv, request(t, srv, http.MethodGet, "/api/networks", ""))
	if !strings.Contains(w.Body.String(), spec.Testnet().Name) {
		t.Fatalf("GET /api/networks does not list the testnet: %s", w.Body.String())
	}
}

// freeTestPort is a port nothing is listening on, so a stub node can be
// "started" on it without colliding with a real one.
func freeTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
