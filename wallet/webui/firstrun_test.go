package webui_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zycord/spec"
	"zycord/wallet"
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

// TestConfigureKnowsTheTestnet: the public testnet is one of the networks a
// wallet can be pointed at, by the same name every other zcd command uses.
func TestConfigureKnowsTheTestnet(t *testing.T) {
	api := newFirstRunAPI(t, "http://127.0.0.1:9420")
	state, err := api.Configure(webui.ConfigureRequest{RPC: "http://127.0.0.1:9420", Network: spec.Testnet().Name})
	if err != nil {
		t.Fatal(err)
	}
	if state.Network != spec.Testnet().Name || state.ChainID != spec.Testnet().ChainID {
		t.Fatalf("configured for %q chain %d, want the testnet", state.Network, state.ChainID)
	}
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

// TestProbeTellsWrongNetworkApartFromNoNode: the two things a person gets
// wrong on the first screen have different fixes, so the answer names which
// one it was.
func TestProbeTellsWrongNetworkApartFromNoNode(t *testing.T) {
	// A node that says it is on the testnet.
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"chain_id":%d,"height":77,"network":%q}`, spec.Testnet().ChainID, spec.Testnet().Name)
	}))
	defer node.Close()
	api := newFirstRunAPI(t, node.URL)

	// Asked as mainnet: reachable, and a mismatch that names both sides.
	res := api.Probe(webui.ProbeRequest{RPC: node.URL, Network: spec.Mainnet().Name})
	if !res.Reachable || res.Matches {
		t.Fatalf("expected reachable and mismatched, got %+v", res)
	}
	if res.Network != spec.Testnet().Name || res.ChainID != spec.Testnet().ChainID || res.Height != 77 {
		t.Fatalf("the node's own answer must be reported: %+v", res)
	}
	if res.Expected != spec.Mainnet().Name || !strings.Contains(res.Error, spec.Mainnet().Name) {
		t.Fatalf("the error must name what was expected: %+v", res)
	}

	// Asked as testnet: a match.
	res = api.Probe(webui.ProbeRequest{RPC: node.URL, Network: spec.Testnet().Name})
	if !res.Reachable || !res.Matches || res.Error != "" {
		t.Fatalf("expected a clean match, got %+v", res)
	}

	// Nothing listening: unreachable, and not a mismatch.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	res = api.Probe(webui.ProbeRequest{RPC: dead.URL, Network: spec.Testnet().Name})
	if res.Reachable || res.Matches || res.Error == "" {
		t.Fatalf("expected unreachable, got %+v", res)
	}

	// An unknown network name is an error before any socket is opened.
	res = api.Probe(webui.ProbeRequest{RPC: node.URL, Network: "moonnet"})
	if res.Reachable || !strings.Contains(res.Error, "moonnet") {
		t.Fatalf("expected the unknown network to be named, got %+v", res)
	}

	// The wallet's own node screen reports the same mismatch, with what the
	// node said, so the interface can offer the switch.
	info := api.Node()
	if info.Reachable || !info.Mismatch || info.NodeNetwork != spec.Testnet().Name {
		t.Fatalf("Node() on a mismatched node = %+v, want mismatch with the node's network", info)
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
		{http.MethodPost, "/api/probe", `{"rpc":"http://127.0.0.1:1","network":"zycord"}`},
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
