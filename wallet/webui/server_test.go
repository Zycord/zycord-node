package webui_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"zycord/spec"
	"zycord/wallet"
	"zycord/wallet/webui"
)

// The security surface of `zcd ui`, tested rather than checked by hand.
//
// This process holds an unlocked private key behind an HTTP server, which is
// a shape with three well-known ways to go wrong: any page in the user's
// browser can send requests to 127.0.0.1, a hostname an attacker controls can
// be made to resolve there (DNS rebinding), and loopback is not an
// authentication boundary on a machine with more than one user. Each test
// below is one of those.

func newTestServer(t *testing.T) (*webui.Server, string) {
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
	api := webui.NewAPI(webui.Config{
		KeyPath:   keyPath,
		Params:    spec.Mainnet(),
		RPC:       "http://127.0.0.1:9420",
		LockAfter: time.Hour,
	})
	srv, err := webui.NewServer(api, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, keyPath
}

// request builds a request that is correct in every respect the test is not
// about, so that a refusal names the one thing the test changed.
func request(t *testing.T, srv *webui.Server, method, path string, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Host = "127.0.0.1:9430"
	r.Header.Set("Authorization", "Bearer "+srv.Token())
	if method != http.MethodGet {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	return r
}

func do(t *testing.T, srv *webui.Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// TestNoTokenIsRefused: the token is the authentication. Without it a request
// from any other process on the machine — or from any page the browser
// happens to have open — would be a request from the wallet's owner.
func TestNoTokenIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/api/wallet", "/api/node", "/api/balances"} {
		r := request(t, srv, http.MethodGet, path, "")
		r.Header.Del("Authorization")
		if got := do(t, srv, r).Code; got != http.StatusUnauthorized {
			t.Fatalf("GET %s with no token = %d, want 401", path, got)
		}
	}
}

func TestWrongTokenIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	r := request(t, srv, http.MethodGet, "/api/wallet", "")
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", len(srv.Token())))
	if got := do(t, srv, r).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", got)
	}
}

// TestForgedHostIsRefused is the DNS-rebinding case, which is the real attack
// against a server on loopback. A page at http://attacker.example, whose name
// the attacker re-points at 127.0.0.1, reaches this process — and the one
// thing it cannot forge is the Host header, because the browser fills it in
// from the name that was navigated to.
func TestForgedHostIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, host := range []string{"attacker.example", "attacker.example:9430", "wallet.local:9430", "127.0.0.1.nip.io:9430"} {
		r := request(t, srv, http.MethodGet, "/api/wallet", "")
		r.Host = host
		if got := do(t, srv, r).Code; got != http.StatusForbidden {
			t.Fatalf("Host %q = %d, want 403", host, got)
		}
	}
}

// TestLoopbackHostsAreAccepted is the control, and it also pins that the port
// is not part of the check: `ssh -L 9999:127.0.0.1:9430` is the documented way
// to reach this interface from another machine, and it arrives with a
// different port and the same name.
func TestLoopbackHostsAreAccepted(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, host := range []string{"127.0.0.1:9430", "localhost:9430", "127.0.0.1:9999", "[::1]:9430"} {
		r := request(t, srv, http.MethodGet, "/api/wallet", "")
		r.Host = host
		if got := do(t, srv, r).Code; got != http.StatusOK {
			t.Fatalf("Host %q = %d, want 200", host, got)
		}
	}
}

// TestCrossSiteWriteIsRefused: a POST that a browser reports as cross-site is
// refused before any handler sees it, whatever it carries.
func TestCrossSiteWriteIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, site := range []string{"cross-site", "same-site", "none"} {
		r := request(t, srv, http.MethodPost, "/api/unlock", `{"passphrase":"testpass"}`)
		r.Header.Set("Sec-Fetch-Site", site)
		if got := do(t, srv, r).Code; got != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Site %q = %d, want 403", site, got)
		}
	}
}

// TestWriteWithoutFetchMetadataOrOriginIsRefused: a request with neither
// header did not come from a browser. The scripting interface for this wallet
// is `zcd wallet`, so refusing costs nothing and closes the case where a
// browser predates Fetch Metadata and sends only Origin.
func TestWriteWithoutFetchMetadataOrOriginIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	r := request(t, srv, http.MethodPost, "/api/lock", `{}`)
	r.Header.Del("Sec-Fetch-Site")
	if got := do(t, srv, r).Code; got != http.StatusForbidden {
		t.Fatalf("write with no Fetch Metadata and no Origin = %d, want 403", got)
	}

	// Origin alone, from this page, is accepted.
	r = request(t, srv, http.MethodPost, "/api/lock", `{}`)
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Origin", "http://127.0.0.1:9430")
	if got := do(t, srv, r).Code; got != http.StatusOK {
		t.Fatalf("same-origin write with Origin only = %d, want 200", got)
	}

	// A cross-origin Origin is refused.
	r = request(t, srv, http.MethodPost, "/api/lock", `{}`)
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Origin", "http://attacker.example")
	if got := do(t, srv, r).Code; got != http.StatusForbidden {
		t.Fatalf("cross-origin write = %d, want 403", got)
	}
}

// TestOriginFallbackComparesThePort names the rule: the Origin fallback must
// compare the whole origin, port included, not just the host. Loopback is not
// an origin — to a browser http://127.0.0.1:8080 and http://127.0.0.1:9430 are
// as different as two unrelated sites are — so any other page served from this
// machine, on any other port, would otherwise count as same-origin to the
// wallet.
//
// Non-vacuity: with the check back at scheme+loopbackHost, every "different
// port" case below returns 200 and the test fails.
func TestOriginFallbackComparesThePort(t *testing.T) {
	srv, _ := newTestServer(t)

	// A loopback origin on some other port is a different origin.
	for _, origin := range []string{
		"http://127.0.0.1:8080",
		"http://127.0.0.1",
		"http://localhost:9430", // same port, different name: still not this origin
		"https://127.0.0.1:9430",
		"http://127.0.0.1:9430.attacker.example",
	} {
		r := request(t, srv, http.MethodPost, "/api/lock", `{}`)
		r.Header.Del("Sec-Fetch-Site")
		r.Header.Set("Origin", origin)
		if got := do(t, srv, r).Code; got != http.StatusForbidden {
			t.Fatalf("Origin %q against Host %q = %d, want 403", origin, r.Host, got)
		}
	}

	// The control, and the tunnel case: a browser puts the same authority in
	// Host and in Origin, so `ssh -L 9999:127.0.0.1:9430` keeps working.
	for _, host := range []string{"127.0.0.1:9430", "localhost:9999", "[::1]:9430"} {
		r := request(t, srv, http.MethodPost, "/api/lock", `{}`)
		r.Host = host
		r.Header.Del("Sec-Fetch-Site")
		r.Header.Set("Origin", "http://"+host)
		if got := do(t, srv, r).Code; got != http.StatusOK {
			t.Fatalf("Host %q with its own Origin = %d, want 200", host, got)
		}
	}
}

// TestNoCORSHeaders: the absence is the security property. A response that
// carried Access-Control-Allow-Origin would be readable by the page that
// asked for it, which is the whole of what the same-origin policy is
// otherwise doing for this wallet.
func TestNoCORSHeaders(t *testing.T) {
	srv, _ := newTestServer(t)
	w := do(t, srv, request(t, srv, http.MethodGet, "/api/wallet", ""))
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers"} {
		if v := w.Header().Get(h); v != "" {
			t.Fatalf("%s = %q, want absent", h, v)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP %q is missing %q", csp, want)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
}

// TestNonLoopbackBindIsRefused: there is no flag for this and there must not
// be one. The authentication here is a bearer token in a URL, which is
// adequate for a socket only the local machine can open and is not adequate
// for anything else.
func TestNonLoopbackBindIsRefused(t *testing.T) {
	api := webui.NewAPI(webui.Config{Params: spec.Mainnet()})
	for _, addr := range []string{"0.0.0.0:9430", "192.168.1.10:9430", "[::]:9430"} {
		if _, err := webui.NewServer(api, addr); !errors.Is(err, webui.ErrNotLoopback) {
			t.Fatalf("NewServer(%q) = %v, want ErrNotLoopback", addr, err)
		}
	}
}

// TestTokenIsFreshPerRun: nothing about a session is written down, so closing
// the window ends it.
func TestTokenIsFreshPerRun(t *testing.T) {
	a, _ := newTestServer(t)
	b, _ := newTestServer(t)
	if a.Token() == b.Token() {
		t.Fatal("two runs produced the same session token")
	}
	if len(a.Token()) < 32 {
		t.Fatalf("token is %d characters; too short to be a secret", len(a.Token()))
	}
	if !strings.Contains(a.URL(), "#t="+a.Token()) {
		t.Fatalf("the token must ride in the URL fragment, got %q", a.URL())
	}
	if strings.Contains(a.URL(), "?t=") {
		t.Fatal("the token is in the query string, where it lands in logs and Referer headers")
	}
}

// TestLockedWalletAnswers423: the interface has to tell a locked wallet apart
// from a bad request in order to show the unlock screen rather than an error.
func TestLockedWalletAnswers423(t *testing.T) {
	srv, _ := newTestServer(t)
	w := do(t, srv, request(t, srv, http.MethodGet, "/api/balances", ""))
	if w.Code != http.StatusLocked {
		t.Fatalf("balances while locked = %d, want 423", w.Code)
	}
}

// TestUnlockAndLock drives the key in and out of memory through the surface a
// browser uses.
func TestUnlockAndLock(t *testing.T) {
	srv, keyPath := newTestServer(t)

	w := do(t, srv, request(t, srv, http.MethodPost, "/api/unlock", `{"passphrase":"wrong"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unlock with a wrong passphrase = %d, want 400", w.Code)
	}

	w = do(t, srv, request(t, srv, http.MethodPost, "/api/unlock", `{"passphrase":"testpass"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("unlock = %d (%s), want 200", w.Code, w.Body.String())
	}
	var st webui.WalletState
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Locked || st.Persistent == "" || st.OneShot == "" {
		t.Fatalf("unlocked state is wrong: %+v", st)
	}
	if st.KeyPath != keyPath {
		t.Fatalf("key path = %q, want %q", st.KeyPath, keyPath)
	}

	w = do(t, srv, request(t, srv, http.MethodPost, "/api/lock", `{}`))
	if w.Code != http.StatusOK {
		t.Fatalf("lock = %d, want 200", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Locked || st.Persistent != "" {
		t.Fatalf("a locked wallet must publish no addresses: %+v", st)
	}
}

// TestIdleLockWipesTheKey: the interval that matters is the one where nobody
// is making requests, so the lock runs on a timer rather than on the next
// request.
func TestIdleLockWipesTheKey(t *testing.T) {
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
		RPC:       "http://127.0.0.1:9420",
		LockAfter: 20 * time.Millisecond,
	})
	if _, err := api.Unlock("testpass"); err != nil {
		t.Fatal(err)
	}
	if api.Wallet().Locked {
		t.Fatal("wallet is locked immediately after unlocking")
	}
	if api.LockIfIdle() {
		t.Fatal("locked before the idle interval elapsed")
	}
	time.Sleep(40 * time.Millisecond)
	if !api.LockIfIdle() {
		t.Fatal("the idle lock did not fire")
	}
	if !api.Wallet().Locked {
		t.Fatal("the wallet is not locked after the idle lock fired")
	}
}

// TestStaticShellNeedsNoToken but still needs a loopback Host: the page
// carries no secret — the token is in the fragment, which never reaches the
// server — while a page that loaded under a rebound hostname is a page that
// can then try the API.
func TestStaticShellNeedsNoToken(t *testing.T) {
	srv, _ := newTestServer(t)
	r := request(t, srv, http.MethodGet, "/", "")
	r.Header.Del("Authorization")
	w := do(t, srv, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Zycord") {
		t.Fatal("GET / did not serve the interface")
	}

	r = request(t, srv, http.MethodGet, "/", "")
	r.Host = "attacker.example"
	if got := do(t, srv, r).Code; got != http.StatusForbidden {
		t.Fatalf("GET / under a forged Host = %d, want 403", got)
	}
}

// TestAssetsAreSelfContained: the CSP forbids every external origin, so an
// asset that referenced one would fail at runtime in a way no Go test would
// otherwise see. This is the check that keeps "no npm, no CDN" true.
func TestAssetsAreSelfContained(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/", "/app.css", "/app.js", "/transport.js"} {
		r := request(t, srv, http.MethodGet, path, "")
		r.Header.Del("Authorization")
		w := do(t, srv, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, w.Code)
		}
		// The SVG namespace is a name, not a location: no agent fetches it,
		// and the favicon is inline in a data: URI precisely so that nothing
		// is fetched at all.
		body := strings.ReplaceAll(w.Body.String(), "http://www.w3.org/2000/svg", "")
		if strings.Contains(body, "@import url(") {
			t.Fatalf("%s imports a stylesheet; the CSP forbids it", path)
		}
		// Every remaining absolute URL must be loopback. The one legitimate
		// case is the default node address prefilled in a form, which is a
		// value a person edits rather than something the page fetches — and
		// which is loopback for the same reason everything else here is.
		for _, m := range urlPattern.FindAllString(body, -1) {
			u, err := url.Parse(m)
			if err != nil || !isLoopbackURL(u) {
				t.Fatalf("%s references an external origin (%q); the CSP forbids it and the wallet must not need one",
					path, m)
			}
		}
	}
}

// TestUnknownFieldsAreRefused: a request body this API does not understand is
// a mistake or a probe, and accepting it silently would let a future field
// name be typo'd into a default.
func TestUnknownFieldsAreRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	w := do(t, srv, request(t, srv, http.MethodPost, "/api/send", `{"to":"0x00","surprise":1}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "surprise") {
		t.Fatalf("the error should name the field it did not understand: %s", w.Body.String())
	}
}

// TestReadVerbsOnly: the API answers GET where it reads and POST where it
// writes, and nothing else. A PUT or a DELETE reaching a handler would be a
// route nobody designed.
func TestReadVerbsOnly(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := request(t, srv, method, "/api/wallet", "")
		if got := do(t, srv, r).Code; got != http.StatusMethodNotAllowed {
			t.Fatalf("%s /api/wallet = %d, want 405", method, got)
		}
	}
}

// TestSendWithoutApprovalIsRefused is the graphical form of the property the
// CLI's typed confirmation carries: a live send that was never approved does
// not happen, and the refusal comes from the wallet process rather than from
// the interface remembering to ask.
func TestSendWithoutApprovalIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	do(t, srv, request(t, srv, http.MethodPost, "/api/unlock", `{"passphrase":"testpass"}`))

	body := fmt.Sprintf(`{"to":%q,"amount":"1000","dry_run":false}`, "0x"+strings.Repeat("02", 32))
	w := do(t, srv, request(t, srv, http.MethodPost, "/api/send", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unapproved send = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not approved") {
		t.Fatalf("the refusal should say the spend was not approved: %s", w.Body.String())
	}
}

// TestZcdUIRefusesReconfiguration: `zcd ui` was told which key file, which
// node and which network on the command line, and the network is precisely the
// operator's own assertion. A page quietly replacing an assertion made one
// command earlier would be that failure wearing the costume of a settings
// screen. The desktop application, which is launched by double-clicking an
// icon and has nowhere else to be told, sets Config.Configurable and gets the
// screen.
func TestZcdUIRefusesReconfiguration(t *testing.T) {
	srv, _ := newTestServer(t)
	w := do(t, srv, request(t, srv, http.MethodPost, "/api/configure",
		`{"key_path":"/tmp/other.json","rpc":"http://127.0.0.1:9999","network":"zycord-devnet"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("configure = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "command line") {
		t.Fatalf("the refusal should say where the configuration came from: %s", w.Body.String())
	}

	// And the wallet is unchanged.
	w = do(t, srv, request(t, srv, http.MethodGet, "/api/wallet", ""))
	if !strings.Contains(w.Body.String(), `"chain_id":1`) {
		t.Fatalf("the network changed under a refused configure: %s", w.Body.String())
	}
}

// urlPattern finds absolute URLs in served assets. It is deliberately greedy
// about what counts as one: a false positive costs a line in this test, and a
// false negative is a wallet quietly reaching a host.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>()]+`)

func isLoopbackURL(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// The handoff, which exists because launching a browser publishes its argument
// vector.
//
// `zcd ui` opens a browser by running `xdg-open <url>` or `open <url>`, and
// that child's argv is readable by other users for as long as it lives —
// /proc/<pid>/cmdline on Linux, the process table on macOS, where an
// unprivileged account reads argv it does not own. Putting the session token
// there would hand it to exactly the reader the token exists to exclude — the
// same multi-user machine the loopback bind is explicitly not trusted on. So
// the browser gets a handoff instead: good once, good for minutes, and worth
// nothing after the page has traded it.

// TestBrowserURLCarriesNoSessionToken is the property the whole mechanism is
// for. If this ever fails, the token is back on another process's command
// line and nothing else here matters.
func TestBrowserURLCarriesNoSessionToken(t *testing.T) {
	srv, _ := newTestServer(t)
	browser := srv.BrowserURL()
	if strings.Contains(browser, srv.Token()) {
		t.Fatalf("BrowserURL leaks the session token: %s", browser)
	}
	if !strings.Contains(browser, "#h=") {
		t.Fatalf("BrowserURL = %q, want a #h= handoff fragment", browser)
	}
	// The printed URL is the other half of the trade and must keep the token:
	// it is what a person pastes into a browser on the far end of `ssh -L`,
	// possibly more than once.
	if !strings.Contains(srv.URL(), srv.Token()) {
		t.Fatalf("URL = %q, want the session token", srv.URL())
	}
}

// handoffOf pulls the secret out of the URL the browser would have been given,
// which is the only place a caller ever sees it.
func handoffOf(t *testing.T, srv *webui.Server) string {
	t.Helper()
	_, frag, ok := strings.Cut(srv.BrowserURL(), "#h=")
	if !ok {
		t.Fatalf("no handoff in %q", srv.BrowserURL())
	}
	return frag
}

// exchange runs the trade the page runs: a POST carrying the handoff and no
// Authorization header at all.
func exchange(t *testing.T, srv *webui.Server, handoff string) *httptest.ResponseRecorder {
	t.Helper()
	r := request(t, srv, http.MethodPost, "/api/session", `{"handoff":"`+handoff+`"}`)
	r.Header.Del("Authorization")
	return do(t, srv, r)
}

// TestHandoffBuysTheSessionTokenExactlyOnce: the first exchange succeeds, and
// the second gets nothing. Spending it is what makes a scraped handoff worth
// at most a race the loser can see.
func TestHandoffBuysTheSessionTokenExactlyOnce(t *testing.T) {
	srv, _ := newTestServer(t)
	h := handoffOf(t, srv)

	w := exchange(t, srv, h)
	if w.Code != http.StatusOK {
		t.Fatalf("first exchange = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Token != srv.Token() {
		t.Fatalf("exchanged token = %q, want the session token", got.Token)
	}

	if w := exchange(t, srv, h); w.Code != http.StatusUnauthorized {
		t.Fatalf("second exchange = %d, want 401", w.Code)
	}
}

// TestWrongHandoffIsRefused: the endpoint is reachable without the session
// token, so the handoff is the whole of its authentication.
func TestWrongHandoffIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, h := range []string{"", "not-the-handoff", srv.Token()} {
		if w := exchange(t, srv, h); w.Code != http.StatusUnauthorized {
			t.Fatalf("handoff %q = %d, want 401", h, w.Code)
		}
	}
	// And a wrong handoff must not have spent the real one.
	if w := exchange(t, srv, handoffOf(t, srv)); w.Code != http.StatusOK {
		t.Fatalf("the real handoff after failed attempts = %d, want 200", w.Code)
	}
}

// TestHandoffExchangeKeepsEveryOtherCheck: exempting this route from the token
// check exempts it from that check and from nothing else. A cross-site POST
// and a rebound Host are refused here exactly as they are everywhere else,
// which is what stops the exemption from being a hole in the guard.
func TestHandoffExchangeKeepsEveryOtherCheck(t *testing.T) {
	srv, _ := newTestServer(t)

	r := request(t, srv, http.MethodPost, "/api/session", `{"handoff":"`+handoffOf(t, srv)+`"}`)
	r.Header.Del("Authorization")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := do(t, srv, r); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site exchange = %d, want 403", w.Code)
	}

	r = request(t, srv, http.MethodPost, "/api/session", `{"handoff":"`+handoffOf(t, srv)+`"}`)
	r.Header.Del("Authorization")
	r.Host = "attacker.example"
	if w := do(t, srv, r); w.Code != http.StatusForbidden {
		t.Fatalf("rebound Host exchange = %d, want 403", w.Code)
	}

	// Both were refused before the handler ran, so the handoff is still good.
	if w := exchange(t, srv, handoffOf(t, srv)); w.Code != http.StatusOK {
		t.Fatalf("handoff after two refusals = %d, want 200", w.Code)
	}
}

// TestHandoffIsNotAToken: redeeming is all a handoff can do. Presenting one as
// a bearer token anywhere else is a 401, or the split would be cosmetic.
func TestHandoffIsNotAToken(t *testing.T) {
	srv, _ := newTestServer(t)
	r := request(t, srv, http.MethodGet, "/api/wallet", "")
	r.Header.Set("Authorization", "Bearer "+handoffOf(t, srv))
	if w := do(t, srv, r); w.Code != http.StatusUnauthorized {
		t.Fatalf("handoff used as a token = %d, want 401", w.Code)
	}
}

// TestHandoffIsFreshPerRun: two runs of `zcd ui` must not share one, for the
// same reason two runs must not share a token.
func TestHandoffIsFreshPerRun(t *testing.T) {
	a, _ := newTestServer(t)
	b, _ := newTestServer(t)
	if handoffOf(t, a) == handoffOf(t, b) {
		t.Fatal("two servers minted the same handoff")
	}
	// One server's handoff is worthless at the other, which is what makes the
	// freshness above mean anything.
	if w := exchange(t, b, handoffOf(t, a)); w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-server handoff = %d, want 401", w.Code)
	}
}

// TestExpiredHandoffIsRefused covers the fourth way a handoff can be no good.
//
// The deadline exists for the browser that never started: without it a handoff
// scraped from the process table stays live for as long as the wallet runs,
// and single use protects nothing if nobody ever spends it.
func TestExpiredHandoffIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	h := handoffOf(t, srv)
	srv.ExpireHandoff()

	if w := exchange(t, srv, h); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired handoff = %d, want 401", w.Code)
	}
	// And the printed URL still works, which is what makes the expiry a
	// bounded loss rather than a locked-out wallet.
	r := request(t, srv, http.MethodGet, "/api/wallet", "")
	if w := do(t, srv, r); w.Code != http.StatusOK {
		t.Fatalf("the session token after the handoff expired = %d, want 200", w.Code)
	}
}

// TestOnlyPOSTIsExemptFromTheTokenCheck: the exemption is for the one route
// that needs it, not for the path. A GET that skipped the token check because
// it shared a path with the exchange would be a hole opened by inheritance.
//
// The assertion is 401 specifically, and that precision is the whole test. An
// earlier version accepted "anything but 200" and passed against the very bug
// it was written for: with the exemption keyed on the path alone these verbs
// were let through the token check and then refused by the mux with 404 or
// 405, for want of a route rather than for want of a token. A test that cannot
// tell those two refusals apart is testing the routing table.
func TestOnlyPOSTIsExemptFromTheTokenCheck(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := request(t, srv, method, "/api/session", "")
		r.Header.Del("Authorization")
		if w := do(t, srv, r); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s /api/session without a token = %d, want 401 from the token check", method, w.Code)
		}
	}
}
