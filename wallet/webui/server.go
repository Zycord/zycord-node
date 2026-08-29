package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultAddr is where `zcd ui` listens. It is not the node's RPC port
// (9420) and not the p2p port (9421): three ports, three surfaces, so a
// firewall rule or a tunnel names exactly one of them.
const DefaultAddr = "127.0.0.1:9430"

// ErrNotLoopback reports an attempt to bind the wallet interface somewhere
// other than loopback.
//
// There is no flag to override this and there should not be. The process
// behind this listener holds an unlocked private key, and its authentication
// is a bearer token in a URL — which is adequate for a socket only the local
// machine can open and is not adequate for anything else. A person who wants
// this interface from another machine forwards the port over ssh, which
// authenticates properly and encrypts, and which is one flag on their side
// rather than a security decision on ours.
var ErrNotLoopback = errors.New("webui: the wallet interface binds loopback only; forward a port over ssh to reach it from elsewhere")

// ErrHandoffSpent reports a handoff secret that is expired, already used, or
// simply wrong. One error for all three on purpose: an attacker who scraped a
// handoff learns nothing from which of them it was.
var ErrHandoffSpent = errors.New("webui: this handoff is no longer valid; open the URL that was printed in the terminal")

// handoffTTL bounds how long the browser we launched has to present its
// handoff. Single use is the actual defence; the deadline covers the case
// where the browser never started at all and the handoff would otherwise stay
// live for the life of the process.
const handoffTTL = 5 * time.Minute

// Server is the loopback HTTP front end for an API.
type Server struct {
	api   *API
	token string
	ln    net.Listener
	srv   *http.Server
	stop  chan struct{}

	// mu guards the handoff, which is single-use by definition and therefore
	// racy by definition.
	mu          sync.Mutex
	handoff     string
	handoffDone bool
	handoffTill time.Time
}

// NewServer binds addr and returns a server that is listening but not yet
// serving. addr must be loopback.
//
// The listener is opened here, rather than inside Serve, so that "the port is
// already in use" is an error the caller can report before it prints a URL
// nobody can open.
func NewServer(api *API, addr string) (*Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("webui: %q is not a host:port address: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %q", ErrNotLoopback, addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	token, err := newToken()
	if err != nil {
		ln.Close()
		return nil, err
	}
	handoff, err := newToken()
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{
		api: api, token: token, ln: ln, stop: make(chan struct{}),
		handoff: handoff, handoffTill: time.Now().Add(handoffTTL),
	}
	s.srv = &http.Server{
		Handler: s.Handler(),
		// A wallet answers in milliseconds. These bound a client that opens a
		// connection and then stalls, which on a single-user loopback server
		// is a bug or an attack and never a slow network.
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s, nil
}

// Addr is the address actually bound, which is what a caller wants when the
// requested port was 0.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Token is the session's bearer token. A fresh one per run: nothing about it
// is written down, so closing the window ends the session.
func (s *Server) Token() string { return s.token }

// URL is what the caller prints and what a browser opens.
//
// The token rides in the fragment, not the query. A fragment is never sent to
// a server, never lands in an access log, and is not carried in a Referer, so
// the one place the secret exists in transit is the address bar of the
// browser that owns it. The page reads it once and clears it.
func (s *Server) URL() string {
	return "http://" + s.Addr() + "/#t=" + s.token
}

// BrowserURL is what `zcd ui` hands to the browser it launches itself, and it
// deliberately carries something weaker than URL does.
//
// Launching a browser means running `xdg-open <url>`, `open <url>` or
// `rundll32 ... <url>`, and the URL is then an argument vector of another
// process. Argument vectors are readable by other users on the machine: on
// Linux through /proc/<pid>/cmdline, and on macOS too — an unprivileged
// account there reads the full argv of processes it does not own, including
// root's, which was measured rather than assumed. So for as long as that child
// lives, what we passed it is public to the machine.
//
// That is precisely the reader the session token exists to exclude — the guard
// below says loopback is not an authentication boundary on a multi-user
// machine, and a token published through argv is not one either.
//
// So the child gets a handoff instead: a second secret, valid once and only
// for a few minutes, which the page trades at POST /api/session for the real
// token. An attacker who scrapes the argv either arrives after the browser and
// gets nothing, or arrives first — and then the wallet fails to open in front
// of the person watching it, rather than sharing its authority in silence.
//
// The printed URL keeps the full token. It goes to the operator's own
// terminal, and it has to stay replayable: reaching this interface over `ssh
// -L` means pasting that URL into a browser on another machine, possibly more
// than once.
func (s *Server) BrowserURL() string {
	return "http://" + s.Addr() + "/#h=" + s.handoff
}

// redeemHandoff exchanges a handoff for the session token, once.
func (s *Server) redeemHandoff(got string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handoffDone || time.Now().After(s.handoffTill) {
		return "", ErrHandoffSpent
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.handoff)) != 1 {
		return "", ErrHandoffSpent
	}
	// Burned whether or not the caller was the browser we launched. If it was
	// not, the browser's own exchange now fails and the person sees it.
	s.handoffDone = true
	return s.token, nil
}

// Serve runs until Close. It also runs the idle lock, because a wallet whose
// window is open and whose owner has gone home is exactly the case the idle
// lock exists for.
func (s *Server) Serve() error {
	go s.api.watchIdle(s.stop)
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops serving and locks the wallet. A closed window must not leave a
// key in memory behind it.
func (s *Server) Close() error {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.api.Lock()
	return s.srv.Close()
}

// Handler is the whole routing table, exported so the security surface can be
// driven by tests without opening a socket.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// The static shell. It carries no secret — the token is in the fragment,
	// which never reaches here — so it is served without authentication. What
	// it is not served without is the Host check: a page that loads at all
	// under a rebound hostname is a page that can then try the API.
	mux.Handle("GET /", http.FileServerFS(Assets()))

	// The one route reachable without the session token, because handing the
	// token over is what it is for. It is not unauthenticated: the handoff is
	// its credential, and the Host and same-origin checks in guard apply to it
	// exactly as they do to everything else under /api/.
	mux.HandleFunc("POST /api/session", s.json(func(r *http.Request) (any, error) {
		var req struct {
			Handoff string `json:"handoff"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		token, err := s.redeemHandoff(req.Handoff)
		if err != nil {
			return nil, err
		}
		return map[string]string{"token": token}, nil
	}))

	mux.HandleFunc("GET /api/wallet", s.json(func(*http.Request) (any, error) {
		return s.api.Wallet(), nil
	}))
	mux.HandleFunc("GET /api/node", s.json(func(*http.Request) (any, error) {
		return s.api.Node(), nil
	}))
	mux.HandleFunc("GET /api/balances", s.json(func(*http.Request) (any, error) {
		return s.api.Balances()
	}))
	mux.HandleFunc("GET /api/balance", s.json(func(r *http.Request) (any, error) {
		return s.api.Balance(r.URL.Query().Get("addr"))
	}))
	mux.HandleFunc("POST /api/unlock", s.json(func(r *http.Request) (any, error) {
		var req struct {
			Passphrase string `json:"passphrase"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return s.api.Unlock(req.Passphrase)
	}))
	mux.HandleFunc("POST /api/lock", s.json(func(*http.Request) (any, error) {
		return s.api.Lock(), nil
	}))
	mux.HandleFunc("GET /api/settings", s.json(func(*http.Request) (any, error) {
		return s.api.Settings(), nil
	}))
	// Registered even though `zcd ui` refuses it (Config.Configurable is
	// false there), so that the frontend is the same file in both front ends
	// and the refusal is the wallet's answer rather than a missing route.
	mux.HandleFunc("POST /api/configure", s.json(func(r *http.Request) (any, error) {
		var req ConfigureRequest
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return s.api.Configure(req)
	}))
	mux.HandleFunc("POST /api/send", s.json(func(r *http.Request) (any, error) {
		var req SendRequest
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return s.api.Send(req)
	}))
	mux.HandleFunc("POST /api/retire", s.json(func(r *http.Request) (any, error) {
		var req RetireRequest
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return s.api.Retire(req)
	}))

	return s.guard(mux)
}

// guard is the security surface, in the order the checks are worth running.
//
// Each one closes a different attack, and none of them is a substitute for
// another:
//
//   - The Host check is what stops DNS rebinding, which is the real attack
//     against a localhost server: any page in the user's browser can make
//     requests to 127.0.0.1, and a hostname the attacker controls can be made
//     to resolve there. The one thing such a request cannot forge is the Host
//     header, because the browser fills it in from the name that was
//     navigated to.
//   - The token is the authentication. Loopback is not an authentication
//     boundary on a multi-user machine, and it is not one against any other
//     process on a single-user machine either.
//   - Sec-Fetch-Site is anti-CSRF for the writes: a token-less cross-site POST
//     would be refused by the token check anyway, and this refuses it one
//     layer earlier and without the request ever reaching a handler.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// default-src 'none' with an explicit allowance per directive, so a
		// directive nobody thought about denies rather than inherits. There
		// is no connect-src beyond 'self': this page has nowhere else to
		// talk to, and a wallet that could reach an external host is a wallet
		// that could export a seed.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		// No CORS headers at all. Their absence is what makes a cross-origin
		// read of any response here unusable to the page that made it.

		if !loopbackHost(r.Host) {
			http.Error(w, "webui: refusing a request whose Host is not loopback (DNS rebinding)", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet && !sameOrigin(r) {
				http.Error(w, "webui: refusing a write that is not same-origin", http.StatusForbidden)
				return
			}
			// POST /api/session is how a page that has only a handoff obtains
			// the token, so requiring the token here would make it
			// unreachable. Its own credential is the handoff, checked in
			// constant time and spent on first use; see BrowserURL.
			//
			// Keyed on the method as well as the path, so the exemption covers
			// exactly the one route that exists rather than every future verb
			// somebody hangs off this path. A hole that opens by being
			// inherited is the kind nobody reviews.
			//
			// This compares the same decoded r.URL.Path that ServeMux routes
			// on, which is what makes "exempt" and "routed to the exchange"
			// the same set — /api/%73ession is exempt here and also lands on
			// the exchange handler. Comparing EscapedPath() or RawPath instead
			// would separate the two and open exactly the gap this check is
			// for, so do not "fix" it that way.
			exempt := r.Method == http.MethodPost && r.URL.Path == "/api/session"
			if !exempt && !s.authorised(r) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="zycord wallet"`)
				http.Error(w, "webui: missing or wrong session token", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorised(r *http.Request) bool {
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// loopbackHost checks the name the browser was navigated to, and deliberately
// ignores the port.
//
// The port is not the security-relevant half. A rebinding attacker chooses
// the port in the URL they navigate to — it has to be ours or the request
// never arrives — while the *name* is the part they control and the part the
// browser reports faithfully. Ignoring the port is also what makes `ssh -L
// 9999:127.0.0.1:9430` work, which is the documented way to reach this
// interface on a server.
func loopbackHost(host string) bool {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	if name == "localhost" {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin refuses a write that a browser did not make from this page.
//
// Fetch Metadata is the primary signal and is what every current browser
// sends. Origin is the fallback for one that does not: it is sent on every
// cross-origin write and on same-origin POSTs too, so an absent Origin *and*
// an absent Sec-Fetch-Site means the request did not come from a browser at
// all — which is a refusal rather than a pass, because the scripting
// interface for this wallet is `zcd wallet`, not a bearer token pasted into
// curl.
//
// The fallback compares the *whole* origin, port included, against the
// authority the browser was navigated to. loopbackHost is deliberately
// port-blind (see above) and is the right rule for the Host check, but it is
// the wrong rule here: to a browser, http://127.0.0.1:8080 is a different
// origin from http://127.0.0.1:9430, so another local process serving a page
// on any other loopback port would otherwise be same-origin to this wallet.
// Comparing against r.Host rather than against the listen address is what
// keeps `ssh -L 9999:127.0.0.1:9430` working: the browser puts the same
// authority in both headers, whatever the tunnel renumbered it to.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	return origin == "http://"+r.Host
}

// json wraps a handler that returns a value or an error.
//
// Errors are 400 with the message, because every error this API can produce
// is a statement about the request or about what a node said, and both are
// things the person at the keyboard needs to read. The one exception is a
// locked wallet, which the interface has to be able to tell apart from a bad
// request in order to show the unlock screen.
func (s *Server) json(h func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := h(r)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			code := http.StatusBadRequest
			switch {
			case errors.Is(err, ErrLocked):
				code = http.StatusLocked
			case errors.Is(err, ErrHandoffSpent):
				code = http.StatusUnauthorized
			}
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

// maxRequestBody bounds what a local page can make this process buffer. Every
// request here is a handful of fields.
const maxRequestBody = 1 << 16

func decode(r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
