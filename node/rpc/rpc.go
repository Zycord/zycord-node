// Package rpc serves a read-only view of the node over HTTP.
//
// The surface is deliberately tiny and deliberately powerless (M1-G4):
//
//   - It binds localhost by default. A node that is reachable by default is a
//     node somebody else operates.
//   - Every method is read-only except certificate submission, which is the one
//     thing a wallet cannot do for itself, and which is subject to exactly the
//     same admission rules as a certificate arriving from a peer.
//   - There are no privileged endpoints, because there is nothing an admin
//     could call: no key can pause, upgrade, censor or mint (P3). The absence
//     is the feature.
//   - **The node holds no key material.** Signing happens in the wallet, in a
//     different process, and nothing in this package accepts a seed, a private
//     key or a passphrase.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/checkpoints"
	"zycord/node/mempool"
)

// Config configures the server.
type Config struct {
	// Addr is the listen address. Default: 127.0.0.1:9420.
	Addr string
	// MaxBodyBytes bounds a submitted certificate.
	MaxBodyBytes int64
	// RequestsPerMinute rate-limits each client address. Zero selects a default;
	// rate limits are on by default rather than opt-in.
	RequestsPerMinute int
	// BlockBytesPerMinute bounds the block bytes one client address may pull
	// from /block?format=ssz in a minute. Zero selects a default.
	//
	// A request count alone bounds the number of questions and nothing about
	// the cost of the answers, and block bytes are the one answer that is
	// orders of magnitude larger than the question: at the default 600
	// requests per minute and an 8 MB block ceiling, a flat count authorises
	// roughly 4.8 GB a minute to a single address, on a box that is also
	// running consensus.
	BlockBytesPerMinute int64
}

// DefaultConfig returns the shipped defaults: localhost, small bodies, limited.
func DefaultConfig() Config {
	return Config{
		Addr:              "127.0.0.1:9420",
		MaxBodyBytes:      1 << 20,
		RequestsPerMinute: 600,
		// 256 MiB a minute is about 36 Mbit/s: a factor of 17.9 below the
		// 4.8 GB the request count alone would permit at the 8 MB capacity
		// wall, and far above anything a real indexer needs — 600 requests a
		// minute of 437 KiB each would still fit under it, and blocks that
		// size do not exist yet. The budget is meant to stop a client asking for the ceiling
		// over and over, not to slow down one that is reading the chain.
		BlockBytesPerMinute: 256 << 20,
	}
}

// Network is the connection view the RPC reports.
//
// An interface rather than a concrete node so that this package does not depend
// on the peer-to-peer one: observability should be able to read the network,
// never to steer it.
type Network interface {
	PeerCount() int
	// Reachability reports whether this node accepts connections, and how many
	// it has in each direction.
	Reachability() (listening bool, inbound, outbound int)
	// PeerHealth reports raw scoring state — known peers, how many are banned,
	// and the lowest score — upstream of every filter that consumes it.
	PeerHealth() (known, banned, minScore int)
	// AnnounceCertificate gossips a certificate this node has accepted.
	//
	// Submission has to reach a miner, and the node a user submits to is
	// usually not one. Without this a certificate accepted over RPC sits in one
	// mempool until its TTL expires while its sender watches a transaction that
	// will never confirm — and the node reports it as accepted, because locally
	// it was.
	AnnounceCertificate(*types.Certificate)
}

// Server exposes a node over HTTP.
type Server struct {
	chain *chain.Chain
	pool  *mempool.Pool
	cfg   Config
	net   Network

	mu sync.Mutex
	// seen is the rate limiter's per-address state. It is swept, not merely
	// pruned in place: see sweepLocked.
	seen      map[string]*client
	lastSweep time.Time
	now       func() time.Time
	srv       *http.Server
	// ln is the bound listener, set by Listen and served by ListenAndServe.
	// Listen runs before the serve goroutine is launched, so the go statement
	// that starts ListenAndServe is the happens-before edge that publishes it;
	// there is no concurrent writer, and Shutdown never reads it.
	ln      net.Listener
	metrics *Metrics
}

// window is the rate limiter's fixed window, for both of its budgets.
const window = time.Minute

// client is one address's usage inside the current window.
type client struct {
	// reqs holds one timestamp per admitted request.
	reqs []time.Time
	// bytes holds block bytes served, kept apart from reqs because the two
	// budgets are independent: /status has to stay answerable to a client that
	// has spent its whole block-byte allowance.
	bytes []byteCharge
}

// byteCharge is block bytes served at a moment.
type byteCharge struct {
	at time.Time
	n  int64
}

func (c *client) empty() bool { return len(c.reqs) == 0 && len(c.bytes) == 0 }

// Metrics is the observability surface (M1-G7). It is deliberately boring
// counters: a public testnet is undebuggable without them, and retrofitting
// observability under incident pressure is how non-consensus code sprouts
// consensus bugs.
type Metrics struct {
	mu sync.Mutex

	// Only what this package is the source of truth for. Chain counters live on
	// the chain (node/chain/stats.go): they were here once, fed from the miner's
	// loop alone, which made every one of them structurally unable to count a
	// block this node received rather than produced.
	SubmitAccepted uint64
	SubmitRejected uint64
}

func (m *Metrics) snapshot() Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Metrics{SubmitAccepted: m.SubmitAccepted, SubmitRejected: m.SubmitRejected}
}

// WriteTimeout is the deadline every handler's response is subject to, and so
// the longest a handler can usefully still be running.
//
// Exported because a process teardown has to size its shutdown grace against
// it: a grace shorter than this abandons handlers the server itself still
// considers live, and cmd/zycordd closes the chain store the moment the grace
// expires. Two independent literals coupled only by a comment drift the
// first time one of them moves, so the teardown reads this one.
const WriteTimeout = 15 * time.Second

// readTimeout is how long a caller has to deliver a whole request. It is its
// own setting rather than WriteTimeout spelled twice: they happen to be equal,
// but WriteTimeout is now the teardown's grace as well, so naming the read
// deadline by it would let a change to the shutdown budget silently move how
// long a slow uploader is given.
const readTimeout = 15 * time.Second

// New returns a server over a chain and its pool.
func New(c *chain.Chain, pool *mempool.Pool, cfg Config, m *Metrics) *Server {
	if cfg.Addr == "" {
		cfg = DefaultConfig()
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultConfig().MaxBodyBytes
	}
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = DefaultConfig().RequestsPerMinute
	}
	if cfg.BlockBytesPerMinute <= 0 {
		cfg.BlockBytesPerMinute = DefaultConfig().BlockBytesPerMinute
	}
	if m == nil {
		m = &Metrics{}
	}
	s := &Server{chain: c, pool: pool, cfg: cfg, seen: map[string]*client{}, now: time.Now, metrics: m}
	// Built here, not in ListenAndServe. ListenAndServe runs on its own
	// goroutine in cmd/zycordd while Shutdown is called from main's teardown,
	// so a field assigned by the one and read by the other is a data race whose
	// losing outcome is a shutdown that shuts nothing down: Shutdown sees nil,
	// returns, and the server keeps serving requests against a chain main is
	// about to close. Constructing it before either goroutine exists
	// removes the window rather than locking it.
	s.srv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      WriteTimeout,
	}
	return s
}

// Handler returns the routed handler, exported so tests can drive it without a
// socket.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Reads refuse anything but GET and HEAD. Answering a POST with the read's
	// body is not a mutation — the state root cannot move — which is exactly
	// why it went unnoticed, and it still meant POST /block?format=ssz returned
	// megabytes to a caller that had asked for the wrong verb.
	mux.HandleFunc("/status", s.read(s.handleStatus))
	mux.HandleFunc("/head", s.read(s.handleHead))
	mux.HandleFunc("/block", s.read(s.handleBlock))
	mux.HandleFunc("/params", s.read(s.handleParams))
	mux.HandleFunc("/cell", s.read(s.handleCell))
	mux.HandleFunc("/balance", s.read(s.handleBalance))
	mux.HandleFunc("/fees", s.read(s.handleFees))
	mux.HandleFunc("/mempool", s.read(s.handleMempool))
	mux.HandleFunc("/metrics", s.read(s.handleMetrics))
	mux.HandleFunc("/network", s.read(s.handleNetwork))
	// The one write, and the only route that accepts a verb other than GET.
	mux.HandleFunc("/submit", s.wrap(s.handleSubmit))
	return mux
}

// Listen binds cfg.Addr. It is split out of ListenAndServe so a caller can
// learn whether the bind succeeded — and log a truthful "listening" line —
// before it hands the serving off to a goroutine. An announcement printed
// ahead of the bind is a prediction, not an observation: in the run where the
// bind then fails it says the RPC is up while the node serves nothing.
//
// It says nothing about whether a failed bind should be fatal; that is the
// caller's policy to keep, and this method only reports the outcome.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Addr reports the address the listener actually bound, or nil before Listen has
// run. Where cfg.Addr names a concrete port this is that same address; where it
// ends in :0 — an ephemeral port a container or a test hands the process — it is
// the port the kernel chose, which cfg.Addr never carried and which is the
// address something must reach the RPC on. A caller logging the bind wants this
// rather than cfg.Addr, so the "listening" line names the socket that opened
// rather than the request that was made for it.
//
// It only reads s.ln, which Listen publishes before the serve goroutine exists,
// so it introduces no new writer and no new race (the construction of s.srv is
// left in NewServer, ahead of both goroutines, for the reason given there).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// ListenAndServe starts the server. It returns http.ErrServerClosed once
// Shutdown or Close has been called.
//
// If Listen has already bound the address it serves that listener; otherwise
// it binds cfg.Addr itself, so a direct caller that does not need to observe
// the bind separately still works unchanged.
func (s *Server) ListenAndServe() error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	return s.srv.Serve(s.ln)
}

// Shutdown stops the server and waits for the requests already being served to
// finish, or for ctx to be done.
//
// This is the one a process teardown wants, and Close is not. A handler holds
// the chain and the mempool for as long as it runs — /block reads block bytes
// out of the store, /balance walks state — so a caller that closes the store
// after Close has returned closes it under a live reader. Close returns
// as soon as the listeners and the idle connections are shut; it says nothing
// about handlers already inside the mux.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// Close stops the server without waiting for in-flight requests. Prefer
// Shutdown wherever the caller is about to release something a handler holds.
func (s *Server) Close() error {
	return s.srv.Close()
}

// errRateLimited asks the wrapper for 429 rather than 400.
//
// A handler that refuses on cost is refusing for the same reason the limiter
// does, and a client cannot tell "your request was malformed" from "you asked
// for too much" if both come back as 400.
var errRateLimited = errors.New("rate limited")

// errNotFound and errWrongMethod are the two answers that used to arrive as
// 400 alongside genuinely malformed input.
//
// This surface is read by machines. A poller asking for a height the chain has
// not reached, or for the body of a block whose body was not retained, is not
// making a mistake — it is asking a well-formed question with a negative
// answer, and it needs to tell that from "your request is wrong" without
// parsing prose. Getting the codes right before an explorer is written against
// them is much cheaper than afterwards.
var (
	errNotFound    = errors.New("not found")
	errWrongMethod = errors.New("method not allowed")
)

// response is a handler's answer when the default — 200 with a JSON body and
// no cache headers — is not what it wants.
//
// Handlers still never touch the ResponseWriter. Keeping the rate limit, the
// error shape, conditional requests and the cache headers in one place is the
// only reason this wrapper earns its existence, and a handler that writes its
// own response is a handler that will eventually forget one of them.
type response struct {
	// etag identifies this representation. Empty means "do not cache".
	etag string
	// immutable marks a representation that can never change again, which is
	// true of block bytes addressed by id and of anything buried deeper than
	// the undo horizon.
	immutable bool
	// notModified answers a conditional request without producing a body at
	// all. writeResponse would reach the same 304 on its own, but only after
	// the handler had already built the thing it is about not to send — which
	// for block bytes means an encode and a charge against the client's byte
	// budget, both spent on an empty response.
	notModified bool
	// raw, when non-nil, is sent verbatim under contentType. Otherwise body is
	// encoded as JSON.
	raw         []byte
	contentType string
	body        any
}

// read wraps a handler that must never be reached by a verb that implies a
// write. It is a separate constructor rather than a flag so that a new route is
// registered as one or the other by choosing a function, and /submit stays the
// single visible exception in the routing table.
func (s *Server) read(h func(http.ResponseWriter, *http.Request) (any, error)) http.HandlerFunc {
	inner := s.wrap(h)
	return func(w http.ResponseWriter, r *http.Request) {
		// Deliberately ahead of the rate limiter. A wrong verb is refused
		// without costing the caller a request from its budget, and without
		// putting a key in the limiter's map for a request the node did no work
		// for. Moving this below allow() would be a regression in both.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed,
				map[string]string{"error": errWrongMethod.Error() + ": " + r.Method})
			return
		}
		inner(w, r)
	}
}

func (s *Server) wrap(h func(http.ResponseWriter, *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.allow(r) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
			return
		}
		body, err := h(w, r)
		if err != nil {
			writeJSON(w, statusFor(err), map[string]string{"error": err.Error()})
			return
		}
		if res, ok := body.(response); ok {
			writeResponse(w, r, res)
			return
		}
		writeJSON(w, http.StatusOK, body)
	}
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, errRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, errNotFound) || errors.Is(err, chain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, errWrongMethod):
		return http.StatusMethodNotAllowed
	case errors.Is(err, chain.ErrLocal):
		// A record this node wrote and can no longer read is this node's
		// fault, and node/chain marks it as one so node/p2p does not score it
		// against the peer that prompted the read. The same attribution is
		// owed to an HTTP client: 400 tells a caller its request was
		// malformed and invites it to stop retrying a request that was always
		// well-formed, which hides a bad disk behind a client-side bug.
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

func writeResponse(w http.ResponseWriter, r *http.Request, res response) {
	if res.etag != "" {
		w.Header().Set("ETag", res.etag)
		if res.immutable {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			// Revalidate rather than cache. A block that is still inside the
			// undo horizon can leave the canonical chain, and a cached copy
			// that says otherwise is a false claim of finality served by a
			// proxy nobody is watching.
			w.Header().Set("Cache-Control", "no-cache")
		}
		if res.notModified || matchesETag(r.Header.Get("If-None-Match"), res.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if res.raw == nil {
		writeJSON(w, http.StatusOK, res.body)
		return
	}
	if res.etag == "" {
		// Reached, and by exactly one caller: the scrape representation of
		// /metrics. It carries no etag because it is live state, and the rule
		// this package states for itself is that every route carries a
		// directive — a raw body has no second writer to fall back on
		// the way res.body does through writeJSON, so without this line the
		// one uncacheable representation on this surface would be the one
		// that shipped with no policy at all. An unlabelled response is
		// heuristically cacheable, and a cached scrape is a monitoring
		// system reporting a node's past as its present.
		w.Header().Set("Cache-Control", "no-store")
	}
	w.Header().Set("Content-Type", res.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(res.raw)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.raw)
}

func matchesETag(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

// allow is a fixed-window rate limiter per client address. Simple on purpose:
// a limiter with subtle behaviour is a limiter nobody can reason about under
// load.
func (s *Server) allow(r *http.Request) bool {
	host := clientHost(r)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	c := s.seen[host]
	if c == nil {
		c = &client{}
		s.seen[host] = c
	}
	c.reqs = keepTimesAfter(c.reqs, now.Add(-window))
	if len(c.reqs) >= s.cfg.RequestsPerMinute {
		return false
	}
	c.reqs = append(c.reqs, now)
	return true
}

// allowBlockBytes reports whether this client may still be sent block bytes.
//
// Checked before the block is encoded and charged after, so a client can
// overshoot its budget by at most one block — the alternative is to encode the
// block in order to price it and then discard it, which pays the expensive
// half of the cost to refuse.
func (s *Server) allowBlockBytes(r *http.Request) bool {
	host := clientHost(r)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.seen[host]
	if c == nil {
		return true
	}
	c.bytes = keepChargesAfter(c.bytes, now.Add(-window))
	var spent int64
	for _, b := range c.bytes {
		spent += b.n
	}
	return spent < s.cfg.BlockBytesPerMinute
}

// chargeBlockBytes bills a client for bytes it is about to be sent. It never
// creates an entry.
//
// allow() is the only thing that admits a client, and so it is the only thing
// that gets to add a key: one writer creating entries is a property worth
// keeping, because the reason this map needed fixing in the first place was
// that nothing was in charge of its size. Every caller here arrives through
// wrap(), which called allow() first, so the entry exists — and if it somehow
// does not, the client has already been forgotten and there is nobody left to
// bill. Dropping the charge is then the honest answer rather than resurrecting
// a client to hold a debt against.
func (s *Server) chargeBlockBytes(r *http.Request, n int64) {
	host := clientHost(r)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.seen[host]
	if c == nil {
		return
	}
	c.bytes = append(keepChargesAfter(c.bytes, now.Add(-window)), byteCharge{at: now, n: n})
}

// sweepLocked drops every client with nothing left inside the window.
//
// The limiter used to prune timestamps *within* a host's entry and write the
// entry back even when it had emptied, so the map was a set of every source
// address the process had ever seen, held until it exited. Pruning in place
// can never remove an entry, because a host that asks one question and never
// returns is never visited again — which is exactly the host that costs the
// most per byte of memory.
//
// At the default localhost bind that is one key and the growth is invisible.
// It becomes real the moment the RPC is exposed, and it is cheap to exploit:
// a single IPv6 /64 hands an attacker 2^64 distinct keys with no spoofing at
// all. Raising RequestsPerMinute does nothing about it — the growth is in
// distinct keys, not in requests per key.
//
// Sweeping from allow rather than from a goroutine keeps the limiter to one
// mechanism with no lifecycle to get wrong, and it bounds the map by the
// clients active recently rather than by every client ever seen. A node with
// no traffic keeps whatever it had, which is the one case where the map is not
// growing anyway.
//
// "Recently" is two windows and not one. A sweep runs at most once per window
// and evicts what was idle for a window before it, so an entry last touched
// just after a sweep survives the next one — its timestamp is still after that
// sweep's cutoff — and dies at the one after. Worst-case retention is
// therefore just under 2*window, which is what the test advances the clock by.
// The bound is what matters here rather than the constant, but a comment that
// says "one window" reads as a specification and would be wrong.
func (s *Server) sweepLocked(now time.Time) {
	if now.Sub(s.lastSweep) < window {
		return
	}
	s.lastSweep = now
	cutoff := now.Add(-window)
	for host, c := range s.seen {
		c.reqs = keepTimesAfter(c.reqs, cutoff)
		c.bytes = keepChargesAfter(c.bytes, cutoff)
		if c.empty() {
			delete(s.seen, host)
		}
	}
}

// Pruning in place reuses the backing array, which makes its capacity a
// high-water mark: a client that spent its whole request budget in one window
// would go on holding the array for six hundred timestamps long after they
// aged out, and its byte charges the same. That is bounded — the client has to
// sustain the traffic to have earned it, and the sweep reclaims the whole
// entry — but it prices a client by the most it ever did rather than by what
// it is doing, and it is twenty times the per-entry cost anyone would estimate
// from the struct. Re-allocating once most of the array has gone is cheaper
// than explaining it.
func keepTimesAfter(times []time.Time, cutoff time.Time) []time.Time {
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if shouldShrink(len(kept), cap(kept)) {
		return append(make([]time.Time, 0, len(kept)), kept...)
	}
	return kept
}

func keepChargesAfter(charges []byteCharge, cutoff time.Time) []byteCharge {
	kept := charges[:0]
	for _, c := range charges {
		if c.at.After(cutoff) {
			kept = append(kept, c)
		}
	}
	if shouldShrink(len(kept), cap(kept)) {
		return append(make([]byteCharge, 0, len(kept)), kept...)
	}
	return kept
}

// shouldShrink trades an allocation for the memory a mostly-empty array holds.
// The slack keeps a client at a steady rate from re-allocating on every
// request, which is the case this must not make worse.
func shouldShrink(length, capacity int) bool { return capacity > 4*length+8 }

// clientHost is the address the limiter keys on.
//
// It is the transport peer and nothing else. X-Forwarded-For is deliberately
// not consulted: a limiter that keys on a header every client can set is a
// limiter that is bypassed by setting it, and it turns the map growth above
// from "many source addresses" into "one client, one header, unlimited keys".
// If the behind-a-proxy case is ever worth fixing, it needs a configured list
// of trusted proxies and the rightmost untrusted hop — not a header read.
func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SetNetwork attaches the network view. It is a setter rather than a
// constructor argument because a node can run without peers at all, and a
// signature that demanded one would make the peerless case the awkward one.
func (s *Server) SetNetwork(n Network) { s.net = n }

// handleNetwork reports connection shape.
//
// The number that matters here is the listening share, which is what the
// networking decision's reopen condition is written against
// (docs/decisions/networking.md §5): Zycord ships without NAT traversal on the
// argument that enough nodes are dialable. That argument is falsifiable, and
// this is the endpoint that falsifies it — a network where inbound-capable
// nodes are scarce shows up here first, as peers that dial out and are never
// dialled back.
func (s *Server) handleNetwork(_ http.ResponseWriter, _ *http.Request) (any, error) {
	if s.net == nil {
		return map[string]any{"enabled": false}, nil
	}
	listening, inbound, outbound := s.net.Reachability()
	known, banned, minScore := s.net.PeerHealth()
	return map[string]any{
		"enabled": true,
		// Raw scoring state. A node that has banned the peers who could tell it
		// it is behind looks identical, in every other field, to a node at the
		// tip — so the counts are reported rather than inferred.
		"known_peers":  known,
		"banned_peers": banned,
		"min_score":    minScore,
		"peers":        s.net.PeerCount(),
		"listening":    listening,
		"inbound":      inbound,
		"outbound":     outbound,
		// A node with no inbound connections while listening is either new or
		// unreachable — a forwarded port that is not actually forwarded looks
		// exactly like this, and looks healthy everywhere else.
		"reachable": listening && inbound > 0,
	}, nil
}

func (s *Server) handleStatus(_ http.ResponseWriter, _ *http.Request) (any, error) {
	tip := s.chain.Tip()
	id := tip.ID()
	network := s.chain.NetworkID()
	p := s.chain.Params()
	out := map[string]any{
		"network":    p.Name,
		"chain_id":   p.ChainID,
		"network_id": hexOf(network),
		"height":     s.chain.Height(),
		"tip":        hexOf(id),
		"state_root": hexOf(s.chain.StoredStateRoot()),
		"time":       tip.Time,
		// Accumulated work of this node's canonical chain up to `tip`.
		//
		// This is the only place the number is readable from outside the
		// process, and it is here because RELEASE.md's checkpoint step needs a
		// source for `min_chain_work`: the pair (`height`, `chain_work`) read
		// off a node the release engineer runs is exactly the pair that goes
		// into `spec/checkpoints.json`, under the same cross-check-on-a-second-
		// node discipline the pinned block ids get. Without it the work floor
		// would be enforcement no release could ever supply a value for.
		//
		// Decimal, like every other U256 this project encodes (`u256.String`):
		// JSON numbers are doubles in most parsers, and a 256-bit accumulator
		// does not survive one.
		"chain_work": s.chain.TotalWork().String(),
	}
	// The launch checkpoint defence this binary carries.
	//
	// Reported because a refused sync is otherwise undiagnosable from outside:
	// `node/sync.Admit` refuses a candidate that contradicts a pin or that
	// arrives at the floor's height too light, and an operator looking at a
	// node that will not advance needs to see which release policy is doing it
	// and at what height. These are **not** consensus values and are
	// deliberately not in `/params`: they change in routine releases, and
	// `/params` is the file the parameter hash covers. `chain_work` above is
	// what this node measures; `min_chain_work` here is what it enforces.
	cps := checkpoints.Active()
	out["min_chain_work"] = cps.MinChainWork.String()
	out["min_chain_work_height"] = cps.MinChainWorkHeight
	out["checkpoint_count"] = len(cps.Points)
	out["checkpoint_sunset_height"] = cps.SunsetHeight
	if c, ok := cps.Highest(); ok {
		out["checkpoint_height"] = c.Height
		out["checkpoint_id"] = hexOf(c.BlockID)
	}
	return out, nil
}

func (s *Server) handleHead(_ http.ResponseWriter, _ *http.Request) (any, error) {
	tip := s.chain.Tip()
	return map[string]any{
		"height":    tip.Height,
		"id":        hexOf(tip.ID()),
		"parent":    hexOf(tip.ParentID),
		"time":      tip.Time,
		"cert_root": hexOf(tip.CertRoot),
		"target":    tip.Target.String(),
	}, nil
}

// handleBlock serves a block by height or by id, as JSON or — with format=ssz
// — as the canonical SSZ encoding the network agreed on.
//
// The bytes are the point, and the JSON is the convenience. An observer that
// wants to know whether a certificate was applied, skipped and billed, or
// dropped has to fold the block itself: the outcome is computed inside the
// fold and never persisted, because persisting one row per certificate forever
// in a store that lives in memory is not something a node can be asked to do.
// Folding it needs the certificates exactly as they were encoded, not a
// projection of them — a field this handler forgot to render is a certificate
// nobody downstream can verify, and a re-encoding that differs by one byte is
// a different block id on a public page, which is a split in what the chain is
// that shows up as a wrong hash rather than as an error.
//
// Serving binary rather than hex is not a preference. Hex doubles the largest
// response the node has and adds an encoding pass to every request for it.
//
// Cost ordering — the property that no request buys work it is not billed for.
// Resolving which block is meant — the height index, or the header a bare id
// must resolve to exist at all — never touches the body, so it costs the same
// for a byte budget of zero as for one that is full. The body itself (up to
// block_byte_capacity, a full SSZ decode and, on the JSON path, one
// marshal-and-hash per certificate) is read only after a conditional request
// has been ruled out — a match never reaches it at all — and after
// allowBlockBytes has cleared the *stored* record's length. Nothing downstream
// of that point runs for free: a client cannot make the node pay for a decode
// it never gets billed for, and a client that already holds the current
// representation is never billed for one it does not receive.
func (s *Server) handleBlock(_ http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()

	var (
		id       types.Hash
		byID     bool
		bodyOK   bool
		byHeight uint64        // the requested height, when this is a height lookup
		hdr      *types.Header // populated eagerly only where resolving id already paid for it
	)
	switch {
	case q.Get("height") != "":
		height, err := strconv.ParseUint(q.Get("height"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad height")
		}
		want, ok := s.chain.CanonicalIDAt(height)
		if !ok {
			return nil, fmt.Errorf("%w: height %d", chain.ErrNotFound, height)
		}
		// Height lookup answers for the canonical chain only, and the height
		// index and the body are written and deleted together in every batch
		// that touches either (commit, switchTo, rollbackLocked) — so a height
		// that resolves at all has a body behind it *as of this read*.
		//
		// It can stop having one before the body is actually read, which is
		// why byHeight is remembered rather than the id alone: the body read
		// below re-resolves the height and reads the record under one lock
		// (Chain.BlockRawAt), so a reorg landing in between serves the block
		// that now holds the height instead of a 404 for the one that used
		// to. Resolving here anyway is what lets the conditional request be
		// answered — and a 304 returned — without reading a body at all.
		id, bodyOK, byHeight = want, true, height
	case q.Get("id") != "":
		want, err := parseHash(q.Get("id"))
		if err != nil {
			return nil, err
		}
		byID, id = true, want
		// A block that lost a reorg keeps its header and loses its body, so
		// the id still resolves: an observer that indexed it while it was at
		// the tip can come back, learn that it is orphaned, and walk its
		// parent links across the fork point. That makes the header — not the
		// body — the existence check for this path, and it is the one reorg-
		// safe lookup and must not regress. HasBlockBody is a presence check,
		// not a copy, so asking "is the body still here" costs nothing
		// proportional to the body's size either way.
		h, err := s.chain.Header(want)
		if err != nil {
			return nil, err
		}
		hdr, bodyOK = h, s.chain.HasBlockBody(want)
	default:
		return nil, fmt.Errorf("specify height or id")
	}
	networkID := s.chain.NetworkID()

	// readBody is the one place a block's bytes are paid for and read, shared
	// by both format arms so the ordering cannot drift between them: the
	// budget is consulted first, then the record is read, then it is charged
	// against the length the read reported. Nothing decodes here — pricing a
	// request must not cost what the request is being priced for.
	//
	// The read itself is atomic in the sense each lookup needs. A height
	// re-resolves the index and reads the body under one lock, so a reorg
	// between the resolution above and this read serves the block that holds
	// the height now rather than 404-ing for the one that held it then. An id
	// names one block for all time, so there is nothing to re-resolve — only
	// the body can go away, and that answer (found=false) is the honest one.
	readBody := func() (raw []byte, found bool, err error) {
		if !s.allowBlockBytes(r) {
			return nil, false, fmt.Errorf("%w: block bytes", errRateLimited)
		}
		if byID {
			raw, err = s.chain.BlockRaw(id)
		} else {
			// The id this resolves to is checked, not assumed. A reorg
			// between the resolution above and this read gives the height a
			// different block, and its bytes are not the answer to *this*
			// request: the id, the etag and the header fields already
			// computed all name the block that held the height a moment ago.
			// Serving the new block's bytes under the old block's identity is
			// the mislabelling the etag exists to prevent, so the body is
			// dropped instead — the header's claims stand, and the client's
			// next request resolves the height afresh.
			//
			// Dropped, but not free: the read already happened and the store
			// already copied the whole record (storage.Get copies), so the
			// node has paid for those bytes whether or not they are sent. A
			// client polling a height through sustained reorg churn would
			// otherwise buy a full block_byte_capacity read per request and
			// be billed nothing — the same "work the node is never paid for"
			// this route was rewritten to close, reappearing on a
			// narrower path. The charge belongs to whoever caused the read.
			//
			// No test drives this branch: it needs a reorg to land between
			// two lock acquisitions inside one handler call, which is not
			// reachable without a hook in production code that exists only
			// for the test. It is asserted by reading instead, and the two
			// properties it turns on are each pinned elsewhere: BlockRawAt
			// returns the id it resolved, and storage.Get returns a copy rather
			// than the live value — which is what makes this a charge for work
			// the store really did (TestGetReturnsACopyNotTheLiveValue).
			var got types.Hash
			got, raw, err = s.chain.BlockRawAt(byHeight)
			if err == nil && got != id {
				s.chargeBlockBytes(r, int64(len(raw)))
				return nil, false, nil
			}
		}
		switch {
		case errors.Is(err, chain.ErrNotFound):
			return nil, false, nil
		case err != nil:
			return nil, false, err
		}
		s.chargeBlockBytes(r, int64(len(raw)))
		return raw, true, nil
	}

	switch format := q.Get("format"); format {
	case "", "json":
		if hdr == nil {
			h, err := s.chain.Header(id)
			if err != nil {
				return nil, err
			}
			hdr = h
		}
		// One read, and the atomicity is load-bearing. The etag names the tip,
		// so an answer computed against one chain and labelled with another's
		// tip is a stale body published under a fresh name: a later request at
		// that same tip derives the same etag, gets a 304, and keeps rendering
		// a reorged-away block as canonical. That is the defect the etag was
		// widened to close, and reading these separately would have left it
		// alive in the window between the two locks.
		tip, canonicalID, committed := s.chain.TipAndCanonicalIDAt(hdr.Height)
		canonical := committed && canonicalID == id
		tipID, tipHeight := tip.ID(), tip.Height

		// The tip is part of the identity of this answer, and the answer is
		// never immutable: burial fixes which block sits at a height, not how
		// many blocks have been mined since — and confirmations counts exactly
		// that. The network id is part of every cache identity on this
		// surface: two chains sharing a proxy must not be able to
		// satisfy one's revalidation from the other's cached entry.
		etag := etagOf("json", id, tipID, networkID)
		if matchesETag(r.Header.Get("If-None-Match"), etag) {
			return response{etag: etag, notModified: true}, nil
		}

		// The height comparison is defence in depth, not a guarded invariant,
		// and no test can kill it: removing it leaves this package green.
		//
		// A block canonical at a height above the tip cannot exist. The height
		// index and the head move in the same storage batch — commit,
		// switchTo and rollbackLocked each write heightKey and
		// metaHeight/metaTip together — and TipAndCanonicalIDAt reads both
		// under one lock, so `canonical` already implies hdr.Height <=
		// tipHeight. The short-circuit means the subtraction is unreachable
		// rather than merely guarded.
		//
		// It stays because the cost is one comparison and the failure it
		// would prevent is unsigned underflow reporting a block as buried
		// under eighteen quintillion confirmations.
		var confirmations uint64
		if canonical && tipHeight >= hdr.Height {
			confirmations = tipHeight - hdr.Height + 1
		}
		out := map[string]any{
			"height": hdr.Height,
			"id":     hexOf(id),
			"parent": hexOf(hdr.ParentID),
			"time":   hdr.Time,
			// Presenting a block from a segment that was reorged away, without
			// saying so, is how a reader is led to act on a finality that
			// never happened. Depth and orphan status are reported rather
			// than left to be inferred from a height lookup that would
			// silently disagree.
			"canonical":     canonical,
			"orphaned":      !canonical,
			"confirmations": confirmations,
			"body_retained": bodyOK,
		}
		if bodyOK {
			// A request this handler answers with certificate ids and a byte
			// count pays for the same store read and the same full decode
			// format=ssz pays for; pricing only one of the two formats left
			// the other free. readBody charges before anything decodes.
			raw, found, err := readBody()
			if err != nil {
				return nil, err
			}
			// The body can go away between the existence check above and the
			// read: a reorg is free to land in between. The honest answer is
			// the one this route already has a field for — the block is
			// known, its body is not retained — and not a 404, which would
			// deny the header this handler is holding and has already
			// reported on. Only the body is dropped; every claim the header
			// supports survives.
			if !found {
				out["body_retained"] = false
			} else {
				blk, err := s.chain.DecodeBlock(id, raw)
				if err != nil {
					return nil, err
				}
				ids := make([]string, len(blk.Certs))
				for i, c := range blk.Certs {
					ids[i] = hexOf(c.ID())
				}
				// Bounded by construction: the fold refuses a block carrying
				// more than max_certs_per_block.
				out["certificates"] = ids
				out["bytes"] = len(raw)
			}
		}
		return response{body: out, etag: etag}, nil
	case "ssz":
		if !bodyOK {
			return nil, fmt.Errorf("%w: no body retained for %s, the block lost a reorg",
				errNotFound, hexOf(id))
		}
		// An id addresses exactly one encoding, so bytes fetched by id can
		// never change under this etag no matter what the fork choice does
		// afterwards. By height they can — a chain reset or a resync gives a
		// height different bytes — so immutable is reserved for the
		// content-addressed lookup and never for a height, buried or not
		// — burial bounds one running process, not the URL, so a year-long
		// immutable cache on a height survives the chain reset or resync that
		// invalidates it, and handleParams declines the same claim for the
		// same reason.
		etag := etagOf("ssz", id, networkID)
		immutable := byID
		if matchesETag(r.Header.Get("If-None-Match"), etag) {
			return response{etag: etag, immutable: immutable, notModified: true}, nil
		}
		// Charged against the stored length before the bytes are served, and
		// the bytes served here are the stored bytes verbatim — the store
		// holds exactly the canonical SSZ encoding (commit and switchTo both
		// write b.MarshalSSZ() under this id), so there is no decode and no
		// re-encode on this path at all, only a Get and a price.
		raw, found, err := readBody()
		if err != nil {
			return nil, err
		}
		// Unlike the JSON arm there is no body-less answer to give here: this
		// route is the bytes. A body that went away between the check and the
		// read is the same answer as one that was already gone.
		if !found {
			return nil, fmt.Errorf("%w: no body retained for %s, the block lost a reorg",
				errNotFound, hexOf(id))
		}
		return response{
			raw:         raw,
			contentType: "application/octet-stream",
			etag:        etag,
			immutable:   immutable,
		}, nil
	default:
		return nil, fmt.Errorf("format must be json or ssz")
	}
}

// handleParams serves the active parameter set.
//
// An explorer renders gas costs, fee ceilings, emission, maturity and the
// block ceilings. A hardcoded copy of them is a second source of truth that
// goes stale silently at the exact moment it matters — a parameter change —
// so the numbers are served rather than published.
func (s *Server) handleParams(_ http.ResponseWriter, _ *http.Request) (any, error) {
	p := s.chain.Params()
	root := p.ConsensusRoot()
	networkID := s.chain.NetworkID()
	return response{
		body: map[string]any{
			"params": p,
			// The digest two nodes must agree on before they will talk to each
			// other. A client that derives a different one from the parameters
			// above is reading a different chain, and this is the field that
			// lets it find out loudly instead of diverging quietly at the
			// first rule the two disagree about.
			"consensus_root": hexOf(root),
			"network_id":     hexOf(networkID),
			// Where the ceilings went. §8.1 made the block's byte, gas and
			// certificate ceilings functions of T, which is consensus state, so
			// they are no longer in here — only the genesis values T starts at
			// and can decay back to. Those stay real numbers forever, which is
			// exactly what makes reading them for "the limit" a silent mistake,
			// so this field says out loud where the live ones are rather than
			// leaving a reader to notice an absence.
			"elastic_ceilings_at": "/fees",
		},
		// Frozen at genesis and changeable only by a hard fork, so it is stable
		// for the life of the process — but not marked immutable, because a
		// resettable testnet is exactly a case where a year-long cache would
		// serve last week's chain. Revalidation costs a 304.
		//
		// The tag names both consensus_root and network_id. ConsensusRoot
		// hashes the parameter fields only — genesis is not among them — so two
		// chains that start from the same params.json (a testnet before and
		// after a reset, a devnet forked from a testnet's params) produce the
		// same root and, without network_id in the tag, the same ETag for
		// bodies that disagree on the one field that says which chain this is.
		// A client revalidating against the old tag would then get a 304 and
		// keep the stale network_id — the etag would have promised more than
		// the body kept.
		etag: etagOf("params", root, networkID),
	}, nil
}

func (s *Server) handleCell(_ http.ResponseWriter, r *http.Request) (any, error) {
	addr, err := parseHash(r.URL.Query().Get("addr"))
	if err != nil {
		return nil, err
	}
	word, err := parseHash(r.URL.Query().Get("word"))
	if err != nil {
		return nil, err
	}
	slot := types.Slot{Addr: addr, Word: word}
	var out map[string]any
	s.chain.Read(func(v chain.View) {
		out = map[string]any{
			"value": v.State.Get(slot).String(),
			"spent": v.State.IsSpent(addr),
		}
	})
	return out, nil
}

func (s *Server) handleBalance(_ http.ResponseWriter, r *http.Request) (any, error) {
	addr, err := parseHash(r.URL.Query().Get("addr"))
	if err != nil {
		return nil, err
	}
	asset := types.NativeAsset
	if a := r.URL.Query().Get("asset"); a != "" {
		asset, err = parseHash(a)
		if err != nil {
			return nil, err
		}
	}
	var out map[string]any
	s.chain.Read(func(v chain.View) {
		out = map[string]any{
			"balance": v.State.Get(types.BalanceSlot(addr, asset)).String(),
			"spent":   v.State.IsSpent(addr),
		}
	})
	return out, nil
}

// handleFees reports what a block currently costs and how much currently fits.
//
// The ceilings belong here rather than in /params because §8.1 made them stop
// being parameters. T, the sequential target, is consensus state that the epoch
// controller moves, and the block's byte and certificate ceilings are derived
// from whatever T is now — so a reader that took `block_byte_limit_genesis`
// from /params and called it "the block size limit" would be quoting the value
// T started at and can fall back to, not the one in force. That reader would be
// wrong by up to the distance between 2.5 MB and the 8 MB capacity wall, and
// wrong silently, because the genesis number stays a real number forever.
func (s *Server) handleFees(_ http.ResponseWriter, _ *http.Request) (any, error) {
	p := s.chain.Params()
	var out map[string]any
	s.chain.Read(func(v chain.View) {
		// T as the block rules will judge the next block against. The epoch
		// controller's update takes effect from the block after the one that
		// triggered it, exactly as fee bids are judged against the pre-block
		// base fees, so the cell holds the value in force now rather than the
		// one the last block was measured by. At height 0 there is no cell yet.
		target := p.SeqGasTargetGenesis
		if v.Height > 0 {
			if t, ok := v.State.Get(types.SeqGasTargetSlot()).Uint64(); ok {
				target = t
			}
		}
		out = map[string]any{
			"seq_base_fee": v.State.Get(types.SeqBaseFeeSlot()).String(),
			"par_base_fee": v.State.Get(types.ParBaseFeeSlot()).String(),
			"skip_fee":     p.SkipFee.String(),
			// The elastic ceilings, and the T they are derived from, so a reader
			// can check the derivation rather than trust it. Every one of these
			// comes from the params' own accessor rather than from arithmetic
			// repeated here, because a second copy of a consensus derivation is
			// the thing this endpoint exists to stop a reader from keeping.
			"seq_gas_target":      target,
			"seq_gas_limit":       p.SeqGasLimit(target),
			"par_gas_limit":       p.ParGasLimit(target),
			"block_byte_limit":    p.BlockByteLimit(target),
			"max_certs_per_block": p.MaxCertsPerBlock(target),
		}
	})
	return out, nil
}

// maxMempoolIDs caps the pending list.
//
// Every list this package returns is bounded. Most are bounded by construction
// — a block cannot carry more certificates than the fold accepts — and the
// mempool is the exception: its length is set by strangers, so the bound has
// to be written down.
const maxMempoolIDs = 1000

// handleMempool reports pool aggregates, and pending certificate ids when the
// caller asks for them.
//
// Ids and never bodies. The mempool is the pre-confirmation view, so serving
// it discloses what has been submitted and not yet committed: era 0 has no
// ordering guarantee for that disclosure to break, which makes it an argument
// for care rather than for refusal, but it should be a decision rather than a
// side effect. Bodies would also be the one response that caching cannot help
// — pool contents turn over continuously, so every poll is a fresh
// serialisation — and an observer that wants them saw them at submission.
//
// Off by default so that the shape of a poll does not change for callers that
// only wanted the counters.
func (s *Server) handleMempool(_ http.ResponseWriter, r *http.Request) (any, error) {
	st := s.pool.Stats()
	out := map[string]any{
		"size":         st.Size,
		"underwriters": st.Underwriters,
		"admitted":     st.Admitted,
		"rejected":     st.Rejected,
		"evicted":      st.Evicted,
		"seq_gas":      st.SeqGas,
		"par_gas":      st.ParGas,
		"bytes":        st.Bytes,
	}
	limit, err := parseLimit(r.URL.Query().Get("limit"), maxMempoolIDs)
	if err != nil {
		return nil, err
	}
	if limit > 0 {
		ids := s.pool.IDs(limit)
		hexIDs := make([]string, len(ids))
		for i, id := range ids {
			hexIDs[i] = hexOf(id)
		}
		out["ids"] = hexIDs
		out["truncated"] = st.Size > len(hexIDs)
	}
	return out, nil
}

func (s *Server) handleMetrics(_ http.ResponseWriter, r *http.Request) (any, error) {
	if wantsProm(r.URL.Query().Get("format"), r.Header.Get("Accept")) {
		return response{raw: renderProm(s.promSamples()), contentType: promContentType}, nil
	}
	return s.metricsJSON(), nil
}

// promSamples is the scrape-format view of the same counters handleMetrics
// serves as JSON, plus the shape the JSON has never carried.
//
// The extra series are not decoration. Connection shape is what
// docs/decisions/networking.md §6's first reopen condition is written against
// (§5 names the cost and defers the condition to §6), and it lived only on
// /network — a surface with no scrape representation, so the one number the
// no-NAT-traversal argument stands or falls on could not be graphed.
// pow_key_epoch is here for a sharper reason: the wrong-key seal was a miner
// hashing under the wrong key epoch for 1112 blocks (see node/miner's
// ErrSealDoesNotVerify), and nothing anywhere could have shown it.
func (s *Server) promSamples() []promSample {
	m := s.metrics.snapshot()
	ch := s.chain.Stats()
	pool := s.pool.Stats()
	height := s.chain.Height()

	out := []promSample{
		{"zycord_blocks_applied_total", "counter", "Blocks accepted onto the chain, from any source.", ch.BlocksApplied, nil},
		{"zycord_blocks_undone_total", "counter", "Blocks removed by reorgs.", ch.BlocksUndone, nil},
		{"zycord_blocks_rejected_total", "counter", "Blocks the fold refused.", ch.BlocksRejected, nil},
		{"zycord_certs_total", "counter", "Certificates by fold outcome.", ch.CertsApplied, map[string]string{"outcome": "applied"}},
		{"zycord_certs_total", "counter", "Certificates by fold outcome.", ch.CertsSkipped, map[string]string{"outcome": "skipped"}},
		{"zycord_certs_total", "counter", "Certificates by fold outcome.", ch.CertsDropped, map[string]string{"outcome": "dropped"}},
		{"zycord_reorgs_total", "counter", "Branch switches performed.", ch.ReorgEvents, nil},
		{"zycord_reorg_depth_max", "gauge", "Most blocks unwound in one reorg.", ch.DeepestReorg, nil},
		{"zycord_submit_total", "counter", "Certificates offered to /submit, by outcome.", m.SubmitAccepted, map[string]string{"outcome": "accepted"}},
		{"zycord_submit_total", "counter", "Certificates offered to /submit, by outcome.", m.SubmitRejected, map[string]string{"outcome": "rejected"}},
		{"zycord_mempool_size", "gauge", "Certificates currently pending.", uint64(pool.Size), nil},
		{"zycord_chain_height", "gauge", "Height of the current tip.", height, nil},
		{"zycord_pow_key_epoch", "gauge", "Proof-of-work key epoch the tip height selects.", pow.SeedEpochFor(height, s.chain.Params()), nil},
	}

	if s.net != nil {
		listening, inbound, outbound := s.net.Reachability()
		known, banned, _ := s.net.PeerHealth()
		out = append(out,
			promSample{"zycord_peers", "gauge", "Connected peers, by direction.", uint64(inbound), map[string]string{"direction": "inbound"}},
			promSample{"zycord_peers", "gauge", "Connected peers, by direction.", uint64(outbound), map[string]string{"direction": "outbound"}},
			promSample{"zycord_peers_known", "gauge", "Addresses in the peer store.", uint64(known), nil},
			promSample{"zycord_peers_banned", "gauge", "Peers currently banned.", uint64(banned), nil},
			promSample{"zycord_listening", "gauge", "1 when this node accepts inbound connections, 0 otherwise.", boolGauge(listening), nil},
		)
	}
	return out
}

// boolGauge renders a boolean as the 0/1 the exposition format has instead of
// a boolean type.
func boolGauge(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (s *Server) metricsJSON() map[string]any {
	// Chain counters come from the chain, not from this package.
	//
	// They used to be fed by the miner's loop alone, which made every one of
	// them count only locally-mined blocks and left reorg depth stuck at zero
	// because nothing ever recorded it. A metric that cannot be non-zero is the
	// observability form of a test that cannot fail. Counting happens where the
	// events happen; this only reports.
	m := s.metrics.snapshot()
	ch := s.chain.Stats()
	pool := s.pool.Stats()
	return map[string]any{
		"blocks_applied":  ch.BlocksApplied,
		"blocks_undone":   ch.BlocksUndone,
		"blocks_rejected": ch.BlocksRejected,
		"certs_applied":   ch.CertsApplied,
		"certs_skipped":   ch.CertsSkipped,
		"certs_dropped":   ch.CertsDropped,
		"reorg_events":    ch.ReorgEvents,
		"deepest_reorg":   ch.DeepestReorg,
		"submit_accepted": m.SubmitAccepted,
		"submit_rejected": m.SubmitRejected,
		"mempool_size":    pool.Size,
		"height":          s.chain.Height(),
	}
}

// handleSubmit accepts a hex-encoded certificate. It is the only write, and it
// grants no authority: the certificate is validated exactly as one arriving
// from a peer would be, and a caller cannot make the node do anything it would
// not do for a stranger.
func (s *Server) handleSubmit(_ http.ResponseWriter, r *http.Request) (any, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("POST required")
	}
	raw := make([]byte, 0, 1024)
	buf := make([]byte, 4096)
	var total int64
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > s.cfg.MaxBodyBytes {
				return nil, fmt.Errorf("body too large")
			}
			raw = append(raw, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	decoded, err := hex.DecodeString(trimHexPrefix(string(trimSpace(raw))))
	if err != nil {
		s.countSubmit(false)
		return nil, fmt.Errorf("body must be hex-encoded ssz(certificate)")
	}
	cert, err := types.UnmarshalCertificate(decoded, s.chain.Params())
	if err != nil {
		s.countSubmit(false)
		return nil, err
	}
	var addErr error
	s.chain.Read(func(v chain.View) { addErr = s.pool.Add(cert, v.State, v.Height) })
	if addErr != nil {
		s.countSubmit(false)
		return nil, addErr
	}
	// Accepted locally, so it is worth other nodes' attention. Relayed only
	// after admission, which is the same rule gossip follows: nothing is
	// forwarded before it has been validated.
	if s.net != nil {
		s.net.AnnounceCertificate(cert)
	}
	s.countSubmit(true)
	return map[string]any{"id": hexOf(cert.ID()), "accepted": true}, nil
}

func (s *Server) countSubmit(ok bool) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	if ok {
		s.metrics.SubmitAccepted++
		return
	}
	s.metrics.SubmitRejected++
}

// writeJSON is the writer for every response this package has not given an
// explicit freshness policy: every error (400/404/405/429, and whatever a
// future 5xx would be), and every handler that answers with tip-, pool- or
// state-derived data rather than a response value.
//
// RFC 9111 §4.2.2 makes an unlabelled response heuristically cacheable by a
// shared cache, and the heuristically-cacheable status set (RFC 9110
// §15.5.5 lists 404 among them, alongside 200/203/204/206/300/301/308/410/
// 414/501) means a bare 404 qualifies too — so leaving this unset was not
// "no policy", it was delegating the decision to whatever a downstream proxy
// guesses. docs/RUNNING.md prescribes exactly that proxy in front of this
// surface. no-store forecloses the guess: nothing here is a claim any cache
// gets to keep and reuse, whether the answer was a state read the fork
// choice can still move under, or an error that must not be replayed as an
// answer once the condition that produced it has passed (a height the chain
// had not yet reached is the sharpest case — its 404 must not outlive the
// block that fills it).
func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// writeResponse sets its own Cache-Control (no-cache or immutable) before
	// falling through to this function for the actual encode, and that
	// decision must survive — so the default here only fills a header nobody
	// has claimed, it never overwrites one.
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func hexOf(h [32]byte) string { return "0x" + hex.EncodeToString(h[:]) }

// etagOf identifies one representation by every input it is derived from.
//
// An ETag is a promise that a 304 means nothing changed, so it has to name
// everything the body depends on. The format is one of those inputs, because
// the JSON rendering and the canonical bytes are different representations of
// the same resource and a cache that confuses them serves the wrong content
// type. For the JSON the tip is another, and leaving it out was a real defect:
// canonical, orphaned, confirmations and body_retained are all functions of
// where the tip is, so an ETag over the block id alone told a revalidating
// client that a block was still canonical after it had been reorged away, and
// froze a confirmation count whose whole purpose is to move. The client that
// broke was the careful one.
func etagOf(format string, parts ...[32]byte) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, p := range parts {
		b.WriteString(hex.EncodeToString(p[:]))
		b.WriteByte('.')
	}
	b.WriteString(format)
	b.WriteByte('"')
	return b.String()
}

// parseLimit reads a caller's list bound and clamps it to a ceiling. An absent
// limit is zero — no list at all — rather than a default that would make every
// caller pay for one.
func parseLimit(s string, ceiling int) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("limit must be a non-negative integer")
	}
	if n > ceiling {
		n = ceiling
	}
	return n, nil
}

func parseHash(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(trimHexPrefix(s))
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("expected a 32-byte hex value")
	}
	copy(out[:], raw)
	return out, nil
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }
