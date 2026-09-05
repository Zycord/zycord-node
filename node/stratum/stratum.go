// Package stratum serves the Monero-dialect Stratum protocol that stock XMRig
// speaks, so that the miner people already have can point at this node and
// mine it without a proxy, a patch or a fork.
//
// # Why this exists at all, given the node already mines
//
// node/miner is not going anywhere. It is the bootstrap path — a network with
// no miners needs a node that mines by itself — and it is the
// solo-without-XMRig path for anyone who wants one binary and no second
// process. What it is not is competitive: it is a nonce loop in Go around a
// cgo call, and the machine that arrives to mine a new coin is running an
// optimised miner with hand-written assembly, huge pages, MSR tweaks and cache
// prefetch that this tree will never reimplement and should never try to.
//
// So the design is: consensus is ours, the hash loop is theirs. This endpoint
// hands XMRig a blob and a target and takes back a nonce.
//
// # This is a solo endpoint, not a pool
//
// The distinction is load-bearing and it is why this package is fifteen
// hundred lines rather than fifteen thousand. A pool accepts shares below the
// network target, accounts for them, and pays out; that means a share
// database, a payout engine, variable difficulty per worker, and custody of
// other people's money. NONE of that is here. Every share submitted to this
// endpoint is checked against the FULL network target, and a share that meets
// it is a block, applied to this node's own chain and announced. The `login`
// address is written straight into the block's EmissionAddr, so the miner that
// found the block is paid by consensus and this node never holds a coin on
// anyone's behalf.
//
// That has a consequence worth stating plainly to anyone who points four
// machines at one node expecting a pool: they will see almost no accepted
// shares, because an accepted share IS a block. This is the correct behaviour
// and the miner's own hashrate display is the number to watch.
//
// # Security posture
//
// This is a new listening socket on a node whose only other local socket, the
// RPC, is loopback-only and unauthenticated by deliberate design (see node/rpc's
// package comment). This endpoint keeps exactly that posture:
//
//   - It is OFF unless --stratum-listen is passed. There is no default-on
//     path and no "enabled if mining" inference.
//   - Its default bind is 127.0.0.1:9422. An operator who wants miners on the
//     LAN types the address that says so, and the server logs a warning
//     naming the exposure when the bind is not loopback, because an
//     unauthenticated socket reachable from a network is a decision and should
//     read like one in the log.
//   - There is no authentication, and adding a password would be worse than
//     not: it would suggest the socket is safe to expose, which it is not.
//     What a stratum connection can do is spend this node's CPU on RandomX
//     verifications and steer this node's EMISSION ADDRESS. The second is the
//     real one — an attacker who can connect can mine to their own address
//     using your electricity — and no protocol-level secret fixes it. Bind it
//     where you trust the network.
//
// Against the connections it does accept it defends with three bounded
// resources: a hard connection cap, a per-connection ban score that closes a
// socket returning invalid work, and a keepalive deadline that reaps a peer
// that has stopped talking. Each is described where it is enforced.
package stratum

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
)

// Config configures the endpoint. The zero value is not usable; use
// DefaultConfig and override.
type Config struct {
	// Addr is the listen address. Default 127.0.0.1:9422.
	//
	// 9422 sits beside the RPC's 9420 and the p2p port rather than on Monero's
	// own 3333/18081, deliberately: a scanner sweeping for Monero pools should
	// not find this, and an operator reading `ss -ltnp` should see this node's
	// ports as a block.
	Addr string
	// MaxConns caps simultaneous connections. Zero selects the default.
	//
	// This is the first of the three bounds and the crudest. Every connection
	// costs a goroutine, a read buffer, a job cache of up to eight blocks, and
	// — the expensive one — the right to make this node perform RandomX
	// verifications. A cap is what keeps that a bounded cost rather than a
	// function of how many sockets somebody opened.
	MaxConns int
	// MaxBanScore is the ban score at which a connection is closed. Zero
	// selects the default. See conn.penalise for the scoring rule and for why
	// it is a score rather than a strike count.
	MaxBanScore int
	// KeepaliveTimeout is how long a connection may be silent before it is
	// closed. Zero selects the default.
	//
	// The `keepalived` method exists precisely so that a miner with nothing to
	// submit can prove it is still there, so silence past this bound is not a
	// slow miner — it is a socket whose far end is gone, or one held open to
	// occupy a slot in MaxConns. Both are answered by closing it.
	KeepaliveTimeout time.Duration
	// JobRefresh is how often a connection is pushed a fresh job even when the
	// head has not moved. Zero selects the default.
	//
	// A timer as well as head-change refresh, for two reasons that are not the
	// same. First, a template's certificate set and fee revenue go stale: a
	// miner searching a five-minute-old template is mining a block that pays
	// less than the one it could be mining. Second, and more importantly, the
	// template's TIMESTAMP is fixed at assembly; a block whose declared time
	// falls far behind the network's median is closer to the median-time floor
	// every second it sits, and eventually the block it produces is one
	// pow.CheckMedianTime rejects. The timer bounds both.
	JobRefresh time.Duration
	// WriteTimeout bounds a single write to a miner. Zero selects the default.
	// Without it a miner that stops reading — a machine that froze, a
	// connection black-holed by a NAT that forgot it — blocks the writer
	// goroutine forever and leaks a connection slot that MaxConns is counting.
	WriteTimeout time.Duration
	// Now supplies the clock. Injected for the same reason miner.Miner injects
	// it: so tests are not at the mercy of one, and so that every reading of
	// wall time in this node is visible at a wiring site rather than buried.
	Now func() time.Time
	// Logger receives the endpoint's operational lines. Nil selects the
	// standard logger.
	Logger *log.Logger
	// Payout is where blocks pay when a miner logs in without naming an
	// address of its own. It is the node's --payout.
	//
	// The zero value means "there is none", and a login that needs the
	// fallback is then refused with a message saying so, rather than mining to
	// the zero address — which is not a burn, it is a cell nobody holds the key
	// to, and every reward paid into it is gone. See conn.resolvePayout for
	// which logins reach the fallback and which do not.
	Payout types.Address
}

// DefaultConfig returns the shipped defaults: loopback, capped, timed out.
func DefaultConfig() Config {
	return Config{
		Addr: "127.0.0.1:9422",
		// Sixteen. A solo endpoint serves the machines in one room, and the
		// number that makes sense is "how many miners does one person own",
		// not "how many can the kernel hold". Set it higher deliberately if
		// you are running a farm against your own node; every slot is a
		// standing licence to consume this node's verification CPU.
		MaxConns: 16,
		// Ten, which is ten bad shares — or five malformed requests, at two
		// points each — before the socket closes. Chosen against the two
		// failure modes it has to separate: an honest miner with a hardware
		// fault emits bad shares steadily and SHOULD be disconnected, quickly,
		// because it is wasting verification CPU it will keep wasting; a
		// healthy miner emits exactly zero, because a share it computed itself
		// under the target it was given cannot fail the check except through
		// the boundary sliver truncateTarget describes, which is one part in
		// 2^192. Ten is far above the sliver and far below "tolerate a broken
		// rig for an hour".
		MaxBanScore: 10,
		// Five minutes. XMRig sends keepalived roughly every minute when idle,
		// so five minutes is five missed keepalives — comfortably past any
		// network hiccup and well short of leaving a dead socket holding a
		// connection slot for an hour.
		KeepaliveTimeout: 5 * time.Minute,
		// Thirty seconds, which is one target block interval. A template
		// younger than one block interval has not meaningfully aged; one older
		// is being outbid by whatever arrived in the mempool since.
		JobRefresh: 30 * time.Second,
		// Ten seconds to put a few hundred bytes on a socket. Anything slower
		// is a miner that is not reading, and the answer is to stop waiting on
		// it.
		WriteTimeout: 10 * time.Second,
	}
}

// withDefaults fills the zero fields of a partially-specified Config.
//
// Applied at New rather than read defensively at each use, so that there is
// exactly one place where "zero means default" is decided and the rest of the
// package can treat the config as concrete. A field read defensively in five
// places is a field that will eventually be read undefended in a sixth.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Addr == "" {
		c.Addr = d.Addr
	}
	if c.MaxConns <= 0 {
		c.MaxConns = d.MaxConns
	}
	if c.MaxBanScore <= 0 {
		c.MaxBanScore = d.MaxBanScore
	}
	if c.KeepaliveTimeout <= 0 {
		c.KeepaliveTimeout = d.KeepaliveTimeout
	}
	if c.JobRefresh <= 0 {
		c.JobRefresh = d.JobRefresh
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = d.WriteTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Assembler builds candidate blocks. It is satisfied by *miner.Miner.
//
// An interface rather than the concrete miner for one reason that is not
// abstraction for its own sake: this endpoint must be testable without a
// proof-of-work engine, a chain store, a mempool and a state tree, and a test
// that had to construct all four to check that `getjob` returns a well-formed
// job would be a test nobody writes. Everything above the seam — the dialect,
// the job cache, the ban score, the caps — is exercised against a fake
// assembler.
//
// It also states the dependency honestly: this package needs exactly one thing
// from the miner, the ability to produce a candidate on the current tip, and
// borrowing the whole miner to say so would let a future change here reach
// into mining policy that is not this package's to set.
type Assembler interface {
	// Assemble returns a fresh candidate block on the current tip, with its
	// roots sealed and its target declared. It is miner.Miner.Assemble.
	Assemble() (*types.Block, error)
}

// Applier applies a solved block and reports the fold's outcome. It is
// satisfied by *chain.Chain.
type Applier interface {
	Apply(*types.Block) (*fold.Result, error)
	Tip() types.Header
	Params() *params.Params
}

// Announcer gossips a block this node accepted. It is satisfied by *p2p.Node.
//
// Optional — a Server with a nil Announcer applies blocks locally and tells
// nobody, which is correct for a devnet of one and catastrophic on a real
// network. The wiring in cmd/zycordd always supplies one; the interface is
// nilable so that a test does not have to stand up a peer-to-peer stack to
// submit a share.
type Announcer interface {
	AnnounceBlock(*types.Block)
}

// Server is the endpoint.
type Server struct {
	cfg   Config
	asm   Assembler
	chain Applier
	net   Announcer
	// engine verifies submitted shares.
	//
	// **It is the node's VERIFYING engine and it is used in light mode.** A
	// verifying RandomX engine holds a 256 MiB cache; the mining engine holds
	// a ~2 GiB dataset that makes hashing about an order of magnitude faster.
	// This endpoint verifies — one hash per submitted share, at a rate bounded
	// by the ban score and the connection cap — and must NEVER be the thing
	// that causes the dataset to be built. Doing so would take two gigabytes
	// of a miner's RAM away from the miner, on a machine whose whole purpose
	// is to give that RAM to XMRig, in order to speed up a hash this node
	// computes a handful of times a minute.
	//
	// The mechanism that guarantees it: this field is a pow.Engine and this
	// package never type-asserts it to pow.HotKeyEngine and never calls
	// MineOn, which is the only way a dataset gets built (see
	// pow.NewSolver's comment — it is the single site that flips it on, and
	// that site exists for the nonce loop). Verification goes through
	// pow.CheckWork, which takes a pow.Engine and cannot request a fast
	// representation even if it wanted to. A test asserts the negative.
	engine pow.Engine

	// ids hands out job and session identifiers.
	ids jobIDs

	mu sync.Mutex
	// conns is the live connection set, keyed by pointer identity. Held so
	// that a head change can push a new job to everyone and so that Close can
	// hang up on everyone; the count is what MaxConns bounds.
	conns map[*conn]struct{}
	// closed latches on Close, so that a connection accepted in the race
	// between the listener closing and the accept loop noticing is refused
	// rather than served by a Server that is shutting down.
	closed bool
	ln     net.Listener
	// wg joins every goroutine this server owns: the accept loop and one
	// reader per connection. Close waits on it, which is what makes
	// "the endpoint has stopped" a true statement rather than a request.
	wg sync.WaitGroup
}

// ErrClosed reports an operation on a server that has been closed.
var ErrClosed = errors.New("stratum: server is closed")

// New builds an endpoint. Nothing is bound and no goroutine starts until
// Listen and Serve are called, in that order — the same split node/rpc uses,
// and for the same reason its comment gives: an operator's log line saying the
// endpoint is up must follow the bind that made it true, not precede it.
func New(cfg Config, asm Assembler, ch Applier, engine pow.Engine) *Server {
	return &Server{
		cfg:    cfg.withDefaults(),
		asm:    asm,
		chain:  ch,
		engine: engine,
		conns:  make(map[*conn]struct{}),
	}
}

// SetAnnouncer supplies the gossip path for blocks found by connected miners.
//
// Separate from New because the peer-to-peer node is constructed after the
// chain and because this package must not depend on node/p2p — the same
// argument node/rpc's Network interface makes. A Server without one still
// applies blocks; it just does not tell anyone, which the wiring warns about.
func (s *Server) SetAnnouncer(n Announcer) { s.net = n }

// Listen binds the configured address.
//
// It is separate from Serve so that a caller can observe the bind, report the
// concrete port the kernel chose for a :0 request, and decide what a failed
// bind means — all three of which node/rpc learned to do the hard way and
// documents at its own Listen.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		// Closed between the caller's decision to listen and the bind
		// completing. Hand the socket back to the kernel rather than leaving a
		// bound port nothing will ever accept on.
		_ = ln.Close()
		return ErrClosed
	}
	s.ln = ln
	return nil
}

// Addr reports the bound address, or nil before Listen has succeeded. For a
// :0 request this is the port the kernel actually chose, which is the only
// address a miner can be pointed at.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve runs the accept loop until Close. It returns nil on a clean close.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return errors.New("stratum: Serve called before Listen")
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			// A transient accept error — a descriptor limit, an interrupted
			// syscall — must not kill the endpoint. Returning here would leave
			// the node running with a dead Stratum port and no log line to say
			// when it died, which is the failure mode node/rpc's Listen
			// comment describes from the other direction.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if !s.admit(c) {
			continue
		}
	}
}

// admit takes a freshly accepted socket and either starts serving it or
// refuses it.
//
// The refusal is a CLOSE with no reply, not an error response, and that is
// deliberate. A miner refused for the connection cap will retry — that is what
// every Stratum client does — and a reply explaining the cap would be a reply
// this server has to write, on a socket it has decided not to spend resources
// on, to a peer that may be the reason the cap was reached. Closing costs
// nothing and says the same thing.
func (s *Server) admit(nc net.Conn) bool {
	s.mu.Lock()
	if s.closed || len(s.conns) >= s.cfg.MaxConns {
		full := !s.closed
		s.mu.Unlock()
		_ = nc.Close()
		if full {
			s.logf("stratum: refused %s: %d connections already, which is the cap "+
				"(--stratum-max-conns)", nc.RemoteAddr(), s.cfg.MaxConns)
		}
		return false
	}
	c := newConn(s, nc)
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		defer s.drop(c)
		c.serve()
	}()
	return true
}

// drop removes a connection from the live set and closes its socket. It is
// idempotent, because both the reader goroutine's exit and Close reach it.
func (s *Server) drop(c *conn) {
	s.mu.Lock()
	_, live := s.conns[c]
	delete(s.conns, c)
	s.mu.Unlock()
	if live {
		c.close()
	}
}

// Close stops the endpoint and joins every goroutine it owns.
//
// The order is the same one cmd/zycordd's teardown argues for at length: stop
// accepting, hang up on everyone, then WAIT. A Close that returned before its
// connection goroutines had exited would let a reader still holding the chain
// outlive `defer c.Close()` on the store, which is the exact hazard the
// heartbeat's join comment describes.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	live := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		live = append(live, c)
	}
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	// Closing the socket is what unblocks a reader parked in Read; there is no
	// cooperative shutdown signal, because a miner that has stopped reading
	// would not observe one.
	for _, c := range live {
		c.close()
	}
	s.wg.Wait()
	return err
}

// OnHead pushes a fresh job to every connected miner.
//
// Called by the wiring whenever this node's tip changes, from any cause — a
// block this node mined, a block a peer announced, a reorg. Every one of those
// invalidates every outstanding template equally: the template names a parent,
// and the parent is no longer the tip, so a share found against it can only
// produce a block Chain.Apply rejects as a stale template.
//
// Best-effort per connection, and a failure to build or push a job to one
// miner never affects another: a chain read that failed for one connection
// failed for all of them, and the connection that notices is not the one that
// should be closed for it. Each connection's own job timer picks up whatever
// this misses.
func (s *Server) OnHead() {
	s.mu.Lock()
	live := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		live = append(live, c)
	}
	s.mu.Unlock()
	for _, c := range live {
		c.pushJob()
	}
}

// ConnCount reports live connections, for the node's heartbeat and for tests.
func (s *Server) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// fallbackPayout returns the node's own payout address, for logins that do not
// name one.
func (s *Server) fallbackPayout() types.Address { return s.cfg.Payout }

// algo names the work function this node serves jobs for, and reports whether
// any Stratum miner implements it.
//
// It is read from the ENGINE rather than from configuration or a constant. The
// engine is fixed by the network's own parameters — cmd/zycordd refuses to run
// against a network whose declared engine it does not hold — so this is the
// one honest source for the identifier, and deriving it here means the answer
// cannot disagree with what the node actually verifies against.
func (s *Server) algo() (string, bool) { return algoFor(s.engine.Name()) }

// Algo reports the algorithm identifier this endpoint advertises to miners,
// and whether any Stratum miner implements it.
//
// Exported for the wiring's "listening" line, which used to spell the
// identifier as a constant — "rx/0" — while algoFor resolved the running
// engine to "rx/2". The log therefore named an algorithm this endpoint does
// not serve, on a line an operator reads while bringing a network up. That is
// the same defect algoFor's own comment records an earlier revision shipping
// into the protocol; it had survived in the log.
func (s *Server) Algo() (string, bool) { return s.algo() }

func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// IsLoopback reports whether an address string binds only to the loopback
// interface.
//
// Used by the wiring to decide whether to print the exposure warning. It
// answers conservatively: anything it cannot parse, and the empty host that
// means "all interfaces", are reported as NOT loopback, because the failure
// that matters is staying silent about a socket that turned out to be public.
// A spurious warning costs a line in a log; a missing one costs an operator
// their emission address.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		// ":9422" binds every interface. This is the case the warning exists
		// for and the one an operator is most likely to type by accident,
		// having copied it from a tutorial written for a service that has
		// authentication.
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// A hostname. "localhost" is the only one worth resolving here, and
	// resolving arbitrary names at startup would make the warning depend on
	// DNS. Anything else is treated as exposed.
	return host == "localhost"
}
