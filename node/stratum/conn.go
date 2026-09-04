package stratum

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"zycord/core/crypto"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
)

// maxLineBytes bounds one JSON-RPC line from a miner.
//
// A Monero-dialect request is a few hundred bytes; the largest legitimate one
// is a `login` carrying an agent string and an algo list, which is well under a
// kilobyte. Four kilobytes is generous by an order of magnitude and is the
// difference between a peer that can send a malformed request and a peer that
// can make this node buffer a gigabyte by opening a socket and never sending a
// newline. bufio.Scanner without an explicit bound would grow to its own
// 64 KiB default and then error, which is better than unbounded but still
// sixteen times more than any miner needs.
const maxLineBytes = 4 << 10

// conn is one miner's connection.
//
// Concurrency: exactly one goroutine reads (serve), and writes come from both
// that goroutine and from OnHead on the server's goroutine, so writes are
// serialised by wmu. Everything else — the job cache, the ban score, the login
// state — is guarded by mu. The two locks are never held at the same time in
// the same order twice, because they are never held at the same time at all:
// a write is prepared under mu, mu is released, and only then is the write
// performed. That ordering is what keeps a miner that has stopped reading from
// blocking a head change for every other miner behind a shared lock.
type conn struct {
	srv *Server
	nc  net.Conn
	// sessionID is echoed by the miner on every submit. Set at login.
	sessionID string

	wmu sync.Mutex

	mu sync.Mutex
	// loggedIn latches at the first successful login. It never un-latches: a
	// second login on the same socket is answered as a fresh login (XMRig does
	// this after some errors) but cannot revoke the session.
	loggedIn bool
	// payout is the address blocks found on this connection pay to. It comes
	// from the login field when that parses to a valid persistent address, and
	// otherwise from the node's --payout. See resolvePayout.
	payout types.Address
	// jobs is this connection's own cache. Per-connection rather than shared
	// because each connection has its own ExtraNonce, which is inside the
	// seed's preimage, so its jobs' blobs differ from every other
	// connection's even at the same height.
	jobs jobCache
	// extraNonce is this connection's slice of the search space.
	extraNonce uint32
	// banScore accumulates the cost of invalid work. See penalise.
	banScore int
	// closed latches so that close is idempotent and so that a write racing a
	// close does not report an error worth logging.
	closed bool
	// lastSeen is the clock reading at the last inbound line. The keepalive
	// reaper compares against it.
	lastSeen time.Time
	// lastAssembly is the clock reading at the last template assembly this
	// connection caused, from any path. onGetJob rate-limits against it; see
	// minAssemblyInterval.
	lastAssembly time.Time
}

func newConn(s *Server, nc net.Conn) *conn {
	c := &conn{srv: s, nc: nc, lastSeen: s.cfg.Now()}
	// The ExtraNonce is derived from the session id rather than from a counter
	// over live connections, because a counter is reused the moment a
	// connection closes: a miner that reconnects after a network blip would be
	// handed the space a *different* live miner is already searching, and the
	// two would duplicate each other's work for as long as both stayed
	// connected. A random draw collides with probability bounded by the
	// birthday bound over MaxConns connections in a 2^32 space, which at the
	// default cap of 16 is about 3 in 10^8 — and a collision costs duplicated
	// work, not incorrectness.
	c.sessionID = s.ids.next()
	c.extraNonce = extraNonceFromSession(c.sessionID)
	return c
}

// extraNonceFromSession folds a session id into 32 bits.
//
// It reads the first four bytes of the id's hex rather than hashing it: the id
// is already uniform random from crypto/rand, so hashing it would buy nothing
// but a dependency. A short or malformed id — only reachable through the
// entropy-failure fallback in jobIDs.next — yields zero, which is the solo
// miner's ExtraNonce and is a correct value rather than a special case.
func extraNonceFromSession(id string) uint32 {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) < 4 {
		return 0
	}
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
}

// serve reads and dispatches until the connection ends.
func (c *conn) serve() {
	defer c.close()

	// The job refresh timer. It runs from connect rather than from login so
	// that its first fire is not synchronised across a fleet of miners that
	// all logged in at the same moment — which they do, because they were all
	// started by the same script.
	refresh := time.NewTicker(c.srv.cfg.JobRefresh)
	defer refresh.Stop()
	done := make(chan struct{})
	defer close(done)
	go c.tick(refresh.C, done)

	sc := bufio.NewScanner(c.nc)
	sc.Buffer(make([]byte, 0, 1024), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		c.mu.Lock()
		c.lastSeen = c.srv.cfg.Now()
		c.mu.Unlock()
		if len(strings.TrimSpace(string(line))) == 0 {
			// A bare newline. Some proxies emit them as their own keepalive.
			// Ignored rather than penalised: it costs nothing and refusing it
			// would disconnect a client that is behaving.
			continue
		}
		if !c.handleLine(line) {
			return
		}
	}
	if err := sc.Err(); err != nil && !c.isClosed() {
		// A line longer than maxLineBytes lands here as bufio.ErrTooLong,
		// alongside ordinary read errors. It is logged at the same level: from
		// this node's chair "the peer sent something oversized" and "the peer
		// went away" are both just the end of a connection, and neither
		// deserves a louder line than the other.
		c.srv.logf("stratum: %s: read: %v", c.nc.RemoteAddr(), err)
	}
}

// tick drives the job refresh and the keepalive reaper off one goroutine.
//
// One goroutine rather than two because the two decisions are made against the
// same clock and neither is urgent to the second. The reaper is checked on the
// job tick, so the effective keepalive resolution is JobRefresh — thirty
// seconds against a five-minute timeout, which is a rounding error on the
// quantity being bounded.
func (c *conn) tick(fire <-chan time.Time, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-fire:
			c.mu.Lock()
			idle := c.srv.cfg.Now().Sub(c.lastSeen)
			live := c.loggedIn
			c.mu.Unlock()
			if idle > c.srv.cfg.KeepaliveTimeout {
				c.srv.logf("stratum: %s: silent for %s, which is past the keepalive "+
					"timeout; closing", c.nc.RemoteAddr(), idle.Truncate(time.Second))
				c.close()
				return
			}
			if live {
				c.pushJob()
			}
		}
	}
}

// handleLine dispatches one request. It returns false when the connection
// should end.
func (c *conn) handleLine(line []byte) bool {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		// Not JSON at all. This is the shape a port scanner, a stray HTTP
		// request or a miner pointed at the wrong protocol makes, and none of
		// them will start behaving; the score is what ends it.
		c.penalise(2, "malformed request")
		return c.reply(nil, nil, errBadRequest)
	}

	switch req.Method {
	case "login":
		return c.onLogin(req)
	case "getjob":
		return c.onGetJob(req)
	case "submit":
		return c.onSubmit(req)
	case "keepalived":
		// Deliberately the cheapest path in the file. A keepalive updates
		// lastSeen — which handleLine's caller has already done for every
		// inbound line, this one included — and says OK. It touches no chain
		// state and takes no lock beyond the write.
		if !c.isLoggedIn() {
			return c.reply(req.ID, nil, errUnauthenticated)
		}
		return c.reply(req.ID, statusResult{Status: "KEEPALIVED"}, nil)
	default:
		// Not scored. An unknown method is what a miner speaking a newer
		// dialect sends — `job` acknowledgements, `mining.subscribe` from
		// something that guessed wrong — and it is a request this endpoint
		// declines, not an attack. What ends such a connection is the
		// keepalive timeout if it never says anything useful.
		return c.reply(req.ID, nil, errInvalidMethod)
	}
}

// onLogin handles `login`: validate the payout address, hand out a session id
// and the first job.
func (c *conn) onLogin(req request) bool {
	var p loginParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		c.penalise(2, "malformed login")
		return c.reply(req.ID, nil, errBadRequest)
	}

	// Algorithm negotiation, such as it is.
	//
	// The algorithm is whatever the NETWORK declares, resolved from the
	// engine — it is not a constant and it is not this endpoint's to choose. A
	// node does not get to decide what it verifies against, so it does not get
	// to decide what it advertises either; an endpoint that hardcoded one
	// would hand every miner a job it cannot win the moment the networks moved,
	// which is exactly what an earlier revision of this file did when it
	// advertised rx/0 into an rx/2 world and refused every correctly
	// configured stock miner at login.
	algo, mineable := c.srv.algo()
	if !mineable {
		// A network whose work function no miner implements — a dev-blake3
		// devnet. Saying so plainly beats advertising something plausible and
		// letting the miner hash the wrong function forever.
		return c.reply(req.ID, nil, &rpcError{-1,
			"this network's work function is not one any Stratum miner implements; " +
				"mine it with the node's built-in miner instead"})
	}
	// XMRig sends the list it was built with; a miner whose list omits this
	// network's algorithm will hash something the chain does not check against
	// and every share it sends will be noise. Refusing at login turns that
	// into one clear line in the miner's own console instead of an hour of
	// silent rejection.
	//
	// An ABSENT list is accepted: older miners and some proxies do not send
	// one, and refusing them would be refusing on the strength of a field's
	// absence rather than its contents.
	if len(p.Algo) > 0 && !containsAlgo(p.Algo, algo) {
		return c.reply(req.ID, nil, &rpcError{-1,
			"Unsupported algorithm: this node serves " + algo + " only"})
	}

	payout, err := c.resolvePayout(p.Login)
	if err != nil {
		// NOT scored. A typo'd address is an operator mistake, and the
		// connection is about to be told so in terms XMRig stops retrying on;
		// adding ban score would additionally blame them for the retries their
		// miner makes before it reads the message.
		c.srv.logf("stratum: %s: login refused: %v", c.nc.RemoteAddr(), err)
		return c.reply(req.ID, nil, errUnauthorizedWorker)
	}

	c.mu.Lock()
	c.loggedIn = true
	c.payout = payout
	c.mu.Unlock()

	agent := p.Agent
	if agent == "" {
		agent = "unidentified"
	}
	c.srv.logf("stratum: %s: %s mining to %x (session %s, extra_nonce %08x)",
		c.nc.RemoteAddr(), agent, payout[:8], c.sessionID, c.extraNonce)

	j, err := c.newJob()
	if err != nil {
		// The login itself succeeded; the node just cannot build a template
		// right now — most often because it is before genesis
		// (miner.ErrTooEarly) or because the tip moved mid-assembly. Reporting
		// this as a login failure would send XMRig into a reconnect loop
		// against a node that is working correctly and simply waiting, so the
		// error carries the reason and the miner's own retry brings it back.
		c.srv.logf("stratum: %s: no template yet: %v", c.nc.RemoteAddr(), err)
		return c.reply(req.ID, nil, &rpcError{-1, "no template available: " + err.Error()})
	}
	return c.reply(req.ID, loginResult{
		ID:         c.sessionID,
		Job:        c.jobParams(j),
		Status:     "OK",
		Extensions: []string{},
	}, nil)
}

// onGetJob handles `getjob`: a miner asking for work outside the push cycle.
//
// It builds a FRESH template rather than returning the cached newest job, and
// that is the right reading of the method. A miner sends getjob when it has
// nothing to do — it has exhausted a nonce space, or it just recovered from an
// error — and handing it back the same job it already holds would leave it
// idle until the timer fires. The cost is one Assemble, which is bounded by
// how often a miner can ask, which is bounded by the ban score and the
// connection cap.
func (c *conn) onGetJob(req request) bool {
	if !c.isLoggedIn() {
		return c.reply(req.ID, nil, errUnauthenticated)
	}
	// A minimum interval between ASSEMBLIES, not between replies.
	//
	// The comment above prices a getjob at "one Assemble, which is bounded by
	// how often a miner can ask, which is bounded by the ban score and the
	// connection cap". Measured, that bound is not a bound: getjob is
	// deliberately unscored — a miner asking for work is behaving — so the ban
	// score never fires, and one connection issues about 16,500 calls a second
	// down a pipelined socket. Against a real chain one Assemble is ~570 µs of
	// snapshot, difficulty-window walk, mempool selection, a dry-run fold to a
	// fixpoint and a root computation, so a single unauthenticated connection
	// asks for roughly nine CPU-seconds of work per wall-clock second, and the
	// default sixteen slowed this node's own template assembly by 45x
	// (I8-H1, measured in TestGetJobFloodAgainstARealChain).
	//
	// Answered by serving the job the connection already has rather than by
	// refusing or by scoring. Refusing would break the method's honest use —
	// a miner that has exhausted a nonce space needs work NOW — and scoring
	// would ban miners for asking, which is what the method is for. A cached
	// job is a correct answer to "give me work": it is the same template the
	// miner would have been pushed, its nonce space is untouched, and a miner
	// that genuinely exhausted 2^32 nonces in under a job interval does not
	// exist. So the honest caller is unaffected and the flood is bounded to
	// one assembly per interval per connection.
	//
	// The interval is deliberately far below JobRefresh: this is a floor on
	// cost, not a second refresh policy, and a miner recovering from an error
	// must not wait thirty seconds for work.
	c.mu.Lock()
	since := c.srv.cfg.Now().Sub(c.lastAssembly)
	cached := c.jobs.newest()
	c.mu.Unlock()
	if cached != nil && since < minAssemblyInterval {
		return c.reply(req.ID, c.jobParams(cached), nil)
	}
	j, err := c.newJob()
	if err != nil {
		return c.reply(req.ID, nil, &rpcError{-1, "no template available: " + err.Error()})
	}
	return c.reply(req.ID, c.jobParams(j), nil)
}

// minAssemblyInterval is the shortest gap between two template assemblies
// driven by one connection's getjob calls.
//
// One second, which is well under the 30-second job refresh — so a miner that
// has run out of work waits at most a second for a genuinely fresh template —
// and is three orders of magnitude above the rate a pipelined socket can ask
// at. It bounds an unscored method's cost without changing what the method
// means to a miner that is behaving.
const minAssemblyInterval = time.Second

// onSubmit handles `submit`: verify a share, and if it is a block, apply and
// announce it.
//
// The order of the checks below is chosen so that the CHEAPEST refusals happen
// first and the RandomX hash — which is the expensive thing an unauthenticated
// peer can make this node do — happens last, after the share has been shown to
// name a real job, carry a well-formed nonce, and not be a duplicate. A
// reordering that hashed first would turn a malformed-submit flood into a CPU
// exhaustion attack that the ban score only catches after the damage.
func (c *conn) onSubmit(req request) bool {
	if !c.isLoggedIn() {
		return c.reply(req.ID, nil, errUnauthenticated)
	}
	var p submitParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		c.penalise(2, "malformed submit")
		return c.reply(req.ID, nil, errBadRequest)
	}
	if p.ID != c.sessionID {
		// A submit carrying somebody else's session id. On an honest
		// connection this cannot happen — XMRig echoes what login gave it —
		// so it is either a proxy multiplexing several miners onto one socket
		// without understanding that sessions are per-socket, or a probe.
		// Scored, because both are things this endpoint wants to stop serving.
		c.penalise(2, "session id mismatch")
		return c.reply(req.ID, nil, errUnauthenticated)
	}

	nonce, ok := parseNonce(p.Nonce)
	if !ok {
		c.penalise(2, "malformed nonce")
		return c.reply(req.ID, nil, errBadRequest)
	}

	c.mu.Lock()
	j := c.jobs.get(p.JobID)
	if j == nil {
		c.mu.Unlock()
		// NOT scored, and this is the single most important non-scoring
		// decision in the file. A job falls out of the cache because eight
		// newer ones replaced it, which on a live chain happens to every miner
		// whose share crossed a head change in flight. Scoring it would ban
		// miners for network latency, and it would ban them hardest exactly
		// when the chain is busiest.
		return c.reply(req.ID, nil, errJobNotFound)
	}
	if _, dup := j.submitted[nonce]; dup {
		c.mu.Unlock()
		// Scored, but lightly. A duplicate is a retransmit (harmless, and the
		// miner's own doing) or a miner re-searching a space it already
		// covered (a fault, but a slow one). One point means a miner would
		// have to send ten before it is disconnected.
		c.penalise(1, "duplicate share")
		return c.reply(req.ID, nil, errDuplicateShare)
	}
	// The nonce is NOT recorded here. It is recorded once the share has been
	// shown to clear the job target — see the insert below the check.
	//
	// The ordering is the finding I8-M1 records. Recording before the check
	// made job.submitted's own comment false: it claims an attacker "would
	// have to spend a real hash per entry to get past the low-difficulty check
	// first", which describes an insert placed after the check, and the insert
	// was before it. Two things followed. The map grew on shares that had
	// demonstrated nothing, and — the reason this is worth moving rather than
	// only documenting — the SECOND copy of a nonce that had already failed
	// the target was answered as a duplicate at one point instead of as a bad
	// share at two, so a flooder halved its own score cost by repeating
	// itself.
	//
	// The header is copied out under the lock and the block is rebuilt
	// outside it. Header is a value type with no pointer fields, so this copy
	// genuinely detaches; the certificate slice is shared, and is safe to
	// share because a job's block is never mutated after construction (see
	// job's comment).
	hdr := j.block.Header
	certs := j.block.Certs
	cites := j.block.Cites
	target := j.target
	height := j.height
	extra := j.extraNonce
	c.mu.Unlock()

	sealNonce(&hdr, nonce, extra)

	// The RandomX digest for this reconstructed header, recomputed here and
	// written into PoWHash.
	//
	// PoWHash is a CONSENSUS FIELD under rx/2 — the commitment is
	// blake2b(PoWInput ‖ PoWHash), so a header without it has no commitment
	// and cannot pass any work check at all. It is recomputed rather than
	// taken from the wire even though XMRig does send the raw digest (in the
	// field confusingly named `commitment`; the names are inverted at every
	// layer under rx/2). A share is a claim, and a claim this node writes into
	// its own chain gets checked rather than believed.
	//
	// This is the one RandomX evaluation a share costs, in LIGHT mode — see
	// Server.engine for why this path must never build the full dataset.
	recoverPoWHash(c.srv.engine, &hdr, c.srv.chain.Params())

	// The share's own arithmetic, against the target the miner was GIVEN and
	// over the quantity the miner actually filters on.
	//
	// That quantity is the COMMITMENT, not the RandomX digest, and getting it
	// wrong is not a near miss: the two are independent uniform values, so
	// comparing the digest here would accept a set of nonces DISJOINT from the
	// set XMRig sends. Every honest share would be scored and the miner banned
	// after five, at a healthy hashrate, with nothing naming the cause. See
	// jobTargetValue.
	//
	// Checked before the full-target check because this is the one whose
	// failure is the miner's fault; a share failing here computed a different
	// function than the one it was asked to.
	if !meetsJobTarget(hdr, target) {
		// Scored at the full weight. See DefaultConfig's MaxBanScore comment
		// for why a healthy miner produces zero of these.
		c.penalise(2, "share below the job target")
		c.srv.logf("stratum: %s: rejected share at height %d: below the job target",
			c.nc.RemoteAddr(), height)
		return c.reply(req.ID, nil, errLowDifficulty)
	}

	// The share has cleared the job target, so it is a share worth remembering
	// and a retransmit of it is a genuine duplicate rather than a repeat of
	// something already refused. This is the insert job.submitted's comment
	// describes: an entry costs the sender a real proof of work.
	c.mu.Lock()
	j.submitted[nonce] = struct{}{}
	c.mu.Unlock()

	// The share against the FULL 256-bit network target, which is the rule
	// every peer will judge the resulting block by.
	//
	// Two checks rather than one, and the second is not redundant: the job
	// target is a 64-bit truncation, so a band of shares one part in 2^192
	// wide satisfies it and not the header's target (truncateTarget explains
	// the arithmetic). Those shares are honest and the miner is not at fault,
	// so they are answered as accepted-but-not-a-block rather than scored.
	//
	// pow.CheckWork, not a hand-rolled comparison, and specifically the same
	// entry point node/miner's own post-seal check uses. Its comment there is
	// exact about why a producer re-derives what it just wrote: a block this
	// node applies through Chain.Apply is checked for work by nothing else.
	// A stratum share is a block from a stranger arriving through a path with
	// even less validation than that, so the check is not optional here — it
	// is the only thing between an attacker's arbitrary bytes and this node's
	// own chain.
	if err := pow.CheckWork(c.srv.engine, hdr, c.srv.chain.Params()); err != nil {
		// A valid share that is not a block. This is the overwhelmingly common
		// outcome on any chain whose difficulty exceeds 2^192, which is every
		// real one — see the package comment's warning that on a solo endpoint
		// an accepted share IS a block. Answered OK so that the miner's
		// accepted counter moves and it can see it is connected and working.
		return c.reply(req.ID, statusResult{Status: "OK"}, nil)
	}

	// It is a block.
	b := &types.Block{Header: hdr, Certs: certs, Cites: cites}
	res, err := c.srv.chain.Apply(b)
	if err != nil {
		if errors.Is(err, chain.ErrWrongParent) {
			// The tip moved between this template being built and this share
			// arriving. The miner did everything right and lost a race; that
			// is a stale job, which is exactly what errJobNotFound means to
			// XMRig, and it is unscored for the same reason the cache miss is.
			c.srv.logf("stratum: %s: block at height %d lost the race to a new tip",
				c.nc.RemoteAddr(), height)
			return c.reply(req.ID, nil, errJobNotFound)
		}
		// The node could not apply a block whose proof of work it just
		// verified. That is this node's problem, not the miner's, so it is
		// errInternal and unscored — blaming the miner here would ban honest
		// miners during a local storage or state fault.
		c.srv.logf("stratum: %s: applying block at height %d: %v",
			c.nc.RemoteAddr(), height, err)
		return c.reply(req.ID, nil, errInternal)
	}
	if c.srv.net != nil {
		c.srv.net.AnnounceBlock(b)
	}
	id := b.Header.ID()
	c.srv.logf("stratum: block height=%d id=%x from %s certs=%d reward=%s",
		b.Header.Height, id[:6], c.nc.RemoteAddr(), len(b.Certs), res.MinerReward.String())

	// Every connection gets a new job at once, this one included. Waiting for
	// the head-change hook would work — the wiring calls OnHead — but going
	// through it here as well means the miner that found the block is not idle
	// for however long the node's own head-change plumbing takes to notice.
	go c.srv.OnHead()
	return c.reply(req.ID, statusResult{Status: "OK"}, nil)
}

// newJob assembles a fresh template, caches it, and returns it.
func (c *conn) newJob() (*job, error) {
	c.mu.Lock()
	payout := c.payout
	extra := c.extraNonce
	c.mu.Unlock()

	b, err := c.srv.asm.Assemble()
	if err != nil {
		return nil, err
	}
	// The payout this connection logged in with, stamped over whatever the
	// node's own --payout put there.
	//
	// After the roots are sealed, which is safe and is worth saying why:
	// EmissionAddr is a HEADER field, and no root in the block commits to the
	// header. CertRoot and CitesRoot are over the bodies; StateRoot is sealed
	// over the fold's effect on state, which reads the emission address from
	// the header it is folding rather than from a copy — so changing it here
	// changes where the emission is paid without invalidating anything already
	// computed. What it DOES change is PoWSeed, which is why this must happen
	// before the blob is built, and it does: the blob is built two lines down.
	b.Header.EmissionAddr = payout

	j := &job{
		id:         c.srv.ids.next(),
		block:      b,
		extraNonce: extra,
		target:     truncateTarget(b.Header.Target),
		height:     b.Header.Height,
		blob:       blobFor(b.Header),
		submitted:  make(map[uint32]struct{}),
	}
	c.mu.Lock()
	c.jobs.put(j)
	// Stamped here rather than in onGetJob so that EVERY assembly — a push, a
	// login, a getjob — counts against the interval. A getjob arriving just
	// after a pushed job has been built is asking for a template that already
	// exists.
	c.lastAssembly = c.srv.cfg.Now()
	c.mu.Unlock()
	return j, nil
}

// jobParams renders a job for the wire.
func (c *conn) jobParams(j *job) jobParams {
	p := c.srv.chain.Params()
	seed, next := seedHashes(j.height, p)
	// Resolved per job rather than cached at login, because it is derived
	// from the engine the node is actually running and a job that named a
	// different algorithm than the login advertised would be a job the miner
	// silently re-initialises its VM for.
	algo, _ := c.srv.algo()
	return jobParams{
		Blob:         hexOf(j.blob),
		JobID:        j.id,
		Target:       jobTargetHex(j.target),
		Algo:         algo,
		Height:       j.height,
		SeedHash:     hexOf(seed[:]),
		NextSeedHash: hexOf(next[:]),
	}
}

// pushJob builds a fresh template and pushes it as a `job` notification.
//
// Failures are logged and swallowed. A push is an optimisation over the
// miner's own getjob — a miner whose push never arrives asks for work when it
// runs out — so a template this node could not build right now (before
// genesis, mid-reorg) must not close a connection that is otherwise healthy.
func (c *conn) pushJob() {
	if !c.isLoggedIn() || c.isClosed() {
		return
	}
	j, err := c.newJob()
	if err != nil {
		c.srv.logf("stratum: %s: job push skipped: %v", c.nc.RemoteAddr(), err)
		return
	}
	c.notify("job", c.jobParams(j))
}

// resolvePayout decides where blocks found on this connection pay.
//
// The login field wins when it is a valid persistent address, because that is
// the whole point of the field: the person running the miner is telling this
// node who to pay, and a solo endpoint that ignored it would silently pay the
// node operator instead — the single worst failure this package could have, in
// that it looks like success from both ends until somebody checks a balance.
//
// An EMPTY login falls back to the node's own --payout, which is what makes
// `xmrig -o 127.0.0.1:9422 -u x` work for an operator mining their own node.
// Monero convention is that `-u` is mandatory, and people type "x".
//
// An address that is present but INVALID is refused rather than fallen back
// on, and the asymmetry with the empty case is deliberate. Empty means "I did
// not specify, use yours"; malformed means "I specified, and I meant it" — and
// quietly paying someone else's address to a miner who typed their own with a
// typo is exactly the failure above. Refusing costs a clear error message; the
// fallback costs them the block.
//
// The persistent-address rule is the same one cmd/zycordd's parsePayout
// enforces and for the same documented reason (docs/WALLET.md rule 3): a
// one-shot (0x01) address burns every future reward the moment it is spent
// once, and a mining payout is paid over and over.
func (c *conn) resolvePayout(login string) (types.Address, error) {
	login = strings.TrimSpace(login)
	// The placeholders every Monero tutorial tells people to type in the
	// username field when the pool does not need one.
	if login == "" || login == "x" || login == "X" {
		fallback := c.srv.fallbackPayout()
		var zero types.Address
		if fallback == zero {
			return zero, errors.New("no login address and this node has no --payout to fall back on")
		}
		return fallback, nil
	}
	// A worker suffix, "<address>.<worker>" or "<address>+<worker>", which is
	// pool convention and which XMRig passes through verbatim. This endpoint
	// has no per-worker accounting, so the suffix is dropped rather than
	// rejected: refusing it would refuse a command line that is correct
	// everywhere else in the ecosystem.
	if i := strings.IndexAny(login, ".+"); i >= 0 {
		login = login[:i]
	}
	return parseAddress(login)
}

// parseAddress decodes and validates a payout address from its hex form.
//
// The decode is encoding/hex rather than a hand-rolled loop, which is the
// correction cmd/zycordd's parsePayout records having had to make: a
// hand-rolled decoder there accepted an odd-length input by silently dropping
// its last character, so two binaries in one tree disagreed about what an
// address is. A third disagreeing implementation is exactly what this comment
// exists to prevent.
func parseAddress(s string) (types.Address, error) {
	var addr types.Address
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil || len(raw) != 32 {
		return addr, errors.New("payout address must be 32 bytes of hex")
	}
	copy(addr[:], raw)
	if addr[0] != crypto.AddrVersionPersistent {
		return addr, errors.New("payout address must be persistent (version 0x02): " +
			"a mining payout is paid every block, and a one-shot (0x01) address burns " +
			"every future reward the moment it is spent once (docs/WALLET.md rule 3)")
	}
	return addr, nil
}

// containsAlgo reports whether an algorithm list names one this node serves.
// Case-insensitive because miners are inconsistent about it and the comparison
// is not a security boundary.
func containsAlgo(list []string, want string) bool {
	for _, a := range list {
		if strings.EqualFold(strings.TrimSpace(a), want) {
			return true
		}
	}
	return false
}

// parseNonce decodes XMRig's 4-byte little-endian hex nonce.
//
// Exactly eight hex characters. Not "at most": a shorter field is ambiguous
// about which end it was padded from, and accepting it would mean this node
// and the miner disagree about which nonce was searched — so a share the miner
// believes is good is verified against a different value and rejected, and the
// miner has no way to see why.
func parseNonce(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return 0, false
	}
	return uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24, true
}

// penalise adds to the connection's ban score and closes it at the cap.
//
// A SCORE rather than a strike count, which is the same instrument node/p2p
// uses on peers and is chosen for the same reason: the offences are not equally
// bad, and a count forces every one of them to be treated as if it were. A
// malformed request costs two because it means the far end is not speaking this
// protocol at all and will not start; a duplicate share costs one because it is
// usually a retransmit; a share below the job target costs two because it means
// the miner is computing the wrong function and every subsequent share it sends
// will cost this node a RandomX verification for nothing.
//
// The score only ever rises. There is no decay, and that is deliberate for a
// connection-scoped score: decay exists to let a long-lived PEER recover from a
// bad patch, and a stratum connection is not long-lived in that sense — a miner
// disconnected here reconnects within seconds with a fresh score. Adding decay
// would mean a miner emitting bad shares at just under the decay rate could do
// so indefinitely, which is precisely the miner this bound exists to stop.
func (c *conn) penalise(points int, why string) {
	c.mu.Lock()
	c.banScore += points
	score := c.banScore
	c.mu.Unlock()
	if score >= c.srv.cfg.MaxBanScore {
		c.srv.logf("stratum: %s: ban score %d reached the cap (%s); closing",
			c.nc.RemoteAddr(), score, why)
		c.close()
	}
}

// reply writes a JSON-RPC response. It returns false when the connection
// should end.
func (c *conn) reply(id json.RawMessage, result any, e *rpcError) bool {
	if id == nil {
		// A request whose id could not be parsed still gets an answer, with a
		// null id, because a miner waiting on a reply it will never receive
		// blocks until its own timeout — and diagnosing that from the miner's
		// end is impossible. JSON-RPC permits a null id on an error response
		// for exactly this case.
		id = json.RawMessage("null")
	}
	return c.write(response{ID: id, JSONRPC: "2.0", Result: result, Error: e})
}

// notify writes a server-initiated notification.
func (c *conn) notify(method string, params any) bool {
	return c.write(notification{JSONRPC: "2.0", Method: method, Params: params})
}

// write marshals a message and puts it on the socket, newline-terminated.
func (c *conn) write(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		// Unreachable for the types this package marshals — every one of them
		// is plain data — but a marshal failure that closed the connection
		// silently would be a defect that presents as an unexplained
		// disconnect, so it is named.
		c.srv.logf("stratum: %s: encoding a reply: %v", c.nc.RemoteAddr(), err)
		return false
	}
	b = append(b, '\n')

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.isClosed() {
		return false
	}
	// The deadline is set per write rather than once at accept, because a
	// deadline is absolute: set once, it would expire mid-session and close a
	// connection that is behaving. See Config.WriteTimeout for what it bounds.
	//
	// time.Now, NOT cfg.Now, and this is the one place in the package where
	// the injected clock is deliberately bypassed. SetWriteDeadline hands an
	// absolute instant to the KERNEL, which compares it against the real
	// clock and knows nothing about a clock a test substituted; a fake reading
	// from any other moment produces a deadline that is either already expired
	// — every write fails instantly with i/o timeout, which is exactly how
	// this was found — or unreachably far away, which silently removes the
	// bound. cfg.Now governs the decisions this package makes; this is a value
	// handed to something outside it.
	_ = c.nc.SetWriteDeadline(time.Now().Add(c.srv.cfg.WriteTimeout))
	if _, err := c.nc.Write(b); err != nil {
		if !c.isClosed() && !errors.Is(err, io.ErrClosedPipe) {
			c.srv.logf("stratum: %s: write: %v", c.nc.RemoteAddr(), err)
		}
		c.close()
		return false
	}
	return true
}

func (c *conn) isLoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loggedIn
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// close shuts the socket. Idempotent: it is reached from the reader goroutine's
// exit, from the ban score, from the keepalive reaper and from Server.Close,
// and all four can happen at once.
func (c *conn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.nc.Close()
}
