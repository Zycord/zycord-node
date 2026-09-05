package stratum

import (
	"encoding/hex"
	"encoding/json"
)

// The Monero-pool Stratum dialect, as stock XMRig speaks it.
//
// This is NOT the Bitcoin Stratum most people mean by the word. It shares the
// transport (newline-delimited JSON-RPC 2.0 over TCP) and nothing else: there
// is no `mining.subscribe`, no merkle branch, no extranonce2 the miner
// assembles a coinbase from. A Monero-dialect pool hands the miner a complete
// hashing blob and a target, and the miner hands back a nonce. That asymmetry
// is why this endpoint can exist at all against a chain with no coinbase
// transaction to vary: there is nothing for the miner to assemble, so there is
// nothing it needs to understand about our block format.
//
// The dialect is defined by an implementation rather than by a document, so
// every field below is written to match what XMRig actually parses. Where
// XMRig tolerates a field being absent it is still emitted, because the other
// miners that speak this dialect (xmrig-proxy, some ASIC firmwares, older
// forks) are less tolerant and the cost of a field is nothing.

// request is an inbound JSON-RPC call.
//
// ID is json.RawMessage rather than a number or a string because the dialect
// does not agree with itself about which it is: XMRig sends integers, some
// proxies send strings, and a response whose id is not byte-identical to the
// request's is a response the miner drops on the floor. Echoing the raw bytes
// back sidesteps the disagreement entirely — this endpoint never needs to
// interpret an id, only to return it.
type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// response is an outbound reply to a request.
//
// Result and Error are both pointers and exactly one is ever set. A reply
// carrying `"error": null` alongside a result is what every pool sends and
// what XMRig expects; a reply carrying both non-null is malformed and some
// miners treat it as a protocol violation and disconnect.
type response struct {
	ID      json.RawMessage `json:"id"`
	JSONRPC string          `json:"jsonrpc"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error"`
}

// notification is a server-initiated push. Only one method is ever pushed:
// `job`.
//
// It carries no id — that is what makes it a notification rather than a
// request, and a miner that received an id here would wait for a reply it will
// never get a chance to send.
type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// rpcError is a JSON-RPC error object.
//
// The codes below are the ones the Monero pool ecosystem settled on, and using
// them is not cosmetic: XMRig's accepted/rejected counters, its
// retry/backoff behaviour, and whether it drops the connection or keeps mining
// all key off the code and off substrings of the message. A pool that invents
// its own codes shows up in a miner's log as an unexplained disconnect loop.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return e.Message }

// The status codes. Values are the de-facto Monero pool set.
//
// -1 is the catch-all every implementation uses for "your request was wrong in
// a way that is your fault"; the message is what distinguishes them, and XMRig
// surfaces it verbatim to the operator, so each message below is written to be
// read by a human staring at a miner's console rather than by a parser.
var (
	// errUnauthenticated is returned to any method other than `login` arriving
	// on a connection that has not logged in. XMRig always logs in first, so a
	// miner seeing this has hit a reconnect race and will re-login.
	errUnauthenticated = &rpcError{-1, "unauthenticated"}
	// errInvalidMethod is a method this endpoint does not implement. Named
	// rather than silently ignored: a miner that gets no reply at all blocks
	// until its own timeout, and diagnosing that from the miner's end is
	// impossible.
	errInvalidMethod = &rpcError{-1, "invalid method"}
	// errBadRequest is a well-formed JSON-RPC envelope whose params this
	// endpoint could not read.
	errBadRequest = &rpcError{-1, "invalid request"}
	// errJobNotFound is the single most important code here. XMRig treats it
	// as "stale share" rather than "bad miner" — it does not count towards the
	// miner's own error budget and does not trigger a reconnect — which is
	// correct, because on a chain with a 30-second target every miner loses
	// this race routinely and a pool that punished it would be punishing
	// latency. The exact string matters: XMRig matches on it.
	errJobNotFound = &rpcError{-1, "Invalid job id"}
	// errLowDifficulty is a share whose nonce does not meet the job's target.
	// Unlike a stale share this IS the miner's fault — it means the miner is
	// computing a different function, or has been corrupted — and XMRig counts
	// it against its own error budget. It is also what earns ban score here;
	// see conn.penalise.
	errLowDifficulty = &rpcError{-1, "Low difficulty share"}
	// errDuplicateShare is the same (job, nonce) twice. Distinguished from a
	// low-difficulty share because the causes are unrelated: a duplicate is a
	// retransmit or a miner searching a space it already searched, and
	// punishing it as hard as a wrong hash would ban miners for a flaky
	// network.
	errDuplicateShare = &rpcError{-1, "Duplicate share"}
	// errUnauthorizedWorker is a login whose address this node will not pay
	// to. It is fatal for the connection: XMRig stops retrying on this
	// message, which is what an operator with a typo'd address needs to
	// happen rather than a silent hour of mining to nobody.
	errUnauthorizedWorker = &rpcError{-1, "Unauthenticated: invalid payout address"}
	// errInternal is a share this endpoint could not judge — a chain read that
	// failed, a template it could not reconstruct. It is deliberately NOT
	// errLowDifficulty: blaming the miner for the node's own fault would ban
	// honest miners during a local incident.
	errInternal = &rpcError{-1, "internal error"}
)

// loginParams is what a miner sends with `login`.
type loginParams struct {
	// Login is the payout address. On a Monero pool this is the wallet the
	// pool credits; here it is written directly into the block's EmissionAddr,
	// which makes this endpoint a solo-mining endpoint rather than a pool: the
	// miner that finds a block is paid by consensus, not by us.
	Login string `json:"login"`
	// Pass is ignored. Monero pools use it for worker naming and difficulty
	// hints ("x", "worker1", "d=5000"); this endpoint has one difficulty, the
	// network's, and no accounting to attach a worker name to. It is parsed
	// only so that its presence is not an error.
	Pass string `json:"pass"`
	// Agent is the miner's self-reported user agent, e.g. "XMRig/6.21.0". It
	// is logged and used for nothing else. A connection is never treated
	// differently on the strength of a string it chose itself.
	Agent string `json:"agent"`
	// Algo is the set of algorithms the miner offers. If it is present and
	// does not include this network's algorithm the login is refused, which
	// turns "this miner will mine noise forever" into "this miner says why it
	// cannot mine" at connect time.
	Algo []string `json:"algo"`
}

// submitParams is what a miner sends with `submit`.
type submitParams struct {
	// ID is the session id handed out by login, not the job id. XMRig sends
	// it on every submit; it is checked against the connection's own id so
	// that a confused proxy multiplexing several miners onto one socket is
	// caught rather than silently credited to the wrong session.
	ID string `json:"id"`
	// JobID names the cached template this nonce was searched against.
	JobID string `json:"job_id"`
	// Nonce is 4 bytes, little-endian, hex. This is the field that matters.
	Nonce string `json:"nonce"`
	// Result is, under rx/2, the miner's own COMMITMENT — not its digest,
	// despite the name. XMRig's field names are inverted at every layer here:
	// `randomx_calculate_commitment` writes over its input buffer in place, so
	// the buffer named for the hash ends up holding the commitment, and the
	// wire fields inherit the swap. The field named `commitment` carries the
	// raw digest.
	//
	// **Neither field is read.** The node recomputes the digest and forms the
	// commitment itself, because a share accepted on the miner's say-so is a
	// block this node would announce without ever having verified it. They are
	// declared so that the submit params parse cleanly and so that this
	// comment has somewhere to live — nothing in this package consults either,
	// and TestTheMinersOwnHashFieldsAreNotTrusted fails if that ever changes.
	Result string `json:"result"`
	// Commitment carries the raw RandomX digest. See Result for why the names
	// are the wrong way round and why neither is believed. Also unread.
	Commitment string `json:"commitment"`
}

// jobParams is a job, both as the `job` push notification's params and as the
// `job` member of a login result.
//
// Field names and types are XMRig's. In particular Height is a number and
// everything else is a hex string, and Target is the 8-byte little-endian form
// (see jobTargetHex).
type jobParams struct {
	Blob   string `json:"blob"`
	JobID  string `json:"job_id"`
	Target string `json:"target"`
	// Algo names the work function, in the identifier stock XMRig selects its
	// implementation by — "rx/2" for RandomX v2, which is what both real
	// networks declare. The key schedule differs from Monero's (pow.KeyFor
	// derives from height, not from a key block) but the schedule is not part
	// of the algorithm identifier, and a miner told "rx/2" initialises exactly
	// the right VM. It is resolved from the node's engine, never hardcoded:
	// see Server.algo.
	Algo string `json:"algo"`
	// Height is what XMRig displays and what it uses to decide whether a job
	// is newer than the one it holds.
	Height uint64 `json:"height"`
	// SeedHash keys the RandomX cache. XMRig re-initialises when it changes,
	// which costs seconds, so it must be exactly right and must not flap.
	SeedHash string `json:"seed_hash"`
	// NextSeedHash lets the miner build the next epoch's cache in the
	// background. See seedHashes.
	NextSeedHash string `json:"next_seed_hash"`
}

// loginResult is the reply to `login`.
type loginResult struct {
	// ID is the session id. XMRig echoes it on every submit.
	ID string `json:"id"`
	// Job is the first job, delivered inside the login reply rather than as a
	// separate push. A miner that had to wait for a push after logging in
	// would idle for however long the job timer takes to fire.
	Job jobParams `json:"job"`
	// Status is "OK". XMRig checks it.
	Status string `json:"status"`
	// Extensions advertise optional dialect features. This endpoint
	// deliberately advertises NONE: `algo` negotiation, `nicehash` nonce
	// partitioning and `keepalive` are all things a pool offers when it is
	// multiplexing many miners over shared work, and this endpoint is not.
	// The field is emitted as an empty list rather than omitted so that a
	// miner parsing it strictly does not fault on a missing key.
	Extensions []string `json:"extensions"`
}

// statusResult is the reply to `submit` and `keepalived`: `{"status":"OK"}`.
//
// It is the same shape for both on purpose. XMRig's submit path checks only
// that the reply is not an error and that status reads OK, and giving
// keepalived a different shape would be inventing dialect.
type statusResult struct {
	Status string `json:"status"`
}

// hexOf renders bytes as lowercase hex. Lowercase because that is what every
// pool emits and what miners' own string comparisons assume; a pool emitting
// uppercase hex has been observed to break job-change detection in miners that
// compare the blob as a string.
func hexOf(b []byte) string { return hex.EncodeToString(b) }
