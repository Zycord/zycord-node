package stratum

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/spec"
)

// These tests deliberately stand up NO chain, NO mempool, NO state tree and no
// proof-of-work engine beyond pow.Dev. That is the whole reason Assembler and
// Applier are interfaces (see their comments): the protocol layer — the
// dialect, the job cache, the ban score, the caps, the payout resolution — is
// the part of this package that has to be right, and it is testable with none
// of that machinery.
//
// Everything that touches the consensus work rule is behind seam.go, and the
// tests that pin it — the commitment comparison above all — assert against
// core/pow directly rather than against a second spelling of the rule kept
// here. That is deliberate: a test that re-derived the comparison would agree
// with a broken endpoint for exactly the same reason the endpoint was broken.

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeChain answers the three Applier questions from fixed values.
type fakeChain struct {
	mu       sync.Mutex
	params   *params.Params
	tip      types.Header
	applyErr error
	applied  []*types.Block
}

func (f *fakeChain) Params() *params.Params { return f.params }

func (f *fakeChain) Tip() types.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tip
}

func (f *fakeChain) Apply(b *types.Block) (*fold.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	f.applied = append(f.applied, b)
	return &fold.Result{}, nil
}

// fakeAssembler hands out candidate headers without touching a chain.
type fakeAssembler struct {
	mu     sync.Mutex
	height uint64
	target u256.U256
	err    error
	calls  int
}

func (f *fakeAssembler) Assemble() (*types.Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &types.Block{Header: types.Header{
		Version: types.HeaderVersion,
		Height:  f.height,
		Time:    1000 + uint64(f.calls),
		Target:  f.target,
	}}, nil
}

// fakeAnnouncer records what was gossiped.
type fakeAnnouncer struct {
	mu     sync.Mutex
	blocks []*types.Block
}

func (f *fakeAnnouncer) AnnounceBlock(b *types.Block) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocks = append(f.blocks, b)
}

func (f *fakeAnnouncer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.blocks)
}

// testEngine is pow.Dev's arithmetic under a name the endpoint will serve jobs
// for.
//
// The name is the whole point. Since the algorithm advertised to miners is
// derived from the ENGINE — a node does not choose what it verifies against,
// so it does not choose what it advertises — an engine calling itself
// dev-blake3 is correctly refused at login as something no Stratum miner
// implements. These tests exercise the endpoint against a network that IS
// mineable, so the engine has to say so, while keeping pow.Dev's cost: a real
// RandomX evaluation per share would make this suite take hours.
//
// The digest arithmetic being Dev's rather than RandomX's is irrelevant to
// everything tested here. Every assertion is about which QUANTITY is compared
// and how, never about what RandomX computes; the commitment is
// blake2b(PoWInput ‖ PoWHash) whatever produced PoWHash.
type testEngine struct{}

func (testEngine) Name() string { return randomxV2Name }

func (testEngine) Hash(key types.Hash, input []byte) types.Hash {
	return pow.Dev{}.Hash(key, input)
}

// testParams returns a real parameter set, because seedHashes and pow.KeyFor
// read enough of one that a hand-built struct would be asserting against a
// network that does not exist.
func testParams(t *testing.T) *params.Params {
	t.Helper()
	return spec.Devnet()
}

// harness is a running Server on an ephemeral port plus the fakes behind it.
type harness struct {
	srv  *Server
	asm  *fakeAssembler
	ch   *fakeChain
	ann  *fakeAnnouncer
	addr string
}

func newHarness(t *testing.T, tune func(*Config)) *harness {
	t.Helper()
	p := testParams(t)
	// The easiest target expressible, so that a test wanting a share to become
	// a block does not have to mine for one.
	//
	// NOT p.MaxTarget, and the reason is worth recording because it was the
	// obvious first choice and it is wrong. Devnet's MaxTarget is 2^251, whose
	// truncation is 2^59 — so under a uniform digest only one nonce in 32
	// meets the JOB target, and a test that submitted a fixed nonce and
	// expected a block failed about ninety-seven times in a hundred. That is
	// not a defect in truncateTarget; it is the truncation being correct and
	// the test having confused "the easiest a network declares" with "easy".
	// An all-ones target truncates to 2^64-1, under which every digest passes,
	// which is what a fixed-nonce test needs.
	asm := &fakeAssembler{height: 1, target: easiestTarget()}
	ch := &fakeChain{params: p, tip: types.Header{Height: 0}}
	ann := &fakeAnnouncer{}

	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	// A payout for logins that do not name one. Version 0x02, because that is
	// what resolvePayout requires and the test must not assert against a value
	// the production path would refuse.
	cfg.Payout = testAddress(0x02, 0xaa)
	if tune != nil {
		tune(&cfg)
	}
	srv := New(cfg, asm, ch, testEngine{})
	srv.SetAnnouncer(ann)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })
	return &harness{srv: srv, asm: asm, ch: ch, ann: ann, addr: srv.Addr().String()}
}

// onlyConnPayout reads back the payout the single live connection resolved.
//
// A test-only reader, and it exists because the payout is deliberately NOT on
// the wire: it goes into the header the miner is about to hash, which is the
// whole point — a solo endpoint that echoed the address back would be
// asserting what it was told rather than what it will pay. The only honest
// place to read it is the connection's own state.
func (s *Server) onlyConnPayout() (types.Address, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) != 1 {
		return types.Address{}, false
	}
	for c := range s.conns {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.payout, true
	}
	return types.Address{}, false
}

// easiestTarget is 2^256-1: every digest meets it, at both the job target and
// the full 256-bit check. It is not a target any network declares — MaxTarget
// is far below it — and it is used only so that a test asserting the SHARE
// PATH does not also have to search for a nonce.
func easiestTarget() u256.U256 {
	var b [32]byte
	for i := range b {
		b[i] = 0xff
	}
	return u256.FromBytes(b)
}

func testAddress(version, fill byte) types.Address {
	var a types.Address
	for i := range a {
		a[i] = fill
	}
	a[0] = version
	return a
}

// client is a miner-side connection that speaks the dialect well enough to
// exercise the server.
type client struct {
	t  *testing.T
	nc net.Conn
	rd *bufio.Reader
	id int
}

func (h *harness) dial(t *testing.T) *client {
	t.Helper()
	nc, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	return &client{t: t, nc: nc, rd: bufio.NewReader(nc)}
}

// call sends a request and reads until a reply with the matching id arrives,
// skipping any `job` notification that overtakes it. Skipping rather than
// failing is what a real miner does and is what makes these tests independent
// of the push timing.
func (c *client) call(method string, params any) response {
	c.t.Helper()
	c.id++
	body, err := json.Marshal(params)
	if err != nil {
		c.t.Fatalf("marshal params: %v", err)
	}
	line, err := json.Marshal(map[string]any{
		"id": c.id, "jsonrpc": "2.0", "method": method,
		"params": json.RawMessage(body),
	})
	if err != nil {
		c.t.Fatalf("marshal request: %v", err)
	}
	_ = c.nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.nc.Write(append(line, '\n')); err != nil {
		c.t.Fatalf("write: %v", err)
	}
	for {
		var r response
		raw := c.readLine()
		if err := json.Unmarshal(raw, &r); err != nil {
			c.t.Fatalf("decoding %q: %v", raw, err)
		}
		if len(r.ID) == 0 || string(r.ID) == "null" {
			// A notification, or an error reply to something unparseable.
			// Notifications carry no id at all.
			var n struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(raw, &n)
			if n.Method != "" {
				continue
			}
		}
		return r
	}
}

func (c *client) readLine() []byte {
	c.t.Helper()
	_ = c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := c.rd.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return raw
}

// writeRaw sends bytes verbatim, for the malformed-input tests.
func (c *client) writeRaw(s string) {
	c.t.Helper()
	_ = c.nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.nc.Write([]byte(s)); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// login performs a login and returns the result.
func (c *client) login(addr string) loginResult {
	c.t.Helper()
	r := c.call("login", loginParams{Login: addr, Pass: "x", Agent: "XMRig/6.26.0", Algo: []string{"rx/2"}})
	if r.Error != nil {
		c.t.Fatalf("login: %v", r.Error)
	}
	var out loginResult
	remarshal(c.t, r.Result, &out)
	return out
}

// remarshal moves a decoded `any` into a typed struct. The response type
// carries Result as `any` because it is the outbound shape; a client decoding
// it gets a map, and this is the shortest honest way to type it.
func remarshal(t *testing.T, from any, into any) {
	t.Helper()
	b, err := json.Marshal(from)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("remarshal into %T: %v", into, err)
	}
}

// ---------------------------------------------------------------------------
// The dialect
// ---------------------------------------------------------------------------

// A login must produce everything XMRig needs to start hashing in ONE reply.
// A miner that has to make a second call before its first hash is a miner that
// idles for a round trip on every reconnect, and some forks simply do not make
// the second call.
func TestLoginReturnsACompleteJob(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")

	if res.Status != "OK" {
		t.Errorf("status = %q, want OK", res.Status)
	}
	if res.ID == "" {
		t.Error("no session id: XMRig echoes it on every submit and cannot proceed without one")
	}
	j := res.Job
	if j.Algo != "rx/2" {
		t.Errorf("algo = %q, want rx/2: the advertised algorithm follows the "+
			"network's engine, and both real networks declare randomx-v2", j.Algo)
	}
	if j.JobID == "" {
		t.Error("no job id: a submit could not name the template it was searched against")
	}
	if j.Height != 1 {
		t.Errorf("height = %d, want 1", j.Height)
	}
	blob, err := hex.DecodeString(j.Blob)
	if err != nil {
		t.Fatalf("blob is not hex: %v", err)
	}
	// The single most important assertion in this file. XMRig writes its nonce
	// at offset 39 and refuses a blob shorter than 43 bytes; a blob of any
	// other length is one no stock miner can mine.
	if len(blob) != types.PoWInputSize {
		t.Errorf("blob is %d bytes, want %d — stock XMRig hardcodes a 4-byte nonce "+
			"at offset %d and will not mine anything shorter",
			len(blob), types.PoWInputSize, types.PoWInputNonceOffset)
	}
	// The seven reserved bytes, which the blob layout requires to be zero. The
	// endpoint emits them as such so that a miner's first hash is over exactly
	// the bytes the node will later re-derive.
	for i := 32; i < types.PoWInputNonceOffset; i++ {
		if blob[i] != 0 {
			t.Errorf("blob[%d] = %#x, want 0: bytes 32..38 are the reserved zero pad", i, blob[i])
		}
	}
	target, err := hex.DecodeString(j.Target)
	if err != nil || len(target) != 8 {
		t.Errorf("target = %q, want 8 bytes of hex (the little-endian 64-bit form)", j.Target)
	}
	if len(j.SeedHash) != 64 {
		t.Errorf("seed_hash = %q, want a 32-byte hex hash", j.SeedHash)
	}
	if len(j.NextSeedHash) != 64 {
		t.Errorf("next_seed_hash = %q, want a 32-byte hex hash", j.NextSeedHash)
	}
	if j.SeedHash == j.NextSeedHash {
		// Not a hard requirement of the dialect, but on devnet parameters the
		// next epoch's key genuinely differs, and a next_seed_hash that echoed
		// the current one would mean seedHashes never crossed a boundary —
		// which is the failure that makes a miner stall for tens of seconds at
		// every rotation.
		t.Error("next_seed_hash equals seed_hash: seedHashes did not cross an epoch boundary")
	}
}

// Every method other than login must refuse an un-logged-in connection.
// XMRig always logs in first, so a miner that sees this has hit a reconnect
// race — but a node that served work to a connection that never named a payout
// address would be mining to whatever the zero value happens to be.
func TestMethodsRequireLogin(t *testing.T) {
	for _, method := range []string{"getjob", "submit", "keepalived"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, nil)
			c := h.dial(t)
			r := c.call(method, map[string]any{})
			if r.Error == nil {
				t.Fatalf("%s before login was accepted", method)
			}
			if r.Error.Message != errUnauthenticated.Message {
				t.Errorf("error = %q, want %q", r.Error.Message, errUnauthenticated.Message)
			}
		})
	}
}

// getjob must hand out a FRESH template, not the cached one. A miner calls it
// when it has nothing left to do; returning what it already holds leaves it
// idle until the refresh timer fires.
func TestGetJobBuildsAFreshTemplate(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	first := c.login("").Job

	r := c.call("getjob", map[string]any{})
	if r.Error != nil {
		t.Fatalf("getjob: %v", r.Error)
	}
	var second jobParams
	remarshal(t, r.Result, &second)

	if second.JobID == first.JobID {
		t.Error("getjob returned the job the miner already holds; it would idle until the timer fires")
	}
	if second.Blob == first.Blob {
		t.Error("getjob returned an identical blob: the template was not rebuilt")
	}
}

// keepalived must be answered, and must not require a job or touch the chain.
// It is the method a miner uses to hold a connection open across a quiet
// period, and a node that failed it would disconnect every idle miner.
func TestKeepalivedIsAnswered(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	c.login("")
	before := h.asm.calls

	r := c.call("keepalived", map[string]any{"id": "ignored"})
	if r.Error != nil {
		t.Fatalf("keepalived: %v", r.Error)
	}
	var out statusResult
	remarshal(t, r.Result, &out)
	if out.Status == "" {
		t.Error("keepalived returned no status")
	}
	if h.asm.calls != before {
		t.Errorf("keepalived assembled %d templates; it must touch no chain state",
			h.asm.calls-before)
	}
}

// An unknown method is declined without ending the connection and without ban
// score. A miner speaking a newer dialect sends things this endpoint does not
// implement, and disconnecting it would be refusing a client that is behaving.
func TestUnknownMethodIsDeclinedNotPunished(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	c.login("")
	for i := 0; i < 20; i++ {
		r := c.call("mining.subscribe", []string{})
		if r.Error == nil || r.Error.Message != errInvalidMethod.Message {
			t.Fatalf("call %d: error = %v, want %q", i, r.Error, errInvalidMethod.Message)
		}
	}
	// Still alive after twenty of them, which is well past MaxBanScore had
	// they been scored.
	if r := c.call("keepalived", map[string]any{}); r.Error != nil {
		t.Fatalf("connection died after unknown methods: %v", r.Error)
	}
}

// A reply's id must be byte-identical to the request's. The dialect does not
// agree with itself about whether an id is a number or a string, and a miner
// drops a reply whose id it does not recognise.
func TestReplyEchoesTheRequestIDVerbatim(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	c.writeRaw(`{"id":"a-string-id","jsonrpc":"2.0","method":"login","params":{"login":"","pass":"x"}}` + "\n")
	for {
		raw := c.readLine()
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("decoding %q: %v", raw, err)
		}
		if probe.Method != "" {
			continue // a job push
		}
		if string(probe.ID) != `"a-string-id"` {
			t.Errorf("id = %s, want \"a-string-id\" echoed verbatim", probe.ID)
		}
		return
	}
}

// ---------------------------------------------------------------------------
// Payout resolution
// ---------------------------------------------------------------------------

func TestPayoutResolution(t *testing.T) {
	valid := testAddress(crypto.AddrVersionPersistent, 0x11)
	oneShot := testAddress(crypto.AddrVersionOneShot, 0x22)
	fallback := testAddress(crypto.AddrVersionPersistent, 0xaa)

	cases := []struct {
		name  string
		login string
		want  types.Address
		// refused says the login must be rejected outright rather than fall
		// back. See resolvePayout for why the empty and malformed cases differ.
		refused bool
	}{
		{name: "empty falls back to the node's payout", login: "", want: fallback},
		{name: "the placeholder x falls back", login: "x", want: fallback},
		{name: "a valid address wins over the fallback", login: hex.EncodeToString(valid[:]), want: valid},
		{name: "a 0x prefix is accepted", login: "0x" + hex.EncodeToString(valid[:]), want: valid},
		{
			name:  "a worker suffix is stripped, not refused",
			login: hex.EncodeToString(valid[:]) + ".rig01",
			want:  valid,
		},
		{
			name:    "a one-shot address is refused, never silently redirected",
			login:   hex.EncodeToString(oneShot[:]),
			refused: true,
		},
		{name: "garbage is refused", login: "not-an-address", refused: true},
		{name: "a short address is refused", login: "aabbcc", refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			c := h.dial(t)
			r := c.call("login", loginParams{Login: tc.login, Pass: "x"})
			if tc.refused {
				if r.Error == nil {
					t.Fatal("login was accepted; a specified-but-invalid address must be " +
						"refused rather than quietly paid to somebody else")
				}
				return
			}
			if r.Error != nil {
				t.Fatalf("login: %v", r.Error)
			}
			// The payout is not on the wire — it is in the header the miner is
			// about to hash — so it is read back from the server's own
			// connection state.
			got, ok := h.srv.onlyConnPayout()
			if !ok {
				t.Fatal("no live connection")
			}
			if got != tc.want {
				t.Errorf("payout = %x, want %x", got[:8], tc.want[:8])
			}
		})
	}
}

// With no --payout and no login address there is nothing to pay, and the login
// must be refused. Mining to the zero address is not a burn: it is a cell
// nobody holds the key to, and every reward paid into it is gone.
func TestLoginWithNoAddressAnywhereIsRefused(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.Payout = types.Address{} })
	c := h.dial(t)
	r := c.call("login", loginParams{Login: "x"})
	if r.Error == nil {
		t.Fatal("login accepted with no payout address anywhere; blocks would pay the zero address")
	}
}

// A miner that does not offer this network's algorithm is refused at login
// rather than left to mine noise. The refusal is one line in the operator's
// console instead of an hour of silent rejection.
//
// Note that rx/0 is among the algorithms REFUSED here, which is the whole
// correction: a v1 miner against an rx/2 network computes a different function,
// and an endpoint that accepted it would be handing it jobs it cannot win.
func TestAMinerOfferingTheWrongAlgorithmIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	r := c.call("login", loginParams{Login: "x", Algo: []string{"rx/0", "cn/r"}})
	if r.Error == nil {
		t.Fatal("a miner offering no rx/2 was accepted")
	}
	if !strings.Contains(r.Error.Message, "rx/2") {
		t.Errorf("error = %q, want it to name rx/2 so the operator can see why", r.Error.Message)
	}
}

// A correctly configured stock rx/2 miner must be ACCEPTED. This is the
// regression the review found: the endpoint advertised rx/0 and refused every
// stock miner on both real networks at connect.
func TestAStockRXTwoMinerIsAccepted(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	r := c.call("login", loginParams{
		Login: "x", Pass: "x", Agent: "XMRig/6.26.0", Algo: []string{"rx/2"},
	})
	if r.Error != nil {
		t.Fatalf("a stock rx/2 miner was refused: %v", r.Error)
	}
}

// An ABSENT algo list is accepted. Older miners and some proxies do not send
// one, and refusing on a field's absence would refuse clients that work.
func TestAnAbsentAlgoListIsAccepted(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	r := c.call("login", loginParams{Login: "x"})
	if r.Error != nil {
		t.Fatalf("a login without an algo list was refused: %v", r.Error)
	}
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------

// A submit naming a job the connection never held is a STALE share, not a bad
// one: it must be answered with the code XMRig reads as stale, and it must not
// cost ban score. Scoring it would ban miners for network latency, hardest
// exactly when the chain is busiest.
func TestAnUnknownJobIsStaleNotPunished(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")
	for i := 0; i < 20; i++ {
		r := c.call("submit", submitParams{
			ID: res.ID, JobID: "deadbeefdeadbeef", Nonce: "00000000",
		})
		if r.Error == nil {
			t.Fatalf("call %d: a submit against an unknown job was accepted", i)
		}
		if r.Error.Message != errJobNotFound.Message {
			t.Fatalf("call %d: error = %q, want %q — XMRig keys its stale-share "+
				"handling off this exact string", i, r.Error.Message, errJobNotFound.Message)
		}
	}
	if r := c.call("keepalived", map[string]any{}); r.Error != nil {
		t.Fatalf("connection was closed by stale shares: %v", r.Error)
	}
}

// The same (job, nonce) twice is a duplicate, distinguished from a bad share
// because the causes are unrelated: a duplicate is a retransmit, and punishing
// it as hard as a wrong hash would ban miners for a flaky network.
func TestADuplicateShareIsNamedAsOne(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")

	first := c.call("submit", submitParams{ID: res.ID, JobID: res.Job.JobID, Nonce: "01000000"})
	if first.Error != nil {
		t.Fatalf("first submit: %v", first.Error)
	}
	second := c.call("submit", submitParams{ID: res.ID, JobID: res.Job.JobID, Nonce: "01000000"})
	if second.Error == nil {
		t.Fatal("a repeated (job, nonce) was accepted twice")
	}
	if second.Error.Message != errDuplicateShare.Message {
		t.Errorf("error = %q, want %q", second.Error.Message, errDuplicateShare.Message)
	}
}

// A submit carrying the wrong session id is refused. On an honest connection
// this cannot happen — XMRig echoes what login gave it — so it is a proxy
// multiplexing sessions it does not understand, or a probe.
func TestASubmitWithTheWrongSessionIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")
	r := c.call("submit", submitParams{ID: "somebody-elses-session", JobID: res.Job.JobID, Nonce: "00000000"})
	if r.Error == nil {
		t.Fatal("a submit with a foreign session id was accepted")
	}
}

// A nonce that is not exactly eight hex characters is refused rather than
// padded. Accepting a short one would mean this node and the miner disagree
// about which nonce was searched, and the miner would have no way to see why
// its shares are rejected.
func TestAMalformedNonceIsRefused(t *testing.T) {
	for _, nonce := range []string{"", "1", "0102030", "010203040", "zzzzzzzz"} {
		t.Run(fmt.Sprintf("%q", nonce), func(t *testing.T) {
			h := newHarness(t, nil)
			c := h.dial(t)
			res := c.login("")
			r := c.call("submit", submitParams{ID: res.ID, JobID: res.Job.JobID, Nonce: nonce})
			if r.Error == nil {
				t.Fatalf("nonce %q was accepted", nonce)
			}
		})
	}
}

// A share that meets the target becomes a block: applied to this node's chain
// and announced to peers. Under pow.Dev with MaxTarget every nonce solves, so
// this exercises the whole path without searching.
func TestAWinningShareBecomesABlock(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")

	r := c.call("submit", submitParams{ID: res.ID, JobID: res.Job.JobID, Nonce: "07000000"})
	if r.Error != nil {
		t.Fatalf("submit: %v", r.Error)
	}

	h.ch.mu.Lock()
	applied := len(h.ch.applied)
	var hdr types.Header
	if applied > 0 {
		hdr = h.ch.applied[0].Header
	}
	h.ch.mu.Unlock()
	if applied != 1 {
		t.Fatalf("applied %d blocks, want 1", applied)
	}
	if h.ann.count() != 1 {
		t.Errorf("announced %d blocks, want 1: a block nobody is told about is a self-fork",
			h.ann.count())
	}
	// The nonce the miner sent, in the header the node applied. A mismatch
	// here means the node verified one nonce and committed another.
	if hdr.PoW.Nonce != 7 {
		t.Errorf("applied header carries nonce %d, want 7", hdr.PoW.Nonce)
	}
	// The address the miner logged in with, in the block that pays.
	if hdr.EmissionAddr != h.srv.cfg.Payout {
		t.Errorf("emission address = %x, want the resolved payout %x",
			hdr.EmissionAddr[:8], h.srv.cfg.Payout[:8])
	}
}

// A block that loses the race to a new tip is a STALE share from the miner's
// point of view — it did everything right — so it must be reported with the
// stale code and must not cost the miner ban score.
func TestABlockThatLosesTheRaceIsReportedAsStale(t *testing.T) {
	h := newHarness(t, nil)
	h.ch.mu.Lock()
	h.ch.applyErr = chain.ErrWrongParent
	h.ch.mu.Unlock()

	c := h.dial(t)
	res := c.login("")
	r := c.call("submit", submitParams{ID: res.ID, JobID: res.Job.JobID, Nonce: "09000000"})
	if r.Error == nil {
		t.Fatal("a block Apply refused was reported as accepted")
	}
	if r.Error.Message != errJobNotFound.Message {
		t.Errorf("error = %q, want %q (the stale code)", r.Error.Message, errJobNotFound.Message)
	}
	if h.ann.count() != 0 {
		t.Error("a block that failed to apply was announced anyway")
	}
}

// A node-side failure to apply is the NODE's fault and must be reported as
// such. Blaming the miner would ban honest miners during a local storage
// incident — exactly when an operator can least afford to lose them.
func TestANodeSideApplyFailureDoesNotBlameTheMiner(t *testing.T) {
	h := newHarness(t, nil)
	h.ch.mu.Lock()
	h.ch.applyErr = errors.New("the disk is on fire")
	h.ch.mu.Unlock()

	c := h.dial(t)
	res := c.login("")
	for i := 0; i < 20; i++ {
		r := c.call("submit", submitParams{
			ID: res.ID, JobID: res.Job.JobID, Nonce: fmt.Sprintf("%02x000000", i),
		})
		if r.Error == nil || r.Error.Message != errInternal.Message {
			t.Fatalf("call %d: error = %v, want %q", i, r.Error, errInternal.Message)
		}
	}
	if r := c.call("keepalived", map[string]any{}); r.Error != nil {
		t.Fatalf("the miner was disconnected for the node's own fault: %v", r.Error)
	}
}

// ---------------------------------------------------------------------------
// Hygiene: caps, ban score, keepalive
// ---------------------------------------------------------------------------

// The connection cap is enforced by CLOSING the extra socket, not by replying.
// See Server.admit for why a refusal carries no message.
func TestTheConnectionCapIsEnforced(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.MaxConns = 2 })
	for i := 0; i < 2; i++ {
		c := h.dial(t)
		c.login("")
	}
	waitFor(t, func() bool { return h.srv.ConnCount() == 2 })

	extra, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = extra.Close() }()
	// The server closes without writing, so the first read returns EOF.
	_ = extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection past the cap was served")
	}
	if got := h.srv.ConnCount(); got != 2 {
		t.Errorf("ConnCount = %d, want 2: the refused connection was counted", got)
	}
}

// Ban score closes a connection that keeps sending things this endpoint cannot
// parse. The score is what stops a peer spending this node's CPU indefinitely.
func TestBanScoreClosesAConnectionSendingGarbage(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.MaxBanScore = 4 })
	c := h.dial(t)
	// Two points each, so three lines is past a cap of four.
	for i := 0; i < 3; i++ {
		c.writeRaw("this is not json at all\n")
	}
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
}

// A share that does not meet the job target is the miner's fault and is
// scored: it means the miner is computing a different function, and every
// subsequent share it sends costs this node a verification for nothing.
func TestABadShareIsScored(t *testing.T) {
	// A target of zero on the wire means no digest can ever meet it, which
	// makes every submitted share a bad one without having to construct a
	// digest by hand. truncateTarget clamps to 1, so this is the hardest
	// expressible job rather than an impossible one — and under pow.Dev a
	// digest below 1 is unreachable.
	// A cap of 6 against 2 points a share: the first two shares are answered,
	// the third reaches the cap. The loop stops at two so that the assertion
	// on the ERROR CODE is separate from the assertion on the DISCONNECT —
	// asserting both against the share that closes the socket would leave the
	// test racing the close, which is how it first failed.
	h := newHarness(t, func(cfg *Config) { cfg.MaxBanScore = 6 })
	h.asm.mu.Lock()
	h.asm.target = u256.FromUint64(1)
	h.asm.mu.Unlock()

	c := h.dial(t)
	res := c.login("")
	for i := 0; i < 2; i++ {
		r := c.call("submit", submitParams{
			ID: res.ID, JobID: res.Job.JobID, Nonce: fmt.Sprintf("%02x000000", i),
		})
		if r.Error == nil {
			t.Fatalf("call %d: a share below the job target was accepted", i)
		}
		if r.Error.Message != errLowDifficulty.Message {
			t.Fatalf("call %d: error = %q, want %q — XMRig counts this against its "+
				"own error budget", i, r.Error.Message, errLowDifficulty.Message)
		}
	}
	// Still connected at 4 of 6.
	if h.srv.ConnCount() != 1 {
		t.Fatal("the connection was closed before the ban score reached its cap")
	}
	// The third crosses it. Written raw rather than through call, because the
	// server closes the socket and the reply may never arrive — which is the
	// behaviour being asserted, not a flake.
	body, err := json.Marshal(submitParams{ID: res.ID, JobID: res.Job.JobID, Nonce: "ff000000"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c.writeRaw(`{"id":99,"jsonrpc":"2.0","method":"submit","params":` + string(body) + "}\n")
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
}

// A connection that stops talking is reaped. The `keepalived` method exists so
// a miner with nothing to submit can prove it is there, so silence past the
// timeout is a socket whose far end is gone — or one held open to occupy a
// slot in MaxConns.
func TestTheKeepaliveTimeoutReapsASilentConnection(t *testing.T) {
	// A frozen clock the test advances by hand, so the reaper's decision is
	// tested rather than the scheduler's. The tick interval is what drives the
	// check, so it is short; the timeout is what is being asserted.
	var clk fakeClock
	clk.set(time.Unix(1_700_000_000, 0))
	h := newHarness(t, func(cfg *Config) {
		cfg.Now = clk.now
		cfg.JobRefresh = 10 * time.Millisecond
		cfg.KeepaliveTimeout = time.Minute
	})
	c := h.dial(t)
	c.login("")
	waitFor(t, func() bool { return h.srv.ConnCount() == 1 })

	// Still inside the timeout: the connection survives several ticks.
	clk.advance(30 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if h.srv.ConnCount() != 1 {
		t.Fatal("a connection was reaped while still inside the keepalive timeout")
	}

	clk.advance(2 * time.Minute)
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
}

// An oversized line is bounded rather than buffered. Without the bound a peer
// could make this node buffer without limit by opening a socket and never
// sending a newline.
func TestAnOversizedLineDoesNotGrowWithoutBound(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	c.writeRaw(`{"id":1,"method":"login","params":{"login":"` +
		strings.Repeat("a", maxLineBytes*2) + `"}}` + "\n")
	// The scanner errors and the reader exits; the connection is dropped.
	waitFor(t, func() bool { return h.srv.ConnCount() == 0 })
}

// Close must join every goroutine it owns before returning, so that a caller's
// `defer chain.Close()` cannot land under a live reader. It is the same
// argument cmd/zycordd's teardown makes about the heartbeat.
func TestCloseJoinsItsGoroutines(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < 3; i++ {
		c := h.dial(t)
		c.login("")
	}
	waitFor(t, func() bool { return h.srv.ConnCount() == 3 })
	if err := h.srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := h.srv.ConnCount(); got != 0 {
		t.Errorf("ConnCount after Close = %d, want 0", got)
	}
	// Idempotent: the wiring's defer and an operator's explicit stop can both
	// reach it.
	if err := h.srv.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

// A head change pushes a fresh job to every connected miner. Without it a
// miner keeps hashing a template whose parent is gone, and every share it
// finds is a block Chain.Apply refuses.
func TestOnHeadPushesToEveryConnection(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		// Long enough that the timer cannot be the thing that produced the
		// push this test is asserting.
		cfg.JobRefresh = time.Hour
	})
	clients := make([]*client, 3)
	held := make([]string, 3)
	for i := range clients {
		clients[i] = h.dial(t)
		held[i] = clients[i].login("").Job.JobID
	}
	waitFor(t, func() bool { return h.srv.ConnCount() == 3 })

	h.srv.OnHead()

	for i, c := range clients {
		var n struct {
			Method string    `json:"method"`
			Params jobParams `json:"params"`
		}
		raw := c.readLine()
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("client %d: decoding %q: %v", i, raw, err)
		}
		if n.Method != "job" {
			t.Fatalf("client %d: pushed method %q, want job", i, n.Method)
		}
		if n.Params.JobID == held[i] {
			t.Errorf("client %d: the pushed job is the one it already holds", i)
		}
	}
}

// The endpoint must never build a RandomX dataset to verify a share. Doing so
// would take two gigabytes from the miner on a machine whose whole purpose is
// to give that RAM to XMRig. The guarantee is structural — the Server holds a
// pow.Engine and never asserts it to pow.HotKeyEngine — and this test asserts
// the negative rather than trusting the comment.
func TestVerificationNeverFlipsOnTheFullDataset(t *testing.T) {
	h := newHarness(t, nil)
	hot := &hotSpy{}
	h.srv.engine = hot

	c := h.dial(t)
	res := c.login("")
	for i := 0; i < 5; i++ {
		c.call("submit", submitParams{
			ID: res.ID, JobID: res.Job.JobID, Nonce: fmt.Sprintf("%02x000000", i),
		})
	}
	if n := hot.mineOnCalls(); n != 0 {
		t.Errorf("MineOn was called %d times: verification asked the engine for its "+
			"fast representation, which on RandomX is a ~2 GiB dataset fill on a "+
			"machine whose RAM belongs to the miner", n)
	}
	if hot.hashCalls() == 0 {
		t.Error("no hashes were computed: the test did not reach the verification path")
	}
}

// hotSpy is a pow.HotKeyEngine that records whether anything asked it to build
// its fast representation.
type hotSpy struct {
	mu     sync.Mutex
	mineOn int
	hashes int
}

// Name reports an engine the endpoint will serve jobs for. A spy that named
// itself would be refused at login as unmineable and would never reach the
// verification path this test exists to watch.
func (h *hotSpy) Name() string { return randomxV2Name }

func (h *hotSpy) Hash(key types.Hash, input []byte) types.Hash {
	h.mu.Lock()
	h.hashes++
	h.mu.Unlock()
	return pow.Dev{}.Hash(key, input)
}

func (h *hotSpy) MineOn(types.Hash) {
	h.mu.Lock()
	h.mineOn++
	h.mu.Unlock()
}

func (h *hotSpy) mineOnCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mineOn
}

func (h *hotSpy) hashCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hashes
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

// The job-target truncation, checked at the boundaries that matter rather than
// only in the middle. It is unchanged by the move to a commitment-based work
// check: what moved is which 32 bytes the miner reads, not how it reads them.
func TestTruncateTarget(t *testing.T) {
	pow2 := func(n uint) u256.U256 {
		var b [32]byte
		b[31-n/8] = 1 << (n % 8)
		return u256.FromBytes(b)
	}
	cases := []struct {
		name   string
		target u256.U256
		want   uint64
	}{
		{
			name:   "a target below 2^192 clamps to 1, never to 0",
			target: u256.FromUint64(1),
			want:   1,
		},
		{
			// XMRig computes its displayed difficulty as 2^64/t64. A zero
			// target divides by zero there.
			name:   "zero clamps to 1 rather than dividing a miner by zero",
			target: u256.U256{},
			want:   1,
		},
		{
			name:   "exactly 2^192 truncates to 1",
			target: pow2(192),
			want:   1,
		},
		{
			// The +1 is what makes the truncation inclusive of the boundary.
			// Without it this case gives 1 and the one below gives 1 too, and
			// the two are a factor of two apart in difficulty.
			name:   "2^193 truncates to 2",
			target: pow2(193),
			want:   2,
		},
		{
			name:   "2^255 truncates to 2^63",
			target: pow2(255),
			want:   1 << 63,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncateTarget(tc.target); got != tc.want {
				t.Errorf("truncateTarget = %d, want %d", got, tc.want)
			}
		})
	}
}

// The wire form of a job target is EIGHT little-endian hex bytes. Four is the
// compact form some pools emit and it cannot express a target below 2^32,
// which is most of the useful range for a chain a CPU can mine.
func TestJobTargetIsEightLittleEndianBytes(t *testing.T) {
	got := jobTargetHex(0x0102030405060708)
	const want = "0807060504030201"
	if got != want {
		t.Errorf("jobTargetHex = %q, want %q", got, want)
	}
	if len(got) != 16 {
		t.Errorf("target is %d hex characters, want 16 (eight bytes)", len(got))
	}
}

// The blob's shape, asserted directly against the layout XMRig hardcodes.
func TestBlobShape(t *testing.T) {
	h := types.Header{Version: types.HeaderVersion, Height: 7}
	blob := blobFor(h)
	if len(blob) != 43 {
		t.Fatalf("blob is %d bytes, want 43", len(blob))
	}
	seed := h.PoWSeed()
	if string(blob[:32]) != string(seed[:]) {
		t.Error("blob[0:32] is not the header's PoWSeed")
	}
	for i := 32; i < 39; i++ {
		if blob[i] != 0 {
			t.Errorf("blob[%d] = %#x, want 0", i, blob[i])
		}
	}
	for i := 39; i < 43; i++ {
		if blob[i] != 0 {
			t.Errorf("blob[%d] = %#x: the nonce bytes must ship zeroed so that two "+
				"jobs with the same seed compare equal", i, blob[i])
		}
	}
}

// The nonce round-trips through the wire form XMRig actually sends.
func TestNonceRoundTrip(t *testing.T) {
	var nonce uint32 = 0x0badf00d
	wire := "0df0ad0b" // little-endian, the way XMRig writes it
	parsed, ok := parseNonce(wire)
	if !ok || parsed != nonce {
		t.Errorf("parseNonce(%q) = %#x, %v; want %#x, true", wire, parsed, ok, nonce)
	}
	// And into the hashing input, at the offset consensus fixes. This is
	// PoWInput rather than blobFor: the SERVED blob always carries a zero
	// nonce (blobFor clears it, deliberately — see there), so the round trip
	// that matters is the one through the bytes actually hashed.
	h := types.Header{Height: 3}
	h.PoW.Nonce = nonce
	in := h.PoWInput()
	got := binary.LittleEndian.Uint32(in[types.PoWInputNonceOffset : types.PoWInputNonceOffset+4])
	if got != nonce {
		t.Errorf("PoWInput nonce = %#x, want %#x", got, nonce)
	}
	// And the served blob for that same header is zeroed regardless.
	blob := blobFor(h)
	if v := binary.LittleEndian.Uint32(blob[types.PoWInputNonceOffset : types.PoWInputNonceOffset+4]); v != 0 {
		t.Errorf("served blob nonce = %#x, want 0: blobFor must clear it whatever the "+
			"header carries, or a stock miner latches into nicehash mode", v)
	}
}

// THE CENTRAL ASSERTION OF THIS PACKAGE.
//
// The quantity the endpoint filters shares on must be the COMMITMENT, which is
// what stock XMRig filters on under rx/2 — never the raw RandomX digest. The
// two are independent uniform values, so an endpoint comparing the digest
// accepts a set of nonces DISJOINT from the set the miner sends: every honest
// share scored, the miner banned after five, at a healthy reported hashrate,
// with nothing in the protocol naming the cause.
//
// This test fails loudly if the comparison ever reverts to the digest, which
// is the mutation the review asked for by name.
func TestTheShareFilterComparesTheCommitmentAndNotTheDigest(t *testing.T) {
	p := testParams(t)
	h := types.Header{Version: types.HeaderVersion, Height: 5, Target: p.MaxTarget}
	h.PoW.Nonce = 42
	h.PoWHash = testEngine{}.Hash(pow.KeyFor(h.Height, p), h.PoWInput())

	commitment := pow.Commitment(h)
	wantValue := binary.LittleEndian.Uint64(commitment[len(commitment)-8:])
	if got := jobTargetValue(h); got != wantValue {
		t.Fatalf("jobTargetValue = %#x, want the commitment's top limb %#x", got, wantValue)
	}

	// And it must NOT be the digest's top limb. If these ever coincide the
	// fixture is degenerate and the test proves nothing, so that is checked
	// rather than assumed.
	digestValue := binary.LittleEndian.Uint64(h.PoWHash[len(h.PoWHash)-8:])
	if digestValue == wantValue {
		t.Fatal("the digest and the commitment have the same top limb; this fixture " +
			"cannot distinguish the two comparisons")
	}
	if jobTargetValue(h) == digestValue {
		t.Error("the share filter is comparing the RAW DIGEST. Stock XMRig filters on " +
			"the commitment under rx/2, so this endpoint would accept a disjoint set " +
			"of nonces: every honest share rejected, the miner banned, at a healthy " +
			"hashrate with no error naming the cause")
	}
}

// The endpoint must agree with the CONSENSUS rule about what a commitment is,
// rather than carrying a second spelling of it that can drift.
func TestTheEndpointFormsTheSameCommitmentAsConsensus(t *testing.T) {
	p := testParams(t)
	for nonce := uint32(0); nonce < 32; nonce++ {
		h := types.Header{Version: types.HeaderVersion, Height: 9, Target: p.MaxTarget}
		h.PoW.Nonce = nonce
		h.PoW.ExtraNonce = 0xabcd1234
		h.PoWHash = testEngine{}.Hash(pow.KeyFor(h.Height, p), h.PoWInput())

		c := pow.Commitment(h)
		want := binary.LittleEndian.Uint64(c[len(c)-8:])
		if got := jobTargetValue(h); got != want {
			t.Fatalf("nonce %d: jobTargetValue = %#x, want %#x", nonce, got, want)
		}
	}
}

// A share that clears the job target must also satisfy the full consensus
// check when the job target is the honest truncation of the header's target.
//
// This is the property that makes the whole scheme work: the miner's cheap
// 64-bit filter and the node's 256-bit rule are the same comparison at
// different widths, so a miner is never asked to send shares the node will
// refuse for arithmetic reasons.
func TestAShareClearingTheJobTargetSatisfiesConsensus(t *testing.T) {
	p := testParams(t)
	target := easiestTarget()
	t64 := truncateTarget(target)

	checked := 0
	for nonce := uint32(0); nonce < 64; nonce++ {
		h := types.Header{Version: types.HeaderVersion, Height: 4, Target: target}
		h.PoW.Nonce = nonce
		h.PoWHash = testEngine{}.Hash(pow.KeyFor(h.Height, p), h.PoWInput())
		if !meetsJobTarget(h, t64) {
			continue
		}
		checked++
		if err := pow.CheckWork(testEngine{}, h, p); err != nil {
			t.Fatalf("nonce %d cleared the job target but failed consensus: %v", nonce, err)
		}
	}
	if checked == 0 {
		t.Fatal("no nonce cleared the job target; the test proved nothing")
	}
}

// recoverPoWHash must write the digest of THIS header's blob, because PoWHash
// is a consensus field and the commitment is formed over it. A header whose
// PoWHash is never set has no commitment and can pass no work check at all —
// which is the defect the review found by grepping for zero assignments.
func TestRecoverPoWHashSetsTheField(t *testing.T) {
	p := testParams(t)
	h := types.Header{Version: types.HeaderVersion, Height: 6, Target: p.MaxTarget}
	h.PoW.Nonce = 17
	if h.PoWHash != (types.Hash{}) {
		t.Fatal("fixture already carries a PoWHash")
	}
	recoverPoWHash(testEngine{}, &h, p)
	if h.PoWHash == (types.Hash{}) {
		t.Fatal("recoverPoWHash left PoWHash zero: the header has no commitment and " +
			"CheckWork can never pass")
	}
	want := testEngine{}.Hash(pow.KeyFor(h.Height, p), h.PoWInput())
	if h.PoWHash != want {
		t.Error("recoverPoWHash wrote something other than the digest of this header's blob")
	}
}

// The miner's own hash fields must not be trusted, and this test fails if they
// ever are.
//
// XMRig sends two 32-byte values on every submit, and under rx/2 their names
// are inverted relative to their contents: `result` carries the commitment and
// `commitment` carries the raw digest. This endpoint reads NEITHER — it
// recomputes the digest and forms the commitment itself — because a share is a
// claim, and a claim this node writes into its own chain gets checked rather
// than believed.
//
// The assertion is behavioural rather than a grep: a winning share is
// submitted with deliberate GARBAGE in both fields, and it must still be
// accepted and still become a block. Any implementation that consulted either
// field — to verify against it, to short-circuit on it, or to fill PoWHash
// from it — would reject this share or apply a block carrying the wrong digest.
//
// It exists because a reviewer wrote a version of this package that trusted the
// wire digest and the whole suite passed: the property was true by construction
// and asserted nowhere, while a mutation table claimed it was covered. An
// untested invariant is not an invariant, it is a habit.
func TestTheMinersOwnHashFieldsAreNotTrusted(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")

	r := c.call("submit", submitParams{
		ID:    res.ID,
		JobID: res.Job.JobID,
		Nonce: "0b000000",
		// Not merely wrong — structurally valid hex of the right width, so
		// that an implementation reading these would parse them happily and
		// then verify against nonsense.
		Result:     strings.Repeat("ab", 32),
		Commitment: strings.Repeat("cd", 32),
	})
	if r.Error != nil {
		t.Fatalf("a winning share was rejected because of the garbage in its "+
			"result/commitment fields: %v. Those fields must not be read", r.Error)
	}

	h.ch.mu.Lock()
	applied := len(h.ch.applied)
	var got types.Hash
	if applied > 0 {
		got = h.ch.applied[0].Header.PoWHash
	}
	h.ch.mu.Unlock()
	if applied != 1 {
		t.Fatalf("applied %d blocks, want 1", applied)
	}

	// The digest in the applied block is the one this node computed, not
	// either value the miner sent.
	var claimedResult, claimedCommitment types.Hash
	for i := range claimedResult {
		claimedResult[i], claimedCommitment[i] = 0xab, 0xcd
	}
	if got == claimedResult || got == claimedCommitment {
		t.Error("the applied block's PoWHash came from the wire. It must be recomputed: " +
			"a miner that could name PoWHash could name a consensus field every peer " +
			"re-derives")
	}
	if got == (types.Hash{}) {
		t.Error("the applied block carries a zero PoWHash")
	}
}

// THE SERVED BLOB MUST SHIP A ZERO NONCE.
//
// This is not tidiness. A stock XMRig handed a job whose blob has a non-zero
// value in the nonce field latches into nicehash mode: it treats the top byte
// as a fixed prefix it must preserve and searches only the remaining 24 bits.
// That silently narrows the connection's search space by a factor of 256,
// permanently, for as long as the connection lives — and nothing in the
// protocol reports it. The miner shows a healthy hashrate and simply finds far
// fewer shares than it should.
//
// Asserted rather than relied upon: the nonce is zero today because newJob
// builds its blob from a freshly assembled header, which is a property of code
// somewhere else that nothing otherwise stops changing.
func TestTheServedBlobShipsAZeroNonce(t *testing.T) {
	h := newHarness(t, nil)
	c := h.dial(t)
	res := c.login("")

	blob, err := hex.DecodeString(res.Job.Blob)
	if err != nil {
		t.Fatalf("blob is not hex: %v", err)
	}
	if len(blob) != types.PoWInputSize {
		t.Fatalf("blob is %d bytes, want %d", len(blob), types.PoWInputSize)
	}
	for i := types.PoWInputNonceOffset; i < types.PoWInputNonceOffset+4; i++ {
		if blob[i] != 0 {
			t.Fatalf("blob[%d] = %#x, want 0. A non-zero nonce in a served blob latches "+
				"stock XMRig into nicehash mode, narrowing this connection's search to "+
				"24 bits permanently, and nothing in the protocol reports it",
				i, blob[i])
		}
	}
	// The same must hold for a pushed job, not only the login's.
	h.srv.OnHead()
	var n struct {
		Params jobParams `json:"params"`
	}
	raw := c.readLine()
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("decoding push: %v", err)
	}
	pushed, err := hex.DecodeString(n.Params.Blob)
	if err != nil {
		t.Fatalf("pushed blob is not hex: %v", err)
	}
	for i := types.PoWInputNonceOffset; i < types.PoWInputNonceOffset+4; i++ {
		if pushed[i] != 0 {
			t.Fatalf("pushed blob[%d] = %#x, want 0", i, pushed[i])
		}
	}
}

// The advertised algorithm follows the NETWORK's engine and is never a
// constant. An endpoint that hardcoded one refuses every correctly configured
// miner the moment the networks move, which is exactly what happened when this
// package advertised rx/0 into an rx/2 world.
func TestTheAdvertisedAlgorithmFollowsTheEngine(t *testing.T) {
	cases := []struct {
		engine   string
		algo     string
		mineable bool
	}{
		{randomxV2Name, "rx/2", true},
		{randomxV1Name, "rx/0", true},
		// A devnet's work function is not RandomX and no miner implements it.
		// Advertising something plausible would let a miner connect and hash
		// the wrong function forever.
		{devEngineName, "", false},
		{"some-future-engine", "", false},
	}
	for _, tc := range cases {
		algo, mineable := algoFor(tc.engine)
		if mineable != tc.mineable || algo != tc.algo {
			t.Errorf("algoFor(%q) = %q, %v; want %q, %v",
				tc.engine, algo, mineable, tc.algo, tc.mineable)
		}
	}
}

// A network no Stratum miner can mine must refuse the login and say why,
// rather than advertising a plausible algorithm and letting the miner hash the
// wrong function forever.
func TestAnUnmineableNetworkRefusesLogin(t *testing.T) {
	h := newHarness(t, nil)
	h.srv.engine = pow.Dev{} // dev-blake3: no miner implements it
	c := h.dial(t)
	r := c.call("login", loginParams{Login: "x"})
	if r.Error == nil {
		t.Fatal("a dev-blake3 network accepted a Stratum login; every share would be noise")
	}
}

// ---------------------------------------------------------------------------
// The exposure check
// ---------------------------------------------------------------------------

// IsLoopback answers conservatively: anything it cannot prove is loopback is
// reported as exposed, because a missing warning costs an operator their
// emission address and a spurious one costs a line in a log.
func TestIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9422", true},
		{"127.0.0.53:9422", true},
		{"[::1]:9422", true},
		{"localhost:9422", true},
		{":9422", false},                // every interface: the accidental one
		{"0.0.0.0:9422", false},         // every interface, said out loud
		{"[::]:9422", false},            // and in v6
		{"192.168.1.10:9422", false},    // a LAN address is a decision
		{"example.invalid:9422", false}, // an unresolvable name is not proof
		{"nonsense", false},             // unparseable is not proof either
	}
	for _, tc := range cases {
		if got := IsLoopback(tc.addr); got != tc.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeClock is a clock the test moves by hand, so that timeout behaviour is
// asserted rather than slept through.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// waitFor polls a condition to a deadline.
//
// Polling rather than a channel because the conditions being waited on are
// states of the server observed from outside it, and adding a notification
// channel to production code for a test's benefit would be the test dictating
// the design. The deadline is generous: it bounds a failure, it does not pace
// a success.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition was not reached within the deadline")
}
