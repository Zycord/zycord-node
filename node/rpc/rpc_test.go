package rpc_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/rpc"
	"zycord/node/storage"
	"zycord/spec"
	"zycord/wallet"
)

func key(t *testing.T, n byte) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

type harness struct {
	p       *params.Params
	chain   *chain.Chain
	pool    *mempool.Pool
	miner   *miner.Miner
	server  *rpc.Server
	handler http.Handler
	clock   uint64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	p := *spec.Devnet()
	// Devnet's real GENESIS_TARGET (2^248), deliberately NOT u256.Max: that is
	// 31x above devnet's own MAX_TARGET, and once NextTarget normalises against
	// the window's AVERAGE target such an outlier dominates the mean for
	// a full DIFFICULTY_WINDOW after any fork, pinning every branch to
	// MAX_TARGET so no branch can out-weigh another. The real value still costs
	// only ~256 expected hash attempts.

	c, err := chain.Open(t.TempDir(), &p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	h := &harness{p: &p, chain: c, pool: mempool.New(&p, mempool.DefaultPolicy()), clock: p.GenesisTime}
	h.miner = &miner.Miner{
		Chain: c, Pool: h.pool, Engine: pow.Dev{},
		Payout: key(t, 1).Persistent(),
		Now: func() uint64 {
			h.clock += p.TargetBlockSeconds
			return h.clock
		},
	}
	h.server = rpc.New(c, h.pool, rpc.DefaultConfig(), &rpc.Metrics{})
	h.handler = h.server.Handler()
	return h
}

func (h *harness) mine(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, _, err := h.miner.MineOne(1 << 20); err != nil {
			t.Fatalf("mining: %v", err)
		}
	}
}

func (h *harness) get(t *testing.T, path string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSubmitAndMine is the end-to-end M1 loop: a wallet builds a certificate,
// the RPC admits it, the miner includes it, and the fold applies it.
func TestSubmitAndMine(t *testing.T) {
	h := newHarness(t)
	miner1, alice := key(t, 1), key(t, 2)

	// Mine to play: nothing is spendable until a coinbase matures.
	h.mine(t, int(h.p.CoinbaseMaturity)+2)

	fees := h.get(t, "/fees")
	seqBase := u256.MustFromDecimal(fees["seq_base_fee"].(string))
	parBase := u256.MustFromDecimal(fees["par_base_fee"].(string))

	b := &wallet.Builder{
		Params:  h.p,
		Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), alice.Persistent(), drops(1_000_000)),
		TTL:     h.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
		FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 20),
		Signers: []*wallet.Key{miner1},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	body := "0x" + hex.EncodeToString(cert.MarshalSSZ())
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("submit: status %d: %s", rec.Code, rec.Body.String())
	}
	if got := h.get(t, "/mempool")["size"]; got != float64(1) {
		t.Fatalf("mempool size = %v, want 1", got)
	}

	block, res, err := h.miner.MineOne(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(block.Certs) != 1 {
		t.Fatalf("the miner built a block with %d certificates", len(block.Certs))
	}
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", res.Outcomes[0].Outcome)
	}

	if got := h.get(t, "/balance?addr="+hexAddr(alice.Persistent()))["balance"]; got != "1000000" {
		t.Fatalf("recipient balance = %v, want 1000000", got)
	}
	if got := h.get(t, "/mempool")["size"]; got != float64(0) {
		t.Fatalf("the committed certificate stayed in the pool: size = %v", got)
	}
}

// TestSubmitIsTheOnlyWriteAndGrantsNothing (M1-G4): every other method is
// read-only, and submission is held to exactly the rules a peer's certificate
// would face. There is no privileged call because there is nothing to
// privilege.
func TestSubmitIsTheOnlyWriteAndGrantsNothing(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)

	// Read-only methods must refuse to mutate regardless of verb.
	for _, path := range []string{"/status", "/head", "/fees", "/mempool", "/metrics"} {
		before := h.chain.StateRoot()
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if h.chain.StateRoot() != before {
			t.Fatalf("%s changed the state", path)
		}
	}

	// A malformed submission is rejected, and an invalid certificate is
	// rejected by the same V-rules a peer's would meet.
	for _, body := range []string{"", "not hex", "0xdeadbeef"} {
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body)))
		if rec.Code == http.StatusOK {
			t.Fatalf("submit accepted %q", body)
		}
	}

	// An unfunded but structurally valid certificate must be refused by the
	// deposit screen, not pooled and handed to the miner.
	pauper := key(t, 9)
	b := &wallet.Builder{
		Params:  h.p,
		Program: wallet.Tip(types.NativeAsset, pauper.Persistent(), key(t, 8).Persistent(), drops(1)),
		TTL:     h.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(pauper.Persistent(), pauper.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(100), drops(500), drops(5)),
		Signers: []*wallet.Key{pauper},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit",
		strings.NewReader(hex.EncodeToString(cert.MarshalSSZ()))))
	if rec.Code == http.StatusOK {
		t.Fatal("an unfunded certificate was pooled")
	}
	if got := h.get(t, "/mempool")["size"]; got != float64(0) {
		t.Fatalf("mempool size = %v after a refused submission", got)
	}
}

// TestRateLimitIsOnByDefault (M1-G4).
func TestRateLimitIsOnByDefault(t *testing.T) {
	h := newHarness(t)
	cfg := rpc.DefaultConfig()
	cfg.RequestsPerMinute = 3
	srv := rpc.New(h.chain, h.pool, cfg, &rpc.Metrics{})
	handler := srv.Handler()

	var limited bool
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("the rate limiter never engaged")
	}
	if rpc.DefaultConfig().Addr != "127.0.0.1:9420" {
		t.Fatalf("the default listen address is %q, want localhost", rpc.DefaultConfig().Addr)
	}
}

// TestMetricsTrackOutcomes (M1-G7): a public testnet is undebuggable without
// per-block outcome counts, and retrofitting them under incident pressure is
// how non-consensus code sprouts consensus bugs.
func TestMetricsTrackOutcomes(t *testing.T) {
	h := newHarness(t)
	metrics := &rpc.Metrics{}
	srv := rpc.New(h.chain, h.pool, rpc.DefaultConfig(), metrics)
	handler := srv.Handler()

	h.mine(t, int(h.p.CoinbaseMaturity)+2)
	miner1, alice := key(t, 1), key(t, 2)

	seqBase := h.chain.Snapshot().State.Get(types.SeqBaseFeeSlot())
	parBase := h.chain.Snapshot().State.Get(types.ParBaseFeeSlot())

	// Two spends of one balance: the first applies, the second skips.
	send := func(seq uint64, amount u256.U256) *types.Certificate {
		b := &wallet.Builder{
			Params:  h.p,
			Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), alice.Persistent(), amount),
			Seq:     seq,
			TTL:     h.chain.Height() + 5,
			Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
			FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 20),
			Signers: []*wallet.Key{miner1},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	huge := h.chain.Snapshot().State.Get(types.NativeBalanceSlot(miner1.Persistent()))
	first, second := send(0, huge.MulDiv64(3, 4)), send(1, huge.MulDiv64(3, 4))
	for i, c := range []*types.Certificate{first, second} {
		if err := h.pool.Add(c, h.chain.Snapshot().State, h.chain.Height()); err != nil {
			t.Fatalf("pooling %d: %v", i, err)
		}
	}

	// The miner's own dry run now correctly recognises that "second" will
	// only skip and pay it nothing, and leaves it out of anything MineOne
	// assembles on its own (node/miner has its own test for this,
	// TestMinerDropsTheStaleSkips). That is the fix working as intended, but
	// it means the real, committed, mixed-outcome block this test needs has
	// to be built by hand: take the candidate the miner would propose, add
	// back the certificate it correctly filtered, reseal and commit directly.
	// What is under test past this point is only whether the metrics endpoint
	// counts what actually landed on chain — not what the builder chooses to
	// propose, which is the builder's concern and is pinned elsewhere.
	candidate, err := h.miner.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range candidate.Certs {
		if c.ID() == second.ID() {
			t.Fatal("setup: the builder kept the certificate meant to demonstrate a skip; " +
				"this scenario no longer forces staleness")
		}
	}
	candidate.Certs = append(candidate.Certs, second)
	candidate.Header.CertRoot = candidate.ComputeCertRoot(h.p)
	if h.p.IsEpochBoundary(candidate.Header.Height) {
		root, err := fold.SealStateRoot(h.chain.Snapshot().State, candidate, h.p)
		if err != nil {
			t.Fatal(err)
		}
		candidate.Header.StateRoot = root
	}
	if err := h.miner.Seal(candidate, 1<<20); err != nil {
		t.Fatal(err)
	}
	res, err := h.chain.Apply(candidate)
	if err != nil {
		t.Fatal(err)
	}
	h.chain.Read(func(v chain.View) { h.pool.OnBlock(candidate, v.State, v.Height) })

	var applied, skipped uint64
	for _, o := range res.Outcomes {
		switch o.Outcome {
		case fold.Applied:
			applied++
		case fold.SkippedStale, fold.SkippedOverflow:
			skipped++
		}
	}
	if applied == 0 || skipped == 0 {
		t.Fatalf("setup produced %d applied and %d skipped; the test needs both", applied, skipped)
	}

	// Nothing is fed to the metrics here on purpose.
	//
	// This test used to call metrics.ObserveBlock itself and then assert the
	// endpoint reported what it had just supplied — so it passed for years while
	// the production path recorded nothing at all, because the only caller of
	// ObserveBlock was this test. The counters are now kept by the chain, where
	// the blocks actually land, and the assertion is that mining a block moved
	// them without anybody asking.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["certs_applied"] != float64(applied) || out["certs_skipped"] != float64(skipped) {
		t.Fatalf("metrics report applied=%v skipped=%v, want %d and %d",
			out["certs_applied"], out["certs_skipped"], applied, skipped)
	}
}

// TestMetricsNegotiatesItsRepresentation is the wiring the unit tests around
// wantsProm and renderProm cannot reach.
//
// Those two decide the format and render it; nothing between them and a scraper
// was asserted, and that gap is where the change actually costs something. The
// scrape body travels as response.raw, which is a different writer from the one
// every other read on this surface uses — it sets its own Content-Type, it has
// no etag, and it reaches the raw arm of writeResponse that carried a comment
// saying nothing reached it. A representation served with the wrong media type
// is not scraped at all, and one served without a caching directive is
// heuristically cacheable, which turns a monitoring system into a display of
// the node's past.
//
// The JSON half is the load-bearing half. /metrics had JSON callers before it
// had a scrape format, and the milestone that added scraping is not a licence
// to break them: a caller that sends no Accept header must get exactly what it
// got before this existed.
func TestMetricsNegotiatesItsRepresentation(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 2)

	get := func(accept, query string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/metrics"+query, nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /metrics%s (Accept %q) answered %d", query, accept, rec.Code)
		}
		return rec
	}

	// A caller that predates the scrape format gets what it always got.
	plain := get("", "")
	if ct := plain.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("an unnegotiated /metrics answered %q; every caller written before the "+
			"scrape format existed sends no Accept header, and this is the one that "+
			"must not move", ct)
	}
	var before map[string]any
	if err := json.Unmarshal(plain.Body.Bytes(), &before); err != nil {
		t.Fatalf("the default representation is not JSON: %v", err)
	}
	if _, ok := before["blocks_applied"]; !ok {
		t.Errorf("the JSON representation lost blocks_applied: %v", before)
	}

	// A scraper gets the exposition format, under the media type it negotiates
	// on. A version-less text/plain has the scraper guess at the grammar.
	scrape := get("text/plain", "")
	if ct := scrape.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") ||
		!strings.Contains(ct, "version=") {
		t.Errorf("the scrape representation is served as %q; it must be text/plain and it "+
			"must name the format version, or the scraper guesses at the grammar", ct)
	}
	body := scrape.Body.String()
	for _, want := range []string{"# HELP zycord_chain_height", "# TYPE zycord_chain_height gauge"} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape body is missing %q; it reads: %s", want, body)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Errorf("Accept: text/plain was answered with JSON: %s", body)
	}

	// Live state, so nothing may cache it. This is stated for /metrics in
	// docs/RUNNING.md and it is the one directive the raw writer has no second
	// writer to fall back on.
	if cc := scrape.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("the scrape representation carries Cache-Control %q, want no-store: an "+
			"unlabelled response is heuristically cacheable, and a cached scrape reports "+
			"a node's past as its present", cc)
	}

	// ?format= overrides the header in both directions, so a human with curl
	// can ask for either without forging one.
	if ct := get("", "?format=prometheus").Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("?format=prometheus answered %q, want the exposition format", ct)
	}
	if ct := get("text/plain", "?format=json").Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("?format=json under Accept: text/plain answered %q, want JSON: the query "+
			"parameter exists precisely to override the header", ct)
	}
}

// TestScrapeReportsTheNodesActualNumbers pins every series in the scrape to a
// value and a TYPE word, from a node driven to a state where all of them
// differ.
//
// Nothing else asserts either half. The renderer's own tests feed it samples
// they invented, and the negotiation test only checks that the body is not
// JSON and mentions zycord_chain_height — so the whole of promSamples was
// unpinned: zycord_chain_height could report `0 * height`, the three
// zycord_certs_total samples could be deleted outright, blocks_applied could
// read BlocksUndone, pow_key_epoch could be nailed to 0, the accepted arm of
// zycord_submit_total could report the rejected count, boolGauge could be
// inverted, and every one of those changes scraped green.
//
// So the state is arranged so that no two numbers coincide: 74 blocks applied
// against 0 undone and 0 rejected, one certificate applied against 0 skipped
// and 0 dropped, 2 submissions accepted against 3 refused, one certificate
// left pending, 4 inbound peers against 6 outbound. "Non-zero" would not do
// it — a sample reading its neighbour's field is non-zero too, and that is
// the exact mutation this catches.
//
// The height is 74 for a reason and not for length: devnet re-keys the work
// function every 64 blocks with 8 blocks of lag, so pow_key_epoch is
// structurally 0 below height 72. A shorter chain cannot tell the real epoch
// from a hardcoded zero, which is what the wrong-key seal — a miner hashing
// under the wrong key epoch for 1112 blocks with nothing able to show it — put
// the series there for.
//
// The TYPE word is asserted per family because a scraper computes rates from
// counters and would compute nonsense from a gauge labelled as one, and that
// mistake is invisible in a curl of the body.
func TestScrapeReportsTheNodesActualNumbers(t *testing.T) {
	h := newHarness(t)
	// Attached before the scrape, because the five network series live behind
	// an `if s.net != nil` that no test had ever entered: deleting the whole
	// block was green.
	h.server.SetNetwork(scrapeNetwork{listening: true})
	h.mine(t, 73)

	miner1 := key(t, 1)
	fees := h.get(t, "/fees")
	seqBase := u256.MustFromDecimal(fees["seq_base_fee"].(string))
	parBase := u256.MustFromDecimal(fees["par_base_fee"].(string))
	build := func(seq uint64) *types.Certificate {
		t.Helper()
		b := &wallet.Builder{
			Params:  h.p,
			Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), key(t, 2).Persistent(), drops(1_000)),
			Seq:     seq,
			TTL:     h.chain.Height() + 20,
			Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
			FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 20),
			Signers: []*wallet.Key{miner1},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	submit := func(body string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body)))
		return rec.Code
	}

	// One certificate submitted and mined, so certs_applied is 1 and not 0.
	if code := submit("0x" + hex.EncodeToString(build(0).MarshalSSZ())); code != http.StatusOK {
		t.Fatalf("setup: the first submission answered %d, so the applied-certificate count "+
			"this test reads would be 0 for a reason that is not the code under test", code)
	}
	h.mine(t, 1)
	// A second submitted and left pending, so mempool_size is 1 and not 0.
	if code := submit("0x" + hex.EncodeToString(build(1).MarshalSSZ())); code != http.StatusOK {
		t.Fatalf("setup: the second submission answered %d, so nothing is left pending", code)
	}
	// Three refusals, so the accepted arm (2) and the rejected arm (3) cannot
	// be mistaken for one another.
	for i := 0; i < 3; i++ {
		if code := submit("not hex"); code == http.StatusOK {
			t.Fatal("setup: a malformed submission was accepted, so the rejected count is not 3")
		}
	}

	values, kinds := parseScrape(t, h.raw(t, "/metrics?format=prometheus"))

	for _, r := range []struct {
		series string
		kind   string
		want   uint64
		why    string
	}{
		{"zycord_blocks_applied_total", "counter", 74,
			"This node mined 74 blocks and unwound none, so a sample reading any other block counter reports 0."},
		{"zycord_blocks_undone_total", "counter", 0, "No reorg happened here."},
		{"zycord_blocks_rejected_total", "counter", 0, "The fold refused nothing here."},
		{`zycord_certs_total{outcome="applied"}`, "counter", 1,
			"One certificate was submitted and mined, and the skipped and dropped arms are 0, so a swap between arms shows."},
		{`zycord_certs_total{outcome="skipped"}`, "counter", 0, "Nothing was skipped."},
		{`zycord_certs_total{outcome="dropped"}`, "counter", 0, "Nothing was dropped."},
		{"zycord_reorgs_total", "counter", 0, "No branch switch happened here."},
		{"zycord_reorg_depth_max", "gauge", 0, "No branch switch happened here."},
		{`zycord_submit_total{outcome="accepted"}`, "counter", 2,
			"Two submissions were accepted and three refused, so this arm reading the rejected counter reports 3."},
		{`zycord_submit_total{outcome="rejected"}`, "counter", 3,
			"Three malformed bodies were posted and two certificates accepted, so this arm reading the accepted counter reports 2."},
		{"zycord_mempool_size", "gauge", 1, "One certificate was left pending on purpose."},
		{"zycord_chain_height", "gauge", 74,
			"74 blocks were mined onto a fresh genesis, so a height multiplied, masked or zeroed on the way out reports something else."},
		{"zycord_pow_key_epoch", "gauge", 1,
			"Devnet re-keys every 64 blocks with 8 of lag, so height 74 is epoch 1 and a hardcoded 0 is visible."},
		{`zycord_peers{direction="inbound"}`, "gauge", 4,
			"The attached network reports 4 inbound against 6 outbound, so the two directions cannot be swapped unseen."},
		{`zycord_peers{direction="outbound"}`, "gauge", 6,
			"The attached network reports 6 outbound against 4 inbound."},
		{"zycord_peers_known", "gauge", 11, "The attached network's peer store holds 11 addresses."},
		{"zycord_peers_banned", "gauge", 2, "The attached network has 2 peers banned."},
		{"zycord_listening", "gauge", 1, "The attached network is listening, and the exposition format spells that 1."},
	} {
		got, ok := values[r.series]
		if !ok {
			t.Errorf("%s is absent from the scrape. %s A family that vanishes takes every "+
				"dashboard and alert built on it with it, and the scrape still parses, so "+
				"nothing reports the loss. The body reads:\n%s",
				r.series, r.why, h.raw(t, "/metrics?format=prometheus").Body.String())
			continue
		}
		if got != r.want {
			t.Errorf("%s scrapes as %d, want %d. %s", r.series, got, r.want, r.why)
		}
		if kind := kinds[familyOf(r.series)]; kind != r.kind {
			t.Errorf("# TYPE %s is %q, want %q: a scraper computes rates from counters, so a "+
				"counter announced as a gauge is dropped from every rate() and a gauge "+
				"announced as a counter has rates computed from a number that falls",
				familyOf(r.series), kind, r.kind)
		}
	}

	// The table above is the inventory, not a sample of it: a family added to
	// promSamples without a row here would ship with no asserted value and no
	// asserted TYPE, which is the state this test was written to end.
	covered := map[string]bool{}
	for _, name := range []string{
		"zycord_blocks_applied_total", "zycord_blocks_undone_total", "zycord_blocks_rejected_total",
		"zycord_certs_total", "zycord_reorgs_total", "zycord_reorg_depth_max", "zycord_submit_total",
		"zycord_mempool_size", "zycord_chain_height", "zycord_pow_key_epoch",
		"zycord_peers", "zycord_peers_known", "zycord_peers_banned", "zycord_listening",
	} {
		covered[name] = true
	}
	for name := range kinds {
		if !covered[name] {
			t.Errorf("%s is exported but has no row in this test: add one naming its value and "+
				"its TYPE, or it ships with neither asserted anywhere", name)
		}
	}

	// boolGauge's other direction. Without it the listening row above is also
	// satisfied by a function that returns 1 for everything.
	h.server.SetNetwork(scrapeNetwork{listening: false})
	dark, _ := parseScrape(t, h.raw(t, "/metrics?format=prometheus"))
	if dark["zycord_listening"] != 0 {
		t.Errorf("a node that accepts no inbound connections scrapes zycord_listening=%d, want 0: "+
			"an operator alerting on unreachable nodes would see every node as reachable",
			dark["zycord_listening"])
	}
}

// parseScrape splits an exposition body into series values and family TYPE
// words. Series are keyed exactly as rendered, labels included, so the two arms
// of a labelled family are told apart rather than collapsed onto one key.
func parseScrape(t *testing.T, rec *httptest.ResponseRecorder) (map[string]uint64, map[string]string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("the scrape answered %d: %s", rec.Code, rec.Body.String())
	}
	values := map[string]uint64{}
	kinds := map[string]string{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# TYPE ") {
			f := strings.Fields(line)
			if len(f) != 4 {
				t.Fatalf("a TYPE line a scraper has to parse reads %q", line)
			}
			kinds[f[2]] = f[3]
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndex(line, " ")
		if i < 0 {
			t.Fatalf("a sample line a scraper has to parse reads %q", line)
		}
		v, err := strconv.ParseUint(line[i+1:], 10, 64)
		if err != nil {
			t.Fatalf("sample %q does not carry a number a scraper can read: %v", line, err)
		}
		values[line[:i]] = v
	}
	return values, kinds
}

// familyOf strips the labels from a rendered series to get the metric name the
// HELP and TYPE lines are written against.
func familyOf(series string) string {
	if i := strings.Index(series, "{"); i >= 0 {
		return series[:i]
	}
	return series
}

// scrapeNetwork is a Network whose numbers are all different and all non-zero.
//
// recordingNetwork is not reused for this: it reports 0 banned peers and the
// same 3 for both PeerCount and known, under which several of the network
// series could read each other's field and still scrape the expected value.
type scrapeNetwork struct{ listening bool }

func (scrapeNetwork) PeerCount() int                         { return 9 }
func (n scrapeNetwork) Reachability() (bool, int, int)       { return n.listening, 4, 6 }
func (scrapeNetwork) PeerHealth() (int, int, int)            { return 11, 2, -3 }
func (scrapeNetwork) AnnounceCertificate(*types.Certificate) {}

func hexAddr(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// TestSubmittedCertificatesAreRelayed closes a bug that only appeared once the
// chaos soak drove real transactions (R6-G2).
//
// `/submit` admitted a certificate to the local mempool and stopped there. On a
// network that is mostly non-mining nodes — which is every network — a user's
// transaction therefore sat in the mempool of the one node they happened to
// submit to, until its TTL expired, while the node cheerfully reported it
// accepted. Locally it was.
//
// A soak that mines empty blocks cannot find this. The first run with real load
// submitted 27 certificates, had all 27 accepted, and saw exactly 1 mined.
func TestSubmittedCertificatesAreRelayed(t *testing.T) {
	h := newHarness(t)
	h.mine(t, int(h.p.CoinbaseMaturity)+2)
	relay := &recordingNetwork{}
	h.server.SetNetwork(relay)

	miner1 := key(t, 1)
	fees := h.get(t, "/fees")
	seqBase := u256.MustFromDecimal(fees["seq_base_fee"].(string))
	parBase := u256.MustFromDecimal(fees["par_base_fee"].(string))
	b := &wallet.Builder{
		Params:  h.p,
		Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), key(t, 2).Persistent(), drops(1_000)),
		TTL:     h.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
		FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 20),
		Signers: []*wallet.Key{miner1},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	body := strings.NewReader("0x" + hex.EncodeToString(cert.MarshalSSZ()))
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/submit", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("submit returned %d: %s", rec.Code, rec.Body.String())
	}

	if len(relay.announced) != 1 {
		t.Fatalf("an accepted certificate was relayed %d times, want 1: it would "+
			"sit in this node's mempool until its TTL expired while the sender "+
			"waited for a confirmation that could never come", len(relay.announced))
	}
	if relay.announced[0] != cert.ID() {
		t.Fatal("a different certificate was relayed")
	}

	// Anti-vacuity: a REFUSED certificate must not be relayed, or the assertion
	// above would pass against a handler that broadcasts unconditionally — which
	// would make the RPC an amplifier for anything anyone posts at it.
	rec2 := httptest.NewRecorder()
	h.handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/submit",
		strings.NewReader("not hex")))
	if rec2.Code == http.StatusOK {
		t.Fatal("setup: the malformed submission was accepted")
	}
	if len(relay.announced) != 1 {
		t.Fatalf("a refused submission was relayed: /submit is an amplifier for "+
			"anything anyone posts at it (%d relays)", len(relay.announced))
	}
}

type recordingNetwork struct{ announced []types.Hash }

func (r *recordingNetwork) PeerCount() int                 { return 3 }
func (r *recordingNetwork) Reachability() (bool, int, int) { return true, 1, 2 }
func (r *recordingNetwork) PeerHealth() (int, int, int)    { return 3, 0, 100 }
func (r *recordingNetwork) AnnounceCertificate(c *types.Certificate) {
	r.announced = append(r.announced, c.ID())
}

// ---------------------------------------------------------------------------
// The explorer surface.
//
// A chain whose defining claim is that inclusion is not application needs a
// surface that can show the difference. These tests pin what the node has to
// hand over for that to be possible, and what it must keep refusing.
// ---------------------------------------------------------------------------

func (h *harness) raw(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func hexHash(x types.Hash) string { return "0x" + hex.EncodeToString(x[:]) }

// TestServedBlockBytesAreTheEncodingTheIDCommitsTo is T1.
//
// The property: the bytes /block?format=ssz returns are the canonical SSZ
// encoding, so an observer that hashes the header out of them derives the id
// the network agreed on.
//
// This is the assertion that stops an explorer computing a different block id
// than the chain. If it were wrong there would be no error anywhere — the node
// would answer, the explorer would decode, and the divergence would surface as
// a wrong hash on a public page. So it is asserted on the served bytes, not on
// a decoded struct: a struct that compares equal after a non-canonical round
// trip is exactly the bug this test exists for.
func TestServedBlockBytesAreTheEncodingTheIDCommitsTo(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 6)

	for height := uint64(0); height <= h.chain.Height(); height++ {
		want, err := h.chain.BlockAt(height)
		if err != nil {
			t.Fatal(err)
		}
		id := want.Header.ID()

		rec := h.raw(t, "/block?format=ssz&id="+hexHash(id))
		if rec.Code != http.StatusOK {
			t.Fatalf("height %d: status %d: %s", height, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Fatalf("block bytes served as %q: hex doubles the node's largest "+
				"response and adds an encoding pass to every request for it", ct)
		}
		served := rec.Body.Bytes()

		decoded, err := types.UnmarshalBlock(served, h.p)
		if err != nil {
			t.Fatalf("height %d: the served bytes do not decode: %v", height, err)
		}
		if got := decoded.Header.ID(); got != id {
			t.Fatalf("height %d: the served bytes hash to %s, want the requested %s",
				height, hexHash(got), hexHash(id))
		}
		// Canonicality, stated as the round trip rather than argued: the bytes
		// re-encode to themselves, so there is exactly one encoding of this
		// block and this is it.
		if reencoded := decoded.MarshalSSZ(); !bytes.Equal(served, reencoded) {
			t.Fatalf("height %d: the served encoding is not canonical: %d bytes in, "+
				"%d bytes back out", height, len(served), len(reencoded))
		}
		// The two lookup paths must agree byte for byte, or an explorer that
		// backfills by height and follows the tip by id indexes two chains.
		byHeight := h.raw(t, fmt.Sprintf("/block?format=ssz&height=%d", height))
		if byHeight.Code != http.StatusOK {
			t.Fatalf("height %d: status %d", height, byHeight.Code)
		}
		if !bytes.Equal(served, byHeight.Body.Bytes()) {
			t.Fatalf("height %d: lookup by id and by height served different bytes", height)
		}
	}
}

// TestBlockBytesAreBudgetedNotJustCounted is T3, and the requirement it comes
// from is that block bytes are the node's one asymmetric response.
//
// The property: the block bytes a single address can pull are bounded by a
// byte budget, not only by a request count. A flat count prices /status and a
// full block identically — at 600 a minute and the block ceiling that
// authorises gigabytes a minute of egress to one address, on a box that is
// also running consensus.
func TestBlockBytesAreBudgetedNotJustCounted(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 4)

	b, err := h.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(b.MarshalSSZ()))

	cfg := rpc.DefaultConfig()
	// Room for two blocks and not a third, while the request budget stays at
	// its default 600 — so nothing below can be explained by the request count.
	cfg.BlockBytesPerMinute = 2 * size
	srv := rpc.New(h.chain, h.pool, cfg, &rpc.Metrics{})
	handler := srv.Handler()

	pull := func() int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/block?format=ssz&height=1", nil))
		return rec.Code
	}
	for i := 0; i < 2; i++ {
		if code := pull(); code != http.StatusOK {
			t.Fatalf("pull %d returned %d, want 200: the budget is too tight to "+
				"measure anything", i, code)
		}
	}
	if code := pull(); code != http.StatusTooManyRequests {
		t.Fatalf("the third pull returned %d, want 429: the byte budget never "+
			"engaged, so the only bound on block egress is a request count that "+
			"prices an 8 MB answer the same as /status", code)
	}

	// Anti-vacuity in two directions. The request budget is at three of six
	// hundred, so this is not the request limiter; and a client that has spent
	// its block bytes must still be able to ask the questions that cost
	// nothing, or the budget is a lockout rather than a price.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/status returned %d after the block-byte budget was spent: the "+
			"budget locked the client out of endpoints it does not price", rec.Code)
	}
}

// TestBlockCacheHeadersMatchWhatCanStillChange is R5.
//
// The property: a representation is advertised as immutable only when it can
// never change again. Block bytes addressed by id are content-addressed and
// qualify; anything whose answer depends on the fork choice does not, because
// a cached copy claiming otherwise is a false finality claim served by a proxy
// nobody is watching.
func TestBlockCacheHeadersMatchWhatCanStillChange(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)
	tip, err := h.chain.BlockAt(h.chain.Height())
	if err != nil {
		t.Fatal(err)
	}
	id := hexHash(tip.Header.ID())

	byID := h.raw(t, "/block?format=ssz&id="+id)
	if got := byID.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("block bytes by id are %q, want immutable: an id addresses exactly "+
			"one encoding, and refetching history is pure waste on a shared box", got)
	}
	etag := byID.Header().Get("ETag")
	if etag == "" {
		t.Fatal("block bytes carry no ETag, so a client cannot revalidate at all")
	}

	// The tip's *JSON* is not immutable: it carries confirmation depth and
	// whether the block is still on the chain, and both move.
	json := h.raw(t, "/block?id="+id)
	if got := json.Header().Get("Cache-Control"); strings.Contains(got, "immutable") {
		t.Fatalf("the tip's JSON is advertised %q; its confirmation count and its "+
			"canonical flag are both still free to change", got)
	}

	// A conditional request is answered without the body.
	req := httptest.NewRequest(http.MethodGet, "/block?format=ssz&id="+id, nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("a matching If-None-Match returned %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("a 304 carried %d bytes of body", rec.Body.Len())
	}
}

// TestOrphanedBlocksAreServedAsOrphaned is R3 and S7 at the RPC boundary.
//
// The property: after a reorg the losing block's id still resolves, and the
// answer says it is not on the chain. Presenting a block from a segment that
// was reorged away, without saying so, is how a reader is led to act on a
// finality that never happened.
func TestOrphanedBlocksAreServedAsOrphaned(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 4)

	losing, err := h.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	losingID := losing.Header.ID()

	// While it is canonical the answer says so, with a depth.
	before := h.get(t, "/block?id="+hexHash(losingID))
	if before["canonical"] != true || before["confirmations"] != float64(2) {
		t.Fatalf("setup: a canonical block reports canonical=%v confirmations=%v",
			before["canonical"], before["confirmations"])
	}

	// A heavier branch from two blocks back displaces it: the first block ties
	// the honest chain's own (a block's target has no freedom relative to a
	// fixed ancestor), the second is mined fast enough that the pair outweighs
	// the two blocks it replaces.
	ancestor, err := h.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	branch := buildHarderBranch(t, h.chain, h.p, key(t, 7).Persistent(), ancestor.Header, 2, fastSolveSeconds)
	reorg, err := h.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the harder branch: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("setup: the heavier branch was not adopted, so there is no reorg to observe")
	}

	after := h.get(t, "/block?id="+hexHash(losingID))
	if after["canonical"] != false || after["orphaned"] != true {
		t.Fatalf("a reorged-out block reports canonical=%v orphaned=%v: a reader "+
			"shown this block would believe it is on the chain",
			after["canonical"], after["orphaned"])
	}
	if after["confirmations"] != float64(0) {
		t.Fatalf("a reorged-out block reports %v confirmations", after["confirmations"])
	}
	if after["parent"] != hexHash(losing.Header.ParentID) {
		t.Fatal("the orphan's parent link did not survive, so the losing segment " +
			"cannot be walked back to the fork point")
	}
	// Header-only retention, deliberately: bodies would grow the node's memory
	// with the network's fork rate, so the body is the observer's to keep.
	if after["body_retained"] != false {
		t.Fatalf("body_retained=%v for an orphan", after["body_retained"])
	}
	if rec := h.raw(t, "/block?format=ssz&id="+hexHash(losingID)); rec.Code == http.StatusOK {
		t.Fatal("the node served bytes for a block whose body it does not retain")
	}

	// The height now answers with the winner, which is why id lookup is the
	// only reorg-safe path.
	byHeight := h.get(t, "/block?height=3")
	if byHeight["id"] != hexHash(branch.Blocks[0].Header.ID()) {
		t.Fatalf("height 3 answers with %v, want the adopted block", byHeight["id"])
	}
}

// TestParamsAreServedRatherThanCopied is R2.
//
// The property: the active parameter set is readable from the node. Anything
// that renders gas costs, fee ceilings, emission or the block ceilings without
// this is keeping a second copy of them, and a second copy goes stale silently
// at the one moment it matters — a parameter change.
func TestParamsAreServedRatherThanCopied(t *testing.T) {
	h := newHarness(t)
	out := h.get(t, "/params")

	served, ok := out["params"].(map[string]any)
	if !ok {
		t.Fatalf("/params returned no parameter set: %v", out)
	}
	for _, field := range []string{
		"seq_gas_target_genesis", "block_byte_limit_genesis", "block_byte_capacity",
		"seq_gas_capacity", "cert_list_capacity", "max_cites_per_block",
		"skip_fee", "genesis_emission", "coinbase_maturity", "epoch_length",
		"gas_seq_per_read", "gas_par_per_sig",
	} {
		if _, present := served[field]; !present {
			t.Fatalf("/params omits %q, so a reader still has to hardcode it", field)
		}
	}
	if served["block_byte_capacity"] != float64(h.p.BlockByteCapacity) {
		t.Fatalf("/params reports block_byte_capacity=%v, want %d",
			served["block_byte_capacity"], h.p.BlockByteCapacity)
	}

	// The ceilings that §8.1 made elastic must NOT appear here as though they
	// were still constants. They are consensus state now, and a reader that
	// found a "block_byte_limit" among the genesis parameters would quote the
	// value T started at for the value in force.
	for _, moved := range []string{"block_byte_limit", "max_certs_per_block", "seq_gas_limit"} {
		if _, present := served[moved]; present {
			t.Fatalf("/params serves %q as a genesis parameter, but §8.1 made it a "+
				"function of consensus state: a reader would hardcode the value T "+
				"starts at and never learn it moved", moved)
		}
	}
	// A reader must be told where the ceilings went, not left to discover an
	// absence. Naming the endpoint is the difference between "this set does not
	// answer your question" and "this set answers it wrongly".
	if out["elastic_ceilings_at"] != "/fees" {
		t.Fatalf("/params does not say where the elastic ceilings are served: %v",
			out["elastic_ceilings_at"])
	}

	// The digest that makes a parameter disagreement loud instead of silent.
	root := h.p.ConsensusRoot()
	if out["consensus_root"] != hexHash(root) {
		t.Fatalf("/params reports consensus_root=%v, want %s", out["consensus_root"], hexHash(root))
	}

	// Consensus-inert prose rides along; the notes exist so that a future
	// parameter editor meets the argument where the parameter is.
	if _, present := served["notes"]; !present && len(h.p.Notes) > 0 {
		t.Fatal("/params dropped the notes")
	}
}

// TestMempoolServesIDsBoundedAndNeverBodies is R4 under S4.
//
// The property: the pending view is ids, bounded, and opt-in. Bodies would be
// the one response caching cannot help — pool contents turn over continuously
// — and they would disclose pre-confirmation contents as a side effect rather
// than as a decision.
func TestMempoolServesIDsBoundedAndNeverBodies(t *testing.T) {
	h := newHarness(t)
	h.mine(t, int(h.p.CoinbaseMaturity)+2)
	miner1 := key(t, 1)

	fees := h.get(t, "/fees")
	seqBase := u256.MustFromDecimal(fees["seq_base_fee"].(string))
	parBase := u256.MustFromDecimal(fees["par_base_fee"].(string))
	for seq := uint64(0); seq < 3; seq++ {
		b := &wallet.Builder{
			Params:  h.p,
			Program: wallet.Tip(types.NativeAsset, miner1.Persistent(), key(t, 2).Persistent(), drops(1_000)),
			Seq:     seq,
			TTL:     h.chain.Height() + 5,
			Deposit: wallet.SelfDeposit(miner1.Persistent(), miner1.Persistent()),
			FeeBid:  wallet.BidWithHeadroom(seqBase, parBase, drops(100), drops(5), 20),
			Signers: []*wallet.Key{miner1},
		}
		cert, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		if err := h.pool.Add(cert, h.chain.Snapshot().State, h.chain.Height()); err != nil {
			t.Fatalf("pooling %d: %v", seq, err)
		}
	}

	// Off by default: a caller that wanted the counters does not pay for a list.
	if _, present := h.get(t, "/mempool")["ids"]; present {
		t.Fatal("/mempool serves the pending list unasked")
	}

	full := h.get(t, "/mempool")
	if full["size"] != float64(3) {
		t.Fatalf("setup: mempool size = %v, want 3", full["size"])
	}

	listed := h.get(t, "/mempool?limit=100")
	ids, ok := listed["ids"].([]any)
	if !ok || len(ids) != 3 {
		t.Fatalf("/mempool?limit=100 returned %v ids, want 3", listed["ids"])
	}
	if listed["truncated"] != false {
		t.Fatalf("truncated=%v with every id served", listed["truncated"])
	}

	// The bound is a bound, and the caller is told when it bit.
	clipped := h.get(t, "/mempool?limit=2")
	if got := clipped["ids"].([]any); len(got) != 2 {
		t.Fatalf("limit=2 returned %d ids", len(got))
	}
	if clipped["truncated"] != true {
		t.Fatal("a truncated list did not say so, so a reader cannot tell a short " +
			"pool from a clipped one")
	}

	// Ids and nothing else. A body here would be a disclosure decision made by
	// accident.
	body, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"reads", "writes", "deposit", "fee_bid", "sigs", "program"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("/mempool leaked certificate contents: found %q in the response", forbidden)
		}
	}
}

// TestTheExplorerSurfaceStaysPowerless (§3): the endpoints added for an
// observer add no authority. Every one of them is a GET that changes nothing,
// there is still exactly one write, and nothing was added that iterates state
// or reaches back in time.
func TestTheExplorerSurfaceStaysPowerless(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)

	for _, path := range []string{
		"/params", "/block?height=1", "/block?format=ssz&height=1", "/mempool?limit=10",
	} {
		before := h.chain.StateRoot()
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if h.chain.StateRoot() != before {
			t.Fatalf("%s changed the state", path)
		}
	}

	// A read endpoint must refuse the wrong verb rather than answer it. The
	// state root never moves either way, which is why this went unnoticed: a
	// POST to /block?format=ssz was answered with megabytes.
	for _, path := range []string{
		"/block?format=ssz&height=1", "/block?height=1", "/status", "/head",
		"/params", "/fees", "/mempool", "/metrics", "/network",
	} {
		rec := httptest.NewRecorder()
		rec2 := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		h.handler.ServeHTTP(rec, rec2)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s answered %d with %d bytes, want 405: a read the node "+
				"should not have performed still costs it the egress",
				path, rec.Code, rec.Body.Len())
		}
	}

	// Nothing that would iterate the keyspace, reach into a retired state, or
	// hand out authority. ScanPrefix sorts every key in the store; it is a
	// startup cost today and exposing its shape to a handler would convert it
	// into an unauthenticated amplification primitive.
	for _, path := range []string{
		"/cells", "/addresses", "/richlist", "/scan?prefix=0x00", "/reindex",
		"/admin", "/debug/eval", "/balance?addr=" + hexAddr(key(t, 1).Persistent()) + "&height=1",
	} {
		rec := h.raw(t, path)
		if rec.Code == http.StatusOK && strings.HasPrefix(path, "/balance") {
			// /balance answers the tip; the point is that the height argument
			// bought nothing, because retained historical state does not exist.
			continue
		}
		if rec.Code == http.StatusOK {
			t.Fatalf("%s exists", path)
		}
	}
}

// TestBlockRejectsInputItCannotDecode: a request parameter is never echoed.
// The decoded-then-re-encoded form is the only thing that comes back, and a
// value that fails to decode is an error rather than a page that displays what
// the caller typed.
func TestBlockRejectsInputItCannotDecode(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 2)

	for _, bad := range []string{
		"/block?id=<script>alert(1)</script>",
		"/block?id=0xzz",
		"/block?id=0x00",
		"/block?height=-1",
		"/block?height=1e9",
		"/block?height=1&format=<b>",
		"/block",
	} {
		rec := h.raw(t, bad)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s was accepted", bad)
		}
		if strings.Contains(rec.Body.String(), "<script>") || strings.Contains(rec.Body.String(), "<b>") {
			t.Fatalf("%s came back echoed in the error: %s", bad, rec.Body.String())
		}
	}

	// The id that does decode comes back in the form the node encoded, not the
	// form it was asked in.
	blk, err := h.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	id := blk.Header.ID()
	got := h.get(t, "/block?id="+strings.ToUpper(hex.EncodeToString(id[:])))
	if got["id"] != hexHash(id) {
		t.Fatalf("the node echoed %v rather than its own encoding of the id", got["id"])
	}
}

// TestElasticCeilingsAreServedFromStateNotFromGenesis.
//
// The property: the block ceilings a reader sees are the ones in force, derived
// from the sequential target T as it stands, not the genesis constants T
// started at.
//
// §8.1 turned the ceilings into functions of consensus state. `params.Params`
// still carries `block_byte_limit_genesis`, and it stays a real number forever
// — which is exactly what makes reading it dangerous. A reader that took it for
// "the block size limit" would be wrong by up to the distance between the
// genesis 2.5 MB and the 8 MB capacity wall, would be wrong silently, and would
// have no way to notice. Serving the derived values, alongside the T they come
// from, is what makes the mistake unavailable rather than merely discouraged.
func TestElasticCeilingsAreServedFromStateNotFromGenesis(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)

	fees := h.get(t, "/fees")

	target, ok := fees["seq_gas_target"].(float64)
	if !ok {
		t.Fatalf("/fees does not report the sequential target: %v", fees["seq_gas_target"])
	}
	live := uint64(target)

	// The ceilings must be what the params derive from that T, computed by the
	// params' own accessors rather than by arithmetic repeated in the handler.
	for _, c := range []struct {
		field string
		want  float64
	}{
		{"seq_gas_limit", float64(h.p.SeqGasLimit(live))},
		{"par_gas_limit", float64(h.p.ParGasLimit(live))},
		{"block_byte_limit", float64(h.p.BlockByteLimit(live))},
		{"max_certs_per_block", float64(h.p.MaxCertsPerBlock(live))},
	} {
		if fees[c.field] != c.want {
			t.Fatalf("/fees reports %s=%v, but the params derive %v from T=%d",
				c.field, fees[c.field], c.want, live)
		}
	}

	// Anti-vacuity: T is genuinely the thing the ceilings track, so a different
	// T must give different ceilings. Without this the assertions above hold
	// against a handler that ignores state and returns the genesis constants,
	// which is the bug they exist to catch.
	other := live * 2
	if h.p.BlockByteLimit(other) == h.p.BlockByteLimit(live) {
		t.Skip("T is at the capacity clamp in this fixture, so the ceilings cannot move")
	}
	if fees["block_byte_limit"] == float64(h.p.BlockByteLimit(other)) {
		t.Fatal("the served ceiling matches a target that is not the live one")
	}
}

// TestConditionalBlockRequestsSeeStateThatMoved.
//
// The property: a 304 means the representation is unchanged. The block's JSON
// carries canonical, orphaned, confirmations and body_retained — every one of
// them a function of where the tip is — so an ETag over the block id alone
// promises something the response does not keep.
//
// The client this breaks is the careful one. An explorer using If-None-Match,
// which R5 exists to encourage, would go on rendering a block as canonical
// after it was orphaned, and would render a confirmation depth frozen at
// whatever it first saw. S7 names that failure exactly: presenting a block from
// a segment that was reorged away, without saying so, causes decisions on false
// finality. The underflow guard on confirmations was careful about the same
// failure and this undid it by another route.
func TestConditionalBlockRequestsSeeStateThatMoved(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 4)

	target, err := h.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	id := hexHash(target.Header.ID())

	first := h.raw(t, "/block?id="+id)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("the block JSON carries no ETag, so there is no conditional to test")
	}

	conditional := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/block?id="+id, nil)
		req.Header.Set("If-None-Match", etag)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		return rec
	}

	// Nothing has changed yet: a 304 here is correct and proves the conditional
	// path is live, so the assertions below are about staleness and not about a
	// conditional that never fires.
	if got := conditional(); got.Code != http.StatusNotModified {
		t.Fatalf("an unchanged block answered %d, want 304: the test cannot show "+
			"a stale 304 if it never gets a fresh one", got.Code)
	}

	// Depth moves with the tip, and the body says so.
	h.mine(t, 5)
	if got := h.get(t, "/block?id="+id)["confirmations"]; got == float64(2) {
		t.Fatalf("setup: confirmations did not move (%v)", got)
	}
	if got := conditional(); got.Code == http.StatusNotModified {
		t.Fatal("a block whose confirmation depth moved was answered 304: a client " +
			"revalidating politely is told its frozen depth is current")
	}

	// And the harder case: the block leaves the chain entirely. Seven honest
	// blocks (heights 3-9) stand between the fork point and the tip, so the
	// branch needs several blocks of its own — a branch's first block always
	// ties the honest chain's own (see buildHarderBranch), and only from the
	// second on does mining fast start compounding into more work than the
	// single-block "declare a hard target" shortcut used to buy for free.
	fresh := h.raw(t, "/block?id="+id)
	etag = fresh.Header().Get("ETag")
	forkPoint, err := h.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	branch := buildHarderBranch(t, h.chain, h.p, key(t, 7).Persistent(), forkPoint.Header, 7, fastSolveSeconds)
	if !branch.Work().Gt(worthOf(t, h.chain, 3, 9)) {
		t.Fatal("setup: the branch does not carry more work than the seven blocks it replaces")
	}
	reorg, err := h.chain.ConsiderBranch(branch)
	if err != nil || !reorg.Adopted {
		t.Fatalf("setup: the reorg did not land (adopted=%v): %v", reorg.Adopted, err)
	}
	if got := h.get(t, "/block?id="+id)["orphaned"]; got != true {
		t.Fatalf("setup: the block was not orphaned (%v)", got)
	}
	if got := conditional(); got.Code == http.StatusNotModified {
		t.Fatal("a block that left the canonical chain was answered 304: an " +
			"explorer that revalidates goes on showing it as canonical, which is " +
			"a claim of finality that never happened")
	}
}

// TestBlockJSONIsNeverAdvertisedImmutable: burial fixes which block sits at a
// height. It does not fix the confirmation count, which grows with every block
// after it — so a year-long immutable cache on the JSON freezes a number whose
// whole purpose is to move.
func TestBlockJSONIsNeverAdvertisedImmutable(t *testing.T) {
	h := newHarness(t)
	h.mine(t, int(h.p.UndoDepth)+3)

	buried, err := h.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	id := hexHash(buried.Header.ID())

	// Setup: this block really is past the undo horizon, or the assertion is
	// about a block that was never eligible to be called immutable.
	if h.chain.Height() < 1+h.p.UndoDepth {
		t.Fatalf("setup: tip %d is not past the undo horizon for height 1",
			h.chain.Height())
	}
	if cc := h.raw(t, "/block?format=ssz&id="+id).Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("setup: the buried block's bytes are %q, want immutable — the "+
			"JSON assertion below only means something if burial is detected", cc)
	}

	if cc := h.raw(t, "/block?id="+id).Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Fatalf("a buried block's JSON is advertised %q, but it carries a "+
			"confirmation count that grows with every block mined after it", cc)
	}
}

// TestAbsenceIsDistinguishableFromMalformedInput.
//
// The property: a well-formed question with a negative answer is a 404, and
// only a malformed question is a 400.
//
// This surface is read by machines. A poller asking for a height the chain has
// not reached yet, or for the body of a block whose body was not retained, is
// behaving correctly — and it has to tell that from "your request is wrong"
// without parsing prose. Fixing the codes before an explorer is written against
// them costs nothing; afterwards it is a breaking change.
func TestAbsenceIsDistinguishableFromMalformedInput(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 4)

	// Malformed: the request itself is wrong.
	for _, bad := range []string{
		"/block?id=0xzz", "/block?height=-1", "/block?height=notanumber",
		"/block?height=1&format=xml", "/block", "/mempool?limit=-3",
	} {
		if got := h.raw(t, bad).Code; got != http.StatusBadRequest {
			t.Fatalf("%s answered %d, want 400", bad, got)
		}
	}

	// Absent: the request is fine and the answer is "no".
	if got := h.raw(t, "/block?height=99999").Code; got != http.StatusNotFound {
		t.Fatalf("a height the chain has not reached answered %d, want 404: a "+
			"poller cannot tell it from a malformed request", got)
	}
	var unknown [32]byte
	unknown[0] = 0xab
	if got := h.raw(t, "/block?id="+hexHash(unknown)).Code; got != http.StatusNotFound {
		t.Fatalf("an unknown block id answered %d, want 404", got)
	}

	// And the orphan whose body was dropped: known, well-formed, unavailable.
	losing, err := h.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	forkPoint, err := h.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	branch := buildHarderBranch(t, h.chain, h.p, key(t, 7).Persistent(), forkPoint.Header, 2, fastSolveSeconds)
	if reorg, err := h.chain.ConsiderBranch(branch); err != nil || !reorg.Adopted {
		t.Fatalf("setup: the reorg did not land: %v", err)
	}
	got := h.raw(t, "/block?format=ssz&id="+hexHash(losing.Header.ID()))
	if got.Code != http.StatusNotFound {
		t.Fatalf("the bytes of an orphan whose body was dropped answered %d, want "+
			"404: the id resolves and the body does not exist, which is an absence "+
			"and not a bad request", got.Code)
	}
	// The JSON for the same block is present and says why the body is not.
	if h.get(t, "/block?id="+hexHash(losing.Header.ID()))["body_retained"] != false {
		t.Fatal("the orphan's JSON does not report the missing body")
	}
}

// TestConditionalBytesCostNeitherSide.
//
// The property: a 304 on the bytes path costs the client nothing from its byte
// budget and costs the node no encode.
//
// The conditional check used to happen in the writer, after the handler had
// already marshalled the block and charged for it — so a client doing exactly
// what R5 asks of it burned its allowance on empty responses, and the node paid
// to produce bodies it then discarded. Failing closed, but the inverse of the
// incentive: the polite client was the one being priced.
func TestConditionalBytesCostNeitherSide(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)

	blk, err := h.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(blk.MarshalSSZ()))

	// Room for exactly one block in the window.
	cfg := rpc.DefaultConfig()
	cfg.BlockBytesPerMinute = size
	srv := rpc.New(h.chain, h.pool, cfg, &rpc.Metrics{})
	handler := srv.Handler()

	fetch := func(etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/block?format=ssz&height=1", nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	first := fetch("")
	if first.Code != http.StatusOK {
		t.Fatalf("the first fetch answered %d", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag, so there is no conditional to make")
	}

	// The budget is now exactly spent. Two polite revalidations must not touch
	// it — if they charge, the second unconditional fetch below is refused.
	for i := 0; i < 2; i++ {
		if got := fetch(etag).Code; got != http.StatusNotModified {
			t.Fatalf("conditional fetch %d answered %d, want 304", i, got)
		}
	}

	// Anti-vacuity, and the assertion that matters: the budget was spent by the
	// one real transfer and by nothing since, so it has recovered nothing and
	// the next unconditional fetch is refused. A 304 that charged would have
	// made this indistinguishable — which is why the check is here rather than
	// on a counter nobody exports.
	if got := fetch("").Code; got != http.StatusTooManyRequests {
		t.Fatalf("the unconditional refetch answered %d, want 429: the budget "+
			"should be spent by exactly one transfer", got)
	}
	// And a conditional still works after the budget is gone, because it costs
	// nothing to answer.
	if got := fetch(etag).Code; got != http.StatusNotModified {
		t.Fatalf("a conditional fetch answered %d once the byte budget was spent, "+
			"want 304: revalidation does not transfer a body and must not be "+
			"priced as though it did", got)
	}
}

// TestBlockBudgetIsChargedBeforeTheDecode.
//
// The property: the byte budget is consulted, and charged, from the *stored*
// record's length — before the block is decoded, on the JSON path exactly as
// on the SSZ one. A client that has already spent its budget must not cost
// the node a decode it is never billed for, which is the reverse of the bug:
// the decode used to run first, so the budget was only ever charged for work
// already spent, and a client could make the node decode and per-certificate
// hash a full block on every request as long as it stayed under the request
// count.
//
// This is asserted by construction rather than by timing. The harness closes
// the chain, opens the storage layer directly, and overwrites one block's
// stored bytes with three bytes that are not valid SSZ under any params —
// short enough that ssz.Decode's length check rejects them outright. The
// block's header lives under a separate key and is untouched, so the id
// still resolves and the body still exists; only decoding it fails, and it
// fails deterministically rather than depending on any particular params
// value (an earlier version of this test tried to break the decode by
// reopening under tighter params instead, and learned the hard way that every
// params field that could do that is committed into ConsensusRoot, which is
// genesis's ParentID — so the "reopen under different params" shape always
// changes the network id along with it and never isolates the decode alone).
//
// A JSON request for the corrupted block has exactly two possible answers:
// 500, if the handler reached the decode — a body this node stored and cannot
// read back is a local fault, which node/chain marks with ErrLocal and
// statusFor maps accordingly — or 429, if the budget refused it first.
// Nothing else produces either code here, which is what makes the 429 below
// load-bearing evidence of the ordering rather than a guess from a clock.
func TestBlockBudgetIsChargedBeforeTheDecode(t *testing.T) {
	dir := t.TempDir()
	p := *spec.Devnet()
	// Devnet's real GENESIS_TARGET (2^248), deliberately NOT u256.Max: that is
	// 31x above devnet's own MAX_TARGET, and once NextTarget normalises against
	// the window's AVERAGE target such an outlier dominates the mean for
	// a full DIFFICULTY_WINDOW after any fork, pinning every branch to
	// MAX_TARGET so no branch can out-weigh another. The real value still costs
	// only ~256 expected hash attempts.

	c, err := chain.Open(dir, &p)
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(&p, mempool.DefaultPolicy())
	clock := p.GenesisTime
	mn := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{},
		Payout: key(t, 1).Persistent(),
		Now: func() uint64 {
			clock += p.TargetBlockSeconds
			return clock
		},
	}
	var id types.Hash
	for i := 0; i < 3; i++ {
		block, _, err := mn.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("mining: %v", err)
		}
		id = block.Header.ID()
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// Overwrite the tip block's body in place. "b/" is prefixBlock and the key
	// is prefix||id, unexported in node/chain — duplicated here rather than
	// exported solely for this test, since the point is to corrupt the record
	// a real store holds, not to exercise an API a caller would use.
	corrupted := []byte{0xff, 0xff, 0xff}
	st, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	batch := &storage.Batch{}
	batch.Put(append([]byte("b/"), id[:]...), corrupted)
	if err := st.Commit(batch); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen under the exact same params: same genesis, same network id, and
	// load() never decodes a block body (state is rebuilt from the cell/spent
	// prefixes, not by replaying blocks), so the corruption above survives
	// the reopen untouched.
	c2, err := chain.Open(dir, &p)
	if err != nil {
		t.Fatalf("reopening the same data: %v", err)
	}
	t.Cleanup(func() { c2.Close() })
	pool2 := mempool.New(&p, mempool.DefaultPolicy())

	// Control: decoding the corrupted block really does fail, so a 429 below
	// cannot be explained by "it was never going to decode either way"
	// instead of by the ordering fix.
	control := rpc.New(c2, pool2, rpc.DefaultConfig(), &rpc.Metrics{})
	ctrlRec := httptest.NewRecorder()
	control.Handler().ServeHTTP(ctrlRec, httptest.NewRequest(http.MethodGet, "/block?id="+hexHash(id), nil))
	if ctrlRec.Code != http.StatusInternalServerError {
		t.Fatalf("setup: decoding the corrupted block answered %d, want 500 — the "+
			"corruption this test relies on did not take: %s",
			ctrlRec.Code, ctrlRec.Body.String())
	}

	// The test: spend the budget on an SSZ pull of the very same block —
	// legal, because format=ssz serves the stored bytes verbatim and never
	// decodes them — then ask for the JSON representation of the same block.
	// If the budget is consulted before the decode, as it must be, this is
	// refused outright; if the decode ran first, it would fail with 500
	// exactly as the control did, budget or not.
	cfg := rpc.DefaultConfig()
	cfg.BlockBytesPerMinute = int64(len(corrupted))
	srv := rpc.New(c2, pool2, cfg, &rpc.Metrics{})
	handler := srv.Handler()

	spend := httptest.NewRecorder()
	handler.ServeHTTP(spend, httptest.NewRequest(http.MethodGet, "/block?format=ssz&id="+hexHash(id), nil))
	if spend.Code != http.StatusOK {
		t.Fatalf("setup: spending the budget with an ssz pull answered %d: %s",
			spend.Code, spend.Body.String())
	}

	got := httptest.NewRecorder()
	handler.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/block?id="+hexHash(id), nil))
	if got.Code != http.StatusTooManyRequests {
		t.Fatalf("a JSON request against an exhausted byte budget answered %d, want 429: "+
			"a 500 here would mean the handler reached the decode before the budget was "+
			"checked, paying for it on a request that was always going to be refused",
			got.Code)
	}
}

// TestCacheControlCoversEveryRoute.
//
// The property: every response on this surface states a caching policy of
// its own, rather than leaving an unlabelled response to a shared cache's
// heuristics. RFC 9111 §4.2.2 makes an unlabelled 200 heuristically
// cacheable, and RFC 9110 §15.5.5's heuristically-cacheable status set
// includes 404 — so an unlabelled error is not "no policy", it is the
// decision left to whatever a downstream proxy guesses. docs/RUNNING.md
// prescribes exactly that proxy in front of this RPC ("put a real reverse
// proxy in front of it or leave it alone").
func TestCacheControlCoversEveryRoute(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)
	addr := hexAddr(key(t, 1).Persistent())

	// State the fork choice, the pool or a peer connection can still move:
	// no caching at all, so a proxy never freezes a tip, a balance or a
	// pool count.
	for _, path := range []string{
		"/status", "/head", "/mempool", "/network", "/metrics", "/fees",
		"/balance?addr=" + addr, "/cell?addr=" + addr + "&word=" + hexHash(types.Hash{}),
	} {
		rec := h.raw(t, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("setup: %s answered %d: %s", path, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s served Cache-Control %q, want %q: a proxy is free to cache "+
				"live state as though it were settled", path, got, "no-store")
		}
	}

	// An error must never be cached as though it were a good answer. A
	// height the chain has not reached yet is the sharpest case: a cached
	// 404 for it would outlive the block that fills it. (An unrouted path
	// like "/nope" is deliberately not included here: it never reaches this
	// package's handlers at all, and its 404 comes straight from
	// http.ServeMux's default, which this fix does not touch.)
	for _, path := range []string{"/block?height=99999", "/block?id=0xzz", "/mempool?limit=-3"} {
		rec := h.raw(t, path)
		if rec.Code == http.StatusOK {
			t.Fatalf("setup: %s answered 200", path)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s (status %d) served Cache-Control %q, want %q",
				path, rec.Code, got, "no-store")
		}
	}

	// The two routes with an ETag keep their own, more specific policy.
	blk, err := h.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	id := hexHash(blk.Header.ID())
	if got := h.raw(t, "/block?id="+id).Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("/block JSON served Cache-Control %q, want %q: canonical, orphaned and "+
			"confirmations are all still free to move", got, "no-cache")
	}
	if got := h.raw(t, "/block?format=ssz&id="+id).Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("block bytes by id served Cache-Control %q, want immutable", got)
	}
	if got := h.raw(t, "/params").Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("/params served Cache-Control %q, want %q: stable for the process's "+
			"life, but not across a reset", got, "no-cache")
	}
}

// TestParamsETagIncludesTheNetworkID, wired end to end: the fix lives
// in etagOf's inputs, and this confirms handleParams actually passes the
// running chain's network id into it rather than only the consensus root.
func TestParamsETagIncludesTheNetworkID(t *testing.T) {
	h := newHarness(t)
	etag := h.raw(t, "/params").Header().Get("ETag")
	if etag == "" {
		t.Fatal("/params carries no ETag, so there is nothing to check")
	}
	networkID := h.chain.NetworkID()
	want := hex.EncodeToString(networkID[:])
	if !strings.Contains(etag, want) {
		t.Fatalf("/params ETag %q does not name the network id %s: two chains that "+
			"share a params file (a testnet before and after a reset) would share this "+
			"tag too, and a revalidating client would keep a stale network_id",
			etag, want)
	}
}

// worthOf returns the accumulated work of the blocks from height `from` to
// `to` inclusive.
func worthOf(t *testing.T, ch *chain.Chain, from, to uint64) u256.U256 {
	t.Helper()
	total := u256.Zero
	for h := from; h <= to; h++ {
		b, err := ch.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		total = total.SatAdd(chain.BlockWork(b.Header.Target))
	}
	return total
}

// fastSolveSeconds times a buildHarderBranch block far below
// TargetBlockSeconds, so the difficulty rule computes a genuinely harder
// target for it — the only way left to make a hand-built branch outweigh
// another now that ConsiderBranch re-derives every declared target instead of
// trusting it.
const fastSolveSeconds = 1

// buildHarderBranch constructs a branch of empty blocks descending from an
// ancestor on ch, each carrying the target and time the difficulty rule and
// the median-time floor actually require for it.
//
// ConsiderBranch re-derives both the target and the time bounds for every block
// on a branch — a branch adopted by fork choice used to be target- and
// timestamp-checked by nothing — so the hand-built "declare an arbitrary hard
// target" shortcut several tests in this file used to reorg a chain out from
// under a running RPC server no longer passes: this runs the same LWMA
// computation the real chain does, walking the same preceding window
// pow.NextTarget reads.
//
// solveSeconds is the gap between each block's time and its parent's — well
// below TargetBlockSeconds drives the LWMA target down the way a faster
// miner would, so a branch shorter than what it replaces can still carry
// more work. A block's own target is fixed entirely by the window that
// precedes it, so the *first* block after a shared ancestor always ties
// whatever the honest chain computed for the same position; only from the
// second block on does a fast solveSeconds start compounding. A branch
// meant to beat more than one replaced block therefore needs more than one
// block of its own.
func buildHarderBranch(t *testing.T, ch *chain.Chain, p *params.Params, payout types.Address,
	ancestor types.Header, count int, solveSeconds uint64) chain.Branch {
	t.Helper()

	window := headersEndingAt(t, ch, ancestor.ID(), int(p.DifficultyWindow)+1)

	var blocks []*types.Block
	parent := ancestor.ID()
	parentTime := ancestor.Time
	for i := 0; i < count; i++ {
		target := pow.NextTarget(window, p)
		when := parentTime + solveSeconds
		if floor := pow.MedianTime(window, p); when <= floor {
			when = floor + 1
		}

		b := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       ancestor.Height + uint64(i) + 1,
			ParentID:     parent,
			Time:         when,
			EmissionAddr: payout,
			Target:       target,
		}}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		blocks = append(blocks, b)

		parent = b.Header.ID()
		parentTime = b.Header.Time
		window = append(window, b.Header)
		if len(window) > int(p.DifficultyWindow)+1 {
			window = window[len(window)-(int(p.DifficultyWindow)+1):]
		}
	}
	return chain.Branch{Blocks: blocks}
}

// headersEndingAt walks ch from id back toward genesis via parent links,
// returning up to want headers oldest-first — the shape pow.NextTarget and
// pow.CheckMedianTime read.
func headersEndingAt(t *testing.T, ch *chain.Chain, id types.Hash, want int) []types.Header {
	t.Helper()
	var out []types.Header
	cursor := id
	for len(out) < want {
		hdr, err := ch.Header(cursor)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *hdr)
		if hdr.Height == 0 {
			break
		}
		cursor = hdr.ParentID
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// TestACorruptLocalBodyIsNotTheClientsFault pins the status a body this node
// stored and can no longer decode is served with.
//
// node/chain marks that failure ErrLocal ("a record this node cannot decode
// is this node's fault"), so node/p2p does not score its own bad disk against
// the peer that prompted the read. An HTTP client is owed the same
// attribution: 400 tells a caller its request was malformed, which invites it
// to stop retrying a request that was always well-formed and hides a local
// fault behind a client-side bug. The route must answer 5xx.
//
// The block is corrupted through the store directly, exactly as the
// budget-ordering test does, because the point is the record a real store
// holds rather than an API a caller would use.
func TestACorruptLocalBodyIsNotTheClientsFault(t *testing.T) {
	dir := t.TempDir()
	p := *spec.Devnet()
	// Devnet's real GENESIS_TARGET (2^248), deliberately NOT u256.Max: that is
	// 31x above devnet's own MAX_TARGET, and once NextTarget normalises against
	// the window's AVERAGE target such an outlier dominates the mean for
	// a full DIFFICULTY_WINDOW after any fork, pinning every branch to
	// MAX_TARGET so no branch can out-weigh another. The real value still costs
	// only ~256 expected hash attempts.

	c, err := chain.Open(dir, &p)
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(&p, mempool.DefaultPolicy())
	clock := p.GenesisTime
	mn := &miner.Miner{
		Chain: c, Pool: pool, Engine: pow.Dev{},
		Payout: key(t, 1).Persistent(),
		Now: func() uint64 {
			clock += p.TargetBlockSeconds
			return clock
		},
	}
	var id types.Hash
	for i := 0; i < 3; i++ {
		block, _, err := mn.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("mining: %v", err)
		}
		id = block.Header.ID()
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	batch := &storage.Batch{}
	batch.Put(append([]byte("b/"), id[:]...), []byte{0xff, 0xff, 0xff})
	if err := st.Commit(batch); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	c2, err := chain.Open(dir, &p)
	if err != nil {
		t.Fatalf("reopening the same data: %v", err)
	}
	t.Cleanup(func() { c2.Close() })

	srv := rpc.New(c2, mempool.New(&p, mempool.DefaultPolicy()), rpc.DefaultConfig(), &rpc.Metrics{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/block?id="+hexHash(id), nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a block this node stored and cannot decode answered %d, want 500: "+
			"400 charges this node's own unreadable record to the client that asked "+
			"for it, which is the misattribution node/chain's ErrLocal exists to "+
			"prevent one layer down (%s)", rec.Code, rec.Body.String())
	}
	// An error must not be cached either way.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("a 500 served Cache-Control %q, want %q", got, "no-store")
	}
}

// TestBuriedHeightBytesAreNotImmutable guards the height half of the cache
// identity — year-long immutable caching applied to height-addressed block
// bytes, which a chain reset or a resync invalidates — against a regression
// the rest of the suite cannot see.
//
// immutable is `byID` alone: a height-addressed URL never earns a year-long
// cache, buried or not, because burial fixes which block sits at a height for
// one running process and not for the URL — a chain reset or a resync gives
// that height different bytes, which is the identical reason handleParams
// declines the same claim for a params file.
//
// Nothing else asserts this. Two existing tests fetch this exact URL and
// never inspect the header, so re-adding `|| buried` to the expression would
// leave the package green. This is the test that would go red.
func TestBuriedHeightBytesAreNotImmutable(t *testing.T) {
	h := newHarness(t)
	// Mine well past UndoDepth so the height in question is genuinely buried
	// — the state in which the old expression would have claimed immutable.
	h.mine(t, int(h.p.UndoDepth)+3)

	tip := h.get(t, "/head")
	tipHeight, ok := tip["height"].(float64)
	if !ok {
		t.Fatalf("/head reported no height: %v", tip)
	}
	if uint64(tipHeight) <= h.p.UndoDepth+1 {
		t.Fatalf("setup: tip height %v is not past UndoDepth %d", tipHeight, h.p.UndoDepth)
	}

	rec := h.raw(t, "/block?format=ssz&height=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: buried height answered %d: %s", rec.Code, rec.Body.String())
	}
	got := rec.Header().Get("Cache-Control")
	if strings.Contains(got, "immutable") {
		t.Fatalf("block bytes at a buried height served Cache-Control %q: a height is "+
			"not content-addressed, and a chain reset or resync gives it different "+
			"bytes — immutable is reserved for the by-id lookup", got)
	}
	if got != "no-cache" {
		t.Fatalf("block bytes at a buried height served Cache-Control %q, want %q", got, "no-cache")
	}

	// The by-id form of the same block is the one that does earn it.
	blk, err := h.chain.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	byID := h.raw(t, "/block?format=ssz&id="+hexHash(blk.Header.ID()))
	if got := byID.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("block bytes by id served Cache-Control %q, want immutable: an id "+
			"names exactly one encoding forever", got)
	}
}

// TestStatusReportsTheChainWorkAReleaseHasToMeasure is the reporting side of
// the launch checkpoint defence.
//
// `min_chain_work` is the primary layer of the launch checkpoint defence and
// docs/RELEASE.md makes refreshing it a mandatory step of every release —
// including after the sunset, when it is the only layer left. A mandatory step
// needs a source for its value, and `/status`'s `chain_work` is the only one:
// `Chain.TotalWork` is otherwise reachable only from inside node/p2p and
// node/sync. Without this field the enforcement in `sync.Admit` is code no
// release can ever supply a floor for, which is layer 1 switched off for the
// life of the network.
//
// The properties, in the order the release step relies on them:
//
//  1. The field exists and is the node's real accumulated work, not an echo of
//     something configured — `min_chain_work` beside it is the echo.
//  2. It is a decimal string, like every other U256 this project encodes: JSON
//     numbers are doubles in most parsers and work at this scale does not
//     survive one.
//  3. It is reported *with* the height it is measured at, in one response, and
//     it grows with that height. RELEASE.md takes the pair out of a single
//     `/status` because pairing a work reading with a different height is the
//     error that sets the floor too high and refuses the honest network.
func TestStatusReportsTheChainWorkAReleaseHasToMeasure(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 4)

	first := h.get(t, "/status")
	work, ok := first["chain_work"].(string)
	if !ok {
		t.Fatalf("/status carries no chain_work string: %v: RELEASE.md's "+
			"min_chain_work step has no source for its number, so layer 1 of "+
			"the checkpoint defence can never be given a value", first)
	}
	if want := h.chain.TotalWork().String(); work != want {
		t.Fatalf("/status reported chain_work %q, the chain holds %q: the field "+
			"must be this node's own accumulated work — a release engineer "+
			"copies it into spec/checkpoints.json", work, want)
	}
	if _, err := u256.FromDecimal(work); err != nil {
		t.Fatalf("chain_work %q does not parse as decimal U256: %v: the floor is "+
			"read back by u256.UnmarshalJSON, which accepts decimal only", work, err)
	}
	if work == "0" {
		t.Fatal("chain_work is 0 after four blocks were mined: a floor copied " +
			"from this would be no floor at all")
	}

	// Anti-echo. min_chain_work is the configured floor — empty at v1.0.0 —
	// and chain_work is the measurement. A field that merely repeated the
	// configuration would satisfy every assertion above and be useless.
	if cfg, ok := first["min_chain_work"].(string); !ok || cfg == work {
		t.Fatalf("min_chain_work %v and chain_work %q are not distinguishable: "+
			"the release step would be reading its own input back", first["min_chain_work"], work)
	}

	// The pair moves together, which is what makes reading both out of one
	// response the correct procedure rather than a convenience.
	height, ok := first["height"].(float64)
	if !ok {
		t.Fatalf("/status carries no height beside chain_work: %v", first)
	}
	h.mine(t, 2)
	second := h.get(t, "/status")
	grown, _ := second["chain_work"].(string)
	if grown == work {
		t.Fatalf("chain_work is still %q after two more blocks: it is not "+
			"tracking the tip", work)
	}
	before, err := u256.FromDecimal(work)
	if err != nil {
		t.Fatal(err)
	}
	after, err := u256.FromDecimal(grown)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Gt(before) {
		t.Fatalf("chain_work went from %q to %q as the chain grew: work only "+
			"accumulates, and a floor measured against a shrinking number "+
			"would refuse the chain it was taken from", work, grown)
	}
	if h2, _ := second["height"].(float64); h2 <= height {
		t.Fatalf("height went from %v to %v while chain_work grew: the two are "+
			"read as one pair and must describe the same tip", height, h2)
	}
}
