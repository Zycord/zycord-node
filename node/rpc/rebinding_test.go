package rpc_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/rpc"
	"zycord/wallet"
)

// I8 — the RPC's write, reached from a browser the operator did not point at
// it.
//
// TestSubmitIsTheOnlyWriteAndGrantsNothing asks whether submission grants
// AUTHORITY, and correctly answers no: a certificate is held to exactly the
// rules a peer's would face. It never asks WHO can reach it, and that is the
// question a loopback bind does not answer on its own.
//
// A page in the operator's own browser can POST to 127.0.0.1 — the same-origin
// policy forbids READING the reply, not sending the request. With a
// Content-Type of text/plain the POST is a CORS "simple request" and is sent
// with no preflight at all. And a hostname the attacker controls, re-resolved
// to 127.0.0.1 after the page has loaded (DNS rebinding), makes the page's own
// origin loopback so even the reply is readable.
//
// docs/RUNNING.md names DNS rebinding as "the real attack against a server on
// loopback", and wallet/webui/server.go:342 carries the guard for it —
// loopbackHost(r.Host) plus a Sec-Fetch-Site/Origin check on every write. The
// node's RPC carries neither.
func TestASubmitFromAForeignOriginIsRefused(t *testing.T) {
	h := newHarness(t)
	miner1, alice := key(t, 1), key(t, 2)
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

	// Exactly what a cross-origin page can send with no preflight: a simple
	// request, text/plain, a Host the attacker chose, an Origin that is not
	// this machine, and Sec-Fetch-Site saying so plainly.
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	req.Host = "rebound.attacker.example"
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")

	// A relay recorder, so the test can say whether the write ESCAPED the
	// machine rather than only whether it landed locally.
	relay := &recordingNetwork{}
	h.server.SetNetwork(relay)

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if len(relay.announced) > 0 {
		t.Errorf("the cross-site submission was GOSSIPED to %d peer(s): the "+
			"write did not stay on the operator's machine", len(relay.announced))
	}
	if rec.Code == http.StatusOK {
		t.Errorf("a cross-site POST carrying Host=%q Origin=%q "+
			"Sec-Fetch-Site=cross-site was ACCEPTED (status %d, body %s); "+
			"any page the operator visits can write to this node's mempool "+
			"and, through AnnounceCertificate, to the peer-to-peer network",
			req.Host, req.Header.Get("Origin"), rec.Code,
			strings.TrimSpace(rec.Body.String()))
	}
	if got := h.get(t, "/mempool")["size"]; got != float64(0) {
		t.Errorf("mempool size = %v after a cross-site submission; the write "+
			"landed", got)
	}
}

// The same question for the reads. A read is not a mutation, but a rebound
// page that can READ /balance and /cell enumerates the operator's addresses
// and holdings from a web page they merely visited.
func TestAReadFromAForeignOriginIsRefused(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)
	for _, path := range []string{"/status", "/head", "/balance?addr=0x" +
		hex.EncodeToString(make([]byte, 32)), "/mempool", "/network"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "rebound.attacker.example"
		req.Header.Set("Origin", "https://attacker.example")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("%s answered a cross-site request with a Host the node "+
				"does not serve (status %d)", path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// What the guard is NOT
// ---------------------------------------------------------------------------

// The property, in one sentence: **guardHost is a rebinding defence and not
// access control — a caller that simply sets `Host: 127.0.0.1` is served, on
// every route including /submit, no matter which interface the node bound.**
//
// This is a characterisation test, not a regression guard: it asserts the
// limitation rather than a protection, and it exists because the limitation was
// repeatedly mis-stated as a protection (docs/adversarial/I8-services.md ~:320
// records the demonstration). It fails the day someone adds a real access
// control here — which is the moment every doc paragraph and every comment
// saying "not access control" needs revisiting, and the moment the exposure
// warning in cmd/zycordd could stop being the whole answer to a routable bind.
//
// It notices the absence of the property it names: with the guard's Host check
// removed the test still passes (the requests were already allowed), and with a
// real source-address or credential check added it fails, which is the
// direction that matters.
func TestTheHostGuardIsNotAccessControl(t *testing.T) {
	h := newHarness(t)
	h.mine(t, 3)

	// A caller from anywhere on the network, holding no credential, that has
	// done nothing more than type one curl flag.
	for _, path := range []string{"/status", "/head", "/mempool", "/network"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:9420"
		req.RemoteAddr = "203.0.113.7:51234"
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s answered %d for an unauthenticated remote caller that "+
				"set a loopback Host; if this is now refused, the guard has "+
				"become more than a rebinding defence and every comment and doc "+
				"paragraph calling it 'not access control' is stale", path, rec.Code)
		}
	}

	// And the write. This is the half that makes the distinction matter: a
	// forged header reaches the one route that leaves the machine.
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("{}"))
	req.Host = "127.0.0.1:9420"
	req.RemoteAddr = "203.0.113.7:51234"
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Errorf("/submit answered 403 for an unauthenticated remote caller " +
			"that set a loopback Host; the guard is no longer only a rebinding " +
			"defence, and the comments saying so must be updated")
	}
}

// IsLoopbackBind answers conservatively about an address the OPERATOR typed:
// anything it cannot prove reaches only loopback is reported as exposed,
// because a missing warning costs an operator a routable /submit they did not
// know they had and a spurious one costs a line in a log.
//
// The empty host is the case that separates this from loopbackHost, which
// reads a header an attacker chooses: ":9420" binds every interface and must
// be exposed here, while an empty Host header is a missing value there. Both
// answer false, for opposite reasons; neither can be folded into the other.
func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9420", true},
		{"127.0.0.53:9420", true},
		{"[::1]:9420", true},
		{"localhost:9420", true},
		{"127.0.0.1:0", true},           // an ephemeral port is still loopback
		{":9420", false},                // every interface: the accidental one
		{"0.0.0.0:9420", false},         // every interface, said out loud
		{"[::]:9420", false},            // and in v6
		{"192.168.1.10:9420", false},    // a LAN address is a decision
		{"203.0.113.7:9420", false},     // and a routable one doubly so
		{"example.invalid:9420", false}, // an unresolvable name is not proof
		{"nonsense", false},             // unparseable is not proof either
		{"", false},
	}
	for _, tc := range cases {
		if got := rpc.IsLoopbackBind(tc.addr); got != tc.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
