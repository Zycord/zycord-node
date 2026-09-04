package rpc_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
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
