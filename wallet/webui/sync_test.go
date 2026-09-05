package webui_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/spec"
	"zycord/wallet/webui"
)

// A wallet that is not a node believes what its node says, and a node that
// is still syncing says something true about an earlier block. These tests
// pin the one signal that tells the two apart, and what the wallet does with
// it.

func TestSyncIsUpToDateOnAFreshTip(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}}
	api, _ := newUnlockedAPI(t, node)
	sy := api.Sync()
	if !sy.Reachable || sy.Syncing || sy.Progress != 100 || sy.Message != "Up to date" {
		t.Fatalf("fresh tip with peers = %+v, want up to date", sy)
	}
}

func TestSyncReportsAStaleTipAndRefusesToSend(t *testing.T) {
	// Mainnet blocks are thirty seconds apart; a tip two days old is a node
	// that has not caught up, whatever its peer count.
	node := &fakeNode{balances: map[types.Address]string{}, tipTime: time.Now().Add(-48 * time.Hour).Unix()}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.mu.Unlock()

	sy := api.Sync()
	if !sy.Reachable || !sy.Syncing || !sy.Stale || sy.BehindFloor || sy.NoPeers {
		t.Fatalf("stale tip = %+v, want syncing because stale", sy)
	}
	if sy.Progress < 0 || sy.Progress >= 100 {
		t.Fatalf("progress = %v, want an estimate under 100", sy.Progress)
	}
	// The estimate is the tip's distance from genesis over the clock's, so it
	// is only meaningful once genesis is in the past; mainnet's may not be.
	if int64(spec.Mainnet().GenesisTime) < node.tipTime && sy.Progress == 0 {
		t.Fatalf("progress = 0 with a tip after genesis; the estimate is not being computed")
	}
	if !strings.Contains(sy.Message, "behind") {
		t.Fatalf("message = %q, want it to say how far behind", sy.Message)
	}

	_, err := api.Send(webui.SendRequest{To: "0x" + strings.Repeat("02", 32), Amount: "1000", DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "still syncing") {
		t.Fatalf("a spend against a stale node must be refused, got %v", err)
	}
	if node.count() != 0 {
		t.Fatal("nothing may reach the node")
	}
}

func TestSyncReportsTheCheckpointFloor(t *testing.T) {
	// A current tip below the floor this release enforces is a node that
	// is on some chain, but not the one the checkpoints pin.
	node := &fakeNode{balances: map[types.Address]string{}, floor: 5000}
	api, _ := newUnlockedAPI(t, node)
	sy := api.Sync()
	if !sy.Syncing || !sy.BehindFloor || sy.Stale {
		t.Fatalf("below the floor = %+v, want syncing because behind the floor", sy)
	}
	if _, err := api.Send(webui.SendRequest{To: "0x" + strings.Repeat("02", 32), Amount: "1", DryRun: true}); err == nil {
		t.Fatal("a spend below the checkpoint floor must be refused")
	}
}

func TestSyncWithoutPeersIsSyncingButNotStale(t *testing.T) {
	node := &fakeNode{balances: map[types.Address]string{}, peers: -1}
	api, k := newUnlockedAPI(t, node)
	node.mu.Lock()
	node.balances[k.Persistent()] = "5000000000000"
	node.mu.Unlock()
	sy := api.Sync()
	if !sy.Syncing || !sy.NoPeers || sy.Stale || sy.Message != "Looking for peers" {
		t.Fatalf("no peers = %+v, want looking for peers", sy)
	}
	// Peerless is not stale: the tip is current, so a spend is allowed. The
	// interface still shows the state; the wallet does not refuse it.
	if _, err := api.Send(webui.SendRequest{To: "0x" + strings.Repeat("02", 32), Amount: "1000", DryRun: true}); err != nil {
		t.Fatalf("a current tip with no peers must not block a preview: %v", err)
	}
}

func TestSyncUnreachableAndRoutes(t *testing.T) {
	api := webui.NewAPI(webui.Config{Params: spec.Mainnet(), RPC: "http://127.0.0.1:1", LockAfter: time.Hour})
	if sy := api.Sync(); sy.Reachable || sy.Error == "" {
		t.Fatalf("unreachable = %+v", sy)
	}
	if info := api.LocalNode(); info.Available {
		t.Fatal("a wallet built without a bundled node must say so")
	}
	if _, err := api.StartLocalNode(); err == nil {
		t.Fatal("starting a node that is not there must fail")
	}

	srv, _ := newTestServer(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/sync"},
		{http.MethodGet, "/api/localnode"},
	} {
		if w := do(t, srv, request(t, srv, tc.method, tc.path, "")); w.Code != http.StatusOK {
			t.Fatalf("%s %s = %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if w := do(t, srv, request(t, srv, http.MethodPost, "/api/localnode/start", "{}")); w.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/localnode/start on zcd ui = %d, want a refusal", w.Code)
	}
}
