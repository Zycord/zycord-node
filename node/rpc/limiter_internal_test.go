package rpc

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Internal because the property is about the limiter's own state, and the
// endpoint behaviour it produces is identical either way. A test that can only
// see responses cannot see this at all.

func (s *Server) clientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func request(host string) *http.Request {
	r := loopbackRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = host + ":1024"
	return r
}

// TestLimiterForgetsClientsThatStopAsking is T2.
//
// The property: the limiter's per-client map is bounded by the clients active
// recently, not by every address the process has ever seen. "Recently" is two
// windows rather than one — a sweep runs at most once per window and evicts
// what was already idle for a window before it — which is why the clock below
// advances by 2*window and not by one.
//
// The old limiter pruned timestamps *inside* each host's entry and wrote the
// entry back even when it had emptied. Pruning in place can never remove an
// entry, because the host that costs the most per byte of memory — one request
// and never again — is never visited a second time. So the map was a set of
// every source address since start-up, held until the process exited.
//
// A test that only asserts "the 601st request is rejected" passes against that
// implementation and against this one, which is why it is written against the
// map rather than against the responses.
func TestLimiterForgetsClientsThatStopAsking(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New(nil, nil, DefaultConfig(), nil)
	s.now = func() time.Time { return now }

	// One request each from a lot of addresses, and none of them comes back.
	// An exposed node does not need an attacker for this shape; a single IPv6
	// /64 supplies 2^64 of them with no spoofing at all.
	const callers = 500
	for i := 0; i < callers; i++ {
		if !s.allow(request(fmt.Sprintf("[2001:db8::%x]", i))) {
			t.Fatalf("caller %d was rate limited on its first request", i)
		}
	}
	if got := s.clientCount(); got != callers {
		t.Fatalf("setup: the limiter is tracking %d callers, want %d", got, callers)
	}

	// The window elapses. One unrelated request arrives.
	now = now.Add(2 * window)
	if !s.allow(request("[2001:db8::ffff]")) {
		t.Fatal("the arrival after the window was rate limited")
	}

	if got := s.clientCount(); got != 1 {
		t.Fatalf("the limiter is holding %d client entries two full windows after "+
			"the last request from any of them, want 1: the map is a record of "+
			"every address ever seen, and the process's memory is already the "+
			"binding constraint on a small box", got)
	}
}

// TestLimiterForgetsByteChargesToo: the byte budget's state is swept on the
// same terms as the request state, and an entry survives only while either
// half of it is live.
func TestLimiterForgetsByteChargesToo(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New(nil, nil, DefaultConfig(), nil)
	s.now = func() time.Time { return now }

	r := request("[2001:db8::1]")
	if !s.allow(r) {
		t.Fatal("the first request was rate limited")
	}
	s.chargeBlockBytes(r, 4<<20)

	// Anti-vacuity: while the charge is live it is counted, so a budget below
	// it refuses.
	tight := New(nil, nil, Config{Addr: "x", BlockBytesPerMinute: 1 << 20}, nil)
	tight.now = func() time.Time { return now }
	tight.allow(r)
	tight.chargeBlockBytes(r, 4<<20)
	if tight.allowBlockBytes(r) {
		t.Fatal("a client over its byte budget was allowed more block bytes")
	}

	now = now.Add(2 * window)
	s.allow(request("[2001:db8::2]"))
	if got := s.clientCount(); got != 1 {
		t.Fatalf("a client with only an aged-out byte charge survived the sweep: "+
			"%d entries, want 1", got)
	}
	if !tight.allowBlockBytes(r) {
		t.Fatal("a byte charge older than the window is still being counted")
	}
}

// TestLimiterIgnoresForwardedForHeaders is S2.
//
// The property: the limiter keys on the transport peer and on nothing a client
// can choose. A limiter that reads X-Forwarded-For is bypassed by setting it,
// and it turns the map growth above from "many source addresses" into "one
// client, one header, unlimited keys".
func TestLimiterIgnoresForwardedForHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cfg := DefaultConfig()
	cfg.RequestsPerMinute = 3
	s := New(nil, nil, cfg, nil)
	s.now = func() time.Time { return now }

	var limited bool
	for i := 0; i < 10; i++ {
		r := request("[2001:db8::1]")
		// A fresh forged identity on every request.
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		r.Header.Set("X-Real-IP", fmt.Sprintf("10.0.1.%d", i))
		if !s.allow(r) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a client rate limited itself out of existence by rotating a header " +
			"it sets itself")
	}
	if got := s.clientCount(); got != 1 {
		t.Fatalf("ten forged forwarding headers produced %d limiter keys, want 1", got)
	}
}

// TestPruningGivesBackTheArrayItStopsUsing: pruning in place reuses the
// backing array, so its capacity is a high-water mark unless something hands it
// back.
//
// The property: after most of a window ages out, the entry stops paying for the
// part it no longer holds. Without it a client that once spent its whole
// request budget goes on holding room for six hundred timestamps — bounded,
// because the sweep eventually takes the entry and because the client had to
// sustain the traffic to earn it, but twenty times the per-entry cost anyone
// would estimate from reading the struct.
//
// Written against the pruning function rather than through allow() on purpose.
// Driven through allow(), a client whose window has fully aged out is *swept* —
// entry deleted, then recreated empty on the same call — so the capacity comes
// back small whether pruning gives it back or not, and the test goes green
// against an implementation that never shrinks anything. That version of this
// test passed with the shrink mutated away.
func TestPruningGivesBackTheArrayItStopsUsing(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	times := make([]time.Time, 0, 600)
	charges := make([]byteCharge, 0, 600)
	for i := 0; i < 600; i++ {
		at := base.Add(time.Duration(i) * time.Millisecond)
		times = append(times, at)
		charges = append(charges, byteCharge{at: at, n: 1})
	}
	peak := cap(times)

	// All but the last four fall outside the window.
	cutoff := base.Add(595 * time.Millisecond)
	keptTimes := keepTimesAfter(times, cutoff)
	keptCharges := keepChargesAfter(charges, cutoff)

	if len(keptTimes) != 4 || len(keptCharges) != 4 {
		t.Fatalf("setup: pruning kept %d timestamps and %d charges, want 4 of each",
			len(keptTimes), len(keptCharges))
	}
	if cap(keptTimes) >= peak {
		t.Fatalf("an entry holding 4 timestamps still has room for %d, down from a "+
			"peak of %d: a client is priced by the most it ever did rather than by "+
			"what it is doing", cap(keptTimes), peak)
	}
	if cap(keptCharges) >= peak {
		t.Fatalf("an entry holding 4 byte charges still has room for %d, down from "+
			"a peak of %d", cap(keptCharges), peak)
	}

	// Anti-thrash, which is what the slack in shouldShrink buys: a client at a
	// steady rate loses nothing to the window sliding, so pruning must not
	// re-allocate on every request it handles.
	steady := make([]time.Time, 0, 16)
	for i := 0; i < 16; i++ {
		steady = append(steady, base.Add(time.Duration(i)*time.Millisecond))
	}
	before := cap(steady)
	if got := keepTimesAfter(steady, base.Add(-time.Second)); cap(got) != before {
		t.Fatalf("pruning re-allocated an entry that lost nothing: capacity %d -> %d",
			before, cap(got))
	}
}

// TestOnlyAdmissionCreatesLimiterEntries: allow() is the one thing that adds a
// key to the map.
//
// The property matters because the defect this limiter was fixed for was
// nobody being in charge of the map's size. A second path that creates entries
// is a second path that has to be audited every time the eviction policy
// changes, and it is the kind of thing a security note gets wrong — the note
// for this change asserted "allow() is the only writer", which was true of the
// code being replaced and not of the code replacing it.
func TestOnlyAdmissionCreatesLimiterEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New(nil, nil, DefaultConfig(), nil)
	s.now = func() time.Time { return now }

	// Billing a client the limiter has never admitted must not conjure one.
	s.chargeBlockBytes(request("[2001:db8::1]"), 8<<20)
	if got := s.clientCount(); got != 0 {
		t.Fatalf("charging an unknown client created %d entries: something other "+
			"than admission can grow the map", got)
	}

	// Anti-vacuity: once admitted, the same call does bill.
	r := request("[2001:db8::1]")
	if !s.allow(r) {
		t.Fatal("the first request was limited")
	}
	s.chargeBlockBytes(r, 8<<20)
	s.mu.Lock()
	charged := len(s.seen["2001:db8::1"].bytes)
	s.mu.Unlock()
	if charged != 1 {
		t.Fatalf("an admitted client carries %d charges after being billed, want 1", charged)
	}
}

// loopbackRequest builds a request the loopback-Host guard admits. See
// guardHost: httptest's default Host of "example.com" is refused, and these
// tests stand in for a local client.
func loopbackRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.Host = "127.0.0.1:9420"
	return r
}
