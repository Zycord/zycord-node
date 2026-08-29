package rpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// The operator-visible line "rpc listening on <addr>" must be an
// observation of a bind that has happened, not a prediction of one. main prints
// it only when srv.Listen has returned nil, so these two tests pin the two
// facts that make that gate correct.

// Listen actually takes the address before it returns — so a line main prints
// right after it is true — and the listener it opens is the one ListenAndServe
// then serves, rather than a second bind of the same address.
func TestListenHoldsTheBindAndListenAndServeReusesIt(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	s := New(nil, nil, cfg, nil)

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen on a free address returned %v; the listening line main prints "+
			"immediately after this call would then be announcing a bind that failed", err)
	}
	if s.ln == nil {
		t.Fatal("Listen returned nil but opened no listener; ListenAndServe would have " +
			"nothing to serve")
	}
	addr := s.ln.Addr().String()

	// The bind is held the moment Listen returns: a second bind of the same
	// concrete address fails. This is the property the "listening" line rests on.
	if probe, err := net.Listen("tcp", addr); err == nil {
		probe.Close()
		t.Fatalf("a second bind of %s succeeded, so Listen had not really taken the "+
			"address when it returned nil", addr)
	}

	// ListenAndServe serves the listener Listen opened rather than binding a
	// fresh one. cfg.Addr now names an address already held by s.ln, so a rebind
	// would fail with address-in-use; a clean shutdown proves it reused s.ln.
	s.cfg.Addr = addr
	served := make(chan error, 1)
	go func() { served <- s.ListenAndServe() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("ListenAndServe returned %v; expected it to serve the listener Listen "+
			"opened and stop cleanly, not to rebind %s", err, addr)
	}
}

// The other half of the same line: it must report the address the listener
// actually bound, not cfg.Addr. With a :0 request the two differ — cfg.Addr
// carries the port 0 the caller asked for, and Addr() carries the concrete port
// the kernel chose, which is what a test or a container-assigned port needs to
// reach the RPC. This pins that Addr() reports that concrete, non-zero port
// after Listen, and nil before it, and that ListenAndServe serves that very
// listener rather than binding a second one.
//
// Non-vacuity: if Addr() returned cfg.Addr the port assertion below would read
// 0 and fail on the :0 case, so the test cannot pass unless Addr() reflects the
// observed bind rather than the requested address.
func TestAddrReportsTheConcreteBoundPortAndListenAndServeReusesIt(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	s := New(nil, nil, cfg, nil)

	if got := s.Addr(); got != nil {
		t.Fatalf("Addr() = %v before Listen; nothing is bound yet, so it must be nil", got)
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen on a free address returned %v", err)
	}

	addr := s.Addr()
	if addr == nil {
		t.Fatal("Addr() is nil after a successful Listen; the listening line would have no " +
			"address to report")
	}
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("Addr() = %q is not a host:port: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Addr() port %q is not an integer: %v", portStr, err)
	}
	if port <= 0 {
		t.Fatalf("Addr() reported port %d for a :0 request; it must carry the concrete port "+
			"the kernel assigned, not the 0 cfg.Addr asked for", port)
	}

	// The address Addr() reports is the one ListenAndServe serves, not a second
	// bind: cfg.Addr still says :0, so a rebind here would open a different port
	// and Shutdown would not stop this listener. A clean shutdown proves reuse.
	served := make(chan error, 1)
	go func() { served <- s.ListenAndServe() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("ListenAndServe returned %v; expected it to serve the listener Listen opened "+
			"on port %d and stop cleanly, not to rebind", err, port)
	}
	if after := s.Addr(); after == nil || after.String() != addr.String() {
		t.Fatalf("Addr() = %v after serving; it must still name the listener that was served "+
			"(%v)", after, addr)
	}
}

// A bind that cannot be made is reported by Listen returning an error, so main
// can withhold the "listening" line — instead of the failure surfacing only
// later, from inside a serve goroutine that has already run past the log.
func TestListenReportsABindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := DefaultConfig()
	cfg.Addr = occupied.Addr().String()
	s := New(nil, nil, cfg, nil)

	if err := s.Listen(); err == nil {
		t.Fatalf("Listen on the already-bound %s returned nil; main would then print "+
			"\"rpc listening\" for a bind that never happened", cfg.Addr)
	}
	if s.ln != nil {
		t.Fatal("Listen failed but left a listener behind; on a failed bind there must be " +
			"nothing for ListenAndServe to serve")
	}
}
