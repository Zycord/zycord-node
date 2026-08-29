package rpc

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// serveOne starts a Server on a loopback listener and returns it with the
// address to dial. It drives the real s.srv, so what is under test is the
// server this package hands cmd/zycordd, not an http.Server assembled here.
func serveOne(t *testing.T, h http.Handler) (*Server, string, <-chan error) {
	t.Helper()
	s := New(nil, nil, DefaultConfig(), nil)
	if s.srv == nil {
		t.Fatal("New did not build the http.Server. It is built there rather than in " +
			"ListenAndServe because ListenAndServe runs on its own goroutine while " +
			"Shutdown is called from main's teardown: a nil read there is a shutdown " +
			"that shuts nothing down")
	}
	if h != nil {
		s.srv.Handler = h
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- s.srv.Serve(ln) }()
	return s, ln.Addr().String(), served
}

// blockingHandler reports when a request has entered it, and holds that request
// inside the handler until release is closed. It is the stand-in for /block or
// /balance, both of which read the chain store for the whole of their run.
func blockingHandler(entered chan<- struct{}, release <-chan struct{}) http.Handler {
	var once atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if once.CompareAndSwap(false, true) {
			close(entered)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	})
}

// The property, in one sentence: **Shutdown does not return while a request is
// still inside a handler, and Close does.**
//
// That difference is the whole of the RPC half of the shutdown-ordering defect:
// the process closed the chain store under readers it never joined. cmd/zycordd
// deferred srv.Close() and then, further out, c.Close(). Close is
// http.Server.Close: it shuts the listeners and the idle connections and
// returns immediately, saying nothing about a handler already running — and a
// handler holds the chain and the mempool for its whole run, so the store was
// closed under a live reader. This is true in either teardown order, because
// nothing between the two joins an RPC handler.
//
// Driven concurrently, because that is how it runs in production: a real
// request is held inside a real handler across the shutdown call. The race
// detector cannot be used on this machine (no C toolchain, so no cgo), which is
// why the observation is an explicit ordering — did the handler return before
// the shutdown call did — rather than a race report.
func TestShutdownWaitsForARequestStillInsideAHandlerAndCloseDoesNot(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stop is the teardown the process performs.
		stop func(*Server) error
		// wantWaited is whether stop must not have returned before the handler
		// finished.
		wantWaited bool
	}{
		{name: "Shutdown", wantWaited: true, stop: func(s *Server) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return s.Shutdown(ctx)
		}},
		// The control the testing discipline asks for: the rejected teardown,
		// in this same scenario, must give a DIFFERENT answer. Without it the
		// first row could pass because the scenario never held a request in
		// flight at all.
		{name: "Close", wantWaited: false, stop: func(s *Server) error { return s.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var handlerDone atomic.Bool
			s, addr, served := serveOne(t, blockingHandler(entered, release))

			reqDone := make(chan struct{})
			go func() {
				defer close(reqDone)
				resp, err := http.Get("http://" + addr + "/block?height=0")
				if err == nil {
					resp.Body.Close()
				}
			}()

			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("no request ever reached the handler; the scenario never held one in flight")
			}

			// The handler is now inside the server, holding what a real one
			// holds. Release it a little after the teardown call starts, so
			// that a teardown which waits observes a handler that finishes and
			// one which does not observes a handler that has not.
			go func() {
				time.Sleep(250 * time.Millisecond)
				handlerDone.Store(true)
				close(release)
			}()

			err := tc.stop(s)
			waited := handlerDone.Load()
			<-reqDone

			if tc.wantWaited && !waited {
				t.Errorf("Shutdown returned while a request was still inside a handler (err=%v). "+
					"cmd/zycordd closes the chain store after this returns, so a handler still "+
					"reading blocks out of that store reads a store that is about to be closed "+
					"under it", err)
			}
			if !tc.wantWaited && waited {
				t.Errorf("Close waited for the in-flight handler. If it did, the two teardowns " +
					"agree on every input this test can produce and the Shutdown row above " +
					"asserts nothing")
			}
			if tc.wantWaited && err != nil {
				t.Errorf("Shutdown: %v", err)
			}

			// And the serve goroutine has left Serve by the time the teardown
			// returns. cmd/zycordd never joins it, so this is what says it is
			// gone rather than still accepting.
			select {
			case err := <-served:
				if !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("the serve loop ended with %v, not http.ErrServerClosed", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("the serve loop was still running after the teardown returned")
			}
		})
	}
}

// The property, in one sentence: **the server New builds is routed to this
// package's own mux, so ListenAndServe cannot serve http.DefaultServeMux.**
//
// The http.Server moved from ListenAndServe into New to close the nil-read
// window above. That move is only safe if the handler moved with it: an
// http.Server with a nil Handler serves the process-global DefaultServeMux,
// which would answer every route with 404 and no test that drives Handler()
// directly would notice.
func TestTheServerNewBuildsIsRoutedToThisPackagesMux(t *testing.T) {
	s := New(nil, nil, DefaultConfig(), nil)
	mux, ok := s.srv.Handler.(*http.ServeMux)
	if !ok {
		t.Fatalf("the server's handler is %T, not this package's mux", s.srv.Handler)
	}
	for _, route := range []string{"/status", "/head", "/block", "/submit", "/metrics"} {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, route, nil))
		if pattern != route {
			t.Errorf("%s resolves to pattern %q; the server ListenAndServe drives is not the "+
				"routed one", route, pattern)
		}
	}
}

// The property, in one sentence: **the http.Server this package serves on is
// the one New built, so the value main's teardown reaches is the value the
// serve goroutine is running.**
//
// The mux test above observes CONSTRUCTION: it says New leaves a routed server
// in the field. It says nothing about the field being written again later, and
// re-assigning it on the serve path is strictly WORSE than the bug that moved
// it here. The original raced a nil read against a first write. A field
// built in New and rewritten in ListenAndServe never reads nil, so the teardown
// looks like it works: Shutdown drains the server New built — which has no
// listener and no handlers — returns nil at once, and the process closes the
// chain store while the goroutine goes on serving a DIFFERENT http.Server whose
// handlers are still reading it. A silent success is harder to find than a nil.
//
// Driven the way production drives it: ListenAndServe on its own goroutine,
// Shutdown from the goroutine that owns the teardown.
func TestTheServerServedIsTheServerNewBuilt(t *testing.T) {
	// A port that was free a moment ago. Bound and released rather than
	// hardcoded, so this cannot collide with a node or another test.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probing for a free port: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	cfg := DefaultConfig()
	cfg.Addr = addr
	s := New(nil, nil, cfg, nil)
	built := s.srv

	served := make(chan error, 1)
	go func() { served <- s.ListenAndServe() }()
	// Every failure arm below leaves a server accepting on a real port
	// otherwise, including the fatal one, which does not run the rest of this
	// function at all.
	t.Cleanup(func() { s.Close() })

	// Wait until the serve loop is actually accepting, so that what the
	// teardown below reaches is a server that is genuinely running.
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the serve loop never accepted on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	select {
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("the serve loop ended with %v, not http.ErrServerClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown returned but the serve loop is still accepting: the teardown reached " +
			"a different http.Server than the one being served. A field assigned on the serve " +
			"goroutine and read from main's teardown shuts down an object nobody is serving, " +
			"and the chain store is then closed under handlers that are still running")
	}

	if s.srv != built {
		t.Errorf("the server in the field is not the one New built. It is written by the " +
			"constructor and by nothing else, so that there is no window in which the " +
			"teardown and the serve goroutine disagree about which server is running")
	}
}

// The property, in one sentence: **s.srv is assigned in New and nowhere else.**
//
// The structural half of the test above, and the reason it is a separate check:
// the behavioural one can only observe the assignments on the path it drives,
// and this field's whole point is that no OTHER path may write it. An
// assignment anywhere but the constructor is a window between a writer and
// main's teardown, whatever that writer happens to be.
func TestTheHTTPServerFieldIsWrittenOnlyByTheConstructor(t *testing.T) {
	// The whole package, not rpc.go. A writer moved to a second file of
	// package rpc is the obvious escape from a single-file parse, and it does
	// not even show up as a vacuous pass: New's own write is still found, so
	// the "no assignment at all" guard below stays quiet while the new writer
	// goes unseen.
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing package rpc: %v", err)
	}
	pkg, ok := pkgs["rpc"]
	if !ok {
		t.Fatal("no package rpc in this directory; this check cannot see the field it guards")
	}

	writes := 0
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "srv" {
						continue
					}
					writes++
					if fn.Name.Name != "New" {
						t.Errorf("%s: %s assigns the http.Server field. Only New may: any "+
							"other writer races main's teardown, which reads it to shut the "+
							"server down, and a teardown that reaches a different server "+
							"than the one being served closes the chain store under live "+
							"handlers",
							fset.Position(assign.Pos()), fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	if writes == 0 {
		t.Fatal("no assignment to the http.Server field was found at all; this check cannot " +
			"see the field it is meant to guard")
	}
}
