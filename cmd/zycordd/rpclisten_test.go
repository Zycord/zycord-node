package main

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// The property, in one sentence: **"rpc listening on <addr>" is printed only on
// the branch where the bind succeeded, and never from inside the serve
// goroutine that used to print it before the bind.**
//
// The defect: the line was logged as the serve goroutine's first statement,
// ahead of the net.Listen that ListenAndServe performs — so a run whose bind
// then failed still announced the RPC as up, and anything reading the log (an
// operator, a start script, a health check grepping for the line) believed it.
// The fix binds first via srv.Listen, prints the line only when that returns
// nil, and leaves serving to the goroutine.
//
// This reads main's source, the way the wiring tests in this package do,
// because main binds a socket and opens a store and so is not callable from a
// test. It pins the ordering only; it says nothing about whether a failed bind
// should be fatal — that is a separate decision, deliberately left as it was:
// the node logs the failure and keeps following the chain without RPC.
func TestRPCListeningLineIsPrintedOnlyAfterASuccessfulBind(t *testing.T) {
	_, _, mainFn := mainFiles(t)

	const marker = "rpc listening on"

	// containsMarker reports whether n's subtree holds a string literal carrying
	// the listening marker.
	containsMarker := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			lit, ok := m.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(s, marker) {
				found = true
			}
			return true
		})
		return found
	}

	if !containsMarker(mainFn.Body) {
		t.Fatalf("main no longer logs %q at all; this check cannot see the line it guards", marker)
	}

	// 1) The line is never emitted from inside a `go` statement. That is where it
	// used to sit — the goroutine's first statement, printed before the bind
	// ListenAndServe makes — so a bind that failed still announced the RPC as up.
	var stack []ast.Node
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, err := strconv.Unquote(lit.Value); err != nil || !strings.Contains(s, marker) {
			return true
		}
		for _, a := range stack[:len(stack)-1] {
			if _, ok := a.(*ast.GoStmt); ok {
				t.Errorf("the %q line is printed inside a goroutine, ahead of the bind "+
					"ListenAndServe makes; a failed bind then still announces the RPC as up", marker)
				break
			}
		}
		return true
	})

	// bindsViaListen reports whether an `if` statement's init clause calls a
	// .Listen() method — the bind main now gates the line on.
	bindsViaListen := func(init ast.Stmt) bool {
		if init == nil {
			return false
		}
		found := false
		ast.Inspect(init, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Listen" {
				found = true
			}
			return true
		})
		return found
	}

	// 2) The line sits on the success (else) branch of an `if` that binds via
	// .Listen(), and never on that if's failure (body) branch.
	gated := false
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !bindsViaListen(ifs.Init) {
			return true
		}
		if containsMarker(ifs.Body) {
			t.Errorf("the %q line is on the failure branch of the bind check; a bind that "+
				"failed must not announce the RPC as listening", marker)
		}
		if ifs.Else != nil && containsMarker(ifs.Else) {
			gated = true
		}
		return true
	})
	if !gated {
		t.Errorf("the %q line is not gated on a successful srv.Listen(): it must be printed "+
			"only after the bind succeeds, not before it", marker)
	}
}

// The property, in one sentence: **a --rpc value that is not loopback is
// announced by a warning, and that warning is guarded by rpc.IsLoopbackBind
// rather than emitted unconditionally or not at all.**
//
// The defect: --rpc accepted a routable address in silence, where
// --stratum-listen one flag over had carried a loud exposure warning since it
// existed. The RPC is the older and the more reachable surface, and
// node/rpc.guardHost does not cover the case: it stops a browser, because a
// page cannot forge Host, and it stops nothing at all against a caller that
// sets the header itself. docs/adversarial/I8-services.md ~:320 records the
// demonstration — `--rpc 0.0.0.0:9420` plus `curl -H "Host: 127.0.0.1"` is
// answered 200, /submit included.
//
// Read from main's source for the reason the test above gives: main binds a
// socket and opens a store, so it is not callable from a test. This pins that
// the warning exists and that it is conditional on the bind check; it says
// nothing about the wording, and deliberately nothing about warn-versus-refuse
// — warn is the decision, and the reason it is not a refusal is that a reverse
// proxy setting Host: 127.0.0.1 is a documented deployment that a refusal would
// break on upgrade.
//
// It notices the absence of what it claims: delete the warning and the marker
// is gone; hoist it out of its `if` and the guard check fails; swap the guard
// for `true` and the IsLoopbackBind requirement fails.
func TestARoutableRPCBindIsWarnedAbout(t *testing.T) {
	_, _, mainFn := mainFiles(t)

	const marker = "rpc: WARNING"

	// The innermost `if` enclosing the warning, and whether its condition
	// consults the bind check.
	var enclosing []*ast.IfStmt
	var stack []ast.Node
	guarded := false
	seen := false
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.Contains(s, marker) {
			return true
		}
		seen = true
		enclosing = enclosing[:0]
		for _, a := range stack {
			if ifs, ok := a.(*ast.IfStmt); ok {
				enclosing = append(enclosing, ifs)
			}
		}
		for _, ifs := range enclosing {
			ast.Inspect(ifs.Cond, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
					sel.Sel.Name == "IsLoopbackBind" {
					guarded = true
				}
				return true
			})
		}
		return true
	})

	if !seen {
		t.Fatalf("main no longer logs a %q line: a routable --rpc bind is accepted "+
			"in silence again, which is the whole of the defect this guards", marker)
	}
	if !guarded {
		t.Errorf("the %q line is not conditional on rpc.IsLoopbackBind(...): it must "+
			"fire for a non-loopback bind and stay quiet for the loopback default, "+
			"or operators learn to ignore it", marker)
	}
}
