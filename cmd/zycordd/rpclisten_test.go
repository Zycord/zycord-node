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
