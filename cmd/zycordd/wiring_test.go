package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// mainFunc returns every non-test file of package main, parsed, and its `func
// main`, which the wiring tests below read. Parsing the source is the only way
// to see main's wiring at all: main reads flags, binds a listener and opens a
// store, so it is not callable from a test. It is the same move
// shutdown_test.go makes for the engine-teardown join.
//
// The whole package rather than main.go alone. `main.go` is where the signal
// channel is created, but package main is one namespace: a sidecar file
// holding `func secondRacer(sig chan os.Signal) { <-sig }` is reachable from
// main, is the signal-channel-as-queue defect verbatim, and a check scoped to
// one file cannot see it. Test files are excluded because a test may
// legitimately hold a signal channel of its own — main_signal_test.go does.
func mainFiles(t *testing.T) (*token.FileSet, []*ast.File, *ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing package main: %v", err)
	}
	pkg, ok := pkgs["main"]
	if !ok {
		t.Fatal("no package main in this directory")
	}
	// Sorted, so a failure names the same file every run.
	names := make([]string, 0, len(pkg.Files))
	for name := range pkg.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	var files []*ast.File
	var mainFn *ast.FuncDecl
	for _, name := range names {
		f := pkg.Files[name]
		files = append(files, f)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "main" {
				mainFn = fd
			}
		}
	}
	if mainFn == nil {
		t.Fatal("no func main in package main")
	}
	return fset, files, mainFn
}

// allDecls flattens the package's declarations so a check can ask "does ANY
// function in package main do this", which is the question the signal-channel
// property turns on.
func allDecls(files []*ast.File) []ast.Decl {
	var out []ast.Decl
	for _, f := range files {
		out = append(out, f.Decls...)
	}
	return out
}

// The property, in one sentence: **the channel `signal.Notify` delivers to has
// exactly one receiver, and the shutdown reaches everybody else as a closed
// channel.**
//
// The regression this pins is a signal channel used as if it were a broadcast,
// and its shape is why the obvious test cannot see it. `signal.Notify`
// delivers each signal ONCE, to whichever receiver is ready. `zycordd` had
// five goroutines selecting on the signal channel itself — main, the mine
// loop, the abandon predicate inside it, the prefetch loop and the heartbeat —
// so a SIGTERM woke exactly one of them and the other four carried on; whether
// the node stopped at all depended on who won. A mutation run against the
// built binary measured that and found survival strongly GOMAXPROCS-dependent
// (7/15 survivals at GOMAXPROCS=2, 0/20 at the default), which is exactly why
// a behavioural test that sends one signal at one GOMAXPROCS value will pass
// against the broken code: it samples one point of a race distribution. The
// property to assert is structural.
//
// So: `signal.Notify` is called once; the channel it names is used in `main`
// for nothing but its own declaration, that call, and being handed to
// `stopOnSignal`; `stopOnSignal` receives from it once and returns a
// RECEIVE-ONLY `<-chan struct{}`, which every later reader observes and no
// reader consumes; and no other function in main.go takes a `chan os.Signal`
// at all — that last one is the move that created the regression, since
// `prefetchLoop` was handed the signal channel and became a fourth racer.
//
// What it cannot see: a receiver added in another file of package main, or one
// inside a package this one imports. The check is over main.go because that is
// where the signal channel is created, and a use of it has to be reachable
// from there to exist at all.
func TestTheSignalChannelHasExactlyOneReceiver(t *testing.T) {
	fset, files, mainFn := mainFiles(t)

	// The calls that turn a channel into a signal destination. What must be
	// one is the CHANNEL, not the call: registering os.Interrupt and SIGTERM
	// in two statements names the same queue twice and adds no racer, so it is
	// a benign spelling. Two DIFFERENT channels is the defect.
	var notifies []*ast.CallExpr
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Notify" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "signal" {
					notifies = append(notifies, call)
				}
			}
			return true
		})
	}
	if len(notifies) == 0 {
		t.Fatal("main.go never calls signal.Notify")
	}
	sigName := ""
	for _, notify := range notifies {
		name := ""
		if len(notify.Args) > 0 {
			if id, ok := notify.Args[0].(*ast.Ident); ok {
				name = id.Name
			}
		}
		if name == "" {
			t.Fatalf("%s: signal.Notify's channel is not a plain identifier, so this test "+
				"cannot follow where it goes", fset.Position(notify.Pos()))
		}
		if sigName == "" {
			sigName = name
		} else if name != sigName {
			t.Fatalf("%s: signal.Notify registers a second channel %q alongside %q: each "+
				"registered channel is another queue the operating system's single delivery "+
				"can land in, and which one wakes is a race",
				fset.Position(notify.Pos()), name, sigName)
		}
	}

	// Every place in main that may name the signal channel: the assignment
	// that creates it, the Notify call above, and the single handoff to
	// stopOnSignal. Recorded by position, so anything else naming it — a
	// receive, a select clause, a capture by a goroutine literal, an argument
	// to a second consumer — is left over and fails below.
	allowed := map[token.Pos]bool{}
	for _, n := range notifies {
		allowed[n.Args[0].Pos()] = true
	}
	handoffs := 0
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == sigName {
					allowed[id.Pos()] = true
				}
			}
		case *ast.ValueSpec:
			// `var sig = make(...)` declares it just as `sig :=` does. The
			// spelling is not the property.
			for _, id := range s.Names {
				if id.Name == sigName {
					allowed[id.Pos()] = true
				}
			}
		case *ast.CallExpr:
			if id, ok := s.Fun.(*ast.Ident); ok && id.Name == "stopOnSignal" {
				for _, a := range s.Args {
					if aid, ok := a.(*ast.Ident); ok && aid.Name == sigName {
						allowed[aid.Pos()] = true
						handoffs++
					}
				}
			}
		}
		return true
	})
	if handoffs != 1 {
		t.Errorf("main hands the signal channel to stopOnSignal %d times; it must be exactly "+
			"one, because each call starts another goroutine receiving from the same "+
			"one-value channel", handoffs)
	}
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || id.Name != sigName || allowed[id.Pos()] {
			return true
		}
		t.Errorf("%s: main names the signal channel %q outside its declaration, "+
			"signal.Notify, and the handoff to stopOnSignal. signal.Notify delivers a signal "+
			"once, to whichever receiver is ready, so a second use of this channel is a "+
			"second racer and which one wakes decides whether the node shuts down at all", fset.Position(id.Pos()), sigName)
		return true
	})

	// stopOnSignal is the one receiver, and what it returns is what makes the
	// shutdown a broadcast: a receive-only channel of struct{}, only ever
	// closed. A bidirectional channel would let a caller send into it, and a
	// send is taken by exactly one receiver — the defect all over again.
	var stopOnSig *ast.FuncDecl
	for _, d := range allDecls(files) {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "stopOnSignal" {
			stopOnSig = fd
		}
	}
	if stopOnSig == nil {
		t.Fatal("main.go has no func stopOnSignal")
	}
	if stopOnSig.Type.Results == nil || len(stopOnSig.Type.Results.List) != 1 {
		t.Fatal("stopOnSignal does not return exactly one value")
	}
	if ch, ok := stopOnSig.Type.Results.List[0].Type.(*ast.ChanType); !ok || ch.Dir != ast.RECV {
		t.Errorf("stopOnSignal does not return a receive-only channel: a caller able to send "+
			"into the shutdown channel hands the shutdown to exactly one receiver again, "+
			"which is the defect; got %T", stopOnSig.Type.Results.List[0].Type)
	} else if st, ok := ch.Value.(*ast.StructType); !ok || st.Fields.NumFields() != 0 {
		t.Errorf("stopOnSignal's channel does not carry struct{}: a channel that carries a " +
			"value invites a send, and a send wakes one receiver")
	}

	// And it receives from its parameter exactly once. Twice is a second
	// delivery taken off the queue and never broadcast.
	param := ""
	if stopOnSig.Type.Params != nil && len(stopOnSig.Type.Params.List) == 1 &&
		len(stopOnSig.Type.Params.List[0].Names) == 1 {
		param = stopOnSig.Type.Params.List[0].Names[0].Name
	}
	if param == "" {
		t.Fatal("stopOnSignal does not take exactly one named parameter")
	}
	receives := 0
	ast.Inspect(stopOnSig.Body, func(n ast.Node) bool {
		u, ok := n.(*ast.UnaryExpr)
		if !ok || u.Op != token.ARROW {
			return true
		}
		if id, ok := u.X.(*ast.Ident); ok && id.Name == param {
			receives++
		}
		return true
	})
	if receives != 1 {
		t.Errorf("stopOnSignal receives from the signal channel %d times; one delivered "+
			"signal must become one close, and nothing else may take a value off that "+
			"channel", receives)
	}

	// The broadcast itself, which every check above only sets up. A receive-only
	// result stops a CALLER sending into the shutdown channel; it says nothing
	// about stopOnSignal, which holds the bidirectional end. Swap `close(stop)`
	// for `stop <- struct{}{}` inside it and every assertion so far still holds
	// while exactly one of the five waiters wakes — the same queue-not-broadcast
	// defect verbatim, one layer down. So: the returned channel is closed, and
	// nothing anywhere sends into it.
	stopName := ""
	for _, stmt := range stopOnSig.Body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		if id, ok := ret.Results[0].(*ast.Ident); ok {
			stopName = id.Name
		}
	}
	if stopName == "" {
		t.Fatal("stopOnSignal does not return a plain identifier, so this test cannot follow " +
			"what happens to the shutdown channel")
	}
	closes, sends := 0, 0
	ast.Inspect(stopOnSig.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.CallExpr:
			if id, ok := s.Fun.(*ast.Ident); ok && id.Name == "close" && len(s.Args) == 1 {
				if a, ok := s.Args[0].(*ast.Ident); ok && a.Name == stopName {
					closes++
				}
			}
		case *ast.SendStmt:
			if id, ok := s.Chan.(*ast.Ident); ok && id.Name == stopName {
				sends++
			}
		}
		return true
	})
	if closes != 1 || sends != 0 {
		t.Errorf("stopOnSignal closes the shutdown channel %d times and sends into it %d "+
			"times; it must close it exactly once and never send. A closed channel is the "+
			"broadcast a signal channel is not — every waiter sees it, forever — whereas a "+
			"send is taken by exactly one receiver and the other four loops keep running", closes, sends)
	}

	// The regression itself. Nothing but stopOnSignal may take a signal
	// channel as a parameter, in either direction.
	for _, d := range allDecls(files) {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name == "stopOnSignal" || fd.Type.Params == nil {
			continue
		}
		for _, p := range fd.Type.Params.List {
			ch, ok := p.Type.(*ast.ChanType)
			if !ok {
				continue
			}
			sel, ok := ch.Value.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Signal" {
				continue
			}
			t.Errorf("%s: %s takes a signal channel. That is exactly how the regression happened: "+
				"prefetchLoop was given one and became a fourth goroutine racing main for the "+
				"single delivered value. A loop takes the closed <-chan struct{} instead", fset.Position(p.Pos()), fd.Name.Name)
		}
	}
}

// The property, in one sentence: **main's unconditional defers are registered
// outermost-resource-first, so the shutdown unwinds p2p, then the hashers and
// the proof-of-work engine, then the chain.**
//
// Deferred registration order IS the teardown order read backwards, so this
// asserts the ordering itself rather than a proxy for it. Read the expected
// list from the bottom up and it is what a SIGTERM does: net.Stop() joins
// every p2p handler and peerStore.Save() writes the peer memory to disk; then
// closeEngine joins the mine and prefetch loops and closes the engine; then
// the chain store closes.
//
// Two adjacencies carry the whole property, and each is a defect reversed:
//
//   - net.Stop() before closeEngine. The p2p handlers verify proof of work, so
//     they hash against the same engine the miner does. Closing the engine
//     first is the engine closed under its own users, with a different set of
//     goroutines.
//   - status.Wait() last of all, so it unwinds first. The heartbeat reads the
//     chain, the mempool and the peer set once an interval, and it was
//     launched bare: `main` returned and `defer c.Close()` ran while it could
//     be inside that read. Joined ahead of every teardown step because it
//     reads what every one of them releases.
//   - closeEngine before c.Close(). closeEngine's first act is hashers.Wait(),
//     and mineLoop writes blocks to the chain, so a chain closed ahead of that
//     wait is a chain the miner is still using. That is the direction the
//     ordering has to run, and it is why the engine is closed before the chain
//     rather than after it. Both users are joined by then, so which of the two
//     closes first is otherwise unobservable — the constraint that decides it
//     is the wait, not the close.
//
// It asserts the exact list, so a new unconditional defer fails here until
// somebody decides where in the teardown it belongs. That is the intended
// failure: the harm in the signal-channel defect was a shutdown path that
// silently did not run, and a resource quietly inserted at the wrong depth is
// the same class of thing.
func TestMainRegistersItsTeardownOutermostResourceFirst(t *testing.T) {
	fset, files, mainFn := mainFiles(t)

	// What each unconditional defer must be, in registration order.
	want := []string{"c.Close", "closeEngine", "net.Stop+peerStore.Save", "status.Wait"}

	// describe names a defer by its structure. An unrecognised one returns "",
	// which fails below rather than being skipped.
	describe := func(d *ast.DeferStmt) string {
		switch fun := d.Call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == "closeEngine" {
				return "closeEngine"
			}
		case *ast.SelectorExpr:
			if x, ok := fun.X.(*ast.Ident); ok {
				return x.Name + "." + fun.Sel.Name
			}
		case *ast.FuncLit:
			// The p2p defer is a literal because two things happen in it and
			// their order matters too: peerStore.Save() must run after
			// net.Stop(), which is what stops the handlers still mutating the
			// peer set. Saving first writes a snapshot that is already stale.
			//
			// Only UNCONDITIONAL statements of the literal count. Matching any call
			// anywhere inside it accepts `if false { net.Stop() }`, which reads as a
			// join and performs none — the same evasion the first version of this
			// wiring check admitted. A call this test credits has to be a statement the
			// literal always executes.
			var calls []string
			for _, s := range fun.Body.List {
				var c *ast.CallExpr
				switch st := s.(type) {
				case *ast.ExprStmt:
					c, _ = st.X.(*ast.CallExpr)
				case *ast.IfStmt:
					// `if err := peerStore.Save(); err != nil` is the shape the
					// save is written in: the call is the init statement, so it
					// runs unconditionally even though a branch follows.
					if a, ok := st.Init.(*ast.AssignStmt); ok && len(a.Rhs) == 1 {
						c, _ = a.Rhs[0].(*ast.CallExpr)
					}
				}
				if c == nil {
					continue
				}
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok {
						calls = append(calls, x.Name+"."+sel.Sel.Name)
					}
				}
			}
			stop, save := -1, -1
			for i, c := range calls {
				if c == "net.Stop" && stop < 0 {
					stop = i
				}
				if c == "peerStore.Save" && save < 0 {
					save = i
				}
			}
			if stop >= 0 && save > stop {
				return "net.Stop+peerStore.Save"
			}
			if stop >= 0 || save >= 0 {
				t.Errorf("%s: the p2p defer runs net.Stop at position %d and peerStore.Save at "+
					"position %d; the peer set must be saved after the handlers that mutate it "+
					"have been joined, or the file records a snapshot taken mid-shutdown", fset.Position(d.Pos()), stop, save)
			}
		}
		return ""
	}

	// Direct children of main's body only. A defer inside `if !*noRPC { ... }`
	// is registered only when that branch is taken, so it is conditional and
	// deliberately outside this ordering.
	var got []string
	for _, stmt := range mainFn.Body.List {
		d, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		name := describe(d)
		if name == "" {
			t.Errorf("%s: main defers something this test does not recognise. Decide where in "+
				"the teardown it belongs and add it to the expected order — an unplaced defer "+
				"releases its resource at whatever depth it happened to be written",
				fset.Position(d.Pos()))
			continue
		}
		got = append(got, name)
	}

	if len(got) != len(want) {
		t.Fatalf("main registers %v as its unconditional teardown; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("main registers %v; want %v. Registration order is the teardown read "+
				"backwards, so this reorders the shutdown: the p2p handlers and the miner must "+
				"be joined before the engine they hash against is closed, and the miner "+
				"must be joined before the chain it writes to is closed", got, want)
		}
	}

	// The adjacency above is only worth asserting because of what closeEngine
	// does FIRST. The whole reason the engine is closed before the chain — and
	// the reason the brief's "engine last" order is wrong — is that closeEngine
	// begins by joining the hashers, and mineLoop writes blocks to the chain.
	// Move that wait behind the close (a `defer hashers.Wait()`, an early return)
	// and the defer list above is unchanged while both defects are back: the
	// engine is freed under its users, and the miner is still running when
	// c.Close() lands.
	var closeEng *ast.FuncDecl
	for _, d := range allDecls(files) {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "closeEngine" {
			closeEng = fd
		}
	}
	if closeEng == nil {
		t.Fatal("main.go has no func closeEngine")
	}
	if len(closeEng.Body.List) == 0 {
		t.Fatal("closeEngine has an empty body")
	}

	// WHICH group is waited on, bound to the parameter main hands it. Checking
	// only that the first statement is some `X.Wait()` is the same hole one level
	// down: `unrelated.Wait()` followed by `go func() { hashers.Wait() }()`
	// satisfies it while the hashers are never joined before the close, and so
	// does `unrelated.Wait()` with the parameter merely mentioned. That is the
	// lesson this teardown was written from — a join that joins a different group
	// is not a join — recurring inside the test written to prevent it.
	hashersParam := ""
	if closeEng.Type.Params != nil {
		for _, prm := range closeEng.Type.Params.List {
			star, ok := prm.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WaitGroup" {
				continue
			}
			if len(prm.Names) == 1 {
				hashersParam = prm.Names[0].Name
			}
		}
	}
	if hashersParam == "" {
		t.Fatal("closeEngine does not take exactly one named *sync.WaitGroup: the group it " +
			"joins has to be the one main registers its hashers in, and this test cannot " +
			"tell which group is waited on otherwise")
	}

	first, ok := closeEng.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatalf("%s: closeEngine's first statement is %T, not the join. It must wait for "+
			"every goroutine that hashes against the engine before anything else happens", fset.Position(closeEng.Body.List[0].Pos()), closeEng.Body.List[0])
	} else if call, ok := first.X.(*ast.CallExpr); !ok {
		t.Errorf("%s: closeEngine's first statement is not a call", fset.Position(first.Pos()))
	} else if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Wait" {
		t.Errorf("%s: closeEngine's first statement is not a Wait on the hashers. The join "+
			"has to happen before the engine is closed, or the engine is released under the "+
			"threads inside it; and before c.Close() runs, or the chain is closed "+
			"under a miner still writing blocks to it", fset.Position(first.Pos()))
	} else if x, ok := sel.X.(*ast.Ident); !ok || x.Name != hashersParam {
		t.Errorf("%s: closeEngine's first statement waits on something other than %q, the "+
			"WaitGroup main registers every hasher in. A Wait on a different group returns "+
			"immediately and joins nobody, which frees the engine under the threads inside "+
			"it and closes the chain under a running miner",
			fset.Position(first.Pos()), hashersParam)
	}

	// And the wait is that statement, not a copy of it running later or
	// elsewhere. A `go func() { hashers.Wait() }()` or a `defer hashers.Wait()`
	// anywhere in the body means the close does not wait for it, whatever the
	// first statement says.
	ast.Inspect(closeEng.Body, func(n ast.Node) bool {
		var body ast.Node
		var what string
		switch st := n.(type) {
		case *ast.GoStmt:
			body, what = st.Call, "a goroutine"
		case *ast.DeferStmt:
			body, what = st.Call, "a defer"
		case *ast.FuncLit:
			body, what = st.Body, "a function literal"
		default:
			return true
		}
		ast.Inspect(body, func(m ast.Node) bool {
			id, ok := m.(*ast.Ident)
			if !ok || id.Name != hashersParam {
				return true
			}
			t.Errorf("%s: closeEngine names %q inside %s. The join has to complete before "+
				"the engine is closed; deferring it or handing it to a goroutine puts the "+
				"close first while the body still reads as if it waits",
				fset.Position(id.Pos()), hashersParam, what)
			return true
		})
		return false
	})
}

// The property, in one sentence: **every goroutine `main` launches is joined by
// something `main` defers, so no goroutine can still be reading the chain when
// `defer c.Close()` runs.**
//
// The regression this pins — a goroutine no defer joins at all — is orthogonal
// to the teardown ORDER the test above fixes. That test asserts what the
// defers are and in which order they unwind; it cannot see a goroutine that no
// defer covers at all. Two were outside the accounting entirely:
//
//   - `go heartbeat(c, net, pool, stop)`, launched bare. It reads c.Tip(),
//     c.Height() and c.Stats() once an interval. Nothing registered it and
//     nothing waited for it, so `main` returned from `<-stop` and the chain
//     store was closed while the heartbeat could be inside that read.
//   - the RPC serve goroutine, whose handlers hold `c` and `pool` for the whole
//     of a request. `srv.Close()` is http.Server.Close: it shuts the listeners
//     and returns without waiting for a handler already running.
//
// So there are exactly two ways a launched goroutine may be accounted for, and
// this test admits only those two:
//
//  1. a WaitGroup main defers a Wait on — either `defer X.Wait()` directly, or
//     by handing &X to closeEngine, which waits on it first thing;
//  2. the RPC serve loop, which is joined instead by Shutdown: it leaves Serve
//     when the server stops, and Shutdown does not return until the handlers
//     inside it have finished. Close does not, which is why naming Close here
//     is not accounted for.
//
// Anything else fails, and the failure is the intended prompt: a new goroutine
// in main has to be given a join before it is allowed to read anything main
// closes.
func TestEveryGoroutineMainLaunchesIsJoinedBeforeTheChainCloses(t *testing.T) {
	fset, _, mainFn := mainFiles(t)

	// serveTarget reports whether a serve loop is started anywhere under n, and
	// on which identifier. A receiver that is not a plain identifier -- a
	// struct field, say -- is reported as started with no name, and fails
	// below: this test reasons about a server by the local it is bound to, and
	// it must say so rather than quietly skip a serve loop it cannot name.
	serveTarget := func(n ast.Node) (bool, string) {
		started, name := false, ""
		ast.Inspect(n, func(m ast.Node) bool {
			sel, ok := m.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ListenAndServe" {
				return true
			}
			started = true
			if x, ok := sel.X.(*ast.Ident); ok {
				name = x.Name
			}
			return true
		})
		return started, name
	}

	// Every goroutine main launches, with the chain of blocks that ENCLOSE it,
	// and every defer main registers, with the innermost block that encloses
	// IT. Nested goroutines are skipped: a defer inside a goroutine is that
	// goroutine's own teardown, not main's.
	//
	// The blocks are the point, and they are round three on this check. Keying a
	// server's teardown by identifier NAME alone collapses two servers that share
	// a local name in sibling scopes -- `srv` inside `if !*noRPC` and `srv`
	// inside another `if`, which is ordinary Go -- into one entry, so a second
	// server correctly shut down vouched for the real one still on `Close` and
	// the unjoined-goroutine regression passed with only the launch count left to
	// object. A defer accounts for a launch only if it sits in a block that
	// contains that launch; a sibling block does not.
	type launch struct {
		stmt      *ast.GoStmt
		enclosing map[*ast.BlockStmt]bool
	}
	type registered struct {
		stmt  *ast.DeferStmt
		block *ast.BlockStmt
	}
	var launches []launch
	var deferred []registered

	var stack []ast.Node
	// inGoroutine reports whether the node being visited sits under a `go`
	// statement. It excludes two things, and the second is a scope boundary
	// worth stating rather than a gap to be closed.
	//
	// A defer inside a goroutine is that goroutine's own teardown, not main's,
	// so it must not be read as a join.
	//
	// And a `go` statement nested INSIDE a goroutine main launched is therefore
	// neither checked here nor counted in the launch total below. That is
	// inherent to reading `main`: this test's whole subject is what main itself
	// launches and what main itself defers, and a goroutine spawned by another
	// goroutine is joined -- or not -- by rules that are not in main's body at
	// all. Closing it would mean following every function main calls, which is
	// a different test. If a launch moves inside another goroutine, the count
	// below is what notices.
	inGoroutine := func() bool {
		// The last element is the node itself, so its own ancestors are the
		// rest.
		for i := 0; i < len(stack)-1; i++ {
			if _, ok := stack[i].(*ast.GoStmt); ok {
				return true
			}
		}
		return false
	}
	enclosingBlocks := func() map[*ast.BlockStmt]bool {
		out := map[*ast.BlockStmt]bool{}
		for _, n := range stack {
			if b, ok := n.(*ast.BlockStmt); ok {
				out[b] = true
			}
		}
		return out
	}
	innermostBlock := func() *ast.BlockStmt {
		for i := len(stack) - 1; i >= 0; i-- {
			if b, ok := stack[i].(*ast.BlockStmt); ok {
				return b
			}
		}
		return nil
	}

	// This always returns true, so that Inspect's closing nil call pairs with
	// every node and the ancestor stack stays balanced. Nesting is handled by
	// asking the stack, not by pruning the walk.
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch node := n.(type) {
		case *ast.GoStmt:
			if !inGoroutine() {
				launches = append(launches, launch{stmt: node, enclosing: enclosingBlocks()})
			}
		case *ast.DeferStmt:
			if !inGoroutine() {
				deferred = append(deferred, registered{stmt: node, block: innermostBlock()})
			}
		}
		return true
	})

	// The teardown deferred on a given server for a given launch: only defers
	// sitting in a block that encloses that launch are eligible for it.
	//
	// KNOWN STRICTNESS, so it is not a surprise: a teardown wrapped in a block
	// that neither contains the launch nor is contained by it -- a separate
	// `if x != nil { defer ... }` beside the block the launch is in -- is not
	// eligible, and this check fails on correct code. The fix is to put the
	// defer directly in the enclosing block with the nil test inside the
	// closure, which is the ordinary shape and passes.
	//
	// Where that can actually bite is narrower than it looks, and only on the
	// WaitGroup branch. For a SERVER it is unreachable: naming the same server
	// from a block that does not enclose the launch needs either a second
	// declaration or a re-assignment, and the binding rule below is checked
	// first and fails there instead. For a GROUP, one declared once and never
	// assigned can be named from a sibling block, so a `defer status.Wait()`
	// moved into one fails here -- which is the point, since a Wait that only
	// sometimes runs joins nobody on the paths where it does not.
	//
	// Loosening this to positional containment -- "the defer is somewhere
	// inside a block that also contains the launch" -- is exactly what let a
	// defer in a sibling `if` block vouch for a launch it had nothing to do
	// with, so the strictness is deliberate and is not to be relaxed without
	// replacing it with something that closes that hole.
	teardownFor := func(l launch, name string) string {
		found := ""
		for _, d := range deferred {
			if !l.enclosing[d.block] {
				continue
			}
			ast.Inspect(d.stmt, func(m ast.Node) bool {
				sel, ok := m.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Shutdown" && sel.Sel.Name != "Close") {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if !ok || x.Name != name {
					return true
				}
				// Shutdown wins over Close if both are present on the same
				// server: a Close beside a Shutdown does not un-join handlers.
				if found != "Shutdown" {
					found = sel.Sel.Name
				}
				return true
			})
		}
		return found
	}

	// A name a launch is accounted for by -- a server, or a WaitGroup -- must
	// denote ONE object for the whole of main: declared once, and assigned at
	// most once on top of that declaration.
	//
	// Two separate escapes, and the counts are split because the honest shapes
	// differ. Block scoping cannot see through SHADOWING: an outer `srv`
	// correctly shut down does enclose an inner `srv := rpc.New(...)` on
	// `Close`, so the outer teardown is eligible for the inner launch and
	// vouches for a server it never refers to. And counting declarations alone
	// misses RE-ASSIGNMENT: `srv := rpc.New(cfg)` followed by
	// `srv = rpc.New(adminCfg)` is one declaration and two live servers, and
	// the deferred closure drains the second while the first serves on. Both
	// were live against earlier versions of this test.
	//
	// The rule is: declared exactly once, and never assigned to afterwards.
	// A bare `var status sync.WaitGroup` and a `srv := rpc.New(...)` are both
	// legal, and they are how main actually spells the two.
	//
	// KNOWN STRICTNESS, disclosed rather than smoothed over: this also refuses
	// `var srv *rpc.Server` followed by a single `srv = rpc.New(...)`, which is
	// legal Go and denotes one server. The looser rule that would admit it -- at
	// most one VALUE-producing write, counting a bare `var` as none -- was tried
	// and rejected, because it admits `var status sync.WaitGroup; status.Add(1);
	// ...; status = sync.WaitGroup{}` as one write too, and that resets the
	// counter to zero so the deferred Wait returns immediately and joins nobody.
	// Telling those two apart needs to know whether the write lands before or
	// after the Add, which is a dataflow question this check cannot answer. The
	// strict rule costs a rewrite to `srv := rpc.New(...)`; the loose one costs
	// the guarantee that every launch is joined.
	declared, assigned := map[string]int{}, map[string]int{}
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			counter := assigned
			if node.Tok == token.DEFINE {
				counter = declared
			} else if node.Tok != token.ASSIGN {
				// Compound assignment (+=, and friends) cannot rebind a server
				// or a group to a different object.
				return true
			}
			for _, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					counter[id.Name]++
				}
			}
		case *ast.ValueSpec:
			for _, id := range node.Names {
				declared[id.Name]++
			}
		case *ast.RangeStmt:
			if node.Tok != token.DEFINE {
				return true
			}
			for _, e := range []ast.Expr{node.Key, node.Value} {
				if id, ok := e.(*ast.Ident); ok {
					declared[id.Name]++
				}
			}
		}
		return true
	})

	// bindingFault describes why a name cannot be trusted to denote one object,
	// or "" if it can.
	bindingFault := func(name string) string {
		switch {
		case declared[name] != 1:
			return fmt.Sprintf("%q is declared %d times in main", name, declared[name])
		case assigned[name] > 0:
			return fmt.Sprintf("%q is declared once and then assigned %d more time(s)",
				name, assigned[name])
		}
		return ""
	}

	// joinedFor reports whether main waits on the group `name` in a block that
	// encloses this launch: `defer name.Wait()`, or `&name` handed to
	// closeEngine, whose first statement is asserted to be that Wait by the
	// test above. A group nothing waits on is not a join -- registering a
	// goroutine in it and never waiting leaves the process exactly where it
	// was -- and a Wait in a SIBLING block joins a different scope's group.
	joinedFor := func(l launch, name string) bool {
		for _, d := range deferred {
			if !l.enclosing[d.block] {
				continue
			}
			switch fun := d.stmt.Call.Fun.(type) {
			case *ast.SelectorExpr:
				if x, ok := fun.X.(*ast.Ident); ok && fun.Sel.Name == "Wait" && x.Name == name {
					return true
				}
			case *ast.Ident:
				if fun.Name != "closeEngine" {
					continue
				}
				for _, a := range d.stmt.Call.Args {
					u, ok := a.(*ast.UnaryExpr)
					if !ok || u.Op != token.AND {
						continue
					}
					if id, ok := u.X.(*ast.Ident); ok && id.Name == name {
						return true
					}
				}
			}
		}
		return false
	}

	// addsTo reports whether main increments group before pos, outside any
	// goroutine of its own. An Add inside the goroutine it is meant to register
	// races the Wait: the group can be at zero when Wait runs.
	addsTo := func(group string, pos token.Pos) bool {
		found := false
		ast.Inspect(mainFn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Add" {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == group && call.Pos() < pos {
				found = true
			}
			return true
		})
		return found
	}

	for _, l := range launches {
		g := l.stmt
		where := fset.Position(g.Pos())

		// Case 2 first: an RPC serve loop, checked against the teardown
		// deferred on ITS OWN identifier, in a block that encloses it.
		if started, name := serveTarget(g); started {
			switch {
			case name == "":
				t.Errorf("%s: main starts a serve loop on something that is not a plain "+
					"identifier, so this check cannot tell which teardown belongs to it. A "+
					"serve loop has to be bound to a local main can defer a Shutdown on", where)
			case bindingFault(name) != "":
				t.Errorf("%s: %s. A serve loop's local must denote one server for the whole "+
					"of main, or a teardown deferred on that name may refer to another "+
					"server entirely - a shadowed or re-assigned name lets one server's "+
					"Shutdown vouch for another server's Close, and the first one is never "+
					"drained", where, bindingFault(name))
			default:
				switch teardownFor(l, name) {
				case "Shutdown":
				case "Close":
					t.Errorf("%s: main launches a serve loop on %q and defers %s.Close(). "+
						"http.Server.Close shuts the listeners and the idle connections and "+
						"returns at once; it does not wait for a handler already inside the "+
						"mux, and a handler holds the chain and the mempool for its whole "+
						"run - so c.Close() lands under a live reader of the store. "+
						"Shutdown(ctx) is the one that waits", where, name, name)
				default:
					t.Errorf("%s: main launches a serve loop on %q and defers nothing on %q "+
						"in any block enclosing it that waits for its handlers. They hold "+
						"the chain for the whole of a request", where, name, name)
				}
			}
			continue
		}

		// Case 1: registered in a group main waits on. The launch must be a
		// literal whose FIRST statement is `defer X.Done()` - first, because a
		// Done registered after work has begun is not what the group counts,
		// and deferred, because a goroutine that panics or returns early must
		// still decrement or the Wait never returns.
		lit, ok := g.Call.Fun.(*ast.FuncLit)
		if !ok || len(lit.Body.List) == 0 {
			t.Errorf("%s: main launches a bare goroutine. Nothing registers it and nothing "+
				"waits for it, so it is still running when main's defers release what it "+
				"reads - which is exactly how the heartbeat came to read the chain after "+
				"c.Close()", where)
			continue
		}
		first, ok := lit.Body.List[0].(*ast.DeferStmt)
		if !ok {
			t.Errorf("%s: this goroutine's first statement is not a deferred Done. It has to "+
				"be deferred and first, or an early return leaves the group above zero and "+
				"the join never returns", where)
			continue
		}
		sel, ok := first.Call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Done" {
			t.Errorf("%s: this goroutine does not defer a Done on a WaitGroup", where)
			continue
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			t.Errorf("%s: this goroutine's Done is not on a plain identifier, so this test "+
				"cannot tell which group it registers with", where)
			continue
		}
		// The same two conditions as the serve loop above, because the same two
		// escapes exist here and this branch covers three of the four launches. A
		// `var status sync.WaitGroup` shadowed inside an `if`, holding a second
		// heartbeat that reads c.Tip/Height/Stats and that nothing waits on, was the
		// original defect verbatim and passed when only Case 2 was guarded.
		if fault := bindingFault(id.Name); fault != "" {
			t.Errorf("%s: %s. A group a launch is registered in must denote one WaitGroup "+
				"for the whole of main, or the Wait main defers may be on a different "+
				"group than the one this goroutine counts itself into - which joins "+
				"nobody", where, fault)
			continue
		}
		if !joinedFor(l, id.Name) {
			t.Errorf("%s: this goroutine registers with %q, which main never waits on in "+
				"any block enclosing it - neither `defer %s.Wait()` nor a handoff to "+
				"closeEngine. A group nobody joins counts a goroutine that nothing waits "+
				"for, and a Wait in a sibling block joins a different scope's group", where, id.Name, id.Name)
			continue
		}
		if !addsTo(id.Name, g.Pos()) {
			t.Errorf("%s: nothing increments %q before this launch, outside any goroutine. "+
				"Wait on a group at zero returns immediately and joins nobody",
				where, id.Name)
		}
	}

	// Every known launch site, so a refactor that hides one behind a helper
	// does not leave this test passing over the rest alone.
	if len(launches) != 4 {
		t.Errorf("main launches %d goroutines; this test was written against four - the RPC "+
			"serve loop, the heartbeat, the prefetch loop and the mine loop. A different "+
			"count means one is no longer visible here and is no longer checked",
			len(launches))
	}
}
