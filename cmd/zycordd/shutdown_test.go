package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zycord/core/types"
)

// The property, in one sentence: **the proof-of-work engine is closed only
// after every goroutine that hashes against it has returned.**
//
// It is an ownership property, and the harm it prevents is not the
// use-after-free this join was originally filed against. The RandomX engine
// owns C allocations and Close calls randomx_release_dataset and
// randomx_release_cache on them. Before the engine grew its own fmu write lock
// over Close, that happened under a live randomx_calculate_hash and was a
// use-after-free across the cgo boundary; today Close takes fmu for write and
// drains its fast VMs first, so the release waits and no fault is reachable.
// What is left is that a hasher arriving after Close builds a fresh entry the
// engine will never free — a leaked cache, reclaimed by the OS at exit. The
// reason to pin the ordering anyway is that a process must not close a
// resource still in use, and must not depend on the engine's locking to be
// correct.
//
// countingEngine is the observation the real engine cannot give a test on a
// machine with no C toolchain: it counts hashes that are IN FLIGHT and records
// how many were in flight at the moment Close was called. Anything but zero is
// the defect.
type countingEngine struct {
	inFlight atomic.Int64
	// atClose is the in-flight count Close observed. -1 means never closed.
	atClose atomic.Int64
	// entered is closed by the first hash, so a test can know a hash is
	// genuinely in progress rather than hope it is.
	entered   sync.Once
	enteredCh chan struct{}
	// hashFor is how long one hash occupies the engine. A RandomX hash is
	// milliseconds of C; this stands in for that window.
	hashFor time.Duration
}

func newCountingEngine(hashFor time.Duration) *countingEngine {
	e := &countingEngine{enteredCh: make(chan struct{}), hashFor: hashFor}
	e.atClose.Store(-1)
	return e
}

func (e *countingEngine) Name() string { return "counting" }

func (e *countingEngine) Hash(key types.Hash, input []byte) types.Hash {
	e.inFlight.Add(1)
	defer e.inFlight.Add(-1)
	e.entered.Do(func() { close(e.enteredCh) })
	time.Sleep(e.hashFor)
	return types.Hash{}
}

func (e *countingEngine) Close() error {
	e.atClose.Store(e.inFlight.Load())
	return nil
}

// hashUntil reproduces what mineLoop and prefetchLoop do: hash against the
// shared engine until the process-wide stop channel closes. It deliberately
// keeps a hash in flight ACROSS the shutdown, which is the case the bug is in
// — a loop that only checks stop between hashes would never observe it.
func hashUntil(e *countingEngine, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		e.Hash(types.Hash{}, nil)
	}
}

func TestTheEngineOutlivesEveryGoroutineThatHashesAgainstIt(t *testing.T) {
	e := newCountingEngine(200 * time.Millisecond)
	stop := make(chan struct{})

	var hashers sync.WaitGroup
	for i := 0; i < 4; i++ {
		hashers.Add(1)
		go func() {
			defer hashers.Done()
			hashUntil(e, stop)
		}()
	}

	<-e.enteredCh // a hash is genuinely in progress
	close(stop)   // this is main's `<-stop` returning
	closeEngine(e, &hashers)

	if got := e.atClose.Load(); got != 0 {
		t.Fatalf("the engine was closed with %d hashes still inside it; "+
			"in the RandomX engine that is randomx_release_dataset reached "+
			"while nonce goroutines are still using the engine — today the "+
			"engine's own fmu makes that wait rather than fault, and a late "+
			"hasher leaks a fresh cache instead, but the process must not be "+
			"relying on either", got)
	}
}

// TestClosingWithoutJoiningLeavesHashesInsideTheEngine is the control, and
// without it the test above asserts nothing: it shows that the SAME scenario,
// with the pre-fix ordering — main's deferred Close firing while the mine and
// prefetch loops run on, joined by nothing — does report hashes inside the
// engine at Close.
//
// It is named for what it observes rather than for what that used to cause. An
// earlier name said "WouldFault", which named an outcome this branch's own
// finding shows is unreachable: since the engine's Close began taking fmu for
// write and draining its fast VMs, a hash inside the engine at Close is not a
// fault, it is a Close that waited, plus a leaked entry if the hasher arrived
// late. The observation — hashes inside the engine — is what survives that
// correction, so it is what the name says.
//
// Same engine, same hashers, same timings; only the teardown order differs.
func TestClosingWithoutJoiningLeavesHashesInsideTheEngine(t *testing.T) {
	e := newCountingEngine(200 * time.Millisecond)
	stop := make(chan struct{})

	var hashers sync.WaitGroup
	for i := 0; i < 4; i++ {
		hashers.Add(1)
		go func() {
			defer hashers.Done()
			hashUntil(e, stop)
		}()
	}

	<-e.enteredCh
	close(stop)
	// The pre-fix sequence: close the engine, do not join anybody.
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	inside := e.atClose.Load()
	hashers.Wait()

	if inside == 0 {
		t.Fatal("the scenario did not keep a hash in flight across Close, so " +
			"the test above would pass against the broken code too")
	}
}

// The property, in one sentence: **`main` registers `mineLoop` and
// `prefetchLoop` with the WaitGroup `closeEngine` joins, before it starts
// them, and defers that join ahead of starting them.**
//
// The test above pins closeEngine — given a WaitGroup, it waits. That is half
// the fix. The other half is the finding this file exists for, which is about
// `main`'s wiring: deleting one `hashers.Add(1)`, or unhooking `closeEngine`
// from the defer stack, leaves closeEngine correct and the process back to
// closing an engine its own goroutines are still using. A unit test cannot see
// that, by construction — `main` reads flags, binds a listener and opens a
// store, so it is not callable from a test. It is visible to one pass over the
// syntax tree, which is the same move sim/wiring makes for the two subsystems
// that were correct, complete and called from nowhere.
//
// For each `go` statement in `main` that runs a hashing loop it asserts that
// some `hashers.Add(n)` with n > 0 appears EARLIER in the same block — the
// property is that the registration happens-before the launch, not that it is
// the statement immediately above, which a stray log line would break without
// breaking anything real — and that the goroutine's body defers
// `hashers.Done()`. Then: that `closeEngine` is reached by a `defer`, not
// merely mentioned, and that the defer is registered before the launches, so
// LIFO puts the join after them.
//
// The name says mineLoop and prefetchLoop rather than "every hashing
// goroutine" because that is what it can check: the list below is hardcoded,
// so a THIRD hashing loop added to main is precisely the case this cannot see.
// The list being fully found is asserted, which makes the failure mode a
// silent gap on new code and never a false pass on the code that exists.
func TestMineLoopAndPrefetchLoopAreRegisteredWithTheGroupCloseEngineJoins(t *testing.T) {
	// The loops that call into the proof-of-work engine.
	hashingLoops := map[string]bool{"mineLoop": true, "prefetchLoop": true}

	// The WaitGroup main uses. Named once so that the registration checks and
	// the defer check are provably talking about the SAME group: an Add on one
	// group and a Wait on another is a wait that returns immediately.
	const group = "hashers"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}

	var mainFn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "main" {
			mainFn = fd
		}
	}
	if mainFn == nil {
		t.Fatal("no func main in main.go")
	}

	// hashersCall reports whether a node is a call to hashers.<name>, and its
	// first argument if that argument is an integer literal.
	hashersCall := func(n ast.Node, name string) (arg int, ok bool) {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return 0, false
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != name {
			return 0, false
		}
		x, isIdent := sel.X.(*ast.Ident)
		if !isIdent || x.Name != group {
			return 0, false
		}
		if len(call.Args) == 1 {
			if lit, isLit := call.Args[0].(*ast.BasicLit); isLit && lit.Kind == token.INT {
				n, err := strconv.Atoi(lit.Value)
				if err == nil {
					return n, true
				}
			}
		}
		// A non-literal argument is not something this test can evaluate; it
		// is reported as a registration of unknown size rather than none, so
		// the test does not fail for code it merely cannot read.
		return 1, true
	}

	// calledLoop returns which hashing loop a `go` statement runs, if any.
	calledLoop := func(gos *ast.GoStmt) string {
		var loop string
		ast.Inspect(gos, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && hashingLoops[id.Name] {
					loop = id.Name
				}
			}
			return true
		})
		return loop
	}

	// The defer that hooks the join into the shutdown path, and three ways of
	// looking like it without being it:
	//
	//   - not a DeferStmt at all. `closeEngine(work, &hashers)` called, or
	//     merely named, does not run at shutdown.
	//   - deferred somewhere OTHER than main's own statement list. A defer
	//     inside `if *mine { ... }` is registered only when that branch is
	//     taken, so a non-mining node would run prefetchLoop unjoined and
	//     never close the engine at all. Only a direct element of the body is
	//     unconditional, which is the property wanted.
	//   - deferred on a DIFFERENT WaitGroup than the one the launches register
	//     with. `defer closeEngine(work, &other)` joins a group nobody ever
	//     adds to: it returns immediately and the wait is decorative. So the
	//     argument is read, and it has to be the same group checked below.
	//
	// Position matters too: registered BEFORE the launches is what guarantees
	// it unwinds after them and after everything deferred later.
	closeEngineDefer := token.NoPos
	for _, stmt := range mainFn.Body.List {
		d, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		id, ok := d.Call.Fun.(*ast.Ident)
		if !ok || id.Name != "closeEngine" {
			continue
		}
		// The group it joins must be the group the launches register with.
		joined := ""
		if len(d.Call.Args) == 2 {
			if u, ok := d.Call.Args[1].(*ast.UnaryExpr); ok && u.Op == token.AND {
				if g, ok := u.X.(*ast.Ident); ok {
					joined = g.Name
				}
			}
		}
		if joined != group {
			t.Errorf("%s: main defers closeEngine on %q, but the launches below register "+
				"with %q — a Wait on a group nothing was added to returns immediately, "+
				"so the engine is closed with its hashers still running",
				fset.Position(d.Pos()), joined, group)
			continue
		}
		closeEngineDefer = d.Pos()
	}
	if !closeEngineDefer.IsValid() {
		t.Fatal("main does not `defer closeEngine(work, &" + group + ")` as a direct " +
			"statement of its own body: calling it, naming it, or deferring it inside a " +
			"conditional branch is not the same as hooking it unconditionally into the " +
			"shutdown path — nothing joins the hashers and nothing closes the engine")
	}

	found := map[string]bool{}
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			gos, ok := stmt.(*ast.GoStmt)
			if !ok {
				continue
			}
			loop := calledLoop(gos)
			if loop == "" {
				continue
			}
			found[loop] = true

			// Registered before the goroutine exists — anywhere earlier in
			// this block. An Add inside the goroutine would race the Wait
			// that is supposed to see it, and Add(0) registers nothing.
			registered := false
			for _, earlier := range block.List[:i] {
				expr, ok := earlier.(*ast.ExprStmt)
				if !ok {
					continue
				}
				if n, ok := hashersCall(expr.X, "Add"); ok && n > 0 {
					registered = true
				}
			}
			if !registered {
				t.Errorf("%s: nothing earlier in this block registers the goroutine running %s "+
					"with hashers.Add(n>0), so closeEngine's Wait cannot see it and the engine "+
					"is closed while it is still using it",
					fset.Position(gos.Pos()), loop)
			}

			if gos.Pos() < closeEngineDefer {
				t.Errorf("%s: the goroutine running %s is started before "+
					"`defer closeEngine(...)` is registered, so an early return between the "+
					"two leaves it running with nothing to join it",
					fset.Position(gos.Pos()), loop)
			}

			lit, ok := gos.Call.Fun.(*ast.FuncLit)
			if !ok {
				t.Errorf("%s: the goroutine running %s is not a literal, so it cannot carry "+
					"defer hashers.Done()", fset.Position(gos.Pos()), loop)
				continue
			}
			done := false
			for _, s := range lit.Body.List {
				d, ok := s.(*ast.DeferStmt)
				if !ok {
					continue
				}
				if _, ok := hashersCall(d.Call, "Done"); ok {
					done = true
				}
			}
			if !done {
				t.Errorf("%s: the goroutine running %s does not defer hashers.Done(), "+
					"so closeEngine's Wait never returns and shutdown hangs",
					fset.Position(gos.Pos()), loop)
			}
		}
		return true
	})

	for loop := range hashingLoops {
		if !found[loop] {
			t.Errorf("main starts no goroutine running %s: the loop was renamed or moved, "+
				"and this test silently stopped checking it", loop)
		}
	}
}
