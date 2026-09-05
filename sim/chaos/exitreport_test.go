package chaos_test

// What the soak can say about a node that stopped answering.
//
// The failure that produced this file is an outbound-only follower found dead
// under load with a 279-byte log and a refused dial, never returning and
// failing convergence. It is a sighting rather than a diagnosis for one reason:
// nothing reaped the process, so "exited 1", "terminated from outside" and
// "alive but wedged" reached the report as the same fact. These tests pin the
// separation of those three, and pin that the separation is actually wired into
// the place the regime reports an unreachable node — a report that exists and
// is not reached is worth exactly as much as the sighting was.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The property: **exitReport tells apart every fate an unreachable node's
// process can be in, and names the exit code when there is one.**
//
// The rows are the fates, not the spellings, and each one is produced by a
// real operating-system process except the two that cannot be: a node the
// harness stopped and did not restart, and a Cmd that was never started. A
// ProcessState is something the OS hands back for a child it reaped, so an
// in-process double would be testing the double.
//
// The exit code is asserted with its closing bracket — "(code 3)" — because a
// substring check for "code 3" is satisfied by "code 30" and by "code 13", and
// a report that says the wrong number is worse than one that says nothing.
func TestExitReportSeparatesEveryFateAnUnreachableNodeCanBeIn(t *testing.T) {
	for _, row := range []struct {
		name string
		// fate is the value of ZCD_SOAK_CHILD_FATE for the child this row
		// spawns; "" means the row builds its node without spawning one.
		fate string
		// kill terminates the child before the report is taken.
		kill bool
		// node overrides the node under report entirely.
		node func() *soakNode
		// logBody, when set, is written to a file and hung on the spawned node
		// as its logPath, so the report can read the node's own log the way the
		// regime does. It is how the "RPC never bound" fate is staged: a child
		// spawned live (so the report reaches the same branch a wedged node
		// would) whose log carries the bind failure that separates the two.
		logBody string
		want    string
		// deny holds fragments this row's report must NOT carry, so that a
		// report which says every outcome at once cannot pass every row. A
		// list rather than one string because strengthening a row must be an
		// addition: swapping one denial for a better one buys nothing.
		deny []string
	}{
		{
			name: "a node the harness stopped and did not restart",
			node: func() *soakNode { return &soakNode{name: "stopped"} },
			want: "no process",
			deny: []string{"process exited", "still running"},
		},
		{
			name: "a process that chose to exit cleanly",
			fate: "0",
			want: "(code 0)",
			deny: []string{"still running", "no process"},
		},
		{
			// The whole rendering, not only the number. ProcessState.String()
			// is the half that carries "signal: killed" on the platforms that
			// have signals, so it is the half that separates a decision the
			// binary made from one made about it — and a row that reads only
			// the code cannot see it being dropped. "exit status 3" is what
			// String() renders for a process that exited 3 on every platform,
			// so asserting it here costs no portability.
			name: "a process that chose to exit with a diagnosis",
			fate: "3",
			want: "exit status 3 (code 3)",
			deny: []string{"(code 0)", "still running"},
		},
		{
			// What this row can assert is bounded by the platform, and saying
			// so is better than a row that looks like it proves more. Windows
			// has no signals: TerminateProcess sets exit code 1, which is
			// exactly what zycordd reports through fatal()'s os.Exit(1), so
			// the report reads "exit status 1 (code 1)" for both and only the
			// stderr line above it tells them apart. The same input on a
			// platform with signals reports "signal: killed". Asserted here is
			// the part that holds on both.
			name: "a process terminated from outside",
			fate: "live",
			kill: true,
			want: "process exited",
			// "(code 0)" is the portable half of the separation this row can
			// still make: nothing terminated from outside exits 0 on either
			// platform — Windows reports the 1 TerminateProcess sets, and a
			// signalled process reports -1. Without it the row asserted only
			// fragments every exit produces, and separated nothing at all.
			deny: []string{"still running", "(code 0)"},
		},
		{
			name: "a process that is alive while its RPC is not",
			fate: "live",
			// The rendered bound, from the named constant rather than a
			// retyped literal, so that dropping `within` from the message —
			// or rendering something other than the grace that was waited —
			// is not invisible here.
			want: "still running after " + exitReportGrace.String(),
			deny: []string{"process exited", "no process"},
		},
		{
			// The third fate an unreachable node can be in, and the one the row above
			// would once have swallowed: a process that is alive, healthy and syncing
			// whose RPC never bound because the port was taken before startup. It is
			// spawned live, exactly like the wedged row, so it reaches the same branch —
			// what separates them is the node's own log, which here carries the "...:
			// bind: ..." line cmd/zycordd writes and keeps running past. The report must
			// read that line and name the port, not pronounce the node wedged.
			name: "a live process whose RPC never bound",
			fate: "live",
			logBody: "2026/08/26 08:40:07 rpc listening on 127.0.0.1:54321 (read-only)\n" +
				"2026/08/26 08:40:07 rpc not listening on 127.0.0.1:54321: " +
				"listen tcp 127.0.0.1:54321: bind: address already in use\n",
			want: "port 54321",
			// "wedged" is the whole point: the fault this fate does NOT have.
			// Denying it, and "no process", is what makes the row fail if the
			// third arm is reverted — the branch then falls through to the
			// wedged sentence, which carries neither the port nor the truth.
			deny: []string{"wedged", "no process", "process exited"},
		},
		{
			// The gate on the row above: a live node WITH a log that carries no
			// bind failure is still wedged. Without this, a reader that fired on
			// any non-empty log would pass every check and report "never bound"
			// against genuinely wedged nodes — the same wrong-owner mistake in
			// the other direction.
			name: "a live process whose log carries no bind failure",
			fate: "live",
			logBody: "2026/08/26 08:40:07 rpc listening on 127.0.0.1:54321 (read-only)\n" +
				"2026/08/26 08:40:22 status height=5 tip=abcd peers=6 in=3 out=3 listening=true\n",
			want: "wedged",
			deny: []string{"never bound", "bind error", "no process"},
		},
		{
			name: "a process that was never started",
			node: func() *soakNode {
				closed := make(chan struct{})
				close(closed)
				return &soakNode{name: "unstarted", cmd: exec.Command(os.Args[0]), exited: closed}
			},
			want: "reported no state",
			deny: []string{"(code", "still running"},
		},
		{
			// No node at all. This runs on the failure path of a regime that
			// is already failing, so a nil has to produce a sentence: a panic
			// here replaces the diagnosis the caller came for with a stack.
			name: "no node at all",
			node: func() *soakNode { return nil },
			want: "no process",
			deny: []string{"process exited", "still running"},
		},
		{
			// A process no reaper ever adopted — cmd set, nothing waiting on
			// it. This row exists because the guard it exercises is a
			// three-term disjunction and the rows above separate only one of
			// the three: without it, dropping the `exited == nil` term is
			// invisible, and the report then answers "still running after 2s"
			// about a process that was never started, which is a wrong answer
			// bought at two seconds per unreachable node.
			name: "a process no reaper ever adopted",
			node: func() *soakNode {
				return &soakNode{name: "unadopted", cmd: exec.Command(os.Args[0])}
			},
			want: "no process",
			deny: []string{"still running", "process exited"},
		},
		{
			// A reaper whose cmd is gone: the mirror of the row above, and the
			// term the first version of this table collapsed *toward* and so
			// never mutated *away from*. Rows that leave both `cmd` and
			// `exited` nil fire on either half of the guard and separate
			// neither; only a node with one set and the other clear does.
			//
			// It is a real intermediate, not a hypothetical: stopNode assigns
			// `n.cmd, n.exited = nil, nil`, and Go carries a tuple assignment
			// out left to right. Without the term, this shape walks past the
			// guard onto a closed channel and dereferences a nil cmd — a stack
			// instead of a diagnosis, on the failure path of a regime that is
			// already failing.
			name: "a reaper whose cmd is gone",
			node: func() *soakNode {
				closed := make(chan struct{})
				close(closed)
				return &soakNode{name: "cmdless", exited: closed}
			},
			want: "no process",
			deny: []string{"still running", "process exited"},
		},
		{
			// A process that takes a moment to go. Every other fated child
			// either exits at once or not at all, so none of them can tell a
			// two-second grace from a ninety-millisecond one — and a grace too
			// short reports an ordinary teardown as wedged, which is the wrong
			// owner rather than a vaguer answer.
			name: "a process that takes a moment to go",
			fate: "linger",
			want: "exit status 0 (code 0)",
			deny: []string{"still running", "no process"},
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			var n *soakNode
			switch {
			case row.node != nil:
				n = row.node()
			default:
				n = spawnFatedChild(t, row.fate)
				if row.kill {
					if err := n.cmd.Process.Kill(); err != nil {
						t.Fatalf("terminating the child: %v", err)
					}
				}
			}
			if row.logBody != "" {
				n.logPath = writeExitReportLog(t, row.logBody)
			}
			got := exitReport(n, exitReportGrace)
			if !strings.Contains(got, row.want) {
				t.Errorf("exitReport = %q, which does not say %q: this fate is not "+
					"distinguishable from the others in the report a failing regime "+
					"prints", got, row.want)
			}
			for _, deny := range row.deny {
				if strings.Contains(got, deny) {
					t.Errorf("exitReport = %q, which also says %q: a report that carries "+
						"every outcome separates none of them", got, deny)
				}
			}
		})
	}
}

// The property: **a process the harness did not kill is still reaped, so its
// exit code survives it.**
//
// This is the half that was the blocker, stated on its own rather than through
// the wording of a report. Before the reaper, cmd.Wait was called only from
// stopNode, on nodes the harness itself had killed; a node that died by itself
// left a ProcessState nobody ever fetched. The check is that the state is there
// WITHOUT anything in the test terminating the child, which is exactly the
// situation node `d` was in.
func TestAProcessThatDiesOnItsOwnIsStillReaped(t *testing.T) {
	n := spawnFatedChild(t, "7")
	select {
	case <-n.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the child was never reaped: nothing in this harness called Wait on a " +
			"process it did not kill, which is the gap the silent death fell into")
	}
	if n.cmd.ProcessState == nil {
		t.Fatal("the child was reaped but no ProcessState was recorded: Process.Wait " +
			"reaps without filling it, and only exec.Cmd.Wait does")
	}
	if code := n.cmd.ProcessState.ExitCode(); code != 7 {
		t.Errorf("the reaped child reports exit code %d, and it exited with 7: the "+
			"harness is reporting a fate that is not the one the process had", code)
	}
}

// spawnFatedChild starts this test binary as a child whose fate is chosen by
// the caller, and supervises it exactly as startNode supervises a node.
func spawnFatedChild(t *testing.T, fate string) *soakNode {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "ZCD_SOAK_CHILD_FATE="+fate)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the fated child: %v", err)
	}
	n := &soakNode{name: "child"}
	superviseNode(n, cmd)
	t.Cleanup(func() { stopNode(n) })
	return n
}

// writeExitReportLog writes a node's log body to a file and returns its path,
// so a row can stage what the report will read out of a node's own log.
func writeExitReportLog(t *testing.T, body string) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + "node.log"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing the node log: %v", err)
	}
	return path
}

// The property: **wherever the soak reports that a node's RPC did not answer,
// it also reports what became of that node's process.**
//
// Structural, and it has to be. The behavioural form of this check is a failing
// soak — the regime whose reporting path this is runs for minutes and reaches
// that path only when convergence fails, which is the once-in-five event the
// silent death was. A test that can only observe the wiring by reproducing the
// bug is a test that observes nothing on every run that passes.
//
// So the shape is the one cmd/zycordd's wiring tests use for the same reason:
// read the source, find every place the harness turns a failed status call into
// a line in the log, and require that the report be passed to the call that
// writes that line — an argument of the reporter, not an identifier loose in
// the branch. What it cannot see is a report added in another file of this
// package; the check is over soak_test.go because that is where every regime
// lives. Nor can it see the report buried in a closure inside an argument and
// its value dropped there — that shape passes, and it is left passing on
// purpose: no refactor of a log line produces it, while rejecting every FuncLit
// under an argument would fail legitimate reporters, and every regression that
// is actually reachable is caught (the call deleted, the answer computed and
// discarded in a sibling statement, a new branch left unwired, or the matcher
// drifting off the source and taking the count with it).
func TestEveryReportOfAnUnreachableNodeNamesWhatBecameOfItsProcess(t *testing.T) {
	const path = "soak_test.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var sites int
	ast.Inspect(file, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i := 0; i+1 < len(block.List); i++ {
			assign, ok := block.List[i].(*ast.AssignStmt)
			if !ok || !assignsFrom(assign, "status") {
				continue
			}
			branch, ok := block.List[i+1].(*ast.IfStmt)
			if !ok || !isErrIsNotNil(branch.Cond) {
				continue
			}
			// Only branches that SAY something. A branch that silently
			// `continue`s over an unreachable node — waitForConvergence's, the
			// history checker's — is not making a claim about why the node did
			// not answer, so there is nothing there for a report to be missing
			// from.
			//
			// The formatted reporters and not `t.Error`, because `Error` is
			// also how every error in Go spells itself: `err.Error()` is the
			// same selector, and a trigger that fires on it would fire on
			// branches that report nothing. The one site that used the bare
			// form was converted to `Errorf` rather than excused, so nothing
			// hides behind that collision.
			reports := callsTo(branch.Body, "Logf", "Errorf", "Fatalf")
			if len(reports) == 0 {
				continue
			}
			sites++
			// Among the reporter's ARGUMENTS, and not merely somewhere in the branch. A
			// branch that computes the report and drops it on the floor logs the exact
			// line the original sighting did, pays the grace to do it, and satisfies a
			// check that only asks whether the identifier appears anywhere: a report
			// that is reached and discarded is worth what the sighting was.
			if !anyCarries(reports, "exitReport") {
				t.Errorf("%s: this branch reports that a node's RPC did not answer and "+
					"does not pass what became of its process to the reporter, so "+
					"\"exited\", \"terminated\" and \"wedged\" reach the log as one "+
					"observation", fset.Position(branch.Pos()))
			}
		}
		return true
	})

	// Anti-vacuity. Three branches in this file report a failed status call —
	// TestChaosSoak's convergence dump, the late joiner's health report, and
	// the billing law's walk of a node that answered a moment earlier — so a
	// run that finds fewer than three has stopped matching the source rather
	// than found it clean, and would pass on a file with the reporting deleted
	// entirely.
	if sites < 3 {
		t.Fatalf("found %d branches that report a failed status call, and there are at "+
			"least three: this check has stopped matching %s and a clean result from it "+
			"means nothing", sites, path)
	}
	t.Logf("checked %d branches that report a failed status call", sites)
}

// assignsFrom reports whether an assignment's right-hand side is a call to the
// named function.
func assignsFrom(assign *ast.AssignStmt, name string) bool {
	if len(assign.Rhs) != 1 {
		return false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == name
}

// isErrIsNotNil reports whether a condition is `err != nil`.
func isErrIsNotNil(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	x, ok := bin.X.(*ast.Ident)
	if !ok || x.Name != "err" {
		return false
	}
	y, ok := bin.Y.(*ast.Ident)
	return ok && y.Name == "nil"
}

// calleeName is the name a call invokes, by bare identifier or as the selector
// of a receiver.
func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// callsAny reports whether a subtree calls any of the named functions.
func callsAny(node ast.Node, names ...string) bool {
	return len(callsTo(node, names...)) > 0
}

// callsTo collects every call to any of the named functions in a subtree.
func callsTo(node ast.Node, names ...string) []*ast.CallExpr {
	var found []*ast.CallExpr
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, want := range names {
			if calleeName(call) == want {
				found = append(found, call)
				break
			}
		}
		return true
	})
	return found
}

// anyCarries reports whether any of these calls passes a call to the named
// function as one of its own arguments.
//
// The distinction from callsAny is the whole of what this check is worth:
// `_ = exitReport(n, exitReportGrace)` next to a bare log line puts the
// identifier in the branch and the answer nowhere.
func anyCarries(calls []*ast.CallExpr, name string) bool {
	for _, call := range calls {
		for _, arg := range call.Args {
			if callsAny(arg, name) {
				return true
			}
		}
	}
	return false
}
