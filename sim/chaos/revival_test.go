package chaos_test

// The regime that holds the second drain.
//
// The revival machinery gave an unbidden node death an owner: `liveness.revive`
// queues it and `reviveTheDead` drains the queue, at the top of `applyChaos`
// **and** inside `waitForConvergence`'s loop. The second site is the one the
// silent-follower death needs — that follower was removed inside the first
// fifteen seconds and the regime then spent five minutes reporting that four
// nodes were not all reachable — and until this file **nothing in the suite
// held it in place.** The revival change declared that itself: its M4 mutant,
// *remove the drain from `waitForConvergence`*, was declared to survive, and it
// did survive every test that runs.
//
// It was never unkillable, only unkilled. Measured while that change was being
// reviewed, with the follower terminated from outside during the convergence
// window and the window shortened to bound wall clock: **drain present** — the
// node is brought back from the `waitForConvergence` call site, the network
// converges, 34.3 s; **drain removed** — `d: unreachable`, "the network did not
// converge after the chaos stopped", 90.5 s. Two runs, one mutant, a clear
// signal. What was missing was that anything ran it.
//
// This is that measurement turned into a thing that runs. Its cost is stated
// beside its gate, and it is skipped unless a soak was asked for, so it is not
// paid by `go test`.
//
// The shape it avoids is the one a widened matcher would have: the mutant
// survives because no test *reaches the state*, not because a matcher is loose,
// so nothing short of a real regime — real processes, a real termination, a real
// convergence window — can kill it.

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// revivalMinHeight is how much chain has to exist before the victim is removed.
//
// `waitForConvergence` refuses to compare below height 3 — two nodes agreeing on
// a genesis they were both handed is not convergence — so a regime that killed
// the follower before that would be asking the window to build the chain and
// re-sync the node at once. Six leaves the check something to have been
// comparing already, and is reached well inside the startup window below.
const revivalMinHeight = 6

// revivalStartupWindow bounds getting three miners to revivalMinHeight.
//
// Generous, because it covers a cold build's first blocks at the initial
// difficulty, and it is not the measurement: nothing about this regime's claim
// depends on how long the network took to start. It exists so a network that
// never starts is reported as that rather than as a convergence failure.
const revivalStartupWindow = 4 * time.Minute

// revivalWindow is the convergence window the victim is killed inside.
//
// Two minutes against a measured 34.3 s for the whole revive-and-reconverge
// path, so the passing run has roughly three times the room it needs, and the
// failing run — the mutant's — pays the whole window and no more. Deliberately
// NOT `5*time.Minute` like the soak's: this regime's value is that its failure
// is cheap to observe, and a five-minute window would triple the cost of the run
// that has something to say.
const revivalWindow = 2 * time.Minute

// revivalReapWindow bounds waiting for the operating system to tear the victim
// down after the termination is issued. A hard kill is not a request, so this is
// a bound on the kernel rather than on the node.
const revivalReapWindow = 30 * time.Second

// The property: **a node removed by something outside the test *during the
// convergence window* is brought back, and the network then reconverges.**
//
// Which is to say: the drain inside `waitForConvergence` is load-bearing, and
// removing it fails this test. That is the whole claim, and it is worth being
// precise about why no cheaper test has it. The drain at the top of `applyChaos`
// is exercised by every soak run, because the chaos loop is where the soak's own
// kills happen. The second drain is reached only by a death that lands *after*
// the chaos has stopped — inside the five-minute window in which the question
// being asked is "does the network reconverge", which is exactly the question a
// node that stays dead makes unanswerable, because `reachable == len(nodes)` is
// the condition. No unit test drives that window, so the call could be deleted
// invisibly.
//
// Three things are asserted, and each fails on the mutant for its own reason:
// the victim is running when the window closes (the drain restarted it), the
// network converged (all four reachable and agreed), and the death was still
// reported (the supervisor repairs the regime, it does not edit the report — a
// supervisor that quietly fixed what the run exists to notice would be a worse
// defect than the one it fixes).
//
// The reports are captured rather than delivered for the same reason
// `captureLiveness` exists: `liveness.announce` is `t.Errorf`, and this regime
// causes the death on purpose, so delivering it would fail the run that is
// asserting on it. Capturing is not a way of ignoring deaths — every death seen
// is checked below, and one that is not the victim's fails the test.
func TestChaosSoakRevivesANodeKilledInsideTheConvergenceWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	// Skipped by default, and the skip says what is going untested rather than
	// reading like a pass (docs/adversarial/I4.md).
	//
	// The cost, stated because somebody pays it: about 90 s of wall clock on a
	// passing run once the binaries are built, and at most about six and a half
	// minutes if both windows expire. It does NOT scale with ZCD_SOAK — the
	// windows above are its own — so under `make soak` it is a fixed couple of
	// minutes on a target whose floor is thirty-five.
	if os.Getenv("ZCD_SOAK") == "" {
		t.Skip("the revival regime runs only when a soak was asked for (ZCD_SOAK, " +
			"which `make soak` and `make soak-revival` set); NOT RUN means the drain " +
			"in waitForConvergence — the one that answers a death landing inside the " +
			"convergence window, the silent-follower death — is held by nothing")
	}

	nodes, bin, _, _, _ := newSoakNetwork(t, 7)

	if !waitForHeight(t, nodes, revivalMinHeight, revivalStartupWindow) {
		t.Fatalf("the network never reached height %d in %s, so there was no chain to "+
			"reconverge on and this regime measured nothing", revivalMinHeight,
			revivalStartupWindow)
	}

	// One miner, for exactly the reason TestChaosSoak leaves one: with three
	// racing, "do all nodes agree right now" is asking whether four processes
	// happened to be sampled between blocks, and this regime needs convergence to
	// be a property rather than a coincidence. Through stopNode, so the harness
	// announces its own kills and they are not counted as deaths.
	for _, n := range nodes[1:] {
		if n.mining {
			stopNode(n)
			n.mining = false
			startNode(t, bin.zycordd, n)
		}
	}

	// The outbound-only follower, which is the node the silent death took and the
	// node with no inbound peer to notice it went.
	victim := nodes[len(nodes)-1]
	if victim.name != "d" || victim.p2pPort != 0 {
		t.Fatalf("expected the outbound-only follower last in the network and found %q; "+
			"this regime's victim is the node the silent death took, not an "+
			"arbitrary one", victim.name)
	}

	mon := victim.monitor
	reports := &livenessReports{}
	mon.mu.Lock()
	mon.sink = reports.add
	mon.mu.Unlock()

	killFromOutside(t, victim)
	select {
	case <-victim.exited:
		// The reaper reports and queues the revival BEFORE it closes this
		// channel, so by here the death is on the queue and nothing but the drain
		// under test can answer it.
	case <-time.After(revivalReapWindow):
		t.Fatalf("%s was terminated and was not reaped within %s, so no death was ever "+
			"noticed and this regime cannot say anything about the drain",
			victim.name, revivalReapWindow)
	}

	// The kill is issued from this goroutine and before the window opens rather
	// than from a timer inside it, and that is not a shortcut. `startNode` writes
	// `n.cmd`, `n.exited` and `n.expected`, and the drain calls it on the test's
	// own goroutine; a killer goroutine reading those fields while the drain
	// writes them would be a data race introduced by the test for the fix for a
	// race. The queue is drained nowhere else in this regime — `applyChaos` is
	// never called — so the death is answered by `waitForConvergence`'s drain or
	// by nothing.
	converged := waitForConvergence(t, nodes, revivalWindow)

	// The direct oracle first: is the process back. Checked before convergence
	// because it is the one that names the cause rather than the symptom.
	select {
	case <-victim.exited:
		t.Errorf("%s was still dead when the convergence window closed: nothing brought "+
			"back a node removed inside the window, which is the drain in "+
			"waitForConvergence missing. %s",
			victim.name, exitReport(victim, exitReportGrace))
	default:
	}

	if !converged {
		for _, n := range nodes {
			st, err := status(n.rpcPort)
			if err != nil {
				t.Logf("%s: unreachable (%v); %s", n.name, err, exitReport(n, exitReportGrace))
				continue
			}
			t.Logf("%s: height=%v tip=%v root=%v", n.name, st["height"], st["tip"], st["state_root"])
		}
		dumpLogs(t, nodes)
		t.Errorf("the network did not converge in %s after %s was terminated inside the "+
			"convergence window; a node that stays dead makes the question this regime "+
			"asks unanswerable, which is the silent death over again",
			revivalWindow, victim.name)
	}

	if got := mon.revivalCount(victim.name); got != 1 {
		t.Errorf("the instrument counted %d revivals of %s having answered one death; the "+
			"bound and the report both read this number", got, victim.name)
	}

	// The supervisor must not have edited the report. A revival that made a red
	// run green would be the failure mode of every supervisor, and the death of a
	// node nobody asked to die is a finding whether or not the network recovered
	// from it.
	got := reports.all()
	if len(got) != 1 {
		t.Fatalf("one node was terminated and the run was told %d things; the revival must "+
			"not change what a run is told:\n%s", len(got), strings.Join(got, "\n---\n"))
	}
	for _, want := range []string{
		"node " + victim.name + " died",
		"the harness did not ask",
	} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the report does not say %q, so bringing the node back has hidden the "+
				"death it was answering:\n%s", want, got[0])
		}
	}

	// And nothing else died. Every unbidden death is captured by the sink above,
	// so a real defect elsewhere in the run would otherwise be swallowed by the
	// very mechanism that keeps the deliberate one from failing this test.
	for _, d := range mon.deathList() {
		if d.name != victim.name {
			t.Errorf("a node this regime did not terminate died unbidden: %s", d.String())
		}
	}
}

// killFromOutside removes a node's process the way something outside the test
// would: a separate program issues the termination, and the harness never
// announces it, so the reaper sees a death nobody asked for.
//
// **Scoped by the process this harness started, never by name.** The change
// that added this regime asked for a `ParentProcessId` walk, and it states the
// reason in the same sentence: this machine runs several lanes at once, and a
// kill selected by process name or command line reaches another lane's
// `zycordd` — observed while the issue was being written. A walk answers "is
// this pid mine?" *after* a name has already chosen the pid. Nothing here
// chooses by name: the pid comes from the `exec.Cmd` this test started and from
// nowhere else, so the question the walk exists to answer cannot arise. That is
// strictly narrower than the walk rather than a weaker substitute for it.
//
// The termination is still issued by a separate program, because the regime is
// about a death the harness did not cause. Where that program is missing or
// refuses, the call falls back to the process handle — `taskkill /F` invokes
// TerminateProcess and `kill -9` sends SIGKILL, so the node dies the same way on
// either route. What makes the death *unbidden* is that `n.expected` is never
// closed, which is the discrimination `liveness.noticeExit` actually makes; the
// identity of the caller is not part of it.
func killFromOutside(t *testing.T, n *soakNode) {
	t.Helper()
	if n.cmd == nil || n.cmd.Process == nil {
		t.Fatalf("%s has no running process to terminate; this regime needs a live node "+
			"here or it measures nothing", n.name)
	}
	select {
	case <-n.exited:
		t.Fatalf("%s was already dead before the regime terminated it, so the death this "+
			"test attributes to itself is not its own", n.name)
	default:
	}
	pid := n.cmd.Process.Pid

	var kill *exec.Cmd
	if runtime.GOOS == "windows" {
		kill = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))
	} else {
		kill = exec.Command("kill", "-9", strconv.Itoa(pid))
	}
	out, err := kill.CombinedOutput()
	if err == nil {
		t.Logf("%s (pid %d) was terminated from outside the harness: %s", n.name, pid,
			strings.TrimSpace(string(out)))
		return
	}
	t.Logf("the external terminator would not run for %s (pid %d): %v (%s); falling back "+
		"to the process handle, which kills it the same way", n.name, pid, err,
		strings.TrimSpace(string(out)))
	if err := n.cmd.Process.Kill(); err != nil {
		t.Fatalf("could not terminate %s (pid %d): %v", n.name, pid, err)
	}
}
