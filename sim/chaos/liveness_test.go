package chaos_test

// Liveness while the regime runs, rather than at the end of it.
//
// Until this file the soak never checked that a node was *running* until
// waitForConvergence sampled its RPC, which is after the whole chaos regime has
// finished. The only earlier check that looked at a node at all read its LOG
// FILE — and an outbound-only follower writes its three startup lines and then
// nothing for fifteen seconds, so for those fifteen seconds a live node and a
// dead one are byte-identical on disk. The follower that was lost died inside
// that window and was first noticed minutes later, by which time the run could
// say only "unreachable now".
//
// The signal used here is neither the log nor the RPC: it is the reaper already
// attached to every started process. exec.Cmd.Wait returns at the instant the
// operating system tears the child down, so a death is observable exactly when
// it happens and nowhere else. Two consequences fall out of that choice, and
// they are the two properties this instrument has to have:
//
//   - It fires on a real death, with the time, the node, and the last state
//     anyone saw it in.
//   - It CANNOT fire on a healthy slow node, because a slow node's process has
//     not been reaped. A liveness check built on "the RPC stopped answering"
//     would have had to guess where slow ends and dead begins; this one never
//     asks the question.
//
// And a third, which is what keeps it from being noise: the harness kills nodes
// on purpose, three or four times a run. stopNode announces its intent before
// it kills, so a chaos kill and an unbidden death are different events rather
// than the same one seen twice.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// livenessSampleInterval is how often each node's RPC is asked where it is.
//
// One second, against a five-second target block interval: close enough that a
// death report names a state from the same block the node died on, cheap enough
// that four nodes cost four requests a second on a loopback socket. It is a
// record of where a node WAS, never a verdict on whether it is alive — that
// verdict comes from the reaper, and nothing here is allowed to second-guess it.
const livenessSampleInterval = time.Second

// liveness watches the soak's node processes for a death the harness did not
// ask for, and reports it when it happens.
type liveness struct {
	t     *testing.T
	start time.Time

	mu sync.Mutex
	// last is the most recent state each node answered with, by node name.
	last map[string]livenessSample
	// starts counts how many times each node has been started, so a report can
	// say which run of a node died.
	starts map[string]int
	// startedAt is when the current run of each node began.
	startedAt map[string]time.Time
	// samples counts the successful RPC samples taken, so that "no node died"
	// can be told apart from "nothing was watching".
	samples int
	watched []string
	deaths  []nodeDeath
	// quiet stops reports from reaching t once the regime is over. Read and
	// written under mu, and every report is written under mu too, so a report
	// in flight when the regime ends completes before quiet is set rather than
	// logging into a finished test.
	quiet bool
	// sink replaces t.Errorf for the tests of this instrument, which cannot
	// assert on a report whose delivery mechanism is failing the run that is
	// asserting.
	//
	// Nil in every regime but one: the revival regime terminates a node on purpose
	// and then asserts that the death was still reported, so it is in the same
	// position as the instrument's own tests. It sets this under mu, before it
	// issues the kill, and it fails on any death that is not the one it caused — a
	// sink is a redirection of the report, never a licence to lose it.
	sink func(format string, args ...any)

	// revive holds the deaths the reaper found unbidden and that nothing has
	// brought back yet.
	//
	// A queue rather than a restart issued from the reaper, and the reason is
	// ownership: startNode writes n.cmd, n.exited and n.expected, and stopNode
	// reads all three, both on the test's own goroutine. A reaper that
	// restarted the node it just buried would be a second writer of those
	// fields racing the chaos loop, which is a data race introduced by the fix
	// for a race. So the reaper records, and the regime — which is already the
	// only goroutine that starts and stops nodes — drains.
	//
	// A queue of DEATHS rather than of nodes, because between the moment a
	// death is queued and the moment the regime drains it the harness may have
	// restarted the node itself. See pendingRevival.
	revive []pendingRevival
	// revivals counts how many times each node has been brought back, so that
	// a node something outside the test keeps killing cannot be restarted for
	// the length of the regime.
	revivals map[string]int
	// restart brings one node back. It is startNode in every regime; the
	// instrument's own tests supply a fated child instead, for the same reason
	// sink exists. Nil means no supervisor, and a nil supervisor queues
	// nothing.
	restart func(n *soakNode)

	stop chan struct{}
	wg   sync.WaitGroup
}

// livenessSample is one answer from a node's RPC, with the time it was given.
type livenessSample struct {
	at   time.Time
	desc string
}

// nodeDeath is one node found dead without the harness having asked.
type nodeDeath struct {
	name    string
	into    time.Duration // since the regime started
	uptime  time.Duration // since this run of the node started
	run     int           // which start of this node died
	fate    string        // what became of the process
	state   string        // the last state it answered with
	tail    string        // the last line it logged
	logPath string
}

// newLiveness starts watching, and prints what it saw when the regime ends.
//
// The summary is a cleanup rather than a call at the end of each regime for one
// reason: a regime that fails early — t.Fatal in assertNodesAreGuarded, a panic
// anywhere — is exactly the run whose deaths are worth reading, and it never
// reaches its own last line.
func newLiveness(t *testing.T) *liveness {
	t.Helper()
	m := &liveness{
		t:         t,
		start:     time.Now(),
		last:      map[string]livenessSample{},
		starts:    map[string]int{},
		startedAt: map[string]time.Time{},
		revivals:  map[string]int{},
		stop:      make(chan struct{}),
	}
	t.Cleanup(func() {
		m.summarise()
		m.close()
	})
	return m
}

// attach begins sampling a node's state. Idempotent: a node that is killed and
// restarted keeps the one sampler it already has.
func (m *liveness) attach(n *soakNode) {
	if m == nil {
		return
	}
	m.mu.Lock()
	for _, name := range m.watched {
		if name == n.name {
			m.mu.Unlock()
			return
		}
	}
	m.watched = append(m.watched, n.name)
	m.mu.Unlock()

	name, port := n.name, n.rpcPort
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		tick := time.NewTicker(livenessSampleInterval)
		defer tick.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-tick.C:
			}
			st, err := status(port)
			if err != nil {
				// Not an event. A node that does not answer may be busy, may be
				// mid-restart, may be behind a partition the chaos loop opened
				// on purpose. Only the reaper says a node is dead.
				continue
			}
			m.record(name, fmt.Sprintf("height=%v tip=%v root=%v",
				st["height"], st["tip"], st["state_root"]))
		}
	}()
}

// record stores the last state a node was seen in.
func (m *liveness) record(name, desc string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last[name] = livenessSample{at: time.Now(), desc: desc}
	m.samples++
}

// started notes that a run of a node has begun.
func (m *liveness) started(name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.starts[name]++
	m.startedAt[name] = time.Now()
}

// noticeExit is called by the reaper the moment a process is torn down, and
// reports it unless the harness had announced that it was about to kill it.
//
// `expected` is the announcement, closed by stopNode BEFORE it issues the kill,
// which is what makes the discrimination sound rather than racy: a kill cannot
// take effect before it is issued, so on the harness's own kills this channel
// is always already closed by the time Wait returns. It is a per-start channel,
// captured by the reaper for the run it is waiting on, so the next start's
// channel cannot answer for this one.
func (m *liveness) noticeExit(n *soakNode, cmd *exec.Cmd, expected <-chan struct{}) {
	if m == nil {
		return
	}
	select {
	case <-expected:
		return
	default:
	}

	at := time.Now()
	// Gathered before the lock, and from the cmd this reaper owns rather than
	// from n.cmd: stopNode nils n.cmd, and this runs on the path where nobody
	// called stopNode at all.
	fate := processFate(cmd)
	tail := lastLogLine(n.logPath)

	m.mu.Lock()
	defer m.mu.Unlock()
	d := nodeDeath{
		name:    n.name,
		into:    at.Sub(m.start),
		run:     m.starts[n.name],
		fate:    fate,
		state:   describeLastState(m.last[n.name], at),
		tail:    tail,
		logPath: n.logPath,
	}
	if began, ok := m.startedAt[n.name]; ok {
		d.uptime = at.Sub(began)
	}
	m.deaths = append(m.deaths, d)
	if m.quiet {
		return
	}
	// Queued BEFORE the report, and it has to be: announce is t.Errorf, which
	// on a regime that has already failed for another reason can be the call
	// that ends the test goroutine. A queue written after it would lose the
	// revival on exactly the runs that have the most to explain.
	m.queueRevivalLocked(n)
	m.announce("%s", d.String())
}

// pendingRevival is one unbidden death waiting for the regime to answer it.
//
// `start` is which run of the node died — m.starts[name] at the moment the
// reaper noticed — and it is the whole reason this is a struct.
//
// **The announcement channel does not cover this.** `expected` separates a
// death the harness caused from one it did not, per start; it says nothing
// about what happened to the NODE between the death and the drain. The drain
// runs at the top of applyChaos and inside waitForConvergence's loop, and
// between those two lies the demote loop that stops each miner and starts it
// again without --mine — a window of several seconds in which the harness
// restarts the very node whose death is sitting in this queue. Issuing the
// revival then starts a SECOND process on one data directory and one RPC port.
//
// The duplicate loses the directory lock and calls fatal(), which sounds
// self-limiting and is not: startNode has already run superviseNode, so n.cmd
// now names the process that is about to die and the healthy one it replaced is
// referenced by nothing. stopNode in t.Cleanup then kills the corpse, and the
// live node is ORPHANED — it outlives the run, on a machine with other work on
// it — while its dead twin is reported as one more unbidden death and queued
// all over again.
//
// So the drain compares the start it was queued for against the start the node
// is on now, and drops a stale one.
type pendingRevival struct {
	node  *soakNode
	start int
}

// resurrectLimit is how many times one node is brought back inside one regime.
//
// Bounded, because the failure this exists for is a process being removed by
// something outside the test, and whatever removed it once can remove it again.
// An unbounded supervisor turns that into a restart loop that runs for the
// length of the regime and buries the report under its own noise. Three is
// enough to survive a one-off and few enough that a repeated kill is still
// legible as a repeated kill.
const resurrectLimit = 3

// queueRevivalLocked asks the regime to bring a node back. Called with mu held.
func (m *liveness) queueRevivalLocked(n *soakNode) {
	// No supervisor, nothing to queue. The instrument is used by regimes that
	// have one and by its own tests, which mostly do not, and a queue that grew
	// without a drain would hold node pointers for the length of the run.
	if m.restart == nil {
		return
	}
	if m.revivals[n.name] >= resurrectLimit {
		// Said once, on the crossing, so a node being killed repeatedly reports
		// the giving-up rather than repeating it.
		if m.revivals[n.name] == resurrectLimit {
			m.revivals[n.name]++
			m.announce("node %s has died unbidden %d times and will not be brought back "+
				"again; the regime continues without it, and a node that keeps being "+
				"removed is a different finding from one removed once",
				n.name, resurrectLimit)
		}
		return
	}
	m.revivals[n.name]++
	m.revive = append(m.revive, pendingRevival{node: n, start: m.starts[n.name]})
}

// takeRevivals hands the caller the deaths that still need answering, and
// empties the queue.
//
// A death whose node the harness has already restarted is dropped here rather
// than issued: see pendingRevival for what issuing it does. The dropped entry
// still counts against resurrectLimit, and that is deliberate — the bound
// counts unbidden deaths RESPONDED TO, and this one was responded to, by the
// harness's own restart.
func (m *liveness) takeRevivals() []*soakNode {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pending := m.revive
	m.revive = nil
	// A death noticed while the regime is being torn down is not brought back:
	// the cleanup is already stopping every node, and a process started here
	// would be started after the thing that was going to stop it.
	if m.quiet {
		return nil
	}
	var out []*soakNode
	for _, p := range pending {
		if m.starts[p.node.name] != p.start {
			continue
		}
		out = append(out, p.node)
	}
	return out
}

// reviveTheDead brings back every node the reaper found dead without the
// harness having asked, and says so.
//
// **This does not make a failing run pass, and that is the property to hold
// on to.** The death has already been reported through t.Errorf by the time a
// node reaches this queue, so the run is red and names the node, the moment it
// died, which start of it died, what became of the process, the last state it
// answered with and its last log line. What changes is only what the run can
// measure AFTERWARDS.
//
// The silent death is why. A follower was removed inside the first fifteen
// seconds, nothing restarted it, and the regime spent the next five minutes
// failing to converge on a node that was not there — so the only thing the run
// could report was the absence, and whether the network recovers from an
// unbidden death went unmeasured. The soak already restarts the three or four
// nodes it kills itself; the gap was never a design decision, it was that a
// death nobody caused had no owner. It has one now.
func reviveTheDead(t *testing.T, nodes []*soakNode) {
	t.Helper()
	if len(nodes) == 0 {
		return
	}
	m := nodes[0].monitor
	for _, n := range m.takeRevivals() {
		// On the test's own goroutine, so startNode's t.Fatal is legal here and
		// n.cmd has exactly one writer. See liveness.revive.
		m.restart(n)
		m.t.Logf("liveness: %s was brought back after a death the harness did not ask "+
			"for (revival %d of %d); the regime continues so that whether the network "+
			"recovers is measured rather than assumed",
			n.name, m.revivalCount(n.name), resurrectLimit)
	}
}

// revivalCount is how many times a node has been brought back.
func (m *liveness) revivalCount(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revivals[name]
}

// announce delivers one report. See liveness.sink.
func (m *liveness) announce(format string, args ...any) {
	if m.sink != nil {
		m.sink(format, args...)
		return
	}
	m.t.Errorf(format, args...)
}

// String renders a death the way an operator reading a failed run needs it: the
// time first, because "before any load existed" and "under load at minute four"
// are different defects and the original sighting could not tell which it had.
func (d nodeDeath) String() string {
	return fmt.Sprintf(
		"node %s died %s into the regime — %s after start number %d — and the harness did not ask it to.\n"+
			"    what became of it: %s\n"+
			"    last state:        %s\n"+
			"    last log line:     %s\n"+
			"    full log:          %s",
		d.name, d.into.Round(time.Millisecond), d.uptime.Round(time.Millisecond), d.run,
		d.fate, d.state, d.tail, d.logPath)
}

// describeLastState renders the last answer a node gave, with its age.
func describeLastState(s livenessSample, at time.Time) string {
	if s.desc == "" {
		return "never answered its RPC after starting, so nothing is known about " +
			"where it was"
	}
	return fmt.Sprintf("%s, sampled %s before it died", s.desc,
		at.Sub(s.at).Round(time.Millisecond))
}

// lastLogLine is the last non-blank line a node wrote.
func lastLogLine(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "(no log file)"
	}
	lines := splitLines(string(raw))
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return "(empty log)"
}

// summarise says what the instrument saw, including when it saw nothing.
//
// The sample count is in the clean line on purpose. "No node died unbidden" is
// worth exactly as much as the watching behind it, and an instrument that
// silently stopped watching reports the same sentence as one that watched all
// run — which is the failure mode this instrument exists to end, reintroduced
// one level up.
func (m *liveness) summarise() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.deaths) == 0 {
		m.t.Logf("liveness: no node died unbidden (%d nodes watched, %d state samples "+
			"over %s)", len(m.watched), m.samples, time.Since(m.start).Round(time.Second))
		return
	}
	for _, d := range m.deaths {
		m.t.Logf("liveness: %s", d.String())
	}
}

// close stops the samplers and stops reports from reaching t.
func (m *liveness) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	already := m.quiet
	m.quiet = true
	m.mu.Unlock()
	if already {
		return
	}
	close(m.stop)
	m.wg.Wait()
}

// deathList is a snapshot, for the tests of this instrument.
func (m *liveness) deathList() []nodeDeath {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]nodeDeath(nil), m.deaths...)
}

// ---------------------------------------------------------------------------
// The instrument's own tests
// ---------------------------------------------------------------------------

// The property: **a node that dies without the harness asking is reported at
// the moment it dies, named, with the last state it was seen in.**
//
// A real child process, because the thing being detected is an operating
// system tearing a process down and an in-process double would be detecting the
// double. The child is never killed by this test — that is the whole point, and
// it is the situation node `d` was in.
//
// The report is captured rather than delivered, because its delivery mechanism
// is t.Errorf: a test cannot assert on a failure that is failing it.
func TestALivenessCheckFiresWhenANodeDiesUnbidden(t *testing.T) {
	m, reports := captureLiveness(t)
	n := superviseFatedChild(t, m, "9")

	select {
	case <-n.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the child was never reaped, so nothing could have noticed it die")
	}
	// The reaper reports before it closes `exited`, so by here the report is in.

	got := reports.all()
	if len(got) != 1 {
		t.Fatalf("a node died unbidden and the run was told %d times; the property "+
			"is that a death reaches the report at all, and once", len(got))
	}
	for _, want := range []string{
		"node d died",             // which node
		"the harness did not ask", // and not one of the chaos kills
		"exit status 9 (code 9)",  // what became of it
		"height=41",               // the last state anyone saw it in
		"after start number 1",    // which run of it
		"last log line:",          // where the evidence is
	} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the death report does not say %q, so a reader still has to "+
				"recover it by hand as the original investigation did:\n%s", want, got[0])
		}
	}
	if d := m.deathList(); len(d) != 1 || d[0].into <= 0 {
		t.Errorf("the death was not placed in time (%v), which is the one thing this "+
			"instrument exists for", d)
	}
}

// The property: **a node that is alive but not answering is NOT reported dead.**
//
// The other half of the same instrument, and the half a liveness check built on
// "the RPC stopped answering" would get wrong. This child is alive for the whole
// test and never serves an RPC at all — the shape of a node mid-restart, a node
// behind a partition the chaos loop opened on purpose, and a node that is merely
// slow. Sampling runs throughout, and finds nothing to record, and that is the
// input: no state, no answer, and still no death.
//
// It is not a weaker restatement of the row above. A check that reported every
// unreachable node would pass that row and fail this one, and a check that
// reported nothing would pass this row and fail that one; only both together
// say the instrument separates them.
func TestALivenessCheckDoesNotFireOnANodeThatIsMerelySlow(t *testing.T) {
	m, reports := captureLiveness(t)
	n := superviseFatedChild(t, m, "live")

	// Several sampling rounds, so the samplers have run and failed repeatedly
	// rather than not yet started.
	time.Sleep(3 * livenessSampleInterval)

	select {
	case <-n.exited:
		t.Fatal("the child was supposed to outlive this test; the input is a LIVE " +
			"node and it is not one")
	default:
	}
	if got := reports.all(); len(got) != 0 {
		t.Errorf("a live node was reported dead, which turns every partition and every "+
			"restart into a false alarm and makes the instrument unreadable:\n%s",
			strings.Join(got, "\n"))
	}
	if d := m.deathList(); len(d) != 0 {
		t.Errorf("a live node was recorded as dead: %v", d)
	}
}

// The property: **a node the harness itself kills is not reported as a death.**
//
// The soak kills and restarts nodes three or four times a run by design. A
// check that reported those would put four false alarms in every passing run,
// which is how an instrument stops being read — and this instrument exists
// because the one real death was invisible among things nobody was looking at.
func TestALivenessCheckDoesNotFireOnAKillTheHarnessAsked(t *testing.T) {
	m, reports := captureLiveness(t)
	n := superviseFatedChild(t, m, "live")

	stopNode(n) // exactly what applyChaos does

	if got := reports.all(); len(got) != 0 {
		t.Errorf("the harness killed a node on purpose and the run was told it died "+
			"unbidden:\n%s", strings.Join(got, "\n"))
	}
	if d := m.deathList(); len(d) != 0 {
		t.Errorf("a kill the harness asked for was recorded as a death: %v", d)
	}
}

// The property: **a node that is killed, restarted, and then dies is reported
// against the run that died, not the one the harness killed.**
//
// The discrimination above is per START, not per node, and this is the input
// that separates the two: a single flag on the node would be left set by the
// kill and would swallow the death that followed it. The lost follower ran in a
// regime that kills a random node every few seconds, so a node with a kill in
// its history is the ordinary case rather than a corner of it.
func TestALivenessCheckStillFiresAfterTheHarnessRestartedTheNode(t *testing.T) {
	m, reports := captureLiveness(t)
	n := superviseFatedChild(t, m, "live")
	stopNode(n)

	// The restart, and this run dies on its own.
	respawn(t, m, n, "4")
	select {
	case <-n.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the restarted child was never reaped")
	}

	got := reports.all()
	if len(got) != 1 {
		t.Fatalf("a node that died after a chaos kill was reported %d times, and it "+
			"died once: the announcement from the kill is being reused for the death",
			len(got))
	}
	if !strings.Contains(got[0], "after start number 2") {
		t.Errorf("the report does not name which run of the node died:\n%s", got[0])
	}
	if !strings.Contains(got[0], "(code 4)") {
		t.Errorf("the report does not carry the fate of the run that actually died:\n%s",
			got[0])
	}
}

// The property: **the clean line carries the evidence that anything was
// watched.**
//
// "No node died unbidden" printed by an instrument that stopped sampling is the
// exact failure this instrument answers, one level up: a reassuring line that
// is a record of nothing. So the count is in the sentence, and this pins that
// it is a count of real samples rather than a constant.
func TestTheCleanLivenessLineSaysHowMuchWasWatched(t *testing.T) {
	m, _ := captureLiveness(t)
	m.record("d", "height=7 tip=0xabc root=0xdef")
	m.record("d", "height=8 tip=0xabc root=0xdef")

	m.mu.Lock()
	got := m.samples
	m.mu.Unlock()
	if got != 2 {
		t.Errorf("the instrument counted %d samples having taken 2; the clean line "+
			"reports this number and a wrong one is worse than none", got)
	}
}

// The property: **a node that died without the harness asking is brought back,
// and the run is still told that it died.**
//
// Both halves in one test on purpose, because the failure mode of a supervisor
// is that it quietly repairs the thing the run exists to notice. The lost
// follower must still turn a regime red, by name, with its fate — the restart
// is only what lets the regime go on to measure whether the network recovers,
// which is the question a permanently absent node makes unanswerable.
func TestANodeThatDiedUnbiddenIsBroughtBackAndStillReported(t *testing.T) {
	m, reports := captureLiveness(t)
	revived := 0
	m.restart = func(n *soakNode) {
		revived++
		respawn(t, m, n, "live")
	}
	n := superviseFatedChild(t, m, "9")

	select {
	case <-n.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the child was never reaped, so nothing could have noticed it die")
	}
	if got := reports.all(); len(got) != 1 {
		t.Fatalf("the death was reported %d times before any revival; the queue must not "+
			"change what a run is told, and this test cannot separate the two if it does",
			len(got))
	}

	reviveTheDead(t, []*soakNode{n})

	if revived != 1 {
		t.Errorf("a node died unbidden and was brought back %d times, not once: the "+
			"regime is still hostage to a process something outside it removed, which "+
			"is the five minutes spent failing to converge on a node that was gone",
			revived)
	}
	if got := m.revivalCount("d"); got != 1 {
		t.Errorf("the instrument counted %d revivals having performed 1; the bound and "+
			"the report both read this number", got)
	}
	select {
	case <-n.exited:
		t.Error("the node was not running after its revival, so nothing was brought back")
	default:
	}
	got := reports.all()
	if len(got) != 1 {
		t.Fatalf("the run was told %d things after one death and one revival, and it "+
			"must be told exactly the death", len(got))
	}
	if !strings.Contains(got[0], "the harness did not ask") ||
		!strings.Contains(got[0], "exit status 9 (code 9)") {
		t.Errorf("bringing the node back changed what the run was told about the death; "+
			"a supervisor that edits the report is how a defect stops being read:\n%s",
			got[0])
	}
}

// The property: **a node the harness killed on purpose is NOT brought back by
// the supervisor.**
//
// The soak kills and restarts three or four nodes a run, and applyChaos owns
// those restarts: it kills, it waits, it starts. A supervisor that also revived
// them would start a second process for the same node behind applyChaos's back
// — two zycordd processes on one data directory and one RPC port — which is a
// worse defect than the one being fixed. The discrimination is the same
// per-start announcement the report uses, and this pins that the queue reads it
// too rather than only the report.
func TestAKillTheHarnessAskedIsNotBroughtBack(t *testing.T) {
	m, _ := captureLiveness(t)
	revived := 0
	m.restart = func(n *soakNode) { revived++ }
	n := superviseFatedChild(t, m, "live")

	stopNode(n) // exactly what applyChaos does, and it restarts the node itself

	reviveTheDead(t, []*soakNode{n})

	if revived != 0 {
		t.Errorf("the harness killed a node on purpose and the supervisor started it "+
			"again as well (%d times); applyChaos already owns that restart, so this is "+
			"two processes on one data directory and one RPC port", revived)
	}
}

// The property: **a revival queued for one run of a node is NOT issued once the
// harness has started that node again itself.**
//
// Distinct from the announcement channel, and no test above covers it. `expected`
// answers "did the harness cause THIS death"; this answers "is the node still
// dead by the time anyone gets round to the queue". The regime drains at the top
// of applyChaos and inside waitForConvergence, and the demote loop between them
// stops and restarts each miner — several seconds in which the node named by a
// queued death comes back without the queue hearing about it.
//
// The harm is not the two-processes-one-lock collision, which is where this
// looks like it stops. The duplicate does lose the lock and call fatal(); by
// then superviseNode has overwritten n.cmd, so t.Cleanup kills the corpse and
// the HEALTHY process is orphaned and outlives the run.
func TestARevivalIsNotIssuedForARunTheHarnessAlreadyRestarted(t *testing.T) {
	m, _ := captureLiveness(t)
	issued := 0
	m.restart = func(n *soakNode) { issued++ }
	n := superviseFatedChild(t, m, "9")

	select {
	case <-n.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the child was never reaped, so no death was ever queued")
	}

	// The harness brings it back on its own — exactly what the demote loop and
	// applyChaos's case 0 do, and neither tells the queue.
	respawn(t, m, n, "live")

	reviveTheDead(t, []*soakNode{n})

	if issued != 0 {
		t.Errorf("a revival was issued %d times for a run the harness had already "+
			"restarted; that is a second process on one data directory and one RPC "+
			"port, and because superviseNode has already replaced n.cmd it leaves the "+
			"HEALTHY process orphaned past t.Cleanup", issued)
	}
}

// The property: **a node that keeps being removed is brought back a bounded
// number of times, and the giving-up is said once.**
//
// The failure this answers is a process removed by something outside the test,
// and whatever removed it once can remove it again. An unbounded supervisor
// answers that with a restart loop for the length of the regime, which buries
// the report under its own noise — the instrument failing the same way the
// silent follower did, from the opposite direction.
//
// Driven through the queue rather than through five real child processes: the
// input here is repetition, and spawning processes to count to five would be
// testing the operating system.
func TestRevivalIsBoundedSoARepeatedRemovalIsNotARestartLoop(t *testing.T) {
	m, reports := captureLiveness(t)
	m.restart = func(n *soakNode) {}
	n := &soakNode{name: "d", monitor: m, logPath: writeFatedLog(t), rpcPort: livenessDeadPort}

	for i := 0; i < resurrectLimit+2; i++ {
		m.mu.Lock()
		m.queueRevivalLocked(n)
		m.mu.Unlock()
	}

	if got := len(m.takeRevivals()); got != resurrectLimit {
		t.Errorf("a node removed %d times was queued for revival %d times, and the bound "+
			"is %d; without it the regime restarts a node for as long as something "+
			"outside keeps killing it", resurrectLimit+2, got, resurrectLimit)
	}
	said := 0
	for _, r := range reports.all() {
		if strings.Contains(r, "will not be brought back again") {
			said++
		}
	}
	if said != 1 {
		t.Errorf("the supervisor said it was giving up %d times; a bound reached in "+
			"silence reads as a supervisor that is still trying, and one that repeats "+
			"itself is the restart loop it replaced", said)
	}
}

// ---------------------------------------------------------------------------

// livenessDeadPort is a loopback port nothing serves, so a sampler pointed at
// it is refused immediately rather than waiting out the client's timeout.
const livenessDeadPort = 1

// livenessReports collects what the instrument announced.
type livenessReports struct {
	mu   sync.Mutex
	seen []string
}

func (r *livenessReports) add(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, fmt.Sprintf(format, args...))
}

func (r *livenessReports) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// captureLiveness builds a monitor whose reports are collected instead of
// failing the test that is asserting on them.
func captureLiveness(t *testing.T) (*liveness, *livenessReports) {
	t.Helper()
	m := newLiveness(t)
	reports := &livenessReports{}
	m.sink = reports.add
	return m, reports
}

// superviseFatedChild starts this test binary as a child with a chosen fate and
// supervises it exactly as startNode supervises a node, monitor included.
//
// It is named `d` and given a log file because the report names both, and a
// report asserted against a node with no name and no log is asserted against
// half of itself.
func superviseFatedChild(t *testing.T, m *liveness, fate string) *soakNode {
	t.Helper()
	n := &soakNode{
		name:    "d",
		monitor: m,
		logPath: writeFatedLog(t),
		// A port nothing serves, so the sampler runs for real and is refused
		// for real. That is the input the slow-node row needs: a watcher that
		// is awake, asking, and getting nothing, and still not calling it a
		// death. A node with no sampler attached would pass that row by not
		// having been watched.
		rpcPort: livenessDeadPort,
	}
	m.attach(n)
	// A state to be the last one, so that "the last state anyone saw it in" has
	// something to be. The sampler cannot supply it — this child serves no RPC —
	// and inventing an RPC server here would be testing the server.
	m.record(n.name, "height=41 tip=0xfeed root=0xbeef")
	respawn(t, m, n, fate)
	t.Cleanup(func() { stopNode(n) })
	return n
}

// respawn starts another run of a fated child on the same node.
func respawn(t *testing.T, m *liveness, n *soakNode, fate string) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "ZCD_SOAK_CHILD_FATE="+fate)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the fated child: %v", err)
	}
	m.started(n.name)
	superviseNode(n, cmd)
}

// writeFatedLog gives a fated child a log file with a last line in it.
func writeFatedLog(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + "d.log"
	const line = "2026/08/26 08:40:07 rpc listening on 127.0.0.1:46089 " +
		"(read-only; submission is the only write)\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
