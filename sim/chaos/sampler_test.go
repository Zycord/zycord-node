package chaos_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The resource-and-latency sampler.
//
// The soak regimes already answer the structural question — every surviving
// node converges to one chain with one state root — and they answer it well.
// What they do not do is put a NUMBER on the two things an operator asks next:
//
//   - how far behind the tip does a node actually run, and how long does a
//     block take to reach every node;
//   - does anything grow without bound over hours — memory, goroutines, file
//     descriptors, disk.
//
// Neither is a pass/fail property the existing assertions could have been
// extended to cover, and that is deliberate. A convergence failure is a defect
// at any load; a trail of four blocks is a defect on an idle machine and
// ordinary on a machine running five other test suites. So this samples and
// reports, and leaves the judgment to whoever reads the artifact — the same
// division chaosScale draws between a lead and a finding.
//
// **Off unless asked for.** `ZCD_SOAK_SAMPLE=10s` turns it on. Unset, it does
// not start, does not poll, and does not write, so every existing run stays
// comparable with every run recorded before this file existed.
//
// The artifact is a TSV in the durable log directory beside the node logs,
// written incrementally and flushed every row: a run killed by a CI timeout or
// an operator's Ctrl-C keeps everything it had measured up to that point,
// which is the same reason soakLogDir exists.

// sampleInterval reads ZCD_SOAK_SAMPLE. Zero means the sampler stays off.
func sampleInterval() time.Duration {
	raw := os.Getenv("ZCD_SOAK_SAMPLE")
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		// Refused rather than defaulted, for the reason ZCD_SOAK_SEED is: a
		// sampler that silently ran at some other interval would date every
		// measurement wrongly, and a rate is what a growth figure is divided by.
		fmt.Fprintln(os.Stderr, "chaos: unusable ZCD_SOAK_SAMPLE:", raw)
		return 0
	}
	return d
}

// sample is one node observed at one instant.
type sample struct {
	at      time.Duration // since the sampler started
	node    string
	height  uint64
	tip     string
	root    string
	rssKB   uint64
	threads uint64
	fds     uint64
	diskKB  uint64
	// trail is how many blocks behind the highest node this one was, at this
	// instant. Zero for whichever node is highest.
	trail uint64
	// reachable is false when the node did not answer; every other field is
	// then meaningless and the row still exists, because an unanswered poll is
	// itself the measurement during a partition or a kill.
	reachable bool
}

// sampler observes a running soak network without disturbing it.
type sampler struct {
	mu      sync.Mutex
	nodes   []*soakNode
	started time.Time
	// rows is every sample taken, kept because the closing percentiles are
	// computed over the whole run rather than over a window. It grows with the
	// duration and nothing else: one small struct per node per interval, so a
	// four-hour run at fifteen seconds holds under four thousand of them. That
	// is a bound, unlike the propagation maps below, which grow with the number
	// of distinct tips a contested chain produces and are pruned.
	rows []sample
	// firstSeen dates a block id's first sighting at any node; seenBy counts
	// how many distinct nodes have since reported it as their tip. Together
	// they give propagation: the delay between one node holding a tip and the
	// last node holding it.
	firstSeen map[string]time.Duration
	seenBy    map[string]map[string]bool
	// propagation is the completed measurements: for every tip that reached
	// every node, how long that took.
	propagation []time.Duration
	out         *os.File
	stop        chan struct{}
	done        sync.WaitGroup
}

// startSampler begins sampling if ZCD_SOAK_SAMPLE asked for it, and returns nil
// otherwise. The returned sampler's report runs from t.Cleanup, so a regime
// that fails part way through still emits everything it measured.
func startSampler(t *testing.T, nodes []*soakNode, dir string) *sampler {
	t.Helper()
	every := sampleInterval()
	if every == 0 {
		return nil
	}
	path := filepath.Join(dir, "samples.tsv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the sample artifact %s: %v", path, err)
	}
	fmt.Fprintln(f, "# seconds\tnode\treachable\theight\ttrail\trss_kb\tthreads\tfds\tdisk_kb\ttip")
	s := &sampler{
		nodes:     nodes,
		started:   time.Now(),
		firstSeen: map[string]time.Duration{},
		seenBy:    map[string]map[string]bool{},
		out:       f,
		stop:      make(chan struct{}),
	}
	t.Logf("sampling every %s into %s", every, path)
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				s.once()
			}
		}
	}()
	t.Cleanup(func() { s.finish(t) })
	return s
}

// once takes one round of samples across every node.
//
// Every node is polled before anything is recorded, so the trail figures in a
// round are computed against a tip observed in the same round rather than
// against a moving one.
func (s *sampler) once() {
	now := time.Since(s.started)
	round := make([]sample, 0, len(s.nodes))
	var best uint64
	for _, n := range s.nodes {
		row := sample{at: now, node: n.name}
		st, err := status(n.rpcPort)
		if err == nil {
			row.reachable = true
			if h, ok := st["height"].(float64); ok {
				row.height = uint64(h)
			}
			row.tip, _ = st["tip"].(string)
			row.root, _ = st["state_root"].(string)
			if row.height > best {
				best = row.height
			}
		}
		// Read from /proc rather than from the node, deliberately: a node
		// reporting its own memory would be reporting the Go heap, and the
		// question is what the operating system has committed to the process —
		// which includes everything the heap figure omits.
		if pid := s.pidOf(n); pid > 0 {
			row.rssKB, row.threads = procStatus(pid)
			row.fds = countFDs(pid)
		}
		row.diskKB = dirKB(n.dir)
		round = append(round, row)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range round {
		if round[i].reachable && best > round[i].height {
			round[i].trail = best - round[i].height
		}
		s.note(round[i], now)
		s.write(round[i])
	}
	s.rows = append(s.rows, round...)
}

// pidOf reads the live process id, under no lock this harness owns.
//
// The fields it reads are written by startNode on the test's own goroutine and
// the sampler only reads them, so a torn read here would produce a pid of zero
// or a stale one — a missing row, never a wrong measurement attributed to a
// live process. A nil check on each hop is the whole guard, because a node
// between a kill and its restart genuinely has no process and that is a fact
// worth recording as a blank rather than a crash.
func (s *sampler) pidOf(n *soakNode) int {
	cmd := n.cmd
	if cmd == nil || cmd.Process == nil {
		return 0
	}
	// A reaped process keeps its Pid field, so /proc simply misses and every
	// resource field stays zero. That is the correct reading for a node that is
	// not running.
	return cmd.Process.Pid
}

// note folds one sample into the propagation tracker.
func (s *sampler) note(row sample, now time.Duration) {
	if !row.reachable || row.tip == "" {
		return
	}
	if _, ok := s.firstSeen[row.tip]; !ok {
		s.firstSeen[row.tip] = now
		s.seenBy[row.tip] = map[string]bool{}
	}
	seen := s.seenBy[row.tip]
	if seen[row.node] {
		return
	}
	seen[row.node] = true
	// Completed the moment every node has held this tip. Tips that never reach
	// every node — the overwhelming majority, since a contested chain reorgs
	// them away — contribute nothing, which is correct: a block that was never
	// universally adopted has no propagation time to measure.
	if len(seen) == len(s.nodes) {
		s.propagation = append(s.propagation, now-s.firstSeen[row.tip])
		// Retired once measured. Nothing further can be learned from a tip every
		// node already holds, and leaving it would keep a row per block for the
		// life of the run.
		delete(s.firstSeen, row.tip)
		delete(s.seenBy, row.tip)
		return
	}
	// A tip that never reached every node is retired by age instead.
	//
	// The instrument in a run that measures unbounded growth must not grow
	// without bound itself. A contested chain abandons most of the tips it
	// produces, so without this the two maps keep one entry per block ever
	// observed — a slow leak in the one process whose job is to notice them.
	// The horizon is generous: a tip still incomplete after this long did not
	// propagate, and the run has already recorded that as a trail.
	s.forget(now)
}

// propagationHorizon is how long an incomplete tip is kept before the sampler
// stops waiting for the rest of the network to adopt it.
const propagationHorizon = 5 * time.Minute

func (s *sampler) forget(now time.Duration) {
	for tip, at := range s.firstSeen {
		if now-at > propagationHorizon {
			delete(s.firstSeen, tip)
			delete(s.seenBy, tip)
		}
	}
}

func (s *sampler) write(row sample) {
	tip := row.tip
	if len(tip) > 16 {
		tip = tip[:16]
	}
	fmt.Fprintf(s.out, "%.0f\t%s\t%t\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
		row.at.Seconds(), row.node, row.reachable, row.height, row.trail,
		row.rssKB, row.threads, row.fds, row.diskKB, tip)
	// Flushed by being unbuffered: os.File writes straight through, so a run
	// that never reaches its own cleanup still leaves every row it took.
}

// finish stops sampling and reports. Called from t.Cleanup, so it runs on a
// failing regime too.
func (s *sampler) finish(t *testing.T) {
	close(s.stop)
	s.done.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.out.Close()

	if len(s.rows) == 0 {
		t.Log("sampler: no rows taken")
		return
	}
	span := s.rows[len(s.rows)-1].at

	// Latency, as two different numbers, because they answer different
	// questions. Trail is a steady-state property of a node; propagation is a
	// property of the link and the gossip path.
	var trails []float64
	for _, r := range s.rows {
		if r.reachable {
			trails = append(trails, float64(r.trail))
		}
	}
	if len(trails) > 0 {
		t.Logf("trail behind tip over %s: p50=%.0f p90=%.0f p99=%.0f max=%.0f blocks (n=%d node-samples)",
			span.Round(time.Second), pct(trails, 0.50), pct(trails, 0.90),
			pct(trails, 0.99), pct(trails, 1.0), len(trails))
	}
	if len(s.propagation) > 0 {
		var ms []float64
		for _, d := range s.propagation {
			ms = append(ms, d.Seconds())
		}
		// Bounded below by the sample interval: a tip that reaches every node
		// between two polls is recorded as zero, and this cannot resolve
		// anything faster than it samples. Stated because a p50 of 0 would
		// otherwise read as instant propagation rather than as sub-interval.
		t.Logf("tip propagation to all %d nodes: p50=%.0fs p90=%.0fs max=%.0fs (n=%d tips; "+
			"resolution is the %s sample interval, so 0 means faster than one poll)",
			len(s.nodes), pct(ms, 0.50), pct(ms, 0.90), pct(ms, 1.0),
			len(s.propagation), sampleInterval())
	} else {
		t.Log("tip propagation: no tip was held by every node within one sample, so NOT MEASURED")
	}

	// Growth, as first-versus-last per node rather than as a slope. A slope
	// over a series with restarts in it is a fit to a discontinuous function
	// and would report a trend that no process experienced; a node that was
	// killed and restarted has a genuinely new process whose memory starts
	// again from nothing, and the honest summary of that is the peak.
	for _, n := range s.nodes {
		var first, last, peakRSS, peakFD, peakDisk, peakThreads uint64
		var haveFirst bool
		for _, r := range s.rows {
			if r.node != n.name {
				continue
			}
			if r.rssKB > 0 && !haveFirst {
				first, haveFirst = r.rssKB, true
			}
			if r.rssKB > 0 {
				last = r.rssKB
			}
			peakRSS = max64(peakRSS, r.rssKB)
			peakFD = max64(peakFD, r.fds)
			peakDisk = max64(peakDisk, r.diskKB)
			peakThreads = max64(peakThreads, r.threads)
		}
		t.Logf("%s: rss %d->%d KB (peak %d), threads peak %d, fds peak %d, disk peak %d KB",
			n.name, first, last, peakRSS, peakThreads, peakFD, peakDisk)
	}
	t.Logf("samples: %d rows over %s", len(s.rows), span.Round(time.Second))
}

// pct returns the qth quantile by nearest rank. q=1.0 is the maximum.
func pct(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	i := int(q * float64(len(s)-1))
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// procStatus reads resident memory and thread count for a pid.
//
// Threads rather than goroutines, and the difference is worth naming: the Go
// runtime multiplexes goroutines onto threads, so a goroutine leak shows here
// only once it blocks in a syscall. It is what /proc can see from outside a
// process that exposes no pprof endpoint, and a thread count that climbs for
// two hours is a finding on its own. A goroutine census would need the node to
// serve /debug/pprof, which it deliberately does not.
func procStatus(pid int) (rssKB, threads uint64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			rssKB = firstNumber(line)
		case strings.HasPrefix(line, "Threads:"):
			threads = firstNumber(line)
		}
	}
	return rssKB, threads
}

func firstNumber(line string) uint64 {
	for _, f := range strings.Fields(line) {
		if v, err := strconv.ParseUint(f, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

func countFDs(pid int) uint64 {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0
	}
	return uint64(len(entries))
}

// dirKB is the node's data directory on disk, in kilobytes.
func dirKB(dir string) uint64 {
	if dir == "" {
		return 0
	}
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		// Errors are skipped rather than returned: a node compacting its store
		// removes files under the walk, and a disk figure that fails whenever
		// the thing it measures is busy would be missing exactly when it
		// matters.
		if err != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // see above
		}
		total += info.Size()
		return nil
	})
	return uint64(total / 1024)
}

// assertSettledHeightAgrees pins the id of a block every node has already
// passed, and is the strong form of "the network converged".
//
// waitForConvergence compares tips, which is the right question at the end of a
// regime that leaves one miner running. It is a weaker question than it looks
// while miners are racing: heights oscillate, so four processes sampled between
// blocks can agree on a tip and still be about to disagree, and a run that
// polled at a lucky instant reports the same success as one that was genuinely
// settled.
//
// A height BELOW every node's tip cannot oscillate that way. Every node has
// built past it, the block at it is committed on each of their canonical
// chains, and asking all of them for its id is asking whether they built the
// same history — which is what convergence means. The margin is what makes it
// settled: a height one block below the shallowest tip is still reachable by an
// ordinary reorg, so the check backs off by `behind` blocks first.
//
// Reported with the height, the id and the number of nodes that answered,
// because "converged" without those three is an impression.
func assertSettledHeightAgrees(t *testing.T, nodes []*soakNode, behind uint64) {
	t.Helper()

	shallowest := ^uint64(0)
	answered := 0
	for _, n := range nodes {
		st, err := status(n.rpcPort)
		if err != nil {
			continue
		}
		h, ok := st["height"].(float64)
		if !ok {
			continue
		}
		answered++
		if uint64(h) < shallowest {
			shallowest = uint64(h)
		}
	}
	if answered < len(nodes) {
		// Not an error here. Whether an unreachable node is a failure is
		// waitForConvergence's question and it already answers it; reporting it
		// twice would attribute one absence to two defects.
		t.Logf("settled-height check: only %d of %d nodes answered", answered, len(nodes))
	}
	if answered == 0 {
		t.Error("no node answered, so the settled height could not be compared")
		return
	}
	if shallowest <= behind {
		t.Errorf("the shallowest tip is %d, which is not %d blocks past genesis: "+
			"NOT MEASURED — no height is settled enough to compare, so this run "+
			"has no id-level convergence evidence", shallowest, behind)
		return
	}
	height := shallowest - behind

	ids := map[string][]string{}
	for _, n := range nodes {
		id, err := blockIDAt(n.rpcPort, height)
		if err != nil {
			t.Logf("settled-height check: %s did not serve height %d: %v", n.name, height, err)
			continue
		}
		ids[id] = append(ids[id], n.name)
	}
	if len(ids) == 0 {
		t.Errorf("no node served the block at settled height %d", height)
		return
	}
	if len(ids) > 1 {
		// The single most valuable thing this suite can find: two nodes that
		// built different history at a height both have passed is a divergence,
		// not churn, and no amount of further running resolves it.
		var lines []string
		for id, who := range ids {
			lines = append(lines, fmt.Sprintf("%s held by %s", id, strings.Join(who, ",")))
		}
		sort.Strings(lines)
		t.Errorf("DIVERGENCE at settled height %d: %s", height, strings.Join(lines, "; "))
		return
	}
	for id, who := range ids {
		// One id among fewer than every node is agreement among those that
		// answered and nothing more. Saying so is the difference between
		// evidence and a number that looks like evidence: a run where three
		// nodes were dead and the fourth agreed with itself must not read the
		// same as a run where four agreed with each other.
		if len(who) < len(nodes) {
			t.Errorf("settled height %d: one id %s, but only %d of %d nodes served it "+
				"(%s). PARTIAL — the nodes that answered agree, and the rest are "+
				"unaccounted for rather than in agreement",
				height, id, len(who), len(nodes), strings.Join(who, ","))
			return
		}
		t.Logf("settled convergence: height %d, id %s, agreed by %d/%d nodes (%s)",
			height, id, len(who), len(nodes), strings.Join(who, ","))
	}
}

// settledMargin is how far below the shallowest tip a height is treated as
// past reorging, for the id comparison.
//
// One epoch. Below a boundary the state root has been committed, so a height
// that far back has survived the one check that detects two nodes holding one
// chain and different state — and it is far enough that the ordinary one- and
// two-block races a contested tip produces cannot reach it. It is deliberately
// NOT contentionDepth: that horizon is sized for continuous three-way mining,
// and applying it to a regime that ends with a single miner would back the
// check off past the chain a short run produced and measure nothing.
const settledMargin = soakEpochLength
