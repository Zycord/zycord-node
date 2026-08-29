package chaos_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/p2p"
	"zycord/sim/chaos"
	"zycord/wallet"
)

// The chaos soak (M2 §5).
//
// Real `zycordd` processes, real sockets, real TLS, and a hostile link
// between them: latency, jitter, loss, severed connections and partitions,
// compounded by killing and restarting nodes at random. The scheduler is the
// operating system's, not a harness's.
//
// The invariant is the same one the deterministic harness checks, and that is
// the point: **every surviving node converges to one chain with one state
// root.** If the logic is right and the implementation of it is not, this is
// where the difference shows.
//
// Run the long version with:
//
//	go test ./sim/chaos -run TestChaosSoak -soak=5m -v

var soakDuration = 25 * time.Second

// soakSeedShift moves every regime's chaos schedule, from ZCD_SOAK_SEED.
//
// The soak's randomness is seeded from a constant, so the kills, the partitions
// and the port block are the same on every run. Measured: consecutive runs of
// `ZCD_SOAK=25s` draw the identical schedule every time — 3 kills, 3 partitions,
// convergence at height 25.
//
// What a shift buys is breadth, not reproduction, and the distinction is worth
// stating here because the opposite was published first and had to be
// withdrawn. A fixed seed is not a fixed outcome: the silent-follower death's
// "roughly one run in five" was itself measured at this one seed, against a
// battery in which not every run failed, so the death it reports is a race
// inside the schedule rather than a property of it. Rerunning a fixed seed
// therefore does sample that race again, and that report's negative controls
// were narrow rather than empty. What rerunning cannot do is widen the kill
// counts, partition counts and port blocks under test. That is what a shift
// gives — along with a failing run able to name the schedule that produced it.
//
// Seed, not schedule, and the distinction is measured: at seed 7 the 25 s and
// 90 s forms draw *different* schedules — (3 kills, 3 partitions) against (4
// kills, 13 partitions) — and the exhibited failure is the 25 s form while its
// reproduction recipe names 90 s, so its battery was plausibly mixed.
//
// A shift rather than an outright seed, so the three regimes keep the distinct
// seeds they were given and stay distinct under every value of it.
var soakSeedShift int64

// soakChildLiveSpan bounds the fated child that has to outlive its own report.
//
// A bound rather than an hour, because the sleep is what an orphan runs. If the
// test binary goes before its cleanup does — a timeout, a panic elsewhere in
// the package — the child is left sleeping for exactly this long on a machine
// that has other work to do. Two minutes outlives every report in this file by
// orders of magnitude and still clears itself when nothing else does.
const soakChildLiveSpan = 2 * time.Minute

// soakChildLingerSpan is an ordinary teardown: long enough that a grace of a
// few tens of milliseconds would call it wedged, short enough that
// exitReportGrace reaps it with room to spare.
//
// It exists to give exitReportGrace's VALUE a separating input. Every other
// fated child either exits at once or not at all, and against those two a
// grace of 90ms and a grace of two seconds are the same grace — while the harm
// of a short one is specific: a process merely on its way out is reported as
// wedged, which names a node defect where there is none, and the owner is the
// whole reason the three fates are told apart.
const soakChildLingerSpan = 300 * time.Millisecond

func TestMain(m *testing.M) {
	// A child process with a fate this binary chose, so exitReport can be
	// driven against real process states rather than a fake one.
	//
	// The thing under test is what os/exec reports about a process that this
	// harness did not kill, which no in-process double can produce: a
	// ProcessState comes from the operating system reaping a real child. An
	// exit code, a process that outlives its report, and a process that takes
	// a moment to go are the fates exitReport has to tell apart, and they
	// differ only in how this branch leaves.
	if fate := os.Getenv("ZCD_SOAK_CHILD_FATE"); fate != "" {
		switch fate {
		case "live":
			time.Sleep(soakChildLiveSpan)
			os.Exit(0)
		case "linger":
			time.Sleep(soakChildLingerSpan)
			os.Exit(0)
		}
		code, err := strconv.Atoi(fate)
		if err != nil {
			fmt.Fprintln(os.Stderr, "chaos: unusable ZCD_SOAK_CHILD_FATE:", fate)
			os.Exit(125)
		}
		os.Exit(code)
	}
	if d := os.Getenv("ZCD_SOAK"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			soakDuration = parsed
		}
	}
	if s := os.Getenv("ZCD_SOAK_SEED"); s != "" {
		parsed, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			// Refused rather than ignored: a sweep that silently ran the same
			// schedule under every value would report a breadth it never had,
			// which is the exact mistake soakSeedShift exists to prevent.
			fmt.Fprintln(os.Stderr, "chaos: unusable ZCD_SOAK_SEED:", s)
			os.Exit(125)
		}
		soakSeedShift = parsed
	}
	os.Exit(m.Run())
}

type soakNode struct {
	name    string
	dir     string
	p2pPort int
	rpcPort int
	// proxyPort is what peers dial; the proxy forwards to p2pPort.
	proxyPort  int
	paramsPath string
	// key signs the load this node's payout funds. Generated in-process rather
	// than by shelling out to `zcd key new`, because the soak needs the private
	// half: a miner's payout is the only funded address on a chain with no
	// premine, so it is also the only thing that can pay for a transfer.
	key   *wallet.Key
	proxy *chaos.Proxy
	cmd   *exec.Cmd
	// exited closes when the process in cmd has been reaped, and is the only thing
	// that makes its ProcessState readable: exec.Cmd fills ProcessState in Wait
	// and nowhere else. One reaper per started process, launched by startNode, so
	// nothing else ever calls Wait and there is no second caller to lose the state
	// to.
	exited chan struct{}
	// expected closes when the harness is ABOUT to kill this run of the node,
	// before the kill is issued. It is what lets the reaper tell a chaos kill from
	// a death nobody asked for, and it is per-start rather than per-node so that
	// the announcement from a kill cannot answer for the run that follows it.
	expected chan struct{}
	// monitor watches this node's process while the regime runs. Nil for a node
	// no regime is monitoring, which is every node in the instrument's own
	// tests except the ones under it.
	monitor *liveness
	payout  string
	mining  bool
	peers   []string
	logPath string
}

func TestChaosSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	nodes, bin, rng, p, _ := newSoakNetwork(t, 7)

	// Before any chaos: prove the nodes are running the guarded build.
	assertNodesAreGuarded(t, nodes)

	// Real certificates, throughout (R6-G2). Without this the soak converges
	// beautifully while never once doing the thing the protocol exists to do.
	loadStop := make(chan struct{})
	driver := runLoad(t, nodes, p, loadStop)

	deadline := time.Now().Add(soakDuration)
	var kills, partitions int
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		kills, partitions = applyChaos(t, bin, nodes, rng, kills, partitions)
	}
	for _, n := range nodes {
		if n.proxy != nil {
			n.proxy.Partition(false)
		}
	}
	t.Logf("chaos: %d kills, %d partitions", kills, partitions)

	// Leave exactly one miner running, and restart the others without --mine.
	//
	// This is not making the test easier, it is making the question
	// well-posed. Three miners racing produce a contested tip almost
	// continuously, so "do all nodes agree right now" is asking whether four
	// processes happened to be sampled between blocks. Stopping *all* of them
	// is wrong too: two branches of equal work stay forked forever, correctly,
	// because first-seen wins and nothing breaks the tie.
	//
	// One miner makes convergence a property rather than a coincidence: it
	// extends its chain, accumulates strictly more work, and every other node
	// must follow it or be wrong.
	//
	// The other regime — contention that never stops, which is what a live
	// network actually has — is TestChaosSoakUnderContinuousContention.
	for _, n := range nodes[1:] {
		if n.mining {
			stopNode(n)
			n.mining = false
			startNode(t, bin.zycordd, n)
		}
	}

	// The window accounts for what stopping two of three miners actually does.
	//
	// Hashrate drops to a third, and LWMA is *deliberately* slow to react — that
	// slowness is the anti-manipulation property, not a defect — so the surviving
	// miner needs tens of blocks at several times the target interval before the
	// difficulty catches up and the cadence recovers. A window sized for the
	// pre-drop block time measures the difficulty rule doing its job and calls it
	// a convergence failure.
	converged := waitForConvergence(t, nodes, 5*time.Minute)
	if !converged {
		for _, n := range nodes {
			st, err := status(n.rpcPort)
			if err != nil {
				t.Logf("%s: unreachable (%v); %s", n.name, err,
					exitReport(n, exitReportGrace))
				continue
			}
			t.Logf("%s: height=%v tip=%v root=%v", n.name, st["height"], st["tip"], st["state_root"])
		}
		dumpLogs(t, nodes)
		t.Error("the network did not converge after the chaos stopped")
	}

	// Reported, not aborted, for the same reason as the contention regime: a
	// convergence failure is a fact about the network's structure and the
	// billing law is a fact about its economics. One must not hide the other,
	// and a run that fails to converge is exactly when it is most useful to know
	// whether anything was billed twice on the way there.
	assertSoakCrossedABoundary(t, nodes, soakEpochLength)
	close(loadStop)
	assertBillingLawHeld(t, nodes, driver)
	assertNoLocalViolations(t, nodes)
}

// newSoakNetwork builds the three-miner-plus-periphery network behind chaos
// proxies and starts it.
//
// The reserved block is returned, not just consumed, so that a regime which
// needs a further port takes it from the reservation rather than from a
// neighbour's port. See soakLateJoinerRPC.
func newSoakNetwork(t *testing.T, seed int64) ([]*soakNode, binaries, *rand.Rand, *params.Params, *portBlock) {
	t.Helper()
	bin := buildBinaries(t)
	root := t.TempDir()
	logs := soakLogDir(t)
	seed += soakSeedShift
	// Named in the output, not only in the manifest: a failing run has to say
	// which schedule produced it, or the reproduction instruction is "run it
	// again and hope".
	t.Logf("chaos schedule seed %d (ZCD_SOAK_SEED=%d)", seed, soakSeedShift)
	rng := rand.New(rand.NewSource(seed))
	// Registered before the nodes, so its cleanup runs after theirs: the summary
	// is printed once every node has been stopped, and a node that had already
	// died unbidden has been reported by then.
	mon := newLiveness(t)
	// The supervisor a death nobody asked for did not have.
	//
	// applyChaos restarts every node IT kills, so "a node comes back from a hard
	// kill" is the most heavily exercised behaviour in this file — and a node
	// removed by anything else stayed removed, because the restart lived inside
	// the code that did the killing rather than beside the code that notices a
	// death. The lost follower is the whole cost of that: it was gone within
	// fifteen seconds and the regime then spent five minutes reporting that four
	// nodes were not all reachable.
	mon.restart = func(n *soakNode) { startNode(t, bin.zycordd, n) }

	// The soak runs on its own parameter set, and the reason is the epoch
	// length. Devnet's is 64, and a soak that converges at height 63 has never
	// run the epoch state-root check — which is the *only* check that detects
	// two nodes agreeing on a chain while holding different state. A four-minute
	// run reached exactly 63 and passed, having tested nothing of the sort.
	//
	// With boundaries every eight blocks the check runs repeatedly inside the
	// default twenty-five seconds, and assertSoakCrossedABoundary below refuses
	// to let a run count if it did not reach one anyway.
	//
	// A different parameter set is a different genesis is a different network
	// id (R3-1), so these nodes cannot talk to a devnet node. That is correct
	// and free: they have nothing to say to one.
	paramsPath := writeSoakParams(t, root)

	// Three miners behind chaos proxies, plus one outbound-only node — the
	// shape a home connection has without NAT traversal.
	//
	// The block stays HELD from here until each port's real bind; nothing is
	// released early and nothing is left to a probe's word.
	block := freePortBlock(t, rng)
	t.Cleanup(block.releaseAll)
	base := block.base
	nodes := []*soakNode{
		{name: "a", p2pPort: base + soakP2PBase, proxyPort: base + soakProxyBase, rpcPort: base + soakRPCBase, mining: true},
		{name: "b", p2pPort: base + soakP2PBase + 1, proxyPort: base + soakProxyBase + 1, rpcPort: base + soakRPCBase + 1, mining: true},
		{name: "c", p2pPort: base + soakP2PBase + 2, proxyPort: base + soakProxyBase + 2, rpcPort: base + soakRPCBase + 2, mining: true},
		{name: "d", rpcPort: base + soakRPCBase + 3}, // outbound-only
	}

	cfg := chaos.Config{
		Latency:   time.Duration(15 * latencyScale() * float64(time.Millisecond)),
		Jitter:    time.Duration(35 * latencyScale() * float64(time.Millisecond)),
		DropRate:  0.001 * chaosScale(),
		SeverRate: 0.0005 * chaosScale(),
	}

	for _, n := range nodes {
		n.dir = filepath.Join(root, n.name)
		n.logPath = filepath.Join(logs, n.name+".log")
		n.paramsPath = paramsPath
		n.monitor = mon
		k, err := wallet.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		n.key = k
		n.payout = hex.EncodeToString(payoutBytes(k))
		if n.p2pPort != 0 {
			// Handed over at the instant the proxy binds it, and not before.
			block.release(n.proxyPort)
			proxy, err := chaos.NewProxy(addr(n.proxyPort), addr(n.p2pPort), cfg, int64(n.p2pPort))
			if err != nil {
				t.Fatal(err)
			}
			n.proxy = proxy
			t.Cleanup(func() { proxy.Close() })
		}
	}
	// Everyone bootstraps through everyone else's *proxy*, so all traffic is
	// hostile.
	for _, n := range nodes {
		for _, other := range nodes {
			if other.name != n.name && other.proxyPort != 0 {
				n.peers = append(n.peers, addr(other.proxyPort))
			}
		}
	}

	writeSoakManifest(t, logs, seed, nodes)

	// Every remaining port goes back at once, here, rather than per node inside
	// the loop below. Per node would keep a hold a few milliseconds longer and
	// would trade this race for a worse one: node a dials b's proxy the moment
	// it starts, the proxy dials b's p2p port, and a port still held HERE
	// accepts that connection into a listener that never reads it. A refused
	// dial the node retries is correct behaviour; a connection swallowed by the
	// harness is not.
	block.releaseAll()
	for _, n := range nodes {
		startNode(t, bin.zycordd, n)
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			stopNode(n)
		}
	})

	return nodes, bin, rng, soakParams(t), block
}

// chaosScale multiplies the link's loss and severance rates.
//
// It exists to buy back wall-clock. The default rates are calibrated so that a
// ten-hour regime accumulates a realistic number of faults; a defect that needs
// a hundred severed connections to show itself therefore needs hours to reach.
// `ZCD_SOAK_CHAOS=10` reaches the same fault count in minutes, which is what
// makes a laptop useful for anticipating what a thirty-one-hour run will find.
//
// **A failure at a raised scale is a lead, not a finding**, and the distinction
// is the whole discipline. At a high enough severance rate no node can sync,
// because no connection survives long enough to carry a block — that is an
// impossible network rather than a broken one, and reporting it as a defect
// would be this project's own "noise with authority" in a new costume. What a
// raised scale is good for is the other direction: passing at 10x is real
// evidence about 1x, and a failure at 10x is a scenario to reproduce
// deterministically at 1x before anyone calls it a bug.
//
// The default is exactly 1.0, so an unset environment reproduces the calibrated
// rates bit for bit and every existing run remains comparable.
func chaosScale() float64 {
	raw := os.Getenv("ZCD_SOAK_CHAOS")
	if raw == "" {
		return 1.0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return 1.0
	}
	return v
}

// latencyScale multiplies the link's delay, separately from its fault rates.
//
// A separate knob from ZCD_SOAK_CHAOS because they are different physics, and
// conflating them would hide which one a finding belongs to. Loss and severance
// ask "does progress survive faults"; delay asks "does the protocol still work
// when every exchange takes longer" — and that question reaches different code:
// the read deadlines in `await`, the sixty-second serve deadline, a three-second
// sync interval against round trips that now take longer than it, and block
// propagation racing a five-second target interval.
//
// The default rates are a LAN with jitter: 15ms plus uniform 0-35ms per chunk,
// in both directions, with the jitter deliberately wide enough to reorder
// chunks. `ZCD_SOAK_LATENCY=5` makes that 75ms plus 0-175ms, which is roughly
// an intercontinental link and is what a global peer-to-peer network actually
// looks like.
//
// Read a raised-latency failure the same way as a raised-chaos one: a lead to
// reproduce at 1x, never a finding on its own. Past some delay no protocol with
// deadlines works, and that is a network nobody has rather than a defect.
//
// Unset is exactly 1.0, so every existing run stays comparable.
func latencyScale() float64 {
	raw := os.Getenv("ZCD_SOAK_LATENCY")
	if raw == "" {
		return 1.0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return 1.0
	}
	return v
}

// soakLogDir returns a directory that outlives the test.
//
// Node logs used to be written under `t.TempDir()`, which the framework deletes
// when the regime returns. A ten-hour run produced a node stranded at height 581
// while the network reached 5,702, and the only record of how it got there —
// 166 sync attempts, each ending in EOF — was deleted by the harness a moment
// after the failure was reported. The finding cost ten hours and could not be
// diagnosed; the next one may cost twenty.
//
// So the logs are written outside the ephemeral tree in the first place rather
// than copied out at the end. Copying is the weaker half of the choice: a run
// killed by a CI timeout, an OOM or an operator's Ctrl-C never reaches its own
// cleanup, and those are the runs whose logs are worth the most.
//
// The directory is deliberately never removed. `ZCD_SOAK_LOGDIR` points it at
// a volume that survives a VPS being reprovisioned.
func soakLogDir(t *testing.T) string {
	t.Helper()
	root := os.Getenv("ZCD_SOAK_LOGDIR")
	if root == "" {
		root = filepath.Join(os.TempDir(), "zycord-soak")
	}
	// Stamped per run: consecutive regimes and repeated runs must not append
	// into one another's files, or a log is a record of no particular execution.
	dir := filepath.Join(root, fmt.Sprintf("%s-%s", t.Name(),
		time.Now().UTC().Format("20060102T150405Z")))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating the durable log directory %s: %v", dir, err)
	}
	t.Logf("node logs: %s (durable — tail them while the run is in flight, and "+
		"they survive it)", dir)
	// Announced again at the end, because that is where an operator reading a
	// failure is looking.
	t.Cleanup(func() { t.Logf("node logs kept at %s", dir) })
	return dir
}

// writeSoakManifest records what a log directory is a log of.
//
// A directory of node logs found weeks later is only evidence if the roles,
// ports and seed that produced it are written down beside it. Which node was
// the outbound-only periphery, which mined, and what seed drove the chaos are
// all needed to reproduce a finding, and none of them is recoverable from the
// logs alone.
func writeSoakManifest(t *testing.T, dir string, seed int64, nodes []*soakNode) {
	t.Helper()
	type entry struct {
		Name    string   `json:"name"`
		Mining  bool     `json:"mining"`
		Listens bool     `json:"listens"`
		P2PPort int      `json:"p2p_port"`
		Proxy   int      `json:"proxy_port"`
		RPCPort int      `json:"rpc_port"`
		Peers   []string `json:"peers"`
		DataDir string   `json:"data_dir"`
		LogFile string   `json:"log_file"`
	}
	m := map[string]any{
		"regime":   t.Name(),
		"started":  time.Now().UTC().Format(time.RFC3339),
		"seed":     seed,
		"duration": soakDuration.String(),
	}
	var list []entry
	for _, n := range nodes {
		list = append(list, entry{
			Name: n.name, Mining: n.mining, Listens: n.p2pPort != 0,
			P2PPort: n.p2pPort, Proxy: n.proxyPort, RPCPort: n.rpcPort,
			Peers: n.peers, DataDir: n.dir, LogFile: n.logPath,
		})
	}
	m["nodes"] = list
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o644); err != nil {
		t.Fatalf("writing the soak manifest: %v", err)
	}
}

// soakParams parses the parameter set the soak nodes are running, so the load
// driver builds certificates against the same rules the nodes enforce.
func soakParams(t *testing.T) *params.Params {
	t.Helper()
	m := soakParamMap(t)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p, err := params.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// applyChaos performs one round of hostility and returns the running tallies.
func applyChaos(t *testing.T, bin binaries, nodes []*soakNode, rng *rand.Rand,
	kills, partitions int) (int, int) {
	t.Helper()
	// Before this round's hostility, not after: a node that is not running
	// cannot be partitioned or killed, so a regime that drew a kill for a node
	// still lying dead would spend that round doing nothing to a corpse.
	reviveTheDead(t, nodes)
	switch rng.Intn(6) {
	case 0:
		// Kill and restart a node. Compounds with R4-M1: a node may die
		// mid-reorg and must come back on exactly one branch.
		victim := nodes[rng.Intn(len(nodes))]
		stopNode(victim)
		kills++
		time.Sleep(300 * time.Millisecond)
		startNode(t, bin.zycordd, victim)
	case 1, 2:
		// Open a partition, then heal it.
		victim := nodes[rng.Intn(3)]
		if victim.proxy != nil {
			victim.proxy.Partition(true)
			partitions++
			time.Sleep(time.Duration(1+rng.Intn(3)) * time.Second)
			victim.proxy.Partition(false)
		}
	}
	return kills, partitions
}

// assertNodesAreGuarded fails unless every node reports the state guard armed.
func assertNodesAreGuarded(t *testing.T, nodes []*soakNode) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for _, n := range nodes {
		var ok bool
		for time.Now().Before(deadline) {
			raw, err := os.ReadFile(n.logPath)
			if err == nil && contains(string(raw), "state_guard=on") {
				ok = true
				break
			}
			if err == nil && contains(string(raw), "state_guard=off") {
				t.Fatalf("node %s is running an UNGUARDED build; the soak's whole "+
					"reason for building with -tags zcdguard is defeated", n.name)
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !ok {
			t.Fatalf("node %s never reported its guard state; cannot confirm the "+
				"soak is running the build it thinks it is", n.name)
		}
	}
	t.Log("all nodes report the consensus-state guard armed")
}

// soakEpochLength is short enough that a twenty-five second run crosses several
// boundaries. Everything else is devnet's.
const soakEpochLength = 8

// writeSoakParams derives the soak's parameter set from devnet.
func writeSoakParams(t *testing.T, dir string) string {
	t.Helper()
	p := soakParamMap(t)
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "params.soak.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// soakParamMap is the single source of the soak's parameter set.
//
// It was two copies: one wrote the file the nodes run, the other built the
// params the load driver signs certificates against. Same patches, applied
// twice, with nothing keeping them equal — and a drift between them is a driver
// building certificates against rules the nodes do not enforce, which would
// surface as a mysterious refusal rate rather than as an error.
//
// **`undo_depth` is raised to mainnet's 1024, and that is the point of this
// function existing at all.** Devnet's 128 is small because devnet is for fast
// tests. A soak that generates 128-block reorgs against a 128-block ceiling is
// measuring the ceiling: `ConsiderBranch` refuses anything deeper, so the
// observed maximum is right-censored at the parameter and the tail cannot be
// seen at any duration. Raising it here is a harness change in service of a
// measurement — the *mainnet* value remains an irreversible §1 parameter to be
// validated on the public testnet, not tuned on this data.
func soakParamMap(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "params.devnet.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["name"] = "zycord-soak"
	m["epoch_length"] = soakEpochLength
	m["undo_depth"] = soakUndoDepth
	return m
}

// assertSoakCrossedABoundary is the anti-vacuity guard on the whole test.
//
// Convergence below the first epoch boundary is convergence with the state-root
// check switched off: nodes are compared on tip and stored root, but no block
// has ever been *rejected* for disagreeing about state. A four-minute run
// stopped at height 63 against a boundary of 64 and reported success.
//
// The requirement lives here and only here. Folding it into waitForConvergence
// as a minimum height would enforce the same thing while reporting it as "the
// network did not converge", which is a true statement about a different
// problem — and it would make this function unreachable, so nothing would ever
// prove the guard works.
func assertSoakCrossedABoundary(t *testing.T, nodes []*soakNode, epochLength uint64) {
	t.Helper()
	var best float64
	for _, n := range nodes {
		st, err := status(n.rpcPort)
		if err != nil {
			continue
		}
		if h, ok := st["height"].(float64); ok && h > best {
			best = h
		}
	}
	if uint64(best) < epochLength {
		t.Errorf("the soak reached height %.0f but the first epoch boundary is %d: "+
			"the state-root check never ran, so this run proves nothing. Run longer "+
			"(ZCD_SOAK=2m) or shorten epoch_length further.", best, epochLength)
	}
	t.Logf("crossed %d epoch boundaries", uint64(best)/epochLength)
}

// violationMarkers are the log substrings that mean a node either broke an
// invariant or caught itself about to.
//
// Listing them explicitly rather than grepping for "error" is deliberate: a
// node under this much chaos logs a great many benign errors (severed
// connections, refused dials, stale templates), and a check that fires on all
// of them is a check nobody will keep.
var violationMarkers = []string{
	"conservation",
	"panic:",
	"goroutine ",
	"state root mismatch",
	"billing",
}

func assertNoLocalViolations(t *testing.T, nodes []*soakNode) {
	t.Helper()

	// The counter first, because it is the honest instrument.
	//
	// The billing law and conservation are enforced as block-invalidity, so a
	// violation cannot be applied — it appears as a refusal. Log-scraping for
	// that refusal was the only check available until the chain started
	// counting it, and the gossip path wrote no line at all unless the peer's
	// score crossed a threshold. A block refused during a soak is not
	// necessarily a bug (a stale template from a losing miner is refused too,
	// with ErrWrongParent, before the fold runs) but a block the *fold* refused
	// is: everything reaching it has already passed the header checks.
	for _, n := range nodes {
		m, err := metrics(n.rpcPort)
		if err != nil {
			continue
		}
		if r, ok := m["blocks_rejected"].(float64); ok && r > 0 {
			t.Errorf("%s refused %.0f block(s) at the fold: every one had already "+
				"passed the header checks, so this is a consensus disagreement, "+
				"not ordinary churn", n.name, r)
		}
	}

	for _, n := range nodes {
		raw, err := os.ReadFile(n.logPath)
		if err != nil {
			continue
		}
		for _, line := range splitLines(string(raw)) {
			for _, marker := range violationMarkers {
				if contains(line, marker) {
					t.Errorf("%s violated a local invariant: %s", n.name, line)
				}
			}
		}
	}
}

// waitForConvergence polls until every node agrees on one chain, or the
// deadline passes.
//
// All three of height, tip and state root are compared, and *every* node must
// answer. Agreeing on a state root alone is too weak — two nodes can share a
// root while sitting at different heights on different branches — and letting
// an unreachable node be skipped would pass a test in which the node that
// disagreed is simply the one that died.
func waitForConvergence(t *testing.T, nodes []*soakNode, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		// Here too, and not only in the chaos loop. The silent death landed in the
		// first fifteen seconds but this window is five minutes long, and it is the
		// window in which the question being asked — does the network reconverge — is
		// precisely the question a node that stays dead makes unanswerable. reachable
		// == len(nodes) is the condition below, so one unrevived node fails the whole
		// regime by absence.
		//
		// **Held by TestChaosSoakRevivesANodeKilledInsideTheConvergenceWindow in
		// revival_test.go, and by nothing that runs on a bare `go test`.** Deleting
		// this call was declared to survive the revival change's mutant table and did
		// survive every test that ran, because no unit test reaches this window at
		// all. The regime in revival_test.go kills it — a real node terminated from
		// outside, inside this window — and is gated on ZCD_SOAK, so `make soak` arms
		// it and `go test ./...` does not pay for it.
		reviveTheDead(t, nodes)

		agreed := map[string]int{}
		reachable := 0
		var maxHeight float64
		for _, n := range nodes {
			st, err := status(n.rpcPort)
			if err != nil {
				continue
			}
			reachable++
			agreed[fmt.Sprintf("%v/%v/%v", st["height"], st["tip"], st["state_root"])]++
			if h, ok := st["height"].(float64); ok && h > maxHeight {
				maxHeight = h
			}
		}
		if reachable < len(nodes) || maxHeight < 3 {
			continue // not the whole network yet, or not enough chain to compare
		}
		if len(agreed) == 1 {
			t.Logf("converged: %d nodes at height %.0f on one chain, one tip, one state root",
				reachable, maxHeight)
			return true
		}
	}
	return false
}

type binaries struct{ zcd, zycordd string }

// exeSuffix is what an executable file has to be called for os/exec to run it.
//
// On unix, nothing: the execute bit is the whole story. On Windows the
// extension is not decoration — exec.LookPath resolves a command through
// PATHEXT, and it applies that even to a path that already names a file, so a
// perfectly good PE image called `zycordd` with no extension fails with
// "executable file not found in %PATH%". `go build -o` writes exactly the name
// it is given and adds nothing, so the suffix has to be here.
//
// This is the whole reason the chaos soak — the one test that runs real nodes
// as real processes, and the test this project credits with finding the worst
// bug it has had — could not start a single node on Windows.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func buildBinaries(t *testing.T) binaries {
	t.Helper()
	dir := t.TempDir()
	ext := exeSuffix()
	out := binaries{
		zcd:     filepath.Join(dir, "zcd"+ext),
		zycordd: filepath.Join(dir, "zycordd"+ext),
	}
	for _, b := range []struct{ path, pkg string }{
		{out.zcd, "zycord/cmd/zcd"},
		{out.zycordd, "zycord/cmd/zycordd"},
	} {
		// Built with the consensus-state guard armed (R5-G2).
		//
		// This is the run the guard exists for. A guard armed only under `-race`
		// would be disarmed in the multi-hour soak — the one execution long
		// enough to reach the states that break rules — which is this project's
		// own lesson about instruments, applied to the fix for the bug that
		// taught it. `-race` is not used here instead: it slows a node enough to
		// change the timing a soak is measuring.
		cmd := exec.Command("go", "build", "-tags", "zcdguard", "-o", b.path, b.pkg)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("building %s: %v", b.pkg, err)
		}
	}
	return out
}

// payoutBytes is a node's payout address as raw bytes.
func payoutBytes(k *wallet.Key) []byte {
	a := k.Persistent()
	return a[:]
}

func newPayout(t *testing.T, zcd string) string {
	t.Helper()
	out, err := exec.Command(zcd, "key", "new").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range splitLines(string(out)) {
		if len(line) > 20 && contains(line, "persistent") {
			return lastField(line)
		}
	}
	t.Fatal("could not parse an address from `zcd key new`")
	return ""
}

func startNode(t *testing.T, bin string, n *soakNode) {
	t.Helper()
	args := []string{
		"--params", n.paramsPath, "--dir", n.dir,
		"--rpc", addr(n.rpcPort),
		"--seed", fmt.Sprint(n.rpcPort),
	}
	if n.p2pPort != 0 {
		// Bind the real port, advertise the proxy. Every peer that dials this
		// node therefore goes through the chaos link — otherwise peer exchange
		// hands out the direct address and the network quietly routes around
		// the thing the test exists to apply.
		args = append(args, "--listen", addr(n.p2pPort), "--advertise", addr(n.proxyPort))
	}
	if len(n.peers) > 0 {
		args = append(args, "--peers", join(n.peers))
	}
	if n.mining {
		args = append(args, "--mine", "--payout", n.payout)
	}

	logFile, err := os.OpenFile(n.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Attached here rather than where the network is built, so that a node
	// introduced by a regime of its own — the late joiner — is watched by the same
	// act that starts it, and cannot be forgotten.
	n.monitor.attach(n)
	n.monitor.started(n.name)
	superviseNode(n, cmd)
}

// superviseNode adopts a started process: it records it on the node and reaps
// it, so that what became of it is readable afterwards.
//
// Before the silent-follower death the only Wait in this harness was
// stopNode's, on nodes the harness itself had killed, so a node that died on
// its own was reaped by nobody and its exit code, its signal and its last words
// were discarded. From outside, "exited 1", "killed by the operating system"
// and "still running but wedged" were then the same observation: an unreachable
// RPC port. That is why that report's evidence stops at a sighting.
//
// It is exec.Cmd.Wait rather than Process.Wait because only the former fills
// cmd.ProcessState, which is the exit code and the signal. Reaping here rather
// than at the report site means exactly one goroutine ever calls Wait for this
// process: a second call returns "Wait was already called" and no state at all,
// which is the failure this reporting exists to avoid reintroducing. It is also
// the only place in the harness that learns of a death AT THE TIME IT HAPPENS,
// which is what the liveness property asks for: Wait returns when the operating
// system tears the child down, so the liveness monitor is told from here and
// not from a later poll that can only say "unreachable now".
func superviseNode(n *soakNode, cmd *exec.Cmd) {
	n.cmd = cmd
	exited := make(chan struct{})
	expected := make(chan struct{})
	n.exited, n.expected = exited, expected
	node, mon := n, n.monitor
	go func() {
		_ = cmd.Wait()
		// Reported BEFORE the reaper's channel closes. stopNode is the only
		// other reader of that channel and it clears n.cmd the moment it
		// returns, so reporting after the close would be reporting on a node
		// whose process fields another goroutine is already tearing down.
		mon.noticeExit(node, cmd, expected)
		close(exited)
	}()
}

func stopNode(n *soakNode) {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	// Announced before the kill, and it has to be before: a kill cannot take
	// effect until it is issued, so closing this first is what guarantees the
	// reaper sees the announcement on every death the harness caused. Announcing
	// afterwards would race the process's own teardown and turn the soak's three
	// or four deliberate kills into three or four false alarms.
	//
	// A false alarm here is not a line to read past. liveness.announce reports
	// through t.Errorf, so each one fails the run — the soak would go red
	// naming deaths that never happened, on the one test whose value is being
	// believed when it goes red. No input in this package separates this
	// ordering from the reverse one, because landing inside the window between
	// Kill and the reaper's Wait would take a delay injected here; the ordering
	// is held by this argument rather than by a test, which is why the argument
	// is written down.
	if n.expected != nil {
		close(n.expected)
	}
	// SIGKILL, not a graceful stop: the point is that a node dies without
	// getting to close anything.
	_ = n.cmd.Process.Kill()
	// The reaper's Wait, not a second one here. Kill has already been issued,
	// so this returns as soon as the operating system has torn the process
	// down, exactly as the Process.Wait it replaces did.
	<-n.exited
	n.cmd, n.exited, n.expected = nil, nil, nil
}

// exitReportGrace is how long exitReport waits for a process to be reaped
// before it reports the node as still running.
//
// It is short on purpose. Reaching this function at all means the node's RPC
// has already failed to answer a request whose own client timeout has expired,
// so the process has had its chance; what is left to decide is only whether it
// is still there. A longer bound would add nothing to that answer and would be
// paid once per unreachable node on a path that already runs at the end of a
// failing regime.
const exitReportGrace = 2 * time.Second

// exitReport says what became of a node's process, for a node whose RPC did
// not answer.
//
// **An unreachable RPC port has three causes and they are not the same bug.**
// The process exited on its own; the process was terminated from outside; or
// the process is alive and wedged. The silent-follower death is a report of the
// first two being indistinguishable from the third: a follower was found with a
// 279-byte log and a refused dial, and the run could say nothing further
// because nothing had reaped it.
//
// So the three are separated here, and the separation is the whole value: an
// exit code names a decision the binary made, a termination status names one
// made about it, and "still running" moves the question from why it died to
// what it is blocked on. Reported beside the unreachable line rather than
// asserted, because which of the three occurred is the finding.
//
// The first two of those three separate only where the platform has signals,
// and this one does not. Windows has no signals: TerminateProcess sets exit
// code 1 and fatal() exits 1 through os.Exit, so both arrive here as "process
// exited: exit status 1 (code 1)" and what separates them is the `zycordd:
// <err>` line fatal() wrote to this same file first. Read the report and the
// tail of the log together on this platform; a bare code 1 does not name an
// owner.
//
// `within` bounds the wait, because a wedged process never exits and this must
// still return an answer about it.
func exitReport(n *soakNode, within time.Duration) string {
	if n == nil || n.cmd == nil || n.exited == nil {
		return "no process: the harness stopped this node and did not restart it"
	}
	select {
	case <-n.exited:
	case <-time.After(within):
		// A live process with an unreachable RPC has a third cause the "wedged"
		// verdict below does not consider: the RPC port was taken before the node
		// could bind it. Such a node is alive, healthy, mining and syncing — and
		// simply unreachable; it is not wedged, and naming it so names a fault in
		// node/ that is not there. The node logged the failed bind and kept running,
		// so the evidence sits in its own log. dumpLogs prints only the last twelve
		// lines, and a startup bind failure scrolls out of that tail within minutes,
		// so the line has to be read here or it is lost — exactly as the liveness
		// instrument reads `last log line:` into its death report. Read before
		// deciding, so the sentence that remains is earned rather than assumed.
		if port, taken := rpcNeverBound(n.logPath); taken {
			where := "before this node could bind it"
			if port != "" {
				where = "on port " + port + " before this node could bind it"
			}
			return fmt.Sprintf("process still running after %s, but its RPC never bound: "+
				"the log shows the listener failed with a bind error, so an unrelated "+
				"process took the port %s. The node is alive, healthy and syncing — "+
				"unreachable, but not at fault", within, where)
		}
		return fmt.Sprintf("process still running after %s: the RPC is unreachable "+
			"on a LIVE process, so this is a wedged node and not a dead one", within)
	}
	return processFate(n.cmd)
}

// rpcNeverBound reports whether a node's log shows its RPC listener failed to
// bind, and on which port. It is the evidence that separates the third fate an
// unreachable node can be in — alive, but its RPC port was taken before it
// could bind — from the "wedged" verdict exitReport would otherwise pronounce
// itself. cmd/zycordd logs the failed bind and the node keeps running, so from
// outside it is a live process with a dead port and nothing but this line says
// why.
//
// It anchors on the bind error itself — net.Listen renders "...: bind: ..." on
// every platform — rather than on the prose around it, because that prose has
// already moved once: splitting Listen out of ListenAndServe moved the line
// from "rpc stopped: <err>" to "rpc not listening on <addr>: <err>". Keying on
// the surrounding words would have turned this reader back into the sighting it
// replaces the next time they change; keying on the failure keeps it reading
// the evidence. The `rpc` requirement is what keeps a p2p bind failure, which
// is a different fault with a different owner, from being reported as this one.
//
// The port is the field before `: bind:` in net.Listen's "listen tcp
// <host>:<port>: bind: <reason>"; "" if the line carries no host:port, so the
// caller reports the failure without inventing a number.
func rpcNeverBound(logPath string) (port string, ok bool) {
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return "", false
	}
	const mark = ": bind:"
	for _, line := range splitLines(string(raw)) {
		if !contains(line, "rpc") {
			continue
		}
		i := -1
		for k := 0; k+len(mark) <= len(line); k++ {
			if line[k:k+len(mark)] == mark {
				i = k
				break
			}
		}
		if i < 0 {
			continue
		}
		addr := line[:i] // "...listen tcp <host>:<port>"
		for k := len(addr) - 1; k >= 0; k-- {
			if addr[k] == ':' {
				return addr[k+1:], true
			}
		}
		return "", true
	}
	return "", false
}

// processFate renders what became of a process that has ALREADY been reaped.
//
// Split out of exitReport because the liveness monitor reaches this fact by a
// different route: it is told by the reaper at the instant of the death and has
// no waiting left to do, while exitReport is asked about a node whose RPC went
// quiet and must first find out whether the process is even gone. Two routes,
// one sentence — a second spelling of "what became of it" would be a second
// thing to keep true.
func processFate(cmd *exec.Cmd) string {
	if cmd == nil || cmd.ProcessState == nil {
		return "process reaped, but it reported no state"
	}
	st := cmd.ProcessState
	// ProcessState.String carries the signal on the platforms that have one
	// ("signal: killed") and the code on the ones that do not; ExitCode is
	// printed alongside because a signalled process reports -1 there, which is
	// how the two cases are told apart without parsing the prose.
	return fmt.Sprintf("process exited: %s (code %d)", st.String(), st.ExitCode())
}

func status(port int) (map[string]any, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr(port) + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func dumpLogs(t *testing.T, nodes []*soakNode) {
	t.Helper()
	for _, n := range nodes {
		raw, err := os.ReadFile(n.logPath)
		if err != nil {
			continue
		}
		lines := splitLines(string(raw))
		from := 0
		if len(lines) > 12 {
			from = len(lines) - 12
		}
		// The path, always. Twelve lines is a pointer to the evidence, not the
		// evidence: the run that made this necessary needed the two hours of
		// sync attempts above the tail, and printing a tail without saying
		// where the rest lives is how a log gets read as the whole story.
		t.Logf("--- %s (full log: %s) ---\n%s", n.name, n.logPath, join2(lines[from:]))
	}
}

func addr(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// The ports the soak network binds, as offsets from the block base.
//
// Named rather than written as literals at the four assignment sites, because
// the set has to be a superset of what the regimes derive: a port the network
// binds and the block does not cover is a port nothing reserved and nothing
// kept out of the kernel's reach. That is not hypothetical — soakLateJoinerRPC
// was exactly such a port, derived as `nodes[0].rpcPort + 50` in the catch-up
// regime, 47 past the highest offset that was probed and 40 past the span they
// were probed with.
//
// And a name alone was not enough. Writing that port as an offset from ANOTHER
// NODE's port — `nodes[0].rpcPort - soakRPCBase + soakLateJoinerRPC` — is right
// only while `nodes[0]` happens to sit at soakRPCBase, so reordering the slice
// would put the joiner outside the block again, in exactly the shape of the
// stolen port, and the offset test below cannot see it by its own admission.
// Every port is therefore derived from the BLOCK, which is the thing that
// reserved it.
const (
	soakP2PBase       = 0   // a, b, c at +0, +1, +2
	soakProxyBase     = 100 // their chaos proxies at +100, +101, +102
	soakRPCBase       = 200 // a, b, c, d at +200 … +203
	soakLateJoinerRPC = 250 // the catch-up regime's joiner
)

// The band the block is drawn from, given where the kernel's own range starts.
//
// preferredBlockFloor is clear of the well-known ports and of most of the
// registered ones, which is why the soak has always started there.
// minimumBlockFloor is where a bind stops needing privilege, and it is only
// reached on a host whose published range leaves no room above the preferred
// floor — see blockRange.
const (
	preferredBlockFloor = 20000
	minimumBlockFloor   = 1024
)

// soakPortOffsets is every offset above, expanded.
var soakPortOffsets = []int{
	soakP2PBase, soakP2PBase + 1, soakP2PBase + 2,
	soakProxyBase, soakProxyBase + 1, soakProxyBase + 2,
	soakRPCBase, soakRPCBase + 1, soakRPCBase + 2, soakRPCBase + 3,
	soakLateJoinerRPC,
}

// soakPortSpan is the width of the block: one past the highest offset.
const soakPortSpan = soakLateJoinerRPC + 1

// ianaDynamicPortFloor is the start of the IANA dynamic/private range
// (RFC 6335 §6). Windows and macOS both default their ephemeral allocator to
// it; Linux does not, and publishes its own, which is why this is a fallback
// and not the answer.
const ianaDynamicPortFloor = 49152

// dynamicPortFloor reports the lowest port this machine's kernel may hand to a
// socket that did not name one.
//
// This is the number the whole block selection hangs on. Below it, no automatic
// allocation can reach a soak port; at or above it, one can: a base drawn up to
// 49999 put a block of 251 ports inside the range the kernel assigns to every
// outbound connection on the machine.
//
// Linux publishes the range and it is NOT the IANA one — the usual default
// starts at 32768, far below it — so assuming the documented Windows floor here
// would put the entire block inside the range on the platform the VPS runs.
// Read it where it is readable; fall back only where it is not.
//
// The path is a parameter of the inner function purely so the Linux branch can
// be driven on a machine that has no /proc: without that, the half of this fix
// that makes it correct on the VPS would be reachable by no test we can run.
const linuxPortRangePath = "/proc/sys/net/ipv4/ip_local_port_range"

func dynamicPortFloor() int { return dynamicPortFloorFrom(linuxPortRangePath) }

func dynamicPortFloorFrom(path string) int {
	raw, err := os.ReadFile(path)
	if err == nil {
		if lo, ok := firstUint(raw); ok && lo > 0 {
			return lo
		}
	}
	return ianaDynamicPortFloor
}

// firstUint reads the leading decimal number of b, skipping leading blanks. A
// value that is not a port number is not one: the caller is reading a file the
// kernel writes, but nothing about that file is guaranteed to this process, and
// an unclamped number would flow straight into the block arithmetic.
func firstUint(b []byte) (int, bool) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	start := i
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == start {
		return 0, false
	}
	v, err := strconv.Atoi(string(b[start:i]))
	if err != nil || v < 1 || v > 65535 {
		return 0, false
	}
	return v, true
}

// blockRange is the inclusive band of bases whose whole block lies below floor.
//
// The upper end is arithmetic: a base at floor-soakPortSpan puts the block's
// last port at floor-1. The lower end is a CHOICE, and it has two settings
// rather than one because the first is a preference and not a limit —
// preferredBlockFloor keeps the soak clear of the registered ports, and on a
// host that publishes a low range there may be nothing above it, in which case
// dropping to minimumBlockFloor is strictly better than refusing to run. That
// case is degraded and is reported as such: the band then overlaps ports real
// services use, and probeBlock is what keeps it honest.
func blockRange(floor int) (lo, hi int, ok bool) {
	hi = floor - soakPortSpan
	for _, lo = range [...]int{preferredBlockFloor, minimumBlockFloor} {
		if hi >= lo {
			return lo, hi, true
		}
	}
	return 0, 0, false
}

// pickPortBase draws a base whose whole block lies below dynamicPortFloor.
//
// Separated from the binding probe so the selection rule can be driven for
// thousands of draws without touching a socket — the property at stake is a
// property of the arithmetic, and a test that had to bind to observe it could
// only ever sample it.
func pickPortBase(rng *rand.Rand, floor int) (int, bool) {
	lo, hi, ok := blockRange(floor)
	if !ok {
		return 0, false
	}
	return lo + rng.Intn(hi-lo+1), true
}

// portBlock is a run of ports this process is holding open on the soak's
// behalf, released one at a time to whoever is about to bind them.
//
// Holding rather than probing-and-releasing is the point. See freePortBlock.
type portBlock struct {
	base int
	held map[int]net.Listener
}

// release hands the named ports back, immediately before the thing that binds
// them binds them. Unknown or already-released ports are ignored, so a caller
// can pass a node's zero-valued p2pPort without a special case.
func (b *portBlock) release(ports ...int) {
	for _, p := range ports {
		if l, ok := b.held[p]; ok {
			l.Close()
			delete(b.held, p)
		}
	}
}

// releaseAll hands back everything still held.
func (b *portBlock) releaseAll() {
	for p, l := range b.held {
		l.Close()
		delete(b.held, p)
	}
}

// freePortBlock reserves a contiguous run of ports for one soak network.
//
// The two soak regimes used to pick a random base from one range, so they could
// collide — and worse, a regime that ran after another could land on ports still
// held by sockets the previous run's SIGKILLs left in TIME_WAIT. That failed as
// "bind: address already in use" two seconds into a test whose job takes twenty
// minutes, which reads exactly like a broken test rather than a busy machine.
//
// Binding is the only honest check: a port is free if the operating system says
// so, not if a random number generator has not used it yet. But binding and
// then LETTING GO is a check with an expiry date, and this is what expired:
// between the probe and the node's own bind, seconds later, the kernel can hand
// the same port to any outbound connection on the machine. Measured: the probe
// certified a block, eight ordinary ephemeral allocations later one of its
// ports was gone, and the bind that followed failed. Nothing about that is rare
// — the soak itself opens hundreds of connections per regime.
//
// Two independent doors, and each is shut by a different thing:
//
//   - The KERNEL's own allocator. Shut by arithmetic, not by timing: the block
//     is drawn entirely below dynamicPortFloor, so no automatic assignment can
//     reach it at any instant. This is what makes the fix hold for a node the
//     chaos loop kills and restarts minutes later, when no listener is held and
//     no window is narrow.
//   - Anything else that names the port explicitly — a second soak in another
//     lane, an unrelated service. Shut by holding: the listeners stay open
//     across the whole of setup and are handed over one at a time at the moment
//     of the bind that needs each.
//
// Holding alone would only narrow the first window; drawing low alone would
// leave the second wide open for the length of setup. Neither is the other's
// substitute, which is why this does both.
func freePortBlock(t *testing.T, rng *rand.Rand) *portBlock {
	t.Helper()
	floor := dynamicPortFloor()
	assertTheKernelAssignsAboveTheFloor(t, floor)
	if _, _, ok := blockRange(floor); !ok {
		// A SKIP and not a Fatal, and the difference is the whole point of the
		// sentence. `net.ipv4.ip_local_port_range = 1024 65535` is a widely
		// recommended server tuning, and under it there is no port on the host
		// the kernel will not hand out on its own — so the soak genuinely
		// cannot reserve anything, and that is a fact about the HOST. A Fatal
		// here renders a configured machine as a broken repository, which is
		// the same failure this whole change exists to stop: a harness limit
		// read as a defect in the thing under test.
		t.Skipf("this host publishes a dynamic port range starting at %d, so no block "+
			"of %d ports fits below it above %d: the soak has no ports it can hold "+
			"against the kernel's own allocator, and NOT RUN is the honest answer "+
			"rather than a run that races. Raise the range's start — "+
			"`sysctl net.ipv4.ip_local_port_range` or "+
			"`netsh int ipv4 set dynamicport tcp` — to run this regime here.",
			floor, soakPortSpan, minimumBlockFloor)
	}
	for attempt := 0; attempt < 64; attempt++ {
		base, ok := pickPortBase(rng, floor)
		if !ok {
			t.Fatalf("pickPortBase refused a floor of %d that blockRange accepted: the "+
				"two disagree about the same band", floor)
		}
		if held, ok := probeBlock(base); ok {
			return &portBlock{base: base, held: held}
		}
	}
	t.Fatal("could not find a free block of ports for the soak network")
	return nil
}

// assertTheKernelAssignsAboveTheFloor fails the run when the floor the block
// selection trusts is not the floor this machine uses.
//
// Declared direction, per PROTOCOL.md rule 22: every port the kernel assigns to
// a socket that did not name one MUST be at or above floor. If one is below it,
// the arithmetic in pickPortBase is selecting inside the range the kernel hands
// out and the soak is back to a port stolen mid-flight — so this stops the run
// and names the tool that reports the range, rather than letting the next
// stolen port be read as a node defect. The check is a sample and cannot prove
// the floor; it can and does refute a wrong one, which is the direction that
// matters.
func assertTheKernelAssignsAboveTheFloor(t *testing.T, floor int) {
	t.Helper()
	const samples = 32
	var held []net.Listener
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()
	for i := 0; i < samples; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			break
		}
		held = append(held, l)
		if p := l.Addr().(*net.TCPAddr).Port; p < floor {
			t.Fatalf("the kernel assigned port %d, below the %d this soak treats as the "+
				"floor of the dynamic range: the reserved block is inside the range the "+
				"kernel hands out and any run can have a port stolen mid-flight. "+
				"Check the range with `netsh int ipv4 show dynamicport tcp` or "+
				"`sysctl net.ipv4.ip_local_port_range`", p, floor)
		}
	}
}

// probeBlock binds every port the network needs and KEEPS them, returning the
// listeners so the caller can hand each over at the moment of its real bind.
func probeBlock(base int) (map[int]net.Listener, bool) {
	held := make(map[int]net.Listener, len(soakPortOffsets))
	for _, offset := range soakPortOffsets {
		l, err := net.Listen("tcp", addr(base+offset))
		if err != nil {
			for _, l := range held {
				l.Close()
			}
			return nil, false
		}
		held[base+offset] = l
	}
	return held, true
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func lastField(s string) string {
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	start := end
	for start > 0 && s[start-1] != ' ' && s[start-1] != '\t' {
		start--
	}
	return s[start:end]
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

func join2(parts []string) string {
	out := ""
	for _, p := range parts {
		out += p + "\n"
	}
	return out
}

// ---------------------------------------------------------------------------
// Continuous contention (R5-G1)
// ---------------------------------------------------------------------------

// TestChaosSoakUnderContinuousContention is the regime a live network is
// actually in: every miner mining, all the time, while the links misbehave.
//
// TestChaosSoak stops all but one miner before it checks anything, and that is
// correct for the question it asks — with three miners racing, "do all nodes
// agree right now" is asking whether four processes happened to be sampled
// between blocks, and stopping every miner is worse, because two branches of
// equal work stay forked forever and are *right* to.
//
// So under continuous contention the invariant has to be a different one:
//
//	every node's finalized-by-depth history is a prefix of one chain,
//	and no node ever violates the billing law locally, throughout.
//
// Agreement about the tip is not expected and not required. Agreement about
// history below the reorg horizon is, and permanent disagreement there is the
// failure this exists to catch.
func TestChaosSoakUnderContinuousContention(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	// This variant needs enough chain for a reorg horizon to exist at all: the
	// check compares history `contentionDepth` blocks below the shallowest tip,
	// so a run that never gets that far makes zero comparisons.
	//
	// It therefore runs only when a duration was asked for (ZCD_SOAK, which
	// `make soak` sets), and the skip says exactly what is going untested. A
	// skip that reads like a pass is the same failure as a green test that
	// measures nothing — see docs/adversarial/I4.md.
	if os.Getenv("ZCD_SOAK") == "" {
		t.Skip("continuous-contention soak needs ZCD_SOAK=<duration> (try `make soak`); " +
			"NOT RUN means history agreement under continuous mining is unverified")
	}
	// The horizon implies a minimum chain length, which implies a minimum
	// duration. Refusing up front is better than running for a quarter of an
	// hour and then reporting that nothing was compared: that reads as a defect
	// and is a setting.
	//
	// Reorgs reach ~130 under this regime, so the horizon is 256; ten
	// comparisons therefore need height 266, and the chain advances at roughly
	// target_block_seconds once difficulty settles.
	needHeight := contentionDepth + 10
	needed := time.Duration(needHeight) * time.Duration(soakTargetBlockSeconds) * time.Second * 3 / 2
	if soakDuration < needed {
		t.Skipf("continuous contention needs ZCD_SOAK of at least %s: the history "+
			"horizon is %d blocks (reorgs reach ~130 in this regime) and ten "+
			"comparisons need height %d, which takes about that long at %ds "+
			"blocks. NOT RUN — history agreement under continuous mining is "+
			"unverified, and a shorter run would compare nothing and say so.",
			needed.Round(time.Minute), contentionDepth, needHeight, soakTargetBlockSeconds)
	}
	nodes, bin, rng, p, _ := newSoakNetwork(t, 11)
	assertNodesAreGuarded(t, nodes)

	loadStop := make(chan struct{})
	driver := runLoad(t, nodes, p, loadStop)

	// The history checker runs *throughout*, not at the end. A divergence that
	// is created and then reorged away would be invisible to an end-of-run
	// check, and it is exactly as much of a bug as one that persists: below the
	// horizon, history is supposed to be settled.
	checker := newHistoryChecker(nodes, contentionDepth)
	stop := make(chan struct{})
	var checkerDone sync.WaitGroup
	checkerDone.Add(1)
	go func() {
		defer checkerDone.Done()
		for {
			select {
			case <-stop:
				checker.sweep(t)
				return
			case <-time.After(2 * time.Second):
				checker.sweep(t)
			}
		}
	}()

	deadline := time.Now().Add(soakDuration)
	var kills, partitions int
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		kills, partitions = applyChaos(t, bin, nodes, rng, kills, partitions)
	}
	for _, n := range nodes {
		if n.proxy != nil {
			n.proxy.Partition(false)
		}
	}

	// Mining never stopped. Give the network a little quiet to let the last
	// blocks propagate, then sweep once more — the final sweep is what checks
	// the heights produced during the chaos, since the horizon lags the tip.
	time.Sleep(15 * time.Second)
	close(stop)
	checkerDone.Wait()

	t.Logf("chaos: %d kills, %d partitions", kills, partitions)
	// Every check runs, and every check reports.
	//
	// These used to abort on the first failure, so a horizon that was too small
	// — a fact about the *harness* — hid the billing-law result entirely, under
	// the one regime where it has been measured least. A structural-invariant
	// failure upstream must never mask an economic-invariant result downstream;
	// they answer different questions and a run should answer both.
	close(loadStop)
	checker.report(t)
	assertBillingLawHeld(t, nodes, driver)
	assertNoLocalViolations(t, nodes)
}

// contentionDepth is how far below the shallowest tip history is treated as
// settled. It is derived, then validated against measurement.
//
// Derived, because a hand-picked constant is a number nobody can argue with:
//
//	K = max(epochLength, ceil(3 · maxIsolation / targetBlockSeconds))
//	    bounded above by undoDepth/4
//
// The first term keeps the horizon at least one epoch back, so a settled height
// always has a state root committed behind it. The second is how far the chain
// can move while the harness has a node cut off: the longest partition this
// soak opens, plus the sync interval, plus a gossip round — times three, for
// margin. The bound keeps it far inside the undo horizon, past which a reorg is
// refused outright rather than performed.
//
// Validated, because a derivation is still an argument: assertDepthExceedsObservedReorgs
// reads every node's deepest *actual* reorg from /metrics and fails the run if
// one reached this far. A K below a real reorg makes the check flap on honest
// behaviour and its silence would mean nothing.
//
// (That metric reported zero through every partition and every fork until R5,
// because nothing ever recorded it — see node/chain/stats.go. Validating a
// constant against a number that cannot be non-zero is not validation.)
// soakLoadWarmupSeconds is how long the load driver waits before its first
// attempt: a mining reward has to mature before anything on this chain can pay
// for anything, and there is no premine and no faucet. Devnet's
// coinbase_maturity is 10 and the soak's target_block_seconds is 5.
//
// Reported rather than enforced. It is only ever used to explain a NOT RUN.
const soakLoadWarmupSeconds = (10 + 2) * soakTargetBlockSeconds

const (
	soakMaxPartitionSeconds = 3 // the longest partition applyChaos opens
	soakSyncIntervalSeconds = 3 // node.SyncInterval
	soakTargetBlockSeconds  = 5 // from the soak parameter set
	soakUndoDepth           = 1024

	// 256, and the number is regime-specific — which is the point.
	//
	// The history: 16, 56, 256, then 64, now 256 again. Each move was forced by a
	// measurement, and the last two teach opposite halves of one lesson.
	//
	// The drop to 64 came from correcting the harness. The dev miner had paced
	// itself with a fixed ticker against an instantly-solvable target, so all
	// three miners emitted blocks simultaneously and held chains of identical
	// weight, which no fork choice can separate. Under exponential (Poisson)
	// pacing the catch-up regime's deepest reorg fell from 297 to 24, and 64
	// looked generous.
	//
	// The return to 256 came from measuring the *right regime*. Under continuous
	// contention — three miners that never stop — the deepest reorg is 128 with
	// Poisson pacing, against 99 and 123 measured before the correction. So the
	// artifact had inflated the catch-up figure enormously and the contention
	// figure barely at all, and "the real number is 24" was a catch-up
	// observation generalised past its regime.
	//
	// Reorg depth is a property of the *regime*, not of the chain. A horizon has
	// to clear the deepest regime it will be applied to, which is contention at
	// 128, so 256 is 2x that and still a quarter of undo_depth.
	//
	// **That 128 was measured while deepest_reorg still recorded the sync batch
	// size rather than the fork depth, and cannot be read as a fork depth.** The
	// sync driver walked back to the common ancestor one whole syncBatch -- also
	// 128 — at a time and reorganised to the overshoot, so any reorg the walk
	// stepped back for recorded at least one stride whatever the fork actually
	// was. The pre-correction figures for this same regime were 99 and 123, both
	// below that floor and so both real; the Poisson figure then landed on the
	// batch size exactly. Whether the tail really rose is now an open question
	// rather than a measurement.
	//
	// 256 is kept regardless, and the direction is why: a horizon that clears a
	// number which may be an overshoot still clears the real one, so the value is
	// conservative under either reading. What is NOT safe is citing the 128 as
	// evidence. docs/decisions/testnet-measurements.md section 1 records the
	// arithmetic; re-running this soak on a build that records the fork depth
	// itself is what settles it.
	contentionDepth = 256
)

// historyChecker verifies that every node agrees about history below the reorg
// horizon, cumulatively and without gaps.
//
// The cumulative watermark is the point. A checker that only compared "the
// current horizon" each round would let a divergence slide through between two
// samples: heights advance faster than the sample interval under load, and an
// unchecked range is an unchecked range whether or not anybody looked at the
// ones on either side. This checks every height exactly once, in order, and
// never skips.
type historyChecker struct {
	nodes []*soakNode
	depth uint64

	checkedTo   uint64
	comparisons int
	// compared totals the node-answers across all heights, and partial counts
	// the heights that were compared across fewer than every node. Together they
	// say how strong the evidence actually is, instead of letting a run that
	// mostly talked to two nodes look like one that talked to four.
	compared  int
	partial   int
	maxHeight uint64
	// disagreements records permanent divergence below the horizon.
	disagreements []string
}

func newHistoryChecker(nodes []*soakNode, depth uint64) *historyChecker {
	return &historyChecker{nodes: nodes, depth: depth}
}

// sweep advances the watermark as far as every node's history allows.
func (h *historyChecker) sweep(t *testing.T) {
	t.Helper()

	// Aborting on the first unreachable node does not work at this chaos rate.
	//
	// The 30-minute contention run killed nodes 132 times, so a window in which
	// all four are up long enough to clear a backlog is rare — the checker
	// verified 167 heights while the network reached 327, and its own
	// fell-behind guard failed the run. That guard was right: unchecked heights
	// are unchecked. But the cause was the checker, not the chain.
	//
	// So a sweep proceeds on whoever answers, requiring a quorum, and records
	// how many nodes each height was compared across. A height compared across
	// two nodes is weaker evidence than one compared across four, and report()
	// says so rather than averaging it away.
	const quorum = 2

	heights := make(map[string]uint64, len(h.nodes))
	var lowest uint64 = ^uint64(0)
	var up int
	for _, n := range h.nodes {
		st, err := status(n.rpcPort)
		if err != nil {
			continue
		}
		up++
		hf, ok := st["height"].(float64)
		if !ok {
			return
		}
		heights[n.name] = uint64(hf)
		if uint64(hf) < lowest {
			lowest = uint64(hf)
		}
		if uint64(hf) > h.maxHeight {
			h.maxHeight = uint64(hf)
		}
	}
	if up < quorum || lowest < h.depth+1 {
		return // too few answering, or nothing below the horizon yet
	}
	target := lowest - h.depth

	for height := h.checkedTo + 1; height <= target; height++ {
		ids := map[string][]string{}
		var answered int
		for _, n := range h.nodes {
			id, err := blockIDAt(n.rpcPort, height)
			if err != nil {
				continue
			}
			answered++
			ids[id] = append(ids[id], n.name)
		}
		if answered < quorum {
			// Not enough of the network to compare anything. Stop here rather
			// than advancing: the watermark must never step over a height that
			// was not actually checked.
			return
		}
		h.comparisons++
		h.compared += answered
		if answered < len(h.nodes) {
			h.partial++
		}
		if len(ids) != 1 {
			var parts []string
			for id, who := range ids {
				parts = append(parts, fmt.Sprintf("%v=%s", who, id[:18]))
			}
			sort.Strings(parts)
			h.disagreements = append(h.disagreements,
				fmt.Sprintf("height %d below the %d-block horizon: %s",
					height, h.depth, join2space(parts)))
		}
		h.checkedTo = height
	}
}

// report asserts the run actually measured something, then the invariant.
func (h *historyChecker) report(t *testing.T) {
	t.Helper()

	// Anti-vacuity first, and it is the more important half.
	//
	// Every failure mode of this check is silence: nodes too low to have a
	// horizon, a node permanently down so the watermark never advances, a run
	// too short to settle anything. All of them produce zero comparisons and a
	// green test, which is precisely the shape of the three instruments this
	// milestone found measuring nothing.
	if h.comparisons == 0 {
		t.Errorf("the history checker made no comparisons at all (max height %d, "+
			"horizon depth %d): this run proves nothing about history agreement",
			h.maxHeight, h.depth)
		return
	}
	minComparisons := 10
	if h.comparisons < minComparisons {
		t.Errorf("the history checker compared only %d heights (max height %d): "+
			"too few to mean anything. Run longer.", h.comparisons, h.maxHeight)
	}
	// The watermark must have tracked the chain rather than stalling early.
	if h.maxHeight > h.depth && h.checkedTo+h.depth*3 < h.maxHeight {
		t.Errorf("the checker fell far behind the chain: verified to %d while the "+
			"network reached %d. Heights above the watermark were never compared.",
			h.checkedTo, h.maxHeight)
	}

	avg := float64(h.compared) / float64(h.comparisons)
	t.Logf("history: %d heights verified to %d (network reached %d); %.2f nodes per "+
		"height on average, %d height(s) compared across fewer than %d nodes",
		h.comparisons, h.checkedTo, h.maxHeight, avg, h.partial, len(h.nodes))

	// Evidence strength, stated as an assertion rather than a log line. A run
	// that only ever reached two of four nodes has checked something much
	// weaker than the invariant claims.
	if avg < 2.5 {
		t.Errorf("heights were compared across %.2f nodes on average: too little "+
			"of the network answered for this to mean what it says", avg)
	}

	assertDepthIsDerivable(t, h.depth)
	assertDepthExceedsObservedReorgs(t, h.nodes, h.depth)

	if len(h.disagreements) > 0 {
		for _, d := range h.disagreements {
			t.Errorf("history diverged: %s", d)
		}
		t.Error("nodes disagreed about history below the reorg horizon under " +
			"continuous contention")
	}
}

// assertDepthIsDerivable keeps the constant honest against its own derivation.
//
// If somebody shortens a partition, changes the block time or edits the epoch
// length, the number that was derived from them stops being derived from them —
// silently, because a constant does not notice. This recomputes the floor and
// the ceiling and fails if the constant has drifted outside them.
func assertDepthIsDerivable(t *testing.T, depth uint64) {
	t.Helper()
	isolation := soakMaxPartitionSeconds + soakSyncIntervalSeconds
	fromIsolation := (3*uint64(isolation) + soakTargetBlockSeconds - 1) / soakTargetBlockSeconds
	floor := uint64(soakEpochLength)
	if fromIsolation > floor {
		floor = fromIsolation
	}
	ceiling := uint64(soakUndoDepth) / 2
	if depth < floor {
		t.Errorf("contentionDepth %d is below its derived floor %d (epoch length %d, "+
			"isolation %ds at %ds blocks): the horizon is inside the window where "+
			"honest reorgs still happen", depth, floor, soakEpochLength, isolation,
			soakTargetBlockSeconds)
	}
	if depth > ceiling {
		t.Errorf("contentionDepth %d exceeds undoDepth/2 = %d: the horizon is out "+
			"past where a reorg would be refused, so it is checking history the "+
			"node could not change anyway", depth, ceiling)
	}
}

// assertDepthExceedsObservedReorgs validates the horizon against measurement.
//
// The depth constant is only meaningful if no real reorg reached it. If one
// did, the check was comparing heights that were legitimately still in flux and
// its silence meant nothing — so this fails loudly and names the number to
// raise, rather than leaving a hand-picked constant unexamined.
func assertDepthExceedsObservedReorgs(t *testing.T, nodes []*soakNode, depth uint64) {
	t.Helper()
	var deepest float64
	var sawMetrics bool
	for _, n := range nodes {
		m, err := metrics(n.rpcPort)
		if err != nil {
			continue
		}
		sawMetrics = true
		if d, ok := m["deepest_reorg"].(float64); ok && d > deepest {
			deepest = d
		}
	}
	if !sawMetrics {
		t.Error("no node served /metrics, so the horizon depth could not be " +
			"validated against observed reorgs")
		return
	}
	if uint64(deepest) >= depth {
		t.Errorf("a reorg reached %d blocks deep but the history horizon is %d: "+
			"the check was comparing heights that were still legitimately in "+
			"flux. Raise contentionDepth above %d.", uint64(deepest), depth, uint64(deepest))
	}
	t.Logf("deepest observed reorg: %d blocks (horizon %d)", uint64(deepest), depth)
}

// blockIDAt asks a node for the id of the block at a height on its canonical
// chain.
func blockIDAt(port int, height uint64) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/block?height=%d", addr(port), height))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	id, ok := out["id"].(string)
	if !ok {
		return "", fmt.Errorf("no id at height %d", height)
	}
	return id, nil
}

func metrics(port int) (map[string]any, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr(port) + "/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func join2space(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "  "
		}
		out += p
	}
	return out
}

// ---------------------------------------------------------------------------
// Billing-law load (R6-G2)
// ---------------------------------------------------------------------------

// runLoad drives continuous certificate load at the network until stop closes.
//
// Every miner's payout key funds transfers out of that miner's own matured
// coinbase — the only funded addresses that exist on a chain with no premine —
// and submissions are spread across every node's RPC, so a certificate's entry
// point is usually not the node that ends up mining it. That is the path a real
// transaction takes and it is the one the empty-block soak never exercised.
func runLoad(t *testing.T, nodes []*soakNode, p *params.Params, stop <-chan struct{}) *soakLoad {
	t.Helper()

	var endpoints []string
	var funded []*soakNode
	for _, n := range nodes {
		endpoints = append(endpoints, addr(n.rpcPort))
		if n.mining {
			funded = append(funded, n)
		}
	}
	load := &soakLoad{driver: chaos.NewDriver(p, endpoints)}
	driver := load.driver

	go func() {
		// Wait for coinbase maturity before the first attempt: until a reward
		// matures there is nothing on the chain that can pay for anything.
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(p.CoinbaseMaturity+2) * time.Duration(p.TargetBlockSeconds) * time.Second):
		}
		// Recorded, because "submitted nothing" has two causes and only one of
		// them is a defect. See soakLoad.
		load.started.Store(true)

		var round int
		for {
			select {
			case <-stop:
				return
			case <-time.After(900 * time.Millisecond):
			}
			round++
			src := funded[round%len(funded)]
			dst := nodes[(round+1)%len(nodes)]
			endpoint := endpoints[round%len(endpoints)]

			sub, err := driver.Transfer(src.key, dst.key.Persistent(),
				u256.FromUint64(1_000), endpoint)
			if err != nil {
				continue
			}
			// A reorg can strand a Seq chain: the pool re-screens against the
			// new tip and a gap blocks everything above it. Re-anchor on
			// refusal rather than counting blindly upward, or the driver spends
			// the rest of the run submitting certificates nothing will accept.
			if !sub.Accepted && round%10 == 0 {
				driver.ResetSeq(src.key.Persistent(), 0)
			}
		}
	}()
	return load
}

// soakLoad is the load driver plus the one fact the billing-law check cannot
// get from it: whether the driver ever woke up.
//
// The driver waits `(coinbase_maturity + 2) x target_block_seconds` before its
// first attempt, because until a mining reward matures there is nothing on the
// chain that can pay for anything. On the soak parameters that is 60 seconds,
// and the default duration is 25 — so the short run that `make ci` executes
// stops the driver before it has ever tried, and then failed its own
// anti-vacuity check for having submitted nothing.
//
// That check is right and stays. What was wrong is that it could not tell "this
// run was too short to have load" from "load was attempted and nothing landed".
// The first is a setting; the second is a defect; and reporting a setting as a
// defect is how a suite teaches its readers to skim failures.
//
// Measured rather than derived — a flag the goroutine sets when it starts —
// because the alternative is comparing durations against a warm-up computed a
// second time in a second place, and two copies of one number drift.
type soakLoad struct {
	driver  *chaos.Driver
	started atomic.Bool
}

// assertBillingLawHeld is the R6-G2 invariant, checked against the canonical
// chain every node agreed on.
//
// The billing law is "one signature, at most one bill, never at a position its
// signer could not avoid". The half that is observable from outside a node is
// the first: a certificate is billed where it is included, and re-inclusion is a
// block-invalidity rule, so **no certificate may appear in two blocks of the
// canonical chain**. A violation is a fold bug, not a peer's misbehaviour.
//
// The anti-vacuity half matters at least as much. A run in which nothing was
// ever included satisfies "no double billing" perfectly, which is exactly the
// shape of every instrument this project has caught measuring nothing.
func assertBillingLawHeld(t *testing.T, nodes []*soakNode, load *soakLoad) {
	t.Helper()
	driver := load.driver

	submitted, accepted, reasons := driver.Submissions()
	t.Logf("load: %d certificates submitted, %d accepted by a mempool", len(submitted), accepted)
	for reason, n := range reasons {
		t.Logf("  refused %4d x %s", n, reason)
	}

	if len(submitted) == 0 {
		if !load.started.Load() {
			// NOT RUN, and said as NOT RUN. The driver never reached its first
			// attempt: a mining reward takes `(coinbase_maturity + 2) x
			// target_block_seconds` to mature, which is %s on these parameters,
			// and this run ended first. Nothing about the billing law was
			// tested, and nothing about it is claimed.
			t.Logf("NOT RUN: the billing law is unverified in this run. The load "+
				"driver waits %s for a coinbase to mature before it can pay for "+
				"anything, and the run ended before that. Use ZCD_SOAK (try "+
				"`make soak`) for a run that exercises it.",
				time.Duration(soakLoadWarmupSeconds)*time.Second)
			return
		}
		t.Error("the load driver ran and submitted nothing: this run says nothing " +
			"about the billing law, and the soak is back to mining empty blocks")
		return
	}

	// Walk the canonical chain of a node that is up, collecting every
	// certificate id and the height it was included at.
	var live *soakNode
	for _, n := range nodes {
		if _, err := status(n.rpcPort); err == nil {
			live = n
			break
		}
	}
	if live == nil {
		t.Error("no node is reachable; the chain cannot be walked")
		return
	}
	st, err := status(live.rpcPort)
	if err != nil {
		t.Errorf("the node this chain was going to be walked from stopped answering "+
			"between one status call and the next: %v; %s", err,
			exitReport(live, exitReportGrace))
		return
	}
	tipHeight := uint64(st["height"].(float64))

	seen := map[string]uint64{}
	var included int
	for h := uint64(1); h <= tipHeight; h++ {
		ids, err := certificatesAt(live.rpcPort, h)
		if err != nil {
			continue
		}
		for _, id := range ids {
			if prev, dup := seen[id]; dup {
				t.Errorf("certificate %s appears at height %d and again at %d: "+
					"one signature has been billed twice on the canonical chain",
					id[:18], prev, h)
			}
			seen[id] = h
			included++
		}
	}

	t.Logf("billing law: %d certificate inclusions across %d blocks, no duplicates",
		included, tipHeight)

	// Anti-vacuity, in the strongest form available: the chain must actually
	// have processed the load. Zero inclusions with hundreds of submissions
	// means the certificates never reached a miner, and the duplicate check
	// above ranged over nothing.
	if included == 0 {
		t.Errorf("%d certificates were submitted and %d accepted, but not one was "+
			"included in %d blocks: the duplicate check ranged over an empty set "+
			"and this run proves nothing about the billing law",
			len(submitted), accepted, tipHeight)
	}

	// And every node must agree about who was paid. A billing difference that
	// left the chain identical would be invisible above; this catches it.
	assertBalancesAgree(t, nodes)
}

// assertBalancesAgree checks every node reports the same balance for every
// address the load touched — but only once they agree on which chain they are
// on.
//
// Without that precondition it is not a check, it is a thermometer reading the
// weather. Balances are a function of height, so two nodes at different heights
// hold different balances and are both right; after 21 kills a freshly
// restarted node is legitimately behind. The first version compared regardless
// and duly reported four "disagreements" that were nothing but a sampling
// artifact — a check that cries wolf, which is worse than no check, because it
// teaches you to skip the output.
//
// Divergence at equal tips is a real finding. Divergence at different tips is
// arithmetic.
func assertBalancesAgree(t *testing.T, nodes []*soakNode) {
	t.Helper()

	tips := map[string]int{}
	reachable := 0
	for _, n := range nodes {
		st, err := status(n.rpcPort)
		if err != nil {
			continue
		}
		reachable++
		tips[fmt.Sprint(st["tip"])]++
	}
	if reachable < 2 || len(tips) != 1 {
		t.Logf("balances not compared: %d/%d nodes reachable on %d distinct tips — "+
			"balances are a function of height, so nodes on different chains hold "+
			"different balances and both are correct",
			reachable, len(nodes), len(tips))
		return
	}

	for _, subject := range nodes {
		want := ""
		var wantFrom string
		for _, n := range nodes {
			bal, err := balanceOf(n.rpcPort, subject.key.Persistent())
			if err != nil {
				continue
			}
			if want == "" {
				want, wantFrom = bal, n.name
				continue
			}
			if bal != want {
				t.Errorf("nodes disagree about %s's balance: %s says %s, %s says %s",
					subject.name, wantFrom, want, n.name, bal)
			}
		}
	}
}

func certificatesAt(port int, height uint64) ([]string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/block?height=%d", addr(port), height))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	raw, _ := out["certificates"].([]any)
	ids := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			ids = append(ids, s)
		}
	}
	return ids, nil
}

func balanceOf(port int, a types.Address) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/balance?addr=0x%s", addr(port), hex.EncodeToString(a[:])))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	bal, ok := out["balance"].(string)
	if !ok {
		return "", fmt.Errorf("no balance field")
	}
	return bal, nil
}

// ---------------------------------------------------------------------------
// Long-distance catch-up (the regime three findings live in)
// ---------------------------------------------------------------------------

// TestChaosSoakLateJoinerCatchesUp is the regime the harness never had.
//
// Every other soak starts its nodes at genesis together and perturbs them for
// seconds, so nothing is ever more than a handful of blocks behind. Three
// findings live in the shadow of that omission and none was observed in any run
// because of it: sync complete and driven by nothing (I4-H2), `SyncFrom` never
// re-screening the pool, and the ban family that arms only past the orphan
// height window. A node trying to reach a network it fell far behind is an
// entirely different problem from a node keeping up with one, and it had never
// been asked.
//
// So: let a network converge and build real history, then introduce a node with
// nothing and require it to arrive, while the chaos continues.
//
// **The shared address group is deliberate, not a loopback accident.** Every
// node and every proxy here is inside 127.0.0.0/16, which `AddressGroup` treats
// as one source — and that is precisely the situation of the demographic the
// whitepaper targets: laptop miners behind CGNAT and shared residential
// prefixes, where honest peers collide in one group by default. The test asserts
// the precondition rather than relying on it.
func TestChaosSoakLateJoinerCatchesUp(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	if os.Getenv("ZCD_SOAK") == "" {
		t.Skip("catch-up regime needs ZCD_SOAK=<duration> (try `make soak`); " +
			"NOT RUN means long-distance catch-up is unverified — the regime three " +
			"findings live in")
	}
	nodes, bin, rng, p, block := newSoakNetwork(t, 23)
	assertNodesAreGuarded(t, nodes)
	assertOneAddressGroup(t, nodes)

	loadStop := make(chan struct{})
	driver := runLoad(t, nodes, p, loadStop)

	// Phase 1: let the network get genuinely far ahead. Past the orphan height
	// window, or the joiner is merely a little behind and this is the ordinary
	// soak with extra steps.
	target := uint64(orphanHeightWindow + 40)
	t.Logf("building history to height %d before the late joiner starts", target)
	if !waitForHeight(t, nodes, target, 40*time.Minute) {
		t.Fatalf("the network never reached height %d; nothing to catch up to", target)
	}

	// Phase 2: a node with nothing joins, and the chaos continues.
	late := &soakNode{
		name:       "late",
		dir:        filepath.Join(filepath.Dir(nodes[0].dir), "late"),
		logPath:    filepath.Join(filepath.Dir(nodes[0].logPath), "late.log"),
		paramsPath: nodes[0].paramsPath,
		monitor:    nodes[0].monitor,
		// From the BLOCK, which is the thing that reserved it. As a literal
		// `nodes[0].rpcPort + 50` this was the one soak port outside the probed
		// offsets and outside the span they were probed with, so nothing had ever
		// checked it was free and nothing kept it below the range the kernel hands
		// out on its own.
		//
		// Deriving it from a neighbour's port instead — `nodes[0].rpcPort -
		// soakRPCBase + …` — would be right only while nodes[0] happens to sit
		// at soakRPCBase, and reordering the slice would put this port back
		// outside the block with nothing able to notice. The block is the only
		// operand that cannot drift.
		rpcPort: block.base + soakLateJoinerRPC,
		key:     nodes[0].key,
		payout:  nodes[0].payout,
	}
	for _, n := range nodes {
		if n.proxyPort != 0 {
			late.peers = append(late.peers, addr(n.proxyPort))
		}
	}
	startNode(t, bin.zycordd, late)
	t.Cleanup(func() { stopNode(late) })

	startHeight := networkHeight(t, nodes)
	t.Logf("late joiner started against a network at height %d", startHeight)

	// Chaos continues while it tries to arrive.
	deadline := time.Now().Add(soakDuration)
	var kills, partitions int
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		kills, partitions = applyChaos(t, bin, nodes, rng, kills, partitions)
	}
	for _, n := range nodes {
		if n.proxy != nil {
			n.proxy.Partition(false)
		}
	}
	t.Logf("chaos: %d kills, %d partitions", kills, partitions)
	close(loadStop)

	// Phase 3: quiet, and a generous window. Catching up is allowed to be slow;
	// it is not allowed to be impossible.
	arrived := waitForCatchUp(t, late, nodes, startHeight, 10*time.Minute)

	// The settled depth has to outrun the reorgs this run actually produced, or
	// "agreement about settled history" is agreement about a zone still in
	// flux — the same validation the contention regime applies to its horizon.
	assertDepthExceedsObservedReorgs(t, append(nodes, late), contentionDepth)

	reportJoinerHealth(t, late)
	if !arrived {
		dumpLogs(t, append(nodes, late))
		t.Error("the late joiner never caught up to the network")
	}
	assertBillingLawHeld(t, nodes, driver)
	assertNoLocalViolations(t, append(nodes, late))
}

// orphanHeightWindow mirrors p2p.DefaultOrphanLimits().HeightWindow. Past it a
// node refuses every announcement it receives — correctly, since it cannot
// place them — which is exactly when sync is the only way home.
const orphanHeightWindow = 128

// assertOneAddressGroup states the precondition instead of relying on it.
func assertOneAddressGroup(t *testing.T, nodes []*soakNode) {
	t.Helper()
	groups := map[string]bool{}
	for _, n := range nodes {
		if n.proxyPort != 0 {
			groups[p2p.AddressGroup(addr(n.proxyPort))] = true
		}
	}
	if len(groups) != 1 {
		t.Fatalf("this scenario requires every peer in ONE address group and found %d: "+
			"the collision it exists to reproduce depends on that precondition", len(groups))
	}
	for g := range groups {
		t.Logf("all peers share address group %s — the CGNAT / shared-prefix case, "+
			"deliberate here rather than incidental", g)
	}
}

func networkHeight(t *testing.T, nodes []*soakNode) uint64 {
	t.Helper()
	var best uint64
	for _, n := range nodes {
		st, err := status(n.rpcPort)
		if err != nil {
			continue
		}
		if h, ok := st["height"].(float64); ok && uint64(h) > best {
			best = uint64(h)
		}
	}
	return best
}

func waitForHeight(t *testing.T, nodes []*soakNode, target uint64, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if networkHeight(t, nodes) >= target {
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

// waitForCatchUp polls until the joiner has arrived on the network's chain.
//
// "Arrived" is agreement about settled history, not possession of the newest
// tip. The first version required the joiner to be within two blocks of the
// instantaneous maximum height across three continuously-mining nodes, and duly
// failed a run in which the joiner had gone from 0 to 356 while the chain
// reached 358. It had arrived; the measure had not.
//
// That is the same error as the balance check made, in a different costume:
// comparing against a moving target without accounting for the fact that it
// moves. Under continuous mining the maximum height is whoever was luckiest a
// second ago, and a node one or two behind it is participating normally — which
// the convergence regime's own comment says, several hundred lines above.
//
// So the question asked here is the one that has an answer: does the joiner hold
// the same history as everyone else, below the depth where the tip is still
// being contested, and did it actually traverse the gap rather than stall near
// where it started.
func waitForCatchUp(t *testing.T, late *soakNode, nodes []*soakNode, startHeight uint64,
	within time.Duration) bool {
	t.Helper()

	// The settled depth is contentionDepth — the same constant, derived and
	// validated against measured reorgs, that the contention regime uses.
	//
	// It was 8 here, in a file that already contained 256 for exactly this
	// purpose. Reorgs in this regime reach 122, so "eight blocks below the
	// slowest node" is not settled history, it is the contested zone with a
	// different name — and the check duly failed a joiner that had synced from
	// 0 to 356 and was tracking the tip two blocks behind with a perfect score.
	//
	// Writing the rule down did not stop me breaking it in the next check I
	// wrote. Deriving the number from one place, and asserting it against
	// measurement below, is what stops it.
	settled := uint64(contentionDepth)

	// Why it declined, counted rather than printed on every poll — a check that
	// times out in silence tells you nothing, which is the failure this very
	// rule was written about. Three cycles were spent guessing at causes this
	// would have named on the first.
	reasons := map[string]int{}
	var attempts int
	note := func(why string) { reasons[why]++ }
	// Nodes excluded from the comparison for sitting below the settled depth.
	// Carried out of the loop and reported, because "a node was too far behind
	// to compare" is a fact about that node and must not be mistaken for a fact
	// about the joiner.
	laggards := map[string]uint64{}
	// The furthest any established node was seen to reach, so the report below
	// can state the gap it is talking about instead of naming a constant that
	// is not the gap. See the Errorf.
	var networkBest uint64
	defer func() {
		t.Logf("catch-up check: %d polls", attempts)
		for why, n := range reasons {
			t.Logf("  %4d x %s", n, why)
		}
		// A node still below the horizon when the run ends is a finding, and it
		// is reported as *itself* rather than folded into the joiner's verdict.
		//
		// Only when some other node was above it, though. If the whole network
		// is younger than the settled depth then nobody is behind — everybody is
		// early — and failing for that would be a check firing on a benign
		// reason, which costs the credibility of every other check beside it.
		// networkBest > settled, not len(laggards) < len(nodes).
		//
		// The second does not establish what the message below asserts. A node
		// absent from `laggards` because heightOf never answered satisfies it
		// just as well as one that cleared the horizon — the poll loop
		// `continue`s on an unreachable node before it counts anything. Two
		// nodes, one reachable at height 0 and one unreachable, and this fired
		// with networkBest still 0: "ended at height 0, at or below the settled
		// depth (256) ... the network was seen as far as 0, leaving this node 0
		// behind it, on its own branch" — a finding reported about a gap of
		// zero, and a branch asserted when nothing was ever compared.
		//
		// The condition that actually licenses the sentence is that the
		// established network was seen above the horizon at all. If it never
		// was, the whole network is young rather than this node being behind,
		// which is the Logf case below and was always meant to be.
		if len(laggards) > 0 && networkBest > settled {
			for name, h := range laggards {
				// What excluded this node is an absolute height — it ended at or
				// below the settled depth, so it cannot hold settled history at
				// all — and not a distance from anyone. Those are different
				// statements, and this used to report the first as the second:
				// "more than the settled depth (256) behind" was printed for a
				// node 54 blocks back in a run where the network had not passed
				// 256 either, and for a node one block short of the horizon it
				// would have been wrong by 255. The exclusion is right; naming a
				// constant that is not the gap is what was wrong. So the height,
				// the horizon and the measured distance are all reported, and
				// each says only what it is.
				t.Errorf("node %s ended at height %d, at or below the settled depth "+
					"(%d), so it holds no settled history to compare — while the "+
					"established network was seen as far as %d, leaving this node %d "+
					"behind it, on its own branch. It is not the joiner's failure and "+
					"must not be read as one: a node that cannot rejoin is the defect "+
					"this whole regime exists to surface, and it was previously "+
					"invisible because one such node made the comparison impossible "+
					"and the run blamed whoever it had been asked about.",
					name, h, contentionDepth, networkBest, networkBest-h)
			}
		} else {
			for name, h := range laggards {
				t.Logf("  %s at height %d is below the settled depth %d, and so is "+
					"everyone else: the network is younger than the horizon rather "+
					"than this node being behind it", name, h, contentionDepth)
			}
		}
	}()

	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)

		attempts++
		lateHeight, ok := heightOf(late)
		if !ok {
			note("late joiner RPC unreachable")
			continue
		}
		// It must have crossed the gap it was introduced to close, not merely
		// started moving.
		if lateHeight <= startHeight {
			note(fmt.Sprintf("joiner at %d has not passed its start height %d",
				lateHeight, startHeight))
			continue
		}

		// The comparison height comes from the nodes that can actually be
		// compared, not from the worst one in the network.
		//
		// It used to be the minimum across every node including the joiner, so
		// a single node far enough behind put the settled height out of reach
		// and the check declined — 120 polls out of 120, comparing nothing —
		// and then the test reported "the late joiner never caught up". The
		// joiner had caught up: it was on the majority tip at the same height
		// as two of the three miners. The node holding the check hostage was a
		// fourth one that had diverged, and blaming the joiner for it named the
		// wrong subject entirely.
		//
		// One stranded node must not make a check unable to speak about anyone.
		// So nodes below the horizon are excluded and *reported* rather than
		// allowed to veto, and the joiner is judged against the ones that are
		// there — while `laggards` below carries the excluded ones out of here,
		// because a node stuck far behind is a finding in its own right and not
		// a reason to stay silent.
		// The comparison height comes from the ESTABLISHED network, never from
		// the joiner. Deriving it from the joiner meant a node that crossed its
		// start height and then stalled forever was compared at its own height
		// minus the horizon — ancient history everybody agrees about — and
		// declared arrived while the network ran away from it.
		var lowest uint64
		var reachable, compared int
		for _, n := range nodes {
			h, ok := heightOf(n)
			if !ok {
				continue
			}
			reachable++
			if h > networkBest {
				networkBest = h
			}
			if h < settled+1 {
				// Too far back to hold settled history at all.
				laggards[n.name] = h
				continue
			}
			delete(laggards, n.name)
			if compared == 0 || h < lowest {
				lowest = h
			}
			compared++
		}
		if reachable == 0 {
			note("no established node reachable")
			continue
		}
		if compared == 0 {
			note(fmt.Sprintf("no established node is above the settled depth %d; "+
				"nothing can be compared", settled))
			continue
		}

		// Agreement about history below the contested tip.
		at := lowest - settled
		// And the joiner must have reached it. Without this the check is about
		// whether the joiner agrees with history it happens to hold, rather than
		// whether it crossed the gap it was introduced to close.
		if lateHeight < at {
			note(fmt.Sprintf("joiner at %d has not reached the network's settled "+
				"height %d", lateHeight, at))
			continue
		}
		want, err := blockIDAt(late.rpcPort, at)
		if err != nil {
			note(fmt.Sprintf("joiner has no block at settled height %d: %v", at, err))
			continue
		}
		// Every node, not the first disagreement. Which nodes agree with which
		// is the whole question when a divergence appears: breaking early names
		// only the first entry in a slice and says nothing about whether it is
		// the outlier or the majority.
		// agreed counts nodes actually compared. `agree` alone starts true and
		// every node can be skipped, so a poll where nobody answered read as
		// unanimous agreement and returned "arrived" having compared nothing.
		agree := true
		agreed := 0
		byID := map[string][]string{want: {"late"}}
		for _, n := range nodes {
			if _, behind := laggards[n.name]; behind {
				continue // excluded above, and reported by the caller
			}
			got, err := blockIDAt(n.rpcPort, at)
			if err != nil {
				note(fmt.Sprintf("%s has no block at settled height %d: %v", n.name, at, err))
				continue
			}
			agreed++
			byID[got] = append(byID[got], n.name)
			if got != want {
				agree = false
			}
		}
		if !agree {
			var parts []string
			for id, who := range byID {
				sort.Strings(who)
				parts = append(parts, fmt.Sprintf("%s=%v", id[:18], who))
			}
			sort.Strings(parts)
			note(fmt.Sprintf("settled height %d has %d distinct histories: %s",
				at, len(byID), join2space(parts)))
		}
		if agreed == 0 {
			note(fmt.Sprintf("no established node answered at settled height %d; "+
				"unanimity among nobody is not agreement", at))
			continue
		}
		if agree {
			t.Logf("late joiner arrived: height %d (network's slowest at %d), "+
				"agreeing on history at height %d", lateHeight, lowest, at)
			return true
		}
	}
	return false
}

func heightOf(n *soakNode) (uint64, bool) {
	st, err := status(n.rpcPort)
	if err != nil {
		return 0, false
	}
	h, ok := st["height"].(float64)
	if !ok {
		return 0, false
	}
	return uint64(h), true
}

// reportJoinerHealth prints the raw scoring state, which is the half the
// filtered signals cannot show.
func reportJoinerHealth(t *testing.T, late *soakNode) {
	t.Helper()
	st, err := status(late.rpcPort)
	if err != nil {
		t.Logf("late joiner unreachable: %v; %s", err, exitReport(late, exitReportGrace))
		return
	}
	n, err := networkInfo(late.rpcPort)
	if err != nil {
		t.Logf("late joiner network endpoint unreachable: %v", err)
		return
	}
	t.Logf("late joiner: height=%v peers=%v known=%v banned=%v min_score=%v",
		st["height"], n["peers"], n["known_peers"], n["banned_peers"], n["min_score"])
	if b, ok := n["banned_peers"].(float64); ok && b > 0 {
		t.Errorf("the late joiner banned %.0f of its peers while trying to catch up: "+
			"an honest peer answering this node's own block request is being charged "+
			"for this node's backlog", b)
	}
}

func networkInfo(port int) (map[string]any, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr(port) + "/network")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
