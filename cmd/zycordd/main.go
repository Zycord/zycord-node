// Command zycordd is the Zycord node.
//
// It runs one node on a network: the chain store, the mempool, an optional
// read-only RPC where submission is the only write, a proof-of-work engine
// chosen by the network's own parameters rather than by a flag, and optional
// mining. `zycordd repair` is a second mode over the same data directory, with
// its own flag set, because it takes the directory lock precisely so a node
// cannot be running.
//
// The peer layer is here in full: a transport identity generated per process, a
// peer store persisted in the data directory across restarts, gossip and block
// sync driven by the same engine the miner hashes against, and an inbound
// listener only when --listen is given. Without one a node is periphery — it
// dials out and can never be dialled, the shape a home connection has without
// NAT traversal.
//
// Two things are absent on purpose. There is **no key material in this
// process**: signing happens in `zcd`, and nothing here accepts a seed or a
// passphrase. And there is **no privileged endpoint**, because there is nothing
// an operator could privilege — no key can pause, upgrade, censor or mint, so
// there is no call to expose (P3).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/pow/randomx"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/checkpoints"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/p2p"
	"zycord/node/rpc"
	"zycord/node/storage"
	"zycord/spec"
)

var version = "dev"

// rpcShutdownGrace is how long the teardown waits for RPC handlers to finish
// before the chain store is closed under them.
//
// It is the server's own WriteTimeout, read from node/rpc rather than repeated
// here: a grace shorter than that abandons handlers the server itself still
// considers live — it is the response deadline every handler is written against
// — so a shorter bound would close the store under exactly the slow readers the
// grace exists for. Past it a handler has outlived its own response deadline
// and is not going to produce one, so waiting further trades a bounded exit for
// an unbounded one; the process must terminate even if a handler is wedged.
// Sizing it by a second literal coupled only by a comment drifts silently the
// first time either moves.
//
// It is a bound and not a guarantee: WriteTimeout fails a handler's WRITES, it
// does not stop a handler blocked on a read of the store. If the grace expires
// the chain is closed under whatever is left, which is exactly what
// srv.Close() did unconditionally — so this can only improve on the old
// behaviour, never regress below it.
const rpcShutdownGrace = rpc.WriteTimeout

func main() {
	// Subcommand dispatch, before the node's own flags are parsed. `repair` is
	// not a mode of running the node — it takes the data directory lock precisely
	// so a node cannot be running — so it gets its own flag set rather than
	// another boolean on this one.
	if len(os.Args) > 1 && os.Args[1] == "repair" {
		os.Exit(runRepair(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}

	fs := flag.NewFlagSet("zycordd", flag.ExitOnError)
	dir := fs.String("dir", "", "data directory (required)")
	paramsPath := fs.String("params", "", "path to a parameter file (defaults to the embedded mainnet set)")
	devnet := fs.Bool("devnet", false, "use the embedded devnet parameters")
	// The public testnet is selected by name, not by handing the binary a file.
	// Until this flag existed an operator joined the testnet by passing --params
	// spec/params.testnet.json, which made "which network is this node on" a
	// property of that operator's disk rather than of the binary. The set is
	// embedded and its genesis is pinned by a vector, so the network a node
	// joins, and the params hash a release announces, are now both recomputable
	// from the binary alone.
	testnet := fs.Bool("testnet", false, "use the embedded public testnet parameters")
	mine := fs.Bool("mine", false, "mine blocks")
	payoutHex := fs.String("payout", "", "payout address for mining: a persistent (0x02) address, hex. A one-shot (0x01) address is refused — it burns every reward once it is spent (docs/WALLET.md rule 3).")
	rpcAddr := fs.String("rpc", rpc.DefaultConfig().Addr, "RPC listen address; localhost by default")
	noRPC := fs.Bool("no-rpc", false, "do not serve RPC")
	listen := fs.String("listen", "", "peer-to-peer listen address; empty means outbound-only")
	advertise := fs.String("advertise", "", "address to advertise to peers; defaults to --listen. Set this when the address peers can reach is not the one this process binds (a forwarded port, a proxy).")
	peersFlag := fs.String("peers", "", "comma-separated bootstrap peer addresses, merged with the network's built-in seeds")
	peersFile := fs.String("peers-file", "", "file of bootstrap peer addresses, one per line; # comments and blank lines ignored. Merged with --peers.")
	noSeeds := fs.Bool("no-seeds", false, "do not use the network's built-in seed addresses; --peers and --peers-file still apply")
	seed := fs.Int64("seed", 1, "dial-jitter seed, so a run is reproducible")
	mineThreads := fs.Int("mine-threads", 0,
		"nonce-search goroutines when mining (0 = one per core)")
	// Two flags because they answer different questions. --update sets a
	// DURABLE policy for this data directory; --no-update-check suppresses ONE
	// run. A CI job or an air-gapped rehearsal wants the second without editing
	// the first.
	updateMode := fs.String("update", "",
		"update policy for this data directory: auto, notify or never. "+
			"Persisted to <dir>/update.json; omit it to use the saved choice.")
	noUpdateCheck := fs.Bool("no-update-check", false,
		"do not contact the release host on this run, whatever <dir>/update.json says")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println("zycordd", version)
		return
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "zycordd: --dir is required")
		fs.Usage()
		os.Exit(2)
	}

	p, err := loadParams(*paramsPath, *devnet, *testnet)
	if err != nil {
		fatal(err)
	}

	// storage.Options.Logger defaults to silent, matching a library's usual
	// stance — cmd/zycordd is the one real caller that wants its rare
	// operator-facing diagnostics (today: a torn-tail recovery, or an
	// automatic compaction that failed and will retry) on the process's own
	// log, the same way net.Logger is wired a few lines down for p2p.
	// The update pre-flight, and the only place in this process where replacing
	// its own executable is safe.
	//
	// It sits here for three reasons, each of which is a different failure if it
	// moved. After --dir is validated, because the policy lives in <dir>. After
	// loadParams, so a bad --params still fails first and `zycordd --params
	// nonsense.json --dir /new` still does not create /new as a side effect. And
	// before chain.OpenWith, so nothing is open: no store, no directory lock, no
	// listener, no goroutine, no block in flight.
	//
	// It may not return. On an applied update it re-execs this process into the
	// new binary, which on Unix preserves the PID so a supervisor sees no
	// restart at all.
	upd := preflightUpdate(*dir, *updateMode, *noUpdateCheck)

	c, err := chain.OpenWith(*dir, p, storage.Options{Logger: log.Default()})
	if err != nil {
		fatal(err)
	}
	defer c.Close()

	networkID := c.NetworkID()
	log.Printf("network=%s chain_id=%d network_id=%x height=%d state_guard=%s",
		p.Name, p.ChainID, networkID[:8], c.Height(), guardState())

	// The launch checkpoint defence. Installed once, here, before anything syncs,
	// and announced on the same breath as the network — a node that refuses to
	// sync because of a pin is only diagnosable if the pin it is enforcing was
	// printed when it started. `/status` carries the same values for a node
	// already running.
	//
	// It is client release policy and not a chain parameter: the file hash
	// below is announced separately from the params hash, and editing a
	// checkpoint cannot move the params hash. That separation is the whole
	// reason a routine release does not fork the network — see
	// node/checkpoints.
	cps := checkpointsFor(*paramsPath, *devnet, *testnet)
	checkpoints.Install(cps)
	cpsHash := spec.CheckpointsHash()
	log.Printf("checkpoints: %s (spec/checkpoints.json %x)", cps.String(), cpsHash[:8])

	pool := mempool.New(p, mempool.DefaultPolicy())
	metrics := &rpc.Metrics{}

	// The network. A node with no --listen is periphery: it dials out and can
	// never be dialled, which is the shape a home connection has without NAT
	// traversal (see docs/decisions/networking.md §5).
	identity, err := p2p.NewIdentity()
	if err != nil {
		fatal(err)
	}
	peerStore, err := p2p.NewPeerStore(filepath.Join(*dir, "peers.json"))
	if err != nil {
		fatal(err)
	}
	// What peers are told to dial is not always what this process binds. A node
	// behind a forwarded port binds a private address and is reachable at a
	// public one, and telling peers the private address makes it unreachable
	// while looking connected (docs/decisions/networking.md §5).
	reachable := *advertise
	if reachable == "" {
		reachable = *listen
	}
	// ONE engine, shared by the gossip path, the sync driver and the miner.
	//
	// Two independent `pow.Dev{}` literals used to stand here and in the miner
	// below. That was inert while the engine was a stateless BLAKE3 call and is
	// not inert now: a RandomX engine holds initialised caches and a pool of
	// virtual machines, so a second instance is a second 256 MiB cache, a
	// second dataset if mining, and two LRUs evicting against each other.
	work, err := selectEngine(p, *mine)
	if err != nil {
		fatal(err)
	}
	// Every goroutine that hashes against this engine is registered here, and
	// closeEngine joins them before the engine is freed.
	//
	// LIFO matters and is the whole reason this is one defer rather than two. The
	// engine's Close used to be deferred right here while mineLoop and
	// prefetchLoop were launched forty lines further down and joined by nothing
	// at all: `main` returned from `<-stop`, this defer fired, and a RandomX
	// engine released its caches, its virtual machines and its ~2 GiB dataset
	// with the nonce-search threads still inside randomx_calculate_hash. The
	// engine's own locking is what has kept that from being a SIGSEGV since the
	// engine grew its own mutex — the point here is that the process must not be
	// relying on it. An engine that is closed is an engine whose users are
	// finished.
	//
	// net.Stop() below already joins the p2p handlers, and it is deferred
	// after this one, so it runs first.
	var hashers sync.WaitGroup
	defer closeEngine(work, &hashers)
	log.Printf("proof of work: %s engine, as %s requires", work.Name(), p.Name)

	engine := p2p.NewEngine(c, pool, peerStore, work, reachable)
	net := p2p.NewNode(identity, engine, peerStore, *seed)
	net.Logger = log.Default()
	bootstrap, err := bootstrapList(*peersFlag, *peersFile, seedsFor(*paramsPath, *devnet, *testnet, *noSeeds))
	if err != nil {
		fatal(err)
	}
	net.Bootstrap = bootstrap
	// Say which addresses this node will start from and where they came from.
	// A seed that is built in is still a seed an operator is entitled to see
	// before it is dialled — and when the list is empty, saying so is the
	// difference between a node nobody can reach and a node nobody can
	// diagnose.
	switch {
	case len(bootstrap) == 0:
		log.Printf("bootstrap: no addresses — this node will not dial anyone " +
			"until a peer dials it (pass --peers, or drop --no-seeds)")
	default:
		log.Printf("bootstrap: %s", strings.Join(bootstrap, " "))
	}
	if *listen != "" {
		if err := net.Listen(*listen); err != nil {
			fatal(err)
		}
		log.Printf("p2p listening on %s (advertising %s) as %s", net.ListenAddr(), reachable, identity)
	}
	net.Start()
	defer func() {
		net.Stop()
		if err := peerStore.Save(); err != nil {
			log.Printf("saving peers: %v", err)
		}
	}()

	if !*noRPC {
		cfg := rpc.DefaultConfig()
		cfg.Addr = *rpcAddr
		srv := rpc.New(c, pool, cfg, metrics)
		srv.SetNetwork(net)
		// Bind before announcing. "rpc listening on <addr>" is an observation of a
		// bind that has happened, not a prediction of one: printed ahead of the bind
		// it declared the RPC up in the very run where the bind then failed and the
		// node served nothing, and anything reading the log — an operator, a start
		// script, a health check that greps for the line — believed it. Listen makes
		// the bind, so the line below follows it.
		//
		// Whether a failed bind should be fatal is a separate decision and is left
		// exactly as it was: the node logs the failure and keeps following the
		// chain without RPC. Only the order of the message is corrected here.
		if err := srv.Listen(); err != nil {
			log.Printf("rpc not listening on %s: %v (continuing without RPC)", cfg.Addr, err)
		} else {
			// srv.Addr(), not cfg.Addr: the line reports the socket that opened, which
			// for a :0 request (a container- or test-assigned port) is the concrete
			// port the kernel chose and which cfg.Addr never carried. For a concrete
			// cfg.Addr the two read identically. Listen has returned nil here, so
			// Addr() is non-nil.
			log.Printf("rpc listening on %s (read-only; submission is the only write)", srv.Addr())
			go func() {
				if err := srv.ListenAndServe(); err != nil {
					log.Printf("rpc stopped: %v", err)
				}
			}()
			// Shutdown, not Close. Close is http.Server.Close: it shuts the listeners
			// and the idle connections and returns at once, without waiting for a
			// handler already inside the mux — and a handler holds `c` and `pool` for
			// its whole run. `defer c.Close()` therefore landed under a live reader of
			// the store, in either teardown order, because nothing between the two
			// joins an RPC handler.
			//
			// The grace period is bounded because a shutdown must terminate; see
			// rpcShutdownGrace for why it is sized at the server's WriteTimeout.
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), rpcShutdownGrace)
				defer cancel()
				if err := srv.Shutdown(ctx); err != nil {
					log.Printf("rpc shutdown: %v (requests still in flight were abandoned)", err)
				}
			}()
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	stop := stopOnSignal(sig)

	// A heartbeat, because until now a node that was not mining logged nothing
	// at all, ever.
	//
	// That is most of a node: every non-mining full node, and every miner
	// between blocks. A 45-minute chaos soak ended with three nodes stuck 23
	// blocks behind and *two minutes of complete silence* in their logs, and
	// there was no way to tell from the outside whether they were disconnected,
	// unable to sync, or simply not trying — the three have entirely different
	// causes and identical logs. An operator debugging a stalled node at three
	// in the morning has exactly the same problem.
	//
	// One line, everything needed to place the node: where it is, who it can
	// see, whether anyone can see it, and whether it believes it is behind.
	//
	// Registered and joined, because it READS the chain: c.Tip(), c.Height(),
	// c.Stats(), plus the mempool and the peer set. It used to be launched bare —
	// nothing added it to a group, nothing waited for it — so `main` returned
	// from `<-stop` and `defer c.Close()` ran while the heartbeat could be inside
	// that read. The storage layer's own locking is what kept that from being
	// worse, and that is exactly the argument this teardown rejects: a process
	// must not close a resource that is still in use, and must not depend on the
	// resource's internal locking to stay correct.
	//
	// This defer is registered LAST, so it unwinds FIRST — before the RPC
	// drain, before net.Stop(), before the engine and the chain. The heartbeat
	// reads all four, so joining it ahead of every one of them is the only
	// depth at which none of its reads can outlive what it reads.
	var status sync.WaitGroup
	status.Add(1)
	go func() {
		defer status.Done()
		heartbeat(c, net, pool, stop)
	}()
	// The update notice, on the same group and for the same reason: it is joined
	// before anything it could still be reading is closed. It reads nothing the
	// heartbeat reads and holds no chain state at all - it only talks to the
	// release host - so joining it here is stricter than it needs to be, which
	// is the right direction. Reusing the group also adds no defer, so the
	// teardown order this file asserts elsewhere is unchanged.
	status.Add(1)
	go func() {
		defer status.Done()
		updateNotice(upd, stop)
	}()
	defer status.Wait()

	// Warm the next epoch's proof-of-work key before the chain reaches it.
	//
	// Possible only because the key comes from the HEIGHT (pow.KeyFor): the
	// next epoch's key is known long before its boundary. Under upstream
	// RandomX's schedule, where the key is a key block's hash, which key comes
	// next depends on which branch wins.
	//
	// It is a node concern rather than a consensus one — a node that never
	// prefetched would verify exactly the same blocks, a few seconds later at
	// each boundary — so it lives here rather than anywhere below.
	if pf, ok := work.(interface{ Prefetch(types.Hash) }); ok {
		// Registered: a prefetch builds a cache inside the engine, so it is a
		// user of the engine exactly as the miner is.
		hashers.Add(1)
		go func() {
			defer hashers.Done()
			prefetchLoop(c, pf, p, stop)
		}()
	}

	if *mine {
		payout, err := parsePayout(*payoutHex)
		if err != nil {
			fatal(err)
		}
		m := &miner.Miner{
			Chain:  c,
			Pool:   pool,
			Engine: work,
			Payout: payout,
			Now:    func() uint64 { return uint64(time.Now().Unix()) },
		}
		// Resolved here rather than left to the miner's zero value, which is
		// deliberately one thread so that the type is reproducible by default.
		threads := *mineThreads
		if threads <= 0 {
			threads = runtime.GOMAXPROCS(0)
		}
		log.Printf("mining to %x with the %s engine on %d threads",
			payout[:8], m.Engine.Name(), threads)
		m.Threads = threads
		hashers.Add(1)
		go func() {
			defer hashers.Done()
			mineLoop(c, m, net, metrics, stop, p, rand.New(rand.NewSource(*seed)))
		}()
	}

	<-stop
	log.Println("shutting down")
}

// closeEngine joins every goroutine that hashes against the proof-of-work
// engine, and only then closes it.
//
// The order is the point, and it is not a tidiness argument — but the harm it
// prevents is not the use-after-free this join was originally filed against,
// and saying so is the difference between a comment that stays true and one
// the next reader disproves.
//
// A RandomX engine owns C allocations: 256 MiB caches, a pool of virtual
// machines, and in full-memory mode a ~2 GiB dataset. Closing it calls
// randomx_release_dataset and randomx_release_cache. Before the engine grew
// its own fmu write lock over Close, a hash in flight was a thread inside
// randomx_calculate_hash reading exactly those buffers, and freeing them under
// it was a use-after-free across the cgo boundary — the SIGSEGV on stopping a
// miner reported from the field. **That is no longer reachable**: Close takes
// fmu for write and drains every fast VM before releasing the dataset, so
// acquiring the write lock is what waits for the hashes already inside.
//
// What is left is a leak, not a fault. Close nils the dataset and empties the
// key table but sets no closed flag, so a hasher arriving afterwards falls
// through to the light path, builds a fresh entry, and allocates a 256 MiB
// cache and its VMs that nothing will ever free. At process exit the OS
// reclaims them, which makes the observable damage today approximately nil.
//
// The case for joining here is therefore structural, and it is enough on its
// own: a process must not close a resource that is still in use, and must not
// depend on the engine's internal locking to stay correct. The caller is the
// only party that knows which goroutines it started.
//
// Not every engine is closeable — pow.Dev owns nothing — so the assertion is
// for io.Closer rather than a widened pow.Engine. The wait happens either way:
// what it establishes is that the users are finished, which does not depend on
// what the engine does next.
func closeEngine(work pow.Engine, hashers *sync.WaitGroup) {
	hashers.Wait()
	closer, ok := work.(io.Closer)
	if !ok {
		return
	}
	if err := closer.Close(); err != nil {
		log.Printf("closing the %s engine: %v", work.Name(), err)
	}
}

// stopOnSignal turns one delivered signal into a shutdown every goroutine sees.
//
// **A signal channel is a queue, not a broadcast**, and this node has five
// places that want to know: main, the mine loop, its abandon predicate, the
// prefetch loop and the heartbeat. signal.Notify delivers each signal ONCE, to
// whichever receiver happens to be ready, so with all five selecting on the
// signal channel itself a SIGTERM woke exactly one of them and the rest carried
// on. Whether the node shut down at all depended on which one won. (Five code
// sites; four are live under `--devnet --mine`, where pow.Dev has no Prefetch
// and the prefetch loop is never started.)
//
// Measured on darwin/arm64, five runs of `zycordd --devnet --mine`, SIGTERM
// six seconds in, fifteen seconds to exit: **one run exited, four kept
// mining** and had to be killed. That is the same coin the miner-SIGSEGV field
// report records landing the other way — "the miner also stopped on SIGTERM
// without the SIGSEGV, once" — and "once" is the word to notice in that
// sentence.
//
// A closed channel is the broadcast a signal channel is not: every receiver
// sees it, forever, and no receiver consumes it. The goroutine outlives nothing
// — it ends with the process — and a second signal after this one takes the
// operating system's default action, which is what an operator pressing ^C
// twice is asking for.
func stopOnSignal(sig chan os.Signal) <-chan struct{} {
	stop := make(chan struct{})
	go func() {
		<-sig
		// Hand the signal back to the operating system before announcing the
		// shutdown, so a SECOND one kills the process instead of vanishing.
		//
		// signal.Notify stays registered for the life of the process unless it
		// is stopped, and once this goroutine has taken its one value nothing
		// reads the channel again — so without this line every later ^C landed
		// in a buffer nobody drains and did nothing at all. That is not an
		// abstract tidiness: a stop that arrives during a key change waits for
		// the ~2 GiB dataset fill to finish, which is exactly the pause in
		// which an operator presses ^C again.
		signal.Stop(sig)
		close(stop)
	}()
	return stop
}

// mineLoop mines until told to stop. It paces itself to the target block time
// rather than spinning: the development engine is trivial, and a devnet that
// produces ten thousand blocks a second is a devnet nobody can read the logs of.
func mineLoop(c *chain.Chain, m *miner.Miner, net *p2p.Node, metrics *rpc.Metrics,
	stop <-chan struct{}, p *params.Params, rng *rand.Rand) {
	// Pacing is stochastic, because real proof of work is.
	//
	// A fixed ticker was not a simplification, it was a different physics. The
	// development engine solves instantly, so every miner on a fixed interval
	// produced a block at the same moment as every other one — three miners
	// started within milliseconds emitted three siblings at the same height,
	// every interval, forever. Equal work never triggers a switch (first-seen
	// wins, correctly), so the network held three chains of *identical* weight
	// that no fork-choice rule could ever separate. That is not a consensus
	// failure; it is a coin that always lands on its edge.
	//
	// Real mining is a Poisson process: inter-block intervals are exponential,
	// ties are transient, and one branch pulls ahead within a block or two. An
	// exponential delay reproduces that.
	//
	// **AND IT IS APPLIED ONLY TO THE DEVELOPMENT ENGINE.** A real work
	// function produces that distribution by being work; pacing it as well
	// would cap the node at one attempt-batch per interval and make the
	// measured hashrate a property of this loop rather than of the machine.
	// The condition is on the engine because the engine is what decides
	// whether a solve costs microseconds or a block interval — see
	// selectEngine, and note that pow_engine is consensus, so this reads the
	// network's own declaration rather than a guess.
	paced := m.Engine.Name() == pow.Dev{}.Name()
	next := func() time.Duration {
		if !paced {
			return 0
		}
		mean := float64(p.TargetBlockSeconds) * float64(time.Second)
		// -mean*ln(U) for U in (0,1]: the standard inverse-transform sample.
		u := rng.Float64()
		if u <= 0 {
			u = math.SmallestNonzeroFloat64
		}
		return time.Duration(-mean * math.Log(u))
	}

	// The attempt budget, which is a different quantity for the two engines
	// and was one number for both. Against pow.Dev almost every nonce solves,
	// so 1<<24 is never reached. Against RandomX a core manages a few hundred
	// hashes a second, so 1<<24 attempts is weeks of work and the miner would
	// not look at the tip again until it finished. What bounds a real search is
	// the abandon condition below, not the budget; the budget is left large so
	// that it never terminates a search that the tip has not already made
	// pointless.
	const budget = 1 << 24

	// The wait before a network's first block, and the rate limit on saying so.
	//
	// A node started hours before genesis refuses to mine (miner.ErrTooEarly)
	// and must then do two things it did not have to do before: not spin, and
	// not go silent. Both are failures an operator reads as "it is broken":
	// a loop with nothing to pace it burns a core for hours, and a miner that
	// logs nothing for four hours is indistinguishable from one that is hung —
	// and the operator's fix for that is to kill it and start editing flags,
	// which is the whole experience this refusal exists to protect.
	//
	// Polling rather than sleeping the whole gap in one go: the wait is a
	// function of the local clock, and a clock that is corrected — by NTP, by a
	// laptop waking from suspend — moves the answer under a sleep already
	// committed to. Thirty seconds is well inside the resolution anybody cares
	// about here and costs one median-time read per tick.
	//
	// The countdown is re-announced on an interval measured by ACCUMULATING the
	// sleeps rather than by reading the clock a second time. I2-L5's claim is
	// that Miner.Now is the only reading of wall time in the node, and a
	// `time.Now()` here to rate-limit a log line would quietly cost that claim
	// for nothing: the durations being slept are already known exactly.
	const (
		mineWaitPoll        = 30 * time.Second
		mineWaitLogInterval = 10 * time.Minute
	)
	var (
		sinceWaitLog time.Duration
		sayWait      = true
	)

	for {
		select {
		case <-stop:
			return
		case <-time.After(next()):
		}

		// The miner abandons on its own when the tip moves; this adds the
		// only other reason to stop, which is that the node is shutting down.
		// Without it a RandomX search would hold the process open for as long
		// as it takes to finish, and `zycordd` would look hung on SIGTERM.
		b, res, err := m.MineOneWhile(budget, func() bool {
			select {
			case <-stop:
				return true
			default:
				return false
			}
		})
		// Not yet: this node's clock has not reached the earliest timestamp the
		// next block may carry. Before a network's genesis that is the whole of
		// what a correctly configured miner is doing, so it is neither an error
		// nor a reason to reconfigure anything — and the line says so, because
		// the operator reading it is deciding whether to leave it running.
		var early *miner.TooEarlyError
		if errors.As(err, &early) {
			if sayWait {
				log.Printf("waiting to mine: the next block cannot be dated before "+
					"%s (unix %d), and this node's clock reads %s — %s to wait. "+
					"Leave this running: mining starts on its own and there is "+
					"nothing to restart or reconfigure.",
					utcStamp(early.NotBefore), early.NotBefore,
					utcStamp(early.Now), waitDuration(early.Remaining()))
				sayWait = false
				sinceWaitLog = 0
			}
			wait := mineWaitPoll
			if d := waitDuration(early.Remaining()); d < wait {
				wait = d
			}
			if wait <= 0 {
				wait = time.Second
			}
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
			sinceWaitLog += wait
			if sinceWaitLog >= mineWaitLogInterval {
				sayWait = true
			}
			continue
		}
		// Any other outcome ends the wait, so the next one announces itself at
		// once rather than inheriting a spent interval.
		sayWait, sinceWaitLog = true, 0
		if errors.Is(err, miner.ErrStaleTemplate) {
			// Somebody else won this height. Build again on the new tip
			// immediately rather than idling out the interval.
			continue
		}
		if err != nil {
			log.Printf("mining: %v", err)
			continue
		}
		net.AnnounceBlock(b)
		id := b.Header.ID()
		log.Printf("block height=%d id=%x certs=%d applied=%d skipped=%d dropped=%d "+
			"seq_gas=%d/%d par_gas=%d reward=%s treasury=%s matured=%s burned=%s peers=%d",
			b.Header.Height, id[:6], len(b.Certs),
			count(res, fold.Applied), skipped(res), count(res, fold.Dropped),
			res.SeqGasApplied, res.SeqGasUsed, res.ParGasApplied,
			res.MinerReward.String(), res.Treasury.String(), res.Matured.String(),
			res.Burned.String(), net.PeerCount())
	}
}

// waitDuration converts a second count to a Duration, saturating rather than
// wrapping.
//
// miner.TooEarlyError.Remaining is a uint64 and time.Duration is a SIGNED
// nanosecond count, so the naive multiplication overflows above about 292
// years and comes back negative. The value that reaches here is a median-time
// floor minus a clock, and neither term is this node's to choose: the floor
// comes from headers, and a chain whose median has been pushed far ahead is a
// documented attack shape rather than a hypothetical (ARCHITECTURE §12, R1-H2).
// A negative duration would make `time.After` fire immediately and turn the
// wait into the spin it exists to prevent.
func waitDuration(secs uint64) time.Duration {
	const max = uint64(math.MaxInt64) / uint64(time.Second)
	if secs > max {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs) * time.Second
}

// utcStamp renders a unix second as an RFC 3339 timestamp, always in UTC.
//
// Always UTC, never Local, and that is a publication rule rather than a
// preference: a local timestamp in a log an operator pastes into an issue is a
// timezone, and a timezone is a location. docs/RELEASE.md §2 makes the same
// point about commit dates, and sim/wiring's text scan tracks the class.
func utcStamp(unix uint64) string {
	if unix > math.MaxInt64 {
		return "out of range"
	}
	return time.Unix(int64(unix), 0).UTC().Format(time.RFC3339)
}

// prefetchLoop builds the next key epoch's cache ahead of the boundary.
//
// The stall it removes was measured rather than imagined: on a devnet with a
// tiny key interval, ordinary blocks arrived every 0.3–1 s and every boundary
// took 8–11 s, three times running. Most of that is a miner's dataset, which
// is deliberately NOT prefetched — holding two of them is 4 GiB to save a
// pause once per key interval, and at mainnet's 2048 blocks that is once every
// seventeen hours. What this removes is the verifier's share, where the cost
// is one cache the engine already holds a slot for.
//
// Deliberately dumb: it asks once a minute and the engine ignores a key it
// already has. A tighter schedule would need to know how fast the chain is
// moving, which is a second estimator to get wrong for a saving measured in
// seconds per epoch.
func prefetchLoop(c *chain.Chain, pf interface{ Prefetch(types.Hash) },
	p *params.Params, stop <-chan struct{}) {
	ticker := time.NewTicker(prefetchPeriodFor(p))
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		pf.Prefetch(pow.KeyFor(prefetchHeight(c.Height(), p), p))
	}
}

// prefetchHeight is the height whose key prefetchLoop warms from a given tip.
//
// It reads "the key this chain will need within a key lag of blocks", and the
// lag is the right distance for a reason rather than by taste: it is the slack
// the schedule already puts between an epoch's key becoming decidable and the
// first height that uses it (pow.SeedEpochFor), so warming across exactly that
// window asks for the next epoch's key over exactly the stretch where the next
// block might be the one that needs it, and never earlier.
//
// It used to be `height + RandomXKeyInterval`, which reads as "one interval
// ahead" and is not: SeedEpochFor shifts the boundary forward by the lag, so
// height + interval crosses into the next epoch as soon as the chain reaches
// height LAG — 64 on mainnet and on the public testnet — and every tick from
// there on warmed a key nothing would need for a whole interval. On the
// testnet that was 512 blocks early; on mainnet it is 2048.
//
// Warming early is not a defect by itself and this is not where the
// prefetch-versus-serving-key fault was fixed; the engine no longer lets a
// prefetch disturb the key it is serving, which is the actual bug. What this
// removes is the distance between what the line says and what it does — the
// property that made the engine defect fire an entire epoch before anyone
// would have looked for it, on a node that had been running for one minute.
func prefetchHeight(height uint64, p *params.Params) uint64 {
	return height + p.RandomXKeyLag
}

// prefetchPeriod is the SLOWEST rate at which prefetchLoop asks, and
// prefetchTicks is how many asks must land inside the window in which it is
// asking for the next epoch's key.
//
// Two ticks would be the bare minimum against phase; three is one spare, and
// the cost of a spare is one goroutine that finds the key already resident.
const (
	prefetchPeriod = time.Minute
	prefetchTicks  = 3
)

// prefetchPeriodFor is how often prefetchLoop asks on a given network.
//
// **The lag is a distance in BLOCKS and a ticker's period is a distance in
// SECONDS**, and nothing in the tree related the two. Where the first is
// shorter than the second the loop can step over the whole window, and the
// boundary is then crossed with nothing warmed — the miner pays a cache build
// on top of the dataset fill it was going to pay anyway.
//
// It is not hypothetical. The end-to-end RandomX bring-up run used a
// devnet-sized RandomX schedule (interval 64, lag 8, 5 s blocks), so an
// 8-block window is 40 s against a 60 s period, and its own log shows the
// miss: the first boundary paid a 14 s pause for a cache nothing had warmed
// and the second paid 9 s for one that had.
//
// The remedy is HERE rather than in prefetchHeight, and the choice is the whole
// point. Widening the lead would work too, and would be the wrong repair: the
// lag is the slack the schedule itself puts between a key becoming decidable
// and the first height that uses it, so `height + lag` says exactly what it
// means and warming earlier only spends one of the engine's two key-table
// slots for longer. What was wrong was never the distance. It was the rate.
//
// Mainnet and the public testnet never reach this branch — 64 blocks of lag at
// 30 s is a 32-minute window, so the 60 s period already fits 32 asks inside
// it — and devnet runs dev-blake3, which has no Prefetch and never starts the
// loop at all. What this covers is every other parameter set somebody points a
// RandomX binary at, including the one this project uses to cross key
// boundaries in minutes instead of hours.
//
// The floor is arithmetic rather than arbitrary: params.Validate forces a lag
// of at least one block and a target of at least one second (checkAllPositive
// walks every numeric field, so neither can be zero, and lag < interval then
// makes the interval at least two), so the shortest period this can return is
// a third of a second.
//
// **prefetchTicks is doing two jobs, and the second one is why it is not two.**
// The obvious one is phase: a window that holds exactly one period can still be
// straddled by a ticker whose offset is unlucky. The other is that the window
// is computed at the chain's TARGET rate and lived at its actual one. Blocks
// arriving faster than target shorten the real window in proportion, and the
// guarantee this function gives degrades with them.
//
// The bound is exact and worth stating, because it is what a reader would
// otherwise have to derive. Both branches return a period no greater than
// window/prefetchTicks — the ceiling branch only fires when the window already
// holds prefetchTicks of them — so at least one ask lands in the real window
// whenever
//
//	actual_block_seconds >= target_block_seconds / prefetchTicks
//
// which is to say the chain may run up to THREE TIMES faster than its target
// before even one ask is guaranteed. Mainnet is far safer still: its period is
// the 60 s ceiling rather than window/3, so 64 blocks of lag hold an ask until
// blocks are arriving under a second apart, thirty times the target rate. A
// chain sustaining more than that has a difficulty controller problem, and the
// cost of missing here is one cache build at a boundary — the behaviour before
// any of this, not a regression below it.
func prefetchPeriodFor(p *params.Params) time.Duration {
	window := prefetchWindowSeconds(p)
	if window == 0 {
		return prefetchPeriod // Validate rejects this; do not divide by it.
	}
	if window >= uint64(prefetchPeriod/time.Second)*prefetchTicks {
		return prefetchPeriod // the window already holds the asks
	}
	return time.Duration(window) * time.Second / prefetchTicks
}

// prefetchWindowSeconds is how long the stretch lasts over which prefetchHeight
// names the NEXT epoch's key: the lag, in blocks, at the chain's target rate.
//
// It saturates rather than wrapping. Validate accepts a target_block_seconds
// large enough to overflow the product, and a wrapped window would come out
// small and make the loop ask far more often than anything needs.
func prefetchWindowSeconds(p *params.Params) uint64 {
	lag, secs := p.RandomXKeyLag, p.TargetBlockSeconds
	if lag == 0 || secs == 0 {
		return 0
	}
	if lag > math.MaxUint64/secs {
		return math.MaxUint64
	}
	return lag * secs
}

// heartbeat prints one status line periodically.
//
// It reports reachability separately from peer count because the two fail
// differently: a node with peers and no inbound is unreachable and looks
// healthy, and a node that is behind with candidates it is not syncing from is
// a different fault from one with no candidates at all.
func heartbeat(c *chain.Chain, net *p2p.Node, pool *mempool.Pool, stop <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		tip := c.Tip()
		id := tip.ID()
		listening, inbound, outbound := net.Reachability()
		stats := c.Stats()
		// ahead_peers is filtered by the ban list; known/banned/min_score are
		// not. Reporting both is the point: a node that has banned everyone who
		// could tell it it is behind shows ahead_peers=0 and banned>0, which is
		// the only pair that distinguishes it from a node at the tip.
		behind := len(net.Engine.SyncCandidates())
		known, banned, minScore := net.PeerHealth()
		// refused_in is a counter, not an alarm: turning a connection away for a
		// full per-source budget is the eclipse defence working. It is here
		// because it was the one thing an operator could not see. A refused
		// accept closes the socket before the TLS handshake and logs nothing, so
		// it reaches the dialer as a bare EOF and reaches this node's log not at
		// all — which made "my sync attempts all end in EOF" and "my peer is
		// full" the same observation, and cost a ten-hour finding its diagnosis.
		// preempted_in is the same instrument one layer down. The global
		// handshake cap preempts the oldest handshake in flight rather than
		// refusing the newest, so that a flood of silent connections cannot
		// lock honest peers out — but the preempted peer sees a bare reset,
		// which is what a flaky link looks like too. A rising count is the
		// only thing that separates them.
		log.Printf("status height=%d tip=%x peers=%d in=%d out=%d listening=%t "+
			"ahead_peers=%d known=%d banned=%d min_score=%d refused_in=%d "+
			"preempted_in=%d mempool=%d "+
			"applied=%d undone=%d rejected=%d reorgs=%d deepest=%d",
			c.Height(), id[:6], net.PeerCount(), inbound, outbound, listening,
			behind, known, banned, minScore, net.InboundRefused(),
			net.HandshakesPreempted(), pool.Stats().Size,
			stats.BlocksApplied, stats.BlocksUndone,
			stats.BlocksRejected, stats.ReorgEvents, stats.DeepestReorg)
	}
}

// guardState reports whether the reentrancy half of the consensus-state guard
// is compiled in.
//
// The borrow-lifetime half is always on, in every build, so it is not reported:
// there is no state in which it is absent. Only reentrancy detection is
// optional, because only it costs microseconds. Logged at startup because a
// build tag is one typo away from disarming every check that depends on it, and
// a disarmed guard is indistinguishable from a clean run. The chaos soak asserts
// this says "on".
func guardState() string {
	if chain.ReentrancyGuardEnabled {
		return "on"
	}
	return "off"
}

func count(res *fold.Result, want fold.Outcome) uint64 {
	var n uint64
	for _, o := range res.Outcomes {
		if o.Outcome == want {
			n++
		}
	}
	return n
}

func skipped(res *fold.Result) uint64 {
	return count(res, fold.SkippedStale) + count(res, fold.SkippedOverflow)
}

// loadParams resolves the parameter set this node runs: an explicit file, or
// one of the sets embedded in the binary (mainnet by default).
//
// The three sources are mutually exclusive rather than ranked. A node given
// two of them speaks one protocol and its operator believes another, and there
// is no ordering of the three that makes that safe to guess at.
//
// Whichever source wins, the parameter set is then held to the embedded
// chain-id ledger before this function returns one. That check is the reason
// the ledger is more than a note: spec/chainid_allocation_test.go binds the
// files this repository ships, and it is `go test ./spec` that runs it — so an
// operator who respins a network by editing their deployed
// params.testnet.json, or a third party who stands one up on an id allocated
// here, met no refusal from any binary. The rule lived in the repository and
// the hazard lives on a machine. It is applied to the embedded sets too, not
// only to --params: a check that skipped the paths it expects to pass is one
// nobody would notice had broken.
func loadParams(path string, devnet, testnet bool) (*params.Params, error) {
	p, err := resolveParams(path, devnet, testnet)
	if err != nil {
		return nil, err
	}
	// genesis.NetworkID is passed in rather than imported by spec: package
	// spec cannot import core/genesis without making core/fold's internal
	// tests an import cycle. It is called only for a chain id the ledger has
	// pinned a genesis against, so the default path builds no block.
	if err := spec.CheckChainID(p, genesis.NetworkID); err != nil {
		return nil, err
	}
	return p, nil
}

// checkpointsFor returns the checkpoint table this run enforces.
//
// It mirrors resolveParams' choice rather than reading p.Name, because p.Name
// is the *chain's* name ("zycord" on mainnet) and the checkpoint file is keyed
// by the embedded set a release ships — the same three names spec.Networks()
// lists.
//
// A hand-supplied --params file gets the empty set, and that is the safe
// answer rather than a gap: this release publishes no policy for a network it
// does not embed, and pinning a stranger's chain to mainnet's block ids would
// refuse every block it has. A respun network therefore syncs exactly as it did
// before this existed, and says so in the startup line.
func checkpointsFor(path string, devnet, testnet bool) checkpoints.Set {
	if path != "" {
		return checkpoints.Set{}
	}
	name := "mainnet"
	switch {
	case testnet:
		name = "testnet"
	case devnet:
		name = "devnet"
	}
	return checkpoints.MustLoad(name)
}

func resolveParams(path string, devnet, testnet bool) (*params.Params, error) {
	chosen := 0
	for _, on := range []bool{path != "", devnet, testnet} {
		if on {
			chosen++
		}
	}
	if chosen > 1 {
		return nil, fmt.Errorf("--params, --testnet and --devnet are mutually exclusive")
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return params.Parse(raw)
	}
	name := "mainnet"
	switch {
	case testnet:
		name = "testnet"
	case devnet:
		name = "devnet"
	}
	raw, err := spec.RawFor(name)
	if err != nil {
		return nil, err
	}
	return params.Parse(raw)
}

// parsePayout requires a persistent (0x02) address, not merely a user one.
//
// A mining payout is paid over and over — every block this node produces, plus
// whatever is already sitting in the COINBASE_MATURITY-block maturity ring at
// the moment the operator first spends from it — so it is exactly the case
// docs/WALLET.md rule 3 names: "for anything that will be paid more than once
// ... use a persistent (0x02) address." A one-shot (0x01) address works fine
// right up until the operator spends from it once; from that block on,
// rollCoinbaseRing's IsSpent check burns every subsequent reward. F12 rolls
// the ring after the block's certificates land, so the burn starts in the very
// block that spends the address — measured on a devnet: the spend block itself
// reports matured=0 with burned= absorbing the whole producer share on top of
// whatever that block's own fees put there, and every block after it the same.
// Nothing errors. The only trace is the producing node's own block line, where
// "matured=0" is also what an ordinary empty ring slot prints and "burned="
// already aggregates base fees, skip fees, burned refunds and burst forfeiture
// — neither field is labelled as a burned coinbase. And the entry burned at
// height H belongs to the producer of H − COINBASE_MATURITY, while the line is
// printed by the producer of H: on a network with more than one miner the
// victim is usually not the node that logs it. The whitepaper calls the loss
// what it is: "a coinbase owed to an address whose holder burned it ... is a
// permanent shortfall against C rather than a debt the curve later repays"
// (§14.2).
//
// The version byte is what makes the surface structurally impossible rather
// than merely unlikely. Only a one-shot address can ever enter the spent
// registry — the whitepaper's attribution theorem rests on it (§5: "only
// one-shot cells can ever be retired, so a payee who publishes a persistent
// address presents no surface at all") — and the enforcement is one
// mechanism, worth naming precisely because it is one and not two. The
// registry is reached only through a certificate's *declared* MARK_SPENT
// writes (F7 stages them, F8 commits them), and V3 pins that declaration to
// exactly what DeriveCert produces, which emits MARK_SPENT only for a
// one-shot debit, a one-shot deposit cell, or a RETIRE target — all gated on
// 0x01. V6 by itself would not do it: it admits MARK_SPENT on any user
// address, 0x02 included. V3 is the whole line of defence, and every
// certificate crosses it inside the fold, not merely at the mempool. So a
// 0x02 payout cell cannot be burned by anyone, including its own holder, and
// this check is the whole fix rather than a narrowing of the window.
//
// This is a hard refusal, not a warning behind a flag. Rule 3 is written as a
// plain imperative — "use a persistent (0x02) address" — over a document
// whose own preamble says these are things "a wallet must therefore prevent"
// and that "the reference CLI implements these rules. It does not merely
// document them." Unlike a payment address, a payout address is
// a long-lived, operator-chosen, restart-time configuration value. Nothing
// honest is lost: a miner who wants a fresh cell per payout can restart
// against a fresh *persistent* address and get everything the one-shot would
// have given, minus the burn and minus a permanent spent-registry entry (§4).
//
// The hex decoding is stdlib rather than the hand-rolled decoder this function
// used to call. That decoder sized its output at len(s)/2 with no even-length
// check, so a 65-character input silently dropped its last character and still
// passed the 32-byte test — while cmd/zcd's parseAddress, on encoding/hex,
// rejected it. Two binaries in one tree disagreed about what an address is;
// they no longer do. The expression is still written out here rather than
// shared — cmd/zcd holds an identical one — because the two are separate main
// packages and a package existing only to hold four lines is its own cost;
// what the hand-rolled decoder cost was a second *behaviour*, and that is what
// is gone.
func parsePayout(s string) (types.Address, error) {
	var addr types.Address
	if s == "" {
		return addr, fmt.Errorf("--payout is required when mining")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil || len(raw) != 32 {
		return addr, fmt.Errorf("--payout must be a 32-byte hex address")
	}
	copy(addr[:], raw)
	if addr[0] != crypto.AddrVersionPersistent {
		return addr, fmt.Errorf("--payout must be a persistent address (version 0x02): " +
			"a mining payout is paid every block, and a one-shot (0x01) address burns " +
			"every future reward — including whatever is already maturing — the moment " +
			"it is spent once (docs/WALLET.md rule 3)")
	}
	return addr, nil
}

// selectEngine returns the proof-of-work engine this network requires, or an
// error naming what is missing.
//
// The network declares its own work function in pow_engine, which is in the
// consensus root, so this is not configuration: a node does not get to choose
// what it verifies against. There is no flag and there will not be one.
//
// The failure this closes is quiet and total. RandomX is compiled only under
// the `randomx` build tag, so a default `make build` binary holds the
// development engine and nothing else. Pointed at mainnet, and left to fall
// back, it would accept ONE BLAKE3 PASS as proof of work for every header it
// ever saw — every forgery valid, every fork weightless, and no error anywhere.
// So there is no fallback. A binary that cannot verify a network refuses to
// start on it.
//
// The reverse is NOT symmetric and deliberately so. A randomx-tagged binary
// carries the development engine too — pow.Dev is compiled unconditionally —
// so it runs a devnet correctly and is allowed to. Refusing would buy no
// safety and would cost a second binary for anyone testing both.
func selectEngine(p *params.Params, mining bool) (pow.Engine, error) {
	var (
		e   pow.Engine
		err error
	)
	switch p.PoWEngine {
	case pow.Dev{}.Name():
		e = pow.Dev{}
	case randomx.Name:
		// FullMemory only for a miner: it is ~2 GiB and roughly an order of
		// magnitude faster per hash. A verifying node must not pay it, and
		// TestLightAndFastAgree is what says the two cannot disagree.
		e, err = randomx.New(randomx.Options{FullMemory: mining})
	case randomx.NameV2:
		// rx/2, which is what mainnet and the public testnet declare. The
		// SAME vendored library and the same binary: RANDOMX_FLAG_V2 selects
		// the function at VM creation, and the allocation sizes are identical,
		// so a v2 node costs a v1 node's memory exactly.
		//
		// V2 is set from the network's declared engine and from nothing else.
		// It changes the digest, so it is consensus rather than configuration
		// — see randomx.Options.V2 — and the check below is what makes the
		// selection visible: the engine reports the function it was built with,
		// and a v1 engine handed to a v2 network is refused by name.
		e, err = randomx.New(randomx.Options{FullMemory: mining, V2: true})
	default:
		return nil, fmt.Errorf(
			"this build has no engine for pow_engine %q, which %s requires",
			p.PoWEngine, p.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s requires the %s engine: %w", p.Name, p.PoWEngine, err)
	}

	// Defence in depth against a wiring mistake rather than against an
	// attacker: the switch above already refuses an engine this binary lacks,
	// and this refuses one that answers to the wrong name — a case a future
	// engine added to the switch could introduce silently.
	if e.Name() != p.PoWEngine {
		return nil, fmt.Errorf(
			"engine %q was selected for a network requiring %q", e.Name(), p.PoWEngine)
	}
	return e, nil
}

// bootstrapList merges --peers, --peers-file and the network's built-in seeds.
//
// **This binary now ships a seed list, and that reverses a decision the tree
// used to state here.** What stood in this comment was: a file, and never a
// list compiled into the binary, because a baked-in list is one nobody can
// change when an entry goes bad and — for a pseudonymous project — a map of
// whoever compiled it. Both halves of that were and remain true; what changed
// is the weight on the other side. A network nobody can join without first
// finding an address out of band is a network with no honest newcomers, and
// "copy this address from the announcement into a flag" is the step at which
// they are lost. The launch this exists for invites people to download a
// binary and run it, and that is not a thing a person does with a seed list
// they must assemble themselves.
//
// The two objections are answered rather than dismissed, and neither is
// answered by this function alone:
//
//   - **Changeable.** seedsFor names hosts, not addresses. The address behind a
//     name is DNS and moves without a release; node/p2p resolves names on every
//     start and expands each to at most maxBootstrapAddrs targets. A bad entry
//     is repaired in a zone file rather than in a binary somebody already
//     downloaded.
//   - **Refusable.** --no-seeds drops the built-in list entirely, --peers and
//     --peers-file still work with or without it, and the addresses actually
//     used are logged at startup. An operator who wants nothing to do with the
//     project's own infrastructure spends one flag, and can see that it worked.
//
// What is NOT answered is the deanonymisation half: a seed on infrastructure
// the project registered is infrastructure the project registered, and no flag
// on a user's machine changes that. docs/RELEASE.md §4 carries that as a
// standing risk with the launch seed named as the exception it is, rather than
// as a rule this quietly stopped following.
//
// All three sources are merged rather than one overriding the others, so an
// operator can add a peer of their own without transcribing anything, and the
// operator's own entries come first: they are the ones chosen for this node.
//
// Duplicates are dropped. The same address reachable twice is not two dial
// targets, and node/p2p budgets outbound connections by count. Dedup is by
// exact string, so a name and an address that resolve to the same host survive
// as two entries here and collapse later, in node/p2p, if they ever do.
func bootstrapList(flagPeers, path string, seeds []string) ([]string, error) {
	out := splitPeers(flagPeers)
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("--peers-file: %w", err)
		}
		// The file is taken as the operator's tooling wrote it, which on Windows
		// means a leading UTF-8 byte order mark and CRLF line endings: PowerShell's
		// `Set-Content -Encoding utf8` writes both, and neither is visible in an
		// editor. Measured: "\xef\xbb\xbf# the public testnet
		// seeds\r\nseed-a.example:9421\r\n" coming back out of here as ["\ufeff",
		// "seed-a.example:9421\r"] with err == nil. The mark rode in on a COMMENT
		// line and became an entry of its own once the comment was cut away, and
		// every address kept its CR, so net.SplitHostPort read the port as "9421\r"
		// and each dial died at `lookup tcp/9421: unknown port` — permanently
		// undiallable, with no error and no log line. The mark is stripped here,
		// once, because only the first line of a file carries one; trimSpaces strips
		// the CR from each line below. docs/TESTNET.md tells operators to join with
		// --peers-file peers.txt, and the maintainer's own CI runs a windows job, so
		// this is the path a new operator is most likely to take.
		body := strings.TrimPrefix(string(raw), "\ufeff")

		found := 0
		for _, line := range strings.Split(body, "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if addr := trimSpaces(line); addr != "" {
				out = append(out, addr)
				found++
			}
		}
		// A file that is readable and names no address is refused for the
		// same reason an unreadable one is (docs/RUNNING.md): the operator
		// pointed at a file to get seeds and got none, and the two cases
		// reach the identical end state — a node that comes up peerless and
		// says nothing, which looks exactly like a network with nobody on it.
		// An interrupted download or a `Set-Content` handed an empty variable
		// leaves a zero-byte file rather than an absent one, so this is the
		// likelier of the two accidents, not the exotic one. Refusing costs
		// an operator who genuinely wants no seed list exactly one thing:
		// omitting the flag, which is what "I have no seed file" spells.
		if found == 0 {
			return nil, fmt.Errorf("--peers-file %s: readable but names no address — "+
				"every line is blank or a comment. Starting anyway would leave this node "+
				"with only whatever --peers gave it and no sign that the list it was "+
				"pointed at was empty", path)
		}
	}
	// Last, so that an address this operator named is dialled before one the
	// release chose for them. Order is preserved through the dedup below and
	// node/p2p adds them to the store in this order.
	out = append(out, seeds...)

	seen := make(map[string]bool, len(out))
	uniq := out[:0]
	for _, a := range out {
		if seen[a] {
			continue
		}
		seen[a] = true
		uniq = append(uniq, a)
	}
	return uniq, nil
}

// seedsFor returns the addresses a node joins this network from when the
// operator names none.
//
// It mirrors checkpointsFor exactly, including the rule that matters most: a
// parameter file passed with --params gets NO seeds. That is not caution, it is
// the only correct answer — an operator running their own network from their
// own parameter file is on a network this release knows nothing about, and
// handing them the public testnet's seeds would have their node dial strangers
// who will refuse it at the handshake (ErrWrongNetwork) and score it down for
// trying.
//
// The same reasoning empties the other two:
//
//   - **devnet** is the throwaway local network, respun many times a day. It
//     has no public participants by construction and a node that reached out to
//     one would be leaking a developer's existence for nothing.
//   - **mainnet** has not launched. There is no address to name, and naming one
//     before it exists is how a release ships a seed that never answers.
//
// So exactly one network has a seed today, and adding the next one is adding a
// line here. The entries are HOST NAMES rather than addresses, which is what
// makes the list repairable without a release — see bootstrapList.
func seedsFor(path string, devnet, testnet, none bool) []string {
	if none || path != "" || devnet {
		return nil
	}
	if testnet {
		return []string{testnetSeed}
	}
	return nil
}

// testnetSeed is the public testnet's launch seed: the node that exists so that
// somebody who has just downloaded a binary has somewhere to start.
//
// A name and not an address, deliberately, and the p2p port is not the web one:
// the same host serves the site and the explorer over TLS on 443, and this is
// the peer-to-peer listener beside them. What a joining node does with this is
// resolve it once at startup, bounded to maxBootstrapAddrs targets, and put the
// results in its own peer store; from then on peer exchange carries the network
// and this address matters again only on a cold start.
//
// **One seed is a single point of failure and is not meant to stay one.** It is
// what a first day looks like, not a design: the network's own peer exchange is
// what removes the dependency, and a second seed on infrastructure somebody
// else operates is the thing that removes it properly. docs/TESTNET.md says so
// where an operator will read it.
const testnetSeed = "testnet.zycord.com:9421"

// splitPeers parses a bootstrap list separated by commas or by line breaks.
//
// A line break separates because a --peers value routinely arrives carrying
// one and nothing downstream can recover from it: a script that writes the
// list across two lines inside one pair of quotes, or any shell expansion of a
// file. On ',' alone such a value arrives as ONE token holding an internal
// CRLF that trimSpaces cannot reach — it only touches the ends — and
// bootstrapList returns it with err == nil: one permanently undiallable
// bootstrap entry, no error and no log line, which is the end state this whole
// family of trims exists to prevent.
//
// It does NOT make --peers a way to pass a file, and the documents must not
// say it does. Comment stripping and the BOM strip live in bootstrapList's
// file branch, not here, so a peers.txt expanded into --peers contributes its
// own `#` header as an address: measured, the file docs/TESTNET.md defines
// yields "U+FEFF # the public testnet seeds" as a bootstrap entry, silently.
// Splitting on the line break narrows that failure to a wrong entry from a
// wrong invocation; --peers-file is what removes it.
//
// Splitting on "\n" mirrors bootstrapList's split over a file's body and
// leaves the CR of each CRLF pair to trimSpaces exactly as that loop does.
// Nothing legitimate is lost: a line break cannot occur inside a host:port.
func splitPeers(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' || s[i] == '\n' {
			if addr := trimSpaces(s[start:i]); addr != "" {
				out = append(out, addr)
			}
			start = i + 1
		}
	}
	return out
}

// trimSpaces strips the invisible bytes an operator's tooling attaches to an
// address: spaces and tabs from hand-editing, CR and LF from a file written on
// Windows.
//
// The CR is the one that costs a node its peers, and it arrives on the
// trailing edge: both callers cut their input on "\n", which leaves the CR of
// every CRLF pair sitting on the end of the token. An address that differs
// from a good one by a trailing CR is not a typo anybody can see —
// net.SplitHostPort hands the resolver a port of "9421\r" and the dial fails
// with `lookup tcp/9421: unknown port`, forever.
//
// The head of the token is stripped for the same four bytes. A leading space
// is no hypothetical: splitPeers hands one over for the second token of every
// "a, b" and the file loop for every indented line. A CR on the head, and an
// LF at either end, are stripped not because a caller is known to hand one
// over — both split on "\n" first, so today neither does — but because this is
// the single place either caller cleans a token: whatever reaches it has to
// leave as an address net.Dial can use or as nothing at all, never as a
// near-miss. Taking the CR and leaving the LF, or cleaning one end and not the
// other, would leave an address broken in precisely the way an untrimmed CR
// breaks it: silently, while looking handled.
func trimSpaces(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' ||
		s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "zycordd:", err)
	os.Exit(1)
}
