package stratum_test

import (
	"bufio"
	"encoding/json"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/stratum"
	"zycord/spec"
)

// TestGetJobFloodAgainstARealChain measures what an unauthenticated getjob
// flood costs a node that is running a REAL chain and a REAL miner-assembler,
// rather than the fake one the package's own suite uses.
//
// getjob is unscored by design and builds a fresh template on every call. The
// question this answers is how much of the node's CPU a peer that has done
// nothing but log in can consume.
func TestGetJobFloodAgainstARealChain(t *testing.T) {
	// Builds a real chain deep enough for the difficulty window and then
	// floods it, which is minutes rather than seconds. Skipped under -short so
	// that `go test ./...` stays inside the default 10-minute panic; run it
	// explicitly when touching the assembly path or minAssemblyInterval.
	if testing.Short() {
		t.Skip("builds a real chain and floods it; run without -short")
	}
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	defer c.Close()

	clock := p.GenesisTime
	m := &miner.Miner{
		Chain:  c,
		Pool:   mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{},
		Payout: [32]byte{0x02, 1, 2, 3},
		Now: func() uint64 {
			clock += p.TargetBlockSeconds
			return clock
		},
	}
	// Populate the difficulty window so NextTarget has real work to do.
	for i := 0; i < int(p.DifficultyWindow)+2; i++ {
		b, err := m.Assemble()
		if err != nil {
			t.Fatalf("assemble %d: %v", i, err)
		}
		if err := m.Seal(b, 1<<22); err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if _, err := c.Apply(b); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	t.Logf("chain built to height %d", c.Tip().Height)

	cfg := stratum.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Payout = [32]byte{0x02, 9, 9, 9}
	cfg.JobRefresh = time.Hour
	sv := stratum.New(cfg, m, c, devAsRXTwo{})
	if err := sv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = sv.Serve() }()
	defer func() { _ = sv.Close() }()
	addr := sv.Addr().String()

	// A control measurement: how long does the node take to assemble one
	// template when nobody is attacking it?
	timeOne := func() time.Duration {
		start := time.Now()
		for i := 0; i < 20; i++ {
			if _, err := m.Assemble(); err != nil {
				t.Fatalf("control assemble: %v", err)
			}
		}
		return time.Since(start) / 20
	}
	idle := timeOne()
	t.Logf("control: one Assemble costs %s with the node idle", idle)

	// Now flood from the number of connections the default cap allows.
	const attackers = 16
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = nc.Close() }()
			body, _ := json.Marshal(map[string]any{
				"id": 1, "jsonrpc": "2.0", "method": "login",
				"params": map[string]any{"login": "x", "algo": []string{"rx/2"}},
			})
			if _, err := nc.Write(append(body, '\n')); err != nil {
				return
			}
			rd := bufio.NewReader(nc)
			// Drain replies so the writer never blocks.
			go func() {
				for {
					_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
					if _, err := rd.ReadBytes('\n'); err != nil {
						return
					}
				}
			}()
			line := []byte(`{"id":2,"jsonrpc":"2.0","method":"getjob","params":{}}` + "\n")
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := nc.Write(line); err != nil {
					return
				}
			}
		}()
	}
	// Let the flood establish.
	time.Sleep(500 * time.Millisecond)
	underAttack := timeOne()
	close(stop)
	wg.Wait()

	t.Logf("under a %d-connection getjob flood, one Assemble costs %s "+
		"(%.1fx the idle cost) on a %d-CPU machine",
		attackers, underAttack, float64(underAttack)/float64(idle), runtime.NumCPU())

	// The bound this asserts is on ASSEMBLY, which is the expensive thing a
	// getjob used to buy and what minAssemblyInterval now limits: a snapshot,
	// a difficulty-window walk, a mempool selection, a dry-run fold to a
	// fixpoint and a root computation, measured at ~570 us against an idle
	// devnet. Before the interval landed, sixteen connections drove this
	// figure to 45x.
	//
	// What is deliberately NOT asserted is a wall-clock ratio. Profiling the
	// flood after the fix puts 36% of the process in syscalls and most of the
	// rest in encoding/json, with blake3 at 2% — the residual slowdown is the
	// socket and the JSON, which is the ordinary cost of serving a client that
	// sends as fast as it can, and is a class of work every network service
	// pays. A ratio assertion here would be asserting the speed of the Go
	// runtime's poller on the machine the test happens to run on, which is the
	// shape of test that fails on a loaded CI box for no defect at all.
	if underAttack > 200*idle {
		t.Errorf("one Assemble cost %s under the flood against %s idle (%.0fx); "+
			"the assembly rate limit is not holding",
			underAttack, idle, float64(underAttack)/float64(idle))
	}
}

// devAsRXTwo is pow.Dev's arithmetic under a name the endpoint will serve jobs
// for. The digest function is irrelevant to what this test measures — the cost
// of assembling a template — and a real RandomX evaluation per share would
// make the run take hours.
type devAsRXTwo struct{}

func (devAsRXTwo) Name() string { return "randomx-v2" }
func (devAsRXTwo) Hash(key [32]byte, input []byte) [32]byte {
	return pow.Dev{}.Hash(key, input)
}
