//go:build randomx

package randomx

import (
	"encoding/hex"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
)

// The work function is the one consensus rule no golden vector can carry.
// spec/README says so and says why: a vector is a statement about the fold, and
// the fold never evaluates work. So this file is where an implementation of the
// work function is measured, and it has to carry the weight the corpus cannot.
//
// Three axes, and each catches a different class of wrong:
//
//   - the published vectors catch a pipeline that is wrong end to end;
//   - JIT against interpreter catches generated machine code that disagrees
//     with the reference semantics. Measured, not assumed: reverting upstream's
//     ISUB_R fix in upstream/jit_compiler_a64.cpp fails this test, fails the
//     published vectors, and fails TestTheISUBREdgeCase on the JIT side while
//     the interpreter side passes — which is the exact signature of a chain
//     split by CPU architecture;
//   - light against fast catches a dataset path that disagrees with the cache
//     path, which would split miners from verifiers.

// A WARNING FOR ANYONE MUTATING THE VENDORED C++ TO CHECK ONE OF THESE TESTS.
// Go's build cache hashes the files in the package directory and does not see
// into upstream/, so editing the C++ there rebuilds NOTHING and every test
// below silently measures the previous contents. `-count=1` does not help: it
// disables result caching, not build caching. Touch a package file — any shim
// will do — in the same edit, or re-run vendor.sh. Every mutation result
// quoted in this file was taken that way, after four earlier ones were taken
// without it and reported a deliberately broken code generator as correct.
// TestVendoredTreeMatchesPinned in pinned_test.go is the standing guard.

func mustEngine(t *testing.T, o Options) *Engine {
	t.Helper()
	e, err := New(o)
	if err != nil {
		t.Fatalf("New(%+v): %v", o, err)
	}
	t.Cleanup(func() {
		if c, ok := e.(io.Closer); ok {
			_ = c.Close()
		}
	})
	return e.(*Engine)
}

// officialVectors are tevador/RandomX's own, from src/tests/tests.cpp at the
// tag PINNED names. Reproduced rather than linked because the upstream test
// programs have their own mains and are not vendored.
var officialVectors = []struct{ key, input, want string }{
	{"test key 000", "This is a test",
		"639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"},
	{"test key 000", "Lorem ipsum dolor sit amet",
		"300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969"},
	{"test key 000", "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
		"c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"},
	{"test key 001", "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
		"e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc"},
}

// TestOfficialVectors is the anchor. If this passes, this build computes the
// same function every other RandomX implementation computes; if it fails,
// nothing else in this file is worth reading.
func TestOfficialVectors(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 2})
	for _, v := range officialVectors {
		sum := e.hashRaw(v.key, []byte(v.input))
		got := hex.EncodeToString(sum[:])
		if got != v.want {
			t.Errorf("key %q input %q:\n got  %s\n want %s", v.key, v.input, got, v.want)
		}
	}
}

// TestJITAgreesWithInterpreter cross-checks the generated machine code against
// the path that generates none, over inputs chosen to sweep rather than to
// spot-check: the JIT compiles a program derived from the input, so different
// inputs compile different instruction mixes, and a bug in one opcode's
// codegen shows up only on the inputs that reach it.
func TestJITAgreesWithInterpreter(t *testing.T) {
	if testing.Short() {
		t.Skip("interpreted RandomX is ~an order of magnitude slower; skipped under -short")
	}
	jit := mustEngine(t, Options{Keys: 1, MaxVMs: 1})
	ref := mustEngine(t, Options{Keys: 1, MaxVMs: 1, Interpreted: true})

	var key types.Hash
	copy(key[:], "zycord jit cross-check")
	for i := 0; i < 32; i++ {
		in := []byte{byte(i), byte(i >> 8), 0xa5, 0x5a}
		if a, b := jit.Hash(key, in), ref.Hash(key, in); a != b {
			t.Fatalf("input %x: JIT %x, interpreter %x — the generated code and the "+
				"reference semantics disagree, which is a chain split by CPU", in, a, b)
		}
	}
}

// TestTheISUBREdgeCase pins the one input upstream found that trips the
// ARM64 and RISC-V JIT bug fixed in v1.2.2.
//
// When `src == dst` and `imm == 0x80000000`, negating the immediate overflows a
// signed 32-bit value, and the old ARM64 and RISC-V code generators emitted the
// wrong instruction. An ARM machine then computed a DIFFERENT HASH from an x86
// one for the same header: not a slow node or a rejected block, but a chain
// split along CPU architecture, invisible until two populations exist.
//
// The (key, input) pair is upstream's own, from tests.cpp at the pinned tag.
// Finding it took a deliberate search, and the value of a vector is that
// nobody has to repeat one.
//
// Mutation-checked on arm64, and the result is worth recording precisely
// because it is not what was predicted. Reverting the fix fails this test on
// the JIT side and passes it on the interpreter side, which is the signature
// to recognise. It ALSO fails TestOfficialVectors and
// TestJITAgreesWithInterpreter — so on this machine the pre-fix code generator
// is broken far more broadly than the narrow `imm == 0x80000000` framing
// suggests. This test is still worth its own existence: it is the one that
// names the bug, splits JIT from interpreter, and fails with a message a
// reader can act on.
func TestTheISUBREdgeCase(t *testing.T) {
	// THE KEY IS 31 BYTES, NOT 32, AND THIS COST AN HOUR. Upstream's harness
	// takes its key as `const char (&key)[N]` and calls
	// `randomx_init_cache(cache, key, N - 1)` — the minus one drops the NUL of
	// a string literal like "test key 000". This vector's key is not a string
	// literal, it is a `char[32]` of raw bytes, so the same helper silently
	// keys the cache with the first THIRTY-ONE of them and the trailing 0x24
	// never reaches RandomX. Passing all 32 produces a perfectly stable,
	// perfectly wrong digest that both the JIT and the interpreter agree on,
	// which is what makes the mistake so easy to keep.
	key := string([]byte{
		0x77, 0x97, 0x37, 0x3e, 0xa4, 0x63, 0x31, 0x94, 0x64, 0x0b, 0xf8, 0xd8,
		0xc3, 0xb6, 0x67, 0x24, 0xd6, 0xaa, 0x7b, 0xd2, 0xdc, 0x20, 0xe0, 0x09,
		0xdf, 0x2f, 0x8f, 0x17, 0x10, 0xab, 0xe8, // 0x24 is dropped by N-1
	})
	in, err := hex.DecodeString(
		"1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e1f68" +
			"21fed84dae58d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6514d906" +
			"89721c4aac5a9bb0d")
	if err != nil {
		t.Fatal(err)
	}
	const want = "78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8"

	// Both paths, because the bug was in one of them and a test that ran only
	// the JIT would report the wrong answer confidently.
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"jit", Options{Keys: 1, MaxVMs: 1}},
		{"interpreter", Options{Keys: 1, MaxVMs: 1, Interpreted: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := mustEngine(t, tc.opts).hashRaw(key, in)
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Fatalf("ISUB_R edge case:\n got  %s\n want %s\n"+
					"this build computes a different hash from every other RandomX "+
					"implementation for this input, which is a chain split by CPU "+
					"architecture", got, want)
			}
		})
	}
}

// TestSoftAESAgreesWithHardAES: the AES path is selected from what the CPU
// reports, so on a heterogeneous network both paths are live at once and a
// disagreement between them splits the chain the same way.
func TestSoftAESAgreesWithHardAES(t *testing.T) {
	if testing.Short() {
		t.Skip("soft AES is slow; skipped under -short")
	}
	hard := mustEngine(t, Options{Keys: 1, MaxVMs: 1})
	soft := mustEngine(t, Options{Keys: 1, MaxVMs: 1, SoftAES: true})

	var key types.Hash
	copy(key[:], "zycord aes cross-check")
	for i := 0; i < 8; i++ {
		in := []byte{byte(i), 0x11}
		if a, b := hard.Hash(key, in), soft.Hash(key, in); a != b {
			t.Fatalf("input %x: hardware AES %x, software AES %x", in, a, b)
		}
	}
}

// fastEngine builds a mining engine, or skips: the ~2 GiB dataset is not a
// cost every `go test` should pay, and a machine that cannot allocate it can
// still verify, which is the whole point of the split.
func fastEngine(t *testing.T, o Options) *Engine {
	t.Helper()
	if testing.Short() {
		t.Skip("fast mode allocates ~2 GiB; skipped under -short")
	}
	o.FullMemory = true
	e, err := New(o)
	if err != nil {
		t.Skipf("fast mode unavailable on this machine: %v", err)
	}
	t.Cleanup(func() { _ = e.(*Engine).Close() })
	return e.(*Engine)
}

// boundKey reports which key the dataset currently holds, under the lock that
// guards it, so the race detector has nothing to say about these tests.
func boundKey(e *Engine) string {
	e.fmu.RLock()
	defer e.fmu.RUnlock()
	return e.fastKey
}

// waitForPrefetch blocks until a prefetched key's entry exists and its build
// has finished.
func waitForPrefetch(t *testing.T, e *Engine, key types.Hash) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		var ready bool
		for _, k := range e.keys {
			if k.key == string(key[:]) {
				select {
				case <-k.ready:
					ready = true
				default:
				}
			}
		}
		e.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the prefetch of %x never landed", key[:8])
}

// TestLightAndFastAgree is the miner-versus-verifier check. Fast mode builds
// the ~2 GiB dataset and is what a miner runs; light mode holds only the cache
// and is what everyone else runs. A disagreement would mean miners producing
// blocks verifiers reject, which is indistinguishable from a network partition
// and would take a long time to diagnose.
//
// Kept out of -short because allocating and filling the dataset takes seconds
// and 2 GiB, which is not a cost every `go test` should pay.
//
// The MineOn call is what makes it a test of fast mode at all. The dataset
// serves ONE key — the one the local miner announced — and every other key is
// served light; without the announcement this engine would answer from a
// cache and the test would be comparing light with light, which passes
// forever and measures nothing. The assertion below is there to say so.
func TestLightAndFastAgree(t *testing.T) {
	light := mustEngine(t, Options{Keys: 1, MaxVMs: 1})
	fast := fastEngine(t, Options{Keys: 1, MaxVMs: 1})

	var key types.Hash
	copy(key[:], "zycord light vs fast")
	fast.MineOn(key)
	if boundKey(fast) != string(key[:]) {
		t.Fatal("the dataset is not bound to the key under test, so both sides of " +
			"this comparison are the light path and it can no longer fail")
	}

	for i := 0; i < 4; i++ {
		in := []byte{byte(i), 0x77}
		if a, b := light.Hash(key, in), fast.Hash(key, in); a != b {
			t.Fatalf("input %x: light %x, fast %x — miners and verifiers would "+
				"disagree about every block", in, a, b)
		}
	}
}

// TestPrefetchDoesNotDisturbTheMiningKey is the prefetch/mining-key collision
// at the engine, in the six lines the incident reduces to.
//
// What the node did: a mining node crossed height randomx_key_lag, the
// once-a-minute prefetch loop asked for the next epoch's key, and from that
// tick on every block it sealed was valid under THAT key and invalid under the
// one its own height selects. It applied them, announced them and built on
// them — 1112 blocks on the public testnet, heights 70 through 1181 — while
// every other node rejected the chain at the first of them and no node that
// tried to sync could ever join.
//
// What the engine did: build() filled the single shared dataset for whichever
// key it was initialising, and every VM in the key table had been created with
// FULL_MEM, so they all read that one buffer. Warming a second key repointed
// the first key's hashing at it. Nothing lied about the key — the miner passed
// the right one in and the rule passed the right one in — the engine simply
// answered from the wrong data.
//
// The assertion is against a LIGHT engine's answer rather than against this
// engine's earlier answer, because "the network's answer" is the property that
// matters; an engine that drifted consistently would satisfy the weaker form.
func TestPrefetchDoesNotDisturbTheMiningKey(t *testing.T) {
	fast := fastEngine(t, Options{Keys: 2, MaxVMs: 2})
	light := mustEngine(t, Options{Keys: 2, MaxVMs: 1})

	var mining, next types.Hash
	copy(mining[:], "epoch n, the key this height selects")
	copy(next[:], "epoch n plus one, an epoch away")
	in := []byte("a header's proof-of-work input")

	fast.MineOn(mining)
	want := light.Hash(mining, in)
	if got := fast.Hash(mining, in); got != want {
		t.Fatalf("before any prefetch the miner already disagrees with the network: "+
			"%x against %x", got[:8], want[:8])
	}

	// Exactly what prefetchLoop does at a boundary, and what it used to do
	// 2048 blocks early.
	fast.Prefetch(next)
	waitForPrefetch(t, fast, next)

	if got := fast.Hash(mining, in); got != want {
		t.Fatalf("after warming the next epoch's key, the mining key hashes to %x "+
			"and the network computes %x for the same header: every block this "+
			"node seals from here is valid under a key its height does not "+
			"select, and every peer rejects it", got[:8], want[:8])
	}
	if k := boundKey(fast); k != string(mining[:]) {
		// %x of the whole string, not k[:8]: the value under test may be the
		// empty string, and slicing it in the failure path would panic and
		// hide the failure it was reporting.
		t.Fatalf("a prefetch moved the dataset off the mining key (bound to %x)", k)
	}
}

// TestVerifyingAnotherEpochDoesNotDisturbTheMiningKey drives the other route to
// the same defect, and it is the one no prefetch schedule can avoid.
//
// The gossip path, the sync driver and the miner share ONE engine. At every key
// boundary a mining node verifies headers from the epoch it is not mining —
// and a node syncing a range from an old epoch while mining on the tip does it
// for thousands of headers. That is an ordinary, honest, unavoidable second
// key, and before the fix it repointed the miner's hashing exactly as a
// prefetch did.
//
// Both directions are asserted: the miner keeps answering for its own key, and
// the other epoch is verified correctly rather than being answered from the
// miner's dataset.
func TestVerifyingAnotherEpochDoesNotDisturbTheMiningKey(t *testing.T) {
	fast := fastEngine(t, Options{Keys: 2, MaxVMs: 2})
	light := mustEngine(t, Options{Keys: 2, MaxVMs: 1})

	var mining, peers types.Hash
	copy(mining[:], "the epoch being mined")
	copy(peers[:], "the epoch a peer is serving")
	in := []byte("a header's proof-of-work input")

	fast.MineOn(mining)
	wantMining, wantPeers := light.Hash(mining, in), light.Hash(peers, in)

	if got := fast.Hash(peers, in); got != wantPeers {
		t.Fatalf("verifying another epoch's header gives %x, the network computes "+
			"%x: a mining node would reject the chain everyone else accepts",
			got[:8], wantPeers[:8])
	}
	if got := fast.Hash(mining, in); got != wantMining {
		t.Fatalf("verifying one header from another epoch moved the mining key's "+
			"answer to %x, against the network's %x", got[:8], wantMining[:8])
	}
	if k := boundKey(fast); k != string(mining[:]) {
		t.Fatal("verification took the dataset off the mining key; a miner would " +
			"rebuild ~2 GiB every time a peer sent a header from another epoch")
	}
}

// TestARebuildDoesNotStopANodeVerifying is I7-M2's property, re-taken for the
// path that actually rebuilds the ~2 GiB dataset.
//
// I7-M2 was measured on a devnet: ordinary blocks every 0.3–1 s, and every
// key boundary 8–11 s of a node verifying nothing, because the rebuild ran
// under the engine lock. That was fixed for the cache. The dataset kept a
// version of it, and holding the dataset in the key table made the miner's
// copy worse than a stall — the VMs went on hashing off a buffer being
// overwritten, so what a node computed during the window was not late, it was
// wrong.
//
// The property: while the dataset is being refilled for a new key, hashing on
// ANOTHER key keeps making progress. It is a count rather than the ratio
// TestANewKeyDoesNotStallTheOldOne uses, and deliberately: a dataset fill runs
// one goroutine per core by design, so the verifier genuinely loses most of
// the machine and a rate comparison would be measuring the scheduler. What
// cannot happen is a STOP.
//
// The bar is five hashes, not one. The verifier is started before the fill, so
// exactly one hash can be in flight when the writer arrives — which is the
// hole the first version of I7-M2's test fell through, where "> 0" passed
// against the locked implementation on the strength of that one hash.
func TestARebuildDoesNotStopANodeVerifying(t *testing.T) {
	fast := fastEngine(t, Options{Keys: 3, MaxVMs: 2})

	var mining, peers, next types.Hash
	copy(mining[:], "the epoch being mined")
	copy(peers[:], "the epoch a peer is serving")
	copy(next[:], "the epoch above the boundary")

	// The first fill, so the one measured below is a REBUILD, which is the
	// event a key boundary produces.
	fast.MineOn(mining)
	fast.Hash(peers, []byte("warm")) // the verifier's cache exists

	var progressed atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			fast.Hash(peers, []byte{byte(i), byte(i >> 8)})
			progressed.Add(1)
		}
	}()

	// Control, with nothing competing: a rate to report rather than a bar to
	// clear.
	time.Sleep(200 * time.Millisecond)
	c0 := progressed.Load()
	time.Sleep(time.Second)
	controlRate := float64(progressed.Load() - c0)

	before := progressed.Load()
	start := time.Now()
	fast.MineOn(next)
	fill := time.Since(start)
	during := progressed.Load() - before

	close(stop)
	wg.Wait()

	if k := boundKey(fast); k != string(next[:]) {
		t.Fatalf("the rebuild did not land: the dataset is bound to %x", k)
	}
	if during < 5 {
		t.Fatalf("a %v dataset rebuild let %d hashes on another key through "+
			"(%.0f/s with nothing competing): a mining node stops verifying at "+
			"every key boundary, which is I7-M2 arriving through the dataset",
			fill, during, controlRate)
	}
	t.Logf("%d hashes during a %v rebuild, %.0f/s idle", during, fill, controlRate)
}

// TestTheDatasetFollowsTheMiner is the boundary crossing itself: the miner
// moves to the next epoch, the dataset moves with it, and both keys keep
// answering what the network answers throughout.
//
// It is the anti-vacuity partner of the two tests above. A dataset that never
// moved would pass both of them and would leave a miner hashing at light speed
// — roughly a twentieth of what its machine can do — from its first key
// boundary onward, forever.
func TestTheDatasetFollowsTheMiner(t *testing.T) {
	fast := fastEngine(t, Options{Keys: 2, MaxVMs: 2})
	light := mustEngine(t, Options{Keys: 2, MaxVMs: 1})

	var before, after types.Hash
	copy(before[:], "the epoch below the boundary")
	copy(after[:], "the epoch above the boundary")
	in := []byte("a header's proof-of-work input")

	for _, key := range []types.Hash{before, after, before} {
		fast.MineOn(key)
		if k := boundKey(fast); k != string(key[:]) {
			t.Fatalf("MineOn(%x) left the dataset bound to %x", key[:8], k)
		}
		if got, want := fast.Hash(key, in), light.Hash(key, in); got != want {
			t.Fatalf("after moving the dataset to %x it hashes to %x, the network "+
				"computes %x", key[:8], got[:8], want[:8])
		}
		// And the key it just left is still answered correctly, out of the key
		// table, which is what a reorg across a boundary needs.
		other := before
		if key == before {
			other = after
		}
		if got, want := fast.Hash(other, in), light.Hash(other, in); got != want {
			t.Fatalf("the key the dataset does not hold hashes to %x, the network "+
				"computes %x", got[:8], want[:8])
		}
	}
}

// TestAFillSurvivesTheThreadThatCreatedTheVMs is I7-H5, made deterministic.
//
// On macOS RandomX allocates its code buffers with MAP_JIT, where W^X is
// pthread_jit_write_protect_np — a PER-THREAD mode, not a page permission.
// upstream's allocMemoryPages ends by putting the calling thread into WRITE
// mode; randomx_init_dataset EXECUTES the JIT-compiled dataset-init function
// and, alone among upstream's entry points, never sets execute mode first. A
// thread left in write mode therefore cannot fill a dataset, and a Go program
// does not choose which thread does.
//
// That was first reported as a SIGBUS observed once and "deliberately not
// described as reproducible", because which OS thread a fill worker lands on is
// not something a test controls. It is reproducible, and the two things it
// needs are both here.
//
//  1. A thread this test knows is in WRITE mode. Not every upstream call leaves
//     one: randomx_init_cache ends in enableExecution, and so does
//     CompiledLightVm::setCache, so building a key-table entry leaves its
//     thread EXECUTABLE. What does not is randomx_create_vm over a dataset —
//     CompiledVm has no cache to set, so nothing follows the JitCompiler
//     constructor's allocMemoryPages. New's fast-VM loop runs HERE, on the
//     pinned thread, and that is what poisons it.
//  2. A fill that lands on that thread. initDataset runs its first share on
//     the calling goroutine, and the cache is warmed through Prefetch — on
//     another goroutine — so that MineOn below reaches the fill without
//     building anything on this thread in between.
//
// Measured on darwin/arm64, go1.26.2: with the pthread_jit_write_protect_np
// call removed from zycord_init_dataset, this test is
//
//	SIGBUS: bus error
//	PC=0x130763458 m=0 sigcode=1 addr=0x130763458
//	signal arrived during cgo execution
//	goroutine 7 ... [syscall, locked to thread]
//
// — the fault address equal to the program counter, which is an instruction
// fetch from a page this thread may not execute. With the guard it passes.
//
// It is a real test on linux/amd64 too, where it cannot fail: there is no
// MAP_JIT, the guard compiles to nothing, and the property asserted — a fill
// completes on the thread that created the virtual machines, and the engine
// then hashes what the network hashes — is the same property.
func TestAFillSurvivesTheThreadThatCreatedTheVMs(t *testing.T) {
	// The pin is the whole experiment. Without it the fill runs on whatever
	// thread the Go runtime hands out and the crash is a lottery — which is how
	// this shipped as "observed once" instead of as a test.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// randomx_alloc_dataset and MaxVMs randomx_create_vm calls, on this
	// thread, each one ending in allocMemoryPages and nothing putting it back.
	fast := fastEngine(t, Options{Keys: 1, MaxVMs: 1})
	light := mustEngine(t, Options{Keys: 1, MaxVMs: 1})

	var key types.Hash
	copy(key[:], "a fill on the thread that built the VMs")
	in := []byte("a header's proof-of-work input")

	// The cache, warmed off this thread. It is also the ordinary production
	// case — prefetchLoop warms the next epoch's cache before the boundary —
	// so what MineOn has left to do is exactly the fill.
	fast.Prefetch(key)
	waitForPrefetch(t, fast, key)

	fast.MineOn(key)

	if k := boundKey(fast); k != string(key[:]) {
		t.Fatalf("the fill did not bind the key, so nothing above was exercised "+
			"(bound to %x)", k)
	}
	if got, want := fast.Hash(key, in), light.Hash(key, in); got != want {
		t.Fatalf("the dataset filled on a JIT-write-mode thread hashes to %x, the "+
			"network computes %x", got[:8], want[:8])
	}
}

// TestConcurrentHashingIsSafe drives the engine the way the node does: the
// gossip path, the sync driver and the miner all hold the same engine, and a
// RandomX VM is not safe for concurrent use. Run under -race this is the test
// that says the VM pool is a pool and not a decoration.
func TestConcurrentHashingIsSafe(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 4})

	var key0, key1 types.Hash
	copy(key0[:], "epoch zero")
	copy(key1[:], "epoch one")

	// The expected answers, computed serially first.
	want0, want1 := e.Hash(key0, []byte("x")), e.Hash(key1, []byte("x"))

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, want := key0, want0
			if i%2 == 1 {
				key, want = key1, want1
			}
			for j := 0; j < 4; j++ {
				if got := e.Hash(key, []byte("x")); got != want {
					t.Errorf("goroutine %d: %x, want %x", i, got, want)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestEvictionDoesNotStrandABorrower is a reviewer's finding, reproduced and
// kept.
//
// keyedFor hands back an entry and the caller borrows a VM from it afterwards.
// Between those two moments another goroutine could evict that entry, and the
// eviction path of the day drained the VM channel and destroyed everything in
// it — so the borrower received from a drained, never-closed channel and
// BLOCKED FOREVER.
//
// The mechanism that had that hole is gone: refs is guarded by the engine
// lock, taken in entryFor under the same lock that removes entries, so an
// entry cannot leave the table between being found and being referenced, and
// destroy runs only for an entry that has left the table at zero references.
// The PROPERTY is what this test pins, and it outlives the mechanism.
//
// Reachable on an honest node at the production default of Keys: 2, which
// needs only three concurrent key epochs: the one being verified, the one the
// prefetcher is warming, and a third from a peer's header. And inducible on
// purpose, because a peer chooses the heights it announces and the key comes
// from the height.
//
// Why the existing concurrency test did not catch it: it used Keys: 2 with
// exactly TWO distinct keys, so eviction never ran at all. The gap was the
// third key, not the concurrency.
//
// Deterministic before the fix — the timeout fired on every attempt, with the
// eviction path blocked in its drain loop — and this is deliberately sized so
// it stays that way rather than becoming a flaky race.
func TestEvictionDoesNotStrandABorrower(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 2})

	keys := make([]types.Hash, 3)
	for i := range keys {
		copy(keys[i][:], []byte{byte('a' + i), byte(i)})
	}

	const rounds = 8
	total := rounds * len(keys)
	done := make(chan struct{}, total)
	for r := 0; r < rounds; r++ {
		for i := range keys {
			go func(k types.Hash) {
				e.Hash(k, []byte("x"))
				done <- struct{}{}
			}(keys[i])
		}
	}

	for got := 0; got < total; got++ {
		select {
		case <-done:
		case <-time.After(120 * time.Second):
			t.Fatalf("only %d of %d hashes completed: a borrower is blocked on "+
				"a VM channel that eviction destroyed out from under it", got, total)
		}
	}
}

// TestCloseWithEntriesOutstanding: Close removes every entry and MARKS it
// evicted, so an entry somebody still holds is freed by that holder's put
// exactly as an ordinary eviction is. An earlier version of Close did not mark
// them, and the waiting release of the day then blocked on a gate nothing ever
// closed — shutdown hung.
//
// What it pins today is that Close RETURNS. It does not observe the dataset:
// this engine is light (no FullMemory), so e.dset is nil and the whole
// dataset path is inert. Widening it means observing the dataset teardown under
// live borrowers, which Close's own fast-path comment describes.
func TestCloseWithEntriesOutstanding(t *testing.T) {
	e, err := New(Options{Keys: 2, MaxVMs: 1})
	if err != nil {
		t.Fatal(err)
	}
	var a, b types.Hash
	copy(a[:], "close a")
	copy(b[:], "close b")
	e.Hash(a, []byte("x"))
	e.Hash(b, []byte("x"))

	closed := make(chan error, 1)
	go func() { closed <- e.(*Engine).Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Close did not return: an entry's idle gate is never closed")
	}
}

// TestPrefetchReturnsItsReference. keyedFor hands back a reference and every
// caller owes a put; a prefetch that kept it would pin the entry forever, and
// an entry that never reaches zero references is one nothing ever destroys —
// a 256 MiB cache leaked per prefetched epoch.
// Driven by prefetching more keys than the table holds, so every one of them
// must be evictable.
func TestPrefetchReturnsItsReference(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 1})
	for i := 0; i < 5; i++ {
		var k types.Hash
		k[0] = byte(0xf0 + i)
		e.Prefetch(k)
	}
	// Force the table to turn over completely, which cannot finish if a
	// prefetched entry is pinned.
	for i := 0; i < 5; i++ {
		var k types.Hash
		k[0] = byte(0x10 + i)
		done := make(chan struct{})
		go func() { e.Hash(k, []byte("x")); close(done) }()
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			t.Fatalf("hash %d blocked: a prefetched entry was never released", i)
		}
	}

	// A healthy run reports no failed warm. The counter exists because
	// Prefetch and MineOn drop the error hashRaw panics on, so the only way a
	// reader ever learns a warm did not land is this number — and a counter
	// that quietly counted successes too would be worse than no counter.
	//
	// This is the ZERO half of the property and it is the only half this
	// package can reach: nothing here can force a 256 MiB allocation to fail.
	// Stated plainly rather than left implied — the non-zero case is
	// read-verified and never observed (I7-L4).
	if got := e.warmFailed.Load(); got != 0 {
		t.Errorf("a healthy engine counted %d failed warms; either an ordinary "+
			"prefetch is reporting failure or the counter is counting the "+
			"wrong thing", got)
	}
}

// TestTheKeyTableIsBounded: the LRU bound is what stops a chain oscillating
// across a key boundary from holding a 256 MiB cache per epoch it has ever
// seen. Asserted rather than assumed, because the failure is an out-of-memory
// kill on a laptop and not a test failure anywhere.
func TestTheKeyTableIsBounded(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 1})
	for i := 0; i < 6; i++ {
		var key types.Hash
		key[0] = byte(i)
		e.Hash(key, []byte("x"))

		e.mu.Lock()
		n := len(e.keys)
		e.mu.Unlock()
		if n > 2 {
			t.Fatalf("after %d distinct keys the table holds %d caches, bound is 2 "+
				"(%d MiB of resident cache)", i+1, n, n*256)
		}
	}
}

// TestConcurrentEpochDemandIsAdmittedKeysAtATime is the refutation of I7-H4's
// memory claim, written as a test instead of as a paragraph.
//
// # The claim being refuted
//
// A review of the invalid-header flood proposed that a queued cache build
// holds its 256 MiB while it waits, so that one identity's five headers are
// five SIMULTANEOUS allocations and an aggregate of identities is an
// out-of-memory kill on an ordinary machine. That claim is false, and it is
// false for one reason that is a single line of `build`: the `building`
// semaphore is taken BEFORE `randomx_alloc_cache`, so a caller beyond the
// bound is parked holding nothing at all.
//
// # Why a test rather than the reading
//
// The claim it refutes was itself produced by reading the same function, and
// this project's own record (I5, I7-L1, I7-L3) is that a confident reading is
// exactly what an instrument is for. The quantity is also unobservable from
// outside: the table stays bounded either way, no hash blocks either way, no
// verdict changes either way — an engine that allocated one cache per WAITING
// caller passes every other test in this file while using as much memory as
// the review said it did.
//
// # It pins TWO numbers, and the second is the one about memory
//
// **Peak concurrent allocation**, asserted EQUAL to `Keys`, in both directions
// and for two different reasons:
//
//   - more than `Keys` is the amplification I7-H4 was fixed to remove, and it
//     is what the review's claim requires: a cache per parked caller, so that
//     the exposure scales with how many peers demand epochs;
//   - fewer than `Keys` means this test never actually raced, and a bound
//     observed under no contention is not a bound that was observed.
//
// **Peak RESIDENT caches**, which is not the same number and is the one an
// operator's RSS follows. The semaphore is released when `build` returns; the
// 256 MiB it allocated lives in the table entry until that entry is destroyed,
// and an entry evicted while somebody still holds a reference keeps everything
// it has until the last `put`. So residency is `Keys` PLUS concurrent holders
// of evicted entries, and this test asserts only `>= Keys` on it — because
// the honest statement is that nothing in the engine bounds the second term,
// and asserting a ceiling here would be inventing one.
//
// Saying the first number and calling it the second is how "the semaphore is
// taken before the allocation" turns into "so memory is bounded at Keys",
// which does not follow. Two different arrangements contradict it: this one,
// where the excess is the builds still being filled, and
// TestAnEvictedEntryStillHeldKeepsItsCache, where `MineOn` holds its reference
// across `initDataset` — ten to thirty seconds at a key boundary — and two
// arriving epochs leave three resident under `Keys: 2`.
//
// **The ceiling for THIS arrangement is derived, and the measurement
// corroborates it rather than being it:** the table holds `Keys` and the gate
// admits `Keys` more, so at most `2 x Keys` — 1024 MiB at the default. The
// assertion below is one-sided at `>= Keys` on purpose, because how many of
// the admitted builds actually overlap is the scheduler's business: a
// single-core run observes three often enough to matter, and a test that
// demanded four would be reporting the runner rather than the engine.
//
// An RSS figure would pin none of it: it is machine-specific, it moves with
// the allocator, and `runtime.ReadMemStats` cannot see a C allocation at all.
// The portable version of "790 MiB on that laptop" is a count of resident
// caches, which is what this measures.
func TestConcurrentEpochDemandIsAdmittedKeysAtATime(t *testing.T) {
	const (
		keys   = 2  // the production default (Options.Keys)
		demand = 16 // goroutines, each on an epoch nothing holds — sixteen
		// because sixteen is the number I7-H4's ad-hoc probe used, and a test
		// that reproduces the probe's arrangement is what lets the entry stop
		// citing the probe.
		cacheMB = 256
	)
	e := mustEngine(t, Options{Keys: keys, MaxVMs: 1})

	// Every goroutine asks for a DIFFERENT key, and none of them is the key
	// any earlier test in this engine's life warmed: a build served from the
	// table is not a build, which is what `builds` below checks.
	var ready, start sync.WaitGroup
	ready.Add(demand)
	start.Add(1)
	var wg sync.WaitGroup
	for i := 0; i < demand; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var key types.Hash
			copy(key[:], "never-seen epoch")
			key[31] = byte(i)
			ready.Done()
			start.Wait()
			e.Hash(key, []byte("x"))
		}(i)
	}
	ready.Wait() // every demander exists before any of them is admitted
	began := time.Now()
	start.Done()
	wg.Wait()
	elapsed := time.Since(began)

	peak := e.peakBuilds.Load()
	built := e.builds.Load()
	resident := e.peakLiveCaches.Load()
	t.Logf("%d goroutines demanding %d never-seen epochs: %d builds, admitted "+
		"%d at a time, %.1f s wall. Peak RESIDENT caches %d (%d MiB) against a "+
		"table of %d — residency is the table, PLUS the builds being filled "+
		"(up to %d more), PLUS anything evicted while a borrower held it; the "+
		"build semaphore sees only the middle term",
		demand, demand, built, peak, elapsed.Seconds(),
		resident, resident*cacheMB, keys, keys)

	// Anti-vacuity FIRST, because every assertion below is vacuous without it:
	// if the table had served these from cache there would have been nothing
	// to be concurrent about.
	if built != demand {
		t.Fatalf("%d cache builds for %d distinct never-seen epochs; the demand "+
			"this test needs did not happen, so its bound was never tested",
			built, demand)
	}

	if peak > keys {
		t.Errorf("%d cache initialisations ran at once against a bound of %d "+
			"(%d MiB resident, not %d): the semaphore is no longer taken before "+
			"randomx_alloc_cache, and concurrent allocation now scales with the "+
			"number of callers — which is exactly what I7-H4 removed and what "+
			"its review claimed was still there",
			peak, keys, peak*cacheMB, keys*cacheMB)
	}
	if peak < keys {
		t.Errorf("%d goroutines demanding %d never-seen epochs never got more "+
			"than %d build(s) running at once, against a bound of %d; the bound "+
			"was not exercised, so this test observed nothing",
			demand, demand, peak, keys)
	}

	// The memory number, and the assertion is deliberately one-sided.
	//
	// At least `Keys` caches are resident by construction — the table holds
	// that many. There is no upper assertion because there is no upper bound to
	// assert: an entry evicted while a borrower holds it stays whole, and
	// nothing in this engine bounds how many borrowers there are. Writing
	// `resident <= keys` here would be this test asserting the very conflation
	// it exists to prevent, and it would fail on the reachable MineOn case
	// rather than on a bug.
	if resident < keys {
		t.Errorf("peak resident caches %d is below the table size %d, which is "+
			"not possible unless the table stopped holding what it built or "+
			"this counter stopped counting", resident, keys)
	}
	if resident > keys {
		t.Logf("NOTE: %d caches (%d MiB) resident at once under a table of %d "+
			"and a build gate of %d. Under demand like this the excess is the "+
			"builds still being FILLED — up to %d of them, since that is what "+
			"the gate admits — and under a long-lived borrower it is instead an "+
			"evicted entry nobody has put yet (TestAnEvictedEntryStillHeldKeeps"+
			"ItsCache). Either way it is why 'concurrent allocation is bounded "+
			"at Keys' is NOT a statement about resident memory",
			resident, resident*cacheMB, keys, keys, keys)
	}

	// And the residual the probe DID establish, stated where it cannot be
	// mistaken for the memory claim: the queue is real. Not asserted as a
	// duration — that is a machine's number, not a property — but the shape is
	// what testnet-measurements §2 has to characterise in aggregate, and it is
	// head-of-line delay on a Keys-wide gate.
	if demand > keys && elapsed <= 0 {
		t.Fatal("no time passed building 8 caches; the clock is not measuring this")
	}
}

// TestAnEvictedEntryStillHeldKeepsItsCache is the other half of the memory
// question, and it is the half that says the reassuring sentence is not a
// memory bound.
//
// `Engine.build` takes the `building` semaphore before `randomx_alloc_cache`,
// so CONCURRENT ALLOCATION is bounded at `Keys`
// (TestConcurrentEpochDemandIsAdmittedKeysAtATime). It is tempting to read
// that as "so at most `Keys` x 256 MiB is resident", and it does not follow:
// the semaphore is released when `build` returns and the memory it allocated
// is not. An entry leaves the table when something newer needs its slot, and
// `evictLocked` frees it only at `refs == 0` — otherwise the last `put` does.
// That is the one invariant I7-H4 was rebuilt around and it is correct. It
// also means **a borrower keeps 256 MiB alive outside the table**, and nothing
// in this engine bounds how many borrowers there are.
//
// This is not theoretical. `MineOn` holds its reference across `initDataset`,
// which this package prices at ten to thirty seconds at a key boundary, and
// two never-held epochs arriving inside that window are exactly the sequence
// below.
//
// The number it pins is 3 under `Keys: 2` — one more than the bound a reader
// would take from the semaphore, and the count that a 790 MiB RSS reading
// actually corresponds to.
func TestAnEvictedEntryStillHeldKeepsItsCache(t *testing.T) {
	const keys = 2
	e := mustEngine(t, Options{Keys: keys, MaxVMs: 1})

	// A borrower that does not let go — MineOn across the dataset fill, in the
	// only form a test can hold still.
	var pinned types.Hash
	copy(pinned[:], "the epoch a miner is filling for")
	held, err := e.keyedFor(string(pinned[:]))
	if err != nil {
		t.Fatalf("building the pinned epoch: %v", err)
	}

	// Two more epochs arrive. The table is two wide, so the pinned entry is
	// evicted to make room — while its reference is still out.
	for i := 0; i < keys; i++ {
		var key types.Hash
		copy(key[:], "an epoch a peer asked about")
		key[31] = byte(i)
		e.Hash(key, []byte("x"))
	}

	e.mu.Lock()
	inTable := len(e.keys)
	evicted := held.evicted
	e.mu.Unlock()
	resident := e.peakLiveCaches.Load()

	t.Logf("table %d entries (bound %d), pinned entry evicted=%v, peak resident "+
		"caches %d (%d MiB)", inTable, keys, evicted, resident, resident*256)

	if !evicted {
		t.Fatalf("the pinned entry is still in the table after %d newer keys, so "+
			"this test never reached the state it is about", keys)
	}
	if inTable > keys {
		t.Fatalf("the table holds %d entries against a bound of %d", inTable, keys)
	}
	if resident != keys+1 {
		t.Errorf("peak resident caches %d, expected %d: the table's %d plus the "+
			"one entry a borrower held after eviction. If this is now %d, "+
			"something frees an entry while a reference is out — which is the "+
			"deadlock I7-H4 replaced the mechanism to remove",
			resident, keys+1, keys, keys)
	}

	// **The composed case, which is the one a mining node reaches and which
	// neither this test nor its neighbour measures on its own.** A borrower
	// holding an evicted entry AND concurrent demand for unheld epochs are two
	// different terms of the same sum, and an operator sizing a machine meets
	// them together: MineOn pins a reference across the dataset fill while
	// peers keep announcing at heights this node has no epoch for.
	//
	// Logged rather than asserted at an exact value, for the reason the
	// neighbour gives: how many of the admitted builds overlap is the
	// scheduler's business. What IS asserted is the floor — the pinned entry
	// plus the table — and the derived ceiling is `2 x Keys + holders`.
	{
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var key types.Hash
				copy(key[:], "composed demand")
				key[31] = byte(i)
				e.Hash(key, []byte("x"))
			}(i)
		}
		wg.Wait()
		composed := e.peakLiveCaches.Load()
		t.Logf("composed: one pinned borrower plus eight concurrent demands — "+
			"peak resident caches %d (%d MiB), against a table of %d and a "+
			"derived ceiling of 2*Keys+holders = %d",
			composed, composed*256, keys, 2*keys+1)
		if composed < int64(keys)+1 {
			t.Errorf("composed peak %d is below the pinned entry plus the table "+
				"(%d); the borrower's entry was freed while it still held a "+
				"reference, which is the deadlock I7-H4 replaced the mechanism "+
				"to remove", composed, keys+1)
		}
	}

	// And the borrower letting go is what returns it. Without this the entry is
	// not merely resident, it is leaked — which is what `destroyed` counts.
	before := e.destroyed.Load()
	e.put(held)
	deadline := time.Now().Add(5 * time.Second)
	for e.destroyed.Load() == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.destroyed.Load() == before {
		t.Fatal("the last put did not destroy the evicted entry; its 256 MiB is leaked")
	}
	if live := e.liveCaches.Load(); live != int64(keys) {
		t.Errorf("%d caches resident after the borrower let go, expected the "+
			"table's %d", live, keys)
	}
}

// TestTheEngineNamesItself pins the string cmd/zycordd compares against
// Params.PoWEngine. A rename here without a matching parameter change is a
// binary that refuses to start on the network it was built for.
func TestTheEngineNamesItself(t *testing.T) {
	var e pow.Engine = mustEngine(t, Options{Keys: 1, MaxVMs: 1})
	if e.Name() != "randomx-v1" {
		t.Fatalf("engine names itself %q; spec/params.json says randomx-v1", e.Name())
	}
	if !Available() {
		t.Fatal("Available() is false in a build that carries the engine")
	}
}

// TestANewKeyDoesNotStallTheOldOne is the measured stall, turned into a test.
//
// On a devnet with a tiny key interval, ordinary blocks arrived every 0.3–1 s
// and EVERY key boundary took 8–11 s. The cause was not the rebuild — a
// rebuild has to happen — it was that the rebuild ran under the engine lock,
// so a node crossing a boundary stopped verifying the chain it already had.
//
// The property: while a new key is being built, hashing on an EXISTING key
// keeps making progress.
//
// **Measured as a RATIO against a control window, not as a count.** A count
// was the first version and it was too weak: holding the lock across the build
// still let ONE hash through — the one already in flight — so `> 0` passed
// against the very implementation the test exists to reject. The ratio also
// avoids an absolute latency threshold, which on a shared machine is a flaky
// test rather than a strict one.
func TestANewKeyDoesNotStallTheOldOne(t *testing.T) {
	e := mustEngine(t, Options{Keys: 3, MaxVMs: 2})

	var oldKey, newKey types.Hash
	copy(oldKey[:], "epoch n")
	copy(newKey[:], "epoch n plus one")

	e.Hash(oldKey, []byte("warm")) // the old key is live

	var progressed atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			e.Hash(oldKey, []byte{byte(i), byte(i >> 8)})
			progressed.Add(1)
		}
	}()

	// Control: how fast the reader goes with nothing competing. Long enough to
	// be a rate rather than a sample.
	time.Sleep(300 * time.Millisecond)
	c0 := progressed.Load()
	time.Sleep(500 * time.Millisecond)
	controlRate := float64(progressed.Load()-c0) / 0.5

	// The build, on this goroutine.
	b0 := progressed.Load()
	t0 := time.Now()
	e.Hash(newKey, []byte("build me"))
	buildD := time.Since(t0).Seconds()
	duringRate := float64(progressed.Load()-b0) / buildD

	close(stop)
	wg.Wait()

	if controlRate == 0 {
		t.Fatal("the reader made no progress even with nothing competing")
	}
	// A quarter of the control rate. The build genuinely competes for CPU, so
	// some slowdown is expected and correct; what is not expected is a stop.
	// Mutation-checked: holding the lock across the build reports ~1 hash for
	// the whole build and fails here.
	if ratio := duringRate / controlRate; ratio < 0.25 {
		t.Errorf("hashing on the live key ran at %.0f/s during a %.2fs key build "+
			"against %.0f/s idle (%.0f%%): the build is holding the engine "+
			"lock, and a node crossing a key boundary stops verifying the "+
			"chain it already has",
			duringRate, buildD, controlRate, ratio*100)
	} else {
		t.Logf("live key: %.0f/s during a %.2fs build, %.0f/s idle (%.0f%%)",
			duringRate, buildD, controlRate, ratio*100)
	}
}

// TestPrefetchMakesTheNextKeyFree pins what Prefetch is for. It is possible at
// all because the key comes from the height, so the next epoch's key is known
// before the boundary; under upstream's key-block schedule it would depend on
// which branch wins.
func TestPrefetchMakesTheNextKeyFree(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 1})

	var k0, k1 types.Hash
	copy(k0[:], "current epoch")
	copy(k1[:], "next epoch")
	e.Hash(k0, []byte("warm"))

	// Cold: the first use of a key pays for the build.
	cold := time.Now()
	e.Hash(k1, []byte("x"))
	coldD := time.Since(cold)

	// Warm the third key through Prefetch and wait for it to land, then time a
	// use of it. Keys is 2, so this also evicts k0 — which is the real
	// sequence a chain walking forward produces.
	var k2 types.Hash
	copy(k2[:], "epoch after next")
	e.Prefetch(k2)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		var ready bool
		for _, k := range e.keys {
			if k.key == string(k2[:]) {
				select {
				case <-k.ready:
					ready = true
				default:
				}
			}
		}
		e.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	warm := time.Now()
	e.Hash(k2, []byte("x"))
	warmD := time.Since(warm)

	if warmD > coldD/2 {
		t.Errorf("a prefetched key cost %v against %v cold; the prefetch is not "+
			"landing before the key is needed", warmD, coldD)
	}
	t.Logf("cold %v, prefetched %v", coldD, warmD)
}

// TestEvictedEntriesAreFreed is the leak check, and it has to be CONCURRENT,
// which is the whole lesson.
//
// An engine that evicts entries and never frees them passes every other test
// here: the table stays bounded, no hash blocks, no verdict changes. It also
// grows by 256 MiB per key epoch, and a node walking forward through epochs
// walks forward forever.
//
// A first version hashed the keys one at a time and did NOT catch it. With
// sequential use every entry has zero references by the time it is evicted, so
// eviction frees it directly and the last-put path — the one the mutation
// breaks — is never taken. Freeing on eviction and freeing on the last put are
// two different code paths, and only concurrency reaches the second.
//
// Mutation-proven both ways: making eviction free unconditionally deadlocks
// TestEvictionDoesNotStrandABorrower, and making the last put skip the free
// fails this.
func TestEvictedEntriesAreFreed(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 2})

	const distinct = 6
	keys := make([]types.Hash, distinct)
	for i := range keys {
		keys[i][0] = byte(0x40 + i)
	}

	// Concurrent, so entries are evicted WHILE they are held and the last
	// reference-holder is the one that has to free them.
	// Four workers, not one per key per round: the point is that entries are
	// evicted WHILE held, which needs concurrency, not a stampede. An earlier
	// version launched twenty-four at once and had eighteen of them allocating
	// a 256 MiB cache simultaneously — which is how the concurrent-build bound
	// in New was found, and is not what this test is for.
	var wg sync.WaitGroup
	work := make(chan types.Hash, distinct*4)
	for round := 0; round < 4; round++ {
		for i := range keys {
			work <- keys[i]
		}
	}
	close(work)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range work {
				e.Hash(k, []byte("x"))
			}
		}()
	}
	wg.Wait()

	// Keys is 2, so at least distinct-2 of them must have been evicted and
	// freed. The exact number is higher and nondeterministic — the table churns
	// — so this is a floor rather than an equality.
	want := int64(distinct - 2)
	deadline := time.Now().Add(60 * time.Second)
	for e.destroyed.Load() < want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.destroyed.Load(); got < want {
		t.Fatalf("at least %d entries left the table, %d were freed: the rest "+
			"leak a 256 MiB cache and their VMs, which nothing else in this "+
			"package would notice", want, got)
	}
}
