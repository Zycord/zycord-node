//go:build randomx

package randomx

/*
#cgo CXXFLAGS: -std=c++11 -O3 -fPIC -DNDEBUG
#cgo CFLAGS:   -O3 -fPIC -DNDEBUG
#cgo amd64 CFLAGS:   -maes
#cgo amd64 CXXFLAGS: -maes
#cgo arm64 CFLAGS:   -march=armv8-a+crypto
#cgo arm64 CXXFLAGS: -march=armv8-a+crypto
// The C++ runtime. Named explicitly on Linux, where cgo does not infer it;
// left to the toolchain on darwin, which links libc++ itself and warns about
// the duplicate if we name it too.
#cgo linux LDFLAGS: -lstdc++

#include <stdlib.h>
#include "upstream/randomx.h"

// zycord_init_dataset is randomx_init_dataset with one thing done first: the
// calling thread is put into JIT-EXECUTE mode.
//
// On Apple Silicon RandomX allocates its code buffers with MAP_JIT, where W^X
// is a PER-THREAD switch (pthread_jit_write_protect_np) rather than a property
// of the pages. Two consequences meet here:
//
//   - randomx_alloc_cache and randomx_create_vm end in allocMemoryPages, which
//     leaves the calling thread in WRITE mode so the compiler can fill the
//     buffer it just allocated. Nothing puts that thread back;
//   - randomx_init_dataset EXECUTES the JIT-compiled dataset-init function and,
//     unlike every hashing path, never sets execute mode first — the hashing
//     VMs do it in run() under RANDOMX_FLAG_SECURE.
//
// So a thread left in write mode cannot run a dataset fill, and Go hands
// goroutines whichever OS thread it likes. The result is SIGBUS on the first
// instruction of the fill, with the fault address equal to the program counter.
//
// WHICH CALLS LEAVE A THREAD POISONED is narrower than "anything that touched
// RandomX", and the difference is what makes this testable rather than a
// lottery. randomx_init_cache ends in JitCompiler::enableExecution
// (dataset.cpp, unconditionally), and so does CompiledLightVm::setCache (under
// RANDOMX_FLAG_SECURE, which randomx_get_flags sets on every platform that
// needs W^X), so a thread that built a key-table entry ends EXECUTABLE. What
// ends in WRITE mode is a randomx_create_vm over a DATASET — CompiledVm has no
// cache to set, so nothing follows the JitCompiler constructor's
// allocMemoryPages — and a randomx_alloc_cache whose goroutine migrates before
// randomx_init_cache reaches the same thread.
//
// Options.Insecure clears SECURE and takes upstream down a path that asks for
// RWX pages outright (setPagesRWX), which MAP_JIT does not grant and which
// upstream does not check. That option is a benchmarking aid, it is not what a
// node runs, and this guard is correct under it either way.
//
// REPRODUCED DETERMINISTICALLY, which corrects what this comment said when the
// guard first landed ("observed once, deliberately not described as
// reproducible"). What a test cannot control is which thread the Go runtime
// gives a fill worker; what it CAN control is its own. Pin the goroutine with
// runtime.LockOSThread, build the engine on it — that is the fast-VM loop in
// New, in write mode — warm the cache through Prefetch so nothing rebuilds it
// back into execute mode, and take the fill's first share on the calling
// goroutine. That is TestAFillSurvivesTheThreadThatCreatedTheVMs, and with the
// pthread_jit_write_protect_np call below removed it is a SIGBUS every time on
// darwin/arm64 (go1.26.2, macOS 15).
//
// The fix belongs on the EXECUTING side and can belong nowhere else. Setting
// the mode after each allocation would leave the invariant one unwrapped
// upstream call away from being false again, and a Go worker cannot know which
// thread it will land on; a call that sets the mode immediately before
// executing, inside the same cgo call — which is what pins a goroutine to one
// thread — is the only version that cannot be defeated by scheduling.
#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#if TARGET_OS_OSX && defined(MAC_OS_VERSION_11_0) \
	&& MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_11_0
#define ZYCORD_PTHREAD_JIT_WP 1
#include <pthread.h>
#endif
#endif

static void zycord_init_dataset(randomx_dataset *dataset, randomx_cache *cache,
                                unsigned long startItem, unsigned long itemCount) {
#ifdef ZYCORD_PTHREAD_JIT_WP
	if (__builtin_available(macOS 11.0, *)) {
		pthread_jit_write_protect_np(1);
	}
#endif
	randomx_init_dataset(dataset, cache, startItem, itemCount);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"zycord/core/pow"
	"zycord/core/types"
)

// A note on the compile flags above, because two of them are load-bearing and
// one is a deliberate omission.
//
// -maes and -march=armv8-a+crypto match upstream's own default build and enable
// the hardware AES intrinsics. They do not decide anything: RandomX selects
// hard or soft AES at RUNTIME from randomx_get_flags, so a CPU without the
// instructions takes the software path rather than an illegal instruction.
//
// What is NOT here is -mssse3 and -mavx2 on the two SIMD Argon2 files.
// Upstream applies those PER FILE and cgo has no per-file flags, so the choice
// is between applying them to the whole library — which would let the compiler
// emit SSSE3 or AVX2 anywhere, including on a CPU that has neither — and
// leaving them off. They are left off. The files are guarded by
// `#if defined(__SSSE3__)` and compile to nothing, Argon2 falls back to the
// reference implementation, and THE OUTPUT IS IDENTICAL: this costs cache
// initialisation time, once per key epoch, and nothing else. Reopen it by
// splitting those two files into their own cgo packages with their own flags,
// and only if a measurement says cache initialisation matters.

// Available reports whether this binary carries the RandomX engine.
func Available() bool { return true }

// Engine is the RandomX proof-of-work engine.
//
// It is safe for concurrent use, which is not optional: the gossip path, the
// sync driver and the miner share one engine, and a RandomX VM is not safe for
// concurrent use at all. Everything below exists to reconcile those two facts.
type Engine struct {
	opts Options
	// flags is the LIGHT configuration and never carries FULL_MEM: it is what
	// every cache and every key-table VM is built with. fastFlags is the same
	// set with FULL_MEM added, and belongs to the dataset and the VMs that
	// read it. Keeping them apart is half of the fix for the prefetch/mining-key
	// collision — see the fast-path block below for the other half.
	flags     C.randomx_flags
	fastFlags C.randomx_flags

	mu   sync.Mutex
	keys []*keyed // most-recently-used last; len <= opts.Keys

	// # The full-memory mining path, and why it is not in the key table
	//
	// There is ONE dataset and it holds ONE key's data at a time. That is not
	// an accident of this implementation: it is ~2 GiB, and holding a second
	// to smooth a key boundary is a trade this package has refused twice
	// already, in Options.FullMemory and in Prefetch.
	//
	// It used to be in the key table anyway. build() filled the shared dataset
	// for whichever key it was building, while every entry ALREADY in the
	// table held VMs created with FULL_MEM — which read that same buffer. So
	// initialising any second key silently re-pointed Hash for the first: the
	// engine went on answering for a key it no longer held, and the caller
	// could not tell, because it had passed the correct key in and got a
	// digest back.
	//
	// On a mining node that is consensus-fatal and silent. Observed: from the
	// first prefetch tick after height randomx_key_lag, a testnet node sealed
	// headers whose work was valid under the NEXT epoch's key while the rule
	// wanted the current one. Its own chain accepted them — nothing in the
	// node re-checked the work of a block it had just mined — and every other
	// node rejected the lot. Heights 70 to 1181, 1112 blocks, no error
	// anywhere. The blocks sealed DURING the rebuild were valid under neither
	// key, because the fill and the hashes reading it ran concurrently.
	//
	// So the dataset is not in the table and no table VM reads it:
	//
	//   - verification always runs LIGHT, on the entry's own 256 MiB cache.
	//     It is correct for any key and is not affected by anything the miner
	//     does, which also means a mining node keeps verifying at full speed
	//     while its dataset is being rebuilt;
	//   - the dataset is bound to exactly one key, moved only by MineOn, and
	//     read only under fmu;
	//   - Hash takes the fast path when the key it was handed is the bound one
	//     and the light path otherwise. That is safe because the two modes
	//     compute the same function (TestLightAndFastAgree), so a stale
	//     binding can now cost speed and nothing else.
	//
	// fmu guards fastKey AND the contents of the dataset. Hashers hold it for
	// read across the whole call, so a rebuild — which holds it for write —
	// cannot start under a hash in flight, and a hash cannot start under a
	// rebuild. fastKey is cleared for the duration of a rebuild as well, so
	// that a panic escaping the fill leaves the engine on the light path
	// rather than serving a half-written dataset.
	fmu     sync.RWMutex
	dset    *C.randomx_dataset
	fastVMs chan *C.randomx_vm // nil unless Options.FullMemory
	fastKey string             // "" means the dataset holds nothing usable

	// building bounds how many cache initialisations run at once.
	//
	// Sized at Keys because more is guaranteed waste: the table holds Keys
	// entries, so a build beyond that is for an entry that will be evicted
	// before anyone uses it. Without the bound, N goroutines wanting N
	// distinct epochs allocate N caches of 256 MiB SIMULTANEOUSLY — measured
	// at 18 concurrent builds and about 4.6 GiB while chasing a test failure,
	// and reachable by a peer, because the key comes from a header height the
	// peer chooses (see I7-H4). The bound turns an unbounded memory
	// amplification into a queue.
	building chan struct{}

	// buildsInFlight and peakBuilds measure whether that bound is the bound.
	//
	// They exist because the sentence above is an argument, and an argument
	// about concurrent 256 MiB allocations is exactly the kind this project
	// has been wrong about twice. A review of I7-H4 proposed that a queued
	// build holds its cache while it waits, so that one peer's five headers
	// are five simultaneous allocations and an aggregate of peers is an
	// out-of-memory kill. Reading `build` refutes it — the semaphore is taken
	// BEFORE randomx_alloc_cache, so a queued caller is parked holding nothing
	// — but reading is what produced the claim being refuted.
	//
	// peakBuilds is the largest number of goroutines ever inside the allocating
	// region at once, over the engine's whole life. It is what makes the bound
	// MEASURABLE rather than argued: nothing else in the package can see it —
	// the table stays bounded, no hash blocks, no verdict changes, and an
	// engine that allocated one cache per waiting caller would pass every other
	// test here while using Keys times more memory than it says it does.
	//
	// **What they do NOT measure is resident memory, and conflating the two is
	// how the refutation would become the next wrong claim.** This semaphore is
	// released when `build` returns, and the 256 MiB it allocated stays alive in
	// the table entry until that entry is destroyed. Residency is therefore
	// `Keys` (the table) PLUS every entry evicted while somebody still holds a
	// reference to it, and the second term is bounded by no constant in this
	// struct — see liveCaches below, which measures the quantity this pair does
	// not.
	buildsInFlight atomic.Int64
	peakBuilds     atomic.Int64

	// liveCaches and peakLiveCaches are the memory quantity, and they exist
	// because the pair above is not it.
	//
	// A cache is resident from the moment `build` succeeds until `destroy`
	// releases it. Between those two, an entry can leave the table — evicted
	// to make room for the key someone else is building — and keep everything
	// it holds, because `evictLocked` destroys only at `refs == 0` and the last
	// `put` does it otherwise. That is the correct lifetime rule (I7-H4's one
	// invariant) and it means **the table bound is not a memory bound**.
	//
	// The reachable long-lived instance is `MineOn`: it holds its reference
	// across `initDataset`, which this package's own `fastHash` comment prices
	// at ten to thirty seconds at a key boundary. Two never-held epochs arriving
	// inside that window turn a `Keys: 2` table over and leave THREE caches
	// resident — 768 MiB of cache on top of the ~2 GiB dataset.
	//
	// A cache is also resident while it is still being FILLED, which is the
	// other term and the one a flood reaches: up to `Keys` builds are in that
	// state at once. So residency has three terms — the table's `Keys`, the
	// builds in flight (up to `Keys` again), and every entry evicted while a
	// borrower holds it — and the first two alone give a DERIVED ceiling of
	// `2 x Keys` under demand, twice what the table bound suggests. 1024 MiB at
	// the default, and observed at exactly that
	// (TestConcurrentEpochDemandIsAdmittedKeysAtATime, whose assertion is
	// one-sided because how many admitted builds overlap is the scheduler's
	// business).
	//
	// So the honest bound is: concurrent *allocation* is `Keys`; residency is
	// `Keys` + in-flight builds + holders of evicted entries, and it is the
	// second quantity an operator's RSS follows.
	liveCaches     atomic.Int64
	peakLiveCaches atomic.Int64

	// builds counts completed cache initialisations, successful or not.
	//
	// It is the anti-vacuity half of the counter above: a peak of Keys proves
	// nothing if the test that observes it never demanded more than Keys
	// epochs, and a build that was served from the table is not a build.
	builds atomic.Int64

	// warmFailed counts the OBSERVATIONS of a failed build on a path which does
	// not report the failure to its caller.
	//
	// Observations, not builds, and the difference is not pedantry: keyedFor
	// hands the same k.err to every goroutine waiting on the same entry, so one
	// failed 256 MiB allocation that three prefetches were waiting for counts
	// three. That makes it a measure of how much warming was lost rather than
	// of how many allocations failed, which is the more useful of the two here
	// and is not what a reader would assume from a name ending in "Failed".
	//
	// hashRaw PANICS when keyedFor returns an error, because a work verdict
	// this node cannot compute is not a verdict and answering anyway is
	// consensus-fatal. Prefetch and MineOn take the identical error from the
	// identical call and carry on: a warm that did not land is not wrong, it
	// only means the later real hash pays the build it was meant to save, and
	// a miner without a dataset mines light rather than not at all.
	//
	// That asymmetry is deliberate and it has one bad property. Both silent
	// paths degrade quietly under the same memory pressure that will make the
	// next verify panic, so the first thing anyone sees is the panic — with the
	// several minutes of declining prefetches that predicted it nowhere at all.
	// Nothing else in the package can see them: the table stays bounded, no
	// hash blocks, no verdict changes, and the node simply gets slower.
	//
	// **This counter does not yet reach an operator, and saying otherwise would
	// be the defect it is meant to fix.** It is package-internal, like
	// `destroyed` below: it makes the quantity exist and gives a later metric
	// something to read. Nothing logs it, no `/metrics` field carries it and no
	// RPC reports it — "no log, no metric, no RPC field", which is the standing
	// observability gap for this engine's internals as a class rather than for
	// this counter alone. Surfacing it belongs to that work and is not done
	// here.
	//
	// **No test forces a 256 MiB allocation to fail**, so its non-zero case is
	// never exercised, and the zero assertion in TestPrefetchReturnsItsReference
	// is therefore weak by construction: it catches a counter that fires on the
	// HAPPY path and it catches nothing else. A counter never incremented at all
	// would pass it. That is stated rather than left for a reader to assume, and
	// classified as I7-L2 classifies its own: read-verified, never observed. The
	// entry is I7-L4.
	//
	// One more thing it does not count, said here because the name suggests
	// otherwise: a warm that BUILT and was then evicted before the real hash
	// arrived. That is the commoner way a prefetch fails to pay off, it is not
	// an error on any path, and the LRU bound is what governs it.
	warmFailed atomic.Int64

	// destroyed counts entries whose VMs and cache have been freed.
	//
	// It exists because nothing else can see the difference. An engine that
	// evicts entries and never frees them passes every test in this package:
	// the table stays bounded, no hash blocks, no verdict changes — and it
	// leaks 256 MiB per key epoch, which on a node walking forward through
	// epochs is unbounded. Mutation-proven: making the last put skip the
	// destruction left the whole suite green until this counter existed.
	destroyed atomic.Int64
}

// keyed is one initialised cache and the VMs bound to it.
//
// ready is closed when the build has finished, successfully or not, and err is
// valid only after that. The gate exists so the expensive part happens outside
// the engine lock: a node crossing a key boundary must keep verifying on the
// key it already has while the next one is built.
//
// # The one invariant, and it is deliberately one sentence
//
// **An entry's VMs are destroyed by whoever drops the last reference to it
// after it has left the table, and by nobody else.**
//
// Everything follows from that. Once an entry is out of e.keys no new
// reference can be taken, so the count can only fall; whoever takes it to zero
// knows every borrowed VM is back, because a borrower returns its VM before
// dropping its reference; and that goroutine is the only one that can be
// there, so the destruction needs no lock and no waiting.
//
// This replaces a design with a per-entry mutex, an idle channel, a sync.Once
// and a background releaser that WAITED for the count to fall. That version
// deadlocked under -race — six borrowers stuck receiving from channels whose
// entries had already been drained, with the table showing full pools and no
// releaser alive — and I could not derive the interleaving from the code. A
// concurrency mechanism nobody can justify is one nobody should ship, so it
// was replaced rather than patched. refs is now guarded by the engine lock,
// the same lock that adds and removes entries, which is what makes
// "no new reference after it leaves the table" true by construction rather
// than by argument.
type keyed struct {
	key   string // the raw key bytes, not a hash of them
	ready chan struct{}
	err   error
	cache *C.randomx_cache
	vms   chan *C.randomx_vm // a semaphore that happens to carry the VMs

	// Guarded by Engine.mu.
	refs    int
	evicted bool
}

// The engine satisfies the optional interface pow.NewSolver looks for, and it
// is asserted at compile time because nothing else would notice if it stopped.
// A drifted signature would not fail a build or a test: the assertion in
// NewSolver would simply stop matching, MineOn would never be called, the
// dataset would never be bound, and every miner in the network would hash at
// light speed — correctly, quietly, at a twentieth of the rate — forever.
var _ pow.HotKeyEngine = (*Engine)(nil)

// New builds an engine.
func New(o Options) (pow.Engine, error) {
	if o.Keys <= 0 {
		o.Keys = 2
	}
	if o.MaxVMs <= 0 {
		o.MaxVMs = runtime.GOMAXPROCS(0)
	}
	if o.InitThreads <= 0 {
		o.InitThreads = runtime.GOMAXPROCS(0)
	}

	// Start from what the CPU and OS actually offer — randomx_get_flags already
	// returns JIT, SECURE where the platform needs it, hardware AES and the
	// Argon2 variants — and then CLEAR what the options turn off.
	//
	// Clearing, not setting, and the difference is not stylistic. An earlier
	// version of this function OR'd JIT in when Interpreted was false and did
	// nothing when it was true, on the assumption that the base flags did not
	// already carry it. They do: this machine reports 26, which is
	// JIT|SECURE|HARD_AES. So Interpreted was a no-op, both engines ran the
	// same configuration, and TestJITAgreesWithInterpreter compared the JIT
	// with itself — a cross-check that could not fail, which is worse than no
	// cross-check because it reads like one. It was caught by mutating the
	// ARM64 code generator and watching every test stay green.
	flags := C.randomx_get_flags()
	if o.Interpreted {
		flags &^= C.RANDOMX_FLAG_JIT
		// SECURE is the W^X discipline for JIT pages and means nothing without
		// them; leaving it set on an interpreted VM asks randomx_create_vm for
		// a combination its switch does not name.
		flags &^= C.RANDOMX_FLAG_SECURE
	} else if o.Insecure {
		flags &^= C.RANDOMX_FLAG_SECURE
	}
	if o.SoftAES {
		flags &^= C.RANDOMX_FLAG_HARD_AES
	}
	if o.LargePages {
		flags |= C.RANDOMX_FLAG_LARGE_PAGES
	}
	// FULL_MEM is deliberately NOT folded into flags. It goes on fastFlags
	// alone, so that the only VMs which can read the dataset are the ones this
	// engine hands out under fmu.
	e := &Engine{
		opts:      o,
		flags:     flags,
		fastFlags: flags | C.RANDOMX_FLAG_FULL_MEM,
		building:  make(chan struct{}, o.Keys),
	}
	if o.FullMemory {
		if e.dset = C.randomx_alloc_dataset(e.fastFlags); e.dset == nil {
			return nil, errors.New("randomx: could not allocate the ~2 GiB dataset; " +
				"mining needs it, verifying does not")
		}
		// The VMs are created here, once, over a dataset that holds nothing
		// yet. A full-memory VM may be created with a NULL cache — randomx.h
		// says so explicitly — and it reads the dataset only while hashing, so
		// there is nothing to recreate when MineOn refills it. Cheap: a VM is
		// a 2 MiB scratchpad beside a 2 GiB dataset.
		e.fastVMs = make(chan *C.randomx_vm, o.MaxVMs)
		for i := 0; i < o.MaxVMs; i++ {
			vm := C.randomx_create_vm(e.fastFlags, nil, e.dset)
			if vm == nil {
				for len(e.fastVMs) > 0 {
					C.randomx_destroy_vm(<-e.fastVMs)
				}
				C.randomx_release_dataset(e.dset)
				return nil, errors.New("randomx: could not create a full-memory virtual machine")
			}
			e.fastVMs <- vm
		}
	}
	return e, nil
}

// Name identifies the engine, and is what Params.PoWEngine must equal.
func (e *Engine) Name() string { return Name }

// Hash evaluates RandomX over input, keyed for key.
func (e *Engine) Hash(key types.Hash, input []byte) types.Hash {
	return e.hashRaw(string(key[:]), input)
}

// hashRaw is Hash with an arbitrary-length key.
//
// The protocol only ever uses 32-byte keys, but RandomX itself accepts any
// length and its published test vectors use short ASCII strings. Keeping the
// raw path exported-to-the-package is what lets those vectors drive EXACTLY
// the code the chain runs, rather than a parallel path written to be testable
// — which would prove the vectors and nothing about the engine.
func (e *Engine) hashRaw(key string, input []byte) types.Hash {
	// The mining key, if this is it. Same digest as the light path below —
	// that is what TestLightAndFastAgree asserts — and roughly an order of
	// magnitude faster.
	if out, ok := e.fastHash(key, input); ok {
		return out
	}

	k, err := e.keyedFor(key)
	// The reference keyedFor took covers the borrow below. Released after the
	// VM goes back, never before: the whole defect this closes was a window
	// between holding an entry and borrowing from it.
	defer e.put(k)
	if err != nil {
		// The interface cannot report this, and inventing a digest would be
		// far worse than stopping: a node that answers "no" to every work
		// check silently rejects the whole chain, and one that answers "yes"
		// accepts anything. Both are consensus failures that look like
		// network problems. Allocation of a 256 MiB cache failing is a
		// machine that cannot run a node.
		panic(fmt.Sprintf("randomx: %v", err))
	}

	vm := <-k.vms
	defer func() { k.vms <- vm }()

	var out types.Hash
	// input may be empty; &input[0] would panic on a zero-length slice, and
	// RandomX accepts a zero-length input.
	var in unsafe.Pointer
	if len(input) > 0 {
		in = unsafe.Pointer(&input[0])
	}
	C.randomx_calculate_hash(vm, in, C.size_t(len(input)), unsafe.Pointer(&out[0]))
	// input and out are Go memory passed to C for the duration of one call,
	// which is exactly what cgo permits; KeepAlive pins them against a
	// collector that cannot see the C reference.
	runtime.KeepAlive(input)
	return out
}

// keyedFor returns the cache and VM pool for a key, initialising them if this
// is a key the engine has not seen, and evicting the least recently used entry
// when the table is full.
func (e *Engine) keyedFor(key string) (*keyed, error) {
	k, mine := e.entryFor(key)
	if mine {
		// This goroutine created the entry, so it does the build — OUTSIDE the
		// lock. Everything else on other keys keeps hashing throughout.
		k.err = e.build(k)
		close(k.ready)
		if k.err != nil {
			// A failed build must not be remembered. A cache allocation can
			// fail transiently under memory pressure, and an entry that
			// answered with the same error forever would turn one bad moment
			// into a node that refuses every header at that epoch.
			e.forget(k)
		}
	}
	<-k.ready
	return k, k.err
}

// entryFor returns the table entry for a key, and whether this caller is the
// one responsible for building it.
//
// The lock is held only for the table bookkeeping — a slice scan and an
// append. No cache initialisation, no dataset fill, no VM creation.
func (e *Engine) entryFor(key string) (k *keyed, mine bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, existing := range e.keys {
		if existing.key == key {
			// Taken under the lock that also removes entries, so an entry
			// cannot leave the table between being found and being referenced.
			existing.refs++
			// Move to the back: most recently used.
			e.keys = append(append(e.keys[:i:i], e.keys[i+1:]...), existing)
			return existing, false
		}
	}

	k = &keyed{key: key, ready: make(chan struct{}), refs: 1}
	if len(e.keys) >= e.opts.Keys {
		victim := e.keys[0]
		e.keys = e.keys[1:]
		e.evictLocked(victim)
	}
	e.keys = append(e.keys, k)
	return k, true
}

// evictLocked marks an entry gone and destroys it if nobody holds it.
// Engine.mu must be held; the destruction itself is handed to a goroutine so
// that neither the build wait nor the C frees happen under the lock.
func (e *Engine) evictLocked(k *keyed) {
	k.evicted = true
	if k.refs == 0 {
		go e.destroy(k)
	}
	// Otherwise the last put destroys it. There is no third case: refs cannot
	// rise again, because the entry is no longer in e.keys and entryFor is the
	// only place a reference is taken.
}

// put drops the reference entryFor handed out.
func (e *Engine) put(k *keyed) {
	e.mu.Lock()
	k.refs--
	last := k.evicted && k.refs == 0
	e.mu.Unlock()
	if last {
		e.destroy(k)
	}
}

// destroy frees an entry's VMs and cache.
//
// Called only when the entry has left the table and holds no references, so
// every VM it lent out is back in the channel and no receive here can block.
// That is the whole reason this function has no waiting in it.
func (e *Engine) destroy(k *keyed) {
	<-k.ready
	defer e.destroyed.Add(1)
	if k.err != nil {
		return // nothing was allocated
	}
	for i := 0; i < e.opts.MaxVMs; i++ {
		C.randomx_destroy_vm(<-k.vms)
	}
	C.randomx_release_cache(k.cache)
	e.liveCaches.Add(-1)
}

// forget drops an entry from the table after a failed build.
func (e *Engine) forget(k *keyed) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, existing := range e.keys {
		if existing == k {
			e.keys = append(e.keys[:i:i], e.keys[i+1:]...)
			// Marked like any other removal. Nothing was allocated, so destroy
			// returns immediately, but a removal path that skipped the mark
			// would be the one exception a later reader has to notice.
			e.evictLocked(existing)
			return
		}
	}
}

// Prefetch builds the cache for a key without waiting for it, so that a node
// crossing a key boundary does not pay the build at the moment it needs the
// key.
//
// It is possible at all because the key comes from the HEIGHT: the next
// epoch's key is known long before the boundary. Under upstream RandomX's
// schedule, where the key is a key block's hash, which key comes next depends
// on which branch wins.
//
// Note what it does NOT do for a miner. In fast mode the expensive part is the
// ~2 GiB dataset, and prefetching that means holding two of them — 4 GiB — to
// save a pause of a few seconds once per key interval, which at mainnet's 2048
// blocks is once every seventeen hours. That is a bad trade for a chain whose
// pitch is the laptop you already have, and it is not made: the dataset is
// still built on demand, by MineOn. What this removes is the VERIFIER's stall,
// where the cost is one 256 MiB cache the engine already holds a slot for.
//
// It said that before the collision was fixed too, and it was not true: the
// prefetch reached build(), and build() filled the shared dataset for the key
// being warmed — which is how warming the NEXT epoch's key made the miner
// start sealing blocks under it, an epoch early, on a network that rejected
// every one of them. Prefetch is a cache-only operation now because nothing
// outside MineOn can reach the dataset at all, not because this function is
// careful.
func (e *Engine) Prefetch(key types.Hash) {
	go func() {
		k, err := e.keyedFor(string(key[:]))
		if err != nil {
			// Counted rather than returned: this runs on its own goroutine,
			// so there is nobody to return it to, and a warm that did not
			// land costs only the build the real hash now pays. See
			// warmFailed for why silent is not the same as invisible.
			e.warmFailed.Add(1)
		}
		// keyedFor hands back a reference and every caller owes a put. A
		// prefetch that kept it would pin the entry forever, and an entry that
		// can never reach zero references is an entry nothing ever destroys —
		// its cache and VMs leaked, once per prefetched epoch. It is owed on
		// the error path too: keyedFor returns a non-nil entry either way.
		e.put(k)
	}()
}

// MineOn tells the engine which key the local miner is about to hammer, so
// that the full-memory dataset holds that key and no other.
//
// It is not part of pow.Engine and must not become part of it. Every other
// caller — the gossip path, the sync driver, a work cache — asks about a key
// once and is served correctly by the light path; only a miner spends millions
// of hashes on one key, which is the only thing that pays for a ~2 GiB fill.
// pow.NewSolver announces the key through an optional interface, so a miner
// gets this by mining and nobody else has to know the mechanism exists.
//
// Synchronous, and the caller is the one that waits. The fill is the boundary
// stall a miner cannot avoid — the dataset for the new epoch has to be built
// by somebody, at some point — and the goroutine that is about to mine is the
// honest place to put it. Nothing else waits: every other hash falls to the
// light path for the duration rather than queueing behind the fill, which is
// what TestARebuildDoesNotStopANodeVerifying measures.
//
// Best-effort about speed, never about correctness. If the cache for the key
// cannot be built this returns and leaves the dataset where it was; hashing
// then takes the light path and produces exactly the same digests, slowly.
func (e *Engine) MineOn(key types.Hash) {
	if !e.opts.FullMemory {
		return // no dataset: every hash is already light
	}
	k := string(key[:])

	e.fmu.RLock()
	bound := e.fastKey == k
	e.fmu.RUnlock()
	if bound {
		return // the common case: one call per candidate block, unchanged key
	}

	// The cache, built OUTSIDE fmu. It is the same 256 MiB cache the light
	// path holds for this key, so a prefetch that has already landed makes
	// this free and the fill below is all that remains to pay.
	entry, err := e.keyedFor(k)
	defer e.put(entry)
	if err != nil {
		// The miner keeps working: without a dataset every hash goes through
		// the light path, which computes the same function more slowly
		// (TestLightAndFastAgree). Counted for the reason warmFailed gives —
		// a node that quietly stopped mining fast looks exactly like a node
		// that is merely unlucky.
		e.warmFailed.Add(1)
		return
	}

	e.fmu.Lock()
	defer e.fmu.Unlock()
	if e.dset == nil || e.fastKey == k {
		// Closed, or another goroutine bound this key while we queued.
		return
	}
	// Unbound for the duration. Redundant against readers — the write lock
	// already excludes them — and not redundant against a panic escaping the
	// fill, which would otherwise leave a half-written dataset bound.
	e.fastKey = ""
	initDataset(e.dset, entry.cache, e.opts.InitThreads)
	e.fastKey = k
}

// fastHash evaluates RandomX on the dataset, and reports whether it did.
//
// The read lock spans the whole hash rather than just the fastKey comparison,
// which is the point of it: a rebuild must not be able to start between the
// two. A hasher that has to wait for a VM waits while holding the lock for
// read, which cannot deadlock against a rebuild — every borrower returns its
// VM before releasing the lock, so the borrowers already inside always drain.
//
// TRY-lock, and it is load-bearing rather than defensive. Go blocks a new
// reader while a writer is waiting, so a plain RLock here would park every
// hash in the process behind MineOn's fill — ten to thirty seconds of it at a
// key boundary — and a mining node would go back to verifying nothing while
// it rebuilt, which is the symptom I7-M2 was fixed to remove and which the
// dataset-in-the-key-table version of this code brought back in a worse form.
// Failing over to the light path costs speed and cannot cost correctness: the
// two modes compute the same function, which is why TestLightAndFastAgree
// exists.
func (e *Engine) fastHash(key string, input []byte) (types.Hash, bool) {
	var out types.Hash
	if !e.opts.FullMemory {
		return out, false
	}
	if !e.fmu.TryRLock() {
		return out, false // a rebuild holds the dataset; hash light instead
	}
	defer e.fmu.RUnlock()
	if e.fastKey != key {
		return out, false
	}

	vm := <-e.fastVMs
	defer func() { e.fastVMs <- vm }()

	var in unsafe.Pointer
	if len(input) > 0 {
		in = unsafe.Pointer(&input[0])
	}
	C.randomx_calculate_hash(vm, in, C.size_t(len(input)), unsafe.Pointer(&out[0]))
	runtime.KeepAlive(input)
	return out, true
}

// build initialises one cache and the VMs bound to it. It runs outside e.mu.
func (e *Engine) build(k *keyed) error {
	// Queue behind the concurrent-build bound. Held for the allocation and the
	// initialisation, released before the VMs are created, which are cheap.
	//
	// **The send is BEFORE randomx_alloc_cache and that ordering is the whole
	// property.** A caller beyond the bound parks here holding nothing: no
	// cache, no VMs, no per-waiter memory of any kind. Reverse these two lines
	// and the bound becomes a bound on how many builds *finish* at once rather
	// than on how many regions exist at once, which is the amplification I7-H4
	// was fixed to remove. peakBuilds is what says so with a number instead of
	// with this paragraph.
	e.building <- struct{}{}
	inFlight := e.buildsInFlight.Add(1)
	for {
		peak := e.peakBuilds.Load()
		if inFlight <= peak || e.peakBuilds.CompareAndSwap(peak, inFlight) {
			break
		}
	}
	defer func() {
		e.buildsInFlight.Add(-1)
		e.builds.Add(1)
		<-e.building
	}()

	cache := C.randomx_alloc_cache(e.flags)
	if cache == nil {
		return errors.New("randomx: could not allocate the 256 MiB cache")
	}
	// Resident from HERE, which is the line the counter has to sit on.
	//
	// Counting it at the end of this function — after the VM loop, where the
	// entry is finally handed over — hides every cache currently being filled,
	// and there are up to `Keys` of those by construction. This counter's whole
	// job is to be the number an operator's RSS follows, so it has to start
	// when malloc does, not when the bookkeeping does.
	e.markCacheResident()
	ckey := C.CBytes([]byte(k.key))
	defer C.free(ckey)
	C.randomx_init_cache(cache, ckey, C.size_t(len(k.key)))

	// **The dataset is not touched here, and that is the fix for the
	// prefetch/mining-key collision.** This function runs for every key the
	// engine is asked about — a peer's header, a reorg, a prefetch — and the
	// dataset belongs to whichever key the local miner is working on. Filling
	// it here filled it for somebody else's key, under the VMs already serving
	// the miner's. MineOn is the only writer.
	//
	// The VMs below are light for the same reason: e.flags carries no
	// FULL_MEM, so nothing in the key table can read the dataset at all.
	vms := make(chan *C.randomx_vm, e.opts.MaxVMs)
	for i := 0; i < e.opts.MaxVMs; i++ {
		// NIL rather than e.dset, and it is a statement rather than a
		// tidy-up: e.flags carries no FULL_MEM, so upstream would ignore the
		// dataset anyway, and a key-table VM that is handed a pointer it must
		// not read is one refactor away from reading it.
		vm := C.randomx_create_vm(e.flags, cache, nil)
		if vm == nil {
			for len(vms) > 0 {
				C.randomx_destroy_vm(<-vms)
			}
			C.randomx_release_cache(cache)
			// Released here rather than by destroy: this build returns an
			// error, k.cache stays nil, and destroy's `k.err != nil` early
			// return is what makes that correct — so the decrement cannot be
			// left to it.
			e.liveCaches.Add(-1)
			return errors.New("randomx: could not create a virtual machine")
		}
		vms <- vm
	}
	k.cache, k.vms = cache, vms
	return nil
}

// markCacheResident records one more live 256 MiB cache and keeps the running
// peak. Split out only so that build's allocation path reads as one statement.
func (e *Engine) markCacheResident() {
	live := e.liveCaches.Add(1)
	for {
		peak := e.peakLiveCaches.Load()
		if live <= peak || e.peakLiveCaches.CompareAndSwap(peak, live) {
			break
		}
	}
}

// initDataset fills the ~2 GiB dataset, in parallel.
//
// It is split across workers because upstream splits it — its own benchmark
// defaults to hardware_concurrency() — and because leaving it serial is not a
// missed optimisation but a stall an operator sees. A LAB MEASUREMENT rather
// than an argument: on a four-thread devnet with a key interval of eight
// blocks, a serial build stopped a mining node dead at the first key boundary
// and it did not produce another block. The dataset is rebuilt on every key
// change, so the cost lands once per epoch, forever, at a moment when every
// miner on the network is doing the same thing.
//
// randomx_init_dataset over disjoint item ranges is safe to call concurrently;
// that is the contract upstream's benchmark relies on.
//
// It goes through zycord_init_dataset rather than randomx_init_dataset — see
// the C above. Upstream's own benchmark never needs that because it fills the
// dataset on threads it created for the purpose; a Go program has a thread
// pool it does not choose from.
//
// **The calling goroutine takes the first share itself**, rather than spawning
// one goroutine per worker and idling. That saves a hand-off the caller was
// going to block through anyway, and it is what makes the W^X guard above
// TESTABLE: a test that pins its goroutine to an OS thread (runtime.LockOSThread)
// and builds an engine on it knows that this thread created VMs, so it is in
// JIT-WRITE mode, and knows the fill will run on it. Without the guard that is
// a certain SIGBUS rather than a scheduling accident, which is what
// TestAFillSurvivesTheThreadThatCreatedTheVMs turns into a regression test.
func initDataset(dset *C.randomx_dataset, cache *C.randomx_cache, workers int) {
	n := uint64(C.randomx_dataset_item_count())
	if workers < 1 {
		workers = 1
	}
	per, rem := n/uint64(workers), n%uint64(workers)

	// Split first, so the caller's share is decided before anything runs.
	type span struct{ start, count uint64 }
	var spans []span
	start := uint64(0)
	for i := 0; i < workers; i++ {
		count := per
		if uint64(i) < rem {
			count++
		}
		if count == 0 {
			continue
		}
		spans = append(spans, span{start, count})
		start += count
	}
	if len(spans) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, sp := range spans[1:] {
		wg.Add(1)
		go func(s, c uint64) {
			defer wg.Done()
			C.zycord_init_dataset(dset, cache, C.ulong(s), C.ulong(c))
		}(sp.start, sp.count)
	}
	C.zycord_init_dataset(dset, cache, C.ulong(spans[0].start), C.ulong(spans[0].count))
	wg.Wait()
}

// Close releases every cache, VM and dataset the engine holds.
//
// It is not part of pow.Engine. Widening a consensus interface to carry one
// implementation's allocation lifetime would make every other implementer
// answer a question only this one has; cmd/zycordd type-asserts for io.Closer
// instead.
func (e *Engine) Close() error {
	e.mu.Lock()
	keys := e.keys
	e.keys = nil
	var free []*keyed
	for _, k := range keys {
		k.evicted = true
		if k.refs == 0 {
			free = append(free, k)
		}
		// An entry somebody still holds is destroyed by that holder's put,
		// exactly as an evicted one is. Close does not wait for it: waiting
		// here is what the previous design did, and it is where the shutdown
		// deadlock lived.
	}
	e.mu.Unlock()

	for _, k := range free {
		e.destroy(k)
	}

	// The fast path, under the lock every hasher holds for read. Taking it is
	// what makes this WAIT for the hashes already inside rather than free the
	// dataset under them, which is a use-after-free in C that no Go tooling
	// would report. The shape it takes on a real node was recorded when that fix
	// landed: SIGSEGV on stopping a miner, cmd/zycordd's deferred Close reaching
	// randomx_release_dataset while the nonce goroutines are still inside
	// randomx_calculate_hash.
	e.fmu.Lock()
	defer e.fmu.Unlock()
	if e.dset != nil {
		e.fastKey = ""
		for i := 0; i < e.opts.MaxVMs; i++ {
			C.randomx_destroy_vm(<-e.fastVMs)
		}
		C.randomx_release_dataset(e.dset)
		e.dset = nil
	}
	return nil
}
