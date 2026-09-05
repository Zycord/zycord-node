// Package randomx binds the reference RandomX implementation, which is the
// mainnet proof-of-work engine.
//
// It is the only cgo in the tree and it is compiled only under the `randomx`
// build tag. Without the tag this package still exists — see randomx_stub.go —
// but holds no C, so `go build ./...`, the golden vectors, the differential
// fold and every test outside this directory keep building and running with no
// C toolchain at all. That is the property the tag exists to preserve: the
// consensus rules are auditable by anyone with a Go toolchain, and only the
// work function needs a compiler.
//
// The vendored upstream lives in upstream/ and is byte-identical to the tag
// PINNED names, so auditing it is a `diff` against tevador's tree rather than a
// review of somebody's copy. vendor.sh is what produces both it and the shims.
//
// # Why the key is an argument
//
// A RandomX VM is keyed, and re-keying costs a full cache initialisation. The
// engine therefore caches per key, and pow.KeyFor derives the key from a
// header's height — so a verifier never needs a chain to know which key a
// header was proved against. See core/pow's KeyFor for the trade that buys.
//
// # Light and fast
//
// Verification runs in *light* mode: a 256 MiB cache and no dataset. Mining
// wants *fast* mode, which additionally builds a ~2 GiB dataset and is much
// faster per hash. Both produce identical digests — that is a property of
// RandomX and it is asserted, not assumed, in TestLightAndFastAgree.
//
// A mining engine runs BOTH at once, and the split is exactly one key wide.
// There is one dataset, it holds the key the local miner announced through
// MineOn, and every other key the node is asked about — a peer's header from
// the next epoch, a reorg into the previous one, a prefetch — is served light
// from its own cache. That is what makes the identical-digest property
// load-bearing rather than decorative, and it is the shape a real incident
// forced: with FULL_MEM VMs in the key table, initialising any second key
// repointed the first key's hashing at the new key's dataset, and the miner
// sealed 1112 blocks that every other node rejected.
//
// # What this actually costs, measured
//
// One machine (Apple Silicon, arm64). Take them as orders of magnitude rather
// than specifications, and re-take them wherever they are load-bearing:
//
//	verify, light, 1 goroutine       18 H/s      ~55 ms per header
//	mine, fast, 8 goroutines         335 H/s     aggregate
//	dataset init, 8 goroutines       ~7 s        ~11 s of pure item generation
//	dataset init, 1 goroutine        ~167 s      the reason it is parallel
//	key rotation, observed on-chain  8–11 s      a devnet's blocks stop for it
//
// The verification figure is the one that changes decisions elsewhere: it is
// three orders of magnitude above the BLAKE3 stand-in every cost decision in
// this tree was made against.
//
// A header range bounded by a thousand is a minute of one core. That
// reclassifies paths that were free: node/sync's per-header work check, the
// orphan pool, block announcements from unknown parents, and I5-L12's
// quadratic extendToCover, which was predicted to "flip when RandomX lands"
// and does. Ordering the cheap checks first (node/sync) removes the half an
// attacker gets for nothing; it does not remove the rest, and nothing here
// should be read as saying it does. What bounds the rest is per-peer scoring
// and rate limiting, whose magnitudes docs/decisions/testnet-measurements.md
// §2 records as invented and never measured.
//
// BenchmarkVerify, BenchmarkInitCache and BenchmarkInitDataset are the
// instruments. Publish from them per ARCHITECTURE §15's rules — their own
// process, medians over runs, an idle machine — not off a `make bench`
// transcript.
//
// # The key-rotation stall, and what was and was not done about it
//
// A node rebuilds when the key epoch changes, and the rebuild has to happen.
// What was wrong is that it happened **under the engine lock**, so a node
// crossing a boundary also stopped VERIFYING the chain it already had. Not a
// projection: on a devnet with an eight-block key interval, blocks arrived
// every 0.3–1 s and then took 8–11 s at every boundary, three times running.
//
// The build now runs outside the lock behind a per-key readiness gate, so
// hashing on a live key keeps making progress throughout — measured, and
// asserted as a ratio against a control window rather than a count, because
// the first version of that test passed against the locked implementation on
// the strength of the one hash already in flight.
//
// Prefetch goes further and is possible only because the key comes from the
// height: the next epoch's key is known long before the boundary, so its cache
// can be built while the current one is in use. Under upstream's schedule,
// where the key is a key block's hash, the same prefetch would depend on which
// branch wins. Measured: 24.8 ms against 574.9 ms cold.
//
// **The miner's dataset is deliberately NOT prefetched.** It is the bulk of
// the cost, and prefetching it means holding two — 4 GiB — to save a pause
// once per key interval, which at mainnet's 2048 blocks is once every
// seventeen hours. That is a bad trade for a chain whose pitch is the laptop
// you already have. A miner still pays the dataset rebuild at a boundary; what
// it no longer does is stop verifying while it pays.
//
// That sentence was true of the intent and false of the code until the
// prefetch/mining-key collision was fixed: a prefetch reached the same build
// path everything else did, and that path filled the shared dataset for the
// key being warmed. The dataset is now outside the key table entirely and
// MineOn is its only writer, so the claim is a property of the structure
// rather than of anybody remembering it.
package randomx

import "errors"

// Name is what Params.PoWEngine must say for a network running rx/0, the
// original RandomX work function.
//
// It names the *hash function*, not the library's patch version: v1.2.1 through
// v1.2.3 differ in ARM64 and RISC-V JIT correctness and in cmake, and not in a
// single bit of output. A name carrying the patch version would make a bug fix
// look like a chain split.
//
// **This engine is no longer what any shipped network selects**, and the name
// is kept rather than deleted because it is a consensus string: a devnet or a
// third-party network may still declare it, and `selectEngine` must be able to
// answer. The vendored library computes both functions — see NameV2.
const Name = "randomx-v1"

// NameV2 is what Params.PoWEngine must say for a network running rx/2, and it
// is what mainnet and the public testnet declare.
//
// rx/2 is a different work function, not a different build of the same one: a
// v1 VM and a v2 VM over the same cache and the same input produce different
// digests, which upstream asserts directly in its own switch test. So the two
// are distinct engine names under the same rule Name's comment states — the
// name tracks the function, and here the function genuinely changed.
//
// **One vendored library serves both.** RANDOMX_FLAG_V2 is a runtime flag on
// randomx_create_vm, every consumer of it inside the library tests it at run
// time rather than under the preprocessor, and src/configuration.h is
// byte-identical between v1.2.3 and v2.0.1 in cache size, dataset size and all
// three scratchpad sizes. So selecting v2 costs no second build, no second
// binary, and not one byte of additional memory; what it changes is the
// program size (256 -> 384 instructions) and three VM-level tweaks.
const NameV2 = "randomx-v2"

// Options configures an engine. The zero value is the verification
// configuration every node needs: light mode, the JIT and hardware AES if the
// CPU has them, and two cached keys.
//
// It is declared outside the build tag so that a caller compiles identically
// with and without cgo, and the difference between the two builds is a runtime
// error carrying a sentence rather than a compile failure.
type Options struct {
	// Keys bounds how many initialised caches are held at once. Each costs
	// 256 MiB in light mode.
	//
	// Two is the default and it is sized for a reason rather than rounded to.
	// Because the key comes from the height, the *next* epoch's key is known
	// in advance and an honest node crossing a boundary never needs the one it
	// just left — so one would serve the honest path. The second entry is for
	// reorgs and branch switches across a boundary, where the previous epoch
	// becomes live again; without it, a chain oscillating around a boundary
	// re-initialises a 256 MiB cache per block.
	Keys int

	// MaxVMs bounds concurrent hashing. A RandomX VM is not safe for
	// concurrent use, so each in-flight Hash needs its own; the pool is what
	// stops an unbounded goroutine count turning into an unbounded VM count.
	// Zero means GOMAXPROCS.
	MaxVMs int

	// InitThreads is how many goroutines fill the dataset when FullMemory is
	// set. Zero means GOMAXPROCS.
	//
	// Separate from MaxVMs on purpose. Dataset initialisation is a one-off
	// burst of pure computation and wants every core; MaxVMs bounds how many
	// hashes may be in flight afterwards and is a memory decision. Deriving
	// one from the other made `MaxVMs: 1` — which is what a cross-check test
	// asks for — build the whole 2 GiB dataset on a single goroutine, taking
	// over two minutes where eight take a fraction of it.
	InitThreads int

	// FullMemory allocates the ~2 GiB dataset and hashes roughly an order of
	// magnitude faster. It is for mining. A verifying node must not pay it,
	// and TestLightAndFastAgree is what says the two modes cannot disagree.
	FullMemory bool

	// Interpreted disables the JIT. Slower by roughly an order of magnitude
	// and identical in output — it exists so that TestJITAgreesWithInterpreter
	// can cross-check the JIT against a path that compiles no machine code,
	// which is the check that would have caught upstream's ARM64 ISUB_R bug
	// (fixed in v1.2.2, and the reason PINNED does not name v1.2.1).
	Interpreted bool

	// SoftAES forces the software AES path. Same digest, slower. Also a
	// cross-check axis rather than a tuning knob.
	SoftAES bool

	// LargePages asks the OS for huge pages. Purely a speed request; it is
	// dropped silently where the OS refuses, and it never changes a digest.
	LargePages bool

	// V2 selects rx/2 — RANDOMX_FLAG_V2 — instead of rx/0.
	//
	// It changes the DIGEST, which makes it the one field in this struct that
	// is consensus rather than configuration. Every other option here is a
	// promise that the answer is the same and only the cost differs
	// (Interpreted, SoftAES, LargePages, FullMemory all have a test asserting
	// exactly that). This one is the opposite: flipping it turns every header
	// the engine has ever judged into a header it now rejects. It is therefore
	// never set from a flag or an environment variable — `selectEngine` sets
	// it from Params.PoWEngine and nothing else does — and Name() reports
	// which function is bound so the mismatch check can see it.
	V2 bool

	// Insecure skips RANDOMX_FLAG_SECURE, which is the W^X discipline the JIT
	// needs on macOS and on hardened kernels. It is opt-out rather than opt-in
	// because a node that fails to allocate executable memory should be slow,
	// not dead, and because the flag costs nothing where it is not needed.
	Insecure bool
}

// ErrNotBuilt reports that this binary was built without the RandomX engine.
//
// Declared here rather than beside the stub that returns it, so that a caller
// can test for it in EITHER build. cmd/zycordd's engine test asserts the
// refusal reaches the operator with this sentence in it, and that test compiles
// under the randomx tag too — where the branch is not taken and the symbol must
// still exist.
//
// It names the FILES because `make build-randomx` no longer overwrites bin/zcd
// and bin/zycordd. While it did, "rebuild with `make build-randomx`" was
// a complete instruction: the operator re-ran the same binary and it worked.
// Now the tagged build lands beside the untagged one under a different name, so
// an instruction that stops at the make target is a loop — rebuild, re-run the
// same untagged binary, read the same refusal — and nothing in the loop says
// which file to start. The rename is only safe if the message that sends
// operators to it moved with it.
var ErrNotBuilt = errors.New(
	"randomx: this binary was built without the randomx build tag; " +
		"rebuild with `make build-randomx` and run the separate binaries it writes " +
		"(bin/zcd-randomx, bin/zycordd-randomx — not bin/zcd or bin/zycordd) to run " +
		"a network whose pow_engine is " + Name + " or " + NameV2)
