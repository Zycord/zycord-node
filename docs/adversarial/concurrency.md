# Zycord — Concurrent access to consensus state

**Status:** found by the chaos soak, fixed, pinned by tests. Recorded because the *way* it was missed generalises.

## 1. The bug

`chain.Chain` holds the in-memory consensus state, the tip header and the height. It had no lock.

A running node touches it from at least four goroutines:

| Goroutine | What it does |
|---|---|
| the miner | reads state and tip to assemble, then writes by applying |
| one message loop **per peer** | writes by applying gossiped blocks and branches |
| the sync driver | writes by applying validated branches |
| the RPC server (one goroutine per request) | reads state, tip, height |

So state was read while it was being written, and written while it was being written.

## 2. Why it was not merely a stale read

An unsynchronised read of a counter gives you an old number. An unsynchronised read of consensus state gives you a number that was never true.

The miner's `Assemble` read the base fees from state, then — at an epoch boundary — computed the state root the block would produce. If a gossiped block landed between those two reads, the header committed to a root derived from a **mixture of two chains**. No fold anywhere reproduces such a root, so the block is invalid on every node including its author.

Three properties made it much worse than a single rejected block:

- **State roots are only checked at epoch boundaries.** The mismatch is detected at the next boundary, which can be dozens of blocks after the moment that caused it, on a different node, during sync.
- **The reported error names the wrong place.** `state root mismatch at epoch boundary height 64` points at height 64. Nothing was wrong at height 64.
- **It is load-dependent.** One miner and no peers never triggers it. The failure needs concurrency that only a real network produces.

## 3. Why the tests did not find it

This is the part worth keeping.

`go test -race ./...` passed cleanly the whole time, across the entire suite, with zero warnings. That was read — by us — as evidence of the absence of races.

It was not. **Every test drove the chain from a single goroutine.** The race detector is not a static analysis: it observes actual memory accesses and reports pairs that actually happened without synchronisation. A concurrent bug in code no test runs concurrently is invisible to it, and it reports that invisibility as success.

The generalisation, which now sits in CONTRIBUTING:

> A property must exist before a test can observe it — and a *tool* observes only the executions it is given. `-race` on a single-goroutine test suite measures nothing and says "ok".

The corollary is that concurrency needs a test that *is* concurrent, written deliberately, exercising the same access pattern the process has. `TestChainSurvivesConcurrentAccess` is that test: a miner, a block applier and a reader, all on one chain, all at once. Under `-race` it reported 12 data races against the unsynchronised chain.

## 4. Why the chaos soak found it

The soak runs real `zycordd` processes on real sockets with real schedulers, kills them at random, and partitions the links. It produced the access pattern nothing else did: three miners racing, gossip arriving mid-assembly, and sync applying branches concurrently with mining.

It found the bug **without knowing what it was looking for** — the failure it reported was "the network did not converge", and the diagnosis took working backwards from a state root mismatch to a torn read.

That is the argument for keeping it, and it produced a second finding on the way.

A 25-second soak passed throughout, because devnet's epoch length is 64 and the soak never got past height 11 — so the only check that can detect this class of divergence never ran. The four-minute run that found the bug reached height 63. **One block short.** The run after the fix converged at 63 as well and reported success, having still never crossed a boundary.

The soak now runs on its own parameter set with an epoch length of 8, so the check runs repeatedly inside the default 25 seconds, and `assertSoakCrossedABoundary` fails the run outright if it did not reach a boundary — with a message saying so, rather than letting a green result stand for a test that was switched off. A different parameter set is a different genesis is a different network id (R3-1), so those nodes cannot reach devnet; that is correct and costs nothing.

## 5. The fix

`Chain` gained a `sync.RWMutex` guarding state, height and tip **together** — they are one value in three fields, and a tip without the state that produced it is not a consistent read of anything.

The accessor that handed out `*state.State` was **removed** rather than locked, because no lock inside an accessor can protect the pointer after it returns. It is replaced by two shapes:

- `Read(fn func(View))` — runs the callback under the read lock. The state pointer is valid only inside `fn`. This makes the safe window syntactically visible instead of documented.
- `Snapshot() View` — a detached clone with its tip, for callers that must hold state across a long operation.

The miner now assembles against a `Snapshot`, which can go stale while the block is hashed, and `Apply` re-checks the parent under the write lock. **Optimistic assembly, validated commit**: a stale template is rejected as `ErrStaleTemplate`, which is not an error condition but what losing a race looks like on a live network.

Removing the accessor rather than deprecating it was deliberate. The compiler then required every call site to be revisited, which is the only review process that cannot be skipped.

## 5b. R5-G2 — the two rules are no longer enforced by review

The fix above left two rules standing on human discipline: the borrowed state must not outlive the callback, and the callback must not re-enter the chain. In a project whose stated destiny is the absence of its author, "enforced by review" means "enforced by nobody after genesis" — and the rule whose violation silently re-creates §1 was one of the two. Both are now machine-checked.

**Rule 1 — the borrow — is enforced by the type system and a liveness flag, in every build.**

`Read` and `Snapshot` no longer return the same type. `Read` lends a `View` whose `State` is a `StateRef`: a value type holding a pointer to an `atomic.Bool` that `Read` clears when the callback returns. Any use afterwards panics at the point of use. `Snapshot` returns a `Snapshot` holding a real `*state.State`, because that one is a detached clone the caller owns. The two lifetimes are two types, so a borrow cannot be mistaken for an owned copy downstream — which it previously could, since both were `View`.

`StateRef` also exposes only `Get`, `IsSpent`, `Seen`, `Root` and the two counters. That is not minimalism for its own sake: the mempool's parameter widened from `*state.State` to a three-method `StateReader` interface, so the pool lost the *capability* to retain or write through a state pointer rather than merely declining to use it.

**This check carries no build tag.** Its cost is measured, not asserted — `BenchmarkChainRead`, run with the guard removed for comparison: **+17.5 ns and one 4-byte allocation per `Read`**, and *flat*, because a ten-access `Read` costs the same +14.5 ns as a one-access one; the per-access atomic load vanishes into the map lookup beneath it. The argument for paying that everywhere is §3's: a guard compiled only into test binaries protects only the executions the tests produce, and the executions that break this rule are by definition the ones nobody thought of.

**Rule 2 — reentrancy — is detected before the lock is taken, in guarded builds.**

The obvious implementation was a watchdog on lock acquisition: a reentrant `Read`→`Apply` deadlocks, so time it out and panic. Measuring Go's `RWMutex` directly settles why that is the wrong mechanism:

| Sequence, same goroutine | Result |
|---|---|
| `RLock` → `Lock` (Read then Apply) | **always blocks** |
| `RLock` → `RLock` (Read then Read), no writer queued | **succeeds** |
| `RLock` → `RLock`, with a writer queued | **blocks** |

The middle row is the whole problem. A nested `Read` works in a quiet test suite and deadlocks in production the moment a writer queues behind it — correct-looking, load-dependent, invisible to the tests that exist. That is this project's signature bug, and a watchdog is blind to it precisely there. So detection is a goroutine-scoped set of chains currently under `Read`, checked *before* the lock, giving a located panic with the offending frame still on the stack instead of a process that stops answering.

It is keyed by `(goroutine, chain)` rather than by goroutine, because in-process multi-node tests run several chains and `chainA.Read(func(){ chainB.Apply(…) })` is not reentrancy — different mutexes, nothing deadlocks. A guard with false positives is a guard somebody switches off.

The goroutine identity costs ~3µs, which is why this half is behind `-tags zcdguard` (and `-race`, so CI gets it free).

**Armed-ness is observable, and the soak asserts it.** A build tag that does not match a constraint is silently ignored by the Go toolchain, so a typo would produce a run that looks exactly like a guarded one and checks nothing. `zycordd` logs `state_guard=on|off` at startup; the chaos soak builds its nodes with `-tags zcdguard` and reads that line back before any chaos starts, failing if it says `off`.

**And the guard fires.** Seven tests violate the rules deliberately — outer-variable assignment (the house idiom, and the likeliest future escape), a struct field, a goroutine started inside the callback, nested `Read`, `Apply` inside `Read` — and each asserts the panic *and its wording*, since a panic from somewhere else would pass a test that only checked "it panicked". Mutating out either check fails them. The anti-vacuity guard on the whole file is `TestOwnedSnapshotStateSurvivesTheCall`: an owned snapshot used long after the call must **not** panic, or the other six would pass against a mechanism that simply panicked on everything.

**What this still does not cover.** The guard knows about one lock. Six call sites establish the order `chain.mu` → `pool.mu`, and a future `pool.mu` → `chain.mu` path would be an ABBA deadlock that the guard certifies as clean and `-race` cannot see either. What makes the inversion impossible is that the mempool cannot reach the chain — it takes state as a parameter and holds no reference — and that was an accident nobody was defending. It is now an import rule in `make check-imports`: `node/mempool` must not depend on `node/chain`, `p2p`, `sync`, `rpc` or `miner`, and `node/storage` on nothing at all.

## 6. What this does not fix

**The lock is coarse.** Every read of any cell takes the same lock every block application holds. At Era 0 volumes this is irrelevant, and a lock that is obviously correct is worth more than one that is fast — but it is a known scaling limit, not an oversight, and it should be measured on the M3 testnet before it is optimised.

**~~`Read` has a discipline the compiler cannot enforce~~** — closed by R5-G2, §5b. Rule 1 is enforced in every build; rule 2 in guarded builds, which the soak now runs.

**The guard has never fired on a real violation**, only on the ones written to test it. Its value is entirely prospective, and prospective value is only realised in builds that carry it — which is the argument that made rule 1 always-on and made the soak build with the tag.

**Storage is not covered by this.** `storage.Store` has its own synchronisation; nothing here changes it.

## 7. Pinned by

| Test | Property |
|---|---|
| `TestChainSurvivesConcurrentAccess` (`-race`) | Miner, applier and reader on one chain concurrently produce no data race, and memory agrees with disk afterwards. |
| `TestConsiderBranchAcrossEpochBoundary` | A reorg that crosses an epoch boundary lands on the branch's state root exactly. This path had never been tested: the branch builder *refused* to cross a boundary. |
| `TestPoolSurvivesConcurrentAccess` (`-race`) | Eight writers and a reader leave the pool's two indexes agreeing with each other. |
| `TestEngineSurvivesConcurrentHandling` (`-race`) | Ten peers flooding the same blocks do not defeat the seen-cache or overfill the orphan pool. |
| `TestStoreReadsAreNeverHalfApplied` (`-race`) | A multi-key read racing a writer never returns a mixture of two batches. |
| `TestChaosSoak` | Real processes under loss, latency, partition and kill-9 converge on one chain, one tip, one state root — and the run fails if it did not cross an epoch boundary, because below one the state-root check is off. |

`make ci` now runs `make race`.

## 8. The rest of the audit

The same question, asked of everything else more than one goroutine touches. All three now have a deliberately concurrent test, and all three passed — which is a different and much weaker statement than "`-race` was clean", because these executions actually happened.

**`mempool.Pool`** — written by every peer's message loop and by the miner's `OnBlock`, read by the builder and the RPC. Its compound operations (screen-then-insert, evict-then-admit) are each inside one critical section. `TestPoolSurvivesConcurrentAccess` runs eight writers against a reader and checks the bookkeeping agrees with itself afterwards: the per-underwriter counts and the resident set are two maps that a lost update would separate.

**`p2p.Engine`** — its seen-caches, pending map and orphan pool are all check-then-act. `TestEngineSurvivesConcurrentHandling` has ten peers offer the same six blocks three times over, simultaneously, and asserts the orphan pool did not accumulate duplicates. That matters beyond tidiness: the byte bound on the orphan pool is what R4-H1 rests on, and a check-then-act race would let it be exceeded silently.

**`storage.Store`** — the audit found no bug and did correct a misunderstanding, which is worth recording because it is the same rule from the other side.

The first version of the test asserted that two `Get` calls for two keys written by one batch always agree. It failed. The store was right and the test was wrong: `Commit` holds the write lock from the fsync through to the in-memory apply, so **any single read** — `Get`, `Has`, `ScanPrefix` — is atomic with respect to a batch, but two separate calls are two separate reads and a commit may land between them. Cross-call consistency was never offered and is not needed, because callers that need several keys together hold a lock of their own across the reads. That is precisely what `chain.Read` is, and why it is a callback rather than an accessor.

`TestStoreReadsAreNeverHalfApplied` asserts what is actually true: a multi-key `ScanPrefix` racing a writer never returns a mixture of two batches.

The lesson is symmetrical with §3. There, a passing tool meant nothing had been asked. Here, a failing test meant the wrong thing had been asked. Neither is settled by the result alone.
