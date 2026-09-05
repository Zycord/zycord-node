# Contributing

Contributions are wanted — and treated as hostile by default, because in a blockchain node **a merge is consensus power**. Nothing here is about you. It is about what a reviewer can verify from the diff alone.

## The two zones

The repository is split by blast radius, and the process differs sharply between them.

### Consensus zone — `core/`, `spec/`

Bugs here are unfixable after genesis. Everything in this zone is slow on purpose.

- **Open an issue first.** A pull request that changes a rule before the rule has been discussed will be closed, however good the code is.
- **Ship vectors with the change.** A consensus change that does not add or modify a golden vector in `spec/vectors` has not been specified, only written. Run `make vectors` and review the diff yourself before asking anyone else to.
- **Pass the griefing suite and the differential fold.** `make ci`. If your change makes `sim/refold` disagree with `core/fold`, the disagreement is the finding — do not "fix" the naive implementation to match.
- **Multiple maintainer ACKs.** Automated checks are a precondition for review, not a substitute.
- **`core/` imports nothing but the standard library.** No exceptions, not for a helper, not for a test dependency reachable from non-test code. `make check-imports` enforces it.
- **No maps iterated in consensus order, no clocks, no goroutines, no floating point.** Determinism beats performance in this zone, always.

If your change makes the fold faster and cannot be shown to be bit-identical, it belongs in `node/`, or it belongs nowhere.

#### Economic rules carry a higher burden still

Consensus code has a compiler and a differential fold. The economic layer has neither: every internally-consistent fee rule compiles, and every one of them passes a differential against itself. Two standards follow, both learned the hard way.

**Mutate both implementations, not one.** The differential fold catches `core/fold` and `sim/refold` *disagreeing*. It cannot catch them agreeing on the wrong design. So for any change to an economic rule, revert the rule in **both** and confirm that a property test still fails. If nothing fails, the rule is undefended and the tests are describing the code rather than constraining it.

**Write the rejected alternatives even when the choice feels forced.** "Feels forced" is the feeling of not having looked. The one significant gap in the M0 economic review was in a decision nobody thought needed arguing — see [H2-economics](docs/adversarial/H2-economics.md) and [R2-H1](docs/adversarial/R2.md).

**A test of an economic or policy rule must assert that the rejected rule would produce a different result *in the test's own scenario*.** A test that passes under both the rule and its negation is measuring the scenario, not the rule. The canonical example is R2-H2's first draft: it checked that a block of skips did not move the base fee, and passed — but at the parameters it used, counting the skipped gas would have given the same answer to the last digit, so it was asserting nothing. It now proves the two answers differ before comparing them.

**A property must exist before a test can observe it.** The two rules above assume the property is there and ask whether the test constrains it. This one comes first and is the harder discipline: before writing the test, name the property in one sentence and check the code actually has it. A test written against a property the code does not have will still go green — it will find some *other* true thing to assert, and it will look like coverage forever. Every vacuity we have found began this way, and none of them was caught by reading the test.

The three compose in order: state the property, write a test that fails without it, mutate to prove the test noticed.

**A check that can fire for a benign reason is not a check. It is noise with authority, and that is worse than silence.**

An invariant check that reports a violation which turns out to be ordinary behaviour does not cost nothing. It costs the credibility of every other output of the same apparatus, because the next real violation arrives in a format you have already learned to skim. A false positive is not neutral; it is negative.

The worked example: `assertBalancesAgree` compared balances across soak nodes without requiring them to be on the same chain. Balances are a function of height, so two nodes at different heights hold different balances and are both correct — and after a few kills, a freshly restarted node is legitimately behind. It duly reported four "nodes disagree about balance" errors that were arithmetic, not divergence. Divergence at equal tips is a finding; divergence at different tips is subtraction.

Every consensus check needs that shape: **compare only when the comparison is meaningful, and say why when you decline.** The declining branch is not an escape hatch, it is part of the check — a run that skipped the comparison and said so is honest, and a run that compared regardless is lying with numbers. And fix it when you find it: in a verification apparatus, flagged-but-unfixed compounds silently, because each check that can cry wolf lowers the signal value of every check beside it.

**An instrument that derives its signal from the state the bug corrupts inherits the bug's blindness.**

This is a domain property, not a run of bad luck. Every one of these was a tool built to catch a class of failure that had that exact failure:

| Instrument | Built to catch | Its own flaw |
|---|---|---|
| `go test -race` | data races | measures only the concurrency the tests create; the suite was single-goroutine, so it reported clean while `chain.Chain` had no lock at all |
| the borrow guard | use of state after its lock is gone | checked before the read and not after, so a read *spanning* the callback's return passed — 0 of 200 caught |
| the wiring check | exports nothing references | derived "referenced" from a walk that visits a declaration's own name, so every definition marked itself used |
| the `ahead_peers` heartbeat | a node silently failing to sync | reads `SyncCandidates()`, which applies the ban filter — so a node that has banned every peer able to tell it it is behind reports `ahead_peers=0`, byte-identical to a node at the tip |
| the chaos soak's miner | whether the network converges | paced block production with a fixed ticker against an instantly-solvable target, so every miner emitted a block at the same instant and the chains held *identical* weight — a state no fork-choice rule can resolve, because equal work correctly never switches. Convergence was precluded by the model, and the resulting non-convergence was read as protocol bugs for several cycles |

**A measurement is true about the conditions it was taken under. Extending it past them is a new hypothesis, and it needs its own scenario.**

This is the sibling of the mirror rule and it cost as much:

- Two mechanically-verified facts — the ban family, and inbound saturation — were each then assumed to be the cause of a specific node's stall. Neither was; a scenario built to arm them showed the node stalling for another reason entirely.
- Reorg depth measures 24 in the catch-up regime and 131 under continuous contention. There is no single number: depth is a property of the regime, and a run that measures one regime has said nothing about another.

The pattern is that **mechanical correlation plus a plausible reading is a hypothesis**, and nothing promotes it to a cause except a scenario that arms it and is watched firing. The same applies to numbers: a figure from one regime is a figure from one regime. Write the conditions next to the number, always, and treat any extension of it as an unproven claim requiring its own arm-and-watch.

**A model is an instrument.** The last row is the most expensive instance and the least obvious: not a check that could not fail, but a *simulation whose dynamics forbade the outcome it was measuring*. Real proof of work is a Poisson process; a fixed interval is a different physics, and under it three miners are permanently tied by construction. When you simulate something, the question is not only "does my check observe correctly" but "can the thing I am looking for even happen in this world".

The shape is the same each time: the signal is computed *downstream* of the thing that breaks, so when that thing breaks the signal breaks with it, silently and in the reassuring direction.

The rule that follows, and it applies to every operator-facing number: **a health signal must derive from state upstream of the policy it reports on.** `ahead_peers` filtered by bans cannot report a ban problem; it needs the raw score and ban counts as well. A coverage tool that infers coverage from the artifact it is checking cannot report that the artifact is empty. When you add an instrument, ask what it reads, ask what would corrupt that, and ask whether the corruption is the thing you built the instrument to find — because if it is, you have built a mirror.

**Consensus-state access rules are machine-checked, not reviewed.** `chain.Read` lends a borrowed reference that stops being valid when the callback returns, and using it afterwards panics — in every build, shipped included. Re-entering the chain from inside a callback panics in builds carrying `-tags zcdguard`. Neither is a style rule you are expected to remember: they are checked, because the project cannot assume a reviewer who was present for [I4-H1](docs/adversarial/I4.md). If you need state that outlives the call, `chain.Snapshot` gives you an owned copy and the type system will not let you confuse the two.

**A tool observes only the executions it is given.** The same trap, one level up. `go test -race ./...` passed cleanly across the whole suite while `chain.Chain` had no lock at all — because every test drove it from a single goroutine, and the race detector reports what actually happened, not what could. It said "ok" and meant "I was shown nothing". The bug that hid there is written up in [concurrency](docs/adversarial/concurrency.md). So: if code runs concurrently in production, a test must run it concurrently, deliberately, in the shape the process actually uses.

### Node zone — `node/`, `wallet/`, `sim/`, `cmd/`, `docs/`

Normal open-source flow: fork, branch, pull request. This is where new contributors are grown, and a first patch here is worth more than a first patch in `core/`. The simulator in particular is never finished — a new adversarial scenario is always welcome, especially one that fails.

**`docs/adversarial/` is two kinds of document, and only one of them tracks the tree.** The **topic** documents — [sync](docs/adversarial/sync.md), [mempool](docs/adversarial/mempool.md), [concurrency](docs/adversarial/concurrency.md) — are current, and the unit that moves a mechanism updates the one that owns it. The **review records** — `I1`…`I7`, `R1`, `R2`, `H2-economics` — are point-in-time and are not rewritten, because a finding edited to match the tree it describes stops being evidence of what the review actually found. The discriminator for anything added later is a marker the author writes deliberately: **a document that carries a `**Status:**` line tracks the tree, and one that does not is a record of a reading.** Declaring it is the act of taking on the currency obligation, so a new document is classified without asking whoever drew up the lists.

What a review record owes instead is a **link**: a finding whose fix describes a mechanism that is still live names the document that owns that mechanism now, so a reader arriving from a search is one hop from the current account instead of stranded on a true sentence about a tree that has moved. Write it when you write the finding — it is the one part a later reader cannot supply, and unlike a bare assertion of currency it leaves an artefact that either resolves or does not.

Two carve-outs, both narrow. A record's **Confidence** list is a forward list rather than a point-in-time one — [RELEASE §8](docs/RELEASE.md) gates on it and [testnet-measurements](docs/decisions/testnet-measurements.md) lifts entries out of it — so an item settled since is marked settled there. And when somebody does trip over one specific stale claim, the answer is one `*Amended.*` block on that finding, in the form [wire §12](docs/spec/wire.md) uses — **not** a licence to sweep the directory, which is the maintenance burden that produced the stale claims in the first place.

## Before you open a pull request

```sh
make ci          # vet, formatting, the import graph, every test, the differential fold
make fuzz        # a minute of decoder fuzzing; the farm runs hours
make check-links # every relative link in the documents resolves
```

**There is no CI. Your machine is the only gate, and nothing will catch this
for you.**

That is not a preference and it is not temporary. This project's forge account
was **permanently suspended, with no appeal**: workflow jobs computed RandomX
hashes — the engine test suite, and two jobs that started a built node and
waited for it to name its proof-of-work engine — and the forge's abuse detection
read repeated hash computation in a runner's log as using its infrastructure to
mine cryptocurrency, which its terms forbid. Everything went with the account.

So one workflow survives,
[`.github/workflows/release.yml`](.github/workflows/release.yml), and it compiles
release artefacts and does nothing else. **What may never go back:** any job that
runs a test, a fuzzer, a benchmark, a soak, the vector generator, or a built
binary of this project. The line to hold is not "no proof of work" but
*compiling* an artefact is fine and *running* it is not — so `make dist-randomx`
stays, and `make release-smoke`, which starts the archived node for two seconds
to read one line of its output, may not. When a job is arguable, it does not
ship: the cost of dropping a build check is a rebuild, and the cost of being
wrong twice is the account. `sim/wiring/workflow_test.go` holds all of that to an
equality — the set of workflow files, the set of jobs, the Make targets a
workflow may call — so the decision has to be taken in writing rather than by
adding a file nobody reads twice.

`make ci` covers lint, the import graph, the whole suite, the race detector, the
wiring guards, the differential fold and a benchmark smoke run. Beyond it, run
what your change touches: `make fuzz` for a decoder, `make test-randomx` and
`make repro-randomx` for `core/pow/randomx/`, `make canonical` and
`make canonical-dist-diff` for `build/Dockerfile`, `make repro` for anything that
could move a build byte, `make soak-long` for consensus or networking. A red run
pushed anyway is a red `dev`.

**On Windows, `make` is not the entry point and is not expected to be.** GNU make
is not installed on a stock Windows machine, and the recipes are POSIX `sh`
throughout. The equivalent is this list, which is what a job on a Windows runner
used to run and what a Windows contributor now runs by hand. Type it in
PowerShell, from the repository root, one line at a time — a list that stops at
the first red line is the point, and `&&` is not a PowerShell operator on the
versions Windows ships by default:

```
go vet ./...
gofmt -l .
go test -timeout 30m ./...
go test -count=1 -run 'TestRenameNoReplaceIsAnExclusiveRename|TestWriteFileNoClobberPublishesWithTheExclusiveRename|TestTruncateOpenLogWorksOnTheAppendHandle|TestSyncDirOnlyIgnoresUnsupportedPlatformErrors' -v ./wallet/ ./node/storage/
go test -count=1 -v ./update/
go test ./sim/wiring/ -count=1
go build -tags zcdguard ./...
go test -tags zcdguard ./...
go test -run TestDifferential -v ./sim/
go test -run XXX -bench . -benchtime 1x ./...
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' -o bin/zcd.exe ./cmd/zcd
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' -o bin/zycordd.exe ./cmd/zycordd
cd desktop
go test -tags desktop ./...
cd ..
```

Run those before opening a pull request, and note that `go build -o` there needs
an explicit `.exe`, because it does not add one. Windows is one of the six
platforms every release ships and nothing else exercises it — there is no runner
left that does.

**The list is written in POSIX `sh` and one line of it does not survive being
typed into PowerShell.** The whole document is `sh` throughout, which is right
for the other platforms and is a trap on this one, so the differences are
enumerated here rather than left to be discovered a line at a time. Windows
PowerShell 5.1 is what a stock Windows machine has; PowerShell 7 fixes some of
these and is not what is installed by default, so assume 5.1.

- **`VAR=value command` does not exist.** PowerShell sets an environment
  variable with `$env:`, on its own line, and `cmd.exe` uses `set VAR=value`.
  The two `CGO_ENABLED=0` build lines are therefore three lines:

  ```
  $env:CGO_ENABLED = '0'
  go build -trimpath -ldflags '-s -w -buildid=' -o bin/zcd.exe ./cmd/zcd
  go build -trimpath -ldflags '-s -w -buildid=' -o bin/zycordd.exe ./cmd/zycordd
  ```

  The variable persists for the rest of the session either way, which is what
  you want here and is worth knowing before the next command in that window.

- **`&&` is a parse error, not a runtime one.** Windows PowerShell 5.1 rejects
  it with *"The token '&&' is not a valid statement separator in this version"*,
  so a line containing it never runs at all. Both places this document joins
  commands with `&&` — the desktop module's `cd`, and the CRLF renormalise
  below — are written as separate lines for that reason. Do not rejoin them.

- **`cd desktop` is not scoped to one command.** In `sh`, `cd desktop && go
  test …` leaves the shell where it started once the line finishes; typed as
  two lines anywhere, it does not. The list ends with `cd ..` so the session is
  back at the repository root, which is where every other line in it expects to
  be. Getting this wrong is quiet: `go test ./...` from `desktop/` tests the
  desktop module and reports success.

- **Single quotes are fine, and are the safe choice.** PowerShell single quotes
  are literal, like `sh`, so `-ldflags '-s -w -buildid='` needs no change. Its
  *double* quotes interpolate `$`, which is why the quoting in this list is
  single throughout and should stay that way.

- **Path separators need no change.** Go's own tooling takes forward slashes on
  every platform, and `./...`, `./wallet/` and `bin/zcd.exe` are all read
  correctly by both shells. Only a path handed to a *Windows* program — the
  `bin\zcd.exe` invocations in the run record — wants backslashes, and
  PowerShell accepts either there too.

- **Nothing in the list redirects, globs, substitutes or deletes.** There is no
  `$(...)`, no `2>&1`, no `/dev/null`, no `rm` or `cp`, and no wildcard. That is
  not an accident and is worth preserving: those are the constructs whose
  `sh`-to-PowerShell translations are individually easy and collectively the
  reason a ported script drifts. Keep new lines in the same shape — one
  program, its flags, no shell.

**How the list maps onto `make ci`, and what deliberately does not port.** The
first four lines above are `lint` and the Windows regressions; the five that
follow are `wiring`, `guard`, `differential` and `bench-smoke` re-expressed as
the plain `go` invocations their recipes already are — cheap to add, so they are
added. `./update/` is on the list on its own account rather than as part of
`make ci`: it carries `replace_windows.go`, `exec_windows.go`,
`guard_windows.go` and `syncdir_windows.go` — four files no Linux run compiles
at all — and the rename-the-running-image technique in the first of them is
Windows-only behaviour with no equivalent anywhere else in the tree.

**That line is a targeted check rather than a generic one, and it is worth
knowing what it reaches.** `update/install_test.go` has eight tests and exactly
two of them skip on Windows: `TestTheExecutableIsStillThereAtEveryPointOfTheReplace`,
because the platform must rename the running image aside and the two-syscall
window that opens is documented rather than tested away, and
`TestASymlinkIsFollowedAndLeftAlone`, because creating a symlink needs a
privilege a test should not assume it has. **The other six run**, so
`replaceBinary` — the rename-a-running-mapped-image path, which exists only on
this platform and which no other test in the tree can reach — is genuinely
exercised by this line and not merely compiled. If either of the two skips
prints on a machine where you expected it not to, that is worth a note in the
record; a skip that has become silent is how a platform stops being tested. Three targets stay
behind, each for a reason rather than for convenience:

- **`lint`'s Makefile wrapper.** Its substance — `go vet ./...` and `gofmt -l .`
  — is the first two lines of the list. The wrapper around them (`tee
  /dev/stderr`, `test -z`) is POSIX plumbing that turns a printed filename into
  a non-zero exit; on Windows, read the output. `gofmt -l .` printing nothing is
  the pass.
- **`check-imports`.** It is POSIX shell with `grep -E` and `sort -u`, and a
  PowerShell re-expression of it would be a second implementation of one guard,
  which is a thing that drifts silently and then disagrees. What it checks is a
  property of the *source* — which packages import which — and source does not
  vary by operating system, so the Linux run covers it completely. Do not port
  it.
- **`race`.** The race detector on `windows/amd64` requires cgo, and cgo on
  Windows requires a MinGW-w64 `gcc` on `PATH` ([docs/INSTALL.md](docs/INSTALL.md)
  discusses that toolchain for the RandomX tier). **The decision, recorded here
  rather than left to whoever is at the keyboard: `-race` is not part of the
  Windows list, and Linux `-race` is what covers the tree.** The races this
  project has had were in the miner, the peer goroutines, the sync driver and
  the RPC server — none of that is platform-specific code, and all of it is
  compiled and raced on Linux. What *is* Windows-specific is file publication,
  log truncation, directory sync and process control, and those are exercised by
  the regression tests and `./update/` above, under the platform's real
  syscalls, which is the coverage that could not be had anywhere else. If you
  have MinGW-w64 installed anyway, `go test -race -timeout 45m ./...` is worth
  running and worth recording; it is not required, and its absence is accepted
  rather than overlooked.

A run of this list at a tagged commit is release evidence and is recorded as
such — [docs/RELEASE.md](docs/RELEASE.md) §8 asks for it, and
[docs/localnet/soaks/windows-manual-run.md](docs/localnet/soaks/windows-manual-run.md)
is the template it is written into, alongside the other runs this tree keeps
rather than quotes.

**If you cloned before `.gitattributes` existed, rewrite the working tree once.**
That file gives every text file LF, but only as git rewrites each file, so an
existing clone made with the Git for Windows default keeps its CRLF working tree
while `git status` reports clean — the clean filter normalises on the way in, so
nothing signals it — and `gofmt -l .` names most of the repository.

`git add --renormalize .` does **not** fix this, and neither does
`git checkout .` after it: the index already holds the LF blobs, so nothing is
staged and nothing is considered changed (measured — "Updated 0 paths", and 173
files still CRLF). What works is making git write every file again. **Commit or
stash first: this discards uncommitted changes.**

```
git rm --cached -r .
git reset --hard
```

Measured on such a clone: `gofmt -l .` from 173 files to 0. A fresh clone needs
none of this.

Windows is not a second-class target: it is one of the six platforms every
release ships. It went untested for a long time, and the cost is stated here
rather than pointed at, because the job that measured it no longer exists and
neither does the discussion it was opened in. Four defects were green on every
Linux runner and failed only on a Windows one: a directory fsync that cannot
succeed there, a log handle opened `O_APPEND` that cannot be truncated through, a
node binary built without `.exe`, and a publish tier that silently degraded on
exFAT. The four tests in the command list above are what those left behind; run
them, because nothing else will. `docs/DEFERRED.md` carries the standing residual
that no runner executes this tree on Windows at all any more.

- Code and comments in **English**, always.
- Comments explain *why*, not *what*. A comment that restates the line above it is noise; a comment that records the attack a rule prevents is the most valuable thing in the file.
- Every consensus rule cites the review finding it comes from (`R1-C1`, `I1-M3`, …) so that a reader can find the argument.
- Tests are named for the property they pin, not for the function they call.
- No new dependencies without a dedicated pull request that argues for the dependency on its own.

## Commits and releases

- Commits in a release are PGP-signed.
- The local gate must be green before you push. There is no CI to be red for you — see "Before you open a pull request" — and a failure you did not understand is not "flaky", it is a failure you have not understood yet.
- Vendored dependencies change only in a pull request that changes nothing else.
- Releases build byte-identically from source. If your change breaks reproducibility, it is a breaking change regardless of what it does.

## Anonymity

This project is anonymous, and that is a property of the artifacts rather than of anyone's intentions. Please do not commit anything that identifies you or anyone else: no real names, no email addresses in code or fixtures, no local filesystem paths, no editor or OS metadata, no company identifiers. `-trimpath` handles paths in binaries; `.gitignore` handles the usual editor debris; the rest is on us to notice in review.

If you would rather contribute pseudonymously, that is the expected case, not a favour.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## What a good consensus patch looks like

1. An issue describing the rule and the attack it addresses.
2. A failing test — ideally a griefing-suite scenario — that demonstrates the problem.
3. The rule change, in the smallest diff that fixes it.
4. Regenerated vectors, with the diff explained in the pull request body.
5. A note in the architecture spec's changelog and decisions log.

Slow is correct here. A protocol that ships a month late is a protocol; a protocol that ships a re-billing hole is an anecdote.
