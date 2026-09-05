# The Windows manual run

**A template, and the record it becomes.** Nothing executes this tree on Windows
anywhere: `release.yml` cross-compiles the Windows archives and every job in it
runs on Linux or macOS, and the reusable workflow that once ran the whole suite
natively on `windows/amd64` is gone with every other job that executed something
([CONTRIBUTING.md](../../../CONTRIBUTING.md), [RELEASE.md](../../RELEASE.md) §0).
Compiling for a platform proves nothing a defect on that platform would show —
the four that got the deleted job written in the first place were green on every
Linux runner. So the run is done by hand, on a real Windows machine or a virtual
one, and it is written down here, because a run nobody recorded is a run nobody
can check.

**This file is filled in, not replaced.** Copy the two sections below, fill in
what was actually observed, and append the result under *Runs*. An empty run
section is the honest state until somebody types the commands; do not pre-tick
it. If a line failed, the finding is the run's whole value — record the failure
in place rather than re-running until it is green and reporting only that.

**What this is not.** Not a benchmark: nothing here is a timing claim, and a slow
VM answers every question below as well as a fast machine. Not a substitute for
`make ci`, which is green on Linux at the same commit or the release does not
proceed — this is the platform-specific half that Linux structurally cannot
reach.

## What to run

The command list is in [CONTRIBUTING.md](../../../CONTRIBUTING.md) and is not
restated here, so that there is one copy of it and it cannot drift from this
file. It carries the `make ci` targets that port (`lint`'s substance, `wiring`,
`guard`, `differential`, `bench-smoke`, the full suite), the four Windows
regression tests, `./update/`, the two `.exe` builds, and the desktop module —
and it names, inline, the three targets that deliberately do not port and the
recorded decision that `-race` is not among them.

After the list, the wallet smoke test below. Both halves are the run; a record
with only one of them is not a release evidence file.

## The wallet smoke test

The tree's wallet is three interfaces over one `wallet/session`
([WALLET.md](../../WALLET.md)), and the Windows-specific risk is not in the
rules — it is in touching the filesystem. `wallet/atomicfile_windows.go` and
`wallet/syncdir_windows.go` exist because a key file published to a FAT-formatted
stick silently degraded a publish tier and a directory fsync cannot succeed on
this platform at all. So the smoke test is about a key file being written,
re-read and spent from, on the platform's own filesystem semantics.

Using the `bin\zcd.exe` the command list just built, and a devnet so that no
mainnet key is created on a test machine:

```
bin\zcd.exe version
bin\zcd.exe wallet new --out smoke.json
bin\zcd.exe wallet address --key smoke.json
bin\zcd.exe genesis
```

**Three of those block on a passphrase prompt, and the document would otherwise
not say so.** `version` and `genesis` take no key and simply print and exit.
`wallet new` prompts for a passphrase and then prompts *again* to confirm it —
twice, on stderr, with no echo. `wallet address` and the `wallet balance` below
each prompt once, to open the key file they were handed. There is deliberately
no flag to supply a passphrase, because one on a command line lands in the shell
history and in the process table, so **this block cannot be scripted as
written**. If you must drive it non-interactively, `readPassphrase` falls back to
reading a plain line from stdin when stdin is not a terminal — that is a pipe
rather than a flag, and the passphrase then lives in whatever produced the pipe.
It is not recoverable either way, so use a throwaway one on a throwaway VM and
reuse nothing.

`wallet new` must refuse to overwrite an existing `smoke.json` rather than
clobbering it — that refusal is publish tier 1, `renameNoReplace`, and it is the
one the exclusive-rename regression tests pin. Run `wallet new --out smoke.json`
a second time and record the refusal; a second run that succeeds is a finding.

Then a node, and a balance read against it, which is the pair that exercises the
storage layer's Windows paths — the log handle, the directory sync, the file
lock — rather than only the wallet's:

```
bin\zycordd.exe --devnet --dir .devnet-smoke --mine --payout <the address above>
```

and, in a second PowerShell window, once the node has printed a few block lines:

```
bin\zcd.exe wallet balance --key smoke.json --devnet --rpc http://127.0.0.1:9420
```

Stop the node with Ctrl-C, start it again against the same `--dir`, and confirm
it re-verifies its chain from disk and continues rather than refusing. **That
restart is the point of this half**: it is the only step that reads back what
the Windows storage paths wrote, and the cold-start re-verification is where a
log that could not be truncated or a directory that was never synced turns into
a visible failure.

If the release's own `.zip` is what is being checked rather than a local build,
unpack the published archive and run the same walk against the binaries inside
it — that is [RELEASE.md](../../RELEASE.md) §8's released-binary item, and the two
overlap on purpose.

**Unverified as written.** Every command in this section is derived from the
tree — the subcommands from `cmd/zcd/wallet.go`, the flags from
[RUNNING.md](../../RUNNING.md) and [WALLET.md](../../WALLET.md), the risk
surface from the `_windows.go` files named above — and **none of it has been
executed on Windows**. The first person to run it is expected to correct it,
and correcting it is part of the run. An instruction nobody has run is a
hypothesis; that is why the first record below matters more than the template
around it.

## The record

For each run, one section, in this shape:

```
### <UTC date> — <commit sha>, <windows version>, <arch>

machine:      e.g. Windows 11 23H2, x86-64, 8 GiB, VM under <hypervisor>
go:           go version   (must be the version Makefile pins; see the toolchain
              header there — a different patch version is a different result)
clone:        fresh clone / existing clone renormalised (CONTRIBUTING.md's
              `git rm --cached -r .` then `git reset --hard`, if it was needed)
race:         not run — accepted (CONTRIBUTING.md) / run, with MinGW-w64 <version>

| line | result | notes |
| --- | --- | --- |
| `go vet ./...` | | |
| `gofmt -l .` | | printed nothing = pass |
| `go test -timeout 30m ./...` | | |
| the four regression tests | | |
| `go test ./update/` | | 2 of 8 in `install_test.go` skip; the other 6 exercise `replaceBinary` |
| `go test ./sim/wiring/` | | |
| `go build -tags zcdguard ./...` | | |
| `go test -tags zcdguard ./...` | | |
| `go test -run TestDifferential ./sim/` | | |
| `go test -run XXX -bench . -benchtime 1x ./...` | | |
| `zcd.exe` build | | |
| `zycordd.exe` build | | |
| `cd desktop`, `go test -tags desktop ./...`, `cd ..` | | |
| wallet: `version`, `new`, `address`, `genesis` | | |
| wallet: second `new` refused | | the tier-1 refusal |
| node: devnet mined blocks | | |
| wallet: `balance` against it | | |
| node: cold restart re-verified from disk | | |

findings: <one line each, or "none">
corrections to CONTRIBUTING.md or to this file: <one line each, or "none">
```

Paste the failing output verbatim for anything that was not green. A summary of
a failure is not evidence of one.

## Runs

**None yet.** Windows has not been executed at any commit since the runner was
removed. This is the residual `docs/DEFERRED.md` records, and the first entry
above this line is what converts it from *never* to *once, at commit X* —
and no further than that, deliberately: the reopen condition is per release, so
this is a recurring gate rather than a box that closes.
