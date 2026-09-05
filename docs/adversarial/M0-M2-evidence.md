# Zycord — M0 and M2 evidence runs

**Scope:** the two long-running checks the [status table](../../README.md) carried as
*in flight* rather than *done* — the 72-hour decoder fuzz behind M0, and the multi-day
chaos soak behind M2. This file is the record those rows were waiting on.

**Why this file exists at all.** Both runs had been performed before and their logs were
not kept, so the rows said *in flight* with a date instead of ✅. The rule the table set
itself was that the row changes when there is a record to link, not when somebody
remembers a run going green. Everything below is transcribed from logs that exist; where
a number is not in a log it is not here.

---

## The runs

| | M0 — decoder fuzz | M2 — chaos soak |
|---|---|---|
| Command | `go test -run=XXX -fuzz=<target> -fuzztime=36h ./core/types/` | `go test -run='TestChaosSoak' -timeout=14h ./sim/chaos/` |
| Targets | `FuzzDecodeCertificate`, then `FuzzDecodeBlock` | four tests, listed below |
| Verdict | **PASS**, `exit=0` on both | **PASS**, `ok`, `exit=0` |
| Wall clock | 129 600.131 s + 129 600.137 s | 43 573.776 s |
| Host | dedicated 2-core build host, nothing else running | a 6-core developer machine |
| Tree | after the self-updater landed — `update/` present | before it — no `update/` in the tree |

`129600` is exactly 36 h. Both targets exited on the time budget rather than on a
finding, which is the outcome the budget was chosen to produce.

### M0 — what the fuzz covered

Sequential, never concurrent: one target at a time on the whole machine.

| | `FuzzDecodeCertificate` | `FuzzDecodeBlock` |
|---|---|---|
| Executions | **3 760 063 822** | **4 266 177 710** |
| Rate | ~28 200/s | ~26 500/s |
| Corpus at exit | 111 entries, 95 newly interesting | 112 entries, 108 newly interesting |
| Crashers written | **0** | **0** |

**8.03 billion executions**, no `testdata/fuzz/` entry produced by either target.

The property under test is the one the harness asserts: a `[]byte` that
`UnmarshalCertificate` (or `UnmarshalBlock`) accepts must re-encode to **the same bytes**.
A decoder that accepts a non-canonical encoding of a valid object is the defect this
looks for, because two peers that disagree about which bytes mean a thing disagree about
its hash, and therefore about the chain.

### M2 — what the soak covered

```
--- PASS: TestChaosSoak                                              (14414.70s)
--- PASS: TestChaosSoakUnderContinuousContention                     (14420.58s)
--- PASS: TestChaosSoakLateJoinerCatchesUp                           (14704.86s)
--- PASS: TestChaosSoakRevivesANodeKilledInsideTheConvergenceWindow  (   33.60s)
ok  	zycord/sim/chaos	43573.776s
```

Both regimes the milestone asks for are present and each ran for four hours: convergence
after the chaos stops, and agreement on history under contention that never stops. The
late joiner catching up is the third, and the fourth is the narrow case of a node killed
inside the window where convergence is still in progress.

Two assertions were required to be more than incidental, and both are in the log:

- **the consensus-state guard armed on every node** — reported three times, once per
  soak that runs a full node set;
- **an epoch boundary crossed** — the run reached `height=3316` with `epoch_length` 64,
  which is **51 boundaries**, not the one the requirement asks for.

---

## What these runs do not establish

**The fuzz says nothing about the encoder.** It asserts that what the decoder accepts
round-trips. An encoder that emits a form no decoder would accept is invisible to it;
that is the golden vectors' job.

**Neither run is a proof, and the fuzz is the weaker of the two.** Coverage-guided
fuzzing explores what the corpus reaches. 8 billion executions with no finding is
evidence that the reachable space is clean, not that the space is small. The corpus grew
from 25 entries to 112 during the block run — 108 of those newly interesting — so the
frontier was still moving when the budget expired.

**The two runs are on different trees, and are recorded separately rather than averaged
into one claim.** The soak ran on the tree as it stood before the self-update mechanism
landed; the fuzz ran after it, on a tree with `update/` in it. Everything separating the
two is that work and the desktop, wallet and packaging changes beside it: `core/` and
`node/` are byte-identical across the pair, and the only change anywhere under `sim/` is
the line adding `update/` to the swept-path list of the guard in
`sim/wiring/history_reference_test.go`. Neither the decoder the fuzz targets drive nor the
chaos harness moved between them, so the gap does not bear on either result — but a
measurement is reported against the tree it ran on, not against a tree chosen afterwards.

**Neither ran on a hosted runner, and neither can.** Everything that exercises this tree
now runs on a developer machine before a push; see
[RELEASE.md](../RELEASE.md) for what that leaves the release workflow doing.

---

## A note on the runs that were discarded

Three earlier attempts at the M0 fuzz were thrown away rather than reported, and the
reason is worth writing down because it will happen again to somebody.

Two of them died mid-run with `fuzzing process hung or terminated unexpectedly: exit
status 2`, each writing a "failing input" that **did not reproduce** — the input replayed
clean in under a hundredth of a second, including under a hard memory cap. Go writes the
last input it handed the worker, and when the worker dies for a reason unrelated to that
input, the file names a bystander.

What actually killed them was contention: another process was compiling the same module
on the same machine. The evidence is in the corpus, not in the crash. The strangled run
found **1** newly interesting input in fourteen hours; the dedicated run found **95** in
the first target alone. The billions of executions the strangled run reported were in
large part re-treading ground.

A third attempt died eleven seconds after the SSH session that started it closed:
`Linger=no`, so the user service manager tore the unit down on logout.

**The lesson that survives all three: a long run on a machine that is not exclusively
yours is not a long run.** It produces a number that looks like evidence and is not one.

---

## Reproducing

The fuzz, one target at a time, on a machine doing nothing else:

```sh
rm -rf core/types/testdata/fuzz          # a stale crasher replays as seed corpus
go test -run=XXX -fuzz=FuzzDecodeCertificate -fuzztime=36h ./core/types/
go test -run=XXX -fuzz=FuzzDecodeBlock      -fuzztime=36h ./core/types/
```

The soak, which needs the longer timeout because the default 10 m kills it:

```sh
go test -run='TestChaosSoak' -timeout=14h ./sim/chaos/
```

Expect two `exit=0` and one `ok`. Expect no `testdata/fuzz/` directory afterwards; if one
appears, the entry in it is the finding, and the first thing to establish is whether it
reproduces.
