# A multi-node devnet convergence soak

A local network of four `zycordd` processes on the **dev engine** — no RandomX,
so the CPU goes into running the protocol rather than into a work function —
mining five-second blocks at each other across a deliberately hostile link,
for two hours, while the harness kills nodes, restarts them, and partitions
them from one another.

The question is the one a network has to answer before anybody trusts it:

> **do all the nodes end up on the same chain, how far behind the tip does a
> node run while they get there, and does anything grow without bound on the
> way?**

The first part was already covered. The second and third were not, and that is
what this run added.

## What was reused, and what was added

The chaos suite in [`sim/chaos`](../../../sim/chaos) already does the hard part
and it was not rebuilt. It starts real processes on real sockets behind a proxy
that injects latency, jitter, loss and severed connections; it kills and
revives nodes on a seeded schedule; it drives real certificate load; and it
asserts that every surviving node converges to one chain with one state root.
Its regimes, its port reservation, its liveness monitor and its exit reporting
are all prior work.

Two things it did not have were added, both small and both out of the way of
everything that was already there.

**A settled-height id check.** The existing convergence test compares every
node's `height`, `tip` and `state_root` at one instant, which is the right
question at the end of a regime that leaves a single miner running. It is a
weaker question than it looks while miners are racing: heights oscillate, so
processes sampled between blocks can agree on a tip and be about to disagree.
A height *below* every node's tip cannot oscillate that way — every node has
already built past it — so `assertSettledHeightAgrees` backs off one epoch from
the shallowest tip and asks every node for the block id at that height. One id
is convergence. Two is a divergence, and there is no amount of further running
that resolves it.

**An out-of-band sampler.** Nothing in the tree measured propagation delay or
resource growth. `ZCD_SOAK_SAMPLE=15s` starts a poller that records, for every
node, its height, its trail behind the highest node, its resident memory, its
thread count, its open file descriptors and its data directory size. It writes
a TSV beside the node logs and prints percentiles at the end.

The sampler **asserts nothing**, and that is deliberate rather than timid. A
state-root divergence is a defect on any machine; a node trailing four blocks
is a defect on an idle machine and unremarkable on a machine running five other
test suites. Turning a reading into a threshold would have manufactured exactly
the load-sensitive failure this project keeps complaining about. It is off
unless the environment variable asks for it, so every run recorded before it
existed remains comparable.

## The network

| | |
| --- | --- |
| nodes | 4 — three miners (`a`, `b`, `c`) plus one outbound-only peer (`d`) |
| engine | `dev-blake3`; no RandomX, by design |
| block target | 5 s |
| epoch length | 8 blocks, so the state-root check runs constantly |
| `undo_depth` | 1024, raised from devnet's 128 so reorg depth is not censored by the parameter |
| link | 15 ms latency, 0-35 ms jitter, 0.1% chunk loss, 0.05% chunk severance, both directions |
| build | `-tags zcdguard`, verified armed from each node's own log before any chaos |

Four is the shape the suite was calibrated for, and it was left alone on
purpose. The roster is enumerated in a port reservation whose span is asserted
exactly, and the contention regime's 256-block history horizon was measured
against *this* number of miners. Adding nodes would have invalidated a constant
that took several corrections to get right, in exchange for a convergence claim
that is not much stronger: with three miners racing, the fork choice is already
being asked the hard question.

## Regimes run

**Convergence after the chaos stops.** Chaos throughout, then all but one miner
is stopped and the network is given a window to agree. One miner makes
convergence a property rather than a coincidence — it accumulates strictly more
work and every other node must follow it. Ends with the tip comparison and the
settled-height id check.

**History agreement under continuous contention.** Every miner mining, all the
time, while the links misbehave — the state a live network is actually in. Tip
agreement is neither expected nor required here, because two branches of equal
work are entitled to disagree. What is required is that every node's history
below the reorg horizon is a prefix of one chain, checked cumulatively
throughout rather than once at the end, so a divergence that is created and
then reorged away is still caught.

## Results

Raw per-node series, with a header on each explaining how to read it:
[`devnet-convergence-samples.tsv`](devnet-convergence-samples.tsv) for the
single-miner regime and
[`devnet-convergence-contention-samples.tsv`](devnet-convergence-contention-samples.tsv)
for continuous contention.

### Convergence after the chaos stops

The chaos was not gentle: **191 kills and 379 partitions** across the 55
minutes. At the end of it, with two of three miners stopped:

```
converged: 4 nodes at height 1015 on one chain, one tip, one state root
settled convergence: height 1007,
  id 0xa21fd355d7a48029c7593956f0c1f9fabd776e91ef21816c61d96057cddf3f28,
  agreed by 4/4 nodes (a,b,c,d)
crossed 126 epoch boundaries
```

The second line is the one that matters. Height 1007 is eight blocks below the
shallowest tip, so every node had already built past it, and all four returned
the same id for the block there. That is convergence stated as a fact about
history rather than about a lucky instant.

The third line is the anti-vacuity guard: 126 epoch boundaries means the
state-root check ran 126 times rather than never, so agreement here is
agreement about state and not only about block ids.

The load driver submitted **2376 certificates, 2373 accepted**, and the billing
law held across **736 certificate inclusions in 1015 blocks with no
duplicates** — so the chain was carrying real transactions, not converging on
empty blocks. The liveness monitor took 12,607 process-state samples and found
**no node dead unbidden**.

### Latency

| measure | p50 | p90 | p99 | max |
| --- | --- | --- | --- | --- |
| trail behind the highest node (blocks) | 0 | 1 | 2 | 11 |

Across **850 node-samples**. Half the time every node is exactly level with the
tip; 99% of the time a node is within two blocks of it. The maximum of 11 is a
node catching up after the harness killed it, which is the instrument working.

Tip propagation to all four nodes, over **151 tips that every node adopted**:
p50 **0 s**, p90 **0 s**, max **15 s**. The sampler polls every 15 s, so a zero
means "faster than one poll" and not "instant" — this method cannot resolve
below its own interval, and the honest statement is that 90% of universally
adopted tips reached every node inside fifteen seconds.

### Resource growth

Per node, start to end, with the peak in brackets:

| node | RSS start → end (peak) | threads peak | fds peak | disk peak |
| --- | --- | --- | --- | --- |
| a | 13.3 → 35.6 MB (49.2) | 13 | 21 | 6.7 MB |
| b | 16.4 → 40.0 MB (50.8) | 13 | 19 | 6.7 MB |
| c | 15.6 → 39.0 MB (69.6) | 13 | 19 | 6.6 MB |
| d | 15.5 → 30.6 MB (30.6) | 13 | 15 | 6.7 MB |

**Threads and file descriptors did not move.** Thirteen threads and at most 21
descriptors at the start, the same at the end, with no trend in between. Those
are the two counters a leak shows up in first, and neither moved.

**Memory grew, and grew more slowly than the chain.** Peaks are the wrong thing
to read — Go's collector produces a sawtooth, and node `c`'s 69.6 MB peak at
t=1710 was back to 27.4 MB by t=1755. The floor is the diagnostic, and per
ten-minute window it went:

```
t=0     floor 13.3 MB   height  278   disk 1.5 MB
t=600   floor 17.1 MB   height  515   disk 2.8 MB
t=1200  floor 14.3 MB   height  665   disk 3.9 MB
t=1800  floor 19.4 MB   height  780   disk 5.0 MB
t=2400  floor 23.1 MB   height  930   disk 6.1 MB
t=3000  floor 25.7 MB   height 1015   disk 6.7 MB
```

Memory ×1.9 against chain ×3.7 and disk ×4.4, and the floor is not monotonic —
it fell between t=600 and t=1200. That is a cache tracking a growing chain, not
a leak. **It is not a claim that memory is flat**, and a run long enough to
reach a steady-state chain size is what would settle whether it plateaus; this
one cannot, because the chain never stopped growing.

Disk grew to 6.7 MB for 1015 blocks, in step with the chain, as it must.

### History agreement under continuous contention

The second regime, and the harder question: every miner mining for the whole
run, **199 kills and 368 partitions** over 50 minutes, with the network reaching
height 1000.

```
history: 744 heights verified to 744 (network reached 1000);
  3.96 nodes per height on average, 33 heights compared across fewer than 4
deepest observed reorg: 3 blocks (horizon 256)
billing law: 874 certificate inclusions across 1000 blocks, no duplicates
load: 2357 certificates submitted, 2357 accepted
```

**744 heights verified with no divergence** is the result. Every one was checked
against every node that could answer, cumulatively and without gaps, so a
divergence created and then reorged away would still have been caught.

The 33 partial comparisons are heights where a node was mid-kill and could not
answer. They are reported rather than folded in, because a run that mostly
talked to three nodes must not read like one that talked to four — 3.96 nodes
per height on average says how strong the evidence actually is.

The deepest reorg was **3 blocks** against a 256-block horizon. That is far
below the 128 the horizon was sized against, and it is worth being careful about
what it means: it is one run at one seed on one machine, not a new measurement
of the tail. The horizon stays where it is.

| measure | p50 | p90 | p99 | max |
| --- | --- | --- | --- | --- |
| trail behind the highest node (blocks) | 0 | 0 | 1 | 3 |

Across 795 node-samples. Resources: threads peaked at 12-13 and descriptors at
20, both flat; disk reached 6.5 MB with the chain. Node `a` shows a 183 MB RSS
peak that was back to 45 MB fifteen seconds later, and a 122 MB peak that
behaved the same way — single-sample transients that fully reclaim. The floor
per ten-minute window ran 15.2, 17.1, 12.6, 22.0, 24.2 MB and *fell* in the
middle, which a leak does not do.

**These two regimes must not be read against each other.** The contention
figures are tighter than the single-miner regime's (p99 of 1 against 2, max of 3
against 11), and it would be wrong to conclude contention is easier: the machine
was at load average 6-19 during this regime and 8-47 during the other. That
difference alone plausibly accounts for the gap. Each regime is evidence about
itself under its own conditions.

### A note on why the settled-height check earns its place

After the convergence check passed, a later stage of the same run logged:

```
balances not compared: 4/4 nodes reachable on 2 distinct tips
```

Read quickly that looks like it contradicts the convergence result. It does
not, and the reason is exactly why this run added the settled-height check.

The sampler's last three rounds show all four nodes on one tip at heights 1011,
1012 and 1015. The two tips seen afterwards are the surviving miner having
produced another block that had not yet reached every node — propagation lag
measured at a different instant, not a fork. Tip agreement is a property of
*when you look*; it was true at every instant the sampler looked and briefly
untrue a moment later, without anything being wrong.

That is the whole argument for comparing a settled height instead. Height 1007
had been passed by every node, so no amount of further mining could change what
any of them held there, and all four returned one id. A check that can be
falsified by sampling a moment later is not the check you want to hang a
convergence claim on.

### What was not established

The propagation figure is bounded below by the sample interval and says nothing
about sub-15-second behaviour. The memory reading is consistent with a
chain-sized cache but does not prove a plateau. And every timing figure was
taken on a heavily loaded machine — see below.


## The machine, and what it does to these numbers

Both regimes shared a six-core machine with five other test suites. The
single-miner regime ran at a load average between 8 and 47; the contention
regime, later, at between 6 and 19. That is stated up front because it is
load-bearing for how the timing figures should be read:

**The convergence results are unaffected by load.** Whether four nodes hold the
same block id at a settled height is not a question a slow machine answers
differently. A loaded machine makes convergence take longer, and the window is
generous enough to absorb that; it does not make two nodes build different
history.

**The latency figures are an upper bound, not a measurement of the protocol.**
Every trail figure includes time the node spent waiting for a core. On an idle
machine they would be smaller, and by an unknown factor — this run cannot say
by how much, and does not.

**The growth figures are the strongest thing here.** Descriptor and thread
counts are not sensitive to how busy the machine is, and both were flat across
both regimes. Memory needs the floor read rather than the peak, and on that
reading it tracks the chain rather than the clock.

**And the difference between the two regimes' latency figures is not a finding.**
They ran at different times under different load. Comparing them would be
measuring the other five test suites.

## Reproducing

```sh
ZCD_SOAK=55m ZCD_SOAK_SAMPLE=15s ZCD_SOAK_LOGDIR=./.soakrun \
  go test ./sim/chaos/ -run 'TestChaosSoak$' -count=1 -v -timeout 120m

ZCD_SOAK=50m ZCD_SOAK_SAMPLE=15s ZCD_SOAK_LOGDIR=./.soakrun \
  go test ./sim/chaos/ -run 'TestChaosSoakUnderContinuousContention$' \
  -count=1 -v -timeout 120m
```

Run separately rather than in one invocation, so that one regime's duration and
conditions are recorded against its own artifact. `-run TestChaosSoak` on its
own matches all four regimes, which is `make soak`'s behaviour and not what
these two artifacts are.

`make soak` is the shorter form at the default 35 minutes and runs all four
regimes; `make soak-long` is the four-hour gate. `ZCD_SOAK_SEED` shifts the
chaos schedule, which is what widens the kill and partition counts under test
rather than reproducing one draw of them.
