# Soak artifacts

Measurements kept from runs that took hours, so the numbers quoted elsewhere in
this tree can be checked rather than taken on trust.

A run is only evidence if what produced it is written down beside it. Each file
here therefore carries its own header: the parameters, the regime, the machine,
and — where it matters — what the run was loaded against. Read a number here
against the regime it came from and not against another one; regime is exactly
what does not transfer, which is the argument
[`../../decisions/testnet-measurements.md`](../../decisions/testnet-measurements.md)
makes at length.

| file | what it is |
| --- | --- |
| [`rx2-epoch-boundary.txt`](rx2-epoch-boundary.txt) | rx/2 crossing 52 key-schedule boundaries, mining and verifying, on the RandomX local net |
| [`devnet-convergence.md`](devnet-convergence.md) | a multi-node dev-engine devnet under chaos: convergence by block id, propagation, and resource growth — the written record |
| [`devnet-convergence-samples.tsv`](devnet-convergence-samples.tsv) | its per-node series, single-miner regime |
| [`devnet-convergence-contention-samples.tsv`](devnet-convergence-contention-samples.tsv) | its per-node series, continuous contention |
| [`windows-manual-run.md`](windows-manual-run.md) | the manual Windows verification run — the template, and the record of each run |

One entry is not a soak and says so in its own header:
[`windows-manual-run.md`](windows-manual-run.md) records a manual run of the
Windows command list, which takes minutes rather than hours. It lives here
because this is where this tree keeps runs it wants checkable rather than
quoted, and that is the property it needs.

## What these are not

**Not benchmarks.** Nothing here is a throughput claim. The runs are about
whether an invariant holds and whether anything grows without bound, and both
are questions a slow machine answers as well as a fast one.

**Not mainnet.** Every soak here is a local network on a parameter set chosen to
reach a boundary quickly. The rules exercised are the shipped ones; the
*timings* are not mainnet's and were never meant to be.
