# The RandomX local net

A throwaway single-machine network that runs the **real** work function and
crosses a key-schedule boundary every eighty seconds or so, instead of every
seventeen hours.

It exists to close a gap that unit tests cannot: devnet runs `dev-blake3`, so
until this recipe nothing in the tree drove RandomX through a running node. The
encoding rules around the hashing blob *are* covered without it — the blob is
built by one function that both the miner and the verifier use, and
`core/pow`'s `blobpath_internal_test.go` pins that on the dev engine at
microsecond cost. What those tests cannot reach is everything that is a
property of the **engine** rather than of the bytes: the ~2 GiB dataset, the
256 MiB per-epoch caches, the mining pause while a dataset is rebuilt, and the
fact that a node keeps verifying across that pause. Those need a real engine
and a real re-key, which is what this file is.

## What it is not

**Not a network anyone joins.** It is not embedded in any binary, it appears in
no release, and `--params` deliberately hands a node **no seeds** — an operator
running their own parameter file is on a network this release knows nothing
about, and dialling the public testnet's seeds would only earn a handshake
refusal. Every node here is one you started yourself.

**Not a measurement of mainnet.** It is devnet's parameter set with two values
changed — `pow_engine` and the key schedule — and that restraint is the point.
A local net that also moved the block time or the gas schedule would be a
different regime, and regime is exactly what does not transfer (see
[`decisions/testnet-measurements.md`](../decisions/testnet-measurements.md)).
Read a run here against a devnet run; do not read it against mainnet.

## Running it

You need a binary built **with** the `randomx` build tag. The tag writes
*separate* binaries, so building it does not overwrite the pure-Go pair:

```sh
make build-randomx      # writes bin/zcd-randomx and bin/zycordd-randomx
```

Then, from the repository root:

```sh
make localnet
```

That is the whole recipe. It creates `.localnet/`, generates a throwaway payout
key, and starts a mining node on
[`params.randomx-localnet.json`](params.randomx-localnet.json). Ctrl-C stops
it. To start over, delete the directory — this network is reset from genesis,
never migrated:

```sh
rm -rf .localnet
```

The equivalent by hand, if you want to vary something:

```sh
./bin/zycordd-randomx --params docs/localnet/params.randomx-localnet.json \
  --dir .localnet --mine --payout <address>
```

Confirm two machines are on the same local net by comparing the genesis id,
which commits to every consensus parameter (R3-1):

```sh
./bin/zcd-randomx genesis --params docs/localnet/params.randomx-localnet.json
```

## What to watch for

**The first dataset build.** Mining allocates the ~2 GiB dataset before the
first block. On a cold start that is tens of seconds during which nothing is
mined; it is not a hang.

**The re-key, which is the reason this recipe exists.** With
`randomx_key_interval: 16` and `randomx_key_lag: 2` at a five-second block
target, the first boundary is at **height 18** — about ninety seconds in — and
every sixteen blocks after that, so roughly every eighty seconds. At each one a
mining node rebuilds the dataset and **stops mining while it does**, on the
order of ten seconds and machine-dependent. Time it on your hardware: that
number is the one no lab run has produced, and on mainnet the same event is
rare enough that nothing routinely observes it.

**That verification does not stop with mining.** A node keeps checking headers
across a rebuild, on the 256 MiB cache for whichever epoch each header belongs
to. If a run shows verification stalling at a boundary, that is a finding.

**Memory.** Budget about **3.3 GiB** for a mining node — the dataset plus the
cache table under load. A machine that can verify comfortably cannot
necessarily mine; [`../RUNNING.md`](../RUNNING.md) has the measured breakdown.

## Why the parameters are what they are

The full argument for each value is in the file's own `notes` block, which is
where this project keeps parameter reasoning. In short: the key interval and
lag are shrunk to reach boundaries in minutes while preserving the **1:8 lag
ratio** both shipped networks keep — the lag is slack inside one interval, and
`params.Validate` refuses a lag at or above the interval outright. The chain id
stays devnet's `1337`, which
[`spec/chain-ids.json`](../../spec/chain-ids.json) allocates as `ephemeral`
precisely for throwaway networks; the two still cannot talk, because a
different engine and key schedule is a different consensus root is a different
genesis id, and the handshake compares that.
