# Zycord — the pool integration surface

**Audience:** you have integrated Monero-family coins before, you know what a
`login`/`getjob`/`submit` dialect looks like, and you want to be done in an
afternoon. This document is the delta: what is the same, what is different, and
which of the differences will fail silently if you assume the Monero answer.

**The single most important sentence in this file:** under `rx/2` the target is
compared against the **commitment**, not against the RandomX digest. If you
filter shares on the digest, you and the miner accept *disjoint* sets of nonces
and every honest share is rejected at a healthy hashrate with nothing naming the
cause. [§4](#4-the-target) is the section that matters.

---

## Contents

1. [What ships in the tree today, and what does not](#1-what-ships-in-the-tree-today-and-what-does-not)
2. [The Stratum dialect and its fields](#2-the-stratum-dialect-and-its-fields)
3. [The blob: 43 bytes, LE nonce at 39](#3-the-blob-43-bytes-le-nonce-at-39)
4. [The target](#4-the-target)
5. [ExtraNonce](#5-extranonce)
6. [`seed_hash`, and why there are no surprise dataset rebuilds](#6-seed_hash-and-why-there-are-no-surprise-dataset-rebuilds)
7. [Payouts](#7-payouts)
8. [A worked example against the testnet](#8-a-worked-example-against-the-testnet)
9. [Mine with XMRig](#9-mine-with-xmrig)
10. [The differences from Monero convention, in one table](#10-the-differences-from-monero-convention-in-one-table)

---

## 1. What ships in the tree today, and what does not

Read this before you plan the afternoon, because the shipped component is not a
pool and the naming will mislead you otherwise.

`node/stratum`, reached by `zycordd --stratum-listen`, is a **solo endpoint**.
It speaks the Monero-pool Stratum dialect that stock XMRig already understands,
so an unmodified miner can point at a node and mine it with no proxy and no
patch. What it does not have is everything that makes a pool a pool:

- **No variable difficulty.** Every job carries the full network target.
- **No share accounting**, no share database, no round, no PPLNS, no PPS.
- **No custody.** The `login` address is written straight into the block's
  `EmissionAddr`, so consensus pays the miner that found the block and the node
  never holds a coin on anyone's behalf.

The practical consequence, and it surprises people: **an accepted share IS a
block.** Point four rigs at one node expecting a pool dashboard and you will see
almost no accepted shares. That is correct behaviour; the miner's own hashrate
display is the number to watch.

So the afternoon's work, if you are building an actual pool, is: take this
document's wire contract and its consensus facts, and implement the parts the
node deliberately does not — vardiff over a *truncated* target of your own, a
share database, and a payout engine. Everything below is the part you cannot
derive from Monero experience, and it is all sourced from the tree rather than
from convention.

Two node-side facts you will want before you start:

- The endpoint is **off unless `--stratum-listen` is passed**, and its suggested
  bind is `127.0.0.1:9422` — beside the RPC's 9420, deliberately *not* on
  Monero's 3333/18081. There is no authentication and none is planned; what a
  connection can do is spend the node's verification CPU and **steer the node's
  emission address**, and no protocol password fixes the second. Bind it where
  you trust the network. A non-loopback bind logs a warning naming the exposure.
- The endpoint is independent of `--mine`. A node can serve miners without
  running its own nonce loop, and on any machine worth pointing XMRig at that is
  the configuration you want: the built-in miner would compete for the same
  cores while holding the ~2 GiB RandomX dataset the miner needs the RAM for.

---

## 2. The Stratum dialect and its fields

Newline-delimited JSON-RPC 2.0 over TCP. This is the **Monero** dialect, not the
Bitcoin one: no `mining.subscribe`, no merkle branch, no `extranonce2` the miner
assembles a coinbase from. The server hands over a complete hashing blob and a
target; the miner hands back a nonce.

Four methods are implemented. Anything else is answered `invalid method` rather
than ignored, so a miner is never left blocking on a reply that will not come.

### `login`

```json
{"id":1,"jsonrpc":"2.0","method":"login",
 "params":{"login":"<payout address hex>","pass":"x",
           "agent":"XMRig/6.26.0","algo":["rx/2"]}}
```

| Field | Meaning here |
|---|---|
| `login` | The payout address, 32 bytes of hex, written into `EmissionAddr`. See [§7](#7-payouts). Empty, `x` or `X` falls back to the node's `--payout`. |
| `pass` | **Ignored.** No worker naming, no `d=` difficulty hint — there is one difficulty, the network's. Parsed only so its presence is not an error. |
| `agent` | Logged; used for nothing. A connection is never treated differently for a string it chose itself. |
| `algo` | If present and it does not contain this network's algorithm, the login is **refused** at connect time rather than letting the miner hash noise for an hour. An **absent** list is accepted — older miners and some proxies do not send one. |

Reply:

```json
{"id":1,"jsonrpc":"2.0","error":null,
 "result":{"id":"<session id>","job":{…},"status":"OK","extensions":[]}}
```

`id` is the **session id**, echoed by the miner on every `submit`. The first job
rides inside the login reply rather than arriving as a separate push, so the
miner is never idle waiting for the job timer.

`extensions` is deliberately **empty**. `algo` negotiation, `nicehash` nonce
partitioning and `keepalive` are all things a pool offers when multiplexing many
miners over shared work; this endpoint is not. It is emitted as an empty list
rather than omitted so a strict parser does not fault on a missing key.

### `getjob`

Builds a **fresh** template rather than returning the cached newest job — a
miner sends `getjob` when it has nothing to do, and handing back the job it
already holds would leave it idle. There is a floor of **one assembly per second
per connection**; inside that window the connection's cached job is returned
instead. That floor is not a policy, it is a cost bound: `getjob` is deliberately
unscored, and a pipelined socket measured ~16,500 calls a second, which at ~570 µs
of real template assembly each is about nine CPU-seconds of work per wall-clock
second from one connection.

### `submit`

```json
{"id":3,"jsonrpc":"2.0","method":"submit",
 "params":{"id":"<session id>","job_id":"<job id>","nonce":"<8 hex chars>",
           "result":"<64 hex>","commitment":"<64 hex>"}}
```

| Field | Meaning here |
|---|---|
| `id` | The **session** id from `login`, not the job id. Checked; a mismatch is scored. |
| `job_id` | The cached template this nonce was searched against. |
| `nonce` | 4 bytes little-endian, hex, **exactly eight characters**. Not "at most": a shorter field is ambiguous about which end it was padded from. |
| `result` | Under `rx/2` this carries the miner's **commitment**, despite the name. |
| `commitment` | Carries the raw RandomX **digest**. The names are inverted. |

**Neither `result` nor `commitment` is read.** The node recomputes the digest
from the reconstructed header and forms the commitment itself. A share accepted
on the miner's say-so is a block announced without ever having been verified.
Build your pool the same way: a share is a claim.

Reply is `{"status":"OK"}` on acceptance, or a JSON-RPC error. Every accepted
share is re-verified against the **full 256-bit consensus target** as well; on
any real chain that second check almost always fails, and that is the
accepted-but-not-a-block case, answered `OK` so the miner's counter moves.

### `keepalived`

Answered `{"status":"KEEPALIVED"}`. Deliberately the cheapest path in the
server: it touches no chain state. XMRig sends one roughly every minute when
idle; the endpoint reaps a connection silent for **5 minutes**.

### Server push: `job`

```json
{"jsonrpc":"2.0","method":"job","params":{…same shape as login's job…}}
```

No `id` — that is what makes it a notification. Pushed on every head change
(from any cause: own block, peer announcement, reorg) and on a **30-second**
timer even when the head has not moved. The timer is not redundant: a template's
certificate set and fee revenue go stale, and more importantly its **timestamp**
is fixed at assembly, so an aging template drifts toward the median-time floor
and eventually produces a block that `pow.CheckMedianTime` rejects.

### The job object

```json
{"blob":"<86 hex chars = 43 bytes>",
 "job_id":"<16 hex chars>",
 "target":"<16 hex chars = 8 bytes LE>",
 "algo":"rx/2",
 "height":12345,
 "seed_hash":"<64 hex>",
 "next_seed_hash":"<64 hex>"}
```

`height` is a JSON **number**; everything else is a lowercase hex string.
Lowercase is not cosmetic — some miners compare the blob as a string to detect a
job change, and uppercase hex has been observed to break that.

`algo` is resolved from the **engine the node is actually running**, never
hardcoded. Both real networks declare `randomx-v2`, so it is `rx/2`. A
`dev-blake3` devnet reports itself unmineable and refuses `login` with a message
saying so, rather than advertising something plausible and letting a miner hash
the wrong function forever.

### Error codes

All are JSON-RPC code `-1`; **the message string is the discriminator**, and
XMRig matches on it. Use these exact strings.

| Message | Meaning | Scored? |
|---|---|---|
| `Invalid job id` | Stale share — the job aged out of the cache, **or** the block lost the race to a new tip. XMRig treats this as "stale", not "bad miner". | **No** |
| `Low difficulty share` | The share does not clear the job target. The miner is computing the wrong function. | 2 points |
| `Duplicate share` | Same `(job, nonce)` twice. | 1 point |
| `Unauthenticated: invalid payout address` | Fatal for the connection; XMRig stops retrying. | No |
| `unauthenticated` | A method other than `login` before login. | No |
| `invalid method` | Not implemented. | No |
| `invalid request` | Envelope parsed, params did not. | 2 points |
| `internal error` | The node could not judge the share — a failed chain read. Deliberately **not** `Low difficulty share`: blaming the miner for the node's fault would ban honest miners during a local incident. | No |

Ban score cap is **10** and there is **no decay** — a stratum connection is not
long-lived in the sense a P2P peer is, and a disconnected miner reconnects
within seconds with a fresh score. Adding decay would let a miner emit bad
shares just under the decay rate forever.

Job cache is **8 jobs deep, per connection**. Not shared across connections,
because each connection has its own ExtraNonce ([§5](#5-extranonce)) and
therefore a genuinely different blob at the same height.

Other bounds worth copying: max **4 KiB** per JSON-RPC line, max **16**
simultaneous connections by default (`--stratum-max-conns`), **10 s** write
timeout per message.

---

## 3. The blob: 43 bytes, LE nonce at 39

```
0..31   pow_seed        blake3("zcd/pow/v1", SSZ(header with Nonce and PoWHash zeroed))
32..38  seven zeroes    reserved; MUST be zero
39..42  le32(nonce)     the searched nonce
```

**None of these three numbers were chosen by this project.** `xmrig::Job::nonceOffset()`
returns 39 for the whole RandomX family and `nonceSize()` returns 4; the offset
is compiled in and no pool-protocol field moves it. `Job::setBlob` refuses any
blob shorter than `nonceOffset() + nonceSize()` = 43, so **43 is XMRig's floor**
and this chain's blob is the smallest one a stock miner accepts. The seven
reserved bytes are not padding anyone picked — they are the distance between 32
and 39, and there is nothing to trim.

Three rules that bind you if you serve blobs yourself:

1. **The reserved bytes MUST be zero.** This is a consensus rule that binds
   *implementations*, not blocks: no header field can reach bytes 32..38, so no
   block a node receives can violate it and no fold rule could reject one. An
   implementation that filled the gap with a version byte or an uninitialised
   buffer computes a different digest for the same header and forks on its first
   block, and no corpus of blocks can catch that.
2. **The served blob MUST carry a zero nonce.** `Job::setBlob` reads the four
   bytes at offset 39 as it loads them, and a non-zero nonce silently latches
   XMRig into **nicehash mode**, where it treats the top byte as a fixed prefix
   and narrows its search from 32 bits to 24 — a permanent 256x reduction of the
   connection's search space, for as long as the connection lives, with nothing
   in the protocol reporting it. The node zeroes the nonce field at run time
   rather than trusting the assembler, precisely because the failure is silent,
   permanent and unreportable.
3. **The seed is over `PoWHash` zeroed as well as `Nonce`.** `PoWHash` is a
   consensus field, and a `PoWHash` inside the seed's preimage would make the
   seed a function of itself — no value would satisfy it and the chain would not
   start. The miner computes the seed with `PoWHash` zero, searches nonces, and
   the digest is written into the field afterwards. `ExtraNonce` deliberately
   **stays** in the preimage; see [§5](#5-extranonce).

---

## 4. The target

### The wire form

The job `target` is the 64-bit target as **eight little-endian bytes**, hex.

Not four. Pools do emit a 4-byte compact form and XMRig widens it, but the
compact form **cannot express a target below 2^32**, which is most of the useful
range for a chain a CPU can mine. A pool emitting it is quietly rounding every
miner's job.

### The truncation

```
t64 = max(1, floor((target256 + 1) / 2^192))
```

The `+1` makes the truncation inclusive of the boundary: a target of exactly
2^192−1 yields `t64 = 1`, not 0. The `max(1, …)` matters because XMRig computes
its display difficulty as `2^64 / t64` and a zero target would divide by zero;
clamping hands such a miner the hardest expressible job, which is the honest
answer.

This truncation is only sound because the consensus rule reads the 256-bit value
**little-endian** — the bytes the truncation keeps correspond to the *last*
bytes of the compared value, which is exactly the window XMRig compares. Under a
big-endian reading no clean truncation exists at all, which is the practical
statement of "no proxy can translate between them".

A share that clears `t64` satisfies the full 256-bit check up to a narrow
boundary sliver — the values in `[t64 · 2^192, target256]`, which `t64` admits
and the full target does not. `docs/ARCHITECTURE.md` §12, which is normative,
states that sliver as one part in `2^64`; `node/stratum`'s own comments say
`2^192` in two places. **The tree contradicts itself here and the discrepancy is
cosmetic** — the sliver is a fraction of a 256-bit space either way, no honest
miner is affected, and nothing in either implementation depends on the figure.
Take §12's number and do not derive anything from either.

What matters operationally is what happens to such a share: it is honest, so it
is answered **accepted-but-not-a-block** and never scored. The node re-verifies
every submitted share against the full 256-bit rule regardless, so the sliver
never reaches the chain.

### Which buffer stock XMRig actually filters on

**It filters on the commitment.** This is the one thing in this document that
will cost you the whole integration if you assume the Monero answer, and it is
recorded in `docs/decisions/randomx-v2.md` §8.1, re-verified from
`xmrig/xmrig` v6.26.0 (commit `b2ca72480c58d197e18c885d9fc1a0c8d517e60a`):

- `RandomX_ConfigurationMoneroV2`'s constructor sets `Tweak_V2_COMMITMENT = 1`
  (`src/crypto/randomx/randomx.cpp:55–63`), and `RxAlgo::base()` returns that
  configuration for every `Algorithm::RX_V2` job. **There is no pool-protocol
  field, no command-line flag and no configuration that yields `rx/2` with the
  commitment off.** It is not a mode to detect; it is what `rx/2` means.
- `CpuWorker.cpp:319–326` copies the raw hash into `m_commitment`, then calls
  `randomx_calculate_commitment(prev_job, prev_job_size, m_hash, m_hash)` —
  **the same buffer as input and output** — so the commitment overwrites the
  hash in place.
- The share filter at `CpuWorker.cpp:354` reads `m_hash`, which by then holds
  the **commitment**:

  ```cpp
  const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
  if (value < job.target())
  ```

- `Client.cpp:205–241` puts `result.result()` — the filtered value, the
  commitment — into the wire field named **`result`**, and `result.commitment()`
  — the raw hash — into the field named **`commitment`**. Inverted at every
  layer, consistently.

So the quantity to compare is:

```
commitment = blake2b-256(pow_input ‖ pow_hash)      # 43 + 32 = 75 bytes
value      = LE_uint64(commitment[24:32])
accept if  value < t64                             # strictly less than
```

`prev_job` is the blob that actually produced the hash in hand —
`randomx_calculate_hash_next` runs the pipeline one nonce behind — which is what
makes `pow_input` (the same 43 bytes) the right operand, not some earlier blob.

The comparison is **strictly less than**, matching XMRig. A share exactly equal
to the target is one the miner would not have sent, so accepting it would be
accepting something no miner produces.

Two failure modes, both silent:

- **Compare the digest instead of the commitment** and you and the miner accept
  *disjoint* sets of nonces — not overlapping, disjoint, because the two values
  are independent and uniform. Every honest share is rejected at a healthy
  reported hashrate, and your ban score then disconnects the miners that are
  behaving.
- **Read the value big-endian** and you read the opposite end of an independent
  32 bytes, with the same result.

The commitment is cheap — measured at **207 ns** over 75 bytes, against ~21 ms
for the light RandomX verify it defers. That ratio is why the node checks the
commitment first: a flood is refused at 207 ns per header instead of 21 ms.

### The two-target order

The node judges a share twice, in this order, and the order is a security
property rather than a style choice:

1. Against the **job target** (`t64`). Failure is the miner's fault → scored.
2. Against the **full 256-bit consensus target** via `pow.CheckWork`. Passing
   this means it is a block.

Cheapest refusals happen first and the RandomX evaluation happens **last**,
after the share has been shown to name a real job, carry a well-formed nonce and
not be a duplicate. A pool that hashed first turns a malformed-submit flood into
CPU exhaustion the ban score only catches after the damage. Note also that the
node records a nonce as "seen" only **after** it clears the job target — record
before, and a flooder halves its own score cost by repeating a share that
already failed.

---

## 5. ExtraNonce

**Read this section carefully — it is where this chain differs most from Monero
convention, and the difference is structural.**

There is a 32-bit `ExtraNonce` in the header's PoW seal, and it is inside the
`pow_seed` preimage. Two connections mining the same template at the same height
therefore get genuinely different blobs and search genuinely different spaces.
That is the whole mechanism by which a pool shards work here.

But:

**There is no ExtraNonce field on the wire.** No `extranonce`, no
`extranonce2`, no `mining.set_extranonce`. The miner never sees it and never
sends it. It is **entirely server-side**: the server picks it, folds it into the
header before deriving the seed, and hands the miner the resulting 43 bytes.
Sharding is invisible to the miner because the blob is already sharded.

Consequences for your implementation:

- **You assign ExtraNonce per connection**, before building the blob. The node
  derives it from the first four bytes of the connection's random session id
  rather than from a counter over live connections — a counter is reused the
  moment a connection closes, so a miner reconnecting after a blip would be
  handed the space a *different live* miner is already searching, and the two
  would duplicate work for as long as both stayed connected. A random draw
  collides with probability bounded by the birthday bound, and a collision costs
  duplicated work, not incorrectness.
- **You must cache the whole candidate block per job, not just the header.** A
  block is certificates plus roots plus a state root sealed over a specific
  snapshot; a header alone cannot be applied, and re-assembling at submit time
  produces a *different* block — different certificate set, different timestamp,
  different roots — whose `pow_seed` the miner's nonce was never searched
  against. The share would then be rejected for arithmetic that was correct.
- **A solo miner sets ExtraNonce to 0 and is not disadvantaged.** 2^32 nonces
  per `(template, ExtraNonce)` pair is ample at a 30-second target; a machine
  that exhausts it takes a fresh template, which moves the timestamp and the
  certificate set anyway.
- **Nothing in consensus constrains ExtraNonce.** It is grinding space by
  design, and it is not covered by any rule beyond being in the seed preimage.

One trap: `pow_seed` zeroes `Nonce` and `PoWHash` and **nothing else**. Zeroing
`ExtraNonce` too would collapse every ExtraNonce onto one seed and silently
un-shard every pool on the network — a change that breaks nothing a test would
notice.

---

## 6. `seed_hash`, and why there are no surprise dataset rebuilds

**The RandomX key is derived from the block height and the chain id. It is never
derived from a key block's hash.** This is a deliberate departure from upstream
RandomX's schedule and it is the single biggest quality-of-life difference for a
pool operator.

```
epoch(h) = 0                                   if h < lag or h - lag < interval
         = (h - lag) / interval                otherwise

key(h)   = blake3("zcd/pow-key/v1", le64(chain_id) ‖ le64(epoch(h)))
```

| Network | interval | lag | first boundary | re-key roughly every |
|---|---|---|---|---|
| mainnet | 2048 | 64 | height 2112 | 17 hours |
| testnet | 512 | 64 | height 576 | 4.2 hours |

Epoch 0 covers everything below the first boundary, including genesis, which
carries no proof of work at all.

**What this buys you:** every key of every epoch is computable from genesis,
offline, with no chain. `seed_hash` is a *lookup*, not a prediction. A Monero
pool derives these from key blocks and cannot compute the next one until the
block exists; here you can compute the seed for any height you like, including
heights that do not exist yet.

So:

- `next_seed_hash` is always correct and always available, from the first job you
  ever serve. XMRig builds the next epoch's cache in the background off it, so a
  rotation does not stall every miner for the tens of seconds a cache fill takes.
  **Populate it.** A `next_seed_hash` that echoed `seed_hash` would mean your
  boundary-crossing logic never crosses, which presents as every miner stalling
  at every rotation.
- **There are no surprise rebuilds.** The boundary is arithmetic on the height.
  You can schedule around it, warm caches ahead of it, and alert on it. Nothing
  about a chain reorganisation can move a boundary, because the key does not
  depend on any block's contents. A reorg across a boundary changes which blocks
  are canonical; it cannot change which key a height uses.
- **Verification stays a total function of a header's bytes.** No chain, no
  ancestry, no clock. You can price an orphan, score an announcement whose
  parent you have never seen, and cache a verdict by block id.

Find the boundary by **stepping forward by the interval**, not by scanning
block-by-block: the next boundary is at most one interval away, so a single
stride crosses it, and a linear scan over a 2048-block mainnet interval would be
2048 evaluations per job for a value that changes once per epoch.

The chain id is in the preimage, so work done on one network is worth nothing on
another even when the parameter sets are otherwise mirrored — which is exactly
how testnet and mainnet are configured. **Testnet and mainnet never share a
RandomX key even at the same height.**

**What it costs, stated honestly:** key unpredictability. Dataset precomputation
is not the concern — it is symmetric and improves liveness at a boundary. The
concern is long-horizon offline specialisation, since part of RandomX's
ASIC-resistance argument is that a chip cannot prepare for future keys. The
reversal trigger on record is evidence of specialised hardware, not a calendar
review. See `docs/ARCHITECTURE.md` §21.

**Memory, because your miners will ask.** Verifying is about **256 MiB per key
epoch held**, with two epochs in the table, and measured peak under concurrent
demand is **1280 MiB** — budget ~1 GiB for a verifying node under load. Mining
additionally allocates the **~2 GiB dataset**, putting a mining node at about
3.3 GiB. A mining node **stops mining** during a boundary rebuild (order of ten
seconds) but **keeps verifying** throughout. **A pool's job server should never
build the dataset**: the node's endpoint deliberately verifies in light mode and
never asks its engine for a fast representation, because taking 2 GiB from a
machine whose whole purpose is to give that RAM to XMRig, to speed up a hash
computed a handful of times a minute, is a bad trade.

---

## 7. Payouts

### The native path

Rewards are paid **by consensus**, to the `EmissionAddr` in the block header.
There is no coinbase transaction to build and nothing for the miner to assemble
— which is, incidentally, why this endpoint can exist against this chain at all:
there is nothing for the miner to understand about the block format.

The reward is `producer share of the subsidy + parallel-market tips of the
certificates that applied`. It is credited to the **maturity ring**, not to a
spendable balance, and released `coinbase_maturity` blocks later (**100** on
both real networks). The treasury's basis-point share is taken from **issuance
only, never from fees**, and is credited immediately.

### The address rule, and it is a real trap

The payout address **must be persistent, version byte `0x02`**. A one-shot
(`0x01`) address is refused rather than warned about.

Why: a one-shot address burns its authority the moment it is spent once, and
from that block on the fold **burns every maturing reward addressed to it** —
including whatever of your last 100 blocks is still in the ring. **Nothing
errors.** The only trace is `matured=0` on the node's block line, which is also
what an ordinary empty ring slot prints, and a `burned=` that has quietly
absorbed the whole producer share. See `docs/WALLET.md` rule 3.

`zcd wallet address` prints a persistent address by default.

### Login address resolution

| `login` value | Result |
|---|---|
| empty, `x`, or `X` | Falls back to the node's `--payout`. If there is none, the login is **refused** rather than mining to the zero address — which is not a burn, it is a cell nobody holds the key to. |
| `<addr>.<worker>` or `<addr>+<worker>` | The suffix is **dropped**, not rejected. There is no per-worker accounting here, and refusing a command line that is correct everywhere else in the ecosystem would be the wrong call. |
| valid persistent hex (with or without `0x`) | Used. |
| present but invalid | **Refused**, fatally. |

The asymmetry between "empty" and "invalid" is deliberate. Empty means "I did
not specify, use yours"; malformed means "I specified, and I meant it" — and
quietly paying the node operator's address to a miner who typed their own with a
typo is the single worst failure this surface could have, because it looks like
success from both ends until somebody checks a balance.

### Paying your own pool's miners

You are outside consensus here: the node pays *you* (or whatever `EmissionAddr`
you set), and distributing to your miners is your own ledger's problem. Pay with
the native **`TRANSFER`** program, built through `wallet.BidWithHeadroom` and
submitted to `/submit`. `zcd wallet send` is the reference implementation.
`docs/WALLET.md` is the rulebook and rules 1, 2, 5 and 6 are the ones a batch
payout gets wrong: sweep whole cells, make `RefundTo` an address you can still
use, set the maximum generously and the priority honestly, and sort moves
canonically. A `TRANSFER` carries up to `max_moves_per_transfer` (**32**) moves,
so a payout batch is a small number of certificates rather than one per payee.

### Tips and payouts never conflict

**A priority tip and a mining payout are different mechanisms operating on
different value, and they cannot interfere.** Stated concretely:

- A **tip** is the excess a certificate's declared `SeqPriority`/`ParPriority`
  pays over the base fee. It is *revenue* flowing to the producer of the block
  that includes the certificate.
- A **payout** is your `TRANSFER`, which is itself a certificate — it *pays* a
  tip like any other certificate, and it *moves* value out of your balance.

They meet in exactly one place: the miner reward, which is
`producer subsidy share + tips`. Both halves land in the same maturity-ring slot
keyed by the block's `EmissionAddr`. There is no separate tip account to
reconcile, no ordering between them, and no way for one to displace the other —
they are summed, once, at F11 in the fold, before anyone is paid.

The treasury share is taken from issuance and never from fees, so a tip is never
diluted by it either.

The one interaction worth knowing about is not a conflict but a forfeiture: the
§8.1 burst valve forfeits the producer's whole block revenue — **subsidy share
and tips together** — at `seq_gas_used == 4T` exactly. It is all-or-nothing and
it hits both halves identically, so it still cannot make tips and payouts
disagree.

---

## 8. A worked example against the testnet

Every number below is computed from `spec/params.testnet.json` and the code in
`core/pow`, and is reproducible offline.

**Testnet constants:** `chain_id = 2`, `pow_engine = randomx-v2`,
`target_block_seconds = 30`, `randomx_key_interval = 512`,
`randomx_key_lag = 64`, `coinbase_maturity = 100`,
`genesis_target = 2^246`, `max_target = 2^252`.

### Step 1 — a node serving jobs

```sh
zcd wallet new --out miner.json
zycordd-randomx --testnet --dir ./testnet \
  --payout $(zcd wallet address --key miner.json) \
  --stratum-listen 127.0.0.1:9422
```

Note the binary: `zycordd-randomx`, not `zycordd`. RandomX is behind a cgo build
tag and the untagged binary **refuses to start** against a RandomX network rather
than falling back to the development engine — which would accept a single BLAKE3
pass as proof of work for every header it ever saw.

`--payout` here is the *fallback* for a miner that logs in without an address;
it is optional on the Stratum path even though it is mandatory for `--mine`.
`--mine` is not passed: the endpoint does not need it.

Expected log line:

```
stratum listening on 127.0.0.1:9422 (rx/2, solo — an accepted share is a block)
```

If that line says `rx/0` or names an unmineable engine, stop: you are pointed at
the wrong network or the wrong binary.

### Step 2 — the seed hashes, computed offline

`key(h) = blake3("zcd/pow-key/v1", le64(chain_id=2) ‖ le64(epoch(h)))`:

| epoch | heights | key |
|---|---|---|
| 0 | 0 … 575 | `4b3154ffde8df318d0f146e06cce3220dfec9e9dae29bbd6e93027415b5d0368` |
| 1 | 576 … 1087 | `ba2363637261df65db5741478f7d844515b548213ffef423264a0ce460841a56` |
| 2 | 1088 … 1599 | `36b7113652cbf5408c92f0095da9d0e595346f21846eac5a976b3d1f4fcd0caf` |

So a job at height 1 carries:

```json
"seed_hash":      "4b3154ffde8df318d0f146e06cce3220dfec9e9dae29bbd6e93027415b5d0368",
"next_seed_hash": "ba2363637261df65db5741478f7d844515b548213ffef423264a0ce460841a56"
```

and it carries that same pair for every height from 0 to 575. At height 576 both
values step: `seed_hash` becomes epoch 1's key and `next_seed_hash` becomes
epoch 2's. **You can precompute this table for the entire life of the chain.**

### Step 3 — the target at genesis difficulty

`genesis_target` is 2^246, whose big-endian 32 bytes are
`0040000000000000…`. Truncating:

```
t64 = max(1, floor((2^246 + 1) / 2^192))
    = 2^54
    = 18014398509481984
    = 0x0040000000000000
```

On the wire, **little-endian**:

```json
"target": "0000000000004000"
```

XMRig will display this as difficulty `2^64 / 2^54 = 1024` — about 1024 expected
hashes per block, which a small VPS solves in seconds. That is deliberate:
`genesis_target` is where the LWMA *starts*, not a relaxed rule, and the
difficulty rule moves it toward reality within `difficulty_window` (90) blocks.

Sanity check the other end: `max_target = 2^252` truncates to
`t64 = 2^60 = 1152921504606846976`, i.e. display difficulty 16. Even at the
easiest permitted difficulty a header costs about 16 expected hashes, so block
work stays a four-bit measurement rather than a single bit.

### Step 4 — a login exchange

Request:

```json
{"id":1,"jsonrpc":"2.0","method":"login","params":{
  "login":"02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  "pass":"x","agent":"XMRig/6.26.0","algo":["rx/2"]}}
```

(The address is illustrative; use your own from `zcd wallet address`. Note the
leading `02` — the persistent version byte.)

Reply, at height 1 on a fresh testnet:

```json
{"id":1,"jsonrpc":"2.0","error":null,"result":{
  "id":"3f1c9a70b2e4d581",
  "job":{
    "blob":"<86 hex chars: 32-byte seed, 7 zero bytes, 00000000>",
    "job_id":"a1b2c3d4e5f60718",
    "target":"0000000000004000",
    "algo":"rx/2",
    "height":1,
    "seed_hash":"4b3154ffde8df318d0f146e06cce3220dfec9e9dae29bbd6e93027415b5d0368",
    "next_seed_hash":"ba2363637261df65db5741478f7d844515b548213ffef423264a0ce460841a56"},
  "status":"OK",
  "extensions":[]}}
```

Three assertions to make on that blob, in order of how badly they fail:

```
len(blob)     == 43 bytes (86 hex chars)   # anything else: no stock miner will mine it
blob[32:39]   == 00 00 00 00 00 00 00      # anything else: you fork on your first block
blob[39:43]   == 00 00 00 00               # anything else: silent nicehash mode, 256x loss
```

The session id `3f1c9a70b2e4d581` also determines this connection's ExtraNonce:
the first four bytes, `3f1c9a70`, read big-endian → `0x3f1c9a70`. That value is
already inside the seed at `blob[0:32]`; the miner never learns it.

### Step 5 — a share

```json
{"id":3,"jsonrpc":"2.0","method":"submit","params":{
  "id":"3f1c9a70b2e4d581","job_id":"a1b2c3d4e5f60718",
  "nonce":"a7f30100","result":"<64 hex>","commitment":"<64 hex>"}}
```

`"a7f30100"` is `0x0001f3a7` = 127399 as a little-endian `uint32`. Eight hex
characters, always.

What the node does with it, and what your pool should do:

1. Look up `job_id` in this connection's cache. Miss → `Invalid job id`,
   unscored.
2. Check `id` against the session id.
3. Duplicate `(job, nonce)` → `Duplicate share`, 1 point.
4. Stamp `nonce` and this connection's ExtraNonce into a **copy** of the cached
   header.
5. Recompute the RandomX digest — **never take it from the wire** — and write it
   into `PoWHash`.
6. `commitment = blake2b-256(pow_input ‖ pow_hash)`; compare
   `LE_uint64(commitment[24:32]) < t64`. Fail → `Low difficulty share`, 2 points.
7. Record the nonce as seen. **Now**, not earlier.
8. Full `CheckWork` against the 256-bit target. Fail → `{"status":"OK"}`; this
   is the ordinary case.
9. Pass → it is a block. Apply it, announce it, push a fresh job to everyone.

On success:

```
stratum: block height=1 id=<6 bytes> from 127.0.0.1:xxxxx certs=0 reward=<u256>
```

### Step 6 — confirm the payout

```sh
curl -s http://127.0.0.1:9420/head
zcd wallet balance --key miner.json --rpc http://127.0.0.1:9420
```

The reward is in the maturity ring for **100 blocks** (~50 minutes at a
30-second target) before it shows as spendable. Until then it is visible in
state and unspendable. There is no faucet and there will not be one: for roughly
the first hundred blocks after your first reward, only miners can transact. That
ramp is mainnet's and the testnet is rehearsing it.

---

## 9. Mine with XMRig

> ## ⚠️ UNVERIFIED — pending issue #12
>
> **The command line below is derived from the source in this tree and from
> XMRig's own compiled-in constants. It has NOT been proven end to end: no
> stock XMRig has yet mined a block against this chain.** Issue #12 ("Prove it
> end to end: stock XMRig mines a testnet block") is open and is the work that
> will replace this notice with a version, a command line and a log excerpt
> that were actually observed.
>
> Until that issue closes, treat this section as a well-founded prediction, not
> a proven recipe. If you run it and it works, or does not, that is exactly the
> evidence #12 is asking for.

Stock XMRig, no patches, no fork. The version the compatibility work was read
against is **v6.26.0** (commit `b2ca72480c58d197e18c885d9fc1a0c8d517e60a`).

```sh
xmrig \
  --url 127.0.0.1:9422 \
  --algo rx/2 \
  --user <your persistent 0x02 address, hex> \
  --pass x \
  --keepalive \
  --no-tls
```

Each flag, and why it is there rather than omitted:

| Flag | Why |
|---|---|
| `--url 127.0.0.1:9422` | The node's `--stratum-listen` address. Plain TCP; the endpoint speaks no TLS. |
| `--algo rx/2` | Pins the algorithm rather than relying on negotiation — this endpoint advertises **no extensions**, `algo` negotiation included. If the node's log says `rx/0`, use `rx/0`; the endpoint follows the network's engine and both real networks declare `randomx-v2`. |
| `--user <address>` | Written into `EmissionAddr`. **Must be persistent (`0x02`).** `--user x` is accepted and falls back to the node's `--payout`. A worker suffix (`<addr>.rig1`) is accepted and the suffix is dropped. |
| `--pass x` | Ignored by the endpoint, but XMRig sends the field and the Monero convention is `x`. |
| `--keepalive` | The endpoint reaps a connection silent for 5 minutes; XMRig's `keepalived` every ~60 s stays well inside that. |
| `--no-tls` | Explicit rather than implicit. There is no TLS endpoint. |

Add `--donate-level 0` if you want to; the endpoint neither knows nor cares.

**Expect almost no accepted shares.** This is a solo endpoint: an accepted share
is a block. Watch XMRig's hashrate display, not its share counter. On the
testnet at genesis difficulty (~1024 expected hashes per block) you will
actually see blocks; on mainnet you will not, unless you win one.

**Do not point XMRig at a devnet.** A `dev-blake3` network has no algorithm any
Stratum miner implements, and the endpoint refuses the login saying exactly
that, rather than letting the miner hash the wrong function forever.

**Memory.** XMRig mining `rx/2` wants the ~2 GiB dataset plus huge pages. Run
the node and the miner on the same machine only if you have the RAM for both —
the node's verifying engine wants ~1 GiB under load on top of whatever XMRig
takes.

### Things that look like miner bugs and are not

| Symptom | Cause |
|---|---|
| Hashrate healthy, every share `Low difficulty share` | Your pool is filtering on the digest instead of the commitment, or reading it big-endian. [§4](#4-the-target). |
| Hashrate silently ~256x lower than expected | The served blob carried a non-zero nonce and XMRig latched into nicehash mode. [§3](#3-the-blob-43-bytes-le-nonce-at-39). |
| A burst of `Invalid job id` when the chain is busy | Normal. Stale shares at a 30-second target. Do not score them. |
| Every rotation stalls every miner for tens of seconds | `next_seed_hash` is wrong, or echoes `seed_hash`. [§6](#6-seed_hash-and-why-there-are-no-surprise-dataset-rebuilds). |
| Login refused, fatally, with an address you believe is correct | It is a one-shot (`0x01`) address. [§7](#7-payouts). |
| Node refuses to start | Untagged binary against a RandomX network. Use `zycordd-randomx`. |

---

## 10. The differences from Monero convention, in one table

Where the tree and Monero-family convention disagree, **the tree wins**. These
are the ones that will bite.

| | Monero convention | Here | Consequence if you assume Monero |
|---|---|---|---|
| Share filter | pre-`rx/2`: the RandomX digest | **the commitment**, `blake2b(pow_input ‖ pow_hash)` | Disjoint accepted sets. Every honest share rejected, silently. |
| `result` / `commitment` wire fields | named for their contents | **inverted**: `result` carries the commitment, `commitment` carries the digest | You believe the wrong buffer. Also: neither is read here — recompute. |
| `seed_hash` source | a key block's hash | **the height and the chain id** | You build key-block tracking you do not need, and you cannot precompute `next_seed_hash` when in fact you always can. |
| Job target | often 4 compact bytes | **8 bytes, LE, always** | Targets below 2^32 are inexpressible; you round every miner's job. |
| ExtraNonce | negotiated on the wire | **server-side only, inside the seed preimage** | You look for a wire field that does not exist, and you fail to shard. |
| Coinbase | a transaction the miner varies | **none — `EmissionAddr` is a header field** | You look for a coinbase to build. There isn't one; there is nothing for the miner to assemble. |
| Payout address | any wallet address | **persistent (`0x02`) only** | A `0x01` address burns every reward the moment it is spent once, silently. |
| Login `pass` | worker name, `d=` vardiff hint | **ignored** | Your vardiff hints go nowhere; this endpoint has one difficulty. |
| Extensions | `algo`, `nicehash`, `keepalive` commonly offered | **none advertised** | Do not rely on negotiation; pin `--algo`. |
| Port | 3333 / 18081 | **9422** | A Monero-pool scanner will not find this, deliberately. |
| Accepted share | credited, below network target | **an accepted share is a block** | You expect a share stream and see almost nothing. |
| Stale share | varies | `Invalid job id`, **never scored** | Score it and you ban miners for latency, hardest when the chain is busiest. |

---

## Where the authority lives

This document is a summary. When it disagrees with one of these, they win.

| Topic | Source |
|---|---|
| The dialect, field by field | `node/stratum/protocol.go` |
| The wire behaviour, ban score, caches | `node/stratum/conn.go`, `node/stratum/job.go` |
| Target truncation, blob, seed hashes, algo mapping | `node/stratum/seam.go` |
| Blob layout, `pow_seed`, ExtraNonce in the preimage | `core/types/block.go` |
| Commitment, LE rule, `CheckWork`, `KeyFor` | `core/pow/pow.go` |
| Why the commitment and not the digest | `docs/decisions/randomx-v2.md` §3, §8.1 |
| Why offset 39 and little-endian at all | `docs/decisions/xmrig.md` |
| The normative statement of both | `docs/ARCHITECTURE.md` §12, §21 |
| Payout address rules | `docs/WALLET.md` rule 3 |
| Running a node, memory, key rotation | `docs/RUNNING.md` |
| The public testnet | `docs/TESTNET.md` |
