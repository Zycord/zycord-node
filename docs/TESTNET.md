# The public testnet

The network M3.5 exists to run: real RandomX, mainnet's economics, and a chain
anyone can join, mine and break without anything being at stake.

This is the operator's document. The parameter set and the reasoning behind each
value that differs from mainnet is in [`spec/params.testnet.json`](../spec/params.testnet.json)'s
own `notes` block. What the network has to *measure* before genesis is
[decisions/testnet-measurements](decisions/testnet-measurements.md).

> ### Read this before you launch one
>
> **The flood bound this milestone was carrying is built, and it is a property of
> the binary rather than of the network.** [ARCHITECTURE §20](ARCHITECTURE.md)
> carries I7-H4's ingress flood bound into this milestone as two findings, and both
> halves are in the tree. `pow.CheckWork` still compares a digest against the
> header's own declared `Target` with no clamp, so an announcement at `u256.Max`
> still passes the work check — what changed is that the RandomX key epoch such an
> announcement forces is now **priced before that check runs**, against the epochs
> this node is itself working in, which are facts no sender can mint. The
> budget is keyed on the peer's Ed25519 identity rather than on a connection, so
> it is not re-bought for the price of a TLS handshake, and a node-wide
> ceiling sits over the per-identity one, so the total no longer scales with
> however many identities a Sybil set cares to present.
>
> **A binary that predates those carries none of them, and nothing you can read off
> the chain will tell you which one you are running.** The guard is refusal-side: it
> produces output only when something is spending against it, so a bounded node and
> an unbounded one are indistinguishable until one is attacked. Check the build.
>
> The outbound-only follower that died silently under load and never returned is
> fixed. The gate it
> was found under is not: the multi-hour and multi-day chaos soak (R5-G1) is still
> M2's remaining item in §20, and the evidence under that gate is the thinnest in
> the project. Convergence over days is something this network exists to
> **establish**, not something it inherits — which is the reason to run a second
> node somewhere else and compare, below.


## What it is

```sh
zcd genesis --testnet
```

```
network        zycord-testnet
chain id       2
params hash    0xce415e2d992c44d60adc0ae0b75775901b26c29e4acba081728e9ed3b505915a
genesis id     0x0c3cdc8b74cd65eae9604f49ee206a952a089b2c025d4f04a90fa38072738935
state root     0x3c8f97c8ef50991522feb4f89cd15e8fe1e0b98cec5adb1a2344ee64115a0df8
genesis time   1788048000
cells written  6
allocations    0
```

> ### Delete your data directory before joining a reset network.
>
> A testnet may be reset from genesis. When it is, its coins, its history and
> its peer lists are gone, the network takes a fresh chain id, and a data
> directory holding the old chain is refused at startup rather than silently
> mixed — the two networks also disconnect at the handshake, so nothing carries
> over quietly. See [Resets](#resets).

**The parameters are embedded in the binary, not read from a path.** Every
participant of a public network has to carry the same bytes or they are not on
one network, and a file passed by `--params` is a file that drifts. A build that
prints a different genesis id above is a build on a different chain, and it will
not connect to this one — the handshake refuses before a block is evaluated.

It differs from mainnet in **six** values and nowhere else, and every one of the
six is explained in `spec/params.testnet.json`'s own `notes` block: `name`,
`chain_id`, `genesis_target`, `max_target`, `genesis_time` and
`randomx_key_interval`. `undo_depth`, `target_block_seconds`,
`coinbase_maturity` and the whole gas schedule are mainnet's on purpose: the
gas schedule especially, because it is what makes the base-fee behaviour
measured here mainnet's rather than this network's own. A testnet on its own
gas schedule measures a different chain.

## Joining

```sh
make build-randomx        # the testnet is randomx-v1; see below
                          #   -> bin/zcd-randomx, bin/zycordd-randomx
./bin/zycordd-randomx --testnet --dir ./testnet --peers-file peers.txt   # see Bootstrap for peers.txt
```

**`make build-randomx`, not `make build`.** The testnet's `pow_engine` is
`randomx-v1`, the same work function as mainnet. A binary built without the tag
refuses to start against it rather than falling back to the development engine,
which would accept a single BLAKE3 pass as proof of work for every header it
ever saw.

The tagged binaries carry the tag **in their names** — `zcd-randomx` and
`zycordd-randomx` — so that building both leaves both on disk and the file name
says which engine is inside it. The commands further down this page write
`zcd` and `zycordd` for brevity; on this network those are the `-randomx` pair.

### Bootstrap

There is **no peer list compiled into the binary**, on this network or any
other. `node/p2p`'s `Bootstrap` field says why: a baked-in list is one nobody
can change when an entry goes bad, and for a pseudonymous project it is a map of
whoever compiled it.

**No address is committed to this repository either**, and that is the same
decision rather than an oversight: a list in the tree ships with the release and
is read by everyone who builds it, which is a baked-in list wearing a filename.
The addresses for a given testnet are published out of band with the release
that opens it — the announcement and the release notes — and `peers.txt` is a
file you write from those. Nothing here will hand you one.

Bootstrap addresses are therefore data. Either form works and they merge, so you
can take a published list and add a peer of your own without transcribing it:

```sh
zycordd --testnet --dir ./testnet --peers host-a:9421,host-b:9421
zycordd --testnet --dir ./testnet --peers-file peers.txt
```

`peers.txt` is one address per line; `#` starts a comment, blank lines are
ignored, duplicates are dropped. A file you name is a refusal to start, not a
warning, if this node cannot read it or if it names no address at all — a
zero-byte file, or one holding nothing but comments, is the same mistake as an
absent one. A node that silently ignored either would end up with no peers and
no explanation, which looks exactly like a network with nobody on it. Want no
seed file? Leave the flag off.

`--peers` separates on line breaks as well as commas, because a value routinely
arrives carrying one and two addresses run together make a single entry nothing
answers on. That is damage control and **not** a second way to pass a file:
comments and a byte order mark are stripped only on the `--peers-file` path, so
a file expanded into `--peers` turns its own `#` header into a bootstrap address
— accepted silently. If the addresses live in a file, name the file.

DNS names work and expand to every address they resolve to (bounded), so one
name can carry a rotating set without anyone editing a file.

### Be dialable if you can

Zycord does not do NAT traversal. A node with `--listen` on a reachable port is
somewhere others can bootstrap *from*, and the share of such nodes is the
falsifiable condition the whole no-traversal decision rests on
([decisions/networking](decisions/networking.md) §6's first reopen condition;
§5 states the cost and defers the condition itself to §6).

```sh
zycordd --testnet --dir ./testnet --listen 0.0.0.0:9421 --advertise <public-address>:9421
```

> **Advertise an address that answers, or none at all.** `--advertise` falls
> back to `--listen`, so `--listen 0.0.0.0:9421` with no `--advertise` publishes
> `0.0.0.0:9421`, which nobody can dial. That no longer strands the node:
> an earlier release closed the half where a peer advertises nothing at all, and
> this release closes the other half — a
> peer whose advertised address does not answer is asked over the connection it
> opened instead. That half is the harder one to see, because such a peer is a
> sync candidate and `ahead_peers` counts it while nothing ever syncs from it.
> A wrong address still propagates through peer exchange and costs every node
> that tries it a dial. If you cannot forward a port, leave `--listen` off and
> be periphery.

## Faucetless self-mining

There is no faucet and there will not be one. Coins come from mining, which is
the same distribution mainnet gets:

```sh
zcd wallet new --out miner.json
zycordd --testnet --dir ./testnet --mine --payout $(zcd wallet address --key miner.json)
```

The payout must be a **persistent (`0x02`)** address — `zcd wallet address`
prints one by default, and `zycordd` refuses anything else rather than warning.

`coinbase_maturity` is 100, so for roughly the first hundred blocks after your
first reward only miners can transact. That ramp is mainnet's and is part of
what this network is rehearsing: **mine to play**.

Mining allocates the RandomX dataset — about **2 GiB**, plus ~256 MiB per key
epoch held. A machine that can verify comfortably cannot necessarily mine.

## Metrics

`/metrics` answers in two formats, and they do not carry the same set of series.
**The JSON is unchanged** — no field added, none renamed, so a poller written
against it keeps working — and the scrape format carries all of it *plus* what
the JSON has never had: `zycord_peers{direction}`, `zycord_peers_known`,
`zycord_peers_banned`, `zycord_listening` and `zycord_pow_key_epoch`. Two of
those are in the table below, so a caller reading the JSON will not find them
there:

```sh
curl localhost:9420/metrics                        # JSON, as before
curl -H 'Accept: text/plain' localhost:9420/metrics # exposition format
curl 'localhost:9420/metrics?format=prometheus'     # the same, without forging a header
```

```yaml
scrape_configs:
  - job_name: zycord
    static_configs: [{targets: ['127.0.0.1:9420']}]
```

**The RPC stays on loopback.** Scrape it over an ssh tunnel or from the same
host. Exposing the node's RPC to reach its metrics would put a consensus process
on the internet and move its rate limit onto one proxy's address.

Worth graphing, and why:

| series | what it tells you |
|---|---|
| `zycord_chain_height` | flat means the chain stopped, and nothing else says so |
| `zycord_peers{direction}` | inbound zero on a listening node means the port is not actually reachable |
| `zycord_reorgs_total`, `zycord_reorg_depth_max` | the distribution `testnet-measurements.md` §1 is waiting for. Depth is the fork depth: an earlier sync driver overshot the common ancestor by a whole batch and reported the overshoot, and that is fixed here — a reading collected from a node older than this one is a reading of that driver's stride |
| `zycord_blocks_rejected_total` | a block the fold refused, from either source: a peer's branch block, or one this node mined — the miner folds its own sealed block through `Chain.Apply`, which records the refusal the same way, so non-zero on a mining node is not evidence about peers. Losing a race is not counted; a stale template is refused for its parent before the fold runs. The billing law is enforced as block-invalidity, so this is where a violation surfaces |
| `zycord_pow_key_epoch` | which key epoch the tip height selects |

## Resets

**This network is resettable, and a reset is not a rollback.** It is a new
parameter file, which is a new consensus root, which is a new genesis id, which
*is* the network id. The old chain and the new one cannot be confused for one
another even by accident: nodes on the two disconnect at the handshake.

What that means in practice:

- A reset is announced by a new `spec/params.testnet.json` in a release. Check
  `zcd genesis --testnet` against the announced values; if your id does not
  match your peers', you are not on their network and no amount of peering will
  fix it.
- **Testnet coins do not survive a reset**, by construction. They are worth
  nothing, which is the point.
- Delete the data directory. A directory holding another network's chain is
  refused at startup — `this directory belongs to a different network` — rather
  than being silently mixed.

```sh
rm -rf ./testnet && zycordd --testnet --dir ./testnet --peers-file peers.txt
```

`genesis_time` should be moved to the relaunch day when a reset is prepared. The
difficulty rule reads the gap between a block's timestamp and its parent's, so a
genesis dated well before block 1 is mined presents the rule with one enormous
solve time and the first blocks measure the file's date rather than the network.

**A respin is safe only because it mints a new identity — do not preserve the
old one.** The guarantee above (the old chain and the new one cannot be confused,
because a node's genesis id *is* its network id) holds only while the respin
actually changes that id. Do not carry a discarded chain's network identity onto
a new genesis while any node still serving that chain can reach the new one:
because an inbound-dialled node now syncs from the peer that dialled it, a
single forgotten node holding the discarded chain under a preserved identity can
re-offer it, and fork-choice — which follows the heaviest chain — can then pull
an honest node back onto the chain the respin was meant to abandon. Before
respinning, give the new network a fresh identity, or make certain the discarded
chain can no longer be offered — its nodes stopped, or unable to reach the new
genesis — *first*, not after.

**"Made certain" has a procedure, and it is the only way a reset may preserve
`genesis_time`.** A reset that keeps the old `genesis_time` — and therefore the
old network id — is permitted only when, *before the fresh chain's first block*:
every node ever pointed at the network is enumerated, from the peers files, the
provisioning records and monitoring; each one is stopped and its data directory
wiped, or verified already wiped; the fresh network starts only from empty data
directories; and the enumeration list is written into the reset log, so what was
covered is a record rather than a recollection. **If any known holder cannot be
stopped, do not preserve the identity** — perform the ordinary reset described
above instead, moving `genesis_time` and minting a new network id. The one
exception is the launch transition, where genesis must be preserved byte for
byte and retreating to a new identity is not available: there the launch does not
proceed until the enumeration closes.

For holders nobody knows about, the residual hazard is accepted rather than
engineered away. **The watch signal is `zycord_reorg_depth_max`, or any forward
jump in `zycord_chain_height`, during the post-reset window**; the response is to
kill the offending peer's node. That is cheap and reversible, and it is
deliberately lopsided against the alternative — a resurrected chain inside a
fresh network costs the reset. There is no consensus-layer remedy here and none
is wanted: a checkpoint or a minimum-work constant would encode one operator's
decision to abandon a chain as a fact every future node has to carry, and fork
choice following the heaviest chain on the same network is the rule working.

## When something looks wrong

The chain being stopped, a node being stuck, and a node being wrong all look
identical from the node itself: the block log goes quiet, `/status` answers
normally, and an explorer on top of it reports healthy because it agrees with
the node it is reading.

**Run a second node somewhere else and compare heights.** It is not redundancy —
it is the only instrument that measures the property that matters, which is
whether a stranger can join and reach the same tip. Three defects found on this
network so far were invisible to every local signal and detected only that way:
a miner hashing under the wrong key epoch; a listening node that never syncs
from the peers that dialled it when they advertise no address at all; and a
reorg counter reporting the sync batch size. Only half of that second defect
was closed at the time — the half where a peer advertises nothing — and the
other half, an advertised address that never answers, is closed in this release. Not one of them is a
disagreement about validity, which is the point — a node that has stopped
hearing and a node that is wrong look the same from inside it.
