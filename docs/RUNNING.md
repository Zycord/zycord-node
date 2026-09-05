# Running a Zycord node

This is the operator's document. The protocol it speaks is in [spec/wire](spec/wire.md); the reasoning behind the network design is in [decisions/networking](decisions/networking.md).

## The one-line version

```sh
zycordd --devnet --dir ./devnet
```

That is a full node: it validates every block from genesis, serves peers, and answers a read-only RPC on `127.0.0.1:9420`.

## What the node does not have

There is **no key material in the node process, ever**. It accepts no seed, no passphrase, and no key file. Signing happens in `zcd`, and the node's only write endpoint — `/submit` — grants no authority: a submitted certificate is validated exactly as one arriving from a stranger would be.

There is also **no privileged endpoint**, because there is nothing to privilege. No key can pause, upgrade, censor or mint, so there is no call to expose.

The RPC binds to localhost by default and rate-limits by default. If you expose it, you are exposing a read-only view of public data — but you are also exposing a rate limit that now applies to a proxy's address rather than to each caller. Put a real reverse proxy in front of it or leave it alone.

The limiter keys on the transport peer and never on `X-Forwarded-For`. A limiter that trusts a header the client sets is a limiter the client turns off, so the header is ignored rather than half-honoured.

**Know what that costs you behind a proxy.** Every request then arrives with the proxy's address, so the per-client limit stops being per-client and becomes one shared bucket of 600 a minute for everybody at once — and a single caller can empty it for all of them. That is arguably worse than no limit at all, and nothing in the response says so: callers get a plain 429 whether they caused it or someone else did. **Rate-limit at the proxy.** The node's limiter is there for the case it can actually see, which is a direct connection.

## The read-only surface

Anything that watches the chain from outside — an explorer, a monitor, an indexer — reads it here. The node hands over bytes and never interpretation.

| | |
|---|---|
| `/status`, `/head` | tip identity, height, state root |
| `/block?height=N` or `?id=0x…` | one block as JSON, with `canonical`, `orphaned` and `confirmations` |
| `/block?…&format=ssz` | the same block as the canonical SSZ bytes, `application/octet-stream` |
| `/params` | the active parameter set and its consensus root |
| `/cell`, `/balance` | tip state |
| `/fees` | base fees, and the elastic ceilings in force |
| `/mempool` | pool counters; `?limit=N` adds up to 1000 pending ids, lowest first |
| `/network`, `/metrics` | connection shape and counters |
| `/submit` | the only write, and it grants nothing |

**The ceilings are not parameters.** Whitepaper §8.1 made the block's byte, gas and certificate ceilings functions of `T`, the sequential target, and `T` is consensus state the epoch controller moves. `/params` therefore carries only the genesis values — `block_byte_limit_genesis` and friends — which are where `T` starts and the floor it can decay back to, never the limit in force. Those numbers stay real forever, so reading one for "the block size limit" is wrong silently and by up to the distance between the 2.5 MB genesis value and the 8 MB capacity wall. `/fees` serves the live `T` and the four ceilings derived from it, so the derivation can be checked rather than trusted.

**Why the bytes matter.** `blake3("zcd/block/v1" ‖ header_bytes)` is the block id, so an observer that re-derives ids from what it was served either agrees with the network or finds out immediately. It is also how per-certificate outcomes are obtained: whether a certificate was applied, skipped and billed, or dropped is computed inside the fold and never persisted, because one row per certificate forever, in a store that lives in memory, is not something a node can be asked to carry. An observer that wants the outcomes folds the block itself.

**What is not here, and will not be.** No arbitrary state iteration — no address list, no prefix scan, no rich list. No historical state: `/cell` and `/balance` read the tip, and "balance at height H" implies retained history the node does not keep. No admin, reindex or debug call, because there is nothing to privilege. Aggregation belongs to whatever is watching, computed once at ingest into its own database.

**Codes.** Reads answer `GET` and `HEAD` and refuse every other verb with `405`. A well-formed question with a negative answer — a height the chain has not reached, an unknown id, the body of a block that lost a reorg — is `404`; only a malformed request is `400`. A record this node wrote and can no longer read back is `500`, not `400`: the fault is the node's disk, and telling a caller its request was malformed invites it to stop retrying a request that was always well-formed. A poller should never have to read prose to tell absence from error, or its own bug from ours.

**The pending list is a prefix, not a sample.** `?limit=N` returns the N lexicographically smallest ids, which is stable and cheap but is the same subset every time. It is enough to notice the pool moving; it is not a fair view of what is in it.

**Reorgs.** Height lookup answers for the canonical chain only. A block that loses a reorg keeps its header and loses its body, so its id still resolves, comes back marked `orphaned`, and still carries the parent link back to the fork point — which makes id lookup the only reorg-safe path. The body is not retained: bodies are unbounded and headers are not, and this node holds every key in memory.

**Cost.** Block bytes are the one response that is orders of magnitude larger than the request that asks for it, so they carry their own budget — `BlockBytesPerMinute`, 256 MiB by default — on top of the request count. The number that sizes it is `block_byte_capacity`, 8 MB: at 600 requests a minute a flat count alone would authorise 4.8 GB a minute of egress to a single address, a factor of 17.9 more, on a box that is also running consensus. The pending list is bounded by construction instead: a limit of ten costs the node a selection of ten, not a copy and a sort of the whole pool. The budget covers `/block` in both formats: the JSON rendering reads and decodes the same record `format=ssz` serves and hashes every certificate on top, so pricing only the binary form left the more expensive one free. A client polling `/block` JSON spends the same budget as one pulling bytes.

Every response on this surface states a caching policy rather than leaving one to a proxy's heuristics. Block bytes fetched *by id* are content-addressed — an id names exactly one encoding forever — and are the only answer that carries a long `Cache-Control` and `immutable`. Everything a chain reset or a fork choice can still change is `no-cache` with an `ETag` to revalidate against: `/block` JSON, `/block` bytes fetched *by height* (a height is not an identity; a reset gives it different bytes), and `/params`. Live state — the tip, balances, cells, fees, the pool, metrics, peers — is `no-store`, and so is every error, because an unlabelled response is heuristically cacheable and a cached `404` would outlive the block that fills it.

**Where to run it.** The watcher is the thing with the public port, and it talks to `127.0.0.1:9420`. Nothing on this surface requires the node's RPC to be internet-reachable, and a design that needs it to be is a design to change.

## Reachability, and why it matters more than it looks

Zycord does not do NAT traversal. That is a deliberate cost, stated plainly in [decisions/networking](decisions/networking.md) §5, and it means the network needs enough publicly-reachable nodes to serve as connection targets. If you can be one, be one.

A node has one of two shapes:

**Periphery** — no `--listen`. It dials out and can never be dialled. It syncs, validates, mines and relays to the peers it chose. This is the default and it is a perfectly good node; it just does not carry connections for anyone else.

**Core** — `--listen` on a port the internet can reach. It accepts inbound connections and becomes somewhere other nodes can bootstrap from.

```sh
# periphery: nothing to configure
zycordd --dir ./data --peers node1.example:9421,node2.example:9421

# core: bind a port, and make sure it is actually reachable
zycordd --dir ./data --listen 0.0.0.0:9421
```

### Port forwarding

If your node is behind a home router, `--listen 0.0.0.0:9421` binds the port on your machine and nothing else happens: inbound connections never arrive, because the router does not know where to send them.

1. Forward TCP `9421` from the router to your machine's LAN address.
2. Give the machine a static LAN address, or a DHCP reservation. A forward that points at an address the machine no longer has is silent.
3. If the address peers should dial is not the one the process binds — which is the normal case behind a router, and the universal case behind a proxy or a container — advertise it:

```sh
zycordd --dir ./data --listen 0.0.0.0:9421 --advertise your.public.address:9421
```

### Bootstrap addresses from a file

`--peers-file FILE` reads bootstrap addresses one per line, ignoring blank lines and everything after a `#`. It **merges** with `--peers` rather than replacing it, and duplicates are dropped, so you can take a published list and add a peer of your own without transcribing the file onto a command line:

```sh
zycordd --dir ./data --peers-file peers.txt --peers node3.example:9421
```

A `--peers-file` that is named and either cannot be read *or* names no address at all — every line blank or a comment, a zero-byte file included — is a refusal to start, not a warning. A node that shrugged and continued would come up peerless with no explanation, which looks exactly like a network with nobody on it, and the two mistakes reach that same end. The empty one is the likelier: an interrupted download, or a `Set-Content` handed an empty variable, leaves a file rather than no file. If you want no seed list, omit the flag — that is what "I have no seed file" spells.

`--peers` separates on line breaks as well as commas, because a value routinely arrives carrying one and running two addresses together into a single token produces one entry nothing answers on. **That is damage control, not a second way to pass a file.** Only `--peers-file` strips comments and a byte order mark; expanding a file into `--peers` instead hands those bytes to the address parser, and a `#` line becomes a bootstrap entry the file never named — accepted with no error and no log line, which is the failure this whole section is about. If the addresses live in a file, name the file.

The binary carries **one seed address, for the public testnet only** — mainnet has not launched, devnet is local, and a network you pass with `--params` is given none. `--no-seeds` drops it; `--peers` and `--peers-file` work with or without it and are dialled first; and the node prints the list it will actually use when it starts, so what it will dial is something you read rather than something you trust. The seed is a name and not an address, so a bad entry is repaired in DNS rather than in a binary somebody already downloaded — which is the half of "a baked-in list is one nobody can change" that can be answered. The half that cannot is that it is the project's own infrastructure: see [RELEASE.md §4](RELEASE.md).

**Advertising the wrong address is worse than advertising none.** A node that tells peers to dial `192.168.1.40` propagates that address through peer exchange, and every node that tries it wastes a dial. If you cannot forward a port, leave `--listen` off and be periphery — that is the honest configuration and it costs the network nothing.

### Checking whether it worked

```sh
curl -s localhost:9420/network
```

```json
{"enabled":true,"peers":8,"listening":true,"inbound":5,"outbound":3,"reachable":true}
```

`listening: true` with `inbound: 0` after the node has been up for a few minutes means the port is not actually reachable: the process is bound and waiting, and nothing is arriving. That looks healthy in every other view, which is why this endpoint exists.

The aggregate of this number across the network is what decides whether the no-NAT-traversal choice holds. It is the first reopen condition in [decisions/networking](decisions/networking.md) §6, and it is measured, not assumed.

## Mining

```sh
zcd wallet new --out miner.json
zycordd --devnet --dir ./devnet \
  --mine --payout $(zcd wallet address --key miner.json)
```

**Start it whenever you like.** A node started before its network's first block is due does not mine early and does not need to be started again at the hour: it refuses to build a block whose timestamp its own clock has not reached, waits, and begins on its own. It says so while it waits, with the time it is waiting for and how long is left:

```
waiting to mine: the next block cannot be dated before 2026-09-04T13:00:01Z
(unix 1788526801), and this node's clock reads 2026-09-04T09:12:31Z — 3h47m30s
to wait. Leave this running: mining starts on its own and there is nothing to
restart or reconfigure.
```

That is a refusal to *mine*, not a refusal to run: the node peers, syncs and serves its RPC throughout. It is repeated every ten minutes so a long wait does not look like a hang, and it is the only thing standing between an honest early start and a private chain nobody else can use — see [TESTNET.md](TESTNET.md) and ARCHITECTURE §12 for what mining ahead of the clock does to the difficulty rule.

**If it never stops saying this, your clock is wrong.** The wait is computed against this machine's clock, so a clock set days behind waits days. Check it before you check anything else.

The payout address is a plain address. The node never sees the key that controls it, and could not spend the reward if it wanted to.

It must be a **persistent (`0x02`) address** — `zcd wallet address` prints one by default — and `zycordd` refuses anything else rather than warning. A one-shot (`0x01`) payout mines correctly right up until you spend from it once; that debit marks it spent forever, and the fold burns every maturing reward addressed to it from that same block on — the maturity ring rolls after the block's certificates land, so the block carrying the spend is already the first block that loses money, and whatever of your last `CoinbaseMaturity` blocks is still in the ring goes with it. **Nothing errors.** The only trace is on this node's own block line: `matured=0`, which is also what an ordinary empty ring slot prints, and a `burned=` that has quietly absorbed the whole producer share alongside the base and skip fees it normally reports. Neither field says "coinbase". The coins are gone (whitepaper §14.2). A persistent address can never enter the spent registry at all, so the failure is removed rather than narrowed ([WALLET.md](WALLET.md) rule 3).

### Which binary, and what it costs to run

The work function is a **consensus parameter**, not a setting. `zcd params` prints it:

```
proof of work    randomx-v2 (re-keyed every 2048 blocks, 64-block lag)
```

**From a release, that is the archive with `-randomx` in its name.** The plain
archives — and Homebrew, and Scoop — are the pure-Go tier: byte-identical,
attested, and devnet-only. The `-randomx` archives are cgo, join mainnet and the
public testnet, and are attested by nothing. The two tiers are disjoint sets and
[INSTALL.md](INSTALL.md) has the table; `zcd version` tells you which one you are
holding.

From source, RandomX is compiled behind a build tag, so there are two binaries and only one of them can speak to a RandomX network:

```sh
make build           # default: no cgo, no C toolchain, development engine only
                     #   -> bin/zcd, bin/zycordd
make build-randomx   # the network binary
                     #   -> bin/zcd-randomx, bin/zycordd-randomx
```

**The two builds write different files on purpose.** They used to write the same
two paths, so whichever ran second replaced the other and the name told you
nothing about which engine was inside it — which is how `make canonical` came to
certify a binary no release ships. Run `zcd-randomx` where the network is
RandomX and `zcd` where it is not; both are present after building both.

A binary built without the tag **refuses to start** on a network whose `pow_engine` it cannot compute, with a message saying so. That refusal is the point: with no engine to fall back to but the development one, such a node would accept a single BLAKE3 pass as proof of work for every header it ever saw — every forgery valid, every fork weightless, and nothing logged. The reverse is not symmetric: the tagged binary carries both engines and runs a devnet correctly.

**Memory.** Verifying needs about **256 MiB per key epoch held**, and the table holds two so that a reorg across a key boundary does not rebuild one per block. **Budget more than that table, because the table is not the bound.** A cache is resident from the moment it is allocated, and the Argon2 fill that makes it expensive comes after — so up to two more are live while they are being built — and an entry evicted while something is still using it keeps everything it has until that user lets go, which is what a miner does across a dataset fill. Peak cache against the same two-entry table was measured at **1280 MiB** with both effects at once (`core/pow/randomx`'s `TestConcurrentEpochDemandIsAdmittedKeysAtATime` and `TestAnEvictedEntryStillHeldKeepsItsCache`). So budget **~1 GiB** for the engine on a verifying node under load rather than the 512 MiB the table suggests. Mining additionally allocates the **~2 GiB dataset** and is the case that pins a borrower across the fill, which puts a mining node at about **3.3 GiB**. A machine that can verify comfortably cannot necessarily mine.

**Threads.** `--mine-threads` defaults to one per core. It changes nothing about validity; it is how fast this node looks for a solution.

**What happens at a key change.** The work function is re-keyed every `randomx_key_interval` blocks. A mining node rebuilds the ~2 GiB dataset then and **stops mining while it does** — order of ten seconds, machine-dependent; measure yours from the first boundary in the log. **It keeps verifying throughout**, and a rebuild cannot stall it: a header from any key epoch other than the one being mined is verified on that epoch's own 256 MiB cache, which the dataset does not touch (`TestARebuildDoesNotStopANodeVerifying` logs the count on yours, against the one hash a blocking implementation lets through). A header from the epoch being mined uses the dataset while it is bound and that same cache while it is not; the two compute identical digests, so the only difference a rebuild makes to verification is speed. The next epoch's cache is warmed before the boundary, over the last `randomx_key_lag` blocks of the epoch, and the node asks often enough that at least three asks fall inside that stretch on any parameter set — the lag is a count of blocks and a ticker's period is a count of seconds, so the rate is derived from `target_block_seconds` rather than fixed. At mainnet's interval the mining pause is one roughly every seventeen hours; on the public testnet's 512-block interval it is one every four hours or so, which is what that network exists to measure. Building the next epoch's dataset *in advance* is possible — the key comes from the height, so it is known well before the boundary — and is deliberately not done: it means holding two of them, 4 GiB, to save a pause that costs a miner a few seconds a day.

**Stopping a mining node.** `SIGTERM` (or `Ctrl-C`) stops it, and it stops *promptly* — one signal reaches every loop, not whichever one happens to be waiting on the channel (`TestOneSignalStopsEveryLoop`, `TestTheSignalChannelHasExactlyOneReceiver`).

A stop that lands during a key change **waits for the dataset fill to finish** — the engine will not release a ~2 GiB buffer while hash calls are still reading it, which is a use-after-free in C that no Go tooling would report. It is a stop waiting for a fixed event rather than one racing it: measured over ten runs on a RandomX devnet, the exit instant did not move however early the signal arrived, while the wait shrank from 4.5 s to 0.7 s, with no `SIGSEGV`.

So budget a stop timeout above your machine's fill time; measure it once from the first boundary in the log. **A second `SIGTERM` (or `^C`) does not wait** — the first one hands the signal back to the operating system, so pressing it again during that pause kills the process immediately (`TestASecondSignalIsHandedBackToTheOperatingSystem`).

Coinbase rewards mature after `CoinbaseMaturity` blocks. Until then they are visible in state and unspendable, which is what funds the first deposits on a chain with no premine: for roughly the first hundred blocks, only miners can transact.

## The wallet interface, over an ssh tunnel

A node holds no key and never will. The wallet is a separate process, and on a
server it is `zcd ui`:

```sh
zcd ui --key wallet.json --no-open
```

That prints a URL and serves it on `127.0.0.1:9430`. **It binds loopback and
refuses anything else, with no flag to override.** The process behind that
listener holds an unlocked private key and authenticates with a bearer token in
a URL, which is adequate for a socket only the local machine can open and is not
adequate for anything else. Reaching it from elsewhere is ssh's job, and ssh is
better at it than this would be:

```sh
# on your own machine
ssh -L 9430:127.0.0.1:9430 <host>
```

Then open the URL the server printed. The token rides in the URL *fragment*, so
it never reaches the server, a log, or a `Referer` header — treat the URL as the
secret it is. It is new on every run, and `Ctrl-C` wipes the key and stops
serving.

On a laptop, `zcd ui` also opens a browser for you, and that path deliberately
carries something weaker. Opening a browser means running `xdg-open <url>` or
`open <url>`, and a child process's argument vector is readable by other users
on the machine — `/proc/<pid>/cmdline` on Linux, and the process table on macOS,
where an unprivileged account reads argv it does not own. A token passed that
way is a token published to every other user on the machine, which is exactly
the reader it exists to exclude. The browser we launch is given a **single-use handoff** instead, which
it trades for the token on its first request. Someone who scrapes it from the
process table arrives after the browser and gets nothing, or arrives first and
the wallet then fails to open in front of you rather than quietly sharing your
session. The printed URL is unaffected: it keeps the full token, because it has
to work more than once and through a tunnel.

The local end of the forward does not have to be port 9430; the interface checks
the *hostname* in the `Host` header and deliberately not the port, so
`-L 9999:127.0.0.1:9430` works. The hostname is what matters: it is what blocks
DNS rebinding, which is the real attack against a server on loopback — any page
in your browser can make requests to `127.0.0.1`, and the one thing it cannot
forge is the name it was navigated to.

**Do not put a reverse proxy in front of `zcd ui`.** The advice above about the
node's RPC — rate-limit at the proxy, expose read-only data if you must — is
about a surface that holds no key and grants no authority. This one holds a key.
There is no version of exposing it that is a good idea, and the tunnel costs one
flag.

Two other shapes worth knowing:

- **`zcd ui --locked`** starts without asking for a passphrase in the terminal;
  the browser asks instead. Useful when the terminal is shared or logged.
- **`zcd ui --lock-after 5m`** shortens the idle lock, which wipes the key in
  place — the seed is overwritten, not merely dereferenced.

## Peer identity and anonymity

The node generates a fresh Ed25519 peer key on every start and never writes it to disk. It is derived from nothing — not from your wallet, not from a seed, not from anything else on the machine. Restarting rotates it.

If you are running a node in a way that matters to you, the thing that deanonymises you is not the key. It is the address. **A bootstrap node you run on infrastructure traceable to you is a deanonymisation vector that no amount of key hygiene fixes.**

## Updates

The first time you start a node on a terminal it asks one question, once:

```
zycordd v0.1.1 — check for updates? Releases are signed, and nothing is
downloaded or replaced until you say so. Details: `zcd update --print-source`.

  [a] automatic   install a newer release on start, before the node opens its
                  data directory
  [n] notify      say when one is available, change nothing
  [x] never       do not contact the release host

Choose [a/n/x] (default n):
```

Enter takes `notify`. The answer is written to `<dir>/update.json` and you are
not asked again. Change it any time:

```sh
zycordd --update notify --dir ./data     # or auto, or never
```

**Started without a terminal — systemd, Docker, cron, a pool — the node never
asks and never blocks.** With no recorded choice it prints one line saying checks
are off and how to turn them on, and starts. Nothing is contacted. If you want a
service to check, say so explicitly in the unit:

```
ExecStart=/usr/local/bin/zycordd --dir /var/lib/zycord --update notify
```

`auto` is honoured there too, and on a root-owned binary it will correctly refuse
to replace itself and print the sequence to run instead — a node runs
unprivileged on purpose.

Nothing is ever replaced while the node is running. In `auto`, the check,
download and replacement all happen **before the data directory is opened**,
which is the only point in the process's life where nothing is holding the chain
lock. A running node only ever prints a notice.

Checking by hand, and from cron:

```sh
zcd update --check      # report only; exit 10 if something is available
zcd update              # ask, then install
zcd update --rollback   # go back to the previous binary
```

`zcd update --print-source` prints the release host and the keys your binary
trusts, and contacts nothing to do it. The full trust model — including exactly
what the signature is worth, and what a check discloses — is in
[UPDATES.md](UPDATES.md).

## Data directory

```
data/
  chain/       blocks, state, and the write-ahead log
  peers.json   the persisted peer store
```

The peer store is persisted on purpose: a node that starts from a blank slate after every restart hands an attacker a fresh chance to fill it. Deleting it is safe but throws that away.

The node survives being killed at any moment — that is what the write-ahead log is for, and it is tested by killing nodes at random under network chaos (`sim/chaos`). It does not survive its data directory being edited underneath it; on start it recomputes the state root and refuses to run if the stored one disagrees.

If it does refuse to start with `storage: log or snapshot is corrupt`, see [Recovering a damaged data directory](#recovering-a-damaged-data-directory) below — that refusal is a classification, not a verdict, and one of the three things it can mean is repairable in place.

## Recovering a damaged data directory

If the node stops with `storage: log or snapshot is corrupt`, the first thing to know is that this is not one failure. It is three, they have different causes, and only one of them is recoverable locally. The node itself will not guess between them: a reader that guesses is how a previous version of this code silently deleted intact blocks, so refusing to start is deliberate. `zycordd repair` is the second door.

**Do this first.** Stop the node — the repair takes the data directory lock and will refuse while a node holds it. Then ask what happened, changing nothing:

```
zycordd repair --dir <the same --dir the node is given> --dry-run
```

It prints how many records are readable, what the damage is, and either what a repair would discard or why it will not offer one. Nothing on disk is touched.

**Two counts appear and they measure different things**, so both are labelled. `readable:  N record(s)` is how many records replay could read before it stopped; the finding's `keeps N record(s)` is how many survive the cut being offered. They differ whenever the damage falls inside a multi-record transaction, because the cut goes back to that transaction's first record and takes its already-written parts with it — so the readable count is the larger and it is *not* the answer to "what will I still have". Read the `keeps` count for that.

### The three damage classes

| What the report says | What it means | What to do |
|---|---|---|
| *nothing to repair — start the node* | The log reads to its end, or the only damage is an unfinished write with nothing readable past it, and nothing this store recorded as committed is behind it. The node discards exactly those bytes itself on start and says so in its log, so there is nothing here for an operator to authorise; `repair` deliberately offers no cut, because a deletion nobody needed is still a deletion. | Just start the node. |
| *no record behind it terminates a transaction* | The write that was in progress when the machine died never completed, and nothing committed sits past it. This is the ordinary crash. The node refuses only because it cannot prove, on its own, that the record-shaped bytes it can see past the damage are not real data — they may be part of a block body it received over the network and wrote verbatim. | Run the repair. |
| *no cut is offered — resync this store* | A record behind the damage declares itself the last record of its transaction, or the bytes are provably somebody's writes rather than an unfinished one. Discarding the tail here would delete data the node was told had landed, and the chain above would later expect to find it. | Do not repair. Resync (below). See the limit below: this report is a refusal to prove the store safe to cut, not a proof that it is unsafe. |

### What the second row already covers, and what the third does not

The second row is wider than it looks. It covers the case the node's own start-up refusal is least able to explain: a hole in the *first* record of a multi-record transaction. The node reads that transaction's surviving later parts, has nothing left on disk saying a transaction began there, and so reads them as writes that landed after the damage — a permanent refusal. `repair` asks a different question about the same bytes: not "did the writer keep going" but "is a *committed* transaction back there", and only a record declaring itself the last of its transaction answers that. Those surviving parts all declare further parts to follow, so none of them does, and the cut is offered. The store the node will not start is repairable.

Read that guarantee for exactly what it is, because it is a statement about what the scan could see and not about what was on the disk. `repair` concludes "nothing behind the damage was ever reported committed" from finding no record that declares itself the last of its transaction. That is sound while the only reason such a record could be missing is that it was never written. It is not sound when the record was written, fsynced, and then destroyed by a *second* piece of damage — the search cannot see a commit record that is itself a hole, and reports its absence the same way either time.

### The commit record, and why the log alone can never answer this

**No reading of the log can settle it, and that is a fact about the bytes rather than about the effort spent.** Two histories — a transaction abandoned by an ordinary crash, and the same transaction committed and then damaged — leave *byte-identical* log files. Any rule that reads only those bytes is right about one history and wrong about the other.

So the fact that separates them is now recorded **outside the log**. The data directory holds a third file, `commits`, and it carries one number: the highest sequence this store has ever **reported committed**. It is written after the log's own fsync has *returned* — the moment at which, and not before, a caller was told the transaction landed — and it is fsynced in turn.

The rule both instruments then apply is one sentence: **refuse to discard anything at or below a sequence this file says was committed.** The node applies it on start, `zycordd repair` applies it before offering a cut, and they call the same function, so they cannot disagree about the same directory.

**It is read in one direction only, and that is the property to rely on.** It can withhold a cut. It can never authorise one. There is no content of `commits` — absent, stale, torn, garbage, or deleted outright — that makes this store discard anything it would keep without the file. If it is missing or unreadable, you are back to exactly the behaviour described above and nothing worse.

That closes both directions of the same defect, at any number of damage sites and at any depth of truncation: a cut is never offered over a transaction that really was committed, and the node never starts, discards one, and says nothing — it refuses, and `repair` says the same thing rather than *nothing to repair — start the node*. The answer does not depend on what the damaged bytes look like.

What it does **not** close, stated so you do not rely on it:

- **A store written by a build without this file.** There is no evidence there, so it behaves as it did before, and it gains the protection after one clean start.
- **The third row's limit** (the payload-plant defect, the next section) is not closed by *this* file, and was never going to be: closing it here would need `commits` read in the other direction — as permission to cut — and that is deliberately not done, because it would mean a deleted `commits` could authorise a deletion. It is closed elsewhere, by the record format; see the next section.
- **A store whose `commits` file could not be written.** If the disk refuses that write, the commit still stands — it was already durable — but the store falls back to reading the log alone until it is restarted. The failure is logged. Restarting restores the file.
- **Repairing with an older binary breaks it.** A build without this file shortens the log and leaves `commits` naming what the log used to hold; a newer binary opened on that directory afterwards refuses it permanently, and the only way out is a resync. **Run `zycordd repair` with the same binary the node runs.**
- **On Windows the file's *name* is not covered by a barrier this code issued.** There is no way to fsync a directory on that platform (see `syncdir_windows.go`), so the durability of the directory entry rests on NTFS journalling its own metadata. That is **documented as weaker than the POSIX path and has not been measured here.** It fails in the safe direction — a `commits` file whose name did not survive reads as absent, and absent is no evidence — but it means a Windows node can lose this protection across a power loss where a Linux node would not.

**This costs one extra device flush per commit**, which is where the ratified price of the change sits: measured paired on a loaded 20-thread machine, 2.07 ms per commit without it and 3.97 ms with it, a median per-commit delta of 2.03 ms. Against a 30-second block interval that is 0.007% of a block in steady state, and it is visible only where commits run back to back — initial sync.

The third row has the opposite limit, and it is worth stating rather than leaving an operator to infer it. `repair` refuses whenever it can see a record behind the damage claiming a completed transaction — and when the damaged record's own frame failed its checksum, there is no honest way to know where that record's payload ends, so the region searched includes that payload.

**What that used to cost, and what it costs now.** A payload is a block body the node accepted over the network and wrote verbatim, so bytes shaped like a completed transaction could be placed *inside* the crashed record by whoever authored the block — for the price of one ordinary transaction, using one 32-byte constant that satisfied every store at every log length. No checksum could tell them from real ones: the record checksum is not a secret, so anything that could place the bytes could compute it. That is the **payload-plant defect**, and it is closed as of storage format version 4: **a record's payload no longer contains the record magic**, because the writer escapes it out, so the search cannot anchor on a plant inside a payload.

**It is priced, not made impossible, and the distinction is the one to carry.** The escape covers payloads and not the record's own 32-byte header, whose checksum field can be forced to any value including the magic. Reaching that state requires authoring the bytes a forged candidate reads, and those come out of the batch's first key — every durable key this node writes is a fixed prefix plus a hash-derived run, so the cost is an offline preimage grind rather than a fee. **Payable became not payable.** If you are reading this because you are adding a feature that writes a key an outside party chooses, that is the condition this rests on, and the payload-plant defect reopens by its own terms; `TestNoDurableWriteBeginsAPayloadWithAttackerChosenBytes` will say so.

The direction of the refusal is still the deliberate one — a wrong "not repairable" costs a resync, a wrong "repairable" costs committed transactions. Bounding the region the search may look at, so a damaged record's own payload is never part of it, is what bounds the search's cost.

### The four refusals, and which one you have

A refusal behind the damage is not one state, it is four. They all print `NOT REPAIRABLE`, they all change nothing, and they all exit 1 — but only the first is a store that is unsafe to cut *on its merits*. In the other three the store may be perfectly recoverable and is being resynced because no instrument on this machine can settle the question. The `verdict:` line says which one you have, and the four sentences are distinct so a runbook step can tell them apart:

| The verdict line says | What was established | What it means |
|---|---|---|
| *Resync this store from the network* | A writer framed the record found, and it declares a completed transaction. | A committed transaction really is behind the damage. The resync is right on its merits. |
| *the one record … was disproved … but the search stopped at it and never read past it* | Those bytes are content another record carries, so they committed nothing. | A proof in the *opposite* direction — and still not permission to cut. The search stopped at its first candidate; what lies past it was never read. |
| *a second damaged record at offset N stopped the walk* | Nothing beyond offset N. | A second damage site, named because you can read it nowhere else. Whether anything committed sits past it is open. |
| *the search had to begin inside that record* | Nothing. | The payload-plant defect proper: the damaged record's own frame failed its checksum, so the bytes found may be that record's own payload. |

The last three end the same way — *that is not proven either way; no local instrument can answer it, and resync is the only remedy this tool can offer*. Read that literally. It is not a hedge you can argue with by re-running the command: the answer is a function of bytes nothing here may write, so a second attempt is the same attempt.

**There is no flag that overrides any of this, and there is deliberately not going to be one.** The three unproven states are unproven because the question cannot be answered from this machine, not because the command lacks permission — so a flag saying "cut anyway" would just move the guess from the reader to the operator, and that is exactly what both the record format and this command decline to offer. The second row is the one to be careful with: "disproved" reads like "safe", and it is not.

There is a fourth line that is not damage at all: *run the matching binary*. The log, or the snapshot, was written by a build with a different storage format version. Deleting it would destroy a store that other build reads perfectly. This is checked for the snapshot as well as the log, and it has to be: the snapshot is read first, so on a store that has ever compacted it is the only one of the two that gets asked.

**A store written before format version 4 gets exactly that line.** The bump above is a flag day, taken before genesis: the node refuses such a directory by version rather than reading it, `repair` reports the version and offers no cut, and neither of them calls it corruption or tells you to resync. There is no in-place migration and none is coming — the remedy is a resync from the network, and it costs a resync rather than a chain fork, because the log is node-local and nothing in it is a consensus surface.

### Running the repair

```
zycordd repair --dir <the same --dir the node is given>
```

The report is printed again, then a proposal naming the exact byte offset and the exact number of bytes, then a prompt. Nothing is discarded until `yes` is typed in full. `--yes` skips the prompt for an unattended run; the report is still printed. The repair is not reversible.

What it will and will not do, stated plainly, because this is a command that deletes a node's data on purpose:

- It only ever **shortens the log at one offset**. It never rewrites a record, never touches the snapshot, and never repairs a damaged snapshot — the log holds only what was written after the snapshot, so no cut to it could recover one.
- It offers a cut **only when no intact record behind the damage declares itself the last record of its transaction**, and **only when the store's own `commits` file does not say a transaction at or above the first sequence the cut would remove was reported committed**. The first test is about what the log shows; the second is about what the store told a caller, and no reading of the log can substitute for it.
- It **rewrites `commits` to name exactly what survives the cut, before shortening the log**. That order matters: a `commits` file left claiming more than the log holds would make the node refuse the store you just repaired. If the machine dies between the two steps, nothing is lost — run the repair again.
- If the damage falls inside a multi-record transaction, **the whole transaction goes**, back to its first record. Its earlier parts are intact but were never applied, and leaving them behind would let the next commit's final record sweep them into a transaction that never happened.
- Before cutting, it **re-derives the diagnosis** and refuses unless the file and the offer are the ones that were shown. It cannot discard more than was approved.
- It **refuses to run against a live node**, via the same lock the node takes.

Take a copy of the directory first if you can afford the space. The repair is cheap to redo from a copy and impossible to undo without one.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing needed doing, or the repair was applied. `--dry-run` also exits 0 without changing anything. |
| 1 | The command refused, or it failed. Three cases share this code: damage it will not repair, a prompt that was declined, and an I/O failure. |
| 2 | The command line was wrong — a missing `--dir`, an unknown flag. Nothing was read and nothing was written. |

A script running with `--yes` cannot reach the declined case, so for it a 1 is "will not repair, or could not"; the two are told apart by the stream, since a refusal writes its verdict to stdout and a failure writes to stderr. Splitting them into distinct codes is deliberately not done: a stable exit code is
an interface, and widening it is a change every existing script has to be told
about, for a distinction the two streams already carry.

### Resyncing

When the report says to resync, the store cannot be recovered from what is on this machine. Stop the node, move the chain directory aside (do not delete it yet — it is the only evidence of what went wrong), and start the node with an empty one. It downloads the chain again from its peers. Keep `peers.json`: it is not part of the damage, and starting from a blank peer store hands an attacker a fresh chance to fill it.

Repeated corruption on one machine is a hardware report, not a software one. The node checksums every record it writes and every record it reads back, so a store that keeps failing this way is usually reporting a failing disk or unreliable memory.

## Choosing a network

A node runs mainnet unless you say otherwise. The other two embedded sets are selected **by name**, not by handing the binary a file:

```sh
zycordd --testnet --dir ./testnet
zycordd --devnet  --dir ./devnet
```

`--params FILE`, `--testnet` and `--devnet` are **mutually exclusive**, and naming two of them is refused rather than ranked. A node given two sources for the protocol it speaks is a node whose operator believes it is on a network it may not be on, and there is no ordering of the three that makes guessing safe.

`--testnet` matters because it makes the answer to "which network is this node on" a property of the binary rather than of the operator's disk. Joining the public testnet used to mean `--params spec/params.testnet.json`, so the parameters were whatever that file happened to contain. The set is embedded and its genesis is pinned by a vector, so the network a node joins and the params hash a release announces are both recomputable from the binary alone:

```sh
zcd genesis --testnet
```

`zcd` carries the same three flags — that is the point of the pair moving together. `genesis` prints the params hash beside the genesis id, taken over the same embedded bytes the parameters were parsed from, so a release announcement can be checked against the binary that will run it.

The public testnet has its own operator document: [TESTNET.md](TESTNET.md) — bootstrapping onto it, mining without a faucet, scraping `/metrics`, and what a reset does to a chain you are already holding.

## A different network is a different network

`--devnet` and `--testnet` are not flags that relax a check. Each selects a different parameter set, which produces a different genesis, which **is** the network id — so a devnet node and a mainnet node cannot connect at all. They disconnect at the handshake, before a block is evaluated.

That is structural rather than a filter, and it is why you cannot accidentally mine devnet coins onto mainnet.
