# Zycord

**Verify in parallel. Commit in order. Let the network do the work.**

Zycord is a proof-of-work-launched, proof-of-stake-bound Layer 1 built from **self-certifying state transitions**: every transaction carries the state it read and the state it wrote, so any machine can verify it statelessly — in a thread pool, on a GPU, with no disk and no history. The chain itself never executes. It orders *certificates* and commits them with a deterministic **fold** that applies what still holds and skips what doesn't — and every skip is billed to someone who signed up for the risk.

The result is a network whose **per-node cost falls as the network grows**, instead of the other way around.

---

## Mine in 60 seconds

The public testnet is live. There is no faucet — coins come from mining, which
is the distribution mainnet gets too.

**Take the archive with `-randomx` in its name** from this repository's
Releases page. The plain one carries no proof-of-work engine and refuses to
join a real network — it exists to be rebuilt and compared, not to be run.
`zycord.com` has per-platform links if you would rather click than choose.

Linux, or macOS on Apple Silicon:

```sh
tar xzf zycord-*-randomx.tar.gz
cd zycord-*-randomx
./zcd wallet new --out miner.json
./zycordd --testnet --dir ./testnet \
  --mine --payout $(./zcd wallet address --key miner.json)
```

**Windows** (PowerShell), from the `-windows-amd64-randomx.zip`:

```powershell
Expand-Archive zycord-*-windows-amd64-randomx.zip -DestinationPath .
cd zycord-*-windows-amd64-randomx
.\zcd.exe wallet new --out miner.json
.\zycordd.exe --testnet --dir .\testnet `
  --mine --payout (.\zcd.exe wallet address --key miner.json)
```

**What you should see.** `bootstrap: testnet.zycord.com:9421` and then
`peers=1` or more within a minute — the network finds itself, there is no peer
address to copy. Then a `block height=N` line each time you win one.

**Where the coins are.** `zcd wallet balance --key miner.json`. A reward is
spendable after `coinbase_maturity` blocks — 100 — so for roughly the first
hundred blocks only miners can transact. That ramp is mainnet's, and it is part
of what a public testnet rehearses: **mine to play**.

**If you start it early, it waits.** A node started before a network's first
block refuses to mine, says how long is left every ten minutes, and begins on
its own. Nothing to schedule and nothing to restart.

**Your operating system will warn you**, because there is no code-signing
certificate and there will not be one — buying one means publishing a verified
legal identity. On Windows: *More info* → *Run anyway*. On macOS: right-click
the binary → *Open*, or `xattr -d com.apple.quarantine <file>`. Running from a
terminal, which is what the commands above do, avoids the dialog on both.
[How to verify what you downloaded](docs/INSTALL.md) — after you have it
running, not before.

---

## The 30-second version

- **Certificates, not transactions.** A certificate declares its reads `[slot, value]` and writes `[slot, value]`. Validity = re-execute against the declared reads, compare the writes. Pure function of bytes. Embarrassingly parallel.
- **The fold.** State is a deterministic left-fold over ordered certificates: reads still hold → apply writes; reads stale → **skip**, bill the underwriter, move on. Inclusion ≠ application. Blocks are never invalidated by conflicts.
- **One signature, at most one bill.** Skipped certificates are marked seen; including a seen, expired, or under-bid certificate makes the *block* invalid. No block producer can farm your deposit.
- **Typed concurrency.** Contracts declare, per storage slot, whether access is *exact*, *guarded* (`balance ≥ x` + delta), or *pure delta*. Transfers, mints, and tips commute — a streamer receiving 10,000 tips in one block causes zero conflicts and zero skips.
- **Two gas markets.** Sequential gas prices state mutation (scarce). Parallel gas prices verification (abundant — it scales with every core and GPU that joins). Heavy cryptography is cheap *by economic construction*.
- **Fair launch, three eras.** Era 0: CPU proof-of-work (RandomX) distributes the coin — mine on the laptop you already have. Era 1: bonding, then bonded underwriters and sequencers and the cEVM by height — and checkpoint finality only once bonded stake sustains, because stake cannot be measured before the operation that creates it exists. Era 2: proof-of-stake proposes; PoW retires on a ramp. The fold never changes — only who orders. No premine and no allocation; 3% of each block subsidy accrues to a treasury cell that no key can open before Era 2.

Read the [whitepaper](docs/whitepaper.md) for the argument, the [architecture spec](docs/ARCHITECTURE.md) for the rules, and the [adversarial reviews](docs/adversarial/) for how we try to break them before you do.

## Status

**Pre-genesis. The public testnet has been live since 2026-08-30. Mainnet
genesis is 2026-09-15 00:00 UTC.** Consensus parameters and golden vectors
freeze before that; until they do, a change is a release, and after they do, a
change is a fork.

| Milestone | Scope | Status |
|---|---|---|
| **M0 — The fold on paper** | pure state machine, golden vectors, griefing suite, differential re-implementation | ✅ implemented; 🟡 the 72 h fuzz run is **in flight since 2026-08-31**; ⬜ external review open |
| **M1 — One node** | storage, mempool, RPC, wallet CLI, dev-PoW | ✅ implemented |
| **M2 — A network** | p2p, hash-first relay, sync, reorg torture | ✅ implemented; 🟡 the multi-day chaos soak is **in flight since 2026-08-31** and is the thinnest evidence here |
| **M3 — Real work** | RandomX behind the `pow` interface, LWMA difficulty, the canonical build container | ✅ implemented; ✅ two adversarial passes over the binding ([I7](docs/adversarial/I7.md)); ⬜ external review of the binding open |
| **M3.5 — A public testnet** | resettable testnet, faucetless self-mining, bootstrap seed, scrape-format metrics | 🟢 **live** — [how to join](docs/TESTNET.md); ⬜ the [§1 measurements](docs/decisions/testnet-measurements.md) it exists to produce are still being collected |
| **M4 — Adversaries** | public attack-net, external review, reproducible-build attestations | ⬜ **open and wanted.** The attestation tooling ships ([attestations/](attestations/)); no external review has been done. If you can break it, [SECURITY.md](SECURITY.md) |
| **M5 — Genesis** | parameter freeze, vector freeze, v1.0, announced launch | 🟡 date set; the freeze is what closes it, and the four genesis-irreversible numbers are re-verified at the freeze commit ([RELEASE.md](docs/RELEASE.md)) |

**Two rows say "in flight" rather than "done", and that is deliberate.** Both
runs had been done before and their logs were not kept. A green checkmark whose
evidence nobody can open is worth less than a yellow one with a date on it, so
they are running again and the row changes when there is a record to link.

**Why the history is three commits.** It was squashed before publication, as
[RELEASE.md §1](docs/RELEASE.md) requires: the public tree is built from the
working tree with no history, because a commit log is a timezone, a routine and
a set of machine names as much as it is a record of changes. What the code was
before is therefore not reconstructable from this repository, and the
[adversarial reviews](docs/adversarial/) are where the reasoning lives instead.

**What exists today.** The whole state machine: certificates, the four native operations, stateless validity, the fold, the block rules that enforce the billing law, proof-of-work and difficulty, the reproducible genesis, and a reference wallet that builds certificates. It is covered by the golden vectors in [`spec/vectors/`](spec/vectors/), a griefing suite that plays the malicious block producer, and a second deliberately naive implementation of the fold that is fuzzed against the first.

**And a node.** `zycordd` runs a private chain: a crash-safe store whose commits are atomic at every byte offset, a mempool with a deposit screen, a block builder that dry-runs its own candidate, a read-only RPC on localhost, and real RandomX behind the same interface the development engine occupies.

**And it syncs.** A node that joins late, or falls behind, catches up headers-first: each header is checked against the target the difficulty rule *computes* rather than the one it declares, so accumulated work is a fact before a single body is requested. Reorgs land as one atomic commit. All of it is exercised by a soak that runs real nodes over sockets with latency, loss, severed connections, partitions and `kill -9`, and asserts they end on one chain with one state root.

**And a network.** Nodes authenticate over standard-library TLS 1.3, gossip certificates that are validated before they are ever re-propagated, relay blocks hash-first with the work checked before any body is fetched, and converge on the heaviest chain after a partition heals. Peer selection is address-diverse and the peer store survives a restart, because a node that reboots into a blank slate is a node an attacker can eclipse cheaply.

**And a wallet you can open.** One wallet interface, served two ways: `zcd ui`
puts it in a browser over a loopback socket that binds nowhere else, and the
desktop application in [`desktop/`](desktop/) puts the same files in a native
window with no port at all. Both go through the same `wallet/session`, so a
graphical wallet is structurally incapable of being more permissive than the CLI
— every rule in [docs/WALLET.md](docs/WALLET.md) applies to all three by
construction rather than by whoever wrote the third one remembering. There is no
transaction list, because the node keeps no history and an interface should not
promise what the network does not have.

**What does not exist yet.** Bonded underwriters, sequencers, the forced queue and the cEVM are Era-1 rules and are absent from the genesis binary on purpose — unreachable consensus code is unauditable consensus code. The whitepaper's §15 measurements are filled in and come from this tree — `make bench` runs the benchmarks behind them — but they are one desktop's numbers, not a network's: the parallelism figure is ten cores of one machine, signature verification is measured one signature at a time because the batch path is not written, and nothing here has yet been measured on a public testnet.

## Install

```sh
# Anyone with a Go toolchain — no release needed, and nobody to trust.
git clone <this repository> && cd zycord

make build           # pure Go, reproducible, devnet only
make build-randomx   # needs a C++ toolchain; this is the one that joins a network
```

**Those two builds are not interchangeable, and picking the wrong one is the
most common way to be stuck.** `make build` is pure Go and byte-identical
across machines, which is what lets a stranger rebuild this tag and compare —
but it carries no proof-of-work engine, so it *refuses to start* on mainnet and
on the public testnet, both of which declare `randomx-v1`. `make build-randomx`
is the one that joins, needs a C++ toolchain, and is reproducible nowhere. The
release publishes both, labelled, and [docs/INSTALL.md](docs/INSTALL.md) is
where the difference is argued rather than asserted.

Homebrew and Scoop are named in `packaging/` and in the install guide, but the
tap and bucket repositories do not exist yet, so those two commands are not
offered here. Until they do, the paths above and a release archive are the ways in.

Or download a release, verify it, and unpack it — [docs/INSTALL.md](docs/INSTALL.md)
has the per-platform detail, the verification commands, and **why there is no
code-signing certificate**: an Authenticode certificate is a certificate
authority attesting to a verified legal identity, and this project is published
pseudonymously. What it offers instead is a build you can reproduce yourself, and
[independent attestations](attestations/) from people who did.

```sh
zcd genesis                 # rebuild block 0 and check it against the announced values
zcd vectors                 # check this build against the protocol
zcd wallet new --out miner.json
zcd ui --key miner.json     # the wallet, in your browser, on loopback only
```

There is also a **desktop wallet** — the same interface in a native window, which
opens no network port at all. It is the one artefact here that is **not attested
on any platform**, and on Linux and macOS not byte-identical across rebuilds
either, because it uses cgo to reach the platform's webview. That is stated
rather than glossed, and `zcd ui` is the reproducible, attested way to get the
identical interface. See [desktop/](desktop/) and
[docs/INSTALL.md](docs/INSTALL.md) for the per-platform detail.

## Build from source

Requires the pinned Go toolchain (see `go.mod`). Nothing else: `make build` has no third-party dependencies and no cgo, and produces a binary carrying the development proof-of-work engine.

The mainnet engine is RandomX, compiled behind the `randomx` build tag — `make build-randomx`, which writes `bin/zcd-randomx` and `bin/zycordd-randomx` so that the tagged binaries never overwrite the untagged ones — because it is C++ and cgo, and the default build's freedom from a C toolchain is worth keeping: the consensus rules stay auditable by anyone with a Go toolchain, and only the work function needs a compiler. A binary without the tag **refuses to start** on a network whose `pow_engine` it cannot compute, rather than falling back to an engine that would call every forgery valid.

Because that build has a C toolchain in it, *which* compiler ran stops being incidental: `-trimpath` and a pinned Go toolchain say nothing about it. `make canonical` builds both pairs inside [`build/Dockerfile`](build/Dockerfile), which pins everything by content — see [docs/RELEASE.md](docs/RELEASE.md) §5. RandomX is pinned by the repository rather than by the container — `core/pow/randomx/pinned.go` carries a hash of the vendored tree and `TestVendoredTreeMatchesPinned` recomputes it in pure Go, so it is checked by `go test ./...` on a machine with no C toolchain at all.

```sh
git clone <this repository>
cd zycord
make build          # builds ./bin/zcd and ./bin/zycordd

# run a devnet node, mining to an address you control
./bin/zcd wallet new --out miner.json
./bin/zycordd --devnet --dir ./devnet --mine --payout $(./bin/zcd wallet address --key miner.json)

# and, from another terminal, spend what it mines
./bin/zcd wallet balance --key miner.json
./bin/zcd wallet send --key miner.json --to <address> --amount 500000000
```

Running a node for real — reachability, port forwarding, mining, and what the node deliberately cannot do — is in [docs/RUNNING.md](docs/RUNNING.md).

And to work on it:

```sh
make ci             # vet, formatting, the import graph, every test, the differential fold
make vectors        # regenerate the golden vectors (a diff here is a consensus change)
make fuzz           # fuzz the decoders
make dist           # release artefacts for every platform, with checksums
```

Mainnet mining will be CPU-only (RandomX), 30-second blocks, `21 ZCD`/block at genesis, halving every two years down to a perpetual `0.33`/block tail reached at height 12,602,880, around year 12 — a pre-tail supply of about `62.74M`. Ninety-seven percent of each subsidy pays consensus and three percent accrues to a treasury cell that no key can open before Era 2 (below). For the first ~100 blocks only miners can transact (coinbase maturity funds the first deposits): **mine to play**.

## The rules we can't break

These are structural commitments, not promises:

1. **Zero premine, zero founder allocation, zero investor round.** Every coin that will ever exist is mined or staked into existence under public rules. Genesis allocates nothing to anybody — `zcd genesis` prints `allocations 0`, and the treasury cell reads zero at block 0.
2. **No admin keys.** There is no code path by which any key can pause, upgrade, censor, or mint. Feature activations are height-gated constants in public releases. The Era-2 treasury quorum is not an exception: it does not exist in genesis, it arrives only if a hard fork writes it in, and it can move one cell and nothing else.
3. **Reproducible builds.** Every release builds byte-identically from source. Trust the code, not the binary — it's the only trust an anonymous author can offer.
4. **Reproducible genesis.** `zcd genesis --params spec/params.json` — anyone can rebuild block 0 and check the announced hash.
5. **The spec is public and executable.** `spec/` holds the golden vectors that *are* the protocol. An independent implementation that passes them is a peer, not a fork.

## Repository layout

```
spec/        the protocol: params.json + golden test vectors        ← consensus, highest review bar
core/        fold, validity, types, crypto, PoW                     ← consensus-critical Go, stdlib-only
  u256/        256-bit arithmetic that never silently wraps
  crypto/      domain-separated hashing, BLAKE3 in-tree, strict Ed25519
  ssz/         canonical encoding and merkleisation
  types/       every object the consensus rules can see
  params/      the genesis parameter set and its invariants
  state/       cells, the spent registry, the seen set, the state root
  validity/    the V-rules — stateless, parallel, state-free
  fold/        the F-rules and the block rules that enforce the billing law
  pow/         the work interface, the dev engine, LWMA difficulty
  genesis/     block 0
node/        the node around the core                             ← no third-party code either
  storage/     crash-safe key-value store; a batch is durable or absent
  chain/       persistence, the atomic block commit, startup integrity
  mempool/     admission: the V-rules plus non-consensus policy
  miner/       block selection and assembly
  rpc/         read-only HTTP on localhost; submission is the only write
  p2p/        transport, handshake, gossip, peer scoring, eclipse resistance
wallet/      key management, certificate builders, the docs/WALLET.md rules
  session/     the one wallet -> node path; every interface spends through it
  webui/       the wallet interface: embedded frontend, no npm, no build step
sim/         adversarial simulator, differential fold, harness
cmd/         zcd (cli, wallet, `zcd ui`), zycordd (node)
desktop/     the desktop wallet                                   ← a SEPARATE Go module
packaging/   Scoop manifest, Homebrew formulae, AppImage, install.sh
attestations/  independent reproducible-build signatures, per release
docs/        whitepaper, architecture spec, adversarial reviews
```

`desktop/` is a separate module on purpose. Wails brings cgo and a large
dependency tree, and the root module's two direct dependencies are a promise
this repository keeps literally: `go list -m all` at the root does not mention
it, `go test ./...` never compiles a webview, and `bin/zcd` stays byte-identical
and cgo-free.

Dependency arrows point inward only (`node → core`, never the reverse), and `core/` imports nothing outside the standard library. Both are enforced by `make check-imports` in CI, not by convention. `core/` and `spec/` changes require golden vectors and simulator runs **before** human review is scheduled — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

Contributions are wanted — and treated as hostile by default, because in a blockchain node **a merge is consensus power**. The repository is split by blast radius: the **consensus zone** (`core/`, `spec/`) is slow on purpose, and the **node zone** (`node/`, `wallet/`, `sim/`, `docs/`) is normal open-source flow and where new contributors are grown.

Full policy in [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerability disclosure in [SECURITY.md](SECURITY.md) — if you can make one signature bill twice, or make a third party's certificate skip in Era 0, that's a critical finding and we want it before genesis.

## Governance

**This repository is a reference implementation, not the network.** Node operators decide what code they run; protocol changes happen by social consensus and hard fork, and there is no other mechanism — none is hidden. If this repository ever misbehaves, the correct response is to fork away from it, and the reproducible builds, public vectors, and MIT license exist precisely so that response stays cheap. There is no foundation and no company.

**Funding.** Eras 0 and 1 are funded by donation — proposals public before payment, budget up front, release against delivered work. From block 0, three percent of every block subsidy also accrues to a **treasury cell**, which is *sealed*: genesis contains no key, no address and no spend path for it, and the Era-0 binary can only credit it. If a hard fork never writes a quorum in, the cell never opens and those coins are never issued. The share is taken from issuance and never from fees, so it dilutes holders in proportion to holdings rather than taxing users. Removing it costs what any consensus change costs: a hard fork. The reasoning is [whitepaper §14.1](docs/whitepaper.md); the mechanics are [ARCHITECTURE §6, §8, §15, §17](docs/ARCHITECTURE.md).

## Documentation

- [Whitepaper](docs/whitepaper.md) — the design and its argument, by The Simstoshi
- [Architecture & Implementation Spec](docs/ARCHITECTURE.md) — the engineering companion to the whitepaper: it explains the normative surface and records the decisions behind it. It is **not** itself normative — the protocol is `spec/params*.json`, `spec/vectors/`, `spec/README.md` and the named rules (V\*, B\*, F\*, I\*), with `docs/spec/wire.md` carrying the peer-layer MUSTs — and where it disagrees with that surface, the surface wins and the document is corrected
- [Adversarial Review R1](docs/adversarial/R1.md) — 16 findings against our own design, 3 critical, all disposed before a line of consensus code
- [Implementation Findings I1](docs/adversarial/I1.md) — 15 findings from actually building it, 3 critical; the spec changed rather than the code quietly diverging
- [Adversarial Review R2](docs/adversarial/R2.md) — the second reading, of I1 and of the economics; two new findings, one of which changed the certificate format
- [I1-H2: Miner Revenue and the Two Markets](docs/adversarial/H2-economics.md) — every revenue line a miner has, what each one incentivises, why an unpriced scarce resource is sold off-chain rather than given away, and why the fee bid has two fields per market instead of one
- [Implementation Findings I2](docs/adversarial/I2.md) — building the node; the storage engine is written in-tree rather than imported, and the argument is here
- [Implementation Findings I3](docs/adversarial/I3.md) — building the network; including the bug that would have left every node permanently on its own fork
- [Implementation Findings I4](docs/adversarial/I4.md) — finishing the network; three things that reported success while measuring nothing
- [Implementation Findings I7](docs/adversarial/I7.md) — binding RandomX; the milestone where the *build* joined the list of instruments that report success while measuring nothing
- [Implementation Findings I5](docs/adversarial/I5.md) — auditing our own instruments; four more that reported success while measuring nothing
- [Implementation Findings I6](docs/adversarial/I6.md) — building the elastic block ceiling; three of four defects found by reading rather than running, including one the differential fold was structurally blind to, and one that was a false claim rather than a bug
- [The sync adversary](docs/adversarial/sync.md) — how one peer with one lie could stop a node syncing forever, and the rotation that fixes it
- [Concurrent access to consensus state](docs/adversarial/concurrency.md) — a data race the whole test suite missed, and why `-race` said it was fine
- [Mempool admission and eviction](docs/adversarial/mempool.md) — the censorship vector a full pool creates, and the price-eviction that closes it
- [Decision: the networking stack](docs/decisions/networking.md) — 141 modules weighed against auditability, and what would reverse the answer
- [The public testnet](docs/TESTNET.md) — joining, bootstrapping, mining, scraping, and what a reset is
- [What the testnet must measure before genesis](docs/decisions/testnet-measurements.md) — the numbers a wrong value makes a fork, separated from the ones it makes a release
- [Wire protocol specification](docs/spec/wire.md) — the peer protocol, written so a second implementation can be built from it alone
- [Wallet rules](docs/WALLET.md) — the behavioural contract the findings accumulated, in one place, with the finding that motivates each rule
- [Release procedure](docs/RELEASE.md) — reproducible builds, the genesis announcement, when to publish, and the anonymity checklist for the public tree
- [`spec/`](spec/README.md) — the protocol itself, as parameters and executable JSON

## License

[MIT](LICENSE). Fork it, study it, ship it.

## Disclaimer

Zycord is software, not an offering. There is no sale, no allocation, no promise of value, and nobody to make one. The code, when it runs, will say the rest.

---

*Zycord does not chase the work. It holds still, and the network does the work.*