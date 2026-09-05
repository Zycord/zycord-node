# Zycord — Structural capacity rides the era ladder

**Scope:** the static bounds behind §8.1's elastic target — `CertListCapacity`, `BlockByteCapacity`/`SeqGasCapacity`, and the transport constants beneath them — and how each may ever move. Raised when the three were observed to cap the network at 3.2× its genesis throughput (~300 certificates/second) while the elastic mechanism's own growth rate (`Γ` = 512, ≤2×/year of full blocks) implies order 10⁵/second in ten years if nothing else binds.

**Verdict:** the walls were sized correctly for launch and placed incorrectly for the curve. One was load-bearing in the wrong layer — the byte capacity was pinned to a transport frame constant, so raising consensus capacity required a transport change and vice versa. The resolution is one rule and one decoupling.

---

## 1. The rule

**Each structural capacity is classified by what re-pinning it costs, and that classification decides when it is sized.**

| Bound | Re-pin cost | Therefore |
|---|---|---|
| `CertListCapacity` | changes `CertRoot`'s merkle width — a height-gated encoding fork, two widths in one chain | sized **at genesis for the whole curve**: 2²⁵ = 33,554,432, i.e. 1,118,481 certificates/second at 30-second blocks. In-era growth never reaches that — `T` is clamped at `seq_gas_capacity`, so the count ceiling tops out at genesis × 3.2 = **12,800 certs/block** (~427/s at 30-second blocks), **2,621× below** 2²⁵. That slack is headroom for the successive per-era re-pins of `seq_gas_capacity` the curve climbs through, not a level in-era growth attains. The padding is virtual (`ssz.Merkleize` zero-subtrees), so the headroom costs tree depth and nothing else |
| `BlockByteCapacity`, `SeqGasCapacity` | a params-only value change, at the fixed genesis ratio | sized **for the launch network**, re-pinned **at era boundaries** — hard forks the schedule already contains — against propagation measured on the running network |
| `MaxBlockChunks`, `BlockChunkBytes`, announcement bounds | a node release, no consensus | raised in the release that accompanies a re-pin; `TestBlockByteCapacityFitsChunkedTransfer` fails any release that forgets |

The health gate (§8.1) remains the *within-era* governor: `T` never outruns demonstrated propagation between re-pins. The era boundary is the only place the walls themselves move, which keeps routine growth inside upgrades node operators already adopt for other reasons, and keeps it out of votes — the whitepaper's constraint that growth must not be a governance event, now satisfied across eras rather than only inside one.

## 2. The decoupling

A block previously travelled as one frame, so `MaxMessageBytes` (8 MiB) was a consensus-adjacent constant: `BlockByteCapacity` could never exceed it without partitioning the network, and the pairing test pinned the two together. That made the transport the layer that decided the chain's terminal throughput — backwards for a network whose thesis is that the transport-facing resources scale out.

Blocks now travel as chunks (`docs/spec/wire.md` §5.1): stateless serving, reassembly keyed by (peer, block id), the claimed total never an allocation. Reassembly carries three bounds because they bound different things — transfers per peer, peers, and total bytes held — and only the last is memory: the count bounds multiply to ≈1.54 GB across a full connection set (`countImpliedBound` in `node/p2p/magnitudes.go`, at 48 connections — `maxConnections`, `MaxInbound + 2 × MaxOutbound`, the inbound gate being inbound-only; see `Node.register`, and note that this is *not* the honest steady state's 40, `honestSteadyStateConns`), which is why `MaxReassemblyBytes` exists and is pinned by a test rather than left implied by the counts. The frame limit bounds a message; `MaxBlockChunks × BlockChunkBytes` (4 × 4,194,304 = **16,777,216 bytes**) bounds a block; the consensus capacity sits under the latter with **2.10×** headroom, which is the pair's own slack and not room for a re-pin — so the transport constants move in the release that carries the first one, which is what `TestBlockByteCapacityFitsChunkedTransfer`'s upper bound exists to force.

`BlockChunkBytes` is 4 MiB — above `block_byte_limit_genesis`, so a block at the genesis ceiling is a single chunk and the launch network pays no extra round trip, and below `MaxMessageBytes`, so a chunk is still one frame. It is also a propagation parameter, and that is the open constraint this design carries: chunks are fetched one round trip each, so an `n`-chunk block costs `n` sequential round trips, and slower propagation raises the competing-header rate the health gate reads. At the current capacity `n ≤ 2` and the cost is noise. **A large capacity re-pin makes it material, so pipelined chunk requests — a serve loop that answers one message with several — are a precondition for the first substantial re-pin, not an optimisation after it.**

## 3. Rejected alternatives

- **Raise the genesis capacities now.** Rejected: a young network's fork rate is its scarcest resource (R1-M4), and nothing about launch traffic needs more than 2.5 MB blocks. The finding was never that genesis is too small — it is that the walls could not move later without touching the wrong layer.
- **Make the byte capacity elastic under the health gate, like `T`.** Rejected for Era 0 on the project's own principle: it is more consensus machinery in the genesis binary, its failure mode (capacity growing past what an un-upgraded node's transport constants carry) recreates the partition the clamp exists to prevent, and the era ladder already provides scheduled, audited moments to move the walls. Reopen at Era 2 if re-pin cadence proves too coarse.
- **Leave `CertListCapacity` at 2¹⁶ and re-pin it at eras like the byte capacity.** Rejected: its re-pin is not a value change but an encoding fork — every `CertRoot` after the fork height merkleises against a different width, so two widths coexist in one chain and every verifier carries both forever. 2¹⁶ also caps the chain at ~2,184 certificates/second, under the curve's second year. The one capacity that is expensive to move later and free to oversize now is oversized now.
- **Size it against the curve's ten-year mark (2²²) rather than its end.** Rejected, and the first revision of this document made exactly this mistake: 2²² is 139,810 certificates/second — a genesis-frozen wall the era-re-pin curve would climb to and then be unable to move past, sited just under the order-10⁶ figure the full curve otherwise reaches. A bound that cannot be re-pinned must be sized against the end of the trajectory it bounds, not against a point on it; the extra three levels of tree depth cost nothing, and the mistake was invisible until the paper's own arithmetic was checked against the parameter.
- **Compress certificates instead (the §13 `(cert_id, index)` reference scheme), making the walls matter less.** Not an alternative but a complement, and not taken here: the paper itself holds it hostage to an unresolved consensus question (what a reference to a skipped certificate resolves to), and this decision must not smuggle that answer in. The walls are placed correctly whether or not certificates later shrink.

## 4. What is pinned by tests

| Test | Property |
|---|---|
| `TestBlockByteCapacityFitsChunkedTransfer` | consensus byte capacity ≤ transport chunk ceiling; announcement bounds cover the reachable certificate ceiling `MaxCertsPerBlock(SeqGasCapacity)`; recomputes on any re-pin |
| `TestReassemblyBufferHoldsExactlyTheBytesSent` | chunk reassembly is byte-faithful, asserted on the buffer itself rather than on failure shapes |
| `TestChunkedTransferCannotExceedTheByteCapacity` | a claimed total buys no allocation; the consensus capacity cuts a transfer off at the bytes actually sent |
| `TestChunkContinuingNoTransferIsRefused` | a chunk matching no held transfer drops that transfer alone, and never scores |
| `TestConcurrentTransfersFromOnePeer` | overlapping fetches from one peer do not evict each other, so an honest peer serving two requests is not banned |
| `TestTransfersPerPeerAreBounded` | transfers per peer are bounded by eviction of the oldest, never by scoring the peer |
| `TestPartialTransferTableIsBounded` | at most `MaxPartialTransfers` reassembly buffers, and a full table is never the peer's fault |
| `TestReassemblyMemoryIsBounded` | total held bytes never pass `MaxReassemblyBytes` — the bound the count bounds do not give, since `countImpliedBound` (48 connections × `MaxTransfersPerPeer` × `block_byte_capacity`) is ≈1.54 GB |
| `TestReassemblyMagnitudeRelationsHold`, `…AtTheShippedCeilings` | the *relations* the magnitude figures above argue from, not the figures themselves: `maxConnections ≤ MaxPartialTransfers`, `tableBound > socketBound`, `socketBound > MaxReassemblyBytes > honestSteadyStatePeakBytes`, `liveReassemblyBound > MaxReassemblyBytes`. A re-pin that leaves a figure stale but its sentence still true fails here |
| `TestReassemblyByteAccountingMatchesTheBuffers` | the byte counter equals the buffers it describes across every removal path, since a drifted counter under-reports and silently stops bounding |
| `TestForgetPeerReleasesTransfers` | a disconnect releases the peer's transfers and their bytes; without it the table fills permanently |
| `TestAnAnnouncementCannotPanicTheNode` | the announce refusal now sits at the reachable ceiling, under the transport bound, so the check is arm-able from the wire |

## 5. What the testnet must measure before the first re-pin

The sustained bandwidth a commodity node actually holds — added to [testnet-measurements](testnet-measurements.md) — because every re-pin sizing argument reduces to it. 8 MB per 30-second block is ~2.1 Mbit/s sustained; the first era re-pin should be derived from the measured distribution of node bandwidth, with the same written-argument discipline as every §1 entry there.
