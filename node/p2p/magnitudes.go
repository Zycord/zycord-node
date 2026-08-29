package p2p

// Derived magnitudes for the reassembly and connection-set arguments.
//
// **Every figure here is evaluated, never transcribed.** The comments in this
// package argue about magnitude — "multiplies past a 256 MiB budget", "is
// still the larger figure" — and each of those arguments is a product of
// named constants. Written down as a numeral, the product goes stale the
// moment one of its inputs moves, and it goes stale *invisibly*: the sentences
// are always used to support an inequality, and the inequality survives the
// correction, so the sentence stays true while the claim underneath it weakens
// and nobody recomputes it — eight such instances were catalogued in this tree.
//
// So the products live here, computed from their inputs, and the prose cites
// the name beside the figure rather than the figure alone. The numerals stay
// in the prose on purpose — replacing "≈ 768 MiB" with a symbol leaves a
// sentence that parses but no longer argues, since the reader can no longer
// see that it passes 256 MiB without performing the multiplication nobody
// performed eight times. What the name buys is that the numeral is now
// checkable against something the compiler evaluates, and that
// magnitudes_internal_test.go asserts the *relations* the prose actually
// claims rather than the values it quotes.
//
// **The two forties are two different quantities and that is the whole
// point.** `honestSteadyStateConns` and `maxConnections` are not the same
// number in the same role that happens to disagree; they are an expectation
// over the honest connection set and an adversarial worst case, and at the
// committed defaults the first is 40 while the second is 48. Before these
// names existed both were spelled as a bare `40` — the honest one correctly,
// the adversarial one staler by 8 — with nothing in the source saying which
// was meant. A sweep that grepped this package for `40` and wrote `48` would
// have introduced two defects while fixing none. Two names make that a
// compile-time distinction instead of a review question.
const (
	// honestSteadyStateConns is what an honest node's connection set peaks at:
	// its inbound allowance plus the outbound dials topUp makes. It is an
	// expectation and not a bound — it is the right multiplier for "what does
	// the honest network hold at once", and the wrong one for anything an
	// adversary arranges. Use maxConnections for the latter.
	honestSteadyStateConns = DefaultMaxInbound + DefaultMaxOutbound

	// maxConnections is C, the bound on the concurrent connection set, and it
	// is larger than honestSteadyStateConns because Node.register's capacity
	// gate is inbound-only: inbound is admitted below MaxInbound+MaxOutbound
	// and topUp then dials up to MaxOutbound *above* that gate, so the set an
	// adversary can arrange is MaxInbound + 2 x MaxOutbound. This is the
	// multiplier for every worst-case argument in this package.
	maxConnections = DefaultMaxInbound + 2*DefaultMaxOutbound

	// honestSteadyStatePeakBytes is the reassembly footprint of every honest
	// peer being mid-transfer on a multi-chunk block at once — the figure
	// MaxReassemblyBytes is sized to sit above. It is honest-set arithmetic,
	// so it takes honestSteadyStateConns and not maxConnections; using C here
	// would overstate an honest steady state, which is the opposite error and
	// a harder one to spot because it would look like consistency.
	honestSteadyStatePeakBytes = honestSteadyStateConns * BlockChunkBytes

	// socketBound is the reassembly demand a hostile connection set can pin
	// through the per-peer transfer slots: every socket holding
	// MaxTransfersPerPeer transfers, each one chunk in. It is the *reachable*
	// bound, since the connection set is what an attacker actually controls.
	socketBound = maxConnections * MaxTransfersPerPeer * BlockChunkBytes

	// tableBound is the same product taken over the partial-transfer table
	// instead of the connection set. It is the larger of the two exactly while
	// maxConnections <= MaxPartialTransfers — which is why the relation and
	// not the pair of values is what magnitudes_internal_test.go pins — and it
	// is the weaker argument of the two, because a full table needs more peers
	// than the connection set admits.
	tableBound = MaxPartialTransfers * MaxTransfersPerPeer * BlockChunkBytes
)

// liveReassemblyBound is this node's whole reassembly footprint at a given
// era ceiling, which is strictly more than MaxReassemblyBytes bounds.
//
// MaxReassemblyBytes counts *buffered* bytes, and two classes of byte sit
// outside it at the completion boundary: dropTransfer repays cap(p.buf) before
// the lock is released while `body` keeps that buffer alive for the whole of
// OnBlock, and a single-chunk transfer never enters the counter at all. serve
// runs one goroutine per connection and runs Handle to completion before
// reading the next frame, so a connection contributes at most one such body
// and the uncounted term is maxConnections x blockByteCapacity.
//
// It takes the capacity rather than reading a params set because that term is
// what an era boundary re-pins, so the bound is a function of the era and not
// a constant of the build.
func liveReassemblyBound(blockByteCapacity int) int {
	return MaxReassemblyBytes + maxConnections*blockByteCapacity
}

// countImpliedBound is what the two count bounds alone would permit: a hostile
// connection set filling every per-peer transfer slot with a full-capacity
// block. It is the figure that made MaxReassemblyBytes necessary — the count
// bounds multiply, and nothing in them bounds the memory behind them — and it
// is stated here so that "far under the count-implied worst case" is a
// comparison against something evaluated.
func countImpliedBound(blockByteCapacity int) int {
	return maxConnections * MaxTransfersPerPeer * blockByteCapacity
}
