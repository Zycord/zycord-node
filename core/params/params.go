// Package params defines the genesis parameter set.
//
// Everything in this file is frozen at genesis and changeable only by a hard
// fork. The canonical values live in spec/params.json — this package holds the
// shape and the invariants, never the numbers, so that a reader who wants to
// know what the chain does looks at the JSON and a reader who wants to know
// what is *allowed* looks here.
//
// The package does no I/O. Loading spec/params.json is the job of the `spec`
// package, which embeds it at compile time.
package params

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"reflect"

	"zycord/core/u256"
)

// workCollapseTarget is 2^255: the smallest target for which BlockWork —
// floor(2^256 / (target + 1)) — returns one, so that every header carries the
// same work and fork choice degenerates into a block count. MaxTarget must
// stay strictly below it (F-PARAM-1).
var workCollapseTarget = u256.MustFromDecimal(
	"57896044618658097711785492504343953926634992332820282019728792003956564819968")

// Params is the complete genesis parameter set.
type Params struct {
	// Identity.
	Name    string `json:"name"`
	ChainID uint64 `json:"chain_id"`

	// Certificate shape limits (V1). Every list in a certificate carries a
	// genesis-fixed maximum length, because an unbounded list is an unbounded
	// verification cost and an unbounded merkle depth.
	MaxReads            int    `json:"max_reads"`
	MaxWrites           int    `json:"max_writes"`
	MaxSigs             int    `json:"max_sigs"`
	MaxMovesPerTransfer int    `json:"max_moves_per_transfer"`
	MaxRetireAddrs      int    `json:"max_retire_addrs"`
	TTLMax              uint64 `json:"ttl_max"`

	// Block ceilings (whitepaper §8.1). The sequential target T is not a
	// constant: it is consensus state (types.SeqGasTargetSlot), a function of
	// measured demand from block 0. Everything below is either T's genesis
	// value/floor, a fixed ratio scaled from it, or a hard structural bound
	// that T's growth may never be asked to exceed.
	//
	// SeqGasTargetGenesis is T₀: the initial and minimum value of T. The
	// sequential ceiling is 2T (SeqGasLimit(t)) and the burst bound is 4T
	// (SeqGasBurst(t)); conservative at launch (R1-M4), since a young
	// network's fork rate is its scarcest resource, and elastic thereafter.
	SeqGasTargetGenesis uint64 `json:"seq_gas_target_genesis"`

	// ParGasRatio is the parallel market's fixed multiple of the sequential
	// ceiling: abundant, priced cheap, and growing only because the sequential
	// ceiling it tracks does (§8's invariant restated as capacity in §8.1).
	ParGasRatio uint64 `json:"par_gas_ratio"`

	// MaxCertsPerBlockGenesis and BlockByteLimitGenesis are the genesis values
	// of the certificate-count and byte-size ceilings; both scale with T
	// (MaxCertsPerBlock(t), BlockByteLimit(t)) rather than staying fixed.
	MaxCertsPerBlockGenesis int `json:"max_certs_per_block_genesis"`
	BlockByteLimitGenesis   int `json:"block_byte_limit_genesis"`

	// MaxSigsPerBlockGenesis is the genesis value of the third policy ceiling:
	// the number of signatures a block's certificates may declare in total
	// (B18), scaling with T exactly as the count and byte ceilings do.
	//
	// It exists because gas_par_per_sig cannot do this job and price the
	// parallel market at the same time. That parameter has two consumers: it
	// *bounds* verification per block through ParGasLimit, and it *prices*
	// parallel-gas density per byte, which is what NextBaseFee compares against
	// the target. Recalibrating it upward to bound verification honestly — the
	// direction the pre-launch audit recommended — moves an ordinary transfer's
	// parallel density from 2.23 to 5.52 gas per byte, so a byte-full block of
	// ordinary payments applies ~2.9x the parallel target instead of the 1.19x
	// the shipped calibration gives, and the derived Era-0 density limit crosses
	// B6's inertness threshold. The two requirements pull one parameter in
	// opposite directions; no value resolves it. So the price stays where that
	// calibration put it and the bound gets a parameter of its own.
	//
	// The precedent is Bitcoin's MAX_BLOCK_SIGOPS: a per-block
	// signature-operation ceiling distinct from the byte limit, in production
	// since 2010 and carried through segwit as MAX_BLOCK_SIGOPS_COST. Price
	// and ceiling are different questions and get different numbers.
	//
	// Checked before any signature is verified (core/fold's checkBlockRules),
	// which is the whole point: a ceiling consulted after the verification it
	// bounds would bound nothing. The number's derivation is in
	// spec/params.json's note on the parameter, because that is where the
	// numbers live.
	MaxSigsPerBlockGenesis int `json:"max_sigs_per_block_genesis"`

	// CertListCapacity is a structural bound, not a policy one: it fixes the
	// SSZ decode limit and the merkle padding width of every certificate list
	// (CertRoot), so it cannot itself move with T — a capacity that changed
	// with height would make one certificate list hash to different roots at
	// different heights. MaxCertsPerBlock(t) is clamped to it.
	CertListCapacity int `json:"cert_list_capacity"`

	// BlockByteCapacity is the second structural bound, and it exists because
	// a block that consensus calls valid must still fit in a network message.
	// BlockByteLimit(t) is clamped to it.
	//
	// Without the clamp the byte ceiling scales with T forever, and T grows
	// whenever demand fills the target — which, under a working fee market,
	// is continuously: §8's EIP-1559 controller steers applied gas toward T,
	// so 2·median lands near 2T, the growth clamp binds every epoch, and T
	// rises at its maximum rate on a *healthy* chain rather than only under
	// attack. From the genesis values that crosses an 8 MiB frame limit in
	// roughly 620 epochs. The failure is not a rejected block: it is a block
	// every node agrees is valid and no node can transmit, so the producer
	// holds a chain nobody can fetch — a permanent partition, unfixable after
	// genesis by anything short of a hard fork.
	//
	// The transport must therefore be able to carry this number. That
	// direction of the check cannot live here (core cannot import node), so
	// it lives in node/p2p as a test against MaxMessageBytes.
	BlockByteCapacity int `json:"block_byte_capacity"`

	// SeqGasCapacity is the third structural bound, and the one that keeps the
	// fee markets alive once the other two bind.
	//
	// Clamping the *derived* ceilings and not T stops the partition and leaves
	// a subtler failure behind: T keeps climbing until 2·median ≤ T, which is
	// T = 2G for G the most sequential gas a full block can physically hold.
	// There the base-fee target sits at twice anything a block can reach, so a
	// physically full block reports applied/target = 0.50 forever, the base fee
	// decays to its resting point, and block space rations purely by priority
	// tip with no burn — the permanent auction §8.1 calls unreachable and the
	// end of §14.2's congestion deflation. The 0.50 is exact and independent of
	// gas density, because T's fixed point is 2·median by construction while
	// the base fee's is applied = T: two controllers whose fixed points cannot
	// both hold.
	//
	// The value is not a new economic assumption. It preserves the ratio the
	// genesis parameters already chose:
	//
	//	SeqGasCapacity / SeqGasTargetGenesis == BlockByteCapacity / BlockByteLimitGenesis
	//
	// so gas and bytes reach their walls together and the terminal state is
	// exactly as well calibrated as block 0. The density-independence is an
	// identity rather than a sampled result: BlockByteLimit(T)/T is the
	// constant BlockByteLimitGenesis/SeqGasTargetGenesis wherever the clamp
	// does not bite, and the pairing puts both walls exactly on that constant.
	// Validate enforces it as a cross-multiplication — the saturating form of
	// the same check passes for every capacity at or above the pairing point,
	// which is most of the ways to get it wrong. Whether *genesis* is well
	// calibrated was a separate, pre-existing question, and it was decided here
	// rather than on the testnet measurement list: the number is in the
	// ConsensusRoot, so a testnet carrying a different one measures a different
	// chain, and "deferred to a measurement" is not a state a frozen parameter
	// can ship in. The break-even is SeqGasTargetGenesis over
	// BlockByteLimitGenesis, in sequential gas per byte *of block*, so the
	// density compared against it has to be in the same unit: a plain transfer
	// is 0.704 (600 gas in 852 bytes of block — 848 of body plus the four SSZ
	// offset bytes a block spends on it), not the 0.708 body-only figure this
	// comment used to give. It was 0.8 at the superseded SeqGasTargetGenesis of
	// 2,000,000, so a byte-full block of the design load applied 0.880 of the
	// target and moved the base fee DOWN; it is 0.64 at 1,600,000, the same
	// block applies 1.0999, and the fee moves up. The pairing above is what
	// carries that calibration to the top of §8.1's curve unchanged, which is
	// why this parameter had to move with the target and is 5,120,000 rather
	// than 6,400,000.
	SeqGasCapacity uint64 `json:"seq_gas_capacity"`

	// MaxCitesPerBlock bounds the competing-header citations a block may
	// carry (§8.1's health signal) — small and static for the same structural
	// reason as CertListCapacity: it is a merkle/decode capacity, not a
	// policy ceiling.
	MaxCitesPerBlock int `json:"max_cites_per_block"`

	// CeilingGrowthDivisor (Γ) and CeilingDecayDivisor (Δ) bound how fast T
	// can move per epoch: at most +T/Γ, at least -T/Δ, so that a step is
	// bounded and — over a year of full blocks and a passing health gate —
	// the ceiling at most doubles (whitepaper §8.1).
	CeilingGrowthDivisor uint64 `json:"ceiling_growth_divisor"`
	CeilingDecayDivisor  uint64 `json:"ceiling_decay_divisor"`

	// HealthGateBps bounds the epoch's rate of cited competing headers, in
	// basis points of the epoch length. Above it, growth is withheld for the
	// epoch (decay and the floor are unaffected) — the gate leans toward
	// caution, which is the direction a gate should lean.
	HealthGateBps uint64 `json:"health_gate_bps"`

	// Sequential gas schedule: the cost of fold work, the one resource that
	// does not parallelise.
	GasSeqPerRead           uint64 `json:"gas_seq_per_read"`
	GasSeqPerWrite          uint64 `json:"gas_seq_per_write"`
	GasSeqPerRegistryInsert uint64 `json:"gas_seq_per_registry_insert"`
	GasSeqPerSeenInsert     uint64 `json:"gas_seq_per_seen_insert"`

	// Parallel gas schedule: the cost of verification, which scales with every
	// core that joins the network.
	GasParPerSig        uint64 `json:"gas_par_per_sig"`
	GasParPerByte       uint64 `json:"gas_par_per_byte"`
	GasParPerDeriveUnit uint64 `json:"gas_par_per_derive_unit"`

	// Fee markets. Two independent EIP-1559-style markets, each with its own
	// base fee stored in a protocol cell and updated by the fold.
	InitialSeqBaseFee           u256.U256 `json:"initial_seq_base_fee"`
	InitialParBaseFee           u256.U256 `json:"initial_par_base_fee"`
	MinBaseFee                  u256.U256 `json:"min_base_fee"`
	BaseFeeMaxChangeDenominator uint64    `json:"base_fee_max_change_denominator"`

	// SkipFee is a protocol constant, not a market price (R1-H1). Constancy is
	// what makes the deposit ceiling statelessly checkable.
	SkipFee u256.U256 `json:"skip_fee"`

	// Emission. Integer-exact and float-free: the per-epoch rate decays by
	// one part in EmissionDecayDivisor, which is chosen so that the rate
	// halves every two years, and is floored at TailEmission forever.
	GenesisEmission      u256.U256 `json:"genesis_emission"`
	TailEmission         u256.U256 `json:"tail_emission"`
	EmissionDecayDivisor uint64    `json:"emission_decay_divisor"`
	CoinbaseMaturity     uint64    `json:"coinbase_maturity"`

	// TreasuryShareBps is the fraction of every block subsidy credited to the
	// treasury cell, in basis points; the remainder pays consensus (§14.1 of
	// the whitepaper). It applies to the subsidy only and never to fees, so
	// the cost falls on issuance rather than on users.
	TreasuryShareBps uint64 `json:"treasury_share_bps"`

	// Timing and chain shape.
	TargetBlockSeconds     uint64 `json:"target_block_seconds"`
	EpochLength            uint64 `json:"epoch_length"`
	DifficultyWindow       uint64 `json:"difficulty_window"`
	DifficultyClampFactor  uint64 `json:"difficulty_clamp_factor"`
	MedianTimeBlocks       int    `json:"median_time_blocks"`
	FutureTimeLimitSeconds uint64 `json:"future_time_limit_seconds"`
	UndoDepth              uint64 `json:"undo_depth"`

	// Proof of work.

	// PoWEngine names the work function this network requires, and it is in
	// the consensus root because that is what it is: a network is defined by
	// the function its headers are proved against, and two chains that agree
	// on every other parameter and disagree here are not the same chain.
	//
	// It also does a job no comment can do. RandomX is compiled behind a
	// build tag, so a binary built without it holds only the development
	// engine — and a development engine pointed at a network that requires
	// RandomX would accept one BLAKE3 pass as proof of work for every header
	// it ever sees. The node compares this against the engine it was built
	// with and refuses to start on a mismatch, in both directions.
	PoWEngine string `json:"pow_engine"`

	// RandomXKeyInterval and RandomXKeyLag are the key schedule: the work
	// function is re-keyed every RandomXKeyInterval blocks, and the epoch a
	// height belongs to is computed with RandomXKeyLag blocks of slack, so
	// the key for any height is settled well before that height is mined.
	//
	// The key itself is derived from the height and the chain id
	// (pow.KeyFor), not from a key block's hash. That is a deliberate
	// departure from upstream RandomX's own schedule and the argument for it
	// is in pow.KeyFor's comment and ARCHITECTURE §21; the short version is
	// that it keeps pow.CheckWork a total function of a header's bytes, which
	// is what orphan admission, announcement scoring and a work cache keyed
	// by block id all rest on.
	RandomXKeyInterval uint64 `json:"randomx_key_interval"`
	RandomXKeyLag      uint64 `json:"randomx_key_lag"`

	// GenesisTarget is the initial proof-of-work target, big-endian. A hash
	// at or below it satisfies the work requirement.
	GenesisTarget u256.U256 `json:"genesis_target"`

	// MaxTarget is the absolute ceiling on the proof-of-work target — the
	// easiest difficulty the chain is ever allowed to reach (F-PARAM-1).
	//
	// The difficulty rule used to clamp only *relatively*, at ±
	// DifficultyClampFactor of the previous target, plus a floor at one. A
	// relative clamp bounds the step and not the destination: sustained
	// upward pressure — which the timestamp rules can supply for free —
	// multiplies the target by the clamp factor every block, and u256's
	// saturating arithmetic delivers it to 2^256−1 rather than erroring.
	//
	// The margin any change to DifficultyClampFactor has to be argued against is
	// the gap to this ceiling, not the gap to saturation. On mainnet that gap is
	// MaxTarget = 2^250 over GenesisTarget = 2^238, so 2^12 = 4096x, which at
	// DifficultyClampFactor = 16 is exactly three clamp steps (16^3 = 4096). An
	// earlier revision of this comment quoted 2^18 and "about 4.5 clamp steps" —
	// the retired rule's distance to 2^256−1 — which reads 64x more generous than
	// the real margin at exactly the place a larger clamp would be justified, on a
	// parameter ConsensusRoot freezes at block 0.
	//
	// At the top there are two failures and both are terminal. CheckWork
	// becomes a tautology, since every hash is at or below 2^256−1; and
	// BlockWork — 2^256/(target+1) — returns one for every header, so
	// accumulated work degenerates into a block count and fork choice picks
	// whoever emits headers fastest rather than whoever did the work.
	//
	// So the ceiling is not tuning, it is the property that keeps work a
	// measurement. Validate pins both ends of it: the chain must start at or
	// below the ceiling, and the ceiling must sit strictly below 2^255, the
	// point at which BlockWork collapses to one.
	MaxTarget u256.U256 `json:"max_target"`

	// GenesisTime is the timestamp block 0 declares. It is a parameter rather
	// than a clock reading so that `zcd genesis` is reproducible: anyone can
	// rebuild block 0 from spec/params.json and compare the id a release
	// announced.
	GenesisTime uint64 `json:"genesis_time"`

	// Phase activation heights (§17). Era-0 releases compile these in but ship
	// none of the code behind them; a height that has not arrived is not a
	// feature flag, it is an absence.
	H1Bond uint64 `json:"h1_bond"`
	H1VM   uint64 `json:"h1_vm"`
	H2PoS  uint64 `json:"h2_pos"`

	// Notes are consensus-inert prose — the one field excluded from the
	// consensus root — carried inside the parameter file, so
	// that a future parameter editor meets a trap where the parameter is rather
	// than in an adversarial review they may never read (R2-S4). JSON has no
	// comments; this is the substitute.
	//
	// They are covered by the parameter hash the launch announcement commits
	// to, which is correct: editing one changes the artifact.
	Notes map[string]string `json:"notes,omitempty" consensus:"-"`

	// emissionTable is the per-epoch coinbase schedule, precomputed by
	// Validate. It is finite because the decay reaches TailEmission and stops:
	// beyond the last entry the emission is the tail, forever.
	emissionTable []u256.U256

	// cumulativeTable is the prefix sum of emissionTable, in blocks rather
	// than in epochs: cumulativeTable[e] is everything the schedule paid
	// strictly before epoch e began. It has one more entry than emissionTable
	// — the empty prefix at index 0 — and it is installed and cleared with it,
	// never separately, so "the schedule is cached" stays one fact.
	cumulativeTable []u256.U256
}

// SeqGasLimit is the sequential-gas ceiling for a given target: 2T
// (whitepaper §8.1). t is the current epoch's target — consensus state
// (types.SeqGasTargetSlot), never a genesis constant, because §8.1 makes it a
// function of measured demand rather than a number frozen at genesis.
func (p *Params) SeqGasLimit(t uint64) uint64 { return 2 * t }

// SeqGasBurst is the hard burst bound a block may never exceed: 4T. Between
// the ceiling and the bound a block is valid but forfeits the producer's block
// revenue quadratically — its subsidy share plus the block's fees —
// the burst valve of §8.1.
func (p *Params) SeqGasBurst(t uint64) uint64 { return 4 * t }

// ParGasLimit is the parallel-gas ceiling for a given sequential target: a
// fixed ratio of the sequential ceiling, so it inherits T's growth without a
// controller of its own (§8's invariant restated as capacity in §8.1).
func (p *Params) ParGasLimit(t uint64) uint64 { return p.ParGasRatio * p.SeqGasLimit(t) }

// ParGasTarget is the per-block parallel gas usage the base fee steers
// towards: half of ParGasLimit(t).
func (p *Params) ParGasTarget(t uint64) uint64 { return p.ParGasRatio * t }

// MaxCertsPerBlock is the certificate-count ceiling for a given sequential
// target, scaled from its genesis value and clamped to CertListCapacity. The
// clamp is not a policy choice: CertListCapacity is the structural bound that
// fixes CertRoot's merkle depth (§4 of the architecture spec), and the
// dynamic ceiling can never be asked to exceed what the encoding can address.
func (p *Params) MaxCertsPerBlock(t uint64) int {
	scaled := u256.FromUint64(uint64(p.MaxCertsPerBlockGenesis)).MulDiv64(t, p.SeqGasTargetGenesis)
	v, ok := scaled.Uint64()
	if !ok || v > uint64(p.CertListCapacity) {
		return p.CertListCapacity
	}
	return int(v)
}

// MaxSigsPerBlock is the signature-count ceiling for a given sequential
// target: max_sigs_per_block_genesis scaled by t/seq_gas_target_genesis,
// exactly as MaxCertsPerBlock scales the count ceiling.
//
// It returns a uint64 and carries no structural clamp, and both are
// deliberate. MaxCertsPerBlock clamps to CertListCapacity because that bound
// is real — it fixes CertRoot's merkle width, so the dynamic ceiling can never
// be asked to exceed what the encoding addresses. Nothing plays that role for
// signatures: a block's signature list is a property of its certificates, not
// a merkleised list of its own. A clamp invented here would be inert at every
// shipped set and would read as covered while covering nothing, which this
// tree treats as worse than absent (§15). Saturation is the only bound, and it
// is arithmetic rather than policy: a scaled ceiling that does not fit a
// uint64 is larger than the number of signatures any block can carry, so
// returning MaxUint64 there refuses exactly the blocks a representable ceiling
// would have refused.
func (p *Params) MaxSigsPerBlock(t uint64) uint64 {
	scaled := u256.FromUint64(uint64(p.MaxSigsPerBlockGenesis)).MulDiv64(t, p.SeqGasTargetGenesis)
	v, ok := scaled.Uint64()
	if !ok {
		return math.MaxUint64
	}
	return v
}

// BlockByteLimit is the block-size ceiling for a given sequential target,
// scaled from its genesis value and clamped to BlockByteCapacity — the bound
// that keeps a consensus-valid block transmissible. See BlockByteCapacity's
// own comment for why an unclamped byte ceiling partitions the network.
func (p *Params) BlockByteLimit(t uint64) int {
	scaled := u256.FromUint64(uint64(p.BlockByteLimitGenesis)).MulDiv64(t, p.SeqGasTargetGenesis)
	v, ok := scaled.Uint64()
	if !ok || v > uint64(p.BlockByteCapacity) {
		return p.BlockByteCapacity
	}
	return int(v)
}

// NextSeqGasTarget is the epoch controller of whitepaper §8.1: T moves toward
// twice the previous epoch's median applied sequential gas, by at most T/Γ up
// or T/Δ down, gated on network health, and never below its genesis floor.
//
// medianApplied2x is 2×median(applied sequential gas, over the epoch that
// just ended) — the caller computes the median, because sorting a whole
// epoch's sample ring is state-shaped work this package has no access to.
// healthy reports whether the epoch's cited-competing-header rate stayed
// under HealthGateBps; when it did not, growth (not decay) is withheld for
// the epoch, which is the direction a gate should lean.
func (p *Params) NextSeqGasTarget(t uint64, medianApplied2x uint64, healthy bool) uint64 {
	lo := t - t/p.CeilingDecayDivisor
	hi := t
	if healthy {
		hi = t + t/p.CeilingGrowthDivisor
	}
	next := medianApplied2x
	if next < lo {
		next = lo
	}
	if next > hi {
		next = hi
	}
	if next > p.SeqGasCapacity {
		next = p.SeqGasCapacity
	}
	if next < p.SeqGasTargetGenesis {
		next = p.SeqGasTargetGenesis
	}
	return next
}

// IsEpochBoundary reports whether a block at this height refreshes the epoch
// beacon and commits a state root.
func (p *Params) IsEpochBoundary(height uint64) bool {
	return height%p.EpochLength == 0
}

// Epoch returns the epoch number containing a height.
func (p *Params) Epoch(height uint64) uint64 { return height / p.EpochLength }

// Emission returns the coinbase amount for a height. It is a pure function of
// the height, computed with integer arithmetic only.
//
// The rate is constant within an epoch and decays once per epoch:
//
//	E(0) = GenesisEmission
//	E(n) = max(TailEmission, E(n-1) - E(n-1)/EmissionDecayDivisor)
//
// With a 30-second block time an epoch is one day, and the genesis divisor of
// 1054 compounds to a yearly factor of 0.70702 — the rate halves every two
// years (I1-L2). The numbers here follow spec/params.json; earlier drafts of
// this comment quoted a divisor and a factor from a schedule that no longer
// ships.
func (p *Params) Emission(height uint64) u256.U256 {
	if height == 0 {
		// The genesis block pays no coinbase: there is no miner to pay, and a
		// reproducible genesis must not credit an address.
		return u256.Zero
	}
	if p.emissionTable == nil {
		// Only reachable on a Params that never passed Validate, which refuses
		// every set whose schedule does not fit; on such a set the table stays
		// uninstalled and this walk repeats per call. That is an accepted cost on
		// a path no validated parameter set reaches, and it is bounded, which is
		// what it was not before.
		p.buildEmissionTable()
	}
	epoch := p.Epoch(height)
	if epoch >= uint64(len(p.emissionTable)) {
		return p.TailEmission
	}
	return p.emissionTable[epoch]
}

// CumulativeEmission is the total coinbase §14.2's schedule has paid through
// `height`, inclusive: the sum of Emission(h) for every h in [0, height].
//
// It is a pure function of the height and the four issuance constants
// (genesis_emission, tail_emission, emission_decay_divisor, epoch_length), so
// a rule that reads it stays *stateless* — no chain, no tip, no supply cell.
// That is what lets V5 bound a declared deposit from above: every drop
// that can exist at a height is a drop this schedule paid, so a deposit
// declaring more than this is an object no chain state can ever satisfy.
//
// Saturating, and deliberately in the permissive direction. A sum that leaves
// 256 bits is larger than any value a cell can hold, so returning Max there
// refuses exactly the deposits a representable sum would have refused, and an
// arithmetic edge can never turn into a *rejection* of something legal.
//
// The prefix table is built with the emission table, by the same walk and
// under the same bound, so this costs one index rather than a walk per call —
// which matters because V5 runs on every certificate on the verification path.
func (p *Params) CumulativeEmission(height uint64) u256.U256 {
	if p.emissionTable == nil {
		// Same path, and the same accepted cost, as Emission's: only a Params
		// that never passed Validate gets here, and on such a set the walk
		// fails, installs nothing, and this falls through to the tail rate —
		// which is exactly what Emission answers on the same set.
		p.buildEmissionTable()
	}
	l := p.EpochLength
	if l == 0 {
		// Refused by Validate (epoch_length must be positive). A schedule with
		// no epochs has no sum to state, and Max is the answer that bounds
		// nothing rather than the one that refuses everything.
		return u256.Max
	}
	epoch := height / l
	within := height % l

	// n is the number of epochs the decay table spells; every epoch at or
	// beyond it pays the tail forever.
	n := uint64(len(p.emissionTable))
	total := u256.Zero
	rate := p.TailEmission
	if epoch < n {
		total = p.cumulativeTable[epoch]
		rate = p.emissionTable[epoch]
	} else {
		if n > 0 {
			total = p.cumulativeTable[n]
		}
		// Every block of every epoch in [n, epoch) paid the tail. The
		// subtraction is epoch 0's short block count: it holds l heights and
		// only l-1 of them pay, because height 0 pays no coinbase. When the
		// table exists it has already accounted for that; when it does not —
		// the unvalidated set above — this is where it is accounted for.
		blocks, over := u256.FromUint64(epoch - n).Mul(u256.FromUint64(l))
		if over {
			return u256.Max
		}
		if n == 0 && epoch > 0 {
			blocks = blocks.SatSub(u256.One)
		}
		paid, over := p.TailEmission.Mul(blocks)
		if over {
			return u256.Max
		}
		total = total.SatAdd(paid)
	}

	// The epoch `height` sits in, up to and including `height` itself. Epoch 0
	// starts at height 0, which pays nothing, so it contributes one block
	// fewer than every later epoch's partial run.
	blocks := within
	if epoch > 0 {
		blocks = within + 1
	}
	part, over := rate.Mul(u256.FromUint64(blocks))
	if over {
		return u256.Max
	}
	return total.SatAdd(part)
}

// maxEmissionEpochs bounds the precomputed emission schedule, and so bounds the
// walk that builds it. It is a policy number, not a derived one: no other
// parameter implies it, and nothing in the whitepaper names it. All three
// shipped networks run divisor 1054 and build a 4377-entry table, whose last
// entry is the first epoch at the tail: epoch 4376, which whitepaper §14.2 and
// ARCHITECTURE §15 now both name (they said 4,375 until that was corrected, off
// by the last saturating step rather than by the schedule), so this leaves a
// factor of about 240 -- room for a decay two orders of magnitude slower than
// any network ships -- and it caps the walk at about 33 MB of u256 on the path
// where a parameter file is being refused.
//
// It exists because termination was the property buildEmissionTable checked and
// it was not the property that was needed.
const maxEmissionEpochs = 1 << 20

// buildEmissionTable walks the decay once, up to the epoch at which the tail
// takes over. It reports whether the tail was reached within maxEmissionEpochs;
// the table is installed only when it was, so a schedule this cannot represent
// is never half-cached and then read as if it were complete.
//
// The walk terminates -- each step subtracts at least one unit while the value
// is above the tail -- but termination is not a bound. The forced one-unit step
// is what guarantees termination, and it is also what makes the walk long: once
// emission_decay_divisor exceeds the emission, every step is one unit and the
// walk runs GenesisEmission-TailEmission times. At the shipped mainnet numbers
// that is ~2.07e9 iterations and a ~2.07e9-element slice, reached by nothing
// more than editing one field of a parameter file.
func (p *Params) buildEmissionTable() bool {
	table := []u256.U256{p.GenesisEmission}
	e := p.GenesisEmission
	for e.Gt(p.TailEmission) {
		if len(table) >= maxEmissionEpochs {
			// Retained belt-and-braces, and NOT what pins "a refused set holds
			// no schedule" -- Validate's first statement does, by position,
			// ahead of every return. This line is strictly redundant today:
			// both callers guarantee the field is already nil on arrival.
			// Validate has just cleared it, and Emission only calls in when it
			// is nil. Deleted, no test moves; deleted together with the entry
			// clear, two do. That is why the mutation evidence for the property
			// is cited against the entry clear and not against this line.
			//
			// It stays because it costs nothing and makes this function's own
			// postcondition true standalone: a walk that did not reach the tail
			// leaves no table behind, whoever calls it. A third caller added
			// later inherits that rather than an unwritten precondition.
			p.emissionTable = nil
			p.cumulativeTable = nil
			return false
		}
		step, _ := e.Div64(p.EmissionDecayDivisor)
		if step.IsZero() {
			step = u256.One
		}
		e = e.SatSub(step)
		if e.Lt(p.TailEmission) {
			e = p.TailEmission
		}
		table = append(table, e)
	}
	// The prefix sum is built in the same call, and installed in the same
	// statement pair, so no caller can ever observe one without the other.
	// Epoch 0 pays on l-1 of its l heights — height 0 has no miner to pay —
	// and every later epoch pays on all l of them.
	cumulative := make([]u256.U256, len(table)+1)
	acc := u256.Zero
	for i, rate := range table {
		blocks := p.EpochLength
		if i == 0 {
			// checkAllPositive has already refused a zero epoch_length on
			// every path Validate takes, but Emission and CumulativeEmission
			// also reach this walk on a set that never passed Validate, and a
			// zero there would wrap the block count to 2^64-1.
			blocks = 0
			if p.EpochLength > 0 {
				blocks = p.EpochLength - 1
			}
		}
		paid, over := rate.Mul(u256.FromUint64(blocks))
		if over {
			paid = u256.Max
		}
		acc = acc.SatAdd(paid)
		cumulative[i+1] = acc
	}
	p.emissionTable = table
	p.cumulativeTable = cumulative
	return true
}

// NextBaseFee applies the EIP-1559 update rule to one market.
//
// Saturating arithmetic is used throughout: an overflow must be deterministic
// on every node, and a base fee pinned at the maximum is a chain that has
// stopped accepting certificates, not a chain that disagrees with itself.
//
// The two directions are deliberately asymmetric. An over-target block always
// raises the fee by at least one unit, so a chain sitting at the floor cannot
// be congested for free. An under-target block lowers it by the proportional
// step only, which integer division rounds to zero once the fee is below the
// change denominator — so the practical resting point is a small constant
// rather than MinBaseFee itself. That is the same behaviour EIP-1559 has, it is
// deterministic, and the alternative (forcing a decrement) would let a quiet
// chain walk its fee to the floor and hand an attacker free block space.
//
// A consequence worth writing down, because it hid the floor for a long time:
// at every shipped set the resting point is 7 and MinBaseFee is 1, so the
// MaxOf below never binds and no test driven at shipped parameters can observe
// it. The floor is quantified over MIN_BASE_FEE, so it is pinned at two legal
// witnesses instead, by TestTheBaseFeeFloorStopsTheDescentAtTwoLegalWitnesses
// here and by sim/refold's port of it.
func (p *Params) NextBaseFee(base u256.U256, gasUsed, gasTarget uint64) u256.U256 {
	if gasTarget == 0 || gasUsed == gasTarget {
		// This MaxOf is KEPT, deliberately rather than by inheritance, and the
		// decision belongs next to it because nothing can observe it.
		// `base < MinBaseFee` is unreachable: Validate refuses an initial fee
		// below the floor, and no return path descends past it. It cannot be
		// made reachable either -- no rule deletion writes the base-fee slot,
		// so no sweep reaches it, and no vector that encodes a REACHABLE
		// pre-state reaches it. (A pre-state omitting or under-setting
		// SeqBaseFeeSlot would, since an unset slot reads as 0 and ApplyBlock
		// has no fallback above height 0 -- but that is a state the protocol
		// cannot produce, so it is not a vector anyone may add. Note this is a
		// DIFFERENT asymmetry from sim/refold's `producer < 0` clamp, which a
		// block-level B5 vector would make structural.)
		//
		// Why keep it, when PROTOCOL.md prefers deleting an unobservable
		// defence -- the rule that governed the vacuous `low.Lt(MinBaseFee)`
		// assertion this change removed from the test beside it. That was a
		// test assertion claiming coverage it did not have, so deleting it
		// removed FALSE information. This is a normalisation that makes an
		// EXPORTED function's postcondition -- the result is never below
		// MinBaseFee -- true standalone rather than by a precondition nobody
		// wrote down, and deleting it would move that precondition into the
		// heads of callers it is not enforced on. Same reason, stated the same
		// way, as core/types.market()'s re-check of a bound B4 already
		// guarantees and buildEmissionTable's belt-and-braces above.
		return u256.MaxOf(base, p.MinBaseFee)
	}
	if gasUsed > gasTarget {
		delta := base.MulDiv64(gasUsed-gasTarget, gasTarget)
		delta, _ = delta.Div64(p.BaseFeeMaxChangeDenominator)
		if delta.IsZero() {
			delta = u256.One
		}
		return base.SatAdd(delta)
	}
	delta := base.MulDiv64(gasTarget-gasUsed, gasTarget)
	delta, _ = delta.Div64(p.BaseFeeMaxChangeDenominator)
	return u256.MaxOf(base.SatSub(delta), p.MinBaseFee)
}

// Validate rejects a parameter set that could not describe a working chain.
// It runs once at load time, never inside the fold.
//
// The blanket rule first: **every numeric parameter must be positive.** No
// exceptions, so that there is nothing to remember. Zero is never a meaningful
// value here — a zero modulus divides by zero inside the fold on every block
// (I1-L11), a zero denominator does the same in the fee update, a zero list
// bound makes a whole operation unusable, and a zero gas price makes a resource
// free, which is a spam vector rather than a policy. Anything that reaches a
// `%` or a `/` is covered by construction rather than by inspection (R2-S3).
func (p *Params) Validate() error {
	// Dropped on the way in, not on one way out. A Params is normally parsed and
	// validated and then edited on a copy, so any cached schedule belongs to the
	// field set that was validated BEFORE this call. Every return below is a
	// refusal that leaves the caller holding this object, and a refused set
	// answering Emission from another set's schedule looks like an answer --
	// which is the whole argument the walk's own refusal path already makes
	// Clearing here covers the early returns too; a set that passes rebuilds the
	// table at the end of this function.
	p.emissionTable = nil
	p.cumulativeTable = nil
	if p.Name == "" {
		return errors.New("params: name must be set")
	}
	if p.PoWEngine == "" {
		return errors.New("params: pow_engine must be set")
	}
	if err := p.checkAllPositive(); err != nil {
		return err
	}
	for _, c := range []struct {
		name string
		v    int
	}{
		{"max_reads", p.MaxReads},
		{"max_writes", p.MaxWrites},
		{"max_sigs", p.MaxSigs},
		{"max_moves_per_transfer", p.MaxMovesPerTransfer},
		{"max_retire_addrs", p.MaxRetireAddrs},
		{"max_certs_per_block_genesis", p.MaxCertsPerBlockGenesis},
		{"max_sigs_per_block_genesis", p.MaxSigsPerBlockGenesis},
		{"block_byte_limit_genesis", p.BlockByteLimitGenesis},
		{"cert_list_capacity", p.CertListCapacity},
		{"block_byte_capacity", p.BlockByteCapacity},
		{"max_cites_per_block", p.MaxCitesPerBlock},
		{"median_time_blocks", p.MedianTimeBlocks},
	} {
		if c.v <= 0 {
			return fmt.Errorf("params: %s must be positive", c.name)
		}
	}
	for _, c := range []struct {
		name string
		v    uint64
	}{
		{"ttl_max", p.TTLMax},
		{"seq_gas_target_genesis", p.SeqGasTargetGenesis},
		{"par_gas_ratio", p.ParGasRatio},
		{"seq_gas_capacity", p.SeqGasCapacity},
		{"ceiling_growth_divisor", p.CeilingGrowthDivisor},
		{"ceiling_decay_divisor", p.CeilingDecayDivisor},
		{"base_fee_max_change_denominator", p.BaseFeeMaxChangeDenominator},
		{"emission_decay_divisor", p.EmissionDecayDivisor},
		{"target_block_seconds", p.TargetBlockSeconds},
		{"epoch_length", p.EpochLength},
		{"difficulty_window", p.DifficultyWindow},
		{"difficulty_clamp_factor", p.DifficultyClampFactor},
		{"undo_depth", p.UndoDepth},
		// The coinbase maturity ring is indexed by height modulo its size, so a
		// size of zero is not "no maturity" — it is a division by zero inside
		// the fold, reached by every block.
		{"coinbase_maturity", p.CoinbaseMaturity},
	} {
		if c.v == 0 {
			return fmt.Errorf("params: %s must be positive", c.name)
		}
	}
	if p.MedianTimeBlocks%2 == 0 {
		return errors.New("params: median_time_blocks must be odd so the median is unambiguous")
	}
	if p.RandomXKeyLag >= p.RandomXKeyInterval {
		// The lag is slack inside one interval, not a second interval. At or
		// above it the epoch arithmetic in pow.SeedEpochFor stops being a
		// shift of the interval boundary and starts skipping epochs, so the
		// key schedule would no longer re-key every randomx_key_interval
		// blocks -- which is the one thing this pair is for.
		return fmt.Errorf(
			"params: randomx_key_lag (%d) must be below randomx_key_interval (%d)",
			p.RandomXKeyLag, p.RandomXKeyInterval)
	}
	if p.RandomXKeyInterval > math.MaxUint64-p.RandomXKeyLag {
		// The pair is only ever used as a boundary at
		// RandomXKeyInterval+RandomXKeyLag, so a pair whose sum is not
		// representable does not name a boundary at all -- it names a small
		// wrapped number, and every height compares above it. That is the
		// wrapped-boundary defect: with interval = 2^64-1 and lag = 1 the sum
		// wrapped to 0, pow.SeedEpochFor's underflow guard was never taken,
		// and genesis landed in a different epoch from every other height on
		// the chain. Refusing the pair here is what makes that state
		// unrepresentable rather than merely handled: SeedEpochFor is total on
		// its own now, but a boundary that cannot be written down is not a key
		// schedule anyone meant to configure.
		return fmt.Errorf(
			"params: randomx_key_interval (%d) + randomx_key_lag (%d) must not overflow uint64",
			p.RandomXKeyInterval, p.RandomXKeyLag)
	}
	if p.TTLMax < 2 {
		// A wallet signs for inclusion at least two blocks out: one for the
		// certificate to propagate, one for it to be built into a block.
		//
		// Bounded from below only, and that asymmetry was asked about
		// directly. The answer is no, for three reasons.
		//
		// First, there is nothing here to make representable. Every other
		// bound in this function refuses a set under which some state cannot
		// be written down: a key schedule whose boundary wraps, a derived gas
		// ceiling that lands below its own target, a pairing whose products
		// differ only above the low word. ttl_max has no such point. h.Height
		// is unbounded chain state the validator never observes, so for any
		// ttl_max >= 1 there is a height at which height + ttl_max wraps; a
		// ceiling only chooses which height that is, which is why B2 compares
		// a distance instead.
		//
		// Second, the cost the parameter's own note names is not a function of
		// ttl_max. The seen set's worst case is roughly ttl_max times the
		// per-block certificate ceiling, and that ceiling is
		// MaxCertsPerBlock(t), clamped to cert_list_capacity — which this
		// function does not bound from above either. Bounding one factor of an
		// unbounded product bounds nothing, and bounding it *as if* it did
		// would be worse than leaving it open: it reads as a memory guarantee
		// that is not one.
		//
		// Third, no derivation for a number exists that is not circular. The
		// shipped sets are 240, 240 and 32; any ceiling picked now is a
		// multiple of what already shipped, chosen after the fact. And the
		// cost falls on the operators of the network that chose it — the
		// parameter set is genesis-fixed and announced by hash, so a
		// large ttl_max is a decision that network's own nodes carry, not an
		// externality onto anyone else. That is documentation's job, and
		// spec/params.json's note on the parameter already does it.
		return errors.New("params: ttl_max must be at least 2")
	}
	if p.CertListCapacity < p.MaxCertsPerBlockGenesis {
		// CertListCapacity is the structural SSZ/merkle bound MaxCertsPerBlock(t)
		// is clamped to (§8.1); a genesis ceiling above it would start the chain
		// already pinned against a wall growth can never move.
		return errors.New("params: cert_list_capacity must be at least max_certs_per_block_genesis")
	}
	if p.MaxSigsPerBlockGenesis < p.MaxSigs {
		// A block ceiling below the *certificate* ceiling makes a certificate
		// that passes every V-rule unincludable in any block: max_sigs is what
		// V1 admits per certificate, and a block that cannot carry one of them
		// is a chain on which that certificate is valid and can never be
		// committed. The freeze-unsafe direction is the low one, so that is
		// the end this refuses; the high end is a policy choice and its
		// derivation lives in spec/params.json's note.
		return errors.New("params: max_sigs_per_block_genesis must be at least max_sigs, " +
			"or a certificate carrying the maximum signature count is valid and " +
			"unincludable in any block")
	}
	if p.SeqGasCapacity < p.SeqGasTargetGenesis {
		return errors.New("params: seq_gas_capacity must be at least seq_gas_target_genesis")
	}
	// The elastic ceiling controller (§8.1, NextSeqGasTarget) moves T by at most
	// t/Γ up and t/Δ down each epoch, both computed as integer division. The
	// positivity loop above already refuses a zero divisor; this refuses the
	// other end of the same failure. A divisor larger than the smallest T the
	// controller ever operates at floors its step to zero: t/Γ = 0 and t/Δ = 0,
	// so hi = lo = t and NextSeqGasTarget returns t unchanged for every input.
	// The elastic ceiling is then frozen -- not slow, frozen -- for the life of
	// the chain, and §8.1's whole demand-responsive curve is dead code.
	//
	// The smallest T in range is seq_gas_target_genesis: NextSeqGasTarget floors
	// every result there, so T never falls below it and the step is smallest at
	// exactly that value. t/Γ and t/Δ are monotone non-decreasing in t, so a
	// step of at least one unit at the genesis floor is a step of at least one
	// unit at every T the set admits. The bound is therefore Γ <= T0 and Δ <=
	// T0. This is not a calibration knob near the shipped values -- all three
	// shipped networks run Γ=512, Δ=1024 against T0=1,600,000, since the
	// parameter respin put testnet and devnet back on mainnet's own schedule and
	// the testnet/devnet T0 of 2,000,000 this comment used to name beside it is
	// superseded, three orders of magnitude inside this bound -- it refuses only
	// a divisor no one operating the chain would freeze it with (the
	// freeze-unsafe class: a value Validate accepts today that no operator could
	// safely freeze a network on).
	if p.CeilingGrowthDivisor > p.SeqGasTargetGenesis {
		return fmt.Errorf(
			"params: ceiling_growth_divisor (%d) must not exceed seq_gas_target_genesis (%d), "+
				"or the growth step t/ceiling_growth_divisor floors to zero at the target's "+
				"genesis floor and the elastic ceiling can never rise",
			p.CeilingGrowthDivisor, p.SeqGasTargetGenesis)
	}
	if p.CeilingDecayDivisor > p.SeqGasTargetGenesis {
		return fmt.Errorf(
			"params: ceiling_decay_divisor (%d) must not exceed seq_gas_target_genesis (%d), "+
				"or the decay step t/ceiling_decay_divisor floors to zero across the target's "+
				"range and the elastic ceiling can never fall",
			p.CeilingDecayDivisor, p.SeqGasTargetGenesis)
	}
	// Every derived capacity ceiling is a multiple of T, and T may reach
	// seq_gas_capacity, so the widest of them must still be a uint64 there --
	// otherwise SeqGasBurst(T) or ParGasLimit(T) wraps and the block-validity
	// ceiling lands *below* the target it is meant to sit above.
	//
	// The widest multiple of T that must fit is not one of the derived ceilings
	// -- it is the controller's own input. NextSeqGasTarget (§8.1) is fed
	// 2*median, computed as a plain uint64 in core/fold's updateSeqGasTarget,
	// where median is a per-epoch sample of *applied* sequential gas. A block is
	// invalid above SeqGasBurst(T) = 4T (blockrules), so every sample is at most
	// 4T and at most 4*seq_gas_capacity; 2*median is therefore at most
	// 8*seq_gas_capacity. If that product wraps, the controller reads a small
	// wrapped target and T collapses -- the same wrapped-boundary shape one
	// level up from SeqGasBurst. So the widest is max(8T, 2*ParGasRatio*T), and
	// proving seq_gas_capacity <= MaxUint64/8 on this same line proves 4T and 6T
	// (which it dominates) along with the 8T the 2*median term needs. Every
	// shipped network runs par_gas_ratio 3 since the parameter respin put
	// testnet and devnet back on mainnet's own schedule -- 10 was the widest
	// until then -- so 8 dominates 2*par_gas_ratio on all three and the shipped
	// bound is MaxUint64/8 ~= 2.3e18 against a shipped capacity of 5.12e6. Even
	// the superseded ratio's MaxUint64/20 ~= 9.2e17 refused only sets nobody
	// could operate (measured by the capacity sweep in params_test.go).
	widest := uint64(8)
	if p.ParGasRatio > math.MaxUint64/2 {
		// Not redundant with the capacity bound below, and not an equivalent way of
		// writing it: 2*ParGasRatio is itself the arithmetic that decides the
		// bound, so at par_gas_ratio = 2^63+4 it wraps to 8, the widest term
		// collapses back to its floor and the capacity bound stays MaxUint64/8 --
		// the bound for an ordinary set, not the MaxUint64/(2*par_gas_ratio) this
		// astronomically wide ratio demands, so the rule that exists to keep
		// ParGasLimit representable is the permissive one. That is the
		// wrapped-boundary shape one level up, so it is refused before it is used.
		return fmt.Errorf(
			"params: par_gas_ratio (%d) is too large: 2*par_gas_ratio does not fit in uint64",
			p.ParGasRatio)
	}
	if w := 2 * p.ParGasRatio; w > widest {
		widest = w
	}
	if p.SeqGasCapacity > math.MaxUint64/widest {
		return fmt.Errorf(
			"params: seq_gas_capacity (%d) is too large: the derived ceilings at that target "+
				"do not fit in uint64", p.SeqGasCapacity)
	}
	// The pairing: the sequential target may grow exactly as far as the byte
	// ceiling does, so both walls arrive together and the terminal state
	// prices like block 0.
	//
	// Stated as a cross-multiplication rather than as
	// BlockByteLimit(SeqGasCapacity) == BlockByteCapacity, which is the obvious
	// form and is nearly useless: BlockByteLimit *saturates* at the capacity, so
	// that comparison passes for every capacity at or above the pairing point —
	// 20,000,000 and 100,000,000 both sail through it. And a capacity above the
	// pairing point is not a harmless slack bound, it reinstalls the exact
	// failure the parameter exists to prevent: the gas wall arrives after the
	// byte wall, T settles above what a full block can deliver, and the
	// sequential market stops pricing. Integer division cannot round a
	// cross-multiplication away either. Both products are computed in 128 bits.
	// Compared in 64 they are two numbers that can wrap, and a wrapped equality
	// is not the pairing this rule states -- it is two different ratios agreeing
	// on their low word. The witness is seq_gas_capacity =
	// seq_gas_target_genesis = 2^59 with block_byte_limit_genesis = 32 and
	// block_byte_capacity = 64: the products are 2^64 and 2^65, a factor of two
	// apart, and identical in every bit a uint64 keeps. The capacity above is
	// representable there, so nothing else in Validate refuses it; only the high
	// word does. Same class as the wrapped boundary above: an arithmetic that
	// wraps inside Validate turns a bound into an accident.
	lhsHi, lhsLo := bits.Mul64(p.SeqGasCapacity, uint64(p.BlockByteLimitGenesis))
	rhsHi, rhsLo := bits.Mul64(p.SeqGasTargetGenesis, uint64(p.BlockByteCapacity))
	if lhsHi != rhsHi || lhsLo != rhsLo {
		return errors.New("params: seq_gas_capacity and block_byte_capacity are not paired " +
			"(seq_gas_capacity/seq_gas_target_genesis must equal " +
			"block_byte_capacity/block_byte_limit_genesis); the gas ceiling and the byte " +
			"ceiling must reach their walls together, or whichever binds later stops being priced")
	}
	if p.BlockByteCapacity < p.BlockByteLimitGenesis {
		// Same shape, and the same reason: a genesis byte ceiling above the
		// capacity it is clamped to would be pinned from block 0.
		return errors.New("params: block_byte_capacity must be at least block_byte_limit_genesis")
	}
	// The count ceiling's sibling pairing. MaxCertsPerBlock(t) scales
	// max_certs_per_block_genesis by t/seq_gas_target_genesis and clamps the
	// result to cert_list_capacity, exactly as BlockByteLimit(t) scales and
	// clamps to block_byte_capacity -- and §15 presents the two as siblings.
	// Without this rule they are not: the byte pairing above forces the byte
	// clamp to bind only at the very end of the domain, while nothing forced
	// the count clamp to stay out of the way at all.
	//
	// The direction is >= and not ==, which is the one real difference from
	// the byte pairing, and it is deliberate. block_byte_capacity is re-pinned
	// at era boundaries against measured propagation, so pinning it to the
	// genesis ratio costs nothing that cannot be repaired later.
	// cert_list_capacity cannot be re-pinned by any era: it fixes CertRoot's
	// merkle width, and a width that moved with height would make one
	// certificate list hash to two different roots (§15). It is therefore
	// oversized once, at genesis, for the whole of whitepaper §8.1's curve, and
	// an equality here would forbid exactly the headroom that sizing exists to
	// buy. What must be refused is the other side: a set in which the scaled
	// count ceiling reaches the frozen capacity somewhere inside the domain,
	// where MaxCertsPerBlock stops tracking T and the count wall arrives before
	// the gas and byte walls it is supposed to arrive with.
	//
	// Stated as a cross-multiplication for the same reason the byte pairing is:
	// MaxCertsPerBlock saturates, so comparing MaxCertsPerBlock(SeqGasCapacity)
	// against CertListCapacity passes for every capacity at or below the
	// binding point -- the direction that is wrong. And in 128 bits for the
	// wrapped-boundary reason: cert_list_capacity is 2^25 and seq_gas_capacity
	// may be near 2^61 under the representability bound above, so the products
	// are ordinary sets away from wrapping a uint64, and a wrapped comparison
	// is two ratios agreeing on a low word rather than a pairing.
	//
	// No shipped set moves. At the mainnet and testnet genesis ratio of 3.2 the
	// rule demands cert_list_capacity >= 12,800 against the shipped 2^25, a
	// factor of about 2,621 of headroom; devnet's ratio demands 820.
	certHi, certLo := bits.Mul64(uint64(p.CertListCapacity), p.SeqGasTargetGenesis)
	ceilHi, ceilLo := bits.Mul64(uint64(p.MaxCertsPerBlockGenesis), p.SeqGasCapacity)
	if certHi < ceilHi || (certHi == ceilHi && certLo < ceilLo) {
		return fmt.Errorf(
			"params: cert_list_capacity (%d) and seq_gas_capacity (%d) are not paired "+
				"(cert_list_capacity * seq_gas_target_genesis must be at least "+
				"max_certs_per_block_genesis * seq_gas_capacity); the scaled count ceiling "+
				"max_certs_per_block_genesis * T / seq_gas_target_genesis must not reach "+
				"cert_list_capacity for any T <= seq_gas_capacity, or the structural clamp "+
				"binds inside the domain and the count wall arrives before the gas and byte "+
				"walls instead of with them",
			p.CertListCapacity, p.SeqGasCapacity)
	}
	if p.HealthGateBps > 10000 {
		return errors.New("params: health_gate_bps must not exceed 10000")
	}
	if p.InitialSeqBaseFee.Lt(p.MinBaseFee) || p.InitialParBaseFee.Lt(p.MinBaseFee) {
		return errors.New("params: initial base fees must be at least min_base_fee")
	}
	if p.GenesisTarget.Gt(p.MaxTarget) {
		// A chain that starts strictly above its own ceiling is mis-specified:
		// the clamp pulls block 1 back below the target block 0 declared, so
		// the declared start is a value the chain can never return to.
		// Equality is admitted deliberately — a chain may begin at the easiest
		// difficulty it is ever allowed to reach, from which the rule can only
		// move it downward; that is the shape node/p2p's test harness uses.
		return errors.New("params: genesis_target must not exceed max_target")
	}
	if !p.MaxTarget.Lt(workCollapseTarget) {
		// BlockWork is floor(2^256 / (target+1)), so at or above 2^255 every
		// header is worth exactly one unit of work and accumulated work stops
		// ordering branches by work at all. A ceiling there is not a ceiling.
		return errors.New("params: max_target must be below 2^255, the target at which " +
			"block work collapses to one and fork choice becomes a block count")
	}
	if p.TailEmission.Gt(p.GenesisEmission) {
		return errors.New("params: tail_emission must not exceed genesis_emission")
	}
	if p.TreasuryShareBps >= 10000 {
		// Two reasons, and the second is why the bound is >= and not >.
		//
		// Above 10000 the producer's remainder underflows in the fold, which is
		// a conservation failure on every single block.
		//
		// At exactly 10000 the arithmetic is fine and the mechanism is not: the
		// producer's share is zero on every block, and F11's burst valve
		// forfeits *producer* subsidy — the treasury share is taken first from
		// the unreduced subsidy and is never forfeited (whitepaper §8.1, and
		// §14.1 fixes the split so that the remainder pays consensus). A zero
		// producer share therefore leaves the valve with nothing to forfeit,
		// silently disabling it and leaving B5's hard bound alone in the burst
		// band. The accepted range is [1, 9999]; the lower end is the blanket
		// positive rule's, not this check's.
		return errors.New("params: treasury_share_bps must be below 10000, or the " +
			"burst valve's producer forfeiture has nothing to forfeit")
	}
	if p.H1VM < p.H1Bond {
		return errors.New("params: the cEVM cannot activate before bonded underwriters exist")
	}
	if p.H2PoS < p.H1VM {
		return errors.New("params: proof-of-stake cannot activate before phase 1")
	}
	if !p.buildEmissionTable() {
		// Validate's job is to refuse a parameter file rather than to run it.
		// Built unconditionally and unbounded, this call was the parameter file
		// running Validate: a node started against an edited params.json got no
		// error, it got a process that hung or was OOM-killed during startup
		// before anything could say why.
		//
		// The message names the length, not a cause: the divisor that produces an
		// over-long schedule is not always one above the emission. It is above
		// the emission that the schedule gets catastrophically long, because
		// every step is then the forced one-unit step; just past the bound it is
		// merely a slower decay than the table can hold.
		return fmt.Errorf(
			"params: emission_decay_divisor (%d) does not decay genesis_emission to "+
				"tail_emission within %d epochs, so the schedule cannot be built",
			p.EmissionDecayDivisor, maxEmissionEpochs)
	}
	return nil
}

// checkAllPositive enforces the blanket rule by walking the struct, so that a
// parameter added later is covered without anybody remembering to cover it.
func (p *Params) checkAllPositive() error {
	v := reflect.ValueOf(p).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Tag.Get("json")
		if name == "" || !f.IsExported() {
			continue // unexported caches and untagged fields carry no policy
		}
		switch val := v.Field(i).Interface().(type) {
		case uint64:
			if val == 0 {
				return fmt.Errorf("params: %s must be positive", name)
			}
		case int:
			if val <= 0 {
				return fmt.Errorf("params: %s must be positive", name)
			}
		case u256.U256:
			if val.IsZero() {
				return fmt.Errorf("params: %s must be positive", name)
			}
		}
	}
	return nil
}

// Parse decodes and validates a parameter set. Unknown fields are rejected: a
// typo in a consensus parameter must not be silently ignored.
func Parse(data []byte) (*Params, error) {
	var p Params
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}
