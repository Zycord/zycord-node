// Package refold is a second, deliberately naive implementation of the fold.
//
// It exists to disagree with core/fold. Where the reference implementation uses
// hash maps, 256-bit limb arithmetic, a scratch overlay and an undo journal,
// this one uses sorted slices, math/big, and recomputes whatever it needs. It
// is slower by an order of magnitude and that is the point: two implementations
// that share a trick share its bugs.
//
// The differential runner in sim/ fuzzes block sequences through both and
// blocks the release on any divergence.
//
// The rest of this comment is the boundary of that gate. It is wider than this
// comment used to admit, and it goes blind in two different ways, which have
// different causes and different fixes.
//
// # What the two folds share, stated in full
//
// This comment used to exclude only "the stateless V-rules and the hash
// primitives" from what the two folds share. The sixth external audit measured
// the actual surface and it is much wider. That understatement is worth
// correcting for a specific reason: a differential that overstates its
// independence is worse than one that claims none, because the overstatement is
// what stops anyone looking.
//
// Both folds call ONE implementation of each of the following. Where a name
// below appears on both sides it is the same code object, not two answers being
// compared:
//
//   - The entire gas schedule — Certificate.SeqGas and Certificate.ParGas.
//     Every per-write, per-byte and per-signature term a certificate is charged
//     is computed once, in core/types, and read by both folds. This package
//     re-implements what is done with the number, never the number.
//   - F1's sort key — Certificate.ID and Certificate.UnderwriterID. order()
//     below re-derives the sort the slow way; it does not re-derive the key it
//     sorts on.
//   - The block's committed shape — Block.SizeBytes, Block.ComputeCertRoot and
//     Block.ComputeCitesRoot, which the B-rules on both sides compare a header
//     against.
//   - Every block ceiling — params.MaxCertsPerBlock, params.MaxSigsPerBlock,
//     params.BlockByteLimit, params.SeqGasLimit, params.SeqGasBurst,
//     params.ParGasLimit and params.ParGasTarget, together with the scaling
//     law X_genesis × T / T₀ that produces them.
//   - The stateless V-rules and the hash primitives, which this comment has
//     always named. Those do have their own vectors and their own differential
//     surface (u256 against math/big, BLAKE3 against the published vectors);
//     duplicating them here would test the same code twice rather than testing
//     the fold twice.
//
// Driven rather than argued, which is why the list is stated at all:
//
//   - Tripling the per-write term in SeqGas left sim's TestDifferentialFold
//     green on all 8 seeds. What killed that mutant was the frozen corpus, via
//     the deposit amounts the vectors commit to — not this differential.
//   - Changing SeqGasBurst from 4T to 8T — B5's hard validity bound — left
//     `go test ./spec` green. Only two Go tests holding literal constants
//     noticed.
//
// One of those has since been closed and the others have not. The seven
// ceilings now have a genuine second computation: core/params/naive derives
// them from §15's table with its own 128-bit arithmetic and its own parameter
// keys as string literals, reaching neither core/params nor core/u256, with the
// boundary enforced by two `make check-imports` stanzas. That is the
// pattern core/state/naive already applied to the state root. The gas schedule,
// the sort key and the block's committed shape have no equivalent: a peer
// implementation that gets a gas term wrong is held only where the corpus
// happens to commit to a number of that shape.
//
// # The other way this gate goes blind: agreement by never being asked
//
// Sharing an implementation is not the only way two folds can agree for a
// reason that is not correctness. They also agree wherever no input reaches
// either one — and from the outside the two look identical, while the fix for
// the second is a fixture rather than a re-implementation.
//
// Measured: deleting this package's F12 zero-reward arm entirely leaves
// TestDifferentialFold green. Not because the arm is shared — it is written
// twice, in rollRing here and in core/fold's rollCoinbaseRing — but because no
// published parameter set produces a zero block reward above height 0, so
// neither fold ever enters it. A panic() placed in BOTH arms, guarded above
// height 0, fires zero times.
//
// F2b's health-gate comparator is the same shape: the boundary the
// differential would have to cross is not an integer at any shipped parameter
// set.
//
// Arms of that kind are pinned directly here, against fixtures that supply the
// antecedent the shipped sets make vacuous: coinbase_ring_zero_test.go,
// health_gate_test.go and fee_arithmetic_test.go.
//
// F3's non-user-deposit-cell refusal is the strongest case of the shape, and it
// is deliberate rather than a gap to close: checkBlock runs validity.Check over
// every certificate before applyCert sees one, so V4 and V5 refuse a 0x00 or
// 0x03 deposit cell first and NO block can drive that clause in either fold. It
// is written twice anyway, because an F-rule is a thing both folds state, and
// it is separated directly in deposit_version_test.go by calling applyCert
// rather than ApplyBlock.
//
// # How to read a green run
//
// Agreement between these two folds is evidence about the region of the input
// space the generator actually reaches, over the surface the two implement
// separately. It is not evidence about the rules. Before treating this gate as
// covering a rule, check both halves: that the rule is written twice, and that
// something drives it.
package refold

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/ssz"
	"zycord/core/types"
	"zycord/core/validity"
)

var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

// cell is one stored value. Values are big.Int, so every range check is
// explicit rather than implied by the width of a limb.
type cell struct {
	slot  types.Slot
	value *big.Int
}

type seenEntry struct {
	id  types.Hash
	ttl uint64
}

// State is the naive consensus state: three sorted slices.
type State struct {
	cells []cell
	spent []types.Address
	seen  []seenEntry
}

// New returns empty state.
func New() *State { return &State{} }

// Clone returns an independent deep copy.
//
// It exists for the differential runner's adversarial probes: a probe that must
// be *accepted* by both folds cannot be run against the live states, because
// acceptance mutates them and the chain would advance on a block the proposer
// never produced. Cloning both sides makes an accept-side probe as free as a
// reject-side one, which is what lets a boundary be driven from both sides
// rather than only from the side that rejects.
//
// The cell values are copied rather than aliased. This fold replaces a cell's
// *big.Int rather than mutating it in place today, so aliasing would happen to
// work; that is a property of the current code and not of the type, and a
// clone that depends on it is a clone that breaks silently when the fold is
// rewritten -- which is the one thing this package exists to survive.
func (s *State) Clone() *State {
	out := &State{
		cells: make([]cell, len(s.cells)),
		spent: append([]types.Address(nil), s.spent...),
		seen:  append([]seenEntry(nil), s.seen...),
	}
	for i, c := range s.cells {
		out.cells[i] = cell{slot: c.slot, value: new(big.Int).Set(c.value)}
	}
	return out
}

// Outcome mirrors the reference implementation's outcome names as plain
// strings, so a comparison failure reads as text rather than as two integers.
type Outcome string

// The four outcomes.
const (
	Applied         Outcome = "APPLIED"
	SkippedStale    Outcome = "SKIPPED_STALE"
	SkippedOverflow Outcome = "SKIPPED_OVERFLOW"
	Dropped         Outcome = "DROPPED"
)

// CertOutcome is what happened to one certificate.
type CertOutcome struct {
	ID            types.Hash
	Outcome       Outcome
	Charged       *big.Int
	Refunded      *big.Int
	RefundBurned  *big.Int
	Swept         *big.Int
	SweptStranded *big.Int
	StrandedCells uint32
}

// Result mirrors fold.Result.
type Result struct {
	Outcomes      []CertOutcome
	SeqGasUsed    uint64
	ParGasUsed    uint64
	SeqGasApplied uint64
	ParGasApplied uint64
	Burned        *big.Int
	MinerReward   *big.Int
	Treasury      *big.Int
	Matured       *big.Int
	StateRoot     types.Hash
}

// ErrInvalidBlock reports block invalidity.
var ErrInvalidBlock = errors.New("refold: invalid block")

// ruleError names the rule this fold rejected a block by. It is a second,
// independently written answer to the question core/fold's own RuleError
// answers, which is the whole reason this package exists: a rule id that only
// core/fold can produce would be a property of one implementation's control
// flow rather than of the protocol.
type ruleError struct {
	Rule string
	Err  error
}

func (e *ruleError) Error() string { return e.Err.Error() }
func (e *ruleError) Unwrap() error { return e.Err }

// Rule reports which rule rejected a block, or "" if the error names none.
func Rule(err error) string {
	var re *ruleError
	if errors.As(err, &re) {
		return re.Rule
	}
	return ""
}

func invalid(rule, format string, args ...any) error {
	// The rule has been deleted for a necessity sweep (sweep.go): this fold is
	// pretending not to have it, so it does not reject here.
	if skipped[rule] {
		return nil
	}
	return &ruleError{
		Rule: rule,
		Err:  fmt.Errorf("%w: %s: %s", ErrInvalidBlock, rule, fmt.Sprintf(format, args...)),
	}
}

// ---------------------------------------------------------------------------
// Naive storage: linear scans over sorted slices.
// ---------------------------------------------------------------------------

func (s *State) index(slot types.Slot) int {
	for i := range s.cells {
		if s.cells[i].slot == slot {
			return i
		}
	}
	return -1
}

// Get returns a cell value, or zero if absent.
func (s *State) Get(slot types.Slot) *big.Int {
	if i := s.index(slot); i >= 0 {
		return new(big.Int).Set(s.cells[i].value)
	}
	return big.NewInt(0)
}

// Set writes a cell, deleting it when the value is zero so that a drained cell
// is indistinguishable from one that never existed.
func (s *State) Set(slot types.Slot, v *big.Int) {
	i := s.index(slot)
	if v.Sign() == 0 {
		if i >= 0 {
			s.cells = append(s.cells[:i], s.cells[i+1:]...)
		}
		return
	}
	if i >= 0 {
		s.cells[i].value = new(big.Int).Set(v)
		return
	}
	s.cells = append(s.cells, cell{slot: slot, value: new(big.Int).Set(v)})
}

// IsSpent reports whether an address has burned its signing authority.
func (s *State) IsSpent(a types.Address) bool {
	for _, x := range s.spent {
		if x == a {
			return true
		}
	}
	return false
}

// MarkSpent burns an address.
func (s *State) MarkSpent(a types.Address) {
	if !s.IsSpent(a) {
		s.spent = append(s.spent, a)
	}
}

// Seen reports whether a certificate id has been committed.
func (s *State) Seen(id types.Hash) bool {
	for _, e := range s.seen {
		if e.id == id {
			return true
		}
	}
	return false
}

// MarkSeen seeds the seen set. The fold reaches the unexported form below; this
// exists so a golden vector's pre-state can be materialised into this
// implementation as well as into core/state, which is what lets the two folds
// be compared on the committed corpus and not only on generated traffic
// (sim/rule_agreement_test.go).
func (s *State) MarkSeen(id types.Hash, ttl uint64) { s.markSeen(id, ttl) }

func (s *State) markSeen(id types.Hash, ttl uint64) {
	if !s.Seen(id) {
		s.seen = append(s.seen, seenEntry{id: id, ttl: ttl})
	}
}

func (s *State) pruneSeen(below uint64) {
	kept := s.seen[:0]
	for _, e := range s.seen {
		if e.ttl >= below {
			kept = append(kept, e)
		}
	}
	s.seen = kept
}

// Root recomputes the epoch state root from scratch, in the same shape the
// reference implementation defines it.
func (s *State) Root() types.Hash {
	sorted := append([]cell(nil), s.cells...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].slot.Less(sorted[j].slot) })
	cellLeaves := make([]types.Hash, len(sorted))
	for i, c := range sorted {
		var v [32]byte
		c.value.FillBytes(v[:])
		cellLeaves[i] = crypto.Sum(crypto.TagStateCell, c.slot.Addr[:], c.slot.Word[:], v[:])
	}

	addrs := append([]types.Address(nil), s.spent...)
	sort.Slice(addrs, func(i, j int) bool {
		for x := range addrs[i] {
			if addrs[i][x] != addrs[j][x] {
				return addrs[i][x] < addrs[j][x]
			}
		}
		return false
	})
	spentLeaves := make([]types.Hash, len(addrs))
	for i, a := range addrs {
		spentLeaves[i] = crypto.Sum(crypto.TagStateSpent, a[:])
	}

	cellRoot := ssz.ListRoot(cellLeaves, nextPow2(len(cellLeaves)))
	spentRoot := ssz.ListRoot(spentLeaves, nextPow2(len(spentLeaves)))
	return crypto.Sum(crypto.TagStateRoot, cellRoot[:], spentRoot[:])
}

func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// ---------------------------------------------------------------------------
// The fold, written the obvious way.
// ---------------------------------------------------------------------------

// ApplyBlock is the naive state-transition function.
func ApplyBlock(s *State, b *types.Block, p *params.Params) (*Result, error) {
	if err := checkBlock(s, b, p); err != nil {
		return nil, err
	}

	res := &Result{
		Burned:      big.NewInt(0),
		MinerReward: big.NewInt(0),
		Treasury:    big.NewInt(0),
		Matured:     big.NewInt(0),
	}

	// T as it stood before this block, read before the epoch controller below
	// (if this is a boundary) has any chance to move it: block rules already
	// judged this block's ceilings against this exact value (checkBlock's own
	// currentSeqGasTarget read), and the burst forfeiture and the base-fee
	// target further down must be measured against the T this block actually
	// operated under, not the T the next block will see.
	t := currentSeqGasTarget(s, p, b.Header.Height)

	if b.Header.Height%p.EpochLength == 0 {
		s.Set(types.BeaconEpochSlot(), big.NewInt(int64(b.Header.Height/p.EpochLength)))
		s.Set(types.BeaconHeightSlot(), new(big.Int).SetUint64(b.Header.Height))
		var entropy [32]byte
		copy(entropy[:16], b.Header.ParentID[:16])
		s.Set(types.BeaconEntropySlot(), new(big.Int).SetBytes(entropy[:]))
	}

	// The epoch controller of whitepaper §8.1, at every boundary but the
	// first — there is no epoch before genesis to have measured.
	if b.Header.Height%p.EpochLength == 0 && b.Header.Height > 0 {
		updateSeqGasTarget(s, p)
	}

	if b.Header.Height == 0 {
		s.Set(types.SeqBaseFeeSlot(), toBig(p.InitialSeqBaseFee.Bytes()))
		s.Set(types.ParBaseFeeSlot(), toBig(p.InitialParBaseFee.Bytes()))
		s.Set(types.SeqGasTargetSlot(), new(big.Int).SetUint64(p.SeqGasTargetGenesis))
	}

	seqBaseFee := s.Get(types.SeqBaseFeeSlot())
	parBaseFee := s.Get(types.ParBaseFeeSlot())

	tips := big.NewInt(0)
	for _, c := range order(b.Certs) {
		res.SeqGasUsed += c.SeqGas(p)
		res.ParGasUsed += c.ParGas(p)

		out, tip, err := applyCert(s, c, p, seqBaseFee, parBaseFee, res)
		if err != nil {
			return nil, err
		}
		if out.Outcome == Applied {
			res.SeqGasApplied += c.SeqGas(p)
			res.ParGasApplied += c.ParGas(p)
		}
		tips.Add(tips, tip)
		res.Outcomes = append(res.Outcomes, out)
	}

	// Bookkeeping for §8.1's epoch controller, run every block: this block's
	// own applied sequential gas joins the sample ring at its epoch position,
	// its own citations join the count for the epoch now in progress (the
	// controller above already zeroed it if this block opened a new one),
	// and its ParentID and Target become what the next block's citations, if
	// any, are checked against.
	s.Set(types.AppliedGasSampleSlot(b.Header.Height%p.EpochLength), new(big.Int).SetUint64(res.SeqGasApplied))
	if len(b.Cites) > 0 {
		s.Set(types.CitedCountSlot(),
			new(big.Int).Add(s.Get(types.CitedCountSlot()), big.NewInt(int64(len(b.Cites)))))
	}
	s.Set(types.PrevParentIDSlot(), new(big.Int).SetBytes(b.Header.ParentID[:]))
	targetBytes := b.Header.Target.Bytes()
	s.Set(types.PrevTargetSlot(), new(big.Int).SetBytes(targetBytes[:]))

	if b.Header.Height >= 1 {
		s.pruneSeen(b.Header.Height - 1)
	}

	// The subsidy split, done the long way. core/fold reaches for MulDiv64 and
	// then subtracts; this multiplies and divides in the open, because a
	// differential that shares the routine under test is not a differential.
	subsidy := emission(p, b.Header.Height)
	share := new(big.Int).SetUint64(p.TreasuryShareBps)
	treasury := new(big.Int).Div(new(big.Int).Mul(subsidy, share), big.NewInt(10000))
	producer := new(big.Int).Sub(subsidy, treasury)

	// The burst valve (whitepaper §8.1): included sequential gas above the
	// target's ceiling 2T forfeits the producer's block revenue quadratically. The
	// base is the producer's subsidy share PLUS the block's fees, not the subsidy
	// share alone: the deterrent was denominated in a quantity §14.2's schedule
	// decays away while the burst revenue it prices does not, so it was
	// re-denominated in something that tracks the benefit. The treasury above is
	// still not a party to it — its share is taken from the unreduced subsidy and
	// never forfeited. Deliberately two sequential divisions —
	// floor(base*excess/2T), then that result times excess/2T again — rather than
	// the single combined division a naive big.Int computation could do exactly:
	// core/fold computes it with two MulDiv64 calls for overflow safety, and
	// matching that exact rounding path is the point of a differential, not a
	// detail to average away. The forfeit is burned: conservation is stated
	// against the schedule (emission(height)), not against what was actually
	// credited, so a forfeit that vanished without registering here would be value
	// the identity cannot account for. See core/fold's longer note.
	reward := new(big.Int).Add(producer, tips)
	seqLimit := p.SeqGasLimit(t)
	if res.SeqGasUsed > seqLimit {
		excess := new(big.Int).SetUint64(res.SeqGasUsed - seqLimit) // ≤ 2T only while B5 is in force; see the clamp below
		limit := new(big.Int).SetUint64(seqLimit)
		step := new(big.Int).Mul(reward, excess)
		step.Quo(step, limit)
		forfeit := new(big.Int).Mul(step, excess)
		forfeit.Quo(forfeit, limit)
		reward = new(big.Int).Sub(reward, forfeit)
		// LATENT AGAIN, AND THE HISTORY IS THE POINT — do not delete this on the
		// strength of "unreachable". With B5 in force excess is at most seqLimit, so
		// the forfeit is at most the producer's whole block revenue and the
		// difference cannot go negative, which is why core/fold's SatSub at the same
		// place is unreachable too. What used to make this clamp STRUCTURAL is that
		// the fold is also run with a rule DELETED: the necessity sweep removes an
		// invalid vector's own recorded rule and requires the block to fold, and
		// while the corpus carried a B5 vector that sweep drove exactly this line —
		// 101,700 included sequential gas against the 50,000 its seeded T made of 2T,
		// a squared ratio above one, a forfeit larger than the base, and this clamp
		// the only thing keeping the reward off a negative number.
		//
		// Adding B18 took the B5 vector away, and not by choice: the gas-densest
		// Era-0 family reaches 4T only by declaring far more signatures than
		// max_sigs_per_block_genesis admits, so B18 answers first and the vector at
		// index 061 is now a B18 one. No vector records B5, so the sweep never
		// deletes B5, and nothing in the tree drives this line.
		//
		// The record before that vector existed read "latent, not structural, and the
		// distinction is corpus-dependent", and an argument was made that the clamp
		// could never become structural because no block could be refused by B5 at
		// all. Re-deriving mainnet's sequential target falsified the argument and the
		// vector falsified the conclusion; B18 has now made the line latent for a
		// THIRD reason, which is neither of the first two — B5 is reachable or not as
		// a question about shapes, and the corpus is silent about it as a question
		// about ceilings. Corpus-dependent was always the right word.
		if reward.Sign() < 0 {
			reward = big.NewInt(0)
		}
		res.Burned.Add(res.Burned, forfeit)
	}

	res.Treasury = treasury
	res.MinerReward = reward
	if treasury.Sign() > 0 {
		slot := types.TreasurySlot()
		s.Set(slot, new(big.Int).Add(s.Get(slot), treasury))
	}
	res.Matured = rollRing(s, b, p, res)

	// The sequential controller's input is clamped at 2T, §8.1's hard elastic
	// bound. Without it the burst band feeds nextBaseFee a deviation of up to 3T
	// against a target of T, so the upward step reaches +37.5% while an empty
	// block still only steps −12.5% down — an asymmetry that drifts the fee upward
	// under alternating full and empty blocks regardless of demand. The burst
	// valve above already prices the excess in subsidy; this keeps the excess from
	// also repricing the market for everyone. core/fold carries the longer note.
	if b.Header.Height > 0 {
		seqFeeInput := res.SeqGasApplied
		if limit := p.SeqGasLimit(t); limit < seqFeeInput {
			seqFeeInput = limit
		}
		s.Set(types.SeqBaseFeeSlot(), nextBaseFee(p, seqBaseFee, seqFeeInput, t))
		s.Set(types.ParBaseFeeSlot(), nextBaseFee(p, parBaseFee, res.ParGasApplied, p.ParGasTarget(t)))
	}

	if b.Header.Height%p.EpochLength == 0 {
		res.StateRoot = s.Root()
		if res.StateRoot != b.Header.StateRoot {
			if err := invalid("F14", "state root mismatch at height %d", b.Header.Height); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

func applyCert(s *State, c *types.Certificate, p *params.Params,
	seqBaseFee, parBaseFee *big.Int, res *Result) (CertOutcome, *big.Int, error) {
	id := c.ID()
	amount := toBig(c.Deposit.Amount.Bytes())

	// F3's non-user deposit cell refuses the BLOCK, F13's shape and not the two
	// drops below. core/fold carries the argument; this fold states it because
	// PROTOCOL rule 12 makes an F-rule a thing written twice, and a clause present
	// in one fold and absent in the other is exactly the drift the frozen corpus
	// cannot separate — the differential cannot see it, because checkBlock runs
	// validity.Check over every certificate first and V4/V5 refuse a non-user
	// deposit cell before this line is ever reached.
	if !crypto.IsUserAddress(c.Deposit.Cell.Addr) {
		if err := invalid("F3", "non-user deposit cell"); err != nil {
			return CertOutcome{}, big.NewInt(0), err
		}
	}

	if s.IsSpent(c.Deposit.Cell.Addr) {
		return CertOutcome{ID: id, Outcome: Dropped, Charged: big.NewInt(0),
			Refunded: big.NewInt(0), RefundBurned: big.NewInt(0),
			Swept: big.NewInt(0), SweptStranded: big.NewInt(0)}, big.NewInt(0), nil
	}
	balance := s.Get(c.Deposit.Cell)
	if balance.Cmp(amount) < 0 {
		return CertOutcome{ID: id, Outcome: Dropped, Charged: big.NewInt(0),
			Refunded: big.NewInt(0), RefundBurned: big.NewInt(0),
			Swept: big.NewInt(0), SweptStranded: big.NewInt(0)}, big.NewInt(0), nil
	}
	s.Set(c.Deposit.Cell, new(big.Int).Sub(balance, amount))

	skipFee := toBig(p.SkipFee.Bytes())
	if !readsHold(s, c) {
		return settle(s, c, id, SkippedStale, skipFee, res), big.NewInt(0), nil
	}

	staged, reason := stage(s, c)
	if reason != Applied {
		return settle(s, c, id, reason, skipFee, res), big.NewInt(0), nil
	}
	for _, w := range staged {
		s.Set(w.slot, w.value)
	}
	for _, w := range c.Writes {
		if w.Op == types.OpMarkSpent {
			s.MarkSpent(w.Slot.Addr)
		}
	}

	// F8b — a burn strands nothing the fold can name. Written the obvious way:
	// collect the cells under each burned address that this certificate can name,
	// then move each one to the same word under the refund address. Nothing is
	// destroyed and nothing can fail — a value that cannot be delivered stays
	// exactly where it was, which is what the fold did before F8b existed.
	swept, sweptStranded := big.NewInt(0), big.NewInt(0)
	var strandedCells uint32
	for _, w := range c.Writes {
		if w.Op != types.OpMarkSpent {
			continue
		}
		cells := []types.Slot{types.NativeBalanceSlot(w.Slot.Addr)}
		for _, x := range c.Writes {
			if x.Slot.Addr == w.Slot.Addr && x.Op != types.OpMarkSpent &&
				!types.IsNativeBalanceSlot(x.Slot) {
				cells = append(cells, x.Slot)
			}
		}
		for _, src := range cells {
			v := s.Get(src)
			if v.Sign() == 0 {
				continue
			}
			dst := types.Slot{Addr: c.Deposit.RefundTo.Addr, Word: src.Word}
			sum := new(big.Int).Add(s.Get(dst), v)
			if s.IsSpent(c.Deposit.RefundTo.Addr) || sum.Cmp(two256) >= 0 {
				// Left where it is. Only the native counter is reported, for
				// the reason core/fold's CertOutcome.Swept gives.
				if types.IsNativeBalanceSlot(src) {
					sweptStranded.Add(sweptStranded, v)
				}
				strandedCells++
				continue
			}
			s.Set(src, big.NewInt(0))
			s.Set(dst, sum)
			if types.IsNativeBalanceSlot(src) {
				swept.Add(swept, v)
			}
		}
	}

	// Both markets charge the full bid; the base portion of each is burned and
	// the excess is the miner's tip. Written out longhand rather than delegated
	// to types.Certificate.Fees, because a differential that shares the routine
	// under test is not a differential.
	// Each market burns gas x base and tips gas x min(priority, max - base).
	// Written out longhand rather than delegated to types.Certificate.Fees,
	// because a differential that shares the routine under test is not a
	// differential.
	seqGas := new(big.Int).SetUint64(c.SeqGas(p))
	parGas := new(big.Int).SetUint64(c.ParGas(p))

	seqBurn, seqTip := marketFees(seqGas, seqBaseFee,
		toBig(c.FeeBid.SeqMax.Bytes()), toBig(c.FeeBid.SeqPriority.Bytes()))
	parBurn, parTip := marketFees(parGas, parBaseFee,
		toBig(c.FeeBid.ParMax.Bytes()), toBig(c.FeeBid.ParPriority.Bytes()))

	tip := new(big.Int).Add(seqTip, parTip)
	burn := new(big.Int).Add(seqBurn, parBurn)
	charge := new(big.Int).Add(burn, tip)

	res.Burned.Add(res.Burned, burn)
	out := settle(s, c, id, Applied, charge, res)
	out.Swept, out.SweptStranded, out.StrandedCells = swept, sweptStranded, strandedCells
	return out, tip, nil
}

func settle(s *State, c *types.Certificate, id types.Hash,
	outcome Outcome, charge *big.Int, res *Result) CertOutcome {
	if outcome != Applied {
		res.Burned.Add(res.Burned, charge)
	}
	refund := new(big.Int).Sub(toBig(c.Deposit.Amount.Bytes()), charge)
	if refund.Sign() < 0 {
		panic("refold: charge exceeded the deposit")
	}
	refunded, refundBurned := big.NewInt(0), big.NewInt(0)
	if refund.Sign() > 0 {
		if s.IsSpent(c.Deposit.RefundTo.Addr) {
			res.Burned.Add(res.Burned, refund)
			refundBurned = refund
		} else {
			s.Set(c.Deposit.RefundTo, new(big.Int).Add(s.Get(c.Deposit.RefundTo), refund))
			refunded = refund
		}
	}
	s.markSeen(id, c.TTL)
	return CertOutcome{ID: id, Outcome: outcome, Charged: charge,
		Refunded: refunded, RefundBurned: refundBurned,
		Swept: big.NewInt(0), SweptStranded: big.NewInt(0)}
}

// marketFees settles one market the obvious way.
func marketFees(gas, base, maxPrice, priority *big.Int) (burn, tip *big.Int) {
	// The clamp is STRUCTURAL here and dead in core/fold, which is PROTOCOL rule
	// 12's shape rather than an accident. B4 forbids a maximum below the base fee,
	// so core/types' market() can only re-check for an underflow it cannot reach;
	// but sweep.go deletes B4 for the necessity sweep and the corpus records a B4
	// vector, so this fold is routinely driven into that state and has to settle
	// it rather than reject it. Without the clamp the tip goes negative and the
	// fold pays the producer money it invented. Held by
	// TestAFeeCapBelowTheBaseFeePaysNoPriorityInThisFold, and by
	// TestTheCorpusDrivesThisFoldIntoAFeeCapBelowTheBaseFee for the reachability
	// half — nothing held it before the twice-written-rule census.
	headroom := new(big.Int).Sub(maxPrice, base)
	if headroom.Sign() < 0 {
		headroom = big.NewInt(0)
	}
	effective := priority
	if effective.Cmp(headroom) > 0 {
		effective = headroom
	}
	return new(big.Int).Mul(gas, base), new(big.Int).Mul(gas, effective)
}

func readsHold(s *State, c *types.Certificate) bool {
	for _, r := range c.Reads {
		if s.IsSpent(r.Slot.Addr) {
			return false
		}
		have := s.Get(r.Slot)
		want := toBig(r.Operand.Bytes())
		switch r.Access {
		case types.AccessExact, types.AccessGuardEQ:
			if have.Cmp(want) != 0 {
				return false
			}
		case types.AccessGuardGE:
			if have.Cmp(want) < 0 {
				return false
			}
		case types.AccessGuardLE:
			if have.Cmp(want) > 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type staged struct {
	slot  types.Slot
	value *big.Int
}

func stage(s *State, c *types.Certificate) ([]staged, Outcome) {
	var out []staged
	for _, w := range c.Writes {
		if s.IsSpent(w.Slot.Addr) {
			return nil, SkippedStale
		}
		if w.Op == types.OpMarkSpent {
			continue
		}
		base := s.Get(w.Slot)
		v := toBig(w.Value.Bytes())
		var next *big.Int
		switch w.Op {
		case types.OpSet:
			next = v
		case types.OpDeltaAdd:
			next = new(big.Int).Add(base, v)
		case types.OpDeltaSub:
			next = new(big.Int).Sub(base, v)
		default:
			return nil, SkippedOverflow
		}
		if next.Sign() < 0 || next.Cmp(two256) >= 0 {
			return nil, SkippedOverflow
		}
		out = append(out, staged{slot: w.Slot, value: next})
	}

	return out, Applied
}

// rollRing is F12, this package's second statement of the coinbase maturity
// ring.
//
// The zero-reward arm below is a consensus rule, not an optimisation: a reward
// of zero clears the entry rather than writing (payout, 0) against it. The
// differential runner cannot hold this arm: it drives spec.Devnet() and nothing
// else, and on devnet the reward is non-zero at every height above 0, so
// neither fold's arm is ever entered and the two agree by never being asked —
// so it is pinned here directly, the way the health gate's comparator is pinned
// here, after the differential turned out to be arithmetically blind to it. See
// core/fold's rollCoinbaseRing for why the pair is cleared rather than
// half-written, and coinbase_ring_zero_test.go here for the port.
func rollRing(s *State, b *types.Block, p *params.Params, res *Result) *big.Int {
	index := b.Header.Height % p.CoinbaseMaturity
	addrSlot := types.PendingCoinbaseAddrSlot(index)
	amountSlot := types.PendingCoinbaseAmountSlot(index)

	matured := big.NewInt(0)
	if pending := s.Get(amountSlot); pending.Sign() > 0 {
		var raw [32]byte
		s.Get(addrSlot).FillBytes(raw[:])
		payee := types.Address(raw)
		if s.IsSpent(payee) {
			res.Burned.Add(res.Burned, pending)
		} else {
			target := types.NativeBalanceSlot(payee)
			s.Set(target, new(big.Int).Add(s.Get(target), pending))
			matured = pending
		}
	}

	if res.MinerReward.Sign() == 0 {
		s.Set(addrSlot, big.NewInt(0))
		s.Set(amountSlot, big.NewInt(0))
	} else {
		s.Set(addrSlot, new(big.Int).SetBytes(b.Header.EmissionAddr[:]))
		s.Set(amountSlot, res.MinerReward)
	}
	return matured
}

// order sorts by (underwriter, seq, id) the slow, obvious way: build the keys,
// then sort.
func order(certs []*types.Certificate) []*types.Certificate {
	type keyed struct {
		cert  *types.Certificate
		under types.Address
		seq   uint64
		id    types.Hash
	}
	keys := make([]keyed, len(certs))
	for i, c := range certs {
		keys[i] = keyed{cert: c, under: c.UnderwriterID(), seq: c.Seq, id: c.ID()}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		for x := range a.under {
			if a.under[x] != b.under[x] {
				return a.under[x] < b.under[x]
			}
		}
		if a.seq != b.seq {
			return a.seq < b.seq
		}
		for x := range a.id {
			if a.id[x] != b.id[x] {
				return a.id[x] < b.id[x]
			}
		}
		return false
	})
	out := make([]*types.Certificate, len(keys))
	for i, k := range keys {
		out[i] = k.cert
	}
	return out
}

// currentSeqGasTarget is T as it stood before a block: SeqGasTargetGenesis at
// height 0, because state has nothing to read yet, the state cell at every
// later height. Independent of, but deliberately named the same as,
// core/fold's function of the same purpose (fold.go's own doc comment
// explains why the value must be read before the epoch controller moves it).
func currentSeqGasTarget(s *State, p *params.Params, height uint64) uint64 {
	if height == 0 {
		return p.SeqGasTargetGenesis
	}
	return s.Get(types.SeqGasTargetSlot()).Uint64()
}

// updateSeqGasTarget is refold's independent reimplementation of whitepaper
// §8.1's epoch controller — no shared formula with core/fold's function of
// the same name, big.Int throughout so nothing here needs to reason about
// overflow the way the reference implementation's u256 comparison does.
//
// The median is the **lower** median of the sample ring (element (L-1)/2 of
// the sorted L values), never an average: L is even at genesis, and two
// implementations of "the median of an even-length list" that pick different
// conventions will disagree on a number that gates real money. This must
// match core/fold's choice exactly, or the differential fails on every
// epoch boundary rather than on a real bug.
func updateSeqGasTarget(s *State, p *params.Params) {
	l := p.EpochLength
	samples := make([]uint64, l)
	for i := uint64(0); i < l; i++ {
		samples[i] = s.Get(types.AppliedGasSampleSlot(i)).Uint64()
	}
	sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
	median := samples[(l-1)/2]

	cited := s.Get(types.CitedCountSlot()).Uint64()
	citedRate := new(big.Int).Mul(big.NewInt(0).SetUint64(cited), big.NewInt(10000))
	gateRate := new(big.Int).Mul(new(big.Int).SetUint64(p.HealthGateBps), new(big.Int).SetUint64(l))
	// `<= 0`, which is §8's F2b verbatim —
	// `healthy <- cited_count x 10000 <= HEALTH_GATE_BPS x EpochLength` — and the
	// same sentence core/fold spells as `!citedRate.Gt(gateRate)`.
	//
	// The differential cannot hold the two to it: cited is an integer, so the
	// comparators differ only where equality is possible, which needs
	// HealthGateBps x EpochLength to be a multiple of 10000, and no shipped
	// parameter set makes it one -- the reasoning is at core/fold's
	// updateSeqGasTarget. Deleting the `=` here would be invisible to every vector
	// and to this sweep. This copy is pinned instead by this package's
	// TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate, the port of
	// core/fold's test of the same name: a unit test at a legal but unshipped
	// operator configuration chosen so an integer count of cited headers lands on
	// the gate. It is legitimate because §8's F2b is quantified over
	// HEALTH_GATE_BPS — the fixture supplies the antecedent rather than
	// substituting the subject — and the test runs at two independent witnesses so
	// that is checkable rather than asserted.
	healthy := citedRate.Cmp(gateRate) <= 0

	t := s.Get(types.SeqGasTargetSlot()).Uint64()
	lo := t - t/p.CeilingDecayDivisor
	hi := t
	if healthy {
		hi = t + t/p.CeilingGrowthDivisor
	}
	next := 2 * median
	if next < lo {
		next = lo
	}
	if next > hi {
		next = hi
	}
	// T may never grow past seq_gas_capacity. docs/ARCHITECTURE.md states the
	// controller as T = min(the epoch controller's output, SeqGasCapacity), and
	// it is what keeps the base-fee target inside what a physically full block
	// can deliver once the byte ceiling binds -- without it T settles at twice
	// the achievable and the sequential market stops pricing at all.
	//
	// This fold did not carry it, and that was a live disagreement with core/fold
	// rather than a difference of derivation: with T pinned at the capacity on one
	// side and still climbing on the other, the two folds disagree on the
	// sequential target cell and therefore on every ceiling derived from it and on
	// the epoch state root. The differential runner could not see it because
	// seq_gas_capacity is 3.2x seq_gas_target_genesis on all three shipped
	// networks and growth is clamped to T/512 per epoch, so the wall is 597 epochs
	// away -- 38,208 blocks at devnet's epoch length, against the 300 the longest
	// run in this package drives. A sweep scoped to core/ cannot find this: core's
	// copy is present and pinned by TestNextSeqGasTargetRespectsItsClamps, and the
	// missing one is here.
	//
	// Clamped ahead of the genesis floor, in core/params.NextSeqGasTarget's own
	// order. Validate refuses a capacity below the floor, so the order is
	// unobservable on any parameter set a network can run; it is matched rather
	// than re-derived so that the two are the same function of the same inputs
	// even where nothing can currently tell them apart.
	if next > p.SeqGasCapacity {
		next = p.SeqGasCapacity
	}
	if next < p.SeqGasTargetGenesis {
		next = p.SeqGasTargetGenesis
	}

	s.Set(types.SeqGasTargetSlot(), new(big.Int).SetUint64(next))
	s.Set(types.CitedCountSlot(), big.NewInt(0))
}

// checkCites is the naive, independent reimplementation of
// fold/blockrules.go's checkCites: rules 1 through 5 of whitepaper §8.1's
// health-signal citations. The capacity bound is checked by the caller
// (above), not here — see checkBlock. Proof of work is out of scope here for
// the same reason it is out of scope there — it belongs to node/, and
// neither fold implementation imports it.
func checkCites(s *State, b *types.Block, p *params.Params) error {
	h := b.Header
	if h.Height <= 1 {
		if len(b.Cites) != 0 {
			if err := invalid("B17", "citation at height %d is impossible", h.Height); err != nil {
				return err
			}
		}
		return nil
	}

	var prevParentID types.Hash
	fillFromBig(prevParentID[:], s.Get(types.PrevParentIDSlot()))
	var prevTarget [32]byte
	fillFromBig(prevTarget[:], s.Get(types.PrevTargetSlot()))

	var lastID types.Hash
	for i, cited := range b.Cites {
		if cited.Version != types.HeaderVersion {
			if err := invalid("C0", "citation %d has an unknown header version", i); err != nil {
				return err
			}
		}
		if cited.Height != h.Height-1 {
			if err := invalid("C1", "citation %d has the wrong height", i); err != nil {
				return err
			}
		}
		if cited.ParentID != prevParentID {
			if err := invalid("C2", "citation %d does not share this block's grandparent", i); err != nil {
				return err
			}
		}
		id := cited.ID()
		if id == h.ParentID {
			if err := invalid("C3", "citation %d names this block's own parent", i); err != nil {
				return err
			}
		}
		targetBytes := cited.Target.Bytes()
		if targetBytes != prevTarget {
			if err := invalid("C4", "citation %d claims the wrong target", i); err != nil {
				return err
			}
		}
		if i > 0 && bytes.Compare(id[:], lastID[:]) <= 0 {
			if err := invalid("C5", "citations are not strictly sorted"); err != nil {
				return err
			}
		}
		lastID = id
	}
	return nil
}

// fillFromBig writes v into dst as big-endian, zero-padded on the left —
// big.Int.Bytes() strips leading zeros, so a plain copy would misalign a
// short value against the left edge of a fixed-width field instead of the
// right, exactly the bug FillBytes exists to prevent.
func fillFromBig(dst []byte, v *big.Int) { v.FillBytes(dst) }

func checkBlock(s *State, b *types.Block, p *params.Params) error {
	h := b.Header
	if h.Version != types.HeaderVersion {
		if err := invalid("B7", "bad header version"); err != nil {
			return err
		}
	}

	// The proof-of-work key epoch a header declares must be the one its height
	// implies.
	//
	// Derived here by *counting boundaries* rather than by core/pow's
	// subtract-and-divide, which is the whole point of this file: a
	// differential that calls the function it is checking measures nothing.
	// The k-th boundary sits at k*interval + lag, so the epoch is the number
	// of boundaries at or below this height. That is O(height/interval) and
	// affordable at the scale this runner works on; it is not the form a
	// consensus implementation should use, and it is not meant to be.
	epoch := uint64(0)
	for (epoch+1)*p.RandomXKeyInterval+p.RandomXKeyLag <= h.Height {
		epoch++
	}
	if h.PoW.SeedEpoch != epoch {
		if err := invalid("B0b", "bad seed epoch"); err != nil {
			return err
		}
	}

	t := currentSeqGasTarget(s, p, h.Height)
	certCeiling := p.MaxCertsPerBlock(t)
	byteCeiling := p.BlockByteLimit(t)
	seqBurst := p.SeqGasBurst(t)   // 4T: the hard ceiling. 2T is a soft
	parCeiling := p.ParGasLimit(t) // threshold enforced by ApplyBlock's forfeiture.

	if len(b.Certs) > certCeiling {
		if err := invalid("B12", "too many certificates"); err != nil {
			return err
		}
	}
	// B18 — the signature ceiling, counted before anything in this function
	// verifies a signature, which is the whole of the rule: it bounds the
	// verification a block can demand of a receiver, so it has to be answerable
	// from the certificate headers alone. Counted here in a plain loop with no
	// ceiling arithmetic shared with core/fold's, per this file's standing rule
	// about differentials that call what they check.
	var sigs uint64
	for _, c := range b.Certs {
		sigs += uint64(len(c.Sigs))
	}
	if sigs > p.MaxSigsPerBlock(t) {
		if err := invalid("B18", "too many signatures"); err != nil {
			return err
		}
	}
	if b.SizeBytes() > byteCeiling {
		if err := invalid("B13", "block too large"); err != nil {
			return err
		}
	}
	// Checked before ComputeCitesRoot, exactly as the certificate count is
	// checked before ComputeCertRoot above: both reach ssz.Merkleize, which
	// panics on a list longer than its capacity rather than erroring.
	if len(b.Cites) > p.MaxCitesPerBlock {
		if err := invalid("B15", "too many citations"); err != nil {
			return err
		}
	}
	if b.ComputeCertRoot(p) != h.CertRoot {
		if err := invalid("B14", "certificate root mismatch"); err != nil {
			return err
		}
	}
	if b.ComputeCitesRoot(p) != h.CitesRoot {
		if err := invalid("B16", "cites root mismatch"); err != nil {
			return err
		}
	}
	if err := checkCites(s, b, p); err != nil {
		return err
	}
	if h.Height == 0 {
		// The genesis parent slot carries the consensus root, so a node with
		// different parameters cannot accept this block (R3-1).
		if len(b.Certs) != 0 || h.EmissionAddr != (types.Address{}) {
			if err := invalid("B10", "malformed genesis block"); err != nil {
				return err
			}
		}
		if h.ParentID != p.ConsensusRoot() {
			if err := invalid("B10", "genesis does not commit to this node's parameters"); err != nil {
				return err
			}
		}
	} else {
		if h.ParentID == (types.Hash{}) {
			if err := invalid("B10", "missing parent"); err != nil {
				return err
			}
		}
		if !crypto.IsUserAddress(h.EmissionAddr) {
			if err := invalid("B11", "bad payout address"); err != nil {
				return err
			}
		}
	}
	if h.Height%p.EpochLength != 0 && h.StateRoot != (types.Hash{}) {
		if err := invalid("B9", "state root outside an epoch boundary"); err != nil {
			return err
		}
	}

	seqBaseFee := s.Get(types.SeqBaseFeeSlot())
	parBaseFee := s.Get(types.ParBaseFeeSlot())
	if h.Height == 0 {
		seqBaseFee = toBig(p.InitialSeqBaseFee.Bytes())
		parBaseFee = toBig(p.InitialParBaseFee.Bytes())
	}

	var seqGas, parGas uint64
	for i, c := range b.Certs {
		// Both folds share ONE copy of V1-V9: this line calls the same core/validity
		// the consensus fold calls, rather than transcribing the certificate
		// predicate a second time. That is deliberate, and it has a cost worth naming
		// at the call site.
		//
		// The cost. sim/refold exists so that two independently written folds
		// can disagree, and TestBothFoldsAgreeOnTheRuleTheCorpusRecords is
		// where that disagreement would surface. On a vector whose recorded
		// rule is a V-rule, that test is comparing core/validity with itself,
		// so it is deliberately uninformative there — it cannot catch a V-rule
		// divergence, and a green run of it says nothing about V1-V9. Read it
		// as covering the block rules; the V-rules are held elsewhere.
		//
		// Why the sharing is still the right trade. A second copy of a consensus
		// predicate is a drift generator, not a check: an F2b capacity clamp was once
		// omitted *by* transcription and carried a live cross-fold divergence until
		// it was found. Era-0 rule — least code, no consensus touch.
		//
		// Where the V-rule surface is actually held, since it is not held here.
		//   - The per-rule frozen vectors, plus spec's
		//     TestEveryVRuleIsSeparatedByTheCorpus, which asserts the property
		//     rather than the instances: every rule §7 defines has a vector
		//     separating it, or an armed exemption that fails the moment the
		//     exemption's reason stops being true. V1-V6 are separated by
		//     vectors, V8 is pinned under its block spelling B2 (vector 027),
		//     and V7/V9 are unreachable through validity.Check in Era 0
		//     because another rule answers first — V3, and for V9 also V4/V5.
		//   - sim's TestEveryInvalidVectorsRuleIsNecessary, via
		//     refold.WithoutRule. Note precisely what that switch does: it
		//     suppresses the rule's *effect*, not its code. skipped[rule] is
		//     read in invalid() below, so for a V-rule the whole of
		//     core/validity still runs and still computes the rejection —
		//     WithoutRule only drops the verdict on its way out of this fold.
		//     It therefore shows the recorded id is necessary to the rejection;
		//     it does not exercise a fold that lacks the rule's code, which is
		//     the thing a transcription would have given and this does not.
		//
		// When this is revisited: at the era boundary that makes V7/V9
		// reachable through validity.Check. Nobody has to remember — the armed
		// exemptions in TestEveryVRuleIsSeparatedByTheCorpus (see
		// spec/README.md) fail by construction at that boundary, and this
		// comment is what that failure should send the reader back to.
		if err := validity.Check(c, p); err != nil {
			// The V-rule that failed, exactly as core/fold reports it: B0 is a
			// quantifier over V1..V9, so naming it would say only "some certificate",
			// which the verdict already said.
			if err := invalid(validity.Rule(err), "certificate %d is invalid: %v", i, err); err != nil {
				return err
			}
		}
		for j := 0; j < i; j++ {
			if b.Certs[j].ID() == c.ID() {
				if err := invalid("B8", "duplicate certificate"); err != nil {
					return err
				}
			}
		}
		if h.Height > c.TTL {
			if err := invalid("B1", "expired certificate"); err != nil {
				return err
			}
		}
		// Written as the distance, not as the sum: h.Height+p.TTLMax wraps, and a
		// wrapped ceiling is not a ceiling. At ttl_max = 2^64-1 -- a value
		// params.Validate accepts -- the sum is below every height, so every
		// certificate B1 admitted was refused here. core/fold carries the same
		// correction; the two folds exist to disagree, and agreeing on this is the
		// point.
		//
		// The height guard is not redundant here as it is in core/fold. There B1
		// directly above always runs, so c.TTL >= h.Height on arrival. Here sweep.go
		// can delete B1, and a bare subtraction would underflow to a huge distance
		// and let B2 reject the block B1's necessity check requires to become valid
		// -- this fold would then disagree with the integers exactly where it is
		// meant to check them.
		if c.TTL > h.Height && c.TTL-h.Height > p.TTLMax {
			if err := invalid("B2", "TTL beyond the bound"); err != nil {
				return err
			}
		}
		if s.Seen(c.ID()) {
			if err := invalid("B3", "replayed certificate"); err != nil {
				return err
			}
		}
		if toBig(c.FeeBid.SeqMax.Bytes()).Cmp(seqBaseFee) < 0 {
			if err := invalid("B4", "sequential maximum below base"); err != nil {
				return err
			}
		}
		if toBig(c.FeeBid.ParMax.Bytes()).Cmp(parBaseFee) < 0 {
			if err := invalid("B4", "parallel maximum below base"); err != nil {
				return err
			}
		}
		for _, w := range c.Writes {
			if w.Slot.Addr[0] == crypto.AddrVersionProtocol {
				if err := invalid("F13", "protocol write"); err != nil {
					return err
				}
			}
		}
		seqGas += c.SeqGas(p)
		parGas += c.ParGas(p)
	}
	if seqGas > seqBurst {
		if err := invalid("B5", "sequential gas burst bound"); err != nil {
			return err
		}
	}
	if parGas > parCeiling {
		if err := invalid("B6", "parallel gas ceiling"); err != nil {
			return err
		}
	}
	return nil
}

// emission recomputes the schedule from scratch every call — the naive way,
// which is exactly what a differential wants.
func emission(p *params.Params, height uint64) *big.Int {
	if height == 0 {
		return big.NewInt(0)
	}
	tail := toBig(p.TailEmission.Bytes())
	e := toBig(p.GenesisEmission.Bytes())
	divisor := new(big.Int).SetUint64(p.EmissionDecayDivisor)
	for n := uint64(0); n < height/p.EpochLength; n++ {
		if e.Cmp(tail) <= 0 {
			return tail
		}
		step := new(big.Int).Quo(e, divisor)
		if step.Sign() == 0 {
			step = big.NewInt(1)
		}
		e = new(big.Int).Sub(e, step)
		if e.Cmp(tail) < 0 {
			e = tail
		}
	}
	return e
}

func nextBaseFee(p *params.Params, base *big.Int, used, target uint64) *big.Int {
	minFee := toBig(p.MinBaseFee.Bytes())
	if target == 0 || used == target {
		// Kept, mirroring core/params.NextBaseFee's decision and for its reason --
		// see the note there. Unobservable in both folds and not makeable observable:
		// no sweep, because no rule deletion writes the base-fee slot, and no vector
		// that encodes a reachable pre-state at all. The two folds must keep or drop
		// it together, or the differential compares two different functions.
		return maxBig(base, minFee)
	}
	denom := new(big.Int).SetUint64(p.BaseFeeMaxChangeDenominator)
	if used > target {
		delta := new(big.Int).Mul(base, new(big.Int).SetUint64(used-target))
		delta.Quo(delta, new(big.Int).SetUint64(target))
		delta.Quo(delta, denom)
		if delta.Sign() == 0 {
			delta = big.NewInt(1)
		}
		out := new(big.Int).Add(base, delta)
		if out.Cmp(two256) >= 0 {
			out = new(big.Int).Sub(two256, big.NewInt(1))
		}
		return out
	}
	delta := new(big.Int).Mul(base, new(big.Int).SetUint64(target-used))
	delta.Quo(delta, new(big.Int).SetUint64(target))
	delta.Quo(delta, denom)
	out := new(big.Int).Sub(base, delta)
	if out.Sign() < 0 {
		out = big.NewInt(0)
	}
	return maxBig(out, minFee)
}

func maxBig(a, b *big.Int) *big.Int {
	if a.Cmp(b) >= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

func toBig(b [32]byte) *big.Int { return new(big.Int).SetBytes(b[:]) }
