package sim

import (
	"fmt"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/sim/refold"
	"zycord/wallet"
)

// The parameter-perturbation harness.
//
// WHY THIS EXISTS. A differential test that folds one block shape under a
// perturbed parameter set proves the two folds agree on that shape. Before the
// signing message was rebound onto the consensus root, the cheap way to get
// many shapes was to lift blocks out of spec/vectors and re-fold them under a
// modified parameter set — and that route is closed, for a reason that is a
// feature rather than a defect: the signing message now binds the consensus
// root, so a corpus block folded under any perturbed set fails V2 on its first
// certificate and never reaches the rule the test names. The corpus does not
// carry the keys that signed it, so nothing can re-sign it.
//
// The lane that closed the route removed one such test and recorded the loss in
// those words: what went was BLOCK-SHAPE VARIETY. This is the capability that
// gives it back. It does not lift corpus blocks; it REBUILDS corpus-shaped
// blocks under whatever parameter set it is handed, signing every certificate
// under that set as it goes, so V2 is satisfied by construction and every
// verdict is attributable to the rule under test.
//
// WHAT IT IS NOT. It is not the golden corpus and does not replace it: the
// corpus pins exact post-states against frozen bytes, and this pins agreement
// between two implementations. It is also not a census of every shape the
// corpus carries — the asset-residual-under-a-burned-address pipeline (F8b's
// second clause) and the difficulty-retarget vectors are not here, because both
// need a multi-block trajectory rather than a block, and Runner already drives
// the first at devnet. What is here is the catalogue below, and the catalogue
// is checked against its own declared outcome census on every run: a shape whose
// certificates all quietly became DROPPED fails rather than passes, which is
// the failure mode a variety claim has to defend against.
//
// MUTATION-PROVEN, because a differential nobody has seen fail is a
// differential nobody has checked. Three mutations, each reverted after:
//
//   - sim/refold's B2 written back as the earlier sum `c.TTL > h.Height +
//     p.TTLMax`: the wrapping arms fail on both bases and no other arm does,
//     which is the divergence that shipped once: the sum wrapped below h and
//     inverted B2 from a ceiling into a blanket refusal;
//   - sim/refold's F8b native sweep deleted (its `cells` list starting empty):
//     one-shot-burn-and-refund fails at all six arms, and it is the ONLY shape
//     here that reaches that clause — the variety is what catches it;
//   - the catalogue's own funding for actorA cut to 3,000 drops: the run fails
//     inside drive() with "single-transfer ... applied=0 dropped=1", which is
//     the anti-vacuity guard doing the job it exists for.

// perturbationBid is the fee bid every certificate in the catalogue carries.
//
// It is deliberately constant across parameter sets rather than derived from
// each set's base fees: the maxima are solvency bounds, and both shipped sets
// start at the same initial_seq_base_fee, so one generous bid clears B4 at all
// of them. A bid that varied per set would make a shape's outcome a function of
// the bid as well as of the parameters.
func perturbationBid() types.FeeBid {
	return wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000),
		u256.FromUint64(500), u256.FromUint64(10))
}

// Shape is one block of the catalogue, recorded after both folds have judged
// it. The Want fields are what the catalogue declared before the run; the rest
// is what happened.
type Shape struct {
	Name   string
	Height uint64
	Certs  int

	Accepted bool
	Applied  int
	Skipped  int
	Dropped  int

	// Absent is set when the shape was not driven at this parameter set, with
	// Why naming the reason. A shape is never absent silently: the test asserts
	// on the reason.
	Absent bool
	Why    string
}

// want is a shape's declared expectation. A run that does not meet it fails,
// which is what keeps the catalogue from eroding into blocks that reach the
// folds while exercising nothing.
type want struct {
	accepted bool
	applied  int
	skipped  int
	dropped  int
}

// Perturbation drives a fixed catalogue of block shapes through both folds
// under an arbitrary parameter set.
//
// Everything it builds is built under Params: the chain starts at that set's
// own genesis, every fee is priced by that set's base fees, and every
// certificate is signed over that set's consensus root. That is the shape any
// parameter-perturbation test has to take now that the signing message binds
// the consensus root, and it is the whole reason this type exists rather than a
// helper that re-folds an existing block.
type Perturbation struct {
	Params *params.Params
	Chain  *harness.Chain
	Naive  *refold.State

	// Driven is the catalogue, in the order it ran.
	Driven []Shape

	miner  *wallet.Key
	payout types.Address

	seqs    map[types.Address]uint64
	nextKey uint16
}

// NewPerturbation builds a chain at p, folds its genesis through both
// implementations, and mines the miner into funds.
//
// It takes no seed and draws nothing at random. The catalogue is scripted
// precisely so that "the same shapes ran at every parameter set" is a fact
// about the harness rather than a hope about a stream: a randomised generator
// that reached a shape at one ttl_max and missed it at another would report
// agreement over a different population in each arm.
func NewPerturbation(p *params.Params) (*Perturbation, error) {
	block, _, err := genesis.Build(p)
	if err != nil {
		return nil, err
	}
	naive := refold.New()
	if _, err := refold.ApplyBlock(naive, block, p); err != nil {
		return nil, fmt.Errorf("sim: the naive fold rejected genesis: %w", err)
	}
	chain, err := harness.New(p)
	if err != nil {
		return nil, err
	}

	x := &Perturbation{
		Params: p,
		Chain:  chain,
		Naive:  naive,
		seqs:   make(map[types.Address]uint64),
	}
	x.miner = x.key()
	x.payout = x.miner.Persistent()

	// Mine to play. Six matured coinbases rather than one: the catalogue funds
	// three cells out of the payout in a single block, and a payout holding one
	// matured coinbase makes that block's fate a function of the emission
	// schedule instead of of the shapes.
	if err := x.mine(int(p.CoinbaseMaturity) + 6); err != nil {
		return nil, err
	}
	return x, nil
}

// key returns the next deterministic key. The seed is a counter, so the same
// catalogue draws the same keys at every parameter set.
func (x *Perturbation) key() *wallet.Key {
	seed := make([]byte, 32)
	seed[0] = byte(x.nextKey)
	seed[1] = byte(x.nextKey >> 8)
	x.nextKey++
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}

// seq hands out the next sequence number for an address.
func (x *Perturbation) seq(addr types.Address) uint64 {
	x.seqs[addr]++
	return x.seqs[addr]
}

// ttl is the TTL every catalogue certificate carries: as far ahead as the
// parameter set allows, up to four blocks.
//
// The clamp is what makes the catalogue run at ttl_max = 2, the smallest value
// params.Validate accepts. It is not the horizon probe — Runner.probeTTLHorizon
// is — and it does not try to be: a shape whose TTL sat on B2's boundary would
// be a shape about B2 rather than about itself.
func (x *Perturbation) ttl() uint64 {
	span := x.Params.TTLMax
	if span > 4 {
		span = 4
	}
	return x.Chain.NextHeight() + span
}

// cert builds one signed certificate under this run's parameter set. A one-shot
// deposit cell refunds to the payout, because the cell it would otherwise
// refund into is the cell the certificate burns.
func (x *Perturbation) cert(k *wallet.Key, from types.Address, prog types.Program, seq uint64) (*types.Certificate, error) {
	refund := from
	if from[0] == crypto.AddrVersionOneShot {
		refund = x.payout
	}
	return (&wallet.Builder{
		Params:  x.Params,
		Program: prog,
		Seq:     seq,
		TTL:     x.ttl(),
		Deposit: wallet.SelfDeposit(from, refund),
		FeeBid:  perturbationBid(),
		Signers: []*wallet.Key{k},
	}).Build()
}

// mine advances the chain by n coinbase-only blocks, through both folds.
//
// They go through Differential like everything else — a run whose funding
// blocks were folded by one implementation would be comparing two states that
// had seen different histories — but they are not recorded as shapes: the
// catalogue's "empty" entry is the one that makes the claim about empty blocks.
func (x *Perturbation) mine(n int) error {
	for i := 0; i < n; i++ {
		if _, err := x.commit(nil); err != nil {
			return err
		}
	}
	return nil
}

// commit proposes a block, runs it through both folds, and advances the tip
// when both accepted it. It reports whether the block was accepted.
func (x *Perturbation) commit(cites []*types.Header, certs ...*types.Certificate) (bool, error) {
	block, err := x.Chain.ProposeWithCites(x.payout, cites, certs...)
	if err != nil {
		return false, err
	}
	accepted, err := Differential(x.Chain.State, x.Naive, block, x.Params)
	if err != nil {
		return false, err
	}
	if accepted {
		x.Chain.Headers = append(x.Chain.Headers, block.Header)
		x.Chain.Undos = append(x.Chain.Undos, nil)
	}
	return accepted, nil
}

// drive runs one catalogue entry and checks it against its declaration.
//
// The outcome census is taken on a CLONE, ahead of the fold that counts, and it
// is what arms this harness. Without it a shape whose deposit stopped covering
// would still hand both folds a block, both folds would still agree that every
// certificate was DROPPED, and the run would report the shape as driven — which
// is the exact erosion this harness exists to prevent, one level down.
func (x *Perturbation) drive(name string, w want, cites []*types.Header, certs ...*types.Certificate) error {
	block, err := x.Chain.ProposeWithCites(x.payout, cites, certs...)
	if err != nil {
		return fmt.Errorf("sim: shape %q could not be proposed at height %d: %w",
			name, x.Chain.NextHeight(), err)
	}

	s := Shape{Name: name, Height: block.Header.Height, Certs: len(block.Certs)}
	if res, err := fold.ApplyBlock(x.Chain.State.Clone(), block, x.Params); err == nil {
		for _, o := range res.Outcomes {
			switch o.Outcome {
			case fold.Applied:
				s.Applied++
			case fold.SkippedStale, fold.SkippedOverflow:
				s.Skipped++
			case fold.Dropped:
				s.Dropped++
			}
		}
	}

	accepted, err := Differential(x.Chain.State, x.Naive, block, x.Params)
	if err != nil {
		return err
	}
	s.Accepted = accepted
	if accepted {
		x.Chain.Headers = append(x.Chain.Headers, block.Header)
		x.Chain.Undos = append(x.Chain.Undos, nil)
	}
	x.Driven = append(x.Driven, s)

	if s.Accepted != w.accepted || s.Applied != w.applied ||
		s.Skipped != w.skipped || s.Dropped != w.dropped {
		return fmt.Errorf("sim: shape %q at height %d is not the shape it names: "+
			"accepted=%v applied=%d skipped=%d dropped=%d, want accepted=%v "+
			"applied=%d skipped=%d dropped=%d — both folds may still agree, but "+
			"they are agreeing about a different block",
			name, s.Height, s.Accepted, s.Applied, s.Skipped, s.Dropped,
			w.accepted, w.applied, w.skipped, w.dropped)
	}
	return nil
}

// absent records a catalogue entry that this parameter set cannot reach, with
// the reason. Nothing is ever dropped silently: the test reads these.
func (x *Perturbation) absent(name, why string) {
	x.Driven = append(x.Driven, Shape{Name: name, Absent: true, Why: why})
}

// PerturbationShapes names every entry of the catalogue, in order. It is what a
// test asserts the run covered, so a shape deleted from Run() fails a test
// rather than shrinking the population it quantifies over.
func PerturbationShapes() []string {
	return []string{
		"empty",
		"funding-three-cells",
		"single-transfer",
		"replay-same-bytes",
		"replay-different-signature",
		"self-conflict",
		"unfunded-drop",
		"asset-issue",
		"asset-mint",
		"retire-one-shot",
		"one-shot-burn-and-refund",
		"cited-sibling",
		"epoch-boundary",
	}
}

// Run drives the whole catalogue. Any divergence between the two folds, and any
// shape that failed to be the shape it names, is returned as an error.
func (x *Perturbation) Run() error {
	actorA, actorB := x.key(), x.key()
	addrA, addrB := actorA.Persistent(), actorB.Persistent()
	vaultKey := x.key()
	vault := vaultKey.OneShot()

	// 1. The empty block: a coinbase and nothing else. It is the shape every
	// chain spends most of its life in, and the one the maturity ring and the
	// emission schedule are read on.
	if err := x.drive("empty", want{accepted: true}, nil); err != nil {
		return err
	}

	// 2. Three certificates in one block, out of one deposit cell. It funds the
	// rest of the catalogue and it is itself a shape: the fold's per-certificate
	// ordering and the running deposit balance are only exercised by a block
	// carrying more than one.
	var funding []*types.Certificate
	for _, f := range []struct {
		to    types.Address
		drops uint64
	}{
		{addrA, 3_000_000_000},
		{addrB, 1_000_000_000},
		{vault, 1_000_000_000},
	} {
		c, err := x.cert(x.miner, x.payout,
			wallet.Tip(types.NativeAsset, x.payout, f.to, u256.FromUint64(f.drops)),
			x.seq(x.payout))
		if err != nil {
			return fmt.Errorf("sim: the funding certificate for %x did not build: %w", f.to[:4], err)
		}
		funding = append(funding, c)
	}
	if err := x.drive("funding-three-cells", want{accepted: true, applied: 3}, nil, funding...); err != nil {
		return err
	}

	// 3. The ordinary payment, and the certificate the two replay shapes below
	// re-present. It is held rather than rebuilt precisely because a replay is
	// about an authorization that already committed.
	payment, err := x.cert(actorA, addrA,
		wallet.Tip(types.NativeAsset, addrA, addrB, u256.FromUint64(100_000_000)),
		x.seq(addrA))
	if err != nil {
		return fmt.Errorf("sim: the payment certificate did not build: %w", err)
	}
	if err := x.drive("single-transfer", want{accepted: true, applied: 1}, nil, payment); err != nil {
		return err
	}

	// 4 and 5. The two replays, driven in the two blocks immediately after the
	// commit so that the seen-set entry is still live at every ttl_max the
	// catalogue runs at — including 2, where it expires two blocks later. Both
	// folds must refuse both blocks.
	//
	// The second replay carries the SAME authorization under a DIFFERENT valid
	// signature. B3 reads the seen set by certificate id and the id covers the
	// body rather than the witness, so this is a distinct shape from a replay of
	// identical bytes and not a repetition of it.
	if err := x.drive("replay-same-bytes", want{accepted: false}, nil, payment); err != nil {
		return err
	}
	variant, err := harness.ReSignCertificate(payment, x.Params, actorA.Seed(), 7)
	if err != nil {
		return fmt.Errorf("sim: the re-signed replay variant could not be built: %w", err)
	}
	if variant.ID() != payment.ID() {
		return fmt.Errorf("sim: re-signing moved the certificate id, so the replay shape " +
			"is no longer a replay")
	}
	if err := x.drive("replay-different-signature", want{accepted: false}, nil, variant); err != nil {
		return err
	}

	// 6. Two spends of nearly the same balance, signed by one key. The first
	// applies, the second is billed a skip — the only way a block's INCLUDED
	// gas exceeds its APPLIED gas, and a fold that confused the two would be
	// invisible to a catalogue where every certificate applied.
	var conflict []*types.Certificate
	for i := 0; i < 2; i++ {
		c, err := x.cert(actorA, addrA,
			wallet.Tip(types.NativeAsset, addrA, addrB, u256.FromUint64(2_000_000_000)),
			x.seq(addrA))
		if err != nil {
			return fmt.Errorf("sim: the self-conflict certificate did not build: %w", err)
		}
		conflict = append(conflict, c)
	}
	if err := x.drive("self-conflict", want{accepted: true, applied: 1, skipped: 1}, nil, conflict...); err != nil {
		return err
	}

	// 7. A certificate with valid bytes and no deposit behind them: DROPPED,
	// which is the one outcome that is not a billable event.
	broke := x.key()
	orphan, err := x.cert(broke, broke.Persistent(),
		wallet.Tip(types.NativeAsset, broke.Persistent(), addrB, u256.FromUint64(1_000)), 0)
	if err != nil {
		return fmt.Errorf("sim: the unfunded certificate did not build: %w", err)
	}
	if err := x.drive("unfunded-drop", want{accepted: true, dropped: 1}, nil, orphan); err != nil {
		return err
	}

	// 8, 9 and 10. The registry programs. ISSUE writes the asset's immutable
	// cells, MINT moves a non-native balance against a cap, and RETIRE burns an
	// address the program names rather than one the deposit implies.
	issueSeq := x.seq(addrA)
	var symbol types.Hash
	symbol[0] = 'P'
	assetCap := u256.FromUint64(1 << 40)
	issue, err := x.cert(actorA, addrA,
		wallet.Issue(addrA, assetCap, 0, symbol, actorA.PubKey()), issueSeq)
	if err != nil {
		return fmt.Errorf("sim: the issue certificate did not build: %w", err)
	}
	if err := x.drive("asset-issue", want{accepted: true, applied: 1}, nil, issue); err != nil {
		return err
	}
	asset := types.DeriveAssetAddress(x.Params.ChainID, addrA, issueSeq)

	mint, err := x.cert(actorA, addrA,
		wallet.Mint(asset, addrB, u256.FromUint64(4_096), assetCap, actorA.PubKey()),
		x.seq(addrA))
	if err != nil {
		return fmt.Errorf("sim: the mint certificate did not build: %w", err)
	}
	if err := x.drive("asset-mint", want{accepted: true, applied: 1}, nil, mint); err != nil {
		return err
	}

	retire, err := x.cert(actorA, addrA, wallet.Retire(actorA.OneShot()), x.seq(addrA))
	if err != nil {
		return fmt.Errorf("sim: the retire certificate did not build: %w", err)
	}
	if err := x.drive("retire-one-shot", want{accepted: true, applied: 1}, nil, retire); err != nil {
		return err
	}

	// 11. A certificate whose DEPOSIT CELL is a one-shot address: the burn comes
	// from the deposit rather than from the program, the remainder is refunded
	// to a cell the certificate does not burn, and F8b sweeps what the address
	// still holds. It is the class F-VAL-5 legalised, and the corpus shape the
	// removed test carried that nothing else here reaches.
	var vaultSymbol types.Hash
	vaultSymbol[0] = 'V'
	burn, err := x.cert(vaultKey, vault,
		wallet.Issue(vault, u256.FromUint64(1_000_000), 0, vaultSymbol, vaultKey.PubKey()), 0)
	if err != nil {
		return fmt.Errorf("sim: the one-shot burn certificate did not build: %w", err)
	}
	if err := x.drive("one-shot-burn-and-refund", want{accepted: true, applied: 1}, nil, burn); err != nil {
		return err
	}

	// 12. A block citing a competitor to its parent. Without it the citation
	// path is empty in both implementations, and two empty lists agree
	// trivially.
	sib := x.Chain.Sibling(x.key().Persistent())
	if sib == nil {
		return fmt.Errorf("sim: no sibling is constructible at height %d, so the "+
			"citation shape cannot be driven", x.Chain.Height())
	}
	if err := x.drive("cited-sibling", want{accepted: true}, []*types.Header{sib}); err != nil {
		return err
	}

	// 13. The epoch boundary: the one block whose header commits to a state
	// root, and therefore the one shape that folds the whole state through both
	// implementations rather than comparing their roots afterwards.
	//
	// It is reachable only where the next boundary is close enough that walking
	// to it is not the whole cost of the run. Where it is not, the entry is
	// recorded absent WITH ITS REASON rather than omitted: an arm that silently
	// covered twelve shapes while another covered thirteen would be the same
	// unstated-population problem this harness exists to fix.
	//
	// NEITHER SHIPPED SET TAKES THE ABSENT BRANCH, and that is stated rather
	// than left to be discovered: devnet's epoch is 64 blocks and mainnet's
	// 2880, so the walk is 39 and 2764 blocks and both fit. The 2764-block walk
	// is what makes a mainnet arm cost about 1.3 s against devnet's 0.05 s, and
	// it is the whole of that difference. The branch is here for a perturbation
	// that moves epoch_length, which is the axis this harness exists to allow —
	// so it is a guard that no arm currently trips, and a reader should not
	// mistake it for one that ever has.
	const boundaryWalkLimit = 4096
	distance := x.distanceToBoundary()
	if distance > boundaryWalkLimit {
		x.absent("epoch-boundary", fmt.Sprintf(
			"the next epoch boundary is %d blocks away at epoch_length %d, above this "+
				"harness's walk limit of %d", distance, x.Params.EpochLength, boundaryWalkLimit))
		return nil
	}
	if err := x.mine(distance - 1); err != nil {
		return err
	}
	boundaryPayment, err := x.cert(actorA, addrA,
		wallet.Tip(types.NativeAsset, addrA, addrB, u256.FromUint64(1_000_000)),
		x.seq(addrA))
	if err != nil {
		return fmt.Errorf("sim: the epoch-boundary certificate did not build: %w", err)
	}
	if !x.Params.IsEpochBoundary(x.Chain.NextHeight()) {
		return fmt.Errorf("sim: height %d is not an epoch boundary, so the boundary "+
			"shape would be an ordinary block", x.Chain.NextHeight())
	}
	return x.drive("epoch-boundary", want{accepted: true, applied: 1}, nil, boundaryPayment)
}

// distanceToBoundary is how many blocks must be added before one of them lands
// on an epoch boundary.
func (x *Perturbation) distanceToBoundary() int {
	for d := 1; d <= 1<<20; d++ {
		if x.Params.IsEpochBoundary(x.Chain.Height() + uint64(d)) {
			return d
		}
	}
	return 1 << 20
}
