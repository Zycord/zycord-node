// Command gen regenerates the golden vector corpus in spec/vectors.
//
// The vectors are generated rather than hand-written because a hand-written
// 800-byte SSZ block is a typo waiting to become a protocol. What makes them
// meaningful is not where the bytes came from but that they are committed,
// reviewed, and thereafter frozen: a regeneration that changes an existing
// vector is a consensus change, and it shows up as a diff in a pull request.
//
//	go run ./spec/gen            # rewrite spec/vectors
//	go test ./spec               # check the tree against them
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

const outDir = "spec/vectors"
const difficultyOutDir = "spec/vectors/difficulty"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(difficultyOutDir, 0o755); err != nil {
		return err
	}
	// Start from a clean directory so that a deleted scenario disappears from
	// the corpus instead of lingering as an orphan.
	if err := clean(outDir); err != nil {
		return err
	}
	if err := clean(difficultyOutDir); err != nil {
		return err
	}

	var vectors []*spec.Vector
	vectors = append(vectors, genesisVectors(spec.Mainnet(), spec.Devnet())...)
	vectors = append(vectors, foldVectors()...)
	vectors = append(vectors, blockRuleVectors()...)
	vectors = append(vectors, citeVectors()...)
	vectors = append(vectors, mainnetVectors()...)
	vectors = append(vectors, seedEpochVectors()...)
	vectors = append(vectors, authorizationVectors()...)
	// The testnet genesis is generated last rather than beside the other
	// two, because a vector's filename prefix is its position in this list and
	// nothing else: inserting it at index 2 would renumber all fifty-two
	// vectors above it and silently repoint every prose citation of them, which
	// is the rot spec/vector_refs_test.go was written after finding. A vector
	// added to a corpus that is already cited goes at the end.
	vectors = append(vectors, genesisVectors(spec.Testnet())...)
	// The V-rule separators go last for the same reason the testnet
	// genesis does: they are an addition to a corpus that is already cited by
	// number, so they take fresh indices rather than renumbering anything.
	vectors = append(vectors, vRuleVectors()...)
	// The four measured gaps — the spent-registry boundary, the asset
	// whitelist, the per-block signature ceiling and the mixed-order signer —
	// in that order and last, for the same reason: they are additions to a
	// corpus that is already cited by number, so they take fresh indices
	// rather than renumbering anything.
	vectors = append(vectors, spentRegistryBoundaryVector())
	vectors = append(vectors, assetWhitelistVector())
	// Index 061 was a B5 vector and is now a B18 one: the block is
	// the same and the rule that answers is not, because B18 is checked before
	// the loop that verifies a signature and the shape that reaches 4T carries
	// more signatures than the ceiling admits. Kept at its own index rather
	// than appended, because the block did not change — see sigCeilingVector.
	vectors = append(vectors, sigCeilingVector())
	vectors = append(vectors, mixedOrderSignerVector())
	// The coinbase burn and the burst-forfeiture rounding vector, appended for
	// the same reason again: the corpus is cited by number, so an addition
	// takes a fresh index and renumbers nothing.
	vectors = append(vectors, coinbaseBurnVector())
	vectors = append(vectors, burstForfeitureRoundingVector())

	for i, v := range vectors {
		name := fmt.Sprintf("%03d-%s.json", i, v.Name)
		if err := v.Write(filepath.Join(outDir, name)); err != nil {
			return err
		}
		fmt.Println("wrote", name)
	}

	// The difficulty vectors are a second, parallel corpus: a
	// (params, headers) -> next_target statement that spec/vector_test.go
	// replays by calling pow.NextTarget directly rather than by folding a
	// block, because fold.ApplyBlock never evaluates the difficulty rule at
	// all. They live in their own directory and their own numbering so that
	// the two corpora never interleave and a reviewer can tell at a glance
	// which replay path a diff belongs to.
	diffVectors := difficultyVectors()
	for i, v := range diffVectors {
		name := fmt.Sprintf("%03d-%s.json", i, v.Name)
		if err := v.Write(filepath.Join(difficultyOutDir, name)); err != nil {
			return err
		}
		fmt.Println("wrote", filepath.Join("difficulty", name))
	}
	return nil
}

// clean removes every *.json file directly inside dir, without descending
// into subdirectories — spec/vectors/difficulty is itself one such
// subdirectory of spec/vectors, and its own contents are cleaned separately
// by the caller so a run of this command never leaves an orphaned vector
// behind in either corpus.
func clean(dir string) error {
	existing, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	for _, f := range existing {
		if err := os.Remove(f); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scenario scaffolding
// ---------------------------------------------------------------------------

type scenario struct {
	p     *params.Params
	chain *harness.Chain
	miner *wallet.Key
	seq   uint64
}

func newScenario(p *params.Params) *scenario {
	c := harness.MustNew(p)
	s := &scenario{p: p, chain: c, miner: key(1)}
	if err := c.MineUntilFunded(s.payout()); err != nil {
		panic(err)
	}
	return s
}

func (s *scenario) payout() types.Address { return s.miner.Persistent() }

func key(n byte) *wallet.Key {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

// bid is the standard shape a wallet produces: maxima far above the base fees
// so the certificate survives its TTL window, and modest priorities that are
// what the miner is actually paid. The headroom is free (R2-H1).
func bid() types.FeeBid {
	return wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10))
}

func (s *scenario) build(b *wallet.Builder) *types.Certificate {
	c, err := b.Build()
	if err != nil {
		panic(err)
	}
	return c
}

func (s *scenario) transfer(k *wallet.Key, from, to types.Address, amount u256.U256, seq uint64) *types.Certificate {
	refund := from
	if from[0] == 0x01 {
		refund = k.Persistent()
	}
	return s.build(&wallet.Builder{
		Params:  s.p,
		Program: wallet.Tip(types.NativeAsset, from, to, amount),
		Seq:     seq,
		TTL:     s.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(from, refund),
		FeeBid:  bid(),
		Signers: []*wallet.Key{k},
	})
}

// buildUnchecked is wallet.Builder.Build without its closing validity.Check,
// and without signing: the caller supplies the Sigs. It exists for the vectors
// whose whole content is a certificate a wallet would refuse to emit — the V2
// vector directly, and buildUncheckedSigned below for the rest — and it
// reproduces the builder's derivation, placeholder sizing and deposit top-up
// so that everything except the rule under test is byte-for-byte what a wallet
// would have produced. Anything looser would make the vector fail for a
// second, uninteresting reason.
func buildUnchecked(p *params.Params, b *wallet.Builder, sigs []types.Sig) *types.Certificate {
	reads, writes, err := validity.DeriveCert(b.Program, p.ChainID, b.Seq, b.Deposit.Cell.Addr)
	if err != nil {
		panic(err)
	}
	c := &types.Certificate{
		ChainID: p.ChainID,
		Seq:     b.Seq,
		Program: b.Program,
		Reads:   reads,
		Writes:  writes,
		Deposit: b.Deposit,
		TTL:     b.TTL,
		FeeBid:  b.FeeBid,
		Sigs:    sigs,
	}
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		panic("fee bid overflows 256 bits")
	}
	if c.Deposit.Amount.Lt(ceiling) {
		c.Deposit.Amount = ceiling
	}
	return c
}

// buildUncheckedSigned is wallet.Builder.Build without its closing
// validity.Check: derive, size placeholder sigs, top the deposit up to the fee
// ceiling, sign. It exists for the vectors whose whole content is a
// certificate a wallet would refuse to emit, but whose signatures must still
// verify — otherwise the vector would fail for V2 rather than for the rule it
// is about.
func buildUncheckedSigned(p *params.Params, b *wallet.Builder) *types.Certificate {
	keys := sortedKeys(b.Signers)
	sigs := make([]types.Sig, len(keys))
	for i, k := range keys {
		sigs[i] = types.Sig{PubKey: k.PubKey()}
	}
	c := buildUnchecked(p, b, sigs)
	msg := c.SigningMessage(p)
	for i, k := range keys {
		c.Sigs[i] = types.Sig{PubKey: k.PubKey(), Sig: k.Sign(msg)}
	}
	return c
}

// buildUncheckedEdited is buildUncheckedSigned with one editing pass over the
// derived body, applied *before* the deposit is topped up and before anything
// is signed.
//
// The order is the whole point. A V-rule vector has to fail for its own rule
// and for nothing else, and both of the things that happen after the edit here
// would otherwise turn it into a vector about a different rule: an edit that
// changes the encoded length moves the fee ceiling, which V5 would then reject
// before the intended rule ran, and an edit to any authorizing field
// invalidates signatures made over the old body, which V2 would reject before
// that. Editing between derivation and those two steps is what leaves exactly
// one thing wrong with the certificate.
func buildUncheckedEdited(p *params.Params, b *wallet.Builder, edit func(*types.Certificate)) *types.Certificate {
	keys := sortedKeys(b.Signers)
	sigs := make([]types.Sig, len(keys))
	for i, k := range keys {
		sigs[i] = types.Sig{PubKey: k.PubKey()}
	}
	c := buildUnchecked(p, b, sigs)
	edit(c)
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		panic("gen: the edited certificate's fee bid overflows 256 bits")
	}
	if c.Deposit.Amount.Lt(ceiling) {
		c.Deposit.Amount = ceiling
	}
	msg := c.SigningMessage(p)
	for i, k := range keys {
		c.Sigs[i] = types.Sig{PubKey: k.PubKey(), Sig: k.Sign(msg)}
	}
	return c
}

// insertWrite places a write in the canonical position V1 requires, so that a
// vector about a declared write is not a vector about sort order.
func insertWrite(c *types.Certificate, w types.Write) {
	c.Writes = append(c.Writes, w)
	sort.Slice(c.Writes, func(i, j int) bool { return c.Writes[i].Slot.Less(c.Writes[j].Slot) })
}

// sortedKeys puts signers in canonical order (by public key, V1).
func sortedKeys(in []*wallet.Key) []*wallet.Key {
	out := append([]*wallet.Key(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].PubKey(), out[j].PubKey()
		for x := range a {
			if a[x] != b[x] {
				return a[x] < b[x]
			}
		}
		return false
	})
	return out
}

func (s *scenario) fund(to types.Address, amount u256.U256) {
	s.seq++
	s.chain.MustAddBlock(s.payout(), s.transfer(s.miner, s.payout(), to, amount, s.seq))
}

// capture folds a block against a copy of the current state and records the
// whole observable result as a vector.
func capture(name, description string, p *params.Params, pre *state.State, b *types.Block) *spec.Vector {
	work := pre.Clone()
	v := &spec.Vector{
		Name:        name,
		Description: description,
		Params:      paramName(p),
		Pre:         spec.Snapshot(pre),
		Block:       "0x" + hex.EncodeToString(b.MarshalSSZ()),
	}

	res, err := fold.ApplyBlock(work, b, p)
	if err != nil {
		// An invalid vector must name the rule that rejected the block, and
		// the fold is the only thing that can answer. An unnamed
		// rejection is a conservation assertion — arithmetic no rule set can
		// reach — and a corpus entry claiming to state a rule while actually
		// pinning a backstop is worse than no entry at all, so refuse to
		// write one rather than commit it and discover it under a mutation
		// sweep later.
		rule := fold.Rule(err)
		if rule == "" {
			panic(fmt.Sprintf("%s: the fold rejected the block without naming a rule (%v); "+
				"a vector may pin a rule, never an assertion", name, err))
		}
		v.Expect = spec.Expect{Valid: false, Rule: rule, Reason: err.Error(), Post: spec.Snapshot(work)}
		return v
	}

	v.Expect = spec.Expect{
		Valid:         true,
		SeqGasUsed:    res.SeqGasUsed,
		ParGasUsed:    res.ParGasUsed,
		SeqGasApplied: res.SeqGasApplied,
		ParGasApplied: res.ParGasApplied,
		Burned:        res.Burned.String(),
		MinerReward:   res.MinerReward.String(),
		Treasury:      res.Treasury.String(),
		Matured:       res.Matured.String(),
		Post:          spec.Snapshot(work),
	}
	if p.IsEpochBoundary(b.Header.Height) {
		v.Expect.PostRoot = "0x" + hex.EncodeToString(res.StateRoot[:])
	}
	for _, o := range res.Outcomes {
		e := spec.OutcomeEntry{
			ID:       "0x" + hex.EncodeToString(o.ID[:]),
			Outcome:  o.Outcome.String(),
			Charged:  o.Charged.String(),
			Refunded: o.Refunded.String(),
		}
		if !o.RefundBurned.IsZero() {
			e.RefundBurned = o.RefundBurned.String()
		}
		if !o.Swept.IsZero() {
			e.Swept = o.Swept.String()
		}
		if !o.SweptStranded.IsZero() {
			e.SweptStranded = o.SweptStranded.String()
		}
		e.StrandedCells = o.StrandedCells
		v.Expect.Outcomes = append(v.Expect.Outcomes, e)
	}
	return v
}

// paramName is the reverse of spec.ParamsFor: the name a vector records so a
// replay resolves the same embedded parameter set. Chain ids are what it keys
// on because they are what a mis-edited file cannot share (TestParamsAreValid
// pins that they are distinct).
func paramName(p *params.Params) string {
	for _, name := range spec.Networks() {
		known, err := spec.ParamsFor(name)
		if err != nil {
			panic(err)
		}
		if p.ChainID == known.ChainID {
			return name
		}
	}
	panic(fmt.Sprintf("gen: chain id %d is not an embedded parameter set", p.ChainID))
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

func genesisVectors(nets ...*params.Params) []*spec.Vector {
	var out []*spec.Vector
	for _, p := range nets {
		b, _, err := genesis.Build(p)
		if err != nil {
			panic(err)
		}
		out = append(out, capture(
			"genesis-"+paramName(p),
			"Block 0 folded against empty state: beacon and fee cells initialised, "+
				"no allocation to anybody, and the state root the launch announcement commits to.",
			p, state.New(), b,
		))
	}
	return out
}

func foldVectors() []*spec.Vector {
	p := spec.Devnet()
	var out []*spec.Vector

	{
		s := newScenario(p)
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		out = append(out, capture("empty-block",
			"A block with no certificates still pays emission into the maturity ring "+
				"and still moves both base fees.", p, s.chain.State, b))
	}

	{
		// The subsidy split, on its own, with nothing else moving. An
		// independent implementation that gets the ratio or the rounding wrong
		// fails here rather than inside a vector that is also testing five
		// other things.
		s := newScenario(p)
		if err := s.chain.Mine(s.payout(), 2); err != nil {
			panic(err)
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		out = append(out, capture("treasury-share",
			"The block subsidy is split before anyone is paid: the treasury takes "+
				"TREASURY_SHARE_BPS of it, floored, and the producer takes the exact "+
				"remainder, so the two always sum to the subsidy. The treasury's share "+
				"is credited straight to the protocol address's native balance cell and "+
				"never enters the maturity ring; the producer's does. Tips are not part "+
				"of the split — the share is taken from issuance and never from fees.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(1_000_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(250_000_000), 0)
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("transfer-applied",
			"The happy path: guards hold, writes land, the deposit is settled at actual "+
				"cost and the remainder is refunded within the same fold step.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(700_000_000))
		first := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(400_000_000), 0)
		second := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(400_000_000), 1)
		b, err := s.chain.Propose(s.payout(), first, second)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("transfer-skipped-stale",
			"Two spends of one balance, ordered by Seq. The first applies; the second "+
				"is skipped at the constant skip fee and marked seen. The block stays valid.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		pauper, bob := key(8), key(3)
		cert := s.transfer(pauper, pauper.Persistent(), bob.Persistent(), drops(1_000), 0)
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("certificate-dropped",
			"An unfundable deposit: nothing is reserved, so nothing is billed, no state "+
				"is touched, and the certificate is NOT marked seen — it stays resubmittable.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.OneShot(), drops(900_000_000))
		// Reserve above the ceiling on purpose, so the vector covers the refund
		// path. The ceiling is tight, so a certificate reserving exactly it owes
		// exactly it and refunds nothing.
		deposit := wallet.SelfDeposit(alice.OneShot(), alice.Persistent())
		deposit.Amount = drops(50_000_000)
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(), drops(500_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: deposit,
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("one-shot-burn-and-refund",
			"R1-C3: a one-shot address funds its own deposit and burns itself in the "+
				"same certificate. MARK_SPENT applies at F8; settlement at F9 is exempt "+
				"from the registry and lands in the nominated refund cell.",
			p, s.chain.State, b))
	}

	{
		// F-VAL-5: before this fix, a wallet holding funds solely under
		// a one-shot address had no satisfiable ISSUE (or MINT) certificate
		// at all. V6 unconditionally required the deposit cell's MARK_SPENT
		// whenever it was one-shot, but Derive never produced one outside
		// deriveTransfer's move sources — so a wallet that added the write
		// by hand, following V6's own error message, was then rejected by
		// V3 for declaring one write too many. The two rules were jointly
		// unsatisfiable for ISSUE, MINT, and any TRANSFER whose deposit cell
		// was not itself a move source.
		//
		// This is the certificate the fix makes buildable: the deposit cell
		// is one-shot and is not a move source (ISSUE has no moves at all).
		// Derivation now includes the deposit cell's own MARK_SPENT for
		// every program kind, so the certificate applies, and the deposit
		// address burns its authority exactly as a one-shot TRANSFER source
		// already did — the previous vector's case, generalised.
		s := newScenario(p)
		issuer := key(9)
		balance := drops(3_000_000_000)
		s.fund(issuer.OneShot(), balance)
		// SweepDeposit, not SelfDeposit: the certificate burns the deposit
		// address, so it must also empty it. Reserving only the fee ceiling
		// would leave the rest of the balance in a cell no key can open
		// again — an APPLIED certificate that destroys most of what the
		// address held. The reservation takes the lot; settlement charges the
		// actual fee and refunds the remainder to the persistent address.
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Issue(issuer.OneShot(), drops(1_000_000), 6, types.Hash{'O', 'N', 'E', 'S'}, issuer.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SweepDeposit(issuer.OneShot(), issuer.Persistent(), balance),
			FeeBid:  bid(),
			Signers: []*wallet.Key{issuer},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("one-shot-deposit-funds-issue",
			"F-VAL-5: an ISSUE whose deposit cell is one-shot and is not a move "+
				"source — ISSUE has no moves at all, so this is the case that "+
				"had no satisfiable certificate before the fix. DeriveCert "+
				"includes the deposit cell's own MARK_SPENT for every program "+
				"kind, so V3 and V6 are satisfiable together and the reference "+
				"wallet builds this certificate through its ordinary path. The "+
				"deposit sweeps the whole balance, because the certificate "+
				"burns the address: post-state shows the one-shot cell empty "+
				"and spent, with every drop it held either charged as fees or "+
				"refunded to the issuer's persistent address.",
			p, s.chain.State, b))
	}

	{
		// The F8b sweep, native half: the deposit reserves only the fee ceiling out
		// of a one-shot cell the certificate burns. Before F8b the difference
		// stayed under the burned address, on a certificate reporting APPLIED.
		s := newScenario(p)
		alice := key(2)
		s.fund(alice.OneShot(), drops(900_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Issue(alice.OneShot(), drops(1_000_000), 6, types.Hash{'O', 'N', 'E'}, alice.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.OneShot(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("one-shot-burn-returns-the-remainder",
			"A one-shot burn is address-scoped — MARK_SPENT names "+
				"SpentSlot(addr) and kills every cell under it — while every guard "+
				"Era 0 derives is slot-scoped and a lower bound, and the deposit cell "+
				"carries no read at all. F8b closes the gap as an EFFECT, not a "+
				"verdict: at commit, whatever a burned address still holds in a cell "+
				"the fold can name moves to Deposit.RefundTo.\n\n"+
				"Here the reservation takes only the fee ceiling out of a cell holding "+
				"900,000,000 drops. Post-state: the address is spent, its cell is gone, "+
				"and the whole balance less the fee is in the refund cell; the outcome "+
				"reports 813,735,000 as `swept`. An implementation missing this rule "+
				"reports the same APPLIED outcome and leaves those drops under an "+
				"address no key opens again — which is why the rule needs a vector "+
				"rather than a test of the verdict.\n\n"+
				"Refusing the burn instead would make the verdict a function of a "+
				"balance any stranger can raise with an unsigned credit, which is the "+
				"fourth case whitepaper §5 forbids.",
			p, s.chain.State, b))
	}

	{
		// The F8b sweep, named-cell half: a TRANSFER moves *part* of an asset
		// balance out of a one-shot address whose native cell the reservation
		// empties. The native clause is satisfied; only the "every cell this
		// certificate names" clause reaches the asset remainder.
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(4_000_000_000))
		capValue := drops(1_000_000)
		asset := types.DeriveAssetAddress(p.ChainID, alice.Persistent(), 0)
		s.chain.MustAddBlock(s.payout(), s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Issue(alice.Persistent(), capValue, 6, types.Hash{'A', 'S', 'T'}, alice.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}))
		s.chain.MustAddBlock(s.payout(), s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Mint(asset, alice.OneShot(), drops(500_000), capValue, alice.PubKey()),
			Seq:     1,
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}))
		s.fund(alice.OneShot(), drops(900_000_000))

		balance := s.chain.State.Get(types.NativeBalanceSlot(alice.OneShot()))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(asset, alice.OneShot(), bob.Persistent(), drops(100_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SweepDeposit(alice.OneShot(), alice.Persistent(), balance),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("one-shot-burn-returns-a-named-asset-remainder",
			"The second family of cell F8b covers: every cell under a burned "+
				"address that the certificate itself names, not only the native "+
				"balance cell. The asset moves partially — 100,000 of the 500,000 the "+
				"one-shot cell holds — and the reservation empties the native cell, so "+
				"a rule covering only native drops is satisfied and the remaining "+
				"400,000 of the asset would stay under the burn forever.\n\n"+
				"Post-state: the payee holds 100,000, the refund address holds the "+
				"other 400,000 at the same balance word, and nothing is left under the "+
				"spent address. The asset id is recoverable only from the "+
				"certificate's own writes — BalanceWord is blake3 of the asset id — "+
				"which is why the rule is stated over the cells a certificate names "+
				"and why an asset it does NOT name is out of reach and still lost.",
			p, s.chain.State, b))
	}

	{
		// The F8b sweep, the branch that moves nothing: the refund address was burned
		// by an EARLIER certificate (V5 rejects the same-certificate case), so
		// F8b leaves the residual exactly where the fold left it before this
		// rule existed. It is here because an earlier revision DESTROYED that
		// residual into the block's native burn accumulator, which broke the
		// conservation identity and — with an asset cap of 2^256-1 — made
		// every block carrying a stateless-valid certificate invalid.
		s := newScenario(p)
		alice, bob, dead := key(2), key(3), key(8)
		s.fund(alice.Persistent(), drops(3_000_000_000))
		asset := types.DeriveAssetAddress(p.ChainID, alice.Persistent(), 0)
		s.chain.MustAddBlock(s.payout(), s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Issue(alice.Persistent(), u256.Max, 0, types.Hash{'M', 'A', 'X'}, alice.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}))
		s.chain.MustAddBlock(s.payout(), s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Mint(asset, alice.OneShot(), u256.Max, u256.Max, alice.PubKey()),
			Seq:     1,
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}))
		s.chain.MustAddBlock(s.payout(), s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(dead.OneShot()),
			Seq:     2,
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice, dead},
		}))
		s.fund(alice.OneShot(), drops(900_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(asset, alice.OneShot(), bob.Persistent(), u256.One),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.OneShot(), dead.OneShot()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("one-shot-burn-strands-into-a-dead-refund-address",
			"F8b delivers a burned address's residual to Deposit.RefundTo, and "+
				"when that address's authority was burned by an EARLIER certificate it "+
				"delivers nothing and leaves the residual exactly where it was. The "+
				"outcome says so in `swept_stranded`, and `swept` is zero.\n\n"+
				"This is the corpus's only non-zero `swept_stranded`, and it pins two "+
				"rules at once. F8b must not DESTROY what it cannot deliver: an earlier "+
				"revision did, adding the amount to the block's native burn accumulator, "+
				"which falsified the native conservation identity whenever the residual "+
				"was an asset — and, because an asset cap is an arbitrary u256, "+
				"overflowed that accumulator into a block-invalidity error for a "+
				"certificate that passes V1-V9 and therefore relays. The one-shot cell "+
				"here holds 2^256-1 of an asset for exactly that reason: an "+
				"implementation that destroys instead of leaving cannot replay this "+
				"vector at all, because it rejects the block.\n\n"+
				"`refund_burned` is non-zero on the same outcome, because settlement is "+
				"burning this certificate's deposit remainder into the same dead "+
				"address (I1-M2) — which is how a consumer tells this case apart.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		issuer := key(5)
		s.fund(issuer.Persistent(), drops(3_000_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Issue(issuer.Persistent(), drops(1_000_000), 6, types.Hash{'C', 'A', 'P', 'Y'}, issuer.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{issuer},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("asset-issued",
			"ISSUE writes the four immutable metadata cells behind a single EXACT read "+
				"of the cap cell, which is the write-once lock.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		issuer, holder := key(5), key(6)
		s.fund(issuer.Persistent(), drops(3_000_000_000))
		capValue := drops(1_000)
		asset := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), 0)
		s.chain.MustAddBlock(s.payout(), s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Issue(issuer.Persistent(), capValue, 0, types.Hash{}, issuer.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{issuer},
		}))

		mint := func(seq uint64, amount u256.U256) *types.Certificate {
			return s.build(&wallet.Builder{
				Params:  p,
				Program: wallet.Mint(asset, holder.Persistent(), amount, capValue, issuer.PubKey()),
				Seq:     seq,
				TTL:     s.chain.NextHeight() + 5,
				Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
				FeeBid:  bid(),
				Signers: []*wallet.Key{issuer},
			})
		}
		b, err := s.chain.Propose(s.payout(), mint(1, drops(600)), mint(2, drops(600)))
		if err != nil {
			panic(err)
		}
		out = append(out, capture("mint-cap-race",
			"Two mints that each fit under the cap but together exceed it. The guarded "+
				"delta holds: the second skips, the cap is not breached, and only the "+
				"minter — who signed both — is billed.",
			p, s.chain.State, b))
	}

	{
		s := newScenario(p)
		alice := key(2)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(alice.OneShot()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("retire",
			"RETIRE burns signing authority without moving value: privacy hygiene and "+
				"state compaction, and a permanent registry entry.",
			p, s.chain.State, b))
	}

	{
		// R2-S1: the maturity ring at height 1, when every entry is still empty.
		s := newScenario(p)
		fresh := harness.MustNew(p)
		b, err := fresh.Propose(key(1).Persistent())
		if err != nil {
			panic(err)
		}
		_ = s
		out = append(out, capture("maturity-ring-bootstrap",
			"R2-S1: at height 1 the maturity ring entry for this index has never "+
				"been written, so the release step is a defined no-op — no credit to "+
				"the zero address, no phantom cell. The block's own reward is written "+
				"into the ring and becomes spendable COINBASE_MATURITY blocks later.",
			p, fresh.State, b))
	}

	{
		// R2-H2: a block of nothing but skips must move the base fees exactly as
		// an empty block would.
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(700_000_000))
		first := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(600_000_000), 0)
		second := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(600_000_000), 1)
		third := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(600_000_000), 2)
		// The first applies; everything after it skips against the drained
		// balance. Committing it leaves the rest as a pure skip block.
		s.chain.MustAddBlock(s.payout(), first)
		b, err := s.chain.Propose(s.payout(), second, third)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("skips-do-not-move-the-base-fee",
			"R2-H2: every certificate in this block is a billed skip, so the applied "+
				"gas is zero and both base fees fall exactly as they would after an "+
				"empty block.\n\n"+
				"Counting included gas instead of applied gas would hand a griefer a "+
				"constant-cost lever: stuff blocks with self-conflicting certificates "+
				"— self-inflicted, so the billing law is untouched — at SKIP_FEE each, "+
				"and price everyone else's certificates upward. Demand is what the "+
				"chain actually did, not what was attempted.",
			p, s.chain.State, b))
	}

	{
		// I1-C3: a deposit cell under an address whose authority has been
		// burned. The expected outcome DROPPED is the discriminator that makes
		// this vector worth having — see the description.
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.OneShot(), drops(2_000_000_000))
		burn := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.OneShot(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		s.chain.MustAddBlock(s.payout(), burn)

		again := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(), drops(1_000_000)),
			Seq:     1,
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.OneShot(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), again)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("deposit-from-burned-address-drops",
			"I1-C3: the deposit cell still holds a balance, but its address is in "+
				"the spent registry. The reservation must refuse it, so the outcome "+
				"is DROPPED and nothing is billed.\n\n"+
				"This vector is the pin on prune-dependence. An implementation whose "+
				"reservation ignored the registry would reserve successfully, then "+
				"fail at the MARK_SPENT of the already-burned address, and report "+
				"SKIPPED_STALE with the skip fee charged — a different outcome and a "+
				"different post-state. Since pruning may delete cell values under "+
				"spent addresses after the undo horizon, such an implementation would "+
				"also answer differently before and after it pruned: a consensus "+
				"split triggered by a storage schedule rather than by code. DROPPED "+
				"here is the only answer that is stable under pruning.",
			p, s.chain.State, b))
	}

	{
		// I1-M2: the refund target is an address a *previous*
		// certificate retired. No stateless rule can see this — V5 knows the
		// certificate's own write set and nothing about the registry — so the
		// remainder is destroyed at settlement, deterministically, and the
		// outcome record has to say so.
		s := newScenario(p)
		payer, stale, bob := key(12), key(13), key(3)
		s.fund(payer.Persistent(), drops(2_000_000_000))
		s.fund(stale.OneShot(), drops(100_000_000))

		// The payee retires the one-shot address it had published, after the
		// payer signed a certificate refunding into it. RETIRE is exactly the
		// §5 attribution theorem's third case, and this is its settlement-side
		// consequence.
		retire := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(stale.OneShot()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(payer.Persistent(), payer.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{payer, stale},
		})
		s.chain.MustAddBlock(s.payout(), retire)

		doomed := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, payer.Persistent(), bob.Persistent(), drops(1_000_000)),
			Seq:     1,
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(payer.Persistent(), stale.OneShot()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{payer},
		})
		b, err := s.chain.Propose(s.payout(), doomed)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("refund-into-a-previously-burned-address",
			"I1-M2: the certificate applies, the payment lands, and the deposit "+
				"remainder is burned rather than written into a cell whose "+
				"authority a previous certificate retired. Crediting it would be "+
				"a payment nobody could ever read, so the fold destroys it "+
				"deterministically (§6).\n\n"+
				"The discriminator is the outcome record, not the state: "+
				"refunded is 0 and refund_burned carries the whole remainder. "+
				"An implementation that reported the destroyed remainder as an "+
				"ordinary refund would produce an identical post-state and an "+
				"identical burn total, and every consumer downstream — a wallet "+
				"reconciling a balance, an explorer, an underwriter pricing its "+
				"exposure — would be told the money arrived somewhere. This is "+
				"the other half of the self-burn family: V5 and V6 close every burn a certificate "+
				"inflicts on itself, and this one, which no stateless rule can "+
				"see, is made visible instead.",
			p, s.chain.State, b))
	}

	{
		// I1-C1: two ISSUEs from one signer at one Seq derive one asset address.
		s := newScenario(p)
		issuer := key(5)
		s.fund(issuer.Persistent(), drops(5_000_000_000))
		issue := func(cap u256.U256, symbol byte) *types.Certificate {
			return s.build(&wallet.Builder{
				Params:  p,
				Program: wallet.Issue(issuer.Persistent(), cap, 0, types.Hash{symbol}, issuer.PubKey()),
				Seq:     7,
				TTL:     s.chain.NextHeight() + 5,
				Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
				FeeBid:  bid(),
				Signers: []*wallet.Key{issuer},
			})
		}
		b, err := s.chain.Propose(s.payout(), issue(drops(1_000), 'A'), issue(drops(2_000), 'B'))
		if err != nil {
			panic(err)
		}
		out = append(out, capture("issue-same-seq-collision",
			"I1-C1: the asset address is derived from (chain id, issuer, seq), so "+
				"two ISSUEs from one signer at one Seq name the same asset. The "+
				"write-once EXACT read of the cap cell resolves it: the first applies "+
				"and the second skips against the issuer's own earlier certificate. "+
				"Exactly one asset exists, and the billed skip is self-inflicted.",
			p, s.chain.State, b))
	}

	// The epoch controller of whitepaper §8.1, pinned as arithmetic.
	//
	// These seed the sample ring directly rather than filling it by mining,
	// because the applied gas a devnet block can hold is far below what moves
	// T: 2*median has to clear T - T/Delta before the controller does anything
	// but clamp, and no reachable devnet block gets close. The samples are
	// ordinary cells, so a pre-state may name them like any other — the vector
	// then states what the controller does with a given epoch, which is the
	// property a second implementation has to match. Without these, an
	// implementation using the upper median, swapping Gamma for Delta, or
	// ignoring the health gate passes the whole corpus.
	for _, tc := range []struct {
		name, desc string
		// sample fills every slot of the ring; lo/hi instead fill the first and
		// second halves, which is what makes the two median conventions differ.
		sample, lo, hi uint64
		cited          uint64
	}{
		{
			"epoch-controller-grows",
			"An epoch whose median applied sequential gas is high enough that " +
				"2*median clears the growth clamp: T rises by exactly T/Gamma, and no " +
				"further. The health gate passes, because nothing was cited.",
			p.SeqGasTargetGenesis, 0, 0, 0,
		},
		{
			"epoch-controller-growth-withheld-by-health-gate",
			"The same epoch, with enough cited competing headers to cross " +
				"health_gate_bps. Growth is withheld — T holds — while decay and the " +
				"genesis floor are untouched. This is the one branch of the controller " +
				"that whitepaper §8.1's health signal exists to reach.",
			p.SeqGasTargetGenesis, 0, 0, p.HealthGateBps*p.EpochLength/10000 + 1,
		},
		{
			"epoch-controller-floor-holds-against-decay",
			"An idle epoch at the genesis floor: 2*median is far below T - T/Delta, " +
				"so the decay clamp binds and the floor then overrides it. T comes out " +
				"exactly at its genesis value, never below.",
			0, 0, 0, 0,
		},
		{
			"epoch-controller-uses-the-lower-median",
			"Half the epoch idle and half of it busy, so the sorted sample ring has " +
				"different values either side of its midpoint. The LOWER median is the " +
				"convention: samples[(L-1)/2], the idle half, so 2*median falls under " +
				"the decay clamp and T holds at its floor. An implementation taking the " +
				"upper median reads the busy half instead, clears the growth clamp, and " +
				"comes out at T + T/Gamma — a different ceiling, from the same epoch. " +
				"Every other vector seeds one value everywhere, which leaves the two " +
				"conventions indistinguishable; this is the one that separates them.",
			0, 0, p.SeqGasTargetGenesis, 0,
		},
	} {
		s := newScenario(p)
		for s.chain.NextHeight()%p.EpochLength != 0 {
			s.chain.MustAddBlock(s.payout())
		}
		// Seed the epoch that is about to be read. The ring holds exactly the
		// heights the boundary block will measure.
		for i := uint64(0); i < p.EpochLength; i++ {
			v := tc.sample
			if tc.hi != 0 {
				// First half low, second half high: sorted, the midpoint lands
				// between them, so samples[(L-1)/2] and samples[L/2] differ.
				v = tc.lo
				if i >= p.EpochLength/2 {
					v = tc.hi
				}
			}
			if v != 0 {
				s.chain.State.Set(types.AppliedGasSampleSlot(i), u256.FromUint64(v))
			}
		}
		if tc.cited != 0 {
			s.chain.State.Set(types.CitedCountSlot(), u256.FromUint64(tc.cited))
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		out = append(out, capture(tc.name, tc.desc, p, s.chain.State, b))
	}

	{
		// Walk to the block before an epoch boundary, then capture the boundary
		// block: the beacon refresh and the state root in one vector.
		s := newScenario(p)
		for s.chain.NextHeight()%p.EpochLength != 0 {
			s.chain.MustAddBlock(s.payout())
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		out = append(out, capture("epoch-boundary",
			"An epoch-boundary block refreshes the three beacon cells and commits a "+
				"state root over the cells and the spent registry.",
			p, s.chain.State, b))
	}

	return out
}

func blockRuleVectors() []*spec.Vector {
	p := spec.Devnet()
	var out []*spec.Vector

	// B3 — replay of an applied certificate.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
		s.chain.MustAddBlock(s.payout(), cert)

		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-replay",
			"R1-C1: re-including an already committed certificate would bill one "+
				"signature twice. Including a seen id makes the block invalid.",
			p, s.chain.State, b))
	}

	// B1 — expired inclusion.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
		if err := s.chain.Mine(s.payout(), 8); err != nil {
			panic(err)
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-expired",
			"R1-C1: a miner withholds a certificate past its TTL and then includes it "+
				"to burn the skip fee. Expired certificates are unincludable.",
			p, s.chain.State, b))
	}

	// B2 — TTL beyond the bound.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
			TTL:     ^uint64(0),
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-ttl-unbounded",
			"R1-H4: an immortal TTL would make its seen-set entry permanent state. "+
				"The bound is consensus, not relay policy.",
			p, s.chain.State, b))
	}

	// B4 — bid below the base fee.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			// A maximum one below the sequential base fee: B4 makes it
			// unincludable however large its priority.
			FeeBid: wallet.Bid(
				s.chain.State.Get(types.SeqBaseFeeSlot()).SatSub(u256.One), u256.Zero,
				drops(500), drops(10)),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-cap-below-base",
			"R1-H3: fee-market drift may strand a signed certificate, but it may never "+
				"bill one. An unpayable certificate is unincludable.",
			p, s.chain.State, b))
	}

	// F-FOLD-1 — the exploit scenario the finding describes: a certificate
	// whose RefundTo names an address it burns itself, dodging the old V5
	// clause because the *deposit cell* is a different, persistent address.
	{
		// A wallet holds hot balance in H (persistent) and has received a
		// payment into one-shot address A. It builds one certificate paying
		// the deposit from H and sweeping A, refunding the change back into
		// A — the obvious thing to write, and what the architecture spec's
		// old Deposit.RefundTo comment reads as an assurance is safe.
		//
		// Before V5 was widened, this certificate was valid: V5 only ever compared
		// RefundTo against Deposit.Cell, and Cell here is H, not A, so the
		// clause never fired. It applied, F8 committed A's MARK_SPENT, and
		// F9's settle saw A already spent and silently burned the whole
		// remainder — reported as an ordinary refund. V5 now rejects any
		// RefundTo naming an address this certificate's own write set marks
		// spent, so the block carrying it is invalid and nothing ever
		// reaches the fold to burn.
		s := newScenario(p)
		hot, a, bob := key(10), key(11), key(3)
		s.fund(hot.Persistent(), drops(900_000_000))
		s.fund(a.OneShot(), drops(2_000_000_000))
		prog := wallet.Tip(types.NativeAsset, a.OneShot(), bob.Persistent(), drops(1_000_000))
		cert := buildUncheckedSigned(p, &wallet.Builder{
			Params:  p,
			Program: prog,
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(hot.Persistent(), a.OneShot()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{hot, a},
		})
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-refund-into-own-mark-spent",
			"F-FOLD-1: Deposit.Cell (H) is persistent, so the old V5 clause — which "+
				"compared RefundTo only against Cell, and only when Cell itself "+
				"was one-shot — could never have caught this. RefundTo names A, "+
				"the TRANSFER's one-shot source, which this same certificate "+
				"marks spent. V5 now rejects any RefundTo naming an address the "+
				"certificate's own write set marks spent, so the block is "+
				"invalid before the fold ever runs.",
			p, s.chain.State, b))
	}

	// Same certificate twice in one block.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), 0)
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert, cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-duplicate-in-block",
			"The same-block variant of replay, which the seen set alone would only "+
				"catch on the second pass.",
			p, s.chain.State, b))
	}

	// V2 — a low-order signer key: the identity-point forgery, as a block.
	//
	// This is the vector the strictness rules of core/crypto.VerifyStrict exist
	// to make binding, and it is the only one in the corpus that a *naively
	// correct* implementation fails. Everything else here is rejected by anyone
	// who reads the spec; this is rejected only by an implementation that
	// checks the order of the public key, which RFC 8032 does not require and
	// which several popular libraries do not do. An implementation that reaches
	// for a bare `ed25519.Verify` accepts this block, and accepting it means
	// accepting a spend from an address whose private key nobody holds.
	//
	// The construction takes no secret. Under A = the identity point the
	// verification equation collapses from [S]B = R + [h]A to [S]B = R, so any
	// (R, S) with that property is a valid signature over *every* message: S = 1
	// with R = the base point is the smallest one. The address is
	// AddressFromPubKey(0x02, A), which anyone can derive, and V4 is satisfied
	// because V4 checks that the declared bytes hash to the declared address —
	// which they do. Only V2 stands between this and an applied transfer.
	{
		s := newScenario(p)

		var identityPub types.PubKey
		identityPub[0] = 0x01
		identityAddr := crypto.AddressFromPubKey(crypto.AddrVersionPersistent, identityPub)

		s.fund(identityAddr, drops(900_000_000))

		// R = the base point, S = 1. [1]B = B = R, for every message.
		basePoint, err := hex.DecodeString(
			"5866666666666666666666666666666666666666666666666666666666666666")
		if err != nil {
			panic(err)
		}
		var forged types.SigBytes
		copy(forged[:32], basePoint)
		forged[32] = 0x01 // S = 1, little-endian

		bob := key(3)
		cert := buildUnchecked(p, &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, identityAddr, bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(identityAddr, identityAddr),
			FeeBid:  bid(),
		}, []types.Sig{{PubKey: identityPub, Sig: forged}})

		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-low-order-signer",
			"V2: the public key is the identity point, under which the verification "+
				"equation collapses to [S]B = R and every well-formed signature verifies. "+
				"Nobody holds a private key for this address. An implementation that "+
				"delegates to a bare ed25519.Verify accepts this block; rejecting it is "+
				"what makes 'one signature, one signer' true.",
			p, s.chain.State, b))
	}

	// Certificate root that does not commit to the bodies.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), 0)
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		b.Header.CertRoot[0] ^= 0xff
		out = append(out, capture("invalid-cert-root",
			"Hash-first relay rests on the header committing to the bodies. A header "+
				"that does not is not a header for this block.",
			p, s.chain.State, b))
	}

	out = append(out, certCeilingVector(p))

	return out
}

// ---------------------------------------------------------------------------
// Whitepaper §8.1: cited competing headers, the health signal.
// ---------------------------------------------------------------------------

// certCeilingVector builds the certificate-count ceiling vector (B12) at the
// parameter set it is given.
//
// The ceiling is not a constant. It is
//
//	MaxCertsPerBlock(T) = max_certs_per_block_genesis * T / seq_gas_target_genesis
//
// read from the pre-state cell at every height past 0 (core/fold's
// currentSeqGasTarget), so a vector that observes the rule does not need
// ceiling+1 certificates at the GENESIS ceiling — it needs them at whatever T
// the pre-state declares. That is what keeps this vector readable: at
// T = T0/64 the devnet ceiling is 4, against the 256 a genesis-T vector would
// have to carry, and it is why the corpus can cover this rule at both
// parameter sets rather than at neither. (The mainnet half seeds a different
// T — see mainnetCertCeilingVector, which explains why it cannot simply reuse
// this one's divisor.)
//
// Seeding T low is sound rather than convenient — 019 already declares
// pre-state cells directly — but it does put the vector off-manifold: T is
// floored at seq_gas_target_genesis on a live chain, so no real devnet
// reaches T0/64. The corpus already accepts that kind of state (no vector's
// block carries a solved nonce), and the alternative is leaving a consensus
// rule with no vector at all.
//
// The byte ceiling scales from the same T and must not bind first, or the
// vector would pin the wrong rule while appearing to pin this one. The
// assertion below is what keeps that honest across any future parameter
// change, and it is not hypothetical: it is what caught the mainnet half being
// built from a certificate shape too large to fit under mainnet's byte
// ceiling, at every T.
//
// WHY THE TWO PARAMETER SETS NEED DIFFERENT CERTIFICATE SHAPES.
//
// Both ceilings scale linearly from the same T, so to a first approximation
// their ratio — the bytes each parameter set allows per certificate — does not
// move with T:
//
//	devnet   2500000/256  = 9765.6 B/cert
//	mainnet  2500000/4000 =  625.0 B/cert
//
// (Only to a first approximation: both MaxCertsPerBlock and BlockByteLimit
// floor, so the realised budget is exactly 625 B/cert only where T0 divides
// evenly and drifts upward at small T — 630 at T0/64, 651 at T0/256, 814 at
// T0/1024. The drift is always in a vector's favour, and mainnetCertCeilingVector
// documents where it stops being enough. The approximation is also generous in
// the other direction, measured and stated here because it does not change any choice
// below: a block spends 236 bytes on itself and four more per certificate, so at
// genesis the budget for a certificate *body* is (2500000-236)/4000 - 4 = 620.9 B
// rather than 625. Both shapes below stay on the side of it they were picked for.)
//
// Lowering T therefore buys a smaller vector but never a materially looser byte
// budget, and mainnet's budget is tight enough that the certificate's shape
// decides whether the count rule is reachable at all. Measured against
// core/types' encoding:
//
//	TRANSFER, one move   1 read, 2 writes   848 B   over mainnet's budget
//	RETIRE, one address  0 reads, 1 write   558 B   under it
//
// So this vector uses a TRANSFER at devnet, which clears 9765 B/cert with room
// to spare and is the network's representative verb, and a RETIRE at mainnet,
// which is the shape that fits. Both are certificates wallet.Builder emits;
// neither is hand-rolled. mainnetCertCeilingVector carries the mainnet half.
func certCeilingVector(p *params.Params) *spec.Vector {
	s := newScenario(p)
	lowT := p.SeqGasTargetGenesis / 64
	ceiling := p.MaxCertsPerBlock(lowT)

	alice, bob := key(2), key(3)
	s.fund(alice.Persistent(), drops(900_000_000))

	// ceiling+1 distinct certificates: one signer, consecutive seqs, so none
	// is a duplicate of another and each is independently valid. The block is
	// rejected for its count alone.
	certs := make([]*types.Certificate, 0, ceiling+1)
	for i := 0; i <= ceiling; i++ {
		certs = append(certs, s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000), uint64(i)))
	}
	b, err := s.chain.Propose(s.payout(), certs...)
	if err != nil {
		panic(err)
	}
	if size, limit := b.SizeBytes(), p.BlockByteLimit(lowT); size > limit {
		panic(fmt.Sprintf("cert-ceiling vector: block of %d bytes exceeds the byte ceiling of %d at T=%d, "+
			"so the byte rule would reject before the count rule and the vector would be vacuous", size, limit, lowT))
	}
	// Seed T after Propose: the proposer builds against the live ceiling and
	// would refuse to emit an oversized block itself (node/miner's own
	// MaxCertsPerBlock call). The vector states what the FOLD does with a
	// block that already exists — the half a peer cannot opt out of.
	s.chain.State.Set(types.SeqGasTargetSlot(), u256.FromUint64(lowT))

	return capture("invalid-cert-count-over-ceiling",
		fmt.Sprintf("A block carrying ceiling+1 certificates at the sequential target the "+
			"pre-state declares. T is seeded to %d, one sixty-fourth of T0, which puts "+
			"the certificate ceiling at %d (%d certificates are present) and the byte "+
			"ceiling at %d against a block of %d bytes, so the count rule is the one "+
			"that rejects. The ceiling moves with T (whitepaper §8.1): an implementation "+
			"that hardcodes max_certs_per_block_genesis accepts this block and forks.",
			lowT, ceiling, ceiling+1, p.BlockByteLimit(lowT), b.SizeBytes()),
		p, s.chain.State, b)
}

// mainnetCertCeilingVector is certCeilingVector's mainnet half.
//
// It is a separate function rather than a second call because mainnet needs a
// different certificate shape and a different T, and both choices are forced
// by one number: mainnet allows 2500000/4000 = 625 B per certificate against
// devnet's 9765, and that ratio does not move with T. See certCeilingVector's
// comment for the measurements. A RETIRE certificate (0 reads, 1 write, 558 B)
// fits under 625; the TRANSFER the devnet vector uses (848 B) does not, at any
// T. RETIRE is not a contrivance for this vector — it is whitepaper §4's state
// compaction verb, and a block of them retiring distinct one-shot addresses is
// the shape the network emits when wallets tidy up.
//
// T is seeded to T0/256 rather than T0/64 to keep the vector readable: the
// ceiling falls to 15, so the block carries 16 certificates instead of 63, and
// the corpus's value depends on a human being able to read its diffs
// (spec/README.md). What the choice does not buy is much slack, and the shape
// of what it does buy is worth stating, because it is not monotone. Measuring
// the ceiling+1 retire block against the byte ceiling across T:
//
//	T0/2     ceiling 2000   89.98%
//	T0/32    ceiling  125   90.94%
//	T0/64    ceiling   62   91.24%
//	T0/256   ceiling   15   94.50%   <- this vector
//	T0/320   ceiling   12   96.54%
//	T0/333   ceiling   12  100.47%   does not fit
//	T0/1024  ceiling    3  101.76%   does not fit
//
// Utilisation is ~90% asymptotically, not the flat ~95% a pure ratio argument
// predicts, and it climbs as T falls for two reasons a ratio misses: the block
// is exactly 562n + 236 bytes for n certificates (558 B of certificate plus a
// 4 B SSZ offset, over a 236 B constant), so the fixed part matters more as n
// shrinks, and the +1 certificate is a larger share of a small ceiling.
//
// Neither column moves with seq_gas_target_genesis, which is why the table
// survived the gas-schedule respin unchanged: at T = T0/D the ceiling is
// floor(max_certs_per_block_genesis/D) and the byte limit is
// floor(block_byte_limit_genesis/D), and T0 cancels out of both.
//
// Where that leaves the lower edge of the band is worth stating exactly,
// because it is ragged rather than sharp. A ceiling of c admits every T in
// [400c, 400c+399], and the block must clear floor(1.5625T):
//
//	c >= 13       fits at every T in the bucket — 13 is the threshold, with
//	              21 B of slack at the worst T in it
//	3 <= c <= 12  fits only in the upper part of the bucket: ceiling 12 fits
//	              at T0/320 and does not at T0/333
//	c <= 2        never fits
//
// So a divisor has to be checked rather than assumed.
//
// The assertions below are therefore load-bearing rather than decorative: a
// parameter change that moves either ceiling, or a divisor picked outside the
// band, must fail the build loudly rather than emit a vector that silently
// tests the wrong rule.
func mainnetCertCeilingVector() *spec.Vector {
	p := spec.Mainnet()
	s := newScenario(p)
	lowT := p.SeqGasTargetGenesis / 256
	ceiling := p.MaxCertsPerBlock(lowT)

	// One key per certificate, each retiring its own one-shot address, so
	// every certificate in the block is independently valid and would apply
	// on its own. Nothing about the block is wrong except that it holds one
	// certificate too many.
	//
	// Every key is funded before any certificate is built: s.fund mines a
	// block per call, so a TTL taken inside the loop would have expired for
	// the earliest certificates by the time the block is proposed sixteen
	// heights later, and the block would be rejected for the TTL rule instead
	// of the count rule.
	// key() takes a byte, and the miner holds key(1), so the seeds available
	// for signers are finite. Refuse to run off the end rather than wrap into
	// a collision: a wrapped seed would silently give two certificates the
	// same signer, or hand a signer the miner's own address, and the vector
	// would fail for a reason that has nothing to do with the ceiling.
	if ceiling+1 > 245 {
		panic(fmt.Sprintf("mainnet cert-ceiling vector: a ceiling of %d needs %d distinct signer seeds, "+
			"more than key() can supply without colliding with the miner's; raise the divisor", ceiling, ceiling+1))
	}
	keys := make([]*wallet.Key, 0, ceiling+1)
	for i := 0; i <= ceiling; i++ {
		k := key(byte(10 + i))
		keys = append(keys, k)
		s.fund(k.Persistent(), drops(900_000_000))
	}
	ttl := s.chain.NextHeight() + 5
	certs := make([]*types.Certificate, 0, len(keys))
	for _, k := range keys {
		certs = append(certs, s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(k.OneShot()),
			TTL:     ttl,
			Deposit: wallet.SelfDeposit(k.Persistent(), k.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{k},
		}))
	}
	b, err := s.chain.Propose(s.payout(), certs...)
	if err != nil {
		panic(err)
	}
	if size, limit := b.SizeBytes(), p.BlockByteLimit(lowT); size > limit {
		panic(fmt.Sprintf("mainnet cert-ceiling vector: block of %d bytes exceeds the byte ceiling of %d at T=%d, "+
			"so the byte rule would reject before the count rule and the vector would be vacuous", size, limit, lowT))
	}
	// The byte ceiling is not the only ceiling that scales with T and could
	// bind before the count rule. Sequential gas does too, and the gas-schedule
	// respin moved where it sits: this assertion used to be against the 2T soft threshold,
	// and at seq_gas_target_genesis = 1,600,000 no T satisfies it.
	//
	// The reason is exact rather than a matter of margin. The count ceiling
	// admits floor(T x max_certs_per_block_genesis / T0) certificates, which
	// at the genesis values is floor(T/400), and the cheapest certificate the
	// Era-0 program set admits costs 800 sequential gas. So a block filled to
	// the count ceiling with floor certificates declares 800*floor(T/400) <= 2T
	// — AT the soft threshold, exactly, whenever T is a multiple of 400 — and
	// the ceiling+1 block this vector is built from is 800 gas above it at
	// every T. Under the superseded T0 = 2,000,000 the same block declared
	// 1.6T and the old assertion had a fifth of headroom.
	//
	// That is a fact about the parameters and not about this vector, so the
	// assertion moves to the bound that would actually change the vector's
	// answer: 4T, where B5 rather than B12 becomes the rejecting rule. The
	// vector's own Expect.Rule pins B12, so a flip is caught twice.
	var seqGas uint64
	for _, c := range b.Certs {
		seqGas += c.SeqGas(p)
	}
	if burst := p.SeqGasBurst(lowT); seqGas > burst {
		panic(fmt.Sprintf("mainnet cert-ceiling vector: block declares %d sequential gas against the "+
			"4T burst bound of %d at T=%d, so B5 rejects it before the count rule and the vector "+
			"pins the wrong rule", seqGas, burst, lowT))
	}
	// Seed T after Propose, for the reason certCeilingVector gives.
	s.chain.State.Set(types.SeqGasTargetSlot(), u256.FromUint64(lowT))

	return capture("mainnet-invalid-cert-count-over-ceiling",
		fmt.Sprintf("The certificate-count ceiling at mainnet's parameters, where "+
			"max_certs_per_block_genesis is 4000 rather than devnet's 256. T is seeded "+
			"to %d, one two-hundred-and-fifty-sixth of T0, putting the certificate "+
			"ceiling at %d against the %d certificates present. Every certificate is a "+
			"RETIRE, not a TRANSFER: mainnet allows roughly 2500000/4000 = 625 bytes per "+
			"certificate — a budget that barely moves with T, since both ceilings scale "+
			"from it — and a one-move TRANSFER is 848 bytes, so a transfer-shaped block "+
			"would be rejected by the byte rule first and pin nothing. This block is %d "+
			"bytes against a byte ceiling of %d, so the count rule is the one that "+
			"rejects. The pair with the devnet vector is the point: an implementation "+
			"that hardcodes either set's max_certs_per_block_genesis, or that fails to "+
			"scale it by T, forks on one of the two.",
			lowT, ceiling, ceiling+1, b.SizeBytes(), p.BlockByteLimit(lowT)),
		p, s.chain.State, b)
}

// siblingSet builds a fresh chain and n structurally distinct blocks all
// extending genesis — competing proposals a real network would produce when
// more than one proposer wins the same height. They differ only in
// EmissionAddr, which is enough to make each a different header. The first is
// applied and becomes the canonical parent of every citing block these
// vectors build; the rest are returned unapplied, exactly the shape a
// citation names.
func siblingSet(p *params.Params, n int) (*harness.Chain, *types.Block, []*types.Block) {
	c := harness.MustNew(p)
	blocks := make([]*types.Block, n)
	for i := 0; i < n; i++ {
		b, err := c.Propose(key(byte(1 + i)).Persistent())
		if err != nil {
			panic(err)
		}
		blocks[i] = b
	}
	if _, err := c.Apply(blocks[0]); err != nil {
		panic(err)
	}
	return c, blocks[0], blocks[1:]
}

// citeBlock builds the next block on c's tip, citing the given headers. It
// mirrors harness.Chain.Propose, which takes no Cites parameter.
func citeBlock(p *params.Params, c *harness.Chain, cites []*types.Header) *types.Block {
	tip := c.Tip()
	b := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + p.TargetBlockSeconds,
			EmissionAddr: key(200).Persistent(),
			Target:       tip.Target,
			PoW:          types.PoWSeal{SeedEpoch: pow.SeedEpochFor(tip.Height+1, p)},
		},
		Cites: cites,
	}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	b.Header.CitesRoot = b.ComputeCitesRoot(p)
	return b
}

func citeVectors() []*spec.Vector {
	p := spec.Devnet()
	var out []*spec.Vector

	// A genuine citation: a real sibling of the parent, sharing the parent's
	// own parent and difficulty target. Applies normally.
	{
		c, _, siblings := siblingSet(p, 2)
		b := citeBlock(p, c, []*types.Header{&siblings[0].Header})
		out = append(out, capture("cites-valid",
			"Whitepaper §8.1: a citation of a genuine sibling of the parent — sharing "+
				"the grandparent and the difficulty target a sibling must share — is "+
				"accepted and counted toward the epoch's health signal.",
			p, c.State, b))
	}

	// Rule 1: wrong height.
	{
		c, _, siblings := siblingSet(p, 2)
		bad := siblings[0].Header
		bad.Height++
		b := citeBlock(p, c, []*types.Header{&bad})
		out = append(out, capture("cites-invalid-height",
			"A citation must name a header at exactly the parent's height — the one "+
				"block a proposer can have seen a real competitor for. This one claims "+
				"one height further.",
			p, c.State, b))
	}

	// Rule 0: a header version that could never have been a block.
	{
		c, _, siblings := siblingSet(p, 2)
		bad := siblings[0].Header
		bad.Version = types.HeaderVersion + 1
		b := citeBlock(p, c, []*types.Header{&bad})
		out = append(out, capture("cites-invalid-version",
			"A citation must be something that could have been a block. An unknown "+
				"header version never could, so counting one toward the health signal "+
				"would let the signal measure things that are not competitors at all. "+
				"The work is checked in full either way, so this buys an attacker no "+
				"discount — it keeps the fork-rate estimate an estimate of the fork rate.",
			p, c.State, b))
	}

	// Rule 2: wrong parent (does not share the grandparent).
	{
		c, _, siblings := siblingSet(p, 2)
		bad := siblings[0].Header
		bad.ParentID[0] ^= 0xff
		b := citeBlock(p, c, []*types.Header{&bad})
		out = append(out, capture("cites-invalid-grandparent",
			"A citation must share this block's grandparent — the same parent its own "+
				"parent has. This one claims a different one, so it is not a sibling of "+
				"anything this chain can see.",
			p, c.State, b))
	}

	// Rule 3: citing the block's own parent as though it were a competitor.
	{
		c, canonical, _ := siblingSet(p, 2)
		b := citeBlock(p, c, []*types.Header{&canonical.Header})
		out = append(out, capture("cites-invalid-self-citation",
			"A citation naming this block's own parent is not describing a "+
				"competitor at all — the fold rejects a certificate offered as its own "+
				"rebuttal for the same reason.",
			p, c.State, b))
	}

	// Rule 4: wrong target.
	{
		c, _, siblings := siblingSet(p, 2)
		bad := siblings[0].Header
		bad.Target = bad.Target.SatAdd(u256.One)
		b := citeBlock(p, c, []*types.Header{&bad})
		out = append(out, capture("cites-invalid-target",
			"A citation must declare the exact difficulty target this height was "+
				"mined under — a sibling of the parent was subject to the same LWMA "+
				"window the real parent was. A different target is a fabrication, not "+
				"merely stale data.",
			p, c.State, b))
	}

	// Rule 5: not strictly sorted (the same header cited twice).
	{
		c, _, siblings := siblingSet(p, 2)
		b := citeBlock(p, c, []*types.Header{&siblings[0].Header, &siblings[0].Header})
		out = append(out, capture("cites-invalid-unsorted",
			"Citations must be strictly increasing by id, the same discipline every "+
				"other list in this protocol already follows (R2-M2). Citing one header "+
				"twice is the clearest violation: two equal ids are not strictly "+
				"increasing.",
			p, c.State, b))
	}

	// Over the per-block citation ceiling is deliberately not a golden vector
	// here: the block's own bytes can never express it. ComputeCitesRoot
	// merkleises against MaxCitesPerBlock and panics on more chunks than its
	// capacity — the same design as the certificate root (core/ssz's own doc
	// comment) — so a block carrying more citations than the capacity cannot
	// be MarshalSSZ'd into vector bytes, and types.UnmarshalBlock rejects an
	// over-capacity encoding at decode time, before this package's block
	// rules ever run. This vector's conformance harness fatals on a decode
	// failure unconditionally (spec/vector_test.go), by design — "an
	// implementation that cannot parse the wire format has not implemented
	// the protocol" — so there is no way to encode this scenario as bytes a
	// vector could carry. It is covered instead where it actually happens:
	// TestUnmarshalBlockRejectsTooManyCites in core/types.

	// Height 0 and 1 may never cite: no sibling of a height-1 block's parent
	// (genesis) can exist, since genesis is unique by construction.
	{
		c := harness.MustNew(p)
		gen := c.Tip()
		b := citeBlock(p, c, []*types.Header{&gen})
		out = append(out, capture("cites-invalid-at-height-one",
			"No block at height 0 or 1 can have a sibling worth citing — genesis is "+
				"unique by construction and a competing genesis is a different network, "+
				"not a fork (whitepaper §1). A citation attached this early is refused "+
				"regardless of what it names.",
			p, c.State, b))
	}

	return out
}

// ---------------------------------------------------------------------------
// Mainnet-parameter coverage, and the emission tail floor.
//
// 33 of the corpus's original 34 vectors ran on devnet's throwaway numbers;
// the one mainnet vector was genesis, whose subsidy is zero. Neither
// mainnet's coinbase maturity (100, not devnet's 10) nor its epoch length
// (2880, not 64) was ever the value that made a vector's expected output what
// it is, and no vector reached the point where core/params' emission
// schedule stops decaying. These two close both gaps.
// ---------------------------------------------------------------------------

func mainnetVectors() []*spec.Vector {
	p := spec.Mainnet()
	var out []*spec.Vector

	{
		// A real mainnet epoch boundary. newScenario mines COINBASE_MATURITY+2
		// blocks to fund the miner, so by the time this loop reaches height
		// 2880 the maturity ring — size 100, not devnet's 10 — has already
		// cycled more than once, and every cell this vector's Post asserts
		// (the beacon epoch number, the sample-ring median the epoch
		// controller reads, the maturing balance) was computed against
		// mainnet's real constants rather than devnet's.
		//
		// height 2880 happens to still be a multiple of devnet's epoch_length
		// (64 | 2880), so an implementation hard-coding epoch_length=64 would
		// still call this a boundary — but it would credit beacon.epoch = 45
		// instead of 1, and an implementation hard-coding coinbase_maturity=10
		// would have released and overwritten ring slots on a completely
		// different schedule for the whole climb to get here. Both diverge
		// from this vector's Post long before height 2880, which is what
		// makes it a constraint on the values and not merely on the boundary
		// arithmetic.
		s := newScenario(p)
		for s.chain.NextHeight()%p.EpochLength != 0 {
			s.chain.MustAddBlock(s.payout())
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		out = append(out, capture("mainnet-epoch-boundary",
			"Mainnet-parameter coverage: the corpus's only prior mainnet vector was genesis, whose "+
				"subsidy is zero. This one reaches mainnet's first real epoch "+
				"boundary — height 2880, not devnet's 64 — after mining past "+
				"several full cycles of mainnet's coinbase maturity ring — size "+
				"100, not devnet's 10. The beacon refresh, the epoch "+
				"controller's decay-and-floor path, and every maturity release "+
				"along the way are pinned at the values the launch actually "+
				"ships, not at devnet's throwaway substitutes for them.",
			p, s.chain.State, b))
	}

	{
		// The TTL bound at mainnet's value, which needs its own vector:
		// ttl_max is 240 on mainnet and 32 on devnet, and the only vector
		// that touches the bound (invalid-ttl-unbounded) runs on devnet with
		// an immortal TTL, which every implementation rejects whichever
		// number it hard-codes. This one sits a certificate EXACTLY at the
		// mainnet bound — TTL = height + 240, the largest value
		// core/fold/blockrules.go accepts — and expects it applied. An
		// implementation carrying devnet's 32, or reading the bound as
		// strict rather than inclusive, rejects the block instead, so the
		// verdict itself diverges rather than some cell deep in the state.
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.build(&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + p.TTLMax,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		b, err := s.chain.Propose(s.payout(), cert)
		if err != nil {
			panic(err)
		}
		out = append(out, capture("mainnet-ttl-bound",
			"B2 at mainnet's value: a certificate whose TTL sits exactly at mainnet's bound — "+
				"height + TTL_MAX, with TTL_MAX = 240 rather than devnet's 32 — "+
				"and is applied. The corpus's other TTL vector uses an "+
				"immortal TTL on devnet, which is rejected under any value of "+
				"the bound and so pins none of them; this one is accepted only "+
				"by an implementation carrying mainnet's number and reading "+
				"the comparison as inclusive. One off either way and the "+
				"block's verdict flips.",
			p, s.chain.State, b))
	}

	out = append(out, mainnetCertCeilingVector())

	{
		// The emission tail floor. Neither branch in core/params that can
		// return TAIL_EMISSION — the per-epoch decay clamp, or "past the end
		// of the precomputed table" — was reachable from any vector; even
		// devnet's tail arrives thousands of epochs out, and nothing in the
		// corpus walked that far.
		//
		// Reaching it by mining would mean replaying past the schedule's
		// decay crossover for real — thousands of epochs, millions of
		// blocks — which is not a generator's job. fold.ApplyBlock has no
		// notion of "the true tip" beyond the height the block itself
		// declares: header-sequence continuity (that a height really follows
		// from the one before it) is a node/chain concern the vectors
		// deliberately do not cover (spec/README.md), so the fold accepts a
		// synthetic jump straight to a height deep in the tail exactly as
		// readily as it would accept the real climb. This vector is that
		// jump: genesis's own initialised state, judged against a single
		// block many epochs past the point the schedule stops decaying.
		c := harness.MustNew(p)
		epoch := deepTailEpoch(p)
		height := epoch*p.EpochLength + 1 // +1: never an epoch boundary
		tip := c.Tip()
		b := &types.Block{
			Header: types.Header{
				Version:      types.HeaderVersion,
				Height:       height,
				ParentID:     tip.ID(),
				Time:         p.GenesisTime + height*p.TargetBlockSeconds,
				EmissionAddr: key(1).Persistent(),
				Target:       tip.Target,
				PoW:          types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p)},
			},
		}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		out = append(out, capture("emission-tail-floor",
			fmt.Sprintf(
				"The emission tail floor: height %d sits in epoch %d, comfortably past the schedule's "+
					"decay crossover — the emission table core/params precomputes at "+
					"load time ends well before it, and every epoch from there on "+
					"pays the flat TAIL_EMISSION. An implementation that forgets the "+
					"floor and keeps applying the per-epoch decay indefinitely pays a "+
					"smaller, still-shrinking subsidy here instead; one that panics or "+
					"defaults to zero past its own precomputed table's length pays "+
					"nothing at all. Built as a direct jump from genesis's own state "+
					"rather than by mining the epochs in between: fold.ApplyBlock "+
					"judges the height a block declares, and header-sequence "+
					"continuity is a node/chain concern this corpus deliberately does "+
					"not cover.",
				height, epoch),
			p, c.State, b))
	}

	return out
}

// seedEpochVectors pin the proof-of-work key epoch a header must declare
// (core/fold's checkSeedEpoch).
//
// The rule is one comparison and it is the kind a second implementation
// silently omits: nothing below the first key boundary can tell the difference,
// because SeedEpochFor returns zero there and a header that never sets the
// field declares zero too. So every vector here sits AT a boundary or one block
// short of it, which is the only place the rule has any content at all — the
// same lesson I6-M3 records about uniform inputs, applied before it could cost
// anything.
//
// Built as direct jumps from genesis state, like emission-tail-floor above and
// for the same reason: fold.ApplyBlock judges the height a block declares, and
// header-sequence continuity is a node/chain concern this corpus does not
// cover. Neither height is an epoch boundary on its own network, so no state
// root is expected.
func seedEpochVectors() []*spec.Vector {
	var out []*spec.Vector

	// atHeight builds a block declaring `epoch` at `height` on p.
	atHeight := func(p *params.Params, height, epoch uint64) (*harness.Chain, *types.Block) {
		c := harness.MustNew(p)
		tip := c.Tip()
		b := &types.Block{
			Header: types.Header{
				Version:      types.HeaderVersion,
				Height:       height,
				ParentID:     tip.ID(),
				Time:         p.GenesisTime + height*p.TargetBlockSeconds,
				EmissionAddr: key(1).Persistent(),
				Target:       tip.Target,
				PoW:          types.PoWSeal{SeedEpoch: epoch},
			},
		}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		return c, b
	}

	for _, net := range []*params.Params{spec.Mainnet(), spec.Devnet()} {
		p := net
		boundary := p.RandomXKeyInterval + p.RandomXKeyLag
		suffix := ""
		if p.Name != spec.Mainnet().Name {
			suffix = "-devnet"
		}

		// The first height at which the schedule says epoch 1.
		{
			c, b := atHeight(p, boundary, 1)
			out = append(out, capture("seed-epoch-at-the-first-boundary"+suffix,
				fmt.Sprintf(
					"The work function re-keys every randomx_key_interval blocks, with "+
						"randomx_key_lag blocks of slack, so the first boundary is at "+
						"%d + %d = %d and this is the first header that must declare "+
						"epoch 1. The key itself is never read from this field — a "+
						"verifier derives it from the height, which is what keeps "+
						"CheckWork a total function of a header's bytes — so what this "+
						"vector pins is that the field is not free: 64 bits inside the "+
						"proof-of-work seed that a miner could otherwise grind.",
					p.RandomXKeyInterval, p.RandomXKeyLag, boundary),
				p, c.State, b))
		}

		// The value every unaware implementation writes.
		{
			c, b := atHeight(p, boundary, 0)
			out = append(out, capture("invalid-seed-epoch-stale"+suffix,
				fmt.Sprintf(
					"Height %d is the first that must declare epoch 1, and this block "+
						"declares 0 — which is not an exotic forgery but the value a "+
						"header gets by default from an implementation that has not "+
						"implemented the schedule at all. That is exactly why it is a "+
						"vector: below the first boundary the correct answer and the "+
						"unimplemented answer are the same number, so a corpus without "+
						"this height cannot tell the two apart.",
					boundary),
				p, c.State, b))
		}

		// The mirror: the boundary is off by one the other way.
		{
			c, b := atHeight(p, boundary-1, 1)
			out = append(out, capture("invalid-seed-epoch-early"+suffix,
				fmt.Sprintf(
					"Height %d is the LAST height of epoch 0 and this block declares 1. "+
						"It is the mirror of the case above and it is what separates the "+
						"shifted boundary from an unshifted one: an implementation that "+
						"drops the lag and re-keys at multiples of the interval alone "+
						"puts the boundary at %d, calls this header correct, and forks "+
						"from every node that reads the lag.",
					boundary-1, p.RandomXKeyInterval),
				p, c.State, b))
		}
	}

	return out
}

// deepTailEpoch returns an epoch comfortably past the point core/params'
// emission schedule reaches TAIL_EMISSION and stops decaying, found by
// walking Emission forward one epoch at a time — the same integer arithmetic
// core/params itself uses to build its table, so this adds no independent
// assumption about where the crossover actually falls.
//
// The +1000-epoch margin is deliberate: the vector should unambiguously
// exercise "the schedule has stopped decaying and holds flat", not merely the
// crossover epoch itself, so that an off-by-one in a second implementation's
// own table length does not happen to still agree with this vector by
// landing one epoch short.
func deepTailEpoch(p *params.Params) uint64 {
	epoch := uint64(1)
	for !p.Emission(epoch * p.EpochLength).Eq(p.TailEmission) {
		epoch++
	}
	return epoch + 1000
}

// ---------------------------------------------------------------------------
// The difficulty rule. fold.ApplyBlock never evaluates pow.NextTarget —
// it records a block's declared target and never checks it (core/fold's only
// contact with Header.Target) — so no statement about the difficulty rule can
// be expressed as a (pre-state, block) vector at all. These are a second,
// parallel vector kind: (params, headers) -> next_target, replayed by calling
// pow.NextTarget directly (spec/vector_test.go) rather than by folding
// anything.
//
// Two defects in the function these vectors pin were fixed after the first
// vectors were committed, and each is handled differently on purpose
// (spec/README.md, "Changing them"):
//
//   - The floor-at-zero on a backwards solve time — FIXED in core/pow: the
//     accumulator is signed and the per-sample clamp is symmetric at
//     ±maxSolve. Every window in the first twelve vectors below
//     still uses STRICTLY INCREASING timestamps, so none of their answers
//     moved when the fix landed — which is why the fix regenerated the
//     corpus without moving a single pre-existing next_target.
//     spec/difficulty_mutation_test.go recomputes the whole corpus under the
//     *retired* floor-at-zero rule and fails if any answer moves; keep it
//     that way when adding a vector. Note the polarity: that harness's
//     mutation arm now models the rule core/pow had BEFORE this fix, not a
//     proposed one.
//     Three vectors are new here and do depend on the fix, deliberately —
//     on-time-holds (the control) and signed-backdate-cancels{,-devnet},
//     whose windows contain a genuinely DECREASING timestamp. They are the
//     only vectors in the corpus that a floor-at-zero implementation answers
//     differently, and they exist so that the fix cannot be silently
//     reverted.
//
//   - The normalisation basis — settled: the ratio applies to the window's
//     AVERAGE target, canonical Zawy LWMA. Exactly ONE vector depends on it,
//     deliberately — normalises-against-the-window-average, the only window
//     here that declares differing targets. Without it core/pow could be
//     switched back to last-target normalisation with the whole corpus
//     staying green, which is the hole this corpus exists to close. Its value is
//     exactly 7/3 of GENESIS_TARGET, the average of the window's declared
//     4x/2x/1x targets.
//
// ---------------------------------------------------------------------------

func difficultyVectors() []*spec.DifficultyVector {
	mainnet := spec.Mainnet()
	devnet := spec.Devnet()
	var out []*spec.DifficultyVector

	// A — fewer than two headers. The one real chain state that produces
	// this is height 1: chain.RecentHeaders(DIFFICULTY_WINDOW+1) returns just
	// genesis, because there is nothing older to return yet. NextTarget's
	// early return must answer GENESIS_TARGET here rather than, say,
	// indexing into an empty pair or treating a missing sample as a zero
	// solve time.
	//
	// The lone header's own declared target is deliberately set to
	// MAX_TARGET, not GENESIS_TARGET. A real genesis header always declares
	// GENESIS_TARGET (core/genesis), so those two values coincide on every
	// real chain and a vector that used the real value could not tell "the
	// early return answers GENESIS_TARGET" apart from "an implementation
	// that forgot the check fell through, found weights==0, and echoed the
	// window's own last target back" — both give the same answer when the
	// header's target already IS GENESIS_TARGET. Declaring something else
	// closes that gap: the fallthrough path would answer MAX_TARGET here,
	// and the early return answers GENESIS_TARGET regardless of what the
	// single header claims.
	out = append(out, captureDifficulty("genesis-only-window",
		"Fewer than two headers — the real shape of the window at "+
			"height 1, where chain.RecentHeaders has only genesis to return. "+
			"NextTarget's len(recent)<2 branch must answer GENESIS_TARGET "+
			"outright, ignoring whatever the lone header itself declares — "+
			"which is why it declares MAX_TARGET here rather than the "+
			"GENESIS_TARGET a real genesis header would carry: an "+
			"implementation that skipped the early return and fell through to "+
			"the general formula would answer with the header's own claimed "+
			"target instead, and this is the vector that catches it.",
		mainnet, diffWindow([]uint64{0}, mainnet.MaxTarget)))

	// B — EXACTLY two headers, which is the edge of the early return above
	// and the one window shape the corpus had no example of. Every real chain
	// passes through it at height 2, where chain.RecentHeaders returns genesis
	// and block 1 and nothing older. One header more than A and the rule stops
	// answering GENESIS_TARGET and starts computing: an implementation whose
	// early return reads `len(recent) < 3` instead of `< 2` — an ordinary
	// off-by-one, and the mirror of the one A catches — answers GENESIS_TARGET
	// here and diverges by 10x on block 2. A pins the inside of the branch;
	// this pins its edge.
	{
		goal := mainnet.TargetBlockSeconds
		headers := diffWindow([]uint64{0, 10 * goal}, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("two-header-window",
			"Exactly two headers — the smallest window on which the rule "+
				"computes rather than returning GENESIS_TARGET outright, and "+
				"the shape every chain has at height 2. The single solve ran "+
				"ten times the goal, so the target rises exactly tenfold, well "+
				"inside the relative ceiling of DIFFICULTY_CLAMP_FACTOR (16). "+
				"An implementation whose early return reads len(recent) < 3 "+
				"rather than < 2 answers GENESIS_TARGET here instead — a "+
				"tenfold disagreement on block 2, from an off-by-one that no "+
				"other vector in this corpus can see.",
			mainnet, headers))
	}

	// C — a short window, still filling: height 3's shape, two solves at
	// twice the goal. Exercises the len(recent)<DIFFICULTY_WINDOW+1 branch
	// that shrinks the window to what is actually available (2 gaps, not
	// DIFFICULTY_WINDOW), rather than dividing a real weighted sum by a
	// denominator sized for a window that does not exist yet — which would
	// crush the result far below what these two gaps actually say.
	{
		goal := mainnet.TargetBlockSeconds
		headers := diffWindow([]uint64{0, 2 * goal, 4 * goal}, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("short-window-early-chain",
			"Three headers — the real shape of the window a few blocks "+
				"after genesis, before DIFFICULTY_WINDOW's full history exists. "+
				"Both solves ran at twice the target spacing, so the target must "+
				"exactly double. An implementation that divides the same "+
				"weighted sum by a denominator sized for the full window, "+
				"instead of the two gaps actually present, would under-shoot "+
				"badly — the relative floor would visibly catch it, giving a "+
				"different, wrong answer from this vector's.",
			mainnet, headers))
	}

	// D — MORE headers than the rule may use. Every caller in this tree hands
	// pow.NextTarget exactly DifficultyWindow+1 headers, so nothing here
	// exercises the truncation; a second implementation whose header store
	// returns whatever it has is the case this vector exists for. 101
	// headers: the oldest 10 gaps ran at the per-block cap and the newest 90
	// at 10s. Take the newest 91 — what the rule says — and every gap in the
	// window is 10s. Take the oldest 91, or skip the truncation and use all
	// 100 gaps, and the slow start is still in the window and the answer is
	// visibly higher. Both wrong readings are ordinary implementation bugs
	// and neither is caught by any other vector, because every other window
	// here is exactly the length the rule wants.
	{
		goal := mainnet.TargetBlockSeconds
		maxSolve := goal * mainnet.DifficultyClampFactor
		times := make([]uint64, 101)
		for i := 1; i <= 100; i++ {
			gap := uint64(10)
			if i <= 10 {
				gap = maxSolve
			}
			times[i] = times[i-1] + gap
		}
		headers := diffWindow(times, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("window-truncates-to-the-newest",
			"101 headers, ten more than the rule may use. The oldest ten "+
				"gaps ran at the per-block cap and the newest ninety at 10s, so "+
				"the correct window — the NEWEST DIFFICULTY_WINDOW+1 headers — "+
				"contains nothing but 10s gaps and lowers the target to a third. "+
				"An implementation that takes the oldest 91 instead, or that "+
				"skips the truncation and averages all 100 gaps, still has the "+
				"slow start in its window and answers higher. Every caller in "+
				"the reference tree happens to pass exactly the right number of "+
				"headers, so this is the one shape the implementation itself "+
				"never exercises.",
			mainnet, headers))
	}

	// E — a full window, away from every clamp: pins the defining property
	// of a *linearly weighted* moving average against a naive unweighted one,
	// which would get this scenario's answer wrong. The older half of the
	// window ran fast (10s); the newer half ran slow (50s). An unweighted
	// average of the two is exactly the 30s goal, so a plain-average
	// implementation would leave the target unchanged; LWMA weighs the
	// newer, slower half more heavily and must raise it instead.
	{
		times := make([]uint64, 91)
		for i := 1; i <= 90; i++ {
			gap := uint64(10)
			if i > 45 {
				gap = 50
			}
			times[i] = times[i-1] + gap
		}
		headers := diffWindow(times, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("retarget-weights-recent-blocks-more",
			"A full 91-header window, away from every clamp. The older "+
				"45 solves ran at 10s and the newer 45 ran at 50s — an "+
				"UNWEIGHTED average of the two is exactly the 30s goal, so a "+
				"plain-average implementation would leave the target where it "+
				"is. The linear weighting that gives LWMA its name weighs the "+
				"newer (slower) half more heavily, so the real answer raises "+
				"the target instead: this is the vector that tells the two "+
				"apart.",
			mainnet, headers))
	}

	// F — the mirror of E, downward. The corpus owes a plain retarget "in each
	// direction, well away from every clamp", and E only covers the upward
	// one. The direction matters on its own: an implementation that inverts
	// the ratio (targets are inverse to difficulty, and multiplying by
	// goal/average instead of average/goal is the classic form of that bug)
	// caught here too, in the opposite direction, but E catches it as well —
	// so the reason to have both is that "each direction", not the inversion.
	// The window is E's, reversed: the
	// older 45 solves ran at 50s and the newer 45 at 10s, so an unweighted
	// average is again exactly the 30s goal and only the linear weighting
	// moves the target — down, this time, to 61/91 of where it was, floored:
	// the ratio does not divide evenly and MulDiv64 floors.
	{
		times := make([]uint64, 91)
		for i := 1; i <= 90; i++ {
			gap := uint64(50)
			if i > 45 {
				gap = 10
			}
			times[i] = times[i-1] + gap
		}
		headers := diffWindow(times, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("retarget-down-away-from-clamps",
			"E's window reversed — the older 45 solves ran at 50s and "+
				"the newer 45 at 10s. The unweighted average is again exactly "+
				"the 30s goal, so only the linear weighting moves the target, "+
				"and here it moves it DOWN: to 61/91 of the previous target, "+
				"floored as MulDiv64 floors — the ratio does not divide evenly, "+
				"and the committed value is the floor. It is well inside both "+
				"relative clamps, and it is the downward half of the plain "+
				"retarget this corpus owes each direction. An implementation that "+
				"inverted the ratio (goal/average instead of average/goal — "+
				"targets are inverse to difficulty) answers with a raised "+
				"target here instead of a lowered one.",
			mainnet, headers))
	}

	// G — WHICH target the ratio is applied to. Every solve ran at exactly the
	// goal, so the ratio is exactly 1 and the answer is "the target does not
	// move" — but the vector's whole content is WHICH target does not move.
	// The window's targets are 4G, 2G, G: the last is G and the average is
	// 7G/3, so an implementation normalising against the window's average
	// answers 7G/3 and this one answers G.
	//
	// This is the one vector that pins the normalisation-basis choice — the
	// deeper half of the clamp question — and the only one that can: the
	// coincidence average == last
	// holds identically on a window whose targets are all equal, so every
	// other vector in this corpus is blind to it. Verified by mutating
	// core/pow to canonical Zawy normalisation — without this vector the
	// whole corpus, and `make vectors`, stay byte-for-byte green.
	//
	// It follows that this is also the only vector a change of normalisation
	// basis moves. That is correct
	// and is the point: a corpus that could not tell the two normalisations
	// apart would let a second implementation write canonical LWMA, pass
	// every vector, and fork at the first retarget.
	{
		goal := mainnet.TargetBlockSeconds
		g := mainnet.GenesisTarget
		headers := diffWindowTargets(
			[]uint64{0, goal, 2 * goal},
			[]u256.U256{g.MulDiv64(4, 1), g.MulDiv64(2, 1), g})
		out = append(out, captureDifficulty("normalises-against-the-window-average",
			"Three headers whose declared targets are falling — 4x, "+
				"2x, then 1x GENESIS_TARGET — with both solves at exactly the "+
				"goal, so the weighted ratio is exactly 1. The answer is "+
				"therefore 'the target is unchanged', and the entire content of "+
				"this vector is WHICH target is unchanged: the window's "+
				"AVERAGE, which is canonical Zawy LWMA and what core/pow now "+
				"computes, not the window's LAST target, which is what it "+
				"computed before. The two coincide identically on a window "+
				"whose targets are all equal, which every other vector in this "+
				"corpus is, so this is the only vector that can tell them "+
				"apart: the average of 4x, 2x and 1x is 7/3 of GENESIS_TARGET, "+
				"and an implementation that still normalises against the last "+
				"target answers 3/7 of this value. That is not a cosmetic "+
				"difference — normalising against the last target leaves the "+
				"retarget loop only marginally stable (dominant pole |z| ~ "+
				"0.9993, a ~1500-block memory), so it integrates proof of "+
				"work's solve-time noise into a random walk that drives an "+
				"entirely honest chain into the MaxTarget ceiling within a few "+
				"hundred blocks; see core/pow.NextTarget and "+
				"core/pow/honest_chain_poisson_test.go.",
			mainnet, headers))
	}

	// H — the per-block cap on a single solve time, observed well inside both
	// relative clamps. 90 gaps, 89 at 10s and one at 1000s, which is more than
	// twice the cap of goal * DIFFICULTY_CLAMP_FACTOR = 480s. Capped, the
	// weighted ratio is 62100/122850; uncapped it is 85500/122850. Neither is
	// anywhere near the relative floor (1/16) or ceiling (16), so unlike the
	// ceiling vector below this one observes the cap directly rather than
	// through the bound it happens to produce — and it also pins the cap's
	// VALUE, since a different multiple of the goal gives a different answer.
	// Without it the cap can be deleted from core/pow outright and the whole
	// corpus stays green (verified).
	{
		times := make([]uint64, 91)
		for i := 1; i <= 90; i++ {
			gap := uint64(10)
			if i == 45 {
				gap = 1000
			}
			times[i] = times[i-1] + gap
		}
		headers := diffWindow(times, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("per-block-solve-cap",
			"Ninety gaps, eighty-nine of them at 10s and one at 1000s, "+
				"which is more than twice "+
				"the per-sample cap of goal * DIFFICULTY_CLAMP_FACTOR (480s). "+
				"The outlier is clamped to the cap before it is weighted, so it "+
				"contributes 480 and not 1000. Both the capped and the uncapped "+
				"answers sit well inside the relative floor and ceiling, so this "+
				"vector observes the cap itself rather than the bound it happens "+
				"to produce elsewhere — and it pins the cap's value, not just "+
				"its existence: a cap at a different multiple of the goal gives "+
				"a different answer here.",
			mainnet, headers))
	}

	// I — the reachable relative clamp, downward. Two one-second solves —
	// strictly increasing timestamps, so the window says nothing about the
	// retired floor-at-zero treatment of a backwards solve — pull the raw weighted average
	// far enough below the goal that NextTarget's lower relative clamp — the previous target
	// divided by DIFFICULTY_CLAMP_FACTOR — binds and overrides the raw
	// arithmetic, rather than the raw (much smaller) division answering.
	{
		headers := diffWindow([]uint64{0, 1, 2}, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("relative-floor-fires",
			"Two one-second solves pull the raw weighted average to a "+
				"thirtieth of the goal. Unclamped, the arithmetic would divide "+
				"the target by 30; the relative floor caps the fall at "+
				"DIFFICULTY_CLAMP_FACTOR (16), and this vector pins that the "+
				"floor is what actually answers, not the raw division. The "+
				"timestamps are strictly increasing on purpose: a window of "+
				"repeated or backwards timestamps would reach the same floor, "+
				"but only through the retired floor-at-zero treatment of a "+
				"backwards solve time, and this vector deliberately does not "+
				"depend on how a backwards solve is treated.",
			mainnet, headers))
	}

	// J — every RAW solve ten times past the per-block cap
	// maxSolve = goal * DIFFICULTY_CLAMP_FACTOR. This is the boundary the
	// relative ceiling exists to describe: whatever the raw solve times
	// were, the target may rise by at most DIFFICULTY_CLAMP_FACTOR in one
	// block. Two mechanisms in the rule as it stands each enforce that bound
	// — a live per-sample cap, and a post-hoc comparison
	// that is provably dead given the first — and this vector is agnostic
	// between them: removing EITHER alone still answers correctly, and only
	// an implementation missing BOTH fails it, which is the property
	// actually worth pinning.
	//
	// The raw input has to genuinely EXCEED maxSolve, not merely equal it:
	// an earlier draft used solves already at exactly maxSolve, under which
	// the per-sample cap is a no-op regardless of whether it is even
	// present, and removing it changed nothing — a vacuous test of the very
	// mechanism it claimed to pin. Ten times over closes that gap.
	{
		goal := mainnet.TargetBlockSeconds
		maxSolve := goal * mainnet.DifficultyClampFactor
		rawSolve := 10 * maxSolve
		headers := diffWindow(
			[]uint64{0, rawSolve, 2 * rawSolve, 3 * rawSolve, 4 * rawSolve}, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("relative-ceiling-boundary",
			"Every raw solve ten times past the per-block cap (goal * "+
				"DIFFICULTY_CLAMP_FACTOR). Capped, the target must rise by "+
				"exactly DIFFICULTY_CLAMP_FACTOR and no more. "+
				"This rule enforces that bound twice as it stands today — a "+
				"live per-sample cap, and a provably dead post-hoc comparison — "+
				"and this vector is agnostic between them: it pins the "+
				"observable ceiling on the per-block multiplier, not which "+
				"internal branch supplies it. An implementation missing BOTH "+
				"mechanisms answers with ten times this vector's expectation "+
				"instead. The per-sample cap makes the post-hoc comparison "+
				"unreachable: after capping, no weighted average can exceed the "+
				"goal by more than DIFFICULTY_CLAMP_FACTOR, so the comparison "+
				"never fires and removing it alone changes no answer.",
			mainnet, headers))
	}

	// K — the absolute ceiling, MAX_TARGET. Starting from a target already at half
	// of MAX_TARGET, the same per-block-cap solve times as J would raise it
	// 16x — to twice MAX_TARGET, comfortably short of u256 saturation, so
	// the absolute clamp is what is actually observed firing here rather
	// than an accident of wraparound.
	{
		goal := mainnet.TargetBlockSeconds
		maxSolve := goal * mainnet.DifficultyClampFactor
		half, _ := mainnet.MaxTarget.Div64(2)
		headers := diffWindow(
			[]uint64{0, maxSolve, 2 * maxSolve, 3 * maxSolve, 4 * maxSolve}, half)
		out = append(out, captureDifficulty("max-target-ceiling-fires",
			"Starting from half of MAX_TARGET, a sustained per-block "+
				"push would raise the target 16x — to twice MAX_TARGET, well "+
				"short of u256 saturation, so the absolute clamp is what is "+
				"actually observed firing rather than an accident of "+
				"wraparound. An implementation that has not implemented the "+
				"MAX_TARGET ceiling returns that larger, unclamped value; this one must "+
				"answer exactly MAX_TARGET.",
			mainnet, headers))
	}

	// L — the floor at one. A tiny previous target (2) with solves short
	// enough that the truncating division underflows drives the raw
	// arithmetic to zero, which NextTarget refuses to return:
	// a target of zero is unsatisfiable by any hash, and the chain would
	// stop. Run on devnet's parameters rather than mainnet's, so both
	// parameter sets are represented in this corpus and not only mainnet.
	{
		headers := diffWindow([]uint64{0, 1, 2}, u256.FromUint64(2))
		out = append(out, captureDifficulty("floor-at-one",
			"A previous target of 2 with two one-second solves drives "+
				"the raw weighted arithmetic to zero — 2 * 3 / (3 * 5) "+
				"truncates to nothing, and the relative floor (2/16, also "+
				"zero) cannot lift it. NextTarget refuses to return it: "+
				"a target of zero admits no hash at all, which would stop the "+
				"chain rather than merely reprice it. The floor raises it to "+
				"one instead.",
			devnet, headers))
	}

	// H — on-time holds: the control case for both clamp families. A full window of blocks
	// arriving exactly on goal leaves the target unchanged: the weighted
	// average solve time equals the goal exactly, so the multiplier
	// NextTarget applies is 1. This is the baseline signed-backdate-cancels
	// (below) perturbs by replacing exactly one interval with a backdate —
	// without this vector fixed in the corpus alongside it, a reviewer has
	// no committed "nothing happened" case to compare the backdated one
	// against.
	//
	// The window's declared target is deliberately NOT GENESIS_TARGET. An
	// "unchanged" answer computed from a genesis-target window is exactly the
	// value the len(recent)<2 early return produces from no computation at
	// all, so such a vector is passed by an implementation that ignores its
	// input entirely — the vacuity class TestDifficultyVectorsAreNotVacuous
	// exists to reject, and which cost two vectors during this corpus's
	// construction. Starting from GENESIS_TARGET/4 keeps the multiplier
	// exactly 1 while making the committed answer a value only a rule that
	// actually reads the window can produce.
	{
		goal := mainnet.TargetBlockSeconds
		window := int(mainnet.DifficultyWindow)
		times := make([]uint64, window+1)
		for i := range times {
			times[i] = uint64(i) * goal
		}
		start, _ := mainnet.GenesisTarget.Div64(4)
		headers := diffWindow(times, start)
		out = append(out, captureDifficulty("on-time-holds",
			"A full window of blocks arriving exactly on goal "+
				"leaves the target unchanged — the weighted average solve "+
				"time equals the goal exactly, so the multiplier NextTarget "+
				"applies is 1. The control case signed-backdate-cancels "+
				"(below) perturbs: without this vector, nothing in the "+
				"corpus pins what 'nothing happened' looks like for a "+
				"reviewer to compare the backdated scenario against. The "+
				"window's declared target is GENESIS_TARGET/4 and not "+
				"GENESIS_TARGET itself, on purpose: an unchanged answer at "+
				"GENESIS_TARGET is indistinguishable from the value the "+
				"len(recent)<2 early return yields without reading the "+
				"window at all, so this vector would be passed by an "+
				"implementation that computes nothing.",
			mainnet, headers))
	}

	// I — signed-backdate-cancels: the signed accumulator, mainnet. A miner backdates
	// the block it wins to Time=0, below its own parent — legal, because the
	// only lower bound on Header.Time is the median of the last
	// MEDIAN_TIME_BLOCKS headers, not the parent's own time. The window has
	// 89 on-goal intervals (i=1..89, weight i, solve=goal) and one interval
	// pulled hard negative at the top of the window (i=90, weight 90): the
	// last header's parent sits at 1_000_000+89*goal and the header itself
	// claims Time=0, so the raw gap saturates the clamp at -maxSolve. Under
	// the retired floor-at-zero rule this interval contributed 0 instead of
	// -maxSolve, which is exactly the donation that made backdating
	// strictly profitable (F-PARAM-3) — this is the vector core/pow_test.go's
	// TestDifficultyClampsAgainstTimestampGames drives directly and derives
	// by hand; see that test's comment for the arithmetic.
	{
		goal := mainnet.TargetBlockSeconds
		window := int(mainnet.DifficultyWindow)
		const base = 1_000_000
		times := make([]uint64, window+1)
		for i := 0; i < window; i++ {
			times[i] = base + uint64(i)*goal
		}
		times[window] = 0
		headers := diffWindow(times, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("signed-backdate-cancels",
			"A miner backdates the block it wins to Time=0, below its "+
				"own parent — legal, because the only lower bound on "+
				"Header.Time is the median of the last MEDIAN_TIME_BLOCKS "+
				"headers, not the parent's own time. The transition into the "+
				"backdated block is a large negative interval, clamped at "+
				"-maxSolve rather than floored at zero, which is the whole "+
				"of the fix: the retired rule left this contribution at 0 "+
				"and made backdating strictly profitable at every weight "+
				"(F-PARAM-3). Compare against on-time-holds, above, for what "+
				"the same window answers with no manipulation at all.",
			mainnet, headers))
	}

	// J — the same scenario as signed-backdate-cancels, against devnet's
	// parameters (goal=5s rather than 30s; a different genesis and max
	// target) — not a restatement of the mainnet vector under a different
	// name. An implementation that hardcodes mainnet's maxSolve or goal
	// instead of reading them from params would answer this one wrong even
	// after getting the mainnet vector right.
	{
		goal := devnet.TargetBlockSeconds
		window := int(devnet.DifficultyWindow)
		const base = 1_000_000
		times := make([]uint64, window+1)
		for i := 0; i < window; i++ {
			times[i] = base + uint64(i)*goal
		}
		times[window] = 0
		headers := diffWindow(times, devnet.GenesisTarget)
		out = append(out, captureDifficulty("signed-backdate-cancels-devnet",
			"The same scenario as signed-backdate-cancels, against "+
				"devnet's parameters — a different goal, genesis target and "+
				"max target, so this is not a restatement of the mainnet "+
				"vector under a different name; it catches an implementation "+
				"that hardcodes mainnet's constants instead of reading them "+
				"from params.",
			devnet, headers))
	}

	// K — the int64-widening trap, an interop hazard. A two-header window whose
	// gap is 2^63 seconds: enormous, but a value core/pow can legally be
	// handed, because NextTarget is clockless and no consensus rule bounds
	// Header.Time from above (the future-time limit withholds at the node
	// layer, and only on some ingress paths — node/sync calls NextTarget
	// before its IsTooFarAhead check, and node/chain's fork-choice
	// revalidation has no clock at all).
	//
	// The shipped rule takes the magnitude in uint64, clamps it to maxSolve,
	// and only then applies a sign, so this window's single solve is +480.
	// An implementation that instead widens the raw difference to int64
	// BEFORE clamping — the obvious way to write "signed solve time", and the
	// trap core/pow's own comment warns about — wraps 2^63 to -2^63 and
	// answers -480 instead. The two differ by the full width of the clamp and
	// send the target in opposite directions.
	//
	// Nothing else in this corpus can see that: the largest gap anywhere else
	// is ~10^6 seconds, thirteen orders of magnitude below where the wrap
	// begins, so a second implementation with this bug passes every other
	// vector and forks the first time anyone hands it a far-dated header.
	// The order matters and is deliberate: the reverse window (2^63, 0) does
	// NOT discriminate, because both readings land on the relative floor.
	{
		headers := diffWindow([]uint64{0, 1 << 63}, mainnet.GenesisTarget)
		out = append(out, captureDifficulty("int64-widening-trap",
			"A two-header window with a gap of 2^63 seconds — legal input, "+
				"since NextTarget is clockless and the future-time limit is a "+
				"node-layer withhold applied on some ingress paths only. The "+
				"magnitude is taken in uint64 and clamped to maxSolve BEFORE a "+
				"sign is applied, so the solve is +480 and the target rises. An "+
				"implementation that widens the raw difference to int64 first "+
				"wraps 2^63 to -2^63, clamps to -480, and lowers the target "+
				"instead — a fork on a header anyone can send. No other vector "+
				"in this corpus carries a gap within thirteen orders of "+
				"magnitude of the wrap, so this is the only one that catches it. "+
				"The direction is deliberate: the reverse window does not "+
				"discriminate, as both readings land on the relative floor.",
			mainnet, headers))
	}

	return out
}

// captureDifficulty runs pow.NextTarget against a header window and records
// the call and its result as a vector. The parallel to capture() above: that
// one drives fold.ApplyBlock, this one drives the one other function a
// conformance vector needs to reach, pow.NextTarget.
func captureDifficulty(name, description string, p *params.Params, headers []types.Header) *spec.DifficultyVector {
	v := &spec.DifficultyVector{
		Name:        name,
		Description: description,
		Params:      paramName(p),
	}
	for _, h := range headers {
		v.Headers = append(v.Headers, "0x"+hex.EncodeToString(h.MarshalSSZ()))
	}
	v.Expect.NextTarget = pow.NextTarget(headers, p).String()
	return v
}

// diffWindow builds a header window from explicit cumulative timestamps, one
// per header, every header declaring the same target. pow.NextTarget derives
// every solve time from consecutive Time fields and reads Target only off the
// window's last header (core/pow/pow.go) — so every earlier header's own
// Target is consensus-irrelevant to the computation, and holding it constant
// keeps the window looking like a real, unremarkable stretch of chain in
// which nothing has retargeted yet, right up to the block these headers are
// windowing towards.
// diffWindowTargets is diffWindow with a target per header rather than one
// for the whole window. Every real window has one: a target that never moved
// across 91 blocks is the unrealistic case, not the realistic one. It exists
// because a uniform window cannot distinguish "normalise against the window's
// last target" from "normalise against the window's average target" — the two
// coincide identically when every target is equal, which is why no vector
// built on diffWindow can pin that choice.
func diffWindowTargets(times []uint64, targets []u256.U256) []types.Header {
	if len(times) != len(targets) {
		panic("diffWindowTargets: one target per header")
	}
	out := make([]types.Header, len(times))
	var prev *types.Header
	for i, t := range times {
		out[i] = types.Header{
			Version:      types.HeaderVersion,
			Height:       uint64(i),
			Time:         t,
			EmissionAddr: key(1).Persistent(),
			Target:       targets[i],
		}
		if prev != nil {
			out[i].ParentID = prev.ID()
		}
		prev = &out[i]
	}
	return out
}

func diffWindow(times []uint64, target u256.U256) []types.Header {
	out := make([]types.Header, len(times))
	var prev *types.Header
	for i, t := range times {
		out[i] = types.Header{
			Version:      types.HeaderVersion,
			Height:       uint64(i),
			Time:         t,
			EmissionAddr: key(1).Persistent(),
			Target:       target,
		}
		if prev != nil {
			out[i].ParentID = prev.ID()
		}
		prev = &out[i]
	}
	return out
}

// authorizationVectors pins the certificate id's contract behaviourally, which
// is the one thing the rest of this corpus cannot do for it.
//
// Every other vector the id-preimage narrowing touched moved by a hex string:
// the ids and the
// seen entries hold different values now, so an implementation still hashing
// the signature list into its id fails them.
//
// Be exact about how much that is worth, because an earlier draft of this
// comment overstated it. Reverting ID()'s preimage to the whole encoding fails
// 16 vectors, and 13 of them fail as a checksum does -- "outcome 0: fold order
// differs" -- which is also what a mistyped domain tag says. The other three
// fail behaviourally, with "the block was accepted", and one of those three is
// the pre-existing invalid-replay. So the corpus was not blind; it was thin.
//
// What it had no vector for at all is an authorization arriving twice under two
// signatures. invalid-replay reaches its behavioural failure only because its
// pre.seen was recorded under the new rule, so the answer is still encoded in
// the input; invalid-duplicate-in-block replays identical bytes and passes the
// mutation outright. invalid-resigned-duplicate-in-block below is the only
// vector in the corpus that pins the rule with no committed id anywhere in its
// inputs -- two certificates, one block, and nothing else -- and
// invalid-resigned-replay is the cross-block half.
//
// These two present that input. Each carries two certificates that are one
// authorization under two signatures, in the two shapes an implementation has
// to refuse: both in one block, and one after the other has been committed. An
// implementation whose id covers the signature list accepts both blocks and
// bills one signed payment twice — and finds out here rather than on a network.
//
// This is the same argument that holds for sim/, one level up. The
// simulator's corpus could not produce two encodings of one authorization
// because wallet.Builder signs deterministically; neither could this one, for
// the same reason, and neither noticed.
//
// Appended after the seed-epoch corpus so that adding them renumbers nothing.
//
// The construction is sim/harness.ReSignCertificate: it replaces one signer's
// signature with a different valid one over the same message at a chosen nonce,
// and verifies the result against crypto/ed25519 before returning it.
func authorizationVectors() []*spec.Vector {
	p := spec.Devnet()
	var out []*spec.Vector

	// A single signer, deliberately. The co-signer shape is the theft case and
	// the more alarming one, but it needs a fee-sponsored deposit to state, and
	// a conformance vector should carry the rule in the smallest shape that
	// holds it. This is the wallet-retry shape: no attacker and no second party,
	// one signer re-signing its own payment at a fresh nonce, which is what any
	// hedged signer does on every retry.
	resign := func(c *types.Certificate, k *wallet.Key, nonce byte) *types.Certificate {
		again, err := harness.ReSignCertificate(c, p, k.Seed(), nonce)
		if err != nil {
			panic(err)
		}
		if again.ID() != c.ID() {
			panic("gen: re-signing moved the certificate id; this vector would assert the wrong thing")
		}
		if again.ExemplarHash() == c.ExemplarHash() {
			panic("gen: re-signing did not change the encoding; this is a byte replay")
		}
		if err := validity.Check(again, p); err != nil {
			panic("gen: the re-signed exemplar is not stateless-valid: " + err.Error())
		}
		return again
	}

	// One authorization, two exemplars, one block.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
		again := resign(cert, alice, 0x5A)

		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert, again}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-resigned-duplicate-in-block",
			"Two encodings of one authorization in one block, differing "+
				"only in one signature's nonce. Both are stateless-valid and both "+
				"carry the same certificate id, because the id covers the "+
				"authorizing fields and never the signatures — so the in-block "+
				"duplicate rule refuses the block. An implementation that hashes "+
				"the signature list into its id sees two certificates here, accepts "+
				"the block, and bills one signed payment twice. Note that the two "+
				"certificates are different bytes: the block's cert_root has two "+
				"distinct leaves, because that root is over exemplar hashes.",
			p, s.chain.State, b))
	}

	// One authorization, committed, then a re-signed exemplar of it.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		cert := s.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
		again := resign(cert, alice, 0xEE)
		s.chain.MustAddBlock(s.payout(), cert)

		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{again}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-resigned-replay",
			"The same rule across blocks: the authorization listed in pre.seen was "+
				"committed under a different signature, and this block re-includes "+
				"it under bytes no node has seen before. B3 keys the seen set on "+
				"the id and the id is over the authorizing fields, so this is a "+
				"replay however it is signed. The distinction from invalid-replay "+
				"is the point: that vector replays identical bytes, which every "+
				"implementation refuses; this one replays the same authorization.",
			p, s.chain.State, b))
	}

	return out
}

// ---------------------------------------------------------------------------
// §7's V-rules: one separating vector per rule the corpus can reach
// ---------------------------------------------------------------------------

// vRuleVectors gives the stateless rules of docs/ARCHITECTURE.md §7 the
// treatment the block rules already had.
//
// An independent audit of the consensus axis found the frozen corpus recorded
// rejection by V2 and V5 only, and named the consequence: an implementation
// that omits V3 entirely — the rule tying declared writes to the program —
// passes every golden vector and every corpus test. That was measured rather
// than argued. A certificate declaring an extra DELTA_ADD to a balance cell
// needs no signature under V4, which requires keys only for SET, DELTA_SUB and
// MARK_SPENT, and trips nothing in V1, V5, V6, V7 or V9; only V3 refuses it.
// The corpus would have certified the implementation that minted coins from
// nothing.
//
// The gap is one-sided. Every invalid vector states that a rejection *happens*;
// what a conformance corpus needs against an omitted rule is a block that is
// valid in every other respect, so that an implementation missing the rule
// accepts it. Each vector below is that shape, and sim's
// TestEveryInvalidVectorsRuleIsNecessary is what holds it: it deletes the
// recorded rule from the naive fold and requires the block to become valid.
//
// Three of §7's nine rules get no vector here.
// TestEveryVRuleIsSeparatedByTheCorpus in spec/invalid_rules_test.go carries
// the reasons in Go, armed rather than asserted, so that an era which makes any
// of them reachable fails instead of inheriting the exemption.
func vRuleVectors() []*spec.Vector {
	p := spec.Devnet()
	var out []*spec.Vector

	// V1 — chain binding. Nothing between the signature and the fold checks
	// which network a certificate was signed for except this clause.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		foreign := spec.Mainnet().ChainID
		cert := buildUncheckedEdited(p, &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}, func(c *types.Certificate) { c.ChainID = foreign })
		if cert.ChainID == p.ChainID {
			panic("gen: the chain id was not moved; this vector would assert nothing")
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-foreign-chain-id",
			"V1: a well-formed, correctly signed transfer that names mainnet's chain "+
				"id, included in a devnet block. Nothing else is wrong with it — the "+
				"signature verifies over its own body, the writes are exactly what the "+
				"program derives, and the deposit covers the ceiling — so an "+
				"implementation that treats the chain id as metadata rather than as a "+
				"validity rule applies it. That is cross-chain replay: the networks "+
				"share an address space and a signature scheme, so every certificate "+
				"ever signed on one of them would be a spendable certificate on the "+
				"other. The bytes need no special handling to arrive, either — "+
				"UnmarshalCertificate does not look at the chain id, which is why the "+
				"rule has to.",
			p, s.chain.State, b))
	}

	// V3 — program agreement. The rule the audit named, in the shape that
	// makes omitting it expensive.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		// The credit lands on an address the signer controls and the program
		// never mentions. It is a DELTA_ADD, so V4 requires no signature for
		// it; it names a fresh slot, so V1's ordering and V6's debit-coverage
		// clause have nothing to say; the address is an ordinary one-shot user
		// address, so V7 and V9 are satisfied. V3 is the only rule between this
		// certificate and a billion drops that never existed.
		forged := types.Write{
			Slot:  types.NativeBalanceSlot(alice.OneShot()),
			Op:    types.OpDeltaAdd,
			Value: drops(1_000_000_000),
		}
		cert := buildUncheckedEdited(p, &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}, func(c *types.Certificate) { insertWrite(c, forged) })
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-write-the-program-does-not-derive",
			"V3: a one-move TRANSFER whose declared write set carries one write the "+
				"program does not derive — a DELTA_ADD of 1,000,000,000 drops to a "+
				"one-shot address the signer controls. This is the vector the corpus was "+
				"missing, and the reason it mattered: V3 is the only rule tying declared "+
				"writes to the program, and every other stateless rule passes this "+
				"certificate. DELTA_ADD needs no signature under V4, which requires a "+
				"key only for SET, DELTA_SUB and MARK_SPENT. The slot is fresh, so V6's "+
				"debit-coverage and burn clauses do not apply. The address is an "+
				"ordinary 0x01 user address, so V7 and V9 are satisfied. An "+
				"implementation that never wrote V3 applies this block and credits coins "+
				"that were never emitted; every other vector in this corpus would have "+
				"certified it.",
			p, s.chain.State, b))
	}

	// V4 — authorization. The debit is somebody else's.
	{
		s := newScenario(p)
		alice, bob := key(2), key(3)
		s.fund(alice.Persistent(), drops(900_000_000))
		// The program moves alice's coins and pays alice's deposit; the only
		// signature is bob's, over bob's own view of this exact body. So V2 is
		// satisfied — the signature verifies — and V4 is the rule that notices
		// the signer is not the payer.
		cert := buildUncheckedSigned(p, &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{bob},
		})
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-debit-nobody-authorised",
			"V4: a TRANSFER debiting alice, with a deposit debiting alice, carrying "+
				"one signature — bob's. Every byte of it is otherwise in order: the "+
				"signature verifies over this body (V2), the writes are exactly the "+
				"derivation (V3), and the deposit covers the ceiling (V5). V4 is the "+
				"rule that asks whether the signer is the payer, and here it is the "+
				"whole of the answer: an implementation that verifies signatures without "+
				"checking whose writes they authorise lets any signer spend any balance. "+
				"Note which half of V4 fires — sufficiency, not minimality; the corpus "+
				"does not separately pin the clause refusing a signature that authorises "+
				"nothing.",
			p, s.chain.State, b))
	}

	// V6 — self-consistency: a credit into the certificate's own burn.
	{
		s := newScenario(p)
		issuer, alice := key(5), key(2)
		s.fund(issuer.Persistent(), drops(3_000_000_000))
		s.fund(alice.OneShot(), drops(3_000_000_000))
		issue := s.build(&wallet.Builder{
			Params: p,
			Program: wallet.Issue(issuer.Persistent(), drops(1_000_000), 6,
				types.Hash{'C', 'A', 'P', 'Y'}, alice.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{issuer},
		})
		s.chain.MustAddBlock(s.payout(), issue)
		asset := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), 0)

		// A MINT whose destination is the one-shot cell paying for it. The
		// deposit cell is one-shot, so DeriveCert adds its MARK_SPENT — which
		// means this write set is exactly what the program derives and V3 has
		// no objection. The certificate is fully authorised, so V4 has none
		// either. What is wrong with it is a fact about two derived writes
		// standing beside each other, which is what V6 is for.
		balance := s.chain.State.Get(types.NativeBalanceSlot(alice.OneShot()))
		cert := buildUncheckedSigned(p, &wallet.Builder{
			Params:  p,
			Program: wallet.Mint(asset, alice.OneShot(), drops(10_000), drops(1_000_000), alice.PubKey()),
			TTL:     s.chain.NextHeight() + 5,
			Deposit: wallet.SweepDeposit(alice.OneShot(), alice.Persistent(), balance),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		})
		if err := validity.CheckDerivation(cert); err != nil {
			panic("gen: the V6 vector's write set is not the derivation, so V3 would " +
				"reject it first and the vector would pin the wrong rule: " + err.Error())
		}
		b, err := s.chain.Propose(s.payout())
		if err != nil {
			panic(err)
		}
		b.Certs = []*types.Certificate{cert}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		out = append(out, capture("invalid-mint-into-its-own-burn",
			"V6: a MINT whose destination is the one-shot cell that funds it. The "+
				"deposit cell is 0x01, so its MARK_SPENT is part of the derivation and "+
				"the declared write set is exactly what the program derives — V3 has no "+
				"objection, which is what lets this vector reach V6 at all, rather than "+
				"being caught earlier as most Era-0 self-consistency violations are. F8 "+
				"commits value writes and burns together, so the minted balance lands in "+
				"a cell whose authority is already gone: an implementation that omits V6 "+
				"applies this certificate, reports it APPLIED with an ordinary refund, "+
				"and destroys the minted supply against a cap that has already counted "+
				"it. It is the write-side twin of the refund-into-own-mark-spent vector "+
				"(F-FOLD-1), one write earlier.",
			p, s.chain.State, b))
	}

	return out
}

// ---------------------------------------------------------------------------
// Four measured gaps in what the corpus binds
// ---------------------------------------------------------------------------
//
// Each vector below closes a measured gap of the same shape: a rule this tree
// enforces and this corpus does not separate, so that a second implementation
// omitting the rule replays the corpus green. The standard every one of them is
// held to is *a vector that passes both ways adds nothing* — so each was shown
// to fail against a verifier missing exactly its clause, and to pass against
// the one that has it. What is here is the construction that makes those probes
// possible; each function's own comment states which mutant it separates.
//
// They are appended after the V-rule separators, for the reason the testnet
// genesis and those separators are: a vector's filename prefix is its position
// in this list, so a vector added to a corpus that is already cited by number
// takes a fresh index rather than renumbering anything.

// spentRegistryBoundaryVector closes the first of the spent-registry gaps: a
// committed root taken over a NON-EMPTY spent registry.
//
// # What was measured
//
// Every committed state root in this corpus was taken over an EMPTY spent
// registry, so `spent_root` was the constant `list_root([], 1)` in every
// artefact this project publishes. Nothing committed anywhere exercised the
// spent-leaf tag `zcd/spentleaf/v1`, the registry's sort order, the spent
// subtree's padding, or its `nextPow2` capacity rule. A second implementation
// that got any of them wrong passed 100% of the corpus and then diverged at
// F14 the first time an epoch boundary landed with any address ever burned —
// which, since mainnet epochs are 2,880 blocks and registry entries are never
// pruned (R1-C3-iii), is the first day of real traffic. The past tense is what
// this function changes; every sentence above is about the corpus without it.
//
// Note what "measured" means here, because it is stronger than a green run. The
// three mutants that separate this vector — a moved spent-leaf tag, a reversed
// registry order, a shifted capacity — were not merely unobserved by the old
// corpus, they were unobservABLE in it. All nine of its committed roots had an
// empty registry, so no spent leaf was ever hashed for the tag to be wrong on,
// there was no pair of entries for an order to exist between, and
// nextPow2(0) = nextPow2(1) = 1 leaves the capacity rule with one input. None of
// the three could have failed.
//
// # Why TWO entries and not one
//
// One entry would close the tag and leave the comparator exactly where it was.
// A single-leaf registry roots at capacity 1, where the tree is one leaf and
// no internal node, so no ordering decision is taken and no padding chunk is
// hashed: a reversed comparator computes the identical root. Two entries is the
// smallest registry on which the sort order is observable at all, and the
// smallest on which the capacity rule stops being `nextPow2(1) = 1`. The
// generator asserts the count rather than trusting the scenario.
//
// # What this vector does NOT reach, stated beside it
//
// Two entries pin the order of two addresses and a depth-1 tree. They do not
// pin the padding of a partially filled subtree (a registry of 5 padding to 8),
// nor any capacity above 2. Those are held by core/state's differential against
// core/state/naive, which is the second half of the same finding and is
// already in the tree.
// This vector is the half of the finding that had to be a *committed artefact*,
// because a second implementation replays the corpus and does not run our tests.
func spentRegistryBoundaryVector() *spec.Vector {
	p := spec.Devnet()
	s := newScenario(p)
	alice, bob := key(2), key(3)
	s.fund(alice.Persistent(), drops(900_000_000))

	// One RETIRE burning two one-shot addresses. RETIRE is whitepaper §4's
	// state-compaction verb and derives one MARK_SPENT per address, so the two
	// registry entries arrive by the ordinary route rather than by seeding the
	// pre-state — which matters, because a seeded registry would state what the
	// root is taken over and not that the fold is what puts entries there.
	retire := s.build(&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(alice.OneShot(), bob.OneShot()),
		TTL:     s.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		// Each burned address authorises its own MARK_SPENT (V4), and alice's
		// key also covers the deposit cell, so both signatures are required and
		// neither is spare — V4's minimality clause would refuse a third.
		Signers: []*wallet.Key{alice, bob},
	})
	s.chain.MustAddBlock(s.payout(), retire)
	if n := s.chain.State.SpentCount(); n != 2 {
		panic(fmt.Sprintf("spent-registry boundary vector: the registry holds %d entries, not 2; "+
			"below two the comparator is unbound and the vector would pin the tag alone", n))
	}

	// Walk to the block before an epoch boundary, then capture the boundary
	// block: B9 sets the state root only there, so this is the only height at
	// which the registry is inside a commitment at all.
	for s.chain.NextHeight()%p.EpochLength != 0 {
		s.chain.MustAddBlock(s.payout())
	}
	b, err := s.chain.Propose(s.payout())
	if err != nil {
		panic(err)
	}
	v := capture("epoch-boundary-over-a-spent-registry",
		"The first committed state root in this corpus taken over a NON-EMPTY spent "+
			"registry. Two one-shot addresses are burned by a RETIRE several "+
			"blocks earlier, and this epoch-boundary block commits "+
			"state_root = blake3(\"zcd/stateroot/v1\" || cell_root || spent_root) with "+
			"spent_root a two-leaf tree rather than the constant list_root([], 1) every "+
			"other post_root here is taken over. Two entries rather than one is the "+
			"point: a one-entry registry roots at capacity 1, where there is no internal "+
			"node and no ordering decision, so a reversed comparator computes the same "+
			"value. At two, the spent-leaf tag, the address ordering and the nextPow2 "+
			"capacity are all inside the commitment. An implementation that tags a spent "+
			"leaf differently, keeps the registry in insertion order, or gives the "+
			"subtree a fixed capacity replays every other vector in this corpus green "+
			"and forks here.",
		p, s.chain.State, b)
	if v.Expect.PostRoot == "" {
		panic("spent-registry boundary vector: no post_root was committed, so the registry " +
			"is inside no commitment and the vector pins nothing")
	}
	if n := len(v.Expect.Post.Spent); n != 2 {
		panic(fmt.Sprintf("spent-registry boundary vector: the committed post state carries %d "+
			"registry entries, not 2", n))
	}
	return v
}

// assetWhitelistVector is the golden vector the asset-id whitelist rule owes:
// the rule landed first and the committed artefact that separates it was
// deliberately deferred to this regeneration pass rather than forgotten.
//
// # The rule
//
// deriveTransfer whitelists a move's asset id: it must be types.NativeAsset or
// an address of version AddrVersionAsset, and anything else is ErrBadAsset,
// forwarded by CheckDerivation as V3. Before that rule the field was validated by
// nothing at all — deriveTransfer tested the amount, Src, Dst and the self-move
// and never looked at it, types.UnmarshalMove copies 32 raw bytes, and V9
// whitelists the *holder* half of a balance slot while the asset half is hashed
// into the Word.
//
// # Why the id is a one-shot address
//
// It has to be a version V9 admits and no asset can carry. A 0x04 id would be
// refused by V9 as well, so a vector built on one would separate the asset
// whitelist from nothing — it would ride on the version whitelist. 0x01 is
// admitted by V9, is well-formed, and is what core/validity's own separating
// input at (deriveTransfer, ErrBadAsset) uses.
//
// # Why the declared body is a legitimate derivation, re-keyed
//
// This is the part that makes the vector separate rather than merely fail. If
// the declared reads and writes were the ones a NATIVE transfer derives, an
// implementation missing the whitelist would derive the bad-asset slots, find
// they do not match the declaration, and reject by V3 anyway — for a different
// reason, with the vector none the wiser. So the body is built by deriving the
// identical one-move transfer of a genuine 0x03 asset id through
// validity.DeriveCert and substituting the asset in the derived slots: it is
// exactly what deriveTransfer WOULD produce for this program if the id were
// admissible. Against this tree the whitelist refuses it; against a tree with
// the whitelist deleted the derivation succeeds, matches the declaration, and
// the block is valid.
func assetWhitelistVector() *spec.Vector {
	p := spec.Devnet()
	s := newScenario(p)
	alice, bob := key(2), key(3)
	s.fund(alice.Persistent(), drops(900_000_000))

	src, dst := alice.Persistent(), bob.Persistent()
	amount := drops(1_000_000)
	badAsset := alice.OneShot()
	if badAsset[0] != crypto.AddrVersionOneShot {
		panic("gen: the asset id is not a one-shot address")
	}
	if !crypto.IsKnownAddressVersion(badAsset) {
		panic("gen: the asset id names a version V9 refuses, so this vector would ride on " +
			"the version whitelist instead of separating the asset whitelist")
	}

	// The control derivation: the same transfer of an id that IS admissible,
	// through the shipped derivation rather than by hand.
	control := types.DeriveAssetAddress(p.ChainID, src, 7)
	reads, writes, err := validity.DeriveCert(
		wallet.Tip(control, src, dst, amount), p.ChainID, 0, src)
	if err != nil {
		panic("gen: the control derivation was refused: " + err.Error())
	}
	moved := retargetAsset(reads, writes, control, badAsset)
	if moved != len(reads)+len(writes) {
		panic(fmt.Sprintf("gen: re-keying the control derivation moved %d of %d slots, so the "+
			"declared body is not what a whitelist-free derivation produces",
			moved, len(reads)+len(writes)))
	}

	cert := buildUncheckedEdited(p, &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(control, src, dst, amount),
		TTL:     s.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(src, src),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}, func(c *types.Certificate) {
		c.Program.Transfer.Moves[0].Asset = badAsset
		c.Reads = reads
		c.Writes = writes
	})
	// The term must be the whitelist and not a mismatch between the declaration
	// and the derivation. Both are reported as V3, and only one of them is what
	// this vector is about.
	if derr := validity.CheckDerivation(cert); !errors.Is(derr, validity.ErrBadAsset) {
		panic(fmt.Sprintf("gen: the asset-whitelist vector is refused by %v rather than by "+
			"ErrBadAsset; it would record V3 for the wrong term", derr))
	}

	b, err := s.chain.Propose(s.payout())
	if err != nil {
		panic(err)
	}
	b.Certs = []*types.Certificate{cert}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	return capture("invalid-transfer-of-a-non-asset-id",
		"V3, at deriveTransfer's asset whitelist. A one-move TRANSFER "+
			"whose Asset is a well-formed 0x01 one-shot address: a version V9 admits and "+
			"no asset can ever carry. Everything else about the move is in order — a "+
			"positive amount, two distinct persistent addresses, no self-move — and the "+
			"declared reads and writes are exactly what the derivation produces for this "+
			"program once the id is admitted, so nothing but the whitelist stands between "+
			"this certificate and a consensus slot keyed by 32 attacker-chosen bytes. A "+
			"0x04 id would have been refused by V9 as well and would have separated the "+
			"asset whitelist from nothing. An implementation that omits the whitelist "+
			"derives this certificate, finds the declaration matches, and accepts the "+
			"block.",
		p, s.chain.State, b)
}

// sigCeilingVector is the corpus's statement of B18, the per-block signature
// ceiling added before the freeze -- and it is what this corpus's B5 vector
// became, on the same block, for a reason worth stating rather than hiding in
// a rename.
//
// # Why this vector used to pin B5, and why it cannot any more
//
// It was built as the first block in this corpus refused by B5, the hard sequential
// ceiling SeqGasBurst(T) = 4T, out of the gas-densest family the Era-0 program
// set admits: RETIRE of fifteen one-shot addresses paying its deposit from a
// sixteenth. That family carries SIXTEEN SIGNATURES per certificate, and 4T is
// reached only by enough of them to declare far more signatures than
// max_sigs_per_block_genesis scaled to the same T admits. B18 is checked before
// the loop that verifies a signature -- which is the whole of the rule, since a
// ceiling consulted after the work it bounds bounds nothing -- so it is checked
// before B5, and that block is now a B18 block.
//
// The corpus therefore loses its B5 vector and gains a B18 one, on the same
// shape and at the same seeded T. That is a real cost, recorded rather than
// glossed: core/fold's TestB18BindsBeforeB5OnTheGasDensestFamily carries the
// measurement, including the part this file must not overstate -- B5 is
// unreachable *on this family*, nobody has taken a census of the shape space,
// and B5 therefore stays a live rule a second implementation must enforce with
// no vector to catch it, exactly like B11 and B16.
//
// # The witness, and why it is cheap
//
// The lever is the one 033 and 044 already pull: T is read from the
// pre-state cell at every height past 0, and every ceiling that could answer
// first scales from the same T. At T = T0/64 the signature ceiling is 93, so
// six certificates of sixteen signatures each cross it well inside every other
// ceiling.
//
// # The assertions are load-bearing
//
// The count is derived from the ceiling rather than written down, and every
// other ceiling is asserted clear against itself rather than against a
// remembered margin. **The sequential-gas assertion is the sharp one**: the
// block sits inside B5's 4T bound but ABOVE the 2T soft threshold, which is a
// forfeiture and not a rejection -- that is what keeps the vector single-rule
// rather than over-determined. A parameter change that pushed it past 4T would
// make the block break two rules, and this function fails the build instead of
// emitting it.
func sigCeilingVector() *spec.Vector {
	p := spec.Mainnet()
	// A bare chain rather than newScenario: nothing here needs a funded miner
	// -- the block is refused by a block rule before any certificate is folded
	// -- and mining until funded fills mainnet's coinbase maturity ring, which
	// would put two hundred cells into `pre` and two hundred more into `post`
	// for no statement at all.
	c := harness.MustNew(p)
	lowT := p.SeqGasTargetGenesis / 64
	sigCeiling := p.MaxSigsPerBlock(lowT)

	ttl := c.NextHeight() + 5
	refund := key(4).Persistent()
	build := func(i uint64) *types.Certificate {
		addrs := make([]types.Address, 0, 15)
		signers := make([]*wallet.Key, 0, 16)
		for j := uint64(0); j < 15; j++ {
			k := indexedKey(0xb5, i*16+j)
			addrs = append(addrs, k.OneShot())
			signers = append(signers, k)
		}
		deposit := indexedKey(0xb5, i*16+15)
		cert, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(addrs...),
			TTL:     ttl,
			Deposit: wallet.SweepDeposit(deposit.OneShot(), refund, drops(1_000_000)),
			FeeBid:  bid(),
			Signers: append(signers, deposit),
		}).Build()
		if err != nil {
			panic(err)
		}
		return cert
	}

	// One certificate first, so the count is derived from what the shape
	// declares rather than written down: n+1 of them is the smallest block of
	// this family strictly above the ceiling.
	one := build(0)
	perCertSigs := uint64(len(one.Sigs))
	n := int(sigCeiling/perCertSigs) + 1
	certs := make([]*types.Certificate, 0, n)
	certs = append(certs, one)
	for i := 1; i < n; i++ {
		certs = append(certs, build(uint64(i)))
	}

	var seqGas, parGas, sigs uint64
	for _, cert := range certs {
		seqGas += cert.SeqGas(p)
		parGas += cert.ParGas(p)
		sigs += uint64(len(cert.Sigs))
	}
	if sigs <= sigCeiling {
		panic(fmt.Sprintf("sig-ceiling vector: %d certificates declare %d signatures, still "+
			"inside the ceiling of %d at T=%d", len(certs), sigs, sigCeiling, lowT))
	}
	b, err := c.Propose(key(1).Persistent(), certs...)
	if err != nil {
		panic(err)
	}
	if burst := p.SeqGasBurst(lowT); seqGas > burst {
		panic(fmt.Sprintf("sig-ceiling vector: %d certificates declare %d sequential gas against "+
			"a 4T bound of %d at T=%d, so the block breaks B5 as well and the vector would be "+
			"over-determined", len(certs), seqGas, burst, lowT))
	}
	if size, limit := b.SizeBytes(), p.BlockByteLimit(lowT); size > limit {
		panic(fmt.Sprintf("sig-ceiling vector: block of %d bytes exceeds the byte ceiling of %d "+
			"at T=%d, so B13 rejects it before B18", size, limit, lowT))
	}
	if ceiling := p.MaxCertsPerBlock(lowT); len(certs) > ceiling {
		panic(fmt.Sprintf("sig-ceiling vector: %d certificates exceeds the count ceiling of %d "+
			"at T=%d, so B12 rejects it before B18", len(certs), ceiling, lowT))
	}
	if ceiling := p.ParGasLimit(lowT); parGas > ceiling {
		panic(fmt.Sprintf("sig-ceiling vector: %d parallel gas exceeds the parallel ceiling of "+
			"%d at T=%d, so B6 rejects it before B18", parGas, ceiling, lowT))
	}
	// Seeded after Propose, for the reason certCeilingVector gives: the proposer
	// builds against the live ceiling and would refuse to emit this block
	// itself. What the vector states is what the FOLD does with a block that
	// already exists -- the half a peer cannot opt out of.
	c.State.Set(types.SeqGasTargetSlot(), u256.FromUint64(lowT))

	return capture("invalid-signature-count-over-the-ceiling",
		fmt.Sprintf("B18, the per-block signature ceiling MaxSigsPerBlock(T). "+
			"T is seeded to %d, one sixty-fourth of T0, so the ceiling is %d and this block's "+
			"%d certificates declare %d signatures between them. THE RULE IS CHECKED BEFORE "+
			"ANY SIGNATURE IS VERIFIED, which is the whole of it: an implementation that "+
			"counts after verifying has bounded nothing, and this block is the input that "+
			"says so -- it costs a conforming node one linear pass over certificate headers "+
			"and a non-conforming one %d strict Ed25519 verifications. Every other ceiling "+
			"that scales with T is clear: %d sequential gas against a 4T bound of %d, above "+
			"the 2T soft threshold of %d, which is a forfeiture and not a rejection; %d bytes "+
			"against %d; %d certificates against %d; and %d parallel gas against %d -- so B18 "+
			"is the rule that rejects, not B5, B12 or B13. Every certificate is a RETIRE of "+
			"fifteen one-shot addresses paying its deposit from a sixteenth, the gas-densest "+
			"family the Era-0 program set admits; none is hand-rolled. THIS BLOCK USED TO BE "+
			"THE CORPUS'S B5 VECTOR: the same family reaches 4T only by declaring far "+
			"more signatures than this ceiling admits, so B18 answers first and B5 is no "+
			"longer reachable on it. B5 remains a rule an implementation must enforce with no "+
			"vector to catch it, like B11 and B16.",
			lowT, sigCeiling, len(certs), sigs, sigs,
			seqGas, p.SeqGasBurst(lowT), p.SeqGasLimit(lowT),
			b.SizeBytes(), p.BlockByteLimit(lowT), len(certs), p.MaxCertsPerBlock(lowT),
			parGas, p.ParGasLimit(lowT)),
		p, c.State, b)
}

// mixedOrderSignerVector is one golden vector for V2's torsion clause, and only
// that one.
//
// # What was measured
//
// The fourth external audit mutated core/crypto.VerifyStrict and replayed the
// corpus. Deleting isTorsionFree left it green. Deleting both isCanonicalEncoding
// calls and the `st != decodeCanonical` gate left it green. Deleting all four,
// leaving ed25519.Verify plus isLowOrder, left it green. Only deleting
// isLowOrder failed anything — 031-invalid-low-order-signer. So the corpus
// separated "bare ed25519.Verify" and nothing else, and four of V2's five
// strictness clauses were bound by no vector at all.
//
// # Why one vector and not three
//
// The audit's findings asked for three, and two of them cannot exist. A
// non-canonical public key encoding is one of the nineteen values y ∈ {p,…,p+18};
// every one that is on the curve and not low order is an ordinary point whose
// discrete log nobody knows, so a signature that *verifies* under one cannot be
// exhibited. And cofactorless verification reconstructs R and byte-compares
// its re-encoding, so ed25519.Verify refuses every non-canonical R before our
// clause is consulted. A vector for either would pass against a verifier that has
// the clause AND against one that does not, which is the definition of pinning
// nothing. spec/README.md's "What the corpus cannot bind" records both, with the
// entailment a differently shaped implementation loses.
//
// Torsion is the one that is bindable, and it is also the one that carries the
// fork: a small-order blocklist plus a cofactored batch verifier — what a
// reimplementer naturally builds — passes every other vector here and then
// disagrees with this tree on a certificate neither side can call invalid.
//
// # Why V2 and not "the same rule twice"
//
// The corpus already records V2, at 031. This project's standing decision
// declines vectors below rule granularity, and this vector does not ask for an exception
// to it: the decision is that a rule gets a vector, not that a rule gets ONE
// vector, and 031 does not make the torsion clause binding — the audit proved
// that by deleting the clause and watching 031 pass. What is added here is a
// second input separating the same rule at a place the first cannot reach, which
// is the same thing 044 is to 033 for B12.
func mixedOrderSignerVector() *spec.Vector {
	p := spec.Devnet()
	s := newScenario(p)

	mixed := newMixedOrderKey(0xa7)
	signer := crypto.AddressFromPubKey(crypto.AddrVersionPersistent, mixed.pub)
	s.fund(signer, drops(900_000_000))

	bob := key(3)
	cert := buildUnchecked(p, &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, signer, bob.Persistent(), drops(1_000_000)),
		TTL:     s.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(signer, signer),
		FeeBid:  bid(),
	}, []types.Sig{{PubKey: mixed.pub}})
	// The signing message excludes the signature list, so forging after the
	// certificate is otherwise finished changes nothing the signature covers.
	cert.Sigs[0].Sig = mixed.forge(cert.SigningMessage(p))

	// The vector's entire content, asserted here rather than hoped for. The
	// standard library must accept this signature and VerifyStrict must refuse
	// it; either half missing and the vector states nothing.
	if !ed25519.Verify(ed25519.PublicKey(mixed.pub[:]), cert.SigningMessage(p), cert.Sigs[0].Sig[:]) {
		panic("gen: the standard library rejects the forged signature, so the vector would " +
			"separate a reduced verifier from nothing")
	}
	if crypto.VerifyStrict(mixed.pub, cert.SigningMessage(p), cert.Sigs[0].Sig) {
		panic("gen: VerifyStrict accepted the mixed-order key; the torsion clause is gone")
	}
	if err := validity.Check(cert, p); validity.Rule(err) != "V2" {
		panic(fmt.Sprintf("gen: the mixed-order certificate is refused by %v, not V2; some "+
			"other rule reaches it first and the vector would pin that instead", err))
	}

	b, err := s.chain.Propose(s.payout())
	if err != nil {
		panic(err)
	}
	b.Certs = []*types.Certificate{cert}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	return capture("invalid-mixed-order-signer",
		"V2's torsion clause, which is the half a small-order blocklist can never reach "+
			"The public key is A = A' + T with A' of large order and T of order "+
			"eight: it is NOT small order, so no blocklist of any finite size names it — "+
			"there are about 2^252 such keys — and crypto.IsSmallOrderPubKey says so. The "+
			"signature is ground so that the torsion residue T_r + [h]T vanishes, which "+
			"makes the cofactorless equation [S]B = R + [h]A close: the Go standard "+
			"library's ed25519.Verify ACCEPTS it, and so does any cofactored batch "+
			"verifier. This tree refuses it because V2 requires the public key to lie in "+
			"the prime-order subgroup, tested as [L]A = O. docs/ARCHITECTURE.md §7 states "+
			"the hazard in its own words — 'a small-order blocklist is not a weaker "+
			"version of this rule, it is a different and insufficient one' — and this is "+
			"the artefact that makes the sentence binding. 031-invalid-low-order-signer "+
			"does not: deleting the torsion test leaves 031 passing, which is how the gap "+
			"was measured. An implementation built as a blocklist plus a cofactored batch "+
			"path applies this block and forks on a certificate neither side can call "+
			"invalid.",
		p, s.chain.State, b)
}

// coinbaseBurnVector is the first artefact anywhere in this tree that reaches
// F12's burn arm.
//
// # The arm, and why nothing reached it
//
// rollCoinbaseRing releases the reward written CoinbaseMaturity blocks ago
// unless the payee has burned its signing authority in the meantime, in which
// case the reward is added to res.Burned and no balance cell is written at all.
// The arm was unreached, and not by oversight: every mining payout in this tree
// is a persistent address — the harness pays key(n).Persistent(), spec/gen pays
// scenario.payout(), and cmd/zycordd refuses anything else at the command line
// (TestParsePayoutRequiresPersistent) — and a persistent address can never
// enter the spent registry, so the question the arm asks is never asked.
// sim/refold's second statement of F12 is dead for the same reason, so the
// differential cannot see it either: both folds agree by never being asked,
// which is the shape earlier audits of this package already found: two
// implementations agreeing because neither is ever asked the question.
//
// # Why the ordering is the thing being pinned
//
// F12 runs after the certificate loop, so a certificate in THIS block that
// burns the payee is seen by the release side of the ring in the same block.
// docs/RUNNING.md states the operational consequence — the block carrying the
// spend is already the first block that loses money — and that sentence is only
// true because of the order. A fold that rolled the ring before the
// certificates would find the payee unspent, credit the reward, and disagree
// with this tree about a balance cell.
//
// The pre-state assertion below is what makes that a separation rather than a
// coincidence: the payee is in the ring, with a non-zero amount, and is NOT yet
// spent when the block arrives. Under either ordering the block is valid; the
// two orderings differ in matured, in burned, and in one cell of the state.
//
// # Why an epoch boundary
//
// So the disagreement is inside a commitment rather than only in the reported
// fields. The block is at height EpochLength, so B9 puts a state root in the
// header and F14 compares it: an implementation that credited the reward
// commits a different root and is refused by its own peers one block later,
// rather than drifting silently.
func coinbaseBurnVector() *spec.Vector {
	p := spec.Devnet()
	s := newScenario(p)

	victim := key(7)
	payee := victim.OneShot()
	if payee[0] != crypto.AddrVersionOneShot {
		panic("gen: the payout address under test is not a one-shot address, so no " +
			"certificate could burn it and the vector would pin nothing")
	}
	if !crypto.IsUserAddress(payee) {
		panic("gen: B11 refuses this payout address, so the block that writes it into the " +
			"ring cannot be mined")
	}

	// The block under test sits on the first epoch boundary reachable after the
	// scenario is funded; the reward it fails to release was written
	// CoinbaseMaturity blocks earlier.
	vectorHeight := p.EpochLength
	payoutHeight := vectorHeight - p.CoinbaseMaturity
	if payoutHeight <= s.chain.Height() {
		panic(fmt.Sprintf("gen: the paying height %d is at or below the funded tip %d, so the "+
			"one-shot payout cannot be mined into the ring", payoutHeight, s.chain.Height()))
	}
	for s.chain.NextHeight() < payoutHeight {
		s.chain.MustAddBlock(s.payout())
	}
	s.chain.MustAddBlock(payee)
	for s.chain.NextHeight() < vectorHeight {
		s.chain.MustAddBlock(s.payout())
	}

	index := vectorHeight % p.CoinbaseMaturity
	pending := s.chain.State.Get(types.PendingCoinbaseAmountSlot(index))
	if pending.IsZero() {
		panic("gen: the ring slot this block rolls is empty, so F12's release side is not " +
			"entered and the vector says nothing about either arm")
	}
	if got := s.chain.State.Get(types.PendingCoinbaseAddrSlot(index)); !got.Eq(u256.FromBytes(payee)) {
		panic(fmt.Sprintf("gen: the ring slot this block rolls names %s, not the one-shot "+
			"payout %s", got.String(), u256.FromBytes(payee).String()))
	}
	// The load-bearing precondition. If the payee were already spent when the
	// block arrived, the burn would happen under BOTH orderings and the vector
	// would separate nothing.
	if s.chain.State.IsSpent(payee) {
		panic("gen: the payee is already spent in the pre-state, so the reward is burned " +
			"under any ordering of F12 against the certificate loop")
	}

	retire := s.build(&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(payee),
		TTL:     s.chain.NextHeight() + 5,
		// A persistent deposit cell: the certificate must survive to burn the
		// payee, and a one-shot deposit would put a second address into the
		// registry and a sweep into the outcome for no statement at all.
		Deposit: wallet.SelfDeposit(s.payout(), s.payout()),
		FeeBid:  bid(),
		// The victim's key authorises the MARK_SPENT of its own one-shot
		// address (V4) and the miner's covers the deposit debit; V4's
		// minimality clause would refuse a third.
		Signers: []*wallet.Key{s.miner, victim},
	})

	// The burn this block reports is the certificate's base fee plus the
	// forfeited reward, and the fee half is derived from the vector's own
	// pre-state rather than remembered, so the assertion below stays exact if
	// the fee schedule moves.
	seqBaseFee := s.chain.State.Get(types.SeqBaseFeeSlot())
	parBaseFee := s.chain.State.Get(types.ParBaseFeeSlot())
	_, certBurn, _, ok := retire.Fees(p, seqBaseFee, parBaseFee)
	if !ok {
		panic("gen: the retire certificate's fee arithmetic overflows")
	}
	wantBurn, over := certBurn.Add(pending)
	if over {
		panic("gen: the expected burn overflows 256 bits")
	}

	b, err := s.chain.Propose(s.payout(), retire)
	if err != nil {
		panic(err)
	}
	v := capture("coinbase-burned-into-a-payee-spent-in-the-same-block",
		fmt.Sprintf("F12's burn arm, which no other vector and no test in this tree reaches "+
			"at all. The block %d blocks below this one paid its producer share to a 0x01 "+
			"one-shot address, so the maturity ring holds (that address, %s) when this block "+
			"arrives; consensus permits it, because B11 admits any user address and the 0x02 "+
			"requirement is a wallet-side guard rather than a rule. A RETIRE in THIS block "+
			"burns that address, and F12 rolls the ring AFTER the certificate loop — so the "+
			"reward is destroyed rather than credited: matured is zero and burned carries it. "+
			"The ordering is the whole content. A fold that rolled the ring first would find "+
			"the payee unspent (it is unspent in the pre-state here, which is what makes the "+
			"two orderings distinguishable at all), credit %s to a balance cell, and report a "+
			"different matured, a different burned and a different state root — committed, "+
			"because this block is on an epoch boundary. docs/RUNNING.md's operator-facing "+
			"claim, that the block carrying the spend is already the first block that loses "+
			"money, is true only under this order.",
			p.CoinbaseMaturity, pending.String(), pending.String()),
		p, s.chain.State, b)

	if !v.Expect.Valid {
		panic(fmt.Sprintf("gen: the coinbase-burn block is invalid (%s); the vector would pin "+
			"a block rule instead of F12", v.Expect.Reason))
	}
	if v.Expect.PostRoot == "" {
		panic("gen: no state root is committed here, so the divergence this vector states " +
			"would live only in the reported fields")
	}
	if len(v.Expect.Outcomes) != 1 || v.Expect.Outcomes[0].Outcome != fold.Applied.String() {
		panic(fmt.Sprintf("gen: the RETIRE did not apply (%v), so the payee is not burned and "+
			"F12 takes its release side", v.Expect.Outcomes))
	}
	if v.Expect.Matured != "0" {
		panic(fmt.Sprintf("gen: the ring released %s; the burn arm was not taken and this "+
			"vector states the opposite of what it claims", v.Expect.Matured))
	}
	if v.Expect.Burned != wantBurn.String() {
		panic(fmt.Sprintf("gen: burned is %s, want %s = the certificate's base fee %s plus the "+
			"forfeited reward %s", v.Expect.Burned, wantBurn.String(), certBurn.String(), pending.String()))
	}
	if cellPresent(v.Expect.Post, types.NativeBalanceSlot(payee)) {
		panic("gen: the payee holds a native balance cell after the block, so the reward was " +
			"credited somewhere after all")
	}
	if !spentPresent(v.Expect.Post, payee) {
		panic("gen: the payee is not in the committed spent registry, so nothing in the " +
			"post-state says why the reward was destroyed")
	}
	return v
}

// burstForfeitureRoundingVector is the first vector that reaches F11's
// burst valve at all, and it reaches it at a point where the valve's two nested
// floors and the single exact division disagree.
//
// # The rule
//
// A block whose INCLUDED sequential gas exceeds 2T forfeits the producer's
// block revenue -- its subsidy share plus the block's fees --
// quadratically in the excess, and the forfeiture is computed as
//
//	floor(floor(producer × excess / 2T) × excess / 2T)
//
// which is not the same integer as floor(producer × excess² / (2T)²). The
// two-step form is deliberate — (2T)² leaves 64 bits once T has grown for
// decades and u256.MulDiv64's divisor is a uint64 — and it rounds in the
// producer's favour, deterministically, on every node. docs/ARCHITECTURE.md §8
// states it normatively.
//
// # Why no vector reached it, and why one can now
//
// The cost at stock mainnet parameters was first measured as 354 RETIRE
// certificates and about 3.7 MB of JSON. Both figures predate the gas-schedule
// respin: §21 and
// TestBurstValveAtGenesisParameters carry the current ones, 284 certificates in
// a 1.12 MB block, and the JSON estimate beside them is scaled rather than
// measured. Either way it is the cost of crossing 2T at T = T₀, and not the
// cost of crossing 2T — T is read from a pre-state cell at every height past 0,
// which a vector carries and spec.ParamsFor never overwrites, and every ceiling
// that could answer first scales from that same T. It is the lever 033, 044 and
// 061 already pull. One certificate of the gas-densest Era-0 family crosses 2T
// at any T in a band this function derives rather than assumes.
//
// # Why the certificate is dropped, and why that is the case the rule is about
//
// The chain is bare, so the certificate's one-shot deposit cell is empty and
// F3 drops it. That is deliberate twice over. It keeps the vector small, and it
// puts the block on exactly the shape whitepaper §8.1 names when it says the
// valve is assessed on included gas, applied and skipped alike, so that "the
// excess cannot be stuffed with manufactured conflict at a discount". A dropped
// certificate pays no fee, so the block's ENTIRE burn is the forfeiture, and
// `burned` in the emitted vector is the forfeited integer itself rather than a
// sum something else contributes to.
//
// # How T is chosen, and what that claim is
//
// The band is derived from the shape: 2T < seqGas ≤ 4T bounds T to
// [⌈seqGas/4⌉, ⌊(seqGas−1)/2⌋]. The byte, count and parallel ceilings are then
// applied to it and, at this shape, cut nothing — the filtered band is the raw
// one, all 2,825 values. The filter is kept anyway, and it is not decoration:
// a change to the shape, to the gas schedule or to a ceiling parameter can make
// one of them bind, and a T where it binds would produce a block some other
// rule rejects first. Inside the admissible band the function takes the T nearest the
// band's midpoint at which the two forms differ — the midpoint because both
// edges are degenerate: at the top the excess is a few gas units and at the
// bottom it equals 2T exactly, where the forfeiture is the whole producer share
// and the two forms agree by construction.
//
// That is an existential, in the shape PROTOCOL.md rule 21 asks for: at this
// shape the two forms differ at a counted subset of the admissible T, and this
// vector takes one of them. It is not a claim that they differ everywhere, and
// they demonstrably do not — at every T that divides the producer's share the
// first floor is exact and the two forms collapse, which is why T₀/64 and every
// other power-of-two divisor of T₀ is NOT usable here.
func burstForfeitureRoundingVector() *spec.Vector {
	p := spec.Mainnet()
	c := harness.MustNew(p)

	// One RETIRE of fifteen one-shot addresses paying its deposit from a
	// sixteenth: the gas-densest family the Era-0 program set admits, and the
	// same shape 061 uses, so the block is a shape wallets emit.
	addrs := make([]types.Address, 0, 15)
	signers := make([]*wallet.Key, 0, 16)
	for i := uint64(0); i < 15; i++ {
		k := indexedKey(0xf1, i)
		addrs = append(addrs, k.OneShot())
		signers = append(signers, k)
	}
	deposit := indexedKey(0xf1, 15)
	cert, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(addrs...),
		TTL:     c.NextHeight() + 5,
		Deposit: wallet.SweepDeposit(deposit.OneShot(), key(4).Persistent(), drops(1_000_000)),
		FeeBid:  bid(),
		Signers: append(signers, deposit),
	}).Build()
	if err != nil {
		panic(err)
	}
	seqGas, parGas := cert.SeqGas(p), cert.ParGas(p)

	b, err := c.Propose(key(1).Persistent(), cert)
	if err != nil {
		panic(err)
	}
	size := b.SizeBytes()

	subsidy := p.Emission(b.Header.Height)
	treasury := subsidy.MulDiv64(p.TreasuryShareBps, 10000)
	producer, under := subsidy.Sub(treasury)
	if under {
		panic("gen: the treasury share exceeds the subsidy")
	}
	share, ok := new(big.Int).SetString(producer.String(), 10)
	if !ok {
		panic("gen: the producer share does not parse as an integer")
	}

	// The admissible band, then the subset of it on which the vector has
	// something to say. Both are counted so the description can state the
	// existential rather than imply a maximum.
	var admissible, separating []uint64
	for t := (seqGas + 3) / 4; t <= (seqGas-1)/2; t++ {
		if seqGas <= p.SeqGasLimit(t) || seqGas > p.SeqGasBurst(t) {
			continue
		}
		if size > p.BlockByteLimit(t) || p.MaxCertsPerBlock(t) < 1 || parGas > p.ParGasLimit(t) {
			continue
		}
		// B18 joins the filter, and unlike the other three it BINDS
		// here: this certificate carries sixteen signatures, so every T below
		// max_sigs × T₀ / max_sigs_per_block_genesis is refused by the
		// signature ceiling before the fold reaches F11's valve at all. That
		// cuts the bottom off the admissible band rather than decorating it,
		// which is exactly what the paragraph above says the filter is for.
		if uint64(len(cert.Sigs)) > p.MaxSigsPerBlock(t) {
			continue
		}
		admissible = append(admissible, t)
		if twoFloors(share, t, seqGas).Cmp(oneDivision(share, t, seqGas)) != 0 {
			separating = append(separating, t)
		}
	}
	if len(admissible) == 0 {
		panic("gen: no T puts this shape inside the burst band with every other ceiling " +
			"clear, so the block cannot reach F11's valve at all")
	}
	if len(separating) == 0 {
		panic(fmt.Sprintf("gen: the two-floor forfeiture equals the single exact division at "+
			"all %d admissible T for this shape, so a vector built here would pass against an "+
			"implementation that collapses the two divisions", len(admissible)))
	}
	mid := (admissible[0] + admissible[len(admissible)-1]) / 2
	chosen := separating[0]
	for _, t := range separating {
		if diff(t, mid) < diff(chosen, mid) {
			chosen = t
		}
	}

	forfeit := twoFloors(share, chosen, seqGas)
	if forfeit.Cmp(share) >= 0 {
		panic("gen: the forfeiture is not smaller than the producer's share, so SatSub clamps " +
			"and the two arithmetics agree at zero")
	}
	// Seeded after Propose, for the reason 044 and 061 give: a proposer builds
	// against the live ceiling and would not emit this block itself. What the
	// vector states is what the FOLD does with a block that already exists.
	c.State.Set(types.SeqGasTargetSlot(), u256.FromUint64(chosen))

	v := capture("burst-forfeiture-where-two-floors-are-not-one-division",
		fmt.Sprintf("F11's burst valve, which no vector in this corpus reached before. "+
			"T is seeded to %d, so the soft ceiling is %d, the hard bound B5 rejects above is "+
			"%d, and this block's single certificate declares %d — inside the band where the "+
			"block is valid and the producer's block revenue -- its subsidy share plus the "+
			"block's fees -- is forfeited quadratically. The "+
			"forfeiture is TWO nested floors, floor(floor(base x excess / 2T) x excess / "+
			"2T) = %s, and NOT the single exact division floor(base x excess^2 / (2T)^2) = "+
			"%s -- where base is the subsidy share exactly, because the block's only "+
			"certificate is DROPPED and pays no fee, so including fees in the base adds "+
			"nothing here and what this vector separates is the rounding alone. "+
			"The two-step form is deliberate: (2T)^2 leaves 64 bits once T has grown for "+
			"decades, and it rounds in the producer's favour on every node. An implementation "+
			"that does the mathematically exact division replays every other vector in this "+
			"corpus green and disagrees here, in burned, in miner_reward and in the ring's "+
			"pending amount cell. The certificate is DROPPED — the chain is bare, so its "+
			"one-shot deposit cell is empty — which is what the rule is about: the valve is "+
			"assessed on INCLUDED gas, applied and skipped alike, so that the excess cannot be "+
			"stuffed with manufactured conflict at a discount. Nothing else in the block burns "+
			"anything, so burned is the forfeited integer itself. T is one of the %d values in "+
			"the %d-wide admissible band for this shape at which the two forms differ; at every "+
			"T that divides the producer's share the first floor is exact and they collapse, "+
			"which is why no power-of-two divisor of T0 can carry this statement.",
			chosen, p.SeqGasLimit(chosen), p.SeqGasBurst(chosen), seqGas,
			forfeit.String(), oneDivision(share, chosen, seqGas).String(),
			len(separating), len(admissible)),
		p, c.State, b)

	if !v.Expect.Valid {
		panic(fmt.Sprintf("gen: the burst-band block is invalid (%s); a block between 2T and "+
			"4T is valid and the valve prices it, so this vector would pin a block rule "+
			"instead of F11", v.Expect.Reason))
	}
	if v.Expect.SeqGasUsed <= p.SeqGasLimit(chosen) {
		panic(fmt.Sprintf("gen: %d included sequential gas is inside the soft ceiling of %d, "+
			"so the valve never fires", v.Expect.SeqGasUsed, p.SeqGasLimit(chosen)))
	}
	if len(v.Expect.Outcomes) != 1 || v.Expect.Outcomes[0].Outcome != fold.Dropped.String() {
		panic(fmt.Sprintf("gen: the certificate did not drop (%v), so it paid a base fee and "+
			"burned is no longer the forfeiture alone", v.Expect.Outcomes))
	}
	if v.Expect.Burned != forfeit.String() {
		panic(fmt.Sprintf("gen: burned is %s, and the two-floor forfeiture is %s; the vector "+
			"does not record the arithmetic it is named for", v.Expect.Burned, forfeit.String()))
	}
	if v.Expect.Burned == oneDivision(share, chosen, seqGas).String() {
		panic("gen: the emitted burn equals the single exact division, so this vector passes " +
			"against the implementation it exists to separate")
	}
	return v
}

// twoFloors is F11's forfeiture exactly as core/fold and sim/refold compute it:
// two successive floors, never one.
func twoFloors(producer *big.Int, t, seqGas uint64) *big.Int {
	limit := new(big.Int).SetUint64(2 * t)
	excess := new(big.Int).SetUint64(seqGas - 2*t)
	step := new(big.Int).Mul(producer, excess)
	step.Quo(step, limit)
	step.Mul(step, excess)
	return step.Quo(step, limit)
}

// oneDivision is the same quantity computed by the single exact division a
// second implementation with wide integers would reach for. It is what this
// vector exists to refuse.
func oneDivision(producer *big.Int, t, seqGas uint64) *big.Int {
	limit := new(big.Int).SetUint64(2 * t)
	excess := new(big.Int).SetUint64(seqGas - 2*t)
	num := new(big.Int).Mul(producer, new(big.Int).Mul(excess, excess))
	return num.Quo(num, new(big.Int).Mul(limit, limit))
}

func diff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// cellPresent reports whether a snapshot carries a value for one slot. The
// comparison is on the encoded pair spec.Snapshot writes, so it asks the
// question of the artefact rather than of the state it came from.
func cellPresent(ps spec.PreState, slot types.Slot) bool {
	addr, word := "0x"+hex.EncodeToString(slot.Addr[:]), "0x"+hex.EncodeToString(slot.Word[:])
	for _, c := range ps.Cells {
		if c.Addr == addr && c.Word == word {
			return true
		}
	}
	return false
}

// spentPresent reports whether a snapshot's registry names an address.
func spentPresent(ps spec.PreState, a types.Address) bool {
	want := "0x" + hex.EncodeToString(a[:])
	for _, got := range ps.Spent {
		if got == want {
			return true
		}
	}
	return false
}

// indexedKey is key() for the vectors that need more distinct signers than a
// single seed byte can supply. The seed is a domain byte followed by the index
// in little-endian, so it can never collide with key()'s repeated-byte seeds
// and never runs out.
func indexedKey(domain byte, n uint64) *wallet.Key {
	seed := make([]byte, 32)
	seed[0] = domain
	for i := 0; i < 8; i++ {
		seed[1+i] = byte(n >> (8 * i))
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}

// retargetAsset rewrites every balance slot keyed to `from` so that it is keyed
// to `to`, and reports how many it moved.
func retargetAsset(reads []types.Read, writes []types.Write, from, to types.Address) int {
	oldWord, newWord := types.BalanceWord(from), types.BalanceWord(to)
	moved := 0
	for i := range reads {
		if reads[i].Slot.Word == oldWord {
			reads[i].Slot.Word = newWord
			moved++
		}
	}
	for i := range writes {
		if writes[i].Slot.Word == oldWord {
			writes[i].Slot.Word = newWord
			moved++
		}
	}
	sort.Slice(reads, func(i, j int) bool { return reads[i].Slot.Less(reads[j].Slot) })
	sort.Slice(writes, func(i, j int) bool { return writes[i].Slot.Less(writes[j].Slot) })
	return moved
}
