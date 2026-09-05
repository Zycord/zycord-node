package sim_test

// The three block-shape ceilings this file is named for — B12's certificate
// count, B13's block size and B15's citation count — are stated twice, once in
// core/fold/blockrules.go and once in sim/refold's checkBlock, and until this
// file no run drove any of them to its boundary. One mutant turning all three
// comparisons in sim/refold from `>` into `>=` survived the whole ./sim suite.
//
// **These are not the class the twice-written-rule census is about, and the
// difference decides the instrument.** That census maps the rules whose
// boundary is unreachable at every shipped parameter set, where the honest
// instrument is a legal-but-unshipped witness supplying an antecedent. These
// three are the adjacent class: their boundaries are reachable at shipped
// parameters by integer arithmetic, so the instrument is an ordinary test and a
// witness would be a fixture pretending to be a measurement. **No parameter is
// modified anywhere in this file.** All three arms run spec.Devnet() or
// spec.Mainnet() exactly as shipped.
//
// The discipline is the B2 horizon sweep's, restated per arm below: state the
// reachable range of the compared quantity, state the two consecutive values
// that separate the rule, and state whether that pair lies inside the range.
//
// One quantity is state rather than a block field, and the B13 arm moves it:
// the sequential target T. That is not the substituted-subject defect, in which
// a fixture leaves the shipped ratio behind and measures a different protocol.
// The earlier sweep's elasticBase() sets the *parameter* seq_gas_target_genesis
// to 1,000 while leaving block_byte_limit_genesis at 2,500,000, moving the
// shipped ratio from 1.25 bytes per gas to 2,500 and reaching B5 and B6 only
// because of it. Here every parameter keeps its shipped value, the ratio
// between the byte ceiling and the certificate ceiling is exactly the shipped
// one because both scale from the same T, and T is set only to values inside
// [seq_gas_target_genesis, seq_gas_capacity] — the interval the epoch
// controller clamps it into, asserted in the arm.

import (
	"errors"
	"math/big"
	"sort"
	"testing"

	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/sim"
	"zycord/sim/harness"
	"zycord/sim/refold"
	"zycord/spec"
	"zycord/wallet"
)

// folds holds one chain fed to both implementations, the shape Runner.commit
// keeps: core/fold's state advances through harness.Chain, sim/refold's through
// its own State, and sim.Differential is the only thing that folds a block.
type folds struct {
	p     *params.Params
	chain *harness.Chain
	naive *refold.State
}

func newFolds(t *testing.T, p *params.Params) *folds {
	t.Helper()
	gb, _, err := genesis.Build(p)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	naive := refold.New()
	if _, err := refold.ApplyBlock(naive, gb, p); err != nil {
		t.Fatalf("the naive fold rejected genesis: %v", err)
	}
	chain, err := harness.New(p)
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	return &folds{p: p, chain: chain, naive: naive}
}

// commit folds a block through both implementations and advances the tip when
// both accept it. A divergence is fatal: the two were written to differ in
// every way except their answer.
func (w *folds) commit(t *testing.T, payout types.Address, certs ...*types.Certificate) bool {
	t.Helper()
	b, err := w.chain.Propose(payout, certs...)
	if err != nil {
		t.Fatalf("propose at height %d: %v", w.chain.NextHeight(), err)
	}
	return w.foldOn(t, w.chain.State, w.naive, b, true)
}

// foldOn runs one block through both implementations against the states given,
// so an arm can fold a block it does not want to keep by handing in clones.
func (w *folds) foldOn(t *testing.T, fast *state.State, naive *refold.State,
	b *types.Block, advance bool) bool {
	t.Helper()
	ok, err := sim.Differential(fast, naive, b, w.p)
	if err != nil {
		t.Fatalf("the two folds disagree: %v", err)
	}
	if ok && advance {
		w.chain.Headers = append(w.chain.Headers, b.Header)
		w.chain.Undos = append(w.chain.Undos, nil)
	}
	return ok
}

// rules reports the rule id each implementation rejects b by, against copies of
// the current pre-state. Both ids are read, because "both refused" is a weaker
// statement than "both refused for the reason this arm is about" — a block that
// the reference fold refuses by B13 and the naive fold refuses by B12 is a
// divergence sim.Differential cannot see, since it deliberately allows two
// rejections to read differently.
func (w *folds) rules(b *types.Block) (string, string) {
	_, fastErr := fold.ApplyBlock(w.chain.State.Clone(), b, w.p)
	_, naiveErr := refold.ApplyBlock(w.naive.Clone(), b, w.p)
	return fold.Rule(fastErr), refold.Rule(naiveErr)
}

// seedSeqGasTarget writes T into both implementations' state. It is the same
// number written to the same slot in both, so it moves neither fold relative to
// the other and the state-root comparison keeps its teeth.
func (w *folds) seedSeqGasTarget(t uint64) {
	w.chain.State.Set(types.SeqGasTargetSlot(), u256.FromUint64(t))
	w.naive.Set(types.SeqGasTargetSlot(), new(big.Int).SetUint64(t))
}

func ceilingKey(t *testing.T, n uint16) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	seed[0], seed[1], seed[2] = byte(n), byte(n>>8), 0xB1
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatalf("key %d: %v", n, err)
	}
	return k
}

// ceilingBid is spec/gen's standard wallet shape: maxima far above the base
// fees, modest priorities. Nothing in this file turns on the bid, but a bid
// below base would be refused by B4 and the arm would pin B4 instead.
func ceilingBid() types.FeeBid {
	return wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000),
		u256.FromUint64(500), u256.FromUint64(10))
}

// fundedSigner mines until the miner holds a matured coinbase, then moves half
// of it to a fresh key and returns that key. Mine to play: there is no faucet.
func (w *folds) fundedSigner(t *testing.T, miner *wallet.Key, extraBlocks int) *wallet.Key {
	t.Helper()
	payout := miner.Persistent()
	for i := 0; i <= int(w.p.CoinbaseMaturity)+1+extraBlocks; i++ {
		if !w.commit(t, payout) {
			t.Fatalf("both folds refused an empty block at height %d", w.chain.NextHeight())
		}
	}
	signer := ceilingKey(t, 0x2222)
	half, ok := w.chain.Balance(payout).Uint64()
	if !ok || half == 0 {
		t.Fatalf("the miner holds %s after maturity, so nothing below can be funded",
			w.chain.Balance(payout))
	}
	c, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, payout, signer.Persistent(), u256.FromUint64(half/2)),
		Seq:     1,
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(payout, payout),
		FeeBid:  ceilingBid(),
		Signers: []*wallet.Key{miner},
	}).Build()
	if err != nil {
		t.Fatalf("funding certificate: %v", err)
	}
	if !w.commit(t, payout, c) {
		t.Fatal("both folds refused the funding block")
	}
	if w.chain.Balance(signer.Persistent()).IsZero() {
		t.Fatal("the funding certificate did not apply, so no arm below can build a certificate")
	}
	return signer
}

// TestBothFoldsAgreeAtTheCertificateCountCeiling drives rule B12.
//
// **Derivation.** The compared quantity is len(b.Certs), against
// MaxCertsPerBlock(T) = max_certs_per_block_genesis * T / seq_gas_target_genesis,
// clamped to cert_list_capacity. The rule is written twice; the bound is one
// core/params function both folds reach, so what this separates is the
// comparison, not the derivation of the bound.
//
// The reachable range of the compared quantity is bounded from above not by
// cert_list_capacity (33,554,432) but by B13's byte ceiling — B5's 4T burst
// bound is checked below and cannot bind here, because this arm runs devnet,
// which still ships block_byte_limit_genesis / seq_gas_target_genesis = 1.25
// and so still asks 3.2 sequential gas per block byte against a densest Era-0
// shape of 2.8937. Do not carry that figure to the mainnet arm: re-deriving
// mainnet's sequential target moved the ratio to 1.5625 there, 4T asks 2.56,
// and B5 is reachable — see assertOnlyTheByteRuleCanFire. At devnet's shipped
// parameters and T at its genesis value, a one-move TRANSFER — the network's
// representative verb, and what wallet.Builder emits — is 848 bytes and 600
// sequential gas, so 257 of them are 219,200 bytes against a byte ceiling of
// 2,500,000 and 154,200 sequential gas against a 4T bound of 8,000,000. Both
// ceilings are clear by an order of magnitude, so the count rule is the only
// one this block can reach, and the arm asserts that rather than assuming it.
//
// The two consecutive values that separate the rule are len == ceiling, which
// must be admitted, and len == ceiling+1, which must be refused. **That pair
// lies inside the reachable range at a shipped parameter set**, which is what
// makes this an ordinary test rather than one needing a witness: devnet's
// ceiling at genesis T is 256, and both 256 and 257 certificates are buildable.
//
// What was there before: the corpus carries invalid-cert-count-over-ceiling and
// its mainnet twin, and sim/rule_agreement_test.go replays both through the
// naive fold — but both are ceiling+1 blocks, and a `>` -> `>=` mutant refuses
// those too. The admitted side is what nothing drove, and it is the side that
// separates the operator.
func TestBothFoldsAgreeAtTheCertificateCountCeiling(t *testing.T) {
	p := spec.Devnet()
	w := newFolds(t, p)
	miner := ceilingKey(t, 1)
	alice := w.fundedSigner(t, miner, 8)
	bob := ceilingKey(t, 3)

	target := w.seqGasTarget(t)
	if target != p.SeqGasTargetGenesis {
		t.Fatalf("T is %d rather than its genesis value %d; this arm means to run at the "+
			"shipped genesis target and nothing here has moved it", target, p.SeqGasTargetGenesis)
	}
	ceiling := p.MaxCertsPerBlock(target)
	if ceiling < 2 {
		t.Fatalf("the certificate ceiling at T=%d is %d; there is no separating pair to drive",
			target, ceiling)
	}

	ttl := w.chain.NextHeight() + 5
	certs := make([]*types.Certificate, 0, ceiling+1)
	for i := 0; i <= ceiling; i++ {
		c, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), u256.FromUint64(1_000)),
			Seq:     uint64(i),
			TTL:     ttl,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  ceilingBid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatalf("certificate %d: %v", i, err)
		}
		certs = append(certs, c)
	}

	over, err := w.chain.Propose(miner.Persistent(), certs...)
	if err != nil {
		t.Fatalf("propose ceiling+1: %v", err)
	}
	// The reachability half: this block must be over the count ceiling and
	// under every other ceiling, or the arm pins whichever rule fires first
	// and says nothing about B12.
	w.assertOnlyTheCountRuleCanFire(t, over, target, ceiling)

	fastRule, naiveRule := w.rules(over)
	if fastRule != "B12" || naiveRule != "B12" {
		t.Fatalf("a block of %d certificates against a ceiling of %d is refused as %q by "+
			"core/fold and %q by sim/refold, want B12 from both",
			len(over.Certs), ceiling, fastRule, naiveRule)
	}

	// The admitted side, and the one nothing drove before: exactly the ceiling
	// must be folded by both, not merely refused by both for matching reasons.
	if !w.commit(t, miner.Persistent(), certs[:ceiling]...) {
		fr, nr := w.rules(over)
		t.Fatalf("a block of exactly %d certificates — the ceiling itself — was refused "+
			"(core/fold %q, sim/refold %q); the comparison is an off-by-one", ceiling, fr, nr)
	}
	t.Logf("devnet, T=%d: %d certificates folded by both implementations, %d refused as B12 by both",
		target, ceiling, ceiling+1)
}

// assertOnlyTheCountRuleCanFire states, from the parameters and the block
// rather than from either fold's verdict, that the block below is over B12's
// ceiling and under B13's, B5's and B6's. A fold asked whether it rejected
// would be vouching for itself.
func (w *folds) assertOnlyTheCountRuleCanFire(t *testing.T, b *types.Block, target uint64, ceiling int) {
	t.Helper()
	if len(b.Certs) != ceiling+1 {
		t.Fatalf("the block carries %d certificates, not ceiling+1 = %d", len(b.Certs), ceiling+1)
	}
	if size, limit := b.SizeBytes(), w.p.BlockByteLimit(target); size > limit {
		t.Fatalf("the block is %d bytes against a byte ceiling of %d, so B13 refuses it "+
			"before B12 is reached and this arm pins the wrong rule", size, limit)
	}
	var seqGas, parGas uint64
	for _, c := range b.Certs {
		seqGas += c.SeqGas(w.p)
		parGas += c.ParGas(w.p)
	}
	if burst := w.p.SeqGasBurst(target); seqGas > burst {
		t.Fatalf("the block declares %d sequential gas against a 4T bound of %d, so B5 "+
			"refuses it and this arm pins the wrong rule", seqGas, burst)
	}
	if limit := w.p.ParGasLimit(target); parGas > limit {
		t.Fatalf("the block declares %d parallel gas against a ceiling of %d, so B6 "+
			"refuses it and this arm pins the wrong rule", parGas, limit)
	}
	t.Logf("ceiling+1 block: %d certificates, %d bytes (ceiling %d), %d seq gas (4T %d), "+
		"%d par gas (ceiling %d)", len(b.Certs), b.SizeBytes(), w.p.BlockByteLimit(target),
		seqGas, w.p.SeqGasBurst(target), parGas, w.p.ParGasLimit(target))
}

func (w *folds) seqGasTarget(t *testing.T) uint64 {
	t.Helper()
	v, ok := w.chain.State.Get(types.SeqGasTargetSlot()).Uint64()
	if !ok {
		t.Fatal("the sequential target does not fit in a uint64")
	}
	if v == 0 {
		return w.p.SeqGasTargetGenesis
	}
	return v
}

// TestBothFoldsAgreeAtTheBlockByteCeiling drives rule B13.
//
// **Derivation.** The compared quantity is b.SizeBytes(), against
// BlockByteLimit(T) = block_byte_limit_genesis * T / seq_gas_target_genesis,
// clamped to block_byte_capacity.
//
// The reachable range of the compared quantity is bounded by B12's certificate
// ceiling and by how wide a certificate the V-rules admit. **B13 is reachable on
// every shipped network, devnet included**, and the network qualifier is only
// about how much room the count ceiling leaves:
//
//   - the widest certificate the V-rules admit is **15,277 bytes of body and
//     15,281 in a block**, and that number is no longer a search result. It is
//     derived in era0CertByteCeiling and attained by a certificate
//     widestEra0Transfer builds, both of them asserted against each other in
//     TestTheWidestEra0CertificateIsDerivedAndAttained. **Nothing in this
//     comment now rests on anybody having looked hard enough**;
//   - devnet: 164 of them are 2,506,320 bytes against a 2,500,000-byte ceiling,
//     at 164 of 256 certificates, 3,952,400 sequential gas against a 4T bound
//     of 6,400,000, and 5,798,056 parallel gas against 9,600,000. **B13 fires
//     at devnet**, and TestDevnetsByteRuleIsReachedByTheWidestCertificate
//     builds that block rather than leaving the arithmetic here to be
//     re-checked by hand. The 2T soft threshold is 3,200,000 and this block is
//     **above** it, at 123.5% — that changed with the gas-schedule respin,
//     which moved devnet's T0 from 2,000,000 to mainnet's 1,600,000 and brought
//     2T down from 4,000,000 with it, where the same block sat at 98.8%. It
//     costs the producer subsidy under F11 and refuses nothing, so the B13
//     claim is untouched: 4T and the parallel ceiling are the bounds that would
//     take the block away from B13, and it is under both. It is reachable
//     T-invariantly and not merely at genesis T: the certificate count the byte
//     ceiling demands over the count ceiling it is allowed is
//     (1.5625T/15,281)/(256T/1,600,000) = 0.6391, in which T cancels. Devnet
//     keeps B13 while the widest shape costs at least 9,765 bytes in a block —
//     256 of those are 2,500,076 bytes and 256 of a 9,764-byte one are
//     2,499,820 — so 15,281 clears the threshold by 5,516 bytes, **56.5%**;
//   - mainnet and testnet allow 4,000 certificates against the same byte
//     ceiling, so the same ratio is 0.0409 and the count ceiling is 15.6x
//     looser. The two agree because both terms of the ratio scale from T, which
//     is why they agreed even while mainnet's re-derived T0 of 1,600,000 stood
//     against testnet's 2,000,000; since the gas-schedule respin they carry the
//     same T0 as well, so the ratio's invariance is no longer what the
//     agreement rests on.
//
// **Why this comment names a maximum again, and why that is not the fourth
// mistake.** Four successive revisions asserted a widest Era-0 certificate —
// 7,823, then 10,125, then 13,703, then 15,281 — and each of the first three
// was falsified by someone other than its author, by a corner the previous
// search could not see. The diagnosis that finally stuck: the binding
// constraint is neither max_sigs nor max_moves_per_transfer but **max_writes**,
// and the optimum is *interior* to a region of several dimensions rather than
// at any named axis's edge, so no enumeration along one axis reaches it. The
// fourth number, 15,281, came from noticing a fifth dimension — merging
// destinations buys back write budget — and the params note recorded it,
// correctly, as a **lower bound on the maximum**.
//
// PROTOCOL rule 21 says a global maximum over a combinatorial space is the
// wrong *kind* of claim, and it is right about search. It is not an argument
// against **derivation**, which is the move made for the certificate-byte
// ceiling and for parallel density (era0ParDensityCeiling): a bound that holds
// over every shape, searched or not, because it is read off the encoding and
// the rules rather than off a sweep. Width admits the same treatment, and
// era0CertByteCeiling carries it out. What makes the result a maximum rather
// than one more claim about shapes nobody built is that the derived upper bound
// and a constructed witness **meet**: 15,277 from above, 15,277 from below.
// Neither half is evidence for the other, and the test fails loudly and
// differently depending on which one moves.
//
// The two consecutive values that separate the rule are size == limit, which
// must be admitted, and size == limit+1, which must be refused. **The pair is
// driven by moving the ceiling onto the block rather than the block onto the
// ceiling, and that is a choice.** An earlier draft of this comment called it
// forced, on the ground that a block's size moves in fixed steps and every
// reachable size is congruent to 236 modulo 3 while 2,500,000 is not. That
// congruence is a property of *this arm's single-shape family*, not of the
// block space: over the 162-shape Era-0 sweep the per-certificate in-block cost
// takes all three residues modulo 3 and is odd for 89 of them, so a mixed block
// reaches both halves exactly at mainnet genesis T with nothing moved —
// 2,888 floor RETIREs at 562 bytes plus 1,029 one-move TRANSFERs at 852 is
// exactly 2,500,000 bytes in 3,917 certificates and 2,927,800 sequential gas,
// and 29 RETIREs with a fresh one-shot deposit cell plus 5 floor RETIREs plus
// 2,905 one-move TRANSFERs is exactly 2,500,001 in 2,939 certificates and
// 1,790,500 sequential gas.
//
// The reason for the choice is that the block-side pair is a hand-solved
// Diophantine mix of three shapes: it is ~3,900 certificates to build and fold
// twice instead of 320, and it holds only while three encoded sizes stay
// exactly where they are, so an encoding change un-solves it silently. The
// ceiling-side pair is derived at run time from a linear model measured off two
// proposed blocks and then asserted against the third, so the same encoding
// change fails here with the number that moved. Both sides of the comparison
// are integers and the rule is `size > limit`; driving (limit = S, limit = S-1)
// against a fixed S is the same separating pair as (size = L, size = L+1)
// against a fixed L, and it is the cheaper and the self-checking one.
//
// **T is state, not a parameter, and it stays inside its own legal interval.**
// The arm asserts seq_gas_target_genesis <= T <= seq_gas_capacity, which is the
// interval whitepaper 8.1's controller clamps T into and the only interval a
// running network's T can occupy. No parameter file is touched and no shipped
// value is widened: this is not the earlier sweep's elasticBase(), which moved
// the *parameter* seq_gas_target_genesis and with it the bytes-per-gas ratio.
func TestBothFoldsAgreeAtTheBlockByteCeiling(t *testing.T) {
	p := spec.Mainnet()
	w := newFolds(t, p)
	miner := ceilingKey(t, 1)
	alice := w.fundedSigner(t, miner, 2)

	dsts := make([]types.Address, 0, p.MaxMovesPerTransfer)
	for i := 0; i < p.MaxMovesPerTransfer; i++ {
		dsts = append(dsts, ceilingKey(t, uint16(0x300+i)).Persistent())
	}
	moves := make([]types.Move, 0, len(dsts))
	for _, d := range dsts {
		moves = append(moves, types.Move{Asset: types.NativeAsset, Src: alice.Persistent(),
			Dst: d, Amount: u256.FromUint64(1)})
	}

	ttl := w.chain.NextHeight() + 5
	certs := make([]*types.Certificate, 0, 512)
	grow := func(n int) []*types.Certificate {
		for len(certs) < n {
			c, err := (&wallet.Builder{
				Params:  p,
				Program: wallet.Transfer(moves...),
				Seq:     uint64(len(certs)),
				TTL:     ttl,
				Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
				FeeBid:  ceilingBid(),
				Signers: []*wallet.Key{alice},
			}).Build()
			if err != nil {
				t.Fatalf("certificate %d: %v", len(certs), err)
			}
			certs = append(certs, c)
		}
		return certs[:n]
	}
	propose := func(n int) *types.Block {
		b, err := w.chain.Propose(miner.Persistent(), grow(n)...)
		if err != nil {
			t.Fatalf("propose %d certificates: %v", n, err)
		}
		return b
	}

	// A block of identical certificates is base + n*step bytes. Both constants
	// are measured from two blocks rather than retyped from the encoding, and
	// the third block below checks the model against the object it predicts —
	// a size derived from a formula nobody re-measured is a size that silently
	// stops being the block's.
	one, two := propose(1).SizeBytes(), propose(2).SizeBytes()
	step := two - one
	base := one - step
	if step <= 0 {
		t.Fatalf("a certificate adds %d bytes to a block; the search below cannot converge", step)
	}

	// The smallest block over the ceiling T's genesis value gives, then the
	// first size at or above it on which the ceiling can be placed both exactly
	// and exactly one below — see byteCeilingTarget for why one size in five
	// cannot carry the ceiling at all.
	genesisLimit := p.BlockByteLimit(p.SeqGasTargetGenesis)
	n := (genesisLimit-base)/step + 1
	var block *types.Block
	var hi, lo uint64
	for ; n <= p.MaxCertsPerBlock(p.SeqGasTargetGenesis); n++ {
		size := base + n*step
		if size <= genesisLimit {
			continue
		}
		h, okHi := byteCeilingTarget(p, size)
		l, okLo := byteCeilingTarget(p, size-1)
		if !okHi || !okLo {
			continue
		}
		block = propose(n)
		if block.SizeBytes() != size {
			t.Fatalf("a block of %d certificates is %d bytes, not the %d the linear model "+
				"predicts; the search above placed the ceiling on a size that does not exist",
				n, block.SizeBytes(), size)
		}
		hi, lo = h, l
		break
	}
	if block == nil {
		t.Fatal("no block within the certificate ceiling exceeded the byte ceiling, so B13 " +
			"is unreachable at these parameters and this arm asserts nothing")
	}

	size := block.SizeBytes()
	// The placement, asserted rather than hoped for.
	if p.BlockByteLimit(hi) != size {
		t.Fatalf("at T=%d the byte ceiling is %d, not the block's %d", hi, p.BlockByteLimit(hi), size)
	}
	if p.BlockByteLimit(lo) != size-1 {
		t.Fatalf("at T=%d the byte ceiling is %d, not the block's size minus one (%d)",
			lo, p.BlockByteLimit(lo), size-1)
	}
	for _, tt := range []uint64{hi, lo} {
		if tt < p.SeqGasTargetGenesis || tt > p.SeqGasCapacity {
			t.Fatalf("T=%d is outside [%d, %d], the interval the epoch controller clamps the "+
				"sequential target into, so this arm would be measuring a state no network "+
				"can occupy", tt, p.SeqGasTargetGenesis, p.SeqGasCapacity)
		}
	}
	// The reachability half, at the *lower* of the two targets, where every
	// other ceiling is at its tightest: the block must be over B13's ceiling
	// and under B12's, B5's and B6's, or the arm pins whichever fires first.
	w.assertOnlyTheByteRuleCanFire(t, block, lo)

	w.seedSeqGasTarget(lo)
	fastRule, naiveRule := w.rules(block)
	if fastRule != "B13" || naiveRule != "B13" {
		t.Fatalf("a block of %d bytes against a ceiling of %d is refused as %q by core/fold "+
			"and %q by sim/refold, want B13 from both",
			size, p.BlockByteLimit(lo), fastRule, naiveRule)
	}

	// The admitted side: the same block, with the ceiling exactly on it.
	w.seedSeqGasTarget(hi)
	if !w.foldOn(t, w.chain.State, w.naive, block, true) {
		fr, nr := w.rules(block)
		t.Fatalf("a block of exactly %d bytes against a byte ceiling of exactly %d — the "+
			"equality case — was refused (core/fold %q, sim/refold %q); the comparison is "+
			"an off-by-one", size, p.BlockByteLimit(hi), fr, nr)
	}
	t.Logf("mainnet: a block of %d bytes in %d certificates, folded by both at T=%d where the "+
		"ceiling is %d, refused as B13 by both at T=%d where it is %d",
		size, len(block.Certs), hi, p.BlockByteLimit(hi), lo, p.BlockByteLimit(lo))
}

// byteCeilingTarget returns the sequential target at which BlockByteLimit is
// exactly limit, and whether one exists inside T's legal interval.
//
// Not every integer is a reachable ceiling: BlockByteLimit floors a ratio, so
// at the 2,500,000 / 1,600,000 all three shipped networks now run, nine values
// in twenty-five are skipped (sixteen consecutive targets advance the ceiling
// by twenty-five). It is the same fraction on all of them since the
// gas-schedule respin; under testnet's and devnet's superseded 2,500,000 /
// 2,000,000 it was one in five. That is why the caller grows the block until it
// finds a size for which both `size` and `size - 1` are reachable ceilings.
//
// The search calls p.BlockByteLimit, which is deliberate: it is a single
// core/params function *both* folds reach, so it is not one of the two
// derivations under test here. What this file separates is the comparison.
func byteCeilingTarget(p *params.Params, limit int) (uint64, bool) {
	lo, hi := p.SeqGasTargetGenesis, p.SeqGasCapacity
	if p.BlockByteLimit(lo) > limit || p.BlockByteLimit(hi) < limit {
		return 0, false
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		if p.BlockByteLimit(mid) < limit {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if p.BlockByteLimit(lo) != limit {
		return 0, false
	}
	return lo, true
}

// assertOnlyTheByteRuleCanFire states, from the parameters and the block rather
// than from either fold's verdict, that the block is over B13's ceiling and
// under every other one.
//
// **The B5 guard below CAN fire since mainnet's target was re-derived, and the
// B6 guard cannot.** This paragraph used to say that neither could, and that
// they were unreachable *by construction at every T* — which was true, and is
// the conclusion drawn from it that this file's caller retires.
//
// The division is the same and only the constants moved. Dividing each ceiling
// by the byte ceiling cancels T, so what each rule asks is fixed by
// block_byte_limit_genesis / seq_gas_target_genesis and, for B6, par_gas_ratio.
// This arm runs spec.Mainnet(), where the fee-market re-derivation moved that
// ratio from 1.25 to **1.5625** and the parallel multiple from 10 to **3**
// (testnet and devnet still ship 1.25 and 10, so 3.2 and 16 remain their
// figures):
//
//	B5 (4T)            2.56 sequential gas per block byte, against 2.8937
//	                   achieved by the densest Era-0 shape — 1.1303 of what the
//	                   rule asks, so the DENSITY is there. Since B18 was added
//	                   the density is no longer sufficient: B18 caps the block's
//	                   signature count, the shape that supplies 2.8937 spends
//	                   one signature per 706 sequential gas, and the largest
//	                   block of it B18 admits reaches 66% of 4T

//	B6 (ParGasLimit)   3.84 parallel gas per block byte, against a DERIVED
//	                   Era-0 ceiling of 3.0352 that a witness attains —
//	                   0.7904 of what the rule asks
//
// **The two rest on different kinds of claim, and that is the point.** B5's
// reachability was an existential — core/fold built the block — and the
// signature ceiling removed the witness rather than the rule: that test is now
// TestB18BindsBeforeB5OnTheGasDensestFamily, which measures the same family
// being refused by the signature ceiling first. So B5's status is once again
// "no witness", which is NOT "unreachable": no census of the shape space
// exists, and B5 stays a rule an implementation must enforce. B6's
// unreachability rests on no maximum either, and it rests on no swept number:
// era0ParDensityCeiling derives 3.0352 for every certificate the V-rules admit,
// searched or not, and densestEra0Retire builds one that costs exactly that.
// The claim is not quoted here, it is executed — this function calls
// assertB6IsInertByDerivation, so a parameter or gas-schedule move that closed
// the gap fails the arm with the number that moved instead of leaving this
// paragraph stale.
//
// **The uncoupled form of this bound gives 3.6242, and nothing here rests on
// it.** That is the same bound with the V4 coupling left out — s and u treated
// as free of each other when a signature must authorise a unit of the program
// or the deposit cell — and it is loose in the honest direction. Its conclusion
// is what the looseness costs: it solves for the max_sigs at which B6 would
// become reachable and reports 35, where under the coupled bound
// (era0ParDensityLimit) no value of max_sigs reaches it at par_gas_ratio = 3.
//
// So B5's silence here is now evidence **about this block** rather than about
// the parameter set: this arm's shape is a 32-move TRANSFER at roughly 0.87
// sequential and 2.23 parallel gas per block byte, well under both, and a
// denser shape would trip the guard instead of the arm. B12, B5 and the 2T
// threshold are all doing work; only B6 is inert, and by proof.
//
// The width family that falsified three maximum claims was checked against the
// old figures directly and dilutes rather than concentrates — the widest Era-0
// certificate, now derived at 15,281 in-block bytes rather than searched for
// (era0CertByteCeiling), is 1.5771 sequential and 2.3136 parallel gas per block
// byte, under the RETIRE family's 2.8937 sequential and under the derived
// parallel ceiling of 3.0352 — because width buys bytes faster than it buys
// gas, so density and width sit at opposite corners of the same region. That
// observation is unchanged by the parameter move, and both halves of it are now
// statements about the *widest* and the *densest* shape rather than about the
// widest and densest anybody had built.
func (w *folds) assertOnlyTheByteRuleCanFire(t *testing.T, b *types.Block, target uint64) {
	t.Helper()
	// B6's guard below can only ever be silent, and a silent guard is
	// indistinguishable from a guard that never ran. What makes it evidence is
	// the derivation, so the arm runs it here rather than citing it above.
	assertB6IsInertByDerivation(t, w.p)
	if size, limit := b.SizeBytes(), w.p.BlockByteLimit(target); size != limit+1 {
		t.Fatalf("the block is %d bytes against a ceiling of %d; this arm exists to drive "+
			"the first refused size, which is %d", size, limit, limit+1)
	}
	if ceiling := w.p.MaxCertsPerBlock(target); len(b.Certs) > ceiling {
		t.Fatalf("the block carries %d certificates against a ceiling of %d, so B12 refuses "+
			"it before B13 is reached and this arm pins the wrong rule", len(b.Certs), ceiling)
	}
	var seqGas, parGas uint64
	for _, c := range b.Certs {
		seqGas += c.SeqGas(w.p)
		parGas += c.ParGas(w.p)
	}
	if burst := w.p.SeqGasBurst(target); seqGas > burst {
		t.Fatalf("the block declares %d sequential gas against a 4T bound of %d, so B5 "+
			"refuses it and this arm pins the wrong rule", seqGas, burst)
	}
	// Asserted against 2T rather than 4T, for the reason the mainnet
	// certificate-ceiling vector gives: crossing the soft threshold makes this
	// a burst-forfeiture block and changes what the arm is about.
	if soft := w.p.SeqGasLimit(target); seqGas > soft {
		t.Fatalf("the block declares %d sequential gas against a 2T threshold of %d, so it "+
			"is a burst block and no longer a clean byte-rule arm", seqGas, soft)
	}
	if limit := w.p.ParGasLimit(target); parGas > limit {
		t.Fatalf("the block declares %d parallel gas against a ceiling of %d, so B6 refuses "+
			"it and this arm pins the wrong rule", parGas, limit)
	}
	t.Logf("first-refused block: %d bytes (ceiling %d), %d certificates (ceiling %d), "+
		"%d seq gas (2T %d), %d par gas (ceiling %d)", b.SizeBytes(),
		w.p.BlockByteLimit(target), len(b.Certs), w.p.MaxCertsPerBlock(target),
		seqGas, w.p.SeqGasLimit(target), parGas, w.p.ParGasLimit(target))
}

// perCertBlockOverhead is what carrying one more certificate costs a block
// beyond that certificate's own body: the four offset bytes EncodeVariableList
// writes per element. Taken from the encoder by difference rather than written
// down, so an encoding change moves it here instead of silently invalidating
// every in-block figure below.
var perCertBlockOverhead = types.BlockOverheadBytes(1, 0) - types.BlockOverheadBytes(0, 0)

// emptyProgramBytes is the SSZ envelope a Program costs before its body: the
// kind byte and the one offset. Read off the encoder for the same reason.
var emptyProgramBytes = len(types.Program{
	Kind: types.ProgramRetire, Retire: &types.RetireArgs{},
}.MarshalSSZ())

// era0CertByteCeiling is the widest certificate body the V-rules admit at p,
// **derived rather than searched for**.
//
// This is the answer to the failure PROTOCOL rule 21 was written about. The
// widest Era-0 certificate was published four times — 7,823, 10,125, 13,703,
// 15,281 — and the first three were each falsified by a corner the previous
// search could not see, because the optimum is interior to a region of several
// dimensions and no enumeration along a named axis reaches an interior optimum.
// Rule 21's remedy is to stop claiming maxima obtained by search. It is not a
// prohibition on maxima obtained by *derivation*, and width admits one.
//
// **The identity.** ssz.Encode over certLayout makes every certificate exactly
//
//	CertMinSize + |program| + ReadSize*R + WriteSize*W + SigSize*S
//
// with no cross terms and no slack: the four variable fields are the only
// variable ones, and each costs its own elements plus an offset already counted
// in CertMinSize. So bounding the certificate is bounding four integers.
//
// **The bounds, per program kind.** V1 caps R, W and S at max_reads, max_writes
// and max_sigs, and caps the program's own list at max_moves_per_transfer or
// max_retire_addrs; V3 forces R and W to be exactly what validity.Derive emits,
// which is where the tighter caps come from; V4 forces S to be exactly the
// number of distinct keys the body requires, because a signature authorising
// nothing is invalid.
//
//	TRANSFER  |program| = emptyProgramBytes + MoveSize*m,  m <= max_moves
//	          R <= min(m, max_reads): deriveTransfer emits one read per DISTINCT
//	                debited slot and every debited slot needs at least one move
//	          W <= max_writes
//	          S <= min(max_sigs, m+1): every required signature belongs to a key
//	                owning a debited address or the deposit cell, and there are
//	                at most m distinct move sources plus the deposit cell
//	RETIRE    R = 0; every target is one-shot and crypto.AddressFromPubKey is
//	          injective on a fixed version, so a distinct targets need a
//	          distinct signatures: a <= min(max_retire_addrs, max_sigs), and
//	          W <= min(max_writes, a+1) counting the deposit cell's own burn
//	ISSUE     R = 1, W <= 5, S <= 2 (issuer, deposit cell) — deriveIssue is a
//	          fixed shape and the +1 write is again the deposit burn
//	MINT      R = 3, W <= 3, S <= 2 (minter key, deposit cell)
//
// At every shipped parameter set the TRANSFER arm dominates by four times, and
// its value is 15,277 bytes of body: 328 + 4,101 + 97x32 + 97x64 + 96x16.
//
// **That domination is also what no test here separates, and the assumption
// belongs beside the number rather than trusted.** Because max() returns the
// TRANSFER arm by a factor of four, a wrong constant in the RETIRE, ISSUE or
// MINT arm cannot move the result and cannot fail anything — measured, not
// assumed: dropping ISSUE's write count from 5 to 4 leaves the suite green. The
// exposure is bounded on the side that matters, since only an arm wrongly
// raised ABOVE the TRANSFER value could change what this returns, and that
// breaks attainment loudly in the test below. An arm wrongly lowered is
// invisible and harmless. The widest RETIRE anyone has built is 3,933 bytes and
// ISSUE and MINT are under 1,400.
//
// **This is an upper bound and nothing here claims it is attained.** That is a
// separate fact, and it is asserted separately, by construction, in
// TestTheWidestEra0CertificateIsDerivedAndAttained — which is the whole point:
// the two halves are established by unrelated means, so neither can be the
// other's echo. The note in spec/params.json states the *loose* form of the
// same identity, 18,381, obtained by taking R, W, S and the program to their
// limits independently; it bounds correctly and is explicitly not claimed to be
// attained. This is the same derivation with the couplings put back.
func era0CertByteCeiling(p *params.Params) int {
	fixed := types.CertMinSize + emptyProgramBytes
	m := p.MaxMovesPerTransfer
	transfer := fixed + types.MoveSize*m +
		types.ReadSize*min(m, p.MaxReads) +
		types.WriteSize*p.MaxWrites +
		types.SigSize*min(p.MaxSigs, m+1)

	a := min(p.MaxRetireAddrs, p.MaxSigs)
	retire := fixed + len(types.Address{})*a +
		types.WriteSize*min(p.MaxWrites, a+1) +
		types.SigSize*min(p.MaxSigs, a+1)

	issue := fixed + types.IssueSize +
		types.ReadSize*1 + types.WriteSize*min(p.MaxWrites, 5) + types.SigSize*min(p.MaxSigs, 2)
	mint := fixed + types.MintSize +
		types.ReadSize*3 + types.WriteSize*min(p.MaxWrites, 3) + types.SigSize*min(p.MaxSigs, 2)

	return max(max(transfer, retire), max(issue, mint))
}

// widestEra0Transfer builds a certificate that attains era0CertByteCeiling, and
// it is built from p rather than from the shipped numbers so that the two sides
// move together or the test says which one did not.
//
// **The shape, and the dimension four searches missed.** max_sigs keys are used
// in BOTH address roles — a one-shot address and its persistent twin — which V4
// authorises on one signature each, giving 2*max_sigs debited addresses out of
// max_sigs signatures. That fills the read budget to the move limit. The write
// budget is then max_sigs debits doubled, plus one MARK_SPENT per one-shot
// source, plus one credit per DISTINCT destination — and the destinations are
// deliberately **merged**, two moves into each, because two moves into one
// destination cost one credit slot instead of two and the slot freed pays for
// another source at 97 bytes of read plus 97 of write plus 96 of signature. The
// objective rises while the constraint that binds stays satisfied. Every
// published maximum before this derivation held destinations distinct, which is
// why none of them found this.
//
// The optimum is a plateau rather than a point: max_sigs persistent-only keys
// debited on two assets each, with all destinations distinct, encodes to the
// same size by the same arithmetic. Only one of the two is built here, since
// what the ceiling needs is that it is reached, not how many ways reach it.
func widestEra0Transfer(t *testing.T, p *params.Params, salt int) *types.Certificate {
	t.Helper()
	keys := min(p.MaxSigs, p.MaxMovesPerTransfer/2)
	srcs := make([]types.Address, 0, 2*keys)
	signers := make([]*wallet.Key, 0, keys)
	for i := 0; i < keys; i++ {
		k := ceilingKey(t, uint16(salt+0x500+i))
		signers = append(signers, k)
		srcs = append(srcs, k.OneShot(), k.Persistent())
	}
	// Exactly the destinations the write budget leaves: one credit each, after
	// the debits and the one-shot burns are paid for.
	nDsts := p.MaxWrites - len(srcs) - keys
	if nDsts < 1 || nDsts > p.MaxMovesPerTransfer {
		t.Fatalf("the write budget leaves room for %d distinct destinations at max_writes=%d "+
			"with %d debited addresses and %d one-shot burns; this construction cannot fill it "+
			"and era0CertByteCeiling's attainment has to be re-derived at these parameters",
			nDsts, p.MaxWrites, len(srcs), keys)
	}
	moves := make([]types.Move, 0, len(srcs))
	for i, s := range srcs {
		moves = append(moves, types.Move{
			Asset:  types.NativeAsset,
			Src:    s,
			Dst:    ceilingKey(t, uint16(salt+0x600+i%nDsts)).Persistent(),
			Amount: u256.FromUint64(1),
		})
	}
	// The deposit is the first one-shot source's own cell, so it derives no
	// extra MARK_SPENT; the refund goes to a key that takes no other role, since
	// V5 refuses a refund into anything this certificate burns.
	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Transfer(moves...),
		Seq:     0,
		TTL:     240,
		Deposit: wallet.SelfDeposit(srcs[0], ceilingKey(t, uint16(salt+0x7FF)).Persistent()),
		FeeBid:  ceilingBid(),
		Signers: signers,
	}).Build()
	if err != nil {
		t.Fatalf("the widest Era-0 transfer did not build at %s: %v", p.Name, err)
	}
	return c
}

// TestTheWidestEra0CertificateIsDerivedAndAttained closes the loop rule 21
// leaves open: a derived upper bound and a constructed lower bound that meet.
//
// The two assertions below fail for different reasons and say so, because they
// are different findings:
//
//   - **built > derived** means era0CertByteCeiling is WRONG. A certificate the
//     V-rules admit is wider than the derivation says any can be, and every
//     downstream figure — this file's devnet argument, spec/params.json's
//     per-certificate note, any buffer sized from either — is unsound.
//   - **built < derived** means the ceiling is no longer known to be ATTAINED.
//     It is still a valid upper bound; what is lost is the right to call it the
//     maximum, and whoever moved the parameter owes a re-derivation.
//
// The sweep at the end is deliberately the weakest instrument here and is used
// only in the direction a sweep is good for. It cannot confirm the bound — that
// is the mistake this file's history is made of — but a single shape above the
// bound refutes it, and refutation is the one thing enumeration does soundly.
func TestTheWidestEra0CertificateIsDerivedAndAttained(t *testing.T) {
	for _, p := range []*params.Params{spec.Devnet(), spec.Testnet(), spec.Mainnet()} {
		t.Run(p.Name, func(t *testing.T) {
			ceiling := era0CertByteCeiling(p)
			c := widestEra0Transfer(t, p, 0)
			body := len(c.MarshalSSZ())
			if body > ceiling {
				t.Fatalf("a certificate wallet.Builder accepts is %d bytes against a derived "+
					"ceiling of %d, so era0CertByteCeiling is wrong and every figure taken "+
					"from it is unsound", body, ceiling)
			}
			if body != ceiling {
				t.Fatalf("the widest certificate this file can construct is %d bytes against a "+
					"derived ceiling of %d; the ceiling still bounds but is no longer known to "+
					"be attained, so it may not be quoted as the widest Era-0 certificate "+
					"until the construction is re-derived at these parameters", body, ceiling)
			}
			// Non-vacuity: the shape must actually sit on the limits the
			// derivation spends its budget on, or it reached the number some
			// other way and the derivation is not what is being confirmed.
			if len(c.Reads) != min(p.MaxMovesPerTransfer, p.MaxReads) ||
				len(c.Writes) != p.MaxWrites || len(c.Sigs) != p.MaxSigs ||
				len(c.Program.Transfer.Moves) != p.MaxMovesPerTransfer {
				t.Fatalf("the witness carries %d reads, %d writes, %d signatures and %d moves; "+
					"the derivation spends its budget at %d/%d/%d/%d, so this certificate "+
					"reaches the ceiling by some other route", len(c.Reads), len(c.Writes),
					len(c.Sigs), len(c.Program.Transfer.Moves),
					min(p.MaxMovesPerTransfer, p.MaxReads), p.MaxWrites, p.MaxSigs,
					p.MaxMovesPerTransfer)
			}

			// The refutation pass. The neighbour first: one distinct destination
			// more than the write budget affords must be refused, and refused as
			// V1, or max_writes is not the constraint the derivation spends the
			// budget against and the ceiling is derived off the wrong limit.
			keys := min(p.MaxSigs, p.MaxMovesPerTransfer/2)
			assertWriteBudgetRefuses(t, p, keys, p.MaxWrites-3*keys+1)

			widest, built := 0, 0
			for keys := 1; keys <= p.MaxSigs; keys++ {
				for dsts := 1; dsts <= p.MaxMovesPerTransfer; dsts += 3 {
					c, err := wideTransfer(t, p, keys, dsts, p.MaxMovesPerTransfer)
					if err != nil {
						continue
					}
					built++
					if n := len(c.MarshalSSZ()); n > widest {
						widest = n
					}
					if n := len(c.MarshalSSZ()); n > ceiling {
						t.Fatalf("a %d-key %d-destination transfer is %d bytes, over the derived "+
							"ceiling of %d: the derivation is refuted", keys, dsts, n, ceiling)
					}
				}
			}
			if built == 0 {
				t.Fatal("the refutation pass built nothing, so it refuted nothing")
			}
			t.Logf("%s: derived ceiling %d body / %d in a block, attained; %d shapes swept, "+
				"widest %d, none over", p.Name, ceiling, ceiling+perCertBlockOverhead, built, widest)
		})
	}
}

// wideTransfer is widestEra0Transfer's family with the two dimensions the
// searches before it held fixed opened up: how many keys are used in both
// address roles, and how many distinct destinations the moves are merged into.
func wideTransfer(t *testing.T, p *params.Params, keys, dsts, moves int) (*types.Certificate, error) {
	t.Helper()
	if keys < 1 || dsts < 1 || 2*keys > moves || dsts > moves {
		return nil, errShapeInfeasible
	}
	srcs := make([]types.Address, 0, 2*keys)
	signers := make([]*wallet.Key, 0, keys)
	for i := 0; i < keys; i++ {
		k := ceilingKey(t, uint16(0x500+i))
		signers = append(signers, k)
		srcs = append(srcs, k.OneShot(), k.Persistent())
	}
	mv := make([]types.Move, 0, moves)
	for i := 0; i < moves; i++ {
		mv = append(mv, types.Move{
			Asset:  types.NativeAsset,
			Src:    srcs[i%len(srcs)],
			Dst:    ceilingKey(t, uint16(0x600+i%dsts)).Persistent(),
			Amount: u256.FromUint64(1),
		})
	}
	return (&wallet.Builder{
		Params:  p,
		Program: wallet.Transfer(mv...),
		Seq:     0,
		TTL:     240,
		Deposit: wallet.SelfDeposit(srcs[0], ceilingKey(t, 0x7FF).Persistent()),
		FeeBid:  ceilingBid(),
		Signers: signers,
	}).Build()
}

var errShapeInfeasible = errors.New("shape is infeasible before any rule sees it")

// assertWriteBudgetRefuses states, before building, that a shape one distinct
// destination past the write budget must be refused as V1 — PROTOCOL rule 22's
// direction declaration applied to a construction rather than to a mutation.
//
// A shape that builds here means max_writes is not the constraint
// era0CertByteCeiling spends the budget against, and the ceiling is derived off
// the wrong limit. Naming V1 rather than merely "refused" is the other half:
// this same shape would also be refused if the deposit arrangement or the
// destination addresses were wrong, and those refusals would prove nothing
// about the write budget.
func assertWriteBudgetRefuses(t *testing.T, p *params.Params, keys, dsts int) {
	t.Helper()
	c, err := wideTransfer(t, p, keys, dsts, p.MaxMovesPerTransfer)
	if err == nil {
		t.Fatalf("a %d-key %d-destination transfer built to %d bytes, but it declares %d writes "+
			"against max_writes=%d and had to be refused; max_writes is not the binding "+
			"constraint the ceiling is derived against", keys, dsts, len(c.MarshalSSZ()),
			len(c.Writes), p.MaxWrites)
	}
	if got := validity.Rule(err); got != "V1" {
		t.Fatalf("the over-budget shape was refused as %q, want V1: %v", got, err)
	}
}

// ratio is a non-negative rational compared by cross-multiplication.
//
// Every quantity in the density derivation below is a ratio of integers, and at
// mainnet the two sides of the comparison it exists to make — what B6 asks and
// what Era 0 can supply — sit 21% apart rather than an order of magnitude. A
// bound rounded to four decimals and compared as a decimal has stopped being a
// bound; only the printed forms here are floating point.
type ratio struct{ num, den int }

func (r ratio) less(o ratio) bool { return r.num*o.den < o.num*r.den }

func (r ratio) dec() float64 { return float64(r.num) / float64(r.den) }

// era0ParDensity is the parallel gas a certificate of n encoded bytes, sigs
// signatures and units derive units costs per byte it adds to a block. The
// denominator is n + perCertBlockOverhead because that, and not n, is what the
// certificate spends out of B13's ceiling.
//
// It is types.Certificate.ParGas's arithmetic over integers a certificate has
// not been built for. On a certificate that exists the two agree by
// construction, which is why the attainment test below measures the witness
// through ParGas rather than through this.
func era0ParDensity(p *params.Params, n, sigs, units int) ratio {
	par := int(p.GasParPerSig)*sigs + int(p.GasParPerByte)*n + int(p.GasParPerDeriveUnit)*units
	return ratio{par, n + perCertBlockOverhead}
}

// era0DensestShape is the point of the derived region at which Era-0 parallel
// density is maximal: which program kind, and the integers that fix both the
// parallel gas and the minimum encoding.
type era0DensestShape struct {
	kind    string
	units   int
	sigs    int
	bytes   int
	density ratio
	// points counts the region's points **per program kind**, and per kind is
	// the whole of it. A single total is the instrument rule 24 warns about: it
	// agrees with the truth everywhere except where it is needed, because an
	// arm that empties takes a few hundred points out of a few thousand and
	// leaves the total looking healthy. Measured, not reasoned: a mutant that
	// emptied the RETIRE arm passed a total-based guard.
	points map[string]int
}

// era0ParDensityCeiling is the greatest parallel gas per block byte any Era-0
// certificate can cost, **derived rather than measured**.
//
// This is the published parallel-density bound with the couplings put back, and
// it is the same move made for width. That bound is derived from the shape
// alone — every certificate carries at least 328 fixed bytes, 5 of program
// header, 96s of signature and 128u of program body, so density is under 2 +
// (200s + 50u)/(337 + 96s + 128u), maximised at s = max_sigs and u = 1 — and
// gets **3.6242**. That form treats s and u as free of one another, and **they
// are not**: V4 refuses a signature that authorises nothing, and every address
// a signature can be needed for is either a unit of the program or the deposit
// cell, so `s <= u + 1` at every program kind. The issue names the looseness
// ("16 signatures cannot coexist with u = 1") and leaves it in.
//
// Put the coupling back and the bound falls to **3.0352, where the witness is**
// — which is what turns an upper bound into a maximum. Two smaller corrections
// come with it: the 3.6242 also drops the -8 its own formula carries (the exact
// value of the loose form is 3.6202, not 3.6242), and its conclusion that
// "max_sigs would have to reach 35 before B6 could fire" understates the
// answer — see era0ParDensityLimit, under which no value of max_sigs does.
//
// **The identity.** For a certificate of n encoded bytes,
//
//	ParGas = gas_par_per_sig*S + gas_par_per_byte*n + gas_par_per_derive_unit*U
//	density = ParGas / (n + perCertBlockOverhead)
//
// With S >= 1 (V1) the numerator's S term alone exceeds
// perCertBlockOverhead*gas_par_per_byte, so density strictly falls as n grows:
// each shape is densest at its own minimum encoding, and bounding density is
// bounding (S, U, minimum n) over three integers per program kind. That premise
// is asserted rather than assumed, in assertB6IsInertByDerivation.
//
// **The region, per program kind.** Each row is a lower bound on n and an upper
// bound on S, both read off validity.Derive and V4 rather than off any built
// shape:
//
//	RETIRE    U = a targets; program body 32*a; R = 0; W >= a, one MARK_SPENT
//	          per target. requiredAddrs is the a targets plus the deposit cell,
//	          and AddressFromPubKey is injective at a fixed version, so
//	          S <= min(max_sigs, a+1). a <= min(max_retire_addrs, max_writes).
//	TRANSFER  U = m moves; program body 128*m; R = D distinct debited slots,
//	          D <= min(m, max_reads); W >= D + 1, one DELTA_SUB per debited slot
//	          and at least one credit. requiredAddrs is the debited addresses
//	          plus the deposit cell and there are at most D of the first, so
//	          S <= min(max_sigs, D+1).
//	ISSUE     U = 1; body IssueSize; R = 1; W >= 4. Every write is OpSet on an
//	          asset address, which IsUserAddress excludes, so requiredAddrs is
//	          the deposit cell and the issuer: S <= min(max_sigs, 2).
//	MINT      U = 1; body MintSize; R = 3; W >= 2. Both writes are DELTA_ADD, so
//	          requiredAddrs is the deposit cell alone and requiredKeys the
//	          declared minter: S <= min(max_sigs, 2).
//
// The region is finite and small — a few thousand points at the shipped limits,
// counted rather than estimated in the shape's points field — so it is
// enumerated whole rather than solved. **That is not the sweep rule 21 is
// about, and the difference is which side of the bound it lands on.** A sweep
// enumerates certificates somebody built and returns the largest of those,
// which is a lower bound on the maximum. This enumerates the *integers the
// rules admit*, and every certificate the rules admit maps to one of these
// points and is at most as dense as the point it maps to — so the maximum over
// the region is an upper bound over every certificate, including the ones
// nobody has built. Where a sweep can only refute, this can only bound; the
// attainment below is what supplies the other half.
//
// **What no test here separates, and how far the exposure runs.** The TRANSFER,
// ISSUE and MINT arms all lose max() to RETIRE, and no witness is built for any
// of them, exactly as era0CertByteCeiling's three dominated arms have none. An
// arm wrongly *lowered* is invisible and harmless. An arm wrongly *raised* above
// the RETIRE value is not: it makes max() return a point densestEra0Retire does
// not construct, and that function refuses to build rather than quietly
// returning something else — "the derived densest shape is a %s ... so it does
// not attain the ceiling". The bound would still bound; what would be lost, and
// said, is attainment.
func era0ParDensityCeiling(p *params.Params) era0DensestShape {
	fixed := types.CertMinSize + emptyProgramBytes
	points := map[string]int{}
	best := era0DensestShape{density: ratio{0, 1}}
	consider := func(kind string, units, sigs, n int) {
		points[kind]++
		if d := era0ParDensity(p, n, sigs, units); best.density.less(d) {
			best = era0DensestShape{kind: kind, units: units, sigs: sigs, bytes: n, density: d}
		}
	}

	for a := 1; a <= min(p.MaxRetireAddrs, p.MaxWrites); a++ {
		for s := 1; s <= min(p.MaxSigs, a+1); s++ {
			consider("RETIRE", a, s,
				fixed+len(types.Address{})*a+types.WriteSize*a+types.SigSize*s)
		}
	}
	for m := 1; m <= p.MaxMovesPerTransfer; m++ {
		for d := 1; d <= min(m, p.MaxReads) && d+1 <= p.MaxWrites; d++ {
			for s := 1; s <= min(p.MaxSigs, d+1); s++ {
				consider("TRANSFER", m, s,
					fixed+types.MoveSize*m+types.ReadSize*d+types.WriteSize*(d+1)+types.SigSize*s)
			}
		}
	}
	for s := 1; s <= min(p.MaxSigs, 2); s++ {
		consider("ISSUE", 1, s,
			fixed+types.IssueSize+types.ReadSize+types.WriteSize*4+types.SigSize*s)
		consider("MINT", 1, s,
			fixed+types.MintSize+types.ReadSize*3+types.WriteSize*2+types.SigSize*s)
	}
	best.points = points
	return best
}

// era0ProgramKinds is the closed Era-0 operation set (§9), named here so the
// enumeration can be required to have reached every one of them.
var era0ProgramKinds = []string{"RETIRE", "TRANSFER", "ISSUE", "MINT"}

// era0ParDensityLimit is the bound era0ParDensityCeiling approaches but never
// reaches **at every setting of the list limits**, and it is what answers the
// parameter question the uncoupled bound asks and gets wrong.
//
// That bound solves for the value of max_sigs at which B6 would become
// reachable at par_gas_ratio = 3 and reports 35. Under the coupled bound there
// is no such value: raising max_sigs raises the ceiling only towards this
// limit, which is 3.1111 against the 3.84 B6 asks.
//
// **The decomposition.** Split a certificate's block cost into groups and give
// each group the parallel gas its own bytes earn plus the gas of the signature
// and the derive unit that group requires. Every group's ratio is then an
// upper bound on a certificate made of that group alone, and a ratio of sums is
// at most the largest ratio of its parts, so the largest group bounds every
// certificate however many groups it has. The groups are exhaustive because V4
// charges each signature to something: at most one signature — the deposit
// cell's — is required by no unit of the program, and it goes in with the fixed
// section.
//
// **The premise, and it is asserted rather than reasoned about.** Listing a
// group with its signature over-counts gas against bytes for any certificate
// that carries fewer, and that is only the safe direction if dropping a
// signature *lowers* the group's ratio — which holds exactly when a signature's
// own ratio is above every row. It is (gas_par_per_sig + gas_par_per_byte *
// SigSize) / SigSize, 4.0833 at the shipped schedule against a largest row of
// 3.1111. era0LoneSignatureDensity computes it and assertB6IsInertByDerivation
// requires it, because a universal claim resting on a premise nothing asserts
// is the exact shape of the parameter note this derivation retires.
func era0ParDensityLimit(p *params.Params) ratio {
	group := func(certBytes, blockBytes, sigs, units int) ratio {
		return ratio{
			int(p.GasParPerByte)*certBytes + int(p.GasParPerSig)*sigs +
				int(p.GasParPerDeriveUnit)*units,
			certBytes + blockBytes,
		}
	}
	groups := []ratio{
		// The fixed section, the program header and the one signature no unit
		// requires — the deposit cell's — carrying the block's per-certificate
		// offset with it.
		group(types.CertMinSize+emptyProgramBytes+types.SigSize, perCertBlockOverhead, 1, 0),
		// RETIRE: one target, its MARK_SPENT, and the signature it requires.
		// This is the largest group at the shipped schedule and so the limit.
		group(len(types.Address{})+types.WriteSize+types.SigSize, 0, 1, 1),
		// TRANSFER: one debited slot — its guard read, its DELTA_SUB and the
		// signature that address requires — and, separately, one move and any
		// write no debit accounts for.
		group(types.ReadSize+types.WriteSize+types.SigSize, 0, 1, 0),
		group(types.MoveSize, 0, 0, 1),
		group(types.WriteSize, 0, 0, 0),
		// ISSUE and MINT are fixed shapes; each takes its whole body, its reads,
		// its writes and its second signature as one group.
		group(types.IssueSize+types.ReadSize+4*types.WriteSize+types.SigSize, 0, 1, 1),
		group(types.MintSize+3*types.ReadSize+2*types.WriteSize+types.SigSize, 0, 1, 1),
	}
	limit := groups[0]
	for _, g := range groups[1:] {
		if limit.less(g) {
			limit = g
		}
	}
	return limit
}

// era0LoneSignatureDensity is what one signature costs per byte of itself: the
// per-signature term plus the parallel gas its own 96 bytes earn. It is the
// densest thing an Era-0 certificate is made of, and era0ParDensityLimit's
// soundness is exactly the statement that it stays that way.
func era0LoneSignatureDensity(p *params.Params) ratio {
	return ratio{int(p.GasParPerSig) + int(p.GasParPerByte)*types.SigSize, types.SigSize}
}

// densestEra0Retire builds a certificate that attains era0ParDensityCeiling,
// from the derived shape rather than from the shipped numbers, so that the two
// sides move together or the test says which one did not.
//
// **The arrangement, and why the deposit cell decides it.** The targets are
// one-shot addresses of distinct keys, so each requires its own signature and
// buys 200 parallel gas for 32 program bytes plus a 97-byte MARK_SPENT. The
// deposit cell is a **fresh persistent** address: it is the one signature no
// target requires, and being persistent it derives no MARK_SPENT of its own, so
// it buys the same 200 gas for 96 bytes rather than for 193. Paying the deposit
// out of a target's own cell instead spends the signature and keeps the write,
// and paying it out of a fresh one-shot cell keeps the signature and adds the
// write — both are built by the refutation pass below and both are less dense.
func densestEra0Retire(t *testing.T, p *params.Params, shape era0DensestShape) *types.Certificate {
	t.Helper()
	if shape.kind != "RETIRE" || shape.sigs != shape.units+1 {
		t.Fatalf("the derived densest shape is a %s of %d units under %d signatures; this "+
			"construction builds a RETIRE of a targets under a+1 signatures, so it does not "+
			"attain the ceiling and attainment has to be re-derived at these parameters",
			shape.kind, shape.units, shape.sigs)
	}
	c, err := retireOfWidth(t, p, shape.units, depositFreshPersistent)
	if err != nil {
		t.Fatalf("the densest Era-0 retire did not build at %s: %v", p.Name, err)
	}
	return c
}

// The three deposit arrangements a RETIRE can take, which is the dimension the
// width figure was filed without searching.
const (
	depositFreshPersistent = iota // one extra signature, no extra write
	depositFreshOneShot           // one extra signature and one extra MARK_SPENT
	depositOwnTarget              // no extra signature, no extra write
)

// retireOfWidth builds a RETIRE of a one-shot targets under one of the three
// deposit arrangements, or returns why the V-rules refuse it.
func retireOfWidth(t *testing.T, p *params.Params, a, deposit int) (*types.Certificate, error) {
	t.Helper()
	if a < 1 {
		return nil, errShapeInfeasible
	}
	addrs := make([]types.Address, 0, a)
	signers := make([]*wallet.Key, 0, a+1)
	for i := 0; i < a; i++ {
		k := ceilingKey(t, uint16(0x900+i))
		signers = append(signers, k)
		addrs = append(addrs, k.OneShot())
	}
	// The refund goes to a key that takes no other role: V5 refuses a refund
	// into any address this certificate marks spent, and every target is one.
	refund := ceilingKey(t, 0x9FE).Persistent()
	cell := addrs[0]
	switch deposit {
	case depositFreshPersistent:
		k := ceilingKey(t, 0x9FF)
		signers = append(signers, k)
		cell = k.Persistent()
	case depositFreshOneShot:
		k := ceilingKey(t, 0x9FF)
		signers = append(signers, k)
		cell = k.OneShot()
	}
	return (&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(addrs...),
		Seq:     0,
		TTL:     240,
		Deposit: wallet.SelfDeposit(cell, refund),
		FeeBid:  ceilingBid(),
		Signers: signers,
	}).Build()
}

// assertSigBudgetRefuses states, before building, that a RETIRE one target past
// the signature budget must be refused as V1 — PROTOCOL rule 22's direction
// declaration applied to a construction, and the neighbour
// TestTheWidestEra0CertificateIsDerivedAndAttained has for max_writes but not
// for max_sigs.
//
// A shape that builds here means max_sigs is not the constraint the density
// ceiling is derived against, and the ceiling is derived off the wrong limit.
// Naming V1 rather than merely "refused" is the other half: the same shape
// would also be refused for a bad deposit arrangement, and that refusal would
// prove nothing about the signature budget.
func assertSigBudgetRefuses(t *testing.T, p *params.Params) {
	t.Helper()
	// max_sigs targets plus the deposit cell's own key is max_sigs+1 signatures,
	// and nothing else in the shape is over a limit — so V1 can only be
	// answering about signatures.
	a := p.MaxSigs
	if a > p.MaxRetireAddrs || a > p.MaxWrites {
		t.Fatalf("a RETIRE of max_sigs=%d targets is already over max_retire_addrs=%d or "+
			"max_writes=%d, so a refusal here would not be about the signature budget",
			a, p.MaxRetireAddrs, p.MaxWrites)
	}
	c, err := retireOfWidth(t, p, a, depositFreshPersistent)
	if err == nil {
		t.Fatalf("a %d-target RETIRE paying its deposit from a fresh persistent cell built with "+
			"%d signatures against max_sigs=%d and had to be refused; max_sigs is not the "+
			"binding constraint the density ceiling is derived against", a, len(c.Sigs), p.MaxSigs)
	}
	if got := validity.Rule(err); got != "V1" {
		t.Fatalf("the over-budget shape was refused as %q, want V1: %v", got, err)
	}
}

// TestEra0ParallelDensityIsDerivedAndAttained closes for B6's premise the loop
// TestTheWidestEra0CertificateIsDerivedAndAttained closes for B13's: a derived
// upper bound and a constructed lower bound that meet.
//
// The two assertions below fail for different reasons and say so, because they
// are different findings:
//
//   - **built > derived** means era0ParDensityCeiling is WRONG. A certificate
//     the V-rules admit is denser than the derivation says any can be, and
//     every figure taken from it — this file's claim that B6 cannot fire, the
//     margin quoted for it — is unsound.
//   - **built < derived** means the ceiling is no longer known to be ATTAINED.
//     It still bounds, and B6's inertness still follows from it; what is lost is
//     the right to call 3.0352 the densest Era-0 shape rather than an upper
//     bound on it.
//
// The refutation pass is deliberately the weakest instrument here and is used
// only in the direction a sweep is sound in. It cannot confirm the bound — that
// is the mistake this file's history is made of — but a single shape above it
// refutes it.
func TestEra0ParallelDensityIsDerivedAndAttained(t *testing.T) {
	for _, p := range []*params.Params{spec.Devnet(), spec.Testnet(), spec.Mainnet()} {
		t.Run(p.Name, func(t *testing.T) {
			shape := era0ParDensityCeiling(p)
			// Anti-vacuity on the enumeration itself, asked of each arm rather
			// than of the total: an arm that empties takes a few hundred points
			// out of a few thousand, so a total-based guard would still read
			// healthy while the ceiling had stopped bounding a whole program
			// kind.
			for _, kind := range era0ProgramKinds {
				if shape.points[kind] == 0 {
					t.Fatalf("the derived region contains no %s point at all (points by kind: %v), "+
						"so the ceiling bounds every Era-0 program kind except that one; a list "+
						"limit or a loop bound has emptied an arm", kind, shape.points)
				}
			}
			c := densestEra0Retire(t, p, shape)
			got := ratio{int(c.ParGas(p)), c.SizeBytes() + perCertBlockOverhead}
			if shape.density.less(got) {
				t.Fatalf("a certificate wallet.Builder accepts costs %d parallel gas in %d block "+
					"bytes, %.4f per byte, against a derived ceiling of %.4f, so "+
					"era0ParDensityCeiling is wrong and every figure taken from it is unsound",
					c.ParGas(p), c.SizeBytes()+perCertBlockOverhead, got.dec(), shape.density.dec())
			}
			if got.less(shape.density) {
				t.Fatalf("the densest certificate this file can construct is %.4f parallel gas per "+
					"block byte against a derived ceiling of %.4f; the ceiling still bounds but is "+
					"no longer known to be attained, so it may not be quoted as the densest Era-0 "+
					"shape until the construction is re-derived at these parameters",
					got.dec(), shape.density.dec())
			}
			// Non-vacuity: the witness must sit on the limits the derivation
			// spends its budget on, or it reached the number some other way and
			// the derivation is not what is being confirmed.
			if len(c.Sigs) != shape.sigs || int(c.Program.DeriveUnits()) != shape.units ||
				len(c.Reads) != 0 || len(c.Writes) != shape.units || c.SizeBytes() != shape.bytes {
				t.Fatalf("the witness carries %d signatures, %d derive units, %d reads and %d "+
					"writes in %d bytes; the derivation's densest point spends %d/%d/0/%d in %d, "+
					"so this certificate reaches the ceiling by some other route",
					len(c.Sigs), c.Program.DeriveUnits(), len(c.Reads), len(c.Writes),
					c.SizeBytes(), shape.sigs, shape.units, shape.units, shape.bytes)
			}
			if limit := era0ParDensityLimit(p); !shape.density.less(limit) {
				t.Fatalf("the derived ceiling %.4f is not below the limit-free bound %.4f, so the "+
					"group decomposition era0ParDensityLimit rests on does not cover the shape "+
					"the enumeration found and the parameter claim built on it is unsound",
					shape.density.dec(), limit.dec())
			}

			// The neighbour first: one target past the signature budget must be
			// refused, and refused as V1.
			assertSigBudgetRefuses(t, p)

			// The refutation pass, over both dimensions the derivation couples:
			// retire width against all three deposit arrangements, and the
			// transfer family the width lane already builds.
			//
			// **Counted per family, for the reason the region above is.** These
			// are two independent families and a single total is the same
			// instrument rule 24 warns about one level up: emptying either one
			// leaves the other's hundred-odd shapes standing, so `built == 0`
			// stays false and the pass reports success over a family it never
			// built. Measured, not reasoned — a review declared both emptyings
			// to survive a total-based guard, and both did.
			widest := ratio{0, 1}
			built := map[string]int{}
			refute := func(family string, x, y int, c *types.Certificate) {
				built[family]++
				d := ratio{int(c.ParGas(p)), c.SizeBytes() + perCertBlockOverhead}
				if widest.less(d) {
					widest = d
				}
				if shape.density.less(d) {
					t.Fatalf("a %s shape at (%d, %d) costs %d parallel gas in %d block bytes, "+
						"%.4f per byte, over the derived ceiling of %.4f: the derivation is "+
						"refuted", family, x, y, c.ParGas(p), c.SizeBytes()+perCertBlockOverhead,
						d.dec(), shape.density.dec())
				}
			}
			for a := 1; a <= min(p.MaxRetireAddrs, p.MaxWrites); a++ {
				for _, dep := range []int{depositFreshPersistent, depositFreshOneShot, depositOwnTarget} {
					c, err := retireOfWidth(t, p, a, dep)
					if err != nil {
						continue
					}
					refute("RETIRE", a, dep, c)
				}
			}
			for keys := 1; keys <= p.MaxSigs; keys++ {
				for dsts := 1; dsts <= p.MaxMovesPerTransfer; dsts += 3 {
					c, err := wideTransfer(t, p, keys, dsts, p.MaxMovesPerTransfer)
					if err != nil {
						continue
					}
					refute("TRANSFER", keys, dsts, c)
				}
			}
			for _, family := range []string{"RETIRE", "TRANSFER"} {
				if built[family] == 0 {
					t.Fatalf("the refutation pass built no %s shape at all (built by family: %v), "+
						"so it refuted nothing about that family — and a total over the two "+
						"would still have read healthy on the other one's shapes", family, built)
				}
			}
			t.Logf("%s: derived ceiling %d/%d = %.4f par gas per block byte over a region of %v, "+
				"at a %d-target RETIRE under %d signatures in %d bytes, attained; limit-free "+
				"bound %.4f; shapes built %v, densest %.4f, none over", p.Name,
				shape.density.num, shape.density.den, shape.density.dec(), shape.points,
				shape.units, shape.sigs, shape.bytes, era0ParDensityLimit(p).dec(),
				built, widest.dec())
		})
	}
}

// TestB6CannotFireOnAnyBlockTheByteCeilingAdmits is the universal claim rule 21
// asks to be derived rather than asserted, and which the fee-market re-pin
// already made for this rule's sister.
//
// "B6 is unreachable" is a claim about every block nobody built, and there is no
// existential form of it. What there is instead is a derivation:
// era0ParDensityCeiling bounds what one certificate can cost per block byte, a
// block's density is at most its densest certificate's, and both ceilings the
// comparison runs between scale from the same T — so the whole statement is
// T-free arithmetic over the parameters.
func TestB6CannotFireOnAnyBlockTheByteCeilingAdmits(t *testing.T) {
	for _, p := range []*params.Params{spec.Devnet(), spec.Testnet(), spec.Mainnet()} {
		t.Run(p.Name, func(t *testing.T) { assertB6IsInertByDerivation(t, p) })
	}
}

// assertB6IsInertByDerivation states, from the parameters and the derivation
// rather than from any block, that no block within B13's byte ceiling can
// breach B6's parallel one.
//
// **The argument, in the order the code below takes it.**
//
//  1. A block's parallel gas is the sum of its certificates' and its size is at
//     least the sum of theirs plus perCertBlockOverhead each — the block's own
//     envelope and any cited headers are bytes carrying no parallel gas at all —
//     so a block is never denser than its densest certificate.
//  2. era0ParDensityCeiling bounds that, for every certificate the V-rules
//     admit rather than for every certificate anybody built.
//  3. What B6 asks is ParGasLimit(T)/BlockByteLimit(T), and T cancels:
//     BlockByteLimit floors block_byte_limit_genesis*T/T0, so the quotient is
//     never below its value at T0, which is 2*par_gas_ratio*T0 over
//     block_byte_limit_genesis. The flooring premise is checked over T's whole
//     legal interval below, at the ends and at the rungs in between, because it
//     is the step that makes the rest T-free.
//
// Both folds check B13 before B6 (core/fold/blockrules.go and sim/refold's
// checkBlock), so a block over both is refused as B13 and B6 is unreachable
// rather than merely dominated. The conclusion here does not depend on that
// order — a block over the byte ceiling is invalid whichever rule names it.
func assertB6IsInertByDerivation(t *testing.T, p *params.Params) {
	t.Helper()
	// The premise the enumeration rests on: with the one signature V1 requires,
	// a certificate's parallel gas already exceeds what its four bytes of block
	// overhead cost, so density strictly falls as the encoding grows and each
	// shape is densest at its minimum encoding.
	if int(p.GasParPerSig)+int(p.GasParPerDeriveUnit) <= perCertBlockOverhead*int(p.GasParPerByte) {
		t.Fatalf("one signature and one derive unit earn %d parallel gas against the %d that "+
			"%d bytes of block overhead cost; density no longer falls as a certificate grows, "+
			"and era0ParDensityCeiling's minimum encodings are no longer its maximisers",
			int(p.GasParPerSig)+int(p.GasParPerDeriveUnit),
			perCertBlockOverhead*int(p.GasParPerByte), perCertBlockOverhead)
	}
	t0 := p.SeqGasTargetGenesis
	asks := ratio{int(p.ParGasLimit(t0)), p.BlockByteLimit(t0)}
	for _, tt := range []uint64{t0, t0 + 1, t0 + t0/p.CeilingGrowthDivisor,
		t0 + (p.SeqGasCapacity-t0)/2, p.SeqGasCapacity - 1, p.SeqGasCapacity} {
		if tt < t0 || tt > p.SeqGasCapacity {
			continue
		}
		if got := (ratio{int(p.ParGasLimit(tt)), p.BlockByteLimit(tt)}); got.less(asks) {
			t.Fatalf("at T=%d B6 asks %.4f parallel gas per block byte, below the %.4f it asks at "+
				"T=%d; the ratio is not T-invariant in the direction this derivation needs and "+
				"the bound below holds only at genesis", tt, got.dec(), asks.dec(), t0)
		}
	}

	ceiling := era0ParDensityCeiling(p)
	if !ceiling.density.less(asks) {
		t.Fatalf("Era-0 parallel density is bounded at %.4f per block byte and B6 asks %.4f at "+
			"par_gas_ratio=%d; B6 is no longer inert in Era 0, so this file may not claim it "+
			"cannot fire and the retired unreachability conclusion needs re-deriving",
			ceiling.density.dec(), asks.dec(), p.ParGasRatio)
	}
	// The stronger half, and the one the uncoupled bound gets wrong: raising
	// max_sigs or max_retire_addrs moves the ceiling only towards
	// era0ParDensityLimit, so if that is under what B6 asks, no setting of the
	// list limits reaches it.
	limit := era0ParDensityLimit(p)
	// Its soundness premise first. Each row of the decomposition is listed with
	// the signature its unit requires and so over-counts gas against bytes for a
	// certificate carrying fewer — safe only while dropping a signature lowers
	// the row's ratio, which is the same as a lone signature outranking every
	// row. Nothing asserted that until this line.
	if lone := era0LoneSignatureDensity(p); !limit.less(lone) {
		t.Fatalf("one signature costs %.4f parallel gas per byte of itself, at or below the "+
			"limit-free bound of %.4f; dropping a signature from a group of "+
			"era0ParDensityLimit no longer lowers that group's ratio, so the decomposition "+
			"over-counts in the unsafe direction and the claim that no setting of the list "+
			"limits reaches B6 is unsound", lone.dec(), limit.dec())
	}
	if asks.less(limit) {
		t.Fatalf("Era-0 density is bounded at %.4f per block byte at any list limits, and B6 asks "+
			"only %.4f; B6 remains inert at the shipped max_sigs=%d, but the claim that no value "+
			"of max_sigs can reach it no longer holds", limit.dec(), asks.dec(), p.MaxSigs)
	}
	t.Logf("%s: B6 asks %d/%d = %.4f par gas per block byte at every T in [%d, %d]; Era 0 "+
		"supplies at most %.4f (derived and attained) and at most %.4f at any list limits, "+
		"%.1f%% and %.1f%% of it", p.Name, asks.num, asks.den, asks.dec(), t0, p.SeqGasCapacity,
		ceiling.density.dec(), limit.dec(), 100*ceiling.density.dec()/asks.dec(),
		100*limit.dec()/asks.dec())
}

// TestDevnetsByteRuleIsReachedByTheWidestCertificate builds the block
// TestBothFoldsAgreeAtTheBlockByteCeiling's comment claims exists at devnet,
// instead of leaving its arithmetic to be re-checked by hand.
//
// **What this asserts, and what it deliberately does not.** B13 compares
// b.SizeBytes() against BlockByteLimit(T) and is checked before any certificate
// is applied, so the block below is refused for its size whatever its
// certificates would have done in a fold. What the arm needs, and all it needs,
// is that the size is reachable without some other block ceiling firing first —
// which is why the count, the 4T bound and the parallel ceiling are all
// asserted here, and why no chain is built: funding 164 blocks' worth of
// one-shot sources would test the harness, not the rule.
//
// The 2T soft threshold is reported and not asserted. Devnet carries mainnet's
// seq_gas_target_genesis of 1,600,000, so 2T sits low enough that this block
// crosses it rather than resting under a thin margin. That makes it a burst-forfeiture block, which is a price F11
// charges a valid producer and not a rule any block is refused by, so the B13
// claim is untouched.
func TestDevnetsByteRuleIsReachedByTheWidestCertificate(t *testing.T) {
	p := spec.Devnet()
	target := p.SeqGasTargetGenesis
	limit, count := p.BlockByteLimit(target), p.MaxCertsPerBlock(target)

	var certs []*types.Certificate
	var seqGas, parGas uint64
	for len(certs) == 0 || types.BlockOverheadBytes(len(certs), 0)+bodyBytes(certs) <= limit {
		if len(certs) > count {
			t.Fatalf("%d widest certificates are still under the %d-byte ceiling at T=%d, but "+
				"the count ceiling is %d, so B12 refuses the block before B13 is reached and "+
				"the byte rule is unreachable at devnet", len(certs), limit, target, count)
		}
		c := widestEra0Transfer(t, p, 0x1000+len(certs)*8)
		certs = append(certs, c)
		seqGas += c.SeqGas(p)
		parGas += c.ParGas(p)
	}

	b := &types.Block{Certs: certs}
	if b.SizeBytes() <= limit {
		t.Fatalf("the block encodes to %d bytes against a ceiling of %d, so the size model the "+
			"loop above grew it with is not the encoder's", b.SizeBytes(), limit)
	}
	if len(certs) > count {
		t.Fatalf("the block carries %d certificates against a ceiling of %d, so B12 refuses it "+
			"before B13", len(certs), count)
	}
	if burst := p.SeqGasBurst(target); seqGas > burst {
		t.Fatalf("the block declares %d sequential gas against a 4T bound of %d, so B5 refuses "+
			"it before B13", seqGas, burst)
	}
	// The 2T threshold is reported, not enforced, and the difference is the one
	// this file states everywhere else: checkBlockRules rejects only above
	// SeqGasBurst(T) = 4T, asserted immediately above. 2T is F11's forfeiture
	// threshold -- a price on the producer's subsidy, charged after the block is
	// already valid -- so a block above it is still a block B13 refuses for its
	// size. Until the gas-schedule respin this block sat at 98.8% of 2T and the
	// margin was worth pinning; devnet's target moved from 2,000,000 to 1,600,000
	// with mainnet's, 2T came down with it, and the same block now crosses it.
	// Nothing about the B13 arm moved with that: what would break the witness is
	// 4T, the count ceiling or B6, and each is a Fatalf here.
	if soft := p.SeqGasLimit(target); seqGas > soft {
		t.Logf("the block declares %d sequential gas against the 2T threshold of %d (%.1f%% of "+
			"it), so it is also a burst-forfeiture block; F11 prices that rather than refusing "+
			"it, and B13 is checked before any certificate is applied",
			seqGas, soft, 100*float64(seqGas)/float64(soft))
	}
	if parLimit := p.ParGasLimit(target); parGas > parLimit {
		t.Fatalf("the block declares %d parallel gas against a ceiling of %d, so B6 refuses it "+
			"before B13", parGas, parLimit)
	}
	t.Logf("devnet T=%d: %d widest certificates are %d bytes against a %d-byte ceiling, at %d "+
		"of %d certificates, %d sequential gas (2T %d, %.1f%% of it; 4T %d) and %d parallel gas "+
		"(ceiling %d)", target, len(certs), b.SizeBytes(), limit, len(certs), count, seqGas,
		p.SeqGasLimit(target), 100*float64(seqGas)/float64(p.SeqGasLimit(target)),
		p.SeqGasBurst(target), parGas, p.ParGasLimit(target))
}

func bodyBytes(cs []*types.Certificate) int {
	n := 0
	for _, c := range cs {
		n += len(c.MarshalSSZ())
	}
	return n
}

// TestBothFoldsAgreeAtTheCitationCountCeiling drives rule B15.
//
// **Derivation.** The compared quantity is len(b.Cites), against
// max_cites_per_block itself — the one bound of the three that is a bare
// parameter rather than a function of T, so the comparison is all there is to
// separate.
//
// The reachable range of the compared quantity is the number of distinct
// siblings the block's parent has, which is unbounded in principle: any number
// of proposers may win the same height. It is *encoding*-bounded at
// max_cites_per_block, because ComputeCitesRoot merkleizes the list against
// that capacity and panics above it — which is exactly why both folds check the
// count before computing the root, and why the ceiling+1 block below is built
// without a citation root.
//
// The two consecutive values that separate the rule are 4 and 5 at all three
// shipped networks, and **both lie inside the reachable range**: a block whose
// parent has five siblings is what a real network produces under a burst of
// concurrent proposals.
//
// What was there before: the corpus carries eight citation vectors and the
// widest of them cites **two** headers, against a ceiling of four. Nothing drove
// the ceiling from either side, so a `>` -> `>=` mutant here refused nothing any
// test built and survived.
func TestBothFoldsAgreeAtTheCitationCountCeiling(t *testing.T) {
	p := spec.Devnet()
	w := newFolds(t, p)
	miner := ceilingKey(t, 1)
	payout := miner.Persistent()
	// Height 2 is the first at which a citation is legal at all (B17), and the
	// grandparent and target slots C2 and C4 read are written by the parent.
	for i := 0; i < 4; i++ {
		if !w.commit(t, payout) {
			t.Fatalf("both folds refused an empty block at height %d", w.chain.NextHeight())
		}
	}
	ceiling := p.MaxCitesPerBlock
	if ceiling < 1 {
		t.Fatalf("max_cites_per_block is %d; there is no separating pair to drive", ceiling)
	}

	// ceiling+1 genuine siblings of the tip: competing proposals at the same
	// height, against the same grandparent, at the same difficulty, differing
	// only in payout address. Sorted by id, because C5 requires it and an
	// unsorted list would pin C5 instead.
	cites := make([]*types.Header, 0, ceiling+1)
	for i := 0; i <= ceiling; i++ {
		sib := w.chain.Sibling(ceilingKey(t, uint16(0x400+i)).Persistent())
		if sib == nil {
			t.Fatal("the chain is too young to have siblings")
		}
		cites = append(cites, sib)
	}
	sort.Slice(cites, func(a, b int) bool {
		x, y := cites[a].ID(), cites[b].ID()
		for i := range x {
			if x[i] != y[i] {
				return x[i] < y[i]
			}
		}
		return false
	})
	for i := 1; i < len(cites); i++ {
		if cites[i-1].ID() == cites[i].ID() {
			t.Fatal("two siblings share an id, so the list is not strictly sorted and C5 " +
				"would refuse it before B15 is reached")
		}
	}

	// The refused side. It cannot go through ProposeWithCites: that computes the
	// citation root, and merkleizing ceiling+1 entries against a capacity of
	// ceiling panics rather than erroring — the panic B15 exists to be checked
	// before. Both folds check the count before the root, so the root this block
	// carries is never read.
	tip := w.chain.Tip()
	over := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + p.TargetBlockSeconds,
			EmissionAddr: payout,
			Target:       tip.Target,
			PoW:          tip.PoW,
		},
		Cites: cites,
	}
	over.Header.CertRoot = over.ComputeCertRoot(p)
	if len(over.Cites) != ceiling+1 {
		t.Fatalf("the refused block carries %d citations, not ceiling+1 = %d",
			len(over.Cites), ceiling+1)
	}
	fastRule, naiveRule := w.rules(over)
	if fastRule != "B15" || naiveRule != "B15" {
		t.Fatalf("a block of %d citations against a ceiling of %d is refused as %q by "+
			"core/fold and %q by sim/refold, want B15 from both",
			len(over.Cites), ceiling, fastRule, naiveRule)
	}

	// The admitted side: exactly the ceiling, with a real citation root, folded
	// by both. This is the side nothing drove.
	at, err := w.chain.ProposeWithCites(payout, cites[:ceiling])
	if err != nil {
		t.Fatalf("propose with %d citations: %v", ceiling, err)
	}
	if !w.foldOn(t, w.chain.State, w.naive, at, true) {
		fr, nr := w.rules(at)
		t.Fatalf("a block citing exactly %d headers — the ceiling itself — was refused "+
			"(core/fold %q, sim/refold %q); the comparison is an off-by-one", ceiling, fr, nr)
	}
	// Non-vacuity: the citations must have been counted, or the block above was
	// folded as though it cited nothing.
	cited, _ := w.chain.State.Get(types.CitedCountSlot()).Uint64()
	if cited < uint64(ceiling) {
		t.Fatalf("the health-gate counter stands at %d after a block citing %d headers, so "+
			"the citations were not folded and this arm drove nothing", cited, ceiling)
	}
	t.Logf("devnet: %d citations folded by both implementations, %d refused as B15 by both; "+
		"health-gate counter %d", ceiling, ceiling+1, cited)
}
