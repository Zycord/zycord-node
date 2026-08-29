package sim

import (
	"fmt"
	"math/rand"

	"zycord/core/crypto"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/sim/harness"
	"zycord/sim/refold"
	"zycord/wallet"
)

// Runner drives a chain forward with randomised but reproducible traffic, and
// checks every block through both fold implementations.
//
// Reproducibility is the whole value: a divergence is reported with its seed,
// and the seed replays the exact block sequence that found it.
type Runner struct {
	Params *params.Params
	Chain  *harness.Chain
	Naive  *refold.State
	Seed   int64

	rng *rand.Rand
	// vrng drives every random choice the asset-vault pipeline makes — its key
	// derivations, its amounts, its payee — so that none of them is a draw of
	// rng's stream. A new arm in generate()'s switch re-rolled that stream
	// outright and cost seed 7 its one-shot-funded census, for no reason connected
	// to what was being added.
	//
	// **This keeps the draw sequence identical. It does not keep the run
	// identical, and it cannot.** The pipeline appends certificates and
	// consumes nextMinerSeq(), so committed state differs, and every
	// generator branch that reads state — every funded/IsSpent predicate,
	// every guard that decides applied against skipped — branches
	// differently. Measured across 8 seeds at 120 steps: ForgedSeedEpoch is
	// identical on every seed, which is the proof the stream discipline works
	// where nothing else leaks; OneShotFunded moved on every seed, and on
	// seed 5 it fell from 8 to 1 — still non-zero, so its guard holds, but at
	// a margin of one. That is inherent to adding traffic to a shared chain,
	// not a defect in this stream, and the honest statement is this one
	// rather than "not a single draw shifts".
	vrng *rand.Rand
	// advRng drives adversarial probes only, so that adding one never shifts
	// the traffic generator's stream and never moves what a seed exercises.
	advRng *rand.Rand
	// hrng drives the TTL-horizon probe and nothing else. It is a third stream for
	// the reason advRng is a second one: the probe folds extra blocks and draws
	// for every one of them, and sharing advRng would have moved which blocks
	// probeSeedEpoch and probeReSigned land on. Both of those are asserted
	// non-zero per seed, so a shared stream would have made adding this probe a
	// change to what every existing seed exercises. With its own stream, rng, vrng
	// and advRng all produce byte-identical sequences to a run without this probe.
	hrng    *rand.Rand
	miner   *wallet.Key
	payout  types.Address
	actors  []*actor
	pending []*types.Certificate
	// history holds committed certificates so the generator can try to replay
	// one occasionally — the block rules must reject it, and both
	// implementations must reject it the same way.
	history []*types.Certificate

	minerSeq uint64
	// Rejected counts blocks both implementations refused. A run in which
	// nothing was ever rejected has not exercised the block rules.
	Rejected int

	// OneShotFunded counts the certificates the generator produced whose deposit
	// cell is a one-shot address and whose program moves no value of its own —
	// ISSUE, MINT, RETIRE. That class was jointly unsatisfiable under V3 and V6
	// until F-VAL-5 was fixed, and for as long as wallet.Builder could not
	// construct one, this generator went on attempting them and silently
	// discarding every attempt: the class was legal and had zero randomised
	// coverage. This is a census, not a rule, and the differential suite asserts
	// it is non-zero so the coverage cannot quietly return to none.
	OneShotFunded int

	// NamedAssetBurns counts burns that landed while the same certificate named a
	// non-native cell under the burned address — F8b's second clause and the only
	// traffic that reaches it. A census in the same sense as OneShotFunded and for
	// the same reason: with this shape absent from the generator, deleting the
	// clause from sim/refold alone left the whole sim suite green, so the
	// strongest cross-implementation instrument the project has was blind to half
	// of a new consensus rule.
	NamedAssetBurns int

	// The asset-vault pipeline's own state; see genAssetVault.
	factory      *wallet.Key
	factoryAsset types.Address
	factoryCap   u256.U256
	factorySeq   uint64
	vaultKey     *wallet.Key
	vaultStage   int
	issueWait    int
	// The moveless one-shot underwriter: a fresh 0x01 cell that funds an
	// ISSUE and is burned only by withDepositMarkSpent. See genMovelessOneShot.
	movelessKey *wallet.Key
	movelessSym uint64

	// Burst counts committed blocks whose INCLUDED sequential gas exceeded the
	// soft ceiling 2T, so F11's forfeiture ran (whitepaper §8.1). Included, not
	// applied: the valve is assessed on every certificate the block carries,
	// skips included, and a run that only watched applied gas would report a
	// bursting block as an ordinary one.
	Burst int
	// ForgedSeedEpoch counts blocks whose declared proof-of-work key epoch was
	// corrupted on purpose before both folds saw it. Without it the differential
	// is structurally blind to core/fold's checkSeedEpoch: this generator only
	// ever produces CORRECT seed epochs, so removing the rule from core/fold
	// changes nothing either fold decides and the two agree all the way down.
	// Mutation-proven — deleting the rule left every differential seed green
	// until this counter's corruption existed to feed it. It is the same shape
	// as I6-M3's finding about uniform inputs, met a second time.
	ForgedSeedEpoch int
	// HorizonAccepted, HorizonRejected and HorizonZeroDistance count the arms of
	// the TTL-horizon probe that ran.
	//
	// Before that probe existed the differential was structurally blind to B2's
	// horizon, and not by an accident of seeding. Runner.ttl() clamps the span it
	// draws to min(ttl_max, 8), so a generated certificate sits d in [1,
	// min(ttl_max, 8)] blocks ahead of the block carrying it. B2's bound is 240 on
	// mainnet and 32 on devnet, so at every SHIPPED parameter set the rule is
	// approached from neither side. A divergence between the two folds at that
	// horizon shipped once and was caught by a human reading the tree, not by the
	// machinery built to catch it.
	//
	// Deliberately NOT "at any parameter set". That stronger claim was true
	// when this comment was written, and the test suite below falsified it: at
	// ttl_max = 2 the span is 2, so d in {1, 2} reaches d = ttl_max and the
	// honest generator meets the accept side on its own -- measured, 241 times
	// across that arm's two seeds.
	//
	// What holds everywhere is the REJECT side, and only that: no route
	// INCREASES d, so d = ttl_max + 1 is unreachable at every parameter set.
	// Runner.ttl() caps a drawn d at min(ttl_max, 8) <= ttl_max, and genReplay
	// -- the one route that re-presents a certificate at a LATER height --
	// shifts d DOWN by the certificate's age. Measured over every certificate
	// in every block handed to Differential, honest and rejected alike:
	// d > ttl_max zero times in six runs, max d exactly min(ttl_max, 8).
	//
	// d = 0 is NOT unreachable, and the +1 does not make it so. The +1 bounds
	// the distance the generator DRAWS; genReplay separates that from the
	// distance B2 SEES. At the same wider scope, d = 0 occurs 5 times and
	// d < 0 (TTL below the block height, which B1 refuses) 78 times, and every
	// one of the 83 is a re-inclusion of an already-committed certificate.
	// A census of COMMITTED blocks reports zero for both and cannot report
	// anything else: a replay is what makes a block un-committable (B3), so
	// that scope structurally excludes the only route that reaches them.
	//
	// Rejected is counted separately from Accepted because a boundary has two
	// sides. An accept-only probe cannot tell B2 from a deleted B2, and a
	// reject-only probe cannot tell B2 from a B2 that is one off -- the arms
	// are the same certificate at consecutive TTLs, so only having both makes
	// either attributable to the rule.
	HorizonAccepted, HorizonRejected, HorizonZeroDistance int

	// HorizonAcceptedAtMax and HorizonRejectedPastMax count the two BOUNDARY
	// arms specifically -- d = ttl_max and d = ttl_max + 1 -- and nothing else.
	//
	// They exist because the three counters above cannot pin them. Accepted is
	// incremented by the d = 0 and 2^64-1 arms as well, and Rejected by the 2^64-1
	// arm, so a suite guarding only on those is satisfied entirely by the
	// NON-boundary arms: deleting either boundary arm, or both, left every guard
	// green and every subtest PASSing -- three separate mutants of the probe, none
	// of them killed. The separating pair is what the probe is named for, and
	// until these counters existed nothing checked it had been handed over.
	//
	// Load-bearing rather than decorative, established by the converse rather
	// than asserted -- and the measurement is bound to the tree it was taken
	// in, because that is the whole defect this file keeps meeting. BEFORE
	// these counters existed, a shared off-by-one `>=` in BOTH folds was
	// killed, while that same mutation applied together with the deletion of
	// both boundary arms SURVIVED: deleting the arms lost a unique kill and
	// nothing reported it. WITH these counters, both die, and the composite
	// cannot pass at all.
	//
	// What shows the two counters are separately load-bearing, at this head:
	// deleting the accept arm alone and deleting the reject arm alone fail at
	// DIFFERENT guards with different messages, and deleting both fires both
	// guards -- they are t.Errorf and not t.Fatalf, so neither masks the other.
	HorizonAcceptedAtMax, HorizonRejectedPastMax int

	// HorizonDeclined counts blocks the probe refused to reason about because
	// the control fold refused the honest block itself. It is reported rather
	// than swallowed: a run in which the control fold NEVER accepts is a run in
	// which the probe silently measured nothing, and that is indistinguishable
	// from a clean pass unless there is a number to look at.
	HorizonDeclined int

	// ParGasOverCeiling counts blocks handed to Differential whose aggregate
	// parallel gas exceeded ParGasLimit(T) -- the blocks rule B6 must refuse.
	//
	// Counted over every block handed to both folds, committed and rejected alike,
	// because a B6-breaking block is by definition never committed and a census
	// over committed blocks could only ever return zero -- the lesson of the
	// horizon probe, applied at the point the same mistake would recur.
	//
	// It exists because B6 was reachable by nothing: at all three shipped networks
	// ParGasLimit(T0) is par_gas_ratio * 2T = 3 * 2 * 1,600,000 = 9,600,000
	// against a largest generated block of 18,486 parallel gas, a factor of 519,
	// so no run at a shipped parameter value has ever handed either fold a block
	// the rule refuses. Measured: deleting B6 from sim/refold entirely survived
	// the whole ./sim package before this counter and the sweep that reads it
	// existed. The 40,000,000 and factor of 2,164 this comment carried were
	// devnet's par_gas_ratio 10 against a T0 of 2,000,000, and the "all three" was
	// already wrong for mainnet once its parallel ratio was re-derived; the
	// gas-schedule respin then put testnet and devnet on mainnet's schedule, so
	// one figure now covers all three and the conclusion is unchanged.
	ParGasOverCeiling int

	// Cited counts committed blocks that carried at least one citation, so
	// checkCites ran on a non-empty list in both implementations.
	Cited int
	// ReSigned counts blocks probed with a second, differently-signed encoding
	// of an authorization the block already carries.
	//
	// It exists for the same reason ForgedSeedEpoch does, and it was learned the
	// same way. This generator builds every certificate through wallet.Builder,
	// which signs with crypto/ed25519 and therefore deterministically, so it can
	// produce two encodings of one authorization by no path at all — and a corpus
	// that cannot produce the input cannot exercise the rule. Measured: with
	// core/fold enforcing a body-keyed rule and sim/refold still keying on the
	// whole encoding, a 382-second uncached differential run passed. The machinery
	// was capable (Differential compares the two verdicts and would have reported
	// `fast invalid / naive valid`); the corpus was blind. That is the pre-testnet
	// sweep's own structural pattern — a test built from an input incapable of
	// firing the rule — recurring one level up.
	ReSigned int

	// Grew and Decayed count epoch boundaries at which T moved in each
	// direction. Movement in one direction is not coverage of the other: the
	// controller's growth arm and its decay arm are different branches, and a
	// run that only ever grew has left half of NextSeqGasTarget unexercised.
	Grew, Decayed int
	// GateWithheld counts boundaries at which the health signal failed and
	// growth was withheld — the `hi = t` branch, which is the entire subject
	// of §8.1's health gate and is unreachable unless citations are frequent
	// enough to cross HealthGateBps.
	GateWithheld int

	// Dense guarantees every block carries at least one certificate that is
	// meant to apply.
	//
	// The default traffic mix is deliberately adversarial — most generated
	// certificates are built to skip, drop, or make the block invalid — which
	// is exactly right for exercising the block rules and exactly wrong for
	// exercising whitepaper §8.1's epoch controller. That controller's input
	// is APPLIED gas, and under the default mix more than half of committed
	// blocks apply nothing at all, so the lower median is 0 no matter how
	// small the target is made and T can never grow. Measured: at T₀ of 512,
	// 600, 1000 and 1500 the median was 0 in every case.
	Dense bool
}

type actor struct {
	key  *wallet.Key
	addr types.Address
	seq  uint64
	// asset is non-zero once this actor has issued one.
	asset    types.Address
	assetCap u256.U256
	funded   bool
}

// NewRunner builds a devnet chain, folds genesis through both implementations,
// and prepares a funded miner.
func NewRunner(p *params.Params, seed int64) (*Runner, error) {
	rng := rand.New(rand.NewSource(seed))
	vrng := rand.New(rand.NewSource(seed ^ 0x5645524e))

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

	r := &Runner{Params: p, Chain: chain, Naive: naive, Seed: seed, rng: rng, vrng: vrng,
		advRng: rand.New(rand.NewSource(^seed)),
		hrng:   rand.New(rand.NewSource(seed ^ 0x54544c48))}
	// Derived from vrng, like every other choice this pipeline makes; see the
	// vrng field for what that does and does not buy.
	r.factory = r.newVaultKey(vrng)
	r.miner = r.newKey()
	r.payout = r.miner.Persistent()

	// Mine to play: nothing can be spent until a coinbase matures.
	for i := 0; i <= int(p.CoinbaseMaturity)+1; i++ {
		if err := r.commit(nil); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// newVaultKey draws from the vault pipeline's own stream, for the reason
// Runner.vrng exists.
func (r *Runner) newVaultKey(g *rand.Rand) *wallet.Key {
	seed := make([]byte, 32)
	g.Read(seed)
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}

func (r *Runner) newKey() *wallet.Key {
	seed := make([]byte, 32)
	r.rng.Read(seed)
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}

// Step generates one block of traffic and checks it through both folds.
func (r *Runner) Step() error {
	r.generate()
	certs := r.pending
	r.pending = nil
	return r.commit(certs)
}

// probeSeedEpoch feeds both folds a copy of this block declaring the wrong
// proof-of-work key epoch, and requires them to agree that it is invalid.
//
// It exists because the differential is otherwise STRUCTURALLY BLIND to
// core/fold's checkSeedEpoch. This generator only ever produces correct seed
// epochs, so deleting the rule from core/fold changes nothing either fold
// decides, and every seed stays green — mutation-proven, that is exactly what
// happened before this probe existed. It is I6-M3's lesson met a second time:
// a scenario built from uniform input cannot pin a rule that only fires on
// non-uniform input, and correct-by-construction is a kind of uniform.
//
// The copy is what keeps this free. types.Block carries its Header by value,
// so mutating the copy's leaves the original alone, and neither fold mutates
// state for a block its block rules refuse — both check before they apply.
func (r *Runner) probeSeedEpoch(block *types.Block) error {
	if r.advRng.Intn(8) != 0 {
		return nil
	}
	probe := *block
	probe.Header.PoW.SeedEpoch += uint64(1 + r.advRng.Intn(3))

	accepted, err := Differential(r.Chain.State, r.Naive, &probe, r.Params)
	if err != nil {
		return err // one of the two stopped enforcing the schedule
	}
	if accepted {
		return fmt.Errorf(
			"both folds accepted a block at height %d declaring seed epoch %d; "+
				"the key schedule is enforced by neither",
			probe.Header.Height, probe.Header.PoW.SeedEpoch)
	}
	r.ForgedSeedEpoch++
	return nil
}

// probeReSigned feeds both folds a copy of this block carrying one of its
// certificates twice — once as proposed, and once re-signed by a key this
// runner holds — and requires them to agree that it is invalid.
//
// One authorization, two encodings. Nothing this generator produces on its own
// can reach that shape: wallet.Builder signs with crypto/ed25519, which is
// deterministic, so every certificate it builds has exactly one encoding and
// the in-block duplicate rule is only ever handed identical bytes. The
// certificate id is what both implementations key that rule on, and a corpus
// that never varies the signatures cannot tell an id over the authorization
// from an id over the bytes.
//
// Epoch boundaries are skipped: the header there commits to a state root, so
// an added certificate would make the block invalid for a second reason and the
// rejection would no longer be attributable to the duplicate.
//
// Like probeSeedEpoch this runs on a copy and draws from advRng, so the chain
// still advances on exactly the block ProposeWithCites produced and the traffic
// generator's stream is untouched.
func (r *Runner) probeReSigned(block *types.Block) error {
	if len(block.Certs) == 0 || r.Params.IsEpochBoundary(block.Header.Height) {
		return nil
	}
	// One block in eight, matching probeSeedEpoch, and the rate is a budget
	// rather than a preference. The probe folds an entire extra block through
	// *both* implementations, so at one in three it added about a third to the
	// work of the heaviest test in this package — measured: TestDifferentialFold
	// and TestDifferentialElasticCeiling fold 1800 Dense blocks between them,
	// and `go test -race ./sim/` then reached the 30-minute ceiling `make race`
	// sets and was killed inside Differential. One in eight keeps every seed
	// covered — the guard in differential_test.go fails a run that never probes,
	// and all eight seeds still probe — at roughly a tenth of the added cost.
	if r.advRng.Intn(8) != 0 {
		return nil
	}
	original := block.Certs[r.advRng.Intn(len(block.Certs))]
	variant := r.reSigned(original)
	if variant == nil {
		return nil
	}

	probe := *block
	probe.Certs = append(append([]*types.Certificate(nil), block.Certs...), variant)
	probe.Header.CertRoot = probe.ComputeCertRoot(r.Params)

	accepted, err := Differential(r.Chain.State, r.Naive, &probe, r.Params)
	if err != nil {
		return err // the two implementations disagree about one authorization
	}
	if accepted {
		return fmt.Errorf(
			"both folds accepted a block at height %d carrying two encodings of "+
				"authorization %x; one signature would be billed twice",
			probe.Header.Height, variant.ID())
	}
	r.ReSigned++
	return nil
}

// reSigned returns a copy of c carrying a different valid signature over the
// same body, or nil when this runner holds none of the keys that signed it.
//
// Every other signer's bytes are carried across untouched, which is the shape
// that makes the attack theft rather than self-harm.
func (r *Runner) reSigned(c *types.Certificate) *types.Certificate {
	k := r.signerFor(c)
	if k == nil {
		return nil
	}
	out, err := harness.ReSignCertificate(c, r.Params, k.Seed(), byte(1+r.advRng.Intn(250)))
	if err != nil {
		return nil
	}
	return out
}

// signerFor returns a key this runner controls that signed c, or nil.
func (r *Runner) signerFor(c *types.Certificate) *wallet.Key {
	for _, s := range c.Sigs {
		if s.PubKey == r.miner.PubKey() {
			return r.miner
		}
		for _, a := range r.actors {
			if a.key.PubKey() == s.PubKey {
				return a.key
			}
		}
	}
	return nil
}

// probeTTLHorizon drives one certificate onto B2's TTL horizon from both sides
// and requires the two folds to agree on which side it fell.
//
// THE HORIZON, DERIVED. B1 rejects a certificate whose TTL is below the block's
// height, so on arrival at B2 the distance d = c.TTL - h.Height is well defined
// and lies in [0, 2^64-1 - h.Height] -- B1, not the field width, is what bounds
// it from above. B2 accepts exactly d <= ttl_max. So the separating pair is d =
// ttl_max (the last accepted distance) against d = ttl_max + 1 (the first
// refused one), and it exists in the reachable range only while ttl_max <
// 2^64-1 - h.Height. At ttl_max = 2^64-1 -- a value params.Validate accepts,
// and the one the horizon fix was about -- no reachable distance exceeds the
// bound and B2 cannot fire at all; the arm that has to be checked there is the
// opposite one, that the largest expressible TTL is *accepted*, which is
// precisely what the earlier sum form got wrong.
//
// WHAT THE GENERATOR CAN AND CANNOT REACH. Runner.ttl() clamps its span to
// min(ttl_max, 8) and adds 1, so a DRAWN d lies in [1, min(ttl_max, 8)]. That
// caps at ttl_max, and no route increases d, so d = ttl_max + 1 -- the reject
// side, and the whole point of this probe -- is unreachable at EVERY parameter
// set. At 32 and 240 the reject side is not approached at all.
//
// The +1 does NOT make d = 0 unreachable, and an earlier version of this
// comment said it did. The +1 bounds the distance the generator DRAWS; B2 sees
// the distance at the height a certificate is finally PRESENTED, and genReplay
// re-presents an already-committed certificate at a later height, shifting d
// down by its age. Measured over every certificate in every block handed to
// Differential -- honest blocks, committed and rejected -- across the three
// regimes below and two seeds: d = 0 five times and d < 0 (refused by B1)
// 78 times, all 83 of them replays, against d > ttl_max zero times.
//
// The census that certified the old claim counted CERTIFICATES IN COMMITTED
// BLOCKS, and at that scope both figures are zero and cannot be anything else:
// a replay is exactly what makes a block un-committable (B3), so the committed
// scope structurally excludes the only route to d <= 0. A check that can only
// return "pass" is not a check, and the population a universal quantifies over
// has to be named alongside it.
//
// The accept side is the exception, and it is worth having: at ttl_max = 2 the
// span is 2, so the generator reaches d = ttl_max on its own (measured, 241
// times). There the honest corpus corroborates this probe's accept arm by an
// independent route instead of the probe standing alone.
//
// An earlier version of this comment said the clamp was 8 and that the horizon
// could not be reached "at any parameter set". That was true of a runner only
// ever driven at 32 and 240, and the ttl_max = 2 regime this suite added is
// what falsified it. Kept as a warning rather than quietly corrected: a claim
// quantified over a parameter has to be re-tested when that parameter's range
// widens, and "has ever" reads as settled history rather than a live assertion.
//
// This is the same shape as probeSeedEpoch and probeReSigned: a rule the honest
// corpus cannot express an input for is a rule the differential is blind to,
// however many seeds it runs.
//
// WHY EVERY ARM IS ONE CERTIFICATE IN AN OTHERWISE HONEST BLOCK. The probe
// block is the proposed block with its certificates replaced by exactly one,
// freshly keyed and unfunded, so it is DROPPED rather than applied.
//
// WHAT ISOLATES THE PROBE FROM THE RUN, precisely, because an earlier version
// of this comment credited the wrong mechanism and a comment that names the
// wrong guard is worse than one that names none:
//
//   - ISOLATION comes from the Clone() calls below, and from nothing else.
//     Every fold this function performs -- the control fold and all four arms
//     -- runs against clones of both states, unconditionally. Nothing the probe
//     builds can reach the live chain, whatever key it carries. Measured: give
//     the probe a real FUNDED actor's key, forcing exactly the collision the
//     old comment said could not happen, and the test still passes on every
//     seed (the collision branch fires on 26 of 33 invocations, so the mutant
//     applied). Conversely, keep the unfunded key and remove the clones, and
//     the accept arms fail at the first probe. Unfundedness is not what saves
//     this; the clones are.
//   - The UNFUNDED key buys something real but different: a DETERMINISTIC
//     outcome. Every arm is DROPPED for the same reason, so no arm can differ
//     from another by whether its deposit happened to cover.
//
// The practical consequence is a maintenance one. If the clones are ever
// removed as an optimisation, an unfunded key will not save this probe -- and
// refold.State.Clone must be kept complete: a field added to refold.State and
// not copied there would silently reconnect the probe to the live run.
//
// The key is drawn ONCE per invocation and every arm is built from it, so the
// arms differ from each other in the TTL field and in nothing else. That is not
// tidiness, it is the attributability argument: a per-arm key would give each
// arm a different address, deposit, program and certificate id, and then the
// accept arm would not vouch for the reject arm's certificate at all -- they
// would be different certificates. A reject arm refused for some key-dependent
// reason would be counted as a B2 rejection and nothing would notice, because
// rejection is what the probe expects there. That was true of the first version
// of this probe; four arms, four owners, measured.
//
// WHY BOTH SIDES. An accept-only probe agrees with a fold that deleted B2; a
// reject-only probe agrees with a fold whose B2 is off by one. Neither alone
// separates the rule, and this package has already learned once that a check
// which can only come back "pass" is not a check.
//
// WHY THE CONTROL FOLD IS NOT OPTIONAL, AND WHY IT IS STRUCTURAL. A two-sided
// oracle inherits every rule the block is subject to, not only the two it
// models. The want below states B1 and B2 and nothing else, so an arm that
// must be ACCEPTED is wrong the moment the honest block is refused for an
// unrelated reason -- and the honest block IS refused, routinely:
// TestDifferentialElasticCeiling deliberately generates citations that break
// C2, so an accept arm there could never be accepted and this probe reported a
// divergence that was not one. Both folds agreed throughout; the defect was in
// the oracle.
//
// The repair is to stop asserting the accept side absolutely and derive it. The
// UNMODIFIED block is folded against clones first, and the arms run only if it
// was accepted -- which positively excludes every non-certificate reason to
// reject, by measurement rather than by enumeration. Enumerating "and not C2"
// would be defeated by the next rule added; "the honest block was accepted"
// cannot be, because it quantifies over the rules instead of listing them.
//
// One-sided probes do not need this. probeSeedEpoch and probeReSigned only ever
// assert !accepted, and a foreign rejection makes those weaker rather than
// wrong. This is the first probe in this file to assert both directions.
//
// Like probeSeedEpoch this runs on a copy of the block, and unlike it, it runs
// against CLONES of both states -- because arms that must be *accepted* would
// otherwise advance the chain on a block the proposer never produced. Epoch
// boundaries are skipped separately from the control fold, and the control fold
// does not subsume that guard: an epoch-boundary header commits to a state root
// computed over the block's OWN certificates, so the honest block is accepted
// there and every arm is refused for a reason the control fold cannot see.
func (r *Runner) probeTTLHorizon(block *types.Block) error {
	if r.Params.IsEpochBoundary(block.Header.Height) {
		return nil
	}
	// One block in six. The probe folds up to four extra blocks, but each
	// carries a single certificate against the honest block's dozens, so it
	// is far cheaper per run than probeReSigned; six keeps every seed well
	// clear of the non-zero guards in differential_test.go.
	if r.hrng.Intn(6) != 0 {
		return nil
	}

	// The control fold. Every arm's expectation is conditioned on this, so a
	// block the honest run could not commit is a block this probe declines to
	// reason about. Nothing is lost: commit counts those in r.Rejected, and the
	// next accepted block gets probed instead.
	honest := *block
	honestOK, err := Differential(r.Chain.State.Clone(), r.Naive.Clone(), &honest, r.Params)
	if err != nil {
		return err
	}
	if !honestOK {
		r.HorizonDeclined++
		return nil
	}

	const maxTTL = ^uint64(0)
	h := block.Header.Height
	// d = 0 first: it is the distance at which the two folds' B2 are written
	// differently -- sim/refold carries an extra c.TTL > h.Height conjunct that
	// core/fold does not.
	//
	// It is COVERAGE of that spelling and cannot be a SEPARATOR of it, and the
	// reason is worth stating exactly, because the obvious reason is the wrong
	// one. It is NOT that params.Validate enforces ttl_max >= 2: on uint64,
	// 0 > ttl_max is false for every ttl_max including 0, so d = 0 separates
	// nothing at any parameter set, legal or not. The load-bearing premise is
	// that B1 runs AHEAD of B2 in both folds, which is what makes d well
	// defined and non-negative. sweep.go's WithoutRule("B1") falsifies exactly
	// that premise, and an underflowed d is the conjunct's real separator --
	// reachable only there. So the conjunct is load-bearing; what this probe
	// cannot be is the thing that shows it.
	// TestEveryInvalidVectorsRuleIsNecessary is.
	//
	// WHY THIS ARM EARNS ITS PLACE, since the above says what it is not. Under the
	// earlier wrapping sum h + ttl_max, at ttl_max = 2^64-1 the bound computes to
	// h - 1 and EVERY certificate B1 admits is refused -- including this one.
	// Restoring that form in BOTH folds is caught here and on this arm first,
	// which is a kill no differential could otherwise report, since a defect
	// present in both folds makes them agree.
	//
	// What this arm is NOT justified by: being the only route to d = 0. It is not.
	// genReplay reaches d = 0 in the honest corpus -- five times across the six
	// runs this suite drives -- and the committed-block census that reported zero
	// could not have reported anything else, because a replay is what makes a
	// block un-committable. See the doc comment above. Then the largest
	// expressible TTL, which is the wrap witness.
	ttls := []uint64{h, maxTTL}
	// The two boundary TTLs are remembered rather than recomputed in the loop,
	// so the counters below name the ARM and not a value that some other arm
	// might coincide with. They are only meaningful when the guard that appends
	// them fired, which is why each carries its own ok flag.
	atMax, atMaxOK := uint64(0), false
	pastMax, pastMaxOK := uint64(0), false
	if r.Params.TTLMax <= maxTTL-h {
		atMax, atMaxOK = h+r.Params.TTLMax, true
		ttls = append(ttls, atMax) // d = ttl_max, last accepted
	}
	if r.Params.TTLMax < maxTTL-h {
		pastMax, pastMaxOK = h+r.Params.TTLMax+1, true
		ttls = append(ttls, pastMax) // d = ttl_max+1, first refused
	}

	// One key for every arm; see the doc comment for why this is load-bearing
	// rather than economical.
	seed := make([]byte, 32)
	r.hrng.Read(seed)
	k, keyErr := wallet.KeyFromSeed(seed)
	if keyErr != nil {
		return fmt.Errorf("sim: could not derive a TTL-horizon probe key at height %d: %w",
			h, keyErr)
	}

	seen := make(map[uint64]bool, len(ttls))
	for _, ttl := range ttls {
		if seen[ttl] {
			// h+ttl_max can coincide with maxTTL at the extreme. Counting it
			// twice would inflate a census that exists to be believed.
			continue
		}
		seen[ttl] = true

		cert, certErr := r.horizonCert(k, ttl)
		if certErr != nil {
			// Loud rather than skipped: a probe that silently declines to
			// build its own input is a probe that reports "pass" for having
			// measured nothing.
			return fmt.Errorf("sim: could not build a TTL-horizon probe certificate "+
				"at height %d with ttl %d: %w", h, ttl, certErr)
		}

		probe := *block
		probe.Certs = []*types.Certificate{cert}
		probe.Header.CertRoot = probe.ComputeCertRoot(r.Params)

		// B1 and B2 stated directly, in the distance form, as the answer the
		// two folds are being held to. Written out rather than called, because
		// a probe that asks core/fold what core/fold thinks is not a check.
		//
		// Sound only because BOTH halves hold. The control fold accepted this
		// same block with a different certificate list, so every non-certificate
		// reason to reject has been measured absent; and every arm carries the
		// same key, so the rejected arm really is the accepted arm plus one
		// rather than a different certificate that happened to be refused.
		want := ttl >= h && ttl-h <= r.Params.TTLMax

		accepted, probeErr := Differential(r.Chain.State.Clone(), r.Naive.Clone(), &probe, r.Params)
		if probeErr != nil {
			return probeErr // the two folds disagree about B2's horizon
		}
		if accepted != want {
			return fmt.Errorf(
				"both folds %s a block at height %d carrying a certificate with ttl %d "+
					"(distance %d, ttl_max %d); B1 and B2 together say it should have been %s",
				verdict(accepted), h, ttl, ttl-h, r.Params.TTLMax, verdict(want))
		}
		if want {
			r.HorizonAccepted++
		} else {
			r.HorizonRejected++
		}
		if ttl == h {
			r.HorizonZeroDistance++
		}
		// Counted after the verdict check, so a counter can only record an arm
		// that was built, folded by BOTH implementations and agreed on. An arm
		// that diverged returns above and increments nothing.
		if atMaxOK && ttl == atMax {
			r.HorizonAcceptedAtMax++
		}
		if pastMaxOK && ttl == pastMax {
			r.HorizonRejectedPastMax++
		}
	}
	return nil
}

func verdict(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "rejected"
}

// horizonCert builds one certificate at an exact TTL under a caller-supplied
// key, so that every arm of one probe shares a key and differs only in TTL.
//
// The key is the caller's precisely because it must NOT vary between arms: see
// probeTTLHorizon. Everything else here is constant too -- bid() takes no draw,
// the sequence is 0, the program and deposit are derived from the one address.
//
// It does not go through Runner.build: that draws a TTL from Runner.ttl(),
// which is the clamp this probe exists to get past, and it feeds the
// OneShotFunded census, which is a census of generated traffic rather than of
// probes.
//
// The key is fresh and therefore unfunded, so the certificate is DROPPED. That
// is deliberate, but for one reason rather than two: it makes every arm's
// outcome the SAME outcome, so no arm differs from another by whether its
// deposit covered. B2 is a block rule and runs before any outcome is decided,
// so the horizon is reached either way.
//
// It is NOT what keeps the probe from colliding with the run's own actors,
// sequences or balances -- the clones in probeTTLHorizon are, unconditionally.
// See the note there; this distinction was measured, not assumed.
func (r *Runner) horizonCert(k *wallet.Key, ttl uint64) (*types.Certificate, error) {
	addr := k.Persistent()
	b := &wallet.Builder{
		Params:  r.Params,
		Program: wallet.Tip(types.NativeAsset, addr, r.payout, u256.FromUint64(1_000)),
		Seq:     0,
		TTL:     ttl,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  r.bid(),
		Signers: []*wallet.Key{k},
	}
	return b.Build()
}

// commit proposes a block, runs it through both implementations, and advances
// the tip only if both accepted it.
func (r *Runner) commit(certs []*types.Certificate) error {
	block, err := r.Chain.ProposeWithCites(r.payout, r.cites(), certs...)
	if err != nil {
		// Sealing an epoch-boundary block dry-runs the fold, so a block the
		// rules reject cannot be proposed at all. An honest miner would have
		// filtered the offending certificates; drop the traffic and move on.
		r.Rejected++
		return nil
	}

	// The seed-epoch probe, run BEFORE the honest block and on a copy, so it
	// costs the run nothing: the chain still advances on exactly the block
	// ProposeWithCites produced, and the traffic generator's random stream is
	// untouched because this draws from its own.
	//
	// Both properties are load-bearing and both were learned the hard way. A
	// first version corrupted the real block and drew from r.rng; it shifted
	// every subsequent draw, and two seeds stopped reaching scenarios their
	// own coverage guards require — the instrument broke the run it was
	// measuring.
	if err := r.probeSeedEpoch(block); err != nil {
		return err
	}
	if err := r.probeReSigned(block); err != nil {
		return err
	}
	if err := r.probeTTLHorizon(block); err != nil {
		return err
	}

	// Read before Differential, which applies the block to both states. T and
	// the citation count are consensus state the block itself moves, so a
	// reading taken afterwards is the wrong side of the transition — an
	// earlier version of this took both afterwards and reported that T never
	// moved in any seed, which is what a same-value comparison against itself
	// always reports.
	before, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
	citedBefore, _ := r.Chain.State.Get(types.CitedCountSlot()).Uint64()

	// Whether this block breaks B6, derived from the parameter rather than read
	// off either fold's verdict -- a census that asked a fold whether the fold
	// rejected would be the fold vouching for itself.
	var parGasProposed uint64
	for _, c := range block.Certs {
		parGasProposed += c.ParGas(r.Params)
	}
	if parGasProposed > r.Params.ParGasLimit(before) {
		r.ParGasOverCeiling++
	}

	// Every address this block would burn while also naming a non-native cell
	// under it — F8b's second clause and nothing else. Collected before the
	// fold runs and counted after, so what the census reports is a burn that
	// actually landed rather than one a certificate merely proposed.
	namedAssetBurns := namedAssetBurnCandidates(block, r.Chain.State)

	accepted, err := Differential(r.Chain.State, r.Naive, block, r.Params)
	if err != nil {
		return err
	}
	if !accepted {
		r.Rejected++
		return nil
	}

	for _, a := range namedAssetBurns {
		if r.Chain.State.IsSpent(a) {
			r.NamedAssetBurns++
		}
	}

	// What the accepted block exercised, so a run can show it reached the code
	// rather than merely finishing.
	var seqGas uint64
	for _, c := range block.Certs {
		seqGas += c.SeqGas(r.Params)
	}
	if seqGas > r.Params.SeqGasLimit(before) {
		r.Burst++
	}
	if len(block.Cites) > 0 {
		r.Cited++
	}
	if r.Params.IsEpochBoundary(block.Header.Height) && block.Header.Height > 0 {
		after, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
		// Whether the gate passed is computable from the count this boundary
		// read, which is the epoch's own total: F2b evaluates it and then
		// zeroes it, so citedBefore is exactly what the gate saw.
		healthy := citedBefore*10000 <= r.Params.HealthGateBps*r.Params.EpochLength
		switch {
		case after > before:
			r.Grew++
		case after < before:
			r.Decayed++
		}
		if !healthy {
			r.GateWithheld++
		}
	}

	r.Chain.Headers = append(r.Chain.Headers, block.Header)
	r.Chain.Undos = append(r.Chain.Undos, nil)
	r.history = append(r.history, certs...)
	if len(r.history) > 64 {
		r.history = r.history[len(r.history)-64:]
	}
	return nil
}

// cites builds the block's cited-competing-header list (whitepaper §8.1).
//
// Most blocks cite nothing, which is the honest common case. The rest cite a
// namedAssetBurnCandidates lists the addresses a block's certificates mark
// spent while also writing a non-native cell under the same address.
//
// That pair is the exact precondition of F8b's second clause — "every cell
// under a burned address that this certificate itself names" — and the
// generator reached it in no run at all until genAssetVault existed. The census
// exists so that a change which quietly stops producing the shape fails loudly,
// the way the one-shot census taught: with the shape absent, deleting the
// clause from sim/refold alone left the entire sim suite green.
func namedAssetBurnCandidates(b *types.Block, s *state.State) []types.Address {
	var out []types.Address
	for _, c := range b.Certs {
		for _, w := range c.Writes {
			if w.Op != types.OpMarkSpent || s.IsSpent(w.Slot.Addr) {
				// Already spent before this block, so the address being spent
				// afterwards proves nothing about this certificate: stageWrites
				// makes such a certificate SkippedStale, and counting it would
				// let the census be satisfied by a burn that never happened.
				continue
			}
			for _, x := range c.Writes {
				if x.Slot.Addr == w.Slot.Addr && x.Op != types.OpMarkSpent &&
					!types.IsNativeBalanceSlot(x.Slot) {
					out = append(out, w.Slot.Addr)
					break
				}
			}
		}
	}
	return out
}

// genuine sibling of the tip — and one time in three, a deliberately broken
// one, because the differential's job is to check that both implementations
// *reject* identically as much as that they accept identically. All six of
// checkCites' rules get a turn, rule 3 included — which needs the block's own
// parent rather than a sibling, so it cannot come from Sibling().
//
// Without this the citation path is unreachable by the fuzzer: a harness that
// never cites produces an empty list in both implementations, which agree
// trivially. That is the shape of blindness that let the burn omission
// through (I6-H1), so the generator has to be able to reach the code.
func (r *Runner) cites() []*types.Header {
	if r.rng.Intn(3) != 0 {
		return nil
	}
	sib := r.Chain.Sibling(r.newKey().Persistent())
	if sib == nil {
		return nil
	}
	if !r.Dense {
		// The default run cites, but never faultily. Its own assertions
		// measure how far the chain got under adversarial *certificate*
		// traffic, and a one-in-three invalid citation rejects the whole
		// block regardless of its certificates — which drowns exactly the
		// signal that run exists to produce. Citation faults belong to the
		// run built for them, below.
		return []*types.Header{sib}
	}
	switch r.rng.Intn(7) {
	case 6: // rule 3: the block's own parent is not a competitor
		tip := r.Chain.Tip()
		return []*types.Header{&tip}
	case 0: // rule 1: wrong height
		sib.Height++
	case 1: // rule 2: does not share the grandparent
		sib.ParentID[0] ^= 0xff
	case 2: // rule 4: a target this height was never mined under
		sib.Target = sib.Target.SatAdd(u256.One)
	case 3: // rule 5: the same header twice is not strictly increasing
		return []*types.Header{sib, sib}
	case 4: // rule 0: a version that could never have been a block
		sib.Version = types.HeaderVersion + 1
	}
	// case 5 leaves it valid.
	return []*types.Header{sib}
}

func (r *Runner) bid() types.FeeBid {
	// A generous maximum and a modest priority: the maximum is free headroom,
	// the priority is what the miner is actually paid.
	return wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000),
		u256.FromUint64(500), u256.FromUint64(10))
}

// ttl draws a TTL for generated traffic: d in [1, min(ttl_max, 8)] ahead of the
// next block. See probeTTLHorizon for which parts of B2's horizon that reaches.
//
// Intn panics on a non-positive argument, so this depends on ttl_max >= 1 --
// params.Validate enforces >= 2. That is a dependency of the traffic generator
// on a consensus-validation rule, and it is stated because it is invisible: a
// caller driving the Runner with an unvalidated params struct gets a panic here
// rather than misbehaviour. Every arm of the horizon suite asserts Validate()
// for this reason among others.
func (r *Runner) ttl() uint64 {
	span := r.Params.TTLMax
	if span > 8 {
		span = 8
	}
	return r.Chain.NextHeight() + uint64(r.rng.Intn(int(span))) + 1
}

// generate fills the pending set with a mix of the traffic a real chain sees:
// funding, tips, self-conflicts, unfunded spam, issues, mints and retires.
func (r *Runner) generate() {
	// Fund a new actor now and then, so the population grows.
	if len(r.actors) < 12 && r.rng.Intn(2) == 0 {
		r.addActor()
	}

	if r.Dense {
		// Traffic that applies, and only that. The adversarial certificate
		// mix below is kept out on purpose: it is what makes the default run
		// valuable and what makes the median zero, and this run needs the
		// median non-zero. Rejection coverage does not disappear — the
		// citation generator stays adversarial, so both implementations still
		// have to refuse the same blocks for the same reasons.
		for i := 0; i < 1+r.rng.Intn(5); i++ {
			r.genTip()
		}
		// One conflicting certificate now and then, so INCLUDED gas exceeds
		// APPLIED gas in some blocks. The burst valve is assessed on included
		// ("applied and skipped alike, so the excess cannot be stuffed with
		// manufactured conflict at a discount") while the epoch controller is
		// fed by applied. If every block in this run had the two equal, a fold
		// that swapped one for the other would pass unnoticed — the run would
		// be dense and blind at the same time.
		if r.rng.Intn(3) == 0 {
			r.genSelfConflict()
		}
		return
	}

	// Asset-vault traffic, on its own stream (see Runner.vrng). Stocking is
	// tried more often than spending because a vault must exist before it can
	// be burned, and stocking fails whenever its actor has no asset yet.
	r.genAssetVault()
	r.genAssetPartialSpend()
	r.genMovelessOneShot()

	n := r.rng.Intn(5)
	for i := 0; i < n; i++ {
		switch r.rng.Intn(10) {
		case 0, 1, 2, 3:
			r.genTip()
		case 4:
			r.genSelfConflict()
		case 5:
			r.genUnfunded()
		case 6:
			r.genIssue()
		case 7:
			r.genMint()
		case 8:
			r.genRetire()
		default:
			r.genReplay()
		}
	}
}

func (r *Runner) addActor() {
	k := r.newKey()
	version := byte(0x02)
	if r.rng.Intn(4) == 0 {
		version = 0x01
	}
	a := &actor{key: k, addr: k.Address(version)}
	r.actors = append(r.actors, a)

	amount := u256.FromUint64(uint64(1+r.rng.Intn(50)) * 1_000_000_000)
	cert := r.build(r.miner, r.payout, wallet.Tip(types.NativeAsset, r.payout, a.addr, amount), r.nextMinerSeq())
	if cert != nil {
		r.pending = append(r.pending, cert)
		a.funded = true
	}
}

func (r *Runner) nextMinerSeq() uint64 {
	r.minerSeq++
	return r.minerSeq
}

// build assembles a certificate, returning nil when the program is one
// derivation rejects. A generator that only produced buildable programs would
// never exercise the wallet's own guard rails.
func (r *Runner) build(k *wallet.Key, depositAddr types.Address, prog types.Program, seq uint64) *types.Certificate {
	refund := depositAddr
	if depositAddr[0] == crypto.AddrVersionOneShot {
		refund = r.miner.Persistent()
	}
	b := &wallet.Builder{
		Params:  r.Params,
		Program: prog,
		Seq:     seq,
		TTL:     r.ttl(),
		Deposit: wallet.SelfDeposit(depositAddr, refund),
		FeeBid:  r.bid(),
		Signers: []*wallet.Key{k},
	}
	cert, err := b.Build()
	if err != nil {
		return nil
	}
	if isNewlyLegalOneShotDeposit(prog, depositAddr, r.Params.ChainID, seq) {
		r.OneShotFunded++
	}
	return cert
}

// isNewlyLegalOneShotDeposit reports whether a certificate belongs to the class
// F-VAL-5 legalized: a one-shot deposit cell whose burn the *program* does not
// already derive.
//
// The distinction matters for the census. A RETIRE of the very address funding
// it, and a TRANSFER sweeping the address it pays from, were always buildable
// — derivation produced the MARK_SPENT for its own reasons — so counting those
// would report coverage the fix did not create.
func isNewlyLegalOneShotDeposit(prog types.Program, depositAddr types.Address, chainID, seq uint64) bool {
	if depositAddr[0] != crypto.AddrVersionOneShot {
		return false
	}
	_, writes, err := validity.Derive(prog, chainID, seq)
	if err != nil {
		return false
	}
	for _, w := range writes {
		if w.Op == types.OpMarkSpent && w.Slot.Addr == depositAddr {
			return false
		}
	}
	return true
}

func (r *Runner) pick() *actor { return r.pickFrom(r.rng) }

// pickFrom chooses uniformly from the actor population using the caller's own
// stream. The vault pipeline passes vrng so that its payee choice is not a
// draw of the traffic generator's stream; see Runner.vrng.
func (r *Runner) pickFrom(g *rand.Rand) *actor {
	if len(r.actors) == 0 {
		return nil
	}
	return r.actors[g.Intn(len(r.actors))]
}

func (r *Runner) genTip() {
	from, to := r.pick(), r.pick()
	if from == nil || to == nil || from == to || !from.funded {
		return
	}
	amount := u256.FromUint64(uint64(1+r.rng.Intn(20)) * 1_000_000)
	from.seq++
	if cert := r.build(from.key, from.addr,
		wallet.Tip(types.NativeAsset, from.addr, to.addr, amount), from.seq); cert != nil {
		r.pending = append(r.pending, cert)
	}
}

// genSelfConflict signs two spends of nearly the whole balance. The second is
// billed a skip; the first applies. Every billed skip in Era 0 must be
// self-inflicted, and this is what self-inflicted looks like.
func (r *Runner) genSelfConflict() {
	from, to := r.pick(), r.pick()
	if from == nil || to == nil || from == to || !from.funded {
		return
	}
	amount := u256.FromUint64(uint64(20+r.rng.Intn(30)) * 1_000_000_000)
	for i := 0; i < 2; i++ {
		from.seq++
		if cert := r.build(from.key, from.addr,
			wallet.Tip(types.NativeAsset, from.addr, to.addr, amount), from.seq); cert != nil {
			r.pending = append(r.pending, cert)
		}
	}
}

// genUnfunded produces a certificate that will be DROPPED: valid bytes, no
// deposit behind them.
func (r *Runner) genUnfunded() {
	k := r.newKey()
	to := r.pick()
	if to == nil {
		return
	}
	if cert := r.build(k, k.Persistent(),
		wallet.Tip(types.NativeAsset, k.Persistent(), to.addr, u256.FromUint64(1_000)), 0); cert != nil {
		r.pending = append(r.pending, cert)
	}
}

func (r *Runner) genIssue() {
	a := r.pick()
	if a == nil || !a.funded || a.asset != (types.Address{}) {
		return
	}
	a.seq++
	capValue := u256.FromUint64(uint64(1000 + r.rng.Intn(100000)))
	var symbol types.Hash
	r.rng.Read(symbol[:])
	cert := r.build(a.key, a.addr,
		wallet.Issue(a.addr, capValue, byte(r.rng.Intn(19)), symbol, a.key.PubKey()), a.seq)
	if cert != nil {
		r.pending = append(r.pending, cert)
		a.asset = types.DeriveAssetAddress(r.Params.ChainID, a.addr, a.seq)
		a.assetCap = capValue
	}
}

func (r *Runner) genMint() {
	a, to := r.pick(), r.pick()
	if a == nil || to == nil || !a.funded || a.asset == (types.Address{}) {
		return
	}
	a.seq++
	// Sometimes mint more than the cap allows in total, to exercise the
	// guarded-delta boundary from both sides.
	amount := u256.FromUint64(uint64(1 + r.rng.Intn(2000)))
	if amount.Gt(a.assetCap) {
		amount = a.assetCap
	}
	cert := r.build(a.key, a.addr,
		wallet.Mint(a.asset, to.addr, amount, a.assetCap, a.key.PubKey()), a.seq)
	if cert != nil {
		r.pending = append(r.pending, cert)
	}
}

// The asset-vault pipeline: the only traffic in this generator that reaches
// F8b's second clause — "every cell under a burned address that this
// certificate itself names".
//
// The clause needs a burn whose write set contains a *non-native* balance
// slot. genTip moves the native coin, so before this existed the only cell
// F8b ever had to move was the native balance cell, and the differential — the
// strongest cross-implementation instrument the project has — was blind to
// half of a new consensus rule: deleting the asset clause from sim/refold
// alone left the entire sim suite green.
//
// It is driven by a dedicated factory key rather than by the random actor
// population, and that is not tidiness. Three successive attempts to build it
// out of ordinary actors were measured and all three starved:
//
//   - issuer-funded vaults — the issuer's own cell is drained by genTip and
//     genSelfConflict within a few blocks, so the funding tip skipped against
//     its own guard 606 times out of 615 on seed 1;
//   - miner-funded vaults with an issuer-underwritten mint in the same block —
//     the mint was dropped for want of a deposit, leaving the vault holding
//     drops and no asset;
//   - a staged version of the same — still zero on four of eight seeds,
//     because whether any actor had issued an asset at all was itself random.
//
// A factory removes every one of those dependencies: one always-solvent cell,
// one asset, a cap large enough that no mint ever loses a cap race, and a
// stage machine that advances only on *committed* state, so each step can rely
// on the previous one having landed.
const (
	vaultNeedsAsset = iota
	vaultNeedsDrops
	vaultSpendable
)

func (r *Runner) genAssetVault() {
	// Every stage re-issues its own precondition rather than advancing on a
	// build. A certificate that builds is not a certificate that applied — the
	// miner's payout is empty until the first coinbase matures, so the first
	// funding tip skipped and a stage machine that advanced on the build sat
	// at "needs asset" for the whole run, in every seed.
	factory := r.factory.Persistent()
	switch r.vaultStage {
	case vaultNeedsAsset:
		if r.Chain.State.Get(types.NativeBalanceSlot(factory)).IsZero() {
			// Sized like addActor's funding, not larger. The payout holds one
			// matured coinbase at a time, so a tip for more than it holds
			// builds cleanly and then skips against its own guard forever —
			// which is exactly how a 500 ZCR request left this stage stuck at
			// zero in every seed.
			r.fundFromMiner(factory, 30_000_000_000)
			return
		}
		if r.factoryAsset != (types.Address{}) &&
			!r.Chain.State.Get(types.AssetCapSlot(r.factoryAsset)).IsZero() {
			r.vaultKey = r.newVaultKey(r.vrng)
			r.vaultStage = vaultNeedsDrops
			return
		}
		// One ISSUE in flight at a time. Re-issuing every step derives a new
		// asset address from a new seq, so the address this pipeline is
		// waiting on changed faster than a block could confirm it and the
		// stage never advanced in any seed. The countdown is the certificate's
		// own window: if it has not landed by then it never will.
		if r.issueWait > 0 {
			r.issueWait--
			return
		}
		r.factorySeq++
		// A cap no run can exhaust, so a vault mint never loses a cap race.
		// The cap boundary is genMint's job and is tested there; here it would
		// only be a source of silent starvation.
		var symbol types.Hash
		symbol[0] = 'V'
		capValue := u256.FromUint64(1 << 60)
		if cert := r.build(r.factory, factory,
			wallet.Issue(factory, capValue, 0, symbol, r.factory.PubKey()),
			r.factorySeq); cert != nil {
			r.pending = append(r.pending, cert)
			r.factoryAsset = types.DeriveAssetAddress(r.Params.ChainID, factory, r.factorySeq)
			r.factoryCap = capValue
			r.issueWait = 8
		}

	case vaultNeedsDrops:
		vault := r.vaultKey.OneShot()
		if r.Chain.State.Get(types.NativeBalanceSlot(vault)).IsZero() {
			r.fundFromMiner(vault, uint64(5+r.vrng.Intn(20))*1_000_000_000)
			return
		}
		if r.Chain.State.Get(types.BalanceSlot(vault, r.factoryAsset)).Gt(u256.One) {
			r.vaultStage = vaultSpendable
			return
		}
		r.factorySeq++
		// At least two units, so that moving one always leaves a remainder for
		// F8b to carry. A sweep of the whole balance would leave nothing to
		// compare, which is the opposite of what this pipeline is for.
		amount := u256.FromUint64(uint64(2 + r.vrng.Intn(500)))
		if cert := r.build(r.factory, factory,
			wallet.Mint(r.factoryAsset, vault, amount, r.factoryCap, r.factory.PubKey()),
			r.factorySeq); cert != nil {
			r.pending = append(r.pending, cert)
		}
	}
}

// genMovelessOneShot deliberately produces the class F-VAL-5 legalised: a
// certificate whose deposit cell is a one-shot address and whose *program*
// moves no value, so the burn comes from withDepositMarkSpent alone.
//
// That class is what Runner.OneShotFunded counts, and the census asserting it
// non-zero exists because the class was legal and had zero randomised coverage
// at all. Until this function existed the class was produced only by luck — an
// actor's address had to be one-shot (one time in four) *and* had to be the one
// genIssue, genMint or genRetire happened to pick — and the count ranged from 1
// to 10 across seeds on main. Adding the asset-vault pipeline shifted the
// chain's trajectory, as any added traffic must, and seed 5 fell from 8 to 1
// and then to 0: a coverage guard one unlucky draw from silence, defended by
// nothing but the seeds happening to be kind.
//
// Producing the shape on purpose is the fix. It runs on vrng like the rest of
// the pipeline, it costs two certificates per cycle, and it makes the census a
// statement about the generator rather than about eight lucky trajectories.
func (r *Runner) genMovelessOneShot() {
	if r.movelessKey == nil {
		r.movelessKey = r.newVaultKey(r.vrng)
		r.fundFromMiner(r.movelessKey.OneShot(), 20_000_000_000)
		return
	}
	addr := r.movelessKey.OneShot()
	if r.Chain.State.IsSpent(addr) {
		r.movelessKey = nil
		return
	}
	if r.Chain.State.Get(types.NativeBalanceSlot(addr)).IsZero() {
		// Re-send rather than wait. A tip that skipped — the payout holds one
		// matured coinbase at a time — would otherwise park this machine on a
		// cell that never gets funded, which is how the count stayed in the
		// low single digits on half the seeds.
		r.fundFromMiner(addr, 20_000_000_000)
		return
	}
	// ISSUE rather than RETIRE: a RETIRE of the deposit address derives its own
	// MARK_SPENT, which is the case isNewlyLegalOneShotDeposit excludes, and a
	// RETIRE of anything else needs that address's signature.
	r.movelessSym++
	var symbol types.Hash
	symbol[0] = 'M'
	symbol[1] = byte(r.movelessSym)
	symbol[2] = byte(r.movelessSym >> 8)
	if cert := r.build(r.movelessKey, addr,
		wallet.Issue(addr, u256.FromUint64(1_000_000), 0, symbol, r.movelessKey.PubKey()),
		0); cert != nil {
		r.pending = append(r.pending, cert)
		r.movelessKey = nil
	}
}

// fundFromMiner sends drops from the always-solvent payout cell. The vault
// pipeline uses it for both of its cells because an actor's own cell is
// drained by genTip and genSelfConflict within a few blocks — measured, that
// starved the pipeline in 606 of 615 attempts on seed 1.
func (r *Runner) fundFromMiner(to types.Address, drops uint64) {
	if cert := r.build(r.miner, r.payout,
		wallet.Tip(types.NativeAsset, r.payout, to, u256.FromUint64(drops)),
		r.nextMinerSeq()); cert != nil {
		r.pending = append(r.pending, cert)
	}
}

// genAssetPartialSpend moves *one unit* of the vault's asset out of it, which
// burns the vault and leaves both a drops remainder and an asset remainder for
// F8b to carry — one certificate exercising both of its clauses.
//
// One unit rather than a computed amount: it is the largest amount guaranteed
// to leave a remainder behind whenever the transfer applies at all, and the
// remainder is the whole point.
func (r *Runner) genAssetPartialSpend() {
	if r.vaultStage != vaultSpendable {
		return
	}
	to := r.pickFrom(r.vrng)
	vault := r.vaultKey.OneShot()
	if to == nil || r.Chain.State.IsSpent(vault) ||
		r.Chain.State.Get(types.NativeBalanceSlot(vault)).IsZero() ||
		!r.Chain.State.Get(types.BalanceSlot(vault, r.factoryAsset)).Gt(u256.One) {
		return
	}
	if cert := r.build(r.vaultKey, vault,
		wallet.Tip(r.factoryAsset, vault, to.addr, u256.One), 0); cert != nil {
		r.pending = append(r.pending, cert)
		// A fresh vault, so the shape recurs through the run rather than
		// happening once.
		r.vaultKey = r.newVaultKey(r.vrng)
		r.vaultStage = vaultNeedsDrops
	}
}

func (r *Runner) genRetire() {
	a := r.pick()
	if a == nil || !a.funded {
		return
	}
	a.seq++
	spare := r.newKey().OneShot()
	if cert := r.build(a.key, a.addr, wallet.Retire(spare), a.seq); cert != nil {
		// The spare address belongs to a different key, so the certificate
		// cannot be authorised: build returns nil and the traffic is skipped.
		r.pending = append(r.pending, cert)
	}
	if cert := r.build(a.key, a.addr, wallet.Retire(a.key.OneShot()), a.seq); cert != nil {
		r.pending = append(r.pending, cert)
	}
}

// genReplay deliberately re-includes an already committed certificate. Both
// implementations must reject the block, and reject it for the same reason.
func (r *Runner) genReplay() {
	if len(r.history) == 0 {
		return
	}
	committed := r.history[r.rng.Intn(len(r.history))]
	// Half the time, replay a *different encoding* of the committed authorization
	// rather than the same bytes. B3 reads the seen set by certificate id, so a
	// replay of identical bytes exercises it only for an id that covers those
	// bytes — the case that was already closed. This is the cross-block half of
	// the double-payment finding, and both implementations must refuse it for the
	// same reason.
	//
	// The draw is from advRng and not from rng, for the reason probeSeedEpoch
	// records: an adversarial addition that draws from the traffic generator's
	// own stream shifts every later draw and moves what a seed exercises.
	// Measured on the first attempt here — two seeds lost their one-shot
	// deposit coverage entirely.
	if r.advRng.Intn(2) == 0 {
		if variant := r.reSigned(committed); variant != nil {
			r.pending = append(r.pending, variant)
			return
		}
	}
	r.pending = append(r.pending, committed)
}
