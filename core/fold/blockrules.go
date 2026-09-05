package fold

import (
	"errors"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/validity"
)

// CheckBlockRules runs every block-validity rule the fold owns, before the
// fold mutates anything.
//
// B1 through B4 are the enforcement half of the billing law:
//
//	one signature, at most one bill, never at a position its signer could not
//	avoid.
//
// A signer accepts staleness risk by signing — a STALE or OVERFLOW skip is
// billable, and that is the risk it took. It never accepts miner-manufactured
// expiry, duplication, or fee-market drift, so a block that would impose any of
// those is not a block at all. Without these rules a block producer could
// withhold a certificate past its TTL and burn the deposit, or re-include an
// applied certificate in every block of the TTL window and bill the same
// signature dozens of times (R1-C1).
func CheckBlockRules(s *state.State, b *types.Block, p *params.Params) error {
	return checkBlockRules(s, b, p, carry(b.Certs))
}

// checkBlockRules is CheckBlockRules with the block's certificate ids already
// computed. The fold computes them once and hands the same slice to every stage
// that needs one; see carry.
func checkBlockRules(s *state.State, b *types.Block, p *params.Params, cc []carried) error {
	h := &b.Header

	if h.Version != types.HeaderVersion {
		return invalid("B7", "unknown header version %d", h.Version)
	}

	// T is whitepaper §8.1's sequential target: consensus state from block 1
	// on, and its own genesis value at block 0 — the same special case
	// seqBaseFee/parBaseFee already need, because state has nothing to read
	// until the fold has written it once. Every ceiling below is derived from
	// it; none is a constant any more.
	t := currentSeqGasTarget(s, p, h.Height)
	certCeiling := p.MaxCertsPerBlock(t)
	byteCeiling := p.BlockByteLimit(t)
	seqBurst := p.SeqGasBurst(t)   // 4T: the hard ceiling. 2T is a soft threshold
	parCeiling := p.ParGasLimit(t) // enforced by F11's forfeiture, not here.

	if len(b.Certs) > certCeiling {
		return invalid("B12", "%d certificates exceeds the ceiling of %d", len(b.Certs), certCeiling)
	}
	// B18 — the block's certificates may declare at most MaxSigsPerBlock(T)
	// signatures between them.
	//
	// **Its position in this function is the rule.** Everything it bounds is
	// spent below, inside the per-certificate loop, where B0 runs
	// validity.Check and pays for one strict Ed25519 verification per
	// signature. A ceiling evaluated after that work would bound the number a
	// block may *report* having cost, not the cost — so this sits above the
	// loop, above the roots, and needs nothing but the certificate headers to
	// answer. Counting is a linear pass over lengths; it verifies nothing.
	//
	// It exists because gas_par_per_sig cannot both bound verification and
	// price the parallel market, and the audit's recommended recalibration was
	// measured against the rest of the parameter system and rejected: see
	// spec/params.json's note on max_sigs_per_block_genesis for the two
	// consumers, the arithmetic, and where 6000 comes from. The short form is
	// that this ceiling caps a fully signature-stuffed block at ~4.4
	// core-seconds of verification per 30-second interval, against ~7.7
	// without it, and that the cap no longer grows when the byte ceilings do.
	//
	// The sum cannot overflow: V1 bounds each certificate at max_sigs, B12
	// above has already bounded the count, and the product of two int-sized
	// ceilings is far inside uint64. It is accumulated in uint64 rather than
	// int for the same reason MaxSigsPerBlock returns one — the ceiling has no
	// structural clamp, so the comparison has to hold at every value the
	// scaling can produce.
	var sigs uint64
	for _, c := range b.Certs {
		sigs += uint64(len(c.Sigs))
	}
	if sigCeiling := p.MaxSigsPerBlock(t); sigs > sigCeiling {
		return invalid("B18", "%d signatures exceeds the ceiling of %d", sigs, sigCeiling)
	}
	if size := b.SizeBytes(); size > byteCeiling {
		return invalid("B13", "block of %d bytes exceeds the ceiling of %d", size, byteCeiling)
	}
	// The count check must run before ComputeCitesRoot, exactly as the
	// certificate count check above runs before ComputeCertRoot: both
	// eventually reach ssz.Merkleize, which panics rather than errors on a
	// list longer than its capacity, because inside the consensus zone an
	// oversized list is a caller's bug rather than an input to be reported
	// (core/ssz's own doc comment). types.UnmarshalBlock already enforces
	// this bound at decode time, so a real network block can never carry
	// more, but this function is also called against blocks a node built
	// itself (the miner's dry run), which do not pass through that decoder.
	if len(b.Cites) > p.MaxCitesPerBlock {
		return invalid("B15", "%d citations exceeds the ceiling of %d", len(b.Cites), p.MaxCitesPerBlock)
	}
	if root := b.ComputeCertRoot(p); root != h.CertRoot {
		return invalid("B14", "certificate root does not commit to the bodies")
	}
	if root := b.ComputeCitesRoot(p); root != h.CitesRoot {
		return invalid("B16", "cites root does not commit to the cited headers")
	}
	if err := checkCites(s, b, p); err != nil {
		return err
	}

	if err := checkGenesisShape(b, p); err != nil {
		return err
	}
	if err := checkEmissionAddr(b); err != nil {
		return err
	}
	if err := checkSeedEpoch(b, p); err != nil {
		return err
	}
	if !p.IsEpochBoundary(h.Height) && h.StateRoot != (types.Hash{}) {
		return invalid("B9", "state root is set on a non-epoch-boundary block")
	}

	seqBaseFee := s.Get(types.SeqBaseFeeSlot())
	parBaseFee := s.Get(types.ParBaseFeeSlot())
	if h.Height == 0 {
		seqBaseFee = p.InitialSeqBaseFee
		parBaseFee = p.InitialParBaseFee
	}

	var seqGas, parGas uint64
	inBlock := make(map[types.Hash]struct{}, len(b.Certs))

	for i, cy := range cc {
		c := cy.cert
		// B0 — every certificate is stateless-valid. In production this runs as
		// a parallel batch before the sequential pass; the fold repeats it here
		// because a fold that trusts its caller is a fold with an attack
		// surface.
		//
		// The rule reported is the V-rule that failed, not "B0". B0 is a
		// quantifier — "V1..V9 pass for all certs" — and naming it would tell
		// a replaying implementation only that some certificate was rejected,
		// which is what the verdict already said. validity.RuleError has
		// carried the V-rule since core/validity was written, promising in its
		// own doc comment that golden vectors record the rule and not the
		// message; this is the line that finally keeps the promise.
		if err := validity.Check(c, p); err != nil {
			rule := validity.Rule(err)
			if rule == "" {
				// Unreachable while every return in core/validity goes through
				// fail/failf. Reported as B0 rather than as an unnamed rejection
				// so that a future rule added without a name is still a *named*
				// failure a vector can pin, instead of one spec/gen refuses to
				// commit for a reason that reads like a corpus bug.
				rule = "B0"
			}
			// The inner message, not err.Error(): RuleError.Error() already
			// begins with the rule id and invalid() prefixes it again, so the
			// full error would name V5 twice.
			msg := err
			if inner := errors.Unwrap(err); inner != nil {
				msg = inner
			}
			return invalidCert(i, rule, "certificate %d: %s", i, msg)
		}

		id := cy.id
		if _, dup := inBlock[id]; dup {
			return invalidCert(i, "B8", "certificate %d appears twice in the block", i)
		}
		inBlock[id] = struct{}{}

		// B1 — expired certificates are unincludable. Stateless, so a proposer
		// cannot claim not to have known.
		if h.Height > c.TTL {
			return invalidCert(i, "B1", "certificate %d expired at height %d, block is at %d", i, c.TTL, h.Height)
		}
		// B2 — and a TTL cannot reach so far ahead that its seen-set entry
		// becomes immortal state (R1-H4).
		//
		// Written as the distance, not as the sum: h.Height+p.TTLMax wraps, and a
		// wrapped ceiling is not a ceiling. At ttl_max = 2^64-1 -- a value
		// params.Validate accepts, and the most permissive horizon expressible --
		// the sum is 0 at height 1, so every certificate B1 admitted was refused
		// here and the chain accepted no certificate at all. No bound on
		// ttl_max can repair the sum: h.Height is unbounded chain state, so for
		// any ttl_max above zero there is a height at which it wraps. The
		// subtraction is total instead -- B1 directly above has already
		// established c.TTL >= h.Height -- and it is the form this rule's own
		// error message already reports.
		if c.TTL-h.Height > p.TTLMax {
			return invalidCert(i, "B2", "certificate %d has a TTL %d blocks ahead, limit is %d",
				i, c.TTL-h.Height, p.TTLMax)
		}
		// B3 — a certificate is billable once per canonical chain, and this is
		// the half of that promise a proposer cannot route around.
		//
		// "A certificate" means an authorization, not an encoding of one. The id
		// is over the authorizing fields and never over the signatures,
		// so a required signer re-signing the same body at a fresh nonce produces
		// the same key here and is refused — in this block by the duplicate check
		// above, and in every later block by this one.
		if _, seen := s.Seen(id); seen {
			return invalidCert(i, "B3", "certificate %d has already been committed", i)
		}
		// B4 — an unpayable certificate is unincludable. Fee drift may strand
		// a signed certificate; it may never bill one (R1-H3).
		if c.FeeBid.SeqMax.Lt(seqBaseFee) {
			return invalidCert(i, "B4", "certificate %d caps below the sequential base fee", i)
		}
		if c.FeeBid.ParMax.Lt(parBaseFee) {
			return invalidCert(i, "B4", "certificate %d caps below the parallel base fee", i)
		}

		seqGas += c.SeqGas(p)
		parGas += c.ParGas(p)
	}

	// The hard sequential ceiling is the burst bound 4T, not the target's
	// ceiling 2T (whitepaper §8.1). A block between 2T and 4T is valid; F11
	// forfeits the producer's block revenue against it quadratically — the
	// subsidy share and the block's fees. Only above 4T is a block invalid
	// outright.
	if seqGas > seqBurst {
		return invalid("B5", "sequential gas %d exceeds the burst bound of %d", seqGas, seqBurst)
	}
	if parGas > parCeiling {
		return invalid("B6", "parallel gas %d exceeds the ceiling of %d", parGas, parCeiling)
	}

	// F13 as a precondition rather than a postcondition: V7 already forbids
	// protocol writes, and checking again before touching state means a
	// regression costs a rejected block instead of corrupted state.
	return assertNoProtocolWrites(b.Certs)
}

// currentSeqGasTarget is T as it stands before this block: SeqGasTargetGenesis
// at height 0 because state has nothing to read yet, the state cell at every
// later height. It must be read before F2b's epoch controller (fold.go) has a
// chance to move it, because this is the value block rules judge the block's
// ceilings against and F11's burst forfeiture is assessed against the same
// value — the updated T takes effect from the block after this one, exactly
// as B4 judges fee bids against the pre-block base fees.
func currentSeqGasTarget(s *state.State, p *params.Params, height uint64) uint64 {
	if height == 0 {
		return p.SeqGasTargetGenesis
	}
	t, _ := s.Get(types.SeqGasTargetSlot()).Uint64()
	return t
}

// checkCites validates the structural and state-checkable half of a block's
// cited-competing-header list (whitepaper §8.1's health signal): C0 through
// C5 below, plus B17's prohibition on citing at all below height 2. The
// capacity bound is checked by the caller, before ComputeCitesRoot rather than
// here, for the same reason the certificate count is checked before
// ComputeCertRoot — see checkBlockRules.
//
// Proof of work is deliberately not a rule here, and the reason is the
// architecture rather than the import graph. An earlier draft of this comment
// claimed core/fold could not import a pow.Engine without inverting the
// dependency graph; that is simply false — core/pow depends only on other
// core packages, and core/fold importing it creates no cycle and breaks no
// principle. What the fold cannot afford is *running* it. Proof of work is
// memory-hard by design (RandomX at M3, milliseconds per evaluation), and
// whitepaper §3's whole claim is that the one sequential stage is a loop over
// memory with no cryptography in it. Up to MaxCitesPerBlock work evaluations
// per block inside the fold would cost more than everything else the fold
// does, in the one place the design has no budget to spend.
//
// So the check lives where the block's own header work is already checked
// (node/p2p, node/sync), and the split is sound because of C4: a citation
// names a target this function pins from state, so the only thing left for
// the node layer to establish is whether the work was actually done. That it
// is *consensus* and not policy — cited_count feeds the health gate, which
// moves T — is stated normatively in spec/wire.md §9, because a rule the fold
// does not enforce has to be written where an independent implementation is
// obliged to read it.
func checkCites(s *state.State, b *types.Block, p *params.Params) error {
	h := &b.Header
	if h.Height <= 1 {
		// No block at height 0 or 1 can have a sibling worth citing: genesis
		// is unique by construction (checkGenesisShape) and a block at height
		// 1 would be citing a competing genesis, which does not exist in this
		// protocol (a competing genesis is a different network, not a fork).
		if len(b.Cites) != 0 {
			return invalid("B17", "block at height %d may not cite: no sibling of its parent can exist", h.Height)
		}
		return nil
	}

	// C2 and C4's basis: the grandparent id and the difficulty target our
	// parent was mined under. A sibling of our parent shares both — it was
	// proposed against the same grandparent, under the same LWMA window.
	prevParentID := types.Hash(s.Get(types.PrevParentIDSlot()).Bytes())
	prevTarget := s.Get(types.PrevTargetSlot())

	var lastID types.Hash
	for i, cited := range b.Cites {
		// C0 — a citation must be something that could have been a block.
		// An unknown header version never could (the block rules reject it on
		// sight), so counting one toward the health signal would let the
		// signal measure things that are not competitors at all. It buys an
		// attacker no discount — the work is checked in full either way — but
		// a signal that counts non-blocks is not measuring the fork rate.
		if cited.Version != types.HeaderVersion {
			return invalid("C0", "citation %d has unknown header version %d", i, cited.Version)
		}
		// C1 — a citation names a sibling of our parent, not some other
		// ancestor: the one-block window that makes dedupe structural rather
		// than a set the fold has to maintain (see the package doc above).
		if cited.Height != h.Height-1 {
			return invalid("C1", "citation %d has height %d, this block is at %d", i, cited.Height, h.Height)
		}
		// C2 — same grandparent as our parent.
		if cited.ParentID != prevParentID {
			return invalid("C2", "citation %d does not share this block's grandparent", i)
		}
		id := cited.ID()
		// C3 — not our own parent restated as a competitor.
		if id == h.ParentID {
			return invalid("C3", "citation %d names this block's own parent", i)
		}
		// C4 — mined at the difficulty our parent's height actually
		// required, so a fabricated easy header cannot pass as a citation.
		if cited.Target != prevTarget {
			return invalid("C4", "citation %d claims a target this height was never mined under", i)
		}
		// C5 — strictly increasing ids, the R2-M2 discipline every other
		// list in this protocol already follows: two citations of one header
		// would be two encodings of one fact, and a duplicate buys nothing a
		// sorted, deduplicated list does not already capture more cheaply.
		if i > 0 && compareBytes(id[:], lastID[:]) <= 0 {
			return invalid("C5", "citations are not strictly sorted by id at index %d", i)
		}
		lastID = id
	}
	return nil
}

// checkGenesisShape pins block 0. Genesis is a reproducible artifact, not a
// ceremony: empty state, initialised beacon cells, empty spent registry, and no
// allocation of any kind to anybody.
func checkGenesisShape(b *types.Block, p *params.Params) error {
	if b.Header.Height != 0 {
		if b.Header.ParentID == (types.Hash{}) {
			return invalid("B10", "block at height %d has no parent", b.Header.Height)
		}
		return nil
	}
	if len(b.Certs) != 0 {
		return invalid("B10", "the genesis block carries certificates")
	}
	// The genesis block's parent slot carries the consensus root, so a node
	// configured with different parameters computes a different genesis id and
	// cannot accept this one (R3-1).
	if root := p.ConsensusRoot(); b.Header.ParentID != root {
		return invalid("B10", "the genesis block does not commit to this node's parameters")
	}
	if b.Header.EmissionAddr != (types.Address{}) {
		return invalid("B10", "the genesis block names a payout address")
	}
	if !p.IsEpochBoundary(0) {
		return invalid("B10", "height 0 must be an epoch boundary")
	}
	return nil
}

// checkSeedEpoch pins the proof-of-work key epoch a header declares to the one
// its own height implies.
//
// **The key is never read from this field.** Verifiers derive it from the
// height (pow.KeyFor), which is what keeps pow.CheckWork a total function of a
// header's bytes. That makes the field redundant with the height by
// construction — and a redundant field in a fixed-size header is exactly the
// kind of thing that has to be either pinned or removed, because the third
// option is 64 bits of free grinding space inside the proof-of-work seed and a
// comment claiming a role nothing performs.
//
// It is pinned rather than removed because pinning costs one comparison and
// removing costs an encoding change: PoWSealSize, HeaderSize, the fuzz corpus
// and wire §5 all move for a field that is genuinely useful to a reader
// holding a header and no parameters.
//
// **Why this lives in the fold rather than beside the target check.** It is
// pure arithmetic over the height — no window, no ancestors, no engine — so
// putting it here buys two things the target rule had to be argued into. It
// gets golden-vector coverage, which is what measures a second implementation
// rather than only this tree. And it is path-independent for free: every
// ingress and fork choice run ApplyBlock, so there is no ordering in which a
// block reaches the chain without this rule having been applied. That
// asymmetry cost the target rule a finding of its own — one ingress path did
// not re-derive the target — and this rule cannot have it.
//
// **Cited headers are deliberately NOT covered**, and the omission is load
// bearing rather than an oversight. wire §9 rule 7 fixes the checks a citation
// gets and states that the list is exhaustive: a node that adds one counts
// fewer citations than its peers, derives a different sequential target T, and
// forks. PoW.SeedEpoch is named there among the unconstrained fields, so a
// citation may carry any value at all and still count. Nothing breaks — the
// key for a cited header comes from *its* height like every other header's, so
// its work is checked against the same key its miner used, whatever it wrote
// in this field. The consequence worth stating out loud is that a citation may
// be a header that would be invalid as a block, which is already true of its
// Time, StateRoot, CertRoot and EmissionAddr.
//
// Genesis needs no exemption: SeedEpochFor returns 0 below the first boundary
// and block 0 declares 0, so the rule holds there like anywhere else.
func checkSeedEpoch(b *types.Block, p *params.Params) error {
	want := pow.SeedEpochFor(b.Header.Height, p)
	if b.Header.PoW.SeedEpoch != want {
		return invalid("B0b", "header at height %d declares seed epoch %d, the schedule gives %d",
			b.Header.Height, b.Header.PoW.SeedEpoch, want)
	}
	return nil
}

// checkEmissionAddr requires a payout address that can actually receive.
// Version 0x00 would pay the protocol and 0x03 would pay an asset's metadata
// address; both are value destroyed by a typo.
func checkEmissionAddr(b *types.Block) error {
	if b.Header.Height == 0 {
		return nil
	}
	if !crypto.IsUserAddress(b.Header.EmissionAddr) {
		return invalid("B11", "payout address is not a user address")
	}
	return nil
}
