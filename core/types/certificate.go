package types

import (
	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/ssz"
	"zycord/core/u256"
)

// Certificate is the only transaction type in Zycord: a self-certifying
// state transition that carries the state it read and the state it wrote.
//
// Its validity is a pure function of its bytes. Its *applicability* is decided
// only by its position in the ledger. Everything else in the protocol follows
// from keeping those two predicates apart.
type Certificate struct {
	ChainID uint64
	// Seq is the intra-underwriter order (R1-C2). The fold sorts by it, so a
	// signer's dependent certificates commit in the order they were signed no
	// matter how a proposer shuffles them.
	Seq     uint64
	Program Program
	// Reads are sorted by slot with no duplicates.
	Reads []Read
	// Writes are sorted by slot with no duplicates; deltas are pre-merged.
	Writes []Write
	// Sigs are sorted by public key with no duplicates.
	Sigs    []Sig
	Deposit Deposit
	// TTL is the last height at which this certificate may be committed.
	TTL    uint64
	FeeBid FeeBid
}

var certLayout = []int{
	8,            // ChainID
	8,            // Seq
	ssz.Variable, // Program
	ssz.Variable, // Reads
	ssz.Variable, // Writes
	ssz.Variable, // Sigs
	DepositSize,  // Deposit
	8,            // TTL
	FeeBidSize,   // FeeBid
}

// CertMinSize is the fixed section of certLayout, and so the least number of
// bytes any certificate can encode to: the four variable fields each still
// cost their offset. UnmarshalBlock hands it to the list decoder so that a
// block cannot claim more certificates than its own payload could carry.
var CertMinSize = ssz.FixedLen(certLayout)

// MarshalSSZ returns the canonical encoding of the whole certificate,
// signatures included.
func (c *Certificate) MarshalSSZ() []byte {
	return c.marshal(c.Sigs)
}

// marshalBody returns the encoding with an empty signature list.
//
// It is what signatures commit to — a signer signs the certificate, not the
// set of people who happened to sign alongside it — and, since signatures
// were taken out of the id's preimage, it is also the preimage of the
// certificate id. The two uses coincide because they are the same question
// asked twice: what did the signers authorise, as opposed to how they
// demonstrated it.
func (c *Certificate) marshalBody() []byte {
	return c.marshal(nil)
}

func (c *Certificate) marshal(sigs []Sig) []byte {
	var reads, writes, sigBytes []byte
	for _, r := range c.Reads {
		reads = append(reads, r.MarshalSSZ()...)
	}
	for _, w := range c.Writes {
		writes = append(writes, w.MarshalSSZ()...)
	}
	for _, s := range sigs {
		sigBytes = append(sigBytes, s.MarshalSSZ()...)
	}
	return ssz.Encode(certLayout, [][]byte{
		ssz.Uint64(c.ChainID),
		ssz.Uint64(c.Seq),
		c.Program.MarshalSSZ(),
		reads,
		writes,
		sigBytes,
		c.Deposit.MarshalSSZ(),
		ssz.Uint64(c.TTL),
		c.FeeBid.MarshalSSZ(),
	})
}

// UnmarshalCertificate decodes a certificate under the genesis list limits.
// Every length bound in p is enforced here, so no later rule has to.
func UnmarshalCertificate(b []byte, p *params.Params) (*Certificate, error) {
	fields, err := ssz.Decode(certLayout, b)
	if err != nil {
		return nil, err
	}

	c := &Certificate{
		ChainID: ssz.ReadUint64(fields[0]),
		Seq:     ssz.ReadUint64(fields[1]),
		TTL:     ssz.ReadUint64(fields[7]),
	}

	prog, err := UnmarshalProgram(fields[2], p.MaxMovesPerTransfer, p.MaxRetireAddrs)
	if err != nil {
		return nil, err
	}
	c.Program = prog

	readElems, err := ssz.DecodeFixedList(fields[3], ReadSize, p.MaxReads)
	if err != nil {
		return nil, err
	}
	c.Reads = make([]Read, len(readElems))
	for i, e := range readElems {
		r, err := UnmarshalRead(e)
		if err != nil {
			return nil, err
		}
		// Strictly increasing, not merely sorted: equal neighbours would give
		// one state transition two encodings and therefore two ids, which the
		// seen set cannot close over (R2-M2).
		if i > 0 && c.Reads[i-1].Slot.Compare(r.Slot) >= 0 {
			return nil, ErrDecode
		}
		c.Reads[i] = r
	}

	writeElems, err := ssz.DecodeFixedList(fields[4], WriteSize, p.MaxWrites)
	if err != nil {
		return nil, err
	}
	c.Writes = make([]Write, len(writeElems))
	for i, e := range writeElems {
		w, err := UnmarshalWrite(e)
		if err != nil {
			return nil, err
		}
		if i > 0 && c.Writes[i-1].Slot.Compare(w.Slot) >= 0 {
			return nil, ErrDecode
		}
		c.Writes[i] = w
	}

	sigElems, err := ssz.DecodeFixedList(fields[5], SigSize, p.MaxSigs)
	if err != nil {
		return nil, err
	}
	c.Sigs = make([]Sig, len(sigElems))
	for i, e := range sigElems {
		s, err := UnmarshalSig(e)
		if err != nil {
			return nil, err
		}
		// Strictly increasing by public key. It is no longer the id that this
		// protects — the id's preimage has no signatures in it — but the
		// exemplar hash, which the block's certificate root commits to: a
		// permuted signature list would be a second encoding of one certificate
		// that no rule could tell from the first, and duplicates would defeat
		// V4's minimality by satisfying one requirement twice.
		if i > 0 && !bytesIncreasing(c.Sigs[i-1].PubKey[:], s.PubKey[:]) {
			return nil, ErrDecode
		}
		c.Sigs[i] = s
	}

	dep, err := UnmarshalDeposit(fields[6])
	if err != nil {
		return nil, err
	}
	c.Deposit = dep

	bid, err := UnmarshalFeeBid(fields[8])
	if err != nil {
		return nil, err
	}
	c.FeeBid = bid

	return c, nil
}

// bytesIncreasing reports whether a sorts strictly before b.
func bytesIncreasing(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ID is the certificate identifier: blake3 over the *authorizing* fields,
// which is every field except the signatures.
//
// It names an authorization, not a set of bytes. That distinction is the whole
// reason signatures are excluded, and it is worth stating rather than assuming.
//
// The seen set is whitepaper §2's replay defence, and a replay defence works
// only if one authorization has one key. An id over the whole encoding does
// not give that. RFC 8032 verification accepts any (R, S) with
// [S]B = R + [h(R‖A‖M)]A; the nonce is the signer's to choose, and
// determinism is a signer-side convention that no verifier can check and no
// encoding rule can impose — every [r]B is a canonically encodable
// prime-order point. So one signed body has unboundedly many valid signature
// lists, and an id covering them had unboundedly many values. Any *one* of the
// required signers could mint a fresh id out of the others' authority and have
// it billed again; measured, one signed transfer of 100_000_000 moved
// 200_000_000 in a single block.
//
// This is whitepaper §2's own rule, and the paper used to get it wrong here: it
// stated the test — a randomized demonstration has unboundedly many valid,
// canonical forms, so canonicity does not reach it — applied it to §12's range
// proofs, and classified the signature it already ships on the other side. §2
// now classifies a signature as evidence, which is what it is: a demonstration
// that an authorization was given, not part of what was authorized. So it
// travels outside the id's preimage, and what pins the bytes instead is
// ExemplarHash below.
//
// What makes the id sufficient is V4. Minimality plus sufficiency mean the
// required signer set is a function of the body alone: every required key must
// sign, and a signature that authorises nothing is invalid. Two stateless-valid
// certificates with one id therefore carry the same signer list, hence the same
// signature count and the same encoded length, hence the same gas and the same
// fee ceiling. One id, one authorization, one cost — pinned by
// TestTheIdPinsTheSignerSetAndThereforeTheCost.
func (c *Certificate) ID() Hash {
	return crypto.Sum(crypto.TagCertID, c.marshalBody())
}

// ExemplarHash names one *encoding* of a certificate: blake3 over the whole
// canonical encoding, signatures included.
//
// It is the evidence commitment. Because signatures sit outside the id's
// preimage, they are bytes anyone in transit could otherwise replace without
// the id noticing — so the block commits to them separately, and this is what
// it commits to: Block.ComputeCertRoot is a root over these, not over ids. The
// id answers "has this authorization been billed"; the exemplar hash answers
// "do these bytes prove it"; and the two questions never share a key
// (whitepaper §2, ARCHITECTURE §4).
//
// Nothing else in the protocol keys on it. A node that has an exemplar whose
// signatures do not verify discards that exemplar and holds nothing against
// the id, because a later exemplar of the same authorization may be perfectly
// good.
func (c *Certificate) ExemplarHash() Hash {
	return crypto.Sum(crypto.TagCert, c.MarshalSSZ())
}

// BodyRoot is the digest signatures are taken over.
func (c *Certificate) BodyRoot() Hash {
	return crypto.Sum(crypto.TagCertBody, c.marshalBody())
}

// SigningMessage returns the exact bytes every signer of this certificate
// signs. The chain id is inside it, so a signature cannot cross networks, and
// the parameter set's consensus root is inside it, so a signature cannot cross
// two incarnations of one network either.
//
// The certificate's own ChainID is what goes in, not p's: V1 is where the two
// are required to agree, and a certificate carrying a foreign chain id must
// fail that rule rather than fail to have a signing message at all.
func (c *Certificate) SigningMessage(p *params.Params) []byte {
	return crypto.SigningMessage(c.ChainID, p.ConsensusRoot(), c.BodyRoot())
}

// SizeBytes is the encoded length, which is what the parallel-gas byte term
// and the block byte ceiling are measured in.
func (c *Certificate) SizeBytes() int { return len(c.MarshalSSZ()) }

// UnderwriterID is the identity the fold sorts by. In Era 0 every certificate
// is self-insured, so the underwriter is the owner of the deposit cell.
//
// Phase 1 adds co-signed underwriters; they reuse this identity and the same
// (id, Seq) ordering, so the sort function never changes.
func (c *Certificate) UnderwriterID() Address { return c.Deposit.Cell.Addr }

// SeqGas is the certificate's sequential-gas cost: the fold work it causes.
// It is a pure function of the certificate, which is what lets the deposit
// ceiling be checked without any state.
func (c *Certificate) SeqGas(p *params.Params) uint64 {
	gas := p.GasSeqPerRead * uint64(len(c.Reads))
	gas += p.GasSeqPerWrite * uint64(len(c.Writes))
	gas += p.GasSeqPerRegistryInsert * uint64(c.markSpentCount())
	gas += p.GasSeqPerSeenInsert
	return gas
}

// ParGas is the certificate's parallel-gas cost: the verification work it
// causes. This is the abundant market — its supply grows with every core and
// GPU that joins the network.
func (c *Certificate) ParGas(p *params.Params) uint64 {
	gas := p.GasParPerSig * uint64(len(c.Sigs))
	gas += p.GasParPerByte * uint64(c.SizeBytes())
	gas += p.GasParPerDeriveUnit * c.Program.DeriveUnits()
	return gas
}

func (c *Certificate) markSpentCount() int {
	n := 0
	for i := range c.Writes {
		if c.Writes[i].Op == OpMarkSpent {
			n++
		}
	}
	return n
}

// Fees splits what an *applied* certificate costs into the part that is burned
// and the part that reaches the miner, given the block's two base fees.
//
// Both markets charge the full bid. The base-fee portion of each is burned, and
// the excess over base is a priority tip paid to the miner. Two properties
// follow, and both are load-bearing:
//
//   - Burning the base fees keeps them honest. A base fee that reached the
//     miner could be manipulated for free: a miner would stuff its own block
//     with self-paying certificates to inflate apparent demand, driving the
//     base fee up for everyone else at no cost to itself. Burned, that attack
//     costs real money.
//   - Tipping on *both* markets is what gives the scarce resource a price. The
//     sequential loop is the one thing that does not parallelise; if only the
//     parallel market carried a tip, a revenue-maximising builder would order
//     by verification demand and allocate state mutation — the actual
//     bottleneck — for free, or sell it off-chain (I1-H2).
//
// Tips are earned only on application: see fold's F9, which is the sole place a
// tip is ever routed and which the skip and drop paths both return before
// reaching. So a builder maximising revenue is maximising *applied*
// certificates, never harvesting skips.
//
// That second sentence is a statement about the builder, not a consequence of
// the first, and it has been false: MinerTip below is computed on the
// assumption a certificate applies — its own doc comment says so — so ranking
// by it ranks a guaranteed-skip certificate at the price it would have paid
// had it applied. Nothing between the signer and the block corrected for that.
// It is true now because node/miner's dropTheDrops makes it true, excluding
// every certificate whose dry-run outcome is not Applied before the block is
// sealed. Anything that ranks or packs certificates has to satisfy this
// itself; the fold will not do it for them.
//
// The final result reports arithmetic overflow, which is a validity failure
// rather than a wrapped fee. It cannot occur for a certificate that passed V5
// and B4.
func (c *Certificate) Fees(p *params.Params, seqBaseFee, parBaseFee u256.U256) (charge, burned, tip u256.U256, ok bool) {
	seqGas := u256.FromUint64(c.SeqGas(p))
	parGas := u256.FromUint64(c.ParGas(p))

	seqBurn, seqTip, ok := market(seqGas, seqBaseFee, c.FeeBid.SeqMax, c.FeeBid.SeqPriority)
	if !ok {
		return u256.Zero, u256.Zero, u256.Zero, false
	}
	parBurn, parTip, ok := market(parGas, parBaseFee, c.FeeBid.ParMax, c.FeeBid.ParPriority)
	if !ok {
		return u256.Zero, u256.Zero, u256.Zero, false
	}

	burned, over := seqBurn.Add(parBurn)
	if over {
		return u256.Zero, u256.Zero, u256.Zero, false
	}
	tip, over = seqTip.Add(parTip)
	if over {
		return u256.Zero, u256.Zero, u256.Zero, false
	}
	charge, over = burned.Add(tip)
	if over {
		return u256.Zero, u256.Zero, u256.Zero, false
	}
	return charge, burned, tip, true
}

// market settles one of the two fee markets:
//
//	effective = min(priority, max − base)
//	burn      = gas × base
//	tip       = gas × effective
//
// The clamp is what makes the safety buffer free: raising `max` while holding
// `priority` and the base fee fixed changes nothing a signer pays (R2-H1).
func market(gas, base, maxPrice, priority u256.U256) (burn, tip u256.U256, ok bool) {
	// B4 forbids a maximum below the base fee, so the headroom never
	// underflows. Re-checked here because Fees is exported and a wallet may
	// call it before B4 has had a chance to.
	headroom, underflow := maxPrice.Sub(base)
	if underflow {
		return u256.Zero, u256.Zero, false
	}
	effective := u256.MinOf(priority, headroom)

	burn, over := gas.Mul(base)
	if over {
		return u256.Zero, u256.Zero, false
	}
	tip, over = gas.Mul(effective)
	if over {
		return u256.Zero, u256.Zero, false
	}
	return burn, tip, true
}

// MinerTip is the revenue a block builder earns from including this
// certificate, assuming it applies. It is the quantity a miner sorts by, and
// the quantity `node/miner` will maximise.
func (c *Certificate) MinerTip(p *params.Params, seqBaseFee, parBaseFee u256.U256) u256.U256 {
	_, _, tip, ok := c.Fees(p, seqBaseFee, parBaseFee)
	if !ok {
		return u256.Zero
	}
	return tip
}

// FeeCeiling is the most a certificate can ever cost its depositor:
//
//	max(SKIP_FEE, seq_gas × seq_bid + par_gas × par_bid)
//
// SKIP_FEE is a protocol constant (R1-H1), which is exactly what makes this
// computable from the certificate alone. The ceiling is tight against the worst
// case the signer authorised: the maximum prices, which is exactly what a
// maximum means. An applied certificate normally costs less, and the difference
// is refunded within the same fold step. The second return value reports
// arithmetic overflow, which is a validity failure rather than a wrapped fee.
func (c *Certificate) FeeCeiling(p *params.Params) (u256.U256, bool) {
	seq, over := u256.FromUint64(c.SeqGas(p)).Mul(c.FeeBid.SeqMax)
	if over {
		return u256.Zero, false
	}
	par, over := u256.FromUint64(c.ParGas(p)).Mul(c.FeeBid.ParMax)
	if over {
		return u256.Zero, false
	}
	total, over := seq.Add(par)
	if over {
		return u256.Zero, false
	}
	return u256.MaxOf(p.SkipFee, total), true
}
