package types

import (
	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/ssz"
	"zycord/core/u256"
)

// PoWSealSize is the encoded width of a PoWSeal.
const PoWSealSize = 16

// PoWSeal is the miner's proof-of-work answer.
//
// SeedEpoch names the key epoch the proof-of-work function was keyed for.
//
// **A verifier does not read it to find the key.** The key is derived from the
// header's own height (pow.KeyFor), which is what keeps pow.CheckWork a total
// function of a header's bytes — a header whose ancestry a node does not hold
// still has checkable work. So this field is redundant with Height by
// construction, and core/fold pins it to the value the schedule gives
// (checkSeedEpoch): redundant-and-pinned is a restatement a reader can use,
// where redundant-and-free would be 64 bits of grinding space inside the
// proof-of-work seed.
//
// The pin is a rule about BLOCK headers. A header carried in Cites is
// unconstrained here, deliberately and normatively — wire §9 rule 7 fixes the
// citation checks and says the list is exhaustive, because a node that adds
// one counts fewer citations than its peers and derives a different T.
//
// An earlier version of this comment said the field existed "so that a
// verifier knows which key to use without consulting a clock or a peer". That
// was the design before the key came from the height, and nothing ever read
// the field.
type PoWSeal struct {
	Nonce     uint64
	SeedEpoch uint64
}

// MarshalSSZ returns the canonical encoding.
func (s PoWSeal) MarshalSSZ() []byte {
	out := make([]byte, 0, PoWSealSize)
	out = append(out, ssz.Uint64(s.Nonce)...)
	out = append(out, ssz.Uint64(s.SeedEpoch)...)
	return out
}

// UnmarshalPoWSeal decodes a proof-of-work seal.
func UnmarshalPoWSeal(b []byte) (PoWSeal, error) {
	var s PoWSeal
	if len(b) != PoWSealSize {
		return s, ErrDecode
	}
	s.Nonce = ssz.ReadUint64(b[:8])
	s.SeedEpoch = ssz.ReadUint64(b[8:])
	return s, nil
}

// HeaderSize is the encoded width of a Header. Headers are fixed-size, which
// is what makes headers-first sync a fixed-cost operation per block.
const HeaderSize = 4 + 8 + 32 + 8 + 32 + 32 + 32 + 32 + PoWSealSize + 32

// HeaderVersion is the Era-0 header version.
const HeaderVersion uint32 = 1

// Header is everything a node needs to judge a block before it has the bodies.
type Header struct {
	Version  uint32
	Height   uint64
	ParentID Hash
	// Time is miner-declared. It is bounded below by the median of the last
	// blocks and withheld (never rejected) above the future-time limit, and it
	// is never read by a program: only beacon cells express time.
	Time uint64
	// CertRoot is the SSZ root of the ordered certificate-*exemplar* list: one
	// leaf per certificate over its whole encoding, signatures included.
	//
	// Not a root over certificate ids, and the distinction is the header half of
	// keeping signatures out of the id's preimage. An id names an authorization
	// and many encodings carry it, so a header committing to ids would commit to
	// no particular signature bytes at all. See Block.ComputeCertRoot for what
	// that would cost.
	CertRoot Hash
	// CitesRoot is the SSZ root of the block's cited competing headers
	// (whitepaper §8.1's health signal) — committed here so a relay cannot
	// strip a citation the proposer included, the same reason CertRoot exists.
	CitesRoot Hash
	// StateRoot is zero except on epoch-boundary blocks.
	StateRoot    Hash
	EmissionAddr Address
	PoW          PoWSeal
	Target       u256.U256
}

var headerLayout = []int{4, 8, 32, 8, 32, 32, 32, 32, PoWSealSize, 32}

// MarshalSSZ returns the canonical encoding.
func (h Header) MarshalSSZ() []byte {
	target := h.Target.Bytes()
	return ssz.Encode(headerLayout, [][]byte{
		ssz.Uint32(h.Version),
		ssz.Uint64(h.Height),
		h.ParentID[:],
		ssz.Uint64(h.Time),
		h.CertRoot[:],
		h.CitesRoot[:],
		h.StateRoot[:],
		h.EmissionAddr[:],
		h.PoW.MarshalSSZ(),
		target[:],
	})
}

// UnmarshalHeader decodes a header.
func UnmarshalHeader(b []byte) (*Header, error) {
	fields, err := ssz.Decode(headerLayout, b)
	if err != nil {
		return nil, err
	}
	h := &Header{
		Version: ssz.ReadUint32(fields[0]),
		Height:  ssz.ReadUint64(fields[1]),
		Time:    ssz.ReadUint64(fields[3]),
	}
	copy(h.ParentID[:], fields[2])
	copy(h.CertRoot[:], fields[4])
	copy(h.CitesRoot[:], fields[5])
	copy(h.StateRoot[:], fields[6])
	copy(h.EmissionAddr[:], fields[7])
	seal, err := UnmarshalPoWSeal(fields[8])
	if err != nil {
		return nil, err
	}
	h.PoW = seal
	var target [32]byte
	copy(target[:], fields[9])
	h.Target = u256.FromBytes(target)
	return h, nil
}

// ID is the block identifier: blake3 over the canonical header encoding.
func (h Header) ID() Hash {
	return crypto.Sum(crypto.TagBlock, h.MarshalSSZ())
}

// PoWSeed is the part of the proof-of-work input that does not change as the
// miner iterates nonces. Separating it is what lets a miner hash the header
// once per candidate block instead of once per attempt.
func (h Header) PoWSeed() Hash {
	sansNonce := h
	sansNonce.PoW.Nonce = 0
	return crypto.Sum(crypto.TagPoW, sansNonce.MarshalSSZ())
}

// PoWInput is the exact byte string the proof-of-work function is evaluated
// over: the seed followed by the nonce.
func (h Header) PoWInput() []byte {
	seed := h.PoWSeed()
	out := make([]byte, 0, 32+8)
	out = append(out, seed[:]...)
	out = append(out, ssz.Uint64(h.PoW.Nonce)...)
	return out
}

// Block is a header plus the certificate bodies it commits to, plus any
// competing headers it cites (whitepaper §8.1). Bodies are chain data: a
// block whose bodies cannot be retrieved is not a valid block, so state is
// always reconstructible from the chain alone.
type Block struct {
	Header Header
	Certs  []*Certificate
	// Cites are competing headers this block reports seeing, bounded by
	// MaxCitesPerBlock — a small, static, structural capacity, not a policy
	// ceiling (§8.1's health signal). Every entry's proof of work is checked
	// alongside the block's own, outside the fold (fold/blockrules.go).
	Cites []*Header
}

var blockLayout = []int{HeaderSize, ssz.Variable, ssz.Variable}

// MarshalSSZ returns the canonical encoding.
func (b *Block) MarshalSSZ() []byte {
	certElems := make([][]byte, len(b.Certs))
	for i, c := range b.Certs {
		certElems[i] = c.MarshalSSZ()
	}
	citeElems := make([][]byte, len(b.Cites))
	for i, h := range b.Cites {
		citeElems[i] = h.MarshalSSZ()
	}
	return ssz.Encode(blockLayout, [][]byte{
		b.Header.MarshalSSZ(),
		ssz.EncodeVariableList(certElems),
		ssz.EncodeVariableList(citeElems),
	})
}

// UnmarshalBlock decodes a block under the genesis limits.
//
// The certificate list is bounded by CertListCapacity, not by the dynamic
// MaxCertsPerBlock(t) ceiling: capacity is structural (it fixes CertRoot's
// merkle depth) and must be the same at every height, while the ceiling
// block rules enforce moves with T. Decoding more certificates than the
// block-rule ceiling allows is not an error here — CheckBlockRules rejects
// the block for it, the same division of labour as every other B-rule.
func UnmarshalBlock(data []byte, p *params.Params) (*Block, error) {
	fields, err := ssz.Decode(blockLayout, data)
	if err != nil {
		return nil, err
	}
	hdr, err := UnmarshalHeader(fields[0])
	if err != nil {
		return nil, err
	}
	certElems, err := ssz.DecodeVariableList(fields[1], p.CertListCapacity, CertMinSize)
	if err != nil {
		return nil, err
	}
	citeElems, err := ssz.DecodeVariableList(fields[2], p.MaxCitesPerBlock, HeaderSize)
	if err != nil {
		return nil, err
	}
	blk := &Block{Header: *hdr, Certs: make([]*Certificate, len(certElems)), Cites: make([]*Header, len(citeElems))}
	for i, e := range certElems {
		c, err := UnmarshalCertificate(e, p)
		if err != nil {
			return nil, err
		}
		blk.Certs[i] = c
	}
	for i, e := range citeElems {
		h, err := UnmarshalHeader(e)
		if err != nil {
			return nil, err
		}
		blk.Cites[i] = h
	}
	return blk, nil
}

// CertExemplars returns the certificate exemplar hashes in block order.
func (b *Block) CertExemplars() []Hash {
	hashes := make([]Hash, len(b.Certs))
	for i, c := range b.Certs {
		hashes[i] = c.ExemplarHash()
	}
	return hashes
}

// ComputeCertRoot returns the SSZ root of the ordered certificate-exemplar
// list.
//
// The root commits to the order the proposer chose, not to the fold's
// canonical order: a proposer is accountable for what it published, and the
// fold sorts a copy. The padding capacity is CertListCapacity, the static
// structural bound, not the dynamic per-block ceiling — see UnmarshalBlock.
//
// The leaves are exemplar hashes rather than certificate ids, and that is the
// half of that separation the fold cannot do. Signatures are evidence and sit
// outside the id's preimage, so an id no longer determines the bytes that
// carry it — and a header that committed only to ids would be a header under
// which a relay could swap or mangle signature bytes with the block id
// unchanged, which is a poisoned cache for every node keying a block by its
// header. Committing to the exemplar keeps "this block is valid" a statement
// about bytes the block itself pins (whitepaper §2, ARCHITECTURE §4).
//
// One leaf covers both questions rather than the paper's pair of (id,
// evidence hash), because in Era 0 signatures are the only evidence a
// certificate carries: the exemplar hash is over the whole encoding, so it
// commits to the id transitively and a second leaf would add nothing. When
// evidence becomes separable field by field — §12's range proofs — the pair
// form is what this function grows into, and it is still the right place.
func (b *Block) ComputeCertRoot(p *params.Params) Hash {
	return ssz.ListRoot(b.CertExemplars(), p.CertListCapacity)
}

// CiteIDs returns the cited header ids in block order.
func (b *Block) CiteIDs() []Hash {
	ids := make([]Hash, len(b.Cites))
	for i, h := range b.Cites {
		ids[i] = h.ID()
	}
	return ids
}

// ComputeCitesRoot returns the SSZ root of the block's cited-header-id list.
func (b *Block) ComputeCitesRoot(p *params.Params) Hash {
	return ssz.ListRoot(b.CiteIDs(), p.MaxCitesPerBlock)
}

// SizeBytes is the encoded block length, measured against the block byte
// ceiling.
func (b *Block) SizeBytes() int { return len(b.MarshalSSZ()) }

// emptyBlockBytes is what a block costs before any certificate: the fixed
// header plus the SSZ envelope around an empty certificate list. Computed from
// the encoder rather than written down, so it cannot drift away from it.
var emptyBlockBytes = len((&Block{}).MarshalSSZ())

// BlockOverheadBytes is the encoded cost of a block carrying nCerts
// certificates and nCites cited headers, *beyond the certificate bodies* — the
// block header, both list envelopes, the four-byte offset SSZ writes per
// element, and the cited headers themselves, which are fixed-size and so are
// pure overhead from a builder's point of view.
//
// It exists because a block builder that sums only certificate sizes builds
// blocks the block rules then reject. At the genesis ceilings that is not a
// near miss: 2,645 one-shot transfers sum to 2,499,525 bytes against a
// 2,500,000 ceiling and encode to 2,510,341, so the miner assembles a
// candidate, its own dry run refuses it, and `mineLoop` logs and retries the
// same set forever — the node stops producing blocks while its pool stays
// full.
//
// **Citations count, and the first version of this function forgot them** —
// four cited headers are another 928 bytes. It did not matter, because no
// builder in this release cites anything; it would have mattered on the day
// one did, which is exactly the day §15's decision to ship the carrier ahead
// of the producer anticipates. A caller that does not yet cite passes 0; a
// caller that might should pass MaxCitesPerBlock rather than its current
// count, since reserving the maximum costs under a thousandth of the ceiling
// and cannot be wrong.
func BlockOverheadBytes(nCerts, nCites int) int {
	return emptyBlockBytes +
		ssz.BytesPerLengthOffset*nCerts +
		(HeaderSize+ssz.BytesPerLengthOffset)*nCites
}
