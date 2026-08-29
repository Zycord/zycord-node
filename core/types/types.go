// Package types defines every object the consensus rules can see.
//
// Each type spells out its own canonical encoding. There is no reflection and
// no generated code: an encoder you cannot read line by line is an encoder in
// which consensus bugs hide. Decoding enforces canonical form, so a decoded
// object is structurally valid by construction and the V-rules and F-rules
// never re-check shape.
package types

import (
	"errors"

	"zycord/core/crypto"
	"zycord/core/ssz"
	"zycord/core/u256"
)

// Common aliases, re-exported so the rest of the tree can speak about
// addresses and hashes without importing the crypto package for a type.
type (
	// Hash is a 32-byte domain-separated digest.
	Hash = crypto.Hash
	// Address is a 32-byte account, asset or protocol identifier.
	Address = crypto.Address
	// PubKey is a 32-byte Ed25519 public key.
	PubKey = crypto.PubKey
	// SigBytes is a 64-byte Ed25519 signature.
	SigBytes = crypto.Signature
)

// Errors returned by decoders and structural checks.
var (
	ErrDecode       = errors.New("types: malformed encoding")
	ErrProgramKind  = errors.New("types: unknown program kind")
	ErrProgramShape = errors.New("types: program body does not match its kind")
)

// ---------------------------------------------------------------------------
// Slot
// ---------------------------------------------------------------------------

// SlotSize is the encoded width of a Slot.
const SlotSize = 64

// Slot is a cell coordinate: an address and a word within it.
//
// Slots are ordered lexicographically over Addr ‖ Word. That order is the one
// certificates must sort their reads and writes by, and it is the order the
// epoch state root is built in — one comparison function, no exceptions.
type Slot struct {
	Addr Address
	Word [32]byte
}

// Compare orders two slots lexicographically. It returns -1, 0 or +1.
func (s Slot) Compare(o Slot) int {
	for i := 0; i < 32; i++ {
		if s.Addr[i] != o.Addr[i] {
			if s.Addr[i] < o.Addr[i] {
				return -1
			}
			return 1
		}
	}
	for i := 0; i < 32; i++ {
		if s.Word[i] != o.Word[i] {
			if s.Word[i] < o.Word[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Less reports whether s sorts before o.
func (s Slot) Less(o Slot) bool { return s.Compare(o) < 0 }

// MarshalSSZ returns the 64-byte canonical encoding.
func (s Slot) MarshalSSZ() []byte {
	out := make([]byte, 0, SlotSize)
	out = append(out, s.Addr[:]...)
	out = append(out, s.Word[:]...)
	return out
}

// UnmarshalSlot decodes a 64-byte slot.
func UnmarshalSlot(b []byte) (Slot, error) {
	var s Slot
	if len(b) != SlotSize {
		return s, ErrDecode
	}
	copy(s.Addr[:], b[:32])
	copy(s.Word[:], b[32:])
	return s, nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Access disciplines. The whole concurrency model is these four values: EXACT
// pins a certificate to a value, the guards assert a predicate without letting
// the value flow into the computation, and everything commutes that can.
const (
	// AccessExact requires the cell to equal the operand.
	AccessExact uint8 = 0
	// AccessGuardGE requires the cell to be at least the operand.
	AccessGuardGE uint8 = 1
	// AccessGuardLE requires the cell to be at most the operand.
	AccessGuardLE uint8 = 2
	// AccessGuardEQ requires the cell to equal the operand, without the value
	// entering the computation. Distinct from AccessExact, which does feed it.
	AccessGuardEQ uint8 = 3
	accessMax           = AccessGuardEQ
)

// ReadSize is the encoded width of a Read.
const ReadSize = SlotSize + 1 + 32

// Read is a declared input: a slot, how it is accessed, and the operand the
// access is evaluated against.
type Read struct {
	Slot    Slot
	Access  uint8
	Operand u256.U256
}

// MarshalSSZ returns the canonical encoding.
func (r Read) MarshalSSZ() []byte {
	op := r.Operand.Bytes()
	out := make([]byte, 0, ReadSize)
	out = append(out, r.Slot.MarshalSSZ()...)
	out = append(out, r.Access)
	out = append(out, op[:]...)
	return out
}

// UnmarshalRead decodes a read, rejecting out-of-range access disciplines.
func UnmarshalRead(b []byte) (Read, error) {
	var r Read
	if len(b) != ReadSize {
		return r, ErrDecode
	}
	s, err := UnmarshalSlot(b[:SlotSize])
	if err != nil {
		return r, err
	}
	r.Slot = s
	r.Access = b[SlotSize]
	if r.Access > accessMax {
		return r, ErrDecode
	}
	var op [32]byte
	copy(op[:], b[SlotSize+1:])
	r.Operand = u256.FromBytes(op)
	return r, nil
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

// Write operations.
const (
	// OpSet replaces the cell value.
	OpSet uint8 = 0
	// OpDeltaAdd adds an unsigned magnitude to the cell.
	OpDeltaAdd uint8 = 1
	// OpDeltaSub subtracts an unsigned magnitude from the cell.
	OpDeltaSub uint8 = 2
	// OpMarkSpent burns the signing authority of an entire address. It is
	// address-wide, so its slot word must be zero and its value must be zero.
	OpMarkSpent uint8 = 3
	opMax             = OpMarkSpent
)

// WriteSize is the encoded width of a Write.
const WriteSize = SlotSize + 1 + 32

// Write is a declared output.
type Write struct {
	Slot  Slot
	Op    uint8
	Value u256.U256
}

// MarshalSSZ returns the canonical encoding.
func (w Write) MarshalSSZ() []byte {
	v := w.Value.Bytes()
	out := make([]byte, 0, WriteSize)
	out = append(out, w.Slot.MarshalSSZ()...)
	out = append(out, w.Op)
	out = append(out, v[:]...)
	return out
}

// UnmarshalWrite decodes a write, rejecting out-of-range operations and
// non-canonical MARK_SPENT encodings.
func UnmarshalWrite(b []byte) (Write, error) {
	var w Write
	if len(b) != WriteSize {
		return w, ErrDecode
	}
	s, err := UnmarshalSlot(b[:SlotSize])
	if err != nil {
		return w, err
	}
	w.Slot = s
	w.Op = b[SlotSize]
	if w.Op > opMax {
		return w, ErrDecode
	}
	var v [32]byte
	copy(v[:], b[SlotSize+1:])
	w.Value = u256.FromBytes(v)
	if w.Op == OpMarkSpent {
		// One address-wide spend has exactly one encoding.
		if w.Slot.Word != ([32]byte{}) || !w.Value.IsZero() {
			return w, ErrDecode
		}
	}
	return w, nil
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

// SigSize is the encoded width of a Sig.
const SigSize = 32 + 64

// Sig is a public key paired with its signature over the certificate's
// signing message. Certificates carry keys, not key hashes, so authorisation
// is checkable without any state.
type Sig struct {
	PubKey PubKey
	Sig    SigBytes
}

// MarshalSSZ returns the canonical encoding.
func (s Sig) MarshalSSZ() []byte {
	out := make([]byte, 0, SigSize)
	out = append(out, s.PubKey[:]...)
	out = append(out, s.Sig[:]...)
	return out
}

// UnmarshalSig decodes a signature pair.
func UnmarshalSig(b []byte) (Sig, error) {
	var s Sig
	if len(b) != SigSize {
		return s, ErrDecode
	}
	copy(s.PubKey[:], b[:32])
	copy(s.Sig[:], b[32:])
	return s, nil
}

// ---------------------------------------------------------------------------
// Deposit and fee bid
// ---------------------------------------------------------------------------

// DepositSize is the encoded width of a Deposit.
const DepositSize = SlotSize + 32 + SlotSize

// Deposit is the reservation that makes a certificate billable.
//
// RefundTo exists because the deposit cell may be a one-shot address that this
// very certificate burns: settling into the burned cell would either fail or
// strand the funds (R1-C3). The remainder therefore always lands somewhere the
// signer nominated in advance.
type Deposit struct {
	Cell     Slot
	Amount   u256.U256
	RefundTo Slot
}

// MarshalSSZ returns the canonical encoding.
func (d Deposit) MarshalSSZ() []byte {
	amt := d.Amount.Bytes()
	out := make([]byte, 0, DepositSize)
	out = append(out, d.Cell.MarshalSSZ()...)
	out = append(out, amt[:]...)
	out = append(out, d.RefundTo.MarshalSSZ()...)
	return out
}

// UnmarshalDeposit decodes a deposit.
func UnmarshalDeposit(b []byte) (Deposit, error) {
	var d Deposit
	if len(b) != DepositSize {
		return d, ErrDecode
	}
	cell, err := UnmarshalSlot(b[:SlotSize])
	if err != nil {
		return d, err
	}
	refund, err := UnmarshalSlot(b[SlotSize+32:])
	if err != nil {
		return d, err
	}
	var amt [32]byte
	copy(amt[:], b[SlotSize:SlotSize+32])
	d.Cell = cell
	d.Amount = u256.FromBytes(amt)
	d.RefundTo = refund
	return d, nil
}

// FeeBidSize is the encoded width of a FeeBid.
const FeeBidSize = 128

// FeeBid is the signer's offer in each of the two markets, as a maximum and a
// priority price per unit of gas.
//
// The two fields do different jobs and conflating them costs the signer money.
// The *maximum* is a solvency bound: B4 makes a certificate unincludable once
// the base fee passes it, and a certificate may sit in the mempool for up to
// TTL_MAX blocks while the base fee moves 12.5% per block — so a signer who
// wants to survive that window must name a maximum far above today's base fee.
// The *priority* is what the signer actually offers the miner for ordering.
//
// Charging the maximum would mean charging that safety buffer in full every
// time a certificate happened to be included early: a structural overpayment
// equal to the signer's own risk margin, on every certificate, forever. With
// two fields the buffer is free unless the market actually moves into it
// (R2-H1).
//
// Canonical form requires priority <= maximum in each market.
type FeeBid struct {
	// SeqMax is the most the signer will pay per unit of sequential gas.
	SeqMax u256.U256
	// SeqPriority is the tip offered per unit of sequential gas, clamped at
	// settlement to whatever headroom the base fee leaves under SeqMax.
	SeqPriority u256.U256
	// ParMax is the most the signer will pay per unit of parallel gas.
	ParMax u256.U256
	// ParPriority is the tip offered per unit of parallel gas.
	ParPriority u256.U256
}

// MarshalSSZ returns the canonical encoding.
func (f FeeBid) MarshalSSZ() []byte {
	sm, sp := f.SeqMax.Bytes(), f.SeqPriority.Bytes()
	pm, pp := f.ParMax.Bytes(), f.ParPriority.Bytes()
	out := make([]byte, 0, FeeBidSize)
	out = append(out, sm[:]...)
	out = append(out, sp[:]...)
	out = append(out, pm[:]...)
	out = append(out, pp[:]...)
	return out
}

// UnmarshalFeeBid decodes a fee bid, rejecting a priority above its maximum.
func UnmarshalFeeBid(b []byte) (FeeBid, error) {
	var f FeeBid
	if len(b) != FeeBidSize {
		return f, ErrDecode
	}
	var sm, sp, pm, pp [32]byte
	copy(sm[:], b[0:32])
	copy(sp[:], b[32:64])
	copy(pm[:], b[64:96])
	copy(pp[:], b[96:128])
	f.SeqMax = u256.FromBytes(sm)
	f.SeqPriority = u256.FromBytes(sp)
	f.ParMax = u256.FromBytes(pm)
	f.ParPriority = u256.FromBytes(pp)
	if f.SeqPriority.Gt(f.SeqMax) || f.ParPriority.Gt(f.ParMax) {
		return f, ErrDecode
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// Programs
// ---------------------------------------------------------------------------

// ProgramKind tags the Era-0 native operation set. There are four operations
// and no virtual machine: issue, mint to a cap, transfer, retire.
type ProgramKind uint8

// The Era-0 program set.
const (
	ProgramTransfer ProgramKind = 0
	ProgramIssue    ProgramKind = 1
	ProgramMint     ProgramKind = 2
	ProgramRetire   ProgramKind = 3
)

// MoveSize is the encoded width of a Move.
const MoveSize = 32 * 4

// Move is one value motion inside a TRANSFER. A zero Asset means the native
// coin.
type Move struct {
	Asset  Address
	Src    Address
	Dst    Address
	Amount u256.U256
}

// MarshalSSZ returns the canonical encoding.
func (m Move) MarshalSSZ() []byte {
	amt := m.Amount.Bytes()
	out := make([]byte, 0, MoveSize)
	out = append(out, m.Asset[:]...)
	out = append(out, m.Src[:]...)
	out = append(out, m.Dst[:]...)
	out = append(out, amt[:]...)
	return out
}

// UnmarshalMove decodes a move.
func UnmarshalMove(b []byte) (Move, error) {
	var m Move
	if len(b) != MoveSize {
		return m, ErrDecode
	}
	copy(m.Asset[:], b[0:32])
	copy(m.Src[:], b[32:64])
	copy(m.Dst[:], b[64:96])
	var amt [32]byte
	copy(amt[:], b[96:128])
	m.Amount = u256.FromBytes(amt)
	return m, nil
}

// TransferArgs moves value between balance cells. Every debit is guarded and
// every credit is a pure delta, which is why ten thousand tips in one block
// cost ten thousand commutative additions and zero skips.
type TransferArgs struct {
	Moves []Move
}

// IssueSize is the encoded width of IssueArgs.
const IssueSize = 32 + 32 + 32 + 32 + 1

// IssueArgs creates an asset. It is permissionless: emitting an asset costs
// only fees.
//
// Issuer is explicit rather than inferred, because the asset address is derived
// from (chain id, issuer, seq) — deriving it from the certificate id instead
// would be circular, since the certificate commits to the writes that name the
// address.
type IssueArgs struct {
	Issuer     Address
	Cap        u256.U256
	SymbolHash Hash
	Minter     PubKey
	Decimals   uint8
}

// MarshalSSZ returns the canonical encoding.
func (a IssueArgs) MarshalSSZ() []byte {
	capBytes := a.Cap.Bytes()
	out := make([]byte, 0, IssueSize)
	out = append(out, a.Issuer[:]...)
	out = append(out, capBytes[:]...)
	out = append(out, a.SymbolHash[:]...)
	out = append(out, a.Minter[:]...)
	out = append(out, a.Decimals)
	return out
}

// UnmarshalIssueArgs decodes issue parameters.
func UnmarshalIssueArgs(b []byte) (IssueArgs, error) {
	var a IssueArgs
	if len(b) != IssueSize {
		return a, ErrDecode
	}
	copy(a.Issuer[:], b[0:32])
	var c [32]byte
	copy(c[:], b[32:64])
	a.Cap = u256.FromBytes(c)
	copy(a.SymbolHash[:], b[64:96])
	copy(a.Minter[:], b[96:128])
	a.Decimals = b[128]
	return a, nil
}

// MintSize is the encoded width of MintArgs.
const MintSize = 32 * 5

// MintArgs mints against a supply cap.
//
// Cap and Minter are the *declared values* of the asset's immutable authority
// cells. Carrying them in the program is what makes authorisation stateless:
// V-rules check the signature against the declared minter, and the fold's exact
// read guarantees the declared value is the real one.
type MintArgs struct {
	Asset  Address
	Dst    Address
	Amount u256.U256
	Cap    u256.U256
	Minter PubKey
}

// MarshalSSZ returns the canonical encoding.
func (a MintArgs) MarshalSSZ() []byte {
	amt := a.Amount.Bytes()
	cp := a.Cap.Bytes()
	out := make([]byte, 0, MintSize)
	out = append(out, a.Asset[:]...)
	out = append(out, a.Dst[:]...)
	out = append(out, amt[:]...)
	out = append(out, cp[:]...)
	out = append(out, a.Minter[:]...)
	return out
}

// UnmarshalMintArgs decodes mint parameters.
func UnmarshalMintArgs(b []byte) (MintArgs, error) {
	var a MintArgs
	if len(b) != MintSize {
		return a, ErrDecode
	}
	copy(a.Asset[:], b[0:32])
	copy(a.Dst[:], b[32:64])
	var amt, cp [32]byte
	copy(amt[:], b[64:96])
	copy(cp[:], b[96:128])
	a.Amount = u256.FromBytes(amt)
	a.Cap = u256.FromBytes(cp)
	copy(a.Minter[:], b[128:160])
	return a, nil
}

// RetireArgs burns the signing authority of one-shot addresses the caller
// owns: privacy hygiene and state compaction without moving value.
type RetireArgs struct {
	Addrs []Address
}

// Program is a tagged union over the Era-0 operation set. Exactly one body
// pointer is non-nil, and it is the one Kind names; decoding cannot produce
// any other shape.
type Program struct {
	Kind     ProgramKind
	Transfer *TransferArgs
	Issue    *IssueArgs
	Mint     *MintArgs
	Retire   *RetireArgs
}

// programLayout is Kind followed by the variable-length body.
var programLayout = []int{1, ssz.Variable}

// MarshalSSZ returns the canonical encoding.
func (p Program) MarshalSSZ() []byte {
	var body []byte
	switch p.Kind {
	case ProgramTransfer:
		for _, m := range p.Transfer.Moves {
			body = append(body, m.MarshalSSZ()...)
		}
	case ProgramIssue:
		body = p.Issue.MarshalSSZ()
	case ProgramMint:
		body = p.Mint.MarshalSSZ()
	case ProgramRetire:
		for _, a := range p.Retire.Addrs {
			body = append(body, a[:]...)
		}
	default:
		panic("types: cannot encode unknown program kind")
	}
	return ssz.Encode(programLayout, [][]byte{{byte(p.Kind)}, body})
}

// UnmarshalProgram decodes a program under the given list limits.
func UnmarshalProgram(b []byte, maxMoves, maxRetire int) (Program, error) {
	var p Program
	fields, err := ssz.Decode(programLayout, b)
	if err != nil {
		return p, err
	}
	p.Kind = ProgramKind(fields[0][0])
	body := fields[1]

	switch p.Kind {
	case ProgramTransfer:
		elems, err := ssz.DecodeFixedList(body, MoveSize, maxMoves)
		if err != nil {
			return p, err
		}
		args := &TransferArgs{Moves: make([]Move, len(elems))}
		for i, e := range elems {
			m, err := UnmarshalMove(e)
			if err != nil {
				return p, err
			}
			args.Moves[i] = m
		}
		p.Transfer = args
	case ProgramIssue:
		args, err := UnmarshalIssueArgs(body)
		if err != nil {
			return p, err
		}
		p.Issue = &args
	case ProgramMint:
		args, err := UnmarshalMintArgs(body)
		if err != nil {
			return p, err
		}
		p.Mint = &args
	case ProgramRetire:
		elems, err := ssz.DecodeFixedList(body, 32, maxRetire)
		if err != nil {
			return p, err
		}
		args := &RetireArgs{Addrs: make([]Address, len(elems))}
		for i, e := range elems {
			copy(args.Addrs[i][:], e)
			// Strictly increasing: a retire list with a repeat, or in another
			// order, would be a second encoding of one transition (R2-M2).
			if i > 0 && !addrIncreasing(args.Addrs[i-1], args.Addrs[i]) {
				return p, ErrDecode
			}
		}
		p.Retire = args
	default:
		return p, ErrProgramKind
	}
	return p, nil
}

func addrIncreasing(a, b Address) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// CheckShape reports whether exactly the body named by Kind is present. It is
// unreachable for decoded programs and exists to catch programs built in code.
func (p Program) CheckShape() error {
	n := 0
	if p.Transfer != nil {
		n++
	}
	if p.Issue != nil {
		n++
	}
	if p.Mint != nil {
		n++
	}
	if p.Retire != nil {
		n++
	}
	if n != 1 {
		return ErrProgramShape
	}
	switch p.Kind {
	case ProgramTransfer:
		if p.Transfer == nil {
			return ErrProgramShape
		}
	case ProgramIssue:
		if p.Issue == nil {
			return ErrProgramShape
		}
	case ProgramMint:
		if p.Mint == nil {
			return ErrProgramShape
		}
	case ProgramRetire:
		if p.Retire == nil {
			return ErrProgramShape
		}
	default:
		return ErrProgramKind
	}
	return nil
}

// DeriveUnits is the program's parallel-gas weight: how many independent
// sub-derivations a verifier must perform.
func (p Program) DeriveUnits() uint64 {
	switch p.Kind {
	case ProgramTransfer:
		return uint64(len(p.Transfer.Moves))
	case ProgramRetire:
		return uint64(len(p.Retire.Addrs))
	default:
		return 1
	}
}
