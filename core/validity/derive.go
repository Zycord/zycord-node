package validity

import (
	"errors"
	"sort"

	"zycord/core/crypto"
	"zycord/core/types"
	"zycord/core/u256"
)

// Derivation errors. Each one is a statically detectable nonsense program —
// none of them requires state to notice.
var (
	ErrEmptyProgram   = errors.New("validity: program has no effect")
	ErrZeroAmount     = errors.New("validity: zero-amount operation")
	ErrSelfMove       = errors.New("validity: move from an address to itself")
	ErrSlotBothWays   = errors.New("validity: slot is both debited and credited")
	ErrBadSrc         = errors.New("validity: source is not a user address")
	ErrBadDst         = errors.New("validity: destination is not a user address")
	ErrBadIssuer      = errors.New("validity: issuer is not a user address")
	ErrBadAsset       = errors.New("validity: asset id is not an asset address")
	ErrZeroCap        = errors.New("validity: asset cap must be positive")
	ErrAmountOverCap  = errors.New("validity: mint amount exceeds the supply cap")
	ErrRetireNotOwned = errors.New("validity: retire target is not a one-shot address")
	ErrRetireOrder    = errors.New("validity: retire list is not sorted and deduplicated")
)

// Derive computes the canonical read and write sets a program implies.
//
// This function *is* the Era-0 instruction set. A certificate is valid only if
// its declared reads and writes equal what this returns (V3), so nothing a
// program can do exists outside this file.
//
// Canonicalisation is the point, not a detail. All debits and credits to one
// slot are merged into a single guard and a single delta before comparison
// (R1-M1): guards within one certificate are claims about a single coherent
// snapshot, and a derivation that emitted two independent guards against the
// same pre-state would let two moves each pass a check that their sum fails.
func Derive(prog types.Program, chainID, seq uint64) ([]types.Read, []types.Write, error) {
	if err := prog.CheckShape(); err != nil {
		return nil, nil, err
	}
	switch prog.Kind {
	case types.ProgramTransfer:
		return deriveTransfer(prog.Transfer)
	case types.ProgramIssue:
		return deriveIssue(prog.Issue, chainID, seq)
	case types.ProgramMint:
		return deriveMint(prog.Mint)
	case types.ProgramRetire:
		return deriveRetire(prog.Retire)
	default:
		return nil, nil, types.ErrProgramKind
	}
}

// DeriveCert computes the canonical read and write sets a *certificate*
// implies: everything Derive produces for its program, plus the MARK_SPENT
// that debiting a one-shot deposit cell requires.
//
// This — not Derive — is what V3 compares against, and it is what a wallet
// must build from. The split exists because the deposit cell is not part of
// the program: its balance debit is performed by the fold rather than by a
// write (§5, F3/F9), so Derive, which is the Era-0 instruction set and
// nothing else, cannot see it. But the *authority* over a one-shot deposit
// cell is spent all the same — the whitepaper's write-once cell has exactly
// three states and one transition out of the second, "a signature from its
// key moves it to spent, permanently" (§4), and V4 requires the deposit
// cell's own signature. So the burn is not a property of which program kind
// happens to be running, and a certificate that omits it is not a
// certificate this rule set accepts.
//
// Be exact about the scope of that, because it is a claim about *declaration*
// and not about the fold. MARK_SPENT is a declared write like any other, and
// the fold commits declared writes only on the APPLIED path (F8). A certificate
// that reaches F3, has its deposit debited, and then skips at F6 has spent
// value out of a one-shot cell without burning it — the address survives and
// can fund another certificate. That is not a hole this function opens: a
// skipped TRANSFER has never burned its one-shot move source either, for the
// same reason. It is the ordinary meaning of "all of them or none" (F7)
// applied to a debit the fold performs outside the write set, and it costs
// nothing, because the skip is billed and the certificate id is marked seen.
// What is unconditional here is what a *valid certificate declares*, which is
// what a stateless rule is able to be unconditional about.
//
// Before this existed, V6 demanded that MARK_SPENT unconditionally while
// derivation only ever produced one for a TRANSFER whose deposit cell was
// also a move source: the two rules were jointly unsatisfiable for ISSUE,
// MINT, RETIRE, and any TRANSFER paying its deposit from an address it does
// not spend (F-VAL-5).
func DeriveCert(prog types.Program, chainID, seq uint64, depositCell types.Address) ([]types.Read, []types.Write, error) {
	reads, writes, err := Derive(prog, chainID, seq)
	if err != nil {
		return nil, nil, err
	}
	return reads, withDepositMarkSpent(writes, depositCell), nil
}

// withDepositMarkSpent adds the deposit cell's MARK_SPENT to a program's
// derived write set when the cell is one-shot, unless the program already
// derived one — which happens exactly when the deposit cell is also a
// TRANSFER move source or a RETIRE target, cases derivation already covers.
func withDepositMarkSpent(writes []types.Write, deposit types.Address) []types.Write {
	if deposit[0] != crypto.AddrVersionOneShot {
		return writes
	}
	for _, w := range writes {
		if w.Op == types.OpMarkSpent && w.Slot.Addr == deposit {
			return writes
		}
	}
	out := make([]types.Write, len(writes), len(writes)+1)
	copy(out, writes)
	out = append(out, types.Write{Slot: types.SpentSlot(deposit), Op: types.OpMarkSpent})
	sortWrites(out)
	return out
}

// deriveTransfer builds the read/write set of a TRANSFER.
//
// A slot that is both debited and credited within one certificate is rejected
// rather than netted. Netting would produce a single delta whose direction no
// longer reveals that the address was debited, and debit authorisation is
// derived from the write set — so a routed transfer (A→B→C) could move B's
// balance without B's signature. Splitting the route across two certificates
// with ascending Seq expresses the same intent and orders correctly.
func deriveTransfer(args *types.TransferArgs) ([]types.Read, []types.Write, error) {
	if len(args.Moves) == 0 {
		return nil, nil, ErrEmptyProgram
	}

	debits := newSlotSums()
	credits := newSlotSums()
	oneShotDebited := make(map[types.Address]struct{})

	for _, m := range args.Moves {
		// The asset id is whitelisted first, mirroring deriveMint, which opens
		// with the same test on the same field. Until this clause existed the
		// field was validated by nothing: deriveTransfer tested the amount,
		// Src, Dst and the self-move and never looked at it,
		// types.UnmarshalMove copies 32 raw bytes, and V9 whitelists the
		// *holder* half of a balance slot while the asset half is hashed into
		// the Word — which V9 cannot meaningfully inspect, because it is a
		// hash. So an attacker-chosen 32 bytes became a consensus slot key
		// with no rule anywhere asserting it named an asset.
		//
		// Nothing was exploitable: the derived cell is empty, the GUARD_GE
		// below carries a positive operand because ErrZeroAmount forbids a
		// zero total, so the certificate skipped and was billed for it. But
		// that argument is a conjunction of clauses in two derive functions
		// plus a storage-layout fact, none of which cited the others, and it
		// is the part that expires when Era 1's VM gives a non-empty cell at
		// such a slot a meaning.
		//
		// The two admitted forms are the two an id can be. types.NativeAsset
		// is the native coin's all-zero id, which every fee, deposit and
		// coinbase already moves through. AddrVersionAsset is what
		// types.DeriveAssetAddress stamps and what deriveMint demands, so no
		// other version can ever hold a unit of anything. This does not claim
		// the asset exists — an unissued 0x03 id still derives an empty cell
		// and still skips — only that the id is one an asset could have, which
		// is the same standard V9 holds a holder to.
		if m.Asset != types.NativeAsset && m.Asset[0] != crypto.AddrVersionAsset {
			return nil, nil, ErrBadAsset
		}
		if m.Amount.IsZero() {
			return nil, nil, ErrZeroAmount
		}
		if !crypto.IsUserAddress(m.Src) {
			return nil, nil, ErrBadSrc
		}
		if !crypto.IsUserAddress(m.Dst) {
			return nil, nil, ErrBadDst
		}
		if m.Src == m.Dst {
			return nil, nil, ErrSelfMove
		}
		if err := debits.add(types.BalanceSlot(m.Src, m.Asset), m.Amount); err != nil {
			return nil, nil, err
		}
		if err := credits.add(types.BalanceSlot(m.Dst, m.Asset), m.Amount); err != nil {
			return nil, nil, err
		}
		if m.Src[0] == crypto.AddrVersionOneShot {
			oneShotDebited[m.Src] = struct{}{}
		}
	}

	for slot := range debits.sums {
		if _, ok := credits.sums[slot]; ok {
			return nil, nil, ErrSlotBothWays
		}
	}

	var reads []types.Read
	var writes []types.Write
	for _, slot := range debits.sorted() {
		total := debits.sums[slot]
		reads = append(reads, types.Read{Slot: slot, Access: types.AccessGuardGE, Operand: total})
		writes = append(writes, types.Write{Slot: slot, Op: types.OpDeltaSub, Value: total})
	}
	for _, slot := range credits.sorted() {
		writes = append(writes, types.Write{Slot: slot, Op: types.OpDeltaAdd, Value: credits.sums[slot]})
	}

	// Every debited one-shot address burns its own authority, explicitly and
	// under signature (R1-C3). The write is address-wide, so its word is zero.
	spent := make([]types.Address, 0, len(oneShotDebited))
	for a := range oneShotDebited {
		spent = append(spent, a)
	}
	sortAddrs(spent)
	for _, a := range spent {
		writes = append(writes, types.Write{Slot: types.SpentSlot(a), Op: types.OpMarkSpent})
	}

	sortReads(reads)
	sortWrites(writes)
	return reads, writes, nil
}

// deriveIssue builds the read/write set of an ISSUE.
//
// The single EXACT read of the cap cell is the write-once lock: a valid issue
// always sets a non-zero cap, so "cap reads zero" is exactly "this asset does
// not exist yet". Re-issuing under the same seq therefore skips against the
// issuer's own earlier certificate — self-inflicted, which is the only kind of
// skip Era 0 permits.
func deriveIssue(args *types.IssueArgs, chainID, seq uint64) ([]types.Read, []types.Write, error) {
	if !crypto.IsUserAddress(args.Issuer) {
		return nil, nil, ErrBadIssuer
	}
	if args.Cap.IsZero() {
		return nil, nil, ErrZeroCap
	}

	asset := types.DeriveAssetAddress(chainID, args.Issuer, seq)

	reads := []types.Read{
		{Slot: types.AssetCapSlot(asset), Access: types.AccessExact, Operand: u256.Zero},
	}
	writes := []types.Write{
		{Slot: types.AssetCapSlot(asset), Op: types.OpSet, Value: args.Cap},
		{Slot: types.AssetDecimalsSlot(asset), Op: types.OpSet, Value: u256.FromUint64(uint64(args.Decimals))},
		{Slot: types.AssetSymbolSlot(asset), Op: types.OpSet, Value: u256.FromBytes(args.SymbolHash)},
		{Slot: types.AssetMinterSlot(asset), Op: types.OpSet, Value: u256.FromBytes(args.Minter)},
	}
	sortReads(reads)
	sortWrites(writes)
	return reads, writes, nil
}

// deriveMint builds the read/write set of a MINT.
//
// The cap and minter reads are EXACT against cells that can never change, so
// they can never go stale — that is the immutable-cell authorisation pattern,
// and it is why a mint cannot be griefed by a third party. The supply bound is
// a GUARD_LE against a pre-computed remainder, so unlimited concurrent mints
// still cannot breach the cap.
func deriveMint(args *types.MintArgs) ([]types.Read, []types.Write, error) {
	if args.Asset[0] != crypto.AddrVersionAsset {
		return nil, nil, ErrBadAsset
	}
	if !crypto.IsUserAddress(args.Dst) {
		return nil, nil, ErrBadDst
	}
	if args.Amount.IsZero() {
		return nil, nil, ErrZeroAmount
	}
	if args.Cap.IsZero() {
		return nil, nil, ErrZeroCap
	}
	// Computing cap − amount in unsigned space underflows when amount > cap
	// (R1-M2). Both operands are in the certificate, so the check is stateless.
	if args.Amount.Gt(args.Cap) {
		return nil, nil, ErrAmountOverCap
	}
	remainder, _ := args.Cap.Sub(args.Amount)

	reads := []types.Read{
		{Slot: types.AssetCapSlot(args.Asset), Access: types.AccessExact, Operand: args.Cap},
		{Slot: types.AssetMinterSlot(args.Asset), Access: types.AccessExact, Operand: u256.FromBytes(args.Minter)},
		{Slot: types.AssetMintedSlot(args.Asset), Access: types.AccessGuardLE, Operand: remainder},
	}
	writes := []types.Write{
		{Slot: types.AssetMintedSlot(args.Asset), Op: types.OpDeltaAdd, Value: args.Amount},
		{Slot: types.BalanceSlot(args.Dst, args.Asset), Op: types.OpDeltaAdd, Value: args.Amount},
	}
	sortReads(reads)
	sortWrites(writes)
	return reads, writes, nil
}

// deriveRetire builds the read/write set of a RETIRE: pure state compaction,
// no value moved.
func deriveRetire(args *types.RetireArgs) ([]types.Read, []types.Write, error) {
	if len(args.Addrs) == 0 {
		return nil, nil, ErrEmptyProgram
	}
	for i, a := range args.Addrs {
		if a[0] != crypto.AddrVersionOneShot {
			return nil, nil, ErrRetireNotOwned
		}
		if i > 0 && !addrLess(args.Addrs[i-1], a) {
			return nil, nil, ErrRetireOrder
		}
	}
	writes := make([]types.Write, len(args.Addrs))
	for i, a := range args.Addrs {
		writes[i] = types.Write{Slot: types.SpentSlot(a), Op: types.OpMarkSpent}
	}
	sortWrites(writes)
	return nil, writes, nil
}

// slotSums accumulates per-slot totals with checked addition, so a program
// whose moves sum past 2^256 is rejected at derivation rather than discovered
// as an overflow skip at commit.
type slotSums struct {
	sums map[types.Slot]u256.U256
}

func newSlotSums() *slotSums {
	return &slotSums{sums: make(map[types.Slot]u256.U256)}
}

func (s *slotSums) add(slot types.Slot, v u256.U256) error {
	sum, overflow := s.sums[slot].Add(v)
	if overflow {
		return ErrAmountOverCap
	}
	s.sums[slot] = sum
	return nil
}

func (s *slotSums) sorted() []types.Slot {
	out := make([]types.Slot, 0, len(s.sums))
	for k := range s.sums {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func sortReads(r []types.Read) {
	sort.Slice(r, func(i, j int) bool { return r[i].Slot.Less(r[j].Slot) })
}

func sortWrites(w []types.Write) {
	sort.Slice(w, func(i, j int) bool { return w[i].Slot.Less(w[j].Slot) })
}

func sortAddrs(a []types.Address) {
	sort.Slice(a, func(i, j int) bool { return addrLess(a[i], a[j]) })
}

func addrLess(a, b types.Address) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
