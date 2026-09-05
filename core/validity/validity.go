// Package validity implements the stateless half of the protocol: the V-rules.
//
// Every node runs these on every certificate, in parallel, before mempool
// admission and again during block verification. They require *zero* state —
// no database, no history, no tip. That is the property the whole design rests
// on: a certificate can be checked by a thread pool, by another machine, or by
// a GPU, and a relay node needs nothing but the bytes to filter spam.
//
// A certificate that fails any V-rule is invalid. It never enters an honest
// mempool, and a block that includes one is itself invalid.
package validity

import (
	"errors"
	"fmt"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
)

// RuleError names the V-rule a certificate failed. Golden vectors record the
// rule, not the message, so error text can be improved without changing the
// protocol.
type RuleError struct {
	Rule string
	Err  error
}

func (e *RuleError) Error() string { return e.Rule + ": " + e.Err.Error() }
func (e *RuleError) Unwrap() error { return e.Err }

func fail(rule string, err error) error { return &RuleError{Rule: rule, Err: err} }

func failf(rule, format string, args ...any) error {
	return &RuleError{Rule: rule, Err: fmt.Errorf(format, args...)}
}

// Rule reports which V-rule an error came from, or "" if it is not a rule
// failure.
func Rule(err error) string {
	var re *RuleError
	if errors.As(err, &re) {
		return re.Rule
	}
	return ""
}

// Check runs the complete stateless validity predicate: V1 through V7, then
// the signature verification of V2.
//
// V8 (the TTL bound) is enforced as a block rule, because it is a statement
// about a certificate's position rather than about the certificate — see
// fold.CheckBlockRules.
func Check(c *types.Certificate, p *params.Params) error {
	if err := CheckStructural(c, p); err != nil {
		return err
	}
	return CheckSignatures(c, p)
}

// CheckStructural runs every V-rule except signature verification.
//
// It is separate because signature verification is the expensive part and
// batches across certificates: the pipeline runs structural checks first, then
// hands a batch of (key, message, signature) triples to a verifier that may be
// a thread pool today and a GPU later. Splitting the predicate here is what
// keeps that substitution out of consensus code.
//
// The individual rules are exported so that each can be tested and reasoned
// about on its own. In Era 0 the derivation rule (V3) subsumes most of what the
// others would catch, because only four programs exist and each pins its write
// set exactly. That will stop being true at H1_VM, when the cEVM runs over the
// declared reads and a program's write set is whatever its code produced (§7's
// V3 bullet, §17) — so the rules that look redundant today are the ones that
// will do the work then.
//
// This paragraph used to end "and they are tested directly", which was false
// and is the reason the counting test below exists: V6 carried seven
// rejection terms and three separating inputs, and a mutation deleting a
// whole case block from CheckSelfConsistency survived core/validity,
// core/fold, spec and sim. A comment naming the wrong reason is how a safety
// property stays invisible, so the claim is now made by a test that counts:
// TestEveryRejectionTermIsSeparated reads the rejection sites of the enrolled
// rules out of this package's own source and requires one input per site,
// recording for each whether Check can reach it in Era 0 or only the rule's
// own function can.
func CheckStructural(c *types.Certificate, p *params.Params) error {
	if err := CheckCanonical(c, p); err != nil {
		return err
	}
	if err := CheckDerivation(c); err != nil {
		return err
	}
	if err := CheckSelfConsistency(c); err != nil {
		return err
	}
	if err := CheckProtocolExclusion(c); err != nil {
		return err
	}
	if err := CheckAuthorization(c); err != nil {
		return err
	}
	if err := CheckDeposit(c, p); err != nil {
		return err
	}
	return CheckAddressVersions(c)
}

// CheckSignatures is V2: every signature verifies over the certificate's
// signing message, under the strict Ed25519 rules that make batch and single
// verification agree.
//
// It takes the parameter set because the signing message binds the consensus
// root as well as the chain id, which is what makes a certificate of a
// network's previous incarnation fail *this* rule on the current one rather
// than pass every rule and be billed. The rule stays stateless: the root is a
// digest over the parameter values the caller already holds, not a lookup
// against a chain.
//
// The root is computed once per certificate rather than once per signature,
// which is what keeps the added cost a small fraction of one strict Ed25519
// verification even on a single-signer certificate. No figure is written here
// on purpose — node/verify's BenchmarkSignatureVerify is the denominator and a
// number copied out of it into a comment is a number nothing rechecks.
// node/verify's TestConsensusRootStaysCheapRelativeToOneSignature measures
// both halves in one run and holds the quotient to a budget, so the ratio is a
// measurement rather than a memory.
//
// Do not memoise the root to make this line cheaper. The reflective walk is
// per certificate and it looks like free money, but a cached field has to be
// populated by somebody and the failure mode of forgetting is silent: a
// params.Params built by struct literal would carry a zero root, every node
// that forgot would agree with every other node that forgot, and all of them
// would fork away from everyone who did not — with no error raised anywhere,
// on the rule whose whole job is to make parameter divergence loud. Any
// memoisation here has to make "not yet computed" impossible to observe, not
// merely unlikely, and the benchmark above is what says whether it is worth
// attempting at all.
func CheckSignatures(c *types.Certificate, p *params.Params) error {
	msg := c.SigningMessage(p)
	for i := range c.Sigs {
		if !crypto.VerifyStrict(c.Sigs[i].PubKey, msg, c.Sigs[i].Sig) {
			return failf("V2", "signature %d does not verify", i)
		}
	}
	return nil
}

// CheckCanonical is V1: canonical form, ordering, limits, and chain binding.
//
// Decoding already rejects non-canonical bytes; this repeats the checks so
// that certificates built in memory — by a wallet, a test, or a fuzzer — are
// held to the identical standard.
func CheckCanonical(c *types.Certificate, p *params.Params) error {
	if c.ChainID != p.ChainID {
		return failf("V1", "chain id %d is not this network's %d", c.ChainID, p.ChainID)
	}
	if err := c.Program.CheckShape(); err != nil {
		return fail("V1", err)
	}
	// The program's OWN lists, which nothing above this line bounds. Reads,
	// writes and signatures are bounded below, but max_moves_per_transfer and
	// max_retire_addrs were enforced only by types.UnmarshalProgram, and the
	// derived write set is not a proxy for either: on devnet a TRANSFER of 33
	// moves out of a single source derives 1 read and 34 writes, inside
	// max_writes = 64, so it passed every V-rule and then failed to decode.
	//
	// Placed before the read/write/signature limits on purpose. On all three
	// shipped networks max_retire_addrs and max_writes are both 64, so an
	// over-long RETIRE also exceeds max_writes; running the specific bound
	// first is what makes the refusal name the list the operator got wrong.
	//
	// CheckShape is left params-free deliberately. It is also called from
	// Derive, which is the Era-0 instruction set and takes no parameter set;
	// making it params-aware would push *p through the derivation to enforce a
	// bound the derivation does not use. The bound belongs where the other
	// length limits already are, in the rule that has p in hand.
	//
	// This moves nothing the network accepts. The expression's inputs are
	// len(c.Program.Transfer.Moves) / len(c.Program.Retire.Addrs) and the two
	// fields of p, and every path that reaches a fold fixes all of them
	// together: node/p2p peer ingress, node/rpc submission and
	// types.UnmarshalBlock all call types.UnmarshalCertificate(raw, p) with
	// the same p this rule is then run under, and that call passes exactly
	// these two fields to UnmarshalProgram. So on a decoded certificate the
	// comparison is against a length the decoder has already refused to
	// exceed, and it can only fire on the population CheckCanonical says at
	// the top of this function that it exists for: a certificate built in
	// memory. wallet.Builder.Build is in that population and already
	// round-trips through UnmarshalCertificate, so it cannot reach it either.
	switch c.Program.Kind {
	case types.ProgramTransfer:
		if n := len(c.Program.Transfer.Moves); n > p.MaxMovesPerTransfer {
			return failf("V1", "%d moves exceeds the limit of %d", n, p.MaxMovesPerTransfer)
		}
	case types.ProgramRetire:
		if n := len(c.Program.Retire.Addrs); n > p.MaxRetireAddrs {
			return failf("V1", "%d retire targets exceeds the limit of %d", n, p.MaxRetireAddrs)
		}
	}
	if len(c.Reads) > p.MaxReads {
		return failf("V1", "%d reads exceeds the limit of %d", len(c.Reads), p.MaxReads)
	}
	if len(c.Writes) > p.MaxWrites {
		return failf("V1", "%d writes exceeds the limit of %d", len(c.Writes), p.MaxWrites)
	}
	if len(c.Sigs) > p.MaxSigs {
		return failf("V1", "%d signatures exceeds the limit of %d", len(c.Sigs), p.MaxSigs)
	}
	if len(c.Sigs) == 0 {
		return failf("V1", "certificate carries no signatures")
	}
	for i := 1; i < len(c.Reads); i++ {
		if c.Reads[i-1].Slot.Compare(c.Reads[i].Slot) >= 0 {
			return failf("V1", "reads are not strictly sorted by slot at index %d", i)
		}
	}
	for i := 1; i < len(c.Writes); i++ {
		if c.Writes[i-1].Slot.Compare(c.Writes[i].Slot) >= 0 {
			return failf("V1", "writes are not strictly sorted by slot at index %d", i)
		}
	}
	for i := 1; i < len(c.Sigs); i++ {
		if !pubKeyLess(c.Sigs[i-1].PubKey, c.Sigs[i].PubKey) {
			return failf("V1", "signatures are not strictly sorted by public key at index %d", i)
		}
	}
	// A priority above its own maximum is not a canonical fee bid: the offer
	// is "at most Max, of which Priority is the tip", and settlement clamps
	// the tip to the headroom Max leaves, so a priority above the maximum
	// names a quantity the settlement arithmetic cannot express (types.FeeBid,
	// "Canonical form requires priority <= maximum in each market").
	//
	// UnmarshalFeeBid already refuses it, which is why this moves nothing the
	// network accepts: every certificate that reaches a fold arrives through
	// UnmarshalCertificate. What that leaves uncovered is exactly the case
	// this function exists for, stated at the top of it — a certificate built
	// in memory by a wallet, a test or a fuzzer, which no decoder has seen.
	// Without the repeat, a wallet could build and locally validate bytes no
	// peer can decode.
	if c.FeeBid.SeqPriority.Gt(c.FeeBid.SeqMax) {
		return failf("V1", "sequential priority %s exceeds the maximum of %s",
			c.FeeBid.SeqPriority.String(), c.FeeBid.SeqMax.String())
	}
	if c.FeeBid.ParPriority.Gt(c.FeeBid.ParMax) {
		return failf("V1", "parallel priority %s exceeds the maximum of %s",
			c.FeeBid.ParPriority.String(), c.FeeBid.ParMax.String())
	}
	return nil
}

// CheckDerivation is V3: the declared reads and writes must equal what the
// certificate derives — its program's read/write set, plus the MARK_SPENT
// that debiting a one-shot deposit cell requires (DeriveCert). This is what
// makes a certificate *self*-certifying — the declaration is not a hint, it
// is the whole computation.
//
// The rule compares against DeriveCert rather than Derive so that exactly one
// function in the tree defines what a certificate's writes are, and a wallet
// building from it cannot disagree with the rule checking it (F-VAL-5).
func CheckDerivation(c *types.Certificate) error {
	reads, writes, err := DeriveCert(c.Program, c.ChainID, c.Seq, c.Deposit.Cell.Addr)
	if err != nil {
		return fail("V3", err)
	}
	if len(reads) != len(c.Reads) {
		return failf("V3", "declared %d reads, program derives %d", len(c.Reads), len(reads))
	}
	for i := range reads {
		if reads[i] != c.Reads[i] {
			return failf("V3", "declared read %d does not match the derived read", i)
		}
	}
	if len(writes) != len(c.Writes) {
		return failf("V3", "declared %d writes, program derives %d", len(c.Writes), len(writes))
	}
	for i := range writes {
		if writes[i] != c.Writes[i] {
			return failf("V3", "declared write %d does not match the derived write", i)
		}
	}
	return nil
}

// CheckSelfConsistency is V6: a certificate must not contradict itself, a
// one-shot address that is debited must burn itself in the same certificate,
// and nothing may be credited to an address the certificate burns.
//
// The debit-coverage rule generalises R1-M1's lesson: every subtraction must be
// bounded from below by a read on the same slot. Derivation already guarantees
// it for the Era-0 op set; stating it as a rule means the guarantee survives
// the op set changing.
//
// Which era reaches the four delta terms, stated here because the alternative
// was to delete them. Four of this rule's seven rejection terms — the
// three inside the OpDeltaSub case and the OpDeltaAdd overflow — cannot be
// reached through Check by any Era-0 certificate, and they are kept rather than
// deleted because §7 states them and Phase 1 reaches them:
//
//   - Era-0 derivation emits, for every DELTA_SUB it produces, a GUARD_GE read
//     on the same slot whose operand *equals* the subtracted total
//     (deriveTransfer), and V3 runs before this rule and demands exact equality
//     with what it derives. So "no read to bound it" has no certificate, "the
//     read bound is exceeded" has none because operand == value, and "bounded
//     only from above" has none because the access is never anything but
//     GUARD_GE.
//   - The only DELTA_ADD Era 0 derives against a read of its own slot is MINT's
//     credit to the minted cell, whose GUARD_LE operand is cap − amount
//     (deriveMint), so operand + value is cap and cannot overflow.
//
// The four are not equally well anchored, and pretending otherwise would be the
// same defect this comment replaces. §7's V6 bullet states the three DELTA_SUB
// terms word for word — the read must be EXACT, GUARD_GE or GUARD_EQ, "never
// GUARD_LE alone, which bounds only from above and cannot license a
// subtraction", and "whose operand the subtracted amount does not exceed". The
// overflow term is covered only by the same bullet's terse "delta magnitudes
// fit", which does not say against what or by whose reckoning. So the first
// three cannot be deleted without editing §7; the fourth rests on a weaker
// citation and on the R1-M1 generalisation above, and whoever revisits it should
// start by making §7 say what it means.
//
// The era that reaches them is **Phase 1 at H1_VM** (§17), where the cEVM runs
// over the declared reads and the write set stops being one of four fixed
// shapes — which is what §7's own V3 bullet says derivation becomes. Until
// then each of the four is separated by asking this function directly, and
// core/validity's TestEveryRejectionTermIsSeparated records, per term, that
// Check answers V3 instead: if any of them ever becomes reachable through the
// whole predicate, that recorded answer moves and the test says so.
func CheckSelfConsistency(c *types.Certificate) error {
	byslot := make(map[types.Slot]types.Read, len(c.Reads))
	for _, r := range c.Reads {
		byslot[r.Slot] = r
	}

	spentHere := make(map[types.Address]struct{})
	for _, w := range c.Writes {
		if w.Op == types.OpMarkSpent {
			if !crypto.IsUserAddress(w.Slot.Addr) {
				return failf("V6", "MARK_SPENT targets a non-user address")
			}
			spentHere[w.Slot.Addr] = struct{}{}
		}
	}

	for _, w := range c.Writes {
		r, hasRead := byslot[w.Slot]
		switch w.Op {
		case types.OpDeltaSub:
			if !hasRead {
				return failf("V6", "DELTA_SUB on a slot with no read to bound it")
			}
			switch r.Access {
			case types.AccessExact, types.AccessGuardGE, types.AccessGuardEQ:
				if w.Value.Gt(r.Operand) {
					return failf("V6", "DELTA_SUB of %s exceeds the read bound of %s",
						w.Value.String(), r.Operand.String())
				}
			default:
				return failf("V6", "DELTA_SUB bounded only from above")
			}
		case types.OpDeltaAdd:
			if hasRead && (r.Access == types.AccessExact || r.Access == types.AccessGuardEQ ||
				r.Access == types.AccessGuardLE) {
				if _, overflow := r.Operand.Add(w.Value); overflow {
					return failf("V6", "DELTA_ADD provably overflows against its read bound")
				}
			}
		}
	}

	// Any address this certificate debits must be burned here if it is
	// one-shot — including the deposit cell, whose debit is performed by the
	// fold rather than by a write (R1-C3).
	debited := make(map[types.Address]struct{})
	for _, w := range c.Writes {
		if w.Op == types.OpDeltaSub || w.Op == types.OpSet {
			debited[w.Slot.Addr] = struct{}{}
		}
	}
	debited[c.Deposit.Cell.Addr] = struct{}{}
	for a := range debited {
		if a[0] != crypto.AddrVersionOneShot {
			continue
		}
		if _, ok := spentHere[a]; !ok {
			return failf("V6", "one-shot address is debited without an explicit MARK_SPENT")
		}
	}

	// And nothing may be credited to an address this same certificate burns.
	// F8 commits the MARK_SPENTs and the value writes together, so the credit
	// lands in a cell whose authority is already gone by the time anyone could
	// spend it: value destroyed, reported as an ordinary APPLIED certificate.
	// It is the write-side twin of V5's refund clause (F-FOLD-1), and it
	// is reachable the moment a certificate names one address in two roles —
	// a TRANSFER crediting a second asset to a one-shot source it sweeps, or a
	// MINT whose destination is also its one-shot deposit cell.
	//
	// A certificate that means to destroy value has no need of this shape, and
	// Era 0 offers no burn operation to confuse it with.
	//
	// The rule is stated as "every write that is not the burn itself or a
	// debit", rather than as "every DELTA_ADD", on purpose. DELTA_ADD is the
	// only op that can credit a burned address in Era 0 — SET reaches only an
	// asset's immutable cells (0x03), which can never be marked spent — so the
	// wider form costs nothing today. It is written for the day it stops being
	// free: this rule exists to hold the line when write sets stop being the
	// output of four fixed shapes, and a version of it enumerating the ops of
	// Era 0 would have to be re-audited by whoever adds the fifth. A SET that
	// stored a value under an address the same certificate burns is the same
	// loss as a credit, and it should not need a second finding to say so.
	for _, w := range c.Writes {
		if w.Op == types.OpMarkSpent || w.Op == types.OpDeltaSub {
			continue
		}
		if _, ok := spentHere[w.Slot.Addr]; ok {
			return failf("V6", "writes value to an address this certificate marks spent")
		}
	}
	return nil
}

// CheckProtocolExclusion is V7: ordinary certificates never write protocol
// cells, and never express a billing operation. Billing is something the fold
// does, not something a certificate can ask for.
func CheckProtocolExclusion(c *types.Certificate) error {
	for _, w := range c.Writes {
		if w.Slot.Addr[0] == crypto.AddrVersionProtocol {
			return failf("V7", "certificate writes a protocol cell")
		}
	}
	return nil
}

// CheckAuthorization is V4: every write that needs a signature has one, and
// every signature is needed.
//
// Minimality matters as much as sufficiency, and since signatures left the
// id's preimage it matters for a different reason than it used to. It used to
// be that a signature authorising nothing gave one transition two ids; the
// id's preimage now excludes the signatures, so both forms have the same id.
// What minimality buys instead is that the id is *sufficient*: sufficiency
// and minimality together make the legal signer set a pure function of the
// body, so two valid certificates sharing an id carry the same signer list —
// hence the same signature count, the same encoded length, the same parallel
// gas and the same fee ceiling. One id, one authorization, one cost. Without
// it a proposer could choose a fatter exemplar of an authorization and bill
// its signer for gas nobody agreed to.
// TestTheIdPinsTheSignerSetAndThereforeTheCost pins it.
func CheckAuthorization(c *types.Certificate) error {
	requiredAddrs := make(map[types.Address]struct{})
	requiredKeys := make(map[types.PubKey]struct{})

	// The deposit is a debit, so its owner signs (see also V5).
	//
	// Unconditional now, and the lost `if crypto.IsUserAddress(…)` is
	// the whole change. While it stood, V5's IsUserAddress narrowing on this
	// same field (CheckDeposit below) was the *only* predicate anywhere in the
	// stateless set between an unsigned certificate and types.TreasurySlot,
	// which is NativeBalanceSlot(ProtocolAddress) — an ordinary native balance
	// cell, not a distinguished object. Everything that would normally back
	// such a seal declines for its own good reason: F3 debits Deposit.Cell
	// directly rather than through a declared write, so V7's and F13's 0x00
	// write ban never sees it; V6 demands a MARK_SPENT only for 0x01; V9
	// admits 0x00; and IsNativeBalanceSlot tests the slot's word, not its
	// version. A guard whose own comment names the refactor that would open it
	// needs a second predicate, not a second test.
	//
	// Be exact about what this buys, because it is not uniform across the
	// versions V5 refuses, and pretending otherwise would be the same defect.
	// crypto.ProtocolAddress is 0x00 followed by 31 zero bytes and is
	// deliberately not a hash, while AddressFromPubKey(0x00, pub) is 0x00
	// followed by 31 bytes of blake3 — so no key satisfies a requirement
	// naming it, and the treasury cell is now refused by two rules that share
	// no call. A 0x03 deposit cell is weaker: an attacker holds
	// AddressFromPubKey(0x03, pub) like any other derived address and can
	// satisfy this clause, so for asset addresses V5's narrowing remains the
	// only gate. The seal this deepens is the treasury's, which is the one
	// this change is about.
	//
	// V4 runs before V5 in CheckStructural, so Check now answers V4 rather
	// than V5 on a certificate depositing from a non-user cell. Both rules
	// still refuse it on their own, which is the property; the recorded
	// answer moves, and core/validity's separating-input table records it.
	requiredAddrs[c.Deposit.Cell.Addr] = struct{}{}

	for _, w := range c.Writes {
		switch w.Op {
		case types.OpSet, types.OpDeltaSub, types.OpMarkSpent:
			if crypto.IsUserAddress(w.Slot.Addr) {
				requiredAddrs[w.Slot.Addr] = struct{}{}
			}
		}
	}

	switch c.Program.Kind {
	case types.ProgramIssue:
		// The asset address is derived from (chain id, issuer, seq); the
		// issuer's signature is what binds the derivation to a key.
		requiredAddrs[c.Program.Issue.Issuer] = struct{}{}
	case types.ProgramMint:
		// Immutable-cell authorisation: the certificate declares the minter as
		// an EXACT read, and a signature by that exact key must be present.
		// The fold's exact-match check then guarantees the declared minter is
		// the real one.
		requiredKeys[c.Program.Mint.Minter] = struct{}{}
	}

	satisfiedAddrs := make(map[types.Address]struct{}, len(requiredAddrs))
	used := make([]bool, len(c.Sigs))

	for i, s := range c.Sigs {
		if _, ok := requiredKeys[s.PubKey]; ok {
			used[i] = true
		}
		for a := range requiredAddrs {
			if crypto.AddressFromPubKey(a[0], s.PubKey) == a {
				satisfiedAddrs[a] = struct{}{}
				used[i] = true
			}
		}
	}

	if len(satisfiedAddrs) != len(requiredAddrs) {
		return failf("V4", "a write or debit is not authorised by any signature")
	}
	for k := range requiredKeys {
		found := false
		for _, s := range c.Sigs {
			if s.PubKey == k {
				found = true
				break
			}
		}
		if !found {
			return failf("V4", "a privileged operation is missing its authorising key")
		}
	}
	for i := range used {
		if !used[i] {
			return failf("V4", "signature %d authorises nothing", i)
		}
	}
	return nil
}

// CheckDeposit is V5: the deposit must be a native-coin cell the signer can
// debit, must refund somewhere that survives this certificate, and must cover
// the certificate's fee ceiling.
func CheckDeposit(c *types.Certificate, p *params.Params) error {
	d := c.Deposit
	if !types.IsNativeBalanceSlot(d.Cell) {
		return failf("V5", "deposit cell is not a native-coin balance cell")
	}
	// IsUserAddress, not IsKnownAddressVersion, and the difference is the whole
	// rule. This clause is the narrowing that refuses a deposit cell at
	// 0x00 — the protocol address, which is where the treasury accrues
	// (types.TreasurySlot) — or at 0x03. IsNativeBalanceSlot above tests the
	// slot's *word*, not its version byte; V7 guards writes, and the deposit
	// debit is performed by the fold at F3 rather than by a declared write; V6
	// demands a MARK_SPENT only for 0x01; and V9 admits both versions.
	//
	// It is no longer the *only* one. V4 above now requires an authorising
	// signature for any deposit cell rather than only for a user address, and
	// no key hashes to crypto.ProtocolAddress, so widening this one call —
	// the edit a refactor unifying two nearby version tests would make — no
	// longer moves Check from V5 to *accepted* on a re-signed certificate
	// depositing from the treasury cell. It moves it to V4. Read the two
	// together: this clause is what refuses 0x03, where a key-derived address
	// does satisfy V4, and V4 is what refuses 0x00 if this clause is ever
	// lost. Pinned by TestV5NarrowsTheDepositToUserAddresses, which asserts
	// each rule refuses on its own rather than asserting which one answers
	// first.
	if !crypto.IsUserAddress(d.Cell.Addr) {
		return failf("V5", "deposit cell is not owned by a user address")
	}
	if !types.IsNativeBalanceSlot(d.RefundTo) {
		return failf("V5", "refund slot is not a native-coin balance cell")
	}
	if !crypto.IsUserAddress(d.RefundTo.Addr) {
		return failf("V5", "refund slot is not owned by a user address")
	}
	// The refund must not target any address this certificate itself marks
	// spent (R1-C3-i, generalised by F-FOLD-1). F8 commits a certificate's
	// own MARK_SPENT writes before F9's settle runs, so a refund landing on
	// an address this same certificate burns would strand the remainder in a
	// cell nobody can ever read — settle can only see that the address is
	// *already* spent by the time it runs, not that this very certificate is
	// the one that spent it, so the fold cannot tell that case apart from
	// I1-M2's (an address burned by some earlier certificate, which settle is
	// right to burn into). The check has to happen here, statelessly, before
	// the certificate is ever considered valid.
	//
	// The original clause — RefundTo naming a one-shot deposit cell — is kept
	// beside the general one rather than folded into it. V3 does make it
	// redundant today (a one-shot deposit cell's own MARK_SPENT is always in
	// c.Writes, so the loop below would catch it), but that is a fact about
	// another rule in another file: V5 reads c.Writes as *declared*, and a
	// rule guarding against silent value loss should not depend on a second
	// rule having run first to be correct.
	if d.Cell.Addr[0] == crypto.AddrVersionOneShot && d.RefundTo.Addr == d.Cell.Addr {
		return failf("V5", "refund targets the one-shot address the deposit burns")
	}
	for _, w := range c.Writes {
		if w.Op == types.OpMarkSpent && w.Slot.Addr == d.RefundTo.Addr {
			return failf("V5", "refund targets an address this certificate marks spent")
		}
	}

	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		return failf("V5", "fee ceiling overflows 256 bits")
	}
	if d.Amount.Lt(ceiling) {
		return failf("V5", "deposit of %s does not cover the fee ceiling of %s",
			d.Amount.String(), ceiling.String())
	}
	// And bounded from above, by every coin the schedule can have paid by the
	// last height at which this certificate may be committed.
	//
	// The rule stays stateless. `params.CumulativeEmission` is a pure function
	// of a height and the four issuance constants of §14.2 — no supply cell,
	// no tip, no chain — and the height it is asked about comes out of the
	// certificate itself. c.TTL is the last height B1 admits this certificate
	// at, and the schedule is non-decreasing, so cumulative emission at the
	// TTL is the supremum of the coin supply over every height at which this
	// certificate can still be committed. Bounding against the TTL is
	// therefore the loosest bound that is sound for a *stateless* rule, and
	// the looseness is deliberate: a tighter one would need the inclusion
	// height, which is exactly the state V-rules may not read.
	//
	// **This is not the fix for drop-stuffing, and the tree should not be read
	// as claiming it is.** The stuffing primitive is that a deterministic DROP
	// costs its producer nothing, and it works identically with `Amount = 1`
	// from an unfunded fresh key — the declared amount is not what makes it
	// cheap. What bounds the receiver-side harm is B18, the per-block
	// signature ceiling. This clause is here because a consensus-valid
	// object declaring a deposit larger than every coin that can exist at that
	// height is an absurdity the cheap stateless gate should refuse, and
	// because closing the far end of the class costs nothing while the fold is
	// still allowed to move. §10 of docs/ARCHITECTURE.md states both halves.
	//
	// CumulativeEmission saturates upward, so an arithmetic edge widens the
	// bound rather than refusing something legal.
	if supply := p.CumulativeEmission(c.TTL); d.Amount.Gt(supply) {
		return failf("V5", "deposit of %s exceeds the %s the schedule can have issued by height %d",
			d.Amount.String(), supply.String(), c.TTL)
	}
	return nil
}

// CheckAddressVersions is V9: every address a certificate names — by a read,
// a write, the deposit cell, or the refund target — must carry a version
// byte this release defines (crypto.KnownAddressVersion).
//
// It is defense in depth, not new coverage: the closed Era-0 program set
// (§9) already never derives an address of any other kind, so V3 rejects
// today's only route to one. What V3 does not close is a certificate built
// by hand rather than derived — nothing upstream of this rule inspects a
// declared address's version byte in isolation. That gap is exactly the
// surface Era S's hidden-value cells (0x04, reserved — architecture spec §6)
// would arrive on: a guarded delta aimed at an unknown-version slot is not
// caught by anything else here, and V4's CheckAuthorization in particular
// treats crypto.IsUserAddress as a condition for requiring a signature, not
// as a whitelist, so an unknown version needs no signature at all under V4
// alone. This rule is the whitelist V4 does not provide.
func CheckAddressVersions(c *types.Certificate) error {
	for i, r := range c.Reads {
		if !crypto.IsKnownAddressVersion(r.Slot.Addr) {
			return failf("V9", "read %d names an unknown address version", i)
		}
	}
	for i, w := range c.Writes {
		if !crypto.IsKnownAddressVersion(w.Slot.Addr) {
			return failf("V9", "write %d names an unknown address version", i)
		}
	}
	if !crypto.IsKnownAddressVersion(c.Deposit.Cell.Addr) {
		return failf("V9", "deposit cell names an unknown address version")
	}
	if !crypto.IsKnownAddressVersion(c.Deposit.RefundTo.Addr) {
		return failf("V9", "refund target names an unknown address version")
	}
	return nil
}

func pubKeyLess(a, b types.PubKey) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// MaxDeltaHeadroom is exported for wallets that want to check, before signing,
// that a credit cannot provably overflow. It mirrors the V6 arithmetic.
func MaxDeltaHeadroom(bound u256.U256) u256.U256 { return u256.Max.SatSub(bound) }
