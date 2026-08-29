package fold_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// The per-certificate byte budget of a block, and what it is for.
//
// MaxCertsPerBlock(T) = max_certs_per_block_genesis × T/T₀ and
// BlockByteLimit(T) = block_byte_limit_genesis × T/T₀ scale together, so
// their ratio is a design decision frozen at genesis. The calibration
// question is whether the ratio mainnet ships is the intended one, on the
// reading that 4000 certificates is "reachable only by an all-RETIRE block".
// The answer is yes, intended, and the framing is off in three ways. Every
// number is a measurement of the encoding and the parameter set, because a
// measurement nothing re-runs is a number that drifts.
//
//  1. The budget is not block_byte_limit_genesis ÷ max_certs_per_block_genesis.
//     A block carries 236 bytes of its own, and ssz.EncodeVariableList spends
//     four offset bytes per element out of the same ceiling. At mainnet
//     genesis the budget is (2,500,000 − 236)/4000 − 4 = 620.9 bytes of
//     certificate *body*, not 625.
//  2. The count ceiling is not inert. Over the whole Era-0 shape space it is
//     the first ceiling to bind for exactly the shapes at the encoding floor
//     and for nothing else — the minimum-size flood, which is the one case
//     bytes are cheap for.
//  3. Reaching 4000 does not require an all-RETIRE block: the slack pays for
//     868 ordinary one-move transfers beside 3,132 minimum retires.
//
// **Two bounds, and they are not the same bound.** core/fold/blockrules.go
// rejects a block whose sequential gas exceeds SeqGasBurst(T) = 4T, and says
// so in as many words: "A block between 2T and 4T is valid; F11 forfeits the
// producer's block revenue against it quadratically." So 4T is the
// block-validity ceiling and 2T is a *soft* threshold — the fee market's
// target ceiling, priced by revenue forfeiture rather than enforced by
// rejection. The
// classification below is stated under 4T, because that is the bound that
// rejects a block, and the 2T classification is reported separately as what
// it is: an economic bound a revenue-maximising producer keeps under, not a
// rule. Under 4T the rejecting ceilings split the shape space into three
// classes — 2 count-bound, 38 gas-bound, 58 byte-bound — and the gas class
// exists only because T₀ was lowered to 1,600,000: at the superseded
// 2,000,000, 4T required 3.2 sequential gas per block byte against a densest
// achievable 2.8937 and the class was empty. None of that widens the count
// rule's job, which is still the floor and only the floor: without it the
// flood bound would be 4447 by bytes and 8,000 by 4T gas instead of 4000.
//
// The rule these numbers describe is enforced and pinned elsewhere —
// TestCertCountCeilingRejects in elastic_ceiling_test.go, and golden vectors
// 030/041. What is missing without this file is the *calibration*: that the
// shipped value sits inside the band [2933, 4447] at T₀ and is not merely
// reachable but actually fires at every T, and that a parameter change which
// pushes it out fails loudly instead of silently converting the count rule
// into an inert rule or a cut in payment capacity.

// budgetKey returns a deterministic key. domain separates the families a
// scenario needs so that two shapes can never collide on one address, and n
// indexes within a family — the byte-sized key() helper in fold_test.go
// cannot reach the thousands of distinct one-shot addresses a full block of
// retires needs.
func budgetKey(t *testing.T, domain byte, n uint64) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	seed[0] = domain
	binary.BigEndian.PutUint64(seed[24:], n)
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// buildCert runs the wallet's own builder, which derives the read/write set
// exactly as V3 re-derives it and refuses to emit a certificate the V-rules
// would reject. Every size below is therefore the size of a certificate the
// network would accept, not of a struct a test assembled.
func buildCert(t *testing.T, p *params.Params, prog types.Program, dep types.Deposit, signers ...*wallet.Key) *types.Certificate {
	t.Helper()
	c, err := tryCert(p, prog, dep, signers...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func tryCert(p *params.Params, prog types.Program, dep types.Deposit, signers ...*wallet.Key) (*types.Certificate, error) {
	b := &wallet.Builder{
		Params:  p,
		Program: prog,
		Seq:     0,
		TTL:     100,
		Deposit: dep,
		FeeBid:  bid(),
		Signers: signers,
	}
	return b.Build()
}

// minimumRetire builds a certificate at the Era-0 encoding floor: a RETIRE of
// one one-shot address, whose deposit cell is that same address, so the
// program's own MARK_SPENT is the only write and one signature authorises
// both roles.
func minimumRetire(t *testing.T, p *params.Params, n uint64) *types.Certificate {
	t.Helper()
	k := budgetKey(t, 0xa0, n)
	refund := budgetKey(t, 0xaf, 0).Persistent()
	return buildCert(t, p, wallet.Retire(k.OneShot()),
		wallet.SweepDeposit(k.OneShot(), refund, drops(1_000_000)), k)
}

// oneMoveTransfer builds the ordinary payment shape: one move between two
// persistent addresses, the deposit paid from the source.
func oneMoveTransfer(t *testing.T, p *params.Params, n uint64) *types.Certificate {
	t.Helper()
	k := budgetKey(t, 0xb0, n)
	to := budgetKey(t, 0xbf, 0).Persistent()
	return buildCert(t, p, wallet.Tip(types.NativeAsset, k.Persistent(), to, drops(1_000)),
		wallet.SelfDeposit(k.Persistent(), k.Persistent()), k)
}

// era0Shape is one shape the Era-0 program set can express, with a real signed
// instance of it to measure.
type era0Shape struct {
	name string
	cert *types.Certificate
}

// era0ShapeSpace enumerates the Era-0 shape space rather than a hand-picked
// list of it.
//
// The distinction cost this file a wrong claim once already. The four program
// *kinds* are closed (whitepaper §11), but a shape is not a kind: it ranges
// over move count, retire width, the address version of each source, and the
// deposit arrangement — and those choices move the read, write and signature
// counts independently of the kind. A hand-picked list of eight shapes
// supported a three-way partition that a systematic sweep falsifies, because
// a one-address RETIRE paying its deposit from a *separate* one-shot cell is
// 751 B and 1500 sequential gas, sits between the floor and the widest RETIRE
// by size, and is bound by neither of the ceilings its neighbours are.
//
// So the sweep varies the dimensions below. It is a sweep and not a
// census, and the difference is worth stating precisely, because the round-1
// lesson was exactly that a shape list smaller than it claimed produced a
// false characterisation. What it does NOT vary: source address version is
// all-or-nothing rather than per-source; only RETIRE gets a deposit-arrangement
// dimension, since TRANSFER always pays from its first source and ISSUE/MINT
// only from the same key's own cells; destinations are always distinct, so
// there is no merged-credit family; and there is no fan-out family (one source,
// many destinations). Those omissions are known to produce shapes with encoded
// sizes and gas costs this sweep never produces, and the classification is
// therefore a claim about a large, deliberately varied sample rather than about
// every certificate the rules admit. Every conclusion here has been checked to
// survive on a 140-shape superset that adds them. How large that sample is,
// measured against the widest certificate the rules admit at all, is asserted
// as a floor in TestTheEra0SweepKeepsItsShareOfTheDerivedWidthCeiling, so that
// an edit which drops a further dimension narrows the sweep loudly.
//
//	RETIRE    width 1..max_sigs × {deposit swept from a retired address,
//	          the persistent twin of a retired key, a fresh persistent cell,
//	          a fresh one-shot cell}
//	TRANSFER  1..max_moves_per_transfer moves × {persistent, one-shot} sources
//	ISSUE     × {persistent, one-shot} deposit cell
//	MINT      × {persistent, one-shot} deposit cell
//
// Combinations the V-rules refuse (a width that would need more than max_sigs
// signatures, for instance) are skipped rather than asserted, because the
// point of the sweep is what the rules *admit*.
func era0ShapeSpace(t *testing.T, p *params.Params) []era0Shape {
	t.Helper()
	var out []era0Shape
	refund := budgetKey(t, 0xff, 0).Persistent()
	add := func(name string, c *types.Certificate, err error) {
		if err == nil {
			out = append(out, era0Shape{name, c})
		}
	}

	for n := 1; n <= p.MaxSigs; n++ {
		addrs := make([]types.Address, 0, n)
		keys := make([]*wallet.Key, 0, n)
		for i := 0; i < n; i++ {
			k := budgetKey(t, 0x10, uint64(i))
			addrs = append(addrs, k.OneShot())
			keys = append(keys, k)
		}
		prog := wallet.Retire(addrs...)

		c, err := tryCert(p, prog, wallet.SweepDeposit(prog.Retire.Addrs[0], refund, drops(1_000_000)), keys...)
		add(fmt.Sprintf("RETIRE width=%d deposit=swept-from-a-retired-address", n), c, err)

		// The deposit cell is the *persistent twin* of a retired key. It is
		// not one-shot, so no extra MARK_SPENT is derived, and V4 is satisfied
		// for both addresses by the one signature that key already provides —
		// a second shape at the encoding floor, and the reason "the floor is
		// one shape" would be wrong.
		c, err = tryCert(p, prog, wallet.SelfDeposit(keys[0].Persistent(), keys[0].Persistent()), keys...)
		add(fmt.Sprintf("RETIRE width=%d deposit=persistent-twin-of-a-retired-key", n), c, err)

		if n < p.MaxSigs {
			fresh := budgetKey(t, 0x11, 0)
			c, err = tryCert(p, prog, wallet.SelfDeposit(fresh.Persistent(), fresh.Persistent()),
				append(append([]*wallet.Key{}, keys...), fresh)...)
			add(fmt.Sprintf("RETIRE width=%d deposit=a-fresh-persistent-cell", n), c, err)

			// A fresh one-shot deposit cell costs a signature *and* a second
			// MARK_SPENT, which is what makes it the gas-densest family.
			oneShot := budgetKey(t, 0x12, 0)
			c, err = tryCert(p, prog, wallet.SweepDeposit(oneShot.OneShot(), refund, drops(1_000_000)),
				append(append([]*wallet.Key{}, keys...), oneShot)...)
			add(fmt.Sprintf("RETIRE width=%d deposit=a-fresh-one-shot-cell", n), c, err)
		}
	}

	for _, oneShot := range []bool{false, true} {
		tag := "persistent"
		if oneShot {
			tag = "one-shot"
		}
		for m := 1; m <= p.MaxMovesPerTransfer; m++ {
			moves := make([]types.Move, 0, m)
			keys := make([]*wallet.Key, 0, m)
			for i := 0; i < m; i++ {
				k := budgetKey(t, 0x20, uint64(i))
				src := k.Persistent()
				if oneShot {
					src = k.OneShot()
				}
				moves = append(moves, types.Move{
					Asset:  types.NativeAsset,
					Src:    src,
					Dst:    budgetKey(t, 0x21, uint64(i)).Persistent(),
					Amount: drops(1_000),
				})
				keys = append(keys, k)
			}
			prog := types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{Moves: moves}}
			dep := wallet.SelfDeposit(keys[0].Persistent(), keys[0].Persistent())
			if oneShot {
				dep = wallet.SweepDeposit(keys[0].OneShot(), refund, drops(1_000_000))
			}
			c, err := tryCert(p, prog, dep, keys...)
			add(fmt.Sprintf("TRANSFER moves=%d source=%s", m, tag), c, err)
		}
	}

	for i, oneShot := range []bool{false, true} {
		tag := "persistent"
		if oneShot {
			tag = "one-shot"
		}
		iss := budgetKey(t, 0x30, uint64(i))
		dep := wallet.SelfDeposit(iss.Persistent(), iss.Persistent())
		if oneShot {
			dep = wallet.SweepDeposit(iss.OneShot(), refund, drops(1_000_000))
		}
		c, err := tryCert(p, wallet.Issue(iss.Persistent(), drops(1_000_000), 8, types.Hash{1}, iss.PubKey()), dep, iss)
		add(fmt.Sprintf("ISSUE deposit=%s", tag), c, err)

		mk := budgetKey(t, 0x32, uint64(i))
		asset := types.DeriveAssetAddress(p.ChainID, mk.Persistent(), 0)
		dep = wallet.SelfDeposit(mk.Persistent(), mk.Persistent())
		if oneShot {
			dep = wallet.SweepDeposit(mk.OneShot(), refund, drops(1_000_000))
		}
		c, err = tryCert(p, wallet.Mint(asset, budgetKey(t, 0x33, 0).Persistent(), drops(10), drops(1_000_000), mk.PubKey()), dep, mk)
		add(fmt.Sprintf("MINT deposit=%s", tag), c, err)
	}
	return out
}

// inBlock is what one certificate costs a block: its own encoding plus the
// four offset bytes ssz.EncodeVariableList writes for every element of a
// variable-length list. The block byte ceiling bounds the encoded *block*, so
// the offsets come out of the same budget as the bodies — which is the term
// the "block_byte_limit_genesis ÷ max_certs_per_block_genesis" reading drops.
func inBlock(c *types.Certificate) int { return c.SizeBytes() + 4 }

// emptyBlockBytes is the block's own fixed cost, measured rather than derived
// from HeaderSize: a header, and one four-byte offset for each of the two
// variable lists a block carries.
func emptyBlockBytes() int { return (&types.Block{}).SizeBytes() }

// binding reports which ceiling admits the fewest certificates of a shape, and
// how many, at a given sequential-gas bound. gasLimit is a parameter and not a
// constant because the answer differs between the 4T bound block validity
// rejects on and the 2T threshold F11 prices — see this file's header.
func binding(p *params.Params, c *types.Certificate, certCeiling, byteCeiling, base int, gasLimit uint64) (string, int, int) {
	cands := []struct {
		name string
		v    int
	}{
		{"bytes", (byteCeiling - base) / inBlock(c)},
		{"count", certCeiling},
		{"gas", int(gasLimit / c.SeqGas(p))},
		{"parallel", int(p.ParGasLimit(p.SeqGasTargetGenesis) / c.ParGas(p))},
	}
	best, n := cands[0].name, cands[0].v
	for _, cand := range cands[1:] {
		if cand.v < n {
			best, n = cand.name, cand.v
		}
	}
	ties := 0
	for _, cand := range cands {
		if cand.v == n {
			ties++
		}
	}
	return best, n, ties
}

// TestTheEra0EncodingFloorIsA558ByteRetire pins the floor of the
// per-certificate byte budget, which every other number in this file is
// measured against.
//
// The floor matters because it is the only thing that decides whether the
// certificate-count ceiling can be reached or violated at all: the count rule
// fires exactly when (ceiling+1) × (cheapest certificate) still fits under
// the byte ceiling. Getting the cheapest shape wrong is how an earlier
// reading first concluded that mainnet's count rule could not be observed —
// it generalised from the TRANSFER shape, and the floor is 290 bytes below
// it.
func TestTheEra0EncodingFloorIsA558ByteRetire(t *testing.T) {
	p := spec.Mainnet()
	shapes := era0ShapeSpace(t, p)
	if len(shapes) < 90 {
		t.Fatalf("the shape sweep produced only %d shapes; it is no longer covering the space "+
			"the classification below claims to be about", len(shapes))
	}

	floor := shapes[0].cert.SizeBytes()
	for _, s := range shapes {
		if s.cert.SizeBytes() < floor {
			floor = s.cert.SizeBytes()
		}
	}
	if floor != 558 {
		t.Fatalf("the Era-0 encoding floor measures %d bytes, not the 558 this file and "+
			"spec/params.json's note on max_certs_per_block_genesis are written against; "+
			"the encoding moved and every byte budget must be re-derived", floor)
	}

	// The floor is reached by TWO shapes, not one, and saying so is the point:
	// a RETIRE whose deposit cell is the persistent twin of a retired key
	// derives no extra MARK_SPENT (the cell is not one-shot) and needs no
	// extra signature (V4 matches on the public key, and both addresses come
	// from it). Describing the floor as "the RETIRE that sweeps its own
	// deposit" is true of one instance and false as a characterisation.
	var atFloor []string
	for _, s := range shapes {
		if s.cert.SizeBytes() == floor {
			atFloor = append(atFloor, s.name)
		}
	}
	if len(atFloor) != 2 {
		t.Fatalf("%d shapes sit at the %d-byte floor, want 2: %v", len(atFloor), floor, atFloor)
	}
	for _, want := range []string{
		"RETIRE width=1 deposit=swept-from-a-retired-address",
		"RETIRE width=1 deposit=persistent-twin-of-a-retired-key",
	} {
		found := false
		for _, name := range atFloor {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q is no longer at the encoding floor; the floor is now %v", want, atFloor)
		}
	}

	// The same number from the encoding's own constants, so that a layout
	// change fails here — naming which term moved — rather than silently
	// shifting every budget below.
	//
	// The certificate's fixed part is two uint64s, four offsets for the four
	// variable-length fields, the deposit, the TTL and the fee bid; the
	// program's is its kind byte and one offset. Nothing below any of these
	// terms is optional: V1 requires at least one signature, Derive rejects
	// every program with no effect, and the cheapest program body that has an
	// effect is one 32-byte address to retire.
	const certFixed = 8 + 8 + 4 + 4 + 4 + 4 + types.DepositSize + 8 + types.FeeBidSize
	const programFixed = 1 + 4
	const smallestProgramBody = 32 // one address to retire
	want := certFixed + programFixed + smallestProgramBody + types.WriteSize + types.SigSize
	if floor != want {
		t.Fatalf("the floor measures %d bytes but its parts sum to %d "+
			"(%d fixed + %d program header + %d address + %d write + %d signature)",
			floor, want, certFixed, programFixed, smallestProgramBody, types.WriteSize, types.SigSize)
	}
	sample := minimumRetire(t, p, 0)
	if n := len(sample.Reads); n != 0 {
		t.Fatalf("the floor certificate declares %d reads, want none", n)
	}
	if n := len(sample.Writes); n != 1 {
		t.Fatalf("the floor certificate declares %d writes, want the single MARK_SPENT", n)
	}
	if n := len(sample.Sigs); n != 1 {
		t.Fatalf("the floor certificate carries %d signatures, want V1's minimum of 1", n)
	}

	// Size is a property of the shape, not of the key material. Every field a
	// key reaches is fixed-width, which is what lets a block's size be a
	// function of the shapes it carries and their count — the form every
	// figure in this file is stated in, and the form the band test derives its
	// 2,933-payment edge in rather than building that block.
	payment := oneMoveTransfer(t, p, 0)
	for i := uint64(1); i < 64; i++ {
		if c := minimumRetire(t, p, i); c.SizeBytes() != floor {
			t.Fatalf("minimum retire %d measures %d bytes against index 0's %d: "+
				"certificate size depends on key material, and every block figure "+
				"in this file assumes it does not", i, c.SizeBytes(), floor)
		}
		if c := oneMoveTransfer(t, p, i); c.SizeBytes() != payment.SizeBytes() {
			t.Fatalf("one-move transfer %d measures %d bytes against index 0's %d: "+
				"certificate size depends on key material, and every block figure "+
				"in this file assumes it does not", i, c.SizeBytes(), payment.SizeBytes())
		}
	}
	if got := payment.SizeBytes(); got != 848 {
		t.Fatalf("the ordinary payment shape measures %d bytes, not the 848 this file, "+
			"spec/params.json's notes and docs/decisions/testnet-measurements.md are "+
			"written against", got)
	}

	// The bridge every block figure in this file rests on: a block costs its
	// own fixed bytes plus, for each certificate, that certificate's encoding
	// and the four offset bytes ssz.EncodeVariableList writes for it. Checked
	// on a block of distinct certificates of mixed shapes, so that the
	// arithmetic can then be applied at counts no test wants to build twice.
	mixed := make([]*types.Certificate, 0, len(shapes))
	sum := emptyBlockBytes()
	for _, s := range shapes {
		mixed = append(mixed, s.cert)
		sum += inBlock(s.cert)
	}
	if got := (&types.Block{Certs: mixed}).SizeBytes(); got != sum {
		t.Fatalf("a block of %d certificates measures %d bytes but its parts sum to %d: "+
			"a block is no longer its fixed cost plus body-plus-offset per certificate, "+
			"and every block figure in this file is derived from that identity",
			len(mixed), got, sum)
	}
}

// era0CertByteCeiling is the widest certificate body the V-rules admit at p,
// derived from the encoding and the rules rather than found by search.
//
// **This is a second copy and it is here on purpose.** The derivation, with the
// whole argument for each arm, lives in sim/block_ceiling_boundary_test.go
// beside the construction that shows the bound attained; it is a helper of a
// _test package and nothing outside that binary can call it. The sweep below
// needs the number and only the number, so the arithmetic is repeated here and
// nothing else is. PROTOCOL.md rule 12's warning about a rule implemented twice
// applies to a derivation too: when that derivation moves onto a surface both
// packages can import, this copy must be deleted and the import taken instead,
// not kept in step by hand.
//
// The identity, in one line: ssz.Encode over certLayout makes every certificate
// exactly CertMinSize + |program| + ReadSize*R + WriteSize*W + SigSize*S, with
// no cross terms, so bounding a certificate is bounding four integers under the
// caps V1 sets and the couplings V3 and V4 force. At every shipped parameter
// set the TRANSFER arm dominates the other three by about four times.
func era0CertByteCeiling(p *params.Params) int {
	fixed := types.CertMinSize + len(types.Program{
		Kind: types.ProgramRetire, Retire: &types.RetireArgs{},
	}.MarshalSSZ())

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

// The coverage floor era0ShapeSpace must keep, as a fraction of the derived
// width ceiling. It is a floor and not a pin: the sweep is free to reach
// further, and 65/100 is below the 0.6628 measured at every shipped parameter
// set so that ordinary parameter movement does not fire it.
const era0WidthCoverageNum, era0WidthCoverageDen = 65, 100

// TestTheEra0SweepKeepsItsShareOfTheDerivedWidthCeiling arms the omissions
// era0ShapeSpace's header already admits to.
//
// That header is honest: destinations are always distinct, so the sweep never
// builds the merged-credit family, and the family it skips is the one that
// falsified three successive published maxima for the widest Era-0 certificate.
// What was missing is that the size of the omission was written nowhere, so it
// could only grow. A future edit that drops another dimension — for the same
// good reasons the current omissions were accepted — narrows the sample in
// silence, and every conclusion this file draws from the sweep (the two-class
// split under 4T, devnet's byte-bound exception, the density figures)
// quietly becomes a claim about less than the header says it is about. The
// first sign would be a test that still passes.
//
// So the omission is measured instead of described. The sweep's widest member
// is compared against era0CertByteCeiling, and losing ground fails. Stating a
// limit is not arming it.
//
// **A floor, and it fails with the reason rather than the number.** The
// fraction is allowed to rise and no assertion here has to be touched when it
// does. If it falls the failure says which claim stopped being supported,
// because a guard that prints an integer teaches the next person to update the
// integer — and updating this one would record the loss rather than repair it.
func TestTheEra0SweepKeepsItsShareOfTheDerivedWidthCeiling(t *testing.T) {
	// Mainnet is where this file's classification is stated; devnet is where the
	// classification's one exception is decided by width, so a sweep that loses
	// width is felt there first.
	for _, p := range []*params.Params{spec.Mainnet(), spec.Devnet()} {
		t.Run(p.Name, func(t *testing.T) {
			shapes := era0ShapeSpace(t, p)
			if len(shapes) == 0 {
				t.Fatal("the shape sweep produced nothing to measure")
			}
			widest := shapes[0]
			for _, s := range shapes[1:] {
				if s.cert.SizeBytes() > widest.cert.SizeBytes() {
					widest = s
				}
			}
			ceiling := era0CertByteCeiling(p)
			// Cross-multiplied, so the floor is exact arithmetic rather than a
			// float comparison.
			if widest.cert.SizeBytes()*era0WidthCoverageDen < ceiling*era0WidthCoverageNum {
				t.Fatalf("the shape sweep no longer reaches the width the ceiling argument "+
					"assumes: its widest member is %q at %d bytes against a derived ceiling "+
					"of %d, under the share this file's conclusions are drawn against. A "+
					"dimension the sweep used to vary has been dropped, so the two-class "+
					"split under 4T, devnet's byte-bound exception and the density "+
					"figures are now claims about a smaller sample than era0ShapeSpace's "+
					"header describes. Restore the dimension, or restate those conclusions "+
					"for the sample that is left; lowering this floor only records the loss.",
					widest.name, widest.cert.SizeBytes(), ceiling)
			}
		})
	}
}

// TestOnlyTheEncodingFloorIsBoundByTheCertificateCount is the answer to that
// question, stated as the property that makes the answer "yes, intended".
//
// Over the whole enumerated shape space, at mainnet genesis, under the bound
// block validity actually rejects on (4T, blockrules.go), the certificate
// count is the first ceiling to bind for **exactly the shapes at the encoding
// floor** and for no other shape, with no ties anywhere. That is the
// minimum-size flood and nothing else — precisely the case the byte ceiling
// is cheapest for and therefore bounds worst. That property is what the
// calibration question asked about and it is unchanged by the move of T₀ and
// par_gas_ratio.
//
// **The class counts beside it did change, and the change is the point.**
// Until T₀ was lowered to 1,600,000, no Era-0 shape was gas-bound under 4T:
// B5 required 4T₀/block_byte_limit_genesis = 3.2 sequential gas per block byte
// and the densest shape anyone had built measured 2.8937, so the rejecting
// ceilings split the space into exactly two classes and B5 was unreachable at
// shipped parameters. At T₀ = 1,600,000 the requirement is 2.56, and
// **38 of the 98 shapes clear it**. So the partition really is three-way now:
// 2 count-bound, 38 gas-bound, 58 byte-bound. B5 is reachable by construction
// on shapes that have been built rather than by an argument about shapes
// nobody has, which is the form PROTOCOL rule 21 asks for — and it is why
// sim/refold's `producer < 0` clamp is structural rather than dead code.
//
// The 2T *soft* threshold is still reported separately, because it is a
// fee-market target priced by F11's subsidy forfeiture rather than a rule any
// block is rejected for, and the two classifications are no longer allowed to
// be confused with one another.
func TestOnlyTheEncodingFloorIsBoundByTheCertificateCount(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	certCeiling := p.MaxCertsPerBlock(t0)
	byteCeiling := p.BlockByteLimit(t0)
	base := emptyBlockBytes()
	hard := p.SeqGasBurst(t0) // 4T — what CheckBlockRules rejects on
	soft := p.SeqGasLimit(t0) // 2T — F11's forfeiture threshold, not a rule

	shapes := era0ShapeSpace(t, p)
	// era0ShapeSpace drops combinations the V-rules refuse, so a change that
	// made most of them invalid would shrink the sweep silently — and the
	// class checks below are partly *relative* to len(shapes), which alone
	// would tolerate a degenerate sweep. The absolute assertion further down (76
	// gas-bound under 2T) does backstop it, but the guard belongs next to the
	// counting rather than one test away — and the devnet arm no longer
	// backstops anything, because it now pins no count at all.
	if len(shapes) != 98 {
		t.Fatalf("the shape sweep produced %d shapes, not the 98 this test's class counts and "+
			"spec/params.json's note are stated over", len(shapes))
	}
	floor := shapes[0].cert.SizeBytes()
	for _, s := range shapes {
		if s.cert.SizeBytes() < floor {
			floor = s.cert.SizeBytes()
		}
	}

	hardClass := map[string]int{}
	for _, s := range shapes {
		bind, n, ties := binding(p, s.cert, certCeiling, byteCeiling, base, hard)
		hardClass[bind]++
		if ties > 1 {
			t.Fatalf("%s: two ceilings tie at %d certificates, so which one binds is not "+
				"well defined and the classification below is not a partition", s.name, n)
		}
		atFloor := s.cert.SizeBytes() == floor
		if bind == "count" != atFloor {
			t.Fatalf("%s (%d B, %d seq gas): %s binds first at %d, and the shape is%s at the "+
				"%d-byte encoding floor — the count ceiling must bind for the floor shapes "+
				"and for nothing else", s.name, s.cert.SizeBytes(), s.cert.SeqGas(p), bind, n,
				map[bool]string{true: "", false: " not"}[atFloor], floor)
		}
	}
	// B6 is the one rejecting ceiling still out of reach, and it is out of
	// reach by derivation rather than by sample: it requires
	// 2·par_gas_ratio·T₀/block_byte_limit_genesis parallel gas per block byte,
	// and Era-0 density is bounded below that for every certificate, searched or
	// not, by sim's era0ParDensityCeiling — which also builds the certificate
	// that attains the bound, so neither half of it is this sweep's echo. Both
	// figures are recomputed here from p rather than quoted, because a hand-typed
	// one goes stale the day a parameter moves. A parallel-bound shape here would
	// mean that derivation is wrong, which is worth more than the count it would
	// change.
	if hardClass["parallel"] != 0 {
		t.Fatalf("under the 4T bound %d shapes are parallel-bound, want none: B6 requires "+
			"%.4f parallel gas per block byte at par_gas_ratio = %d, and the derivation bounds Era-0 "+
			"density below that (sim's era0ParDensityCeiling) — one of the two is wrong",
			hardClass["parallel"],
			float64(p.ParGasLimit(t0))/float64(p.BlockByteLimit(t0)), p.ParGasRatio)
	}
	// The three-way split, asserted per class so that a shift between gas and
	// bytes cannot hide inside a total. The gas class is the B5 flip and it is
	// asserted as non-empty in its own right: if it ever empties, B5 has gone
	// back to being unreachable at shipped parameters and the retired "B5 is
	// unreachable at shipped parameters" conclusion revives.
	if hardClass["count"] != 2 || hardClass["gas"] != 38 || hardClass["bytes"] != len(shapes)-40 {
		t.Fatalf("under the 4T bound the classes are %v over %d shapes, want 2 count-bound "+
			"(the encoding floor), 38 gas-bound and %d byte-bound",
			hardClass, len(shapes), len(shapes)-40)
	}
	if hardClass["gas"] == 0 {
		t.Fatal("no Era-0 shape is gas-bound under 4T: B5 is unreachable at shipped " +
			"parameters again, and sim/refold's producer < 0 clamp is dead code")
	}

	// The 2T soft threshold, reported as the separate thing it is. A producer
	// that crosses it keeps a valid block and forfeits subsidy quadratically
	// (F11), so it binds a revenue-maximising producer without binding a
	// block — and under it the gas-dense shapes really are the tightest. This
	// is asserted so the distinction stays visible: if the two classifications
	// ever coincide, either blockrules.go started rejecting at 2T or no shape
	// is gas-dense any more, and both are things to notice.
	//
	// **The current T₀ makes one coincidence exact, and a tie here is now expected
	// rather than a defect.** The count ceiling admits
	// max_certs_per_block_genesis = 4000 certificates; the 2T threshold admits
	// 2·T₀/800 = 4000 of the 800-gas encoding-floor certificate. They are the
	// same number, because 2 × 1,600,000 == 4000 × 800 exactly. Under the
	// superseded T₀ = 2,000,000 they were 4000 against 5000 and no shape tied.
	//
	// The consequence worth carrying out of here: a block filled to the count
	// ceiling with floor certificates now declares exactly 2T of sequential
	// gas — at F11's forfeiture threshold, where the quadratic is zero, and
	// never above it. The count rule and the soft threshold stopped being
	// independent bounds on the minimum-size flood. Nothing is rejected that
	// was not rejected before; what is gone is the margin between them.
	//
	// So the tie is admitted only for the shape it is admitted for — 800
	// sequential gas, tying at the count ceiling itself — and its absence is a
	// failure, because a tie that stops appearing means the identity above has
	// stopped holding and this paragraph has gone stale.
	const floorGas = 800
	softClass := map[string]int{}
	softTies := 0
	for _, s := range shapes {
		bind, n, ties := binding(p, s.cert, certCeiling, byteCeiling, base, soft)
		softClass[bind]++
		if ties > 1 {
			if s.cert.SeqGas(p) != floorGas || n != certCeiling {
				t.Fatalf("%s (%d B, %d seq gas): two ceilings tie at %d under the 2T threshold "+
					"for a reason other than the count/soft coincidence stated above",
					s.name, s.cert.SizeBytes(), s.cert.SeqGas(p), n)
			}
			softTies++
		}
	}
	if softTies == 0 {
		t.Fatal("no shape tied the count ceiling against the 2T threshold; the exact " +
			"coincidence 2*seq_gas_target_genesis == max_certs_per_block_genesis * 800 " +
			"no longer holds and the paragraph above is stale")
	}
	if softClass["gas"] != 76 {
		t.Fatalf("%d shapes are gas-bound under the 2T threshold (%v), not the 76 "+
			"spec/params.json's note on max_certs_per_block_genesis records; the soft "+
			"threshold's reach has moved", softClass["gas"], softClass)
	}
	// And the gas-densest shape the note names. Cross-multiplied: gas_i/size_i >
	// gas_j/size_j becomes gas_i*size_j > gas_j*size_i, so no float is needed.
	densest := shapes[0]
	for _, s := range shapes[1:] {
		if s.cert.SeqGas(p)*uint64(densest.cert.SizeBytes()) >
			densest.cert.SeqGas(p)*uint64(s.cert.SizeBytes()) {
			densest = s
		}
	}
	if densest.name != "RETIRE width=15 deposit=a-fresh-one-shot-cell" {
		t.Fatalf("the gas-densest Era-0 shape is %q (%d gas in %d B), not the width-15 RETIRE "+
			"with a fresh one-shot deposit cell that spec/params.json's note names",
			densest.name, densest.cert.SeqGas(p), densest.cert.SizeBytes())
	}
	if softClass["count"] != hardClass["count"] {
		t.Fatalf("the count-bound class differs between the 2T threshold (%d) and the 4T bound "+
			"(%d); the answer is stated under 4T and must not depend on which is used",
			softClass["count"], hardClass["count"])
	}

	// Devnet, because the note on this parameter says what devnet does and a
	// claim about a second parameter set needs a second measurement. Its 256
	// against the same byte ceiling makes the count rule the operative bound
	// almost everywhere — but not everywhere.
	//
	// **The exception used to be a census, and that is what was objected to.**
	// This arm read `devClass["bytes"] != 1`, and both the 1 and the note it
	// checked came out of era0ShapeSpace. Assertion and oracle shared the
	// enumeration, so the arm could not fail for the reason it existed: a sweep
	// that stopped reaching over devnet's budget would move the note and the
	// assertion together, and "the byte rule can bind at devnet" would quietly
	// become a claim about a sample that no longer contains a witness. That is
	// the same defect the widest Era-0 certificate ran into: it was published
	// four times — 7,823, 10,125, 13,703, 15,281 — and the first three were
	// each falsified by a corner the previous search could not see. The remedy
	// that ended it is the one taken here: derive the claim from the rules
	// rather than search for it again (era0CertByteCeiling).
	//
	// **What is derived.** Which ceiling binds at devnet is decided by size
	// alone, because floor((limit − base)/inBlock) < ceiling is exactly
	// inBlock > (limit − base)/ceiling. That threshold is devnet's
	// per-certificate in-block byte budget; it is arithmetic over devnet's own
	// parameters and it owes this sweep nothing. Three things are asserted
	// against it, and none of them is a count of shapes:
	//
	//  1. the split IS that threshold — every shape lands in the class its size
	//     puts it in, and no shape is gas- or parallel-bound, which is the
	//     premise the equivalence needs and the half that would really break;
	//  2. the byte class is non-empty in the RULES and not merely in the sweep:
	//     the widest certificate the V-rules admit is era0CertByteCeiling(dev)
	//     + 4 in a block, derived rather than searched for and built by sim's
	//     TestTheWidestEra0CertificateIsDerivedAndAttained, and it is over the
	//     budget with room to spare. Dropping a dimension from era0ShapeSpace
	//     can empty devnet's byte class in this sweep; it cannot empty it in the
	//     rules, and these two arms say which of the two happened;
	//  3. the count class covers the traffic devnet exists to carry — the
	//     encoding floor and the ordinary payment shape are an order of
	//     magnitude under the budget — so "count-bound almost everywhere" is a
	//     statement about the shapes devnet actually sees rather than about the
	//     arithmetic majority of an enumeration.
	//
	// The 97/1 spec/params.json quotes is still computed and is logged rather
	// than pinned. It is a property of the sample, the note already labels it as
	// one ("THAT SHAPE IS THE SWEEP'S WIDEST AND NOT THE WIDEST"), and pinning
	// it here would restore exactly the echo this replaced.
	dev := spec.Devnet()
	devT0 := dev.SeqGasTargetGenesis
	devLimit := dev.BlockByteLimit(devT0)
	devCeiling := dev.MaxCertsPerBlock(devT0)
	devBudget := (devLimit - base) / devCeiling

	devClass := map[string]int{}
	for _, s := range era0ShapeSpace(t, dev) {
		bind, n, _ := binding(dev, s.cert, devCeiling, devLimit, base, dev.SeqGasBurst(devT0))
		devClass[bind]++
		if bind != "bytes" && bind != "count" {
			t.Fatalf("at devnet %s (%d B, %d seq gas) is %s-bound at %d certificates: devnet's "+
				"split is stated as a size threshold, and that rests on neither gas ceiling "+
				"reaching a shape before bytes or count do",
				s.name, s.cert.SizeBytes(), s.cert.SeqGas(dev), bind, n)
		}
		if overBudget := inBlock(s.cert) > devBudget; (bind == "bytes") != overBudget {
			t.Fatalf("at devnet %s costs a block %d bytes against a per-certificate budget of %d "+
				"((%d-%d)/%d) and %s binds first: which class a shape lands in is no longer "+
				"decided by its size alone, so devnet's split cannot be stated as the derived "+
				"threshold this arm rests on", s.name, inBlock(s.cert), devBudget,
				devLimit, base, devCeiling, bind)
		}
	}
	if widest := era0CertByteCeiling(dev) + 4; widest <= devBudget {
		t.Fatalf("the widest certificate the V-rules admit at devnet costs a block %d bytes "+
			"against a per-certificate budget of %d: nothing can be byte-bound at devnet at "+
			"all, and spec/params.json's note that the count rule binds for all but the widest "+
			"shape has become a claim that it binds for every shape", widest, devBudget)
	}
	if devClass["bytes"] == 0 {
		t.Fatalf("no shape in the sweep is byte-bound at devnet, though the rules admit a "+
			"certificate of %d in-block bytes against a budget of %d — derived by "+
			"era0CertByteCeiling and built by sim's "+
			"TestTheWidestEra0CertificateIsDerivedAndAttained. What has been lost is the "+
			"sweep's witness for the exception, not the exception", era0CertByteCeiling(dev)+4, devBudget)
	}
	if devClass["count"] == 0 {
		t.Fatalf("no shape is count-bound at devnet: the count ceiling of %d is not the "+
			"operative bound anywhere, which is the opposite of what devnet's 256 is for", devCeiling)
	}
	// The margin ordinary devnet traffic keeps under the budget. A factor and
	// not a pin: it is measured at 17.4x for the encoding floor and 11.5x for
	// the payment shape, and ten is under both so ordinary encoding movement
	// does not fire it.
	const devOrdinaryTrafficMargin = 10
	for _, ordinary := range []struct {
		name string
		cert *types.Certificate
	}{
		{"the encoding floor", minimumRetire(t, dev, 0)},
		{"the ordinary payment shape", oneMoveTransfer(t, dev, 0)},
	} {
		if got := inBlock(ordinary.cert); got*devOrdinaryTrafficMargin > devBudget {
			t.Fatalf("%s costs a block %d bytes against devnet's per-certificate budget of %d, "+
				"within a factor of %d of it: the count ceiling has stopped being the operative "+
				"bound for the traffic devnet exists to carry, and \"count-bound almost "+
				"everywhere\" is now a statement about the sweep rather than about devnet",
				ordinary.name, got, devBudget, devOrdinaryTrafficMargin)
		}
	}
	t.Logf("devnet: per-certificate in-block budget %d bytes ((%d-%d)/%d); the classes over the "+
		"%d-shape sample are %v, and the rules admit %d in-block bytes",
		devBudget, devLimit, base, devCeiling, len(shapes), devClass, era0CertByteCeiling(dev)+4)

	// What the count rule is worth, stated as the number it changes: without
	// it, a flood of floor-sized certificates would be bounded by bytes and by
	// 4T gas alone.
	floorCert := minimumRetire(t, p, 0)
	byBytes := (byteCeiling - base) / inBlock(floorCert)
	byHardGas := int(hard / floorCert.SeqGas(p))
	if certCeiling >= byBytes || certCeiling >= byHardGas {
		t.Fatalf("the count ceiling (%d) is not below the flood bound the other rejecting "+
			"ceilings would impose (bytes %d, 4T gas %d): it adds nothing at the floor",
			certCeiling, byBytes, byHardGas)
	}
}

// TestTheCountRuleFiresAtEveryReachableT sweeps T one unit at a time, which is
// the only step size that can observe the property its predecessor claimed to
// check.
//
// The earlier version stepped by 1000. With the superseded T₀ = 2,000,000 that
// makes every sampled T divide exactly in both ceilings — 0 of 4401 samples had a
// non-exact division — so it sampled only the maxima of a quantity that dips
// between them, and it produced a utilisation interval that is wrong in this
// file's own prose. spec/README.md already said so, untouched, one paragraph
// away: "MaxCertsPerBlock and BlockByteLimit both floor … so its utilisation
// of the byte ceiling is neither constant nor monotone in T." An instrument
// whose sampling grid is aligned to the signal it is looking for measures the
// grid.
//
// The three properties, all over every integer T in [T₀, seq_gas_capacity]:
// the count ceiling is reachable, the count rule actually *fires* (a block of
// ceiling+1 floor certificates fits under the byte ceiling, so the count rule
// is the rejecting one rather than a formality bytes gets to first), and the
// utilisation of the byte ceiling stays inside the measured interval.
func TestTheCountRuleFiresAtEveryReachableT(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	base := emptyBlockBytes()
	minCost := inBlock(minimumRetire(t, p, 0))

	// Utilisation is a ratio, and it is compared as one: a/b < c/d becomes
	// a*d < c*b. No floating point in this tree, tests included — and the
	// integer form matters beyond style here, because rounding the ratio to
	// parts per million before comparing makes two neighbouring T values tie
	// and hands back whichever came first rather than the true extremum.
	// Parts per million is computed only for the message and the pinned
	// interval.
	const wantLo, wantHi = 899_070, 899_294
	loN, loD := 1, 0 // a sentinel ratio above anything real (1/0 is treated as +inf below)
	hiN, hiD := 0, 1
	var loT, hiT uint64
	worstSlack := 1 << 62
	var worstT uint64

	for tv := t0; tv <= p.SeqGasCapacity; tv++ {
		ceiling := p.MaxCertsPerBlock(tv)
		limit := p.BlockByteLimit(tv)
		full := minCost*ceiling + base
		if full > limit {
			t.Fatalf("at T=%d a block of MaxCertsPerBlock(T)=%d floor certificates is %d bytes "+
				"against a byte ceiling of %d: the count ceiling is unreachable there",
				tv, ceiling, full, limit)
		}
		// The rule fires only if ceiling+1 still fits under the byte ceiling;
		// otherwise bytes rejects the block first and the count rule never has
		// content, however reachable the ceiling itself is.
		if slack := limit - (minCost*(ceiling+1) + base); slack < worstSlack {
			worstSlack, worstT = slack, tv
		}
		// full/limit against the running extremes, exactly.
		if loD == 0 || full*loD < loN*limit {
			loN, loD, loT = full, limit, tv
		}
		if full*hiD > hiN*limit {
			hiN, hiD, hiT = full, limit, tv
		}
	}
	lo := loN * 1_000_000 / loD
	hi := hiN * 1_000_000 / hiD

	if worstSlack < 0 {
		t.Fatalf("at T=%d a block of ceiling+1 floor certificates does not fit under the byte "+
			"ceiling (slack %d bytes): the byte rule rejects it first, so the count rule is "+
			"inert there", worstT, worstSlack)
	}
	if worstSlack != 251_202 || worstT != t0 {
		t.Fatalf("the tightest a ceiling+1 floor block ever gets is %d bytes of slack at T=%d, "+
			"not the 251,202 at T₀ that spec/params.json's note records", worstSlack, worstT)
	}
	if lo != wantLo || hi != wantHi || loT != 1_600_399 || hiT != t0 {
		t.Fatalf("byte-ceiling utilisation of a count-bound floor block is [%d, %d] ppm "+
			"(min at T=%d, max at T=%d), not the [%d, %d] at T=1,600,399 and T₀ recorded in "+
			"spec/params.json's note and docs/ARCHITECTURE.md; the two ceilings floor "+
			"independently, so this interval is a measurement and not an identity",
			lo, hi, loT, hiT, wantLo, wantHi)
	}
	// The first rung of the maximal growth ladder is already off the maximum,
	// which is the concrete form of "not constant in T" the note quotes: this
	// is the path a healthy chain actually takes, not a pathological T.
	rung1 := t0 + t0/p.CeilingGrowthDivisor
	if u := (minCost*p.MaxCertsPerBlock(rung1) + base) * 1_000_000 / p.BlockByteLimit(rung1); u != 899_112 {
		t.Fatalf("one epoch of maximal growth past genesis (T=%d) gives %d ppm utilisation, "+
			"not the 899,112 (89.9112%%) spec/params.json's note records", rung1, u)
	}
	if p.MaxCertsPerBlock(p.SeqGasCapacity) >= p.CertListCapacity {
		t.Fatalf("MaxCertsPerBlock at the gas capacity is %d, at or above cert_list_capacity %d: "+
			"the structural clamp binds inside Era 0, which the capacity is not sized for",
			p.MaxCertsPerBlock(p.SeqGasCapacity), p.CertListCapacity)
	}
}

// TestTheCertCountCeilingIsReachableWithOrdinaryPayments closes the claim the
// calibration question was opened on: that max_certs_per_block_genesis = 4000
// "is reachable only by an all-RETIRE block".
//
// It is not. Measured on real blocks of real signed certificates: 4000 floor
// certificates occupy 89.93% of the byte ceiling, and the remaining slack pays
// for 868 ordinary one-move transfers — 21.7% of the block by count, 29.6% by
// bytes — before the byte rule takes over.
func TestTheCertCountCeilingIsReachableWithOrdinaryPayments(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	ceiling := p.MaxCertsPerBlock(t0)
	byteCeiling := p.BlockByteLimit(t0)

	retires := make([]*types.Certificate, 0, ceiling)
	for i := 0; i < ceiling; i++ {
		retires = append(retires, minimumRetire(t, p, uint64(i)))
	}
	allRetire := &types.Block{Certs: retires}
	if size := allRetire.SizeBytes(); size > byteCeiling {
		t.Fatalf("a block of %d floor certificates is %d bytes against a byte ceiling of %d: "+
			"max_certs_per_block_genesis is not reachable at all", ceiling, size, byteCeiling)
	} else if size != 2_248_236 {
		t.Fatalf("a block of %d floor certificates measures %d bytes, not the 2,248,236 "+
			"spec/params.json's note and spec/README.md quote", ceiling, size)
	}

	// The largest number of ordinary payments a block at the count ceiling can
	// carry. Both sides of the edge are asserted, because "868 fit" without
	// "869 does not" would pass for every number below the real maximum and
	// would be measuring the scenario rather than the parameter.
	const maxPayments = 868
	// The pool is sized for the largest block below, not for the mix, so that
	// every block this test measures is built from distinct certificates —
	// a block of repeats is not a block any rule would accept, and measuring
	// one would be measuring a shape the network cannot carry.
	const paperBlock = 2900
	transfers := make([]*types.Certificate, 0, paperBlock)
	for i := 0; i < paperBlock; i++ {
		transfers = append(transfers, oneMoveTransfer(t, p, uint64(i)))
	}
	mixed := func(payments int) *types.Block {
		certs := make([]*types.Certificate, 0, ceiling)
		certs = append(certs, transfers[:payments]...)
		certs = append(certs, retires[:ceiling-payments]...)
		return &types.Block{Certs: certs}
	}
	fits := mixed(maxPayments)
	if size := fits.SizeBytes(); size > byteCeiling {
		t.Fatalf("a %d-certificate block with %d ordinary transfers is %d bytes, over the byte "+
			"ceiling of %d: the count ceiling is not reachable with that many payments",
			ceiling, maxPayments, size, byteCeiling)
	}
	over := mixed(maxPayments + 1)
	if size := over.SizeBytes(); size <= byteCeiling {
		t.Fatalf("a %d-certificate block with %d ordinary transfers is %d bytes, still under the "+
			"byte ceiling of %d: %d is not the maximum and the figure in spec/params.json's note "+
			"understates it", ceiling, maxPayments+1, size, byteCeiling, maxPayments)
	}

	// Every certificate in it is distinct and stateless-valid, so what the
	// count ceiling binds here is a block the rest of the rules would admit
	// rather than an arithmetic construction: wallet.Builder refuses to emit a
	// certificate validity.Check rejects, and B0's duplicate-id rule is the
	// one other block rule a block of repeats would trip.
	ids := make(map[types.Hash]struct{}, ceiling)
	for _, c := range fits.Certs {
		ids[c.ID()] = struct{}{}
	}
	if len(ids) != ceiling {
		t.Fatalf("the mixed block carries %d distinct certificate ids for %d certificates: "+
			"a block with a repeat is rejected by B0 and is not evidence about the count rule",
			len(ids), ceiling)
	}

	// The mixed block is one the rejecting ceilings also admit — the 4T bound
	// rather than 2T, since 2T is a price and not a rule (see the header).
	var seqGas, parGas uint64
	for _, c := range fits.Certs {
		seqGas += c.SeqGas(p)
		parGas += c.ParGas(p)
	}
	if limit := p.SeqGasBurst(t0); seqGas > limit {
		t.Fatalf("the mixed block applies %d sequential gas against the 4T bound of %d: "+
			"gas rejects it before the count does, so it is not evidence about the count rule",
			seqGas, limit)
	}
	if limit := p.ParGasLimit(t0); parGas > limit {
		t.Fatalf("the mixed block costs %d parallel gas against a ceiling of %d", parGas, limit)
	}

	// Whitepaper §8.1 sizes the genesis ceiling as "~90 applied certificates
	// per second (a §15 block per 30-second interval)", and §15's block is
	// 2,900 certificates. The byte ceiling — not the count ceiling — is what
	// has to carry that claim, because payment traffic is byte-bound, so it
	// is checked here against the payment shape.
	if size := (&types.Block{Certs: transfers}).SizeBytes(); size > byteCeiling {
		t.Fatalf("whitepaper §15's block of %d certificates is %d bytes at the ordinary payment "+
			"shape, over mainnet's genesis byte ceiling of %d: the parameters no longer deliver "+
			"the throughput §8.1 claims for them", paperBlock, size, byteCeiling)
	}
}

// TestMaxCertsPerBlockGenesisSitsInsideItsReachableBand is the calibration
// that question asked for, and the half that makes the rest of this file a
// constraint rather than a description.
//
// The shipped value is defensible only if the values around it are not, so
// both edges of the band are computed from the measured encoding and both are
// shown to change the answer:
//
//	upper edge — above it, no block at T₀ reaches the ceiling.
//	lower edge — below it, the count ceiling starts cutting the byte-bound
//	             capacity of ordinary payments, which is a capacity decision
//	             wearing a structural rule's clothes.
//
// **The upper edge is a statement about T₀ and only about T₀**, which an
// earlier draft got wrong by extending it to "inert at any T". Both ceilings
// floor independently, so a genesis value that is unreachable at T₀ can become
// reachable — and then violable — further up the curve. The all-T threshold is
// computed separately below and is a different number.
func TestMaxCertsPerBlockGenesisSitsInsideItsReachableBand(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	byteCeiling := p.BlockByteLimit(t0)
	base := emptyBlockBytes()

	minCost := inBlock(minimumRetire(t, p, 0))
	paymentCost := inBlock(oneMoveTransfer(t, p, 0))

	upper := (byteCeiling - base) / minCost
	lower := (byteCeiling - base) / paymentCost

	if got := p.MaxCertsPerBlockGenesis; got < lower || got > upper {
		t.Fatalf("max_certs_per_block_genesis = %d is outside the T₀ band [%d, %d] that keeps the "+
			"count rule reachable (upper) without cutting byte-bound payment capacity (lower); "+
			"the floor certificate costs %d bytes in a block and an ordinary transfer %d",
			got, lower, upper, minCost, paymentCost)
	}
	if p.MaxCertsPerBlockGenesis == lower || p.MaxCertsPerBlockGenesis == upper {
		t.Fatalf("max_certs_per_block_genesis = %d sits exactly on an edge of the band [%d, %d]; "+
			"one byte of encoding drift in either direction changes what the count rule does",
			p.MaxCertsPerBlockGenesis, lower, upper)
	}

	// Both T₀ edges are armed: the values just outside must genuinely produce
	// the failures the band is drawn against, or this test is describing
	// arithmetic instead of constraining a choice.
	over := *p
	over.MaxCertsPerBlockGenesis = upper + 1
	if full := minCost*over.MaxCertsPerBlock(t0) + base; full <= byteCeiling {
		t.Fatalf("at max_certs_per_block_genesis = %d the cheapest possible block at the ceiling "+
			"is %d bytes, still inside the byte ceiling of %d: the upper edge is not where this "+
			"test says it is", over.MaxCertsPerBlockGenesis, full, byteCeiling)
	}
	at := *p
	at.MaxCertsPerBlockGenesis = upper
	if full := minCost*at.MaxCertsPerBlock(t0) + base; full > byteCeiling {
		t.Fatalf("at max_certs_per_block_genesis = %d the cheapest possible block at the ceiling "+
			"is %d bytes, already over the byte ceiling of %d: the upper edge is one lower",
			at.MaxCertsPerBlockGenesis, full, byteCeiling)
	}
	under := *p
	under.MaxCertsPerBlockGenesis = lower - 1
	if under.MaxCertsPerBlock(t0) >= lower {
		t.Fatalf("at max_certs_per_block_genesis = %d the count ceiling is still %d, so it does "+
			"not cut the %d-payment block the byte ceiling admits: the lower edge is not where "+
			"this test says it is", under.MaxCertsPerBlockGenesis, under.MaxCertsPerBlock(t0), lower)
	}
	if size := lower*paymentCost + base; size > byteCeiling {
		t.Fatalf("the %d-payment block the lower edge is drawn from is %d bytes, over the byte "+
			"ceiling of %d: the lower edge is one lower", lower, size, byteCeiling)
	}
	if size := (lower+1)*paymentCost + base; size <= byteCeiling {
		t.Fatalf("a block of %d payments is %d bytes, still under the byte ceiling of %d: "+
			"%d is not where the byte rule starts refusing payment traffic",
			lower+1, size, byteCeiling, lower)
	}

	if want := fmt.Sprintf("[%d, %d]", lower, upper); want != "[2933, 4447]" {
		t.Fatalf("the T₀ band is now %s, not the [2933, 4447] recorded in spec/params.json's "+
			"note on max_certs_per_block_genesis, in spec/README.md and in the header of this "+
			"file; re-derive the prose before changing this line", want)
	}

	// The all-T threshold, which is a different number from the T₀ edge and is
	// the one a "the rule can never fire" claim has to be made against. A
	// genesis value is inert only if no T in the reachable range admits a
	// block of ceiling+1 floor certificates under the byte ceiling.
	inert := func(genesis int) (bool, uint64) {
		q := *p
		q.MaxCertsPerBlockGenesis = genesis
		for tv := t0; tv <= q.SeqGasCapacity; tv++ {
			if minCost*(q.MaxCertsPerBlock(tv)+1)+base <= q.BlockByteLimit(tv) {
				return false, tv
			}
		}
		return true, 0
	}
	if ok, firstT := inert(upper + 1); ok {
		t.Fatalf("max_certs_per_block_genesis = %d is inert at every T; the all-T threshold is "+
			"the T₀ edge after all, and the note's separate figure is redundant", upper+1)
	} else if firstT != 1_687_410 {
		t.Fatalf("max_certs_per_block_genesis = %d first becomes violable at T=%d, not the "+
			"1,687,410 recorded in spec/params.json's note and docs/ARCHITECTURE.md",
			upper+1, firstT)
	}
	if ok, firstT := inert(upper + 2); !ok {
		t.Fatalf("max_certs_per_block_genesis = %d is violable from T=%d, so it is not the "+
			"all-T inert threshold this file and spec/params.json's note name", upper+2, firstT)
	}
	// How much of the curve that threshold covers. A single violable T would
	// be a curiosity; a large, densely populated band is what makes "4448 is
	// not inert" an argument rather than an anecdote.
	//
	// The multiples of 200 are the sharp version: NextSeqGasTarget's input is
	// 2·median(applied sequential gas), every Era-0 gas constant is a multiple
	// of 100, so every median is too and every target the controller can set
	// is a multiple of 200. A violable T the controller cannot land on would
	// prove less than one it can.
	// over is already the upper+1 copy the T₀ edge was armed with above.
	violableAt := func(tv uint64) bool {
		return minCost*(over.MaxCertsPerBlock(tv)+1)+base <= over.BlockByteLimit(tv)
	}
	total, viol, mult, multViol := 0, 0, 0, 0
	var firstMult uint64
	for tv := t0; tv <= over.SeqGasCapacity; tv++ {
		total++
		v := violableAt(tv)
		if v {
			viol++
		}
		if tv%200 == 0 {
			mult++
			if v {
				multViol++
				if firstMult == 0 {
					firstMult = tv
				}
			}
		}
	}
	if viol != 1_469_202 || total != 3_520_001 {
		t.Fatalf("at max_certs_per_block_genesis = %d, %d of %d reachable T are violable, not the "+
			"1,469,202 of 3,520,001 recorded in spec/params.json's note", upper+1, viol, total)
	}
	if multViol != 7_316 || mult != 17_601 || firstMult != 1_744_600 {
		t.Fatalf("%d of %d multiples of 200 are violable (first at T=%d), not the 7,316 of 17,601 "+
			"first at T=1,744,600 that spec/params.json's note records", multViol, mult, firstMult)
	}

	// And the trap that sentence exists to keep shut. The maximal growth
	// ladder T ← T + T/Γ *passes* the first violable T at rung 28 and is not
	// violable there — it steps over the band — while its first violable rung
	// is 77. An earlier revision quoted the passing rung as though it answered
	// "when can the rule first fire", which is the question rung 77 answers. Both
	// are asserted so neither can be attached to the other's claim again.
	tv, rung := t0, 0
	passRung, firstViolRung := -1, -1
	for tv <= over.SeqGasCapacity {
		if passRung < 0 && tv >= 1_687_410 {
			passRung = rung
		}
		if firstViolRung < 0 && violableAt(tv) {
			firstViolRung = rung
		}
		if passRung >= 0 && firstViolRung >= 0 {
			break
		}
		tv += tv / over.CeilingGrowthDivisor
		rung++
	}
	if passRung != 28 || firstViolRung != 77 {
		t.Fatalf("the maximal growth ladder passes T=1,687,410 at rung %d and is first violable at "+
			"rung %d, not the 28 and 77 spec/params.json's note and docs/ARCHITECTURE.md record",
			passRung, firstViolRung)
	}
	if ladder28 := func() uint64 {
		v := t0
		for i := 0; i < 28; i++ {
			v += v / over.CeilingGrowthDivisor
		}
		return v
	}(); violableAt(ladder28) {
		t.Fatalf("ladder rung 28 (T=%d) is violable after all; the note's whole point is that "+
			"passing the threshold and being able to fire are different things", ladder28)
	}
}

// TestB18BindsBeforeB5OnTheGasDensestFamily is what this file's
// TestB5RefusesABlockOfShapesThatHaveBeenBuilt became when B18, the per-block
// signature ceiling, was added, and the rename is the finding.
//
// That test built a block B5 refuses, at unmodified mainnet parameters, out
// of the gas-densest family the Era-0 program set admits: RETIRE of fifteen
// one-shot addresses paying its deposit from a sixteenth. That block carries
// sixteen signatures per certificate and 566 certificates, so it declares
// 9,056 signatures — above `max_sigs_per_block_genesis` = 6,000. **B18 is
// checked before the loop that verifies a signature and therefore before B5,
// so the witness it built is now refused by B18 and B5 never answers.**
//
// That is not a defect in either rule; it is the interaction B18's introduction
// produces and it belongs in a test rather than in a paragraph. **What it
// costs is stated plainly: the corpus no longer carries a B5 vector** — 061
// was retargeted to B18, which the same block now breaks — and this test no
// longer demonstrates B5 firing at shipped parameters. What replaces it is
// the measurement below.
//
// **The measurement, and the exact limit of what it claims.** The largest
// block of this family B18 admits is `MaxSigsPerBlock(T₀) / 16` certificates,
// and the test asserts that block declares strictly less than
// `SeqGasBurst(T₀) = 4T`. So along *this* axis B5 cannot be reached at all
// any more: not by this family at any count, at unmodified mainnet
// parameters. **It is NOT a claim that B5 is unreachable over the whole Era-0
// shape space.** That claim would need a census, and this tree's record on
// shape maxima is four published figures and four falsifications — so the
// honest statement is the existential's negation restricted to the family
// that used to witness it. A second implementation should read B5 as a live
// rule it must enforce, exactly as it reads B11 and B16, neither of which any
// vector reaches either.
//
// EXPECTED DIRECTION (PROTOCOL rule 22), declared before the run: the block of
// n+1 certificates must be REFUSED with `fold.Rule` naming **B18**, and the
// largest signature-admissible block of the family must declare strictly less
// than 4T. A refusal naming B5 would mean the ceiling does not bind first and
// B18's "checked before any signature is verified" is not what the code does;
// a signature-admissible block at or above 4T would mean B5 is still reachable
// on this family and this test should go back to being the B5 witness it was.
//
// The parameters are spec.Mainnet() unmodified, for the reason the retired
// conclusion turned on: a tightened copy would prove the arithmetic and
// not the shipped network.
func TestB18BindsBeforeB5OnTheGasDensestFamily(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	burst := p.SeqGasBurst(t0)

	// The gas-bound shape with the FEWEST certificates at its gas ceiling, so
	// the block is as cheap to build as the property allows: RETIRE of 15
	// one-shot addresses paying its deposit from a fresh one-shot cell, which
	// costs a sixteenth signature and a second MARK_SPENT and is the
	// gas-densest family in the sweep.
	build := func(i uint64) *types.Certificate {
		addrs := make([]types.Address, 0, 15)
		keys := make([]*wallet.Key, 0, 16)
		for j := uint64(0); j < 15; j++ {
			k := budgetKey(t, 0xb5, i*16+j)
			addrs = append(addrs, k.OneShot())
			keys = append(keys, k)
		}
		deposit := budgetKey(t, 0xb5, i*16+15)
		refund := budgetKey(t, 0xbe, 0).Persistent()
		return buildCert(t, p, wallet.Retire(addrs...),
			wallet.SweepDeposit(deposit.OneShot(), refund, drops(1_000_000)),
			append(append([]*wallet.Key{}, keys...), deposit)...)
	}

	one := build(0)
	perCert := one.SeqGas(p)
	perCertSigs := uint64(len(one.Sigs))
	n := int(burst / perCert)
	if n <= 0 {
		t.Fatalf("one certificate of this shape costs %d sequential gas against a 4T bound of %d",
			perCert, burst)
	}

	certs := make([]*types.Certificate, 0, n+1)
	certs = append(certs, one)
	for i := 1; i <= n; i++ {
		certs = append(certs, build(uint64(i)))
	}

	// The setup assertions are the anti-vacuity half, and they are stated
	// against the ceilings rather than against a remembered margin. The block
	// of n+1 must still be over 4T and under the byte and count ceilings, or
	// the rule that answers is not the one this test is about.
	var seqGas, sigs uint64
	for _, c := range certs {
		seqGas += c.SeqGas(p)
		sigs += uint64(len(c.Sigs))
	}
	if seqGas <= burst {
		t.Fatalf("%d certificates declare %d sequential gas, still inside the 4T bound of %d",
			len(certs), seqGas, burst)
	}
	size := (&types.Block{Certs: certs}).SizeBytes()
	if limit := p.BlockByteLimit(t0); size > limit {
		t.Fatalf("the block is %d bytes against a byte ceiling of %d: B13 refuses it before the "+
			"rule under test", size, limit)
	}
	if ceiling := p.MaxCertsPerBlock(t0); len(certs) > ceiling {
		t.Fatalf("the block carries %d certificates against a count ceiling of %d: B12 refuses it "+
			"first", len(certs), ceiling)
	}
	sigCeiling := p.MaxSigsPerBlock(t0)
	if sigs <= sigCeiling {
		t.Fatalf("the block declares %d signatures against a ceiling of %d: B18 does not bind "+
			"here and this test would be measuring B5 under another name", sigs, sigCeiling)
	}

	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()

	over, err := c.Propose(payout, certs...)
	if err != nil {
		t.Fatal(err)
	}
	err = fold.CheckBlockRules(c.State, over, p)
	if err == nil {
		t.Fatalf("a block of %d certificates declaring %d signatures was accepted against a "+
			"ceiling of %d: B18 is not enforced", len(certs), sigs, sigCeiling)
	}
	if got := fold.Rule(err); got != "B18" {
		t.Fatalf("the block was refused by %s, not B18 (%v): the signature ceiling does not "+
			"bind before the rule that answered, and B18's \"checked before any signature is "+
			"verified\" is not what the code does", ruleOrAssertion(got), err)
	}

	// And the consequence: the largest block of this family the signature
	// ceiling admits cannot reach 4T at all.
	admissible := sigCeiling / perCertSigs
	if got := admissible * perCert; got >= burst {
		t.Fatalf("the %d certificates B18 admits of this family declare %d sequential gas "+
			"against a 4T bound of %d: B5 is still reachable here and this test should be "+
			"TestB5RefusesABlockOfShapesThatHaveBeenBuilt again", admissible, got, burst)
	}
	t.Logf("B18 refuses %d certificates of %q at %d signatures against a ceiling of %d; the "+
		"largest admissible block of the family is %d certificates declaring %d sequential gas, "+
		"%.1f%% of the 4T bound of %d",
		len(certs), "RETIRE width=15 deposit=a-fresh-one-shot-cell", sigs, sigCeiling,
		admissible, admissible*perCert, 100*float64(admissible*perCert)/float64(burst), burst)
}

// ruleOrAssertion reads better than an empty string in a failure message, and
// the empty answer is the interesting one: it means the block was refused by
// an internal conservation assertion rather than by a named rule.
func ruleOrAssertion(rule string) string {
	if rule == "" {
		return "no rule (an internal assertion)"
	}
	return rule
}
