package validity_test

import (
	"bytes"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

// The free-runs record.
//
// An audit measured a property of the ISSUE certificate and left it as prose:
// of the four 32-byte fields of IssueArgs, THREE are chosen freely by the
// signer — Cap (one excluded value out of 2^256), SymbolHash (no rule at all)
// and Minter (a rule that exists, but on ProgramMint, not here) — and every
// one of them reaches durable state VERBATIM, TWICE: once inside the encoded
// block body the store writes, and once again as the value of a state cell.
//
// The direction that closes it is NOT a validity rule per field. That was
// measured out when the finding was taken: three fields, three different
// reasons to be unconstrained, one program of four, and the reader is where
// the count of carriers stops mattering. The reader side was taken instead —
// recordMagic is escaped out of every payload node/storage writes, and
// node/chain's TestNoDurableWriteBeginsAPayloadWithAttackerChosenBytes arms
// the clause that makes the residual unpayable. A format constraint on these
// three cells would be consensus-affecting and therefore a
// genesis-or-era-boundary change, and none is taken.
//
// What is left is the measurement, and an unfixed measurement is a claim with
// a shelf life: it is true about the tree it was taken on, and nothing says
// when it stops being true. This file fixes it. It asserts what the
// reader-side argument quotes from that measurement — the runs are free, they
// are contiguous, and each lands twice — so the day any of that changes, the
// change is announced here rather than discovered on the storage side.
//
// If this file fails because a rule was added over one of the three fields:
// that is not a bug in the test. It is a consensus-surface change, and both
// this measurement and the reader-side escaping argument that rests on it
// have to be re-read before it ships.

// freeRun is one of the three runs, with the reason it is free stated next to
// it rather than in a paragraph above the table.
type freeRun struct {
	field string
	// why is the rule that does NOT constrain this field, quoted from where
	// the absence lives.
	why string
	// bytes are the 32 the signer chose for this field in the fixture below.
	bytes [32]byte
	// slot is the durable cell the derivation writes the same 32 bytes into.
	slot func(asset types.Address) types.Slot
}

// marker32 builds a distinct high-entropy 32-byte run per field. High entropy
// so that a four-byte coincidence against an unrelated part of the encoding
// would be a deterministic failure that can be re-rolled, not a flake; three
// distinct runs so that finding one is never evidence about another.
func marker32(tag byte) [32]byte {
	var b [32]byte
	for i := range b {
		b[i] = byte(int(tag)*31 ^ (i*37 + 0x5B))
	}
	// Keep the top byte away from zero: Cap carries one of these as a u256,
	// and a leading zero would make "contiguous 32 bytes" a claim about a
	// shorter run than the one being measured.
	b[0] |= 0x80
	return b
}

// TestTheThreeFreeRunsOfAnIssueAreFreeContiguousAndPersistedTwice is that
// record, fixed.
//
// It is one test rather than three because the three facts are one claim: the
// bytes are unconstrained AT the validator, they survive CONTIGUOUS through
// the block encoding the store writes, and they reappear VERBATIM as durable
// state cells. Any one of them alone is not what the reader-side argument
// quotes.
func TestTheThreeFreeRunsOfAnIssueAreFreeContiguousAndPersistedTwice(t *testing.T) {
	p := spec.Devnet()
	issuer := key(t, 9)

	runs := []freeRun{
		{
			field: "Cap",
			why:   "derive.go's deriveIssue rejects only args.Cap.IsZero() — one excluded value out of 2^256",
			bytes: marker32(1),
			slot:  types.AssetCapSlot,
		},
		{
			field: "SymbolHash",
			why:   "no rule anywhere: a symbol hash is opaque by design and every value is as legal as every other",
			bytes: marker32(2),
			slot:  types.AssetSymbolSlot,
		},
		{
			field: "Minter",
			why:   "validity.go's authorisation rule requires a signature by Mint.Minter, on ProgramMint; Issue.Minter is signed for by nobody",
			bytes: marker32(3),
			slot:  types.AssetMinterSlot,
		},
	}

	var symbol types.Hash
	copy(symbol[:], runs[1].bytes[:])
	var minter types.PubKey
	copy(minter[:], runs[2].bytes[:])
	prog := wallet.Issue(issuer.Persistent(), u256.FromBytes(runs[0].bytes), 8, symbol, minter)

	const seq = 0
	cert, err := (&wallet.Builder{
		Params:  p,
		Program: prog,
		Seq:     seq,
		TTL:     100,
		Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{issuer},
	}).Build()
	if err != nil {
		t.Fatalf("wallet.Builder refused an ISSUE carrying three chosen 32-byte runs: %v", err)
	}

	// (1) FREE. Asserted through the whole stateless validator rather than by
	// reading derive.go, because "no rule constrains this" is a statement
	// about every rule, and only Check knows them all.
	if err := validity.Check(cert, p); err != nil {
		t.Fatalf("the validator now refuses an ISSUE whose Cap, SymbolHash and Minter are chosen "+
			"freely: %v\n"+
			"That is a change to what a signer may put in a durable cell, which is a consensus "+
			"surface: it belongs at genesis or an era boundary, and both this measurement and "+
			"node/storage's payload-escaping argument rest on the fields being unconstrained. "+
			"Re-read them before taking this.", err)
	}

	// (2) CONTIGUOUS, in the certificate and in the block body the store
	// writes. IssueArgs.MarshalSSZ is the inner encoding; Block.MarshalSSZ is
	// the byte string node/chain hands to node/storage as one value.
	args := cert.Program.Issue.MarshalSSZ()
	blk := &types.Block{Certs: []*types.Certificate{cert}}
	body := blk.MarshalSSZ()

	for _, r := range runs {
		at := bytes.Index(args, r.bytes[:])
		if at < 0 {
			t.Fatalf("%s (%s): the 32 chosen bytes are not contiguous in IssueArgs.MarshalSSZ",
				r.field, r.why)
		}
		if n := bytes.Count(args, r.bytes[:]); n != 1 {
			t.Fatalf("%s: %d contiguous copies in IssueArgs.MarshalSSZ, want exactly 1", r.field, n)
		}
		inBody := bytes.Index(body, r.bytes[:])
		if inBody < 0 {
			t.Fatalf("%s: the run is contiguous in the certificate but not in Block.MarshalSSZ, "+
				"which is the byte string a node persists", r.field)
		}
		t.Logf("%s: contiguous at IssueArgs offset %d of %d, and at block offset %d of %d",
			r.field, at, len(args), inBody, len(body))
	}

	// (3) TWICE. The second landing is the state cell, and it is the one that
	// has nothing to do with the block body: u256.FromBytes(x).Bytes() is x,
	// so the store writes the same 32 bytes again as a value of their own.
	asset := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), seq)
	_, writes, err := validity.Derive(cert.Program, p.ChainID, seq)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		slot := r.slot(asset)
		var found *types.Write
		for i := range writes {
			if writes[i].Slot == slot {
				found = &writes[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("%s: the derivation writes no cell at the slot this run lands in", r.field)
		}
		got := found.Value.Bytes()
		if !bytes.Equal(got[:], r.bytes[:]) {
			t.Fatalf("%s: the durable cell holds %x, not the 32 bytes the signer chose (%x). "+
				"The second verbatim copy is what node/storage's payload-escaping argument "+
				"quotes from this measurement; if the value is now derived or "+
				"domain-separated, say so in both places.",
				r.field, got, r.bytes)
		}
	}

	// Direction control (rule 22). Every row above came back positive; a
	// search that finds anything would report exactly the same. A fourth run,
	// built the same way and never put in the certificate, must be absent from
	// both encodings and from every write.
	absent := marker32(4)
	if bytes.Contains(args, absent[:]) || bytes.Contains(body, absent[:]) {
		t.Fatal("a 32-byte run that was never put in the certificate was found in its encoding, " +
			"so the searches above are not evidence of anything")
	}
	for _, w := range writes {
		v := w.Value.Bytes()
		if bytes.Equal(v[:], absent[:]) {
			t.Fatal("a run that was never put in the certificate turned up as a durable cell value")
		}
	}
}

// TestTheFourthFieldOfAnIssueIsNotFree is the other half of the partition, and
// it exists so the test above cannot be read as "nothing in ISSUE is checked".
//
// Issuer is the one 32-byte field of IssueArgs that a signer does NOT choose
// freely: it must be a user address, and V4 requires a signature binding it.
// Cap's single excluded value is checked here too, because "free apart from
// zero" is the precise claim and an unqualified "free" would be wrong.
func TestTheFourthFieldOfAnIssueIsNotFree(t *testing.T) {
	p := spec.Devnet()
	issuer := key(t, 9)
	var symbol types.Hash
	var minter types.PubKey

	// A non-user issuer: the derivation refuses it, so the field cannot carry
	// 32 chosen bytes the way the other three can.
	assetShaped := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), 0)
	if _, _, err := validity.Derive(
		wallet.Issue(assetShaped, u256.FromUint64(1), 0, symbol, minter), p.ChainID, 0,
	); err == nil {
		t.Fatal("the derivation accepted an ISSUE whose Issuer is not a user address, so Issuer " +
			"is now a fourth free run and this file's count of three is stale")
	}

	// Cap's one excluded value.
	if _, _, err := validity.Derive(
		wallet.Issue(issuer.Persistent(), u256.Zero, 0, symbol, minter), p.ChainID, 0,
	); err == nil {
		t.Fatal("the derivation accepted a zero cap, so Cap's single constraint is gone and the " +
			"field is free without qualification")
	}
}
