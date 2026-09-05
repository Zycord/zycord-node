package spec_test

import (
	"strings"
	"testing"

	"zycord/spec"
)

// TestTheCertListCapacityNoteStatesTheInEraWallItIsConditionedOn arms the two
// figures `spec/params.json`'s `cert_list_capacity` note states.
//
// **What was wrong.** The note said 2^25 certificates "is 1,118,481 per second
// at 30-second blocks, which maximal ceiling growth from the genesis rate of
// ~88 reaches in 13.6 years", full stop. Whitepaper 8.1 reaches that rate only
// under three named conditions and the note dropped them, so it published a
// reachability claim that is false as stated: within one era `T` is clamped at
// `seq_gas_capacity`, so `MaxCertsPerBlock` tops out at
// `max_certs_per_block_genesis x seq_gas_capacity / seq_gas_target_genesis` and
// goes no further, however long the chain runs. Only an era re-pin of
// `seq_gas_capacity` moves that wall. PROTOCOL.md rule 21: a stated limit that
// is wrong is worse than a missing one.
//
// **Why a test and not just the corrected sentence.** The corrected sentence
// carries two derived numbers — the in-era wall and its distance below the
// capacity — and both are functions of four parameters. A note is not
// recomputed when a parameter moves; it goes stale silently, which is the
// failure mode this whole family of notes has already suffered four times over
// a neighbouring number. So the figures are derived here from the shipped set
// and the note is required to be the document that agrees with them.
//
// **What it does NOT do.** It does not check the prose reads well, and it is
// not a spell-check on a comment. It fails in exactly two situations, both of
// which are somebody publishing a false number: the parameters move and the
// note does not, or the note is rewritten back toward the unconditioned claim.
// Neither is caught by anything else — the params hash pins the note's BYTES,
// which changes whenever the note is edited at all and says nothing about
// whether the edit was true.
func TestTheCertListCapacityNoteStatesTheInEraWallItIsConditionedOn(t *testing.T) {
	p, err := spec.ParamsFor("mainnet")
	if err != nil {
		t.Fatal(err)
	}

	// The wall itself, through the shipped ceiling function rather than through
	// a re-multiplication of the note's own words: T is clamped at
	// seq_gas_capacity by NextSeqGasTarget, so this is the largest count
	// ceiling any block inside one era can be judged against.
	inEra := p.MaxCertsPerBlock(p.SeqGasCapacity)
	if want := int(uint64(p.MaxCertsPerBlockGenesis) * p.SeqGasCapacity / p.SeqGasTargetGenesis); inEra != want {
		t.Fatalf("MaxCertsPerBlock(seq_gas_capacity) = %d, but the note's closed form gives %d; "+
			"the note explains the ceiling with a formula the ceiling does not follow", inEra, want)
	}
	if inEra >= p.CertListCapacity {
		t.Fatalf("the in-era count ceiling %d reaches cert_list_capacity %d, so the note's whole "+
			"point — that in-era growth cannot get there — is now false rather than merely "+
			"unstated", inEra, p.CertListCapacity)
	}
	factor := p.CertListCapacity / inEra

	// The note is required to carry both, in the thousands-separated form the
	// rest of the file writes numbers in.
	note, ok := p.Notes["cert_list_capacity"]
	if !ok {
		t.Fatal("spec/params.json has no cert_list_capacity note; the claim this test holds " +
			"is stated nowhere and the parameter is unexplained")
	}
	for _, want := range []string{
		// The condition, which is the half that was missing. Without it the
		// sentence is a reachability claim about a wall that does not move.
		"only across era re-pins of seq_gas_capacity",
		// The wall, and its distance below the capacity.
		commas(uint64(inEra)),
		commas(uint64(factor)) + "x below this capacity",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("the cert_list_capacity note does not contain %q.\n"+
				"At the shipped values the in-era count ceiling is %d and cert_list_capacity is "+
				"%dx above it. Either a parameter moved and the note was not recomputed, or the "+
				"note was rewritten back toward the unconditioned claim that the genesis "+
				"rate reaches this capacity in 13.6 years, which within one era it cannot.",
				want, inEra, factor)
		}
	}
	t.Logf("in-era count ceiling %d = %d x %d / %d, %dx below cert_list_capacity %d",
		inEra, p.MaxCertsPerBlockGenesis, p.SeqGasCapacity, p.SeqGasTargetGenesis,
		factor, p.CertListCapacity)
}

// commas renders a uint64 the way spec/params.json's notes write numbers, so a
// figure derived here and a figure written there are compared in one form
// rather than two.
func commas(n uint64) string {
	s := ""
	for n >= 1000 {
		s = "," + pad3(n%1000) + s
		n /= 1000
	}
	return itoa(n) + s
}

func pad3(n uint64) string {
	s := itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
