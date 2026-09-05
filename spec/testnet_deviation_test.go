package spec_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"zycord/spec"
)

// theSixDeviations is the whole of what spec/params.testnet.json's PURPOSE note
// permits itself: the testnet is mainnet in every value but these, and each one
// has its own entry in that file's `notes` block explaining why it moved.
var theSixDeviations = []string{
	"name",
	"chain_id",
	"genesis_target",
	"max_target",
	"genesis_time",
	"randomx_key_interval",
}

// TestTheTestnetDeviatesFromMainnetInExactlySixValues arms the claim the
// testnet's PURPOSE note makes, at the level the claim is made at.
//
// **What went wrong without it.** The PURPOSE note said "it deviates from
// spec/params.json in SIX values and nowhere else" and it was true when written.
// A later mainnet respin then moved three gas values — par_gas_ratio,
// seq_gas_target_genesis and seq_gas_capacity — and the testnet file was not
// moved with them, so the count silently became nine and nothing failed. The
// defect was found by reading rather than by any check, and carried for weeks,
// during which docs/TESTNET.md had to carry a "read this section, not that one"
// pointer at the file's own note. A second respin put the three gas fields back;
// this test is what stops the next mainnet-side move from opening the same gap
// in silence.
//
// **Why the raw bytes and not the parsed struct.** The note claims byte
// identity, and byte identity is a property of the files rather than of what a
// decoder makes of them. Comparing `json.RawMessage` per key catches a value
// re-spelled into an equal number as readily as a changed one, and it needs no
// maintenance when a parameter is added: a new field lands in both files or it
// lands in the deviation set, and either way this test has an opinion.
//
// **Anti-vacuity.** A test that only counted the differences would pass on any
// six, so the six are named. The `notes` block is excluded from the comparison
// for the reason the whole gas-drift argument turns on: `ConsensusRoot` excludes
// notes by tag, the announced params hash does not, and the notes SHOULD differ
// — the testnet file explains what moved and refers the reader to mainnet's for
// everything else.
func TestTheTestnetDeviatesFromMainnetInExactlySixValues(t *testing.T) {
	mainnet := keyedFields(t, spec.MainnetJSON(), "spec/params.json")
	testnet := keyedFields(t, spec.TestnetJSON(), "spec/params.testnet.json")

	deviating := map[string]bool{}
	for k, mv := range mainnet {
		tv, ok := testnet[k]
		if !ok || !bytes.Equal(mv, tv) {
			deviating[k] = true
		}
	}
	for k := range testnet {
		if _, ok := mainnet[k]; !ok {
			deviating[k] = true
		}
	}

	want := map[string]bool{}
	for _, k := range theSixDeviations {
		want[k] = true
		if _, ok := testnet[k]; !ok {
			t.Fatalf("spec/params.testnet.json has no %q field at all, so the deviation its "+
				"PURPOSE note names cannot be checked", k)
		}
	}

	for k := range deviating {
		if !want[k] {
			t.Errorf("%q differs between spec/params.json and spec/params.testnet.json, and it "+
				"is not one of the six the PURPOSE note permits (%s).\n"+
				"mainnet: %s\ntestnet: %s\n"+
				"Either the testnet must move with mainnet — which is a respin, because the "+
				"field is in the consensus root — or the note and docs/TESTNET.md must stop "+
				"claiming byte identity. Doing neither is how the count silently became nine "+
				"and the note went on publishing six.",
				k, strings.Join(theSixDeviations, ", "), mainnet[k], testnet[k])
		}
	}
	for k := range want {
		if !deviating[k] {
			t.Errorf("%q is byte-identical to mainnet's, but the testnet PURPOSE note counts it "+
				"as one of the six deviations. A deviation that stopped deviating is a note "+
				"that now over-counts; drop it from the note and from this test together.", k)
		}
	}

	// The three the respin restored, named on their own so a regression reports
	// as itself rather than as an arithmetic surprise about a count.
	for _, gas := range []string{"par_gas_ratio", "seq_gas_target_genesis", "seq_gas_capacity"} {
		if !bytes.Equal(mainnet[gas], testnet[gas]) {
			t.Errorf("the testnet's %s is %s against mainnet's %s. The gas schedule is what the "+
				"testnet exists to measure (docs/decisions/testnet-measurements.md); a testnet "+
				"carrying a different one measures its own economics, which is exactly the state "+
				"the network was respun out of.", gas, testnet[gas], mainnet[gas])
		}
	}

	// The note is the document the claim is published in, so it has to still be
	// making it. "SIX" is upper-cased in the file and is checked in that form.
	p := spec.Testnet()
	purpose, ok := p.Notes["PURPOSE"]
	if !ok {
		t.Fatal("spec/params.testnet.json has no PURPOSE note, so the byte-identity claim this " +
			"test holds is published nowhere")
	}
	if !strings.Contains(purpose, "SIX values and nowhere else") {
		t.Errorf("the testnet PURPOSE note no longer says \"SIX values and nowhere else\".\n"+
			"The files deviate in exactly %s, so the claim is true and should be stated; "+
			"restating it vaguely is narrowing a claim to buy quiet, which this project "+
			"does not do: a weaker true sentence hides the same drift.",
			strings.Join(sortedKeys(deviating), ", "))
	}
	// Each of the six has to be explained where the note says it is explained.
	for _, k := range theSixDeviations {
		if _, ok := p.Notes[k]; !ok {
			t.Errorf("%q deviates from mainnet but spec/params.testnet.json's notes block has no "+
				"entry for it, so the PURPOSE note's \"this file only explains what moved\" is "+
				"false for it", k)
		}
	}
}

// keyedFields decodes a parameter file into its top-level fields, keeping each
// value's raw bytes, and drops `notes` — the one member that is meant to differ.
func keyedFields(t *testing.T, raw []byte, name string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("%s is not decodable as a JSON object: %v", name, err)
	}
	delete(fields, "notes")
	if len(fields) == 0 {
		t.Fatalf("%s decoded to no comparable fields, so this test would pass vacuously", name)
	}
	return fields
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
