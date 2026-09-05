package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zycord/spec"
)

// The property, in one sentence: **a node refuses to start on a parameter file
// that reuses a chain id the embedded ledger has already spent.**
//
// spec/chain-ids.json's rule — an id is allocated once and never reused — was
// enforced only by `go test ./spec`, which binds the parameter files this
// repository ships. `zycordd --params /etc/zycord/params.testnet.json` takes
// whatever file an operator hands it, and params.Validate has no ledger, so
// the operator who respins the testnet by editing their deployed copy is the
// one case the rule was written for and the one case nothing was checking.
// This test drives the real startup path, on the real embedded ledger, with a
// file on disk — because every one of those was where the gap was.
func TestANodeRefusesToStartOnARespunChainID(t *testing.T) {
	// The respin, performed the way an operator performs it: take the file the
	// testnet runs on, change the launch date, keep the chain id. The testnet
	// parameter file's own prose tells them to do the first two ("Reset this to
	// the actual launch day if this testnet is ever restarted from genesis")
	// and says nothing about the third, which is exactly why the refusal has to
	// live in the binary.
	respun := respinTestnetFile(t)

	// Taken from the shipped file rather than written down here. The testnet's id
	// moves whenever the testnet is respun -- it has already gone 2 -> 3 once for
	// that reason, and the ledger's own rule guarantees it moves again at the
	// next one -- so a literal here would turn every future respin into a failure
	// of this test rather than of the thing it guards.
	id := spec.Testnet().ChainID

	_, err := loadParams(respun, false, false)
	if err == nil {
		t.Fatalf("the node accepted %s and would have started on it. Two networks then answer "+
			"to chain id %d in every certificate, every log line and every operator's --params "+
			"file, which is what spec/chain-ids.json refuses", respun, id)
	}
	// The refusal has to name the ledger, because the fix is an edit to it: the
	// operator has to allocate a new id and retire the old entry, and an error
	// that only said "refused" would send them to the wrong file.
	for _, want := range []string{fmt.Sprintf("chain id %d", id), "spec/chain-ids.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal reads %q and does not mention %q; an operator who reads it "+
				"has to learn which id is spent and where to allocate a new one", err, want)
		}
	}
}

// The anti-vacuity, and the compatibility half in one: the SAME file,
// unedited, still starts. A guard that refused every --params file would pass
// the test above while making the flag useless, and an operator running the
// testnet from a copy on disk — which is how it was joined before --testnet
// existed — must not be locked out by a rule about respins.
func TestANodeStillStartsOnAnUneditedParamsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "params.testnet.json")
	if err := os.WriteFile(path, spec.TestnetJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := loadParams(path, false, false)
	if err != nil {
		t.Fatalf("a node was refused the testnet's own parameter file: %v", err)
	}
	// Same reason as above: the live testnet id is read off the shipped file, so
	// this stays an assertion that loadParams returned THAT network rather than
	// an assertion about which respin the testnet is currently on. It is still
	// non-vacuous -- mainnet is 1 and devnet 1337, so a loader handing back the
	// wrong embedded file fails here.
	if want := spec.Testnet().ChainID; p.ChainID != want {
		t.Fatalf("loaded chain id %d from the testnet parameter file, want %d", p.ChainID, want)
	}
}

// respinTestnetFile writes the embedded testnet parameters to a temporary file
// with genesis_time moved by a day and the chain id untouched, and returns the
// path.
//
// It edits the JSON rather than a parsed Params so that what reaches loadParams
// is a file an operator could have written, which is the whole subject here.
func respinTestnetFile(t *testing.T) string {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(spec.TestnetJSON(), &doc); err != nil {
		t.Fatal(err)
	}
	raw, ok := doc["genesis_time"]
	if !ok {
		t.Fatal("the testnet parameter file has no genesis_time; this respin cannot be built")
	}
	var t0 uint64
	if err := json.Unmarshal(raw, &t0); err != nil {
		t.Fatal(err)
	}
	moved, err := json.Marshal(t0 + 86400)
	if err != nil {
		t.Fatal(err)
	}
	doc["genesis_time"] = moved

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "params.testnet.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
