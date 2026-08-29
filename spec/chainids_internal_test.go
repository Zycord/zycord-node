package spec

import (
	"errors"
	"strings"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
)

// The property, in one sentence: **checkChainID refuses a retired id and a live
// id whose parameters derive a different genesis, and refuses nothing else.**
//
// This is the arm of the rule that the shipped ledger cannot exercise. The ledger
// in spec/chain-ids.json has no retired entry today — retiring one is what a
// respin does, and no network has been respun — so a test that only ran against
// the embedded file would report "retired ids are refused" having never seen a
// retired id. The table below hands checkChainID a ledger of its own, which is
// what makes each rule reachable, and the permitted cases are asserted here
// too: a guard that refuses everything is not a guard, and the cases it must
// let through are the ones an operator meets (a private network on a free id, a
// devnet respun this morning).
func TestCheckChainIDRefusesASpentID(t *testing.T) {
	pinned := crypto.Hash{0xaa, 0xbb, 0xcc}
	other := crypto.Hash{0xdd, 0xee, 0xff}
	pinnedHex := "0x" + hexOf(pinned)

	ledger := []ChainIDAllocation{
		{ChainID: 1, Network: "unfrozen", ParamsFile: "params.json", Status: StatusPreGenesis},
		{ChainID: 2, Network: "deployed", ParamsFile: "params.testnet.json",
			Status: StatusLive, GenesisID: &pinnedHex},
		{ChainID: 3, Network: "gone", ParamsFile: "params.old.json",
			Status: StatusRetired, GenesisID: &pinnedHex},
		{ChainID: 1337, Network: "throwaway", ParamsFile: "params.devnet.json",
			Status: StatusEphemeral},
		{ChainID: 7, Network: "unpinned-live", ParamsFile: "params.broken.json",
			Status: StatusLive},
		{ChainID: 8, Network: "nonsense", ParamsFile: "params.broken.json", Status: "someday"},
	}

	for _, tc := range []struct {
		name    string
		chainID uint64
		derives crypto.Hash
		wantErr error
		// A fragment of the refusal that must survive rewording, because an
		// operator who reads only the first line has to learn what to do.
		wantSays string
	}{
		{name: "a retired id is spent forever", chainID: 3, derives: pinned,
			wantErr: ErrChainIDSpent, wantSays: "retired"},
		{name: "a live id under a different genesis is a respin", chainID: 2, derives: other,
			wantErr: ErrChainIDSpent, wantSays: "spec/chain-ids.json"},
		{name: "a live id deriving its own pinned genesis is the network itself",
			chainID: 2, derives: pinned},
		{name: "a pre-genesis id pins nothing", chainID: 1, derives: other},
		{name: "an ephemeral id is respun by design", chainID: 1337, derives: other},
		{name: "an unallocated id is not this rule's business", chainID: 99, derives: other},
		{name: "a live entry with no pin cannot be enforced", chainID: 7, derives: pinned,
			wantErr: ErrChainIDLedger, wantSays: "no genesis id"},
		{name: "a status STATUS_VALUES does not define cannot be enforced", chainID: 8,
			derives: pinned, wantErr: ErrChainIDLedger, wantSays: "STATUS_VALUES"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &params.Params{ChainID: tc.chainID, Name: "under-test"}
			derived := 0
			err := checkChainID(ledger, p, func(*params.Params) (crypto.Hash, error) {
				derived++
				return tc.derives, nil
			})
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("chain id %d was refused: %v.\nRefusing an id the ledger has not "+
					"spent makes this node a gate on networks it has no claim over",
					tc.chainID, err)
			case tc.wantErr != nil && err == nil:
				t.Fatalf("chain id %d was accepted. The ledger says the id is spent, and a "+
					"startup that accepts it leaves the rule enforced only in "+
					"`go test ./spec` -- and never on the machine that runs the node, "+
					"which is the state the embedded ledger exists to end", tc.chainID)
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("refusal is %v; callers separate a spent id from a broken ledger "+
						"by errors.Is, so it must wrap %v", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantSays) {
					t.Errorf("the refusal reads %q and does not mention %q; an operator who "+
						"reads it has to learn what to change", err, tc.wantSays)
				}
			}
			// derive is the expensive half — it builds block 0 — so it runs
			// only where a pin exists to compare against, and it must run
			// there, or the live rule would pass by never looking.
			wantDerived := 0
			if tc.chainID == 2 {
				wantDerived = 1
			}
			if derived != wantDerived {
				t.Errorf("derive ran %d times, want %d", derived, wantDerived)
			}
		})
	}
}

// The embedded ledger is one this code can enforce: every entry it ships parses
// into a status checkChainID recognises, and every live entry carries a genesis
// id it can decode.
//
// Without this, ErrChainIDLedger would be a runtime surprise rather than a
// build-time one: a ledger edit that ships an undefined status or an
// unparseable pin is caught by `go test ./spec` here, instead of by an operator
// whose node refuses to start.
func TestTheEmbeddedLedgerIsEnforceable(t *testing.T) {
	allocations := ChainIDAllocations()
	if len(allocations) == 0 {
		t.Fatal("the embedded ledger allocates nothing; every check below is vacuous")
	}
	for _, a := range allocations {
		switch a.Status {
		case StatusPreGenesis, StatusEphemeral, StatusRetired:
		case StatusLive:
			if a.GenesisID == nil {
				t.Errorf("chain id %d (%s) is live with no pinned genesis id; CheckChainID "+
					"would refuse to start a node on it", a.ChainID, a.Network)
				continue
			}
			if _, err := decodeChainIDHash(*a.GenesisID); err != nil {
				t.Errorf("chain id %d (%s) genesis id %q: %v", a.ChainID, a.Network, *a.GenesisID, err)
			}
		default:
			t.Errorf("chain id %d (%s) has status %q, which STATUS_VALUES does not define; "+
				"CheckChainID cannot say whether the id is spent and refuses to guess",
				a.ChainID, a.Network, a.Status)
		}
	}
}

// The embedded ledger and the embedded parameter files are the same bytes the
// binary enforces against: ChainIDsJSON hands back what is compiled in, and a
// copy of it, so a caller cannot edit the ledger this process checks against.
func TestChainIDsJSONIsACopyOfTheEmbeddedLedger(t *testing.T) {
	raw := ChainIDsJSON()
	if string(raw) != string(chainIDsJSON) {
		t.Fatal("ChainIDsJSON does not return the embedded bytes")
	}
	if len(raw) == 0 {
		t.Fatal("the embedded ledger is empty")
	}
	raw[0] = 'X'
	if chainIDsJSON[0] == 'X' {
		t.Fatal("ChainIDsJSON aliases the embedded ledger; a caller can rewrite the rule " +
			"this binary enforces")
	}
}

func hexOf(h crypto.Hash) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(h))
	for _, b := range h {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}
