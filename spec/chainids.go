package spec

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"zycord/core/crypto"
	"zycord/core/params"
)

// The chain-id ledger, embedded.
//
// spec/chain-ids.json states that a chain id is allocated once and never
// reused, and spec/chainid_allocation_test.go holds the parameter files THIS
// REPOSITORY SHIPS to it. That is a build-time instrument, and it leaves one
// gap: `zycordd --params /etc/zycord/params.testnet.json` takes whatever
// file an operator hands it, params.Validate has no ledger, and an operator who
// respins a network by editing a deployed copy never runs `go test ./spec`. The
// rule lived in the repository and the hazard lives on a machine.
//
// Embedding the ledger the same way the parameter files are embedded is what
// closes that: a binary and the ledger it was built from can never drift apart,
// so CheckChainID below is an answer the node can give about the file in front
// of it rather than one somebody had to remember to ask in CI.

//go:embed chain-ids.json
var chainIDsJSON []byte

// ChainIDsJSON returns the raw bytes of spec/chain-ids.json. It is exported for
// the same reason MainnetJSON is: a second implementation reads the ledger to
// learn which networks exist, and reading it out of the binary is the only way
// to be sure it is the one that binary enforces.
func ChainIDsJSON() []byte { return append([]byte(nil), chainIDsJSON...) }

// Ledger status values, as spec/chain-ids.json's STATUS_VALUES defines them.
const (
	// StatusPreGenesis: parameters still moving, block 0 never produced.
	// genesis_id is null because there is nothing to pin.
	StatusPreGenesis = "pre-genesis"
	// StatusLive: deployed, parameters frozen, genesis_id recorded and equal to
	// the id the parameter file derives today.
	StatusLive = "live"
	// StatusRetired: the network is gone and its id is spent forever.
	StatusRetired = "retired"
	// StatusEphemeral: an id reserved for throwaway local networks respun
	// freely by design. genesis_id is null because there is no single genesis.
	StatusEphemeral = "ephemeral"
)

// ChainIDAllocation is one entry of spec/chain-ids.json's "allocations".
//
// Only the machine-checked fields are decoded. The prose keys beside them carry
// the argument for the rule and are read by people, which is why this struct
// deliberately does not mirror the whole file.
type ChainIDAllocation struct {
	ChainID    uint64  `json:"chain_id"`
	Network    string  `json:"network"`
	ParamsFile string  `json:"params_file"`
	Status     string  `json:"status"`
	GenesisID  *string `json:"genesis_id"`
}

type chainIDLedger struct {
	Allocations []ChainIDAllocation `json:"allocations"`
}

// ChainIDAllocations returns the ledger this binary was built from, in file
// order.
//
// A malformed embedded ledger panics for the reason mustParse does: it is a
// broken build and not a runtime condition, and a node that shrugged and
// carried on would be one whose chain-id refusal is silently absent — the exact
// state embedding the ledger exists to end.
func ChainIDAllocations() []ChainIDAllocation {
	l := mustParseChainIDs()
	return append([]ChainIDAllocation(nil), l.Allocations...)
}

// ChainIDAllocationFor returns the entry allocating an id, if the ledger has
// one.
func ChainIDAllocationFor(chainID uint64) (ChainIDAllocation, bool) {
	for _, a := range mustParseChainIDs().Allocations {
		if a.ChainID == chainID {
			return a, true
		}
	}
	return ChainIDAllocation{}, false
}

// ErrChainIDSpent reports a parameter set whose chain id the ledger has spent:
// either the id is retired, or it is live under a different genesis.
var ErrChainIDSpent = errors.New("spec: chain id is spent")

// ErrChainIDLedger reports an embedded ledger this code cannot enforce — a live
// entry with no pinned genesis, or a status STATUS_VALUES does not define.
var ErrChainIDLedger = errors.New("spec: chain-ids.json is inconsistent")

// CheckChainID refuses a parameter set whose chain id spec/chain-ids.json has
// already spent. It is the runtime half of the allocation rule — the half that
// answers about the file an operator actually handed this binary — and the two
// refusals are exactly the two the ledger can prove:
//
//   - The id is RETIRED. That network is gone and the id went with it.
//     Certificates naming it still pass V1 on any successor, so a successor
//     holding the id is the reuse the ledger exists to refuse.
//   - The id is LIVE and this parameter set derives a different genesis id from
//     the one pinned against it. That is a respin — or a fork — holding on to a
//     spent id. The signing message binds the consensus root as well as the
//     chain id, so the predecessor's certificates fail V2 on the successor —
//     but two networks still answer to one id in every certificate, every log
//     line and every operator's --params file.
//
// Everything else is permitted, and each omission is deliberate:
//
//   - An id the ledger does not allocate is not this rule's business. A private
//     network on an id nobody here has spent is exactly what the "take the
//     lowest free id" rule leaves room for, and refusing it would make the node
//     a gate on other people's networks rather than a guard on ours.
//   - pre-genesis and ephemeral pin no genesis, so there is nothing to compare
//     against. STATUS_VALUES says why in both cases, and for ephemeral it is
//     the point: a devnet is respun freely and a pin there would fire on every
//     routine parameter edit.
//
// derive is how the genesis id is computed — normally genesis.NetworkID. It is
// a parameter rather than an import because this package CANNOT import
// core/genesis: genesis imports core/fold, and core/fold's internal tests
// (package fold) import spec, so the import would make that test binary a
// cycle. It is called at most once, and only for a live entry.
func CheckChainID(p *params.Params, derive func(*params.Params) (crypto.Hash, error)) error {
	return checkChainID(mustParseChainIDs().Allocations, p, derive)
}

func checkChainID(allocations []ChainIDAllocation, p *params.Params,
	derive func(*params.Params) (crypto.Hash, error)) error {

	var a ChainIDAllocation
	found := false
	for _, cand := range allocations {
		if cand.ChainID == p.ChainID {
			a, found = cand, true
			break
		}
	}
	if !found {
		return nil
	}

	switch a.Status {
	case StatusPreGenesis, StatusEphemeral:
		return nil
	case StatusRetired:
		return fmt.Errorf("%w: chain id %d was allocated to %s (%s) and is retired. "+
			"An id is allocated once and never reused -- not by a respin of a network and "+
			"not by a fork of one -- because certificates of the retired chain still name "+
			"this id and still pass V1 against a successor holding it. Allocate the lowest "+
			"free id in spec/chain-ids.json and add an entry for this network",
			ErrChainIDSpent, a.ChainID, a.Network, a.ParamsFile)
	case StatusLive:
		if a.GenesisID == nil {
			return fmt.Errorf("%w: chain id %d is %q with no genesis id, so the pin that "+
				"catches a respin cannot be compared. A network that has run has an identity; "+
				"record it in spec/chain-ids.json", ErrChainIDLedger, a.ChainID, a.Status)
		}
		want, err := decodeChainIDHash(*a.GenesisID)
		if err != nil {
			return fmt.Errorf("%w: chain id %d genesis id %q: %v",
				ErrChainIDLedger, a.ChainID, *a.GenesisID, err)
		}
		got, err := derive(p)
		if err != nil {
			return fmt.Errorf("spec: deriving the genesis id of chain %d: %w", p.ChainID, err)
		}
		if got != want {
			return fmt.Errorf("%w: chain id %d is allocated to %s, whose genesis id is %x, "+
				"and these parameters derive %x. This is a respin -- or a fork -- holding on "+
				"to a spent chain id. The signing message binds the consensus root as well as "+
				"the chain id, so the predecessor's certificates fail V2 here rather than "+
				"being billed, but the id is still spent and two networks still "+
				"answer to one id in every certificate, every log line and every operator's "+
				"--params file. Allocate a new chain id, retire %d in spec/chain-ids.json, "+
				"and add an entry for this network",
				ErrChainIDSpent, a.ChainID, a.Network, want, got, a.ChainID)
		}
		return nil
	default:
		return fmt.Errorf("%w: chain id %d has status %q, which STATUS_VALUES does not "+
			"define, so this binary cannot say whether the id is spent",
			ErrChainIDLedger, a.ChainID, a.Status)
	}
}

func mustParseChainIDs() chainIDLedger {
	var l chainIDLedger
	// Unknown fields are allowed on purpose: the prose keys beside the
	// allocations are the argument for the rule, and they are read by people.
	if err := json.Unmarshal(chainIDsJSON, &l); err != nil {
		panic(fmt.Sprintf("spec: chain-ids.json does not parse: %v", err))
	}
	if len(l.Allocations) == 0 {
		panic("spec: chain-ids.json allocates nothing; every chain id would look free")
	}
	return l
}

func decodeChainIDHash(s string) (crypto.Hash, error) {
	var h crypto.Hash
	trimmed := strings.TrimPrefix(s, "0x")
	if len(trimmed) != 2*len(h) {
		return h, fmt.Errorf("is %d hex digits, not %d", len(trimmed), 2*len(h))
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}
