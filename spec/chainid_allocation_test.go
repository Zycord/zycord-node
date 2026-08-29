package spec_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"zycord/core/crypto"
	"zycord/core/genesis"
	"zycord/spec"
)

// The allocation ledger, spec/chain-ids.json. Only the machine-checked fields
// are decoded; the prose keys beside them carry the argument and are read by
// people, so this struct deliberately does not mirror the whole file.
type chainIDLedger struct {
	Allocations []chainIDAllocation `json:"allocations"`
}

type chainIDAllocation struct {
	ChainID    uint64  `json:"chain_id"`
	Network    string  `json:"network"`
	ParamsFile string  `json:"params_file"`
	Status     string  `json:"status"`
	GenesisID  *string `json:"genesis_id"`
}

const (
	statusPreGenesis = "pre-genesis"
	statusLive       = "live"
	statusRetired    = "retired"
	statusEphemeral  = "ephemeral"
)

// TestChainIDsAreAllocatedOnce is the instrument behind spec/chain-ids.json's
// rule: a chain id is allocated once and never reused.
//
// It exists because the check that was already here cannot see the threat.
// TestParamsAreValid refuses two *embedded* networks that share a chain id,
// which is a cross-sectional check over the networks shipping right now. The
// hazard this ledger exists for is temporal: a testnet respin rewrites
// spec/params.testnet.json, keeps chain_id 2, and pairwise distinctness still
// passes because there is still only one testnet.
//
// What that used to mean was that the dead testnet's certificates were valid on
// the new one: V1 compared chain ids and passed, V2 verified a signature over
// blake3(TagSig || chain_id || cert_body_root) and passed, and the certificate
// was billed. The preimage now carries the consensus root as well, so a respin
// -- which always moves genesis_time -- fails V2 instead. **The ledger is not
// redundant because of it, and the reason is the one case the preimage cannot
// reach**: two incarnations whose parameter VALUES are identical derive the
// same consensus root, so nothing in a signature can tell them apart. An id
// handed to such a network is exactly the reuse this ledger refuses, and it is
// refusable only outside the protocol.
//
// So the ledger pins what the params file cannot: which genesis each spent id
// was spent on. A rewritten parameter file that keeps its id produces a
// different genesis id, and R4 below fails on the difference.
//
// This file is the REVIEW-TIME arm. The startup arm is spec.CheckChainID,
// which reads the same embedded ledger and refuses to bring a node up on a
// retired id or on a live id deriving the wrong genesis — that is what
// reaches the file an operator hands to --params, which no test here can see.
// The two are held to each other by TestEveryEmbeddedNetworkPassesTheStartupCheck.
//
// What this is NOT: a lock. Somebody may edit a pinned genesis id in the same
// commit that respins the network, and both arms will pass. The point is that
// doing so is then a deliberate line in a diff that says "I am reusing a spent
// chain id", instead of the silent default it is today.
func TestChainIDsAreAllocatedOnce(t *testing.T) {
	ledger := loadChainIDLedger(t)

	// R1: the ledger is non-empty and its ids are pairwise unique. Emptiness is
	// checked first because every rule below quantifies over the entries, and a
	// ledger that failed to decode into anything would satisfy all of them.
	if len(ledger.Allocations) == 0 {
		t.Fatal("spec/chain-ids.json allocates nothing; every check below would pass vacuously")
	}
	byID := map[uint64]chainIDAllocation{}
	for _, a := range ledger.Allocations {
		if prev, dup := byID[a.ChainID]; dup {
			t.Fatalf("R1: chain id %d is allocated twice in the ledger, to %q and to %q; "+
				"an id is allocated once and never reused", a.ChainID, prev.Network, a.Network)
		}
		byID[a.ChainID] = a
	}

	// R3: status and genesis_id agree. This is what stops a null genesis id
	// from meaning two different things. A null is legal only under a status
	// that says there is nothing to pin -- so "not yet allocated" is a claim
	// somebody wrote down, and never the absence of one.
	for _, a := range ledger.Allocations {
		switch a.Status {
		case statusLive, statusRetired:
			if a.GenesisID == nil {
				t.Errorf("R3: chain id %d (%s) is %q with no genesis id; a network that has "+
					"run has an identity, and an unpinned one is an id nobody can prove was "+
					"not reused", a.ChainID, a.Network, a.Status)
				continue
			}
			if _, err := decodeLedgerHash(*a.GenesisID); err != nil {
				t.Errorf("R3: chain id %d (%s) genesis id %q: %v", a.ChainID, a.Network, *a.GenesisID, err)
			}
		case statusPreGenesis, statusEphemeral:
			if a.GenesisID != nil {
				t.Errorf("R3: chain id %d (%s) is %q but pins genesis id %s; a network whose "+
					"block 0 is not fixed cannot have a true one recorded, so this is a stale "+
					"value that would be compared against and believed",
					a.ChainID, a.Network, a.Status, *a.GenesisID)
			}
		default:
			t.Errorf("R3: chain id %d (%s) has status %q, which spec/chain-ids.json's "+
				"STATUS_VALUES does not define", a.ChainID, a.Network, a.Status)
		}
	}

	files := embeddedParamsFiles(t)
	live := 0

	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}

		// R2: every embedded network holds an id the ledger allocated to it, by
		// name and by file. This is the arm that fires on the cheapest respin
		// of all -- a new network dropped into the old network's parameter file
		// with the old network's chain id still in it.
		a, ok := byID[p.ChainID]
		if !ok {
			t.Errorf("R2: %s ships chain id %d, which spec/chain-ids.json does not allocate; "+
				"an id in use and not in the ledger is an id the ledger cannot stop somebody "+
				"reusing", name, p.ChainID)
			continue
		}
		if a.Network != p.Name {
			t.Errorf("R2: chain id %d is allocated to network %q, but %s ships it under the "+
				"name %q. A different name is a different network, and a different network "+
				"needs its own chain id -- reusing this one puts %q's certificates through V1 "+
				"here",
				p.ChainID, a.Network, name, p.Name, a.Network)
		}
		if got := files[name]; a.ParamsFile != got {
			t.Errorf("R2: chain id %d is allocated to %s, but the network shipping it is "+
				"embedded from %s", p.ChainID, a.ParamsFile, got)
		}
		if a.Status == statusRetired {
			// R5: a retired id is spent. An embedded network holding one is the
			// reuse this whole file exists to refuse, stated the other way
			// round.
			t.Errorf("R5: chain id %d is retired -- %s used it and is gone -- but %s ships it "+
				"today. Certificates of the retired chain still name this id and still pass "+
				"V1 here; allocate a new id instead", p.ChainID, a.Network, name)
		}

		// R4: a live network's pinned genesis id is the one its parameter file
		// derives right now. This is the temporal check. A respin that keeps
		// the id changes something in the parameters -- if it changed nothing
		// it would not be a respin -- so the consensus root moves, block 0
		// moves, and this comparison is what notices.
		if a.Status != statusLive {
			continue
		}
		// R3 already reported a live entry with no pinned id, and its continue
		// only left R3's own loop. Dereferencing here would panic and take R5,
		// R6 and R7 down with it -- a check that crashes reports less than one
		// that fails. Not counting it toward `live` is the honest half: the
		// comparison did not happen, so R6 says the pin never ran rather than
		// this loop claiming it did.
		if a.GenesisID == nil {
			continue
		}
		live++
		want, err := decodeLedgerHash(*a.GenesisID)
		if err != nil {
			t.Errorf("R4: chain id %d: %v", p.ChainID, err)
			continue
		}
		got, err := genesis.NetworkID(p)
		if err != nil {
			t.Fatalf("R4: %s: building genesis: %v", name, err)
		}
		if got != want {
			t.Errorf("R4: chain id %d was allocated to the network whose genesis id is %x, "+
				"and %s now derives %x from %s.\n"+
				"This is a respin holding on to a spent chain id. The signed message "+
				"binds the consensus root as well as the chain id "+
				"(core/crypto.SigningMessage), so the predecessor's certificates fail V2 here "+
				"rather than being billed -- but the id is still spent, and the two networks "+
				"still answer to one name in every certificate, every log line and every "+
				"operator's --params file. Allocate a new chain id, retire %d in "+
				"spec/chain-ids.json, and add an entry for the new network.",
				p.ChainID, want, name, got, a.ParamsFile, p.ChainID)
		}
	}

	// R6: anti-vacuity for R4 specifically. R1 to R3 hold over any ledger, and
	// R2 holds over any set of networks, so all of them could be green with the
	// genesis comparison never having executed once -- which is the state this
	// file would be in if every entry drifted to "pre-genesis". The pin is the
	// only rule here that catches a respin, so its reachability is asserted
	// rather than assumed.
	if live == 0 {
		t.Error("R6: no embedded network is allocated 'live', so R4 -- the genesis pin, and the " +
			"only rule here that catches a respin reusing an id -- never ran")
	}

	// R7: the ledger does not name networks that do not exist. An entry that is
	// pre-genesis or live claims a parameter file is shipping under that id; if
	// it is not, either the file was deleted without retiring the id, or the
	// entry was written for a network that never arrived. Both leave an id
	// looking allocated to something nobody can inspect.
	shipping := map[uint64]bool{}
	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		shipping[p.ChainID] = true
	}
	for _, a := range ledger.Allocations {
		if a.Status == statusRetired || shipping[a.ChainID] {
			continue
		}
		t.Errorf("R7: chain id %d is allocated to %s with status %q, but no embedded network "+
			"ships it. Retire the entry if the network is gone -- an id whose network cannot "+
			"be inspected is one nobody can check a successor against",
			a.ChainID, a.ParamsFile, a.Status)
	}
}

func loadChainIDLedger(t *testing.T) chainIDLedger {
	t.Helper()
	raw, err := os.ReadFile("chain-ids.json")
	if err != nil {
		t.Fatalf("spec/chain-ids.json is the allocation ledger and every check in this file "+
			"reads it: %v", err)
	}
	var l chainIDLedger
	// Unknown fields are allowed on purpose: the prose keys beside the
	// allocations are the argument for the rule, and they are read by people.
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatalf("spec/chain-ids.json does not parse: %v", err)
	}
	return l
}

// embeddedParamsFiles maps each name in spec.Networks() to the file on disk it
// is embedded from, by comparing bytes. Going through the bytes rather than a
// written table is deliberate: a table would let the ledger's params_file agree
// with a name that agrees with nothing.
func embeddedParamsFiles(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "params") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		onDisk, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range spec.Networks() {
			raw, err := spec.RawFor(name)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) == string(onDisk) {
				out[name] = e.Name()
			}
		}
	}
	if len(out) != len(spec.Networks()) {
		t.Fatalf("%d embedded networks resolved to %d parameter files on disk; R2's file check "+
			"would compare against an empty string", len(spec.Networks()), len(out))
	}
	return out
}

func decodeLedgerHash(s string) (crypto.Hash, error) {
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
