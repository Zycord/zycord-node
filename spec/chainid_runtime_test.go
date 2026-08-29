package spec_test

import (
	"errors"
	"testing"

	"zycord/core/genesis"
	"zycord/spec"
)

// The property, in one sentence: **every network this binary embeds starts
// under the ledger check, and a respin of one does not.**
//
// TestChainIDsAreAllocatedOnce already holds the embedded files to the ledger,
// and it is the review-time instrument. This one holds spec.CheckChainID — the
// function a node calls at startup — to the same files, which is what
// makes "the node will not start" true of the binary rather than of the test
// suite. If the two ever disagreed, the shipping binary would refuse to run on
// its own parameters while `go test ./spec` stayed green.
func TestEveryEmbeddedNetworkPassesTheStartupCheck(t *testing.T) {
	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := spec.CheckChainID(p, genesis.NetworkID); err != nil {
			t.Errorf("a node started on the embedded %s set would refuse to start: %v.\n"+
				"Either the ledger entry for chain id %d is wrong, or this network was "+
				"respun without allocating a new id", name, err, p.ChainID)
		}
	}
}

// The respin, end to end and on the real ledger: the testnet's parameter file
// says in its own prose to "reset this to the actual launch day if this testnet
// is ever restarted from genesis", and doing exactly that while keeping chain
// id 2 is the reuse the ledger was written for and the startup check arms.
//
// This is the anti-vacuity for the test above. Both networks pass today, so a
// CheckChainID that returned nil unconditionally would satisfy it; nothing but
// a genuine comparison satisfies this one.
func TestARespinOfAnEmbeddedNetworkIsRefused(t *testing.T) {
	p, err := spec.ParamsFor("testnet")
	if err != nil {
		t.Fatal(err)
	}
	// A copy, moved by one second. That is the smallest respin there is — a
	// relaunch on a new day moves it much further — and it is enough, because
	// genesis_time is inside the consensus root and therefore inside block 0's
	// id.
	respun := *p
	respun.GenesisTime++

	err = spec.CheckChainID(&respun, genesis.NetworkID)
	if err == nil {
		t.Fatalf("a testnet respun on chain id %d was accepted at startup. Two networks then "+
			"answer to one id in every certificate and every log line, which is what "+
			"spec/chain-ids.json refuses", respun.ChainID)
	}
	if !errors.Is(err, spec.ErrChainIDSpent) {
		t.Errorf("the refusal is %v; a respin is a spent id and must wrap ErrChainIDSpent, "+
			"not be reported as a broken ledger", err)
	}
}
