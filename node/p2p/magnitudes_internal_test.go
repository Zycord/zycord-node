package p2p

import (
	"testing"

	"zycord/spec"
)

// The magnitude figures in this package's comments exist to support
// inequalities, and it is the inequalities and not the figures that this file
// pins.
//
// **A test that pins the values would be the defect it is meant to catch.** A
// value test asserts a number the prose also states, which leaves two copies
// that must agree and no check that either of them still means what it did —
// the failure mode a transcribed magnitude already produced here once. What the
// prose actually claims is relations: that the reachable bound passes the
// budget, that the table bound is the larger figure, that the honest peak fits
// under the budget the adversarial one does not. Those are the things an era
// re-pin or a default change threatens, and unlike the values they cannot be
// satisfied by two copies agreeing with each other.
//
// Each assertion below names, in its failure message, the sentence that stops
// being true — so a build that breaks here points at the prose to repair
// rather than at a number to update.

// TestReassemblyMagnitudeRelationsHold asserts the parameter-independent
// relations the reassembly-bounds note in engine.go argues from.
func TestReassemblyMagnitudeRelationsHold(t *testing.T) {
	// The connection set fits inside the partial-transfer table. This is the
	// premise the "still the larger figure" parenthetical rests on, and it was
	// established by a reviewer after the fact rather than by the edit that
	// needed it. tableBound >= socketBound holds iff this does.
	if maxConnections > MaxPartialTransfers {
		t.Fatalf("the connection set (%d) now exceeds MaxPartialTransfers (%d): a hostile population can fill the table from sockets alone, "+
			"so the reassembly-bounds note's table-bound parenthetical in engine.go is no longer the weaker argument and must be rewritten",
			maxConnections, MaxPartialTransfers)
	}

	// ... which is what makes the table bound the larger figure. Asserted
	// separately from its premise so that a change to MaxTransfersPerPeer or
	// BlockChunkBytes that broke the products without breaking the count
	// relation would still be caught here.
	if tableBound <= socketBound {
		t.Fatalf("tableBound (%d) is no longer above socketBound (%d): engine.go's OnUnservedBody note says the table bound "+
			"\"is still the larger figure\", and it has stopped being one", tableBound, socketBound)
	}

	// The reachable bound passes the byte budget. This is the claim that
	// settles the eviction-gate argument: saturation is a state a peer
	// population arranges on demand rather than one it happens to meet.
	if socketBound <= MaxReassemblyBytes {
		t.Fatalf("socketBound (%d) no longer passes MaxReassemblyBytes (%d): the connection set alone can no longer saturate the reassembly "+
			"budget, so engine.go's OnUnservedBody note argues from a saturation an attacker can no longer reach",
			socketBound, MaxReassemblyBytes)
	}

	// The honest steady state fits under the budget. The other side of the
	// same constant, and the reason MaxReassemblyBytes is not simply the
	// smallest number that stops the attack: it has to leave the honest
	// network alone.
	if honestSteadyStatePeakBytes >= MaxReassemblyBytes {
		t.Fatalf("honestSteadyStatePeakBytes (%d) has reached MaxReassemblyBytes (%d): the reassembly-bounds note says the budget "+
			"\"sits above what the honest network peaks at\", and an honest network can now be refused chunks",
			honestSteadyStatePeakBytes, MaxReassemblyBytes)
	}

	// The two forties are two quantities, not one. Nothing in the tree may
	// collapse the honest expectation into the adversarial bound or the
	// reverse; if the gate in Node.register ever became symmetric this stops
	// holding and every worst-case comment in the package needs rereading.
	if honestSteadyStateConns >= maxConnections {
		t.Fatalf("honestSteadyStateConns (%d) is no longer below maxConnections (%d): the inbound-only capacity gate in Node.register is "+
			"what separates them, and the honest-versus-adversarial distinction every magnitude comment in this package draws has collapsed",
			honestSteadyStateConns, maxConnections)
	}
}

// TestReassemblyMagnitudeRelationsHoldAtTheShippedCeilings asserts the
// relations that carry an era ceiling, at the parameter sets a release ships.
// These are the ones an era re-pin moves: BlockByteCapacity appears in the
// uncounted term directly, and it is the term that is already the larger half.
func TestReassemblyMagnitudeRelationsHoldAtTheShippedCeilings(t *testing.T) {
	for _, tc := range []struct {
		name string
		cap  int
	}{
		{"mainnet", spec.Mainnet().BlockByteCapacity},
		{"devnet", spec.Devnet().BlockByteCapacity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live := liveReassemblyBound(tc.cap)

			// The bound that matters is strictly larger than the counter that
			// enforces it. Reading MaxReassemblyBytes as this node's whole
			// reassembly footprint is the error to avoid, and a future
			// re-sizing done against it alone would be done against the wrong
			// figure.
			if live <= MaxReassemblyBytes {
				t.Fatalf("liveReassemblyBound (%d) is no longer above MaxReassemblyBytes (%d): the reassembly-bounds note's "+
					"\"buffered is not the same as live\" paragraph describes a gap that has closed", live, MaxReassemblyBytes)
			}

			// The uncounted half is the larger one. This is the sentence that
			// makes the gap worth documenting rather than a rounding note, and
			// it is exactly what an era re-pin threatens in the other
			// direction — a *smaller* capacity would falsify it.
			if uncounted := maxConnections * tc.cap; uncounted <= MaxReassemblyBytes {
				t.Fatalf("the uncounted term (%d connections x %d bytes = %d) has fallen under MaxReassemblyBytes (%d): "+
					"the reassembly-bounds note says \"the uncounted half is the larger one\", and it no longer is",
					maxConnections, tc.cap, uncounted, MaxReassemblyBytes)
			}

			// The byte budget sits far under what the counts alone permit,
			// which is why it exists at all.
			if implied := countImpliedBound(tc.cap); implied <= live {
				t.Fatalf("countImpliedBound (%d) has fallen to or under liveReassemblyBound (%d): the reassembly-bounds note says "+
					"MaxReassemblyBytes sits \"far under the count-implied worst case\", and the count bounds have stopped being the looser ones",
					implied, live)
			}
		})
	}
}
