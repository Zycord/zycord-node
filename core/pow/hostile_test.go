package pow_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// The work check is reached by bytes off the wire, so it is reached by headers
// nobody sane constructed. Two properties have to hold for every one of them,
// and neither is implied by the tests that mine.
//
// **CheckWork is TOTAL.** Its doc comment claims it — "no chain, no clock, no
// ancestry" — and the claim is load-bearing: a node prices orphans with it,
// scores announcements whose parent it has never seen with it, and caches its
// verdict by block id. A panic on a hostile header is a remote crash on the
// gossip path, reachable by anyone who can send a header.
//
// **And it never ACCEPTS one.** Every case below carries a PoWHash that is not
// the digest of its own blob, which is the forgery the expensive half exists to
// refuse. A header at `height = 2^64 - 1` is included on purpose: the key comes
// from the height through KeyFor's epoch arithmetic, so the extreme is where a
// division or a subtraction there would go wrong, and KeyFor is the reason
// CheckWork can be total at all.
//
// Mutation-checked. Deleting the digest-identity half of checkWorkWith — which
// is what makes the cheap commitment test the whole rule — makes "bad version"
// and "max time" ACCEPTED here, and this test is what says so.
func TestHostileHeadersAreTotalAndRefused(t *testing.T) {
	e := pow.Dev{}
	p := spec.Mainnet()
	max := u256.Max

	cases := []struct {
		name string
		h    types.Header
	}{
		{"zero header", types.Header{}},
		{"zero target at height 1", types.Header{Version: types.HeaderVersion, Height: 1}},
		{"height 2^64-1", types.Header{Version: types.HeaderVersion, Height: ^uint64(0), Target: max}},
		{"height 2^64-2", types.Header{Version: types.HeaderVersion, Height: ^uint64(0) - 1, Target: max}},
		{"unknown version", types.Header{Version: 0xffffffff, Height: 1, Target: max}},
		{"time 2^64-1", types.Header{Version: types.HeaderVersion, Height: 1, Time: ^uint64(0), Target: max}},
		{"target 1", types.Header{Version: types.HeaderVersion, Height: 1, Target: u256.One}},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: CheckWork panicked, which is a remote crash on "+
						"the gossip path: %v", c.name, r)
				}
			}()
			err := pow.CheckWork(e, c.h, p)
			// Height 0 is exempt by design and is here only to prove the
			// exemption is the ONLY one.
			if c.h.Height == 0 {
				return
			}
			if err == nil {
				t.Errorf("%s: a header whose PoWHash is not the digest of its "+
					"own blob was ACCEPTED", c.name)
			}
		}()
	}

	// The mirror, so the refusals above cannot be satisfied by a check that
	// refuses everything: the same extremes, sealed honestly, must PASS.
	h := types.Header{Version: types.HeaderVersion, Height: 1, Target: max}
	h.PoW.Nonce = ^uint32(0)
	h.PoW.ExtraNonce = ^uint32(0)
	h.PoWHash = e.Hash(pow.KeyFor(h.Height, p), h.PoWInput())
	if err := pow.CheckWork(e, h, p); err != nil {
		t.Fatalf("a correctly sealed header at the maximum nonce and ExtraNonce "+
			"was refused, so the refusals above prove nothing: %v", err)
	}
}

// TestTheReservedGapIsZeroForEveryHeaderAnAttackerCanBuild is the consensus
// rule types.Header.PoWInput states and that no corpus of blocks can carry: the
// seven bytes between the seed and the nonce are pinned at zero, so a verifier
// that filled them with anything else computes a different digest for the same
// header and forks.
//
// The existing coverage pins the gap on headers a test constructed politely.
// This one pins it on the field values an attacker actually controls, at their
// extremes — every header field saturated, the nonce and ExtraNonce at 2^32-1,
// and a PoWHash of all-ones. The gap is written by PoWInput rather than derived
// from any field, so nothing SHOULD reach it; the point is to demonstrate that
// nothing does.
//
// Mutation-checked: writing the nonce's high byte into the first reserved byte
// — the exact "a future field placed there" hazard PoWInput's comment names —
// is caught here.
func TestTheReservedGapIsZeroForEveryHeaderAnAttackerCanBuild(t *testing.T) {
	saturated := types.Header{
		Version: 0xffffffff, Height: ^uint64(0), Time: ^uint64(0), Target: u256.Max,
	}
	saturated.PoW.Nonce = ^uint32(0)
	saturated.PoW.ExtraNonce = ^uint32(0)
	for i := range saturated.PoWHash {
		saturated.PoWHash[i] = 0xff
	}

	hs := []struct {
		name string
		h    types.Header
	}{
		{"zero header", types.Header{}},
		{"every field saturated", saturated},
		{"ordinary header", types.Header{Version: types.HeaderVersion, Height: 1}},
	}
	for _, c := range hs {
		in := c.h.PoWInput()
		if len(in) != types.PoWInputSize {
			t.Fatalf("%s: the blob is %d bytes, want %d", c.name, len(in), types.PoWInputSize)
		}
		for k := types.PoWInputReservedOffset; k < types.PoWInputNonceOffset; k++ {
			if in[k] != 0 {
				t.Errorf("%s: reserved byte %d is %#x — a verifier that wrote "+
					"anything here would compute a different digest for this "+
					"same header and fork", c.name, k, in[k])
			}
		}
	}
}
