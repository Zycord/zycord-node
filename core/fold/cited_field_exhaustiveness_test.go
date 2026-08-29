package fold_test

import (
	"bytes"
	"math"
	"sort"
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/sim/harness"
	"zycord/spec"
)

// TestACitationCarryingValuesNoPlausibleConstraintAdmitsIsStillCounted pins the
// second half of `docs/spec/wire.md` §9 rule 7: the six checks a citation is
// held to — version, height, grandparent, not-our-own-parent, declared target,
// and the node layer's work check — are **exhaustive**. A cited header's
// `Time`, `CertRoot`, `CitesRoot`, `StateRoot`, `EmissionAddr` and
// `PoW.SeedEpoch` are unconstrained, and a node that constrains one of them
// counts fewer citations than its peers, derives a different sequential target
// `T`, and forks. Adding a check here is as much a consensus change as removing
// one.
//
// # Why this is a test and not a vector
//
// This is a **negative** rule: it says what a verifier must NOT check. The
// corpus cannot bind it. A valid vector citing a header with odd field values
// refutes only the constraints those particular values happen to violate, and
// passes both ways against every other plausible constraint, and the corpus
// standard — a vector must fail without the rule it claims to bind — rules
// such a vector out. Choosing which values to carry is choosing which
// constraints a reimplementer is plausibly tempted by, and that is a
// judgement no vector in this corpus makes. So the judgement is made here, in
// the open, where the sub-case names carry it.
//
// The first half of rule 7 — that a cited header's work is verified before the
// citation is counted — lives at ingress and is held by `node/p2p`'s and
// `node/sync`'s `citedwork_test.go`. This file is the fold's half, and
// the two halves together are the whole executable hold on rule 7.
//
// # Why each field's value is the one it is
//
// Every sub-case below carries a value that a **real, named block rule in this
// very package** refuses for a block's own header. That is the point: a
// reimplementer's most likely mistake is not inventing a novel constraint, it
// is applying to a citation a rule it already implements for blocks. Each
// sub-case therefore refutes a specific such rule by name, and if `checkCites`
// ever grows that rule the sub-case naming it goes red on its own.
//
//   - `Time`      — refutes the ingress plausibility window (`wire.md` §5's
//     withheld/future-drift bound), by sitting further in the
//     future than any clock will ever reach.
//   - `CertRoot`  — refutes B14 ("commits to the bodies"): a citation carries no
//     bodies, so "must be the empty-list root" is the tempting rule.
//   - `CitesRoot` — refutes B16, the same way, and the further temptation that a
//     competing header may not itself have cited.
//   - `StateRoot` — refutes B9 ("state root is set on a non-epoch-boundary
//     block"), which the citation's own height would trigger.
//   - `EmissionAddr` — refutes B11 ("payout address is not a user address"), by
//     naming the protocol address, which B11 refuses for a block.
//   - `PoW.SeedEpoch` — refutes B0b, and is the sharpest of the six because
//     block headers ARE constrained in this field by
//     `checkSeedEpoch`. A citation must not be held to it: no
//     verifier reads the field to find a key — the key comes
//     from the height, for a citation exactly as for a block.
//
// # Declared direction, before running
//
// With any one of these constraints added to `checkCites`, the sub-case naming
// it fails with `ApplyBlock` returning an invalid-block error, and every other
// arm — including the control — stays green. With `cited_count`'s increment
// (fold.go F4) changed to skip such citations rather than reject the block, the
// sub-case fails on the count assertion instead, not on the verdict. No arm
// goes red because something else complained: the control arm cites an honest
// sibling that differs from the block's own parent in one field, and it is
// asserted valid and counted first.
func TestACitationCarryingValuesNoPlausibleConstraintAdmitsIsStillCounted(t *testing.T) {
	p := spec.Devnet()
	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()
	rival := key(t, 2).Persistent()

	// Height 2 is the lowest at which a block may cite at all (B17), so the
	// block under test sits at 3: the first height whose parent is itself
	// citable-against and whose grandparent is a real block rather than genesis.
	for c.Height() < 2 {
		if _, _, err := c.AddBlock(payout); err != nil {
			t.Fatal(err)
		}
	}
	height := c.NextHeight()
	if p.IsEpochBoundary(height) {
		t.Fatalf("setup: the block under test is at height %d, an epoch boundary, where "+
			"the health gate zeroes cited_count in the same block — every count "+
			"assertion below would read 0 and pin nothing", height)
	}

	honest := c.Sibling(rival)
	if honest == nil {
		t.Fatal("setup: the chain is too young to have a sibling to cite")
	}
	if honest.ID() == c.Tip().ID() {
		t.Fatal("setup: the sibling is byte-identical to this block's own parent, which C3 " +
			"refuses for reasons that have nothing to do with the rule under test")
	}

	fill := func(b byte) types.Hash {
		var h types.Hash
		for i := range h {
			h[i] = b
		}
		return h
	}
	// An epoch the citation's own height does not imply. Asserted, not assumed:
	// devnet's key lag puts every low height in epoch 0, and a "wrong" value
	// that happened to equal the schedule's answer would make the sharpest of
	// the six sub-cases vacuous.
	wrongSeedEpoch := pow.SeedEpochFor(honest.Height, p) + 1
	if wrongSeedEpoch == pow.SeedEpochFor(honest.Height, p) {
		t.Fatal("setup: the fabricated seed epoch equals the one the schedule gives")
	}

	cases := []struct {
		name    string
		refutes string
		mutate  func(*types.Header)
	}{
		{
			name:    "control-an-honest-sibling-counts",
			refutes: "nothing; it is the control, and it fails only if citing is broken outright",
			mutate:  func(*types.Header) {},
		},
		{
			name:    "Time-far-beyond-any-clock",
			refutes: "the ingress future-drift window (wire.md §5) applied to a citation",
			mutate:  func(h *types.Header) { h.Time = math.MaxUint64 },
		},
		{
			name:    "CertRoot-arbitrary-nonzero",
			refutes: "B14 applied to a citation: that its cert root be the empty-list root, since no bodies ride with it",
			mutate:  func(h *types.Header) { h.CertRoot = fill(0xa1) },
		},
		{
			name:    "CitesRoot-arbitrary-nonzero",
			refutes: "B16 applied to a citation, and the temptation that a competing header may not itself have cited",
			mutate:  func(h *types.Header) { h.CitesRoot = fill(0xb2) },
		},
		{
			name:    "StateRoot-set-off-an-epoch-boundary",
			refutes: "B9 applied to a citation: a non-boundary header carrying a state root",
			mutate:  func(h *types.Header) { h.StateRoot = fill(0xc3) },
		},
		{
			name:    "EmissionAddr-the-protocol-address",
			refutes: "B11 applied to a citation: a payout address that is not a user address",
			mutate:  func(h *types.Header) { h.EmissionAddr = crypto.ProtocolAddress },
		},
		{
			name:    "PoW-SeedEpoch-an-epoch-its-height-does-not-imply",
			refutes: "B0b applied to a citation — the sharpest of the six, because block headers ARE held to it by checkSeedEpoch",
			mutate:  func(h *types.Header) { h.PoW.SeedEpoch = wrongSeedEpoch },
		},
		{
			name:    "all-six-fields-at-once",
			refutes: "any conjunction of the six, which a per-field arm alone leaves open",
			mutate: func(h *types.Header) {
				h.Time = math.MaxUint64
				h.CertRoot = fill(0xa1)
				h.CitesRoot = fill(0xb2)
				h.StateRoot = fill(0xc3)
				h.EmissionAddr = crypto.ProtocolAddress
				h.PoW.SeedEpoch = wrongSeedEpoch
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cited := *honest
			tc.mutate(&cited)
			// The mutated citation still satisfies all five fold-checkable
			// rules — it differs from the honest one in the field under test
			// and in nothing else — so whatever a failure below is about, it
			// is not the shape of the citation.
			if cited.Version != honest.Version || cited.Height != honest.Height ||
				cited.ParentID != honest.ParentID || !cited.Target.Eq(honest.Target) {
				t.Fatalf("%s: the mutation reached a field checkCites DOES pin; this arm "+
					"would refute a rule that exists", tc.name)
			}
			if tc.name != "control-an-honest-sibling-counts" && cited.ID() == honest.ID() {
				t.Fatalf("%s: the mutation left the header byte-identical to the honest "+
					"citation, so this arm carries no fabricated value at all", tc.name)
			}
			assertCitationsCount(t, c, p, payout, []*types.Header{&cited}, tc.refutes)
		})
	}

	// "Incremented by EVERY citation", at the ceiling. MaxCitesPerBlock is 4 on
	// every parameter set in this tree, so all six fields cannot ride one block;
	// four distinct constraint-refusing citations in one block is the widest the
	// rule can be exercised, and it is what catches an implementation that
	// counts the first such citation and drops the rest.
	t.Run("four-constraint-refusing-citations-in-one-block", func(t *testing.T) {
		if p.MaxCitesPerBlock < 4 {
			t.Skipf("MaxCitesPerBlock is %d; this arm needs 4", p.MaxCitesPerBlock)
		}
		mutations := []func(*types.Header){
			func(h *types.Header) { h.Time = math.MaxUint64 },
			func(h *types.Header) { h.CertRoot = fill(0xa1) },
			func(h *types.Header) { h.StateRoot = fill(0xc3) },
			func(h *types.Header) { h.PoW.SeedEpoch = wrongSeedEpoch },
		}
		cites := make([]*types.Header, 0, len(mutations))
		for _, mutate := range mutations {
			cited := *honest
			mutate(&cited)
			cites = append(cites, &cited)
		}
		// C5 wants strictly increasing ids, which is orthogonal to this rule
		// and would otherwise reject the block for a reason of its own.
		sort.Slice(cites, func(i, j int) bool {
			a, b := cites[i].ID(), cites[j].ID()
			return bytes.Compare(a[:], b[:]) < 0
		})
		for i := 1; i < len(cites); i++ {
			a, b := cites[i-1].ID(), cites[i].ID()
			if bytes.Equal(a[:], b[:]) {
				t.Fatal("setup: two of the four fabricated citations collided on id, so " +
					"C5 rejects the block for a reason unrelated to the rule under test")
			}
		}
		assertCitationsCount(t, c, p, payout, cites,
			"that only one citation carrying a constraint-refusing value may be counted per block")
	})
}

// assertCitationsCount folds one block carrying cites onto a clone of the
// chain's state and requires two things in order: that the fold ACCEPTS it, and
// that cited_count rose by exactly len(cites). The order matters — a verifier
// that silently skipped a citation rather than rejecting the block would pass
// the first and fail the second, and those are different bugs with the same
// consequence for `T`.
func assertCitationsCount(t *testing.T, c *harness.Chain, p *params.Params,
	payout types.Address, cites []*types.Header, refutes string) {
	t.Helper()

	b, err := c.ProposeWithCites(payout, cites)
	if err != nil {
		t.Fatalf("proposing the carrier failed: %v", err)
	}
	st := c.State.Clone()
	before := citedCount(t, st)

	if _, err := fold.ApplyBlock(st, b, p); err != nil {
		t.Fatalf("the fold REJECTED a block citing a header with an unconstrained field "+
			"carrying a value no plausible constraint admits: %v.\n"+
			"This arm refutes %s.\n"+
			"If the rejection is deliberate, somebody constrained a citation field that "+
			"wire.md §9 rule 7 declares unconstrained — a consensus change that counts "+
			"fewer citations than peers, derives a different sequential target T, and "+
			"forks. Read this failure as the flag it is.", err, refutes)
	}

	after := citedCount(t, st)
	if want := before + uint64(len(cites)); after != want {
		t.Fatalf("cited_count went %d -> %d over a block carrying %d citations, want %d.\n"+
			"The block folded valid, so the citations were not rejected — they were not "+
			"COUNTED, which moves the epoch health signal and T exactly as a rejection "+
			"would. This arm refutes %s.", before, after, len(cites), want, refutes)
	}
}

func citedCount(t *testing.T, s *state.State) uint64 {
	t.Helper()
	n, ok := s.Get(types.CitedCountSlot()).Uint64()
	if !ok {
		t.Fatal("cited_count does not fit in a uint64, which the fold's own increment assumes")
	}
	return n
}
