package checkpoints_test

import (
	"errors"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/checkpoints"
	"zycord/spec"
)

func id(b byte) types.Hash {
	var h types.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// The constraint that would break the network if it were missed.
//
// A checkpoint is edited in every routine release. If editing one could move
// the consensus root, then every routine release would derive a different
// genesis id and every node that took it would refuse to speak to every node
// that had not — a network split delivered by a patch release, arriving through
// the function whose whole job is to make parameter divergence a connection
// refusal rather than a silent fork.
//
// Three separate ways of asking the same question, because the failure this
// pins is somebody *moving* a field later, and a single assertion is one
// refactor away from being about something else.
func TestCheckpointDataDoesNotEnterTheConsensusRoot(t *testing.T) {
	before := spec.Mainnet().ConsensusRoot()
	paramsHash := spec.MainnetParamsHash()

	// 1. Installing a fat, non-empty table changes neither.
	checkpoints.Install(checkpoints.Set{
		Network:            "mainnet",
		MinChainWork:       u256.FromUint64(1 << 40),
		MinChainWorkHeight: 20160,
		SunsetHeight:       checkpoints.Sunset,
		MinimumAge:         checkpoints.MinAge,
		Points: []checkpoints.Checkpoint{
			{Height: 2880, BlockID: id(0xaa)},
			{Height: 20160, BlockID: id(0xbb)},
		},
	})
	t.Cleanup(func() { checkpoints.Install(checkpoints.Set{}) })

	if after := spec.Mainnet().ConsensusRoot(); after != before {
		t.Fatalf("installing a checkpoint table moved the consensus root: %x -> %x", before, after)
	}
	if after := spec.MainnetParamsHash(); after != paramsHash {
		t.Fatalf("installing a checkpoint table moved the params hash: %x -> %x", paramsHash, after)
	}

	// 2. Parsing a *different* checkpoint file changes neither. This is the
	//    shape of a real release: the file's bytes change, nothing else does.
	edited := strings.Replace(string(spec.CheckpointsJSON()),
		`"sunset_height": 1051200`, `"sunset_height": 999999`, 1)
	if edited == string(spec.CheckpointsJSON()) {
		t.Fatal("the edit did not apply; this test is checking nothing")
	}
	if _, err := checkpoints.Parse([]byte(edited), "mainnet"); err != nil {
		t.Fatalf("the edited file should still parse: %v", err)
	}
	if after := spec.Mainnet().ConsensusRoot(); after != before {
		t.Fatalf("an edited checkpoint file moved the consensus root: %x -> %x", before, after)
	}

	// 3. No parameter is *named* after any of this. A future field added to
	//    params.Params called min_chain_work would be committed by the
	//    reflective walk in core/params/root.go, and layers 1 and 2 would
	//    become consensus without anybody deciding that they should.
	for _, name := range spec.Mainnet().ConsensusFieldNames() {
		if strings.Contains(name, "checkpoint") || strings.Contains(name, "min_chain_work") {
			t.Fatalf("parameter %q is committed by ConsensusRoot; checkpoints must not be", name)
		}
	}

	// And the two files are genuinely two files: the parameter hash is over
	// params.json alone.
	if spec.CheckpointsHash() == spec.MainnetParamsHash() {
		t.Fatal("the checkpoint file and the parameter file hash to the same value")
	}
}

// Every network this binary embeds has a checkpoint section, and it is valid.
// A network added without one is a network shipping no defence at all, and it
// should fail here rather than at the first sync a joining node attempts.
func TestEveryEmbeddedNetworkHasAValidCheckpointSection(t *testing.T) {
	for _, name := range spec.Networks() {
		s, err := checkpoints.Load(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.SunsetHeight != checkpoints.Sunset {
			t.Fatalf("%s: sunset_height is %d, the code enforces %d",
				name, s.SunsetHeight, checkpoints.Sunset)
		}
		if s.MinimumAge != checkpoints.MinAge {
			t.Fatalf("%s: minimum_age_blocks is %d, the code enforces %d",
				name, s.MinimumAge, checkpoints.MinAge)
		}
	}
	if _, err := checkpoints.Load("nosuchnet"); !errors.Is(err, checkpoints.ErrUnknownNetwork) {
		t.Fatalf("want ErrUnknownNetwork, got %v", err)
	}
}

// v1.0.0 ships the enforcement and no data. The empty table must be inert on
// every question the sync path asks it, because a defence that has to be
// switched on later is a defence nothing has ever run.
func TestTheShippedTableIsInert(t *testing.T) {
	s, err := checkpoints.Load("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsEmpty() {
		t.Fatalf("mainnet ships a non-empty table at v1.0.0: %s", s)
	}
	if s.Contradicts(2880, id(0x01)) {
		t.Fatal("an empty table contradicted a block")
	}
	if !s.MeetsFloor(1_000_000, u256.Zero) {
		t.Fatal("an empty table refused a chain on work")
	}
	if _, ok := s.Highest(); ok {
		t.Fatal("an empty table named a highest checkpoint")
	}
}

func TestValidateRefusesTablesThatWouldBeWrongRatherThanEmpty(t *testing.T) {
	base := func() checkpoints.Set {
		return checkpoints.Set{
			SunsetHeight: checkpoints.Sunset,
			MinimumAge:   checkpoints.MinAge,
		}
	}
	cases := []struct {
		name string
		set  func() checkpoints.Set
		want error
	}{
		{"past the sunset", func() checkpoints.Set {
			s := base()
			s.Points = []checkpoints.Checkpoint{{Height: checkpoints.Sunset + 1, BlockID: id(1)}}
			return s
		}, checkpoints.ErrPastSunset},
		{"out of order", func() checkpoints.Set {
			s := base()
			s.Points = []checkpoints.Checkpoint{
				{Height: 20160, BlockID: id(1)}, {Height: 2880, BlockID: id(2)}}
			return s
		}, checkpoints.ErrNotAscending},
		{"repeated height", func() checkpoints.Set {
			s := base()
			s.Points = []checkpoints.Checkpoint{
				{Height: 2880, BlockID: id(1)}, {Height: 2880, BlockID: id(2)}}
			return s
		}, checkpoints.ErrNotAscending},
		{"zero block id", func() checkpoints.Set {
			s := base()
			s.Points = []checkpoints.Checkpoint{{Height: 2880}}
			return s
		}, checkpoints.ErrZeroID},
		{"genesis", func() checkpoints.Set {
			s := base()
			s.Points = []checkpoints.Checkpoint{{Height: 0, BlockID: id(1)}}
			return s
		}, checkpoints.ErrGenesisPin},
		{"a floor with no height", func() checkpoints.Set {
			s := base()
			s.MinChainWork = u256.FromUint64(1)
			return s
		}, checkpoints.ErrFloorPairing},
		{"a height with no floor", func() checkpoints.Set {
			s := base()
			s.MinChainWorkHeight = 2880
			return s
		}, checkpoints.ErrFloorPairing},
		{"an age the code does not enforce", func() checkpoints.Set {
			s := base()
			s.MinimumAge = 100
			return s
		}, checkpoints.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.set().Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("the empty table must validate: %v", err)
	}
}

// The 24-hour rule, and the published schedule against it.
//
// "Never checkpoint a block younger than 2,880 blocks" is what makes a pin
// unable to partition a live network: 2,880 is one epoch and 2.8x undo_depth,
// so anything old enough to be pinned is a block no honest node would reorg
// away. The rule is enforceable at release time and not at build time — the
// binary does not know the tip its table was authored against — so it lives in
// a function a release step calls, and this is what keeps that function honest.
func TestTheAgeRuleIsTheOneTheScheduleAssumes(t *testing.T) {
	if checkpoints.MinAge != 2880 {
		t.Fatalf("MinAge is %d; the argument that a pin cannot split the network "+
			"depends on it being one epoch and above undo_depth", checkpoints.MinAge)
	}
	if _, ok := checkpoints.MaxPinnableHeight(checkpoints.MinAge - 1); ok {
		t.Fatal("a chain younger than one minimum age may pin nothing")
	}
	if h, ok := checkpoints.MaxPinnableHeight(2 * checkpoints.MinAge); !ok || h != checkpoints.MinAge {
		t.Fatalf("at tip %d the highest pinnable height is %d, got %d (ok=%v)",
			2*checkpoints.MinAge, checkpoints.MinAge, h, ok)
	}
	if _, ok := checkpoints.MaxPinnableHeight(checkpoints.Sunset + checkpoints.MinAge + 1); ok {
		t.Fatal("nothing may be pinned past the sunset")
	}

	// The schedule in the issue: 2,880 at ~day 3, 20,160 at ~day 10, 40,320 and
	// 86,400 at ~day 31. Each is pinned by the release that follows it, so each
	// must be at least MinAge below the tip at that time, and each must be
	// inside the sunset.
	for _, want := range []uint64{2880, 20160, 40320, 86400} {
		s := checkpoints.Set{
			SunsetHeight: checkpoints.Sunset,
			MinimumAge:   checkpoints.MinAge,
			Points:       []checkpoints.Checkpoint{{Height: want, BlockID: id(1)}},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("scheduled height %d does not validate: %v", want, err)
		}
		if err := s.ValidateAgainstTip(want + checkpoints.MinAge); err != nil {
			t.Fatalf("scheduled height %d refused at the tip it is pinned from: %v", want, err)
		}
		if err := s.ValidateAgainstTip(want + checkpoints.MinAge - 1); !errors.Is(err, checkpoints.ErrTooYoung) {
			t.Fatalf("height %d one block too young was accepted: %v", want, err)
		}
	}
}

// The work floor is not evaluated below the height it is measured at, and that
// is what stops it from bricking a fresh node: a chain that is not allowed to
// grow can never reach a floor.
func TestTheWorkFloorOnlyJudgesAChainThatReachedItsHeight(t *testing.T) {
	s := checkpoints.Set{
		MinChainWork:       u256.FromUint64(1000),
		MinChainWorkHeight: 20160,
		SunsetHeight:       checkpoints.Sunset,
		MinimumAge:         checkpoints.MinAge,
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if !s.MeetsFloor(20159, u256.FromUint64(1)) {
		t.Fatal("a chain below the floor's height was judged against it")
	}
	if s.MeetsFloor(20160, u256.FromUint64(999)) {
		t.Fatal("a chain arriving at the floor's height too light was admitted")
	}
	if !s.MeetsFloor(20160, u256.FromUint64(1000)) {
		t.Fatal("a chain exactly at the floor was refused")
	}
	if !s.MeetsFloor(20161, u256.FromUint64(1000)) {
		t.Fatal("a chain above the floor was refused")
	}
}

func TestContradictsIsSilentAboutHeightsItDoesNotPin(t *testing.T) {
	s := checkpoints.Set{
		SunsetHeight: checkpoints.Sunset,
		MinimumAge:   checkpoints.MinAge,
		Points:       []checkpoints.Checkpoint{{Height: 2880, BlockID: id(0xaa)}},
	}
	if s.Contradicts(2879, id(0xff)) || s.Contradicts(2881, id(0xff)) {
		t.Fatal("an unpinned height was treated as a claim")
	}
	if s.Contradicts(2880, id(0xaa)) {
		t.Fatal("the pinned block contradicted its own pin")
	}
	if !s.Contradicts(2880, id(0xff)) {
		t.Fatal("a different block at the pinned height was admitted")
	}
}

// Install hands out copies. A caller that keeps its slice and appends to it
// must not be able to change what the process enforces afterwards.
func TestTheActiveTableCannotBeMutatedThroughACallersSlice(t *testing.T) {
	points := []checkpoints.Checkpoint{{Height: 2880, BlockID: id(0xaa)}}
	checkpoints.Install(checkpoints.Set{
		Points: points, SunsetHeight: checkpoints.Sunset, MinimumAge: checkpoints.MinAge})
	t.Cleanup(func() { checkpoints.Install(checkpoints.Set{}) })

	points[0].BlockID = id(0xff)
	got := checkpoints.Active()
	if want, _ := got.At(2880); want != id(0xaa) {
		t.Fatalf("the active table followed the caller's slice: %x", want)
	}
	got.Points[0].BlockID = id(0xee)
	if want, _ := checkpoints.Active().At(2880); want != id(0xaa) {
		t.Fatalf("the active table followed a reader's slice: %x", want)
	}
}

// A guard on the one place this package touches core/: it reads a params set
// only to name a network, and must never be the reason a parameter exists.
func TestNothingHereNeedsAParameter(t *testing.T) {
	var p *params.Params = spec.Mainnet()
	if p.Name == "" {
		t.Fatal("the mainnet parameter set has no name")
	}
	s, err := checkpoints.Load("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if s.Network != "mainnet" {
		t.Fatalf("the loaded table names %q", s.Network)
	}
	if !strings.Contains(s.String(), "no checkpoints") {
		t.Fatalf("the operator line for an empty table reads %q", s.String())
	}
}
