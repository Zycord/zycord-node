// Package checkpoints carries the launch-era history-rewrite defence: a
// cumulative-work floor and a table of hard-coded (height, block id) pins,
// shipped with the client release rather than with the protocol.
//
// # What this is for, and what it is not for
//
// `undo_depth` already defends the *tip*: `node/chain.ConsiderBranch` refuses
// any reorg deeper than 1024 blocks, so a node that has been online since
// genesis cannot be made to abandon more than about 8.5 hours of work at any
// hashrate. The uncovered case is the node with **no history** — a first sync
// from genesis, or a return after an outage longer than the undo horizon. It
// has no tip to defend and adopts the heaviest chain it is offered, so an
// attacker who mines a heavier chain *from genesis* takes every node that
// joins later while the early network keeps its own chain. This package exists
// for that case and is scoped to it.
//
// Stated honestly: **no checkpoint stops a hashrate majority from winning the
// live tip going forward.** What checkpoints do is make history rewrite against
// joining nodes impossible past the pinned heights, and nothing more.
//
// # The rule that would break the network if it were missed
//
// **None of this may enter `params.ConsensusRoot()`.** Checkpoints are client
// release policy, not chain parameters: they are edited in every routine
// release, and if editing one could move the parameter hash then every routine
// release would fork the network. The data lives in `spec/checkpoints.json`,
// which the parameter hash does not cover, the types live here rather than in
// `core/`, and `TestCheckpointDataDoesNotEnterTheConsensusRoot` pins the
// boundary so that moving a field across it fails a test instead of a network.
//
// # Why a pin is safe against an honest node
//
// A checkpoint may never name a block younger than MinAge (2880 blocks, 24 h) —
// that is `epoch_length`, and 2.8x `undo_depth`. Anything old enough to be
// pinned is therefore a block no honest node would reorg away even if it wanted
// to, so a pin can never split a live network the way an automatic
// tip-following checkpoint would. That age rule is also what keeps enforcement
// out of the gossip path entirely: a gossiped branch cannot reach further back
// than `undo_depth`, so it can never cross a checkpoint, and `node/sync` is the
// only place the check has to exist.
//
// # Sunset
//
// Past Sunset (height 1,051,200, about one year) no new checkpoint is added and
// the work floor alone carries the defence. Validate refuses a set that pins
// anything above it, so the sunset is a property of the code rather than of
// somebody remembering.
package checkpoints

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	stdsync "sync"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// MinAge is the youngest block a release may pin: 2,880 blocks, one epoch, 24
// hours at the 30 s target, and 2.8x `undo_depth`.
//
// It is a constant rather than a parameter because it is the reason a
// human-published checkpoint cannot partition the network, and a number that
// argument depends on should not be editable in the same file as the data it
// constrains.
const MinAge uint64 = 2880

// Sunset is the height past which no new checkpoint is added: 1,051,200, about
// one year. Above it `min_chain_work` alone carries the floor.
const Sunset uint64 = 1_051_200

// Errors a checkpoint set can fail with. Each names a distinct way a release
// could ship a table that is wrong rather than merely empty.
var (
	ErrUnknownNetwork = errors.New("checkpoints: no entry for this network")
	ErrMalformed      = errors.New("checkpoints: malformed checkpoint file")
	ErrNotAscending   = errors.New("checkpoints: heights are not strictly ascending")
	ErrPastSunset     = errors.New("checkpoints: a checkpoint is above the sunset height")
	ErrZeroID         = errors.New("checkpoints: a checkpoint names the zero block id")
	ErrGenesisPin     = errors.New("checkpoints: a checkpoint names height 0")
	ErrFloorPairing   = errors.New("checkpoints: min_chain_work and min_chain_work_height must be set together")
	ErrTooYoung       = errors.New("checkpoints: a checkpoint is younger than the minimum age")
)

// Checkpoint pins one height to one block id.
type Checkpoint struct {
	Height  uint64
	BlockID types.Hash
}

// Set is the defence one network's release carries.
//
// The zero Set is the v1.0.0 shape: no floor, no pins, and every method on it
// answers "allowed". The enforcement code therefore exists in the binary from
// the first release even though the first release enforces nothing, which is
// the point — a defence added later is a defence that has never been run.
type Set struct {
	// Network names the parameter set this applies to, for diagnostics only.
	Network string

	// MinChainWork is the cumulative-work floor, and MinChainWorkHeight is the
	// height it is measured at: "by MinChainWorkHeight, the real chain has at
	// least MinChainWork of accumulated work".
	//
	// **The height is what makes the floor implementable here.** Bitcoin Core
	// evaluates `nMinimumChainWork` against a peer's *complete* header chain,
	// which it downloads before it requests a single block. `node/sync` is
	// batch-interleaved by design — it validates a batch of headers, fetches
	// their bodies, folds them, and only then asks for the next batch — so a
	// bare "total work must exceed W" would refuse a fresh node's very first
	// batch and every batch after it, because a chain that is not allowed to
	// grow can never reach a floor. Pairing the value with the height it is
	// measured at keeps the refusal exactly where it belongs: a chain that
	// *arrives* at MinChainWorkHeight carrying less than MinChainWork is not
	// the network's chain, and a chain still below that height is simply not
	// yet judged.
	//
	// It still names no block, so it cannot decide between two chains that both
	// clear the floor, which is the property that makes this the least
	// opinionated of the three layers.
	MinChainWork       u256.U256
	MinChainWorkHeight uint64

	// Points are the pins, strictly ascending by height.
	Points []Checkpoint

	// SunsetHeight is the height past which no pin may be added. Zero means the
	// file did not state one, and Validate then refuses to check the rule
	// rather than inventing a bound.
	SunsetHeight uint64

	// MinimumAge is the file's copy of MinAge, cross-checked by Validate so
	// that the number the data file documents and the number the code enforces
	// cannot drift apart.
	MinimumAge uint64
}

// IsEmpty reports whether this set enforces nothing at all — the v1.0.0 shape.
func (s Set) IsEmpty() bool {
	return len(s.Points) == 0 && s.MinChainWork.IsZero()
}

// Highest returns the highest pin, if there is one.
func (s Set) Highest() (Checkpoint, bool) {
	if len(s.Points) == 0 {
		return Checkpoint{}, false
	}
	return s.Points[len(s.Points)-1], true
}

// At returns the block id pinned at a height, if any.
//
// A linear scan on purpose: the table holds one entry per release and the
// schedule is monthly after the first month, so it is a handful of comparisons
// against a slice that is already in cache, and a map would be a second
// representation of the same data that Validate would then have to keep honest.
func (s Set) At(height uint64) (types.Hash, bool) {
	for _, c := range s.Points {
		if c.Height == height {
			return c.BlockID, true
		}
	}
	return types.Hash{}, false
}

// Contradicts reports whether a block at a height disagrees with a pin.
//
// A height this set does not pin never contradicts: silence is not a claim.
func (s Set) Contradicts(height uint64, id types.Hash) bool {
	want, ok := s.At(height)
	return ok && want != id
}

// MeetsFloor reports whether a chain reaching tipHeight with the given
// accumulated work clears the work floor.
//
// A zero floor admits everything, which is v1.0.0. A chain below
// MinChainWorkHeight also admits: it has not reached the height the claim is
// about, so there is nothing to compare it against yet.
func (s Set) MeetsFloor(tipHeight uint64, work u256.U256) bool {
	if s.MinChainWork.IsZero() || tipHeight < s.MinChainWorkHeight {
		return true
	}
	return work.Gte(s.MinChainWork)
}

// MaxPinnableHeight is the highest block a release cut at tipHeight may pin.
//
// This is the 24-hour rule expressed as a function rather than as a sentence in
// a checklist: a release engineer asks this, and the answer is false when the
// chain is younger than one minimum age or when the tip is already past the
// sunset. RELEASE.md's checkpoint step names it, and
// TestTheAgeRuleIsTheOneTheScheduleAssumes pins it against the published
// schedule.
func MaxPinnableHeight(tipHeight uint64) (uint64, bool) {
	if tipHeight < MinAge {
		return 0, false
	}
	h := tipHeight - MinAge
	if h == 0 || h > Sunset {
		return 0, false
	}
	return h, true
}

// ValidateAgainstTip checks the age rule for a set against a chain tip: no pin
// may name a block younger than MinAge.
//
// Separate from Validate because it needs a tip, and a binary validating its
// own embedded table at startup does not have the tip the table was authored
// against — the chain it is about to sync is precisely what it does not know
// yet. This is the release-time check; Validate is the build-time one.
func (s Set) ValidateAgainstTip(tipHeight uint64) error {
	for _, c := range s.Points {
		if c.Height+MinAge > tipHeight {
			return fmt.Errorf("%w: height %d is within %d blocks of tip %d",
				ErrTooYoung, c.Height, MinAge, tipHeight)
		}
	}
	return nil
}

// Validate checks everything about a set that can be checked without a chain.
func (s Set) Validate() error {
	if s.MinimumAge != 0 && s.MinimumAge != MinAge {
		return fmt.Errorf("%w: minimum_age_blocks is %d, the code enforces %d",
			ErrMalformed, s.MinimumAge, MinAge)
	}
	if s.MinChainWork.IsZero() != (s.MinChainWorkHeight == 0) {
		return fmt.Errorf("%w: work %s at height %d",
			ErrFloorPairing, s.MinChainWork.String(), s.MinChainWorkHeight)
	}
	var prev uint64
	for i, c := range s.Points {
		if c.Height == 0 {
			// Genesis is not a checkpoint. Two nodes that disagree about block
			// 0 are on different networks (R3-1) and never speak, so a pin
			// there would decide nothing and would read as though it did.
			return ErrGenesisPin
		}
		if i > 0 && c.Height <= prev {
			return fmt.Errorf("%w: %d after %d", ErrNotAscending, c.Height, prev)
		}
		if c.BlockID == (types.Hash{}) {
			return fmt.Errorf("%w: height %d", ErrZeroID, c.Height)
		}
		if s.SunsetHeight != 0 && c.Height > s.SunsetHeight {
			return fmt.Errorf("%w: height %d is above %d",
				ErrPastSunset, c.Height, s.SunsetHeight)
		}
		prev = c.Height
	}
	return nil
}

// String is the one line an operator needs: what this binary will refuse and
// why. It is what the startup log prints and what the RPC reports.
func (s Set) String() string {
	if s.IsEmpty() {
		return "no checkpoints, no chain-work floor"
	}
	var b strings.Builder
	if !s.MinChainWork.IsZero() {
		fmt.Fprintf(&b, "min_chain_work %s at height %d", s.MinChainWork.String(), s.MinChainWorkHeight)
	} else {
		b.WriteString("no chain-work floor")
	}
	if c, ok := s.Highest(); ok {
		fmt.Fprintf(&b, ", %d checkpoints, highest height %d = %x", len(s.Points), c.Height, c.BlockID[:8])
	} else {
		b.WriteString(", no checkpoints")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Loading.

type fileFormat struct {
	MinimumAgeBlocks uint64                    `json:"minimum_age_blocks"`
	SunsetHeight     uint64                    `json:"sunset_height"`
	Networks         map[string]networkSection `json:"networks"`
}

type networkSection struct {
	MinChainWork       u256.U256 `json:"min_chain_work"`
	MinChainWorkHeight uint64    `json:"min_chain_work_height"`
	Checkpoints        []struct {
		Height  uint64 `json:"height"`
		BlockID string `json:"block_id"`
	} `json:"checkpoints"`
}

// Parse reads one network's section out of a checkpoint file.
func Parse(raw []byte, network string) (Set, error) {
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return Set{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	sec, ok := f.Networks[network]
	if !ok {
		return Set{}, fmt.Errorf("%w: %q", ErrUnknownNetwork, network)
	}
	s := Set{
		Network:            network,
		MinChainWork:       sec.MinChainWork,
		MinChainWorkHeight: sec.MinChainWorkHeight,
		SunsetHeight:       f.SunsetHeight,
		MinimumAge:         f.MinimumAgeBlocks,
	}
	for _, c := range sec.Checkpoints {
		id, err := parseID(c.BlockID)
		if err != nil {
			return Set{}, fmt.Errorf("%w: height %d: %v", ErrMalformed, c.Height, err)
		}
		s.Points = append(s.Points, Checkpoint{Height: c.Height, BlockID: id})
	}
	if err := s.Validate(); err != nil {
		return Set{}, err
	}
	return s, nil
}

func parseID(s string) (types.Hash, error) {
	var h types.Hash
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil {
		return h, err
	}
	if len(raw) != len(h) {
		return h, fmt.Errorf("block id is %d bytes, want %d", len(raw), len(h))
	}
	copy(h[:], raw)
	return h, nil
}

// Load parses the embedded spec/checkpoints.json for a network.
func Load(network string) (Set, error) { return Parse(spec.CheckpointsJSON(), network) }

// MustLoad is Load for a network name this binary is known to embed. A
// malformed embedded table is a broken build, not a runtime condition.
func MustLoad(network string) Set {
	s, err := Load(network)
	if err != nil {
		panic(fmt.Sprintf("checkpoints: spec/checkpoints.json is unusable: %v", err))
	}
	return s
}

// ---------------------------------------------------------------------------
// The process-wide active set.

var (
	activeMu stdsync.RWMutex
	active   Set
)

// Install sets the checkpoint table this process enforces.
//
// Process-wide rather than threaded through every call, for the same reason
// `node/sync.Clock` is: every caller of ValidateHeaders would otherwise have to
// carry release policy it has no other use for, and there is exactly one right
// answer per process. It is meant to be called once, at startup, before any
// sync runs — the mutex is there so that a test which installs a set is not a
// data race against a node that is already serving, not to make mid-flight
// swapping a supported thing to do.
//
// The default is the zero Set, so a library caller that never installs one
// enforces nothing and behaves exactly as it did before this package existed.
func Install(s Set) {
	activeMu.Lock()
	defer activeMu.Unlock()
	s.Points = append([]Checkpoint(nil), s.Points...)
	active = s
}

// Active returns the checkpoint table this process enforces.
func Active() Set {
	activeMu.RLock()
	defer activeMu.RUnlock()
	s := active
	s.Points = append([]Checkpoint(nil), s.Points...)
	return s
}
