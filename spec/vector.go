package spec

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
)

// A Vector is one executable statement about the protocol:
//
//	(pre-state, block) → (post-state | invalid, outcomes, fees)
//
// The vectors in spec/vectors are the compatibility contract. An independent
// implementation that passes them is a peer, not a fork — which is what allows
// the maintainer of this repository to eventually be nobody in particular.
//
// The block is carried as hex-encoded SSZ rather than as structured JSON on
// purpose: an implementation that cannot parse the wire format has not
// implemented the protocol, and a vector that hands it a pre-parsed block would
// hide that.
type Vector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Params names the parameter file: one of Networks().
	Params string   `json:"params"`
	Pre    PreState `json:"pre"`
	// Block is hex-encoded ssz(block), 0x-prefixed.
	Block  string `json:"block"`
	Expect Expect `json:"expect"`
}

// PreState is the consensus state a vector starts from.
type PreState struct {
	Cells []CellEntry `json:"cells"`
	Spent []string    `json:"spent"`
	Seen  []SeenEntry `json:"seen"`
}

// CellEntry is one stored value: a slot and its decimal contents.
type CellEntry struct {
	Addr  string `json:"addr"`
	Word  string `json:"word"`
	Value string `json:"value"`
}

// SeenEntry is one already-committed certificate id and the TTL it carries.
type SeenEntry struct {
	ID  string `json:"id"`
	TTL uint64 `json:"ttl"`
}

// Expect is everything the fold must produce.
type Expect struct {
	// Valid reports whether the block is a valid block at all. When false,
	// every other field is absent: an invalid block has no outcomes.
	Valid bool `json:"valid"`
	// Rule names the protocol rule that rejects the block, and it IS a
	// conformance requirement: present on every invalid vector, compared on
	// replay, and the reason this corpus can tell an implementation that
	// rejects a block from one that rejects it *by the stated rule* — two
	// implementations can agree that a block is invalid and disagree about
	// which rule refused it, and that disagreement is a real incompatibility.
	//
	// The ids come from docs/ARCHITECTURE.md — §8's B0..B17 for the block rules,
	// C0..C5 for a citation's, §7's V1..V9 for a certificate's, and §8's F13/F14
	// for the two fold rules that can reject — and that document is normative. A
	// vector may only name a rule; an implementation that rejects a block by
	// an internal assertion has not applied the rule the vector is about, and
	// spec/gen refuses to emit such a vector at all.
	//
	// A vector names exactly one rule because its block breaks exactly one.
	// That is a property of the corpus rather than of the format: nothing in
	// the protocol fixes the order rules are evaluated in, so a block that
	// broke two could be reported either way by two conformant
	// implementations, and the field would be unanswerable. The generator
	// carries the assertions that keep it true where the margin is thin.
	Rule string `json:"rule,omitempty"`
	// Reason is a human-readable note about why an invalid block is invalid.
	// It is documentation, never a conformance requirement — implementations
	// are held to the verdict and to the rule, never to the wording.
	Reason string `json:"reason,omitempty"`

	Outcomes []OutcomeEntry `json:"outcomes,omitempty"`
	// SeqGasUsed and ParGasUsed are the declared gas of every included
	// certificate — what the block ceilings bound.
	SeqGasUsed uint64 `json:"seq_gas_used,omitempty"`
	ParGasUsed uint64 `json:"par_gas_used,omitempty"`
	// SeqGasApplied and ParGasApplied are the gas of the certificates that
	// applied — the only input to the base fees (R2-H2).
	SeqGasApplied uint64 `json:"seq_gas_applied,omitempty"`
	ParGasApplied uint64 `json:"par_gas_applied,omitempty"`
	Burned        string `json:"burned,omitempty"`
	MinerReward   string `json:"miner_reward,omitempty"`
	// Treasury is the subsidy's treasury share for this block. It is separate
	// from MinerReward because the two are paid to different places by
	// different rules: the producer's share matures, the treasury's does not.
	Treasury string `json:"treasury,omitempty"`
	Matured  string `json:"matured,omitempty"`
	// PostRoot is the epoch state root the block commits to, present only on
	// epoch-boundary blocks.
	PostRoot string `json:"post_root,omitempty"`
	// Post is the complete resulting state. It is the strongest form of the
	// assertion and the one an independent implementation should diff against
	// when a vector fails.
	Post PreState `json:"post"`
}

// OutcomeEntry is what the fold did with one certificate, in fold order.
type OutcomeEntry struct {
	ID       string `json:"id"`
	Outcome  string `json:"outcome"`
	Charged  string `json:"charged"`
	Refunded string `json:"refunded"`
	// RefundBurned is the remainder settlement destroyed because RefundTo's
	// authority was already spent, rather than credited. Omitted when zero,
	// which is every ordinary certificate.
	RefundBurned string `json:"refund_burned,omitempty"`
	// Swept is what F8b moved out of the addresses this certificate burned and
	// into the refund address; SweptStranded is what it had to leave behind
	// because the refund address was already spent. Both count native
	// drops only — an asset residual moves under the same rule and is observed
	// in the cells, like every other asset movement in this protocol. Both are
	// omitted when zero.
	Swept         string `json:"swept,omitempty"`
	SweptStranded string `json:"swept_stranded,omitempty"`
	// StrandedCells counts every cell left behind, which is how an asset
	// residual is reported at all: the two amounts above are drops.
	StrandedCells uint32 `json:"stranded_cells,omitempty"`
}

// ErrUnknownParams reports a vector naming a parameter set that does not exist.
var ErrUnknownParams = errors.New("spec: unknown parameter set")

// ParamsFor resolves a vector's parameter name.
func ParamsFor(name string) (*params.Params, error) {
	switch name {
	case "mainnet":
		return Mainnet(), nil
	case "testnet":
		return Testnet(), nil
	case "devnet":
		return Devnet(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownParams, name)
	}
}

// LoadVectors reads every vector in a directory, sorted by file name so that a
// run is reproducible.
func LoadVectors(dir string) ([]*Vector, error) {
	names, err := jsonFileNames(dir)
	if err != nil {
		return nil, err
	}

	out := make([]*Vector, 0, len(names))
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var v Vector
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, &v)
	}
	return out, nil
}

// Write serialises a vector to a file with stable formatting, so that a
// regenerated corpus produces a readable diff rather than a reshuffle.
func (v *Vector) Write(path string) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// DecodeBlock parses the vector's block.
func (v *Vector) DecodeBlock(p *params.Params) (*types.Block, error) {
	raw, err := decodeHex(v.Block)
	if err != nil {
		return nil, err
	}
	return types.UnmarshalBlock(raw, p)
}

// BuildState materialises a pre-state.
func (ps *PreState) BuildState() (*state.State, error) {
	s := state.New()
	for _, c := range ps.Cells {
		addr, err := decodeAddress(c.Addr)
		if err != nil {
			return nil, err
		}
		word, err := decodeHash(c.Word)
		if err != nil {
			return nil, err
		}
		value, err := u256.FromDecimal(c.Value)
		if err != nil {
			return nil, err
		}
		s.Set(types.Slot{Addr: addr, Word: word}, value)
	}
	for _, a := range ps.Spent {
		addr, err := decodeAddress(a)
		if err != nil {
			return nil, err
		}
		s.MarkSpent(addr)
	}
	for _, e := range ps.Seen {
		id, err := decodeHash(e.ID)
		if err != nil {
			return nil, err
		}
		s.MarkSeen(id, e.TTL)
	}
	return s, nil
}

// Snapshot captures a state as a pre/post-state description, in canonical
// order so that two snapshots of equal states are byte-identical.
func Snapshot(s *state.State) PreState {
	var out PreState
	for _, slot := range s.SortedCells() {
		out.Cells = append(out.Cells, CellEntry{
			Addr:  encodeHex(slot.Addr[:]),
			Word:  encodeHex(slot.Word[:]),
			Value: s.Get(slot).String(),
		})
	}
	for _, a := range s.SortedSpent() {
		out.Spent = append(out.Spent, encodeHex(a[:]))
	}
	for _, e := range s.SortedSeen() {
		out.Seen = append(out.Seen, SeenEntry{ID: encodeHex(e.ID[:]), TTL: e.TTL})
	}
	return out
}

// Equal reports whether two snapshots describe the same state.
func (ps PreState) Equal(other PreState) bool {
	if len(ps.Cells) != len(other.Cells) || len(ps.Spent) != len(other.Spent) ||
		len(ps.Seen) != len(other.Seen) {
		return false
	}
	for i := range ps.Cells {
		if ps.Cells[i] != other.Cells[i] {
			return false
		}
	}
	for i := range ps.Spent {
		if ps.Spent[i] != other.Spent[i] {
			return false
		}
	}
	for i := range ps.Seen {
		if ps.Seen[i] != other.Seen[i] {
			return false
		}
	}
	return true
}

// A DifficultyVector is one executable statement about the difficulty rule:
//
//	(params, headers) → next_target
//
// It exists because pow.NextTarget takes a window of preceding headers and a
// parameter set, and nothing else — no consensus state, no block — so its
// statement cannot be squeezed into Vector's (pre-state, block) shape. It is
// its own vector kind rather than an optional section bolted onto Vector,
// because a Vector whose Pre and Block happened to be empty would look like a
// degenerate fold vector to any reader who has not memorised this comment.
//
// Headers are carried as hex-encoded ssz(header), oldest first — the same
// "cannot parse the wire format" discipline Vector.Block already follows: an
// implementation that cannot decode a header has not implemented the wire
// format, and a vector that handed it pre-parsed headers would hide that.
type DifficultyVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Params names the parameter file: one of Networks().
	Params string `json:"params"`
	// Headers is the exact window pow.NextTarget is given, oldest first.
	// Every caller in this tree (node/miner, node/sync via
	// chain.RecentHeaders) hands it at most DifficultyWindow+1 headers, and
	// as few as one on a young chain. The corpus carries both of those ends
	// AND one window deliberately longer than any caller here produces: the
	// rule truncates, a second implementation's header store may well return
	// more than it asks for, and a vector is the only thing that can say
	// which end the truncation keeps.
	Headers []string         `json:"headers"`
	Expect  DifficultyExpect `json:"expect"`
}

// DifficultyExpect is what pow.NextTarget must produce.
type DifficultyExpect struct {
	// NextTarget is the computed target, decimal — it can exceed 2^53.
	NextTarget string `json:"next_target"`
}

// LoadDifficultyVectors reads every difficulty vector in a directory, sorted
// by file name so that a run is reproducible.
func LoadDifficultyVectors(dir string) ([]*DifficultyVector, error) {
	names, err := jsonFileNames(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*DifficultyVector, 0, len(names))
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var v DifficultyVector
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, &v)
	}
	return out, nil
}

// jsonFileNames lists the *.json files directly inside dir, sorted. Shared by
// LoadVectors and LoadDifficultyVectors, which decode into different types
// but agree on how a corpus directory is read.
func jsonFileNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Write serialises a difficulty vector to a file with stable formatting, so
// that a regenerated corpus produces a readable diff rather than a reshuffle.
func (v *DifficultyVector) Write(path string) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// DecodeHeaders parses the vector's header window.
func (v *DifficultyVector) DecodeHeaders() ([]types.Header, error) {
	out := make([]types.Header, 0, len(v.Headers))
	for i, hx := range v.Headers {
		raw, err := decodeHex(hx)
		if err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}
		h, err := types.UnmarshalHeader(raw)
		if err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}
		out = append(out, *h)
	}
	return out, nil
}

func encodeHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

func decodeHash(s string) (types.Hash, error) {
	var h types.Hash
	raw, err := decodeHex(s)
	if err != nil {
		return h, err
	}
	if len(raw) != len(h) {
		return h, fmt.Errorf("spec: expected %d bytes, got %d", len(h), len(raw))
	}
	copy(h[:], raw)
	return h, nil
}

func decodeAddress(s string) (types.Address, error) { return decodeHash(s) }
