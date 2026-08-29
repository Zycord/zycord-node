package chain

import (
	"encoding/binary"

	"zycord/core/fold"
)

// Chain statistics (M1-G7, repaired at R5).
//
// These used to live in node/rpc and be fed from exactly one place: the miner's
// loop. Everything they claimed to count was therefore wrong in the same
// direction — a non-mining node reported zero blocks applied forever, a mining
// node did not count the blocks it received, and reorg depth was never recorded
// at all because nothing ever called the function that recorded it.
//
// A metric that cannot be non-zero is the observability version of a test that
// cannot fail, and it was found the same way: a check that depended on
// `deepest_reorg` passed while the number was structurally stuck at zero.
//
// So they are counted here, where the events actually happen. Every block that
// this node accepts — mined, gossiped or synced — passes through Apply or
// ConsiderBranch, and there is no fourth door.
type Stats struct {
	// BlocksApplied counts blocks accepted onto the chain, from any source.
	BlocksApplied uint64
	CertsApplied  uint64
	CertsSkipped  uint64
	CertsDropped  uint64
	// ReorgEvents counts branch switches; DeepestReorg is the most blocks ever
	// unwound in one. Operationally this is the number that matters most on a
	// live chain, and it is the one that was missing.
	ReorgEvents  uint64
	DeepestReorg uint64
	// BlocksUndone counts blocks removed by reorgs, so that applied-minus-undone
	// is the net a reader can reconcile against the height.
	BlocksUndone uint64
	// BlocksRejected counts blocks the fold refused.
	//
	// The billing law and conservation are enforced as block-invalidity, so a
	// violation cannot be applied — it shows up as a refusal. Until R5 that
	// refusal was recorded nowhere: the gossip path logged it only if the peer's
	// score crossed a threshold, so "no node violated the billing law" was
	// checkable only by scraping logs for a line that usually was not written.
	// A refusal is a fact about this node and belongs in a counter.
	BlocksRejected uint64
}

// Stats returns a snapshot of the counters.
func (c *Chain) Stats() Stats {
	c.assertNotInRead("Stats")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// withBlock returns the counters after one block's outcomes.
//
// Pure, and returning a value rather than mutating in place, because the
// counters now ride the same storage batch as everything else — so the version
// that goes to disk must be computed *before* the commit, while the version in
// memory must not change until the commit lands. Mutating in place made the two
// impossible to keep together, and the persisted counters were silently one
// commit stale.
func (s Stats) withBlock(res *fold.Result) Stats {
	s.BlocksApplied++
	for _, o := range res.Outcomes {
		switch o.Outcome {
		case fold.Applied:
			s.CertsApplied++
		case fold.SkippedStale, fold.SkippedOverflow:
			s.CertsSkipped++
		case fold.Dropped:
			s.CertsDropped++
		}
	}
	return s
}

// recordRejection notes a block the fold refused.
//
// This one does mutate in place and is not persisted with a block, because a
// refusal is precisely the case where no block is committed. It is written on
// the next successful commit, which is the earliest a batch exists to carry it.
func (c *Chain) recordRejection() { c.stats.BlocksRejected++ }

// withReorg returns the counters after a branch switch of the given depth.
func (s Stats) withReorg(undone int) Stats {
	if undone == 0 {
		// A branch that extends the tip is not a reorg. Counting it as one would
		// make the deepest-reorg number meaningless by flooding it with zeroes,
		// which is how a metric becomes decorative.
		return s
	}
	s.ReorgEvents++
	s.BlocksUndone += uint64(undone)
	if d := uint64(undone); d > s.DeepestReorg {
		s.DeepestReorg = d
	}
	return s
}

// statsFields is the on-disk order. Appending is safe — a shorter record simply
// leaves later fields at zero — and reordering is not, which is why the order is
// written down once here rather than implied by a struct literal in two places.
func (s *Stats) fields() []*uint64 {
	return []*uint64{
		&s.BlocksApplied, &s.CertsApplied, &s.CertsSkipped, &s.CertsDropped,
		&s.ReorgEvents, &s.DeepestReorg, &s.BlocksUndone, &s.BlocksRejected,
	}
}

func (s Stats) encode() []byte {
	fields := (&s).fields()
	out := make([]byte, 0, len(fields)*8)
	for _, f := range fields {
		out = binary.LittleEndian.AppendUint64(out, *f)
	}
	return out
}

// decodeStats reads counters written by this or an older version.
//
// A short record is not corruption: it is a node upgraded from a build with
// fewer counters, and the missing ones are legitimately zero. A long one is a
// downgrade, and the extra fields are ignored rather than refused — these are
// observability, not consensus, and refusing to start over a counter would be
// the wrong trade entirely.
func decodeStats(raw []byte) Stats {
	var s Stats
	fields := (&s).fields()
	for i, f := range fields {
		if (i+1)*8 > len(raw) {
			break
		}
		*f = binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
	}
	return s
}
