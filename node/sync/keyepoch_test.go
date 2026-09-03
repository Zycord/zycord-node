package sync_test

import (
	"errors"
	"strings"
	gosync "sync"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/sync"
)

// epochCountingEngine records the DISTINCT keys the work function is asked to
// evaluate under.
//
// Counting hashes is the wrong instrument for this property. A RandomX key is a
// cache initialisation and a hash under a key already held is orders of
// magnitude cheaper, so what an attacker amplifies is the number of distinct
// keys one message demands, not the number of digests.
type epochCountingEngine struct {
	mu   gosync.Mutex
	seen map[types.Hash]bool
}

func newEpochCountingEngine() *epochCountingEngine {
	return &epochCountingEngine{seen: make(map[types.Hash]bool)}
}

func (c *epochCountingEngine) Name() string { return pow.Dev{}.Name() }
func (c *epochCountingEngine) Hash(key types.Hash, in []byte) types.Hash {
	c.mu.Lock()
	c.seen[key] = true
	c.mu.Unlock()
	return pow.Dev{}.Hash(key, in)
}
func (c *epochCountingEngine) distinctKeys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// farCitingPeer serves genuine headers except at its tip, where it serves a
// header committing to a citation list of MaxCitesPerBlock headers placed in
// widely separated RandomX key epochs, and the body that matches it.
//
// Only the tip's CitesRoot changes, and the tip is re-mined at its own real
// declared target, so the header stage accepts it exactly as it accepts the
// honest tip. The forgery is therefore reached with the carrier genuinely paid
// for — which is the point: on this path the carrier costs work, and the
// citations are still the sender's to place.
type farCitingPeer struct {
	*peer
	forged types.Header
	body   *types.Block
	epochs int
}

func newFarCitingPeer(t *testing.T, base *peer, p *params.Params) *farCitingPeer {
	t.Helper()
	tip, err := base.chain.BlockAt(base.chain.Height())
	if err != nil {
		t.Fatal(err)
	}
	body := &types.Block{Header: tip.Header, Certs: tip.Certs}
	epochs := map[uint64]bool{pow.SeedEpochFor(tip.Header.Height, p): true}
	for i := uint64(1); i <= uint64(p.MaxCitesPerBlock); i++ {
		// Seven key intervals apart: citations a few blocks apart share an
		// epoch and would measure nothing at all.
		h := i * 7 * p.RandomXKeyInterval
		epochs[pow.SeedEpochFor(h, p)] = true
		body.Cites = append(body.Cites, &types.Header{
			Version:  types.HeaderVersion,
			Height:   h,
			ParentID: types.Hash{byte(i)},
			Time:     p.GenesisTime + h*p.TargetBlockSeconds,
			// The attacker's own declaration, so these citations cost their
			// sender zero hashes. Nothing on this path bounds a cited header's
			// declared target.
			Target: u256.Max,
			PoW:    types.PoWSeal{Nonce: uint32(i)},
		})
	}
	body.Header.CitesRoot = body.ComputeCitesRoot(p)
	// CitesRoot is a proof-of-work input, so the honest tip's nonce no longer
	// solves. Re-mine at the target the rule actually requires, leaving the
	// declared target untouched.
	if !pow.Solve(pow.Dev{}, &body.Header, p, 1<<24) {
		t.Fatal("setup: could not re-solve the forged tip at the real target")
	}
	return &farCitingPeer{peer: base, forged: body.Header, body: body, epochs: len(epochs)}
}

func (c *farCitingPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	out, err := c.peer.Headers(from, count)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Height == c.forged.Height {
			out[i] = c.forged
		}
	}
	return out, nil
}

func (c *farCitingPeer) Body(id types.Hash) (*types.Block, error) {
	if id == c.forged.ID() {
		c.bodyRequests++
		return c.body, nil
	}
	return c.peer.Body(id)
}

// TestASyncedBodyCannotBuyManyKeyEpochsThroughItsCitations is the sync half of
// the citation-work key-epoch flood — a zero-work block forcing a RandomX key
// epoch initialisation per citation, before the height rule that would refuse
// it — and it exists because the gossip half alone leaves the rule
// path-dependent. A rule enforced on one ingress path and not the other is the
// shape this repository treats as the serious class: it is not a weaker rule,
// it is no rule, because an attacker picks the door.
//
// The property: the number of DISTINCT proof-of-work key epochs a served body
// can force this node to initialise does not depend on the heights its sender
// chose for the headers it cites.
//
// pow.KeyFor derives a key from a header's own height, so a citation at an
// arbitrary height names an arbitrary key epoch. With the citation work loop
// running before any height rule, one body carrying MaxCitesPerBlock citations
// at widely separated heights demanded that many extra epochs before the fold
// refused the block for a rule its own bytes already violated.
//
// A test that only asserted "sync fails" would pass either way — the fold
// refuses this block regardless — so the assertion is on the work demanded.
func TestASyncedBodyCannotBuyManyKeyEpochsThroughItsCitations(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	victim := newNode(t, p, key(t, 3).Persistent())
	liar := newFarCitingPeer(t, &peer{t: t, chain: source.chain}, p)

	// Anti-vacuity 1: the forged citations must really name distinct epochs.
	if liar.epochs < 2 {
		t.Fatalf("setup: the forged citations name %d key epoch(s); this test can "+
			"only measure amplification across at least 2", liar.epochs)
	}
	// Anti-vacuity 2: every forged citation must PASS pow.CheckWork, or the
	// citation loop would be refusing them on their own work rather than never
	// reaching them, and the test would be measuring the work check. Asked of a
	// bare pow.Dev, not of the instrument, which would otherwise be seeded with
	// every answer before the measurement began.
	for i, h := range liar.body.Cites {
		if err := pow.CheckWork(pow.Dev{}, *h, p); err != nil {
			t.Fatalf("setup: forged citation %d does not pass CheckWork (%v); at "+
				"u256.Max no digest can exceed the target and it must", i, err)
		}
	}

	work := newEpochCountingEngine()
	cache := sync.NewBodyCache()
	_, err := sync.Run(victim.chain, work, cache.Source(liar), 128)
	if liar.bodyRequests == 0 {
		t.Fatal("setup: the forged tip was never requested, so nothing was exercised")
	}

	// The chain synced here spans heights 0..6, one key epoch. The rejected
	// design ("check the work of every citation, then let the fold's height
	// rule refuse the block") gives a different answer in this very scenario:
	// it demands that one epoch plus MaxCitesPerBlock more.
	if got := work.distinctKeys(); got != 1 {
		t.Fatalf("one served body drove %d distinct key epochs; every header on "+
			"this chain sits in one, so a citation's height must not be able to "+
			"name another", got)
	}

	// And the refusal happens at ingress, before Retain, rather than in the
	// fold once the body is already cached. Asserted after the measurement
	// above, because "sync fails" is true either way and is not the property.
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("got %v, want the body refused at ingress as unavailable", err)
	}
	// By identity, not only by sentinel: every refusal on this path wraps
	// ErrBodyUnavailable, so the sentinel alone cannot distinguish the rule
	// this test names from a benign failure to serve the body at all.
	if !strings.Contains(err.Error(), "cites a header at height") {
		t.Fatalf("refused with %v, want the citation height rule; any other "+
			"refusal means the count above was bounded for some other reason", err)
	}
}
