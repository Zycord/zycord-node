// Package harness drives a chain forward in memory.
//
// It is the scaffolding the golden vectors, the griefing suite and the
// differential runner are built on: propose a block, fold it, keep the undo log
// so a test can reorg it away. It performs no proof of work — a test that
// spends CPU on RandomX is a test nobody runs.
//
// Nothing here is consensus. The harness *builds* blocks; the fold *judges*
// them, and the fold is the only opinion that counts.
package harness

import (
	"errors"

	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
)

// Chain is an in-memory chain: state, tip, and the undo logs needed to walk
// backwards.
type Chain struct {
	Params  *params.Params
	State   *state.State
	Headers []types.Header
	Undos   []*state.UndoLog
}

// New builds the genesis block and folds it.
func New(p *params.Params) (*Chain, error) {
	b, s, err := genesis.Build(p)
	if err != nil {
		return nil, err
	}
	return &Chain{
		Params:  p,
		State:   s,
		Headers: []types.Header{b.Header},
		Undos:   []*state.UndoLog{nil}, // genesis is never undone
	}, nil
}

// MustNew is New for tests.
func MustNew(p *params.Params) *Chain {
	c, err := New(p)
	if err != nil {
		panic(err)
	}
	return c
}

// Height returns the height of the tip.
func (c *Chain) Height() uint64 { return c.Headers[len(c.Headers)-1].Height }

// Tip returns the current tip header.
func (c *Chain) Tip() types.Header { return c.Headers[len(c.Headers)-1] }

// NextHeight is the height a newly proposed block would occupy.
func (c *Chain) NextHeight() uint64 { return c.Height() + 1 }

// Propose assembles the next block: it links to the tip, commits to the
// certificate bodies, and — on an epoch boundary — fills in the state root the
// block will be judged against.
//
// It does not filter the certificates. A test that wants to propose an invalid
// block must be able to, or the block rules are untested.
func (c *Chain) Propose(payout types.Address, certs ...*types.Certificate) (*types.Block, error) {
	return c.ProposeWithCites(payout, nil, certs...)
}

// ProposeWithCites is Propose with a cited-competing-header list attached
// (whitepaper §8.1). It exists because the differential runner has to be able
// to exercise `checkCites` — a rule the fold enforces and the fuzzer could
// otherwise never reach, since a harness that never cites produces blocks
// whose citation path is identical in both implementations by being empty in
// both.
//
// Building a *valid* citation is `Sibling` below; callers wanting an invalid
// one mutate what it returns.
func (c *Chain) ProposeWithCites(payout types.Address, cites []*types.Header, certs ...*types.Certificate) (*types.Block, error) {
	tip := c.Tip()
	b := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + c.Params.TargetBlockSeconds,
			EmissionAddr: payout,
			Target:       tip.Target,
			PoW:          types.PoWSeal{SeedEpoch: pow.SeedEpochFor(tip.Height+1, c.Params)},
		},
		Certs: certs,
		Cites: cites,
	}
	b.Header.CertRoot = b.ComputeCertRoot(c.Params)
	b.Header.CitesRoot = b.ComputeCitesRoot(c.Params)

	if c.Params.IsEpochBoundary(b.Header.Height) {
		root, err := fold.SealStateRoot(c.State, b, c.Params)
		if err != nil {
			return nil, err
		}
		b.Header.StateRoot = root
	}
	return b, nil
}

// Apply folds a block onto the tip and records its undo log.
// Sibling returns a header that is a valid citation for the *next* block:
// a competitor to the current tip, sharing the tip's parent and difficulty.
//
// It is what a real proposer would have seen lose a race at this height. The
// three fields checkCites pins from state — height, grandparent, target —
// come from the tip itself, so the only thing distinguishing it is the payout
// address, which is enough to make it a different header with a different id.
// A caller wanting an *invalid* citation mutates one of those three.
//
// Nil once the chain is too young to have siblings: no block at height 0 or 1
// can have one, and checkCites rejects any citation there.
func (c *Chain) Sibling(payout types.Address) *types.Header {
	tip := c.Tip()
	if tip.Height < 1 {
		return nil
	}
	h := tip
	h.EmissionAddr = payout
	return &h
}

func (c *Chain) Apply(b *types.Block) (*fold.Result, error) {
	res, err := fold.ApplyBlock(c.State, b, c.Params)
	if err != nil {
		return nil, err
	}
	c.Headers = append(c.Headers, b.Header)
	c.Undos = append(c.Undos, res.Undo)
	return res, nil
}

// AddBlock proposes and applies in one step.
func (c *Chain) AddBlock(payout types.Address, certs ...*types.Certificate) (*types.Block, *fold.Result, error) {
	b, err := c.Propose(payout, certs...)
	if err != nil {
		return nil, nil, err
	}
	res, err := c.Apply(b)
	if err != nil {
		return nil, nil, err
	}
	return b, res, nil
}

// MustAddBlock is AddBlock for tests that assert on the happy path.
func (c *Chain) MustAddBlock(payout types.Address, certs ...*types.Certificate) *fold.Result {
	_, res, err := c.AddBlock(payout, certs...)
	if err != nil {
		panic(err)
	}
	return res
}

// ErrNoParent reports an attempt to roll back past genesis.
var ErrNoParent = errors.New("harness: cannot roll back the genesis block")

// Rollback undoes the tip block, restoring cells, the spent registry and the
// seen set exactly. Reorg tests live or die on this being exact.
func (c *Chain) Rollback() error {
	if len(c.Headers) <= 1 {
		return ErrNoParent
	}
	fold.UndoBlock(c.State, c.Undos[len(c.Undos)-1])
	c.Headers = c.Headers[:len(c.Headers)-1]
	c.Undos = c.Undos[:len(c.Undos)-1]
	return nil
}

// Mine advances the chain by n empty blocks paid to payout. It is how a test
// gets funded coins: there is no faucet and no premine, so the only way to hold
// a coin is to have mined it. Mine to play.
func (c *Chain) Mine(payout types.Address, n int) error {
	for i := 0; i < n; i++ {
		if _, _, err := c.AddBlock(payout); err != nil {
			return err
		}
	}
	return nil
}

// MineUntilFunded mines just enough blocks for payout to hold a spendable
// balance: one block to earn a reward, plus COINBASE_MATURITY blocks for it to
// mature, plus one for the release to land.
func (c *Chain) MineUntilFunded(payout types.Address) error {
	return c.Mine(payout, int(c.Params.CoinbaseMaturity)+2)
}

// Balance returns a spendable native-coin balance.
func (c *Chain) Balance(addr types.Address) u256.U256 {
	return c.State.Get(types.NativeBalanceSlot(addr))
}

// AssetBalance returns a spendable balance of a non-native asset.
func (c *Chain) AssetBalance(addr, asset types.Address) u256.U256 {
	return c.State.Get(types.BalanceSlot(addr, asset))
}
