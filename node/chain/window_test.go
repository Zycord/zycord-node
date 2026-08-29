package chain_test

import (
	"fmt"
	"sync"
	"testing"
)

// TestTheDifficultyWindowIsOneSnapshot reads HeadersEndingAt while the chain
// reorgs underneath it, and requires every window it returns to be a real
// chain: header i+1's ParentID is header i's id, all the way down.
//
// # What this test is, and what it is NOT
//
// It is a standing invariant. It is NOT a demonstration that the old
// implementation was broken, and the distinction is recorded rather than
// glossed because this repository has been bitten by the other kind.
//
// The fix it accompanies replaces ninety-two lock acquisitions with one. The
// defect that motivates it is read, not observed: with a lock per header, a
// reorg landing between two acquisitions returns a window MIXING TWO
// BRANCHES, pow.NextTarget derives a target from the mixture, and the honest
// peer whose header disagrees is scored down — which also removes it from
// sync candidacy (I5-M5), so the node punishes its own race and loses a sync
// source for it, silently.
//
// **Driving the per-header form with this test does not fail it.** Three
// attempts, all green. Two earlier framings of the writer were tried and
// discarded first: extending the chain only (a torn read across an extension
// is still a linked chain, so it is unobservable by construction) and
// replacing the tip alone (depth one leaves every header below untouched, so
// linkage holds). Depth three does put a parent change in the middle of the
// window, and the interleave is simply too narrow to hit by chance at this
// rate. Forcing it would take a scheduling hook inside the chain lock, which
// is more machinery inside consensus-adjacent code than the finding is worth.
//
// So this stays read-verified and never observed. That classification is
// load-bearing and must not be quietly upgraded. What the test does buy is real — it fails immediately if any
// future implementation returns a window that is not a chain, and it drives
// real reorgs while asking.
func TestTheDifficultyWindowIsOneSnapshot(t *testing.T) {
	p := devnetEasy()
	n := openNode(t, t.TempDir(), p, key(t, 1).Persistent())
	defer n.close(t)

	n.mine(t, 12) // something to read before the writer starts

	const windowSize = 8
	stop := make(chan struct{})
	violations := make(chan string, 8)
	var reads, links int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// The READER runs in the goroutine, so that the writer — which needs
	// t.Fatal on a real failure — stays on the test's own goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			h := n.chain.Height()
			if h < windowSize {
				continue
			}
			w := n.chain.HeadersEndingAt(h, windowSize)
			mu.Lock()
			reads++
			mu.Unlock()
			for i := 1; i < len(w); i++ {
				mu.Lock()
				links++
				mu.Unlock()
				if w[i].ParentID != w[i-1].ID() {
					select {
					case violations <- fmt.Sprintf(
						"window ending at %d is not a chain: height %d does not "+
							"extend height %d — the read was torn across a reorg "+
							"and mixes two branches", h, w[i].Height, w[i-1].Height):
					default:
					}
					return
				}
				if w[i].Height != w[i-1].Height+1 {
					select {
					case violations <- fmt.Sprintf(
						"window ending at %d skips a height: %d then %d",
						h, w[i-1].Height, w[i].Height):
					default:
					}
					return
				}
			}
		}
	}()

	// The WRITER: extend, and repeatedly replace the tip with a different
	// block at the same height. Rollback plus a fresh Assemble is a branch
	// replacement — the clock advances per template, so the new block has a
	// different id at the same height, which is precisely what makes a torn
	// read observable.
	const rounds, depth = 120, 3
	reorgs := 0
	for i := 0; i < rounds; i++ {
		n.mine(t, 1)
		if i%2 == 0 {
			// Depth THREE, not one, and that is the whole difference between
			// a test and a decoration. Replacing only the tip leaves every
			// header below it untouched, so a torn read still returns a
			// linked chain and the property is unobservable — the previous
			// version of this test did exactly that and passed against the
			// per-header-lock implementation it exists to reject. At depth
			// three, headers in the MIDDLE of the window change parents, and
			// a read interleaved with the replacement returns two branches
			// spliced together.
			for d := 0; d < depth; d++ {
				if err := n.chain.Rollback(); err != nil {
					t.Fatalf("round %d: rollback %d: %v", i, d, err)
				}
			}
			n.mine(t, depth)
			reorgs++
		}
	}
	close(stop)
	wg.Wait()
	close(violations)

	for v := range violations {
		t.Error(v)
	}

	// Anti-vacuity, three ways: the reader must have read, it must have
	// checked linkage rather than only degenerate windows, and the writer must
	// actually have replaced blocks.
	mu.Lock()
	gotReads, gotLinks := reads, links
	mu.Unlock()
	if gotReads == 0 {
		t.Fatal("no window was read")
	}
	if gotLinks == 0 {
		t.Fatalf("%d windows read and no linkage checked", gotReads)
	}
	if reorgs < 10 {
		t.Fatalf("only %d tip replacements; the reader was not racing a reorg", reorgs)
	}
	t.Logf("%d windows, %d links checked, %d tip replacements, height %d",
		gotReads, gotLinks, reorgs, n.chain.Height())
}
