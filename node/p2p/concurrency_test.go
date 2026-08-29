package p2p_test

import (
	"sync"
	"testing"

	"zycord/node/p2p"
)

// The gossip engine under concurrent access.
//
// `Engine.Handle` is called from one goroutine per peer, simultaneously. Its
// seen-caches, pending map and orphan pool are all check-then-act: "have I seen
// this? no — record it and forward". Two goroutines running that on the same
// message can both decide they have not seen it, and the consequences differ by
// map: a duplicate forward is harmless bandwidth, a duplicate orphan entry
// escapes the byte bound that R4-H1 depends on.
//
// The audit in docs/adversarial/concurrency.md §8. As there: a mutex with no
// concurrent test is untested, not correct.
func TestEngineSurvivesConcurrentHandling(t *testing.T) {
	p := devnetEasy()
	src := newNode(t, "src", p, key(t, 1).Persistent())
	src.mine(t, 6)

	victim := newNode(t, "victim", p, key(t, 2).Persistent())

	// Every peer offers the same blocks and certificates at the same moment,
	// which is what flood gossip does by design.
	var payloads []struct {
		kind p2p.MessageKind
		body []byte
	}
	for h := uint64(1); h <= src.chain.Height(); h++ {
		blk, err := src.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		ann := p2p.BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		payloads = append(payloads,
			struct {
				kind p2p.MessageKind
				body []byte
			}{p2p.KindBlockAnnounce, ann.MarshalAnnounce()},
			struct {
				kind p2p.MessageKind
				body []byte
			}{p2p.KindBlock, deliver(blk)},
		)
	}

	const peers = 10
	var wg sync.WaitGroup
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := sybilAddr(i)
			victim.engine.Handle(addr, p2p.KindHello, victim.engine.Hello().MarshalHello())
			for round := 0; round < 3; round++ {
				for _, m := range payloads {
					victim.engine.Handle(addr, m.kind, m.body)
				}
			}
		}(i)
	}
	wg.Wait()

	// Whatever it adopted, it must agree with itself — and it must have adopted
	// something, or the test raced through without exercising anything.
	if victim.chain.Height() == 0 {
		t.Fatal("the victim adopted nothing; the test exercised no state transition")
	}
	if victim.chain.StateRoot() != victim.chain.StoredStateRoot() {
		t.Fatal("in-memory state diverged from the committed state under concurrent gossip")
	}
	// Ten peers offering the same six blocks three times over must not leave ten
	// copies of anything: the seen-cache is what makes flood gossip affordable,
	// and a check-then-act race defeats it silently.
	if n := victim.engine.OrphanCount(); n > len(payloads) {
		t.Fatalf("orphan pool holds %d blocks after duplicate gossip; the seen-cache leaked", n)
	}
}
