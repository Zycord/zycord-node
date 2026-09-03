package p2p

import (
	"testing"

	"zycord/core/pow"
)

// The four benchmarks below are one paired measurement, and they are meant to
// be read as ratios rather than as times: what the announce path's target
// re-derivation costs, against what the same 232-byte message already costs
// this node before any such check could add.
//
// The denominator is BenchmarkTheFloorEveryAnnouncementAlreadyPays — the parse
// and the id hash at the top of OnBlockAnnounceFrom, which every announcement
// forces and which no policy here can remove. Deriving the target from the
// window on every announcement costs at least 30x that floor and allocates at
// least 100x it — an independent run of these same benchmarks measured 50.8x,
// 101.5x and 182x allocations, so these are lower bounds on the ratio and not
// estimates of it — which is a second asymmetric-cost hole opened while closing
// the first; through the tip memo the same answer costs about a fifth of the
// floor and allocates a third of it. The work check it now stands in front of is the fourth, and it is
// measured with the dev hasher, which is a lower bound on RandomX by three
// orders of magnitude (the Engine's own note on the work cache records ~55 ms
// per relayed block there).

// benchWindow is deep enough that RecentHeaders(DifficultyWindow+1) reads a
// full window rather than a short prefix.
const benchWindow = 120

func BenchmarkTheFloorEveryAnnouncementAlreadyPays(b *testing.B) {
	c, _, _ := announceChain(b, benchWindow)
	raw := BlockAnnounce{Header: tipHeaderAt(b, c, ruleTarget(c), 1)}.MarshalAnnounce()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ann, err := UnmarshalAnnounce(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = ann.Header.ID()
	}
}

func BenchmarkRederivingTheTargetFromTheWindow(b *testing.B) {
	c, _, _ := announceChain(b, benchWindow)
	p := c.Params()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pow.NextTarget(c.RecentHeaders(int(p.DifficultyWindow)+1), p)
	}
}

func BenchmarkRederivingTheTargetThroughTheTipMemo(b *testing.B) {
	c, e, _ := announceChain(b, benchWindow)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := e.tipNextTarget(c.Tip()); !ok {
			b.Fatal("the window did not end at the tip")
		}
	}
}

func BenchmarkTheWorkCheckTheRederivationStandsInFrontOf(b *testing.B) {
	c, e, _ := announceChain(b, benchWindow)
	h := tipHeaderAt(b, c, ruleTarget(c), 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// A distinct id each iteration, so the work cache never answers.
		h.PoW.Nonce = uint32(i) | 1<<30
		_ = e.work.Check(e.Engine, h, c.Params())
	}
}
