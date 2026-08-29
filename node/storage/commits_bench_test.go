package storage

import (
	"os"
	"sort"
	"testing"
	"time"
)

// BenchmarkCommitWithAndWithoutTheSidecar prices the one term the owner
// ratified when the sidecar was commissioned: one extra device flush per commit.
//
// IT IS PAIRED AND INTERLEAVED, and that is not fastidiousness. Absolute
// wall-clock on a machine running several build lanes is worthless — five
// unpaired runs of identical code spread 97.5 s to 150.6 s on the day this was
// written — so the two arms alternate commit by commit inside ONE loop, in ONE
// process, against ONE store. Whatever the machine is doing, it is doing it to
// both arms at once. The statistic reported is the MEDIAN of the per-pair
// deltas rather than a ratio of means, because a mean over a shared box is a
// measurement of the neighbours.
//
// The only thing the off arm removes is the sidecar's fsync. The 32-byte
// pwrite stays in both arms, deliberately: the ratified quantity is a device
// flush, the write is a few hundred nanoseconds into an already-allocated page,
// and leaving it in both arms means the number reported is the barrier and
// nothing else.
func BenchmarkCommitWithAndWithoutTheSidecar(b *testing.B) {
	dir := b.TempDir()
	// A compaction threshold no run reaches: a snapshot rewrite landing in one
	// arm and not the other would be measured as that arm's cost.
	s, err := Open(dir, Options{CompactAfterBytes: 1 << 40})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	real := s.sync
	skipSidecar := false
	s.sync = func(f *os.File) error {
		if skipSidecar && f == s.commits {
			return nil
		}
		return real(f)
	}

	value := make([]byte, 1024)
	commit := func(i int) time.Duration {
		batch := &Batch{}
		batch.Put([]byte{byte(i), byte(i >> 8), byte(i >> 16)}, value)
		start := time.Now()
		if err := s.Commit(batch); err != nil {
			b.Fatal(err)
		}
		return time.Since(start)
	}

	with := make([]time.Duration, 0, b.N)
	without := make([]time.Duration, 0, b.N)
	deltas := make([]time.Duration, 0, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		skipSidecar = false
		on := commit(2 * i)
		skipSidecar = true
		off := commit(2*i + 1)
		with = append(with, on)
		without = append(without, off)
		deltas = append(deltas, on-off)
	}
	b.StopTimer()

	b.ReportMetric(median(with).Seconds()*1e3, "ms/commit-with-sidecar")
	b.ReportMetric(median(without).Seconds()*1e3, "ms/commit-without")
	b.ReportMetric(median(deltas).Seconds()*1e3, "ms/median-pair-delta")
	if m := median(without); m > 0 {
		b.ReportMetric(float64(median(with))/float64(m), "x-median-ratio")
	}
}

func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	c := append([]time.Duration(nil), d...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}
