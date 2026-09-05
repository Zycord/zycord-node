package state

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
)

// The cost of the epoch state root as a function of state size — the numbers
// the incremental root cache is about, so that the next person does not have to
// re-measure.
//
// Six regimes, because they are six different costs and reporting one figure
// for all of them is how the "hundreds of ms at 10M" estimate that motivated
// the cache came to be wrong by two orders of magnitude — and how the first
// summary of this work came to quote a 55–64× speedup that only one of the
// six enjoys, and which is itself 28–73× depending on the size:
//
//   - FromScratch — no cache at all. What every block used to pay, and what a
//     restart and a capacity crossing still pay.
//   - Unchanged   — nothing written since the last call. The floor.
//   - OrdinaryBlock — a block of cell writes to slots that already exist. No
//     leaf changes position. This is the *only* regime that is fast, and it is
//     still not proportional to the dirty set: see below.
//   - OneNewCell — a single write to a slot that does not exist yet, which is
//     what an ordinary payment to a fresh address does. One insertion into a
//     sorted list shifts every leaf after it, so this is Θ(N).
//   - OneRetire — a single RETIRE. Same shape, in the registry subtree. This is
//     the adversarial floor: 700 gas, 0.0175% of the sequential ceiling, and it
//     denies the fast path for the whole block.
//   - RetirementBlock — a block of RETIREs at the sequential-gas ceiling.
//
// The two single-operation regimes are the important ones and they were missing
// from the first version of this file. They show that the improvement is 6.7–
// 7.9× against a workload an attacker chooses, not the 28–73× that the
// overwrite-only regime shows. Nothing about the cache changes that: the leaves
// are a sorted list and no cache can make an insertion into one cheap without
// changing what the root is.
//
// Sizes are the live cell count and the registry count together: populate(n)
// makes n of each, so "100000" is 200k leaves across the two subtrees.

// populate fills a state with n cells and n registry entries, deterministically
// and with keys spread across the whole address space so the sorted order is
// not the insertion order.
func populate(s *State, n int) {
	for i := 0; i < n; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
}

func slotOf(i int) types.Slot {
	var sl types.Slot
	// A hash-like spread: the mixed bits go to the top of the key so that
	// consecutive i land far apart in canonical order.
	binary.BigEndian.PutUint64(sl.Addr[0:8], mix(uint64(i)))
	binary.BigEndian.PutUint64(sl.Addr[24:32], uint64(i))
	binary.BigEndian.PutUint64(sl.Word[24:32], mix(uint64(i)^0x5bf03635))
	return sl
}

func addrOf(i int) types.Address {
	var a types.Address
	binary.BigEndian.PutUint64(a[0:8], mix(uint64(i)^0xa5a5a5a5))
	binary.BigEndian.PutUint64(a[24:32], uint64(i))
	return a
}

// mix is splitmix64's finaliser: deterministic, stdlib-only, no clock.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

var benchSizes = []int{1_000, 10_000, 100_000, 1_000_000}

// BenchmarkRootFromScratch is the cost the node paid on every commit, every
// switchTo and every rollback before the cache: a full sort of the key set, a
// full leaf-hash pass and a full merkle build.
func BenchmarkRootFromScratch(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := New()
			populate(s, n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.invalidateRootCache()
				_ = s.Root()
			}
		})
	}
}

// BenchmarkRootUnchanged is the floor: nothing was written, so the answer is
// already in the tree and only the two length mix-ins are recomputed.
func BenchmarkRootUnchanged(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := New()
			populate(s, n)
			_ = s.Root()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.Root()
			}
		})
	}
}

// BenchmarkRootOrdinaryBlock is a block that writes cells which already exist:
// no leaf changes position, so only the paths from the written leaves to the
// root are rehashed. The state size is constant across iterations.
func BenchmarkRootOrdinaryBlock(b *testing.B) {
	const writes = 200
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := New()
			populate(s, n)
			_ = s.Root()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < writes; j++ {
					s.Set(slotOf(int(mix(uint64(i)*1013+uint64(j))%uint64(n))),
						u256.FromUint64(uint64(i+j)+1))
				}
				_ = s.Root()
			}
		})
	}
}

// BenchmarkRootOneNewCell is one write to a slot that did not exist: the
// ordinary case of paying an address that has no cell yet.
//
// It is the same cost as a retirement, and that is the point. The dirty set has
// one element; the work is Θ(N), because the new leaf lands somewhere in the
// middle of a sorted array and every leaf after it moves one position. "Costs
// the dirty set" is true of the *hashing* and of nothing else.
func BenchmarkRootOneNewCell(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := New()
			populate(s, n)
			_ = s.Root()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Set(slotOf(n+i), u256.FromUint64(uint64(i)+1))
				_ = s.Root()
			}
		})
	}
}

// BenchmarkRootOneRetire is one RETIRE, and it is the number an operator needs.
//
// A single registry insertion costs the whole registry subtree. Priced from
// spec/params.json and types.Certificate.SeqGas, which charges a MarkSpent
// twice — it is a Write (gas_seq_per_write 200) *and* a registry insert
// (gas_seq_per_registry_insert 500) — so one RETIRE is 700 gas against a
// sequential ceiling of 2 × seq_gas_target_genesis = 3,200,000, i.e. 0.0219%
// of a block's budget (it read 4,000,000 and 0.0175% while the genesis
// sequential target was 2,000,000; the gas schedule itself did not move), and
// the cheapest certificate carrying one is 800 with its seen-set insert. At
// the min_base_fee floor of 1 drop/gas an attacker who includes one in every
// block pays ~800 drops per block and pins every node on the chain to this
// path forever. There is no version of the fast path they cannot deny, which
// is why the speedup that matters is the one measured here and not the one in
// BenchmarkRootOrdinaryBlock.
func BenchmarkRootOneRetire(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := New()
			populate(s, n)
			_ = s.Root()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.MarkSpent(addrOf(n + i))
				_ = s.Root()
			}
		})
	}
}

// BenchmarkRootRetirementBlock is the adversarial block the cache has to
// survive: 5,700 RETIREs, the number the sequential gas ceiling allows. Each
// one inserts a registry leaf at a position determined by its address and
// therefore shifts every leaf after it, so the registry subtree is rebuilt
// whole.
//
// The registry grows by 5,700 per iteration and is never pruned, so the
// reported ns/op is an average over a growing state rather than a figure at n
// — which is the point: this is the term that has no bound.
func BenchmarkRootRetirementBlock(b *testing.B) {
	const retirements = 5_700
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := New()
			populate(s, n)
			_ = s.Root()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				base := n + i*retirements
				for j := 0; j < retirements; j++ {
					s.MarkSpent(addrOf(base + j))
				}
				_ = s.Root()
			}
		})
	}
}

// BenchmarkRootCacheMemory measures what the cache costs in RAM, which is the
// other half of the trade the cache makes and which the first version of this
// file did not measure at all.
//
// The cache holds, per live entry: the key (a 64-byte types.Slot or a 32-byte
// types.Address), its 32-byte leaf hash, and the internal merkle nodes above
// it, which ssz.Tree keeps for nextPow2(count) leaf slots — so the per-entry
// figure is worst when the live count is just over a power of two and best when
// it is just under. That slack is why 100k (131,072/100,000 = 1.31×) costs more
// per entry than 1M (1,048,576/1,000,000 = 1.05×).
//
// The baseline is a state holding the two maps and nothing else — written
// straight into them, which is exactly the footprint main carries — rather
// than the same state mid-write. Measuring from mid-write was the first
// version's mistake and it understated the answer: `populate` leaves one
// dirty-set entry per live entry, so the baseline it read was already
// carrying two maps that do not exist on main, and the reported delta
// silently netted them out. Every figure here is therefore what the cache
// costs against a node without it, which is the number §14 quotes and the
// number an operator sizing a node needs.
//
// It matters because this node keeps the whole chain in RAM and nothing is
// pruned: this is added to a total that only grows.
func BenchmarkRootCacheMemory(b *testing.B) {
	for _, n := range []int{100_000, 1_000_000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				base := heapInUse()

				// main's footprint: the two maps, no dirty sets, no cache.
				bare := New()
				populateBare(bare, n)
				bareTotal := heapInUse()
				runtime.KeepAlive(bare)
				bare = nil
				_ = bare // dead by design: the reading below must not see it

				// This branch's footprint, in the steady state a node runs in.
				s := New()
				populate(s, n)
				_ = s.Root()
				full := heapInUse()
				runtime.KeepAlive(s)

				added := int64(full) - int64(bareTotal)
				b.ReportMetric(float64(added)/float64(2*n), "B/entry")
				b.ReportMetric(float64(added)/(1<<20), "MB-added")
				b.ReportMetric(float64(int64(bareTotal)-int64(base))/(1<<20), "MB-main")
				b.ReportMetric(float64(int64(full)-int64(base))/(1<<20), "MB-total")
				b.ReportMetric(0, "ns/op") // the timing here is meaningless
			}
		})
	}
}

// populateBare writes the maps directly, bypassing Set and MarkSpent, so that
// the resulting State holds exactly what main's State holds: no dirty sets, no
// leaf arrays, no trees.
func populateBare(s *State, n int) {
	for i := 0; i < n; i++ {
		s.cells[slotOf(i)] = u256.FromUint64(uint64(i) + 1)
		s.spent[addrOf(i)] = struct{}{}
	}
}

// heapInUse is a settled reading of the live heap: two collections, because one
// leaves the most recent allocations unswept and the figure being reported is a
// difference of two such readings.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}
