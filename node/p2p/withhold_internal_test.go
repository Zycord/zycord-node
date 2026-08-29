package p2p

import (
	"reflect"
	"strings"
	"testing"

	"zycord/core/types"
)

// TestAWithheldEntryHoldsNoDecodedBlock is the structural half of the byte
// bound's property, and it exists because the behavioural half can decline to measure.
//
// TestTheWithholdQueueCountsEverythingItRetains compares the queue's byte
// accounting against the heap it really retains, which is the property proper —
// but a heap measurement can fail to observe anything (it skips when the heap
// does not shrink), and a skip is not a pass. This one cannot skip: it reads
// the type. Between them, the behavioural test says the bound is honest and
// this one says it stays honest for the reason it was made honest.
//
// The rule, in one sentence: a queue entry retains the block in exactly one
// form, the delivered bytes, so `withheldBytes` — which counts those bytes — is
// the whole of what the entry holds. wire.md §9 rule 8 makes that bound the
// entire memory argument for this queue, and it can only be exact if there is
// nothing beside the thing counted.
//
// Deliberately a check on *shape* rather than a check on `blk` by name. The
// regression is not "somebody re-adds a field called blk"; it is "somebody
// retains a second representation of the block", and a decoded block reached by
// any other name or through any other type is the same defect. So this walks
// the fields and refuses any reference into the block types, whatever it is
// called.
func TestAWithheldEntryHoldsNoDecodedBlock(t *testing.T) {
	// The types that would constitute retaining the block a second time. The
	// bytes are `[]byte` and the id is `types.Hash`, so neither is caught here.
	decoded := map[reflect.Type]bool{
		reflect.TypeOf(types.Block{}):       true,
		reflect.TypeOf(types.Header{}):      true,
		reflect.TypeOf(types.Certificate{}): true,
	}

	e := reflect.TypeOf(withheldBlock{})
	var offenders []string
	for i := 0; i < e.NumField(); i++ {
		f := e.Field(i)
		ft := f.Type
		// Through pointers and slices alike: `*types.Block`, `[]*types.Header`
		// and `[]types.Certificate` are all the same mistake.
		for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if decoded[ft] {
			offenders = append(offenders, f.Name+" "+f.Type.String())
		}
	}
	if len(offenders) != 0 {
		t.Fatalf("withheldBlock retains a decoded form of the block in %s, "+
			"beside the raw bytes it already holds. `withheldBytes` counts the "+
			"bytes only, so MaxBytes would once again bound one of two things "+
			"held and understate the queue's real footprint, "+
			"and which wire.md §9 rule 8 makes the whole memory argument for "+
			"this queue. If a released block genuinely needs its structure, "+
			"decode it on release through Released.Decode: the block has by "+
			"then waited up to FUTURE_TIME_LIMIT_SECONDS and the release runs "+
			"from a ticker, so it is on no latency path",
			strings.Join(offenders, ", "))
	}

	// And the check is not vacuous: it must actually be looking at fields, and
	// at the byte slice the entry is supposed to hold. A withheldBlock that had
	// been refactored to hold nothing at all would pass the loop above in
	// silence.
	if _, ok := e.FieldByName("raw"); !ok {
		t.Fatal("withheldBlock no longer holds `raw`: the loop above is " +
			"checking a type that has stopped being the thing under test")
	}
}

// TestAWithheldEntryAllocatesExactlyWhatItAccounts is the same property one
// level below the test above.
//
// TestAWithheldEntryHoldsNoDecodedBlock says the entry retains one
// representation of the block. This says the accounting of that representation
// is the allocation rather than a floor under it. `withhold` adds
// `len(entry.raw)` to `withheldBytes`, so a `raw` whose capacity exceeds its
// length is retained memory the bound cannot see — the same shape of error as
// the decoded block, on a smaller scale and by a different mechanism.
//
// It is neither hypothetical nor constant. `append([]byte(nil), raw...)` sizes
// through Go's allocator size classes, so the excess is a function of the
// body's length, and the body's length is the sender's to choose. Swept across
// every size class up to `block_byte_capacity` (8,000,000) on go1.26 arm64, the
// worst point a block body can reach is **25.00 % at 32,769 bytes**; 65,537
// bytes gives 12.50 %, the 2,500,000-byte genesis ceiling 0.27 %, and 8,000,000
// bytes 0.04 %. The bad end is not an exotic size: it is an ordinary small
// block, a little larger than the 31,676-byte devnet block this issue was
// measured on. A bound whose slack the sender selects is the defect.
//
// Driven through the real admission path rather than a copy helper, because the
// property belongs to what the queue stores, and asserted on capacity rather
// than on a byte count so it survives any change of block size here.
//
// Two sizes rather than one, because the anti-vacuity guard below can skip. If
// a future toolchain gained a size class at exactly one of them, `append` would
// be exact there and the test would decline; the second size keeps the property
// pinned rather than silently unguarded, and the guard fires only if `append`
// is exact at *both*.
func TestAWithheldEntryAllocatesExactlyWhatItAccounts(t *testing.T) {
	// The worst reachable point (32,769 = one past the 32 KiB class, 25.00 %)
	// and the runner-up at the 64 KiB boundary (12.50 %).
	sizes := []int{32769, 65537}

	// The premise: the mistake being guarded against must be a mistake on this
	// toolchain at at least one of these sizes. If `append` allocated exactly
	// at both, this test would pass for a reason unrelated to the code under
	// test, so it declines to measure instead of reporting a pass.
	inexact := false
	for _, n := range sizes {
		if cap(append([]byte(nil), make([]byte, n)...)) != n {
			inexact = true
		}
	}
	if !inexact {
		t.Skipf("append allocates exactly at every size in %v on this "+
			"toolchain, so this test cannot tell the two copies apart", sizes)
	}

	for _, n := range sizes {
		e := testEngine(t)
		p := e.Chain.Params()

		blk := &types.Block{}
		blk.Header.Time = e.now() + p.FutureTimeLimitSeconds + 60
		if err := e.withhold("flooder:1", blk, make([]byte, n)); err != nil {
			t.Fatalf("the %d-byte body was not queued, so nothing was "+
				"measured: %v", n, err)
		}

		entry := e.withheld[blk.Header.ID()]
		if entry == nil {
			t.Fatalf("withhold reported success for the %d-byte body but "+
				"stored nothing", n)
		}
		if len(entry.raw) != n {
			t.Fatalf("the queue stored %d bytes of a %d-byte body",
				len(entry.raw), n)
		}
		if cap(entry.raw) != len(entry.raw) {
			t.Fatalf("a withheld entry retains %d bytes of capacity for a "+
				"%d-byte body while `withheldBytes` counts %d: MaxBytes bounds "+
				"less than the queue allocates, and the slack is a function of "+
				"the body length, which the sender chooses. Copy the "+
				"body with make+copy rather than append",
				cap(entry.raw), len(entry.raw), len(entry.raw))
		}
		if got := e.WithheldBytes(); got != n {
			t.Fatalf("the queue accounts %d bytes for a %d-byte body", got, n)
		}
	}
}
