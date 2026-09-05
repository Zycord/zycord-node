package chaos_test

// The soak's port reservation.
//
// It exists because the soak's port block could overlap the host's dynamic port
// range, so a node's port could be handed to any outbound connection on the
// machine between the probe and the bind, and a swept seed then failed for a
// reason that had nothing to do with the node.
//
// A harness whose ports can be taken from under it mid-run produces failures
// that look exactly like the thing under test, and this project has spent days
// on that class of confusion. The reservation has two separate jobs, and these
// tests are named for the two properties rather than for freePortBlock:
//
//   - a block the kernel's own allocator cannot reach, at any instant; and
//   - a port that stays held from the check to the bind, rather than one that
//     was free when somebody looked.

import (
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The property: **where the kernel publishes its range, the published number
// wins over the documented one.**
//
// This is the half of the fix that matters on the VPS. Linux's usual range
// starts at 32768 — 16384 ports BELOW the IANA floor — so a soak that assumed
// the IANA number there would draw its whole block inside the range the kernel
// hands out, which is the stolen-port failure restored in full on the platform
// that is going to run it.
//
// Driven through a path parameter rather than through /proc, so that the
// parsing and the precedence are pinned on every platform rather than on one.
//
// **The real path and the real file are NOT unmeasurable, and saying they were
// is the error this comment exists to stop.** They are twenty seconds away in a
// container, and the first draft of this change declared the gap an
// impossibility instead — which is worse than an untested line, because the next
// reader believes it and never tries. Run:
//
//	docker run --rm -v "$PWD:/src" -w /src golang:1.25 \
//	  sh -c 'od -c /proc/sys/net/ipv4/ip_local_port_range; go test ./sim/chaos -run TestThePublishedPortRange -v'
//
// Measured that way: the file is byte-for-byte "32768\t60999\n" — the first row
// below is the real format, not a guess — the floor is read as 32768 rather than
// the fallback, and blocks are drawn in [20000,32517]. Add
// `--sysctl net.ipv4.ip_local_port_range="<lo> <hi>"` to drive the bands that
// blockRange bends and refuses.
func TestThePublishedPortRangeBeatsTheDocumentedOne(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		// The kernel writes the pair tab-separated.
		{"linux default", "32768\t60999\n", 32768},
		{"space separated", "32768 60999\n", 32768},
		{"tightened by an operator", "40000\t45000\n", 40000},
		// A range an operator widened all the way down is reported honestly;
		// freePortBlock is what refuses to draw under it, not this.
		{"widened to the bottom", "1024\t65535\n", 1024},
		// Anything unreadable falls back rather than inventing a number.
		{"empty", "", ianaDynamicPortFloor},
		{"not a number", "auto\tauto\n", ianaDynamicPortFloor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "range")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := dynamicPortFloorFrom(path); got != tc.want {
				t.Errorf("floor from %q = %d, want %d: the block would be drawn "+
					"against the wrong range", tc.body, got, tc.want)
			}
		})
	}

	// No file at all — every platform that is not Linux — is the fallback.
	if got := dynamicPortFloorFrom(filepath.Join(dir, "absent")); got != ianaDynamicPortFloor {
		t.Errorf("with no published range the floor is %d, want the IANA %d",
			got, ianaDynamicPortFloor)
	}

	// And the band the block is drawn from bends before it breaks. This is the
	// half a Fatal used to get wrong: a published range starting below
	// preferredBlockFloor+soakPortSpan is a *host setting*, and two of the three
	// rows below are settings a server operator is routinely told to apply.
	for _, tc := range []struct {
		name           string
		floor          int
		wantLo, wantHi int
		wantOK         bool
	}{
		// Room above the preferred floor: nothing changes.
		{"windows default", 49152, preferredBlockFloor, 49152 - soakPortSpan, true},
		{"linux default", 32768, preferredBlockFloor, 32768 - soakPortSpan, true},
		{"tightened", 40000, preferredBlockFloor, 40000 - soakPortSpan, true},
		// No room above it, but room above the minimum: degrade, do not refuse.
		{"widened to 15000", 15000, minimumBlockFloor, 15000 - soakPortSpan, true},
		{"exactly at the preferred floor plus a span", preferredBlockFloor + soakPortSpan,
			preferredBlockFloor, preferredBlockFloor, true},
		// No room at all: refuse, and freePortBlock turns that into a SKIP.
		{"widened to the bottom", 1024, 0, 0, false},
		{"widened below the bottom", 512, 0, 0, false},
	} {
		lo, hi, ok := blockRange(tc.floor)
		if ok != tc.wantOK || (ok && (lo != tc.wantLo || hi != tc.wantHi)) {
			t.Errorf("%s: blockRange(%d) = (%d,%d,%v), want (%d,%d,%v)",
				tc.name, tc.floor, lo, hi, ok, tc.wantLo, tc.wantHi, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		// Whatever band it chose, the block still ends below the floor and
		// still starts above the privileged ports.
		if hi+soakPortSpan-1 >= tc.floor {
			t.Errorf("%s: a base at %d puts the block's last port at %d, at or above "+
				"the floor %d", tc.name, hi, hi+soakPortSpan-1, tc.floor)
		}
		if lo < minimumBlockFloor {
			t.Errorf("%s: band starts at %d, below the %d a bind stops needing "+
				"privilege at", tc.name, lo, minimumBlockFloor)
		}
	}
}

// The property: **no block the selection can draw contains a port the kernel
// may assign on its own.**
//
// This is the arithmetic half of the fix, and it is the half that holds for a
// node the chaos loop kills and restarts minutes later — by then no listener is
// held and the only thing standing between the node's port and the machine's
// next outbound connection is where the block was drawn.
func TestNoPortBlockTheSoakCanDrawReachesTheRangeTheKernelAssigns(t *testing.T) {
	const draws = 200000
	rng := rand.New(rand.NewSource(1))
	floor := dynamicPortFloor()
	bandLo, _, ok := blockRange(floor)
	if !ok {
		t.Skipf("this host publishes a dynamic range starting at %d, which leaves the "+
			"soak no band to draw from; the selection rule is unexercised here and "+
			"blockRange's own table above is what covers it", floor)
	}

	seen := map[int]bool{}
	highest := 0
	for i := 0; i < draws; i++ {
		base, ok := pickPortBase(rng, floor)
		if !ok {
			t.Fatalf("pickPortBase refused a floor of %d that blockRange accepted", floor)
		}
		if base < bandLo {
			t.Fatalf("drew base %d, below the %d the band starts at", base, bandLo)
		}
		top := base + soakPortSpan - 1
		if top >= floor {
			t.Fatalf("drew base %d, whose block reaches %d and so overlaps the dynamic "+
				"range starting at %d: a node's port can be handed to any outbound "+
				"connection on this machine between the probe and the bind",
				base, top, floor)
		}
		seen[base] = true
		if top > highest {
			highest = top
		}
	}

	// Anti-vacuity, both halves. A rule that returned one constant would pass
	// the loop above, and so would a rule that never came near the ceiling —
	// the interesting draws are the ones just under it, which are precisely the
	// ones the old rule got wrong.
	if len(seen) < 1000 {
		t.Fatalf("%d draws produced only %d distinct bases: the loop above is not "+
			"exercising the selection", draws, len(seen))
	}
	if gap := floor - 1 - highest; gap > 4*soakPortSpan {
		t.Fatalf("the highest block over %d draws ends at %d, %d ports short of the "+
			"floor at %d: this test never sampled the edge it exists to pin",
			draws, highest, gap, floor)
	}
}

// The property: **a reserved port is unavailable to anyone else until the
// harness hands it over.**
//
// This is what separates a reservation from a probe. The old code bound the
// block, closed it, and then spent the whole of setup — key generation, proxy
// construction, manifest, process launch — with nothing but a random number
// generator's word that the ports were still there.
func TestAReservedPortStaysHeldUntilTheHarnessHandsItOver(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	block := freePortBlock(t, rng)
	t.Cleanup(block.releaseAll)

	for _, offset := range soakPortOffsets {
		port := block.base + offset
		if l, err := net.Listen("tcp", addr(port)); err == nil {
			l.Close()
			t.Fatalf("port %d (offset %d) bound while the block still holds it: the "+
				"reservation is a probe again, and the steal window is open",
				port, offset)
		}
	}

	// And handing one over really hands it over — otherwise the node that needs
	// it could not start, which would be this fix trading one broken run for
	// another.
	port := block.base + soakPortOffsets[0]
	block.release(port)
	l, err := net.Listen("tcp", addr(port))
	if err != nil {
		t.Fatalf("port %d did not become bindable after release: %v", port, err)
	}
	l.Close()

	// Releasing a port that was never held, and one already released, are both
	// no-ops: callers pass a node's zero-valued p2pPort without a special case.
	block.release(port)
	block.release(0)
}

// The property: **every port a soak regime binds is one the block reserved.**
//
// The catch-up regime derived its joiner's RPC port as `nodes[0].rpcPort + 50`,
// fifty past the end of a block probed with a span of 210 — so that one port
// was never checked free and never kept below the dynamic range. Naming the
// offsets is what makes the two sets comparable at all.
//
// What this cannot see: a port derived somewhere else from a fresh literal. It
// compares the named offsets against the span and against each other; a new
// `+ 50` written against a node's port in another file would be invisible to
// it, exactly as the old one was invisible to the probe.
func TestEveryNamedSoakPortOffsetIsInsideTheReservedBlock(t *testing.T) {
	reserved := map[int]bool{}
	for _, offset := range soakPortOffsets {
		if offset < 0 || offset >= soakPortSpan {
			t.Fatalf("offset %d lies outside the block's own span of %d", offset, soakPortSpan)
		}
		reserved[offset] = true
	}

	// The offsets the network's named constants actually produce.
	for _, want := range []struct {
		offset int
		what   string
	}{
		{soakP2PBase, "a's p2p port"},
		{soakP2PBase + 1, "b's p2p port"},
		{soakP2PBase + 2, "c's p2p port"},
		{soakProxyBase, "a's chaos proxy"},
		{soakProxyBase + 1, "b's chaos proxy"},
		{soakProxyBase + 2, "c's chaos proxy"},
		{soakRPCBase, "a's rpc port"},
		{soakRPCBase + 1, "b's rpc port"},
		{soakRPCBase + 2, "c's rpc port"},
		{soakRPCBase + 3, "d's rpc port"},
		{soakLateJoinerRPC, "the late joiner's rpc port"},
	} {
		if !reserved[want.offset] {
			t.Errorf("%s is at offset %d, which the block does not reserve: nothing "+
				"probed it free and nothing keeps it below the dynamic range",
				want.what, want.offset)
		}
	}

	// The span is exactly what the offsets need — no more, so the block does not
	// squat on ports nothing binds, and no less, which is the failure above.
	highest := 0
	for _, offset := range soakPortOffsets {
		if offset > highest {
			highest = offset
		}
	}
	if soakPortSpan != highest+1 {
		t.Errorf("span is %d for a highest offset of %d: the block and the ports it "+
			"claims to cover are two different runs", soakPortSpan, highest)
	}
}

// The property: **the floor the selection trusts is at or below every port the
// kernel hands out here.**
//
// The whole fix rests on this one number, and it is the number most likely to
// be wrong on a machine nobody measured: Linux publishes a range that starts
// well below the IANA floor, and either platform's can be reconfigured. A
// sample cannot prove the floor and this test does not claim to — it refutes a
// wrong one, which is the direction that matters, and it is the same assertion
// the soak itself makes before it draws.
func TestTheDynamicPortFloorIsNotAboveWhatThisKernelAssigns(t *testing.T) {
	floor := dynamicPortFloor()
	// Fails loudly through the same guard the harness uses, so a machine that
	// would break the soak breaks this test first and says so. This runs
	// whatever the band works out to: the guard is about the FLOOR being right,
	// which matters even on a host where no band fits.
	assertTheKernelAssignsAboveTheFloor(t, floor)
	lo, hi, ok := blockRange(floor)
	if !ok {
		t.Skipf("dynamic port floor here: %d — no band of %d ports fits above %d, so "+
			"the soak would SKIP on this host rather than race", floor, soakPortSpan,
			minimumBlockFloor)
	}
	t.Logf("dynamic port floor here: %d; blocks are drawn in [%d,%d]", floor, lo, hi)
}
