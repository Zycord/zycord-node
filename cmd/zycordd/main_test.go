package main

import (
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/token"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/spec"
)

// hexAddr builds the hex encoding of an address of the given version, over an
// arbitrary payload. parsePayout only inspects the decoded bytes' length and
// version byte, so this needs no real key material — cmd/zycordd never
// holds any (see the package doc comment).
func hexAddr(t *testing.T, version byte) string {
	t.Helper()
	a := crypto.DeriveAddress(version, []byte("parsePayout-test-payload"))
	return hex.EncodeToString(a[:])
}

// TestParsePayoutRequiresPersistent is the burned-coinbase property: a mining
// payout is paid every block, plus whatever is already sitting in the maturity
// ring, so it must be a persistent (0x02) address — not merely a user (0x01 or
// 0x02) one. Before this fix, a one-shot payout address parsed successfully
// and mined for however long until the operator spent from it once, at which
// point every subsequent reward (and the ~100 blocks already maturing) was
// silently burned, with no error anywhere.
func TestParsePayoutRequiresPersistent(t *testing.T) {
	t.Run("persistent address is accepted", func(t *testing.T) {
		want := crypto.DeriveAddress(crypto.AddrVersionPersistent, []byte("parsePayout-test-payload"))
		addr, err := parsePayout(hexAddr(t, crypto.AddrVersionPersistent))
		if err != nil {
			t.Fatalf("a persistent address should be accepted: %v", err)
		}
		if addr != want {
			t.Fatalf("got %x, want %x", addr, want)
		}
	})

	t.Run("one-shot address is refused", func(t *testing.T) {
		_, err := parsePayout(hexAddr(t, crypto.AddrVersionOneShot))
		if err == nil {
			t.Fatal("a one-shot (0x01) payout address must be refused: it burns every future " +
				"reward, including everything already maturing, the moment it is spent once")
		}
		if !strings.Contains(err.Error(), "persistent") {
			t.Fatalf("error should explain the persistent-address requirement, got: %v", err)
		}
	})

	t.Run("protocol address is refused", func(t *testing.T) {
		if _, err := parsePayout(hexAddr(t, crypto.AddrVersionProtocol)); err == nil {
			t.Fatal("a protocol (0x00) address must be refused")
		}
	})

	t.Run("asset address is refused", func(t *testing.T) {
		if _, err := parsePayout(hexAddr(t, crypto.AddrVersionAsset)); err == nil {
			t.Fatal("an asset (0x03) address must be refused")
		}
	})
}

// TestParsePayoutStillValidatesShape pins the checks the version-byte rule
// does not touch, so the version-byte fix above cannot be read as having
// replaced them.
func TestParsePayoutStillValidatesShape(t *testing.T) {
	t.Run("empty is required", func(t *testing.T) {
		if _, err := parsePayout(""); err == nil {
			t.Fatal("an empty --payout must be refused")
		}
	})

	t.Run("wrong length is refused", func(t *testing.T) {
		short := hex.EncodeToString([]byte{crypto.AddrVersionPersistent, 1, 2, 3})
		if _, err := parsePayout(short); err == nil {
			t.Fatal("a payout address shorter than 32 bytes must be refused")
		}
	})

	t.Run("non-hex input is refused", func(t *testing.T) {
		if _, err := parsePayout("not-hex-at-all-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
			t.Fatal("non-hex --payout must be refused")
		}
	})

	// The odd-length hole, fixed here: the hand-rolled decoder this function used
	// to call sized its output at len(s)/2 with no even-length check, so 65
	// characters yielded 32 bytes with the 65th silently discarded — and the
	// len(raw) != 32 test could not see it. cmd/zcd's parseAddress, already on
	// encoding/hex, refused the same string. One tree, two answers to "is this an
	// address"; now one.
	t.Run("odd-length input is refused", func(t *testing.T) {
		valid := hexAddr(t, crypto.AddrVersionPersistent)
		for _, s := range []string{
			valid + "a",          // 65 chars: a trailing nibble the old decoder dropped
			"a" + valid,          // 65 chars: a leading nibble, shifting every byte
			valid[:len(valid)-1], // 63 chars: one nibble short
		} {
			if _, err := parsePayout(s); err == nil {
				t.Fatalf("an odd-length --payout must be refused, accepted %q", s)
			}
		}
	})

	// The old decoder trimmed "0x" itself; encoding/hex does not, so the trim
	// is now this function's own and both cases stay pinned.
	t.Run("0X prefix is accepted", func(t *testing.T) {
		if _, err := parsePayout("0X" + hexAddr(t, crypto.AddrVersionPersistent)); err != nil {
			t.Fatalf("an 0X-prefixed persistent address should be accepted: %v", err)
		}
	})

	t.Run("uppercase hex is accepted", func(t *testing.T) {
		if _, err := parsePayout(strings.ToUpper(hexAddr(t, crypto.AddrVersionPersistent))); err != nil {
			t.Fatalf("uppercase hex should be accepted: %v", err)
		}
	})

	t.Run("0x prefix is accepted", func(t *testing.T) {
		if _, err := parsePayout("0x" + hexAddr(t, crypto.AddrVersionPersistent)); err != nil {
			t.Fatalf("a 0x-prefixed persistent address should be accepted: %v", err)
		}
	})
}

// TestPrefetchWarmsTheNextKeyWithinOneLagOfTheBoundary is the second half of
// the prefetch-lead defect.
//
// prefetchLoop asked for `height + randomx_key_interval` and its comment said
// "one interval ahead". SeedEpochFor shifts the boundary forward by the lag, so
// that expression crosses into the next epoch at height LAG — 64 blocks in,
// on mainnet and on the public testnet both — and every tick from there warmed
// a key nothing would need for another full interval. It is what fired the
// engine defect one minute into a node's life and an epoch before anyone would
// have thought to look.
//
// The property, over every network that runs a keyed engine: the key warmed is
// this epoch's or the next one's and never further, and it is the next one over
// exactly the last `lag` blocks before the boundary. Both halves are needed.
// "Never further" alone is satisfied by warming nothing at all, and "warms the
// next one" alone is satisfied by the expression this replaces.
//
// And a third, which is not about the schedule at all: that window has to hold
// prefetchTicks asks, or the loop can step over it and the boundary is crossed
// with nothing warmed. It is asserted here against prefetchPeriodFor rather
// than against a constant, because the two quantities are in different units —
// the lag counts blocks and a ticker counts seconds — and the network is what
// converts between them.
//
// The parameter sets are swept rather than listed. Three shipped networks are
// three points, and a property that holds at three points and nowhere else is
// the shape of defect this file already carries one of.
func TestPrefetchWarmsTheNextKeyWithinOneLagOfTheBoundary(t *testing.T) {
	// The public testnet is the set the defect was found on: 512/64 is the pair
	// that made the old expression warm 512 blocks early instead of mainnet's
	// 2048. Its schedule used to be reproduced here by hand because the file was
	// not embedded; it is now the shipped set itself, so the property is asserted
	// over the parameters the network will actually run.

	// The set this project reproduces key rotation on: devnet's schedule with a
	// real work function, which is what the end-to-end RandomX bring-up run used
	// and where the 8-block window is 40 s against a 60 s period.
	fast := *spec.Devnet()
	fast.Name = "devnet schedule, RandomX engine"
	fast.PoWEngine = "randomx-v1"

	nets := []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"testnet", spec.Testnet()},
		{"devnet", spec.Devnet()},
		{"devnet-schedule-randomx", &fast},
	}
	// And a sweep, so the property is a property of the arithmetic rather than
	// of the four sets above. Every combination Validate accepts is fair game
	// for an operator with a --params file.
	for _, interval := range []uint64{2, 3, 8, 16, 64, 512, 2048, 100000} {
		for _, lag := range []uint64{1, 2, 8, 64, interval / 2, interval - 1} {
			if lag == 0 || lag >= interval {
				continue
			}
			for _, secs := range []uint64{1, 2, 5, 15, 30, 600} {
				q := *spec.Devnet()
				q.RandomXKeyInterval, q.RandomXKeyLag, q.TargetBlockSeconds = interval, lag, secs
				if err := q.Validate(); err != nil {
					continue // not a network anyone can start
				}
				c := q
				nets = append(nets, struct {
					name string
					p    *params.Params
				}{fmt.Sprintf("swept-i%d-l%d-t%ds", interval, lag, secs), &c})
			}
		}
	}
	if len(nets) < 50 {
		t.Fatalf("the sweep produced %d parameter sets; it is meant to be the "+
			"bulk of this test and something has stopped Validate accepting them",
			len(nets))
	}

	for _, net := range nets {
		t.Run(net.name, func(t *testing.T) {
			p := net.p
			lead := prefetchHeight(0, p)
			if lead != p.RandomXKeyLag {
				t.Fatalf("the lead is %d blocks, the schedule's own slack is %d",
					lead, p.RandomXKeyLag)
			}
			// The window, against the rate at which anybody asks inside it.
			// This is the half that fails if prefetchPeriodFor stops adapting.
			//
			// It is also the rate-margin statement, which is the same
			// inequality read the other way: the window is computed at the
			// chain's TARGET block time and lived at its actual one, and a
			// period no greater than window/prefetchTicks is exactly the
			// condition for one ask to still land while the chain runs up to
			// prefetchTicks times faster than target.
			if prefetchWindowSeconds(p) == 0 {
				t.Fatalf("the warm window is empty, so prefetchPeriodFor takes a "+
					"branch that assumes Validate rejected these parameters — and "+
					"it did not: lag %d, target %d s",
					p.RandomXKeyLag, p.TargetBlockSeconds)
			}
			window := time.Duration(prefetchWindowSeconds(p)) * time.Second
			if got := prefetchTicks * prefetchPeriodFor(p); got > window {
				t.Fatalf("the next epoch's key is warmed over %d blocks = %s, and "+
					"prefetchLoop asks every %s: %d asks need %s, so a boundary "+
					"can be crossed with nothing warmed at all",
					lead, window, prefetchPeriodFor(p), prefetchTicks, got)
			}
			if got := prefetchPeriodFor(p); got > prefetchPeriod {
				t.Fatalf("asks every %s, which is slower than the %s ceiling",
					got, prefetchPeriod)
			}

			// The walk ends at 4*interval - 1, and the number is chosen rather
			// than round. It is the last height before the FOURTH early-warm
			// window opens, for every lag Validate accepts: the window for
			// epoch e is [e*interval, e*interval+lag-1], and lag < interval
			// puts the third entirely inside the range and the fourth entirely
			// outside it. So the count below is exactly three windows, on every
			// parameter set, rather than on the ones somebody happened to list.
			//
			// It was `3*interval + lag + 2` until the sweep arrived, which is
			// three boundaries plus a tail — and at interval 100000, lag 99999
			// the tail reached two heights into the fourth window and the
			// anti-vacuity count was two over. A count that has to be right is
			// a poor place for an approximate range.
			last := 4*p.RandomXKeyInterval - 1
			var warmedEarly int
			for h := uint64(0); h <= last; h++ {
				here := pow.SeedEpochFor(h, p)
				// The epoch of the next block, which is the soonest thing this
				// node can be asked to hash.
				soon := pow.SeedEpochFor(h+1, p)
				warmed := pow.SeedEpochFor(prefetchHeight(h, p), p)

				if warmed < here || warmed > here+1 {
					t.Fatalf("height %d (epoch %d): warms epoch %d; a prefetch may "+
						"reach one epoch ahead and no further", h, here, warmed)
				}
				// Where the next block is already in a new epoch, the key for
				// it must have been asked for by now — that is the whole job.
				if soon != here && warmed != soon {
					t.Fatalf("height %d: the next block needs epoch %d and the "+
						"prefetch is still warming %d", h, soon, warmed)
				}
				if warmed != here {
					warmedEarly++
					// The distance to the boundary this warm is for.
					boundary := warmed*p.RandomXKeyInterval + p.RandomXKeyLag
					if h+lead < boundary {
						t.Fatalf("height %d warms epoch %d, whose first height is "+
							"%d: more than the %d-block lead early",
							h, warmed, boundary, lead)
					}
				}
			}
			// Anti-vacuity: the walk must actually cross boundaries, and the
			// warm must actually happen. One lead per epoch crossed.
			if want := int(3 * lead); warmedEarly != want {
				t.Fatalf("warmed the next epoch's key at %d heights over three "+
					"boundaries, want %d — one lead before each", warmedEarly, want)
			}
		})
	}
}

// TestTheOldPrefetchExpressionWouldFail records what the fix is against, so
// that a future simplification back to "one interval ahead" fails here with the
// reason rather than looking like a tidy-up.
func TestTheOldPrefetchExpressionWouldFail(t *testing.T) {
	p := spec.Mainnet()
	// The height at which `height + interval` first crosses into epoch 1.
	h := p.RandomXKeyLag
	if got := pow.SeedEpochFor(h+p.RandomXKeyInterval, p); got == pow.SeedEpochFor(h, p) {
		t.Fatalf("the expression this test exists to reject no longer crosses the "+
			"boundary at height %d; the schedule must have changed", h)
	}
	if got := pow.SeedEpochFor(prefetchHeight(h, p), p); got != pow.SeedEpochFor(h, p) {
		t.Fatalf("at height %d, a full interval (%d blocks) below the first "+
			"boundary, the prefetch already warms epoch %d",
			h, p.RandomXKeyInterval, got)
	}
}

// TestOneSignalStopsEveryLoop.
//
// `zycordd` had five goroutines selecting on the SAME `chan os.Signal`: main,
// the mine loop, the abandon predicate inside it, the prefetch loop and the
// heartbeat. signal.Notify delivers a signal ONCE, to whichever receiver is
// ready — a channel is a queue, not a broadcast — so a SIGTERM woke one of the
// five and the other four went on as if nothing had happened. Whether the
// process shut down at all was a lottery over which goroutine won.
//
// Measured before the fix, on darwin/arm64: five runs of
// `zycordd --devnet --mine`, SIGTERM at six seconds, fifteen seconds to exit.
// **One exited. Four kept producing blocks and had to be killed.** After it,
// eight runs out of eight exited, each logging "shutting down" exactly once.
//
// The number of waiters here is the number of places in main that take the
// channel, and it matters: with one waiter the old code passes. It went from
// five to six when the mine loop gained its pre-genesis wait — a node that
// refuses to mine until its clock reaches the next block's earliest timestamp
// sleeps on a select, and a SIGTERM during a four-hour wait has to reach it.
func TestOneSignalStopsEveryLoop(t *testing.T) {
	sig := make(chan os.Signal, 1)
	stop := stopOnSignal(sig)

	const waiters = 6
	var wg sync.WaitGroup
	woke := make(chan int, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case <-stop:
				woke <- i
			case <-time.After(10 * time.Second):
			}
		}(i)
	}

	sig <- syscall.SIGTERM // exactly one signal, as the operating system sends

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
	if n := len(woke); n != waiters {
		t.Fatalf("one signal woke %d of %d waiters: a node whose loops share a "+
			"signal channel keeps running after SIGTERM, and which loop stops is "+
			"decided by whoever reaches the receive first", n, waiters)
	}

	// And it stays down. A closed channel is what makes the shutdown visible to
	// a goroutine that only looks later — the abandon predicate polls it once
	// per 512 nonces — where a consumed value would have been gone.
	for i := 0; i < 3; i++ {
		select {
		case <-stop:
		case <-time.After(time.Second):
			t.Fatal("the stop signal was consumed by reading it; a goroutine that " +
				"checks after another has already checked would never see it")
		}
	}
}

// TestBootstrapListMergesRatherThanOverrides covers the shape an operator
// actually wants: take the shipped list and add one of their own, without
// transcribing the file onto a command line.
func TestBootstrapListMergesRatherThanOverrides(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/peers.txt"
	body := "" +
		"# the public testnet seeds\n" +
		"seed-a.example:9421\n" +
		"\n" +
		"   seed-b.example:9421   # trailing comment\n" +
		"# a commented-out entry\n" +
		"#seed-c.example:9421\n" +
		"seed-a.example:9421\n" // a duplicate of the first
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := bootstrapList("mine.example:9421, seed-b.example:9421", path, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mine.example:9421", "seed-b.example:9421", "seed-a.example:9421"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestBootstrapFileMissingIsRefused. A file an operator named and this node
// silently ignored would produce a node with no peers and no explanation,
// which is indistinguishable from a network with nobody on it.
func TestBootstrapFileMissingIsRefused(t *testing.T) {
	if _, err := bootstrapList("", t.TempDir()+"/absent.txt", nil); err == nil {
		t.Fatal("a missing --peers-file was accepted")
	}
}

// TestBootstrapFileWrittenOnWindowsIsDiallable pins the property the fixture
// above cannot reach: every address bootstrapList returns is one net.Dial can
// use. The file here is written the way PowerShell's `Set-Content -Encoding
// utf8` writes one — a leading UTF-8 byte order mark and CRLF line endings —
// which is the file docs/TESTNET.md's `--peers-file peers.txt` becomes on the
// platform this repo's CI has a job for.
// TestBootstrapListMergesRatherThanOverrides uses "\n" and no mark, which is
// exactly why nothing caught this.
//
// The assertion goes through net.SplitHostPort and strconv rather than
// comparing strings, because comparing strings is what a reader would write
// and it is the weaker check: "seed-a.example:9421\r" prints indistinguishably
// from a good address in a %v, so the diff would read as a passing test's
// output, and a leading byte order mark is invisible outright. What broke is
// the resolver being handed a port of "9421\r" — `lookup tcp/9421: unknown
// port`, for the life of the node — so the port is what this parses.
func TestBootstrapFileWrittenOnWindowsIsDiallable(t *testing.T) {
	// Both places the mark can land. It was measured on a COMMENT line, where
	// cutting the comment away leaves the mark alone as an entry of its own; a
	// file whose first line is an address instead carries it into the address. A
	// strip that handled only one of the two would still hand node/p2p a dial
	// target nothing answers on.
	for _, c := range []struct{ name, body string }{
		{"mark on a comment line", "\xef\xbb\xbf" +
			"# the public testnet seeds\r\nseed-a.example:9421\r\n127.0.0.1:9421\r\n"},
		{"mark on an address line", "\xef\xbb\xbf" +
			"seed-a.example:9421\r\n# the public testnet seeds\r\n127.0.0.1:9421\r\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := t.TempDir() + "/peers.txt"
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := bootstrapList("", path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 {
				t.Fatalf("a file naming two addresses produced %d entries (%q): an entry "+
					"this file never named is an outbound connection node/p2p budgets for "+
					"nothing", len(got), got)
			}
			for _, addr := range got {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					t.Errorf("bootstrap address %q does not split into host and port (%v): "+
						"a byte order mark left on a line of its own is not an address, and "+
						"node/p2p still spends a dial slot on it", addr, err)
					continue
				}
				if strings.Contains(host, "\xef\xbb\xbf") {
					t.Errorf("bootstrap host %q carries a byte order mark: it resolves to "+
						"nothing, and the operator cannot see the difference in the file "+
						"they wrote", host)
				}
				if _, err := strconv.ParseUint(port, 10, 16); err != nil {
					t.Errorf("bootstrap address %q has port %q, which is not a number: the "+
						"CR of a CRLF file rides on the port, so every dial to this address "+
						"fails at `lookup tcp/%s: unknown port` and the node never reaches "+
						"the seed it was handed", addr, port, port)
				}
			}
		})
	}
}

// TestBootstrapDedupSurvivesCRLF. Dropping duplicates is a stated purpose of
// bootstrapList — node/p2p budgets outbound connections by count, so the same
// address twice costs a slot no second peer is reachable through — and a CR
// defeats it silently: "127.0.0.1:9421\r" from the file is not string-equal to
// "127.0.0.1:9421" from the command line, so both were measured surviving the
// dedup. The dedup has to hold ACROSS the two sources, not merely within the
// file, because merging the two is the reason the flag exists.
func TestBootstrapDedupSurvivesCRLF(t *testing.T) {
	path := t.TempDir() + "/peers.txt"
	body := "\xef\xbb\xbf127.0.0.1:9421\r\nseed-a.example:9421\r\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := bootstrapList("127.0.0.1:9421", path, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:9421", "seed-a.example:9421"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q: the command line and the file name 127.0.0.1:9421 "+
			"between them once, and a copy differing only by an invisible CR is not a "+
			"second peer — it is a dial slot spent on an address nothing answers on",
			got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// TestBootstrapFileWithNoAddressesIsRefused. A file that is named, readable and
// names nothing reaches the end state docs/RUNNING.md refuses an unreadable
// file to prevent: the operator asked for seeds and got none. The two are the
// same mistake, and the empty one is the likelier of the pair — an interrupted
// download, or a `Set-Content` handed an empty variable, leaves a zero-byte
// file rather than an absent one.
//
// --peers is supplied deliberately, so the property is "the file did its job",
// not "the merged list came out empty". A node started from a seed file that
// supplied nothing is running on a bootstrap list its operator did not think
// they gave it, and nothing on the way up says so.
func TestBootstrapFileWithNoAddressesIsRefused(t *testing.T) {
	dir := t.TempDir()
	for i, c := range []struct{ name, body string }{
		{"zero bytes", ""},
		{"nothing but comments", "\xef\xbb\xbf# the public testnet seeds\r\n\r\n" +
			"#seed-a.example:9421\r\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := fmt.Sprintf("%s/peers%d.txt", dir, i)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := bootstrapList("127.0.0.1:9421", path, nil); err == nil {
				t.Error("a --peers-file naming no address was accepted: the node comes up " +
					"on a bootstrap list its operator did not think they gave it, and a " +
					"node with no reachable seed looks exactly like a network with nobody " +
					"on it")
			}
		})
	}
}

// TestPeersFlagCarryingLineEndingsSplitsIntoDiallableAddresses pins the half
// of the stray-line-ending defect that lives on the command line rather than
// in the file. PowerShell's `--peers (Get-Content -Raw peers.txt)` hands the
// whole file over as ONE argument, line endings and all, and a script that
// writes the value across two lines inside one pair of quotes produces the
// same string. Splitting on ',' alone turns a two-line file into a single
// token with an internal CRLF that no trim can reach, and bootstrapList
// returns it with err == nil: one bootstrap entry nothing will ever answer on,
// silently.
//
// The two-line case is the one a weaker test would miss. A single address with
// a trailing CRLF comes out right whether splitPeers separates on line breaks
// or not, because trimSpaces cleans the ends either way — only a value naming
// two addresses can tell the two implementations apart. The count check is
// what reports it, though not the only check that would: net.SplitHostPort
// rejects a merged token with "too many colons in address", so the
// per-address assertion at the bottom would catch it too. The count is a
// Fatalf and simply fires first.
func TestPeersFlagCarryingLineEndingsSplitsIntoDiallableAddresses(t *testing.T) {
	for _, c := range []struct {
		name  string
		peers string
		want  []string
	}{
		{"one address with a trailing CRLF", "seed-a.example:9421\r\n",
			[]string{"seed-a.example:9421"}},
		{"a whole CRLF file expanded raw",
			"seed-a.example:9421\r\n127.0.0.1:9421\r\n",
			[]string{"seed-a.example:9421", "127.0.0.1:9421"}},
		{"a whole LF file expanded raw", "seed-a.example:9421\n127.0.0.1:9421\n",
			[]string{"seed-a.example:9421", "127.0.0.1:9421"}},
		{"a comma list broken across two lines", "seed-a.example:9421,\r\n127.0.0.1:9421",
			[]string{"seed-a.example:9421", "127.0.0.1:9421"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := bootstrapList(c.peers, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("--peers %q produced %d entries (%q), want %d: an address merged "+
					"with the next one across a line ending is a dial target nothing "+
					"answers on, and node/p2p budgets a connection for it",
					c.peers, len(got), got, len(c.want))
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("--peers %q produced %q, want %q", c.peers, got, c.want)
				}
			}
			for _, addr := range got {
				if _, port, err := net.SplitHostPort(addr); err != nil {
					t.Errorf("bootstrap address %q does not split into host and port (%v): "+
						"the operator wrote an address and this node holds something it "+
						"cannot dial", addr, err)
				} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
					t.Errorf("bootstrap address %q has port %q, which is not a number: a "+
						"line ending riding on the port fails every dial at `lookup "+
						"tcp/%s: unknown port`", addr, port, port)
				}
			}
		})
	}
}

// TestTrimSpacesCleansBothEndsOfAToken pins trimSpaces' own contract rather
// than one route through it: every byte it names, at either end, alone and in
// the combinations an operator's tooling actually emits.
//
// Going through bootstrapList pins only part of it. The space is already held
// at both ends by TestBootstrapListMergesRatherThanOverrides, whose --peers
// value leads its second token with one and whose file line reads
// "   seed-b.example:9421   # trailing comment" — spaced at both ends once
// the comment is cut. The trailing CR is held by the CRLF fixtures above.
// What no live path reaches is a tab at either end, an LF at either end, or
// a CR on the head: both callers cut their input on "\n" first, so an LF
// never gets this far at all. The contract is what makes trimSpaces safe as
// the single place either caller cleans a token: a token leaves as an
// address net.Dial can use or as nothing at all, never as a near-miss that
// prints indistinguishably from a good address and fails every dial for the
// life of the node.
func TestTrimSpacesCleansBothEndsOfAToken(t *testing.T) {
	const addr = "seed-a.example:9421"
	for _, c := range []struct{ name, in, want string }{
		{"leading space", " " + addr, addr},
		{"trailing space", addr + " ", addr},
		{"leading tab", "\t" + addr, addr},
		{"trailing tab", addr + "\t", addr},
		{"leading CR", "\r" + addr, addr},
		{"trailing CR", addr + "\r", addr},
		{"leading LF", "\n" + addr, addr},
		{"trailing LF", addr + "\n", addr},
		{"leading CRLF", "\r\n" + addr, addr},
		{"trailing CRLF", addr + "\r\n", addr},
		{"both ends at once", " \t\r\n" + addr + "\r\n\t ", addr},
		{"nothing but line endings", "\r\n", ""},
		{"nothing but whitespace", " \t", ""},
		{"interior bytes are left alone", "a b", "a b"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := trimSpaces(c.in); got != c.want {
				t.Errorf("trimSpaces(%q) = %q, want %q: an address carrying an invisible "+
					"byte is not a typo anybody can see — net.SplitHostPort hands the "+
					"resolver the byte along with the port and every dial dies at `lookup "+
					"tcp/...: unknown port`, forever", c.in, got, c.want)
			}
		})
	}
}

// TestMainHandsThePeersFileToTheNodeAndRefusesABadOne is about the seam
// between the helper above and the process: bootstrapList can be correct and
// the flag still do nothing.
//
// Three mutations of `main` survived this package's whole suite before this
// test. Passing "" for the path instead of the flag, or merging the list and
// never assigning it to the node's Bootstrap field, leaves `--peers-file`
// accepted on the command line and ignored — a node with no seeds and no
// complaint, which is the state the flag exists to prevent. Turning the
// `fatal(err)` into a `log.Printf` demotes the refusal docs/RUNNING.md promises
// ("a refusal to start, not a warning") into a line that scrolls past.
//
// Read off the syntax tree because main is not callable: it parses flags, binds
// a listener and opens a store. It is the move wiring_test.go and
// network_test.go already make, and mainFiles is theirs.
//
// What this cannot see is the process exiting. It asserts that the error
// reaches `fatal` and that `fatal` calls os.Exit, not that a started zycordd
// dies; observing that needs a seam this binary does not have — main's body
// extracted into a `run() error` a test could call.
func TestMainHandsThePeersFileToTheNodeAndRefusesABadOne(t *testing.T) {
	fset, files, mainFn := mainFiles(t)

	// The variable --peers-file is bound to, read off the literal it is
	// registered under rather than assumed, so renaming the variable does not
	// quietly turn this test into a check of nothing.
	peersFileVar := ""
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "String" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if name, err := strconv.Unquote(lit.Value); err == nil && name == "peers-file" {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				peersFileVar = id.Name
			}
		}
		return true
	})
	if peersFileVar == "" {
		t.Fatal("main registers no --peers-file flag, so the file docs/TESTNET.md tells " +
			"operators to join with cannot be given to this binary at all")
	}

	// The single call to bootstrapList, and where it sits, so the error check
	// that must follow it can be found.
	var (
		assign *ast.AssignStmt
		block  *ast.BlockStmt
		idx    int
		calls  int
	)
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		b, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, st := range b.List {
			as, ok := st.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 {
				continue
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "bootstrapList" {
				assign, block, idx = as, b, i
				calls++
			}
		}
		return true
	})
	if calls != 1 {
		t.Fatalf("main assigns the result of bootstrapList %d times; it must be exactly "+
			"once, and this test cannot follow a call it does not recognise", calls)
	}

	fed := false
	for _, a := range assign.Rhs[0].(*ast.CallExpr).Args {
		star, ok := a.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); ok && id.Name == peersFileVar {
			fed = true
		}
	}
	if !fed {
		t.Errorf("%s: main never passes the --peers-file flag to bootstrapList, so the flag "+
			"is parsed and ignored: the operator names a seed file, the node reads nothing "+
			"from it, and it comes up peerless with no error",
			fset.Position(assign.Pos()))
	}

	// And the merged list has to reach the node. Merging it and dropping it is
	// the same peerless node by a different route.
	listVar := ""
	if id, ok := assign.Lhs[0].(*ast.Ident); ok {
		listVar = id.Name
	}
	if listVar == "" {
		t.Fatalf("%s: bootstrapList's result is not assigned to a plain identifier, so this "+
			"test cannot follow it to the node", fset.Position(assign.Pos()))
	}
	reached := false
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Bootstrap" || i >= len(as.Rhs) {
				continue
			}
			if id, ok := as.Rhs[i].(*ast.Ident); ok && id.Name == listVar {
				reached = true
			}
		}
		return true
	})
	if !reached {
		t.Errorf("%s: the bootstrap list main merges is never assigned to the node's "+
			"Bootstrap field, so both --peers and --peers-file are read and thrown away", fset.Position(assign.Pos()))
	}

	// The refusal. docs/RUNNING.md: a --peers-file that is named and either
	// cannot be read or names no address is a refusal to start, not a warning.
	if idx+1 >= len(block.List) {
		t.Fatalf("%s: nothing follows the call to bootstrapList, so its error is discarded", fset.Position(assign.Pos()))
	}
	ifs, ok := block.List[idx+1].(*ast.IfStmt)
	if !ok {
		t.Fatalf("%s: the statement after bootstrapList is not an error check, so a "+
			"--peers-file that cannot be read does not stop this node",
			fset.Position(block.List[idx+1].Pos()))
	}
	fatals := 0
	ast.Inspect(ifs.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "fatal" {
			fatals++
		}
		return true
	})
	if fatals != 1 {
		t.Errorf("%s: bootstrapList's error is handled by %d calls to fatal, not one. A node "+
			"that logged this and carried on would come up peerless with no explanation, "+
			"which looks exactly like a network with nobody on it (docs/RUNNING.md)",
			fset.Position(ifs.Pos()), fatals)
	}

	// And fatal is what its name claims. A fatal that only printed would leave
	// the check above true and the refusal false.
	var fatalFn *ast.FuncDecl
	for _, d := range allDecls(files) {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "fatal" {
			fatalFn = fd
		}
	}
	if fatalFn == nil {
		t.Fatal("package main has no func fatal")
	}
	exits := false
	ast.Inspect(fatalFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Exit" {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" {
				exits = true
			}
		}
		return true
	})
	if !exits {
		t.Error("fatal does not call os.Exit, so every refusal in main — including the one " +
			"for an unreadable --peers-file — prints and continues")
	}
}
