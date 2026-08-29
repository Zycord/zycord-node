package mempool_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"zycord/core/types"
	"zycord/core/validity"
	"zycord/node/mempool"
	"zycord/wallet"
)

// Admission is ordered by cost: every byte a peer sends is priced before it
// buys work.
//
// The property, in one sentence: **a certificate that any O(1) gate refuses
// costs the pool zero Ed25519 verifications, and a certificate the pool admits
// costs it exactly one.**
//
// These tests count verifications rather than timing them. "verified
// twice" and "verified before every cheap reject" are both claims about
// how many times a function ran, and a benchmark answers a different question —
// it measures this machine on this day, and it cannot distinguish "the check
// moved" from "the check got faster".

// forge corrupts a certificate's first signature without touching its body, so
// the certificate is structurally valid, has the same id (the id has not
// covered the signatures since the id was redefined to name an authorization
// rather than an encoding of one), and fails V2 and nothing else.
func forge(c *types.Certificate) *types.Certificate {
	forged := *c
	forged.Sigs = append([]types.Sig(nil), c.Sigs...)
	forged.Sigs[0].Sig[0] ^= 0xff
	return &forged
}

// certTTL is world.cert with the TTL chosen rather than fixed at 20. The
// ErrTTLTooFar row needs a TTL beyond params.TTLMax, and mutating a built
// certificate's TTL would break its signature, which would make that row's
// forged-signature twin assert nothing.
func (w *world) certTTL(signer *wallet.Key, ttl uint64) *types.Certificate {
	w.t.Helper()
	addr := signer.Persistent()
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, addr, key(w.t, 9999).Persistent(), drops(1_000)),
		Seq:     0,
		TTL:     ttl,
		Deposit: wallet.SelfDeposit(addr, addr),
		FeeBid:  wallet.Bid(drops(1_000_000), drops(10), drops(1_000_000), drops(1)),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		w.t.Fatal(err)
	}
	ceiling, ok := c.FeeCeiling(w.p)
	if !ok {
		w.t.Fatal("ceiling overflow")
	}
	slot := types.NativeBalanceSlot(addr)
	w.state.Set(slot, w.state.Get(slot).SatAdd(ceiling).SatAdd(drops(1_000_000_000)))
	return c
}

// freeRefusal is one gate of Add, the certificate that trips it, and the tip
// height to present it at.
type freeRefusal struct {
	name string
	cert func(w *world) *types.Certificate
	tip  uint64
	want error
}

// freeRefusals covers every gate in Pool.screen. If a gate is added without a
// row here, TestEveryFreeRefusalIsCoveredHere fails.
func freeRefusals() []freeRefusal {
	return []freeRefusal{
		{
			name: "ErrAlreadyPooled",
			cert: func(w *world) *types.Certificate {
				c := w.cert(key(w.t, 41_001), 0, 10, 1)
				if err := w.pool.Add(c, w.state, 1); err != nil {
					w.t.Fatalf("seeding the pool: %v", err)
				}
				return c
			},
			tip:  1,
			want: mempool.ErrAlreadyPooled,
		},
		{
			name: "ErrExpired",
			cert: func(w *world) *types.Certificate { return w.cert(key(w.t, 41_002), 0, 10, 1) },
			// The cert is built with TTL 20, so a tip already past it is the
			// cheapest refusal the pool has: no funds are needed, and the
			// chain advancing makes it permanent.
			tip:  100,
			want: mempool.ErrExpired,
		},
		{
			name: "ErrTTLTooFar",
			// params.TTLMax is 32 on devnet, so a TTL of 100 presented at
			// tip 0 is beyond the consensus bound by a wide margin.
			cert: func(w *world) *types.Certificate { return w.certTTL(key(w.t, 41_003), 100) },
			tip:  0,
			want: mempool.ErrTTLTooFar,
		},
		{
			name: "ErrTTLTooNear",
			cert: func(w *world) *types.Certificate { return w.cert(key(w.t, 41_004), 0, 10, 1) },
			tip:  19,
			want: mempool.ErrTTLTooNear,
		},
		{
			name: "ErrAlreadyCommitted",
			cert: func(w *world) *types.Certificate {
				c := w.cert(key(w.t, 41_005), 0, 10, 1)
				w.state.MarkSeen(c.ID(), c.TTL)
				return c
			},
			tip:  1,
			want: mempool.ErrAlreadyCommitted,
		},
		{
			name: "ErrBelowFloor",
			cert: func(w *world) *types.Certificate {
				c := w.cert(key(w.t, 41_006), 0, 10, 1)
				// One drop above the certificate's declared sequential
				// maximum, so the base fee has risen past what it offers.
				w.state.Set(types.SeqBaseFeeSlot(), c.FeeBid.SeqMax.SatAdd(drops(1)))
				return c
			},
			tip:  1,
			want: mempool.ErrBelowFloor,
		},
		{
			name: "ErrUnderfunded",
			cert: func(w *world) *types.Certificate {
				c := w.cert(key(w.t, 41_007), 0, 10, 1)
				// w.cert funds the deposit cell; take it back down to nothing.
				w.state.Set(types.NativeBalanceSlot(key(w.t, 41_007).Persistent()), drops(0))
				return c
			},
			tip:  1,
			want: mempool.ErrUnderfunded,
		},
		{
			name: "ErrTooManyInFlight",
			cert: func(w *world) *types.Certificate {
				signer := key(w.t, 41_008)
				for i := 0; i <= w.policy.MaxPerUnderwriter; i++ {
					c := w.cert(signer, uint64(i), 10, 1)
					if i == w.policy.MaxPerUnderwriter {
						return c
					}
					if err := w.pool.Add(c, w.state, 1); err != nil {
						w.t.Fatalf("filling the underwriter's quota at %d: %v", i, err)
					}
				}
				panic("unreachable")
			},
			tip:  1,
			want: mempool.ErrTooManyInFlight,
		},
	}
}

// TestAFreeRefusalBuysNoSignatureVerification.
//
// Before the fix every one of these rows verified the certificate's signatures
// first and refused afterwards, so the cheapest refusal the pool has cost the
// most expensive check it has.
func TestAFreeRefusalBuysNoSignatureVerification(t *testing.T) {
	for _, row := range freeRefusals() {
		t.Run(row.name, func(t *testing.T) {
			w := newWorld(t, smallPolicy())
			c := row.cert(w)

			var err error
			n := mempool.CountSignatureChecks(func() { err = w.pool.Add(c, w.state, row.tip) })

			if !errors.Is(err, row.want) {
				t.Fatalf("Add: got %v, want %v", err, row.want)
			}
			if n != 0 {
				t.Errorf("a refusal with %v verified signatures %d times, want 0", row.want, n)
			}
		})
	}
}

// TestAFreeRefusalOutranksAForgedSignature is the same property observed with
// no test seam at all, so that the counter above cannot be believed on its own
// authority.
//
// Each row's certificate is re-signed into garbage. V2 would refuse it with a
// validity error; the cheap gate refuses it with a policy error. Which error
// comes back is therefore a direct read of which check ran first, using nothing
// but the public API. Before the fix every row returned the V2 error.
func TestAFreeRefusalOutranksAForgedSignature(t *testing.T) {
	for _, row := range freeRefusals() {
		t.Run(row.name, func(t *testing.T) {
			w := newWorld(t, smallPolicy())
			c := forge(row.cert(w))

			err := w.pool.Add(c, w.state, row.tip)

			if !errors.Is(err, row.want) {
				t.Fatalf("Add: got %v, want %v", err, row.want)
			}
		})
	}
}

// TestAForgedSignatureIsStillRefused is the anti-vacuity companion to the test
// above, and it is what stops that test from passing for the wrong reason.
//
// If `forge` did not actually break V2, every row up there would return its
// policy error whatever the ordering was, and the whole table would assert
// nothing. So: the same forgery, with no gate failing, must be refused, and
// refused by V2 specifically.
func TestAForgedSignatureIsStillRefused(t *testing.T) {
	w := newWorld(t, smallPolicy())
	honest := w.cert(key(t, 41_100), 0, 10, 1)

	if err := w.pool.Add(forge(honest), w.state, 1); err == nil {
		t.Fatal("a forged certificate was admitted")
	} else if rule := validity.Rule(err); rule != "V2" {
		t.Fatalf("a forged certificate was refused by %q, want V2 (%v)", rule, err)
	}

	// And the un-forged original is admitted, so the refusal above is the
	// signature and not something else about this certificate.
	if err := w.pool.Add(honest, w.state, 1); err != nil {
		t.Fatalf("the honest original was refused too: %v", err)
	}
}

// TestAnAdmittedCertificateIsVerifiedExactlyOnce is the pool's half of
// "verified exactly once".
//
// One admission, one Ed25519 pass. The engine's own pre-Add validity.Check is
// the other half and lives in node/p2p, which this file does not own.
func TestAnAdmittedCertificateIsVerifiedExactlyOnce(t *testing.T) {
	w := newWorld(t, smallPolicy())
	c := w.cert(key(t, 41_200), 0, 10, 1)

	var err error
	n := mempool.CountSignatureChecks(func() { err = w.pool.Add(c, w.state, 1) })

	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if n != 1 {
		t.Fatalf("an admitted certificate was verified %d times, want exactly 1", n)
	}
}

// TestTheCounterCanSeeAVerification is the surroundings mutation for
// TestAFreeRefusalBuysNoSignatureVerification: the zero it asserts must be a
// zero the harness could have failed to produce.
//
// Same world, same certificate factory, same counter — the only difference is
// that no gate refuses. If this reported 0 as well, the counter would be blind
// and every "want 0" above would be vacuous.
func TestTheCounterCanSeeAVerification(t *testing.T) {
	w := newWorld(t, smallPolicy())
	c := w.cert(key(t, 41_300), 0, 10, 1)

	// Refused: TTL already past, the cheapest gate there is.
	refused := mempool.CountSignatureChecks(func() {
		if err := w.pool.Add(c, w.state, 100); !errors.Is(err, mempool.ErrExpired) {
			t.Fatalf("Add at a tip past the TTL: got %v, want ErrExpired", err)
		}
	})
	// Admitted: the identical certificate, at a tip inside its window.
	admitted := mempool.CountSignatureChecks(func() {
		if err := w.pool.Add(c, w.state, 1); err != nil {
			t.Fatalf("Add inside the TTL window: %v", err)
		}
	})

	if refused != 0 || admitted != 1 {
		t.Fatalf("one certificate, two tips: refused cost %d verifications and admitted cost %d; want 0 and 1",
			refused, admitted)
	}
}

// TestEveryFreeRefusalIsCoveredHere stops the table above from silently going
// out of date: a gate added to Pool.screen without a row is a gate nobody has
// shown to be free.
//
// The list of sentinels is checked against the package's own source rather than
// trusted, because a hand-maintained list is invisible to exactly the change it
// exists to catch — a *new* sentinel. The AST pass below reads every top-level
// Err... declaration out of mempool.go, so adding one fails this test until
// somebody has said, here, whether it is free or whether the eviction pass owns
// it.
//
// The refusals the eviction pass owns (ErrFull, ErrBelowEvictionFloor) run
// after V2 by design, because they mutate the pool and an unverified
// certificate must never cause an eviction.
func TestEveryFreeRefusalIsCoveredHere(t *testing.T) {
	afterSignatures := map[string]bool{
		"ErrFull":               true,
		"ErrBelowEvictionFloor": true,
	}
	all := map[string]error{
		"ErrAlreadyPooled":      mempool.ErrAlreadyPooled,
		"ErrAlreadyCommitted":   mempool.ErrAlreadyCommitted,
		"ErrExpired":            mempool.ErrExpired,
		"ErrTTLTooFar":          mempool.ErrTTLTooFar,
		"ErrTTLTooNear":         mempool.ErrTTLTooNear,
		"ErrUnderfunded":        mempool.ErrUnderfunded,
		"ErrBelowFloor":         mempool.ErrBelowFloor,
		"ErrTooManyInFlight":    mempool.ErrTooManyInFlight,
		"ErrFull":               mempool.ErrFull,
		"ErrBelowEvictionFloor": mempool.ErrBelowEvictionFloor,
	}

	declared := declaredSentinels(t)
	if len(declared) == 0 {
		t.Fatal("no sentinels were read out of mempool.go, so this check asserts nothing")
	}
	for name := range declared {
		if _, known := all[name]; !known {
			t.Errorf("mempool declares %s, which this test has never classified: "+
				"give it a row in freeRefusals() if a cheap gate returns it, or add it to "+
				"afterSignatures if the eviction pass owns it", name)
		}
	}
	for name := range all {
		if !declared[name] {
			t.Errorf("%s is listed here but is no longer declared in mempool.go", name)
		}
	}

	covered := map[error]bool{}
	for _, row := range freeRefusals() {
		covered[row.want] = true
	}
	for name, e := range all {
		if afterSignatures[name] {
			continue
		}
		if !covered[e] {
			t.Errorf("%v is a free refusal with no row in freeRefusals()", e)
		}
	}
}

// declaredSentinels is the set of top-level Err... variables mempool.go
// declares. Source-derived on purpose; see the test above.
func declaredSentinels(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "mempool.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				if strings.HasPrefix(n.Name, "Err") {
					names[n.Name] = true
				}
			}
		}
	}
	return names
}

// TestAnUnverifiedCertificateNeverEvicts is the safety half of the reorder.
//
// The gates moved in front of V2 are all read-only. The eviction pass is not,
// and it stayed behind V2 deliberately: if it had moved too, a forged
// certificate would have been able to evict honest residents for free, which
// would have traded a signature-verification flood for a strictly worse one.
func TestAnUnverifiedCertificateNeverEvicts(t *testing.T) {
	w := newWorld(t, smallPolicy())
	size := w.fillToHighWater(1)
	if size == 0 {
		t.Fatal("the pool did not fill")
	}

	// An arrival that would comfortably clear the eviction floor — so the pass
	// would run and would remove somebody — but whose signature is garbage.
	rich := forge(w.cert(key(t, 41_400), 0, 1_000_000, 1))
	if err := w.pool.Add(rich, w.state, 1); err == nil {
		t.Fatal("a forged certificate was admitted")
	}
	if got := w.pool.Stats().Size; got != size {
		t.Fatalf("a forged certificate evicted %d residents; the pool must not move", size-got)
	}

	// Anti-vacuity: the honestly-signed twin of that arrival does evict, so the
	// pool was genuinely at a mark where an eviction was available to be
	// wrongly bought.
	honest := w.cert(key(t, 41_401), 0, 1_000_000, 1)
	if err := w.pool.Add(honest, w.state, 1); err != nil {
		t.Fatalf("the honest twin was refused, so nothing was at stake: %v", err)
	}
	if got := w.pool.Stats().Size; got >= size {
		t.Fatalf("the honest twin evicted nobody (size %d -> %d); the pool was not under pressure", size, got)
	}
}
