package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/spec"
	"zycord/wallet"
)

// The property, in one sentence: the view coverageFixture.full() hand-builds
// records exactly what FetchState records for the same addresses, so the
// per-axis tests are separating terms of the real producer's output rather
// than of a fixture that only resembles it.
//
// # Why this is worth its own test
//
// TestEachCoverageAxisRefusesOnItsOwnSeparatingInput and
// TestPayeeCoverageDoesNotFireForAPayeeNoRuleReads are white-box over View
// literals, and they have to be: FetchState always fills both sets together
// for one address, so no exported constructor can build the view that
// separates the spent flag from the credited cell. The cost of that is the
// classic one — a test that agrees with its fixture rather than with the code
// that builds the thing in production. If full() recorded a set FetchState
// never produces, every case built on it would be separating terms of a view
// that cannot exist, and the axes could still be wrong about real sessions.
//
// This closes that gap from the other side: it drives the real FetchState
// against a node and asserts the two sets it records are EQUAL to the ones
// full() asserts. It compares the sets themselves rather than a coverage
// verdict, because two different sets can agree on one certificate and
// disagree on the next.

// producerNode is the smallest node surface FetchState needs. It is separate
// from session_test.go's mockNode because that one lives in the external test
// package and this test must see the unexported sets.
func producerNode(t *testing.T, p *params.Params) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			fmt.Fprintf(w, `{"chain_id":%d,"height":%d,"network":%q}`, p.ChainID, 1000, "zycord")
		case "/fees":
			fmt.Fprint(w, `{"seq_base_fee":"10","par_base_fee":"5","skip_fee":"1000"}`)
		case "/balance":
			// Every address answers live and empty. What is under test is
			// which questions the view can answer, not the answers.
			fmt.Fprint(w, `{"balance":"1000000000","spent":false}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestTheHandBuiltCoverageViewRecordsWhatFetchStateRecords(t *testing.T) {
	f := newCoverageFixture(oneShot(0xBB), types.NativeAsset)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	p := spec.Devnet()
	s, err := New(k, p, producerNode(t, p), "")
	if err != nil {
		t.Fatal(err)
	}

	// The same three addresses the fixture claims a fully covered view holds.
	produced, err := s.FetchState(f.src, f.payee, f.refund)
	if err != nil {
		t.Fatal(err)
	}
	built := f.full()

	if got, want := slotKeys(produced.fetched), slotKeys(built.fetched); !equal(got, want) {
		t.Errorf("the hand-built view's balance-cell set is not the one FetchState produces.\n"+
			"  FetchState: %v\n  fixture:    %v\n"+
			"The per-axis tests separate terms of the fixture, so a fixture the producer cannot "+
			"build makes them assertions about a view no session ever holds.", got, want)
	}
	if got, want := addrKeys(produced.fetchedSpent), addrKeys(built.fetchedSpent); !equal(got, want) {
		t.Errorf("the hand-built view's spent-flag set is not the one FetchState produces.\n"+
			"  FetchState: %v\n  fixture:    %v", got, want)
	}

	// And the produced view must actually cover the fixture's certificate. If
	// the sets above agree but this does not, the guard reads something
	// neither set records.
	if err := produced.CoversCertificate(f.cert); err != nil {
		t.Fatalf("a view FetchState built over every address the rules read must cover the certificate: %v", err)
	}

	// Truncating these keys would let a set with the WRONG members compare
	// equal to the right one, which is the failure this whole test exists to
	// catch, so they are rendered in full.

	// The other direction, and the one that carries the uncovered-read failure:
	// drop the payee from what the session asks the node about, and the real
	// producer's view is refused. This is the fixture's `drop` step performed by
	// the producer rather than by a delete on a literal.
	blind, err := s.FetchState(f.src, f.refund)
	if err != nil {
		t.Fatal(err)
	}
	if err := blind.CoversCertificate(f.cert); err == nil {
		t.Fatal("a view FetchState built without the one-shot payee accepted the certificate; " +
			"the payee axis does not fire on the producer's own output")
	}
}

func slotKeys(m map[types.Slot]struct{}) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, fmt.Sprintf("%x/%x", s.Addr[:], s.Word[:]))
	}
	sort.Strings(out)
	return out
}

func addrKeys(m map[types.Address]struct{}) []string {
	out := make([]string, 0, len(m))
	for a := range m {
		out = append(out, fmt.Sprintf("%x", a[:]))
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
