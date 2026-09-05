package crypto_test

import (
	"crypto/ed25519"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"zycord/core/crypto"
)

// TestDomainSeparationIsTotal: no two tags may produce the same digest for the
// same payload. A value hashed for one purpose must never be replayable as a
// value hashed for another, and the tag list is small enough to check
// exhaustively — so it is.
//
// The list it checks is DERIVED FROM THE SOURCE rather than written out here
// rather than trusted to a list. It used to be a hand-maintained slice of
// eighteen constants, and a hand-maintained slice can only ever check what
// somebody remembered to add to it: a nineteenth Tag constant repeating an
// existing value was absent from the slice, so it was never compared to
// anything and this test — the only check on duplicate tag *values* in the
// tree — could not fire on it. The identifier-keyed scan in
// TestNoTwoVariableLengthHashCallSitesCanShareAPreimage could not fire on it
// either, because it keys on four names a new constant does not mention. Each
// guard's blind spot was the other's coverage on paper and neither covered it
// in fact, which is why the enumeration here is now mechanical.
//
// declaredDomainTags parses every Tag* constant the package declares, so the
// checks below apply to what exists. The compiled map underneath is not the
// enumeration any more — it is the cross-check that the literal in the source is
// the value the compiler hands callers, and a tag missing from it is a failure
// naming the constant rather than a silent omission.
func TestDomainSeparationIsTotal(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	declared := declaredDomainTags(t, dir)

	// Every entry here is a reference to the constant itself, so it carries the
	// value the compiler sees. The two directions below make this map and the
	// parsed set prove each other: a new constant fails the first loop, and a
	// constant renamed or deleted out from under this map fails the second.
	compiled := map[string]string{
		"TagCert":          crypto.TagCert,
		"TagCertID":        crypto.TagCertID,
		"TagCertBody":      crypto.TagCertBody,
		"TagBlock":         crypto.TagBlock,
		"TagAddr":          crypto.TagAddr,
		"TagPoW":           crypto.TagPoW,
		"TagPoWKey":        crypto.TagPoWKey,
		"TagSig":           crypto.TagSig,
		"TagBalanceWord":   crypto.TagBalanceWord,
		"TagAssetWord":     crypto.TagAssetWord,
		"TagBeaconWord":    crypto.TagBeaconWord,
		"TagProtocolWord":  crypto.TagProtocolWord,
		"TagSSZNode":       crypto.TagSSZNode,
		"TagStateCell":     crypto.TagStateCell,
		"TagStateSpent":    crypto.TagStateSpent,
		"TagStateRoot":     crypto.TagStateRoot,
		"TagParams":        crypto.TagParams,
		"TagConsensusRoot": crypto.TagConsensusRoot,
	}

	seenName := map[string]bool{}
	for _, d := range declared {
		if seenName[d.name] {
			t.Fatalf("the constant %s is declared twice", d.name)
		}
		seenName[d.name] = true

		value, listed := compiled[d.name]
		if !listed {
			t.Fatalf("%s: crypto.%s is declared but is not in this test's compiled map — "+
				"add %q: crypto.%s to it so the value the compiler sees is the value checked here",
				d.pos, d.name, d.name, d.name)
		}
		if value != d.value {
			t.Fatalf("%s: crypto.%s is %q to the compiler and %q in the source",
				d.pos, d.name, value, d.value)
		}
	}
	for name := range compiled {
		if !seenName[name] {
			t.Fatalf("crypto.%s is listed in this test's compiled map but the source scan "+
				"did not find it: the scan is missing declarations it must see", name)
		}
	}

	if err := checkDomainSeparation(declared); err != nil {
		t.Fatal(err)
	}
}

// domainTag is one Tag* constant as the package source declares it.
type domainTag struct {
	name  string
	value string
	pos   string // file:line, for a failure that points at the declaration
}

// checkDomainSeparation runs every property the tag set must have, over
// whatever set it is handed. It returns an error rather than failing a *testing.T
// so that TestDomainSeparationEnumerationIsMechanical can hand it a constructed
// counterexample and assert it fires — a guard nothing ever trips is a guard
// nobody has evidence for.
func checkDomainSeparation(tags []domainTag) error {
	// The tags themselves must be distinct strings. This is the check the
	// hand-maintained slice could not make about a constant that was not in it.
	byValue := map[string]string{}
	for _, tag := range tags {
		if other, dup := byValue[tag.value]; dup {
			return fmt.Errorf("%s: %s and %s are both the domain tag %q: "+
				"every digest taken under one is a digest under the other",
				tag.pos, other, tag.name, tag.value)
		}
		byValue[tag.value] = tag.name
	}

	// And no tag may be a prefix of another, which the loop below cannot see.
	//
	// Sum is blake3(tag || payload), so if tag A is a prefix of tag B then
	// Sum(A, B[len(A):] || payload) and Sum(B, payload) are the same call over
	// the same bytes. The loop below hashes one payload under every tag and so
	// only ever compares equal-payload digests; a prefix collision needs two
	// *different* payloads and is invisible to it. Distinct strings are not
	// enough — "zcd/cert/v1" and "zcd/certid/v1" are distinct, and they are the
	// closest pair in the table, which is why this is computed here rather than
	// argued in a comment. The /v1 suffix is what keeps the cert family safe,
	// and this is the check that keeps it that way when the next tag is added.
	for _, a := range tags {
		for _, b := range tags {
			if a.value != b.value && strings.HasPrefix(b.value, a.value) {
				return fmt.Errorf("the domain tag %q (%s) is a prefix of %q (%s): "+
					"Sum(%q, %q||payload) and Sum(%q, payload) are the same digest",
					a.value, a.name, b.value, b.name,
					a.value, b.value[len(a.value):], b.value)
			}
		}
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		payload := make([]byte, rng.Intn(64))
		rng.Read(payload)

		seen := map[crypto.Hash]string{}
		for _, tag := range tags {
			h := crypto.Sum(tag.value, payload)
			if other, dup := seen[h]; dup {
				return fmt.Errorf("tags %q and %q collide on a %d-byte payload",
					tag.value, other, len(payload))
			}
			seen[h] = tag.value
		}
	}
	return nil
}

// declaredDomainTags returns every Tag* string constant declared by the non-test
// Go source in dir, sorted by name.
//
// It scans the whole package directory rather than one file, so that a tag
// declared next to the code that uses it is enumerated too; and it keys on the
// Tag prefix rather than on a list of names, so that a constant nobody told it
// about is exactly the constant it reports. A Tag* constant that is not a plain
// string literal is a failure and not a skip — silently dropping the shapes a
// scanner did not expect is the failure mode this scan exists to end.
func declaredDomainTags(t *testing.T, dir string) []domainTag {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	var (
		out    []domainTag
		parsed int
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		parsed++

		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if !strings.HasPrefix(ident.Name, "Tag") {
						continue
					}
					pos := fmt.Sprintf("%s:%d", name, fset.Position(ident.Pos()).Line)
					if i >= len(vs.Values) {
						t.Fatalf("%s: %s has no value of its own (an implicit "+
							"repetition or iota); this scan cannot price it", pos, ident.Name)
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: %s is not a plain string literal; this scan "+
							"cannot price it", pos, ident.Name)
					}
					value, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						t.Fatalf("%s: %s: %v", pos, ident.Name, uerr)
					}
					out = append(out, domainTag{name: ident.Name, value: value, pos: pos})
				}
			}
		}
	}
	if parsed == 0 {
		t.Fatalf("no non-test Go source under %s: the enumeration is measuring nothing", dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// TestDomainSeparationEnumerationIsMechanical is the evidence that the scan
// above sees a constant nobody added to a list, and that the check above fires
// on what it sees. Both halves are what the hand-maintained tag list left
// unchecked, so both are demonstrated on a constructed package rather than
// asserted in a comment.
//
// The duplicate is the counterexample that motivated the scan: a nineteenth tag
// whose value repeats TagProtocolWord's.
func TestDomainSeparationEnumerationIsMechanical(t *testing.T) {
	const clean = `package crypto

const HashSize = 32

// Domain tags.
const (
	TagProtocolWord = "zcd/protoword/v1"
	TagBlock        = "zcd/block/v1"
)

const NotATag = "zcd/protoword/v1"
`
	const withDuplicate = clean + `
// A tag declared away from the block, with a value that already exists.
const TagCoinbaseWord = "zcd/protoword/v1"
`

	write := func(t *testing.T, src string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "crypto.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		// A _test.go file must be ignored: a tag named only in a test is not a
		// tag the package declares.
		if err := os.WriteFile(filepath.Join(dir, "crypto_test.go"),
			[]byte("package crypto\n\nconst TagFromATestFile = \"zcd/nope/v1\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	got := declaredDomainTags(t, write(t, clean))
	var names []string
	for _, d := range got {
		names = append(names, d.name)
	}
	if want := []string{"TagBlock", "TagProtocolWord"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("the scan enumerated %v, want %v", names, want)
	}
	if err := checkDomainSeparation(got); err != nil {
		t.Fatalf("a well-separated tag set was rejected: %v", err)
	}

	// And now the nineteenth constant. Nothing below names it; the scan finds it
	// because it is declared, which is the whole point.
	got = declaredDomainTags(t, write(t, withDuplicate))
	found := false
	for _, d := range got {
		if d.name == "TagCoinbaseWord" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the scan did not enumerate a newly declared tag constant: %v", got)
	}
	err := checkDomainSeparation(got)
	if err == nil {
		t.Fatal("a duplicated tag value passed the check: the guard cannot fire, " +
			"which is exactly the state a hand-maintained tag list leaves it in")
	}
	if !strings.Contains(err.Error(), "TagCoinbaseWord") ||
		!strings.Contains(err.Error(), "zcd/protoword/v1") {
		t.Fatalf("the failure does not name the duplicate pair: %v", err)
	}
}

// TestSumIsConcatenationOfParts pins the one thing a variadic hash helper can
// get wrong: the parts must be hashed as one stream, so that a caller cannot
// change the meaning by moving a boundary.
func TestSumIsConcatenationOfParts(t *testing.T) {
	a, b := []byte("hello"), []byte("world")
	if crypto.Sum(crypto.TagCert, a, b) != crypto.Sum(crypto.TagCert, append(append([]byte{}, a...), b...)) {
		t.Fatal("multi-part hashing differs from hashing the concatenation")
	}
}

// TestAddressDerivation: the version byte is inside the hash and is also the
// first byte of the address, so an address cannot be reinterpreted as another
// kind by rewriting one byte.
func TestAddressDerivation(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	var pub crypto.PubKey
	rng.Read(pub[:])

	versions := []byte{
		crypto.AddrVersionOneShot,
		crypto.AddrVersionPersistent,
		crypto.AddrVersionAsset,
	}
	seen := map[crypto.Address]bool{}
	for _, v := range versions {
		a := crypto.AddressFromPubKey(v, pub)
		if a[0] != v {
			t.Fatalf("version %d is not the first byte of the address", v)
		}
		if seen[a] {
			t.Fatal("two versions produced the same address")
		}
		seen[a] = true
	}

	// The protocol address is recognisable by inspection rather than derived,
	// so that nothing can ever collide with it by finding a preimage.
	if crypto.ProtocolAddress != (crypto.Address{0x00}) {
		t.Fatal("the protocol address is not version 0x00 followed by zeros")
	}
	if crypto.IsUserAddress(crypto.ProtocolAddress) {
		t.Fatal("the protocol address is debitable by signature")
	}
}

// TestStrictVerification: real signatures verify, and the ways a signature can
// be almost-right do not.
func TestStrictVerification(t *testing.T) {
	pubRaw, priv, err := ed25519.GenerateKey(rand.New(rand.NewSource(3)))
	if err != nil {
		t.Fatal(err)
	}
	var pub crypto.PubKey
	copy(pub[:], pubRaw)

	msg := []byte("zcd/test")
	var sig crypto.Signature
	copy(sig[:], ed25519.Sign(priv, msg))

	if !crypto.VerifyStrict(pub, msg, sig) {
		t.Fatal("a valid signature did not verify")
	}
	if crypto.VerifyStrict(pub, []byte("other"), sig) {
		t.Fatal("a signature verified over the wrong message")
	}

	flipped := sig
	flipped[0] ^= 1
	if crypto.VerifyStrict(pub, msg, flipped) {
		t.Fatal("a corrupted signature verified")
	}

	wrongKey := pub
	wrongKey[0] ^= 1
	if crypto.VerifyStrict(wrongKey, msg, sig) {
		t.Fatal("a signature verified under the wrong key")
	}
}

// TestSigningMessageBindsEveryFieldOfItsPreimage: a mainnet certificate
// replayed on a testnet must fail signature verification, not some policy
// check -- and the same must hold for a certificate lifted off a previous
// incarnation of one network, which is what the consensus root is in the
// preimage for.
//
// Each of the three fields is moved on its own, so a preimage that dropped one
// of them fails here rather than being caught only by the corpus.
func TestSigningMessageBindsEveryFieldOfItsPreimage(t *testing.T) {
	root := crypto.Hash{1, 2, 3}
	consensus := crypto.Hash{4, 5, 6}
	base := crypto.SigningMessage(1, consensus, root)

	if reflect.DeepEqual(base, crypto.SigningMessage(2, consensus, root)) {
		t.Fatal("the signing message does not depend on the chain id")
	}
	if reflect.DeepEqual(base, crypto.SigningMessage(1, crypto.Hash{7}, root)) {
		t.Fatal("the signing message does not depend on the consensus root")
	}
	if reflect.DeepEqual(base, crypto.SigningMessage(1, consensus, crypto.Hash{9})) {
		t.Fatal("the signing message does not depend on the certificate body")
	}
}

// TestSignaturesAreNotMalleable is the test behind a consensus rule, and the
// rule is load-bearing in a way that is not obvious from where it sits.
//
// What it defends is cross-implementation agreement. A verifier that accepts an
// encoding its peers reject forks the network on a certificate neither side can
// call invalid, and the split is silent because both sides believe they are
// right. Every signature this project generates is canonical, so no ordinary
// test ever presents a non-canonical one and nothing else in the suite would
// notice a regression.
//
// It used to be stated as the replay defence, and that reason was wrong. The
// argument ran: the certificate id covers Sigs, so two encodings of one
// authorization are two ids and the second sails past the seen check. It closed
// the ENCODING channel and never reached the NONCE channel, which no encoding
// rule can reach — a signer picks r, every [r]B is a canonically encodable
// prime-order point, and each yields a valid canonical signature over the same
// message. One authorization therefore had unboundedly many valid exemplars
// whatever this function does, and the fix was never available here: it was to
// take Sigs out of the id's preimage (core/types.Certificate.ID). The
// same correction is written at VerifyStrict, where the rule lives.
//
// The property is stronger than "signatures verify": for a given key, message
// and nonce there must be exactly *one* byte string that verifies. Ed25519 as
// specified has that property, and this repository gets it from the standard
// library rather than from code of its own — which is precisely why it is
// tested here. A library swap, a build tag, or a future implementation that
// relaxes scalar canonicality would reopen the hole silently, and nothing else
// in the suite would notice: every signature this project generates is
// canonical, so no ordinary test ever presents a non-canonical one.
func TestSignaturesAreNotMalleable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(deterministicReader(7))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a payment somebody signed once")

	var key crypto.PubKey
	copy(key[:], pub)
	var sig crypto.Signature
	copy(sig[:], ed25519.Sign(priv, msg))

	if !crypto.VerifyStrict(key, msg, sig) {
		t.Fatal("the honest signature does not verify; the rest of this test proves nothing")
	}

	// Every mutation below is a re-encoding an attacker can compute from the
	// signature alone. None of them may verify.
	for _, tc := range []struct {
		name string
		sig  crypto.Signature
	}{
		{"S + L, the classic non-canonical scalar", addGroupOrder(sig)},
		{"S with the high bit set", tweak(sig, 63, 0x80)},
		{"R with its sign bit flipped", tweak(sig, 31, 0x80)},
		{"S with its low bit flipped", tweak(sig, 32, 0x01)},
		{"R with its low bit flipped", tweak(sig, 0, 0x01)},
	} {
		if tc.sig == sig {
			t.Fatalf("%s: the mutation did not change the signature", tc.name)
		}
		if crypto.VerifyStrict(key, msg, tc.sig) {
			t.Fatalf("%s: a re-encoded signature verified — one authorization now has "+
				"two certificate ids, and the seen set cannot stop the second", tc.name)
		}
	}

	// And the same property from the other side: a key whose encoding was
	// altered must not verify a signature made under the original.
	if crypto.VerifyStrict(tweakKey(key, 31, 0x80), msg, sig) {
		t.Fatal("a re-encoded public key verified a signature made under the original")
	}
}

// addGroupOrder returns the signature with S replaced by S + L, where L is the
// order of the Ed25519 prime-order subgroup. S and S+L are congruent modulo L,
// so an implementation that reduces before checking — rather than rejecting a
// scalar that is not already reduced — accepts both. That is the malleability
// this project must not have.
//
// L is written out as little-endian bytes, matching the wire encoding of S, so
// that the addition is a plain carry loop and needs no bignum in core/.
func addGroupOrder(sig crypto.Signature) crypto.Signature {
	order := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	out := sig
	var carry uint16
	for i := 0; i < 32; i++ {
		sum := uint16(out[32+i]) + uint16(order[i]) + carry
		out[32+i] = byte(sum)
		carry = sum >> 8
	}
	return out
}

func tweak(sig crypto.Signature, index int, mask byte) crypto.Signature {
	out := sig
	out[index] ^= mask
	return out
}

func tweakKey(key crypto.PubKey, index int, mask byte) crypto.PubKey {
	out := key
	out[index] ^= mask
	return out
}

// deterministicReader seeds key generation from a fixed source, because a test
// that cannot be reproduced from source is not evidence.
func deterministicReader(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }
