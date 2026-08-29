package ssz_test

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"testing"

	"zycord/core/crypto"
	"zycord/core/ssz"
	"zycord/core/state"
)

// TestTheDocumentFixesTheListRootSpellingByValue holds spec/README.md's
// statement of the merkle spelling against what this package computes.
//
// It exists because a second implementation of the epoch state root, written
// from the documents and forbidden from importing this package, derived every
// other part of the commitment and had to open ssz.go for exactly one line:
// how a list root binds its length. SSZ fixes the shape
// mix_in_length(merkleize(chunks, limit), len) and neither of the two choices
// underneath it — that this protocol spells the mix-in with the same tagged
// node function rather than a tag of its own, and that the length is a
// little-endian uint64 in the low eight bytes of a 32-byte chunk. Both are now
// written down; this is what stops them being written down *wrongly*, or
// quietly deleted.
//
// It follows core/validity's TestSpecReadmeNumbersAreDerivedNotAsserted and
// spec/invalid_rules_test.go: a document that is normative for a
// second implementation is checked against the tree rather than maintained
// beside it.
//
// **What it binds, and what it does not.** Four values are read out of the
// document and held against what the tree computes: the internal node tag; the
// empty list root, which is the one merkleised value every vector carrying a
// post_root commits to; the endianness and byte range of the length
// chunk; and nextPow2(0).
//
// **Every one of them is read, never restated.** The first version of this
// test transcribed the mix-in sentence into Go instead of parsing it, and a
// reviewer killed it in one move: flipping the document to big-endian and
// leaving the code alone left the test green. The tag and the constant were
// genuinely bound and the endianness decision was merely maintained beside the
// tree — which is the state this file exists to end, and the harder of the two
// decisions to get right. A claim wider than its check is the defect, not the
// wording of the claim.
//
// nextPow2(0) is bound through core/state rather than here, because that is
// where the protocol's only dynamic capacity lives and an empty state is the
// one input that reaches it. Importing it from an external test package of ssz
// creates no cycle.
//
// Not bound, and named rather than covered by the claim: the prose *around*
// those four values, and every reason the document gives for them. A reworded
// paragraph that still states the same four values passes here, because no
// test can tell a good explanation from a bad one — what this guarantees is
// that the values a reimplementer copies out of the document are the values
// this tree uses.
func TestTheDocumentFixesTheListRootSpellingByValue(t *testing.T) {
	raw, err := os.ReadFile("../../spec/README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	// The node function, stated by value.
	tagRe := regexp.MustCompile(`node\(left, right\) = blake3\("([^"]+)" ‖ left ‖ right\)`)
	m := tagRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("spec/README.md no longer states the internal node function in the shape "+
			"this test reads (%s); the normative value of the node tag is now bound by "+
			"nothing, and it would live only in a Go constant's comment again — reword the "+
			"regexp with the document, or the tag goes unchecked", tagRe)
	}
	if m[1] != crypto.TagSSZNode {
		t.Errorf("spec/README.md gives the internal node tag as %q, core/crypto uses %q — "+
			"a second implementation built from the document would compute a different value "+
			"for every merkle root in the protocol", m[1], crypto.TagSSZNode)
	}

	// The empty list root, stated by value. It is spent_root in every vector
	// that commits a post_root today, so it is the one constant an independent
	// implementation can check itself against before building anything.
	rootRe := regexp.MustCompile(`list_root\(\[\], 1\)[^\n]*\n\s*= ([0-9a-f]{64})`)
	m = rootRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("spec/README.md no longer states the empty list root in the shape this test "+
			"reads (%s); the document's one self-check constant is now bound by nothing", rootRe)
	}
	stated, err := hex.DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	var empty []crypto.Hash
	got := ssz.ListRoot(empty, 1)
	if string(stated) != string(got[:]) {
		t.Errorf("spec/README.md states list_root([], 1) = %s, this package computes %x — "+
			"the document and the tree disagree about the value every vector's spent_root "+
			"carries", m[1], got)
	}

	// Arming. Both decisions the document calls out must be observable in that
	// constant, or the two sentences state nothing and this test is checking a
	// value that any spelling would produce.
	//
	// Direction, declared before the fact: each variant below MUST differ from
	// the stated constant. A variant that matches is not a finding about the
	// protocol — it is a finding about this test.
	var zero crypto.Hash
	for _, v := range []struct {
		what string
		got  crypto.Hash
	}{
		{"a tag of its own for the mix-in", crypto.Sum("zcd/listlen/v1", zero[:], zero[:])},
		{"an untagged node function", crypto.Sum("", zero[:], zero[:])},
		{"the length chunk at capacity two", ssz.ListRoot(empty, 2)},
	} {
		if string(v.got[:]) == string(stated) {
			t.Errorf("FAIL (armed check): %s reproduces the constant the document states, so "+
				"that decision is unobservable here and the document's sentence about it is "+
				"bound by nothing", v.what)
		}
	}

	// The length chunk, built from what the document says rather than from what
	// this test would otherwise have restated. A non-empty list is required for
	// it to say anything: the length above is zero, and zero reads the same in
	// either endianness, which is why the constant checked above cannot see this
	// decision and this arm has to exist.
	lenRe := regexp.MustCompile(`length_chunk: len\(chunks\) as a (little|big)-endian uint64 in bytes (\d+)[-–](\d+), zero in bytes (\d+)[-–](\d+)`)
	m = lenRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("spec/README.md no longer states the length chunk in the shape this test "+
			"reads (%s); the endianness decision — the harder of the two, and the one the "+
			"document calls most likely to be got wrong — is now bound by nothing", lenRe)
	}
	lo, hi, zLo, zHi := atoi(t, m[2]), atoi(t, m[3]), atoi(t, m[4]), atoi(t, m[5])
	if hi-lo != 7 || zLo != hi+1 || zHi != 31 {
		t.Fatalf("spec/README.md describes a length chunk of bytes %d-%d with %d-%d zeroed; "+
			"that is not a uint64 widened into 32 bytes, so either the document is wrong or "+
			"this test can no longer read it", lo, hi, zLo, zHi)
	}
	chunks := []crypto.Hash{crypto.Sum("zcd/stateleaf/v1", zero[:])}
	var stmtLen crypto.Hash
	if m[1] == "little" {
		binary.LittleEndian.PutUint64(stmtLen[lo:hi+1], uint64(len(chunks)))
	} else {
		binary.BigEndian.PutUint64(stmtLen[lo:hi+1], uint64(len(chunks)))
	}
	shipped := ssz.ListRoot(chunks, 1)
	if stated := crypto.Sum(crypto.TagSSZNode, chunks[0][:], stmtLen[:]); stated != shipped {
		t.Errorf("spec/README.md's mix-in — the node tag over the merkle root and a "+
			"%s-endian length in bytes %d-%d — gives %x, ListRoot gives %x; the sentence a "+
			"second implementation would copy is false", m[1], lo, hi, stated, shipped)
	}
	// Direction, declared: the opposite endianness MUST differ, or the document's
	// sentence names a decision that is not one.
	var flipped crypto.Hash
	if m[1] == "little" {
		binary.BigEndian.PutUint64(flipped[24:], uint64(len(chunks)))
	} else {
		binary.LittleEndian.PutUint64(flipped[:8], uint64(len(chunks)))
	}
	if crypto.Sum(crypto.TagSSZNode, chunks[0][:], flipped[:]) == shipped {
		t.Errorf("FAIL (armed check): the opposite endianness roots the same as the stated " +
			"one, so the document's endianness sentence states nothing")
	}

	// nextPow2(0), read out of the document and bound through the one input in
	// the tree that reaches the protocol's only dynamic capacity: an empty
	// state, whose two subtrees are both ListRoot(nil, nextPow2(0)).
	capRe := regexp.MustCompile("`nextPow2\\(0\\) = (\\d+)`")
	m = capRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("spec/README.md no longer states nextPow2(0) in the shape this test reads "+
			"(%s); a normative value read back by nothing is what this file exists to "+
			"prevent", capRe)
	}
	statedCap := atoi(t, m[1])
	if r := ssz.ListRoot(empty, statedCap); string(r[:]) != string(stated) {
		t.Errorf("spec/README.md gives nextPow2(0) = %d, at which the empty list roots to %x, "+
			"but publishes %s as that root; the document disagrees with itself", statedCap, r, hex.EncodeToString(stated))
	}
	sub := ssz.ListRoot(empty, statedCap)
	want := crypto.Sum(crypto.TagStateRoot, sub[:], sub[:])
	if got := state.New().Root(); crypto.Hash(got) != want {
		t.Errorf("an empty state roots to %x; F14 over the document's nextPow2(0) = %d gives "+
			"%x — core/state's capacity for an empty list is not the one the specification "+
			"states", got, statedCap, want)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("spec/README.md says %q where this test expects a number: %v", s, err)
	}
	return n
}
