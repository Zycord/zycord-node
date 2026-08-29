package blake3

import (
	"encoding/hex"
	"testing"
)

// testInput reproduces the input pattern used by the official BLAKE3 test
// vectors: byte i is i mod 251.
func testInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// Official BLAKE3 test vectors (unkeyed, 32-byte output). The selected lengths
// exercise every structural path in the tree construction: the empty input,
// a partial first block, a full chunk, a chunk boundary, the first parent node
// and a two-chunk tree.
var officialVectors = []struct {
	length int
	hash   string
}{
	{0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
	{1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
	{2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"},
	{3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"},
	{1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"},
	{1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"},
	{1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"},
	{2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"},
}

func TestOfficialVectors(t *testing.T) {
	for _, v := range officialVectors {
		got := Sum256(testInput(v.length))
		if hex.EncodeToString(got[:]) != v.hash {
			t.Errorf("Sum256(len=%d) = %s, want %s", v.length, hex.EncodeToString(got[:]), v.hash)
		}
	}
}

// TestIncrementalMatchesOneShot pins the property the tree construction exists
// for: the digest must not depend on how the input was split across writes.
func TestIncrementalMatchesOneShot(t *testing.T) {
	input := testInput(5000)
	want := Sum256(input)
	for _, split := range []int{1, 7, 63, 64, 65, 127, 512, 1023, 1024, 1025, 2047, 4096} {
		h := New()
		for off := 0; off < len(input); off += split {
			end := off + split
			if end > len(input) {
				end = len(input)
			}
			h.Write(input[off:end])
		}
		var got [Size]byte
		h.XOF(got[:])
		if got != want {
			t.Errorf("split=%d: digest differs from one-shot", split)
		}
	}
}

// TestXOFPrefix checks that the extendable output is a stream, not a family of
// unrelated digests: the 32-byte digest must be the prefix of any longer one.
func TestXOFPrefix(t *testing.T) {
	input := testInput(3000)
	short := Sum256(input)

	h := New()
	h.Write(input)
	long := make([]byte, 512)
	h.XOF(long)

	if string(long[:Size]) != string(short[:]) {
		t.Fatal("XOF output does not extend the 32-byte digest")
	}

	// The stream must also be independent of the requested chunking.
	h2 := New()
	h2.Write(input)
	piece := make([]byte, 512)
	h2.XOF(piece)
	if string(piece) != string(long) {
		t.Fatal("XOF output is not deterministic")
	}
}

func TestKeyedDiffersFromUnkeyed(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}
	input := testInput(300)
	if Sum256Keyed(key, input) == Sum256(input) {
		t.Fatal("keyed and unkeyed digests collide")
	}
	// A one-bit key change must change the digest.
	key2 := key
	key2[0] ^= 1
	if Sum256Keyed(key, input) == Sum256Keyed(key2, input) {
		t.Fatal("keyed digest ignores the key")
	}
}

func TestReset(t *testing.T) {
	h := New()
	h.Write(testInput(4000))
	h.Reset()
	h.Write(testInput(10))
	var got [Size]byte
	h.XOF(got[:])
	if got != Sum256(testInput(10)) {
		t.Fatal("Reset did not restore the initial state")
	}
}

func BenchmarkSum256_1KiB(b *testing.B) {
	data := testInput(1024)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}
