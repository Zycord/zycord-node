package ssz_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"

	"zycord/core/crypto"
	"zycord/core/ssz"
	"zycord/spec"
)

// TestContainerRoundTrip: a mixed fixed/variable container survives encoding.
func TestContainerRoundTrip(t *testing.T) {
	layout := []int{8, ssz.Variable, 4, ssz.Variable}
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 500; i++ {
		fields := [][]byte{
			ssz.Uint64(rng.Uint64()),
			randBytes(rng, rng.Intn(40)),
			ssz.Uint32(rng.Uint32()),
			randBytes(rng, rng.Intn(40)),
		}
		enc := ssz.Encode(layout, fields)
		back, err := ssz.Decode(layout, enc)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		for j := range fields {
			if !bytes.Equal(back[j], fields[j]) {
				t.Fatalf("field %d differs after a round trip", j)
			}
		}
	}
}

// TestNonCanonicalOffsetsAreRejected. The offset table is where a decoder that
// merely *works* differs from one that is canonical: two different byte strings
// must never decode to one value.
func TestNonCanonicalOffsetsAreRejected(t *testing.T) {
	layout := []int{4, ssz.Variable, ssz.Variable}
	enc := ssz.Encode(layout, [][]byte{ssz.Uint32(7), []byte("abc"), []byte("de")})

	t.Run("first offset past the fixed section", func(t *testing.T) {
		bad := append([]byte(nil), enc...)
		binary.LittleEndian.PutUint32(bad[4:], 13)
		if _, err := ssz.Decode(layout, bad); err == nil {
			t.Fatal("an offset that skips bytes decoded")
		}
	})

	t.Run("offsets move backwards", func(t *testing.T) {
		bad := append([]byte(nil), enc...)
		binary.LittleEndian.PutUint32(bad[8:], 0)
		if _, err := ssz.Decode(layout, bad); err == nil {
			t.Fatal("a backwards offset decoded")
		}
	})

	t.Run("offset past the end", func(t *testing.T) {
		bad := append([]byte(nil), enc...)
		binary.LittleEndian.PutUint32(bad[8:], uint32(len(enc)+1))
		if _, err := ssz.Decode(layout, bad); err == nil {
			t.Fatal("an out-of-range offset decoded")
		}
	})

	t.Run("short input", func(t *testing.T) {
		if _, err := ssz.Decode(layout, enc[:3]); err == nil {
			t.Fatal("a truncated container decoded")
		}
	})

	t.Run("trailing bytes on a fixed container", func(t *testing.T) {
		fixed := []int{4, 4}
		good := ssz.Encode(fixed, [][]byte{ssz.Uint32(1), ssz.Uint32(2)})
		if _, err := ssz.Decode(fixed, append(good, 0)); err == nil {
			t.Fatal("a fixed container with trailing bytes decoded")
		}
	})
}

func TestFixedListRejectsPartialElements(t *testing.T) {
	if _, err := ssz.DecodeFixedList(make([]byte, 10), 4, 100); err == nil {
		t.Fatal("a list that is not a whole number of elements decoded")
	}
	if _, err := ssz.DecodeFixedList(make([]byte, 12), 4, 2); err == nil {
		t.Fatal("a list over its limit decoded")
	}
	elems, err := ssz.DecodeFixedList(make([]byte, 12), 4, 3)
	if err != nil || len(elems) != 3 {
		t.Fatalf("got %d elements, %v", len(elems), err)
	}
	if elems, err := ssz.DecodeFixedList(nil, 4, 3); err != nil || len(elems) != 0 {
		t.Fatal("an empty list must decode to no elements")
	}
}

func TestVariableListRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for n := 0; n < 8; n++ {
		elems := make([][]byte, n)
		for i := range elems {
			elems[i] = randBytes(rng, rng.Intn(20))
		}
		enc := ssz.EncodeVariableList(elems)
		back, err := ssz.DecodeVariableList(enc, 100, 0)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(back) != n {
			t.Fatalf("n=%d: decoded %d elements", n, len(back))
		}
		for i := range elems {
			if !bytes.Equal(back[i], elems[i]) {
				t.Fatalf("n=%d: element %d differs", n, i)
			}
		}
	}
}

// TestMerkleRootDependsOnTheLimit: the tree depth comes from the list's
// genesis-fixed maximum, not from how full the list happens to be. Without
// that, the meaning of a root would change as traffic changed.
func TestMerkleRootDependsOnTheLimit(t *testing.T) {
	chunks := []crypto.Hash{{1}, {2}, {3}}
	if ssz.Merkleize(chunks, 4) == ssz.Merkleize(chunks, 8) {
		t.Fatal("the merkle root ignores the list limit")
	}
}

// TestMixInLengthSeparatesShortLists: a short list must never merkleise to the
// same root as a longer one padded with zeros.
func TestMixInLengthSeparatesShortLists(t *testing.T) {
	short := []crypto.Hash{{1}}
	long := []crypto.Hash{{1}, {}}
	if ssz.ListRoot(short, 8) == ssz.ListRoot(long, 8) {
		t.Fatal("zero padding is indistinguishable from a zero element")
	}
}

// TestEmptyListRoot is defined, stable, and distinct from a single zero chunk.
func TestEmptyListRoot(t *testing.T) {
	empty := ssz.ListRoot(nil, 16)
	if empty != ssz.ListRoot([]crypto.Hash{}, 16) {
		t.Fatal("nil and empty lists differ")
	}
	if empty == ssz.ListRoot([]crypto.Hash{{}}, 16) {
		t.Fatal("an empty list and a one-zero-element list share a root")
	}
}

// TestRootIsOrderSensitive: reordering the leaves must change the root, or the
// certificate root would not commit to the order a proposer chose.
func TestRootIsOrderSensitive(t *testing.T) {
	a := []crypto.Hash{{1}, {2}, {3}}
	b := []crypto.Hash{{3}, {2}, {1}}
	if ssz.ListRoot(a, 16) == ssz.ListRoot(b, 16) {
		t.Fatal("the list root ignores order")
	}
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// sink keeps a decoded list live so the compiler cannot elide the call whose
// allocations the tests below are counting.
var sink [][]byte

// maximalOffsetPayload is the offset-table amplification shape: every
// four-byte word of the payload is an offset pointing at the end of the
// payload, so the first word claims the largest element count the payload's
// own length can support and every element is empty. It is well-formed under
// the codec's rules.
func maximalOffsetPayload(size int) []byte {
	data := make([]byte, size)
	for i := 0; i < size; i += ssz.BytesPerLengthOffset {
		binary.LittleEndian.PutUint32(data[i:], uint32(size))
	}
	return data
}

// TestClaimedElementCountBuysOneTableNotTwo: the element count is derived
// from a wire-supplied offset, and the decoder must charge that claim exactly
// the one table it hands back — the slice headers of the elements it returns
// — and nothing else. Sizing a second, private []int of offsets from the same
// count was half the amplification such a payload bought, and it is an
// allocation the caller never sees, so counting allocations rather than bytes
// pins the property exactly and cannot fire for a benign reason.
func TestClaimedElementCountBuysOneTableNotTwo(t *testing.T) {
	data := maximalOffsetPayload(1 << 12)
	n := len(data) / ssz.BytesPerLengthOffset

	elems, err := ssz.DecodeVariableList(data, n, 0)
	if err != nil {
		t.Fatalf("a payload of maximal offsets is well-formed: %v", err)
	}
	if len(elems) != n {
		t.Fatalf("decoded %d elements, want %d", len(elems), n)
	}

	got := testing.AllocsPerRun(4, func() {
		out, err := ssz.DecodeVariableList(data, n, 0)
		if err != nil {
			t.Fatal(err)
		}
		sink = out
	})
	// The decoder as it stood before the count was bounded scored 2 here: the
	// returned [][]byte and a private []int of the same length. Both were
	// sized from the claim.
	if got != 1 {
		t.Fatalf("decoding a payload claiming %d elements made %v allocations, want exactly 1 "+
			"(the returned slice headers and nothing else)", n, got)
	}
}

// TestARejectedOffsetTableBuysNoPerElementMemory: a claim that does not
// survive validation must not have sized anything at all. The count is checked
// in a pass that allocates nothing, so a frame whose offsets are rejected
// costs the receiver no per-element memory — this is what makes the claim
// unable to buy work before it is shown to be true.
func TestARejectedOffsetTableBuysNoPerElementMemory(t *testing.T) {
	data := maximalOffsetPayload(1 << 12)
	n := len(data) / ssz.BytesPerLengthOffset
	// Move the last offset backwards: the claimed count still stands, the
	// table no longer validates.
	binary.LittleEndian.PutUint32(data[len(data)-ssz.BytesPerLengthOffset:], 0)

	if _, err := ssz.DecodeVariableList(data, n, 0); !errors.Is(err, ssz.ErrOffset) {
		t.Fatalf("a backwards offset must be ErrOffset, got %v", err)
	}
	got := testing.AllocsPerRun(4, func() {
		out, err := ssz.DecodeVariableList(data, n, 0)
		if err == nil {
			t.Fatal("expected rejection")
		}
		sink = out
	})
	if got != 0 {
		t.Fatalf("a rejected offset table claiming %d elements made %v allocations, want 0", n, got)
	}
}

// decodeVariableListPreFix is the decoder exactly as it stood before the
// element-count bound was added. It is here so that the accept/reject set
// can be compared against it directly: this is core, so any input on which
// the two disagree is a consensus fork, and a source-level argument that the
// validation is "the same rule" is not evidence. Do not change it to match
// the current code.
//
// The one liberty taken is arithmetic width: the offsets are held in int64
// rather than int. Zycord has only ever shipped 64-bit builds, so the
// accept/reject set this oracle exists to pin is the one those builds
// implement, and on a 64-bit build int64 and int agree on every value a uint32
// can hold — the two forms are the same function there. Written in int, the
// oracle would instead narrow 0xFFFFFFFC to -4 on a 32-bit build and panic in
// makeslice, i.e. it would reproduce the defect under test instead of
// being able to judge it.
//
// This comment demands evidence rather than a source-level argument, so the
// widening was measured rather than reasoned about: both forms were held side
// by side and run over 306,030 inputs (offset alphabet straddling every signed
// and unsigned boundary x payload lengths x limits), on amd64 and on 386. On
// amd64 they agree on every input, digest for digest — there the edit is
// literally the same function, so nothing that has ever shipped is affected.
// On 386 they differ on 48,480 inputs and every one of those is the int form
// panicking where the int64 form returns ErrOffset; there is no input on which
// both reach a verdict and the verdicts differ. The widening therefore moves no
// accept/reject decision in the oracle's favour: it can still fail the decoder,
// it has only stopped crashing before it can judge one.
func decodeVariableListPreFix(data []byte, limit int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < ssz.BytesPerLengthOffset {
		return nil, ssz.ErrShort
	}
	first := int64(binary.LittleEndian.Uint32(data))
	if first%ssz.BytesPerLengthOffset != 0 || first == 0 || first > int64(len(data)) {
		return nil, ssz.ErrOffset
	}
	n := int(first / ssz.BytesPerLengthOffset)
	if n > limit {
		return nil, ssz.ErrLimit
	}
	offsets := make([]int64, n)
	for i := 0; i < n; i++ {
		offsets[i] = int64(binary.LittleEndian.Uint32(data[i*ssz.BytesPerLengthOffset:]))
		if offsets[i] > int64(len(data)) {
			return nil, ssz.ErrOffset
		}
		if i > 0 && offsets[i] < offsets[i-1] {
			return nil, ssz.ErrOffset
		}
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		end := int64(len(data))
		if i+1 < n {
			end = offsets[i+1]
		}
		out[i] = data[offsets[i]:end]
	}
	return out, nil
}

// TestAWireOffsetIsRefusedOnItsUnsignedValueNotItsNarrowedOne: an offset is
// four peer-supplied bytes, and the width of int is a property of the build,
// not of the wire. Where int is 32 bits, int(uint32(0xFFFFFFFC)) is -4 and
// satisfies every signed form of the guard — Go's % keeps the sign, so -4%4 is
// 0; -4 is not 0; -4 is not greater than any length — after which the element
// count is negative and make panics rather than the decoder refusing.
//
// Each of the three terms of the first-offset guard is separated here by an
// input that only that term can refuse, so the test cannot pass because some
// other term happened to fire: 0xFFFFFFFC and 0x80000000 are whole multiples of
// BytesPerLengthOffset and non-zero, so only the length bound refuses them, and
// they are the two values whose narrowed forms are -4 and the most negative
// int32; 0xFFFFFFFF and 0x80000001 are refused by the alignment term with the
// high bit still set; and the table cases put a high-bit offset at index 1,
// where the monotonicity term is the one that must hold. A payload of exactly
// 0x80000000 or 0xFFFFFFFC bytes cannot exist, so the correct verdict for every
// case is ErrOffset on every platform.
func TestAWireOffsetIsRefusedOnItsUnsignedValueNotItsNarrowedOne(t *testing.T) {
	// Above any element count these payloads can claim, so ErrLimit can never
	// be the reason a case is refused; minElemSize is 0 for the same reason.
	const limit = 1 << 30

	for _, off := range []uint32{0x80000000, 0x80000001, 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFF80} {
		data := make([]byte, 64)
		binary.LittleEndian.PutUint32(data, off)
		out, err := ssz.DecodeVariableList(data, limit, 0)
		if !errors.Is(err, ssz.ErrOffset) {
			t.Fatalf("first offset %#08x: got (%d elements, %v), want ErrOffset", off, len(out), err)
		}
		if out != nil {
			t.Fatalf("first offset %#08x: refused input returned %d elements", off, len(out))
		}

		// The same value one slot in: the first offset is well-formed and
		// claims two elements, so the offset table is walked and the high-bit
		// value is judged by the monotonicity and bound terms instead.
		table := make([]byte, 64)
		binary.LittleEndian.PutUint32(table, 2*ssz.BytesPerLengthOffset)
		binary.LittleEndian.PutUint32(table[ssz.BytesPerLengthOffset:], off)
		out, err = ssz.DecodeVariableList(table, limit, 0)
		if !errors.Is(err, ssz.ErrOffset) {
			t.Fatalf("second offset %#08x: got (%d elements, %v), want ErrOffset", off, len(out), err)
		}
		if out != nil {
			t.Fatalf("second offset %#08x: refused input returned %d elements", off, len(out))
		}

		// Decode reads offsets from the same wire with the same widths. Both
		// variable positions of a two-variable container are exercised, because
		// the first offset is judged by equality with the fixed length and the
		// rest by monotonicity — different terms, different narrowing exposure.
		layout := []int{4, ssz.Variable, ssz.Variable}
		for pos := 0; pos < 2; pos++ {
			enc := ssz.Encode(layout, [][]byte{ssz.Uint32(7), []byte("ab"), []byte("cd")})
			binary.LittleEndian.PutUint32(enc[4+pos*ssz.BytesPerLengthOffset:], off)
			fields, err := ssz.Decode(layout, enc)
			if !errors.Is(err, ssz.ErrOffset) {
				t.Fatalf("Decode with offset %#08x at variable %d: got (%v, %v), want ErrOffset", off, pos, fields, err)
			}
		}
	}
}

// TestDecodeVariableListDecidesExactlyWhatItDecidedBeforeTheFix: the
// element-count fix removed a table, not a rule. Every input — including the
// adversarial edge cases the fix moves through differently (zero elements, a
// first offset of 0, a first offset that is not a whole number of words,
// offsets equal to and past len(data), non-monotonic offsets, trailing bytes
// past the last offset, an offset table overlapping the payload) — must
// produce the same verdict, the same error value and the same elements as the
// pre-fix decoder.
func TestDecodeVariableListDecidesExactlyWhatItDecidedBeforeTheFix(t *testing.T) {
	check := func(data []byte, limit int) {
		t.Helper()
		wantOut, wantErr := decodeVariableListPreFix(data, limit)
		gotOut, gotErr := ssz.DecodeVariableList(data, limit, 0)
		if !errors.Is(gotErr, wantErr) || !errors.Is(wantErr, gotErr) {
			t.Fatalf("data=%x limit=%d: error %v, pre-fix said %v", data, limit, gotErr, wantErr)
		}
		if len(gotOut) != len(wantOut) {
			t.Fatalf("data=%x limit=%d: %d elements, pre-fix said %d", data, limit, len(gotOut), len(wantOut))
		}
		for i := range wantOut {
			if !bytes.Equal(gotOut[i], wantOut[i]) {
				t.Fatalf("data=%x limit=%d: element %d is %x, pre-fix said %x",
					data, limit, i, gotOut[i], wantOut[i])
			}
		}
	}

	// Word-level exhaustive sweep. The words cover every boundary the rule
	// names: 0, a non-multiple of four, each in-range offset, exactly
	// len(data), one past it, and the 32-bit maximum.
	words := []uint32{0, 1, 3, 4, 8, 12, 16, 20, 0xFFFFFFFF}
	var sweep func(prefix []uint32, depth int)
	sweep = func(prefix []uint32, depth int) {
		if len(prefix) > 0 {
			for _, tail := range [][]byte{nil, {0xAA}, {0xAA, 0xBB, 0xCC}, make([]byte, 8)} {
				data := make([]byte, 0, len(prefix)*4+len(tail))
				for _, w := range prefix {
					data = binary.LittleEndian.AppendUint32(data, w)
				}
				data = append(data, tail...)
				for _, limit := range []int{0, 1, 2, 3, 4, 1 << 20} {
					check(data, limit)
				}
			}
		}
		if depth == 0 {
			return
		}
		for _, w := range words {
			next := make([]uint32, len(prefix), len(prefix)+1)
			copy(next, prefix)
			sweep(append(next, w), depth-1)
		}
	}
	sweep(nil, 3)

	// Degenerate lengths the sweep cannot express.
	for _, data := range [][]byte{nil, {}, {0}, {0, 0}, {0, 0, 0}, {4, 0, 0}} {
		check(data, 1<<20)
	}

	// Random fuzz over the same shape, biased towards words that are plausible
	// offsets so that the accepting side of the boundary is exercised too.
	rng := rand.New(rand.NewSource(208))
	for iter := 0; iter < 200000; iter++ {
		size := rng.Intn(33)
		data := make([]byte, size)
		for i := 0; i+4 <= size; i += 4 {
			var w uint32
			switch rng.Intn(3) {
			case 0:
				w = uint32(rng.Intn(size + 2))
			case 1:
				w = uint32(rng.Intn(size+2)) &^ 3
			default:
				w = rng.Uint32()
			}
			binary.LittleEndian.PutUint32(data[i:], w)
		}
		for i := (size / 4) * 4; i < size; i++ {
			data[i] = byte(rng.Intn(256))
		}
		check(data, []int{0, 1, 2, 4, 8, 1 << 20}[rng.Intn(6)])
	}
}

// TestTheElementFloorRefusesOnlyWhatTheElementDecoderWouldHaveRefused is the
// consensus-safety proof for the bound minElemSize adds. minElemSize makes the
// decoder refuse a claimed element count its payload could not carry, which is
// a *new* refusal at this layer — and this is core, so a refusal that is not
// already implied elsewhere would be a fork. It is implied: whenever the bound
// refuses input the unbounded decoder accepts, the unbounded decoder's own
// output contains an element shorter than the floor, and that element's
// decoder (ssz.Decode against the layout the floor came from) refuses it with
// ErrShort. The block is refused either way; only the error value differs, and
// no non-test caller distinguishes ssz's sentinels.
func TestTheElementFloorRefusesOnlyWhatTheElementDecoderWouldHaveRefused(t *testing.T) {
	rng := rand.New(rand.NewSource(235))
	refusals := 0
	for iter := 0; iter < 200000; iter++ {
		size := rng.Intn(65)
		data := make([]byte, size)
		for i := 0; i+4 <= size; i += 4 {
			if rng.Intn(2) == 0 {
				binary.LittleEndian.PutUint32(data[i:], uint32(rng.Intn(size+2))&^3)
			} else {
				binary.LittleEndian.PutUint32(data[i:], uint32(rng.Intn(size+2)))
			}
		}
		m := 1 + rng.Intn(12)

		unbounded, unboundedErr := ssz.DecodeVariableList(data, 1<<20, 0)
		bounded, boundedErr := ssz.DecodeVariableList(data, 1<<20, m)

		if unboundedErr != nil {
			// The floor may only refuse more, never less.
			if boundedErr == nil {
				t.Fatalf("data=%x m=%d: the floor accepted what the unbounded rule refused (%v)", data, m, unboundedErr)
			}
			continue
		}
		if boundedErr == nil {
			if len(bounded) != len(unbounded) {
				t.Fatalf("data=%x m=%d: accepted with %d elements, unbounded said %d",
					data, m, len(bounded), len(unbounded))
			}
			for i := range unbounded {
				if !bytes.Equal(bounded[i], unbounded[i]) {
					t.Fatalf("data=%x m=%d: element %d differs", data, m, i)
				}
			}
			continue
		}
		// Refused by the floor and not by the rule it tightens: some element
		// the old rule would have handed on is below the floor, so the
		// element's own decoder refuses the container regardless.
		refusals++
		if !errors.Is(boundedErr, ssz.ErrOffset) {
			t.Fatalf("data=%x m=%d: floor refusal must be ErrOffset, got %v", data, m, boundedErr)
		}
		short := false
		for _, e := range unbounded {
			if len(e) < m {
				short = true
				break
			}
		}
		if !short {
			t.Fatalf("data=%x m=%d: the floor refused a list whose every element meets the floor — "+
				"this input decodes today and would stop decoding: a fork", data, m)
		}
	}
	if refusals == 0 {
		t.Fatal("the floor never fired: this test proved nothing")
	}
}

// TestTheElementFloorBindsWhereTheStructuralLimitCannot: CertListCapacity is
// three orders of magnitude above what a message frame can carry, so it never
// refuses anything a peer can actually send. The floor does, and it does so
// before sizing any per-element table — which is the difference between
// bounding the amplification and removing it. The capacity is read from the
// shipped params, not written out here, so that a change to it cannot leave
// this test quietly asserting against a number the network no longer uses.
func TestTheElementFloorBindsWhereTheStructuralLimitCannot(t *testing.T) {
	capacity := spec.Devnet().CertListCapacity
	data := maximalOffsetPayload(1 << 12)
	n := len(data) / ssz.BytesPerLengthOffset
	if n > capacity {
		t.Fatalf("test payload claims %d elements, above the capacity %d it is meant to slip past", n, capacity)
	}

	if _, err := ssz.DecodeVariableList(data, capacity, 0); err != nil {
		t.Fatalf("without a floor the structural capacity accepts the maximal claim: %v", err)
	}
	if _, err := ssz.DecodeVariableList(data, capacity, 60); !errors.Is(err, ssz.ErrOffset) {
		t.Fatalf("a payload claiming %d elements of at least 60 bytes in %d bytes must be refused, got %v",
			n, len(data), err)
	}
	got := testing.AllocsPerRun(4, func() {
		out, err := ssz.DecodeVariableList(data, capacity, 60)
		if err == nil {
			t.Fatal("expected refusal")
		}
		sink = out
	})
	if got != 0 {
		t.Fatalf("refusing an over-claimed list made %v allocations, want 0", got)
	}
}

// TestTheElementFloorIsExactAtTheRealCertificateSize: the floor is a boundary,
// so it is worth exercising at the value the network actually uses rather than
// only at a convenient small one. A list of three certificate-sized elements
// fits exactly and must decode; one byte short of that, the same claim must be
// refused. CertMinSize is 328 (core/types), and the fixed section of a header
// is 228 — both are re-derived here from the payload arithmetic rather than
// imported, because core/types imports this package.
func TestTheElementFloorIsExactAtTheRealCertificateSize(t *testing.T) {
	for _, m := range []int{328, 228} {
		const n = 3
		head := n * ssz.BytesPerLengthOffset

		exact := make([]byte, head+n*m)
		for i := 0; i < n; i++ {
			binary.LittleEndian.PutUint32(exact[i*ssz.BytesPerLengthOffset:], uint32(head+i*m))
		}
		out, err := ssz.DecodeVariableList(exact, 1<<20, m)
		if err != nil {
			t.Fatalf("m=%d: %d elements of exactly %d bytes fit in %d bytes and must decode: %v",
				m, n, m, len(exact), err)
		}
		if len(out) != n {
			t.Fatalf("m=%d: decoded %d elements, want %d", m, len(out), n)
		}
		for i, e := range out {
			if len(e) != m {
				t.Fatalf("m=%d: element %d is %d bytes, want %d", m, i, len(e), m)
			}
		}

		// One byte short: the last element is below the floor, so the same
		// claim of n elements no longer fits its own payload.
		short := exact[:len(exact)-1]
		if _, err := ssz.DecodeVariableList(short, 1<<20, m); !errors.Is(err, ssz.ErrOffset) {
			t.Fatalf("m=%d: %d elements claimed in %d bytes leaves one below the floor and must be "+
				"refused, got %v", m, n, len(short), err)
		}
		// Without the floor the same bytes still decode, which is what makes
		// the refusal above a tightening and not a pre-existing rule.
		if _, err := ssz.DecodeVariableList(short, 1<<20, 0); err != nil {
			t.Fatalf("m=%d: the unbounded rule must still accept the short payload: %v", m, err)
		}
	}
}
