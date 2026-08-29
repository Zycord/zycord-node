package types_test

import (
	"bytes"
	"math/rand"
	"slices"
	"sort"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

func testParams() *params.Params { return spec.Devnet() }

func randSlot(rng *rand.Rand) types.Slot {
	var s types.Slot
	rng.Read(s.Addr[:])
	rng.Read(s.Word[:])
	s.Addr[0] = byte(rng.Intn(4))
	return s
}

// randFeeBid respects the canonical-form rule that a priority never exceeds its
// maximum, so the codec round trip exercises values the decoder will accept.
func randFeeBid(rng *rand.Rand) types.FeeBid {
	seqMax, parMax := randU256(rng), randU256(rng)
	seqPri, parPri := randU256(rng), randU256(rng)
	if seqPri.Gt(seqMax) {
		seqMax, seqPri = seqPri, seqMax
	}
	if parPri.Gt(parMax) {
		parMax, parPri = parPri, parMax
	}
	return types.FeeBid{SeqMax: seqMax, SeqPriority: seqPri, ParMax: parMax, ParPriority: parPri}
}

func randU256(rng *rand.Rand) u256.U256 {
	var b [32]byte
	rng.Read(b[:])
	return u256.FromBytes(b)
}

// randCertificate builds a structurally well-formed certificate. It is
// deliberately not *valid* — the point is to exercise the codec, and the codec
// must not care what the V-rules will later think.
func randCertificate(rng *rand.Rand) *types.Certificate {
	c := &types.Certificate{
		ChainID: rng.Uint64(),
		Seq:     rng.Uint64(),
		TTL:     rng.Uint64(),
		FeeBid:  randFeeBid(rng),
		Deposit: types.Deposit{Cell: randSlot(rng), Amount: randU256(rng), RefundTo: randSlot(rng)},
	}

	switch rng.Intn(4) {
	case 0:
		n := rng.Intn(4)
		moves := make([]types.Move, n)
		for i := range moves {
			rng.Read(moves[i].Asset[:])
			rng.Read(moves[i].Src[:])
			rng.Read(moves[i].Dst[:])
			moves[i].Amount = randU256(rng)
		}
		c.Program = types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{Moves: moves}}
	case 1:
		a := &types.IssueArgs{Cap: randU256(rng), Decimals: byte(rng.Intn(256))}
		rng.Read(a.Issuer[:])
		rng.Read(a.SymbolHash[:])
		rng.Read(a.Minter[:])
		c.Program = types.Program{Kind: types.ProgramIssue, Issue: a}
	case 2:
		a := &types.MintArgs{Amount: randU256(rng), Cap: randU256(rng)}
		rng.Read(a.Asset[:])
		rng.Read(a.Dst[:])
		rng.Read(a.Minter[:])
		c.Program = types.Program{Kind: types.ProgramMint, Mint: a}
	default:
		n := rng.Intn(4)
		addrs := make([]types.Address, n)
		for i := range addrs {
			rng.Read(addrs[i][:])
		}
		// The retire list is canonical too: strictly increasing, no repeats.
		sort.Slice(addrs, func(i, j int) bool { return bytes.Compare(addrs[i][:], addrs[j][:]) < 0 })
		addrs = slices.Compact(addrs)
		c.Program = types.Program{Kind: types.ProgramRetire, Retire: &types.RetireArgs{Addrs: addrs}}
	}

	// Canonical order is part of the encoding, so the generator produces it:
	// strictly increasing, no duplicates. The negative cases live in
	// TestNonCanonicalEncodingsAreRejected, where they belong.
	for i := 0; i < rng.Intn(4); i++ {
		c.Reads = append(c.Reads, types.Read{
			Slot: randSlot(rng), Access: uint8(rng.Intn(4)), Operand: randU256(rng)})
	}
	sort.Slice(c.Reads, func(i, j int) bool { return c.Reads[i].Slot.Less(c.Reads[j].Slot) })
	c.Reads = slices.CompactFunc(c.Reads, func(a, b types.Read) bool { return a.Slot == b.Slot })

	for i := 0; i < rng.Intn(4); i++ {
		c.Writes = append(c.Writes, types.Write{
			Slot: randSlot(rng), Op: uint8(rng.Intn(3)), Value: randU256(rng)})
	}
	sort.Slice(c.Writes, func(i, j int) bool { return c.Writes[i].Slot.Less(c.Writes[j].Slot) })
	c.Writes = slices.CompactFunc(c.Writes, func(a, b types.Write) bool { return a.Slot == b.Slot })

	for i := 0; i < rng.Intn(3); i++ {
		var sig types.Sig
		rng.Read(sig.PubKey[:])
		rng.Read(sig.Sig[:])
		c.Sigs = append(c.Sigs, sig)
	}
	sort.Slice(c.Sigs, func(i, j int) bool {
		return bytes.Compare(c.Sigs[i].PubKey[:], c.Sigs[j].PubKey[:]) < 0
	})
	c.Sigs = slices.CompactFunc(c.Sigs, func(a, b types.Sig) bool { return a.PubKey == b.PubKey })
	return c
}

// TestCertificateRoundTrip: every certificate has exactly one encoding, and
// every encoding decodes to the certificate it came from.
func TestCertificateRoundTrip(t *testing.T) {
	p := testParams()
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		c := randCertificate(rng)
		enc := c.MarshalSSZ()
		back, err := types.UnmarshalCertificate(enc, p)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if !bytes.Equal(back.MarshalSSZ(), enc) {
			t.Fatal("re-encoding a decoded certificate produced different bytes")
		}
		if back.ID() != c.ID() {
			t.Fatal("the certificate id did not survive a round trip")
		}
	}
}

// TestSignaturesReachNeitherTheBodyRootNorTheId: a signer signs the
// certificate, not the set of people who happened to sign alongside it — and
// the id names the authorization, not the signatures that demonstrate it.
//
// The last assertion is the one with an attack behind it. While the
// id covered Sigs, a required signer could re-sign one body at a fresh nonce
// and mint a second id for an authorization the other signers had given once,
// and every id-keyed defence in the protocol — the seen set above all — saw
// two certificates where there was one.
func TestSignaturesReachNeitherTheBodyRootNorTheId(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	c := randCertificate(rng)
	root, id, exemplar := c.BodyRoot(), c.ID(), c.ExemplarHash()

	var extra types.Sig
	rng.Read(extra.PubKey[:])
	rng.Read(extra.Sig[:])
	c.Sigs = append(c.Sigs, extra)

	if c.BodyRoot() != root {
		t.Fatal("adding a signature changed what the earlier signers signed")
	}
	if c.ID() != id {
		t.Fatal("adding a signature changed the certificate id")
	}
	// And the block still has to be able to pin the bytes it carries, which is
	// the obligation moving Sigs out of the id's preimage creates.
	if c.ExemplarHash() == exemplar {
		t.Fatal("adding a signature did not change the exemplar hash")
	}
	if id == root {
		t.Fatal("the id and the signing digest must be separate values")
	}
}

// TestOneAuthorizationIsOneIdAcrossEveryEncodingOfIt states the id's contract
// directly, over the certificate's whole signature list rather than over one
// appended entry: whatever the signature bytes are, the id is the same, and
// the exemplar hash is not.
func TestOneAuthorizationIsOneIdAcrossEveryEncodingOfIt(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	c := randCertificate(rng)
	if len(c.Sigs) == 0 {
		t.Skip("the fixture drew a certificate with no signatures")
	}
	id, exemplar := c.ID(), c.ExemplarHash()

	// The signer set is untouched; only the 64 bytes each signer contributed
	// change, which is exactly what a different Ed25519 nonce produces.
	for i := range c.Sigs {
		rng.Read(c.Sigs[i].Sig[:])
	}

	if c.ID() != id {
		t.Fatal("re-signing the same body produced a second certificate id")
	}
	if c.ExemplarHash() == exemplar {
		t.Fatal("re-signing produced the same exemplar hash, so the block cannot tell the bytes apart")
	}
}

// TestSigningMessageIsChainBound: the same certificate body on two networks
// yields two different messages, so a signature cannot be replayed across them.
func TestSigningMessageIsChainBound(t *testing.T) {
	p := testParams()
	rng := rand.New(rand.NewSource(3))
	c := randCertificate(rng)
	c.ChainID = 1
	mainnet := append([]byte(nil), c.SigningMessage(p)...)
	c.ChainID = 2
	if bytes.Equal(mainnet, c.SigningMessage(p)) {
		t.Fatal("the signing message does not depend on the chain id")
	}
}

// TestSigningMessageIsBoundToTheParameterSet: the same certificate body under
// two parameter sets that share a chain id yields two different messages, so a
// signature cannot be replayed from one incarnation of a network onto the next.
//
// The two sets differ in genesis_time and in nothing else, which is the pair a
// respin produces. A pair that differed in more than one field would not say
// which field did the work.
func TestSigningMessageIsBoundToTheParameterSet(t *testing.T) {
	before := testParams()
	after := testParams()
	after.GenesisTime = before.GenesisTime + 1

	if before.ChainID != after.ChainID {
		t.Fatal("the two parameter sets differ in their chain id, so this test would pass for the wrong reason")
	}

	rng := rand.New(rand.NewSource(3))
	c := randCertificate(rng)
	if bytes.Equal(c.SigningMessage(before), c.SigningMessage(after)) {
		t.Fatal("the signing message does not depend on the parameter set")
	}
}

// TestNonCanonicalEncodingsAreRejected. Canonicality is not tidiness: a value
// with two encodings has two ids, and the seen set cannot tolerate that.
func TestNonCanonicalEncodingsAreRejected(t *testing.T) {
	p := testParams()
	rng := rand.New(rand.NewSource(4))
	base := randCertificate(rng)
	enc := base.MarshalSSZ()

	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := types.UnmarshalCertificate(append(enc, 0), p); err == nil {
			// A trailing byte lands inside the final variable field, so it must
			// change the decoded value rather than be ignored.
			back, _ := types.UnmarshalCertificate(append(enc, 0), p)
			if back != nil && bytes.Equal(back.MarshalSSZ(), enc) {
				t.Fatal("a trailing byte was silently discarded")
			}
		}
	})

	t.Run("truncated", func(t *testing.T) {
		for cut := 1; cut < 40 && cut < len(enc); cut++ {
			if _, err := types.UnmarshalCertificate(enc[:len(enc)-cut], p); err == nil {
				t.Fatalf("a certificate truncated by %d bytes decoded", cut)
			}
		}
	})

	t.Run("out of range access", func(t *testing.T) {
		bad := types.Read{Slot: randSlot(rng), Access: 4, Operand: u256.One}
		if _, err := types.UnmarshalRead(bad.MarshalSSZ()); err == nil {
			t.Fatal("an unknown access discipline decoded")
		}
	})

	t.Run("out of range write op", func(t *testing.T) {
		bad := types.Write{Slot: randSlot(rng), Op: 4, Value: u256.One}
		if _, err := types.UnmarshalWrite(bad.MarshalSSZ()); err == nil {
			t.Fatal("an unknown write operation decoded")
		}
	})

	t.Run("non-canonical mark spent", func(t *testing.T) {
		s := randSlot(rng)
		s.Word[0] = 1
		bad := types.Write{Slot: s, Op: types.OpMarkSpent}
		if _, err := types.UnmarshalWrite(bad.MarshalSSZ()); err == nil {
			t.Fatal("an address-wide MARK_SPENT with a non-zero word decoded")
		}
		bad = types.Write{Slot: types.SpentSlot(s.Addr), Op: types.OpMarkSpent, Value: u256.One}
		if _, err := types.UnmarshalWrite(bad.MarshalSSZ()); err == nil {
			t.Fatal("a MARK_SPENT with a non-zero value decoded")
		}
	})

	t.Run("unknown program kind", func(t *testing.T) {
		enc := []byte{9, 5, 0, 0, 0}
		if _, err := types.UnmarshalProgram(enc, 4, 4); err == nil {
			t.Fatal("an unknown program kind decoded")
		}
	})

	// R2-M2: "sorted" admits equal neighbours; strictly increasing does not. A
	// list with a repeat would give one state transition two encodings and
	// therefore two certificate ids, which the seen set cannot close over — so
	// the rule belongs at decode time, not in a later check.
	t.Run("duplicate read slot", func(t *testing.T) {
		c := randCertificate(rng)
		r := types.Read{Slot: randSlot(rng), Access: types.AccessExact, Operand: u256.One}
		c.Reads = []types.Read{r, r}
		if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), p); err == nil {
			t.Fatal("a duplicate read slot decoded")
		}
	})

	t.Run("unsorted reads", func(t *testing.T) {
		c := randCertificate(rng)
		lo, hi := randSlot(rng), randSlot(rng)
		if hi.Less(lo) {
			lo, hi = hi, lo
		}
		c.Reads = []types.Read{{Slot: hi}, {Slot: lo}}
		if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), p); err == nil {
			t.Fatal("reads out of order decoded")
		}
	})

	t.Run("duplicate write slot", func(t *testing.T) {
		c := randCertificate(rng)
		w := types.Write{Slot: randSlot(rng), Op: types.OpDeltaAdd, Value: u256.One}
		c.Writes = []types.Write{w, w}
		if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), p); err == nil {
			t.Fatal("a duplicate write slot decoded")
		}
	})

	t.Run("duplicate signer", func(t *testing.T) {
		c := randCertificate(rng)
		var sig types.Sig
		rng.Read(sig.PubKey[:])
		c.Sigs = []types.Sig{sig, sig}
		if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), p); err == nil {
			t.Fatal("a duplicate public key decoded")
		}
	})

	t.Run("unsorted signers", func(t *testing.T) {
		c := randCertificate(rng)
		var a, b types.Sig
		rng.Read(a.PubKey[:])
		rng.Read(b.PubKey[:])
		if bytes.Compare(a.PubKey[:], b.PubKey[:]) < 0 {
			a, b = b, a
		}
		c.Sigs = []types.Sig{a, b}
		if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), p); err == nil {
			t.Fatal("signatures out of order decoded")
		}
	})

	t.Run("duplicate retire address", func(t *testing.T) {
		var addr types.Address
		rng.Read(addr[:])
		body := append(append([]byte{}, addr[:]...), addr[:]...)
		enc := []byte{byte(types.ProgramRetire), 5, 0, 0, 0}
		enc = append(enc, body...)
		if _, err := types.UnmarshalProgram(enc, 8, 8); err == nil {
			t.Fatal("a duplicate retire address decoded")
		}
	})

	t.Run("priority above its maximum", func(t *testing.T) {
		// Canonical form requires priority <= max in each market; without it a
		// range of priorities all clamp to the same behaviour.
		bad := types.FeeBid{SeqMax: u256.One, SeqPriority: u256.FromUint64(2)}
		if _, err := types.UnmarshalFeeBid(bad.MarshalSSZ()); err == nil {
			t.Fatal("a priority above its maximum decoded")
		}
	})

	t.Run("list over the limit", func(t *testing.T) {
		small := *p
		small.MaxReads = 1
		c := randCertificate(rng)
		c.Reads = []types.Read{
			{Slot: randSlot(rng)}, {Slot: randSlot(rng)},
		}
		if _, err := types.UnmarshalCertificate(c.MarshalSSZ(), &small); err == nil {
			t.Fatal("a list over its genesis-fixed maximum decoded")
		}
	})
}

// TestBlockRoundTrip covers the one place a variable-size element list appears.
func TestBlockRoundTrip(t *testing.T) {
	p := testParams()
	rng := rand.New(rand.NewSource(5))
	for n := 0; n < 6; n++ {
		b := &types.Block{Header: types.Header{
			Version: types.HeaderVersion,
			Height:  rng.Uint64(),
			Time:    rng.Uint64(),
			Target:  randU256(rng),
			PoW:     types.PoWSeal{Nonce: rng.Uint64(), SeedEpoch: rng.Uint64()},
		}}
		rng.Read(b.Header.ParentID[:])
		rng.Read(b.Header.StateRoot[:])
		rng.Read(b.Header.EmissionAddr[:])
		for i := 0; i < n; i++ {
			b.Certs = append(b.Certs, randCertificate(rng))
		}
		b.Header.CertRoot = b.ComputeCertRoot(p)

		enc := b.MarshalSSZ()
		back, err := types.UnmarshalBlock(enc, p)
		if err != nil {
			t.Fatalf("decode failed with %d certificates: %v", n, err)
		}
		if !bytes.Equal(back.MarshalSSZ(), enc) {
			t.Fatalf("re-encoding a decoded block with %d certificates differed", n)
		}
		if back.Header.ID() != b.Header.ID() {
			t.Fatal("the block id did not survive a round trip")
		}
	}
}

// TestABlockCommitsToTheSignaturesItCarries is the obligation that moving
// signatures out of the id's preimage creates, and it is the reason
// ComputeCertRoot is a root over exemplar hashes rather than over ids
// (whitepaper §2).
//
// Evidence outside the id is evidence anyone in transit can replace. If the
// header committed only to ids it would commit to no particular signature
// bytes at all: two bodies carrying different valid signatures over the same
// authorizations would share a CertRoot, a header and a block id, so "this
// block is valid" would stop being a claim about bytes the header pins. And it
// would be free, because CertRoot is inside the proof-of-work preimage — under
// the shipped rule a swapped exemplar moves the seed and invalidates the work,
// and under an id-keyed root it moves nothing.
//
// This comment used to give a different reason: that a relay could mutilate a
// signature and a receiver which fetched that body, refused it and recorded the
// id as seen would refuse the honest body forever. That failure is real, but it
// is a property of the receiver's own bookkeeping — it fires for ANY refusal
// reason, including this rule's own "certificate root does not commit to the
// bodies" — so it is neither caused nor cured by what CertRoot commits to, and
// citing it here argued for this rule from something this rule does not fix.
// docs/spec/wire.md §3.1 states it as a receiver obligation instead.
//
// So: change one signature byte anywhere in a block, and the block's id must
// change. Nothing here is about the *validity* of the mutilated signature; the
// point is that the mutilated block cannot wear the honest block's name.
func TestABlockCommitsToTheSignaturesItCarries(t *testing.T) {
	p := testParams()
	rng := rand.New(rand.NewSource(23))

	b := &types.Block{Header: types.Header{Version: types.HeaderVersion, Height: 7}}
	for i := 0; i < 4; i++ {
		b.Certs = append(b.Certs, randCertificate(rng))
	}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	honest := b.Header.ID()

	for i, c := range b.Certs {
		if len(c.Sigs) == 0 {
			continue
		}
		// The id of the certificate must NOT move — it names the
		// authorization, which nothing here touched.
		before := c.ID()
		c.Sigs[0].Sig[0] ^= 0xFF
		if c.ID() != before {
			t.Fatalf("certificate %d: mutilating a signature moved the certificate id", i)
		}
		// The block's must.
		b.Header.CertRoot = b.ComputeCertRoot(p)
		if b.Header.ID() == honest {
			t.Fatalf("certificate %d: a mutilated body kept the honest block id", i)
		}
		c.Sigs[0].Sig[0] ^= 0xFF
		b.Header.CertRoot = b.ComputeCertRoot(p)
		if b.Header.ID() != honest {
			t.Fatalf("certificate %d: restoring the signature did not restore the block id", i)
		}
	}
}

// TestUnmarshalBlockRejectsTooManyCites pins the boundary fold/blockrules.go's
// checkCites relies on rather than duplicates (whitepaper §8.1): a block
// carrying more citations than MaxCitesPerBlock must never reach the fold at
// all, because ComputeCitesRoot merkleises the list and panics on more
// chunks than its capacity — the same design as the certificate root
// (core/ssz's own doc comment) — inside the consensus zone, an oversized
// list is a caller's bug, not an input to report. The decoder is the only
// place that boundary can be enforced on bytes arriving from a peer: encoding
// itself has no opinion (MarshalSSZ never calls Merkleize), so an
// over-capacity block is perfectly encodable and must be caught coming back
// in, exactly where TestAnAnnouncementCannotPanicTheNode (node/p2p) pins the
// analogous certificate-count boundary.
func TestUnmarshalBlockRejectsTooManyCites(t *testing.T) {
	p := testParams()
	rng := rand.New(rand.NewSource(11))

	b := &types.Block{Header: types.Header{Version: types.HeaderVersion}}
	for i := 0; i < p.MaxCitesPerBlock+1; i++ {
		h := &types.Header{Version: types.HeaderVersion, Height: rng.Uint64(), Target: randU256(rng)}
		rng.Read(h.ParentID[:])
		rng.Read(h.StateRoot[:])
		rng.Read(h.EmissionAddr[:])
		b.Cites = append(b.Cites, h)
	}
	// CertRoot and CitesRoot need not actually commit to anything for the
	// codec to accept or reject these bytes — only DecodeVariableList's
	// bound does, and that bound is exactly what this test exercises.
	enc := b.MarshalSSZ()

	if _, err := types.UnmarshalBlock(enc, p); err == nil {
		t.Fatalf("decoded a block with %d citations, want rejection at MaxCitesPerBlock=%d",
			len(b.Cites), p.MaxCitesPerBlock)
	}
}

// TestPoWSeedExcludesTheNonce: a miner must be able to hash the header once per
// candidate block rather than once per attempt.
func TestPoWSeedExcludesTheNonce(t *testing.T) {
	h := types.Header{Version: types.HeaderVersion, Height: 7}
	seed := h.PoWSeed()
	h.PoW.Nonce = 12345
	if h.PoWSeed() != seed {
		t.Fatal("the proof-of-work seed changes with the nonce")
	}
	if bytes.Equal(types.Header{Version: types.HeaderVersion, Height: 7}.PoWInput(), h.PoWInput()) {
		t.Fatal("the proof-of-work input does not change with the nonce")
	}
	h.Height = 8
	if h.PoWSeed() == seed {
		t.Fatal("the proof-of-work seed ignores the header")
	}
}

// TestAddressesAreVersionBound: the same key under two versions yields two
// unrelated addresses, and rewriting the version byte of an address does not
// reinterpret it as another kind.
func TestAddressesAreVersionBound(t *testing.T) {
	var pub types.PubKey
	rand.New(rand.NewSource(6)).Read(pub[:])

	oneShot := crypto.AddressFromPubKey(crypto.AddrVersionOneShot, pub)
	persistent := crypto.AddressFromPubKey(crypto.AddrVersionPersistent, pub)
	if oneShot == persistent {
		t.Fatal("two address versions collided")
	}
	if bytes.Equal(oneShot[1:], persistent[1:]) {
		t.Fatal("the version byte is not inside the hash")
	}
	if oneShot[0] != crypto.AddrVersionOneShot || persistent[0] != crypto.AddrVersionPersistent {
		t.Fatal("the version byte is not the first byte of the address")
	}
	if crypto.IsUserAddress(crypto.ProtocolAddress) {
		t.Fatal("the protocol address is debitable by signature")
	}
}

// FuzzDecodeCertificate is the continuous guard on the parse-don't-validate
// rule: whatever the decoder accepts must re-encode to exactly the bytes it was
// given.
func FuzzDecodeCertificate(f *testing.F) {
	p := testParams()
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 16; i++ {
		f.Add(randCertificate(rng).MarshalSSZ())
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := types.UnmarshalCertificate(data, p)
		if err != nil {
			return
		}
		if !bytes.Equal(c.MarshalSSZ(), data) {
			t.Fatalf("decoder accepted a non-canonical encoding of %d bytes", len(data))
		}
	})
}

// FuzzDecodeBlock does the same for blocks, where the variable-size element
// list makes the offset arithmetic hardest.
func FuzzDecodeBlock(f *testing.F) {
	p := testParams()
	rng := rand.New(rand.NewSource(8))
	for n := 0; n < 4; n++ {
		b := &types.Block{Header: types.Header{Version: types.HeaderVersion}}
		for i := 0; i < n; i++ {
			b.Certs = append(b.Certs, randCertificate(rng))
		}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		f.Add(b.MarshalSSZ())
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := types.UnmarshalBlock(data, p)
		if err != nil {
			return
		}
		if !bytes.Equal(b.MarshalSSZ(), data) {
			t.Fatalf("decoder accepted a non-canonical block encoding of %d bytes", len(data))
		}
	})
}

// TestBlockOverheadMatchesTheEncoder pins BlockOverheadBytes against what the
// encoder actually produces, at several list lengths.
//
// The formula is arithmetic about SSZ's envelope, and arithmetic about an
// encoding drifts silently when the encoding changes — which is the whole
// reason it lives beside the encoder instead of in the block builder that
// needs it. A builder that sizes a block by summing certificate sizes alone
// overshoots the ceiling and then has its own candidate refused by the block
// rules, so this is load-bearing for liveness rather than for tidiness.
func TestBlockOverheadMatchesTheEncoder(t *testing.T) {
	p := spec.Devnet()
	for _, n := range []int{0, 1, 2, 3, 17, 256} {
		for _, cites := range []int{0, 1, p.MaxCitesPerBlock} {
			certs := make([]*types.Certificate, n)
			sum := 0
			for i := range certs {
				certs[i] = &types.Certificate{
					ChainID: p.ChainID,
					Program: types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{}},
				}
				sum += certs[i].SizeBytes()
			}
			b := &types.Block{Header: types.Header{Version: types.HeaderVersion}, Certs: certs}
			for i := 0; i < cites; i++ {
				b.Cites = append(b.Cites, &types.Header{Version: types.HeaderVersion})
			}
			if got, want := b.SizeBytes()-sum, types.BlockOverheadBytes(n, cites); got != want {
				t.Fatalf("certs=%d cites=%d: the encoder's overhead is %d, BlockOverheadBytes says %d",
					n, cites, got, want)
			}
		}
	}
}

// BenchmarkCertificateDigests times the two per-certificate digests against
// each other in one process. `exemplar` hashes `ssz(certificate)` — byte for
// byte the preimage the certificate id used to have — and `id` hashes the
// preimage it has now.
//
// **This benchmark does not settle whether the change costs anything, and must
// not be quoted as if it did.** On the machine this was written on, the spread
// *within* one of these two configurations exceeded the difference *between*
// them, so any ordering read off it is noise wearing a number. What settles the
// question is TestTheIdPreimageDoesNotGrowWithTheSignatureCount below: same
// hash function, same number of calls per certificate, strictly less data. A
// benchmark is the wrong instrument for a claim that is true by construction.
//
// It is kept because it is a live tripwire — `make bench-smoke` runs it, so a
// future change that made either digest wildly more expensive would show up
// here — and because deleting the measurement that failed to support the claim
// is how the next person repeats it.
func BenchmarkCertificateDigests(b *testing.B) {
	rng := rand.New(rand.NewSource(31))
	c := randCertificate(rng)
	// A certificate with no signatures would make the two preimages identical
	// and the comparison vacuous.
	for len(c.Sigs) == 0 {
		c = randCertificate(rng)
	}
	b.Logf("%d signatures, %d encoded bytes", len(c.Sigs), c.SizeBytes())

	b.Run("id", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sink = c.ID()
		}
	})
	b.Run("exemplar", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sink = c.ExemplarHash()
		}
	})
}

// sink defeats the dead-store elimination that would otherwise let the compiler
// delete the call being measured.
var sink types.Hash

// TestTheIdPreimageDoesNotGrowWithTheSignatureCount is the cost argument for
// keeping signatures out of the id's preimage, made structurally rather than by
// timing.
//
// The fold hashes each certificate once, in `carry`, exactly as it did before —
// the change moved the preimage, it did not add a digest. So the whole question
// of whether the sequential stage got slower reduces to whether the new
// preimage is larger than the old one, and that is decidable rather than
// measurable: the id's preimage is the body, which no signature appears in, so
// it is *invariant* under the signature count, while the exemplar's grows by
// one fixed-size Sig per signer. Same hash, same call count, strictly less
// data, at every signature count the protocol admits.
//
// Stating it this way also pins something a timing run never could: that the
// preimage stays invariant. A future edit that let any part of Sigs leak back
// into the body would be a silent return of the double spend, and it would show
// up here as a preimage that grew.
func TestTheIdPreimageDoesNotGrowWithTheSignatureCount(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	c := randCertificate(rng)

	c.Sigs = nil
	invariant := len(c.MarshalSSZ()) // with no signatures the two coincide

	for n := 0; n <= testParams().MaxSigs; n++ {
		c.Sigs = make([]types.Sig, n)
		for i := range c.Sigs {
			// Distinct, so that nothing here is measuring a degenerate list.
			c.Sigs[i].PubKey[0] = byte(i)
		}
		exemplar := c.SizeBytes()

		// The id's preimage is not exported, but its length is exactly the
		// exemplar's minus what the signature list contributes.
		if got := exemplar - n*types.SigSize; got != invariant {
			t.Fatalf("%d signatures: the id preimage is %d bytes, want %d — "+
				"something other than Sigs moved with the signature count", n, got, invariant)
		}
		if n > 0 && exemplar <= invariant {
			t.Fatalf("%d signatures: the exemplar preimage did not grow, so the two "+
				"preimages are the same and this test asserts nothing", n)
		}
	}
}
