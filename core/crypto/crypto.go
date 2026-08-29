// Package crypto holds every cryptographic primitive the consensus rules
// depend on, behind a surface small enough to audit in one sitting.
//
// Three rules govern this package:
//
//   - Every hash is domain separated. There is no raw blake3 call anywhere in
//     consensus code; a value hashed for one purpose can never be replayed as
//     a value hashed for another.
//   - Nothing here reads a clock, a random source or the filesystem. Key
//     generation lives in wallet/, outside the consensus core.
//   - The choices are frozen at genesis. Until then they are swappable behind
//     these functions, which is the whole reason the functions exist.
package crypto

import (
	"crypto/ed25519"
	"sync/atomic"

	"zycord/core/crypto/blake3"
)

// verifications counts every Ed25519 signature verification this process has
// attempted. It exists because a claim about how many times a predicate RUNS
// cannot be pinned by any amount of reading: the two findings that produced
// this counter were both claims of that shape, and four successive
// source-shaped guards were defeated in turn by a spelling nobody had
// enumerated — a function value, a package-scope binding, a hop through
// node/verify, a second mempool.Add. A fifth ships today and is defeated by
// none of those four: the symbol-granularity reference set in node/p2p, which
// permits only the symbols package node/p2p legitimately names across ALL its
// non-test files — package-scoped, not engine.go-scoped: three of its allowed
// symbols (ed25519.PublicKey, PrivateKey, GenerateKey) are named in
// transport.go and peerstore.go and never in engine.go. What it is blind to
// is a route through a package its table does not list, which is why counting
// sits BESIDE it and not instead of it — deleting it once already opened the
// asynchronous shape this counter structurally cannot see. An enumeration of
// spellings is not the property; a count of evaluations is.
//
// VerifyStrict is the one place to put it. It is the only non-test caller of
// ed25519.Verify on the node path, and core/validity's V2 loop is its only
// non-test caller in turn, so every certificate signature this node checks —
// by whatever route, through however many packages — passes through here once.
//
// Mutable package state in consensus code is a real cost and it is taken
// deliberately, so the shape matters: this is a monotonic COUNTER and not a
// swappable verifier. Nothing outside can set it, reset it, or use it to make a
// signature pass, so it cannot move a verdict — which is exactly what a seam of
// the `var check = realCheck` kind, the idiom used one layer up in
// node/mempool, could do if it ever escaped a test binary. Reading it is the
// only thing the outside world can do.
//
// atomic, because node/verify's pool verifies concurrently. sync/atomic is
// standard library, so core/ still imports nothing else.
var verifications atomic.Uint64

// VerificationCount returns how many Ed25519 verifications this process has
// attempted since it started.
//
// It is process-wide and monotonic, so a caller measures a DELTA across the
// operation it cares about, and must not be racing another verifier while it
// does — in practice, one non-parallel test.
func VerificationCount() uint64 { return verifications.Load() }

// HashSize is the length of every identifier in the protocol.
const HashSize = 32

// Hash is a 32-byte domain-separated digest.
type Hash = [HashSize]byte

// Domain tags. Adding a tag is a protocol change; reusing one is a bug.
const (
	// TagCert covers ssz(certificate) to produce a certificate's *exemplar
	// hash*: the evidence commitment the block's certificate root is built
	// from. It names one encoding of one certificate, signatures included,
	// which is what lets a block pin the bytes it carries.
	//
	// It is not the certificate id. A certificate id names an authorization
	// and many exemplars can carry it, because a signature is a randomized
	// demonstration that the authorization was given rather than part of what
	// was authorized.
	TagCert = "zcd/cert/v1"
	// TagCertID covers ssz(certificate with an empty signature list) to
	// produce the certificate id: the seen-set key, the fold's tiebreak, and
	// the identity every layer above the fold dedupes on.
	//
	// The preimage is the authorizing fields and never the signatures. Two
	// exemplars of one authorization therefore share an id, which is the whole
	// of the replay defence — see the note on Certificate.ID.
	TagCertID = "zcd/certid/v1"
	// TagCertBody covers ssz(certificate with an empty signature list) and is
	// what signatures actually commit to.
	//
	// Same preimage as TagCertID, deliberately a different tag. The two answer
	// different questions — "what does a signer sign" and "what does the seen
	// set key on" — and one value per question is what keeps a change to the
	// signing scheme from silently moving every certificate id with it.
	TagCertBody = "zcd/certbody/v1"
	// TagBlock covers ssz(header) to produce a block id.
	TagBlock = "zcd/block/v1"
	// TagAddr covers version ‖ payload to produce an address.
	TagAddr = "zcd/addr/v1"
	// TagPoW covers ssz(header without the nonce) as the proof-of-work input.
	TagPoW = "zcd/pow/v1"
	// TagPoWKey derives the key the proof-of-work engine is keyed from. It
	// covers chain_id ‖ seed_epoch, so the key is a pure function of the
	// header's height and the network, and never of a block this node may
	// not hold.
	TagPoWKey = "zcd/pow-key/v1"
	// TagSig covers chain_id ‖ consensus_root ‖ cert_body_root as the message
	// signers sign. The consensus root is the genesis binding — it is the value
	// block 0 carries as its ParentID — so a signature is bound to one
	// *incarnation* of a network and not merely to its chain id.
	// spec/chain-ids.json is the allocation ledger, which stays load-bearing
	// for the one case no preimage can separate: two incarnations whose
	// parameter values are identical. SigningMessage carries both arguments.
	TagSig = "zcd/sig/v1"
	// TagBalanceWord derives the storage word of an (address, asset) balance.
	TagBalanceWord = "zcd/bal/v1"
	// TagAssetWord derives the storage words of an asset's metadata cells.
	TagAssetWord = "zcd/assetword/v1"
	// TagBeaconWord derives the storage words of the epoch beacon.
	TagBeaconWord = "zcd/beacon/v1"
	// TagProtocolWord derives the storage words of protocol-owned cells that
	// are neither beacon nor asset (the two fee-market base fees).
	//
	// This is the one tag whose call sites mix shapes: some hash a bare label,
	// some a label followed by an 8-byte ring index. Sum has no length prefix,
	// so a bare label that happens to begin with an indexed family's label and
	// to be exactly eight bytes longer names the same cell as that family at
	// one index. Nothing about the tag prevents it; the disjointness is checked
	// in TestNoTwoVariableLengthHashCallSitesCanShareAPreimage instead.
	TagProtocolWord = "zcd/protoword/v1"
	// TagSSZNode is the internal node tag of every merkle tree in the protocol.
	TagSSZNode = "zcd/node/v1"
	// TagStateCell is the leaf tag of a cell in the epoch state root.
	TagStateCell = "zcd/stateleaf/v1"
	// TagStateSpent is the leaf tag of a spent-registry entry in the state root.
	TagStateSpent = "zcd/spentleaf/v1"
	// TagStateRoot finalises the epoch state root over its two sub-roots.
	TagStateRoot = "zcd/stateroot/v1"
	// TagParams covers a raw parameter file; a launch announcement commits to
	// this value weeks in advance.
	TagParams = "zcd/params/v1"
	// TagConsensusRoot covers every consensus parameter, by value. It is what
	// the genesis block commits to, so that nodes configured differently derive
	// different genesis ids and refuse each other (R3-1).
	TagConsensusRoot = "zcd/consensusroot/v1"
)

// Sum returns blake3(tag ‖ payload). Every hash in the protocol goes through
// this function.
//
// The parts are concatenated with no length prefix, so injectivity is a
// property of the *call sites* rather than of this function: two sites under
// one tag share a preimage as soon as their concatenated payloads can be equal
// Where the digest is a storage word, that is two purposes on one state
// cell, with no error and no symptom until the two values disagree.
//
// One tag with one call site is safe whatever its payload. A tag with several
// is safe only when the payloads cannot coincide, and the two families where
// that is arithmetic rather than construction — the TagProtocolWord words and
// the address derivations — are checked by
// TestNoTwoVariableLengthHashCallSitesCanShareAPreimage, which reads them out
// of the source. Adding a length prefix here would close the class outright,
// but it moves every preimage in the protocol and so is a pre-genesis decision,
// not an edit.
func Sum(tag string, payload ...[]byte) Hash {
	h := blake3.New()
	h.Write([]byte(tag))
	for _, p := range payload {
		h.Write(p)
	}
	var out Hash
	h.XOF(out[:])
	return out
}

// AddrSize is the length of an address in bytes: one version byte followed by
// 31 bytes of domain-separated hash.
const AddrSize = 32

// Address is version ‖ blake3(TagAddr ‖ version ‖ payload)[:31].
//
// The version byte is part of the hash input, so the same payload under two
// versions yields two unrelated addresses and an address cannot be reinterpreted
// as a different kind by rewriting its first byte.
type Address = [AddrSize]byte

// Address kinds. The version byte is consensus-visible: it decides debit
// authorisation (§6 of the architecture spec).
const (
	// AddrVersionProtocol is the single fold-owned address. Certificates may
	// never write to it (V7).
	AddrVersionProtocol byte = 0x00
	// AddrVersionOneShot is a user address whose signing authority is burned
	// by the first certificate that debits it.
	AddrVersionOneShot byte = 0x01
	// AddrVersionPersistent is a reusable user address.
	AddrVersionPersistent byte = 0x02
	// AddrVersionAsset is an asset address, governed by its immutable
	// authority cells rather than by a signature over the address itself.
	AddrVersionAsset byte = 0x03
)

// DeriveAddress builds an address of the given version over an arbitrary
// payload.
func DeriveAddress(version byte, payload ...[]byte) Address {
	parts := make([][]byte, 0, len(payload)+1)
	parts = append(parts, []byte{version})
	parts = append(parts, payload...)
	h := Sum(TagAddr, parts...)

	var a Address
	a[0] = version
	copy(a[1:], h[:AddrSize-1])
	return a
}

// AddressFromPubKey derives a user address (one-shot or persistent) from an
// Ed25519 public key.
func AddressFromPubKey(version byte, pub PubKey) Address {
	return DeriveAddress(version, pub[:])
}

// ProtocolAddress is the fold-owned address: version 0x00 followed by 31 zero
// bytes. It is deliberately *not* derived from a hash — it must be recognisable
// by inspection, and nothing may ever collide with it by finding a preimage.
var ProtocolAddress = Address{AddrVersionProtocol}

// IsUserAddress reports whether debit authorisation for the address comes from
// a signature by the key that hashes to it.
func IsUserAddress(a Address) bool {
	return a[0] == AddrVersionOneShot || a[0] == AddrVersionPersistent
}

// KnownAddressVersion is the highest address version this release defines.
// Versions are allocated contiguously from 0x00, so "known" is a range check
// rather than a set — and the range stops one short of 0x04, reserved for
// Era S's hidden-value cells (architecture spec §6) and unreachable by any
// certificate this release can build or accept.
const KnownAddressVersion = AddrVersionAsset

// IsKnownAddressVersion reports whether an address carries a version byte
// this release defines. Nothing here rejects it on its own — the closed
// Era-0 program set already never derives an address of any other kind — but
// a certificate is bytes controlled by whoever built it, not only by what a
// program would derive, so core/validity checks this explicitly (V9) rather
// than relying on that as an accident of the current op set.
func IsKnownAddressVersion(a Address) bool {
	return a[0] <= KnownAddressVersion
}

// PubKeySize is the length of an Ed25519 public key.
const PubKeySize = ed25519.PublicKeySize

// SigSize is the length of an Ed25519 signature.
const SigSize = ed25519.SignatureSize

// PubKey is a 32-byte Ed25519 public key in compressed Edwards form.
type PubKey = [PubKeySize]byte

// Signature is a 64-byte Ed25519 signature.
type Signature = [SigSize]byte

// IsSmallOrderPubKey reports whether the key encodes one of the eight points
// of order dividing 8 — the points that must never be accepted as a signer,
// because a small-order key verifies many distinct messages under a crafted
// signature and would let a certificate claim authority it does not hold.
//
// The answer is computed ([8]A == identity), not looked up. The table this
// replaced listed nine encodings; `crypto/ed25519` accepts fourteen, because
// each low-order point can also be spelled with y + p where that still fits in
// 255 bits, and the two points with x = 0 can also be spelled with the sign bit
// set. The five it was missing were live: two of them decode to the identity,
// under which *every* well-formed signature verifies. A literal cannot defend
// this property, because nothing makes a literal fail when it is short.
//
// Non-canonical spellings answer true as well. The point of this predicate is
// "would some verifier somewhere treat this as a low-order signer", and the
// encodings other implementations relax on are exactly the ones that matter.
func IsSmallOrderPubKey(pub PubKey) bool {
	p, st := decodeEdPoint(pub[:])
	if st == decodeInvalid {
		return false
	}
	return isLowOrder(p)
}

// VerifyStrict checks an Ed25519 signature under Zycord's strict rules:
//
//   - the public key and the signature's R must each be a *canonical* encoding
//     of a curve point: y < p, and no sign bit on an x that is zero. The
//     standard library does not do this for the public key — `SetBytes`
//     documents both relaxations — so it is done here (V2);
//   - the signature's scalar half must be canonically reduced (this the
//     standard library does enforce: it rejects S >= L);
//   - the public key must not be of low order, which is now *computed* ([8]A ==
//     identity) rather than matched against a list;
//   - the public key must be **torsion-free**: [L]A is the identity;
//   - verification itself is cofactorless, exactly RFC 8032.
//
// R gets the encoding rule and nothing else, and the omission is deliberate.
// An earlier draft of this function also ran isLowOrder(r); that rule could
// only ever fire on one input, and it was the wrong one. Once [L]A is the
// identity, R = S*B - h*A lies in the prime-order subgroup, whose only
// low-order point is the identity — so isLowOrder(r) reduces to "reject R =
// identity", and R = identity is a signature RFC 8032 accepts, crypto/ed25519
// accepts, and §7 of ARCHITECTURE.md accepts (it says R's subgroup membership
// is *entailed*, and the identity is in the subgroup). A signer reaches it by
// signing with a zero nonce, which no honest signer does and which leaks the
// signing scalar to anyone who looks — but "no honest signer does this" is
// not the test. The test is whether a second implementation written from the
// spec agrees, and it does not: rejecting it is the mirror image of the
// non-canonical-encoding defect, where this client accepted what others
// rejected. TestRIdentityIsAcceptedAsRFC8032Requires holds the line.
//
// The torsion rule is the one that cannot be expressed as a list. A mixed-order
// key A = A' + T, with A' of large order and T of order 8, is not small-order,
// so no blocklist of any size catches it — there are about 2^252 of them — and
// it is exactly where a cofactored batch verifier and a cofactorless single
// verifier disagree. The choice made here is (a) of the two coherent options:
// cofactorless verification plus explicit torsion rejection, rather than (b)
// ZIP-215 semantics. ZIP-215 was rejected because it deliberately accepts
// non-canonical encodings, and this protocol cannot: an implementation that
// accepts an encoding its peers refuse forks the network on a certificate
// neither side can call invalid, and the split is silent because both sides
// think they are right.
//
// That sentence used to end differently, and the correction matters more than
// the rule. It said the id covers Sigs, so two encodings of one authorization
// are two ids and the seen set stops holding — reaching the doorstep of the
// signatures-in-the-id defect and stopping. It closed the ENCODING channel
// and never considered the NONCE channel, which no encoding rule can reach: a
// signer picks r, every [r]B is a canonically encodable prime-order point,
// and every one of them yields a valid canonical signature over the same
// message. One authorization therefore had unboundedly many valid exemplars
// whatever this function does, and the fix was never available here. It was
// to take Sigs out of the id's preimage entirely (core/types.Certificate.ID).
// What this function defends is agreement between implementations, and that
// is the whole of what canonicity was ever able to buy.
//
// What the future batch verifier must then do. With A in the prime-order
// subgroup, S*B - R - h*A lies in that subgroup, so it is the identity if and
// only if eight times it is: a cofactored batch verifier — which is what batch
// verifiers normally are — agrees with this function on every input, provided
// it applies these same encoding, order and torsion rules to A before batching,
// and rejects R that is not torsion-free. That last clause is free here and is
// not free there: cofactorless verification reconstructs R as S*B - h*A, which
// is torsion-free whenever A is, so an R carrying a torsion component can never
// satisfy this function. It can satisfy a cofactored one. That is why R is not
// re-tested below and why a batch verifier must test it.
//
// That last argument is sound but it is enforced in a dependency: nothing in
// this function reconstructs R — ed25519.Verify does — and Go documents
// cofactorless verification nowhere as a compatibility guarantee. A release
// that adopted cofactored semantics would make this function start accepting
// the seven torsion offsets of every R, which is eight ids for one
// authorization and exactly the replay the ZIP-215 paragraph above refuses. So
// the property is pinned: TestCofactorlessVerificationIsPinned builds a
// signature a cofactored verifier accepts (asserting that with its own
// arithmetic, so it cannot pass vacuously) and requires the standard library to
// reject it. If that test ever fails, this function must grow isTorsionFree(r);
// it is not a test to relax.
// The checks are ordered by cost, cheapest first, because every one of them is
// reachable from unauthenticated gossip and the caller of an invalid signature
// is the attacker. The canonicality rule is byte comparisons; the signature
// equation is the standard library's optimised field; only then does this
// function do any math/big work of its own. An attacker's cheapest rejection
// therefore costs what it cost before this change, and the multiplier is paid
// only by inputs that already carry a valid signature.
func VerifyStrict(pub PubKey, message []byte, sig Signature) bool {
	verifications.Add(1)

	// V2's point half: y < p, and no sign bit on a zero x. Decided on the raw
	// bytes so that a 32-byte forgery is refused without a modular exponentiation.
	//
	// Neither half of this line is observable by deleting it, and the two are
	// unobservable for different reasons — both recorded rather than left for a
	// reader to rediscover as "dead code". For the public key: every
	// non-canonical encoding that is on the curve and not low order is an
	// ordinary point whose discrete log nobody knows, so no test can present a
	// signature that verifies under one. It is watched one level down, by
	// TestDecodeReportsCanonicality and TestPrefilterAgreesWithTheDecoder. For R:
	// ed25519.Verify re-encodes the R it reconstructs and byte-compares, so the
	// standard library already refuses every other spelling — the check is
	// redundant *today*, and is kept because V2 is a consensus rule rather than
	// an assumption about somebody's library. That assumption is pinned by
	// TestRIdentityIsAcceptedAsRFC8032Requires, which fails the day it stops
	// holding.
	if !isCanonicalEncoding(pub[:]) || !isCanonicalEncoding(sig[:PubKeySize]) {
		return false
	}
	if !ed25519.Verify(ed25519.PublicKey(pub[:]), message, sig[:]) {
		return false
	}
	a, st := decodeEdPoint(pub[:])
	if st != decodeCanonical {
		return false
	}
	// isLowOrder is NOT subsumed by isTorsionFree, and must not be removed as
	// redundant next to it. L is odd, so [L]T is not the identity for T of order
	// 2, 4 or 8 — but [L]O *is* the identity, so the identity key passes the
	// torsion test below. It is caught only here. The identity key is the whole
	// of the identity-key forgery: under it the equation collapses to [S]B = R
	// and every well-formed signature verifies. Deleting this line reopens that,
	// and the torsion check will not notice. TestIdentityKeysForgeEverySignature
	// is the guard.
	if isLowOrder(a) {
		return false
	}
	return isTorsionFree(a)
}

// SigningMessage returns the exact bytes a signer signs for a certificate:
// blake3(TagSig ‖ chain_id_le ‖ consensus_root ‖ cert_body_root).
//
// The three payloads are 8, 32 and 32 bytes, so the concatenation is injective
// without a length prefix and this call site cannot collide with itself — the
// property Sum's own note says belongs to the caller.
//
// The chain id is inside the signed message, so a signature is bound to one
// network. A mainnet certificate replayed on a testnet fails V2, not some
// policy check.
//
// The consensus root is inside it too, and that is the incarnation binding.
// It binds a signature to one *incarnation* of a network rather than to the
// name of one, and the binding is structural rather than by convention: the
// genesis id is derived from the parameters — block 0's ParentID *is*
// p.ConsensusRoot() (genesis.Build) — so a respin, which always moves
// genesis_time, derives a different root and a different genesis id. Every
// certificate signed against the previous incarnation then fails V2 on the
// new one, even though V1 still passes because the chain id was reused.
//
// What is bound is the consensus root and not the genesis block id, and the
// two are not a matter of taste:
//
//   - They separate the same sets, and the root separates them at least as
//     finely. Every field of block 0's header is a consensus parameter or a
//     function of them (ParentID = ConsensusRoot, Time = genesis_time,
//     Target = genesis_target, and the three roots are folded from an empty
//     block under p), so equal consensus roots imply equal genesis ids; and
//     equal genesis ids imply an equal ParentID, which is the root itself.
//     core/params holds both halves: TestBlock0CommitsToTheConsensusRoot is
//     the containment, and TestEveryConsensusParameterChangesTheGenesisID
//     walks every parameter and requires both values to move.
//
//     The direction this preimage needs is the *stronger* of the two, and it
//     is worth saying which one that is. That walk asserts the root moves
//     unconditionally; its genesis-id assertion is guarded by `err == nil`,
//     because a perturbed set can be unbuildable. So binding the root is not a
//     weaker stand-in for binding the id — it is the binding whose separating
//     power is pinned on every parameter with no case exempted. The only field
//     outside the root is Notes, and TestConsensusBoundaryIsExplicit pins that
//     the excluded set is exactly {notes} while TestNotesDoNotAffectConsensus
//     pins that a note moves neither value. So no pair of parameter sets has
//     two genesis ids and one root.
//
//   - Only one of them is reachable here. core/genesis imports core/fold,
//     which imports core/validity, so V2 cannot compute a genesis id without
//     an import cycle; and a rule the package doc calls stateless should not
//     need a state root folded to answer. The consensus root is a pure
//     function of the parameter set, in the package V2 already takes.
//
// The binding does not replace the allocation rule, which stays load-bearing
// and is stated where its reason is:
//
//	A chain id is allocated once and is never reused — not by a respin of a
//	network, not by a fork of one.
//
// It is what still covers the case no preimage can separate: two incarnations
// whose parameter values are *identical*. A fork over history rather than over
// rules, and a same-file reset that wipes the data directory without touching
// the parameter file, both derive the identical consensus root, so nothing in
// here can tell them from their predecessor — and for the reset that is
// wanted, since it is meant to be the same network. Only a distinct chain id
// separates those, which is what spec/chain-ids.json holds and
// spec/chainid_allocation_test.go refuses a second use of.
//
// TagSig freezes at block 0, so what a signature covers has no in-protocol
// path to change. That is why this shape is decided before genesis rather
// than after it.
func SigningMessage(chainID uint64, consensusRoot, certBodyRoot Hash) []byte {
	var cid [8]byte
	putUint64LE(cid[:], chainID)
	m := Sum(TagSig, cid[:], consensusRoot[:], certBodyRoot[:])
	return m[:]
}

func putUint64LE(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}
