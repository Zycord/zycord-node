package stratum

import (
	"encoding/binary"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
)

// ---------------------------------------------------------------------------
// THE CONSENSUS SEAM
//
// This file is where the endpoint touches the work rule, and it is drawn
// around ONE question: **what quantity does the rule compare against the
// target?** Not around the bytes of the blob, not around the shape of the
// seal, not around an endianness convention — around the compared value.
//
// That perimeter is the correction of a real and instructive mistake. An
// earlier revision drew this seam around blob layout, seal shape and digest
// endianness, on the theory that those were the encoding details a consensus
// change would move. Then rx/2 landed and moved the compared quantity instead:
// the rule stopped comparing the RandomX digest and started comparing
// `blake2b(PoWInput ‖ PoWHash)`. Every byte offset the old seam guarded was
// still correct, so the "mechanical rebase" it promised produced exactly one
// compile error, its own tripwire test went green, and the endpoint kept
// comparing a number no miner on earth filters on. A seam that reports success
// while the defect it exists to catch walks through is worse than no seam.
//
// So the rule this file follows is: **never re-derive a consensus comparison.
// Call the one in core/pow.** Where that is impossible the reason is written
// out, the divergence is named, and a test pins the two together.
//
// # What the endpoint compares, and why there are two comparisons
//
// A submitted share is judged twice, against two different targets, and the
// two are not redundant:
//
//  1. Against the JOB target — the 64-bit truncation this package handed the
//     miner. This is the miner's own filter reproduced, and a share failing it
//     means the miner computed the wrong function. It is scored.
//  2. Against the FULL 256-bit consensus target, via pow.CheckWork. A share
//     passing this is a block.
//
// Both now compare the COMMITMENT, because that is what rx/2 compares. See
// jobTargetValue.
// ---------------------------------------------------------------------------

// jobTargetValue is the 64-bit quantity a miner filters its shares on, and the
// quantity this endpoint must therefore filter on to agree with it.
//
// **It is the commitment, not the RandomX digest, and that distinction is the
// whole of this function.** Under rx/2, stock XMRig computes
// `randomx_calculate_commitment(blob, size, hash, hash)` — which writes over
// its own input buffer — and then filters on the buffer that now holds the
// commitment. The two values are independent and uniform, so a pool comparing
// the digest and a miner comparing the commitment accept DISJOINT sets of
// nonces. Not overlapping sets, disjoint ones: every honest share would be
// rejected and every share the pool accepted would be one the miner would
// never send. At a healthy reported hashrate, with nothing in the protocol
// naming the cause, and with this endpoint's ban score then disconnecting the
// miners that are behaving. That failure is exactly what
// docs/decisions/xmrig.md exists to prevent, and it is what an earlier
// revision of this package shipped.
//
// The commitment is obtained from pow.Commitment rather than assembled here.
// That is the seam's own rule applied to itself: the operand order, the digest
// function and its width are upstream's, core/pow already states them, and a
// second spelling of the same BLAKE2b call in this package would be a second
// place for them to drift.
//
// The value read is the TOP LIMB of the little-endian 256-bit reading —
// XMRig's filter is `*(uint64_t*)(m_hash + 24) < job.target()`, eight bytes at
// offset 24 read natively. That is bytes 24..31 as a little-endian uint64,
// which is what binary.LittleEndian.Uint64 over the final eight bytes gives.
func jobTargetValue(h types.Header) uint64 {
	c := pow.Commitment(h)
	return binary.LittleEndian.Uint64(c[len(c)-8:])
}

// meetsJobTarget reports whether a header's commitment clears the 64-bit job
// target the miner was handed.
//
// Strictly below, matching XMRig's `value < job.target()`. A share exactly
// equal to the target is one the miner would not have sent, so accepting it
// would be accepting something no miner produces.
func meetsJobTarget(h types.Header, target uint64) bool {
	return jobTargetValue(h) < target
}

// blobFor renders the hashing blob a miner searches.
//
// It is now h.PoWInput() and nothing else. The 43-byte layout — 0..31 seed,
// 32..38 reserved zero, 39..42 le32(nonce) — is consensus, stated once in
// core/types, and this package's job is to transmit it rather than to have an
// opinion about it. An earlier revision wrote those bytes by hand because the
// layout had not merged yet; keeping that writer now would be maintaining a
// second implementation of a consensus encoding for no reason at all.
//
// The nonce bytes ship ZERO, and that is enforced here at RUN TIME rather than
// only asserted in a test.
//
// A stock XMRig handed a job whose blob carries a non-zero nonce latches into
// nicehash mode: it treats the top byte as a fixed prefix it must preserve and
// searches only the remaining 24 bits. That silently narrows the connection's
// search space by a factor of 256, permanently, for as long as the connection
// lives — and nothing in the protocol reports it, so the miner shows a healthy
// hashrate and simply finds far fewer shares than it should.
//
// A test alone would be the wrong instrument for that. The invariant depends
// on a caller handing this a freshly assembled header, which is a property of
// code elsewhere that nothing otherwise stops changing; a silent, permanent,
// unreportable degradation is exactly the failure worth paying four byte
// comparisons per job to make impossible rather than merely unlikely. Jobs are
// built once per connection per template, not per hash, so the cost is not on
// any hot path. TestTheServedBlobShipsAZeroNonce covers the served output; this
// covers the caller that has not been written yet.
//
// Zeroed rather than refused: the nonce field is the miner's to write and its
// value on the wire is never hashed by anyone, so a template that arrives with
// one set is a template this endpoint can serve correctly by clearing it. There
// is nothing to reject and nobody to tell.
func blobFor(h types.Header) []byte {
	b := h.PoWInput()
	for i := types.PoWInputNonceOffset; i < types.PoWInputNonceOffset+4; i++ {
		b[i] = 0
	}
	return b
}

// sealNonce writes a submitted nonce and the miner's ExtraNonce back into a
// template's header, so that the header can be verified and, if it wins,
// applied.
//
// PoWHash is deliberately NOT set here. It is not a value the miner is trusted
// to supply — see recoverPoWHash — and setting it in the same breath as the
// nonce would blur a field this node computes with two fields it accepts.
func sealNonce(hdr *types.Header, nonce, extraNonce uint32) {
	hdr.PoW.Nonce = nonce
	hdr.PoW.ExtraNonce = extraNonce
}

// recoverPoWHash computes the RandomX digest for a reconstructed header and
// writes it into PoWHash.
//
// **The digest is recomputed, never taken from the wire**, and the reasoning
// is the same one node/miner gives for re-checking its own seal: a producer
// must not trust its own construction, and this producer is a stranger.
// XMRig does send the raw digest — in the Stratum field confusingly NAMED
// `commitment`, while the field named `result` carries the actual commitment,
// the names being inverted at every layer under rx/2 — but a share is a claim,
// and a claim that this node writes into its own chain has to be checked.
// Accepting a submitted digest would let a miner name any 32 bytes as the
// header's PoWHash, and PoWHash is a consensus field every peer will re-derive.
//
// It costs one RandomX evaluation per share, in light mode, which is what the
// ban score and the connection cap exist to bound.
func recoverPoWHash(e pow.Engine, hdr *types.Header, p *params.Params) {
	hdr.PoWHash = e.Hash(pow.KeyFor(hdr.Height, p), hdr.PoWInput())
}

// algoFor names the work function a job is for, in the identifier stock XMRig
// selects its implementation by.
//
// It is derived from the network's declared engine rather than hardcoded,
// because the engine is consensus — a node does not choose what it verifies
// against — and an endpoint advertising an algorithm the chain is not running
// would hand every miner a job it cannot win. An earlier revision hardcoded
// "rx/0" and, once the networks moved to rx/2, refused every correctly
// configured stock miner at login.
//
// The mapping is small and explicit rather than derived from the engine's name
// by string surgery: these are two different namespaces that happen to be
// related, and a rule like "strip the prefix" would silently produce a
// plausible-looking identifier for any engine added later.
func algoFor(engineName string) (string, bool) {
	switch engineName {
	case randomxV2Name:
		return "rx/2", true
	case randomxV1Name:
		return "rx/0", true
	case devEngineName:
		// The development engine is not RandomX and no miner implements it. A
		// devnet is mined by node/miner, not by XMRig, so there is no honest
		// algorithm string to advertise — and inventing one would let a miner
		// connect, hash something else entirely, and have every share refused.
		// Reported as unmineable so that login refuses with a message saying
		// exactly that.
		return "", false
	}
	return "", false
}

// The engine names this endpoint knows how to advertise. They are consensus
// values (params.PoWEngine) and are spelled here rather than imported from
// core/pow/randomx because that package is behind the `randomx` build tag: a
// binary built without it must still compile this one, and must still be able
// to say "this network's engine is one I cannot serve jobs for".
const (
	randomxV1Name = "randomx-v1"
	randomxV2Name = "randomx-v2"
	devEngineName = "dev-blake3"
)

// truncateTarget converts a 256-bit consensus target into the 64-bit target a
// Monero-dialect job carries.
//
//	t64 = max(1, floor((target256 + 1) / 2^192))
//
// **Unchanged by rx/2, and that is a finding rather than an assumption.** What
// rx/2 moved is WHICH 32 bytes the miner reads; it did not move how it reads
// them. The filter is still eight bytes at offset 24 taken as a native
// little-endian uint64, which is still the top limb of the little-endian
// 256-bit reading, so a job target is still the clean truncation of the
// consensus target and the commitment is uniform for the same reason the
// digest was. docs/spec/wire.md and ARCHITECTURE §12 both say so explicitly.
//
// max(1, …): a target below 2^192 truncates to zero, and a zero job target
// means "no nonce can ever win" to a miner that divides by it — XMRig computes
// its display difficulty as 2^64/t64 and would divide by zero. Clamping to 1
// hands such a miner the hardest expressible job instead, which is the honest
// answer rather than a defect in the endpoint.
//
// The +1 makes the truncation INCLUSIVE of the boundary: a target of exactly
// 2^192-1 should yield t64 = 1, not 0. u256.Add reports a carry, so a target
// at the very ceiling answers with the easiest job rather than wrapping to the
// hardest.
func truncateTarget(target u256.U256) uint64 {
	plusOne, carry := target.Add(u256.FromUint64(1))
	if carry {
		return ^uint64(0)
	}
	// floor(x / 2^192) is the top 64 bits of the big-endian encoding: a byte
	// slice rather than a division, because doing it as arithmetic would be a
	// slower way to be wrong in more places.
	b := plusOne.Bytes()
	t64 := binary.BigEndian.Uint64(b[0:8])
	if t64 == 0 {
		return 1
	}
	return t64
}

// jobTargetHex renders a job target the way the Monero dialect does: the
// 64-bit target as EIGHT little-endian hex bytes.
//
// Not four. Pools do emit a 4-byte compact form and XMRig widens it, but the
// compact form cannot express a target below 2^32 — most of the useful range
// for a chain whose difficulty a CPU meets — so a pool emitting it is quietly
// rounding every miner's job.
func jobTargetHex(t64 uint64) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], t64)
	return hexOf(b[:])
}

// seedHashes returns the RandomX seed for a height and the seed the NEXT key
// epoch will use.
//
// XMRig needs both: `seed_hash` tells it which key to initialise its cache
// for, and `next_seed_hash` lets it build the next one in the background so a
// key rotation does not stall every miner for the tens of seconds a cache fill
// takes. Monero pools derive these from key blocks and cannot compute the next
// one until the block exists; this chain derives the key from the HEIGHT
// (pow.KeyFor), so the next epoch's seed is known arbitrarily far ahead and
// this is a lookup rather than a prediction.
//
// The boundary is found by walking forward rather than by recomputing the
// arithmetic here: pow.SeedEpochFor's own comment is emphatic that its
// expression is subtle and mutation-checked in both directions, and a second
// implementation of it in this package would be a second place for it to be
// wrong.
func seedHashes(height uint64, p *params.Params) (seed, next types.Hash) {
	seed = pow.KeyFor(height, p)
	epoch := pow.SeedEpochFor(height, p)
	// Step by the interval, not by one: the boundary is at most one interval
	// away, so a single stride crosses it, and a linear scan over a 2048-block
	// mainnet interval would be 2048 hashes per job for a value that changes
	// once per epoch.
	step := p.RandomXKeyInterval
	if step == 0 {
		step = 1
	}
	for h := height + 1; ; h += step {
		if pow.SeedEpochFor(h, p) != epoch {
			return seed, pow.KeyFor(h, p)
		}
		if h < height {
			// Overflow: a height within one interval of the uint64 ceiling,
			// which is not a chain anyone is mining. The current seed is the
			// honest answer — there is no next epoch.
			return seed, seed
		}
	}
}
