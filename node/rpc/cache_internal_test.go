package rpc

import "testing"

// Internal because the property is about etagOf's own inputs, independent of
// any real chain: two chains that publish the same consensus root can only
// be produced synthetically here, since ConsensusRoot in this codebase
// already covers every field genesis.Build reads (genesis's ParentID is
// literally p.ConsensusRoot()), so two distinct *params.Params values with
// the same root always build the same genesis and the same network id. The
// bug this pins — a reset that changes network_id while the params file,
// and so the root, stays the same — is a property of etagOf's inputs, not of
// any params object this process could construct, and belongs at that level.

// TestParamsETagNamesTheNetworkID.
//
// The property: the /params ETag has to name every field the body depends
// on. network_id is the genesis id, and genesis.ConsensusRoot hashes the
// parameter fields only — genesis is not one of them — so a params object
// used to derive the tag is not enough to promise the tag names the chain.
// Two synthetic params that hash identically (same root) but describe
// different chains (different network_id) — the case a testnet reset
// produces, same params.json, new genesis — must mint different tags, or a
// client revalidating across the reset gets a 304 and keeps the stale
// network_id: the one field that says which chain it is reading.
func TestParamsETagNamesTheNetworkID(t *testing.T) {
	var root [32]byte
	root[0] = 0xAA
	var netA, netB [32]byte
	netA[0], netB[0] = 0x01, 0x02

	tagA := etagOf("params", root, netA)
	tagB := etagOf("params", root, netB)
	if tagA == tagB {
		t.Fatalf("etagOf(\"params\", root, netA) == etagOf(\"params\", root, netB) == %q: "+
			"two chains with the same consensus root and different network ids would "+
			"share a tag, and a revalidation across a reset would return a 304 carrying "+
			"the old network_id", tagA)
	}

	// Anti-vacuity: the root alone is not what makes the two tags differ —
	// prove the two-part form actually differs from the one-part form this
	// package served before the network id was added to the tag, so a
	// regression that silently drops the network id back out is caught here
	// rather than by the two tags happening to differ for some other reason.
	rootOnly := etagOf("params", root)
	if rootOnly == tagA || rootOnly == tagB {
		t.Fatalf("etagOf(\"params\", root) collided with a network-id-qualified tag: %q", rootOnly)
	}
}
