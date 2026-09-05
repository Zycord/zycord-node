package chain_test

import (
	"encoding/hex"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
)

// TestTheSeenKeyRuleAndTheStoreVersionMoveTogether is the tripwire the
// `storeVersion` bump the certificate-id redefinition needs and that no
// ordinary test can be.
//
// The certificate id is the key this package writes seen entries under, and it
// lives *outside* the state root by design (core/state.Root excludes the seen
// set, being prunable and derivable from recent history). So when the id's
// definition changes, both of the guards that normally refuse a stale database
// are blind: the genesis id need not move, and a seen set keyed under the old
// rule still reconciles against a perfectly correct root. `storeVersion` is the
// only thing left watching, and nothing was watching `storeVersion`.
//
// The neighbouring TestAnOlderLayoutVersionRefusesToOpen pins the *mechanism* —
// that a mismatched version is refused — and passes whatever the constant is,
// so it cannot notice a forgotten bump. This pins the *pairing*: the id rule and
// the version are both recorded here, and **any** drift in either fails.
//
// It fails on any drift rather than only on one-sided drift, and that is not
// belt-and-braces — a one-sided test disarms itself the first time it is
// obeyed. The first draft fired only when exactly one of the two had moved, so
// after a correct firing (both constants stale, developer bumps the real
// version and the real id rule) neither recorded value matched any more,
// **both** branches went quiet, and the very next forgotten bump passed.
// Measured on that draft: with the tree one generation ahead of the constants,
// changing the id rule again while leaving storeVersion alone — the precise
// case this exists to catch — passed. A guard that switches itself off the
// first time it is obeyed is absent exactly when the next consensus key change
// arrives. That is the same defect this file already fixed once, one
// generation earlier, in TestAnOlderLayoutVersionRefusesToOpen.
//
// So: if this fails, update **both** constants below, and decide first which
// of these happened —
//
//   - the id rule changed → bump `storeVersion` as well, or every pre-upgrade
//     certificate with a live TTL becomes includable again on an upgraded node
//     while a genesis-synced node rejects the same block. That is a chain split
//     by upgrade path rather than by content, which is the shape where both
//     sides are internally consistent and neither can be shown wrong from its
//     own data;
//   - the version changed for an unrelated layout reason → the id rule is
//     untouched and there is nothing to fix here, but say so in the commit.
//
// Either way the constants move together with the tree, deliberately, which is
// what keeps the guard armed for the generation after this one.
//
// The fixture is a hand-built certificate rather than one from wallet.Builder,
// so it depends on the SSZ encoding and the domain tag and on nothing else. A
// fixture derived from consensus parameters would fire whenever a parameter
// moved, which is a check that cries wolf.
func TestTheSeenKeyRuleAndTheStoreVersionMoveTogether(t *testing.T) {
	const (
		wantID      = "bce3c329f39b50ea0b7bd97aac17602157f1a529d5d3159906fe72c4f427ea9e"
		wantVersion = 2
	)

	got := seenKeyFixture().ID()
	gotHex := hex.EncodeToString(got[:])
	version := chain.StoreVersionForTest()

	idMoved := gotHex != wantID
	versionMoved := version != wantVersion
	if !idMoved && !versionMoved {
		return
	}

	var what string
	switch {
	case idMoved && !versionMoved:
		what = "The certificate id rule changed and storeVersion did NOT. That is the " +
			"dangerous case: the id is the seen-set key, the seen set is not in the state " +
			"root, and the genesis id need not move — so neither the network-id guard nor " +
			"the state-root guard can refuse a database written under the old rule. Bump " +
			"storeVersion."
	case !idMoved && versionMoved:
		what = "storeVersion moved and the certificate id rule did not. That is fine if some " +
			"other stored layout changed — say so in the commit."
	default:
		what = "Both moved. That is the expected shape of a deliberate seen-key change."
	}

	// Printed on every arm rather than only on the one that looks like it needs
	// it. The first version of this test told branch 1 to "bump storeVersion"
	// and said nothing about re-pinning these constants — so obeying it
	// correctly left both stale, and a stale constant is a branch that can
	// never fire again. The disarming happened on the path the test itself
	// instructed. Hence: whatever the cause, both come level, in the same
	// commit, and the values are quoted so nobody has to derive them by hand.
	t.Fatalf("%s\n\nRe-pin BOTH constants in this test, in the same commit as the change.\n"+
		"Leaving either stale disarms this tripwire: a constant that no longer\n"+
		"describes the tree can never disagree with it again.\n"+
		"  wantID      = %q  (currently %q)\n"+
		"  wantVersion = %d  (currently %d)",
		what, gotHex, wantID, version, wantVersion)
}

// seenKeyFixture is a fixed certificate. Its only purpose is to have an id, so
// every field is arbitrary except that the shape must be one the encoder
// accepts.
func seenKeyFixture() *types.Certificate {
	var src, dst, dep types.Address
	src[0], dst[0], dep[0] = 2, 2, 2
	for i := 1; i < len(src); i++ {
		src[i], dst[i], dep[i] = byte(i), byte(0x40+i), byte(0x80+i)
	}
	var pub types.PubKey
	for i := range pub {
		pub[i] = byte(0xC0 + i)
	}
	return &types.Certificate{
		ChainID: 7,
		Seq:     3,
		Program: types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{
			Moves: []types.Move{{Asset: types.NativeAsset, Src: src, Dst: dst, Amount: u256.FromUint64(1000)}},
		}},
		Reads:   []types.Read{{Slot: types.NativeBalanceSlot(src), Access: types.AccessGuardGE, Operand: u256.FromUint64(1000)}},
		Writes:  []types.Write{{Slot: types.NativeBalanceSlot(src), Op: types.OpDeltaSub, Value: u256.FromUint64(1000)}},
		Sigs:    []types.Sig{{PubKey: pub}},
		Deposit: types.Deposit{Cell: types.NativeBalanceSlot(dep), RefundTo: types.NativeBalanceSlot(dep), Amount: u256.FromUint64(50)},
		TTL:     99,
		FeeBid:  types.FeeBid{SeqMax: u256.FromUint64(10), SeqPriority: u256.FromUint64(1), ParMax: u256.FromUint64(10), ParPriority: u256.FromUint64(1)},
	}
}
