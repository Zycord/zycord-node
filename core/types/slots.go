package types

import (
	"zycord/core/crypto"
	"zycord/core/ssz"
)

// The storage layout of the whole protocol is in this file. Every word is a
// domain-separated hash of a label, so no two purposes can ever land on the
// same cell, and the all-zero word is reserved: it is the canonical word of an
// address-wide MARK_SPENT and belongs to no value.
//
// "No two purposes can land on the same cell" is a claim about the labels, not
// only about the tags. crypto.Sum concatenates without a length prefix, so
// under TagProtocolWord a bare label collides with an indexed family whenever
// it begins with that family's label and is exactly eight bytes longer —
// "coinbase_addr_pending" against pendingCoinbaseWord("coinbase_addr", index)
// is the shape, and it looks like an ordinary one-line addition.
// crypto.TestNoTwoVariableLengthHashCallSitesCanShareAPreimage reads the labels
// below out of this source and fails on such a pair, so a new label is checked
// here rather than by whoever reviews the diff.

// NativeAsset is the asset id of the native coin: the all-zero address.
var NativeAsset Address

// SpentWord is the canonical word of an address-wide MARK_SPENT write.
var SpentWord [32]byte

func word(tag, label string) [32]byte {
	return crypto.Sum(tag, []byte(label))
}

// Asset metadata words. All five live under the asset's own address; the first
// four are immutable once written, which is what lets MINT authorise itself
// with an EXACT read that can never go stale.
var (
	assetWordCap      = word(crypto.TagAssetWord, "cap")
	assetWordDecimals = word(crypto.TagAssetWord, "decimals")
	assetWordSymbol   = word(crypto.TagAssetWord, "symbol")
	assetWordMinter   = word(crypto.TagAssetWord, "minter")
	assetWordMinted   = word(crypto.TagAssetWord, "minted")
)

// Epoch beacon words. Programs express time as ordinary guards on these cells
// — never as ambient reads, which would break stateless validity.
var (
	beaconWordEpoch   = word(crypto.TagBeaconWord, "epoch")
	beaconWordHeight  = word(crypto.TagBeaconWord, "height")
	beaconWordEntropy = word(crypto.TagBeaconWord, "entropy")
)

// Fee-market words. The two base fees are consensus state, so they are cells
// under the protocol address like everything else the fold owns.
var (
	protoWordSeqBaseFee = word(crypto.TagProtocolWord, "seq_base_fee")
	protoWordParBaseFee = word(crypto.TagProtocolWord, "par_base_fee")
)

// Elastic-ceiling words (whitepaper §8.1). SeqGasTarget is T, the epoch
// controller's only piece of memory besides the sample ring below;
// PrevParentID and PrevTarget are what let a citation be checked against the
// grandparent and difficulty a competing header actually shares, without the
// fold holding more than one block of lookback.
var (
	protoWordSeqGasTarget = word(crypto.TagProtocolWord, "seq_gas_target")
	protoWordCitedCount   = word(crypto.TagProtocolWord, "cited_count")
	protoWordPrevParentID = word(crypto.TagProtocolWord, "prev_parent_id")
	protoWordPrevTarget   = word(crypto.TagProtocolWord, "prev_target")
)

// BalanceWord returns the storage word of an asset's balance. Balances of
// different assets under one address are different cells, so a mint cannot
// overflow into another asset and a transfer of one asset never contends with
// a transfer of another.
func BalanceWord(asset Address) [32]byte {
	return crypto.Sum(crypto.TagBalanceWord, asset[:])
}

// BalanceSlot returns the balance cell of (holder, asset).
func BalanceSlot(holder, asset Address) Slot {
	return Slot{Addr: holder, Word: BalanceWord(asset)}
}

// NativeBalanceSlot returns the native-coin balance cell of an address. Every
// fee, deposit and coinbase moves through one of these.
func NativeBalanceSlot(holder Address) Slot {
	return BalanceSlot(holder, NativeAsset)
}

// IsNativeBalanceSlot reports whether a slot is a native-coin balance cell.
// Deposits must name one, which V5 checks statelessly.
func IsNativeBalanceSlot(s Slot) bool { return s.Word == BalanceWord(NativeAsset) }

// TreasurySlot is the cell the block subsidy's treasury share accrues into
// (whitepaper §14.1). It is the protocol address's own native balance, and
// that choice is deliberate rather than incidental: it is an ordinary balance
// cell, so everything that already accounts for native supply — the state
// root, the conservation property, any later audit — counts it without being
// told it exists. A bespoke protocol word would have needed a special case in
// each of them, and a special case nobody adds is how a conservation check
// turns into a rubber stamp.
//
// Certificates can never write it: V7 and F13 reject every write to a 0x00
// address by version byte, so the cell is sealed by the rules that already
// exist rather than by a rule written for it. Era 0 ships no debit path at
// all — the seal is the absence of an operation, which is the only kind of
// seal a chain with no admin keys can offer.
func TreasurySlot() Slot { return NativeBalanceSlot(crypto.ProtocolAddress) }

// SpentSlot returns the canonical slot of an address-wide MARK_SPENT write.
func SpentSlot(a Address) Slot { return Slot{Addr: a, Word: SpentWord} }

// Asset metadata slots.

// AssetCapSlot returns the immutable supply-cap cell of an asset.
func AssetCapSlot(asset Address) Slot { return Slot{Addr: asset, Word: assetWordCap} }

// AssetDecimalsSlot returns the immutable decimals cell of an asset.
func AssetDecimalsSlot(asset Address) Slot { return Slot{Addr: asset, Word: assetWordDecimals} }

// AssetSymbolSlot returns the immutable symbol-hash cell of an asset.
func AssetSymbolSlot(asset Address) Slot { return Slot{Addr: asset, Word: assetWordSymbol} }

// AssetMinterSlot returns the immutable minter-key cell of an asset.
func AssetMinterSlot(asset Address) Slot { return Slot{Addr: asset, Word: assetWordMinter} }

// AssetMintedSlot returns the mutable minted-so-far cell of an asset. It is
// the only asset cell that changes after issue, and it changes only by guarded
// deltas, so unlimited concurrent mints cannot breach the cap.
func AssetMintedSlot(asset Address) Slot { return Slot{Addr: asset, Word: assetWordMinted} }

// Beacon slots.

// BeaconEpochSlot returns the cell holding the current epoch number.
func BeaconEpochSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: beaconWordEpoch}
}

// BeaconHeightSlot returns the cell holding the height at which the current
// epoch began.
func BeaconHeightSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: beaconWordHeight}
}

// BeaconEntropySlot returns the cell holding the epoch's entropy.
//
// The value is proof-of-work output and is therefore miner-grindable (R1-L1):
// it is documented as unfit for high-value lotteries until a verifiable random
// function arrives in Phase 2.
func BeaconEntropySlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: beaconWordEntropy}
}

// SeqBaseFeeSlot returns the cell holding the sequential-market base fee.
func SeqBaseFeeSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: protoWordSeqBaseFee}
}

// ParBaseFeeSlot returns the cell holding the parallel-market base fee.
func ParBaseFeeSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: protoWordParBaseFee}
}

// SeqGasTargetSlot returns the cell holding T, the sequential target the
// epoch controller of whitepaper §8.1 moves. The sequential ceiling is 2T and
// the burst bound is 4T; both are derived from this cell, never stored.
func SeqGasTargetSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: protoWordSeqGasTarget}
}

// CitedCountSlot returns the cell counting competing headers cited so far in
// the current epoch — §8.1's health signal, reset at every epoch boundary
// after being evaluated against the gate.
func CitedCountSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: protoWordCitedCount}
}

// PrevParentIDSlot returns the cell holding the previous block's ParentID —
// the grandparent of the block about to be applied. A citation must name this
// exact id as its own ParentID: that is what makes it a sibling of our
// parent, sharing our parent's parent, rather than an unrelated header.
func PrevParentIDSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: protoWordPrevParentID}
}

// PrevTargetSlot returns the cell holding the previous block's difficulty
// target. A citation must have been mined at this exact target: a sibling of
// our parent was subject to the same difficulty rule our parent was, so a
// cited header claiming an easier target is fabricated, not merely stale.
func PrevTargetSlot() Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: protoWordPrevTarget}
}

// Applied-sequential-gas sample ring (whitepaper §8.1).
//
// One cell per height mod epoch_length, holding that block's applied
// sequential gas. At an epoch boundary the ring's L entries hold exactly the
// applied gas of the epoch that just ended — (H-L) mod L == H mod L == 0 — so
// the epoch controller reads it with no history beyond one epoch's worth of
// cells, the same shape as the coinbase maturity ring below.
func appliedGasSampleWord(index uint64) [32]byte {
	return crypto.Sum(crypto.TagProtocolWord, []byte("applied_gas_sample"), ssz.Uint64(index))
}

// AppliedGasSampleSlot returns the cell holding one epoch position's applied
// sequential gas sample.
func AppliedGasSampleSlot(index uint64) Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: appliedGasSampleWord(index)}
}

// DeriveAssetAddress computes the address an ISSUE certificate creates.
//
// The derivation is (chain id, issuer, seq) rather than the issuing
// certificate id, because the certificate commits to the writes that name the
// address — deriving from the id would be circular. Reusing a seq re-derives
// the same address, and the write-once EXACT reads that ISSUE carries then
// make the duplicate skip against its own earlier issue: self-inflicted, which
// is the only kind of skip Era 0 permits.
func DeriveAssetAddress(chainID uint64, issuer Address, seq uint64) Address {
	return crypto.DeriveAddress(
		crypto.AddrVersionAsset,
		ssz.Uint64(chainID),
		issuer[:],
		ssz.Uint64(seq),
	)
}

// Coinbase maturity ring.
//
// A miner's reward is not spendable for COINBASE_MATURITY blocks. Balances are
// fungible, so no stateless rule can distinguish a young coin from an old one;
// instead the fold keeps a fixed-size ring of pending rewards under the
// protocol address, indexed by height modulo the maturity. The entry the fold
// finds at index (H mod maturity) is always the one written at H − maturity.
//
// Two cells per entry: the payout address (an address is exactly one cell
// value wide) and the amount.
func pendingCoinbaseWord(kind string, index uint64) [32]byte {
	return crypto.Sum(crypto.TagProtocolWord, []byte(kind), ssz.Uint64(index))
}

// PendingCoinbaseAddrSlot returns the cell holding the payout address of the
// pending reward at a ring index.
func PendingCoinbaseAddrSlot(index uint64) Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: pendingCoinbaseWord("coinbase_addr", index)}
}

// PendingCoinbaseAmountSlot returns the cell holding the amount of the pending
// reward at a ring index.
func PendingCoinbaseAmountSlot(index uint64) Slot {
	return Slot{Addr: crypto.ProtocolAddress, Word: pendingCoinbaseWord("coinbase_amount", index)}
}
