package update

import "runtime"

// Tier is which of the two disjoint release tiers a binary belongs to.
//
// docs/INSTALL.md, "Two tiers of assurance", is the authority and the summary
// is this: the plain archives are byte-reproducible and DEVNET-ONLY, because
// pure Go carries no RandomX engine; the -randomx archives join mainnet and the
// public testnet and are reproducible nowhere, because cgo is. There is no
// third archive that is both.
//
// For an updater the consequence is sharp. Replacing a -randomx binary with a
// plain one takes a machine that mines and leaves it with a binary that refuses
// to start on any real network — a working miner turned into a broken one, by
// an update the operator asked for.
type Tier string

const (
	// TierPlain is the reproducible, devnet-only tier.
	TierPlain Tier = ""
	// TierRandomX is the tier that can mine.
	TierRandomX Tier = "randomx"
)

// TierFor maps "does this binary carry the RandomX engine" to a tier.
//
// The answer is passed in rather than read here, and update/ does not import
// core/pow/randomx. Two reasons: this package stays free of a cgo-adjacent
// import, so `go test ./update/...` is trivially pure; and the tier becomes an
// explicit input, so a test can exercise BOTH tiers. Reading a build-tag global
// instead would leave the tier-mismatch test able to check only whichever tier
// the test binary happened to be compiled as, which is the same trap
// cmd/zcd/version_test.go had to work around.
func TierFor(randomxAvailable bool) Tier {
	if randomxAvailable {
		return TierRandomX
	}
	return TierPlain
}

// PlatformKey is the manifest key for one platform and tier: "linux-amd64",
// "linux-amd64-randomx", "windows-arm64".
//
// **This is the only constructor of an asset key, and that is the whole
// mechanism by which a tier can never be crossed.** The tier is part of the
// key rather than a field beside it, so a running binary computes exactly one
// key and the manifest either has it or does not. There is no lookup that
// could fall back, because there is no code path that constructs the other
// key — which is a stronger guarantee than any `if` guarding a comparison.
func PlatformKey(goos, goarch string, t Tier) string {
	k := goos + "-" + goarch
	if t != TierPlain {
		k += "-" + string(t)
	}
	return k
}

// LocalPlatformKey is PlatformKey for the running binary.
func LocalPlatformKey(t Tier) string {
	return PlatformKey(runtime.GOOS, runtime.GOARCH, t)
}
