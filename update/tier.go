package update

import (
	"fmt"
	"runtime"
	"strings"
)

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
	// TierUnset is the zero value, and it is not a tier.
	//
	// **The devnet-only tier deliberately does NOT get to be the zero value.**
	// It was TierPlain = "" in the first version of this file, which meant a
	// forgotten field, a zero-valued struct or a missing argument silently
	// produced the plain asset key — a tier crossing in exactly the direction
	// this package exists to prevent, arriving through Go's zero value rather
	// than through any decision. PlatformKey refuses it instead.
	TierUnset Tier = ""
	// TierPlain is the reproducible, devnet-only tier.
	TierPlain Tier = "plain"
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
func PlatformKey(goos, goarch string, t Tier) (string, error) {
	if goos == "" || goarch == "" {
		return "", fmt.Errorf("update: platform key needs an os and an arch, got %q and %q", goos, goarch)
	}
	switch t {
	case TierPlain:
		return goos + "-" + goarch, nil
	case TierRandomX:
		return goos + "-" + goarch + "-" + string(TierRandomX), nil
	default:
		// Including TierUnset. An error rather than a default, because the
		// default that felt natural here is the one that breaks a miner.
		return "", fmt.Errorf("update: %q is not a tier; a binary must say which one it is", string(t))
	}
}

// MustPlatformKey is PlatformKey for a caller that has already established the
// tier, such as a test naming a literal.
func MustPlatformKey(goos, goarch string, t Tier) string {
	k, err := PlatformKey(goos, goarch, t)
	if err != nil {
		panic(err)
	}
	return k
}

// LocalPlatformKey is PlatformKey for the running binary.
func LocalPlatformKey(t Tier) (string, error) {
	return PlatformKey(runtime.GOOS, runtime.GOARCH, t)
}

// KeyNamesRandomX reports whether an asset KEY names the mining tier.
//
// A key ends in the tier, so this is a suffix test.
func KeyNamesRandomX(platformKey string) bool {
	return strings.HasSuffix(platformKey, "-"+string(TierRandomX))
}

// FileNamesRandomX reports whether an archive FILE NAME names the mining tier.
//
// Not a suffix test, and that difference is why these are two functions rather
// than one: an archive is `zycord-0.2.0-linux-amd64-randomx.tar.gz`, so the tier
// sits in the middle and a suffix test against it answers false for every file
// there is. Using one helper for both shapes made every well-formed manifest
// fail the key/file agreement check.
func FileNamesRandomX(file string) bool {
	return strings.Contains(file, "-"+string(TierRandomX)+".") ||
		strings.HasSuffix(file, "-"+string(TierRandomX))
}
