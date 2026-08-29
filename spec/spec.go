// Package spec embeds the protocol.
//
// spec/ is not documentation about the protocol — it *is* the protocol. The
// parameter files and the golden vectors are the compatibility contract; the
// Go code in core/ is one implementation of them, and an independent
// implementation that passes the vectors is a peer, not a fork.
//
// Embedding rather than reading from disk is deliberate: a binary and the
// parameter file it was built from can never drift apart, and the parameter
// hash a release announces is a property of the binary you can check.
package spec

import (
	_ "embed"
	"fmt"

	"zycord/core/crypto"
	"zycord/core/params"
)

//go:embed params.json
var mainnetJSON []byte

//go:embed params.devnet.json
var devnetJSON []byte

//go:embed params.testnet.json
var testnetJSON []byte

// MainnetJSON returns the raw bytes of spec/params.json.
func MainnetJSON() []byte { return append([]byte(nil), mainnetJSON...) }

// DevnetJSON returns the raw bytes of spec/params.devnet.json.
func DevnetJSON() []byte { return append([]byte(nil), devnetJSON...) }

// TestnetJSON returns the raw bytes of spec/params.testnet.json.
func TestnetJSON() []byte { return append([]byte(nil), testnetJSON...) }

// Mainnet returns the frozen parameter set of the main network.
func Mainnet() *params.Params { return mustParse(mainnetJSON, "params.json") }

// Devnet returns the parameter set of the throwaway development network:
// short epochs, short TTLs and a trivial proof-of-work target, so that a single
// laptop can exercise every boundary the main network reaches once a day.
func Devnet() *params.Params { return mustParse(devnetJSON, "params.devnet.json") }

// Testnet returns the parameter set of the public testnet: mainnet in every
// value except the six spec/params.testnet.json's PURPOSE note names, so that
// the numbers docs/decisions/testnet-measurements.md is waiting for are
// measurements of mainnet's economics rather than of a convenient one.
//
// It is embedded for the same reason the other two are: until it was, the one
// network about to carry real traffic was the one whose parameters a binary
// read from disk, which is the drift this package exists to prevent.
func Testnet() *params.Params { return mustParse(testnetJSON, "params.testnet.json") }

// Networks names every parameter set this binary embeds. It is the list
// ParamsFor resolves, and the list spec/vectors must carry a genesis vector
// for: a fourth parameter set added without one fails
// TestEveryEmbeddedNetworkHasAPinnedGenesis rather than passing silently,
// which is exactly how the testnet set stayed unpinned: it was a real network
// with no genesis vector, and nothing in the corpus noticed.
func Networks() []string { return []string{"mainnet", "testnet", "devnet"} }

// RawFor returns the embedded bytes of a named parameter set. It is what makes
// "every parameter file in spec/ is embedded" checkable from outside the
// package: a file on disk that no name here resolves to is a network shipped
// outside the compatibility contract — which is precisely the state the
// testnet parameter file was in before it was embedded above.
func RawFor(name string) ([]byte, error) {
	switch name {
	case "mainnet":
		return MainnetJSON(), nil
	case "testnet":
		return TestnetJSON(), nil
	case "devnet":
		return DevnetJSON(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownParams, name)
	}
}

// Hash returns blake3 over a raw parameter file. A release announces this
// value alongside the genesis id, and anyone can recompute both.
func Hash(raw []byte) crypto.Hash {
	return crypto.Sum(crypto.TagParams, raw)
}

// MainnetParamsHash is the value a launch announcement commits to.
func MainnetParamsHash() crypto.Hash { return Hash(mainnetJSON) }

// TestnetParamsHash is the same commitment for the public testnet: the value a
// testnet launch announcement publishes, recomputable from the binary alone.
func TestnetParamsHash() crypto.Hash { return Hash(testnetJSON) }

func mustParse(raw []byte, name string) *params.Params {
	p, err := params.Parse(raw)
	if err != nil {
		// A malformed embedded parameter file is a broken build, not a runtime
		// condition: there is no sensible way to continue without a protocol.
		panic(fmt.Sprintf("spec: %s is not a valid parameter set: %v", name, err))
	}
	return p
}
