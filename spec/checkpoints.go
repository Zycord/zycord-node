package spec

import (
	_ "embed"

	"zycord/core/crypto"
)

// checkpointsJSON is spec/checkpoints.json, embedded for the same reason the
// parameter files are: a binary and the release policy it was built from can
// never drift apart, and the value a release announces is a property of the
// binary you can check.
//
// **It is embedded here and it is NOT part of the protocol.** spec/ is the
// compatibility contract, and checkpoints are deliberately outside it: two
// implementations that disagree about a checkpoint are still the same network,
// whereas two that disagree about a parameter are not. The file lives beside
// the parameter sets because it is release *data* that ships with the binary,
// and it is parsed by node/checkpoints rather than by this package so that
// nothing in the parameter path can reach it. Nothing here feeds
// params.ConsensusRoot(), Hash(), MainnetParamsHash() or TestnetParamsHash() —
// see node/checkpoints/checkpoints_test.go, which pins that.
//
//go:embed checkpoints.json
var checkpointsJSON []byte

// CheckpointsJSON returns the raw bytes of spec/checkpoints.json.
//
// Raw bytes rather than a parsed structure, because the parser belongs to
// node/checkpoints: this package must stay reachable from core/ without
// dragging client release policy along with it.
func CheckpointsJSON() []byte { return append([]byte(nil), checkpointsJSON...) }

// CheckpointsHash is blake3 over the raw checkpoint file, so an operator can
// confirm which release policy a binary carries.
//
// It reuses TagParams for the domain because it is the same "digest of a file
// this build embeds" question; it is deliberately NOT MainnetParamsHash, is
// announced separately, and appears in no consensus preimage anywhere.
func CheckpointsHash() crypto.Hash { return Hash(checkpointsJSON) }
