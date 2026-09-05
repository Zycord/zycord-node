//go:build !randomx

package randomx

import "zycord/core/pow"

// Available reports whether this binary carries the RandomX engine.
//
// It is false in every build without the `randomx` tag, which is the default
// one: `make build` sets CGO_ENABLED=0 and produces a binary that can run a
// development network and cannot run a RandomX one. cmd/zycordd turns that
// into a refusal at startup rather than a wrong answer at height 1 — a node
// holding the development engine against a network whose pow_engine says
// randomx-v1 would accept a single BLAKE3 pass as proof of work for every
// header it ever saw.
func Available() bool { return false }

// New returns ErrNotBuilt. The signature matches the cgo build's exactly, so a
// caller compiles identically either way and the difference is a runtime error
// with a sentence in it rather than a build failure with a stack trace.
func New(Options) (pow.Engine, error) { return nil, ErrNotBuilt }
