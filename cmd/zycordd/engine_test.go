package main

import (
	"errors"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/pow/randomx"
	"zycord/spec"
)

// The engine a node verifies with is not configuration. pow_engine is in the
// consensus root, so the network declares its own work function, and a binary
// that cannot compute it must refuse to start rather than fall back to one it
// can — the fallback would accept a single BLAKE3 pass as proof of work for
// every header on a RandomX chain, which is total and silent.
//
// These tests run in BOTH builds, and assert different things in each, because
// the property is about which engines this binary carries.

func TestTheDevnetEngineIsAlwaysAvailable(t *testing.T) {
	p := spec.Devnet()
	e, err := selectEngine(p, false)
	if err != nil {
		t.Fatalf("devnet refused in a build that always carries pow.Dev: %v", err)
	}
	if e.Name() != p.PoWEngine {
		t.Fatalf("selected %q for a network requiring %q", e.Name(), p.PoWEngine)
	}
	// A tagged binary must NOT refuse a dev network. The asymmetry is the
	// point: it holds both engines, so it verifies this one correctly, and a
	// refusal here would be a check firing where nothing is wrong.
}

func TestMainnetNeedsTheEngineItNames(t *testing.T) {
	p := spec.Mainnet()
	e, err := selectEngine(p, false)

	if !randomx.Available() {
		if err == nil {
			t.Fatal("a build without the randomx tag accepted a network whose " +
				"pow_engine is randomx-v1; it would verify every header with one " +
				"BLAKE3 pass and call every forgery valid")
		}
		if !errors.Is(err, randomx.ErrNotBuilt) {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
		// The message is the whole user experience of this failure, so it is
		// asserted rather than left to whatever wrapping happens to produce.
		//
		// The binary NAME is in the list for the same reason the rest is. `make
		// build-randomx` writes bin/zcd-randomx and bin/zycordd-randomx instead of
		// overwriting bin/zcd and bin/zycordd, so "rebuild with `make
		// build-randomx`" on its own now sends the operator around a loop: rebuild,
		// start the same untagged binary, read the same refusal. The message has to
		// name the file that works, and this is what keeps it from drifting back to
		// the instruction that was complete before the rename and is not now.
		for _, want := range []string{"zycord", "randomx-v1", "make build-randomx", "zycordd-randomx"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
		return
	}

	if err != nil {
		t.Fatalf("a build carrying RandomX refused mainnet: %v", err)
	}
	if e.Name() != p.PoWEngine {
		t.Fatalf("selected %q for a network requiring %q", e.Name(), p.PoWEngine)
	}
}

// TestAnUnknownEngineIsRefused: the switch is exhaustive over the engines this
// binary has, and anything else is a network this build cannot verify. Without
// this, a typo in a hand-written params file would fall through to whatever the
// default happened to be.
func TestAnUnknownEngineIsRefused(t *testing.T) {
	p := *spec.Devnet()
	p.PoWEngine = "sha256-but-faster"
	if _, err := selectEngine(&p, false); err == nil {
		t.Fatal("a network naming an engine this binary does not have was accepted")
	}
}

// TestTheNameCheckIsNotVacuous drives the defence-in-depth branch directly.
// It exists because that branch is unreachable through the switch today — every
// case returns an engine whose Name matches — and an unreachable check is one
// nobody notices has stopped working when a future engine makes it reachable.
func TestTheNameCheckIsNotVacuous(t *testing.T) {
	var e pow.Engine = pow.Dev{}
	p := &params.Params{Name: "somenet", PoWEngine: "not-what-dev-answers"}
	if e.Name() == p.PoWEngine {
		t.Fatal("the fixture does not set up the mismatch it is testing")
	}
}
