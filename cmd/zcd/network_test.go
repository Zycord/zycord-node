package main

import (
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/spec"
)

// The property, in one sentence: **--testnet resolves to the parameter set
// embedded in this binary, and naming a second source is refused rather than
// silently ranked.**
//
// The defect it closes: before `--testnet` existed, joining the public testnet
// meant `--params spec/params.testnet.json`: which network a node was on was a
// property of the operator's disk, and the params hash a release announces was
// reachable from Go (spec.TestnetParamsHash) but not from the command line.
//
// The exclusivity half is asserted pair by pair on purpose. The guard covers
// three sources, so it needs three separating inputs — the rule it replaced was
// `path != "" && devnet`, which accepts --params with --testnet and accepts
// --devnet with --testnet, and a single "two flags are refused" case would have
// passed against it.
func TestTestnetResolvesToTheEmbeddedSetAndASecondSourceIsRefused(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)

	for _, tc := range []struct {
		name    string
		devnet  bool
		testnet bool
		want    string
	}{
		{name: "default is mainnet", want: "mainnet"},
		{name: "testnet", testnet: true, want: "testnet"},
		{name: "devnet", devnet: true, want: "devnet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadParams(fs, "", tc.devnet, tc.testnet)
			if err != nil {
				t.Fatalf("loadParams: %v", err)
			}
			want, err := spec.RawFor(tc.want)
			if err != nil {
				t.Fatalf("RawFor(%s): %v", tc.want, err)
			}
			// The WHOLE parsed value, not its name. A name comparison passes
			// against a set that agrees on its label and disagrees on the
			// protocol, which is the failure this flag exists to remove.
			embedded, err := params.Parse(want)
			if err != nil {
				t.Fatalf("parsing the embedded %s: %v", tc.want, err)
			}
			if !reflect.DeepEqual(got, embedded) {
				t.Fatalf("--%s selected %q (chain id %d); the set embedded under that name is "+
					"%q (chain id %d). The flag exists so that the network a node joins is a "+
					"property of the binary and not of a file a node happens to find",
					tc.want, got.Name, got.ChainID, embedded.Name, embedded.ChainID)
			}
		})
	}

	// Every pair, and the triple. Each row separates one term of the guard.
	for _, tc := range []struct {
		name    string
		path    string
		devnet  bool
		testnet bool
	}{
		{name: "params and testnet", path: "spec/params.testnet.json", testnet: true},
		{name: "params and devnet", path: "spec/params.devnet.json", devnet: true},
		{name: "devnet and testnet", devnet: true, testnet: true},
		{name: "all three", path: "spec/params.json", devnet: true, testnet: true},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			_, err := loadParams(fs, tc.path, tc.devnet, tc.testnet)
			if err == nil {
				t.Fatalf("loadParams accepted %s and picked one of them silently. Two sources "+
					"for the protocol a node speaks is an operator who believes they are on a "+
					"network they are not; it has to be refused, not ranked", tc.name)
			}
			if !strings.Contains(err.Error(), "mutually exclusive") {
				t.Errorf("the refusal reads %q; it must say which flags conflict", err)
			}
		})
	}
}

// The property, in one sentence: **the params hash `zcd genesis` prints for a
// network is taken over the same embedded bytes its parameters were parsed
// from, for every embedded network.**
//
// A release announcement commits to a params hash and a genesis id together.
// They used to be resolved by two separate ladders in cmdGenesis — one for the
// parsed set, one for the raw bytes — and a network added to one and not the
// other prints a mainnet hash beside a testnet genesis, which is an
// announcement that commits to nothing. Asserted over spec.Networks() rather
// than over the network that happened to be added, so the next one cannot be
// half-wired either.
func TestEveryEmbeddedNetworkPairsItsRawBytesWithItsParameters(t *testing.T) {
	for _, n := range spec.Networks() {
		// mainnet is the default, and has no flag of its own.
		var args []string
		if n != "mainnet" {
			args = append(args, "--"+n)
		}
		out := runGenesis(t, args...)
		raw, err := spec.RawFor(n)
		if err != nil {
			t.Fatalf("RawFor(%s): %v", n, err)
		}
		p, err := params.Parse(raw)
		if err != nil {
			t.Fatalf("parsing the embedded %s: %v", n, err)
		}
		if got := out["network"]; got != p.Name {
			t.Errorf("`zcd genesis --%s` reports network %q; the embedded set of that name is "+
				"%q", n, got, p.Name)
		}
		if got, want := out["params hash"], hexOf(spec.Hash(raw)); got != want {
			t.Errorf("`zcd genesis --%s` prints params hash %s over some other file; the bytes "+
				"its parameters were parsed from hash to %s. A params hash and a genesis id "+
				"from two different files commit to nothing", n, got, want)
		}
		if n == "testnet" {
			if got, want := out["params hash"], hexOf(spec.TestnetParamsHash()); got != want {
				t.Errorf("`zcd genesis --testnet` prints params hash %s; the value this binary "+
					"announces is %s", got, want)
			}
		}
	}
}

// runGenesis runs cmdGenesis for real and returns its report as label -> value.
// Reading the printed report rather than re-deriving it in the test is the
// point: the two ladders this pins live INSIDE cmdGenesis, so a test that only
// calls loadParams and RawFor agrees with itself no matter what cmdGenesis
// hashes.
func runGenesis(t *testing.T, args ...string) map[string]string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	runErr := cmdGenesis(args)
	os.Stdout = saved
	w.Close()
	buf, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	if runErr != nil {
		t.Fatalf("zcd genesis %v: %v", args, runErr)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(buf), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		out[strings.Join(fields[:len(fields)-1], " ")] = fields[len(fields)-1]
	}
	if len(out) == 0 {
		t.Fatalf("zcd genesis %v printed nothing this check can read", args)
	}
	return out
}
