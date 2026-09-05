package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/spec"
)

// The property, in one sentence: **--testnet resolves to the parameter set
// embedded in this binary, and naming a second source is refused rather than
// silently ranked.**
//
// Until --testnet landed, joining the public testnet meant `--params
// spec/params.testnet.json`, so which network a node was on was a property of
// the operator's disk. The set is embedded and its genesis is pinned by a
// vector, so the flag makes it a property of the binary.
//
// The exclusivity half is asserted pair by pair on purpose. The rule it
// replaced was `path != "" && devnet`: that accepts --params with --testnet,
// and accepts --devnet with --testnet, so a single "two flags are refused" case
// would have passed against it unchanged.
func TestTestnetResolvesToTheEmbeddedSetAndASecondSourceIsRefused(t *testing.T) {
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
			got, err := loadParams("", tc.devnet, tc.testnet)
			if err != nil {
				t.Fatalf("loadParams: %v", err)
			}
			raw, err := spec.RawFor(tc.want)
			if err != nil {
				t.Fatalf("RawFor(%s): %v", tc.want, err)
			}
			// The WHOLE parsed value, not its name. A name comparison passes
			// against a set that agrees on its label and disagrees on the
			// protocol, which is the failure this flag exists to remove.
			embedded, err := params.Parse(raw)
			if err != nil {
				t.Fatalf("parsing the embedded %s: %v", tc.want, err)
			}
			if !reflect.DeepEqual(got, embedded) {
				t.Fatalf("--%s selected %q (chain id %d); the set embedded under that name is "+
					"%q (chain id %d). A node must join the network its flag names, not one "+
					"that happens to be nearby",
					tc.want, got.Name, got.ChainID, embedded.Name, embedded.ChainID)
			}
		})
	}

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
			_, err := loadParams(tc.path, tc.devnet, tc.testnet)
			if err == nil {
				t.Fatalf("loadParams accepted %s and picked one of them silently. A node whose "+
					"operator gave two sources for the protocol it speaks may be on a network "+
					"neither of them meant; that has to be refused, not ranked", tc.name)
			}
			if !strings.Contains(err.Error(), "mutually exclusive") {
				t.Errorf("the refusal reads %q; it must say which flags conflict", err)
			}
		})
	}
}

// The property, in one sentence: **both binaries expose --testnet, or neither
// does.**
//
// This is why the flag was added to both binaries as one change rather than
// two: giving one a --testnet and not the other is a worse state than neither
// having it. An operator who starts `zycordd --testnet` and then reaches for
// `zcd genesis --testnet` to check the params hash the node announced, and
// finds the flag missing there, has no way to verify what the node joined —
// which is the whole point of embedding the set.
//
// Checked across the two packages by reading cmd/zcd's source, because nothing
// else can: they are two separate main packages and neither imports the other,
// so no compile-time or runtime check inside either one can see the pair.
func TestBothBinariesSelectTheTestnetByFlag(t *testing.T) {
	// Every network flag has to appear in both, not just the new one. Listing
	// the whole surface is what makes the check about the PAIR staying in step
	// rather than about one flag that happens to be present today.
	want := []string{"params", "devnet", "testnet"}

	for _, dir := range []struct{ binary, path string }{
		{"zycordd", "."},
		{"zcd", "../zcd"},
	} {
		got := flagNames(t, dir.path)
		for _, name := range want {
			if !got[name] {
				t.Errorf("%s does not register a --%s flag, but the other binary does. The "+
					"network selection surface moves in one step for both or the operator "+
					"cannot check on one what the other did", dir.binary, name)
			}
		}
	}
}

// flagNames returns the flag names a main package registers, read off the
// string literal each fs.Bool/fs.String call names them by.
func flagNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}
	pkg, ok := pkgs["main"]
	if !ok {
		t.Fatalf("no package main in %s", dir)
	}
	names := map[string]bool{}
	for _, f := range pkg.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Bool" && sel.Sel.Name != "String") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			names[name] = true
			return true
		})
	}
	if len(names) == 0 {
		t.Fatalf("%s registers no flags at all; this check cannot see the surface it is "+
			"meant to compare", dir)
	}
	return names
}
