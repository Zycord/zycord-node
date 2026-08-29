package main

import (
	"strings"
	"testing"

	"zycord/core/pow/randomx"
)

// TestVersionNamesTheEngineThisBinaryCarries pins the second line of
// `zcd version`.
//
// The failure it guards — a release shipping binaries nobody could join a
// network with — is not a formatting failure. A build without the `randomx`
// tag refuses to start on mainnet and on the public testnet, because both
// parameter sets declare pow_engine randomx-v1 — and before this line existed
// there was nowhere a downloader could read that off the binary they had. `zcd
// params` prints what the network requires, not what the build carries; the
// two questions have the same words in the answer and only one of them is
// about the file on disk.
//
// The test is written from randomx.Available() rather than from a build tag of
// its own, so it says something in BOTH builds: the tagless one must warn, and
// the tagged one must not.
func TestVersionNamesTheEngineThisBinaryCarries(t *testing.T) {
	var b strings.Builder
	cmdVersion(&b)
	out := b.String()

	// The first line is a contract with packaging/install.sh (which runs this
	// command as its last act) and with the Homebrew formula's `test do` block.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if want := "zcd " + version; lines[0] != want {
		t.Errorf("first line is %q, want %q", lines[0], want)
	}
	if len(lines) < 2 {
		t.Fatalf("no engine line at all:\n%s", out)
	}
	if !strings.HasPrefix(lines[1], "proof of work: ") {
		t.Errorf("second line is %q, want it to start with %q", lines[1], "proof of work: ")
	}

	// Either way the engine mainnet requires is named, because a warning that
	// does not name what is missing cannot be matched against `zcd params`.
	if !strings.Contains(out, randomx.Name) {
		t.Errorf("the output never names %q:\n%s", randomx.Name, out)
	}

	if randomx.Available() {
		if strings.Contains(out, "refuses to start") {
			t.Errorf("a build that carries the engine warns that it refuses to start:\n%s", out)
		}
		// The tier this binary is in has to be stated on the binary itself:
		// it is cgo, so it is not byte-identical and docs/RELEASE.md §5
		// forbids it a line in SHA256SUMS.binaries.
		if !strings.Contains(out, "SHA256SUMS.binaries") {
			t.Errorf("a cgo build does not say it is outside the attested tier:\n%s", out)
		}
		return
	}

	if !strings.Contains(out, "refuses to start") {
		t.Errorf("a build without the engine does not say it refuses to start:\n%s", out)
	}
	if !strings.Contains(out, "devnet") {
		t.Errorf("a build without the engine does not say which network it can run:\n%s", out)
	}
	// A warning with no route out of it is a dead end. The one thing an
	// operator needs next is where the runnable binary comes from.
	if !strings.Contains(out, "-randomx") {
		t.Errorf("a build without the engine does not say where to get one that works:\n%s", out)
	}
}
