package wiring_test

import (
	"regexp"
	"strings"
	"testing"
)

// The published checksum commands, and the flag that decides whether a good
// download looks like a bad one.
//
// This used to live in release_key_test.go, which asserted the whole
// GPG-signing chain and went when that chain did. The defect below has nothing
// to do with signing: it is about a verification command a reader is told to
// run, and it survives every change to what the release is verified WITH.

// installShPath is the installer this and the docs must agree with.
var installShPath = repoRoot + "/packaging/install.sh"

// checksumCommand matches a whole checksum invocation, stopping at a comment,
// a pipe or a statement separator.
//
// It is deliberately not line-wide. The bug this was written for had the flag
// on one platform's command and not the other's, on the same line of a
// two-command block, so a line-wide search found the flag in the Linux command
// and passed the macOS one that was missing it. A check that the bug itself
// satisfies is worse than no check.
var checksumCommand = regexp.MustCompile(`(?:sha256sum|shasum -a 256)[^\n#|&;)]*`)

// checkFlag matches the verify mode of either spelling, so a plain hashing
// command (`sha256sum bin/zcd`) is not held to a flag that does not apply.
var checkFlag = regexp.MustCompile(`(?:^|\s)(?:--check|-c)(?:\s|$)`)

// TestEveryPublishedChecksumCommandIgnoresMissingFiles is about how a real
// warning is made ignorable.
//
// SHA256SUMS lists every archive the release publishes and a user downloads
// one. Without --ignore-missing, `sha256sum --check` reports the archives that
// are not there as FAILED and exits non-zero — several failures and a non-zero
// exit for a perfectly good download, on the very page that says a mismatch
// means a compromised binary. Teach that once and the reader learns to skip it.
func TestEveryPublishedChecksumCommandIgnoresMissingFiles(t *testing.T) {
	for _, path := range []string{installDocPath, installShPath} {
		for _, line := range checksumCommand.FindAllString(readRepoFile(t, path), -1) {
			if !checkFlag.MatchString(line) {
				continue // hashing something, not verifying against SHA256SUMS.
			}
			if strings.Contains(line, "--ignore-missing") {
				continue
			}
			t.Errorf("%s publishes a checksum command without --ignore-missing:\n"+
				"    %s\n"+
				"SHA256SUMS covers every archive in the release and the reader has one\n"+
				"of them, so this command reports the rest as FAILED and exits 1 for a\n"+
				"good download. packaging/install.sh already builds both spellings with\n"+
				"the flag; the documented command has to match it.",
				path, strings.TrimSpace(line))
		}
	}
}
