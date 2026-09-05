// Shared helpers for the wiring guards.
//
// These were extracted verbatim from anonymity_test.go, which is where they
// grew up. They live here because they are ordinary infrastructure rather than
// part of any one guard: `trackedFiles` enumerates what publication would copy,
// `reason` reports a failure by class instead of by value, and `isText` is the
// whole-file NUL rule the scans share. anonymity_test.go, github_url_test.go
// and history_reference_test.go all depend on them, so a file that is about
// none of the three is the honest home for them.

package wiring_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// vendored is upstream RandomX, carried verbatim.
const vendored = "core/pow/randomx/upstream/"

// trackedEntry is one row of the index: what publication would copy, and in
// what form.
type trackedEntry struct {
	mode string
	path string
}

func (e trackedEntry) symlink() bool { return e.mode == "120000" }
func (e trackedEntry) gitlink() bool { return e.mode == "160000" }

func names(entries []trackedEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.path)
	}
	return out
}

// trackedFiles is what publication would copy, in repository-relative form.
//
// This shells out rather than walking the directory because the two are not the
// same set and the difference is the whole point: `bin/`, `dist/` and a local
// devnet are in the working directory and are not published, while a build
// artefact committed by accident is published and looks exactly like them. The
// mode comes with it, because a symlink and a regular file are read very
// differently and only one of them is what it appears to be.
func trackedFiles(t *testing.T, root string) []trackedEntry {
	t.Helper()

	out, err := exec.Command("git", "-C", root, "ls-files", "-s", "-z").Output()
	if err != nil {
		// **Not a skip.** `make wiring` runs without -v and is the recipe
		// RELEASE.md §3 names for the pre-release audit, so a skip here prints
		// `ok` for a run that asserted nothing -- a green light meaning "git was
		// not on PATH". If the tree cannot be enumerated, the audit failed.
		t.Fatalf("git ls-files: %s\n\n"+
			"This test's subject is the tree that will be published, and git is "+
			"how that tree is named. It fails rather than skips: `make wiring` "+
			"runs without -v, so a skip here is indistinguishable from a pass "+
			"and RELEASE.md §3 would read it as an audit.", reason(err))
	}

	var entries []trackedEntry
	for _, row := range bytes.Split(out, []byte{0}) {
		if len(row) == 0 {
			continue
		}
		// "<mode> <sha> <stage>\t<path>"
		meta, path, found := strings.Cut(string(row), "\t")
		if !found {
			t.Fatalf("git ls-files -s: unparsable row %q", row)
		}
		entries = append(entries, trackedEntry{
			mode: strings.SplitN(meta, " ", 2)[0],
			path: path,
		})
	}
	if len(entries) == 0 {
		t.Fatal("git ls-files returned nothing: the scan would pass by reaching " +
			"no file, and its silence would mean nothing")
	}
	return entries
}

// reason describes a failure by its class and never by its value.
//
// **Every error string these tests could print quotes something, and both
// sources quote something that should not be published.** The operating system
// quotes itself in the author's system language, so `%v` on a failed open puts
// a locale in the output — and a failure message is the text most likely to be
// pasted into a public issue, which makes the guard's own diagnostics a leak
// path for the timezone/locale class it exists to catch. The second source was
// `regexp`, which quotes the offending expression back: the guards once
// compiled the identity patterns at run time, so a typo in that untracked file
// would print the real name or the handle verbatim — the anti-leak tool
// publishing the exact secret it was built to protect. That loader is gone and
// every pattern here is now a tracked literal, which retires the second source
// but not the first, and not the rule.
//
// So: the class, never the value. An exit code and an errno category are facts
// about what went wrong and are the same in every language.
func reason(err error) string {
	switch {
	case err == nil:
		return "no error"
	case errors.Is(err, fs.ErrNotExist):
		return "does not exist"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, exec.ErrNotFound):
		return "not found on PATH"
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "exited " + strconv.Itoa(exit.ExitCode())
	}
	return "unreadable"
}

// isText reports whether the whole file is free of NUL bytes.
//
// Deliberately stricter than git's own rule, which looks only at the first
// 8 KiB. The opacity test's guarantee is "the text scan read all of this", and
// a head-only rule cannot make that promise about the tail.
func isText(body []byte) bool { return !bytes.ContainsRune(body, 0) }
