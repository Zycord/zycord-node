package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"zycord/update"
)

// TestTheUpdateQuestionIsAskedOnceAndDefaultsToNotify.
//
// Enter takes notify, and that is the decision this test exists to hold.
//
// NOT auto: a program that rewrites its own executable because somebody pressed
// Enter has taken consent it was not given. NOT never: the default has to keep a
// miner reachable by a security release, and a notice does that while touching
// nothing. Everything else about the prompt can be reworded; this cannot change
// without a reason.
func TestTheUpdateQuestionIsAskedOnceAndDefaultsToNotify(t *testing.T) {
	for _, tc := range []struct {
		typed string
		want  update.Mode
	}{
		{"a\n", update.ModeAuto},
		{"auto\n", update.ModeAuto},
		{"A\n", update.ModeAuto},
		{"n\n", update.ModeNotify},
		{"notify\n", update.ModeNotify},
		{"\n", update.ModeNotify},      // Enter
		{"  \n", update.ModeNotify},    // whitespace is Enter
		{"x\n", update.ModeNever},      //
		{"never\n", update.ModeNever},  //
		{"", update.ModeNotify},        // EOF: a dropped session is not a refusal
		{"what?\n", update.ModeNotify}, // unrecognised, then the default
	} {
		t.Run(strings.TrimSpace(tc.typed), func(t *testing.T) {
			var out strings.Builder
			got := askAboutUpdates(strings.NewReader(tc.typed), &out)
			if got != tc.want {
				t.Errorf("typing %q gave %q, want %q", tc.typed, got, tc.want)
			}
			if !strings.Contains(out.String(), "zcd update --print-source") {
				t.Error("the prompt does not point at where the trust model is explained, " +
					"which is the whole reason it is allowed to be short")
			}
		})
	}
}

// TestTheQuestionNeverLoopsOnAClosedStdin.
//
// A terminal whose stdin closes mid-session must not spin. The failure this
// prevents is a node that never starts, which is worse than any update policy.
func TestTheQuestionNeverLoopsOnAClosedStdin(t *testing.T) {
	done := make(chan update.Mode, 1)
	go func() {
		var out strings.Builder
		done <- askAboutUpdates(strings.NewReader(""), &out)
	}()
	select {
	case got := <-done:
		if got != update.ModeNotify {
			t.Errorf("= %q, want the default", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("askAboutUpdates did not return on a closed stdin")
	}
}

// TestAReplacementMustAcceptTheCommandLineWeWereStartedWith.
//
// The restart passes os.Args verbatim, so a release that removes or renames a
// flag makes the new binary reject the command line the old one was started
// with. The node then exits at flag parsing — and it is already running the new
// binary, so restarting does not help. An end-to-end run produced exactly that.
//
// The probe runs the replacement with this process's own arguments plus
// --version, which parses the whole flag set and returns before the data
// directory is touched.
func TestAReplacementMustAcceptTheCommandLineWeWereStartedWith(t *testing.T) {
	// The stand-ins below are shell scripts, which Windows will not execute.
	// runtime.GOOS, never os.Getenv("GOOS") - GOOS is a build constant, and
	// reading it as an environment variable is how a skip silently never fires.
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in binaries here are shell scripts")
	}
	dir := t.TempDir()

	// A "binary" that accepts anything.
	ok := filepath.Join(dir, "ok")
	writeScript(t, ok, "exit 0")
	if err := acceptsOurCommandLine(ok); err != nil {
		t.Errorf("a replacement that accepts our arguments was refused: %v", err)
	}

	// One that refuses, the way flag.ExitOnError does on an unknown flag.
	bad := filepath.Join(dir, "bad")
	writeScript(t, bad, "echo 'flag provided but not defined: -update' >&2; exit 2")
	err := acceptsOurCommandLine(bad)
	if err == nil {
		t.Fatal("a replacement that cannot be started with our arguments was accepted")
	}
	if !strings.Contains(err.Error(), "not defined") {
		t.Errorf("err = %v, want it to carry the binary's own complaint so an operator can see "+
			"WHICH flag is the problem", err)
	}

	// And one that is not executable at all.
	if err := acceptsOurCommandLine(filepath.Join(dir, "missing")); err == nil {
		t.Error("a replacement that does not exist was accepted")
	}
}

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
