package update_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"zycord/update"
)

// TestPrefsRoundTrip, including that the file lands inside the data directory
// rather than somewhere the node's --dir does not describe.
func TestPrefsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := update.Prefs{
		Mode:            update.ModeNotify,
		Asked:           true,
		LastCheck:       time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		DeclinedVersion: "v0.3.0",
		RevokedKeys:     []string{"zu1"},
	}
	if err := update.SavePrefs(dir, want); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(update.PrefsPath(dir)) != dir {
		t.Errorf("prefs landed outside the data directory: %s", update.PrefsPath(dir))
	}
	got, note := update.LoadPrefs(dir)
	if note != "" {
		t.Errorf("note = %q, want none", note)
	}
	if got.Mode != want.Mode || !got.Asked || got.DeclinedVersion != want.DeclinedVersion {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !got.LastCheck.Equal(want.LastCheck) {
		t.Errorf("LastCheck = %v, want %v", got.LastCheck, want.LastCheck)
	}
	if !got.IsRevoked("zu1") || got.IsRevoked("zu2") {
		t.Errorf("RevokedKeys round-tripped wrong: %v", got.RevokedKeys)
	}
}

// TestPrefsAreWrittenSoOnlyThisUserCanChangeThem.
//
// The file holds no secret. It decides whether this machine downloads and
// executes new code, which is not something another account on the box should be
// able to edit.
func TestPrefsAreWrittenSoOnlyThisUserCanChangeThem(t *testing.T) {
	// runtime.GOOS, not os.Getenv("GOOS"): GOOS is a build constant, and there
	// is no environment variable of that name at run time. Reading it as one
	// made this skip never fire, so the assertion below ran on Windows - where
	// Go's Chmod controls only the read-only bit and the mode is -rw-rw-rw- -
	// and failed there while passing everywhere the author could see.
	if runtime.GOOS == "windows" {
		t.Skip("Go's Chmod on Windows controls only the read-only bit, so 0600 is not " +
			"expressible; the file's protection there is the directory ACL it inherits")
	}
	dir := t.TempDir()
	if err := update.SavePrefs(dir, update.Prefs{Mode: update.ModeAuto}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(update.PrefsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %v, want 0600", perm)
	}
}

// TestANodeNeverRefusesToStartOverAPreferenceFile is the property that matters
// most in this file.
//
// A missing file is what every node looks like before it has been asked. A
// corrupt one is a file somebody edited, a disk that lied, or a crash mid-write.
// The worst outcome of ignoring either is that an operator is asked a question
// again. The worst outcome of failing on them is a miner whose node will not
// come up and who has no idea why — over a preferences file.
func TestANodeNeverRefusesToStartOverAPreferenceFile(t *testing.T) {
	t.Run("missing is silent", func(t *testing.T) {
		p, note := update.LoadPrefs(t.TempDir())
		if note != "" {
			t.Errorf("note = %q; a node that has never been asked is not a problem to report", note)
		}
		if p.Mode != update.ModeUnset || p.Asked {
			t.Errorf("got %+v, want the zero policy", p)
		}
	})

	for _, tc := range []struct{ name, body string }{
		{"not json", "{{{"},
		{"truncated mid-write", `{"mode":"noti`},
		{"a mode this build does not know", `{"mode":"telepathy","asked":true}`},
		{"the wrong shape entirely", `[1,2,3]`},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(update.PrefsPath(dir), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			p, note := update.LoadPrefs(dir)
			if note == "" {
				t.Error("a damaged preference file was accepted silently")
			}
			if p.Mode != update.ModeUnset {
				t.Errorf("Mode = %q, want the zero policy", p.Mode)
			}
			if !strings.Contains(note, "update.json") {
				t.Errorf("note = %q, want it to name the file", note)
			}
		})
	}
}

// TestParseMode, including that an unset mode is not the same as never.
//
// The two behave identically on a server — neither contacts anything — but they
// mean different things on a terminal, where one is a question to ask once and
// the other is an answer already given.
func TestParseMode(t *testing.T) {
	for _, tc := range []struct {
		in     string
		want   update.Mode
		ok     bool
		checks bool
	}{
		{"", update.ModeUnset, true, false},
		{"auto", update.ModeAuto, true, true},
		{"AUTO", update.ModeAuto, true, true},
		{"  notify  ", update.ModeNotify, true, true},
		{"never", update.ModeNever, true, false},
		{"sometimes", update.ModeUnset, false, false},
		{"yes", update.ModeUnset, false, false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := update.ParseMode(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("ParseMode(%q) = %v", tc.in, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ParseMode(%q) accepted", tc.in)
				}
				return
			}
			if got != tc.want {
				t.Errorf("= %q, want %q", got, tc.want)
			}
			if got.Checks() != tc.checks {
				t.Errorf("%q.Checks() = %v, want %v", got, got.Checks(), tc.checks)
			}
		})
	}
	if update.ModeUnset == update.ModeNever {
		t.Error("unset and never are the same value, so a node cannot tell " +
			"'nobody has been asked' from 'somebody said no'")
	}
}

// TestSavingPrefsIsAtomic. A crash mid-write must not leave a file that parses
// as something nobody chose.
func TestSavingPrefsIsAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := update.SavePrefs(dir, update.Prefs{Mode: update.ModeNotify, Asked: true}); err != nil {
		t.Fatal(err)
	}
	if err := update.SavePrefs(dir, update.Prefs{Mode: update.ModeAuto, Asked: true}); err != nil {
		t.Fatal(err)
	}
	got, note := update.LoadPrefs(dir)
	if note != "" || got.Mode != update.ModeAuto {
		t.Errorf("got %+v note %q, want auto", got, note)
	}
	// No temporary files survive a completed write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != update.PrefsName {
			t.Errorf("left %q behind", e.Name())
		}
	}
}

// TestRevokeIsIdempotentAndDoesNotShareBacking.
func TestRevokeIsIdempotentAndDoesNotShareBacking(t *testing.T) {
	p := update.Prefs{}
	p = p.Revoke("zu1")
	p = p.Revoke("zu1")
	p = p.Revoke("")
	if len(p.RevokedKeys) != 1 {
		t.Fatalf("RevokedKeys = %v, want one entry", p.RevokedKeys)
	}
	q := p.Revoke("zu2")
	if len(p.RevokedKeys) != 1 {
		t.Errorf("Revoke mutated the receiver's slice: %v", p.RevokedKeys)
	}
	if len(q.RevokedKeys) != 2 {
		t.Errorf("q.RevokedKeys = %v", q.RevokedKeys)
	}
}
