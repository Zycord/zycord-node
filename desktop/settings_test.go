package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"zycord/wallet/webui"
)

// TestSettingsSurviveACrashMidWrite.
//
// This file decides which node the wallet talks to and whether it checks for
// updates, and it used to be written with a bare os.WriteFile — which can be
// torn by a crash between the write and the flush, leaving a document that
// parses as something nobody chose. It is written through a temp file in the
// same directory now, fsynced and renamed, so the name is only ever published
// over bytes that are already on the disk.
//
// What is checkable here is the consequence: a completed write leaves exactly
// one file, with no temporary beside it for a later start to find.
func TestSettingsSurviveACrashMidWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")

	for _, rpc := range []string{"http://127.0.0.1:9420", "http://127.0.0.1:9999"} {
		if err := saveSettings(path, webui.ConfigureRequest{
			KeyPath: "/keys/w.json", RPC: rpc, Network: "zycord",
		}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "wallet.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only wallet.json", names)
	}
	if got := loadSettings(path); got.RPC != "http://127.0.0.1:9999" {
		t.Errorf("RPC = %q, want the second write", got.RPC)
	}
	assertOwnerOnly(t, path)
}

// assertOwnerOnly checks the file is readable only by its owner, where that is a
// thing a mode bit can say.
//
// On Windows it is not. Go's Chmod there controls only the read-only bit, so the
// mode reads back -rw-rw-rw- however the file was created, and the file's actual
// protection is the ACL it inherits from its directory — a different mechanism
// that no mode comparison can check.
//
// This is the THIRD place in this stack that had to learn it, after
// update/prefs_test.go and the GOOS-as-an-environment-variable bug before that.
// It is one helper now so the next test that wants this asks for it by name
// instead of writing the comparison again and finding out from a CI runner.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %v, want 0600", perm)
	}
}

// TestTheUpdateAnswerHasThreeStates.
//
// "Nobody has been asked" and "somebody said no" are different, and a bool
// cannot hold the difference: the first shows a one-time banner and the second
// must never show it again. Saving must also not lose the rest of the settings,
// which is the failure a separate writer for one field invites.
func TestTheUpdateAnswerHasThreeStates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")

	if got := loadSettings(path); got.UpdateCheck != "" {
		t.Errorf("a wallet that has never been asked reports %q, want the empty state", got.UpdateCheck)
	}

	if err := saveSettings(path, webui.ConfigureRequest{
		KeyPath: "/keys/w.json", RPC: "http://127.0.0.1:9420", Network: "zycord",
	}); err != nil {
		t.Fatal(err)
	}
	b := &Bridge{settingsPath: path}
	for _, tc := range []struct {
		on   bool
		want string
	}{{false, "off"}, {true, "on"}, {false, "off"}} {
		if err := b.SetUpdateCheck(tc.on); err != nil {
			t.Fatal(err)
		}
		got := loadSettings(path)
		if got.UpdateCheck != tc.want {
			t.Errorf("SetUpdateCheck(%v) recorded %q, want %q", tc.on, got.UpdateCheck, tc.want)
		}
		// The answer must not cost the configuration it sits beside.
		if got.KeyPath != "/keys/w.json" || got.RPC != "http://127.0.0.1:9420" {
			t.Errorf("recording the update answer lost the rest of the settings: %+v", got)
		}
	}
}

// TestNothingIsContactedBeforeTheQuestionIsAnswered.
//
// Not-yet-asked is not consent. The check must report the unanswered state and
// return without reaching a release host — which is observable here because a
// wallet with no answer recorded reports Enabled false and no available version,
// with no network configured in this test at all.
func TestNothingIsContactedBeforeTheQuestionIsAnswered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	b := &Bridge{settingsPath: path}

	rep, err := b.UpdateStatus()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Asked {
		t.Error("a wallet that has never been asked reports that it was")
	}
	if rep.Enabled {
		t.Error("a wallet that has never been asked reports checking as enabled")
	}
	if rep.Available != "" || rep.Error != "" {
		t.Errorf("a check ran before consent: available=%q err=%q", rep.Available, rep.Error)
	}
	if rep.ReleaseURL == "" {
		t.Error("no release page to point at")
	}

	if err := b.SetUpdateCheck(false); err != nil {
		t.Fatal(err)
	}
	rep, err = b.UpdateStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Asked || rep.Enabled {
		t.Errorf("after declining: asked=%v enabled=%v, want asked and not enabled", rep.Asked, rep.Enabled)
	}
}
