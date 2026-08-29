package wallet_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"zycord/wallet"
)

func TestSaveAndLoadKeyFileRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")
	if err := wallet.SaveKeyFile(path, k, pass); err != nil {
		t.Fatal(err)
	}

	loaded, err := wallet.LoadKeyFile(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Persistent() != k.Persistent() || loaded.OneShot() != k.OneShot() {
		t.Fatal("the loaded key's addresses differ from the saved one")
	}
}

// TestSaveKeyFileRefusesToOverwriteAnExistingFile is the rule 7 property: a
// key file, once written, is never silently replaced by a later save to the
// same path — the same guarantee O_CREATE|O_EXCL used to provide before
// writeFileNoClobber replaced it with a crash-safe write that keeps the
// guarantee.
func TestSaveKeyFileRefusesToOverwriteAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")

	k1, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("first passphrase")
	if err := wallet.SaveKeyFile(path, k1, pass); err != nil {
		t.Fatal(err)
	}

	k2, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(path, k2, []byte("second passphrase")); err == nil {
		t.Fatal("expected an error; SaveKeyFile must never overwrite an existing key file")
	}

	// The original key must still be the one on disk, untouched by the
	// refused attempt.
	loaded, err := wallet.LoadKeyFile(path, pass)
	if err != nil {
		t.Fatalf("the original key file was damaged by the refused overwrite: %v", err)
	}
	if loaded.Persistent() != k1.Persistent() {
		t.Fatal("the key on disk no longer matches the original")
	}
}

func TestSaveKeyFileRequiresAPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")
	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(path, k, nil); err == nil {
		t.Fatal("expected an error for an empty passphrase")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("no file should be created when the passphrase is rejected")
	}
}

// writeTamperedKeyFile generates a normal, valid key file, overrides the named
// top-level JSON fields (e.g. "argon2_threads"), and writes the result to a
// fresh path. This mimics the hostile envelope that arrives on a restore-backup
// path: a well-formed key file whose KDF parameters have been edited to values
// the wallet itself would never write.
func writeTamperedKeyFile(t *testing.T, overrides map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(good, k, []byte("correct horse battery staple")); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	for key, val := range overrides {
		envelope[key] = val
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, body, 0600); err != nil {
		t.Fatal(err)
	}
	return bad
}

// TestKeyFileRejectsHostileArgon2Params is the hostile-envelope property: the
// three KDF parameters ride in the envelope, so a hostile file can set
// argon2_threads or argon2_time to 0 (which panics golang.org/x/crypto/argon2)
// or argon2_memory_kib to an absurd value (4 TiB). InspectKeyFile — whose
// documented job is to make a bad file an error at the moment of picking —
// must reject each, and LoadKeyFile must never hand them to argon2.IDKey.
//
// Non-vacuity: with validateArgon2Params removed, threads=0 and time=0 make
// LoadKeyFile panic (confirmed by running the suite without the guard) and
// InspectKeyFile returns nil for all three cases, so these assertions fail.
func TestKeyFileRejectsHostileArgon2Params(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
	}{
		{"threads zero", map[string]any{"argon2_threads": 0}},
		{"time zero", map[string]any{"argon2_time": 0}},
		{"memory near 4 TiB", map[string]any{"argon2_memory_kib": 4294967295}}, // uint32 max KiB, ~4 TiB
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTamperedKeyFile(t, tc.overrides)

			if err := wallet.InspectKeyFile(path); err == nil {
				t.Fatal("InspectKeyFile accepted a key file with hostile Argon2 parameters")
			}
			// Must be a plain error, not a panic taking the process down.
			if _, err := wallet.LoadKeyFile(path, []byte("correct horse battery staple")); err == nil {
				t.Fatal("LoadKeyFile accepted a key file with hostile Argon2 parameters")
			}
		})
	}
}

// TestInspectAndLoadAcceptWalletDefaults guards against the fix rejecting files
// the wallet itself writes: a key file created today with the wallet's default
// Argon2 parameters must keep inspecting and loading cleanly (round-trip).
func TestInspectAndLoadAcceptWalletDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")

	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")
	if err := wallet.SaveKeyFile(path, k, pass); err != nil {
		t.Fatal(err)
	}

	if err := wallet.InspectKeyFile(path); err != nil {
		t.Fatalf("InspectKeyFile rejected a key file the wallet just wrote: %v", err)
	}
	loaded, err := wallet.LoadKeyFile(path, pass)
	if err != nil {
		t.Fatalf("LoadKeyFile rejected a key file the wallet just wrote: %v", err)
	}
	if loaded.Persistent() != k.Persistent() || loaded.OneShot() != k.OneShot() {
		t.Fatal("the loaded key's addresses differ from the saved one")
	}
}

func TestLoadKeyFileWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")
	k, err := wallet.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.SaveKeyFile(path, k, []byte("right")); err != nil {
		t.Fatal(err)
	}
	if _, err := wallet.LoadKeyFile(path, []byte("wrong")); !errors.Is(err, wallet.ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
}
