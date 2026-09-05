package update_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zycord/update"
)

// fakeRelease writes archives shaped like the Makefile's dist templates, plus
// the checksum lists that ship beside them.
func fakeRelease(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]string{
		"SHA256SUMS": {
			"zycord-" + version + "-linux-amd64.tar.gz",
			"zycord-" + version + "-windows-amd64.zip",
			"zycord-" + version + "-windows-arm64.zip",
		},
		"SHA256SUMS.randomx": {
			"zycord-" + version + "-linux-amd64-randomx.tar.gz",
		},
		"SHA256SUMS.desktop": {
			"zycord-wallet-" + version + "-darwin-arm64.zip",
		},
	}
	for list, names := range files {
		var lines []string
		for i, n := range names {
			body := []byte(fmt.Sprintf("archive %s %d", n, i))
			if err := os.WriteFile(filepath.Join(dir, n), body, 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			lines = append(lines, fmt.Sprintf("%s  %s", hex.EncodeToString(sum[:]), n))
		}
		if err := os.WriteFile(filepath.Join(dir, list), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestAGeneratedManifestIsOneThisBuildAccepts is the round trip that justifies
// generating in Go rather than in a shell script.
//
// A jq or shell generator can emit JSON the decoder rejects — or worse, accepts
// differently. One package with this test is the only way generation and
// verification are guaranteed to agree on bytes.
func TestAGeneratedManifestIsOneThisBuildAccepts(t *testing.T) {
	dir := fakeRelease(t, "0.2.0")
	_, raw, err := update.BuildManifest(dir, "v0.2.0", time.Now(), update.UrgencyRoutine, "Routine.")
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	// Sign with a throwaway key and read it back through the real verifier.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := update.ParseKeys([]byte(fmt.Sprintf(
		`{"schema":1,"algorithm":"ed25519","keys":[{"id":"t1","role":"current","key":%q}]}`,
		hex.EncodeToString(pub))))
	if err != nil {
		t.Fatal(err)
	}
	sig := []byte(hex.EncodeToString(ed25519.Sign(priv, raw)) + "\n")

	m, err := update.ParseManifest(raw, sig, ks)
	if err != nil {
		t.Fatalf("the generator produced a manifest its own verifier refuses: %v", err)
	}
	if m.Version != "v0.2.0" {
		t.Errorf("Version = %q", m.Version)
	}
	cli, ok := m.Products[update.ProductCLI]
	if !ok {
		t.Fatal("no zycord-cli product")
	}
	for _, want := range []string{"linux-amd64", "linux-amd64-randomx", "windows-amd64", "windows-arm64"} {
		if _, ok := cli.Assets[want]; !ok {
			t.Errorf("no %s asset: %v", want, cli.SortedAssetKeys())
		}
	}
	if _, ok := m.Products[update.ProductWallet]; !ok {
		t.Error("no zycord-wallet product")
	}
	// The tier suffix has to survive classification, or every randomx user is
	// offered the archive that cannot mine.
	if got := cli.Assets["linux-amd64-randomx"].File; !strings.Contains(got, "-randomx") {
		t.Errorf("the randomx key names %q", got)
	}
}

// TestGenerationIsDeterministic. The bytes are what gets signed, so two runs
// over the same directory must produce the same document.
func TestGenerationIsDeterministic(t *testing.T) {
	dir := fakeRelease(t, "0.2.0")
	at := time.Date(2026, 9, 30, 14, 2, 11, 0, time.UTC)
	_, a, err := update.BuildManifest(dir, "v0.2.0", at, update.UrgencyRoutine, "x")
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := update.BuildManifest(dir, "v0.2.0", at, update.UrgencyRoutine, "x")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("two runs over one directory produced different bytes, so a regenerate-and-compare " +
			"check could never pass")
	}
}

// TestTheManifestMustAgreeWithTheChecksumLists.
//
// Four files describing the same bytes is four chances to disagree. This is what
// makes the manifest a superset of SHA256SUMS rather than a rival to it.
func TestTheManifestMustAgreeWithTheChecksumLists(t *testing.T) {
	t.Run("a list that disagrees", func(t *testing.T) {
		dir := fakeRelease(t, "0.2.0")
		p := filepath.Join(dir, "SHA256SUMS")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		// Flip one digit of the first digest.
		corrupted := []byte(strings.Replace(string(raw), string(raw[0]), map[bool]string{true: "0", false: "1"}[raw[0] != '0'], 1))
		if err := os.WriteFile(p, corrupted, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := update.BuildManifest(dir, "v0.2.0", time.Now(), update.UrgencyRoutine, ""); err == nil {
			t.Error("generated a manifest that disagrees with SHA256SUMS")
		}
	})

	t.Run("an archive in no list at all", func(t *testing.T) {
		dir := fakeRelease(t, "0.2.0")
		extra := filepath.Join(dir, "zycord-0.2.0-darwin-arm64.tar.gz")
		if err := os.WriteFile(extra, []byte("unlisted"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, err := update.BuildManifest(dir, "v0.2.0", time.Now(), update.UrgencyRoutine, "")
		if err == nil {
			t.Fatal("an archive appearing in no checksum list was published anyway")
		}
		if !strings.Contains(err.Error(), "no checksum list") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("no lists at all", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "zycord-0.2.0-linux-amd64.tar.gz"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := update.BuildManifest(dir, "v0.2.0", time.Now(), update.UrgencyRoutine, ""); err == nil {
			t.Error("generated a manifest with nothing cross-checking it")
		}
	})
}

// TestAManifestNamingSomethingThatIsNotAReleaseIsRefused.
func TestAManifestNamingSomethingThatIsNotAReleaseIsRefused(t *testing.T) {
	dir := fakeRelease(t, "0.2.0")
	for _, v := range []string{"v0.2.0-3-gabcdef1", "dev", "", "tomorrow", "v0.2.0-dirty"} {
		t.Run(v, func(t *testing.T) {
			if _, _, err := update.BuildManifest(dir, v, time.Now(), update.UrgencyRoutine, ""); err == nil {
				t.Errorf("generated a manifest naming %q", v)
			}
		})
	}
}

// TestSigningRefusesAKeyNothingWouldAccept is the check that turns a silent
// non-release into a failed one.
//
// A manifest signed by a key outside the embedded set updates NOBODY, and does
// it without any error anywhere: every node fetches it, fails the signature, and
// reports what looks like a hostile document. Catching it at signing time is the
// difference between a release that fails and a release that quietly does
// nothing.
func TestSigningRefusesAKeyNothingWouldAccept(t *testing.T) {
	dir := fakeRelease(t, "0.2.0")
	_, raw, err := update.BuildManifest(dir, "v0.2.0", time.Now(), update.UrgencyRoutine, "")
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.SignManifest(raw, hex.EncodeToString(priv.Seed()))
	if err == nil {
		t.Fatal("signed with a key no shipped binary carries")
	}
	if !strings.Contains(err.Error(), "not in the embedded key set") {
		t.Errorf("err = %v", err)
	}

	for _, bad := range []string{"", "nothex", strings.Repeat("ab", 16)} {
		if _, err := update.SignManifest(raw, bad); err == nil {
			t.Errorf("accepted signing key %q", bad)
		}
	}
}

// TestOnlyKnownArchiveShapesAreClassified. A file this build does not recognise
// is skipped rather than mis-filed, and the release checklist's own count of
// archives is what catches a template that changed.
func TestOnlyKnownArchiveShapesAreClassified(t *testing.T) {
	dir := fakeRelease(t, "0.2.0")
	for _, junk := range []string{
		"README.md", "SHA256SUMS.binaries", "zycord-release-key.asc",
		"install.sh", "zycord-0.2.0-linux-amd64.tar.gz.sig",
		"zycord-0.1.9-linux-amd64.tar.gz", // a different version entirely
	} {
		if err := os.WriteFile(filepath.Join(dir, junk), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, _, err := update.BuildManifest(dir, "v0.2.0", time.Now(), update.UrgencyRoutine, "")
	if err != nil {
		t.Fatalf("BuildManifest choked on files beside the archives: %v", err)
	}
	total := 0
	for _, p := range m.Products {
		total += len(p.Assets)
	}
	if total != 5 {
		t.Errorf("classified %d assets, want the 5 real archives", total)
	}
}
