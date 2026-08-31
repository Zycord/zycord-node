package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The manifest is the one document this package trusts, and the order of
// operations on it is the whole of why it can be trusted.
//
// **Verify, then parse. Never parse, then verify.** The signature is checked
// over the exact bytes as fetched, before a JSON decoder ever sees them. Two
// things follow, and both are lost the moment the order is reversed:
//
//   - No attacker-controlled JSON reaches the decoder unsigned. Whatever the
//     decoder's own edge cases are, they are only reachable by someone holding
//     a key.
//   - There is no canonicalisation anywhere. A verifier that re-serialises
//     before checking is a second, undocumented implementation of the format,
//     and the gap between the two is a place for a signature to be valid over
//     bytes nobody ever saw. Signing the file as it lies removes the question.
//
// TestASemanticallyEqualManifestWithDifferentBytesFailsVerification pins it.

// manifestSchema is the only manifest layout this build understands.
const manifestSchema = 1

// project is the name this build will accept a manifest for.
//
// One string, and it closes a whole class: a manifest signed by the same key
// for a different project, replayed here. A project name is not an identity
// surface, so unlike the release host it is safe to write down.
const project = "zycord"

// Urgency is how loudly a release asks to be taken.
type Urgency string

const (
	// UrgencyRoutine is the default, and what any unknown value degrades to.
	UrgencyRoutine Urgency = "routine"
	// UrgencySecurity is printed on every check rather than once a day.
	UrgencySecurity Urgency = "security"
)

// Asset is one downloadable file.
//
// There is no URL here on purpose. The download address is built from the
// release host this binary was compiled with and the version this manifest
// names. A URL in a signed manifest would widen a key compromise from "serve a
// bad binary from the release page" to "serve a bad binary from anywhere",
// which is a much larger thing to have bought for a field nobody needed.
type Asset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Product is one shippable thing: the CLI pair, or the desktop wallet.
type Product struct {
	Assets map[string]Asset `json:"assets"`
}

// Product names.
const (
	ProductCLI    = "zycord-cli"
	ProductWallet = "zycord-wallet"
)

// Manifest is the parsed, verified release description.
type Manifest struct {
	Schema      int                `json:"schema"`
	Project     string             `json:"project"`
	Version     string             `json:"version"`
	PublishedAt time.Time          `json:"published_at"`
	Urgency     Urgency            `json:"urgency"`
	Note        string             `json:"note"`
	Supersedes  string             `json:"supersedes,omitempty"`
	Products    map[string]Product `json:"products"`

	// SignedBy is the id of the key whose signature verified, filled in by
	// ParseManifest. It is not a field of the document.
	SignedBy string `json:"-"`

	// Parsed is Version, already through ParseVersion.
	Parsed Version `json:"-"`
}

// Errors a caller distinguishes.
var (
	// ErrBadSignature is a manifest no held key verifies. It is never
	// "no update available": it is a compromise or a broken release.
	ErrBadSignature = errors.New("update: the manifest is not signed by any key this build carries")
	// ErrUnknownKey is the stranded-binary case, separated from ErrBadSignature
	// because the operator's next step is completely different.
	ErrUnknownKey = errors.New("update: the manifest names a signing key this build does not carry")
	// ErrNoAssetForTier is a release that publishes nothing for this platform
	// and tier.
	ErrNoAssetForTier = errors.New("update: this release publishes no archive for this platform and tier")
)

// ParseManifest verifies a detached signature over raw and then decodes it.
//
// keys is the set the signature may verify against, and a signature verifying
// under ANY of them is accepted — that is what makes a key rotation an ordinary
// update rather than a fleet-wide hand-download.
func ParseManifest(raw, sig []byte, ks KeySet) (*Manifest, error) {
	signature, err := ParseSignature(sig)
	if err != nil {
		return nil, err
	}

	signer := ""
	for _, k := range ks.Keys {
		pub, err := hex.DecodeString(k.Key)
		if err != nil {
			continue // ParseKeys already refused these; belt and braces
		}
		if ed25519.Verify(ed25519.PublicKey(pub), raw, signature) {
			signer = k.ID
			break
		}
	}
	if signer == "" {
		return nil, ErrBadSignature
	}

	// Only now does a decoder see these bytes.
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("update: the manifest is signed but does not parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("update: the manifest has trailing content after the document")
	}
	m.SignedBy = signer

	if err := m.validate(ks); err != nil {
		return nil, err
	}
	return &m, nil
}

// ParseSignature decodes the detached signature file.
//
// Hex, 128 characters, one optional trailing newline. Strict on purpose: a
// lenient parser is where two implementations begin to disagree about what was
// signed. Hex rather than raw bytes because raw loses to any text-mangling step
// in the path — CRLF translation, an editor, a copy-paste — and because a file
// containing NUL cannot be committed as a test fixture under sim/wiring's
// text scan. Hex rather than base64 because hex has exactly one spelling for a
// fixed-length input.
func ParseSignature(sig []byte) ([]byte, error) {
	s := strings.TrimSuffix(strings.TrimSuffix(string(sig), "\n"), "\r")
	want := hex.EncodedLen(ed25519.SignatureSize)
	if len(s) != want {
		return nil, fmt.Errorf("update: the signature is %d characters, want %d hex", len(s), want)
	}
	if s != strings.ToLower(s) {
		return nil, errors.New("update: the signature is not lower-case hex")
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("update: the signature is not hex: %w", err)
	}
	return out, nil
}

// validate applies the rules that a signature alone cannot: the document is for
// this project, in a layout this build reads, and — if it claims a key
// rotation — claims one it is allowed to claim.
func (m *Manifest) validate(ks KeySet) error {
	// Schema first, before any other field is believed. An unknown value is a
	// release newer than this binary, not a parse failure and not a misread.
	if m.Schema != manifestSchema {
		return fmt.Errorf("update: this release publishes a schema %d manifest and this build reads schema %d; "+
			"it is newer than this binary understands, so update by hand", m.Schema, manifestSchema)
	}
	if m.Project != project {
		return fmt.Errorf("update: the manifest is for project %q, not %q", m.Project, project)
	}
	v, err := ParseVersion(m.Version)
	if err != nil {
		return fmt.Errorf("update: the manifest names version %q: %w", m.Version, err)
	}
	if !v.Release {
		return fmt.Errorf("update: the manifest names %q, which is not a release tag", m.Version)
	}
	m.Parsed = v

	// An unknown urgency degrades rather than failing. An old binary cannot act
	// on a level it does not know, and must not be made to shout by a future
	// manifest; the note always works.
	if m.Urgency != UrgencySecurity {
		m.Urgency = UrgencyRoutine
	}
	m.Note = sanitiseNote(m.Note)

	if len(m.Products) == 0 {
		return errors.New("update: the manifest publishes no products")
	}
	for name, p := range m.Products {
		for key, a := range p.Assets {
			if err := a.validate(); err != nil {
				return fmt.Errorf("update: %s/%s: %w", name, key, err)
			}
		}
	}
	return m.validateSupersedes(ks)
}

// validateSupersedes enforces the one rule in this package that cannot be
// turned around.
//
// **Only the key held as `next` may revoke the key held as `current`, and only
// by superseding it.** A general in-band revocation list would be a weapon: an
// attacker holding the stolen current key could sign a manifest revoking the
// GOOD key and strand every node permanently. Under this rule a stolen current
// key can revoke nothing at all, because it is nobody's spare — so the worst it
// buys is what it already had, the ability to sign a release.
//
// TestAStolenCurrentKeyCannotRevokeTheSpare is named for the attack.
func (m *Manifest) validateSupersedes(ks KeySet) error {
	if m.Supersedes == "" {
		return nil
	}
	next, hasNext := ks.KeyByRole(RoleNext)
	current, hasCurrent := ks.KeyByRole(RoleCurrent)
	if !hasNext || !hasCurrent {
		return errors.New("update: the manifest supersedes a key, but this build holds no spare to promote")
	}
	if m.SignedBy != next.ID {
		return fmt.Errorf("update: the manifest supersedes key %q but is signed by %q, which is not this build's spare; "+
			"only the held-back key may retire the signing key", m.Supersedes, m.SignedBy)
	}
	if m.Supersedes != current.ID {
		return fmt.Errorf("update: the manifest supersedes key %q, which is not this build's signing key %q",
			m.Supersedes, current.ID)
	}
	return nil
}

func (a Asset) validate() error {
	if a.File == "" {
		return errors.New("the asset names no file")
	}
	// The filename is used to build a URL and to name a file on disk. It is
	// signed, so this is not defence against a stranger — it is defence against
	// a maintainer's typo becoming a path.
	if strings.ContainsAny(a.File, `/\`) || a.File == "." || a.File == ".." {
		return fmt.Errorf("the asset file %q is a path rather than a name", a.File)
	}
	raw, err := hex.DecodeString(a.SHA256)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("the asset %q has no usable sha256", a.File)
	}
	if a.SHA256 != strings.ToLower(a.SHA256) {
		return fmt.Errorf("the asset %q has an upper-case sha256", a.File)
	}
	if a.Size <= 0 {
		return fmt.Errorf("the asset %q has size %d", a.File, a.Size)
	}
	if a.Size > maxArchive {
		return fmt.Errorf("the asset %q is %d bytes, above the %d-byte ceiling this build will download",
			a.File, a.Size, int64(maxArchive))
	}
	return nil
}

// maxArchive is the absolute ceiling on a downloadable archive, independent of
// what a manifest asks for. The manifest's own Size is the operative bound; this
// is the one that still applies if a manifest asks for something absurd.
const maxArchive = 128 << 20

// Digest returns the asset's expected sha256 as bytes.
func (a Asset) Digest() [sha256.Size]byte {
	var out [sha256.Size]byte
	raw, _ := hex.DecodeString(a.SHA256) // validated
	copy(out[:], raw)
	return out
}

// Asset finds the archive for one product and platform key.
//
// A plain map lookup with **no fallback**, and that is deliberate: see
// PlatformKey. Nothing here tries the other tier, or the other architecture, or
// a near miss.
func (m *Manifest) Asset(product, platformKey string) (Asset, error) {
	p, ok := m.Products[product]
	if !ok {
		return Asset{}, fmt.Errorf("%w: %s publishes no %s", ErrNoAssetForTier, m.Version, product)
	}
	a, ok := p.Assets[platformKey]
	if !ok {
		return Asset{}, fmt.Errorf("%w: %s publishes no %s archive for %s",
			ErrNoAssetForTier, m.Version, platformKey, product)
	}
	return a, nil
}

// sanitiseNote makes a signed string safe to print to a terminal.
//
// The note is signed, which says it came from the release pipeline. It does not
// say it is safe to write to a terminal: a signature is not a licence to move
// the cursor, clear the screen, or repaint what the operator already read. So
// control characters go, and the length is bounded — an operator's screen is not
// the release notes.
func sanitiseNote(s string) string {
	var b strings.Builder
	lines := 0
	for _, r := range s {
		switch {
		case r == '\n':
			lines++
			if lines >= maxNoteLines {
				return strings.TrimSpace(b.String())
			}
			b.WriteRune('\n')
		case r < 0x20 || r == 0x7f, r >= 0x80 && r <= 0x9f:
			// C0, DEL and C1. Dropped rather than escaped: there is nothing an
			// operator needs from them and no rendering of them that is safer
			// than their absence.
		default:
			b.WriteRune(r)
		}
		if b.Len() >= maxNoteBytes {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

const (
	maxNoteBytes = 500
	maxNoteLines = 4
)
