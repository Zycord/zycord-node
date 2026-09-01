package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
	// ErrBadSignature is a manifest no held key verifies.
	//
	// It deliberately covers two cases this build CANNOT tell apart: a forgery,
	// and a legitimate release signed by a key introduced after this binary was
	// published. A schema 1 manifest carries no signer id, so there is nothing
	// to distinguish them by — and a separate "unknown key" error would have
	// been a promise to make a distinction that no field supports. Saying so is
	// the honest version; the message names both possibilities.
	ErrBadSignature = errors.New("update: the manifest is not signed by any key this build carries - " +
		"either it is not ours, or it is a release signed by a key introduced after this binary was published")
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
		// ParseKeys refuses both of these, but KeySet is exported with exported
		// fields and can be built by hand or by json.Unmarshal. ed25519.Verify
		// PANICS on a key that is not 32 bytes, so an unchecked length here is a
		// process crash reachable from an ordinary struct literal.
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
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
	// Unknown fields are IGNORED here, and that is the opposite of the rule
	// keys.json is parsed under. The asymmetry is deliberate and it is about
	// what each file is for.
	//
	// keys.json is ours and must carry keys and nothing else, so an unexpected
	// field there is a mistake to catch. The manifest is a wire format that has
	// to be read by binaries older than the release that wrote it — and every
	// one of those is frozen at genesis. Refusing unknown fields would mean any
	// field a later release needs is rejected by every binary already shipped,
	// while bumping `schema` to add one makes those binaries refuse the manifest
	// outright. Between them there would be no way to add anything, ever. The
	// document is signed, so ignoring what we do not understand costs nothing.
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("update: the manifest is signed but does not parse: %w", err)
	}
	// dec.More() is NOT this check: it reports whether another element follows
	// in an array or object, so it answers false whenever the next byte is `]`
	// or `}` and accepts `{...}] anything at all`. What is wanted is that the
	// document is the whole file.
	if rest := bytes.TrimSpace(raw[dec.InputOffset():]); len(rest) != 0 {
		return nil, fmt.Errorf("update: the manifest has %d bytes of trailing content after the document", len(rest))
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
		if len(p.Assets) == 0 {
			return fmt.Errorf("update: product %q publishes no assets", name)
		}
		for key, a := range p.Assets {
			if err := validatePlatformKey(key); err != nil {
				return fmt.Errorf("update: %s: %w", name, err)
			}
			if err := a.validate(); err != nil {
				// %q, not %s: the key is decoded from the document and may hold
				// anything a JSON string can, escapes included. It is signed,
				// which says where it came from, not that it is safe to print.
				return fmt.Errorf("update: %s/%q: %w", name, key, err)
			}
			// The tier is part of the asset KEY, and this is what stops that
			// from being a convention nobody enforces. Without it a manifest
			// whose linux-amd64-randomx entry names the PLAIN archive parses,
			// validates and installs - the tier crossed by a mislabel, through
			// the exact mechanism that was supposed to make crossing it
			// unrepresentable. A key and the file it names must agree.
			if got, want := FileNamesRandomX(a.File), KeyNamesRandomX(key); got != want {
				return fmt.Errorf("update: %s/%q names file %q; the key and the file disagree about the tier",
					name, key, a.File)
			}
		}
	}
	return m.validateSupersedes(ks)
}

// validateSupersedes decides what a key-rotation claim means to THIS build.
//
// The rule that cannot be turned around: **only the key held as `next` may
// retire the key held as `current`.** A general in-band revocation would be a
// weapon — an attacker holding the stolen current key could sign a manifest
// retiring the GOOD key and strand every node permanently, turning a key
// compromise into an unrecoverable one. Under this rule a stolen current key can
// revoke nothing, because it is nobody's spare.
//
// **And `supersedes` is a record of a transition, not an instruction aimed at
// the reader.** The first version of this function read it as a live command and
// deadlocked the rotation it existed to enable: after the rotation the manifest
// is still the newest release, but to a freshly-updated binary — which now holds
// zu2 as `current` and zu3 as `next` — a manifest signed by zu2 superseding zu1
// is signed by something that is not its spare, so it was refused. Every updated
// node then errored on every check until an unrelated release shipped, which is
// exactly the fleet-wide breakage the spare exists to avoid.
//
// So the claim is judged against what this build actually holds:
//
//   - It names our current key. That is a live promotion, and only our spare may
//     make it.
//   - It names our spare. Nobody may retire our spare; refuse, loudly.
//   - It names anything else — including a key retired before this build existed.
//     A record of somebody else's transition. Ignore it.
func (m *Manifest) validateSupersedes(ks KeySet) error {
	current, hasCurrent := ks.KeyByRole(RoleCurrent)
	next, hasNext := ks.KeyByRole(RoleNext)

	// The spare signs rotations and nothing else.
	//
	// Without this, a stolen spare is strictly worse than a stolen current key:
	// it could sign ordinary releases AND retire the signing key. Restricting it
	// does not make a stolen spare harmless — it can still sign the rotation that
	// promotes it — but it forces the attack to be a visible, permanent, publicly
	// signed key change rather than a quiet release nobody looks at twice.
	if hasNext && hasCurrent && m.SignedBy == next.ID && m.Supersedes != current.ID {
		return fmt.Errorf("update: the manifest is signed by the held-back key %q but does not retire %q; "+
			"the spare signs key rotations and nothing else", next.ID, current.ID)
	}

	switch {
	case m.Supersedes == "":
		return nil

	case hasCurrent && m.Supersedes == current.ID:
		if !hasNext {
			return fmt.Errorf("update: the manifest retires key %q, but this build holds no spare to promote", current.ID)
		}
		if m.SignedBy != next.ID {
			return fmt.Errorf("update: the manifest retires key %q but is signed by %q; "+
				"only the held-back key %q may retire the signing key", m.Supersedes, m.SignedBy, next.ID)
		}
		return nil

	case hasNext && m.Supersedes == next.ID:
		return fmt.Errorf("update: the manifest retires key %q, which is this build's spare; "+
			"nothing may retire the spare, because that is the key a compromise is recovered with", m.Supersedes)

	default:
		// A key this build does not hold in either role. Most often: the record
		// of a rotation that happened before this binary was published, or the
		// one that produced it. Not addressed to us.
		return nil
	}
}

// validatePlatformKey refuses a key that is not <os>-<arch>[-randomx] in shape.
//
// Without this a typo'd key is indistinguishable from "we publish nothing for
// your platform": a manifest with "linux-amd64 " (trailing space) silently
// offers nothing to every linux-amd64 node, and the failure surfaces as silence
// rather than as the maintainer error it is.
func validatePlatformKey(key string) error {
	if key == "" {
		return errors.New("an asset key is empty")
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
		if !ok {
			return fmt.Errorf("asset key %q is not <os>-<arch>[-randomx] in shape", key)
		}
	}
	if n := strings.Count(key, "-"); n < 1 || n > 2 {
		return fmt.Errorf("asset key %q is not <os>-<arch>[-randomx] in shape", key)
	}
	if strings.HasPrefix(key, "-") || strings.HasSuffix(key, "-") || strings.Contains(key, "--") {
		return fmt.Errorf("asset key %q is not <os>-<arch>[-randomx] in shape", key)
	}
	return nil
}

func (a Asset) validate() error {
	if a.File == "" {
		return errors.New("the asset names no file")
	}
	// The filename is used to build a URL and to name a file on disk, so it is
	// checked against an ALLOW-LIST rather than a list of separators to reject.
	// The deny-list this replaced tested only the two path separators, and
	// accepted every other way a name becomes something else: `C:evil` and
	// `a.tar.gz:stream` (NTFS drive-relative paths and alternate data streams),
	// `-rf` (a name that becomes a flag), `%2e%2e%2fetc` (decoded by something
	// downstream), `...`, `.hidden`, and names carrying NUL or a newline.
	//
	// It is signed, so this is not defence against a stranger; it is defence
	// against a maintainer typo becoming a path on somebody else's disk.
	if err := validAssetFileName(a.File); err != nil {
		return err
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

// validAssetFileName allows exactly what a release archive is named: lower-case
// letters, digits, dot, dash and underscore, not starting with a dot or a dash.
func validAssetFileName(f string) error {
	if f == "" {
		return errors.New("the asset names no file")
	}
	if len(f) > 128 {
		return fmt.Errorf("the asset file name is %d characters", len(f))
	}
	for i := 0; i < len(f); i++ {
		c := f[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_'
		if !ok {
			return fmt.Errorf("the asset file %q is not a plain file name", f)
		}
	}
	if f[0] == '.' || f[0] == '-' {
		return fmt.Errorf("the asset file %q starts with %q", f, string(f[0]))
	}
	if strings.Contains(f, "..") {
		return fmt.Errorf("the asset file %q contains %q", f, "..")
	}
	// Windows reserved device names, which are not files: opening CON writes to
	// the console, NUL discards. Reserved with any extension and case, so the
	// check is on the stem. Defence in depth - a release archive is never named
	// this - but it costs one lookup and the failure mode is a download that
	// silently goes nowhere.
	stem := f
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if reservedDeviceNames[strings.ToUpper(stem)] {
		return fmt.Errorf("the asset file %q is a reserved device name", f)
	}
	return nil
}

var reservedDeviceNames = func() map[string]bool {
	m := map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}
	for i := 1; i <= 9; i++ {
		m["COM"+strconv.Itoa(i)] = true
		m["LPT"+strconv.Itoa(i)] = true
	}
	return m
}()

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
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x061c, r == 0x200f, r == 0x200e:
			// Bidirectional overrides and isolates. Under this function's own
			// model - signed says where it came from, not that it is safe to
			// print - Trojan-Source text is the hole a C0/C1 filter leaves
			// open: U+202E reverses everything after it, so a note can be made
			// to read as the opposite of what a reader would copy.
		case r == 0x200b, r == 0x200c, r == 0x200d, r == 0xfeff:
			// Zero-width characters, which hide differences between two strings
			// that a reader is being asked to compare.
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
