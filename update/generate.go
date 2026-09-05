package update

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// This file is the maintainer half: it builds the document the rest of the
// package verifies. It lives beside the verifier rather than in a shell script
// for one reason — **generation and verification must agree on bytes**, and one
// package with a round-trip test is the only way to guarantee that. A jq or
// shell generator can emit JSON the decoder rejects, or worse, accepts
// differently.

// SigningKeyEnv holds the 64-hex ed25519 seed used to sign a manifest.
//
// The seed rather than a PEM: signing goes through crypto/ed25519, the same
// library that verifies, so there is no second encoding to get wrong, no openssl
// version to pin, and no newline mangling between a CI secret and a file.
const SigningKeyEnv = "ZYCORD_UPDATE_SIGNING_KEY"

// checksumFiles are the lists a generated manifest must agree with.
//
// The manifest is a SUPERSET of these, never a replacement: they keep their own
// jobs (transfer integrity, and the rebuild-and-compare that the reproducibility
// claim rests on). Cross-checking is what stops four files from becoming four
// sources of truth that can disagree.
var checksumFiles = []string{"SHA256SUMS", "SHA256SUMS.randomx", "SHA256SUMS.desktop"}

// BuildManifest scans a directory of published release artefacts and returns the
// manifest describing them, together with the exact bytes to sign.
//
// The bytes are what matter. They are produced once, here, and everything
// downstream — the signature, the verification, a regeneration that compares —
// uses these and never a re-encoding.
func BuildManifest(dir, version string, published time.Time, urgency Urgency, note string) (*Manifest, []byte, error) {
	v, err := ParseVersion(version)
	if err != nil {
		return nil, nil, err
	}
	if !v.Release {
		return nil, nil, fmt.Errorf("update: %q is not a release tag; a manifest naming it names no release", version)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	if urgency != UrgencySecurity {
		urgency = UrgencyRoutine
	}

	m := &Manifest{
		Schema:      manifestSchema,
		Project:     project,
		Version:     version,
		PublishedAt: published.UTC().Truncate(time.Second),
		Urgency:     urgency,
		Note:        sanitiseNote(note),
		Products:    map[string]Product{},
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		product, key, ok := classify(e.Name(), version)
		if !ok {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fi, err := e.Info()
		if err != nil {
			return nil, nil, err
		}
		sum, err := sha256File(path)
		if err != nil {
			return nil, nil, err
		}
		p, seen := m.Products[product]
		if !seen {
			p = Product{Assets: map[string]Asset{}}
			m.Products[product] = p
		}
		if prev, dup := p.Assets[key]; dup {
			return nil, nil, fmt.Errorf("update: %s and %s both claim %s/%s", prev.File, e.Name(), product, key)
		}
		p.Assets[key] = Asset{File: e.Name(), SHA256: hex.EncodeToString(sum[:]), Size: fi.Size()}
	}
	if len(m.Products) == 0 {
		return nil, nil, fmt.Errorf("update: %s holds no release archives for %s", dir, version)
	}
	if err := crossCheck(dir, m); err != nil {
		return nil, nil, err
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	raw = append(raw, '\n')

	// Round-trip before returning. The generator must not be able to emit a
	// document its own verifier rejects, and finding that out at release time
	// rather than on a user's machine is the entire point of doing it here.
	ks, err := Keys()
	if err != nil {
		return nil, nil, err
	}
	if _, err := parseForSelfCheck(raw, ks); err != nil {
		return nil, nil, fmt.Errorf("update: the generated manifest does not pass this build's own reader: %w", err)
	}
	return m, raw, nil
}

// parseForSelfCheck runs everything ParseManifest does except the signature,
// which cannot exist yet.
func parseForSelfCheck(raw []byte, ks KeySet) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m.SignedBy = "" // no signer yet; validateSupersedes tolerates it
	if err := m.validate(ks); err != nil {
		return nil, err
	}
	return &m, nil
}

// classify maps a release file name onto a product and a platform key.
//
// Names are matched against the exact templates the Makefile emits rather than
// guessed at, so a file this build does not recognise is skipped rather than
// silently mis-filed — and the release checklist's own count of archives is what
// catches a template that changed.
func classify(name, version string) (product, key string, ok bool) {
	bare := strings.TrimPrefix(version, "v")

	var rest string
	switch {
	case strings.HasPrefix(name, "zycord-wallet-"+bare+"-"):
		product = ProductWallet
		rest = strings.TrimPrefix(name, "zycord-wallet-"+bare+"-")
	case strings.HasPrefix(name, "zycord-"+bare+"-"):
		product = ProductCLI
		rest = strings.TrimPrefix(name, "zycord-"+bare+"-")
	default:
		return "", "", false
	}
	switch {
	case strings.HasSuffix(rest, ".tar.gz"):
		rest = strings.TrimSuffix(rest, ".tar.gz")
	case strings.HasSuffix(rest, ".zip"):
		rest = strings.TrimSuffix(rest, ".zip")
	default:
		return "", "", false
	}
	if rest == "" || validatePlatformKey(rest) != nil {
		return "", "", false
	}
	return product, rest, true
}

// crossCheck refuses a manifest that disagrees with the checksum lists beside it.
//
// Four files describing the same bytes is four chances to disagree. This makes
// the manifest a superset rather than a rival: every digest it carries for a file
// named in a SHA256SUMS list must match that list.
func crossCheck(dir string, m *Manifest) error {
	published := map[string]string{}
	for _, name := range checksumFiles {
		sums, err := readChecksums(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for file, sum := range sums {
			if prev, dup := published[file]; dup && prev != sum {
				return fmt.Errorf("update: the checksum lists disagree about %s", file)
			}
			published[file] = sum
		}
	}
	if len(published) == 0 {
		return fmt.Errorf("update: %s holds none of %s, so nothing cross-checks the manifest",
			dir, strings.Join(checksumFiles, ", "))
	}
	for product, p := range m.Products {
		for key, a := range p.Assets {
			want, listed := published[a.File]
			if !listed {
				return fmt.Errorf("update: %s (%s/%s) appears in no checksum list", a.File, product, key)
			}
			if !strings.EqualFold(want, a.SHA256) {
				return fmt.Errorf("update: %s hashes to %s, the checksum list says %s", a.File, a.SHA256, want)
			}
		}
	}
	return nil
}

// readChecksums parses a `sha256sum` output file.
func readChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "<hex>  <name>" or "<hex> *<name>" (binary mode).
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		sum, file := fields[0], strings.TrimPrefix(fields[1], "*")
		if len(sum) != hex.EncodedLen(sha256.Size) {
			continue
		}
		out[filepath.Base(file)] = strings.ToLower(sum)
	}
	return out, sc.Err()
}

func sha256File(path string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SignManifest signs the exact bytes with a 64-hex ed25519 seed.
//
// The returned file is hex plus one newline, which is what ParseSignature reads.
func SignManifest(raw []byte, seedHex string) ([]byte, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, fmt.Errorf("update: the signing key is not hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("update: the signing key is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// Refuse to sign with a key nothing will accept. A release signed by a key
	// outside the embedded set updates nobody and does it silently, which is the
	// failure this whole feature exists to prevent — so it is caught here rather
	// than discovered by every node in the world doing nothing.
	ks, err := Keys()
	if err != nil {
		return nil, err
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	found := ""
	for _, k := range ks.Keys {
		if strings.EqualFold(k.Key, pub) {
			found = k.ID
			break
		}
	}
	if found == "" {
		return nil, fmt.Errorf("update: this signing key is not in the embedded key set, so no binary "+
			"would accept what it signs (its public half is %s)", pub)
	}
	return []byte(hex.EncodeToString(ed25519.Sign(priv, raw)) + "\n"), nil
}

// SortedAssetKeys lists a product's platform keys in a stable order, for output.
func (p Product) SortedAssetKeys() []string {
	out := make([]string, 0, len(p.Assets))
	for k := range p.Assets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
