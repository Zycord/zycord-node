// The project GPG key, and the four files that have to keep agreeing about it.
//
// This file exists because GnuPG refused the project key on import from the
// default keyserver, and the defect it guards is not a bug in any program
// either: it is that the only anti-impersonation anchor this project has could
// not be *used*.
//
//	keys.openpgp.org   served the key stripped to one public-key packet, with
//	                   no user ID and no self-signature
//	gpg --import       answered "new key but contains no user ID - skipped",
//	                   so the key never entered the keyring
//	docs/INSTALL.md    named no keyserver, so a user had no way to learn that
//	                   another one serves an importable copy
//	install.sh         said "import the project key first" and stopped there
//
// The published recovery was to stop checking — `install.sh --no-signature`,
// whose own message correctly describes what that leaves: "the files against a
// SHA256SUMS from the same host, and nothing more", which is exactly the
// fake-release-page case docs/INSTALL.md says the scheme does not cover.
// `make dist` signs nothing, so `SHA256SUMS.asc` is the whole chain.
//
// The fix is a key file in the tree and in the release, a keyserver named in
// full, and a fingerprint printed beside both. What this file pins:
//
//	the key is the key     packaging/zycord-release-key.asc hashes to the
//	                       fingerprint in the whitepaper header. A key file that
//	                       does not is worse than no key file, because it would
//	                       be imported and trusted.
//	it is importable       it carries a user ID and a self-signature, which is
//	                       the precise property the stripped copy lacked and the
//	                       precise reason gpg refused it.
//	it is published        `make dist` stages it as a release asset.
//	it is findable         INSTALL.md names all three sources, prints the
//	                       fingerprint, and warns off the server that breaks.
//	the checksum line      both spellings carry --ignore-missing, on the same
//	                       page (the one-line defect bundled with it): SHA256SUMS
//	                       covers six archives and a user downloads one, so
//	                       without the flag an honest download reports five
//	                       FAILED lines and exits non-zero.
//
// Read from the files rather than by running gpg, for the reason toolchain_test.go
// beside this gives: a test that needs a tool the CI image may not carry is a
// test that gets skipped. The armour, the CRC-24 and the packet framing are all
// parsed here, so "the file is the key" is checked rather than asserted.
package wiring_test

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The files that name the key, relative to this package.
const (
	releaseKeyPath = repoRoot + "/packaging/zycord-release-key.asc"
	whitepaperPath = repoRoot + "/docs/whitepaper.md"
	installShPath  = repoRoot + "/packaging/install.sh"
	releaseDocPath = repoRoot + "/docs/RELEASE.md"
)

// The keyserver that serves an importable copy, and the one that does not.
const (
	workingKeyserver = "keyserver.ubuntu.com"
	brokenKeyserver  = "keys.openpgp.org"
)

// whitepaperGPG matches the `GPG: ` + "`...`" + ` header line of docs/whitepaper.md,
// which is the published anchor every other copy of the fingerprint is a copy of.
var whitepaperGPG = regexp.MustCompile("(?m)^GPG:\\s*`([0-9A-Fa-f ]+)`")

// installShFingerprint matches PROJECT_KEY_FPR in packaging/install.sh.
var installShFingerprint = regexp.MustCompile(`(?m)^PROJECT_KEY_FPR="([0-9A-Fa-f]+)"`)

// checksumCommand matches one sha256 invocation and the arguments that belong
// to it, stopping at a comment marker, a shell operator or the end of the line.
//
// Per *invocation* rather than per line, and that is the whole point: the
// defect this guards lived in the trailing comment of a line whose first half
// was correct —
//
//	sha256sum --check --ignore-missing SHA256SUMS   # shasum -a 256 -c on macOS
//
// so a line-wide search for `--ignore-missing` found the flag in the Linux
// command and passed the macOS one that was missing it. A check that the bug
// itself satisfies is worse than no check.
var checksumCommand = regexp.MustCompile(`(?:sha256sum|shasum -a 256)[^\n#|&;)]*`)

// checkFlag matches the verify mode of either spelling, so that a plain hashing
// command (`sha256sum bin/zcd`) is not held to a flag that does not apply to it.
var checkFlag = regexp.MustCompile(`(?:^|\s)(?:--check|-c)(?:\s|$)`)

// normaliseFingerprint strips the grouping spaces and upper-cases, so the
// whitepaper's `E724 39CE ...` and install.sh's `E72439CE...` compare equal.
func normaliseFingerprint(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), ""))
}

// pgpPacket is one OpenPGP packet: its tag and its body.
type pgpPacket struct {
	tag  int
	body []byte
}

// crc24 is the checksum RFC 4880 puts on the last line of an armoured block.
// It is checked rather than skipped because a truncated key file is the one
// corruption that would otherwise reach a user as a mysterious gpg failure.
func crc24(data []byte) uint32 {
	crc := uint32(0xB704CE)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}

// dearmour returns the binary body of an ASCII-armoured block, after checking
// the CRC-24 trailer.
func dearmour(t *testing.T, armoured string) []byte {
	t.Helper()

	lines := strings.Split(strings.ReplaceAll(armoured, "\r\n", "\n"), "\n")
	var (
		b64      []string
		crcLine  string
		inBlock  bool
		inBase64 bool
		sawEnd   bool
	)
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "-----BEGIN PGP PUBLIC KEY BLOCK-----"):
			inBlock = true
		case strings.HasPrefix(line, "-----END PGP PUBLIC KEY BLOCK-----"):
			sawEnd = true
		case !inBlock:
			// Text before the armour is not part of the block.
		case !inBase64:
			// Armour headers, then one blank line, then the data.
			if strings.TrimSpace(line) == "" {
				inBase64 = true
			}
		case strings.HasPrefix(line, "="):
			crcLine = line[1:]
		case strings.TrimSpace(line) != "":
			b64 = append(b64, strings.TrimSpace(line))
		}
		if sawEnd {
			break
		}
	}
	if !inBlock || !sawEnd {
		t.Fatalf("%s is not an ASCII-armoured PGP public key block.\n"+
			"gpg --import reads armour; a raw or truncated file is not importable.", releaseKeyPath)
	}

	body, err := base64.StdEncoding.DecodeString(strings.Join(b64, ""))
	if err != nil {
		t.Fatalf("the armoured body of %s is not valid base64: %v", releaseKeyPath, err)
	}
	if crcLine == "" {
		t.Fatalf("%s carries no =CRC line. RFC 4880 puts one on every armoured\n"+
			"block and it is the only thing that catches a truncated key file.", releaseKeyPath)
	}
	want, err := base64.StdEncoding.DecodeString(crcLine)
	if err != nil || len(want) != 3 {
		t.Fatalf("the =CRC line of %s is not three base64 bytes: %q", releaseKeyPath, crcLine)
	}
	got := crc24(body)
	wantCRC := uint32(want[0])<<16 | uint32(want[1])<<8 | uint32(want[2])
	if got != wantCRC {
		t.Fatalf("%s has a bad armour checksum: computed %06X, the file says %06X.\n"+
			"The key file is corrupt or was edited inside the base64.", releaseKeyPath, got, wantCRC)
	}
	return body
}

// parsePackets splits an OpenPGP message into its packets. Both the old and the
// new header format are handled: a keyserver may hand out either.
func parsePackets(t *testing.T, data []byte) []pgpPacket {
	t.Helper()

	var packets []pgpPacket
	for i := 0; i < len(data); {
		h := data[i]
		if h&0x80 == 0 {
			t.Fatalf("byte %d of the key is not an OpenPGP packet header (%#02x)", i, h)
		}
		var tag, length, header int
		if h&0x40 != 0 { // new format
			tag = int(h & 0x3f)
			if i+1 >= len(data) {
				t.Fatalf("the key ends inside a packet header at byte %d", i)
			}
			first := int(data[i+1])
			switch {
			case first < 192:
				length, header = first, 2
			case first < 224:
				if i+2 >= len(data) {
					t.Fatalf("the key ends inside a packet length at byte %d", i)
				}
				length, header = (first-192)<<8+int(data[i+2])+192, 3
			case first == 255:
				if i+5 >= len(data) {
					t.Fatalf("the key ends inside a packet length at byte %d", i)
				}
				length = int(data[i+2])<<24 | int(data[i+3])<<16 | int(data[i+4])<<8 | int(data[i+5])
				header = 6
			default:
				t.Fatalf("the key uses a partial-length packet at byte %d, which a public key never needs", i)
			}
		} else { // old format
			tag = int(h&0x3c) >> 2
			switch h & 0x03 {
			case 0:
				length, header = int(data[i+1]), 2
			case 1:
				length, header = int(data[i+1])<<8|int(data[i+2]), 3
			case 2:
				length = int(data[i+1])<<24 | int(data[i+2])<<16 | int(data[i+3])<<8 | int(data[i+4])
				header = 5
			default:
				t.Fatalf("the key uses an indeterminate-length packet at byte %d", i)
			}
		}
		if i+header+length > len(data) {
			t.Fatalf("packet tag %d at byte %d runs past the end of the key", tag, i)
		}
		packets = append(packets, pgpPacket{tag: tag, body: data[i+header : i+header+length]})
		i += header + length
	}
	return packets
}

// v4Fingerprint is RFC 4880 §12.2: SHA-1 over 0x99, the two-byte length of the
// public-key packet body, and the body. It is what `gpg --fingerprint` prints.
func v4Fingerprint(body []byte) string {
	prefix := []byte{0x99, byte(len(body) >> 8), byte(len(body))}
	sum := sha1.Sum(append(prefix, body...))
	return strings.ToUpper(fmt.Sprintf("%x", sum[:]))
}

// whitepaperFingerprint returns the published anchor, or fails the test.
func whitepaperFingerprint(t *testing.T) string {
	t.Helper()
	m := whitepaperGPG.FindStringSubmatch(readRepoFile(t, whitepaperPath))
	if m == nil {
		t.Fatalf("docs/whitepaper.md carries no `GPG: ` header line.\n"+
			"That line is the anti-impersonation anchor: docs/RELEASE.md §8 makes a\n"+
			"mismatch between it and the announcement a release blocker, and\n"+
			"%s exists only to be checked against it.", releaseKeyPath)
	}
	return normaliseFingerprint(m[1])
}

// TestTheShippedKeyIsTheWhitepaperKey is the check every reader is told to
// perform, performed on the file this repository ships.
//
// A key file in a repository is worth exactly the fingerprint it matches. If
// this test could be made to pass by any key, the file would be an
// impersonation surface rather than an anchor: it would be imported, trusted,
// and used to verify signatures made by whoever swapped it in.
func TestTheShippedKeyIsTheWhitepaperKey(t *testing.T) {
	packets := parsePackets(t, dearmour(t, readRepoFile(t, releaseKeyPath)))

	var primary []byte
	for _, p := range packets {
		if p.tag == 6 { // public-key
			primary = p.body
			break
		}
	}
	if primary == nil {
		t.Fatalf("%s contains no public-key packet.", releaseKeyPath)
	}
	if primary[0] != 4 {
		t.Fatalf("%s holds a version %d key; the published fingerprint is a v4 fingerprint.",
			releaseKeyPath, primary[0])
	}

	got := v4Fingerprint(primary)
	want := whitepaperFingerprint(t)
	if got != want {
		t.Errorf("the shipped key is NOT the published key.\n"+
			"  %s hashes to %s\n"+
			"  docs/whitepaper.md publishes  %s\n"+
			"Do not resolve this by editing the whitepaper. The fingerprint in the\n"+
			"paper is the anchor and it never rotates silently: a key that changes\n"+
			"without a signed statement from the old one is indistinguishable from a\n"+
			"compromise (docs/INSTALL.md, \"The signature\").",
			releaseKeyPath, got, want)
	}
}

// TestTheShippedKeyIsImportable pins the exact property the default keyserver's
// copy lacked.
//
// `gpg --import` refuses a key with no user ID — "new key but contains no user
// ID - skipped" — and refuses it silently enough that the next command fails
// looking like a bad signature. A user ID alone is not enough either: without a
// self-signature binding it to the primary key, the user ID is an unattested
// string and gpg treats the key as unusable.
func TestTheShippedKeyIsImportable(t *testing.T) {
	packets := parsePackets(t, dearmour(t, readRepoFile(t, releaseKeyPath)))

	var sawPrimary, sawUserID, sawSelfSig bool
	for _, p := range packets {
		switch p.tag {
		case 6:
			sawPrimary = true
		case 13:
			sawUserID = true
		case 2:
			// A certification over a user ID: 0x10..0x13.
			if len(p.body) >= 2 && p.body[0] == 4 && p.body[1] >= 0x10 && p.body[1] <= 0x13 {
				sawSelfSig = true
			}
		}
	}

	if !sawPrimary {
		t.Fatalf("%s contains no public-key packet.", releaseKeyPath)
	}
	if !sawUserID {
		t.Errorf("%s carries no user-ID packet, so `gpg --import` will refuse it:\n"+
			"  gpg: key ...: new key but contains no user ID - skipped\n"+
			"The key never enters the keyring, and `gpg --verify SHA256SUMS.asc\n"+
			"SHA256SUMS` then fails in a way that reads as a bad signature. This is\n"+
			"the defect exactly: do not ship the stripped copy %s serves.",
			releaseKeyPath, brokenKeyserver)
	}
	if !sawSelfSig {
		t.Errorf("%s carries no self-certification over its user ID.\n"+
			"An unsigned user ID is an unattested string; gpg will not treat the key\n"+
			"as usable. Export the key with `gpg --armor --export <fpr>` from a\n"+
			"keyring that holds the self-signature, not from a stripped keyserver copy.",
			releaseKeyPath)
	}
}

// TestTheInstallDocsCanBeFollowedToAnImportedKey checks that the page a user
// actually reads names a source that works, prints the anchor beside it, and
// warns off the source that does not.
//
// Naming no keyserver was the other half of it: the reader had no way to learn
// that an importable copy exists anywhere.
func TestTheInstallDocsCanBeFollowedToAnImportedKey(t *testing.T) {
	doc := readRepoFile(t, installDocPath)
	fpr := whitepaperFingerprint(t)

	if !strings.Contains(normaliseFingerprint(doc), fpr) {
		t.Errorf("docs/INSTALL.md does not print the project key fingerprint.\n"+
			"The fingerprint is the anchor, and a page that tells a reader to import a\n"+
			"key without telling them what to compare it against has told them to\n"+
			"import whatever they were handed. Expected %s.", fpr)
	}
	if !strings.Contains(doc, "packaging/zycord-release-key.asc") {
		t.Errorf("docs/INSTALL.md does not name packaging/zycord-release-key.asc.\n" +
			"The in-repository copy is the source that needs no network and no\n" +
			"keyserver, which is the whole point of shipping it.")
	}
	if !strings.Contains(doc, workingKeyserver) {
		t.Errorf("docs/INSTALL.md names no keyserver that serves an importable copy.\n"+
			"That omission IS the defect: %s serves this key stripped of its user "+
			"ID, and\n"+
			"with no alternative named the reader has no way to learn that %s\n"+
			"serves a copy gpg will accept.", brokenKeyserver, workingKeyserver)
	}
	if !strings.Contains(doc, brokenKeyserver) {
		t.Errorf("docs/INSTALL.md does not warn about %s.\n"+
			"It is the default keyserver in several GnuPG builds, so a reader who is\n"+
			"not warned will reach it by doing nothing, and will meet a failure that\n"+
			"reads as a bad signature rather than as a missing key.", brokenKeyserver)
	}

	sh := readRepoFile(t, installShPath)
	m := installShFingerprint.FindStringSubmatch(sh)
	if m == nil {
		t.Fatalf("packaging/install.sh defines no PROJECT_KEY_FPR.\n" +
			"Its signature-failure message is the last thing a user sees before they\n" +
			"reach for --no-signature, and it has to name the key and the fingerprint.")
	}
	if got := normaliseFingerprint(m[1]); got != fpr {
		t.Errorf("packaging/install.sh's PROJECT_KEY_FPR is %s, the whitepaper says %s.\n"+
			"Two published fingerprints that disagree are a release blocker, not a typo\n"+
			"(docs/RELEASE.md §8).", got, fpr)
	}
	if !strings.Contains(sh, workingKeyserver) {
		t.Errorf("packaging/install.sh's failure path names no keyserver.\n" +
			"\"Import the project key first\" is not actionable when the default\n" +
			"keyserver serves a copy gpg refuses.")
	}
}

// TestEveryPublishedChecksumCommandIgnoresMissingFiles is the one-line defect
// bundled with the key finding, guarded in both places it can regress.
//
// SHA256SUMS lists every archive the release publishes and a user downloads
// one. Without --ignore-missing, `sha256sum --check` reports the archives that
// are not there as FAILED and exits non-zero — five failures and a non-zero
// exit for a perfectly good download, on the page that says a mismatch means a
// compromised binary. That is how a real warning is made ignorable.
func TestEveryPublishedChecksumCommandIgnoresMissingFiles(t *testing.T) {
	for _, path := range []string{installDocPath, installShPath} {
		for _, line := range checksumCommand.FindAllString(readRepoFile(t, path), -1) {
			if !checkFlag.MatchString(line) {
				continue // hashing something, not verifying against SHA256SUMS.
			}
			if strings.Contains(line, "--ignore-missing") {
				continue
			}
			t.Errorf("%s publishes a checksum command without --ignore-missing:\n"+
				"    %s\n"+
				"SHA256SUMS covers every archive in the release and the reader has one\n"+
				"of them, so this command reports the rest as FAILED and exits 1 for a\n"+
				"good download. packaging/install.sh already builds both spellings with\n"+
				"the flag; the documented command has to match it.",
				path, strings.TrimSpace(line))
		}
	}
}

// TestMakeDistPublishesTheKey checks that the release carries the key, so the
// import needs no keyserver at all.
//
// A key that only exists in the repository helps someone who already has a
// clone. The user this is for downloaded an archive from a release page.
func TestMakeDistPublishesTheKey(t *testing.T) {
	makefile := readRepoFile(t, makefilePath)
	recipe, ok := recipeFor(makefile, "dist")
	if !ok {
		t.Fatalf("the Makefile has no `dist` target; it is what builds the release.")
	}
	if !strings.Contains(recipe, "zycord-release-key.asc") {
		t.Errorf("`make dist` does not stage packaging/zycord-release-key.asc.\n" +
			"docs/INSTALL.md tells the reader to fetch the key from the release page,\n" +
			"so the release has to carry it — otherwise the documented command 404s\n" +
			"and the reader is back to the keyserver that does not work.")
	}
}

// TestTheReleaseChecklistWalksTheVerificationOnAnEmptyKeyring pins the item
// that would have caught the unimportable key before it was published.
//
// The audit's own statement of the gap: install.sh was never run end to end on
// a real host. Every other gate in docs/RELEASE.md §8 builds an artefact and
// hashes it, and a hash cannot tell you that `gpg --import` succeeds.
func TestTheReleaseChecklistWalksTheVerificationOnAnEmptyKeyring(t *testing.T) {
	doc := readRepoFile(t, releaseDocPath)

	var item string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- [ ]") && strings.Contains(line, "empty keyring") {
			item = line
			break
		}
	}
	if item == "" {
		t.Fatalf("docs/RELEASE.md §8 has no checklist item that runs the published\n" +
			"verification commands on an empty keyring. Reading INSTALL.md is not the\n" +
			"check; walking it on a host where this key has never been imported is,\n" +
			"and it is the only gate that would have caught this before publication.")
	}
	for _, must := range []string{"GNUPGHOME", "gpg --verify", workingKeyserver, "--ignore-missing"} {
		if !strings.Contains(item, must) {
			t.Errorf("the empty-keyring checklist item does not mention %q.\n"+
				"The item has to name the commands to run, not the outcome to hope for:\n"+
				"a clean keyring, an import from every source INSTALL.md offers, the\n"+
				"checksum line in both spellings, and the verify.", must)
		}
	}
}
