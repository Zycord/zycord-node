// The half of the identity guard that CAN live in git.
//
// `anonymity_test.go` explains why the class that matters most — real name,
// account handle, the other project's codename — cannot be carried by a
// tracked regexp: writing the handle into a tracked pattern publishes the
// handle. That argument is correct and it has a blind spot, which was paid for
// once already.
//
// The leak that actually happened was not a bare handle. It was a **shape**:
// an absolute forge URL, `<scheme>://github.com/<account>/<repo>/issues/<n>`,
// repeated 68 times across ten tracked files, one of which `make dist` copies
// into the staging directory of all six platform archives. The account segment
// of that URL is a handle by construction — a forge has no other kind of first
// path segment.
//
// And the *shape* is safe to write down. `github.com` is not an identity: it is
// the name of a service, it appears in every `go.mod` in the ecosystem, and a
// tracked regexp for it publishes nothing. So this class is asserted by a test
// that is in the repository, cannot be forgotten, needs no environment
// variable, and — unlike the untracked identity patterns `anonymity_test.go`
// used to load, which have since been removed along with their loader — cannot
// be absent.
//
// # What this asserts, exactly
//
// No tracked file may contain an absolute URL into this forge whose first path
// segment is not on `allowedAccounts` below. Three things follow:
//
//   - It does not know the author's handle and never will. It refuses every
//     account it has not been told about, which is the same refusal for the
//     author's handle as for a stranger's.
//   - The allow-list is a tracked diff. Adding the author's own account to it
//     to make a red run green would be a deliberate, reviewable line — not the
//     silent drift an exemption table normally accumulates.
//   - Module paths and imports (`github.com/wailsapp/wails/v2`) are untouched:
//     they carry no scheme, and this pattern requires one. `go.mod`, `go.sum`
//     and every Go import stay exactly as they are.
//
// # What it does not assert
//
// Other forges, and any other venue an account name can be spelled into. The
// pattern is deliberately one forge rather than a general "URL with a name in
// it": this is the forge this project uses, the shape is exact, and a vaguer
// pattern would fire on ordinary links and be suppressed within a week — the
// failure mode `anonymity_test.go` documents at length.
//
// A bare `#NNN` reference, which is what the 68 URLs became, resolves to
// nothing in a repository published under a different origin. Making the prose
// self-contained is a separate, later sweep; this test only guarantees that the
// reference cannot be *re-expanded* into a URL naming an account.
//
// # Why this file needs no self-exemption
//
// `anonymity_test.go` has to skip itself, because it contains every pattern it
// scans for. This one does not, and that is a property worth keeping — an
// exempted path is the one place a leak can be quoted into, which is a mistake
// that file records having made.
//
// Three details buy it. The regexp source is not matched by the regexp it
// compiles: `https?` needs a literal `http`, and the source spells it `https?`.
// The allow-listed accounts are written as bare names rather than as links.
// And the probe in the arming test assembles its scheme from two pieces, so no
// complete URL is spelled anywhere in this file. So this file is scanned like
// every other, and a URL pasted into it fails the run.
package wiring_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// forgeURL matches an absolute URL into the forge and captures the account.
//
// The account segment stops at the next path separator or at any character
// that ends a URL in prose, markdown, shell or JSON. Angle brackets are *kept*
// rather than excluded, because both shapes that legitimately occur here carry
// them: the `<publisher>` substitution placeholder in the install docs, and the
// `<...>` autolink form upstream's copyright headers use. `trimBrackets` takes
// them off before the comparison, so one entry covers both spellings.
var forgeURL = regexp.MustCompile(`(?i)https?://(?:www\.)?github\.com/([A-Za-z0-9_.<>-]*)`)

// allowedAccounts is the closed list of first path segments that may appear in
// an absolute forge URL in this tree, and the reason each one is there.
//
// Compared case-insensitively and after `trimBrackets`, so `PUBLISHER` and
// `<publisher>` are the same entry.
//
// **Nothing here is the author.** That is the whole design: the list is
// placeholders and third-party upstreams, so the account this repository must
// never publish is refused by the default rather than by an exception.
var allowedAccounts = map[string]string{
	// The organisation this repository is published under.
	//
	// **This is the one entry that is the project's own account, and adding it
	// was a decision rather than a convenience.** The list was built so that
	// the publishing account is refused BY DEFAULT, on the argument that
	// publication is a one-way door and a name in the tree is an identity.
	// That argument was written before publication. It has since happened: the
	// repository lives at this account, every release archive is served from
	// it, and a reader holding this tree got it from a URL that already
	// carried the name. The guard was refusing to write down something the
	// reader had to know to arrive.
	//
	// What it cost while it held is the part worth recording, because it is
	// what tipped this. Install instructions could not name where to install
	// from; the README could not link its own releases page and said "this
	// repository's Releases page" in prose instead; the issue-template config
	// could carry no contact_links at all, since those take an absolute URL.
	// Three places where a reader was sent looking rather than pointed.
	//
	// The entry has moved once, and the move is the reason to read it as an
	// address rather than as a name. The account this project first published
	// under was permanently suspended, and the repository now lives at this
	// organisation under a new name. The old account is deliberately NOT kept
	// beside this one: it serves nothing, so a URL still naming it is a broken
	// download rather than a historical note, and this guard going red is how
	// the next one gets found.
	//
	// **The property that matters survives intact**: this list is closed, so
	// every OTHER account still fails, including the one that would actually
	// deanonymise. Nothing about this entry loosens that -- it names one
	// account, and the sweep for the rest is exactly as tight as it was.
	"zycord": "the publishing organisation; see the note above for why it is here",

	// The substitution placeholder, kept beside the real account rather than
	// replaced by it. packaging/ still writes it: those files are copied into
	// forks and mirrors, RELEASE.md §8 stamps them at publication, and a fork
	// that inherits a hard-coded upstream account silently installs from
	// somewhere its user did not choose.
	"publisher": "substitution placeholder, still used by packaging/",

	// Upstream RandomX: the pinned source this repository vendors. It names
	// the upstream project, not us, and core/pow/randomx/PINNED exists to
	// record exactly which upstream the vendored tree came from.
	"tevador": "upstream RandomX, recorded in core/pow/randomx/PINNED",

	// RandomX's second author, in the copyright headers of the vendored
	// JIT sources. Reproducing a copyright notice is a licence obligation;
	// removing it would be a licence violation dressed as a privacy fix.
	"schernykh": "vendored RandomX copyright notice (licence obligation)",

	// The Argon2 reference implementation vendored inside RandomX, cited in
	// its BSD/CC0 headers. Same obligation as above.
	"p-h-c": "vendored Argon2 licence header (licence obligation)",

	// The third-party AppImage tool packaging/appimage/build.sh documents
	// fetching. A build dependency's own address, published by that project.
	"linuxdeploy": "third-party AppImage tool used by packaging/appimage",
}

// trimBrackets removes the autolink and placeholder brackets around an account.
func trimBrackets(account string) string {
	return strings.Trim(account, "<>")
}

// TestNoAbsoluteGitHubURLIsPublished refuses an absolute forge URL naming an
// account that is not on allowedAccounts.
//
// Same subject as TestNoMachineIdentifierIsPublished — the git index, because
// that is what publication copies — and the same treatment of what it cannot
// read: symlinks, gitlinks and binaries belong to
// TestNothingPublishedIsOpaqueToTheTextScan, which fails on them rather than
// letting them pass unread.
func TestNoAbsoluteGitHubURLIsPublished(t *testing.T) {
	root := filepath.Join("..", "..")

	// Every match on a line is reported, not the first: a report that stops at
	// one match tells whoever is fixing it that they are done when they are not.
	var findings []string

	for _, f := range trackedFiles(t, root) {
		if f.symlink() || f.gitlink() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.path)))
		if err != nil {
			t.Fatalf("read tracked file %s: %s", f.path, reason(err))
		}
		if !isText(body) {
			continue
		}
		for lineNo, line := range strings.Split(string(body), "\n") {
			for _, m := range forgeURL.FindAllStringSubmatch(line, -1) {
				account := strings.ToLower(trimBrackets(m[1]))
				if _, ok := allowedAccounts[account]; ok {
					continue
				}
				// The matched URL is echoed back. That is safe here and
				// deliberate: this test only ever prints strings that are
				// already in the tracked tree, which is the tree about to be
				// published, and a finding that does not say WHICH URL cannot
				// be acted on. Contrast the removed identity loader, which
				// printed no value at all because the values it handled were
				// themselves the secret — see `reason` in tracked_test.go for
				// the rule that survived it.
				findings = append(findings, f.path+":"+strconv.Itoa(lineNo+1)+
					"  "+m[0])
			}
		}
	}

	if len(findings) > 0 {
		t.Fatalf("%d absolute forge URL(s) name an account this tree may not "+
			"publish:\n  %s\n\n"+
			"The first path segment of a forge URL is an account name, and this "+
			"repository is published pseudonymously: an account name in it is an\n"+
			"identity, and publication is a one-way door.\n"+
			"Write the reference as a bare #NNN instead. If the URL genuinely "+
			"belongs to an upstream project or is a substitution placeholder, "+
			"add the account to allowedAccounts in this file with the reason — "+
			"in the diff, where it can be reviewed.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// TestTheForgeURLGuardActuallyFires is the arming charge.
//
// A guard nobody has seen fail is a guard nobody has seen. This pins the two
// halves that could rot independently: the pattern must match the shape that
// actually leaked, and an account that is not on the allow-list must not be
// waved through by the lookup.
func TestTheForgeURLGuardActuallyFires(t *testing.T) {
	// Neither the author's handle nor any real account appears here: the
	// account name below is a fabrication, which is exactly what the test
	// needs, because the guard's claim is about the SHAPE.
	//
	// **The scheme is assembled rather than written**, and that is not
	// obfuscation for its own sake: this file is scanned by the test above like
	// every other tracked file, and a probe spelled out in full would make the
	// guard fail on its own source. The alternative is a self-exemption, and an
	// exempted path is the one place a leak can be quoted into — the mistake
	// `anonymity_test.go` records having made with `selfPath` and the identity
	// class. Splitting the literal is the cheaper half of that trade.
	const forge = "github.com"
	// The link TEXT is ordinary words rather than a bare issue number, and that
	// is not cosmetic either: `history_reference_test.go` scans this file too,
	// and it strips a markdown link's target before it looks, so a number in
	// the text is the one half of a link it still sees. What this probe pins is
	// the SHAPE of the target, so the text is free to be prose and had better
	// be.
	probe := "see [the finding](http" + "s://" + forge +
		"/not-a-real-account/zycord/issues/578) for the record"

	m := forgeURL.FindStringSubmatch(probe)
	if m == nil {
		t.Fatal("the pattern no longer matches the shape that leaked: an " +
			"absolute forge URL in a markdown link. That shape is the whole " +
			"subject of this file.")
	}
	if got := strings.ToLower(trimBrackets(m[1])); got != "not-a-real-account" {
		t.Fatalf("captured account %q, want the first path segment: the "+
			"allow-list is keyed on it, so a capture that drifts turns every "+
			"lookup into a miss or a false hit", got)
	}
	if _, ok := allowedAccounts[strings.ToLower(m[1])]; ok {
		t.Fatal("an account nobody put on the allow-list is on the allow-list")
	}

	// Both spellings of the placeholder resolve to one entry, and the
	// autolinked upstream form loses its bracket. If this stops holding the
	// tree goes red for reasons that have nothing to do with a leak, which is
	// how a guard gets suppressed.
	for _, spelling := range []string{"PUBLISHER", "<publisher>", "SChernykh>"} {
		if _, ok := allowedAccounts[strings.ToLower(trimBrackets(spelling))]; !ok {
			t.Errorf("%q does not resolve to an allow-list entry", spelling)
		}
	}

	// A module path is not an absolute URL and must stay invisible here: this
	// pattern must never touch go.mod, go.sum or a Go import.
	if forgeURL.MatchString("\tgithub.com/wailsapp/wails/v2 v2.15.0 // indirect") {
		t.Error("a scheme-less module path matched: this guard would fire on " +
			"every go.mod in the tree and be suppressed within a week")
	}
}
