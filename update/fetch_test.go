package update_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"zycord/update"
)

// release is a fake release host: it serves a signed manifest and one archive,
// and records what was asked for.
type release struct {
	t        *testing.T
	signer   signer
	manifest []byte
	sig      []byte
	assets   map[string][]byte
	srv      *httptest.Server
	requests []*http.Request

	// knobs
	dropSignature bool
	corruptAsset  bool
	extraBytes    int
	status        int
}

func newRelease(t *testing.T, body string) *release {
	t.Helper()
	s := newSigner(t)
	r := &release{t: t, signer: s, manifest: []byte(body), assets: map[string][]byte{}}
	r.sig = s.sign(s.current, r.manifest)
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.requests = append(r.requests, req)
		if r.status != 0 {
			w.WriteHeader(r.status)
			return
		}
		switch {
		case strings.HasSuffix(req.URL.Path, "update-manifest.json.sig"):
			if r.dropSignature {
				http.NotFound(w, req)
				return
			}
			w.Write(r.sig)
		case strings.HasSuffix(req.URL.Path, "update-manifest.json"):
			w.Write(r.manifest)
		default:
			name := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			body, ok := r.assets[name]
			if !ok {
				http.NotFound(w, req)
				return
			}
			if r.corruptAsset {
				body = append([]byte("x"), body[1:]...)
			}
			if r.extraBytes > 0 {
				body = append(body, make([]byte, r.extraBytes)...)
			}
			w.Write(body)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *release) fetcher() *update.Fetcher {
	return &update.Fetcher{Base: r.srv.URL, Client: r.srv.Client()}
}

// manifestWithAsset builds a manifest naming one archive with a real digest.
func manifestWithAsset(file string, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf(`{
  "schema": 1,
  "project": "zycord",
  "version": "v0.2.0",
  "published_at": "2026-09-30T14:02:11Z",
  "urgency": "routine",
  "note": "Nothing alarming.",
  "products": {"zycord-cli": {"assets": {
    "linux-amd64": {"file": %q, "sha256": %q, "size": %d}
  }}}
}`, file, hex.EncodeToString(sum[:]), len(body))
}

// TestAManifestIsFetchedAndVerified is the happy path end to end over HTTP.
func TestAManifestIsFetchedAndVerified(t *testing.T) {
	r := newRelease(t, goodManifest())
	m, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if m.Version != "v0.2.0" {
		t.Errorf("Version = %q", m.Version)
	}
	if len(r.requests) != 2 {
		t.Fatalf("made %d requests, want 2 (the document and its signature)", len(r.requests))
	}
	for _, req := range r.requests {
		if got := req.Header.Get("User-Agent"); got != "zycord-update/1" {
			t.Errorf("User-Agent = %q; every Zycord binary must send the same constant, "+
				"carrying no version, OS or architecture", got)
		}
	}
	if got := r.requests[0].URL.Path; !strings.Contains(got, "/releases/latest/download/") {
		t.Errorf("manifest path = %q", got)
	}
}

// TestNoManifestIsQuietAndAMissingSignatureIsNot.
//
// A release with no manifest is the ordinary state of everything published
// before this feature existed, so it must be distinguishable from a release
// whose signature has been stripped — which is an attack shape.
func TestNoManifestIsQuietAndAMissingSignatureIsNot(t *testing.T) {
	t.Run("no manifest at all", func(t *testing.T) {
		r := newRelease(t, goodManifest())
		r.status = http.StatusNotFound
		_, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
		if !errors.Is(err, update.ErrNoManifest) {
			t.Errorf("err = %v, want ErrNoManifest", err)
		}
	})
	t.Run("manifest served, signature stripped", func(t *testing.T) {
		r := newRelease(t, goodManifest())
		r.dropSignature = true
		_, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
		if !errors.Is(err, update.ErrNoSignature) {
			t.Errorf("err = %v, want ErrNoSignature - a 200 on the document and a 404 on its "+
				"signature is what signature stripping looks like", err)
		}
	})
}

// TestAServerErrorIsTransient. The host's problem is not this node's, and a node
// that logs an error every six hours because a CDN is having a day is a node
// whose logs get ignored.
func TestAServerErrorIsTransient(t *testing.T) {
	r := newRelease(t, goodManifest())
	r.status = http.StatusBadGateway
	_, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
	if !errors.Is(err, update.ErrTransient) {
		t.Errorf("err = %v, want ErrTransient", err)
	}
}

// TestAnOversizeManifestIsRefusedBeforeItIsParsed.
func TestAnOversizeManifestIsRefusedBeforeItIsParsed(t *testing.T) {
	r := newRelease(t, goodManifest())
	r.manifest = []byte(strings.Repeat("a", 2<<20))
	_, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
	if err == nil {
		t.Fatal("a 2 MiB manifest was read")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v, want a size refusal", err)
	}
}

// TestAnAssetIsVerifiedAgainstTheManifestThatNamedIt walks the three ways a
// download can be wrong, each of which must be its own error.
func TestAnAssetIsVerifiedAgainstTheManifestThatNamedIt(t *testing.T) {
	body := []byte("this is a release archive, honest")
	const file = "zycord-0.2.0-linux-amd64.tar.gz"

	newOne := func(t *testing.T) *release {
		r := newRelease(t, manifestWithAsset(file, body))
		r.assets[file] = body
		return r
	}

	t.Run("intact", func(t *testing.T) {
		r := newOne(t)
		m, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
		if err != nil {
			t.Fatal(err)
		}
		a, err := m.Asset(update.ProductCLI, "linux-amd64")
		if err != nil {
			t.Fatal(err)
		}
		path, err := r.fetcher().FetchAsset(context.Background(), m, a, t.TempDir())
		if err != nil {
			t.Fatalf("a good archive was refused: %v", err)
		}
		if path == "" {
			t.Error("no path returned")
		}
	})

	for _, tc := range []struct {
		name string
		set  func(*release)
		want string
	}{
		{"wrong bytes, right length", func(r *release) { r.corruptAsset = true }, "digest"},
		{"more bytes than the manifest says", func(r *release) { r.extraBytes = 16 }, "bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newOne(t)
			tc.set(r)
			m, err := r.fetcher().FetchManifest(context.Background(), r.signer.set)
			if err != nil {
				t.Fatal(err)
			}
			a, err := m.Asset(update.ProductCLI, "linux-amd64")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if _, err := r.fetcher().FetchAsset(context.Background(), m, a, dir); err == nil {
				t.Fatalf("accepted an archive with %s", tc.name)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			// And nothing is left behind for a later run to find and trust.
			entries, _ := readDirNames(dir)
			if len(entries) != 0 {
				t.Errorf("a failed download left %v in place", entries)
			}
		})
	}
}

// TestTheAssetURLPinsTheVersionRatherThanFollowingLatest.
//
// `latest` can move between the manifest fetch and the asset fetch. A release
// published in that window would hand a node bytes whose digest the manifest it
// just verified says nothing about.
func TestTheAssetURLPinsTheVersionRatherThanFollowingLatest(t *testing.T) {
	r := newRelease(t, goodManifest())
	u, err := r.fetcher().AssetURL("v0.2.0", "zycord-0.2.0-linux-amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u, "latest") {
		t.Errorf("asset URL follows latest: %s", u)
	}
	if !strings.Contains(u, "/releases/download/v0.2.0/") {
		t.Errorf("asset URL does not pin the tag: %s", u)
	}
}

// TestAPlaintextReleaseHostIsRefusedUnlessItIsThisMachine.
func TestAPlaintextReleaseHostIsRefusedUnlessItIsThisMachine(t *testing.T) {
	for _, tc := range []struct {
		base string
		ok   bool
	}{
		{"https://github.com/Zycord/zycord-node", true},
		{"http://127.0.0.1:9999/x", true},   // the test harness and a local mirror
		{"http://localhost:9999/x", true},   //
		{"http://[::1]:9999/x", true},       //
		{"http://example.invalid/x", false}, // plaintext to a real host
		{"ftp://example.invalid/x", false},
		{"not a url at all", false},
		// Empty is not an invalid host, it is "use the compiled-in one", which
		// is how every ordinary caller reaches this. Asserted so a later change
		// that made an unset Base an error would be caught here rather than by
		// every node failing its first check.
		{"", true},
	} {
		t.Run(tc.base, func(t *testing.T) {
			f := &update.Fetcher{Base: tc.base}
			_, err := f.ManifestURL()
			if tc.ok && err != nil {
				t.Errorf("refused %q: %v", tc.base, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("accepted %q", tc.base)
			}
		})
	}
}

// TestARedirectToPlaintextIsRefused. A 302 from https to http is a downgrade
// whether or not anything sensitive is being carried.
func TestARedirectToPlaintextIsRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nope"))
	}))
	defer plain.Close()

	// A TLS origin that bounces to a non-loopback plaintext URL.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/elsewhere", http.StatusFound)
	}))
	defer tlsSrv.Close()

	client := tlsSrv.Client()
	client.CheckRedirect = update.DefaultClient().CheckRedirect
	f := &update.Fetcher{Base: tlsSrv.URL, Client: client}
	_, err := f.FetchManifest(context.Background(), newSigner(t).set)
	if err == nil {
		t.Fatal("followed a redirect from https to plaintext")
	}
	if !strings.Contains(err.Error(), "not https") {
		t.Errorf("err = %v, want a scheme refusal", err)
	}
}

// readDirNames is a small helper so a failed-download assertion can say what was
// left behind.
func readDirNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}
