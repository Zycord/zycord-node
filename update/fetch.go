package update

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"
)

// Fetcher retrieves the manifest and the archive it names.
//
// It is the only code in this package that talks to a network, and everything
// about it is bounded: the URLs it will build, the time it will wait, the bytes
// it will read, and what it will say about the machine it runs on.
type Fetcher struct {
	// Base is the release host. Empty means RepoURL().
	Base string
	// Client is the HTTP client. Empty means DefaultClient().
	Client *http.Client
}

// The two documents, at fixed names under the newest release.
const (
	manifestName  = "update-manifest.json"
	signatureName = "update-manifest.json.sig"
)

// userAgent is what every Zycord binary in the world sends, identically.
//
// No version, no OS, no architecture. Which asset a node later asks for already
// discloses its platform and that is unavoidable; repeating it in a header buys
// nothing and moves a per-install fingerprint one field closer to existing. A
// constant string is the most this request needs to say.
const userAgent = "zycord-update/1"

// Bounds. Each one is the answer to "what does a hostile or broken server get to
// make this process do".
const (
	maxManifest  = 1 << 20 // a two-product manifest is a few kB; this is 100x headroom
	maxSignature = 1 << 12
	maxRedirects = 10

	manifestTimeout = 20 * time.Second
	archiveTimeout  = 10 * time.Minute
)

// Errors a caller distinguishes rather than lumping into "the check failed".
var (
	// ErrNoManifest is a release that publishes no manifest.
	//
	// This is the NORMAL state for every release cut before this feature
	// existed, so it must degrade quietly: a node that logs an error because the
	// project has not published a manifest yet is a node whose logs get ignored.
	ErrNoManifest = errors.New("update: this release publishes no update manifest")

	// ErrNoSignature is a manifest served without one, and it is the opposite of
	// quiet. A 200 on the document and a 404 on its signature is the shape a
	// signature-stripping attempt takes.
	ErrNoSignature = errors.New("update: the manifest is published without a signature")

	// ErrTransient is a network failure. Non-fatal everywhere.
	ErrTransient = errors.New("update: the release host could not be reached")
)

// DefaultClient is the HTTP client used when none is supplied.
func DefaultClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// Set explicitly. Building a Transport to get the TLS floor below
			// means NOT inheriting http.DefaultTransport, and its proxy support
			// goes with it: without this line a node behind a corporate proxy
			// silently cannot check, and an operator running everything through
			// a tunnel would find this one request ignoring it.
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				// 1.2, not 1.3. A middlebox or an older CDN edge terminating at
				// 1.2 is a real deployment, and refusing it does not make that
				// operator safer - it makes them pass --no-update-check once and
				// never check again. install.sh pins --tlsv1.2 for the same
				// reason, so the two agree.
				MinVersion: tls.VersionTLS12,
			},
			// A server that accepts a connection and then says nothing must fail
			// in seconds rather than at the whole-request bound.
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Redirects must be followed: releases/latest/download 302s to the
			// asset host. They are bounded, and every hop is re-checked for
			// scheme - a 302 from https to http is a downgrade whether or not
			// anything sensitive is being sent.
			if len(via) >= maxRedirects {
				return fmt.Errorf("update: more than %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" && !isLoopbackHost(req.URL.Hostname()) {
				return fmt.Errorf("update: redirected to %s, which is not https", req.URL.Scheme)
			}
			// No header-stripping rule, and the reason is worth stating rather
			// than implementing: this request carries no credentials at all, so
			// a cross-host redirect has nothing to leak.
			return nil
		},
	}
}

func (f *Fetcher) base() string {
	if f.Base != "" {
		return f.Base
	}
	return RepoURL()
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return DefaultClient()
}

// ManifestURL and SignatureURL name the two documents under the newest release.
//
// `releases/latest/download/<name>` rather than the API: no token, no rate
// limit, no JSON schema belonging to somebody else, and GitHub's `latest`
// excludes pre-releases for free. What `latest` resolves to is the SERVER's
// opinion, which is why the manifest names its own version and why a downgrade
// is refused on the parsed value rather than trusted from the path.
func (f *Fetcher) ManifestURL() (string, error) {
	return f.join("releases", "latest", "download", manifestName)
}

// SignatureURL is the detached signature beside it.
func (f *Fetcher) SignatureURL() (string, error) {
	return f.join("releases", "latest", "download", signatureName)
}

// AssetURL names one archive under a SPECIFIC tag.
//
// The pinned tag, never `latest/download`. `latest` can move between the
// manifest fetch and the asset fetch — a release published in that window would
// hand a node bytes whose digest the manifest it just verified says nothing
// about. Pinning the version closes that window.
func (f *Fetcher) AssetURL(version, file string) (string, error) {
	if version == "" || file == "" {
		return "", errors.New("update: an asset URL needs a version and a file name")
	}
	return f.join("releases", "download", version, file)
}

func (f *Fetcher) join(parts ...string) (string, error) {
	u, err := validateRepoURL(f.base())
	if err != nil {
		return "", err
	}
	for _, p := range parts {
		// Every part is either a fixed constant above or a value already
		// validated out of a signed manifest, so this escapes rather than
		// rejects; it exists so that a future caller cannot make a path out of
		// one by accident.
		u.Path = path.Join(u.Path, url.PathEscape(p))
	}
	return u.String(), nil
}

// FetchManifest retrieves the manifest and its signature and verifies them
// against the key set, returning the parsed document.
//
// The two documents are fetched separately and on purpose: a 404 on the manifest
// is the ordinary state of a release published before this feature existed, and
// a 404 on the signature while the manifest is present is a signature-stripping
// attempt. Collapsing them into one request would make those the same event.
func (f *Fetcher) FetchManifest(ctx context.Context, ks KeySet) (*Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, manifestTimeout)
	defer cancel()

	mURL, err := f.ManifestURL()
	if err != nil {
		return nil, err
	}
	raw, err := f.get(ctx, mURL, maxManifest)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, ErrNoManifest
		}
		return nil, err
	}

	sURL, err := f.SignatureURL()
	if err != nil {
		return nil, err
	}
	sig, err := f.get(ctx, sURL, maxSignature)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, ErrNoSignature
		}
		return nil, err
	}
	return ParseManifest(raw, sig, ks)
}

// FetchAsset downloads one archive to a file in dir and verifies it.
//
// The digest is checked before the path is returned, so a caller cannot be
// handed bytes that have not been proved. On any failure the partial file is
// removed rather than left for a later run to find and trust.
func (f *Fetcher) FetchAsset(ctx context.Context, m *Manifest, a Asset, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, archiveTimeout)
	defer cancel()

	aURL, err := f.AssetURL(m.Version, a.File)
	if err != nil {
		return "", err
	}
	req, err := f.request(ctx, aURL)
	if err != nil {
		return "", err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTransient, err)
	}
	defer resp.Body.Close()
	if err := statusError(resp, aURL); err != nil {
		return "", err
	}

	// Named for the asset so a directory listing during a download says what is
	// happening, and created inside the caller's directory so the later rename
	// onto a binary cannot cross a filesystem.
	tmp, err := os.CreateTemp(dir, "."+a.File+".part-*")
	if err != nil {
		return "", err
	}
	// Not named `path`: this file imports the path package a few functions up,
	// and a local that shadows it is how a later edit calls the wrong Join.
	dst := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(dst)
		}
	}()

	// size+1, so "the server sent more than the manifest says" is its own error
	// rather than a digest mismatch that says nothing about which half is wrong.
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, a.Size+1))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTransient, err)
	}
	if err = tmp.Sync(); err != nil {
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	if n != a.Size {
		err = fmt.Errorf("update: %s is %d bytes, the manifest says %d", a.File, n, a.Size)
		return "", err
	}
	var got [sha256.Size]byte
	copy(got[:], h.Sum(nil))
	if got != a.Digest() {
		err = fmt.Errorf("update: %s does not match the digest the manifest signs for it", a.File)
		return "", err
	}
	return dst, nil
}

// errNotFound is a 404, which two callers above turn into different errors.
var errNotFound = errors.New("update: not published")

func (f *Fetcher) request(ctx context.Context, u string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	// Asked for explicitly so a caching proxy cannot answer a manifest request
	// from a copy older than the one being replaced.
	req.Header.Set("Cache-Control", "no-cache")
	return req, nil
}

func (f *Fetcher) get(ctx context.Context, u string, max int64) ([]byte, error) {
	req, err := f.request(ctx, u)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransient, err)
	}
	defer resp.Body.Close()
	if err := statusError(resp, u); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransient, err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("update: %s is larger than %d bytes", u, max)
	}
	return body, nil
}

// statusError maps a response status onto the distinctions a caller acts on.
func statusError(resp *http.Response, u string) error {
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode >= 500:
		// The host's problem, not this node's. Transient, and quiet.
		return fmt.Errorf("%w: %s returned %d", ErrTransient, u, resp.StatusCode)
	default:
		return fmt.Errorf("update: %s returned %d", u, resp.StatusCode)
	}
}
