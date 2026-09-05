package update

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// defaultRepoURL is where releases are published.
//
// A constant in the source, exactly as packaging/install.sh carries it, and for
// the reasons that file records: the repository is published, so the account is
// not a secret this program could keep — a reader downloaded the binary from it
// — and a placeholder substituted at release time is a step that has to actually
// happen, which for install.sh it never did.
//
// It was briefly designed as a link-time stamp instead. That would have made the
// release host a BUILD INPUT with no free reproduction: a verifier following
// docs/INSTALL.md runs `make build` and compares against SHA256SUMS.binaries, and
// one they could not guess turns an honest check into a hash mismatch — which
// that same document tells them looks like a compromised binary.
//
// A fork or a mirror overrides it, which is the mechanism install.sh already
// offers.
const defaultRepoURL = "https://github.com/Zycord/zycord-node"

// repoURLEnv names the override. Spelled the same as install.sh's, so an
// operator who has set one for the installer does not discover a second name.
const repoURLEnv = "ZYCORD_REPO_URL"

// RepoURL is the release host this process will talk to.
func RepoURL() string {
	if v := strings.TrimSpace(os.Getenv(repoURLEnv)); v != "" {
		return v
	}
	return defaultRepoURL
}

// validateRepoURL refuses a base URL that could be intercepted.
//
// https, or http to a loopback address. The carve-out is not a convenience: a
// loopback URL cannot be reached by a network attacker at all, and it is what
// the test harness and a local mirror use. Every other plaintext URL is refused
// rather than warned about — install.sh pins `--proto '=https'` for the same
// reason and this is the Go spelling of it.
func validateRepoURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("update: %s is not a URL: %w", repoURLEnv, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("update: %q names no host", raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("update: %q is plaintext http to %s; releases are fetched over https", raw, u.Hostname())
	default:
		return nil, fmt.Errorf("update: %q has scheme %q", raw, u.Scheme)
	}
}

// isLoopbackHost reports whether a host names this machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
