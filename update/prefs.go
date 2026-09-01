package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mode is what an operator has decided this data directory should do about
// updates.
type Mode string

const (
	// ModeUnset is "nobody has been asked yet", and is not a policy.
	//
	// It is distinct from ModeNever on purpose. The two would behave identically
	// on a server — neither contacts anything — but they mean different things
	// on a terminal, where one is a question to ask once and the other is an
	// answer already given.
	ModeUnset Mode = ""
	// ModeAuto installs a newer release before the node opens its data directory.
	ModeAuto Mode = "auto"
	// ModeNotify checks and says so. Nothing is downloaded, nothing is replaced.
	ModeNotify Mode = "notify"
	// ModeNever contacts nothing.
	ModeNever Mode = "never"
)

// ParseMode reads a mode from a flag or an environment variable.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeUnset:
		return ModeUnset, nil
	case ModeAuto:
		return ModeAuto, nil
	case ModeNotify:
		return ModeNotify, nil
	case ModeNever:
		return ModeNever, nil
	default:
		return ModeUnset, fmt.Errorf("update: %q is not a mode; use auto, notify or never", s)
	}
}

// Checks reports whether this mode contacts the release host at all.
func (m Mode) Checks() bool { return m == ModeAuto || m == ModeNotify }

// PrefsName is the file, inside the node's data directory.
//
// In the data directory rather than a home directory, because zycordd has no
// home-directory resolution and inventing one here would give the node a second
// place to keep state that --dir does not describe. It also makes the policy a
// property of the node instance, which is right: two nodes on one machine can
// reasonably disagree about this.
const PrefsName = "update.json"

// Prefs is the persisted policy for one data directory.
type Prefs struct {
	// Mode is the operator's answer.
	Mode Mode `json:"mode"`
	// Asked records that the question was put, so an operator who chose
	// `notify` by pressing Enter is not asked again on every start.
	Asked bool `json:"asked"`
	// LastCheck bounds how often the host is contacted across restarts, so a
	// node restarted hourly does not check hourly.
	LastCheck time.Time `json:"last_check,omitempty"`
	// DeclinedVersion is the release the operator said no to, so declining once
	// is not re-asked every start for the same version.
	DeclinedVersion string `json:"declined_version,omitempty"`
	// RevokedKeys records keys retired by a rotation this node has seen, so a
	// promotion is not re-applied and a retired key is refused from then on.
	RevokedKeys []string `json:"revoked_keys,omitempty"`
}

// PrefsPath is where the file lives for a data directory.
func PrefsPath(dir string) string { return filepath.Join(dir, PrefsName) }

// LoadPrefs reads the policy for a data directory.
//
// A missing file is not an error: it is what every node looks like before it has
// been asked. A malformed one is also not an error — it returns the zero policy
// with a note, because **a node must never refuse to start over a preference
// file.** The worst outcome of ignoring a corrupt one is that an operator is
// asked a question again; the worst outcome of failing on it is a miner whose
// node will not come up and who has no idea why.
func LoadPrefs(dir string) (Prefs, string) {
	raw, err := os.ReadFile(PrefsPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return Prefs{}, ""
	}
	if err != nil {
		return Prefs{}, fmt.Sprintf("update: %s could not be read (%v); continuing as if no choice were recorded", PrefsName, err)
	}
	var p Prefs
	if err := json.Unmarshal(raw, &p); err != nil {
		return Prefs{}, fmt.Sprintf("update: %s does not parse (%v); continuing as if no choice were recorded", PrefsName, err)
	}
	if _, err := ParseMode(string(p.Mode)); err != nil {
		return Prefs{}, fmt.Sprintf("update: %s records mode %q, which this build does not know; continuing as if no choice were recorded", PrefsName, p.Mode)
	}
	return p, ""
}

// SavePrefs writes the policy.
//
// 0o600 and atomic. It holds no secret, but it decides whether this machine
// downloads and executes new code, which is not something another user on the
// box should be able to edit.
func SavePrefs(dir string, p Prefs) error {
	return writeJSONAtomic(PrefsPath(dir), p, 0o600)
}

// IsRevoked reports whether a key id has been retired by a rotation this node
// has already applied.
func (p Prefs) IsRevoked(id string) bool {
	for _, k := range p.RevokedKeys {
		if k == id {
			return true
		}
	}
	return false
}

// Revoke records a retired key, idempotently.
func (p Prefs) Revoke(id string) Prefs {
	if id == "" || p.IsRevoked(id) {
		return p
	}
	p.RevokedKeys = append(append([]string(nil), p.RevokedKeys...), id)
	return p
}
