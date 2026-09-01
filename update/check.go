package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// Outcome is what a check found. Every one of these is a distinct thing to say
// to an operator, and collapsing any two of them loses information somebody acts
// on.
type Outcome int

const (
	// OutcomeUpToDate: the published release is the one running.
	OutcomeUpToDate Outcome = iota
	// OutcomeAvailable: something newer is published.
	OutcomeAvailable
	// OutcomeOlder: the published release is OLDER than the one running.
	//
	// Reported, never folded into "up to date". A manifest naming an older
	// version is either a replayed old document or a botched release, and
	// silence is the wrong answer to both.
	OutcomeOlder
	// OutcomeNotARelease: this binary is not built from a tag, so it is never
	// replaced automatically. A developer testing a branch must not have that
	// binary swapped for a release.
	OutcomeNotARelease
	// OutcomeNoManifest: this release publishes none. Ordinary, and quiet.
	OutcomeNoManifest
	// OutcomeNoAsset: nothing is published for this platform and tier.
	OutcomeNoAsset
)

// Checker performs one update check.
type Checker struct {
	// Fetcher reaches the release host. Nil means a default one.
	Fetcher *Fetcher
	// Keys is the set a manifest signature must verify against.
	Keys KeySet
	// Current is the version string this binary was stamped with.
	Current string
	// RandomX is whether this binary carries the mining engine, which decides
	// which tier's archive it may take.
	RandomX bool
	// Product is which archive family to look in.
	Product string
	// Revoked is key ids this node has already seen retired by a rotation.
	Revoked []string
}

// Result is one check's answer.
type Result struct {
	Outcome  Outcome
	Current  Version
	Manifest *Manifest
	Asset    Asset
	Platform string

	// Refusal is why this install cannot be replaced in place, when that is
	// known. An update can be available AND unreplaceable, and an operator needs
	// to be told both at once rather than discovering the second after agreeing
	// to the first.
	Refusal *Refusal

	// Promotes is a key id this manifest retires, when it retires this build's
	// signing key. The caller persists it.
	Promotes string
}

// Available reports whether a newer release exists, whatever can be done about it.
func (r *Result) Available() bool { return r.Outcome == OutcomeAvailable }

// Check contacts the release host once.
func (c *Checker) Check(ctx context.Context) (*Result, error) {
	cur, err := ParseVersion(c.Current)
	res := &Result{Current: cur}
	// Two different things are both "never replace this", and checking only the
	// first was a defect its own test caught: `dev` and a bare commit hash fail
	// to PARSE, but `v0.1.0-9-gab12cd3` parses perfectly and is still not a
	// release. Without the second half, a developer nine commits past a tag
	// would be offered an automatic update and would lose the change they were
	// testing to something that looks like a build-system bug.
	if err != nil || !cur.Release {
		res.Outcome = OutcomeNotARelease
	}

	f := c.Fetcher
	if f == nil {
		f = &Fetcher{}
	}
	m, err := f.FetchManifest(ctx, c.Keys)
	if err != nil {
		if errors.Is(err, ErrNoManifest) {
			res.Outcome = OutcomeNoManifest
			return res, nil
		}
		return nil, err
	}
	// A key this node has already watched being retired is refused from here on,
	// even though it is still in the compiled-in set. The set is what this build
	// shipped with; the revocation is what it has since learned.
	if c.isRevoked(m.SignedBy) {
		return nil, fmt.Errorf("%w: it is signed by %s, which this node recorded as retired",
			ErrBadSignature, m.SignedBy)
	}
	res.Manifest = m
	if m.Supersedes != "" {
		if cur, ok := c.Keys.KeyByRole(RoleCurrent); ok && m.Supersedes == cur.ID {
			res.Promotes = m.Supersedes
		}
	}

	if res.Outcome == OutcomeNotARelease {
		return res, nil
	}
	switch cmp := m.Parsed.Compare(cur); {
	case cmp == 0:
		res.Outcome = OutcomeUpToDate
		return res, nil
	case cmp < 0:
		res.Outcome = OutcomeOlder
		return res, nil
	}

	key, err := LocalPlatformKey(TierFor(c.RandomX))
	if err != nil {
		return nil, err
	}
	res.Platform = key
	product := c.Product
	if product == "" {
		product = ProductCLI
	}
	a, err := m.Asset(product, key)
	if err != nil {
		res.Outcome = OutcomeNoAsset
		return res, nil
	}
	res.Asset = a
	res.Outcome = OutcomeAvailable

	// Whether it COULD be installed is answered now rather than after the
	// operator has agreed to it and the download has finished.
	if t, lerr := Locate(); lerr == nil {
		res.Refusal = Guard(t, c.Current)
	}
	return res, nil
}

func (c *Checker) isRevoked(id string) bool {
	for _, r := range c.Revoked {
		if r == id {
			return true
		}
	}
	return false
}

// Install downloads the asset this result names, verifies it, unpacks it and
// replaces the binaries.
//
// Every step that can fail does so before anything is replaced: the digest is
// checked against the signed manifest, the archive is unpacked into a scratch
// directory, and the guards run again — the state of the disk can have changed
// since Check, and the second look costs one syscall.
func (r *Result) Install(ctx context.Context, f *Fetcher) (*Install, map[string]string, error) {
	if r.Outcome != OutcomeAvailable {
		return nil, nil, fmt.Errorf("update: there is nothing to install")
	}
	if r.Refusal != nil {
		return nil, nil, r.Refusal
	}
	t, err := Locate()
	if err != nil {
		return nil, nil, err
	}
	if f == nil {
		f = &Fetcher{}
	}

	// Scratch inside the target's own directory, so the later rename onto the
	// binary cannot cross a filesystem. The guards have already proved this
	// directory is writable.
	work, err := os.MkdirTemp(t.Dir, ".zycord-update-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(work)

	archive, err := f.FetchAsset(ctx, r.Manifest, r.Asset, work)
	if err != nil {
		return nil, nil, err
	}
	want := []string{BinaryStem(t.Name)}
	if other := otherBinary(BinaryStem(t.Name)); other != "" {
		want = append(want, other)
	}
	extracted, err := Extract(archive, r.Asset.File, work, want)
	if err != nil {
		// The sibling may genuinely not be in this archive; retry with only what
		// this process is running as, rather than refusing the whole update.
		if !errors.Is(err, ErrMemberMissing) {
			return nil, nil, err
		}
		extracted, err = Extract(archive, r.Asset.File, work, want[:1])
		if err != nil {
			return nil, nil, err
		}
	}
	in, err := PlanInstall(t, extracted, r.Manifest.Version, r.Current.Raw)
	if err != nil {
		return nil, nil, err
	}
	backups, err := in.Apply()
	if err != nil {
		return nil, nil, err
	}
	return in, backups, nil
}

func otherBinary(stem string) string {
	switch stem {
	case BinaryNode:
		return BinaryCLI
	case BinaryCLI:
		return BinaryNode
	}
	return ""
}

// DueForCheck reports whether enough time has passed since the last one.
//
// Bounds network cost across restarts, so a node restarted hourly does not check
// hourly. The interval is generous on purpose: this is a request to a third
// party, and a release happens every few weeks.
func DueForCheck(last time.Time, every time.Duration, now time.Time) bool {
	return last.IsZero() || now.Sub(last) >= every
}

// CheckInterval is how often a running node contacts the release host.
//
// Six hours means a security release reaches every running node within a quarter
// of a day, at four requests per node per day. Anything much shorter is a beacon;
// anything much longer stops being a channel for the thing SECURITY.md says is
// the project's only incident response.
const CheckInterval = 6 * time.Hour
