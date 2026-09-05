package update_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"zycord/update"
)

func checkerFor(r *release, current string) *update.Checker {
	return &update.Checker{
		Fetcher: r.fetcher(), Keys: r.signer.set, Current: current,
		RandomX: false, Product: update.ProductCLI,
	}
}

// TestCheckDistinguishesEveryOutcomeItReports.
//
// Each of these is a different thing to say to an operator, and collapsing any
// two loses information somebody acts on: "there is an update" is not "the check
// broke", and neither is "the published release is older than yours".
func TestCheckDistinguishesEveryOutcomeItReports(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current string
		want    update.Outcome
	}{
		{"a newer release is available", "v0.1.0", update.OutcomeAvailable},
		{"the running version is the published one", "v0.2.0", update.OutcomeUpToDate},
		{"the published release is older", "v0.3.0", update.OutcomeOlder},
		{"this build is not from a tag", "v0.1.0-9-gab12cd3", update.OutcomeNotARelease},
		{"this build is not stamped at all", "dev", update.OutcomeNotARelease},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelease(t, goodManifest()) // publishes v0.2.0
			res, err := checkerFor(r, tc.current).Check(context.Background())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if res.Outcome != tc.want {
				t.Errorf("Outcome = %v, want %v", res.Outcome, tc.want)
			}
		})
	}
}

// TestARolledBackManifestIsReportedRatherThanObeyed.
//
// An attacker who cannot forge a signature can still replay an old, genuinely
// signed manifest. Refusing to go backwards is the whole mitigation, and
// REPORTING it rather than folding it into "up to date" is what makes the attack
// visible instead of merely ineffective.
func TestARolledBackManifestIsReportedRatherThanObeyed(t *testing.T) {
	r := newRelease(t, goodManifest()) // v0.2.0
	res, err := checkerFor(r, "v0.9.0").Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != update.OutcomeOlder {
		t.Fatalf("Outcome = %v, want OutcomeOlder", res.Outcome)
	}
	if res.Available() {
		t.Error("an older release was reported as available")
	}
}

// TestNoManifestIsAnOutcomeAndNotAnError. Every release cut before this feature
// existed looks like this, so it must not surface as something being wrong.
func TestNoManifestIsAnOutcomeAndNotAnError(t *testing.T) {
	r := newRelease(t, goodManifest())
	r.status = 404
	res, err := checkerFor(r, "v0.1.0").Check(context.Background())
	if err != nil {
		t.Fatalf("a release with no manifest produced an error: %v", err)
	}
	if res.Outcome != update.OutcomeNoManifest {
		t.Errorf("Outcome = %v, want OutcomeNoManifest", res.Outcome)
	}
}

// TestARandomXBinaryIsNeverOfferedThePlainArchive, through the whole check
// rather than through Manifest.Asset alone.
func TestARandomXBinaryIsNeverOfferedThePlainArchive(t *testing.T) {
	r := newRelease(t, goodManifest())
	c := checkerFor(r, "v0.1.0")
	c.RandomX = true
	res, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// On a platform the fixture publishes both tiers for, a mining binary gets
	// the mining archive and never the other one.
	if res.Outcome == update.OutcomeAvailable && !strings.Contains(res.Asset.File, "-randomx") {
		t.Errorf("a mining binary was offered %q", res.Asset.File)
	}
}

// TestAKeyThisNodeWatchedBeingRetiredIsRefusedAfterwards.
//
// The compiled-in set is what this build SHIPPED with. A revocation is what it
// has since learned, and it has to outrank the compiled-in set — otherwise a
// rotation would protect nothing after the fact, which is the only moment it
// matters.
func TestAKeyThisNodeWatchedBeingRetiredIsRefusedAfterwards(t *testing.T) {
	r := newRelease(t, goodManifest())
	c := checkerFor(r, "v0.1.0")
	c.Revoked = []string{"zu1"} // the key this fixture signs with

	_, err := c.Check(context.Background())
	if err == nil {
		t.Fatal("a manifest signed by a retired key was accepted")
	}
	if !errors.Is(err, update.ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Errorf("err = %v, want it to say the key was retired", err)
	}
}

// TestDueForCheckBoundsNetworkCostAcrossRestarts, so a node restarted hourly
// does not check hourly.
func TestDueForCheckBoundsNetworkCostAcrossRestarts(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if !update.DueForCheck(time.Time{}, update.CheckInterval, now) {
		t.Error("a node that has never checked is not due")
	}
	if update.DueForCheck(now.Add(-time.Hour), update.CheckInterval, now) {
		t.Error("a node that checked an hour ago is due again")
	}
	if !update.DueForCheck(now.Add(-7*time.Hour), update.CheckInterval, now) {
		t.Error("a node that checked seven hours ago is not due")
	}
	if update.CheckInterval < time.Hour {
		t.Errorf("CheckInterval is %v; anything much shorter is a beacon", update.CheckInterval)
	}
}
