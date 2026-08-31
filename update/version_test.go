package update_test

import (
	"testing"

	"zycord/update"
)

// TestParseVersionReadsWhatTheBuildActuallyStamps walks the shapes `git
// describe` produces, because the parser's whole job is that it is not fed
// semver.
func TestParseVersionReadsWhatTheBuildActuallyStamps(t *testing.T) {
	for _, tc := range []struct {
		in                  string
		major, minor, patch int
		pre                 string
		ahead               int
		commit              string
		dirty, release      bool
	}{
		{in: "v0.1.1", major: 0, minor: 1, patch: 1, release: true},
		{in: "0.1.1", major: 0, minor: 1, patch: 1, release: true},
		{in: "v1.2.3", major: 1, minor: 2, patch: 3, release: true},
		{in: "v0.1.1-9-gc861966", major: 0, minor: 1, patch: 1, ahead: 9, commit: "gc861966"},
		{in: "v0.1.1-9-gc861966-dirty", major: 0, minor: 1, patch: 1, ahead: 9, commit: "gc861966", dirty: true},
		{in: "v0.1.1-dirty", major: 0, minor: 1, patch: 1, dirty: true},
		{in: "v1.0.0-rc1", major: 1, minor: 0, patch: 0, pre: "rc1", release: true},
		// The shape the parser exists for: `rc1` is the pre-release and
		// `-2-gdeadbee` is the describe suffix, not one long identifier.
		{in: "v1.0.0-rc1-2-gdeadbee", major: 1, minor: 0, patch: 0, pre: "rc1", ahead: 2, commit: "gdeadbee"},
		{in: "v1.0.0-rc1-2-gdeadbee-dirty", major: 1, minor: 0, patch: 0, pre: "rc1", ahead: 2, commit: "gdeadbee", dirty: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			v, err := update.ParseVersion(tc.in)
			if err != nil {
				t.Fatalf("ParseVersion(%q) = %v", tc.in, err)
			}
			if v.Major != tc.major || v.Minor != tc.minor || v.Patch != tc.patch {
				t.Errorf("triple = %d.%d.%d, want %d.%d.%d", v.Major, v.Minor, v.Patch, tc.major, tc.minor, tc.patch)
			}
			if v.Pre != tc.pre {
				t.Errorf("Pre = %q, want %q", v.Pre, tc.pre)
			}
			if v.Ahead != tc.ahead || v.Commit != tc.commit {
				t.Errorf("ahead = %d %q, want %d %q", v.Ahead, v.Commit, tc.ahead, tc.commit)
			}
			if v.Dirty != tc.dirty {
				t.Errorf("Dirty = %v, want %v", v.Dirty, tc.dirty)
			}
			if v.Release != tc.release {
				t.Errorf("Release = %v, want %v", v.Release, tc.release)
			}
			if v.Raw != tc.in {
				t.Errorf("Raw = %q, want the string as stamped %q", v.Raw, tc.in)
			}
		})
	}
}

// TestAnUnstampedBuildIsNotAVersion covers the two shapes a build with no
// reachable tag produces.
//
// Neither is a failure of the build, and neither is a version. The caller's
// answer to both is the same and it is the safe one: report what is published,
// never replace the binary.
func TestAnUnstampedBuildIsNotAVersion(t *testing.T) {
	for _, in := range []string{
		"dev",      // the Makefile fallback and the `var version` default
		"c861966",  // git describe --always, no tag reachable
		"",         //
		"   ",      //
		"v1.2",     // not a triple
		"v1.2.3.4", // not a triple either
		"v1.-2.3",  // Atoi accepts a sign; the parser must not
		"v1.2.x",   //
		"v1.0.0-",  // empty pre-release identifier
		"vhello",   //
	} {
		t.Run(in, func(t *testing.T) {
			if v, err := update.ParseVersion(in); err == nil {
				t.Errorf("ParseVersion(%q) returned %+v, want an error", in, v)
			}
		})
	}
}

// TestATagThatLooksLikeADescribeSuffixSurvives guards the one way the shape
// heuristic could eat something real.
//
// The suffix is only stripped when BOTH trailing fields match — a run of digits
// and then `g` plus hex. A pre-release identifier that happens to look like
// half of it must come through whole.
func TestATagThatLooksLikeADescribeSuffixSurvives(t *testing.T) {
	for _, tc := range []struct{ in, pre string }{
		{"v1.0.0-beta-2", "beta-2"},           // digits last, but no g-hash
		{"v1.0.0-2", "2"},                     // only one trailing field
		{"v1.0.0-rc-gabcdefg", "rc-gabcdefg"}, // g-field is not hex
		{"v1.0.0-x-gabcdef1", "x-gabcdef1"},   // count field is not a number
	} {
		t.Run(tc.in, func(t *testing.T) {
			v, err := update.ParseVersion(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if v.Pre != tc.pre {
				t.Errorf("Pre = %q, want %q — the describe heuristic ate part of a real tag", v.Pre, tc.pre)
			}
			if v.Ahead != 0 {
				t.Errorf("Ahead = %d, want 0", v.Ahead)
			}
		})
	}
}

// TestCompareOrdersByTheTripleAndNotTheString is the test that stops a
// downgrade being read as an upgrade.
//
// The v0.10.0 case is the one that matters: it is not hypothetical, it is the
// second minor bump of any project that reaches ten, and string comparison gets
// it backwards.
func TestCompareOrdersByTheTripleAndNotTheString(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"v0.1.1", "v0.1.1", 0},
		{"v0.1.1", "v0.1.2", -1},
		{"v0.1.2", "v0.1.1", 1},
		{"v0.9.0", "v0.10.0", -1},    // string comparison says the opposite
		{"v0.10.0", "v0.9.0", 1},     //
		{"v1.0.0", "v2.0.0", -1},     //
		{"v0.2.0", "v0.1.99", 1},     //
		{"v1.0.0-rc1", "v1.0.0", -1}, // a pre-release precedes its release
		{"v1.0.0", "v1.0.0-rc1", 1},  //
		{"v1.0.0-rc1", "v1.0.0-rc2", -1},
		{"v1.0.0-rc2", "v1.0.0-rc10", -1}, // numeric identifiers compare numerically
		{"v1.0.0-alpha", "v1.0.0-beta", -1},
		{"v1.0.0-1", "v1.0.0-alpha", -1}, // numeric has lower precedence
		// Commits ahead and dirtiness are not ordering information: two builds
		// from one tag are the same release for "is something newer published".
		{"v0.1.1", "v0.1.1-9-gc861966", 0},
		{"v0.1.1-dirty", "v0.1.1", 0},
	} {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			a, err := update.ParseVersion(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := update.ParseVersion(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := a.Compare(b); got != tc.want {
				t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := b.Compare(a); got != -tc.want {
				t.Errorf("Compare(%s, %s) = %d, want %d — comparison is not symmetric", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

// TestOnlyAnExactTagIsARelease pins the gate on automatic replacement.
//
// A developer who ran `make build` on a branch must not have that binary
// swapped for a release: they would lose the change they are testing, and the
// replacement would look like a build-system bug rather than an update.
func TestOnlyAnExactTagIsARelease(t *testing.T) {
	for _, tc := range []struct {
		in      string
		release bool
	}{
		{"v0.1.1", true},
		{"v1.0.0-rc1", true}, // a pre-release tag is still exactly a tag
		{"v0.1.1-9-gc861966", false},
		{"v0.1.1-dirty", false},
		{"v0.1.1-9-gc861966-dirty", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			v, err := update.ParseVersion(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if v.Release != tc.release {
				t.Errorf("Release = %v, want %v", v.Release, tc.release)
			}
		})
	}
}
