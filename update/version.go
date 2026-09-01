package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a release version, parsed from what the build stamped into it.
//
// The input is not semver. It is whatever `git describe --tags --always
// --dirty` produced at build time (Makefile), which means this parser has to
// cope with six shapes rather than one:
//
//	v0.1.1                     a release, exactly
//	v0.1.1-9-gab12cd3          nine commits past a release
//	v0.1.1-9-gab12cd3-dirty    ...with uncommitted changes
//	v1.0.0-rc1-2-gdeadbee      a pre-release, two commits past it
//	ab12cd3                    --always, when no tag is reachable
//	dev                        the unstamped default
//
// The ambiguity worth naming: `git describe` joins the commit count with a
// hyphen, and semver joins a pre-release identifier with a hyphen too. So
// `v1.0.0-rc1-2-gdeadbee` has to be read as "rc1, two commits ahead" and not as
// a pre-release literally called "rc1-2-gdeadbee". The suffix is recognised by
// SHAPE — a run of digits, then `g` followed by hex — and only stripped when
// both fields match, which no real pre-release identifier does.
type Version struct {
	Major, Minor, Patch int

	// Pre is the pre-release identifier without its hyphen ("rc1"), empty for
	// an ordinary release.
	Pre string

	// Ahead is the number of commits past the tag, and Commit is the `g`-
	// prefixed abbreviated hash beside it. Both are zero for a release.
	Ahead  int
	Commit string

	// Dirty records the `-dirty` suffix: the tree had uncommitted changes.
	Dirty bool

	// Release is true only when this is exactly a tag: parsed cleanly, no
	// commits ahead, not dirty. It is the whole of what gates an automatic
	// update, so it is computed here rather than re-derived at each call site.
	Release bool

	// Raw is the string as stamped, kept so any message can quote what the
	// binary actually says about itself rather than a normalisation of it.
	Raw string
}

// ParseVersion reads a stamped version string.
//
// It returns an error for anything it cannot resolve to a version triple,
// including the two unstamped shapes (`dev`, and a bare commit hash from
// `--always`). Those are not failures of the build — they are what a build from
// a tree with no reachable tag looks like — but they are not versions either,
// and the caller's answer to both is the same: report, never replace.
func ParseVersion(s string) (Version, error) {
	v := Version{Raw: s}
	rest := strings.TrimSpace(s)
	if rest == "" {
		return v, fmt.Errorf("update: empty version string")
	}

	// -dirty comes off first, because it is always last and never carries
	// information about the rest of the shape.
	if strings.HasSuffix(rest, "-dirty") {
		v.Dirty = true
		rest = strings.TrimSuffix(rest, "-dirty")
	}

	// Then the describe suffix, recognised by shape rather than by counting
	// hyphens. Both fields must match or neither is removed: a tag genuinely
	// ending in something numeric must not lose it.
	if fields := strings.Split(rest, "-"); len(fields) >= 3 {
		count, commit := fields[len(fields)-2], fields[len(fields)-1]
		if n, err := strconv.Atoi(count); err == nil && n >= 0 && isDescribeCommit(commit) {
			v.Ahead = n
			v.Commit = commit
			rest = strings.Join(fields[:len(fields)-2], "-")
		}
	}

	rest = strings.TrimPrefix(rest, "v")

	// What is left is MAJOR.MINOR.PATCH[-PRE].
	if i := strings.Index(rest, "-"); i >= 0 {
		v.Pre = rest[i+1:]
		rest = rest[:i]
		if v.Pre == "" {
			return v, fmt.Errorf("update: %q has an empty pre-release identifier", s)
		}
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("update: %q is not a version this build can read; it names no MAJOR.MINOR.PATCH", s)
	}
	dst := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		// strconv.Atoi accepts a leading sign, which would make "1.-2.3" parse.
		if p == "" || strings.ContainsAny(p, "+-") {
			return v, fmt.Errorf("update: %q has a malformed version number", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return v, fmt.Errorf("update: %q is not a version this build can read: %w", s, err)
		}
		*dst[i] = n
	}

	v.Release = v.Ahead == 0 && !v.Dirty
	return v, nil
}

// isDescribeCommit reports whether s is the `g<hex>` field git describe appends.
func isDescribeCommit(s string) bool {
	if len(s) < 8 || s[0] != 'g' { // g + at least 7 hex, which is git's floor
		return false
	}
	for _, c := range s[1:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Compare orders two versions: -1 if v is older than w, +1 if newer, 0 if the
// same release.
//
// It compares the parsed triple and never the strings. String comparison gets
// v0.10.0 and v0.9.0 backwards, and that is not a hypothetical — it is the
// second minor bump of any project that reaches ten.
//
// Ahead, Commit and Dirty deliberately take no part. Two builds from the same
// tag are the same release for the purpose of "is there something newer
// published", and a build that is not exactly a tag is refused an automatic
// update by Release rather than by being ordered somewhere.
func (v Version) Compare(w Version) int {
	if c := cmpInt(v.Major, w.Major); c != 0 {
		return c
	}
	if c := cmpInt(v.Minor, w.Minor); c != 0 {
		return c
	}
	if c := cmpInt(v.Patch, w.Patch); c != 0 {
		return c
	}
	return comparePre(v.Pre, w.Pre)
}

// comparePre orders pre-release identifiers by the semver rule.
//
// A version WITH a pre-release sorts below the same triple without one: 1.0.0
// is the finished thing that 1.0.0-rc1 was leading up to. Getting this backwards
// would offer every user of a release an "update" to the release candidate it
// superseded.
func comparePre(a, b string) int {
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	af, bf := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(af) && i < len(bf); i++ {
		x, y := af[i], bf[i]
		if x == y {
			continue
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			return cmpInt(xn, yn)
		case xerr == nil:
			// Numeric identifiers have lower precedence than alphanumeric ones.
			return -1
		case yerr == nil:
			return 1
		default:
			return compareAlnumIdentifier(x, y)
		}
	}
	return cmpInt(len(af), len(bf))
}

// compareAlnumIdentifier orders two alphanumeric pre-release identifiers by
// splitting each into alternating runs of letters and digits and comparing them
// run by run.
//
// **Two rules, and the second is a deliberate deviation from semver.**
//
// Semver compares a single alphanumeric identifier by ASCII, so `rc10` sorts
// BELOW `rc2` — it wants `rc.10` and `rc.2` if you meant numbers. Nobody tags
// that way; everybody tags `-rc1`, `-rc2`, `-rc10`. And Compare is what the
// downgrade refusal is built on, so following the letter here would let a node
// running rc10 read rc2 as newer and install it: the exact rollback the refusal
// exists to stop, arriving through the ordering rather than past it.
//
// **The run-by-run shape is what makes it a TOTAL order, and that matters more
// than the deviation.** The first version of this function special-cased a
// trailing digit run and fell back to a byte comparison otherwise, which mixed
// two incompatible orderings over one domain and was intransitive:
//
//	rc9 < rc10 < rc10a < rc9
//
// All three parse as releases, so nothing upstream excluded them, and an
// install-if-newer loop over that set never terminates. Here each run is
// compared under one total order — digit runs by value, letter runs by bytes,
// a digit run below a letter run, following semver's own rule that numeric
// identifiers have the lower precedence — and a lexicographic extension of a
// total order is a total order. Transitivity is a property of the shape rather
// than of the cases anybody thought to test, which is the only way to hold it.
//
// TestCompareIsATotalOrder brute-forces it over the shapes that produced the
// cycle.
func compareAlnumIdentifier(a, b string) int {
	ar, br := splitRuns(a), splitRuns(b)
	for i := 0; i < len(ar) && i < len(br); i++ {
		if c := compareRun(ar[i], br[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(ar), len(br))
}

// splitRuns divides an identifier into maximal runs of digits and non-digits:
// "rc10a" becomes ["rc", "10", "a"].
func splitRuns(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		j := i
		digit := isDigit(s[i])
		for j < len(s) && isDigit(s[j]) == digit {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

// compareRun is the total order on runs that everything above rests on.
func compareRun(a, b string) int {
	an, bn := isDigit(a[0]), isDigit(b[0])
	switch {
	case an && bn:
		// By value, and by length first so an arbitrarily long run cannot
		// overflow: with no leading zeroes, more digits is a larger number.
		if c := cmpInt(len(trimZeroes(a)), len(trimZeroes(b))); c != 0 {
			return c
		}
		return strings.Compare(trimZeroes(a), trimZeroes(b))
	case an:
		return -1 // a numeric run has lower precedence than a letter run
	case bn:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// trimZeroes drops leading zeroes so "007" and "7" compare equal by length.
func trimZeroes(s string) string {
	i := 0
	for i < len(s)-1 && s[i] == '0' {
		i++
	}
	return s[i:]
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// String renders the version the way it was stamped.
func (v Version) String() string {
	if v.Raw != "" {
		return v.Raw
	}
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}
