package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Refusal is a reason this install must not be replaced in place, and what to
// do instead.
//
// The Advice half is not decoration. Every refusal below is a case where the
// operator CAN update — through a package manager, or with the installer, or by
// moving a symlink — and an updater that says only "no" teaches them that
// updating is somebody else's problem.
type Refusal struct {
	Reason string
	Advice string
}

func (r *Refusal) Error() string {
	if r.Advice == "" {
		return r.Reason
	}
	return r.Reason + "\n\n" + r.Advice
}

// Guard reports why this executable must not be replaced in place, or nil.
//
// Ordered most specific first, first match wins, because a Homebrew install is
// also unwritable and the useful thing to say about it is `brew upgrade`, not
// "permission denied".
func Guard(t Target, current string) *Refusal {
	for _, check := range []func(Target, string) *Refusal{
		guardHomebrew,
		guardScoop,
		guardVersionedDirectory,
		guardAppImage,
		guardOwnership, // platform split
		guardWritable,  // last: a probe, and the least specific answer
	} {
		if r := check(t, current); r != nil {
			return r
		}
	}
	return nil
}

// hasPathElement reports whether p contains an exact path element, so that
// matching "Cellar" does not also match "MyCellarThing".
func hasPathElement(p, want string) bool {
	for _, e := range strings.Split(filepath.ToSlash(p), "/") {
		if strings.EqualFold(e, want) {
			return true
		}
	}
	return false
}

func guardHomebrew(t Target, _ string) *Refusal {
	brewed := hasPathElement(t.Resolved, "Cellar")
	// ".linuxbrew" is matched WITHOUT the home-directory prefix it usually
	// carries. sim/wiring/anonymity_test.go scans every tracked file for a home
	// path followed by an account name, and writing the full conventional
	// location here would turn `make ci` red. The element alone is exactly as
	// specific, and taking an exemption in that guard's skip list to write a
	// longer string would be the wrong trade.
	if hasPathElement(t.Resolved, ".linuxbrew") {
		brewed = true
	}
	if prefix := os.Getenv("HOMEBREW_PREFIX"); prefix != "" && underDir(t.Resolved, prefix) {
		brewed = true
	}
	if underDir(t.Resolved, "/opt/homebrew") {
		brewed = true
	}
	if !brewed {
		return nil
	}
	return &Refusal{
		Reason: fmt.Sprintf("%s was installed by Homebrew (%s). Replacing it in place would leave "+
			"brew's manifest describing a file that is no longer there, and the next `brew upgrade` "+
			"would overwrite the update anyway.", t.Name, t.Resolved),
		Advice: "  brew update && brew upgrade zycord",
	}
}

func guardScoop(t Target, _ string) *Refusal {
	scooped := hasPathElement(t.Resolved, "scoop") && hasPathElement(t.Resolved, "apps")
	if root := os.Getenv("SCOOP"); root != "" && underDir(t.Resolved, filepath.Join(root, "apps")) {
		scooped = true
	}
	if !scooped {
		return nil
	}
	// Scoop's shim spawns the real executable, so os.Executable reports the
	// versioned path under apps/ rather than the shim - which is where this
	// check needs to land.
	return &Refusal{
		Reason: fmt.Sprintf("%s was installed by Scoop (%s). Scoop keeps one directory per version and "+
			"rewrites its shims on upgrade, so replacing the file in place would leave the shim pointing "+
			"at a binary whose version no longer matches its directory.", t.Name, t.Resolved),
		Advice: "  scoop update zycord",
	}
}

// guardVersionedDirectory backstops the two above and catches the hand-rolled
// layout: /opt/zycord/v0.1.1/zycordd, with a `current` symlink beside it.
func guardVersionedDirectory(t Target, current string) *Refusal {
	if current == "" {
		return nil
	}
	bare := strings.TrimPrefix(current, "v")
	if bare == "" {
		return nil
	}
	dir := t.Dir
	for i := 0; i < 2 && dir != "" && dir != string(filepath.Separator); i++ {
		base := filepath.Base(dir)
		if base == current || base == bare {
			return &Refusal{
				Reason: fmt.Sprintf("%s lives in %s, a directory named for its own version. Replacing the "+
					"file would make that name a lie, and anything pointing at this directory by version "+
					"would now reach a different build.", t.Resolved, dir),
				Advice: "  Unpack the new archive beside it and move the symlink that selects a version.",
			}
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

func guardAppImage(t Target, _ string) *Refusal {
	if os.Getenv("APPIMAGE") == "" {
		return nil
	}
	return &Refusal{
		Reason: "this process is running from an AppImage, which is a read-only filesystem mounted for " +
			"the life of the process. There is nothing here that can be replaced.",
		Advice: "  Download the new AppImage and replace the file you launched.",
	}
}

// guardWritable is a PROBE, not a reading of mode bits.
//
// It performs the exact operation the replace needs — creating a file in the
// directory — which is the only check that gets read-only mounts, `chattr +i`,
// POSIX ACLs, SELinux and Windows' entire permission model right. None of those
// are visible in a mode bit, and on Windows there is no portable mode answer at
// all, so this is not a choice between two equivalent tests.
//
// It names the DIRECTORY, because the replace is a rename into it rather than a
// write to the file. And it proves in advance that the `.new` and `.old` entries
// the replace is about to need can actually be created.
func guardWritable(t Target, _ string) *Refusal {
	f, err := os.CreateTemp(t.Dir, ".zycord-update-probe-*")
	if err != nil {
		return &Refusal{
			Reason: fmt.Sprintf("%s is not writable by this process (%v), so %s cannot be replaced here.",
				t.Dir, err, t.Name),
			Advice: "  Re-install with the same privileges the original install used, or install into a\n" +
				"  directory you own and put that ahead of this one on PATH.",
		}
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

// underDir reports whether p is inside dir.
func underDir(p, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
