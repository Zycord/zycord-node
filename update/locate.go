package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Target is the executable this process is running from, and where a
// replacement would have to land.
type Target struct {
	// Path is what os.Executable reported.
	Path string
	// Resolved is Path with symlinks followed. This is the file that gets
	// replaced.
	Resolved string
	// ViaSymlink records that the two differ, so output can say so.
	ViaSymlink bool
	// Dir and Name are of Resolved.
	Dir, Name string
}

// deletedSuffix is what /proc/self/exe reports for an unlinked binary.
const deletedSuffix = " (deleted)"

// Locate finds the running executable.
//
// **A symlink is followed and then left alone.** The resolved file is replaced;
// the link is not touched. Overwriting the link would turn a managed symlink
// into a regular file and break whatever manages it — Homebrew's
// `bin/zcd -> ../Cellar/...`, or a `current -> v0.1.1` release layout an
// operator maintains by hand. The guards then run against the resolved path,
// which is where the cases in which replacing the target is ALSO wrong get
// caught.
func Locate() (Target, error) {
	exe, err := os.Executable()
	if err != nil {
		return Target{}, fmt.Errorf("update: this process cannot find its own executable: %w", err)
	}
	// On Linux os.Executable reads /proc/self/exe, which for an unlinked binary
	// reports the old path with this suffix. Replacing "the file at that path"
	// would create a NEW file unrelated to what is running.
	if strings.HasSuffix(exe, deletedSuffix) {
		return Target{}, fmt.Errorf("update: this process's executable has been replaced or removed since it " +
			"started; restart it before updating")
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return Target{}, fmt.Errorf("update: %s cannot be resolved: %w", exe, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return Target{}, err
	}
	return Target{
		Path:       exe,
		Resolved:   abs,
		ViaSymlink: abs != exe,
		Dir:        filepath.Dir(abs),
		Name:       filepath.Base(abs),
	}, nil
}

// Sibling is the path the other CLI binary would occupy: same directory, exact
// name.
//
// Never a PATH search. Hunting for a second binary to overwrite is how an
// updater overwrites something it was never installed as; same directory plus
// exact name is one install by every convention this project ships — install.sh
// puts both there, the archive holds both, and Scoop's manifest lists both.
func (t Target) Sibling(name string) string {
	return filepath.Join(t.Dir, name+exeSuffix(t.Name))
}

// exeSuffix returns ".exe" when name carries it, matching case, and "" otherwise.
//
// **Not filepath.Ext.** Ext returns everything after the LAST dot, so for a
// binary installed as `zycordd-0.1.1` it answers ".1" — which turned the stem
// into "zycordd-0.1" and made the sibling "zcd.1". The only extension this
// package has any business knowing about is the one Windows requires, so that is
// the only one it looks for.
func exeSuffix(name string) string {
	if len(name) >= 4 && strings.EqualFold(name[len(name)-4:], ".exe") {
		return name[len(name)-4:]
	}
	return ""
}

// BinaryStem is a binary's name without the Windows extension.
func BinaryStem(name string) string {
	return strings.TrimSuffix(name, exeSuffix(name))
}

// String describes the target, saying when a link is being left alone.
func (t Target) String() string {
	if t.ViaSymlink {
		return fmt.Sprintf("%s (reached through %s, which is left alone)", t.Resolved, t.Path)
	}
	return t.Resolved
}
