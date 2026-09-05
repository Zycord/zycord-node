//go:build unix

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// guardOwnership is the VPS and systemd case, and it is the one that must never
// be argued with.
//
// A node deliberately runs as an unprivileged user with its binary in a
// root-owned directory. That is not a misconfiguration to work around — it is
// the configuration, and a process that could rewrite its own executable from
// there would be a privilege escalation wearing an update's clothes.
func guardOwnership(t Target, _ string) *Refusal {
	fi, err := os.Stat(t.Resolved)
	if err != nil {
		return nil // guardWritable will produce the better message
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid := os.Getuid()
	if uid == 0 || int(st.Uid) == uid {
		return nil
	}
	return &Refusal{
		Reason: fmt.Sprintf("%s is owned by uid %d and this process runs as uid %d. A node runs "+
			"unprivileged on purpose, so it cannot — and should not be able to — rewrite its own "+
			"executable.", t.Resolved, st.Uid, uid),
		Advice: "  Stop the service, install the new release with the privileges the original install\n" +
			"  used, and start it again. Fetch and read install.sh first; it is never piped into a\n" +
			"  shell, which is the posture docs/INSTALL.md argues for and this updater does not undercut.",
	}
}

// guardDpkg refuses a binary that belongs to an installed .deb.
//
// The ownership check below already stops the common case — a node runs as the
// unprivileged `zycord` account and the package's binary is root-owned, so it
// cannot be written. But an operator who runs the node as root has no such
// protection, and replacing a file dpkg owns leaves the package database
// describing bytes that are no longer there: the next `apt upgrade` overwrites
// the update, and `dpkg -V` reports a modified file forever.
//
// dpkg-query is asked rather than the path guessed at. /usr/bin is where this
// project's own package installs and also where install.sh does NOT — it uses
// /usr/local/bin — but "under /usr/bin" is a heuristic and the database is an
// answer. On a machine with no dpkg the query is simply absent and this returns
// nothing, which is correct: there is no package to conflict with.
func guardDpkg(t Target, _ string) *Refusal {
	q, err := exec.LookPath("dpkg-query")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, q, "-S", t.Resolved).Output()
	if err != nil {
		// A non-zero exit is dpkg-query saying no package owns this path, which
		// is the ordinary answer for a tarball or install.sh install.
		return nil
	}
	pkg := strings.TrimSpace(string(out))
	if i := strings.Index(pkg, ":"); i > 0 {
		pkg = pkg[:i]
	}
	if pkg == "" {
		return nil
	}
	return &Refusal{
		Reason: fmt.Sprintf("%s belongs to the installed package %q. Replacing it in place would leave "+
			"dpkg's database describing a file that is no longer there: the next upgrade would overwrite "+
			"the update, and `dpkg -V` would report a modified file from then on.", t.Resolved, pkg),
		Advice: "  sudo systemctl stop zycordd\n" +
			"  # install the new .deb from the release page, then\n" +
			"  sudo systemctl start zycordd",
	}
}
