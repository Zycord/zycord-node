//go:build unix

package update

import (
	"fmt"
	"os"
	"syscall"
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
