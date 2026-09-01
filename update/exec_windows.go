//go:build windows

package update

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

// Reexec starts path and waits for it, because Windows has no exec.
//
// There is no way to replace a process image on this platform, so the parent
// becomes a one-process supervisor: it starts the new binary attached to the
// same console, waits, and exits with the child's status. Stdio is inherited by
// handle, so `zycordd ... > node.log` keeps working across the update.
//
// **signal.Ignore(os.Interrupt) in the parent is load-bearing.** A console
// CTRL_C_EVENT is delivered to EVERY process attached to the console, so parent
// and child both receive it. Without the ignore the parent exits on the first
// ^C and the shell returns to a prompt while the child is still shutting down —
// and the operator's next command then runs against a node that still holds the
// data-directory lock, which is exactly the confusion that lock exists to
// prevent. The child does its own orderly shutdown and the parent reports its
// status.
//
// signal.Ignore is not signal.Notify: it registers no channel, so it does not
// create the second delivery queue that cmd/zycordd's wiring test refuses.
func Reexec(path string, argv, env []string) error {
	signal.Ignore(os.Interrupt)

	cmd := exec.Command(path, argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// No SysProcAttr: the child stays in this console and this process group,
	// which is what makes the inherited handles and the signal behaviour above
	// work at all.
	if err := cmd.Start(); err != nil {
		return err
	}
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

// reexecReplacesTheProcess is false here: the PID changes, and a message that
// said otherwise would be wrong on this platform.
const reexecReplacesTheProcess = false
