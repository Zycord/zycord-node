//go:build unix

package update

import "syscall"

// Reexec replaces this process image with path, keeping argv and the environment.
//
// syscall.Exec, and the choice matters more than it looks. It never returns on
// success and it **preserves the PID**, which is what makes an update invisible
// to everything watching this process: systemd's MainPID stays valid, a
// `Restart=` unit does not observe a restart at all, the service is never
// "down", and no supervisor policy fires. A fork-and-exit would look like a
// crash to every one of those.
//
// argv is passed verbatim, argv[0] included, so `ps` output and any
// $0-dependent behaviour are unchanged.
//
// The caller is responsible for the only precondition that matters: nothing may
// be open. In zycordd this runs before the chain store is opened, so there is no
// store, no directory lock, no listener, no goroutine and no block in flight.
// That is the entire reason replacing this executable is safe at that point in
// main and nowhere else.
func Reexec(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}

// reexecReplacesTheProcess reports whether Reexec keeps the PID. Used by tests
// and by the messages, which should not claim a restart is invisible where it
// is not.
const reexecReplacesTheProcess = true
