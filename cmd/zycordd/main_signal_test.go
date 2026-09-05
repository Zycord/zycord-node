//go:build !windows

// The signal-delivery tests that can only run where the signals exist.
//
// `syscall.SIGWINCH` and `syscall.Kill` are not declared in `syscall` on
// Windows, so a file using them does not COMPILE there — and because a Go test
// binary is one package, that took the whole of `cmd/zycordd`'s test suite
// down on that platform, including every test that has nothing to do with
// signals. The build tag is on the file that needs it rather than a `t.Skip`
// inside the test, because a skip is a runtime decision and this is a
// compile-time one.
//
// What stays here is only what genuinely cannot be expressed portably: sending
// a real signal to this process. `TestOneSignalStopsEveryLoop` in main_test.go
// drives `stopOnSignal` by writing to its channel directly, which is portable,
// so the broadcast property — one signal wakes every waiter, not whichever one
// happened to be ready — keeps its coverage everywhere.

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestASecondSignalIsHandedBackToTheOperatingSystem.
//
// `stopOnSignal` takes ONE value off the signal channel and never reads it
// again, but `signal.Notify` stays registered for the life of the process. So
// without `signal.Stop`, every later signal is delivered into a buffer nobody
// drains and does nothing — the operator presses ^C a second time and the node
// does not die.
//
// That matters here specifically. A stop that lands during a key change waits
// for the ~2 GiB dataset fill to finish before the process exits, measured at
// up to 4.5 s on the RandomX bring-up machine, and a pause is exactly when
// somebody presses ^C again.
//
// SIGWINCH is the signal under test because its default action is to be
// IGNORED. The property is "the second one is no longer intercepted", and the
// only way to assert that is to send one and watch it not arrive — which with
// SIGTERM or SIGUSR1 would end the test binary rather than the test.
func TestASecondSignalIsHandedBackToTheOperatingSystem(t *testing.T) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	defer signal.Stop(sig)

	stop := stopOnSignal(sig)

	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("could not signal this process: %v", err)
	}
	select {
	case <-stop:
	case <-time.After(10 * time.Second):
		t.Fatal("the first signal did not reach stopOnSignal at all")
	}

	// The second one. It must reach the operating system's default action —
	// ignore, for this signal — rather than this channel.
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("could not signal this process: %v", err)
	}
	select {
	case <-sig:
		t.Fatal("a second signal was still intercepted: signal.Notify is registered " +
			"for the life of the process and nothing reads this channel after the " +
			"first value, so an operator pressing ^C again during a shutdown that " +
			"is waiting on a dataset fill would have no way to give up")
	case <-time.After(2 * time.Second):
	}
}
