package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"zycord/wallet/webui"
)

// cmdUI serves the wallet's graphical interface on loopback.
//
// It is the same frontend the desktop application ships, and it exists as a
// command because the two deployments people actually have are a laptop and a
// server: on a laptop this opens a browser, and on a server it prints a URL
// that becomes reachable through `ssh -L 9430:127.0.0.1:9430 host`. One
// binary, both cases, and no port exposed to a network in either.
func cmdUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to an encrypted key file (required)")
	addr := fs.String("addr", webui.DefaultAddr, "loopback address to serve on; a non-loopback address is refused")
	noOpen := fs.Bool("no-open", false, "print the URL instead of opening a browser")
	locked := fs.Bool("locked", false, "start locked and ask for the passphrase in the browser instead of here")
	lockAfter := fs.Duration("lock-after", 15*time.Minute, "wipe the key after this much inactivity; 0 disables the idle lock")
	n := addNodeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("usage: zcd ui --key KEYFILE")
	}
	expected, err := n.resolve(fs)
	if err != nil {
		return err
	}

	api := webui.NewAPI(webui.Config{
		KeyPath:    *keyPath,
		Params:     expected,
		RPC:        *n.rpc,
		ConfirmRPC: *n.confirmRPC,
		LockAfter:  *lockAfter,
	})

	// Unlocking here rather than in the browser is the default because it
	// fails early: a wrong passphrase or a missing key file is an error
	// before a URL is printed, not after a browser has opened on a form that
	// cannot work. It also keeps the passphrase off the loopback socket
	// entirely for the common case.
	if !*locked {
		pass, err := readPassphrase("passphrase for "+*keyPath+": ", false)
		if err != nil {
			return err
		}
		_, err = api.Unlock(string(pass))
		zero(pass)
		if err != nil {
			return err
		}
	}

	srv, err := webui.NewServer(api, *addr)
	if err != nil {
		return err
	}
	url := srv.URL()

	fmt.Fprintf(os.Stderr, "zcd ui — %s (%s, chain id %d)\n", *keyPath, expected.Name, expected.ChainID)
	fmt.Fprintf(os.Stderr, "node     %s\n", *n.rpc)
	if *n.confirmRPC != "" {
		fmt.Fprintf(os.Stderr, "confirm  %s\n", *n.confirmRPC)
	}
	fmt.Fprintf(os.Stderr, "\n  %s\n\n", url)
	fmt.Fprint(os.Stderr,
		"The token in that URL is this session's whole authentication, it is new on every run,\n"+
			"and it is in the fragment — so it never reaches the server, a log, or a Referer header.\n"+
			"Treat the URL as the secret it is. The browser opened for you gets a single-use\n"+
			"handoff rather than this token, because a browser is launched by putting its argument\n"+
			"on a command line every local user can read.\n\n"+
			"On a server, leave the port where it is and forward it:\n"+
			"  ssh -L 9430:127.0.0.1:9430 <host>\n"+
			"then open the URL on your own machine. Ctrl-C here locks the key and stops serving.\n")

	// Ctrl-C must wipe the key, not just stop the listener. A process that
	// exits without doing so has left a seed in a core file's future.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()

	if !*noOpen {
		// Not `url`. The browser is launched by running another program with
		// the address on its command line, and a command line is readable by
		// every other user on the machine for as long as that program lives —
		// /proc/<pid>/cmdline on Linux, and the process table on macOS, where
		// an unprivileged account reads argv it does not own. What goes there
		// is a single-use handoff the page trades for the token, never the
		// token itself — see webui.Server.BrowserURL.
		openBrowser(srv.BrowserURL())
	}

	select {
	case err := <-done:
		return err
	case <-stop:
		fmt.Fprintln(os.Stderr, "\nlocking and shutting down")
		return srv.Close()
	}
}

// openBrowser asks the desktop to open a URL, and does not care whether it
// worked: the URL has already been printed, so a failure here costs a copy
// and paste rather than the session. Nothing is read back from the child and
// no shell is involved.
//
// The caller must pass a handoff URL rather than the session URL. Avoiding a
// shell stops the URL being re-split; it does not stop it being *read*, and
// the argument vector of this child is readable by other users of the machine
// on every platform in the switch below — /proc/<pid>/cmdline on Linux, the
// process table on macOS.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return
	}
	// Reap it. xdg-open in particular exits immediately once the browser is
	// handed the URL, and leaving it unreaped would keep a zombie for the
	// life of a process that is meant to run for hours.
	go func() { _ = cmd.Wait() }()
}
