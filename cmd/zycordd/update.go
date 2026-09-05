package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/term"

	"zycord/core/pow/randomx"
	"zycord/update"
)

// The update pre-flight and the notice a running node prints.
//
// Two rules shape everything here, and they are not the same rule.
//
// **The pre-flight owns the binary; the running node never touches it.** All of
// the checking, prompting, downloading and replacing happens BEFORE the chain
// store is opened — no store, no directory lock, no listener, no goroutine, no
// block in flight. That is the only point in this process's life where replacing
// its own executable is safe, and it is why the call sits where it does in main.
// A replace from the notice goroutine would race the store's lock, the miner's
// in-flight block and every p2p handler.
//
// **A non-interactive node is never asked anything and never blocked.** systemd,
// Docker, cron and a future pool operator all look identical from in here: no
// terminal. They get one line saying checks are off and how to turn them on, and
// the node starts. That is what makes those cases safe by construction rather
// than by an operator remembering to pass a flag.

// preflightBudget bounds the whole pre-flight. A release host that hangs must
// not stop a node from starting.
const preflightBudget = 30 * time.Second

// updateState is what the pre-flight hands to the running node.
type updateState struct {
	mode    update.Mode
	dir     string
	checker *update.Checker
	// offered is the version the pre-flight already reported, so the in-run
	// notice does not repeat it the moment the node starts.
	offered string
}

// preflightUpdate resolves the update policy, and may not return: on an applied
// update it re-execs this process into the new binary.
func preflightUpdate(dir, modeFlag string, suppress bool) *updateState {
	prefs, note := update.LoadPrefs(dir)
	if note != "" {
		log.Print(note)
	}

	// An explicit flag is a decision, and it is persisted: an operator who
	// passes --update notify once should not have to keep passing it.
	if modeFlag != "" {
		m, err := parseModeOrExit(modeFlag)
		if err != nil {
			fatal(err)
		}
		if m != prefs.Mode || !prefs.Asked {
			prefs.Mode, prefs.Asked = m, true
			savePrefsOrLog(dir, prefs)
		}
	} else if env := os.Getenv("ZYCORD_UPDATE"); env != "" {
		m, err := update.ParseMode(env)
		if err != nil {
			fatal(err)
		}
		prefs.Mode = m
	}

	// The loop guard. Set means this process is the result of an update that
	// already happened this boot.
	if into := update.RestartedInto(); into != "" {
		if into == version {
			log.Printf("update: now running %s", version)
		} else {
			// The exec landed on a binary that is not the one just installed —
			// the replace did not take, or something rolled it back. Do NOT try
			// again: a retry loop here is a node that never starts.
			log.Printf("update: an update to %s was applied but this process reports %s; not retrying",
				into, version)
		}
		return &updateState{mode: update.ModeNever, dir: dir}
	}

	if !prefs.Asked && prefs.Mode == update.ModeUnset {
		if interactive() && !suppress {
			prefs.Mode = askAboutUpdates(os.Stdin, os.Stderr)
			prefs.Asked = true
			// Persisted BEFORE anything is contacted, so an answer is not lost
			// to a failed check.
			savePrefsOrLog(dir, prefs)
		} else {
			// Never prompt, never block. One line, alongside the other
			// configuration this node announces at start.
			log.Printf("update checks are off: no choice is recorded in %s and this is not an "+
				"interactive terminal. Turn them on with `zycordd --update notify --dir %s`, "+
				"or set ZYCORD_UPDATE=notify.", update.PrefsPath(dir), dir)
			return &updateState{mode: update.ModeNever, dir: dir}
		}
	}

	st := &updateState{mode: prefs.Mode, dir: dir}
	if suppress || !prefs.Mode.Checks() {
		return st
	}

	ks, err := update.Keys()
	if err != nil {
		log.Printf("update: %v", err)
		return st
	}
	st.checker = &update.Checker{
		Keys: ks, Current: version, RandomX: randomx.Available(),
		Product: update.ProductCLI, Revoked: prefs.RevokedKeys,
	}

	ctx, cancel := context.WithTimeout(context.Background(), preflightBudget)
	defer cancel()
	res, err := st.checker.Check(ctx)
	if err != nil {
		// Never fatal. A node that will not start because a release host is
		// unreachable is a worse outcome than an out-of-date node.
		log.Printf("update: check failed: %v", err)
		return st
	}
	prefs.LastCheck = time.Now().UTC()
	if res.Promotes != "" {
		prefs = prefs.Revoke(res.Promotes)
		log.Printf("update: key %s is retired by %s; this node will not accept it again",
			res.Promotes, res.Manifest.Version)
	}
	savePrefsOrLog(dir, prefs)

	switch res.Outcome {
	case update.OutcomeNoManifest, update.OutcomeUpToDate:
		return st
	case update.OutcomeOlder:
		log.Printf("update: the published release is %s, which is OLDER than this node (%s). "+
			"Nothing was changed.", res.Manifest.Version, version)
		return st
	case update.OutcomeNotARelease:
		if res.Manifest != nil {
			log.Printf("update: %s is published; this build is not from a release tag, so it is "+
				"never replaced automatically", res.Manifest.Version)
		}
		return st
	case update.OutcomeNoAsset:
		log.Printf("update: %s publishes no %s archive, and taking another would cross the two "+
			"release tiers (docs/INSTALL.md). Nothing was changed.", res.Manifest.Version, res.Platform)
		return st
	}

	st.offered = res.Manifest.Version
	announce(res)
	if st.mode != update.ModeAuto {
		log.Printf("update: run `zcd update` to install it, or start this node with --update auto")
		return st
	}
	if res.Refusal != nil {
		log.Printf("update: this install cannot be replaced in place.\n%s", res.Refusal.Error())
		return st
	}

	log.Printf("update: installing %s before opening the data directory", res.Manifest.Version)
	in, _, err := res.Install(ctx, nil, acceptsOurCommandLine)
	if err != nil {
		log.Printf("update: %v", err)
		log.Printf("update: nothing was changed; starting %s", version)
		return st
	}
	log.Printf("update: restarting into %s", res.Manifest.Version)
	// Nothing is open here. No store, no lock, no listener, no goroutine, no
	// block in flight — see this file's header. On Unix this does not return and
	// the PID is preserved, so a supervisor sees no restart at all.
	if err := in.RestartInto(); err != nil {
		log.Printf("update: could not restart into the new binary: %v", err)
		log.Printf("update: %s is installed and will run on the next start", res.Manifest.Version)
	}
	return st
}

func announce(res *update.Result) {
	if res.Manifest.Urgency == update.UrgencySecurity {
		log.Printf("update: SECURITY RELEASE %s is available (this node is %s)",
			res.Manifest.Version, version)
	} else {
		log.Printf("update: %s is available (this node is %s, published %s)",
			res.Manifest.Version, version, res.Manifest.PublishedAt.Format("2006-01-02"))
	}
	if res.Manifest.Note != "" {
		log.Printf("update: %q", res.Manifest.Note)
	}
}

// interactive reports whether there is a person on the other end.
//
// BOTH streams, not just stdin. A systemd unit has stdin on /dev/null and stdout
// on the journal; `docker run` without -t has neither; `-it` has both. Requiring
// both is what makes `zycordd < /dev/null | tee log` correctly non-interactive.
func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// askAboutUpdates puts the question once.
//
// Short on purpose. The person reading this is trying to start a miner, and the
// trust model belongs in docs/UPDATES.md and behind `zcd update --print-source`,
// which exists for exactly this question. A wall of security prose in front of
// somebody who wants to mine is the opposite of the goal.
func askAboutUpdates(in io.Reader, out io.Writer) update.Mode {
	fmt.Fprintf(out, `
zycordd %s — check for updates? Releases are signed, and nothing is downloaded
or replaced until you say so. Details: `+"`zcd update --print-source`"+`.

  [a] automatic   install a newer release on start, before the node opens its
                  data directory
  [n] notify      say when one is available, change nothing
  [x] never       do not contact the release host

`, version)

	r := bufio.NewReader(in)
	for i := 0; i < 3; i++ {
		fmt.Fprint(out, "Choose [a/n/x] (default n): ")
		line, err := r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "a", "auto", "automatic":
			return update.ModeAuto
		case "n", "notify", "":
			// Enter takes notify. NOT auto: a program that rewrites its own
			// executable because somebody pressed Enter has taken consent it was
			// not given. NOT never: the default has to keep a miner reachable by
			// a security release, and a notice does that while touching nothing.
			return update.ModeNotify
		case "x", "never", "no":
			return update.ModeNever
		}
		if err != nil {
			// EOF on an interactive stdin is a dropped session, not a refusal,
			// and looping on a closed reader is a node that never starts.
			break
		}
	}
	fmt.Fprintln(out, "Taking the default: notify.")
	return update.ModeNotify
}

// updateNotice is the running node's half, and it never touches the binary.
//
// The pre-flight owns the binary because it is the only point where nothing is
// open. A replace from here would race the chain store's lock, the miner's
// in-flight block and every p2p handler.
func updateNotice(st *updateState, stop <-chan struct{}) {
	if st == nil || st.checker == nil || !st.mode.Checks() {
		return
	}
	// A random first offset, from crypto/rand rather than the --seed flag: that
	// flag defaults to 1, so every node in the world would pick the same offset
	// and ten thousand nodes restarted by a distribution update would all check
	// in the same second.
	wait := update.CheckInterval + jitter(30*time.Minute)
	offered := st.offered

	// Time is accumulated from the intervals actually slept rather than read off
	// a clock, following mineLoop's precedent in this package: the durations are
	// already known exactly, and a wall-time read to rate-limit a log line would
	// spend a claim the node makes for nothing.
	var sinceNotice time.Duration
	const repeat = 24 * time.Hour
	warned := false

	for {
		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
		sinceNotice += wait
		wait = update.CheckInterval

		ctx, cancel := context.WithTimeout(context.Background(), preflightBudget)
		res, err := st.checker.Check(ctx)
		cancel()
		if err != nil {
			// Transient failures print once and then stop. A node that logs a
			// warning every six hours because its operator is behind a firewall
			// is a node whose logs get ignored. A SIGNATURE failure is different
			// and says so, because it is either a compromise or a broken release.
			if !warned {
				log.Printf("update: check failed: %v", err)
				warned = true
			}
			continue
		}
		warned = false
		if !res.Available() {
			continue
		}
		security := res.Manifest.Urgency == update.UrgencySecurity
		fresh := res.Manifest.Version != offered
		// A security release prints on every check. It is the one case where
		// being noisy is correct.
		if !security && !fresh && sinceNotice < repeat {
			continue
		}
		announce(res)
		log.Printf("update: this node will not change itself while it is running. " +
			"Stop it and start it again to install, or run `zcd update`.")
		offered, sinceNotice = res.Manifest.Version, 0
	}
}

// jitter returns a uniform duration in [0, max).
func jitter(max time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return time.Duration(n.Int64())
}

func parseModeOrExit(s string) (update.Mode, error) { return update.ParseMode(s) }

func savePrefsOrLog(dir string, p update.Prefs) {
	// A failed write is logged and the choice applies for this run only. A node
	// must never refuse to start over a preference file.
	if err := update.SavePrefs(dir, p); err != nil {
		log.Printf("update: could not record the update policy in %s: %v", update.PrefsPath(dir), err)
	}
}

// acceptsOurCommandLine proves the replacement can be started the way this
// process was, while the old binary is still in place.
//
// It runs the new executable with THIS process's exact arguments plus
// --version. zycordd parses its whole flag set before the --version check, so
// an unknown or removed flag fails there — and --version returns before the data
// directory is touched, so the probe opens nothing and takes no lock.
//
// Without it, a release that renames a flag turns `--update auto` into a node
// that installs the update, re-execs, dies at flag parsing, and cannot be fixed
// by restarting because the new binary is already in place. An end-to-end run
// produced exactly that, which is why this is here rather than in a comment
// about being careful with flags.
func acceptsOurCommandLine(newExe string) error {
	args := append(append([]string{}, os.Args[1:]...), "--version")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, newExe, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", newExe, strings.Join(args, " "), err,
			strings.TrimSpace(firstLine(string(out))))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
