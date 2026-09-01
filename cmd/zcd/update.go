package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"zycord/core/pow/randomx"
	"zycord/update"
)

// Exit codes, and they are the interface.
//
// A monitoring job has to tell "there is an update" from "this box cannot
// self-update" from "the check broke" from "all good", and one non-zero code
// collapses all four. They sit above the shell's ordinary range and below 64, so
// the documentation can describe them as a block, and 1 keeps its usual meaning
// so `set -e` still trips on a real failure.
//
// The dispatch in main.go uses os.Exit(cmdUpdate(...)) rather than returning an
// error for exactly this reason - the `err != nil -> os.Exit(1)` tail there
// collapses every outcome to 1. cmd/zycordd/main.go's `os.Exit(runRepair(...))`
// is the same choice for the same reason.
const (
	exitUpToDate    = 0
	exitAvailable   = 10 // available, not installed
	exitCannotPatch = 11 // available, but a guard refuses this install
	exitNoManifest  = 12 // this release publishes none - not an error
	exitFailed      = 1
	exitUsage       = 2
)

// cmdUpdate is `zcd update`.
func cmdUpdate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Maintainer subcommands, before the flag set, because they take their own.
	if len(args) > 0 {
		switch args[0] {
		case "manifest":
			return cmdUpdateManifest(args[1:], stdout, stderr)
		case "verify":
			return cmdUpdateVerify(args[1:], stdout, stderr)
		}
	}

	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "report what is available and change nothing")
	yes := fs.Bool("yes", false, "install without asking")
	dir := fs.String("dir", "", "a node data directory, to read and write its update policy")
	repo := fs.String("repo", "", "release host, overriding "+"ZYCORD_REPO_URL")
	printSource := fs.Bool("print-source", false, "print where this binary would look and which keys it trusts, and contact nothing")
	rollback := fs.Bool("rollback", false, "restore the binary kept from the previous update")
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: zcd update [--check] [--yes] [--dir DIR]

  --check          report and change nothing (implied when stdout is not a terminal)
  --yes            install without asking
  --dir DIR        a node data directory, whose update policy is read and written
  --repo URL       release host, for a fork or a mirror
  --print-source   print the release host and trusted keys; contact nothing
  --rollback       restore the binary kept from the previous update

  zcd update manifest --dir DIR --version vX.Y.Z [--sign]
  zcd update verify   --dir DIR
                   maintainer commands; see docs/RELEASE.md

Exit codes: 0 up to date or installed, 10 available, 11 available but this
install cannot be replaced in place, 12 no manifest published, 1 failed.
`)
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if *printSource {
		return updatePrintSource(*repo, stdout)
	}
	if *rollback {
		return updateRollback(stdout, stderr)
	}
	return runUpdate(args, *check, *yes, *dir, *repo, stdin, stdout, stderr)
}

// runUpdate is the check, and the install when one is asked for.
func runUpdate(_ []string, check, yes bool, dir, repo string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Not a terminal means not a conversation. A scripted or cron invocation
	// gets a report, never an install it did not ask for in words.
	if !term.IsTerminal(int(os.Stdout.Fd())) && !yes {
		check = true
	}

	var prefs update.Prefs
	if dir != "" {
		var note string
		prefs, note = update.LoadPrefs(dir)
		if note != "" {
			fmt.Fprintln(stderr, note)
		}
		if prefs.Mode == update.ModeNever {
			fmt.Fprintf(stdout, "update checks are off for %s (mode: never)\n", dir)
			return exitUpToDate
		}
	}

	f := &update.Fetcher{Base: repo}
	ks, err := update.Keys()
	if err != nil {
		fmt.Fprintln(stderr, "zcd update:", err)
		return exitFailed
	}
	c := &update.Checker{
		Fetcher: f, Keys: ks, Current: version,
		RandomX: randomx.Available(), Product: update.ProductCLI,
		Revoked: prefs.RevokedKeys,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := c.Check(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "zcd update:", err)
		return exitFailed
	}

	if dir != "" {
		prefs.LastCheck = time.Now().UTC()
		if res.Promotes != "" {
			prefs = prefs.Revoke(res.Promotes)
		}
		if err := update.SavePrefs(dir, prefs); err != nil {
			fmt.Fprintln(stderr, "zcd update: could not record the check:", err)
		}
	}

	switch res.Outcome {
	case update.OutcomeNoManifest:
		fmt.Fprintln(stdout, "no update manifest is published for this release yet; nothing to do")
		return exitNoManifest
	case update.OutcomeUpToDate:
		fmt.Fprintf(stdout, "zcd %s - up to date\n", version)
		printSourceLine(stdout, res)
		return exitUpToDate
	case update.OutcomeOlder:
		fmt.Fprintf(stdout, "zcd %s - the published release is %s, which is OLDER than this binary.\n",
			version, res.Manifest.Version)
		fmt.Fprintln(stdout, "Nothing was changed. This is either a replayed manifest or a botched release,")
		fmt.Fprintln(stdout, "and it is reported rather than ignored because both are worth knowing about.")
		return exitAvailable
	case update.OutcomeNotARelease:
		fmt.Fprintf(stdout, "zcd %s is not built from a release tag, so it is never replaced automatically.\n", version)
		if res.Manifest != nil {
			fmt.Fprintf(stdout, "The published release is %s.\n", res.Manifest.Version)
		}
		return exitAvailable
	case update.OutcomeNoAsset:
		fmt.Fprintf(stderr, "zcd update: %s publishes no %s archive.\n", res.Manifest.Version, res.Platform)
		fmt.Fprintln(stderr, "Taking a different one would cross the two release tiers; see docs/INSTALL.md.")
		return exitCannotPatch
	}

	// Available.
	fmt.Fprintf(stdout, "zcd %s - %s is available\n", version, res.Manifest.Version)
	fmt.Fprintf(stdout, "  published   %s\n", res.Manifest.PublishedAt.Format("2006-01-02"))
	if res.Manifest.Urgency == update.UrgencySecurity {
		fmt.Fprintln(stdout, "  URGENCY     security release")
	}
	if res.Manifest.Note != "" {
		fmt.Fprintf(stdout, "  note        %s\n", res.Manifest.Note)
	}
	fmt.Fprintf(stdout, "  archive     %s (%s)\n", res.Asset.File, humanBytes(res.Asset.Size))
	fmt.Fprintf(stdout, "  signed by   %s\n", res.Manifest.SignedBy)

	if res.Refusal != nil {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, res.Refusal.Error())
		return exitCannotPatch
	}
	if check {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Run `zcd update --yes` to install it.")
		return exitAvailable
	}
	if !yes {
		fmt.Fprintf(stderr, "\nInstall %s now? [y/N]: ", res.Manifest.Version)
		line, _ := readLineFrom(stdin)
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(stdout, "Nothing was changed.")
			if dir != "" {
				prefs.DeclinedVersion = res.Manifest.Version
				_ = update.SavePrefs(dir, prefs)
			}
			return exitAvailable
		}
	}

	fmt.Fprintf(stdout, "==> fetching %s\n", res.Asset.File)
	// The critical section: from the first backup rename to the last replace.
	// Two syscalls wide, and the only window in this command where an interrupt
	// costs anything real.
	signal.Ignore(os.Interrupt, syscall.SIGTERM)
	in, backups, err := res.Install(ctx, f, nil)
	signal.Reset(os.Interrupt, syscall.SIGTERM)
	if err != nil {
		fmt.Fprintln(stderr, "zcd update:", err)
		return exitFailed
	}
	for dst := range in.Binaries {
		fmt.Fprintf(stdout, "==> replaced %s\n", dst)
	}
	fmt.Fprintf(stdout, "installed %s; the previous binary is kept at %s\n",
		res.Manifest.Version, backups[in.Target.Resolved])
	return exitUpToDate
}

func printSourceLine(w io.Writer, res *update.Result) {
	if res.Manifest == nil {
		return
	}
	fmt.Fprintf(w, "  manifest    %s, signed by %s\n", res.Manifest.Version, res.Manifest.SignedBy)
	fmt.Fprintf(w, "  tier        %s\n", localPlatformKey())
}

// readLineFrom reads one line, tolerating a closed stdin as a decline.
func readLineFrom(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	return br.ReadString('\n')
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// updatePrintSource answers "where would this talk to, and with what key",
// without letting it talk.
//
// It earns its place twice: it is what the node's first-run prompt points at
// instead of twenty lines of prose, and it is how a wiring test proves the host
// constant and the embedded key set actually landed in the binary.
func updatePrintSource(repo string, w io.Writer) int {
	f := &update.Fetcher{Base: repo}
	mURL, err := f.ManifestURL()
	if err != nil {
		fmt.Fprintln(w, "release host:", err)
		return exitFailed
	}
	fmt.Fprintln(w, "release host   ", update.RepoURL())
	if repo != "" {
		fmt.Fprintln(w, "  overridden to", repo)
	}
	fmt.Fprintln(w, "manifest       ", mURL)

	ks, err := update.Keys()
	if err != nil {
		fmt.Fprintln(w, "keys:", err)
		return exitFailed
	}
	sum := update.KeysHash()
	fmt.Fprintf(w, "key set         sha256:%x\n", sum[:8])
	fmt.Fprintln(w, "                (reproduce with: sha256sum update/keys.json)")
	for _, k := range ks.Keys {
		fmt.Fprintf(w, "  %-4s %-8s %s\n", k.ID, k.Role, k.Key)
	}
	fmt.Fprintln(w, "this platform  ", localPlatformKey())
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Nothing was contacted to print this.")
	return exitUpToDate
}

func updateRollback(stdout, stderr io.Writer) int {
	t, err := update.Locate()
	if err != nil {
		fmt.Fprintln(stderr, "zcd update:", err)
		return exitFailed
	}
	in := &update.Install{Target: t, Binaries: map[string]string{t.Resolved: ""}}
	if err := in.Rollback(); err != nil {
		fmt.Fprintln(stderr, "zcd update:", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "restored the previous %s\n", t.Name)
	return exitUpToDate
}

// cmdUpdateManifest builds the release manifest, and signs it when asked.
func cmdUpdateManifest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory of published release artefacts (required)")
	version := fs.String("version", "", "the release tag this manifest describes (required)")
	sign := fs.Bool("sign", false, "sign it with the seed in "+update.SigningKeyEnv)
	urgency := fs.String("urgency", "routine", "routine or security")
	note := fs.String("note", "", "one or two sentences shown to an operator")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" || *version == "" {
		fmt.Fprintln(stderr, "zcd update manifest: --dir and --version are required")
		return exitUsage
	}

	m, raw, err := update.BuildManifest(*dir, *version, time.Now(), update.Urgency(*urgency), *note)
	if err != nil {
		fmt.Fprintln(stderr, "zcd update manifest:", err)
		return exitFailed
	}
	out := filepath.Join(*dir, "update-manifest.json")
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		fmt.Fprintln(stderr, "zcd update manifest:", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "wrote %s\n", out)
	for _, name := range []string{"zycord-cli", "zycord-wallet"} {
		p, ok := m.Products[name]
		if !ok {
			continue
		}
		fmt.Fprintf(stdout, "  %s\n", name)
		for _, k := range p.SortedAssetKeys() {
			fmt.Fprintf(stdout, "    %-24s %s\n", k, p.Assets[k].File)
		}
	}

	if !*sign {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "NOTHING IS SIGNED YET, AND THIS FILE DOES NOTHING UNTIL IT IS.")
		fmt.Fprintf(stdout, "Sign it with the seed in %s and write %s.sig beside it.\n",
			update.SigningKeyEnv, filepath.Base(out))
		return exitUpToDate
	}
	seed := os.Getenv(update.SigningKeyEnv)
	if seed == "" {
		fmt.Fprintf(stderr, "zcd update manifest: --sign was given and %s is not set\n", update.SigningKeyEnv)
		return exitFailed
	}
	sig, err := update.SignManifest(raw, seed)
	if err != nil {
		fmt.Fprintln(stderr, "zcd update manifest:", err)
		return exitFailed
	}
	if err := os.WriteFile(out+".sig", sig, 0o644); err != nil {
		fmt.Fprintln(stderr, "zcd update manifest:", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "wrote %s.sig\n", out)
	return exitUpToDate
}

// cmdUpdateVerify checks a manifest the way a node will.
//
// This is the release-smoke of this feature. Every other gate in the pipeline
// hashes something, and a hash cannot tell you a signature verifies.
func cmdUpdateVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory holding update-manifest.json and its signature (required)")
	printVersion := fs.Bool("print-version", false, "print only the version it names")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "zcd update verify: --dir is required")
		return exitUsage
	}
	raw, err := os.ReadFile(filepath.Join(*dir, "update-manifest.json"))
	if err != nil {
		fmt.Fprintln(stderr, "zcd update verify:", err)
		return exitFailed
	}
	sig, err := os.ReadFile(filepath.Join(*dir, "update-manifest.json.sig"))
	if err != nil {
		fmt.Fprintln(stderr, "zcd update verify:", err)
		return exitFailed
	}
	ks, err := update.Keys()
	if err != nil {
		fmt.Fprintln(stderr, "zcd update verify:", err)
		return exitFailed
	}
	m, err := update.ParseManifest(raw, sig, ks)
	if err != nil {
		fmt.Fprintln(stderr, "zcd update verify:", err)
		return exitFailed
	}
	if *printVersion {
		fmt.Fprintln(stdout, m.Version)
		return exitUpToDate
	}
	fmt.Fprintf(stdout, "%s verifies against key %s\n", m.Version, m.SignedBy)
	fmt.Fprintf(stdout, "  published %s\n", m.PublishedAt.Format(time.RFC3339))
	fmt.Fprintf(stdout, "  urgency   %s\n", m.Urgency)
	if m.Note != "" {
		fmt.Fprintf(stdout, "  note      %s\n", m.Note)
	}
	total := 0
	for _, p := range m.Products {
		total += len(p.Assets)
	}
	fmt.Fprintf(stdout, "  %d archives across %d products\n", total, len(m.Products))

	// Every asset the manifest names must actually be here. A signed manifest
	// promising an archive the release does not carry is a release that updates
	// that platform into a 404.
	missing := 0
	for name, p := range m.Products {
		for _, k := range p.SortedAssetKeys() {
			if _, err := os.Stat(filepath.Join(*dir, p.Assets[k].File)); err != nil {
				fmt.Fprintf(stderr, "  MISSING %s/%s: %s\n", name, k, p.Assets[k].File)
				missing++
			}
		}
	}
	if missing > 0 {
		fmt.Fprintf(stderr, "zcd update verify: %d archives named by the manifest are not here\n", missing)
		return exitFailed
	}
	return exitUpToDate
}

// localPlatformKey names the archive this binary would ask for.
//
// randomx.Available() is the same question `zcd version` answers on its second
// line, and asking it here is what keeps an updater from ever handing a mining
// binary the archive that cannot mine.
func localPlatformKey() string {
	k, err := update.LocalPlatformKey(update.TierFor(randomx.Available()))
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	return k
}
