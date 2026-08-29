package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"zycord/node/storage"
)

// `zycordd repair` is the recovery door for a data directory the node refuses
// to open.
//
// Until this existed, storage had a refusal policy and no recovery policy:
// every damage class collapsed into one permanent ErrCorrupt, and an operator
// whose node hit the false-corruption shape — an ordinary crash whose last
// record happens to carry record-shaped bytes in its payload — had a store
// that would never boot again and no instrument to tell that apart from real
// data loss. This is that instrument. It is also, unavoidably, a command that
// deletes a node's data on purpose, so it is built to make an operator's
// mistake small:
//
//   - it says exactly what it would discard, and what survives, before
//     discarding anything;
//   - it does nothing without an explicit "yes" typed at the prompt, or
//     --yes given deliberately;
//   - it refuses outright on every damage class a truncation cannot honestly
//     fix, and says "resync this store" instead of offering a cut that would
//     silently lose committed transactions;
//   - it re-derives the plan under the same lock before cutting, so what is
//     discarded is what was approved and never more (storage.Repairer.Apply);
//   - it takes the data directory lock, so it cannot run against a live node.
//
// Diagnosis with no repair is the default: --dry-run reports and exits, and
// so does a plain run whose damage is not repairable.
//
// Exit codes: 0 nothing to do, or the repair was applied; 1 damage that this
// command refuses to repair (or a declined prompt, or an I/O failure);
// 2 usage.
func runRepair(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("zycordd repair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "data directory (required)")
	dryRun := fs.Bool("dry-run", false, "report what would be discarded and exit without changing anything")
	assumeYes := fs.Bool("yes", false, "skip the confirmation prompt; the report is still printed first")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: zycordd repair --dir <data directory> [--dry-run] [--yes]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Diagnose a data directory the node refuses to open, and, when the damage")
		fmt.Fprintln(stderr, "is an unfinished write with nothing committed behind it, discard it.")
		fmt.Fprintln(stderr, "See docs/RUNNING.md, \"Recovering a damaged data directory\".")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "zycordd repair: --dir is required")
		fs.Usage()
		return 2
	}

	r, err := storage.OpenForRepair(*dir)
	if err != nil {
		if errors.Is(err, storage.ErrLocked) {
			fmt.Fprintf(stderr, "zycordd repair: %v\n", err)
			fmt.Fprintln(stderr, "A repair reads the log, decides on an offset and truncates there; "+
				"a running node appending records would make each of those three steps describe "+
				"a different file. Stop the node first.")
			return 1
		}
		fmt.Fprintf(stderr, "zycordd repair: %v\n", err)
		return 1
	}
	defer r.Close()

	d, err := r.Diagnose()
	if err != nil {
		fmt.Fprintf(stderr, "zycordd repair: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "log:       %s (%d byte(s))\n", d.Path, d.Size)
	// LABELLED, because unlabelled it was the larger and more reassuring of two
	// adjacent counts and it sat first. This number is what replay could READ;
	// the finding's "keeps" count is what survives the cut, and on a store whose
	// damage falls inside an open transaction the two differ by that
	// transaction's own parts — so an operator was being asked to type `yes`
	// under a line saying four when three would remain. Neither count moves; only
	// the reader's ability to tell which is which.
	fmt.Fprintf(stdout, "readable:  %d record(s) (records replay could read)\n", d.RecordsIntact)
	fmt.Fprintf(stdout, "finding:   %s\n", d.Explanation)

	if !d.Damaged {
		return 0
	}
	if !d.Repairable {
		// The honest outcome, and the reason this command refuses more
		// classes than it fixes: a store whose committed data is behind the
		// damage cannot be repaired locally at all. Saying so is worth more
		// than a cut that appears to work and has quietly dropped
		// transactions the chain above will later expect to find.
		fmt.Fprintln(stdout, refusalVerdict(d))
		return 1
	}

	fmt.Fprintf(stdout, "proposal:  discard %d byte(s) at offset %d and keep everything before "+
		"it. This is not reversible.\n", d.Discard, d.Offset)
	if *dryRun {
		fmt.Fprintln(stdout, "verdict:   REPAIRABLE. --dry-run given, so nothing was changed.")
		return 0
	}
	if !*assumeYes {
		fmt.Fprint(stdout, "Type yes to discard those bytes: ")
		// The read error is deliberately ignored, and the whole rule is the
		// one comparison. Anything short of the whole word is not consent —
		// a prompt that accepts "y" accepts a stray keystroke, and the thing
		// on the other side of this one is deletion — and that already covers
		// every failed read, because a read that returned nothing returns ""
		// and "" is not "yes". Testing the error as well is the tempting
		// version and it is wrong: ReadString returns io.EOF alongside a
		// final line that has no trailing newline, which is exactly what a
		// human typing yes into a pipe produces.
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Fprintln(stdout, "verdict:   declined. Nothing was changed.")
			return 1
		}
	}

	if err := r.Apply(d); err != nil {
		fmt.Fprintf(stderr, "zycordd repair: %v\n", err)
		return 1
	}
	// RecordsKept, not RecordsIntact: inside an open transaction the cut goes
	// back to that transaction's first record, so the records replay READ are not
	// the records that remain. This line is the last thing an operator is told
	// after an irreversible deletion, and it used to say the larger number.
	fmt.Fprintf(stdout, "verdict:   repaired. %d byte(s) discarded; %d record(s) remain. Start "+
		"the node normally.\n", d.Discard, d.RecordsKept)
	return 0
}

// seeTheManual ends every refusal verdict, so the four sentences below differ
// only in what they establish.
const seeTheManual = " see docs/RUNNING.md, \"Recovering a damaged data directory\"."

// notProven is the shared half of the three refusals that establish nothing.
//
// It is one constant rather than three copies because the claim is literally
// the same claim: no local instrument can answer the question, so there is no
// second attempt to make and no flag that would help. Each caller supplies
// the clause naming WHICH proof failed, and only that.
const notProven = " That is not proven either way; no local instrument can answer it, " +
	"and resync is the only remedy this tool can offer;" + seeTheManual

// refusalVerdict is the last line an operator reads before deciding whether to
// throw a data directory away.
//
// There are four states behind Repairable == false, all refusing, all exiting
// 1, and until this function existed they shared one sentence. Only
// ProvenUnsafeToCut is a store that is unsafe to cut on its merits; in the
// other three the store may be perfectly recoverable and is resynced for want
// of an instrument. An operator could not tell them apart from this line, and
// neither could a runbook step — which is the one that actually runs.
//
// THE EXIT CODE IS NOT PART OF THE DISTINCTION and must not become part of it.
// An exit-code split was considered on its own merits and declined; an exit
// code is the surface most likely to grow an automated lever; this reports,
// and every caller of it returns 1.
//
// Nor is any of this overridable. The reason repair refuses in the three
// unproven states is that the question cannot be answered locally, so a flag
// that said "cut anyway" would be the override flag this command has twice
// been asked for and twice refused. FoundRecordDisproved is the one to watch:
// it is a proof, and it reads like permission, and it is not — the search
// stopped at its first candidate, which is why its sentence has to say so.
func refusalVerdict(d *storage.LogDiagnosis) string {
	switch d.Verdict {
	case storage.FoundRecordDisproved:
		return "verdict:   NOT REPAIRABLE. Nothing was changed. The one record behind the " +
			"damage that looked like a committed transaction was disproved — it is content " +
			"another record carries — but the search stopped at it and never read past it." +
			notProven

	case storage.BlockedBySecondDamage:
		return fmt.Sprintf("verdict:   NOT REPAIRABLE. Nothing was changed. A second damaged "+
			"record at offset %d stopped the walk before it reached the record found, so "+
			"nothing beyond that offset was established.%s", d.SecondDamageOffset, notProven)

	case storage.SearchBeganInsideDamage:
		return "verdict:   NOT REPAIRABLE. Nothing was changed. The damaged record's own frame " +
			"failed its checksum, so the search had to begin inside that record and what it " +
			"found may be that record's own payload." + notProven

	default:
		// ProvenUnsafeToCut and every refusal that never ran a search behind
		// the damage — a damaged snapshot, a record some writer put out of
		// sequence, a header declaring an impossible length, a commit record
		// this log can no longer account for, a scan that spent its budget.
		// They share this line because they share its instruction: the resync
		// is right on its merits, not a remedy of last resort. The finding
		// line above already says which of them it is.
		return "verdict:   NOT REPAIRABLE. Nothing was changed. Resync this store " +
			"from the network;" + seeTheManual
	}
}
