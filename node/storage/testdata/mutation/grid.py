"""Mutation driver for the commit-slot guard in repair.go.

THIS GRID MEASURES NOTHING AS IT STANDS, AND SAYS SO BEFORE IT RUNS.

Every row below names text the commit sidecar deleted or rewrote in repair.go: the durable
commit record in commits.go replaced the three recovery guesses these rows probed
(`successorRunEnd`, `followSequenceRun`, `commitRecordSlotOccupied` and the
prefix-walk anchor around them), so not one substitution matches any more. A
driver in that state applies nothing, the suite passes because nothing changed,
and the run reads as eight covered sites. That is the failure `PROTOCOL.md`
rule 22 exists to catch, in the instrument rather than in the code: an outcome
that cannot tell "the mutant was killed" from "the mutant was never applied".

So the preflight below runs on every invocation and refuses the whole grid while
any row is dead. Nothing here has been retargeted at what replaced the deleted
code, and that is deliberate — retargeting is a new measurement, not a repair of
this one. Until someone does it, the only honest output is a refusal: read this
grid as UNMEASURED, never as covered.

Run from the repository root. It mutates a tracked source file in place, so the
caller restores with `git checkout -- node/storage/repair.go` and MUST verify the
restore by content, not by `git status`:

    python node/storage/testdata/mutation/grid.py --check   # preflight only
    python node/storage/testdata/mutation/grid.py <name>
    go test -c -o /somewhere/st.test ./node/storage/   # fresh binary
    /somewhere/st.test -test.count=1                   # NO -run filter
    git checkout -- node/storage/repair.go
    git show HEAD:node/storage/repair.go | cmp - node/storage/repair.go

Four disciplines are load-bearing and each cost something to learn:

  * EXIT NON-ZERO IF THE PATTERN IS NOT FOUND EXACTLY ONCE, AND CHECK EVERY ROW,
    NOT ONLY THE ONE BEING RUN. A mutant that silently fails to apply reports as
    a survivor, which is indistinguishable from a guard that is not load-bearing.
    Per-row this was here from the start; what was missing is that a caller runs
    one row at a time and never learns that the other seven stopped applying, so
    the grid as a whole decays into a measurement of nothing one row at a time.

  * DECLARE THE DIRECTION BEFORE THE RUN. Each row carries KILL or SURVIVE, and
    applying it prints that word. A run whose outcome is the opposite of the
    printed direction is a FAIL to be reported — including a SURVIVE row that
    starts being killed, which means the unreachability it asserts stopped
    holding. Without the declaration "the suite behaved as I expected" is
    unfalsifiable, because the expectation is written after the result.

  * BUILD INTO A FRESH BINARY, DELETED FIRST. A mutant that fails to compile
    leaves the previous test binary in place and the runner prints PASS. The
    exposure is one-directional: a stale binary can only manufacture a false
    SURVIVOR, never a false kill.

  * RUN WITHOUT A -run FILTER. A filter built for one mutant set and reused
    for another bounds every "killed by" list to whatever the filter names,
    turning kill sets into lower bounds. That is a reused command rather than
    a missing one, so "what would I run to regenerate this row?" does not
    catch it; the follow-up question is "and is that command still scoped to
    THIS row?".

A mutation loop that exceeds its timeout leaves a live mutant in the tree,
because the restore is the part a timeout cuts. That happened while building
this grid and was caught by comparing content before restoring. Size batches
to finish.
"""

import io
import sys

PATH = "node/storage/repair.go"

# name -> (exact text to replace, replacement, direction). Each must match
# exactly once, and the direction is what the suite must do to the mutant:
# KILL (at least one test fails) or SURVIVE (the whole suite passes, and that
# passing IS the claim the row makes).
MUTANTS = {
    # The guard as a whole: does anything depend on it at all?
    "M0-fix-absent": (
        "\t\tif result == scanNothingFound {",
        "\t\tif false && result == scanNothingFound {",
        "KILL",
    ),
    # The anchor is expectedSeq+1 by the prefix walk's density invariant.
    # Loosening it to >= lets a forged record inside a damaged payload anchor
    # a run, which is the shape `zycordd repair` exists to recover.
    "M1-anchor-loosened-to-ge": (
        "\t\t\t\t\tseq == expectedSeq+1 {",
        "\t\t\t\t\tseq >= expectedSeq+1 {",
        "KILL",
    ),
    # The run is followed by frame adjacency; returning the anchor frame alone
    # makes any later part read as "the log keeps going".
    "M3-run-not-followed": (
        "return followSequenceRun(raw, pos, n, seq, &budget), true",
        "return pos + n, true",
        "KILL",
    ),
    # The run stops when the next frame is not this transaction's next part.
    "M4-adjacency-seq-ignored": (
        "if status != decodeOK || nextSeq != seq+1 {",
        "if status != decodeOK {",
        "KILL",
    ),
    # The commit slot must hold something that could have BEEN a commit
    # record. Neutralising the test convicts an ordinary torn tail.
    "R1-torn-check-neutralised": (
        "if ok && slot != decodeTorn {",
        "if ok && slot != decodeStatus(99) {",
        "KILL",
    ),
    "R2-torn-check-inverted": (
        "if ok && slot != decodeTorn {",
        "if ok && slot == decodeTorn {",
        "KILL",
    ),
    # Both exhaustion branches are unreachable: reaching successorRunEnd
    # requires findTerminalRecordWithin to have traversed the whole region on
    # an equal budget, and this function charges a subset of that traversal.
    # These two are expected to SURVIVE the whole package, which is the proof.
    "P1-outer-exhaustion-panics": (
        '\t\t\t\tif cost > budget {\n\t\t\t\t\treturn 0, false\n\t\t\t\t}',
        '\t\t\t\tif cost > budget {\n\t\t\t\t\tpanic("UNREACHABLE-A: successorRunEnd outer budget")\n\t\t\t\t}',
        "SURVIVE",
    ),
    "P2-inner-exhaustion-panics": (
        "\t\tif *budget < 0 {\n\t\t\treturn end\n\t\t}",
        '\t\tif *budget < 0 {\n\t\t\tpanic("UNREACHABLE-B: followSequenceRun budget")\n\t\t}',
        "SURVIVE",
    ),
}

# Dropping the `ok` gate (`if ok && slot != decodeTorn` -> `if slot != ...`)
# is deliberately absent: it does not compile, because `ok` then goes unused.
# A mutation that cannot be built because the property is structurally
# enforced is a result rather than a gap, and the compiler is the instrument.


def preflight(src):
    """Report every row whose pattern no longer matches exactly once.

    Whole-grid rather than per-row, because a caller runs one row per
    invocation and would otherwise learn only about the row they named. That is
    how all eight rows here came to target text the commit sidecar had deleted
    without anyone running the grid discovering it.
    """
    dead = []
    for name in sorted(MUTANTS):
        count = src.count(MUTANTS[name][0])
        if count != 1:
            dead.append((name, count))
    return dead


def main():
    argv = sys.argv[1:]
    if len(argv) != 1 or (argv[0] != "--check" and argv[0] not in MUTANTS):
        print("usage: grid.py <--check|%s>" % "|".join(sorted(MUTANTS)))
        return 2

    src = io.open(PATH, encoding="utf-8").read()
    dead = preflight(src)
    if dead:
        print("GRID-DOES-NOT-APPLY: %d of %d rows no longer match %s exactly once."
              % (len(dead), len(MUTANTS), PATH))
        for name, count in dead:
            print("  %-28s found %d times, want exactly 1" % (name, count))
        print("This grid measures NOTHING while any row is dead. Its output is not")
        print("coverage of the sites those rows name: retarget them at the code that")
        print("replaced them, or delete them, but do not run the suite against this.")
        return 4

    if argv[0] == "--check":
        print("PREFLIGHT-OK: all %d rows apply exactly once" % len(MUTANTS))
        for name in sorted(MUTANTS):
            print("  %-28s expect %s" % (name, MUTANTS[name][2]))
        return 0

    old, new, expect = MUTANTS[argv[0]]
    io.open(PATH, "w", encoding="utf-8", newline="").write(src.replace(old, new))
    print("applied %s" % argv[0])
    # The direction is printed BEFORE the suite runs, so the verdict is compared
    # against a declaration rather than written after the result. The opposite
    # outcome is a FAIL to report, not a row to re-run.
    print("EXPECT %s %s" % (argv[0], expect))
    return 0


if __name__ == "__main__":
    sys.exit(main())
