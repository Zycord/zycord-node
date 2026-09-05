// The one workflow that is left, and the equality that keeps it that way.
//
// # What this file is now, and why it changed shape
//
// It began as a duplication check. CI carried its own inline copy of the
// whole-tree test command instead of calling the Makefile: a commit gave `make
// race` an explicit `-timeout 30m`, with a comment explaining exactly why Go's
// ten-minute default is wrong for `node/mempool` under the race detector, and
// the workflow kept running `go test -race ./...` at the default. The fix
// landed in one file and the job kept failing in the other. So this file pinned
// a golden set of the CI commands naming `./...`, and argued at length that an
// equality is the only form that survives contact with a reviewer.
//
// **That premise is gone, and it is worth saying exactly how.** This project's
// forge account was permanently suspended, with no appeal: workflow jobs
// computed proof-of-work hashes, and the forge's abuse detection read that as
// using its runners to mine cryptocurrency. Every workflow but one was deleted
// in response, and the survivor builds release artefacts and does nothing else.
// There is no `go test` in CI to duplicate the Makefile, because there is no
// testing in CI. The whole tree is tested on the developer's machine, before
// the push, and that is the only gate there is.
//
// So the question this file answers changed, and the answer it gives did not:
// **an equality, over data somebody had to write down.** What is pinned now is
// five of them, in the order a reader should meet them.
//
//	the files    `.github/workflows/` holds exactly the files named below.
//	             This is the check that most directly encodes the ban: putting
//	             `ci.yml` back is a diff here before it is anything else.
//
//	the jobs     that file defines exactly the jobs named below. A job added to
//	             an existing workflow is the second way the pattern returns, and
//	             it is invisible to the check above.
//
//	the Go tool  no command invokes `go test`, `go run` or `go generate`. This
//	             one is a rule and not a list, deliberately: it is a policy
//	             rather than a judgement about shell, there is no honest reason
//	             for a build workflow to execute Go code, and a list would
//	             invite somebody to add a line to it.
//
//	the targets  every `make <target>` in a workflow names a target from the
//	             allow-list below. The Makefile is where running and building
//	             are told apart -- `dist` compiles, `release-smoke` starts a
//	             node -- so an allow-list over target names is an equality with
//	             the grain of the tree rather than against it.
//
//	the binaries every command whose raw text names a program this repository
//	             builds is one of the commands written down below, and there are
//	             no others. This is the old check with the marker changed:
//	             `./...` meant "runs the whole tree", and `zcd` / `zycordd` /
//	             `zycord-wallet` mean "touches something we compiled". It is the
//	             one that catches the pattern arriving with no Makefile and no
//	             Go tool in sight, which is precisely how the deleted
//	             `randomx-smoke-windows` job was written: PowerShell, a
//	             downloaded artefact, `Start-Process`, and a loop waiting for the
//	             engine to name itself.
//
// # Why equalities and not rules
//
// The first three versions of this file tried to *decide* whether a shell
// command invokes a whole-tree `go test`: a prefix match, then a substring
// match, then an anchored regular expression with exemptions. Two hostile
// reviews put nine evasions through them, and the ninth was created by the fix
// for the eighth:
//
//	prefix      `CGO_ENABLED=0 go test ./...`
//	substring   the positive half satisfied by `make test-randomx`
//	prose       `echo 'run make test locally'`
//	quoting     `go test -race "./..."` — invisible once quoted text was
//	            stripped to stop the prose case, which is the previous row's fix
//	            opening the hole
//	wrappers    `timeout 20m go test ./...`, `xvfb-run …`, `nice …`, `sudo …`
//	grouping    `(go test -race ./...)`
//	indirection `sh -c "go test -race ./..."`
//	multi-line  a `\` continuation, and a folded `run: >` body
//	scope       a job id containing `_` inherited the previous job's exemption
//
// None needed special knowledge. Every one of them lands in the diff of a
// golden list, because every one of them contains the marker — which is the
// property of the thing rather than a guess about it. That reasoning is why the
// lists below are lists, and it is unchanged by the change of subject.
//
// Editing a workflow now requires editing this file. That is the cost, and it
// is the point: the failure is a prompt to read this comment before adding a
// job, not an assertion about a shell string that may be wrong. It is the same
// trade `spec/vectors` already makes — a golden corpus, regenerated by hand,
// whose diff is the review.
//
// The two known limits, stated rather than discovered.
//
// False negative: a command that runs a built program without naming it is not
// seen. `exe=$(ls dist/randomx/*/zycordd); "$exe"` names it once and could name
// it never. Closing that needs a rule about what a shell string MEANS, which is
// the deciding this file spent three rounds proving it cannot do reliably; the
// honest position is that the lists cover the literal markers and the four
// checks around them cover the rest — a command like that still has to live in
// a job, in a file, and a new one of either is a diff.
//
// False positive: a command that merely *mentions* a program — an `echo` in an
// error message — lands in the list too, because the marker is matched in the
// raw text and nothing here parses shell. That is four of the entries below.
// The trade is worth naming: the cost is four lines somebody read once, and the
// thing bought is that no shell SYNTAX evades the check.
//
// # A job may be a call rather than a list of steps
//
// A job whose body is `uses: ./.github/workflows/<file>` runs that workflow's
// steps, and this file has to follow the call to see them. It is the same
// blindness the parser checks guard against, arriving through the one door they
// did not watch: `parseJobs` still saw the job, so the job list was green, and
// `parseRuns` found no step inside it, so every command it runs left the golden
// list at once. That is how three `windows` entries once vanished — the
// commands did not change, the file the parser reads did.
//
// No workflow calls another today, and the file list is what keeps it that way.
// The machinery stays because removing it would make the next `workflow_call`
// silent, which is the state the paragraph above describes.
//
// Commands from a called workflow are attributed to the CALLING job, because
// that is the job the golden list names and the one a reader sees in the checks
// list. The callee's own job id is not used: renaming it is invisible to the
// caller and must not churn the list here.
//
// Deliberately textual rather than a YAML parse. The tree carries two direct
// dependencies and `go.mod` says that is meant to stay that way, so a YAML
// library would need the dedicated pull request CONTRIBUTING.md requires — to
// read a file this reads in eighty lines.
package wiring_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// workflowDir holds every workflow this repository has, relative to this
// package. It is read as a directory rather than by naming one file, so that a
// second workflow appearing is seen by every check here on the day it lands and
// not only by the file list.
const workflowDir = "../../.github/workflows"

// workflowFiles is that directory's contents, and it is the shortest statement
// of the policy in the tree.
//
// One file, which builds release artefacts. Nothing else runs on a hosted
// runner: no tests, no fuzzing, no vector regeneration, no job that starts a
// binary this repository built. The account this project published from was
// permanently suspended for the last of those, so a second entry here is not a
// tidiness question — it is the decision that cost the account, being taken
// again.
var workflowFiles = []string{"release.yml"}

// makefilePath is where the whole tree is now tested from, and the only place.
const makefilePath = "../../Makefile"

// repoRoot is the repository root, relative to this package. A workflow's
// `uses: ./...` reference is written from there rather than from the file
// carrying it.
const repoRoot = "../.."

// resolver reads a workflow named by a `uses:` reference. It reports false for
// a reference this file will not follow, which covers three cases the caller
// treats alike: a reference outside this repository (a published action, which
// has no steps to read here), one that cannot be read, and one already visited.
//
// A reference that cannot be read is deliberately quiet rather than fatal,
// because the per-job blindness check in TestTheParserStillSeesTheWholeWorkflow
// already reports the consequence — a job reaching no command — and reports it
// against the job a reader has to fix rather than against a path.
type resolver func(ref string) (string, bool)

// localWorkflows resolves `uses:` references naming a workflow in this
// repository, and refuses to follow one twice.
//
// The refusal is the cycle guard: workflow_call is a call graph, so a workflow
// calling one that calls back would otherwise recurse until the stack ends. It
// is per-traversal state, so each walk of the file needs its own resolver — two
// walks sharing one would leave the second blind to everything the first read.
func localWorkflows() resolver {
	seen := map[string]bool{}
	return func(ref string) (string, bool) {
		if !strings.HasPrefix(ref, "./") {
			return "", false
		}
		path := filepath.Join(repoRoot, filepath.Clean(strings.TrimPrefix(ref, "./")))
		if seen[path] {
			return "", false
		}
		seen[path] = true
		b, err := os.ReadFile(path)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

// treeWide is the whole-tree package pattern. It no longer appears in any
// workflow — nothing there runs a test — and it is still the marker the
// Makefile's own targets are read for, which is where the whole tree is
// exercised now.
const treeWide = "./..."

// builtPrograms are the names of the programs this repository compiles.
//
// They are the marker for "this command touches something we built", and they
// are matched against a command's RAW text, quotes and all. Stripping quotes
// first — which an earlier version of the `./...` check did, to stop an `echo`
// firing it — made `go test -race "./..."` invisible, which is ordinary
// defensive shell and was the exact thing being guarded. The marker is the
// marker wherever it appears; whether the command is prose is settled by the
// list in TestNothingInAWorkflowRunsWhatItBuilt, not by parsing shell.
//
// `zcd-randomx` and `zycordd.exe` need no entry: they contain `zcd` and
// `zycordd`, and a substring match is what makes that free.
var builtPrograms = []string{"zcd", "zycordd", "zycord-wallet"}

// goSubcommands are the ways of invoking the Go tool that EXECUTE code rather
// than compile it. None of them may appear in a workflow.
//
// A rule rather than a list, and that is the one place this file still decides
// something. It can afford to: it is a policy, not a judgement about shell — a
// build workflow has no honest use for any of these, so there is no case to
// argue and nothing to exempt. A golden list here would be an invitation to add
// a line to it, and the line somebody would add is `go test ./core/pow/randomx/`.
var goSubcommands = []string{"go test", "go run", "go generate", "go tool"}

// makeTargets is every Make target a workflow is allowed to call.
//
// The Makefile is where building and running are told apart, so an allow-list
// over target names reads with the grain of the tree: `dist` and `dist-randomx`
// compile, `dist-deb-check` unpacks an archive and reads its metadata,
// `repro-desktop` builds the wallet three times and compares the bytes. What is
// NOT here is the half of the Makefile that starts things — `release-smoke`
// starts a node and waits for it to name its proof-of-work engine, `test`,
// `race`, `test-randomx`, `fuzz`, `differential`, `bench`, `soak` and `localnet`
// run the suites, and `ci` runs most of them at once. Every one of those is
// worth running; none of them may run here.
//
// Adding a target to this list is a decision about what a hosted runner does,
// and the reasoning belongs in the pull request that adds it.
var makeTargets = []string{
	"build",
	"dist",
	"dist-deb",
	"dist-deb-check",
	"dist-desktop",
	"dist-randomx",
	"repro-desktop",
}

// makeCall finds a `make <target>` invocation anywhere in a command's raw text,
// including one behind `sudo`, `env VAR=x`, a pipe or a `&&` — because the
// target name is what is being read and none of those hide it.
var makeCall = regexp.MustCompile(`\bmake\s+([a-z][a-z0-9-]*)`)

// runLine matches a step's `run:` key and captures whatever follows it on the
// same line: either the command itself, or a block-scalar indicator.
var runLine = regexp.MustCompile(`^(\s*)run:\s*(.*?)\s*$`)

// blockScalar matches YAML's literal and folded block indicators — `|`, `>`, and
// their chomping and indentation modifiers — which say the command is on the
// following, more-indented lines rather than this one.
//
// The first version of this file matched only `run: <command>` on one line, so a
// `run: |` step captured the literal "|" as its command and the actual command,
// indented below, was never read. This workflow uses the block form nine times.
var blockScalar = regexp.MustCompile(`^([|>])([-+]?[0-9]*|[0-9]*[-+]?)$`)

// stepStart matches the `- ` that begins a new step, which is where a
// `working-directory:` stops applying.
var stepStart = regexp.MustCompile(`^(\s*)- `)

// workingDir matches a `working-directory:` key, in a step or in a job's
// `defaults.run` block.
//
// It carries the same trailing-comment tolerance as the structural keys, and for
// the same reason: without it, `working-directory: desktop # the separate
// module` dropped the key, and the golden list then reported the desktop
// module's own `go vet ./...` as an unreviewed command running "at the
// repository root". A benign comment, a false accusation, and a wrong
// diagnosis — the same shape as the job-header bug one regex earlier.
var workingDir = regexp.MustCompile(`^\s*working-directory:\s*(\S+)\s*(#.*)?$`)

// jobsKey matches the top-level `jobs:` mapping, at column zero.
//
// The job scan is gated on it because jobHeader describes an indentation, not a
// meaning: `on:` carries `push:` and `pull_request:` at the same two spaces, and
// without this gate they are read as jobs.
var jobsKey = regexp.MustCompile(`^jobs:\s*(#.*)?$`)

// jobHeader matches a job key: two spaces, a name, a colon, nothing else.
//
// The charset is deliberately wide. It was `[a-z][a-z0-9-]*` — no underscore,
// though `pull_request:` two screens above proves the character is idiomatic in
// this very file. An unmatched header made the parser carry the PREVIOUS job's
// name forward, silently attributing one job's steps to another.
var jobHeader = regexp.MustCompile(`^  ([A-Za-z0-9_.-]+):\s*(#.*)?$`)

// stepsKey matches a job's `steps:` list. Steps are read only after it, so that
// a job-level `defaults:` block — which contains a `run:` mapping of its own —
// is not mistaken for a step running the empty command.
//
// All three structural keys tolerate a trailing `# comment`, because without it
// they did not, and the consequence was silence. `steps: # its commands` failed
// to match, so the parser never entered that job and an inline whole-tree race
// run inside it was invisible. One key up, `windows: # the platform job` failed
// jobHeader and re-attributed every windows command to the previous job, firing
// the golden list with the wrong story and a suggested fix that deletes real
// coverage. Annotating a YAML key is ordinary; a check that goes quiet when
// someone does it is the mirror CONTRIBUTING.md warns about.
var stepsKey = regexp.MustCompile(`^\s*steps:\s*(#.*)?$`)

// runKey matches what a step's `run:` key looks like before any indentation
// reasoning is applied, including the unnamed `- run:` form. It is used only to
// ask whether a step the parser produced nothing for *should* have produced
// something.
var runKey = regexp.MustCompile(`^\s*(- )?run:`)

// localWorkflowCall matches a job-level `uses:` naming a reusable workflow.
//
// It is applied only where a job-level key can appear — inside a job and before
// its `steps:` — so it needs no indentation reasoning to tell itself apart from
// the `- uses:` of a step, which cannot occur there. What it does require is the
// leading `./` that marks a workflow in this repository: a published action is
// a `uses:` too, and there is nothing here to read inside one.
var localWorkflowCall = regexp.MustCompile(`^\s*uses:\s*(\S+)\s*(#.*)?$`)

// usesKey matches a step's `uses:` key.
//
// A step that `uses:` an action is exempt from the blindness check, because a
// composite action's `with:` block can carry a `run:` input of its own — a
// string the action consumes, not a command this workflow runs. That exemption
// is what lets the check be per-step and therefore free of any need to know how
// many keys the parser deliberately skips.
var usesKey = regexp.MustCompile(`^\s*(- )?uses:`)

// command is one shell command from the workflow, with the context a reader
// needs in order to judge it.
//
// WorkingDir is part of the identity, not decoration. `desktop/` is a separate
// Go module, so `go test ./...` evaluated there names a different package set
// from the same command at the repository root — the two are different facts
// that read identically, and an earlier version of this file accepted a
// root-module race run because it compared only the job.
type command struct {
	Job        string
	WorkingDir string
	Text       string
}

// workflowNames returns the .yml files in the workflow directory, in name
// order.
func workflowNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Clean(workflowDir))
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// readWorkflowCommands returns every shell command in EVERY workflow, tagged
// with the job and working directory it runs under.
//
// Every workflow rather than a named one: the file list below says there is
// exactly one, and reading the directory means a second is scanned by every
// check here the day it appears rather than only by the list that forbids it.
// Two checks seeing the same file is the cheap half of a belt and braces; a
// smuggled file that only one of them looks at is the expensive half.
func readWorkflowCommands(t *testing.T) []command {
	t.Helper()
	var cmds []command
	for _, name := range workflowNames(t) {
		path := filepath.Join(workflowDir, name)
		b, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		// A resolver per file: the cycle guard is per-traversal state, and one
		// shared across files would leave the second walk blind to whatever the
		// first had already followed.
		cmds = append(cmds, parseRuns(string(b), localWorkflows())...)
	}
	if len(cmds) == 0 {
		t.Fatalf("parsed no run: steps out of %s; the parser has gone stale", workflowDir)
	}
	return cmds
}

// TestTheWorkflowDirectoryHoldsOnlyTheBuild is the shortest check in this file
// and the one that carries the most.
//
// The property: **`.github/workflows/` holds exactly the files written down
// here.**
//
// This project's forge account was permanently suspended, with no appeal,
// because workflow jobs computed proof-of-work hashes and the forge's abuse
// detection read that as mining on its runners. The response was to delete
// every workflow but the one that builds release artefacts, and to move all
// testing onto the developer's machine, before the push.
//
// A file added here is that decision being reversed, whatever the file is
// called and whatever it contains. It may be the right decision — but it is a
// decision, and this is where somebody has to take it in writing rather than by
// adding a file nobody reviews twice. Every other check in this file assumes
// the answer to "what runs on a hosted runner" is short enough to read.
func TestTheWorkflowDirectoryHoldsOnlyTheBuild(t *testing.T) {
	got := workflowNames(t)
	want := append([]string(nil), workflowFiles...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("%s holds %d workflow(s) and %d are written down here:\n"+
			"    holds:   %v\n    written: %v", workflowDir, len(got), len(want), got, want)
	}
	for _, name := range got {
		if !contains(want, name) {
			t.Errorf("%s/%s is a workflow this list does not name.\n"+
				"Adding a workflow is not a tidiness question here. The account this\n"+
				"project published from was permanently suspended, with no appeal, for\n"+
				"jobs that computed proof-of-work hashes on hosted runners; what is left\n"+
				"is one workflow that builds release artefacts and runs nothing.\n"+
				"Everything that tests this tree runs on the developer's machine before\n"+
				"the push — CONTRIBUTING.md and docs/RELEASE.md name the commands.\n"+
				"If this file genuinely belongs, add it here and say in the pull request\n"+
				"what it runs and why a hosted runner's log could not be read as mining.",
				workflowDir, name)
		}
	}
	for _, name := range want {
		if !contains(got, name) {
			t.Errorf("%s/%s is written down here and is not in the tree.\n"+
				"If it was deliberately removed, remove it from this list too.",
				workflowDir, name)
		}
	}
}

// TestNoWorkflowExecutesGoCode is the rule, and it is the only one here.
//
// The property: **no command in any workflow invokes `go test`, `go run`,
// `go generate` or `go tool`.**
//
// It is a rule and not a golden list on purpose. The lists in this file exist
// because deciding whether a shell string does something is unreliable — nine
// measured evasions say so. This is not that question. It is a policy about
// what a hosted runner is for, it admits no exemptions, and a list would only
// give somebody a place to write one down. The line that would be written is
// `go test -count=1 -run TestVendoredTreeMatchesPinned ./core/pow/randomx/`,
// which was a real step of a real job, was worth running, and is now run on the
// release machine instead.
//
// `go build` and `go vet` are absent from the forbidden set and that is not an
// oversight: they compile, they do not execute, and compiling a binary that
// contains a proof-of-work engine is not the thing that got this project
// banned. Running one is.
func TestNoWorkflowExecutesGoCode(t *testing.T) {
	for _, c := range readWorkflowCommands(t) {
		for _, sub := range goSubcommands {
			if strings.Contains(c.Text, sub) {
				t.Errorf("a workflow command invokes %q:\n    %s\n"+
					"Nothing in a workflow may execute Go code. The whole tree is tested on\n"+
					"the developer's machine before the push, and that is the only gate\n"+
					"there is — `make ci`, and the release additions in docs/RELEASE.md.\n"+
					"The reason is in this file's header and in the surviving workflow's:\n"+
					"a job that runs the engine is what cost this project its account.",
					sub, show(c))
			}
		}
	}
}

// TestAWorkflowCallsOnlyTheBuildTargets is the allow-list, and it is where the
// distinction this whole policy turns on is actually written down.
//
// The property: **every `make <target>` in a workflow names a target from
// `makeTargets`.**
//
// Compiling a binary that contains the proof-of-work engine is not mining, and
// hashing a finished artefact to show two builds agree is ordinary build
// practice. Running the proof-of-work function is the thing that looks like
// mining. The Makefile is where those two are already separated by name —
// `dist-randomx` compiles the engine, `release-smoke` starts a node and waits
// for it to print which engine it selected — so an allow-list over target names
// says the policy in the tree's own vocabulary instead of in a regular
// expression about shell.
//
// The failure names the target rather than the command, because the target is
// the thing to think about.
func TestAWorkflowCallsOnlyTheBuildTargets(t *testing.T) {
	for _, c := range readWorkflowCommands(t) {
		for _, m := range makeCall.FindAllStringSubmatch(c.Text, -1) {
			if contains(makeTargets, m[1]) {
				continue
			}
			t.Errorf("a workflow calls `make %s`:\n    %s\n"+
				"Only the build targets may run on a hosted runner: %v.\n"+
				"Everything else in the Makefile either runs the test suites or starts a\n"+
				"binary this repository built, and a runner log full of proof-of-work\n"+
				"hashes is what got this project's account permanently suspended.\n"+
				"If this target genuinely only builds, add it to makeTargets and say so\n"+
				"in the pull request.", m[1], show(c), makeTargets)
		}
	}
}

// TestTheParserStillSeesTheWholeWorkflow is the obsolescence check, and it is

// the one this file most needs.
//
// The property: **the set of jobs the parser finds is exactly the set of jobs
// the workflow defines.**
//
// Everything else here now rests on the parser. That is the cost of replacing a
// rule with a golden list: the list cannot be argued with, but it can be fed an
// incomplete reading of the file, and a parser that has stopped seeing a job
// reports exactly the same green as a workflow with nothing wrong in it. That is
// the mirror CONTRIBUTING.md tabulates — an instrument whose signal is derived
// from the state the bug corrupts — and it was not hypothetical: `steps:` failed
// to match when someone wrote `steps: # its commands`, so the parser never
// entered that job and an inline whole-tree race run inside it was invisible.
//
// A `len(cmds) == 0` guard does not reach this. It fires only when the parser
// goes blind to the *whole* file, and the failure that matters is going blind to
// one job. So the job names are pinned as data, in the same style as the command
// list: a job that disappears from the parser's view is a diff, and a job that is
// genuinely added is one line plus the thought about whether it runs the whole
// tree.
//
// Two blindness checks sit beside the job names, and they are the half with the
// sharper teeth. Pinning jobs catches blindness at job granularity and is
// structurally incapable of catching it one level down: when `- run:` without a
// `name:` matched no key, `parseJobs` and `parseRuns` still agreed perfectly
// about every job in the file while an inline whole-tree race run inside one of
// those jobs produced no command at all. Both readings were confidently right
// about jobs and silently wrong about a step.
//
//	per step  a step with no `uses:` key, carrying a line that looks like a
//	          `run:` key, that yields no command, is a step the parser cannot
//	          read. That is exactly what an unnamed `- run:` was, and it is what
//	          any future key-regex regression will be, at any indentation.
//
//	per job   every job named above yields at least one command. That is the
//	          other shape: a job the parser SEES but whose steps it cannot
//	          reach, which is what a commented `steps:` key produced.
//
// Both are conditions on the parser's own reading rather than on a number, so
// neither fires when the workflow legitimately changes.
//
// A pinned command count was tried first and replaced, and the reason is the
// point rather than a detail. It worked — it caught the unnamed step — but it
// also fired on every benign edit, and its failure read "recovers 76 commands
// and 75 are expected". The golden lists' churn is the point *because their
// diff is a review*: the reader sees which whole-tree command appeared and
// decides. "76 ≠ 75" is not a review. It says nothing about what changed, and
// the only available response is to increment the constant — and a check whose
// remedy is to reflexively bump a number is a check people learn to skim, which
// is the exact failure this file exists to prevent. CONTRIBUTING.md: a check
// that fires for a benign reason is noise with authority, and worse than
// silence.
//
// The narrower pair gives up detecting a step that was *deleted*. The golden
// list of commands touching a built program already catches deletion of those,
// and a deleted `echo` step is not worth a red build.
//
// The job names carry a second job now, and it is the one this file cares most
// about. `cli`, `cli-randomx` and `desktop` compile; `publish` collects, attests
// and releases. A fifth entry is somebody proposing that a hosted runner do
// something else, which is the decision the file list above is about.
func TestTheParserStillSeesTheWholeWorkflow(t *testing.T) {
	want := []string{"cli", "cli-randomx", "desktop", "publish"}

	var src string
	for _, name := range workflowNames(t) {
		b, err := os.ReadFile(filepath.Clean(filepath.Join(workflowDir, name)))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		src += string(b) + "\n"
	}

	// A fresh resolver for each traversal: they are independent walks of the
	// same text, and the cycle guard is per-resolver state.
	for _, blind := range blindSteps(src, localWorkflows()) {
		t.Errorf("the parser cannot read this step:\n%s\n"+
			"It has what looks like a `run:` key and no `uses:`, and yet produced no\n"+
			"command — so none of the checks in this file apply to whatever it runs.\n"+
			"This is a parser defect, not a workflow defect: fix the reading, and add\n"+
			"the form to TestTheParserSeesTheFormsTheWorkflowUses so it stays fixed.",
			blind)
	}

	got := parseJobs(src)

	reached := map[string]bool{}
	for _, c := range parseRuns(src, localWorkflows()) {
		reached[c.Job] = true
	}

	if len(got) != len(want) {
		t.Errorf("the parser sees %d jobs and %d are written down here:\n"+
			"    sees:    %v\n    written: %v\n"+
			"A job the parser cannot see is a job none of the checks in this file apply\n"+
			"to, and it reports the same green as a job with nothing wrong in it.",
			len(got), len(want), got, want)
	}
	seen := map[string]bool{}
	for _, j := range got {
		seen[j] = true
	}
	for _, j := range want {
		if !seen[j] {
			t.Errorf("the parser no longer sees the %q job.\n"+
				"Either it was renamed or removed — update this list — or the parser has\n"+
				"gone blind to it, in which case nothing else in this file is checking it.", j)
			continue
		}
		if !reached[j] {
			t.Errorf("the parser sees the %q job but reaches none of its commands.\n"+
				"Every job in this workflow runs something. A job whose steps cannot be\n"+
				"read reports the same green as a job with nothing wrong in it — a\n"+
				"commented `steps:` key did exactly this.", j)
		}
	}
	for _, j := range got {
		if !contains(want, j) {
			t.Errorf("the workflow defines a job this list does not name: %q.\n"+
				"Add it — and while you are here, check that it BUILDS rather than\n"+
				"runs. A job that starts what it compiled is the one thing that may\n"+
				"never come back.", j)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// blindSteps returns a rendering of every step that looks like it runs
// something and that the parser could not read.
//
// The property it serves: a step carrying a `run:` key and no `uses:` must
// produce at least one command. An unnamed `- run:` satisfied the first half and
// failed the second — silently, at every indentation — and so would any future
// regression in the key regexes.
//
// It walks the same eachStep as parseRuns, deliberately: a check that segmented
// the file its own way could disagree with the reading it is auditing, and
// then it would be reporting on a workflow nobody runs.
func blindSteps(src string, resolve resolver) []string {
	var blind []string
	eachStep(src, resolve, func(job, defaultWD string, step []string) {
		hasRun, hasUses := false, false
		for _, line := range step {
			if runKey.MatchString(line) {
				hasRun = true
			}
			if usesKey.MatchString(line) {
				hasUses = true
			}
		}
		if !hasRun || hasUses {
			return
		}
		if len(commandsInStep(job, defaultWD, step)) > 0 {
			return
		}
		blind = append(blind, "    job "+job+":\n        "+strings.Join(step, "\n        "))
	})
	return blind
}

// parseJobs returns the job names, in file order. Separate from parseRuns
// because the question it answers is about the parser rather than the commands.
func parseJobs(src string) []string {
	var jobs []string
	inJobs := false
	for _, line := range strings.Split(src, "\n") {
		if jobsKey.MatchString(line) {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if m := jobHeader.FindStringSubmatch(line); m != nil {
			jobs = append(jobs, m[1])
		}
	}
	return jobs
}

// TestNothingInAWorkflowRunsWhatItBuilt is the equality with the sharpest
// teeth, and it is the old whole-tree list with the marker changed.
//
// The property, in one sentence: **every workflow command whose raw text names
// a program this repository builds is one of the commands written down here,
// and there are no others.**
//
// The marker used to be `./...`, which meant "runs the whole tree". It is now
// `zcd`, `zycordd` and `zycord-wallet`, which mean "touches something we
// compiled" — because the thing that has to be impossible here is no longer a
// duplicated test command, it is a job that STARTS a binary. This project's
// forge account was permanently suspended for exactly that: the engine tests
// and two smoke jobs computed proof-of-work hashes on hosted runners, and the
// abuse detection read them as mining.
//
// The two checks either side of this one — the Go-tool rule and the Make
// allow-list — cover the two ordinary ways of running something. This one
// covers the third, and it is the way the job that mattered most was actually
// written: `randomx-smoke-windows` downloaded the published archive, unzipped
// it, and used PowerShell's `Start-Process` on `zycordd.exe` with a loop
// waiting for the engine line. No Makefile, no Go tool, nothing a rule about
// either would have seen. What it could not avoid was naming the binary.
//
// The list is short because the property is narrow, and each entry is a
// command somebody had to write down and a reviewer had to read:
//
//	cli      four lines of the rebuild-and-compare step. Two read a hash out of
//	         a file and out of `bin/zcd`; two are error text that mentions the
//	         program. Hashing a finished artefact to show two builds of one
//	         commit agree is ordinary build practice and is the whole of the
//	         reproducibility claim docs/INSTALL.md makes — it is not running
//	         anything, and it stays.
//
//	publish  two lines that stage the wallet archives and merge their checksum
//	         lists, and the update manifest, which is the one place a workflow
//	         executes a
//	         binary from a release archive. `zcd update manifest --sign` hashes
//	         the staged files and signs the list with an ed25519 key; `zcd
//	         update verify` reads that signature back. Neither touches the
//	         proof-of-work engine — `randomx.Available()` is a build-tag
//	         question — and the round trip is the only way to know the manifest
//	         a node will read is one this release can produce. It is the entry
//	         to look hardest at if this list ever grows.
//
// Adding a command that names a built program fails here. If it belongs, add
// it, and say in the pull request what it does with the binary. If it starts
// it, it does not belong, and no wording in a pull request changes that.
func TestNothingInAWorkflowRunsWhatItBuilt(t *testing.T) {
	// Every reviewed command naming a built program. Ordered as the file is.
	want := []command{
		{"cli", "", `host=$(cat dist/SHA256SUMS.binaries | grep 'linux-amd64/zcd$' | cut -d' ' -f1)`},
		{"cli", "", `local=$(sha256sum bin/zcd | cut -d' ' -f1)`},
		{"cli", "", `echo "the linux/amd64 zcd in dist/ does not match a fresh make build"`},
		{"cli", "", `echo "zcd is reproducible: $local"`},
		{"publish", "", `cp staging/zycord-wallet-*/zycord-wallet-* release/`},
		{"publish", "", `cat staging/zycord-wallet-*/SHA256SUMS.desktop     | sort -k2 > release/SHA256SUMS.desktop`},
		{"publish", "", `tar xzf "$cli" --strip-components=1 -C tools --wildcards '*/zcd'`},
		{"publish", "", `test -x tools/zcd || { echo "no zcd was unpacked from $cli" >&2; exit 1; }`},
		{"publish", "", `./tools/zcd update manifest --dir release --version "${GITHUB_REF_NAME}" --sign`},
		{"publish", "", `test -x tools/zcd || { echo "tools/zcd is missing; the signing step did not run" >&2; exit 1; }`},
		{"publish", "", `./tools/zcd update verify --dir release`},
	}

	var got []command
	for _, c := range readWorkflowCommands(t) {
		for _, prog := range builtPrograms {
			if strings.Contains(c.Text, prog) {
				got = append(got, c)
				break
			}
		}
	}

	// Compared as multisets, not as sequences. Moving two job blocks past each
	// other in the YAML is a pure reorder that changes nothing about what runs,
	// and an ordered comparison reported four "command changed" errors for it —
	// four failures naming real commands, none of them a real change. Job and
	// working-directory are already part of each entry's identity, so ordering
	// carries no information that would be lost.
	missing, extra := diff(want, got)
	for _, c := range extra {
		t.Errorf("unreviewed command naming a program this repository builds:\n    %s\n%s", show(c), why)
	}
	for _, c := range missing {
		t.Errorf("a reviewed command is gone from the workflows:\n    %s\n"+
			"If it was deliberately removed or edited, update the list here too — and if\n"+
			"it was NOT, something else is touching a built binary now.", show(c))
	}
}

// diff reports the entries of want absent from got and the entries of got absent
// from want, comparing multisets so a duplicated command is not absorbed.
func diff(want, got []command) (missing, extra []command) {
	count := map[command]int{}
	for _, c := range got {
		count[c]++
	}
	for _, c := range want {
		if count[c] > 0 {
			count[c]--
			continue
		}
		missing = append(missing, c)
	}
	for _, c := range got {
		if count[c] > 0 {
			count[c]--
			extra = append(extra, c)
		}
	}
	return missing, extra
}

// why is the explanation attached to every failure of the list above, because
// the person who trips it is editing YAML and has no reason to have read this
// file's package comment.
const why = "" +
	"A workflow may BUILD the programs in this tree. It may not RUN them.\n" +
	"That is not a style preference: this project's forge account was permanently\n" +
	"suspended, with no appeal, because jobs computed proof-of-work hashes on hosted\n" +
	"runners and the abuse detection read it as mining. Compiling a binary that\n" +
	"contains the engine is fine. Hashing a finished artefact to show that two builds\n" +
	"agree is fine. Starting one is what ended the account.\n" +
	"Everything that runs this tree runs on the developer's machine before the push:\n" +
	"`make ci` for a contributor, plus the release additions in docs/RELEASE.md.\n" +
	"If this command only reads or names an artefact, add it to the list in this test\n" +
	"and say so in the pull request."

// show renders a command the way a reader needs it, spelling out the working
// directory: the same text is a different fact at the repository root and inside
// `desktop/`, and a failure has to say which one it is looking at.
func show(c command) string {
	wd := "at the repository root"
	if c.WorkingDir != "" {
		wd = "working-directory: " + c.WorkingDir
	}
	return "job " + c.Job + " (" + wd + "): " + c.Text
}

// TestTheLocalGateStillRunsTheWholeTree pins the gate itself, at its source.
//
// The property: **`make ci` reaches `test` and `race`, `make test` runs the
// whole tree, and `make race` runs it with `-race` and an explicit `-timeout`.**
//
// This used to be the smaller half of the file: CI ran the suites, and this
// checked that the target CI called still carried the flags. The suites do not
// run in CI any more — nothing does — so `make ci` on a developer's machine
// before the push is now the ONLY thing standing between a defect and `dev`.
// A gate with nothing behind it is worth checking; a gate with everything
// behind it is worth checking more.
//
// The three assertions are the three ways it can go quietly hollow. `ci:` can
// lose a prerequisite. `test:`'s recipe can stop naming the whole tree —
// replacing it with `@echo 'skipping the suite'` once left every assertion in
// this file green. And `race:` can lose its `-timeout`, which is the original
// defect this file was written for: Go's ten-minute default cuts
// `node/mempool`'s eviction suite under the race detector, so the target
// carries an explicit ceiling and a comment explaining the measurement.
//
// The Makefile is read directly, because the recipe is the ground truth here
// and `make -n` would only report it second-hand.
func TestTheLocalGateStillRunsTheWholeTree(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean(makefilePath))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}

	// `make ci` is the command CONTRIBUTING.md and docs/RELEASE.md both name as
	// the gate, and it is a list of prerequisites rather than a recipe — so it
	// is read from the target line, not through recipeFor. A prerequisite
	// silently dropped from here is the whole gate losing a suite while every
	// document that names `make ci` goes on being true.
	gate := regexp.MustCompile(`(?m)^ci:(.*)$`).FindStringSubmatch(string(b))
	if gate == nil {
		t.Fatal("the Makefile has no `ci:` target; it is the local gate both\n" +
			"CONTRIBUTING.md and docs/RELEASE.md tell people to run before pushing")
	}
	for _, prereq := range []string{"test", "race"} {
		if !contains(strings.Fields(gate[1]), prereq) {
			t.Errorf("`make ci` no longer runs `%s`:\n    ci:%s\n"+
				"Nothing runs on a hosted runner any more, so this target is the gate. A\n"+
				"suite dropped from here is a suite nothing runs at all, and every\n"+
				"document that says \"run `make ci`\" stays true while meaning less.",
				prereq, gate[1])
		}
	}

	// The `test` target, pinned for the reason the golden lists exist: naming a
	// target in a document is worth nothing if the target stops running the
	// suite. Replacing `test:`'s recipe with `@echo 'skipping the suite'` left
	// every assertion in this file green — no whole-tree suite running
	// anywhere, reachable from one file over.
	testRecipe, ok := recipeFor(string(b), "test")
	if !ok {
		t.Fatal("the Makefile has no `test:` target; it is the whole-tree suite")
	}
	if !strings.Contains(testRecipe, treeWide) {
		t.Errorf("the test target no longer runs the whole tree:\n%s\n"+
			"No workflow runs a test, so this recipe is the only definition of what the\n"+
			"whole-tree suite is and the only place it is ever run from.",
			testRecipe)
	}

	recipe, ok := recipeFor(string(b), "race")
	if !ok {
		t.Fatal("the Makefile has no `race:` target; `make ci` runs it")
	}
	if !strings.Contains(recipe, "-race") {
		t.Errorf("the race target does not pass -race:\n%s", recipe)
	}
	if !strings.Contains(recipe, "-timeout") {
		t.Errorf("the race target no longer passes an explicit -timeout:\n%s\n"+
			"Go's ten-minute default is not enough for node/mempool's eviction suite under\n"+
			"the race detector — measured at 709s and then 984s on darwin/arm64, and cut at\n"+
			"exactly 600s on the runner that used to run it. Removing the flag restores\n"+
			"the failure this target's explicit ceiling exists to prevent.\n"+
			"The VALUE is deliberately not checked, so that the ceiling can be lowered\n"+
			"again once node/mempool's own runtime leaves room for it.",
			recipe)
	}
}

// parseRuns reads the workflow's steps, split from the file read so that
// TestTheParserSeesTheFormsTheWorkflowUses can exercise it against a fixture
// rather than against whatever syntax the real workflow happens to use today.
//
// It works a step at a time rather than a line at a time. A step is buffered in
// full, its `working-directory:` is found wherever in the step it sits, and only
// then are its commands read. The line-at-a-time version required
// `working-directory:` to appear *above* `run:`, which YAML does not require —
// mapping keys are unordered — so the same step was judged differently depending
// on the order two keys were typed in.
func parseRuns(src string, resolve resolver) []command {
	var cmds []command
	eachStep(src, resolve, func(job, defaultWD string, step []string) {
		cmds = append(cmds, commandsInStep(job, defaultWD, step)...)
	})
	return cmds
}

// eachStep walks the workflow's steps, calling fn with the job and default
// working directory each one runs under. It is shared by parseRuns and by the
// blindness checks, so that those cannot disagree with the reading they are
// meant to be auditing.
func eachStep(src string, resolve resolver, fn func(job, defaultWD string, step []string)) {
	lines := strings.Split(src, "\n")

	inJobs, inSteps := false, false
	job, jobDefaultWD := "", ""
	stepIndent := -1
	var step []string

	flush := func() {
		if len(step) > 0 {
			fn(job, jobDefaultWD, step)
			step = nil
		}
	}

	for _, line := range lines {
		if jobsKey.MatchString(line) {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if m := jobHeader.FindStringSubmatch(line); m != nil {
			flush()
			job, jobDefaultWD, inSteps, stepIndent = m[1], "", false, -1
			continue
		}
		if !inSteps {
			// Before `steps:`, the only thing worth reading is the job's
			// `defaults.run.working-directory`, which applies to every step
			// that does not set its own. Ignoring it made a job using the
			// defaults block — valid, and common on GitHub — misattributed.
			if m := workingDir.FindStringSubmatch(line); m != nil {
				jobDefaultWD = m[1]
			}
			// A job whose body is a `uses:` has no steps of its own: it runs
			// the called workflow's. Its steps are reported under THIS job's
			// name, which is the one the golden list names and the one CI
			// shows. The called workflow supplies its own working directories,
			// so nothing of this job's context carries into it.
			if m := localWorkflowCall.FindStringSubmatch(line); m != nil && resolve != nil {
				if called, ok := resolve(m[1]); ok {
					caller := job
					eachStep(called, resolve, func(_, wd string, step []string) {
						fn(caller, wd, step)
					})
				}
				continue
			}
			if stepsKey.MatchString(line) {
				inSteps = true
			}
			continue
		}
		if m := stepStart.FindStringSubmatch(line); m != nil {
			indent := len(m[1])
			if stepIndent == -1 {
				stepIndent = indent
			}
			if indent == stepIndent {
				flush()
			}
		}
		step = append(step, line)
	}
	flush()
}

// commandsInStep reads one step's lines: its working directory first, wherever
// it appears, then its commands.
func commandsInStep(job, defaultWD string, step []string) []command {
	// A step's first line carries the `- ` that begins it, and in `- run: …`
	// that dash occupies the column the key would otherwise start at. So the
	// dash is replaced by two spaces, putting `run:` at the same indent as the
	// sibling keys of a named step.
	//
	// Without this, a step written without a `name` was invisible: `- run: go
	// test -race -timeout 5m ./...` matched no key and produced no command at
	// all. Unnamed steps are ordinary GitHub — this workflow already has several
	// unnamed `- uses:` steps — so it is drift, not an adversary.
	//
	// Only the FIRST line is normalised. A `- ` deeper in the step belongs to a
	// nested list or to block-scalar content, and rewriting those would change
	// the text of the very commands being compared.
	step = append([]string(nil), step...)
	if len(step) > 0 {
		if m := stepStart.FindStringSubmatch(step[0]); m != nil {
			step[0] = m[1] + "  " + step[0][len(m[1])+2:]
		}
	}

	wd := defaultWD
	for _, line := range step {
		if m := workingDir.FindStringSubmatch(line); m != nil {
			wd = m[1]
			break
		}
	}

	// A step's own keys sit two spaces in from its `- `. Anything deeper is a
	// nested mapping — a composite action's `with:` block can carry a `run:`
	// input of its own — and reading those as commands churns the golden list
	// with strings that are data rather than commands CI runs.
	keyIndent := -1
	if len(step) > 0 {
		keyIndent = len(step[0]) - len(strings.TrimLeft(step[0], " "))
	}

	var cmds []command
	for i := 0; i < len(step); i++ {
		m := runLine.FindStringSubmatch(step[i])
		if m == nil {
			continue
		}
		indent, rest := len(m[1]), m[2]
		if keyIndent >= 0 && indent != keyIndent {
			continue
		}
		bs := blockScalar.FindStringSubmatch(rest)
		if bs == nil {
			if rest != "" {
				cmds = append(cmds, command{Job: job, WorkingDir: wd, Text: rest})
			}
			continue
		}
		body, next := blockBody(step, i, indent)
		i = next
		for _, text := range splitCommands(body, bs[1] == ">") {
			cmds = append(cmds, command{Job: job, WorkingDir: wd, Text: text})
		}
	}
	return cmds
}

// blockBody returns the lines belonging to a block scalar introduced at index i,
// and the index of its last line. The block is the following lines indented
// further than the `run:` key itself; blank lines belong to it.
func blockBody(step []string, i, indent int) ([]string, int) {
	var body []string
	for i+1 < len(step) {
		next := step[i+1]
		if strings.TrimSpace(next) != "" &&
			len(next)-len(strings.TrimLeft(next, " ")) <= indent {
			break
		}
		body = append(body, next)
		i++
	}
	return body, i
}

// splitCommands turns a block scalar's lines into the commands it actually runs.
//
// Three joins happen here, and the first two closed blind spots found by
// mutating the real workflow. The first version treated every physical line as
// one command, which is right only for a literal block of single-line commands.
//
//	backslash   `go test -race \` / `  -timeout 5m ./...` is ONE command that
//	            the line-at-a-time reader saw as two. Nothing clever: it is how
//	            a long command gets written when it stops fitting.
//
//	folded      `run: >` means the lines ARE one command — that is the whole
//	            meaning of the indicator. The fixture that was supposed to pin
//	            folded blocks used a one-line body, so it could not see this.
//
//	comments    a shell `#` line is prose, not a command, for the reason
//	            recipeFor strips Make recipe comments.
func splitCommands(body []string, folded bool) []string {
	var out []string
	var cur []string
	end := func() {
		if len(cur) > 0 {
			out = append(out, strings.Join(cur, " "))
			cur = nil
		}
	}
	for _, line := range body {
		text := strings.TrimSpace(line)
		if text == "" {
			end() // a blank line ends a folded paragraph and a continuation.
			continue
		}
		if strings.HasPrefix(text, "#") {
			end()
			continue
		}
		if strings.HasSuffix(text, `\`) {
			cur = append(cur, strings.TrimSpace(strings.TrimSuffix(text, `\`)))
			continue
		}
		cur = append(cur, text)
		if !folded {
			end()
		}
	}
	end()
	return out
}

// TestTheParserSeesTheFormsTheWorkflowUses is the anti-vacuity test for the
// reading apparatus.
//
// The property: **parseRuns reports the command a step runs, with the job and
// working directory it runs under, for every YAML form this workflow uses.**
//
// The assertions above all read the real workflow, so they can only ever observe
// the syntax that file happens to use today. That is how four separate blind
// spots shipped: a `run: |` block whose body was never read, a `\` continuation
// split into two half-commands, a folded body split the same way, and a job id
// containing `_` that made the parser attribute one job's steps to another.
// Each of them let a whole-tree race command sit in the file, at a five-minute
// timeout, with every test here green.
//
// So the parser is exercised against a fixture carrying every form at once. A
// blind spot fixed without being pinned is a blind spot moved.
func TestTheParserSeesTheFormsTheWorkflowUses(t *testing.T) {
	const fixture = `on:
  push:
    branches: [main]
  pull_request:
jobs:
  build:
    steps:
      - name: single line
        run: make test
      - name: literal block
        run: |
          # a shell comment is prose, not a command
          go test -race ./...
          echo done
      - name: a backslash continues one command onto the next line
        run: |
          go test -race \
            -timeout 5m ./...
      - name: chomped block
        run: |-
          go vet ./...
      - name: a folded block is ONE command, however many lines it occupies
        run: >
          go test -race -timeout 5m
          ./...
      - name: after the block
        run: make race
      - run: go vet -tags x ./...
      - run: |
          go test -tags y ./...
  windows:
    steps:
      - name: inline
        run: go test ./...
  reproducible_check:
    steps:
      - name: an underscore is a legal job id, and this job is not windows
        run: go test -race ./...
  defaulted:
    defaults:
      run:
        working-directory: desktop
    steps:
      - name: the job default applies
        run: go test -tags desktop ./...
  desktop:
    steps:
      - name: no working directory, so the repository root
        run: go test ./...
      - name: keys are unordered, so this one sits BELOW its run
        run: go test -tags desktop ./...
        working-directory: desktop
      - name: the scope does not leak to the next step
        run: go test ./...
  platform:
    uses: ./.github/workflows/reusable.yml
  published:
    uses: some/action@v1
`
	// The workflow `platform` calls. Its own job id differs from the calling
	// job's on purpose: the commands must arrive under the CALLER's name, since
	// that is the one the golden list names and the one CI shows.
	const reusable = `on:
  workflow_call:
jobs:
  windows:
    steps:
      - name: at the repository root
        run: go test ./...
      - name: in the separate module
        working-directory: desktop
        run: go test -tags desktop ./...
`
	resolve := func(ref string) (string, bool) {
		if ref != "./.github/workflows/reusable.yml" {
			return "", false
		}
		return reusable, true
	}
	want := []command{
		{"build", "", "make test"},
		{"build", "", "go test -race ./..."},
		{"build", "", "echo done"},
		// The backslash join: one command, not two half-commands.
		{"build", "", "go test -race -timeout 5m ./..."},
		{"build", "", "go vet ./..."},
		// The folded join: `>` means these lines ARE one command.
		{"build", "", "go test -race -timeout 5m ./..."},
		{"build", "", "make race"},
		// Unnamed steps. The `- ` sits where the key would, and both forms
		// produced no command at all before it was normalised away.
		{"build", "", "go vet -tags x ./..."},
		{"build", "", "go test -tags y ./..."},
		{"windows", "", "go test ./..."},
		// Not attributed to `windows`, which is what an unmatched job header
		// used to do.
		{"reproducible_check", "", "go test -race ./..."},
		// defaults.run.working-directory, with no per-step key.
		{"defaulted", "desktop", "go test -tags desktop ./..."},
		{"desktop", "", "go test ./..."},
		// The key sits below its `run:`, which YAML permits.
		{"desktop", "desktop", "go test -tags desktop ./..."},
		// A working-directory belongs to ONE step and does not leak forward.
		{"desktop", "", "go test ./..."},
		// A job that is a call to a workflow in this repository. Its steps are
		// reported under `platform`, the calling job, not under `windows`, the
		// job id inside the called file.
		{"platform", "", "go test ./..."},
		{"platform", "desktop", "go test -tags desktop ./..."},
		// `published` contributes nothing: a `uses:` outside this repository
		// names an action, which has no steps to read here.
	}

	got := parseRuns(fixture, resolve)
	if len(got) != len(want) {
		t.Fatalf("got %d commands, want %d:\ngot  %+v\nwant %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	// The block indicator itself must never be reported as a command.
	for _, c := range got {
		if blockScalar.MatchString(c.Text) {
			t.Errorf("the parser reported a block indicator %q as a command", c.Text)
		}
	}
}

// recipeFor returns the COMMAND lines of a Make target: the tab-indented lines
// following `name:`, with the recipe's own comments removed.
//
// Dropping the comments is not tidiness, it is the whole correctness of this
// helper. A Make recipe comments with a tab followed by `#`, and `race:`'s
// comment block spends sixteen lines explaining itself. A version that returned
// those comments let an assertion match the *prose about a flag* instead of the
// flag. Measured, on this Makefile, with the comments included:
//
//	delete `-timeout 30m` from the command, search for "-timeout"  →  not found
//	delete `-race`        from the command, search for "-race"     →  FOUND
//
// So it was the `-race` assertion that was vacuous, not the timeout one: the
// prose writes "an explicit timeout" without the hyphen, but it does write
// `-race` when quoting a measurement, and that one backticked mention satisfied
// the check after the flag itself was gone.
func recipeFor(makefile, name string) (string, bool) {
	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, name+":") {
			continue
		}
		var recipe []string
		for _, next := range lines[i+1:] {
			// A blank line does not end a recipe — GNU make ignores it — and
			// treating it as a terminator truncated the recipe at the blank,
			// firing both assertions on a target that satisfies both. That is
			// the false positive CONTRIBUTING.md calls worse than silence.
			if strings.TrimSpace(next) == "" {
				continue
			}
			if !strings.HasPrefix(next, "\t") {
				break // the recipe ends at the first line that is not tab-indented.
			}
			if strings.HasPrefix(strings.TrimSpace(next), "#") {
				continue // a recipe comment: prose, not a command.
			}
			recipe = append(recipe, next)
		}
		return strings.Join(recipe, "\n"), true
	}
	return "", false
}
