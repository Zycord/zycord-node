package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReexecEnv marks a process that has already restarted into a new binary.
//
// An environment variable rather than a file, because its lifetime is exactly
// one process lineage, which is exactly the lifetime of the hazard. A file would
// have to be cleaned up, and would make an operator's own manual restart after a
// failed update look like a loop.
const ReexecEnv = "ZYCORD_UPDATE_REEXEC"

// Install is one prepared replacement, ready to apply.
type Install struct {
	// Target is the running executable.
	Target Target
	// Binaries maps a destination path to the extracted file that will replace
	// it. Both CLI binaries when both are present.
	Binaries map[string]string
	// Version is what the manifest named.
	Version string
}

// CLIBinaries are the two names a CLI archive carries.
const (
	BinaryNode = "zycordd"
	BinaryCLI  = "zcd"
)

// PlanInstall works out what would be replaced, and refuses early if it may not
// be.
//
// **Both binaries, as one change.** The archive ships zcd and zycordd and they
// are one release. A node at v0.2.0 beside a zcd at v0.1.1 is a configuration
// nobody chose and nobody tests — and zcd builds certificates against core/'s
// rules through wallet/session, so a skewed pair is how an operator gets a
// certificate their own node refuses with no reason to suspect the CLI.
//
// The sibling is taken only when it is in the same directory under exactly the
// expected name, and it must pass the same guards. There is no PATH search:
// hunting for a second binary to overwrite is how an updater overwrites
// something it was never installed as.
//
// No version check is run on the sibling, deliberately. Reading it would mean
// executing a binary that is about to be replaced, which can hang; same
// directory plus exact name is one install by every convention this project
// ships, and being wrong costs "it got upgraded to the release it belongs to"
// rather than anything worse.
func PlanInstall(t Target, extracted map[string]string, version, current string) (*Install, error) {
	if r := Guard(t, current); r != nil {
		return nil, r
	}
	in := &Install{Target: t, Version: version, Binaries: map[string]string{}}

	// The running binary first, so a message can always name it.
	stem := BinaryStem(t.Name)
	src, ok := extracted[stem]
	if !ok {
		return nil, fmt.Errorf("update: the archive holds no %s to replace this binary with", stem)
	}
	in.Binaries[t.Resolved] = src

	other := BinaryCLI
	if stem == BinaryCLI {
		other = BinaryNode
	}
	if src, ok := extracted[other]; ok {
		path := t.Sibling(other)
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			sibling := Target{Path: path, Resolved: path, Dir: filepath.Dir(path), Name: filepath.Base(path)}
			if r := Guard(sibling, current); r == nil {
				in.Binaries[path] = src
			}
		}
	}
	return in, nil
}

// Apply replaces every binary in the plan, and rolls back if the second fails.
//
// **This is not atomic across the pair, and saying so plainly is better than
// implying otherwise.** Two renames cannot be made one. What IS guaranteed:
// every replacement is written and checked before any rename happens, the
// renames run back to back, and a failure part-way restores what was already
// changed. A failure leaves a matched OLD pair, never a mismatched one.
func (in *Install) Apply() (backups map[string]string, err error) {
	backups = map[string]string{}
	done := make([]string, 0, len(in.Binaries))

	// The running binary last, so if anything is going to fail it fails before
	// the executable underneath this process changes.
	order := make([]string, 0, len(in.Binaries))
	for dst := range in.Binaries {
		if dst != in.Target.Resolved {
			order = append(order, dst)
		}
	}
	order = append(order, in.Target.Resolved)

	for _, dst := range order {
		backup, rerr := replaceBinary(dst, in.Binaries[dst])
		if rerr != nil {
			// Undo what already landed, so the pair is matched even in failure.
			for _, prev := range done {
				if uerr := restoreBinary(prev); uerr != nil {
					return backups, fmt.Errorf("update: %s could not be replaced (%w) and %s could not be "+
						"rolled back (%v); the kept copy is at %s", dst, rerr, prev, uerr, backups[prev])
				}
			}
			return nil, rerr
		}
		backups[dst] = backup
		done = append(done, dst)
	}
	return backups, nil
}

// Rollback restores the kept copy of every binary this install replaced.
func (in *Install) Rollback() error {
	var errs []error
	for dst := range in.Binaries {
		if err := restoreBinary(dst); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RestartInto re-executes the freshly installed binary.
//
// The loop guard goes into the environment here: the new image reads it and
// knows not to check again this run. Set to the version that was installed, so
// the two failure shapes are distinguishable — a value equal to the running
// version means the update worked, and a value that differs means the exec
// landed on a binary that is not the one just installed, which must NOT be
// retried.
func (in *Install) RestartInto() error {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, ReexecEnv+"=") {
			env = append(env, kv)
		}
	}
	env = append(env, ReexecEnv+"="+in.Version)
	// Target.Path, not Resolved: if the binary was reached through a symlink the
	// operator maintains, the link is what they mean by "the program", and it
	// still points at the file just replaced.
	return Reexec(in.Target.Path, os.Args, env)
}

// RestartedInto reports the version this process was restarted into, if any.
func RestartedInto() string { return os.Getenv(ReexecEnv) }

// RestartKeepsThePID reports whether a restart is invisible to a supervisor on
// this platform. Messages use it rather than claiming the Unix behaviour
// everywhere.
func RestartKeepsThePID() bool { return reexecReplacesTheProcess }
