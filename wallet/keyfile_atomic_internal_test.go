package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// The crash-recovery suite for the write-in-place defect.
//
// A key file used to be written with a direct O_CREATE|O_EXCL open to its
// final path, so any crash between the open and the page cache flushing left
// a torn file sitting exactly where a recovery attempt needed to write —
// and O_EXCL then refused that attempt. The fix (writeFileNoClobber) never
// creates anything at the destination until a fully-written, fsynced temp
// file is published under it in one filesystem operation, so these tests
// drive a crash right up to that boundary and prove the destination is
// untouched either side of it.
//
// They cover both publish paths: the hard link used where the filesystem has
// them, and the rename used where it does not — FAT32 and exFAT, which is
// where a cold-storage key backup actually lives, so it is the path that
// least deserves to be the untested one.
//
// The crash is injected deterministically through crashAfterWrite rather
// than by killing a real process, the same choice node/storage's
// torture_test.go makes for the same reason: it can be aimed exactly at the
// moment that matters and it reproduces the same way every run.

// TestWriteFileNoClobberCrashDuringWriteNeverTouchesTheDestination is the
// crash-simulation test for the write-in-place defect.
func TestWriteFileNoClobberCrashDuringWriteNeverTouchesTheDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")

	crashErr := errors.New("simulated crash")
	old := crashAfterWrite
	crashAfterWrite = func() error { return crashErr }
	t.Cleanup(func() { crashAfterWrite = old })

	err := writeFileNoClobber(path, []byte("first attempt, never completes"))
	if !errors.Is(err, crashErr) {
		t.Fatalf("expected the simulated crash to surface, got %v", err)
	}

	// The whole point of the fix: nothing was ever created at path.
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("path must not exist after a crash mid-write, got stat error %v", statErr)
	}

	// No litter either: writeFileNoClobber's own cleanup removes the aborted
	// temp file on any error return, crashAfterWrite included, because this
	// simulated crash still runs Go's deferred cleanup in the test process
	// (a real kill -9 would not — see the stale-litter test below for that
	// case).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected the directory empty after a crashed write, found %v", entries)
	}

	// Recovery: re-running to the exact same path, with no cleanup step in
	// between, must simply work. Under the old O_CREATE|O_EXCL write this is
	// precisely what a torn file at path would have refused (ErrBadPassphrase on
	// a file whose passphrase the user knew — the failure mode the write-in-place
	// defect produces).
	crashAfterWrite = nil
	want := []byte("second attempt, completes")
	if err := writeFileNoClobber(path, want); err != nil {
		t.Fatalf("recovery write failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("recovered file contains %q, want %q", got, want)
	}
}

// TestWriteFileNoClobberRefusesAnExistingDestination is the property the fix
// had to keep, not just the one it had to add: a real, complete file at path
// (exactly the case a crash can no longer produce, per the test above) must
// still refuse to be overwritten, the same as O_CREATE|O_EXCL did.
func TestWriteFileNoClobberRefusesAnExistingDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")

	if err := writeFileNoClobber(path, []byte("original")); err != nil {
		t.Fatal(err)
	}

	err := writeFileNoClobber(path, []byte("attempted overwrite"))
	if err == nil {
		t.Fatal("expected an error; a second write to the same path must not succeed")
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("expected an error wrapping fs.ErrExist, got %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("the original file was modified: got %q", got)
	}

	// And nothing was left behind from the refused attempt either.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly the original file, found %v", entries)
	}
}

// TestWriteFileNoClobberSurvivesStaleTempLitter covers the one artifact a
// real crash (unlike the deferred-cleanup one simulated above) can leave
// behind: an orphaned "<name>.tmp-*" file from a process that never got to
// run its own cleanup. It must never block a later save — the random suffix
// os.CreateTemp picks guarantees no collision, and the destination-existence
// check is against path, not against anything matching that pattern.
func TestWriteFileNoClobberSurvivesStaleTempLitter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")

	litter := filepath.Join(dir, "wallet.json.tmp-stale-from-a-real-kill-9")
	if err := os.WriteFile(litter, []byte("half a key file"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeFileNoClobber(path, []byte("the real thing")); err != nil {
		t.Fatalf("stale litter must not block a fresh save: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the real thing" {
		t.Fatalf("got %q", got)
	}
}

// The two mechanisms a publish can have used, as publishSpy reports them.
// They are named by what they do to the temporary name rather than by tier
// number, because which tier runs is a property of the filesystem and not of
// the row a test configured: forcing tier 2 on a volume without hard links
// falls through to tier 3, and then it is a rename that published. That is not
// a corner case — os.Link fails with "operation not supported" on both FAT
// drivers, measured on real exFAT and FAT32 volumes, so on the filesystems
// this file cares most about the tier-2 row is always judged as a rename.
type publishedVia string

const (
	publishedByRename publishedVia = "a rename"
	publishedByLink   publishedVia = "a hard link"
)

// publishMarker is appended to the prepared inode through a descriptor held
// across the publish, and then removed again. See markerReachesTheDestination.
var publishMarker = []byte("<<the inode that was prepared>>")

// publishSpy observes and steers writeFileNoClobber's publish step.
//
// Three things it records bear on the one question this file exists to answer —
// did the publish hand over the fsynced temp inode, or re-write its bytes at
// the destination? They are not equally strong, and the difference matters,
// because on exFAT only one of them is available:
//
//  1. **markerVisible** — the real answer, and the only one that needs nothing
//     from the filesystem but a working descriptor. See the field.
//  2. **prepared**, compared with os.SameFile — the cheap answer, unavailable
//     wherever a rename does not preserve st_ino.
//  3. **tempNameSurvived** — a statement about the *mechanism*, not about the
//     inode, and explicitly not sufficient on its own. See the field.
type publishSpy struct {
	// prepared is a stat of the temp file taken at the moment publishing began.
	// Tests compare it with os.SameFile against whatever ends up at the
	// destination. It is a true identity comparison where it works at all, and on
	// exFAT it does not work: identity is not preserved across the rename a
	// publish performs, for two different reasons on the two drivers measured,
	// both written up on probePublishObservability.
	prepared os.FileInfo

	// publishedBy names the mechanism that actually returned nil, and
	// tempNameSurvived says whether the temporary name still existed at that
	// instant — observed inside the publish seam, because
	// writeFileNoClobber's deferred cleanup removes the name on the way out
	// whatever the publish did.
	//
	// Read what this pair does and does not say, because an earlier version of
	// this file read more into it and shipped a hole. A rename consumes the
	// temporary name and a re-write at the destination leaves it, so the pair
	// catches the re-write that abandons the temp file — but a re-write that
	// *removes* the temp file afterwards consumes the name too, and this pair
	// cannot tell that from a rename. That shape is not exotic: it is what every
	// os.Rename cross-device copy-fallback looks like. So this is a statement
	// about which mechanism ran, useful for a precise message and for pinning
	// that tier 3 did not quietly become a link, and it is never the assertion
	// that stands between this package and the write-in-place defect.
	publishedBy      publishedVia
	tempNameSurvived bool

	// markerVisible is the assertion that does stand there. With a descriptor
	// held on the temp inode across the publish, a marker written through it
	// afterwards appears at the destination if and only if the destination
	// *is* that inode — which is exactly the question, asked without st_ino,
	// without hard links and without a surviving name. Measured to
	// discriminate correctly on real exFAT, FAT32 and APFS volumes; see
	// probePublishObservability, which is what decides whether this channel
	// can be used here at all, and markerErr for when the check itself broke.
	markerVisible bool
	markerErr     error

	// What probePublishObservability measured about this filesystem, and the
	// descriptor it licensed. Nil held means the marker channel is not armed:
	// either the test did not ask for it, or the probe said this platform
	// cannot hold a descriptor across a rename.
	identityIsExpressible bool
	markerChannelWorks    bool
	held                  *os.File
	heldSize              int64
}

func (s *publishSpy) preparedFile(t *testing.T) os.FileInfo {
	t.Helper()
	if s.prepared == nil {
		t.Fatal("the publish step was never reached, so no temp file was captured")
	}
	return s.prepared
}

// publishMechanism reports which mechanism published, failing if none did.
func (s *publishSpy) publishMechanism(t *testing.T) publishedVia {
	t.Helper()
	if s.publishedBy == "" {
		t.Fatal("no publish mechanism reported success, so nothing about the publish was observed")
	}
	return s.publishedBy
}

// watchTheTempInode arms the marker channel for the write about to be made to
// path, and measures what this filesystem can show about a publish at all. Call
// it after the destination directory exists and before writeFileNoClobber.
//
// It is opt-in rather than automatic in forcePublishTiers for two reasons.
// Holding a descriptor across a publish is exactly the thing this package's
// production code is careful not to do, so no test should do it unless it is
// the subject; and the probe leaves and removes files in the destination
// directory, which the tests that assert on that directory's exact contents
// would notice.
func (s *publishSpy) watchTheTempInode(t *testing.T, path string) {
	t.Helper()
	s.identityIsExpressible, s.markerChannelWorks = probePublishObservability(t, path)
}

// markerReachesTheDestination appends publishMarker to whatever inode held
// refers to, asks whether it appeared at dst, and then truncates it away again
// so the published key file is left byte-for-byte as the publish left it.
//
// If the destination is a different file — the write-in-place defect, in
// either of its shapes — the marker lands in the abandoned temp inode and dst
// never shows it.
//
// The destination is read *before* the marker is written as well as after, and
// the answer is the transition from absent to present rather than the presence
// alone. Presence alone is a statement about the destination's bytes, and a
// payload that already contained publishMarker would satisfy it whichever
// inode was there — reported by the review, and confirmed: writing the marker
// string into the main test's fixture made all five rows pass on exFAT against
// a live write-in-place defect. The string is distinctive and appears in
// exactly one place, so it takes a deliberate edit; asking for the transition
// removes the class rather than relying on nobody making it. A destination
// that already holds the marker is reported as an error, not as a false: it
// means this check cannot mean anything here, which is a different thing from
// "the bytes were re-written".
func markerReachesTheDestination(held *os.File, size int64, dst string) (bool, error) {
	before, err := os.ReadFile(dst)
	if err != nil {
		return false, err
	}
	if bytes.Contains(before, publishMarker) {
		return false, fmt.Errorf("the destination already contains %q before the marker was "+
			"written, so finding it there afterwards would prove nothing about which inode "+
			"the destination is; a fixture must not contain the marker string", publishMarker)
	}
	if _, err := held.WriteAt(publishMarker, size); err != nil {
		return false, err
	}
	defer held.Truncate(size)
	after, err := os.ReadFile(dst)
	if err != nil {
		return false, err
	}
	return bytes.Contains(after, publishMarker), nil
}

// forcePublishTiers installs spies on all three publish seams so a test can
// (a) drive the lower tiers on a filesystem that supports the higher ones and
// would otherwise never reach them, (b) learn which file was handed to the
// publish step, (c) run atPublish at that exact moment, and (d) learn how the
// publish that succeeded left the temporary name behind it.
//
// Passing a non-nil error for a tier makes that tier fail with it; nil runs
// the real one. The errors the tests pass are the ones measured against real
// volumes: EPERM is what Linux's vfat and exfat drivers return when asked to
// hard-link, ENOTSUP is what macOS's msdos driver returns for the same thing.
//
// atPublish (nil for most tests) fires once, on the first publish attempt,
// after writeFileNoClobber's top-of-function courtesy check has already
// passed. That is the only way to test what the publish step itself does
// about an occupied destination: plant the destination from in there and the
// refusal has to come from the real syscall, because the cheap pre-check has
// already been and gone.
func forcePublishTiers(t *testing.T, exclusiveErr, linkErr error, atPublish func()) *publishSpy {
	t.Helper()

	spy := &publishSpy{}
	fired := false
	enter := func(tmpPath string) {
		if fired {
			return
		}
		fired = true
		if fi, err := os.Stat(tmpPath); err == nil {
			// The self-comparison is not a tautology and must not be
			// deleted as one: on Windows it is what makes spy.prepared
			// usable at all.
			//
			// os.SameFile compares a volume serial and a file index. On unix os.Stat
			// fills those in eagerly (st_dev, st_ino), so a FileInfo keeps its identity
			// after the file is renamed away. On Windows os.Stat records only the
			// *path* and loads the identity lazily, on the first SameFile call, by
			// reopening that path (os.(*fileStat).loadFileId) — and by the time the
			// assertion runs, publishing has consumed tmpPath, so the reopen fails and
			// SameFile answers false for the file against itself. Measured: without
			// this line every tier of TestWriteFileNoClobberPublishesTheTempFile fails
			// on windows/amd64 claiming the write-in-place defect had returned.
			//
			// Calling SameFile here, while tmpPath still exists, forces
			// that load and caches the result, so the comparison after
			// the publish is against a real identity rather than a dead
			// path. It costs one extra stat on unix, where the id is
			// already loaded and this returns immediately.
			//
			// It does not weaken what the assertion proves. A re-write at
			// the final path is a different file with a different index,
			// and still compares false — verified directly rather than
			// assumed, in TestPreparedIdentitySurvivesPublishing below.
			os.SameFile(fi, fi)
			spy.prepared = fi
			if spy.markerChannelWorks {
				// Only ever opened after probePublishObservability has shown,
				// on this filesystem and this platform, that a descriptor held
				// across a rename neither blocks it nor stops following the
				// file. Nothing here perturbs a publish that was not first
				// measured to tolerate it.
				if held, err := openTempInodeForMarker(tmpPath); err != nil {
					spy.markerErr = err
				} else {
					spy.held, spy.heldSize = held, fi.Size()
					t.Cleanup(func() { held.Close() })
				}
			}
		}
		if atPublish != nil {
			atPublish()
		}
	}

	// observe runs the instant a real mechanism returned nil — the only moment
	// the temporary name says anything, and the natural moment to ask the
	// descriptor its question too. See publishSpy.
	observe := func(mechanism publishedVia, tmpPath, dstPath string) {
		spy.publishedBy = mechanism
		_, err := os.Lstat(tmpPath)
		spy.tempNameSurvived = err == nil
		if spy.held != nil {
			spy.markerVisible, spy.markerErr = markerReachesTheDestination(spy.held, spy.heldSize, dstPath)
		}
	}

	oldExclusive, oldLink, oldRename := publishExclusive, publishByLink, publishByRename
	publishExclusive = func(oldpath, newpath string) error {
		enter(oldpath)
		if exclusiveErr != nil {
			return exclusiveErr
		}
		if err := oldExclusive(oldpath, newpath); err != nil {
			return err
		}
		observe(publishedByRename, oldpath, newpath)
		return nil
	}
	publishByLink = func(oldpath, newpath string) error {
		enter(oldpath)
		if linkErr != nil {
			return linkErr
		}
		if err := oldLink(oldpath, newpath); err != nil {
			return err
		}
		observe(publishedByLink, oldpath, newpath)
		return nil
	}
	// Tier 3 takes no forced error: it is the last resort, so making it fail
	// would exercise an error message rather than a publish. It is wrapped
	// only to be observed.
	publishByRename = func(oldpath, newpath string) error {
		if err := oldRename(oldpath, newpath); err != nil {
			return err
		}
		observe(publishedByRename, oldpath, newpath)
		return nil
	}
	t.Cleanup(func() {
		publishExclusive, publishByLink, publishByRename = oldExclusive, oldLink, oldRename
	})
	return spy
}

// probePublishObservability measures which of the two identity-bearing
// questions the filesystem holding path can answer about a publish, by
// performing the publish's rename itself and watching:
//
//   - identity — does os.SameFile still recognise the file after the rename?
//   - marker — does a descriptor held across the rename survive it and keep
//     referring to the renamed file, so a write through it can be seen at the
//     new name?
//
// Neither is assumed and neither is derived from a build tag, because the
// property is the filesystem's rather than the platform's and the answers do
// not line up with any static rule. Measured directly:
//
//   - **Windows** derives a file's identity from the location of its directory
//     entry, and exFAT stores a name in 15-character chunks, so a rename that
//     changes how many entries the name needs moves the entry and changes the
//     id. Measured on windows/amd64: "p.tmp" to "p" preserves it,
//     "wallet.json.tmp-4107390348" to "wallet.json" does not — and the second
//     is the only shape os.CreateTemp can produce, so on Windows + exFAT the
//     identity answer is *always* no.
//   - **macOS** (26.5, the fskit exFAT and msdos drivers) does not care about
//     the name at all. It takes st_ino from the file's first data cluster,
//     which a rename never touches — but an *empty* file has no first cluster
//     and it synthesizes one from the directory entry instead, which every
//     rename moves. Measured on real volumes: a 1-byte file survives
//     "wallet.json.tmp-4107390348" to "wallet.json" with st_ino unchanged,
//     while a 0-byte file loses it even renaming "aaa" to "bbb".
//
// So the probe mirrors the publish it stands in for, in both respects that were
// measured to matter. The source is made by os.CreateTemp with the very pattern
// writeFileNoClobber uses, and the destination has the same *length* as the
// real destination — which is all the exFAT arithmetic depends on, since a name
// costs one directory entry per 15 characters and equal lengths cost equal
// entries. Both names are derived from path rather than written out, so the
// mirror cannot drift if the key file is ever called something else. And the
// probe file is written to before it is renamed, because the temp file a real
// publish renames always holds a key file and is never empty; a probe left at
// zero bytes reports "not expressible" on macOS exFAT, where the assertion in
// fact holds perfectly well.
//
// The marker pass is measured, not assumed, for a reason with teeth on the
// platform this issue is about: Windows refuses to rename a file whose open
// handle did not grant FILE_SHARE_DELETE, so a descriptor held across a publish
// can turn a working publish into ERROR_SHARING_VIOLATION. The pass renames its
// own probe file with a descriptor open, so if that is what happens here it is
// this probe that meets it, before any test holds a descriptor across a real
// publish. A failed rename is an answer — "no marker channel here" — not an
// error.
//
// Neither pass is a mirror of the bug it stands next to: both drive os.Rename
// directly and neither touches writeFileNoClobber, so no regression in the
// publish path can make this report "unavailable" and silence an assertion.
// Errors that are the environment's rather than the filesystem's answer — no
// space, a read-only directory — fail the test, and say that the probe could
// not be run rather than reporting something about identity.
func probePublishObservability(t *testing.T, path string) (identity, marker bool) {
	t.Helper()
	dir, base := filepath.Dir(path), filepath.Base(path)
	// Same length as the real destination, and it cannot collide with it.
	dst := filepath.Join(dir, strings.Repeat("p", len(base)))

	newProbe := func() string {
		f, err := os.CreateTemp(dir, base+".tmp-*")
		if err != nil {
			t.Fatalf("the publish-observability probe could not be created in %s, so nothing was measured: %v", dir, err)
		}
		if _, err := f.Write([]byte("not empty")); err != nil {
			f.Close()
			t.Fatalf("the publish-observability probe could not be written in %s, so nothing was measured: %v", dir, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("the publish-observability probe could not be closed in %s, so nothing was measured: %v", dir, err)
		}
		return f.Name()
	}

	// Pass 1: identity across the rename, with no descriptor involved.
	src := newProbe()
	defer os.Remove(src)
	defer os.Remove(dst)
	before, err := os.Stat(src)
	if err != nil {
		t.Fatalf("the publish-observability probe could not be stat'd, so nothing was measured: %v", err)
	}
	// The same forced load forcePublishTiers performs, at the same moment:
	// while the source name still exists. Without it this measures Go's lazy
	// identity load rather than the filesystem's behaviour.
	os.SameFile(before, before)
	if err := os.Rename(src, dst); err != nil {
		t.Fatalf("the publish-observability probe could not rename %s, so nothing was measured: %v", src, err)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("the publish-observability probe could not stat its destination, so nothing was measured: %v", err)
	}
	identity = os.SameFile(before, after)
	os.Remove(dst)

	// Pass 2: a descriptor held across the rename. A fresh probe file, so the
	// two passes cannot interfere.
	src = newProbe()
	defer os.Remove(src)
	held, err := openTempInodeForMarker(src)
	if err != nil {
		// Not an environment failure: a platform that will not hand out this
		// descriptor simply has no marker channel.
		t.Logf("no marker channel here: the prepared file cannot be held open (%v)", err)
		return identity, false
	}
	defer held.Close()
	size := int64(len("not empty"))
	if err := os.Rename(src, dst); err != nil {
		// The Windows sharing violation, if that is what this platform does.
		t.Logf("no marker channel here: a rename fails while the file is held open (%v)", err)
		return identity, false
	}
	visible, err := markerReachesTheDestination(held, size, dst)
	if err != nil {
		t.Logf("no marker channel here: the marker could not be written or read back (%v)", err)
		return identity, false
	}
	return identity, visible
}

// publishTiers names the three publish mechanisms writeFileNoClobber tries,
// with the errors needed to force each one. Every behavioural test below runs
// against all three, because the whole point of having three is that a user on
// an unmeasured filesystem gets a defined degradation rather than a failure —
// and an untested degradation path is exactly how the write-in-place defect
// survived three rounds of review inside the fallback that was supposed to fix
// it.
func publishTiers() map[string]struct{ exclusiveErr, linkErr error } {
	eperm := &os.LinkError{Op: "link", Err: syscall.EPERM}
	enotsup := &os.LinkError{Op: "link", Err: syscall.ENOTSUP}
	return map[string]struct{ exclusiveErr, linkErr error }{
		"tier 1: exclusive rename":                    {nil, nil},
		"tier 2: hard link":                           {errors.New("no exclusive rename here"), nil},
		"tier 3: checked rename (Linux vfat/exfat)":   {errors.New("no exclusive rename here"), eperm},
		"tier 3: checked rename (macOS msdos)":        {errors.New("no exclusive rename here"), enotsup},
		"tier 3: checked rename (unclassified fault)": {errors.New("no exclusive rename here"), errors.New("some link failure nobody enumerated")},
	}
}

// TestWriteFileNoClobberPublishesTheTempFile is the test that actually pins
// the mechanism, and the one the rest of this file cannot substitute for.
//
// Every other assertion here — the content is right, the destination is absent
// after a crash, an existing file is refused — is equally true of an
// implementation that throws the temp file away and writes the bytes straight
// to the destination under O_CREATE|O_EXCL. That implementation IS the
// write-in-place defect. It was what this package did before
// writeFileNoClobber, it is what an earlier attempt at the FAT32 fallback
// reintroduced, and no test in this suite noticed, because crashAfterWrite
// fires before the publish step and so can never reach it.
//
// The question is therefore always the same — *is the file at the destination
// the inode that was fsynced off to the side?* — and the whole difficulty is
// that the obvious way to ask it does not work everywhere. os.SameFile asks it
// directly and cannot be used on exFAT, where a publish's rename does not
// preserve a file's identity (see probePublishObservability for the two
// separate driver mechanisms behind that). So the test asks it two ways and
// requires at least one of them to have answered:
//
//   - **Through a descriptor held on the prepared inode across the publish.**
//     A marker written through it afterwards shows up at the destination if and
//     only if the destination is that inode. This needs nothing from the
//     filesystem but a working descriptor — no st_ino, no hard links, no
//     surviving name — and it is what carries the assertion on FAT media.
//   - **Through os.SameFile**, wherever the filesystem preserves identity
//     across the publish's rename.
//
// If neither is available the test skips. It does not pass: there is nothing
// here that a passing run would have established, and saying "ok" would be the
// false assurance this test exists to prevent.
//
// A third observation rides along and is deliberately *not* trusted to carry
// the assertion: tiers 1 and 3 must consume the temporary name, because they
// publish by rename. That catches a re-write that abandons the temp file, with
// a precise message, and it pins that tier 3 has not quietly become a link. It
// does not catch a re-write that removes the temp file afterwards — the shape
// of every os.Rename cross-device copy-fallback — which is why an earlier
// version of this test, which rested on it alone once identity was
// unavailable, went green against a live write-in-place defect on exFAT. See
// TestPublishObservationsRefuseARewriteThatTidiesTheTempFileAway, which is
// that exact defect, kept in the suite so the hole cannot reopen.
func TestWriteFileNoClobberPublishesTheTempFile(t *testing.T) {
	for name, tier := range publishTiers() {
		t.Run(name, func(t *testing.T) {
			spy := forcePublishTiers(t, tier.exclusiveErr, tier.linkErr, nil)

			dir := t.TempDir()
			path := filepath.Join(dir, "wallet.json")
			spy.watchTheTempInode(t, path)

			want := []byte("the durable copy, published rather than rewritten")
			if err := writeFileNoClobber(path, want); err != nil {
				t.Fatalf("write failed: %v", err)
			}

			published, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(path); err != nil {
				t.Fatal(err)
			} else if string(got) != string(want) {
				t.Fatalf("got %q, want %q", got, want)
			}

			// Which mechanism ran is the filesystem's decision, not the row's:
			// forcing tier 2 on a volume without hard links falls through to
			// tier 3, and a rename is what published. On both FAT drivers that
			// is what every row does.
			switch mechanism := spy.publishMechanism(t); mechanism {
			case publishedByRename:
				if spy.tempNameSurvived {
					t.Fatal("the publish returned with the temporary name still in " +
						"place, so it did not rename the fsynced temp file into " +
						"position: the bytes were re-written at the final path " +
						"instead, which is the write-in-place defect")
				}
			case publishedByLink:
				if !spy.tempNameSurvived {
					t.Fatal("the publish reported a hard link but the temporary name " +
						"is gone, so it was not a link")
				}
			default:
				t.Fatalf("unknown publish mechanism %q", mechanism)
			}

			// And the question itself, asked however this filesystem allows.
			asked := false
			if spy.markerErr != nil {
				t.Fatalf("the marker channel was armed but did not produce an answer, so "+
					"nothing was established about the published inode: %v", spy.markerErr)
			}
			if spy.held != nil {
				asked = true
				if !spy.markerVisible {
					t.Fatal("a marker written through the descriptor held on the " +
						"prepared inode is not visible at the destination, so the " +
						"destination is a different file: the bytes were re-written " +
						"at the final path instead of being published, which is " +
						"the write-in-place defect")
				}
			}
			if spy.identityIsExpressible {
				asked = true
				if !os.SameFile(spy.preparedFile(t), published) {
					t.Fatal("the destination is not the temp file that was fsynced: " +
						"the bytes were re-written at the final path instead of being " +
						"published, which is the write-in-place defect")
				}
			}
			if !asked {
				t.Skip("this filesystem preserves no file identity across the publish's " +
					"rename and this platform will not hold a descriptor across it " +
					"either, so nothing here can tell publishing the fsynced temp " +
					"inode apart from re-writing its bytes at the destination; the " +
					"consumed temporary name above does not distinguish them, because " +
					"a re-write that removes the temp file consumes it too")
			}
		})
	}
}

// TestPublishObservationsRefuseARewriteThatTidiesTheTempFileAway is the
// proof-of-teeth for the assertion above, and it is named for the defect that
// broke the first version of it.
//
// The write-in-place defect has two shapes. Both write the bytes at the final
// path and abandon the fsynced temp inode; they differ only in whether they
// then remove the temp file. The first is refused by "the temporary name was
// consumed". The second is not — it consumes the name exactly as a rename does
// — and it is the more realistic of the two, because it is what an os.Rename
// cross-device copy-fallback looks like:
//
//	data, _ := os.ReadFile(oldpath)
//	os.WriteFile(newpath, data, 0o600)
//	return os.Remove(oldpath)
//
// An earlier version of the test above let that through on any filesystem
// where os.SameFile was unavailable — which is Windows + exFAT on every run,
// since os.CreateTemp's name always crosses the 15-character directory-entry
// boundary there. It reported a pass while the defect was live, on the one
// medium a cold-storage key backup uses. That is worse than a probe that is
// always red — a red probe is at least visible — so the shape is kept here
// permanently.
//
// Both shapes are run, and each is checked against every observation the test
// above uses, so the file records what each one is worth rather than leaving it
// to a comment. The broken publish is installed *before* forcePublishTiers, so
// it is wrapped and watched by the very spy the real test uses rather than by a
// copy of it: what is pinned is that helper's observations, which is the part
// that can rot.
func TestPublishObservationsRefuseARewriteThatTidiesTheTempFileAway(t *testing.T) {
	rewrite := func(alsoRemove bool) func(oldpath, newpath string) error {
		return func(oldpath, newpath string) error {
			data, err := os.ReadFile(oldpath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(newpath, data, 0o600); err != nil {
				return err
			}
			if alsoRemove {
				return os.Remove(oldpath)
			}
			return nil
		}
	}

	// The control first, so that a failure below cannot be read as "this
	// filesystem cannot show anything anyway". No skip: whichever mechanism
	// publishes here, a correct publish must satisfy every observation that is
	// available, and on the BSDs — where tier 1 is absent and tier 2 is the
	// production mechanism — that is a hard link rather than a rename.
	t.Run("a correct publish satisfies every observation", func(t *testing.T) {
		spy := forcePublishTiers(t, nil, nil, nil)
		dir := t.TempDir()
		path := filepath.Join(dir, "wallet.json")
		spy.watchTheTempInode(t, path)
		if err := writeFileNoClobber(path, []byte("published")); err != nil {
			t.Fatal(err)
		}
		switch mechanism := spy.publishMechanism(t); mechanism {
		case publishedByRename:
			if spy.tempNameSurvived {
				t.Error("a rename left the temporary name behind, so the observation " +
					"cannot mean what the mutation subtests read into it")
			}
		case publishedByLink:
			if !spy.tempNameSurvived {
				t.Error("a hard link consumed the temporary name, so the observation " +
					"cannot mean what the mutation subtests read into it")
			}
		}
		if spy.held != nil && !spy.markerVisible {
			t.Error("the marker is not visible at the destination after a correct " +
				"publish, so a false negative would be indistinguishable from " +
				"a write in place")
		}
		if spy.identityIsExpressible {
			published, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(spy.preparedFile(t), published) {
				t.Error("os.SameFile refuses a correct publish on a filesystem the " +
					"probe said preserves identity, so the probe and the assertion " +
					"disagree")
			}
		}
	})

	for _, shape := range []struct {
		name       string
		alsoRemove bool
		wantName   bool // whether the temporary name is expected to survive
	}{
		{"a re-write that abandons the temp file", false, true},
		{"a re-write that removes the temp file", true, false},
	} {
		t.Run(shape.name, func(t *testing.T) {
			oldExclusive := publishExclusive
			publishExclusive = rewrite(shape.alsoRemove)
			t.Cleanup(func() { publishExclusive = oldExclusive })

			// Installed after the swap above, so the spy wraps the broken
			// publish and observes it exactly as it observes the real one.
			spy := forcePublishTiers(t, nil, nil, nil)
			dir := t.TempDir()
			path := filepath.Join(dir, "wallet.json")
			spy.watchTheTempInode(t, path)

			want := []byte("re-written at the destination, not published")
			if err := writeFileNoClobber(path, want); err != nil {
				t.Fatalf("the simulated regression must still look like a successful "+
					"write, or this test is not reproducing the write-in-place defect: %v", err)
			}
			if got, err := os.ReadFile(path); err != nil {
				t.Fatal(err)
			} else if string(got) != string(want) {
				t.Fatalf("content = %q, want %q", got, want)
			}
			if got := spy.publishMechanism(t); got != publishedByRename {
				t.Fatalf("the broken publish reported success as %s, so the rename "+
					"branch of TestWriteFileNoClobberPublishesTheTempFile is not the "+
					"one that would have judged it", got)
			}

			// What the consumed temporary name is worth, recorded rather than asserted:
			// it refuses the first shape and accepts the second. This is the line that
			// documents why it cannot be the only observation.
			if spy.tempNameSurvived != shape.wantName {
				t.Errorf("temporary name survived = %v, want %v", spy.tempNameSurvived, shape.wantName)
			}

			// And what the two real observations are worth: both must refuse
			// both shapes, and at least one of them has to have been available,
			// or this subtest proved nothing.
			refused := false
			if spy.markerErr != nil {
				t.Fatalf("the marker channel was armed but did not produce an answer: %v", spy.markerErr)
			}
			if spy.held != nil {
				refused = true
				if spy.markerVisible {
					t.Error("a marker written through the descriptor held on the " +
						"prepared inode is visible at a destination that was re-written " +
						"rather than published, so the marker no longer distinguishes " +
						"the two and a write in place could return unnoticed")
				}
			}
			if spy.identityIsExpressible {
				refused = true
				published, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if os.SameFile(spy.preparedFile(t), published) {
					t.Error("a forced-and-cached file identity compares equal to a file " +
						"re-written at the destination, so os.SameFile no longer " +
						"distinguishes publishing from re-writing")
				}
			}
			if !refused {
				t.Skip("neither observation is available on this filesystem, so this " +
					"subtest cannot show that a write in place is refused here — which is " +
					"the gap TestWriteFileNoClobberPublishesTheTempFile skips for")
			}
		})
	}
}

// TestPreparedIdentitySurvivesPublishing is the test forcePublishTiers cites,
// and it exists because the line it cites is the kind a later reader deletes.
//
// `os.SameFile(fi, fi)` reads as a tautology. It is not one, and the first
// subtest is the proof: on Windows os.Stat records only a path and loads the
// volume/index identity lazily, on the first SameFile call, so a FileInfo
// taken before a rename and compared after it answers false for a file against
// itself. Forcing the load while the path still exists caches a real identity
// that survives the rename. Measured: deleting that one line from
// forcePublishTiers fails all five tiers of
// TestWriteFileNoClobberPublishesTheTempFile on windows/amd64, each claiming
// the write-in-place defect had returned.
//
// The second subtest answers the question the first one raises, and it is the
// one that matters: does a forced, *cached* identity still refuse a file
// re-written at the destination? If it did not, the assertion standing between
// this package and the defect's return would be decoration. So the defect is
// reintroduced deliberately — a publish step that writes the bytes at the
// final path and abandons the fsynced temp file — and the cached identity
// still refuses it. Verified to have teeth by swapping that step for a real
// rename, where it fails.
//
// Note what the two subtests together rule out and what neither alone does.
// The second passes whether or not the identity was forced, because in the
// re-write case the answer is false either way; on its own it distinguishes
// rename from re-write, not cached from uncached. The first is what pins the
// caching. Both are needed, and an earlier draft of this comment claimed the
// second did the first one's job.
//
// The first subtest renames within one name length, deliberately. On exFAT a
// file's identity moves when a rename changes how many 15-character directory
// entries the name needs — measured, `p.tmp` to `p` preserves it and
// `wallet.json.tmp-4107390348` to `wallet.json` does not — so a
// length-changing rename here would make this test fail on that filesystem for
// a reason that has nothing to do with what it is testing. That property is
// what made TestWriteFileNoClobberPublishesTheTempFile unpassable with TMP on
// exFAT; that test no longer rests on identity alone, and
// probePublishObservability is where it asks what this filesystem can show at
// all.
func TestPreparedIdentitySurvivesPublishing(t *testing.T) {
	// 1. The mechanism: a forced identity survives a rename, an unforced one
	// does not. This is a statement about the standard library, asserted
	// deliberately, because the line it justifies looks like a no-op and will
	// be deleted by someone who has not read this. If Go ever loads the
	// identity eagerly on every platform, the second half of this fails, and
	// the right answer then is to delete the forced call and this subtest
	// together — not to weaken either.
	t.Run("a forced identity survives the publish and an unforced one does not", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "aaa")
		dst := filepath.Join(dir, "bbb") // same length: see the doc comment
		if err := os.WriteFile(src, []byte("the durable copy"), 0o600); err != nil {
			t.Fatal(err)
		}

		forced, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		os.SameFile(forced, forced) // the line under test

		unforced, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}

		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
		published, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}

		if !os.SameFile(forced, published) {
			t.Error("a forced identity does not survive the rename, so spy.prepared " +
				"cannot be compared after a publish and forcePublishTiers' " +
				"os.SameFile(fi, fi) does not do what its comment says")
		}
		if os.SameFile(unforced, published) {
			t.Log("an unforced identity also survives the rename on this platform, " +
				"so the forced call in forcePublishTiers is redundant here and the " +
				"comment justifying it should be revisited")
		}
	})

	// 2. And the guarantee: a cached identity is still a real identity, so it
	// refuses a different file at the same path.
	t.Run("and still refuses a re-write at the destination", func(t *testing.T) {
		var prepared os.FileInfo

		oldExclusive := publishExclusive
		publishExclusive = func(oldpath, newpath string) error {
			fi, err := os.Stat(oldpath)
			if err != nil {
				return err
			}
			// The same forced load forcePublishTiers performs, at the same
			// moment: while oldpath still exists.
			os.SameFile(fi, fi)
			prepared = fi

			// And now the write-in-place defect rather than a publish: the destination
			// is written as a new file and the durable temp file is abandoned. This
			// returns nil, so writeFileNoClobber reports success and the content, mode
			// and no-clobber assertions elsewhere in this file all still hold.
			data, err := os.ReadFile(oldpath)
			if err != nil {
				return err
			}
			return os.WriteFile(newpath, data, 0o600)
		}
		t.Cleanup(func() { publishExclusive = oldExclusive })

		dir := t.TempDir()
		path := filepath.Join(dir, "wallet.json")
		want := []byte("re-written at the destination, not published")
		if err := writeFileNoClobber(path, want); err != nil {
			t.Fatalf("the simulated regression must still look like a successful "+
				"write, or this test is not reproducing the write-in-place defect: %v", err)
		}
		if got, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		} else if string(got) != string(want) {
			t.Fatalf("content = %q, want %q", got, want)
		}
		if prepared == nil {
			t.Fatal("the publish step was never reached, so nothing was captured")
		}

		published, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(prepared, published) {
			t.Fatal("a forced-and-cached file identity compares equal to a file " +
				"re-written at the destination, so the os.SameFile assertion in " +
				"TestWriteFileNoClobberPublishesTheTempFile no longer distinguishes " +
				"publishing from re-writing and a write in place could return unnoticed")
		}
	})
}

// TestWriteFileNoClobberSucceedsOnEveryPublishTier covers the properties a
// successful write has to have whichever mechanism published it: the right
// content, no widening of the mode, and nothing left in the directory but the
// key file itself.
func TestWriteFileNoClobberSucceedsOnEveryPublishTier(t *testing.T) {
	for name, tier := range publishTiers() {
		t.Run(name, func(t *testing.T) {
			forcePublishTiers(t, tier.exclusiveErr, tier.linkErr, nil)

			dir := t.TempDir()
			path := filepath.Join(dir, "wallet.json")
			if err := writeFileNoClobber(path, []byte("a key file")); err != nil {
				t.Fatalf("write failed: %v", err)
			}

			// The key file's mode is not widened: os.CreateTemp makes the
			// temp file 0600 and every tier publishes that same inode.
			//
			// The comparison is against a freshly created temp file in the same
			// directory rather than against a literal 0600, because FAT32 and exFAT
			// have no Unix permission bits at all — the mount options decide, and a key
			// file on a FAT stick reads back as whatever they say no matter what mode
			// it was created with. That is a property of the format, true before and
			// after this fix; what this package can be held to is that it does not
			// widen whatever the filesystem does give.
			probe, err := os.CreateTemp(dir, "mode-probe-*")
			if err != nil {
				t.Fatal(err)
			}
			probeInfo, err := probe.Stat()
			if err != nil {
				t.Fatal(err)
			}
			probe.Close()
			os.Remove(probe.Name())

			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := fi.Mode().Perm(), probeInfo.Mode().Perm(); got != want {
				t.Fatalf("key file mode is %v, want %v (what this filesystem gives a 0600 create)", got, want)
			}

			// No second copy of the encrypted seed is left behind under the
			// temporary name — the tier-1 and tier-3 renames consume it, and
			// the tier-2 link path removes it before the directory fsync so
			// that even a crash immediately afterwards cannot leave one.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "wallet.json" {
				t.Fatalf("expected only the key file to remain, found %v", entries)
			}
		})
	}
}

// TestWriteFileNoClobberRefusesADestinationThatAppearsDuringTheWrite is the
// no-clobber half of rule 7, checked against each publish mechanism itself
// rather than against the cheap pre-check that normally shields them.
//
// The distinction matters and is easy to lose. writeFileNoClobber opens with
// a courtesy refuseIfExists, so a test that simply creates the destination
// first never reaches the publish step at all — every tier returns the same
// pre-check error and the test passes no matter what the tiers do. (Verified:
// with the destination planted up front, spy.preparedFile reports the publish
// step was never entered, on all five tiers.) That is how tier 2's atomicity
// could be broken outright — publishing by os.Rename, which clobbers — with
// the whole suite still green, even though tier 2 is the production mechanism
// on Windows and the BSDs.
//
// So the destination is planted from inside the publish seam, after the
// pre-check has already passed. Whatever refuses now is the real mechanism:
// tiers 1 and 2 atomically, as part of the publishing syscall; tier 3 on the
// check it makes immediately before its rename.
func TestWriteFileNoClobberRefusesADestinationThatAppearsDuringTheWrite(t *testing.T) {
	for name, tier := range publishTiers() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "wallet.json")

			var planted os.FileInfo
			spy := forcePublishTiers(t, tier.exclusiveErr, tier.linkErr, func() {
				if err := os.WriteFile(path, []byte("a key file that appeared mid-write"), 0o600); err != nil {
					t.Fatal(err)
				}
				fi, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				planted = fi
			})

			err := writeFileNoClobber(path, []byte("attempted overwrite"))
			if err == nil {
				t.Fatal("expected the publish step to refuse a destination that appeared during the write")
			}
			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("expected an error wrapping fs.ErrExist, got %v", err)
			}
			spy.preparedFile(t) // the publish step really was reached

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "a key file that appeared mid-write" {
				t.Fatalf("the destination was modified: got %q", got)
			}
			still, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(planted, still) {
				t.Fatal("the destination was replaced by a different file")
			}

			// And the refused attempt left no copy of its own body behind.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "wallet.json" {
				t.Fatalf("expected exactly the destination file, found %v", entries)
			}
		})
	}
}

// TestWriteFileNoClobberCrashMidWriteLeavesNothingOnEveryPublishTier is the
// crash-safety guarantee itself, checked on each mechanism rather than only on
// the one that happens to run on the developer's filesystem. A tier that wrote
// straight to path would reproduce the write-in-place defect exactly — a torn
// file at the destination that a rerun is then refused — and that is precisely
// how an earlier fallback in this PR reintroduced the bug on FAT32 and exFAT,
// where a cold-storage key backup actually lives.
func TestWriteFileNoClobberCrashMidWriteLeavesNothingOnEveryPublishTier(t *testing.T) {
	for name, tier := range publishTiers() {
		t.Run(name, func(t *testing.T) {
			forcePublishTiers(t, tier.exclusiveErr, tier.linkErr, nil)

			dir := t.TempDir()
			path := filepath.Join(dir, "wallet.json")

			crashErr := errors.New("simulated crash")
			old := crashAfterWrite
			crashAfterWrite = func() error { return crashErr }
			t.Cleanup(func() { crashAfterWrite = old })

			if err := writeFileNoClobber(path, []byte("never completes")); !errors.Is(err, crashErr) {
				t.Fatalf("expected the simulated crash to surface, got %v", err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("path must not exist after a crash mid-write, got stat error %v", statErr)
			}

			// Recovery with no cleanup step in between — the thing the old write made
			// impossible.
			crashAfterWrite = nil
			want := []byte("the rerun that recovers")
			if err := writeFileNoClobber(path, want); err != nil {
				t.Fatalf("recovery write failed: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("recovered file contains %q, want %q", got, want)
			}
		})
	}
}

// TestWriteFileNoClobberRefusesADanglingSymlinkAtTheDestination covers the
// case os.Stat would have got wrong. A symlink pointing at nothing stats as
// "not there", and a write through it would both create the key file
// somewhere the operator never named and clobber whatever the link is aimed
// at if it later exists. writeFileNoClobber uses os.Lstat, so the name counts
// as taken.
func TestWriteFileNoClobberRefusesADanglingSymlinkAtTheDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), path); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	err := writeFileNoClobber(path, []byte("must not be written through the link"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("expected a no-clobber refusal, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "nowhere")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatal("the key file was written through the dangling symlink")
	}
}

// TestWriteFileNoClobberIsAtomicUnderConcurrentWriters is the no-clobber
// guarantee under the only conditions that can actually break it: many
// writers racing for the same path.
//
// It runs against the real publish path — no seams — so on any platform with
// an exclusive rename it is exercising exactly what a user gets. Exactly one
// writer may win; every other must be refused with fs.ErrExist, and the
// winner's bytes must survive untouched. A check-then-rename publish fails
// this: the losers pass the existence check and then silently replace the
// winner's key file, reporting success to both.
//
// How much this proves depends on the filesystem underneath, so do not read a
// green run as evidence that tier 3 is safe. Forced onto tier 3 it fails
// almost immediately on a fast local filesystem — measured: three winners in
// the first round on APFS — but the same racy tier survives hundreds of
// rounds on a real FAT volume, where each writer's fsync latency
// desynchronizes the goroutines enough that they rarely collide in the window
// between the check and the rename. The race is no less real there; it is
// just not reachable by this kind of test. What actually protects a FAT
// destination is tier 1, and TestRenameNoReplaceIsAnExclusiveRename is what
// pins tier 1 into existence.
func TestWriteFileNoClobberIsAtomicUnderConcurrentWriters(t *testing.T) {
	const writers = 8
	const rounds = 40

	for round := 0; round < rounds; round++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "wallet.json")

		var wg sync.WaitGroup
		results := make([]error, writers)
		bodies := make([][]byte, writers)
		start := make(chan struct{})
		for i := 0; i < writers; i++ {
			bodies[i] = []byte(fmt.Sprintf("key file from writer %d\n", i))
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = writeFileNoClobber(path, bodies[i])
			}(i)
		}
		close(start)
		wg.Wait()

		winners := 0
		for i, err := range results {
			switch {
			case err == nil:
				winners++
			case errors.Is(err, fs.ErrExist):
				// The correct refusal.
			default:
				t.Fatalf("round %d writer %d: unexpected error %v", round, i, err)
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: %d writers reported success, want exactly 1", round, winners)
		}

		// The surviving file must be one writer's body in full — never a
		// blend, never a later writer's silent overwrite of an earlier one's.
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		matched := false
		for i, body := range bodies {
			if string(got) == string(body) && results[i] == nil {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("round %d: the surviving key file %q is not the body of the writer that reported success", round, got)
		}

		// And no writer left its temp file behind.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("round %d: expected only the key file, found %v", round, entries)
		}
	}
}
