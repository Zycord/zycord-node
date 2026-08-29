package wallet

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// writeFileNoClobber durably writes data to a new file at path, mode 0600 —
// the same mode a key file has always used.
//
// It holds two properties at once, and the whole shape of this function is
// about not trading either away for the other:
//
//   - **No clobber.** A pre-existing file at path is left completely untouched
//     and the call fails. This is the property SaveKeyFile's original O_EXCL
//     comment cared about: "never silently overwrite a key file. Losing one is
//     losing money."
//   - **Crash safety.** Nothing is ever created at path until the bytes behind
//     it are already written and fsynced, so a crash at any point leaves path
//     either absent or complete — never torn. This is the property O_EXCL
//     never provided, and its absence is the torn-key-file defect: a direct
//     O_CREATE|O_EXCL write can be torn by a crash between the write and the
//     page cache flushing, and O_EXCL then refuses the obvious recovery —
//     rerunning the same command to the same path — because a damaged file
//     already sits there. That turns a recoverable partial write into a
//     permanently unrecoverable one, and the seed exists nowhere else.
//
// The sequence is the one node/storage's Store.compactLocked uses for its
// snapshot file, and it is deliberately mirrored rather than shared, to keep
// this change inside the wallet: write the body to a temp file in the same
// directory, fsync and close it while it is still under its temporary name,
// publish it under path, then fsync the containing directory so the new
// directory entry itself survives a crash, not just the bytes behind it.
//
// # Publishing
//
// Publishing is the step that has to deliver both properties at once, so it
// is the step worth being exact about. There are three mechanisms, tried in
// order, each strictly weaker than the last and each only reached when the
// one above it is unavailable:
//
//  1. **An exclusive rename** — renameat2(RENAME_NOREPLACE) on Linux,
//     renamex_np(RENAME_EXCL) on darwin, MoveFileEx without
//     MOVEFILE_REPLACE_EXISTING on Windows (renameNoReplace, implemented per
//     platform). This is the primitive that does the whole job in one
//     syscall: it publishes the already-fsynced temp inode under path and
//     refuses with EEXIST if anything is already there, both atomically, and
//     it leaves no temp name behind at all. Measured working on every
//     filesystem this package was exercised against, FAT32 and exFAT
//     included — see the table below.
//  2. **A hard link.** For platforms with no exclusive rename of their own
//     (atomicfile_other.go — the BSDs) os.Link still refuses an existing
//     destination atomically. It costs an extra step, because link leaves
//     the bytes under two names and the temporary one has to be removed
//     afterwards. Note what this tier depends on and tier 1 does not: hard
//     links. Windows used to build atomicfile_other.go and rely on this,
//     which held on NTFS and did not on exFAT — see the row below, and
//     atomicfile_windows.go for why that file now exists.
//  3. **A checked plain rename.** Last resort, for a filesystem that has
//     neither. os.Rename keeps crash safety in full — it publishes the same
//     fsynced inode — but it clobbers, so the destination has to be checked
//     immediately before it. That check is not atomic: two copies of this
//     binary writing one path at one instant could both pass it. That race
//     is the reason this tier is last and not first.
//
// A tier is entered on *any* failure of the tier above other than
// fs.ErrExist, and deliberately without classifying the errno first.
// Classification is what the earlier attempts at this got stuck on, and it
// buys nothing: the same "this filesystem cannot do that" condition reports
// EPERM on Linux and ENOTSUP on darwin, and on Linux EPERM is additionally
// what link returns for a directory source, a source blocked by
// fs.protected_hardlinks, and an immutable source. None of that ambiguity
// matters, because every tier publishes the same already-durable temp file
// and the temp file is one this process just created and owns — so falling
// through is a correct response to any of those errnos, and where the
// refusal is something the next tier cannot get past either (a read-only
// filesystem, no permission on the directory) that tier fails too and its
// error surfaces.
//
// Measured directly, on a real volume of each format rather than reasoned
// about from man pages:
//
//	                    exclusive rename   link (absent/exists)   plain rename   fsync(dir)
//	Linux 6.12 vfat     ok / EEXIST        EPERM / EEXIST         ok             ok
//	Linux 6.12 exfat    ok / EEXIST        EPERM / EEXIST         ok             ok
//	macOS msdos FAT32   ok / EEXIST        ENOTSUP / EEXIST       ok             ok
//	macOS APFS          ok / EEXIST        ok / EEXIST            ok             ok
//	Linux overlayfs     ok / EEXIST        ok / EEXIST            ok             ok
//	Windows NTFS        ok / EEXIST        ok / EEXIST            ok             ACCESS_DENIED
//	Windows exFAT       ok / EEXIST        EINVAL_FN / same       ok             ACCESS_DENIED
//
// The two Windows rows are why atomicfile_windows.go exists. EINVAL_FN is
// ERROR_INVALID_FUNCTION, which exFAT returns for a hard link on a *free*
// destination as readily as an occupied one — and it is not fs.ErrExist, so
// tier 2 does not short-circuit and the fall-through reaches tier 3. Windows
// is also the one platform where fsync(dir) never succeeds, for a reason that
// is the platform's rather than the filesystem's; syncdir_windows.go carries
// it.
//
// So in practice tier 1 is what runs, on every filesystem measured, and both
// guarantees are atomic on all of them — FAT32 and exFAT, the formats a
// cold-storage USB backup of a key file is most likely to use, included.
// Tiers 2 and 3 exist for the platforms and filesystems that were not
// measured, so that an unmeasured one degrades in a defined order instead of
// failing outright.
//
// That sentence is worth reading as a claim rather than a summary: it was
// false for a while, on Windows + exFAT, precisely because "every filesystem
// measured" meant every filesystem measured *from Linux and macOS*, where a
// FAT volume is reached through a kernel that has renameat2. The platform, not
// only the format, is part of a row here.
//
// # What is not guaranteed
//
// Two limits, both properties of the FAT formats rather than of this code, and
// both as true before the torn-key-file fix as after — no write to FAT32 can
// do better:
//
//   - FAT32 and exFAT have no journal, so "atomically" on those is as atomic
//     as the format makes it. It is still categorically better than writing
//     the seed straight to its final name, which is what this function
//     replaced.
//   - FAT32 and exFAT have no Unix permission bits, so the 0600 the temp file
//     is created with does not survive there. See docs/WALLET.md rule 7.
func writeFileNoClobber(path string, data []byte) error {
	dir := filepath.Dir(path)

	// A courtesy check, not the guarantee. It gives the common case — "I
	// already have a wallet there" — a clear error without first writing an
	// encrypted seed to a temp file that is only going to be thrown away.
	// The guarantee itself is enforced at the publish step below, where
	// tiers 1 and 2 enforce it atomically and cannot be raced. Note that an
	// unexpected stat error here (no permission to read the directory, say)
	// surfaces as-is rather than as the clearer error the write itself would
	// have produced.
	if err := refuseIfExists(path); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// The temp file's own name is always transient: once this function
	// returns, its contents have either become path or the attempt has
	// failed, and either way the name tmpPath itself has nothing left to do.
	// Best-effort — a failed removal here is litter, not a correctness
	// problem, and is exactly what TestWriteFileNoClobberSurvivesStaleTempLitter
	// exists to prove is safe. On the tier-1 and tier-3 success paths the
	// rename has already consumed the name and this finds nothing; on the
	// tier-2 path the removal has already happened explicitly, before the
	// directory fsync, so that it is durable too.
	defer os.Remove(tmpPath)

	// os.CreateTemp already creates with mode 0600, which is the mode a key
	// file has always had; publishing preserves it, because every tier
	// publishes this same inode rather than writing a new file.
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if crashAfterWrite != nil {
		// Test-only seam: see the doc comment on crashAfterWrite below.
		if err := crashAfterWrite(); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Publish. From here on the bytes are durable under tmpPath; all that is
	// left is to give them the name the caller asked for.

	// Tier 1: an exclusive rename does both jobs in one syscall.
	err = publishExclusive(tmpPath, path)
	if err == nil {
		return syncDir(dir)
	}
	if errors.Is(err, fs.ErrExist) {
		return alreadyExistsError(path, err)
	}

	// Tier 2: a hard link still refuses an existing destination atomically.
	linkErr := publishByLink(tmpPath, path)
	if linkErr == nil {
		// Link leaves two directory entries for the one inode, and only path
		// is meant to remain. Drop the temporary one *before* the directory
		// fsync rather than in the deferred cleanup above, so that a crash
		// the instant this function returns cannot leave a second, fully
		// valid copy of the encrypted key file behind under a name the
		// operator never asked for and does not know to look for.
		os.Remove(tmpPath)
		return syncDir(dir)
	}
	if errors.Is(linkErr, fs.ErrExist) {
		return alreadyExistsError(path, linkErr)
	}

	// Tier 3: a plain rename keeps crash safety but will clobber, so the
	// destination is checked as close to the rename as it can be put. This
	// check is not atomic; see the doc comment.
	if err := refuseIfExists(path); err != nil {
		return err
	}
	if renameErr := publishByRename(tmpPath, path); renameErr != nil {
		// Report all three: the rename error is what actually stopped the
		// write, but the two above it are usually the more informative.
		return fmt.Errorf("wallet: could not write %s (exclusive rename: %v; link: %v; rename: %w)",
			path, err, linkErr, renameErr)
	}
	return syncDir(dir)
}

// refuseIfExists returns a no-clobber error if anything at all is already at
// path, nil if the name is free, and any other stat error unchanged.
//
// It is os.Lstat, not os.Stat, so that a dangling symlink at path counts as
// "something is already there" rather than as a free name: following the
// link and writing through it would both clobber whatever the link is aimed
// at and leave the key file somewhere the operator did not name.
func refuseIfExists(path string) error {
	switch _, err := os.Lstat(path); {
	case err == nil:
		return alreadyExistsError(path, fs.ErrExist)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return err
	}
}

func alreadyExistsError(path string, err error) error {
	return fmt.Errorf("wallet: %s already exists; refusing to overwrite a key file (docs/WALLET.md rule 7): %w", path, err)
}

// publishExclusive, publishByLink and publishByRename are the three publish
// mechanisms, indirected so the tests can drive the lower tiers on an
// ordinary filesystem that supports the higher ones and would otherwise never
// reach them. Production never reassigns any of them.
//
// The first two are the steerable ones: making either fail is how a test
// reaches the tier below it. publishByRename is last and steering it would
// only exercise an error message, so it is indirected for a different reason —
// to give a test the one instant at which a publish can be *observed*, which
// is the moment it returned and before writeFileNoClobber's deferred cleanup
// has run. Two things are asked there, and only from inside: whether the
// temporary name is still in place, which says which mechanism ran; and
// whether the destination is still the inode a descriptor is holding, which
// says whether the fsynced temp file was handed over or its bytes re-written
// at the final path. The second is the one that matters, because it is the
// only form of that question exFAT can answer — identity there does not
// survive a publish's rename. Without this seam the tier-3 rows of
// TestWriteFileNoClobberPublishesTheTempFile could ask neither.
//
// None of the three seams is guarded, and neither is crashAfterWrite: they
// are package globals swapped by tests that run sequentially. Nothing in
// wallet/ calls t.Parallel(), and adding it to a test that touches these
// would make them genuine data races — which -race may not even flag, since
// the assignment happens before the parallel goroutines start.
var (
	publishExclusive = renameNoReplace
	publishByLink    = os.Link
	publishByRename  = os.Rename
)

// crashAfterWrite, when non-nil, is called immediately after data is written
// to the temp file but before it is fsynced — the same point in the sequence
// where an OS-level crash or power loss can land during a genuine partial
// write. It exists purely for the fault-injection tests in
// keyfile_atomic_internal_test.go, which use it to prove what the crash-recovery
// property actually is: whatever happens here, path is never observed to
// exist until a fully-written, fsynced temp file is published under it, so
// re-running the caller with the same path always either recovers or (if a
// good file is already there) correctly refuses to clobber it. Production
// code never sets this; it is nil, and the check costs one nil comparison
// per save.
var crashAfterWrite func() error

// syncDir fsyncs a directory so that a publish into it is durable, not merely
// visible.
//
// On platforms or filesystems where a directory cannot be opened for fsync at
// all, Sync reports it, and what it reports is per-platform: ENOTSUP or EINVAL
// on unix, ERROR_ACCESS_DENIED on Windows, which is why the classification
// lives in syncdir_unix.go and syncdir_windows.go rather than here. None of
// them means the sync silently failed; all of them mean there was never
// anything to sync in the first place, so treating them as success does not
// weaken the guarantee this function exists to provide. Any other error is
// real and is returned. (Every filesystem in the table above does support it,
// FAT32 and exFAT included — measured — so on unix this tolerance is for
// filesystems beyond the ones the key-file path has been exercised on. On
// Windows it is the whole platform: see syncdir_windows.go, which is the file
// to read before assuming this path is dead code.)
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if isUnsupportedDirSync(err) {
			return nil
		}
		return err
	}
	return nil
}
