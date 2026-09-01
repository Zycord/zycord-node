//go:build unix

package update

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// backupName is where the previous binary is kept, exactly one generation back.
func backupName(dir, name string) string { return filepath.Join(dir, "."+name+".old") }

// replaceBinary puts src in place of dst, keeping the previous file.
//
// The ordering is the recoverable one, and each step is placed where it is for a
// reason that only shows up on a crash:
//
//  1. Write the replacement into the SAME DIRECTORY as dst. Not the system temp:
//     a rename across filesystems fails with EXDEV, and /tmp is very often a
//     different filesystem from /usr/local/bin.
//  2. Hard-link dst to the backup name, rather than renaming it there. A rename
//     would mean an instant with no file at dst; a link means dst never stops
//     existing at all.
//  3. Rename the replacement over dst. Atomic, and legal on a RUNNING
//     executable: the process holds the inode, not the name. ETXTBSY is about
//     writing into an open image, not about renaming over its name.
//  4. fsync the directory, so the new entry survives a crash and not just the
//     bytes behind it.
//
// A crash at any point leaves either (no backup, dst = the old binary) or
// (backup = the old binary, dst = old or new). **There is no state in which
// there is no working binary at dst.**
func replaceBinary(dst, src string) (backup string, err error) {
	dir := filepath.Dir(dst)
	name := filepath.Base(dst)

	fi, err := os.Stat(dst)
	if err != nil {
		return "", err
	}
	// Keep whatever bits the current file has beyond 0755, so an install that
	// deliberately restricts execution keeps doing so. Never Chown: if this
	// process could, it is already root and the file is already its own, and an
	// updater that chowns is an updater that can be talked into giving a file
	// away.
	mode := fi.Mode().Perm() | 0o755

	tmp, err := os.CreateTemp(dir, "."+name+".new-*")
	if err != nil {
		return "", err
	}
	newPath := tmp.Name()
	defer func() {
		if err != nil {
			os.Remove(newPath)
		}
	}()

	in, err := os.Open(src)
	if err != nil {
		tmp.Close()
		return "", err
	}
	_, err = io.Copy(tmp, in)
	in.Close()
	if err != nil {
		tmp.Close()
		return "", err
	}
	if err = tmp.Chmod(mode); err != nil {
		tmp.Close()
		return "", err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}

	backup = backupName(dir, name)
	os.Remove(backup) // best effort: last update's copy
	if err = os.Link(dst, backup); err != nil {
		// A filesystem that refuses hard links still needs a backup, so fall
		// back to a copy. Slower and briefly uses more space, and neither
		// matters next to having nothing to roll back to.
		if err = copyFile(backup, dst, mode); err != nil {
			return "", fmt.Errorf("update: could not keep a copy of %s: %w", dst, err)
		}
	}
	if err = os.Rename(newPath, dst); err != nil {
		return "", err
	}
	if err = syncDir(dir); err != nil {
		return backup, err
	}
	return backup, nil
}

// restoreBinary puts the kept copy back.
func restoreBinary(dst string) error {
	backup := backupName(filepath.Dir(dst), filepath.Base(dst))
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("update: there is no kept copy of %s to restore: %w", dst, err)
	}
	if err := os.Rename(backup, dst); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}

func copyFile(dst, src string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
