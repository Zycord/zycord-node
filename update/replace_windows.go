package update

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// backupName is where the previous binary is kept.
//
// The suffix goes AFTER the extension — `zycordd.exe.old` — so that nothing
// tries to execute a stale artefact by accident, and so a shell completing
// `*.exe` does not offer it.
func backupName(dir, name string) string { return filepath.Join(dir, name+".old") }

// replaceBinary puts src in place of dst on Windows.
//
// Windows refuses to delete or overwrite a mapped image, but it PERMITS renaming
// one. That asymmetry is the whole technique every Windows updater uses: move
// the running executable out of the way under a new name, then put the
// replacement at the name that was freed. The running process keeps executing
// from the renamed file, which is still the same open image.
func replaceBinary(dst, src string) (backup string, err error) {
	dir := filepath.Dir(dst)
	name := filepath.Base(dst)

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
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}

	backup = backupName(dir, name)
	// A previous .old may still be MAPPED by a parent process from the last
	// update - the Windows re-exec leaves the parent alive supervising the
	// child - so failing to remove it is expected rather than exceptional.
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		for i := 1; i < 32; i++ {
			alt := fmt.Sprintf("%s-%d", backup, i)
			if _, statErr := os.Stat(alt); os.IsNotExist(statErr) {
				backup = alt
				break
			}
		}
	}
	if err = os.Rename(dst, backup); err != nil {
		return "", fmt.Errorf("update: %s could not be moved aside: %w", dst, err)
	}
	if err = os.Rename(newPath, dst); err != nil {
		// Put it back rather than leaving the name empty. This is the one window
		// in the sequence where dst does not exist, and it is two syscalls wide.
		if back := os.Rename(backup, dst); back != nil {
			return "", fmt.Errorf("update: %s could not be replaced (%v) and the original could not be "+
				"restored (%v); the previous binary is at %s", dst, err, back, backup)
		}
		return "", err
	}
	// No syncDir: there is no directory handle on Windows that can be flushed
	// the way fsync(2) flushes one. wallet/syncdir_windows.go records the same
	// thing about the same problem.
	return backup, nil
}

// restoreBinary puts the kept copy back.
func restoreBinary(dst string) error {
	backup := backupName(filepath.Dir(dst), filepath.Base(dst))
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("update: there is no kept copy of %s to restore: %w", dst, err)
	}
	// The current file has to go first, and it may be mapped by a running
	// process; renaming it aside is the only move Windows allows.
	aside := backup + "-superseded"
	os.Remove(aside)
	if err := os.Rename(dst, aside); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(backup, dst); err != nil {
		os.Rename(aside, dst)
		return err
	}
	os.Remove(aside)
	return nil
}
