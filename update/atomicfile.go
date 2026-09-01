package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic durably replaces the file at path.
//
// The sequence — write a temp file in the SAME directory, fsync it, close it,
// rename it over the target, then fsync the directory — is the one
// node/storage's compaction and wallet/atomicfile.go's key-file publish both
// use. It is **mirrored rather than shared**, which is what wallet/atomicfile.go
// says about its own relationship to node/storage: the helpers there are
// unexported, and exporting them to reach across three packages would make one
// change to a wallet internal a change to how the node writes its chain.
//
// The difference from wallet/atomicfile.go is deliberate and is the whole reason
// this is a separate function: that one must NOT clobber, because overwriting a
// key file loses money. This one must clobber, because a preference file that
// cannot be updated is a preference that cannot be changed.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	// Same directory, not the system temp: a rename across filesystems fails
	// with EXDEV, and /tmp is very often a different filesystem.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename below has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	// Before the rename, so the bytes are on the disk before anything points at
	// them. The other order leaves a crash window where the name is published
	// and the content behind it is not.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// The directory entry itself, so a crash cannot leave the rename unrecorded.
	return syncDir(dir)
}

// writeJSONAtomic is writeFileAtomic for a document, with a trailing newline so
// the file is well-formed text to everything that reads files.
func writeJSONAtomic(path string, v any, perm os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("update: %s: %w", filepath.Base(path), err)
	}
	return writeFileAtomic(path, append(raw, '\n'), perm)
}
