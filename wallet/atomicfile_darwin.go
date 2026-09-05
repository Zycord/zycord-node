//go:build darwin

package wallet

import "golang.org/x/sys/unix"

// renameNoReplace publishes oldpath as newpath and fails with EEXIST if
// newpath already exists — both atomically, in one syscall.
//
// Darwin spells this renamex_np(2) with RENAME_EXCL, available since macOS
// 10.12 and reachable without cgo. Verified against a real FAT32 volume
// created and mounted with hdiutil (wallet/fat32_darwin_test.go) as well as
// against APFS: an absent destination is published, an existing one is
// refused with the destination left byte-for-byte untouched. That is what
// makes the wallet's no-clobber guarantee atomic on FAT media, which have no
// hard links and where the alternative would have been a racy
// check-then-rename.
//
// A filesystem that does not implement it returns ENOTSUP.
// writeFileNoClobber treats any error but fs.ErrExist as "try the next
// publish mechanism", so no errno handling belongs here.
func renameNoReplace(oldpath, newpath string) error {
	return unix.RenamexNp(oldpath, newpath, unix.RENAME_EXCL)
}
