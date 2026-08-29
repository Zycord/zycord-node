//go:build linux

package wallet

import "golang.org/x/sys/unix"

// renameNoReplace publishes oldpath as newpath and fails with EEXIST if
// newpath already exists — both atomically, in one syscall.
//
// Linux spells this renameat2(2) with RENAME_NOREPLACE, available since
// kernel 3.15. The no-replace check is made by the VFS before the filesystem
// is asked to do anything, so it does not depend on the filesystem
// implementing anything special: verified against real loopback-mounted vfat
// and exfat volumes (kernel 6.12), where an absent destination is published
// and an existing one is refused with the destination left byte-for-byte
// untouched. That is what makes the wallet's no-clobber guarantee atomic on
// FAT media, which have no hard links and where the alternative would have
// been a racy check-then-rename.
//
// A kernel older than 3.15 returns ENOSYS, and a filesystem that rejects the
// flag returns EINVAL or EOPNOTSUPP. writeFileNoClobber treats any error but
// fs.ErrExist as "try the next publish mechanism", so no errno handling
// belongs here.
func renameNoReplace(oldpath, newpath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE)
}
