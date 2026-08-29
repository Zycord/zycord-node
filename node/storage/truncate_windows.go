package storage

import "os"

// truncateOpenLog shortens the store's own append handle to size, on the one
// platform where the handle cannot do it itself.
//
// The log is opened O_RDWR|O_CREATE|O_APPEND (see Open). On Windows that flag
// combination is not additive the way it is on unix: syscall.Open *removes*
// GENERIC_WRITE from the requested access when O_APPEND is set without
// O_TRUNC, and grants FILE_APPEND_DATA in its place — deliberately, because
// GENERIC_WRITE without FILE_WRITE_DATA would make writes land at the
// beginning of the file rather than at its end. Setting a file's length needs
// FILE_WRITE_DATA, which is the one right that combination gives up, so
// (*os.File).Truncate on the log handle fails ERROR_ACCESS_DENIED — always,
// on every Windows machine, not as a permissions accident. Measured:
//
//	truncate C:\...\log: Access is denied.
//
// The consequence was not cosmetic. This is the last step of compactLocked,
// so on Windows every compaction failed after the new snapshot was already
// published: the log was never truncated, logBytes and nextSeq were never
// reset, and compactIfDueLocked then re-ran a full snapshot rewrite on every
// subsequent commit — for the life of the process, growing the log without
// bound. A node would have run, and slowed to a stop.
//
// os.Truncate opens its own handle (O_WRONLY, so GENERIC_WRITE) and sets the
// length through that. It works while the append handle is open because Go
// opens files with FILE_SHARE_READ|FILE_SHARE_WRITE, so a second writer to the
// same path is admitted; and it is still one atomic metadata operation on the
// same file — so the paragraph compactLocked writes about what a reader sees
// the instant this returns holds here too.
//
// Go does *not* pass FILE_SHARE_DELETE, and that is worth knowing here rather
// than being rediscovered: an open file cannot be renamed or unlinked on
// Windows the way it can on unix. Measured with the same flags Open uses — a
// second reader and a second writer are both admitted while the log is open,
// while os.Remove of it fails "the file is being used by another process".
// Nothing in this function depends on that, but the next person to reach for
// "just rename the log out of the way" does. The append handle needs no repositioning afterwards:
// FILE_APPEND_DATA writes go to the current end of file, whatever that is now.
// All three of those were verified on windows/amd64 rather than reasoned about,
// and TestTruncateOpenLogWorksOnTheAppendHandle keeps them verified.
//
// f.Name() is the path os.OpenFile was given, which is what Open built with
// filepath.Join — an absolute path under the data directory, unaffected by any
// later working-directory change.
func truncateOpenLog(f *os.File, size int64) error {
	return os.Truncate(f.Name(), size)
}
