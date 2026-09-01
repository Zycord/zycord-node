package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extraction bounds. An archive is signed by the time it reaches here, so these
// are not the defence against a stranger — they are what stops a corrupt or
// mistaken archive from filling a disk before anything notices.
const (
	maxMembers      = 256
	maxMemberBytes  = 256 << 20
	maxTotalMembers = 512 << 20
)

// ErrMemberMissing is an archive that verified and does not contain what it was
// supposed to.
var ErrMemberMissing = errors.New("update: the archive does not contain an expected file")

// Extract writes the members of the archive at src whose BASE NAME appears in
// want into dir, and returns where each landed.
//
// **The archive's own paths are never used as paths, and that is the whole
// defence.** The usual fix for zip-slip cleans each member name and checks the
// result stays under the destination — which works, and which puts the archive
// in charge of choosing a path and this code in charge of noticing a bad one.
// Here the archive chooses nothing: we know exactly which files we want, we
// match on the base name alone, and we write to filepath.Join(dir, ourName).
// A member called `../../etc/cron.d/x` is not rejected, it simply never matches
// anything we asked for.
//
// Everything below that is depth, because a sloppier matcher would reopen the
// hole this shape closes.
func Extract(src, dir string, want []string) (map[string]string, error) {
	wanted := make(map[string]bool, len(want))
	for _, w := range want {
		if w == "" || strings.ContainsAny(w, `/\`) {
			return nil, fmt.Errorf("update: %q is not a file name to look for", w)
		}
		wanted[w] = true
	}

	var (
		out map[string]string
		err error
	)
	switch {
	case strings.HasSuffix(src, ".zip"):
		out, err = extractZip(src, dir, wanted)
	case strings.HasSuffix(src, ".tar.gz"), strings.HasSuffix(src, ".tgz"):
		out, err = extractTarGz(src, dir, wanted)
	default:
		return nil, fmt.Errorf("update: %s is not an archive shape this build unpacks", filepath.Base(src))
	}
	if err != nil {
		return nil, err
	}
	for w := range wanted {
		if _, ok := out[w]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrMemberMissing, w)
		}
	}
	return out, nil
}

func extractTarGz(src, dir string, wanted map[string]bool) (map[string]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("update: %s is not gzip: %w", filepath.Base(src), err)
	}
	defer gz.Close()

	out := map[string]string{}
	tr := tar.NewReader(gz)
	var members int
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("update: %s: %w", filepath.Base(src), err)
		}
		if members++; members > maxMembers {
			return nil, fmt.Errorf("update: %s holds more than %d members", filepath.Base(src), maxMembers)
		}
		// Regular files only. A symlink named `zcd` pointing at /etc/shadow, a
		// hard link, a device node and a directory are all things this loop
		// could otherwise be talked into creating; none of them is ever a thing
		// we came here for.
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(filepath.FromSlash(h.Name))
		if !wanted[name] {
			continue
		}
		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("update: %s contains %q twice", filepath.Base(src), name)
		}
		written, dst, err := writeMember(dir, name, tr, h.Size)
		if err != nil {
			return nil, err
		}
		if total += written; total > maxTotalMembers {
			os.Remove(dst)
			return nil, fmt.Errorf("update: %s expands past %d bytes", filepath.Base(src), int64(maxTotalMembers))
		}
		out[name] = dst
	}
	return out, nil
}

func extractZip(src, dir string, wanted map[string]bool) (map[string]string, error) {
	// The file is already on disk because it had to be hashed, so the reader can
	// take it directly rather than buffering the whole archive in memory.
	zr, err := zip.OpenReader(src)
	if err != nil {
		return nil, fmt.Errorf("update: %s is not a zip: %w", filepath.Base(src), err)
	}
	defer zr.Close()

	if len(zr.File) > maxMembers {
		return nil, fmt.Errorf("update: %s holds more than %d members", filepath.Base(src), maxMembers)
	}
	out := map[string]string{}
	var total int64
	for _, fh := range zr.File {
		if !fh.Mode().IsRegular() {
			continue
		}
		name := filepath.Base(filepath.FromSlash(fh.Name))
		if !wanted[name] {
			continue
		}
		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("update: %s contains %q twice", filepath.Base(src), name)
		}
		rc, err := fh.Open()
		if err != nil {
			return nil, err
		}
		// UncompressedSize64 is the archive's own claim and is not trusted as a
		// bound; writeMember caps independently. It is passed only so a member
		// that lies large is refused before anything is written.
		if fh.UncompressedSize64 > maxMemberBytes {
			rc.Close()
			return nil, fmt.Errorf("update: %s declares %q as %d bytes", filepath.Base(src), name, fh.UncompressedSize64)
		}
		written, dst, err := writeMember(dir, name, rc, int64(fh.UncompressedSize64))
		rc.Close()
		if err != nil {
			return nil, err
		}
		if total += written; total > maxTotalMembers {
			os.Remove(dst)
			return nil, fmt.Errorf("update: %s expands past %d bytes", filepath.Base(src), int64(maxTotalMembers))
		}
		out[name] = dst
	}
	return out, nil
}

// writeMember writes one member under a name WE chose, in the directory WE
// chose, capped independently of what the archive says about it.
func writeMember(dir, name string, r io.Reader, declared int64) (int64, string, error) {
	if declared > maxMemberBytes {
		return 0, "", fmt.Errorf("update: %q is %d bytes", name, declared)
	}
	dst := filepath.Join(dir, name)
	// 0o700: an extracted binary is about to be executed, and it is written
	// where only this user can reach it until the replace moves it into place.
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return 0, "", err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxMemberBytes+1))
	if err != nil {
		f.Close()
		os.Remove(dst)
		return 0, "", err
	}
	if n > maxMemberBytes {
		f.Close()
		os.Remove(dst)
		return 0, "", fmt.Errorf("update: %q expands past %d bytes", name, int64(maxMemberBytes))
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(dst)
		return 0, "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(dst)
		return 0, "", err
	}
	return n, dst, nil
}
