//go:build linux || darwin

package fileupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Fault injection is local to one transaction; production uses the defaults.
type hooks struct {
	write        func(*os.File, []byte) error
	sync         func(*os.File) error
	close        func(*os.File) error
	rename       func(int, string, string) error
	dirsync      func(int) error
	ancestorSync func(int) error
	tempStat     func(int, *unix.Stat_t) error
}

func update(ctx context.Context, path string, policy Policy, edit func([]byte, bool) ([]byte, bool, error), h hooks) (Publication, error) {
	if ctx == nil || edit == nil || policy.MaxBytes <= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return Unchanged, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Unchanged, err
	}
	if h.ancestorSync == nil {
		h.ancestorSync = unix.Fsync
	}
	if h.tempStat == nil {
		h.tempStat = unix.Fstat
	}
	parent, chain, err := openParent(path, true, h.ancestorSync)
	if err != nil {
		return Unchanged, err
	}
	defer unix.Close(parent)
	name := filepath.Base(path)
	lock, err := unix.Openat(parent, name+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return Unchanged, openError(err)
	}
	defer unix.Close(lock)
	var lockStat unix.Stat_t
	if unix.Fstat(lock, &lockStat) != nil {
		return Unchanged, ErrIO
	}
	if !trustedFile(lockStat, true) || lockStat.Mode&0777 != 0600 {
		return Unchanged, ErrInvalid
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return Unchanged, ErrBusy
		}
		return Unchanged, ErrIO
	}
	if err := ctx.Err(); err != nil {
		return Unchanged, err
	}
	current, exists, before, err := snapshot(parent, name, policy)
	if err != nil {
		return Unchanged, err
	}
	defer clear(current)
	borrowed := bytes.Clone(current)
	defer clear(borrowed)
	next, changed, err := edit(borrowed, exists)
	if err != nil {
		return Unchanged, callbackError(err)
	}
	if err := ctx.Err(); err != nil {
		return Unchanged, err
	}
	if !changed {
		return Unchanged, nil
	}
	if len(next) > policy.MaxBytes {
		return Unchanged, ErrInvalid
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Unchanged, ErrIO
	}
	temp := ".fileupdate-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(parent, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return Unchanged, ErrIO
	}
	file := os.NewFile(uintptr(fd), "file update")
	var tempStat unix.Stat_t
	identityKnown, published := false, false
	defer func() {
		// Retry a transient initial stat failure on the retained descriptor,
		// before closing it. A pathname stat alone cannot prove ownership.
		if !published {
			if !identityKnown {
				identityKnown = h.tempStat(fd, &tempStat) == nil
			}
			var named unix.Stat_t
			if identityKnown && unix.Fstatat(parent, temp, &named, unix.AT_SYMLINK_NOFOLLOW) == nil && named.Dev == tempStat.Dev && named.Ino == tempStat.Ino {
				_ = unix.Unlinkat(parent, temp, 0)
			}
		}
		_ = file.Close()
	}()
	if h.tempStat(fd, &tempStat) != nil {
		return Unchanged, ErrIO
	}
	identityKnown = true
	if h.write == nil {
		h.write = writeComplete
	}
	if h.sync == nil {
		h.sync = (*os.File).Sync
	}
	if h.close == nil {
		h.close = (*os.File).Close
	}
	if h.rename == nil {
		h.rename = func(dir int, from, to string) error { return unix.Renameat(dir, from, dir, to) }
	}
	if h.dirsync == nil {
		h.dirsync = unix.Fsync
	}
	if h.write(file, next) != nil || h.sync(file) != nil {
		return Unchanged, ErrIO
	}
	var writtenStat unix.Stat_t
	if h.tempStat(fd, &writtenStat) != nil || !trustedFile(writtenStat, true) || writtenStat.Mode&0777 != 0600 || writtenStat.Size != int64(len(next)) {
		return Unchanged, ErrIO
	}
	tempStat = writtenStat
	if h.close(file) != nil {
		return Unchanged, ErrIO
	}
	// Reopen from the root, not from a potentially detached retained parent.
	check, afterChain, err := openParent(path, false, nil)
	if err != nil {
		return Unchanged, ErrConflict
	}
	_ = unix.Close(check)
	if len(chain) != len(afterChain) {
		return Unchanged, ErrConflict
	}
	for i := range chain {
		if !sameDirectory(chain[i], afterChain[i]) {
			return Unchanged, ErrConflict
		}
	}
	var currentLock, namedLock unix.Stat_t
	if unix.Fstat(lock, &currentLock) != nil || unix.Fstatat(parent, name+".lock", &namedLock, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameMetadata(lockStat, currentLock) || !sameMetadata(currentLock, namedLock) {
		return Unchanged, ErrConflict
	}
	final, finalExists, after, err := snapshot(parent, name, policy)
	defer clear(final)
	if err != nil || exists != finalExists || (exists && (!sameMetadata(before, after) || !bytes.Equal(current, final))) {
		return Unchanged, ErrConflict
	}
	var namedTemp unix.Stat_t
	if unix.Fstatat(parent, temp, &namedTemp, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameMetadata(tempStat, namedTemp) {
		return Unchanged, ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return Unchanged, err
	}
	if h.rename(parent, temp, name) != nil {
		return Unchanged, ErrIO
	}
	published = true
	if h.dirsync(parent) != nil {
		return DurabilityUncertain, ErrIO
	}
	return Published, nil
}

func writeComplete(f *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := f.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func openError(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EACCES) {
		return ErrInvalid
	}
	return ErrIO
}

// The root owner is the filesystem trust anchor (as in agent traversal).
func openParent(path string, create bool, syncAncestor func(int) error) (int, []unix.Stat_t, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, ErrIO
	}
	fail := func(err error) (int, []unix.Stat_t, error) { _ = unix.Close(fd); return -1, nil, err }
	var root unix.Stat_t
	if unix.Fstat(fd, &root) != nil {
		return fail(ErrIO)
	}
	dir := filepath.Dir(path)
	parts := []string{}
	if dir != "/" {
		parts = strings.Split(strings.TrimPrefix(dir, "/"), "/")
	}
	trusted := func(st unix.Stat_t, parent bool) bool {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR && (st.Uid == uint32(os.Geteuid()) || st.Uid == root.Uid) && (st.Mode&0022 == 0 || (!parent && st.Uid == root.Uid && st.Mode&unix.S_ISVTX != 0))
	}
	if !trusted(root, len(parts) == 0) {
		return fail(ErrInvalid)
	}
	chain := []unix.Stat_t{root}
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return fail(openError(err))
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return fail(openError(err))
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil {
			_ = unix.Close(next)
			return fail(ErrIO)
		}
		if !trusted(st, i == len(parts)-1) {
			_ = unix.Close(next)
			return fail(ErrInvalid)
		}
		// Persist each containing directory's child entry before publication.
		// Include existing entries: a prior failed call may have created them
		// without successfully syncing their containing directory.
		if create && syncAncestor(fd) != nil {
			_ = unix.Close(next)
			return fail(ErrIO)
		}
		_ = unix.Close(fd)
		fd = next
		chain = append(chain, st)
	}
	return fd, chain, nil
}

func trustedFile(st unix.Stat_t, private bool) bool {
	forbidden := uint32(0022)
	if private {
		forbidden = 0077
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && uint32(st.Mode)&forbidden == 0
}

func snapshot(dir int, name string, policy Policy) ([]byte, bool, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, st, nil
	}
	if err != nil {
		return nil, false, st, openError(err)
	}
	f := os.NewFile(uintptr(fd), "file snapshot")
	defer f.Close()
	if unix.Fstat(fd, &st) != nil {
		return nil, false, st, ErrIO
	}
	if !trustedFile(st, policy.Private) || st.Size < 0 || st.Size > int64(policy.MaxBytes) {
		return nil, false, st, ErrInvalid
	}
	// Avoid MaxBytes+1 overflowing int; a second read detects growth at the bound.
	data, err := io.ReadAll(io.LimitReader(f, int64(policy.MaxBytes)))
	var extra [1]byte
	n, end := f.Read(extra[:])
	if err != nil || (end != nil && end != io.EOF) {
		clear(data)
		return nil, false, st, ErrIO
	}
	if n != 0 {
		clear(data)
		return nil, false, st, ErrInvalid
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil {
		clear(data)
		return nil, false, st, ErrIO
	}
	if !sameMetadata(st, after) || int64(len(data)) != st.Size {
		clear(data)
		return nil, false, st, ErrConflict
	}
	return data, true, st, nil
}

func sameDirectory(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

func sameMetadata(a, b unix.Stat_t) bool {
	return sameDirectory(a, b) && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
