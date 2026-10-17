//go:build linux || darwin

package fileupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

var testPolicy = Policy{MaxBytes: 32}

func target(t *testing.T) string {
	t.Helper()
	// macOS's /var is a symlink; resolve the test base, not the API input.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "document")
}
func put(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func replacement([]byte, bool) ([]byte, bool, error) { return []byte("new"), true, nil }
func require(t *testing.T, got Publication, err error, want Publication, wantErr error) {
	t.Helper()
	if got != want || !errors.Is(err, wantErr) {
		t.Fatalf("got %v, %v; want %v, %v", got, err, want, wantErr)
	}
}

func TestPublicationAndNoop(t *testing.T) {
	p := target(t)
	got, err := Update(context.Background(), p, testPolicy, func(b []byte, exists bool) ([]byte, bool, error) {
		if exists || len(b) != 0 {
			t.Fatal("not absent")
		}
		return nil, false, nil
	})
	require(t, got, err, Unchanged, nil)
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("noop created target")
	}
	got, err = Update(context.Background(), p, testPolicy, replacement)
	require(t, got, err, Published, nil)
	before, _ := os.Stat(p)
	got, err = Update(context.Background(), p, testPolicy, func(b []byte, exists bool) ([]byte, bool, error) { b[0] = 'X'; return b, false, nil })
	require(t, got, err, Unchanged, nil)
	after, _ := os.Stat(p)
	if !os.SameFile(before, after) || before.ModTime() != after.ModTime() || read(t, p) != "new" || after.Mode().Perm() != 0600 {
		t.Fatal("noop rewrote target")
	}
	lockBefore, _ := os.Stat(p + ".lock")
	got, err = Update(context.Background(), p, testPolicy, replacement)
	require(t, got, err, Published, nil)
	lockAfter, _ := os.Stat(p + ".lock")
	if !os.SameFile(lockBefore, lockAfter) {
		t.Fatal("lock replaced")
	}
}

func TestInvalidTrust(t *testing.T) {
	for _, kind := range []string{"relative", "unclean", "nul", "target-symlink", "ancestor-symlink", "fifo", "hardlink", "writable-target", "private-target", "writable-parent", "sticky-parent", "lock-symlink", "lock-hardlink", "lock-mode", "lock-fifo", "oversize", "owner", "ancestor-owner"} {
		t.Run(kind, func(t *testing.T) {
			p := target(t)
			policy := testPolicy
			switch kind {
			case "relative":
				p = "relative"
			case "unclean":
				p = filepath.Dir(p) + "/./document"
			case "nul":
				p += "\x00"
			case "target-symlink":
				put(t, p+"other", "secret")
				if e := os.Symlink(p+"other", p); e != nil {
					t.Fatal(e)
				}
			case "ancestor-symlink":
				if e := os.Symlink(filepath.Dir(p), p+"link"); e != nil {
					t.Fatal(e)
				}
				p = p + "link/document"
			case "fifo":
				if e := unix.Mkfifo(p, 0600); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				put(t, p, "old")
				if e := os.Link(p, p+"other"); e != nil {
					t.Fatal(e)
				}
			case "writable-target":
				put(t, p, "old")
				os.Chmod(p, 0660)
			case "private-target":
				put(t, p, "old")
				os.Chmod(p, 0644)
				policy.Private = true
			case "writable-parent":
				os.Chmod(filepath.Dir(p), 0770)
			case "sticky-parent":
				os.Chmod(filepath.Dir(p), os.ModeSticky|0777)
			case "lock-symlink":
				put(t, p+"other", "old")
				os.Symlink(p+"other", p+".lock")
			case "lock-hardlink":
				put(t, p+".lock", "old")
				os.Link(p+".lock", p+"other")
			case "lock-mode":
				put(t, p+".lock", "")
				os.Chmod(p+".lock", 0644)
			case "lock-fifo":
				unix.Mkfifo(p+".lock", 0600)
			case "oversize":
				put(t, p, strings.Repeat("x", 33))
			case "owner":
				if os.Geteuid() != 0 {
					t.Skip("requires root")
				}
				put(t, p, "old")
				if e := os.Chown(p, 12345, -1); e != nil {
					t.Fatal(e)
				}
			case "ancestor-owner":
				if os.Geteuid() != 0 {
					t.Skip("requires root")
				}
				if e := os.Chown(filepath.Dir(p), 12345, -1); e != nil {
					t.Fatal(e)
				}
			}
			got, err := Update(context.Background(), p, policy, func([]byte, bool) ([]byte, bool, error) {
				t.Fatal("callback on untrusted file")
				return nil, false, nil
			})
			require(t, got, err, Unchanged, ErrInvalid)
		})
	}
}

func TestConfigPermissionsAndDirectoryCreation(t *testing.T) {
	p := target(t)
	os.Chmod(filepath.Dir(p), 0755)
	put(t, p, "old")
	os.Chmod(p, 0644)
	got, err := Update(context.Background(), p, testPolicy, replacement)
	require(t, got, err, Published, nil)
	st, _ := os.Stat(filepath.Dir(p))
	if st.Mode().Perm() != 0755 {
		t.Fatal("repaired parent")
	}
	p = filepath.Join(filepath.Dir(p), "one", "two", "doc")
	got, err = Update(context.Background(), p, testPolicy, replacement)
	require(t, got, err, Published, nil)
	for _, d := range []string{filepath.Dir(p), filepath.Dir(filepath.Dir(p))} {
		st, e := os.Stat(d)
		if e != nil || st.Mode().Perm() != 0700 {
			t.Fatal("directory not private", e)
		}
	}
}

func TestConflicts(t *testing.T) {
	for _, kind := range []string{"replace", "inplace", "mode", "restored-mode", "hardlink", "absent-create", "ancestor-replace", "ancestor-mode", "lock-replace", "target-symlink"} {
		t.Run(kind, func(t *testing.T) {
			p := target(t)
			if kind != "absent-create" {
				put(t, p, "old")
			}
			got, err := Update(context.Background(), p, testPolicy, func(b []byte, _ bool) ([]byte, bool, error) {
				switch kind {
				case "replace":
					put(t, p+"other", "external")
					os.Rename(p+"other", p)
				case "inplace":
					put(t, p, "ext")
				case "mode":
					os.Chmod(p, 0644)
				case "restored-mode":
					os.Chmod(p, 0644)
					os.Chmod(p, 0600)
				case "hardlink":
					os.Link(p, p+"other")
				case "absent-create":
					put(t, p, "external")
				case "ancestor-replace":
					dir := filepath.Dir(p)
					if e := os.Rename(dir, dir+"moved"); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(dir, 0700); e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { os.RemoveAll(dir + "moved") })
				case "ancestor-mode":
					os.Chmod(filepath.Dir(p), 0755)
				case "lock-replace":
					os.Remove(p + ".lock")
					put(t, p+".lock", "")
				case "target-symlink":
					os.Remove(p)
					os.Symlink(p+"other", p)
				}
				if len(b) > 0 {
					b[0] = 'X'
				}
				return []byte("new"), true, nil
			})
			require(t, got, err, Unchanged, ErrConflict)
		})
	}
}

func TestBusyAndSerialization(t *testing.T) {
	p := target(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, err := Update(context.Background(), p, testPolicy, func([]byte, bool) ([]byte, bool, error) { close(entered); <-release; return []byte("one"), true, nil })
		if got != Published || err != nil {
			t.Errorf("first: %v %v", got, err)
		}
		close(done)
	}()
	<-entered
	got, err := Update(context.Background(), p, testPolicy, func([]byte, bool) ([]byte, bool, error) { t.Error("busy callback"); return nil, false, nil })
	require(t, got, err, Unchanged, ErrBusy)
	close(release)
	<-done
	wg.Wait()
	got, err = Update(context.Background(), p, testPolicy, func(b []byte, _ bool) ([]byte, bool, error) { return append(b, []byte("two")...), true, nil })
	require(t, got, err, Published, nil)
	if read(t, p) != "onetwo" {
		t.Fatal("lost cooperating update")
	}
}

func TestFaultsAndCancellation(t *testing.T) {
	for _, stage := range []string{"write", "sync", "close", "rename", "dirsync", "cancel-before", "cancel-edit", "cancel-sync", "cancel-after"} {
		t.Run(stage, func(t *testing.T) {
			p := target(t)
			put(t, p, "old")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fault := errors.New("secret path and values")
			h := hooks{}
			switch stage {
			case "write":
				h.write = func(f *os.File, b []byte) error { f.Write(b[:1]); return fault }
			case "sync":
				h.sync = func(*os.File) error { return fault }
			case "close":
				h.close = func(f *os.File) error { f.Close(); return fault }
			case "rename":
				h.rename = func(int, string, string) error { return fault }
			case "dirsync":
				h.dirsync = func(int) error { return fault }
			case "cancel-before":
				cancel()
			case "cancel-sync":
				h.sync = func(f *os.File) error { cancel(); return f.Sync() }
			case "cancel-after":
				h.dirsync = func(fd int) error { cancel(); return unix.Fsync(fd) }
			}
			got, err := update(ctx, p, testPolicy, func(b []byte, e bool) ([]byte, bool, error) {
				if stage == "cancel-edit" {
					cancel()
				}
				return replacement(b, e)
			}, h)
			want, wantErr := Unchanged, ErrIO
			if strings.HasPrefix(stage, "cancel-") {
				wantErr = context.Canceled
			}
			if stage == "dirsync" {
				want = DurabilityUncertain
			}
			if stage == "cancel-after" {
				want = Published
				wantErr = nil
			}
			require(t, got, err, want, wantErr)
			expected := "old"
			if want != Unchanged {
				expected = "new"
			}
			if read(t, p) != expected {
				t.Fatal("incorrect publication")
			}
			entries, _ := os.ReadDir(filepath.Dir(p))
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".fileupdate-") {
					t.Fatal("temp leaked")
				}
			}
		})
	}
}

func TestBoundsAndSanitizedCallback(t *testing.T) {
	p := target(t)
	put(t, p, strings.Repeat("x", 32))
	got, err := Update(context.Background(), p, testPolicy, func(b []byte, _ bool) ([]byte, bool, error) {
		if len(b) != 32 {
			t.Fatal("bound truncated")
		}
		return append(b, 'x'), true, nil
	})
	require(t, got, err, Unchanged, ErrInvalid)
	got, err = Update(context.Background(), p, testPolicy, func([]byte, bool) ([]byte, bool, error) { return nil, false, errors.New("private contents") })
	require(t, got, err, Unchanged, ErrInvalid)
	got, err = Update(context.Background(), p, Policy{}, replacement)
	require(t, got, err, Unchanged, ErrInvalid)
}

func TestHooksArePerCall(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "fault", false: "normal"}[fail], func(t *testing.T) {
			t.Parallel()
			p := target(t)
			h := hooks{}
			if fail {
				h.sync = func(*os.File) error { return errors.New("injected") }
			}
			got, err := update(context.Background(), p, testPolicy, replacement, h)
			if fail {
				require(t, got, err, Unchanged, ErrIO)
			} else {
				require(t, got, err, Published, nil)
			}
		})
	}
}

func TestCleanupDoesNotRemoveSubstitutedTemp(t *testing.T) {
	p := target(t)
	var substitute string
	h := hooks{sync: func(*os.File) error {
		entries, err := os.ReadDir(filepath.Dir(p))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".fileupdate-") {
				substitute = filepath.Join(filepath.Dir(p), entry.Name())
				// Retain the original inode elsewhere to avoid inode reuse.
				if err := os.Rename(substitute, substitute+"saved"); err != nil {
					t.Fatal(err)
				}
				put(t, substitute, "external")
			}
		}
		return errors.New("injected")
	}}
	got, err := update(context.Background(), p, testPolicy, replacement, h)
	require(t, got, err, Unchanged, ErrIO)
	if substitute == "" || read(t, substitute) != "external" {
		t.Fatal("removed unowned temporary file")
	}
}

func TestHigherAncestorReplacement(t *testing.T) {
	base := filepath.Dir(target(t))
	ancestor := filepath.Join(base, "ancestor")
	if err := os.MkdirAll(filepath.Join(ancestor, "parent"), 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(ancestor, "parent", "document")
	put(t, p, "old")
	got, err := Update(context.Background(), p, testPolicy, func([]byte, bool) ([]byte, bool, error) {
		if err := os.Rename(ancestor, ancestor+"moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(ancestor, "parent"), 0700); err != nil {
			t.Fatal(err)
		}
		return []byte("new"), true, nil
	})
	require(t, got, err, Unchanged, ErrConflict)
	if read(t, filepath.Join(ancestor+"moved", "parent", "document")) != "old" {
		t.Fatal("published into detached ancestor")
	}
}

func TestCancellationWithDurabilityFailure(t *testing.T) {
	p := target(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := update(ctx, p, testPolicy, replacement, hooks{dirsync: func(int) error {
		cancel()
		return errors.New("injected")
	}})
	require(t, got, err, DurabilityUncertain, ErrIO)
	if read(t, p) != "new" {
		t.Fatal("postrename cancellation rolled back")
	}
}

func TestAncestorSync(t *testing.T) {
	for _, failAt := range []string{"", "base", "config"} {
		t.Run("failure-"+failAt, func(t *testing.T) {
			t.Parallel()
			base := filepath.Dir(target(t))
			config := filepath.Join(base, ".config")
			parent := filepath.Join(config, "sshx")
			p := filepath.Join(parent, "document")
			seen := map[string]int{}
			directoryName := func(fd int) string {
				var opened unix.Stat_t
				if err := unix.Fstat(fd, &opened); err != nil {
					t.Fatal(err)
				}
				for label, path := range map[string]string{"base": base, "config": config, "parent": parent} {
					var named unix.Stat_t
					if unix.Stat(path, &named) == nil && opened.Dev == named.Dev && opened.Ino == named.Ino {
						return label
					}
				}
				return "other"
			}
			h := hooks{ancestorSync: func(fd int) error {
				label := directoryName(fd)
				seen[label]++
				if label == failAt {
					return errors.New("ancestor sync failed")
				}
				return unix.Fsync(fd)
			}, dirsync: func(fd int) error {
				if directoryName(fd) != "parent" || seen["base"] != 1 || seen["config"] != 1 {
					t.Fatal("missing containing-directory sync before publication")
				}
				seen["parent"]++
				return unix.Fsync(fd)
			}}
			got, err := update(context.Background(), p, testPolicy, func(b []byte, exists bool) ([]byte, bool, error) {
				if failAt != "" {
					t.Fatal("callback after ancestor sync failure")
				}
				if seen["base"] != 1 || seen["config"] != 1 {
					t.Fatal("ancestors not synced before edit")
				}
				return replacement(b, exists)
			}, h)
			if failAt == "" {
				require(t, got, err, Published, nil)
				if seen["parent"] != 1 || read(t, p) != "new" {
					t.Fatal("publication not synced")
				}
			} else {
				require(t, got, err, Unchanged, ErrIO)
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("target published on ancestor sync failure")
				}
				// Retry must sync entries left behind by the failed call too.
				h.ancestorSync = func(fd int) error { seen[directoryName(fd)]++; return unix.Fsync(fd) }
				seen = map[string]int{}
				got, err = update(context.Background(), p, testPolicy, replacement, h)
				require(t, got, err, Published, nil)
			}
		})
	}
}

func TestInitialTempStatFailure(t *testing.T) {
	for _, substitute := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup", true: "replacement-preserved"}[substitute], func(t *testing.T) {
			t.Parallel()
			p := target(t)
			put(t, p, "old")
			calls := 0
			var temp string
			h := hooks{tempStat: func(fd int, st *unix.Stat_t) error {
				calls++
				if calls != 1 {
					return unix.Fstat(fd, st)
				}
				entries, err := os.ReadDir(filepath.Dir(p))
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".fileupdate-") {
						temp = filepath.Join(filepath.Dir(p), entry.Name())
					}
				}
				if temp == "" {
					t.Fatal("no temporary file")
				}
				if substitute {
					if err := os.Rename(temp, temp+"saved"); err != nil {
						t.Fatal(err)
					}
					put(t, temp, "external")
				}
				return errors.New("transient initial stat failure")
			}}
			got, err := update(context.Background(), p, testPolicy, replacement, h)
			require(t, got, err, Unchanged, ErrIO)
			if calls != 2 {
				t.Fatalf("expected descriptor-stat retry, got %d calls", calls)
			}
			if read(t, p) != "old" {
				t.Fatal("target changed on initial stat failure")
			}
			if substitute {
				if read(t, temp) != "external" {
					t.Fatal("removed unrelated replacement")
				}
			} else if _, err := os.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("owned temporary file leaked")
			}
		})
	}
}

func TestWrittenTempStatFailureKeepsCleanupIdentity(t *testing.T) {
	p := target(t)
	calls := 0
	got, err := update(context.Background(), p, testPolicy, replacement, hooks{tempStat: func(fd int, st *unix.Stat_t) error {
		calls++
		if calls == 2 {
			*st = unix.Stat_t{}
			return errors.New("stat failed")
		}
		return unix.Fstat(fd, st)
	}})
	require(t, got, err, Unchanged, ErrIO)
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".fileupdate-") {
			t.Fatal("lost cleanup identity")
		}
	}
}
