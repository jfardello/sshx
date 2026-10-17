package helperexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/sensitive"
)

func helperFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "helper")
	if err := os.WriteFile(path, []byte("#!/usr/bin/python3 -I\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func helperContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestTrustedPaths(t *testing.T) {
	path := helperFixture(t, "pass\n")
	if !Trusted(path) {
		t.Fatal("owner-controlled executable rejected")
	}
	for _, invalid := range []string{"", "helper", path + " --argument", filepath.Dir(path) + "/./helper", path + "/missing", filepath.Dir(path)} {
		if Trusted(invalid) {
			t.Fatalf("unsafe path trusted: %q", invalid)
		}
	}
	for _, mode := range []os.FileMode{0600, 0720, 0702} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if Trusted(path) {
			t.Fatalf("unsafe executable mode trusted: %o", mode)
		}
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if Trusted(link) {
		t.Fatal("symlink executable trusted")
	}
	ancestorLink := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(filepath.Dir(path), ancestorLink); err != nil {
		t.Fatal(err)
	}
	if Trusted(filepath.Join(ancestorLink, "helper")) {
		t.Fatal("symlink ancestor trusted")
	}
	if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
		t.Fatal(err)
	}
	if Trusted(path) {
		t.Fatal("writable parent trusted")
	}
}

func TestRunRechecksTrust(t *testing.T) {
	path := helperFixture(t, "raise SystemExit(0)\n")
	if !Trusted(path) {
		t.Fatal("initial helper not trusted")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	output, err := Run(helperContext(t), path, nil, Limits{16, 16})
	if !errors.Is(err, ErrUnavailable) || output != nil {
		t.Fatal("helper trust not rechecked before invocation")
	}
}

func TestRunPrivatePipesAndEnvironment(t *testing.T) {
	for _, name := range []string{"SSH_AUTH_SOCK", "SSH_AGENT_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID", "GOPASS_CONFIG", "GOPASS_GPG_OPTS", "GNUPGHOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "SENTINEL_SECRET"} {
		t.Setenv(name, "must-not-inherit")
	}
	t.Setenv("DISPLAY", ":fixture")
	t.Setenv("LANG", "untrusted-locale")
	path := helperFixture(t, `import os,stat,sys
allowed={'PATH','LANG','HOME','DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','LC_CTYPE'}
assert not set(os.environ)-allowed
assert os.environ['PATH']=='/usr/bin:/bin'
assert os.environ['LANG']=='C.UTF-8'
assert os.environ['DISPLAY']==':fixture'
assert len(sys.argv)==1 and os.getcwd()=='/'
assert stat.S_ISFIFO(os.fstat(0).st_mode) and stat.S_ISFIFO(os.fstat(1).st_mode)
assert not os.isatty(2)
if os.path.isdir('/proc/self/fd'):
 assert not any(os.readlink('/proc/self/fd/'+f).startswith('socket:') for f in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+f))
data=sys.stdin.buffer.read()
sys.stderr.write('PRIVATE-STDERR-MARKER')
sys.stdout.buffer.write(data)
`)
	input := []byte("arbitrary binary input\x00\n\xff")
	output, err := Run(helperContext(t), path, input, Limits{len(input), len(input)})
	defer sensitive.Clear(output)
	if err != nil || !bytes.Equal(output, input) {
		t.Fatalf("private pipe exchange failed: %v", err)
	}
	output[0] = 'X'
	if input[0] != 'a' {
		t.Fatal("response aliases borrowed input")
	}
}

func TestRunCallerSpecificLimits(t *testing.T) {
	path := helperFixture(t, "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n")
	input := bytes.Repeat([]byte("x"), 16*1024+1)
	for _, tc := range []struct {
		name   string
		limits Limits
		ok     bool
	}{
		{"larger-request", Limits{256 * 1024, 256 * 1024}, true},
		{"smaller-request", Limits{16 * 1024, 256 * 1024}, false},
		{"smaller-response", Limits{256 * 1024, 16 * 1024}, false},
		{"zero-request", Limits{0, 16}, false},
		{"negative-response", Limits{16, -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := Run(helperContext(t), path, input, tc.limits)
			defer sensitive.Clear(output)
			if tc.ok {
				if err != nil || !bytes.Equal(output, input) {
					t.Fatal("valid caller limits rejected", err)
				}
			} else if !errors.Is(err, ErrFailed) || output != nil {
				t.Fatalf("limit failure returned output or wrong error: %v", err)
			}
		})
	}
	if !bytes.Equal(input, bytes.Repeat([]byte("x"), len(input))) {
		t.Fatal("borrowed input was modified")
	}
}

func TestRunRejectsOversizedRequestBeforeLaunch(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	path := helperFixture(t, fmt.Sprintf("open(%q,'w').write('executed')\n", marker))
	if output, err := Run(helperContext(t), path, []byte("too large"), Limits{1, 16}); !errors.Is(err, ErrFailed) || output != nil {
		t.Fatal("oversized input accepted", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversized input launched helper")
	}
}

func TestRunFailuresAreSanitized(t *testing.T) {
	for _, body := range []string{
		"import sys\nsys.stdout.write('PRIVATE-MARKER')\nsys.stderr.write('PRIVATE-MARKER')\nsys.exit(1)\n",
		"import os,signal\nos.kill(os.getpid(),signal.SIGTERM)\n",
		"import sys\nwhile True: sys.stdout.buffer.write(b'x'*4096); sys.stdout.buffer.flush()\n",
	} {
		path := helperFixture(t, body)
		start := time.Now()
		output, err := Run(helperContext(t), path, []byte("REQUEST-MARKER"), Limits{32, 32})
		if !errors.Is(err, ErrFailed) || output != nil || err.Error() != "trusted helper execution failed" || time.Since(start) > 2*time.Second {
			t.Fatal("helper failure was not bounded and sanitized", err)
		}
	}
	path := helperFixture(t, "pass\n")
	if err := os.WriteFile(path, []byte("#!/nonexistent/interpreter\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := Run(helperContext(t), path, nil, Limits{16, 16}); !errors.Is(err, ErrUnavailable) || output != nil {
		t.Fatal("start failure was not sanitized", err)
	}
}

func TestRunDeadline(t *testing.T) {
	path := helperFixture(t, "import time\ntime.sleep(10)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	output, err := Run(ctx, path, nil, Limits{16, 16})
	if !errors.Is(err, ErrFailed) || output != nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatal("caller deadline was not enforced", err)
	}
}

func TestRunProcessGroupCleanup(t *testing.T) {
	for _, mode := range []string{"cancel", "complete"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			ready, survived, trigger := filepath.Join(dir, "ready"), filepath.Join(dir, "survived"), filepath.Join(dir, "trigger")
			// A surviving descendant may write only after Run has returned. This
			// avoids mistaking scheduler delays before cleanup for a live child.
			child := fmt.Sprintf("import os,time\nopen(%q,'w').write('ready')\ndeadline=time.monotonic()+5\nwhile not os.path.exists(%q):\n if time.monotonic()>deadline: raise SystemExit(0)\n time.sleep(0.005)\nopen(%q,'w').write('survived')\n", ready, trigger, survived)
			encoded, err := json.Marshal(child)
			if err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf("import subprocess,sys,time,os\np=subprocess.Popen([sys.executable,'-I','-c',%s],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nwhile not os.path.exists(%q): time.sleep(0.005)\n", encoded, ready)
			if mode == "cancel" {
				body += "time.sleep(10)\n"
			} else {
				body += "sys.stdout.write('ok')\n"
			}
			path := helperFixture(t, body)
			ctx, cancel := context.WithCancel(helperContext(t))
			defer cancel()
			done := make(chan error, 1)
			go func() {
				output, err := Run(ctx, path, nil, Limits{16, 16})
				sensitive.Clear(output)
				done <- err
			}()
			deadline := time.Now().Add(2 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("descendant did not become ready")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if (mode == "cancel" && !errors.Is(err, ErrFailed)) || (mode == "complete" && err != nil) {
					t.Fatal("unexpected helper result", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("helper cleanup did not finish")
			}
			if err := os.WriteFile(trigger, []byte("run completed"), 0600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(650 * time.Millisecond)
			if _, err := os.Stat(survived); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("descendant survived process-group cleanup")
			}
		})
	}
}
