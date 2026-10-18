package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/promptprotocol"
	"github.com/jfardello/sshx/internal/promptzenity"
)

func TestWorkerLifetime(t *testing.T) {
	if mode := os.Getenv("SSHX_WORKER_LIFETIME_TEST"); mode != "" {
		err := watchSupervisor()
		if mode == "invalid" {
			if err != promptzenity.ErrFailed {
				t.Fatal("non-pipe lifetime accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stdout.Write([]byte("ready"))
		select {}
	}
	for _, mode := range []string{"valid", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			var lifetime *os.File = read
			if mode == "invalid" {
				lifetime, err = os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer lifetime.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkerLifetime$")
			cmd.Env = append(os.Environ(), "SSHX_WORKER_LIFETIME_TEST="+mode)
			cmd.ExtraFiles = []*os.File{lifetime}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if mode == "invalid" {
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("invalid descriptor: %v %s", err, out)
				}
				return
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
			ready := make([]byte, 5)
			if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "ready" {
				t.Fatal("worker did not arm watchdog", err)
			}
			_ = write.Close() // equivalent to the supervisor dying, including SIGKILL
			err = cmd.Wait()
			exit, ok := err.(*exec.ExitError)
			if !ok || ctx.Err() != nil {
				t.Fatalf("worker survived lifetime EOF: %v", err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("watchdog did not kill worker group")
			}
		})
	}
}

func TestSupervisor(t *testing.T) {
	for _, mode := range []string{"success", "exit", "overflow", "timeout", "child-exit", "child-timeout", "environment", "unsafe", "missing", "writer", "short"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			executable := filepath.Join(dir, "worker")
			ready := filepath.Join(dir, "ready")
			trigger := filepath.Join(dir, "trigger")
			survived := filepath.Join(dir, "survived")
			body := "#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --internal-dialog-worker ] || exit 2\n[ \"$PWD\" = / ] || exit 3\n"
			switch mode {
			case "exit":
				body += "printf 'secret'; exit 1\n"
			case "overflow":
				body += "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done\n"
			case "timeout":
				body += "exec /bin/sleep 10\n"
			case "child-exit", "child-timeout":
				body += "( : > '" + ready + "'; while [ ! -f '" + trigger + "' ]; do /bin/sleep 0.01; done; : > '" + survived + "' ) </dev/null >/dev/null 2>&1 &\nwhile [ ! -f '" + ready + "' ]; do /bin/sleep 0.01; done\n"
				if mode == "child-timeout" {
					body += "exec /bin/sleep 10\n"
				} else {
					body += "printf response\n"
				}
			case "environment":
				body += "[ \"$PATH\" = /usr/bin:/bin ] && [ \"$LANG\" = C.UTF-8 ] || exit 4\n[ -z \"$SSH_AUTH_SOCK$GOPASS_PASSWORD_STORE_DIR$LD_PRELOAD$LISTEN_FDS\" ] || exit 5\nprintf response\n"
			default:
				body += "printf response\n"
			}
			if err := os.WriteFile(executable, []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			if mode == "unsafe" {
				if err := os.Chmod(executable, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing" {
				executable += "-missing"
			}
			if mode == "environment" {
				for _, key := range []string{"SSH_AUTH_SOCK", "GOPASS_PASSWORD_STORE_DIR", "LD_PRELOAD", "LISTEN_FDS"} {
					t.Setenv(key, "untrusted")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			in, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			var out bytes.Buffer
			var runErr error
			switch mode {
			case "writer":
				runErr = supervise(ctx, executable, in, failingWriter{})
			case "short":
				runErr = supervise(ctx, executable, in, shortWriter{})
			default:
				runErr = supervise(ctx, executable, in, &out)
			}
			if mode == "success" || mode == "child-exit" || mode == "environment" {
				if runErr != nil || out.String() != "response" {
					t.Fatalf("success: %v %q", runErr, out.String())
				}
			} else if runErr != promptzenity.ErrFailed || out.Len() != 0 {
				t.Fatalf("failure leaked data/error: %v %q", runErr, out.String())
			}
			if strings.HasPrefix(mode, "child-") {
				if _, err := os.Stat(ready); err != nil {
					t.Fatal("child did not start")
				}
				if err := os.WriteFile(trigger, nil, 0600); err != nil {
					t.Fatal(err)
				}
				time.Sleep(100 * time.Millisecond)
				if _, err := os.Stat(survived); !os.IsNotExist(err) {
					t.Fatal("descendant survived")
				}
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, promptzenity.ErrFailed }

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func TestResponseBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := responseBuffer{data: make([]byte, 0, promptprotocol.MaxBytes), cancel: cancel}
	if n, err := b.Write(bytes.Repeat([]byte("a"), promptprotocol.MaxBytes)); err != nil || n != promptprotocol.MaxBytes {
		t.Fatal("exact bound failed")
	}
	if _, err := b.Write([]byte("x")); err != promptzenity.ErrFailed || ctx.Err() == nil {
		t.Fatal("overflow did not cancel")
	}
}
