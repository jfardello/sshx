package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/agent"
)

// Run the actual entry point in a subprocess, including its os.Exit behavior.
func TestCLIEntryPoint(t *testing.T) {
	if os.Getenv("SSHX_ENTRY_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"sshx"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(99)
}

func TestCLISignalChild(t *testing.T) {
	if os.Getenv("SSHX_ENTRY_TEST") != "1" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if err := agent.Probe(context.Background(), os.Getenv("SSH_AUTH_SOCK")); err != nil {
		os.Exit(91)
	}
	if err := os.WriteFile(os.Getenv("SSHX_ENTRY_READY"), []byte(os.Getenv("SSH_AUTH_SOCK")), 0600); err != nil {
		os.Exit(92)
	}
	sig := <-signals
	os.Exit(128 + int(sig.(syscall.Signal)))
}

func TestCLIProcessSignalsAndExitStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "sshx-main-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("SSHX_ENTRY_TEST", "1")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	ready := filepath.Join(dir, "ready")
	t.Setenv("SSHX_ENTRY_READY", ready)
	command := func(args ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestCLIEntryPoint$", "--"}, args...)...)
		cmd.Env = os.Environ()
		return cmd
	}
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			_ = os.Remove(ready)
			cmd := command("agent", "run", "--", os.Args[0], "-test.run=^TestCLISignalChild$")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			waitFile(t, ready)
			socket, err := os.ReadFile(ready)
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			err = waitProcess(t, cmd)
			var status *exec.ExitError
			if !errors.As(err, &status) || status.ExitCode() != 128+int(sig) {
				t.Fatalf("signal %v returned %v", sig, err)
			}
			if _, err := os.Stat(string(socket)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("signal left agent socket")
			}
		})
	}
	cmd := command("agent", "start", "--foreground")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	socket := filepath.Join(dir, "sshx", "agent.sock")
	deadline := time.Now().Add(5 * time.Second)
	for agent.Probe(context.Background(), socket) != nil {
		if time.Now().After(deadline) {
			t.Fatal("foreground startup timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitProcess(t, cmd); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreground socket leaked")
	}
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("child readiness timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitProcess(t *testing.T, cmd *exec.Cmd) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("process did not exit")
		return nil
	}
}
