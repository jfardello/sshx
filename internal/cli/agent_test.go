package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/agent"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func agentCLIHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sshx-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	return dir
}

func agentCLIExecute(ctx context.Context, argv ...string) (string, error) {
	var output bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{stdout: &output, stderr: io.Discard})
	cmd.SetArgs(argv)
	err := cmd.ExecuteContext(ctx)
	return output.String(), err
}

func TestAgentCommandValidation(t *testing.T) {
	dir := agentCLIHome(t)
	for _, argv := range [][]string{
		{"agent", "start"}, {"agent", "start", "--foreground=false"},
		{"agent", "run"}, {"agent", "run", "echo"}, {"agent", "env", "--shell", "fish"},
		{"agent", "status"}, {"agent", "env"}, {"agent", "stop"},
		{"agent", "env", "--socket", "relative"}, {"agent", "status", "unexpected"},
	} {
		if output, err := agentCLIExecute(context.Background(), argv...); err == nil || output != "" {
			t.Fatalf("%v: stdout=%q error=%v", argv, output, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sshx")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only commands created a runtime directory")
	}
	store := &recordingStore{entries: gopassCredentialRefs("agent")}
	runner := &recordingRunner{}
	cmd := newRootCommandWithDependencies(dependencies{gopassStore: store, goos: "darwin", runProgram: runner.run})
	cmd.SetArgs([]string{"ssh", "agent"})
	if err := cmd.Execute(); err != nil || runner.program != "ssh" {
		t.Fatal("explicit credential named agent", err)
	}
}

func TestAgentForegroundEnvironmentAndStatus(t *testing.T) {
	dir := agentCLIHome(t)
	// Quote and shell metacharacters are valid path bytes, never shell code.
	socket := filepath.Join(dir, "a'$(false);.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := agentCLIExecute(ctx, "agent", "start", "--foreground", "--socket", socket)
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for agent.Probe(ctx, socket) != nil {
		select {
		case err := <-done:
			t.Fatalf("startup failed: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not start")
		}
		time.Sleep(time.Millisecond)
	}
	for _, shell := range []string{"sh", "zsh"} {
		output, err := agentCLIExecute(ctx, "agent", "env", "--shell", shell, "--socket", socket)
		if err != nil {
			t.Fatal(err)
		}
		check := exec.Command("sh", "-c", output+"printf '%s\\n%s' \"$SSH_AUTH_SOCK\" \"${SSH_AGENT_PID-unset}\"")
		check.Env = append(os.Environ(), "SSH_AGENT_PID=123")
		got, err := check.Output()
		if err != nil || string(got) != socket+"\nunset" {
			t.Fatalf("shell output %q: %v", got, err)
		}
	}
	output, err := agentCLIExecute(ctx, "agent", "status", "--socket", socket)
	if err != nil || !strings.Contains(output, "available") || !strings.Contains(output, "not checked") {
		t.Fatal(output, err)
	}
	if _, err := agentCLIExecute(ctx, "agent", "start", "--foreground", "--socket", socket); err == nil {
		t.Fatal("replaced live endpoint")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung")
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket survived shutdown")
	}
}

// A real subprocess verifies argv/env and performs a wire readiness check.
func TestManagedAgentChild(t *testing.T) {
	if os.Getenv("SSHX_AGENT_CHILD_TEST") != "1" {
		return
	}
	mode := os.Getenv("SSHX_AGENT_CHILD_MODE")
	socket := os.Getenv("SSH_AUTH_SOCK")
	if err := agent.Probe(context.Background(), socket); err != nil {
		os.Exit(90)
	}
	if os.Getenv("SSH_AGENT_PID") != "" || os.Getenv("LISTEN_FDS") != "" {
		os.Exit(91)
	}
	fmt.Fprintln(os.Stdout, socket)
	switch mode {
	case "descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestAgentDescendantChild$")
		child.Env = os.Environ()
		if err := child.Start(); err != nil {
			os.Exit(95)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(os.Getenv("SSHX_AGENT_DESCENDANT_READY")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				_ = child.Process.Kill()
				os.Exit(96)
			}
			time.Sleep(time.Millisecond)
		}
	case "exit":
		os.Exit(23)
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(time.Second)
		os.Exit(92)
	case "wait":
		if err := os.WriteFile(os.Getenv("SSHX_AGENT_CHILD_READY"), []byte(socket), 0600); err != nil {
			os.Exit(93)
		}
		for {
			time.Sleep(time.Second)
		}
	default:
		args := os.Args
		for i, arg := range args {
			if arg == "--" {
				args = args[i+1:]
				break
			}
		}
		if !reflect.DeepEqual(args, []string{"with spaces", "$(touch never)", ";literal", "-x"}) {
			os.Exit(94)
		}
	}
	os.Exit(0)
}

func TestAgentDescendantChild(t *testing.T) {
	if os.Getenv("SSHX_AGENT_CHILD_TEST") != "1" {
		return
	}
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		os.Exit(90)
	}
	defer conn.Close()
	client := sshagent.NewClient(conn)
	if _, err := client.List(); err != nil {
		os.Exit(91)
	}
	ready := os.Getenv("SSHX_AGENT_DESCENDANT_READY")
	if err := os.WriteFile(ready, []byte(fmt.Sprint(os.Getpid())), 0600); err != nil {
		os.Exit(92)
	}
	// The parent command exits while this connection is still held. Server
	// teardown must close it even though the descendant remains alive.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := client.List(); err != nil {
			_ = os.WriteFile(ready+".closed", []byte("closed"), 0600)
			os.Exit(0)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(93)
}

func TestAgentRunClosesDescendantConnection(t *testing.T) {
	dir := agentCLIHome(t)
	t.Setenv("SSHX_AGENT_CHILD_TEST", "1")
	t.Setenv("SSHX_AGENT_CHILD_MODE", "descendant")
	ready := filepath.Join(dir, "descendant")
	t.Setenv("SSHX_AGENT_DESCENDANT_READY", ready)
	if err := runWithAgent(context.Background(), []string{os.Args[0], "-test.run=^TestManagedAgentChild$"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready + ".closed"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("descendant retained agent connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAgentRunLifecycle(t *testing.T) {
	dir := agentCLIHome(t)
	t.Setenv("SSHX_AGENT_CHILD_TEST", "1")
	t.Setenv("SSH_AUTH_SOCK", "/foreign/agent.sock")
	t.Setenv("SSH_AGENT_PID", "123")
	t.Setenv("LISTEN_FDS", "4")
	for _, tc := range []struct {
		mode string
		code int
	}{{"argv", 0}, {"exit", 23}, {"signal", 143}} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("SSHX_AGENT_CHILD_MODE", tc.mode)
			output, err := agentCLIExecute(context.Background(), "agent", "run", "--", os.Args[0], "-test.run=^TestManagedAgentChild$", "--", "with spaces", "$(touch never)", ";literal", "-x")
			if tc.code == 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var status interface{ Code() int }
				if !errors.As(err, &status) || status.Code() != tc.code {
					t.Fatalf("status %v, want %d", err, tc.code)
				}
			}
			socket := strings.TrimSpace(output)
			if !strings.HasPrefix(socket, dir+"/") {
				t.Fatalf("child socket %q", socket)
			}
			if _, err := os.Stat(filepath.Dir(socket)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private directory survived", err)
			}
		})
	}
	if os.Getenv("SSH_AUTH_SOCK") != "/foreign/agent.sock" || os.Getenv("SSH_AGENT_PID") != "123" {
		t.Fatal("caller environment changed")
	}
	if _, err := agentCLIExecute(context.Background(), "agent", "run", "--", "/nonexistent/sshx-command"); err == nil {
		t.Fatal("launch failure ignored")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "sshx"))
	if err != nil || len(entries) != 0 {
		t.Fatal("launch failure leaked socket", entries, err)
	}
}

func TestAgentRunConcurrentAndCancellation(t *testing.T) {
	dir := agentCLIHome(t)
	t.Setenv("SSHX_AGENT_CHILD_TEST", "1")
	t.Setenv("SSHX_AGENT_CHILD_MODE", "argv")
	var wg sync.WaitGroup
	sockets := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var output bytes.Buffer
			err := runWithAgent(context.Background(), []string{os.Args[0], "-test.run=^TestManagedAgentChild$", "--", "with spaces", "$(touch never)", ";literal", "-x"}, nil, &output, io.Discard)
			if err != nil {
				t.Error(err)
			}
			sockets <- strings.TrimSpace(output.String())
		}()
	}
	wg.Wait()
	if a, b := <-sockets, <-sockets; a == "" || a == b {
		t.Fatal("instances shared a socket")
	}
	t.Setenv("SSHX_AGENT_CHILD_MODE", "wait")
	ready := filepath.Join(dir, "ready")
	t.Setenv("SSHX_AGENT_CHILD_READY", ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runWithAgent(ctx, []string{os.Args[0], "-test.run=^TestManagedAgentChild$"}, nil, io.Discard, io.Discard)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child not ready")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation lost")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation hung")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "sshx"))
	if len(entries) != 0 {
		t.Fatal("cancelled run leaked private instance")
	}
}

func TestAgentRuntimeRejectsUnsafeDirectories(t *testing.T) {
	dir := agentCLIHome(t)
	t.Setenv("XDG_RUNTIME_DIR", "relative")
	if _, err := agentRuntimeDirectory(true); err == nil {
		t.Fatal("relative runtime accepted")
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)
	if err := os.Mkdir(filepath.Join(dir, "sshx"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := agentRuntimeDirectory(true); err == nil {
		t.Fatal("public directory accepted")
	}
}

func TestAgentRunStartupFailureCleanup(t *testing.T) {
	dir := agentCLIHome(t)
	config := filepath.Join(dir, "config", "sshx")
	if err := os.MkdirAll(config, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "agent.json"), []byte("invalid registry"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runWithAgent(context.Background(), []string{"/bin/true"}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("invalid registry accepted")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "sshx"))
	if err != nil || len(entries) != 0 {
		t.Fatal("startup failure leaked private directory", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runWithAgent(ctx, []string{"/bin/true"}, nil, io.Discard, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled startup", err)
	}
	entries, _ = os.ReadDir(filepath.Join(dir, "sshx"))
	if len(entries) != 0 {
		t.Fatal("cancelled startup leaked directory")
	}
}

func TestAgentManagedEnvironment(t *testing.T) {
	got := managedAgentEnvironment([]string{"SSH_AUTH_SOCK=foreign", "SSH_AUTH_SOCK=duplicate", "SSH_AGENT_PID=1", "LISTEN_PID=2", "LISTEN_FDS=3", "LISTEN_FDNAMES=agent", "LISTEN_PIDFDID=123", "PATH=/bin", "HOME=/owned"}, "/private/socket")
	want := []string{"PATH=/bin", "HOME=/owned", "SSH_AUTH_SOCK=/private/socket"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestAgentRunVerbose(t *testing.T) {
	agentCLIHome(t)
	for _, enabled := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		cmd := newRootCommandWithDependencies(dependencies{stdout: &stdout, stderr: &stderr})
		cmd.SetArgs([]string{"agent", "run", fmt.Sprintf("--verbose=%t", enabled), "--", "sh", "-c", "printf child-output"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if stdout.String() != "child-output" {
			t.Fatalf("stdout contaminated: %q", stdout.String())
		}
		if strings.Contains(stderr.String(), "diagnostics enabled") != enabled {
			t.Fatalf("verbose=%v stderr=%q", enabled, stderr.String())
		}
	}
}

func TestAgentPromptHelperValidation(t *testing.T) {
	agentCLIHome(t)
	_, err := agentCLIExecute(context.Background(), "agent", "run", "--prompt-helper=relative-command", "--", "sh", "-c", "exit 0")
	if err == nil {
		t.Fatal("untrusted prompt helper accepted")
	}
}

func TestAgentCacheTTLValidation(t *testing.T) {
	agentCLIHome(t)
	for _, ttl := range []string{"-1s", "6m", "invalid"} {
		if _, err := agentCLIExecute(context.Background(), "agent", "run", "--cache-ttl="+ttl, "--", "sh", "-c", "exit 0"); err == nil {
			t.Fatal("invalid cache TTL accepted", ttl)
		}
	}
}
