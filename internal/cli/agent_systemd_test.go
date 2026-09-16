package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAgentSystemdStopOrder(t *testing.T) {
	for _, fail := range []int{0, 1, 2} {
		var calls [][]string
		deps := dependencies{goos: "linux", stdout: io.Discard, stderr: io.Discard,
			systemctl: func(ctx context.Context, args ...string) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded manager operation")
				}
				calls = append(calls, args)
				if len(calls) == fail {
					return nil, errors.New("synthetic secret diagnostic")
				}
				return nil, nil
			}}
		cmd := newRootCommandWithDependencies(deps)
		cmd.SetArgs([]string{"agent", "stop", "--systemd"})
		err := cmd.Execute()
		if (err != nil) != (fail != 0) || (err != nil && strings.Contains(err.Error(), "synthetic")) {
			t.Fatal("stop error", err)
		}
		want := [][]string{
			{"--user", "--no-pager", "--no-ask-password", "stop", agentSocketUnit},
			{"--user", "--no-pager", "--no-ask-password", "stop", agentServiceUnit},
		}
		if fail == 1 {
			want = want[:1]
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("stop calls: %v", calls)
		}
	}
}

func TestAgentSystemdStatus(t *testing.T) {
	for _, tc := range []struct {
		name, socket, service string
		ok                    bool
	}{
		{"waiting", "loaded active listening", "loaded inactive dead", true},
		{"running", "loaded active listening", "loaded active running", true},
		{"stopped", "loaded inactive dead", "loaded inactive dead", false},
		{"failed", "loaded active listening", "loaded failed failed", false},
		{"missing", "not-found inactive dead", "not-found inactive dead", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			calls := 0
			deps := dependencies{goos: "linux", stdout: &output, stderr: io.Discard,
				systemctl: func(_ context.Context, args ...string) ([]byte, error) {
					if len(args) != 6 || args[3] != "show" || args[4] != "--property=LoadState,ActiveState,SubState" {
						t.Fatalf("unexpected status command: %v", args)
					}
					state := tc.socket
					if calls == 1 {
						state = tc.service
					}
					calls++
					parts := strings.Fields(state)
					return []byte("LoadState=" + parts[0] + "\nActiveState=" + parts[1] + "\nSubState=" + parts[2] + "\n"), nil
				}}
			cmd := newRootCommandWithDependencies(deps)
			cmd.SetArgs([]string{"agent", "status", "--systemd"})
			err := cmd.Execute()
			if (err == nil) != tc.ok || calls != 2 || !strings.Contains(output.String(), "no connection or signing attempted") {
				t.Fatalf("status: %v %s", err, &output)
			}
		})
	}
	for _, response := range []string{"", "LoadState=loaded", "LoadState=loaded\nLoadState=loaded", "LoadState=private\x1b", "Other=loaded"} {
		m := agentManager{goos: "linux", run: func(context.Context, ...string) ([]byte, error) { return []byte(response), nil }}
		if m.status(context.Background(), io.Discard) == nil {
			t.Fatal("accepted invalid manager response")
		}
	}
	m := agentManager{goos: "linux", run: func(context.Context, ...string) ([]byte, error) { return nil, errors.New("unavailable") }}
	if m.status(context.Background(), io.Discard) == nil {
		t.Fatal("ignored manager error")
	}
	m.goos = "darwin"
	if m.stop(context.Background()) == nil {
		t.Fatal("systemd supported on non-Linux")
	}
}

func TestAgentSystemdSocketAndEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux systemd CLI")
	}
	dir := agentCLIHome(t)
	want := filepath.Join(dir, "sshx-agent", "agent.sock")
	if got, err := systemdAgentSocket(""); err != nil || got != want {
		t.Fatal(got, err)
	}
	if _, err := os.Stat(filepath.Dir(want)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("resolver created manager directory")
	}
	if got, err := systemdAgentSocket("/custom/agent.sock"); err != nil || got != "/custom/agent.sock" {
		t.Fatal(got, err)
	}
	if err := os.Mkdir(filepath.Dir(want), 0700); err != nil {
		t.Fatal(err)
	}
	server, err := startAgent(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	output, err := agentCLIExecute(ctx, "agent", "env", "--systemd")
	if err != nil || !strings.Contains(output, want) {
		t.Fatal(output, err)
	}
	if _, err := agentCLIExecute(ctx, "agent", "status", "--systemd", "--socket", want); err == nil {
		t.Fatal("ambiguous status flags accepted")
	}
	for _, base := range []string{"", "relative", dir + "/../other"} {
		t.Setenv("XDG_RUNTIME_DIR", base)
		if _, err := systemdAgentSocket(""); err == nil {
			t.Fatal("accepted invalid runtime directory")
		}
	}
}

func TestSystemctlExecutionIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux systemd CLI")
	}
	dir := agentCLIHome(t)
	script := `#!/bin/sh
test "$1" = --user || exit 1
test -z "${LISTEN_PID+x}${LISTEN_FDS+x}${LISTEN_FDNAMES+x}${LISTEN_PIDFDID+x}${SSH_AGENT_PID+x}" || exit 2
test -z "$SSH_AUTH_SOCK" || exit 3
printf 'LoadState=loaded\nActiveState=active\nSubState=listening\n'
`
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID", "SSH_AGENT_PID", "SSH_AUTH_SOCK"} {
		t.Setenv(name, "foreign")
	}
	m := newAgentManager(dependencies{})
	if _, err := m.command(context.Background(), "show", agentSocketUnit); err != nil {
		t.Fatal(err)
	}
}
