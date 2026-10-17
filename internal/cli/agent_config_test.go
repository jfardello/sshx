package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/agent"
	"github.com/spf13/cobra"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func agentConfigFile(t *testing.T, data string) string {
	t.Helper()
	name := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "sshx", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func agentConfigExecute(ctx context.Context, deps dependencies, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	deps.stdout, deps.stderr = &stdout, &stderr
	cmd := newRootCommandWithDependencies(deps)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return stdout.String(), stderr.String(), err
}

// Use real agent flag definitions, but stop before endpoint or state operations.
func agentConfigOptions(t *testing.T, file optionOverrides, args ...string) (agentOptions, error) {
	t.Helper()
	var got agentOptions
	loads := 0
	deps := dependencies{stdout: io.Discard, stderr: io.Discard, loadConfig: func() (optionOverrides, error) {
		loads++
		return file, nil
	}}
	cmd := newAgentCommand(deps)
	cmd.PersistentPreRunE = func(leaf *cobra.Command, _ []string) error {
		var err error
		got, err = configuredAgentOptions(leaf, deps)
		return err
	}
	for _, leaf := range cmd.Commands() {
		leaf.RunE = func(*cobra.Command, []string) error { return nil }
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	if loads != 1 {
		t.Fatalf("configuration loads = %d, want 1", loads)
	}
	return got, err
}

func TestAgentConfigOptionPrecedence(t *testing.T) {
	full := configForTest(t, `agent:
  verbose: true
  allow-forwarding: true
  allow-key-mutations: true
  cache-ttl: 2m
  prompt-helper: /configured/helper
  socket: /configured/agent.sock
  state-file: /configured/state.json
`)
	wantFull := agentOptions{verbose: true, allowForwarding: true, allowKeyMutations: true,
		cacheTTL: 2 * time.Minute, promptHelper: "/configured/helper", socket: "/configured/agent.sock", stateFile: "/configured/state.json"}
	falseFlags := []string{"--verbose=false", "--allow-forwarding=false", "--allow-key-mutations=false", "--cache-ttl=0", "--prompt-helper=", "--state-file="}
	trueFlags := []string{"--verbose=true", "--allow-forwarding=true", "--allow-key-mutations=true", "--cache-ttl=5m", "--prompt-helper=/cli/helper", "--state-file=/cli/state.json"}
	wantCLI := agentOptions{verbose: true, allowForwarding: true, allowKeyMutations: true,
		cacheTTL: 5 * time.Minute, promptHelper: "/cli/helper", socket: "/cli/agent.sock", stateFile: "/cli/state.json"}
	for _, tc := range []struct {
		name string
		file optionOverrides
		args []string
		want agentOptions
	}{
		{"defaults", optionOverrides{}, []string{"env"}, agentOptions{}},
		{"empty-agent", configForTest(t, "agent: {}"), []string{"env"}, agentOptions{}},
		{"all-file-fields", full, []string{"env"}, wantFull},
		{"explicit-file-zeroes", configForTest(t, "verbose: true\nagent:\n  verbose: false\n  allow-forwarding: false\n  allow-key-mutations: false\n  cache-ttl: 0s\n  prompt-helper: ''\n  socket: ''\n  state-file: ''"), []string{"env"}, agentOptions{}},
		{"clear-before", full, append(append([]string{}, falseFlags...), "env", "--socket="), agentOptions{}},
		{"clear-after", full, append([]string{"env", "--socket="}, falseFlags...), agentOptions{}},
		{"replace-before", full, append(append([]string{}, trueFlags...), "env", "--socket=/cli/agent.sock"), wantCLI},
		{"replace-after", full, append([]string{"env", "--socket=/cli/agent.sock"}, trueFlags...), wantCLI},
		{"enable-defaults", optionOverrides{}, append([]string{"env", "--socket=/cli/agent.sock"}, trueFlags...), wantCLI},
		{"partial-preserves-file", full, []string{"--verbose=false", "env"}, agentOptions{allowForwarding: true, allowKeyMutations: true, cacheTTL: 2 * time.Minute, promptHelper: wantFull.promptHelper, socket: wantFull.socket, stateFile: wantFull.stateFile}},
		{"last-flag-wins", full, []string{"--verbose=true", "env", "--verbose=false"}, agentOptions{allowForwarding: true, allowKeyMutations: true, cacheTTL: 2 * time.Minute, promptHelper: wantFull.promptHelper, socket: wantFull.socket, stateFile: wantFull.stateFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agentConfigOptions(t, tc.file, tc.args...)
			if err != nil || got != tc.want {
				t.Fatalf("options = %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
	// Commands without a socket flag still receive the file setting; run must
	// deliberately ignore it when creating its private endpoint.
	for _, args := range [][]string{{"start", "--foreground"}, {"status"}, {"run", "--", "/bin/true"}, {"reset-state"}} {
		got, err := agentConfigOptions(t, full, args...)
		if err != nil || got != wantFull {
			t.Fatalf("%v: options = %#v, %v", args, got, err)
		}
	}
	got, err := configuredAgentOptions(&cobra.Command{}, dependencies{})
	if err != nil || got != (agentOptions{}) {
		t.Fatalf("no loader/flags: %#v, %v", got, err)
	}
}

func TestAgentConfigValidationCannotBeMasked(t *testing.T) {
	for _, tc := range []struct {
		name, field, value, flag string
	}{
		{"negative-ttl", "cache-ttl", "-1s", "--cache-ttl=0"},
		{"excessive-ttl", "cache-ttl", "5m1ns", "--cache-ttl=0"},
		{"relative-helper", "prompt-helper", "relative", "--prompt-helper="},
		{"relative-socket", "socket", "relative", "--socket="},
		{"unclean-state", "state-file", "/tmp/../state", "--state-file="},
		{"control-path", "socket", "/tmp/agent\n.sock", "--socket="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Decode rejects invalid files already. Inject a typed invalid value
			// as well to exercise configuredAgentOptions' own validation boundary.
			file := configForTest(t, "agent: {}")
			file.Source = "configuration file test.yaml"
			switch tc.field {
			case "cache-ttl":
				value, err := time.ParseDuration(tc.value)
				if err != nil {
					t.Fatal(err)
				}
				file.Agent.CacheTTL = &value
			case "prompt-helper":
				file.Agent.PromptHelper = &tc.value
			case "socket":
				file.Agent.Socket = &tc.value
			case "state-file":
				file.Agent.StateFile = &tc.value
			}
			_, err := agentConfigOptions(t, file, "env", tc.flag)
			if err == nil || !strings.Contains(err.Error(), file.Source) || !strings.Contains(err.Error(), "agent."+tc.field) {
				t.Fatalf("invalid file was masked or lost provenance: %v", err)
			}
			_, err = agentConfigOptions(t, optionOverrides{}, "env", "--"+tc.field+"="+tc.value)
			if err == nil || !strings.Contains(err.Error(), "command line") || !strings.Contains(err.Error(), "agent."+tc.field) {
				t.Fatalf("invalid CLI value: %v", err)
			}
		})
	}
}

func TestAgentConfigErrorsPrecedeSideEffects(t *testing.T) {
	for i, data := range []string{
		"agent: [", "unknown: secret", "agent:\n  unknown: secret",
		"agent:\n  verbose: true\n  verbose: false", "agent:\n  verbose: 'true'",
		"agent:\n  cache-ttl: nonsense", "agent:\n  cache-ttl: -1s", "agent:\n  cache-ttl: 6m",
		"agent:\n  prompt-helper: relative", "agent:\n  socket: relative", "agent:\n  state-file: relative",
	} {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			dir := agentCLIHome(t)
			name := agentConfigFile(t, data)
			state := filepath.Join(dir, "state.json")
			const sentinel = "state must remain untouched"
			if err := os.WriteFile(state, []byte(sentinel), 0600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "child-ran")
			for _, args := range [][]string{
				{"agent", "start", "--foreground", "--socket=" + filepath.Join(dir, "endpoint.sock")},
				{"agent", "run", "--", "sh", "-c", "touch '" + marker + "'"},
				{"agent", "env", "--socket=" + filepath.Join(dir, "endpoint.sock")},
				{"agent", "status", "--systemd"},
				{"agent", "reset-state"},
			} {
				// Valid CLI values cannot repair an invalid configuration file.
				flags := []string{"agent", "--cache-ttl=0", "--prompt-helper=", "--state-file=" + state}
				argv := append(flags, args[1:]...)
				loads := 0
				stdout, stderr, err := agentConfigExecute(context.Background(), dependencies{
					loadConfig:         func() (optionOverrides, error) { loads++; return loadUserConfig() },
					secretServiceStore: func(context.Context) (credentialStore, error) { t.Fatal("password backend opened"); return nil, nil },
					runProgram:         func(string, []string, []byte) error { t.Fatal("password runner invoked"); return nil },
					systemctl:          func(context.Context, ...string) ([]byte, error) { t.Fatal("systemctl invoked"); return nil, nil },
				}, argv...)
				if err == nil || !strings.Contains(err.Error(), name) || stdout != "" || stderr != "" || loads != 1 {
					t.Fatalf("%v: loads=%d stdout=%q stderr=%q error=%v", argv, loads, stdout, stderr, err)
				}
			}
			for _, path := range []string{filepath.Join(dir, "sshx"), filepath.Join(dir, "endpoint.sock"), marker, state + ".lock", filepath.Join(dir, "state")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("side effect at %s: %v", path, err)
				}
			}
			if got, err := os.ReadFile(state); err != nil || string(got) != sentinel {
				t.Fatalf("state modified: %q, %v", got, err)
			}
		})
	}
	// Also cover loader failures that happen before YAML decoding.
	for _, command := range []string{"start", "run", "env", "status", "reset-state"} {
		args := []string{"agent", command}
		if command == "start" {
			args = append(args, "--foreground")
		}
		if command == "run" {
			args = append(args, "--", "/bin/true")
		}
		failure := errors.New("configuration unavailable")
		_, _, err := agentConfigExecute(context.Background(), dependencies{loadConfig: func() (optionOverrides, error) { return optionOverrides{}, failure }}, args...)
		if !errors.Is(err, failure) {
			t.Fatalf("%s: loader failure lost: %v", command, err)
		}
	}
}

func TestAgentConfigProductionLoader(t *testing.T) {
	agentCLIHome(t)
	for _, data := range []string{"", "agent: ["} {
		name := agentConfigFile(t, data)
		cmd := newRootCommand()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"agent", "start"})
		err := cmd.Execute()
		if data == "" {
			if err == nil || !strings.Contains(err.Error(), "requires --foreground") {
				t.Fatalf("empty configuration did not preserve defaults: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "invalid YAML syntax") {
			t.Fatalf("production agent command did not load configuration: %v", err)
		}
	}
}

func TestAgentConfigHelpCompletionAndStopSkipLoading(t *testing.T) {
	agentCLIHome(t)
	for _, args := range [][]string{
		{"agent", "--help"}, {"help", "agent"}, {"help", "agent", "run"},
		{"agent", "start", "--help"}, {"agent", "run", "--help"}, {"agent", "env", "--help"},
		{"agent", "status", "--help"}, {"agent", "reset-state", "--help"}, {"agent", "stop", "--help"},
		{"completion", "bash"}, {"completion", "zsh"}, {"__complete", "agent", ""},
		{"__complete", "agent", "env", "--s"}, {"agent", "stop"}, {"agent", "stop", "--systemd"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			cmd := newRootCommandWithDependencies(dependencies{goos: "linux", stdout: io.Discard, stderr: io.Discard,
				loadConfig: func() (optionOverrides, error) {
					t.Fatal("help/completion/stop loaded config")
					return optionOverrides{}, errors.New("invalid config")
				},
				systemctl: func(_ context.Context, args ...string) ([]byte, error) {
					if len(args) != 5 || args[3] != "stop" {
						t.Fatalf("unexpected manager action: %v", args)
					}
					calls++
					return nil, nil
				},
			})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(args)
			err := cmd.Execute()
			foregroundStop := reflect.DeepEqual(args, []string{"agent", "stop"})
			if foregroundStop {
				if err == nil || !strings.Contains(err.Error(), "Ctrl-C") {
					t.Fatalf("foreground stop: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			if reflect.DeepEqual(args, []string{"agent", "stop", "--systemd"}) {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("manager calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestAgentConfigSystemdStatusIgnoresSocket(t *testing.T) {
	dir := agentCLIHome(t)
	file := configForTest(t, "agent:\n  socket: "+filepath.Join(dir, "missing.sock"))
	loads := 0
	var units []string
	stdout, _, err := agentConfigExecute(context.Background(), dependencies{goos: "linux",
		loadConfig: func() (optionOverrides, error) { loads++; return file, nil },
		systemctl: func(_ context.Context, args ...string) ([]byte, error) {
			if len(args) != 6 || args[3] != "show" || args[4] != "--property=LoadState,ActiveState,SubState" {
				t.Fatalf("unexpected manager action: %v", args)
			}
			units = append(units, args[5])
			substate := "listening"
			if args[5] == agentServiceUnit {
				substate = "running"
			}
			return []byte("LoadState=loaded\nActiveState=active\nSubState=" + substate + "\n"), nil
		},
	}, "agent", "status", "--systemd")
	if err != nil || loads != 1 || !reflect.DeepEqual(units, []string{agentSocketUnit, agentServiceUnit}) || !strings.Contains(stdout, "no connection or signing attempted") {
		t.Fatalf("loads=%d units=%v output=%q error=%v", loads, units, stdout, err)
	}
}

func TestAgentConfigConfiguredEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		enabled bool
	}{
		{"file", []string{"agent", "start", "--foreground"}, true},
		{"false-before", []string{"agent", "--allow-key-mutations=false", "start", "--foreground"}, false},
		{"false-after", []string{"agent", "start", "--foreground", "--allow-key-mutations=false"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := agentCLIHome(t)
			socket := filepath.Join(dir, "configured.sock")
			state := filepath.Join(dir, "configured-state.json")
			if err := agent.ResetMutationState(state); err != nil {
				t.Fatal(err)
			}
			agentConfigFile(t, fmt.Sprintf("verbose: false\nagent:\n  verbose: true\n  allow-key-mutations: true\n  socket: %s\n  state-file: %s\n", socket, state))
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			loads := 0
			go func() {
				_, _, err := agentConfigExecute(ctx, dependencies{loadConfig: func() (optionOverrides, error) { loads++; return loadUserConfig() }}, tc.args...)
				done <- err
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("foreground shutdown: %v", err)
					}
					if loads != 1 {
						t.Errorf("start configuration loads = %d, want 1", loads)
					}
					if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("configured socket survived shutdown: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("foreground shutdown hung")
				}
			})
			deadline := time.Now().Add(5 * time.Second)
			for agent.Probe(ctx, socket) != nil {
				select {
				case err := <-done:
					// Return the result for cleanup to consume, too.
					done <- err
					t.Fatalf("configured startup failed: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("configured endpoint did not become ready")
				}
				time.Sleep(time.Millisecond)
			}
			for _, command := range []string{"env", "status"} {
				count := 0
				stdout, _, err := agentConfigExecute(ctx, dependencies{loadConfig: func() (optionOverrides, error) { count++; return loadUserConfig() }}, "agent", command)
				if err != nil || count != 1 {
					t.Fatalf("%s: loads=%d error=%v", command, count, err)
				}
				if command == "env" && !strings.Contains(stdout, "SSH_AUTH_SOCK="+quoteShell(socket)) {
					t.Fatalf("configured env: %q", stdout)
				}
				if command == "status" && !strings.Contains(stdout, "not checked") {
					t.Fatalf("configured status: %q", stdout)
				}
				_, _, err = agentConfigExecute(ctx, dependencies{loadConfig: loadUserConfig}, "agent", command, "--socket="+filepath.Join(dir, "absent.sock"))
				if err == nil {
					t.Fatalf("%s ignored CLI socket override", command)
				}
			}
			conn, err := net.Dial("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			client := sshagent.NewClient(conn)
			lockErr := client.Lock([]byte("test-lock"))
			if (lockErr == nil) != tc.enabled {
				t.Fatalf("mutation permission enabled=%v: Lock returned %v", tc.enabled, lockErr)
			}
			if tc.enabled {
				if err := client.Unlock([]byte("test-lock")); err != nil {
					t.Fatal(err)
				}
			}
			stdout, _, err := agentConfigExecute(ctx, dependencies{loadConfig: loadUserConfig}, "agent", "reset-state")
			if err == nil || stdout != "" {
				t.Fatalf("reset active configured state: %q, %v", stdout, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "sshx")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("configured start created default runtime: %v", err)
			}
		})
	}
}

func TestAgentConfigResetStatePrecedence(t *testing.T) {
	dir := agentCLIHome(t)
	configured := filepath.Join(dir, "configured-state.json")
	cli := filepath.Join(dir, "cli-state.json")
	defaultState, err := agent.DefaultMutationStatePath()
	if err != nil {
		t.Fatal(err)
	}
	const suppressed = `{"version":1,"suppressed":[],"suppress_all":true}`
	const reset = `{"version":1,"suppressed":[],"suppress_all":false}`
	for _, tc := range []struct {
		name, path string
		flags      []string
	}{
		{"configured", configured, nil},
		{"cli", cli, []string{"--state-file=" + cli}},
		{"clear", defaultState, []string{"--state-file="}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{configured, cli, defaultState} {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(suppressed), 0600); err != nil {
					t.Fatal(err)
				}
			}
			agentConfigFile(t, "agent:\n  state-file: "+configured)
			loads := 0
			stdout, _, err := agentConfigExecute(context.Background(), dependencies{loadConfig: func() (optionOverrides, error) { loads++; return loadUserConfig() }}, append([]string{"agent", "reset-state"}, tc.flags...)...)
			if err != nil || loads != 1 || !strings.Contains(stdout, "state reset") {
				t.Fatalf("reset: loads=%d output=%q error=%v", loads, stdout, err)
			}
			for _, path := range []string{configured, cli, defaultState} {
				want := suppressed
				if path == tc.path {
					want = reset
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("state %s = %q, %v; want %q", path, got, err, want)
				}
			}
		})
	}
}

func TestAgentConfigRunPrivateSocketAndVerbosePrecedence(t *testing.T) {
	dir := agentCLIHome(t)
	configuredSocket := filepath.Join(dir, "configured.sock")
	state := filepath.Join(dir, "configured-state.json")
	agentConfigFile(t, fmt.Sprintf("verbose: false\nagent:\n  verbose: true\n  socket: %s\n  state-file: %s\n  allow-key-mutations: true\n  allow-forwarding: true\n  cache-ttl: 1s\n", configuredSocket, state))
	t.Setenv("SSHX_AGENT_CHILD_TEST", "1")
	t.Setenv("SSHX_AGENT_CHILD_MODE", "argv")
	for _, tc := range []struct {
		name    string
		flags   []string
		verbose bool
	}{
		{"file", nil, true},
		{"false-before", []string{"--verbose=false"}, false},
		{"false-after", []string{"--verbose=false"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"agent"}
			if tc.name == "false-before" {
				args = append(args, tc.flags...)
			}
			args = append(args, "run")
			if tc.name == "false-after" {
				args = append(args, tc.flags...)
			}
			args = append(args, "--", os.Args[0], "-test.run=^TestManagedAgentChild$", "--", "with spaces", "$(touch never)", ";literal", "-x")
			loads := 0
			stdout, stderr, err := agentConfigExecute(context.Background(), dependencies{
				loadConfig: func() (optionOverrides, error) { loads++; return loadUserConfig() },
				secretServiceStore: func(context.Context) (credentialStore, error) {
					t.Fatal("agent opened password backend")
					return nil, nil
				},
				runProgram: func(string, []string, []byte) error { t.Fatal("agent used password runner"); return nil },
			}, args...)
			if err != nil || loads != 1 || strings.Contains(stderr, "diagnostics enabled") != tc.verbose {
				t.Fatalf("run: loads=%d stdout=%q stderr=%q error=%v", loads, stdout, stderr, err)
			}
			socket := strings.TrimSpace(stdout)
			if socket == configuredSocket || !strings.HasPrefix(socket, filepath.Join(dir, "sshx", "run-")) {
				t.Fatalf("run did not use private socket: %q", socket)
			}
			if _, err := os.Stat(filepath.Dir(socket)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("run directory survived: %v", err)
			}
			if _, err := os.Stat(configuredSocket); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("run touched configured socket: %v", err)
			}
			if _, err := os.Stat(state); err != nil {
				t.Fatalf("run ignored configured mutation state: %v", err)
			}
		})
	}
}

func TestAgentConfigPasswordAndAgentIsolation(t *testing.T) {
	for _, command := range []string{"ssh", "scp", "credentials"} {
		t.Run(command, func(t *testing.T) {
			file := configForTest(t, "credential-backend: gopass\ngopass-prefix: infra\nverbose: false\noptions: '-o ConnectTimeout=10'\nagent:\n  verbose: true\n  allow-forwarding: true\n  allow-key-mutations: true\n  cache-ttl: 5m\n  prompt-helper: /nonexistent/helper\n  socket: /nonexistent/socket\n  state-file: /nonexistent/state")
			store := &recordingStore{entries: gopassCredentialRefs("infra/user@host")}
			runner := &recordingRunner{}
			loads := 0
			args := []string{"ssh", "user@host"}
			wantProgram := "ssh"
			wantArgs := []string{"-o", "ConnectTimeout=10", "user@host"}
			if command == "scp" {
				args = []string{"scp", "user@host", "local", ":/remote"}
				wantProgram = "scp"
				wantArgs = []string{"-o", "ConnectTimeout=10", "local", "user@host:/remote"}
			}
			if command == "credentials" {
				args = []string{"credentials", "list", "user@host"}
				wantProgram = ""
				wantArgs = nil
			}
			_, stderr, err := agentConfigExecute(context.Background(), dependencies{goos: "darwin", gopassStore: store, runProgram: runner.run,
				loadConfig: func() (optionOverrides, error) { loads++; return file, nil },
			}, args...)
			if err != nil || loads != 1 || stderr != "" || store.searchPrefix != "infra" || runner.program != wantProgram || !reflect.DeepEqual(runner.args, wantArgs) {
				t.Fatalf("password command inherited agent settings: loads=%d store=%#v runner=%#v stderr=%q error=%v", loads, store, runner, stderr, err)
			}
		})
	}
	// Top-level password verbosity/options do not enable agent diagnostics or
	// become arguments to the managed child.
	agentCLIHome(t)
	file := configForTest(t, "verbose: true\noptions: '-o ConnectTimeout=10'\ncredential-backend: secret-service\nsecret-collection: Login")
	stdout, stderr, err := agentConfigExecute(context.Background(), dependencies{loadConfig: func() (optionOverrides, error) { return file, nil },
		secretServiceStore: func(context.Context) (credentialStore, error) {
			t.Fatal("agent opened password backend")
			return nil, nil
		},
	}, "agent", "run", "--", "sh", "-c", "printf child-output")
	if err != nil || stdout != "child-output" || stderr != "" {
		t.Fatalf("agent inherited password options: stdout=%q stderr=%q error=%v", stdout, stderr, err)
	}
}
