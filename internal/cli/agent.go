package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jfardello/sshx/internal/agent"
	"github.com/jfardello/sshx/internal/keystore"
	"github.com/spf13/cobra"
)

func newAgentCommand(deps dependencies) *cobra.Command {
	root := &cobra.Command{Use: "agent", Short: "Run and inspect the native SSH agent", Args: cobra.NoArgs}
	root.SetOut(deps.stdout)
	root.SetErr(deps.stderr)
	var startSocket, envSocket, statusSocket, shell string
	var foreground, activation, envSystemd, statusSystemd, stopSystemd bool
	var verbose bool
	var promptHelper string
	var cacheTTL time.Duration
	root.PersistentFlags().DurationVar(&cacheTTL, "cache-ttl", 0, "absolute signer cache lifetime (0 disables; maximum 5m)")
	root.PersistentFlags().StringVar(&promptHelper, "prompt-helper", "", "absolute path to trusted local confirmation/passphrase helper")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "write secret-safe agent diagnostics to stderr")
	diagnosticWriter := func(cmd *cobra.Command) io.Writer {
		if verbose {
			return cmd.ErrOrStderr()
		}
		return nil
	}
	manager := newAgentManager(deps)
	start := &cobra.Command{Use: "start --foreground", Short: "Serve until interrupted", Args: cobra.NoArgs}
	start.Flags().BoolVar(&foreground, "foreground", false, "serve in the foreground (required)")
	start.Flags().StringVar(&startSocket, "socket", "", "socket in an existing private directory")
	start.Flags().BoolVar(&activation, "socket-activation", false, "consume a systemd listening descriptor (Linux)")
	start.RunE = func(cmd *cobra.Command, _ []string) error {
		if !foreground {
			return errors.New("agent start requires --foreground; start managed activation with systemctl --user start sshx-agent.socket")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()
		var name string
		var err error
		if activation {
			name, err = systemdAgentSocket(startSocket)
		} else {
			name, err = agentSocketPath(startSocket, true)
		}
		if err != nil {
			return err
		}
		server, err := startAgentMode(context.WithValue(context.WithValue(ctx, agentCacheTTLContext{}, cacheTTL), agentPromptHelperContext{}, promptHelper), name, activation, diagnosticWriter(cmd))
		if err != nil {
			return err
		}
		defer server.Close()
		return errors.Join(server.Serve(ctx), server.Close())
	}
	// startAgent binds synchronously; run additionally probes the serving loop
	// before launching a child. Foreground start enters that loop directly.
	env := &cobra.Command{Use: "env", Short: "Print shell assignments for an existing agent", Args: cobra.NoArgs}
	env.Flags().StringVar(&shell, "shell", "sh", "assignment syntax: sh or zsh")
	env.Flags().StringVar(&envSocket, "socket", "", "existing agent socket")
	env.Flags().BoolVar(&envSystemd, "systemd", false, "use the systemd socket, activating the service if necessary")
	env.RunE = func(cmd *cobra.Command, _ []string) error {
		if shell != "sh" && shell != "zsh" {
			return fmt.Errorf("unsupported shell %q (expected sh or zsh)", shell)
		}
		var name string
		var err error
		if envSystemd {
			name, err = systemdAgentSocket(envSocket)
		} else {
			name, err = agentSocketPath(envSocket, false)
		}
		if err != nil {
			return err
		}
		if err := agent.Probe(cmd.Context(), name); err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\nunset SSH_AGENT_PID;\n", quoteShell(name))
		return err
	}
	status := &cobra.Command{Use: "status", Short: "Check the socket without reading private keys", Args: cobra.NoArgs}
	status.Flags().StringVar(&statusSocket, "socket", "", "existing agent socket")
	status.Flags().BoolVar(&statusSystemd, "systemd", false, "inspect socket and service units without activating them")
	status.MarkFlagsMutuallyExclusive("socket", "systemd")
	status.RunE = func(cmd *cobra.Command, _ []string) error {
		if statusSystemd {
			return manager.status(cmd.Context(), cmd.OutOrStdout())
		}
		name, err := agentSocketPath(statusSocket, false)
		if err == nil {
			err = agent.Probe(cmd.Context(), name)
		}
		if err != nil {
			return fmt.Errorf("agent endpoint unavailable: %w", err)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Agent endpoint: available\nCredential backend readiness: not checked (no signing attempted)")
		return err
	}
	run := &cobra.Command{Use: "run -- command [args...]", Short: "Run a command with a private agent", Args: cobra.MinimumNArgs(1)}
	run.RunE = func(cmd *cobra.Command, args []string) error {
		if cmd.ArgsLenAtDash() != 0 {
			return errors.New("use agent run -- command [args...]")
		}
		return runWithAgent(context.WithValue(context.WithValue(cmd.Context(), agentCacheTTLContext{}, cacheTTL), agentPromptHelperContext{}, promptHelper), args, os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), diagnosticWriter(cmd))
	}
	stop := &cobra.Command{Use: "stop", Short: "Stop the systemd socket and service, or explain foreground shutdown", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if stopSystemd {
				return manager.stop(cmd.Context())
			}
			return errors.New("stop a foreground agent with Ctrl-C; use agent stop --systemd for the systemd user units")
		}}
	stop.Flags().BoolVar(&stopSystemd, "systemd", false, "stop the user socket before stopping its service")
	root.AddCommand(start, env, status, run, stop)
	return root
}

func quoteShell(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func agentRuntimeDirectory(create bool) (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	var directory string
	if base != "" {
		if !filepath.IsAbs(base) || filepath.Clean(base) != base {
			return "", errors.New("XDG_RUNTIME_DIR must be an absolute clean path")
		}
		if err := agent.ValidateDirectory(base); err != nil {
			return "", err
		}
		directory = filepath.Join(base, "sshx")
	} else {
		// /tmp is a root-managed symlink on macOS. Resolve only this fixed
		// platform path; the resulting private directory and all ancestors
		// still undergo the agent's ownership and no-symlink validation.
		temporary, err := filepath.EvalSymlinks("/tmp")
		if err != nil {
			return "", err
		}
		directory = filepath.Join(temporary, fmt.Sprintf("sshx-%d", os.Geteuid()))
	}
	if create {
		if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	if err := agent.ValidateDirectory(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func agentSocketPath(explicit string, create bool) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	directory, err := agentRuntimeDirectory(create)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "agent.sock"), nil
}

type agentPromptHelperContext struct{}
type agentCacheTTLContext struct{}

func startAgent(ctx context.Context, socket string) (*agent.Server, error) {
	return startAgentMode(ctx, socket, false)
}

func startAgentMode(ctx context.Context, socket string, activation bool, diagnostics ...io.Writer) (*agent.Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	registry, err := agent.LoadRegistry()
	if err != nil {
		return nil, err
	}
	var server *agent.Server
	if activation {
		server, err = agent.NewActivatedServer(socket, registry, keystore.Open)
	} else {
		server, err = agent.NewServer(socket, registry, keystore.Open)
	}
	if err == nil {
		if helper, _ := ctx.Value(agentPromptHelperContext{}).(string); helper != "" {
			if err = server.SetPromptHelper(helper); err != nil {
				_ = server.Close()
				return nil, err
			}
		}
	}
	if err == nil {
		ttl, _ := ctx.Value(agentCacheTTLContext{}).(time.Duration)
		if err = server.SetCacheTTL(ttl); err != nil {
			_ = server.Close()
			return nil, err
		}
	}
	if err == nil && len(diagnostics) > 0 {
		server.SetDiagnostics(diagnostics[0])
	}
	return server, err
}

func managedAgentEnvironment(inherited []string, socket string) []string {
	env := make([]string, 0, len(inherited)+1)
	for _, value := range inherited {
		name, _, _ := strings.Cut(value, "=")
		switch name {
		case "SSH_AUTH_SOCK", "SSH_AGENT_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID":
			continue
		}
		env = append(env, value)
	}
	return append(env, "SSH_AUTH_SOCK="+socket)
}

type agentCommandExit struct{ code int }

func (e *agentCommandExit) Error() string { return "agent command exited with a non-zero status" }
func (e *agentCommandExit) Code() int     { return e.code }

func runWithAgent(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer, diagnostics ...io.Writer) (returnErr error) {
	// Register before setup so a termination signal cannot strand a new socket.
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	base, err := agentRuntimeDirectory(true)
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp(base, "run-")
	if err != nil {
		return err
	}
	owned, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	defer func() {
		// Remove only the empty directory we created; preserve replacements.
		if current, err := os.Lstat(directory); err == nil && os.SameFile(owned, current) {
			returnErr = errors.Join(returnErr, os.Remove(directory))
		}
	}()
	socket := filepath.Join(directory, "agent.sock")
	server, err := startAgentMode(ctx, socket, false, diagnostics...)
	if err != nil {
		return err
	}
	serving, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serving) }()
	defer func() {
		cancel()
		returnErr = errors.Join(returnErr, server.Close(), <-done)
	}()
	if err := agent.Probe(ctx, socket); err != nil {
		return fmt.Errorf("agent did not become ready: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case sig := <-signals:
		return &agentCommandExit{128 + int(sig.(syscall.Signal))}
	default:
	}
	child := exec.Command(argv[0], argv[1:]...)
	child.Env = managedAgentEnvironment(os.Environ(), socket)
	child.Stdin, child.Stdout, child.Stderr = stdin, stdout, stderr
	// Keep the foreground terminal process group, allowing interactive ssh/git
	// to read the terminal normally. No shell or PTY is inserted.
	child.WaitDelay = time.Second
	if err := child.Start(); err != nil {
		return err
	}
	wait := make(chan error, 1)
	go func() { wait <- child.Wait() }()
	var kill <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	cancelled := ctx.Done()
	for {
		select {
		case err := <-wait:
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code := exit.ExitCode()
				if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
					code = 128 + int(status.Signal())
				}
				return &agentCommandExit{code}
			}
			return err
		case sig := <-signals:
			_ = child.Process.Signal(sig)
			if timer == nil {
				timer = time.NewTimer(2 * time.Second)
				kill = timer.C
			}
		case <-cancelled:
			cancelled = nil
			_ = child.Process.Signal(syscall.SIGTERM)
			if timer == nil {
				timer = time.NewTimer(2 * time.Second)
				kill = timer.C
			}
		case <-kill:
			kill = nil
			_ = child.Process.Kill()
		}
	}
}
