package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jfardello/sshx/internal/agent"
)

const agentSocketUnit = "sshx-agent.socket"
const agentServiceUnit = "sshx-agent.service"

func systemdAgentSocket(explicit string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("systemd user agents are supported only on Linux")
	}
	if explicit != "" {
		return explicit, nil
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	if err := agent.ValidateDirectory(base); err != nil {
		return "", errors.New("systemd agent requires a trusted owner-only XDG_RUNTIME_DIR")
	}
	return filepath.Join(base, "sshx-agent", "agent.sock"), nil
}

type agentManager struct {
	goos string
	run  func(context.Context, ...string) ([]byte, error)
}

func newAgentManager(deps dependencies) agentManager {
	goos := deps.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	run := deps.systemctl
	if run == nil {
		run = func(ctx context.Context, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, "systemctl", args...)
			cmd.Env = managedAgentEnvironment(os.Environ(), "")
			cmd.WaitDelay = time.Second
			return cmd.Output()
		}
	}
	return agentManager{goos: goos, run: run}
}

func (m agentManager) command(ctx context.Context, args ...string) ([]byte, error) {
	if m.goos != "linux" {
		return nil, errors.New("systemd user agents are supported only on Linux")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := m.run(ctx, append([]string{"--user", "--no-pager", "--no-ask-password"}, args...)...)
	if err != nil {
		return nil, errors.New("systemd user operation failed; check the user manager and sshx-agent units")
	}
	return output, nil
}

func (m agentManager) stop(ctx context.Context) error {
	// Do not stop the service if stopping the activation source failed.
	if _, err := m.command(ctx, "stop", agentSocketUnit); err != nil {
		return fmt.Errorf("could not stop agent socket: %w", err)
	}
	if _, err := m.command(ctx, "stop", agentServiceUnit); err != nil {
		return fmt.Errorf("agent socket stopped but service stop failed: %w", err)
	}
	return nil
}

func (m agentManager) status(ctx context.Context, out io.Writer) error {
	ready := true
	for _, unit := range []string{agentSocketUnit, agentServiceUnit} {
		output, err := m.command(ctx, "show", "--property=LoadState,ActiveState,SubState", unit)
		if err != nil {
			return fmt.Errorf("could not inspect %s: %w", unit, err)
		}
		values := make(map[string]string)
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || (key != "LoadState" && key != "ActiveState" && key != "SubState") || values[key] != "" || !unitStateWord(value) {
				return errors.New("invalid systemd unit state response")
			}
			values[key] = value
		}
		if len(values) != 3 {
			return errors.New("incomplete systemd unit state response")
		}
		if _, err := fmt.Fprintf(out, "%s: %s, %s/%s\n", unit, values["LoadState"], values["ActiveState"], values["SubState"]); err != nil {
			return err
		}
		if values["LoadState"] != "loaded" || values["ActiveState"] == "failed" || (unit == agentSocketUnit && (values["ActiveState"] != "active" || values["SubState"] != "listening")) {
			ready = false
		}
	}
	if _, err := fmt.Fprintln(out, "Credential backend readiness: not checked (no connection or signing attempted)"); err != nil {
		return err
	}
	if !ready {
		return errors.New("systemd agent is not ready for socket activation")
	}
	return nil
}

func unitStateWord(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if c != '-' && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
