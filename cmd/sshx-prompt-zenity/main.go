// sshx-prompt-zenity handles one private signing or credential-selection prompt
// per invocation. Each protocol retains its own validation and resource bounds.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/jfardello/sshx/internal/helperexec"
	"github.com/jfardello/sshx/internal/promptprotocol"
	"github.com/jfardello/sshx/internal/promptzenity"
	"github.com/jfardello/sshx/internal/sensitive"
)

const workerArgument = "--internal-dialog-worker"
const localTimeout = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, localTimeout)
	defer cancel()
	var err error
	switch {
	case len(os.Args) == 1:
		var executable string
		executable, err = os.Executable()
		if err == nil {
			err = supervise(ctx, executable, os.Stdin, os.Stdout)
		}
	case len(os.Args) == 2 && os.Args[1] == workerArgument:
		err = watchSupervisor()
		if err == nil {
			err = promptzenity.Serve(ctx, os.Stdin, os.Stdout, promptzenity.Zenity{})
		}
	default:
		err = promptzenity.ErrFailed
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "desktop prompt failed")
		os.Exit(1)
	}
}

// The agent may SIGKILL the supervisor, so signal handlers alone are insufficient.
// A private pipe closes on supervisor death, including SIGKILL. The worker then
// kills its own group, including native dialogs. fd 3 contains no request/secret.
func watchSupervisor() error {
	parent := os.NewFile(3, "supervisor-lifetime")
	if parent == nil {
		return promptzenity.ErrFailed
	}
	info, err := parent.Stat()
	group, groupErr := syscall.Getpgid(0)
	if err != nil || groupErr != nil || group != os.Getpid() || info.Mode()&os.ModeNamedPipe == 0 {
		_ = parent.Close()
		return promptzenity.ErrFailed
	}
	syscall.CloseOnExec(3)
	go func() {
		_, _ = io.Copy(io.Discard, parent)
		_ = parent.Close()
		_ = syscall.Kill(-group, syscall.SIGKILL)
	}()
	return nil
}

type responseBuffer struct {
	data   []byte
	cancel context.CancelFunc
}

func (b *responseBuffer) Write(p []byte) (int, error) {
	if len(p) > promptprotocol.MaxBytes-len(b.data) {
		b.cancel()
		return 0, promptzenity.ErrFailed
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// supervise isolates the library and its native dialog in a process group.
// Unlike the public agent/helper interface, this private self-invocation has one
// fixed argument. No user-supplied executable, command or arguments are accepted.
// The library kills only its immediate child on context cancellation; the
// supervisor kills the worker and all descendants remaining in the group even
// when Output is blocked by a descendant retaining a pipe. Deliberately detached
// descendants are outside this mechanism, as in the agent's helper executor.
func supervise(ctx context.Context, executable string, in *os.File, out io.Writer) error {
	if !helperexec.Trusted(executable) {
		return promptzenity.ErrFailed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lifetime, alive, err := os.Pipe()
	if err != nil {
		return promptzenity.ErrFailed
	}
	defer lifetime.Close()
	defer alive.Close()
	cmd := exec.CommandContext(ctx, executable, workerArgument)
	cmd.ExtraFiles = []*os.File{lifetime}
	cmd.Dir = "/"
	// This process is itself launched with the agent's curated environment.
	// Curate again for standalone invocations, excluding sockets and loader vars.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	for _, key := range []string{"HOME", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Stdin = in
	response := responseBuffer{data: make([]byte, 0, promptprotocol.MaxBytes), cancel: cancel}
	defer func() { sensitive.Clear(response.data) }()
	cmd.Stdout = &response
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	if cmd.Start() != nil {
		return promptzenity.ErrFailed
	}
	_ = lifetime.Close()
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	if cmd.Wait() != nil || ctx.Err() != nil {
		return promptzenity.ErrFailed
	}
	n, err := out.Write(response.data)
	if err != nil || n != len(response.data) {
		return promptzenity.ErrFailed
	}
	return nil
}
