// Package helperexec executes explicitly trusted local helpers over private
// pipes. It does not interpret requests or responses, approve operations, impose
// a concurrency policy, or choose an operation deadline. Callers own those rules.
package helperexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jfardello/sshx/internal/sensitive"
)

var (
	ErrUnavailable = errors.New("trusted helper unavailable")
	ErrFailed      = errors.New("trusted helper execution failed")
)

// Limits are supplied by each protocol's caller. Both values must be positive;
// a larger limit for one caller never changes the limits used by another.
type Limits struct {
	RequestBytes  int
	ResponseBytes int
}

// Trusted checks an absolute, clean executable path and all its ancestors.
// Symlinks and group/other-writable paths are rejected, except root-owned sticky
// ancestors above the executable's parent. Ownership must be the current UID or
// root. This checks pathnames, not retained executable/directory handles: the
// same user or root can still replace paths between validation and execution.
// The executable's interpreter, libraries and imports are also trusted code.
func Trusted(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	current := "/"
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if info.Mode().Perm()&0022 != 0 && !(i < len(parts)-2 && st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return false
		}
		if i == len(parts)-1 {
			return info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
		}
		if !info.IsDir() {
			return false
		}
	}
	return false
}

// environment passes only fixed PATH/LANG and local home/desktop routing.
// Credential, loader, agent-socket and arbitrary caller variables are excluded.
func environment() []string {
	env := []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	for _, key := range []string{"HOME", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

type boundedOutput struct {
	data   []byte
	limit  int
	cancel context.CancelFunc
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		// A helper might keep running after filling its output pipe. Stop its
		// process group immediately rather than waiting for the caller deadline.
		b.cancel()
		return 0, ErrFailed
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// Run rechecks path trust and invokes exactly that executable with no arguments,
// no shell, a curated environment, and cwd "/". The caller must bound its context
// and concurrent invocations. Cancellation kills the helper's process group;
// remaining members of that group are also killed on completion. Descendants
// that deliberately leave the process group are not contained by this mechanism.
//
// Input is borrowed and never modified. A successful response is owned by the
// caller, which must clear it when no longer needed. Failed response buffers are
// cleared here. Go and subprocess I/O may retain copies outside these buffers.
// Errors contain no request, response, path, stderr, or underlying process error.
func Run(ctx context.Context, path string, input []byte, limits Limits) (response []byte, returnErr error) {
	if !Trusted(path) {
		return nil, ErrUnavailable
	}
	if limits.RequestBytes <= 0 || limits.ResponseBytes <= 0 || len(input) > limits.RequestBytes {
		return nil, ErrFailed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = environment()
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(input)
	// Allocate once to avoid leaving old response arrays behind on growth.
	output := boundedOutput{data: make([]byte, 0, limits.ResponseBytes), limit: limits.ResponseBytes, cancel: cancel}
	defer func() {
		if returnErr != nil {
			sensitive.Clear(output.data)
		}
	}()
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	if err := cmd.Wait(); err != nil {
		return nil, ErrFailed
	}
	if ctx.Err() != nil {
		return nil, ErrFailed
	}
	return output.data, nil
}
