package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

var passwordPrompt = regexp.MustCompile(`(?i)assword:[[:space:]]*$`)

type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return "child process exited with a non-zero status"
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

func runPTY(program string, args []string, password []byte, stdin *os.File, stdout io.Writer) (returnErr error) {
	command := exec.Command(program, args...)

	var size *pty.Winsize
	stdinIsTerminal := term.IsTerminal(int(stdin.Fd()))
	if stdinIsTerminal {
		if currentSize, err := pty.GetsizeFull(stdin); err == nil {
			size = currentSize
		}
	}

	ptmx, err := pty.StartWithSize(command, size)
	if err != nil {
		return err
	}

	input := &lockedWriter{w: ptmx}
	sessionDone := make(chan struct{})
	defer close(sessionDone)
	defer ptmx.Close()

	if stdinIsTerminal {
		state, rawErr := term.MakeRaw(int(stdin.Fd()))
		if rawErr != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return rawErr
		}
		defer func() {
			if err := term.Restore(int(stdin.Fd()), state); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("restore terminal: %w", err))
			}
		}()
	}

	resize := make(chan os.Signal, 1)
	if stdinIsTerminal {
		signal.Notify(resize, syscall.SIGWINCH)
		defer signal.Stop(resize)
		go func() {
			for {
				select {
				case <-resize:
					_ = pty.InheritSize(stdin, ptmx)
				case <-sessionDone:
					return
				}
			}
		}()
	}

	forward := make(chan os.Signal, 1)
	signal.Notify(forward, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(forward)
	go func() {
		for {
			select {
			case received := <-forward:
				if unixSignal, ok := received.(syscall.Signal); ok {
					_ = syscall.Kill(-command.Process.Pid, unixSignal)
				}
			case <-sessionDone:
				return
			}
		}
	}()

	go copyInput(stdin, input, sessionDone)

	outputDone := make(chan error, 1)
	go func() {
		outputDone <- copyOutputAndAnswer(ptmx, stdout, input, password)
	}()

	waitErr := command.Wait()
	var readErr error
	select {
	case readErr = <-outputDone:
	case <-time.After(250 * time.Millisecond):
		// Do not wait forever if a daemonized descendant inherited the PTY.
		_ = ptmx.Close()
		readErr = <-outputDone
	}

	if readErr != nil && !errors.Is(readErr, syscall.EIO) && !errors.Is(readErr, os.ErrClosed) {
		return readErr
	}
	if waitErr == nil {
		return nil
	}

	var processExit *exec.ExitError
	if errors.As(waitErr, &processExit) {
		code := processExit.ExitCode()
		if status, ok := processExit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code = 128 + int(status.Signal())
		}
		return &exitCodeError{code: code}
	}
	return waitErr
}

func copyInput(stdin io.Reader, ptyInput io.Writer, sessionDone <-chan struct{}) {
	_, _ = io.Copy(ptyInput, stdin)

	// A PTY cannot be half-closed. Like passh, inject the terminal EOF
	// character periodically after a redirected stdin reaches EOF.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _ = ptyInput.Write([]byte{4})
		case <-sessionDone:
			return
		}
	}
}

func copyOutputAndAnswer(ptyOutput io.Reader, stdout io.Writer, ptyInput io.Writer, password []byte) error {
	buffer := make([]byte, 32*1024)
	cache := make([]byte, 0, 4096)
	answered := false

	for {
		count, err := ptyOutput.Read(buffer)
		if count > 0 {
			chunk := buffer[:count]
			if _, writeErr := stdout.Write(chunk); writeErr != nil {
				return writeErr
			}

			if !answered {
				cache = append(cache, chunk...)
				if len(cache) > 4096 {
					cache = append(cache[:0], cache[len(cache)-4096:]...)
				}
				if passwordPrompt.Match(cache) {
					response := make([]byte, 0, len(password)+1)
					response = append(response, password...)
					response = append(response, '\r')
					_, writeErr := ptyInput.Write(response)
					clearBytes(response)
					if writeErr != nil {
						return writeErr
					}
					answered = true
					cache = cache[:0]
				} else if newline := bytes.LastIndexAny(cache, "\r\n"); newline >= 0 {
					cache = append(cache[:0], cache[newline+1:]...)
				}
			}
		}
		if err != nil {
			return err
		}
	}
}
