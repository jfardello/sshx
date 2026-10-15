package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func registrationPTY(t *testing.T) (*os.File, *os.File, int) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close(); slave.Close() })
	fd, err := unix.Open(slave.Name(), unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return master, slave, fd
}

func registrationSettings(t *testing.T, fd int) *unix.Termios {
	t.Helper()
	get, _, _ := registrationTermiosRequests()
	state, err := unix.IoctlGetTermios(fd, get)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Bound every test-side read too, so a broken prompt cannot hang the suite.
func registrationPromptOutput(t *testing.T, master *os.File) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var output []byte
	for !bytes.Contains(output, []byte(registrationPassphrasePrompt)) {
		if err := registrationTTYPoll(ctx, int(master.Fd()), unix.POLLIN); err != nil {
			t.Fatal("prompt was not written to terminal", err)
		}
		var chunk [128]byte
		n, err := unix.Read(int(master.Fd()), chunk[:])
		if err != nil {
			t.Fatal("reading prompt failed", err)
		}
		output = append(output, chunk[:n]...)
		if len(output) > 512 {
			t.Fatal("unexpected terminal output")
		}
	}
	if string(output) != registrationPassphrasePrompt {
		t.Fatal("unexpected terminal prompt")
	}
	return output
}

func registrationAssertNoEcho(t *testing.T, fd int) {
	t.Helper()
	state := registrationSettings(t, fd)
	if state.Lflag&(unix.ECHO|unix.ECHONL|unix.ICANON|unix.ISIG) != 0 || state.Cc[unix.VMIN] != 1 || state.Cc[unix.VTIME] != 0 {
		t.Fatal("prompt must disable echo, canonical input and terminal signals with VMIN=1/VTIME=0")
	}
}

func registrationAssertOutputSafe(t *testing.T, master *os.File) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := registrationTTYPoll(ctx, int(master.Fd()), unix.POLLIN); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return
		}
		t.Fatal(err)
	}
	{
		var chunk [2048]byte
		n, err := unix.Read(int(master.Fd()), chunk[:])
		if err != nil || strings.Trim(string(chunk[:n]), "\r\n") != "" {
			t.Fatal("terminal output contained more than a fixed prompt and newline")
		}
	}
}

func TestRegistrationPassphrasePTY(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		wantErr           error
	}{
		{"success", "test-secret-marker\n", "test-secret-marker", nil},
		{"spaces", "  test secret  \n", "  test secret  ", nil},
		{"maximum", strings.Repeat("s", maxRegistrationPassphraseBytes) + "\n", strings.Repeat("s", maxRegistrationPassphraseBytes), nil},
		{"too long", strings.Repeat("s", maxRegistrationPassphraseBytes+1) + "\n", "", errRegistrationPassphrase},
		{"empty", "\n", "", errRegistrationPassphrase},
		{"eof", "\x04", "", errRegistrationPassphrase},
		{"partial eof", "test-secret-marker\x04", "test-secret-marker", nil},
		{"erase", "test-secret-markerX\x7f\n", "test-secret-marker", nil},
		{"backspace", "test-secret-markerX\b\n", "test-secret-marker", nil},
		{"UTF8 backspace", "secreté\be\n", "secrete", nil},
		{"UTF8 erase", "secret界\x7fe\n", "secrete", nil},
		{"UTF8 four byte erase", "secret🔑\be\n", "secrete", nil},
		{"invalid byte fallback", "secret\xff\be\n", "secrete", nil},
		{"partial UTF8 fallback", "secret\xe2\x82\be\n", "secret\xe2e", nil},
		{"partial UTF8 interrupt", "secret\xe2\x82\x03", "", context.Canceled},
		{"erase empty", "\b\x7ftest-secret-marker\n", "test-secret-marker", nil},
		{"kill line", "discarded-secret-marker\x15test-secret-marker\n", "test-secret-marker", nil},
		{"kill empty", "\x15test-secret-marker\n", "test-secret-marker", nil},
		{"erase at limit", strings.Repeat("s", maxRegistrationPassphraseBytes) + "\bX\n", strings.Repeat("s", maxRegistrationPassphraseBytes-1) + "X", nil},
		{"kill at limit", strings.Repeat("s", maxRegistrationPassphraseBytes) + "\x15test-secret-marker\n", "test-secret-marker", nil},
		{"interrupt", "unfinished-secret-marker\x03", "", context.Canceled},
		{"quit", "unfinished-secret-marker\x1c", "", context.Canceled},
		{"suspend", "unfinished-secret-marker\x1a", "", context.Canceled},
		{"pasted ahead", "test-secret-marker\nunread-secret-marker\n", "test-secret-marker", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, _, fd := registrationPTY(t)
			// Exercise ECHONL as well as ECHO, even if the PTY default omits it.
			_, set, _ := registrationTermiosRequests()
			settings := registrationSettings(t, fd)
			settings.Lflag |= unix.ECHO | unix.ECHONL
			settings.Cc[unix.VMIN] = 7
			settings.Cc[unix.VTIME] = 3
			if err := unix.IoctlSetTermios(fd, set, settings); err != nil {
				t.Fatal(err)
			}
			before := registrationSettings(t, fd)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type result struct {
				pass []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { pass, err := readRegistrationPassphraseFD(ctx, fd); done <- result{pass, err} }()
			registrationPromptOutput(t, master)
			registrationAssertNoEcho(t, fd)
			if _, err := master.Write([]byte(tc.input)); err != nil {
				t.Fatal("writing test input failed", err)
			}
			r := <-done
			defer clear(r.pass)
			if tc.wantErr != nil {
				if !errors.Is(r.err, tc.wantErr) || r.pass != nil {
					t.Fatal("invalid input did not fail safely")
				}
			} else if r.err != nil || !bytes.Equal(r.pass, []byte(tc.want)) {
				t.Fatal("passphrase was not returned intact")
			}
			if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
				t.Fatal("terminal settings not restored")
			}
			registrationAssertOutputSafe(t, master)
			var pending [64]byte
			if n, err := unix.Read(fd, pending[:]); n != -1 || !errors.Is(err, unix.EAGAIN) {
				t.Fatal("unread input survived prompt exit")
			}
		})
	}
}

func TestRegistrationEraseRuneClearsRemovedBytes(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"ASCII", "secretX", "secret"},
		{"two byte", "secreté", "secret"},
		{"three byte", "secret界", "secret"},
		{"four byte", "secret🔑", "secret"},
		{"replacement rune", "secret\uFFFD", "secret"},
		{"invalid byte", "secret\xff", "secret"},
		{"incomplete rune", "secret\xe2\x82", "secret\xe2"},
		{"valid suffix after invalid byte", "secret\xffé", "secret\xff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buffer := []byte(tc.input)
			defer clear(buffer)
			remaining := registrationEraseRune(buffer)
			if !bytes.Equal(remaining, []byte(tc.want)) {
				t.Fatal("erase did not preserve the expected prefix")
			}
			for _, b := range buffer[len(remaining):] {
				if b != 0 {
					t.Fatal("removed secret bytes were not cleared")
				}
			}
		})
	}
}

// Split the terminator from the 4096-byte input so a canonical queue cannot
// silently truncate the test or make overflow depend on receiving a newline.
func TestRegistrationPassphraseBoundaryWithoutNewline(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(map[bool]string{false: "newline", true: "overflow byte"}[overflow], func(t *testing.T) {
			master, _, fd := registrationPTY(t)
			before := registrationSettings(t, fd)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type result struct {
				pass []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { pass, err := readRegistrationPassphraseFD(ctx, fd); done <- result{pass, err} }()
			registrationPromptOutput(t, master)
			registrationAssertNoEcho(t, fd)
			prefix := bytes.Repeat([]byte("s"), maxRegistrationPassphraseBytes)
			defer clear(prefix)
			if _, err := master.Write(prefix); err != nil {
				t.Fatal("writing boundary input failed", err)
			}
			select {
			case r := <-done:
				clear(r.pass)
				t.Fatal("reader returned before newline or overflow")
			case <-time.After(50 * time.Millisecond):
			}
			suffix := "\n"
			if overflow {
				suffix = "X" // No newline: the first excess byte must fail immediately.
			}
			if _, err := master.Write([]byte(suffix)); err != nil {
				t.Fatal(err)
			}
			r := <-done
			defer clear(r.pass)
			if overflow {
				if r.pass != nil || !errors.Is(r.err, errRegistrationPassphrase) {
					t.Fatal("overflow byte without newline did not fail safely")
				}
			} else if r.err != nil || !bytes.Equal(r.pass, prefix) {
				t.Fatal("4096-byte passphrase was not accepted intact")
			}
			if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
				t.Fatal("terminal settings not restored at boundary")
			}
			registrationAssertOutputSafe(t, master)
		})
	}
}

func TestRegistrationPassphraseCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			master, _, fd := registrationPTY(t)
			before := registrationSettings(t, fd)
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				pass, err := readRegistrationPassphraseFD(ctx, fd)
				if pass != nil {
					clear(pass)
					done <- errors.New("unexpected buffer on cancellation")
					return
				}
				done <- err
			}()
			registrationPromptOutput(t, master)
			registrationAssertNoEcho(t, fd)
			if _, err := master.Write([]byte("unfinished-secret-marker")); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if !deadline {
				cancel()
			}
			err := <-done
			if !errors.Is(err, ctx.Err()) || time.Since(start) > time.Second {
				t.Fatal("cancellation was not explicit and bounded")
			}
			if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
				t.Fatal("terminal settings not restored")
			}
			registrationAssertOutputSafe(t, master)
			// The cancelled partial line must not survive to a later reader.
			var chunk [64]byte
			if n, err := unix.Read(fd, chunk[:]); n != -1 || !errors.Is(err, unix.EAGAIN) {
				t.Fatal("partial input was not discarded")
			}
		})
	}
}

func TestRegistrationPassphraseWriteFailureRestores(t *testing.T) {
	master, slave, fd := registrationPTY(t)
	before := registrationSettings(t, fd)
	readOnly, err := unix.Open(slave.Name(), unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(readOnly)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pass, err := readRegistrationPassphraseFD(ctx, readOnly)
	if pass != nil || !errors.Is(err, errRegistrationPassphrase) {
		t.Fatal("prompt write failure did not return a safe error")
	}
	if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
		t.Fatal("terminal settings not restored after prompt write failure")
	}
	registrationAssertOutputSafe(t, master)
}

func TestRegistrationPassphrasePreCancelledAndInvalidFD(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pass, err := readRegistrationPassphrase(ctx)
	if pass != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled context was ignored")
	}
	pass, err = readRegistrationPassphraseFD(context.Background(), -1)
	if pass != nil || !errors.Is(err, errRegistrationPassphrase) {
		t.Fatal("invalid fd did not fail safely")
	}
}

func TestRegistrationPassphraseSubprocess(t *testing.T) {
	mode := os.Getenv("SSHX_TEST_REGISTRATION_PROMPT")
	if mode == "" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGQUIT, syscall.SIGTSTP)
	defer stop()
	if mode == "pre-interrupt" {
		if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("interrupt not delivered")
		}
	}
	pass, err := readRegistrationPassphrase(ctx)
	defer clear(pass)
	switch mode {
	case "missing":
		if pass != nil || err != errRegistrationTTY || err.Error() != "encrypted SSH key requires a controlling terminal; run registration from a terminal" {
			t.Fatal("missing TTY did not return actionable sentinel")
		}
	case "interrupt", "quit", "suspend", "external-quit", "external-suspend", "pre-interrupt":
		if pass != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("interrupt did not cancel prompt")
		}
	case "success":
		if err != nil || !bytes.Equal(pass, []byte("test-secret-marker")) {
			t.Fatal("controlling terminal input was not used")
		}
	default:
		t.Fatal("invalid test mode")
	}
}

func TestRegistrationPassphraseControllingTTY(t *testing.T) {
	for _, mode := range []string{"missing", "success", "interrupt", "quit", "suspend", "external-quit", "external-suspend", "pre-interrupt"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistrationPassphraseSubprocess$")
			cmd.Env = append(os.Environ(), "SSHX_TEST_REGISTRATION_PROMPT="+mode)
			// Stdin is deliberately unrelated to the controlling terminal.
			cmd.Stdin = strings.NewReader("stdin-must-not-be-read\n")
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			var master *os.File
			var fd int
			var before *unix.Termios
			if mode != "missing" {
				var slave *os.File
				master, slave, fd = registrationPTY(t)
				before = registrationSettings(t, fd)
				cmd.ExtraFiles = []*os.File{slave}
				cmd.SysProcAttr.Setctty = true
				cmd.SysProcAttr.Ctty = 3
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if mode != "missing" && mode != "pre-interrupt" {
				registrationPromptOutput(t, master)
				registrationAssertNoEcho(t, fd)
				input := "test-secret-marker\n"
				switch mode {
				case "interrupt":
					input = "unfinished-secret-marker\x03"
				case "quit":
					input = "unfinished-secret-marker\x1c"
				case "suspend":
					input = "unfinished-secret-marker\x1a"
				case "external-quit", "external-suspend":
					input = "unfinished-secret-marker"
				}
				if _, err := master.Write([]byte(input)); err != nil {
					t.Fatal(err)
				}
				if mode == "external-quit" || mode == "external-suspend" {
					sig := syscall.SIGQUIT
					if mode == "external-suspend" {
						sig = syscall.SIGTSTP
					}
					if err := cmd.Process.Signal(sig); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal("prompt subprocess failed", err)
			}
			if strings.TrimSpace(output.String()) != "PASS" {
				t.Fatal("prompt wrote unexpected stdout/stderr")
			}
			if master != nil {
				if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
					t.Fatal("terminal settings not restored after subprocess")
				}
				registrationAssertOutputSafe(t, master)
			}
		})
	}
}
