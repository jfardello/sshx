package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func selectionPromptOutput(t *testing.T, master *os.File) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var output []byte
	for !bytes.Contains(output, []byte("Choice (0 cancels): ")) {
		if err := registrationTTYPoll(ctx, int(master.Fd()), unix.POLLIN); err != nil {
			t.Fatal("missing menu", err)
		}
		var chunk [1024]byte
		n, err := unix.Read(int(master.Fd()), chunk[:])
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, chunk[:n]...)
		if len(output) > 10000 {
			t.Fatal("unexpected menu")
		}
	}
	return string(output)
}

func TestTerminalSelectionNumericInput(t *testing.T) {
	for _, tc := range []struct {
		name, input  string
		index        int
		cancel, fail bool
	}{
		{"second", "2\n", 1, false, false}, {"editing", "12\x7f\x7f2\n", 1, false, false},
		{"zero", "0\n", -1, true, true}, {"empty", "\n", -1, true, true}, {"eof", "\x04", -1, true, true},
		{"interrupt", "\x03", -1, true, true}, {"quit", "\x1c", -1, true, true}, {"suspend", "\x1a", -1, true, true},
		{"invalid", "a\n", -1, false, true}, {"range", "3\n", -1, false, true}, {"bound", "12345\n", -1, false, true},
		{"kill-line", "2\x151\n", 0, false, false},
		{"pasted-ahead", "2\nSHOULD-BE-DISCARDED\n", 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, _, fd := registrationPTY(t)
			before := registrationSettings(t, fd)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type result struct {
				index int
				err   error
			}
			done := make(chan result, 1)
			go func() {
				index, err := selectTerminalCredentialFD(ctx, fd, gopassCredentialRefs("a/host", "b/host"))
				done <- result{index, err}
			}()
			menu := selectionPromptOutput(t, master)
			if !strings.Contains(menu, "0. Cancel") {
				t.Fatal("no cancel option")
			}
			if _, err := master.Write([]byte(tc.input)); err != nil {
				t.Fatal(err)
			}
			var got result
			select {
			case got = <-done:
			case <-ctx.Done():
				t.Fatal("selector did not finish")
			}
			if got.index != tc.index || (got.err != nil) != tc.fail || (tc.cancel && !errors.Is(got.err, context.Canceled)) {
				t.Fatalf("index=%d err=%v", got.index, got.err)
			}
			if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
				t.Fatal("terminal state not restored")
			}
			// A subsequent reader sees fresh input: there is no picker goroutine
			// or buffered reader left to consume SSH's terminal input.
			if _, err := master.Write([]byte("remote-input\n")); err != nil {
				t.Fatal(err)
			}
			if err := registrationTTYPoll(ctx, fd, unix.POLLIN); err != nil {
				t.Fatal(err)
			}
			var input [64]byte
			n, err := unix.Read(fd, input[:])
			if err != nil || string(input[:n]) != "remote-input\n" {
				t.Fatalf("terminal input stolen or paste retained: %q %v", input[:n], err)
			}
		})
	}
}

func TestTerminalSelectionCancellationAndRendering(t *testing.T) {
	master, _, fd := registrationPTY(t)
	before := registrationSettings(t, fd)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := selectTerminalCredentialFD(ctx, fd, []credentialRef{{Backend: credentialBackendSecretService, Label: "host\n\x1b\u202e<b>", Target: "alice@host", Collection: "Login"}})
		done <- err
	}()
	menu := selectionPromptOutput(t, master)
	if strings.ContainsAny(menu, "\x1b<\u202e") || !strings.Contains(menu, `\u202e`) || !strings.Contains(menu, `\n`) {
		t.Fatal("unsafe menu", menu)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop reader")
	}
	if !reflect.DeepEqual(before, registrationSettings(t, fd)) {
		t.Fatal("cancel did not restore terminal")
	}
}

func TestSSHSelectionSubprocess(t *testing.T) {
	mode := os.Getenv("SSHX_TEST_SHELL_PICKER")
	if mode == "" {
		return
	}
	store := &recordingStore{entries: gopassCredentialRefs("a/alice@host", "b/alice@host")}
	var before *unix.Termios
	if mode != "missing" {
		before = registrationSettings(t, 3)
	}
	ran := false
	err := executeSSH([]string{"--ui=shell"}, dependencies{ctx: context.Background(), goos: "darwin", gopassStore: store, stdout: os.Stdout, stderr: os.Stderr,
		runProgram: func(string, []string, []byte) error {
			ran = true
			if !reflect.DeepEqual(before, registrationSettings(t, 3)) {
				t.Fatal("PTY handoff before restoration")
			}
			input, err := io.ReadAll(os.Stdin)
			if err != nil || string(input) != "redirected-stdin-marker" {
				t.Fatal("picker consumed stdin")
			}
			_, err = os.Stdout.WriteString("ssh-output\n")
			return err
		}})
	if mode == "success" {
		if err != nil || !ran || store.passwordEntry != "b/alice@host" {
			t.Fatal("selection failed", err)
		}
	} else if mode == "missing" {
		if !errors.Is(err, errSelectionTTY) {
			t.Fatal("no TTY did not fail", err)
		}
	} else {
		var status interface{ Code() int }
		if !errors.As(err, &status) || status.Code() != 130 {
			t.Fatal("cancellation did not return 130", err)
		}
	}
	if mode != "success" && (ran || store.secretCalls != 0) {
		t.Fatal("cancellation read password or launched SSH")
	}
}

func TestShellPickerControllingTTY(t *testing.T) {
	for _, mode := range []string{"success", "cancel", "missing", "external-suspend"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHSelectionSubprocess$")
			cmd.Env = append(os.Environ(), "SSHX_TEST_SHELL_PICKER="+mode)
			cmd.Stdin = strings.NewReader("redirected-stdin-marker")
			var out, diagnostic bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &diagnostic
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
			if mode != "missing" {
				selectionPromptOutput(t, master)
				input := "2\n"
				if mode == "cancel" {
					input = "0\n"
				}
				if mode == "external-suspend" {
					if err := cmd.Process.Signal(syscall.SIGTSTP); err != nil {
						t.Fatal(err)
					}
				} else if _, err := master.Write([]byte(input)); err != nil {
					t.Fatal(err)
				}
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("child %v stdout=%s stderr=%s", err, &out, &diagnostic)
			}
			pattern := `\APASS\n`
			if mode == "success" {
				pattern = `\Assh-output\nPASS\n`
			}
			if testing.CoverMode() != "" {
				pattern += `coverage: [0-9]+\.[0-9]+% of statements\n`
			}
			pattern += `\z`
			if !regexp.MustCompile(pattern).Match(out.Bytes()) || diagnostic.Len() != 0 {
				t.Fatalf("redirected streams changed: %q %q", &out, &diagnostic)
			}
			if mode != "missing" && !reflect.DeepEqual(before, registrationSettings(t, fd)) {
				t.Fatal("child left terminal modified")
			}
		})
	}
}
