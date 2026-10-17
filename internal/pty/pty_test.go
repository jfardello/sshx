package pty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/term"
)

func TestCopyOutputAndAnswer(t *testing.T) {
	var output bytes.Buffer
	var input bytes.Buffer
	err := copyOutputAndAnswer(
		&chunkReader{chunks: [][]byte{[]byte("user@host's pass"), []byte("word: ")}},
		&output,
		&input,
		[]byte("secret"),
	)
	if !errors.Is(err, errReaderDone) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := output.String(), "user@host's password: "; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if got, want := input.String(), "secret\r"; got != want {
		t.Fatalf("PTY input = %q, want %q", got, want)
	}
}

func TestExportedPTYHelpers(t *testing.T) {
	err := &ExitCodeError{code: 23}
	if err.Error() == "" || err.Code() != 23 {
		t.Fatal("exit status contract")
	}
	var output, input bytes.Buffer
	readErr := CopyOutputAndAnswer(&chunkReader{chunks: [][]byte{[]byte("Password: ")}}, &output, &input, []byte("secret"))
	if !errors.Is(readErr, errReaderDone) || input.String() != "secret\r" {
		t.Fatal("exported PTY output helper", readErr)
	}
}

func TestRunPTYConnectsChildAndAnswersPasswordPrompt(t *testing.T) {
	stdin, keepOpen, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer keepOpen.Close()

	var output bytes.Buffer
	err = run("sh", []string{"-c", `
		test -t 0 && test -t 1 && test -t 2 || exit 91
		test "$(tty | sed 's#^/dev/##')" = "$(ps -o tty= -p $$ | tr -d ' ')" || exit 92
		printf 'Password: '
		stty -echo
		IFS= read -r password
		stty echo
		printf '\r\nreceived=%s\r\n' "$password"
	`}, []byte("secret"), stdin, &output, &output, true)
	if err != nil {
		t.Fatalf("runPTY() error = %v; output = %q", err, output.String())
	}
	if !strings.Contains(output.String(), "received=secret") {
		t.Fatalf("output does not contain received password: %q", output.String())
	}
}

func TestRunRedirectedBinaryStreams(t *testing.T) {
	payload := make([]byte, 256*2048)
	for i := range payload {
		payload[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{0, 23} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			stdin, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			var output, diagnostic bytes.Buffer
			err = Run("sh", []string{"-c", `
				test ! -t 0 && test ! -t 1 && test ! -t 2 || exit 91
				stty -echo < /dev/tty
				printf 'Password: ' > /dev/tty
				IFS= read -r password < /dev/tty
				test "$password" = secret || exit 92
				printf 'remote diagnostic\n' >&2
				cat
				exit "$1"
			`, "repro", fmt.Sprint(status)}, []byte("secret"), stdin, &output, &diagnostic)
			if status == 0 && err != nil {
				t.Fatal(err)
			}
			if status != 0 {
				var exit *ExitCodeError
				if !errors.As(err, &exit) || exit.Code() != status {
					t.Fatalf("exit error = %v", err)
				}
			}
			if !bytes.Equal(output.Bytes(), payload) {
				t.Fatalf("binary output changed: got %d bytes, want %d", output.Len(), len(payload))
			}
			if !strings.Contains(diagnostic.String(), "Password: ") || !strings.Contains(diagnostic.String(), "remote diagnostic\n") {
				t.Fatalf("missing diagnostics: %q", diagnostic.String())
			}
			if strings.Contains(diagnostic.String(), "secret") {
				t.Fatal("password echoed")
			}
		})
	}
}

func TestRunRedirectedPipeEOF(t *testing.T) {
	stdin, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer writer.Close()
	payload := []byte{0, 4, 10, 13, 255}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var output, diagnostic bytes.Buffer
	if err := Run("cat", nil, nil, stdin, &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), payload) || diagnostic.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", output.Bytes(), diagnostic.Bytes())
	}
}

func TestRunRedirectedOutputAcceptsTerminalInput(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	diagnostic := &promptReplyWriter{terminal: master}
	err = Run("sh", []string{"-c", `
		printf 'Continue? ' > /dev/tty
		IFS= read -r answer < /dev/tty
		test "$answer" = yes || exit 91
		stty -echo < /dev/tty
		printf 'Password: ' > /dev/tty
		IFS= read -r password < /dev/tty
		test "$password" = secret || exit 92
		printf '\000\004\012\015\377'
	`}, []byte("secret"), slave, &output, diagnostic)
	if err != nil {
		t.Fatalf("run: %v; stderr=%q", err, diagnostic.String())
	}
	if !bytes.Equal(output.Bytes(), []byte{0, 4, 10, 13, 255}) {
		t.Fatalf("binary output changed: %q", output.Bytes())
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal state was not restored: %v", err)
	}
}

type promptReplyWriter struct {
	bytes.Buffer
	terminal io.Writer
	replied  bool
}

func (w *promptReplyWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if !w.replied && strings.Contains(w.String(), "Continue? ") {
		w.replied = true
		_, err = io.WriteString(w.terminal, "yes\n")
	}
	return n, err
}

func TestRunSelectsInteractiveOnlyForThreeTerminals(t *testing.T) {
	for _, redirected := range []string{"none", "stdin", "stdout", "stderr"} {
		t.Run(redirected, func(t *testing.T) {
			master, slave, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer slave.Close()
			stdin := slave
			var stdout, stderr io.Writer = slave, slave
			var output bytes.Buffer
			switch redirected {
			case "stdin":
				stdin, err = os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer stdin.Close()
			case "stdout":
				stdout = &output
			case "stderr":
				stderr = &output
			}
			// Only the all-terminal path puts stdout and stderr on the same
			// terminal as stdin. Redirected paths preserve their own descriptors.
			script := `test -t 0 && test -t 1 && test -t 2 && test "$(tty)" = "$(ps -o tty= -p $$ | sed 's/^ */\/dev\//')"`
			if redirected != "none" {
				script = "! (" + script + ")"
			}
			if err := Run("sh", []string{"-c", script}, nil, stdin, stdout, stderr); err != nil {
				t.Fatal(err)
			}
		})
	}
}

var errReaderDone = errors.New("done")

type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, errReaderDone
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return copy(p, chunk), nil
}
