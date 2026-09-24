package pty

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
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
	err = Run("sh", []string{"-c", `
		test -t 0 && test -t 1 && test -t 2 || exit 91
		test "$(tty | sed 's#^/dev/##')" = "$(ps -o tty= -p $$ | tr -d ' ')" || exit 92
		printf 'Password: '
		stty -echo
		IFS= read -r password
		stty echo
		printf '\r\nreceived=%s\r\n' "$password"
	`}, []byte("secret"), stdin, &output)
	if err != nil {
		t.Fatalf("runPTY() error = %v; output = %q", err, output.String())
	}
	if !strings.Contains(output.String(), "received=secret") {
		t.Fatalf("output does not contain received password: %q", output.String())
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
