package main

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseCommandOptionsPreservesOriginalSyntax(t *testing.T) {
	got, err := parseCommandOptions([]string{
		"user@example.com",
		"-x", "-L 8080:localhost:8080 -p 2222",
		"-t", "remote command",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := commandOptions{
		target:         "user@example.com",
		programOptions: []string{"-L", "8080:localhost:8080", "-p", "2222"},
		extraArgs:      []string{"-t", "remote command"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCommandOptions() = %#v, want %#v", got, want)
	}
}

func TestParseCommandOptionsRequiresXValue(t *testing.T) {
	_, err := parseCommandOptions([]string{"host", "-x"})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseCommandOptionsSupportsGopassPrefixAndVerbose(t *testing.T) {
	got, err := parseCommandOptions([]string{
		"user@example.com",
		"--gopass-prefix", "infrastructure/production/",
		"--verbose",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got.gopassPrefix != "infrastructure/production" {
		t.Fatalf("gopass prefix = %q", got.gopassPrefix)
	}
	if !got.verbose {
		t.Fatal("verbose was not enabled")
	}
}

func TestParseCommandOptionsRejectsUnsafeGopassPrefix(t *testing.T) {
	for _, prefix := range []string{"/absolute", "../production", "production/../other", "production/./other"} {
		t.Run(prefix, func(t *testing.T) {
			_, err := parseCommandOptions([]string{"host", "--gopass-prefix", prefix})
			if err == nil {
				t.Fatalf("expected prefix %q to be rejected", prefix)
			}
		})
	}
}

func TestParseCommandOptionsStopsWrapperParsingAfterDoubleDash(t *testing.T) {
	got, err := parseCommandOptions([]string{"host", "--", "--verbose"})
	if err != nil {
		t.Fatal(err)
	}
	if got.verbose {
		t.Fatal("--verbose after -- must be passed to SSH")
	}
	if want := []string{"--", "--verbose"}; !reflect.DeepEqual(got.extraArgs, want) {
		t.Fatalf("extra args = %#v, want %#v", got.extraArgs, want)
	}
}

func TestSelectCredential(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		entries  []string
		entry    string
		host     string
		selected bool
	}{
		{"one result", "user@host", []string{"servers/user@host"}, "servers/user@host", "user@host", true},
		{"ambiguous", "host", []string{"a/host", "b/host"}, "", "", false},
		{"not found", "host", nil, "", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, host, selected := selectCredential(test.target, test.entries)
			if entry != test.entry || host != test.host || selected != test.selected {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)",
					entry, host, selected, test.entry, test.host, test.selected)
			}
		})
	}
}

func TestFilterEntriesPrefersExactMatch(t *testing.T) {
	entries := []string{
		"infrastructure/production/backup-user@example.com",
		"infrastructure/production/user@example.com",
		"infrastructure/production/nested/user@example.com",
	}

	got := filterEntries(entries, "infrastructure/production", "user@example.com")
	want := []string{
		"infrastructure/production/user@example.com",
		"infrastructure/production/nested/user@example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEntries() = %#v, want %#v", got, want)
	}
}

func TestFilterEntriesFallsBackToCaseInsensitivePartialMatch(t *testing.T) {
	entries := []string{
		"production/servers/Admin@Example.com",
		"production/databases/admin",
		"personal/user@example.com",
	}

	got := filterEntries(entries, "production", "example")
	want := []string{"production/servers/Admin@Example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEntries() = %#v, want %#v", got, want)
	}
}

func TestSSHCommandSupportsImplicitAndExplicitSyntax(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"implicit", []string{"user@example.com", "-x", "-p 2222", "uptime"}},
		{"explicit", []string{"ssh", "user@example.com", "-x", "-p 2222", "uptime"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingStore{entries: []string{"servers/user@example.com"}}
			runner := &recordingRunner{}
			cmd := newRootCommandWithDependencies(dependencies{
				store:      store,
				runProgram: runner.run,
				stdout:     &bytes.Buffer{},
			})
			cmd.SetArgs(test.args)

			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if runner.program != "ssh" {
				t.Fatalf("program = %q, want ssh", runner.program)
			}
			wantArgs := []string{"-p", "2222", "user@example.com", "uptime"}
			if !reflect.DeepEqual(runner.args, wantArgs) {
				t.Fatalf("args = %#v, want %#v", runner.args, wantArgs)
			}
			if store.searchQuery != "user@example.com" {
				t.Fatalf("search query = %q", store.searchQuery)
			}
			if store.searchPrefix != "" {
				t.Fatalf("search prefix = %q, want empty", store.searchPrefix)
			}
			if store.passwordEntry != "servers/user@example.com" {
				t.Fatalf("password entry = %q", store.passwordEntry)
			}
		})
	}
}

func TestSSHCommandScopesSearchAndLogsSelectedEntry(t *testing.T) {
	store := &recordingStore{entries: []string{"infrastructure/production/servers/user@example.com"}}
	runner := &recordingRunner{}
	var stderr bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		store:      store,
		runProgram: runner.run,
		stdout:     &bytes.Buffer{},
		stderr:     &stderr,
	})
	cmd.SetArgs([]string{
		"ssh", "user@example.com",
		"--gopass-prefix", "infrastructure/production",
		"--verbose",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if store.searchPrefix != "infrastructure/production" {
		t.Fatalf("search prefix = %q", store.searchPrefix)
	}
	if store.searchQuery != "user@example.com" {
		t.Fatalf("search query = %q", store.searchQuery)
	}
	if got := stderr.String(); got != "sshx: using gopass entry \"infrastructure/production/servers/user@example.com\"\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestExplicitGopassPathSkipsSearchAndUsesPrefix(t *testing.T) {
	store := &recordingStore{}
	runner := &recordingRunner{}
	var stderr bytes.Buffer
	err := executeSSH(
		[]string{
			"servers/user@example.com",
			"--gopass-prefix", "infrastructure/production",
			"--verbose",
		},
		dependencies{
			store:      store,
			runProgram: runner.run,
			stdout:     &bytes.Buffer{},
			stderr:     &stderr,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if store.searchCalls != 0 {
		t.Fatalf("Search() calls = %d, want 0", store.searchCalls)
	}
	wantEntry := "infrastructure/production/servers/user@example.com"
	if store.passwordEntry != wantEntry {
		t.Fatalf("password entry = %q, want %q", store.passwordEntry, wantEntry)
	}
	if !strings.Contains(stderr.String(), wantEntry) {
		t.Fatalf("selected entry was not logged: %q", stderr.String())
	}
}

func TestCredentialLookupReportsNoMatches(t *testing.T) {
	store := &recordingStore{}
	_, _, _, err := resolveCredential(
		commandOptions{target: "missing", gopassPrefix: "production"},
		dependencies{store: store, stdout: &bytes.Buffer{}},
	)
	if err == nil || !strings.Contains(err.Error(), `no gopass entry matching "missing" under gopass path "production"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCPCommandExpandsRemotePlaceholder(t *testing.T) {
	tests := []struct {
		name     string
		operands []string
		want     []string
	}{
		{
			name:     "upload",
			operands: []string{"directory/", ":/opt/app/"},
			want:     []string{"-r", "-P", "2222", "directory/", "user@example.com:/opt/app/"},
		},
		{
			name:     "download",
			operands: []string{":/var/log/app.log", "./"},
			want:     []string{"-r", "-P", "2222", "user@example.com:/var/log/app.log", "./"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingStore{entries: []string{"ignored"}}
			runner := &recordingRunner{}
			cmd := newRootCommandWithDependencies(dependencies{
				store:      store,
				runProgram: runner.run,
				stdout:     &bytes.Buffer{},
			})
			args := []string{"scp", "servers/user@example.com", "-x", "-r -P 2222"}
			args = append(args, test.operands...)
			cmd.SetArgs(args)

			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if runner.program != "scp" {
				t.Fatalf("program = %q, want scp", runner.program)
			}
			if !reflect.DeepEqual(runner.args, test.want) {
				t.Fatalf("args = %#v, want %#v", runner.args, test.want)
			}
			if store.passwordEntry != "servers/user@example.com" {
				t.Fatalf("password entry = %q", store.passwordEntry)
			}
		})
	}
}

func TestSCPRejectsRemoteToRemoteCopy(t *testing.T) {
	store := &recordingStore{entries: []string{"servers/user@example.com"}}
	runner := &recordingRunner{}
	err := executeSCP(
		[]string{"user@example.com", "first:/source", "second:/destination"},
		dependencies{store: store, runProgram: runner.run, stdout: &bytes.Buffer{}},
	)
	if err == nil || !strings.Contains(err.Error(), "remote-to-remote") {
		t.Fatalf("error = %v, want remote-to-remote rejection", err)
	}
	if runner.program != "" {
		t.Fatalf("unexpected program execution: %q", runner.program)
	}
	if store.passwordEntry != "" {
		t.Fatalf("password should not have been retrieved, got entry %q", store.passwordEntry)
	}
}

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

func TestRunPTYConnectsChildAndAnswersPasswordPrompt(t *testing.T) {
	stdin, keepOpen, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer keepOpen.Close()

	var output bytes.Buffer
	err = runPTY("sh", []string{"-c", `
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

type recordingStore struct {
	entries       []string
	searchPrefix  string
	searchQuery   string
	searchCalls   int
	passwordEntry string
}

func (s *recordingStore) Search(prefix, query string) ([]string, error) {
	s.searchCalls++
	s.searchPrefix = prefix
	s.searchQuery = query
	return s.entries, nil
}

func (s *recordingStore) Password(entry string) ([]byte, error) {
	s.passwordEntry = entry
	return []byte("secret"), nil
}

type recordingRunner struct {
	program  string
	args     []string
	password []byte
}

func (r *recordingRunner) run(program string, args []string, password []byte) error {
	r.program = program
	r.args = append([]string(nil), args...)
	r.password = append([]byte(nil), password...)
	return nil
}
