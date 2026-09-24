package cli

import (
	"bytes"
	"context"
	"errors"
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
		target:            "user@example.com",
		credentialBackend: credentialBackendAuto,
		programOptions:    []string{"-L", "8080:localhost:8080", "-p", "2222"},
		extraArgs:         []string{"-t", "remote command"},
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

func TestParseCommandOptionsSupportsCredentialBackends(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want credentialBackend
	}{
		{name: "default", args: []string{"host"}, want: credentialBackendAuto},
		{name: "auto", args: []string{"host", "--credential-backend", "auto"}, want: credentialBackendAuto},
		{name: "secret service", args: []string{"host", "--credential-backend", "secret-service"}, want: credentialBackendSecretService},
		{name: "gopass", args: []string{"host", "--credential-backend", "gopass"}, want: credentialBackendGopass},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCommandOptions(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if got.credentialBackend != test.want {
				t.Fatalf("credential backend = %q, want %q", got.credentialBackend, test.want)
			}
		})
	}
}

func TestParseCommandOptionsRejectsInvalidCredentialBackend(t *testing.T) {
	_, err := parseCommandOptions([]string{"host", "--credential-backend", "unknown"})
	if err == nil || !strings.Contains(err.Error(), "invalid credential backend") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCommandOptionsRequiresCredentialBackendValue(t *testing.T) {
	_, err := parseCommandOptions([]string{"host", "--credential-backend"})
	if err == nil || !strings.Contains(err.Error(), "requires an argument") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCommandOptionsRejectsDuplicateCredentialBackend(t *testing.T) {
	_, err := parseCommandOptions([]string{
		"host",
		"--credential-backend", "auto",
		"--credential-backend", "gopass",
	})
	if err == nil || !strings.Contains(err.Error(), "may only be specified once") {
		t.Fatalf("unexpected error: %v", err)
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
		entries  []credentialRef
		entry    string
		host     string
		selected bool
	}{
		{"one result", "user@host", gopassCredentialRefs("servers/user@host"), "servers/user@host", "user@host", true},
		{"ambiguous", "host", gopassCredentialRefs("a/host", "b/host"), "", "", false},
		{"not found", "host", nil, "", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credentials, err := matchCredentials(test.target, test.entries)
			if err != nil {
				t.Fatal(err)
			}
			credential, selected := selectCredential(credentials)
			if credential.ID != test.entry || credential.Target != test.host || selected != test.selected {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)",
					credential.ID, credential.Target, selected, test.entry, test.host, test.selected)
			}
		})
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
			store := &recordingStore{entries: gopassCredentialRefs("servers/user@example.com")}
			runner := &recordingRunner{}
			cmd := newRootCommandWithDependencies(dependencies{
				gopassStore: store,
				runProgram:  runner.run,
				stdout:      &bytes.Buffer{},
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
	store := &recordingStore{entries: gopassCredentialRefs("infrastructure/production/servers/user@example.com")}
	runner := &recordingRunner{}
	var stderr bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		gopassStore: store,
		runProgram:  runner.run,
		stdout:      &bytes.Buffer{},
		stderr:      &stderr,
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
			gopassStore: store,
			runProgram:  runner.run,
			stdout:      &bytes.Buffer{},
			stderr:      &stderr,
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
	_, _, err := resolveCredential(
		commandOptions{target: "missing", gopassPrefix: "production"},
		selectedCredentialStore{backend: credentialBackendGopass, store: store},
		dependencies{gopassStore: store, stdout: &bytes.Buffer{}},
	)
	if err == nil || !strings.Contains(err.Error(), `no gopass entry matching "missing" under gopass path "production"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAmbiguousCredentialLookupDoesNotRetrieveSecret(t *testing.T) {
	store := &recordingStore{entries: gopassCredentialRefs("first/host", "second/host")}
	var stdout bytes.Buffer

	err := executeSSH(
		[]string{"host"},
		dependencies{
			gopassStore: store,
			runProgram:  (&recordingRunner{}).run,
			stdout:      &stdout,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if store.secretCalls != 0 {
		t.Fatalf("Secret() calls = %d, want 0", store.secretCalls)
	}
	if got := stdout.String(); got != "Please choose one of:\nfirst/host\nsecond/host\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestExplicitSecretServiceDoesNotFallBackToGopass(t *testing.T) {
	store := &recordingStore{entries: gopassCredentialRefs("servers/user@example.com")}
	err := executeSSH(
		[]string{"user@example.com", "--credential-backend", "secret-service"},
		dependencies{
			gopassStore: store,
			runProgram:  (&recordingRunner{}).run,
			stdout:      &bytes.Buffer{},
		},
	)
	if err == nil || !isCredentialBackendUnavailable(err) {
		t.Fatalf("error = %v, want backend-unavailable error", err)
	}
	if store.searchCalls != 0 || store.secretCalls != 0 {
		t.Fatalf("gopass calls = search %d, secret %d; want none", store.searchCalls, store.secretCalls)
	}
}

func TestSSHClosesCredentialStoreAndReturnsCleanupError(t *testing.T) {
	cleanupErr := errors.New("close failed")
	store := &recordingStore{
		entries:  gopassCredentialRefs("servers/user@example.com"),
		closeErr: cleanupErr,
	}
	err := executeSSH(
		[]string{"user@example.com"},
		dependencies{
			gopassStore: store,
			runProgram:  (&recordingRunner{}).run,
			stdout:      &bytes.Buffer{},
		},
	)
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("executeSSH() error = %v, want cleanup error", err)
	}
	if store.closeCalls != 1 {
		t.Fatalf("Close() calls = %d, want 1", store.closeCalls)
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
			store := &recordingStore{entries: gopassCredentialRefs("ignored")}
			runner := &recordingRunner{}
			cmd := newRootCommandWithDependencies(dependencies{
				gopassStore: store,
				runProgram:  runner.run,
				stdout:      &bytes.Buffer{},
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
	store := &recordingStore{entries: gopassCredentialRefs("servers/user@example.com")}
	runner := &recordingRunner{}
	err := executeSCP(
		[]string{"user@example.com", "first:/source", "second:/destination"},
		dependencies{gopassStore: store, runProgram: runner.run, stdout: &bytes.Buffer{}},
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

type recordingStore struct {
	entries       []credentialRef
	searchErr     error
	searchPrefix  string
	searchQuery   string
	searchCalls   int
	secretCalls   int
	secretErr     error
	secret        []byte
	closeCalls    int
	closeErr      error
	passwordEntry string
	credential    credentialRef
}

func (s *recordingStore) Search(ctx context.Context, query credentialQuery) ([]credentialRef, error) {
	s.searchCalls++
	s.searchPrefix = query.Collection
	s.searchQuery = query.Text
	return s.entries, s.searchErr
}

func (s *recordingStore) Secret(ctx context.Context, credential credentialRef, options credentialReadOptions) ([]byte, error) {
	s.secretCalls++
	s.passwordEntry = credential.ID
	s.credential = credential
	if s.secretErr != nil {
		return nil, s.secretErr
	}
	if s.secret != nil {
		return append([]byte(nil), s.secret...), nil
	}
	return []byte("secret"), nil
}

func (s *recordingStore) Close() error {
	s.closeCalls++
	return s.closeErr
}

func gopassCredentialRefs(entries ...string) []credentialRef {
	credentials := make([]credentialRef, 0, len(entries))
	for _, entry := range entries {
		credentials = append(credentials, credentialRef{
			Backend: credentialBackendGopass,
			ID:      entry,
		})
	}
	return credentials
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
