package cli

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseCommandOptionsSupportsBackendScopes(t *testing.T) {
	t.Run("secret collection keeps auto", func(t *testing.T) {
		got, err := parseCommandOptions([]string{"host", "--secret-collection", "Login"})
		if err != nil {
			t.Fatal(err)
		}
		if got.secretCollection != "Login" || got.credentialBackend != credentialBackendAuto {
			t.Fatalf("options = %#v", got)
		}
	})

	for _, args := range [][]string{
		{"host", "--gopass-prefix", "production"},
		{"host", "--credential-backend", "auto", "--gopass-prefix", "production"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			got, err := parseCommandOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			if got.credentialBackend != credentialBackendGopass {
				t.Fatalf("backend = %q, want gopass", got.credentialBackend)
			}
		})
	}
}

func TestParseCommandOptionsRejectsBackendScopeConflicts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "gopass prefix with Secret Service",
			args: []string{"host", "--credential-backend", "secret-service", "--gopass-prefix", "production"},
			want: "--gopass-prefix cannot be used",
		},
		{
			name: "secret collection with gopass",
			args: []string{"host", "--credential-backend", "gopass", "--secret-collection", "Login"},
			want: "--secret-collection cannot be used",
		},
		{
			name: "both scopes in auto",
			args: []string{"host", "--secret-collection", "Login", "--gopass-prefix", "production"},
			want: "cannot be combined",
		},
		{
			name: "duplicate collection",
			args: []string{"host", "--secret-collection", "Login", "--secret-collection", "Other"},
			want: "may only be specified once",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseCommandOptions(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAutoUsesSecretServiceForSSHOnLinux(t *testing.T) {
	gopass := &recordingStore{entries: gopassCredentialRefs("legacy/alice@example.com")}
	secretService := &recordingStore{entries: []credentialRef{
		secretServiceCredential("Login", "production", map[string]string{"sshx.target": "alice@server.example"}),
	}}
	runner := &recordingRunner{}
	providerCalls := 0

	err := executeSSH([]string{"production", "uptime"}, dependencies{
		goos:        "linux",
		gopassStore: gopass,
		secretServiceStore: func(context.Context) (credentialStore, error) {
			providerCalls++
			return secretService, nil
		},
		runProgram: runner.run,
		stdout:     &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if providerCalls != 1 || secretService.searchCalls != 1 || secretService.secretCalls != 1 {
		t.Fatalf("provider calls = %d, Secret Service search/secret = %d/%d", providerCalls, secretService.searchCalls, secretService.secretCalls)
	}
	if gopass.searchCalls != 0 || gopass.secretCalls != 0 {
		t.Fatalf("gopass search/secret = %d/%d, want none", gopass.searchCalls, gopass.secretCalls)
	}
	if want := []string{"alice@server.example", "uptime"}; !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("SSH args = %#v, want %#v", runner.args, want)
	}
	if secretService.credential.Target != "alice@server.example" {
		t.Fatalf("retrieved credential target = %q", secretService.credential.Target)
	}
}

func TestSecretCollectionScopesLookup(t *testing.T) {
	secretService := &recordingStore{entries: []credentialRef{
		secretServiceCredential("Work", "server.example", nil),
	}}
	err := executeSSH(
		[]string{"server.example", "--secret-collection", "Work", "--credential-backend", "secret-service"},
		dependencies{
			goos: "linux",
			secretServiceStore: func(context.Context) (credentialStore, error) {
				return secretService, nil
			},
			runProgram: (&recordingRunner{}).run,
			stdout:     &bytes.Buffer{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if secretService.searchPrefix != "Work" {
		t.Fatalf("collection = %q, want Work", secretService.searchPrefix)
	}
}

func TestAutoFallsBackToGopassOnlyWhenSecretServiceIsUnavailable(t *testing.T) {
	gopass := &recordingStore{entries: gopassCredentialRefs("servers/alice@example.com")}
	runner := &recordingRunner{}
	err := executeSSH([]string{"alice@example.com"}, dependencies{
		goos:        "linux",
		gopassStore: gopass,
		secretServiceStore: func(context.Context) (credentialStore, error) {
			return nil, newCredentialBackendUnavailableError(credentialBackendSecretService, errors.New("no session bus"))
		},
		runProgram: runner.run,
		stdout:     &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gopass.searchCalls != 1 || gopass.secretCalls != 1 {
		t.Fatalf("gopass search/secret = %d/%d, want 1/1", gopass.searchCalls, gopass.secretCalls)
	}
	if want := []string{"alice@example.com"}; !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("SSH args = %#v, want %#v", runner.args, want)
	}
}

func TestAutoNeverFallsBackAfterSecretServiceWasOpened(t *testing.T) {
	tests := []struct {
		name    string
		entries []credentialRef
		err     error
	}{
		{name: "no matches"},
		{name: "locked store", err: errors.New("Secret Service object remains locked")},
		{name: "prompt cancellation", err: errors.New("Secret Service prompt was dismissed")},
		{name: "access denial", err: errors.New("access denied")},
		{name: "malformed response", err: errors.New("malformed Secret Service response")},
		{name: "provider failure", err: errors.New("provider failed")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gopass := &recordingStore{entries: gopassCredentialRefs("legacy/alice@example.com")}
			secretService := &recordingStore{entries: test.entries, searchErr: test.err}
			err := executeSSH([]string{"alice@example.com"}, dependencies{
				goos:        "linux",
				gopassStore: gopass,
				secretServiceStore: func(context.Context) (credentialStore, error) {
					return secretService, nil
				},
				runProgram: (&recordingRunner{}).run,
				stdout:     &bytes.Buffer{},
			})
			if err == nil {
				t.Fatal("executeSSH() returned no error")
			}
			if gopass.searchCalls != 0 || gopass.secretCalls != 0 {
				t.Fatalf("gopass search/secret = %d/%d, want none", gopass.searchCalls, gopass.secretCalls)
			}
		})
	}
}

func TestAutoDoesNotFallBackWhenSecretRetrievalFails(t *testing.T) {
	providerErr := errors.New("provider failed to retrieve secret")
	gopass := &recordingStore{entries: gopassCredentialRefs("legacy/alice@example.com")}
	secretService := &recordingStore{
		entries: []credentialRef{
			secretServiceCredential("Login", "server", map[string]string{"sshx.target": "alice@example.com"}),
		},
		secretErr: providerErr,
	}
	err := executeSSH([]string{"server"}, dependencies{
		goos:        "linux",
		gopassStore: gopass,
		secretServiceStore: func(context.Context) (credentialStore, error) {
			return secretService, nil
		},
		runProgram: (&recordingRunner{}).run,
		stdout:     &bytes.Buffer{},
	})
	if !errors.Is(err, providerErr) {
		t.Fatalf("executeSSH() error = %v, want provider error", err)
	}
	if gopass.searchCalls != 0 || gopass.secretCalls != 0 {
		t.Fatalf("gopass search/secret = %d/%d, want none", gopass.searchCalls, gopass.secretCalls)
	}
}

func TestGopassPrefixSkipsSecretService(t *testing.T) {
	gopass := &recordingStore{entries: gopassCredentialRefs("production/alice@example.com")}
	providerCalls := 0
	err := executeSSH([]string{"alice@example.com", "--gopass-prefix", "production"}, dependencies{
		goos:        "linux",
		gopassStore: gopass,
		secretServiceStore: func(context.Context) (credentialStore, error) {
			providerCalls++
			return &recordingStore{}, nil
		},
		runProgram: (&recordingRunner{}).run,
		stdout:     &bytes.Buffer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if providerCalls != 0 {
		t.Fatalf("Secret Service provider calls = %d, want 0", providerCalls)
	}
	if gopass.searchPrefix != "production" {
		t.Fatalf("gopass prefix = %q, want production", gopass.searchPrefix)
	}
}

func TestAmbiguousSecretServiceResultsDoNotRetrieveSecret(t *testing.T) {
	secretService := &recordingStore{entries: []credentialRef{
		secretServiceCredential("Login", "server", map[string]string{"sshx.target": "first@example.com"}),
		secretServiceCredential("Work", "server", map[string]string{"sshx.target": "second@example.com"}),
	}}
	var stdout bytes.Buffer
	err := executeSSH([]string{"server", "--credential-backend", "secret-service"}, dependencies{
		goos: "linux",
		secretServiceStore: func(context.Context) (credentialStore, error) {
			return secretService, nil
		},
		runProgram: (&recordingRunner{}).run,
		stdout:     &stdout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secretService.secretCalls != 0 {
		t.Fatalf("Secret() calls = %d, want 0", secretService.secretCalls)
	}
	if got := stdout.String(); got != "Please choose one of:\nLogin/server\nWork/server\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestSecretServiceWorksForSCPUploadAndDownload(t *testing.T) {
	for _, test := range []struct {
		name     string
		operands []string
		want     []string
	}{
		{name: "upload", operands: []string{"file.txt", ":/tmp/"}, want: []string{"file.txt", "alice@server.example:/tmp/"}},
		{name: "download", operands: []string{":/var/log/app.log", "./"}, want: []string{"alice@server.example:/var/log/app.log", "./"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			secretService := &recordingStore{entries: []credentialRef{
				secretServiceCredential("Login", "server", map[string]string{"sshx.target": "alice@server.example"}),
			}}
			runner := &recordingRunner{}
			args := []string{"server", "--credential-backend", "secret-service"}
			args = append(args, test.operands...)
			err := executeSCP(args, dependencies{
				goos: "linux",
				secretServiceStore: func(context.Context) (credentialStore, error) {
					return secretService, nil
				},
				runProgram: runner.run,
				stdout:     &bytes.Buffer{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if runner.program != "scp" || !reflect.DeepEqual(runner.args, test.want) {
				t.Fatalf("program/args = %q/%#v, want scp/%#v", runner.program, runner.args, test.want)
			}
			if secretService.secretCalls != 1 {
				t.Fatalf("Secret() calls = %d, want 1", secretService.secretCalls)
			}
		})
	}
}

func secretServiceCredential(collection, label string, attributes map[string]string) credentialRef {
	return credentialRef{
		Backend:    credentialBackendSecretService,
		ID:         "/org/freedesktop/secrets/collection/" + strings.ToLower(collection) + "/" + strings.ReplaceAll(label, " ", "_"),
		Collection: collection,
		Label:      label,
		Attributes: attributes,
	}
}
