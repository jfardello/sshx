package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCredentialsListEmptyResultPrintsStableHeaderWithoutReadingSecrets(t *testing.T) {
	store := &recordingStore{}
	var output bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		stdout: &output,
	})
	cmd.SetArgs([]string{"credentials", "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "BACKEND\tCOLLECTION\tLABEL\tTARGET\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if store.searchQuery != "" || store.searchPrefix != "" {
		t.Fatalf("search = (%q, %q), want empty query and collection", store.searchQuery, store.searchPrefix)
	}
	if store.secretCalls != 0 {
		t.Fatalf("secret calls = %d, want 0", store.secretCalls)
	}
	if store.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", store.closeCalls)
	}
}

func TestCredentialsListFiltersUsingResolverPriority(t *testing.T) {
	store := &recordingStore{entries: []credentialRef{
		{
			Backend:    credentialBackendSecretService,
			ID:         "/items/private-id",
			Collection: "Login",
			Label:      "production-admin",
			Attributes: map[string]string{
				"sshx.target": "admin@example.com",
				"password":    "attribute-secret",
			},
		},
		{
			Backend:    credentialBackendSecretService,
			ID:         "/items/other-id",
			Collection: "Login",
			Label:      "admin@example.com",
			Attributes: map[string]string{"sshx.target": "other@example.com"},
		},
	}}
	store.secret = []byte("decrypted-secret")
	var output bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		stdout: &output,
	})
	cmd.SetArgs([]string{"credentials", "list", "admin@example.com"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "BACKEND\tCOLLECTION\tLABEL\tTARGET\n" +
		"secret-service\tLogin\tproduction-admin\tadmin@example.com\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	for _, forbidden := range []string{"private-id", "attribute-secret", "decrypted-secret", "password"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("output contains protected value %q: %q", forbidden, output.String())
		}
	}
	if store.secretCalls != 0 {
		t.Fatalf("secret calls = %d, want 0", store.secretCalls)
	}
}

func TestCredentialsListPrintsAmbiguousMatchesInStableOrder(t *testing.T) {
	store := &recordingStore{entries: []credentialRef{
		{
			Backend:    credentialBackendSecretService,
			Collection: "Work",
			Label:      "admin",
			Attributes: map[string]string{"sshx.target": "admin@z.example"},
		},
		{
			Backend:    credentialBackendSecretService,
			Collection: "Personal",
			Label:      "admin",
			Attributes: map[string]string{"sshx.target": "admin@a.example"},
		},
	}}
	var output bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		stdout: &output,
	})
	cmd.SetArgs([]string{"credentials", "list", "admin"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "BACKEND\tCOLLECTION\tLABEL\tTARGET\n" +
		"secret-service\tPersonal\tadmin\tadmin@a.example\n" +
		"secret-service\tWork\tadmin\tadmin@z.example\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestCredentialsListScopesSecretServiceCollection(t *testing.T) {
	store := &recordingStore{}
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		stdout: &bytes.Buffer{},
	})
	cmd.SetArgs([]string{"credentials", "list", "host", "--secret-collection", "Login"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if store.searchPrefix != "Login" || store.searchQuery != "host" {
		t.Fatalf("search = (%q, %q), want (Login, host)", store.searchPrefix, store.searchQuery)
	}
}

func TestCredentialsListGopassPrefixImpliesLegacyBackend(t *testing.T) {
	gopass := &recordingStore{entries: []credentialRef{{
		Backend:    credentialBackendGopass,
		ID:         "production/admin@example.com",
		Collection: "production",
		Label:      "admin@example.com",
	}}}
	providerCalls := 0
	var output bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		goos:        "linux",
		gopassStore: gopass,
		secretServiceStore: func() (credentialStore, error) {
			providerCalls++
			return &recordingStore{}, nil
		},
		stdout: &output,
	})
	cmd.SetArgs([]string{"credentials", "list", "--gopass-prefix", "production"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if providerCalls != 0 {
		t.Fatalf("Secret Service provider calls = %d, want 0", providerCalls)
	}
	if gopass.searchPrefix != "production" || gopass.secretCalls != 0 {
		t.Fatalf("gopass search prefix = %q, secret calls = %d", gopass.searchPrefix, gopass.secretCalls)
	}
	want := "BACKEND\tCOLLECTION\tLABEL\tTARGET\n" +
		"gopass\tproduction\tadmin@example.com\tadmin@example.com\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestCredentialsListRejectsBackendScopeConflicts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "Secret Service with gopass prefix",
			args: []string{"credentials", "list", "--credential-backend", "secret-service", "--gopass-prefix", "production"},
			want: "--gopass-prefix cannot be used with the secret-service backend",
		},
		{
			name: "gopass with Secret Service collection",
			args: []string{"credentials", "list", "--credential-backend", "gopass", "--secret-collection", "Login"},
			want: "--secret-collection cannot be used with the gopass backend",
		},
		{
			name: "both scopes",
			args: []string{"credentials", "list", "--gopass-prefix", "production", "--secret-collection", "Login"},
			want: "--secret-collection cannot be combined with --gopass-prefix",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newRootCommandWithDependencies(dependencies{})
			cmd.SetArgs(test.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCredentialsListSanitizesMetadataAndToleratesInvalidTarget(t *testing.T) {
	store := &recordingStore{entries: []credentialRef{{
		Backend:    credentialBackendSecretService,
		Collection: "Login\tCollection",
		Label:      "unsafe\nlabel\x1b[31m",
		Attributes: map[string]string{"sshx.target": "target with spaces"},
	}}}
	var output bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		stdout: &output,
	})
	cmd.SetArgs([]string{"credentials", "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "BACKEND\tCOLLECTION\tLABEL\tTARGET\n" +
		"secret-service\tLogin Collection\tunsafe label [31m\t-\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestCredentialsListJoinsCloseError(t *testing.T) {
	searchErr := errors.New("search failed")
	closeErr := errors.New("close failed")
	store := &recordingStore{searchErr: searchErr, closeErr: closeErr}
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		stdout: &bytes.Buffer{},
	})
	cmd.SetArgs([]string{"credentials", "list"})

	err := cmd.Execute()
	if !errors.Is(err, searchErr) || !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want joined search and close errors", err)
	}
}

func TestVerboseSecretServiceDiagnosticContainsOnlyIdentityMetadata(t *testing.T) {
	store := &recordingStore{
		entries: []credentialRef{{
			Backend:    credentialBackendSecretService,
			ID:         "/items/private-id",
			Collection: "Login",
			Label:      "Production",
			Attributes: map[string]string{
				"sshx.target": "admin@example.com",
				"password":    "attribute-secret",
			},
		}},
		secret: []byte("decrypted-secret"),
	}
	var stderr bytes.Buffer
	cmd := newRootCommandWithDependencies(dependencies{
		goos: "linux",
		secretServiceStore: func() (credentialStore, error) {
			return store, nil
		},
		runProgram: (&recordingRunner{}).run,
		stdout:     &bytes.Buffer{},
		stderr:     &stderr,
	})
	cmd.SetArgs([]string{"ssh", "Production", "--credential-backend", "secret-service", "--verbose"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "sshx: using secret-service credential \"Login/Production\"\n"
	if got := stderr.String(); got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	for _, forbidden := range []string{"private-id", "attribute-secret", "decrypted-secret", "password", "admin@example.com"} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("diagnostic contains protected value %q: %q", forbidden, stderr.String())
		}
	}
}

func TestCommandHelpIncludesCredentialDiscovery(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "root", args: []string{"--help"}, want: []string{"credentials", "ssh", "scp"}},
		{name: "ssh", args: []string{"ssh", "--help"}, want: []string{"--credential-backend", "--secret-collection", "--gopass-prefix"}},
		{name: "scp", args: []string{"scp", "--help"}, want: []string{"--credential-backend", "--secret-collection", "--gopass-prefix"}},
		{name: "credentials", args: []string{"credentials", "--help"}, want: []string{"list", "Discover stored credential metadata"}},
		{name: "credentials list", args: []string{"credentials", "list", "--help"}, want: []string{"list [query]", "--credential-backend", "--secret-collection", "--gopass-prefix", "never requested or displayed"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			cmd := newRootCommandWithDependencies(dependencies{})
			cmd.SetOut(&output)
			cmd.SetArgs(test.args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("help does not contain %q:\n%s", want, output.String())
				}
			}
		})
	}
}
