package cli

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jfardello/sshx/internal/config"
)

func TestSSHUIParser(t *testing.T) {
	for _, tc := range []struct {
		args               []string
		target, ui, helper string
		extra              []string
	}{
		{[]string{"host"}, "host", "none", "", nil},
		{[]string{"--ui", "shell"}, "", "shell", "", nil},
		{[]string{"--gopass-prefix", "work", "--ui=shell"}, "", "shell", "", nil},
		{[]string{"--ui=desktop", "host", "--prompt-helper=/helper", "uptime", "--ui", "none"}, "host", "desktop", "/helper", []string{"uptime", "--ui", "none"}},
		{[]string{"host", "-p", "22", "--ui=shell", "echo", "--prompt-helper", "remote"}, "host", "shell", "", []string{"-p", "22", "echo", "--prompt-helper", "remote"}},
		{[]string{"host", "-o", "--ui=shell"}, "host", "none", "", []string{"-o", "--ui=shell"}},
		{[]string{"host", "-vp", "22", "--ui=shell"}, "host", "shell", "", []string{"-vp", "22"}},
		{[]string{"host", "-p2222", "--ui=shell"}, "host", "shell", "", []string{"-p2222"}},
		{[]string{"host", "--", "--ui=shell"}, "host", "none", "", []string{"--", "--ui=shell"}},
		{[]string{"--ui=shell", "--", "host", "echo", "--ui=none"}, "host", "shell", "", []string{"echo", "--ui=none"}},
	} {
		got, err := parseConfiguredSSHOptions(tc.args, dependencies{})
		if err != nil || got.target != tc.target || got.ui != tc.ui || got.promptHelper != tc.helper || !reflect.DeepEqual(got.extraArgs, tc.extra) {
			t.Fatalf("%v: %+v %v", tc.args, got, err)
		}
	}
	for _, args := range [][]string{nil, {"--ui=none"}, {"--ui"}, {"--ui="}, {"--ui=bad"}, {"--ui=shell", "--ui=none"}, {"host", "--prompt-helper"}, {"host", "--prompt-helper=relative"}, {"host", "--prompt-helper=/a/../b"}, {"host", "--prompt-helper=/a", "--prompt-helper="}, {""}, {"-t", "host"}, {"host", "-p"}} {
		if _, err := parseConfiguredSSHOptions(args, dependencies{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestSSHUIConfigurationPrecedence(t *testing.T) {
	file, err := config.Decode([]byte("ssh:\n  ui: shell\n  prompt-helper: /ssh-helper\nagent:\n  prompt-helper: /agent-helper\n"))
	if err != nil {
		t.Fatal(err)
	}
	deps := dependencies{loadConfig: func() (optionOverrides, error) { return file, nil }}
	got, err := parseConfiguredSSHOptions(nil, deps)
	if err != nil || got.ui != "shell" || got.promptHelper != "/ssh-helper" {
		t.Fatal(got, err)
	}
	got, err = parseConfiguredSSHOptions([]string{"host", "--ui=none", "--prompt-helper="}, deps)
	if err != nil || got.ui != "none" || got.promptHelper != "" {
		t.Fatal("explicit reset ignored", got, err)
	}
	legacy, err := parseConfiguredCommandOptions([]string{"host", "local", ":/remote"}, deps)
	if err != nil || legacy.ui != "" || legacy.promptHelper != "" {
		t.Fatal("SSH settings reached SCP", legacy, err)
	}
	file.SSH = nil
	got, err = parseConfiguredSSHOptions([]string{"host"}, deps)
	if err != nil || got.promptHelper != "" {
		t.Fatal("agent helper inherited", got, err)
	}
}

func TestSSHUIResolutionAndDispatch(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, tc := range []struct {
			name         string
			args         []string
			entries      []credentialRef
			pick         bool
			want         string
			cancel, fail bool
		}{
			{"browse-one", []string{"--ui=shell", "--gopass-prefix=scope"}, gopassCredentialRefs("scope/alice@host"), true, "scope/alice@host", false, false},
			{"browse-many", []string{"--ui=shell"}, gopassCredentialRefs("a/alice@host", "b/alice@host"), true, "b/alice@host", false, false},
			{"query-many", []string{"host", "--ui=shell"}, gopassCredentialRefs("a/alice@host", "b/alice@host"), true, "b/alice@host", false, false},
			{"query-one", []string{"host", "--ui=shell"}, gopassCredentialRefs("a/alice@host"), false, "a/alice@host", false, false},
			{"exact-path", []string{"a/alice@host", "--ui=shell"}, nil, false, "a/alice@host", false, false},
			{"no-match", []string{"missing", "--ui=shell"}, nil, false, "", false, true},
			{"empty-scope", []string{"--ui=shell"}, nil, false, "", false, true},
			{"cancellation", []string{"--ui=shell"}, gopassCredentialRefs("a/alice@host"), true, "", true, true},
			{"default-ambiguous", []string{"host"}, gopassCredentialRefs("a/alice@host", "b/alice@host"), false, "", false, false},
			{"desktop-deferred", []string{"--ui=desktop"}, gopassCredentialRefs("a/alice@host"), false, "", false, true},
		} {
			t.Run(tc.name+map[bool]string{true: "/ssh", false: "/root"}[explicit], func(t *testing.T) {
				store := &recordingStore{entries: tc.entries}
				runner := &recordingRunner{}
				called := false
				cmd := newRootCommandWithDependencies(dependencies{gopassStore: store, goos: "darwin", stdout: &bytes.Buffer{}, runProgram: runner.run,
					selectShell: func(ctx context.Context, refs []credentialRef) (int, error) {
						called = true
						if store.secretCalls != 0 || runner.program != "" {
							t.Fatal("secret/session before choice")
						}
						if tc.cancel {
							return -1, context.Canceled
						}
						return len(refs) - 1, nil
					}})
				args := tc.args
				if explicit {
					args = append([]string{"ssh"}, args...)
				}
				cmd.SetArgs(args)
				err := cmd.Execute()
				if (err != nil) != tc.fail || called != tc.pick || store.passwordEntry != tc.want {
					t.Fatalf("err=%v pick=%v ref=%q", err, called, store.passwordEntry)
				}
				if tc.want != "" && (runner.program != "ssh" || store.secretCalls != 1) {
					t.Fatal("selected credential did not connect")
				}
				if tc.want == "" && (runner.program != "" || store.secretCalls != 0) {
					t.Fatal("failure/ambiguity retrieved password")
				}
				if tc.cancel {
					var exit interface{ Code() int }
					if !errors.As(err, &exit) || exit.Code() != 130 {
						t.Fatal("cancellation status", err)
					}
				}
				if tc.name == "browse-one" && (store.searchPrefix != "scope" || store.searchQuery != "") {
					t.Fatal("scope/query lost")
				}
				if tc.name == "exact-path" && store.searchCalls != 0 {
					t.Fatal("exact path searched")
				}
			})
		}
	}
}

func TestSSHUIRejectsInvalidTargetBeforePrompt(t *testing.T) {
	store := &recordingStore{entries: []credentialRef{{Backend: credentialBackendSecretService, ID: "private-path", Label: "invalid", Attributes: map[string]string{"sshx.target": "-unsafe"}}}}
	deps := dependencies{goos: "linux", secretServiceStore: func(context.Context) (credentialStore, error) { return store, nil },
		selectShell: func(context.Context, []credentialRef) (int, error) {
			t.Fatal("invalid metadata reached picker")
			return 0, nil
		}}
	if err := executeSSH([]string{"--ui=shell"}, deps); err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatal("invalid target accepted", err)
	}
	if store.secretCalls != 0 {
		t.Fatal("invalid target read secret")
	}
}

func TestSSHUISecretServiceScopeAndMatching(t *testing.T) {
	for _, query := range []string{"", "production"} {
		store := &recordingStore{entries: []credentialRef{
			{Backend: credentialBackendSecretService, ID: "opaque-a", Collection: "Login", Label: "production", Attributes: map[string]string{"sshx.target": "alice@host"}},
			{Backend: credentialBackendSecretService, ID: "opaque-b", Collection: "Login", Label: "other", Attributes: map[string]string{"sshx.target": "bob@host"}},
		}}
		picked := false
		deps := dependencies{goos: "linux", secretServiceStore: func(context.Context) (credentialStore, error) { return store, nil },
			selectShell: func(context.Context, []credentialRef) (int, error) { picked = true; return 1, nil }, runProgram: (&recordingRunner{}).run}
		args := []string{"--ui=shell", "--secret-collection=Login"}
		if query != "" {
			args = append(args, query)
		}
		if err := executeSSH(args, deps); err != nil {
			t.Fatal(err)
		}
		want := "opaque-b"
		if query != "" {
			want = "opaque-a"
		}
		if picked != (query == "") || store.passwordEntry != want || store.searchPrefix != "Login" || store.searchQuery != query {
			t.Fatalf("query=%q picked=%v ref=%s", query, picked, store.passwordEntry)
		}
		if store.entries[0].Target != "" {
			t.Fatal("provider-owned reference mutated")
		}
	}
}
