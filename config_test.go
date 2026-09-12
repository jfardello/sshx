package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func configForTest(t *testing.T, data string) optionOverrides {
	t.Helper()
	config, err := decodeConfig([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestResolveConfigPath(t *testing.T) {
	for _, tc := range []struct{ home, xdg, want string }{
		{"/home/test", "", "/home/test/.config/sshx/config.yaml"},
		{"/home/test", "relative", "/home/test/.config/sshx/config.yaml"},
		{"/home/test", "/custom", "/custom/sshx/config.yaml"},
		{"", "/custom", "/custom/sshx/config.yaml"},
	} {
		got, err := resolveConfigPath(tc.home, tc.xdg)
		if err != nil || got != tc.want {
			t.Fatalf("path = %q, %v; want %q", got, err, tc.want)
		}
	}
	if _, err := resolveConfigPath("", ""); err == nil {
		t.Fatal("missing home must fail")
	}
}

func TestDecodeConfig(t *testing.T) {
	for _, data := range []string{"", "# comment\n", "{}"} {
		if got := configForTest(t, data); !reflect.DeepEqual(got, optionOverrides{}) {
			t.Fatalf("unexpected empty config: %#v", got)
		}
	}
	got := configForTest(t, "credential-backend: auto\nsecret-collection: Login\ngopass-prefix: ''\nverbose: false\noptions: '-o ConnectTimeout=10'\n")
	if *got.CredentialBackend != "auto" || *got.SecretCollection != "Login" || *got.GopassPrefix != "" || *got.Verbose || *got.Options != "-o ConnectTimeout=10" {
		t.Fatalf("config = %#v", got)
	}
	for _, data := range []string{
		"null", "[]", "hello", "---\n", "verbose: true\n---\n{}", "{}\n---\n", "verbose: [", "secret: synthetic-do-not-log",
		"verbose: true\nverbose: false", "options: null", "options: [one]", "options: {one: two}", "options: 123",
		"verbose: 'true'", "verbose: yes", "verbose: True", "verbose: 1", "verbose: null", "credential-backend: invalid",
		"credential-backend: ''", "gopass-prefix: ../bad", "gopass-prefix: /bad", "gopass-prefix: a/./b",
		"options: &opts hello", "&root {}", "!!str {}", "!custom {}", "<<: {verbose: true}", "? [one, two]\n: value",
		"options: *undefined", "secret-collection: &c Login\noptions: *c", "? &key verbose\n: true",
	} {
		t.Run(data, func(t *testing.T) {
			_, err := decodeConfig([]byte(data))
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if strings.Contains(err.Error(), "synthetic-do-not-log") {
				t.Fatal("configuration payload leaked")
			}
		})
	}
}

func TestLoadConfigFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if _, err := loadConfig(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("verbose: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(file)
	if err != nil || got.Verbose == nil || !*got.Verbose || !strings.Contains(got.source, file) {
		t.Fatalf("load = %#v, %v", got, err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(link); err == nil {
		t.Fatal("dangling symlink treated as missing")
	}
	if _, err := loadConfig(filepath.Join(link, "child.yaml")); err == nil {
		t.Fatal("dangling ancestor treated as missing")
	}
	if _, err := loadConfig(dir); err == nil {
		t.Fatal("directory accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(fifo); err == nil {
		t.Fatal("FIFO accepted")
	}
	if err := os.WriteFile(file, bytes.Repeat([]byte("#"), maxConfigBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(file); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("oversize: %v", err)
	}
	if err := os.WriteFile(file, []byte("unknown: value"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(file); err == nil || !strings.Contains(err.Error(), file) {
		t.Fatalf("invalid config diagnostic: %v", err)
	}
	if err := os.Chmod(file, 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := loadConfig(file); err == nil {
			t.Fatal("unreadable file accepted")
		}
	}
}

func TestLoadUserConfigLocation(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	write := func(base, content string) {
		t.Helper()
		dir := filepath.Join(base, "sshx")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".config"), "verbose: true")
	write(xdg, "verbose: false")
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		xdg  string
		want bool
	}{{"", true}, {"relative", true}, {xdg, false}} {
		t.Setenv("XDG_CONFIG_HOME", tc.xdg)
		got, err := loadUserConfig()
		if err != nil || got.Verbose == nil || *got.Verbose != tc.want {
			t.Fatalf("config = %#v, %v", got, err)
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := loadUserConfig(); err == nil {
		t.Fatal("missing HOME accepted")
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if _, err := loadUserConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredOptionPrecedence(t *testing.T) {
	file := configForTest(t, "credential-backend: secret-service\nsecret-collection: Login\nverbose: true\noptions: '-o ConnectTimeout=10'\n")
	deps := dependencies{loadConfig: func() (optionOverrides, error) { return file, nil }}
	got, err := parseConfiguredCommandOptions([]string{"host"}, deps)
	if err != nil || got.credentialBackend != credentialBackendSecretService || got.secretCollection != "Login" || !got.verbose || !reflect.DeepEqual(got.programOptions, []string{"-o", "ConnectTimeout=10"}) {
		t.Fatalf("file defaults = %#v, %v", got, err)
	}
	got, err = parseConfiguredCommandOptions([]string{"host", "--credential-backend=auto", "--secret-collection=Work", "--verbose=false", "--options=-p 2222", "-x", "-t", "uptime"}, deps)
	if err != nil || got.credentialBackend != credentialBackendAuto || got.secretCollection != "Work" || got.verbose || !reflect.DeepEqual(got.programOptions, []string{"-p", "2222", "-t"}) || !reflect.DeepEqual(got.extraArgs, []string{"uptime"}) {
		t.Fatalf("CLI override = %#v, %v", got, err)
	}
	got, err = parseConfiguredCommandOptions([]string{"host", "--credential-backend", "gopass", "--secret-collection", "", "--gopass-prefix=infra/", "-x", ""}, deps)
	if err != nil || got.secretCollection != "" || got.gopassPrefix != "infra" || len(got.programOptions) != 0 {
		t.Fatalf("clears = %#v, %v", got, err)
	}
	_, err = parseConfiguredCommandOptions([]string{"host", "--credential-backend=gopass"}, deps)
	if err == nil || !strings.Contains(err.Error(), "configuration file") || !strings.Contains(err.Error(), "command line") {
		t.Fatalf("conflict lacks provenance: %v", err)
	}
	file = configForTest(t, "credential-backend: auto\ngopass-prefix: infra")
	got, err = parseConfiguredCommandOptions([]string{"host", "--credential-backend=auto"}, deps)
	if err != nil || got.credentialBackend != credentialBackendGopass {
		t.Fatalf("prefix inference = %#v, %v", got, err)
	}
	got, err = parseConfiguredCommandOptions([]string{"host", "--gopass-prefix", ""}, deps)
	if err != nil || got.gopassPrefix != "" || got.credentialBackend != credentialBackendAuto {
		t.Fatalf("prefix clear = %#v, %v", got, err)
	}
	file = configForTest(t, "credential-backend: secret-service\ngopass-prefix: infra")
	if _, err := parseConfiguredCommandOptions([]string{"host", "--gopass-prefix="}, deps); err != nil {
		t.Fatalf("CLI should repair cross-field conflict: %v", err)
	}
	invalid := "bad"
	file.CredentialBackend = &invalid
	if _, err := parseConfiguredCommandOptions([]string{"host", "--credential-backend=auto", "--gopass-prefix="}, deps); err == nil {
		t.Fatal("invalid file value masked by CLI")
	}
}

func TestConfigurationParserBoundaries(t *testing.T) {
	for _, args := range [][]string{
		{"host", "--secret-collection=", "--secret-collection", "Login"},
		{"host", "--gopass-prefix", "", "--gopass-prefix=infra"},
		{"host", "--credential-backend=auto", "--credential-backend=auto"},
		{"host", "--verbose=invalid"}, {"host", "--credential-backend="}, {"host", "--secret-collection"}, {"host", "--gopass-prefix"}, {"host", "--options"},
	} {
		if _, err := parseCommandOptions(args); err == nil {
			t.Fatalf("accepted invalid args %#v", args)
		}
	}
	got, err := parseCommandOptions([]string{"host", "--verbose=false", "--verbose", "false", "--native=value", "--", "--verbose=false", "--options=ignored"})
	if err != nil || !got.verbose || !reflect.DeepEqual(got.extraArgs, []string{"false", "--native=value", "--", "--verbose=false", "--options=ignored"}) {
		t.Fatalf("boundary = %#v, %v", got, err)
	}
	got, err = parseCommandOptions([]string{"host", "--verbose=true", "--verbose=false"})
	if err != nil || got.verbose {
		t.Fatalf("last boolean = %#v, %v", got, err)
	}
}

func TestCommandsUseConfig(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args, want []string
		program    string
	}{
		{"implicit", []string{"user@host", "uptime"}, []string{"-o", "ConnectTimeout=10", "user@host", "uptime"}, "ssh"},
		{"ssh", []string{"ssh", "user@host", "--verbose=false"}, []string{"-o", "ConnectTimeout=10", "user@host"}, "ssh"},
		{"scp", []string{"scp", "user@host", "local", ":/remote"}, []string{"-o", "ConnectTimeout=10", "local", "user@host:/remote"}, "scp"},
		{"replace", []string{"ssh", "user@host", "-x", "-p 2222"}, []string{"-p", "2222", "user@host"}, "ssh"},
		{"passthrough", []string{"ssh", "user@host", "-p", "2222"}, []string{"-o", "ConnectTimeout=10", "user@host", "-p", "2222"}, "ssh"},
		{"list", []string{"credentials", "list", "user@host"}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &recordingStore{entries: gopassCredentialRefs("infra/user@host")}
			runner := &recordingRunner{}
			var stderr, stdout bytes.Buffer
			loads := 0
			cmd := newRootCommandWithDependencies(dependencies{
				loadConfig: func() (optionOverrides, error) {
					loads++
					return configForTest(t, "credential-backend: gopass\ngopass-prefix: infra\nverbose: true\noptions: '-o ConnectTimeout=10'"), nil
				},
				gopassStore: store, runProgram: runner.run, stdout: &stdout, stderr: &stderr,
			})
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if loads != 1 || store.searchPrefix != "infra" || runner.program != tc.program || !reflect.DeepEqual(runner.args, tc.want) {
				t.Fatalf("loads %d, prefix %q, runner %#v", loads, store.searchPrefix, runner)
			}
			if tc.name == "list" && (store.secretCalls != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "user@host")) {
				t.Fatal("list used execution options or fetched secret")
			}
			if tc.name == "ssh" && stderr.Len() != 0 {
				t.Fatal("false CLI override did not disable logging")
			}
			if tc.name == "implicit" && stderr.Len() == 0 {
				t.Fatal("file verbose not used")
			}
		})
	}
}

func TestCredentialListOverrides(t *testing.T) {
	store := &recordingStore{entries: gopassCredentialRefs("user@host")}
	cmd := newRootCommandWithDependencies(dependencies{
		loadConfig: func() (optionOverrides, error) {
			return configForTest(t, "credential-backend: secret-service\nsecret-collection: Login\ngopass-prefix: infra"), nil
		},
		gopassStore: store,
	})
	cmd.SetArgs([]string{"credentials", "list", "--credential-backend=gopass", "--secret-collection=", "--gopass-prefix="})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if store.searchPrefix != "" || store.secretCalls != 0 {
		t.Fatalf("store = %#v", store)
	}
	for _, name := range []string{"credential-backend", "secret-collection", "gopass-prefix"} {
		cmd = newRootCommandWithDependencies(dependencies{})
		value := ""
		if name == "credential-backend" {
			value = "auto"
		}
		cmd.SetArgs([]string{"credentials", "list", "--" + name + "=" + value, "--" + name + "=" + value})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "may only be specified once") {
			t.Fatalf("duplicate %s: %v", name, err)
		}
	}
}

func TestConfigErrorsPrecedeBackendAccessAndHelpSkipsConfig(t *testing.T) {
	for _, args := range [][]string{{"host"}, {"ssh", "host"}, {"scp", "host", "local", ":/remote"}, {"credentials", "list"}} {
		cmd := newRootCommandWithDependencies(dependencies{
			loadConfig: func() (optionOverrides, error) { return optionOverrides{}, errors.New("unreadable config") },
			secretServiceStore: func(context.Context) (credentialStore, error) {
				t.Fatal("backend opened on invalid config")
				return nil, nil
			},
		})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unreadable config") {
			t.Fatalf("config error = %v", err)
		}
	}
	for _, args := range [][]string{{"--help"}, {"ssh", "--help"}, {"scp", "--help"}, {"credentials", "list", "--help"}, {"help", "ssh"}, {"completion", "bash"}, {"__complete", "ssh", ""}} {
		cmd := newRootCommandWithDependencies(dependencies{loadConfig: func() (optionOverrides, error) {
			t.Fatal("help/completion loaded config")
			return optionOverrides{}, nil
		}})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
	}
	// Production construction actually installs the loader, not only test injection.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.Mkdir(filepath.Join(dir, "sshx"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshx", "config.yaml"), []byte("bad: value"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	cmd.SetArgs([]string{"credentials", "list"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown configuration key") {
		t.Fatalf("production config load: %v", err)
	}
}
