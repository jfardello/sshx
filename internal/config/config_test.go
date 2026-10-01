package config

import (
	"bytes"
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
	if err != nil || got.Verbose == nil || !*got.Verbose || !strings.Contains(got.Source, file) {
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
