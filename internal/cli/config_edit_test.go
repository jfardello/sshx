package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfardello/sshx/internal/config"
	"github.com/jfardello/sshx/internal/fileupdate"
)

// Exercise root dispatch while making any unrelated loader or backend work fail.
func configEditExecute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	store := &recordingStore{}
	cmd := newRootCommandWithDependencies(dependencies{
		stdout: &stdout, stderr: &stderr, gopassStore: store,
		loadConfig: func() (optionOverrides, error) {
			t.Fatal("config command called deps.loadConfig")
			return optionOverrides{}, nil
		},
		secretServiceStore: func(context.Context) (credentialStore, error) {
			t.Fatal("config command opened Secret Service")
			return nil, nil
		},
		runProgram: func(string, []string, []byte) error {
			t.Fatal("config command ran an external program")
			return nil
		},
		systemctl: func(context.Context, ...string) ([]byte, error) {
			t.Fatal("config command called systemctl")
			return nil, nil
		},
	})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	if store.searchCalls != 0 || store.secretCalls != 0 || store.closeCalls != 0 {
		t.Fatalf("config command accessed gopass: %+v", store)
	}
	if stderr.Len() != 0 {
		t.Fatalf("%v: unexpected stderr %q", args, stderr.String())
	}
	return stdout.String(), err
}

func configEditWant(t *testing.T, want string, args ...string) {
	t.Helper()
	got, err := configEditExecute(t, args...)
	if err != nil || got != want {
		t.Fatalf("%v: stdout=%q, error=%v; want %q", args, got, err, want)
	}
}

func configEditPath(t *testing.T) string {
	t.Helper()
	name, err := config.UserPath()
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func configEditWrite(t *testing.T, name, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func configEditRead(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var configEditSettings = []struct{ key, value, printed, fallback string }{
	{"credential-backend", "secret-service", "secret-service", "auto"},
	{"secret-collection", "Login\t\"quoted\"\nnext\\line", "Login\t\"quoted\"\nnext\\line", ""},
	{"gopass-prefix", "infra/production/", "infra/production/", ""},
	{"verbose", "false", "false", "false"},
	{"options", "-o ProxyCommand=echo 'hello world'", "-o ProxyCommand=echo 'hello world'", ""},
	{"agent.verbose", "true", "true", "false"},
	{"agent.cache-ttl", "90s", "1m30s", "0s"},
	{"agent.prompt-helper", "/not-installed/helper", "/not-installed/helper", ""},
	{"agent.allow-forwarding", "true", "true", "false"},
	{"agent.allow-key-mutations", "false", "false", "false"},
	{"agent.socket", "/not-created/agent.sock", "/not-created/agent.sock", ""},
	{"agent.state-file", "/not-created/state", "/not-created/state", ""},
	{"ssh.ui", "shell", "shell", "none"},
	{"ssh.prompt-helper", "/ssh-helper", "/ssh-helper", ""},
}

func TestConfigEditShorthandExplicitAndAliases(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, aliases := range []bool{false, true} {
			t.Run(fmt.Sprintf("explicit=%t/aliases=%t", explicit, aliases), func(t *testing.T) {
				agentCLIHome(t)
				var list, effective strings.Builder
				for _, setting := range configEditSettings {
					key := setting.key
					if aliases {
						key = strings.ReplaceAll(key, "-", "_")
					}
					args := []string{"config"}
					if explicit {
						args = append(args, "set")
					}
					configEditWant(t, "", append(args, key, "--", setting.value)...)
					for _, spelling := range []string{setting.key, strings.ReplaceAll(setting.key, "-", "_")} {
						configEditWant(t, fmt.Sprintf("%q\n", setting.printed), "config", spelling)
						configEditWant(t, fmt.Sprintf("%q\n", setting.printed), "config", "get", spelling)
						configEditWant(t, fmt.Sprintf("%q\t(file)\n", setting.printed), "config", "get", spelling, "--effective")
					}
					fmt.Fprintf(&list, "%s = %q\n", setting.key, setting.printed)
					fmt.Fprintf(&effective, "%s = %q\t(file)\n", setting.key, setting.printed)
				}
				configEditWant(t, list.String(), "config")
				configEditWant(t, list.String(), "config", "list")
				configEditWant(t, effective.String(), "config", "--effective")
				configEditWant(t, effective.String(), "config", "--effective", "list")
				for _, setting := range configEditSettings {
					configEditWant(t, "", "config", "unset", strings.ReplaceAll(setting.key, "-", "_"))
				}
				configEditWant(t, "", "config", "list")
			})
		}
	}
}

func TestConfigEditDefaultsAndEffectiveFlagPositions(t *testing.T) {
	agentCLIHome(t)
	name := configEditPath(t)
	configEditWant(t, "", "config")
	configEditWant(t, "", "config", "list")
	var defaults strings.Builder
	for _, setting := range configEditSettings {
		fmt.Fprintf(&defaults, "%s = %q\t(default)\n", setting.key, setting.fallback)
		for _, args := range [][]string{
			{"config", setting.key}, {"config", "get", setting.key},
		} {
			got, err := configEditExecute(t, args...)
			if err == nil || !strings.Contains(err.Error(), "not stored") || !strings.Contains(err.Error(), "--effective") || got != "" {
				t.Fatalf("%v: stdout=%q, error=%v", args, got, err)
			}
		}
		for _, args := range [][]string{
			{"config", "--effective", setting.key},
			{"config", setting.key, "--effective=true"},
			{"config", "--effective", "get", setting.key},
			{"config", "get", "--effective=true", setting.key},
			{"config", "get", setting.key, "--effective"},
		} {
			configEditWant(t, fmt.Sprintf("%q\t(default)\n", setting.fallback), args...)
		}
	}
	for _, args := range [][]string{
		{"config", "--effective"}, {"config", "--effective", "list"}, {"config", "list", "--effective"},
	} {
		configEditWant(t, defaults.String(), args...)
	}
	configEditWant(t, "", "config", "list", "--effective=false")
	if _, err := os.Stat(filepath.Dir(name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only commands created configuration directory: %v", err)
	}

	configEditWant(t, "", "config", "verbose", "false")
	configEditWant(t, "", "config", "set", "options", "")
	configEditWant(t, "\"false\"\t(file)\n", "config", "verbose", "--effective")
	configEditWant(t, "\"\"\t(file)\n", "config", "--effective", "get", "options")
	configEditWant(t, "\"false\"\n", "config", "get", "verbose", "--effective=false")
	want := strings.Replace(defaults.String(), "verbose = \"false\"\t(default)\n", "verbose = \"false\"\t(file)\n", 1)
	want = strings.Replace(want, "options = \"\"\t(default)\n", "options = \"\"\t(file)\n", 1)
	configEditWant(t, want, "config", "list", "--effective")
	for _, key := range []string{"verbose", "options"} {
		configEditWant(t, "", "config", "unset", key)
		configEditWant(t, "", "config", "unset", key)
	}
	configEditWant(t, defaults.String(), "config", "--effective")
}

func TestConfigEditStrictArguments(t *testing.T) {
	agentCLIHome(t)
	name := configEditPath(t)
	original := "# untouched\nverbose: false\n"
	configEditWrite(t, name, original)
	for _, args := range [][]string{
		{"config", "verbose", "true", "extra"},
		{"config", "get"}, {"config", "get", "verbose", "extra"},
		{"config", "set"}, {"config", "set", "verbose"}, {"config", "set", "verbose", "true", "extra"},
		{"config", "unset"}, {"config", "unset", "verbose", "extra"},
		{"config", "list", "extra"}, {"config", "path", "extra"},
		{"config", "--unknown"}, {"config", "get", "verbose", "--effective=invalid"},
		{"config", "unknown"}, {"config", "get", "agent.unknown"},
		{"config", "set", "agent", "true"}, {"config", "unset", "Verbose"},
		{"config", "--effective", "verbose", "true"},
		{"config", "verbose", "true", "--effective=false"},
		{"config", "--effective", "set", "verbose", "true"},
		{"config", "set", "verbose", "true", "--effective=false"},
		{"config", "--effective=false", "unset", "verbose"},
		{"config", "unset", "verbose", "--effective"},
		{"config", "--effective", "path"}, {"config", "path", "--effective=false"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			got, err := configEditExecute(t, args...)
			if err == nil || got != "" {
				t.Fatalf("stdout=%q, error=%v", got, err)
			}
			if strings.Contains(strings.Join(args, " "), "--effective") && !strings.Contains(strings.Join(args, " "), "invalid") && !strings.Contains(err.Error(), "only to get and list") {
				t.Fatalf("wrong effective restriction: %v", err)
			}
			if got := configEditRead(t, name); got != original {
				t.Fatalf("invalid arguments changed file: %q", got)
			}
		})
	}
}

func TestConfigEditInvalidValuesAreNotPublished(t *testing.T) {
	agentCLIHome(t)
	name := configEditPath(t)
	original := "# untouched\noptions: original\n"
	configEditWrite(t, name, original)
	for _, tc := range []struct{ key, value string }{
		{"credential-backend", "invalid"}, {"credential-backend", ""},
		{"gopass-prefix", "../escape"}, {"gopass-prefix", "/absolute"},
		{"verbose", "True"}, {"verbose", "1"}, {"agent.verbose", ""},
		{"agent.allow-forwarding", "yes"}, {"agent.allow-key-mutations", "FALSE"},
		{"agent.cache-ttl", "garbage"}, {"agent.cache-ttl", "-1s"}, {"agent.cache-ttl", "5m1s"},
		{"agent.prompt-helper", "relative"}, {"agent.socket", "/tmp/../socket"},
		{"agent.state-file", "/tmp/state/"}, {"agent.socket", "/tmp/socket\n"},
	} {
		for _, explicit := range []bool{false, true} {
			args := []string{"config"}
			if explicit {
				args = append(args, "set")
			}
			args = append(args, tc.key, "--", tc.value)
			got, err := configEditExecute(t, args...)
			if !errors.Is(err, fileupdate.ErrInvalid) || !strings.Contains(err.Error(), "configuration was not published") || got != "" {
				t.Fatalf("%v: stdout=%q, error=%v", args, got, err)
			}
			if configEditRead(t, name) != original {
				t.Fatalf("%v changed configuration", args)
			}
		}
	}
	for _, value := range []string{"0", "0s", "300s", "5m"} {
		configEditWant(t, "", "config", "set", "agent.cache-ttl", value)
		want := "0s"
		if value == "300s" || value == "5m" {
			want = "5m0s"
		}
		configEditWant(t, fmt.Sprintf("%q\n", want), "config", "agent.cache-ttl")
	}
	// Values beginning with flags remain possible with the normal -- boundary.
	configEditWant(t, "", "config", "set", "options", "--", "--effective")
	configEditWant(t, "\"--effective\"\n", "config", "options")
}

func TestConfigEditInvalidFileHelpAndPath(t *testing.T) {
	agentCLIHome(t)
	name := configEditPath(t)
	for _, original := range []string{
		"options: [unterminated\n", "unknown: redacted-secret\n", "verbose: 'false'\n",
		"verbose: false\nverbose: true\n", "---\n{}\n---\n{}\n",
		"agent: {cache-ttl: 6m}\n", strings.Repeat("#", config.MaxBytes+1),
	} {
		configEditWrite(t, name, original)
		configEditWant(t, name+"\n", "config", "path")
		for _, args := range [][]string{
			{"config", "--help"}, {"help", "config"}, {"config", "get", "--help"},
			{"config", "set", "--help"}, {"config", "unset", "--help"},
			{"config", "list", "--help"}, {"config", "path", "--help"},
		} {
			got, err := configEditExecute(t, args...)
			if err != nil || !strings.Contains(got, "Usage:") || !strings.Contains(got, "--effective") {
				t.Fatalf("%v: help=%q, error=%v", args, got, err)
			}
		}
		for _, args := range [][]string{
			{"config"}, {"config", "list", "--effective"}, {"config", "verbose"},
			{"config", "get", "verbose", "--effective"},
			{"config", "set", "verbose", "false"}, {"config", "unset", "options"},
		} {
			got, err := configEditExecute(t, args...)
			if err == nil || got != "" || strings.Contains(err.Error(), "redacted-secret") {
				t.Fatalf("%v: stdout=%q, error=%v", args, got, err)
			}
		}
		if configEditRead(t, name) != original {
			t.Fatal("invalid configuration was changed")
		}
	}
}

func TestConfigEditUserPathEnvironment(t *testing.T) {
	dir := agentCLIHome(t)
	home := filepath.Join(dir, "home")
	t.Setenv("HOME", home)
	for _, xdg := range []string{filepath.Join(dir, "absolute-xdg"), "relative-xdg", ""} {
		t.Setenv("XDG_CONFIG_HOME", xdg)
		want := filepath.Join(home, ".config", "sshx", "config.yaml")
		if filepath.IsAbs(xdg) {
			want = filepath.Join(xdg, "sshx", "config.yaml")
		}
		configEditWant(t, want+"\n", "config", "path")
		configEditWant(t, "", "config", "set", "options", xdg)
		configEditWant(t, fmt.Sprintf("%q\n", xdg), "config", "get", "options")
		if !strings.Contains(configEditRead(t, want), "options:") {
			t.Fatal("set did not write the selected user path")
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "relative")
	for _, args := range [][]string{{"config", "path"}, {"config"}, {"config", "set", "verbose", "false"}, {"config", "unset", "verbose"}} {
		got, err := configEditExecute(t, args...)
		if err == nil || !strings.Contains(err.Error(), "home directory is unavailable") || got != "" {
			t.Fatalf("%v: stdout=%q, error=%v", args, got, err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "without-home"))
	configEditWant(t, filepath.Join(dir, "without-home", "sshx", "config.yaml")+"\n", "config", "path")
	configEditWant(t, "", "config", "set", "verbose", "false")
}

func TestConfigEditCommentsAndNoops(t *testing.T) {
	agentCLIHome(t)
	name := configEditPath(t)
	original := "# document\noptions: 'original' # options inline\nsecret-collection: '' # unrelated\nagent: # agent inline\n  # ttl head\n  cache-ttl: 90s # ttl inline\n  socket: /socket # socket inline\n# footer\n"
	configEditWrite(t, name, original)
	before, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	configEditWant(t, "", "config", "agent.cache-ttl", "1m30s")
	configEditWant(t, "", "config", "unset", "verbose")
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || configEditRead(t, name) != original {
		t.Fatalf("no-op rewrote file: %v", err)
	}
	value := "true\nsecond line\t\"quoted\"\\end"
	configEditWant(t, "", "config", "set", "options", value)
	configEditWant(t, "", "config", "unset", "agent.cache_ttl")
	configEditWant(t, "", "config", "unset", "agent.socket")
	for _, comment := range []string{"# document", "# options inline", "# unrelated", "# agent inline", "# ttl head", "# ttl inline", "# socket inline", "# footer"} {
		if !strings.Contains(configEditRead(t, name), comment) {
			t.Errorf("lost comment %q", comment)
		}
	}
	configEditWant(t, fmt.Sprintf("%q\n", value), "config", "get", "options")
	configEditWant(t, "\"\"\n", "config", "secret-collection")
	configEditWant(t, "\"0s\"\t(default)\n", "config", "agent.cache-ttl", "--effective")
}

func TestConfigEditSymlinkReadAllowedWriteRefused(t *testing.T) {
	for _, ancestor := range []bool{false, true} {
		t.Run(fmt.Sprintf("ancestor=%t", ancestor), func(t *testing.T) {
			dir := agentCLIHome(t)
			name := configEditPath(t)
			target := filepath.Join(dir, "target", "config.yaml")
			original := "# target\nverbose: false\n"
			configEditWrite(t, target, original)
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			link, destination := name, target
			if ancestor {
				link, destination = filepath.Dir(name), filepath.Dir(target)
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(destination, link); err != nil {
				t.Fatal(err)
			}
			configEditWant(t, "\"false\"\n", "config", "verbose")
			configEditWant(t, "verbose = \"false\"\n", "config", "list")
			for _, args := range [][]string{{"config", "verbose", "true"}, {"config", "set", "verbose", "false"}, {"config", "unset", "verbose"}} {
				got, err := configEditExecute(t, args...)
				if !errors.Is(err, fileupdate.ErrInvalid) || !strings.Contains(err.Error(), "was not published") || got != "" {
					t.Fatalf("%v: stdout=%q, error=%v", args, got, err)
				}
			}
			if configEditRead(t, target) != original {
				t.Fatal("symlink target was changed")
			}
			info, err := os.Lstat(link)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("symlink was replaced: %v", err)
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if !ancestor {
				got, err := configEditExecute(t, "config", "list", "--effective")
				if err == nil || got != "" {
					t.Fatalf("dangling symlink treated as absent: stdout=%q, error=%v", got, err)
				}
			}
		})
	}
}

func TestConfigEditNonregularFileAndAbsentUnset(t *testing.T) {
	agentCLIHome(t)
	name := configEditPath(t)
	configEditWant(t, "", "config", "unset", "verbose")
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent unset created configuration: %v", err)
	}
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	configEditWant(t, name+"\n", "config", "path")
	for _, args := range [][]string{{"config"}, {"config", "get", "verbose"}, {"config", "set", "verbose", "true"}, {"config", "unset", "verbose"}} {
		got, err := configEditExecute(t, args...)
		if err == nil || got != "" {
			t.Fatalf("directory configuration accepted: %v: stdout=%q, error=%v", args, got, err)
		}
	}
}
