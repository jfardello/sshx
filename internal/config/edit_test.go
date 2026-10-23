package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jfardello/sshx/internal/fileupdate"
)

func editTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sshx", "config.yaml")
}

func writeEditConfig(t *testing.T, name, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func readEditConfig(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEditUserPath(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	for _, tc := range []struct{ xdg, want string }{
		{xdg, filepath.Join(xdg, "sshx", "config.yaml")},
		{"relative", filepath.Join(home, ".config", "sshx", "config.yaml")},
		{"", filepath.Join(home, ".config", "sshx", "config.yaml")},
	} {
		t.Setenv("XDG_CONFIG_HOME", tc.xdg)
		got, err := UserPath()
		if err != nil || got != tc.want {
			t.Fatalf("UserPath = %q, %v; want %q", got, err, tc.want)
		}
	}
	t.Setenv("HOME", "")
	if _, err := UserPath(); err == nil {
		t.Fatal("missing home accepted")
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got, err := UserPath(); err != nil || got != filepath.Join(xdg, "sshx", "config.yaml") {
		t.Fatalf("absolute XDG requires no home: %q, %v", got, err)
	}
}

func TestEditAllKeysAndSettings(t *testing.T) {
	keys := []string{
		"credential-backend", "secret-collection", "gopass-prefix", "verbose", "options",
		"agent.verbose", "agent.cache-ttl", "agent.prompt-helper", "agent.allow-forwarding",
		"agent.allow-key-mutations", "agent.socket", "agent.state-file",
		"ssh.ui", "ssh.prompt-helper",
	}
	values := []string{"gopass", "", "prefix/", "false", "true", "false", "90s", "/helper", "false", "true", "", "/state", "shell", "/ssh-helper"}
	name := editTestPath(t)
	stored, err := Settings(name, false)
	if err != nil || len(stored) != 0 {
		t.Fatalf("absent stored settings: %v, %v", stored, err)
	}
	defaults, err := Settings(name, true)
	if err != nil || len(defaults) != len(keys) {
		t.Fatalf("defaults: %v, %v", defaults, err)
	}
	for i, key := range keys {
		want := ""
		switch key {
		case "credential-backend":
			want = "auto"
		case "verbose", "agent.verbose", "agent.allow-forwarding", "agent.allow-key-mutations":
			want = "false"
		case "agent.cache-ttl":
			want = "0s"
		case "ssh.ui":
			want = "none"
		}
		if defaults[i] != (Setting{key, want, "default"}) {
			t.Fatalf("default %d: %+v", i, defaults[i])
		}
		alias := strings.ReplaceAll(key, "-", "_")
		if got, err := NormalizeKey(alias); err != nil || got != key {
			t.Fatalf("normalize %q: %q, %v", alias, got, err)
		}
		if pub, err := Set(context.Background(), name, alias, values[i]); err != nil || pub != fileupdate.Published {
			t.Fatalf("set %s: %v, %v", alias, pub, err)
		}
	}
	stored, err = Settings(name, false)
	if err != nil || len(stored) != len(keys) {
		t.Fatalf("stored: %v, %v", stored, err)
	}
	for i, key := range keys {
		want := values[i]
		if key == "agent.cache-ttl" {
			want = "1m30s"
		}
		if stored[i] != (Setting{key, want, "file"}) {
			t.Fatalf("stored %d: %+v", i, stored[i])
		}
	}
	effective, err := Settings(name, true)
	if err != nil || !reflect.DeepEqual(effective, stored) {
		t.Fatalf("effective stored settings: %v, %v", effective, err)
	}
	for _, key := range keys {
		if pub, err := Unset(context.Background(), name, strings.ReplaceAll(key, "-", "_")); err != nil || pub != fileupdate.Published {
			t.Fatalf("unset %s: %v, %v", key, pub, err)
		}
	}
	stored, err = Settings(name, false)
	if err != nil || len(stored) != 0 {
		t.Fatalf("unset stored settings: %v, %v", stored, err)
	}
	effective, err = Settings(name, true)
	if err != nil || !reflect.DeepEqual(effective, defaults) {
		t.Fatalf("unset defaults: %v, %v", effective, err)
	}
}

func TestEditCommentsAndSemantics(t *testing.T) {
	name := editTestPath(t)
	writeEditConfig(t, name, "# document\ncredential-backend: auto # backend\n# options head\noptions: 'original' # options inline\nsecret-collection: '' # unrelated\nagent: # agent inline\n  # ttl head\n  cache-ttl: 90s # ttl inline\n  socket: /socket # socket inline\n# document footer\n")
	if pub, err := Set(context.Background(), name, "options", "true\nsecond line"); err != nil || pub != fileupdate.Published {
		t.Fatalf("set: %v, %v", pub, err)
	}
	if pub, err := Unset(context.Background(), name, "agent.cache-ttl"); err != nil || pub != fileupdate.Published {
		t.Fatalf("unset: %v, %v", pub, err)
	}
	data := readEditConfig(t, name)
	for _, comment := range []string{"# document", "# backend", "# options head", "# options inline", "# unrelated", "# agent inline", "# ttl head", "# ttl inline", "# socket inline", "# document footer"} {
		if !strings.Contains(data, comment) {
			t.Errorf("lost comment %q in %s", comment, data)
		}
	}
	got, err := Load(name)
	if err != nil || got.Options == nil || *got.Options != "true\nsecond line" || got.SecretCollection == nil || *got.SecretCollection != "" || got.Agent.Socket == nil || *got.Agent.Socket != "/socket" || got.Agent.CacheTTL != nil {
		t.Fatalf("edited semantics: %+v, %v", got, err)
	}
	if _, err := Unset(context.Background(), name, "agent.socket"); err != nil {
		t.Fatal(err)
	}
	data = readEditConfig(t, name)
	for _, comment := range []string{"# ttl head", "# ttl inline", "# socket inline", "# agent inline", "# document footer"} {
		if !strings.Contains(data, comment) {
			t.Errorf("lost empty-agent comment %q in %s", comment, data)
		}
	}
	got, err = Load(name)
	if err != nil || got.Agent == nil || !reflect.DeepEqual(*got.Agent, AgentOverrides{}) {
		t.Fatalf("empty agent: %+v, %v", got.Agent, err)
	}
}

func TestEditLastSettingComments(t *testing.T) {
	for _, original := range []string{
		"# head\noptions: original # inline\n# foot\n",
		"# head\nagent: {socket: /socket} # inline\n# foot\n",
		"# head\nagent: # inline\n  socket: /socket\n# foot\n",
	} {
		t.Run(original, func(t *testing.T) {
			name := editTestPath(t)
			writeEditConfig(t, name, original)
			key := "options"
			if strings.Contains(original, "agent:") {
				key = "agent.socket"
			}
			if pub, err := Unset(context.Background(), name, key); err != nil || pub != fileupdate.Published {
				t.Fatalf("unset last: %v, %v", pub, err)
			}
			for _, comment := range []string{"# head", "# inline", "# foot"} {
				if !strings.Contains(readEditConfig(t, name), comment) {
					t.Fatalf("lost %s after unset", comment)
				}
			}
			if pub, err := Set(context.Background(), name, key, ""); err != nil || pub != fileupdate.Published {
				t.Fatalf("set again: %v, %v", pub, err)
			}
			for _, comment := range []string{"# head", "# inline", "# foot"} {
				if !strings.Contains(readEditConfig(t, name), comment) {
					t.Fatalf("lost %s after set again", comment)
				}
			}
		})
	}
}

func TestEditNoops(t *testing.T) {
	name := editTestPath(t)
	if pub, err := Unset(context.Background(), name, "agent.verbose"); err != nil || pub != fileupdate.Unchanged {
		t.Fatalf("absent unset: %v, %v", pub, err)
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent unset created target: %v", err)
	}
	original := "# unchanged\nverbose: false\noptions: ''\nagent: {cache-ttl: 90s}\n"
	writeEditConfig(t, name, original)
	before, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, value string }{{"verbose", "false"}, {"options", ""}, {"agent.cache-ttl", "1m30s"}} {
		if pub, err := Set(context.Background(), name, tc.key, tc.value); err != nil || pub != fileupdate.Unchanged {
			t.Fatalf("same typed %s: %v, %v", tc.key, pub, err)
		}
	}
	if pub, err := Unset(context.Background(), name, "agent.socket"); err != nil || pub != fileupdate.Unchanged {
		t.Fatalf("missing key unset: %v, %v", pub, err)
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || readEditConfig(t, name) != original {
		t.Fatalf("no-op rewrote target: %v", err)
	}
}

func TestEditEmptyInput(t *testing.T) {
	for _, original := range []string{"", " \n", "# comment only\n", "{}\n"} {
		t.Run(original, func(t *testing.T) {
			name := editTestPath(t)
			writeEditConfig(t, name, original)
			if pub, err := Set(context.Background(), name, "agent.verbose", "false"); err != nil || pub != fileupdate.Published {
				t.Fatalf("set empty: %v, %v", pub, err)
			}
			got, err := Settings(name, false)
			if err != nil || !reflect.DeepEqual(got, []Setting{{"agent.verbose", "false", "file"}}) {
				t.Fatalf("empty set settings: %v, %v", got, err)
			}
			if strings.Contains(original, "# comment only") && !strings.Contains(readEditConfig(t, name), "# comment only") {
				t.Fatal("lost comment-only input")
			}
		})
	}
}

func TestEditIndentedCommentOnlyInput(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{
			input: "  # alpha\n\n  # beta\n",
			want:  "# alpha\n\n# beta\noptions: value\n",
		},
		{
			input: "\n  # alpha  # text\r\n  \r\n\r\n    #   beta\r\n\n",
			want:  "# alpha  # text\n\n\n#   beta\noptions: value\n",
		},
	} {
		t.Run(tc.input, func(t *testing.T) {
			name := editTestPath(t)
			writeEditConfig(t, name, tc.input)
			if pub, err := Set(context.Background(), name, "options", "value"); err != nil || pub != fileupdate.Published {
				t.Fatalf("set: %v, %v", pub, err)
			}
			if got := readEditConfig(t, name); got != tc.want {
				t.Fatalf("comment-only output = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestEditValidationBeforeFilesystem(t *testing.T) {
	invalid := []struct{ key, value string }{
		{"secret-key", "secret-value"}, {"agent", "secret-value"}, {"agent_verbose", "true"}, {"Verbose", "true"}, {" agent.verbose", "true"},
		{"verbose", "True"}, {"verbose", "1"}, {"verbose", ""}, {"agent.allow-forwarding", "yes"}, {"agent.allow-key-mutations", "FALSE"},
		{"credential-backend", "secret-value"}, {"credential-backend", ""}, {"gopass-prefix", "/secret"}, {"gopass-prefix", "secret/../path"},
		{"agent.cache-ttl", "secret-duration"}, {"agent.cache-ttl", ""}, {"agent.cache-ttl", "-1ns"}, {"agent.cache-ttl", "5m1ns"},
		{"agent.prompt-helper", "secret-relative"}, {"agent.socket", "/secret/../path"}, {"agent.state-file", "/secret/\npath"},
		{"options", strings.Repeat("secret", MaxBytes)},
	}
	for _, tc := range invalid {
		name := editTestPath(t)
		pub, err := Set(context.Background(), name, tc.key, tc.value)
		if pub != fileupdate.Unchanged || !errors.Is(err, fileupdate.ErrInvalid) {
			t.Fatalf("invalid %s: %v, %v", tc.key, pub, err)
		}
		if (strings.Contains(tc.value, "secret") && strings.Contains(err.Error(), tc.value)) || strings.Contains(err.Error(), "secret-key") {
			t.Fatalf("input leaked: %v", err)
		}
		if _, err := os.Stat(filepath.Dir(name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid input created directory: %v", err)
		}
	}
	name := editTestPath(t)
	if _, err := Unset(context.Background(), name, "secret-key"); !errors.Is(err, fileupdate.ErrInvalid) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unset invalid key: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid unset created directory: %v", err)
	}
}

func TestEditInvalidDocuments(t *testing.T) {
	inputs := []string{
		"options: [secret", "secret-key: secret-value", "options: secret-one\noptions: secret-two", "options: null", "agent: null",
		"agent: {verbose: 'secret'}", "options: secret\n---\n{}", "options: &secret secret-value", "[]", strings.Repeat("#secret", MaxBytes/7+1),
	}
	for _, input := range inputs {
		name := editTestPath(t)
		writeEditConfig(t, name, input)
		for _, unset := range []bool{false, true} {
			var pub fileupdate.Publication
			var err error
			if unset {
				pub, err = Unset(context.Background(), name, "options")
			} else {
				pub, err = Set(context.Background(), name, "verbose", "false")
			}
			if pub != fileupdate.Unchanged || !errors.Is(err, fileupdate.ErrInvalid) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid document: %v, %v", pub, err)
			}
			if readEditConfig(t, name) != input {
				t.Fatal("invalid input changed")
			}
		}
		if _, err := Settings(name, true); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid query: %v", err)
		}
	}
}

func TestEditOutputBound(t *testing.T) {
	name := editTestPath(t)
	original := "options: '" + strings.Repeat("x", MaxBytes-12) + "'\n"
	writeEditConfig(t, name, original)
	if _, err := Decode([]byte(original)); err != nil {
		t.Fatal(err)
	}
	pub, err := Set(context.Background(), name, "verbose", "true")
	if pub != fileupdate.Unchanged || !errors.Is(err, fileupdate.ErrInvalid) || readEditConfig(t, name) != original {
		t.Fatalf("oversized output: %v, %v", pub, err)
	}
}

func TestEditSymlinkReadWriteSplit(t *testing.T) {
	name := editTestPath(t)
	writeEditConfig(t, name, "options: secret-value\n")
	link := filepath.Join(filepath.Dir(name), "link.yaml")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(filepath.Dir(filepath.Dir(name)), "alias")
	if err := os.Symlink(filepath.Dir(name), ancestor); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(ancestor, "config.yaml")} {
		got, err := Settings(path, false)
		if err != nil || !reflect.DeepEqual(got, []Setting{{"options", "secret-value", "file"}}) {
			t.Fatalf("symlink query: %v, %v", got, err)
		}
		if pub, err := Set(context.Background(), path, "verbose", "false"); pub != fileupdate.Unchanged || !errors.Is(err, fileupdate.ErrInvalid) {
			t.Fatalf("symlink set: %v, %v", pub, err)
		}
		if pub, err := Unset(context.Background(), path, "options"); pub != fileupdate.Unchanged || !errors.Is(err, fileupdate.ErrInvalid) {
			t.Fatalf("symlink unset: %v, %v", pub, err)
		}
	}
	if readEditConfig(t, name) != "options: secret-value\n" {
		t.Fatal("symlink target changed")
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if _, err := Settings(link, true); err == nil {
		t.Fatal("dangling symlink query accepted")
	}
}

func TestEditAllowsCrossFieldCombinations(t *testing.T) {
	name := editTestPath(t)
	for _, tc := range []struct{ key, value string }{
		{"credential-backend", "secret-service"}, {"gopass-prefix", "prefix"}, {"secret-collection", "collection"},
		{"agent.cache-ttl", "5m"}, {"agent.prompt-helper", ""}, {"agent.allow-forwarding", "true"}, {"agent.allow-key-mutations", "true"},
	} {
		if pub, err := Set(context.Background(), name, tc.key, tc.value); err != nil || pub != fileupdate.Published {
			t.Fatalf("cross-field %s: %v, %v", tc.key, pub, err)
		}
	}
	if _, err := Load(name); err != nil {
		t.Fatal(err)
	}
}
