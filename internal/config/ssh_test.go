package config

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHSettingsSchemaAndEdits(t *testing.T) {
	for _, bad := range []string{
		"ssh: null", "ssh: []", "ssh: {ui: true}", "ssh: {ui: null}", "ssh: {ui: invalid}",
		"ssh: {ui: ''}", "ssh: {ui: shell, ui: none}", "ssh: {unknown: value}",
		"ssh: {prompt-helper: 1}", "ssh: {prompt-helper: relative}", "ssh: {prompt-helper: /a/../b}",
		"ssh: {prompt-helper: \"/bad\\npath\"}", "ssh: {ui: &mode shell}", "ssh: &settings {ui: shell}",
	} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, mode := range []string{"none", "shell", "desktop"} {
		got, err := Decode([]byte("ssh:\n  ui: " + mode + "\n  prompt-helper: ''\nagent:\n  prompt-helper: /agent\n"))
		if err != nil || got.SSH == nil || *got.SSH.UI != mode || *got.SSH.PromptHelper != "" || *got.Agent.PromptHelper != "/agent" {
			t.Fatal(got, err)
		}
	}
	name := filepath.Join(t.TempDir(), "config.yaml")
	writeEditConfig(t, name, "ssh: # SSH section\n  ui: shell # chooser\n  prompt-helper: /ssh # picker\nagent:\n  prompt-helper: /agent\n")
	if _, err := Set(context.Background(), name, "ssh.ui", "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := Unset(context.Background(), name, "ssh.prompt_helper"); err != nil {
		t.Fatal(err)
	}
	if _, err := Unset(context.Background(), name, "ssh.ui"); err != nil {
		t.Fatal(err)
	}
	data := readEditConfig(t, name)
	for _, comment := range []string{"# SSH section", "# chooser", "# picker"} {
		if !strings.Contains(data, comment) {
			t.Fatal("lost comment", comment, data)
		}
	}
	got, err := Load(name)
	if err != nil || got.Agent == nil || *got.Agent.PromptHelper != "/agent" {
		t.Fatal("agent helper changed", err)
	}
	if got.SSH != nil && (got.SSH.UI != nil || got.SSH.PromptHelper != nil) {
		t.Fatal("SSH overrides not removed")
	}
}
