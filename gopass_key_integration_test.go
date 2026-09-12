package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Uses only disposable HOME, GPG keyring, config and password store. Normal tests
// never start real providers or touch the developer's credential stores.
func TestGopassKeyIntegration(t *testing.T) {
	if os.Getenv("SSHX_GOPASS_KEY_INTEGRATION") != "1" {
		t.Skip("set SSHX_GOPASS_KEY_INTEGRATION=1 to exercise disposable gopass/GPG")
	}
	for _, name := range []string{"gopass", "gpg", "gpgconf"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("required integration tool unavailable", name)
		}
	}
	for _, protected := range []bool{false, true} {
		name := "unprotected"
		if protected {
			name = "locked"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			gnupg := filepath.Join(home, "gnupg")
			if err := os.Mkdir(gnupg, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("GNUPGHOME", gnupg)
			t.Setenv("GOPASS_HOMEDIR", home)
			t.Setenv("GOPASS_CONFIG", filepath.Join(home, "gopass-config"))
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
			t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
			t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
			t.Setenv("PASSWORD_STORE_DIR", filepath.Join(home, "store"))
			t.Setenv("GOPASS_DEBUG", "")
			t.Setenv("GOPASS_DEBUG_LOG", "")
			t.Setenv("GOPASS_DEBUG_LOG_SECRETS", "")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			run := func(input []byte, program string, args ...string) []byte {
				t.Helper()
				cmd := exec.CommandContext(ctx, program, args...)
				cmd.Env = gopassKeyEnvironment(os.Environ())
				cmd.Stdin = bytes.NewReader(input)
				data, err := cmd.Output()
				if err != nil {
					t.Fatalf("disposable %s setup failed: %T", program, err)
				}
				return data
			}
			defer func() { cmd := exec.Command("gpgconf", "--kill", "gpg-agent"); cmd.Env = os.Environ(); _ = cmd.Run() }()
			passphrase := []byte("\n")
			if protected {
				passphrase = []byte("synthetic-keyring-passphrase\n")
			}
			run(passphrase, "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--quick-generate-key", "sshx-fixture@example.invalid", "rsa2048", "encr", "0")
			run(nil, "gopass", "init", "--path", filepath.Join(home, "store"), "--storage", "fs", "--crypto", "gpgcli", "sshx-fixture@example.invalid")
			_, raw := testAgentKey(t)
			defer clearBytes(raw)
			encrypted := run(raw, "gpg", "--batch", "--yes", "--trust-model", "always", "--encrypt", "--recipient", "sshx-fixture@example.invalid")
			if err := os.WriteFile(filepath.Join(home, "store", "test-key.gpg"), encrypted, 0600); err != nil {
				t.Fatal(err)
			}
			if protected {
				run(nil, "gpgconf", "--kill", "gpg-agent")
			}
			store := newGopassStore(nil)
			data, err := store.KeyMaterial(ctx, credentialRef{Backend: credentialBackendGopass, ID: "test-key"})
			defer clearBytes(data)
			if protected {
				if err == nil || len(data) != 0 {
					t.Fatal("locked GPG keyring yielded material")
				}
				return
			}
			if err != nil || !bytes.Equal(data, raw) {
				t.Fatal("gopass did not preserve full key bytes", err)
			}
			if _, err := store.KeyMaterial(ctx, credentialRef{Backend: credentialBackendGopass, ID: "test-ke"}); err == nil {
				t.Fatal("missing path selected a fuzzy match")
			}
		})
	}
}
