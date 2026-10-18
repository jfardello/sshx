package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/credential/gopass"
	"github.com/jfardello/sshx/internal/keystore"
	"golang.org/x/crypto/ssh/agent"
)

// Called inside the disposable GPG fixture, after raw retrieval has been checked.
// The production opener must retrieve the enrolled key again through gopass.
func testGopassAgentRoundTrip(t *testing.T, ctx context.Context, record agentKeyRecord) {
	t.Helper()
	registry, err := parseAgentRegistry(registryJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(socketPath, registry, keystore.Open)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.Serve(ctx)
	client := agent.NewClient(agentTestDial(t, socketPath))
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("gopass-backed agent list", err)
	}
	data := []byte("disposable gopass agent challenge")
	signature, err := client.Sign(keys[0], data)
	if err != nil {
		t.Fatal("gopass-backed agent signing", err)
	}
	if err := registry.keys[0].publicKey.Verify(data, signature); err != nil {
		t.Fatal("invalid gopass-backed signature", err)
	}
}

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
				cmd.Env = gopass.KeyEnvironment(os.Environ())
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
			record, raw := testAgentKey(t)
			defer clearBytes(raw)
			encrypted := run(raw, "gpg", "--batch", "--yes", "--trust-model", "always", "--encrypt", "--recipient", "sshx-fixture@example.invalid")
			if err := os.WriteFile(filepath.Join(home, "store", "test-key.gpg"), encrypted, 0600); err != nil {
				t.Fatal(err)
			}
			if protected {
				run(nil, "gpgconf", "--kill", "gpg-agent")
			}
			store := gopass.New(nil)
			data, err := store.KeyMaterial(ctx, credentialRef{Backend: credentialBackendGopass, ID: "test-key"})
			defer clearBytes(data)
			if protected {
				if !errors.Is(err, credential.ErrLocked) || len(data) != 0 {
					t.Fatalf("locked GPG keyring: error=%v, bytes=%d; want ErrLocked and no material", err, len(data))
				}
				return
			}
			if err != nil || !bytes.Equal(data, raw) {
				t.Fatal("gopass did not preserve full key bytes", err)
			}
			record.Reference = "test-key"
			testGopassAgentRoundTrip(t, ctx, record)
			if _, err := store.KeyMaterial(ctx, credentialRef{Backend: credentialBackendGopass, ID: "test-ke"}); err == nil {
				t.Fatal("missing path selected a fuzzy match")
			}
		})
	}
}
