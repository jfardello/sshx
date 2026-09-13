package gopass

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testPrivateKeyBytes(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestGopassKeyMaterialRawAndSanitized(t *testing.T) {
	raw := testPrivateKeyBytes(t)
	var diagnostic bytes.Buffer
	store := newGopassStore(&diagnostic)
	store.executeCommand = func(args ...string) ([]byte, []byte, error) {
		want := []string{"show", "--noparsing", "--unsafe", "--nofuzzysearch", "--nosync", "--alsoclip=false", "--", "keys/test"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("args: %#v", args)
		}
		return append([]byte(nil), raw...), []byte("private stderr"), nil
	}
	data, err := store.KeyMaterial(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "keys/test"})
	if err != nil || !bytes.Equal(data, raw) || diagnostic.Len() != 0 {
		t.Fatal("raw output changed or diagnostics leaked", err)
	}
	for _, ref := range []credentialRef{{Backend: credentialBackendSecretService, ID: "key"}, {Backend: credentialBackendGopass, ID: "../key"}, {Backend: credentialBackendGopass, ID: "--help"}} {
		if _, err := store.KeyMaterial(context.Background(), ref); !errors.Is(err, errCredentialReference) {
			t.Fatal(err)
		}
	}
	for _, failure := range []error{errors.New("unknown --noparsing private stderr"), context.DeadlineExceeded, errCredentialTooLarge} {
		store.executeCommand = func(...string) ([]byte, []byte, error) {
			return append([]byte(nil), raw...), []byte("private stderr"), failure
		}
		if data, err := store.KeyMaterial(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "key"}); err == nil || len(data) != 0 || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe failure")
		}
	}
	store.executeCommand = func(...string) ([]byte, []byte, error) { return make([]byte, maxKeyMaterialBytes+1), nil, nil }
	if _, err := store.KeyMaterial(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "key"}); !errors.Is(err, errCredentialTooLarge) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.KeyMaterial(ctx, credentialRef{Backend: credentialBackendGopass, ID: "key"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := store.Search(ctx, credentialQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := store.Secret(ctx, credentialRef{Backend: credentialBackendGopass, ID: "key"}, credentialReadOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestGopassKeyEnvironment(t *testing.T) {
	for _, name := range []string{"SSH_AUTH_SOCK", "SSH_AGENT_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		for _, value := range gopassKeyEnvironment([]string{name + "=must-not-inherit"}) {
			if strings.HasPrefix(value, name+"=") {
				t.Fatalf("helper inherited %s", name)
			}
		}
	}
	env := gopassKeyEnvironment([]string{"PATH=/bin", "GOPASS_CONFIG=/owned/config", "GOPASS_HOMEDIR=/owned/home", "GOPASS_DEBUG=1", "GOPASS_DEBUG_LOG_SECRETS=true", "GOPASS_MEM_PROFILE=/tmp/leak", "GOPASS_GPG_OPTS=--pinentry-mode ask", "PASSWORD_STORE_GPG_OPTS=--pinentry-mode ask", "GPG_TTY=/dev/tty", "GOPASS_AGE_PASSWORD=private"})
	joined := strings.Join(env, "\n")
	for _, bad := range []string{"private", "--pinentry-mode ask", "GOPASS_DEBUG", "GOPASS_MEM_PROFILE", "GPG_TTY="} {
		if strings.Contains(joined, bad) {
			t.Fatal("unsafe environment", bad)
		}
	}
	for _, want := range []string{"GOPASS_CONFIG=/owned/config", "GOPASS_HOMEDIR=/owned/home", "--batch --no-tty --pinentry-mode error", "GOPASS_HOOK=1", "core.follow-references", "age.agent-enabled"} {
		if !strings.Contains(joined, want) {
			t.Fatal("missing control", want)
		}
	}
}
func TestGopassSubprocessLimitsAndCancellation(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gopass")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("printf 'first\\nsecond\\n'\n")
	data, stderr, err := runGopassCommand(context.Background(), true, "show")
	if err != nil || string(data) != "first\nsecond\n" || len(stderr) != 0 {
		t.Fatal("subprocess output", err)
	}
	store := newGopassStore(nil)
	data, err = store.KeyMaterial(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "key"})
	if err != nil || string(data) != "first\nsecond\n" {
		t.Fatal(err)
	}
	write("head -c 70000 /dev/zero\n")
	if _, _, err := runGopassCommand(context.Background(), true, "show"); !errors.Is(err, errCredentialTooLarge) {
		t.Fatal("output limit", err)
	}
	write("sleep 20 &\nwait\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := runGopassCommand(ctx, true, "show"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("helper survived cancellation")
	}
	write("printf 'private stderr' >&2\nexit 2\n")
	if _, err := store.KeyMaterial(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "key"}); !errors.Is(err, errCredentialRead) {
		t.Fatal(err)
	}
}

func TestGopassPasswordReadDefaultsNoninteractive(t *testing.T) {
	store := newGopassStore(nil)
	store.executeCommand = func(args ...string) ([]byte, []byte, error) {
		want := []string{"show", "--password", "--nofuzzysearch", "--nosync", "--alsoclip=false", "--", "key"}
		if !reflect.DeepEqual(args, want) {
			t.Fatal("unsafe default read options", args)
		}
		return []byte("password\n"), []byte("hidden helper diagnostic"), nil
	}
	data, err := store.Secret(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "key"}, credentialReadOptions{})
	if err != nil || string(data) != "password" {
		t.Fatal(err)
	}
	if _, err := store.Search(context.Background(), credentialQuery{Attributes: map[string]string{"service": "sshx"}}); !errors.Is(err, errCredentialReference) {
		t.Fatal("ignored unsupported exact attribute query", err)
	}
}
