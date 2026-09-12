package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestGopassKeyMaterialRawAndSanitized(t *testing.T) {
	_, raw := testAgentKey(t)
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
	if _, err := store.Secret(ctx, credentialRef{Backend: credentialBackendGopass, ID: "key"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestGopassKeyEnvironment(t *testing.T) {
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

func keySecretServiceFixture(t *testing.T) (*secretServiceStore, *fakeSecretServiceTransport, credentialRef, []byte) {
	t.Helper()
	f := newFakeSecretServiceTransport()
	collection := dbus.ObjectPath("/collection")
	item := dbus.ObjectPath("/collection/key")
	session := dbus.ObjectPath("/session")
	attrs := map[string]string{"service": "sshx", "sshx.type": "ssh-key", "sshx.schema": "1", "sshx.id": "stable-id"}
	// Replace the helper's call body with the wire signature of ReadAlias.
	f.calls[secretServiceCallKey{secretServicePath, secretServiceInterface + ".ReadAlias"}] = []*dbus.Call{{Body: []any{collection}}}
	f.setProperty(collection, secretServiceCollectionInterface+".Locked", false)
	f.setProperty(collection, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{item})
	f.setProperty(item, secretServiceItemInterface+".Attributes", attrs)
	f.setProperty(item, secretServiceItemInterface+".Locked", false)
	_, data := testAgentKey(t)
	f.calls[secretServiceCallKey{secretServicePath, secretServiceInterface + ".OpenSession"}] = []*dbus.Call{{Body: []any{dbus.MakeVariant(""), session}}}
	f.calls[secretServiceCallKey{item, secretServiceItemInterface + ".GetSecret"}] = []*dbus.Call{{Body: []any{secretServiceSecret{Session: session, Value: append([]byte(nil), data...), ContentType: "text/plain"}}}}
	f.calls[secretServiceCallKey{session, secretServiceSessionInterface + ".Close"}] = []*dbus.Call{{}}
	return &secretServiceStore{transport: f}, f, credentialRef{Backend: credentialBackendSecretService, ID: "stable-id", Collection: "default"}, data
}
func TestSecretServiceKeyMaterial(t *testing.T) {
	s, f, ref, want := keySecretServiceFixture(t)
	data, err := s.KeyMaterial(context.Background(), ref)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatal("key read", err)
	}
	for _, call := range f.callLog {
		if strings.HasSuffix(call.method, ".Unlock") {
			t.Fatal("unlocked provider")
		}
	}
	if len(f.promptCalls) != 0 {
		t.Fatal("prompted")
	}
	for _, name := range []string{"locked collection", "locked item", "ambiguous", "missing", "wrong schema", "metadata changed", "provider error", "oversized", "collection relocked"} {
		t.Run(name, func(t *testing.T) {
			s, f, ref, _ := keySecretServiceFixture(t)
			collection := dbus.ObjectPath("/collection")
			item := dbus.ObjectPath("/collection/key")
			switch name {
			case "locked collection":
				f.properties[secretServicePropertyKey{collection, secretServiceCollectionInterface + ".Locked"}] = []propertyResult{{value: dbus.MakeVariant(true)}}
			case "locked item":
				f.properties[secretServicePropertyKey{item, secretServiceItemInterface + ".Locked"}] = []propertyResult{{value: dbus.MakeVariant(true)}}
			case "ambiguous":
				f.properties[secretServicePropertyKey{collection, secretServiceCollectionInterface + ".Items"}] = []propertyResult{{value: dbus.MakeVariant([]dbus.ObjectPath{item, item})}}
			case "missing":
				ref.ID = "missing-id"
			case "wrong schema":
				f.properties[secretServicePropertyKey{item, secretServiceItemInterface + ".Attributes"}] = []propertyResult{{value: dbus.MakeVariant(map[string]string{"sshx.id": "stable-id", "sshx.schema": "2"})}}
			case "metadata changed":
				f.setProperty(item, secretServiceItemInterface+".Attributes", map[string]string{"sshx.id": "changed-id"})
			case "provider error":
				f.calls[secretServiceCallKey{item, secretServiceItemInterface + ".GetSecret"}] = []*dbus.Call{{Err: errors.New("private provider message")}}
			case "oversized":
				f.calls[secretServiceCallKey{item, secretServiceItemInterface + ".GetSecret"}] = []*dbus.Call{{Body: []any{secretServiceSecret{Session: "/session", Value: make([]byte, maxKeyMaterialBytes+1)}}}}
			case "collection relocked":
				f.setProperty(collection, secretServiceCollectionInterface+".Locked", true)
			}
			data, err := s.KeyMaterial(context.Background(), ref)
			if err == nil || len(data) != 0 || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe key read", err)
			}
			if len(f.promptCalls) != 0 {
				t.Fatal("prompted")
			}
		})
	}
}
func TestSecretServiceNoninteractiveDiscovery(t *testing.T) {
	f := newFakeSecretServiceTransport()
	collection := dbus.ObjectPath("/collection")
	item := dbus.ObjectPath("/collection/key")
	f.setProperty(secretServicePath, secretServiceInterface+".Collections", []dbus.ObjectPath{collection})
	f.setProperty(collection, secretServiceCollectionInterface+".Label", "Test")
	f.setProperty(collection, secretServiceCollectionInterface+".Locked", true)
	f.setProperty(collection, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{item})
	f.setProperty(item, secretServiceItemInterface+".Label", "Key")
	f.setProperty(item, secretServiceItemInterface+".Attributes", map[string]string{"service": "sshx"})
	f.setProperty(item, secretServiceItemInterface+".Locked", false)
	s := &secretServiceStore{transport: f}
	refs, err := s.Search(context.Background(), credentialQuery{Attributes: map[string]string{"service": "sshx"}})
	if err != nil || len(refs) != 1 || !refs[0].Locked || len(f.callLog) != 0 || len(f.promptCalls) != 0 {
		t.Fatal("interactive discovery", err)
	}
	refs, err = s.Search(context.Background(), credentialQuery{Attributes: map[string]string{"service": "other"}})
	if err != nil || len(refs) != 0 {
		t.Fatal("inexact metadata query", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Search(ctx, credentialQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Secret(ctx, credentialRef{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.KeyMaterial(ctx, credentialRef{}); !errors.Is(err, context.Canceled) {
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
	data, err := store.Secret(context.Background(), credentialRef{Backend: credentialBackendGopass, ID: "key"})
	if err != nil || string(data) != "password" {
		t.Fatal(err)
	}
	if _, err := store.Search(context.Background(), credentialQuery{Attributes: map[string]string{"service": "sshx"}}); !errors.Is(err, errCredentialReference) {
		t.Fatal("ignored unsupported exact attribute query", err)
	}
}
