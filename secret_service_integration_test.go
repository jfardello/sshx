package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

const secretServiceIntegrationEnvironment = "SSHX_SECRET_SERVICE_INTEGRATION"

var (
	integrationCollectionPath = dbus.ObjectPath("/org/freedesktop/secrets/collection/integration")
	integrationItemPath       = dbus.ObjectPath("/org/freedesktop/secrets/collection/integration/item")
	integrationPromptPath     = dbus.ObjectPath("/org/freedesktop/secrets/prompt/integration")
	integrationSessionPath    = dbus.ObjectPath("/org/freedesktop/secrets/session/integration")
)

type integrationSecretServiceProvider struct {
	conn       *dbus.Conn
	itemProps  *prop.Properties
	secret     []byte
	mutex      sync.Mutex
	failSecret bool
	prompts    int
	opened     int
	closed     int
	released   bool
}

func TestSecretServiceIntegration(t *testing.T) {
	if os.Getenv(secretServiceIntegrationEnvironment) != "1" {
		t.Skipf("set %s=1 and run under dbus-run-session", secretServiceIntegrationEnvironment)
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Fatal("DBUS_SESSION_BUS_ADDRESS is required")
	}

	provider, err := newIntegrationSecretServiceProvider([]byte("synthetic-integration-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clearBytes(provider.secret)
		_ = provider.conn.Close()
	})
	baselineNames := integrationBusNames(t, provider.conn)

	t.Run("discovery uses metadata only", func(t *testing.T) {
		var output bytes.Buffer
		err := executeCredentialList("integration", commandOptions{
			credentialBackend: credentialBackendSecretService,
			secretCollection:  "default",
		}, dependencies{
			goos:               "linux",
			secretServiceStore: newSecretServiceStore,
			stdout:             &output,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "BACKEND\tCOLLECTION\tLABEL\tTARGET\n" +
			"secret-service\tIntegration\tintegration\tintegration@127.0.0.1\n"
		if got := output.String(); got != want {
			t.Fatalf("credential list = %q, want %q", got, want)
		}
		if strings.Contains(output.String(), "synthetic-integration-password") {
			t.Fatalf("credential list exposed the synthetic secret: %q", output.String())
		}
		provider.assertCounts(t, 0, 0, 0)
		assertIntegrationConnectionsClosed(t, provider.conn, baselineNames)
	})

	t.Run("prompt retrieval and cleanup", func(t *testing.T) {
		var stderr bytes.Buffer
		runner := &recordingRunner{}
		err := executeSSH([]string{
			"integration",
			"--credential-backend", "secret-service",
			"--secret-collection", "default",
			"--verbose",
		}, dependencies{
			goos:               "linux",
			gopassStore:        &recordingStore{},
			secretServiceStore: newSecretServiceStore,
			runProgram:         runner.run,
			stdout:             &bytes.Buffer{},
			stderr:             &stderr,
		})
		if err != nil {
			t.Fatal(err)
		}
		if runner.program != "ssh" || !reflect.DeepEqual(runner.args, []string{"integration@127.0.0.1"}) {
			t.Fatalf("program/args = %q/%#v", runner.program, runner.args)
		}
		if got := string(runner.password); got != "synthetic-integration-password" {
			t.Fatalf("runner received %q, want the synthetic integration secret", got)
		}
		clearBytes(runner.password)
		if got, want := stderr.String(), "sshx: using secret-service credential \"Integration/integration\"\n"; got != want {
			t.Fatalf("diagnostic = %q, want %q", got, want)
		}
		if strings.Contains(stderr.String(), "synthetic-integration-password") {
			t.Fatalf("diagnostic exposed the synthetic secret: %q", stderr.String())
		}
		provider.assertCounts(t, 1, 1, 1)
		assertIntegrationConnectionsClosed(t, provider.conn, baselineNames)
	})

	t.Run("provider error never falls back", func(t *testing.T) {
		provider.setFailSecret(true)
		gopass := &recordingStore{entries: gopassCredentialRefs("legacy/integration")}
		err := executeSSH([]string{
			"integration",
			"--credential-backend", "auto",
		}, dependencies{
			goos:               "linux",
			gopassStore:        gopass,
			secretServiceStore: newSecretServiceStore,
			runProgram:         (&recordingRunner{}).run,
			stdout:             &bytes.Buffer{},
		})
		if err == nil || !strings.Contains(err.Error(), "synthetic provider failure") {
			t.Fatalf("error = %v, want the provider failure", err)
		}
		if gopass.searchCalls != 0 || gopass.secretCalls != 0 {
			t.Fatalf("gopass search/secret calls = %d/%d, want none", gopass.searchCalls, gopass.secretCalls)
		}
		provider.assertCounts(t, 1, 2, 2)
		assertIntegrationConnectionsClosed(t, provider.conn, baselineNames)
	})

	t.Run("unavailable service falls back", func(t *testing.T) {
		if err := provider.releaseName(); err != nil {
			t.Fatal(err)
		}
		releasedNames := integrationBusNames(t, provider.conn)
		gopass := &recordingStore{}
		selection, err := selectCredentialStore(
			credentialBackendAuto,
			"linux",
			gopass,
			newSecretServiceStore,
		)
		if err != nil {
			t.Fatal(err)
		}
		if selection.backend != credentialBackendGopass || selection.store != gopass {
			t.Fatalf("selection = %#v, want gopass", selection)
		}
		if err := selection.store.Close(); err != nil {
			t.Fatal(err)
		}
		assertIntegrationConnectionsClosed(t, provider.conn, releasedNames)
	})
	t.Run("key registry and provider lifecycle", testSecretServiceKeyIntegration)
	t.Run("cancel stalled bus authentication", testSecretServiceConnectCancellation)
}

func newIntegrationSecretServiceProvider(secret []byte) (*integrationSecretServiceProvider, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect fake Secret Service provider: %w", err)
	}
	provider := &integrationSecretServiceProvider{
		conn:   conn,
		secret: append([]byte(nil), secret...),
	}
	failed := true
	defer func() {
		if failed {
			clearBytes(provider.secret)
			_ = conn.Close()
		}
	}()

	if _, err := prop.Export(conn, secretServicePath, prop.Map{
		secretServiceInterface: {
			"Collections": {Value: []dbus.ObjectPath{integrationCollectionPath}, Emit: prop.EmitConst},
		},
	}); err != nil {
		return nil, fmt.Errorf("export service properties: %w", err)
	}
	if _, err := prop.Export(conn, integrationCollectionPath, prop.Map{
		secretServiceCollectionInterface: {
			"Label":  {Value: "Integration", Emit: prop.EmitConst},
			"Locked": {Value: false, Emit: prop.EmitTrue},
			"Items":  {Value: []dbus.ObjectPath{integrationItemPath}, Emit: prop.EmitConst},
		},
	}); err != nil {
		return nil, fmt.Errorf("export collection properties: %w", err)
	}
	provider.itemProps, err = prop.Export(conn, integrationItemPath, prop.Map{
		secretServiceItemInterface: {
			"Label": {Value: "integration", Emit: prop.EmitConst},
			"Attributes": {Value: map[string]string{
				"application": "sshx-integration-test",
				"sshx.target": "integration@127.0.0.1",
			}, Emit: prop.EmitConst},
			"Locked": {Value: true, Emit: prop.EmitTrue},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("export item properties: %w", err)
	}

	if err := conn.ExportMethodTable(map[string]any{
		"ReadAlias":   provider.readAlias,
		"Unlock":      provider.unlock,
		"OpenSession": provider.openSession,
	}, secretServicePath, secretServiceInterface); err != nil {
		return nil, fmt.Errorf("export service methods: %w", err)
	}
	if err := conn.ExportMethodTable(map[string]any{
		"GetSecret": provider.getSecret,
	}, integrationItemPath, secretServiceItemInterface); err != nil {
		return nil, fmt.Errorf("export item methods: %w", err)
	}
	if err := conn.ExportMethodTable(map[string]any{
		"Prompt": provider.prompt,
	}, integrationPromptPath, secretServicePromptInterface); err != nil {
		return nil, fmt.Errorf("export prompt methods: %w", err)
	}
	if err := conn.ExportMethodTable(map[string]any{
		"Close": provider.closeSession,
	}, integrationSessionPath, secretServiceSessionInterface); err != nil {
		return nil, fmt.Errorf("export session methods: %w", err)
	}

	reply, err := conn.RequestName(secretServiceBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, fmt.Errorf("request Secret Service bus name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, fmt.Errorf("request Secret Service bus name: %s", reply)
	}
	failed = false
	return provider, nil
}

func (p *integrationSecretServiceProvider) readAlias(alias string) (dbus.ObjectPath, *dbus.Error) {
	if alias == "default" {
		return integrationCollectionPath, nil
	}
	return secretServiceNoPromptPath, nil
}

func (p *integrationSecretServiceProvider) unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	if len(objects) == 1 && objects[0] == integrationItemPath {
		return nil, integrationPromptPath, nil
	}
	return objects, secretServiceNoPromptPath, nil
}

func (p *integrationSecretServiceProvider) openSession(
	algorithm string,
	input dbus.Variant,
) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	if algorithm != "plain" || input.Value() != "" {
		return dbus.Variant{}, secretServiceNoPromptPath, dbus.NewError(
			"org.freedesktop.DBus.Error.InvalidArgs",
			[]any{"expected a plain session"},
		)
	}
	p.mutex.Lock()
	p.opened++
	p.mutex.Unlock()
	// Match gopass-secret-service's current plain-session response. The Secret
	// Service specification calls for an empty string, but this provider uses
	// an empty byte array for all session negotiation output.
	return dbus.MakeVariant([]byte{}), integrationSessionPath, nil
}

func (p *integrationSecretServiceProvider) prompt(_ string) *dbus.Error {
	p.itemProps.SetMust(secretServiceItemInterface, "Locked", false)
	p.mutex.Lock()
	p.prompts++
	p.mutex.Unlock()
	if err := p.conn.Emit(
		integrationPromptPath,
		secretServicePromptInterface+".Completed",
		false,
		dbus.MakeVariant([]dbus.ObjectPath{integrationItemPath}),
	); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func (p *integrationSecretServiceProvider) getSecret(
	session dbus.ObjectPath,
) (secretServiceSecret, *dbus.Error) {
	if session != integrationSessionPath {
		return secretServiceSecret{}, dbus.NewError(
			"org.freedesktop.DBus.Error.InvalidArgs",
			[]any{"unexpected session"},
		)
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.failSecret {
		return secretServiceSecret{}, dbus.NewError(
			"org.freedesktop.Secret.Error.NoSuchObject",
			[]any{"synthetic provider failure"},
		)
	}
	return secretServiceSecret{
		Session:     session,
		Value:       append([]byte(nil), p.secret...),
		ContentType: "text/plain",
	}, nil
}

func (p *integrationSecretServiceProvider) closeSession() *dbus.Error {
	p.mutex.Lock()
	p.closed++
	p.mutex.Unlock()
	return nil
}

func (p *integrationSecretServiceProvider) setFailSecret(value bool) {
	p.mutex.Lock()
	p.failSecret = value
	p.mutex.Unlock()
}

func (p *integrationSecretServiceProvider) assertCounts(t *testing.T, prompts, opened, closed int) {
	t.Helper()
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.prompts != prompts || p.opened != opened || p.closed != closed {
		t.Fatalf(
			"provider prompt/open/close counts = %d/%d/%d, want %d/%d/%d",
			p.prompts, p.opened, p.closed,
			prompts, opened, closed,
		)
	}
}

func (p *integrationSecretServiceProvider) releaseName() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.released {
		return nil
	}
	reply, err := p.conn.ReleaseName(secretServiceBusName)
	if err != nil {
		return fmt.Errorf("release Secret Service bus name: %w", err)
	}
	if reply != dbus.ReleaseNameReplyReleased {
		return fmt.Errorf("release Secret Service bus name: %s", reply)
	}
	p.released = true
	return nil
}

func integrationBusNames(t *testing.T, conn *dbus.Conn) []string {
	t.Helper()
	var names []string
	if err := conn.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names); err != nil {
		t.Fatalf("list D-Bus names: %v", err)
	}
	sort.Strings(names)
	return names
}

func assertIntegrationConnectionsClosed(t *testing.T, conn *dbus.Conn, want []string) {
	t.Helper()
	got := integrationBusNames(t, conn)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("D-Bus names after client cleanup = %#v, want %#v", got, want)
	}
}

func testSecretServiceKeyIntegration(t *testing.T) {
	ctx := context.Background()
	record, raw := testAgentKey(t)
	record.Backend = credentialBackendSecretService
	record.Reference = "stable-key"
	record.Collection = "default"
	registry, err := parseAgentRegistry(registryJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newIntegrationSecretServiceProvider(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.conn.Close()
	defer clearBytes(provider.secret)
	attributes := map[string]string{"service": "sshx", "sshx.type": "ssh-key", "sshx.schema": "1", "sshx.id": "stable-key"}
	provider.itemProps.SetMust(secretServiceItemInterface, "Attributes", attributes)
	store, err := newSecretServiceStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	keys := store.(keyMaterialStore)
	refs, err := store.Search(ctx, credentialQuery{Attributes: attributes})
	if err != nil || len(refs) != 1 || !refs[0].Locked {
		t.Fatal("locked discovery", err)
	}
	if err := registry.withKey(ctx, record.ID, keys, func(ssh.Signer) error { t.Fatal("locked key used"); return nil }); !errors.Is(err, errCredentialLocked) {
		t.Fatal(err)
	}
	provider.assertCounts(t, 0, 0, 0)
	provider.itemProps.SetMust(secretServiceItemInterface, "Locked", false)
	if err := registry.withKey(ctx, record.ID, keys, func(ssh.Signer) error { return nil }); err != nil {
		t.Fatal("key read", err)
	}
	provider.assertCounts(t, 0, 1, 1)

	// A blocked remote call must honor caller cancellation and close its session.
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	if err := provider.conn.ExportMethodTable(map[string]any{"GetSecret": func(session dbus.ObjectPath) (secretServiceSecret, *dbus.Error) {
		defer close(finished)
		close(entered)
		<-release
		return provider.getSecret(session)
	}}, integrationItemPath, secretServiceItemInterface); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- registry.withKey(cancelled, record.ID, keys, func(ssh.Signer) error { return nil }) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read not started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read ignored cancellation")
	}
	close(release)
	<-finished
	provider.assertCounts(t, 0, 2, 2)

	// Losing the well-known name while retaining the old connection cannot route
	// this read or session cleanup to a replacement exposing the same object paths.
	entered = make(chan struct{})
	release = make(chan struct{})
	if err := provider.conn.ExportMethodTable(map[string]any{"GetSecret": func(session dbus.ObjectPath) (secretServiceSecret, *dbus.Error) {
		close(entered)
		<-release
		return provider.getSecret(session)
	}}, integrationItemPath, secretServiceItemInterface); err != nil {
		t.Fatal(err)
	}
	go func() {
		done <- registry.withKey(ctx, record.ID, keys, func(ssh.Signer) error { t.Error("key released after owner loss"); return nil })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read not started")
	}
	if err := provider.releaseName(); err != nil {
		t.Fatal(err)
	}
	_, replacementRaw := testAgentKey(t)
	replacement, err := newIntegrationSecretServiceProvider(replacementRaw)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.conn.Close()
	defer clearBytes(replacement.secret)
	replacement.itemProps.SetMust(secretServiceItemInterface, "Attributes", attributes)
	replacement.itemProps.SetMust(secretServiceItemInterface, "Locked", false)
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, errCredentialProviderChanged) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owner loss blocked")
	}
	replacement.assertCounts(t, 0, 0, 0)
	if err := registry.withKey(ctx, record.ID, keys, func(ssh.Signer) error { t.Error("substituted key used"); return nil }); !errors.Is(err, errKeyMismatch) {
		t.Fatal("re-resolved replacement must match full public key", err)
	}
	replacement.assertCounts(t, 0, 1, 1)

	// Password prompts remain opt-in, cancellable, and separate from key reads.
	replacement.itemProps.SetMust(secretServiceItemInterface, "Locked", true)
	if err := replacement.conn.ExportMethodTable(map[string]any{"Prompt": func(string) *dbus.Error { return nil }}, integrationPromptPath, secretServicePromptInterface); err != nil {
		t.Fatal(err)
	}
	deadline, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	_, err = store.Secret(deadline, credentialRef{Backend: credentialBackendSecretService, ID: string(integrationItemPath)}, credentialReadOptions{AllowInteraction: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("prompt ignored deadline", err)
	}
	if err := replacement.releaseName(); err != nil {
		t.Fatal(err)
	}
	if err := registry.withKey(ctx, record.ID, keys, func(ssh.Signer) error { return nil }); !errors.Is(err, errCredentialProviderChanged) {
		t.Fatal("provider loss", err)
	}
}

func testSecretServiceConnectCancellation(t *testing.T) {
	dir, err := os.MkdirTemp("", "sshx-bus-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	name := filepath.Join(dir, "bus")
	listener, err := net.Listen("unix", name)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+name)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := newSecretServiceStore(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stalled auth was not cancelled", err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled connection was not closed")
	}
}
