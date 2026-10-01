package secretservice

import (
	"context"
	"encoding/json"
	nativeagent "github.com/jfardello/sshx/internal/agent"
	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestSecretServiceCacheSignals(t *testing.T) {
	for _, name := range []string{"provider", "replacement", "disconnect"} {
		t.Run(name, func(t *testing.T) {
			signals := &keyCacheSignals{owner: ":1.42", done: make(chan struct{})}
			signals.DeliverSignal("unrelated", "event", &dbus.Signal{Sender: ":1.100"})
			select {
			case <-signals.done:
				t.Fatal("unrelated signal revoked lease")
			default:
			}
			switch name {
			case "provider":
				signals.DeliverSignal("org.freedesktop.DBus.Properties", "PropertiesChanged", &dbus.Signal{Sender: ":1.42"})
			case "replacement":
				signals.DeliverSignal("org.freedesktop.DBus", "NameOwnerChanged", &dbus.Signal{Sender: "org.freedesktop.DBus", Body: []any{secretServiceBusName, ":1.42", ":1.43"}})
			case "disconnect":
				signals.Terminate()
			}
			select {
			case <-signals.done:
			default:
				t.Fatal("lease not revoked")
			}
			signals.Terminate()
		})
	}
}

func TestSecretServiceCacheIntegration(t *testing.T) {
	if os.Getenv(secretServiceIntegrationEnvironment) != "1" {
		t.Skip("requires isolated dbus-run-session")
	}
	for _, mode := range []string{"lock", "change", "delete", "replacement", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			provider, err := newIntegrationSecretServiceProvider([]byte("cache-fixture"))
			if err != nil {
				t.Fatal(err)
			}
			defer provider.conn.Close()
			provider.itemProps.SetMust(secretServiceItemInterface, "Attributes", map[string]string{"service": "sshx", "sshx.type": "ssh-key", "sshx.schema": "1", "sshx.id": "cache-key"})
			provider.itemProps.SetMust(secretServiceItemInterface, "Locked", false)
			store, err := New(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			lease, err := store.(*secretServiceStore).WatchKey(context.Background(), credentialRef{Backend: credentialBackendSecretService, Collection: "default", ID: "cache-key"})
			if err != nil {
				t.Fatal("watch", err)
			}
			defer lease.Close()
			for i := 0; i < 3; i++ {
				if err := lease.Check(context.Background()); err != nil {
					t.Fatal("readiness", err)
				}
			}
			provider.assertCounts(t, 0, 0, 0) // Checks must neither fetch secrets nor unlock.
			switch mode {
			case "lock":
				provider.itemProps.SetMust(secretServiceItemInterface, "Locked", true)
			case "change":
				provider.itemProps.SetMust(secretServiceItemInterface, "Modified", uint64(2))
			case "delete":
				if err := provider.conn.Emit(integrationCollectionPath, secretServiceCollectionInterface+".ItemDeleted", integrationItemPath); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err := provider.releaseName(); err != nil {
					t.Fatal(err)
				}
			case "disconnect":
				provider.conn.Close()
			}
			select {
			case <-lease.Invalidated():
			case <-time.After(time.Second):
				t.Fatal("notification did not revoke lease")
			}
			if err := lease.Check(context.Background()); err == nil {
				t.Fatal("revoked lease reusable")
			}
		})
	}
}

func TestSecretServiceAgentCacheIntegration(t *testing.T) {
	if os.Getenv(secretServiceIntegrationEnvironment) != "1" {
		t.Skip("requires isolated dbus-run-session")
	}
	raw := testPrivateKeyBytes(t)
	defer clearBytes(raw)
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newIntegrationSecretServiceProvider(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.conn.Close()
	provider.itemProps.SetMust(secretServiceItemInterface, "Attributes", map[string]string{"service": "sshx", "sshx.type": "ssh-key", "sshx.schema": "1", "sshx.id": "cache-key"})
	provider.itemProps.SetMust(secretServiceItemInterface, "Locked", false)
	baseline := integrationBusNames(t, provider.conn)
	directory, err := os.MkdirTemp("", "sshx-cache-integration-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	data, _ := json.Marshal(map[string]any{"version": 2, "keys": []any{map[string]any{"id": "fixture", "public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), "enabled": true, "policy": "unrestricted-local", "backend": "secret-service", "reference": "cache-key", "collection": "default"}}})
	path := filepath.Join(directory, "agent.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := nativeagent.ReadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "agent.sock")
	server, err := nativeagent.NewServer(socket, registry, func(ctx context.Context, _ credential.Backend) (credential.KeyStore, error) { return New(ctx) })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetCacheTTL(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	go server.Serve(context.Background())
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := sshagent.NewClient(conn)
	for i := 0; i < 2; i++ {
		sig, err := client.Sign(signer.PublicKey(), []byte("fixture-data"))
		if err != nil || signer.PublicKey().Verify([]byte("fixture-data"), sig) != nil {
			t.Fatal("cached signature", err)
		}
	}
	provider.assertCounts(t, 0, 1, 1)
	if server.CacheStats().Hits != 1 {
		t.Fatal("no cache hit")
	}
	provider.itemProps.SetMust(secretServiceItemInterface, "Modified", uint64(2))
	deadline := time.Now().Add(time.Second)
	for server.CacheStats().Evictions == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.CacheStats().Evictions == 0 {
		t.Fatal("credential change not observed")
	}
	if _, err := client.Sign(signer.PublicKey(), []byte("fixture-data")); err != nil {
		t.Fatal(err)
	}
	provider.assertCounts(t, 0, 2, 2)
	provider.itemProps.SetMust(secretServiceItemInterface, "Locked", true)
	if _, err := client.Sign(signer.PublicKey(), []byte("fixture-data")); err == nil {
		t.Fatal("locked provider signed")
	}
	provider.assertCounts(t, 0, 2, 2)
	conn.Close()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	assertIntegrationConnectionsClosed(t, provider.conn, baseline)
}

func TestSecretServiceCacheReadinessWithoutNotifications(t *testing.T) {
	for _, mode := range []string{"modified", "malformed-modified", "item-locked", "collection-locked", "deleted", "owner", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			store, f, ref, _ := keySecretServiceFixture(t)
			collection, item := dbus.ObjectPath("/collection"), dbus.ObjectPath("/collection/key")
			f.setProperty(item, secretServiceItemInterface+".Modified", uint64(1))
			lease := &secretKeyCacheLease{store: store, signals: &keyCacheSignals{owner: ":1.42", done: make(chan struct{})}, owner: ":1.42", ref: ref, collection: collection, item: item, modified: 1}
			if err := lease.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			replace := func(path dbus.ObjectPath, property string, value any) {
				f.properties[secretServicePropertyKey{path, property}] = []propertyResult{{value: dbus.MakeVariant(value)}}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "modified":
				replace(item, secretServiceItemInterface+".Modified", uint64(2))
			case "malformed-modified":
				replace(item, secretServiceItemInterface+".Modified", "invalid")
			case "item-locked":
				replace(item, secretServiceItemInterface+".Locked", true)
			case "collection-locked":
				replace(collection, secretServiceCollectionInterface+".Locked", true)
			case "deleted":
				replace(collection, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{})
			case "owner":
				lease.owner = ":1.43"
			case "canceled":
				cancel()
			}
			if err := lease.Check(ctx); err == nil {
				t.Fatal("readiness change was ignored")
			}
			select {
			case <-lease.Invalidated():
			default:
				t.Fatal("readiness failure did not revoke")
			}
			if err := lease.Check(context.Background()); err == nil {
				t.Fatal("revoked lease recovered")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
