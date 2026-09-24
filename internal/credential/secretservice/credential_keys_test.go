package secretservice

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

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
	data := testPrivateKeyBytes(t)
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
	if _, err := s.Secret(ctx, credentialRef{}, credentialReadOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.KeyMaterial(ctx, credentialRef{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
