package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func testAgentKey(t *testing.T) (agentKeyRecord, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return agentKeyRecord{ID: "test-key", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), Enabled: true, Policy: "unrestricted-local", Backend: credentialBackendGopass, Reference: "keys/test-key"}, pem.EncodeToMemory(block)
}
func registryJSON(t *testing.T, records ...agentKeyRecord) []byte {
	t.Helper()
	if records == nil {
		records = []agentKeyRecord{}
	}
	data, err := json.Marshal(agentRegistryDocument{Version: 1, Keys: records})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type fakeKeyMaterialStore struct {
	data  []byte
	err   error
	calls int
	ref   credentialRef
}

func (s *fakeKeyMaterialStore) KeyMaterial(ctx context.Context, ref credentialRef) ([]byte, error) {
	s.calls++
	s.ref = ref
	return s.data, s.err
}

func TestAgentRegistryDiscoveryAndExactRead(t *testing.T) {
	rec, raw := testAgentKey(t)
	reg, err := parseAgentRegistry(registryJSON(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	identities, err := reg.List(context.Background())
	if err != nil || len(identities) != 1 {
		t.Fatalf("List: %v, %d", err, len(identities))
	}
	store := &fakeKeyMaterialStore{data: raw}
	if store.calls != 0 {
		t.Fatal("discovery fetched private material")
	}
	called := false
	err = reg.withKey(context.Background(), rec.ID, store, func(s ssh.Signer) error {
		called = true
		sig, err := s.Sign(rand.Reader, []byte("challenge"))
		if err != nil {
			return err
		}
		return identities[0].PublicKey.Verify([]byte("challenge"), sig)
	})
	if err != nil || !called || store.calls != 1 || store.ref.ID != rec.Reference || store.ref.Backend != rec.Backend {
		t.Fatalf("exact read: %v, %+v", err, store.ref)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("owned material not cleared")
	}
	// The public key returned by discovery is not the trusted registry's object.
	exposed := identities[0].PublicKey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	exposed[0] ^= 1
	again, _ := reg.List(context.Background())
	if bytes.Equal(again[0].PublicKey.Marshal(), identities[0].PublicKey.Marshal()) {
		t.Fatal("registry was mutated by caller")
	}
}
func TestAgentRegistryRejectsUnsafeRecords(t *testing.T) {
	rec, _ := testAgentKey(t)
	for name, change := range map[string]func(*agentKeyRecord){
		"empty id": func(r *agentKeyRecord) { r.ID = "" }, "bad id": func(r *agentKeyRecord) { r.ID = "a/b" },
		"unknown backend": func(r *agentKeyRecord) { r.Backend = "auto" }, "traversal": func(r *agentKeyRecord) { r.Reference = "../key" },
		"option": func(r *agentKeyRecord) { r.Reference = "--help" }, "absolute": func(r *agentKeyRecord) { r.Reference = "/key" },
		"unclean": func(r *agentKeyRecord) { r.Reference = "a//key" }, "dot": func(r *agentKeyRecord) { r.Reference = "." },
		"newline": func(r *agentKeyRecord) { r.Reference = "a\nb" }, "backslash": func(r *agentKeyRecord) { r.Reference = "a\\b" },
		"collection": func(r *agentKeyRecord) { r.Collection = "default" }, "secret-service path": func(r *agentKeyRecord) {
			r.Backend = credentialBackendSecretService
			r.Reference = "/item"
			r.Collection = "default"
		},
		"missing collection": func(r *agentKeyRecord) { r.Backend = credentialBackendSecretService; r.Reference = "stable-id" },
		"constrained":        func(r *agentKeyRecord) { r.Policy = "destination-constrained" }, "missing policy": func(r *agentKeyRecord) { r.Policy = "" },
		"control comment": func(r *agentKeyRecord) { r.Comment = "bad\x1b[1m" }, "long comment": func(r *agentKeyRecord) { r.Comment = strings.Repeat("x", 129) },
		"invalid public key": func(r *agentKeyRecord) { r.PublicKey = "invalid" }, "public comment": func(r *agentKeyRecord) { r.PublicKey += " comment" },
		"multiple keys": func(r *agentKeyRecord) { r.PublicKey += "\n" + r.PublicKey }, "authorized options": func(r *agentKeyRecord) { r.PublicKey = "restrict " + r.PublicKey },
		"noncanonical": func(r *agentKeyRecord) { r.PublicKey += "\n" },
	} {
		t.Run(name, func(t *testing.T) {
			r := rec
			change(&r)
			if _, err := parseAgentRegistry(registryJSON(t, r)); !errors.Is(err, errAgentRegistry) {
				t.Fatalf("accepted record: %v", err)
			}
		})
	}
	for _, data := range []string{"", "null", "[]", "{}", `{"version":3,"keys":[]}`, `{"version":1,"version":1,"keys":[]}`, `{"version":1,"keys":null}`, `{"version":1,"keys":[],"passphrase":"private"}`, `{"version":1,"keys":[]} {}`, `{"version":1,`, strings.Repeat(" ", maxAgentRegistryBytes+1)} {
		if _, err := parseAgentRegistry([]byte(data)); err == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
func TestAgentRegistryDuplicateAndDisabledPolicies(t *testing.T) {
	rec, _ := testAgentKey(t)
	alias := rec
	alias.ID = "alias"
	reg, err := parseAgentRegistry(registryJSON(t, rec, alias))
	if err != nil || len(reg.keys) != 1 {
		t.Fatalf("equivalent alias: %v", err)
	}
	for _, change := range []func(*agentKeyRecord){func(r *agentKeyRecord) { r.ID = rec.ID }, func(r *agentKeyRecord) { r.Reference = "different" }, func(r *agentKeyRecord) { r.Enabled = false }, func(r *agentKeyRecord) {
		r.Backend = credentialBackendSecretService
		r.Collection = "default"
		r.Reference = "stable"
	}} {
		other := alias
		change(&other)
		if _, err := parseAgentRegistry(registryJSON(t, rec, other)); err == nil {
			t.Fatal("accepted conflicting duplicate")
		}
	}
	rec.Enabled = false
	reg, err = parseAgentRegistry(registryJSON(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	list, err := reg.List(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatal("disabled identity visible")
	}
	if err := reg.withKey(context.Background(), rec.ID, nil, nil); !errors.Is(err, errCredentialReference) {
		t.Fatal(err)
	}
	rec.Backend = credentialBackendSecretService
	rec.Collection = "default"
	rec.Reference = "stable-id"
	if _, err := parseAgentRegistry(registryJSON(t, rec)); err != nil {
		t.Fatal(err)
	}
}
func TestAgentRegistryReadErrorsAreSanitized(t *testing.T) {
	rec, raw := testAgentKey(t)
	reg, _ := parseAgentRegistry(registryJSON(t, rec))
	for _, providerErr := range []error{errors.New("private fixture leaked by provider"), errCredentialLocked, errCredentialProviderChanged, context.Canceled, context.DeadlineExceeded, errCredentialReference, errCredentialTooLarge} {
		data := append([]byte(nil), raw...)
		store := &fakeKeyMaterialStore{data: data, err: providerErr}
		err := reg.withKey(context.Background(), rec.ID, store, func(ssh.Signer) error { t.Fatal("callback after failure"); return nil })
		if err == nil || strings.Contains(err.Error(), "fixture") || !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("unsafe failure")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reg.List(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := reg.withKey(ctx, rec.ID, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := reg.withKey(context.Background(), rec.ID, nil, nil); !errors.Is(err, errCredentialRead) {
		t.Fatal(err)
	}
	_, other := testAgentKey(t)
	if err := reg.withKey(context.Background(), rec.ID, &fakeKeyMaterialStore{data: other}, func(ssh.Signer) error { t.Fatal("wrong key used"); return nil }); !errors.Is(err, errKeyMismatch) {
		t.Fatal(err)
	}
}
func TestRegisteredPrivateKeyFormats(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := []any{ed, rsaKey}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		openssh, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		blocks := []*pem.Block{openssh, {Type: "PRIVATE KEY", Bytes: der}}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			blocks = append(blocks, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				t.Fatal(err)
			}
			blocks = append(blocks, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}
		for _, block := range blocks {
			data := pem.EncodeToMemory(block)
			if _, err := parseRegisteredPrivateKey(data, signer.PublicKey()); err != nil {
				t.Fatalf("%T %s: %v", key, block.Type, err)
			}
		}
	}
	rec, raw := testAgentKey(t)
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(rec.PublicKey))
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(ed, "", []byte("disposable"))
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("not PEM"), append(append([]byte(nil), raw...), raw...), append(append([]byte(nil), raw...), []byte("metadata")...), pem.EncodeToMemory(encrypted), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("invalid")}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("invalid")}), []byte("-----BEGIN PRIVATE KEY-----\ninvalid"), bytes.Repeat([]byte("x"), maxKeyMaterialBytes+1)} {
		if _, err := parseRegisteredPrivateKey(data, pub); err == nil {
			t.Fatal("accepted unsupported key")
		}
	}
	if _, err := parseRegisteredPrivateKey(raw, nil); !errors.Is(err, errKeyMismatch) {
		t.Fatal(err)
	}
}
func TestAgentRegistryFilesystem(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "agent.json")
	rec, _ := testAgentKey(t)
	data := registryJSON(t, rec)
	if reg, err := readAgentRegistry(name); err != nil || len(reg.keys) != 0 {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(name); err == nil {
		t.Fatal("accepted exposed registry")
	}
	os.Chmod(name, 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(link); err == nil {
		t.Fatal("accepted symlink")
	}
	parentLink := filepath.Join(dir, "parent")
	os.Symlink(dir, parentLink)
	if _, err := readAgentRegistry(filepath.Join(parentLink, "agent.json")); err == nil {
		t.Fatal("accepted parent symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(fifo); err == nil {
		t.Fatal("accepted FIFO")
	}
	for _, path := range []string{"relative", dir, dir + "/../agent.json"} {
		if _, err := readAgentRegistry(path); err == nil {
			t.Fatal("accepted unsafe path")
		}
	}
	os.Chmod(dir, 0777)
	if _, err := readAgentRegistry(name); err == nil {
		t.Fatal("accepted writable parent")
	}
	os.Chmod(dir, 0700)
	os.WriteFile(name, bytes.Repeat([]byte("x"), maxAgentRegistryBytes+1), 0600)
	if _, err := readAgentRegistry(name); err == nil {
		t.Fatal("accepted oversized registry")
	}
}
func TestAgentRegistryDefaultLocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	path, err := agentRegistryPath()
	if err != nil || path != filepath.Join(home, ".config", "sshx", "agent.json") {
		t.Fatal(path, err)
	}
	reg, err := loadAgentRegistry()
	if err != nil || len(reg.keys) != 0 {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	same, _ := agentRegistryPath()
	if same != path {
		t.Fatal(same)
	}
	t.Setenv("XDG_CONFIG_HOME", home)
	path, _ = agentRegistryPath()
	if path != filepath.Join(home, "sshx", "agent.json") {
		t.Fatal(path)
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := loadAgentRegistry(); err == nil {
		t.Fatal("accepted missing home")
	}
}

func TestRegistryRejectsCaseAlteredSecurityFields(t *testing.T) {
	record, _ := testAgentKey(t)
	data := bytes.Replace(registryJSON(t, record), []byte(`"enabled"`), []byte(`"Enabled"`), 1)
	if _, err := parseAgentRegistry(data); err == nil {
		t.Fatal("accepted case-altered security field")
	}
}
func TestPrivateKeyValidationRejectsInconsistentEd25519(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	private[0] ^= 1 // retain the embedded public key but change the private seed
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRegisteredPrivateKey(pem.EncodeToMemory(block), public); err == nil {
		t.Fatal("accepted inconsistent Ed25519 key")
	}
}
