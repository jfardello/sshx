package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/fileupdate"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func writerLiveServer(t *testing.T, name, state string, opener agentStoreOpener) (*agentServer, sshagent.ExtendedAgent) {
	t.Helper()
	registry, err := readAgentRegistry(name)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(agentTestDirectory(t), "agent.sock")
	server, err := newAgentServer(socket, registry, opener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	if err := server.ConfigureMutations(state, true); err != nil {
		t.Fatal(err)
	}
	go server.Serve(context.Background())
	return server, sshagent.NewClient(agentTestDial(t, socket))
}

func TestAgentRegistryWriterReloadDurableState(t *testing.T) {
	for _, all := range []bool{false, true} {
		label := "individual"
		if all {
			label = "all"
		}
		t.Run(label, func(t *testing.T) {
			record, raw := testAgentKey(t)
			name := filepath.Join(agentTestDirectory(t), "agent.json")
			pub, err := UpsertRegistryRecord(context.Background(), name, record, false)
			writerResult(t, pub, err, fileupdate.Published, nil)
			backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
			state := filepath.Join(agentTestDirectory(t), "state")
			server, client := writerLiveServer(t, name, state, backend.open)
			enrolled := server.keys.registry.keys[0].publicKey
			if all {
				err = client.RemoveAll()
			} else {
				err = client.Remove(enrolled)
			}
			if err != nil {
				t.Fatal(err)
			}
			private := mutationPrivate(t)
			imported, err := ssh.NewPublicKey(private.Public())
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Sign(imported, []byte("before reload")); err != nil {
				t.Fatal(err)
			}
			if err := client.Lock([]byte("writer-reload-password")); err != nil {
				t.Fatal(err)
			}
			durable := writerRead(t, state)
			generation, locked := server.keys.signingState()
			if !locked {
				t.Fatal("lock not active")
			}
			record.Comment = "writer changed canonical record"
			pub, err = UpsertRegistryRecord(context.Background(), name, record, true)
			writerResult(t, pub, err, fileupdate.Published, nil)
			if list, err := client.List(); err != nil || len(list) != 0 {
				t.Fatalf("reload exposed locked identities: %d, %v", len(list), err)
			}
			next, locked := server.keys.signingState()
			if next != generation+1 || !locked {
				t.Fatalf("reload generation/lock = %d/%t, previous %d", next, locked, generation)
			}
			server.keys.stateMutex.RLock()
			overlays := len(server.keys.mutations.overlay)
			server.keys.stateMutex.RUnlock()
			if overlays != 0 {
				t.Fatal("reload retained volatile import")
			}
			if !bytes.Equal(durable, writerRead(t, state)) {
				t.Fatal("registry update rewrote durable suppression/lock")
			}
			server.Close()
			_, restarted := writerLiveServer(t, name, state, backend.open)
			if list, err := restarted.List(); err != nil || len(list) != 0 {
				t.Fatalf("restart bypassed lock: %d, %v", len(list), err)
			}
			if _, err := restarted.Sign(enrolled, []byte("locked after restart")); err == nil {
				t.Fatal("restart bypassed durable lock")
			}
			if err := restarted.Unlock([]byte("writer-reload-password")); err != nil {
				t.Fatalf("reload changed lock verifier: %v", err)
			}
			if list, err := restarted.List(); err != nil || len(list) != 0 {
				t.Fatalf("unlock restored suppressed/imported identities: %d, %v", len(list), err)
			}
			if _, err := restarted.Sign(enrolled, []byte("suppressed after unlock")); err == nil {
				t.Fatal("restart lost durable suppression")
			}
		})
	}
}

func TestAgentRegistryWriterReloadSuppressionAndImports(t *testing.T) {
	record, raw := testAgentKey(t)
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	writerPut(t, name, writerJSON(t, 1, record))
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	state := filepath.Join(agentTestDirectory(t), "state")
	server, client := writerLiveServer(t, name, state, backend.open)
	enrolled := server.keys.registry.keys[0].publicKey
	if err := client.Remove(enrolled); err != nil {
		t.Fatal(err)
	}
	private := mutationPrivate(t)
	imported, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	durable := writerRead(t, state)
	generation, _ := server.keys.signingState()
	pub, err := UpsertRegistryRecord(context.Background(), name, record, true)
	writerResult(t, pub, err, fileupdate.Unchanged, nil)
	if _, err := client.Sign(imported, []byte("no-op retains import")); err != nil {
		t.Fatal(err)
	}
	if next, _ := server.keys.signingState(); next != generation {
		t.Fatal("no-op invalidated generation")
	}
	record.Comment = "actual change"
	pub, err = UpsertRegistryRecord(context.Background(), name, record, true)
	writerResult(t, pub, err, fileupdate.Published, nil)
	if list, err := client.List(); err != nil || len(list) != 0 {
		t.Fatalf("reload restored suppressed or imported key: %d, %v", len(list), err)
	}
	if _, err := client.Sign(imported, []byte("retired")); err == nil {
		t.Fatal("retired volatile key signed")
	}
	if _, err := client.Sign(enrolled, []byte("suppressed")); err == nil {
		t.Fatal("reload restored suppressed key")
	}
	if next, _ := server.keys.signingState(); next != generation+1 {
		t.Fatal("mutation did not invalidate exactly one generation")
	}
	if !bytes.Equal(durable, writerRead(t, state)) {
		t.Fatal("reload altered suppression document")
	}
	server.Close()
	_, restarted := writerLiveServer(t, name, state, backend.open)
	if list, err := restarted.List(); err != nil || len(list) != 0 {
		t.Fatalf("restart restored suppressed/volatile key: %d, %v", len(list), err)
	}
}

func TestAgentRegistryWriterReloadCacheAndEquivalentAliases(t *testing.T) {
	record, raw := testAgentKey(t)
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	writerPut(t, name, writerJSON(t, 1, record))
	provider := &cacheTestProvider{agentTestBackend: &agentTestBackend{data: map[string][]byte{record.Reference: raw}}}
	server, client := writerLiveServer(t, name, filepath.Join(agentTestDirectory(t), "state"), provider.open)
	if err := server.SetCacheTTL(time.Minute); err != nil {
		t.Fatal(err)
	}
	enrolled := server.keys.registry.keys[0].publicKey
	data := []byte("writer reload cache challenge")
	sign := func() {
		t.Helper()
		sig, err := client.Sign(enrolled, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := enrolled.Verify(data, sig); err != nil {
			t.Fatal(err)
		}
	}
	sign()
	provider.mutex.Lock()
	lease := provider.leases[0]
	provider.mutex.Unlock()
	generation, _ := server.keys.signingState()
	private := mutationPrivate(t)
	imported, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Add(sshagent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	// Import advances the generation itself, so establish the baseline afterwards.
	sign()
	generation, _ = server.keys.signingState()
	provider.mutex.Lock()
	lease = provider.leases[len(provider.leases)-1]
	provider.mutex.Unlock()
	reads := provider.reads.Load()
	assertEquivalent := func() {
		t.Helper()
		sign()
		if next, _ := server.keys.signingState(); next != generation {
			t.Fatalf("equivalent source invalidated generation: %d -> %d", generation, next)
		}
		if lease.closed.Load() || provider.reads.Load() != reads {
			t.Fatal("equivalent source invalidated cache lease")
		}
		if _, err := client.Sign(imported, data); err != nil {
			t.Fatalf("equivalent source retired import: %v", err)
		}
	}
	pub, err := UpsertRegistryRecord(context.Background(), name, record, true)
	writerResult(t, pub, err, fileupdate.Unchanged, nil)
	assertEquivalent()
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, writerRead(t, name), "", "    "); err != nil {
		t.Fatal(err)
	}
	writerPut(t, name, append(formatted.Bytes(), '\n'))
	assertEquivalent()
	alias := record
	alias.ID = "equivalent-alias"
	alias.Comment = "noncanonical alias label"
	pub, err = UpsertRegistryRecord(context.Background(), name, alias, false)
	writerResult(t, pub, err, fileupdate.Published, nil)
	assertEquivalent() // Includes v1 -> v2: neither changes the runtime fingerprint.
	alias.Comment = "only alias changed"
	pub, err = UpsertRegistryRecord(context.Background(), name, alias, true)
	writerResult(t, pub, err, fileupdate.Published, nil)
	assertEquivalent()
	record.Comment = "canonical comment changed"
	pub, err = UpsertRegistryRecord(context.Background(), name, record, true)
	writerResult(t, pub, err, fileupdate.Published, nil)
	list, err := client.List()
	if err != nil || len(list) != 1 || list[0].Comment != record.Comment {
		t.Fatalf("live canonical reload: %+v, %v", list, err)
	}
	if next, _ := server.keys.signingState(); next != generation+1 {
		t.Fatal("canonical change did not invalidate generation")
	}
	waitAgentCondition(t, func() bool { return lease.closed.Load() })
	if _, err := client.Sign(imported, data); err == nil {
		t.Fatal("canonical change retained import")
	}
	sign()
	if provider.reads.Load() != reads+1 {
		t.Fatal("canonical reload reused stale signer")
	}
}

func TestAgentRegistryWriterReloadEnablement(t *testing.T) {
	record, raw := testAgentKey(t)
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	writerPut(t, name, writerJSON(t, 1, record))
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	server, client := writerLiveServer(t, name, filepath.Join(agentTestDirectory(t), "state"), backend.open)
	enrolled := server.keys.registry.keys[0].publicKey
	for _, enabled := range []bool{false, true} {
		record.Enabled = enabled
		pub, err := UpsertRegistryRecord(context.Background(), name, record, true)
		writerResult(t, pub, err, fileupdate.Published, nil)
		list, err := client.List()
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if enabled {
			want = 1
		}
		if len(list) != want {
			t.Fatalf("enabled=%t, identities=%d", enabled, len(list))
		}
		_, err = client.Sign(enrolled, []byte("enablement"))
		if (err == nil) != enabled {
			t.Fatalf("enabled=%t, signing error=%v", enabled, err)
		}
	}
	// Rejected proposals leave the live snapshot and file untouched.
	before, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	original := writerRead(t, name)
	generation, _ := server.keys.signingState()
	conflict := record
	conflict.ID = "conflict"
	conflict.Reference = "other/key"
	pub, err := UpsertRegistryRecord(context.Background(), name, conflict, false)
	writerResult(t, pub, err, fileupdate.Unchanged, ErrRegistryInvalid)
	writerUnchanged(t, name, before, original)
	if _, err := client.Sign(enrolled, []byte("after rejection")); err != nil {
		t.Fatal(err)
	}
	if next, _ := server.keys.signingState(); next != generation {
		t.Fatal("rejected update invalidated runtime")
	}
}
