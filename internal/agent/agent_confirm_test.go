package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func confirmationAgent(t *testing.T, encrypted bool) (*agentConnection, *agentTestBackend, ssh.PublicKey, []byte) {
	t.Helper()
	host := bindingSigner(t)
	record, raw := policyRecord(t, host.PublicKey())
	if encrypted {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		record.PublicKey = policyPin(pub)
		block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "fixture", []byte("fixture-passphrase"))
		if err != nil {
			t.Fatal(err)
		}
		raw = pem.EncodeToMemory(block)
	}
	record.Confirm = true
	a, b := policyConnection(t, record, raw, host)
	pub := policyPublic(t, record)
	return a, b, pub, authData(pub, nil, pub.Type())
}

func TestAgentConfirmationFreshAndPrivate(t *testing.T) {
	a, b, pub, data := confirmationAgent(t, false)
	if _, err := a.Sign(pub, data); err == nil || b.reads.Load() != 0 {
		t.Fatal("missing helper did not deny before read")
	}
	var seen []agentPromptRequest
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		seen = append(seen, r)
		return nil, nil
	}}
	for i := 0; i < 2; i++ {
		sig, err := a.Sign(pub, data)
		if err != nil || pub.Verify(data, sig) != nil {
			t.Fatal("approved sign failed", err)
		}
	}
	if len(seen) != 2 || seen[0].RequestID == seen[1].RequestID || seen[0].Operation != "confirm" {
		t.Fatal("approval reused")
	}
	if seen[0].Destination.Status != "verified-session-and-policy" || seen[0].Destination.Username != "alice" {
		t.Fatal("missing verified context")
	}
	if len(seen[0].RequestID) != 64 || len(seen[0].DataDigest) != 64 {
		t.Fatal("missing request binding")
	}
	a.keys.prompt = &agentPrompter{ask: func(context.Context, agentPromptRequest) ([]byte, error) { return nil, errAgentPromptDenied }}
	reads := b.reads.Load()
	if _, err := a.Sign(pub, data); err == nil || reads != b.reads.Load() {
		t.Fatal("denial read backend")
	}
	b.assertCleared(t)
}

func TestAgentPromptResponseIsolation(t *testing.T) {
	a, _, pub, data := confirmationAgent(t, false)
	key, _ := a.keys.lookup(pub.Marshal())
	first, _ := newAgentPromptRequest(context.Background(), key, data, pub.Type(), 0, &a.bindings)
	second, _ := newAgentPromptRequest(context.Background(), key, data, pub.Type(), 0, &a.bindings)
	first.Operation = "confirm"
	second.Operation = "confirm"
	response, _ := json.Marshal(agentPromptResponse{Version: 1, RequestID: first.RequestID, Approved: true})
	if _, err := decodeAgentPrompt(response, first); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAgentPrompt(response, second); err == nil {
		t.Fatal("cross-request approval accepted")
	}
	for _, bad := range [][]byte{
		[]byte(`{"version":1,"version":1}`), []byte(`{"Version":1}`), []byte(`{"approved":null}`),
		append(append([]byte(nil), response...), []byte(` {}`)...), []byte(`[]`), bytes.Repeat([]byte("x"), maxAgentPromptBytes+1),
	} {
		if pass, err := decodeAgentPrompt(bad, first); err == nil {
			clearBytes(pass)
			t.Fatal("malformed response accepted")
		}
	}
	first.Operation = "passphrase"
	if _, err := decodeAgentPrompt(response, first); err == nil {
		t.Fatal("approval supplied passphrase")
	}
}

func TestAgentConfirmationInvalidation(t *testing.T) {
	for _, transition := range []string{"lock", "policy", "cancel", "helper"} {
		t.Run(transition, func(t *testing.T) {
			a, b, pub, data := confirmationAgent(t, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.ctx = ctx
			entered := make(chan struct{})
			exited := make(chan struct{})
			a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
				close(entered)
				<-ctx.Done()
				close(exited)
				return nil, nil
			}}
			result := make(chan error, 1)
			go func() { _, err := a.Sign(pub, data); result <- err }()
			<-entered
			switch transition {
			case "lock":
				a.keys.setLocked(true)
				a.keys.setLocked(false)
			case "policy":
				a.keys.invalidateRegistry()
			case "cancel":
				cancel()
			case "helper":
				if err := (&agentServer{keys: a.keys}).SetPromptHelper(""); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("prompt not canceled")
			}
			if err := <-result; err == nil || b.reads.Load() != 0 {
				t.Fatal("late approval used")
			}
		})
	}
}

func TestAgentEncryptedKeyPrompts(t *testing.T) {
	a, b, pub, data := confirmationAgent(t, true)
	var operations []string
	var owned []byte
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		operations = append(operations, r.Operation)
		if r.Operation == "passphrase" {
			owned = []byte("fixture-passphrase")
			return owned, nil
		}
		return nil, nil
	}}
	sig, err := a.Sign(pub, data)
	if err != nil || pub.Verify(data, sig) != nil {
		t.Fatal("encrypted sign failed", err)
	}
	if strings.Join(operations, ",") != "confirm,passphrase" || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("prompt separation or passphrase clearing failed")
	}
	for _, mode := range []string{"wrong", "empty", "unavailable", "locked-provider"} {
		t.Run(mode, func(t *testing.T) {
			operations = nil
			b.read = nil
			if mode == "locked-provider" {
				b.read = func(context.Context) error { return errCredentialLocked }
			}
			a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
				operations = append(operations, r.Operation)
				if r.Operation == "confirm" {
					return nil, nil
				}
				if mode == "unavailable" {
					return nil, errAgentPromptUnavailable
				}
				if mode == "empty" {
					return nil, nil
				}
				return []byte("wrong"), nil
			}}
			if sig, err := a.Sign(pub, data); err == nil || sig != nil {
				t.Fatal("failed prompt yielded signature")
			}
			if mode == "locked-provider" && len(operations) != 1 {
				t.Fatal("passphrase prompt tried to unlock provider")
			}
		})
	}
	b.assertCleared(t)
}

func promptFixture(t *testing.T, body string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sshx-prompt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "helper")
	if err := os.WriteFile(path, []byte("#!/usr/bin/python3 -I\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAgentPromptHelperPipesAndEnvironment(t *testing.T) {
	path := promptFixture(t, `import json,os,sys
r=json.load(sys.stdin)
assert len(sys.argv)==1
assert not any(k in os.environ for k in ['SSH_AUTH_SOCK','SSH_AGENT_PID','LISTEN_FDS','GOPASS_CONFIG','LD_PRELOAD','PYTHONPATH','SENTINEL_SECRET'])
# No network descriptor may reach the helper.
if os.path.isdir('/proc/self/fd'):
 assert not any(os.readlink('/proc/self/fd/'+f).startswith('socket:') for f in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+f))
json.dump(dict(version=1,request_id=r['request_id'],approved=True,passphrase='Zml4dHVyZQ=='),sys.stdout)
`)
	t.Setenv("SENTINEL_SECRET", "must-not-leak")
	t.Setenv("SSH_AUTH_SOCK", "must-not-inherit")
	r := agentPromptRequest{Version: 1, RequestID: "fixture-request", Operation: "passphrase"}
	pass, err := runAgentPrompt(context.Background(), path, r)
	if err != nil || string(pass) != "fixture" {
		t.Fatal("helper pipe failed", err)
	}
	clearBytes(pass)
	r.Operation = "confirm"
	if _, err := runAgentPrompt(context.Background(), path, r); err == nil {
		t.Fatal("passphrase accepted as confirmation")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if trustedAgentHelper(path) {
		t.Fatal("writable helper trusted")
	}
	if trustedAgentHelper("helper") {
		t.Fatal("PATH search permitted")
	}
}

func TestAgentPromptHelperTimeoutAndBounds(t *testing.T) {
	for _, body := range []string{"import time\ntime.sleep(10)\n", "import sys\nsys.stdout.write('x'*20000)\n", "import sys\nsys.exit(1)\n"} {
		path := promptFixture(t, body)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		started := time.Now()
		_, err := runAgentPrompt(ctx, path, agentPromptRequest{Version: 1, RequestID: "fixture", Operation: "confirm"})
		cancel()
		if err == nil || time.Since(started) > 2*time.Second {
			t.Fatal("helper did not fail promptly")
		}
	}
}

func TestAgentConfirmationConcurrentIsolation(t *testing.T) {
	a, _, pub, data := confirmationAgent(t, false)
	var mutex sync.Mutex
	ids := map[string]bool{}
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		mutex.Lock()
		defer mutex.Unlock()
		if ids[r.RequestID] {
			return nil, errors.New("reused approval")
		}
		ids[r.RequestID] = true
		return nil, nil
	}}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Sign(pub, data); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(ids) != 4 {
		t.Fatal("requests shared approvals")
	}
}

func TestAgentConfirmationDisconnectAndShutdown(t *testing.T) {
	for _, mode := range []string{"disconnect", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			record, raw := testAgentKey(t)
			record.Confirm = true
			registry, err := parseAgentRegistry(policyJSON(t, record))
			if err != nil {
				t.Fatal(err)
			}
			backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
			path := filepath.Join(agentTestDirectory(t), "agent.sock")
			server, err := newAgentServer(path, registry, backend.open)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			entered := make(chan struct{})
			exited := make(chan struct{})
			server.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
				close(entered)
				<-ctx.Done()
				close(exited)
				return nil, ctx.Err()
			}}
			go server.Serve(context.Background())
			conn := agentTestDial(t, path)
			pub := policyPublic(t, record)
			body := append([]byte{agentSignCode}, ssh.Marshal(struct {
				Key, Data []byte
				Flags     uint32
			}{pub.Marshal(), []byte("request"), 0})...)
			if _, err := conn.Write(agentPacket(body)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("prompt not entered")
			}
			if mode == "disconnect" {
				_ = conn.Close()
			} else {
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("prompt survived client/server")
			}
			if backend.reads.Load() != 0 {
				t.Fatal("canceled approval opened provider")
			}
		})
	}
}

func TestAgentConfirmationRegistryAndUnknownDestination(t *testing.T) {
	record, _ := testAgentKey(t)
	record.Confirm = true
	if _, err := parseAgentRegistry(registryJSON(t, record)); err == nil {
		t.Fatal("version 1 enabled confirmation")
	}
	alias := record
	alias.ID = "alias"
	alias.Confirm = false
	if _, err := parseAgentRegistry(policyJSON(t, record, alias)); err == nil {
		t.Fatal("alias weakened confirmation")
	}
	record.Comment = "UNTRUSTED-LABEL"
	record.Confirm = false
	reg, err := parseAgentRegistry(policyJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	r, err := newAgentPromptRequest(context.Background(), reg.keys[0], []byte("arbitrary-data"), "ssh-ed25519", 0, nil)
	if err != nil || r.Destination.Status != "unknown" || r.Destination.HostFingerprint != "" || r.Destination.Username != "" {
		t.Fatal("unverified destination claimed")
	}
	encoded, _ := json.Marshal(r)
	if bytes.Contains(encoded, []byte(record.Comment)) || bytes.Contains(encoded, []byte(record.Reference)) || bytes.Contains(encoded, []byte("arbitrary-data")) {
		t.Fatal("untrusted metadata shown")
	}
}

func TestAgentEncryptedPolicyChangeDuringPassphrase(t *testing.T) {
	a, b, pub, data := confirmationAgent(t, true)
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		if r.Operation == "passphrase" {
			a.keys.setLocked(true)
			a.keys.setLocked(false)
			return []byte("fixture-passphrase"), nil
		}
		return nil, nil
	}}
	if signature, err := a.Sign(pub, data); err == nil || signature != nil {
		t.Fatal("passphrase ignored lock transition")
	}
	b.assertCleared(t)
}

func FuzzAgentPromptResponse(f *testing.F) {
	f.Add([]byte(`{"version":1,"request_id":"fixture","approved":true,"passphrase":"cGFzcw=="}`))
	f.Add([]byte(`{"version":1,"request_id":"wrong","approved":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxAgentPromptBytes+1 {
			return
		}
		pass, err := decodeAgentPrompt(data, agentPromptRequest{Version: 1, RequestID: "fixture", Operation: "passphrase"})
		defer clearBytes(pass)
		if err == nil && (len(pass) == 0 || len(pass) > maxAgentPassphraseBytes) {
			t.Fatal("invalid passphrase admitted")
		}
	})
}

func TestAgentConfirmationFilePolicyChange(t *testing.T) {
	a, b, pub, data := confirmationAgent(t, false)
	record := a.keys.registry.keys[0].record
	path := filepath.Join(agentTestDirectory(t), "agent.json")
	writePolicyFile(t, path, policyJSON(t, record))
	a.keys.source = path
	a.keys.prompt = &agentPrompter{ask: func(ctx context.Context, r agentPromptRequest) ([]byte, error) {
		record.Enabled = false
		writePolicyFile(t, path, policyJSON(t, record))
		return nil, nil
	}}
	if signature, err := a.Sign(pub, data); err == nil || signature != nil || b.reads.Load() != 0 {
		t.Fatal("approval survived file policy revocation")
	}
}
