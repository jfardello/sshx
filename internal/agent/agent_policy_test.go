package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func policyPin(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
func policyEdge(from, to ssh.PublicKey, user string) agentDestinationEdge {
	e := agentDestinationEdge{To: agentDestinationHop{Hostname: "destination.example", Username: user, HostKeys: []string{policyPin(to)}}}
	if from != nil {
		e.From = agentDestinationHop{Hostname: "source.example", HostKeys: []string{policyPin(from)}}
	}
	return e
}
func policyRecord(t *testing.T, host ssh.PublicKey) (agentKeyRecord, []byte) {
	t.Helper()
	record, raw := testAgentKey(t)
	record.Policy = "destination-constrained"
	record.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, host, "alice")}}
	return record, raw
}
func policyJSON(t *testing.T, records ...agentKeyRecord) []byte {
	t.Helper()
	data, err := json.Marshal(agentRegistryDocument{Version: 2, Keys: records})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func policyConnection(t *testing.T, record agentKeyRecord, raw []byte, host ssh.Signer) (*agentConnection, *agentTestBackend) {
	t.Helper()
	reg, err := parseAgentRegistry(policyJSON(t, record))
	if err != nil {
		t.Fatal(err)
	}
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	service, err := newAgentKeyService(reg, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	a := &agentConnection{ctx: context.Background(), keys: service}
	if host != nil {
		bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
	}
	return a, backend
}

type policyAuth struct {
	Session               []byte
	Message               byte
	User, Service, Method string
	Follows               bool
	Algorithm             string
	Key                   []byte
}

func authData(key ssh.PublicKey, host ssh.PublicKey, algorithm string) []byte {
	r := policyAuth{[]byte("session"), 50, "alice", "ssh-connection", "publickey", true, algorithm, key.Marshal()}
	if host != nil {
		r.Method = agentHostboundMethod
	}
	data := ssh.Marshal(r)
	if host != nil {
		data = append(data, ssh.Marshal(struct{ Host []byte }{host.Marshal()})...)
	}
	return data
}
func policyPublic(t *testing.T, record agentKeyRecord) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAgentDestinationDirectAndVisibility(t *testing.T) {
	host := bindingSigner(t)
	record, raw := policyRecord(t, host.PublicKey())
	pub := policyPublic(t, record)
	a, backend := policyConnection(t, record, raw, nil)
	if keys, err := a.List(); err != nil || len(keys) != 0 {
		t.Fatal("unbound constrained key visible", err)
	}
	data := authData(pub, nil, pub.Type())
	if _, err := a.Sign(pub, data); err == nil {
		t.Fatal("unbound constrained signing")
	}
	if _, err := a.keys.sign(context.Background(), pub.Marshal(), data, pub.Type()); err == nil {
		t.Fatal("internal unbound path bypassed constraints")
	}
	bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
	if keys, err := a.List(); err != nil || len(keys) != 1 {
		t.Fatal("allowed destination not visible", err)
	}
	if backend.opens.Load() != 0 {
		t.Fatal("discovery read a key")
	}
	for _, destination := range []ssh.PublicKey{nil, host.PublicKey()} {
		data = authData(pub, destination, pub.Type())
		sig, err := a.Sign(pub, data)
		if err != nil || pub.Verify(data, sig) != nil {
			t.Fatal("valid direct authentication denied", err)
		}
	}
	wrong, wrongBackend := policyConnection(t, record, raw, bindingSigner(t))
	if keys, err := wrong.List(); err != nil || len(keys) != 0 {
		t.Fatal("wrong host can list constrained key", err)
	}
	if _, err := wrong.Sign(pub, data); err == nil || wrongBackend.opens.Load() != 0 {
		t.Fatal("wrong host fetched key")
	}
	backend.assertCleared(t)
	// Same host key under another label/port is deliberately indistinguishable.
	record.Destinations.Edges[0].To.Hostname = "different-label.example:2222"
	shared, _ := policyConnection(t, record, raw, host)
	if _, err := shared.Sign(pub, authData(pub, nil, pub.Type())); err != nil {
		t.Fatal("label substituted for host-key trust")
	}
	record.Destinations.RequireHostbound = true
	strict, b := policyConnection(t, record, raw, host)
	if _, err := strict.Sign(pub, authData(pub, nil, pub.Type())); err == nil || b.opens.Load() != 0 {
		t.Fatal("strict policy admitted ordinary publickey")
	}
	if _, err := strict.Sign(pub, authData(pub, host.PublicKey(), pub.Type())); err != nil {
		t.Fatal("strict hostbound denied", err)
	}
}

func TestAgentDestinationRejectsPayloadMismatches(t *testing.T) {
	host := bindingSigner(t)
	record, raw := policyRecord(t, host.PublicKey())
	pub := policyPublic(t, record)
	base := policyAuth{[]byte("session"), 50, "alice", "ssh-connection", "publickey", true, pub.Type(), pub.Marshal()}
	variants := map[string]func(*policyAuth){
		"session":               func(r *policyAuth) { r.Session = []byte("other") },
		"empty-session":         func(r *policyAuth) { r.Session = nil },
		"message":               func(r *policyAuth) { r.Message = 51 },
		"username":              func(r *policyAuth) { r.User = "root" },
		"empty-user":            func(r *policyAuth) { r.User = "" },
		"username-control":      func(r *policyAuth) { r.User = "alice\x00root" },
		"service":               func(r *policyAuth) { r.Service = "ssh-userauth" },
		"method":                func(r *policyAuth) { r.Method = "hostbased" },
		"signature-follows":     func(r *policyAuth) { r.Follows = false },
		"algorithm":             func(r *policyAuth) { r.Algorithm = ssh.KeyAlgoRSASHA512 },
		"key":                   func(r *policyAuth) { r.Key = host.PublicKey().Marshal() },
		"missing-hostbound-key": func(r *policyAuth) { r.Method = agentHostboundMethod },
	}
	payloads := map[string][]byte{"arbitrary": []byte("arbitrary data"), "sshsig": []byte("SSHSIG"), "trailing": append(ssh.Marshal(base), 0), "wrong-hostbound-key": authData(pub, bindingSigner(t).PublicKey(), pub.Type())}
	for name, change := range variants {
		r := base
		change(&r)
		payloads[name] = ssh.Marshal(r)
	}
	valid := ssh.Marshal(base)
	for i := 0; i < len(valid); i++ {
		payloads[fmt.Sprintf("truncated-%d", i)] = valid[:i]
	}
	a, b := policyConnection(t, record, raw, host)
	for name, data := range payloads {
		t.Run(name, func(t *testing.T) {
			if sig, err := a.Sign(pub, data); err == nil || sig != nil {
				t.Fatal("invalid payload signed")
			}
		})
	}
	if b.opens.Load() != 0 {
		t.Fatal("denied payload opened backend")
	}
	// A denied sign does not poison a valid proof: retry with authorized data.
	if _, err := a.Sign(pub, valid); err != nil {
		t.Fatal(err)
	}
}

func TestAgentDestinationRSAFlags(t *testing.T) {
	host := bindingSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	record, raw, pub := agentTestRecord(t, key, "rsa")
	record.Policy = "destination-constrained"
	record.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, host.PublicKey(), "alice")}}
	a, b := policyConnection(t, record, raw, host)
	for _, pair := range []struct {
		algorithm string
		flags     sshagent.SignatureFlags
	}{{ssh.KeyAlgoRSASHA256, sshagent.SignatureFlagRsaSha256}, {ssh.KeyAlgoRSASHA512, sshagent.SignatureFlagRsaSha512}} {
		data := authData(pub, nil, pair.algorithm)
		sig, err := a.SignWithFlags(pub, data, pair.flags)
		if err != nil || sig.Format != pair.algorithm || pub.Verify(data, sig) != nil {
			t.Fatal("RSA constrained signature", err)
		}
		before := b.opens.Load()
		if _, err := a.SignWithFlags(pub, data, pair.flags^6); err == nil || b.opens.Load() != before {
			t.Fatal("RSA algorithm/flags mismatch accepted")
		}
	}
}

func TestAgentDestinationPaths(t *testing.T) {
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t), bindingSigner(t)}
	doc := &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, hosts[0].PublicKey(), "ignored-intermediate"), policyEdge(hosts[0].PublicKey(), hosts[1].PublicKey(), "alice"), policyEdge(hosts[1].PublicKey(), hosts[2].PublicKey(), "backup")}}
	p, err := compileAgentPolicy(doc)
	if err != nil {
		t.Fatal(err)
	}
	var b agentBindingState
	if err := b.record(signedBinding(t, hosts[0], []byte("bastion"), 1)); err != nil {
		t.Fatal(err)
	}
	if !p.visible(&b) {
		t.Fatal("allowed onward edge hidden")
	}
	if err := b.record(signedBinding(t, hosts[1], []byte("session"), 0)); err != nil {
		t.Fatal(err)
	}
	key := bindingSigner(t).PublicKey()
	if !p.authorize(&b, key.Marshal(), authData(key, hosts[1].PublicKey(), key.Type()), key.Type()) {
		t.Fatal("allowed hostbound path rejected")
	}
	if p.authorize(&b, key.Marshal(), authData(key, nil, key.Type()), key.Type()) {
		t.Fatal("forwarded ordinary publickey accepted")
	}
	missing, _ := compileAgentPolicy(&agentDestinationPolicy{Version: 1, Edges: doc.Edges[1:]})
	if missing.visible(&b) {
		t.Fatal("missing origin edge bypassed")
	}
	// No implicit origin -> destination permission and no omitted middle edge.
	var direct agentBindingState
	direct.record(signedBinding(t, hosts[1], []byte("session"), 0))
	if p.visible(&direct) {
		t.Fatal("path skipped bastion")
	}
	var deadend agentBindingState
	deadend.record(signedBinding(t, hosts[0], []byte("first"), 1))
	deadend.record(signedBinding(t, hosts[1], []byte("second"), 1))
	deadend.record(signedBinding(t, hosts[2], []byte("third"), 1))
	if p.visible(&deadend) {
		t.Fatal("forwarding-only path without onward edge visible")
	}
	record, raw := policyRecord(t, hosts[1].PublicKey())
	record.Destinations = doc
	a, backend := policyConnection(t, record, raw, nil)
	bindingReply(t, a, signedBinding(t, hosts[0], []byte("bastion"), 1), 28)
	bindingReply(t, a, signedBinding(t, hosts[1], []byte("session"), 0), 28)
	pub := policyPublic(t, record)
	if _, err := a.Sign(pub, authData(pub, hosts[1].PublicKey(), pub.Type())); err == nil || backend.opens.Load() != 0 {
		t.Fatal("forwarding enabled before its milestone")
	}
}

func TestAgentPolicyRegistryValidation(t *testing.T) {
	host := bindingSigner(t)
	base, _ := policyRecord(t, host.PublicKey())
	cases := map[string]func(*agentKeyRecord){
		"missing":             func(r *agentKeyRecord) { r.Destinations = nil },
		"version":             func(r *agentKeyRecord) { r.Destinations.Version = 2 },
		"empty":               func(r *agentKeyRecord) { r.Destinations.Edges = nil },
		"too-many-edges":      func(r *agentKeyRecord) { r.Destinations.Edges = make([]agentDestinationEdge, maxAgentPolicyEdges+1) },
		"unrestricted-policy": func(r *agentKeyRecord) { r.Policy = "unrestricted-local" },
		"no-pins":             func(r *agentKeyRecord) { r.Destinations.Edges[0].To.HostKeys = nil },
		"unknown-pin":         func(r *agentKeyRecord) { r.Destinations.Edges[0].To.HostKeys = []string{"not-a-key"} },
		"no-host":             func(r *agentKeyRecord) { r.Destinations.Edges[0].To.Hostname = "" },
		"source-user":         func(r *agentKeyRecord) { r.Destinations.Edges[0].From.Username = "root" },
		"source-without-pins": func(r *agentKeyRecord) { r.Destinations.Edges[0].From.Hostname = "bastion" },
		"source-without-host": func(r *agentKeyRecord) { r.Destinations.Edges[0].From.HostKeys = []string{policyPin(host.PublicKey())} },
		"wildcard-user":       func(r *agentKeyRecord) { r.Destinations.Edges[0].To.Username = "*" },
		"duplicate-pin": func(r *agentKeyRecord) {
			r.Destinations.Edges[0].To.HostKeys = append(r.Destinations.Edges[0].To.HostKeys, policyPin(host.PublicKey()))
		},
		"pin-comment": func(r *agentKeyRecord) { r.Destinations.Edges[0].To.HostKeys[0] += " comment" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			var r agentKeyRecord
			data, _ := json.Marshal(base)
			json.Unmarshal(data, &r)
			change(&r)
			if _, err := parseAgentRegistry(policyJSON(t, r)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	if _, err := parseAgentRegistry(registryJSON(t, base)); err == nil {
		t.Fatal("v1 enabled constraints")
	}
	alias := base
	alias.ID = "alias"
	if r, err := parseAgentRegistry(policyJSON(t, base, alias)); err != nil || len(r.keys) != 1 {
		t.Fatal("identical alias rejected", err)
	}
	alias.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{policyEdge(nil, host.PublicKey(), "root")}}
	if _, err := parseAgentRegistry(policyJSON(t, base, alias)); err == nil {
		t.Fatal("conflicting aliases unioned user policies")
	}
	for _, raw := range []string{`"version":1,"version":1`, `"Version":1`, `"version":null`} {
		data := bytes.Replace(policyJSON(t, base), []byte(`"version":1`), []byte(raw), 1)
		if _, err := parseAgentRegistry(data); err == nil {
			t.Fatal("invalid nested JSON accepted")
		}
	}
}

func writePolicyFile(t *testing.T, name string, data []byte) {
	t.Helper()
	tmp := name + ".new"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, name); err != nil {
		t.Fatal(err)
	}
}
func TestAgentPolicyChangesInvalidatePendingSignatures(t *testing.T) {
	for _, change := range []string{"user", "host", "disabled", "deleted", "invalid", "permissions", "reference"} {
		t.Run(change, func(t *testing.T) {
			host := bindingSigner(t)
			record, raw := policyRecord(t, host.PublicKey())
			pub := policyPublic(t, record)
			name := filepath.Join(agentTestDirectory(t), "agent.json")
			writePolicyFile(t, name, policyJSON(t, record))
			registry, err := readAgentRegistry(name)
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}, read: func(context.Context) error { close(entered); <-release; return nil }}
			service, err := newAgentKeyService(registry, backend.open)
			if err != nil {
				t.Fatal(err)
			}
			a := &agentConnection{ctx: context.Background(), keys: service}
			bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
			done := make(chan error, 1)
			go func() {
				sig, err := a.Sign(pub, authData(pub, nil, pub.Type()))
				if sig != nil || err == nil {
					done <- fmt.Errorf("stale signature released")
					return
				}
				done <- nil
			}()
			<-entered
			switch change {
			case "user":
				record.Destinations.Edges[0].To.Username = "root"
				writePolicyFile(t, name, policyJSON(t, record))
			case "host":
				record.Destinations.Edges[0].To.HostKeys = []string{policyPin(bindingSigner(t).PublicKey())}
				writePolicyFile(t, name, policyJSON(t, record))
			case "disabled":
				record.Enabled = false
				writePolicyFile(t, name, policyJSON(t, record))
			case "deleted":
				os.Remove(name)
			case "invalid":
				writePolicyFile(t, name, []byte("{"))
			case "permissions":
				os.Chmod(name, 0644)
			case "reference":
				record.Reference = "different"
				writePolicyFile(t, name, policyJSON(t, record))
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			backend.assertCleared(t)
		})
	}
}

func TestAgentPolicyRefreshAndConcurrency(t *testing.T) {
	host := bindingSigner(t)
	record, raw := policyRecord(t, host.PublicKey())
	pub := policyPublic(t, record)
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	writePolicyFile(t, name, policyJSON(t, record))
	registry, err := readAgentRegistry(name)
	if err != nil {
		t.Fatal(err)
	}
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	service, err := newAgentKeyService(registry, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	a := &agentConnection{ctx: context.Background(), keys: service}
	bindingReply(t, a, signedBinding(t, host, []byte("session"), 0), 6)
	generation, _ := service.signingState()
	if _, err := a.List(); err != nil {
		t.Fatal(err)
	}
	if current, _ := service.signingState(); generation != current {
		t.Fatal("unchanged policy invalidated itself")
	}
	writePolicyFile(t, name, []byte("{}"))
	if _, err := a.List(); err == nil {
		t.Fatal("invalid policy retained old visibility")
	}
	writePolicyFile(t, name, policyJSON(t, record))
	if _, err := a.Sign(pub, authData(pub, nil, pub.Type())); err != nil {
		t.Fatal("valid policy did not recover", err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 8; j++ {
				_, _ = a.List()
				_, _ = a.Sign(pub, authData(pub, nil, pub.Type()))
			}
		}()
	}
	for i := 0; i < 8; i++ {
		record.Enabled = i%2 == 0
		writePolicyFile(t, name, policyJSON(t, record))
		_ = service.refresh()
	}
	workers.Wait()
	service.setLocked(true)
	writePolicyFile(t, name, policyJSON(t, record))
	_ = service.refresh()
	if _, locked := service.signingState(); !locked {
		t.Fatal("policy refresh unlocked service")
	}
	if err := service.replaceRegistry(nil); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if _, ok := service.lookup(pub.Marshal()); ok {
		t.Fatal("invalid registry retained usable lookup")
	}
}

func TestAgentDestinationMixedCatalogAndRotation(t *testing.T) {
	oldHost, newHost := bindingSigner(t), bindingSigner(t)
	constrained, raw := policyRecord(t, oldHost.PublicKey())
	unrestricted, otherRaw := testAgentKey(t)
	unrestricted.ID = "unrestricted"
	unrestricted.Reference = "other-key"
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	writePolicyFile(t, name, policyJSON(t, constrained, unrestricted))
	registry, err := readAgentRegistry(name)
	if err != nil {
		t.Fatal(err)
	}
	backend := &agentTestBackend{data: map[string][]byte{constrained.Reference: raw, unrestricted.Reference: otherRaw}}
	service, err := newAgentKeyService(registry, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	old := &agentConnection{ctx: context.Background(), keys: service}
	if list, err := old.List(); err != nil || len(list) != 1 || !bytes.Equal(list[0].Blob, policyPublic(t, unrestricted).Marshal()) {
		t.Fatal("unbound catalog did not preserve unrestricted identity")
	}
	bindingReply(t, old, signedBinding(t, oldHost, []byte("session"), 0), 6)
	if list, err := old.List(); err != nil || len(list) != 2 {
		t.Fatal("approved bound catalog incomplete")
	}
	// Explicit overlapping pins allow a controlled rotation window.
	constrained.Destinations.Edges[0].To.HostKeys = append(constrained.Destinations.Edges[0].To.HostKeys, policyPin(newHost.PublicKey()))
	writePolicyFile(t, name, policyJSON(t, constrained, unrestricted))
	newer := &agentConnection{ctx: context.Background(), keys: service}
	bindingReply(t, newer, signedBinding(t, newHost, []byte("session"), 0), 6)
	for _, a := range []*agentConnection{old, newer} {
		if list, err := a.List(); err != nil || len(list) != 2 {
			t.Fatal("explicit rotation pin missing")
		}
	}
	if backend.opens.Load() != 0 {
		t.Fatal("catalog rotation retrieved private key")
	}
	constrained.Destinations.Edges[0].To.HostKeys = []string{policyPin(newHost.PublicKey())}
	writePolicyFile(t, name, policyJSON(t, constrained, unrestricted))
	if list, err := old.List(); err != nil || len(list) != 1 {
		t.Fatal("revoked host retained constrained identity")
	}
	if list, err := newer.List(); err != nil || len(list) != 2 {
		t.Fatal("new pin not usable after rotation")
	}
	key := policyPublic(t, constrained)
	if _, err := old.Sign(key, authData(key, nil, key.Type())); err == nil || backend.opens.Load() != 0 {
		t.Fatal("revoked host fetched key")
	}
	if _, err := newer.Sign(key, authData(key, nil, key.Type())); err != nil {
		t.Fatal("new pinned host could not sign", err)
	}
}
