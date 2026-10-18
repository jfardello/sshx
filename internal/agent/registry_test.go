package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

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

func TestRegistryRejectsCaseAlteredSecurityFields(t *testing.T) {
	record, _ := testAgentKey(t)
	data := bytes.Replace(registryJSON(t, record), []byte(`"enabled"`), []byte(`"Enabled"`), 1)
	if _, err := parseAgentRegistry(data); err == nil {
		t.Fatal("accepted case-altered security field")
	}
}
