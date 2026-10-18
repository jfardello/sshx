package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"reflect"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

func parseAgentRegistry(data []byte) (*agentRegistry, error) {
	if len(data) > maxAgentRegistryBytes || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return nil, errAgentRegistry
	}
	// encoding/json otherwise silently accepts duplicate security fields.
	check := json.NewDecoder(bytes.NewReader(data))
	if rejectDuplicateJSONFields(check) != nil {
		return nil, errAgentRegistry
	}
	if _, err := check.Token(); err != io.EOF {
		return nil, errAgentRegistry
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc agentRegistryDocument
	if decoder.Decode(&doc) != nil || (doc.Version != 1 && doc.Version != 2) {
		return nil, errAgentRegistry
	}
	registry := &agentRegistry{}
	ids := map[string]bool{}
	blobs := map[string]agentKeyRecord{}
	for _, record := range doc.Keys {
		if !validRegistryID(record.ID) || ids[record.ID] || len(record.Comment) > 128 || strings.IndexFunc(record.Comment, unicode.IsControl) >= 0 {
			return nil, errAgentRegistry
		}
		ids[record.ID] = true
		if record.Confirm && doc.Version != 2 {
			return nil, errAgentRegistry
		}
		var policy *agentPolicy
		switch record.Policy {
		case "unrestricted-local":
			if record.Destinations != nil {
				return nil, errAgentRegistry
			}
		case "destination-constrained":
			if doc.Version != 2 {
				return nil, errAgentRegistry
			}
			var err error
			policy, err = compileAgentPolicy(record.Destinations)
			if err != nil {
				return nil, errAgentRegistry
			}
		default:
			return nil, errAgentRegistry
		}
		switch record.Backend {
		case credentialBackendGopass:
			if !validAgentGopassPath(record.Reference) || record.Collection != "" {
				return nil, errAgentRegistry
			}
		case credentialBackendSecretService:
			if !validRegistryID(record.Reference) || !validRegistryID(record.Collection) {
				return nil, errAgentRegistry
			}
		default:
			return nil, errAgentRegistry
		}
		pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
		if err != nil || comment != "" || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || !supportedAgentPublicKey(pub) {
			return nil, errAgentRegistry
		}
		canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if record.PublicKey != canonical {
			return nil, errAgentRegistry
		}
		blob := string(pub.Marshal())
		if prior, ok := blobs[blob]; ok {
			if prior.Backend != record.Backend || prior.Reference != record.Reference || prior.Collection != record.Collection || prior.Policy != record.Policy || prior.Enabled != record.Enabled || prior.Confirm != record.Confirm || !reflect.DeepEqual(prior.Destinations, record.Destinations) {
				return nil, errAgentRegistry
			}
			continue // Equivalent aliases resolve to one canonical identity.
		}
		blobs[blob] = record
		registry.keys = append(registry.keys, registeredAgentKey{record: record, publicKey: pub, policy: policy})
	}
	return registry, nil
}

func rejectDuplicateJSONFields(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		if tok == nil {
			return errAgentRegistry
		}
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			tok, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := tok.(string)
			if !ok || seen[key] || !validRegistryJSONField(key) {
				return errAgentRegistry
			}
			seen[key] = true
			if err := rejectDuplicateJSONFields(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := rejectDuplicateJSONFields(d); err != nil {
				return err
			}
		}
	default:
		return errAgentRegistry
	}
	_, err = d.Token()
	return err
}

func validRegistryID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}

func validAgentGopassPath(s string) bool {
	if s == "" || len(s) > 1024 || path.IsAbs(s) || path.Clean(s) != s || strings.ContainsAny(s, "\\\x00\r\n\t") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == "." || part == "" || strings.HasPrefix(part, "-") {
			return false
		}
	}
	return strings.IndexFunc(s, unicode.IsControl) < 0
}

func validRegistryJSONField(name string) bool {
	switch name {
	case "confirm", "version", "keys", "id", "public_key", "enabled", "policy", "comment", "backend", "reference", "collection", "destinations", "require_hostbound", "edges", "from", "to", "hostname", "username", "host_keys":
		return true
	}
	return false
}
