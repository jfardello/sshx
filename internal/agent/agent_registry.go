package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const maxAgentRegistryBytes = 1024 * 1024

var errAgentRegistry = errors.New("invalid or untrusted SSH key registry")

// Registry data is public, owner-approved configuration. Backend metadata never
// changes enablement or policy. Version 2 adds explicitly pinned destinations.
type agentRegistryDocument struct {
	Version int              `json:"version"`
	Keys    []agentKeyRecord `json:"keys"`
}
type agentKeyRecord struct {
	Confirm      bool                    `json:"confirm,omitempty"`
	ID           string                  `json:"id"`
	PublicKey    string                  `json:"public_key"`
	Enabled      bool                    `json:"enabled"`
	Policy       string                  `json:"policy"`
	Comment      string                  `json:"comment,omitempty"`
	Backend      credentialBackend       `json:"backend"`
	Reference    string                  `json:"reference"`
	Collection   string                  `json:"collection,omitempty"`
	Destinations *agentDestinationPolicy `json:"destinations,omitempty"`
}
type registeredAgentKey struct {
	record    agentKeyRecord
	publicKey ssh.PublicKey
	policy    *agentPolicy
}
type agentRegistry struct {
	keys   []registeredAgentKey
	source string
}
type agentIdentity struct {
	ID        string
	PublicKey ssh.PublicKey
	Comment   string
}

func agentRegistryPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errAgentRegistry
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "sshx", "agent.json"), nil
}
func loadAgentRegistry() (*agentRegistry, error) {
	name, err := agentRegistryPath()
	if err != nil {
		return nil, err
	}
	return readAgentRegistry(name)
}

// Traverse directory descriptors rather than checking paths then reopening them.
// O_NOFOLLOW protects both the file and ancestors from symlink substitution.
func readAgentRegistry(name string) (*agentRegistry, error) {
	registry, err := readAgentRegistrySnapshot(name)
	if err == nil {
		registry.source = name
	}
	return registry, err
}
func readAgentRegistrySnapshot(name string) (*agentRegistry, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errAgentRegistry
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errAgentRegistry
	}
	defer func() { _ = unix.Close(fd) }()
	var rootStat unix.Stat_t
	if unix.Fstat(fd, &rootStat) != nil {
		return nil, errAgentRegistry
	}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if errors.Is(err, unix.ENOENT) {
			return &agentRegistry{}, nil
		}
		if err != nil {
			return nil, errAgentRegistry
		}
		var st unix.Stat_t
		if err = unix.Fstat(next, &st); err != nil {
			unix.Close(next)
			return nil, errAgentRegistry
		}
		owner := st.Uid == uint32(os.Geteuid())
		trusted := owner || st.Uid == rootStat.Uid
		// Root-owned sticky ancestors such as /tmp cannot replace an owned child.
		writable := st.Mode&0022 != 0 && !(i < len(parts)-2 && st.Uid == rootStat.Uid && st.Mode&unix.S_ISVTX != 0)
		if !trusted || writable {
			unix.Close(next)
			return nil, errAgentRegistry
		}
		if i == len(parts)-1 {
			if !owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Size > maxAgentRegistryBytes {
				unix.Close(next)
				return nil, errAgentRegistry
			}
			file := os.NewFile(uintptr(next), "agent registry")
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, maxAgentRegistryBytes+1))
			if err != nil {
				return nil, errAgentRegistry
			}
			defer clearBytes(data)
			return parseAgentRegistry(data)
		}
		unix.Close(fd)
		fd = next
	}
	return nil, errAgentRegistry
}

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
func supportedAgentPublicKey(pub ssh.PublicKey) bool {
	crypto, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	switch key := crypto.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.E >= 3 && key.E%2 == 1
	case *ecdsa.PublicKey:
		return key.Curve.Params().Name == "P-256" || key.Curve.Params().Name == "P-384" || key.Curve.Params().Name == "P-521"
	}
	return false
}
func (r *agentRegistry) List(ctx context.Context) ([]agentIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identities := []agentIdentity{}
	for _, key := range r.keys {
		if key.record.Enabled {
			// Return fresh parsed keys so callers cannot mutate the trusted registry.
			pub, err := ssh.ParsePublicKey(key.publicKey.Marshal())
			if err != nil {
				return nil, errAgentRegistry
			}
			identities = append(identities, agentIdentity{ID: key.record.ID, PublicKey: pub, Comment: key.record.Comment})
		}
	}
	return identities, nil
}

// withKey bounds ownership of private material to one local operation. The caller
// must authorize that operation first; this is not a public signing/agent API.
// Signers must not escape the callback. Go does not guarantee secure erasure.
func (r *agentRegistry) withKey(ctx context.Context, id string, store keyMaterialStore, use func(ssh.Signer) error, parsers ...func([]byte, ssh.PublicKey) (ssh.Signer, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, key := range r.keys {
		if key.record.ID == id && key.record.Enabled {
			if store == nil || use == nil {
				return errCredentialRead
			}
			data, err := store.KeyMaterial(ctx, credentialRef{Backend: key.record.Backend, ID: key.record.Reference, Collection: key.record.Collection})
			defer clearBytes(data)
			if err != nil {
				return sanitizeKeyReadError(ctx, err)
			}
			parse := parseRegisteredPrivateKey
			if len(parsers) > 0 {
				parse = parsers[0]
			}
			signer, err := parse(data, key.publicKey)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return use(signer)
		}
	}
	return errCredentialReference
}
func parseRegisteredPrivateKey(data []byte, public ssh.PublicKey) (ssh.Signer, error) {
	if len(data) > maxKeyMaterialBytes {
		return nil, errCredentialTooLarge
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, errKeyUnsupported
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return nil, errKeyUnsupported
	}
	defer clearBytes(block.Bytes)
	if len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errKeyUnsupported
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
	default:
		return nil, errKeyUnsupported
	}
	if !boundedPrivateKeyDER(block) {
		return nil, errKeyUnsupported
	}
	private, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, errKeyUnsupported
	}
	return validateRegisteredPrivateKey(private, public)
}

func validateRegisteredPrivateKey(private any, public ssh.PublicKey) (ssh.Signer, error) {
	var ed ed25519.PrivateKey
	switch key := private.(type) {
	case *ed25519.PrivateKey:
		ed = *key
	case ed25519.PrivateKey:
		ed = key
	}
	if ed != nil {
		derived := ed25519.NewKeyFromSeed(ed.Seed())
		defer clearBytes(derived)
		if !bytes.Equal(derived, ed) {
			return nil, errKeyUnsupported
		}
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil || !supportedAgentPublicKey(signer.PublicKey()) {
		return nil, errKeyUnsupported
	}
	if public == nil || !bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
		return nil, errKeyMismatch
	}
	return signer, nil
}
func sanitizeKeyReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, errCredentialLocked, errCredentialProviderChanged, errCredentialReference, errCredentialTooLarge, errKeyUnsupported, errKeyMismatch} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errCredentialRead
}

func validRegistryJSONField(name string) bool {
	switch name {
	case "confirm", "version", "keys", "id", "public_key", "enabled", "policy", "comment", "backend", "reference", "collection", "destinations", "require_hostbound", "edges", "from", "to", "hostname", "username", "host_keys":
		return true
	}
	return false
}

// Bound RSA integers before x509 performs CRT validation/precomputation. PEM
// size alone would still allow disproportionate arithmetic on hostile material.
func boundedPrivateKeyDER(block *pem.Block) bool {
	data := block.Bytes
	if block.Type == "OPENSSH PRIVATE KEY" {
		return true
	} // upstream bounds wire integers
	if block.Type == "PRIVATE KEY" {
		var outer struct {
			Version    int
			Algorithm  asn1.RawValue
			PrivateKey []byte
		}
		if _, err := asn1.Unmarshal(data, &outer); err != nil {
			return false
		}
		data = outer.PrivateKey
		// Ed25519 PKCS#8 contains an OCTET STRING; RSA and EC contain a SEQUENCE.
	}
	return boundedASN1Integers(data, 0)
}
func boundedASN1Integers(data []byte, depth int) bool {
	if depth > 8 {
		return false
	}
	for len(data) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return false
		}
		if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagInteger && len(value.Bytes) > 1025 {
			return false
		}
		if value.IsCompound && !boundedASN1Integers(value.Bytes, depth+1) {
			return false
		}
		data = rest
	}
	return true
}
