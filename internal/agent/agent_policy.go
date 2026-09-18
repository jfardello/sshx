package agent

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const (
	maxAgentPolicyEdges       = 64
	maxAgentPolicyHostKeys    = 16
	maxAgentConstraintBytes   = 64 * 1024
	agentHostboundMethod      = "publickey-hostbound-v00@openssh.com"
	agentDestinationExtension = "restrict-destination-v00@openssh.com"
)

// Versioned, owner-approved pins. Hostname labels never establish host trust.
type agentDestinationPolicy struct {
	Version          int                    `json:"version"`
	RequireHostbound bool                   `json:"require_hostbound,omitempty"`
	Edges            []agentDestinationEdge `json:"edges"`
}
type agentDestinationEdge struct {
	From agentDestinationHop `json:"from"`
	To   agentDestinationHop `json:"to"`
}
type agentDestinationHop struct {
	Hostname string   `json:"hostname,omitempty"`
	Username string   `json:"username,omitempty"`
	HostKeys []string `json:"host_keys,omitempty"`
}
type agentPolicyHop struct {
	keys     map[string]bool
	username string
}
type agentPolicyEdge struct{ from, to agentPolicyHop }
type agentPolicy struct {
	edges            []agentPolicyEdge
	requireHostbound bool
}

func compileAgentPolicy(doc *agentDestinationPolicy) (*agentPolicy, error) {
	if doc == nil || doc.Version != 1 || len(doc.Edges) == 0 || len(doc.Edges) > maxAgentPolicyEdges {
		return nil, errAgentRegistry
	}
	p := &agentPolicy{requireHostbound: doc.RequireHostbound}
	for _, edge := range doc.Edges {
		from, err := compileAgentHop(edge.From, true)
		if err != nil {
			return nil, err
		}
		to, err := compileAgentHop(edge.To, false)
		if err != nil {
			return nil, err
		}
		p.edges = append(p.edges, agentPolicyEdge{from, to})
	}
	return p, nil
}
func compileAgentHop(h agentDestinationHop, from bool) (agentPolicyHop, error) {
	result := agentPolicyHop{keys: make(map[string]bool), username: h.Username}
	if !policyText(h.Hostname, 255) || !policyText(h.Username, 256) || len(h.HostKeys) > maxAgentPolicyHostKeys {
		return result, errAgentRegistry
	}
	if from {
		if h.Username != "" || (h.Hostname == "") != (len(h.HostKeys) == 0) {
			return result, errAgentRegistry
		}
	} else if h.Hostname == "" || len(h.HostKeys) == 0 {
		return result, errAgentRegistry
	}
	for _, pin := range h.HostKeys {
		if len(pin) > 24*1024 {
			return result, errAgentRegistry
		}
		fields := strings.Split(pin, " ")
		if len(fields) != 2 {
			return result, errAgentRegistry
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return result, errAgentRegistry
		}
		key, err := parseAgentPolicyHost(blob)
		if err != nil || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != pin {
			return result, errAgentRegistry
		}
		raw := string(key.Marshal())
		if result.keys[raw] {
			return result, errAgentRegistry
		}
		result.keys[raw] = true
	}
	return result, nil
}
func policyText(value string, max int) bool {
	return len(value) <= max && strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0 && !strings.ContainsAny(value, "*?![]\\")
}

// visible checks the bound path without a username or a credential-store read.
// Forwarding visibility additionally requires an allowed onward edge; the
// current connection admission gate still denies all forwarded operations.
func (p *agentPolicy) visible(b *agentBindingState) bool {
	if b == nil || b.poisoned || len(b.chain) == 0 {
		return false
	}
	if !p.pathAllowed(b, "") {
		return false
	}
	last := b.chain[len(b.chain)-1]
	if !last.forwarding {
		return true
	}
	blob := string(last.hostKey.Marshal())
	for _, edge := range p.edges {
		if edge.from.keys[blob] {
			return true
		}
	}
	return false
}
func (p *agentPolicy) pathAllowed(b *agentBindingState, user string) bool {
	previous := ""
	for i, binding := range b.chain {
		if binding.hostKey == nil || (i < len(b.chain)-1 && !binding.forwarding) {
			return false
		}
		current := string(binding.hostKey.Marshal())
		allowed := false
		for _, edge := range p.edges {
			sourceOK := (previous == "" && len(edge.from.keys) == 0) || (previous != "" && edge.from.keys[previous])
			userOK := i < len(b.chain)-1 || user == "" || edge.to.username == "" || edge.to.username == user
			if sourceOK && edge.to.keys[current] && userOK {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
		previous = current
	}
	return len(b.chain) > 0
}

// authorize checks the original unsigned userauth bytes against the signing
// key, algorithm, verified session chain and pinned policy before any key read.
func (p *agentPolicy) authorize(b *agentBindingState, key, data []byte, algorithm string) bool {
	if b == nil || b.poisoned || len(b.chain) == 0 || len(b.chain) > maxAgentBindings {
		return false
	}
	last := b.chain[len(b.chain)-1]
	if last.forwarding || last.hostKey == nil {
		return false
	}
	request, ok := parseAgentUserauth(data)
	if !ok || !bytes.Equal(request.session, last.session) || !bytes.Equal(request.key, key) || request.algorithm != algorithm || !p.pathAllowed(b, request.username) {
		return false
	}
	if request.hostbound {
		return bytes.Equal(request.host, last.hostKey.Marshal())
	}
	return !p.requireHostbound && len(b.chain) == 1 && !b.forwarded
}

type agentUserauth struct {
	session, key, host  []byte
	username, algorithm string
	hostbound           bool
}

func parseAgentUserauth(data []byte) (r agentUserauth, ok bool) {
	if len(data) > maxAgentFrameBytes {
		return r, false
	}
	r.session, data, ok = agentWireString(data)
	if !ok || len(r.session) == 0 || len(r.session) > maxAgentSessionBytes || len(data) == 0 || data[0] != 50 {
		return r, false
	}
	user, data, ok := agentWireString(data[1:])
	if !ok || len(user) == 0 || !policyText(string(user), 256) {
		return r, false
	}
	r.username = string(user)
	service, data, ok := agentWireString(data)
	if !ok || string(service) != "ssh-connection" {
		return r, false
	}
	method, data, ok := agentWireString(data)
	if !ok || (string(method) != "publickey" && string(method) != agentHostboundMethod) || len(data) == 0 || data[0] != 1 {
		return r, false
	}
	r.hostbound = string(method) == agentHostboundMethod
	algorithm, data, ok := agentWireString(data[1:])
	if !ok || len(algorithm) == 0 || len(algorithm) > 64 {
		return r, false
	}
	r.algorithm = string(algorithm)
	r.key, data, ok = agentWireString(data)
	if !ok || len(r.key) == 0 || len(r.key) > maxAgentBindingKeyBytes {
		return r, false
	}
	if r.hostbound {
		r.host, data, ok = agentWireString(data)
		if !ok || len(r.host) == 0 || len(r.host) > maxAgentBindingKeyBytes {
			return r, false
		}
	}
	return r, len(data) == 0
}

// Decode the complete tag-255 key-add constraint, not a standalone extension.
// All nested SSH strings are consumed exactly; CA and wildcard policy is denied.
func parseAgentDestinationConstraint(data []byte) (*agentDestinationPolicy, error) {
	if len(data) == 0 || len(data) > maxAgentConstraintBytes || data[0] != 255 {
		return nil, errAgentDenied
	}
	name, data, ok := agentWireString(data[1:])
	if !ok || string(name) != agentDestinationExtension {
		return nil, errAgentDenied
	}
	details, rest, ok := agentWireString(data)
	if !ok || len(rest) != 0 {
		return nil, errAgentDenied
	}
	policy := &agentDestinationPolicy{Version: 1}
	for len(details) > 0 {
		if len(policy.Edges) >= maxAgentPolicyEdges {
			return nil, errAgentDenied
		}
		constraint, next, ok := agentWireString(details)
		if !ok {
			return nil, errAgentDenied
		}
		details = next
		from, rest, ok := agentWireString(constraint)
		if !ok {
			return nil, errAgentDenied
		}
		to, rest, ok := agentWireString(rest)
		if !ok {
			return nil, errAgentDenied
		}
		reserved, rest, ok := agentWireString(rest)
		if !ok || len(reserved) != 0 || len(rest) != 0 {
			return nil, errAgentDenied
		}
		source, err := parseAgentDestinationHop(from)
		if err != nil {
			return nil, err
		}
		destination, err := parseAgentDestinationHop(to)
		if err != nil {
			return nil, err
		}
		policy.Edges = append(policy.Edges, agentDestinationEdge{source, destination})
	}
	if _, err := compileAgentPolicy(policy); err != nil {
		return nil, errAgentDenied
	}
	return policy, nil
}
func parseAgentDestinationHop(data []byte) (h agentDestinationHop, err error) {
	user, data, ok := agentWireString(data)
	if !ok {
		return h, errAgentDenied
	}
	h.Username = string(user)
	host, data, ok := agentWireString(data)
	if !ok {
		return h, errAgentDenied
	}
	h.Hostname = string(host)
	reserved, data, ok := agentWireString(data)
	if !ok || len(reserved) != 0 {
		return h, errAgentDenied
	}
	for len(data) > 0 {
		if len(h.HostKeys) >= maxAgentPolicyHostKeys {
			return h, errAgentDenied
		}
		blob, rest, ok := agentWireString(data)
		if !ok || len(blob) > maxAgentBindingKeyBytes || len(rest) == 0 || rest[0] != 0 {
			return h, errAgentDenied
		}
		data = rest[1:]
		key, err := parseAgentPolicyHost(blob)
		if err != nil {
			return h, errAgentDenied
		}
		h.HostKeys = append(h.HostKeys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	}
	return h, nil
}

func parseAgentPolicyHost(blob []byte) (ssh.PublicKey, error) {
	if len(blob) > maxAgentBindingKeyBytes {
		return nil, errAgentDenied
	}
	kind, _, ok := agentWireString(blob)
	if !ok {
		return nil, errAgentDenied
	}
	switch string(kind) {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return nil, errAgentDenied
	}
	key, err := ssh.ParsePublicKey(blob)
	if err != nil || !supportedAgentPublicKey(key) || !bytes.Equal(key.Marshal(), blob) {
		return nil, errAgentDenied
	}
	return key, nil
}
